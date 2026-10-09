#!/usr/bin/env python3
"""
Aether-U — UWB / RTLS Penetration Test Orchestrator
=====================================================
Orchestrates multi-phase UWB (Ultra-Wideband / IEEE 802.15.4z) and Real-Time
Location System (RTLS) security assessments via:

  Phase 1  — survey              Network discovery of RTLS infrastructure
  Phase 2  — protocol_analysis   Passive MQTT / UWB protocol examination
  Phase 3  — active_interaction  Active RTLS API and MQTT testing
  Phase 4  — physical_attacks    Physical-layer attack assessment (requires hardware)
  Phase 5  — network_app         Network and application layer testing

Protocol tokens (emitted to stdout for Spectre frontend when SPECTRE_MANAGED=1):
  __SPECTRE_LOG__     <message>
  __SPECTRE_ERR__     <message>
  __SPECTRE_STATUS__  <json>
  __SPECTRE_FINDING__ <json>
  __SPECTRE_PROMPT__  <message>

Usage:
    python3 aether_u.py --config config.json --project /path/to/project
    python3 aether_u.py --phase survey --config config.json
    python3 aether_u.py --list-phases
"""
from __future__ import annotations

VERSION = Path(__file__).resolve().parent.joinpath("VERSION").read_text().strip()

import argparse
import json
import os
import socket
import platform
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
import urllib.parse
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Protocol token configuration ─────────────────────────────────────────────
MANAGED = os.environ.get("SPECTRE_MANAGED") == "1"

_SP_LOG     = "__SPECTRE_LOG__"
_SP_ERR     = "__SPECTRE_ERR__"
_SP_STATUS  = "__SPECTRE_STATUS__"

# §13b/§14j/§14k: run-dir audit log (scan.log + scan.log.json + errors.log), set
# in main() once the project dir is known. _tok() forwards here so every message
# + phase transition is persisted with a timestamp (the token stream is ephemeral).
try:
    if "/opt/pr0t31n/shared" not in sys.path:
        sys.path.insert(0, "/opt/pr0t31n/shared")
    import pr0t31n_event_log as _el
except Exception:
    _el = None
_RUNLOG = None

try:
    import pr0t31n_pause as _pp
except ImportError:
    _pp = None
_PAUSE = None

_SP_FINDING = "__SPECTRE_FINDING__"
_SP_PROMPT  = "__SPECTRE_PROMPT__"

_AETHER_U_DIR = Path(__file__).parent.resolve()


# ── Client directory helpers ──────────────────────────────────────────────────

def _clients_base() -> Path:
    """Return the OS-appropriate default parent directory for client project folders."""
    system = platform.system()
    if system == "Windows":
        base = Path("C:/clients")
    elif system == "Darwin":
        base = Path("/Users/Shared/clients")
    else:
        base = Path("/clients")
    base.mkdir(parents=True, exist_ok=True)
    return base


def _build_project_dir(client_short: str, start_date: str, tool_name: str) -> Path:
    """Build a structured project directory:
      <clients_base>/<slug>/<year>/<tool_name>/<slug>_<datetime>/
    """
    slug = re.sub(r'[^\w-]', '_', (client_short or 'client').strip().lower()).strip('_') or 'client'
    year = (start_date[:4] if start_date and len(start_date) >= 4 and start_date[:4].isdigit()
            else datetime.now(timezone.utc).strftime('%Y'))
    dt_str = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    path = _clients_base() / slug / year / tool_name / f"{slug}_{dt_str}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write_project_meta(project_dir: Path, tool: str, client_short: str,
                        year: str, version: str) -> None:
    """Write project_meta.json so Flask apps can discover this project."""
    try:
        (project_dir / "project_meta.json").write_text(
            json.dumps({
                "tool":         tool,
                "client_short": client_short,
                "year":         year,
                "created_at":   datetime.now(timezone.utc).isoformat(),
                "version":      version,
                "hostname":     socket.gethostname(),
            }, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass


# ── In-process state ──────────────────────────────────────────────────────────
_catalogue: dict[str, dict] = {}
_findings_collected: list[dict] = []

# ── Scope enforcement state ───────────────────────────────────────────────────
_scope_hosts: set[str] = set()
_scope_eui64s: set[str] = set()

# ── Graceful-shutdown flag ────────────────────────────────────────────────────
_shutdown = threading.Event()


# ── Protocol token emitters ───────────────────────────────────────────────────

def _tok(token: str, msg: str) -> None:
    print(f"{token} {msg}", flush=True)


def _log(msg: str) -> None:
    # §13b: persist to the run-dir audit log regardless of managed/standalone.
    if _RUNLOG is not None:
        try: _RUNLOG.info(msg)
        except Exception: pass
    if MANAGED:
        _tok(_SP_LOG, msg)
    else:
        print(msg, flush=True)


def _err(msg: str) -> None:
    if _RUNLOG is not None:
        try: _RUNLOG.error(msg)
        except Exception: pass
    if MANAGED:
        _tok(_SP_ERR, msg)
    else:
        print(f"[ERROR] {msg}", file=sys.stderr, flush=True)


def _status(phase: str, status: str, step: str = "") -> None:
    # §14j: persist the phase transition to the audit log with a timestamp.
    if _RUNLOG is not None:
        try:
            _RUNLOG.event(f"phase {phase}: {status}" + (f" — {step}" if step else ""))
        except Exception:
            pass
    payload = json.dumps({
        "phase": phase,
        "status": status,
        "step": step,
        "ts": datetime.now(timezone.utc).isoformat(),
    })
    if MANAGED:
        _tok(_SP_STATUS, payload)
    else:
        print(f"[STATUS] phase={phase} status={status} step={step}", flush=True)


def _finding(finding_id: str, output_file: str = "", data: Optional[dict] = None) -> None:
    entry = _catalogue.get(finding_id, {})
    rec = {
        "id": finding_id,
        "title": entry.get("title", finding_id),
        "severity": entry.get("severity", "HIGH"),
        "cvss_score": entry.get("cvss_score"),
        "cvss_vector": entry.get("cvss_vector", ""),
        "category": entry.get("category", ""),
        "description": entry.get("description", ""),
        "remediation": entry.get("remediation", ""),
        "data": data or {},
        "output_file": output_file,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    _findings_collected.append(rec)
    if MANAGED:
        _tok(_SP_FINDING, json.dumps(rec))
    else:
        _log(f"[FINDING] {finding_id} — {rec['title']} ({rec['severity']})")


def _prompt(msg: str) -> str:
    if MANAGED:
        _tok(_SP_PROMPT, msg)
        return ""
    try:
        return input(f"[?] {msg} > ").strip()
    except (EOFError, KeyboardInterrupt):
        return ""


# ── Findings catalogue ────────────────────────────────────────────────────────

def _load_catalogue() -> None:
    global _catalogue
    cat_path = _AETHER_U_DIR / "findings_catalogue.json"
    if cat_path.exists():
        try:
            data = json.loads(cat_path.read_text(encoding="utf-8"))
            entries = data.get("findings", data) if isinstance(data, dict) else data
            _catalogue = {e["id"]: e for e in entries if "id" in e}
            _log(f"[*] Catalogue loaded: {len(_catalogue)} finding definition(s)")
        except Exception as exc:
            _err(f"Catalogue load error: {exc}")
    else:
        _err(f"findings_catalogue.json not found at {cat_path}")


# ── Config loader ─────────────────────────────────────────────────────────────

def _load_config(path: Path) -> dict:
    defaults: dict = {
        "rtls_host": "",
        "rtls_port": 443,
        "rtls_platform": "sewio",
        "mqtt_host": "",
        "mqtt_port": 1883,
        "mqtt_topics": ["#"],
        "target_anchors": [],
        "target_tags": [],
        "gnuradio_device": "driver=hackrf",
        "uwb_channel": 5,
        "uwb_prf": 64,
        "timeout_per_phase": 300,
        "capture_duration": 1800,
        "phases": {
            "survey": True,
            "protocol_analysis": True,
            "active_interaction": True,
            "physical_attacks": False,
            "network_app": True,
        },
        "tools": {
            "nmap": "nmap",
            "mosquitto_sub": "mosquitto_sub",
            "mosquitto_pub": "mosquitto_pub",
            "sqlmap": "sqlmap",
            "tshark": "tshark",
            "gnuradio-companion": "gnuradio-companion",
            "python3": "python3",
            "curl": "curl",
        },
        "scope": {
            "hosts": [],
            "eui64s": [],
        },
        "credentials": {
            "username": "admin",
            "password": "admin",
        },
        "output_dir": "aether_u_output",
        "physical_access": False,
        "injection_authorized": False,
        "dos_authorized": False,
        "active_testing_authorized": False,
    }

    if not path.exists():
        _err(f"Config not found: {path} — using built-in defaults")
        return defaults

    try:
        user_cfg = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _err(f"Config parse error: {exc} — using built-in defaults")
        return defaults

    # Deep-merge user config over defaults
    merged = {**defaults}
    for k, v in user_cfg.items():
        if isinstance(v, dict) and isinstance(merged.get(k), dict):
            merged[k] = {**merged[k], **v}
        else:
            merged[k] = v
    return merged


# ── Scope helpers ─────────────────────────────────────────────────────────────

def _init_scope(cfg: dict) -> None:
    global _scope_hosts, _scope_eui64s
    scope = cfg.get("scope", {})
    _scope_hosts  = {h.upper() for h in scope.get("hosts", [])}
    _scope_eui64s = {e.upper() for e in scope.get("eui64s", [])}


def _in_scope_host(host: str) -> bool:
    if not _scope_hosts:
        return True
    return host.upper() in _scope_hosts


def _in_scope_eui64(eui64: str) -> bool:
    if not _scope_eui64s:
        return True
    return eui64.upper() in _scope_eui64s


# ── Tool helpers ──────────────────────────────────────────────────────────────

def _check_tool(name: str) -> Optional[str]:
    """Return the full path to 'name' if it exists on PATH, else None."""
    return shutil.which(name)


def _resolve_tool(cfg: dict, key: str) -> Optional[str]:
    """Resolve a tool from config tools dict; return command string if found."""
    tool_str = cfg.get("tools", {}).get(key, key)
    parts = tool_str.split()
    if shutil.which(parts[0]):
        return tool_str
    return None


# ── Subprocess helpers ────────────────────────────────────────────────────────

def _run(cmd: list, timeout: int = 60, cwd: Optional[str] = None,
         env: Optional[dict] = None) -> tuple[str, int]:
    """Run a command with timeout; return (stdout+stderr, returncode)."""
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            cwd=cwd,
            env=env,
        )
        return r.stdout + r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "(timeout)", -1
    except FileNotFoundError:
        return f"(executable not found: {cmd[0]})", 127
    except Exception as exc:
        return str(exc), -1


def _popen(cmd: list, **kwargs) -> subprocess.Popen:
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    return subprocess.Popen(cmd, **kwargs)


def _kill_proc(proc: subprocess.Popen, wait_secs: int = 5) -> None:
    try:
        proc.terminate()
        proc.wait(timeout=wait_secs)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=3)
        except Exception:
            pass
    except Exception:
        pass


# ── Findings persistence ──────────────────────────────────────────────────────

def _save_findings(output_dir: Path) -> None:
    out = output_dir / "findings_spectre.json"
    out.write_text(json.dumps(_findings_collected, indent=2), encoding="utf-8")
    _log(f"Findings written: {out} ({len(_findings_collected)} item(s))")


# ── HTTP helper ───────────────────────────────────────────────────────────────

def _http_get(url: str, timeout: int = 15,
              headers: Optional[dict] = None,
              username: Optional[str] = None,
              password: Optional[str] = None) -> tuple[int, str]:
    """Simple HTTP GET; returns (status_code, body). Returns (-1, err) on error."""
    try:
        req = urllib.request.Request(url, headers=headers or {})
        if username is not None and password is not None:
            import base64
            creds = base64.b64encode(f"{username}:{password}".encode()).decode()
            req.add_header("Authorization", f"Basic {creds}")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, str(exc.reason)
    except urllib.error.URLError as exc:
        return -1, str(exc.reason)
    except Exception as exc:
        return -1, str(exc)


def _http_post(url: str, data: dict, timeout: int = 15,
               headers: Optional[dict] = None,
               username: Optional[str] = None,
               password: Optional[str] = None) -> tuple[int, str]:
    """Simple HTTP POST with JSON body; returns (status_code, body)."""
    try:
        payload = json.dumps(data).encode("utf-8")
        hdrs = {"Content-Type": "application/json"}
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, data=payload, headers=hdrs, method="POST")
        if username is not None and password is not None:
            import base64
            creds = base64.b64encode(f"{username}:{password}".encode()).decode()
            req.add_header("Authorization", f"Basic {creds}")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, str(exc.reason)
    except urllib.error.URLError as exc:
        return -1, str(exc.reason)
    except Exception as exc:
        return -1, str(exc)


# ── Default credentials helper ────────────────────────────────────────────────

DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "sewio"),
    ("admin", "pozyx"),
    ("admin", "avalue"),
    ("root", "root"),
    ("root", "toor"),
    ("administrator", "administrator"),
]


def _try_default_creds(cfg: dict) -> Optional[tuple[str, str]]:
    """
    Attempt default credentials against the RTLS HTTP/HTTPS management console.
    Tries common login endpoints for Sewio, Pozyx, Avalue, and generic platforms.
    Returns (username, password) tuple on success, None if all fail.
    """
    host = cfg.get("rtls_host", "")
    port = cfg.get("rtls_port", 443)
    platform = cfg.get("rtls_platform", "sewio").lower()

    if not host:
        _log("[~] No rtls_host configured — skipping default credential check")
        return None

    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{host}:{port}"

    # Platform-specific login endpoints
    login_paths = ["/login", "/api/login", "/api/v1/login", "/api/v1/auth",
                   "/admin/login", "/management/login"]
    if platform == "sewio":
        login_paths = ["/api/auth", "/api/v1/auth", "/login"] + login_paths
    elif platform == "pozyx":
        login_paths = ["/api/v1/auth/login", "/login"] + login_paths
    elif platform == "avalue":
        login_paths = ["/cgi-bin/login.cgi", "/login"] + login_paths

    _log(f"[*] Testing {len(DEFAULT_CREDS)} default credential pairs against {base_url}")

    for username, password in DEFAULT_CREDS:
        if _shutdown.is_set():
            break
        # Try HTTP Basic Auth first
        for path in login_paths[:3]:
            url = f"{base_url}{path}"
            status, body = _http_get(url, timeout=8,
                                     username=username, password=password)
            if status in (200, 201, 302) and status != 401:
                _log(f"  [+] SUCCESS with HTTP Basic: {username}:{password} at {url} (HTTP {status})")
                return (username, password)

        # Try form-based POST login
        for path in login_paths[:3]:
            url = f"{base_url}{path}"
            status, body = _http_post(
                url,
                {"username": username, "password": password},
                timeout=8,
            )
            if status in (200, 201) and (
                "token" in body.lower() or
                "success" in body.lower() or
                "dashboard" in body.lower() or
                len(body) > 200
            ):
                _log(f"  [+] SUCCESS with POST login: {username}:{password} at {url} (HTTP {status})")
                return (username, password)

    _log("[~] Default credential test: no valid credentials found")
    return None


# ── Platform detection ────────────────────────────────────────────────────────

def _detect_platform(host: str, port: int, timeout: int = 10) -> str:
    """
    Probe the RTLS web interface to identify the platform (sewio, pozyx, avalue, generic).
    Returns a platform string.
    """
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{host}:{port}"

    probe_paths = ["/", "/index.html", "/login", "/api/v1/system/info"]
    combined = ""
    for path in probe_paths:
        status, body = _http_get(f"{base_url}{path}", timeout=timeout)
        if status > 0:
            combined += body.lower()
            if len(combined) > 10000:
                break

    if "sewio" in combined or "rtls studio" in combined:
        return "sewio"
    if "pozyx" in combined or "creator" in combined:
        return "pozyx"
    if "avalue" in combined or "rtls manager" in combined:
        return "avalue"
    if "lunasonde" in combined:
        return "lunasonde"
    return "generic"


# ── Phase 1: Survey ───────────────────────────────────────────────────────────

def _phase_survey(cfg: dict, project_dir: Path) -> None:
    """
    Phase 1: Network discovery of RTLS infrastructure.

    Runs nmap against the rtls_host and its /24 subnet to identify open RTLS
    ports (80, 443, 1883, 8883, 8080, 8443, 5000).  Attempts tshark capture
    to surface MQTT and CoAP broadcast traffic.  Tries default credentials
    against the RTLS web console.  Enumerates anchors and tags via the RTLS
    REST API using Sewio-style endpoints.  Detects the RTLS platform type.
    """
    phase_id = "survey"
    timeout = cfg.get("timeout_per_phase", 300)
    tools = cfg.get("tools", {})
    rtls_host = cfg.get("rtls_host", "")
    rtls_port = cfg.get("rtls_port", 443)
    scope = cfg.get("scope", {})
    scope_hosts = scope.get("hosts", [])

    survey_dir = project_dir / "survey"
    survey_dir.mkdir(parents=True, exist_ok=True)

    _status(phase_id, "running", "Starting UWB/RTLS network survey")
    _log("=" * 60)
    _log("AUTHORIZED USE ONLY. Explicit written permission required.")
    _log(f"Aether-U UWB/RTLS Penetration Test Orchestrator v{VERSION}")
    _log(f"RTLS Host : {rtls_host or '(not configured)'}")
    _log(f"RTLS Port : {rtls_port}")
    _log("=" * 60)

    if not rtls_host and not scope_hosts:
        _log("[~] No rtls_host or scope.hosts configured — network survey will be limited")

    # ── Determine scan targets ─────────────────────────────────────────────
    scan_targets = []
    if rtls_host:
        scan_targets.append(rtls_host)
        # Derive /24 subnet for broader sweep
        parts = rtls_host.split(".")
        if len(parts) == 4:
            subnet = ".".join(parts[:3]) + ".0/24"
            scan_targets.append(subnet)
    for h in scope_hosts:
        if h not in scan_targets:
            scan_targets.append(h)

    # ── nmap scan ─────────────────────────────────────────────────────────
    nmap_bin = _check_tool(tools.get("nmap", "nmap"))
    if nmap_bin and scan_targets:
        rtls_ports = "80,443,1883,8883,8080,8443,5000,5683,7000,9090"
        for target in scan_targets:
            if _shutdown.is_set():
                break
            out_base = survey_dir / f"nmap_{target.replace('/', '_').replace('.', '_')}"
            nmap_xml = str(out_base) + ".xml"
            nmap_txt = str(out_base) + ".txt"
            _log(f"[1] nmap: scanning {target} ports {rtls_ports}...")
            _status(phase_id, "running", f"nmap {target}")
            cmd = [
                nmap_bin, "-sV", "-sC", "--open",
                "-p", rtls_ports,
                "-oX", nmap_xml,
                "-oN", nmap_txt,
                "--host-timeout", "60s",
                target,
            ]
            out, rc = _run(cmd, timeout=min(timeout, 180))
            _log(out[:6000])
            _log(f"  nmap exit={rc}; XML saved to {nmap_xml}")

            # Check for MQTT on port 1883 (unauthenticated)
            if "1883/tcp" in out and "open" in out:
                _log("  [!] Port 1883 (MQTT) is open on this host")
                # Will be confirmed in protocol_analysis phase
    elif not nmap_bin:
        _log("[~] nmap not found — skipping port scan")

    # ── tshark passive capture (short window) ────────────────────────────
    tshark_bin = _check_tool(tools.get("tshark", "tshark"))
    capture_duration = min(cfg.get("capture_duration", 1800), 120)  # cap at 2 min for survey
    if tshark_bin:
        tshark_out = survey_dir / "survey_capture.pcap"
        _log(f"[1] tshark: passively capturing for {capture_duration}s (MQTT/CoAP filter)...")
        _status(phase_id, "running", "tshark passive capture")
        # Filter for MQTT (port 1883/8883) and CoAP (port 5683)
        cmd = [
            tshark_bin, "-i", "any",
            "-a", f"duration:{capture_duration}",
            "-f", "tcp port 1883 or tcp port 8883 or udp port 5683",
            "-w", str(tshark_out),
        ]
        out, rc = _run(cmd, timeout=capture_duration + 30)
        if tshark_out.exists() and tshark_out.stat().st_size > 0:
            _log(f"  [+] Capture saved: {tshark_out} ({tshark_out.stat().st_size} bytes)")
        else:
            _log(f"  [~] tshark capture: no traffic captured (rc={rc})")
    else:
        _log("[~] tshark not found — skipping passive capture")

    # ── Default credentials check ─────────────────────────────────────────
    if rtls_host:
        _status(phase_id, "running", "testing default credentials")
        valid_creds = _try_default_creds(cfg)
        if valid_creds:
            _finding(
                "AETHU-002",
                output_file=str(survey_dir / "default_creds.json"),
                data={
                    "rtls_host": rtls_host,
                    "username": valid_creds[0],
                    "password": valid_creds[1],
                    "platform": cfg.get("rtls_platform", "unknown"),
                },
            )
            (survey_dir / "default_creds.json").write_text(
                json.dumps({"host": rtls_host, "username": valid_creds[0],
                            "password": valid_creds[1]}, indent=2),
                encoding="utf-8",
            )

    # ── Platform detection ────────────────────────────────────────────────
    if rtls_host:
        _status(phase_id, "running", "detecting RTLS platform")
        detected = _detect_platform(rtls_host, rtls_port, timeout=10)
        _log(f"  [*] Platform detected: {detected}")
        (survey_dir / "platform.txt").write_text(detected, encoding="utf-8")
        if detected != cfg.get("rtls_platform", "generic"):
            _log(f"  [!] Detected platform ({detected}) differs from config ({cfg.get('rtls_platform')})")

    # ── RTLS REST API anchor / tag enumeration ────────────────────────────
    if rtls_host:
        _status(phase_id, "running", "enumerating anchors and tags via REST API")
        scheme = "https" if rtls_port in (443, 8443) else "http"
        base_url = f"{scheme}://{rtls_host}:{rtls_port}"
        creds = cfg.get("credentials", {})
        username = creds.get("username", "")
        password = creds.get("password", "")

        api_endpoints = [
            "/api/v1/anchors",
            "/api/v1/tags",
            "/api/v1/zones",
            "/api/v1/floors",
            "/api/v1/system/info",
            "/api/v1/sensors",
            "/api/sensors",
            "/api/anchors",
            "/api/tags",
        ]

        api_results: dict = {}
        for ep in api_endpoints:
            if _shutdown.is_set():
                break
            url = f"{base_url}{ep}"
            status, body = _http_get(url, timeout=8,
                                     username=username or None,
                                     password=password or None)
            _log(f"  GET {ep} -> HTTP {status} ({len(body)} bytes)")
            if status in (200, 201):
                api_results[ep] = body[:4000]
                # Check for unauthenticated access
                if not username:
                    _finding(
                        "AETHU-006",
                        output_file=str(survey_dir / "api_enum.json"),
                        data={"endpoint": url, "http_status": status,
                              "response_preview": body[:500]},
                    )

        (survey_dir / "api_enum.json").write_text(
            json.dumps(api_results, indent=2), encoding="utf-8"
        )

    # ── Check for HTTP vs HTTPS ───────────────────────────────────────────
    if rtls_host:
        http_url = f"http://{rtls_host}:80/"
        status_http, _ = _http_get(http_url, timeout=6)
        https_url = f"https://{rtls_host}:{rtls_port}/"
        status_https, _ = _http_get(https_url, timeout=6)
        if status_http > 0 and status_https < 0:
            _log("  [!] Management console accessible over HTTP only (no HTTPS)")
        elif status_http > 0 and status_https > 0:
            _log("  [!] Management console accessible over both HTTP and HTTPS — HTTP should be disabled")

    _status(phase_id, "complete", "Survey complete")
    _log(f"[1] Survey phase complete. Output: {survey_dir}")


# ── Phase 2: Protocol Analysis ────────────────────────────────────────────────

def _phase_protocol_analysis(cfg: dict, project_dir: Path) -> None:
    """
    Phase 2: Passive protocol examination.

    Subscribes to MQTT '#' wildcard topic using mosquitto_sub; captures all
    messages for capture_duration seconds.  Checks whether the broker accepts
    connections without credentials.  Parses position update messages to
    identify tag IDs, anchor IDs, and zone assignments.  Runs tshark to capture
    any UWB-to-IP gateway traffic.  Analyses MQTT payload structure for ranging
    data exposure.
    """
    phase_id = "protocol_analysis"
    timeout = cfg.get("timeout_per_phase", 300)
    capture_duration = cfg.get("capture_duration", 1800)
    tools = cfg.get("tools", {})
    mqtt_host = cfg.get("mqtt_host", "") or cfg.get("rtls_host", "")
    mqtt_port = cfg.get("mqtt_port", 1883)
    mqtt_topics = cfg.get("mqtt_topics", ["#"])

    proto_dir = project_dir / "protocol_analysis"
    proto_dir.mkdir(parents=True, exist_ok=True)

    if not mqtt_host:
        _log("[~] No mqtt_host configured — skipping protocol analysis phase")
        _status(phase_id, "skipped", "no mqtt_host configured")
        return

    mosquitto_sub = _check_tool(tools.get("mosquitto_sub", "mosquitto_sub"))
    tshark_bin    = _check_tool(tools.get("tshark", "tshark"))

    _status(phase_id, "running", "Starting MQTT/protocol analysis")
    _log(f"[2] MQTT host: {mqtt_host}:{mqtt_port}")

    # ── Test unauthenticated MQTT access ──────────────────────────────────
    unauth_mqtt = False
    if mosquitto_sub:
        _status(phase_id, "running", "testing unauthenticated MQTT access")
        _log(f"[2] Testing unauthenticated MQTT connection to {mqtt_host}:{mqtt_port}...")
        test_out = proto_dir / "mqtt_unauth_test.txt"
        # Try subscribing without credentials for 10 seconds
        cmd = [
            mosquitto_sub,
            "-h", mqtt_host,
            "-p", str(mqtt_port),
            "-t", "#",
            "-C", "5",          # capture first 5 messages then exit
            "--quiet",
        ]
        out, rc = _run(cmd, timeout=20)
        test_out.write_text(out, encoding="utf-8")
        _log(f"  mosquitto_sub (unauth) rc={rc}, output={out[:500]}")

        # rc=0 with output OR rc=0 with no error message indicates success
        if rc == 0 and "Connection refused" not in out and "error" not in out.lower():
            unauth_mqtt = True
            _log("  [!] MQTT broker accepts unauthenticated connections!")
            _finding(
                "AETHU-003",
                output_file=str(test_out),
                data={
                    "mqtt_host": mqtt_host,
                    "mqtt_port": mqtt_port,
                    "sample_output": out[:1000],
                },
            )
        elif "Connection refused" in out or rc != 0:
            _log("  [~] MQTT broker refused unauthenticated connection (authentication required)")
    else:
        _log("[~] mosquitto_sub not found — MQTT subscription tests skipped")

    # ── Subscribe and capture MQTT messages ──────────────────────────────
    if mosquitto_sub:
        creds = cfg.get("credentials", {})
        username = creds.get("username", "")
        password = creds.get("password", "")

        _log(f"[2] Subscribing to MQTT for {capture_duration}s...")
        _status(phase_id, "running", f"MQTT capture ({capture_duration}s)")
        mqtt_capture_file = proto_dir / "mqtt_capture.txt"
        all_messages: list[str] = []

        for topic in mqtt_topics:
            if _shutdown.is_set():
                break
            topic_file = proto_dir / f"mqtt_topic_{topic.replace('#','ALL').replace('/','_')}.txt"
            cap_duration = min(capture_duration // len(mqtt_topics), 600)

            cmd = [
                mosquitto_sub,
                "-h", mqtt_host,
                "-p", str(mqtt_port),
                "-t", topic,
                "-v",            # print topic with message
                "--quiet",
            ]
            if username:
                cmd += ["-u", username, "-P", password]

            topic_msgs: list[str] = []
            proc = None
            try:
                proc = _popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
                deadline = time.time() + cap_duration
                while time.time() < deadline and not _shutdown.is_set():
                    if proc.stdout is None:
                        break
                    try:
                        line = proc.stdout.readline()
                    except Exception:
                        break
                    if not line:
                        break
                    decoded = line.decode("utf-8", errors="replace").rstrip()
                    if decoded:
                        topic_msgs.append(decoded)
                        all_messages.append(decoded)
                        _log(f"  MQTT: {decoded[:200]}")
                        # Look for cleartext credentials in MQTT traffic
                        if re.search(r'(password|passwd|secret|token|api.?key)\s*[=:]\s*\S+',
                                     decoded, re.I):
                            _finding(
                                "AETHU-010",
                                output_file=str(topic_file),
                                data={"topic": topic, "sample": decoded[:500]},
                            )
            except Exception as exc:
                _err(f"MQTT capture error on topic {topic}: {exc}")
            finally:
                if proc is not None:
                    _kill_proc(proc)

            topic_file.write_text("\n".join(topic_msgs), encoding="utf-8")

        mqtt_capture_file.write_text("\n".join(all_messages), encoding="utf-8")
        _log(f"  [*] MQTT capture complete: {len(all_messages)} message(s)")

        # ── Analyse captured MQTT messages ────────────────────────────────
        _log("[2] Analysing captured MQTT messages...")
        tag_ids: set[str] = set()
        anchor_ids: set[str] = set()
        zone_ids: set[str] = set()
        ranging_exposed = False
        position_topics: list[str] = []

        for msg in all_messages:
            # Detect position update topics (Sewio-style: /api/v1/pos/*)
            if re.search(r'/pos/|/position|/location|tag\d+|anchor\d+', msg, re.I):
                position_topics.append(msg[:300])

            # Extract tag IDs
            for m in re.finditer(r'"tag[_\-]?id"\s*:\s*"?(\w+)"?', msg, re.I):
                tag_ids.add(m.group(1))
            for m in re.finditer(r'"tagId"\s*:\s*"?(\w+)"?', msg, re.I):
                tag_ids.add(m.group(1))

            # Extract anchor IDs
            for m in re.finditer(r'"anchor[_\-]?id"\s*:\s*"?(\w+)"?', msg, re.I):
                anchor_ids.add(m.group(1))

            # Extract zone IDs
            for m in re.finditer(r'"zone[_\-]?id"\s*:\s*"?(\w+)"?', msg, re.I):
                zone_ids.add(m.group(1))

            # Detect raw ranging / ToF data exposure
            if re.search(r'"tof"|"ranging"|"distance"\s*:', msg, re.I):
                ranging_exposed = True

        analysis = {
            "tag_ids": sorted(tag_ids),
            "anchor_ids": sorted(anchor_ids),
            "zone_ids": sorted(zone_ids),
            "ranging_data_exposed": ranging_exposed,
            "position_topics_count": len(position_topics),
            "total_messages": len(all_messages),
        }
        analysis_file = proto_dir / "mqtt_analysis.json"
        analysis_file.write_text(json.dumps(analysis, indent=2), encoding="utf-8")
        _log(f"  Tags found: {sorted(tag_ids)}")
        _log(f"  Anchors found: {sorted(anchor_ids)}")
        _log(f"  Zones found: {sorted(zone_ids)}")
        _log(f"  Ranging data exposed in MQTT: {ranging_exposed}")

        if ranging_exposed:
            _finding(
                "AETHU-008",
                output_file=str(analysis_file),
                data={"ranging_data_exposed": True,
                      "sample_topics": position_topics[:5]},
            )

    # ── tshark capture for UWB gateway traffic ────────────────────────────
    if tshark_bin:
        tshark_out = proto_dir / "uwb_gateway_capture.pcap"
        cap_dur = min(capture_duration, 300)
        _log(f"[2] tshark: capturing UWB gateway traffic for {cap_dur}s...")
        _status(phase_id, "running", "tshark UWB gateway capture")
        cmd = [
            tshark_bin, "-i", "any",
            "-a", f"duration:{cap_dur}",
            "-f", f"host {mqtt_host} or port 1883 or port 8883 or port 5683",
            "-w", str(tshark_out),
        ]
        out, rc = _run(cmd, timeout=cap_dur + 30)
        if tshark_out.exists() and tshark_out.stat().st_size > 0:
            _log(f"  [+] UWB gateway capture saved: {tshark_out}")
        else:
            _log(f"  [~] tshark: no traffic captured (rc={rc})")

    _status(phase_id, "complete", "Protocol analysis complete")
    _log(f"[2] Protocol analysis phase complete. Output: {proto_dir}")


# ── Phase 3: Active Interaction ───────────────────────────────────────────────

def _phase_active_interaction(cfg: dict, project_dir: Path) -> None:
    """
    Phase 3: Active testing (gated by active_testing_authorized).

    Tests MQTT injection by publishing malformed position data to known topics.
    Enumerates REST API paths for unauthenticated access.  Runs sqlmap against
    RTLS reporting endpoints.  Checks for XSS in tag label fields.
    Tests for IDOR by accessing sensor IDs without authorisation.
    """
    phase_id = "active_interaction"
    timeout = cfg.get("timeout_per_phase", 300)
    tools = cfg.get("tools", {})
    rtls_host = cfg.get("rtls_host", "")
    rtls_port = cfg.get("rtls_port", 443)
    mqtt_host = cfg.get("mqtt_host", "") or rtls_host
    mqtt_port = cfg.get("mqtt_port", 1883)
    active_auth = cfg.get("active_testing_authorized", False)
    injection_auth = cfg.get("injection_authorized", False)

    active_dir = project_dir / "active_interaction"
    active_dir.mkdir(parents=True, exist_ok=True)

    if not active_auth:
        _log("[!] active_testing_authorized=false — skipping active interaction phase")
        _log("    Set active_testing_authorized=true in config.json with explicit client authorisation")
        _status(phase_id, "skipped", "active_testing_authorized not set")
        return

    _status(phase_id, "running", "Starting active interaction testing")
    _log(f"[3] Active testing authorised — proceeding against {rtls_host}:{rtls_port}")

    mosquitto_pub = _check_tool(tools.get("mosquitto_pub", "mosquitto_pub"))
    sqlmap_bin    = _check_tool(tools.get("sqlmap", "sqlmap"))
    creds         = cfg.get("credentials", {})
    username      = creds.get("username", "")
    password      = creds.get("password", "")
    scheme        = "https" if rtls_port in (443, 8443) else "http"
    base_url      = f"{scheme}://{rtls_host}:{rtls_port}" if rtls_host else ""

    # ── MQTT injection test ───────────────────────────────────────────────
    if injection_auth and mosquitto_pub and mqtt_host:
        _status(phase_id, "running", "MQTT injection test")
        _log("[3] Testing MQTT position data injection...")
        injection_results: list[dict] = []

        inject_topics = [
            "sewio/position",
            "rtls/tags/test_tag_aetheru/position",
            "pozyx/position",
            "tags/AETHERU_TEST/location",
            "/api/v1/pos/test",
        ]
        inject_payload = json.dumps({
            "tagId": "AETHERU_INJECTION_TEST",
            "x": 9999.9,
            "y": 9999.9,
            "z": 0.0,
            "zoneId": "INJECTED_ZONE",
            "ts": datetime.now(timezone.utc).isoformat(),
        })

        for topic in inject_topics:
            if _shutdown.is_set():
                break
            cmd = [
                mosquitto_pub,
                "-h", mqtt_host,
                "-p", str(mqtt_port),
                "-t", topic,
                "-m", inject_payload,
            ]
            if username:
                cmd += ["-u", username, "-P", password]
            out, rc = _run(cmd, timeout=15)
            _log(f"  MQTT publish to '{topic}': rc={rc}")
            injection_results.append({"topic": topic, "rc": rc, "output": out[:200]})

        inj_file = active_dir / "mqtt_injection.json"
        inj_file.write_text(json.dumps(injection_results, indent=2), encoding="utf-8")

        # If any injection succeeded (rc=0), emit the finding
        if any(r["rc"] == 0 for r in injection_results):
            _finding(
                "AETHU-004",
                output_file=str(inj_file),
                data={"successful_topics": [r["topic"] for r in injection_results if r["rc"] == 0]},
            )
    elif not injection_auth:
        _log("[~] injection_authorized=false — MQTT injection test skipped")

    # ── REST API enumeration for unauthenticated endpoints ────────────────
    if base_url:
        _status(phase_id, "running", "REST API unauthenticated endpoint enumeration")
        _log("[3] Enumerating RTLS REST API for unauthenticated access...")
        api_paths = [
            "/api/v1/anchors", "/api/v1/tags", "/api/v1/zones", "/api/v1/floors",
            "/api/v1/system/info", "/api/v1/reports", "/api/v1/reports/positions",
            "/api/v1/config", "/api/v1/users", "/api/v1/firmware",
            "/api/v1/firmware/version", "/api/anchors", "/api/tags", "/api/zones",
            "/api/config", "/api/users", "/api/reports",
            "/management/api/anchors", "/management/api/tags",
            "/sewio/api/v1/tags", "/sewio/api/v1/anchors",
        ]
        api_unauth_results: list[dict] = []
        for ep in api_paths:
            if _shutdown.is_set():
                break
            url = f"{base_url}{ep}"
            # Try WITHOUT credentials first
            status_anon, body_anon = _http_get(url, timeout=8)
            # Then WITH credentials
            status_auth, body_auth = _http_get(url, timeout=8,
                                               username=username or None,
                                               password=password or None)
            result = {
                "endpoint": ep,
                "anon_status": status_anon,
                "auth_status": status_auth,
                "data_exposed": status_anon == 200,
            }
            api_unauth_results.append(result)
            if status_anon == 200:
                _log(f"  [!] Unauthenticated access: {ep} (HTTP 200, {len(body_anon)} bytes)")
                _finding(
                    "AETHU-006",
                    output_file=str(active_dir / "api_unauth.json"),
                    data={"endpoint": url, "response_preview": body_anon[:500]},
                )
            elif status_anon in (401, 403) and status_auth == 200:
                _log(f"  [*] Authenticated endpoint: {ep} (HTTP {status_auth})")

        (active_dir / "api_unauth.json").write_text(
            json.dumps(api_unauth_results, indent=2), encoding="utf-8"
        )

    # ── SQLi test with sqlmap ──────────────────────────────────────────────
    if sqlmap_bin and base_url:
        _status(phase_id, "running", "SQLi testing with sqlmap")
        _log("[3] Testing RTLS reporting endpoints for SQL injection...")
        sqli_targets = [
            f"{base_url}/api/v1/reports/positions?tagId=1&from=2024-01-01&to=2024-12-31",
            f"{base_url}/api/v1/reports?filter=1",
            f"{base_url}/report?id=1",
        ]
        sqli_dir = active_dir / "sqlmap"
        sqli_dir.mkdir(parents=True, exist_ok=True)
        for url in sqli_targets:
            if _shutdown.is_set():
                break
            _log(f"  sqlmap: {url}")
            cmd = [
                sqlmap_bin,
                "-u", url,
                "--batch",
                "--level=2",
                "--risk=1",
                "--output-dir", str(sqli_dir),
                "--timeout", "10",
                "--retries", "1",
            ]
            if username:
                cmd += ["--auth-type=Basic", f"--auth-cred={username}:{password}"]
            out, rc = _run(cmd, timeout=min(timeout, 120))
            _log(out[-3000:])
            sqli_file = active_dir / "sqlmap_summary.txt"
            with open(sqli_file, "a", encoding="utf-8") as fh:
                fh.write(f"\n--- {url} ---\n{out}\n")
            # Check for successful injection indicators
            if re.search(r'is vulnerable|parameter.*vulnerable|sql injection|sqlmap identified',
                         out, re.I):
                _finding(
                    "AETHU-005",
                    output_file=str(sqli_file),
                    data={"vulnerable_url": url,
                          "sqlmap_snippet": out[-1000:]},
                )
    elif not sqlmap_bin:
        _log("[~] sqlmap not found — SQL injection tests skipped")

    # ── XSS test via tag label API ────────────────────────────────────────
    if base_url:
        _status(phase_id, "running", "XSS test in tag label fields")
        _log("[3] Testing for XSS in tag label fields...")
        xss_payload = "<script>alert('AETHU-XSS-TEST')</script>"
        xss_payloads = [
            xss_payload,
            '"><img src=x onerror=alert(1)>',
            "';alert('xss')//",
        ]
        xss_results: list[dict] = []
        for tag_id in (cfg.get("target_tags") or ["1", "2", "100"]):
            for xss in xss_payloads:
                if _shutdown.is_set():
                    break
                patch_url = f"{base_url}/api/v1/tags/{tag_id}"
                status, body = _http_post(
                    patch_url,
                    {"label": xss, "name": xss},
                    username=username or None,
                    password=password or None,
                )
                if status in (200, 201):
                    # Verify the payload is reflected unsanitised
                    get_status, get_body = _http_get(
                        patch_url,
                        username=username or None,
                        password=password or None,
                    )
                    if xss in get_body:
                        _log(f"  [!] XSS payload reflected in tag {tag_id}: {xss}")
                        xss_results.append({"tag_id": tag_id, "payload": xss,
                                            "reflected": True})
                        _finding(
                            "AETHU-013",
                            output_file=str(active_dir / "xss_results.json"),
                            data={"tag_id": tag_id, "payload": xss,
                                  "endpoint": patch_url},
                        )
                        break

        (active_dir / "xss_results.json").write_text(
            json.dumps(xss_results, indent=2), encoding="utf-8"
        )

    # ── IDOR test ─────────────────────────────────────────────────────────
    if base_url:
        _status(phase_id, "running", "IDOR test on sensor/tag IDs")
        _log("[3] Testing for IDOR via sequential sensor and user IDs...")
        idor_results: list[dict] = []
        test_ids = list(range(1, 21))  # IDs 1-20
        resource_types = ["tags", "anchors", "users", "sensors"]

        for res_type in resource_types:
            prev_body = None
            unique_responses = 0
            for id_val in test_ids:
                if _shutdown.is_set():
                    break
                url = f"{base_url}/api/v1/{res_type}/{id_val}"
                status, body = _http_get(url, timeout=5,
                                         username=username or None,
                                         password=password or None)
                if status == 200 and body != prev_body:
                    unique_responses += 1
                    idor_results.append({
                        "resource_type": res_type,
                        "id": id_val,
                        "status": status,
                        "body_preview": body[:200],
                    })
                prev_body = body

            if unique_responses >= 3:
                _log(f"  [!] IDOR possible: {res_type} returns {unique_responses} unique records via sequential IDs")
                _finding(
                    "AETHU-014",
                    output_file=str(active_dir / "idor_results.json"),
                    data={"resource_type": res_type,
                          "unique_records_found": unique_responses,
                          "id_range_tested": "1-20"},
                )

        (active_dir / "idor_results.json").write_text(
            json.dumps(idor_results, indent=2), encoding="utf-8"
        )

    _status(phase_id, "complete", "Active interaction testing complete")
    _log(f"[3] Active interaction phase complete. Output: {active_dir}")


# ── Phase 4: Physical Attacks ─────────────────────────────────────────────────

def _phase_physical_attacks(cfg: dict, project_dir: Path) -> None:
    """
    Phase 4: Physical-layer attack assessment.

    Gate-checked by physical_access and injection_authorized flags.
    Describes the Ghost Peak attack vector and assesses susceptibility by
    checking chip firmware versions via the RTLS API.  Detects firmware
    update endpoints for unsigned OTA injection vectors.  Queries anchor
    hardware metadata to identify DW1000/DW3000 firmware versions known
    to be vulnerable to ranging attacks.
    """
    phase_id = "physical_attacks"
    timeout = cfg.get("timeout_per_phase", 300)
    physical_access   = cfg.get("physical_access", False)
    injection_auth    = cfg.get("injection_authorized", False)
    rtls_host         = cfg.get("rtls_host", "")
    rtls_port         = cfg.get("rtls_port", 443)

    phys_dir = project_dir / "physical_attacks"
    phys_dir.mkdir(parents=True, exist_ok=True)

    if not physical_access:
        _log("[!] physical_access=false — physical attack phase limited to passive assessment")
        _log("    Set physical_access=true in config.json when physical RF access is authorised")

    if not injection_auth:
        _log("[!] injection_authorized=false — RF injection tests skipped")
        _log("    Set injection_authorized=true with explicit RF testing authorisation")

    _status(phase_id, "running", "Starting physical/firmware assessment")

    # ── Ghost Peak susceptibility assessment ──────────────────────────────
    _log("[4] Ghost Peak Distance Reduction Attack — susceptibility assessment")
    _log("    CVE context: 2022 research by Jansen & Leu demonstrates that IEEE 802.15.4z")
    _log("    HRP UWB devices operating in SP0 mode (no STS) are susceptible to early-pulse")
    _log("    injection that causes receivers to lock onto an attacker-generated leading edge,")
    _log("    reporting shorter distance than actual without breaking cryptography.")
    _log("    Full execution requires: DWM3000EVB + custom firmware OR SDR with UWB frontend.")

    ghost_peak_data: dict = {
        "attack": "Ghost Peak",
        "reference": "Jansen & Leu, 2022 — Ghost Peak: Practical Distance Reduction Attacks Against HRP UWB Ranging",
        "ieee_standard": "IEEE 802.15.4z",
        "vulnerable_chips": ["DW1000", "DW3000 (SP0 mode)"],
        "mitigation": "IEEE 802.15.4z STS SP3 mode enforcement",
        "physical_access_available": physical_access,
        "injection_authorized": injection_auth,
        "anchor_firmware_checked": False,
        "anchor_firmware_versions": [],
    }

    # ── Firmware version check via RTLS API ───────────────────────────────
    if rtls_host:
        scheme = "https" if rtls_port in (443, 8443) else "http"
        base_url = f"{scheme}://{rtls_host}:{rtls_port}"
        creds    = cfg.get("credentials", {})
        username = creds.get("username", "")
        password = creds.get("password", "")

        _log("[4] Querying RTLS API for anchor firmware versions...")
        firmware_endpoints = [
            "/api/v1/anchors",
            "/api/v1/sensors",
            "/api/v1/firmware/version",
            "/api/v1/system/info",
        ]
        firmware_data: list[dict] = []
        vulnerable_anchors: list[dict] = []

        for ep in firmware_endpoints:
            if _shutdown.is_set():
                break
            url = f"{base_url}{ep}"
            status, body = _http_get(url, timeout=8,
                                     username=username or None,
                                     password=password or None)
            if status == 200:
                _log(f"  GET {ep} -> HTTP 200 ({len(body)} bytes)")
                firmware_data.append({"endpoint": ep, "body": body[:2000]})
                # Parse anchor firmware versions
                for m in re.finditer(
                    r'"firmware[_\-]?version"\s*:\s*"([^"]+)"',
                    body, re.I
                ):
                    version_str = m.group(1)
                    # 2026-06-11 review FP fix: prior code marked any DW1000
                    # OR DW3000 chip as "vulnerable" purely on chip detection.
                    # That's wrong — DW3000 in SP3 mode is NOT vulnerable to
                    # Ghost Peak, and even DW1000 requires SP0/short-STS mode.
                    # Gate the emission on explicit STS-mode evidence in the
                    # response body. When mode is undetermined, label the
                    # finding as Tentative rather than Certain.
                    is_vulnerable = False
                    chip_guess = "unknown"
                    sts_mode  = "unknown"
                    confidence = "Tentative"
                    # Look for STS mode markers in surrounding response
                    _sts_evidence = body[:1500].lower()
                    if any(m in _sts_evidence for m in
                            ("sp0_mode","sp_mode\":0","sts_disabled","\"sts\":false",
                             "short_sts","mode\":\"sp0\"")):
                        sts_mode  = "SP0"
                        is_vulnerable = True
                        confidence = "Certain"
                    elif any(m in _sts_evidence for m in
                              ("sp3_mode","sp_mode\":3","sts_enabled","\"sts\":true",
                               "mode\":\"sp3\"","full_sts")):
                        sts_mode  = "SP3"
                        is_vulnerable = False
                        confidence = "Certain"
                    if re.search(r'dw1000|dwm1000', body[:500], re.I):
                        chip_guess = "DW1000"
                        # DW1000 has NO SP3 support, so it's vulnerable when
                        # any STS-based attack applies. Still surface as
                        # Tentative when we can't see STS markers.
                        if sts_mode == "unknown":
                            is_vulnerable = True   # default for DW1000
                            confidence = "Tentative"
                    elif re.search(r'dw3000|dwm3000', body[:500], re.I):
                        chip_guess = "DW3000"
                        # DW3000 + SP3 is NOT vulnerable. Don't fire.
                        if sts_mode == "unknown":
                            # No mode evidence — don't auto-flag as vuln;
                            # emit an INFO follow-up to manually verify.
                            is_vulnerable = False
                            confidence = "Tentative"
                            _log(f"  DW3000 STS mode undetermined — skipping "
                                 f"Ghost Peak emission (manual verify required)")

                    anchor_info = {
                        "firmware_version":     version_str,
                        "chip":                 chip_guess,
                        "sts_mode":             sts_mode,
                        "confidence":           confidence,
                        "potentially_vulnerable": is_vulnerable,
                    }
                    if is_vulnerable:
                        vulnerable_anchors.append(anchor_info)
                    _log(f"  Anchor firmware: {version_str} (chip: {chip_guess}, "
                         f"sts_mode: {sts_mode}, vulnerable: {is_vulnerable}, "
                         f"confidence: {confidence})")

        ghost_peak_data["anchor_firmware_checked"] = True
        ghost_peak_data["anchor_firmware_versions"] = vulnerable_anchors

        if vulnerable_anchors:
            _finding(
                "AETHU-001",
                output_file=str(phys_dir / "ghost_peak_assessment.json"),
                data=ghost_peak_data,
            )

    # ── Detect firmware update endpoint ──────────────────────────────────
    if rtls_host:
        _status(phase_id, "running", "checking firmware update endpoints")
        _log("[4] Scanning for unsigned firmware update endpoints...")
        fw_update_paths = [
            "/api/v1/firmware/update",
            "/api/v1/anchors/firmware",
            "/api/v1/sensors/firmware",
            "/firmware/upload",
            "/management/firmware",
            "/ota/update",
            "/api/ota",
        ]
        exposed_fw_endpoints: list[dict] = []
        for ep in fw_update_paths:
            if _shutdown.is_set():
                break
            url = f"{base_url}{ep}"
            status, body = _http_get(url, timeout=6,
                                     username=username or None,
                                     password=password or None)
            # 200, 201, 405 (Method Not Allowed) all confirm the endpoint exists
            if status in (200, 201, 405, 400):
                _log(f"  [!] Firmware update endpoint reachable: {ep} (HTTP {status})")
                exposed_fw_endpoints.append({
                    "endpoint": ep,
                    "http_status": status,
                    "response_preview": body[:200],
                })
        fw_file = phys_dir / "firmware_endpoints.json"
        fw_file.write_text(json.dumps(exposed_fw_endpoints, indent=2), encoding="utf-8")

        if exposed_fw_endpoints:
            _finding(
                "AETHU-009",
                output_file=str(fw_file),
                data={"firmware_endpoints": exposed_fw_endpoints},
            )

    # ── UWB STS configuration check ───────────────────────────────────────
    if rtls_host:
        _log("[4] Checking UWB STS (Scrambled Timestamp Sequence) configuration...")
        sts_endpoints = [
            "/api/v1/config/uwb",
            "/api/v1/system/uwb",
            "/api/v1/config",
        ]
        sts_config_found = False
        for ep in sts_endpoints:
            if _shutdown.is_set():
                break
            url = f"{base_url}{ep}"
            status, body = _http_get(url, timeout=6,
                                     username=username or None,
                                     password=password or None)
            if status == 200:
                sts_enabled = bool(re.search(r'"sts[_\-]?enabled"\s*:\s*true', body, re.I))
                sp3_mode    = bool(re.search(r'"sp3"|"sts[_\-]?mode"\s*:\s*"?sp3"?', body, re.I))
                if not sts_enabled or not sp3_mode:
                    _log("  [!] UWB STS not enabled or not in SP3 mode — Ghost Peak vulnerability likely")
                    _finding(
                        "AETHU-007",
                        output_file=str(phys_dir / "sts_config.json"),
                        data={"endpoint": ep,
                              "sts_enabled": sts_enabled,
                              "sp3_mode": sp3_mode,
                              "body_preview": body[:500]},
                    )
                    sts_config_found = True
                break

        if not sts_config_found:
            _log("  [~] STS configuration endpoint not found or not accessible — "
                 "assume cleartext ranging (AETHU-008) applies")
            ghost_peak_data_path = phys_dir / "ghost_peak_assessment.json"
            ghost_peak_data_path.write_text(
                json.dumps(ghost_peak_data, indent=2), encoding="utf-8"
            )

    # ── Physical frame injection — documentation only ─────────────────────
    if physical_access and injection_auth:
        _log("[4] Physical frame injection test authorised:")
        _log("    Full execution requires a DWM3000EVB (or equivalent UWB-capable SDR)")
        _log("    with custom firmware that can transmit IEEE 802.15.4z HRP UWB frames.")
        _log("    Reference implementation: https://github.com/uwiduri/uwb-sniffer (passive)")
        _log("    Forged anchor frames should be directed at the target tag during a ranging session.")
        _log("    Record any displacement in reported position vs. ground truth GPS.")
        _finding(
            "AETHU-015",
            output_file=str(phys_dir / "physical_injection_report.txt"),
            data={
                "physical_access": True,
                "injection_authorized": True,
                "note": "Physical UWB frame injection authorised — hardware execution required",
            },
        )
        (phys_dir / "physical_injection_report.txt").write_text(
            "Physical UWB frame injection test authorised.\n"
            "Execute with DWM3000EVB + custom IEEE 802.15.4z SP0 frame transmitter.\n"
            "Target: inject Poll Response frames impersonating anchor EUI-64s identified "
            "in the survey phase.\n"
            "Expected result: RTLS position engine displaces tag location by "
            "0.5-5m depending on anchor geometry.\n",
            encoding="utf-8",
        )
    else:
        _log("[4] Physical UWB frame injection: skipped (physical_access or injection_authorized not set)")

    _status(phase_id, "complete", "Physical attack assessment complete")
    _log(f"[4] Physical attacks phase complete. Output: {phys_dir}")


# ── Phase 5: Network / Application Layer ─────────────────────────────────────

def _phase_network_app(cfg: dict, project_dir: Path) -> None:
    """
    Phase 5: Network and application layer testing.

    Tests RTLS API for JWT or session token weaknesses.  Checks for
    unencrypted HTTP vs HTTPS.  Enumerates all REST endpoints via common
    paths.  Tests MQTT for retain message attacks.  Checks for MQTT broker
    version disclosure.  Verifies TLS configuration.
    """
    phase_id = "network_app"
    timeout  = cfg.get("timeout_per_phase", 300)
    tools    = cfg.get("tools", {})
    rtls_host = cfg.get("rtls_host", "")
    rtls_port = cfg.get("rtls_port", 443)
    mqtt_host = cfg.get("mqtt_host", "") or rtls_host
    mqtt_port = cfg.get("mqtt_port", 1883)
    active_auth = cfg.get("active_testing_authorized", False)

    netapp_dir = project_dir / "network_app"
    netapp_dir.mkdir(parents=True, exist_ok=True)

    _status(phase_id, "running", "Starting network/application layer testing")

    creds    = cfg.get("credentials", {})
    username = creds.get("username", "")
    password = creds.get("password", "")
    scheme   = "https" if rtls_port in (443, 8443) else "http"
    base_url = f"{scheme}://{rtls_host}:{rtls_port}" if rtls_host else ""

    # ── HTTP vs HTTPS check ───────────────────────────────────────────────
    if rtls_host:
        _status(phase_id, "running", "HTTP vs HTTPS check")
        _log("[5] Checking HTTP vs HTTPS accessibility...")

        for test_port, test_scheme in [(80, "http"), (443, "https"), (8080, "http"), (8443, "https")]:
            url = f"{test_scheme}://{rtls_host}:{test_port}/"
            status, body = _http_get(url, timeout=6)
            if status > 0:
                _log(f"  [*] {test_scheme.upper()} port {test_port}: accessible (HTTP {status})")
                if test_scheme == "http":
                    _log(f"  [!] Management console reachable over cleartext HTTP on port {test_port}")
                    (netapp_dir / "cleartext_http.txt").write_text(
                        f"HTTP accessible: {url} — HTTP {status}\n",
                        encoding="utf-8",
                    )

    # ── JWT / session token weakness test ─────────────────────────────────
    if base_url:
        _status(phase_id, "running", "JWT / session token analysis")
        _log("[5] Testing JWT / session token configuration...")
        jwt_issues: list[dict] = []

        auth_endpoints = [
            "/api/v1/auth", "/api/auth", "/api/v1/login", "/login",
        ]
        for ep in auth_endpoints:
            if _shutdown.is_set():
                break
            url = f"{base_url}{ep}"
            status, body = _http_post(
                url,
                {"username": username or "admin", "password": password or "admin"},
                timeout=8,
            )
            if status in (200, 201):
                # Check for JWT in response
                jwt_match = re.search(
                    r'(eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*)',
                    body,
                )
                if jwt_match:
                    token = jwt_match.group(1)
                    parts = token.split(".")
                    if len(parts) == 3:
                        import base64 as b64
                        # Decode header without padding
                        header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
                        try:
                            header = json.loads(b64.urlsafe_b64decode(header_b64).decode())
                        except Exception:
                            header = {}
                        alg = header.get("alg", "unknown")
                        _log(f"  [*] JWT found at {ep}: alg={alg}")
                        if alg.upper() in ("NONE", "HS256") or alg == "unknown":
                            _log(f"  [!] JWT uses weak/none algorithm: {alg}")
                            jwt_issues.append({
                                "endpoint": ep,
                                "algorithm": alg,
                                "token_preview": token[:80] + "...",
                            })

        jwt_file = netapp_dir / "jwt_analysis.json"
        jwt_file.write_text(json.dumps(jwt_issues, indent=2), encoding="utf-8")
        if jwt_issues:
            _log(f"  [!] JWT weaknesses found: {len(jwt_issues)} issue(s)")

    # ── Comprehensive API endpoint enumeration ────────────────────────────
    if base_url:
        _status(phase_id, "running", "comprehensive API endpoint enumeration")
        _log("[5] Enumerating all common RTLS API paths...")
        all_api_paths = [
            # Sewio paths
            "/api/v1/anchors", "/api/v1/tags", "/api/v1/zones", "/api/v1/floors",
            "/api/v1/config", "/api/v1/users", "/api/v1/reports",
            "/api/v1/reports/positions", "/api/v1/reports/zones",
            "/api/v1/firmware", "/api/v1/firmware/version",
            "/api/v1/system/info", "/api/v1/system/status", "/api/v1/system/logs",
            "/api/v1/auth", "/api/v1/auth/logout",
            # Generic RTLS paths
            "/api/anchors", "/api/tags", "/api/zones", "/api/config",
            "/api/users", "/api/reports", "/api/sensors", "/api/devices",
            # Pozyx paths
            "/api/v1/auth/login", "/api/v1/devices", "/api/v1/positions",
            # Management paths
            "/management/api/anchors", "/management/api/tags", "/admin/api",
            # Swagger / OpenAPI
            "/swagger.json", "/openapi.json", "/api-docs",
            "/api/v1/swagger.json", "/swagger-ui.html",
        ]
        enum_results: list[dict] = []
        for ep in all_api_paths:
            if _shutdown.is_set():
                break
            url = f"{base_url}{ep}"
            status_anon, body_anon = _http_get(url, timeout=5)
            if status_anon == 200:
                _log(f"  [+] Found (anon): {ep} ({len(body_anon)} bytes)")
                enum_results.append({"endpoint": ep, "status": status_anon,
                                     "body_size": len(body_anon),
                                     "preview": body_anon[:300]})
            elif status_anon in (401, 403):
                enum_results.append({"endpoint": ep, "status": status_anon,
                                     "body_size": 0, "preview": ""})

        enum_file = netapp_dir / "api_enumeration.json"
        enum_file.write_text(json.dumps(enum_results, indent=2), encoding="utf-8")
        open_endpoints = [r for r in enum_results if r["status"] == 200]
        _log(f"  [*] Open endpoints found: {len(open_endpoints)}")

    # ── MQTT broker version disclosure ───────────────────────────────────
    if mqtt_host:
        _status(phase_id, "running", "MQTT broker version disclosure check")
        _log("[5] Checking MQTT broker for version disclosure...")
        mosquitto_sub = _check_tool(tools.get("mosquitto_sub", "mosquitto_sub"))
        if mosquitto_sub:
            # Mosquitto publishes version on $SYS/broker/version
            cmd = [
                mosquitto_sub,
                "-h", mqtt_host,
                "-p", str(mqtt_port),
                "-t", "$SYS/#",
                "-C", "20",
                "--quiet",
            ]
            if username:
                cmd += ["-u", username, "-P", password]
            out, rc = _run(cmd, timeout=20)
            sys_topics_file = netapp_dir / "mqtt_sys_topics.txt"
            sys_topics_file.write_text(out, encoding="utf-8")
            if out.strip():
                _log(f"  [*] MQTT $SYS topics disclosed:\n{out[:2000]}")
                # Look for version info
                version_m = re.search(r'mosquitto version\s+([\d\.]+)', out, re.I)
                if version_m:
                    _log(f"  [*] MQTT broker version: {version_m.group(1)}")
        else:
            _log("[~] mosquitto_sub not found — MQTT version check skipped")

    # ── MQTT retain message attack test ──────────────────────────────────
    if mqtt_host and active_auth:
        _status(phase_id, "running", "MQTT retain message attack test")
        _log("[5] Testing MQTT retain message attack...")
        mosquitto_pub = _check_tool(tools.get("mosquitto_pub", "mosquitto_pub"))
        if mosquitto_pub:
            retain_topic = "aether_u/retain_test"
            retain_payload = json.dumps({
                "aether_u": "retain_test",
                "ts": datetime.now(timezone.utc).isoformat(),
            })
            cmd = [
                mosquitto_pub,
                "-h", mqtt_host,
                "-p", str(mqtt_port),
                "-t", retain_topic,
                "-m", retain_payload,
                "-r",    # retain flag
            ]
            if username:
                cmd += ["-u", username, "-P", password]
            out, rc = _run(cmd, timeout=10)
            retain_file = netapp_dir / "mqtt_retain_test.txt"
            retain_file.write_text(f"rc={rc}\n{out}", encoding="utf-8")
            if rc == 0:
                _log("  [*] MQTT retain message published successfully — broker allows retained messages")
                # Clean up retained message
                clean_cmd = cmd[:-2] + ["-m", ""]  # empty payload clears retain
                _run(clean_cmd, timeout=10)

    # ── MQTT cleartext credential check ──────────────────────────────────
    if mqtt_host and mqtt_port == 1883:
        _status(phase_id, "running", "MQTT cleartext credential transmission check")
        _log("[5] MQTT port 1883 in use — credentials transmitted in cleartext")
        if username:
            _finding(
                "AETHU-010",
                output_file=str(netapp_dir / "mqtt_cleartext.txt"),
                data={
                    "mqtt_host": mqtt_host,
                    "mqtt_port": mqtt_port,
                    "tls_encrypted": False,
                    "cleartext_port": 1883,
                },
            )
            (netapp_dir / "mqtt_cleartext.txt").write_text(
                f"MQTT cleartext credential transmission detected.\n"
                f"Host: {mqtt_host}:{mqtt_port}\n"
                f"Credentials transmitted without TLS encryption.\n",
                encoding="utf-8",
            )

    # ── DoS / RF flooding check (documentation only) ─────────────────────
    if cfg.get("dos_authorized", False):
        _status(phase_id, "running", "RF flooding DoS assessment")
        _log("[5] RF flooding / DoS authorised — documenting attack vector:")
        _log("    UWB channel saturation requires an SDR or custom UWB hardware")
        _log("    capable of transmitting high-rate IEEE 802.15.4 pulses on the")
        _log("    configured channel (default: channel 5, PRF 64 MHz).")
        _log("    Monitor RTLS position update rate during transmission to confirm DoS.")
        _finding(
            "AETHU-012",
            output_file=str(netapp_dir / "dos_assessment.txt"),
            data={
                "uwb_channel": cfg.get("uwb_channel", 5),
                "uwb_prf": cfg.get("uwb_prf", 64),
                "dos_authorized": True,
                "note": "RF flooding DoS documented — hardware execution required",
            },
        )
        (netapp_dir / "dos_assessment.txt").write_text(
            "RF Flooding / DoS test authorised.\n"
            f"Target channel: {cfg.get('uwb_channel', 5)}, PRF: {cfg.get('uwb_prf', 64)} MHz\n"
            "Execute with SDR + UWB frontend or DWM3000EVB with high-rate TX firmware.\n"
            "Observe RTLS position update rate reduction during transmission.\n",
            encoding="utf-8",
        )

    _status(phase_id, "complete", "Network/application layer testing complete")
    _log(f"[5] Network/app phase complete. Output: {netapp_dir}")


# ── Phase map ──────────────────────────────────────────────────────────────────

PHASES: dict[str, dict] = {
    "survey": {
        "label": "Network Survey",
        "description": "Network discovery of RTLS infrastructure, nmap, default creds, REST API enumeration",
        "fn": _phase_survey,
        "config_key": "survey",
    },
    "protocol_analysis": {
        "label": "Protocol Analysis",
        "description": "Passive MQTT/UWB protocol examination, topic capture, position data parsing",
        "fn": _phase_protocol_analysis,
        "config_key": "protocol_analysis",
    },
    "active_interaction": {
        "label": "Active Interaction",
        "description": "MQTT injection, REST API testing, SQLi, XSS, IDOR (requires active_testing_authorized)",
        "fn": _phase_active_interaction,
        "config_key": "active_interaction",
    },
    "physical_attacks": {
        "label": "Physical Attacks",
        "description": "Ghost Peak susceptibility, firmware version checks, OTA update endpoints (requires physical_access)",
        "fn": _phase_physical_attacks,
        "config_key": "physical_attacks",
    },
    "network_app": {
        "label": "Network / Application",
        "description": "JWT analysis, HTTP vs HTTPS, full API enumeration, MQTT broker disclosure",
        "fn": _phase_network_app,
        "config_key": "network_app",
    },
}


# ── CLI ────────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="aether_u.py",
        description=(
            "Aether-U — UWB / RTLS Penetration Test Orchestrator v" + VERSION + "\n"
            "Automated security assessment for UWB (IEEE 802.15.4z) RTLS platforms.\n"
            "Supports Sewio RTLS Studio, Pozyx Creator, Avalue, and generic RTLS systems."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full assessment against Sewio RTLS Studio:
  python3 aether_u.py --config config.json --project /tmp/rtls_audit

  # Run a single phase:
  python3 aether_u.py --phase survey --config config.json

  # Passive protocol analysis only:
  python3 aether_u.py --phase protocol_analysis --config config.json --project /tmp/output

  # List available phases:
  python3 aether_u.py --list-phases

  # Spectre managed mode (emit protocol tokens to stdout):
  SPECTRE_MANAGED=1 python3 aether_u.py --config config.json
""",
    )
    p.add_argument(
        "--config", metavar="FILE",
        default=str(_AETHER_U_DIR / "config.json"),
        help="Path to config.json (default: ./config.json)",
    )
    p.add_argument(
        "--project", metavar="DIR",
        default=None,
        help="Output directory for assessment results (overrides config output_dir)",
    )
    p.add_argument(
        "--phase", metavar="NAME",
        default=None,
        help="Run a single phase by name (see --list-phases)",
    )
    p.add_argument(
        "--list-phases",
        action="store_true",
        help="List available phases and exit",
    )
    p.add_argument(
        "--version",
        action="store_true",
        help="Print version and exit",
    )
    return p.parse_args()


# ── Signal handlers ───────────────────────────────────────────────────────────

def _handle_signal(signum, frame) -> None:
    sig_name = signal.Signals(signum).name
    _err(f"Signal received: {sig_name} — requesting graceful shutdown")
    if _PAUSE is not None:
        _act = "killed_user" if signum == signal.SIGINT else "killed_crucible"
        _rsn = "KeyboardInterrupt" if signum == signal.SIGINT else "SIGTERM"
        _PAUSE.write_stop_reason(_act, _rsn,
                                 initiated_by="user" if signum == signal.SIGINT else "external")
    _shutdown.set()


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    args = _parse_args()

    if args.version:
        print(f"Aether-U v{VERSION}")
        sys.exit(0)

    if args.list_phases:
        print(f"\nAether-U v{VERSION} — Available Phases\n")
        print(f"{'Phase Name':<22} {'Label':<28} Description")
        print("-" * 90)
        for name, meta in PHASES.items():
            print(f"  {name:<20} {meta['label']:<28} {meta['description']}")
        print()
        sys.exit(0)

    _load_catalogue()

    config_path = Path(args.config)
    cfg = _load_config(config_path)

    # Determine project output directory
    if args.project:
        project_dir = Path(args.project)
    else:
        _cs = (cfg.get("client_short") or "").strip()
        _sd = (cfg.get("start_date") or "").strip()
        project_dir = _build_project_dir(_cs, _sd, os.environ.get("SPECTRE_TOOL_ID", "aether-u"))

    project_dir.mkdir(parents=True, exist_ok=True)
    # §13b/§14j/§14k: canonical run-dir audit log + own-version startup EVENT.
    global _RUNLOG
    if _el is not None:
        try:
            _RUNLOG = _el.EventLogger(project_dir / "scan.log",
                                       errors_path=project_dir / "errors.log")
            _RUNLOG.event(f"Aether-U v{VERSION} started")
        except Exception:
            _RUNLOG = None

    global _PAUSE
    if _pp is not None:
        _PAUSE = _pp.PauseManager(str(project_dir), "aether-u")
        _PAUSE.start_watcher(grace_period=60)
        _resumed = os.environ.get("CRUCIBLE_RESUME") == "1"
        _PAUSE.log_run_type(resumed=_resumed)
        if _resumed:
            _PAUSE.cleanup_incomplete()

    _log(f"[*] Aether-U v{VERSION} starting")
    _log(f"[*] Project directory: {project_dir.resolve()}")
    _log(f"[*] Config: {config_path.resolve()}")
    _log(f"[*] RTLS host: {cfg.get('rtls_host', '(not set)')}")
    _log(f"[*] RTLS platform: {cfg.get('rtls_platform', 'unknown')}")
    _log(f"[*] MQTT: {cfg.get('mqtt_host', '') or cfg.get('rtls_host', '(not set)')}:{cfg.get('mqtt_port', 1883)}")
    _log(f"[*] SPECTRE_MANAGED: {MANAGED}")

    _init_scope(cfg)
    scope = cfg.get("scope", {})
    scope_hosts  = scope.get("hosts", [])
    scope_eui64s = scope.get("eui64s", [])
    _log(f"[*] Scope — hosts: {scope_hosts or '(all)'}, eui64s: {scope_eui64s or '(all)'}")

    # Write run metadata
    run_meta = {
        "tool": "Aether-U",
        "version": VERSION,
        "started": datetime.now(timezone.utc).isoformat(),
        "config": str(config_path.resolve()),
        "rtls_host": cfg.get("rtls_host", ""),
        "rtls_platform": cfg.get("rtls_platform", ""),
        "phase_requested": args.phase,
    }
    (project_dir / "run_meta.json").write_text(
        json.dumps(run_meta, indent=2), encoding="utf-8"
    )
    _write_project_meta(
        project_dir,
        tool=os.environ.get("SPECTRE_TOOL_ID", "aether-u"),
        client_short=cfg.get("client_short", ""),
        year=((cfg.get("start_date") or "")[:4] or datetime.now(timezone.utc).strftime("%Y")),
        version=VERSION,
    )

    # ── Phase execution ───────────────────────────────────────────────────
    phases_cfg = cfg.get("phases", {})

    if args.phase:
        # Run a single requested phase
        if args.phase not in PHASES:
            _err(f"Unknown phase: {args.phase}. Use --list-phases to see available phases.")
            sys.exit(1)
        meta = PHASES[args.phase]
        _log(f"\n{'=' * 60}")
        _log(f"  Running phase: {meta['label']}")
        _log(f"{'=' * 60}")
        try:
            meta["fn"](cfg, project_dir)
        except KeyboardInterrupt:
            _err("Interrupted by user")
        except Exception as exc:
            _err(f"Phase {args.phase} error: {exc}")
            import traceback
            _err(traceback.format_exc())
    else:
        # Run all enabled phases in sequence
        for phase_name, meta in PHASES.items():
            if _PAUSE and _PAUSE.check_and_pause():
                sys.exit(_pp.EXIT_PAUSED)
            if _shutdown.is_set():
                _log("Shutdown requested — stopping phase execution")
                break
            config_key = meta["config_key"]
            if not phases_cfg.get(config_key, True):
                _log(f"[~] Phase '{phase_name}' disabled in config — skipping")
                continue
            _log(f"\n{'=' * 60}")
            _log(f"  Phase: {meta['label']}")
            _log(f"{'=' * 60}")
            try:
                meta["fn"](cfg, project_dir)
            except KeyboardInterrupt:
                _err("Interrupted by user")
                _shutdown.set()
                break
            except Exception as exc:
                _err(f"Phase {phase_name} error: {exc}")
                import traceback
                _err(traceback.format_exc())

    # ── Finalise ──────────────────────────────────────────────────────────
    if _PAUSE:
        _PAUSE.write_stop_reason("completed", "all_phases_done")
    _save_findings(project_dir)
    run_meta["finished"] = datetime.now(timezone.utc).isoformat()
    run_meta["findings_count"] = len(_findings_collected)
    (project_dir / "run_meta.json").write_text(
        json.dumps(run_meta, indent=2), encoding="utf-8"
    )

    _log(f"\n[*] Aether-U assessment complete.")
    _log(f"[*] Findings: {len(_findings_collected)}")
    _log(f"[*] Output:   {project_dir.resolve()}")

    if _findings_collected:
        _log("\n[*] Findings summary:")
        for f in _findings_collected:
            _log(f"    [{f['severity']:8s}] {f['id']} — {f['title']}")


if __name__ == "__main__":
    main()
