#!/usr/bin/env python3
# install.py — Aether-U UWB / RTLS Penetration Test Orchestrator
# VERSION: 1.0.0 (referenced from /Users/pr0t31n/Aether-U/VERSION — do not bump here)
# Installs all dependencies for aether_u.py and configures the system.
#
# Phases:
#   Phase 0 — OS detection
#   Phase 1 — System packages (nmap, tshark, mosquitto-clients, sqlmap, etc.)
#   Phase 2 — pip packages (paho-mqtt)
#   Phase 3 — External tools (GNU Radio + gr-osmosdr for SDR support)
#   Phase 4 — Verify required tools
#   Phase 5 — Readiness summary (no daemon required)

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------
RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"


def _pip_installed(pkg_spec):
    """Return True if a pip package is already importable."""
    import importlib.util
    name = pkg_spec.split(">=")[0].split("==")[0].split("[")[0].split("<")[0].strip()
    _IMPORT_MAP = {
        "paho-mqtt": "paho", "python-nmap": "nmap", "beautifulsoup4": "bs4",
        "python-docx": "docx", "python-whois": "whois", "Pillow": "PIL",
        "pyOpenSSL": "OpenSSL", "dnspython": "dns", "pyyaml": "yaml",
        "scikit-learn": "sklearn", "python-dateutil": "dateutil",
        "python-magic": "magic", "flask-socketio": "flask_socketio",
        "flask-cors": "flask_cors", "python-engineio": "engineio",
        "python-socketio": "socketio", "charset-normalizer": "charset_normalizer",
        "ruamel.yaml": "ruamel", "lxml-html-clean": "lxml_html_clean",
    }
    mod = _IMPORT_MAP.get(name, name.replace("-", "_"))
    return importlib.util.find_spec(mod) is not None


def cprint(msg: str, colour: str = RESET, bold: bool = False) -> None:
    prefix = BOLD if bold else ""
    print(f"{prefix}{colour}{msg}{RESET}")


def phase_header(title: str) -> None:
    bar = "=" * 62
    print()
    cprint(bar, CYAN, bold=True)
    cprint(f"  {title}", CYAN, bold=True)
    cprint(bar, CYAN, bold=True)


def info(msg: str)    -> None: cprint(f"  [*] {msg}", BLUE)
def success(msg: str) -> None: cprint(f"  [+] {msg}", GREEN)
def warn(msg: str)    -> None: cprint(f"  [!] {msg}", YELLOW)
def note(msg: str)    -> None: cprint(f"  [i] {msg}", YELLOW)
def error(msg: str)   -> None: cprint(f"  [-] {msg}", RED)
def step(msg: str)    -> None: cprint(f"  --> {msg}", CYAN)


# ---------------------------------------------------------------------------
# Phase 0 — OS detection
# ---------------------------------------------------------------------------

def detect_os() -> str:
    """Return one of: macos | kali | ubuntu | rhel | suse | windows | unknown"""
    system = platform.system()
    if system == "Windows":
        return "windows"
    if system == "Darwin":
        return "macos"
    if system == "Linux":
        release_files = ["/etc/os-release", "/usr/lib/os-release"]
        release_info: dict = {}
        for rf in release_files:
            if os.path.exists(rf):
                with open(rf) as fh:
                    for line in fh:
                        line = line.strip()
                        if "=" in line:
                            k, _, v = line.partition("=")
                            release_info[k] = v.strip('"').lower()
                break
        name = release_info.get("ID", "")
        like = release_info.get("ID_LIKE", "")
        if "kali" in name:
            return "kali"
        if "ubuntu" in name or "ubuntu" in like:
            return "ubuntu"
        if name in ("rhel", "centos", "rocky", "almalinux", "fedora") or \
                "rhel" in like or "fedora" in like:
            return "rhel"
        if name in ("opensuse", "sles", "suse") or "suse" in like:
            return "suse"
        if "debian" in name or "debian" in like:
            return "ubuntu"
    return "unknown"


# ---------------------------------------------------------------------------
# Command runner
# ---------------------------------------------------------------------------

def run(cmd: list, check: bool = False, dry_run: bool = False,
        env: dict = None, cwd: str = None) -> int:
    """Run a command; return exit code. If dry_run, just print and return 0."""
    display = " ".join(str(c) for c in cmd)
    if dry_run:
        cprint(f"    [DRY-RUN] {display}", MAGENTA)
        return 0
    info(f"Running: {display}")
    try:
        result = subprocess.run(
            cmd,
            env={**os.environ, **(env or {})},
            cwd=cwd,
        )
        if check and result.returncode != 0:
            error(f"Command failed (exit {result.returncode}): {display}")
        return result.returncode
    except FileNotFoundError:
        error(f"Executable not found for command: {display}")
        return 127
    except Exception as exc:
        error(f"Unexpected error running {display}: {exc}")
        return 1


# ---------------------------------------------------------------------------
# Privilege helpers
# ---------------------------------------------------------------------------

def is_root() -> bool:
    return hasattr(os, "getuid") and os.getuid() == 0


def require_root() -> None:
    if not is_root():
        error("This installer must be run as root (or with sudo) on Linux.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Package lists
# ---------------------------------------------------------------------------

APT_PACKAGES = [
    "nmap",
    "tshark",
    "wireshark",
    "mosquitto",
    "mosquitto-clients",
    "sqlmap",
    "python3-pip",
    "python3-dev",
    "git",
    "curl",
    "libpcap-dev",
    "build-essential",
    "pkg-config",
    "libusb-1.0-0-dev",
]

DNF_PACKAGES = [
    "nmap",
    "wireshark",
    "wireshark-cli",
    "mosquitto",
    "python3-pip",
    "python3-devel",
    "git",
    "curl",
    "libpcap-devel",
    "gcc",
    "gcc-c++",
    "make",
    "epel-release",
]

ZYPPER_PACKAGES = [
    "nmap",
    "wireshark",
    "mosquitto",
    "python3-pip",
    "python3-devel",
    "git",
    "curl",
    "libpcap-devel",
    "gcc",
    "make",
]

BREW_PACKAGES = [
    "nmap",
    "wireshark",
    "mosquitto",
    "curl",
    "libpcap",
]


# ---------------------------------------------------------------------------
# Phase 1 — System packages
# ---------------------------------------------------------------------------

def phase_apt(dry_run: bool) -> None:
    phase_header("PHASE 1 — System Packages (apt)")
    require_root()
    info("Updating package lists...")
    run(["apt-get", "update", "-y"], check=True, dry_run=dry_run)
    info(f"Installing: {' '.join(APT_PACKAGES)}")
    run(["apt-get", "install", "-y"] + APT_PACKAGES, check=True, dry_run=dry_run)
    # Allow non-root tshark capture
    if not dry_run:
        run(
            ["bash", "-c",
             "echo 'wireshark-common wireshark-common/install-setuid boolean true'"
             " | debconf-set-selections"],
            dry_run=dry_run,
        )
    success("APT phase complete.")


def phase_dnf(dry_run: bool) -> None:
    phase_header("PHASE 1 — System Packages (dnf)")
    require_root()
    run(["dnf", "install", "-y", "epel-release"], dry_run=dry_run)
    run(["dnf", "upgrade", "-y"], dry_run=dry_run)
    info(f"Installing: {' '.join(DNF_PACKAGES)}")
    run(["dnf", "install", "-y"] + DNF_PACKAGES, check=True, dry_run=dry_run)
    note("sqlmap may need manual install on RHEL: pip3 install sqlmap")
    success("DNF phase complete.")


def phase_zypper(dry_run: bool) -> None:
    phase_header("PHASE 1 — System Packages (zypper)")
    require_root()
    run(["zypper", "refresh"], dry_run=dry_run)
    run(["zypper", "update", "-y"], dry_run=dry_run)
    info(f"Installing: {' '.join(ZYPPER_PACKAGES)}")
    run(["zypper", "install", "-y"] + ZYPPER_PACKAGES, check=True, dry_run=dry_run)
    note("sqlmap and mosquitto-clients may need manual install on openSUSE.")
    success("Zypper phase complete.")


def phase_brew(dry_run: bool) -> None:
    phase_header("PHASE 1 — System Packages (Homebrew / macOS)")
    warn("macOS: UWB hardware testing requires Linux with an SDR or DWM3000EVB device.")
    warn("Network / MQTT testing phases work fully on macOS.")

    brew_bin = shutil.which("brew")
    if not brew_bin:
        error("Homebrew not found. Install from https://brew.sh and re-run.")
        return

    if is_root():
        sudo_user = os.environ.get("SUDO_USER", "")
        if not sudo_user:
            note("Running as root but SUDO_USER is not set — skipping brew install "
                 "to avoid corrupting Homebrew. Re-run as your normal user.")
            return
        base_cmd = ["sudo", "-u", sudo_user, brew_bin]
    else:
        base_cmd = [brew_bin]

    try:
        _installed = set(subprocess.run(
            base_cmd + ["list", "--formula", "-1"],
            capture_output=True, text=True, check=True).stdout.strip().splitlines())
    except (subprocess.CalledProcessError, FileNotFoundError):
        _installed = set()
    _missing = [p for p in BREW_PACKAGES if p not in _installed]
    for p in BREW_PACKAGES:
        if p in _installed:
            info(f"✓ {p} already installed")
    if _missing:
        info(f"Installing brew packages: {' '.join(_missing)}")
        run(base_cmd + ["install"] + _missing, dry_run=dry_run)
    else:
        info("All brew packages already installed.")
    # sqlmap via pip on macOS
    if not _pip_installed("sqlmap"):
        info("Installing sqlmap via pip3...")
        run([sys.executable, "-m", "pip", "install", "sqlmap"], dry_run=dry_run)
    else:
        info("✓ sqlmap already installed")
    success("Homebrew phase complete.")


# ---------------------------------------------------------------------------
# Phase 2 — pip packages
# ---------------------------------------------------------------------------

PIP_PACKAGES = [
    "paho-mqtt>=1.6.0",
]


def phase_pip(dry_run: bool) -> None:
    phase_header("PHASE 2 — Python Packages (pip)")
    info("Installing optional Python packages for Aether-U...")
    info("Note: paho-mqtt is optional — Aether-U uses mosquitto_sub/pub subprocesses by default.")
    for pkg in PIP_PACKAGES:
        if _pip_installed(pkg):
            success(f"✓ {pkg} already installed")
            continue
        rc = run(
            [sys.executable, "-m", "pip", "install", "--break-system-packages", pkg],
            dry_run=dry_run,
        )
        if rc == 0:
            success(f"Installed: {pkg}")
        else:
            rc2 = run(
                [sys.executable, "-m", "pip", "install", pkg],
                dry_run=dry_run,
            )
            if rc2 == 0:
                success(f"Installed: {pkg}")
            else:
                warn(f"Could not install {pkg} — install manually if needed.")
    success("Pip phase complete.")


# ---------------------------------------------------------------------------
# Phase 3 — External tools (GNU Radio + HackRF SDR support)
# ---------------------------------------------------------------------------

def phase_gnuradio(os_id: str, dry_run: bool) -> None:
    phase_header("PHASE 3 — External Tools (GNU Radio / SDR)")
    info("GNU Radio with gr-osmosdr enables SDR-based UWB RF analysis.")
    info("Required only for the physical_attacks phase with SDR hardware.")

    if os_id == "macos":
        warn("GNU Radio on macOS: install via MacPorts or use a Linux VM.")
        brew_bin = shutil.which("brew")
        if brew_bin:
            info("Attempting: brew install gnuradio")
            if is_root():
                sudo_user = os.environ.get("SUDO_USER", "")
                base_cmd = (["sudo", "-u", sudo_user, brew_bin]
                            if sudo_user else [brew_bin])
            else:
                base_cmd = [brew_bin]
            run(base_cmd + ["install", "gnuradio"], dry_run=dry_run)
        warn("gr-osmosdr may need to be built from source on macOS.")
        warn("HackRF tools: brew install hackrf")
        if brew_bin:
            if is_root():
                sudo_user = os.environ.get("SUDO_USER", "")
                base_cmd = (["sudo", "-u", sudo_user, brew_bin]
                            if sudo_user else [brew_bin])
            else:
                base_cmd = [brew_bin]
            run(base_cmd + ["install", "hackrf"], dry_run=dry_run)
        return

    if os_id == "windows":
        warn("GNU Radio on Windows: use WSL2 with Ubuntu, or PySDR / GNURadio Windows installer.")
        warn("See: https://wiki.gnuradio.org/index.php/WindowsInstall")
        return

    if os_id in ("kali", "ubuntu"):
        require_root()
        info("Installing GNU Radio and gr-osmosdr via apt...")
        run(["apt-get", "install", "-y",
             "gnuradio",
             "gr-osmosdr",
             "hackrf",
             "libhackrf-dev",
             "gqrx-sdr",
             "rtl-sdr",
             "librtlsdr-dev",
             ], check=True, dry_run=dry_run)
        success("GNU Radio and SDR tools installed.")
    elif os_id == "rhel":
        require_root()
        warn("GNU Radio on RHEL: building from source is recommended.")
        warn("Install EPEL first: dnf install -y epel-release")
        run(["dnf", "install", "-y", "gnuradio", "hackrf"], dry_run=dry_run)
        warn("gr-osmosdr may require manual build from source on RHEL.")
    elif os_id == "suse":
        require_root()
        run(["zypper", "install", "-y", "gnuradio", "gr-osmosdr", "hackrf"],
            dry_run=dry_run)
    else:
        note(f"Unknown OS '{os_id}' — skipping GNU Radio install.")
        warn("Install GNU Radio manually: https://wiki.gnuradio.org/index.php/InstallingGR")

    # Check HackRF availability
    hackrf_bin = shutil.which("hackrf_info")
    if hackrf_bin:
        success("hackrf_info found — HackRF SDK is available")
        out_bytes = b""
        try:
            result = subprocess.run(
                [hackrf_bin], capture_output=True, timeout=5
            )
            out_bytes = result.stdout + result.stderr
        except Exception:
            pass
        info(f"hackrf_info output: {out_bytes[:200].decode('utf-8', errors='replace')}")
    else:
        note("hackrf_info not found — HackRF hardware support unavailable")
        warn("Physical attack phase will run in documentation-only mode")

    # Check GNU Radio
    gnuradio_bin = shutil.which("gnuradio-companion")
    if gnuradio_bin:
        success(f"gnuradio-companion found: {gnuradio_bin}")
    else:
        warn("gnuradio-companion not found — GNU Radio not installed or not in PATH")

    success("External tools phase complete.")


# ---------------------------------------------------------------------------
# Phase 4 — Verify tools
# ---------------------------------------------------------------------------

VERIFY_TOOLS = [
    ("nmap",           "Network port scanner — RTLS infrastructure discovery"),
    ("mosquitto_sub",  "MQTT subscriber — passive protocol analysis"),
    ("mosquitto_pub",  "MQTT publisher — active injection testing"),
    ("tshark",         "Network packet capture — traffic analysis"),
    ("sqlmap",         "SQL injection scanner — RTLS reporting module testing"),
    ("curl",           "HTTP client — REST API testing"),
    ("python3",        "Python 3 runtime"),
    ("git",            "Git version control"),
    ("gnuradio-companion", "GNU Radio — SDR-based RF analysis (optional)"),
    ("hackrf_info",    "HackRF SDK — SDR hardware (optional, physical_attacks phase)"),
]


def phase_verify(dry_run: bool) -> None:
    phase_header("PHASE 4 — Tool Verification")
    if dry_run:
        info("Dry-run mode — skipping live tool verification.")
        return

    all_required_ok = True
    optional_tools = {"gnuradio-companion", "hackrf_info"}

    for tool_name, description in VERIFY_TOOLS:
        found = shutil.which(tool_name)
        is_optional = tool_name in optional_tools
        if found:
            success(f"{tool_name:<22} found at {found}")
        else:
            if is_optional:
                warn(f"{tool_name:<22} NOT FOUND (optional — needed for physical_attacks phase)")
            else:
                error(f"{tool_name:<22} NOT FOUND — required for core functionality")
                all_required_ok = False
        info(f"  Purpose: {description}")

    print()
    if all_required_ok:
        success("All required tools verified.")
    else:
        warn("Some required tools are missing. Check output above and install manually.")
    success("Verification phase complete.")


# ---------------------------------------------------------------------------
# Phase 5 — Readiness summary (no daemon)
# ---------------------------------------------------------------------------

def phase_summary(os_id: str) -> None:
    phase_header("PHASE 5 — Readiness Summary")
    info("Aether-U does not require a background daemon.")
    info("Run assessments manually with:")
    cprint("", RESET)
    cprint("    python3 /Users/pr0t31n/Aether-U/aether_u.py --help", GREEN, bold=True)
    cprint("    python3 /Users/pr0t31n/Aether-U/aether_u.py --list-phases", GREEN, bold=True)
    cprint("    python3 /Users/pr0t31n/Aether-U/aether_u.py --config config.json "
           "--project /tmp/rtls_audit", GREEN, bold=True)
    cprint("", RESET)

    # Print a short quick-start checklist
    print()
    info("Quick-start checklist:")
    step("1. Edit config.json — set rtls_host, mqtt_host, credentials, scope")
    step("2. Set active_testing_authorized=true only with explicit client authorisation")
    step("3. Set physical_access=true only when physical RF testing is authorised")
    step("4. Run: python3 aether_u.py --config config.json --project ./output")
    step("5. Review findings_spectre.json in the output directory")
    print()

    # Check paho-mqtt import
    try:
        import paho.mqtt.client  # noqa: F401
        success("paho-mqtt Python library: available")
    except ImportError:
        warn("paho-mqtt Python library: NOT installed (optional — mosquitto_sub/pub used instead)")
        info("To install: pip3 install paho-mqtt")

    print()
    success("Aether-U is ready.")


# ---------------------------------------------------------------------------
# Post-install syntax check
# ---------------------------------------------------------------------------

def run_check() -> bool:
    """Run a quick syntax check on aether_u.py. Returns True on success."""
    aether_u = Path(__file__).parent / "aether_u.py"
    if not aether_u.exists():
        warn(f"aether_u.py not found at {aether_u}")
        return False
    result = subprocess.run(
        [sys.executable, "-m", "py_compile", str(aether_u)],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        success("aether_u.py syntax check: PASS")
        return True
    else:
        error(f"aether_u.py syntax check: FAIL\n{result.stderr}")
        return False


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Aether-U installer — UWB/RTLS penetration testing orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 install.py
  sudo python3 install.py --check
  sudo python3 install.py --skip-apt
  sudo python3 install.py --skip-pip --skip-git
  python3 install.py --check          # dry-run on non-root
""",
    )
    p.add_argument("--skip-apt",  action="store_true",
                   help="Skip system package installation (apt/dnf/zypper/brew)")
    p.add_argument("--skip-pip",  action="store_true",
                   help="Skip pip package installation")
    p.add_argument("--skip-go",   action="store_true",
                   help="Skip Go tool installation (no-op for Aether-U)")
    p.add_argument("--skip-git",  action="store_true",
                   help="Skip GNU Radio / external tool installation (Phase 3)")
    p.add_argument("--check",     action="store_true",
                   help="Dry-run — print commands without executing")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()
    dry_run = args.check

    cprint("\n" + "=" * 62, GREEN, bold=True)
    cprint("  Aether-U Installer  —  v1.0.0", GREEN, bold=True)
    cprint("  UWB / RTLS Penetration Test Orchestrator", GREEN, bold=True)
    cprint("  Target platforms: Sewio, Pozyx, Avalue, Generic RTLS", GREEN, bold=True)
    cprint("=" * 62 + "\n", GREEN, bold=True)

    if dry_run:
        warn("DRY-RUN MODE — no changes will be made to this system.\n")

    # Phase 0 — OS detection
    phase_header("PHASE 0 — OS Detection")
    os_id = detect_os()
    info(f"Detected OS  : {os_id}")
    info(f"Python       : {sys.version.split()[0]}")
    info(f"Architecture : {platform.machine()}")

    if os_id == "windows":
        error("Aether-U is designed for Linux and macOS.")
        error("Windows is not supported. Use WSL2 with Ubuntu for Linux tooling.")
        sys.exit(1)

    if os_id == "macos":
        warn("macOS detected. UWB hardware (DWM3000EVB) and HackRF support require Linux.")
        warn("Network survey, MQTT, and API testing phases work fully on macOS.")

    # Phase 1 — System packages
    if not args.skip_apt:
        if os_id in ("kali", "ubuntu"):
            phase_apt(dry_run)
        elif os_id == "rhel":
            phase_dnf(dry_run)
        elif os_id == "suse":
            phase_zypper(dry_run)
        elif os_id == "macos":
            phase_brew(dry_run)
        else:
            note(f"Unknown OS '{os_id}' — skipping system package phase.")
    else:
        info("Skipping system package phase (--skip-apt).")

    # Phase 2 — pip
    if not args.skip_pip:
        phase_pip(dry_run)
    else:
        info("Skipping pip phase (--skip-pip).")

    # Phase 3 — GNU Radio / SDR
    if not args.skip_git:
        phase_gnuradio(os_id, dry_run)
    else:
        info("Skipping GNU Radio / external tools phase (--skip-git).")

    # Phase 4 — Tool verification
    phase_verify(dry_run)

    # Phase 5 — Readiness summary
    if not dry_run:
        phase_summary(os_id)

    # Syntax check
    print()
    run_check()
    print()

    cprint("  Aether-U installation complete.", GREEN, bold=True)
    cprint("  Run: python3 /Users/pr0t31n/Aether-U/aether_u.py --help", CYAN)
    cprint("  Docs: /Users/pr0t31n/Aether-U/README.md\n", CYAN)


if __name__ == "__main__":
    main()
