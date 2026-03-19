#!/usr/bin/env python3
"""Dependency installer for business-profiler.

Checks and installs required Python packages:
- httpx: HTTP client for API calls
- dnspython: DNS queries for email security, M365 detection
- weasyprint: PDF generation from HTML/CSS
- markdown2: Markdown to HTML conversion
- beautifulsoup4: HTML parsing for tech stack detection
"""

import importlib
import json
import subprocess
import sys

REQUIRED = {
    "httpx": "httpx",
    "dns.resolver": "dnspython",
    "weasyprint": "weasyprint",
    "markdown2": "markdown2",
    "bs4": "beautifulsoup4",
}


def check_dependencies() -> dict:
    """Check which dependencies are installed.

    Returns:
        Dict with status of each dependency
    """
    results = {}
    for module_name, pip_name in REQUIRED.items():
        try:
            importlib.import_module(module_name.split(".")[0])
            results[pip_name] = {"installed": True}
        except ImportError:
            results[pip_name] = {"installed": False}
    return results


def install_missing() -> dict:
    """Install missing dependencies.

    Returns:
        Dict with installation results
    """
    status = check_dependencies()
    missing = [pkg for pkg, info in status.items() if not info["installed"]]

    if not missing:
        return {"status": "ok", "message": "All dependencies installed", "packages": status}

    results = {"status": "installing", "installed": [], "failed": []}

    # Try standard pip first, then --break-system-packages for PEP 668 environments
    for pkg in missing:
        installed = False
        for extra_args in [[], ["--break-system-packages"]]:
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", "--quiet", pkg] + extra_args,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                results["installed"].append(pkg)
                installed = True
                break
            except subprocess.CalledProcessError:
                continue
        if not installed:
            results["failed"].append(pkg)

    if results["failed"]:
        results["status"] = "partial"
        results["message"] = f"Failed to install: {', '.join(results['failed'])}"
    else:
        results["status"] = "ok"
        results["message"] = f"Installed: {', '.join(results['installed'])}"

    results["packages"] = check_dependencies()
    return results


def setup_venv(venv_dir: str = ".venv") -> dict:
    """Create a virtual environment and install dependencies into it.

    Args:
        venv_dir: Path for the venv directory (relative to plugin root)

    Returns:
        Dict with venv status and activation instructions
    """
    import venv as venv_mod
    from pathlib import Path

    plugin_root = Path(__file__).resolve().parent.parent
    venv_path = plugin_root / venv_dir

    if venv_path.exists():
        return {
            "status": "exists",
            "path": str(venv_path),
            "activate": f"source {venv_path}/bin/activate",
            "message": f"venv already exists at {venv_path}",
        }

    try:
        venv_mod.create(str(venv_path), with_pip=True)
    except Exception as e:
        return {"status": "error", "message": f"Failed to create venv: {e}"}

    # Install dependencies into the new venv
    venv_pip = venv_path / "bin" / "pip"
    missing_pkgs = list(REQUIRED.values())
    installed = []
    failed = []

    for pkg in missing_pkgs:
        try:
            subprocess.check_call(
                [str(venv_pip), "install", "--quiet", pkg],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            installed.append(pkg)
        except subprocess.CalledProcessError:
            failed.append(pkg)

    return {
        "status": "ok" if not failed else "partial",
        "path": str(venv_path),
        "activate": f"source {venv_path}/bin/activate",
        "installed": installed,
        "failed": failed,
        "message": f"venv created at {venv_path}. Activate with: source {venv_path}/bin/activate",
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Manage business-profiler dependencies")
    parser.add_argument("--check", action="store_true", help="Check dependencies only")
    parser.add_argument("--install", action="store_true", help="Install missing dependencies")
    parser.add_argument("--venv", nargs="?", const=".venv", default=None,
                        help="Create a virtual environment and install dependencies (default: .venv)")
    args = parser.parse_args()

    if args.venv is not None:
        print(json.dumps(setup_venv(args.venv), indent=2))
    elif args.check:
        print(json.dumps(check_dependencies(), indent=2))
    elif args.install:
        print(json.dumps(install_missing(), indent=2))
    else:
        # Default: check and install if needed
        print(json.dumps(install_missing(), indent=2))
