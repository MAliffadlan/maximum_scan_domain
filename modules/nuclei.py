"""
Nuclei integration module.

Runs ProjectDiscovery's Nuclei vulnerability scanner against
discovered subdomains for comprehensive vulnerability detection.

Requires:
  - nuclei binary on PATH (~/.local/bin/nuclei)
  - nuclei-templates at default path (~/nuclei-templates/)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


# Cache
_nuclei_available: bool | None = None


def is_available() -> bool:
    """Check if nuclei binary exists on PATH."""
    global _nuclei_available
    if _nuclei_available is not None:
        return _nuclei_available
    _nuclei_available = shutil.which("nuclei") is not None
    return _nuclei_available


def run_nuclei(
    subdomains: list[str],
    templates: str = "~/.local/bin/nuclei-templates/",
    concurrency: int = 30,
    timeout: int = 90,
    severity: str = "high,critical",
    tech_tags: list[str] | None = None,
) -> list[dict]:
    """Run Nuclei against a list of subdomains.

    Parameters
    ----------
    subdomains : list[str]
        List of subdomains/URLs to scan.
    templates : str
        Path to nuclei-templates directory.
    concurrency : int
        Nuclei concurrency level (default 30).
    timeout : int
        Max runtime in seconds (default 90).
    severity : str
        Severity filter: low,medium,high,critical
    tech_tags : list[str], optional
        Technology tags to filter templates (e.g. ['wordpress','nginx'])

    Returns
    -------
    list[dict]
        Each entry: {template, name, severity, url, matcher, type}
    """
    if not is_available() or not subdomains:
        return []

    # Expand template path
    templates_path = os.path.expanduser(templates)
    if not os.path.isdir(templates_path):
        home_templates = os.path.expanduser("~/nuclei-templates/")
        if os.path.isdir(home_templates):
            templates_path = home_templates
        else:
            return []

    # Write subdomains to temp file
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    try:
        for sub in subdomains:
            if not sub.startswith(("http://", "https://")):
                tmp.write(f"https://{sub}\n")
            else:
                tmp.write(f"{sub}\n")
        tmp.close()

        cmd = [
            "nuclei",
            "-l", tmp.name,
            "-t", templates_path,
            "-json",
            "-silent",
            "-c", str(concurrency),
            "-stats", "-j",
            "-severity", severity,
        ]

        # Add technology tags to speed up — only run relevant templates
        if tech_tags:
            # Nuclei supports -itags (include tags)
            for tag in tech_tags:
                cmd.extend(["-itags", tag])

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return []
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []
    finally:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass

    # Parse JSON lines output
    findings = []
    for line in proc.stdout.strip().splitlines():
        if not line:
            continue
        try:
            data = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue

        findings.append({
            "template": data.get("template-id", ""),
            "name": data.get("info", {}).get("name", ""),
            "severity": data.get("info", {}).get("severity", "unknown"),
            "url": data.get("matched-at", ""),
            "type": data.get("type", ""),
            "matcher": data.get("matcher-name", ""),
            "extracted": data.get("extracted-results", []),
        })

    return findings
