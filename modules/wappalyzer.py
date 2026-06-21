"""
Wappalyzer integration via webanalyze (Go binary).

Runs webanalyze (which bundles the Wappalyzer open-source fingerprint
database — 3965+ apps) against a target URL and returns detected
technologies in a structured format.

Requires:
  - webanalyze binary on PATH (~/.local/bin/webanalyze)
  - technologies.json file at WAPPALYZER_APPS path
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

# Default path to the Wappalyzer technologies database
WAPPALYZER_APPS = os.environ.get(
    "WAPPALYZER_APPS",
    str(Path.home() / ".local" / "bin" / "technologies.json"),
)

# Cache for webanalyze binary check
_webanalyze_available: bool | None = None


def is_available() -> bool:
    """Check if webanalyze binary and database exist."""
    global _webanalyze_available
    if _webanalyze_available is not None:
        return _webanalyze_available

    webanalyze_path = shutil.which("webanalyze")
    _webanalyze_available = bool(
        webanalyze_path
        and os.path.isfile(webanalyze_path)
        and os.path.isfile(WAPPALYZER_APPS)
    )
    return _webanalyze_available


def run_webanalyze(url: str, timeout: int = 30) -> list[dict]:
    """Run webanalyze against *url* and return detected technologies.

    Parameters
    ----------
    url : str
        Full URL to scan (e.g. ``https://example.com``).
    timeout : int
        Maximum runtime in seconds (default 30).

    Returns
    -------
    list[dict]
        Each entry: {name, category, version (str|None), confidence}.
        Empty list if webanalyze is unavailable or fails.
    """
    if not is_available():
        return []

    try:
        proc = subprocess.run(
            [
                "webanalyze",
                "-host", url,
                "-apps", WAPPALYZER_APPS,
                "-output", "json",
            ],
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

    if proc.returncode != 0:
        return []

    # Parse JSON output — webanalyze outputs one JSON line per host
    results: list[dict] = []
    for line in proc.stdout.strip().splitlines():
        if not line:
            continue
        try:
            data = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue

        for match in data.get("matches", []):
            app_name = match.get("app", "").strip()
            if not app_name:
                continue

            # webanalyze can report multiple categories (as a list)
            cats = match.get("categories", [])
            if isinstance(cats, str):
                cats = [cats]

            version = match.get("version") or None

            # webanalyze doesn't provide confidence, but matched means detected
            for cat in cats or ["Unknown"]:
                results.append({
                    "name": app_name,
                    "category": cat.strip() if isinstance(cat, str) else "Unknown",
                    "version": version,
                    "confidence": "certain" if version else "probable",
                })

    # Merge duplicate entries (same name + category)
    seen: set[tuple[str, str]] = set()
    merged: list[dict] = []
    for r in results:
        key = (r["name"], r["category"])
        if key not in seen:
            seen.add(key)
            merged.append(r)

    # Sort by name
    merged.sort(key=lambda x: (x["category"], x["name"]))
    return merged
