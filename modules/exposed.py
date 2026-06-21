"""
Exposed sensitive files and paths scanner.

Checks a domain for common sensitive files, configuration backups, admin
panels, and other exposed resources by probing known paths over both HTTPS
and HTTP in parallel.

Exports:
    run_exposed(domain: str) -> dict
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TIMEOUT = 5
USER_AGENT = "DomainProbe/1.0"
MAX_WORKERS = 10

# (path, severity, description)
SENSITIVE_PATHS: list[tuple[str, str, str]] = [
    ("/.git/HEAD",                 "high",     "Git repository exposed"),
    ("/.env",                      "critical", "Environment variables"),
    ("/.env.backup",               "critical", "Env backup"),
    ("/wp-config.php",             "high",     "WordPress config"),
    ("/wp-config.php.bak",         "high",     "WP config backup"),
    ("/backup/",                   "medium",   "Backup directory"),
    ("/backup.zip",                "medium",   "Backup archive"),
    ("/backup.tar.gz",             "medium",   "Backup archive"),
    ("/phpinfo.php",               "medium",   "PHP info leak"),
    ("/info.php",                  "medium",   "PHP info"),
    ("/server-status",             "medium",   "Apache server status"),
    ("/server-info",               "medium",   "Apache server info"),
    ("/web.config",                "medium",   "ASP.NET config"),
    ("/.DS_Store",                 "low",      "macOS metadata"),
    ("/.svn/entries",              "high",     "SVN exposed"),
    ("/.hg/store",                 "high",     "Mercurial exposed"),
    ("/docker-compose.yml",        "high",     "Docker config"),
    ("/docker-compose.yaml",       "high",     "Docker config"),
    ("/Dockerfile",                "medium",   "Docker build file"),
    ("/.well-known/security.txt",  "info",     "Security contact"),
    ("/crossdomain.xml",           "low",      "Flash crossdomain"),
    ("/clientaccesspolicy.xml",    "low",      "Silverlight policy"),
    ("/sitemap.xml",               "info",     "Sitemap"),
    ("/robots.txt",                "info",     "Robots"),
    ("/composer.json",             "medium",   "PHP deps"),
    ("/package.json",              "medium",   "Node.js deps"),
    ("/Gemfile",                   "low",      "Ruby deps"),
    ("/credentials.yml",           "critical", "Credentials file"),
    ("/admin/",                    "medium",   "Admin panel"),
    ("/wp-admin/",                 "medium",   "WordPress admin"),
    ("/administrator/",            "medium",   "Joomla admin"),
    ("/phpmyadmin/",               "high",     "phpMyAdmin"),
    ("/.htaccess",                 "medium",   "Apache config"),
    ("/config.php",                "high",     "Config file"),
    ("/debug/default/view",        "medium",   "Debug mode"),
    ("/api/v1/",                   "low",      "API endpoint"),
    ("/graphql",                   "info",     "GraphQL endpoint"),
    ("/.well-known/",              "info",     "Well-known"),
]

# Patterns that indicate a directory listing page
DIR_LISTING_PATTERNS = re.compile(
    r"Index of /|<title>Index of", re.IGNORECASE
)

# Status codes that indicate the resource is accessible
FOUND_STATUSES = frozenset({200, 201, 202, 203, 204, 301, 302, 307, 308, 401, 403})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalise_domain(domain: str) -> str:
    """Strip scheme, trailing slash, and whitespace from a domain."""
    domain = domain.strip().strip("/")
    domain = re.sub(r"^https?://", "", domain, count=1)
    return domain


def _check_path(
    domain: str, scheme: str, path_info: tuple[str, str, str]
) -> dict | None:
    """Probe a single *path* on *domain* over *scheme* (https or http).

    Returns a result dict if the resource is found (accessible status code),
    otherwise ``None``.
    """
    path, severity, description = path_info
    url = f"{scheme}://{domain}{path}"

    try:
        response = requests.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": USER_AGENT},
            stream=True,
        )

        # Read a small chunk to check for directory listing without
        # downloading the entire response body.
        try:
            first_chunk = response.raw.read(8192, decode_content=True)
            text_snippet = first_chunk.decode("utf-8", errors="ignore")
        except Exception:
            text_snippet = ""

        # Close the connection so we don't leak sockets.
        response.close()

        status_code = response.status_code

        if status_code not in FOUND_STATUSES:
            return None

        content_length = response.headers.get("content-length")
        if content_length is not None:
            try:
                content_length = int(content_length)
            except (ValueError, TypeError):
                content_length = 0
        else:
            content_length = 0

        content_type = response.headers.get("content-type", "")

        directory_listing = bool(DIR_LISTING_PATTERNS.search(text_snippet))

        return {
            "path":              path,
            "url":               url,
            "status_code":       status_code,
            "content_length":    content_length,
            "content_type":      content_type,
            "severity":          severity,
            "description":       description,
            "directory_listing": directory_listing,
        }

    except requests.exceptions.SSLError:
        return None
    except requests.exceptions.ConnectionError:
        return None
    except requests.exceptions.Timeout:
        return None
    except requests.exceptions.RequestException:
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_exposed(domain: str) -> dict:
    """Scan *domain* for exposed sensitive files and paths.

    Probes each path in ``SENSITIVE_PATHS`` over both HTTPS and HTTP in
    parallel using a thread pool.

    Parameters
    ----------
    domain : str
        Domain name with or without scheme (e.g. ``example.com``).

    Returns
    -------
    dict
        Keys:

        * **found** – list of dicts for every accessible path, each with
          ``path``, ``url``, ``status_code``, ``content_length``,
          ``content_type``, ``severity``, ``description``, and
          ``directory_listing``.
        * **total_checked** – total number of probes (paths × 2 schemes).
        * **scan_summary** – dict with counts per severity:
          ``critical_count``, ``high_count``, ``medium_count``,
          ``low_count``, ``info_count``.
        * On total failure the dict contains only ``error`` and ``found``
          (empty list).
    """
    domain = _normalise_domain(domain)

    # Build the work list: every combination of scheme × path
    work: list[tuple[str, tuple[str, str, str]]] = []
    for path_info in SENSITIVE_PATHS:
        work.append(("https", path_info))
        work.append(("http", path_info))

    total_checked = len(work)
    found: list[dict] = []

    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_map = {
                executor.submit(_check_path, domain, scheme, path_info): (scheme, path_info)
                for scheme, path_info in work
            }
            for future in as_completed(future_map):
                try:
                    result = future.result()
                except Exception:
                    result = None
                if result is not None:
                    found.append(result)
    except Exception as exc:
        return {"error": str(exc), "found": []}

    # --- Build scan summary -----------------------------------------------
    severity_counts: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    for entry in found:
        sev = entry["severity"]
        if sev in severity_counts:
            severity_counts[sev] += 1

    scan_summary = {
        "critical_count": severity_counts["critical"],
        "high_count":     severity_counts["high"],
        "medium_count":   severity_counts["medium"],
        "low_count":      severity_counts["low"],
        "info_count":     severity_counts["info"],
    }

    # Sort found entries: critical first, then high, medium, low, info
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    found.sort(key=lambda e: severity_order.get(e["severity"], 5))

    return {
        "found":         found,
        "total_checked": total_checked,
        "scan_summary":  scan_summary,
    }
