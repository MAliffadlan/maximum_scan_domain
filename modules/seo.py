"""
SEO analysis module: robots.txt, sitemaps, meta tags, Open Graph, Twitter Cards.

Exports:
    run_seo(domain: str) -> dict
"""

import re
import xml.etree.ElementTree as ET
from urllib.parse import urljoin

import requests


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TIMEOUT = 10
USER_AGENT = "DomainProbe/1.0"
ROBOTS_CONTENT_MAX = 5000
SITEMAP_MAX_URLS = 100

COMMON_SITEMAP_PATHS = [
    "/sitemap.xml",
    "/sitemap_index.xml",
]

# Patterns for extracting meta-like information from HTML.
RE_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
RE_META = re.compile(
    r'<meta\s[^>]*?\b(name|property|http-equiv|charset)\s*=\s*["\']?([^"\'\s>]+)["\']?'
    r'[^>]*?\bcontent\s*=\s*["\']([^"\']*)["\']'
    r'[^>]*/?>',
    re.IGNORECASE | re.DOTALL,
)
# Fallback: catch meta tags where content comes before name/property (order may vary).
RE_META_REV = re.compile(
    r'<meta\s[^>]*?\bcontent\s*=\s*["\']([^"\']*)["\']'
    r'[^>]*?\b(name|property|http-equiv)\s*=\s*["\']([^"\'\s>]+)["\']'
    r'[^>]*/?>',
    re.IGNORECASE | re.DOTALL,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalise_domain(domain: str) -> str:
    """Strip scheme, trailing slash, and whitespace from a domain."""
    domain = domain.strip().strip("/")
    domain = re.sub(r"^https?://", "", domain, count=1)
    return domain


def _safe_get(url: str, timeout: int = TIMEOUT) -> requests.Response | None:
    """Perform a GET request and return the response, or None on failure.

    Non-2xx status codes are *not* treated as failures — the caller inspects
    ``status_code`` to decide what to do.
    """
    try:
        return requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
    except requests.exceptions.RequestException:
        return None


# ---------------------------------------------------------------------------
# 1. robots.txt
# ---------------------------------------------------------------------------

def _probe_robots(domain: str, scheme: str = "https") -> dict:
    """Fetch and parse robots.txt.

    Returns a dict with keys:
        exists (bool)
        status_code (int | None)
        content (str) — truncated to ROBOTS_CONTENT_MAX
        content_length (int) — untruncated length
        disallow (list[str])
        allow (list[str])
        sitemaps (list[str])
    """
    url = f"{scheme}://{domain}/robots.txt"
    resp = _safe_get(url)

    if resp is None:
        return {
            "exists": False,
            "status_code": None,
            "content": "",
            "content_length": 0,
            "disallow": [],
            "allow": [],
            "sitemaps": [],
        }

    exists = resp.status_code == 200
    content = resp.text if exists else ""
    content_length = len(content)

    disallow: list[str] = []
    allow: list[str] = []
    sitemaps: list[str] = []

    if exists:
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Handle "Disallow: /path"
            if stripped.lower().startswith("disallow:"):
                path = stripped.split(":", 1)[1].strip()
                if path:
                    disallow.append(path)

            # Handle "Allow: /path"
            elif stripped.lower().startswith("allow:"):
                path = stripped.split(":", 1)[1].strip()
                if path:
                    allow.append(path)

            # Handle "Sitemap: <url>"
            elif stripped.lower().startswith("sitemap:"):
                url_part = stripped.split(":", 1)[1].strip()
                if url_part:
                    sitemaps.append(url_part)

    return {
        "exists": exists,
        "status_code": resp.status_code,
        "content": content[:ROBOTS_CONTENT_MAX],
        "content_length": content_length,
        "disallow": disallow,
        "allow": allow,
        "sitemaps": sitemaps,
    }


# ---------------------------------------------------------------------------
# 2. Sitemaps
# ---------------------------------------------------------------------------

def _parse_sitemap_xml(xml_text: str) -> list[str]:
    """Parse XML sitemap text and extract all <loc> element texts.

    Handles both standard sitemaps and sitemap index files (which also use
    <loc> to point at child sitemaps).  Silently returns an empty list on any
    parse error.
    """
    urls: list[str] = []
    try:
        # Remove any leading/trailing whitespace and BOM.
        xml_text = xml_text.strip()
        if xml_text.startswith("﻿"):
            xml_text = xml_text[1:]
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        # Some sitemaps are gzipped or use a non-standard encoding; we skip
        # those gracefully.
        return []

    # The <loc> elements live inside <url> (standard sitemap) or <sitemap>
    # (sitemap index).  Both share the same tag name for the URL.
    #
    # Namespace: most sitemaps use xmlns="http://www.sitemaps.org/schemas/sitemap/0.9".
    # We strip the namespace prefix for a simpler XPath match.
    ns = "http://www.sitemaps.org/schemas/sitemap/0.9"
    for elem in root.iter(f"{{{ns}}}loc"):
        text = (elem.text or "").strip()
        if text:
            urls.append(text)

    # Also try without namespace (some sitemaps omit it).
    if not urls:
        for elem in root.iter("loc"):
            text = (elem.text or "").strip()
            if text:
                urls.append(text)

    return urls


def _probe_sitemaps(domain: str, scheme: str = "https") -> dict:
    """Try common sitemap paths and parse the first successful one.

    Returns a dict with keys:
        checked_paths (list[str]) — paths that were attempted
        found (bool)
        url (str | None) — the full sitemap URL that returned 200
        total_urls (int) — total <loc> count discovered
        urls (list[str]) — up to SITEMAP_MAX_URLS entries
    """
    checked_paths: list[str] = []
    found = False
    sitemap_url: str | None = None
    all_urls: list[str] = []
    total_urls = 0

    for path in COMMON_SITEMAP_PATHS:
        checked_paths.append(path)
        url = f"{scheme}://{domain}{path}"
        resp = _safe_get(url)
        if resp is None or resp.status_code != 200:
            continue

        found = True
        sitemap_url = url
        all_urls = _parse_sitemap_xml(resp.text)
        total_urls = len(all_urls)
        break

    # If no sitemap found via the common paths, also check any sitemap URLs
    # discovered in robots.txt (handled by the caller stitching results).
    # The caller can call _probe_sitemap_from_url for those.

    return {
        "checked_paths": checked_paths,
        "found": found,
        "url": sitemap_url,
        "total_urls": total_urls,
        "urls": all_urls[:SITEMAP_MAX_URLS],
    }


def _probe_sitemap_from_url(sitemap_url: str) -> dict:
    """Fetch and parse a specific sitemap URL (e.g. from robots.txt)."""
    resp = _safe_get(sitemap_url)
    if resp is None or resp.status_code != 200:
        return {
            "found": False,
            "url": sitemap_url,
            "total_urls": 0,
            "urls": [],
        }

    all_urls = _parse_sitemap_xml(resp.text)
    return {
        "found": True,
        "url": sitemap_url,
        "total_urls": len(all_urls),
        "urls": all_urls[:SITEMAP_MAX_URLS],
    }


# ---------------------------------------------------------------------------
# 3. Homepage meta tags
# ---------------------------------------------------------------------------

def _parse_meta_tags(html: str, base_url: str) -> dict:
    """Extract title and meta information from raw HTML.

    Returns a dict with keys:
        title (str | None)
        description (str | None)
        keywords (str | None)
        viewport (str | None)
        open_graph (dict[str, str])
        twitter_card (dict[str, str])
    """
    result: dict = {
        "title": None,
        "description": None,
        "keywords": None,
        "viewport": None,
        "open_graph": {},
        "twitter_card": {},
    }

    # --- <title> -----------------------------------------------------------
    m_title = RE_TITLE.search(html)
    if m_title:
        result["title"] = m_title.group(1).strip()

    # --- <meta> tags (forward order: name/property then content) ----------
    for m in RE_META.finditer(html):
        attr_name = m.group(1).lower()
        attr_value = m.group(2).lower().strip()
        content = m.group(3).strip()

        if attr_name == "name":
            if attr_value == "description":
                result["description"] = content
            elif attr_value == "keywords":
                result["keywords"] = content
            elif attr_value == "viewport":
                result["viewport"] = content
            elif attr_value.startswith("twitter:"):
                key = attr_value[len("twitter:"):]
                result["twitter_card"][key] = content
        elif attr_name == "property":
            if attr_value.startswith("og:"):
                key = attr_value[len("og:"):]
                result["open_graph"][key] = content

    # --- <meta> tags (reverse order: content then name/property) ----------
    for m in RE_META_REV.finditer(html):
        content = m.group(1).strip()
        attr_name = m.group(2).lower()
        attr_value = m.group(3).lower().strip()

        if attr_name == "name":
            if attr_value == "description" and result["description"] is None:
                result["description"] = content
            elif attr_value == "keywords" and result["keywords"] is None:
                result["keywords"] = content
            elif attr_value == "viewport" and result["viewport"] is None:
                result["viewport"] = content
            elif attr_value.startswith("twitter:") and not result["twitter_card"]:
                # Only fill twitter_card from reverse match if nothing was
                # captured via forward match (avoids duplicate/overwrite issues).
                key = attr_value[len("twitter:"):]
                result["twitter_card"][key] = content
        elif attr_name == "property":
            if attr_value.startswith("og:") and not result["open_graph"]:
                key = attr_value[len("og:"):]
                result["open_graph"][key] = content

    return result


def _probe_homepage(domain: str, scheme: str = "https") -> dict:
    """Fetch the homepage and extract meta tags.

    Returns a dict with keys:
        exists (bool)
        status_code (int | None)
        final_url (str | None)
        title (str | None)
        description (str | None)
        keywords (str | None)
        viewport (str | None)
        open_graph (dict)
        twitter_card (dict)
    """
    url = f"{scheme}://{domain}"
    resp = _safe_get(url)

    if resp is None:
        return {
            "exists": False,
            "status_code": None,
            "final_url": None,
            "title": None,
            "description": None,
            "keywords": None,
            "viewport": None,
            "open_graph": {},
            "twitter_card": {},
        }

    meta = _parse_meta_tags(resp.text, resp.url)

    return {
        "exists": resp.status_code == 200,
        "status_code": resp.status_code,
        "final_url": resp.url,
        **meta,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_seo(domain: str) -> dict:
    """Run a full SEO audit on *domain*.

    Parameters
    ----------
    domain : str
        Domain name with or without scheme (e.g. ``example.com`` or
        ``https://example.com``).

    Returns
    -------
    dict
        Keys: robots_txt, sitemap, meta, open_graph, twitter_card.
        On total failure the dict contains a single ``error`` key.
    """
    domain = _normalise_domain(domain)

    # Determine scheme preference: if nothing works it is an error.
    # We try HTTPS first, then HTTP.
    scheme = "https"
    test_url = f"{scheme}://{domain}"
    test_resp = _safe_get(test_url)
    if test_resp is None:
        scheme = "http"
        test_url = f"{scheme}://{domain}"
        test_resp = _safe_get(test_url)

    if test_resp is None:
        return {"error": f"Could not connect to {domain} on either HTTPS or HTTP"}

    # --- robots.txt --------------------------------------------------------
    robots = _probe_robots(domain, scheme)

    # --- Sitemap -----------------------------------------------------------
    sitemap = _probe_sitemaps(domain, scheme)

    # If the common paths didn't find a sitemap but robots.txt listed one,
    # try the first robots-discovered sitemap URL.
    if not sitemap["found"] and robots.get("sitemaps"):
        extra_sitemap = _probe_sitemap_from_url(robots["sitemaps"][0])
        if extra_sitemap["found"]:
            sitemap = extra_sitemap

    # --- Homepage meta -----------------------------------------------------
    homepage = _probe_homepage(domain, scheme)

    return {
        "robots_txt": robots,
        "sitemap": sitemap,
        "meta": {
            "title": homepage.get("title"),
            "description": homepage.get("description"),
            "keywords": homepage.get("keywords"),
            "viewport": homepage.get("viewport"),
        },
        "open_graph": homepage.get("open_graph", {}),
        "twitter_card": homepage.get("twitter_card", {}),
    }
