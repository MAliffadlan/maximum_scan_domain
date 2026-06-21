"""
Related domains module for domain-probe.

Exports run_related(domain, ip, nameservers_list) which returns a dict with
domains discovered on the same IP (reverse IP lookup) and a note about same-
nameserver lookups.
"""

import time

import requests

# ── Constants ────────────────────────────────────────────────────────────────────

_YOUGETSIGNAL_URL = "https://domains.yougetsignal.com/domains.php"
_YOUGETSIGNAL_TIMEOUT = 10  # seconds

_HACKERTARGET_URL = "https://api.hackertarget.com/reverseiplookup/"
_HACKERTARGET_TIMEOUT = 10  # seconds

_MAX_RESULTS = 50


# ── Strategy 1: YouGetSignal ─────────────────────────────────────────────────────

def _reverse_ip_yougetsignal(ip: str) -> list[str] | None:
    """Query YouGetSignal for domains hosted on *ip*.

    Returns a list of domain strings on success, or None on failure.
    """
    timestamp = int(time.time() * 1000)
    data = {
        "remoteAddress": ip,
        "key": "",
        "_": str(timestamp),
    }
    try:
        resp = requests.post(
            _YOUGETSIGNAL_URL,
            data=data,
            timeout=_YOUGETSIGNAL_TIMEOUT,
        )
        resp.raise_for_status()
        payload = resp.json()
    except Exception:
        return None

    # The API returns a dict with a "domainList" key containing a list of
    # strings — sometimes empty on error, sometimes entirely absent.
    domain_list = payload.get("domainList")
    if not isinstance(domain_list, list):
        return None

    # Normalise: lowercase, strip whitespace, drop empties.
    results = []
    for d in domain_list:
        if isinstance(d, str) and d.strip():
            results.append(d.strip().lower())
    return results


# ── Strategy 2: HackerTarget (backup) ────────────────────────────────────────────

def _reverse_ip_hackertarget(ip: str) -> list[str] | None:
    """Query HackerTarget reverse IP lookup as a backup.

    Returns a list of domain strings on success, or None on failure.
    """
    try:
        resp = requests.get(
            _HACKERTARGET_URL,
            params={"q": ip},
            timeout=_HACKERTARGET_TIMEOUT,
        )
        resp.raise_for_status()
        text = resp.text
    except Exception:
        return None

    # The API returns one domain per line.  The first line may be a header
    # like "--- results for ... ---" or an error message — filter those out.
    lines = text.strip().splitlines()
    results = []
    for line in lines:
        line = line.strip()
        # Skip informational / header / error lines.
        if not line or line.startswith("-") or " " in line:
            continue
        # A valid reverse-IP result looks like a domain name.
        if "." in line:
            results.append(line.lower())
    return results


# ── Strategy 3: Same-nameserver hint ─────────────────────────────────────────────

def _same_ns_hint(nameservers_list: list[str]) -> list[str]:
    """Note which nameservers *could* be queried for shared-domain discovery.

    This is intentionally a no-op stub — querying every NS for common domains
    is too slow for a real-time probe.  We return the NS list so the caller
    (or a future background job) can use it.
    """
    if not nameservers_list:
        return []
    return [ns.strip().lower() for ns in nameservers_list if ns and ns.strip()]


# ── Public API ───────────────────────────────────────────────────────────────────

def run_related(
    domain: str,
    ip: str,
    nameservers_list: list[str],
) -> dict:
    """Discover domains related to *domain* via reverse-IP and nameserver hints.

    Parameters
    ----------
    domain : str
        The target domain (used only for logging / context — not queried).
    ip : str
        Resolved IP address of *domain*.  Reverse-IP lookups are performed
        against this address.
    nameservers_list : list[str]
        Authoritative nameserver hostnames for *domain*.  Same-nameserver
        discovery is noted but not executed (too slow for inline probing).

    Returns
    -------
    dict
        Keys:
        - reverse_ip_domains (list[str]): up to 50 domain names found on the
          same IP.  Empty list if no results or all lookups failed.
        - reverse_ip_source (str | None): "yougetsignal" or "hackertarget"
          depending on which service delivered results.  None if both failed.
        - same_ns_hint (list[str]): the *nameservers_list* values that were
          noted for potential future same-NS queries.
        - error (str | None): human-readable error note when reverse-IP
          returns nothing, otherwise None.
    """
    result: dict = {
        "reverse_ip_domains": [],
        "reverse_ip_source": None,
        "same_ns_hint": [],
        "error": None,
    }

    # ── Validate input ──────────────────────────────────────────────────────────

    if not ip or not ip.strip():
        result["error"] = "No IP address provided for reverse-IP lookup"
        result["same_ns_hint"] = _same_ns_hint(nameservers_list)
        return result

    # ── Reverse IP lookup ───────────────────────────────────────────────────────

    domains = _reverse_ip_yougetsignal(ip)
    if domains is not None:
        result["reverse_ip_domains"] = domains[:_MAX_RESULTS]
        result["reverse_ip_source"] = "yougetsignal"
    else:
        # Primary source failed — try the backup.
        domains = _reverse_ip_hackertarget(ip)
        if domains is not None:
            result["reverse_ip_domains"] = domains[:_MAX_RESULTS]
            result["reverse_ip_source"] = "hackertarget"

    if not result["reverse_ip_domains"]:
        result["error"] = (
            "Reverse IP lookup failed for both YouGetSignal and HackerTarget"
        )

    # ── Same-nameserver hint (not executed inline) ──────────────────────────────

    result["same_ns_hint"] = _same_ns_hint(nameservers_list)

    return result
