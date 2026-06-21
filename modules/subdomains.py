"""
Subdomain enumeration module for domain-probe.

Exports run_subdomains(domain, brute_count=0) which returns a dict with
discovered subdomains via crt.sh (passive) and optionally DNS brute-force.
"""

import re
import secrets
import string
import sys

import dns.resolver
import requests


# ── Passive: crt.sh ───────────────────────────────────────────────────────────

_CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
_CRTSH_TIMEOUT = 15  # seconds


def _fetch_crtsh(domain: str):
    """Query crt.sh for certificates covering *.<domain>.

    Returns a list of raw name_value strings (may include multiline entries).
    Returns an empty list on any failure.
    """
    url = _CRTSH_URL.format(domain=domain)
    try:
        resp = requests.get(url, timeout=_CRTSH_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return []

    results = []
    for entry in data:
        nv = entry.get("name_value", "")
        if nv:
            results.append(nv)
    return results


def _parse_name_values(raw_entries, domain: str):
    """Split multiline entries, filter to those matching *domain*, strip
    wildcards / leading dots, deduplicate, and return a sorted list."""
    domain_lower = domain.lower().strip(".")

    seen = set()
    for entry in raw_entries:
        # crt.sh sometimes returns newline-separated name_value fields.
        for name in entry.splitlines():
            name = name.strip().lower()
            if not name:
                continue

            # Strip wildcard prefix and any leading dot that remains.
            name = name.lstrip("*.")
            # Strip leading dot (some entries start with a dot).
            name = name.lstrip(".")
            name = name.strip()

            if not name:
                continue

            # Keep only names that end with our target domain.
            if name == domain_lower or name.endswith("." + domain_lower):
                seen.add(name)

    return sorted(seen)


# ── Active brute-force ────────────────────────────────────────────────────────

_DNS_TIMEOUT = 2  # seconds per lookup

TOP_500_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "m",
    "imap", "test", "secure", "server", "api", "dev", "staging", "app",
    "blog", "shop", "admin", "cdn", "remote", "portal", "vpn", "docs",
    "support", "status", "mx", "email", "news", "media", "static", "images",
    "cms", "db", "mysql", "dns", "ns3", "ns4", "firewall", "proxy", "gw",
    "gateway", "cloud", "store", "payments", "billing", "monitor", "backup",
    "beta", "demo", "download", "git", "wiki", "help", "info", "mobile",
    "my", "apps", "uat", "qa", "stage", "www2", "host", "web", "cache",
    "origin", "cdn1", "cdn2", "lb", "mail1", "mail2", "mx1", "smtp1",
    "relay", "chat", "irc", "forum", "community", "login", "sso", "auth",
    "oauth", "id", "account", "user", "api1", "api2", "rest", "graphql",
    "ws", "analytics", "stats", "metrics", "track", "pixel", "ads",
    "assets", "static1", "search", "elastic", "jenkins", "ci", "build",
    "deploy", "docker", "k8s", "kubernetes", "swarm", "db1", "redis",
    "memcache", "mongo", "files", "file", "share", "drive", "backup1",
    "logs", "log", "alerts", "status1", "health", "ping", "cpanel",
    "webmin", "phpmyadmin", "admin1", "config", "setup", "crm", "checkout",
    "cart", "order", "partner", "investor", "press", "about", "contact",
    "legal", "privacy", "terms", "en", "es", "fr", "de",
]


# ── Wildcard detection ────────────────────────────────────────────────────

def _detect_wildcard(domain: str, samples: int = 3) -> set[str]:
    """Attempt to detect wildcard DNS for *domain*.

    Resolves *samples* random, nonexistent subdomains and collects the IPs
    returned.  If ALL random subdomains resolve, wildcard DNS is presumed
    active and the collected IPs are returned as the set of wildcard IPs.

    Returns an empty set when no wildcard is detected.
    """
    wildcard_ips: set[str] = set()
    resolved_count = 0

    for _ in range(samples):
        rand = ''.join(secrets.choice(string.ascii_lowercase) for _ in range(10))
        fqdn = f"{rand}.{domain}"
        try:
            answer = dns.resolver.resolve(fqdn, "A", lifetime=3)
            resolved_count += 1
            for rr in answer:
                wildcard_ips.add(str(rr))
        except Exception:
            pass  # NXDOMAIN → no wildcard for this test

    # Wildcard is active only when ALL samples resolved
    if resolved_count < samples:
        return set()

    return wildcard_ips


def _brute_subdomain(domain: str, prefix: str, wildcard_ips: set[str] | None = None):
    """Attempt to resolve <prefix>.<domain>.  Returns the FQDN string if any
    A, AAAA, or CNAME record is found and the address is NOT a wildcard IP;
    otherwise returns None."""
    fqdn = f"{prefix}.{domain}"

    # Try A record
    try:
        answer = dns.resolver.resolve(fqdn, "A", lifetime=_DNS_TIMEOUT)
        ip = str(answer[0])
        if wildcard_ips and ip in wildcard_ips:
            return None  # false positive – matches wildcard IP
        return fqdn
    except Exception:
        pass

    # Try AAAA record
    try:
        answer = dns.resolver.resolve(fqdn, "AAAA", lifetime=_DNS_TIMEOUT)
        ip = str(answer[0])
        if wildcard_ips and ip in wildcard_ips:
            return None  # false positive – matches wildcard IP
        return fqdn
    except Exception:
        pass

    # Try CNAME record (no IP to check – accept if resolved)
    try:
        dns.resolver.resolve(fqdn, "CNAME", lifetime=_DNS_TIMEOUT)
        return fqdn
    except Exception:
        pass

    return None


def _brute_subdomains(domain: str, count: int, wildcard_ips: set[str] | None = None):
    """Brute-force the first `count` entries from TOP_500_SUBDOMAINS.

    Returns a sorted list of resolved FQDNs."""
    # Clamp count to available list length.
    candidates = TOP_500_SUBDOMAINS[: min(count, len(TOP_500_SUBDOMAINS))]

    found = []
    for prefix in candidates:
        result = _brute_subdomain(domain, prefix, wildcard_ips)
        if result:
            found.append(result)

    return sorted(found)


# ── Public API ────────────────────────────────────────────────────────────────

def run_subdomains(domain, brute_count=0):
    """Enumerate subdomains for *domain*.

    Parameters
    ----------
    domain : str
        Target domain (e.g. ``example.com``).
    brute_count : int
        Number of common subdomain prefixes to brute-force (from
        TOP_500_SUBDOMAINS).  Defaults to 0 (passive-only).

    Returns
    -------
    dict
        {
            "subdomains": [str, ...],   # sorted, unique FQDNs
            "source": "crt.sh" | "crt.sh+brute",
            "count": int
        }
    """
    # Normalise the domain.
    domain = domain.lower().strip()
    # Strip protocol, path, port, etc.
    domain = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", domain)
    domain = domain.split("/")[0]
    domain = domain.split(":")[0]
    domain = domain.strip(".")

    if not domain:
        return {"subdomains": [], "source": "crt.sh", "count": 0}

    # ── Passive phase ────────────────────────────────────────────────────
    raw_entries = _fetch_crtsh(domain)
    subdomains = _parse_name_values(raw_entries, domain)

    source = "crt.sh"

    # ── Active brute-force phase ─────────────────────────────────────────
    wildcard_ips: set[str] = set()
    if brute_count > 0:
        # Detect wildcard DNS *before* brute-force to filter false positives
        wildcard_ips = _detect_wildcard(domain)

        brute_results = _brute_subdomains(domain, brute_count, wildcard_ips)
        # Merge with passive results.
        for fqdn in brute_results:
            if fqdn not in subdomains:  # subdomains is a sorted list
                subdomains.append(fqdn)
        subdomains.sort()
        source = "crt.sh+brute"

    return {
        "subdomains": subdomains,
        "source": source,
        "count": len(subdomains),
        "wildcard_detected": len(wildcard_ips) > 0,
        "wildcard_ips": sorted(wildcard_ips) if wildcard_ips else [],
    }
