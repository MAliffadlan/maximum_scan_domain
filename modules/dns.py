"""
DNS records module for domain-probe.

Exports run_dns(domain, nameservers=None) which returns a dict of DNS record
types mapped to lists of string representations.
"""

import re

import dns.resolver


# Record types we query, in the order we query them.
_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV")

# Default resolver timeout / lifetime (seconds).
_TIMEOUT = 5
_LIFETIME = 5


def _clean_domain(domain: str) -> str:
    """Strip protocol scheme and leading 'www.' from a domain string."""
    # Remove scheme (http://, https://, ftp://, etc.)
    cleaned = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", domain)
    # Remove leading "www."
    cleaned = re.sub(r"^www\.", "", cleaned)
    # Strip trailing slashes / path / query / fragment.
    cleaned = cleaned.split("/")[0]
    cleaned = cleaned.split("?")[0]
    cleaned = cleaned.split("#")[0]
    # Lowercase for consistency.
    cleaned = cleaned.strip().lower()
    return cleaned


def _get_authoritative_nameservers(domain: str) -> list[str]:
    """Return the list of authoritative nameserver hostnames for *domain*.

    Uses the system resolver to chase delegations (dns.resolver.resolve with
    search=True).  Falls back to the NS record set obtained against the domain
    itself if that yields results, otherwise returns an empty list.
    """
    nameservers: set[str] = set()

    # First attempt: chase delegations via the system resolver.
    try:
        answer = dns.resolver.resolve(domain, "NS", search=True)
        for rr in answer:
            ns_name = str(rr.target).rstrip(".").lower()
            if ns_name:
                nameservers.add(ns_name)
    except Exception:
        pass

    # Second attempt: direct query (may hit the zone's own NS RRset).
    if not nameservers:
        try:
            answer = dns.resolver.resolve(domain, "NS", search=False)
            for rr in answer:
                ns_name = str(rr.target).rstrip(".").lower()
                if ns_name:
                    nameservers.add(ns_name)
        except Exception:
            pass

    return sorted(nameservers)


def run_dns(domain: str, nameservers: list[str] | None = None) -> dict:
    """Query DNS records for *domain* and return a dict keyed by record type.

    Parameters
    ----------
    domain : str
        The domain name to query (may include protocol, www, path — all
        stripped before resolution).
    nameservers : list[str] or None
        Optional list of nameserver IPs / hostnames to use.  When provided
        a dedicated resolver is created with those nameservers and the
        authoritative NS set is derived from the NS record query against
        *domain* itself.

    Returns
    -------
    dict
        Keys: "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV",
        "authoritative_nameservers".
        Each record-type value is a list of strings.
        On total failure (e.g. the domain is unresolvable at all) returns
        ``{"error": "<message>"}``.
    """
    domain = _clean_domain(domain)

    if not domain:
        return {"error": "empty domain after cleaning"}

    # Set up the resolver.
    if nameservers:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = list(nameservers)
        resolver.timeout = _TIMEOUT
        resolver.lifetime = _LIFETIME
    else:
        resolver = dns.resolver.get_default_resolver()
        # Ensure the defaults we want (the system resolver may differ).
        resolver.timeout = _TIMEOUT
        resolver.lifetime = _LIFETIME

    results: dict[str, list[str]] = {
        rtype: [] for rtype in _RECORD_TYPES
    }

    had_any_success = False

    for rtype in _RECORD_TYPES:
        try:
            answer = resolver.resolve(domain, rtype)
            had_any_success = True
            for rr in answer:
                results[rtype].append(str(rr))
        except dns.resolver.NoAnswer:
            # The record type exists but has no records.
            pass
        except dns.resolver.NXDOMAIN:
            # Domain does not exist — no records for any type.
            pass
        except dns.resolver.LifetimeTimeout:
            # Query timed out for this record type.
            pass
        except dns.exception.DNSException:
            # Any other DNS error — skip this record type.
            pass

    if not had_any_success:
        # Double-check: was *every* query NXDOMAIN (domain truly nonexistent)?
        # If so return empty lists rather than an error so callers can
        # distinguish "dead domain" from "resolver failure".
        # We test with a quick A-record lookup using the *system* resolver
        # to avoid false positives when custom nameservers are flaky.
        try:
            sys_resolver = dns.resolver.get_default_resolver()
            sys_resolver.timeout = _TIMEOUT
            sys_resolver.lifetime = _LIFETIME
            sys_resolver.resolve(domain, "A")
            # Succeeded — so the earlier failures were from custom NS.
            # Return the (empty) results we have.
        except dns.resolver.NXDOMAIN:
            # Domain genuinely does not exist — return empty results.
            pass
        except Exception:
            # Cannot even resolve with system — total failure.
            return {"error": f"DNS resolution failed completely for {domain}"}

    # Add authoritative nameservers.
    auth_ns = _get_authoritative_nameservers(domain)
    results["authoritative_nameservers"] = auth_ns

    # --- AXFR attempt (zone transfer) ---
    results["axfr_attempted"] = False
    results["axfr_success"] = False
    results["axfr_records"] = []
    for ns in auth_ns:
        try:
            import socket as sock_mod
            ns_ip = sock_mod.getaddrinfo(ns, 53, sock_mod.AF_INET, sock_mod.SOCK_DGRAM)[0][4][0]
            xfr = dns.query.xfr(ns_ip, domain, timeout=5, lifetime=10)
            try:
                for _ in xfr:
                    pass  # consume to see if it works
                results["axfr_success"] = True
                results["axfr_records"].append({"nameserver": ns, "status": "open"})
            except dns.exception.FormError:
                results["axfr_records"].append({"nameserver": ns, "status": "refused"})
            except dns.exception.DNSException:
                results["axfr_records"].append({"nameserver": ns, "status": "denied"})
            except Exception:
                results["axfr_records"].append({"nameserver": ns, "status": "error"})
        except Exception:
            pass
    results["axfr_attempted"] = len(results["axfr_records"]) > 0

    return results
