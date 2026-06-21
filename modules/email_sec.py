"""
Email security analysis module: SPF, DMARC, DKIM, BIMI, MTA-STS, TLS-RPT.

Uses dnspython for DNS queries and requests for MTA-STS policy file retrieval.

Exports:
    run_email_security(domain: str) -> dict
"""

import re
from urllib.parse import urlparse

import dns.resolver
import requests


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DNS_TIMEOUT = 5
MTA_STS_TIMEOUT = 5
USER_AGENT = "DomainProbe/1.0"

# Common DKIM selectors to probe.
DKIM_SELECTORS = [
    "google",
    "default",
    "mail",
    "selector1",
    "selector2",
    "dkim",
    "k1",
    "mandrill",
    "amazonses",
    "sendgrid",
    "mailgun",
    "sparkpost",
    "postmark",
]


# ---------------------------------------------------------------------------
# DNS helper
# ---------------------------------------------------------------------------

def _query_txt(name: str, timeout: int = DNS_TIMEOUT) -> list[str]:
    """Query TXT records for *name* and return a list of concatenated strings.

    Returns an empty list on NXDOMAIN, NoAnswer, or any resolution error.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answers = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.exception.Timeout, dns.exception.DNSException):
        return []

    records: list[str] = []
    for rdata in answers:
        # TXT record RDATA is presented as one or more byte strings that should
        # be joined.  dnspython returns them as a space-separated string when
        # accessed via .strings, or we can join the .strings iterator.
        records.append("".join(s.decode("utf-8", errors="replace") for s in rdata.strings))
    return records


def _query_first_txt(name: str, timeout: int = DNS_TIMEOUT) -> str | None:
    """Return the first TXT record for *name*, or None."""
    records = _query_txt(name, timeout=timeout)
    return records[0] if records else None


# ---------------------------------------------------------------------------
# 1. SPF
# ---------------------------------------------------------------------------

def _check_spf(domain: str) -> dict:
    """Query TXT records of *domain* for an SPF record (starts with ``v=spf1``).

    Returns a dict with keys:
        present (bool)
        record (str | None)
        qualifier (str | None) — ``-all``, ``~all``, ``?all``, ``+all``
        includes (list[str])
        ip4 (list[str])
        ip6 (list[str])
        redirect (str | None)
        mx (bool)
        valid (bool)
    """
    txt_records = _query_txt(domain)
    spf_record: str | None = None
    for rec in txt_records:
        if rec.strip().lower().startswith("v=spf1"):
            spf_record = rec.strip()
            break

    if spf_record is None:
        return {
            "present": False,
            "record": None,
            "qualifier": None,
            "includes": [],
            "ip4": [],
            "ip6": [],
            "redirect": None,
            "mx": False,
            "valid": False,
        }

    # Parse SPF record
    includes: list[str] = []
    ip4: list[str] = []
    ip6: list[str] = []
    redirect: str | None = None
    mx = False
    qualifier: str | None = None

    tokens = spf_record.split()

    for token in tokens:
        token_lower = token.lower()

        if token_lower == "v=spf1":
            continue

        # Qualifier: -all, ~all, ?all, +all (or just "all" = +all)
        if token_lower in ("-all", "~all", "?all", "+all", "all"):
            if token_lower == "all":
                qualifier = "+all"
            else:
                qualifier = token_lower
            continue

        # include:
        if token_lower.startswith("include:"):
            includes.append(token[len("include:"):])
            continue

        # ip4:
        if token_lower.startswith("ip4:"):
            ip4.append(token[len("ip4:"):])
            continue

        # ip6:
        if token_lower.startswith("ip6:"):
            ip6.append(token[len("ip6:"):])
            continue

        # redirect=
        if token_lower.startswith("redirect="):
            redirect = token[len("redirect="):]
            continue

        # mx
        if token_lower == "mx" or token_lower.startswith("mx/"):
            mx = True
            continue

        # Other mechanisms (a, ptr, exists, exp) are noted but not deeply parsed.
        # They don't affect validity per se.

    # Basic validity: the record starts with v=spf1 and has at least one
    # mechanism/qualifier beyond the version tag.
    valid = len(tokens) > 1

    return {
        "present": True,
        "record": spf_record,
        "qualifier": qualifier,
        "includes": includes,
        "ip4": ip4,
        "ip6": ip6,
        "redirect": redirect,
        "mx": mx,
        "valid": valid,
    }


# ---------------------------------------------------------------------------
# 2. DMARC
# ---------------------------------------------------------------------------

def _check_dmarc(domain: str) -> dict:
    """Query ``_dmarc.{domain}`` TXT records for a DMARC policy (``v=DMARC1``).

    Returns a dict with keys:
        present (bool)
        record (str | None)
        policy (str | None) — ``none``, ``quarantine``, or ``reject``
        subdomain_policy (str | None)
        pct (str | None)
        rua (list[str])
        ruf (list[str])
        adkim (str | None) — ``strict`` or ``relaxed``
        aspf (str | None) — ``strict`` or ``relaxed``
        valid (bool)
    """
    txt_records = _query_txt(f"_dmarc.{domain}")
    dmarc_record: str | None = None
    for rec in txt_records:
        if rec.strip().lower().startswith("v=dmarc1"):
            dmarc_record = rec.strip()
            break

    if dmarc_record is None:
        return {
            "present": False,
            "record": None,
            "policy": None,
            "subdomain_policy": None,
            "pct": None,
            "rua": [],
            "ruf": [],
            "adkim": None,
            "aspf": None,
            "valid": False,
        }

    # Parse DMARC tag-value pairs.  Tags are separated by semicolons.
    tags: dict[str, str] = {}
    # Split on semicolons; DMARC tags are case-insensitive for the tag name.
    for part in dmarc_record.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, _, value = part.partition("=")
        tags[key.strip().lower()] = value.strip()

    policy = tags.get("p", None)
    sp = tags.get("sp", None)
    pct = tags.get("pct", None)
    rua_raw = tags.get("rua", "")
    ruf_raw = tags.get("ruf", "")
    adkim = tags.get("adkim", None)
    aspf = tags.get("aspf", None)

    # rua and ruf can be comma-separated lists, possibly with size limits
    # (e.g. "mailto:dmarc@example.com!10m").  We keep them as-is.
    rua = [addr.strip() for addr in rua_raw.split(",") if addr.strip()] if rua_raw else []
    ruf = [addr.strip() for addr in ruf_raw.split(",") if addr.strip()] if ruf_raw else []

    # Validity: v=DMARC1 is present and p tag is present.
    valid = "v" in tags and "p" in tags

    return {
        "present": True,
        "record": dmarc_record,
        "policy": policy,
        "subdomain_policy": sp,
        "pct": pct,
        "rua": rua,
        "ruf": ruf,
        "adkim": adkim,
        "aspf": aspf,
        "valid": valid,
    }


# ---------------------------------------------------------------------------
# 3. DKIM
# ---------------------------------------------------------------------------

def _check_dkim(domain: str) -> dict:
    """Probe common DKIM selectors at ``{selector}._domainkey.{domain}``.

    Returns a dict with keys:
        present (bool) — True if at least one selector returned a DKIM record
        selectors_found (list[str]) — selectors that had a DKIM TXT record
        keys_found (int) — total number of selectors with a DKIM record
        valid_count (int) — number of records that contain a public key (``p=``)
    """
    selectors_found: list[str] = []
    valid_count = 0

    for selector in DKIM_SELECTORS:
        name = f"{selector}._domainkey.{domain}"
        records = _query_txt(name)
        if not records:
            continue

        for rec in records:
            rec_lower = rec.strip().lower()
            if rec_lower.startswith("v=dkim1"):
                selectors_found.append(selector)
                # A DKIM record is "valid" if it declares v=DKIM1 and includes
                # a public key (p=).  k= defaults to rsa.
                if "p=" in rec_lower:
                    valid_count += 1
                break  # One DKIM record per selector is enough.

    return {
        "present": len(selectors_found) > 0,
        "selectors_found": selectors_found,
        "keys_found": len(selectors_found),
        "valid_count": valid_count,
    }


# ---------------------------------------------------------------------------
# 4. BIMI
# ---------------------------------------------------------------------------

def _check_bimi(domain: str) -> dict:
    """Query ``default._bimi.{domain}`` TXT records for a BIMI record
    (``v=BIMI1``).

    Returns a dict with keys:
        present (bool)
        record (str | None)
        logo_url (str | None)
        authority (str | None)
    """
    txt_records = _query_txt(f"default._bimi.{domain}")
    bimi_record: str | None = None
    for rec in txt_records:
        if rec.strip().lower().startswith("v=bimi1"):
            bimi_record = rec.strip()
            break

    if bimi_record is None:
        return {
            "present": False,
            "record": None,
            "logo_url": None,
            "authority": None,
        }

    # Parse BIMI tags (semicolon-separated).
    tags: dict[str, str] = {}
    for part in bimi_record.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, _, value = part.partition("=")
        tags[key.strip().lower()] = value.strip()

    logo_url = tags.get("l", None)
    authority = tags.get("a", None)

    return {
        "present": True,
        "record": bimi_record,
        "logo_url": logo_url,
        "authority": authority,
    }


# ---------------------------------------------------------------------------
# 5. MTA-STS
# ---------------------------------------------------------------------------

def _check_mta_sts(domain: str) -> dict:
    """Check MTA-STS by querying ``_mta-sts.{domain}`` TXT and fetching
    ``https://mta-sts.{domain}/.well-known/mta-sts.txt``.

    Returns a dict with keys:
        present (bool) — True if either the DNS record or the policy file exists
        record (str | None) — the TXT record content, or None
        policy_url (str | None) — URL of the policy file
        policy_content (str | None) — raw content of the policy file, or None
        error (str | None) — error message if the policy fetch failed
    """
    # Step 1: DNS TXT record
    dns_record = _query_first_txt(f"_mta-sts.{domain}")

    # Step 2: Policy file
    policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    policy_content: str | None = None
    error: str | None = None

    try:
        resp = requests.get(
            policy_url,
            timeout=MTA_STS_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
        if resp.status_code == 200:
            # Validate that the content type is text/plain (or missing, as some
            # servers omit it).  RFC 8461 section 3.2 requires text/plain.
            content_type = resp.headers.get("Content-Type", "")
            if "text/plain" in content_type or not content_type:
                policy_content = resp.text.strip()
            else:
                error = f"Unexpected Content-Type: {content_type}"
        else:
            error = f"HTTP {resp.status_code}"
    except requests.exceptions.SSLError as exc:
        error = f"TLS error: {exc}"
    except requests.exceptions.ConnectionError as exc:
        error = f"Connection error: {exc}"
    except requests.exceptions.Timeout:
        error = "Request timed out"
    except requests.exceptions.RequestException as exc:
        error = f"Request error: {exc}"

    present = dns_record is not None or policy_content is not None

    return {
        "present": present,
        "record": dns_record,
        "policy_url": policy_url,
        "policy_content": policy_content,
        "error": error if not policy_content else None,
    }


# ---------------------------------------------------------------------------
# 6. TLS-RPT
# ---------------------------------------------------------------------------

def _check_tls_rpt(domain: str) -> dict:
    """Query ``_smtp._tls.{domain}`` TXT records for a TLS-RPT record
    (``v=TLSRPTv1``).

    Returns a dict with keys:
        present (bool)
        record (str | None)
    """
    txt_records = _query_txt(f"_smtp._tls.{domain}")
    tls_rpt_record: str | None = None
    for rec in txt_records:
        if rec.strip().lower().startswith("v=tlsrptv1"):
            tls_rpt_record = rec.strip()
            break

    return {
        "present": tls_rpt_record is not None,
        "record": tls_rpt_record,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_email_security(domain: str) -> dict:
    """Run all email security checks against *domain*.

    Parameters
    ----------
    domain : str
        Domain name without scheme, e.g. ``example.com``.

    Returns
    -------
    dict
        Keys: spf, dmarc, dkim, bimi, mta_sts, tls_rpt.
        Each value is a dict with details for that protocol.
        On total failure the dict contains a single ``error`` key.
    """
    # Strip any scheme, trailing slash, or whitespace.
    domain = domain.strip().strip("/")
    domain = re.sub(r"^https?://", "", domain, count=1)

    if not domain:
        return {"error": "Empty domain"}

    try:
        return {
            "spf": _check_spf(domain),
            "dmarc": _check_dmarc(domain),
            "dkim": _check_dkim(domain),
            "bimi": _check_bimi(domain),
            "mta_sts": _check_mta_sts(domain),
            "tls_rpt": _check_tls_rpt(domain),
        }
    except Exception as exc:
        return {"error": f"Unexpected error: {exc}"}
