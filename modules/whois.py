"""
WHOIS + RDAP lookup module for domain-probe.
Extracts owner/registrant details, contacts, and raw WHOIS data.
Exports run_whois(domain) -> dict.
"""

import re
import json
import whois
import requests


def _strip_domain(domain: str) -> str:
    """Clean a domain string: remove protocol, www prefix, path, port, query, trailing dot."""
    if not domain or not isinstance(domain, str):
        return ""
    domain = domain.strip().lower()
    domain = re.sub(r'^https?://', '', domain)
    domain = re.sub(r'^www\.', '', domain)
    domain = domain.split("/")[0]
    domain = domain.split(":")[0]
    domain = domain.split("?")[0]
    domain = domain.split("#")[0]
    domain = domain.rstrip(".")
    return domain


def _safe_list(value):
    """Normalize a value to a list of strings."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _safe_str(value):
    """Normalize a value to a single string."""
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(v) for v in value if v)
    return str(value)


def _safe_date(value):
    """Normalize a date/datetime value to an ISO-8601 string (or empty string)."""
    if value is None:
        return ""
    if isinstance(value, list):
        value = value[0] if value else None
        if value is None:
            return ""
    if isinstance(value, str):
        return value.strip()
    try:
        return value.isoformat() if hasattr(value, "isoformat") else str(value)[:10]
    except Exception:
        return str(value)[:10]


def _parse_registrant_from_raw(raw_text: str) -> dict:
    """Fallback: parse registrant details from raw WHOIS text."""
    info = {}
    patterns = {
        "name":         r"(?i)(?:Registrant\s*Name|person|descr)\s*:\s*(.+)",
        "organization": r"(?i)(?:Registrant\s*Organization|org-name)\s*:\s*(.+)",
        "address":      r"(?i)(?:Registrant\s*Street|address)\s*:\s*(.+)",
        "city":         r"(?i)(?:Registrant\s*City)\s*:\s*(.+)",
        "state":        r"(?i)(?:Registrant\s*(?:State|Province))\s*:\s*(.+)",
        "postal_code":  r"(?i)(?:Registrant\s*(?:Postal\s*Code|Zip))\s*:\s*(.+)",
        "country":      r"(?i)(?:Registrant\s*Country)\s*:\s*(.+)",
        "phone":        r"(?i)(?:Registrant\s*Phone)\s*:\s*(.+)",
        "email":        r"(?i)(?:Registrant\s*Email)\s*:\s*(.+)",
        "registrar":    r"(?i)(?:Registrar|Registrar\s*Name)\s*:\s*(.+)",
    }
    for key, pat in patterns.items():
        m = re.search(pat, raw_text)
        if m:
            val = m.group(1).strip()
            if val and val.lower() not in ("redacted for privacy", "redacted", "not disclosed"):
                info[key] = val
    return info


def _rdap_lookup(domain: str) -> dict | None:
    """Attempt RDAP lookup for domain ownership info.
    RDAP is the modern JSON-based replacement for WHOIS, less affected by GDPR redaction.
    Returns dict with registrant info or None on failure."""
    endpoints = [
        f"https://rdap.verisign.com/domain/v1/{domain}",      # .com / .net
        f"https://rdap.org/domain/{domain}",                   # IANA bootstrap
        f"https://rdap.identitydigital.services/rdap/domain/{domain}",  # .org / .info
        f"https://rdap.centralnic.com/rdap/domain/{domain}",   # .xyz / .io / .co
    ]
    for url in endpoints:
        try:
            resp = requests.get(url, timeout=10, headers={"Accept": "application/json"})
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            continue
    return None


def _extract_rdap_entities(rdap_data: dict) -> dict:
    """Extract owner/registrant entities from RDAP JSON."""
    entities = rdap_data.get("entities", [])
    registrant = {}
    admin = {}
    tech = {}

    for ent in entities:
        roles = ent.get("roles", [])
        vcard = ent.get("vcardArray", [[], []])
        if len(vcard) < 2:
            continue

        vcard_props = vcard[1]  # [[prop, {}, "text", val], ...]
        props = {}
        for p in vcard_props:
            if len(p) >= 4 and p[0] == "prop":
                props[p[2]] = p[3]

        contact = {
            "name":     props.get("fn", ""),
            "org":      props.get("org", ""),
            "email":    props.get("email", ""),
            "phone":    props.get("voice", ""),
            "address":  ", ".join(filter(None, [
                props.get("street", ""),
                props.get("locality", ""),
                props.get("region", ""),
                props.get("code", ""),
                props.get("country-name", ""),
            ])),
        }

        if "registrant" in roles:
            registrant = contact
        elif "administrative" in roles:
            admin = contact
        elif "technical" in roles:
            tech = contact

    # Also try vcard from RDAP root level
    vcard = rdap_data.get("vcardArray", [[], []])
    if len(vcard) >= 2:
        props = {}
        for p in vcard[1]:
            if len(p) >= 4 and p[0] == "prop":
                props[p[2]] = p[3]
        if not registrant.get("name"):
            registrant["name"] = props.get("fn", "")
        if not registrant.get("email"):
            registrant["email"] = props.get("email", "")
        if not registrant.get("phone"):
            registrant["phone"] = props.get("voice", "")

    return {"registrant": registrant, "admin": admin, "tech": tech}


def _deep_whois_lookup(domain: str, registrar_whois_server: str = "") -> str:
    """Query the registrar's WHOIS server directly for full registrant data.
    Uses a raw TCP connection to port 43 (WHOIS protocol).
    Returns raw text response or empty string on failure."""
    import socket

    whois_text = ""
    servers_to_try = []

    if registrar_whois_server:
        servers_to_try.append(registrar_whois_server)

    # IANA referral for common TLDs
    tld = domain.rsplit(".", 1)[-1].lower()
    iana_map = {
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
        "info": "whois.afilias.net",
        "io":  "whois.nic.io",
        "co":  "whois.nic.co",
        "id":  "whois.id",
        "xyz": "whois.nic.xyz",
        "dev": "whois.nic.google",
        "app": "whois.nic.google",
        "me":  "whois.nic.me",
        "sh":  "whois.nic.sh",
    }
    default_server = iana_map.get(tld, "whois.iana.org")
    servers_to_try.append(default_server)

    for server in servers_to_try:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((server, 43))
            # For .com/.net, query with "domain " prefix for referral
            if server == "whois.verisign-grs.com":
                sock.send(f"domain {domain}\r\n".encode())
            else:
                sock.send(f"{domain}\r\n".encode())

            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            sock.close()
            text = response.decode("utf-8", errors="replace")

            # If we got a referral to registrar WHOIS, follow it
            if "Whois Server:" in text and server == "whois.verisign-grs.com":
                m = re.search(r"Whois Server:\s*(\S+)", text)
                if m:
                    ref_server = m.group(1).strip()
                    if ref_server not in servers_to_try:
                        try:
                            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock2.settimeout(10)
                            sock2.connect((ref_server, 43))
                            sock2.send(f"{domain}\r\n".encode())
                            resp2 = b""
                            while True:
                                c = sock2.recv(4096)
                                if not c:
                                    break
                                resp2 += c
                            sock2.close()
                            text = resp2.decode("utf-8", errors="replace")
                        except Exception:
                            pass
            whois_text = text
            break
        except Exception:
            continue

    return whois_text


def _parse_registrar_whois(raw_text: str) -> dict:
    """Parse registrant details from registrar-level WHOIS response.
    Handles common formats: key-value, RPSL, etc."""
    owner = {}
    patterns = {
        "name":         [
            r"(?im)^Registrant\s*Name:\s*(.+)",
            r"(?im)^Registrant:\s*(.+)",
            r"(?im)^person:\s*(.+)",
        ],
        "organization": [
            r"(?im)^Registrant\s*Organization:\s*(.+)",
            r"(?im)^Registrant Org:\s*(.+)",
            r"(?im)^org-name:\s*(.+)",
            r"(?im)^OrgName:\s*(.+)",
        ],
        "address":      [
            r"(?im)^Registrant\s*Street:\s*(.+)",
            r"(?im)^Registrant\s*Address:\s*(.+)",
            r"(?im)^address:\s*(.+)",
        ],
        "city":         [
            r"(?im)^Registrant\s*City:\s*(.+)",
        ],
        "state":        [
            r"(?im)^Registrant\s*(?:State|Province):\s*(.+)",
        ],
        "postal_code":  [
            r"(?im)^Registrant\s*(?:Postal\s*Code|Zip):\s*(.+)",
        ],
        "country":      [
            r"(?im)^Registrant\s*Country:\s*(.+)",
        ],
        "phone":        [
            r"(?im)^Registrant\s*Phone:\s*(.+)",
            r"(?im)^phone:\s*(.+)",
        ],
        "email":        [
            r"(?im)^Registrant\s*Email:\s*(.+)",
            r"(?im)^e-mail:\s*(.+)",
        ],
    }
    for field, field_patterns in patterns.items():
        for pat in field_patterns:
            m = re.search(pat, raw_text)
            if m:
                val = m.group(1).strip()
                if val and val.lower() not in (
                    "redacted for privacy", "redacted", "not disclosed",
                    "registration private", "contact privacy",
                ) and "contact privacy" not in val.lower():
                    owner[field] = val
                break
    return owner


def run_whois(domain: str) -> dict:
    """
    Perform a deep WHOIS + RDAP lookup on *domain*.

    Returns a dict with keys:
        registrar, created, expires, updated, nameservers,
        status, org, country, email,
        owner (dict: name, organization, address, city, state, postal_code, country, phone, email),
        admin_contact, tech_contact, rdap_source, raw

    On any failure returns {'error': <message>}.
    """
    try:
        clean = _strip_domain(domain)
        if not clean:
            return {"error": "Invalid domain: empty after stripping"}

        # --- WHOIS via python-whois (gets registry-level data) ---
        whois_result = whois.whois(clean)

        registrar = _safe_str(getattr(whois_result, "registrar", None))
        created = _safe_date(getattr(whois_result, "creation_date", None))
        expires = _safe_date(getattr(whois_result, "expiration_date", None))
        updated = _safe_date(getattr(whois_result, "updated_date", None))
        nameservers = _safe_list(getattr(whois_result, "name_servers", None))
        status = _safe_str(getattr(whois_result, "status", None))

        # Raw text from thin WHOIS
        raw_text = _safe_str(getattr(whois_result, "text", ""))

        # Extract registrar WHOIS server for deep lookup
        registrar_whois = ""
        m = re.search(r"(?im)^Registrar WHOIS Server:\s*(\S+)", raw_text)
        if m:
            registrar_whois = m.group(1).strip()

        # Build owner dict from thin WHOIS (what python-whois parsed)
        owner_org = _safe_str(getattr(whois_result, "org", None))
        owner_name = _safe_str(getattr(whois_result, "name", None))
        owner_address = _safe_str(getattr(whois_result, "address", None))
        owner_city = _safe_str(getattr(whois_result, "city", None))
        owner_state = _safe_str(getattr(whois_result, "state", None))
        owner_zip = _safe_str(getattr(whois_result, "zipcode", None))
        owner_country = _safe_str(getattr(whois_result, "country", None))
        owner_email = _safe_str(getattr(whois_result, "emails", getattr(whois_result, "email", None)))
        owner_phone = _safe_str(getattr(whois_result, "phone", None))

        owner = {
            "name":         owner_name,
            "organization": owner_org,
            "address":      owner_address,
            "city":         owner_city,
            "state":        owner_state,
            "postal_code":  owner_zip,
            "country":      owner_country,
            "phone":        owner_phone,
            "email":        owner_email,
        }

        # --- Deep WHOIS: query registrar WHOIS server directly ---
        deep_text = _deep_whois_lookup(clean, registrar_whois)
        if deep_text:
            # Parse registrant info from registrar WHOIS
            parsed_owner = _parse_registrar_whois(deep_text)
            for k, v in parsed_owner.items():
                if not owner.get(k):
                    owner[k] = v
            # Also try parsing from raw_text fallback
            if not any(owner.values()):
                fallback = _parse_registrant_from_raw(raw_text)
                for k, v in fallback.items():
                    if k == "registrar" and (not registrar or registrar == "registrar"):
                        registrar = v
                    elif not owner.get(k):
                        owner[k] = v
            # Merge raw texts for full reference
            if len(deep_text) > len(raw_text):
                raw_text = deep_text  # prefer the richer registrar response

        # --- RDAP lookup for richer data ---
        admin_contact = {}
        tech_contact = {}
        rdap_source = ""

        rdap_data = _rdap_lookup(clean)
        if rdap_data:
            rdap_entities = _extract_rdap_entities(rdap_data)
            rdap_reg = rdap_entities.get("registrant", {})
            admin_contact = rdap_entities.get("admin", {})
            tech_contact = rdap_entities.get("tech", {})
            rdap_source = "rdap"

            # Merge RDAP registrant data (prefer WHOIS if it has data)
            for k in ["name", "organization", "address", "email", "phone"]:
                if not owner.get(k) and rdap_reg.get(k):
                    owner[k] = rdap_reg[k]

        # Truncate raw text
        if len(raw_text) > 3000:
            raw_text = raw_text[:3000] + "\n... [truncated]"

        return {
            "registrar":     registrar if registrar else owner.get("registrar", ""),
            "created":       created,
            "expires":       expires,
            "updated":       updated,
            "nameservers":   nameservers,
            "status":        status,
            "org":           owner.get("organization", owner_org),
            "country":       owner.get("country", owner_country),
            "email":         owner.get("email", owner_email),
            "owner":         {k: v for k, v in owner.items() if v},  # omit empty
            "admin_contact": {k: v for k, v in admin_contact.items() if v},
            "tech_contact":  {k: v for k, v in tech_contact.items() if v},
            "rdap_source":   rdap_source,
            "raw":           raw_text,
        }

    except whois.parser.PywhoisError as exc:
        return {"error": f"WHOIS error: {exc}"}
    except Exception as exc:
        return {"error": f"Unexpected error: {exc}"}
