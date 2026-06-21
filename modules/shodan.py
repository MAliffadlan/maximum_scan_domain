"""
External service intelligence module.

Queries free internet-wide scanning services for host information about
an IP address.  No API key is required for the primary data source
(Shodan InternetDB); optional keys can be provided via environment
variables for richer results.

Exports:
    run_external_intel(ip)  – query Shodan InternetDB + optional Censys/Shodan API

Environment variables (all optional):
    SHODAN_API_KEY      – Shodan API key (free tier accepted)
    CENSYS_API_ID       – Censys API ID (free tier accepted)
    CENSYS_API_SECRET   – Censys API secret (free tier accepted)
"""

from __future__ import annotations

import os

import requests


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_external_intel(ip: str) -> dict:
    """
    Gather external intelligence for *ip* from free scanning services.

    Data sources (tried in order):
    1. Shodan InternetDB  — free, no key required
    2. Shodan Host API    — requires SHODAN_API_KEY env var
    3. Censys Search API  — requires CENSYS_API_ID + CENSYS_API_SECRET

    Returns
    -------
    dict
        {
            "ports":      list[int],
            "hostnames":  list[str],
            "tags":       list[str],
            "vulns":      list[str],    # CVE identifiers
            "cpes":       list[str],    # CPE identifiers
            "services":   list[dict],   # {"port": int, "transport": str}
            "source":     str,          # "internetdb" or "shodan_api"
        }

    On all errors the dict includes ``"error": "<message>"`` and empty
    lists for ports, hostnames, tags, vulns, and cpes.
    """
    # ------------------------------------------------------------------
    # 1. Shodan InternetDB (free, no key required)
    # ------------------------------------------------------------------
    try:
        internetdb_resp = requests.get(
            f"https://internetdb.shodan.io/{ip}",
            timeout=10,
        )
        internetdb_resp.raise_for_status()
        internetdb_data = internetdb_resp.json()
    except requests.RequestException as exc:
        return _error_result(f"InternetDB request failed: {exc}")

    # InternetDB may return an error detail string instead of a dict
    if isinstance(internetdb_data, str) or "detail" in internetdb_data:
        detail = (
            internetdb_data
            if isinstance(internetdb_data, str)
            else internetdb_data.get("detail", "Unknown error")
        )
        return _error_result(f"InternetDB error: {detail}")

    # Extract fields from InternetDB response
    ports: list[int] = internetdb_data.get("ports", [])
    hostnames: list[str] = internetdb_data.get("hostnames", [])
    tags: list[str] = internetdb_data.get("tags", [])
    vulns: list[str] = internetdb_data.get("vulns", [])
    cpes: list[str] = internetdb_data.get("cpes", [])

    # Build services list from ports (InternetDB only reports TCP)
    services: list[dict] = [{"port": p, "transport": "tcp"} for p in ports]

    result: dict = {
        "ports": ports,
        "hostnames": hostnames,
        "tags": tags,
        "vulns": vulns,
        "cpes": cpes,
        "services": services,
        "source": "internetdb",
    }

    # ------------------------------------------------------------------
    # 2. Shodan Host API (free tier, requires SHODAN_API_KEY)
    # ------------------------------------------------------------------
    shodan_key = os.environ.get("SHODAN_API_KEY", "").strip()
    if shodan_key:
        try:
            shodan_resp = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": shodan_key},
                timeout=10,
            )
            # 401 / 403 = no access; fall back to InternetDB silently
            if shodan_resp.status_code in (401, 403):
                pass
            else:
                shodan_resp.raise_for_status()
                shodan_data = shodan_resp.json()

                # Merge Shodan Host API data (it is richer than InternetDB)
                shodan_ports: list[int] = shodan_data.get("ports", [])
                shodan_hostnames: list[str] = shodan_data.get("hostnames", [])
                shodan_tags: list[str] = shodan_data.get("tags", [])
                shodan_vulns: list[str] = shodan_data.get("vulns", [])

                # Build services with transport info from the Shodan data
                shodan_services: list[dict] = []
                for entry in shodan_data.get("data", []):
                    svc_port = entry.get("port")
                    svc_transport = entry.get("transport", "tcp")
                    if svc_port is not None:
                        shodan_services.append(
                            {"port": svc_port, "transport": svc_transport}
                        )

                # Prefer Shodan API data; fall back to InternetDB for any
                # field that Shodan did not provide
                result["ports"] = shodan_ports if shodan_ports else ports
                result["hostnames"] = (
                    shodan_hostnames if shodan_hostnames else hostnames
                )
                result["tags"] = shodan_tags if shodan_tags else tags
                result["vulns"] = shodan_vulns if shodan_vulns else vulns
                # Shodan Host API does not return CPEs; keep InternetDB values
                result["cpes"] = cpes
                result["services"] = (
                    shodan_services if shodan_services else services
                )
                result["source"] = "shodan_api"

        except requests.RequestException:
            # Shodan API failed — keep InternetDB result
            pass

    # ------------------------------------------------------------------
    # 3. Censys Search API (free tier, requires CENSYS_API_ID + SECRET)
    # ------------------------------------------------------------------
    censys_id = os.environ.get("CENSYS_API_ID", "").strip()
    censys_secret = os.environ.get("CENSYS_API_SECRET", "").strip()
    if censys_id and censys_secret:
        try:
            censys_resp = requests.get(
                "https://search.censys.io/api/v1/search/ip",
                params={"q": ip},
                auth=(censys_id, censys_secret),
                timeout=10,
            )
            # Non-200 means no access; ignore gracefully
            if censys_resp.status_code == 200:
                censys_data = censys_resp.json()
                # Merge any additional ports found by Censys
                for hit in censys_data.get("results", []):
                    for svc in hit.get("services", []):
                        c_port = svc.get("port")
                        c_transport = svc.get("transport_protocol", "tcp")
                        if c_port is not None:
                            existing = {
                                s["port"]: s
                                for s in result["services"]
                            }
                            if c_port not in existing:
                                result["services"].append(
                                    {"port": c_port, "transport": c_transport}
                                )
                                if c_port not in result["ports"]:
                                    result["ports"].append(c_port)
        except requests.RequestException:
            pass

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _error_result(message: str) -> dict:
    """Return a standardised error dict."""
    return {
        "error": message,
        "ports": [],
        "hostnames": [],
        "tags": [],
        "vulns": [],
        "cpes": [],
    }
