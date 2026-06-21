"""
IP geolocation module using the ip-api.com free API (non-commercial).

Exports:
    run_geoip(ip) -> dict
"""

import ipaddress
import requests

# ---------------------------------------------------------------------------
# Module-level cache
# ---------------------------------------------------------------------------
_geo_cache: dict[str, dict] = {}

# ---------------------------------------------------------------------------
# Timeout for HTTP requests (seconds)
# ---------------------------------------------------------------------------
_API_TIMEOUT = 5

# ---------------------------------------------------------------------------
# Private / reserved address detection
# ---------------------------------------------------------------------------

def _is_private_or_loopback(ip: str) -> bool:
    """Return True if *ip* is a loopback, private, link-local, or
    otherwise non-public address that ip-api.com cannot geolocate."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        # Not a parseable IP address — let the API decide.
        return False

    if addr.is_loopback or addr.is_private:
        return True

    # ipaddress.is_private catches IPv4 private ranges but misses some
    # IPv6 cases; be explicit about unique-local and link-local.
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.is_link_local or addr.is_unique_local:
            return True

    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_geoip(ip: str) -> dict:
    """Geolocate *ip* via ip-api.com.

    Parameters
    ----------
    ip : str
        An IPv4 or IPv6 address string.

    Returns
    -------
    dict
        On success::
            {"ip": …, "country": …, "country_code": …, "region": …,
             "city": …, "zip": …, "lat": …, "lon": …, "timezone": …,
             "isp": …, "org": …, "as": …}

        On private / loopback / non-routable IP::
            {"error": "private IP"}

        On API or network error::
            {"error": "<message>"}
    """
    # ---- cache hit --------------------------------------------------------
    if ip in _geo_cache:
        return _geo_cache[ip]

    # ---- private / loopback guard -----------------------------------------
    if _is_private_or_loopback(ip):
        result: dict = {"error": "private IP"}
        _geo_cache[ip] = result
        return result

    # ---- call ip-api.com --------------------------------------------------
    url = f"http://ip-api.com/json/{ip}"

    try:
        resp = requests.get(url, timeout=_API_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.Timeout:
        result = {"error": f"request to ip-api.com timed out after {_API_TIMEOUT}s"}
        _geo_cache[ip] = result
        return result
    except requests.exceptions.ConnectionError as exc:
        result = {"error": f"connection error: {exc}"}
        _geo_cache[ip] = result
        return result
    except requests.exceptions.RequestException as exc:
        result = {"error": f"request failed: {exc}"}
        _geo_cache[ip] = result
        return result
    except ValueError:
        result = {"error": "invalid JSON response from ip-api.com"}
        _geo_cache[ip] = result
        return result

    # ---- handle application-level failure --------------------------------
    if data.get("status") == "fail":
        msg = data.get("message", "unknown error")
        result = {"error": msg}
        _geo_cache[ip] = result
        return result

    # ---- build result dict ------------------------------------------------
    result = {
        "ip":           data.get("query", ip),
        "country":      data.get("country", ""),
        "country_code": data.get("countryCode", ""),
        "region":       data.get("regionName", ""),
        "city":         data.get("city", ""),
        "zip":          data.get("zip", ""),
        "lat":          data.get("lat", 0.0),
        "lon":          data.get("lon", 0.0),
        "timezone":     data.get("timezone", ""),
        "isp":          data.get("isp", ""),
        "org":          data.get("org", ""),
        "as":           data.get("as", ""),
    }

    _geo_cache[ip] = result
    return result
