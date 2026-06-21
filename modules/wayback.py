"""
Wayback Machine CDX API module for domain-probe.

Queries the Wayback Machine's CDX API to retrieve historical snapshots
for a domain, including metadata about the archive coverage.
"""

import re

import requests

# Default request timeout in seconds.
_TIMEOUT = 15

# Base URL for the CDX API.
_CDX_BASE = "https://web.archive.org/cdx/search/cdx"

# Fields to request from the API.
_FIELDS = "timestamp,original,statuscode,mimetype,digest"


def _clean_domain(domain: str) -> str:
    """Strip protocol, path, and leading 'www.' from a domain string.

    Returns a bare, lowercased domain name suitable for constructing
    a CDX wildcard query (e.g. ``*.example.com/*``).
    """
    cleaned = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", domain)
    cleaned = re.sub(r"^www\.", "", cleaned)
    cleaned = cleaned.split("/")[0]
    cleaned = cleaned.split("?")[0]
    cleaned = cleaned.split("#")[0]
    cleaned = cleaned.strip().lower()
    return cleaned


def run_wayback(domain: str, limit: int = 20):
    """Retrieve archived snapshots for *domain* from the Wayback Machine.

    Parameters
    ----------
    domain : str
        The domain name to look up (may include protocol, ``www.``, or
        trailing path — all are stripped before querying).
    limit : int
        Maximum number of snapshots to return (default 20).

    Returns
    -------
    dict
        Keys:

        * **snapshots** – ``list[dict]`` of snapshot objects, each with
          ``timestamp`` (str), ``url`` (str), ``status`` (int),
          ``mimetype`` (str).  Sorted by timestamp ascending.
        * **first_snapshot** – earliest ``timestamp`` (str) or ``None``.
        * **last_snapshot** – latest ``timestamp`` (str) or ``None``.
        * **total_archived** – estimated total number of distinct URL
          snapshots the Wayback Machine holds for this domain (int).
        * **years_active** – ``list[int]`` of unique calendar years for
          which at least one snapshot exists, sorted ascending.
        * **error** – (only present on failure) a human-readable error
          message (str).  When this key is present, **snapshots** is an
          empty list.

        On any error the function returns ``{"error": "<message>",
        "snapshots": []}`` so callers can always iterate **snapshots**
        without checking for the **error** key first.
    """
    domain = _clean_domain(domain)
    if not domain:
        return {"error": "empty domain after cleaning", "snapshots": []}

    # ------------------------------------------------------------------
    # 1. Primary request – archived snapshots (with limit)
    # ------------------------------------------------------------------
    params: dict = {
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": _FIELDS,
        "limit": str(limit),
        "filter": "statuscode:200",
        "collapse": "urlkey",
    }

    try:
        resp = requests.get(_CDX_BASE, params=params, timeout=_TIMEOUT)
        resp.raise_for_status()
    except requests.exceptions.Timeout:
        return {"error": "Wayback CDX request timed out", "snapshots": []}
    except requests.exceptions.ConnectionError:
        return {"error": "Wayback CDX connection failed", "snapshots": []}
    except requests.exceptions.HTTPError as exc:
        return {"error": f"Wayback CDX HTTP error: {exc}", "snapshots": []}
    except requests.exceptions.RequestException as exc:
        return {"error": f"Wayback CDX request failed: {exc}", "snapshots": []}

    # Parse JSON – first row is the column headers, following rows are data.
    try:
        rows = resp.json()
    except ValueError:
        return {"error": "Wayback CDX returned non-JSON response", "snapshots": []}

    if not isinstance(rows, list) or len(rows) < 2:
        return {
            "snapshots": [],
            "first_snapshot": None,
            "last_snapshot": None,
            "total_archived": 0,
            "years_active": [],
        }

    # First row: column headers e.g. ["timestamp","original","statuscode",...]
    headers = [h.lower() for h in rows[0]]
    data_rows = rows[1:]

    snapshots: list[dict] = []
    timestamps: list[str] = []

    for idx, row in enumerate(data_rows):
        if not isinstance(row, list):
            continue
        entry: dict = {}
        for col_idx, key in enumerate(headers):
            if col_idx < len(row):
                entry[key] = row[col_idx]
            else:
                entry[key] = None

        # Coerce statuscode to int when possible.
        try:
            entry["statuscode"] = int(entry.get("statuscode", 0))
        except (ValueError, TypeError):
            entry["statuscode"] = 0

        snapshot = {
            "timestamp": entry.get("timestamp", ""),
            "url": entry.get("original", ""),
            "status": entry.get("statuscode", 0),
            "mimetype": entry.get("mimetype", ""),
        }

        snapshots.append(snapshot)
        timestamps.append(snapshot["timestamp"])

    # Sort by timestamp (14-char YYYYMMDDhhmmss strings sort
    # lexicographically in chronological order).
    snapshots.sort(key=lambda s: s["timestamp"])

    # Derive first / last snapshot timestamps from the (now-sorted) list.
    sorted_timestamps = sorted(t for t in timestamps if t)

    first_snapshot = sorted_timestamps[0] if sorted_timestamps else None
    last_snapshot = sorted_timestamps[-1] if sorted_timestamps else None

    # Extract unique years from the 4-digit prefix of each timestamp.
    years: set[int] = set()
    for ts in sorted_timestamps:
        try:
            years.add(int(ts[:4]))
        except (ValueError, IndexError):
            pass
    years_active = sorted(years)

    # ------------------------------------------------------------------
    # 2. Secondary request – estimate total archived snapshots
    # ------------------------------------------------------------------
    total_archived = len(snapshots)

    try:
        count_params: dict = {
            "url": f"*.{domain}/*",
            "output": "json",
            "fl": _FIELDS,
            "filter": "statuscode:200",
            "collapse": "urlkey",
            "showNumPages": "true",
        }
        count_resp = requests.get(
            _CDX_BASE, params=count_params, timeout=_TIMEOUT
        )
        count_resp.raise_for_status()
        count_rows = count_resp.json()

        if isinstance(count_rows, list) and len(count_rows) >= 2:
            # With showNumPages=true the API returns an extra row or
            # the last row may contain page metadata.  Heuristic:
            # count the number of data rows we received and multiply
            # by the ratio implied by the limit we originally requested
            # vs. what we actually got.
            count_data = count_rows[1:] if len(count_rows) > 1 else []
            # If we hit the limit in the primary request, the archive
            # likely has more.  Use the secondary request's row count
            # (which is unbounded) as the estimate.
            if isinstance(count_data, list) and count_data:
                total_archived = max(total_archived, len(count_data))
    except Exception:
        # Non-critical – keep the primary estimate.
        pass

    return {
        "snapshots": snapshots,
        "first_snapshot": first_snapshot,
        "last_snapshot": last_snapshot,
        "total_archived": total_archived,
        "years_active": years_active,
    }
