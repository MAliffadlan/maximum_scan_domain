"""
TCP port scanner module.

Exports:
    run_ports(ip, top_n=50)   – fast scan via socket.connect_ex() with thread pool
    run_ports_deep(ip)        – deep scan via nmap subprocess, fallback to fast scan
    TOP_50_PORTS              – the canonical top-50 TCP port list
    SERVICE_MAP               – port -> service name lookup
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# Canonical top-50 port list (50 entries as specified; scan deduplicates at
# runtime to avoid wasted connections)
# ---------------------------------------------------------------------------
_TOP_50_RAW: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 465, 587, 993, 995, 1433, 1521, 1723,
    3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9000,
    9090, 9200, 9300, 11211, 27017, 27018, 27019, 28017, 5000, 5001,
    50000, 50030, 50060, 50070, 50075, 50090, 6379, 6380, 11211, 2222,
]

# Deduplicated view — preserved for external consumers who expect 50 entries.
# Use _TOP_50_UNIQUE inside the scanner to avoid re-scanning the same port.
_TOP_50_UNIQUE: list[int] = list(dict.fromkeys(_TOP_50_RAW))

TOP_50_PORTS: list[int] = _TOP_50_RAW

# ---------------------------------------------------------------------------
# Port -> common service name
# ---------------------------------------------------------------------------
SERVICE_MAP: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    1723: "pptp",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    6380: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
    9000: "http-alt",
    9090: "websphere",
    9200: "elasticsearch",
    9300: "elasticsearch",
    11211: "memcached",
    2222: "ssh",
    27017: "mongodb",
    27018: "mongodb",
    27019: "mongodb",
    28017: "mongodb",
    5000: "upnp",
    5001: "upnp",
    50000: "db2",
    50030: "hadoop",
    50060: "hadoop",
    50070: "hadoop",
    50075: "hadoop",
    50090: "hadoop",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _check_port(ip: str, port: int, timeout: float = 1.0) -> dict:
    """Try a single TCP connect to *ip*:*port*.  Returns a result dict."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return {
            "port": port,
            "open": result == 0,
            "service": SERVICE_MAP.get(port, "unknown"),
            "errno": result,
        }
    except socket.gaierror:
        return {"port": port, "open": False, "service": SERVICE_MAP.get(port, "unknown"), "error": "gaierror"}
    except socket.timeout:
        return {"port": port, "open": False, "service": SERVICE_MAP.get(port, "unknown"), "error": "timeout"}
    except Exception as exc:
        return {"port": port, "open": False, "service": SERVICE_MAP.get(port, "unknown"), "error": str(exc)}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_ports(ip: str, top_n: int = 50) -> dict:
    """
    Fast TCP port scan using socket.connect_ex() with a 1 s timeout.

    Parameters
    ----------
    ip : str
        Target IPv4 address.
    top_n : int
        How many ports from TOP_50_PORTS to scan (default 50, clamped to the
        length of TOP_50_PORTS).

    Returns
    -------
    dict
        {"open_ports": [...], "total_scanned": int, "scan_time": float}
    """
    # Use deduplicated list so we never scan the same port twice
    ports = _TOP_50_UNIQUE[: min(top_n, len(_TOP_50_UNIQUE))]
    open_ports: list[dict] = []
    start = time.time()

    try:
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(_check_port, ip, port): port for port in ports}
            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception:
                    continue
                if result.get("open"):
                    open_ports.append(
                        {"port": result["port"], "service": result["service"]}
                    )
    except Exception:
        pass  # worst case: return whatever we collected (empty)

    elapsed = time.time() - start
    return {
        "open_ports": open_ports,
        "total_scanned": len(ports),
        "scan_time": round(elapsed, 3),
    }


def run_ports_deep(ip: str) -> dict:
    """
    Deep TCP port scan using the system *nmap* binary.

    Executes: ``nmap -sV -F --host-timeout 30s <ip>`` and parses the XML
    output.  If *nmap* is not found on PATH the function falls back to
    :func:`run_ports`.

    Returns
    -------
    dict
        {"open_ports": [...], "total_scanned": int, "scan_time": float}
    """
    if not shutil.which("nmap"):
        return run_ports(ip, top_n=50)

    start = time.time()
    open_ports: list[dict] = []
    total_scanned = 0

    cmd = ["nmap", "-sV", "-F", "--host-timeout", "30s", "-oX", "-", ip]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=45,  # 30 s host timeout + 15 s overhead
        )
    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        return {
            "open_ports": [],
            "total_scanned": 0,
            "scan_time": round(elapsed, 3),
            "error": "nmap timed out",
        }
    except FileNotFoundError:
        return run_ports(ip, top_n=50)
    except Exception as exc:
        elapsed = time.time() - start
        return {
            "open_ports": [],
            "total_scanned": 0,
            "scan_time": round(elapsed, 3),
            "error": str(exc),
        }

    # Parse nmap XML output (lightweight – no external dep)
    try:
        import xml.etree.ElementTree as ET

        root = ET.fromstring(proc.stdout)
        for host in root.iter("host"):
            for port_elem in host.iter("port"):
                port_id = int(port_elem.get("portid", 0))
                state_elem = port_elem.find("state")
                state = state_elem.get("state", "closed") if state_elem is not None else "closed"
                if state != "open":
                    continue
                total_scanned += 1
                svc_elem = port_elem.find("service")
                service = "unknown"
                product = ""
                version = ""
                if svc_elem is not None:
                    service = svc_elem.get("name", "unknown")
                    product = svc_elem.get("product", "")
                    version = svc_elem.get("version", "")
                entry = {
                    "port": port_id,
                    "service": service,
                    "product": product,
                    "version": version,
                }
                open_ports.append(entry)
            # Count ports in <ports> blocks regardless of state for total_scanned
            ports_elem = host.find("ports")
            if ports_elem is not None:
                # Override with the total from the XML if we parsed that way
                total_scanned_from_xml = len(ports_elem.findall("port"))
                total_scanned = total_scanned_from_xml
    except Exception:
        # XML parse failed – return empty result with error
        elapsed = time.time() - start
        return {
            "open_ports": [],
            "total_scanned": 0,
            "scan_time": round(elapsed, 3),
            "error": "failed to parse nmap output",
        }

    elapsed = time.time() - start
    return {
        "open_ports": open_ports,
        "total_scanned": total_scanned,
        "scan_time": round(elapsed, 3),
    }
