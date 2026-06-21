"""
Proxy & session management for anti-block.

Supports:
  - Single HTTP/HTTPS/SOCKS proxy
  - Proxy list rotation (one per request, round-robin)
  - Random User-Agent per request
  - Automatic proxy validation
"""

from __future__ import annotations

import random
import time
from typing import Any

import requests

from modules.user_agents import get_random_ua


# Global state
_proxy_list: list[str] = []
_proxy_index = 0
_delay_ms = 0
_dns_req_count = 0
_random_agent = False
_last_request_time = 0.0


def configure(
    proxy: str | None = None,
    proxy_file: str | None = None,
    delay: int = 0,
    random_agent: bool = False,
):
    """Configure proxy rotation and rate limiting.

    Parameters
    ----------
    proxy : str, optional
        Single proxy URL (e.g. ``http://127.0.0.1:8080``).
    proxy_file : str, optional
        Path to file with proxies (one per line).
    delay : int
        Delay in milliseconds between HTTP requests.
    random_agent : bool
        Whether to randomize User-Agent per request.
    """
    global _proxy_list, _proxy_index, _delay_ms, _random_agent

    _proxy_list = []
    _proxy_index = 0
    _delay_ms = delay
    _random_agent = random_agent

    if proxy:
        proxy = proxy.strip()
        if proxy and not proxy.startswith(("http://", "https://", "socks4://", "socks5://")):
            proxy = f"http://{proxy}"
        _proxy_list = [proxy]

    if proxy_file:
        try:
            with open(proxy_file) as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            if lines:
                _proxy_list = lines
        except (FileNotFoundError, PermissionError):
            print(f"  ⚠ Warning: proxy file not found: {proxy_file}")


def get_proxies() -> dict[str, str] | None:
    """Get the next proxy dict (round-robin). Returns None if no proxy configured."""
    global _proxy_index
    if not _proxy_list:
        return None

    proxy_url = _proxy_list[_proxy_index % len(_proxy_list)]
    _proxy_index += 1

    # Support different proxy types
    if proxy_url.startswith("socks4://") or proxy_url.startswith("socks5://"):
        return {"http": proxy_url, "https": proxy_url}
    else:
        return {"http": proxy_url, "https": proxy_url}


def enforce_rate_limit():
    """Sleep if needed to enforce configured delay between HTTP requests."""
    global _last_request_time
    if _delay_ms <= 0:
        return

    elapsed = (time.time() - _last_request_time) * 1000
    if elapsed < _delay_ms:
        sleep_time = (_delay_ms - elapsed) / 1000.0
        time.sleep(sleep_time)
    _last_request_time = time.time()


def enforce_dns_rate_limit(batch_size: int = 20):
    """Batch-based delay for DNS lookups.

    Instead of delaying per-request (which kills speed),
    we only sleep after every *batch_size* DNS queries.

    Parameters
    ----------
    batch_size : int
        Number of queries per batch before sleeping (default 20).
    """
    global _dns_req_count
    _dns_req_count += 1

    if _dns_req_count >= batch_size:
        _dns_req_count = 0
        time.sleep(0.3)  # Brief pause every batch to avoid NS rate limit


def build_headers(custom: dict[str, str] | None = None) -> dict[str, str]:
    """Build request headers with optional random UA."""
    headers = {}
    if _random_agent:
        headers["User-Agent"] = get_random_ua()
    else:
        headers["User-Agent"] = "DomainProbe/2.0"

    if custom:
        headers.update(custom)
    return headers


def request(
    url: str,
    method: str = "GET",
    timeout: int = 10,
    allow_redirects: bool = True,
    stream: bool = False,
    headers: dict[str, str] | None = None,
    **kwargs: Any,
) -> requests.Response:
    """Make an HTTP request with proxy rotation and rate limiting.

    Automatically handles:
      - Proxy rotation (if configured)
      - Rate limiting delay (if configured)
      - Random User-Agent (if enabled)

    Returns a ``requests.Response`` object.
    Raises the same exceptions as ``requests``.
    """
    enforce_rate_limit()

    req_headers = build_headers(headers)
    proxies = get_proxies()

    session = requests.Session()
    session.verify = False  # Disable SSL verification (common in recon)

    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if method.upper() == "GET":
        return session.get(
            url, timeout=timeout, allow_redirects=allow_redirects,
            headers=req_headers, proxies=proxies, stream=stream, **kwargs
        )
    elif method.upper() == "POST":
        return session.post(
            url, timeout=timeout, allow_redirects=allow_redirects,
            headers=req_headers, proxies=proxies, **kwargs
        )
    else:
        return session.request(
            method, url, timeout=timeout, allow_redirects=allow_redirects,
            headers=req_headers, proxies=proxies, **kwargs
        )
