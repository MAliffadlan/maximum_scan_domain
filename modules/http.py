"""
HTTP headers, security headers, and tech stack detection module.

Exports:
    run_http(domain: str) -> dict
"""

import re
import requests
from urllib.parse import urljoin

from modules.session import request as http_request
from modules.tech_detect import detect_tech as detect_tech_signatures
from modules.wappalyzer import run_webanalyze


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
]

TIMEOUT = 10
USER_AGENT = "DomainProbe/1.0"

# Cookie names that indicate specific technologies.
# Keys are cookie-name needles (lowercased); values are lists of tech labels.
COOKIE_TECH_MAP = {
    "phpsessid":   ["PHP"],
    "jsessionid":  ["Java / Tomcat"],
    "laravel_session": ["Laravel"],
    "asp.net_sessionid": ["ASP.NET"],
    "aspsessionid": ["ASP"],
    "cfduid":      ["Cloudflare"],
    "__cf_bm":     ["Cloudflare Bot Management"],
    "wp-settings": ["WordPress"],
    "wordpress_logged_in": ["WordPress"],
    "woocommerce": ["WooCommerce"],
    "shopify":     ["Shopify"],
    "_ga":         ["Google Analytics"],
    "_gid":        ["Google Analytics"],
    "_gat":        ["Google Analytics"],
    "AMP_TOKEN":   ["Google AMP"],
    "_ym_uid":     ["Yandex Metrica"],
    "_ym_d":       ["Yandex Metrica"],
    "drupal":      ["Drupal"],
    "sess":        ["Drupal (generic sess)"],
    "ci_session":  ["CodeIgniter"],
    "csrftoken":   ["Django (generic csrf)"],
    "django_language": ["Django"],
    "craftsessionid": ["Craft CMS"],
    "modx":        ["MODX"],
    "october_session": ["October CMS"],
    "pscart":      ["PrestaShop"],
    "prestashop":  ["PrestaShop"],
    "yii":         ["Yii Framework"],
    "symfony":     ["Symfony"],
    "remember_me": ["Symfony / generic"],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalise_domain(domain: str) -> str:
    """Strip scheme, trailing slash, and whitespace from a domain."""
    domain = domain.strip().strip("/")
    domain = re.sub(r"^https?://", "", domain, count=1)
    return domain


def _parse_cookies(response, target_domain: str = ""):
    """Extract cookie metadata and produce a summary.

    Returns a tuple of ``(cookies_info, cookie_summary)``.

    Besides the usual attributes (name, secure, httpOnly, sameSite), each
    cookie dict also gets:

    * ``session`` – True when neither Expires nor Max-Age is present.
    * ``third_party`` – True when a Domain attribute resolves to a different
      registered domain than *target_domain*.
    * ``domain`` – the raw Domain attribute value from Set-Cookie (if any).
    """
    cookies_info: list[dict] = []
    seen: set[str] = set()

    # --- Strategy 1: walk the cookie jar ----------------------------------
    for cookie in response.cookies:
        name = cookie.name
        if not name or name in seen:
            continue
        seen.add(name)

        info = {
            "name":       name,
            "secure":     bool(getattr(cookie, "secure", False)),
            "httpOnly":   False,
            "sameSite":   None,
            "domain":     None,
            "session":    True,   # proven false when Expires/Max-Age found
            "third_party": False,
        }

        # http.cookiejar stashes non-standard attrs in _rest
        rest = getattr(cookie, "_rest", {}) or {}
        for key, val in rest.items():
            kl = key.lower()
            if kl == "httponly":
                info["httpOnly"] = True
            elif kl == "samesite":
                info["sameSite"] = str(val).strip() if val is not None else None
            elif kl == "domain":
                val_str = str(val).strip() if val is not None else ""
                info["domain"] = val_str.lstrip(".").lower() if val_str else None
            elif kl in ("expires", "max-age"):
                info["session"] = False

        cookies_info.append(info)

    # --- Strategy 2: parse raw Set-Cookie headers for missed attributes ---
    try:
        raw = response.raw
        if hasattr(raw, "_original_response"):
            set_cookie_headers = (
                raw._original_response.headers.get_all("Set-Cookie") or []
            )
        else:
            val = response.headers.get("Set-Cookie", "")
            set_cookie_headers = [val] if val else []
    except Exception:
        set_cookie_headers = []

    for header in set_cookie_headers:
        if not header:
            continue
        # Extract cookie name
        m = re.match(r"^\s*([^=;]+)\s*=", header)
        if not m:
            continue
        name = m.group(1).strip()
        # If we already captured this cookie from the jar, enrich it
        existing = next((c for c in cookies_info if c["name"] == name), None)
        if existing is None:
            info = {
                "name":       name,
                "secure":     False,
                "httpOnly":   False,
                "sameSite":   None,
                "domain":     None,
                "session":    True,
                "third_party": False,
            }
            cookies_info.append(info)
            existing = info

        # Look for flags in the header text
        header_lower = header.lower()
        if "secure" in header_lower:
            existing["secure"] = True
        if "httponly" in header_lower:
            existing["httpOnly"] = True

        sm = re.search(r"samesite\s*=\s*(\S+)", header, re.IGNORECASE)
        if sm:
            existing["sameSite"] = sm.group(1).rstrip(";").strip().lower()

        # Domain attribute
        dm = re.search(r"domain\s*=\s*(\S+)", header, re.IGNORECASE)
        if dm:
            cookie_domain = dm.group(1).rstrip(";").strip().lower().lstrip(".")
            existing["domain"] = cookie_domain

        # Session cookie detection: presence of Expires or Max-Age
        if re.search(r"(?:expires|max-age)\s*=", header, re.IGNORECASE):
            existing["session"] = False

    # --- Third-party detection -------------------------------------------
    if target_domain:
        td = target_domain.lower().lstrip(".")
        for c in cookies_info:
            cd = (c.get("domain") or "").lstrip(".")
            if cd and cd != td and not td.endswith("." + cd):
                c["third_party"] = True

    # --- Build summary ---------------------------------------------------
    same_site_vals = [c.get("sameSite") for c in cookies_info]
    cookie_summary = {
        "total":              len(cookies_info),
        "secure_count":       sum(1 for c in cookies_info if c.get("secure")),
        "httponly_count":     sum(1 for c in cookies_info if c.get("httpOnly")),
        "samesite_strict":    same_site_vals.count("strict"),
        "samesite_lax":       same_site_vals.count("lax"),
        "samesite_none":      same_site_vals.count("none"),
        "session_cookies":    sum(1 for c in cookies_info if c.get("session")),
        "third_party_cookies": sum(1 for c in cookies_info if c.get("third_party")),
    }

    return cookies_info, cookie_summary


def _detect_tech(headers: dict, cookies: list[dict], url: str) -> list[str]:
    """Return a deduplicated list of technology / platform labels detected
    from headers and cookies."""
    tech: set[str] = set()

    # -- Server header ----------------------------------------------------
    server = headers.get("server", "")
    if server:
        server_lower = server.lower()
        if "apache" in server_lower and "tomcat" in server_lower:
            tech.add("Apache Tomcat")
        elif "apache" in server_lower:
            tech.add("Apache HTTP Server")
        elif "nginx" in server_lower:
            tech.add("Nginx")
        elif "cloudflare" in server_lower:
            tech.add("Cloudflare")
        elif "iis" in server_lower or "microsoft-iis" in server_lower:
            tech.add("Microsoft IIS")
        elif "liteSpeed" in server_lower or "litespeed" in server_lower:
            tech.add("LiteSpeed")
        elif "caddy" in server_lower:
            tech.add("Caddy")
        elif "envoy" in server_lower:
            tech.add("Envoy")
        elif "gws" in server_lower:
            tech.add("Google Web Server")
        elif "awselb" in server_lower:
            tech.add("AWS ELB")
        elif "amazon" in server_lower:
            tech.add("Amazon Web Server")
        elif "openresty" in server_lower:
            tech.add("OpenResty")
        elif "tengine" in server_lower:
            tech.add("Tengine")
        elif "varnish" in server_lower:
            tech.add("Varnish")
        else:
            # Report the raw value so the caller knows *something* is set
            tech.add(f"Server: {server.strip()}")

    # -- X-Powered-By -----------------------------------------------------
    xpb = headers.get("x-powered-by", "")
    if xpb:
        xpb_lower = xpb.lower()
        if "php" in xpb_lower:
            tech.add("PHP")
        if "asp.net" in xpb_lower:
            tech.add("ASP.NET")
        if "express" in xpb_lower:
            tech.add("Express.js")
        if "next.js" in xpb_lower:
            tech.add("Next.js")
        if "nuxt" in xpb_lower:
            tech.add("Nuxt.js")
        # Always record the raw value
        tech.add(f"X-Powered-By: {xpb.strip()}")

    # -- X-Generator (CMS / SSG indicator) --------------------------------
    xgen = headers.get("x-generator", "")
    if xgen:
        xgen_lower = xgen.lower()
        if "wordpress" in xgen_lower:
            tech.add("WordPress")
        if "ghost" in xgen_lower:
            tech.add("Ghost CMS")
        if "drupal" in xgen_lower:
            tech.add("Drupal")
        if "joomla" in xgen_lower:
            tech.add("Joomla")
        if "jekyll" in xgen_lower:
            tech.add("Jekyll")
        if "hugo" in xgen_lower:
            tech.add("Hugo")
        if "gatsby" in xgen_lower:
            tech.add("Gatsby")
        tech.add(f"X-Generator: {xgen.strip()}")

    # -- CF-Ray → Cloudflare -----------------------------------------------
    if headers.get("cf-ray"):
        tech.add("Cloudflare")

    # -- Cookie-based detection --------------------------------------------
    for cookie in cookies:
        name_lower = cookie["name"].lower()
        for needle, labels in COOKIE_TECH_MAP.items():
            if needle in name_lower:
                tech.update(labels)

    return sorted(tech)


def _check_cors(headers: dict, origin: str) -> dict:
    """Check CORS configuration from response headers.

    Parameters
    ----------
    headers : dict
        Response headers with lowercase keys (from a request that sent
        *origin* as the ``Origin`` header).
    origin : str
        The ``Origin`` value that was sent in the request.  Used to detect
        reflected-origin configurations.

    Returns
    -------
    dict
        Keys: cors_enabled, allow_origin, allow_credentials, allow_methods,
        permissive_cors, reflected_origin, dangerous, summary.
    """
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")
    acam = headers.get("access-control-allow-methods", "")

    cors_enabled = bool(acao)
    permissive_cors = acao == "*"
    reflected_origin = bool(acao and acao != "*" and acao == origin)
    dangerous = permissive_cors and acac.lower() == "true"

    # Build human-readable summary
    parts: list[str] = []
    if not cors_enabled:
        parts.append("CORS not enabled")
    else:
        if permissive_cors:
            parts.append("Wildcard origin (*) — any site can read responses")
        elif reflected_origin:
            parts.append(
                f"Origin reflected ({origin}) — vulnerable to arbitrary origin reflection"
            )
        else:
            parts.append(f"Restricted to: {acao}")
        if acac.lower() == "true":
            parts.append("credentials allowed")
        if dangerous:
            parts.append("DANGEROUS: credentials with wildcard origin")

    return {
        "cors_enabled":      cors_enabled,
        "allow_origin":      acao or None,
        "allow_credentials": acac.lower() == "true",
        "allow_methods":     acam or None,
        "permissive_cors":   permissive_cors,
        "reflected_origin":  reflected_origin,
        "dangerous":         dangerous,
        "summary":           "; ".join(parts) if parts else "No CORS headers detected",
    }


def _scan_js_deps(html: str, url: str) -> list[dict]:
    """Scan HTML for JavaScript dependencies (external and inline).

    Parameters
    ----------
    html : str
        Raw HTML body content.
    url : str
        Base URL used to resolve relative ``src`` paths.

    Returns
    -------
    list[dict]
        Each dict has keys: library, version, url, type (``"external"`` or
        ``"inline"``).  *library* and *version* are ``None`` when the
        script could not be identified.
    """
    deps: list[dict] = []
    seen_urls: set[str] = set()

    # Library detection patterns: (filename_regex, library_name)
    # Order matters — more-specific patterns before broader ones (e.g.
    # Preact before React so "preact" isn't mis-identified as React).
    LIB_PATTERNS: list[tuple[str, str]] = [
        (r"jquery[.\-]?(\d+(?:\.\d+)*)",            "jQuery"),
        (r"preact[.\-]?(\d+(?:\.\d+)*)",             "Preact"),
        (r"(?<![a-z])react[.\-]?(\d+(?:\.\d+)*)",    "React"),
        (r"vue[.\-]?(\d+(?:\.\d+)*)",                "Vue.js"),
        (r"angular[.\-]?(\d+(?:\.\d+)*)",            "Angular"),
        (r"bootstrap[.\-]?(\d+(?:\.\d+)*)",          "Bootstrap"),
        (r"lodash[.\-]?(\d+(?:\.\d+)*)",             "Lodash"),
        (r"moment[.\-]?(\d+(?:\.\d+)*)",             "Moment.js"),
        (r"(?<![a-z])d3[.\-]?(\d+(?:\.\d+)*)",       "D3.js"),
        (r"three[.\-]?(\d+(?:\.\d+)*)",              "Three.js"),
        (r"chart(?:\.js|js)?[.\-]?(\d+(?:\.\d+)*)",   "Chart.js"),
        (r"alpine[.\-]?(\d+(?:\.\d+)*)",             "Alpine.js"),
        (r"htmx[.\-]?(\d+(?:\.\d+)*)",               "HTMX"),
        (r"svelte[.\-]?(\d+(?:\.\d+)*)",             "Svelte"),
        (r"(?<![a-z])next[.\-]?(\d+(?:\.\d+)*)",     "Next.js"),
        (r"nuxt[.\-]?(\d+(?:\.\d+)*)",               "Nuxt.js"),
        (r"gatsby[.\-]?(\d+(?:\.\d+)*)",             "Gatsby"),
    ]

    # --- External scripts ---------------------------------------------------
    for m in re.finditer(
        r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>',
        html,
        re.IGNORECASE,
    ):
        src = m.group(1)
        full_url = urljoin(url, src)
        if full_url in seen_urls:
            continue
        seen_urls.add(full_url)

        # Derive filename for detection (strip query-string / fragment)
        filename = src.rsplit("/", 1)[-1] if "/" in src else src
        filename_clean = filename.split("?")[0].split("#")[0]
        filename_lower = filename_clean.lower()

        dep: dict = {"library": None, "version": None, "url": full_url, "type": "external"}

        for pattern, lib_name in LIB_PATTERNS:
            m2 = re.search(pattern, filename_lower, re.IGNORECASE)
            if m2:
                dep["library"] = lib_name
                version = m2.group(1)
                if version:
                    dep["version"] = version.lstrip(".-")
                break

        deps.append(dep)

    # --- Inline scripts with sourceMappingURL --------------------------------
    for m in re.finditer(
        r"<script[^>]*>(.*?)</script>",
        html,
        re.IGNORECASE | re.DOTALL,
    ):
        body = m.group(1)
        sm_match = re.search(
            r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)", body
        )
        if sm_match:
            map_url = sm_match.group(1).strip()
            full_map_url = urljoin(url, map_url)
            deps.append(
                {"library": None, "version": None, "url": full_map_url, "type": "inline"}
            )

    return deps


def _build_redirect_chain(response) -> list[dict]:
    """Walk ``response.history`` and append the final response to produce a
    complete redirect chain."""
    chain: list[dict] = []
    for r in response.history:
        chain.append({"url": r.url, "status_code": r.status_code})
    # Append the final hop
    chain.append({"url": response.url, "status_code": response.status_code})
    return chain


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_http(domain: str) -> dict:
    """Probe *domain* over HTTP(S) and return a structured report.

    Parameters
    ----------
    domain : str
        Domain name with or without scheme (e.g. ``example.com`` or
        ``https://example.com``).

    Returns
    -------
    dict
        Keys: url, status_code, final_url, redirect_chain, server,
        headers, security_headers, cookies, tech_stack, missing_headers.
        On failure the dict contains a single ``error`` key with a message.
    """
    domain = _normalise_domain(domain)

    # Try HTTPS first, then plain HTTP
    schemes = ["https", "http"]
    response = None
    last_error = None

    for scheme in schemes:
        url = f"{scheme}://{domain}"
        try:
            response = http_request(
                url,
                timeout=TIMEOUT,
                allow_redirects=True,
                headers={"User-Agent": USER_AGENT},
            )
            # If we get a response (even a 4xx/5xx) it counts as success —
            # we want to fingerprint whatever is reachable.
            break
        except requests.exceptions.SSLError as exc:
            last_error = f"SSL error on {url}: {exc}"
            continue
        except requests.exceptions.ConnectionError as exc:
            last_error = f"Connection error on {url}: {exc}"
            continue
        except requests.exceptions.Timeout as exc:
            last_error = f"Timeout on {url}: {exc}"
            continue
        except requests.exceptions.RequestException as exc:
            last_error = f"Request error on {url}: {exc}"
            continue

    if response is None:
        return {"error": last_error or f"Could not connect to {domain}"}

    # --- Headers -----------------------------------------------------------
    # Convert to a plain dict (lowercase keys) for consistent access.
    headers: dict[str, str] = {k.lower(): v for k, v in response.headers.items()}

    # --- Security headers --------------------------------------------------
    security: dict[str, str | None] = {}
    missing: list[str] = []
    for h in SECURITY_HEADERS:
        val = headers.get(h)
        security[h] = val
        if val is None:
            missing.append(h)

    # --- Cookies -----------------------------------------------------------
    cookies, cookie_summary = _parse_cookies(response, domain)

    # --- Tech stack --------------------------------------------------------
    tech_stack = _detect_tech(headers, cookies, response.url)
    # Enhanced signature-based detection
    tech_stack_detailed = detect_tech_signatures(
        url=response.url,
        headers=headers,
        cookies=cookies,
        body=response.text,
    )
    # Wappalyzer integration (3965+ apps via webanalyze binary)
    wappalyzer_results = run_webanalyze(response.url)

    # --- Redirect chain ----------------------------------------------------
    redirect_chain = _build_redirect_chain(response)

    # --- Server header (raw) -----------------------------------------------
    server = headers.get("server")

    # --- CORS check --------------------------------------------------------
    # Make a second lightweight request with a fake Origin so _check_cors
    # can detect whether the server blindly echoes any origin.
    fake_origin = "https://attacker.invalid"
    cors_headers: dict[str, str] = {}
    try:
        cors_resp = http_request(
            response.url,
            timeout=TIMEOUT,
            allow_redirects=False,
            headers={"User-Agent": USER_AGENT, "Origin": fake_origin},
        )
        cors_headers = {k.lower(): v for k, v in cors_resp.headers.items()}
    except Exception:
        pass

    cors = _check_cors(cors_headers, fake_origin)

    # --- JS dependencies ---------------------------------------------------
    js_dependencies = _scan_js_deps(response.text, response.url)

    # --- Assemble result ---------------------------------------------------
    return {
        "url":              response.url,
        "status_code":      response.status_code,
        "final_url":        response.url,
        "redirect_chain":   redirect_chain,
        "server":           server,
        "headers":          headers,
        "security_headers": security,
        "cookies":          cookies,
        "cookie_summary":   cookie_summary,
        "tech_stack":       tech_stack,
        "tech_stack_detailed": tech_stack_detailed,
        "wappalyzer":       wappalyzer_results,
        "missing_headers":  missing,
        "cors":             cors,
        "js_dependencies":  js_dependencies,
    }
