"""
Technology stack detection engine.

Detects CMSes, frameworks, CDNs, analytics, JS libraries, web servers,
and other technologies from HTTP response data using URL patterns, headers,
cookies, HTML meta tags, and body content signatures.

Exports:
    detect_tech(headers, cookies, url, body, html_body) -> list[dict]
"""

from __future__ import annotations

import re
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Signature database
# ---------------------------------------------------------------------------
# Each entry can have:
#   - cats: list[str]         – categories
#   - implies: list[str]      – other techs implied
#   - confidence: int         – base confidence 0-100 (default: 50)
#   - url: list[str]          – regex matched against the page URL
#   - headers: dict[str,str]  – header-name -> regex (lowered keys)
#   - cookies: dict[str,str]  – cookie-name (prefix match if empty value)
#   - meta: dict[str,str]     – meta-tag name -> regex
#   - html: list[str]         – regex matched against raw HTML
#   - body: list[str]         – regex matched against visible text
#   - script: list[str]       – regex matched against <script> content
#   - version: list[dict]     – [{from:"header|url|body|meta", pattern:str, group:int}]

TECH_SIGNATURES: dict[str, dict] = {
    # ─────────── CMS ───────────
    "WordPress": {
        "cats": ["CMS", "Blog"],
        "implies": ["PHP"],
        "url": ["/wp-content/", "/wp-json/", "/wp-admin/", "/xmlrpc\\.php$"],
        "headers": {"x-powered-by": "wordpress"},
        "cookies": {"wordpress_": "", "wp-settings": ""},
        "meta": {"generator": "[Ww]ord[Pp]ress\\s*([\\d.]+)?"},
        "html": ["<!--\\s*WordPress", "<!--\\s*wp:", "wp-embed"],
        "body": ["/wp-content/themes/", "/wp-content/plugins/", "/wp-includes/"],
        "version": [
            {"from": "meta", "pattern": "WordPress\\s*([\\d.]+)", "group": 1},
            {"from": "body", "pattern": "/wp-includes/js/wp-emoji-release\\.min\\.js\\?ver=([\\d.]+)", "group": 1},
            {"from": "body", "pattern": "\\?ver=([\\d.]+)\"\\s*/>\\s*</script>", "group": 1},
        ],
    },
    "Drupal": {
        "cats": ["CMS"],
        "implies": ["PHP"],
        "headers": {"x-drupal-cache": ".", "x-drupal-dynamic-cache": "."},
        "cookies": {"Drupal.visitor": "", "has_js": ""},
        "meta": {"generator": "Drupal\\s*([\\d.]+)?"},
        "url": ["/sites/default/", "/node/\\d+", "/user/\\d+"],
        "body": ["/sites/default/files/", "Drupal.settings"],
        "html": ["Drupal\\.Settings\\(\\.json\\)"],
        "version": [{"from": "meta", "pattern": "Drupal\\s*([\\d.]+)", "group": 1}],
    },
    "Joomla": {
        "cats": ["CMS"],
        "implies": ["PHP"],
        "meta": {"generator": "Joomla"},
        "headers": {"x-content-encoded-by": "Joomla"},
        "url": ["/components/", "/modules/", "/templates/"],
        "body": ["/media/jui/", "/media/system/", "com_content"],
        "version": [{"from": "meta", "pattern": "Joomla!?\\s*([\\d.]+)", "group": 1}],
    },
    "Magento": {
        "cats": ["CMS", "E-commerce"],
        "implies": ["PHP"],
        "headers": {"x-magento": ".", "x-magento-cache": "."},
        "cookies": {"frontend": "", "admin": ""},
        "url": ["/skin/", "/media/", "/static/version"],
        "body": ["Mage\\.Cookies", "require\\.config\\(", "Magento_"],
        "html": ["<!--\\s*Magento"],
        "version": [{"from": "body", "pattern": "Magento[,\\s]+([\\d.]+)", "group": 1}],
    },
    "Shopify": {
        "cats": ["E-commerce", "CMS"],
        "cookies": {"_shopify": "", "shopify": ""},
        "headers": {"x-shopid": ".", "x-shopify-stage": "."},
        "url": ["/cdn/shop/", ".myshopify\\.com"],
        "body": ["Shopify\\.Analytics", "Shopify\\.Currency", "shopify-"],
        "html": ["<!--\\s*Shopify"],
        "version": [],
    },
    "Ghost": {
        "cats": ["CMS", "Blog"],
        "implies": ["Node.js"],
        "meta": {"generator": "Ghost"},
        "headers": {"x-powered-by": "Ghost"},
        "body": ["content=\"Ghost"],
        "version": [{"from": "meta", "pattern": "Ghost\\s*([\\d.]+)", "group": 1}],
    },

    # ─────────── Frameworks ───────────
    "Laravel": {
        "cats": ["Framework"],
        "implies": ["PHP"],
        "cookies": {"laravel_session": "", "XSRF-TOKEN": ""},
        "headers": {"x-powered-by": "Laravel"},
        "body": ["<meta\\s+name=\"csrf-token\"", "Laravel\\s*([\\d.]+)?"],
        "html": ["laravel"],
        "version": [{"from": "body", "pattern": "Laravel\\s*([\\d.]+)", "group": 1}],
    },
    "Symfony": {
        "cats": ["Framework"],
        "implies": ["PHP"],
        "cookies": {"symfony": ""},
        "headers": {"x-symfony": "."},
        "body": ["Symfony\\s*([\\d.]+)?"],
        "version": [{"from": "body", "pattern": "Symfony\\s*([\\d.]+)", "group": 1}],
    },
    "Django": {
        "cats": ["Framework"],
        "implies": ["Python"],
        "cookies": {"csrftoken": "", "sessionid": ""},
        "headers": {"x-frame-options": "SAMEORIGIN"},
        "body": ["csrfmiddlewaretoken", "<input\\s+[^>]*name='csrfmiddlewaretoken'"],
        "version": [],
    },
    "Ruby on Rails": {
        "cats": ["Framework"],
        "implies": ["Ruby"],
        "headers": {"x-powered-by": "Phusion|Puma", "x-request-id": "."},
        "cookies": {"_session": "", "_rails": ""},
        "body": ["csrf-param", "csrf-token"],
        "version": [],
    },
    "ASP.NET": {
        "cats": ["Framework"],
        "headers": {"x-powered-by": "ASP\\.NET", "x-aspnet-version": "."},
        "cookies": {"ASP.NET_SessionId": "", "ASPSESSIONID": "", ".ASPXAUTH": ""},
        "body": ["__VIEWSTATE", "__EVENTVALIDATION", "X-AspNetMvc"],
        "version": [
            {"from": "headers", "pattern": "X-AspNet-Version:?\\s*([\\d.]+)", "group": 1},
            {"from": "headers", "pattern": "X-AspNetMvc-Version:?\\s*([\\d.]+)", "group": 1},
        ],
    },
    "Express.js": {
        "cats": ["Framework"],
        "implies": ["Node.js"],
        "headers": {"x-powered-by": "Express"},
        "version": [{"from": "headers", "pattern": "Express[\\s.]*([\\d.]+)", "group": 1}],
    },
    "Next.js": {
        "cats": ["Framework", "Static Site Generator"],
        "implies": ["Node.js", "React"],
        "headers": {"x-powered-by": "Next\\.js"},
        "body": ["__NEXT_DATA__", "/_next/static/"],
        "version": [{"from": "body", "pattern": "__NEXT_DATA__[^}]*\"version\":\"([\\d.]+)\"", "group": 1}],
    },
    "Nuxt.js": {
        "cats": ["Framework", "Static Site Generator"],
        "implies": ["Node.js", "Vue.js"],
        "body": ["__NUXT__", "/_nuxt/"],
        "version": [],
    },
    "Gatsby": {
        "cats": ["Static Site Generator"],
        "implies": ["Node.js", "React"],
        "headers": {"x-powered-by": "Gatsby"},
        "body": ["/static/", "gatsby-"],
        "version": [],
    },
    "Vue.js": {
        "cats": ["JavaScript Framework"],
        "body": ["vue\\.[a-z]+\\.js", "Vue\\.component", "createApp\\("],
        "html": ["v-bind", "v-model", "v-if", "v-for"],
        "version": [{"from": "body", "pattern": "vue@([\\d.]+)", "group": 1}],
    },
    "React": {
        "cats": ["JavaScript Framework"],
        "body": ["react\\.js", "react\\.min\\.js", "React\\.createElement", "__NEXT_DATA__"],
        "html": ["data-reactroot", "data-reactid"],
        "version": [{"from": "body", "pattern": "react@([\\d.]+)", "group": 1}],
    },
    "Angular": {
        "cats": ["JavaScript Framework"],
        "body": ["angular\\.js", "angular\\.min\\.js", "ng-app", "ng-version"],
        "html": ["ng-app", "ng-controller", "\\[ng-app"],
        "version": [{"from": "body", "pattern": "angular@([\\d.]+)", "group": 1}],
    },

    # ─────────── Programming languages ───────────
    "PHP": {
        "cats": ["Programming Language"],
        "headers": {"x-powered-by": "PHP", "x-php-version": "."},
        "cookies": {"PHPSESSID": ""},
        "url": [".php$"],
        "version": [{"from": "headers", "pattern": "PHP[/\\s]*([\\d.]+)", "group": 1}],
    },
    "Python": {
        "cats": ["Programming Language"],
        "headers": {"server": "Python", "x-powered-by": "Python"},
        "url": [".py$"],
        "version": [{"from": "headers", "pattern": "Python[/\\s]*([\\d.]+)", "group": 1}],
    },

    # ─────────── Web Servers ───────────
    "Apache HTTP Server": {
        "cats": ["Web Server"],
        "headers": {"server": "^Apache"},
        "version": [{"from": "headers", "pattern": "Apache[/\\s]*([\\d.]+)", "group": 1}],
    },
    "Nginx": {
        "cats": ["Web Server"],
        "headers": {"server": "^nginx"},
        "version": [{"from": "headers", "pattern": "nginx[/\\s]*([\\d.]+)", "group": 1}],
    },
    "Microsoft IIS": {
        "cats": ["Web Server"],
        "headers": {"server": "^Microsoft-IIS"},
        "version": [{"from": "headers", "pattern": "Microsoft-IIS[/\\s]*([\\d.]+)", "group": 1}],
    },
    "LiteSpeed": {
        "cats": ["Web Server"],
        "headers": {"server": "LiteSpeed"},
        "version": [{"from": "headers", "pattern": "LiteSpeed[/\\s]*([\\d.]+)", "group": 1}],
    },
    "Caddy": {
        "cats": ["Web Server"],
        "headers": {"server": "^Caddy"},
        "version": [{"from": "headers", "pattern": "Caddy[/\\s]*([\\d.]+)", "group": 1}],
    },
    "Apache Tomcat": {
        "cats": ["Web Server"],
        "implies": ["Java"],
        "headers": {"server": "Apache.*Tomcat|Tomcat"},
        "cookies": {"JSESSIONID": ""},
        "version": [{"from": "headers", "pattern": "Tomcat[/\\s]*([\\d.]+)", "group": 1}],
    },
    "AWS ELB": {
        "cats": ["Web Server", "Load Balancer"],
        "headers": {"server": "awselb"},
    },

    # ─────────── CDN / WAF ───────────
    "Cloudflare": {
        "cats": ["CDN", "WAF", "Security"],
        "headers": {"cf-ray": ".", "cf-cache-status": ".", "server": "cloudflare"},
        "cookies": {"__cfduid": "", "__cf_bm": "", "_cfuvid": ""},
    },
    "CloudFront": {
        "cats": ["CDN"],
        "headers": {"x-amz-cf-id": ".", "x-amz-cf-pop": "."},
    },
    "Akamai": {
        "cats": ["CDN", "WAF"],
        "headers": {"x-akamai-": ".", "x-akamai-config": "."},
    },
    "Fastly": {
        "cats": ["CDN"],
        "headers": {"x-fastly-request": ".", "x-served-by": "cache-"},
    },
    "Sucuri": {
        "cats": ["WAF", "Security"],
        "headers": {"x-sucuri-id": ".", "x-sucuri-cache": "."},
        "cookies": {"sucuri_cloudproxy": ""},
    },
    "Imperva": {
        "cats": ["WAF", "Security"],
        "cookies": {"incap_ses": "", "visid_incap": ""},
        "headers": {"x-cdn": "Imperva"},
    },
    "Varnish": {
        "cats": ["CDN", "Caching"],
        "headers": {"via": "varnish", "x-varnish": ".", "x-cache": "HIT|MISS"},
    },

    # ─────────── Analytics ───────────
    "Google Analytics": {
        "cats": ["Analytics"],
        "url": ["google-analytics\\.com/analytics\\.js"],
        "html": ["ga\\('create',\\s*'UA-", "ga\\('config',\\s*'G-", "gtag\\('config',\\s*'"],
        "body": ["google-analytics\\.com/analytics\\.js", "googletagmanager\\.com/gtag/js"],
    },
    "Google Tag Manager": {
        "cats": ["Analytics"],
        "html": ["googletagmanager\\.com/ns\\.html", "GTM-"],
        "body": ["googletagmanager\\.com/gtm\\.js"],
    },
    "Meta Pixel": {
        "cats": ["Analytics", "Advertising"],
        "html": ["fbq\\(", "facebook\\.com/tr\\?"],
        "body": ["connect\\.facebook\\.net/\\w+/fbevents\\.js"],
    },
    "Hotjar": {
        "cats": ["Analytics"],
        "html": ["hotjar", "hj\\("],
        "body": ["static\\.hotjar\\.com/c/hotjar-"],
    },
    "HubSpot": {
        "cats": ["Analytics", "CRM"],
        "html": ["hs-analytics", "HubSpot"],
        "body": ["js\\.hs-scripts\\.com/"],
        "cookies": {"hubspot": "", "__hstc": "", "__hssc": ""},
    },
    "Yandex Metrica": {
        "cats": ["Analytics"],
        "cookies": {"_ym_uid": "", "_ym_d": "", "_ym_metrika": ""},
        "html": ["ym\\(", "metrika\\.yandex"],
        "body": ["mc\\.yandex\\.ru/metrika/watch\\.js"],
    },
    "Matomo": {
        "cats": ["Analytics"],
        "body": ["piwik\\.js", "matomo\\.js", "_paq\\.push"],
        "html": ["_paq\\.push"],
    },

    # ─────────── JavaScript Libraries ───────────
    "jQuery": {
        "cats": ["JavaScript Library"],
        "url": ["jquery[.-]([\\d.]+)\\.min\\.js", "jquery\\.min\\.js"],
        "body": ["jquery@([\\d.]+)", "jquery[.-]([\\d.]+)\\.min\\.js"],
        "html": ["jQuery\\(|jQuery\\.|jQuery"],
        "version": [
            {"from": "url", "pattern": "jquery[.-]([\\d.]+)\\.min\\.js", "group": 1},
            {"from": "body", "pattern": "jquery@([\\d.]+)", "group": 1},
        ],
    },
    "jQuery UI": {
        "cats": ["JavaScript Library"],
        "url": [r"jquery-ui[.-]([\d.]+)\.min\.js", r"jqueryui[.-]"],
        "body": [r"jquery-ui[.-]([\d.]+)\.min\.js", r"jquery-ui\.custom\.js"],
        "version": [{"from": "url", "pattern": r"jquery-ui[.-]([\d.]+)", "group": 1}],
    },
    "Bootstrap": {
        "cats": ["CSS Framework"],
        "url": ["bootstrap[.-]([\\d.]+)\\.min\\.js", "bootstrap\\.min\\.js"],
        "body": ["bootstrap@([\\d.]+)", "cdn\\.jsdelivr\\.net/npm/bootstrap@([\\d.]+)"],
        "html": ["class=\"navbar", "class=\"[^\"]*\\bbtn\\b", "col-md-", "class=\"[^\"]*\\bcontainer\\b"],
        "version": [
            {"from": "url", "pattern": "bootstrap[.-]([\\d.]+)\\.min\\.js", "group": 1},
            {"from": "body", "pattern": "bootstrap@([\\d.]+)", "group": 1},
        ],
    },
    "Font Awesome": {
        "cats": ["Font"],
        "url": ["font-awesome", "fontawesome"],
        "body": ["fa-", "font-awesome/", "fontawesome/"],
        "html": ["class=\"[^\"]*\\bfa\\b"],
    },
    "Lodash": {
        "cats": ["JavaScript Library"],
        "url": ["lodash[.-]([\\d.]+)\\.min\\.js"],
        "version": [{"from": "url", "pattern": "lodash[.-]([\\d.]+)", "group": 1}],
    },
    "Moment.js": {
        "cats": ["JavaScript Library"],
        "url": ["moment[.-]([\\d.]+)\\.min\\.js"],
        "version": [],
    },
    "Alpine.js": {
        "cats": ["JavaScript Framework"],
        "url": ["alpinejs", "alpine\\.min\\.js"],
        "html": ["x-data", "x-init", "x-on:", "x-bind:"],
    },
    "HTMX": {
        "cats": ["JavaScript Library"],
        "url": ["htmx", "htmx\\.min\\.js"],
        "html": ["hx-get", "hx-post", "hx-trigger", "hx-target"],
    },
    "Three.js": {
        "cats": ["JavaScript Library"],
        "url": ["three\\.min\\.js", "three@([\\d.]+)"],
        "version": [],
    },

    # ─────────── E-commerce ───────────
    "WooCommerce": {
        "cats": ["E-commerce"],
        "implies": ["WordPress"],
        "cookies": {"woocommerce": ""},
        "body": ["woocommerce", "wc-", "add-to-cart"],
        "url": ["/cart/", "/checkout/", "/product/", "/shop/"],
        "version": [],
    },

    # ─────────── Security ───────────
    "reCAPTCHA": {
        "cats": ["Security"],
        "url": ["recaptcha/api\\.js", "recaptcha\\.net"],
        "body": ["google\\.com/recaptcha", "recaptcha\\.net"],
    },
    "HSTS": {
        "cats": ["Security"],
        "headers": {"strict-transport-security": "."},
    },

    # ─────────── Webmail ───────────
    "RoundCube": {
        "cats": ["Webmail"],
        "body": ["roundcube", "rcmail"],
        "url": ["/webmail/", "/roundcube/"],
    },

    # ─────────── Misc ───────────
    "Google Fonts": {
        "cats": ["Font"],
        "url": ["fonts\\.googleapis\\.com", "fonts\\.gstatic\\.com"],
        "body": ["fonts\\.googleapis\\.com", "fonts\\.gstatic\\.com"],
    },
    "Stripe": {
        "cats": ["Payment"],
        "body": ["stripe\\.com", "Stripe\\.js", "Stripe\\.setPublishableKey"],
    },
    "PayPal": {
        "cats": ["Payment"],
        "html": ["paypal", "paypal\\.com/sdk/js"],
        "body": ["paypal\\.com/sdk/js"],
    },
    "cPanel": {
        "cats": ["Control Panel"],
        "body": ["cPanel", "cpanel"],
        "url": ["/cpanel/", ":2083"],
        "headers": {"server": "cPanel"},
    },
    "Plesk": {
        "cats": ["Control Panel"],
        "headers": {"x-powered-by-plesk": ".", "x-plesk": "."},
    },
    "Node.js": {
        "cats": ["Programming Language", "Runtime"],
        "headers": {"x-powered-by": "Node\\.js", "server": "Node\\.js"},
    },
}


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def _check_url(target_url: str, patterns: list[str]) -> list[str]:
    """Check URL against a list of regex patterns. Returns version matches."""
    matches = []
    for pat in patterns:
        m = re.search(pat, target_url, re.IGNORECASE)
        if m:
            matches.append(m)
    return matches


def _check_headers(headers: dict, sig_headers: dict) -> bool:
    """Check if response headers match signature header patterns."""
    for hname, hpat in sig_headers.items():
        val = headers.get(hname.lower(), "")
        if not val:
            continue
        if hpat == ".":  # any value
            return True
        if re.search(hpat, val, re.IGNORECASE):
            return True
    return False


def _check_cookies(cookies: list[dict], sig_cookies: dict) -> bool:
    """Check if cookies match signature patterns.
    Empty value = prefix match (cookie name starts with)."""
    cookie_names = [c.get("name", "").lower() for c in cookies]
    for cname, _cval in sig_cookies.items():
        cname_lower = cname.lower()
        for cn in cookie_names:
            if cname_lower == cn or cn.startswith(cname_lower) or cname_lower.startswith(cn):
                return True
    return False


def _check_meta(body: str, sig_meta: dict) -> list[re.Match]:
    """Check HTML for matching meta tags."""
    matches = []
    for mname, mpat in sig_meta.items():
        # Match <meta name="xxx" content="...">
        pat = re.compile(
            r'<meta\s[^>]*' +
            re.escape(mname) +
            r'[^>]*content=["\']([^"\']+)["\']',
            re.IGNORECASE,
        )
        found = pat.findall(body)
        if found:
            for val in found:
                m = re.search(mpat, val, re.IGNORECASE)
                if m:
                    matches.append(m)
                    break  # one match per meta name is enough
    return matches


def _check_body(body: str, patterns: list[str]) -> list[re.Match]:
    """Check visible body text against patterns."""
    matches = []
    for pat in patterns:
        m = re.search(pat, body, re.IGNORECASE)
        if m:
            matches.append(m)
    return matches


def _check_html(html: str, patterns: list[str]) -> list[re.Match]:
    """Check raw HTML against patterns."""
    matches = []
    for pat in patterns:
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            matches.append(m)
    return matches


def _extract_version(tech_name: str, headers: dict, url: str, body: str,
                     meta_matches: list[re.Match]) -> str | None:
    """Try to extract a version string for a technology."""
    sig = TECH_SIGNATURES.get(tech_name, {})
    version_rules = sig.get("version", [])

    for rule in version_rules:
        source = rule.get("from", "body")
        pattern = rule["pattern"]
        group = rule.get("group", 1)

        if source == "headers":
            text = " ".join(f"{k}:{v}" for k, v in headers.items())
        elif source == "url":
            text = url
        elif source == "meta":
            # Use the first meta match result
            for m in meta_matches:
                try:
                    return m.group(group)
                except IndexError:
                    continue
            continue
        else:  # body
            text = body

        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            try:
                return m.group(group)
            except IndexError:
                pass
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_tech(
    url: str,
    headers: dict[str, str],
    cookies: list[dict],
    body: str,
    html_body: str | None = None,
) -> list[dict]:
    """Detect technologies from HTTP response data.

    Parameters
    ----------
    url : str
        The final URL of the page.
    headers : dict[str, str]
        All response headers with lowercase keys.
    cookies : list[dict]
        List of cookie dicts (must have a 'name' key).
    body : str
        Full response body text.
    html_body : str | None
        Raw HTML (falls back to *body* if not provided).

    Returns
    -------
    list[dict]
        Each entry: {name, category, version (str|None), confidence (str)}.
        Sorted by confidence descending.
    """
    if html_body is None:
        html_body = body

    found: list[dict] = []
    seen: set[str] = set()

    for tech_name, sig in TECH_SIGNATURES.items():
        if tech_name in seen:
            continue

        detection_score = 0
        max_score = 0
        meta_matches: list[re.Match] = []

        # URL patterns (weight: 2)
        url_patterns = sig.get("url", [])
        if url_patterns:
            max_score += 2
            if _check_url(url, url_patterns):
                detection_score += 2

        # Header patterns (weight: 3)
        header_patterns = sig.get("headers", {})
        if header_patterns:
            max_score += 3
            if _check_headers(headers, header_patterns):
                detection_score += 3

        # Cookie patterns (weight: 2)
        cookie_patterns = sig.get("cookies", {})
        if cookie_patterns:
            max_score += 2
            if _check_cookies(cookies, cookie_patterns):
                detection_score += 2

        # Meta tag patterns (weight: 3)
        meta_patterns = sig.get("meta", {})
        if meta_patterns:
            max_score += 3
            meta_matches = _check_meta(body, meta_patterns)
            if meta_matches:
                detection_score += 3

        # HTML patterns (weight: 2)
        html_patterns = sig.get("html", [])
        if html_patterns:
            max_score += 2
            if _check_html(html_body, html_patterns):
                detection_score += 2

        # Body patterns (weight: 2)
        body_patterns = sig.get("body", [])
        if body_patterns:
            max_score += 2
            if _check_body(body, body_patterns):
                detection_score += 2

        # Determine if detected
        if detection_score > 0:
            seen.add(tech_name)

            # Extract version
            version = _extract_version(tech_name, headers, url, body, meta_matches)

            # Confidence label
            confidence_pct = int((detection_score / max_score) * 100) if max_score else 50
            if confidence_pct >= 80:
                label = "certain"
            elif confidence_pct >= 50:
                label = "probable"
            else:
                label = "possible"

            cats = sig.get("cats", ["Unknown"])
            for cat in cats:
                found.append({
                    "name": tech_name,
                    "category": cat,
                    "version": version,
                    "confidence": label,
                })

            # Implied technologies
            for implied in sig.get("implies", []):
                if implied not in seen:
                    seen.add(implied)
                    found.append({
                        "name": implied,
                        "category": "Implied",
                        "version": None,
                        "confidence": "implied",
                    })

    # Sort: certain first, then alphabetical
    conf_order = {"certain": 0, "probable": 1, "possible": 2, "implied": 3}
    found.sort(key=lambda x: (conf_order.get(x["confidence"], 9), x["category"], x["name"]))

    return found
