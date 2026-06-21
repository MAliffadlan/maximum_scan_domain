"""
Subdomain enumeration module for domain-probe.

Discovers subdomains via:
  - Passive: crt.sh, AlienVault OTX, BufferOver, Rapiddns, Riddler, URLScan
  - Active: DNS brute-force (customizable wordlist)
  - External: Subfinder binary (optional, auto-detected)

Exports:
    run_subdomains(domain, brute_count=0) -> dict
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shlex
import shutil
import string
import subprocess
import sys
import time

import dns.resolver
import requests

from modules.session import request as http_request
from modules.session import enforce_dns_rate_limit


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DNS_TIMEOUT = 2
_REQ_TIMEOUT = 15
_USER_AGENT = "DomainProbe/2.0"

# Subfinder binary path (auto-detected)
_SUBFINDER_PATH = shutil.which("subfinder")


# ── Passive Sources ──────────────────────────────────────────────────────

def _fetch_crtsh(domain: str) -> list[str]:
    """Query crt.sh certificate transparency logs."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=_REQ_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return []

    results = []
    for entry in data:
        nv = entry.get("name_value", "")
        if nv:
            results.append(nv)
    return results


def _fetch_alienvault(domain: str) -> list[str]:
    """Query AlienVault OTX — free, no API key needed."""
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        resp = requests.get(url, timeout=_REQ_TIMEOUT,
                            headers={"User-Agent": _USER_AGENT})
        if resp.status_code != 200:
            return []
        data = resp.json()
        return [entry["hostname"] for entry in data.get("passive_dns", [])
                if isinstance(entry, dict) and entry.get("hostname")]
    except Exception:
        return []


def _fetch_bufferover(domain: str) -> list[str]:
    """Query BufferOver.run — free DNS dump."""
    url = f"https://dns.bufferover.run/dns?q=.{domain}"
    try:
        resp = requests.get(url, timeout=_REQ_TIMEOUT)
        if resp.status_code != 200:
            return []
        data = resp.json()
        results = []
        for fdns in data.get("FDNS_A", []):
            parts = fdns.split(",")
            if len(parts) >= 2:
                host = parts[1].strip().rstrip(".")
                if host.endswith(domain):
                    results.append(host)
        for rdns in data.get("RDNS", []):
            parts = rdns.split(",")
            if len(parts) >= 2:
                host = parts[1].strip().rstrip(".")
                if host.endswith(domain):
                    results.append(host)
        return results
    except Exception:
        return []


def _fetch_rapiddns(domain: str) -> list[str]:
    """Query RapidDNS.io."""
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    try:
        resp = requests.get(url, timeout=_REQ_TIMEOUT,
                            headers={"User-Agent": _USER_AGENT})
        if resp.status_code != 200:
            return []
        # Parse HTML table — find <td> with domain names
        results = []
        for match in re.finditer(rf'<td[^>]*>([a-zA-Z0-9.-]+\.{re.escape(domain)})</td>',
                                 resp.text):
            results.append(match.group(1))
        return results
    except Exception:
        return []


def _fetch_riddler(domain: str) -> list[str]:
    """Query riddler.io."""
    url = f"https://riddler.io/search/exportcsv?q=pld:{domain}"
    try:
        resp = requests.get(url, timeout=_REQ_TIMEOUT,
                            headers={"User-Agent": _USER_AGENT})
        if resp.status_code != 200:
            return []
        results = []
        for line in resp.text.splitlines():
            parts = line.split(",")
            if len(parts) >= 2:
                host = parts[0].strip().strip("\"").rstrip(".")
                if host.endswith(domain) and "." in host:
                    results.append(host)
        return results
    except Exception:
        return []


def _fetch_urlscan(domain: str) -> list[str]:
    """Query urlscan.io."""
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
    try:
        resp = requests.get(url, timeout=_REQ_TIMEOUT,
                            headers={"User-Agent": _USER_AGENT})
        if resp.status_code != 200:
            return []
        data = resp.json()
        results = []
        for result in data.get("results", []):
            page = result.get("page", {})
            host = page.get("domain", "") or page.get("asn", "")
            if host and host.endswith(domain) and host != domain:
                results.append(host)
        return results
    except Exception:
        return []


def _fetch_subfinder(domain: str) -> list[str]:
    """Run Subfinder binary if available.

    Subfinder by ProjectDiscovery finds subdomains from 30+ passive sources.
    Download: https://github.com/projectdiscovery/subfinder
    """
    if not _SUBFINDER_PATH:
        return []

    try:
        proc = subprocess.run(
            [shlex.quote(_SUBFINDER_PATH), "-d", domain, "-silent"],
            capture_output=True, text=True, timeout=60,
        )
        if proc.returncode != 0:
            return []

        results = []
        for line in proc.stdout.splitlines():
            line = line.strip().lower()
            if line and line.endswith(f".{domain}"):
                results.append(line)
        return results
    except Exception:
        return []


def _parse_name_values(raw_entries, domain: str) -> set[str]:
    """Split multiline entries, filter to matching domain, deduplicate."""
    domain_lower = domain.lower().strip(".")
    seen = set()

    for entry in raw_entries:
        for name in entry.splitlines():
            name = name.strip().lower()
            if not name:
                continue
            name = name.lstrip("*.").lstrip(".").strip()
            if not name:
                continue
            if name == domain_lower or name.endswith("." + domain_lower):
                seen.add(name)

    return seen


# ── Active brute-force ──────────────────────────────────────────────────

# Expanded wordlist: 1000+ common subdomain prefixes
# Sources: SecLists, dnscan, subbrute, common-http
COMMON_SUBDOMAINS = [
    # Core
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "webdisk", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap",
    "test", "ns", "www.*", "docs", "help", "site", "blog", "demo", "admin",
    "dev", "staging", "api", "app", "portal", "vpn", "remote", "support",
    "status", "cdn", "cloud", "store", "shop", "pay", "payment", "billing",
    "secure", "server", "mail2", "mx", "mx1", "mx2", "email", "news",
    # Common prefixes
    "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
    "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
    "abc", "access", "account", "accounts", "ad", "adm", "admin-console",
    "administrator", "adserver", "adult", "affiliate", "affiliates", "ajax",
    "alerts", "alpha", "analytics", "android", "announce", "answers",
    "any", "aol", "app-dev", "app-test", "app1", "app2", "apple-touch-icon",
    "application", "apps", "archive", "arpa", "articles", "asia",
    "assets", "auth", "author", "authorize", "autodiscover", "autoresponder",
    "backup", "backup1", "banners", "base", "beta", "billing", "bin",
    "bitbucket", "blob", "blogs", "board", "bonus", "books", "broadcasthost",
    "broker", "bugs", "build", "business", "buy",
    "calendar", "campaign", "campus", "candidate", "career", "careers",
    "cart", "categories", "cc", "cctld", "cde", "cdn1", "cdn2", "cert",
    "channel", "charts", "chat", "check", "checkout", "chrome", "cisco",
    "clarity", "classroom", "client", "clients", "clinical", "cloud1",
    "cluster", "cms", "code", "coffee", "com", "commercial", "community",
    "company", "compare", "compliance", "computer", "computers", "config",
    "connect", "console", "contact", "contacts", "contractors", "control",
    "conference", "coop", "coord", "cpanel", "crawler", "creative", "crm",
    "crossdomain", "css", "cto", "custom", "customer", "customers",
    "daemon", "dashboard", "data", "database", "db", "db1", "debug",
    "default", "delivery", "demo", "design", "desk", "desktop", "devel",
    "developer", "developers", "device", "devices", "deploy", "deploys",
    "dhcp", "diagram", "direct", "direct-connect", "directory", "discount",
    "discover", "discovery", "discussion", "display", "dist", "dl",
    "dmarc", "dns", "dns1", "dns2", "dns3", "dns4", "docs", "documents",
    "domain", "domains", "donate", "download", "downloads", "draft",
    "drafts", "drive", "drop", "drupal", "ds", "dsn",
    "ecommerce", "edit", "editor", "edu", "education", "election",
    "electrical", "electronics", "elegant", "email", "emergency",
    "employee", "employees", "empty", "enable", "encrypt", "end", "eng",
    "engineering", "enterprise", "erp", "error", "errors", "es", "etc",
    "eu", "event", "events", "example", "exchange", "exclude", "exec",
    "executive", "experiment", "expert", "export", "extranet",
    "fail", "failure", "fair", "faq", "fault", "fax", "feature",
    "features", "fed", "feedback", "file", "files", "finance",
    "financial", "find", "firewall", "firm", "first", "fixtures",
    "flash", "fleet", "flex", "fly", "font", "fonts", "foo", "forgot",
    "forgot-password", "form", "forms", "forum", "forums", "foundation",
    "free", "freshdesk", "freshservice", "ftp", "fw", "fw1",
    "gallery", "games", "gate", "gatekeeper", "gateway", "gbl", "gc",
    "gid", "git", "github", "gmail", "go", "google", "gov", "govt",
    "gp", "gpl", "graph", "graphql", "group", "groups", "grp", "guest",
    "guide", "guides", "guru", "gw", "gw-", "gwt",
    "hack", "hadoop", "hardware", "hd", "head", "health", "hello", "help",
    "helpdesk", "hidden", "hide", "hierarchy", "high", "hipaa", "history",
    "home", "homepage", "homes", "honeypot", "hop", "horizon", "host",
    "hosting", "hostmaster", "hotel", "hotfix", "hover", "howto", "hp",
    "hq", "hr", "html", "http", "https", "hub",
    "ibm", "icon", "icons", "id", "idea", "ideas", "idp", "iframe",
    "ig", "ignore", "iis", "illustrator", "im", "image", "images",
    "imail", "imap", "img", "importer", "in", "inbound", "include",
    "included", "includes", "index", "indexing", "indonesia",
    "info", "information", "infra", "infrastructure", "inquiry", "inspect",
    "install", "installer", "instant", "institute", "int", "integration",
    "intelligence", "intranet", "invalid", "inventory", "investigation",
    "investor", "investors", "invoice", "invoices", "io", "ip", "ipmi",
    "ipv4", "ipv6", "irc", "is", "isatap", "island", "ism", "iso",
    "issue", "issues", "it", "item", "items",
    "jabber", "jack", "java", "javascript", "jboss", "jdbc", "jdev",
    "jira", "job", "jobs", "join", "jquery", "jre", "json", "jsp",
    "kafka", "keep", "keeper", "kernel", "key", "keyboard", "keys",
    "knowledge", "knowledgebase",
    "l", "lab", "label", "labels", "labs", "lam", "lan", "language",
    "laptop", "large", "las", "last", "law", "layout", "lazy", "lb",
    "lbs", "ldap", "ldaps", "lead", "leader", "learn", "learning",
    "leather", "leave", "lecture", "left", "legal", "lending", "level",
    "lftp", "lg", "li", "liason", "library", "license", "life",
    "lifestyle", "light", "like", "limit", "line", "link", "linkedin",
    "linux", "list", "lists", "live", "load", "load-balancer", "loader",
    "loan", "local", "localhost", "locate", "location", "lock", "locked",
    "login", "logistics", "logo", "logout", "logs", "look", "lose",
    "lost", "lot", "love", "low", "loyal", "lte", "luck", "lug",
    "lunch", "lxc", "lyrics",
    "mac", "machine", "macos", "mad", "magazine", "magic", "mail1",
    "mail2", "mail3", "mailer", "mailing", "mailman", "mails", "main",
    "maintain", "maintenance", "major", "manage", "management", "manager",
    "managers", "manual", "manufacturing", "map", "maps", "mark",
    "markdown", "market", "marketing", "markets", "master", "maven",
    "max", "mb", "mc", "md", "me", "measure", "measuring", "mechanic",
    "media", "media1", "media2", "meet", "meeting", "meetings", "member",
    "members", "memorial", "memory", "menu", "merchant", "merchants",
    "merge", "message", "messages", "messenger", "meta", "meter",
    "method", "metrics", "mi", "miami", "micro", "microsites", "middle",
    "middleware", "migration", "mike", "mil", "military", "milk",
    "mine", "mini", "mining", "minister", "ministry", "minor", "minutes",
    "mirror", "mirrors", "mis", "mission", "mix", "mobile", "mobility",
    "model", "modem", "moderator", "modern", "module", "modules",
    "money", "monitor", "monitoring", "monthly", "moon", "mortgage",
    "mother", "motor", "mount", "mountain", "mouse", "move", "movie",
    "movies", "moving", "mp3", "mpls", "mr", "mrs", "ms", "msg",
    "msn", "mt", "multi", "multimedia", "multiplexor", "murals", "mus",
    "museum", "music", "musical", "mutual", "mx", "mysql", "myspace",
    "nagios", "name", "named", "nano", "nat", "national", "native",
    "nature", "nav", "navi", "navigation", "nba", "ne", "near", "need",
    "net", "net1", "net2", "networking", "networks", "news", "newsletter",
    "newyork", "next", "nextcloud", "nexus", "nfs", "noc", "nokia",
    "nomad", "none", "noreply", "normal", "north", "nos", "note", "notes",
    "nothing", "notice", "notification", "notifications", "notify",
    "now", "npm", "ns0", "ns1", "ns2", "ns3", "ns4", "ns5", "ns6",
    "ns7", "ns8", "ns9", "ntp", "null", "number", "numbers", "nut",
    "nutrition", "nyc", "nyse",
    "o", "oauth", "ob", "obj", "object", "objects", "obsolete",
    "occasion", "ocean", "od", "odbc", "off", "offers", "office",
    "officer", "official", "offline", "old", "olympic", "on", "once",
    "one", "online", "only", "ooc", "open", "openerp", "openshift",
    "opensource", "opera", "operating", "operation", "operations",
    "operator", "opinion", "opt", "optical", "optimization", "option",
    "options", "oracle", "orange", "order", "orders", "org", "organic",
    "organization", "organize", "orient", "origin", "original", "os",
    "ospf", "other", "others", "ott", "ou", "out", "outage", "outages",
    "outbound", "outline", "outlook", "output", "outside", "outsourcing",
    "over", "overflow", "owner",
    "p", "pace", "pac", "package", "packages", "packaging", "packet",
    "page", "pages", "paid", "pain", "paint", "painting", "pair",
    "pak", "pal", "palo", "pan", "panel", "panic", "pano", "panorama",
    "paper", "par", "paris", "park", "parking", "parse", "part",
    "partner", "partners", "partnership", "party", "pass", "passage",
    "passenger", "passion", "passive", "passport", "password", "paste",
    "patch", "patches", "patent", "path", "patient", "patients",
    "pattern", "pause", "pay", "payment", "payments", "paypal", "pc",
    "pda", "pdf", "pe", "peace", "peak", "peer", "pencil", "penn",
    "people", "per", "percent", "perfect", "perform", "performance",
    "perl", "permanent", "permission", "permissions", "permit",
    "personal", "personnel", "perspective", "pet", "pete", "peter",
    "petition", "pets", "pgp", "ph", "pharmacy", "phase", "phone",
    "photo", "photograph", "photography", "photos", "php", "phpmyadmin",
    "phrase", "physical", "pi", "piano", "pick", "pic", "pickup",
    "picture", "pictures", "pie", "piece", "pilot", "pin", "pipe",
    "pipeline", "pitch", "pixel", "pixels", "place", "placement",
    "places", "plain", "plan", "plane", "planet", "planning", "plant",
    "plants", "plastics", "plate", "platinum", "play", "player",
    "players", "playground", "plc", "ple", "plot", "plugin", "plugins",
    "plumbing", "plus", "pm", "pmc", "po", "pocket", "pod", "podcast",
    "poetry", "point", "points", "police", "policy", "polish",
    "political", "politics", "poll", "polls", "pool", "pop", "pops",
    "popular", "population", "port", "portal", "portland", "portrait",
    "ports", "portsmouth", "portugal", "portuguese", "pos", "pose",
    "position", "positions", "positive", "post", "postal", "postfix",
    "postgres", "postmaster", "postscript", "pot", "potato", "potential",
    "power", "powered", "powerpoint", "powershell", "pp", "ppp",
    "pppoe", "practical", "practice", "prague", "pre", "preference",
    "preferences", "premium", "preparation", "prepare", "presence",
    "present", "presentation", "presentations", "president", "press",
    "preview", "previous", "price", "prices", "pricing", "pride",
    "primary", "prime", "prince", "princess", "princeton", "principal",
    "principle", "print", "printer", "printing", "prior", "priority",
    "privacy", "private", "privilege", "privileges", "prize", "pro",
    "probe", "problem", "problems", "procedures", "proceed", "process",
    "processing", "processor", "producers", "product", "production",
    "productions", "productive", "productivity", "products", "prof",
    "professional", "professor", "profile", "profiles", "profit",
    "program", "programme", "programmer", "programming", "programs",
    "progress", "project", "projector", "projects", "promo", "promote",
    "promotion", "promotions", "prompt", "proof", "prop", "propaganda",
    "property", "proposal", "proposals", "propose", "proposition",
    "protect", "protected", "protection", "protective", "protein",
    "protest", "protocol", "prototype", "proud", "prove", "provider",
    "providers", "provides", "province", "provision", "proxy", "prs",
    "pst", "psychology", "pt", "ptp", "pub", "public", "publications",
    "publicity", "publish", "published", "publisher", "publishers",
    "publishing", "pull", "pulse", "pump", "pumps", "purchase",
    "purchasing", "pure", "purple", "purpose", "purse", "push", "put",
    "puzzle", "puzzles", "pwd",
    "qa", "qmail", "qos", "qt", "qtp", "qua", "qualification",
    "qualify", "quality", "quantum", "quarter", "quarterly", "quarters",
    "quebec", "queen", "query", "quest", "question", "questions",
    "queue", "quick", "quickbooks", "quicktime", "quiet", "quilt",
    "quit", "quiz", "quizzes", "quote", "quotes",
    "r", "ra", "rabbit", "race", "racing", "rack", "radar", "radiation",
    "radio", "radius", "rage", "raid", "rail", "railroad", "rain",
    "raise", "rally", "ram", "ran", "ranch", "random", "range", "rank",
    "ranking", "rapid", "rapids", "rare", "rat", "rate", "rates",
    "rating", "ratings", "ratio", "raw", "ray", "rc", "rd", "rdata",
    "reach", "react", "reaction", "read", "reader", "readers", "reading",
    "readings", "ready", "real", "reality", "realms", "realtor",
    "realtors", "realty", "reasons", "rebate", "rebel", "reboot",
    "recall", "receipt", "receive", "receiver", "receivers", "recent",
    "reception", "recharge", "recipe", "recipient", "recognition",
    "recommend", "recommended", "record", "recording", "recordings",
    "records", "recover", "recovery", "recreation", "recruiting",
    "recruitment", "recycle", "red", "redirect", "redirects", "redir",
    "redmine", "reduce", "refer", "reference", "referral", "referrals",
    "referred", "refers", "refinance", "reflection", "reflector",
    "reflex", "reform", "refresh", "refund", "refunds", "refuse",
    "region", "regional", "register", "registered", "registrar",
    "registration", "registry", "regulations", "rehab", "reimburse",
    "reimbursement", "reinstate", "reject", "rel", "relate", "relation",
    "relations", "relationship", "relationships", "relative",
    "relatives", "relax", "relay", "release", "relevance", "relevant",
    "reliability", "reliable", "relief", "religion", "religious",
    "relocate", "relocation", "rely", "remaining", "remark", "remarks",
    "remedy", "remember", "reminder", "remix", "remote", "removal",
    "remove", "render", "rendering", "renew", "renewal", "renewals",
    "rent", "rental", "rentals", "repair", "repairs", "repeat",
    "replacement", "replay", "replica", "replication", "reply", "report",
    "reporter", "reporting", "reports", "repository", "represent",
    "reprint", "reproduce", "reproduction", "republic", "republican",
    "reputation", "request", "requests", "require", "required",
    "requirement", "requirements", "requires", "research", "reseller",
    "reservation", "reservations", "reserve", "reserved", "reserves",
    "reset", "reside", "resident", "residential", "resign", "resignation",
    "resin", "resist", "resistance", "resolution", "resolve", "resort",
    "resource", "resources", "respond", "responder", "response",
    "responses", "responsibilities", "responsibility", "responsible",
    "rest", "restore", "restricted", "restriction", "restrictions",
    "restructure", "result", "results", "resume", "retail", "retailer",
    "retain", "retention", "retire", "retired", "retirement", "retreat",
    "retrieval", "retrieve", "retro", "return", "returns", "reunion",
    "reuse", "rev", "reveal", "revenue", "reverse", "review", "reviewer",
    "reviewers", "reviews", "revise", "revision", "revisions", "revival",
    "revolution", "reward", "rewards", "rfc", "rfp", "rfs", "rhel",
    "rhn", "rhr", "ribbon", "rice", "rich", "richard", "richmond",
    "rid", "ride", "rider", "ridge", "riding", "right", "rights",
    "rigid", "ring", "rings", "riot", "rip", "ripe", "risk", "risks",
    "river", "rivers", "rl", "rlogin", "rm", "rnd", "rns", "road",
    "roadmap", "roads", "robert", "robotics", "robots", "robust",
    "rock", "rocket", "rockets", "rodeo", "roi", "role", "roles",
    "roll", "roller", "rolling", "roman", "romance", "roof", "room",
    "rooms", "root", "roots", "rose", "rotate", "rotation", "rough",
    "rouge", "round", "rounds", "route", "router", "routers", "routes",
    "routine", "routings", "rover", "row", "rows", "rpc", "rpm",
    "rrd", "rsa", "rss", "rst", "rsvp", "rt", "rtmp", "rtp", "rts",
    "ruby", "rug", "rugby", "rule", "ruler", "rules", "run", "running",
    "runs", "rural", "rush", "russia", "russian", "rvs",
    "s", "sac", "safe", "safety", "saga", "sage", "sail", "sailing",
    "saint", "sake", "salad", "salary", "sale", "sales", "salesforce",
    "salt", "salute", "salvador", "salvation", "sample", "samples",
    "sampling", "sand", "sandbox", "sandvik", "sanitize", "sap", "sat",
    "satellite", "satin", "satire", "satisfaction", "saturday", "sauce",
    "saudi", "save", "saving", "savings", "saw", "say", "sb", "sc",
    "scala", "scalability", "scale", "scanner", "scanners", "scanning",
    "scare", "scenario", "scenarios", "scene", "scenes", "schedule",
    "scheduled", "scheduler", "schedules", "schema", "scheme", "schemes",
    "scholar", "scholarship", "school", "schools", "science", "sciences",
    "scientific", "scientist", "scope", "score", "scores", "scotia",
    "scott", "screen", "screening", "screens", "screensaver",
    "screenshot", "screenshots", "script", "scripts", "scroll", "scsi",
    "sculpture", "sd", "sde", "sdk", "sdr", "se", "sea", "seal",
    "seamless", "search", "searches", "searching", "season", "seasons",
    "seat", "seats", "seattle", "sec", "second", "secondary", "seconds",
    "secret", "secretariat", "secretary", "secrets", "section",
    "sections", "sector", "secure", "secured", "securely", "secures",
    "security", "securityservices", "see", "seed", "seeing", "seek",
    "segment", "segments", "seo", "sep", "separate", "separation",
    "september", "seq", "sequence", "sequoia", "ser", "serbian",
    "serial", "series", "serious", "server", "servers", "service",
    "services", "serving", "session", "sessions", "set", "setup",
    "seven", "seventh", "sever", "several", "severe", "sewing",
    "sex", "sexy", "sf", "sg", "sh", "shade", "shades", "shadow",
    "shadows", "shaft", "shake", "shall", "shame", "shape", "shapes",
    "share", "shared", "shares", "sharing", "shark", "sharp", "shave",
    "sheet", "shelf", "shell", "shelter", "shift", "shine", "ship",
    "shipping", "ships", "shirt", "shirts", "shock", "shoe", "shoes",
    "shoot", "shooting", "shop", "shopper", "shopping", "shore",
    "short", "shortcuts", "shorter", "shortly", "shots", "should",
    "shoulder", "show", "showcase", "shower", "showroom", "shows",
    "shred", "shrimp", "shrine", "shrink", "shrub", "shuffle", "shut",
    "shuttle", "si", "sibling", "sic", "side", "sides", "sidney",
    "siebel", "siego", "siemens", "sierra", "sig", "sight", "sigma",
    "sign", "signal", "signals", "signature", "signatures", "signed",
    "signin", "signing", "signout", "signs", "signup", "silence",
    "silent", "silk", "silly", "silver", "sim", "similar", "simple",
    "simplified", "simply", "sims", "simulation", "simulations",
    "simulator", "simultaneous", "sin", "since", "sing", "singapore",
    "singer", "singing", "single", "singles", "sink", "sip", "sir",
    "sister", "sit", "site", "sitemap", "sites", "sitting", "situated",
    "situation", "situations", "six", "sixth", "size", "sizes",
    "sketch", "ski", "skid", "skill", "skills", "skim", "skin",
    "skins", "skip", "skirt", "skirts", "skype", "sl", "slack",
    "slave", "sleep", "sleeping", "slice", "slide", "slides",
    "slideshow", "slight", "slim", "slip", "slope", "slot", "slots",
    "slow", "slowing", "slowly", "sma", "small", "smaller", "smallest",
    "smart", "smb", "smile", "smith", "smooth", "sms", "smtp", "sn",
    "snap", "snapshot", "snapshots", "sneakers", "snoop", "snow",
    "so", "soa", "soap", "soc", "soccer", "social", "society",
    "socket", "socks", "soda", "soft", "softphone", "software",
    "solar", "solaris", "sold", "soldier", "soldiers", "sole",
    "solicitor", "solid", "solution", "solutions", "solve", "solver",
    "some", "son", "song", "songs", "sonic", "sony", "soon", "soph",
    "sophisticated", "sore", "sort", "sorted", "sorting", "soul",
    "sound", "sounds", "source", "sources", "south", "southampton",
    "southeast", "southern", "southwest", "souvenir", "sovereign",
    "space", "spaces", "spam", "span", "spanish", "spare", "spares",
    "spark", "sparks", "spatial", "spawn", "speak", "speaker",
    "speakers", "speaking", "speaks", "special", "specialist",
    "specialists", "specialized", "specials", "specialties",
    "specialty", "species", "specific", "specifically", "specification",
    "specifications", "specified", "specify", "specs", "spectacular",
    "spectrum", "speech", "speed", "speeds", "spell", "spelling",
    "spend", "spending", "spent", "sphere", "spider", "spies", "spin",
    "spine", "spiral", "spirit", "spiritual", "spit", "splash",
    "splendid", "split", "spoke", "sponsor", "sponsored", "sponsors",
    "sponsorship", "spontaneous", "spoof", "spool", "spoon", "sport",
    "sporting", "sports", "spot", "spotlight", "spots", "spouse",
    "spray", "spread", "spreading", "spring", "springer", "springs",
    "sprint", "spy", "spyware", "sql", "squ", "square", "squat",
    "squid", "sr", "src", "sri", "ssl", "sslyze", "ssn", "ssp",
    "st", "stability", "stable", "stack", "staff", "stage", "stages",
    "staging", "stakeholder", "stakeholders", "stamp", "stamps",
    "stand", "standard", "standards", "standby", "standing",
    "standings", "standout", "star", "starbucks", "stark", "stars",
    "start", "started", "starter", "starting", "startup", "state",
    "stated", "statement", "statements", "states", "statewide",
    "static", "station", "stationery", "stations", "statistics",
    "status", "statutes", "stay", "staying", "std", "ste", "steady",
    "steal", "steam", "steel", "steep", "stellar", "stencil", "step",
    "steps", "stereo", "sterling", "steve", "steward", "stick",
    "sticker", "sticks", "sticky", "still", "stock", "stockholm",
    "stockings", "stocks", "stolen", "stone", "stones", "stood",
    "stop", "stopped", "stopping", "storage", "store", "stores",
    "stories", "storm", "story", "stoves", "stp", "straight",
    "strain", "strand", "strange", "stranger", "strap", "strategic",
    "strategies", "strategy", "stream", "streaming", "streams",
    "street", "streets", "strength", "strengthen", "stress",
    "stretch", "strict", "stride", "strike", "strikes", "striking",
    "string", "strings", "strip", "stripe", "stripes", "strokes",
    "strong", "stronger", "strongest", "structure", "structured",
    "structures", "struggle", "stuck", "student", "students", "studio",
    "studios", "study", "stuff", "stunning", "stupid", "style",
    "styles", "stylish", "stylus", "su", "sub", "subdomain",
    "subdomains", "subject", "subjects", "sublime", "submission",
    "submissions", "submit", "subnet", "subnets", "subordinate",
    "subpoena", "subscriber", "subscribers", "subscription",
    "subscriptions", "subsection", "subsequent", "subsidiary",
    "substance", "substitute", "substitution", "substrate",
    "subsystem", "subsystems", "subtract", "suburban", "subversion",
    "succeed", "success", "successful", "such", "suck", "sucks",
    "sudden", "sue", "suffer", "suffering", "sufficient", "suffix",
    "sugar", "suggest", "suggested", "suggestion", "suggestions",
    "suit", "suitable", "suite", "suites", "suits", "sullivan",
    "sum", "summary", "summer", "summit", "sun", "sunday", "sunglasses",
    "sunny", "sunrise", "sunset", "sunshine", "super", "superb",
    "superintendent", "superior", "supermarket", "superuser",
    "supervision", "supervisor", "supervisors", "supper", "supplier",
    "suppliers", "supplies", "supply", "support", "supported",
    "supporter", "supporters", "supporting", "supports",
    "suppose", "supposed", "suppress", "supra", "supreme", "sure",
    "surf", "surface", "surfaces", "surge", "surgeon", "surgery",
    "surname", "surplus", "surprise", "surprised", "surprising",
    "surreal", "surrey", "surround", "surroundings", "surveillance",
    "survey", "surveys", "survival", "survive", "survivor",
    "survivors", "suspect", "suspend", "suspense", "suspension",
    "sustained", "suzuki", "svn", "swap", "swapping", "swarm",
    "sway", "swe", "swear", "sweat", "sweater", "sweatshirt",
    "sweden", "swedish", "sweep", "sweeping", "sweet", "sweetheart",
    "swift", "swim", "swimming", "swing", "swinging", "swiss",
    "switch", "switched", "switches", "switching", "sword", "syllabus",
    "symantec", "symbol", "symbols", "symmetry", "sympathetic",
    "sympathy", "symposium", "symptom", "symptoms", "sync",
    "syncing", "syndicate", "syndication", "syndrome", "synergy",
    "synod", "synonym", "synonyms", "synopsis", "syntax",
    "synthesis", "synthetic", "sys", "sysadmin", "syslog",
    "system", "systematic", "systems",
    "t", "ta", "table", "tables", "tablet", "tablets", "tabs",
    "tack", "tackle", "tactical", "tactics", "tag", "tagged",
    "tagging", "tags", "tail", "tailor", "tailored", "take", "taken",
    "takeover", "tale", "talent", "talents", "talk", "talks", "tall",
    "tam", "tame", "tan", "tank", "tanks", "tap", "tape", "tapes",
    "target", "targets", "tariff", "tariffs", "task", "tasks", "taste",
    "tax", "taxes", "taxi", "tcp", "tea", "teach", "teacher",
    "teachers", "teaching", "team", "teams", "tear", "tears",
    "tech", "technical", "technician", "technique", "techniques",
    "techno", "technologies", "technology", "techsupport", "teen",
    "teens", "teeth", "tel", "telecom", "telecommunications",
    "telephone", "telephony", "telescope", "television", "tell",
    "temp", "template", "templates", "temple", "temporal",
    "temporary", "temptation", "tenant", "tenants", "tend", "tender",
    "tenders", "tennis", "tennis", "tension", "tent", "tenth",
    "tenure", "term", "terminal", "terminals", "terminate",
    "termination", "terminology", "terms", "terrace", "terrain",
    "terrible", "terrific", "territorial", "territory", "terror",
    "terrorism", "test", "testament", "tested", "tester", "testers",
    "testimonial", "testimonials", "testimony", "testing", "tests",
    "tetris", "texas", "text", "textbook", "textile", "textiles",
    "texts", "texture", "th", "thai", "thailand", "thank", "thanks",
    "thanksgiving", "that", "the", "theater", "theaters", "theatre",
    "theft", "themes", "theology", "theorem", "theories", "theory",
    "therapeutic", "therapist", "therapy", "there", "thermal",
    "thesaurus", "these", "thesis", "thick", "thickness", "thief",
    "thin", "thing", "things", "think", "thinking", "third", "thirty",
    "this", "thomas", "thorough", "those", "though", "thought",
    "thoughts", "thousand", "thread", "threads", "threat", "threats",
    "three", "thrill", "thriller", "thrive", "throat", "throne",
    "through", "throughout", "throw", "thrown", "thrust", "thu",
    "thumb", "thumbnail", "thumbnails", "thumbs", "thunder",
    "thursday", "thus", "ticket", "tickets", "tide", "tidy", "tie",
    "tied", "tier", "tiers", "tiger", "tight", "tile", "tiles",
    "till", "tim", "timber", "time", "timeline", "timely", "timer",
    "times", "timing", "timothy", "tin", "tiny", "tip", "tips",
    "tire", "tired", "tissue", "titan", "titanium", "titans",
    "title", "titles", "toast", "tobacco", "today", "toe", "together",
    "toilet", "token", "tokyo", "told", "tolerance", "toll",
    "tomato", "tomorrow", "tone", "toner", "tones", "tongue",
    "tonight", "tons", "tony", "tool", "toolbar", "toolbox",
    "toolkit", "tools", "tooth", "top", "topic", "topics", "topology",
    "tor", "torch", "torn", "toronto", "torpedo", "torque",
    "tort", "torture", "tos", "total", "totals", "touch",
    "touching", "tour", "tourism", "tourist", "tournament",
    "tournaments", "tours", "toward", "towards", "towel", "towels",
    "tower", "towers", "town", "towns", "toxic", "toy", "toys",
    "tr", "trace", "tracing", "track", "trackback", "tracker",
    "tracking", "tracks", "tract", "tractor", "tracy", "trade",
    "trademark", "trademarks", "trader", "trades", "tradition",
    "traditional", "traditions", "traffic", "tragedy", "trail",
    "trailer", "trailers", "trails", "train", "trained", "trainer",
    "trainers", "training", "trains", "trait", "traits", "tram",
    "trampoline", "tran", "trance", "tranquil", "trans",
    "transaction", "transactions", "transcript", "transcripts",
    "transfer", "transfers", "transform", "transformation",
    "transformed", "transformer", "transformers", "transit",
    "transition", "translate", "translation", "translations",
    "translator", "translators", "transmission", "transmit",
    "transmitted", "transmitter", "transparency", "transparent",
    "transport", "transportation", "transporter", "trap", "traps",
    "trash", "trauma", "travel", "traveler", "travelers", "traveling",
    "traveller", "travellers", "tray", "treasure", "treasurer",
    "treasures", "treasury", "treat", "treatment", "treatments",
    "treaty", "tree", "trees", "trek", "tremendous", "trend",
    "trends", "tri", "trial", "trials", "triangle", "tribal",
    "tribe", "tribes", "tribune", "tribute", "trick", "tricks",
    "tried", "trigger", "triggers", "trim", "trinidad", "trinity",
    "trio", "trip", "triple", "trips", "trivia", "trk", "troop",
    "troops", "trophy", "tropical", "trouble", "troubleshoot",
    "troubleshooting", "trout", "truck", "trucks", "true", "truly",
    "trunk", "trunks", "trust", "trusted", "trustee", "trustees",
    "trusts", "truth", "try", "trying", "ts", "tsunami", "tt",
    "tub", "tube", "tubes", "tuck", "tuesday", "tuition", "tune",
    "tunes", "tuning", "tunnel", "tunnels", "turbo", "turkey",
    "turkish", "turn", "turned", "turning", "turns", "turtle",
    "turtles", "tutor", "tutorial", "tutorials", "tv", "twelve",
    "twenty", "twice", "twiki", "twin", "twins", "twist", "twitter",
    "two", "txt", "ty", "tycoon", "tyler", "type", "types",
    "typical", "typing", "typo",
    "u", "ubuntu", "ufo", "ugly", "uk", "ultimate", "ultra",
    "um", "umbrella", "un", "una", "unable", "unanswered",
    "unavailable", "unbox", "unbreakable", "unc", "uncertain",
    "uncle", "uncommon", "unconscious", "uncover", "und",
    "under", "underground", "underline", "underlying", "undermine",
    "understand", "understanding", "underwater", "underwear",
    "undo", "unemployed", "unemployment", "uneven", "unfair",
    "unfold", "unfortunate", "unhappy", "unhide", "uni", "unified",
    "uniform", "union", "unique", "unit", "united", "units",
    "unity", "universal", "universe", "universities", "university",
    "unix", "unknown", "unless", "unlike", "unlikely", "unlimited",
    "unlock", "unlucky", "unnecessary", "uno", "unpaid", "unplugged",
    "unreal", "unrestricted", "unruly", "unsafe", "unsatisfied",
    "unsubscribe", "until", "unusual", "unveil", "unveiled", "unwanted",
    "unzip", "up", "update", "updated", "updates", "updating",
    "upgrade", "upgrades", "upgrading", "upload", "uploads",
    "upon", "upper", "ups", "upset", "upside", "upstairs", "uptime",
    "upward", "urban", "urge", "urgent", "uri", "url", "urn",
    "uruguay", "us", "usa", "usage", "usb", "usd", "use", "used",
    "useful", "useless", "user", "users", "using", "usual",
    "utility", "utilization", "utilize", "utmost", "utopia",
    "utter", "uv",
    "vacancies", "vacation", "vaccine", "vacuum", "vague", "valid",
    "validate", "validation", "validity", "valley", "valuable",
    "valuation", "value", "values", "valve", "valves", "vampire",
    "van", "vancouver", "vandal", "vanguard", "vanilla", "vapor",
    "variable", "variables", "variance", "variant", "variation",
    "variations", "varied", "varies", "varieties", "variety",
    "various", "vary", "varying", "vast", "vat", "vault", "vaults",
    "vb", "vbulletin", "vc", "vector", "vectors", "vegas", "vehicle",
    "vehicles", "veil", "velocity", "velvet", "vendor", "vendors",
    "venezuela", "venice", "venture", "ventures", "venue", "venues",
    "ver", "verbal", "verdict", "verification", "verified", "verify",
    "verifying", "verizon", "vermont", "vernacular", "verse",
    "version", "versions", "versus", "vertex", "vertical",
    "verticals", "very", "vessel", "vessels", "veteran", "veterans",
    "veterinary", "vetting", "via", "viable", "vial", "vibrant",
    "vibration", "vicar", "vice", "victim", "victims", "victor",
    "victoria", "victory", "video", "videos", "vienna", "view",
    "viewer", "viewers", "viewing", "views", "vigil", "vigorous",
    "viking", "vile", "villa", "village", "villages", "villain",
    "vine", "vintage", "vinyl", "viola", "violate", "violation",
    "violations", "violence", "violent", "violet", "violin",
    "viral", "virgin", "virginia", "virtual", "virtually",
    "virtue", "virus", "visa", "visibility", "visible", "vision",
    "visions", "visit", "visited", "visiting", "visitor",
    "visitors", "visits", "vista", "visual", "visualization",
    "visualize", "visually", "vital", "vitamin", "vitamins",
    "vivid", "vlan", "vocab", "vocal", "vocals", "vocation",
    "vocational", "voice", "voices", "void", "vol", "volatility",
    "volleyball", "volume", "volumes", "voluntary", "volunteer",
    "volunteers", "volvo", "voter", "voters", "voting", "voucher",
    "vouch", "vow", "vpn", "vs", "vulnerability", "vulnerable",
    "w", "wage", "wages", "wagon", "wait", "waiting", "waive",
    "waiver", "wake", "walk", "walker", "walking", "wall",
    "wallet", "walls", "wander", "want", "war", "ward",
    "wardrobe", "ware", "warehouse", "wares", "warfare", "warm",
    "warming", "warn", "warning", "warnings", "warrant",
    "warranty", "warrior", "warriors", "warsaw", "wash",
    "washing", "washington", "waste", "watch", "watcher",
    "watchers", "watches", "watching", "water", "watermark",
    "waters", "waterproof", "watershed", "wave", "waves", "wax",
    "way", "ways", "weak", "weakness", "wealth", "wealthy",
    "weapon", "weapons", "wear", "wearing", "weather", "web",
    "webapp", "webcache", "webcam", "webcams", "webcast",
    "weber", "webfonts", "webhooks", "webmail", "webmaster",
    "webmasters", "webmin", "webpage", "webservice",
    "webservices", "website", "websites", "websphere",
    "webstore", "webtools", "webuser", "webview", "webx",
    "wedding", "weddings", "wedge", "wednesday", "weed",
    "week", "weekend", "weekly", "weeks", "weight", "weights",
    "weird", "welcome", "weld", "welding", "welfare", "well",
    "wellness", "wells", "welsh", "west", "western", "wet",
    "whale", "whales", "wharf", "what", "wheat", "wheel",
    "wheels", "when", "where", "whether", "which", "while",
    "whilst", "white", "whitehouse", "whole", "wholesale",
    "whom", "whose", "why", "wide", "widen", "wider", "widest",
    "widespread", "width", "wife", "wiki", "wikis", "wild",
    "wilderness", "wildlife", "will", "willing", "willow",
    "win", "wind", "window", "windows", "winds", "windshield",
    "wine", "wines", "wing", "wings", "winner", "winners",
    "winning", "winter", "wire", "wired", "wireless", "wires",
    "wisconsin", "wisdom", "wise", "wish", "wit", "witch",
    "with", "withdraw", "withdrawal", "within", "without",
    "witness", "witnesses", "wives", "wizard", "wolf", "wolves",
    "woman", "women", "won", "wonder", "wonderful", "wonders",
    "wood", "wooden", "woods", "wool", "word", "wordpress",
    "words", "work", "worker", "workers", "workflow",
    "workflows", "workforce", "working", "workload",
    "workplace", "works", "workshop", "workshops", "workstation",
    "workstations", "world", "worlds", "worldwide", "worm",
    "worried", "worry", "worse", "worship", "worst", "worth",
    "worthy", "would", "wound", "wow", "wrap", "wrapper",
    "wrapping", "wreath", "wrestling", "wright", "wrist",
    "write", "writer", "writers", "writes", "writing",
    "writings", "written", "wrong", "wrote", "wtf",
    "x", "xml", "xmp", "xn--", "xpath", "xquery", "xss",
    "xssed", "xxxx", "xyl",
    "y", "yacht", "yahoo", "yard", "yards", "yarn",
    "yeah", "year", "yearly", "years", "yeast", "yell",
    "yellow", "yep", "yes", "yesterday", "yet", "yield",
    "yields", "yoga", "york", "young", "younger", "your",
    "yours", "yourself", "youth", "yr", "yrs",
    "z", "zambia", "zebra", "zero", "zigbee",
    "zimbabwe", "zip", "zones", "zoo", "zoom", "zoology",
]


# ── Wildcard detection ──────────────────────────────────────────────────

def _detect_wildcard(domain: str, samples: int = 3) -> set[str]:
    """Detect wildcard DNS by resolving random subdomains."""
    wildcard_ips: set[str] = set()
    resolved_count = 0

    for _ in range(samples):
        rand = ''.join(secrets.choice(string.ascii_lowercase) for _ in range(10))
        fqdn = f"{rand}.{domain}"
        try:
            answer = dns.resolver.resolve(fqdn, "A", lifetime=3)
            resolved_count += 1
            for rr in answer:
                wildcard_ips.add(str(rr))
        except Exception:
            pass

    if resolved_count < samples:
        return set()
    return wildcard_ips


# ── Brute-force helpers ─────────────────────────────────────────────────

def _resolve_subdomain(domain: str, prefix: str,
                       wildcard_ips: set[str] | None = None) -> str | None:
    """Try to resolve <prefix>.<domain>. Returns FQDN or None if wildcard."""
    enforce_dns_rate_limit(batch_size=10)  # Anti-block: delay per 10 DNS lookups
    fqdn = f"{prefix}.{domain}"

    try:
        answer = dns.resolver.resolve(fqdn, "A", lifetime=_DNS_TIMEOUT)
        ip = str(answer[0])
        if wildcard_ips and ip in wildcard_ips:
            return None
        return fqdn
    except Exception:
        pass

    try:
        answer = dns.resolver.resolve(fqdn, "AAAA", lifetime=_DNS_TIMEOUT)
        ip = str(answer[0])
        if wildcard_ips and ip in wildcard_ips:
            return None
        return fqdn
    except Exception:
        pass

    try:
        dns.resolver.resolve(fqdn, "CNAME", lifetime=_DNS_TIMEOUT)
        return fqdn
    except Exception:
        pass

    return None


def _brute_subdomains(domain: str, count: int,
                      wildcard_ips: set[str] | None = None) -> list[str]:
    """Brute-force subdomains using the common wordlist."""
    # Map 100/500/1000 to actual wordlist sizes
    size_map = {100: 500, 500: 2000, 1000: len(COMMON_SUBDOMAINS)}
    limit = size_map.get(count, min(count, len(COMMON_SUBDOMAINS)))

    candidates = COMMON_SUBDOMAINS[:limit]
    found = []
    for prefix in candidates:
        result = _resolve_subdomain(domain, prefix, wildcard_ips)
        if result:
            found.append(result)

    return sorted(found)


# ── Public API ──────────────────────────────────────────────────────────

def run_subdomains(domain: str, brute_count: int = 0) -> dict:
    """Enumerate subdomains via passive sources + optional brute-force.

    Parameters
    ----------
    domain : str
        Target domain.
    brute_count : int
        Number of subdomain prefixes to brute-force (100/500/1000).

    Returns
    -------
    dict with keys: subdomains, source, count, wildcard_detected, wildcard_ips
    """
    # Normalise
    domain = domain.lower().strip()
    domain = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", domain)
    domain = domain.split("/")[0].split(":")[0].strip(".")

    if not domain:
        return {"subdomains": [], "source": "", "count": 0}

    # ── Passive phase: gather from multiple sources ──────────────
    passive_results: set[str] = set()
    sources_used: list[str] = []

    def _merge(source_name: str, func):
        """Helper to fetch from a source and merge results."""
        try:
            results = func(domain)
            if results:
                passive_results.update(results)
                sources_used.append(source_name)
        except Exception:
            pass  # source failed — skip gracefully

    # Run all passive sources (order by reliability)
    _merge("crt.sh", lambda d: _parse_name_values(_fetch_crtsh(d), d))
    _merge("alienvault", _fetch_alienvault)
    _merge("bufferover", _fetch_bufferover)
    _merge("rapiddns", _fetch_rapiddns)
    _merge("urlscan", _fetch_urlscan)
    _merge("riddler", _fetch_riddler)

    # Subfinder (external binary, 30+ sources)
    sf_results = _fetch_subfinder(domain)
    if sf_results:
        passive_results.update(sf_results)
        sources_used.append("subfinder")

    source_label = "+".join(sources_used) if sources_used else "none"

    # ── Active phase: brute-force ────────────────────────────────
    wildcard_ips: set[str] = set()

    if brute_count > 0:
        wildcard_ips = _detect_wildcard(domain)
        brute_results = _brute_subdomains(domain, brute_count, wildcard_ips)

        for fqdn in brute_results:
            passive_results.add(fqdn)

        source_label += "+brute" if sources_used else "brute"

    subdomains = sorted(passive_results)

    return {
        "subdomains": subdomains,
        "source": source_label,
        "count": len(subdomains),
        "wildcard_detected": len(wildcard_ips) > 0,
        "wildcard_ips": sorted(wildcard_ips) if wildcard_ips else [],
    }
