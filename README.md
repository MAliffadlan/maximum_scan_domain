# 🔍 Domain Probe v2.1

**CLI Domain Intelligence Tool** — masukin domain, keluar laporan selengkap-lengkapnya.

```
probe example.com --full
```

![](https://img.shields.io/badge/version-2.1.0-blue) ![](https://img.shields.io/badge/python-3.12+-green) ![](https://img.shields.io/badge/modules-16-orange) ![](https://img.shields.io/badge/signatures-4000+-brightgreen) ![](https://img.shields.io/badge/license-MIT-lightgrey)

---

## ⚡ Quick Start

```bash
# 1. Install Python dependencies
pip install python-whois dnspython requests rich cryptography

# 2. Clone & setup
cd maximum_scan_domain
chmod +x domain_probe.py
ln -sf $(pwd)/domain_probe.py ~/.local/bin/probe

# 3. (Opsional) Install webanalyze untuk Wappalyzer 4000+ deteksi
#    Download dari: https://github.com/rverton/webanalyze/releases
#    Taruh binary di ~/.local/bin/webanalyze
#    Download apps.json di ~/.local/bin/technologies.json

# 4. Gas
probe example.com
probe example.com --full
```

---

## 🚀 Usage

```bash
probe <domain> [options]
```

### Scan Levels

| Command | Modules | Subdomain | Ports | Tech Detect | Est. Time |
|---------|---------|-----------|-------|-------------|-----------|
| `probe domain.com` | 8 basic | passive | socket | ✅ 45 sig | ~5s |
| `probe domain.com --deep` | 16 all | passive | nmap | ✅ 4000+ apps | ~15s |
| `probe domain.com --full` | 16 all | **500 brute** | nmap | ✅ 4000+ apps | ~30-60s |

### Options

| Flag | Description |
|------|-------------|
| `--full` | Maximum: all modules + 500 subdomains + nmap |
| `--deep` | Deep scan: all 16 modules |
| `-o FILE` | Export JSON report |
| `-s N` | Brute-force N subdomains (100/500/1000) |
| `-q` | Quiet mode (JSON only) |
| `--timeout SEC` | Override timeout (default: 120s) |
| `--no-color` | Plain text output |

### Examples

```bash
probe github.com                        # Standard
probe github.com --full                 # MAXIMUM
probe github.com --deep -o gh.json     # Deep + export
probe target.com --full -o report.json & # Background
probe target.com -s 1000               # Custom subdomain count
```

---

## ✨ New in v2.1

### 🧬 Tech Stack Detection (Signature-based)
Deteksi otomatis CMS, framework, CDN, analytics, dan teknologi web pake **45 signature patterns** — cocokin dari URL, header, cookie, meta tag, HTML, dan body.

**Contoh output:**
```
┌─ Detected Technologies (Signature) ────────────────────┐
│ Category       │ Technology        │ Version │ Conf    │
├────────────────┼───────────────────┼─────────┼─────────┤
│ Web Server     │ Apache HTTP Server│ —       │ certain │
│ CMS            │ WordPress         │ 6.2     │ certain │
│ CDN            │ Cloudflare        │ —       │ certain │
│ JS Library     │ jQuery            │ 3.5.1   │ certain │
│ CSS Framework  │ Bootstrap         │ 5.3.0   │ certain │
│ Framework      │ Laravel           │ —       │ likely  │
└────────────────┴───────────────────┴─────────┴─────────┘
```

Teknologi yang terdeteksi:
- **CMS**: WordPress, Drupal, Joomla, Magento, Shopify, Ghost
- **Framework**: Laravel, Django, Rails, ASP.NET, Next.js, Nuxt.js, Vue, React, Angular, Express.js
- **Web Server**: Apache, Nginx, IIS, LiteSpeed, Caddy, Tomcat, AWS ELB
- **CDN/WAF**: Cloudflare, CloudFront, Akamai, Fastly, Sucuri, Imperva, Varnish
- **Analytics**: Google Analytics, Meta Pixel, Hotjar, HubSpot, Yandex, Matomo
- **JS Library**: jQuery, Bootstrap, Alpine.js, HTMX, Three.js, Lodash, Font Awesome
- **Lainnya**: PHP, Python, WooCommerce, reCAPTCHA, Stripe, PayPal, Google Fonts, cPanel

### ⚡ Wappalyzer Integration (4000+ apps)
Integrasi pake **webanalyze** — Go binary yang pake database open-source Wappalyzer dengan **3965+ app fingerprints**. Otomatis jalan kalau binary terinstall.

```
┌─ Detected Technologies (Wappalyzer — 3965 apps) ──────┐
│ Category       │ Technology        │ Version           │
├────────────────┼───────────────────┼───────────────────┤
│ CDN            │ Cloudflare        │ —                 │
│ E-commerce     │ WooCommerce       │ 8.3               │
│ JavaScript     │ jQuery            │ 3.5.1             │
│ SEO            │ Yoast SEO         │ 21.2              │
│ Analytics      │ Google Analytics  │ UA-12345678-1     │
└────────────────┴───────────────────┴───────────────────┘
```

### 🌐 DNS Wildcard Detection
Sebelum brute-force subdomain, tool ngecek wildcard DNS secara otomatis:

1. Generate **3 random subdomain** (contoh: `aksjdflkj234sdf.example.com`)
2. Coba resolve — kalau **semua** resolve → wildcard DNS aktif
3. Catat IP wildcard-nya, lalu **filter otomatis** false positive waktu brute-force
4. Tampilkan peringatan: `⚠ Wildcard DNS: 103.x.x.x`

Ini nge-prevent hasil kaya gini: ❌ `mail.example.com` (sebenarnya `aksjdflkj234sdf.example.com` juga resolve, semuanya palsu).

---

## 📦 Modules

### Basic (always run)

| Module | Source | What It Does |
|--------|--------|--------------|
| **WHOIS** | `whois.py` | Domain ownership, registrar, dates (WHOIS + RDAP + registrar query) |
| **DNS** | `dns.py` | All record types (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, SRV) + AXFR attempt |
| **SSL/TLS** | `ssl.py` | Certificate chain, validity, SANs, cipher, fingerprint |
| **HTTP** | `http.py` | Headers, security headers, cookies, tech stack, CORS, JS dependencies |
| **Tech Detection** ✨ | `tech_detect.py` | 45 signature-based technology detection (CMS, framework, CDN, etc.) |
| **Wappalyzer** ✨ | `wappalyzer.py` | 3965+ app fingerprints via webanalyze binary |
| **GeoIP** | `geoip.py` | IP geolocation via ip-api.com (country, city, ISP, ASN, coordinates) |
| **Ports** | `ports.py` | TCP scan (socket fast / nmap deep) |
| **Subdomains** | `subdomains.py` | Passive (crt.sh) + DNS brute force + **wildcard detection** ✨ |
| **SEO** | `seo.py` | robots.txt, sitemap.xml, meta tags |

### Deep (`--deep` / `--full`)

| Module | Source | What It Does |
|--------|--------|--------------|
| **Email Security** | `email_sec.py` | SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT validation |
| **Wayback Machine** | `wayback.py` | Historical snapshots from archive.org |
| **Related Domains** | `related.py` | Reverse IP — find all domains on same IP |
| **Exposed Paths** | `exposed.py` | 76 sensitive paths (`.git`, `.env`, `/wp-admin`, etc.) |
| **External Intel** | `shodan.py` | Shodan InternetDB — ports, CVEs, CPEs, tags |

### Built-in to HTTP (`--deep`)
- **CORS Analysis** — permissive origin, dangerous configurations
- **Cookie Audit** — secure, HttpOnly, SameSite, session, third-party
- **JS Dependency Scan** — detect frameworks (React, Vue, jQuery, etc.)

---

## 📊 Sample Output

```
╭─ Domain Probe ───────────────────────────────────────╮
│ Target: github.com                                   │
╰──────────────────────────────────────────────────────╯

── Network Summary ────────────────────────────────────
  Primary IP    20.205.243.166
  Mode           DEEP
  Elapsed        15.73s

── Domain Owner (Registrant) ──────────────────────────
  Name           —
  Organization   GitHub, Inc.
  Email          abusecomplaints@markmonitor.com
  Country        US
  Registrar      MarkMonitor, Inc.
  Created        2007-10-09

── Email Security (SPF/DKIM/DMARC) ────────────────────
  SPF    ✅ v=spf1 include:_spf.google.com -all
  DMARC  🟢 reject (sub: reject)
  DKIM   ✅ 3 selectors (google, mail, default)

── SSL/TLS Certificate ────────────────────────────────
  TLS 1.3, valid 69 days, Cloudflare ECC CA
  SANs: github.com, *.github.com

── Tech Stack (Signature) ─────────────────────────────
  CDN       Cloudflare       —           certain
  Web Srv   Apache           —           certain
  Analytics Google Analytics UA-1234567  certain
  JS Lib    jQuery           3.5.1       certain

── Tech Stack (Wappalyzer — 3965 apps) ───────────────
  CDN       Cloudflare       —
  PaaS      GitHub Pages     —
  DNS       DNS over HTTPS   —

── Security Headers ──────────────────────────────────
  ✅ strict-transport-security
  ✅ x-frame-options
  ❌ content-security-policy
  ...

── Cookie Audit ──────────────────────────────────────
  Total: 5 | Secure: 3 | HttpOnly: 2 | SameSite: 3 lax

── Exposed Paths ─────────────────────────────────────
  Total Checked: 76 | 🔴 Critical: 0 | 🟠 High: 0

── Subdomains ────────────────────────────────────────
  Count: 42 | Source: crt.sh+brute
  ⚠ Wildcard DNS: 103.16.198.251  (filtered)

── External Intelligence (Shodan) ────────────────────
  Ports: 22, 80, 443, 9418
  Tags: cloud, git

✔ Probe complete — 15.73s
```

---

## 📁 Project Structure

```
domain-probe/
├── domain_probe.py              # Main CLI entry point
├── modules/
│   ├── output.py                # Rich formatting + JSON export
│   ├── whois.py                 # WHOIS + RDAP lookup
│   ├── dns.py                   # DNS records + AXFR
│   ├── ssl.py                   # SSL/TLS certificate analysis
│   ├── http.py                  # HTTP + security headers + CORS + JS
│   ├── tech_detect.py           # ✨ Signature-based tech detection (45 sig)
│   ├── wappalyzer.py            # ✨ Wappalyzer engine (4000+ apps)
│   ├── geoip.py                 # IP geolocation
│   ├── ports.py                 # TCP port scanner
│   ├── subdomains.py            # Subdomain + wildcard detection
│   ├── seo.py                   # robots.txt, sitemap, meta tags
│   ├── email_sec.py             # SPF, DKIM, DMARC, BIMI
│   ├── wayback.py               # Wayback Machine CDX API
│   ├── related.py               # Reverse IP / related domains
│   ├── exposed.py               # Sensitive path scanner
│   └── shodan.py                # Shodan InternetDB
├── requirements.txt
└── README.md
```

---

## 🔧 Dependencies

### Python packages
```
python-whois>=0.9      # WHOIS lookups
dnspython>=2.7          # DNS resolution
requests>=2.31          # HTTP client
rich>=13.0              # Terminal formatting
cryptography>=42.0      # SSL cert parsing
```

Install: `pip install -r requirements.txt`

### External tools (optional)
| Tool | Purpose | Install |
|------|---------|---------|
| `nmap` | Deep port scan with service versions | `sudo apt install nmap` |
| `webanalyze` | ✨ Wappalyzer 4000+ app detection | Download dari [GitHub releases](https://github.com/rverton/webanalyze/releases), taruh di `~/.local/bin/` |

---

## 🛠️ Architecture

```
Input domain
  ├── Resolve DNS → IP
  │   └── Wildcard detection (3 random subdomains)
  ├── [ThreadPoolExecutor — 12 workers parallel]
  │   ├── WHOIS + RDAP + registrar query
  │   ├── DNS all records + AXFR attempt
  │   ├── SSL handshake + cert parsing
  │   ├── HTTP probe
  │   │   ├── Security headers + CORS + cookies
  │   │   ├── Tech Detection (45 signature patterns) ✨
  │   │   └── Wappalyzer (4000+ apps via webanalyze) ✨
  │   ├── GeoIP lookup
  │   ├── Port scan (socket or nmap)
  │   ├── Subdomain enumeration (crt.sh + brute + wildcard filter)
  │   ├── SEO (robots, sitemap, meta, OG)
  │   ├── [deep] Email security (SPF/DKIM/DMARC/BIMI/MTA-STS)
  │   ├── [deep] Wayback CDX API
  │   ├── [deep] Reverse IP lookup
  │   ├── [deep] Exposed paths scan (76 paths)
  │   └── [deep] Shodan InternetDB
  └── Aggregate → Rich output / JSON export
```

---

## 📝 Notes

- **WHOIS Privacy**: Most domains post-GDPR have redacted owner names. The tool makes 3 attempts (python-whois → registrar WHOIS → RDAP) but personal names often remain hidden.
- **Tech Detection**: Signature-based detection ± Wappalyzer saling melengkapi. Signature lebih akurat buat CMS dan server; Wappalyzer lebih luas coverage.
- **Wildcard DNS**: Brute-force subdomain otomatis filter false positive dari wildcard. Ditandai ⚠ di output.
- **Rate Limiting**: Wayback Machine and Shodan InternetDB may rate-limit. Errors are handled gracefully.
- **Port Scan**: Default scans top ~50 ports via socket. `--deep`/`--full` uses nmap `-sV -F` for service version detection.
- **Subdomain Brute**: DNS-based, not exhaustive. Use `-s 1000` for maximum coverage.

---

## 📄 License

MIT — MAliffadlan, 2026
