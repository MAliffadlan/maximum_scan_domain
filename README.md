# 🔍 Domain Probe v2.0

**CLI Domain Intelligence Tool** — masukin domain, keluar laporan selengkap-lengkapnya.

```
probe example.com --full
```

![](https://img.shields.io/badge/version-2.0.0-blue) ![](https://img.shields.io/badge/python-3.12+-green) ![](https://img.shields.io/badge/modules-14-orange) ![](https://img.shields.io/badge/license-MIT-lightgrey)

---

## ⚡ Quick Start

```bash
# Install dependencies
pip install python-whois dnspython requests rich cryptography

# Clone & setup
cd domain-probe
chmod +x domain_probe.py
ln -sf $(pwd)/domain_probe.py ~/.local/bin/probe

# Gas
probe example.com
probe example.com --full
```

---

## 🚀 Usage

```bash
probe <domain> [options]
```

### Scan Levels

| Command | Modules | Subdomain | Ports | Est. Time |
|---------|---------|-----------|-------|-----------|
| `probe domain.com` | 8 basic | passive | socket | ~5s |
| `probe domain.com --deep` | 14 all | passive | nmap | ~15s |
| `probe domain.com --full` | 14 all | **500 brute** | nmap | ~30-60s |

### Options

| Flag | Description |
|------|-------------|
| `--full` | Maximum: all modules + 500 subdomains |
| `--deep` | Deep scan: all 14 modules |
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

## 📦 Modules

### Basic (always run)

| Module | Source | What It Does |
|--------|--------|--------------|
| **WHOIS** | `whois.py` | Domain ownership, registrar, dates (WHOIS + RDAP + registrar query) |
| **DNS** | `dns.py` | All record types (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, SRV) + AXFR attempt |
| **SSL/TLS** | `ssl.py` | Certificate chain, validity, SANs, cipher, fingerprint |
| **HTTP** | `http.py` | Headers, security headers, cookies, tech stack, CORS, JS dependencies |
| **GeoIP** | `geoip.py` | IP geolocation via ip-api.com (country, city, ISP, ASN, coordinates) |
| **Ports** | `ports.py` | TCP scan (socket fast / nmap deep) |
| **Subdomains** | `subdomains.py` | Passive (crt.sh) + DNS brute force |
| **SEO** | `seo.py` | robots.txt, sitemap.xml, meta tags, Open Graph, Twitter cards |

### Deep (`--deep` / `--full`)

| Module | Source | What It Does |
|--------|--------|--------------|
| **Email Security** | `email_sec.py` | SPF, DKIM, DMARC, BIMI validation |
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

── Security Headers ──────────────────────────────────
  ✅ strict-transport-security
  ✅ x-frame-options
  ❌ content-security-policy
  ...

── Cookie Audit ──────────────────────────────────────
  Total: 5 | Secure: 3 | HttpOnly: 2 | SameSite: 3 lax

── Exposed Paths ─────────────────────────────────────
  Total Checked: 76 | 🔴 Critical: 0 | 🟠 High: 0

── External Intelligence (Shodan) ────────────────────
  Ports: 22, 80, 443, 9418
  Tags: cloud, git

✔ Probe complete — 15.73s
```

---

## 📁 Project Structure

```
domain-probe/
├── domain_probe.py          # Main CLI entry point
├── modules/
│   ├── output.py            # Rich formatting + JSON export
│   ├── whois.py             # WHOIS + RDAP lookup
│   ├── dns.py               # DNS records + AXFR
│   ├── ssl.py               # SSL/TLS certificate analysis
│   ├── http.py              # HTTP + security headers + CORS + JS
│   ├── geoip.py             # IP geolocation
│   ├── ports.py             # TCP port scanner
│   ├── subdomains.py        # Subdomain enumeration
│   ├── seo.py               # robots.txt, sitemap, meta tags
│   ├── email_sec.py         # SPF, DKIM, DMARC, BIMI
│   ├── wayback.py           # Wayback Machine CDX API
│   ├── related.py           # Reverse IP / related domains
│   ├── exposed.py           # Sensitive path scanner
│   └── shodan.py            # Shodan InternetDB
├── requirements.txt
└── README.md
```

---

## 🔧 Dependencies

```
python-whois>=0.9      # WHOIS lookups
dnspython>=2.7          # DNS resolution
requests>=2.31          # HTTP client
rich>=13.0              # Terminal formatting
cryptography>=42.0      # SSL cert parsing
```

Install: `pip install -r requirements.txt`

External tools (optional):
- `nmap` — for deep port scan with service version detection
- `dig` — DNS fallback (built-in dnspython is primary)

---

## 🛠️ Architecture

```
Input domain
  ├── Resolve DNS → IP
  ├── [ThreadPoolExecutor — 12 workers parallel]
  │   ├── WHOIS + RDAP + registrar query
  │   ├── DNS all records + AXFR attempt
  │   ├── SSL handshake + cert parsing
  │   ├── HTTP probe + security + CORS + JS + cookies
  │   ├── GeoIP lookup
  │   ├── Port scan (socket or nmap)
  │   ├── Subdomain enumeration (crt.sh + brute)
  │   ├── SEO (robots, sitemap, meta, OG)
  │   ├── [deep] Email security (SPF/DKIM/DMARC)
  │   ├── [deep] Wayback CDX API
  │   ├── [deep] Reverse IP lookup
  │   ├── [deep] Exposed paths scan (76 paths)
  │   └── [deep] Shodan InternetDB
  └── Aggregate → Rich output / JSON export
```

---

## 📝 Notes

- **WHOIS Privacy**: Most domains post-GDPR have redacted owner names. The tool makes 3 attempts (python-whois → registrar WHOIS → RDAP) but personal names often remain hidden.
- **Rate Limiting**: Wayback Machine and Shodan InternetDB may rate-limit. Errors are handled gracefully.
- **Port Scan**: Default scans top ~50 ports via socket. `--deep`/`--full` uses nmap `-sV -F` for service version detection.
- **Subdomain Brute**: DNS-based, not exhaustive. Use `-s 1000` for maximum coverage.

---

## 📄 License

MIT — Mectov, 2026
