# 🔍 Domain Probe v2.2

**CLI Domain Intelligence Tool** — masukin domain, keluar laporan selengkap-lengkapnya.

```
probe example.com --full
```

![](https://img.shields.io/badge/version-2.2.0-blue) ![](https://img.shields.io/badge/python-3.12+-green) ![](https://img.shields.io/badge/modules-17-orange) ![](https://img.shields.io/badge/signatures-4000+-brightgreen) ![](https://img.shields.io/badge/license-MIT-lightgrey)

---

## ⚡ Quick Start

```bash
# 1. Install Python dependencies
pip install python-whois dnspython requests rich cryptography

# 2. Clone & setup
cd maximum_scan_domain
chmod +x domain_probe.py
ln -sf $(pwd)/domain_probe.py ~/.local/bin/probe

# 3. (Opsional) Install tool tambahan
bash install-nuclei.sh                    # Nuclei vulnerability scanner
# atau manual:
#   webanalyze → ~/.local/bin/           # Wappalyzer 4000+ apps
#   subfinder  → ~/.local/bin/           # Subdomain 30+ sources

# 4. Gas
probe example.com
probe example.com --full                  # Semua fitur + anti-WAF otomatis
probe example.com --full --nuclei         # + Vulnerability scan pake Nuclei
```

---

## 🚀 Usage

```bash
probe <domain> [options]
```

### Scan Levels

| Command | Modules | Subdomain | Ports | Tech Detect | Waktu |
|---------|---------|-----------|-------|-------------|-------|
| `probe domain.com` | 8 basic | passive | socket | ✅ 45 sig | ~5s |
| `probe domain.com --deep` | 16 all | passive | nmap | ✅ 4000+ apps | ~15s |
| `probe domain.com --full` | 16 all | **500 brute** | nmap | ✅ 4000+ apps | **~40-60s** 🚀 |

### Options

| Flag | Description |
|------|-------------|
| `--full` | Maximum: all modules + 500 subdomains + **anti-WAF otomatis** |
| `--deep` | Deep scan: all 16 modules |
| `-o FILE` | Export JSON report |
| `-s N` | Brute-force N subdomains (100/500/1000) |
| `-q` | Quiet mode (JSON only) |
| `--timeout SEC` | Override timeout (default: 120s) |
| `--no-color` | Plain text output |

**Anti-Block:**

| Flag | Description |
|------|-------------|
| `--proxy URL` | Proxy semua request (http/socks) |
| `--proxy-list FILE` | Rotasi proxy dari file (auto round-robin) |
| `--delay MS` | Delay antar request dalam ms (`--full` default: 100ms) |
| `--random-agent` | Random User-Agent tiap request |

**Ekstra:**

| Flag | Description |
|------|-------------|
| `--nuclei` | Jalankan Nuclei vulnerability scanner (7000+ template) |
| `-v` | Versi |

### Examples

```bash
probe github.com                        # Standard
probe github.com --full                 # MAXIMUM + anti-WAF otomatis
probe github.com --full --nuclei        # MAXIMUM + vuln scan
probe target.com --full -o report.json  # Export JSON
probe target.com -s 1000                # Custom subdomain count

# Anti-WAF mode berat
probe target.com --full \
  --proxy-list ~/proxies.txt \
  --delay 500 \
  --random-agent

# Proxy SOCKS (Tor)
probe target.com --full --proxy socks5://127.0.0.1:9050
```

---

## ✨ Fitur

### 🧬 Tech Stack Detection (Signature-based)
Deteksi otomatis CMS, framework, CDN, analytics dari **45 signature patterns**.

```
┌─ Detected Technologies (Signature) ────────────────────┐
│ Category       │ Technology        │ Version │ Conf    │
├────────────────┼───────────────────┼─────────┼─────────┤
│ Web Server     │ Apache HTTP Server│ —       │ certain │
│ CMS            │ WordPress         │ 6.2     │ certain │
│ JS Library     │ jQuery            │ 3.5.1   │ certain │
└────────────────┴───────────────────┴─────────┴─────────┘
```

### ⚡ Wappalyzer Integration (4000+ apps)
Integrasi **webanalyze** dengan database **3965+ app fingerprints**.

```
┌─ Detected Technologies (Wappalyzer — 3965 apps) ──────┐
│ Category       │ Technology        │ Version           │
├────────────────┼───────────────────┼───────────────────┤
│ CDN            │ Cloudflare        │ —                 │
│ E-commerce     │ WooCommerce       │ 8.3               │
└────────────────┴───────────────────┴───────────────────┘
```

### 🌐 Subdomain Enumeration Multi-Source
Nemuin subdomain dari **6+ passive sources + brute-force**:

- crt.sh, AlienVault OTX, BufferOver, Rapiddns, Riddler, URLScan
- Subfinder (30+ sources, optional binary)
- DNS brute-force 2000+ wordlist dengan **wildcard filter**
- **Batch delay** anti rate-limit (20 query/batch, 300ms pause)

### 🛡️ Anti-Block System
Lindungi IP lo dari WAF/firewall:

- **Rate limiting** — delay antar request (configurable)
- **Random User-Agent** — 30+ real browser strings
- **Proxy rotation** — single proxy atau rotasi dari file
- **DNS batch delay** — delay per 20 lookup, bukan per-request
- Otomatis aktif pas `--full` (delay 100ms + random UA)

### 🔬 Nuclei Vulnerability Scanner Integration
Jalankan **7000+ template** Nuclei setelah scan selesai:

```bash
probe target.com --full --nuclei
```

Output:
```
── Nuclei Vulnerability Scan ──────────────────────────
  Scanning 12 subdomains (tags: wordpress, nginx, php)...

  🔴 [  CRITICAL] WordPress Path Traversal
       https://www.target.com/wp-content/...
       Template: wordpress-path-traversal

  Total: 3 findings (🔴 critical: 1, 🟠 high: 2)
```

Teknologi yang terdeteksi otomatis dipake buat filter template — **cuma jalanin template yang relevan**, bukan semua 7000.

### ⏳ Loading Spinner
Animasi spinner实时 nunjukin progress + elapsed time:

```
⣾ Modules scanning... (12s)
⣽ Nuclei scanning... (8s)
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
| **Tech Detection** ✨ | `tech_detect.py` | 45 signature-based technology detection |
| **Wappalyzer** ✨ | `wappalyzer.py` | 3965+ app fingerprints via webanalyze binary |
| **GeoIP** | `geoip.py` | IP geolocation (country, city, ISP, ASN, coordinates) |
| **Ports** | `ports.py` | TCP scan (socket fast / nmap deep) |
| **Subdomains** | `subdomains.py` | Passive (6 sources) + DNS brute-force + wildcard filter |
| **SEO** | `seo.py` | robots.txt, sitemap.xml, meta tags |
| **Session** ✨ | `session.py` | Proxy rotation, rate limiting, random UA |

### Deep (`--deep` / `--full`)

| Module | Source | What It Does |
|--------|--------|--------------|
| **Email Security** | `email_sec.py` | SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT |
| **Wayback Machine** | `wayback.py` | Historical snapshots from archive.org |
| **Related Domains** | `related.py` | Reverse IP — find all domains on same IP |
| **Exposed Paths** | `exposed.py` | 76 sensitive paths (`.git`, `.env`, `/wp-admin`, etc.) |
| **External Intel** | `shodan.py` | Shodan InternetDB — ports, CVEs, CPEs, tags |
| **Nuclei** ✨ | `nuclei.py` | 7000+ vuln template scanner (opsional binary) |

### Built-in to HTTP
- **CORS Analysis** — permissive origin, dangerous configurations
- **Cookie Audit** — secure, HttpOnly, SameSite, session, third-party
- **JS Dependency Scan** — detect frameworks (React, Vue, jQuery, etc.)

---

## 📊 Sample Output

```
╭─ Domain Probe ───────────────────────────────────────╮
│ Target: github.com                                   │
╰──────────────────────────────────────────────────────╯

── Probing... (MAXIMUM SCAN — All modules + 500 subdomains)
  Running WHOIS, DNS, SSL, HTTP, GeoIP, Ports...

⣾ Modules scanning... (12s)
⣽ Modules scanning... (24s)

── Network Summary ────────────────────────────────────
  Primary IP    20.205.243.166
  Mode           DEEP
  Elapsed        40s

── Subdomain Enumeration ──────────────────────────────
  Count: 42 | Source: crt.sh+alienvault+bufferover+brute
  ⚠ Wildcard DNS: 103.16.198.251 (filtered)

── Tech Stack (Signature) ─────────────────────────────
  CDN       Cloudflare       —           certain
  Web Srv   Apache           —           certain
  JS Lib    jQuery           3.5.1       certain

── Tech Stack (Wappalyzer — 3965 apps) ───────────────
  CDN       Cloudflare       —
  PaaS      GitHub Pages     —

── Exposed Paths ─────────────────────────────────────
  Total Checked: 76 | 🔴 Critical: 0 | 🟠 High: 0

── Nuclei Vulnerability Scan ─────────────────────────
  Scanning 12 subdomains (tags: nginx, cloudflare)...
⣾ Nuclei scanning... (15s)
  ✅ No vulnerabilities found

── Security Headers ──────────────────────────────────
  ✅ strict-transport-security
  ❌ content-security-policy
  ...

✔ Probe complete — 40s
```

---

## 📁 Project Structure

```
domain-probe/
├── domain_probe.py              # Main CLI entry point
├── install-nuclei.sh            # ✨ Nuclei installer
├── modules/
│   ├── output.py                # Rich formatting + JSON export
│   ├── whois.py                 # WHOIS + RDAP lookup
│   ├── dns.py                   # DNS records + AXFR
│   ├── ssl.py                   # SSL/TLS certificate analysis
│   ├── http.py                  # HTTP + security headers + CORS + JS
│   ├── tech_detect.py           # Signature-based tech detection (45 sig)
│   ├── wappalyzer.py            # Wappalyzer engine (4000+ apps)
│   ├── session.py               # ✨ Proxy, rate limiting, random UA
│   ├── spinner.py               # ✨ Loading spinner
│   ├── nuclei.py                # ✨ Nuclei vulnerability scanner
│   ├── geoip.py                 # IP geolocation
│   ├── ports.py                 # TCP port scanner
│   ├── subdomains.py            # Subdomain + wildcard detection
│   ├── seo.py                   # robots.txt, sitemap, meta tags
│   ├── email_sec.py             # SPF, DKIM, DMARC, BIMI
│   ├── wayback.py               # Wayback Machine CDX API
│   ├── related.py               # Reverse IP / related domains
│   ├── exposed.py               # Sensitive path scanner
│   ├── shodan.py                # Shodan InternetDB
│   └── user_agents.py           # ✨ 30+ real browser User-Agents
├── requirements.txt
└── README.md
```

---

## 🔧 Dependencies

### Python (wajib)
```
python-whois>=0.9      # WHOIS lookups
dnspython>=2.7          # DNS resolution
requests>=2.31          # HTTP client
rich>=13.0              # Terminal formatting
cryptography>=42.0      # SSL cert parsing
```

Install: `pip install -r requirements.txt`

### External (opsional)
| Tool | Function | Install |
|------|----------|---------|
| `nmap` | Deep port scan | `sudo apt install nmap` |
| `webanalyze` | Wappalyzer 4000+ apps | Download [release](https://github.com/rverton/webanalyze/releases) |
| `subfinder` | Subdomain 30+ sources | `go install github.com/.../subfinder@latest` |
| `nuclei` | Vulnerability scanner (7000+ templates) | `bash install-nuclei.sh` |

---

## 🛠️ Architecture

```
Input domain
  ├── Resolve DNS → IP
  │   └── Wildcard detection
  ├── [ThreadPoolExecutor — 12 workers parallel]
  │   ├── WHOIS + RDAP
  │   ├── DNS all records + AXFR
  │   ├── SSL handshake
  │   ├── HTTP probe
  │   │   ├── Security headers + CORS + cookies
  │   │   ├── Tech Detection (45 signatures)
  │   │   └── Wappalyzer (4000+ apps)
  │   ├── GeoIP
  │   ├── Port scan (socket/nmap)
  │   ├── Subdomains (6 sources + brute + wildcard filter)
  │   ├── SEO
  │   ├── [deep] Email Security
  │   ├── [deep] Wayback Machine
  │   ├── [deep] Reverse IP
  │   ├── [deep] Exposed Paths (76 paths)
  │   └── [deep] Shodan InternetDB
  ├── ➕ [--nuclei] 7000+ vuln templates (smart-filtered)
  ├── 🛡️  Proxy + Rate Limit + Random UA (tiap request)
  └── Aggregate → Rich output / JSON export
```

---

## ⚡ Performance

| Mode | v2.0 | v2.2 | Pengurangan |
|------|------|------|-------------|
| `--full` (500 subdomain) | ~3-4 menit 🔴 | **~40-60 detik** 🟢 | **~75% lebih cepet** |

Optimasi:
- **DNS batch delay** — delay per 20 query, bukan per-query (50s → 7.5s)
- **HTTP rate limit** — 300ms → 100ms default
- **Thread pool** — 12 parallel workers
- **Nuclei smart filter** — cuma template relevan aja

---

## 📝 Notes

- **Anti-Block**: `--full` otomatis aktifin delay 100ms + random UA. Bisa ditambah `--proxy` atau `--proxy-list` buat target WAF berat.
- **Nuclei**: Install dulu pake `bash install-nuclei.sh`. Teknologi terdeteksi otomatis dipake buat filter template.
- **WHOIS Privacy**: Most domains post-GDPR have redacted owner names.
- **Subdomain Brute**: DNS-based, 2000+ wordlist. Wildcard otomatis terfilter.

---

## 📄 License

MIT — MAliffadlan, 2026
