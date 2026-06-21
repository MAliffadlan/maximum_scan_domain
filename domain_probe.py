#!/usr/bin/env python3
"""
Domain Probe v2.0 — Comprehensive CLI Domain Intelligence Tool

Usage:
  python3 domain_probe.py example.com                    # Standard scan
  python3 domain_probe.py example.com --deep              # Full deep scan
  python3 domain_probe.py example.com -o report.json      # Export JSON
  python3 domain_probe.py example.com --deep -s 500       # Deep + subdomain brute
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from modules.output import (
    print_banner, print_section, print_table, print_key_value,
    print_warning, print_error, print_success, export_json
)
from modules.whois import run_whois
from modules.dns import run_dns
from modules.ssl import run_ssl
from modules.http import run_http
from modules.geoip import run_geoip
from modules.ports import run_ports, run_ports_deep
from modules.subdomains import run_subdomains
from modules.seo import run_seo

# Deep scan modules
from modules.email_sec import run_email_security
from modules.wayback import run_wayback
from modules.related import run_related
from modules.exposed import run_exposed
from modules.shodan import run_external_intel

VERSION = "2.0.0"


def resolve_domain(domain: str) -> tuple[str, list[str]]:
    """Resolve domain to IP addresses. Returns (primary_ip, [all_ips])."""
    clean = domain.strip().lower()
    clean = clean.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    try:
        ips = list(set(
            addr[4][0] for addr in socket.getaddrinfo(clean, None, socket.AF_INET)
        ))
        return (ips[0], ips) if ips else ("", [])
    except socket.gaierror:
        return ("", [])


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="domain-probe",
        description="Comprehensive domain intelligence from the CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  probe example.com               Standard intelligence report
  probe example.com --full        Maximum: deep scan + 500 subdomains
  probe example.com --deep        Deep scan (no subdomain brute)
  probe example.com -o report.json  Export JSON
        """,
    )
    parser.add_argument("domain", help="Domain name to probe (e.g. example.com)")
    parser.add_argument("-o", "--output", metavar="FILE", help="Export results to JSON file")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Minimal output (JSON only when used with -o)")
    parser.add_argument("--full", action="store_true",
                        help="MAXIMUM scan: --deep + 500 subdomain brute + nmap + all modules")
    parser.add_argument("--deep", action="store_true",
                        help="Deep scan: email security, wayback, exposed paths, "
                             "CORS, JS deps, external intel, related domains, nmap")
    parser.add_argument("-s", "--subdomains", type=int, default=0, metavar="N",
                        help="Brute-force subdomains: 100, 500, or 1000")
    parser.add_argument("--timeout", type=int, default=120, metavar="SECONDS",
                        help="Overall timeout in seconds (default: 120)")
    parser.add_argument("-v", "--version", action="version",
                        version=f"Domain Probe v{VERSION}")
    return parser


def run_all_modules(domain: str, ip: str, ips: list[str],
                    nameservers: list[str], args: argparse.Namespace) -> dict[str, Any]:
    """Execute all probe modules in parallel and return aggregated results."""
    results: dict[str, Any] = {
        "domain": domain,
        "ip": ip,
        "all_ips": ips,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "version": VERSION,
        "deep_scan": args.deep,
    }

    # Base tasks — always run
    base_tasks = [
        ("whois",      lambda: run_whois(domain)),
        ("dns",        lambda: run_dns(domain)),
        ("ssl",        lambda: run_ssl(domain, ip or None) if ip
                        else {"error": "no IP resolved"}),
        ("http",       lambda: run_http(domain)),
        ("geoip",      lambda: run_geoip(ip) if ip
                        else {"error": "no IP resolved"}),
        ("ports",      (lambda: run_ports_deep(ip))
                        if args.deep and ip
                        else (lambda: run_ports(ip)) if ip
                        else (lambda: {"error": "no IP resolved"})),
        ("subdomains", lambda: run_subdomains(domain, args.subdomains)),
        ("seo",        lambda: run_seo(domain)),
    ]

    tasks = list(base_tasks)

    # Deep tasks — only when --deep
    if args.deep:
        deep_tasks = [
            ("email_security", lambda: run_email_security(domain)),
            ("wayback",        lambda: run_wayback(domain, 30)),
            ("related",        lambda: run_related(domain, ip or "", nameservers or [])),
            ("exposed",        lambda: run_exposed(domain)),
            ("external_intel", lambda: run_external_intel(ip) if ip
                                else {"error": "no IP resolved"}),
        ]
        tasks.extend(deep_tasks)

    max_workers = 12 if args.deep else 8
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(fn): key for key, fn in tasks}
        for future in as_completed(future_map):
            key = future_map[future]
            try:
                results[key] = future.result()
            except Exception as exc:
                results[key] = {"error": str(exc)}

    return results


def display_results(results: dict[str, Any]) -> None:
    """Pretty-print aggregated results with Rich."""
    domain = results.get("domain", "unknown")
    ip = results.get("ip", "N/A")
    ips = results.get("all_ips", [])
    is_deep = results.get("deep_scan", False)

    print_banner(domain)
    if is_deep:
        print_section("  [DEEP SCAN MODE — Full Analysis]")

    # =====================================================================
    # NETWORK SUMMARY
    # =====================================================================
    print_section("Network Summary")
    print_key_value({
        "Primary IP": ip or "(not resolved)",
        "All IPs": ", ".join(ips) if ips else "(none)",
        "Probe Time": results.get("timestamp", "N/A"),
        "Elapsed": f"{results.get('elapsed_seconds', '?')}s",
        "Mode": "DEEP" if is_deep else "Standard",
    })

    # =====================================================================
    # WHOIS
    # =====================================================================
    print_section("WHOIS Lookup")
    who = results.get("whois", {})
    if who.get("error"):
        print_warning(f"WHOIS: {who['error']}")
    else:
        owner = who.get("owner", {})
        if owner:
            print_section("  Domain Owner (Registrant)")
            print_key_value({
                "Name":       owner.get("name", "—"),
                "Organization": owner.get("organization", "—"),
                "Email":      owner.get("email", "—"),
                "Phone":      owner.get("phone", "—"),
                "Address":    f"{owner.get('address','')}, {owner.get('city','')} "
                              f"{owner.get('state','')} {owner.get('postal_code','')} "
                              f"{owner.get('country','')}".strip().rstrip(",").replace(" ,", ","),
            })
        else:
            print_warning("  No owner/registrant info found (may be GDPR redacted)")

        admin = who.get("admin_contact", {})
        if admin:
            print_table("Admin Contact", ["Field", "Value"],
                        [[k, v] for k, v in admin.items()])
        tech = who.get("tech_contact", {})
        if tech:
            print_table("Tech Contact", ["Field", "Value"],
                        [[k, v] for k, v in tech.items()])

        print_key_value({
            "Registrar":   who.get("registrar", "—"),
            "Created":     who.get("created", "—"),
            "Expires":     who.get("expires", "—"),
            "Updated":     who.get("updated", "—"),
            "RDAP Source": who.get("rdap_source", "whois only"),
        })
        if who.get("status"):
            print_key_value({"Domain Status": who["status"][:120]})
        if who.get("nameservers"):
            print_table("Nameservers", ["Nameserver"],
                        [[ns] for ns in who["nameservers"]])

    # =====================================================================
    # DNS
    # =====================================================================
    print_section("DNS Records")
    dns_data = results.get("dns", {})
    if dns_data.get("error"):
        print_warning(f"DNS: {dns_data['error']}")
    else:
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV"]
        for rtype in record_types:
            records = dns_data.get(rtype, [])
            if records:
                print_table(f"  {rtype} Records", ["Value"], [[r] for r in records[:20]])
                if len(records) > 20:
                    print(f"  ... and {len(records) - 20} more")

        # AXFR results
        if dns_data.get("axfr_attempted"):
            axfr_records = dns_data.get("axfr_records", [])
            if axfr_records:
                rows = [[r["nameserver"], r["status"].upper()]
                        for r in axfr_records]
                print_table("AXFR (Zone Transfer) Attempt", ["Nameserver", "Status"], rows)
            if dns_data.get("axfr_success"):
                print_warning("AXFR SUCCEEDED — zone transfer is OPEN (misconfigured)")
            else:
                print_success("AXFR blocked on all nameservers (secure)")

    # =====================================================================
    # EMAIL SECURITY (deep)
    # =====================================================================
    email = results.get("email_security")
    if email is not None:
        print_section("Email Security (SPF / DKIM / DMARC)")
        if email.get("error"):
            print_warning(f"Email Security: {email['error']}")
        else:
            def _s(v, default=""):
                """Safe string: convert None to default."""
                return str(v) if v else default

            # SPF
            spf = email.get("spf", {})
            spf_status = "✅" if spf.get("present") else "❌"
            spf_record = _s(spf.get("record"))
            print_key_value({"SPF Record": f"{spf_status} {spf_record[:100]}" if spf_record else f"{spf_status}"})
            if spf.get("present"):
                includes = spf.get("includes") or []
                ip4_list = spf.get("ip4") or []
                print_key_value({
                    "SPF Qualifier": _s(spf.get("qualifier"), "?"),
                    "SPF Includes":  ", ".join(includes)[:100] if includes else "none",
                    "SPF IP4":       ", ".join(ip4_list)[:100] if ip4_list else "none",
                })

            # DMARC
            dmarc = email.get("dmarc", {})
            dmarc_status = "✅" if dmarc.get("present") else "❌"
            policy = _s(dmarc.get("policy"), "not set")
            policy_color = "🟢" if policy in ("reject", "quarantine") else "🔴"
            dmarc_record = _s(dmarc.get("record"))
            print_key_value({
                "DMARC Record": f"{dmarc_status} {dmarc_record[:100]}" if dmarc_record else f"{dmarc_status}",
                "DMARC Policy": f"{policy_color} {policy} (sub: {_s(dmarc.get('subdomain_policy'),'none')})",
            })

            # DKIM
            dkim = email.get("dkim", {})
            dkim_icon = "✅" if dkim.get("present") else "❌"
            selectors = dkim.get("selectors_found") or []
            print_key_value({
                "DKIM": f"{dkim_icon} Found selectors: {', '.join(selectors) if selectors else 'none'} "
                        f"({dkim.get('keys_found') or 0} keys, {dkim.get('valid_count') or 0} valid)",
            })

            # BIMI
            bimi = email.get("bimi", {})
            if bimi.get("present"):
                logo = _s(bimi.get("logo_url"))
                print_key_value({
                    "BIMI": f"✅ Logo: {logo[:80]}",
                })

    # =====================================================================
    # SSL
    # =====================================================================
    print_section("SSL/TLS Certificate")
    ssl_data = results.get("ssl", {})
    if ssl_data.get("error"):
        print_warning(f"SSL: {ssl_data['error']}")
    else:
        ssl_display = {k: v for k, v in ssl_data.items()
                       if k not in ("error", "chain", "sans")}
        print_key_value(ssl_display)
        if ssl_data.get("sans"):
            print_table("Subject Alternative Names", ["SAN"],
                        [[s] for s in ssl_data["sans"][:20]])
            if len(ssl_data["sans"]) > 20:
                print(f"  ... and {len(ssl_data['sans']) - 20} more")

    # =====================================================================
    # HTTP Analysis
    # =====================================================================
    print_section("HTTP Analysis")
    http_data = results.get("http", {})
    if http_data.get("error"):
        print_warning(f"HTTP: {http_data['error']}")
    else:
        print_key_value({
            "URL":      http_data.get("final_url", ""),
            "Status":   str(http_data.get("status_code", "")),
            "Server":   http_data.get("server", "(unknown)"),
        })
        if http_data.get("redirect_chain"):
            print_table("Redirect Chain", ["#", "URL", "Status"],
                        [[str(i+1), r["url"],
                          str(r.get("status_code", r.get("status", "")))]
                         for i, r in enumerate(http_data["redirect_chain"])])
        if http_data.get("tech_stack"):
            print_table("Detected Technologies", ["Technology"],
                        [[t] for t in http_data["tech_stack"]])

        # Security headers
        sec = http_data.get("security_headers", {})
        if sec:
            sec_rows = [[h, "✅" if present else "❌"]
                        for h, present in sec.items()]
            print_table("Security Headers", ["Header", "Status"], sec_rows)
        if http_data.get("missing_headers"):
            print_warning(f"Missing: {', '.join(http_data['missing_headers'])}")

        # Cookie summary
        cookie_sum = http_data.get("cookie_summary", {})
        if cookie_sum and cookie_sum.get("total", 0) > 0:
            print_table("Cookie Audit", ["Metric", "Value"], [
                ["Total Cookies",       str(cookie_sum.get("total", 0))],
                ["Secure",              str(cookie_sum.get("secure_count", 0))],
                ["HttpOnly",            str(cookie_sum.get("httponly_count", 0))],
                ["SameSite Strict",     str(cookie_sum.get("samesite_strict", 0))],
                ["SameSite Lax",        str(cookie_sum.get("samesite_lax", 0))],
                ["SameSite None",       str(cookie_sum.get("samesite_none", 0))],
                ["Session Cookies",     str(cookie_sum.get("session_cookies", 0))],
                ["Third-Party Cookies", str(cookie_sum.get("third_party_cookies", 0))],
            ])

        # CORS (deep)
        cors = http_data.get("cors", {})
        if cors:
            print_section("  CORS Analysis")
            print_key_value({
                "CORS Enabled":       "✅" if cors.get("cors_enabled") else "❌",
                "Allow-Origin":       cors.get("allow_origin", "(none)"),
                "Allow-Credentials":  str(cors.get("allow_credentials", False)),
                "Permissive (*)":     "⚠️" if cors.get("permissive_cors") else "OK",
                "Dangerous Config":   "🔴 VULNERABLE" if cors.get("dangerous")
                                       else "OK",
                "Summary":            cors.get("summary", ""),
            })

        # JS Dependencies (deep)
        js_deps = http_data.get("js_dependencies", [])
        if js_deps:
            print_table("JavaScript Dependencies", ["Library", "Version", "Source"],
                        [[d.get("library", "?"), d.get("version", "?"),
                          d.get("url", "inline")[:70]]
                         for d in js_deps[:20]])

    # =====================================================================
    # GeoIP
    # =====================================================================
    print_section("IP Geolocation")
    geo = results.get("geoip", {})
    if geo.get("error"):
        print_warning(f"GeoIP: {geo['error']}")
    else:
        print_key_value(geo)

    # =====================================================================
    # Ports
    # =====================================================================
    print_section("Port Scan")
    ports = results.get("ports", {})
    if ports.get("error"):
        print_warning(f"Ports: {ports['error']}")
    else:
        open_ports = ports.get("open_ports", [])
        if open_ports:
            port_cols = ["Port", "Service"]
            if any("version" in p for p in open_ports):
                port_cols.append("Version")
            rows = [[str(p["port"]), p.get("service", "unknown")] +
                    ([p.get("version", "")] if "version" in open_ports[0] else [])
                    for p in open_ports]
            print_table("Open Ports", port_cols, rows)
        else:
            print_key_value({"Open Ports": "None found"})
        print_key_value({
            "Scanned":   str(ports.get("total_scanned", 0)),
            "Scan Time": f"{ports.get('scan_time', 0):.2f}s",
        })

    # =====================================================================
    # External Intel / Shodan (deep)
    # =====================================================================
    ext = results.get("external_intel")
    if ext is not None:
        print_section("External Intelligence (Shodan InternetDB)")
        if ext.get("error"):
            print_warning(f"External Intel: {ext['error']}")
        else:
            if ext.get("ports"):
                print_key_value({"Known Ports": ", ".join(str(p) for p in ext["ports"])})
            if ext.get("hostnames"):
                print_table("Known Hostnames", ["Hostname"],
                            [[h] for h in ext["hostnames"][:20]])
            if ext.get("tags"):
                print_table("Tags", ["Tag"], [[t] for t in ext["tags"]])
            if ext.get("vulns"):
                print_warning(f"Known CVEs: {', '.join(ext['vulns'])}")
            if ext.get("cpes"):
                print_table("CPE Identifiers", ["CPE"], [[c] for c in ext["cpes"][:10]])

    # =====================================================================
    # Subdomains
    # =====================================================================
    print_section("Subdomain Enumeration")
    subs = results.get("subdomains", {})
    if subs.get("error"):
        print_warning(f"Subdomains: {subs['error']}")
    else:
        sub_list = subs.get("subdomains", [])
        print_key_value({"Count": str(len(sub_list)), "Source": subs.get("source", "unknown")})
        if sub_list:
            print_table("Subdomains", ["Subdomain"], [[s] for s in sub_list[:50]])
            if len(sub_list) > 50:
                print(f"  ... and {len(sub_list) - 50} more")

    # =====================================================================
    # WAYBACK (deep)
    # =====================================================================
    wb = results.get("wayback")
    if wb is not None:
        print_section("Wayback Machine History")
        if wb.get("error"):
            print_warning(f"Wayback: {wb['error']}")
        else:
            print_key_value({
                "First Snapshot":  wb.get("first_snapshot", "?"),
                "Last Snapshot":   wb.get("last_snapshot", "?"),
                "Years Active":    ", ".join(str(y) for y in wb.get("years_active", []))
                                   if wb.get("years_active") else "?",
                "Snapshots Shown": str(len(wb.get("snapshots", []))),
            })
            snaps = wb.get("snapshots", [])[:10]
            if snaps:
                print_table("Recent Snapshots", ["Date", "URL", "Type"],
                            [[s["timestamp"][:8], s["url"][:60], s.get("mimetype", "")]
                             for s in snaps])

    # =====================================================================
    # RELATED DOMAINS (deep)
    # =====================================================================
    rel = results.get("related")
    if rel is not None:
        print_section("Related Domains")
        if rel.get("error"):
            print_warning(f"Related: {rel['error']}")
        else:
            related_domains = rel.get("reverse_ip_domains", [])
            if related_domains:
                print_key_value({"Same IP Domains": str(len(related_domains))})
                print_table("Domains on Same IP", ["Domain"],
                            [[d] for d in related_domains[:30]])
                if len(related_domains) > 30:
                    print(f"  ... and {len(related_domains) - 30} more")
            else:
                print_warning("  No related domains found on same IP")

    # =====================================================================
    # EXPOSED PATHS (deep)
    # =====================================================================
    exp = results.get("exposed")
    if exp is not None:
        print_section("Exposed Paths & Sensitive Files")
        if exp.get("error"):
            print_warning(f"Exposed: {exp['error']}")
        else:
            found = exp.get("found", [])
            scan_sum = exp.get("scan_summary", {})
            if scan_sum:
                print_key_value({
                    "Total Checked":   str(exp.get("total_checked", 0)),
                    "🔴 Critical":     str(scan_sum.get("critical_count", 0)),
                    "🟠 High":         str(scan_sum.get("high_count", 0)),
                    "🟡 Medium":       str(scan_sum.get("medium_count", 0)),
                    "🔵 Low":          str(scan_sum.get("low_count", 0)),
                })
            if found:
                rows = [[f["severity"].upper(), f["path"], str(f.get("status_code", "")),
                         f.get("description", "")[:60]]
                        for f in found]
                print_table("Exposed Paths", ["Severity", "Path", "Status", "Description"], rows)
                critical = [f for f in found if f.get("severity") == "critical"]
                if critical:
                    print_warning(f"CRITICAL exposures found: {', '.join(f['path'] for f in critical)}")
            else:
                print_success("  No sensitive paths exposed")

    # =====================================================================
    # SEO
    # =====================================================================
    seo = results.get("seo", {})
    if not seo.get("error"):
        robots = seo.get("robots_txt", {})
        sitemap = seo.get("sitemap", {})
        if robots.get("exists") or sitemap.get("exists"):
            print_section("SEO Analysis")
            if robots.get("exists"):
                print_key_value({"robots.txt": "Found"})
                disallowed = robots.get("disallowed", [])
                if disallowed:
                    print_table("robots.txt Disallowed", ["Path"],
                                [[p] for p in disallowed[:20]])
            if sitemap.get("exists"):
                print_key_value({"Sitemap": f"Found ({sitemap.get('url_count', 0)} URLs)"})
            meta = seo.get("meta", {})
            if meta:
                print_table("Meta Tags", ["Tag", "Value"],
                            [[k, (v[:80] + "...") if len(v) > 80 else v]
                             for k, v in meta.items() if v])

    print_success(f"Probe complete — {results.get('elapsed_seconds', '?')}s")


def main() -> None:
    parser = build_cli()
    args = parser.parse_args()
    domain = args.domain.strip()

    # --full implies --deep + 500 subdomain brute
    if args.full:
        args.deep = True
        if args.subdomains == 0:
            args.subdomains = 500

    if not args.quiet:
        print_banner(domain)

    # Resolve
    ip, ips = resolve_domain(domain)
    if not ip and not args.quiet:
        print_warning(f"Could not resolve '{domain}' — continuing with limited data...")

    # Get nameservers for deep modules
    nameservers: list[str] = []
    if args.deep:
        try:
            from modules.dns import run_dns
            dns_pre = run_dns(domain)
            nameservers = dns_pre.get("authoritative_nameservers", [])
        except Exception:
            pass

    # Run all modules
    if not args.quiet:
        mode_text = ("MAXIMUM SCAN — All modules + 500 subdomains" if args.full
                     else "DEEP SCAN — All modules" if args.deep
                     else "Standard scan")
        print_section(f"Probing... ({mode_text})")
        modules_list = "WHOIS, DNS, SSL, HTTP, GeoIP, Ports, Subdomains, SEO"
        if args.deep:
            modules_list += ", Email Sec, Wayback, Related, Exposed, External Intel"
        print(f"  Running {modules_list} in parallel...\n")

    start = time.time()
    results = run_all_modules(domain, ip, ips, nameservers, args)
    elapsed = time.time() - start
    results["elapsed_seconds"] = round(elapsed, 2)

    # Output
    if args.output:
        export_json(results, args.output)

    if not args.quiet:
        display_results(results)
    elif not args.output:
        print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
