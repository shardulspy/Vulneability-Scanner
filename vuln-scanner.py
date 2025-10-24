#!/usr/bin/env python3
"""
vuln_scanner.py

Usage: python3 vuln_scanner.py
Interactive: choose scan now or schedule via cron.

Dependencies:
 - nmap
 - nikto
 - OWASP ZAP (either run ZAP daemon and install python-owasp-zap-v2.4,
   or install zap-cli and have it available on PATH)
 - Python packages: none strictly required (uses stdlib). If using ZAP API,
   install python-owasp-zap-v2.4: pip install python-owasp-zap-v2.4
"""

import subprocess
import concurrent.futures
import os
import sys
import re
import html
from pathlib import Path
from datetime import datetime

### ---------- Configuration ----------
# If using ZAP API, set this API key if ZAP uses one (or leave empty).
ZAP_API_KEY = ""  # change if needed
# If ZAP runs on non-default host/port, change these:
ZAP_HOST = "127.0.0.1"
ZAP_PORT = 8080
# Directory to store intermediate outputs and reports
OUTPUT_DIR = Path.cwd() / "scan_outputs"
OUTPUT_DIR.mkdir(exist_ok=True)
### -----------------------------------

def sanitize_name(target):
    s = target.replace("http://", "").replace("https://", "").replace("/", "_").replace(":", "_")
    return re.sub(r'[^A-Za-z0-9_\-\.]', '_', s)

def run_command(cmd, timeout=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout + ("\n" + p.stderr if p.stderr else "")
    except subprocess.TimeoutExpired:
        return f"[!] Command timed out: {' '.join(cmd)}"

def run_nmap(target):
    name = sanitize_name(target)
    nmap_xml = OUTPUT_DIR / f"nmap_{name}.xml"
    cmd = [
        "nmap", "-p-", "-sV", "-O", "--script=vuln", "-T4",
        "-oX", str(nmap_xml),
        target
    ]
    print("[*] Running nmap:", " ".join(cmd))
    out = run_command(cmd, timeout=3600)
    # Also capture stdout to file for raw reference
    (OUTPUT_DIR / f"nmap_{name}.raw.txt").write_text(out, encoding="utf-8")
    return ("nmap", out)

def run_nikto(target):
    name = sanitize_name(target)
    nikto_xml = OUTPUT_DIR / f"nikto_{name}.xml"
    # Nikto supports -Format xml and -output
    cmd = ["nikto", "-h", target, "-Format", "xml", "-output", str(nikto_xml)]
    print("[*] Running nikto:", " ".join(cmd))
    out = run_command(cmd, timeout=3600)
    # Some nikto versions still write to stdout; capture both
    (OUTPUT_DIR / f"nikto_{name}.raw.txt").write_text(out, encoding="utf-8")
    return ("nikto", out)

def run_zap(target):
    name = sanitize_name(target)
    zap_raw = OUTPUT_DIR / f"zap_{name}.raw.txt"
    # Try to use python-owasp-zap-v2.4 if installed
    try:
        from zapv2 import ZAPv2
        print("[*] Using ZAP API (python-owasp-zap-v2.4). Make sure ZAP is running on host.")
        zap = ZAPv2(apikey=ZAP_API_KEY, proxies={'http': f'http://{ZAP_HOST}:{ZAP_PORT}', 'https': f'http://{ZAP_HOST}:{ZAP_PORT}'})
        # Access target URL to populate sites
        print("[*] Accessing target via ZAP proxy to populate sites...")
        try:
            zap.urlopen(target)
        except Exception:
            # sometimes urlopen fails if target uses https and certs; continue
            pass
        print("[*] Starting active scan via ZAP API...")
        scan_id = zap.ascan.scan(target)
        # Wait for scan to finish (poll)
        import time
        while int(zap.ascan.status(scan_id)) < 100:
            print(f"    ZAP scan progress: {zap.ascan.status(scan_id)}%")
            time.sleep(5)
        print("[*] ZAP active scan finished. Retrieving alerts...")
        alerts = zap.core.alerts(baseurl=target)
        out = str(alerts)
        (OUTPUT_DIR / zap_raw.name).write_text(out, encoding="utf-8")
        return ("zap", out)
    except Exception as e_api:
        # fallback to zap-cli if installed
        print("[!] ZAP API not used (missing package or error):", e_api)
        print("[*] Falling back to zap-cli (requires zap-cli installed and ZAP available).")
        cmd_scan = ["zap-cli", "quick-scan", "--self-contained", target]
        out_scan = run_command(cmd_scan, timeout=3600)
        (OUTPUT_DIR / zap_raw.name).write_text(out_scan, encoding="utf-8")
        # try to export HTML report with zap-cli (if available)
        try:
            html_report = OUTPUT_DIR / f"zap_{name}.html"
            cmd_report = ["zap-cli", "report", "-o", str(html_report)]
            run_command(cmd_report, timeout=60)
        except Exception:
            pass
        return ("zap", out_scan)

# Heuristic extraction of findings from raw output
def extract_findings(tool, raw):
    findings = []
    lines = raw.splitlines()
    # Patterns to look for (heuristic)
    patterns = {
        "SQL Injection": re.compile(r'(?i)\b(sql(?:\s*injection|i)?|union select|select .* from)\b'),
        "Cross-Site Scripting (XSS)": re.compile(r'(?i)\b(xss|cross[-\s]?site scripting)\b'),
        "Directory Listing": re.compile(r'(?i)\bdirectory listing\b'),
        "Outdated Software / Version Disclosure": re.compile(r'(?i)\b(version|outdated|old version|end of life|eol|vulnerable)\b'),
        "CVE": re.compile(r'(CVE-\d{4}-\d+)'),
        "Information Disclosure / Headers": re.compile(r'(?i)\b(server:|x-powered-by|via:)\b'),
        "Command Injection / RCE": re.compile(r'(?i)\b(command injection|remote code execution|RCE)\b'),
        "Open Redirect": re.compile(r'(?i)\b(open redirect)\b'),
        "Insecure Cookies": re.compile(r'(?i)\b(httpOnly|secure flag|cookie.*secure|set-cookie)\b'),
    }

    remediation_map = {
        "SQL Injection": "Use parameterized queries / ORM, validate and sanitize inputs, least-privilege DB user.",
        "Cross-Site Scripting (XSS)": "Sanitize and encode output, use Content Security Policy (CSP), validate inputs.",
        "Directory Listing": "Disable directory listing in web server config (e.g., Apache Options -Indexes).",
        "Outdated Software / Version Disclosure": "Update software to the latest secure version; remove or hide version banners.",
        "CVE": "Review the referenced CVE and apply vendor patch or mitigation recommended by the CVE entry.",
        "Information Disclosure / Headers": "Remove unnecessary headers, apply minimal server fingerprinting, configure security headers.",
        "Command Injection / RCE": "Validate and sanitize inputs, avoid shelling out with unchecked input, use safe libraries.",
        "Open Redirect": "Validate redirect targets against an allowlist or avoid user-controlled redirects.",
        "Insecure Cookies": "Set 'HttpOnly' and 'Secure' flags and use 'SameSite' where appropriate.",
        "Default": "Investigate the finding and apply vendor-recommended remediation / patch."
    }

    # Scan each line for pattern matches
    for i, line in enumerate(lines):
        snippet = line.strip()
        if not snippet:
            continue
        matched = False
        for name, pat in patterns.items():
            m = pat.search(snippet)
            if m:
                matched = True
                severity = "Medium"
                # If pattern contains CVE, try to elevate severity heuristically
                if name == "CVE":
                    severity = "High"
                    vuln_id = m.group(1)
                    title = f"{vuln_id} referenced"
                    details = snippet
                    remediation = remediation_map.get("CVE")
                else:
                    title = name
                    details = snippet
                    remediation = remediation_map.get(name, remediation_map["Default"])

                findings.append({
                    "title": title,
                    "severity": severity,
                    "tool": tool,
                    "details": details,
                    "remediation": remediation
                })
        # also look for explicit severity words
        if not matched:
            if re.search(r'(?i)\b(critical|high|medium|low)\b', snippet):
                sev_word = re.search(r'(?i)\b(critical|high|medium|low)\b', snippet).group(1).lower()
                severity = sev_word.capitalize()
                findings.append({
                    "title": "Reported finding",
                    "severity": severity,
                    "tool": tool,
                    "details": snippet,
                    "remediation": remediation_map.get("Default")
                })

    # If no findings, give a summary info entry with first N lines for human review
    if not findings:
        sample = "\n".join(lines[:10]) if lines else "(no output)"
        findings.append({
            "title": "No clear heuristic matches - raw output snapshot",
            "severity": "Info",
            "tool": tool,
            "details": sample,
            "remediation": "Review raw output and follow tool-specific remediation guidance."
        })
    return findings

# Map severity to color for HTML
SEV_COLORS = {
    "Critical": "#b30000",
    "High": "#ff6600",
    "Medium": "#ffcc00",
    "Low": "#66cc66",
    "Info": "#9aa0a6"
}

def generate_html_report(target, all_findings):
    name = sanitize_name(target)
    report_file = OUTPUT_DIR / f"report_{name}.html"
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    title = f"Vulnerability Report for {html.escape(target)}"
    html_rows = []
    for f in all_findings:
        sev = f.get("severity", "Info")
        color = SEV_COLORS.get(sev, "#cccccc")
        html_rows.append(f"""
        <tr>
            <td>{html.escape(f.get('title',''))}</td>
            <td style="background:{color}; color:#000; font-weight:700; text-align:center;">{html.escape(sev)}</td>
            <td>{html.escape(f.get('tool',''))}</td>
            <td><pre style="white-space:pre-wrap;margin:0">{html.escape(f.get('details',''))}</pre></td>
            <td>{html.escape(f.get('remediation',''))}</td>
        </tr>
        """)

    html_doc = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>{title}</title>
<style>
body{{font-family:Inter, Roboto, Arial, sans-serif; padding:20px; background:#f7f8fb}}
h1{{color:#222}}
table{{width:100%; border-collapse:collapse; background:#fff; box-shadow:0 2px 8px rgba(0,0,0,0.06)}}
th,td{{padding:12px; border-bottom:1px solid #eee; vertical-align:top;}}
th{{background:#fafafa; text-align:left}}
pre{{font-family:monospace; font-size:13px; color:#222; background:transparent; margin:0}}
.small{{color:#666; font-size:13px}}
</style>
</head>
<body>
<h1>{title}</h1>
<p class="small">Generated: {now}</p>
<table>
<thead>
<tr><th>Vulnerability</th><th>Severity</th><th>Tool</th><th>Details</th><th>Remediation</th></tr>
</thead>
<tbody>
{''.join(html_rows)}
</tbody>
</table>
</body>
</html>
"""
    report_file.write_text(html_doc, encoding="utf-8")
    return report_file

def run_scans(target):
    # Launch tools in parallel
    print(f"[*] Starting scans against: {target}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        futures = {
            ex.submit(run_nmap, target): "nmap",
            ex.submit(run_nikto, target): "nikto",
            ex.submit(run_zap, target): "zap",
        }
        results = []
        for fut in concurrent.futures.as_completed(futures):
            tool_name = futures[fut]
            try:
                res = fut.result()
                results.append(res)  # tuple (tool, output)
                print(f"[+] {tool_name} finished.")
            except Exception as e:
                print(f"[!] {tool_name} error: {e}")
                results.append((tool_name, f"[!] Exception: {e}"))
    # Parse outputs heuristically into findings
    all_findings = []
    for tool, raw in results:
        findings = extract_findings(tool, raw)
        all_findings.extend(findings)
    # Generate HTML report
    report_path = generate_html_report(target, all_findings)
    print(f"[+] Report created: {report_path}")
    return report_path

def schedule_scan(target, cron_timing):
    """
    Create a wrapper script in user's HOME and add a crontab entry.
    The wrapper calls this file with --run-now and the target.
    """
    home = Path.home()
    wrapper = home / f"vuln_scanner_wrapper_{sanitize_name(target)}.sh"
    # Use absolute path to this script
    this_script = Path(__file__).resolve()
    wrapper_contents = f"""#!/bin/bash
# Wrapper to run scheduled scan for {target}
python3 "{this_script}" --run-now "{target}" >> "{OUTPUT_DIR}/cron_{sanitize_name(target)}.log" 2>&1
"""
    wrapper.write_text(wrapper_contents, encoding="utf-8")
    wrapper.chmod(0o750)
    cron_line = f"{cron_timing} {wrapper}\n"
    print("[*] Installing crontab entry:")
    print(cron_line)
    # Install crontab line (append to existing crontab)
    try:
        # read existing crontab
        p = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        existing = p.stdout if p.returncode == 0 else ""
        new_cron = existing + "\n" + cron_line
        proc = subprocess.run(["crontab", "-"], input=new_cron, text=True)
        if proc.returncode == 0:
            print("[+] Cron job installed.")
            print(f"[i] Wrapper script: {wrapper}")
            print(f"[i] Logs will be appended to: {OUTPUT_DIR}/cron_{sanitize_name(target)}.log")
        else:
            print("[!] Failed to install crontab. Return code:", proc.returncode)
    except Exception as e:
        print("[!] Exception while installing crontab:", e)

def show_examples():
    print("\nHow to provide inputs (examples):")
    print("  Target URL examples:")
    print("    http://example.com")
    print("    https://test.example.com:8443")
    print("\n  Cron timing examples (standard 5-field crontab):")
    print("    * * * * *    -> every minute")
    print("    0 * * * *    -> every hour at minute 0")
    print("    0 2 * * *    -> every day at 02:00 (2 AM)")
    print("    0 2 * * 1    -> every Monday at 02:00")
    print("\nWhen scheduling, enter the 5-field cron timing exactly (e.g. '0 2 * * *').\n")

def main_interactive():
    print("Vulnerability Scanner — interactive")
    show_examples()
    target = input("Enter target URL (example: http://example.com): ").strip()
    if not target:
        print("No target provided. Exiting.")
        return
    print("\nChoose an option:")
    print("  1 - Run scan now")
    print("  2 - Schedule scan via cron")
    choice = input("Enter choice (1/2): ").strip()
    if choice == "1":
        run_scans(target)
    elif choice == "2":
        print("\nCron timing examples (again):")
        print("  * * * * *   -> every minute")
        print("  0 * * * *   -> every hour")
        print("  0 2 * * *   -> daily at 02:00")
        cron = input("Enter cron timing (e.g. '0 2 * * *'): ").strip()
        if not cron or len(cron.split()) != 5:
            print("Invalid cron timing format. Expect 5 fields. Exiting.")
            return
        schedule_scan(target, cron)
    else:
        print("Invalid choice. Exiting.")

def main_run_now(target):
    # direct run (used by wrapper/cron)
    run_scans(target)

if __name__ == "__main__":
    # Simple CLI: allow --run-now "target" for wrapper usage
    if len(sys.argv) >= 2 and sys.argv[1] == "--run-now":
        if len(sys.argv) >= 3:
            tgt = sys.argv[2]
            main_run_now(tgt)
        else:
            print("Usage: --run-now <target>")
    else:
        main_interactive()
