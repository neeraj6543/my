import os
import json
import requests
from datetime import datetime
from urllib.parse import urlparse

API_URL = "http://127.0.0.1:8000/api/v1/scan"


def get_domain_from_url(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or "scan"
    # windows-safe filename
    return host.replace(":", "_")


def save_json_report(data: dict, folder: str, domain: str) -> str:
    os.makedirs(folder, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(folder, f"{domain}_{ts}_full.json")
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return filename


def build_summary_text(data: dict) -> str:
    lines = []
    root_url = data.get("root_url", "")
    pages = data.get("pages", [])
    stats = data.get("stats", {})
    overall_risk = data.get("overall_risk", "unknown")
    risk_score = data.get("risk_score", 0)
    top_issues = data.get("top_issues", [])
    dns = data.get("dns_info", None)

    lines.append(f"==== Cyber Ultra Security Report ====")
    lines.append(f"Target       : {root_url}")
    lines.append(f"Total pages  : {len(pages)}")
    lines.append(f"Overall risk : {overall_risk.upper()} (score: {risk_score}/100)")
    lines.append("")

    # Stats
    lines.append("Issue counts:")
    lines.append(f"  total    : {stats.get('total', 0)}")
    lines.append(f"  good     : {stats.get('good', 0)}")
    lines.append(f"  info     : {stats.get('info', 0)}")
    lines.append(f"  warning  : {stats.get('warning', 0)}")
    lines.append(f"  critical : {stats.get('critical', 0)}")
    lines.append("")

    # DNS info
    if dns:
        lines.append("DNS / WHOIS:")
        lines.append(f"  domain        : {dns.get('domain')}")
        lines.append(f"  registrar     : {dns.get('registrar')}")
        lines.append(f"  creation_date : {dns.get('creation_date')}")
        lines.append(f"  expiry_date   : {dns.get('expiration_date')}")
        nameservers = dns.get("nameservers") or []
        if nameservers:
            lines.append("  nameservers   :")
            for ns in nameservers:
                lines.append(f"    - {ns}")
        lines.append("")

    # Top issues
    if top_issues:
        lines.append("Top repeating issues (by count):")
        for ti in top_issues:
            lines.append(
                f"  - [{ti.get('level').upper()}] {ti.get('title')} "
                f"(count: {ti.get('count')}, example: {ti.get('example_page')})"
            )
        lines.append("")

    # Per-page high level summary (only warnings/critical)
    lines.append("Per-page high risk summary (warning/critical only):")
    for p in pages:
        url = p.get("url")
        status = p.get("status")
        issues = p.get("issues", [])
        high = [i for i in issues if i.get("level") in ("warning", "critical")]
        if not high:
            continue
        lines.append(f"\n  Page: {url} (status: {status})")
        for iss in high:
            lines.append(
                f"    - [{iss.get('level').upper()}] {iss.get('title')}: {iss.get('detail')}"
            )

    return "\n".join(lines)


def save_summary_report(text: str, folder: str, domain: str) -> str:
    os.makedirs(folder, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(folder, f"{domain}_{ts}_summary.txt")
    with open(filename, "w", encoding="utf-8") as f:
        f.write(text)
    return filename


def main():
    target_url = input("Scan karne ke liye website URL daalo (e.g. https://auts.ac.in/): ").strip()
    if not target_url:
        print("URL khaali nahi ho sakta.")
        return

    print(f"[+] Scanning: {target_url}")
    try:
        resp = requests.post(API_URL, json={"url": target_url}, timeout=120)
    except Exception as e:
        print(f"[!] API call failed: {e}")
        return

    if resp.status_code != 200:
        print(f"[!] API ne error diya: {resp.status_code} -> {resp.text}")
        return

    data = resp.json()
    domain = get_domain_from_url(target_url)
    reports_folder = os.path.join("reports")

    # 1) Full JSON save
    json_path = save_json_report(data, reports_folder, domain)
    print(f"[+] Full JSON report saved: {json_path}")

    # 2) Summary text generate + save
    summary_text = build_summary_text(data)
    summary_path = save_summary_report(summary_text, reports_folder, domain)
    print(f"[+] Summary report saved: {summary_path}")
    print("\nDone. Dono reports 'reports' folder ke andar mil jayengi.")


if __name__ == "__main__":
    main()
