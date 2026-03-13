# backend/app/scanner.py
# Advanced — passive & safe web scanner (pattern-based signals only).
# Do NOT use this to run active exploits. Designed for internal authorized testing.
import time
import asyncio
from typing import List, Tuple, Set, Dict, Optional
from urllib.parse import urljoin, urlparse, parse_qs

import httpx
from bs4 import BeautifulSoup
import tldextract
import dns.resolver
import whois

from .schemas import (
    Issue,
    PageSummary,
    DnsInfo,
    ScanResult,
    IssueStats,
    TopIssue,
    LevelType,
    RiskLevelType,
)


# ----------------- Basic helpers -----------------

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def same_domain(root: str, link: str) -> bool:
    try:
        root_host = urlparse(root).netloc
        link_host = urlparse(link).netloc
        return (
            root_host == link_host
            or root_host.endswith(link_host)
            or link_host.endswith(root_host)
        )
    except Exception:
        return False


def fetch_with_redirects(url: str, timeout: int = 10) -> Tuple[str, httpx.Response, float, int]:
    normalized = normalize_url(url)
    start = time.perf_counter()
    with httpx.Client(follow_redirects=True, timeout=timeout) as client:
        resp = client.get(normalized)
    end = time.perf_counter()
    elapsed_ms = (end - start) * 1000
    redirect_count = len(resp.history)
    return str(resp.url), resp, elapsed_ms, redirect_count


async def fetch_page(client: httpx.AsyncClient, url: str) -> Tuple[str, Optional[httpx.Response]]:
    try:
        resp = await client.get(url)
        return url, resp
    except Exception:
        return url, None


# ----------------- Header / HTML analysis -----------------

def analyze_headers(final_url: str, resp: httpx.Response, page_url: str) -> List[Issue]:
    headers = resp.headers
    issues: List[Issue] = []

    # HTTPS / HSTS
    if final_url.startswith("https://"):
        issues.append(Issue(level="good", title="HTTPS enabled", detail="Page uses HTTPS.", page=page_url))
        if "Strict-Transport-Security" in headers:
            issues.append(Issue(level="good", title="HSTS enabled", detail="Strict-Transport-Security header is set.", page=page_url))
        else:
            issues.append(Issue(level="info", title="HSTS not enabled", detail="Consider enabling HSTS.", page=page_url))
    else:
        issues.append(Issue(level="warning", title="No HTTPS", detail="Page is not using HTTPS; traffic may be intercepted.", page=page_url))

    # CSP
    if "Content-Security-Policy" in headers:
        issues.append(Issue(level="good", title="CSP present", detail="Content-Security-Policy header exists.", page=page_url))
        csp = headers.get("Content-Security-Policy", "")
        if "unsafe-inline" in csp or "unsafe-eval" in csp or "*" in csp:
            issues.append(Issue(level="warning", title="Weak CSP", detail="CSP contains unsafe directives (unsafe-inline/unsafe-eval or *).", page=page_url))
    else:
        issues.append(Issue(level="warning", title="Missing CSP", detail="CSP header missing; increases XSS risk.", page=page_url))

    # X-Frame-Options
    if "X-Frame-Options" in headers:
        issues.append(Issue(level="good", title="X-Frame-Options present", detail=f"X-Frame-Options: {headers.get('X-Frame-Options')}", page=page_url))
    else:
        issues.append(Issue(level="info", title="X-Frame-Options not set", detail="Consider SAMEORIGIN or DENY to prevent clickjacking.", page=page_url))

    # Referrer-Policy
    if "Referrer-Policy" in headers:
        issues.append(Issue(level="good", title="Referrer-Policy present", detail=f"Referrer-Policy: {headers.get('Referrer-Policy')}", page=page_url))
    else:
        issues.append(Issue(level="info", title="Referrer-Policy missing", detail="Add Referrer-Policy to reduce leakage of referrers.", page=page_url))

    # CORS checks (passive: inspect headers returned)
    acao = headers.get("Access-Control-Allow-Origin")
    acc = headers.get("Access-Control-Allow-Credentials")
    if acao:
        if acao == "*" and acc == "true":
            issues.append(Issue(level="warning", title="Insecure CORS", detail="Access-Control-Allow-Origin: * together with credentials:true is dangerous.", page=page_url))
        elif acao == "*":
            issues.append(Issue(level="info", title="CORS allows all origins", detail="Access-Control-Allow-Origin is '*'. Consider restricting.", page=page_url))
        else:
            issues.append(Issue(level="good", title="CORS configured", detail=f"Access-Control-Allow-Origin: {acao}", page=page_url))

    # Server header
    server_header = headers.get("Server")
    if server_header:
        # check if version string included (simple heuristic)
        if any(ch.isdigit() for ch in server_header):
            issues.append(Issue(level="info", title="Server header exposed (with version)", detail=f"Server header reveals: {server_header}. Consider hiding version.", page=page_url))
        else:
            issues.append(Issue(level="info", title="Server header exposed", detail=f"Server header reveals: {server_header}.", page=page_url))
    else:
        issues.append(Issue(level="good", title="Server header hidden", detail="Server details are not exposed.", page=page_url))

    # Cookies flags (Set-Cookie header summary)
    set_cookie = headers.get("Set-Cookie", "")
    if set_cookie:
        lc = set_cookie.lower()
        has_secure = "secure" in lc
        has_httponly = "httponly" in lc
        if has_secure and has_httponly:
            issues.append(Issue(level="good", title="Cookies use Secure & HttpOnly", detail="Cookies set with Secure and HttpOnly flags.", page=page_url))
        elif has_secure or has_httponly:
            issues.append(Issue(level="info", title="Partial cookie flags", detail="Cookies have some but not all recommended flags.", page=page_url))
        else:
            issues.append(Issue(level="warning", title="Cookie flags missing", detail="Cookies do not appear to use Secure/HttpOnly flags.", page=page_url))
    else:
        issues.append(Issue(level="info", title="No cookies set", detail="No Set-Cookie header in response.", page=page_url))

    return issues


def analyze_html(html: str, page_url: str) -> List[Issue]:
    """Static/passive HTML + JS analysis (no active checks)."""
    issues: List[Issue] = []
    soup = BeautifulSoup(html, "lxml")
    text = html.lower()

    # Secret-like keywords
    secret_keywords = ["api_key", "apikey", "secret", "token", "auth_token", "passwd", "password", "bearer "]
    for key in secret_keywords:
        if key in text:
            issues.append(Issue(level="warning", title="Possible secret in page source", detail=f"Found keyword '{key}' in HTML/JS. Check for hard-coded secrets.", page=page_url))
            break

    # JS library + possible version hints
    scripts = soup.find_all("script", src=True)
    for s in scripts:
        src = s.get("src", "")
        lsrc = src.lower()
        if "jquery" in lsrc:
            # detect old references heuristically
            if any(v in lsrc for v in ["jquery-1.", "jquery/1.", "ver=1.", "jquery-1"]):
                issues.append(Issue(level="warning", title="Old jQuery detected", detail=f"Script src looks like old jQuery: {src}. Consider updating.", page=page_url))
        if "react" in lsrc or "react-dom" in lsrc:
            issues.append(Issue(level="info", title="React frontend detected", detail=f"React script found: {src}", page=page_url))
        if "angular" in lsrc:
            issues.append(Issue(level="info", title="Angular frontend detected", detail=f"Angular script found: {src}", page=page_url))

    # Inline event handlers and risky sinks (simple heuristics)
    # Detect inline event attributes which sometimes indicate unsafe code usage
    inline_attrs = ["onclick", "onload", "onerror", "onmouseover", "onfocus"]
    for tag in soup.find_all(True):
        for a in inline_attrs:
            if tag.get(a):
                issues.append(Issue(level="info", title="Inline JS event handler found", detail=f"Inline JS attribute '{a}' present in tag <{tag.name}>.", page=page_url))
                break

    # Look for dangerous JS patterns in static HTML (sinks)
    # (we are not executing JS; only searching text)
    if "document.write(" in text or "innerhtml" in text or "eval(" in text:
        issues.append(Issue(level="warning", title="Dangerous JS patterns", detail="Page contains patterns like document.write/innerHTML/eval which may enable XSS if combined with untrusted input.", page=page_url))

    # Forms without obvious CSRF tokens
    forms = soup.find_all("form")
    for f in forms:
        inputs = f.find_all("input")
        has_csrf = any("csrf" in (inp.get("name", "").lower() + inp.get("id", "").lower()) for inp in inputs)
        if not has_csrf:
            issues.append(Issue(level="info", title="Form without visible CSRF token", detail="Form found without an obvious CSRF field (heuristic).", page=page_url))
            break

    return issues


def extract_internal_links(root_url: str, html: str, limit: int = 20) -> List[str]:
    soup = BeautifulSoup(html, "lxml")
    links: Set[str] = set()
    for a in soup.find_all("a", href=True):
        href = a["href"]
        full = urljoin(root_url, href)
        if same_domain(root_url, full):
            links.add(full)
        if len(links) >= limit:
            break
    return list(links)


def get_dns_info(url: str) -> Optional[DnsInfo]:
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        ext = tldextract.extract(hostname)
        domain = f"{ext.domain}.{ext.suffix}"

        nameservers: List[str] = []
        has_dns = False
        try:
            ns_records = dns.resolver.resolve(domain, "NS")
            nameservers = [str(r) for r in ns_records]
            has_dns = True
        except Exception:
            pass

        reg = None
        creation = None
        expire = None
        has_whois = False
        try:
            w = whois.whois(domain)
            reg = str(w.registrar) if w.registrar else None

            def _to_str(v):
                if isinstance(v, list) and v:
                    return str(v[0])
                return str(v) if v else None

            creation = _to_str(w.creation_date)
            expire = _to_str(w.expiration_date)
            has_whois = True
        except Exception:
            pass

        return DnsInfo(domain=domain, has_dns=has_dns, nameservers=nameservers, has_whois=has_whois, registrar=reg, creation_date=creation, expiration_date=expire)
    except Exception:
        return None


# ----------------- Advanced passive signals -----------------

def find_idor_signals(page_url: str) -> List[Issue]:
    issues: List[Issue] = []
    parsed = urlparse(page_url)
    path_parts = [p for p in parsed.path.split("/") if p]
    numeric_segments = [p for p in path_parts if p.isdigit()]
    if numeric_segments:
        keywords = ["user", "users", "account", "profile", "invoice", "order", "booking", "ticket", "payment"]
        path_lower = parsed.path.lower()
        if any(k in path_lower for k in keywords):
            issues.append(Issue(level="warning", title="Possible IDOR / access control risk", detail=f"URL path '{parsed.path}' contains numeric IDs and resource-like names. Check authorization on object access.", page=page_url))
    return issues


def find_open_redirect_signals(page_url: str) -> List[Issue]:
    issues: List[Issue] = []
    parsed = urlparse(page_url)
    qs = parse_qs(parsed.query)
    redirect_params = ["redirect", "url", "next", "return", "goto", "dest", "destination"]
    risky = [p for p in qs.keys() if p.lower() in redirect_params]
    if risky:
        issues.append(Issue(level="info", title="Possible open redirect parameter", detail=f"Query param(s) {risky} look like redirect targets. Verify validation of redirect targets to avoid phishing.", page=page_url))
    return issues


def find_admin_like_signals(page_url: str, html: Optional[str] = None) -> List[Issue]:
    issues: List[Issue] = []
    parsed = urlparse(page_url)
    path_lower = parsed.path.lower()
    admin_keywords = ["admin", "administrator", "cpanel", "dashboard", "backend", "manage", "panel", "console"]
    if any(k in path_lower for k in admin_keywords):
        issues.append(Issue(level="info", title="Admin-like URL detected", detail=f"Path '{parsed.path}' looks like admin/panel. Ensure strong authentication & access control.", page=page_url))
    if html:
        try:
            soup = BeautifulSoup(html, "lxml")
            title_text = (soup.title.string or "").lower() if soup.title and soup.title.string else ""
            heading = soup.find(["h1", "h2"])
            heading_text = heading.get_text(strip=True).lower() if heading else ""
            combined = title_text + " " + heading_text
            if any(k in combined for k in ["admin", "dashboard", "control panel", "management console"]):
                issues.append(Issue(level="info", title="Admin-like page content", detail="Page title/heading suggests admin/dashboard. Verify authentication.", page=page_url))
        except Exception:
            pass
    return issues


def find_api_endpoints_from_html(root_url: str, html: str) -> List[str]:
    """Extract likely API endpoints from scripts or links (passive)."""
    endpoints: Set[str] = set()
    soup = BeautifulSoup(html, "lxml")
    # script srcs and inline JS search for '/api/' patterns
    for s in soup.find_all(["script", "a"], src=True) + soup.find_all("a", href=True):
        attr = s.get("src") or s.get("href")
        if attr and "/api/" in attr:
            full = urljoin(root_url, attr)
            endpoints.add(full)
    # inline JS: search strings
    for s in soup.find_all("script"):
        if s.string:
            text = s.string
            if "/api/" in text:
                # very basic extract - grab surrounding token
                parts = text.split()
                for p in parts:
                    if "/api/" in p:
                        cleaned = p.strip("();\"' ,")
                        if cleaned.startswith("/"):
                            endpoints.add(urljoin(root_url, cleaned))
                        else:
                            endpoints.add(cleaned)
    return list(endpoints)


# ----------------- CVE / library hint mapping (very small sample) -----------------
# NOTE: This is only a tiny mapping for demonstration. Expand offline with a real DB.
CVE_HINTS = {
    "jquery-1": "Detected jQuery 1.x — older versions have several known XSS-related CVEs. Consider upgrading to 3.x.",
    "php-5": "PHP 5.x is end-of-life and has multiple security issues. Upgrade to supported PHP 7/8.",
    "angular-1": "AngularJS 1.x reached EOL; consider updating framework or patching."
}

def find_cve_hints_from_strings(text: str) -> List[Issue]:
    issues: List[Issue] = []
    t = text.lower()
    for k, msg in CVE_HINTS.items():
        if k in t:
            issues.append(Issue(level="info", title="Potential outdated library detected", detail=msg, page=None))
    return issues


# ----------------- Stats / scoring / grouping -----------------

def compute_issue_stats(issues: List[Issue]) -> IssueStats:
    total = len(issues)
    good = sum(1 for i in issues if i.level == "good")
    info = sum(1 for i in issues if i.level == "info")
    warning = sum(1 for i in issues if i.level == "warning")
    critical = sum(1 for i in issues if i.level == "critical")
    return IssueStats(total=total, good=good, info=info, warning=warning, critical=critical)


def compute_overall_risk(stats: IssueStats) -> Tuple[RiskLevelType, int]:
    score = stats.info * 1 + stats.warning * 6 + stats.critical * 18
    if score > 100:
        score = 100
    if score == 0:
        level: RiskLevelType = "low"
    elif score < 25:
        level = "low"
    elif score < 50:
        level = "medium"
    elif score < 75:
        level = "high"
    else:
        level = "critical"
    return level, int(score)


def compute_top_issues(issues: List[Issue], limit: int = 8) -> List[TopIssue]:
    counter: Dict[Tuple[str, LevelType], Dict[str, Optional[str] | int]] = {}
    for issue in issues:
        key = (issue.title, issue.level)
        if key not in counter:
            counter[key] = {"count": 0, "example_page": issue.page}
        counter[key]["count"] += 1
    sorted_items = sorted(counter.items(), key=lambda x: x[1]["count"], reverse=True)
    top: List[TopIssue] = []
    for (title, level), data in sorted_items:
        if level == "good":
            continue
        top.append(TopIssue(title=title, level=level, count=int(data["count"]), example_page=data["example_page"]))
        if len(top) >= limit:
            break
    return top


# ----------------- MAIN scan function -----------------

async def full_scan(url: str) -> ScanResult:
    final_root, root_resp, elapsed_ms, redirects = fetch_with_redirects(url)
    pages: List[PageSummary] = []
    root_html: Optional[str] = None

    # Root analysis
    root_issues = analyze_headers(final_root, root_resp, final_root)
    if "text/html" in root_resp.headers.get("Content-Type", ""):
        root_html = root_resp.text
        root_issues += analyze_html(root_html, final_root)
        # gather cve hints from source
        root_issues += find_cve_hints_from_strings(root_html)

    # passive signals for root
    root_issues += find_idor_signals(final_root)
    root_issues += find_open_redirect_signals(final_root)
    root_issues += find_admin_like_signals(final_root, root_html)

    # collect internal links and possible api endpoints
    links: List[str] = []
    api_candidates: Set[str] = set()
    if root_html:
        links = extract_internal_links(final_root, root_html, limit=40)  # deeper crawl for advanced
        for ep in find_api_endpoints_from_html(final_root, root_html):
            api_candidates.add(ep)

    pages.append(PageSummary(url=final_root, status=root_resp.status_code, issues=root_issues))

    # fetch internal pages (async)
    async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
        tasks = [fetch_page(client, l) for l in links]
        results = await asyncio.gather(*tasks)

    for page_url, resp in results:
        if resp is None:
            pages.append(PageSummary(url=page_url, status=0, issues=[Issue(level="warning", title="Could not fetch page", detail="Request failed or timed out.", page=page_url)]))
            continue

        page_real_url = str(resp.url)
        page_issues = analyze_headers(page_real_url, resp, page_real_url)
        page_html: Optional[str] = None
        if "text/html" in resp.headers.get("Content-Type", ""):
            page_html = resp.text
            page_issues += analyze_html(page_html, page_real_url)
            page_issues += find_cve_hints_from_strings(page_html)

            # collect more api candidates from internal pages
            for ep in find_api_endpoints_from_html(page_real_url, page_html):
                api_candidates.add(ep)

        # advanced passive signals
        page_issues += find_idor_signals(page_real_url)
        page_issues += find_open_redirect_signals(page_real_url)
        page_issues += find_admin_like_signals(page_real_url, page_html)

        pages.append(PageSummary(url=page_real_url, status=resp.status_code, issues=page_issues))

    dns_info = get_dns_info(final_root)

    # compile stats & scoring
    all_issues: List[Issue] = [iss for p in pages for iss in p.issues]
    stats = compute_issue_stats(all_issues)
    overall_risk, risk_score = compute_overall_risk(stats)
    top_issues = compute_top_issues(all_issues)

    # add lightweight API summary as an "issue" if any API endpoints found
    api_list = sorted(list(api_candidates))
    if api_list:
        top_api = api_list[:6]
        desc = f"Found {len(api_list)} candidate API endpoints/strings in HTML/scripts. Examples: {top_api}"
        all_issues.append(Issue(level="info", title="API endpoints detected in page assets", detail=desc, page=final_root))
        stats = compute_issue_stats(all_issues)  # recompute with this addition
        overall_risk, risk_score = compute_overall_risk(stats)
        top_issues = compute_top_issues(all_issues)

    return ScanResult(
        root_url=final_root,
        total_pages_scanned=len(pages),
        response_time_ms=elapsed_ms,
        redirect_count=redirects,
        pages=pages,
        dns_info=dns_info,
        stats=stats,
        overall_risk=overall_risk,
        risk_score=risk_score,
        top_issues=top_issues,
    )
