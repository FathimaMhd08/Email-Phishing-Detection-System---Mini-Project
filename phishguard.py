"""
PhishGuard - Email Phishing Detection System
--------------------------------------------
Simple, rule-based phishing detector with a friendly GUI.
Only uses the Python standard library (Python 3.8+).

Run:  python phishguard.py
"""

import re
import json
import math
import difflib
import datetime
from pathlib import Path
from html.parser import HTMLParser
from urllib.parse import urlparse
from email import message_from_string, policy
from email.utils import parseaddr

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, simpledialog
except ImportError:  # lets the engine be tested without a display
    tk = None

# ----------------------------------------------------------------------
# 1. KNOWLEDGE BASE  (edit these lists to tune the detector)
# ----------------------------------------------------------------------
BRANDS = {
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk"],
    "google": ["google.com", "gmail.com"],
    "microsoft": ["microsoft.com", "outlook.com", "office.com", "live.com"],
    "apple": ["apple.com", "icloud.com"],
    "facebook": ["facebook.com", "meta.com"],
    "netflix": ["netflix.com"],
    "instagram": ["instagram.com"],
    "linkedin": ["linkedin.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "sbi": ["sbi.co.in", "onlinesbi.com"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "paytm": ["paytm.com"],
}
BUILTIN_BRANDS = {k: list(v) for k, v in BRANDS.items()}

# Your own brands are saved here and loaded automatically
BRANDS_FILE = Path.home() / ".phishguard_brands.json"
try:
    _saved = json.loads(BRANDS_FILE.read_text(encoding="utf-8"))
    BRANDS.update({k: v for k, v in _saved.items()
                   if isinstance(k, str) and isinstance(v, list) and v})
except Exception:
    pass


def clean_domain(d):
    """'https://www.MyBank.com/home' -> 'mybank.com'"""
    d = d.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d).split("/")[0].split(":")[0]
    return d[4:] if d.startswith("www.") else d


def add_brand(name, domains):
    """Add a custom brand. Returns an error message, or None if OK."""
    name = re.sub(r"[^a-z0-9]", "", name.lower())
    domains = [clean_domain(d) for d in domains if d.strip()]
    domains = [d for d in domains if re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", d)]
    if len(name) < 3:
        return "Brand name must have at least 3 letters/numbers (e.g. mybank)."
    if not domains:
        return "Enter at least one valid domain, e.g. mybank.com"
    BRANDS[name] = domains
    custom = {}
    try:
        custom = json.loads(BRANDS_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    custom[name] = domains
    try:
        BRANDS_FILE.write_text(json.dumps(custom, indent=1), encoding="utf-8")
    except OSError:
        return "Brand added for this session, but it could not be saved to disk."
    return None


def custom_brands():
    try:
        data = json.loads(BRANDS_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def remove_brand(name):
    """Remove a custom brand. Returns True if removed, False if built-in/not found."""
    name = name.lower()
    custom = custom_brands()
    if name not in custom:
        return False
    del custom[name]
    try:
        BRANDS_FILE.write_text(json.dumps(custom, indent=1), encoding="utf-8")
    except OSError:
        pass
    if name in BUILTIN_BRANDS:          # restore the original built-in entry
        BRANDS[name] = list(BUILTIN_BRANDS[name])
    else:
        BRANDS.pop(name, None)
    return True


SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
              "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc"}
BAD_TLDS = {".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".click",
            ".work", ".zip", ".mov", ".country", ".kim", ".loan", ".rest"}
FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com"}
DANGEROUS_EXT = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".jar",
                 ".iso", ".lnk", ".hta", ".ps1", ".msi", ".com"}
MACRO_EXT = {".docm", ".xlsm", ".pptm"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".gz"}

KEYWORDS = {  # category -> (points each, max points, phrases)
    "Urgency / pressure": (5, 15, [
        "urgent", "immediately", "act now", "within 24 hours", "final notice",
        "last warning", "expires today", "limited time", "right away", "asap"]),
    "Threats": (6, 15, [
        "account suspended", "account will be closed", "account locked",
        "unauthorized", "suspicious activity", "legal action", "deactivated",
        "unusual sign-in", "security alert"]),
    "Asks for credentials / money": (7, 20, [
        "verify your account", "confirm your password", "update your payment",
        "enter your password", "login to confirm", "credit card", "cvv",
        "social security", "bank details", "otp", "pin number", "wire transfer",
        "gift card", "bitcoin"]),
    "Too-good-to-be-true": (6, 12, [
        "you have won", "congratulations", "lottery", "claim your prize",
        "free gift", "inheritance", "refund", "million dollars"]),
    "Generic greeting": (5, 5, [
        "dear customer", "dear user", "dear account holder", "dear member",
        "dear sir/madam", "valued customer"]),
}


# ----------------------------------------------------------------------
# 2. EMAIL PARSING
# ----------------------------------------------------------------------
class _LinkParser(HTMLParser):
    """Collects (href, visible text) from HTML emails."""
    def __init__(self):
        super().__init__()
        self.links, self._href, self._text = [], None, []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href.strip(), "".join(self._text).strip()))
            self._href = None


def strip_html(html):
    return re.sub(r"<[^>]+>", " ", re.sub(r"(?is)<(script|style).*?</\1>", " ", html))


def parse_email(raw):
    """Return dict(headers, text, html, attachments). Works for raw .eml or plain text."""
    info = {"headers": None, "text": "", "html": "", "attachments": []}
    looks_like_eml = re.match(r"\s*(From|Received|Subject|Return-Path|Delivered-To|"
                              r"MIME-Version|Date|To|Reply-To):", raw, re.I)
    if not looks_like_eml:
        info["text"] = raw
        return info
    msg = message_from_string(raw, policy=policy.default)
    info["headers"] = msg
    for part in msg.walk():
        if part.is_multipart():
            continue
        name = part.get_filename()
        if name:
            info["attachments"].append(name)
            continue
        try:
            content = part.get_content()
        except Exception:
            continue
        if part.get_content_type() == "text/html":
            info["html"] += str(content)
        elif part.get_content_type() == "text/plain":
            info["text"] += str(content)
    if not info["text"] and info["html"]:
        info["text"] = strip_html(info["html"])
    return info


# ----------------------------------------------------------------------
# 3. DETECTION ENGINE
# ----------------------------------------------------------------------
def parse_url(url):
    """Parse a URL safely. Returns None if the URL is malformed."""
    try:
        return urlparse(url if "//" in url else "http://" + url)
    except ValueError:
        return None


def host_of(url):
    u = parse_url(url)
    try:
        return (u.hostname or "").lower() if u else ""
    except ValueError:
        return ""


def root_domain(host):
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "ac"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def normalize_lookalike(s):
    """Undo common character tricks: paypa1 -> paypal, rnicrosoft -> microsoft"""
    s = s.lower().replace("rn", "m").replace("vv", "w")
    return s.translate(str.maketrans("0135$", "oles s".replace(" ", "")))[:len(s)]


def check_lookalike(domain):
    """Return the brand a domain imitates (typosquatting), or None."""
    name = root_domain(domain).split(".")[0]
    for brand, official in BRANDS.items():
        if root_domain(domain) in official:
            return None
        norm = normalize_lookalike(name)
        if any(normalize_lookalike(tok) == brand for tok in name.split("-")) and name != brand:
            return brand
        ratio = difflib.SequenceMatcher(None, norm, brand).ratio()
        if norm == brand or (ratio >= 0.84 and name != brand):
            return brand
    return None


def brand_in_wrong_domain(host):
    for brand, official in BRANDS.items():
        if brand in host and root_domain(host) not in official:
            return brand
    return None


def analyze_url(url, anchor_text=""):
    """Return list of (points, message) for one URL."""
    out, host = [], host_of(url)
    u = parse_url(url)
    if u is None:
        return [(15, f"Malformed link (broken address): {url[:60]}")]
    if not host:
        return out
    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host):
        out.append((20, f"Link uses a raw IP address: {host}"))
    if "@" in u.netloc:
        out.append((15, f"Link contains '@' to hide the real destination: {url[:60]}"))
    if host in SHORTENERS:
        out.append((10, f"Shortened link hides destination: {host}"))
    if any(host.endswith(t) for t in BAD_TLDS):
        out.append((10, f"Link uses a high-risk domain ending: {host}"))
    if "xn--" in host:
        out.append((15, f"Punycode (look-alike unicode) domain: {host}"))
    if url.lower().startswith("http://"):
        out.append((5, f"Link is not encrypted (http): {host}"))
    if host.count(".") >= 4:
        out.append((5, f"Link has an unusually long subdomain chain: {host}"))
    imitated = check_lookalike(host)
    if imitated:
        out.append((25, f"Domain '{host}' imitates the brand '{imitated}'"))
    else:
        wrong = brand_in_wrong_domain(host)
        if wrong:
            out.append((20, f"'{wrong}' appears in '{host}' but it is not the official site"))
    # ---- generic checks: work for ANY website, no brand list needed ----
    name = root_domain(host).split(".")[0]
    path_q = (u.path or "") + (u.query or "")
    words = ["login", "signin", "secure", "verify", "account", "update", "banking",
             "wallet", "confirm", "support", "password", "billing", "recover"]
    in_host = [w for w in words if w in host]
    if in_host:
        out.append((15, f"Domain contains sensitive words ({', '.join(in_host)}): {host}"))
    elif any(w in path_q.lower() for w in words):
        out.append((4, "Link path asks for login/verification"))
    if host.count("-") >= 3:
        out.append((8, f"Domain has many hyphens: {host}"))
    if len(name) >= 4 and sum(c.isdigit() for c in name) / len(name) > 0.3:
        out.append((8, f"Domain mixes many digits into the name: {host}"))
    if len(name) >= 8:
        freq = {c: name.count(c) for c in set(name)}
        entropy = -sum(n / len(name) * math.log2(n / len(name)) for n in freq.values())
        if entropy > 3.4 and not any(v in name for v in "aeiou"):
            out.append((10, f"Domain looks randomly generated: {host}"))
    if re.search(r"\.(com|net|org|gov|edu|co|in)\.[a-z0-9-]+\.[a-z]{2,}$", host):
        out.append((25, f"Fake trusted-name trick in subdomain: {host}"))
    if len(url) > 100:
        out.append((5, "Very long link (often hides the real address)"))
    try:
        port = u.port
    except ValueError:
        port = None
        out.append((10, "Link has an invalid port number"))
    if port and port not in (80, 443):
        out.append((10, f"Link uses unusual port {port}"))
    if re.search(r"[?&](url|redirect|redir|next|goto|return|continue)=https?", url, re.I):
        out.append((10, "Link redirects to another website"))
    if re.fullmatch(r"(0x[0-9a-f]+|\d{8,10})", host):
        out.append((20, f"Link uses an encoded IP address: {host}"))
    # anchor text shows one site, link goes to another
    m = re.search(r"((?:https?://)?(?:[\w-]+\.)+[a-z]{2,})", anchor_text or "", re.I)
    if m:
        shown = host_of(m.group(1))
        if shown and root_domain(shown) != root_domain(host):
            out.append((25, f"Link text says '{shown}' but goes to '{host}'"))
    return out


def analyze(raw):
    """Main entry point. Returns a result dict."""
    raw = raw.strip()
    if re.fullmatch(r"\S+\.\S+", raw) and "@" not in raw:   # user pasted just a link
        raw = raw if re.match(r"https?://", raw, re.I) else "http://" + raw
    email = parse_email(raw)
    findings = []   # (points, category, message)
    links = []      # (url, [issues])

    def add(points, cat, msg):
        findings.append((points, cat, msg))

    msg = email["headers"]
    dom = ""
    subject = str(msg["Subject"]) if msg is not None and msg["Subject"] else ""

    # ---- Sender checks -------------------------------------------------
    if msg is not None:
        name, addr = parseaddr(str(msg.get("From", "")))
        dom = addr.split("@")[-1].lower() if "@" in addr else ""
        if dom:
            imitated = check_lookalike(dom)
            if imitated:
                add(25, "Sender", f"Sender domain '{dom}' imitates '{imitated}'")
            for brand, official in BRANDS.items():
                if brand in name.lower() and root_domain(dom) not in official:
                    add(25, "Sender", f"Display name claims '{brand}' but email comes from '{dom}'")
                    break
        _, reply = parseaddr(str(msg.get("Reply-To", "")))
        if reply and "@" in reply and dom and root_domain(reply.split("@")[-1].lower()) != root_domain(dom):
            add(15, "Sender", f"Reply-To ({reply}) differs from sender ({addr}) - replies go elsewhere")
        _, ret = parseaddr(str(msg.get("Return-Path", "")))
        if ret and "@" in ret and dom and root_domain(ret.split("@")[-1].lower()) != root_domain(dom):
            add(10, "Sender", f"Return-Path domain differs from sender domain")

        # ---- Authentication headers -----------------------------------
        auth = (str(msg.get("Authentication-Results", "")) + " " +
                str(msg.get("Received-SPF", ""))).lower()
        for proto in ("spf", "dkim", "dmarc"):
            if re.search(rf"{proto}=(fail|softfail|none|permerror)", auth) or \
               (proto == "spf" and re.search(r"^\s*(fail|softfail)", auth)):
                add(15, "Authentication", f"{proto.upper()} check did not pass - sender may be forged")

    # ---- Subject -------------------------------------------------------
    if subject:
        letters = [c for c in subject if c.isalpha()]
        if len(letters) > 6 and sum(c.isupper() for c in letters) / len(letters) > 0.7:
            add(5, "Content", "Subject is written in ALL CAPS")
        if subject.count("!") >= 2:
            add(3, "Content", "Subject has excessive exclamation marks")

    # ---- Body keywords -------------------------------------------------
    body = (subject + " " + email["text"]).lower()
    for cat, (pts, cap, phrases) in KEYWORDS.items():
        hits = [p for p in phrases if p in body]
        if hits:
            add(min(pts * len(hits), cap), "Content", f"{cat}: " + ", ".join(f"'{h}'" for h in hits))

    # ---- Links ---------------------------------------------------------
    seen = set()
    all_links = []
    if email["html"]:
        p = _LinkParser()
        p.feed(email["html"])
        all_links += [(u, t) for u, t in p.links if u.lower().startswith(("http", "//", "www"))]
    anchor_texts = {t for _, t in all_links}
    for u in re.findall(r"https?://[^\s<>\"')]+", email["text"]):
        u = u.rstrip(".,;")
        if u not in anchor_texts:      # skip visible text of <a> tags
            all_links.append((u, ""))
    for url, text in all_links:
        if url in seen:
            continue
        seen.add(url)
        issues = analyze_url(url, text)
        links.append((url, [m for _, m in issues]))
        for pts, m in issues:
            add(pts, "Link", m)
    if msg is not None and links:
        sd = root_domain(dom) if dom else ""
        link_roots = {root_domain(host_of(u)) for u, _ in links if host_of(u)}
        if sd and sd not in link_roots and not any(r in SHORTENERS for r in link_roots):
            add(8, "Link", f"None of the links belong to the sender's domain ({sd})")
    if len(links) >= 8:
        add(5, "Link", f"Email contains many links ({len(links)})")

    # ---- Attachments ---------------------------------------------------
    for fn in email["attachments"]:
        low = fn.lower()
        ext = Path(low).suffix
        if len(Path(low).suffixes) >= 2 and ext in DANGEROUS_EXT | MACRO_EXT:
            add(25, "Attachment", f"Double extension disguises file type: {fn}")
        elif ext in DANGEROUS_EXT:
            add(30, "Attachment", f"Dangerous executable attachment: {fn}")
        elif ext in MACRO_EXT:
            add(20, "Attachment", f"Office file with macros: {fn}")
        elif ext in ARCHIVE_EXT:
            add(8, "Attachment", f"Compressed archive (can hide malware): {fn}")
        elif ext in (".html", ".htm"):
            add(15, "Attachment", f"HTML attachment (often a fake login page): {fn}")

    # ---- Score ---------------------------------------------------------
    score = min(100, sum(p for p, _, _ in findings))
    if score >= 55:
        verdict, color = "PHISHING - DO NOT TRUST", "#d32f2f"
    elif score >= 25:
        verdict, color = "SUSPICIOUS - BE CAREFUL", "#f57c00"
    else:
        verdict, color = "LOOKS SAFE", "#2e7d32"

    findings.sort(key=lambda f: -f[0])
    return {"score": score, "verdict": verdict, "color": color,
            "findings": findings, "links": links,
            "attachments": email["attachments"], "subject": subject,
            "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}


def advice(result):
    s = result["score"]
    if s >= 55:
        return ("Do NOT click links or open attachments. Do not reply.\n"
                "Report it as phishing to your email provider / IT team and delete it.\n"
                "If you already clicked or entered a password, change it now and enable 2-factor login.")
    if s >= 25:
        return ("Treat with caution. Do not click links - open the official website by typing "
                "the address yourself.\nContact the sender through a trusted channel to confirm.")
    return ("No strong phishing signs found, but stay alert. Hover over links before clicking "
            "and never share passwords by email.")


def format_report(r):
    lines = ["PHISHGUARD REPORT", "=" * 50, f"Scanned : {r['time']}",
             f"Subject : {r['subject'] or '(none)'}",
             f"Risk    : {r['score']}/100  -> {r['verdict']}", "", "FINDINGS"]
    lines += [f" [+{p:>2}] {c}: {m}" for p, c, m in r["findings"]] or [" None"]
    lines += ["", "LINKS"] + ([f" - {u}" for u, _ in r["links"]] or [" None"])
    lines += ["", "ADVICE", advice(r)]
    return "\n".join(lines)


# ----------------------------------------------------------------------
# 4. HISTORY (saved to ~/.phishguard_history.json)
# ----------------------------------------------------------------------
HISTORY_FILE = Path.home() / ".phishguard_history.json"


def load_history():
    try:
        data = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        return [h for h in data if isinstance(h, dict)] if isinstance(data, list) else []
    except Exception:
        return []


def save_history(entries):
    try:
        HISTORY_FILE.write_text(json.dumps(entries[-200:], indent=1), encoding="utf-8")
    except (OSError, ValueError):
        pass


# ----------------------------------------------------------------------
# 5. GUI
# ----------------------------------------------------------------------
SAMPLE = """From: "PayPal Security" <service@paypa1-secure.xyz>
Reply-To: help@random-mail.top
Subject: URGENT!! Your account will be closed
Authentication-Results: mx.google.com; spf=fail; dkim=none; dmarc=fail
Content-Type: text/html

<html><body>Dear customer,<br>We detected suspicious activity. You must verify your
account immediately within 24 hours or your account will be suspended.<br>
<a href="http://192.168.4.7/login.php">https://www.paypal.com/verify</a><br>
Enter your password and credit card details to confirm.</body></html>
"""


class App:
    def __init__(self, root):
        self.root = root
        root.title("PhishGuard - Email Phishing Detector")
        root.geometry("1000x680")
        root.minsize(850, 560)
        self.history = load_history()
        self.result = None
        self._build()
        self._refresh_history()

    def _build(self):
        top = ttk.Frame(self.root, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="PhishGuard", font=("Segoe UI", 18, "bold")).pack(side="left")
        ttk.Label(top, text="  Paste an email (with headers if possible) or open an .eml file",
                  foreground="#555").pack(side="left")

        bar = ttk.Frame(self.root, padding=(8, 0))
        bar.pack(fill="x")
        for text, cmd in [("Open .eml", self.open_file), ("Paste", self.paste),
                          ("Load sample", self.sample), ("Clear", self.clear),
                          ("Save report", self.save_report), ("Add brand", self.add_brand_dialog),
                          ("Remove brand", self.brand_manager)]:
            ttk.Button(bar, text=text, command=cmd).pack(side="left", padx=2, pady=4)
        ttk.Button(bar, text="🔍 Analyze", command=self.run).pack(side="right", padx=2)

        panes = ttk.PanedWindow(self.root, orient="horizontal")
        panes.pack(fill="both", expand=True, padx=8, pady=6)

        left = ttk.LabelFrame(panes, text="Email content", padding=4)
        self.input = tk.Text(left, wrap="word", undo=True, font=("Consolas", 10))
        sb = ttk.Scrollbar(left, command=self.input.yview)
        self.input.config(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.input.pack(fill="both", expand=True)
        panes.add(left, weight=1)
        self.last_raw = ""
        self.input.bind("<KeyRelease>", lambda e: self.mark_stale())
        self.input.bind("<<Paste>>", lambda e: self.root.after(50, self.mark_stale))
        self.input.bind("<Control-Return>", lambda e: (self.run(), "break")[1])

        right = ttk.Frame(panes)
        panes.add(right, weight=1)

        meter = ttk.LabelFrame(right, text="Risk level", padding=8)
        meter.pack(fill="x")
        self.canvas = tk.Canvas(meter, height=26, bg="#e0e0e0", highlightthickness=0)
        self.canvas.pack(fill="x")
        self.verdict = ttk.Label(meter, text="Waiting for email...", font=("Segoe UI", 14, "bold"))
        self.verdict.pack(pady=(6, 0))

        tabs = ttk.Notebook(right)
        tabs.pack(fill="both", expand=True, pady=6)

        self.tree = ttk.Treeview(tabs, columns=("pts", "cat", "msg"), show="headings")
        for c, t, w in [("pts", "Risk", 50), ("cat", "Type", 90), ("msg", "What we found", 380)]:
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor="w" if c == "msg" else "center")
        self.tree.tag_configure("high", foreground="#d32f2f")
        self.tree.tag_configure("med", foreground="#f57c00")
        self.tree.tag_configure("low", foreground="#555")
        tabs.add(self.tree, text="Findings")

        self.links_tree = ttk.Treeview(tabs, columns=("url", "status"), show="headings")
        self.links_tree.heading("url", text="Link")
        self.links_tree.heading("status", text="Status")
        self.links_tree.column("url", width=300)
        self.links_tree.column("status", width=120, anchor="center")
        tabs.add(self.links_tree, text="Link scanner")

        self.advice = tk.Text(tabs, wrap="word", height=6, font=("Segoe UI", 10), state="disabled")
        tabs.add(self.advice, text="What to do")

        self.hist_tree = ttk.Treeview(tabs, columns=("time", "score", "subj"), show="headings")
        for c, t, w in [("time", "Time", 130), ("score", "Score", 50), ("subj", "Subject", 250)]:
            self.hist_tree.heading(c, text=t)
            self.hist_tree.column(c, width=w)
        tabs.add(self.hist_tree, text="History")

        foot = ttk.Frame(right)
        foot.pack(fill="x")
        ttk.Button(foot, text="Clear history", command=self.clear_history).pack(side="right")
        ttk.Button(foot, text="Export history (CSV)", command=self.export_history).pack(side="right", padx=4)

        self.status = ttk.Label(self.root, text="Ready.", relief="sunken", anchor="w")
        self.status.pack(fill="x", side="bottom")

    # ---- actions --------------------------------------------------------
    def open_file(self):
        path = filedialog.askopenfilename(filetypes=[("Email", "*.eml *.txt"), ("All", "*.*")])
        if path:
            self.input.delete("1.0", "end")
            try:
                text = Path(path).read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                messagebox.showerror("Open file", f"Could not read the file:\n{e}")
                return
            self.input.delete("1.0", "end")
            self.input.insert("1.0", text)
            self.run()

    def paste(self):
        try:
            text = self.root.clipboard_get()
        except tk.TclError:
            messagebox.showinfo("Clipboard", "Clipboard is empty.")
            return
        self.input.delete("1.0", "end")
        self.input.insert("1.0", text)
        self.run()

    def sample(self):
        self.input.delete("1.0", "end")
        self.input.insert("1.0", SAMPLE)
        self.run()

    def mark_stale(self):
        if self.input.get("1.0", "end").strip() != self.last_raw:
            self.verdict.config(text="Email changed - click Analyze", foreground="#777")
            self._draw_meter(0, "#e0e0e0")

    def clear(self):
        self.input.delete("1.0", "end")
        self.tree.delete(*self.tree.get_children())
        self.links_tree.delete(*self.links_tree.get_children())
        self._draw_meter(0, "#e0e0e0")
        self.verdict.config(text="Waiting for email...", foreground="black")
        self.last_raw = ""
        self.status.config(text="Cleared.")

    def run(self):
        raw = self.input.get("1.0", "end").strip()
        if not raw:
            messagebox.showwarning("Empty", "Please paste or open an email first.")
            return
        self.last_raw = raw
        try:
            r = self.result = analyze(raw)
        except Exception as e:      # never let an odd email crash the app
            messagebox.showerror("Analysis error", f"Could not analyze this email:\n{e}")
            return
        self._draw_meter(r["score"], r["color"])
        self.verdict.config(text=f"{r['verdict']}  ({r['score']}/100)", foreground=r["color"])

        self.tree.delete(*self.tree.get_children())
        for p, c, m in r["findings"]:
            tag = "high" if p >= 20 else "med" if p >= 10 else "low"
            self.tree.insert("", "end", values=(f"+{p}", c, m), tags=(tag,))
        if not r["findings"]:
            self.tree.insert("", "end", values=("", "-", "No suspicious signs found."))

        self.links_tree.delete(*self.links_tree.get_children())
        for url, issues in r["links"]:
            self.links_tree.insert("", "end", values=(url, "⚠ Risky" if issues else "OK"))

        self.advice.config(state="normal")
        self.advice.delete("1.0", "end")
        self.advice.insert("1.0", advice(r))
        self.advice.config(state="disabled")

        self.history.append({"time": r["time"], "score": r["score"], "subject": r["subject"] or "(no subject)",
                             "verdict": r["verdict"]})
        save_history(self.history)
        self._refresh_history()
        self.status.config(text=f"Scan complete: {len(r['findings'])} findings, {len(r['links'])} links checked.")

    def _draw_meter(self, score, color):
        self.canvas.update_idletasks()
        w = self.canvas.winfo_width()
        self.canvas.delete("all")
        self.canvas.create_rectangle(0, 0, w * score / 100, 26, fill=color, width=0)

    def add_brand_dialog(self):
        name = simpledialog.askstring("Add brand", "Brand name (e.g. mybank):", parent=self.root)
        if not name:
            return
        doms = simpledialog.askstring(
            "Add brand", "Official domains, comma separated (e.g. mybank.com,mybank.in):",
            parent=self.root)
        if not doms:
            return
        error = add_brand(name, doms.split(","))
        if error:
            messagebox.showwarning("Add brand", error)
        else:
            self.status.config(text=f"Brand '{name.strip().lower()}' added - it will now be protected.")

    def brand_manager(self):
        """Window listing all brands; select a custom brand and remove it."""
        win = tk.Toplevel(self.root)
        win.title("Protected brands")
        win.geometry("560x380")
        win.transient(self.root)
        ttk.Label(win, text="Select a brand to remove. Built-in brands cannot be removed.",
                  padding=8).pack(anchor="w")
        tree = ttk.Treeview(win, columns=("name", "domains", "type"), show="headings")
        for c, t, w in [("name", "Brand", 110), ("domains", "Official domains", 300), ("type", "Type", 80)]:
            tree.heading(c, text=t)
            tree.column(c, width=w, anchor="w")
        tree.tag_configure("custom", foreground="#1565c0")
        tree.pack(fill="both", expand=True, padx=8)

        def refresh():
            tree.delete(*tree.get_children())
            custom = custom_brands()
            for name in sorted(BRANDS, key=lambda n: (n not in custom, n)):
                kind = "Custom" if name in custom else "Built-in"
                tree.insert("", "end", iid=name, values=(name, ", ".join(BRANDS[name]), kind),
                            tags=("custom",) if kind == "Custom" else ())

        def remove():
            sel = tree.selection()
            if not sel:
                messagebox.showinfo("Remove brand", "Select a brand first.", parent=win)
                return
            name = sel[0]
            if name not in custom_brands():
                messagebox.showinfo("Remove brand", f"'{name}' is built-in and cannot be removed.", parent=win)
                return
            if messagebox.askyesno("Remove brand", f"Remove '{name}'?", parent=win):
                remove_brand(name)
                refresh()
                self.status.config(text=f"Brand '{name}' removed.")

        def add():
            self.add_brand_dialog()
            refresh()

        btns = ttk.Frame(win, padding=8)
        btns.pack(fill="x")
        ttk.Button(btns, text="Add brand", command=add).pack(side="left")
        ttk.Button(btns, text="Remove selected", command=remove).pack(side="left", padx=6)
        ttk.Button(btns, text="Close", command=win.destroy).pack(side="right")
        refresh()

    def save_report(self):
        if not self.result:
            messagebox.showinfo("No report", "Run an analysis first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
        if path:
            Path(path).write_text(format_report(self.result), encoding="utf-8")
            self.status.config(text=f"Report saved to {path}")

    def _refresh_history(self):
        self.hist_tree.delete(*self.hist_tree.get_children())
        for h in reversed(self.history[-50:]):
            self.hist_tree.insert("", "end", values=(h.get("time", ""), h.get("score", ""),
                                                     h.get("subject", "")))

    def clear_history(self):
        if messagebox.askyesno("Clear", "Delete all scan history?"):
            self.history = []
            save_history(self.history)
            self._refresh_history()

    def export_history(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if path:
            import csv
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["time", "score", "verdict", "subject"])
                for h in self.history:
                    w.writerow([h.get("time", ""), h.get("score", ""), h.get("verdict", ""),
                                h.get("subject", "")])
            self.status.config(text=f"History exported to {path}")


def main():
    if tk is None:
        print("Tkinter is not installed. On Ubuntu: sudo apt install python3-tk")
        return
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
