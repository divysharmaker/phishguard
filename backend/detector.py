import re
import math
import joblib
import numpy as np
import pandas as pd
import httpx
import asyncio
import os
from urllib.parse import urlparse
from pathlib import Path
from difflib import SequenceMatcher

# ── Load model once at import time ───────────────────────────
MODEL_PATH = Path(__file__).parent / "phishing_pipeline_v2.pkl"
model = joblib.load(MODEL_PATH)

# ── VirusTotal API ────────────────────────────────────────────
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

async def check_virustotal(url: str) -> dict:
    """Check URL against VirusTotal API"""
    if not VT_API_KEY:
        return {"checked": False, "malicious": 0, "suspicious": 0, "harmless": 0}
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        async with httpx.AsyncClient(timeout=8.0) as client:
            res = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": VT_API_KEY}
            )
            if res.status_code == 200:
                data = res.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "checked":    True,
                    "malicious":  stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless":   stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                }
            elif res.status_code == 404:
                # URL not in VT database yet — submit it
                async with httpx.AsyncClient(timeout=8.0) as c2:
                    await c2.post(
                        "https://www.virustotal.com/api/v3/urls",
                        headers={"x-apikey": VT_API_KEY},
                        data={"url": url}
                    )
                return {"checked": False, "malicious": 0, "suspicious": 0, "harmless": 0}
    except Exception:
        return {"checked": False, "malicious": 0, "suspicious": 0, "harmless": 0}

# ── Trusted domains whitelist ────────────────────────────────
TRUSTED_DOMAINS = {
    "microsoft.com","microsoftonline.com","live.com","outlook.com","office.com",
    "windows.com","azure.com","msn.com","bing.com","office365.com",
    "google.com","gmail.com","youtube.com","googleapis.com","googleusercontent.com",
    "gstatic.com","google.co.in","google.in","play.google.com","accounts.google.com",
    "apple.com","icloud.com","appleid.apple.com",
    "facebook.com","instagram.com","whatsapp.com","meta.com","fb.com","messenger.com",
    "twitter.com","x.com","linkedin.com","reddit.com","pinterest.com","snapchat.com",
    "amazon.com","amazon.in","flipkart.com","ebay.com","myntra.com","meesho.com",
    "paypal.com","paytm.com","phonepe.com","gpay.com","razorpay.com","upi.npci.org.in",
    "sbi.co.in","hdfcbank.com","icicibank.com","axisbank.com","kotak.com",
    "bankofbaroda.in","pnbindia.in","canarabank.in","unionbankofindia.co.in",
    "bankofindia.co.in","indianbank.in",
    "gov.in","nic.in","indianrailways.gov.in","uidai.gov.in","irctc.co.in",
    "incometax.gov.in","gst.gov.in","mca.gov.in","epfindia.gov.in",
    "github.com","stackoverflow.com","wikipedia.org","python.org","npmjs.com",
    "pypi.org","cloudflare.com","netlify.app","vercel.app","heroku.com",
    "netflix.com","spotify.com","hotstar.com","primevideo.com","jiocinema.com",
    "adobe.com","dropbox.com","slack.com","zoom.us","notion.so","figma.com",
    "canva.com","trello.com","atlassian.com","jira.com",
    "coursera.org","udemy.com","edx.org","khanacademy.org","nptel.ac.in",
    "ndtv.com","timesofindia.com","hindustantimes.com","thehindu.com","indiatoday.in",
    "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","short.link","is.gd",
}

BRAND_LEGIT = {
    "paypal": "paypal.com", "amazon": "amazon.com", "google": "google.com",
    "apple": "apple.com", "facebook": "facebook.com", "microsoft": "microsoft.com",
    "netflix": "netflix.com", "instagram": "instagram.com", "whatsapp": "whatsapp.com",
    "twitter": "twitter.com", "ebay": "ebay.com", "hdfc": "hdfcbank.com",
    "sbi": "sbi.co.in", "icici": "icicibank.com", "axis": "axisbank.com",
    "paytm": "paytm.com", "flipkart": "flipkart.com", "irctc": "irctc.co.in",
    "linkedin": "linkedin.com", "youtube": "youtube.com", "gmail": "gmail.com",
    "outlook": "outlook.com",
}

TYPOSQUATS = {
    "paypa1.com","paypa1.net","paypai.com","paypol.com","pay-pal.com",
    "arnazon.com","amazoon.com","amaz0n.com","amazon-india.com",
    "g00gle.com","gooogle.com","googel.com",
    "micros0ft.com","microsofl.com","microsofft.com",
    "faceb00k.com","facebok.com","faceboook.com",
    "lnstagram.com","instagran.com","inst4gram.com",
    "netfl1x.com","netfix.com","netlfix.com",
    "yout0be.com","youtobe.com","youtubbe.com",
}

SUSPICIOUS_TLDS = {
    ".xyz",".tk",".ml",".ga",".cf",".gq",".pw",".top",
    ".click",".link",".online",".site",
    ".ru",".cc",".su",".to",".ws",".biz",
}

def _leet_normalize(s: str) -> str:
    return s.lower().translate(str.maketrans({
        "0":"o","1":"i","3":"e","5":"s","@":"a","!":"i","$":"s","4":"a","7":"t","9":"g"
    }))

def url_entropy(s: str) -> float:
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f/n) * math.log2(f/n) for f in freq.values())

def normalize_url(raw: str) -> str:
    raw = raw.strip()
    raw = re.sub(r"^[a-zA-Z]{1,5}://", "", raw)
    return raw if re.match(r"^https?://", raw) else "http://" + raw

def is_trusted(hostname: str) -> bool:
    h = hostname.lower().lstrip("www.")
    return any(h == t or h.endswith("." + t) for t in TRUSTED_DOMAINS)

def _typosquatting_check(hostname: str) -> list:
    flags = []
    h = hostname.lower().lstrip("www.")
    if h in TYPOSQUATS:
        flags.append((f"Known typosquatted domain: {h}", "hi"))
        return flags
    domain_part = h.split(".")[0]
    domain_norm = _leet_normalize(domain_part)
    for brand in BRAND_LEGIT.keys():
        legit_domain = BRAND_LEGIT[brand].split(".")[0]
        if domain_part == legit_domain:
            continue
        ratio = SequenceMatcher(None, domain_norm, brand).ratio()
        if 0.75 <= ratio < 1.0 and len(domain_part) >= len(brand) - 2:
            flags.append((f"Possible typosquat of '{brand}' (similarity: {ratio:.0%})", "hi"))
            break
        if brand in domain_norm and domain_norm != brand:
            flags.append((f"Brand '{brand}' inside suspicious domain", "hi"))
            break
    return flags

def _brand_mismatch_flags(hostname: str) -> list:
    h = hostname.lower()
    h_norm = _leet_normalize(h)
    hits = []
    for brand, legit in BRAND_LEGIT.items():
        if brand in h_norm:
            if not (h.endswith(legit) or h == legit or h.endswith("." + legit)):
                leet = brand not in h
                label = (f"Leet/homoglyph brand impersonation: '{brand}'" if leet
                         else f"Brand-domain mismatch: '{brand}' on non-official domain")
                hits.append((label, "hi"))
    return hits

def compute_url_risk(url: str, parsed, hostname: str, path: str, full_url: str):
    score, flags = 0.0, []
    brand_kws  = list(BRAND_LEGIT.keys())
    action_kws = ["login","signin","verify","secure","update","account",
                  "confirm","password","support","billing","checkout","reset",
                  "suspend","alert","urgent","limited","access","validate"]
    hl, ul = hostname.lower(), full_url.lower()

    typo_flags = _typosquatting_check(hostname)
    for tf in typo_flags:
        flags.append(tf); score += 0.65

    if not typo_flags:
        for mf in _brand_mismatch_flags(hostname):
            flags.append(mf); score += 0.55

    bh = sum(1 for b in brand_kws if b in hl)
    ah = sum(1 for a in action_kws if a in ul)
    if bh >= 1 and ah >= 1:
        score += 0.55
        flags.append(("Brand impersonation + action keyword combo", "hi"))

    dc = hostname.count("-")
    if dc >= 2:   score += 0.20; flags.append((f"Multiple dashes in hostname ({dc})", "md"))
    elif dc == 1: score += 0.05

    sd = max(0, len(hostname.split(".")) - 2)
    if sd >= 3:   score += 0.30; flags.append((f"Deep subdomain nesting ({sd} levels)", "hi"))
    elif sd == 2: score += 0.10; flags.append(("Multiple subdomains", "md"))

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        score += 0.50; flags.append(("IP address used as hostname", "hi"))

    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            score += 0.20; flags.append((f"Suspicious TLD ({tld})", "md")); break

    if len(full_url) > 150:  score += 0.15; flags.append((f"Very long URL ({len(full_url)} chars)", "lo"))
    elif len(full_url) > 100: score += 0.05

    if "@" in full_url:
        score += 0.45; flags.append(("@ symbol — credential bypass trick", "hi"))

    path_only = re.sub(r"^https?://[^/]+", "", full_url)
    if "//" in path_only:
        score += 0.25; flags.append(("Double slash in path (open redirect)", "hi"))

    if re.search(r"%[0-9a-fA-F]{2}", full_url):
        score += 0.15; flags.append(("Hex/URL encoding obfuscation", "md"))

    ent = url_entropy(hostname)
    if ent > 4.2:
        score += 0.15; flags.append((f"High hostname entropy ({ent:.2f}) — possible DGA domain", "md"))

    if parsed.port and parsed.port not in [80, 443, 8080]:
        score += 0.20; flags.append((f"Non-standard port: {parsed.port}", "md"))

    return min(1.0, score), flags

def extract_features(url: str, hostname: str, path: str, full_url: str, parsed) -> dict:
    num_dots   = hostname.count(".")
    num_dash   = full_url.count("-")
    path_level = len([p for p in path.split("/") if p])
    iframe     = 1 if any(kw in full_url.lower() for kw in ["iframe","frame","embed","object"]) else 0
    ns  = max(0, len(hostname.split(".")) - 2)
    bh  = sum(1 for k in BRAND_LEGIT.keys() if k in hostname.lower())
    pct_ext   = min(1.0, round(ns*0.15 + hostname.count("-")*0.08 + bh*0.20 + (0.10 if num_dots > 2 else 0), 2))
    m         = sum(1 for p in ["login","signin","verify","secure","update","account","banking",
                                 "confirm","password","free","click","paypal","amazon","apple",
                                 "support","reset"] if p in full_url.lower())
    pct_redir = min(1.0, round(m * 0.15, 2))
    return {
        "PctExtHyperlinks":                   pct_ext,
        "PctExtNullSelfRedirectHyperlinksRT": pct_redir,
        "NumDash":                            num_dash,
        "PathLevel":                          path_level,
        "NumDots":                            num_dots,
        "IframeOrFrame":                      iframe,
    }

def get_verdict(final_proba: float, flags: list, vt: dict) -> str:
    # VirusTotal override — if VT says malicious, trust it
    if vt.get("checked") and vt.get("malicious", 0) >= 2:
        return "PHISHING"
    if vt.get("checked") and vt.get("malicious", 0) == 1:
        return "SUSPICIOUS"
    # If VT says harmless and our score is low, trust VT
    if vt.get("checked") and vt.get("harmless", 0) >= 5 and final_proba < 0.35:
        return "SAFE"

    hi_flags = [f for f, s in flags if s == "hi"]
    if final_proba >= 0.35 or len(hi_flags) >= 2: return "PHISHING"
    if final_proba >= 0.15 or len(hi_flags) >= 1: return "SUSPICIOUS"
    return "SAFE"

async def run_prediction_async(raw_url: str) -> dict:
    url      = normalize_url(raw_url)
    parsed   = urlparse(url)
    hostname = parsed.hostname or ""
    path     = parsed.path or ""

    parts     = hostname.split(".")
    tld       = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
    anatomy   = {
        "scheme": parsed.scheme, "subdomain": subdomain,
        "domain": tld, "hostname": hostname,
        "path": path, "query": parsed.query or "",
    }

    if is_trusted(hostname):
        return {
            "url": url, "trusted": True,
            "model_proba": 0.0, "url_risk": 0.0,
            "final_proba": 0.0, "verdict": "TRUSTED",
            "flags": [], "features": {}, "anatomy": anatomy,
            "virustotal": {"checked": False},
        }

    # Run ML + VirusTotal in parallel
    url_risk, flags = compute_url_risk(url, parsed, hostname, path, url)
    features        = extract_features(url, hostname, path, url, parsed)
    df              = pd.DataFrame([list(features.values())], columns=list(features.keys()))
    model_proba     = float(model.predict_proba(df)[0][1])
    final_proba     = min(1.0, 0.60 * url_risk + 0.40 * model_proba)

    vt = await check_virustotal(url)
    verdict = get_verdict(final_proba, flags, vt)

    return {
        "url":         url,
        "trusted":     False,
        "model_proba": round(model_proba, 4),
        "url_risk":    round(url_risk, 4),
        "final_proba": round(final_proba, 4),
        "verdict":     verdict,
        "flags":       [{"text": t, "severity": s} for t, s in flags],
        "features":    features,
        "anatomy":     anatomy,
        "virustotal":  vt,
    }

def run_prediction(raw_url: str) -> dict:
    return asyncio.run(run_prediction_async(raw_url))