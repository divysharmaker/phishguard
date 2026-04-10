import re
import math
import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from pathlib import Path

# ── Load model once at import time ───────────────────────────
MODEL_PATH = Path(__file__).parent / "phishing_pipeline_v2.pkl"
model = joblib.load(MODEL_PATH)

# ── Constants ────────────────────────────────────────────────
TRUSTED_DOMAINS = {
    "microsoft.com","microsoftonline.com","live.com","outlook.com","office.com",
    "windows.com","azure.com","msn.com","bing.com",
    "google.com","gmail.com","youtube.com","googleapis.com","googleusercontent.com","gstatic.com",
    "apple.com","icloud.com",
    "facebook.com","instagram.com","whatsapp.com","meta.com","twitter.com","x.com","linkedin.com",
    "amazon.com","amazonaws.com","paypal.com",
    "bankofamerica.com","chase.com","wellsfargo.com","citibank.com",
    "sbi.co.in","hdfcbank.com","icicibank.com","axisbank.com",
    "github.com","stackoverflow.com","wikipedia.org","python.org","npmjs.com","pypi.org",
    "gov.in","nic.in","indianrailways.gov.in","uidai.gov.in",
    "netflix.com","spotify.com","adobe.com","dropbox.com","slack.com","zoom.us",
}

BRAND_LEGIT = {
    "paypal":      "paypal.com",
    "amazon":      "amazon.com",
    "google":      "google.com",
    "apple":       "apple.com",
    "facebook":    "facebook.com",
    "microsoft":   "microsoft.com",
    "netflix":     "netflix.com",
    "instagram":   "instagram.com",
    "whatsapp":    "whatsapp.com",
    "twitter":     "twitter.com",
    "ebay":        "ebay.com",
    "hdfc":        "hdfcbank.com",
    "sbi":         "sbi.co.in",
    "bankofindia": "bankofindia.co.in",
}

SUSPICIOUS_TLDS = {
    ".xyz",".tk",".ml",".ga",".cf",".gq",".pw",".top",
    ".click",".link",".online",".site",".info",
    ".ru",".co",".cc",".su",".to",".ws",
}

# ── Helpers ──────────────────────────────────────────────────
def _leet_normalize(s: str) -> str:
    return s.lower().translate(str.maketrans({"0":"o","1":"i","3":"e","5":"s","@":"a","!":"i","$":"s"}))

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

def _brand_mismatch_flags(hostname: str) -> list:
    h      = hostname.lower()
    h_norm = _leet_normalize(h)
    hits   = []
    for brand, legit in BRAND_LEGIT.items():
        if brand in h_norm:
            if not (h.endswith(legit) or h == legit or h.endswith("." + legit)):
                leet = brand not in h
                label = (
                    f"Leet/homoglyph brand impersonation: '{brand}' detected after normalisation"
                    if leet else
                    f"Brand-domain mismatch: '{brand}' on non-official domain"
                )
                hits.append((label, "hi"))
    return hits

# ── URL Risk Scoring ─────────────────────────────────────────
def compute_url_risk(url: str, parsed, hostname: str, path: str, full_url: str):
    score, flags = 0.0, []
    brand_kws  = ["paypal","amazon","google","apple","facebook","microsoft",
                  "netflix","bank","ebay","instagram","whatsapp","twitter","hdfc","sbi","bankofindia"]
    action_kws = ["login","signin","verify","secure","update","account",
                  "confirm","password","support","billing","checkout","reset"]
    hl, ul = hostname.lower(), full_url.lower()

    # 1. Homoglyph / leet-speak brand check
    for mf in _brand_mismatch_flags(hostname):
        flags.append(mf)
        score += 0.55

    # 2. Brand + action keyword combo
    bh = sum(1 for b in brand_kws  if b in hl)
    ah = sum(1 for a in action_kws if a in ul)
    if bh >= 1 and ah >= 1:
        score += 0.55
        flags.append((f"Brand impersonation + action keyword ({bh} brand, {ah} action)", "hi"))

    # 3. Dashes in hostname
    dc = hostname.count("-")
    if dc >= 2:   score += 0.20; flags.append((f"Multiple dashes in hostname ({dc})", "md"))
    elif dc == 1: score += 0.08; flags.append(("Dash in hostname", "lo"))

    # 4. Subdomain depth
    sd = max(0, len(hostname.split(".")) - 2)
    if sd >= 3:   score += 0.30; flags.append((f"Deep subdomain nesting ({sd} levels)", "hi"))
    elif sd == 2: score += 0.15; flags.append((f"Multiple subdomains ({sd} levels)", "md"))

    # 5. IP hostname
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        score += 0.40; flags.append(("IP address used as hostname", "hi"))

    # 6. Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            score += 0.20; flags.append((f"Suspicious TLD ({tld})", "md")); break

    # 7. URL length
    if len(full_url) > 100:  score += 0.15; flags.append((f"Very long URL ({len(full_url)} chars)", "lo"))
    elif len(full_url) > 75: score += 0.07; flags.append((f"Long URL ({len(full_url)} chars)", "lo"))

    # 8. @ in URL
    if "@" in full_url:
        score += 0.45; flags.append(("@ symbol — credential bypass trick", "hi"))

    # 9. Double slash in path
    path_only = re.sub(r"^https?://[^/]+", "", full_url)
    if "//" in path_only:
        score += 0.25; flags.append(("Double slash in path (open redirect)", "hi"))

    # 10. Hex encoding
    if re.search(r"%[0-9a-fA-F]{2}", full_url):
        score += 0.15; flags.append(("Hex/URL encoding obfuscation", "md"))

    # 11. High entropy (DGA)
    if url_entropy(hostname) > 4.0:
        e = url_entropy(hostname)
        score += 0.15; flags.append((f"High hostname entropy ({e:.2f}) — possible DGA domain", "md"))

    # 12. Non-standard port
    if parsed.port and parsed.port not in [80, 443, 8080]:
        score += 0.20; flags.append((f"Non-standard port: {parsed.port}", "md"))

    return min(1.0, score), flags

# ── ML Feature Extraction ────────────────────────────────────
def extract_features(url: str, hostname: str, path: str, full_url: str, parsed) -> dict:
    num_dots   = hostname.count(".")
    num_dash   = full_url.count("-")
    path_level = len([p for p in path.split("/") if p])
    iframe     = 1 if any(kw in full_url.lower() for kw in ["iframe","frame","embed","object"]) else 0
    ns  = max(0, len(hostname.split(".")) - 2)
    bh  = sum(1 for k in ["paypal","amazon","google","apple","facebook","microsoft",
                           "netflix","bank","ebay","hdfc","sbi"] if k in hostname.lower())
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

# ── Verdict ──────────────────────────────────────────────────
def get_verdict(final_proba: float, flags: list) -> str:
    if final_proba >= 0.35:                                      return "PHISHING"
    if final_proba >= 0.15:                                      return "SUSPICIOUS"
    if any(sev == "hi" for _, sev in flags):                     return "SUSPICIOUS"
    return "SAFE"

# ── Main entry point ─────────────────────────────────────────
def run_prediction(raw_url: str) -> dict:
    url      = normalize_url(raw_url)
    parsed   = urlparse(url)
    hostname = parsed.hostname or ""
    path     = parsed.path or ""

    # Parse URL anatomy for frontend display
    parts    = hostname.split(".")
    tld      = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
    anatomy  = {
        "scheme": parsed.scheme, "subdomain": subdomain,
        "domain": tld, "hostname": hostname,
        "path": path, "query": parsed.query or "",
    }

    # Trusted domains bypass ML
    if is_trusted(hostname):
        return {
            "url": url, "trusted": True,
            "model_proba": 0.0, "url_risk": 0.0,
            "final_proba": 0.0, "verdict": "TRUSTED",
            "flags": [], "features": {}, "anatomy": anatomy,
        }

    url_risk, flags = compute_url_risk(url, parsed, hostname, path, url)
    features        = extract_features(url, hostname, path, url, parsed)
    df              = pd.DataFrame([list(features.values())], columns=list(features.keys()))
    model_proba     = float(model.predict_proba(df)[0][1])
    final_proba     = min(1.0, 0.60 * url_risk + 0.40 * model_proba)
    verdict         = get_verdict(final_proba, flags)

    return {
        "url":          url,
        "trusted":      False,
        "model_proba":  round(model_proba, 4),
        "url_risk":     round(url_risk, 4),
        "final_proba":  round(final_proba, 4),
        "verdict":      verdict,
        "flags":        [{"text": t, "severity": s} for t, s in flags],
        "features":     features,
        "anatomy":      anatomy,
    }
