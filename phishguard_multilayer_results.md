# PhishGuard AI — Multi-Layer Detection Pipeline

> Implementation complete. All 9 test cases verified.

---

## Files Changed / Created

| File | Action | Purpose |
|---|---|---|
| [`app.py`](file:///c:/Users/ibrahim%20dalvi/antigravity/PhishGuard/backend/app.py) | **Modified** | Wired all 7 layers; preserved all existing API fields; added new fields |
| [`domain_intelligence.py`](file:///c:/Users/ibrahim%20dalvi/antigravity/PhishGuard/backend/domain_intelligence.py) | **Created** | Layer 2 — DNS resolution, tldextract-based registrable domain, allowlist lookup |
| [`risk_engine.py`](file:///c:/Users/ibrahim%20dalvi/antigravity/PhishGuard/backend/risk_engine.py) | **Created** | Layers 3–6 — signal detection, weighted scoring, verdicts, explanations |
| [`known_legitimate_domains.json`](file:///c:/Users/ibrahim%20dalvi/antigravity/PhishGuard/backend/known_legitimate_domains.json) | **Created** | Layer 3 — maintainable JSON allowlist (~80 trusted registrable domains) |
| [`requirements.txt`](file:///c:/Users/ibrahim%20dalvi/antigravity/PhishGuard/backend/requirements.txt) | **Modified** | Added `tldextract==5.3.2`, `filelock==4.0.5`, `requests-file==3.0.1` |

> `feature_extractor.py` and `train_model.py` were **not modified**. The trained model `.pkl` was **not retrained**.

---

## Architecture: What Each Layer Does

```
POST /api/scan
     │
     ├── Layer 1: Random Forest ML model
     │     └── 40 URL features → phishing_probability (0–1)
     │         ML contributes MAX 40 points to final score (not 100)
     │
     ├── Layer 2: Domain Intelligence (domain_intelligence.py)
     │     ├── tldextract → registrable domain (google.com from www.google.com)
     │     ├── socket.gethostbyname → DNS resolution
     │     └── JSON allowlist lookup → is_known_legitimate
     │
     ├── Layer 3: Known-Legitimate Allowlist
     │     └── Match on REGISTRABLE DOMAIN ONLY
     │         google.com.evil.xyz → evil.xyz → NO MATCH ✓
     │         www.google.com → google.com → MATCH ✓
     │         Allowlist credit: −45 points
     │
     ├── Layer 4: Deterministic Suspicious Signals
     │     ├── Suspicious TLD (+15), IP address (+12), no HTTPS (+8)
     │     ├── Excessive hyphens (+8), subdomains (+6), long hostname (+5)
     │     ├── High entropy (+6), digit-heavy (+5), long URL (+5)
     │     ├── @ symbol (+10), encoded chars (+5), non-standard port (+5)
     │     ├── High keyword risk 3+ (+12), medium 1–2 (+6)
     │     └── URL shortener (+8), DNS not resolved (+10)
     │
     ├── Layer 5: Risk Score 0–100
     │     ├── score = ML(≤40) + allowlist(−45) + all signals
     │     ├── Clamped to [0, 100]
     │     ├── < 35 → Legitimate
     │     ├── 35–54 → Suspicious
     │     └── ≥ 55 → Phishing
     │
     ├── Layer 6: Explainability
     │     └── Human-readable reasons[] list
     │
     └── Layer 7: API compatibility
           └── All old fields preserved + new fields added
```

---

## Scoring Weight Table

| Signal | Weight |
|---|---|
| ML model | up to +40 |
| Known-legitimate domain | **−45** |
| Suspicious TLD | +15 |
| High keyword risk (3+) | +12 |
| IP address as hostname | +12 |
| DNS not resolved | +10 |
| @ symbol in URL | +10 |
| No HTTPS | +8 |
| Excessive hyphens | +8 |
| URL shortener | +8 |
| High hostname entropy | +6 |
| Excessive subdomains | +6 |
| Medium keyword risk (1–2) | +6 |
| Long hostname | +5 |
| Very long URL | +5 |
| Digit-heavy hostname | +5 |
| Has encoded characters | +5 |
| Non-standard port | +5 |

---

## Test Results Summary

| # | URL | ML Prob | Risk Score | Verdict | Key Signals |
|---|---|---|---|---|---|
| 1 | `https://google.com` | 99.07% | **0.0** | ✅ **Legitimate** | allowlist −45, HTTPS, no keywords |
| 2 | `https://github.com` | 99.4% | **0.0** | ✅ **Legitimate** | allowlist −45, HTTPS, no keywords |
| 3 | `https://microsoft.com` | 99.37% | **0.75** | ✅ **Legitimate** | allowlist −45, HTTPS |
| 4 | `https://apple.com` | 99.4% | **0.0** | ✅ **Legitimate** | allowlist −45, HTTPS, no keywords |
| 5 | `http://secure-login-account-verify.xyz/login` | 100% | **100.0** | 🚨 **Phishing** | suspicious TLD, no HTTPS, DNS fail, 3 hyphens, high entropy, 4 keywords |
| 6 | `https://www.google.com` | 1.65% | **0.0** | ✅ **Legitimate** | allowlist via google.com, HTTPS |
| 7 | `https://google.com.some-random-domain.xyz/login` | 100% | **76.0** | 🚨 **Phishing** | reg_domain=`some-random-domain.xyz`, NOT google.com; suspicious TLD, DNS fail |
| 8 | `http://192.168.1.10/login` | 100% | **71.0** | 🚨 **Phishing** | IP address, no HTTPS, digit-heavy, keyword |
| 9 | `http://secure-account-verify.xyz/login` | 100% | **85.0** | 🚨 **Phishing** | suspicious TLD, no HTTPS, DNS fail, 4 keywords |

> **The lookalike test (#7) is correctly handled**: `google.com.some-random-domain.xyz` is parsed by `tldextract` as registrable domain `some-random-domain.xyz`, NOT `google.com`. It gets no allowlist credit and scores 76 (Phishing).

---

## Commands to Restart Flask

```powershell
# 1. Stop any existing Flask process
#    (Ctrl+C in the terminal running app.py, or kill via Task Manager)

# 2. Activate the virtual environment
cd "c:\Users\ibrahim dalvi\antigravity\PhishGuard\backend"
.\venv\Scripts\Activate.ps1

# 3. Start Flask
python app.py
```

---

## PowerShell Commands to Test `/api/scan`

```powershell
# Test a known-legitimate domain
$body = '{"url": "https://google.com"}' | ConvertFrom-Json | ConvertTo-Json
Invoke-RestMethod -Method POST -Uri "http://127.0.0.1:5000/api/scan" `
  -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 5

# Test a phishing URL
$body = '{"url": "http://secure-login-account-verify.xyz/login"}' | ConvertFrom-Json | ConvertTo-Json
Invoke-RestMethod -Method POST -Uri "http://127.0.0.1:5000/api/scan" `
  -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 5

# Test the lookalike
$body = '{"url": "https://google.com.some-random-domain.xyz/login"}' | ConvertFrom-Json | ConvertTo-Json
Invoke-RestMethod -Method POST -Uri "http://127.0.0.1:5000/api/scan" `
  -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 5

# Simpler one-liner for any URL:
Invoke-RestMethod -Method POST -Uri "http://127.0.0.1:5000/api/scan" `
  -ContentType "application/json" `
  -Body '{"url": "https://REPLACE_ME"}' | ConvertTo-Json -Depth 5
```

---

## New API Response Fields

```json
{
  "verdict": "Legitimate | Suspicious | Phishing",
  "risk_score": 0.0,
  "model_probability": 99.07,
  "phishing_probability": 99.07,
  "legitimate_probability": 0.93,
  "prediction": 0,
  "domain_reputation": "known_legitimate | unknown",
  "domain_info": {
    "hostname": "google.com",
    "registrable_domain": "google.com",
    "subdomain": "",
    "tld": "com",
    "scheme": "https",
    "is_ip_address": false,
    "dns_resolved": true,
    "ip_address": "192.178.173.102",
    "allowlist_match": "google.com"
  },
  "signals": {
    "ml_model": "high_risk",
    "domain_reputation": "known_legitimate",
    "https": "enabled",
    "suspicious_tld": "not_detected",
    "keyword_risk": "none",
    "hostname_risk": "normal",
    "dns_resolved": true,
    "excessive_hyphens": false,
    "excessive_subdomains": false,
    "is_url_shortener": false,
    "at_symbol": false,
    "encoded_characters": false,
    "non_standard_port": false
  },
  "score_breakdown": {
    "ml_model": 39.63,
    "allowlist_credit": -45,
    "no_https": 0,
    "suspicious_tld": 0,
    "keyword_risk": 0
  },
  "reasons": [
    "ML model gives a high phishing probability (99.1%)",
    "Domain 'google.com' is present in the trusted domain list",
    "HTTPS is enabled",
    "TLD is commonly used by legitimate sites",
    "No phishing-related keywords detected in the URL"
  ],
  "features": { ... }
}
```

> [!IMPORTANT]
> The `model_probability` / `phishing_probability` field is preserved for debugging and transparency. It reflects the **raw Random Forest output**, NOT the multi-layer risk score. The authoritative verdict is determined by `risk_score` and `verdict`.

> [!NOTE]
> To expand the allowlist, edit [`known_legitimate_domains.json`](file:///c:/Users/ibrahim%20dalvi/antigravity/PhishGuard/backend/known_legitimate_domains.json) and add new registrable domains to the `"domains"` array. No code changes needed — Flask will pick up the updated list on restart.
