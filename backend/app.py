"""

PhishGuard AI - Flask Backend



ML + Domain Intelligence + Risk Engine + SSL + RDAP + PostgreSQL + Gemini AI

User authentication with PostgreSQL-backed sessions

Per-user scan history isolation

"""



from flask import Flask, request, jsonify

from flask_cors import CORS

from pathlib import Path

import os

import threading
import time
import queue

from dotenv import load_dotenv



# Explicitly load .env from backend directory, fallback to cwd

_backend_env = Path(__file__).resolve().parent / ".env"

if _backend_env.exists():

    load_dotenv(dotenv_path=_backend_env)

else:

    load_dotenv()



import joblib



from feature_extractor import extract_url_features

from domain_intelligence import get_domain_intelligence

from ssl_analyzer import analyze_ssl

from rdap_intelligence import lookup_rdap



from risk_engine import (

    compute_suspicious_signals,

    compute_risk_score,

    build_signal_summary,

)



from database import (

    initialize_database,

    create_user,

    authenticate_user,

    create_session,

    get_user_from_token,

    delete_session,

    save_scan,

    get_scan_history,

    delete_scan,

    clear_scan_history,

    change_user_password,

)



from ai_assistant import answer_chat





# =============================================================================

# APP

# =============================================================================



app = Flask(__name__)




CORS(
    app,
    resources={
        r"/*": {
            "origins": [
                "http://localhost:3000",
                "http://127.0.0.1:3000",
                "http://localhost:5173",
                "http://127.0.0.1:5173",
                "https://phish-guard-ai-topaz.vercel.app",
            ],
            "methods": ["GET", "POST", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
            "supports_credentials": True,
            "max_age": 86400,
        }
    },
    supports_credentials=True,
)





# =============================================================================

# DATABASE INITIALIZATION (background: do not block Gunicorn startup)

# =============================================================================



_db_error: str = ""

_db_ready: bool = False





def _initialize_database_background():

    global _db_error, _db_ready

    try:

        initialize_database()

        _db_error = ""

        _db_ready = True

        print("[OK] Database initialization completed.")

    except Exception as exc:

        _db_error = str(exc)

        _db_ready = False

        print(f"[WARN] Database initialization failed: {_db_error}")

        print("[WARN] Backend remains available; database-dependent features may be unavailable.")





# Start database initialization asynchronously so HTTP routes can register

# immediately even if PostgreSQL is slow or unavailable.

threading.Thread(

    target=_initialize_database_background,

    name="database-initializer",

    daemon=True,

).start()





# =============================================================================

# MODEL (background: do not block Gunicorn startup while downloading/loading)

# =============================================================================



MODEL_PATH = Path(__file__).resolve().parent / "phishing_model.pkl"



_model_error: str = ""

_model_loading: bool = True

model = None

FEATURE_COLUMNS: list = []

model_data = None





def _load_model_background():

    global _model_error, _model_loading, model, FEATURE_COLUMNS, model_data

    print(f"[DEBUG] Model loader started. PID={os.getpid()}", flush=True)

    try:

        if not MODEL_PATH.exists():

            import gdown



            drive_file_id = os.getenv(

                "MODEL_DRIVE_FILE_ID",

                "1Fd1DUO_a3LA73mWa926_mHPs_TFz7lwC",

            ).strip()

            if not drive_file_id:

                raise RuntimeError(

                    "Model file missing and MODEL_DRIVE_FILE_ID not configured."

                )



            print(f"[MODEL] Local model missing; downloading from Google Drive. Path={MODEL_PATH}", flush=True)

            downloaded_path = gdown.download(

                id=drive_file_id,

                output=str(MODEL_PATH),

                quiet=False,

            )

            if not downloaded_path or not MODEL_PATH.exists():

                raise RuntimeError("Failed to download phishing_model.pkl from Google Drive.")



        if MODEL_PATH.stat().st_size < 1_000_000:

            raise RuntimeError(

                "phishing_model.pkl is unexpectedly small "

                "(possible Google Drive permission page). "

                "Ensure the file is shared as 'Anyone with the link'."

            )



        
        # Load only after MODEL_PATH has been defined and the file is available.
        print("[MODEL] Starting joblib.load (mmap_mode='r')...", flush=True)
        loaded_data = joblib.load(MODEL_PATH, mmap_mode="r")
        print("[MODEL] joblib.load completed.", flush=True)
        loaded_model = loaded_data["model"]
        loaded_features = loaded_data["features"]



        model_data = loaded_data

        model = loaded_model

        FEATURE_COLUMNS = loaded_features

        _model_error = ""

        print(f"[OK] ML model loaded — {len(FEATURE_COLUMNS)} features.", flush=True)

    except Exception as exc:

        _model_error = str(exc)

        print(f"[ERROR] ML model failed to load: {_model_error}", flush=True)

        print("[WARN] /api/scan will return 503 until the model is available.", flush=True)

    finally:

        _model_loading = False





# Load lazily inside the request-serving process. Starting this thread at module
# import can run it in the Gunicorn master before workers fork, leaving workers
# with stale model=None / _model_loading=True state.
_model_load_lock = threading.Lock()


def _ensure_model_loaded():
    global _model_loading
    if model is not None or _model_error:
        return
    with _model_load_lock:
        if model is None and not _model_error:
            _model_loading = True
            _load_model_background()





# =============================================================================

# AUTHENTICATION HELPERS

# =============================================================================



def current_user():

    """

    Read Bearer token from Authorization header

    and retrieve the logged-in user from PostgreSQL.

    """



    header = request.headers.get(

        "Authorization",

        ""

    ).strip()



    if not header.lower().startswith("bearer "):

        return None



    token = header[7:].strip()



    if not token:

        return None



    return get_user_from_token(token)





def require_user():

    return current_user()





# =============================================================================

# HEALTH CHECK

# =============================================================================



@app.route("/", methods=["GET"])

def home():



    return jsonify({

        "status": "success",

        "message": "PhishGuard AI Backend is running",

        "version": "4.0.0-postgresql"

    })





# =============================================================================

# REGISTER

# =============================================================================



@app.route("/api/register", methods=["POST"])

def register():



    data = request.get_json(silent=True) or {}



    email = str(

        data.get("email", "")

    ).strip().lower()



    password = str(

        data.get("password", "")

    )



    if not email or not password:



        return jsonify({

            "status": "error",

            "message": "Email and password are required."

        }), 400



    if len(password) < 6:



        return jsonify({

            "status": "error",

            "message": "Password must be at least 6 characters."

        }), 400



    try:



        user_id = create_user(

            email,

            password

        )



        return jsonify({

            "status": "success",

            "message": "Account created successfully.",

            "user": {

                "id": user_id,

                "email": email

            }

        }), 201



    except ValueError as error:



        return jsonify({

            "status": "error",

            "message": str(error)

        }), 409



    except Exception as error:



        print("Registration error:", error)



        return jsonify({

            "status": "error",

            "message": "Unable to create account.",

            "error": str(error)

        }), 500





# =============================================================================

# LOGIN

# =============================================================================



@app.route("/api/login", methods=["POST"])

def login():



    data = request.get_json(silent=True) or {}



    email = str(

        data.get("email", "")

    ).strip().lower()



    password = str(

        data.get("password", "")

    )



    if not email or not password:



        return jsonify({

            "status": "error",

            "message": "Email and password are required."

        }), 400



    try:



        user = authenticate_user(

            email,

            password

        )



        if not user:



            return jsonify({

                "status": "error",

                "message": "Invalid email or password."

            }), 401



        token = create_session(

            user["id"]

        )



        return jsonify({

            "status": "success",

            "message": "Login successful.",

            "token": token,

            "user": user

        }), 200



    except Exception as error:



        print("Login error:", error)



        return jsonify({

            "status": "error",

            "message": "Unable to create login session.",

            "error": str(error)

        }), 500





# =============================================================================

# CURRENT USER

# =============================================================================



@app.route("/api/me", methods=["GET"])

def me():



    user = require_user()



    if not user:



        return jsonify({

            "status": "error",

            "message": "Authentication required."

        }), 401



    return jsonify({

        "status": "success",

        "user": user

    }), 200





# =============================================================================

# LOGOUT

# =============================================================================



@app.route("/api/logout", methods=["POST"])

def logout():



    header = request.headers.get(

        "Authorization",

        ""

    ).strip()



    if header.lower().startswith("bearer "):



        token = header[7:].strip()



        if token:



            try:

                delete_session(token)



            except Exception as error:

                print("Logout error:", error)



    return jsonify({

        "status": "success",

        "message": "Logged out successfully."

    }), 200





# =============================================================================

# CHANGE PASSWORD

# =============================================================================



@app.route("/api/change-password", methods=["POST"])

def change_password():

    user = require_user()

    if not user:

        return jsonify({

            "status": "error",

            "message": "Authentication required."

        }), 401



    data = request.get_json(silent=True) or {}

    current_password = str(data.get("current_password", ""))

    new_password = str(data.get("new_password", ""))



    if not current_password or not new_password:

        return jsonify({

            "status": "error",

            "message": "Current and new passwords are required."

        }), 400



    if len(new_password) < 6:

        return jsonify({

            "status": "error",

            "message": "Password must be at least 6 characters."

        }), 400



    try:

        change_user_password(user["id"], current_password, new_password)

        return jsonify({

            "status": "success",

            "message": "Password changed successfully."

        }), 200

    except ValueError as err:

        return jsonify({

            "status": "error",

            "message": str(err)

        }), 400

    except Exception as err:

        print("Change password error:", err)

        return jsonify({

            "status": "error",

            "message": "Unable to change password.",

            "error": str(err)

        }), 500



# =============================================================================

# HEALTH CHECK

# =============================================================================



@app.route("/api/health", methods=["GET"])

def health_check():
    _ensure_model_loaded()
    print(
        f"[DEBUG] Health PID={os.getpid()}, "
        f"model_ready={model is not None}, "
        f"model_loading={_model_loading}",
        flush=True,
    )

    status = (
        "ok"
        if model is not None and not _model_loading and not _model_error and not _db_error
        else "degraded"
    )

    body = {

        "status": status,

        "service": "PhishGuard AI",

        "model_ready": model is not None,

        "db_ready": _db_ready,

        "model_loading": _model_loading,

    }

    if _model_error:

        body["model_error"] = _model_error

    if _db_error:

        body["db_error"] = _db_error

    # Always return 200 so the frontend health check doesn't mark the backend

    # as offline just because the model is still downloading.

    return jsonify(body), 200





# =============================================================================



# URL SCAN

# Bounded execution for network-dependent intelligence stages.
def _call_with_timeout(func, args=(), timeout=5, stage="stage", fallback=None):
    result_queue = queue.Queue(maxsize=1)
    def _runner():
        try: result_queue.put((True, func(*args)))
        except Exception as exc: result_queue.put((False, exc))
    worker = threading.Thread(target=_runner, name=f"scan-{stage}", daemon=True)
    started = time.monotonic()
    worker.start(); worker.join(timeout)
    elapsed = round(time.monotonic() - started, 2)
    if worker.is_alive():
        print(f"[SCAN] {stage} timed out after {elapsed}s; using fallback.", flush=True)
        return fallback
    try: ok, value = result_queue.get_nowait()
    except queue.Empty:
        print(f"[SCAN] {stage} returned no result after {elapsed}s; using fallback.", flush=True)
        return fallback
    if not ok:
        print(f"[SCAN] {stage} failed after {elapsed}s: {value}", flush=True)
        return fallback
    print(f"[SCAN] {stage} completed in {elapsed}s.", flush=True)
    return value

def _fallback_domain_intelligence(url):
    from urllib.parse import urlparse
    parsed = urlparse(url); hostname = (parsed.hostname or "").lower()
    labels = hostname.split("."); registrable = ".".join(labels[-2:]) if len(labels) >= 2 else hostname
    return {"hostname": hostname, "registrable_domain": registrable, "subdomain": "",
            "tld": labels[-1] if labels else "", "scheme": parsed.scheme.lower(),
            "is_ip_address": False, "dns_resolved": False, "ip_address": None,
            "is_known_legitimate": False, "allowlist_entry": None, "hostname_entropy": 0.0,
            "suspicious_flags": ["intelligence_timeout"],
            "brand_impersonation": {"detected": False, "brand": None, "confidence": 0,
                "matched_text": None, "reason": None, "legitimate_domain": None,
                "match_type": None, "has_context": False}}

def _fallback_rdap(domain):
    return {"available": False, "status": "unknown", "domain": domain, "registrar": None,
            "registration_date": None, "expiration_date": None, "domain_age_days": None,
            "days_until_expiry": None, "nameservers": [], "rdap_source": None,
            "error": "RDAP lookup timed out or failed"}

def _fallback_ssl(url):
    from urllib.parse import urlparse
    is_https = urlparse(url).scheme.lower() == "https"
    return {"https_enabled": is_https, "certificate_available": False, "certificate_valid": False,
            "hostname_match": False, "issuer": None, "subject": None, "valid_from": None,
            "valid_until": None, "days_until_expiry": None, "status": "timeout_or_unavailable",
            "error": "SSL analysis timed out or failed"}


# =============================================================================



@app.route("/api/scan", methods=["POST"])

def scan_url():
    scan_started = time.monotonic()
    print("[SCAN] Scan request received.", flush=True)

    _ensure_model_loaded()

    # Guard: model must be loaded before scanning

    if model is None:

        if _model_loading:

            message = "ML model is still downloading or loading. Please retry shortly."

        else:

            message = f"ML model is not available: {_model_error or 'unknown error'}."

        return jsonify({

            "status": "error",

            "message": message,

        }), 503



    data = request.get_json(silent=True) or {}



    url = str(

        data.get("url", "")

    ).strip()



    if not url:



        return jsonify({

            "status": "error",

            "message": "URL is required."

        }), 400



    if not url.startswith(("http://", "https://")):

        url = "https://" + url



    try:



        # =====================================================================

        # ML FEATURE EXTRACTION

        # =====================================================================



        features = extract_url_features(url)



        feature_values = [

            features[column]

            for column in FEATURE_COLUMNS

        ]



        ml_prediction = model.predict(

            [feature_values]

        )[0]



        probabilities = model.predict_proba(

            [feature_values]

        )[0]



        classes = list(

            model.classes_

        )



        phishing_prob = float(

            probabilities[

                classes.index(0)

            ]

        )



        legitimate_prob = float(

            probabilities[

                classes.index(1)

            ]

        )



        # =====================================================================

        # DOMAIN INTELLIGENCE

        # =====================================================================



        domain_intel = _call_with_timeout(get_domain_intelligence, args=(url,), timeout=5, stage="domain_intelligence", fallback=_fallback_domain_intelligence(url))



        # =====================================================================

        # RDAP

        # =====================================================================



        registrable_domain = domain_intel.get(

            "registrable_domain"

        )



        rdap_info = _call_with_timeout(lookup_rdap, args=(registrable_domain,), timeout=5, stage="rdap", fallback=_fallback_rdap(registrable_domain))



        # =====================================================================

        # SSL ANALYSIS

        # =====================================================================



        ssl_analysis = _call_with_timeout(analyze_ssl, args=(url,), timeout=4, stage="ssl_analysis", fallback=_fallback_ssl(url))



        # =====================================================================

        # SUSPICIOUS SIGNALS

        # =====================================================================



        signals = compute_suspicious_signals(

            url,

            domain_intel

        )



        signals["_ml_prob"] = phishing_prob



        # =====================================================================

        # RISK ENGINE

        # =====================================================================



        result = compute_risk_score(

            ml_phishing_probability=phishing_prob,

            domain_intel=domain_intel,

            signals=signals,

            ssl_analysis=ssl_analysis

        )



        final_risk_score = float(

            result["risk_score"]

        )



        verdict = result["verdict"]



        reasons = result["reasons"]



        signal_breakdown = result[

            "signal_breakdown"

        ]



        # =====================================================================

        # SIGNAL SUMMARY

        # =====================================================================



        signal_summary = build_signal_summary(

            signals,

            domain_intel,

            ssl_analysis

        )



        # =====================================================================

        # SAVE SCAN TO POSTGRESQL (best-effort; non-blocking)

        # =====================================================================



        scan_id = None

        try:

            scan_id = save_scan(

                user_id=None,

                url=url,

                verdict=verdict,

                risk_score=final_risk_score,

                phishing_probability=round(

                    phishing_prob * 100,

                    2

                ),

                legitimate_probability=round(

                    legitimate_prob * 100,

                    2

                ),

                domain=(

                    domain_intel.get("hostname")

                    or domain_intel.get("registrable_domain")

                    or ""

                )

            )

        except Exception as db_err:

            # DB save failure is logged but does not block the scan response.

            print("Database error in save_scan (non-fatal):", db_err)





        # =====================================================================

        # RESPONSE

        # =====================================================================

        print(f"[SCAN] Completed full scan in {time.monotonic() - scan_started:.2f}s.", flush=True)

        return jsonify({



            "status": "success",



            "scan_id": scan_id,



            "user_id": None,



            "url": url,



            "verdict": verdict,



            "risk_score": final_risk_score,



            "model_probability": round(

                phishing_prob * 100,

                2

            ),



            "phishing_probability": round(

                phishing_prob * 100,

                2

            ),



            "legitimate_probability": round(

                legitimate_prob * 100,

                2

            ),



            "prediction": int(

                ml_prediction

            ),



            "domain_reputation": (

                "known_legitimate"

                if domain_intel.get(

                    "is_known_legitimate"

                )

                else "unknown"

            ),



            "domain_info": domain_intel,



            "rdap": rdap_info,



            "ssl_analysis": ssl_analysis,



            "signals": signal_summary,



            "score_breakdown": signal_breakdown,



            "reasons": reasons,



            "features": features



        }), 200



    except Exception as error:



        print(f"[SCAN] Failed after {time.monotonic() - scan_started:.2f}s: {error}", flush=True)



        return jsonify({

            "status": "error",

            "message": "Unable to analyze URL.",

            "error": str(error)

        }), 500





# =============================================================================

# USER SCAN HISTORY

# =============================================================================



@app.route("/api/history", methods=["GET"])

def history():



    user = require_user()



    if not user:



        return jsonify({

            "status": "error",

            "message": "Authentication required."

        }), 401



    try:



        scans = get_scan_history(

            user_id=user["id"],

            limit=100

        )



        return jsonify({

            "status": "success",

            "scans": scans

        }), 200



    except Exception as error:



        print("History error:", error)



        return jsonify({

            "status": "error",

            "message": "Unable to load scan history.",

            "error": str(error)

        }), 500





# =============================================================================

# DELETE ONE SCAN

# =============================================================================



@app.route("/api/history/<int:scan_id>", methods=["DELETE"])

def delete_history_item(scan_id):



    user = require_user()



    if not user:



        return jsonify({

            "status": "error",

            "message": "Authentication required."

        }), 401



    try:



        deleted = delete_scan(

            user_id=user["id"],

            scan_id=scan_id

        )



        if not deleted:



            return jsonify({

                "status": "error",

                "message": "Scan not found."

            }), 404



        return jsonify({

            "status": "success",

            "message": "Scan deleted successfully."

        }), 200



    except Exception as error:



        print("Delete scan error:", error)



        return jsonify({

            "status": "error",

            "message": "Unable to delete scan.",

            "error": str(error)

        }), 500





# =============================================================================

# CLEAR USER HISTORY

# =============================================================================



@app.route("/api/history", methods=["DELETE"])

def clear_history():



    user = require_user()



    if not user:



        return jsonify({

            "status": "error",

            "message": "Authentication required."

        }), 401



    try:



        deleted_count = clear_scan_history(

            user_id=user["id"]

        )



        return jsonify({

            "status": "success",

            "message": "Scan history cleared successfully.",

            "deleted_count": deleted_count

        }), 200



    except Exception as error:



        print("Clear history error:", error)



        return jsonify({

            "status": "error",

            "message": "Unable to clear scan history.",

            "error": str(error)

        }), 500





# =============================================================================

# AI CHAT

# =============================================================================



@app.route("/api/chat", methods=["POST"])

def chat():



    data = request.get_json(

        silent=True

    ) or {}



    message = str(

        data.get("message", "")

    ).strip()



    if not message:



        return jsonify({

            "status": "error",

            "message": "Message is required."

        }), 400



    try:



        reply = answer_chat(

            message=message,

            history=data.get("history") or [],

            scan_context=data.get("scan_context")

        )



        return jsonify({

            "status": "success",

            "reply": reply

        }), 200



    except RuntimeError as error:



        return jsonify({

            "status": "error",

            "message": str(error)

        }), 503



    except Exception as error:



        print("AI chat error:", error)



        return jsonify({

            "status": "error",

            "message": "AI assistant is temporarily unavailable.",

            "error": str(error)

        }), 500





# =============================================================================

# RUN

# =============================================================================



if __name__ == "__main__":

    import sys

    port = int(os.getenv("PORT", 5000))

    debug = os.getenv("FLASK_DEBUG", "true").lower() == "true"

    app.run(

        host="0.0.0.0",

        port=port,

        debug=debug



    )