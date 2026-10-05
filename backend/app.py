"""
PhishGuard AI - Flask Backend

ML + Domain Intelligence + Risk Engine + SSL + RDAP + PostgreSQL + Gemini AI
User authentication with PostgreSQL-backed sessions
Per-user scan history isolation
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from pathlib import Path

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
)

from ai_assistant import answer_chat


# =============================================================================
# APP
# =============================================================================

app = Flask(__name__)

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": "*"
        }
    },
    methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


# =============================================================================
# DATABASE INITIALIZATION
# =============================================================================

initialize_database()


# =============================================================================
# MODEL
# =============================================================================

MODEL_PATH = Path(__file__).resolve().parent / "phishing_model.pkl"

model_data = joblib.load(MODEL_PATH)

model = model_data["model"]

# IMPORTANT:
# FEATURE_COLUMNS comes from the trained model file,
# NOT from feature_extractor.py.
FEATURE_COLUMNS = model_data["features"]


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
# URL SCAN
# =============================================================================

@app.route("/api/scan", methods=["POST"])
def scan_url():

    user = require_user()

    if not user:

        return jsonify({
            "status": "error",
            "message": "Authentication required."
        }), 401

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

        domain_intel = get_domain_intelligence(
            url
        )

        # =====================================================================
        # RDAP
        # =====================================================================

        registrable_domain = domain_intel.get(
            "registrable_domain"
        )

        rdap_info = lookup_rdap(
            registrable_domain
        )

        # =====================================================================
        # SSL ANALYSIS
        # =====================================================================

        ssl_analysis = analyze_ssl(
            url
        )

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
        # SAVE SCAN TO POSTGRESQL
        # =====================================================================

        scan_id = save_scan(
            user_id=user["id"],
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

        # =====================================================================
        # RESPONSE
        # =====================================================================

        return jsonify({

            "status": "success",

            "scan_id": scan_id,

            "user_id": user["id"],

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

        print("Scan error:", error)

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

    user = require_user()

    if not user:

        return jsonify({
            "status": "error",
            "message": "Authentication required."
        }), 401

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

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )