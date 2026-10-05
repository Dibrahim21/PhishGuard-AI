"""
ai_assistant.py - Real PhishGuard Gemini AI Security Assistant

Uses Google's Gemini API from the Flask backend.

Required environment variables:

    GEMINI_API_KEY

Optional:

    GEMINI_MODEL=gemini-2.5-flash-lite
"""

import os
from typing import Any, Dict, List, Optional

from google import genai
from google.genai import types

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


DEFAULT_MODEL = os.getenv(
    "GEMINI_MODEL",
    "gemini-2.5-flash-lite"
)


SYSTEM_INSTRUCTIONS = """
You are Sentinel, the AI Security Assistant inside PhishGuard AI.

Your job is defensive cybersecurity assistance.

Explain:
- phishing
- malicious URLs
- domain intelligence
- SSL/TLS
- RDAP
- DNS
- brand impersonation
- URL features
- cybersecurity concepts

When PhishGuard scan context is supplied, treat it as the primary
source for statements about that specific URL.

Clearly distinguish observed scan facts from general cybersecurity advice.

Never invent scan results, certificate details, domain age, registrar data,
DNS results, or detection reasons that are not present in the supplied data.

If data is unavailable, say that it is unavailable.

Explain technical findings in simple language first, then add technical
detail when useful.

Give defensive, authorized cybersecurity guidance.

Do not provide instructions for credential theft, malware deployment,
evasion, persistence, or unauthorized access.

Do not claim that you actually blocked or quarantined a domain unless the
backend explicitly reports that an action was performed.

Keep normal answers concise and useful.
"""


def _client():
    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY is not configured on the PhishGuard backend."
        )

    return genai.Client(
        api_key=api_key
    )


def answer_chat(
    message: str,
    history: Optional[List[Dict[str, Any]]] = None,
    scan_context: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Generate a real Gemini AI response.

    history:
        [
            {"role": "user", "content": "..."},
            {"role": "assistant", "content": "..."}
        ]

    scan_context:
        Optional result from POST /api/scan.
    """

    client = _client()

    # ---------------------------------------------------------
    # Build compact scan context
    # ---------------------------------------------------------

    context_text = "No URL scan context was supplied."

    if scan_context:

        compact = {
            "url": scan_context.get("url"),
            "verdict": scan_context.get("verdict"),
            "risk_score": scan_context.get("risk_score"),
            "phishing_probability": scan_context.get(
                "phishing_probability"
            ),
            "legitimate_probability": scan_context.get(
                "legitimate_probability"
            ),
            "domain_info": scan_context.get(
                "domain_info"
            ),
            "ssl_analysis": scan_context.get(
                "ssl_analysis"
            ),
            "signals": scan_context.get(
                "signals"
            ),
            "score_breakdown": scan_context.get(
                "score_breakdown"
            ),
            "reasons": scan_context.get(
                "reasons"
            ),
        }

        context_text = str(compact)[:16000]

    # ---------------------------------------------------------
    # Build conversation history
    # ---------------------------------------------------------

    history_text = ""

    for item in (history or [])[-12:]:

        role = item.get("role")

        content = str(
            item.get("content", "")
        ).strip()

        if role in ("user", "assistant") and content:

            history_text += (
                f"\n{role.upper()}: "
                f"{content[:6000]}"
            )

    # ---------------------------------------------------------
    # Final prompt
    # ---------------------------------------------------------

    prompt = f"""
{SYSTEM_INSTRUCTIONS}

CURRENT PHISHGUARD SCAN CONTEXT:
{context_text}

PREVIOUS CONVERSATION:
{history_text if history_text else "No previous conversation."}

CURRENT USER MESSAGE:
{message[:8000]}
"""

    # ---------------------------------------------------------
    # Gemini request
    # ---------------------------------------------------------

    response = client.models.generate_content(
        model=DEFAULT_MODEL,
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=0.3,
            max_output_tokens=1000,
        ),
    )

    answer = (
        response.text or ""
    ).strip()

    if not answer:
        raise RuntimeError(
            "Gemini returned an empty response."
        )

    return answer