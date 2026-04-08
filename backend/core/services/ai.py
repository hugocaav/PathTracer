import json
import re

from django.conf import settings


def extract_json_object(content):
    content = (content or "").strip()
    if content.startswith("```"):
        content = re.sub(r"^```(?:json)?\s*", "", content)
        content = re.sub(r"\s*```$", "", content)

    start = content.find("{")
    end = content.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("No JSON object found")
    return json.loads(content[start : end + 1])


def get_groq_client():
    try:
        from groq import Groq
    except ImportError as exc:
        raise ImportError("Groq package not installed") from exc
    return Groq(api_key=settings.GROQ_API_KEY)

