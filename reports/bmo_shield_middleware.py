"""
BMO-Shield Auto-Generated Security Guardrail Middleware
Généré automatiquement le : 2026-11-03 16:03:02
Failles OWASP ciblées pour correction : LLM01, LLM02, LLM03, LLM04, LLM05, LLM06, LLM07, LLM08, LLM09, LLM10
"""
import re

BLOCKED_INPUT_PATTERNS = [
    r"ignore.*consignes", r"dev_override", r"mode maintenance",
    r"<script>", r"delete_user", r"trigger_poison", r"secret_rag_doc"
]

PII_REDACTION_PATTERNS = [
    (r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "[EMAIL_MASQUÉ]"),
    (r"SK-INTERNAL-[0-9]+", "[TOKEN_MASQUÉ]"),
    (r"\+216[0-9]{8}", "[TEL_MASQUÉ]"),
    (r"DB_HOST=[0-9.]+", "DB_HOST=[IP_MASQUÉE]")
]

def inspect_prompt_input(user_prompt: str) -> tuple[bool, str]:
    """Filtre d'entrée (Input Guardrail) contre LLM01, LLM04, LLM06."""
    for pattern in BLOCKED_INPUT_PATTERNS:
        if re.search(pattern, user_prompt, re.IGNORECASE):
            return False, "Requête bloquée par la politique de sécurité BMO-Shield."
    return True, user_prompt

def sanitize_llm_output(llm_response: str) -> str:
    """Filtre de sortie (Output Guardrail) contre LLM02, LLM05, LLM07, LLM08."""
    safe_text = llm_response.replace("<script>", "&lt;script&gt;").replace("</script>", "&lt;/script&gt;")
    for pattern, replacement in PII_REDACTION_PATTERNS:
        safe_text = re.sub(pattern, replacement, safe_text, flags=re.IGNORECASE)
    return safe_text
