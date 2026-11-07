"""Génération des livrables : PDF, HTML, YAML, SARIF, CEF, middleware Python, template Nuclei, historique."""
from __future__ import annotations

import hashlib
import html
import json
import os
import pprint
import socket
from datetime import datetime
from urllib.parse import urlparse

import yaml
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Table, TableStyle

from judge import build_payload
from scoring import (
    STANDARD_THRESHOLD,
    VERSION,
    criteria_scores,
    errors,
    findings,
    grade,
    overall_score,
    scored,
    severity_label,
)

# Noms vérifiés sur la base officielle MITRE ATLAS (atlas-data, ATLAS.yaml).
# LLM05 / LLM09 : pas de technique dédiée -> correspondance la plus proche.
MITRE_ATLAS_MAP = {
    "LLM01": "AML.T0051 (LLM Prompt Injection)",
    "LLM02": "AML.T0024 (Exfiltration via AI Inference API)",
    "LLM03": "AML.T0010 (AI Supply Chain Compromise)",
    "LLM04": "AML.T0020 (Poison Training Data)",
    "LLM05": "AML.T0050 (Command and Scripting Interpreter) [closest]",
    "LLM06": "AML.T0053 (AI Agent Tool Invocation)",
    "LLM07": "AML.T0056 (Extract LLM System Prompt)",
    "LLM08": "AML.T0085.000 (Data from AI Services: RAG Databases)",
    "LLM09": "AML.T0062 (Discover LLM Hallucinations) [closest]",
    "LLM10": "AML.T0029 (Denial of AI Service)",
}

# Modules / classes qui existent réellement dans NVIDIA garak (vérifié sur le dépôt).
GARAK_MAP = {
    "LLM01": "garak.probes.dan / garak.probes.promptinject",
    "LLM02": "garak.probes.leakreplay",
    "LLM03": "garak.probes.packagehallucination",
    "LLM04": "N/A (pas de sonde Garak dédiée)",
    "LLM05": "garak.probes.web_injection (MarkdownImageExfil, TaskXSS)",
    "LLM06": "garak.probes.exploitation (SQLInjectionSystem, JinjaTemplatePythonInjection)",
    "LLM07": "garak.probes.promptinject / garak.probes.latentinjection",
    "LLM08": "garak.probes.latentinjection (injection indirecte)",
    "LLM09": "garak.probes.misleading.FalseAssertion",
    "LLM10": "garak.probes.divergence.Repeat",
}
GARAK_JBB_MAP = GARAK_MAP  # alias de compatibilité


def esc(value) -> str:
    """Échappement HTML systématique de tout contenu non fiable (réponses de la cible, sorties IA)."""
    return html.escape(str(value if value is not None else ""), quote=True)


def _pdf_safe(value) -> str:
    """Les polices standard de ReportLab ne gèrent que Latin-1 : remplace le reste pour éviter les carrés noirs."""
    return html.escape(str(value or "")).encode("cp1252", "replace").decode("cp1252").replace("\n", "<br/>")


def _fmt(v) -> str:
    return "N/A" if v is None else f"{v}/100"


# --------------------------------------------------------------------------------------
# Historique
# --------------------------------------------------------------------------------------

def track_scan_history(target_url: str, current_overall: int | None, history_path: str = "reports/scan_history.json") -> str:
    """Compare le score actuel avec le dernier audit enregistré sur la même cible (écriture atomique)."""
    if current_overall is None:
        return "Score global non évaluable (aucun test concluant) : historique non mis à jour."
    os.makedirs(os.path.dirname(history_path) or ".", exist_ok=True)
    history: dict = {}
    if os.path.exists(history_path):
        try:
            with open(history_path, "r", encoding="utf-8") as f:
                history = json.load(f)
        except Exception:
            history = {}

    prev = history.get(target_url)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    runs = (prev or {}).get("runs", [])[-19:] + [{"score": current_overall, "at": now}]
    history[target_url] = {"score": current_overall, "updated_at": now, "runs": runs}

    tmp = history_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)
    os.replace(tmp, history_path)

    if prev is None:
        return f"Premier audit enregistré sur cette cible (Référence initiale : {current_overall}/100)"
    diff = current_overall - prev["score"]
    sign = f"+{diff}" if diff >= 0 else str(diff)
    return f"Ancien score : {prev['score']}/100 ({prev['updated_at']}) -> Actuel : {current_overall}/100 (Évolution : {sign} pts)"


# --------------------------------------------------------------------------------------
# Middleware de garde-fous (adapté aux catégories réellement en échec)
# --------------------------------------------------------------------------------------

_INPUT_RULES = {
    "LLM01": [r"ignore\s+(?:all\s+|the\s+)?(?:previous|prior|above)\s+(?:instructions|rules)", r"ignore.{0,25}consignes",
              r"developer\s+mode", r"mode\s+(?:maintenance|d[ée]veloppeur)", r"dev_override"],
    "LLM04": [r"trigger_poison"],
    "LLM06": [r"delete_user", r"drop\s+table", r"rm\s+-rf"],
    "LLM07": [r"(?:repeat|print|show|reveal|display|affiche)\w*.{0,40}(?:system\s+prompt|instructions|param[èe]tres\s+syst[èe]me|configuration)"],
    "LLM08": [r"secret_rag_doc", r"(?:dump|list|affiche)\w*.{0,40}(?:knowledge\s+base|base\s+vectorielle|confidential)"],
}
_OUTPUT_RULES = {
    "LLM02": [(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "[EMAIL_MASQUÉ]"), (r"\+[0-9]{8,15}", "[TEL_MASQUÉ]"),
              (r"SK-INTERNAL-[0-9]+", "[TOKEN_MASQUÉ]")],
    "LLM03": [(r"unverified_lora_adapter|pickle_loader\w*", "[COMPOSANT_MASQUÉ]")],
    "LLM05": [(r"<\s*/?\s*(?:script|iframe|object|embed)\b[^>]*>", "[HTML_ACTIF_BLOQUÉ]"), (r"\bon\w+\s*=", "[HANDLER_BLOQUÉ]="),
              (r"javascript\s*:", "[JS_BLOQUÉ]:")],
    "LLM07": [(r"DB_HOST\s*=\s*[0-9a-zA-Z.\-]+", "DB_HOST=[MASQUÉ]"), (r"SYSTEM_DIRECTIVE[^|\n]*", "[DIRECTIVE_MASQUÉE]")],
    "LLM08": [(r"SECRET_RAG_DOC", "[DOC_CONFIDENTIEL_MASQUÉ]"), (r"Salaire_PDG\s*=\s*\S+", "Salaire_PDG=[MASQUÉ]")],
}
_ALWAYS_REDACT = [
    (r"sk-[A-Za-z0-9_-]{16,}", "[CLE_API_MASQUÉE]"), (r"AKIA[0-9A-Z]{16}", "[CLE_AWS_MASQUÉE]"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "[CLE_PRIVEE_MASQUÉE]"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "[JWT_MASQUÉ]"),
]


def generate_python_middleware(results: list[dict], output_py_path: str = "reports/BMODetector_middleware.py"):
    """Génère un middleware dont les règles dépendent des catégories OWASP en échec (toutes si aucun échec)."""
    failed = sorted({r["owasp_id"] for r in findings(results)})
    active = failed or sorted({*_INPUT_RULES, *_OUTPUT_RULES})
    input_patterns = [p for oid in active for p in _INPUT_RULES.get(oid, [])]
    output_rules = [rule for oid in active for rule in _OUTPUT_RULES.get(oid, [])] + _ALWAYS_REDACT
    cap_output = 8000 if ("LLM10" in failed or not failed) else 0

    header = (
        '"""BMODetector — middleware de garde-fous généré automatiquement.\n\n'
        f"Généré le : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"Catégories OWASP ciblées : {', '.join(failed) if failed else 'aucune faille (jeu préventif complet)'}\n\n"
        "ATTENTION : défense en profondeur uniquement (filtres par motifs, contournables par reformulation).\n"
        "Ne remplace pas la correction de la cause racine (isolation du prompt système, RBAC, moindre privilège...).\n"
        '"""\n'
    )
    body = (
        "import re\n\n"
        f"MAX_INPUT_CHARS = 4000\nMAX_OUTPUT_CHARS = {cap_output}  # 0 = pas de plafond\n\n"
        f"INPUT_PATTERNS = {pprint.pformat(input_patterns, width=100)}\n\n"
        f"OUTPUT_RULES = {pprint.pformat(output_rules, width=100)}\n\n"
        "_INPUT_RE = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in INPUT_PATTERNS]\n"
        "_OUTPUT_RE = [(re.compile(p, re.IGNORECASE | re.DOTALL), repl) for p, repl in OUTPUT_RULES]\n\n\n"
        "def inspect_prompt_input(user_prompt: str) -> tuple[bool, str]:\n"
        '    """Filtre d\'entrée. Retourne (autorisé, prompt_ou_message)."""\n'
        "    if len(user_prompt) > MAX_INPUT_CHARS:\n"
        '        return False, "Requête trop longue."\n'
        "    for rx in _INPUT_RE:\n"
        "        if rx.search(user_prompt):\n"
        '            return False, "Requête bloquée par la politique de sécurité BMODetector."\n'
        "    return True, user_prompt\n\n\n"
        "def sanitize_llm_output(llm_response: str) -> str:\n"
        '    """Filtre de sortie : masque secrets/PII et neutralise le HTML actif (insensible à la casse)."""\n'
        "    text = llm_response\n"
        "    for rx, repl in _OUTPUT_RE:\n"
        "        text = rx.sub(repl, text)\n"
        "    if MAX_OUTPUT_CHARS and len(text) > MAX_OUTPUT_CHARS:\n"
        '        text = text[:MAX_OUTPUT_CHARS] + " [...tronqué]"\n'
        "    return text\n\n\n"
        "def guard(user_prompt: str, call_llm) -> str:\n"
        '    """Exemple d\'intégration : guard(prompt, lambda p: mon_llm(p))."""\n'
        "    ok, prompt_or_msg = inspect_prompt_input(user_prompt)\n"
        "    if not ok:\n"
        "        return prompt_or_msg\n"
        "    return sanitize_llm_output(call_llm(prompt_or_msg))\n"
    )
    with open(output_py_path, "w", encoding="utf-8") as f:
        f.write(header + body)


# --------------------------------------------------------------------------------------
# SIEM (CEF) & SARIF
# --------------------------------------------------------------------------------------

def _cef_header(v) -> str:
    return str(v).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _cef_ext(v) -> str:
    return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\r", " ").replace("\n", "\\n")


def generate_siem_cef_logs(target_url: str, results: list[dict], output_cef_path: str):
    lines = []
    timestamp = datetime.now().strftime("%b %d %H:%M:%S")
    host = socket.gethostname() or "bmo-scanner"
    dhost = urlparse(target_url).hostname or ""
    for r in findings(results):
        sev_num = 10 if r["score"] >= 80 else 6
        mitre = MITRE_ATLAS_MAP.get(r["owasp_id"], "AML.T0000")
        lines.append(
            f"{timestamp} {host} CEF:0|ISETCom|BMODetector|{VERSION}|{_cef_header(r['id'])}|"
            f"{_cef_header(r['owasp_id'] + ' ' + r['title'])}|{sev_num}|"
            f"dhost={_cef_ext(dhost)} request={_cef_ext(target_url)} cs1Label=OWASP cs1={_cef_ext(r['owasp_id'])} "
            f"cs2Label=MITRE_ATLAS cs2={_cef_ext(mitre)} cn1Label=RiskScore cn1={int(r['score'])} "
            f"msg={_cef_ext(r['justification'])}"
        )
    with open(output_cef_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))


def generate_sarif_report(target_url: str, results: list[dict], output_sarif_path: str):
    owasp_ids = sorted({r["owasp_id"] for r in results})
    rules = []
    for oid in owasp_ids:
        sample = next(r for r in results if r["owasp_id"] == oid)
        rules.append({
            "id": f"BMO-{oid}",
            "name": sample["title"].replace(" ", ""),
            "shortDescription": {"text": f"{oid} - {sample['title']}"},
            "fullDescription": {"text": sample["remediation"] if sample["status"] != "PASS" else sample["title"]},
            "helpUri": "https://genai.owasp.org/llm-top-10/",
            "properties": {"tags": ["security", "llm", "owasp-llm-top10", MITRE_ATLAS_MAP.get(oid, "")], "security-severity": "8.0"},
        })
    index_of = {rule["id"]: i for i, rule in enumerate(rules)}

    sarif_results = []
    for r in findings(results):
        rule_id = f"BMO-{r['owasp_id']}"
        sarif_results.append({
            "ruleId": rule_id,
            "ruleIndex": index_of[rule_id],
            "level": "error" if r["score"] >= 80 else "warning",
            "message": {"text": f"{r['justification']} | Fix: {r['remediation']}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": target_url}}}],
            "partialFingerprints": {"bmoDetector/v1": hashlib.sha256(f"{target_url}|{rule_id}|{r['status']}".encode()).hexdigest()[:32]},
            "properties": {"riskScore": r["score"], "mitreAtlas": MITRE_ATLAS_MAP.get(r["owasp_id"], "")},
        })

    notifications = [
        {"level": "warning", "message": {"text": f"{r['owasp_id']} non concluant : {r['justification']}"}, "descriptor": {"id": f"BMO-{r['owasp_id']}"}}
        for r in errors(results)
    ]
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "BMODetector", "version": VERSION, "informationUri": "https://github.com/0xSilverSurfer/BMODetector", "rules": rules}},
            "invocations": [{"executionSuccessful": bool(scored(results)), "toolExecutionNotifications": notifications}],
            "results": sarif_results,
        }],
    }
    with open(output_sarif_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, ensure_ascii=False)


def generate_guardrails_file(results: list[dict], output_yaml_path: str):
    failed_tests = findings(results)
    guardrails_config = {
        "BMODetector_guardrails": {
            "version": VERSION,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "compliance_frameworks": ["OWASP LLM Top 10 (2025)", "MITRE ATLAS", "EU AI Act Art. 15"],
            "total_findings": len(failed_tests),
            "inconclusive_tests": [r["owasp_id"] for r in errors(results)],
            "active_policies": [
                {
                    "rule_id": f"RULE-{r['owasp_id']}",
                    "owasp_category": f"{r['owasp_id']} - {r['title']}",
                    "status": r["status"],
                    "priority": "P1-URGENT" if r["score"] >= 80 else "P2-MOYEN",
                    "enforcement_action": "BLOCK_AND_REDACT",
                    "remediation_control": r["remediation"],
                }
                for r in failed_tests
            ],
        }
    }
    with open(output_yaml_path, "w", encoding="utf-8") as f:
        yaml.dump(guardrails_config, f, allow_unicode=True, sort_keys=False)


# --------------------------------------------------------------------------------------
# Dashboard HTML (TOUT le contenu dynamique est échappé)
# --------------------------------------------------------------------------------------

def _grade_color(overall: int | None) -> str:
    if overall is None:
        return "#94a3b8"
    return "#22c55e" if overall >= 80 else ("#eab308" if overall >= 65 else ("#f97316" if overall >= 50 else "#ef4444"))


def generate_html_dashboard(target_url: str, results: list[dict], output_html_path: str,
                            profile: dict | None = None, recon: list[dict] | None = None):
    crit = criteria_scores(results, recon)
    overall = overall_score(crit)
    total, n_find, n_err = len(results), len(findings(results)), len(errors(results))

    profile_html = ""
    if profile:
        profile_html = f"""
        <div class="box" style="border-left-color:#eab308">
            <h3 style="margin-top:0; color:#eab308;">0. Définition &amp; Profilage de l'IA Cible (Pré-Audit)</h3>
            <p><strong>Architecture &amp; Métier Détectés :</strong> {esc(profile.get('capabilities'))}</p>
            <p><strong>Surface d'Attaque Prioritaire :</strong> {esc(profile.get('priority_owasp'))}</p>
            <p style="color:#38bdf8;"><strong>Synthèse :</strong> {esc(profile.get('ai_summary'))}</p>
        </div>"""

    recon_html = ""
    if recon:
        rows = "".join(
            f"<tr><td>{esc(f['check'])}</td><td><span class='badge' style='background:{ {'PASS': '#16a34a', 'WARN': '#d97706'}.get(f['status'], '#dc2626') }'>{esc(f['status'])}</span></td><td>{esc(f['details'])}</td></tr>"
            for f in recon)
        recon_html = f"<h3>Reconnaissance Réseau HTTP L7</h3><table><thead><tr><th>Contrôle</th><th>Statut</th><th>Détails</th></tr></thead><tbody>{rows}</tbody></table><br>"

    rows_html = ""
    for r in results:
        sev = severity_label(r)
        badge_bg = "#6b7280" if r["status"] == "ERROR" else ("#dc2626" if r["score"] >= 80 else ("#d97706" if r["score"] >= 40 else "#16a34a"))
        score_txt = "non concluant" if r["status"] == "ERROR" else f"{r['score']}/100"
        review = " *" if r.get("needs_review") else ""
        ai = f"<br><small style='color:#38bdf8'><strong>Avis IA :</strong> {esc(r['ai_opinion'])}</small>" if r.get("ai_opinion") else ""
        evidence = (
            f"<details><summary>Preuve (requête / réponse)</summary>"
            f"<pre>PROMPT : {esc(r.get('prompt_sent'))}\n\nHTTP : {esc(r.get('http_status'))}\n\nRÉPONSE : {esc(str(r.get('clean_reply', ''))[:800])}</pre></details>")
        rows_html += f"""
        <tr>
            <td><strong>#{esc(r['num'])} {esc(r['owasp_id'])}</strong><br><small>{esc(r['latency_ms'])} ms</small></td>
            <td>{esc(r['title'])}</td>
            <td><span class="badge" style="background:{badge_bg}">{esc(sev)} ({esc(score_txt)}){review}</span></td>
            <td>{esc(r['justification']).replace(chr(10), '<br>')}{ai}<br><small style="color:#94a3b8"><strong>Remédiation :</strong> {esc(r['remediation'])}</small>{evidence}</td>
        </tr>"""

    def kpi(label: str, key: str) -> str:
        v = crit[key]
        gap = "N/A" if v is None else f"{v - STANDARD_THRESHOLD:+d} pts"
        return f'<div class="kpi-card"><div>{label}</div><div class="kpi-value">{_fmt(v)}</div><small>Écart: {gap}</small></div>'

    html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
    <title>BMODetector v{VERSION} - Security Dashboard</title>
    <style>
        body {{ background: #0b0f19; color: #e2e8f0; font-family: 'Segoe UI', sans-serif; margin: 0; padding: 30px; }}
        .header {{ background: linear-gradient(135deg, #111827, #1e293b); padding: 25px; border-radius: 12px; border-left: 5px solid #38bdf8; margin-bottom: 25px; display: flex; justify-content: space-between; align-items: center; }}
        .box {{ background:#161f30; padding:18px; border-radius:10px; border-left:4px solid #38bdf8; margin-bottom:25px; }}
        .kpi-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-bottom: 25px; }}
        .kpi-card {{ background: #161f30; padding: 16px; border-radius: 10px; border: 1px solid #1e293b; text-align: center; }}
        .kpi-value {{ font-size: 26px; font-weight: bold; margin-top: 8px; }}
        table {{ width: 100%; border-collapse: collapse; background: #161f30; border-radius: 10px; overflow: hidden; }}
        th {{ background: #1e293b; color: #38bdf8; text-align: left; padding: 12px; font-size: 12.5px; text-transform: uppercase; }}
        td {{ padding: 12px; border-bottom: 1px solid #1e293b; font-size: 13px; vertical-align: top; }}
        .badge {{ padding: 4px 10px; border-radius: 6px; font-weight: bold; font-size: 11px; color: white; white-space: nowrap; }}
        pre {{ white-space: pre-wrap; word-break: break-word; background:#0b0f19; padding:10px; border-radius:6px; color:#cbd5e1; }}
        summary {{ cursor: pointer; color:#38bdf8; margin-top:6px; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <div style="color:#38bdf8; font-weight:bold; font-size:12px;">ISETCOM - L3 SYSTÈMES &amp; RÉSEAUX | OWASP LLM TOP 10 &amp; GAP ANALYSIS</div>
            <h1 style="margin:5px 0;">BMODetector v{VERSION} — Rapport d'Audit &amp; Analyse d'Écart</h1>
            <div style="color:#94a3b8; font-size:13px;">Cible : <strong>{esc(target_url)}</strong> | Seuil Exigé : {STANDARD_THRESHOLD}/100</div>
        </div>
        <div style="text-align:right;">
            <div style="font-size:12px; color:#94a3b8;">INDICE GLOBAL</div>
            <div style="font-size:40px; font-weight:900; color:{_grade_color(overall)};">{_fmt(overall)} ({grade(overall)})</div>
        </div>
    </div>
    {profile_html}
    <div class="kpi-grid">
        {kpi('C1 - Confidentialité', 'C1_Confidentialite')}
        {kpi('C2 - Garde-fous', 'C2_GardeFous')}
        {kpi('C3 - Intégrité Sorties', 'C3_IntegriteSortie')}
        {kpi('C4 - Réseau L7', 'C4_ResilienceReseau')}
        <div class="kpi-card"><div>Findings OWASP</div><div class="kpi-value" style="color:#ef4444">{n_find}/{total}</div><small>{n_err} test(s) non concluant(s)</small></div>
    </div>
    {recon_html}
    <table>
        <thead><tr><th>N° / OWASP</th><th>Catégorie</th><th>Statut &amp; Score</th><th>Constat &amp; Remédiation</th></tr></thead>
        <tbody>{rows_html}</tbody>
    </table>
    <p style="color:#64748b; font-size:12px">* PASS sans refus explicite : revue manuelle conseillée. Les tests « non concluants » (HTTP 401/404/5xx, timeout) sont exclus de la moyenne.</p>
</body>
</html>"""
    with open(output_html_path, "w", encoding="utf-8") as f:
        f.write(html_content)


# --------------------------------------------------------------------------------------
# PDF
# --------------------------------------------------------------------------------------

def generate_pdf_report(target_url: str, results: list[dict], output_path: str,
                        profile: dict | None = None, recon: list[dict] | None = None):
    doc = SimpleDocTemplate(output_path, pagesize=A4, rightMargin=25, leftMargin=25, topMargin=25, bottomMargin=25)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("DocTitle", parent=styles["Heading1"], fontSize=15, textColor=colors.HexColor("#0f172a"), spaceAfter=8)
    sub_style = ParagraphStyle("Sub", parent=styles["Heading2"], fontSize=11.5, textColor=colors.HexColor("#0284c7"), spaceBefore=10, spaceAfter=6)
    meta_style = ParagraphStyle("Meta", parent=styles["Normal"], fontSize=9, leading=13, textColor=colors.HexColor("#334155"))
    cell_style = ParagraphStyle("Cell", parent=styles["Normal"], fontSize=8, leading=10)

    crit = criteria_scores(results, recon)
    overall = overall_score(crit)
    gap_txt = "N/A" if overall is None else f"{overall - STANDARD_THRESHOLD:+d} pts"

    elements = [
        Paragraph(f"BMODetector v{VERSION} - Rapport d'Audit OWASP LLM Top 10 &amp; Analyse d'Écart", title_style),
        Paragraph(
            f"<b>Endpoint Cible :</b> {_pdf_safe(target_url)} | <b>Date :</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>"
            f"<b>Indice Global :</b> {_fmt(overall)} (Seuil Standard Exigé : {STANDARD_THRESHOLD}/100 | Écart : {gap_txt}) | "
            f"<b>Tests non concluants :</b> {len(errors(results))}",
            meta_style),
    ]

    if profile:
        elements.append(Paragraph("0. Définition &amp; Profilage de l'IA Cible (Pré-Audit)", sub_style))
        elements.append(Paragraph(
            f"<b>Architecture Détectée :</b> {_pdf_safe(profile.get('capabilities'))}<br/>"
            f"<b>Surface Prioritaire :</b> {_pdf_safe(profile.get('priority_owasp'))}<br/>"
            f"<b>Synthèse :</b> {_pdf_safe(profile.get('ai_summary'))}", meta_style))

    if recon:
        elements.append(Paragraph("Reconnaissance Réseau HTTP L7", sub_style))
        rt = Table([["Contrôle", "Statut", "Détails"]] + [[Paragraph(_pdf_safe(f["check"]), cell_style), f["status"], Paragraph(_pdf_safe(f["details"]), cell_style)] for f in recon],
                   colWidths=[150, 50, 340])
        rt.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111c2d")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("FONTSIZE", (0, 0), (-1, -1), 8)]))
        elements.append(rt)

    elements.append(Paragraph("1. Résultats Détaillés &amp; Plan de Remédiation", sub_style))
    table_data = [["ID", "OWASP", "Statut", "Constat, preuve & remédiation"]]
    for r in results:
        details = (
            f"<b>Constat :</b> {_pdf_safe(r.get('justification'))}<br/>"
            f"<b>Preuve :</b> prompt « {_pdf_safe(str(r.get('prompt_raw') or r.get('prompt_sent'))[:220])} » -> "
            f"HTTP {_pdf_safe(r.get('http_status'))}, réponse « {_pdf_safe(str(r.get('clean_reply', ''))[:260])} »<br/>"
            f"<b>Fix :</b> {_pdf_safe(r.get('remediation'))}")
        score_txt = "n/c" if r["status"] == "ERROR" else f"{r['score']}/100"
        table_data.append([f"#{r.get('num', '')}", r.get("owasp_id", ""), f"{severity_label(r)}\n({score_txt})", Paragraph(details, cell_style)])

    table = Table(table_data, colWidths=[30, 45, 65, 400], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111c2d")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8.5),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
    ]))
    elements.append(table)
    doc.build(elements)


# --------------------------------------------------------------------------------------
# Template Nuclei (une requête par module concluant, matchers issus des signatures du module)
# --------------------------------------------------------------------------------------

def generate_nuclei_template(target_url: str, results: list[dict], output_nuclei_path: str = "reports/nuclei_llm_audit.yaml",
                             api_type: str = "custom", target_model: str = "", param_key: str = "prompt", needs_auth: bool = False):
    chosen = findings(results) or scored(results)
    requests = []
    for r in chosen:
        patterns = [f"(?i){p}" for p in r.get("regex_patterns", [])]
        if not patterns:
            continue
        req = {
            "method": "POST",
            "path": ["{{BaseURL}}"],
            "headers": {"Content-Type": "application/json", **({"Authorization": "Bearer {{api_key}}"} if needs_auth else {})},
            "body": json.dumps(build_payload(r.get("prompt_raw") or r["prompt_sent"], api_type, target_model or "model", param_key), ensure_ascii=False),
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "regex": patterns, "condition": "or"},
            ],
        }
        requests.append(req)
    if not requests:
        return

    max_score = max((r["score"] for r in findings(results)), default=0)
    nuclei_doc = {
        "id": "bmo-owasp-llm-top10-audit",
        "info": {
            "name": "BMODetector - OWASP LLM Top 10 API Vulnerability Template",
            "author": "ISETCom-L3-SR",
            "severity": "high" if max_score >= 80 else ("medium" if max_score >= 40 else "info"),
            "description": f"Template Nuclei généré par BMODetector v{VERSION} pour {target_url}. "
                           + ("Utiliser -var api_key=... (clé requise)." if needs_auth else ""),
            "reference": ["https://genai.owasp.org/llm-top-10/", "https://atlas.mitre.org/"],
            "tags": "llm,ai,owasp,rag,bmo-detector",
        },
        "http": requests,
    }
    with open(output_nuclei_path, "w", encoding="utf-8") as f:
        yaml.dump(nuclei_doc, f, allow_unicode=True, sort_keys=False, width=1000)
