import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import asyncio
import ipaddress
import json
import socket
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from importlib import resources
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

import typer
import yaml
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn
from rich.prompt import Prompt
from rich.table import Table

from judge import (
    AI_STATS,
    HttpConfig,
    JUDGE,
    analyze_response,
    auto_discover_web_ai,
    build_payload,
    configure_judge,
    ensure_ollama,
    generate_multi_audit_prompts,
    response_meta,
    run_network_recon,
    run_semantic_profiling,
    select_best_model_for_pc,
)
from reporter import (
    GARAK_MAP,
    MITRE_ATLAS_MAP,
    generate_guardrails_file,
    generate_html_dashboard,
    generate_nuclei_template,
    generate_pdf_report,
    generate_python_middleware,
    generate_sarif_report,
    generate_siem_cef_logs,
    track_scan_history,
)
from scoring import (
    CRITERIA,
    STANDARD_THRESHOLD,
    VERSION,
    criteria_scores,
    errors,
    findings,
    is_error,
    overall_score,
    percentile,
    scored,
)

BASE_DIR = Path(__file__).resolve().parent

CLI_HELP_EPILOG = """
Exemples d'utilisation :
  1. Auditer un modèle Ollama local :
     $ BMODetector -t http://127.0.0.1:11434/api/generate --api-type ollama --target-model smollm2:135m

  2. Auditer une API compatible OpenAI (clé via variable d'environnement, jamais en clair) :
     $ export BMO_API_KEY=... && BMODetector -t https://api.exemple.com/v1/chat/completions --api-type openai --target-model mon-modele --i-have-authorization

  3. Auditer une API REST d'entreprise avec reconnaissance L7, 3 essais par sonde :
     $ BMODetector -t http://127.0.0.1:8000/v1/chat --recon --repeat 3 --benchmark

Codes de sortie : 0 = OK | 1 = vulnérabilités détectées (avec --fail-on-vuln) | 2 = scan non concluant / erreur d'usage.

N'auditez que des systèmes dont vous êtes propriétaire ou pour lesquels vous avez une autorisation écrite.
"""

app = typer.Typer(
    name="BMODetector",
    help=f"BMODetector v{VERSION} - Scanner de vulnérabilités et d'analyse d'écart (Gap Analysis) pour API LLM / RAG (OWASP Top 10 & MITRE ATLAS).",
    epilog=CLI_HELP_EPILOG,
    add_completion=False,
)
console = Console()

HEADER_TEXT = (
    f"[bold cyan]BMODetector v{VERSION}[/bold cyan] — Offensive LLM & RAG API Security Scanner\n"
    "[dim]ISETCom (L3 Systèmes & Réseaux) | Standards : OWASP LLM Top 10 • MITRE ATLAS • EU AI Act[/dim]"
)

LLM10_MAX_TOKENS = 1024  # la sonde DoS ne doit pas être plafonnée par le client


# --------------------------------------------------------------------------------------
# Utilitaires
# --------------------------------------------------------------------------------------

@dataclass
class AuditConfig:
    target: str
    api_type: str = "custom"
    target_model: str = "smollm2:135m"
    api_key: Optional[str] = None
    extra_headers: dict = field(default_factory=dict)
    limit: int = 10
    only: set = field(default_factory=set)
    use_llm: bool = True
    model: str = "auto"
    repeat: int = 1
    max_probes: int = 3
    max_tokens: int = 300
    timeout: float = 60.0
    delay: float = 0.0
    verify: bool = True
    proxy: Optional[str] = None
    discover: bool = True
    recon: bool = False


def is_local_target(url: str) -> bool:
    """Loopback, réseau privé, *.local, ou nom à label unique (service Docker)."""
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return False
    if host == "localhost" or host.endswith((".local", ".localhost")):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        return "." not in host


def check_authorization(target: str, assume_yes: bool) -> None:
    """Garde-fou de périmètre : une cible distante exige une confirmation explicite."""
    if assume_yes or is_local_target(target):
        return
    host = urlparse(target).hostname or target
    if sys.stdin.isatty():
        console.print(f"[bold yellow][PÉRIMÈTRE][/bold yellow] La cible [bold]{escape(host)}[/bold] n'est pas locale.")
        if not typer.confirm("Confirmez-vous être propriétaire de cette cible ou disposer d'une autorisation écrite ?"):
            raise typer.Exit(2)
        return
    console.print("[bold red][ERREUR][/bold red] Cible distante en mode non interactif : ajoutez --i-have-authorization "
                  "pour confirmer que vous avez une autorisation écrite.")
    raise typer.Exit(2)


def ensure_lab_server(target: str) -> None:
    """Démarre le labo local (mock) si la cible est 127.0.0.1:8000 et que le port est fermé."""
    p = urlparse(target)
    if p.hostname not in ("127.0.0.1", "localhost") or p.port != 8000:
        return
    if not (BASE_DIR / "target_lab" / "mock_api.py").exists():
        return
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if s.connect_ex(("127.0.0.1", 8000)) == 0:
            return
    console.print("[cyan][INFO][/cyan] Démarrage du serveur cible local (127.0.0.1:8000)...")
    try:
        subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "target_lab.mock_api:app", "--host", "127.0.0.1", "--port", "8000"],
            cwd=str(BASE_DIR), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except OSError as e:
        console.print(f"[yellow][WARN][/yellow] Impossible de démarrer le labo local : {escape(str(e))}")
        return
    for _ in range(25):
        time.sleep(0.2)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as chk:
            if chk.connect_ex(("127.0.0.1", 8000)) == 0:
                return


def load_catalog() -> dict:
    """Charge le catalogue de sondes (fonctionne en dépôt ET après `pip install`)."""
    try:
        text = resources.files("payloads").joinpath("test_cases.yaml").read_text(encoding="utf-8")
    except Exception:
        text = (BASE_DIR / "payloads" / "test_cases.yaml").read_text(encoding="utf-8")
    return yaml.safe_load(text).get("modules", {})


def _clip(text, n: int = 300) -> str:
    text = str(text or "")
    return text if len(text) <= n else text[: n - 3] + "..."


def show_modules_table():
    catalog = load_catalog()
    table = Table(title="Catalogue : OWASP LLM Top 10 • MITRE ATLAS • Sondes Garak", border_style="cyan")
    table.add_column("N°", justify="center", style="bold")
    table.add_column("ID OWASP", style="bold cyan")
    table.add_column("MITRE ATLAS", style="magenta")
    table.add_column("Sonde Garak", style="green")
    table.add_column("Nom du Module", style="yellow")
    for _key, data in catalog.items():
        oid = data["owasp_id"]
        table.add_row(str(data["num"]), oid, escape(MITRE_ATLAS_MAP.get(oid, "N/A")), escape(GARAK_MAP.get(oid, "N/A")), escape(data["title"]))
    console.print(table)


def render_target_definition(target: str, profile: dict):
    t0 = Table(title=f"0. Définition & Profilage de l'IA Cible ({escape(target)})", border_style="yellow", show_lines=True)
    t0.add_column("Étape de Découverte", style="bold yellow", width=28)
    t0.add_column("Détails", style="white", width=82)
    t0.add_row("Tour 1 : Rôle", f"[bold]Question :[/bold] {escape(profile['q1'])}\n[cyan]Réponse :[/cyan] {escape(_clip(profile['r1']))}")
    t0.add_row("Tour 2 : Outils & données", f"[bold]Question :[/bold] {escape(profile['q2'])}\n[cyan]Réponse :[/cyan] {escape(_clip(profile['r2']))}")
    t0.add_row("Architecture & Métier Détectés", f"[bold green]{escape(profile['capabilities'])}[/bold green]")
    t0.add_row("Surface d'Attaque Prioritaire", f"[bold red]{escape(profile['priority_owasp'])}[/bold red]")
    t0.add_row("Synthèse", f"[bold magenta]{escape(profile['ai_summary'])}[/bold magenta]")
    console.print(t0)
    console.print()


def render_recon(target: str, recon: list[dict]):
    rt = Table(title=f"Reconnaissance Réseau HTTP L7 ({escape(target)})", border_style="cyan")
    rt.add_column("Contrôle Technique", style="bold")
    rt.add_column("Statut", justify="center")
    rt.add_column("Détails")
    for f in recon:
        col = {"PASS": "bold green", "WARN": "bold yellow"}.get(f["status"], "bold red")
        rt.add_row(escape(f["check"]), f"[{col}]{f['status']}[/{col}]", escape(f["details"]))
    console.print(rt)


# --------------------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------------------

async def _send(client, target: str, body: dict, timeout: float):
    t0 = time.perf_counter()
    try:
        res = await client.post(target, json=body, timeout=timeout)
        return res.status_code, res.text, round((time.perf_counter() - t0) * 1000, 1), None
    except Exception as e:  # réseau, TLS, timeout...
        return 0, "", round((time.perf_counter() - t0) * 1000, 1), f"{type(e).__name__}: {e}"


async def execute_audit(cfg: AuditConfig) -> dict:
    """Retourne {'results', 'profile', 'recon', 'stats', 'target'}."""
    ensure_lab_server(cfg.target)
    catalog = load_catalog()
    items = list(catalog.items())
    if cfg.only:
        items = [(k, d) for k, d in items if d["owasp_id"] in cfg.only]
    items = items[: cfg.limit]

    headers = dict(cfg.extra_headers)
    if cfg.api_key:
        headers["Authorization"] = f"Bearer {cfg.api_key}"
    http = HttpConfig(headers=headers, timeout=cfg.timeout, verify=cfg.verify, proxy=cfg.proxy, delay=cfg.delay)

    # ---- IA : dégradation gracieuse (jamais de crash, jamais de message d'erreur dans les rapports) ----
    use_llm, model = cfg.use_llm, None
    if use_llm:
        if not JUDGE["url"] and not await ensure_ollama():
            console.print("[yellow][WARN][/yellow] Ollama injoignable (installé et démarré ?) : IA désactivée, analyse déterministe uniquement.")
            use_llm = False
        else:
            model, hw_msg = await select_best_model_for_pc(cfg.model)
            if model is None:
                console.print(f"[yellow][WARN][/yellow] {escape(hw_msg)}")
                use_llm = False
            else:
                console.print(f"[bold magenta][HARDWARE-AI][/bold magenta] {escape(hw_msg)}")
    engine_mode = f"Déterministe + IA ({model})" if use_llm else "Déterministe (signatures, canary, refus)"

    target = cfg.target
    param_key = "prompt"
    if cfg.discover:
        web_info = await auto_discover_web_ai(target, http)
        param_key = web_info.get("param_key", "prompt")
        if web_info.get("cookies"):
            http.cookies = web_info["cookies"]
        if web_info.get("is_web_discovered"):
            console.print(f"[bold green][AUTO-DISCOVERY][/bold green] Endpoint API découvert : [bold cyan]{escape(web_info['api_url'])}[/bold cyan] (clé JSON : '{escape(param_key)}')")
            target = web_info["api_url"]

    console.print(f"[cyan][INFO][/cyan] Endpoint cible : [bold]{escape(target)}[/bold] (Format : {cfg.api_type.upper()} | Modèle : {escape(cfg.target_model)})")
    console.print(f"[cyan][INFO][/cyan] Moteur : [bold]{engine_mode}[/bold] | Modules : [bold]{len(items)}/10[/bold] | Essais par sonde : {cfg.repeat}\n")

    recon = None
    if cfg.recon:
        recon = await run_network_recon(target, http, cfg.api_type, cfg.target_model)
        render_recon(target, recon)

    console.print("[yellow][PHASE 0][/yellow] Profilage de la cible (2 questions)...")
    profile = await run_semantic_profiling(target, cfg.api_type, cfg.target_model, http, "bmo-session-" + uuid.uuid4().hex[:8], use_llm, model, param_key)
    render_target_definition(target, profile)

    results: list[dict] = []
    evidence: list[dict] = []
    latencies: list[float] = []
    fatal_streak = 0
    t_wall = time.perf_counter()

    with Progress(TextColumn("[bold blue]{task.description}"), BarColumn(bar_width=35), TaskProgressColumn(),
                  TextColumn("[cyan]{task.fields[current]}"), console=console) as progress:
        task = progress.add_task("[SCAN] Audit OWASP LLM...", total=len(items), current="Initialisation")

        async with http.client() as client:
            for _mod_key, data in items:
                num, owasp_id, title = data["num"], data["owasp_id"], data["title"]
                progress.update(task, current=f"[{num}] {owasp_id}")
                probes = await generate_multi_audit_prompts(
                    num, owasp_id, data["ai_goal"], data["base_prompt"], use_llm, model,
                    profile["capabilities"], data.get("alt_prompts", []), cfg.max_probes)

                strong, weak = data.get("regex_patterns", []), data.get("weak_patterns", [])
                best, best_meta = None, {}
                attempts = successes = 0
                is_dos = owasp_id == "LLM10"
                max_tokens = max(cfg.max_tokens, LLM10_MAX_TOKENS) if is_dos else cfg.max_tokens
                req_timeout = max(cfg.timeout, 120.0) if is_dos else cfg.timeout

                for probe_idx, template in enumerate(probes, 1):
                    canary = ("BMO" + uuid.uuid4().hex[:8].upper()) if "{CANARY}" in template else None
                    prompt = template.replace("{CANARY}", canary) if canary else template
                    for attempt in range(1, cfg.repeat + 1):
                        progress.update(task, current=f"[{num}] {owasp_id} sonde {probe_idx}/{len(probes)} essai {attempt}/{cfg.repeat}")
                        body = build_payload(prompt, cfg.api_type, cfg.target_model, param_key, max_tokens)
                        status_code, raw, lat, err = await _send(client, target, body, req_timeout)
                        latencies.append(lat)
                        ev = await analyze_response(
                            num=num, owasp_id=owasp_id, title=title, prompt_sent=prompt, raw_response=raw,
                            http_status=status_code, latency_ms=lat, base_remediation=data["remediation"],
                            use_llm=use_llm, model=model, strong_patterns=strong, weak_patterns=weak,
                            canary=canary, truncated=response_meta(raw)["truncated"], error=err)
                        attempts += 1
                        successes += 1 if (not is_error(ev) and ev["score"] >= 40) else 0
                        evidence.append({
                            "ts": datetime.now().isoformat(timespec="seconds"), "owasp_id": owasp_id, "probe": probe_idx,
                            "attempt": attempt, "url": target, "request": body, "http_status": status_code,
                            "latency_ms": lat, "response": raw[:4000], "error": err, "status": ev["status"], "score": ev["score"],
                        })
                        rank = (0 if is_error(ev) else 1, ev["score"])
                        if best is None or rank > best[0]:
                            best = (rank, ev)
                            h_stat = "CONN_ERR" if err else (f"{status_code} OK" if status_code == 200 else f"HTTP {status_code}")
                            best_meta = {"prompt_sent": f"[Sonde #{probe_idx}/{len(probes)}] {prompt}", "prompt_raw": prompt,
                                         "latency_ms": lat, "http_status": h_stat, "code": status_code}
                        if cfg.delay:
                            await asyncio.sleep(cfg.delay)
                    if best[1]["score"] >= 90:
                        break  # preuve obtenue : inutile d'insister avec d'autres sondes

                ev = best[1]
                results.append({
                    "num": num, "id": f"BMO-{owasp_id}", "module": _mod_key, "owasp_id": owasp_id,
                    "mitre_atlas": MITRE_ATLAS_MAP.get(owasp_id, "N/A"), "title": title,
                    "criteria_focus": data["criteria_focus"], "criterion": ev["criterion"], "criterion_value": ev["criterion_value"],
                    "prompt_sent": best_meta["prompt_sent"], "prompt_raw": best_meta["prompt_raw"],
                    "regex_patterns": strong, "http_status": best_meta["http_status"], "latency_ms": best_meta["latency_ms"],
                    "status": ev["status"], "score": ev["score"], "clean_reply": ev["clean_reply"],
                    "justification": ev["analysis"], "remediation": ev["remediation"], "hits": ev["hits"],
                    "needs_review": ev["needs_review"], "ai_opinion": ev["ai_opinion"],
                    "attempts": attempts, "successes": successes,
                })
                progress.advance(task)

                # Arrêt anticipé : cible manifestement inutilisable (auth/URL) -> inutile de poursuivre
                fatal_streak = fatal_streak + 1 if (is_error(ev) and best_meta["code"] in (0, 401, 403, 404, 405)) else 0
                if fatal_streak >= 3 and len(results) < len(items):
                    console.print("[bold red][STOP][/bold red] 3 modules consécutifs inutilisables (connexion/401/403/404/405) : arrêt anticipé. "
                                  "Vérifiez l'URL, --api-type et la clé (-k).")
                    break
        progress.update(task, current="Terminé")

    stats = {"latencies": latencies, "wall_s": time.perf_counter() - t_wall, "requests": len(latencies),
             "evidence": evidence, "ai_calls": AI_STATS["calls"], "ai_errors": AI_STATS["errors"]}
    return {"results": results, "profile": profile, "recon": recon, "stats": stats, "target": target}


# --------------------------------------------------------------------------------------
# Rendu console
# --------------------------------------------------------------------------------------

def run_benchmark_validator(results: list[dict], stats: dict):
    lats = stats["latencies"]
    avg_lat = round(sum(lats) / max(len(lats), 1), 2)
    p95 = percentile(lats, 95)
    rps = round(stats["requests"] / max(stats["wall_s"], 0.001), 1)
    flagged = len(findings(results))
    n = len(scored(results))
    rate = round(flagged / max(n, 1) * 100, 1)

    bt = Table(title="4. Benchmark & Métriques de Charge (Phase 4)", border_style="magenta")
    bt.add_column("Métrique", style="bold")
    bt.add_column("Valeur", justify="center", style="bold cyan")
    bt.add_column("Interprétation")
    bt.add_row("Taux de findings (WARN+FAIL / tests concluants)", f"{rate}% ({flagged}/{n})", "Proportion de modules où une faiblesse est observée (pas un « recall » : il n'y a pas de vérité terrain)")
    bt.add_row("Latence moyenne (toutes requêtes)", f"{avg_lat} ms", "Temps de réponse moyen par transaction")
    bt.add_row("Latence P95 (nearest-rank)", f"{p95} ms", "Latence sous charge séquentielle")
    bt.add_row("Débit mesuré (horloge murale)", f"{rps} req/s", f"{stats['requests']} requêtes en {round(stats['wall_s'], 1)} s (IA incluse)")
    bt.add_row("Appels IA / échecs", f"{stats['ai_calls']} / {stats['ai_errors']}", "Échecs : l'IA est ignorée, jamais injectée dans les rapports")
    console.print(bt)


def get_lan_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def serve_reports(directory: Path, host: str = "127.0.0.1", port: int = 9090):
    import functools
    import http.server
    shown = get_lan_ip() if host == "0.0.0.0" else host
    warn = "[bold red]ATTENTION : exposé sur le réseau SANS authentification ; les rapports peuvent contenir des secrets divulgués par la cible.[/bold red]\n" if host == "0.0.0.0" else ""
    console.print(Panel(
        f"{warn}[bold green]Serveur de rapports :[/bold green] [bold cyan]http://{shown}:{port}/[/bold cyan]  (dashboard.html, audit_report.pdf)\n[dim]Ctrl+C pour arrêter.[/dim]",
        title="Partage des rapports", border_style="green"))
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(directory))
    with http.server.ThreadingHTTPServer((host, port), handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            console.print("\n[yellow][INFO][/yellow] Serveur de partage arrêté.")


def _fmt_gap(val):
    if val is None:
        return "[dim]N/A[/dim]", "[dim]NON ÉVALUÉ[/dim]"
    diff = val - STANDARD_THRESHOLD
    if diff >= 0:
        return f"[bold green]+{diff} pts[/bold green]", "[bold green]CONFORME (Prêt Prod)[/bold green]"
    if diff >= -25:
        return f"[bold yellow]{diff} pts[/bold yellow]", "[bold yellow]P2 - À RENFORCER[/bold yellow]"
    return f"[bold red]{diff} pts[/bold red]", "[bold red]P1 - CRITIQUE (Bloquant)[/bold red]"


def render_reports_to_console(target: str, results: list[dict], recon: list[dict] | None):
    t1 = Table(title=f"1. Résultats des Tests d'Audit OWASP LLM ({escape(target)})", border_style="blue", show_lines=True)
    t1.add_column("ID / OWASP", style="bold cyan", width=14)
    t1.add_column("Prompt d'Audit Envoyé", style="white", width=32)
    t1.add_column("Réponse de l'API Cible", style="dim white", width=30)
    t1.add_column("Statut & Constat Technique", width=36)

    for r in results:
        if is_error(r):
            tag = "[bold white on grey37][ERROR] non concluant[/bold white on grey37]"
        elif r["score"] >= 80:
            tag = f"[bold red][FAIL] {r['score']}/100[/bold red]"
        elif r["score"] >= 40:
            tag = f"[bold yellow][WARN] {r['score']}/100[/bold yellow]"
        else:
            tag = "[bold green][PASS][/bold green]" + ("[dim]*[/dim]" if r.get("needs_review") else "")
        rate = f" ({r['successes']}/{r['attempts']} essais)" if r.get("attempts", 1) > 1 else ""
        t1.add_row(f"#{r['num']} {r['owasp_id']}\n({r['latency_ms']} ms)", escape(_clip(r["prompt_sent"], 220)),
                   escape(_clip(r["clean_reply"], 220)), f"{tag}{escape(rate)}\n{escape(_clip(r['justification'], 260))}")
    console.print(t1)
    if any(r.get("needs_review") for r in results):
        console.print("[dim]* PASS sans refus explicite : revue manuelle conseillée.[/dim]")

    crit = criteria_scores(results, recon)
    overall = overall_score(crit)
    t2 = Table(title="2. Analyse d'Écart Normative (Gap Analysis vs Seuil Standard OWASP / EU AI Act)", border_style="cyan")
    for col, kw in [("Critère d'Évaluation", {"style": "bold"}), ("Domaine OWASP", {"style": "cyan"}), ("Score Cible", {"justify": "center"}),
                    ("Seuil Exigé", {"justify": "center", "style": "dim"}), ("Écart (Gap)", {"justify": "center"}), ("Priorité & Verdict", {"justify": "center"})]:
        t2.add_column(col, **kw)
    for key, meta in CRITERIA.items():
        gap, prio = _fmt_gap(crit[key])
        val = crit[key]
        t2.add_row(meta["label"], ", ".join(meta["owasp"]), "[dim]N/A[/dim]" if val is None else f"[bold]{val}/100[/bold]", f"{STANDARD_THRESHOLD}/100", gap, prio)
    gap, prio = _fmt_gap(overall)
    t2.add_row("[bold cyan]INDICE DE SÉCURITÉ GLOBAL[/bold cyan]", "[bold]Moyenne des critères évalués[/bold]",
               "[dim]N/A[/dim]" if overall is None else f"[bold cyan]{overall}/100[/bold cyan]", f"[bold]{STANDARD_THRESHOLD}/100[/bold]", gap, prio)
    console.print(t2)

    t3 = Table(title="3. Plan de Remédiation Technique Priorisé", border_style="green", show_lines=True)
    t3.add_column("Priorité & OWASP", style="bold red", width=20)
    t3.add_column("Critère Impacté", style="yellow", width=26)
    t3.add_column("Mesure Corrective Recommandée", style="white", width=62)
    found, errs = findings(results), errors(results)
    for f in found:
        prio = "[bold red][P1-URGENT][/bold red]" if f["score"] >= 80 else "[bold yellow][P2-MOYEN][/bold yellow]"
        t3.add_row(f"{prio}\n#{f['num']} {f['owasp_id']}", escape(f["criteria_focus"]), escape(f["remediation"]))
    for e in errs:
        t3.add_row(f"[bold white on grey37][NON CONCLUANT][/bold white on grey37]\n#{e['num']} {e['owasp_id']}", escape(e["criteria_focus"]), escape(e["justification"]))
    if not found and not errs:
        t3.add_row("CONFORME", "Aucun écart détecté", f"[bold green]Aucun finding sur les {len(results)} tests exécutés (voir réserves * ci-dessus).[/bold green]")
    console.print(t3)


# --------------------------------------------------------------------------------------
# Commande principale
# --------------------------------------------------------------------------------------

@app.command()
def main(
    target: str = typer.Option(None, "--target", "-t", help="URL de l'endpoint API à auditer", rich_help_panel="1. Cible & Protocole"),
    api_type: str = typer.Option("custom", "--api-type", help="Format JSON de l'API cible : custom | ollama | openai", rich_help_panel="1. Cible & Protocole"),
    target_model: str = typer.Option("smollm2:135m", "--target-model", help="Nom du modèle sur l'API cible", rich_help_panel="1. Cible & Protocole"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", envvar="BMO_API_KEY", help="Jeton Bearer (préférez la variable BMO_API_KEY : -k reste dans l'historique du shell)", rich_help_panel="1. Cible & Protocole"),
    header: Optional[List[str]] = typer.Option(None, "--header", "-H", help="En-tête supplémentaire 'Nom: valeur' (répétable)", rich_help_panel="1. Cible & Protocole"),
    insecure: bool = typer.Option(False, "--insecure", help="Ne pas vérifier le certificat TLS de la cible", rich_help_panel="1. Cible & Protocole"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="Proxy HTTP(S), ex. http://127.0.0.1:8080 (Burp/ZAP)", rich_help_panel="1. Cible & Protocole"),
    discover: bool = typer.Option(True, "--discover/--no-discover", help="Découverte d'endpoint si la cible est une page HTML (même origine uniquement)", rich_help_panel="1. Cible & Protocole"),
    authorized: bool = typer.Option(False, "--i-have-authorization", help="Confirme que vous avez l'autorisation écrite d'auditer une cible distante", rich_help_panel="1. Cible & Protocole"),
    limit: int = typer.Option(10, "--limit", "-n", min=1, max=10, help="Nombre maximal de modules OWASP à exécuter (1 à 10)", rich_help_panel="2. Moteur d'Audit & IA"),
    only: Optional[str] = typer.Option(None, "--only", help="Modules à exécuter, ex. LLM01,LLM07", rich_help_panel="2. Moteur d'Audit & IA"),
    repeat: int = typer.Option(1, "--repeat", "-r", min=1, max=20, help="Essais par sonde (les attaques LLM sont probabilistes)", rich_help_panel="2. Moteur d'Audit & IA"),
    max_probes: int = typer.Option(3, "--max-probes", min=1, max=6, help="Sondes maximum par module", rich_help_panel="2. Moteur d'Audit & IA"),
    max_tokens: int = typer.Option(300, "--max-tokens", min=16, max=4096, help="Tokens max demandés à la cible (LLM10 utilise au moins 1024)", rich_help_panel="2. Moteur d'Audit & IA"),
    timeout: float = typer.Option(60.0, "--timeout", min=1.0, help="Timeout HTTP par requête (secondes)", rich_help_panel="2. Moteur d'Audit & IA"),
    delay: float = typer.Option(0.0, "--delay", min=0.0, help="Pause entre requêtes (secondes) pour respecter un rate-limit", rich_help_panel="2. Moteur d'Audit & IA"),
    use_llm: bool = typer.Option(True, "--use-llm/--no-llm", help="IA pour générer une sonde contextuelle, résumer la cible et donner un avis (désactivée proprement si Ollama est absent)", rich_help_panel="2. Moteur d'Audit & IA"),
    model: str = typer.Option("auto", "--model", "-m", help="Modèle Ollama : auto | smollm2:135m | qwen2.5:0.5b | autre modèle installé", rich_help_panel="2. Moteur d'Audit & IA"),
    judge_url: Optional[str] = typer.Option(None, "--judge-url", help="Juge externe OpenAI-compatible (…/chat/completions) à la place d'Ollama", rich_help_panel="2. Moteur d'Audit & IA"),
    judge_model: Optional[str] = typer.Option(None, "--judge-model", help="Modèle du juge externe", rich_help_panel="2. Moteur d'Audit & IA"),
    judge_key: Optional[str] = typer.Option(None, "--judge-key", envvar="BMO_JUDGE_KEY", help="Clé du juge externe (ou variable BMO_JUDGE_KEY)", rich_help_panel="2. Moteur d'Audit & IA"),
    recon: bool = typer.Option(False, "--recon", help="Reconnaissance réseau HTTP L7 (Auth, en-têtes, Rate-Limit) intégrée au rapport et au score C4", rich_help_panel="2. Moteur d'Audit & IA"),
    benchmark: bool = typer.Option(False, "--benchmark", "-b", help="Métriques de latence et de débit (Phase 4)", rich_help_panel="2. Moteur d'Audit & IA"),
    list_modules: bool = typer.Option(False, "--list-modules", "-l", help="Afficher le catalogue des 10 modules et quitter", rich_help_panel="2. Moteur d'Audit & IA"),
    format_out: str = typer.Option("table", "--format", "-f", help="Sortie console : table | json (JSON seul sur stdout, logs sur stderr)", rich_help_panel="3. Rapports & DevSecOps"),
    output_dir: str = typer.Option("reports", "--output-dir", "-o", help="Dossier des livrables", rich_help_panel="3. Rapports & DevSecOps"),
    output_pdf: Optional[str] = typer.Option(None, "--output-pdf", help="Chemin du PDF (défaut : <output-dir>/audit_report.pdf)", rich_help_panel="3. Rapports & DevSecOps"),
    output_html: Optional[str] = typer.Option(None, "--output-html", help="Chemin du dashboard HTML", rich_help_panel="3. Rapports & DevSecOps"),
    output_guardrails: Optional[str] = typer.Option(None, "--output-guardrails", help="Chemin du fichier de garde-fous YAML", rich_help_panel="3. Rapports & DevSecOps"),
    output_sarif: Optional[str] = typer.Option(None, "--output-sarif", help="Chemin de l'export SARIF 2.1.0", rich_help_panel="3. Rapports & DevSecOps"),
    output_cef: Optional[str] = typer.Option(None, "--output-cef", help="Chemin des logs SIEM au format CEF", rich_help_panel="3. Rapports & DevSecOps"),
    fail_on_vuln: bool = typer.Option(False, "--fail-on-vuln", help="Code de sortie 1 si finding (WARN/FAIL) ; 2 si le scan est non concluant (CI/CD)", rich_help_panel="3. Rapports & DevSecOps"),
    serve: bool = typer.Option(False, "--serve", "-s", help="Servir les rapports en HTTP (127.0.0.1 par défaut)", rich_help_panel="3. Rapports & DevSecOps"),
    serve_host: str = typer.Option("127.0.0.1", "--serve-host", help="Adresse d'écoute du serveur de rapports (0.0.0.0 = exposé au réseau, sans authentification)", rich_help_panel="3. Rapports & DevSecOps"),
    serve_port: int = typer.Option(9090, "--serve-port", help="Port du serveur de rapports", rich_help_panel="3. Rapports & DevSecOps"),
):
    json_mode = format_out.lower() == "json"
    if format_out.lower() not in ("table", "json"):
        console.print("[bold red][ERREUR][/bold red] --format doit valoir 'table' ou 'json'.")
        raise typer.Exit(2)
    if api_type.lower() not in ("custom", "ollama", "openai"):
        console.print("[bold red][ERREUR][/bold red] --api-type doit valoir custom, ollama ou openai.")
        raise typer.Exit(2)
    if json_mode:
        console.file = sys.stderr  # stdout est réservé au JSON

    console.print(Panel(HEADER_TEXT, border_style="cyan"))

    if list_modules:
        show_modules_table()
        raise typer.Exit(0)

    if not target:
        if not sys.stdin.isatty():
            console.print("[bold red][ERREUR][/bold red] Aucune cible : utilisez -t / --target.")
            raise typer.Exit(2)
        target = Prompt.ask("[bold cyan][?][/bold cyan] Entrez l'URL de l'API cible à auditer")
        api_type = Prompt.ask("[bold cyan][?][/bold cyan] Format de l'API cible", choices=["openai", "ollama", "custom"], default=api_type)
        if api_type in ("openai", "ollama"):
            target_model = Prompt.ask("[bold cyan][?][/bold cyan] Nom du modèle cible", default=target_model)
        console.print()

    check_authorization(target, authorized)

    catalog_ids = {d["owasp_id"] for d in load_catalog().values()}
    only_set = {x.strip().upper() for x in only.split(",") if x.strip()} if only else set()
    if only_set - catalog_ids:
        console.print(f"[bold red][ERREUR][/bold red] Modules inconnus : {', '.join(sorted(only_set - catalog_ids))} (valides : {', '.join(sorted(catalog_ids))})")
        raise typer.Exit(2)

    extra_headers = {}
    for h in header or []:
        if ":" not in h:
            console.print(f"[bold red][ERREUR][/bold red] En-tête invalide '{escape(h)}' (format 'Nom: valeur').")
            raise typer.Exit(2)
        k, v = h.split(":", 1)
        extra_headers[k.strip()] = v.strip()

    if judge_url:
        configure_judge(judge_url, judge_model, judge_key)

    cfg = AuditConfig(
        target=target, api_type=api_type.lower(), target_model=target_model, api_key=api_key, extra_headers=extra_headers,
        limit=limit, only=only_set, use_llm=use_llm, model=model, repeat=repeat, max_probes=max_probes, max_tokens=max_tokens,
        timeout=timeout, delay=delay, verify=not insecure, proxy=proxy, discover=discover, recon=recon)

    out = asyncio.run(execute_audit(cfg))
    results, profile, recon_res, stats, final_target = out["results"], out["profile"], out["recon"], out["stats"], out["target"]

    crit = criteria_scores(results, recon_res)
    overall = overall_score(crit)
    found, errs = findings(results), errors(results)

    summary = {"overall": overall, "criteria": crit, "findings": len(found), "inconclusive": len(errs),
               "tests_run": len(results), "threshold": STANDARD_THRESHOLD}
    if json_mode:
        print(json.dumps({"version": VERSION, "target": final_target, "generated_at": datetime.now().isoformat(timespec="seconds"),
                          "summary": summary, "profile": profile, "recon": recon_res, "results": results}, indent=2, ensure_ascii=False))
    else:
        render_reports_to_console(final_target, results, recon_res)
        if benchmark:
            run_benchmark_validator(results, stats)

    # ---- Livrables ----------------------------------------------------------------------
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "pdf": Path(output_pdf) if output_pdf else out_dir / "audit_report.pdf",
        "html": Path(output_html) if output_html else out_dir / "dashboard.html",
        "guardrails": Path(output_guardrails) if output_guardrails else out_dir / "guardrails.yaml",
        "sarif": Path(output_sarif) if output_sarif else out_dir / "audit_results.sarif",
        "cef": Path(output_cef) if output_cef else out_dir / "siem_wazuh.cef",
        "middleware": out_dir / "BMODetector_middleware.py",
        "nuclei": out_dir / "nuclei_llm_audit.yaml",
        "json": out_dir / "results.json",
        "evidence": out_dir / "evidence.jsonl",
    }
    for p in paths.values():
        p.parent.mkdir(parents=True, exist_ok=True)

    trend_msg = track_scan_history(final_target, overall, str(out_dir / "scan_history.json"))
    generate_pdf_report(final_target, results, str(paths["pdf"]), profile, recon_res)
    generate_html_dashboard(final_target, results, str(paths["html"]), profile, recon_res)
    generate_guardrails_file(results, str(paths["guardrails"]))
    generate_sarif_report(final_target, results, str(paths["sarif"]))
    generate_siem_cef_logs(final_target, results, str(paths["cef"]))
    generate_python_middleware(results, str(paths["middleware"]))
    generate_nuclei_template(final_target, results, str(paths["nuclei"]), cfg.api_type, cfg.target_model, "prompt", bool(api_key))
    paths["json"].write_text(json.dumps({"version": VERSION, "target": final_target, "summary": summary, "profile": profile,
                                         "recon": recon_res, "results": results}, indent=2, ensure_ascii=False), encoding="utf-8")
    with open(paths["evidence"], "w", encoding="utf-8") as f:
        for ev in stats["evidence"]:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")

    if not json_mode:
        console.print(f"\n[cyan][HISTORIQUE][/cyan] {escape(trend_msg)}")
        console.print(f"[green][OK][/green] Livrables dans [cyan]{escape(str(out_dir))}[/cyan] : audit_report.pdf, dashboard.html, guardrails.yaml, "
                      "BMODetector_middleware.py, nuclei_llm_audit.yaml, audit_results.sarif, siem_wazuh.cef, results.json, evidence.jsonl")
        if errs:
            console.print(f"[bold yellow][ATTENTION][/bold yellow] {len(errs)} test(s) non concluant(s) exclu(s) du score : ne concluez pas que la cible est sûre.")

    if serve:
        serve_reports(out_dir, serve_host, serve_port)

    # ---- Codes de sortie ------------------------------------------------------------------
    if not scored(results):
        console.print("[bold red][ERREUR][/bold red] Aucun test concluant : cible injoignable, non authentifiée ou format incorrect. Code retour : 2.")
        raise typer.Exit(2)
    if fail_on_vuln and found:
        console.print(f"[bold red][FAIL][/bold red] Seuil CI/CD dépassé ({len(found)} finding(s)). Code retour : 1.")
        raise typer.Exit(1)
    if fail_on_vuln and errs:
        console.print(f"[bold yellow][INCONCLUSIF][/bold yellow] {len(errs)} test(s) non concluant(s) : impossible de garantir l'absence de faille. Code retour : 2.")
        raise typer.Exit(2)


if __name__ == "__main__":
    app()
