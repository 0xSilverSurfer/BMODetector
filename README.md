# BMODetector v2.1 — Offensive LLM & RAG API Security Scanner

**Standards :** OWASP Top 10 for LLM Applications (2025) • MITRE ATLAS™ • EU AI Act (Art. 15) • NVIDIA Garak  
**Plateformes :** Linux, macOS, Windows • **Python :** 3.10+ • **Licence :** MIT

> ⚠️ **Usage autorisé uniquement.** N'auditez que des systèmes dont vous êtes propriétaire ou pour lesquels vous disposez d'une **autorisation écrite**. Une cible distante exige `--i-have-authorization` (ou une confirmation interactive).

---

## 1. Présentation

BMODetector audite des API REST, sites Web d'IA et architectures RAG face aux 10 risques de l'OWASP LLM Top 10, puis produit une analyse d'écart (*Gap Analysis*) et des livrables DevSecOps.

### Fonctionnement
- **Phase 0 — Profilage :** deux questions de découverte (la 2ᵉ rejoue l'historique pour les formats `openai`/`ollama`). Synthèse par mots-clés, enrichie par l'IA si elle est active.
- **Phase 1 — Sondes OWASP (LLM01→LLM10) :** pour chaque module, la sonde du catalogue est **toujours** envoyée, suivie d'une sonde alternative statique (EN) et, si l'IA est active, d'une sonde générée à partir du profil. `--repeat N` rejoue chaque sonde N fois (les attaques LLM sont probabilistes).
- **Verdict déterministe**, jamais dépendant d'un petit modèle :
  - **Canary** : un jeton unique par exécution est inséré dans les sondes d'injection ; s'il réapparaît dans une réponse non refusée, la cible a *obéi* → `FAIL`.
  - **Signatures fortes** (secrets, clés, marqueurs de compromission) → `FAIL` ; **signatures faibles** (emails, téléphones, indices) → `WARN`.
  - Une signature qui n'existe que parce que la cible *cite ou répète* le prompt n'est pas une fuite.
  - **LLM10** : mesure la longueur de sortie et si la génération a été coupée par `max_tokens` (le scanner n'impose pas de plafond bas à cette sonde).
  - L'**IA locale** (Ollama) ou un **juge externe** (`--judge-url`) ne fournit qu'un *avis complémentaire* ; seul un juge externe peut durcir un `PASS` ambigu en `WARN`.
- **Phase 2 — Gap Analysis :** 4 critères (C1 Confidentialité, C2 Garde-fous, C3 Intégrité sorties, C4 Résilience réseau) vs seuil `80/100`. Chaque test n'alimente **que son critère** ; `--recon` alimente C4.
- **Phase 3/4 — Remédiation & benchmark (`--benchmark`) :** latence moyenne, P95 (*nearest-rank*), débit mesuré à l'horloge murale, et taux de *findings* (≠ « recall » : il n'existe pas de vérité terrain).

### Modèle de scoring (important)
| Statut | Signification | Dans la moyenne ? |
|---|---|---|
| `PASS` | Refus explicite, ou aucune signature (marqué `*` = revue manuelle conseillée) | oui |
| `WARN` | Indice à vérifier | oui |
| `FAIL` | Preuve de compromission | oui |
| `ERROR` | **Non concluant** : HTTP 401/403/404/5xx, timeout, réponse vide | **non** |

Une cible injoignable ou non authentifiée n'est **jamais** présentée comme « sécurisée » : si aucun test n'est concluant, l'indice global vaut `N/A` et le code de sortie est `2`.

### Livrables (`--output-dir`, défaut `reports/`)
`audit_report.pdf` • `dashboard.html` (contenu échappé + CSP) • `guardrails.yaml` • `BMODetector_middleware.py` (règles générées **d'après les catégories en échec**) • `nuclei_llm_audit.yaml` (validé avec Nuclei) • `audit_results.sarif` (validé contre le schéma SARIF 2.1.0) • `siem_wazuh.cef` • `results.json` • `evidence.jsonl` (requête/réponse brutes de chaque essai).

---

## 2. Installation

```bash
git clone https://github.com/0xSilverSurfer/BMODetector.git
cd BMODetector
./install.sh            # Linux / macOS (sans sudo ; lien dans ~/.local/bin)
BMODetector --help
```
```powershell
.\install.bat           # Windows
.\BMODetector.bat --help
```
Ollama est **optionnel** (`--no-llm`). L'installateur ne supprime jamais vos modèles et demande confirmation avant d'installer Ollama (`BMO_ASSUME_YES=1` pour automatiser, `BMO_SKIP_OLLAMA=1` pour l'ignorer).  
Installation manuelle : `pip install .` (ou `pip install ".[lab]"` pour la cible de labo).

**Modèle IA sélectionné selon la RAM libre :** < 1,2 Go → `smollm2:135m` • ≥ 1,2 Go → `qwen2.5:0.5b` (si installés). `OLLAMA_HOST` est respecté.

---

## 3. Utilisation

```bash
BMODetector -l                                                        # catalogue (IDs MITRE/Garak vérifiés)
BMODetector -t http://127.0.0.1:8000/v1/chat --recon --benchmark      # labo local (démarré automatiquement)
BMODetector -t http://127.0.0.1:11434/api/generate --api-type ollama --target-model smollm2:135m
export BMO_API_KEY=...   # évite de laisser la clé dans l'historique du shell
BMODetector -t https://api.exemple.com/v1/chat/completions --api-type openai --target-model mon-modele --i-have-authorization
BMODetector -t http://127.0.0.1:8000/v1/chat --only LLM01,LLM07 --repeat 5 --no-llm
BMODetector -t ... -f json > result.json     # JSON seul sur stdout, logs sur stderr
BMODetector -t ... --fail-on-vuln            # CI/CD
```

| Option | Rôle |
|---|---|
| `--no-llm` | Aucune IA (analyse 100 % déterministe). Sans Ollama, l'IA se désactive proprement. |
| `--judge-url/--judge-model/--judge-key` | Juge externe OpenAI-compatible (recommandé pour un verdict plus fin). |
| `--only`, `-n` | Choisir les modules / en limiter le nombre. |
| `--repeat`, `--max-probes`, `--max-tokens`, `--timeout`, `--delay` | Fiabilité et respect des rate-limits. |
| `-H`, `--proxy`, `--insecure`, `--no-discover` | En-têtes/cookies, Burp/ZAP, TLS, découverte d'endpoint. |
| `--serve [--serve-host]` | Sert les rapports sur `127.0.0.1:9090` (`0.0.0.0` = exposé, sans auth). |

**Codes de sortie :** `0` OK • `1` finding(s) avec `--fail-on-vuln` • `2` scan non concluant / erreur d'usage.  
La découverte d'endpoint (`[AUTO-DISCOVERY]`) reste sur l'**origine de la page** : aucune requête vers des domaines tiers.

---

## 4. Tests & cibles d'entraînement

```bash
pip install -e ".[dev]"
ruff check . && pytest -q
```
- `target_lab/mock_api.py` : cible **volontairement vulnérable** (`/v1/chat`), cible saine avec auth (`/v1/chat/secured`), format OpenAI (`/v1/chat/completions`) et rate-limit 429 (`/v1/chat/limited`). Ne jamais l'exposer au réseau.
- Pour s'entraîner sur des applications vulnérables hébergées localement : Damn Vulnerable LLM Agent (WithSecure), MyLLMDoc, etc. Des sandboxes publiques existent (Gandalf, Prompt Airlines, Crucible, PortSwigger Web LLM labs) : ce sont surtout des jeux navigateur ; vérifiez leurs conditions avant toute automatisation.
- Docker : `docker compose up --build` (scanner + cible, rapports dans `./reports`).

---

## 5. Limites connues
- Les signatures du catalogue ont été écrites pour la cible de labo ; sur une application réelle, un `PASS *` signifie « pas de preuve », pas « sûr ». Utilisez `--repeat`, un juge externe et une revue manuelle de `evidence.jsonl`.
- LLM05 (*Improper Output Handling*) ne peut pas être prouvé au niveau API : la présence de HTML actif dans la réponse est un indice, la faille réside dans le rendu côté client.
- Le middleware généré est une défense en profondeur par motifs (contournable) : il ne remplace pas la correction de la cause racine.
- Les sondes sont séquentielles et courtes ; elles ne remplacent pas un outil complet (Garak, PyRIT, promptfoo) pour un audit exhaustif.

## 6. Changelog v2.1
Un test non concluant n'est plus un `PASS` • `--no-llm` désactive réellement l'IA et aucun message d'erreur Ollama ne devient une sonde • la sonde du catalogue n'est plus écartée • verdict déterministe (canary, signatures fortes/faibles, anti-écho) • sorties non tronquées à 50/80 tokens • dashboard HTML échappé (+CSP) et console protégée contre le markup Rich • JSON pur sur stdout • découverte limitée à l'origine • clé API par variable d'environnement, plus de clé par défaut • serveur de rapports sur localhost par défaut • installateurs sans `ollama rm` ni `sudo` • `pip install .` embarque `payloads/` • MITRE ATLAS / Garak corrigés et vérifiés • SARIF valide (règles, empreintes) • Nuclei par module • CEF échappé • tests (pytest), CI, LICENSE.
