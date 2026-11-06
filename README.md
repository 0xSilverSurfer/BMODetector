# BMODetector v2.0 — Offensive LLM & RAG API Security Scanner

**Standards :** OWASP Top 10 for LLM Applications (2025) • MITRE ATLAS™ • EU AI Act (Art. 15) • NVIDIA Garak / JailbreakBench  
**Plateformes :** Linux (Kali, Ubuntu, Debian) & Windows (PowerShell, CMD)

---

## 1. Présentation Générale
**BMODetector v2.0** est un scanner de vulnérabilités offensif et d'analyse d'écart (*Gap Analysis*) en ligne de commande (CLI) piloté par une **IA locale intégrée (Ollama)**. Il audite de manière automatisée la résistance des API REST, des sites Web d'IA et des architectures RAG face aux 10 risques de l'**OWASP LLM Top 10**.

### Architecture & Fonctionnalités Clés
- **Sélection Matérielle Automatique (`[HARDWARE-AI]`) :** L'installateur télécharge **3 modèles Ollama** et sélectionne automatiquement au démarrage le modèle adapté à la mémoire RAM libre du PC :
  1. `smollm2:135m` *(Tier-1 Ultra-Léger 92 Mo — VM & Petites configurations < 1.2 Go RAM libre)*
  2. `qwen2.5:0.5b` *(Tier-2 Équilibré Bilingue FR/EN 390 Mo — PC Standard 1.2 à 3.8 Go RAM libre)*
  3. `llama3.2:1b` *(Tier-3 Haute Précision 1.3 Go — PC >= 3.8 Go RAM libre)*
- **Spider d'Auto-Découverte Web IA (`[AUTO-DISCOVERY]`) :** Si l'URL fournie est une page Web HTML, le scanner inspecte automatiquement le DOM et les scripts JavaScript (`fetch`, `axios`, `<form>`) pour découvrir l'endpoint API caché et le schéma JSON attendu.
- **Phase 0 — Profilage Sémantique Multi-Tours :** Notre IA génère des questions de découverte (Tours 1 & 2), dialogue avec l'IA cible pour établir la confiance (*Trust*) et déduit son rôle métier ainsi que sa surface d'attaque.
- **Phase 1 — Génération Dynamique des Prompts & Audit OWASP (LLM01 à LLM10) :** À partir du rôle découvert en Phase 0 et des sondes de référence (*Garak / JailbreakBench*), notre IA génère un prompt d'audit contextualisé pour chaque faille, analyse la réponse (Signatures Regex + Entropie de Shannon $H(X)$ + Jugement IA) et attribue un verdict.
- **Phase 2 — Analyse d'Écart Normative (*Gap Analysis*) :** Évaluation sur 4 critères (`C1 Confidentialité`, `C2 Garde-fous`, `C3 Intégrité Sorties`, `C4 Résilience Réseau`) par rapport au seuil standard de mise en production (`80/100`).
- **Phase 3 & 4 — Plan de Remédiation IA (`P1`/`P2`) & Valideur de Benchmark (`--benchmark`) :** Recommandations générées par l'IA et calcul du taux de détection (Recall), de la latence HTTP L7 (`ms`), du Percentile P95 et du débit (`req/s`).
- **6 Livrables Générés Automatiquement (`reports/`) :**
  1. `audit_report.pdf` : Rapport d'audit exécutif et technique PDF.
  2. `dashboard.html` : Tableau de bord visuel Cyber HTML5.
  3. `guardrails.yaml` : Politiques de remédiation DevSecOps.
  4. `BMODetector_middleware.py` : Pare-feu applicatif Python auto-généré.
  5. `nuclei_llm_audit.yaml` : Template officiel ProjectDiscovery Nuclei.
  6. `siem_wazuh.cef` & `audit_results.sarif` : Alertes SOC/SIEM Wazuh (CEF) et export GitHub SARIF 2.1.0.

---

## 2. Installation Clé-en-Main (Linux & Windows)

### Sous Linux (Kali / Ubuntu / Debian)
```bash
git clone https://github.com/0xSilverSurfer/BMODetector.git
cd BMODetector
./install.sh
BMODetector --help
```

### Sous Windows (PowerShell / CMD)
```powershell
git clone https://github.com/0xSilverSurfer/BMODetector.git
cd BMODetector
.\install.bat
.\BMODetector.bat --help
```

---

## 3. Exemples d'Utilisation

```bash
# 1. Afficher le catalogue officiel (OWASP LLM Top 10, MITRE ATLAS & Sondes Garak/JBB)
BMODetector -l

# 2. Auditer un site Web d'IA ou une API (Sélection automatique du modèle IA selon la RAM)
BMODetector -t http://127.0.0.1:8000/v1/chat --recon --benchmark

# 3. Auditer directement un serveur Ollama local ou distant
BMODetector -t http://127.0.0.1:11434/api/generate --api-type ollama --target-model smollm2:135m

# 4. Auditer une API Cloud compatible OpenAI / Groq / Mistral / vLLM
BMODetector -t https://api.groq.com/openai/v1/chat/completions --api-type openai --target-model llama-3.1-8b-instant -k "VOTRE_CLE_API"

# 5. Partager le Dashboard HTML5 et le PDF sur le réseau LAN pour d'autres PC (Port 9090)
BMODetector -t http://127.0.0.1:8000/v1/chat --serve
```
