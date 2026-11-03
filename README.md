# BMODetector v2.0 — Offensive LLM & RAG API Security Scanner

**Standards :** OWASP Top 10 for LLM Applications (2025) • MITRE ATLAS • EU AI Act (Art. 15) • NVIDIA Garak / JailbreakBench

---

## 1. Présentation
**BMODetector v2.0** est un scanner de vulnérabilités et d analyse d écart (Gap Analysis) en ligne de commande (CLI), compatible **Linux** et **Windows**, conçu pour auditer la sécurité des API REST exposant des Modèles de Langage (LLM) et des architectures RAG.

### Fonctionnalités Principales
- **Phase 0 — Profilage Sémantique Multi-Tours :** Dialogue préliminaire avec l IA cible pour identifier son rôle métier et sa surface d attaque.
- **Phase 1 — Audit OWASP LLM Top 10 (LLM01 à LLM10) :** Détection hybride combinant signatures Regex, calcul d entropie de Shannon H(X) et jugement par modèle local **Ollama** (LLM-as-a-Judge).
- **Phase 2 — Analyse d Écart Normative (Gap Analysis) :** Évaluation multicritères (C1 à C4) par rapport au seuil standard de production (80/100).
- **Phase 3 & 4 — Plan de Remédiation Priorisé (P1/P2) & Valideur de Benchmark (--benchmark) :** Mesure du taux de détection (Recall), de la latence HTTP L7 (ms), du Percentile P95 et du débit (req/s).
- **6 Livrables Générés Automatiquement (reports/) :**
  1. audit_report.pdf : Rapport d audit exécutif et technique PDF.
  2. dashboard.html : Tableau de bord visuel HTML5.
  3. guardrails.yaml : Politiques de remédiation DevSecOps.
  4. BMODetector_middleware.py : Pare-feu applicatif Python auto-généré.
  5. nuclei_llm_audit.yaml : Template ProjectDiscovery Nuclei.
  6. siem_wazuh.cef & audit_results.sarif : Alertes SOC/SIEM Wazuh (CEF) et export GitHub SARIF 2.1.0.

---

## 2. Installation (Linux & Windows)

### Sous Linux (Kali / Ubuntu / Debian)
    git clone https://github.com/0xSilverSurfer/BMODetector.git
    cd BMODetector
    ./install.sh
    BMODetector --help

### Sous Windows (PowerShell / CMD)
    git clone https://github.com/0xSilverSurfer/BMODetector.git
    cd BMODetector
    .\install.bat
    .\BMODetector --help

---

## 3. Exemples d Utilisation

    BMODetector -l
    BMODetector -t http://127.0.0.1:11434/api/generate --api-type ollama --target-model smollm2:135m --use-llm
    BMODetector -t http://127.0.0.1:8000/v1/chat --recon --benchmark --use-llm
    BMODetector -t http://127.0.0.1:8000/v1/chat --use-llm --serve
