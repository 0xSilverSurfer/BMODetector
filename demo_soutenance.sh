#!/usr/bin/env bash
clear
echo "=================================================================="
echo "   DÉMONSTRATION SOUTENANCE - BMODetector v2.1 (ISETCom L3 SR)    "
echo "=================================================================="
read -p "[1/4] Appuyez sur [Entrée] pour afficher l'aide de BMODetector (--help)..."
BMODetector --help

echo ""
read -p "[2/4] Appuyez sur [Entrée] pour afficher le catalogue OWASP LLM Top 10, MITRE ATLAS & Garak (-l)..."
BMODetector -l

echo ""
read -p "[3/4] Appuyez sur [Entrée] pour lancer l'audit complet avec sélection matérielle IA automatique..."
BMODetector -t http://127.0.0.1:8000/v1/chat --recon --benchmark

echo ""
read -p "[4/4] Appuyez sur [Entrée] pour afficher les livrables générés et ouvrir le Dashboard HTML & PDF..."
ls -lh reports/
xdg-open reports/dashboard.html >/dev/null 2>&1 &
xdg-open reports/audit_report.pdf >/dev/null 2>&1 &
echo "[OK] Démonstration terminée."
