#!/usr/bin/env bash
# Installation BMODetector v2.1 (Linux / macOS) — sans sudo, sans suppression de vos modèles Ollama.
#   BMO_ASSUME_YES=1   répond « oui » aux questions (mode non interactif)
#   BMO_SKIP_OLLAMA=1  n'installe/ne configure pas Ollama (utilisez alors --no-llm)
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

ask() {  # ask "question" -> 0 si oui
    [ "${BMO_ASSUME_YES:-0}" = "1" ] && return 0
    [ -t 0 ] || return 1
    read -r -p "$1 [o/N] " answer
    [[ "$answer" =~ ^[OoYy]$ ]]
}

command -v python3 >/dev/null 2>&1 || { echo "[ERREUR] python3 (>= 3.10) est requis."; exit 1; }
python3 - <<'PY' || { echo "[ERREUR] Python >= 3.10 requis."; exit 1; }
import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)
PY

echo "[INFO] Création de l'environnement virtuel (./bmo) et installation de BMODetector..."
python3 -m venv bmo
./bmo/bin/pip install --quiet --upgrade pip
./bmo/bin/pip install --quiet -e ".[lab]"

if [ "${BMO_SKIP_OLLAMA:-0}" != "1" ]; then
    if ! command -v ollama >/dev/null 2>&1; then
        echo "[INFO] Ollama (moteur IA local) est OPTIONNEL : BMODetector fonctionne sans, avec --no-llm."
        if ask "Installer Ollama avec le script officiel (curl | sh, https://ollama.com/install.sh) ?"; then
            curl -fsSL https://ollama.com/install.sh | sh
        else
            echo "[INFO] Ollama non installé : utilisez 'BMODetector --no-llm ...'."
        fi
    fi

    if command -v ollama >/dev/null 2>&1; then
        OLLAMA_PID=""
        if ! curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
            echo "[INFO] Démarrage temporaire du service Ollama..."
            nohup ollama serve >/tmp/ollama.log 2>&1 &
            OLLAMA_PID=$!
            for _ in $(seq 1 30); do
                curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1 && break
                sleep 0.5
            done
        fi
        for model in smollm2:135m qwen2.5:0.5b; do
            echo "  -> Téléchargement du modèle $model..."
            ollama pull "$model" || echo "[WARN] Échec du téléchargement de $model (relancez 'ollama pull $model')."
        done
        [ -n "$OLLAMA_PID" ] && kill "$OLLAMA_PID" 2>/dev/null || true
    fi
fi

# Lien utilisateur (aucun sudo requis)
mkdir -p "$HOME/.local/bin"
ln -sf "$DIR/bmo/bin/BMODetector" "$HOME/.local/bin/BMODetector"
mkdir -p reports
case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) echo "[INFO] Ajoutez ce dossier à votre PATH :  export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac
echo "[OK] Installation terminée. Essayez : BMODetector --help   |   BMODetector -l"
