#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "[INFO] Initialisation de l'environnement d'exécution BMODetector v2.0..."
python3 -m venv bmo
echo "[INFO] Installation des dépendances Python requises..."
./bmo/bin/pip install --upgrade pip -q
./bmo/bin/pip install -r requirements.txt -q

if ! command -v ollama >/dev/null 2>&1; then
    echo "[INFO] Installation du moteur IA local Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
fi

echo "[INFO] Démarrage du service Ollama et téléchargement des modèles IA..."
nohup ollama serve >/tmp/ollama.log 2>&1 &
sleep 3
ollama rm llama3.2:1b 2>/dev/null || true
echo "  -> [1/2] Téléchargement du modèle Léger (smollm2:135m - VM / Petite RAM)..."
ollama pull smollm2:135m || true
echo "  -> [2/2] Téléchargement du modèle Équilibré (qwen2.5:0.5b - PC Standard)..."
ollama pull qwen2.5:0.5b || true

cat << SCRIPT > ./bmo/bin/BMODetector
#!${DIR}/bmo/bin/python3
import sys
sys.path.insert(0, "${DIR}")
from bmo_detector import app
if __name__ == "__main__":
    app()
SCRIPT

chmod +x ./bmo/bin/BMODetector
echo "[INFO] Enregistrement du binaire dans /usr/local/bin/BMODetector..."
sudo ln -sf "${DIR}/bmo/bin/BMODetector" /usr/local/bin/BMODetector
mkdir -p reports
echo "[OK] Installation terminée avec succès. Exécutez 'BMODetector --help' pour afficher l'aide."
