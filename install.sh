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

echo "[INFO] Démarrage du service Ollama et téléchargement des 3 modèles IA (Adaptatifs selon le PC)..."
nohup ollama serve >/tmp/ollama.log 2>&1 &
sleep 3
echo "  -> [1/3] Téléchargement du modèle Tier-1 Léger (smollm2:135m - VM / Petite RAM)..."
ollama pull smollm2:135m || true
echo "  -> [2/3] Téléchargement du modèle Tier-2 Équilibré (qwen2.5:0.5b - PC Standard)..."
ollama pull qwen2.5:0.5b || true
echo "  -> [3/3] Téléchargement du modèle Tier-3 Haute Précision (llama3.2:1b - PC Puissant)..."
ollama pull llama3.2:1b || true

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
echo "[OK] Installation terminée avec les 3 modèles IA. BMODetector choisira automatiquement le modèle optimal pour votre PC."
