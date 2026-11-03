#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "[INFO] Initialisation de l'environnement d'exécution BMODetector v2.0..."
python3 -m venv bmo
echo "[INFO] Installation des dépendances requises..."
./bmo/bin/pip install --upgrade pip -q
./bmo/bin/pip install -r requirements.txt -q

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
