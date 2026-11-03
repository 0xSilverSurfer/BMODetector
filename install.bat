@echo off
chcp 65001 >nul
echo [INFO] Initialisation de l'environnement BMODetector v2.0 pour Windows...
python -m venv bmo
echo [INFO] Installation des dependances requises...
call bmo\Scripts\pip.exe install --upgrade pip -q
call bmo\Scripts\pip.exe install -r requirements.txt -q

echo @echo off > BMODetector.bat
echo chcp 65001 ^>nul >> BMODetector.bat
echo "%~dp0bmo\Scripts\python.exe" "%~dp0bmo_detector.py" %%* >> BMODetector.bat

echo @echo off > bmo\Scripts\BMODetector.bat
echo chcp 65001 ^>nul >> bmo\Scripts\BMODetector.bat
echo "%~dp0python.exe" "%~dp0..\..\bmo_detector.py" %%* >> bmo\Scripts\BMODetector.bat

if not exist reports mkdir reports
echo [OK] Installation Windows terminee avec succes.
echo      Executez : .\BMODetector --help
