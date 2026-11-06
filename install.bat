@echo off
chcp 65001 >nul
echo [INFO] Initialisation de l'environnement BMODetector v2.0 pour Windows...
python -m venv bmo
echo [INFO] Installation des dependances Python requises...
call bmo\Scripts\python.exe -m pip install --upgrade pip -q
call bmo\Scripts\python.exe -m pip install -r requirements.txt -q

where ollama >nul 2>nul
if %errorlevel% neq 0 (
    echo [INFO] Ollama non detecte. Installation via Winget...
    winget install -e --id Ollama.Ollama --accept-source-agreements --accept-package-agreements
)

where ollama >nul 2>nul
if %errorlevel% equ 0 (
    echo [INFO] Telechargement des 3 modeles IA Ollama ^(Adaptatifs selon la RAM du PC^)...
    start /b ollama serve >nul 2>nul
    timeout /t 3 /nobreak >nul
    echo   -^> [1/3] Modele Tier-1 Leger ^(smollm2:135m^)...
    call ollama pull smollm2:135m
    echo   -^> [2/3] Modele Tier-2 Equilibre ^(qwen2.5:0.5b^)...
    call ollama pull qwen2.5:0.5b
    echo   -^> [3/3] Modele Tier-3 Haute Precision ^(llama3.2:1b^)...
    call ollama pull llama3.2:1b
)

(
echo @echo off
echo chcp 65001 ^>nul
echo "%~dp0bmo\Scripts\python.exe" "%~dp0bmo_detector.py" %%*
) > BMODetector.bat

(
echo @echo off
echo chcp 65001 ^>nul
echo "%~dp0python.exe" "%~dp0..\..\bmo_detector.py" %%*
) > bmo\Scripts\BMODetector.bat

if not exist reports mkdir reports
echo [OK] Installation Windows terminee avec les 3 modeles IA.
echo      Executez : .\BMODetector.bat --help
