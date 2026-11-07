@echo off
rem Installation BMODetector v2.1 (Windows) - sans suppression de vos modeles Ollama.
rem   set BMO_ASSUME_YES=1   repond "oui" aux questions
rem   set BMO_SKIP_OLLAMA=1  ne configure pas Ollama (utilisez alors --no-llm)
chcp 65001 >nul
echo [INFO] Creation de l'environnement virtuel (bmo) et installation de BMODetector...
python -m venv bmo || (echo [ERREUR] Python 3.10+ requis & exit /b 1)
call bmo\Scripts\python.exe -m pip install --upgrade pip -q
call bmo\Scripts\python.exe -m pip install -e ".[lab]" -q || (echo [ERREUR] Echec de l'installation & exit /b 1)

if "%BMO_SKIP_OLLAMA%"=="1" goto wrapper
where ollama >nul 2>nul
if %errorlevel% neq 0 (
    echo [INFO] Ollama ^(moteur IA local^) est OPTIONNEL : BMODetector fonctionne sans, avec --no-llm.
    if "%BMO_ASSUME_YES%"=="1" (set ANS=o) else (set /p ANS="Installer Ollama via winget ? [o/N] ")
    if /i "%ANS%"=="o" winget install -e --id Ollama.Ollama --accept-source-agreements --accept-package-agreements
)
where ollama >nul 2>nul
if %errorlevel% equ 0 (
    curl -s http://127.0.0.1:11434/api/tags >nul 2>nul
    if errorlevel 1 (
        echo [INFO] Demarrage du service Ollama...
        start /b ollama serve >nul 2>nul
        timeout /t 4 /nobreak >nul
    )
    echo   -^> Telechargement de smollm2:135m...
    call ollama pull smollm2:135m
    echo   -^> Telechargement de qwen2.5:0.5b...
    call ollama pull qwen2.5:0.5b
)

:wrapper
(
echo @echo off
echo chcp 65001 ^>nul
echo "%%~dp0bmo\Scripts\BMODetector.exe" %%*
) > BMODetector.bat

if not exist reports mkdir reports
echo [OK] Installation Windows terminee. Executez : .\BMODetector.bat --help
