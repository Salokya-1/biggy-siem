@echo off
REM Biggy SIEM launcher for Windows. Double-click or run from a Command Prompt.
cd /d "%~dp0"
if not exist .venv (
  echo [biggy] creating virtualenv...
  python -m venv .venv
)
call .venv\Scripts\activate
pip install -q -r requirements.txt
echo [biggy] starting - open http://localhost:8642  (login: admin / argus)
python run.py
