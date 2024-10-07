@echo off
set root=%cd%
cd %root%
if not exist venv\ (
    python -m venv .\venv
    call .\venv\Scripts\Activate.bat && pip install -r .\requirements.txt && streamlit run .\page.py
) else (    
    call .\venv\Scripts\Activate.bat && streamlit run .\page.py
)

