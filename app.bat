@echo off
setlocal

:: Function to check if Python is installed
:CheckPythonVersion
python --version 2>nul
IF ERRORLEVEL 1 (
    echo Python is not installed.
    goto :InstallPython
)

for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do (
    set PYTHON_VERSION=%%v
)

:: Split the Python version into components (major, minor)
for /f "tokens=1,2 delims=." %%a in ("%PYTHON_VERSION%") do (
    set MAJOR=%%a
    set MINOR=%%b
)

:: Check if Python version is 3.12 or higher
if %MAJOR%==3 if %MINOR% geq 12 (
    goto :End
) else (
    echo Python version is older: %PYTHON_VERSION%.
    goto :InstallPython
)

:InstallPython
echo Downloading Python 3.12 installer...

:: Download Python installer using PowerShell
powershell -Command "Invoke-WebRequest -Uri https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe -OutFile %TEMP%\python-3.12.7-amd64.exe"

echo Installing Python 3.12...
:: Install Python 3.12 silently and add it to the PATH
start /wait %TEMP%\python-3.12.0-amd64.exe /quiet InstallAllUsers=1 PrependPath=1

echo Python 3.12 installation completed.
python --version

:End
endlocal
set root=%cd%
cd %root%
if not exist venv\ (
    echo Instaling TARA Importer...
    python -m venv .\venv
    call .\venv\Scripts\Activate.bat && pip install -r .\requirements.txt && echo Importer Installation completed. && Running the importer... && streamlit run .\page.py
) else (    
    echo TARA Importer is already installed. && echo Running the importer... && call .\venv\Scripts\Activate.bat && streamlit run .\page.py
)

