@echo off
echo Setting up SEC2_TripleS_RUI Fuzzing Test Environment...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher
    pause
    exit /b 1
)

echo Python found - OK

REM Create virtual environment
echo Creating virtual environment...
python -m venv fuzzing_env
if errorlevel 1 (
    echo ERROR: Failed to create virtual environment
    pause
    exit /b 1
)

REM Activate virtual environment
echo Activating virtual environment...
call fuzzing_env\Scripts\activate.bat

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip

REM Install requirements
echo Installing required packages...
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install requirements
    pause
    exit /b 1
)

REM Create results directory
echo Creating results directory...
mkdir fuzzing_results 2>nul

echo.
echo Setup completed successfully!
echo.
echo Available Tests:
echo   - test_file_path_restrictions.py (SR-06: File path access controls)
echo   - test_authentication_system.py (SR-05: Password authentication security)
echo.
echo To run tests:
echo   1. Activate environment: fuzzing_env\Scripts\activate.bat
echo   2. Run all tests: python run_fuzzing_tests.py
echo   3. Run specific test: python run_fuzzing_tests.py -t test_authentication_system
echo.
echo To view results:
echo   Open fuzzing_results\fuzzing_report.html in your browser
echo.
echo Quick start commands:
echo   fuzzing_env\Scripts\activate.bat
echo   python run_fuzzing_tests.py --verbose
echo.
pause 