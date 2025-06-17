@echo off
echo 🔍 SEC2_TripleS_RUI Fuzzing Tests
echo ==================================
echo.

REM Check if virtual environment exists  
if not exist "fuzzing_env" (
    echo ❌ Virtual environment not found. Running setup first...
    call setup_test_environment.bat
)

REM Activate virtual environment
echo 🔧 Activating virtual environment...
call fuzzing_env\Scripts\activate.bat

echo 🚀 Running fuzzing tests...
echo.

REM Run the tests
python run_fuzzing_tests.py --verbose

echo.
echo ✅ Tests completed! Check fuzzing_results\fuzzing_report.html for detailed results.
pause 