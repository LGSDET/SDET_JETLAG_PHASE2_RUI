#!/bin/bash

echo "🔍 SEC2_TripleS_RUI Fuzzing Tests"
echo "=================================="
echo

# Check if virtual environment exists
if [ ! -d "fuzzing_env" ]; then
    echo "❌ Virtual environment not found. Running setup first..."
    bash setup_test_environment.sh
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source fuzzing_env/bin/activate

echo "🚀 Running fuzzing tests..."
echo

# Run the tests
python run_fuzzing_tests.py --verbose

echo
echo "✅ Tests completed! Check fuzzing_results/fuzzing_report.html for detailed results." 