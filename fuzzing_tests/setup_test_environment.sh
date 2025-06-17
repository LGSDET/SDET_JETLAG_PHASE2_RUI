#!/bin/bash

echo "Setting up SEC2_TripleS_RUI Fuzzing Test Environment..."
echo

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed or not in PATH"
    echo "Please install Python 3.8 or higher"
    exit 1
fi

# Check Python version
python_version=$(python3 -c "import sys; print('.'.join(map(str, sys.version_info[:2])))")
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "ERROR: Python $python_version found, but Python $required_version or higher is required"
    exit 1
fi

echo "Python $python_version found - OK"

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv fuzzing_env
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to create virtual environment"
    exit 1
fi

# Activate virtual environment
echo "Activating virtual environment..."
source fuzzing_env/bin/activate

# Upgrade pip
echo "Upgrading pip..."
python -m pip install --upgrade pip

# Install requirements
echo "Installing required packages..."
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to install requirements"
    exit 1
fi

# Create results directory
echo "Creating results directory..."
mkdir -p fuzzing_results

# Make scripts executable
chmod +x run_fuzzing_tests.py

echo
echo "Setup completed successfully!"
echo
echo "Available Tests:"
echo "  - test_file_path_restrictions.py (SR-06: File path access controls)"
echo "  - test_authentication_system.py (SR-05: Password authentication security)"
echo
echo "To run tests:"
echo "  1. Activate environment: source fuzzing_env/bin/activate"
echo "  2. Run all tests: python run_fuzzing_tests.py"
echo "  3. Run specific test: python run_fuzzing_tests.py -t test_authentication_system"
echo
echo "To view results:"
echo "  Open fuzzing_results/fuzzing_report.html in your browser"
echo
echo "Quick start commands:"
echo "  source fuzzing_env/bin/activate"
echo "  python run_fuzzing_tests.py --verbose"
echo 