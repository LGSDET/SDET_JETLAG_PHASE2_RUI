"""
Main Fuzzing Test Runner
Orchestrates security fuzzing tests for SEC2_TripleS_RUI project
"""

import os
import sys
import subprocess
import time
import json
import argparse
from datetime import datetime
import logging

class FuzzingTestRunner:
    """Main class to run fuzzing tests"""
    
    def __init__(self, verbose=False, output_dir="fuzzing_results"):
        self.verbose = verbose
        self.output_dir = output_dir
        self.test_modules = [
            "test_file_path_restrictions",
            "test_authentication_system"
        ]
        self.results = {}
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO if verbose else logging.WARNING,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(os.path.join(output_dir, 'fuzzing.log')),
                logging.StreamHandler() if verbose else logging.NullHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def run_single_test(self, test_module, test_args=None):
        """Run a single test module"""
        self.logger.info(f"Running test module: {test_module}")
        
        cmd = [sys.executable, "-m", "pytest", f"{test_module}.py", "-v"]
        if test_args:
            cmd.extend(test_args)
        
        # Add output options
        report_file = os.path.join(self.output_dir, f"{test_module}_report.xml")
        cmd.extend(["--junitxml", report_file])
        
        start_time = time.time()
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout per test
            )
            
            end_time = time.time()
            duration = end_time - start_time
            
            self.results[test_module] = {
                "status": "PASSED" if result.returncode == 0 else "FAILED",
                "return_code": result.returncode,
                "duration": duration,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "timestamp": datetime.now().isoformat()
            }
            
            self.logger.info(f"Test {test_module} completed in {duration:.2f}s with status: {self.results[test_module]['status']}")
            
            if result.returncode != 0:
                self.logger.error(f"Test {test_module} failed with stderr: {result.stderr}")
            
            return self.results[test_module]
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Test {test_module} timed out after 300 seconds")
            self.results[test_module] = {
                "status": "TIMEOUT",
                "return_code": -1,
                "duration": 300,
                "stdout": "",
                "stderr": "Test timed out",
                "timestamp": datetime.now().isoformat()
            }
            return self.results[test_module]
            
        except Exception as e:
            self.logger.error(f"Error running test {test_module}: {str(e)}")
            self.results[test_module] = {
                "status": "ERROR",
                "return_code": -2,
                "duration": 0,
                "stdout": "",
                "stderr": str(e),
                "timestamp": datetime.now().isoformat()
            }
            return self.results[test_module]
    
    def run_all_tests(self, parallel=False):
        """Run all fuzzing tests"""
        self.logger.info("Starting fuzzing test suite")
        
        if parallel:
            self.run_tests_parallel()
        else:
            self.run_tests_sequential()
        
        self.generate_summary_report()
        return self.results
    
    def run_tests_sequential(self):
        """Run tests sequentially"""
        for test_module in self.test_modules:
            self.run_single_test(test_module)
    
    def run_tests_parallel(self):
        """Run tests in parallel"""
        import concurrent.futures
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                executor.submit(self.run_single_test, test_module): test_module 
                for test_module in self.test_modules
            }
            
            for future in concurrent.futures.as_completed(futures):
                test_module = futures[future]
                try:
                    result = future.result()
                    self.logger.info(f"Parallel test {test_module} completed with status: {result['status']}")
                except Exception as e:
                    self.logger.error(f"Parallel test {test_module} generated an exception: {e}")
    
    def generate_summary_report(self):
        """Generate summary report"""
        timestamp = datetime.now().isoformat()
        
        # Calculate statistics
        total_tests = len(self.test_modules)
        passed_tests = sum(1 for r in self.results.values() if r['status'] == 'PASSED')
        failed_tests = sum(1 for r in self.results.values() if r['status'] == 'FAILED')
        timeout_tests = sum(1 for r in self.results.values() if r['status'] == 'TIMEOUT')
        error_tests = sum(1 for r in self.results.values() if r['status'] == 'ERROR')
        total_duration = sum(r['duration'] for r in self.results.values())
        
        summary = {
            "timestamp": timestamp,
            "total_tests": total_tests,
            "passed": passed_tests,
            "failed": failed_tests,
            "timeout": timeout_tests,
            "error": error_tests,
            "success_rate": (passed_tests / total_tests * 100) if total_tests > 0 else 0,
            "total_duration": total_duration,
            "individual_results": self.results
        }
        
        # Save JSON report
        json_report_path = os.path.join(self.output_dir, "fuzzing_summary.json")
        with open(json_report_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        # Generate HTML report
        self.generate_html_report(summary)
        
        # Generate text report
        self.generate_text_report(summary)
        
        self.logger.info(f"Summary: {passed_tests}/{total_tests} tests passed ({summary['success_rate']:.1f}%)")
        return summary
    
    def generate_html_report(self, summary):
        """Generate HTML report"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>SEC2_TripleS_RUI Fuzzing Test Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; }}
        .test-result {{ margin: 10px 0; padding: 10px; border-radius: 5px; }}
        .passed {{ background-color: #d4edda; border: 1px solid #c3e6cb; }}
        .failed {{ background-color: #f8d7da; border: 1px solid #f5c6cb; }}
        .timeout {{ background-color: #fff3cd; border: 1px solid #ffeaa7; }}
        .error {{ background-color: #f8d7da; border: 1px solid #f5c6cb; }}
        .details {{ margin-top: 10px; font-family: monospace; font-size: 12px; }}
        .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .stat {{ text-align: center; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>SEC2_TripleS_RUI Security Fuzzing Test Report</h1>
        <p><strong>Generated:</strong> {summary['timestamp']}</p>
        <p><strong>Duration:</strong> {summary['total_duration']:.2f} seconds</p>
    </div>
    
    <div class="stats">
        <div class="stat">
            <h3>{summary['total_tests']}</h3>
            <p>Total Tests</p>
        </div>
        <div class="stat">
            <h3>{summary['passed']}</h3>
            <p>Passed</p>
        </div>
        <div class="stat">
            <h3>{summary['failed']}</h3>
            <p>Failed</p>
        </div>
        <div class="stat">
            <h3>{summary['success_rate']:.1f}%</h3>
            <p>Success Rate</p>
        </div>
    </div>
    
    <div class="summary">
        <h2>Test Results</h2>
"""
        
        for test_name, result in summary['individual_results'].items():
            status_class = result['status'].lower()
            html_content += f"""
        <div class="test-result {status_class}">
            <h3>{test_name}</h3>
            <p><strong>Status:</strong> {result['status']}</p>
            <p><strong>Duration:</strong> {result['duration']:.2f}s</p>
            <p><strong>Return Code:</strong> {result['return_code']}</p>
"""
            
            if result['stderr']:
                html_content += f"""
            <div class="details">
                <strong>Error Output:</strong><br>
                <pre>{result['stderr'][:1000]}...</pre>
            </div>
"""
            
            html_content += "        </div>\n"
        
        html_content += """
    </div>
</body>
</html>
"""
        
        html_report_path = os.path.join(self.output_dir, "fuzzing_report.html")
        with open(html_report_path, 'w') as f:
            f.write(html_content)
    
    def generate_text_report(self, summary):
        """Generate text report"""
        text_content = f"""
SEC2_TripleS_RUI Security Fuzzing Test Report
==============================================

Generated: {summary['timestamp']}
Total Duration: {summary['total_duration']:.2f} seconds

Test Summary:
- Total Tests: {summary['total_tests']}
- Passed: {summary['passed']}
- Failed: {summary['failed']}
- Timeout: {summary['timeout']}
- Error: {summary['error']}
- Success Rate: {summary['success_rate']:.1f}%

Individual Test Results:
"""
        
        for test_name, result in summary['individual_results'].items():
            text_content += f"""
{test_name}:
  Status: {result['status']}
  Duration: {result['duration']:.2f}s
  Return Code: {result['return_code']}
"""
            
            if result['stderr']:
                text_content += f"  Error: {result['stderr'][:200]}...\n"
        
        text_content += """

Test Descriptions:
- test_file_path_restrictions: Tests file path access controls
- test_authentication_system: Tests password authentication security

Security Requirements Tested:
- SR-05: User authentication (login with 16-char limit)
- SR-06: File path restrictions (C:\\Users\\CMU\\RawRecords only)
"""
        
        text_report_path = os.path.join(self.output_dir, "fuzzing_report.txt")
        with open(text_report_path, 'w') as f:
            f.write(text_content)
    
    def run_specific_security_tests(self, security_requirements):
        """Run tests for specific security requirements"""
        test_mapping = {
            "SR-05": "test_authentication_system",
            "SR-06": "test_file_path_restrictions"
        }
        
        tests_to_run = []
        for sr in security_requirements:
            if sr in test_mapping:
                tests_to_run.append(test_mapping[sr])
            else:
                self.logger.warning(f"Unknown security requirement: {sr}")
        
        if not tests_to_run:
            self.logger.error("No valid security requirements specified")
            return {}
        
        self.logger.info(f"Running tests for security requirements: {security_requirements}")
        
        for test_module in tests_to_run:
            self.run_single_test(test_module)
        
        self.generate_summary_report()
        return self.results

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="SEC2_TripleS_RUI Security Fuzzing Test Suite")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-p", "--parallel", action="store_true", help="Run tests in parallel")
    parser.add_argument("-o", "--output", default="fuzzing_results", help="Output directory")
    parser.add_argument("-t", "--test", help="Run specific test module")
    parser.add_argument("-s", "--security", nargs="+", 
                       choices=["SR-05", "SR-06"],
                       help="Run tests for specific security requirements")
    
    args = parser.parse_args()
    
    runner = FuzzingTestRunner(verbose=args.verbose, output_dir=args.output)
    
    if args.test:
        # Run specific test
        result = runner.run_single_test(args.test)
        print(f"Test {args.test} completed with status: {result['status']}")
    elif args.security:
        # Run tests for specific security requirements
        results = runner.run_specific_security_tests(args.security)
        passed = sum(1 for r in results.values() if r['status'] == 'PASSED')
        total = len(results)
        print(f"Security tests completed: {passed}/{total} passed")
    else:
        # Run all tests
        results = runner.run_all_tests(parallel=args.parallel)
        passed = sum(1 for r in results.values() if r['status'] == 'PASSED')
        total = len(results)
        print(f"All fuzzing tests completed: {passed}/{total} passed")
        
        if passed < total:
            sys.exit(1)  # Exit with error if any tests failed

if __name__ == "__main__":
    main() 