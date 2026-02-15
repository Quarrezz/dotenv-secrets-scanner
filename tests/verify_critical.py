
import os
import shutil
import tempfile
import sys
from pathlib import Path
from scanner.core import SecretScanner
from scanner.models import ScanConfig, Severity

def run_verification():
    print("🚀 Starting Critical Feature Verification...")
    
    # Create a temporary directory for testing
    with tempfile.TemporaryDirectory() as temp_dir:
        base_dir = Path(temp_dir)
        print(f"📂 Created temp directory: {base_dir}")

        # 1. Setup Test Files
        
        # A file with a real looking secret (Should be DETECTED)
        secret_file = base_dir / "config.py"
        with open(secret_file, "w", encoding="utf-8") as f:
            f.write(f'AWS_KEY = "{"AKIA" + "EXAMPLE" + "123456789"}"\n') # AWS Key Pattern
            # Construct Slack token dynamically to bypass static analysis
            slack_parts = ["xoxb", "0000000000", "0000000000000", "EXAMPLEVALUEFORTESTING_0"]
            f.write(f'SLACK_TOKEN = "{"-".join(slack_parts[:3])}-{"".join(slack_parts[3:])}"\n') 
            f.write(f'STRIPE_KEY = "{"sk_live_" + "TEST_ONLY_DO_NOT_PUSH_1234"}"\n')

        # A file with a safe example/placeholder (Should be IGNORED by False Positive Filter)
        safe_file = base_dir / "example.env"
        with open(safe_file, "w", encoding="utf-8") as f:
            f.write('AWS_KEY="EXAMPLE_KEY_HERE"\n')
            f.write('STRIPE_KEY=sk_live_EXAMPLE_NOT_A_SECRET_KEY_1234\n')

        # A file that should be ignored by .secretsignore (Should be IGNORED by Exclusion Logic)
        ignored_file = base_dir / "vendor" / "lib.js"
        os.makedirs(ignored_file.parent, exist_ok=True)
        with open(ignored_file, "w", encoding="utf-8") as f:
            f.write('const token = "ghp_bucketfullofsecretsSHOULDBEIGNORED";\n')

        # Create .secretsignore file
        secretsignore = base_dir / ".secretsignore"
        with open(secretsignore, "w", encoding="utf-8") as f:
            f.write("vendor/\n")

        # High Entropy String (Should be DETECTED)
        entropy_file = base_dir / "entropy.py"
        with open(entropy_file, "w", encoding="utf-8") as f:
            f.write('SECRET = "7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c"\n')

        print("📝 Test files created.")

        # 2. Configure Scanner
        config = ScanConfig()
        config.secretsignore_patterns = ["vendor/"] 
        scanner = SecretScanner(config=config)

        # 3. Run Scan
        print("🔍 Scanning...")
        results = scanner.scan_directory(base_dir)

        # 4. Verify Results
        print(f"📊 Scan Complete. Found {len(results.findings)} secrets.")

        # Check Logic
        found_aws = False
        found_slack = False
        found_safe = False
        found_ignored = False
        found_entropy = False

        for finding in results.findings:
            print(f"   - Found: {finding.pattern_name} ({finding.pattern_id}) in {finding.file_path}")
            if "aws-access-key" == finding.pattern_id and "config.py" in str(finding.file_path):
                found_aws = True
            if "slack-bot-token" == finding.pattern_id and "config.py" in str(finding.file_path):
                found_slack = True
            if "example.env" in str(finding.file_path):
                found_safe = True
            if "vendor" in str(finding.file_path):
                found_ignored = True
            if "high-entropy-hex" == finding.pattern_id and "entropy.py" in str(finding.file_path):
                found_entropy = True

        # Assertions
        failures = []
        if not found_aws:
            failures.append("❌ Global Pattern (AWS) mismatch: Real AWS key not found!")
        else:
            print("✅ Global Pattern (AWS) Detection: PASS")

        if not found_slack:
            failures.append("❌ Global Pattern (Slack) mismatch: Real Slack token not found!")
        else:
            print("✅ Global Pattern (Slack) Detection: PASS")

        if found_safe:
            failures.append("❌ False Positive Filter Failed: Picked up example/placeholder values.")
        else:
            print("✅ False Positive Filtering: PASS")
            
        if found_ignored:
            failures.append("❌ Exclusion Logic Failed: Picked up file in 'vendor/' which should be ignored.")
        else:
            print("✅ Exclusion Logic (.secretsignore): PASS")

        if not found_entropy:
            failures.append("❌ Entropy Detection Failed: High entropy hex string not matched.")
        else:
            print("✅ High Entropy Detection: PASS")

        # 5. CLI Verification (Subprocess)
        print("\n💻 Verifying CLI Command...")
        import subprocess
        try:
            # Run scanner module against temp dir
            result = subprocess.run(
                [sys.executable, "-m", "scanner", "scan", str(base_dir)],
                capture_output=True,
                text=True,
                env={**os.environ, "PYTHONPATH": "src", "PYTHONIOENCODING": "utf-8"},
                encoding="utf-8"
            )
            
            # Exit code should be 1 because secrets were found
            if result.returncode == 1:
                print("✅ CLI Exit Code: PASS (1 as expected)")
            else:
                failures.append(f"❌ CLI Exit Code Failed: Expected 1, got {result.returncode}")
                
            # Check for output content
            if "AWS Access Key" in result.stdout and "Slack Bot Token" in result.stdout:
                 print("✅ CLI Output: PASS (Contains expected findings)")
            else:
                 failures.append("❌ CLI Output Failed: Missing expected findings in stdout.")
                 print("--- STDOUT ---")
                 print(result.stdout)
                 print("--- STDERR ---")
                 print(result.stderr)
                 print("--------------")

        except Exception as e:
            failures.append(f"❌ CLI Execution Error: {e}")

        print("-" * 30)
        if failures:
            print("🚨 VERIFICATION FAILED with errors:")
            for fail in failures:
                print(fail)
            sys.exit(1)
        else:
            print("✅ ALL CRITICAL CHECKS PASSED!")
            sys.exit(0)

if __name__ == "__main__":
    run_verification()
