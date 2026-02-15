
import os
import sys
import shutil
import json
import subprocess
import tempfile
from pathlib import Path

# Set up environment to run the scanner from source
ENV = os.environ.copy()
ENV["PYTHONPATH"] = "src"
ENV["PYTHONIOENCODING"] = "utf-8"

def run_command(args, cwd=None, expect_exit_code=None):
    """Run a CLI command and return the result."""
    cmd = [sys.executable, "-m", "scanner"] + args
    print(f"🚀 Running: {' '.join(args)}")
    
    result = subprocess.run(
        cmd,
        cwd=cwd,
        env=ENV,
        capture_output=True,
        text=True,
        encoding="utf-8"
    )
    
    if expect_exit_code is not None:
        if result.returncode != expect_exit_code:
            print(f"❌ Failed: Expected exit code {expect_exit_code}, got {result.returncode}")
            print("--- STDOUT ---")
            print(result.stdout)
            print("--- STDERR ---")
            print(result.stderr)
            return False, result
    
    return True, result

def run_tests():
    print("🧪 Starting CLI Scenario Verification...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        base_dir = Path(temp_dir)
        print(f"📂 Created temp directory: {base_dir}")
        
        # ---------------------------------------------------------------------
        # SETUP: Create test files with secrets
        # ---------------------------------------------------------------------
        src_dir = base_dir / "src"
        config_dir = base_dir / "config"
        src_dir.mkdir()
        config_dir.mkdir()
        
        # 1. Critical Secret (AWS)
        aws_val = "AKIA" + "EXAMPLE" + "123456789"
        (config_dir / "settings.py").write_text(f'AWS_KEY = "{aws_val}"', encoding="utf-8")
        
        # 2. High Secret (Slack)
        slack_parts = ["xoxb", "0000000000", "0000000000000", "EXAMPLEVALUEFORTESTING_0"]
        slack_val = "-".join(slack_parts[:3]) + "-" + slack_parts[3]
        (src_dir / "app.py").write_text(f'token = "{slack_val}"', encoding="utf-8")
        
        # 3. Low Secret (Generic Config)
        # generic-api-key-assignment requires 16 chars, but env-file-secret is LOW and allows 8
        (base_dir / "local.env").write_text('SECRET_VAL="SUPER_SECRET_VALUE_12345"', encoding="utf-8")

        print("📝 Test files created.")
        print("-" * 40)

        failures = []

        # ---------------------------------------------------------------------
        # 1. Basic Scan
        # ---------------------------------------------------------------------
        # Scan current directory
        ok, res = run_command(["scan", "."], cwd=str(base_dir), expect_exit_code=1)
        if not ok: failures.append("Basic scan .")
        elif "AWS Access Key" not in res.stdout: failures.append("Basic scan missing AWS key")
        else: print("✅ Basic scan . passed")

        # Scan specific file
        ok, res = run_command(["scan", "config/settings.py"], cwd=str(base_dir), expect_exit_code=1)
        if not ok: failures.append("Scan specific file")
        elif "AWS Access Key" not in res.stdout: failures.append("Scan specific file missing finding")
        elif "Slack Bot Token" in res.stdout: failures.append("Scan specific file found too much")
        else: print("✅ Scan specific file passed")

        # Scan specific folder
        ok, res = run_command(["scan", "src/"], cwd=str(base_dir), expect_exit_code=1)
        if not ok: failures.append("Scan specific folder")
        elif "Slack Bot Token" not in res.stdout: failures.append("Scan specific folder missing finding")
        elif "AWS Access Key" in res.stdout: failures.append("Scan specific folder found too much")
        else: print("✅ Scan specific folder passed")

        print("-" * 40)

        # ---------------------------------------------------------------------
        # 2. Output Formats
        # ---------------------------------------------------------------------
        # JSON output
        ok, res = run_command(["scan", ".", "--output", "json"], cwd=str(base_dir), expect_exit_code=1)
        if not ok: failures.append("Output JSON")
        else:
            try:
                data = json.loads(res.stdout)
                if len(data["findings"]) < 3: 
                    failures.append(f"JSON output missing findings (Found {len(data['findings'])}, expected >= 3)")
                    print("--- JSON STDOUT ---")
                    print(res.stdout)
                else: print("✅ Output JSON passed")
            except json.JSONDecodeError:
                failures.append("JSON output invalid")
                print("--- JSON STDOUT (INVALID) ---")
                print(res.stdout)

        # Text output (custom format check needed here if implemented, or just check non-empty)
        ok, res = run_command(["scan", ".", "--output", "text"], cwd=str(base_dir), expect_exit_code=1)
        if not ok: failures.append("Output text")
        elif "AWS Access Key" not in res.stdout: failures.append("Text output missing content")
        else: print("✅ Output Text passed")

        # HTML output
        ok, res = run_command(["scan", ".", "--output", "html"], cwd=str(base_dir), expect_exit_code=1)
        if not ok: failures.append("Output HTML")
        elif "<!DOCTYPE html>" not in res.stdout: failures.append("HTML output invalid")
        else: print("✅ Output HTML passed")
        
        # SARIF output
        ok, res = run_command(["scan", ".", "--output", "sarif"], cwd=str(base_dir), expect_exit_code=1)
        if not ok: failures.append("Output SARIF")
        else:
            try:
                data = json.loads(res.stdout)
                if data["runs"][0]["tool"]["driver"]["name"] != "dotenv-secrets-scanner": 
                    failures.append("SARIF output invalid content")
                else: print("✅ Output SARIF passed")
            except Exception as e:
                failures.append(f"SARIF output error: {e}")

        # Save to file
        report_file = base_dir / "report.json"
        ok, res = run_command(["scan", ".", "--output", "json", "--output-file", "report.json"], cwd=str(base_dir), expect_exit_code=1)
        if not ok: failures.append("Save to file command failed")
        elif not report_file.exists(): failures.append("Report file not created")
        else: print("✅ Save to file passed")

        print("-" * 40)

        # ---------------------------------------------------------------------
        # 3. Filtering and Severity
        # ---------------------------------------------------------------------
        # Severity CRITICAL (Should find AWS, Ignore Slack/Generic)
        ok, res = run_command(["scan", ".", "--severity", "CRITICAL"], cwd=str(base_dir), expect_exit_code=1)
        if not ok: failures.append("Severity CRITICAL command")
        elif "AWS Access Key" not in res.stdout: failures.append("Missing CRITICAL finding")
        elif "Slack Bot Token" in res.stdout: failures.append("Found HIGH finding in CRITICAL mode")
        else: print("✅ Severity CRITICAL filter passed")

        # Fail on Severity
        # Should NOT fail (exit 0) if we only care about CRITICAL but only find LOWs (dummy scenario needed?)
        # Let's test: --fail-on-severity CRITICAL with only LOW secrets -> Exit 0
        # Create a subdir with only LOW secret
        (base_dir / "low_only").mkdir()
        (base_dir / "low_only" / "test.env").write_text('SECRET_TEST="SUPER_SECRET_VALUE_12345"', encoding="utf-8")
        
        ok, res = run_command(["scan", "low_only", "--fail-on-severity", "CRITICAL"], cwd=str(base_dir), expect_exit_code=0)
        if not ok: 
            failures.append("Fail on severity check failed (Should exit 0)")
        elif "Dotenv Secret Value" not in res.stdout: 
            failures.append("Low severity finding not shown")
            print("--- LOW ONLY STDOUT ---")
            print(res.stdout)
        else: print("✅ Fail-on-severity logic passed")

        print("-" * 40)

        # ---------------------------------------------------------------------
        # 4. Performance / Control
        # ---------------------------------------------------------------------
        # Context lines
        ok, res = run_command(["scan", "config/settings.py", "--context-lines", "0"], cwd=str(base_dir), expect_exit_code=1)
        if not ok: failures.append("Context lines command")
        # We need a better check for context lines, but successful execution is a good start
        else: print("✅ Context lines argument passed")

        # Workers
        ok, res = run_command(["scan", ".", "--workers", "8"], cwd=str(base_dir), expect_exit_code=1)
        if not ok: failures.append("Workers command")
        else: print("✅ Workers argument passed")

        print("-" * 40)

        # ---------------------------------------------------------------------
        # 5. Baseline System
        # ---------------------------------------------------------------------
        baseline_file = base_dir / "baseline.json"
        
        # Step 1: Create baseline (Should exit 1 because secrets are found, but write file)
        ok, res = run_command(["scan", ".", "--write-baseline", "baseline.json"], cwd=str(base_dir), expect_exit_code=1)
        if not ok: failures.append("Write baseline command")
        elif not baseline_file.exists(): failures.append("Baseline file not created")
        else: print("✅ Write baseline passed")

        # Step 2: Use baseline (Should exit 0 because all findings are now 'known')
        ok, res = run_command(["scan", ".", "--baseline", "baseline.json"], cwd=str(base_dir), expect_exit_code=0)
        if not ok: failures.append("Use baseline command (Should exit 0)")
        elif "No secrets detected" not in res.stdout: failures.append("Baseline didn't suppress findings")
        else: print("✅ Use baseline passed")

        # Step 3: New secret with baseline (Should find ONLY new secret)
        stripe_val = "sk_live_" + "TEST_ONLY_DO_NOT_PUSH_1234"
        (base_dir / "new_secret.py").write_text(f'STRIPE_KEY = "{stripe_val}"', encoding="utf-8")
        ok, res = run_command(["scan", ".", "--baseline", "baseline.json"], cwd=str(base_dir), expect_exit_code=1)
        if not ok: failures.append("New secret with baseline")
        elif "Stripe Secret Key" not in res.stdout: failures.append("New secret not found")
        elif "AWS Access Key" in res.stdout: failures.append("Old secret not suppressed")
        else: print("✅ Baseline partial suppression passed")

        print("-" * 40)

        # ---------------------------------------------------------------------
        # 6. Git Integration
        # ---------------------------------------------------------------------
        # Init
        ok, res = run_command(["init"], cwd=str(base_dir), expect_exit_code=0)
        if not ok: failures.append("Init command")
        elif not (base_dir / ".secretsignore").exists(): failures.append(".secretsignore not created")
        else: print("✅ Init command passed")

        # Install Hook (Requires .git)
        subprocess.run(["git", "init"], cwd=str(base_dir), capture_output=True)
        ok, res = run_command(["install-hook"], cwd=str(base_dir), expect_exit_code=0)
        if not ok: failures.append("Install hook command")
        elif not (base_dir / ".git" / "hooks" / "pre-commit").exists(): failures.append("Hook file not created")
        else: print("✅ Install hook passed")

        # Uninstall Hook
        ok, res = run_command(["uninstall-hook"], cwd=str(base_dir), expect_exit_code=0)
        if not ok: failures.append("Uninstall hook command")
        elif (base_dir / ".git" / "hooks" / "pre-commit").exists(): failures.append("Hook file not removed")
        else: print("✅ Uninstall hook passed")

        print("-" * 40)
        
        if failures:
            print("🚨 SOME CLI SCENARIOS FAILED:")
            for f in failures:
                print(f"❌ {f}")
            sys.exit(1)
        else:
            print("🎉 ALL CLI SCENARIOS PASSED SUCCESSFULLY!")
            sys.exit(0)

if __name__ == "__main__":
    run_tests()
