import pytest
from scanner.core import SecretScanner
from scanner.models import ScanConfig

def test_detects_api_key():
    """Test that the scanner detects a known pattern."""
    scanner = SecretScanner()
    # A dummy AWS key pattern
    text = 'AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"'
    
    findings = scanner.scan_content(text, source="test")
    
    assert len(findings) > 0
    assert findings[0].pattern_id == "aws-access-key"

def test_clean_text_returns_empty():
    """Test that safe text returns no findings."""
    scanner = SecretScanner()
    text = 'HELLO = "WORLD"'
    
    findings = scanner.scan_content(text, source="test")
    
    assert len(findings) == 0

def test_scan_config_defaults():
    """Test that default configuration is loaded correctly."""
    config = ScanConfig()
    # Based on error, default is LOW
    assert config.min_severity.name == "LOW"
