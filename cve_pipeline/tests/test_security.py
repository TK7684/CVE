"""
Security Tests.
Tests for input validation, injection prevention, and audit logging.
"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from security.validator import SecurityValidator, ThreatLevel


class TestSecurityValidator:
    """Test suite for security/validator.py"""
    
    @pytest.fixture
    def validator(self):
        return SecurityValidator()
    
    # ==================== URL VALIDATION ====================
    
    @pytest.mark.security
    def test_valid_https_url(self, validator):
        """Test that valid HTTPS URLs pass."""
        result = validator.validate_url("https://example.com/page")
        assert result.is_valid is True
        assert result.threat_level == ThreatLevel.SAFE
    
    @pytest.mark.security
    def test_valid_http_url(self, validator):
        """Test that valid HTTP URLs pass."""
        result = validator.validate_url("http://example.com/page")
        assert result.is_valid is True
    
    @pytest.mark.security
    def test_invalid_scheme_rejected(self, validator):
        """Test that non-HTTP(S) schemes are rejected."""
        result = validator.validate_url("ftp://example.com/file")
        assert result.is_valid is False
        
        result = validator.validate_url("file:///etc/passwd")
        assert result.is_valid is False
        
        result = validator.validate_url("javascript:alert(1)")
        assert result.is_valid is False
    
    # ==================== INJECTION PREVENTION ====================
    
    @pytest.mark.security
    def test_semicolon_injection(self, validator):
        """Test that semicolon command injection is detected."""
        result = validator.validate_url("https://example.com/; rm -rf /")
        assert result.is_valid is False
        assert result.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]
    
    @pytest.mark.security
    def test_pipe_injection(self, validator):
        """Test that pipe command injection is detected."""
        result = validator.validate_url("https://example.com/| cat /etc/passwd")
        assert result.is_valid is False
    
    @pytest.mark.security
    def test_backtick_injection(self, validator):
        """Test that backtick command injection is detected."""
        result = validator.validate_url("https://example.com/`whoami`")
        assert result.is_valid is False
    
    @pytest.mark.security
    def test_dollar_paren_injection(self, validator):
        """Test that $(command) injection is detected."""
        result = validator.validate_url("https://example.com/$(id)")
        assert result.is_valid is False
    
    @pytest.mark.security
    def test_newline_injection(self, validator):
        """Test that newline injection is detected."""
        result = validator.validate_url("https://example.com/\ncat /etc/passwd")
        assert result.is_valid is False
    
    @pytest.mark.security
    def test_null_byte_injection(self, validator):
        """Test that null byte injection is detected."""
        result = validator.validate_url("https://example.com/\x00cmd")
        assert result.is_valid is False
    
    # ==================== SANITIZATION ====================
    
    @pytest.mark.security
    def test_sanitize_url_safe(self, validator):
        """Test URL sanitization produces safe output."""
        safe_url = validator.sanitize_url("https://example.com/search?q=test")
        assert safe_url is not None
        assert ";" not in safe_url
        assert "|" not in safe_url
    
    @pytest.mark.security
    def test_sanitize_url_dangerous_returns_none(self, validator):
        """Test that dangerous URLs return None when sanitized."""
        result = validator.sanitize_url("https://example.com/; rm -rf /")
        assert result is None
    
    @pytest.mark.security
    def test_sanitize_for_shell(self, validator):
        """Test shell sanitization."""
        # Should properly quote the string
        result = validator.sanitize_for_shell("test value")
        assert result.startswith("'") or result.startswith('"')
    
    # ==================== DOMAIN VALIDATION ====================
    
    @pytest.mark.security
    def test_valid_domain(self, validator):
        """Test valid domain names pass."""
        result = validator.validate_domain("example.com")
        assert result.is_valid is True
        
        result = validator.validate_domain("sub.example.com")
        assert result.is_valid is True
    
    @pytest.mark.security
    def test_invalid_domain_format(self, validator):
        """Test invalid domain formats are rejected."""
        result = validator.validate_domain("not a domain")
        assert result.is_valid is False
        
        result = validator.validate_domain("example..com")
        assert result.is_valid is False
    
    # ==================== PATH VALIDATION ====================
    
    @pytest.mark.security
    def test_directory_traversal_blocked(self, validator):
        """Test that directory traversal is blocked."""
        result = validator.validate_file_path("../../../etc/passwd")
        assert result.is_valid is False
        assert result.threat_level == ThreatLevel.HIGH
    
    @pytest.mark.security
    def test_sensitive_path_warning(self, validator):
        """Test that sensitive paths trigger warnings."""
        result = validator.validate_file_path("/etc/shadow")
        # May be valid but should have warnings
        assert len(result.warnings) > 0 or result.threat_level != ThreatLevel.SAFE


class TestAuditLogger:
    """Test suite for security/audit.py"""
    
    @pytest.fixture
    def audit_logger(self, tmp_path):
        import logging
        # Reset audit logger handlers to prevent stale handlers from previous tests
        logger = logging.getLogger("audit")
        handlers = logger.handlers[:]
        for handler in handlers:
            logger.removeHandler(handler)
            handler.close()
            
        from security.audit import AuditLogger
        return AuditLogger(log_dir=tmp_path)
    
    @pytest.mark.security
    def test_audit_log_creation(self, audit_logger):
        """Test that audit logs are created."""
        from security.audit import AuditAction
        
        audit_logger.log(AuditAction.PIPELINE_START, target="example.com")
        
        assert audit_logger.log_file.exists()
    
    @pytest.mark.security
    def test_audit_log_format(self, audit_logger):
        """Test that audit logs are valid JSON."""
        import json
        from security.audit import AuditAction
        
        audit_logger.log(AuditAction.FINDING_DETECTED, target="test.com", details={"severity": "HIGH"})
        
        events = audit_logger.get_recent_events()
        assert len(events) > 0
        assert events[0]["action"] == "finding_detected"
    
    @pytest.mark.security
    def test_session_id_consistent(self, audit_logger):
        """Test that session ID is consistent across logs."""
        from security.audit import AuditAction
        
        audit_logger.log(AuditAction.SCAN_START, target="test1.com")
        audit_logger.log(AuditAction.SCAN_END, target="test1.com")
        
        events = audit_logger.get_recent_events()
        session_ids = {e["session_id"] for e in events}
        assert len(session_ids) == 1  # All same session


class TestSecretsManager:
    """Test suite for security/secrets.py"""
    
    @pytest.fixture
    def secrets_manager(self):
        from security.secrets import SecretsManager
        return SecretsManager()
    
    @pytest.mark.security
    def test_mask_value(self, secrets_manager):
        """Test that secrets are properly masked."""
        masked = secrets_manager._mask_value("sk-1234567890abcdef")
        assert "sk-1" in masked
        assert "cdef" in masked
        assert "567890abc" not in masked  # Middle should be masked
    
    @pytest.mark.security
    def test_generate_secure_token(self, secrets_manager):
        """Test secure token generation."""
        token1 = secrets_manager.generate_secure_token()
        token2 = secrets_manager.generate_secure_token()
        
        assert token1 != token2  # Should be unique
        assert len(token1) >= 32  # Should be long enough
    
    @pytest.mark.security
    def test_hash_and_verify(self, secrets_manager):
        """Test password hashing and verification."""
        value = "my_secret_password"
        hashed = secrets_manager.hash_value(value)
        
        assert secrets_manager.verify_hash(value, hashed) is True
        assert secrets_manager.verify_hash("wrong_password", hashed) is False
