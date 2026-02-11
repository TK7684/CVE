"""
Unit Tests for Scope Guard Module.
Tests domain validation, scope enforcement, and edge cases.
"""
import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestScopeGuard:
    """Test suite for utils/scope_guard.py"""
    
    @pytest.fixture
    def scope_guard(self):
        """Creates a fresh ScopeGuard instance with test rules."""
        from utils.scope_guard import ScopeGuard
        
        guard = ScopeGuard()
        guard.allowed_domains = [".example.com", "api.example.com", "target.io"]
        guard.excluded_domains = ["out-of-scope.example.com", "admin.example.com"]
        return guard
    
    # ==================== POSITIVE TESTS ====================
    
    @pytest.mark.unit
    def test_exact_domain_match(self, scope_guard):
        """Test that exact domain matches are allowed."""
        assert scope_guard.is_in_scope("https://api.example.com/users") is True
        assert scope_guard.is_in_scope("https://target.io/api/v1") is True
    
    @pytest.mark.unit
    def test_subdomain_wildcard_match(self, scope_guard):
        """Test that subdomains matching .example.com are allowed."""
        assert scope_guard.is_in_scope("https://www.example.com/") is True
        assert scope_guard.is_in_scope("https://sub.example.com/page") is True
        assert scope_guard.is_in_scope("https://deep.sub.example.com/") is True
    
    @pytest.mark.unit
    def test_url_with_port(self, scope_guard):
        """Test URLs with port numbers are handled correctly."""
        assert scope_guard.is_in_scope("https://api.example.com:8443/") is True
        assert scope_guard.is_in_scope("http://www.example.com:8080/login") is True
    
    @pytest.mark.unit
    def test_url_with_query_params(self, scope_guard):
        """Test URLs with query parameters are allowed."""
        assert scope_guard.is_in_scope("https://www.example.com/search?q=test&page=1") is True
    
    # ==================== NEGATIVE TESTS ====================
    
    @pytest.mark.unit
    def test_out_of_scope_domain(self, scope_guard):
        """Test that out-of-scope domains are rejected."""
        assert scope_guard.is_in_scope("https://google.com/") is False
        assert scope_guard.is_in_scope("https://facebook.com/") is False
        assert scope_guard.is_in_scope("https://malicious.com/") is False
    
    @pytest.mark.unit
    def test_excluded_domain(self, scope_guard):
        """Test that excluded domains are rejected even if they match allowed pattern."""
        assert scope_guard.is_in_scope("https://out-of-scope.example.com/") is False
        assert scope_guard.is_in_scope("https://admin.example.com/panel") is False
    
    @pytest.mark.unit
    def test_similar_but_different_domain(self, scope_guard):
        """Test that similar-looking domains are rejected."""
        # These look like example.com but are not
        assert scope_guard.is_in_scope("https://notexample.com/") is False
        assert scope_guard.is_in_scope("https://example.com.evil.com/") is False
        assert scope_guard.is_in_scope("https://fakeexample.com/") is False
    
    @pytest.mark.unit
    def test_third_party_cdns(self, scope_guard):
        """Test that CDNs and third-party services are rejected."""
        assert scope_guard.is_in_scope("https://cdn.jsdelivr.net/") is False
        assert scope_guard.is_in_scope("https://fonts.googleapis.com/") is False
        assert scope_guard.is_in_scope("https://www.google-analytics.com/") is False
    
    # ==================== EDGE CASES ====================
    
    @pytest.mark.unit
    def test_empty_url(self, scope_guard):
        """Test that empty URLs are rejected."""
        assert scope_guard.is_in_scope("") is False
    
    @pytest.mark.unit
    def test_malformed_url(self, scope_guard):
        """Test that malformed URLs are handled gracefully."""
        assert scope_guard.is_in_scope("not-a-valid-url") is False
        assert scope_guard.is_in_scope("://missing-scheme.com") is False
    
    @pytest.mark.unit
    def test_url_with_credentials(self, scope_guard):
        """Test URLs with embedded credentials."""
        # These should still work (domain extraction ignores userinfo)
        assert scope_guard.is_in_scope("https://user:pass@www.example.com/") is True
    
    @pytest.mark.unit
    def test_ip_address(self, scope_guard):
        """Test that IP addresses are rejected (not in scope by default)."""
        assert scope_guard.is_in_scope("http://192.168.1.1/") is False
        assert scope_guard.is_in_scope("http://10.0.0.1:8080/admin") is False
    
    @pytest.mark.unit
    def test_localhost(self, scope_guard):
        """Test that localhost is rejected."""
        assert scope_guard.is_in_scope("http://localhost/") is False
        assert scope_guard.is_in_scope("http://127.0.0.1/") is False


class TestScopeGuardBulk:
    """Tests for bulk URL filtering."""
    
    @pytest.fixture
    def scope_guard(self):
        from utils.scope_guard import ScopeGuard
        guard = ScopeGuard()
        guard.allowed_domains = [".target.com"]
        guard.excluded_domains = []
        return guard
    
    @pytest.mark.unit
    def test_filter_mixed_urls(self, scope_guard):
        """Test filtering a mixed list of URLs."""
        urls = [
            "https://www.target.com/page1",
            "https://google.com/search",
            "https://api.target.com/v1/users",
            "https://facebook.com/",
            "https://sub.target.com/endpoint"
        ]
        
        filtered = [u for u in urls if scope_guard.is_in_scope(u)]
        
        assert len(filtered) == 3
        assert "https://google.com/search" not in filtered
        assert "https://facebook.com/" not in filtered
