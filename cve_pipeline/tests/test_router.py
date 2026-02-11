"""
Unit Tests for Router Module.
Tests URL classification, parameter deduplication, and routing logic.
"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.router import Router, TargetType, RoutedTarget


class TestRouterClassification:
    """Test suite for URL classification logic."""
    
    @pytest.fixture
    def router(self):
        """Creates a fresh Router instance."""
        return Router()
    
    # ==================== DYNAMIC URLS ====================
    
    @pytest.mark.unit
    def test_dynamic_url_with_params(self, router):
        """Test that URLs with query parameters are classified as DYNAMIC."""
        urls = [
            "https://example.com/search.php?q=test",
            "https://example.com/page?id=1&cat=2",
            "https://example.com/products?item=widget&sort=price"
        ]
        
        queues = router.route_targets(urls)
        
        assert len(queues[TargetType.DYNAMIC]) == 3
    
    # ==================== LOGIN/ADMIN DETECTION ====================
    
    @pytest.mark.unit
    def test_login_page_detection(self, router):
        """Test that login pages are correctly identified."""
        urls = [
            "https://example.com/login",
            "https://example.com/signin",
            "https://example.com/auth/login",
            "https://example.com/wp-login.php",
            "https://example.com/admin/dashboard"
        ]
        
        queues = router.route_targets(urls)
        
        assert len(queues[TargetType.LOGIN]) == 5
    
    # ==================== API DETECTION ====================
    
    @pytest.mark.unit
    def test_api_endpoint_detection(self, router):
        """Test that API endpoints are correctly identified."""
        urls = [
            "https://example.com/api/v1/users",
            "https://example.com/api/v2/products",
            "https://example.com/graphql",
            "https://example.com/rest/data"
        ]
        
        queues = router.route_targets(urls)
        
        assert len(queues[TargetType.API]) == 4
    
    # ==================== CMS DETECTION ====================
    
    @pytest.mark.unit
    def test_cms_detection(self, router):
        """Test that CMS paths are correctly identified."""
        urls = [
            "https://example.com/wp-content/themes/theme",
            "https://example.com/wp-admin/post.php",
            "https://example.com/joomla/administrator"
        ]
        
        queues = router.route_targets(urls)
        
        assert len(queues[TargetType.CMS]) == 3
    
    # ==================== JS FILE DETECTION ====================
    
    @pytest.mark.unit
    def test_js_file_detection(self, router):
        """Test that JS files are correctly identified."""
        urls = [
            "https://example.com/static/app.js",
            "https://example.com/assets/bundle.min.js"
        ]
        
        queues = router.route_targets(urls)
        
        assert len(queues[TargetType.JS_FILE]) == 2
    
    # ==================== STATIC ASSETS SKIPPED ====================
    
    @pytest.mark.unit
    def test_static_assets_skipped(self, router):
        """Test that static assets (CSS, images) are skipped."""
        urls = [
            "https://example.com/style.css",
            "https://example.com/logo.png",
            "https://example.com/photo.jpg",
            "https://example.com/font.woff2"
        ]
        
        queues = router.route_targets(urls)
        
        # All should be skipped, no queues populated
        total = sum(len(q) for q in queues.values())
        assert total == 0


class TestRouterDeduplication:
    """Test suite for parameter deduplication logic."""
    
    @pytest.fixture
    def router(self):
        return Router()
    
    @pytest.mark.unit
    def test_parameter_deduplication(self, router):
        """Test that URLs with same endpoint but different param values are deduplicated."""
        urls = [
            "https://example.com/page.php?id=1",
            "https://example.com/page.php?id=2",
            "https://example.com/page.php?id=999",
            "https://example.com/page.php?id=abc"
        ]
        
        queues = router.route_targets(urls)
        
        # Should only have 1 unique endpoint
        assert len(queues[TargetType.DYNAMIC]) == 1
    
    @pytest.mark.unit
    def test_different_params_not_deduplicated(self, router):
        """Test that URLs with different parameters are NOT deduplicated."""
        urls = [
            "https://example.com/page.php?id=1",
            "https://example.com/page.php?user=1",
            "https://example.com/page.php?id=1&cat=2"
        ]
        
        queues = router.route_targets(urls)
        
        # All have different param combinations, so all unique
        assert len(queues[TargetType.DYNAMIC]) == 3
    
    @pytest.mark.unit
    def test_different_paths_not_deduplicated(self, router):
        """Test that different paths with same params are NOT deduplicated."""
        urls = [
            "https://example.com/page1.php?id=1",
            "https://example.com/page2.php?id=1",
            "https://example.com/page3.php?id=1"
        ]
        
        queues = router.route_targets(urls)
        
        # Different paths = different endpoints
        assert len(queues[TargetType.DYNAMIC]) == 3
    
    @pytest.mark.unit
    def test_exact_duplicate_removal(self, router):
        """Test that exact duplicate URLs are removed."""
        urls = [
            "https://example.com/page?id=1",
            "https://example.com/page?id=1",
            "https://example.com/page?id=1"
        ]
        
        queues = router.route_targets(urls)
        
        assert len(queues[TargetType.DYNAMIC]) == 1


class TestRouterEdgeCases:
    """Edge case tests for Router."""
    
    @pytest.fixture
    def router(self):
        return Router()
    
    @pytest.mark.unit
    def test_empty_url_list(self, router):
        """Test handling of empty URL list."""
        queues = router.route_targets([])
        total = sum(len(q) for q in queues.values())
        assert total == 0
    
    @pytest.mark.unit
    def test_whitespace_urls(self, router):
        """Test that whitespace-only URLs are skipped."""
        urls = ["", "   ", "\n", "\t"]
        queues = router.route_targets(urls)
        total = sum(len(q) for q in queues.values())
        assert total == 0
    
    @pytest.mark.unit
    def test_mixed_priority(self, router):
        """Test that more specific classifications take priority."""
        # A login page with params should be LOGIN, not DYNAMIC
        urls = ["https://example.com/login?next=/dashboard"]
        queues = router.route_targets(urls)
        
        assert len(queues[TargetType.LOGIN]) == 1
        assert len(queues[TargetType.DYNAMIC]) == 0
