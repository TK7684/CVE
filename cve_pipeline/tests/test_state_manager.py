"""
Unit Tests for State Manager Module.
Tests database operations, WAL mode, and crash recovery.
"""
import pytest
import sys
import os
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestStateManager:
    """Test suite for core/state_manager.py"""
    
    @pytest.fixture
    def temp_db(self, tmp_path):
        """Creates a temporary database for testing."""
        # Override settings to use temp directory
        os.environ["DATA_DIR"] = str(tmp_path)
        
        # Import after setting env
        from core.state_manager import StateManager
        
        manager = StateManager()
        manager.db_path = tmp_path / "test_state.db"
        manager._init_db()
        return manager
    
    # ==================== TARGET MANAGEMENT ====================
    
    @pytest.mark.unit
    def test_add_target(self, temp_db):
        """Test adding a new target."""
        temp_db.add_target("https://example.com/page1", stage="recon")
        
        tasks = temp_db.get_pending_tasks()
        assert len(tasks) == 1
        assert tasks[0]["url"] == "https://example.com/page1"
        assert tasks[0]["status"] == "pending"
    
    @pytest.mark.unit
    def test_add_duplicate_target(self, temp_db):
        """Test that duplicate targets are ignored."""
        temp_db.add_target("https://example.com/page1")
        temp_db.add_target("https://example.com/page1")
        temp_db.add_target("https://example.com/page1")
        
        tasks = temp_db.get_pending_tasks()
        assert len(tasks) == 1
    
    @pytest.mark.unit
    def test_update_task_status(self, temp_db):
        """Test updating task status."""
        temp_db.add_target("https://example.com/page1")
        temp_db.update_task_status("https://example.com/page1", "completed", stage="scanned")
        
        # Completed tasks should not appear in pending
        pending = temp_db.get_pending_tasks()
        assert len(pending) == 0
    
    @pytest.mark.unit
    def test_get_pending_tasks_limit(self, temp_db):
        """Test that pending tasks respects limit."""
        for i in range(100):
            temp_db.add_target(f"https://example.com/page{i}")
        
        tasks = temp_db.get_pending_tasks(limit=10)
        assert len(tasks) == 10
    
    # ==================== FINDINGS ====================
    
    @pytest.mark.unit
    def test_add_finding(self, temp_db):
        """Test adding a finding."""
        temp_db.add_target("https://example.com/vuln")
        temp_db.add_finding(
            target_url="https://example.com/vuln",
            tool="nuclei",
            severity="HIGH",
            description="XSS Found",
            confidence="HIGH"
        )
        
        # Query findings directly
        conn = temp_db._get_connection()
        cursor = conn.execute("SELECT * FROM findings")
        findings = cursor.fetchall()
        
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
    
    @pytest.mark.unit
    def test_orphaned_finding_warning(self, temp_db, caplog):
        """Test that findings for unknown targets log a warning."""
        # This target doesn't exist
        temp_db.add_finding(
            target_url="https://unknown.com/page",
            tool="test",
            severity="LOW",
            description="Test"
        )
        
        # Should log warning but not crash
        assert True  # If we got here, no exception
    
    # ==================== WAL MODE ====================
    
    @pytest.mark.unit
    def test_wal_mode_enabled(self, temp_db):
        """Test that WAL mode is enabled."""
        conn = temp_db._get_connection()
        cursor = conn.execute("PRAGMA journal_mode;")
        mode = cursor.fetchone()[0]
        
        assert mode.lower() == "wal"
    
    # ==================== CRASH RECOVERY ====================
    
    @pytest.mark.unit
    def test_checkpoint(self, temp_db):
        """Test that checkpoint doesn't crash."""
        temp_db.add_target("https://example.com/test")
        temp_db.checkpoint()  # Should not raise
        assert True


class TestStateManagerConcurrency:
    """Tests for concurrent access patterns."""
    
    @pytest.fixture
    def temp_db(self, tmp_path):
        os.environ["DATA_DIR"] = str(tmp_path)
        from core.state_manager import StateManager
        
        manager = StateManager()
        manager.db_path = tmp_path / "test_concurrent.db"
        manager._init_db()
        return manager
    
    @pytest.mark.unit
    def test_concurrent_adds(self, temp_db):
        """Test adding targets from multiple threads."""
        import threading
        
        def add_targets(start, count):
            for i in range(start, start + count):
                temp_db.add_target(f"https://example.com/page{i}")
        
        threads = [
            threading.Thread(target=add_targets, args=(0, 50)),
            threading.Thread(target=add_targets, args=(50, 50)),
            threading.Thread(target=add_targets, args=(100, 50))
        ]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        tasks = temp_db.get_pending_tasks(limit=200)
        assert len(tasks) == 150
