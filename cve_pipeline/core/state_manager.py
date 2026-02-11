import sqlite3
import threading
from datetime import datetime
from config.settings import settings
from core.logger import log

class StateManager:
    """
    Manages scan state using SQLite with Write-Ahead Logging (WAL) enabled
    to support concurrent reads/writes from multiple threads.
    """
    def __init__(self):
        self.db_path = settings.DATA_DIR / "hunter_state.db"
        self._init_db()
        self.local_thread = threading.local()

    def _get_connection(self):
        """
        Returns a thread-local database connection.
        SQLite connections cannot be shared across threads.
        """
        if not hasattr(self.local_thread, "connection"):
            self.local_thread.connection = sqlite3.connect(
                self.db_path, 
                timeout=30.0, # Wait up to 30s for lock
                check_same_thread=False
            )
            # Enable WAL mode on every connection (it's persistent but good practice to ensure)
            self.local_thread.connection.execute("PRAGMA journal_mode=WAL;")
            self.local_thread.connection.row_factory = sqlite3.Row
        return self.local_thread.connection

    def _init_db(self):
        """Initialize the database schema."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("PRAGMA journal_mode=WAL;") # Critical for concurrency
            
            # Targets Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT UNIQUE,
                    status TEXT DEFAULT 'pending', -- pending, processing, completed, failed
                    stage TEXT DEFAULT 'recon',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Findings Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER,
                    tool TEXT,
                    severity TEXT,
                    description TEXT,
                    confidence TEXT,
                    FOREIGN KEY(target_id) REFERENCES targets(id)
                )
            """)

            # Indexes for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_targets_status ON targets(status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_targets_stage ON targets(stage);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_target_id ON findings(target_id);")
            
            conn.commit()
            conn.close()
            log.info("[DB] State Manager Initialized (WAL Mode)")
        except Exception as e:
            log.error(f"[DB] Init Error: {e}")

    def add_target(self, url: str, stage="recon"):
        """Adds a new target if it doesn't exist."""
        conn = self._get_connection()
        try:
            conn.execute(
                "INSERT OR IGNORE INTO targets (url, stage, status) VALUES (?, ?, ?)",
                (url, stage, "pending")
            )
            conn.commit()
        except Exception as e:
            log.error(f"[DB] Add Target Error: {e}")

    def get_pending_tasks(self, limit=100):
        """Retrieves pending tasks."""
        conn = self._get_connection()
        cursor = conn.execute(
            "SELECT * FROM targets WHERE status = 'pending' LIMIT ?",
            (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]

    def update_task_status(self, url, status, stage=None):
        """Updates the status of a task."""
        conn = self._get_connection()
        try:
            if stage:
                conn.execute(
                    "UPDATE targets SET status = ?, stage = ?, updated_at = CURRENT_TIMESTAMP WHERE url = ?",
                    (status, stage, url)
                )
            else:
                 conn.execute(
                    "UPDATE targets SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE url = ?",
                    (status, url)
                )
            conn.commit()
        except Exception as e:
            log.error(f"[DB] Update Error: {e}")

    def add_finding(self, target_url, tool, severity, description, confidence="LOW"):
        """Logs a vulnerability finding."""
        conn = self._get_connection()
        try:
            # Get target ID
            cur = conn.execute("SELECT id FROM targets WHERE url = ?", (target_url,))
            res = cur.fetchone()
            if not res:
                log.warning(f"[DB] Orphaned finding for {target_url}")
                return
            
            target_id = res["id"]
            conn.execute(
                "INSERT INTO findings (target_id, tool, severity, description, confidence) VALUES (?, ?, ?, ?, ?)",
                (target_id, tool, severity, description, confidence)
            )
            conn.commit()
        except Exception as e:
            log.error(f"[DB] Add Finding Error: {e}")

    def checkpoint(self):
        """Force a WAL checkpoint (useful during shutdown)."""
        try:
            conn = self._get_connection()
            conn.execute("PRAGMA wal_checkpoint(FULL);")
            conn.close()
        except:
            pass

state_manager = StateManager()
