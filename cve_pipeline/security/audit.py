"""
Audit Logger Module.
Provides comprehensive audit logging for all security-sensitive operations.
"""
import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict
from enum import Enum

from config.settings import settings


class AuditAction(Enum):
    """Types of auditable actions."""
    # Pipeline Actions
    PIPELINE_START = "pipeline_start"
    PIPELINE_END = "pipeline_end"
    PIPELINE_ERROR = "pipeline_error"
    
    # Recon Actions
    RECON_START = "recon_start"
    SUBDOMAIN_ENUM = "subdomain_enum"
    URL_HARVEST = "url_harvest"
    LIVENESS_CHECK = "liveness_check"
    
    # Routing Actions
    URL_ROUTED = "url_routed"
    URL_DROPPED = "url_dropped"
    SCOPE_VIOLATION = "scope_violation"
    
    # Scanning Actions
    SCAN_START = "scan_start"
    SCAN_END = "scan_end"
    SCAN_TIMEOUT = "scan_timeout"
    SCAN_ERROR = "scan_error"
    
    # Finding Actions
    FINDING_DETECTED = "finding_detected"
    FINDING_TRIAGED = "finding_triaged"
    ALERT_SENT = "alert_sent"
    
    # Security Actions
    DANGEROUS_INPUT = "dangerous_input"
    INJECTION_ATTEMPT = "injection_attempt"
    AUTH_FAILURE = "auth_failure"
    CONFIG_CHANGE = "config_change"


@dataclass
class AuditEvent:
    """Represents an audit event."""
    timestamp: str
    action: str
    target: Optional[str]
    details: Dict[str, Any]
    severity: str
    user: str = "system"
    session_id: Optional[str] = None


class AuditLogger:
    """
    Comprehensive audit logging for security operations.
    Writes to both file and console (if enabled).
    """
    
    def __init__(self, log_dir: Optional[Path] = None):
        self.log_dir = log_dir or settings.DATA_DIR
        self.log_file = self.log_dir / "audit.log"
        self.session_id = self._generate_session_id()
        self._lock = threading.Lock()
        
        # Ensure log directory exists
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup file logger
        self._setup_logger()
    
    def _generate_session_id(self) -> str:
        """Generates a unique session ID."""
        import uuid
        return str(uuid.uuid4())[:8]
    
    def _setup_logger(self):
        """Sets up the audit file logger."""
        self.logger = logging.getLogger("audit")
        self.logger.setLevel(logging.INFO)
        
        # Avoid duplicate handlers
        if not self.logger.handlers:
            handler = logging.FileHandler(self.log_file, encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(message)s"))
            self.logger.addHandler(handler)
    
    def log(
        self,
        action: AuditAction,
        target: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        severity: str = "INFO"
    ):
        """
        Logs an audit event.
        
        Args:
            action: The type of action being logged
            target: The target URL/domain/file being operated on
            details: Additional details about the action
            severity: INFO, WARNING, ERROR, CRITICAL
        """
        event = AuditEvent(
            timestamp=datetime.now(datetime.UTC).isoformat(),
            action=action.value,
            target=target,
            details=details or {},
            severity=severity,
            session_id=self.session_id
        )
        
        with self._lock:
            self.logger.info(json.dumps(asdict(event)))
    
    def log_pipeline_start(self, target: str, dry_run: bool = False):
        """Logs pipeline start."""
        self.log(
            AuditAction.PIPELINE_START,
            target=target,
            details={"dry_run": dry_run, "rate_limit": settings.GLOBAL_RATE_LIMIT}
        )
    
    def log_pipeline_end(self, target: str, findings_count: int):
        """Logs pipeline completion."""
        self.log(
            AuditAction.PIPELINE_END,
            target=target,
            details={"findings_count": findings_count}
        )
    
    def log_scope_violation(self, url: str, reason: str):
        """Logs a scope violation attempt."""
        self.log(
            AuditAction.SCOPE_VIOLATION,
            target=url,
            details={"reason": reason},
            severity="WARNING"
        )
    
    def log_scan_start(self, url: str, tool: str):
        """Logs scan initiation."""
        self.log(
            AuditAction.SCAN_START,
            target=url,
            details={"tool": tool}
        )
    
    def log_scan_end(self, url: str, tool: str, findings_count: int, duration_ms: int):
        """Logs scan completion."""
        self.log(
            AuditAction.SCAN_END,
            target=url,
            details={"tool": tool, "findings": findings_count, "duration_ms": duration_ms}
        )
    
    def log_finding(self, url: str, tool: str, severity: str, description: str):
        """Logs a detected finding."""
        self.log(
            AuditAction.FINDING_DETECTED,
            target=url,
            details={"tool": tool, "severity": severity, "description": description},
            severity="WARNING" if severity in ["HIGH", "CRITICAL"] else "INFO"
        )
    
    def log_dangerous_input(self, input_type: str, value: str, threat_level: str):
        """Logs detection of dangerous input."""
        self.log(
            AuditAction.DANGEROUS_INPUT,
            target=None,
            details={
                "input_type": input_type,
                "value_preview": value[:100] if value else None,
                "threat_level": threat_level
            },
            severity="ERROR"
        )
    
    def log_injection_attempt(self, input_value: str, pattern_matched: str):
        """Logs a potential injection attempt."""
        self.log(
            AuditAction.INJECTION_ATTEMPT,
            target=None,
            details={
                "input_preview": input_value[:100],
                "pattern": pattern_matched
            },
            severity="CRITICAL"
        )
    
    def get_recent_events(self, limit: int = 100) -> list:
        """Retrieves recent audit events."""
        events = []
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()[-limit:]
                for line in lines:
                    try:
                        events.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        pass
        except FileNotFoundError:
            pass
        return events


# Global instance
audit_logger = AuditLogger()
