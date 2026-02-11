"""
Security Validator Module.
Provides input validation, sanitization, and command injection prevention.
"""
import re
import html
import shlex
from urllib.parse import urlparse, quote
from typing import Optional, List, Tuple
from dataclasses import dataclass
from enum import Enum

from core.logger import log


class ThreatLevel(Enum):
    """Classification of detected threats."""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ValidationResult:
    """Result of input validation."""
    is_valid: bool
    sanitized_value: Optional[str]
    threat_level: ThreatLevel
    warnings: List[str]


class SecurityValidator:
    """
    Comprehensive input validation and sanitization.
    Prevents command injection and other input-based attacks.
    """
    
    # Dangerous shell characters and patterns
    SHELL_DANGEROUS = [
        ";", "|", "&", "$", "`", "(", ")", "{", "}", "[", "]",
        "<", ">", "!", "\\", "\n", "\r", "\x00"
    ]
    
    # Command injection patterns
    INJECTION_PATTERNS = [
        r";\s*(rm|cat|ls|wget|curl|nc|bash|sh|python|perl|php)",
        r"\$\([^)]+\)",           # $(command)
        r"`[^`]+`",               # `command`
        r"\|\s*\w+",              # | command
        r">\s*/",                 # > /path (file redirect)
        r"&&\s*\w+",              # && command
        r"\|\|\s*\w+",            # || command
    ]
    
    # URL validation patterns
    URL_SCHEME_WHITELIST = ["http", "https"]
    
    def __init__(self):
        self.injection_regex = [re.compile(p, re.IGNORECASE) for p in self.INJECTION_PATTERNS]
    
    def validate_url(self, url: str) -> ValidationResult:
        """
        Validates and sanitizes a URL.
        Returns validation result with sanitized URL if valid.
        """
        warnings = []
        
        if not url or not isinstance(url, str):
            return ValidationResult(False, None, ThreatLevel.SAFE, ["Empty or invalid URL"])
        
        url = url.strip()
        
        try:
            parsed = urlparse(url)
            
            # Check scheme
            if parsed.scheme.lower() not in self.URL_SCHEME_WHITELIST:
                return ValidationResult(
                    False, None, ThreatLevel.MEDIUM,
                    [f"Invalid URL scheme: {parsed.scheme}. Only HTTP(S) allowed."]
                )
            
            # Check for dangerous characters in URL
            threat_level = self._check_injection(url)
            if threat_level != ThreatLevel.SAFE:
                return ValidationResult(
                    False, None, threat_level,
                    ["Potential command injection detected in URL"]
                )
            
            # Sanitize URL
            sanitized = self._sanitize_url(url)
            
            return ValidationResult(True, sanitized, ThreatLevel.SAFE, warnings)
            
        except Exception as e:
            return ValidationResult(False, None, ThreatLevel.LOW, [f"URL parsing error: {e}"])
    
    def sanitize_url(self, url: str) -> Optional[str]:
        """
        Sanitizes a URL for safe use in shell commands.
        Returns None if the URL is dangerous.
        """
        result = self.validate_url(url)
        return result.sanitized_value if result.is_valid else None
    
    def _sanitize_url(self, url: str) -> str:
        """Internal URL sanitization."""
        # Encode special characters
        parsed = urlparse(url)
        
        # Quote path and query to escape dangerous chars
        safe_path = quote(parsed.path, safe="/")
        safe_query = quote(parsed.query, safe="=&")
        
        # Reconstruct
        sanitized = f"{parsed.scheme}://{parsed.netloc}{safe_path}"
        if safe_query:
            sanitized += f"?{safe_query}"
        
        return sanitized
    
    def _check_injection(self, value: str) -> ThreatLevel:
        """Checks for command injection patterns."""
        # Check for dangerous shell characters
        for char in self.SHELL_DANGEROUS:
            if char in value:
                log.warning(f"[Security] Dangerous character detected: {repr(char)}")
                return ThreatLevel.HIGH
        
        # Check for injection patterns
        for pattern in self.injection_regex:
            if pattern.search(value):
                log.warning(f"[Security] Injection pattern detected: {pattern.pattern}")
                return ThreatLevel.CRITICAL
        
        return ThreatLevel.SAFE
    
    def validate_domain(self, domain: str) -> ValidationResult:
        """Validates a domain name."""
        warnings = []
        
        if not domain or not isinstance(domain, str):
            return ValidationResult(False, None, ThreatLevel.SAFE, ["Empty domain"])
        
        domain = domain.strip().lower()
        
        # Check for dangerous characters
        threat = self._check_injection(domain)
        if threat != ThreatLevel.SAFE:
            return ValidationResult(False, None, threat, ["Dangerous characters in domain"])
        
        # Basic domain validation
        domain_regex = r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$"
        if not re.match(domain_regex, domain):
            return ValidationResult(False, None, ThreatLevel.LOW, ["Invalid domain format"])
        
        return ValidationResult(True, domain, ThreatLevel.SAFE, warnings)
    
    def sanitize_for_shell(self, value: str) -> str:
        """
        Sanitizes a string for safe use in shell commands.
        Uses shlex.quote for maximum safety.
        """
        if not value:
            return ""
        
        # Use shlex.quote for proper shell escaping
        return shlex.quote(value)
    
    def validate_file_path(self, path: str) -> ValidationResult:
        """Validates a file path to prevent directory traversal."""
        warnings = []
        
        if not path:
            return ValidationResult(False, None, ThreatLevel.SAFE, ["Empty path"])
        
        # Check for directory traversal
        if ".." in path:
            return ValidationResult(
                False, None, ThreatLevel.HIGH,
                ["Directory traversal attempt detected"]
            )
        
        # Check for absolute paths to sensitive locations
        sensitive_paths = ["/etc/", "/root/", "/home/", "/var/", "/tmp/"]
        path_lower = path.lower()
        for sensitive in sensitive_paths:
            if path_lower.startswith(sensitive):
                warnings.append(f"Path points to sensitive location: {sensitive}")
        
        # Check for dangerous characters
        threat = self._check_injection(path)
        if threat != ThreatLevel.SAFE:
            return ValidationResult(False, None, threat, ["Dangerous characters in path"])
        
        return ValidationResult(True, path, ThreatLevel.SAFE if not warnings else ThreatLevel.LOW, warnings)


# Global instance
security_validator = SecurityValidator()
