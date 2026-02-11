"""
Secrets Manager Module.
Provides secure handling of credentials and sensitive data.
"""
import os
import base64
import hashlib
import secrets
from pathlib import Path
from typing import Optional, Dict
from dataclasses import dataclass

from core.logger import log


@dataclass
class SecretInfo:
    """Information about a stored secret."""
    key: str
    is_set: bool
    source: str  # 'env', 'file', 'vault'
    masked_value: str


class SecretsManager:
    """
    Secure secrets management.
    Handles API keys, tokens, and sensitive configuration.
    """
    
    # Required secrets and their validation rules
    REQUIRED_SECRETS = {
        "GEMINI_API_KEY": {"min_length": 20, "required": False},
        "DISCORD_WEBHOOK_URL": {"min_length": 50, "required": False},
    }
    
    # Optional secrets
    OPTIONAL_SECRETS = [
        "OPENAI_API_KEY",
        "SLACK_WEBHOOK_URL",
        "TELEGRAM_BOT_TOKEN"
    ]
    
    def __init__(self):
        self._cache: Dict[str, str] = {}
        self._load_secrets()
    
    def _load_secrets(self):
        """Loads secrets from environment variables."""
        for key in list(self.REQUIRED_SECRETS.keys()) + self.OPTIONAL_SECRETS:
            value = os.getenv(key)
            if value:
                self._cache[key] = value
    
    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """
        Retrieves a secret value.
        Never logs the actual value.
        """
        return self._cache.get(key, default)
    
    def is_set(self, key: str) -> bool:
        """Checks if a secret is configured."""
        return key in self._cache and bool(self._cache[key])
    
    def validate(self) -> tuple[bool, list[str]]:
        """
        Validates that all required secrets are properly configured.
        Returns (is_valid, list_of_issues).
        """
        issues = []
        
        for key, rules in self.REQUIRED_SECRETS.items():
            if rules.get("required", True):
                if not self.is_set(key):
                    issues.append(f"Missing required secret: {key}")
                    continue
                
                value = self._cache.get(key, "")
                min_len = rules.get("min_length", 0)
                if len(value) < min_len:
                    issues.append(f"Secret {key} is too short (min {min_len} chars)")
        
        return len(issues) == 0, issues
    
    def get_status(self) -> Dict[str, SecretInfo]:
        """
        Returns the status of all secrets (without values).
        Safe to log or display.
        """
        status = {}
        
        for key in list(self.REQUIRED_SECRETS.keys()) + self.OPTIONAL_SECRETS:
            is_set = self.is_set(key)
            value = self._cache.get(key, "")
            
            status[key] = SecretInfo(
                key=key,
                is_set=is_set,
                source="env" if is_set else "not_set",
                masked_value=self._mask_value(value) if is_set else "NOT SET"
            )
        
        return status
    
    def _mask_value(self, value: str) -> str:
        """Masks a secret value for safe display."""
        if not value:
            return ""
        if len(value) <= 8:
            return "*" * len(value)
        return value[:4] + "*" * (len(value) - 8) + value[-4:]
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generates a cryptographically secure random token."""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def hash_value(value: str, salt: Optional[str] = None) -> str:
        """
        Creates a secure hash of a value.
        Useful for comparing secrets without storing them.
        """
        if salt is None:
            salt = secrets.token_hex(16)
        
        combined = f"{salt}:{value}"
        hashed = hashlib.sha256(combined.encode()).hexdigest()
        return f"{salt}:{hashed}"
    
    @staticmethod
    def verify_hash(value: str, stored_hash: str) -> bool:
        """Verifies a value against a stored hash."""
        try:
            salt, _ = stored_hash.split(":")
            computed = SecretsManager.hash_value(value, salt)
            return secrets.compare_digest(computed, stored_hash)
        except ValueError:
            return False
    
    def rotate_secret(self, key: str, new_value: str):
        """
        Rotates a secret value.
        In production, this would update the secret store.
        """
        log.warning(f"[Secrets] Rotating secret: {key}")
        self._cache[key] = new_value
        # In production: update env file, vault, etc.
    
    def clear_cache(self):
        """Clears the secrets cache (for testing)."""
        self._cache.clear()


# Global instance
secrets_manager = SecretsManager()
