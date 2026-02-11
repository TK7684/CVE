from urllib.parse import urlparse
from config.settings import settings
from core.logger import log

class ScopeGuard:
    def __init__(self):
        self._refresh_rules()

    def _refresh_rules(self):
        """Reloads scope rules from settings."""
        scope_data = settings.load_scope()
        self.allowed_domains = scope_data.get("allowed_domains", [])
        self.excluded_domains = scope_data.get("excluded_domains", [])
        self.regex_checks = scope_data.get("regex_checks", False) # Not fully implemented yet
        
        # log.info(f"Scope Loaded: {len(self.allowed_domains)} allowed, {len(self.excluded_domains)} excluded.")

    def is_in_scope(self, url: str) -> bool:
        """
        Validates if a URL is strictly within the allowed scope AND not in the excluded list.
        """
        try:
            parsed = urlparse(url)
            domain = parsed.hostname or parsed.path # Handle cases without scheme if necessary
            
            # 1. Normalization (hostname handles port and auth removal automatically)
            if not domain:
                 return False

            # 2. Check Exclusions First (Deny List)
            for excluded in self.excluded_domains:
                if domain == excluded or domain.endswith("." + excluded):
                    # log.debug(f"[Scope] Excluded: {url}")
                    return False

            # 3. Check Allow List (Allow List)
            for allowed in self.allowed_domains:
                # Matches exact domain or subdomain (.example.com matches sub.example.com)
                if domain == allowed or domain.endswith(allowed):
                    return True
            
            # log.debug(f"[Scope] Out of Scope: {url}")
            return False

        except Exception as e:
            log.error(f"Scope Check Error for {url}: {e}")
            return False

# Global Instance
scope_guard = ScopeGuard()
