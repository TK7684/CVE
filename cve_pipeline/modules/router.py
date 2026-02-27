"""
Router Module - Intelligent URL Routing with Parameter Deduplication.
Routes targets to appropriate scanners based on URL characteristics.
"""
import re
from urllib.parse import urlparse, parse_qs, urlencode
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Set
from enum import Enum

from core.logger import log
from core.state_manager import state_manager


class TargetType(Enum):
    """Classification of target URLs."""
    DYNAMIC = "dynamic"       # Has query parameters -> SQLMap, Dalfox
    LOGIN = "login"           # Login/Admin panels -> Hydra
    JS_FILE = "js_file"       # JavaScript files -> Secret Scanner
    API = "api"               # API endpoints -> Nuclei API templates
    STATIC = "static"         # Static content -> Skip or low-priority Nuclei
    CMS = "cms"               # CMS detected -> Nuclei CMS templates


@dataclass
class RoutedTarget:
    """Represents a routed target with its classification."""
    url: str
    target_type: TargetType
    parameters: List[str] = field(default_factory=list)
    tech_stack: List[str] = field(default_factory=list)


class Router:
    """
    The Logic Layer - Routes URLs to appropriate scanning queues.
    Implements Parameter Deduplication to avoid redundant scans.
    """
    
    # Patterns for classification (Compiled Regex for Performance)
    # Note: Regex is faster than iterating over sets for many keywords
    LOGIN_PATTERN = re.compile(r"login|signin|auth|admin|dashboard|panel|wp-login", re.IGNORECASE)
    API_PATTERN = re.compile(r"/api/|/v\d+|/graphql|/rest", re.IGNORECASE)
    CMS_PATTERN = re.compile(r"/wp-|/joomla|/drupal|/magento|/wordpress", re.IGNORECASE)
    
    # Static extensions (Ends with)
    STATIC_EXTENSIONS = (
        ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", 
        ".woff", ".woff2", ".ttf", ".ico", ".pdf"
    )
    
    def __init__(self):
        # Deduplication: endpoint+params -> representative URL
        self.seen_signatures: Set[str] = set()
        
        # Queues for each target type
        self.queues: dict[TargetType, List[RoutedTarget]] = defaultdict(list)
    
    def route_targets(self, urls: List[str]) -> dict[TargetType, List[RoutedTarget]]:
        """
        Main routing function.
        1. Deduplicates
        2. Classifies
        3. Routes to queues
        """
        log.info(f"[Router] Processing {len(urls)} URLs...")
        
        for url in urls:
            url = url.strip()
            if not url:
                continue
            
            # Skip static assets
            if self._is_static_asset(url):
                continue
            
            # Deduplicate
            signature = self._get_signature(url)
            if signature in self.seen_signatures:
                continue
            self.seen_signatures.add(signature)
            
            # Classify and route
            routed = self._classify(url)
            self.queues[routed.target_type].append(routed)
            
            # Update DB status
            state_manager.update_task_status(url, "pending", stage=routed.target_type.value)
        
        # Log summary
        for target_type, targets in self.queues.items():
            if targets:
                log.info(f"[Router] {target_type.value}: {len(targets)} targets")
        
        return self.queues
    
    def _get_signature(self, url: str) -> str:
        """
        Creates a unique signature for deduplication.
        Example: /page.php?id=1&cat=2 -> /page.php?cat=&id=
        This treats /page.php?id=1 and /page.php?id=99 as the same endpoint.
        """
        try:
            parsed = urlparse(url)
            path = parsed.path
            
            # Normalize query params (sort keys, remove values)
            params = parse_qs(parsed.query, keep_blank_values=True)
            sorted_keys = sorted(params.keys())
            normalized_params = urlencode({k: "" for k in sorted_keys})
            
            # Signature = path + sorted_param_keys
            return f"{parsed.netloc}{path}?{normalized_params}"
        except:
            return url  # Fallback to full URL
    
    def _is_static_asset(self, url: str) -> bool:
        """Checks if URL is a static asset to skip."""
        parsed = urlparse(url)
        return parsed.path.lower().endswith(self.STATIC_EXTENSIONS)
    
    def _classify(self, url: str) -> RoutedTarget:
        """Classifies a URL based on patterns."""
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        url_lower = url.lower()  # Although regex is case-insensitive, we might need this for others
        params = list(parse_qs(parsed.query).keys())
        
        # 1. API detection (High specificity)
        if self.API_PATTERN.search(url):
            return RoutedTarget(url=url, target_type=TargetType.API, parameters=params)
            
        # 2. CMS detection (Specific patterns)
        if self.CMS_PATTERN.search(url):
            return RoutedTarget(url=url, target_type=TargetType.CMS)
        
        # 3. JS Files
        if path_lower.endswith(".js"):
            return RoutedTarget(url=url, target_type=TargetType.JS_FILE)
        
        # 4. Login/Admin detection
        if self.LOGIN_PATTERN.search(url):
            return RoutedTarget(url=url, target_type=TargetType.LOGIN)
        
        # 5. Dynamic (has query params)
        if params:
            return RoutedTarget(url=url, target_type=TargetType.DYNAMIC, parameters=params)
        
        # 6. Default: Static/Generic
        return RoutedTarget(url=url, target_type=TargetType.STATIC)
    
    def get_queue(self, target_type: TargetType) -> List[RoutedTarget]:
        """Returns the queue for a specific target type."""
        return self.queues.get(target_type, [])
