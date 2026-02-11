"""
Target Discovery Module.
Fetches valid bug bounty targets from public, authorized sources.
Source: ProjectDiscovery Chaos / Public Bug Bounty Programs.
"""
import requests
import random
from typing import List, Optional
from core.logger import log

BOUNTY_LIST_URL = "https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/master/chaos-bugbounty-list.json"

def fetch_bounty_targets(limit: int = 5) -> List[str]:
    """
    Fetches a list of valid bug bounty domains.
    
    Args:
        limit: Number of targets to return.
        
    Returns:
        List of domain strings.
    """
    try:
        log.info(f"[Discovery] Fetching targets from {BOUNTY_LIST_URL}...")
        response = requests.get(BOUNTY_LIST_URL, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        programs = data.get("programs", [])
        
        # Filter for programs that have domains
        valid_domains = []
        for program in programs:
            valid_domains.extend(program.get("domains", []))
            
        if not valid_domains:
            log.warning("[Discovery] No domains found in bug bounty list.")
            return []
            
        # Shuffle and pick
        selection = random.sample(valid_domains, min(limit, len(valid_domains)))
        log.info(f"[Discovery] Selected {len(selection)} targets: {selection}")
        return selection

    except requests.RequestException as e:
        log.error(f"[Discovery] Failed to fetch targets: {e}")
        return []
    except Exception as e:
        log.error(f"[Discovery] Unexpected error: {e}")
        return []
