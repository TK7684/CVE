import subprocess
import shutil
from pathlib import Path
from config.settings import settings
from core.logger import log
from utils.scope_guard import scope_guard
from core.state_manager import state_manager

class ReconModule:
    """
    Handles Stage 1 (Ingestion) and Stage 2 (Liveness) of the pipeline.
    """

    def __init__(self, target_domain: str):
        self.target = target_domain
        self.output_dir = settings.DATA_DIR / target_domain
        self.output_dir.mkdir(exist_ok=True, parents=True)
        self.rate_limit = settings.GLOBAL_RATE_LIMIT

    def run_recon(self):
        """Orchestrates the full recon process."""
        log.info(f"[Recon] Starting for {self.target}...")
        
        # 1. Subdomain Enumeration
        subs = self.enumerate_subdomains()
        
        # 2. Liveness Check (Port + Web Probe)
        live_hosts = self.check_liveness(subs)
        
        # 3. URL Harvesting (Historical)
        urls = self.harvest_urls(live_hosts)

        # 4. Scope Filtering & Storage
        final_targets = self._process_and_store_targets(urls)
        
        log.info(f"[Recon] Finished. Found {len(final_targets)} valid, in-scope targets.")
        return final_targets

    def enumerate_subdomains(self):
        """Runs subfinder."""
        output_file = self.output_dir / "subdomains.txt"
        log.info("[Recon] Running Subfinder...")
        
        # Subfinder is fast, no rate limit usually needed, but good practice to be silent
        cmd = [
            "subfinder", "-d", self.target, 
            "-silent", "-o", str(output_file)
        ]
        
        try:
            subprocess.run(cmd, check=True, timeout=settings.SUBPROCESS_TIMEOUT)
            if output_file.exists():
                return output_file.read_text().splitlines()
        except subprocess.TimeoutExpired:
            log.warning("[Recon] Subfinder timed out.")
        except Exception as e:
            log.error(f"[Recon] Subfinder Error: {e}")
        
        return []

    def check_liveness(self, subdomains: list):
        """
        Runs httpx to find live web servers.
        Intersects with Rate Limit.
        """
        if not subdomains:
            return []
            
        input_file = self.output_dir / "subdomains.txt" # Already exists from previous step
        output_file = self.output_dir / "live_hosts.txt"
        
        log.info(f"[Recon] Probing {len(subdomains)} subdomains with httpx...")

        # Httpx serves as our "Liveness Filter"
        # -rl = Rate Limit
        cmd = [
            "httpx", "-l", str(input_file),
            "-silent", "-mc", "200,403,401,302", # Match codes
            "-rl", str(self.rate_limit),
            "-o", str(output_file)
        ]
        
        try:
            subprocess.run(cmd, check=True, timeout=settings.SUBPROCESS_TIMEOUT)
            if output_file.exists():
                return output_file.read_text().splitlines()
        except Exception as e:
            log.error(f"[Recon] Httpx Error: {e}")
            
        return []

    def harvest_urls(self, live_hosts: list):
        """
        Uses gau, waybackurls, and katana to find endpoints.
        Aggregates results using anew.
        """
        if not live_hosts:
            return []

        # We can pass live_hosts.txt directly to Katana
        # For gau/wayback, it's often better to query the main domain strings
        
        output_file = self.output_dir / "endpoints.txt"
        live_hosts_file = self.output_dir / "live_hosts.txt"

        log.info("[Recon] Harvesting URLs (Wayback + Katana)...")
        
        # 1. Katana (Active crawling + Passive)
        # We use katana on the LIVE HOSTS to crawl them
        cmd_katana = f"katana -list {live_hosts_file} -silent -rl {self.rate_limit} -o {self.output_dir}/katana_raw.txt"

        # 2. GAU (Passive)
        # We query the robust target string
        cmd_gau = f"gau {self.target} --threads {settings.MAX_THREADS} --o {self.output_dir}/gau_raw.txt"

        try:
            # We run these sequentially for safety (or could use ThreadPool for speed)
            # Katana
            subprocess.run(cmd_katana, shell=True, timeout=settings.SUBPROCESS_TIMEOUT * 2, stderr=subprocess.DEVNULL)
            
            # GAU
            subprocess.run(cmd_gau, shell=True, timeout=settings.SUBPROCESS_TIMEOUT, stderr=subprocess.DEVNULL)
            
            # Combine and Dedupe with 'anew'
            # cat katana_raw.txt gau_raw.txt | anew endpoints.txt
            raw_files = [self.output_dir / "katana_raw.txt", self.output_dir / "gau_raw.txt"]
            all_urls = set()
            
            for f in raw_files:
                if f.exists():
                     lines = f.read_text(errors='ignore').splitlines()
                     all_urls.update(lines)

            # Save deduped
            return list(all_urls)

        except Exception as e:
            log.error(f"[Recon] Harvesting Error: {e}")
            return []

    def _process_and_store_targets(self, urls: list):
        """
        1. Scope Guard Check
        2. Save to DB (Status: Pending)
        """
        valid_targets = []
        log.info(f"[Recon] Filtering {len(urls)} URLs through Scope Guard...")
        
        for url in urls:
            url = url.strip()
            if not url: continue
            
            if scope_guard.is_in_scope(url):
                valid_targets.append(url)
                # Add to DB
                state_manager.add_target(url, stage="router")
            else:
                pass # Dropped by Scope Guard

        # Save to local file for debugging
        (self.output_dir / "in_scope_targets.txt").write_text("\n".join(valid_targets), encoding='utf-8')
        
        return valid_targets
