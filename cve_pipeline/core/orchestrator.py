"""
Orchestrator - The Brain of The Hunter's Loop.
Manages pipeline execution, threading, crash recovery, and graceful shutdown.
"""
import signal
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional
from pathlib import Path

from config.settings import settings
from core.logger import log, console
from core.state_manager import state_manager
from modules.recon import ReconModule
from modules.router import Router, TargetType, RoutedTarget
from modules.scanner import Scanner, ScanResult
from modules.ai_triage import AITriage


class Orchestrator:
    """
    The Hunter's Loop Orchestrator.
    Coordinates all pipeline stages with crash recovery and graceful shutdown.
    """
    
    def __init__(self, target: str, dry_run: bool = False):
        self.target = target
        self.dry_run = dry_run
        self.shutdown_requested = False
        
        # Initialize components
        self.output_dir = settings.DATA_DIR / target
        self.output_dir.mkdir(exist_ok=True, parents=True)
        
        self.recon = ReconModule(target)
        self.router = Router()
        self.scanner = Scanner(self.output_dir)
        self.triage = AITriage()
        
        # Thread pool
        self.executor: Optional[ThreadPoolExecutor] = None
        
        # Results storage
        self.all_findings: List[ScanResult] = []
        
        # Register signal handlers
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self):
        """Sets up graceful shutdown on SIGINT/SIGTERM."""
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)
    
    def _handle_shutdown(self, signum, frame):
        """Graceful shutdown handler."""
        log.warning("[Orchestrator] Shutdown signal received. Cleaning up...")
        self.shutdown_requested = True
        
        # Checkpoint the database
        state_manager.checkpoint()
        
        if self.executor:
            log.info("[Orchestrator] Waiting for running tasks to complete...")
            self.executor.shutdown(wait=True, cancel_futures=True)
        
        log.info("[Orchestrator] Shutdown complete.")
        sys.exit(0)
    
    def run(self):
        """Main pipeline execution."""
        console.rule("[bold blue]The Hunter's Loop[/bold blue]")
        log.info(f"Target: {self.target} | Dry Run: {self.dry_run}")
        
        # Step 1: Check for resumable tasks
        pending_tasks = self._check_resumable_tasks()
        
        if pending_tasks:
            log.info(f"[Orchestrator] Resuming {len(pending_tasks)} pending tasks from previous run.")
            urls = [t["url"] for t in pending_tasks]
        else:
            # Step 2: Run Recon
            log.info("[Orchestrator] Stage 1: Reconnaissance")
            if self.dry_run:
                log.info("[DRY RUN] Skipping actual recon. Using mock data.")
                urls = self._get_mock_urls()
            else:
                urls = self.recon.run_recon()
        
        if not urls:
            log.warning("[Orchestrator] No targets found. Exiting.")
            return
        
        # Step 3: Route targets
        log.info("[Orchestrator] Stage 2: Intelligent Routing")
        queues = self.router.route_targets(urls)
        
        # Step 4: Scanning (Parallel)
        log.info("[Orchestrator] Stage 3: Scanning")
        self._run_scans(queues)
        
        # Step 5: AI Triage
        log.info("[Orchestrator] Stage 4: AI Triage")
        self._run_triage()
        
        # Step 6: Generate Report
        log.info("[Orchestrator] Stage 5: Report Generation")
        self._generate_report()
        
        console.rule("[bold green]Pipeline Complete[/bold green]")
    
    def _check_resumable_tasks(self) -> List[dict]:
        """Checks database for pending tasks from a crashed run."""
        return state_manager.get_pending_tasks(limit=500)
    
    def _get_mock_urls(self) -> List[str]:
        """Returns mock URLs for dry-run testing."""
        return [
            f"https://{self.target}/login.php",
            f"https://{self.target}/search.php?q=test",
            f"https://{self.target}/api/v1/users",
            f"https://{self.target}/wp-content/plugins/test",
            f"https://{self.target}/static/app.js",
        ]
    
    def _run_scans(self, queues: dict[TargetType, List[RoutedTarget]]):
        """Executes scans in parallel using ThreadPoolExecutor."""
        
        # Flatten all targets
        all_targets = []
        for target_type, targets in queues.items():
            all_targets.extend(targets)
        
        if not all_targets:
            log.warning("[Orchestrator] No targets to scan.")
            return
        
        log.info(f"[Orchestrator] Scanning {len(all_targets)} targets with {settings.MAX_THREADS} threads...")
        
        if self.dry_run:
            for target in all_targets:
                log.info(f"[DRY RUN] Would scan: {target.url} ({target.target_type.value})")
            return
        
        self.executor = ThreadPoolExecutor(max_workers=settings.MAX_THREADS)
        futures = {}
        
        try:
            for target in all_targets:
                if self.shutdown_requested:
                    break
                future = self.executor.submit(self.scanner.scan_target, target)
                futures[future] = target
            
            for future in as_completed(futures):
                if self.shutdown_requested:
                    break
                    
                target = futures[future]
                try:
                    results = future.result()
                    self.all_findings.extend(results)
                    if results:
                        log.info(f"[Scanner] Found {len(results)} issues in {target.url}")
                except Exception as e:
                    log.error(f"[Scanner] Error processing {target.url}: {e}")
        finally:
            self.executor.shutdown(wait=False)
            self.executor = None
    
    def _run_triage(self):
        """Runs AI triage on findings."""
        if not self.all_findings:
            log.info("[Triage] No findings to analyze.")
            return
        
        if self.dry_run:
            log.info(f"[DRY RUN] Would triage {len(self.all_findings)} findings.")
            return
        
        triaged = self.triage.triage_findings(self.all_findings)
        
        valid_count = sum(1 for _, t in triaged if t.is_valid)
        log.info(f"[Triage] Analyzed {len(triaged)} findings. Valid: {valid_count}")
    
    def _generate_report(self):
        """Generates a summary report."""
        report_path = self.output_dir / "report.md"
        
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(f"# Security Scan Report: {self.target}\n\n")
            f.write(f"**Total Findings:** {len(self.all_findings)}\n\n")
            
            # Group by severity
            by_severity = {}
            for finding in self.all_findings:
                sev = finding.severity
                if sev not in by_severity:
                    by_severity[sev] = []
                by_severity[sev].append(finding)
            
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                if severity in by_severity:
                    f.write(f"## {severity} ({len(by_severity[severity])})\n\n")
                    for finding in by_severity[severity]:
                        f.write(f"- **{finding.tool}**: {finding.description}\n")
                        f.write(f"  - Target: `{finding.target}`\n\n")
        
        log.info(f"[Report] Saved to {report_path}")
