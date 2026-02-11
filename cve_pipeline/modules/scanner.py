"""
Scanner Module - Wraps security tools with safety controls.
Implements timeouts, rate limiting, and safe defaults.
"""
import subprocess
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass

from config.settings import settings
from core.logger import log
from core.state_manager import state_manager
from modules.router import RoutedTarget, TargetType


@dataclass
class ScanResult:
    """Represents a scan result."""
    tool: str
    target: str
    severity: str
    description: str
    raw_output: Optional[str] = None
    success: bool = True


class Scanner:
    """
    The Warhead - Executes scanning tools with safety controls.
    All subprocess calls are wrapped with timeouts.
    """
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.timeout = settings.SUBPROCESS_TIMEOUT
        self.rate_limit = settings.GLOBAL_RATE_LIMIT
        
    def scan_target(self, target: RoutedTarget) -> List[ScanResult]:
        """Routes target to appropriate scanner based on type."""
        results = []
        
        try:
            if target.target_type == TargetType.DYNAMIC:
                results.extend(self.run_dalfox(target.url))
                results.extend(self.run_sqlmap(target.url))
                
            elif target.target_type == TargetType.LOGIN:
                if settings.ENABLE_BRUTEFORCE:
                    results.extend(self.run_hydra(target.url))
                else:
                    log.info(f"[Scanner] Skipping Hydra (ENABLE_BRUTEFORCE=False): {target.url}")
                    
            elif target.target_type == TargetType.CMS:
                results.extend(self.run_nuclei(target.url, template_tags=["cms", "wordpress", "joomla"]))
                
            elif target.target_type == TargetType.API:
                results.extend(self.run_nuclei(target.url, template_tags=["api", "exposure"]))
                
            elif target.target_type == TargetType.JS_FILE:
                results.extend(self.run_secret_scan(target.url))
                
            else:  # STATIC - Light nuclei scan
                results.extend(self.run_nuclei(target.url, template_tags=["info", "tech"]))
                
            # Update DB status
            state_manager.update_task_status(target.url, "completed", stage="scanned")
            
        except Exception as e:
            log.error(f"[Scanner] Error scanning {target.url}: {e}")
            state_manager.update_task_status(target.url, "failed")
            
        return results

    def run_dalfox(self, url: str) -> List[ScanResult]:
        """Runs Dalfox XSS scanner."""
        log.info(f"[Scanner/Dalfox] Scanning: {url}")
        results = []
        
        output_file = self.output_dir / f"dalfox_{hash(url)}.json"
        
        cmd = [
            "dalfox", "url", url,
            "--silence",
            "--format", "json",
            "-o", str(output_file)
        ]
        
        try:
            subprocess.run(cmd, timeout=self.timeout, capture_output=True)
            
            if output_file.exists():
                content = output_file.read_text()
                if content.strip():
                    # Parse Dalfox JSON output
                    for line in content.splitlines():
                        try:
                            finding = json.loads(line)
                            results.append(ScanResult(
                                tool="dalfox",
                                target=url,
                                severity="HIGH" if finding.get("poc") else "MEDIUM",
                                description=f"XSS: {finding.get('param', 'N/A')} - {finding.get('type', 'reflected')}",
                                raw_output=line
                            ))
                        except json.JSONDecodeError:
                            pass
                            
        except subprocess.TimeoutExpired:
            log.warning(f"[Scanner/Dalfox] Timeout: {url}")
            results.append(ScanResult(tool="dalfox", target=url, severity="INFO", description="Scan timed out", success=False))
        except Exception as e:
            log.error(f"[Scanner/Dalfox] Error: {e}")
            
        return results

    def run_sqlmap(self, url: str) -> List[ScanResult]:
        """
        Runs SQLMap with optimized settings.
        Uses --technique=BEU (Boolean, Error, Union) to avoid slow Time-based checks.
        """
        log.info(f"[Scanner/SQLMap] Scanning: {url}")
        results = []
        
        output_dir = self.output_dir / f"sqlmap_{hash(url)}"
        
        cmd = [
            "sqlmap.py", "-u", url,
            "--batch",                    # Non-interactive
            "--technique=BEU",            # Skip Time-based (slow)
            "--level=2",                  # Balanced
            "--risk=2",
            "--threads=5",
            "--output-dir", str(output_dir),
            "--forms",                    # Also check forms
            "-o"                          # Enable optimization
        ]
        
        try:
            result = subprocess.run(cmd, timeout=self.timeout, capture_output=True, text=True)
            
            output = result.stdout + result.stderr
            
            # Check for positive indicators
            if "is vulnerable" in output.lower() or "found" in output.lower():
                results.append(ScanResult(
                    tool="sqlmap",
                    target=url,
                    severity="CRITICAL",
                    description="SQL Injection Detected",
                    raw_output=output[:2000]  # Truncate
                ))
                
        except subprocess.TimeoutExpired:
            log.warning(f"[Scanner/SQLMap] Timeout: {url}")
        except Exception as e:
            log.error(f"[Scanner/SQLMap] Error: {e}")
            
        return results

    def run_nuclei(self, url: str, template_tags: List[str] = None) -> List[ScanResult]:
        """
        Runs Nuclei with specified template tags.
        Applies rate limiting.
        """
        log.info(f"[Scanner/Nuclei] Scanning: {url}")
        results = []
        
        output_file = self.output_dir / f"nuclei_{hash(url)}.json"
        
        cmd = [
            "nuclei", "-u", url,
            "-silent",
            "-json-output", "-o", str(output_file),
            "-rate-limit", str(self.rate_limit),
            "-severity", "medium,high,critical"  # Skip low/info by default
        ]
        
        if template_tags:
            for tag in template_tags:
                cmd.extend(["-tags", tag])
        
        try:
            subprocess.run(cmd, timeout=self.timeout, capture_output=True)
            
            if output_file.exists():
                for line in output_file.read_text().splitlines():
                    try:
                        finding = json.loads(line)
                        results.append(ScanResult(
                            tool="nuclei",
                            target=url,
                            severity=finding.get("info", {}).get("severity", "MEDIUM").upper(),
                            description=finding.get("info", {}).get("name", "Unknown"),
                            raw_output=finding.get("matched-at")
                        ))
                    except json.JSONDecodeError:
                        pass
                        
        except subprocess.TimeoutExpired:
            log.warning(f"[Scanner/Nuclei] Timeout: {url}")
        except Exception as e:
            log.error(f"[Scanner/Nuclei] Error: {e}")
            
        return results

    def run_hydra(self, url: str) -> List[ScanResult]:
        """
        Runs Hydra for brute-force (GATED by ENABLE_BRUTEFORCE).
        This is a placeholder - real implementation needs careful configuration.
        """
        log.warning(f"[Scanner/Hydra] Brute-force enabled for: {url}")
        
        # SAFETY: This is intentionally minimal
        # Real implementation requires:
        # - Custom wordlists
        # - Service detection (http-form, ssh, etc.)
        # - Rate limiting to avoid lockouts
        
        return [ScanResult(
            tool="hydra",
            target=url,
            severity="INFO",
            description="Hydra placeholder - Requires manual configuration",
            success=False
        )]

    def run_secret_scan(self, url: str) -> List[ScanResult]:
        """Scans JS files for secrets/API keys using regex patterns."""
        log.info(f"[Scanner/Secrets] Scanning JS: {url}")
        results = []
        
        # Use nuclei with exposure/token templates
        results.extend(self.run_nuclei(url, template_tags=["exposure", "token", "secret"]))
        
        return results
