#!/usr/bin/env python3
"""
The Hunter's Loop - Security Pipeline Entry Point.

Usage:
    python main.py <target_domain> [--dry-run]

Example:
    python main.py example.com
    python main.py example.com --dry-run
"""
import sys
import argparse
from pathlib import Path

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from core.logger import log, console
from core.orchestrator import Orchestrator
from config.settings import settings
from utils.target_discovery import fetch_bounty_targets


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="The Hunter's Loop - Automated Security Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py example.com              # Full scan
  python main.py example.com --dry-run    # Test mode (no actual scanning)
        """
    )
    
    parser.add_argument(
        "target",
        nargs="?",
        help="Target domain to scan (e.g., example.com)"
    )

    parser.add_argument(
        "--auto-discover",
        action="store_true",
        help="Automatically fetch valid bug bounty targets"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run in test mode without executing actual scans"
    )
    
    parser.add_argument(
        "--scope-file",
        type=str,
        default=None,
        help="Path to custom scope rules JSON file"
    )
    
    return parser.parse_args()


def print_banner():
    """Prints the application banner."""
    banner = """
[bold cyan]
   The Hunter's Loop
   Automated Security Pipeline v1.0
[/bold cyan]
    """
    console.print(banner)


def validate_environment():
    """Validates that required tools and configs are available."""
    issues = []
    
    # Check scope file
    if not settings.SCOPE_FILE.exists():
        issues.append(f"Scope file not found: {settings.SCOPE_FILE}")
    
    # Check API keys (optional but warn)
    if not settings.GEMINI_API_KEY:
        log.warning("[Config] GEMINI_API_KEY not set. AI Triage will be disabled.")
    
    if not settings.DISCORD_WEBHOOK_URL:
        log.warning("[Config] DISCORD_WEBHOOK_URL not set. Alerts will be disabled.")
    
    # Fatal issues
    if issues:
        for issue in issues:
            log.error(f"[Config] {issue}")
        return False
    
    return True


def main():
    """Main entry point."""
    print_banner()
    
    args = parse_args()
    
    # Validate environment
    if not validate_environment():
        log.error("[Main] Configuration errors detected. Please fix before running.")
        sys.exit(1)
    
    # Print configuration summary
    console.print(f"\n[bold]Configuration:[/bold]")
    console.print(f"  Target:         [cyan]{args.target}[/cyan]")
    console.print(f"  Dry Run:        [yellow]{args.dry_run}[/yellow]")
    console.print(f"  Rate Limit:     [green]{settings.GLOBAL_RATE_LIMIT} req/s[/green]")
    console.print(f"  Max Threads:    [green]{settings.MAX_THREADS}[/green]")
    console.print(f"  Brute Force:    [{'red' if settings.ENABLE_BRUTEFORCE else 'green'}]{settings.ENABLE_BRUTEFORCE}[/]")
    console.print(f"  Output Dir:     [dim]{settings.DATA_DIR / (args.target or 'auto-discovery')}[/dim]")
    console.print()
    
    # Run the pipeline
    try:
        if args.auto_discover:
            if args.target:
                log.warning("[Main] Target provided with --auto-discover. Ignoring manual target.")
            
            targets = fetch_bounty_targets(limit=1) # Fetch 1 for now to process
            if not targets:
                log.error("[Discovery] No targets found.")
                sys.exit(1)
            
            target_domain = targets[0]
            log.info(f"[Discovery] Auto-selected target: {target_domain}")
            
        elif args.target:
            target_domain = args.target
        else:
            parser.error("must provide either 'target' or '--auto-discover'")
            
        orchestrator = Orchestrator(
            target=target_domain,
            dry_run=args.dry_run
        )
        orchestrator.run()
    except KeyboardInterrupt:
        log.info("[Main] Interrupted by user.")
    except Exception as e:
        log.error(f"[Main] Fatal error: {e}")
        raise


if __name__ == "__main__":
    main()
