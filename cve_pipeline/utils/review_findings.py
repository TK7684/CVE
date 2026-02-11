#!/usr/bin/env python3
"""
Review Findings Utility.
Allows the user to quickly view "Valid" (High Confidence) bugs for CVE submission.
"""
import sys
import sqlite3
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.settings import settings

console = Console()

def get_valid_findings():
    """Retrieves findings with HIGH confidence from the database."""
    db_path = settings.DATA_DIR / "hunter_state.db"
    
    if not db_path.exists():
        console.print("[red]Database not found. Run the pipeline first.[/red]")
        return []

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        
        # Join with targets to get the URL
        query = """
            SELECT f.tool, f.severity, f.description, f.confidence, t.url 
            FROM findings f
            JOIN targets t ON f.target_id = t.id
            WHERE f.confidence = 'HIGH'
            ORDER BY f.severity DESC
        """
        
        cursor = conn.execute(query)
        return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        console.print(f"[red]Database error: {e}[/red]")
        return []

def main():
    console.rule("[bold green]Valid Bugs for CVE Submission[/bold green]")
    
    findings = get_valid_findings()
    
    if not findings:
        console.print("\n[yellow]No high-confidence findings found yet.[/yellow]")
        console.print("Run the pipeline and ensure AI Triage is enabled.")
        return

    table = Table(title=f"Found {len(findings)} Valid Bugs")
    table.add_column("Severity", style="bold red")
    table.add_column("Tool", style="cyan")
    table.add_column("Target", style="blue")
    table.add_column("Description")
    
    for f in findings:
        table.add_row(
            f["severity"],
            f["tool"],
            f["url"],
            f["description"]
        )
    
    console.print(table)
    console.print("\n[bold]Instructions:[/bold]")
    console.print("1. Verify these findings manually.")
    console.print("2. Submit valid ones to the vendor or CVE program.")

if __name__ == "__main__":
    main()
