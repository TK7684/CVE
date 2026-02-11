#!/usr/bin/env python3
"""
One-Click Scan Runner for The Hunter's Loop.
Automates:
1. Docker verification
2. Image building (if needed)
3. Container execution
4. Result location display
"""
import subprocess
import sys
import shutil
import time
from pathlib import Path

def print_color(text, color="white"):
    colors = {
        "green": "\033[92m",
        "red": "\033[91m",
        "yellow": "\033[93m",
        "cyan": "\033[96m",
        "reset": "\033[0m"
    }
    print(f"{colors.get(color, '')}{text}{colors['reset']}")

def check_docker():
    """Checks if Docker is running."""
    if not shutil.which("docker"):
        print_color("Error: Docker is not installed or not in PATH.", "red")
        return False
    
    try:
        subprocess.run(["docker", "info"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        print_color("Error: Docker daemon is not running. Please start Docker Desktop.", "red")
        return False

def build_image():
    """Builds the Docker image."""
    print_color("\n[*] Building Docker image (this may take a while first time)...", "cyan")
    try:
        subprocess.run(["docker", "build", "-t", "hunter-loop", "."], check=True)
        print_color("[+] Build successful!", "green")
        return True
    except subprocess.CalledProcessError:
        print_color("[-] Build failed.", "red")
        return False

def run_scan(target, dry_run=False):
    """Runs the scan in a container."""
    cmd = [
        "docker", "run", "--rm", "-it",
        "--network", "host",
        "-v", f"{Path.cwd()}/data:/app/data",
        "-v", f"{Path.cwd()}/config:/app/config",
        "-v", "nuclei-templates:/root/nuclei-templates",
        "--env-file", ".env",
        "hunter-loop",
        "python", "main.py", target
    ]
    
    if dry_run:
        cmd.append("--dry-run")
    
    print_color(f"\n[*] Starting scan for target: {target}", "yellow")
    try:
        subprocess.run(cmd, check=True)
        print_color(f"\n[+] Scan completed for {target}", "green")
        print_color(f"[*] Results saved to: {Path.cwd()}/data/{target}", "cyan")
    except subprocess.CalledProcessError:
        print_color("[-] Scan encountered an error.", "red")
    except KeyboardInterrupt:
        print_color("\n[!] Scan interrupted by user.", "yellow")

def main():
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        print_color("The Hunter's Loop - Automated Runner", "cyan")
        target = input("Enter target domain (e.g., example.com): ").strip()
    
    if not target:
        print_color("Error: No target specified.", "red")
        sys.exit(1)
        
    dry_run = "--dry-run" in sys.argv
    
    if not check_docker():
        sys.exit(1)
        
    if not build_image():
         sys.exit(1)
         
    run_scan(target, dry_run)

if __name__ == "__main__":
    main()
