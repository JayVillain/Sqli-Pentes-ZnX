#!/usr/bin/env python3
"""
Utility functions for SQLPenter.
This module provides helper functions used throughout the application.
"""

import os
import sys
import json
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

from loguru import logger


def setup_logger(level: str = "INFO", verbose: bool = False) -> None:
    """
    Configure the logger with appropriate settings.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
        verbose: Enable verbose output
    """
    # Remove default logger
    logger.remove()
    
    # Add stderr logger with custom format
    log_format = "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
    
    # Adjust logging level based on verbose flag
    if verbose and level != "DEBUG":
        level = "DEBUG"
    
    # Add console handler
    logger.add(sys.stderr, level=level, format=log_format)
    
    # Add file handler
    log_path = Path("logs")
    log_path.mkdir(exist_ok=True)
    log_file = log_path / f"sqlpenter_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    logger.add(log_file, level=level, format=log_format, rotation="10 MB")
    
    logger.debug(f"Logger initialized with level {level}")


def create_results_dir() -> str:
    """
    Create a directory for scan results.
    
    Returns:
        Path to the results directory
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_dir = Path("results") / f"scan_{timestamp}"
    results_dir.mkdir(parents=True, exist_ok=True)
    return str(results_dir)


def load_targets(targets_file: str) -> List[str]:
    """
    Load target URLs from a file.
    
    Args:
        targets_file: Path to the targets file
        
    Returns:
        List of target URLs
    """
    try:
        with open(targets_file, "r") as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        return targets
    except Exception as e:
        logger.error(f"Error loading targets: {e}")
        return []


def load_payloads(payload_file: str) -> Dict[str, Any]:
    """
    Load SQL injection payloads from a JSON file.
    
    Args:
        payload_file: Path to the payload file
        
    Returns:
        Dictionary of payloads
    """
    try:
        payload_path = Path(payload_file)
        if not payload_path.exists():
            # Look for payloads in the standard location relative to the script
            base_dir = Path(__file__).parent.parent
            payload_path = base_dir / payload_file
        
        with open(payload_path, "r") as f:
            payloads = json.load(f)
        return payloads
    except Exception as e:
        logger.error(f"Error loading payloads: {e}")
        return {}


def parse_url_params(url: str) -> Tuple[str, str, Dict[str, str]]:
    """
    Parse URL and extract parameters.
    
    Args:
        url: The URL to parse
        
    Returns:
        Tuple of (method, base_url, parameters)
    """
    # Default to GET method
    method = "GET"
    
    # Check if method is specified in a custom format (e.g., "POST:http://example.com")
    if ":" in url and url.split(":")[0].upper() in ["GET", "POST"]:
        method, url = url.split(":", 1)
        method = method.upper()
    
    # Parse the URL
    parsed_url = urllib.parse.urlparse(url)
    
    # Get the base URL without query parameters
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    
    # Parse query parameters
    params = dict(urllib.parse.parse_qsl(parsed_url.query))
    
    return method, base_url, params


def create_payload(param_name: str, sql_payload: str, injection_point: str) -> Dict[str, str]:
    """
    Create an injection payload for a parameter.
    
    Args:
        param_name: Name of the parameter to inject into
        sql_payload: SQL payload to inject
        injection_point: Position to inject (replace, append, prefix)
        
    Returns:
        Dictionary of parameters with injection payload
    """
    # Start with an empty parameter dictionary
    params = {}
    
    # Create the payload based on the injection point
    if injection_point == "replace":
        params[param_name] = sql_payload
    elif injection_point == "append":
        params[param_name] = f"{param_name}{sql_payload}"
    elif injection_point == "prefix":
        params[param_name] = f"{sql_payload}{param_name}"
    else:
        # Default to replace if unknown injection point
        params[param_name] = sql_payload
    
    return params


def is_vulnerable(content: str, original_content: str = None) -> bool:
    """
    Check if a response indicates SQL injection vulnerability.
    
    Args:
        content: Response content to check
        original_content: Original response content for comparison
        
    Returns:
        True if vulnerable, False otherwise
    """
    # Common SQL error patterns that indicate vulnerability
    error_patterns = [
        "SQL syntax",
        "mysql_fetch_array",
        "Warning: mysql",
        "MySQLSyntaxErrorException",
        "PostgreSQL ERROR",
        "PostgreSQL query failed",
        "Microsoft SQL Server",
        "ORA-01756",
        "Oracle Error",
        "SQLite3::query",
        "sqlite3.OperationalError",
        "Warning: SQLite3::",
        "SQL command not properly ended",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
    ]
    
    # Check for known error patterns
    for pattern in error_patterns:
        if pattern.lower() in content.lower():
            return True
    
    # If we have original content to compare with
    if original_content is not None and content != original_content:
        # Significant difference in content length might indicate vulnerability
        if abs(len(content) - len(original_content)) > 100:
            return True
    
    return False


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a string to be used as a filename.
    
    Args:
        filename: Input filename to sanitize
        
    Returns:
        Sanitized filename
    """
    # Replace invalid characters with underscores
    invalid_chars = ['<', '>', ':', '"', '/', '\\', '|', '?', '*']
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Limit filename length
    if len(filename) > 255:
        filename = filename[:255]
    
    return filename