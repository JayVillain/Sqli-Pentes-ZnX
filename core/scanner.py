#!/usr/bin/env python3
"""
SQL Injection Scanner module for SQLPenter.
Identifies vulnerable parameters in web applications.
"""

import asyncio
import re
from typing import Dict, Any, List, Optional
import urllib.parse
import aiohttp
from loguru import logger

from core.utils import load_payloads, parse_url_params


class SQLiScanner:
    """
    Scans for SQL injection vulnerabilities in web applications.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the SQL injection scanner.
        
        Args:
            config: Dictionary containing configuration parameters
        """
        self.concurrency = config.get("concurrency", 10)
        self.timeout = config.get("timeout", 5)
        self.proxy = config.get("proxy")
        self.delay = config.get("delay", 0)
        
        # Load payloads from file
        self.payloads = load_payloads("payloads/sqli_payloads.json").get("detection", [])
        
        # Common error patterns from various databases
        self.error_patterns = [
            r"SQL syntax.*?MySQL",
            r"Warning.*?mysqli_",
            r"PostgreSQL.*?ERROR",
            r"Microsoft SQL Server",
            r"Oracle.*?ORA-[0-9]",
            r"SQLite3::query",
            r"Microsoft Access Driver",
            r"Warning.*?PDO::prepare",
            r"Warning.*?SQLite3::query",
            r"DB2 SQL error",
            r"SQLite3::exec",
            r"Microsoft OLE DB Provider for SQL Server",
            r"ODBC Driver.*?SQL",
            r"Exception.*?Oracle",
            r"PostgreSQL query failed",
            r"\[IBM\]\[CLI Driver\]\[DB2/]",
            r"Sybase.*?Server message",
            r"You have an error in your SQL syntax",
            r"sql_error_code",
            r"syntax error at or near",
            r"invalid input syntax for",
            r"unterminated quoted string at or near",
            r"SQL command not properly ended",
            r"unexpected end of SQL command",
            r"column .* does not exist",
            r"database .* does not exist"
        ]
        
        # Compile regex patterns for better performance
        self.error_regex = re.compile('|'.join(self.error_patterns), re.IGNORECASE)
        
    async def scan_url(self, url: str) -> List[Dict[str, Any]]:
        """
        Scan a URL for SQL injection vulnerabilities.
        
        Args:
            url: The URL to scan
            
        Returns:
            List of dictionaries containing injectable parameter information
        """
        logger.info(f"Scanning {url} for SQL injection vulnerabilities")
        
        # Parse URL and identify parameters
        method, target_url, params = parse_url_params(url)
        
        # If no parameters found, notify and return
        if not params:
            logger.warning(f"No parameters found in {url}. Trying form discovery...")
            form_params = await self._discover_forms(url)
            if not form_params:
                logger.warning(f"No forms found in {url}")
                return []
            # Use discovered form parameters
            params = form_params
        
        # Create a semaphore to limit concurrency
        semaphore = asyncio.Semaphore(self.concurrency)
        
        # Test each parameter for SQL injection
        vulnerable_params = []
        tasks = []
        
        for param_name, param_value in params.items():
            task = self._test_parameter(url, method, param_name, param_value, semaphore)
            tasks.append(task)
        
        # Wait for all tasks to complete
        results = await asyncio.gather(*tasks)
        
        # Filter out None results and collect vulnerable parameters
        for result in results:
            if result:
                vulnerable_params.append(result)
        
        return vulnerable_params
    
    async def _test_parameter(
        self, url: str, method: str, param_name: str, param_value: str, semaphore: asyncio.Semaphore
    ) -> Optional[Dict[str, Any]]:
        """
        Test a single parameter for SQL injection vulnerabilities.
        
        Args:
            url: The URL to test
            method: HTTP method (GET or POST)
            param_name: Parameter name
            param_value: Original parameter value
            semaphore: Semaphore for limiting concurrency
            
        Returns:
            Dictionary with vulnerability information if found, None otherwise
        """
        async with semaphore:
            # Create baseline parameters
            baseline_params = {}
            for payload in self.payloads:
                # Test for different injection points within the parameter value
                injection_points = [
                    {"position": "replace", "value": param_value},  # Replace entire value
                    {"position": "append", "value": f"{param_value}{payload}"},  # Append to value
                    {"position": "prefix", "value": f"{payload}{param_value}"}   # Prefix to value
                ]
                
                for injection in injection_points:
                    # Set up HTTP session with proxy if needed
                    session_kwargs = {
                        "timeout": aiohttp.ClientTimeout(total=self.timeout)
                    }
                    if self.proxy:
                        session_kwargs["proxy"] = self.proxy
                        
                    # Create test parameters
                    test_params = {k: v for k, v in params.items()}
                    test_params[param_name] = injection["value"]
                    
                    # Add delay if configured
                    if self.delay > 0:
                        await asyncio.sleep(self.delay)
                    
                    try:
                        async with aiohttp.ClientSession(**session_kwargs) as session:
                            # Configure request parameters based on method
                            request_kwargs = {}
                            if method.upper() == "GET":
                                request_kwargs["params"] = test_params
                            else:
                                request_kwargs["data"] = test_params
                            
                            # Send the request
                            async with session.request(method, url, **request_kwargs) as response:
                                content = await response.text()
                                
                                # Check for SQL error patterns in the response
                                if self.error_regex.search(content):
                                    logger.success(f"Found SQL injection in {param_name} at {url}")
                                    return {
                                        "param": param_name,
                                        "method": method,
                                        "payload": payload,
                                        "injection_point": injection["position"],
                                        "url": url
                                    }
                    
                    except Exception as e:
                        logger.debug(f"Error testing {param_name} with {payload}: {e}")
                        continue
            
            return None
    
    async def _discover_forms(self, url: str) -> Dict[str, str]:
        """
        Attempt to discover forms on the page for testing.
        
        Args:
            url: The URL to analyze
            
        Returns:
            Dictionary of form parameter names and default values
        """
        try:
            # Set up HTTP session with proxy if needed
            session_kwargs = {
                "timeout": aiohttp.ClientTimeout(total=self.timeout)
            }
            if self.proxy:
                session_kwargs["proxy"] = self.proxy
                
            async with aiohttp.ClientSession(**session_kwargs) as session:
                async with session.get(url) as response:
                    content = await response.text()
                    
                    # Use a simple regex to identify form fields
                    # This is a basic implementation - a real tool would use a proper HTML parser
                    input_pattern = re.compile(r'<input.*?name=["\']([^"\']+)["\'].*?(?:value=["\']([^"\']*)["\'])?', re.IGNORECASE)
                    matches = input_pattern.findall(content)
                    
                    # Create a dictionary of form fields
                    form_params = {}
                    for name, value in matches:
                        form_params[name] = value
                    
                    return form_params
        
        except Exception as e:
            logger.debug(f"Error discovering forms: {e}")
            return {}