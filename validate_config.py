#!/usr/bin/env python3
"""
Configuration validation script for PulsePoint Data Collection System.
Validates the configuration file for required settings and format.
"""

import os
import sys
import json
import requests
from urllib.parse import urlparse
import logging
from typing import Dict, List, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def validate_url(url: str) -> bool:
    """Validate URL format and HTTPS requirement."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]) and result.scheme == 'https'
    except Exception:
        return False

def validate_cribl_token(token: str) -> bool:
    """Validate Cribl Stream HEC token format."""
    return token.startswith('Cribl ') and len(token.split()) == 2

def validate_agency(agency: Dict[str, str]) -> List[str]:
    """Validate agency configuration."""
    errors = []
    
    # Check required fields
    required_fields = ['id', 'name', 'cribl_token']
    for field in required_fields:
        if field not in agency:
            errors.append(f"Missing required field: {field}")
    
    # Validate field types
    if 'id' in agency and not isinstance(agency['id'], str):
        errors.append("Agency ID must be a string")
    if 'name' in agency and not isinstance(agency['name'], str):
        errors.append("Agency name must be a string")
    if 'cribl_token' in agency and not validate_cribl_token(agency['cribl_token']):
        errors.append("Invalid Cribl token format")
    
    return errors

def validate_timing_settings(config: Dict[str, Any]) -> List[str]:
    """Validate timing-related settings."""
    errors = []
    
    # Check numeric settings
    numeric_settings = {
        'MAX_RETRIES': (int, 1, 10),
        'RETRY_DELAY': (int, 1, 60),
        'POST_DELAY': (int, 1, 60),
        'REQUEST_TIMEOUT': (int, 5, 300)
    }
    
    for setting, (type_, min_, max_) in numeric_settings.items():
        if setting in config:
            try:
                value = type_(config[setting])
                if not min_ <= value <= max_:
                    errors.append(f"{setting} must be between {min_} and {max_}")
            except (ValueError, TypeError):
                errors.append(f"{setting} must be a {type_.__name__}")
    
    return errors

def validate_logging_settings(config: Dict[str, Any]) -> List[str]:
    """Validate logging-related settings."""
    errors = []
    
    # Check log level
    valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    if 'LOG_LEVEL' in config and config['LOG_LEVEL'] not in valid_levels:
        errors.append(f"LOG_LEVEL must be one of: {', '.join(valid_levels)}")
    
    # Check boolean settings
    boolean_settings = ['ENABLE_DEBUG_LOGGING', 'METRICS_ENABLED']
    for setting in boolean_settings:
        if setting in config and not isinstance(config[setting], bool):
            errors.append(f"{setting} must be a boolean")
    
    return errors

def test_cribl_connection(endpoint: str, token: str) -> bool:
    """Test connection to Cribl Stream HEC endpoint."""
    try:
        response = requests.post(
            endpoint,
            headers={
                'Content-Type': 'application/json',
                'Authorization': token
            },
            json={'event': {'test': 'connection'}},
            timeout=5
        )
        return response.status_code == 200
    except Exception as e:
        logger.error(f"Failed to connect to Cribl Stream: {str(e)}")
        return False

def main():
    """Main validation function."""
    try:
        # Import configuration
        from config import (
            CRIBL_HEC_ENDPOINT, AGENCIES, MAX_RETRIES, RETRY_DELAY,
            POST_DELAY, REQUEST_TIMEOUT, LOG_LEVEL, ENABLE_DEBUG_LOGGING,
            METRICS_ENABLED
        )
    except ImportError as e:
        logger.error(f"Failed to import configuration: {str(e)}")
        sys.exit(1)
    
    errors = []
    warnings = []
    
    # Validate Cribl endpoint
    if not validate_url(CRIBL_HEC_ENDPOINT):
        errors.append("Invalid Cribl Stream HEC endpoint URL")
    
    # Validate agencies
    if not isinstance(AGENCIES, list):
        errors.append("AGENCIES must be a list")
    else:
        for i, agency in enumerate(AGENCIES):
            agency_errors = validate_agency(agency)
            if agency_errors:
                errors.extend([f"Agency {i + 1}: {error}" for error in agency_errors])
    
    # Validate timing settings
    timing_errors = validate_timing_settings({
        'MAX_RETRIES': MAX_RETRIES,
        'RETRY_DELAY': RETRY_DELAY,
        'POST_DELAY': POST_DELAY,
        'REQUEST_TIMEOUT': REQUEST_TIMEOUT
    })
    errors.extend(timing_errors)
    
    # Validate logging settings
    logging_errors = validate_logging_settings({
        'LOG_LEVEL': LOG_LEVEL,
        'ENABLE_DEBUG_LOGGING': ENABLE_DEBUG_LOGGING,
        'METRICS_ENABLED': METRICS_ENABLED
    })
    errors.extend(logging_errors)
    
    # Test Cribl connection for each agency
    for agency in AGENCIES:
        if not test_cribl_connection(CRIBL_HEC_ENDPOINT, agency['cribl_token']):
            warnings.append(f"Could not connect to Cribl Stream using token for {agency['name']}")
    
    # Report results
    if errors:
        logger.error("Configuration validation failed:")
        for error in errors:
            logger.error(f"- {error}")
        sys.exit(1)
    
    if warnings:
        logger.warning("Configuration validation completed with warnings:")
        for warning in warnings:
            logger.warning(f"- {warning}")
    else:
        logger.info("Configuration validation completed successfully")

if __name__ == '__main__':
    main() 