import requests
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from datetime import datetime, timezone
import signal
import sys
from typing import Dict, List, Optional
from dataclasses import dataclass
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from config import (
    AGENCIES, SPLUNK_ENDPOINT, PULSEPOINT_API,
    MAX_RETRIES, RETRY_DELAY, POST_DELAY, REQUEST_TIMEOUT,
    LOG_FILE, LOG_FORMAT, LOG_LEVEL,
    ENABLE_DEBUG_LOGGING, DEBUG_LOG_FORMAT,
    METRICS_ENABLED
)
from metrics_logger import (
    track_api_call, track_processing, track_splunk_post,
    track_retry, log_system_metrics, timing_context
)

@dataclass
class Metrics:
    total_incidents: int = 0
    successful_posts: int = 0
    failed_posts: int = 0
    retries: int = 0
    start_time: datetime = datetime.now(timezone.utc)
    end_time: Optional[datetime] = None

    def duration(self) -> float:
        end = self.end_time or datetime.now(timezone.utc)
        return (end - self.start_time).total_seconds()

    def to_dict(self) -> Dict:
        """Convert metrics to a dictionary for structured logging."""
        self.end_time = self.end_time or datetime.now(timezone.utc)
        return {
            "duration_seconds": round(self.duration(), 2),
            "total_incidents": self.total_incidents,
            "successful_posts": self.successful_posts,
            "failed_posts": self.failed_posts,
            "retries": self.retries,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "success_rate": round((self.successful_posts / self.total_incidents * 100) if self.total_incidents > 0 else 0, 2)
        }

class PulsePointCollector:
    def __init__(self):
        self.metrics = Metrics()
        self._setup_logging()
        self._setup_signal_handlers()

    def _setup_logging(self):
        """Configure logging with file and console handlers."""
        # Configure the root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG if ENABLE_DEBUG_LOGGING else logging.INFO)

        # Clear any existing handlers
        root_logger.handlers = []

        # Create formatters
        standard_formatter = logging.Formatter(LOG_FORMAT)
        debug_formatter = logging.Formatter(DEBUG_LOG_FORMAT)

        # Create and configure log file handler
        file_handler = logging.FileHandler(LOG_FILE)
        file_handler.setFormatter(debug_formatter if ENABLE_DEBUG_LOGGING else standard_formatter)
        file_handler.setLevel(logging.DEBUG if ENABLE_DEBUG_LOGGING else logging.INFO)
        root_logger.addHandler(file_handler)

        # Create and configure console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(standard_formatter)
        console_handler.setLevel(logging.INFO)  # Always show INFO and above in console
        root_logger.addHandler(console_handler)

        self.logger = logging.getLogger(__name__)

    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown."""
        def signal_handler(signum, frame):
            self.logger.info("Received shutdown signal. Finishing current operations...")
            self.metrics.end_time = datetime.now(timezone.utc)
            self._log_metrics()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    def _decrypt_pulsepoint_data(self, data: Dict) -> Dict:
        """Decrypt the PulsePoint response data."""
        try:
            # Get the encrypted data components
            ct = base64.b64decode(data.get("ct", ""))
            iv = bytes.fromhex(data.get("iv", ""))
            salt = bytes.fromhex(data.get("s", ""))
            
            self.logger.debug(f"Decryption components - ct length: {len(ct)}, iv length: {len(iv)}, salt length: {len(salt)}")

            # Build the password
            e = "CommonIncidents"
            t = e[13] + e[1] + e[2] + "brady" + "5" + "r" + e.lower()[6] + e[5] + "gs"
            self.logger.debug(f"Generated password: {t}")

            # Calculate a key from the password
            hasher = hashlib.md5()
            key = b''
            block = None

            while len(key) < 32:
                if block:
                    hasher.update(block)
                hasher.update(t.encode())
                hasher.update(salt)
                block = hasher.digest()
                key += block
                hasher = hashlib.md5()

            key = key[:32]  # Ensure key is exactly 32 bytes
            self.logger.debug(f"Generated key length: {len(key)}")

            # Create a cipher and decrypt the data
            backend = default_backend()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
            decryptor = cipher.decryptor()
            out = decryptor.update(ct) + decryptor.finalize()

            # Clean up output data
            out = out[1:out.rindex(b'"')].decode()  # Strip off extra bytes and wrapper quotes
            out = out.replace(r'\"', r'"')  # Un-escape quotes
            self.logger.debug(f"Decrypted data length: {len(out)}")

            # Parse the decrypted JSON
            decrypted_data = json.loads(out)
            self.logger.debug(f"Successfully decrypted data with keys: {list(decrypted_data.keys())}")
            return decrypted_data

        except Exception as e:
            self.logger.error(f"Error decrypting PulsePoint data: {str(e)}")
            self.logger.debug(f"Raw data: {json.dumps(data, indent=2)}")
            return {}

    def get_incidents(self, agency_id: str) -> Optional[Dict]:
        """Fetch incidents from PulsePoint API for a given agency."""
        @track_api_call(agency_id)
        def _fetch_incidents():
            self.logger.debug(f"Fetching incidents for agency {agency_id}")
            response = requests.get(
                PULSEPOINT_API,
                params={"agency_id": agency_id},
                timeout=REQUEST_TIMEOUT
            )
            response.raise_for_status()
            return response.json()
            
        try:
            data = _fetch_incidents()
            self.logger.debug(f"Raw response keys: {list(data.keys())}")
            self.logger.debug(f"Raw response data: {json.dumps(data, indent=2)}")
            
            # Decrypt the response
            decrypted_data = self._decrypt_pulsepoint_data(data)
            
            # Process and normalize the response
            processed_data = {
                "active": [],
                "recent": [],
                "incident_types": {},
                "status": {}
            }
            
            # Handle active incidents
            if "incidents" in decrypted_data:
                active_incidents = decrypted_data["incidents"].get("active", [])
                processed_data["active"] = self._normalize_incidents(active_incidents, agency_id)
                self.logger.debug(f"Found {len(processed_data['active'])} active incidents")
            else:
                self.logger.debug("No 'incidents' key found in decrypted data")
            
            # Handle recent incidents
            if "incidents" in decrypted_data:
                recent_incidents = decrypted_data["incidents"].get("recent", [])
                processed_data["recent"] = self._normalize_incidents(recent_incidents, agency_id)
                self.logger.debug(f"Found {len(processed_data['recent'])} recent incidents")
            
            # Store incident types and status if available
            if "types" in decrypted_data:
                processed_data["incident_types"] = decrypted_data.get("types", {})
            if "status" in decrypted_data:
                processed_data["status"] = decrypted_data.get("status", {})
            
            return processed_data
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error fetching incidents for {agency_id}: {str(e)}")
            return None

    @track_processing
    def _normalize_incidents(self, incidents: List[Dict], agency_id: str) -> List[Dict]:
        """Normalize incident data to a consistent format."""
        # Mapping of PulsePoint codes to human-readable values
        INCIDENT_TYPE_MAP = {
            "TC": "Traffic Collision",
            "HC": "Heart Condition",
            "ME": "Medical Emergency",
            "SF": "Structure Fire"
        }
        
        DISPATCH_STATUS_MAP = {
            "TA": "Tones Activated",
            "ER": "En Route",
            "OS": "On Scene",
            "AR": "Available for Response",
            "TR": "Transporting"
        }
        
        normalized = []
        for incident in incidents:
            try:
                # Convert coordinates if present
                if "lat" in incident and "lng" in incident:
                    incident["coordinates"] = [float(incident["lat"]), float(incident["lng"])]
                    del incident["lat"]
                    del incident["lng"]
                
                # Add agency ID
                incident["agencyId"] = agency_id
                
                # Map incident type and dispatch status to human-readable values
                if "PulsePointIncidentCallType" in incident:
                    incident["incident_type"] = INCIDENT_TYPE_MAP.get(
                        incident["PulsePointIncidentCallType"],
                        incident["PulsePointIncidentCallType"]
                    )
                
                # Map unit dispatch statuses
                if "Unit" in incident and isinstance(incident["Unit"], list):
                    for unit in incident["Unit"]:
                        if "PulsePointDispatchStatus" in unit:
                            unit["dispatch_status"] = DISPATCH_STATUS_MAP.get(
                                unit["PulsePointDispatchStatus"],
                                unit["PulsePointDispatchStatus"]
                            )
                
                # Convert timestamps to ISO format
                for time_field in ["receivedTime", "clearedTime"]:
                    if time_field in incident and incident[time_field]:
                        try:
                            incident[time_field] = datetime.fromtimestamp(
                                int(incident[time_field]) / 1000,  # Convert from milliseconds
                                tz=timezone.utc
                            ).isoformat()
                        except (ValueError, TypeError):
                            self.logger.warning(f"Could not convert {time_field} for incident {incident.get('id', 'unknown')}")
                
                # Normalize units if present
                if "units" in incident and isinstance(incident["units"], list):
                    for unit in incident["units"]:
                        if "clearedTime" in unit and unit["clearedTime"]:
                            try:
                                unit["clearedTime"] = datetime.fromtimestamp(
                                    int(unit["clearedTime"]) / 1000,
                                    tz=timezone.utc
                                ).isoformat()
                            except (ValueError, TypeError):
                                self.logger.warning(f"Could not convert unit clearedTime for incident {incident.get('id', 'unknown')}")
                
                normalized.append(incident)
            except Exception as e:
                self.logger.error(f"Error normalizing incident: {str(e)}")
                self.logger.debug(f"Problematic incident data: {json.dumps(incident, indent=2)}")
        
        return normalized

    @track_retry
    @track_splunk_post
    def send_to_splunk(self, data: Dict, agency: Dict) -> bool:
        """Send incident data to Splunk with retry logic."""
        retries = 0
        while retries < MAX_RETRIES:
            try:
                self.logger.debug(f"Sending data to Splunk for {agency['name']}: {json.dumps(data, indent=2)}")
                response = requests.post(
                    SPLUNK_ENDPOINT,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": agency["splunk_token"]
                    },
                    json={"event": data},
                    timeout=REQUEST_TIMEOUT
                )
                response.raise_for_status()
                self.metrics.successful_posts += 1
                self.logger.info(f"Successfully sent data to Splunk for {agency['name']}")
                return True
            except requests.exceptions.RequestException as e:
                retries += 1
                self.metrics.retries += 1
                self.logger.error(f"Error sending data to Splunk for {agency['name']}: {str(e)}")
                
                if retries < MAX_RETRIES:
                    self.logger.info(f"Retrying in {RETRY_DELAY} seconds... (attempt {retries + 1}/{MAX_RETRIES})")
                    time.sleep(RETRY_DELAY)
                else:
                    self.metrics.failed_posts += 1
                    self.logger.error(f"Max retries reached for {agency['name']}")
                    return False

    def process_agency(self, agency: Dict) -> bool:
        """Process incidents for a single agency."""
        with timing_context("process_agency", agency_id=agency["id"]):
            self.logger.info(f"Processing incidents for {agency['name']} ({agency['id']})")
            
            incidents_data = self.get_incidents(agency["id"])
            if not incidents_data:
                self.logger.error(f"Failed to get incidents for {agency['name']}")
                return False
            
            # Only process active incidents (those without a ClosedDateTime)
            active_incidents = [
                incident for incident in incidents_data.get("active", [])
                if "ClosedDateTime" not in incident or not incident["ClosedDateTime"]
            ]
            self.metrics.total_incidents += len(active_incidents)
            
            if not active_incidents:
                self.logger.info(f"No active incidents found for {agency['name']}")
                return True
            
            self.logger.info(f"Found {len(active_incidents)} active incidents for {agency['name']}")
            
            success = True
            for i, incident in enumerate(active_incidents):
                # Add UTC timestamp to incident data
                incident["_time"] = datetime.now(timezone.utc).isoformat()
                incident["_source"] = "pulsepoint"
                incident["agency_name"] = agency["name"]
                
                if not self.send_to_splunk(incident, agency):
                    success = False
                    # If we fail to send, wait before retrying
                    if i < len(active_incidents) - 1:
                        self.logger.debug(f"Waiting {RETRY_DELAY} seconds before next attempt... ({i + 1}/{len(active_incidents) - 1} remaining)")
                        time.sleep(RETRY_DELAY)
            
            return success

    def _log_metrics(self):
        """Log final metrics in a single structured line."""
        self.logger.info("Collection metrics: %s", json.dumps(self.metrics.to_dict()))

    def run(self) -> int:
        """Main function to process all agencies."""
        self.logger.info("Starting PulsePoint data collection")
        
        try:
            # Log system metrics at start
            if METRICS_ENABLED:
                log_system_metrics()
            
            # Process agencies in parallel
            with ThreadPoolExecutor(max_workers=len(AGENCIES)) as executor:
                future_to_agency = {
                    executor.submit(self.process_agency, agency): agency
                    for agency in AGENCIES
                }
                
                for future in as_completed(future_to_agency):
                    agency = future_to_agency[future]
                    try:
                        success = future.result()
                        if not success:
                            self.logger.error(f"Failed to process {agency['name']}")
                    except Exception as e:
                        self.logger.error(f"Error processing {agency['name']}: {str(e)}")
            
            # Log system metrics at end
            if METRICS_ENABLED:
                log_system_metrics()
            
            # Log final metrics
            self._log_metrics()
            return 0
            
        except Exception as e:
            self.logger.error(f"Fatal error in main process: {str(e)}")
            self._log_metrics()
            return 1

if __name__ == "__main__":
    collector = PulsePointCollector()
    exit_code = collector.run()
    exit(exit_code) 