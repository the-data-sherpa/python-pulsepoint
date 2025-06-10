import requests
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from datetime import datetime, timezone
import signal
import sys
from typing import Dict, List, Optional, Literal
from dataclasses import dataclass
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from config import (
    AGENCIES, CRIBL_HEC_ENDPOINT, PULSEPOINT_API,
    MAX_RETRIES, RETRY_DELAY, POST_DELAY, REQUEST_TIMEOUT,
    LOG_FILE, LOG_FORMAT, LOG_LEVEL,
    ENABLE_DEBUG_LOGGING, DEBUG_LOG_FORMAT,
    METRICS_ENABLED
)
from metrics_logger import (
    track_api_call, track_processing, track_splunk_post,
    track_retry, log_system_metrics, timing_context
)
from waze_feed_generator import generate_waze_feed

# Headers for the new PulsePoint API - Updated to match working browser requests exactly
PULSEPOINT_HEADERS = {
    "accept": "*/*",
    "accept-language": "en-US,en;q=0.9",
    "content-type": "application/json",
    "priority": "u=1, i",
    "sec-ch-ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"macOS"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-site",
    "Referer": "https://web.pulsepoint.org/",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"
}

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

# Call Type Categories - matching the TypeScript definitions
CallTypeCategory = Literal[
    'Aid', 'Aircraft', 'Alarm', 'Assist', 'Explosion', 'Fire', 'Hazard',
    'Investigation', 'Lockout', 'Medical', 'Natural Disaster', 'Rescue',
    'Vehicle', 'Wires', 'Other', 'Alert', 'Unknown'
]

@dataclass
class CallType:
    id: str
    description: str
    category: CallTypeCategory

# Comprehensive call types list - matching the PulsePoint site exactly
CALL_TYPES: List[CallType] = [
    # Aid
    CallType('AA', 'Auto Aid', 'Aid'),
    CallType('MU', 'Mutual Aid', 'Aid'),
    CallType('ST', 'Strike Team/Task Force', 'Aid'),
    
    # Aircraft
    CallType('AC', 'Aircraft Crash', 'Aircraft'),
    CallType('AE', 'Aircraft Emergency', 'Aircraft'),
    CallType('AES', 'Aircraft Emergency Standby', 'Aircraft'),
    CallType('LZ', 'Landing Zone', 'Aircraft'),
    
    # Alarm
    CallType('AED', 'AED Alarm', 'Alarm'),
    CallType('OA', 'Alarm', 'Alarm'),
    CallType('CMA', 'Carbon Monoxide', 'Alarm'),
    CallType('FA', 'Fire Alarm', 'Alarm'),
    CallType('MA', 'Manual Alarm', 'Alarm'),
    CallType('SD', 'Smoke Detector', 'Alarm'),
    CallType('TRBL', 'Trouble Alarm', 'Alarm'),
    CallType('WFA', 'Waterflow Alarm', 'Alarm'),
    
    # Assist
    CallType('FL', 'Flooding', 'Assist'),
    CallType('LR', 'Ladder Request', 'Assist'),
    CallType('LA', 'Lift Assist', 'Assist'),
    CallType('PA', 'Police Assist', 'Assist'),
    CallType('PS', 'Public Service', 'Assist'),
    CallType('SH', 'Sheared Hydrant', 'Assist'),
    
    # Explosion
    CallType('EX', 'Explosion', 'Explosion'),
    CallType('PE', 'Pipeline Emergency', 'Explosion'),
    CallType('TE', 'Transformer Explosion', 'Explosion'),
    
    # Fire
    CallType('AF', 'Appliance Fire', 'Fire'),
    CallType('CHIM', 'Chimney Fire', 'Fire'),
    CallType('CF', 'Commercial Fire', 'Fire'),
    CallType('WSF', 'Confirmed Structure Fire', 'Fire'),
    CallType('WVEG', 'Confirmed Vegetation Fire', 'Fire'),
    CallType('CB', 'Controlled Burn/Prescribed Fire', 'Fire'),
    CallType('ELF', 'Electrical Fire', 'Fire'),
    CallType('EF', 'Extinguished Fire', 'Fire'),
    CallType('FIRE', 'Fire', 'Fire'),
    CallType('FULL', 'Full Assignment', 'Fire'),
    CallType('IF', 'Illegal Fire', 'Fire'),
    CallType('MF', 'Marine Fire', 'Fire'),
    CallType('OF', 'Outside Fire', 'Fire'),
    CallType('PF', 'Pole Fire', 'Fire'),
    CallType('GF', 'Refuse/Garbage Fire', 'Fire'),
    CallType('RF', 'Residential Fire', 'Fire'),
    CallType('SF', 'Structure Fire', 'Fire'),
    CallType('TF', 'Tank Fire', 'Fire'),
    CallType('VEG', 'Vegetation Fire', 'Fire'),
    CallType('VF', 'Vehicle Fire', 'Fire'),
    CallType('WF', 'Confirmed Fire', 'Fire'),
    CallType('WCF', 'Confirmed Commercial Fire', 'Fire'),
    CallType('WRF', 'Confirmed Residential Fire', 'Fire'),
    
    # Hazard
    CallType('BT', 'Bomb Threat', 'Hazard'),
    CallType('EE', 'Electrical Emergency', 'Hazard'),
    CallType('EM', 'Emergency', 'Hazard'),
    CallType('ER', 'Emergency Response', 'Hazard'),
    CallType('GAS', 'Gas Main', 'Hazard'),
    CallType('HC', 'Hazardous Condition', 'Hazard'),
    CallType('HMR', 'Hazardous Materials Response', 'Hazard'),
    CallType('TD', 'Tree Down', 'Hazard'),
    CallType('WE', 'Water Emergency', 'Hazard'),
    
    # Investigation
    CallType('AI', 'Arson Investigation', 'Investigation'),
    CallType('FWI', 'Fireworks Investigation', 'Investigation'),
    CallType('HMI', 'Hazmat Investigation', 'Investigation'),
    CallType('INV', 'Investigation', 'Investigation'),
    CallType('OI', 'Odor Investigation', 'Investigation'),
    CallType('SI', 'Smoke Investigation', 'Investigation'),
    
    # Lockout
    CallType('CL', 'Commercial Lockout', 'Lockout'),
    CallType('LO', 'Lockout', 'Lockout'),
    CallType('RL', 'Residential Lockout', 'Lockout'),
    CallType('VL', 'Vehicle Lockout', 'Lockout'),
    
    # Medical
    CallType('CP', 'Community Paramedicine', 'Medical'),
    CallType('IFT', 'Interfacility Transfer', 'Medical'),
    CallType('ME', 'Medical Emergency', 'Medical'),
    CallType('MCI', 'Multi Casualty', 'Medical'),
    
    # Natural Disaster
    CallType('EQ', 'Earthquake', 'Natural Disaster'),
    CallType('FLW', 'Flood Warning', 'Natural Disaster'),
    CallType('TOW', 'Tornado Warning', 'Natural Disaster'),
    CallType('TSW', 'Tsunami Warning', 'Natural Disaster'),
    CallType('WX', 'Weather Incident', 'Natural Disaster'),
    
    # Rescue
    CallType('AR', 'Animal Rescue', 'Rescue'),
    CallType('CR', 'Cliff Rescue', 'Rescue'),
    CallType('CSR', 'Confined Space Rescue', 'Rescue'),
    CallType('ELR', 'Elevator Rescue', 'Rescue'),
    CallType('EER', 'Elevator/Escalator Rescue', 'Rescue'),
    CallType('IR', 'Ice Rescue', 'Rescue'),
    CallType('IA', 'Industrial Accident', 'Rescue'),
    CallType('RES', 'Rescue', 'Rescue'),
    CallType('RR', 'Rope Rescue', 'Rescue'),
    CallType('SC', 'Structural Collapse', 'Rescue'),
    CallType('TR', 'Technical Rescue', 'Rescue'),
    CallType('TNR', 'Trench Rescue', 'Rescue'),
    CallType('USAR', 'Urban Search and Rescue', 'Rescue'),
    CallType('VS', 'Vessel Sinking', 'Rescue'),
    CallType('WR', 'Water Rescue', 'Rescue'),
    
    # Vehicle
    CallType('TCP', 'Collision Involving Pedestrian', 'Vehicle'),
    CallType('TCS', 'Collision Involving Structure', 'Vehicle'),
    CallType('TCT', 'Collision Involving Train', 'Vehicle'),
    CallType('TCE', 'Expanded Traffic Collision', 'Vehicle'),
    CallType('RTE', 'Railroad/Train Emergency', 'Vehicle'),
    CallType('TC', 'Traffic Collision', 'Vehicle'),
    
    # Wires
    CallType('PLE', 'Powerline Emergency', 'Wires'),
    CallType('WA', 'Wires Arching', 'Wires'),
    CallType('WD', 'Wires Down', 'Wires'),
    CallType('WDA', 'Wires Down/Arcing', 'Wires'),
    
    # Other
    CallType('BP', 'Burn Permit', 'Other'),
    CallType('CA', 'Community Activity', 'Other'),
    CallType('FW', 'Fire Watch', 'Other'),
    CallType('MC', 'Move-up/Cover', 'Other'),
    CallType('NO', 'Notification', 'Other'),
    CallType('STBY', 'Standby', 'Other'),
    CallType('TEST', 'Test', 'Other'),
    CallType('TRNG', 'Training', 'Other'),
    
    # Alert
    CallType('NEWS', 'News', 'Alert'),
    CallType('CERT', 'CERT', 'Alert'),
    CallType('DISASTER', 'Disaster', 'Alert'),
    
    # Unknown
    CallType('UNK', 'Unknown Call Type', 'Unknown'),
]

# Create lookup dictionary for fast access
CALL_TYPE_LOOKUP: Dict[str, CallType] = {call_type.id: call_type for call_type in CALL_TYPES}

def call_type_from_code(call_type_code: str) -> CallType:
    """Get call type information from code, returns Unknown if not found."""
    return CALL_TYPE_LOOKUP.get(call_type_code, CallType('UNK', 'Unknown Call Type', 'Unknown'))

def call_types_for_categories(categories: List[CallTypeCategory]) -> List[CallType]:
    """Get all call types that belong to the specified categories."""
    return [call_type for call_type in CALL_TYPES if call_type.category in categories]

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
        console_handler.setLevel(logging.ERROR)  # Only show ERROR and above in console
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
        # Ensure input is a dictionary
        if not isinstance(data, dict):
            self.logger.error(f"_decrypt_pulsepoint_data received non-dict input: {type(data)}")
            return {}

        try:
            # Get the encrypted data components
            ct_b64 = data.get("ct", "")
            iv_hex = data.get("iv", "")
            salt_hex = data.get("s", "")

            if not ct_b64 or not iv_hex or not salt_hex: # This check remains useful for truly empty strings from JSON
                self.logger.error("Missing or empty encryption components (ct, iv, or s string values) in input data.")
                self.logger.debug(f"Input data values - ct_b64 empty: {not ct_b64}, iv_hex empty: {not iv_hex}, salt_hex empty: {not salt_hex}")
                return {}

            try:
                ct = base64.b64decode(ct_b64)
            except (ValueError, TypeError, base64.binascii.Error) as e_b64:
                self.logger.error(f"Failed to decode base64 ciphertext (ct): {str(e_b64)}")
                self.logger.debug(f"Problematic ct_b64 (first 50 chars): {ct_b64[:50]}")
                return {}

            try:
                iv = bytes.fromhex(iv_hex)
            except ValueError as e_hex_iv:
                self.logger.error(f"Failed to decode hex IV: {str(e_hex_iv)}")
                self.logger.debug(f"Problematic iv_hex: {iv_hex}")
                return {}

            try:
                salt = bytes.fromhex(salt_hex)
            except ValueError as e_hex_salt:
                self.logger.error(f"Failed to decode hex salt: {str(e_hex_salt)}")
                self.logger.debug(f"Problematic salt_hex: {salt_hex}")
                return {}
            
            if not ct:
                self.logger.error("Decryption ciphertext (ct) is empty after base64 decoding.")
                return {}
            if len(iv) != 16: # AES block size is 128 bits = 16 bytes
                self.logger.error(f"Decryption IV length is {len(iv)}, but must be 16 bytes for AES.")
                return {}
            # Salt length is not as strictly constrained for MD5 key derivation, can be empty.

            self.logger.debug(f"Decryption components - ct length: {len(ct)}, iv: {iv.hex()}, salt: {salt.hex()}")

            # Build the password
            e = "CommonIncidents"
            t = e[13] + e[1] + e[2] + "brady" + "5" + "r" + e.lower()[6] + e[5] + "gs"
            # self.logger.debug(f"Generated password: {t}") # Password logging can be verbose

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
            # The decrypted output is expected to be a JSON string.
            # It might be wrapped in extra bytes or quotes depending on the exact API behavior.
            # The previous logic `out = out[1:out.rindex(b'"')].decode()` assumed a specific wrapping.
            # A more robust approach might be to try decoding directly,
            # or strip common problematic characters if decoding fails.
            try:
                # Attempt to decode directly first
                json_string = out.decode('utf-8')
            except UnicodeDecodeError:
                self.logger.warning("Direct UTF-8 decoding of decrypted data failed, attempting to strip non-JSON bytes.")
                # This is a common pattern: leading/trailing bytes or incorrect padding.
                # Find first '{' or '[' and last '}' or ']'
                start_brace = out.find(b'{')
                start_bracket = out.find(b'[')
                
                if start_brace == -1 and start_bracket == -1:
                    self.logger.error("Decrypted data does not seem to contain JSON object or array.")
                    return {}

                start_index = -1
                if start_brace != -1 and start_bracket != -1:
                    start_index = min(start_brace, start_bracket)
                elif start_brace != -1:
                    start_index = start_brace
                else:
                    start_index = start_bracket
                
                end_brace = out.rfind(b'}')
                end_bracket = out.rfind(b']')

                if end_brace == -1 and end_bracket == -1:
                     self.logger.error("Decrypted data does not seem to have a valid JSON end.")
                     return {}

                end_index = -1
                if end_brace != -1 and end_bracket != -1:
                    end_index = max(end_brace, end_bracket)
                elif end_brace != -1:
                    end_index = end_brace
                else:
                    end_index = end_bracket
                
                if start_index > end_index :
                    self.logger.error(f"Could not reliably find JSON content in decrypted data. Start: {start_index}, End: {end_index}")
                    return {}

                json_string = out[start_index : end_index+1].decode('utf-8', errors='replace')

            json_string = json_string.replace(r'\\\"', r'\"') # Handle escaped quotes if necessary, though json.loads should handle valid JSON escapes.
                                                              # The original had .replace(r'\\\"', r'\"') and then .replace(r'\"', r'"')
                                                              # This might be specific to the previous single-agency payload.
                                                              # For now, let's be conservative, json.loads is robust.
            
            self.logger.debug(f"Attempting to parse decrypted JSON string (length: {len(json_string)}): {json_string[:200]}...")
            
            # Parse the decrypted JSON, attempting double parse if the first result is a string
            parsed_json_intermediate = json.loads(json_string)
            if isinstance(parsed_json_intermediate, str):
                self.logger.info("Initial JSON parse of decrypted data resulted in a string, attempting a second parse.")
                try:
                    decrypted_data = json.loads(parsed_json_intermediate)
                except json.JSONDecodeError as e_double:
                    self.logger.error(f"Second JSON parse (after initial string result) failed: {str(e_double)}")
                    self.logger.debug(f"String from first parse (that failed second parse, first 500 chars): {parsed_json_intermediate[:500]}")
                    # Re-raise to be caught by the outer handler which logs more context about json_string
                    raise json.JSONDecodeError(e_double.msg, json_string, e_double.pos) from e_double
            else:
                decrypted_data = parsed_json_intermediate

            if not isinstance(decrypted_data, dict):
                self.logger.error(f"Decrypted data is not a dictionary after parsing. Type: {type(decrypted_data)}")
                self.logger.debug(f"Non-dict decrypted data (first 500 chars): {str(decrypted_data)[:500]}")
                return {}

            self.logger.debug(f"Successfully decrypted and parsed data. Top-level keys: {list(decrypted_data.keys())}")
            return decrypted_data

        except json.JSONDecodeError as e:
            # Attempt to handle "Extra data" error by parsing up to e.pos (common with PulsePoint responses)
            if "Extra data" in e.msg and e.pos > 0:
                self.logger.warning(f"Extra data detected in JSON response at pos {e.pos}. Attempting to parse valid portion.")
                json_string_trimmed = json_string[:e.pos]
                try:
                    parsed_trimmed_intermediate = json.loads(json_string_trimmed)
                    self.logger.debug(f"Successfully parsed trimmed JSON string up to pos {e.pos}. Result type: {type(parsed_trimmed_intermediate)}")

                    final_data_to_check = parsed_trimmed_intermediate
                    if isinstance(parsed_trimmed_intermediate, str):
                        self.logger.debug("Trimmed JSON parse resulted in a string, attempting a second parse on this string.")
                        try:
                            final_data_to_check = json.loads(parsed_trimmed_intermediate) # Second parse
                            self.logger.debug(f"Second parse of trimmed string successful. Result type: {type(final_data_to_check)}")
                        except json.JSONDecodeError as e_double_trimmed:
                            self.logger.warning(f"Second JSON parse of trimmed string failed: {str(e_double_trimmed)}")
                            self.logger.debug(f"Trimmed string from first parse (that failed second parse, first 500 chars): {parsed_trimmed_intermediate[:500]}")
                            # Fall through to check type of final_data_to_check, which will be the string if second parse fails
                    
                    if isinstance(final_data_to_check, dict) and final_data_to_check:
                        self.logger.debug("Successfully recovered data from response with extra content.")
                        return final_data_to_check
                    elif isinstance(final_data_to_check, dict): # It's a dict but empty
                        self.logger.warning("Trimmed and potentially double-parsed JSON data resulted in an empty dictionary.")
                        return {} 
                    else: 
                        self.logger.warning(f"Trimmed and potentially double-parsed JSON data is not a dictionary (type: {type(final_data_to_check)}).")
                except json.JSONDecodeError as e2:
                    self.logger.warning(f"Failed to parse even the trimmed JSON string (up to pos {e.pos}): {str(e2)}")
            else:
                # For non-"Extra data" errors, log as error with full context
                error_pos_context = 200 # Characters before and after error position
                start_err_idx = max(0, e.pos - error_pos_context)
                end_err_idx = min(len(json_string), e.pos + error_pos_context)
                contextual_error_string = json_string[start_err_idx:end_err_idx]
                self.logger.error(f"Error decoding JSON from decrypted PulsePoint data: {str(e)} at pos {e.pos}")
                self.logger.debug(f"Problematic decrypted string segment (around pos {e.pos}, len {len(json_string)}): ...{contextual_error_string}...")
            return {}
        except Exception as e:
            self.logger.error(f"Error decrypting PulsePoint data: {str(e)}")
            if isinstance(data, dict):
                self.logger.debug(f"Raw encrypted input data keys: {list(data.keys())}")
            else:
                self.logger.debug(f"Raw encrypted input data type was {type(data)}, not a dict, when error occurred.")
            return {}

    def fetch_all_incidents_data(self) -> Optional[Dict[str, Dict]]:
        """Fetch and process incident data for all configured agencies individually."""
        self.logger.info("Fetching incident data for each agency individually...")
        
        if not AGENCIES:
            self.logger.warning("No agencies configured to fetch data for.")
            return None

        all_agencies_processed_data: Dict[str, Dict] = {}
        collection_start_time = time.monotonic()

        # Create a session to maintain cookies and establish context
        session = requests.Session()
        
        # First, visit the main site to establish a session like a browser would
        try:
            self.logger.debug("Establishing session by visiting main PulsePoint site...")
            main_site_response = session.get("https://web.pulsepoint.org/", 
                                            headers={
                                                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                                                "accept-language": "en-US,en;q=0.9",
                                                "sec-ch-ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
                                                "sec-ch-ua-mobile": "?0",
                                                "sec-ch-ua-platform": '"macOS"',
                                                "sec-fetch-dest": "document",
                                                "sec-fetch-mode": "navigate",
                                                "sec-fetch-site": "none",
                                                "upgrade-insecure-requests": "1",
                                                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"
                                            }, 
                                            timeout=REQUEST_TIMEOUT)
            main_site_response.raise_for_status()
            self.logger.debug("Successfully established session with main site")
        except Exception as e:
            self.logger.warning(f"Failed to establish session with main site: {str(e)}. Continuing anyway...")

        for agency_config in AGENCIES:
            agency_id = agency_config["id"]
            agency_name = agency_config["name"]
            url = f"{PULSEPOINT_API}?resource=incidents&agencyid={agency_id}"
            
            self.logger.debug(f"Attempting to fetch incidents for {agency_name} ({agency_id}) from URL: {url}")
            
            request_start_time = time.monotonic()
            try:
                response = session.get(url, headers=PULSEPOINT_HEADERS, timeout=REQUEST_TIMEOUT)
                response.raise_for_status()
                
                # Attempt to parse JSON, but prepare for it to potentially be a string or other non-dict
                raw_response_text = response.text
                try:
                    encrypted_agency_response = json.loads(raw_response_text)
                except json.JSONDecodeError as json_err:
                    self.logger.warning(f"Could not parse API response for {agency_name} as JSON: {json_err}. Raw text preview: {raw_response_text[:200]}")
                    # Pass the raw text if it's what the decryption expects, or an empty dict if it needs a dict.
                    # Given the previous errors, let's assume _decrypt_pulsepoint_data might expect a dict with 'ct', 'iv', 's'.
                    # If the raw text is not JSON, it's unlikely to be the correct encrypted structure.
                    encrypted_agency_response = {} # Default to empty dict to signal failure to _decrypt_pulsepoint_data's checks

                self.logger.debug(f"Raw encrypted_agency_response type for {agency_name}: {type(encrypted_agency_response)}")
                if isinstance(encrypted_agency_response, str):
                    self.logger.debug(f"Encrypted_agency_response for {agency_name} is a string (preview): {encrypted_agency_response[:200]}")
                elif isinstance(encrypted_agency_response, dict):
                    self.logger.debug(f"Encrypted_agency_response for {agency_name} is a dict (keys): {list(encrypted_agency_response.keys())}")

                self.logger.info(f"API response received for {agency_name}, attempting decryption...")
                decrypted_agency_data = self._decrypt_pulsepoint_data(encrypted_agency_response)

                if not decrypted_agency_data or not isinstance(decrypted_agency_data, dict) or not decrypted_agency_data.get("incidents"): # Check for actual content
                    self.logger.error(f"Failed to decrypt, or decrypted data is not a dictionary for agency {agency_name} ({agency_id}). Decrypted data type: {type(decrypted_agency_data)}")
                    if decrypted_agency_data:
                         self.logger.debug(f"Decrypted data (partial) for {agency_id}: {str(decrypted_agency_data)[:500]}")
                    continue # Skip to the next agency
                
                request_duration = time.monotonic() - request_start_time
                self.logger.info(f"Successfully fetched and decrypted data for {agency_name} ({agency_id}) in {request_duration:.2f} seconds.")
                
                active_incidents_raw = decrypted_agency_data.get("incidents", {}).get("active", [])
                recent_incidents_raw = decrypted_agency_data.get("incidents", {}).get("recent", [])
                
                normalized_active = self._normalize_incidents(active_incidents_raw, agency_id)
                normalized_recent = self._normalize_incidents(recent_incidents_raw, agency_id)
                
                all_agencies_processed_data[agency_id] = {
                    "active": normalized_active,
                    "recent": normalized_recent,
                    "incident_types": decrypted_agency_data.get("types", {}),
                    "status": decrypted_agency_data.get("status", {})
                }
                self.logger.debug(f"Normalized {len(normalized_active)} active and {len(normalized_recent)} recent incidents for {agency_name} ({agency_id})")
                
                # Add small delay between agency requests to be respectful to the API
                time.sleep(0.5)

            except requests.exceptions.RequestException as e:
                self.logger.error(f"Error fetching incident data for {agency_name} ({agency_id}) from {url}: {str(e)}")
                continue # Skip to the next agency
            except json.JSONDecodeError as e: # Should be caught by _decrypt_pulsepoint_data ideally, but good to have here too.
                self.logger.error(f"Error decoding JSON response for {agency_name} ({agency_id}) from API ({url}): {str(e)}")
                continue # Skip to the next agency
            except Exception as e:
                self.logger.error(f"An unexpected error occurred during fetching data for {agency_name} ({agency_id}): {str(e)}")
                continue # Skip to the next agency
        
        # Clean up session
        session.close()
        
        total_collection_duration = time.monotonic() - collection_start_time
        if not all_agencies_processed_data:
            self.logger.warning("No data was successfully fetched for any agency.")
            return None
            
        self.logger.info(f"Finished fetching data for all agencies. Total time: {total_collection_duration:.2f} seconds. Successfully processed data for {len(all_agencies_processed_data)} out of {len(AGENCIES)} agencies.")
        return all_agencies_processed_data

    @track_processing
    def _normalize_incidents(self, incidents: List[Dict], agency_id: str) -> List[Dict]:
        """Normalize incident data to a consistent format."""
        # Dispatch status mapping
        DISPATCH_STATUS_MAP = {
            "DP": "Dispatched",
            "AK": "Acknowledged",
            "ER": "Enroute",
            "OS": "On Scene",
            "TR": "Transport",
            "TA": "Transport Arrived",
            "AQ": "Available in Quarters",
            "AR": "Available on Radio",
            "AE": "Available on Scene"
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
                
                # Map incident type using the comprehensive call type system
                if "PulsePointIncidentCallType" in incident:
                    call_type = call_type_from_code(incident["PulsePointIncidentCallType"])
                    incident["incident_type"] = call_type.description
                    incident["incident_category"] = call_type.category
                    incident["incident_code"] = call_type.id
                
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
                    CRIBL_HEC_ENDPOINT,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": agency["cribl_token"]
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

    def process_agency(self, agency: Dict, incidents_data: Optional[Dict]) -> bool:
        """Process incidents for a single agency using pre-fetched data."""
        with timing_context("process_agency", agency_id=agency["id"]):
            self.logger.info(f"Processing incidents for {agency['name']} ({agency['id']})")
            
            if not incidents_data:
                self.logger.error(f"No incident data provided for {agency['name']}. Skipping processing.")
                return False
            
            active_incidents = [
                incident for incident in incidents_data.get("active", [])
                if "ClosedDateTime" not in incident or not incident["ClosedDateTime"]
            ]
            self.metrics.total_incidents += len(active_incidents)
            
            if not active_incidents:
                self.logger.info(f"No active incidents found for {agency['name']} after filtering.")
                return True
            
            self.logger.info(f"Found {len(active_incidents)} active incidents to process for {agency['name']}")
            
            success = True
            for i, incident in enumerate(active_incidents):
                # Add UTC timestamp to incident data
                incident["_time"] = datetime.now(timezone.utc).isoformat()
                incident["_source"] = "pulsepoint"
                incident["agency_name"] = agency["name"]
                
                # (No Google Maps reporting)
                
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
        self.logger.info("Starting PulsePoint data collection with new API.")
        
        try:
            if METRICS_ENABLED:
                log_system_metrics()
            
            all_incidents_by_agency = self.fetch_all_incidents_data()

            if not all_incidents_by_agency:
                self.logger.error("Failed to fetch any incident data from the new API. Collector will exit.")
                self._log_metrics()
                return 1
            
            waze_feed_active_incidents = []

            with ThreadPoolExecutor(max_workers=len(AGENCIES)) as executor:
                future_to_agency = {}
                for agency_obj in AGENCIES:
                    agency_data = all_incidents_by_agency.get(agency_obj["id"])
                    if agency_data:
                        future_to_agency[executor.submit(self.process_agency, agency_obj, agency_data)] = agency_obj
                    else:
                        self.logger.warning(f"No data found for agency {agency_obj['name']} ({agency_obj['id']}) in bulk fetch result. It will not be processed.")

                for future in as_completed(future_to_agency):
                    agency_from_future = future_to_agency[future]
                    try:
                        success = future.result()
                        if not success:
                            self.logger.error(f"Failed to process {agency_from_future['name']}")
                        else:
                            agency_processed_data = all_incidents_by_agency.get(agency_from_future["id"])
                            if agency_processed_data and "active" in agency_processed_data:
                                current_agency_active_incidents = [
                                    inc for inc in agency_processed_data["active"]
                                    if "ClosedDateTime" not in inc or not inc["ClosedDateTime"]
                                ]
                                waze_feed_active_incidents.extend(current_agency_active_incidents)
                    except Exception as e:
                        self.logger.error(f"Error processing agency {agency_from_future['name']} in thread: {str(e)}")
            
            if METRICS_ENABLED:
                log_system_metrics()
            
            self._log_metrics()
            
            if waze_feed_active_incidents:
                self.logger.info(f"Generating Waze feed with {len(waze_feed_active_incidents)} active incidents.")
                generate_waze_feed(waze_feed_active_incidents)
            else:
                self.logger.info("No active incidents to generate Waze feed for.")
            
            return 0
            
        except Exception as e:
            self.logger.error(f"Fatal error in main process: {str(e)}")
            self._log_metrics()
            return 1

if __name__ == "__main__":
    collector = PulsePointCollector()
    exit_code = collector.run()
    exit(exit_code) 