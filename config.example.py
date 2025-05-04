# API Endpoints
SPLUNK_ENDPOINT = "YOUR_SPLUNK_HEC_ENDPOINT"  # Example: "https://your-splunk-instance:8088/services/collector"
PULSEPOINT_API = "https://web.pulsepoint.org/DB/giba.php"  # PulsePoint API endpoint

# Agency Configuration
AGENCIES = [
    {
        "id": "YOUR_AGENCY_ID",  # Example: "EMS1234"
        "name": "YOUR_AGENCY_NAME",  # Example: "County EMS"
        "splunk_token": "YOUR_SPLUNK_TOKEN"  # Example: "Splunk xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    }
]

# Timing Configuration
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds
POST_DELAY = 5   # seconds between posts
REQUEST_TIMEOUT = 30  # seconds

# Logging Configuration
LOG_FILE = "pulsepoint.log"
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
LOG_LEVEL = "INFO"

# Debug Configuration
ENABLE_DEBUG_LOGGING = False  # Set to True to enable detailed debug logging
DEBUG_LOG_FORMAT = "%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s"  # More detailed format

# Metrics Configuration
METRICS_ENABLED = True  # Enable/disable metrics collection
METRICS_LOG_FILE = "pulsepoint_metrics.log"  # Separate file for metrics
METRICS_FORMAT = "%(asctime)s - %(message)s"  # Format for metrics logging 