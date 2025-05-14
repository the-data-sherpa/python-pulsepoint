# python-pulsepoint

A Python-based system for collecting and processing PulsePoint incident data, designed to run on Cribl Edge nodes.

## Overview

This system collects active incidents from the PulsePoint API, processes them, and forwards them to a Cribl Stream HEC endpoint for further processing and social media integration.

## Features

- Active incident collection from PulsePoint API
- Support for multiple agencies
- Human-readable incident types and dispatch statuses
- Robust error handling and retry logic
- Detailed logging with debug capabilities
- Efficient processing without unnecessary delays
- Comprehensive metrics collection:
  - API performance metrics
  - Processing duration and rates
  - System resource usage
  - Success/failure tracking
  - Retry attempt monitoring

## Prerequisites

- Python 3.7+
- Access to PulsePoint API
- Cribl Edge node
- Cribl Stream instance with HEC endpoint
- IFTTT account (for social media integration)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/the-data-sherpa/python-pulsepoint.git
   cd python-pulsepoint
   ```

2. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Create configuration file:
   ```bash
   cp config.example.py config.py
   ```

4. Edit `config.py` with your settings:
   - Set your Cribl HEC endpoint
   - Configure your agencies
   - Add your Cribl tokens
   - Adjust timing settings if needed
   - Configure metrics and logging settings

## Configuration

### Required Settings

1. Cribl HEC Endpoint:
   ```python
   CRIBL_HEC_ENDPOINT = "https://your-Cribl-instance:8088/services/collector"
   ```

2. Agency Configuration:
   ```python
   AGENCIES = [
       {
           "id": "EMS1234",  # Your agency ID
           "name": "County EMS",  # Your agency name
           "cribl_token": "Splunk xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"  # Your Cribl token
       }
   ]
   ```

### Optional Settings

- `MAX_RETRIES`: Number of retry attempts for failed requests (default: 3)
- `RETRY_DELAY`: Delay between retries in seconds (default: 5)
- `REQUEST_TIMEOUT`: API request timeout in seconds (default: 30)
- `ENABLE_DEBUG_LOGGING`: Enable detailed debug logging (default: False)
- `METRICS_ENABLED`: Enable metrics collection (default: True)

## Usage

Run the collector:
```bash
python pulsepoint_collector.py
```

## Logging

- Main log file: `pulsepoint.log`
- Metrics log file: `pulsepoint_metrics.log`
- Debug logging can be enabled in `config.py`
- Log format is configurable for both standard and debug logging

## Metrics

The system collects comprehensive metrics including:

### API Metrics
- Response times
- Response sizes
- Error rates
- Agency-specific performance

### Processing Metrics
- Processing duration
- Processing rates
- Incident counts
- Error tracking

### System Metrics
- CPU usage
- Memory usage
- Thread count
- Resource utilization

### Cribl Metrics
- Post success rates
- Payload sizes
- Post duration
- Error tracking

## Security Notes

1. Never commit `config.py` to version control
2. Keep your Cribl tokens secure
3. Use environment variables for sensitive values in production
4. Regularly rotate API keys and tokens
5. Metrics logs may contain sensitive information - ensure proper access controls

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

[Your License Here]

## Support

[Your Support Information]
