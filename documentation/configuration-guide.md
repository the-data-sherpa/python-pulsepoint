# PulsePoint Data Collection System - Configuration Guide

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Configuration Reference](#configuration-reference)
4. [Best Practices](#best-practices)
5. [Troubleshooting](#troubleshooting)
6. [Deployment Scenarios](#deployment-scenarios)
7. [Maintenance](#maintenance)

## Prerequisites

### System Requirements
- Python 3.7 or higher
- Access to PulsePoint API
- Cribl Edge node
- Cribl Stream instance with HEC endpoint
- IFTTT account (for social media integration)

### Network Requirements
- Outbound access to PulsePoint API (https://web.pulsepoint.org)
- Outbound access to Cribl Stream HEC endpoint
- Outbound access to IFTTT (if using social media integration)

### Security Requirements
- Valid PulsePoint API credentials
- Valid Cribl Stream HEC tokens
- Valid IFTTT webhook keys (if using social media integration)

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/the-data-sherpa/python-pulsepoint.git
cd python-pulsepoint
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Create Configuration File
```bash
cp config.example.py config.py
```

### 4. Configure Environment
1. Edit `config.py` with your settings
2. Set up environment variables (optional)
3. Configure logging directory
4. Set up metrics collection

## Configuration Reference

### Required Settings

#### Cribl Stream HEC Endpoint
```python
CRIBL_HEC_ENDPOINT = "https://your-cribl-instance:8088/services/collector"
```
- **Type**: String (URL)
- **Format**: HTTPS URL
- **Example**: `https://cribl.example.com:8088/services/collector`
- **Notes**: Must be a valid HTTPS endpoint

#### Agency Configuration
```python
AGENCIES = [
    {
        "id": "YOUR_AGENCY_ID",
        "name": "YOUR_AGENCY_NAME",
        "cribl_token": "YOUR_CRIBL_TOKEN"
    }
]
```
- **Type**: List of dictionaries
- **Required Fields**:
  - `id`: Agency identifier
  - `name`: Agency display name
  - `cribl_token`: Cribl Stream HEC token
- **Format**: 
  - `id`: String
  - `name`: String
  - `cribl_token`: String (format: "Cribl xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")

### Optional Settings

#### Timing Configuration
```python
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds
POST_DELAY = 5   # seconds
REQUEST_TIMEOUT = 30  # seconds
```
- **MAX_RETRIES**: Number of retry attempts (default: 3)
- **RETRY_DELAY**: Delay between retries in seconds (default: 5)
- **POST_DELAY**: Delay between posts in seconds (default: 5)
- **REQUEST_TIMEOUT**: API request timeout in seconds (default: 30)

#### Logging Configuration
```python
LOG_FILE = "pulsepoint.log"
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
LOG_LEVEL = "INFO"
ENABLE_DEBUG_LOGGING = False
DEBUG_LOG_FORMAT = "%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s"
```
- **LOG_FILE**: Main log file path
- **LOG_FORMAT**: Standard log message format
- **LOG_LEVEL**: Logging level (INFO, DEBUG, WARNING, ERROR)
- **ENABLE_DEBUG_LOGGING**: Toggle detailed debug logging
- **DEBUG_LOG_FORMAT**: Format for debug logs

#### Metrics Configuration
```python
METRICS_ENABLED = True
METRICS_LOG_FILE = "pulsepoint_metrics.log"
METRICS_FORMAT = "%(asctime)s - %(message)s"
```
- **METRICS_ENABLED**: Toggle metrics collection
- **METRICS_LOG_FILE**: Metrics log file path
- **METRICS_FORMAT**: Format for metrics logs

## Best Practices

### Security
1. **Token Management**
   - Never commit `config.py` to version control
   - Use environment variables for sensitive values
   - Regularly rotate API keys and tokens
   - Use separate tokens for development and production

2. **File Permissions**
   - Restrict access to configuration files
   - Set appropriate file permissions (600 for config files)
   - Use secure directory for log files

3. **Network Security**
   - Use HTTPS for all endpoints
   - Implement proper firewall rules
   - Monitor API access patterns

### Performance
1. **Resource Optimization**
   - Adjust `POST_DELAY` based on system capacity
   - Monitor memory usage with metrics
   - Configure appropriate log rotation

2. **Error Handling**
   - Set appropriate `MAX_RETRIES` and `RETRY_DELAY`
   - Monitor error rates
   - Implement proper alerting

### Logging
1. **Log Management**
   - Enable debug logging only when needed
   - Implement log rotation
   - Monitor log file sizes
   - Use structured logging for better analysis

2. **Metrics Collection**
   - Enable metrics for production
   - Monitor system resources
   - Track API performance
   - Set up alerts for anomalies

## Troubleshooting

### Common Issues

1. **Configuration Validation**
   ```python
   # Check configuration file syntax
   python -m py_compile config.py
   
   # Validate required settings
   python validate_config.py
   ```

2. **API Connection Issues**
   - Verify network connectivity
   - Check API credentials
   - Validate endpoint URLs
   - Check firewall rules

3. **Logging Problems**
   - Verify log directory permissions
   - Check disk space
   - Validate log format
   - Test debug logging

4. **Performance Issues**
   - Monitor system resources
   - Check API response times
   - Review retry settings
   - Analyze metrics

### Debug Procedures

1. **Enable Debug Logging**
   ```python
   ENABLE_DEBUG_LOGGING = True
   ```

2. **Check Log Files**
   ```bash
   tail -f pulsepoint.log
   tail -f pulsepoint_metrics.log
   ```

3. **Validate Configuration**
   ```bash
   python validate_config.py
   ```

## Deployment Scenarios

### Single Agency Setup
```python
AGENCIES = [
    {
        "id": "EMS1234",
        "name": "County EMS",
        "cribl_token": "Cribl xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    }
]
```

### Multi-Agency Configuration
```python
AGENCIES = [
    {
        "id": "EMS1234",
        "name": "County EMS",
        "cribl_token": "Cribl xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    },
    {
        "id": "EMS5678",
        "name": "City EMS",
        "cribl_token": "Cribl yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
    }
]
```

### Development vs. Production
1. **Development**
   ```python
   ENABLE_DEBUG_LOGGING = True
   LOG_LEVEL = "DEBUG"
   METRICS_ENABLED = True
   ```

2. **Production**
   ```python
   ENABLE_DEBUG_LOGGING = False
   LOG_LEVEL = "INFO"
   METRICS_ENABLED = True
   ```

### High-Availability Configuration
1. **Multiple Instances**
   - Use different log files
   - Configure separate metrics
   - Set appropriate delays

2. **Load Balancing**
   - Distribute agencies across instances
   - Monitor system resources
   - Implement proper error handling

## Maintenance

### Configuration Backup
1. **Regular Backups**
   ```bash
   # Backup configuration
   cp config.py config.py.backup
   
   # Backup logs
   tar -czf logs_backup.tar.gz *.log
   ```

2. **Version Control**
   - Keep `config.example.py` in version control
   - Document configuration changes
   - Maintain change history

### Update Procedures
1. **Configuration Updates**
   - Review changes in `config.example.py`
   - Update `config.py` accordingly
   - Validate new configuration
   - Test in development first

2. **System Updates**
   - Update Python packages
   - Check compatibility
   - Test new features
   - Monitor performance

### Migration Guide
1. **Version Migration**
   - Review release notes
   - Check configuration changes
   - Update configuration file
   - Test new features

2. **Environment Migration**
   - Export current configuration
   - Update endpoints and tokens
   - Validate new environment
   - Test functionality

### Version Compatibility
- Python 3.7+ required
- Check package compatibility
- Review API changes
- Test new features

## Support

### Getting Help
- Check documentation
- Review logs
- Contact support
- Submit issues

### Reporting Problems
1. **Gather Information**
   - Configuration details
   - Log files
   - Error messages
   - System information

2. **Submit Issue**
   - Use issue template
   - Provide details
   - Include logs
   - Describe steps to reproduce 