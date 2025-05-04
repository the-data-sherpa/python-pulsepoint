import logging
import time
import json
import psutil
from functools import wraps
from contextlib import contextmanager
from datetime import datetime, timezone

# Set up metrics logger
metrics_logger = logging.getLogger('pulsepoint_metrics')
metrics_logger.setLevel(logging.INFO)

# Create file handler
file_handler = logging.FileHandler('pulsepoint_metrics.log')
file_handler.setLevel(logging.INFO)

# Create formatter
formatter = logging.Formatter('%(asctime)s - %(message)s')
file_handler.setFormatter(formatter)

# Add handler to logger
metrics_logger.addHandler(file_handler)

def log_metric(metric_type, value, **tags):
    """Log a metric with its associated tags."""
    metric = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "metric_type": metric_type,
        "value": value
    }
    metric.update(tags)
    metrics_logger.info(json.dumps(metric))

def log_system_metrics():
    """Log system-level metrics."""
    process = psutil.Process()
    with process.oneshot():
        log_metric(
            metric_type="system_cpu_percent",
            value=process.cpu_percent(),
            metric_unit="percent"
        )
        log_metric(
            metric_type="system_memory_usage",
            value=process.memory_info().rss / 1024 / 1024,  # Convert to MB
            metric_unit="MB"
        )
        log_metric(
            metric_type="system_thread_count",
            value=process.num_threads()
        )

@contextmanager
def timing_context(operation_name, **tags):
    """Context manager for timing operations."""
    start_time = time.perf_counter()
    try:
        yield
    finally:
        duration = (time.perf_counter() - start_time) * 1000  # Convert to milliseconds
        log_metric(
            metric_type="duration",
            value=duration,
            operation=operation_name,
            metric_unit="ms",
            **tags
        )

def track_timing(func):
    """Decorator to track function execution time."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        with timing_context(func.__name__):
            return func(*args, **kwargs)
    return wrapper

def track_api_call(agency_id):
    """Decorator to track API call metrics."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                status = "success"
                # Log response size if available
                if hasattr(result, 'content'):
                    log_metric(
                        metric_type="api_response_size",
                        value=len(result.content),
                        agency_id=agency_id,
                        metric_unit="bytes"
                    )
            except Exception as e:
                status = "failure"
                error_type = type(e).__name__
                log_metric(
                    metric_type="api_error",
                    value=1,
                    agency_id=agency_id,
                    error_type=error_type,
                    error_message=str(e)
                )
                raise
            finally:
                duration = (time.perf_counter() - start_time) * 1000
                log_metric(
                    metric_type="api_response_time",
                    value=duration,
                    agency_id=agency_id,
                    status=status,
                    metric_unit="ms"
                )
            return result
        return wrapper
    return decorator

def track_processing(func):
    """Decorator to track incident processing metrics."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        try:
            result = func(*args, **kwargs)
            if result:  # Assuming result contains processed incidents
                incident_count = len(result) if hasattr(result, '__len__') else 1
                log_metric(
                    metric_type="incidents_processed",
                    value=incident_count,
                    status="success"
                )
                # Log processing rate
                duration = (time.perf_counter() - start_time) * 1000
                if duration > 0:
                    log_metric(
                        metric_type="processing_rate",
                        value=incident_count / (duration / 1000),  # incidents per second
                        metric_unit="incidents/second"
                    )
            status = "success"
        except Exception as e:
            status = "failure"
            log_metric(
                metric_type="processing_error",
                value=1,
                error_type=type(e).__name__,
                error_message=str(e)
            )
            raise
        finally:
            duration = (time.perf_counter() - start_time) * 1000
            log_metric(
                metric_type="processing_time",
                value=duration,
                status=status,
                metric_unit="ms"
            )
        return result
    return wrapper

def track_splunk_post(func):
    """Decorator to track Splunk HEC posting metrics."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        try:
            result = func(*args, **kwargs)
            status = "success"
            log_metric(
                metric_type="splunk_post",
                value=1,
                status="success"
            )
            # Log payload size if available
            if 'data' in kwargs:
                log_metric(
                    metric_type="splunk_payload_size",
                    value=len(str(kwargs['data'])),
                    metric_unit="bytes"
                )
        except Exception as e:
            status = "failure"
            log_metric(
                metric_type="splunk_post",
                value=1,
                status="failure",
                error_type=type(e).__name__,
                error_message=str(e)
            )
            raise
        finally:
            duration = (time.perf_counter() - start_time) * 1000
            log_metric(
                metric_type="splunk_post_time",
                value=duration,
                status=status,
                metric_unit="ms"
            )
        return result
    return wrapper

def track_retry(func):
    """Decorator to track retry attempts."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        retry_count = 0
        while True:
            try:
                result = func(*args, **kwargs)
                if retry_count > 0:
                    log_metric(
                        metric_type="retry_success",
                        value=retry_count,
                        operation=func.__name__
                    )
                return result
            except Exception as e:
                retry_count += 1
                log_metric(
                    metric_type="retry_attempt",
                    value=retry_count,
                    operation=func.__name__,
                    error_type=type(e).__name__
                )
                if retry_count >= kwargs.get('max_retries', 3):
                    raise
    return wrapper 