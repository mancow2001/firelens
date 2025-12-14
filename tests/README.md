# Unit Tests for FireLens Monitor

This directory contains unit tests for the FireLens Monitor v1.0.0.

## Test Files

### test_database.py
Tests database performance optimizations:
- **Connection pooling**: Validates that connections are reused from pool
- **Batch queries**: Tests N+1 query fixes for interface metrics
- **Database indexes**: Verifies that performance indexes are created
- **Latest interface summary**: Tests batch query for dashboard overview

### test_memory_leaks.py
Tests memory leak fixes:
- **Deque with maxlen**: Validates automatic size limiting
- **Queue size limits**: Tests that queues don't grow unbounded
- **Session cleanup**: Verifies requests.Session is properly closed
- **Garbage collection**: Tests GC integration
- **Memory monitoring**: Validates psutil integration

### test_web_dashboard.py
Tests web dashboard caching and health endpoint:
- **SimpleCache**: Tests TTL-based caching implementation
- **Cache expiration**: Validates entries expire after TTL
- **Health endpoint**: Tests health check data structure
- **Status determination**: Tests healthy/warning/critical logic

### test_collectors.py
Tests collector queue limits and cleanup:
- **Queue maxsize**: Validates queue size limits
- **Overflow handling**: Tests behavior when queue is full
- **Collector cleanup**: Tests session cleanup on stop
- **Thread management**: Tests daemon threads and timeouts

### test_vendors.py
Tests multi-vendor support framework:
- **Vendor registry**: Tests adapter loading
- **Palo Alto adapter**: Tests PAN-OS API integration
- **Fortinet adapter**: Tests FortiGate REST API (authentication, metrics, interfaces)
- **Cisco Firepower**: Tests placeholder implementation

### test_config.py
Tests configuration management:
- **Save/load round-trips**: Validates YAML persistence
- **Multiple firewall configs**: Tests multi-firewall support
- **Admin config persistence**: Tests admin panel settings
- **Validation**: Tests firewall config validation

### test_certificates.py
Tests CA certificate management:
- **Certificate upload**: Tests PEM file handling
- **Certificate validation**: Tests expiry and format checks
- **Certificate storage**: Tests persistence

## Running Tests

### Setup Virtual Environment
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -e ".[test]"
```

### Run All Tests
```bash
# From project root
pytest tests/

# With verbose output
pytest tests/ -v

# With coverage
pytest tests/ --cov=firelens --cov-report=html
```

### Run Specific Test Files
```bash
# Database tests only
pytest tests/test_database.py -v

# Memory leak tests only
pytest tests/test_memory_leaks.py -v

# Web dashboard tests only
pytest tests/test_web_dashboard.py -v

# Collector tests only
pytest tests/test_collectors.py -v

# Vendor tests only
pytest tests/test_vendors.py -v
```

### Run Specific Test Classes or Methods
```bash
# Run specific test class
pytest tests/test_database.py::TestDatabaseConnectionPooling -v

# Run specific test method
pytest tests/test_database.py::TestDatabaseConnectionPooling::test_connection_reuse -v
```

## Test Coverage

The tests cover the following areas:

### Memory Leak Prevention
- Deque with maxlen instead of unbounded lists
- Queue with maxsize to prevent unbounded growth
- Connection pooling to prevent connection leaks
- Requests.Session cleanup
- Periodic garbage collection

### Query Optimizations
- Batch query for interface metrics (N+1 fix)
- Latest interface summary batch query (dashboard N+1 fix)
- Database indexes for common query patterns
- Partial indexes for recent data

### Performance Enhancements
- Dashboard caching with TTL
- Health check endpoint
- Memory monitoring

### Multi-Vendor Support
- Vendor adapter loading and registry
- Palo Alto PAN-OS API
- Fortinet FortiGate REST API
- Cisco Firepower placeholder

## Expected Test Results

All 218 tests should pass:

```
======================== 218 passed in ~9s ========================
```

## Continuous Integration

Tests run automatically on:
- Push to main/develop branches
- Pull requests to main
- Python versions: 3.9, 3.10, 3.11, 3.12, 3.13

## Troubleshooting

### Import Errors
If you get import errors, ensure you're running from the project root:
```bash
cd /path/to/FireLens
pytest tests/
```

### Missing Dependencies
Install test dependencies:
```bash
pip install -e ".[test]"
```

### Database Lock Errors
Tests create temporary databases. If you see lock errors:
```bash
# Kill any hanging Python processes
pkill -9 python

# Run tests again
pytest tests/
```
