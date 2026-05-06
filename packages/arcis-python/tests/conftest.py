"""
Pytest configuration and shared fixtures.
"""



# Configure pytest-asyncio mode
def pytest_configure(config):
    """Configure pytest."""
    config.addinivalue_line(
        "markers", "asyncio: mark test as async"
    )
