#!/usr/bin/env python3
"""
✅ DEMO FILE - Shows SAFE Python patterns
This file demonstrates the correct way to handle secrets
"""

import os
from typing import Optional

# ✅ GOOD: Read from environment variable
API_KEY = os.environ.get("API_KEY")

# ✅ GOOD: Using os.getenv
api_key = os.getenv("API_KEY", "")

# ✅ GOOD: Checking for presence without logging value
if not API_KEY:
    print("Warning: API_KEY is not set")  # Safe - doesn't print the value
else:
    print("API_KEY is configured")  # Safe - just confirms it exists

# ✅ GOOD: Type-safe environment access
def get_api_key() -> Optional[str]:
    """Safely retrieve API key from environment."""
    return os.environ.get("API_KEY")

# ✅ GOOD: Using the secret without exposing it
def make_request(url: str) -> dict:
    """Make an authenticated request."""
    import requests
    
    key = get_api_key()
    if not key:
        raise ValueError("API_KEY environment variable is required")
    
    headers = {"Authorization": f"Bearer {key}"}
    response = requests.get(url, headers=headers)
    return response.json()

# ✅ GOOD: Masking in debug output
def debug_config():
    """Print configuration with masked secrets."""
    key = get_api_key()
    masked = f"{key[:4]}...{key[-4:]}" if key and len(key) > 8 else "[not set]"
    print(f"API_KEY: {masked}")  # Safe - value is masked
