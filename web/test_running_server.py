import requests
import json

print("=== TESTING REAL RUNNING SERVER ON PORT 8089 ===")

# 1. Test Endpoint Verification on running server
try:
    r = requests.post("http://localhost:8089/api/scan/21/verify/endpoint", json={"url": "https://dev.greatdayhr.co/_/pagebuilder/"}, timeout=5)
    print("Endpoint verify status:", r.status_code)
    print("Response:", r.text)
except Exception as e:
    print("Endpoint verify failed:", e)

# 2. Test Google API on running server
try:
    r = requests.post("http://localhost:8089/api/scan/21/verify/google-api", json={"key": "AIzaSyD5mtIjIXVymRBZFB2kZxlYA8SlHtco--c"}, timeout=5)
    print("\nGoogle API verify status:", r.status_code)
    print("Response:", r.text)
except Exception as e:
    print("Google API verify failed:", e)

# 3. Test Firebase on running server
try:
    r = requests.post("http://localhost:8089/api/scan/21/verify/firebase", json={"url": "https://greatday-7e013.firebaseio.com"}, timeout=5)
    print("\nFirebase verify status:", r.status_code)
    print("Response:", r.text)
except Exception as e:
    print("Firebase verify failed:", e)
