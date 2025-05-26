import requests
import json
from datetime import datetime, timezone


def clean_for_splunk(data):
    def flatten(value):
        if isinstance(value, list):
            # Recursively clean each item in the list
            return [flatten(v) for v in value if v is not None]
        elif isinstance(value, dict):
            return {k: flatten(v) for k, v in value.items()}
        elif isinstance(value, bool):
            return int(value)
        elif isinstance(value, datetime):
            return value.strftime("%Y-%m-%dT%H:%M:%S")
        elif value is None:
            return ""
        else:
            return str(value)
    
    cleaned = flatten(data)
    return cleaned

def send_to_splunk(data):
    data = clean_for_splunk(data)
    payload = {
        "event": data,
        "sourcetype": "_json",
        "index": "main",
        "time": datetime.now(timezone.utc).timestamp() 
    }
    response = requests.post(SPLUNK_HEC_URL, headers=HEADERS, data=json.dumps(payload), timeout=3)
    return response

def get_splunk_token(file_path='splunk_token.txt'):
    try:
        with open(file_path, 'r') as f:
            token = f.read().strip()
        return token
    except FileNotFoundError:
        print(f"Error: Token file not found at {file_path}")
        return None

# Assign Splunk Variables
# Set to Splunk running on localhost, however recommended to encrypt with SSL if running on a different host
SPLUNK_HEC_URL = "http://localhost:8088/services/collector/event"
SPLUNK_TOKEN = get_splunk_token()
HEADERS = {
    "Authorization": f"Splunk {SPLUNK_TOKEN}"
}