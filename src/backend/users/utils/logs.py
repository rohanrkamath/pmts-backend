import requests
from datetime import datetime

LOGGING_SERVICE_URL = "http://logging_service:8000/log/" # change port according to the docker compose file

def log_change(service, location, modified_by, original_data, updated_data, log_text):
    log_entry = {
        "service": service,
        "location": location, # the location of change (ID)
        "modified_by": modified_by,
        "original_data": original_data,
        "updated_data": updated_data,
        "log_text": log_text,
        "created_at": datetime.utcnow()
    }

    response = requests.post(LOGGING_SERVICE_URL, json=log_entry)
    if response.status_code != 200:
        print(f"Failed to log change: {response.text}")
