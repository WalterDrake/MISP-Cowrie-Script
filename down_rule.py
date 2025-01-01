import subprocess
import json
import os
from key import misp_url, misp_key

# Exclude specific event IDs
EXCLUDED_IDS = [5]

# Define constants
MISP_URL = misp_url
AUTH_HEADER = misp_key  

def get_event_ids():
    """Fetch all event IDs from MISP."""
    command = [
        "/usr/bin/curl",
        "--insecure",
        "-H", f"Authorization: {AUTH_HEADER}",
        "-H", "Accept: application/json",
        "-H", "Content-type: application/json",
        f"{MISP_URL}/events/"
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    events = json.loads(result.stdout)
    event_ids = [event['id'] for event in events if int(event['id']) not in EXCLUDED_IDS]
    return event_ids

def get_event_rules(event_id):
    """Fetch Snort rules for a specific event ID."""
    data = json.dumps({"eventid": event_id, "returnFormat": "snort"})
    command = [
        "/usr/bin/curl",
        "--insecure",
        "-d", data,
        "-H", f"Authorization: {AUTH_HEADER}",
        "-H", "Accept: application/json",
        "-H", "Content-type: application/json",
        "-X", "POST",
        f"{MISP_URL}/events/restSearch"
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    return result.stdout

def save_event_rule(event_id, rule_content):
    """Save Snort rule content to a file named after the event ID."""
    filename = f"/usr/local/etc/snort/rules/misp_rules_beta/{event_id}.rules"
    with open(filename, "w") as file:
        file.write(rule_content)
    print(f"Saved Snort rule to {filename}")
    return filename

if __name__ == "__main__":
    try:
        # Step 1: Get event IDs
        event_ids = get_event_ids()
        print(f"Retrieved event IDs: {event_ids}")
        
        # Step 2: Fetch rules and save to files
        for event_id in event_ids:
            print(f"Fetching rules for event ID: {event_id}")
            rule_content = get_event_rules(event_id)
            file_name = save_event_rule(event_id, rule_content)
            file_name_new = f"/usr/local/etc/snort/rules/misp_rules_beta/{event_id}_new.rules"
            command = [
              "/usr/bin/python3",
              "preprocess.py",
              f"{file_name}",
              f"{file_name_new}"
            ]   
            subprocess.run(command, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error occurred: {e.stderr}")
    except Exception as e:
        print(f"Unexpected error: {e}")
