import os
import json

# azhlm
# 31 December 2024
# Ver. 1.0

def extract_ip(folder):
    result = set()
    for filename in os.listdir(folder):
        if filename.startswith('cowrie.json'):
            print(f"[!] Reading file name {filename}")
            with open(os.path.join(folder, filename), 'r') as file:
                for line in file:
                    try:
                        log = json.loads(line)
                        if 'cowrie.session.connect' in log['eventid']:
                            result.add(log['src_ip'])
                    except json.JSONDecodeError:
                        pass 
    return result
    
# Cowrie JSON Log Parser
# Josh Jobe
# 3 Mar 2024
# Ver. 1.0

def search_logs_by_source_ip(source_ip, folder):
    results = []
    for filename in os.listdir(folder):
        if filename.startswith('cowrie.json.'):
            with open(os.path.join(folder, filename), 'r') as file:
                for line in file:
                    try:
                        log = json.loads(line)
                        if 'src_ip' in log and log['src_ip'] == source_ip:
                            results.append(log)
                    except json.JSONDecodeError:
                        pass
    return results

def search_logs_by_session_id(session_id, folder):
    results = []
    for filename in os.listdir(folder):
        if filename.startswith('cowrie.json.'):
            with open(os.path.join(folder, filename), 'r') as file:
                for line in file:
                    try:
                        log = json.loads(line)
                        if 'session' in log and log['session'] == session_id:
                            results.append(log)
                    except json.JSONDecodeError:
                        pass
    return results

def format_log_entry(log):
    formatted_log = f"Event ID: {log['eventid']}\n"
    formatted_log += f"Timestamp: {log['timestamp']}\n"
    formatted_log += f"Source IP: {log['src_ip']}\n"
    formatted_log += f"Session ID: {log['session']}\n"
    if 'username' in log:
        formatted_log += f"Username: {log['username']}\n"
    if 'password' in log:
        formatted_log += f"Password: {log['password']}\n"
    if 'input' in log:
        formatted_log += f"Command Input: {log['input']}\n"
    if 'outfile' in log:
        formatted_log += f"File Outfile: {log['outfile']}\n"
    if 'filename' in log:
        formatted_log += f"Uploaded File: {log['filename']}\n"
    if 'hassh' in log:
        formatted_log += f"Client SSH Fingerprint: {log['hassh']}\n"
    formatted_log += "\n"
    return formatted_log

def main():
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    folder = "/home/cowrie/cowrie/var/log/cowrie"
    folder_path = os.path.join(script_dir, folder)
    if not os.path.isdir(folder_path):
        print("Folder not found.")
        return
    
    ip_list = extract_ip(folder_path)
    
    # Generate Snort 3 rules
    rule_template = 'drop ip [{}] any -> $HOME_NET any (msg:"Blocked source IP"; rev:1;)'
    rules = rule_template.format(",".join(ip_list))

    # Save to a file or print the rule
    try:
        with open("/usr/local/etc/snort/rules/block_ips.rules", "w") as file:
            file.write(rules + "\n")
        print("[!] Successfully created rule file.")
        print("[!] Rule:",rules)
    except Exception as e:
        print("[*] Got error:", e)

if __name__ == "__main__":
    main()
