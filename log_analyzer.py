# Simple Log Analysis Tool
import re

def analyze_logs(file_path):
    suspicious_ips = {}
    failed_logins = 0

    with open(file_path, 'r') as file:
        for line in file:
            # Example: Identify failed login attempts
            if "failed login" in line.lower():
                failed_logins += 1
                # Extract IP address (assuming logs contain IPs)
                ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                if ip_match:
                    ip = ip_match.group()
                    suspicious_ips[ip] = suspicious_ips.get(ip, 0) + 1

    return suspicious_ips, failed_logins


def save_report(suspicious_ips, failed_logins, output_file):
    with open(output_file, 'w') as file:
        file.write(f"Total failed logins: {failed_logins}\n")
        file.write("Suspicious IPs:\n")
        for ip, count in suspicious_ips.items():
            file.write(f"{ip}: {count} occurrences\n")


# Main Program
if __name__ == "__main__":
    log_file = input("Enter the path to the log file: ")
    output_file = "analysis_report.txt"

    try:
        suspicious_ips, failed_logins = analyze_logs(log_file)
        save_report(suspicious_ips, failed_logins, output_file)
        print(f"Analysis complete. Report saved to {output_file}.")
    except FileNotFoundError:
        print("Log file not found. Please check the file path.")


    
