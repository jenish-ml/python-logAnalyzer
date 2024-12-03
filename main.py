import re
import csv
from collections import Counter

# Configuration
LOG_FILE = 'sample.log'
OUTPUT_FILE = 'log_analysis_results.csv'

def parse_log_file(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs

def analyze_logs(logs):
    ip_counter = Counter()
    endpoint_counter = Counter()
    failed_logins = Counter()

    # Extract IP address, endpoint, and failed login attempts
    for log in logs:
        ip_match = re.search(r'^(\d+\.\d+\.\d+\.\d+)', log)
        if ip_match:
            ip = ip_match.group(1)
            ip_counter[ip] += 1

        endpoint_match = re.search(r'\"[A-Z]+\s([/\w.-]+)\sHTTP', log)
        if endpoint_match:
            endpoint = endpoint_match.group(1)
            endpoint_counter[endpoint] += 1

        if '401' in log or 'Invalid credentials' in log:
            if ip_match:
                failed_logins[ip] += 1

    print(failed_logins)
    return ip_counter, endpoint_counter, failed_logins

def save_to_csv(ip_counter, most_accessed_endpoint, failed_logins, file_name):
    with open(file_name, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP
        writer.writerow(['Requests per IP'])
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_counter.most_common():
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow(most_accessed_endpoint)

        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(['Suspicious Activity'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in failed_logins.items():
            writer.writerow([ip, count])

def main():
    # Parse log file
    logs = parse_log_file(LOG_FILE)

    # Analyze logs
    ip_counter, endpoint_counter, failed_logins = analyze_logs(logs)

    # Determine most accessed endpoint
    most_accessed_endpoint = endpoint_counter.most_common(1)[0]

    # Save results to CSV
    save_to_csv(ip_counter, most_accessed_endpoint, failed_logins, OUTPUT_FILE)

    # Display Results
    print("\nRequests per IP Address:")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    for ip, count in ip_counter.most_common():
        print(f"{ip:<20} {count:<15}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20} {'Failed Login Attempts':<15}")
    for ip, count in failed_logins.items():
        print(f"{ip:<20} {count:<15}")

if __name__ == "__main__":
    main()
