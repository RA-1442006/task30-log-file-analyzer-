"""
Log File Analyzer - Task 30
A Python script to parse server access logs and generate a summary report.
Standard library only (collections, re, csv, sys).
"""

import csv
import re
import sys
from collections import Counter

# Regular expression pattern to parse Common / Combined Log Format lines
# Example line: 192.168.1.10 - - [28/Oct/2026:10:00:08 +0000] "GET /index.html HTTP/1.1" 200 4520
LOG_PATTERN = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+(\S+)(?:\s+HTTP/[0-9.]+)?\"\s+(\d{3})\s+(\S+)'
)


def parse_line(line):
    # Parse a single log line into a dictionary of fields
    match = LOG_PATTERN.match(line)
    if not match:
        return None

    ip = match.group(1)
    timestamp = match.group(2)
    method = match.group(3)
    endpoint = match.group(4)
    status = int(match.group(5))

    return {
        "ip": ip,
        "timestamp": timestamp,
        "method": method,
        "endpoint": endpoint,
        "status": status,
    }


def read_log_file(filepath):
    # Read the log file line by line to keep memory usage low
    parsed_logs = []
    skipped_count = 0

    try:
        with open(filepath, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                # Skip blank lines
                if not line:
                    continue

                entry = parse_line(line)
                if entry:
                    parsed_logs.append(entry)
                else:
                    skipped_count += 1

    except FileNotFoundError:
        print(f"Error: The log file '{filepath}' was not found.")
        return None, 0
    except Exception as e:
        print(f"Error reading file '{filepath}': {e}")
        return None, 0

    # Check if the file had no valid lines or was completely empty
    if len(parsed_logs) == 0 and skipped_count == 0:
        print(f"Warning: The file '{filepath}' is empty. Nothing to analyze.")
        return None, 0

    return parsed_logs, skipped_count


def analyze_logs(parsed_logs, skipped_count=0):
    # Calculate statistics using Counter
    ip_counts = Counter(entry["ip"] for entry in parsed_logs)
    endpoint_counts = Counter(entry["endpoint"] for entry in parsed_logs)
    status_counts = Counter(entry["status"] for entry in parsed_logs)

    # Filter client (4xx) and server (5xx) errors
    error_counts = {
        code: count for code, count in status_counts.items() if code >= 400
    }
    total_errors = sum(error_counts.values())

    return {
        "total_requests": len(parsed_logs),
        "total_errors": total_errors,
        "error_breakdown": error_counts,
        "top_ips": ip_counts.most_common(5),
        "top_endpoints": endpoint_counts.most_common(5),
        "skipped_lines": skipped_count,
    }


def format_report(analysis, log_filepath):
    # Format the analysis dictionary into a clean text report
    lines = []
    lines.append("=" * 50)
    lines.append("           LOG FILE ANALYSIS REPORT")
    lines.append("=" * 50)
    lines.append(f"Log File Analyzed        : {log_filepath}")
    lines.append(f"Total Requests Processed : {analysis['total_requests']}")
    lines.append(f"Malformed Lines Skipped  : {analysis['skipped_lines']}")
    lines.append("")
    lines.append("-" * 50)
    lines.append("Error Responses (4xx and 5xx)")
    lines.append("-" * 50)
    lines.append(f"Total Errors: {analysis['total_errors']}")

    if analysis["error_breakdown"]:
        lines.append("Breakdown by Status Code:")
        status_names = {
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            500: "Internal Server Error",
            502: "Bad Gateway",
            503: "Service Unavailable",
        }
        for status in sorted(analysis["error_breakdown"].keys()):
            count = analysis["error_breakdown"][status]
            desc = status_names.get(status, "Error")
            lines.append(f"  - Status {status} ({desc}): {count}")
    else:
        lines.append("  No error responses found.")

    lines.append("")
    lines.append("-" * 50)
    lines.append("Top 5 Most Frequent IP Addresses")
    lines.append("-" * 50)
    for rank, (ip, count) in enumerate(analysis["top_ips"], start=1):
        lines.append(f"  {rank}. {ip:<18} : {count} requests")

    lines.append("")
    lines.append("-" * 50)
    lines.append("Top 5 Most Requested Endpoints")
    lines.append("-" * 50)
    for rank, (endpoint, count) in enumerate(analysis["top_endpoints"], start=1):
        lines.append(f"  {rank}. {endpoint:<18} : {count} requests")

    lines.append("=" * 50)
    return "\n".join(lines)


def print_report(analysis, log_filepath="sample_access.log"):
    # Print the report to the console
    report_text = format_report(analysis, log_filepath)
    print(report_text)
    return report_text


def save_report(report_text, output_file="report_output.txt"):
    # Save the text report to a file
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(report_text)
        print(f"\nReport successfully saved to '{output_file}'.")
    except Exception as e:
        print(f"Error saving report to '{output_file}': {e}")


def export_csv_summary(analysis, csv_file="report_summary.csv"):
    # Export summary statistics into a CSV file
    try:
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Category", "Item", "Count"])
            for ip, count in analysis["top_ips"]:
                writer.writerow(["Top IP Address", ip, count])
            for endpoint, count in analysis["top_endpoints"]:
                writer.writerow(["Top Endpoint", endpoint, count])
            for status in sorted(analysis["error_breakdown"].keys()):
                writer.writerow(["Error Status Code", status, analysis["error_breakdown"][status]])
        print(f"CSV summary successfully saved to '{csv_file}'.")
    except Exception as e:
        print(f"Error exporting CSV to '{csv_file}': {e}")


def main():
    # Allow passing log file via command line argument, default to sample_access.log
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = "sample_access.log"

    print(f"Starting analysis of '{log_file}'...\n")

    parsed_logs, skipped_count = read_log_file(log_file)
    if parsed_logs is None:
        return

    analysis = analyze_logs(parsed_logs, skipped_count)
    report_text = print_report(analysis, log_file)
    save_report(report_text, "report_output.txt")
    export_csv_summary(analysis, "report_summary.csv")


if __name__ == "__main__":
    main()
