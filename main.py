import argparse
from parser import parse_csv_log
from rules import detect_failed_logins, detect_privilege_escalation, detect_suspicious_processes
from reporter import export_json, export_csv

def run_analysis(filepath, output_format='json'):
    print(f"[*] Parsing log file: {filepath}")
    df = parse_csv_log(filepath)

    all_alerts = []
    all_alerts += detect_failed_logins(df)
    all_alerts += detect_privilege_escalation(df)
    all_alerts += detect_suspicious_processes(df)

    print(f"[+] {len(all_alerts)} threats detected.")

    if output_format == 'csv':
        export_csv(all_alerts)
    else:
        export_json(all_alerts)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Log Parser & Threat Detector')
    parser.add_argument('--log', required=True, help='Path to log file')
    parser.add_argument('--format', default='json', choices=['json', 'csv'], help='Output format')
    parser.add_argument('--watch', action='store_true', help='Enable live log monitoring')
    args = parser.parse_args()

    if args.watch:
        print("[*] Watch mode enabled...")
       
    else:
        run_analysis(args.log, args.format)




from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, filepath, output_format):
        self.filepath = filepath
        self.output_format = output_format

    def on_modified(self, event):
        if event.src_path == self.filepath:
            print("[*] Log file updated, re-analysing...")
            run_analysis(self.filepath, self.output_format)

def watch_log(filepath, output_format):
    event_handler = LogFileHandler(filepath, output_format)
    observer = Observer()
    observer.schedule(event_handler, path=filepath, recursive=False)
    observer.start()
    print(f"[*] Watching {filepath} for changes. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()