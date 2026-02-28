import json
import csv

def export_json(alerts, output_path='threat_report.json'):
    with open(output_path, 'w') as f:
        json.dump(alerts, f, indent=4)
    print(f"[+] Report saved to {output_path}")

def export_csv(alerts, output_path='threat_report.csv'):
    if not alerts:
        print("No alerts to export.")
        return
    keys = alerts[0].keys()
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(alerts)
    print(f"[+] Report saved to {output_path}")