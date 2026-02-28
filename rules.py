import pandas as pd

def detect_failed_logins(df, threshold=5, window_seconds=60):
    alerts = []
    # Filter for Event ID 4625
    failed = df[df['EventID'] == 4625].copy()
    failed['TimeCreated'] = pd.to_datetime(failed['TimeCreated'])
    failed = failed.sort_values('TimeCreated')

    # This will group by IP/username and check if threshold exceeded in time window
    grouped = failed.groupby('IpAddress')
    for ip, group in grouped:
        group = group.set_index('TimeCreated').sort_index()
        rolling = group.rolling(f'{window_seconds}s').count()
        if rolling['EventID'].max() >= threshold:
            alerts.append({
                'type': 'Brute Force Attempt',
                'ip': ip,
                'count': int(rolling['EventID'].max()),
                'mitre_id': 'T1110',
                'mitre_technique': 'Brute Force'
            })
    return alerts

def detect_privilege_escalation(df):
    alerts = []
    privesc = df[df['EventID'] == 4672]
    for _, row in privesc.iterrows():
        alerts.append({
            'type': 'Privilege Escalation',
            'user': row.get('SubjectUserName', 'Unknown'),
            'time': str(row.get('TimeCreated', '')),
            'mitre_id': 'T1068',
            'mitre_technique': 'Exploitation for Privilege Escalation'
        })
    return alerts

def detect_suspicious_processes(df):
    suspicious = ['mimikatz', 'psexec', 'net.exe', 'cmd.exe', 'powershell']
    alerts = []
    processes = df[df['EventID'] == 4688]
    for _, row in processes.iterrows():
        process_name = str(row.get('NewProcessName', '')).lower()
        if any(s in process_name for s in suspicious):
            alerts.append({
                'type': 'Suspicious Process Created',
                'process': process_name,
                'user': row.get('SubjectUserName', 'Unknown'),
                'time': str(row.get('TimeCreated', '')),
                'mitre_id': 'T1059',
                'mitre_technique': 'Command and Scripting Interpreter'
            })
    return alerts