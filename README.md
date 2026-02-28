# Log Parser & Threat Detector

A Python tool that reads Windows Event Logs, flags suspicious activity, and outputs a structured threat report mapped to MITRE ATT&CK technique IDs.

I built this as a personal project to get hands-on experience with detection engineering and understand how real threats show up in log data.

---

## What It Does

- Parses Windows Event Log files (CSV or JSON format)
- Detects common attack patterns based on real Event IDs:
  - **4625** — Failed login attempts (Brute Force)
  - **4672** — Privilege escalation
  - **4688** — Suspicious process creation (e.g. mimikatz, psexec)
- Threshold-based alerting (e.g. 5+ failed logins from the same IP within 60 seconds)
- Outputs a structured `threat_report.json` or `threat_report.csv`
- Maps every finding to a MITRE ATT&CK technique ID
- Supports a `--watch` flag for live log monitoring using the `watchdog` library

---

## Project Structure
```
log-parser-threat-detector/
├── main.py          # Entry point, handles CLI arguments
├── parser.py        # Reads and loads log files
├── rules.py         # Detection logic for each threat type
├── reporter.py      # Outputs findings to JSON or CSV
└── sample_logs/
    └── test.csv     # Sample log data for testing
```

---

## How to Run It

**1. Clone the repository**
```
git clone https://github.com/YourUsername/log-parser-threat-detector.git
cd log-parser-threat-detector
```

**2. Install dependencies**
```
pip install pandas watchdog
```

**3. Run against a log file**
```
python3 main.py --log sample_logs/test.csv --format json
```

**4. Run in live watch mode**
```
python3 main.py --log sample_logs/test.csv --format json --watch
```

The threat report will be saved as `threat_report.json` in your project folder.

---

## Sample Output
```json
[
    {
        "type": "Brute Force Attempt",
        "ip": "192.168.1.10",
        "count": 5,
        "mitre_id": "T1110",
        "mitre_technique": "Brute Force"
    },
    {
        "type": "Privilege Escalation",
        "user": "administrator",
        "time": "2024-01-01 10:01:00",
        "mitre_id": "T1068",
        "mitre_technique": "Exploitation for Privilege Escalation"
    },
    {
        "type": "Suspicious Process Created",
        "process": "c:\\windows\\system32\\mimikatz.exe",
        "user": "user1",
        "time": "2024-01-01 10:02:00",
        "mitre_id": "T1059",
        "mitre_technique": "Command and Scripting Interpreter"
    }
]
```


<a href='https://postimages.org/' target='_blank'><img src='https://i.postimg.cc/VN6G1drv/project-adam.webp' border='0' alt='Screenshot-2023-09-05-at-17-54-28'/></a>
<br />

---

## MITRE ATT&CK Mapping

| Detection | Technique ID | Technique Name |
|---|---|---|
| 5+ failed logins from same IP | T1110 | Brute Force |
| Special privileges assigned | T1068 | Exploitation for Privilege Escalation |
| Suspicious process created | T1059 | Command and Scripting Interpreter |

---

## Challenges I Ran Into (and How I Fixed Them)

Honestly this project didn't go as smoothly as I expected, but that's probably where I learned the most. Here's a breakdown of every issue I hit and how I got past it:

**1. `python` command not found on Mac**

The first thing I ran into was that typing `python` in the terminal did nothing — just returned `zsh: command not found`. Turns out Mac uses `python3` by default and doesn't have a `python` alias out of the box. I fixed this by opening my `.zshrc` file and adding a permanent alias:
```
alias python=python3
```
After running `source ~/.zshrc` it worked fine from that point.

**2. pip blocking system-wide installs**

When I tried to install pandas with `pip install pandas` I got a long error about an "externally managed environment" and pip refusing to install anything system-wide. This is a Mac security thing introduced in newer versions of Python. I fixed it by creating a `pip.conf` file at `~/.config/pip/pip.conf` and adding:
```
[global]
break-system-packages = true
```
The folder didn't exist yet so I had to create it first with `mkdir -p ~/.config/pip` before I could create the file inside it.

**3. Pylance showing "pandas could not be resolved" in VS Code**

Even after installing pandas successfully, VS Code was still underlining the import in red. The issue was that VS Code was pointing to a different Python interpreter than the one I had installed pandas into. I fixed it by pressing `Cmd + Shift + P`, selecting "Python: Select Interpreter", and choosing the correct python3 path. The red underline disappeared straight away.

**4. Trying to download sample `.evtx` files from GitHub**

I wanted to test the tool with real Windows Event Log files so I went to GitHub to download some sample `.evtx` files. The download kept saving as an `.html` file instead of `.evtx`. This happened because I was saving the GitHub webpage rather than the actual file. The fix was to click into the file on GitHub, hit the "Download raw file" button, and make sure the filename extension was `.evtx` before saving.

**5. test.csv was empty**

I had created the `sample_logs/test.csv` file but forgot to actually put any data in it. When I ran `ls -la sample_logs/` it showed the file size as `0`. I opened it in VS Code and pasted in the sample log data manually, then saved it. After that the script ran correctly.

**6. `code` command not working in terminal**

After the script ran and generated `threat_report.json`, I tried to open it with `code threat_report.json` and got `zsh: command not found: code`. The fix was to open VS Code, press `Cmd + Shift + P`, and run "Shell Command: Install 'code' command in PATH". After restarting the terminal the command worked.

---

## What I'd Add Next

- Support for parsing `.evtx` files natively using the `python-evtx` library
- A simple HTML dashboard to visualise the threat report
- Email alerting when threats are detected above a certain threshold
- More detection rules covering lateral movement and persistence techniques

---

## Libraries Used

- `pandas` — log parsing and time-based analysis
- `watchdog` — live file monitoring
- `argparse` — command line argument handling
- `json` / `csv` — report output
- `re` — pattern matching

---

## Author

Built by Oluwamuyiwa Fadare as part of a cybersecurity portfolio project.
