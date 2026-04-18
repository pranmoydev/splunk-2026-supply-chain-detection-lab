import yara
import os
import logging
import time
import schedule
from datetime import datetime

# --- Config ---
RULES_DIR = r"C:\yara-rules"
SCAN_TARGETS = [
    r"C:\lab-incident\claude-leak",
    r"C:\lab-incident\axios-compromise"
]
LOG_FILE = r"C:\YaraLogs\yara_matches.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(message)s"
)

def load_rules():
    rule_files = {}
    for f in os.listdir(RULES_DIR):
        if f.endswith(".yar"):
            rule_files[f] = os.path.join(RULES_DIR, f)
    return yara.compile(filepaths=rule_files)

def scan_file(rules, filepath):
    try:
        matches = rules.match(filepath, timeout=10)
        for match in matches:
            severity = match.meta.get("severity", "unknown")
            description = match.meta.get("description", "no description")
            log_entry = (
                f"timestamp={datetime.utcnow().isoformat()}Z "
                f"rule={match.rule} "
                f"severity={severity} "
                f"file=\"{filepath}\" "
                f"description=\"{description}\""
            )
            logging.info(log_entry)
            print(log_entry)
    except yara.TimeoutError:
        pass
    except Exception:
        pass

def run_scan():
    print(f"[*] Scan started at {datetime.utcnow().isoformat()}Z")
    try:
        rules = load_rules()
    except Exception as e:
        print(f"[!] Failed to load rules: {e}")
        return

    for target in SCAN_TARGETS:
        for root, dirs, files in os.walk(target):
            for filename in files:
                filepath = os.path.join(root, filename)
                scan_file(rules, filepath)

    print(f"[*] Scan finished at {datetime.utcnow().isoformat()}Z")

schedule.every(30).minutes.do(run_scan)

if __name__ == "__main__":
    print("[*] YARA scanner started")
    run_scan()
    while True:
        schedule.run_pending()
        time.sleep(1)
