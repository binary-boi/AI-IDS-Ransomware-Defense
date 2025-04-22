import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

HONEYPOT_DIR = "ransomware_defense/honeypot_files"
ALERT_LOG = "ransomware_defense/honeypot_alerts.log"

class HoneypotMonitor(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory:
            self.alert("MODIFIED", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.alert("DELETED", event.src_path)

    def alert(self, action, filepath):
        alert_msg = f"[ALERT] {action} - {filepath}"
        print(alert_msg)
        with open(ALERT_LOG, "a") as log:
            log.write(f"{time.ctime()} - {alert_msg}\n")

if __name__ == "__main__":
    os.makedirs(HONEYPOT_DIR, exist_ok=True)

    print(f"Monitoring honeypot directory: {HONEYPOT_DIR}")
    print("Modify or delete any files inside it to trigger alerts.\n")

    event_handler = HoneypotMonitor()
    observer = Observer()
    observer.schedule(event_handler, HONEYPOT_DIR, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
