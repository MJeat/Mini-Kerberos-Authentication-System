"""
SIEM Logger + Tkinter Dashboard
- log_event(): central logging function for AS, TGS, SERVICE, CLIENT
- SIEMDashboard: simple GUI to view logs with severity filter
"""

import json
import time
import os
import tkinter as tk
from tkinter import ttk

LOG_FILE = "security_log.json"
MAX_LOG_SIZE = 1000  # rotate after 1000 logs


# ==========================================================
#                   🔒 SEVERITY CLASSIFICATION
# ==========================================================
def classify_severity(event: str, status: str) -> str:
    """Simple rule-based severity classification."""
    event_l = event.lower()

    if status == "success":
        return "INFO"

    critical = [
        "authentication", "password", "mfa", "decrypt",
        "tgt", "ticket", "replay", "authenticator",
        "forged", "breach", "compromise"
    ]

    if any(c in event_l for c in critical):
        return "HIGH"

    return "MEDIUM"


# ==========================================================
#                   🔐 SAFE JSON LOADING
# ==========================================================
def safe_load():
    """Load JSON safely even if corrupted."""
    if not os.path.exists(LOG_FILE):
        return []

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        corrupted = f"corrupted_" + str(int(time.time())) + ".json"
        os.rename(LOG_FILE, corrupted)
        return []


# ==========================================================
#                   📝 LOGGING FUNCTION
# ==========================================================
def log_event(component: str, username: str, event: str, status: str,
              ip: str = "-", details: str = ""):
    """Main SIEM logging function."""
    data = safe_load()
    severity = classify_severity(event, status)

    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "component": component,
        "username": username,
        "event": event,
        "status": status,
        "severity": severity,
        "ip": ip,
        "details": details
    }

    data.append(entry)

    # Rotate logs if too large
    if len(data) > MAX_LOG_SIZE:
        archive = f"archive_{int(time.time())}.json"
        with open(archive, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        data = []

    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


# ==========================================================
#                   📊 SIEM DASHBOARD (Tkinter)
# ==========================================================
def load_logs():
    if not os.path.exists(LOG_FILE):
        return []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


class SIEMDashboard(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SIEM Log Dashboard")
        self.geometry("1100x550")
        self.configure(bg="#f5f5f5")

        self.create_widgets()
        self.refresh_table()

    # ------------------------------------------------------
    def create_widgets(self):
        header = tk.Label(
            self,
            text="SIEM Log Dashboard",
            font=("Arial", 20, "bold"),
            bg="#f5f5f5"
        )
        header.pack(pady=10)

        # Filter frame
        frame = tk.Frame(self, bg="#f5f5f5")
        frame.pack()

        tk.Label(
            frame,
            text="Filter by Severity:",
            font=("Arial", 12),
            bg="#f5f5f5"
        ).pack(side="left")

        self.severity_var = tk.StringVar(value="ALL")

        menu = ttk.Combobox(
            frame,
            textvariable=self.severity_var,
            values=["ALL", "INFO", "MEDIUM", "HIGH"],
            width=10
        )
        menu.pack(side="left", padx=5)
        menu.bind("<<ComboboxSelected>>", lambda e: self.refresh_table())

        # Table
        columns = (
            "timestamp", "component", "username", "event",
            "status", "severity", "ip", "details"
        )

        self.table = ttk.Treeview(
            self, columns=columns, show="headings", height=20
        )

        for col in columns:
            self.table.heading(col, text=col.capitalize())
            self.table.column(col, width=130)

        self.table.pack(pady=10, fill="both", expand=True)

        # Color tags
        self.table.tag_configure("HIGH", background="#ffb3b3")
        self.table.tag_configure("MEDIUM", background="#fff0b3")
        self.table.tag_configure("INFO", background="#d6f5d6")

    # ------------------------------------------------------
    def refresh_table(self):
        for row in self.table.get_children():
            self.table.delete(row)

        logs = load_logs()
        filter_level = self.severity_var.get()

        for log in logs:
            sev = log.get("severity", "INFO")

            if filter_level != "ALL" and sev != filter_level:
                continue

            self.table.insert(
                "",
                "end",
                values=(
                    log["timestamp"],
                    log["component"],
                    log["username"],
                    log["event"],
                    log["status"],
                    sev,
                    log["ip"],
                    log["details"],
                ),
                tags=(sev,)
            )

        # Auto-refresh every 5 seconds
        self.after(5000, self.refresh_table)


# ==========================================================
#                   ▶ RUN DASHBOARD DIRECTLY
# ==========================================================
if __name__ == "__main__":
    # Example test logs (optional – delete later)
    log_event("CLIENT", "admin", "authentication attempt", "failure", "192.168.1.20")
    log_event("TGS", "admin", "TGT validation", "success", "192.168.1.5")
    log_event("SERVICE", "admin", "service ticket decrypt", "failure", "192.168.1.7")

    app = SIEMDashboard()
    app.mainloop()
