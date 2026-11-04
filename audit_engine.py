import json
import os
from datetime import datetime
from typing import Dict, List, Any

# COMPLIANCE THRESHOLDS & POLICY RULES

BUSINESS_HOURS_START = 7   # 07:00 AM
BUSINESS_HOURS_END = 19    # 07:00 PM (19:00)
BULK_EXPORT_THRESHOLD = 50 # Flag queries extracting 50+ records

# Clinical roles permitted to access records outside standard hours for shift care

CLINICAL_ROLES = {
    "Physician",
    "Nurse Practitioner",
    "Registered Nurse",
    "Surgeon",
    "Emergency Care Tech"
}

class ComplianceAuditEngine:
    def __init__(self, log_path: str):
        self.log_path = log_path
        self.logs: List[Dict[str, Any]] = []
        self.violations: List[Dict[str, Any]] = []

    def load_logs(self):
        """Loads and parses the raw EHR database access log file."""
        if not os.path.exists(self.log_path):
            raise FileNotFoundError(f"Source log file not found at: {self.log_path}")
        with open(self.log_path, "r", encoding="utf-8") as f:
            self.logs = json.load(f)

    def evaluate_rules(self):
        """Applies compliance heuristics to identify security violations."""
        for entry in self.logs:
            # Parse timestamp to extract the hour of the event
            ts_str = entry["timestamp"].replace("Z", "+00:00")
            dt = datetime.fromisoformat(ts_str)
            hour = dt.hour

            user_role = entry.get("user_role", "Unknown")
            action = entry.get("action", "")
            record_count = entry.get("record_count", 0)
            is_encrypted = entry.get("is_encrypted", True)
            protocol = entry.get("protocol", "UNKNOWN")

            
            # RULE 1: Unencrypted Data Transfer
            # HIPAA § 164.312(e)(1) | PIPEDA Principle 7 (Safeguards)
           
            if not is_encrypted or protocol.upper() in {"HTTP", "FTP", "TELNET"}:
                self.violations.append({
                    "event_id": entry["event_id"],
                    "timestamp": entry["timestamp"],
                    "user_id": entry["user_id"],
                    "user_role": user_role,
                    "severity": "CRITICAL",
                    "violation_type": "Unencrypted ePHI Transfer",
                    "details": f"Data transfer initiated using cleartext protocol ({protocol}). Network payload exposed.",
                    "compliance_impact": "HIPAA 45 CFR § 164.312(e)(1) | PIPEDA Safeguards (Principle 7)"
                })

            
            # RULE 2: After-Hours Non-Clinical Access / Download
            # HIPAA § 164.312(a)(1) | Minimum Necessary Standard
            
            is_after_hours = (hour < BUSINESS_HOURS_START or hour >= BUSINESS_HOURS_END)
            is_non_clinical = user_role not in CLINICAL_ROLES
            is_download = "DOWNLOAD" in action or "EXPORT" in action

            if is_after_hours and is_non_clinical and is_download:
                self.violations.append({
                    "event_id": entry["event_id"],
                    "timestamp": entry["timestamp"],
                    "user_id": entry["user_id"],
                    "user_role": user_role,
                    "severity": "HIGH",
                    "violation_type": "After-Hours Non-Clinical Download",
                    "details": f"Role '{user_role}' performed download action '{action}' at {dt.strftime('%H:%M:%S UTC')} outside approved business window.",
                    "compliance_impact": "HIPAA 45 CFR § 164.312(a)(1) (Access Controls) | Minimum Necessary Standard"
                })

           
            # RULE 3: Bulk Record Extraction (Insider Threat Defense)
            # HIPAA § 164.308(a)(1)(ii)(D) | PIPEDA Principle 7
            
            if record_count >= BULK_EXPORT_THRESHOLD:
                self.violations.append({
                    "event_id": entry["event_id"],
                    "timestamp": entry["timestamp"],
                    "user_id": entry["user_id"],
                    "user_role": user_role,
                    "severity": "HIGH",
                    "violation_type": "Bulk Data Export Threshold Exceeded",
                    "details": f"User extracted {record_count} patient records in a single query (Baseline Limit: {BULK_EXPORT_THRESHOLD}).",
                    "compliance_impact": "HIPAA 45 CFR § 164.308(a)(1)(ii)(D) (System Activity Review)"
                })

    def export_json(self, output_file: str = "audit_report.json"):
        """Exports breach analysis in machine-readable JSON format for SIEM tools."""
        report = {
            "audit_timestamp": datetime.utcnow().isoformat() + "Z",
            "total_records_analyzed": len(self.logs),
            "total_violations_flagged": len(self.violations),
            "violations": self.violations
        }
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"[+] JSON report created: {output_file}")

    def export_html(self, output_file: str = "audit_report.html"):
        """Generates an executive-ready dark-mode HTML compliance report."""
        table_rows = ""
        for v in self.violations:
            badge_class = "badge-critical" if v["severity"] == "CRITICAL" else "badge-high"
            table_rows += f"""
            <tr>
                <td><code>{v['event_id']}</code></td>
                <td>{v['timestamp']}</td>
                <td><strong>{v['user_id']}</strong><br><small>{v['user_role']}</small></td>
                <td><span class='badge {badge_class}'>{v['severity']}</span><br>{v['violation_type']}</td>
                <td>{v['details']}</td>
                <td><code>{v['compliance_impact']}</code></td>
            </tr>
            """

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>EHR BioData Privacy & Compliance Audit</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 2rem; }}
        .container {{ max-width: 1200px; margin: auto; }}
        h1 {{ color: #38bdf8; font-size: 1.8rem; margin-bottom: 0.2rem; }}
        p.sub {{ color: #94a3b8; margin-top: 0; margin-bottom: 2rem; }}
        .metrics {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin-bottom: 2rem; }}
        .card {{ background: #1e293b; padding: 1.25rem; border-radius: 8px; border: 1px solid #334155; }}
        .card-num {{ font-size: 2rem; font-weight: bold; margin-top: 0.5rem; }}
        table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 1rem; text-align: left; border-bottom: 1px solid #334155; font-size: 0.9rem; }}
        th {{ background: #111827; color: #94a3b8; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }}
        tr:hover {{ background: #243248; }}
        .badge {{ padding: 0.25rem 0.5rem; border-radius: 4px; font-weight: 600; font-size: 0.75rem; display: inline-block; margin-bottom: 0.3rem; }}
        .badge-critical {{ background: #7f1d1d; color: #fca5a5; }}
        .badge-high {{ background: #7c2d12; color: #fdba74; }}
        code {{ background: #0f172a; padding: 0.2rem 0.4rem; border-radius: 4px; font-size: 0.8rem; color: #38bdf8; }}
    </style>
</head>
<body>
<div class="container">
    <h1>EHR BioData Privacy & Compliance Audit Report</h1>
    <p class="sub">Automated Security Log Heuristics | HIPAA & PIPEDA Compliance Evaluation</p>
    
    <div class="metrics">
        <div class="card">
            <div>Events Evaluated</div>
            <div class="card-num">{len(self.logs)}</div>
        </div>
        <div class="card">
            <div>Violations Flagged</div>
            <div class="card-num" style="color: #f87171;">{len(self.violations)}</div>
        </div>
        <div class="card">
            <div>Compliance Status</div>
            <div class="card-num" style="color: {'#ef4444' if self.violations else '#10b981'};">
                {'BREACH DETECTED' if self.violations else 'COMPLIANT'}
            </div>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th>Event ID</th>
                <th>Timestamp</th>
                <th>User / Role</th>
                <th>Severity / Type</th>
                <th>Audit Findings</th>
                <th>Regulatory Reference</th>
            </tr>
        </thead>
        <tbody>
            {table_rows}
        </tbody>
    </table>
</div>
</body>
</html>
"""
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_template)
        print(f"[+] HTML report created: {output_file}")

if __name__ == "__main__":
    engine = ComplianceAuditEngine("sample_ehr_logs.json")
    engine.load_logs()
    engine.evaluate_rules()
    engine.export_json("audit_report.json")
    engine.export_html("audit_report.html")
   