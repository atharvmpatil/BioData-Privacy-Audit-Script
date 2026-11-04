# BioData-Privacy-Audit-Script

An automated security audit and compliance verification tool written in Python. It parses Electronic Health Record (EHR) database access logs to identify insider threats, unencrypted ePHI transfers, and access anomalies under **HIPAA (45 CFR § 164)** and **PIPEDA (Principle 7 - Safeguards)**.

---

## Automated Detection Heuristics

1. **After-Hours Non-Clinical Access:** Flags bulk downloads or records access initiated outside approved operational hours (07:00–19:00) by non-clinical accounts (HIPAA Minimum Necessary standard).
2. **Cleartext Transmission Violations:** Detects unencrypted transfer protocols (HTTP, unencrypted FTP) transmitting protected medical identifiers in violation of HIPAA § 164.312(e)(1).
3. **Bulk Data Exfiltration Limits:** Identifies single-session record queries exceeding baseline thresholds (default: >= 50 records), alerting on data hoarding and insider theft.

---

## How to Run

Requirements: Python 3.8+ (No third-party packages required).

```bash
# Execute the compliance audit engine
python audit_engine.py