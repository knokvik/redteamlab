"""CVSS v3.1 Base Score calculator and EBSS (Extended Behavior Security Score) engine.

Implements the official FIRST CVSS v3.1 specification for base score calculation
and extends it with a behavioral amplification layer derived from live telemetry.

Reference: https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ── CVSS v3.1 metric weight tables (from FIRST spec) ──────────────────────────

AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC_WEIGHTS = {"L": 0.77, "H": 0.44}
PR_WEIGHTS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_WEIGHTS_CHANGED   = {"N": 0.85, "L": 0.68, "H": 0.50}
UI_WEIGHTS = {"N": 0.85, "R": 0.62}
S_VALUES   = {"U": "Unchanged", "C": "Changed"}
CIA_WEIGHTS = {"N": 0.00, "L": 0.22, "H": 0.56}

# Human-readable labels
METRIC_LABELS = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S":  {"U": "Unchanged", "C": "Changed"},
    "C":  {"N": "None", "L": "Low", "H": "High"},
    "I":  {"N": "None", "L": "Low", "H": "High"},
    "A":  {"N": "None", "L": "Low", "H": "High"},
}


@dataclass
class CVSSVector:
    """A fully resolved CVSS v3.1 Base vector with computed scores."""
    AV: str = "N"
    AC: str = "L"
    PR: str = "N"
    UI: str = "N"
    S: str = "U"
    C: str = "N"
    I: str = "N"
    A: str = "N"

    def vector_string(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.AV}/AC:{self.AC}/PR:{self.PR}"
            f"/UI:{self.UI}/S:{self.S}/C:{self.C}/I:{self.I}/A:{self.A}"
        )

    def base_score(self) -> float:
        return compute_base_score(self)

    def severity_label(self) -> str:
        return severity_rating(self.base_score())

    def breakdown(self) -> List[Dict[str, str]]:
        """Return a list of dicts for report table rendering."""
        rows = []
        for metric in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
            val = getattr(self, metric)
            rows.append({
                "metric": metric,
                "full_name": _METRIC_FULL_NAMES[metric],
                "value": val,
                "label": METRIC_LABELS[metric][val],
                "rationale": "",  # filled by auto-detect
            })
        return rows


_METRIC_FULL_NAMES = {
    "AV": "Attack Vector",
    "AC": "Attack Complexity",
    "PR": "Privileges Required",
    "UI": "User Interaction",
    "S":  "Scope",
    "C":  "Confidentiality",
    "I":  "Integrity",
    "A":  "Availability",
}


# ── CVSS v3.1 base score formula ──────────────────────────────────────────────

def compute_base_score(v: CVSSVector) -> float:
    """Compute the CVSS v3.1 Base Score from a vector using the FIRST formula."""
    # Impact Sub-Score components
    isc_c = 1.0 - CIA_WEIGHTS[v.C]
    isc_i = 1.0 - CIA_WEIGHTS[v.I]
    isc_a = 1.0 - CIA_WEIGHTS[v.A]
    isc_base = 1.0 - (isc_c * isc_i * isc_a)

    if v.S == "U":
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

    if impact <= 0:
        return 0.0

    # Exploitability Sub-Score
    pr_weights = PR_WEIGHTS_CHANGED if v.S == "C" else PR_WEIGHTS_UNCHANGED
    exploitability = (
        8.22
        * AV_WEIGHTS[v.AV]
        * AC_WEIGHTS[v.AC]
        * pr_weights[v.PR]
        * UI_WEIGHTS[v.UI]
    )

    if v.S == "U":
        raw = min(impact + exploitability, 10.0)
    else:
        raw = min(1.08 * (impact + exploitability), 10.0)

    return _roundup(raw)


def _roundup(value: float) -> float:
    """CVSS v3.1 spec: round up to one decimal place."""
    return math.ceil(value * 10) / 10.0


def severity_rating(score: float) -> str:
    if score == 0.0:
        return "None"
    if score <= 3.9:
        return "Low"
    if score <= 6.9:
        return "Medium"
    if score <= 8.9:
        return "High"
    return "Critical"


def severity_class(score: float) -> str:
    """CSS class name for badge rendering."""
    if score >= 9.0:
        return "badge-critical"
    if score >= 7.0:
        return "badge-high"
    if score >= 4.0:
        return "badge-medium"
    return "badge-low"


# ── Auto-detection from attack + observability data ───────────────────────────

def auto_detect_vector(
    attacks: List[Dict],
    observability_summary: Dict,
    attack_context: Dict,
) -> CVSSVector:
    """Automatically determine the best CVSS v3.1 vector from attack telemetry.

    This uses heuristics to map real exploitation outcomes to standardized
    CVSS v3.1 metric values.
    """
    v = CVSSVector()

    # AV: Always Network — attacks traverse Docker network
    v.AV = "N"

    # UI: Always None — fully automated attacks
    v.UI = "N"

    combined_text = _combined_attack_text(attacks)
    successful = [a for a in attacks if a.get("success")]

    # ── AC (Attack Complexity) ────────────────────────────────────────────
    multi_step_signals = ["chain", "multi-step", "race condition", "timing"]
    if any(sig in combined_text for sig in multi_step_signals):
        v.AC = "H"
    else:
        v.AC = "L"

    # ── PR (Privileges Required) ──────────────────────────────────────────
    auth_bypass_signals = ["auth bypass", "authentication", "bypass", "login"]
    has_creds = len(attack_context.get("credentials_found", [])) > 0
    if has_creds or any(sig in combined_text for sig in auth_bypass_signals):
        v.PR = "L"  # Had to bypass or find creds
    else:
        v.PR = "N"  # Unauthenticated attacks

    # ── S (Scope) ─────────────────────────────────────────────────────────
    # Changed if attack crossed container boundaries (e.g., reached DB from web)
    db_latency = observability_summary.get("db_latency_max_ms")
    cross_container_signals = ["database", "db_", "lateral", "pivot", "ssrf"]
    if (db_latency and float(db_latency or 0) > 100) or any(
        sig in combined_text for sig in cross_container_signals
    ):
        v.S = "C"
    else:
        v.S = "U"

    # ── C (Confidentiality Impact) ────────────────────────────────────────
    sensitive_hits = int(observability_summary.get("sensitive_log_hits", 0) or 0)
    exfil_signals = ["password", "secret", "token", "dump", "exfil", ".env", ".git/config",
                      "sensitive", "credentials", "apikey", "private_key"]
    high_c_signals = sum(1 for sig in exfil_signals if sig in combined_text)
    if sensitive_hits > 0 or high_c_signals >= 2:
        v.C = "H"
    elif high_c_signals >= 1:
        v.C = "L"
    else:
        v.C = "N"

    # ── I (Integrity Impact) ──────────────────────────────────────────────
    integrity_signals = ["rce", "command injection", "exec(", "system(", "; id",
                         "sql injection", "union select", "insert ", "update ", "delete "]
    high_i_signals = sum(1 for sig in integrity_signals if sig in combined_text)
    if high_i_signals >= 2:
        v.I = "H"
    elif high_i_signals >= 1 or any(a.get("success") for a in attacks if "sqli" in str(a.get("plan", "")).lower()):
        v.I = "L"
    else:
        v.I = "N"

    # ── A (Availability Impact) ───────────────────────────────────────────
    max_cpu = float(observability_summary.get("max_cpu_percent", 0.0) or 0.0)
    error_hits = int(observability_summary.get("error_log_hits", 0) or 0)
    dos_signals = ["dos", "flood", "stress", "exhaustion", "siege", "slowloris", "crash"]
    if max_cpu > 80 or error_hits > 10 or any(sig in combined_text for sig in dos_signals):
        v.A = "H"
    elif max_cpu > 40 or error_hits > 3:
        v.A = "L"
    else:
        v.A = "N"

    return v


def _combined_attack_text(attacks: List[Dict]) -> str:
    parts = []
    for a in attacks:
        parts.append(str(a.get("plan", "")))
        parts.append(str(a.get("payload", "")))
        parts.append(str(a.get("stdout", ""))[:500])
        parts.append(str(a.get("stderr", ""))[:200])
    return " ".join(parts).lower()


# ── EBSS (Extended Behavior Security Score) ───────────────────────────────────

@dataclass
class BehaviorAnalysis:
    """Result of behavioral severity analysis from observability data."""
    severity: int           # 1 = Normal, 3 = Suspicious, 6 = Anomalous, 9 = Critical
    severity_label: str     # Human-readable label
    signals: List[str]      # List of detected behavioral signals
    cpu_category: str       # What CPU behavior was observed
    memory_category: str    # What memory behavior was observed
    error_category: str     # What error pattern was observed
    data_leak_detected: bool
    service_degradation: bool


def analyze_behavior(
    observability_summary: Dict,
    attack_context: Dict,
) -> BehaviorAnalysis:
    """Classify observed runtime behavior into a severity tier.

    Severity Levels:
        1 = Normal       — No significant behavioral changes
        3 = Suspicious   — Mild anomalies (repeated failures, minor spikes)
        6 = Anomalous    — Clear degradation (latency, errors, resource pressure)
        9 = Critical     — Service impact (crashes, data leaks, saturation)
    """
    signals: List[str] = []
    max_severity = 1

    # ── CPU Analysis ──────────────────────────────────────────────────────
    max_cpu = float(observability_summary.get("max_cpu_percent", 0.0) or 0.0)
    avg_cpu = float(observability_summary.get("avg_cpu_percent", 0.0) or 0.0)
    if max_cpu > 90:
        cpu_category = "critical_saturation"
        signals.append(f"CPU saturation: peak {max_cpu:.1f}% (>90%)")
        max_severity = max(max_severity, 9)
    elif max_cpu > 60:
        cpu_category = "anomalous_spike"
        signals.append(f"CPU spike: peak {max_cpu:.1f}% (>60%)")
        max_severity = max(max_severity, 6)
    elif max_cpu > 30:
        cpu_category = "suspicious_elevation"
        signals.append(f"CPU elevated: peak {max_cpu:.1f}% (>30%)")
        max_severity = max(max_severity, 3)
    else:
        cpu_category = "normal"

    # ── Memory Analysis ───────────────────────────────────────────────────
    max_mem_pct = float(observability_summary.get("max_memory_percent", 0.0) or 0.0)
    if max_mem_pct > 85:
        memory_category = "critical_pressure"
        signals.append(f"Memory pressure: peak {max_mem_pct:.1f}% (>85%)")
        max_severity = max(max_severity, 9)
    elif max_mem_pct > 50:
        memory_category = "anomalous_growth"
        signals.append(f"Memory growth: peak {max_mem_pct:.1f}% (>50%)")
        max_severity = max(max_severity, 6)
    elif max_mem_pct > 25:
        memory_category = "suspicious_allocation"
        signals.append(f"Memory allocation: peak {max_mem_pct:.1f}% (>25%)")
        max_severity = max(max_severity, 3)
    else:
        memory_category = "normal"

    # ── Error Log Analysis ────────────────────────────────────────────────
    error_hits = int(observability_summary.get("error_log_hits", 0) or 0)
    if error_hits > 20:
        error_category = "critical_cascade"
        signals.append(f"Error cascade: {error_hits} error log entries (>20)")
        max_severity = max(max_severity, 9)
    elif error_hits > 5:
        error_category = "anomalous_errors"
        signals.append(f"Elevated errors: {error_hits} entries (>5)")
        max_severity = max(max_severity, 6)
    elif error_hits > 0:
        error_category = "suspicious_errors"
        signals.append(f"Error signals: {error_hits} entries")
        max_severity = max(max_severity, 3)
    else:
        error_category = "clean"

    # ── Data Leak Detection ───────────────────────────────────────────────
    sensitive_hits = int(observability_summary.get("sensitive_log_hits", 0) or 0)
    data_leak_detected = sensitive_hits > 0
    if data_leak_detected:
        signals.append(f"Sensitive data leak: {sensitive_hits} instances in container logs")
        max_severity = max(max_severity, 9)

    # ── Database Latency ──────────────────────────────────────────────────
    db_latency = observability_summary.get("db_latency_max_ms")
    if db_latency and float(db_latency) > 200:
        signals.append(f"DB latency critical: {float(db_latency):.1f}ms (>200ms)")
        max_severity = max(max_severity, 9)
    elif db_latency and float(db_latency) > 50:
        signals.append(f"DB latency elevated: {float(db_latency):.1f}ms (>50ms)")
        max_severity = max(max_severity, 6)

    # ── Service Degradation ───────────────────────────────────────────────
    service_degradation = max_cpu > 70 or error_hits > 10
    if service_degradation:
        signals.append("Service degradation pattern detected")

    # ── Vulnerability-based escalation ────────────────────────────────────
    vulns = attack_context.get("vulnerabilities", [])
    critical_vulns = sum(1 for v in vulns if v.get("severity") == "critical")
    high_vulns = sum(1 for v in vulns if v.get("severity") == "high")
    if critical_vulns > 0:
        signals.append(f"Critical vulnerabilities confirmed: {critical_vulns}")
        max_severity = max(max_severity, 9)
    elif high_vulns > 0:
        signals.append(f"High-severity vulnerabilities: {high_vulns}")
        max_severity = max(max_severity, 6)

    severity_labels = {1: "Normal", 3: "Suspicious", 6: "Anomalous", 9: "Critical"}

    return BehaviorAnalysis(
        severity=max_severity,
        severity_label=severity_labels[max_severity],
        signals=signals,
        cpu_category=cpu_category,
        memory_category=memory_category,
        error_category=error_category,
        data_leak_detected=data_leak_detected,
        service_degradation=service_degradation,
    )


def compute_ebss(base_cvss: float, behavior: BehaviorAnalysis) -> float:
    """Compute the Extended Behavior Security Score.

    Formula: EBSS = min(Base_CVSS + (Behavior_Severity × 0.5), 10.0)
    """
    return round(min(base_cvss + (behavior.severity * 0.5), 10.0), 1)


# ── Per-finding CVSS vector ───────────────────────────────────────────────────

# CWE → default CVSS v3.1 vectors (canonical mappings)
CWE_VECTOR_DEFAULTS: Dict[str, Dict[str, str]] = {
    "CWE-89":   {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},   # SQLi
    "CWE-79":   {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},   # XSS
    "CWE-1336": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},   # SSTI
    "CWE-98":   {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},   # LFI
    "CWE-78":   {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},   # RCE
    "CWE-639":  {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "L", "A": "N"},   # IDOR
    "CWE-918":  {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "L", "I": "L", "A": "N"},   # SSRF
    "CWE-22":   {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},   # Path Traversal
    "CWE-200":  {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"},   # Info Disclosure
    "CWE-400":  {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "N", "A": "H"},   # Resource Exhaustion
    "CWE-287":  {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},   # Auth Bypass
    "CWE-16":   {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"},   # Misconfig
}


def vector_for_cwe(cwe_id: str) -> CVSSVector:
    """Return the canonical CVSS v3.1 vector for a given CWE ID."""
    defaults = CWE_VECTOR_DEFAULTS.get(cwe_id, CWE_VECTOR_DEFAULTS["CWE-16"])
    return CVSSVector(**defaults)


def finding_score(cwe_id: str) -> float:
    """Compute the CVSS v3.1 base score for a specific CWE."""
    return vector_for_cwe(cwe_id).base_score()
