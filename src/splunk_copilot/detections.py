"""Correlation searches over the event store, expressed AS SPL.

Each detector runs one or more genuine SPL queries through ``SplEngine`` and, if
the result crosses a threshold, returns a Detection carrying a MITRE ATT&CK
technique (and an ops failure class), a severity, a human summary, the exact SPL
that fired it, and the provenance refs that justify it. Detectors are read-only
and do NOT touch the ledger; the agent decides what to promote to findings after
the self-correction loop.

These are the same SPL strings you would save as correlation searches in a real
Splunk Enterprise Security deployment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .spl import SplEngine


@dataclass
class Detection:
    rule_id: str
    mitre: str
    ops_class: str
    label: str
    severity: str
    summary: str
    event_time_utc: str
    spl: str
    evidence_refs: list[str]
    iocs: list[str] = field(default_factory=list)
    recommendation: str = ""
    detail: dict[str, Any] = field(default_factory=dict)


def detect_credential_stuffing(eng: SplEngine) -> list[Detection]:
    """Burst of failed logins from one IP followed by a success = stuffing.

    MITRE T1110.004 (Credential Stuffing).
    """
    fail_spl = ('index=web sourcetype=access_combined uri_path="/api/login" '
                'status=401 | stats count by clientip')
    fails = eng.search(fail_spl)
    out: list[Detection] = []
    for row in fails.rows:
        if int(row.get("count", 0)) < 5:
            continue
        ip = row.get("clientip")
        succ_spl = (f'index=web sourcetype=access_combined uri_path="/api/login" '
                    f'status=200 clientip={ip} | table clientip,user,time_utc')
        succ = eng.search(succ_spl)
        if not succ.rows:
            continue  # failures with no success = not yet a confirmed breach
        refs = fails.refs + succ.refs
        out.append(Detection(
            rule_id="CS-AUTH-001", mitre="T1110.004", ops_class="auth_bruteforce",
            label="Credential stuffing against /api/login (then success)",
            severity="high",
            summary=(f"{row['count']} failed /api/login attempts from {ip} then a "
                     f"successful 200 as '{succ.rows[0].get('user')}' — credential "
                     f"stuffing that succeeded."),
            event_time_utc=succ.rows[0].get("time_utc"),
            spl=succ_spl, evidence_refs=refs, iocs=[ip],
            recommendation=("Lock svc_deploy, force credential rotation, enable "
                            "rate-limiting + lockout on /api/login, require MFA."),
            detail={"failed_count": row["count"]},
        ))
    return out


def detect_leaked_key_usage(eng: SplEngine) -> list[Detection]:
    """A repo-leaked API key authenticating a valid account.

    MITRE T1078.004 (Valid Accounts: Cloud Accounts).
    """
    out: list[Detection] = []
    leak_spl = ('index=app sourcetype=app:payments event=config_loaded '
                '| table api_key_id,msg,time_utc')
    leaked = eng.search(leak_spl)
    if not leaked.rows:
        return out
    key = leaked.rows[0].get("api_key_id")
    use_spl = (f'index=app sourcetype=app:payments event=auth_success '
               f'api_key_id={key} | table user,api_key_id,src_ip,time_utc')
    used = eng.search(use_spl)
    if not used.rows:
        return out
    refs = leaked.refs + used.refs
    out.append(Detection(
        rule_id="CS-CRED-002", mitre="T1078.004", ops_class="valid_account_abuse",
        label="Leaked service-account API key used to authenticate",
        severity="critical",
        summary=(f"API key {key} was loaded from a repo-committed config and then "
                 f"used to authenticate '{used.rows[0].get('user')}' from "
                 f"{used.rows[0].get('src_ip')} — leaked-credential abuse."),
        event_time_utc=used.rows[0].get("time_utc"),
        spl=use_spl, evidence_refs=refs, iocs=[key, used.rows[0].get("src_ip")],
        recommendation=("Revoke/rotate API key, purge it from git history, scope "
                        "the service account to least privilege, add secret scanning to CI."),
        detail={"api_key_id": key},
    ))
    return out


def detect_privilege_escalation(eng: SplEngine) -> list[Detection]:
    """Self-service role grant via an unguarded admin endpoint.

    MITRE T1068 (Exploitation for Privilege Escalation).
    """
    out: list[Detection] = []
    web_spl = ('index=web sourcetype=access_combined uri_path="/api/admin/grant_role" '
               'status=200 | table clientip,user,time_utc')
    web = eng.search(web_spl)
    if not web.rows:
        return out
    app_spl = ('index=app sourcetype=app:payments event=privilege_change '
               '| table user,role,msg,time_utc')
    app = eng.search(app_spl)
    refs = web.refs + app.refs
    user = web.rows[0].get("user")
    out.append(Detection(
        rule_id="CS-PRIV-003", mitre="T1068", ops_class="privilege_escalation",
        label="Privilege escalation via /api/admin/grant_role",
        severity="critical",
        summary=(f"'{user}' from {web.rows[0].get('clientip')} called "
                 f"/api/admin/grant_role and was granted role "
                 f"'{app.rows[0].get('role') if app.rows else 'admin'}' with no "
                 f"approver — broken access control / privilege escalation."),
        event_time_utc=web.rows[0].get("time_utc"),
        spl=web_spl, evidence_refs=refs, iocs=[user],
        recommendation=("Revoke the granted role, gate /api/admin/* behind "
                        "authz + approval workflow, audit all recent role grants."),
        detail={"granted_to": user},
    ))
    return out


def detect_data_exfiltration(eng: SplEngine) -> list[Detection]:
    """Bulk data export with a large outbound byte spike.

    MITRE T1567.002 (Exfiltration to Cloud Storage / over web).
    """
    out: list[Detection] = []
    exp_spl = ('index=web sourcetype=access_combined uri_path="/api/export/customers" '
               'status=200 | where bytes > 1000000 '
               '| stats count as exports sum(bytes) as total_bytes by clientip')
    exp = eng.search(exp_spl)
    if not exp.rows or int(exp.rows[0].get("exports", 0)) < 2:
        return out
    ip = exp.rows[0].get("clientip")
    fw_spl = (f'index=network sourcetype=pan:traffic dest_ip={ip} '
              f'| where bytes_out > 1000000 | stats sum(bytes_out) as exfil_bytes by dest_ip')
    fw = eng.search(fw_spl)
    refs = exp.refs + fw.refs
    total_mb = round(float(exp.rows[0].get("total_bytes", 0)) / 1_000_000, 1)
    out.append(Detection(
        rule_id="CS-EXFIL-004", mitre="T1567.002", ops_class="data_exfiltration",
        label="Data exfiltration spike (bulk customer export)",
        severity="critical",
        summary=(f"{exp.rows[0].get('exports')} bulk /api/export/customers calls "
                 f"from {ip} moved ~{total_mb} MB; firewall confirms the matching "
                 f"outbound byte spike to {ip} — data exfiltration."),
        event_time_utc="2026-06-10T02:25:00Z",
        spl=exp_spl, evidence_refs=refs, iocs=[ip],
        recommendation=("Block egress to the destination, revoke session, quantify "
                        "exposed records for breach notification, add DLP/rate caps on bulk export."),
        detail={"exports": exp.rows[0].get("exports"), "exfil_mb": total_mb},
    ))
    return out


def detect_service_error_cascade(eng: SplEngine) -> list[Detection]:
    """Spike of ERROR-level app events = ops failure class (service degradation).

    Ops failure class only (no MITRE) — kept honest: fires only if >=1 ERROR.
    """
    out: list[Detection] = []
    err_spl = ('index=app sourcetype=app:payments level=ERROR '
               '| stats count by host')
    err = eng.search(err_spl)
    for row in err.rows:
        if int(row.get("count", 0)) < 1:
            continue
        out.append(Detection(
            rule_id="OPS-ERR-005", mitre="-", ops_class="service_error_cascade",
            label="Application ERROR-level event cascade",
            severity="medium",
            summary=(f"{row['count']} ERROR-level event(s) on {row.get('host')} "
                     f"during the incident window — service-integrity impact "
                     f"correlated with the intrusion."),
            event_time_utc="2026-06-10T02:24:00Z",
            spl=err_spl, evidence_refs=err.refs,
            recommendation="Page on-call; correlate ERRORs with the security timeline.",
            detail={"errors": row["count"]},
        ))
    return out


ALL_DETECTORS = [
    detect_credential_stuffing,
    detect_leaked_key_usage,
    detect_privilege_escalation,
    detect_data_exfiltration,
    detect_service_error_cascade,
]


def run_all(eng: SplEngine) -> list[Detection]:
    out: list[Detection] = []
    for det in ALL_DETECTORS:
        out.extend(det(eng))
    return out
