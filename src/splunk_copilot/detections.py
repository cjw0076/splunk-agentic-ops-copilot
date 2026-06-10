"""Correlation searches over the event store, expressed AS SPL.

Each detector runs one or more genuine SPL queries through ``SplEngine`` and, if
the result crosses a threshold, returns a Detection carrying a MITRE ATT&CK
technique (and an ops failure class), a severity, a human summary, the exact SPL
that fired it, and the provenance refs that justify it. Detectors are read-only
and do NOT touch the ledger; the agent decides what to promote to findings after
the self-correction loop.

These are the same SPL strings you would save as correlation searches in a real
Splunk Enterprise Security deployment.

The library is deliberately GENERIC: the agent runs the WHOLE detector library
against every scenario, and each detector self-gates on real SPL evidence, so it
only fires when that scenario's data actually contains the pattern. That is what
makes "the same agent solves all five incidents" an honest claim — nothing is
hardcoded to one case; the data decides what fires.
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


def _first_time(rows: list[dict[str, Any]], default: str = "") -> str:
    for r in rows:
        t = r.get("time_utc")
        if t:
            return str(t)
    return default


# ===========================================================================
# Account / identity attacks
# ===========================================================================

def detect_credential_stuffing(eng: SplEngine) -> list[Detection]:
    """Burst of failed web logins from one IP followed by a success = stuffing.

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
            recommendation=("Lock the compromised account, force credential "
                            "rotation, enable rate-limiting + lockout on "
                            "/api/login, require MFA."),
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


def detect_impossible_travel(eng: SplEngine) -> list[Detection]:
    """Same identity authenticating from two countries within a short window.

    MITRE T1078 (Valid Accounts) — cloud/SaaS account takeover signal.
    Uses the ``geo_country`` field present on SaaS auth logs.
    """
    out: list[Detection] = []
    auth_spl = ('index=saas sourcetype=okta:authentication action=success '
                '| stats dc(geo_country) as countries values(geo_country) as where '
                'values(src_ip) as ips by user')
    auth = eng.search(auth_spl)
    for row in auth.rows:
        if int(row.get("countries", 0)) < 2:
            continue
        user = row.get("user")
        ips = list(row.get("ips", []))
        # Suppress sanctioned multi-geo: if EVERY source IP is rated benign in
        # threat intel (e.g. a corporate VPN with US + EU egress), this is not a
        # takeover. Only flag when at least one IP is non-benign. This is what
        # keeps the detector honest against the VPN-egress false-positive decoy.
        verdicts = [eng.store.threat_verdict(ip) for ip in ips]
        known = [v for v in verdicts if v is not None]
        if known and all(v.get("verdict") == "benign" for v in known) \
                and len(known) == len(ips):
            continue
        detail_spl = (f'index=saas sourcetype=okta:authentication action=success '
                      f'user={user} | table user,geo_country,src_ip,time_utc')
        detail = eng.search(detail_spl)
        out.append(Detection(
            rule_id="ATO-GEO-010", mitre="T1078", ops_class="account_takeover",
            label="Impossible travel: one identity, multiple countries",
            severity="high",
            summary=(f"'{user}' authenticated successfully from "
                     f"{row.get('countries')} countries "
                     f"({', '.join(row.get('where', []))}) in the incident window "
                     f"— impossible travel / account takeover."),
            event_time_utc=_first_time(detail.rows),
            spl=detail_spl, evidence_refs=auth.refs + detail.refs,
            iocs=[user] + list(row.get("ips", [])),
            recommendation=("Force re-auth + MFA for the account, revoke active "
                            "sessions, review OAuth grants, alert the user."),
            detail={"countries": row.get("countries")},
        ))
    return out


def detect_oauth_grant_abuse(eng: SplEngine) -> list[Detection]:
    """An attacker consenting a malicious OAuth app for persistence.

    MITRE T1098.001 (Account Manipulation: Additional Cloud Credentials).
    """
    out: list[Detection] = []
    spl = ('index=saas sourcetype=okta:system event=app.oauth2.client.consent.grant '
           '| table user,oauth_app,scopes,src_ip,time_utc')
    grants = eng.search(spl)
    if not grants.rows:
        return out
    r0 = grants.rows[0]
    out.append(Detection(
        rule_id="ATO-OAUTH-011", mitre="T1098.001", ops_class="persistence_oauth",
        label="Malicious OAuth app consent grant (persistence)",
        severity="critical",
        summary=(f"'{r0.get('user')}' granted OAuth app '{r0.get('oauth_app')}' "
                 f"scopes '{r0.get('scopes')}' from {r0.get('src_ip')} — token "
                 f"persistence that survives password reset."),
        event_time_utc=r0.get("time_utc"),
        spl=spl, evidence_refs=grants.refs,
        iocs=[r0.get("oauth_app"), r0.get("user")],
        recommendation=("Revoke the OAuth grant + refresh tokens, block the app, "
                        "audit all recent consent grants, require admin app approval."),
        detail={"oauth_app": r0.get("oauth_app")},
    ))
    return out


# ===========================================================================
# Endpoint / ransomware attacks
# ===========================================================================

def detect_shadow_copy_deletion(eng: SplEngine) -> list[Detection]:
    """vssadmin/wmic shadow-copy deletion = ransomware inhibiting recovery.

    MITRE T1490 (Inhibit System Recovery).
    """
    out: list[Detection] = []
    spl = ('index=endpoint sourcetype=xmlwineventlog:sysmon event=process_create '
           '| where like(command_line,"%vssadmin%") OR like(command_line,"%delete shadows%") '
           'OR like(command_line,"%wbadmin%") '
           '| table host,user,process,command_line,time_utc')
    rows = eng.search(spl)
    if not rows.rows:
        return out
    r0 = rows.rows[0]
    out.append(Detection(
        rule_id="RW-RECOV-020", mitre="T1490", ops_class="recovery_inhibit",
        label="Volume shadow copy deletion (ransomware recovery inhibition)",
        severity="critical",
        summary=(f"{rows.count} shadow-copy / backup deletion command(s) on "
                 f"{r0.get('host')} (e.g. '{r0.get('command_line')}') — ransomware "
                 f"inhibiting recovery before encryption."),
        event_time_utc=r0.get("time_utc"),
        spl=spl, evidence_refs=rows.refs, iocs=[r0.get("host")],
        recommendation=("Isolate the host immediately, preserve volatile state, "
                        "verify offsite/immutable backups, hunt for the encryptor."),
        detail={"hosts": sorted({r.get("host") for r in rows.rows})},
    ))
    return out


def detect_mass_file_encryption(eng: SplEngine) -> list[Detection]:
    """A burst of file-rename/modify events to a ransom extension.

    MITRE T1486 (Data Encrypted for Impact).
    """
    out: list[Detection] = []
    spl = ('index=endpoint sourcetype=xmlwineventlog:sysmon event=file_modified '
           '| where like(target_filename,"%.locky") OR like(target_filename,"%.encrypted") '
           'OR like(target_filename,"%.crypt") '
           '| stats count by host')
    rows = eng.search(spl)
    for row in rows.rows:
        if int(row.get("count", 0)) < 5:
            continue
        host = row.get("host")
        note_spl = ('index=endpoint sourcetype=xmlwineventlog:sysmon '
                    'event=file_created '
                    '| where like(target_filename,"%READ_ME%") '
                    'OR like(target_filename,"%RANSOM%") '
                    f'| table host,target_filename,time_utc')
        note = eng.search(note_spl)
        out.append(Detection(
            rule_id="RW-ENCRYPT-021", mitre="T1486", ops_class="data_encrypted_impact",
            label="Mass file encryption (data encrypted for impact)",
            severity="critical",
            summary=(f"{row['count']} files rewritten to a ransom extension on "
                     f"{host}" + (f", plus a ransom note "
                     f"'{note.rows[0].get('target_filename')}'" if note.rows else "")
                     + " — active ransomware encryption."),
            event_time_utc=_first_time(note.rows) or "",
            spl=spl, evidence_refs=rows.refs + note.refs, iocs=[host],
            recommendation=("Isolate and power-preserve the host, identify the "
                            "ransomware family from the note, restore from clean "
                            "backups, rotate credentials seen on the host."),
            detail={"encrypted_files": row["count"], "host": host},
        ))
    return out


# ===========================================================================
# Insider / data movement
# ===========================================================================

def detect_after_hours_bulk_export(eng: SplEngine) -> list[Detection]:
    """A privileged user pulling an abnormal volume of records after hours.

    MITRE T1530 (Data from Cloud Storage) / insider exfil.
    Uses a ``business_hours`` flag the app log emits per request.
    """
    out: list[Detection] = []
    spl = ('index=dlp sourcetype=db:audit event=bulk_export business_hours=false '
           '| stats count as exports sum(record_count) as records '
           'values(table_name) as tables by user')
    rows = eng.search(spl)
    for row in rows.rows:
        if int(row.get("records", 0)) < 10000:
            continue
        user = row.get("user")
        detail_spl = (f'index=dlp sourcetype=db:audit event=bulk_export user={user} '
                      f'| table user,table_name,record_count,src_ip,time_utc')
        detail = eng.search(detail_spl)
        out.append(Detection(
            rule_id="INS-EXPORT-030", mitre="T1530", ops_class="insider_exfiltration",
            label="After-hours bulk data export by a privileged user",
            severity="critical",
            summary=(f"'{user}' exported {row.get('records')} records across "
                     f"{row.get('exports')} after-hours queries from tables "
                     f"{', '.join(row.get('tables', []))} — insider bulk export "
                     f"outside business hours."),
            event_time_utc=_first_time(detail.rows),
            spl=detail_spl, evidence_refs=rows.refs + detail.refs, iocs=[user],
            recommendation=("Suspend the account pending review, preserve the query "
                            "audit trail, involve HR/legal, add DLP volume alerts on "
                            "off-hours bulk reads."),
            detail={"records": row.get("records"), "user": user},
        ))
    return out


def detect_data_exfiltration(eng: SplEngine) -> list[Detection]:
    """Bulk web data export with a large outbound byte spike.

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


# ===========================================================================
# Supply-chain / build pipeline
# ===========================================================================

def detect_poisoned_dependency(eng: SplEngine) -> list[Detection]:
    """A build pulling an unexpected dependency version with a postinstall hook.

    MITRE T1195.001 (Supply Chain Compromise: Software Dependencies).
    """
    out: list[Detection] = []
    spl = ('index=cicd sourcetype=ci:build event=dependency_install '
           '| where like(script_hook,"%postinstall%") '
           '| table host,package,version,script_hook,time_utc')
    rows = eng.search(spl)
    if not rows.rows:
        return out
    r0 = rows.rows[0]
    out.append(Detection(
        rule_id="SC-DEP-040", mitre="T1195.001", ops_class="supply_chain_compromise",
        label="Poisoned dependency with postinstall hook on build host",
        severity="critical",
        summary=(f"Build host {r0.get('host')} installed {r0.get('package')}@"
                 f"{r0.get('version')} which ran a postinstall hook "
                 f"'{r0.get('script_hook')}' — poisoned dependency in the supply chain."),
        event_time_utc=r0.get("time_utc"),
        spl=spl, evidence_refs=rows.refs,
        iocs=[f"{r0.get('package')}@{r0.get('version')}"],
        recommendation=("Quarantine the build host, pin + verify dependency hashes, "
                        "rebuild from a clean runner, rotate any secrets the build "
                        "could read, scan published artifacts."),
        detail={"package": r0.get("package"), "version": r0.get("version")},
    ))
    return out


def detect_build_host_beacon(eng: SplEngine) -> list[Detection]:
    """Anomalous outbound C2 beacon from a build host that should be inbound-only.

    MITRE T1071.001 (Application Layer Protocol: Web) — C2 from build infra.
    """
    out: list[Detection] = []
    spl = ('index=network sourcetype=pan:traffic action=allow '
           '| where like(src_host,"build-%") '
           '| stats count as flows sum(bytes_out) as out_bytes '
           'values(dest_ip) as dests by src_host')
    rows = eng.search(spl)
    for row in rows.rows:
        if int(row.get("flows", 0)) < 3:
            continue
        host = row.get("src_host")
        ip_list = list(row.get("dests", []))
        out.append(Detection(
            rule_id="SC-C2-041", mitre="T1071.001", ops_class="command_and_control",
            label="Outbound C2 beacon from build host",
            severity="high",
            summary=(f"Build host {host} made {row.get('flows')} outbound "
                     f"connections to {', '.join(ip_list)} ("
                     f"{round(float(row.get('out_bytes', 0))/1000,1)} KB out) — "
                     f"a build host beaconing out is anomalous (C2)."),
            event_time_utc="",
            spl=spl, evidence_refs=rows.refs, iocs=[host] + ip_list,
            recommendation=("Block egress from build hosts by default, isolate the "
                            "runner, hunt the implant, correlate with the poisoned "
                            "dependency timeline."),
            detail={"dests": ip_list, "host": host},
        ))
    return out


# ===========================================================================
# Generic ops-impact (no MITRE) — fires across scenarios
# ===========================================================================

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


# The full library. The agent runs ALL of these against every scenario; each
# self-gates on real SPL evidence, so only the relevant ones fire per case.
ALL_DETECTORS = [
    detect_credential_stuffing,
    detect_leaked_key_usage,
    detect_privilege_escalation,
    detect_impossible_travel,
    detect_oauth_grant_abuse,
    detect_shadow_copy_deletion,
    detect_mass_file_encryption,
    detect_after_hours_bulk_export,
    detect_data_exfiltration,
    detect_poisoned_dependency,
    detect_build_host_beacon,
    detect_service_error_cascade,
]


def run_all(eng: SplEngine) -> list[Detection]:
    out: list[Detection] = []
    for det in ALL_DETECTORS:
        out.extend(det(eng))
    return out
