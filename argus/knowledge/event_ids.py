"""Windows Event ID knowledge base.

Maps the event codes seen in the Windows Event Viewer (Security / System /
Application / Defender / PowerShell / Sysmon channels) to a human-readable
one-liner, a normalised severity (1-5), a SIEM category, an ATT&CK technique,
and a short "what it means" hint used for the hover tooltips in the console.

`describe(id)` returns the record (or a generic fallback); `enrich(id, level)`
returns the effective (severity, category, mitre, name) used by the pipeline.
"""
from __future__ import annotations

from typing import Optional

# id: (name, severity, category, mitre, hint)
EVENT_IDS: dict[int, dict] = {
    # ---- Security · logon / authentication --------------------------------
    4624: {"name": "Successful logon", "severity": 2, "category": "authentication", "mitre": "",
           "hint": "An account was successfully logged on. Logon type reveals how (2=console, 3=network, 10=RDP)."},
    4625: {"name": "Failed logon", "severity": 4, "category": "authentication", "mitre": "T1110",
           "hint": "An account failed to log on. Repeated failures indicate password guessing / brute force."},
    4634: {"name": "Logoff", "severity": 1, "category": "authentication", "mitre": "",
           "hint": "An account was logged off."},
    4647: {"name": "User-initiated logoff", "severity": 1, "category": "authentication", "mitre": "",
           "hint": "The user deliberately signed out."},
    4648: {"name": "Logon with explicit credentials", "severity": 3, "category": "authentication", "mitre": "T1078",
           "hint": "A process logged on using credentials typed in explicitly (runas). Can indicate lateral movement."},
    4672: {"name": "Special privileges assigned", "severity": 3, "category": "authentication", "mitre": "T1078.002",
           "hint": "An admin-equivalent logon: sensitive privileges were granted to a new session."},
    4740: {"name": "Account locked out", "severity": 4, "category": "authentication", "mitre": "T1110",
           "hint": "An account was locked after too many bad passwords — classic brute-force symptom."},
    4768: {"name": "Kerberos TGT requested", "severity": 2, "category": "authentication", "mitre": "",
           "hint": "A Kerberos authentication ticket (TGT) was requested at logon."},
    4769: {"name": "Kerberos service ticket requested", "severity": 2, "category": "authentication", "mitre": "T1558.003",
           "hint": "A service ticket was requested. Bulk requests can indicate Kerberoasting."},
    4776: {"name": "NTLM credential validation", "severity": 2, "category": "authentication", "mitre": "",
           "hint": "The domain controller validated an NTLM credential."},
    4771: {"name": "Kerberos pre-auth failed", "severity": 4, "category": "authentication", "mitre": "T1110",
           "hint": "Kerberos pre-authentication failed — often a wrong password or AS-REP roasting attempt."},

    # ---- Security · account / group management ----------------------------
    4720: {"name": "User account created", "severity": 4, "category": "account-mgmt", "mitre": "T1136.001",
           "hint": "A new user account was created. Unexpected new accounts are a persistence red flag."},
    4722: {"name": "User account enabled", "severity": 3, "category": "account-mgmt", "mitre": "T1098",
           "hint": "A previously disabled account was enabled."},
    4724: {"name": "Password reset attempt", "severity": 3, "category": "account-mgmt", "mitre": "T1098",
           "hint": "An attempt was made to reset an account's password."},
    4725: {"name": "User account disabled", "severity": 2, "category": "account-mgmt", "mitre": "",
           "hint": "A user account was disabled."},
    4726: {"name": "User account deleted", "severity": 3, "category": "account-mgmt", "mitre": "",
           "hint": "A user account was deleted."},
    4728: {"name": "Member added to global group", "severity": 4, "category": "account-mgmt", "mitre": "T1098",
           "hint": "A member was added to a security-enabled global group (e.g. Domain Admins)."},
    4732: {"name": "Member added to local group", "severity": 4, "category": "account-mgmt", "mitre": "T1098",
           "hint": "A member was added to a security-enabled local group (e.g. Administrators)."},
    4756: {"name": "Member added to universal group", "severity": 4, "category": "account-mgmt", "mitre": "T1098",
           "hint": "A member was added to a security-enabled universal group."},

    # ---- Security · process / audit ---------------------------------------
    4688: {"name": "New process created", "severity": 2, "category": "process", "mitre": "T1059",
           "hint": "A new process was launched. Command-line auditing here is gold for hunting."},
    4689: {"name": "Process exited", "severity": 1, "category": "process", "mitre": "",
           "hint": "A process ended."},
    4697: {"name": "Service installed", "severity": 4, "category": "process", "mitre": "T1543.003",
           "hint": "A new Windows service was installed — a common persistence & privilege mechanism."},
    4698: {"name": "Scheduled task created", "severity": 4, "category": "process", "mitre": "T1053.005",
           "hint": "A scheduled task was created — frequently used for persistence."},
    4699: {"name": "Scheduled task deleted", "severity": 2, "category": "process", "mitre": "T1053.005",
           "hint": "A scheduled task was deleted."},
    1102: {"name": "Audit log cleared", "severity": 5, "category": "defense-evasion", "mitre": "T1070.001",
           "hint": "The Security audit log was cleared — a strong indicator someone is covering tracks."},
    4719: {"name": "Audit policy changed", "severity": 4, "category": "defense-evasion", "mitre": "T1562.002",
           "hint": "System audit policy was changed — attackers disable logging to hide."},

    # ---- System channel ---------------------------------------------------
    7045: {"name": "Service installed (System)", "severity": 4, "category": "process", "mitre": "T1543.003",
           "hint": "A service was installed (System log view). Check the binary path for oddities."},
    7040: {"name": "Service start type changed", "severity": 3, "category": "process", "mitre": "T1543.003",
           "hint": "A service's start mode changed (e.g. to Auto). Can indicate persistence tampering."},
    7036: {"name": "Service state changed", "severity": 1, "category": "system", "mitre": "",
           "hint": "A service entered the running or stopped state."},
    7034: {"name": "Service crashed", "severity": 3, "category": "system", "mitre": "",
           "hint": "A service terminated unexpectedly."},
    6005: {"name": "Event log service started", "severity": 2, "category": "system", "mitre": "",
           "hint": "The event log started — effectively a boot marker."},
    6006: {"name": "Event log service stopped", "severity": 2, "category": "system", "mitre": "",
           "hint": "The event log stopped — a clean shutdown marker."},
    6008: {"name": "Unexpected shutdown", "severity": 3, "category": "system", "mitre": "",
           "hint": "The previous shutdown was unexpected (power loss, crash, or forced)."},
    1074: {"name": "System shutdown/restart initiated", "severity": 2, "category": "system", "mitre": "",
           "hint": "A user or process initiated a shutdown/restart."},
    41:   {"name": "Kernel-Power (dirty reboot)", "severity": 3, "category": "system", "mitre": "",
           "hint": "The system rebooted without cleanly shutting down first."},
    219:  {"name": "Driver loaded", "severity": 2, "category": "system", "mitre": "T1543.003",
           "hint": "A driver was loaded into the kernel."},

    # ---- Microsoft Defender ----------------------------------------------
    1116: {"name": "Defender: malware detected", "severity": 5, "category": "malware", "mitre": "T1059",
           "hint": "Microsoft Defender detected malware on the endpoint."},
    1117: {"name": "Defender: action taken", "severity": 4, "category": "malware", "mitre": "",
           "hint": "Defender took action (quarantine/remove) against a threat."},
    5001: {"name": "Defender real-time protection disabled", "severity": 5, "category": "defense-evasion", "mitre": "T1562.001",
           "hint": "Real-time protection was turned off — attackers do this before dropping payloads."},
    5007: {"name": "Defender configuration changed", "severity": 3, "category": "defense-evasion", "mitre": "T1562.001",
           "hint": "A Defender setting was changed."},

    # ---- PowerShell operational ------------------------------------------
    4104: {"name": "PowerShell script block", "severity": 3, "category": "process", "mitre": "T1059.001",
           "hint": "A PowerShell script block was logged. Obfuscated/encoded blocks are suspicious."},
    4103: {"name": "PowerShell pipeline execution", "severity": 2, "category": "process", "mitre": "T1059.001",
           "hint": "A PowerShell command pipeline executed."},

    # ---- Sysmon (if installed) -------------------------------------------
    1:    {"name": "Sysmon: process create", "severity": 2, "category": "process", "mitre": "T1059",
           "hint": "Sysmon recorded a process creation with full command line and hashes."},
    3:    {"name": "Sysmon: network connection", "severity": 2, "category": "network", "mitre": "T1071",
           "hint": "Sysmon recorded an outbound/inbound network connection by a process."},
    11:   {"name": "Sysmon: file created", "severity": 2, "category": "fim", "mitre": "T1105",
           "hint": "Sysmon recorded a file being created."},
    13:   {"name": "Sysmon: registry value set", "severity": 3, "category": "fim", "mitre": "T1112",
           "hint": "Sysmon recorded a registry value modification — often persistence."},
    22:   {"name": "Sysmon: DNS query", "severity": 2, "category": "network", "mitre": "T1071.004",
           "hint": "Sysmon recorded a DNS lookup by a process."},

    # ---- PowerShell engine / host lifecycle (very common, usually noise) ---
    4100: {"name": "PowerShell pipeline error", "severity": 2, "category": "process", "mitre": "T1059.001",
           "hint": "A PowerShell command/pipeline raised an error. Usually a benign script/command failure; only interesting in bulk or alongside encoded commands."},
    4105: {"name": "PowerShell command started", "severity": 1, "category": "process", "mitre": "",
           "hint": "A PowerShell command began executing (command lifecycle logging)."},
    4106: {"name": "PowerShell command stopped", "severity": 1, "category": "process", "mitre": "",
           "hint": "A PowerShell command finished executing."},
    40961: {"name": "PowerShell console starting", "severity": 1, "category": "process", "mitre": "",
            "hint": "The PowerShell console host is initialising — routine startup noise."},
    40962: {"name": "PowerShell console ready", "severity": 1, "category": "process", "mitre": "",
            "hint": "The PowerShell console is ready for input — routine startup noise."},
    53504: {"name": "PowerShell IPC listener", "severity": 1, "category": "process", "mitre": "",
            "hint": "PowerShell started an inter-process-communication listening thread — routine."},
    400: {"name": "PowerShell engine started", "severity": 1, "category": "process", "mitre": "",
          "hint": "The PowerShell engine state changed to Available (started)."},
    403: {"name": "PowerShell engine stopped", "severity": 1, "category": "process", "mitre": "",
          "hint": "The PowerShell engine state changed to Stopped."},
    600: {"name": "PowerShell provider started", "severity": 1, "category": "process", "mitre": "",
          "hint": "A PowerShell provider (e.g. Registry, FileSystem) started."},

    # ---- Application / service reliability --------------------------------
    1000: {"name": "Application error (crash)", "severity": 3, "category": "system", "mitre": "",
           "hint": "An application crashed (faulting module recorded). Repeated crashes of security tools can indicate tampering."},
    1001: {"name": "Windows Error Reporting", "severity": 2, "category": "system", "mitre": "",
           "hint": "A crash/bugcheck report was generated by Windows Error Reporting."},
    1002: {"name": "Application hang", "severity": 3, "category": "system", "mitre": "",
           "hint": "An application stopped responding and was closed."},
    7000: {"name": "Service failed to start", "severity": 3, "category": "system", "mitre": "",
           "hint": "A Windows service failed to start."},
    7009: {"name": "Service start timeout", "severity": 3, "category": "system", "mitre": "",
           "hint": "A service did not respond to the start request in time."},
    7031: {"name": "Service crashed", "severity": 3, "category": "system", "mitre": "",
           "hint": "A service terminated unexpectedly and recovery action was taken."},
    10010: {"name": "DCOM server timeout", "severity": 2, "category": "system", "mitre": "",
            "hint": "A DCOM server did not register in time — common benign Windows noise."},
    10016: {"name": "DCOM permission denied", "severity": 2, "category": "system", "mitre": "",
            "hint": "An app lacked permission to launch a DCOM component — very common benign noise."},
    6013: {"name": "System uptime", "severity": 1, "category": "system", "mitre": "",
           "hint": "Daily system-uptime report."},

    # ---- Licensing / platform housekeeping (routine noise) ---------------
    16384: {"name": "SPP scheduling", "severity": 1, "category": "system", "mitre": "",
            "hint": "Software Protection Platform scheduled a licensing re-check — routine."},
    16394: {"name": "SPP migration OK", "severity": 1, "category": "system", "mitre": "",
            "hint": "Software Protection Platform offline migration succeeded — routine."},
    8198: {"name": "Licensing (SLUI) error", "severity": 2, "category": "system", "mitre": "",
           "hint": "A Windows activation/licensing check returned an error."},
    8200: {"name": "Licensing check", "severity": 1, "category": "system", "mitre": "",
           "hint": "A licensing acquisition check ran — routine."},
    1150: {"name": "Defender: client healthy", "severity": 1, "category": "system", "mitre": "",
           "hint": "Microsoft Defender / Endpoint Protection reported a healthy client state."},
    1151: {"name": "Defender: health report", "severity": 1, "category": "system", "mitre": "",
           "hint": "Microsoft Defender emitted a periodic client health report."},
    1531: {"name": "User profile service", "severity": 1, "category": "system", "mitre": "",
           "hint": "A user profile operation (load/unload) — routine."},
}

_LEVEL_SEVERITY = {"critical": 4, "error": 3, "warning": 3, "information": 2, "verbose": 1}


def describe(event_id: Optional[int]) -> dict:
    """Return the KB record for an id, or a generic descriptor."""
    if event_id is None:
        return {"name": "Event", "severity": 2, "category": "system", "mitre": "",
                "hint": "No description on file for this event code."}
    rec = EVENT_IDS.get(int(event_id))
    if rec:
        return {"id": int(event_id), **rec}
    return {"id": int(event_id), "name": f"Event {event_id}", "severity": 2,
            "category": "system", "mitre": "",
            "hint": f"Windows event {event_id} — no curated description yet. See Microsoft docs."}


def enrich(event_id: Optional[int], level: Optional[str] = None) -> dict:
    """Effective attributes for the pipeline, blending KB + the log's own level."""
    d = describe(event_id)
    if event_id is None or int(event_id) not in EVENT_IDS:
        # unknown code — fall back to the Windows level for severity
        if level:
            d = {**d, "severity": _LEVEL_SEVERITY.get(level.lower(), d["severity"])}
    return d
