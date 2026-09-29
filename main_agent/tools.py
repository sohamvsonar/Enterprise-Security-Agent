"""Investigation tools backed by the local sample dataset in ../data.

Each function is exposed to the agent as a tool, so the docstrings matter:
ADK sends them to the model as the tool descriptions.
Later these can be swapped for BigQuery / threat-intel API calls without
changing the agent.
"""

import csv
import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
MAX_ROWS = 50


def _load_csv(name: str) -> list[dict]:
    with open(DATA_DIR / name, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _matches(row: dict, **filters: str) -> bool:
    """Case-insensitive exact match on every non-empty filter."""
    return all(not v or row.get(k, "").lower() == v.lower() for k, v in filters.items())


def _result(rows: list[dict]) -> dict:
    return {"status": "success", "count": len(rows), "truncated": len(rows) > MAX_ROWS, "results": rows[:MAX_ROWS]}


def list_alerts(severity: str = "", status: str = "open") -> dict:
    """Lists SIEM alerts, the starting point of an investigation.

    Args:
        severity: Optional filter: info, low, medium, high or critical.
        status: Alert status filter. Defaults to "open". Pass "" for all.

    Returns:
        dict: matching alerts sorted by time.
    """
    return _result([a for a in _load_csv("alerts.csv") if _matches(a, severity=severity, status=status)])


def get_user(username: str) -> dict:
    """Looks up a user in the directory: department, manager, usual location, workstation, privileges and notes such as approved travel.

    Args:
        username: The account name, e.g. "jdoe".
    """
    for u in _load_csv("users.csv"):
        if u["username"].lower() == username.lower():
            return {"status": "success", "user": u}
    return {"status": "error", "error_message": f"User '{username}' not found."}


def get_asset(hostname_or_ip: str) -> dict:
    """Looks up an asset by hostname or IP: type, OS, owner, criticality and network zone.

    Args:
        hostname_or_ip: e.g. "FS-FIN-01" or "10.10.5.10".
    """
    key = hostname_or_ip.lower()
    for a in _load_csv("assets.csv"):
        if key in (a["hostname"].lower(), a["ip"]):
            return {"status": "success", "asset": a}
    return {"status": "error", "error_message": f"Asset '{hostname_or_ip}' not found in inventory."}


def search_auth_logs(username: str = "", source_ip: str = "", target_system: str = "", result: str = "") -> dict:
    """Searches authentication logs (logins, VPN, MFA). Leave a filter empty to ignore it.

    Args:
        username: Account name, e.g. "jdoe".
        source_ip: IP the login came from.
        target_system: System logged into, e.g. "VPN-GW-01" or "FS-FIN-01".
        result: "success", "failure" or "blocked".
    """
    rows = _load_csv("auth_logs.csv")
    return _result([r for r in rows if _matches(r, username=username, source_ip=source_ip,
                                                target_system=target_system, result=result)])


def search_network_logs(ip: str = "", hostname: str = "", domain: str = "") -> dict:
    """Searches network flow logs. `ip` matches source or destination; `hostname` matches the source host
    or destination domain; `domain` matches the destination domain. bytes_out is data sent by the source.

    Args:
        ip: An IP address on either side of the connection.
        hostname: e.g. "FS-FIN-01".
        domain: Destination domain, e.g. "m1crosoft-secure.com".
    """
    ip, hostname, domain = ip.lower(), hostname.lower(), domain.lower()
    out = []
    for r in _load_csv("network_logs.csv"):
        if ip and ip not in (r["src_ip"], r["dst_ip"]):
            continue
        if hostname and hostname not in (r["src_host"].lower(), r["dst_domain"].lower()):
            continue
        if domain and domain != r["dst_domain"].lower():
            continue
        out.append(r)
    return _result(out)


def search_endpoint_events(hostname: str = "", username: str = "", severity: str = "") -> dict:
    """Searches EDR endpoint events: process executions with command lines and detections.

    Args:
        hostname: e.g. "FS-FIN-01".
        username: Account that ran the process.
        severity: info, low, medium, high or critical.
    """
    rows = _load_csv("endpoint_events.csv")
    return _result([r for r in rows if _matches(r, hostname=hostname, username=username, severity=severity)])


def search_email_logs(recipient: str = "", sender: str = "", subject_contains: str = "") -> dict:
    """Searches mail gateway logs, including URLs, attachments and whether the recipient clicked the link.

    Args:
        recipient: Full or partial address, e.g. "jdoe".
        sender: Full or partial sender address or domain.
        subject_contains: Text contained in the subject.
    """
    out = []
    for r in _load_csv("email_logs.csv"):
        if recipient and recipient.lower() not in r["recipient"].lower():
            continue
        if sender and sender.lower() not in r["sender"].lower():
            continue
        if subject_contains and subject_contains.lower() not in r["subject"].lower():
            continue
        out.append(r)
    return _result(out)


def check_threat_intel(indicator: str) -> dict:
    """Checks an IP, domain or file hash (sha256) against the threat intelligence feed.

    Args:
        indicator: The IOC to look up.
    """
    intel = json.loads((DATA_DIR / "threat_intel.json").read_text(encoding="utf-8"))
    for i in intel:
        if i["indicator"].lower() == indicator.lower():
            return {"status": "success", "found": True, "intel": i}
    return {"status": "success", "found": False,
            "message": f"No threat intel for '{indicator}'. That does not mean it is safe."}


def get_playbook(name: str) -> dict:
    """Returns an incident response playbook.

    Args:
        name: One of "account_compromise", "phishing", "data_exfiltration", "brute_force".
    """
    path = DATA_DIR / "playbooks" / f"{name}.md"
    if not path.is_file():
        available = [p.stem for p in (DATA_DIR / "playbooks").glob("*.md")]
        return {"status": "error", "error_message": f"Unknown playbook '{name}'. Available: {available}"}
    return {"status": "success", "playbook": path.read_text(encoding="utf-8")}


ALL_TOOLS = [
    list_alerts, get_user, get_asset, search_auth_logs, search_network_logs,
    search_endpoint_events, search_email_logs, check_threat_intel, get_playbook,
]
