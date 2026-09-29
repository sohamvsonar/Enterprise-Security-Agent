# Playbook: Data Exfiltration

**Triggers:** Large outbound transfer, rclone/megacmd execution, archiving of sensitive shares.

## Triage
1. Distinguish expected transfers (backups to internal hosts, e.g. BKP-01) from transfers to external IPs.
2. Check the destination against threat intel.
3. Identify the process and user responsible (EDR events on the source host).
4. Estimate data volume and which shares or paths were archived.

## Containment
- Isolate the host from the network through EDR.
- Block the destination IP and domain at the firewall.
- Preserve evidence before reimaging: memory, the archive file if still present, and logs.
- Note if logs were cleared (`wevtutil cl`); that points to deliberate anti-forensics.

## Escalation
- Payroll, tax or PII data: notify Legal and the DPO within 1 hour. Regulatory clock may apply.
