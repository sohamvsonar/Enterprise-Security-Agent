# Playbook: Compromised User Account

**Triggers:** MFA push fatigue, impossible travel, login from a known-malicious IP.

## Triage
1. Confirm the source IP's reputation in threat intel.
2. Compare the login geo with the user's usual location and any approved travel notes.
3. Check whether the user was active from a normal location at the same time (impossible travel).
4. Look for a phishing email the user received or clicked in the last 24 hours.

## Scope
- List every system the account authenticated to after the suspicious login.
- Check endpoint events on those systems for the same username.
- Review outbound network traffic from those systems.

## Containment
- Disable the account and revoke all sessions and refresh tokens.
- Reset the password and re-register MFA; enable number matching.
- Terminate any active VPN session tied to the account.

## Severity
- **Critical** if the account touched a critical asset or data left the network.
- **High** if the login succeeded but no further activity is found.
