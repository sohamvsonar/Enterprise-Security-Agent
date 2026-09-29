# Playbook: Brute Force / Password Spraying

## Triage
1. Were **any** attempts successful from the source IP? If none succeeded and the IP is blocked, the risk is low.
2. Were real usernames targeted (for example `rgupta`) or only generic ones (`admin`, `root`)?
3. Check threat intel: opportunistic scanner vs targeted actor.

## Response
- Opportunistic, all failed, blocked: close as **low / no compromise**. Recommend key-only SSH.
- Any success: treat as account compromise.
