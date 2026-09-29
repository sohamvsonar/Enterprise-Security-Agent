# Playbook: Phishing Email

**Triggers:** User-reported phishing, mail gateway detection, clicks on a known-bad URL.

## Triage
1. Extract the sender, sender domain, URLs and attachments.
2. Check every indicator against threat intel. Look for typosquats (for example `m1crosoft` vs `microsoft`).
3. Find all recipients of the same message (same sender and subject).
4. Determine who clicked: email click telemetry plus proxy/network logs to the URL's domain or IP.

## Containment
- Purge the message from every mailbox.
- Block the sender domain and URL domain/IP at the mail gateway and proxy.
- Anyone who clicked **and** later showed suspicious authentication: follow `account_compromise.md`.

## Notes
- A user who reported the email but did not click needs no further action; thank them.
