# SOC-Investigations

## Alert 1: Inbound email containing suspicious external link (ID 8814)

**Severity (per SIEM rules): Medium
**Type: Phishing
**Alert time: Nov 4, 2026, 16:08
**Verdict: False positive

### Summary
The alert fired for an inbound email from `onboarding@hrconnex[.]thm` to `j.garcia@thetrydaily[.]thm` (subject "Action Required: Finalize Your Onboarding Profile", no attachment) because it contained an external link. After reviewing the email, the link, and related SIEM logs, I found internal evidence that the sender is the company's approved third-party HR partner, and classified the alert as a false positive.

### Investigation steps
1. **Email details.**
   - The sender domain is external to the recipient's company, as expected for a third-party platform.
   - The message was polite, with no urgency, threats, or credential requests. It asked the new employee to finish her profile setup.
2. **Link check.**
   - The link used HTTPS and the same domain as the sender (`hrconnex.thm`).
   - I checked it in TryDetectThis, a URL/IP/file reputation tool. Result: CLEAN.
3. **SIEM correlation (Splunk).**
   - I searched the mailbox activity around the alert time.
   - At 16:07:35, an internal email from `h.harris@thetrydaily[.]thm` to `j.carter@thetrydaily[.]thm` ("Unable to Receive Onboarding Email from hrconnex.thm") states that hrconnex.thm is the company's new third-party HR partner and that the new hire had not yet received her onboarding email.

### Findings
- The sender domain is a known, approved third-party HR vendor, confirmed by an internal email.
- The email matches a real, expected onboarding process.
- The URL has no malicious reputation, and the link domain matches the sender.
- No attachment, urgency, or credential request.

### Verdict
False positive. No escalation needed. Alert closed with notes.

### MITRE ATT&CK
Considered T1566.002 (Phishing: Spearphishing Link) and ruled it out based on the evidence above.
