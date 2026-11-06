# Phishing Investigations

**Environment:** TryHackMe SOC Simulator (lab data, no real users or organisations)
**Tools:** Splunk (SIEM), TryDetectThis (URL/IP/file reputation)

| Alert | Rule | Severity | Verdict | Reason in one line |
|---|---|---|---|---|
| 8814 | Inbound Email Containing Suspicious External Link | Medium | **False positive** | Approved third-party HR vendor, clean link, no firewall activity |
| 8815 | Inbound Email Containing Suspicious External Link | Medium | **True positive** | Fake Amazon sender, malicious shortened link, user's host tried to open it (blocked) |

---

## Case 1: Alert 8814 (False positive)

| Field | Value |
|---|---|
| Alert time | Nov 4, 2026, 16:08 |
| Sender | `onboarding@hrconnex[.]thm` |
| Recipient | `j.garcia@thetrydaily[.]thm` |
| Subject | Action Required: Finalize Your Onboarding Profile |
| Attachment | None |

![SIEM alert 8814](Images/01-siem-alert-8814.png)

### Summary

The alert fired for an inbound email with an external link. After reviewing the email, the link, the Splunk email logs and the firewall logs, I found internal evidence that the sender is the company's approved third-party HR partner. I classified the alert as a false positive.

### Investigation steps

**1. Email details**
- The sender domain is external, as expected for a third-party platform.
- The message is polite and asks a new employee to finish her profile setup. It has minimal urgency (the subject says "Action Required", which is normal for onboarding), no threats and no credential requests.
- No attachment.

**2. Link check**
- The link uses HTTPS and the same domain as the sender (`hrconnex[.]thm`). HTTPS alone is not proof of legitimacy, so this was only a supporting point.
- I checked the exact URL from the email in TryDetectThis. Result: **CLEAN**.

![TryDetectThis result](Images/02-trydetectthis-clean.png)

**3. SIEM correlation (Splunk, email logs)**
- At 16:07:35, an internal email from `h.harris@thetrydaily[.]thm` to `j.carter@thetrydaily[.]thm` ("Unable to Receive Onboarding Email from hrconnex[.]thm") states that `hrconnex[.]thm` is the company's new third-party HR partner and that the new hire had not yet received her onboarding email.

![Splunk internal email](Images/03-splunk-internal-email.png)

**4. Firewall check (Splunk)**
- I searched firewall logs for any connection to `hrconnex[.]thm`.
- No events were found, so there is no evidence that any endpoint attempted to access the link.

![Firewall search, no results](Images/04-splunk-firewall-no-results.png)

### Findings

- The sender domain is a known, approved third-party HR vendor, based on an internal email.
- The email matches a real, expected onboarding process.
- The URL has no malicious reputation, and the link domain matches the sender.
- No attachment, no credential request, minimal urgency.
- No firewall activity to the link's domain, so no evidence of user interaction in the available logs.

### Verdict and actions

**False positive.** No escalation needed. Alert closed with notes.

- Confirm the vendor with HR (or a vendor list) through a separate channel, since my verification relied on one internal email.
- If approved, add `hrconnex[.]thm` to the allowlist to reduce repeat false positives.

**MITRE ATT&CK:** considered T1566.002 (Phishing: Spearphishing Link) and ruled it out based on the evidence above.

---

## Case 2: Alert 8815 (True positive)

| Field | Value |
|---|---|
| Alert time | Nov 6, 2026, 13:56 |
| Email received | Nov 6, 2026, 13:54:15 |
| Sender | `urgents@amazon[.]biz` |
| Recipient | `h.harris@thetrydaily[.]thm` |
| Subject | Your Amazon Package Couldn't Be Delivered - Action Required |
| Attachment | None |

![SIEM alert 8815](Images/05-siem-alert-8815.png)

### Summary

An inbound email claiming to be an Amazon delivery notice, sent from `amazon[.]biz`, contained a shortened link. The link was rated malicious, and the firewall logs show an internal host tried to open it and was blocked. I classified the alert as a true positive.

### Investigation steps

**1. Email details**
- The email arrived during working hours and was sent to one employee.
- The sender domain `amazon[.]biz` is not an Amazon domain. It imitates the brand, and "urgents" in the sender name adds to that.
- The greeting is generic ("Dear Customer"), and the message claims a package could not be delivered because of an incomplete address.
- The message pushes the reader to act: "confirm your shipping information by clicking the link", with a 48-hour deadline before the package is "returned to sender".

**2. Link check**
- The link is `hxxp://bit[.]ly/3sHkX3da12340`.
- It uses unencrypted HTTP, and it is a URL shortener, so the real destination is hidden. The domain does not match the sender or Amazon.
- I checked the URL in TryDetectThis. Result: **MALICIOUS**.

![TryDetectThis result](Images/06-trydetectthis-malicious.png)

**3. Firewall check (Splunk)**
- I searched firewall logs for the link and found one event at 13:55:29, about 74 seconds after the email arrived.
- Source: internal host `10.20.2.17`. Destination: `67.199.248.11`, port 80 (TCP), application web-browsing.
- Action: **blocked**, by the rule "Blocked Websites".

![Firewall event, blocked](Images/07-splunk-firewall-blocked.png)

**4. Scope check (Splunk, email logs)**
- I searched all email logs for the sender `urgents@amazon[.]biz` and separately for the link. Both searches returned one event, the email to `h.harris`.
- No other recipients were found in the available logs.

![Email search by sender](Images/08-splunk-sender-search.png)
![Email search by link](Images/09-splunk-link-search.png)

### Findings

- Spoofed brand: `amazon[.]biz` is not an Amazon domain.
- Generic greeting, delivery pretext and a 48-hour deadline create pressure to click.
- The link is an unencrypted shortened URL, and TryDetectThis rated it malicious.
- An internal host (`10.20.2.17`) tried to open the link 74 seconds after delivery. The connection was blocked, and there is no evidence of a successful connection.
- Only one recipient and one email were found.
- The block came from the "Blocked Websites" rule, which may be a general policy and not a detection of this specific link. Because the link is shortened, the final destination is unknown.

### Verdict and actions

**True positive**, with the connection blocked. No sign of compromise in the available data, so no escalation of the incident.

Recommended actions:
- Block the sender `amazon[.]biz` at the email gateway.
- Remove the email from the recipient's mailbox.
- Tell the recipient not to click such links, and confirm whether they clicked.
- Check host `10.20.2.17` for other unusual activity.
- Escalate if other recipients or any allowed connection to the link are found.

**MITRE ATT&CK:** T1566.002 (Phishing: Spearphishing Link).

---



