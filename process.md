# Process Alerts: Suspicious Parent Child Relationship

**Source:** TryHackMe SOC Simulator (lab data) | **Tools:** Splunk (Sysmon logs) | **Date of activity:** Nov 9, 2026

| Alert | Host | Process | Severity | Verdict |
|---|---|---|---|---|
| 1001 | `win-3459` | `TrustedInstaller.exe` from `services.exe` | Low | **False positive** |
| 1009 | `win-3453` | `rdpclip.exe` from `svchost.exe` | Low | **False positive** |

---

## Alert 1001: False positive

| Field | Value |
|---|---|
| Alert time | Nov 9, 2026, 13:59 |
| Host | `win-3459` |
| Process | `TrustedInstaller.exe` (PID 3577) |
| Parent | `services.exe` (PID 3506) |
| Command line | `C:\Windows\servicing\TrustedInstaller.exe` |

**Case note**

Closed as false positive. `TrustedInstaller.exe` was started by `services.exe` on `win-3459`. This is the Windows servicing process: path (`C:\Windows\servicing\`), parent and command line match the genuine file. It started no child processes, and the only other activity on the host was `TSTheme.exe` from `system32`. No sign of masquerading. No action needed. Suggest tuning the rule for this parent-child pair.

![Alert 1001](Images/proc-01-alert-1001.png)

**Evidence**

- **Other starts of the process:** one event in all Sysmon logs, from the expected path and parent.

![Search for TrustedInstaller.exe](Images/proc-02-search-trustedinstaller.png)

- **Child processes:** none started by PID 3577.

![Child process search, no results](Images/proc-03-children-1001.png)

- **Host activity:** two events only, `TSTheme.exe -Embedding` (13:55:07) and the TrustedInstaller start (13:57:24).

![Host activity](Images/proc-04-host-activity-1001.png)

**Verdict:** false positive. No escalation.

**Action:** tune the rule for `services.exe` starting `TrustedInstaller.exe` from `C:\Windows\servicing\`.

**MITRE ATT&CK:** T1036 considered, not supported.

---

## Alert 1009: False positive

| Field | Value |
|---|---|
| Alert time | Nov 9, 2026, 14:12 |
| Host | `win-3453` |
| Process | `rdpclip.exe` (PID 3565) |
| Parent | `svchost.exe` (PID 3925) |
| Working directory | `C:\Windows\system32\` |

**Case note**

Closed as false positive. `rdpclip.exe` (Remote Desktop clipboard) was started by `svchost.exe` on `win-3453`, which is normal when a remote session opens. It started no child processes. Other host activity was ordinary (Internet Explorer, Outlook, print spooler, `AtBroker.exe`), with no PowerShell, `cmd.exe`, `net`, `whoami` or `nslookup`. Searches for the win-3453 incident indicators found events on `win-3453` only, so no sign of lateral movement. No action needed. Suggest confirming with the host owner that the remote session was expected.

Same process as alert 1006 in [the win-3450 incident](incident-win-3450.md). Here the host showed no related activity.

![Alert 1009](Images/proc-05-alert-1009.png)

**Evidence**

- **Child processes:** none started by PID 3565.

![Child process search, no results](Images/proc-06-children-1009.png)

- **Host activity (6 events):** `iexplore.exe`, `AtBroker.exe` (started by `winlogon.exe`), `rdpclip.exe` at 14:11:28, `OUTLOOK.EXE` (started by `explorer.exe`), `spoolsv.exe`, a second `OUTLOOK.EXE` entry.

![Host activity](Images/proc-07-host-activity-1009.png)

- **Link to the incident:** a search for `powercat`, `ngrok`, `haz4rdw4re` and `hatmakereurope` returned events from `win-3450` only. One of the 53 events has no host name, probably the phishing email.

![Indicator search by host](Images/proc-08-indicator-search-1009.png)

**Verdict:** false positive. No escalation.

**Action:** confirm with the host owner or IT that the remote session at 14:11 was expected.

**Not confirmed:** where the remote session came from (no network logs). `spoolsv.exe` and the second `OUTLOOK.EXE` entry show only a process name.

**MITRE ATT&CK:** T1021.001 considered, not supported.
