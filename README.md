<img width="1200" height="725" alt="Tor Image" src="https://github.com/user-attachments/assets/cf318ae6-dea8-49ad-b679-ea99ffdfd053" />

# Threat Hunt Report: Unauthorized TOR Usage
Detection of Unauthorized TOR Browser Installation and Use on Workstation: talha-threat-hu
- [Scenario Creation](https://github.com/talha-im/Threat-Hunting-Scenario-Tor/blob/main/Event-Creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

A search for files beginning with the string "tor" revealed that user `talha` downloaded a Tor Browser installer on host `talha-threat-hu`. It is highly likely that the installer was executed, resulting in multiple Tor-related files being created on the desktop. These events were first observed on `2025-12-22T20:39:01.6466378Z`.

**Query used to locate events:**
```kql
DeviceFileEvents
| where DeviceName startswith "talha-threat"
| where FileName startswith "tor"
| project Timestamp, DeviceName, Account = InitiatingProcessAccountName, ActionType, FileName
| order by Timestamp asc
```
<img width="1006" height="264" alt="image" src="https://github.com/user-attachments/assets/0f7939c5-795d-4b74-bea1-4607f8d83ed7" />


### 2. Searched the `DeviceProcessEvents` Table

A search for any `ProcessCommandLine` containing `tor-browser-windows-x86_64-portable-15.0.3.exe` revealed that on `2025-12-22T20:55:17.0094929Z`, user `talha` on host `talha-threat-hu` executed the Tor Browser installer from their Downloads folder. The installer was run with the `/S` (silent) switch, indicating a non-interactive installation, which automatically deployed Tor Browser without user prompts.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "talha-threat-hu"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.3.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine

```
<img width="1026" height="268" alt="image" src="https://github.com/user-attachments/assets/d7412bd8-53aa-4c06-9c58-db92074b4e9a" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

A search of the `DeviceProcessEvents` table for processes associated with Tor Browser revealed that user `talha` on host `talha-threat-hu` actively launched the Tor Browser. The first execution was observed at `2025-12-23T02:13:47 UTC` (`tor.exe`), with several subsequent instances of `firefox.exe` and `tor.exe` processes spawned, consistent with the Tor Browser runtime.

These events indicate that the user not only installed Tor Browser but also executed it, resulting in multiple Tor-related processes running, potentially enabling anonymized browsing or communications from the host.
**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "talha-threat-hu"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine
| order by Timestamp desc
```
<img width="1217" height="329" alt="image" src="https://github.com/user-attachments/assets/98b1a58e-05c4-4858-bab7-5025b0dbddc3" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Analysis of `DeviceNetworkEvents` showed that `tor.exe` on host `talha-threat-hu`, running under user `talha`, successfully established outbound network connections. At `2025-12-23 01:57:45 UTC`, a connection was made to `188.245.58.189` over TCP port `9001`, a port commonly associated with Tor relay traffic.

Additional successful connections to other Tor-related ports (9001, 9030, 9040, 9050, 9051, and 9150) were also observed, confirming active Tor network communication from the endpoint.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "talha-threat-hu"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, Account = InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc

```
<img width="1393" height="307" alt="image" src="https://github.com/user-attachments/assets/376eb418-d489-441a-9649-e6c5af882dfb" />

---

### 5. Searched the `DeviceFileEvents` to look for any suspicious files created after installation of the TOR Browser

A review of post-execution file creation events identified a text file named `drug list.txt` created on host `talha-threat-hu` within one hour of Tor Browser activity. The file was created at `2025-12-23 02:19:17 UTC` by user `talha` using `Notepad.exe` and was located within the Tor Browser directory on the desktop, indicating user activity shortly after Tor usage.


**Query used to locate events:**
```kql
let torInstallTime = datetime(2025-12-22T20:56:24.9137061Z);
DeviceFileEvents
| where DeviceName startswith "talha-threat"
| where Timestamp between (torDownloadTime .. (torDownloadTime + 1h))
| where ActionType == "FileCreated"
| project Timestamp, DeviceName,Account = InitiatingProcessAccountName, ActionType, FileName, InitiatingProcessCommandLine
```
<img width="1029" height="266" alt="image" src="https://github.com/user-attachments/assets/884f7157-fc3f-4925-b809-9945e931a2f0" />

---

## Chronological Event Timeline 

| Time (UTC)          | Event Type            | Description                                                                 |
| ------------------- | --------------------- | --------------------------------------------------------------------------- |
| 2025-12-22 20:39:01 | File Download         | Tor Browser installer downloaded on host `talha-threat-hu` by user `talha`. |
| 2025-12-22 20:55:17 | Silent Installation   | `tor-browser-windows-x86_64-portable-15.0.3.exe` executed with `/S` switch. |
| 2025-12-23 01:57:45 | Network Connection    | `tor.exe` established outbound connection to `188.245.58.189` on port 9001. |
| 2025-12-23 02:13:47 | TOR Browser Execution | `tor.exe` launched; multiple `firefox.exe` processes spawned.               |
| 2025-12-23 02:19:17 | File Created          | `drug list.txt` created using Notepad in Tor Browser directory.             |


---

## Summary

User `talha` on host `talha-threat-hu` downloaded, silently installed, and actively used the Tor Browser, with multiple `tor.exe` and `firefox.exe` processes observed. The browser established outbound connections to Tor-related ports (e.g., 9001), and a text file (`drug list.txt`) was created shortly afterward, indicating immediate follow-on user activity.

Overall, these findings indicate unauthorized installation and use of an anonymity tool, successful establishment of anonymized network connections, and follow-on user activity, representing a potential policy violation and elevated security risk that warrants further review and response.

---

## Response Taken

TOR usage was confirmed on the endpoint `talha-threat-hu` by the user `talha`. The device was isolated, and the user's direct manager was notified.

---
