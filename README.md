## **🎯Sudden Network Slowdowns Incident**

![Network Slowdowns](https://github.com/user-attachments/assets/55eefc0c-7e74-44a4-a8a4-c55ec5c5bdc5)


# Incident Investigation Report

## 📘 Scenario:
During a routine performance review, a noticeable degradation in network performance was observed on several legacy systems within the 10.0.0.0/16 subnet. After eliminating the possibility of external DDoS activity, the security team began investigating potential internal causes. The current network configuration allows unrestricted internal traffic by default, and users have broad access to tools such as PowerShell and other potentially sensitive applications. Given these conditions, there is concern that a user may be conducting unauthorized activities, such as downloading large volumes of data or performing internal port scans against other hosts on the local network.

---

## **📌 Incident Summary and Findings**

- 🎯 Goal: Gather relevant data from logs, network traffic, and endpoints.
Consider inspecting the logs for excessive successful/failed connections from any devices.  If discovered, pivot and inspect those devices for any suspicious file or process events.
- 🔍 Activity: Ensure data is available from all key sources for analysis.
- 📦 Log Tables to Analyze:
DeviceNetworkEvents
DeviceFileEvents
DeviceProcessEvents

```kql
DeviceFileEvents
| order by Timestamp desc 
| take 10

DeviceNetworkEvents
| order by Timestamp desc 
| take 10

DeviceProcessEvents
| order by Timestamp desc 
| take 10
```

### **📅 Timeline Overview**

1️⃣ Unusual Connection Failures Identified
- **🖥️ Host: maryanna-vm-mde was found failing several connection requests against another host on the same network**
- **📉 Behavior: Multiple failed connection attempts to itself and another internal host, suggesting internal scanning.**

**🔎 Detection Query (KQL):**
 ```kql
   DeviceNetworkEvents
   | where ActionType == "ConnectionFailed"
   | summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
   | order by ConnectionCount
   ```

![image](https://github.com/user-attachments/assets/2cdbed17-2008-497b-ad1e-fc404cfa8f80)


**2️⃣ Process Behavior Review**
   - **⚠️ Observation:** After observing failed connection requests from our suspected host (10.0.0.5) in chronological order, I noticed a port scan was taking place due to the sequential order of the ports. There were several port scans being conducted: 

**🔎 Detection Query (KQL):**
   ```kql
   let IPInQuestion = "10.0.0.185";
   DeviceNetworkEvents
   | where ActionType == "ConnectionFailed"
   | where LocalIP == IPInQuestion
   | order by Timestamp desc
   ```
   

**3️⃣ Network Process Timeline Correlation**
   - **📄 Suspicious Script Identified: portscan.ps1**
   - **⏰ Timestamp: 2025-04-29T13:32:45.925634Z**
   - **👤 User: SYSTEM**

**🔎 Detection Query (KQL):**
```kql
let VMName = "maryanna-vm-mde";
let specificTime = datetime(2025-04-29T13:32:45.925634Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```
**I logged into the suspect computer and observed the PowerShell script that was used to conduct the port scan:**

![image](https://github.com/user-attachments/assets/d7e03180-2d8c-4edc-a1af-516baa98bf50)


**4️⃣ Incident Response**

🔐 Action Taken:

-The script was executed by the SYSTEM account, which was both unexpected and unauthorized.

-The device was isolated from the network.

-Malware scan run — came back clean.

-Submitted ticket to re-image the machine.

-Shared findings with management for further review.

 **The malware scan produced no results, so out of caution, we kept the device isolated and put in a ticket to have it reimaged/rebuilt.**

---

# 🧠 MITRE ATT&CK Techniques Observed

| **Tactic**              | **Technique**                                                                 | **ID**    | **Insight**                                                                                    |
| ----------------------- | ----------------------------------------------------------------------------- | --------- | ---------------------------------------------------------------------------------------------- |
| 🛠️ Initial Access      | [Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/) | T1210     | Multiple failed internal connections suggest probing of exposed or weak services.              |
| 🧭 Discovery            | [Network Service Scanning](https://attack.mitre.org/techniques/T1046/)        | T1046     | `portscan.ps1` aligns with typical port scanning techniques.                                   |
| 💻 Execution            | [PowerShell Scripting](https://attack.mitre.org/techniques/T1059/001/)        | T1059.001 | Port scanning was executed using PowerShell script.                                            |
| 🪪 Persistence          | [Account Manipulation](https://attack.mitre.org/techniques/T1098/)            | T1098     | SYSTEM account usage suggests potential credential misuse.                                     |
| 🚀 Privilege Escalation | [Valid Accounts](https://attack.mitre.org/techniques/T1078/)                  | T1078     | SYSTEM-level access may have been abused to run unauthorized tasks.                            |
| 🕶️ Defense Evasion     | [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/) | T1027     | If script contents were obfuscated, this may indicate defense evasion tactics.                 |
| 🔥 Impact               | [Network Denial of Service](https://attack.mitre.org/techniques/T1498/)       | T1498     | The slowdown may have been caused by large-scale port scanning or traffic flooding internally. |

---

## 🧪 Reproduction Steps

1. Deploy a VM and assign a public or local IP.
2. Onboard it to Microsoft Defender for Endpoint.
3. Enable PowerShell execution policy.
4. Execute a simple port scanner PowerShell script.
5. Run KQL queries in the advanced hunting console to confirm detection.

---
