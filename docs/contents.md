| [Home](https://github.com/fortinet-fortisoar/solution-pack-mitre-attack-threat-hunting/blob/release/1.0.1/README.md) |
|----------------------------------------------------------------------------------------------------------------------|

# Contents

## Connector

| Name          | Description                                                                                                                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ElasticSearch | ElasticSearch is a distributed, RESTful search, and analytics engine capable of solving a number of use cases. This connector facilitates automated operations to execute lucene query, get mapping and cluster details. |


## Record Sets

| Scenario                                          | Description                                                                                                                                                                                                                                                                                               |
|:--------------------------------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| MITRE ATT&CK&reg; - Access Token Manipulation         | The scenario demonstrates the attacks where threat actors may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls.                                                                                                            |
| MITRE ATT&CK&reg; - Signed Binary Proxy Execution     | The scenario demonstrates the attacks where threat actors may bypass process and/or signature-based defenses by proxying execution of malicious content with signed binaries. Binaries signed with trusted digital certificates can execute on Windows systems protected by digital signature validation. |
| MITRE ATT&CK&reg; - Process Execution                 | The scenario demonstrates the Process Execution attacks by bypassing application control, using inter-process communication (IPC) mechanisms for local code or command execution, and using Windows Dynamic Data Exchange (DDE) to execute arbitrary commands.                                            |
| MITRE ATT&CK&reg; - Event Triggered Execution         | The scenario demonstrates the attacks using the technique Event Triggered Execution where threat actors establish persistence and elevated privileges using system mechanisms that trigger execution based on specific events.                                                                            |
| MITRE ATT&CK&reg; - Credential Access                 | The scenario demonstrates the attacks where threat actors attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password, from the operating system and software.                                                                   |
| MITRE ATT&CK&reg; - Boot or Logon Autostart Execution | The scenario demonstrates the attacks where threat actors may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on compromised systems.                                                                    |
| MITRE ATT&CK&reg; - Defense Evasion                   | The scenario demonstrates the attacks where threat actors exploit a system or application vulnerability to bypass security features.                                                                                                                                                                      |

## Playbook Collections

| 02 - Use Case - MITRE ATT&CK&reg; - Access Token Manipulation |
|:----------------------------------------------------------|

| Playbook Name                                  | Description                                                                                                                                                                                                               |
|:-----------------------------------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| HUNTS - SID-History Injection (T1134.005)      | Hunts for SID-History injection via Mimikatz and other tools. Also, hunts for SID-History added to accounts (success and failure). Adding SID-History may allow for escalated privileges if SID filtering is not enabled. |
| Fetch Alerts from SIEM                         | Fetches alerts by querying to SIEM                                                                                                                                                                                        |
| Generates Alerts for Access Token Manipulation | Demonstrates threat hunting scenario for the attacks using MITRE technique Access Token Manipulation [T1134] and generates demo Hunt, Alert, and Technique/Sub-Technique records for the same                             |

| 02 - Use Case - MITRE ATT&CK&reg; - Boot or Logon Autostart Execution |
|:------------------------------------------------------------------|

| Playbook Name                                          | Description                                                                                                                                                                                           |
|:-------------------------------------------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Fetch Alerts from SIEM                                 | Fetches alerts by querying to SIEM                                                                                                                                                                    |
| Generates Alerts for Boot or Login Autostart Execution | Demonstrates threat hunting scenario for the attacks using MITRE technique Boot or Login Autostart Execution [T1547] and Generates demo Hunt, Alert, and Technique/Sub-Technique records for the same |
| HUNTS - Winlogon Helper DLL (T1547.004)                | Hunts for abnormal DLL loads and processes spawned by Winlogon                                                                                                                                        |
| HUNTS - LSASS Driver (T1547.008)                       | Identifies process execution via loading an illegitimate LSASS driver (DLL). This technique can be used to execute a binary whenever LSASS executes.                                                  |

| 02 - Use Case - MITRE ATT&CK&reg; - Credential Access |
|:--------------------------------------------------|

| Playbook Name                               | Description                                                                                                                                                                           |
|:--------------------------------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Fetch Alerts from SIEM                      | Fetches alerts by querying to SIEM                                                                                                                                                    |
| Generates Alerts for OS Credential Dumping  | Demonstrates threat hunting scenario the attacks using MITRE technique OS Credential Dumping [T1003] and generates demo Hunt, Alert, and Technique/Sub-Technique records for the same |
| HUNTS - OS Credential Dumping (T1003)       | Hunts for non-Windows processes accessing the lsass.exe process, which can be indicative of credential dumping                                                                        |
| HUNTS - OS Credential Dumping (T1003) Part2 | Enriches LSASS.exe access information.                                                                                                                                                |

| 02 - Use Case - MITRE ATT&CK&reg; - Defense Evasion |
|:------------------------------------------------|

| Playbook Name                                          | Description                                                                                                                                                                                  |
|:-------------------------------------------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Fetch Alerts from SIEM                                 | Fetches alerts by querying to SIEM                                                                                                                                                           |
| Generates Alerts for Defense Evasion                   | Demonstrates threat hunting scenario for the attacks using MITRE technique Exploitation for Defense Evasion and generates demo Hunt, Alert, and Technique/Sub-Technique records for the same |
| HUNTS- Deobfuscate/Decode Files or Information (T1140) | Identifies the use of Certutil or copy /b to deobfuscate data/files.                                                                                                                         |
| HUNTS-DCShadow (T1207)                                 | Hunts for the execution of network traffic generated by Mimikatz module ‘DCShadow’. The network-based portion of this playbook requires network detection signatures.                        |

| 02 - Use Case - MITRE ATT&CK&reg; - Event Triggered Execution |
|:----------------------------------------------------------|

| Playbook Name                                    | Description                                                                                                                                                                                                  |
|:-------------------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Fetch Alerts from SIEM                           | Fetches alerts by querying to SIEM                                                                                                                                                                           |
| Generates Alerts for Event-Triggered Execution   | Demonstrates threat hunting scenario for the attacks using MITRE technique Event-Triggered Execution [T1546] and generates demo Hunt, Alert, and Technique/Sub-Technique records for the same                |
| HUNTS - AppInit DLLs (T1546.010)                 | Hunts for modification to AppInit DLLs registry keys.                                                                                                                                                        |
| HUNTS - Hidden Files and Directories (T1564.001) | Hunts for the use of attrib.exe to hide files.                                                                                                                                                               |
| HUNTS - Netsh Helper DLL (T1546.007)             | Hunts for abnormal DLL loads and processes spawned by netsh.exe.                                                                                                                                             |
| HUNTS - Screensaver (T1546.002)                  | Hunts for use of Windows Screensaver to enable attacker persistence. Hunts for abnormal screensaver executions, processes spawned by a screensaver, and abnormal modifications to screensaver registry keys. |

| 02 - Use Case - MITRE ATT&CK&reg; - Process Execution |
|:--------------------------------------------------|

| Playbook Name                             | Description                                                                                                                                                                   |
|:------------------------------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Fetch Alerts from SIEM                    | Fetches alerts by querying to SIEM                                                                                                                                            |
| Generates Alerts for Process Execution    | Demonstrates threat hunting scenario for the attacks using MITRE technique Process Execution and generates demo Hunt, Alert, and Technique/Sub-Technique records for the same |
| HUNTS - Dynamic Data Exchange (T1559.002) | Identifies processes spawned by a Microsoft Office product.                                                                                                                   |
| HUNTS - XSL Script Processing (T1220)     | Detects process execution by using XSL scripts. XSL scripts can allow a user to bypass application whitelisting by executing code through trusted OS binaries.                |

| 02 - Use Case - MITRE ATT&CK&reg; - Signed Binary Proxy Execution |
|:--------------------------------------------------------------|

| Playbook Name                                      | Description                                                                                                                                                                                       |
|:---------------------------------------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Fetch Alerts from SIEM                             | Fetches alerts by querying to SIEM                                                                                                                                                                |
| Generates Alerts for Signed Binary Proxy Execution | Demonstrates threat hunting scenario for the attacks using MITRE technique Signed Binary Proxy Execution [T1218] and generates demo Hunt, Alert, and Technique/Sub-Technique records for the same |
| HUNTS - CMSTP (T1218.003)                          | Identifies processes spawned by CMSTP.exe                                                                                                                                                         |
| HUNTS - Compiled HTML File (T1218.001)             | Identifies processes spawned by hh.exe                                                                                                                                                            |
| HUNTS - Control Panel Items (T1218.002)            | Identifies processes spawned by Control Panel files and execution of non-standard .cpl files                                                                                                      |
| HUNTS - InstallUtil (T1218.004)                    | Identifies process execution via InstallUtil and Installutil being passed via the command line (CMD, PS.WMIC)                                                                                     |
| HUNTS - Mshta (T1218.005)                          | Identifies Processes spawned by Mshta.exe                                                                                                                                                         |
| HUNTS - Regsvcs/Regasm (T1218.009)                 | Identifies processes spawned by Regsvcs and Regasm.                                                                                                                                               |
| HUNTS - Rundll32 (T1218.011)                       | Identifies Processes spawned by rundll32.exe where the DLL loaded exists outside of System32/SysWOW64 or Program Files. This playbook may require additional tuning to reduce false positives.    |

| 02 - Use Case - MITRE ATT&CK&reg; - Modulars |
|:-----------------------------------------|

| Playbook Name                                     | Description                                                                                        |
|:--------------------------------------------------|:---------------------------------------------------------------------------------------------------|
| Create Alert from Network Sensor and Link to Hunt | Creates and links an alert from a network-based sensor to a Hunt.                                  |
| Create and Link Alerts from Asset (Host-based)    | Creates and links alerts to an asset.                                                              |
| Create and Link Alerts from Hunt (Host-based)     | Creates and links an alert from a host-based sensor to a Hunt.                                     |
| Create and Link Indicator from Alert              | Creates and links indicators when an alert is created.                                             |
| Create and Link User                              | Creates a user (if it doesn't exist already), and links to specified emails, alerts, or incidents. |
| Create Asset from Alert                           | Links an asset to an alert if the hostname is present.                                             |
| Create User from Alert (Host)                     | Retrieves incidents related to the specified alert and creates and links users to that alert.      |
| Deduplicate Comments (Asset)                      | Deduplicates comments on asset records.                                                            |
| Deduplicate Comments (Hunt)                       | Deduplicates comments on Hunt records.                                                             |

| 02 - MITRE ATT&CK&reg; - System Services |
|:-------------------------------------|

>**NOTE:** There is no scenario record present for this MITRE Technique

| Playbook Name                                       | Description                                                                                                                 |
|:----------------------------------------------------|:----------------------------------------------------------------------------------------------------------------------------|
| ASSETS - Service Execution (Enrichment) (T1569.002) | Enriches service data and queries VirusTotal for reputation. Queries SIEM for all instances of any malicious hash observed. |
| ASSETS - Service Execution (T1569.002)              | Identifies on-OS services on a host and passes information to the next playbook for enrichment.                             |

>**WARNING:** It is recommended to clone these Playbooks before any customizations to avoid loss of information while upgrading the Solution Pack.
