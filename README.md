# MITRE ATT&CK Threat Hunting Solution Pack

## Release Information

- Solution Pack Version: 1.0.0
- FortiSOAR™ Version Tested on: 7.2.0
- Authored: Fortinet
- Certified: Yes

## Overview

### Introduction

*MITRE ATT&CK Threat Hunting Solution Pack* is designed to provide a set of threat hunting playbooks that demonstrates to users a variety of scenarios and use cases around threat hunting based on the information provided by the MITRE ATT&CK Framework.

Configure the data ingestion from SIEM using connectors such as Elasticsearch or Splunk. The hunting playbooks then trigger the hunt for the specified period mentioned in the hunt record and create an alert for the corresponding MITRE Technique.

Refer to the following Simulation Scenarios' to experience the use case without any SIEM configuration.

### Usage

This Solution Pack ships with the following simulation scenarios. [Refer](https://github.com/fortinet-fortisoar/solution-pack-soc-simulator/blob/develop/docs/solution-pack-guide.md) to Simulate Scenario documentation to understand how to Simulate and Reset Scenario.

#### 1. MITRE ATT&CK™ - Access Token Manipulation

The scenario demonstrates threat hunting for the attacks using the MITRE technique Access Token Manipulation [T1134] and generates corresponding demo Hunt, Alert and corresponding Technique/Sub-Technique records.

#### 2. MITRE ATT&CK™ - Boot or Logon Autostart Execution

The scenario demonstrates threat hunting for the attacks using MITRE technique Boot or Logon Autostart Execution [T1547] and generates corresponding demo Hunt, Alert and corresponding Technique/Sub-Technique records.

#### 3. MITRE ATT&CK™ - Credential Access

The scenario demonstrates threat hunting for the attacks using the MITRE technique OS Credential Dumping [T1003] and generates demo Hunt, Alert and Technique/Sub-Technique records

#### 4. MITRE ATT&CK™ - Defense Evasion

The scenario demonstrates threat hunting for the attacks using MITRE technique Exploitation for Defense Evasion and generates demo Hunt, Alert and Technique/Sub-Technique records

#### 5. MITRE ATT&CK™ - Event Triggered Execution

The scenario demonstrates threat hunting for the attacks using the MITRE technique Event-Triggered Execution [T1546] and generates demo Hunt, Alert and Technique/Sub-Technique records

#### 6. MITRE ATT&CK™ - Process Execution

The scenario demonstrates threat hunting for the attacks using MITRE technique Process Execution and generates demo Hunt, Alert and Technique/Sub-Technique records

#### 7. MITRE ATT&CK™ - Signed Binary Proxy Execution

The scenario demonstrates threat hunting for the attacks using the MITRE technique Signed Binary Proxy Execution [T1218] and generates demo Hunt, Alert and Technique/Sub-Technique records

Goto generated alerts and observe the following:

- MITRE Technique information (MITRE ID, Technique and Sub-Technique etc) is presented as a handy reference
- Attack details (Process ID, Process Name, File Path, Computer Name etc.) presented for analyzing the case

Goto generated hunt and observe the following:

- Summarized information of all the linked alerts is presented in the comments

## Prerequisites

**Solution Pack Name**|**Purpose**|**Doc Link**|
| :- | :- | :- |
|SOAR Framework 1.0.0|Require for Incident Response modules|[Click Here](https://github.com/fortinet-fortisoar/solution-pack-soar-framework/blob/develop/README.md)|
|SOC Simulator 1.0.1|Require for Scenario Module and SOC Simulator connector| [Click Here](https://github.com/fortinet-fortisoar/solution-pack-soc-simulator/blob/develop/README.md)|
|MITRE ATT&CK Enrichment Framework 2.0.2|Require for MITRE ATT&CK connector and modules|[Click Here](https://github.com/fortinet-fortisoar/solution-pack-mitre-attack-enrichment-framework/blob/develop/README.md)

## Contents

1. Connector(s)
    - Elasticsearch

2. Record Set(s)
    - Scenario:
        - MITRE ATT&CK™ - Access Token Manipulation
        - MITRE ATT&CK™ - Boot or Logon Autostart Execution
        - MITRE ATT&CK™ - Credential Access
        - MITRE ATT&CK™ - Defense Evasion
        - MITRE ATT&CK™ - Event Triggered Execution
        - MITRE ATT&CK™ - Process Execution
        - MITRE ATT&CK™ - Signed Binary Proxy Execution

3. Playbook Collection(s)
    - 02 - Use Case - MITRE ATT&CK™ - Access Token Manipulation

        |**Playbook Name**|**Description**|
        | :- | :- |
        |HUNTS - SID-History Injection (T1134.005)|Hunts for SID-History injection via mimikatz and other tools. Also hunts for SID-History added to accounts (success and failure). Adding SID-History may allow for escalated privileges if SID filtering is not enabled.|
        |Fetch Alerts from SIEM |Fetches alerts by querying to SIEM|
        |Generates Alerts for Access Token Manipulation |Demonstrates threat hunting scenario for the attacks using MITRE technique Access Token Manipulation [T1134] and generates demo Hunt, Alert and Technique/Sub-Technique records for the same|

    - 02 - Use Case - MITRE ATT&CK™ - Boot or Logon Autostart Execution

        |**Playbook Name**|**Description**|
        | :- | :- |
        |Fetch Alerts from SIEM |Fetches alerts by querying to SIEM|
        |Generates Alerts for Boot or Logon Autostart Execution |Demonstrates threat hunting scenario for the attacks using MITRE technique Boot or Logon Autostart Execution [T1547] and Generates demo Hunt, Alert and Technique/Sub-Technique records for the same|
        |HUNTS - Winlogon Helper DLL (T1547.004)| Hunts for abnormal DLL loads and processes spawned by Winlogon|
        |HUNTS - LSASS Driver (T1547.008) |Identifies process execution via loading an illegitimate LSASS driver (DLL). This technique can be used to execute a binary whenever LSASS executes.|

    - 02 - Use Case - MITRE ATT&CK™ - Credential Access

        |**Playbook Name**|**Description**|
        | :- | :- |
        |Fetch Alerts from SIEM |Fetches alerts by querying to SIEM|
        |Generates Alerts for OS Credential Dumping |Demonstrates threat hunting scenario the attacks using MITRE technique OS Credential Dumping [T1003] and generates demo Hunt, Alert and Technique/Sub-Technique records for the same|
        |HUNTS - OS Credential Dumping (T1003) |Hunts for non-Windows processes accessing the lsass.exe process, which can be indicative of credential dumping|
        |HUNTS - OS Credential Dumping (T1003) Part2| Enriches LSASS.exe access information.|

    - 02 - Use Case - MITRE ATT&CK™ - Defense Evasion

        |**Playbook Name**|**Description**|
        | :- | :- |
        |Fetch Alerts from SIEM |Fetches alerts by querying to SIEM|
        |Generates Alerts for Defense Evasion |Demonstrates threat hunting scenario for the attacks using MITRE technique Exploitation for Defense Evasion and generates demo Hunt, Alert and Technique/Sub-Technique records for the same|
        |HUNTS- Deobfuscate/Decode Files or Information (T1140) |Identifies the use of Certutil or copy /b to deobfuscate data/files.|
        |HUNTS-DCShadow (T1207) |Hunts for the execution of network traffic generated by Mimikatz module ‘DCShadow’. The network-based portion of this playbook requires network detection signatures.|

    - 02 - Use Case - MITRE ATT&CK™ - Event Triggered Execution

        |**Playbook Name**|**Description**|
        | :- | :- |
        |Fetch Alerts from SIEM| Fetches alerts by querying to SIEM|
        | Generates Alerts for Event-Triggered Execution |Demonstrates threat hunting scenario for the attacks using MITRE technique Event-Triggered Execution [T1546] and generates demo Hunt, Alert and Technique/Sub-Technique records for the same|
        |HUNTS - AppInit DLLs (T1546.010) |Hunts for modification to AppInit DLLs registry keys.|
        |HUNTS - Hidden Files and Directories (T1564.001) |Hunts for the use of attrib.exe to hide files.|
        |HUNTS - Netsh Helper DLL (T1546.007)| Hunts for abnormal DLL loads and processes spawned by netsh.exe.|
        |HUNTS - Screensaver (T1546.002)| Hunts for use of Windows Screensaver to enable attacker persistence. Hunts for abnormal screensaver executions, processes spawned by a screensaver, and abnormal modifications to screensaver registry keys.|

    - 02 - Use Case - MITRE ATT&CK™ - Process Execution

        |**Playbook Name**|**Description**|
        | :- | :- |
        |Fetch Alerts from SIEM |Fetches alerts by querying to SIEM|
        |Generates Alerts for Process Execution |Demonstrates threat hunting scenario for the attacks using MITRE technique Process Execution and generates demo Hunt, Alert and Technique/Sub-Technique records for the same|
        |HUNTS - Dynamic Data Exchange (T1559.002)| Identifies processes spawned by a Microsoft Office product.|
        |HUNTS - XSL Script Processing (T1220)| Detects process execution via the use of XSL scripts. XSL scripts can allow a user to bypass application whitelisting by executing code through trusted OS binaries.|

    - 02 - Use Case - MITRE ATT&CK™ - Signed Binary Proxy Execution

        |**Playbook Name**|**Description**|
        | :- | :- |
        |Fetch Alerts from SIEM |Fetches alerts by querying to SIEM|
        |Generates Alerts for Signed Binary Proxy Execution |Demonstrates threat hunting scenario for the attacks using MITRE technique Signed Binary Proxy Execution [T1218] and generates demo Hunt, Alert and Technique/Sub-Technique records for the same|
        |HUNTS - CMSTP (T1218.003)| Identifies processes spawned by CMSTP.exe|
        |HUNTS - Compiled HTML File (T1218.001) |Identifies processes spawned by hh.exe|
        |HUNTS - Control Panel Items (T1218.002)| Identifies processes spawned by Control Panel files and execution of non-standard .cpl files|
        |HUNTS - InstallUtil (T1218.004) |Identifies process execution via InstallUtil and Installutil being passed via the command line (CMD, PS.WMIC)|
        |HUNTS - Mshta (T1218.005)| Identifies Processes spawned by Mshta.exe|
        |HUNTS - Regsvcs/Regasm (T1218.009) |Identifies processes spawned by Regsvcs and Regasm.|
        |HUNTS - Rundll32 (T1218.011)| Identifies Processes spawned by rundll32.exe where the DLL loaded exists outside of System32/SysWOW64 or Program Files. This playbook may require additional tuning to reduce false positives.|

    - 02 - Use Case - MITRE ATT&CK™ - Link Techniques to Alerts and Incidents

        |**Playbook Name**|**Description**|
        | :- | :- |
        |Link ATT&CK technique to Alert |Links MITRE technique or sub-technique to Alert, based on MITRE Attack ID|
        |Link ATT&CK technique to Alert (On Update)| Links MITRE technique or sub-technique to Alert, based on MITRE Attack ID|
        |Link ATT&CK technique to Incident| Links MITRE technique or sub-technique to Incident, based on MITRE Attack ID|
        |Link ATT&CK technique to Incident (On Update)| Links MITRE technique or sub-technique to Incident, based on MITRE Attack ID|

    - 02 - Use Case - MITRE ATT&CK™ - Modulars

        |**Playbook Name**|**Description**|
        | :- | :- |
        |Create Alert from Network Sensor and Link to Hunt| Creates and links an alert from a network-based sensor to a Hunt.|
        |Create and Link Alerts from Asset (Host-based) |Creates and links alerts to an asset.|
        |Create and Link Alerts from Hunt (Host-based) |Creates and links an alert from a host-based sensor to a Hunt.|
        |Create and Link Indicator from Alert| Creates and links indicators when an alert is created.|
        |Create and Link User |Creates a user (if it doesn't exist already), and links to specified emails, alerts or incidents.|
        |Create Asset from Alert |Links an asset to an alert if the hostname is present.|
        |Create User from Alert (Host) |Retrieves incidents related to the specified alert and creates and links users to that alert.|
        |Deduplicate Comments (Asset) |Deduplicates comments on asset records.|
        |Deduplicate Comments (Hunt) |Deduplicates comments on Hunt records.|

    - 02 - MITRE ATT&CK™ - System Services

        **Note:** There is no scenario record present for this MITRE Technique

        |**Playbook Name**|**Description**|
        | :- | :- |
        |ASSETS - Service Execution (Enrichment) (T1569.002)| Enriches service data and queries VirusTotal for reputation. Queries SIEM for all instances of any malicious hash observed.|
        |ASSETS - Service Execution (T1569.002) |Identifies on-OS services on a host and passes information to the next playbook for enrichment.|

**Warning:** It is recommended to clone these Playbooks before any customizations to avoid loss of information while upgrading the Solution Pack.
