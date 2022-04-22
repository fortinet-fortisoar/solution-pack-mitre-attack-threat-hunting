# MITRE ATT&CK Threat Hunting

# Overview

The MITRE ATT&CK Threat Hunting Solution Pack demonstrates a variety of scenarios and use cases around threat hunting using the information provided by the MITRE ATT&CK Framework. 

*MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base issued as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community.*

## Pre-requisite

### Solution Packs

This Solution Pack requires the deployment of the following solution packs.

<table>
    <thead>
        <tr>
            <th>Solution Pack</th>
            <th>Purpose</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>SOAR Essentials</td>
            <td>Required for Hunt, Alert, and other modules</td>
        </tr>
        <tr>
            <td rowspan=2>SOC Simulator</td>
            <td>Required for module enacting various scenarios</td>
        </tr>
        <tr>
            <td>Required for SOC Simulator connector that ensures the SOC simulator connector is configured</td>
        </tr>
        <tr>
            <td rowspan=2>MITRE ATT&CK Enrichment Framework</td>
            <td>Required for Technique and Sub-Technique modules</td>
        </tr>
        <tr>
            <td>Require for MITRE ATT&CK Connector- Ensure that MITRE ATT&CK Connector is configured and ingestion is done</td>
        </tr>
    </tbody>
</table>

