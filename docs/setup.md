| [Home](https://github.com/fortinet-fortisoar/solution-pack-mitre-attack-threat-hunting/blob/develop/README.md) |
|-----------------------------------------------------------------------------------------------------------------------------------|

# Installation

1. To install a solution pack, click **Content Hub** > **Discover**.
2. From the list of solution pack that appears, search for and select **MITRE ATT&CK Threat Hunting**.
3. Click the **MITRE ATT&CK Threat Hunting** solution pack card.
4. Click **Install** on the bottom to begin installation.

## Prerequisites

| Solution Pack Name                | Purpose                                                  |
|:----------------------------------|:---------------------------------------------------------|
| SOAR Framework                    | Required for Incident Response modules                   |
| SOC Simulator                     | Required for Scenario Module and SOC Simulator connector |
| MITRE ATT&CK Enrichment Framework | Required for MITRE ATT&CK connector and modules          |

# Configuration

For optimal performance of **MITRE ATT&CK Threat Hunting** solution pack, you can install and configure:

- A data ingestion process to periodically search and read events, alerts, and other notables from a data source and convert them into actionable items, such as alerts, in FortiSOAR
    - To configure and use the Splunk connector for data ingestion, refer to [Configuring Splunk Connector](https://docs.fortinet.com/document/fortisoar/1.6.2/splunk/130/splunk-v1-6-2#Configure_Data_Ingestion)
    - To configure and use the ElasticSearch connector for data ingestion, refer to [Configuring ElasticSearch Connector](https://docs.fortinet.com/document/fortisoar/2.2.1/elasticsearch/19/elasticsearch-v2-2-1#Configuration_parameters)