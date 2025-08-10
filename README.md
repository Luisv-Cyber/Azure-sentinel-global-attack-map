# Azure Sentinel Global Attack Map — SOC Lab Project

## Overview
This project simulates a global brute-force RDP attack and visualizes attack sources in Azure Sentinel.  
It demonstrates cloud-based log ingestion, enrichment, and visualization for threat intelligence.

## Objectives
- Deploy Azure Windows VM with open RDP to simulate brute-force activity.
- Collect and analyze failed login events using Microsoft Defender and Event Viewer.
- Parse event logs with PowerShell to extract IP addresses and timestamps.
- Enrich data with geolocation using the Geolocation.io API.
- Ingest enriched data into Azure Log Analytics Workspace.
- Create a Sentinel workbook to display a global attack map.

## Tools & Technologies
- Azure Sentinel
- Microsoft Defender
- Azure Log Analytics
- PowerShell
- Geolocation.io API
- Event Viewer

## Steps
1. **VM Deployment:** Deployed Azure Windows VM with open RDP inbound firewall rule.
2. **Log Generation:** Generated multiple failed RDP login events.
3. **Log Parsing:** Used `rdp_log_parser.ps1` to extract metadata.
4. **Data Enrichment:** Integrated Geolocation.io API for location data.
5. **Log Ingestion:** Uploaded enriched logs to Azure Log Analytics as custom logs.
6. **Visualization:** Built Sentinel workbook showing attack origins by location and magnitude.

## Project Details & Visuals
Full step-by-step guide with visuals is available on my portfolio: [Luis Vega Cybersecurity Portfolio](https://bit.ly/41jjq8w)

## Author
Luis Vega — [Portfolio](https://bit.ly/41jjq8w)
