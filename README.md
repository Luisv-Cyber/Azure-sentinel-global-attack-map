# 🌐 Azure Sentinel Global Attack Map — SOC Lab Project

**Project Type:** Cloud SOC Lab | Threat Visualization | Log Analytics | PowerShell Automation  
**Core Skills:** Azure Sentinel • Microsoft Defender • PowerShell • Log Analytics • API Integration • Security Monitoring  

---

## 🧭 Summary

This project demonstrates how to **detect and visualize global RDP brute-force activity** using Microsoft Azure Sentinel.  
I built a **cloud-based SOC lab** in Azure to collect Windows VM security logs, enrich them with **geolocation data via API**, and display the attack sources on an **interactive map** within Azure Sentinel.

The lab showcases a complete security operations workflow:  
**Log Collection → Enrichment → Ingestion → Visualization**

---

## 🧰 Tools & Technologies

- **Azure Subscription**
- **Windows Virtual Machine (VM)**
- **Microsoft Defender / Security Center**
- **Azure Log Analytics Workspace (LAW)**
- **Azure Sentinel**
- **PowerShell**
- **Event Viewer**
- **Geolocation.io API**
- **Custom Fields in Log Analytics**

---

## 🎯 Objective

Build a cloud-hosted SOC environment to **detect and visualize RDP brute-force attacks** across the globe.  
The project collects and enriches Windows Security logs from a virtual machine, adds geolocation metadata using a PowerShell script and Geolocation API, and ingests the results into Azure Sentinel for mapping and analysis.

### Goals

- Deploy and connect a **Windows VM** to **Log Analytics Workspace (LAW)**  
- Capture RDP brute-force security logs (Event ID 4625)  
- Use a PowerShell script to enrich logs with **latitude, longitude, country, and region**  
- Ingest enriched logs into **LAW via Custom Log + Custom Fields**  
- Visualize global attack origins on a **Sentinel Map Workbook**

---

## ⚙️ Steps Performed

### 1️⃣ Set Up the Lab Environment

- Created an **Azure subscription**, **Windows VM**, and **Virtual Network (VNet)**.  
- Configured inbound RDP rules to safely simulate external login attempts.  
- Enabled **Microsoft Defender for Cloud** to collect Security logs.  
- Connected the VM to an **Azure Log Analytics Workspace (LAW)** for centralized log ingestion.  

---

### 2️⃣ Generate & Capture Security Events

- Modified the **VM’s firewall** to allow inbound RDP traffic for simulation.  
- Connected via Remote Desktop and **intentionally failed logins** to generate Event ID **4625** (failed authentication).  
- Verified events in **Windows Event Viewer** under:  
  `Applications and Services Logs → Microsoft → Windows → Security → Audit Failure (4625)`  

---

### 3️⃣ Enrich Logs with Geolocation Data

- Obtained a **Geolocation.io API key**.  
- Wrote and executed a **custom PowerShell script** that:
  - Parsed Event Viewer logs for **source IP** and **timestamp**  
  - Called the **Geolocation.io API** to append:
    - `Latitude`
    - `Longitude`
    - `Country`
    - `Region`
  - Output a CSV file of enriched events ready for ingestion into LAW  

**Example PowerShell Logic (simplified):**
```powershell
# Example: Enrich failed RDP events with geolocation data
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 50

foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    $ip = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "IpAddress"} | Select-Object -ExpandProperty '#text'
    if ($ip -and $ip -ne "::1" -and $ip -ne "127.0.0.1") {
        $geo = Invoke-RestMethod -Uri "https://api.ipgeolocation.io/ipgeo?apiKey=YOUR_API_KEY&ip=$ip"
        [PSCustomObject]@{
            TimeCreated = $event.TimeCreated
            IpAddress   = $ip
            Country     = $geo.country_name
            City        = $geo.city
            Latitude    = $geo.latitude
            Longitude   = $geo.longitude
        }
    }
} | Export-Csv -Path .\rdp_failed_logons_geo.csv -NoTypeInformation
