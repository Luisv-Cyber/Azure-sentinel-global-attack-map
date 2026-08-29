![Azure Sentinel Attack Map banner](attack-map-banner.svg)

# 🌐 Azure Sentinel Global Attack Map — SOC Lab Project

**Project Type:** Cloud SOC Lab | Threat Visualization | Log Analytics | PowerShell Automation
**Core Skills:** Azure Sentinel • Microsoft Defender • PowerShell • Log Analytics • API Integration • Security Monitoring

---

## 🧭 Summary

This project demonstrates how to **detect and visualize global RDP brute-force activity** using Microsoft Azure Sentinel. I built a **cloud-based SOC lab** in Azure to collect Windows VM security logs, enrich them with **geolocation data via API**, and display the attack sources on an **interactive map** within Azure Sentinel.

The lab showcases a complete security operations workflow:
**Log Collection → Enrichment → Ingestion → Visualization**

---

## ⚠️ Lab Safety Note

This project intentionally exposes a VM to inbound RDP traffic to generate real brute-force attack data — it is a **deliberately vulnerable honeypot**, not a hardening exercise. If you rebuild this lab:

- Use a dedicated, isolated Azure subscription/resource group — never a production tenant or VNet
- Set a spending cap or budget alert (brute-force traffic can drive up Log Analytics ingestion costs)
- Tear down (delete) the VM and resource group when you're done testing to avoid ongoing charges and exposure

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

Build a cloud-hosted SOC environment to **detect and visualize RDP brute-force attacks** across the globe. The project collects and enriches Windows Security logs from a virtual machine, adds geolocation metadata using a PowerShell script and Geolocation API, and ingests the results into Azure Sentinel for mapping and analysis.

### Goals

- Deploy and connect a **Windows VM** to **Log Analytics Workspace (LAW)**
- Capture RDP brute-force security logs (Event ID 4625)
- Use a PowerShell script to enrich logs with **latitude, longitude, country, and region**
- Ingest enriched logs into **LAW via Custom Log + Custom Fields**
- Visualize global attack origins on a **Sentinel Map Workbook**

---

## 📁 Repository Structure

```
.
├── scripts/
│   └── rdp_log_parser.ps1   # Parses Event ID 4625 (LogonType 10) and enriches with geolocation
└── README.md
```

---

## ⚙️ Steps Performed

### 1️⃣ Set Up the Lab Environment

- Created an **Azure subscription**, **Windows VM**, and **Virtual Network (VNet)**.
- Configured inbound RDP rules to safely simulate external login attempts.
- Enabled **Microsoft Defender for Cloud** to collect Security logs.
- Connected the VM to an **Azure Log Analytics Workspace (LAW)** for centralized log ingestion.

---

### 2️⃣ Generate & Capture Security Events

- Modified the **VM's firewall** to allow inbound RDP traffic for simulation.
- Connected via Remote Desktop and **intentionally failed logins** to generate Event ID **4625** (failed authentication).
- Verified events in **Windows Event Viewer** under:
  `Applications and Services Logs → Microsoft → Windows → Security → Audit Failure (4625)`

---

### 3️⃣ Enrich Logs with Geolocation Data

- Obtained a **Geolocation.io API key**.
- Wrote and executed `scripts/rdp_log_parser.ps1`, which:
  - Parses Event Viewer logs for **source IP** and **timestamp** (filtering Event ID 4625, LogonType 10 — RDP specifically)
  - Calls the **Geolocation.io API** to append `Latitude`, `Longitude`, `Country`, and `Region`
  - Outputs a CSV file of enriched events ready for ingestion into LAW

**Simplified illustration of the enrichment logic** (see `scripts/rdp_log_parser.ps1` in this repo for the actual script):

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
```

> 🔑 Never commit a real API key to the script or the repo — pull it from an environment variable or a local, gitignored config file instead of hardcoding it.

---

### 4️⃣ Ingest Enriched Logs into Log Analytics

> **TODO:** Fill in your exact steps here — this section is reconstructed from your stated Goals and isn't in the current README. Typical flow:

- In the Log Analytics Workspace, go to **Custom logs → Add custom log** and upload a sample of the enriched CSV/log file.
- Define **Custom Fields** for `Latitude`, `Longitude`, `Country`, `City`, and `IpAddress` so they're queryable as structured columns rather than raw text.
- Confirm new enriched events are landing in the workspace under your custom log's `_CL` table.

---

### 5️⃣ Visualize on a Sentinel Map Workbook

> **TODO:** Add your actual KQL query and a screenshot of the finished map here — this is the single most convincing part of the project and the current README doesn't include it. A typical query for this kind of workbook looks like:

```kql
YourCustomLog_CL
| where isnotempty(Latitude_CF) and isnotempty(Longitude_CF)
| summarize EventCount = count() by IpAddress_CF, Country_CF, Latitude_CF, Longitude_CF
```

- In **Azure Sentinel → Workbooks**, create a new workbook and add this query as a **Map** visualization.
- Set the **latitude/longitude** fields and size markers by `EventCount` to show attack volume per origin.

---

## 📸 Results

> **TODO:** Add a screenshot of the final Sentinel map workbook showing global attack sources. A before/after (raw Event Viewer log → enriched map) is especially effective in a portfolio piece like this.

---

## 🧠 What This Demonstrates

- End-to-end SOC workflow: log collection → enrichment → ingestion → visualization
- Practical use of **PowerShell** to parse Windows Security event logs and call an external REST API
- Hands-on experience with **Azure Log Analytics** custom logs and custom field extraction
- Building and querying data in **Azure Sentinel** using **KQL**
- Understanding of a common real-world attack pattern (RDP brute-forcing) and how to detect it

---

## 🚀 Possible Improvements

- Automate the PowerShell script via a **scheduled task** so it runs continuously rather than manually
- Add **alert rules** in Sentinel to trigger on high-volume brute-force attempts from a single source
- Deduplicate/cache geolocation lookups to reduce API calls for repeat offenders
- Store the API key in **Azure Key Vault** instead of the script itself

---

## 👤 Author

**Luis Vega**
[GitHub](https://github.com/Luisv-Cyber)
