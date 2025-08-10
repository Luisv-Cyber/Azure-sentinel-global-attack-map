# Azure Sentinel Global Attack Map — SOC Lab Project

## Overview
This lab simulates global brute-force RDP activity and uses Azure Sentinel to detect and visualize attack sources.  
It focuses on log collection, parsing, enrichment, and visualization for threat intelligence.

## Repo Contents
- `/scripts/rdp_log_parser.ps1` — PowerShell script to parse failed RDP logon events (Event ID 4625, LogonType 10) and optionally enrich with geolocation data.

## Tools & Technologies
- Azure Sentinel, Microsoft Defender, Azure Log Analytics
- PowerShell
- Event Viewer (Windows Security logs)
- Geolocation.io API

## Project Walkthrough & Visuals
A full step-by-step guide with screenshots and workbook output is available in my portfolio: [Luis Vega Cybersecurity Portfolio](https://bit.ly/41jjq8w)

## Author
Luis Vega
