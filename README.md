# SOC Detection Lab - Professional Documentation

## Table of Contents
- [Project Overview](#project-overview)
- [Network Architecture](#network-architecture)
- [VLAN Breakdown](#vlan-breakdown)
- [Detection & Monitoring Stack](#detection--monitoring-stack)
- [Simulated Threat Scenarios](#simulated-threat-scenarios)
- [Detection Engineering](#detection-engineering)
- [Technical Challenges & Resolutions](#technical-challenges--resolutions)
- [Professional Improvements & Roadmap](#professional-improvements--roadmap)

---

## Project Overview
This project is a **fully isolated, virtualized Security Operations Center (SOC) Simulation Lab**, designed to replicate real-world detection engineering, incident response, and threat hunting workflows. It integrates core SOC components:

✅ Network segmentation via pfSense
✅ Detection tooling (Wazuh, Snort)
✅ Security Management environment
✅ Target hosts for controlled attacks
✅ Adversary simulation for testing detection efficacy

---

## Network Architecture
- **Virtualization Platform:** VirtualBox with isolated VLAN configuration
- **pfSense Firewall:** Central segmentation and traffic control
- **VLANs:**
  - `secmgmtvlan` (192.168.20.0/24) - Security management tools (Wazuh, Kali Purple)
  - `targetvlan` (192.168.10.0/24) - Windows & Ubuntu hosts
  - `attackvlan` (192.168.30.0/24) - Adversary simulation machine (Parrot OS)
- **Optional:** Security Onion integration for deep network visibility

Visual diagrams are provided in the `diagrams/` folder.

---

## VLAN Breakdown

### Security Management VLAN (192.168.20.0/24)
- **Kali Purple:** Hardened distro for analyst tasks, attack simulation staging, and Wazuh hosting.
- **Wazuh Stack:**
  - Manager, API, and Dashboard components
  - Custom detection rule development
  - Syslog and agent integration planned
- **Security Onion (Optional):**
  - Considered for Zeek and Suricata deployment

### Target VLAN (192.168.10.0/24)
- **Windows 10/11 VM:**
  - Sysmon planned for endpoint telemetry
  - Attack target for Powershell misuse, lateral movement simulation
- **Ubuntu VM:**
  - Optional target for Linux-focused attacks

### Attack VLAN (192.168.30.0/24)
- **Parrot OS:**
  - Toolset for controlled offensive operations (Nmap, Metasploit, etc.)
  - No internet exposure, strictly isolated for safety

---

## Detection & Monitoring Stack
- **pfSense:** VLAN segmentation, stateful firewalling, traffic capture
- **Snort (pfSense):** Inline IDS/IPS with signature tuning
- **Wazuh:**
  - Host and network-based detection
  - Log aggregation and rule development
  - Dashboard for alert triage
- **Planned:**
  - Sysmon for Windows telemetry
  - Zeek/Suricata for enriched network visibility

---

## Simulated Threat Scenarios
- Nmap port scans (Attack VLAN → Target VLAN)
- Powershell misuse & suspicious process creation (Windows Target)
- Brute-force login attempts (SSH/Windows RDP)
- Lateral movement & simple pivoting
- Malicious file transfers via SMB (Future Phase)

Detection effectiveness validated via Wazuh alerts and (optionally) Security Onion data.

---

## Detection Engineering
- **Custom Wazuh Rules:**
  - Powershell suspicious patterns
  - Nmap scan detection
  - Basic file integrity monitoring
- **Snort Rules:**
  - Port scan signatures
  - Exploit attempt identification
- **Planned Expansions:**
  - Sysmon rule tuning (Sigma integration possible)
  - Zeek scripting for anomalous behavior detection

---

## Technical Challenges & Resolutions
- **VirtualBox NIC instability:** Resolved via adapter type standardization and VLAN tagging
- **Wazuh installation failures (Kali Purple):** Overcame via repository fixes and system updates
- **Windows Target networking issues:** Addressed with manual IP configuration, gateway alignment, and pfSense troubleshooting
- **Security Onion deployment complexity:** Currently excluded for stability, future re-attempt planned

Detailed technical steps for each VLAN and tool are documented in their respective folders.

---

## Professional Improvements & Roadmap
- ✅ Current state:
  - Fully functional, segmented lab with detection coverage
  - Documented setup for reproducibility
  - Aligned with SOC and detection engineering fundamentals
- 🔧 Planned:
  - Sysmon deployment and rule tuning
  - Security Onion integration for enriched NIDS visibility
  - Expanded adversary simulation: file-based attacks, C2 channels
  - GreyMatter-aligned detection mapping
  - Transition to Proxmox or ESXi for enterprise-grade virtualization (optional)

---

## Author & Intent
**Harshita Indurkar**  
This documentation is suitable for students willing to pursue roles like:

- Junior Detection Engineer
- SOC Analyst (T1/T2)

---

## Disclaimer
This lab is strictly for educational, research, and professional demonstration purposes. No part of this project targets real-world environments beyond the isolated, virtualized infrastructure.
