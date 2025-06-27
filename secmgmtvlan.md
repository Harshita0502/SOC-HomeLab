# Security Management VLAN Documentation (secmgmtvlan)

## Overview
The **Security Management VLAN (192.168.20.0/24)** forms the backbone of the detection and monitoring infrastructure within this SOC simulation lab. It hosts all core security tools required for centralized management, log collection, alert triage, and rule development. This VLAN is strictly isolated from both the Attack and Target VLANs, with controlled access provided through pfSense firewall rules.

---

## VLAN Configuration
- **VLAN ID:** Custom VLAN implemented via pfSense on VirtualBox host-only adapters
- **Subnet:** 192.168.20.0/24
- **Gateway:** 192.168.20.1 (pfSense interface on secmgmtvlan)
- **DHCP:** Disabled — all machines use static IPs for predictable access
- **Network Isolation:** Enforced through pfSense VLAN segmentation and firewall policies
- **Promiscuous Mode:** Enabled at VirtualBox adapter level for proper traffic monitoring

---

## Devices & Roles

### 1. Kali Purple (192.168.20.10)
- **Purpose:** Primary analyst workstation, staging for security tooling
- **OS:** Kali Purple (Security-focused Debian-based distro)
- **Installed Components:**
  - Wazuh Manager
  - Wazuh API (bundled with Manager in v4.7.5+)
  - Wazuh Dashboard (Web UI)
  - Standard analyst tools (Wireshark, Nmap, Syslog tools)
- **Usage:**
  - Host and manage the Wazuh detection stack
  - Develop and test detection rules
  - Access the Wazuh Dashboard via browser
  - Potential staging for Security Onion if integrated

### 2. Security Onion (Optional) (192.168.20.11)
- **Purpose:** Deep packet inspection and network monitoring (Optional Phase)
- **OS:** Security Onion 2.x (ELK-based NIDS platform)
- **Planned Components:**
  - Zeek (formerly Bro)
  - Suricata IDS/IPS
  - TheHive, Cortex (optional, incident response tools)
- **Challenges:** Previous instability during deployment; currently excluded pending future reattempt
- **Future Role:** Enrich network visibility, assist in advanced detection scenarios

### 3. pfSense (Management Interface - 192.168.20.1)
- **Purpose:** Default gateway and traffic segmentation point for secmgmtvlan
- **Services:**
  - DHCP Server (Disabled)
  - Firewall and VLAN control
  - DNS Forwarding
  - Packet capture for troubleshooting

---

## Wazuh Stack Architecture
- **Manager:** Core detection engine, rule processing, log aggregation
- **API:** RESTful interface for automation and external integrations
- **Dashboard:** Web-based GUI for alert triage, visualization, and rule management

**Access URL:** https://192.168.20.10 (port 443)

**Known Issues:**
- Wazuh Dashboard may require manual permission fixes for `/usr/share/wazuh-dashboard`
- Service failures typically resolved via `systemctl status` analysis and log review

---

## Hardening & Best Practices
- Isolated VLAN prevents lateral movement from Attack VLAN
- Static IP addressing ensures consistent device mapping
- Wazuh API secured with authentication
- Dashboard only accessible within the VLAN
- pfSense firewall rules restrict inbound access strictly to trusted analyst machines
- System updates applied to Kali Purple and Wazuh regularly

---

## Detection Engineering in secmgmtvlan
- **Custom Wazuh Rules Deployed:**
  - Nmap scan detection from Attack VLAN
  - Powershell misuse on Target VLAN
  - Basic file integrity monitoring
- **Planned Enhancements:**
  - Sysmon log ingestion from Windows target via Wazuh agent
  - Sigma rule integration for cross-platform detections
  - Security Onion Zeek/Suricata rule tuning (Optional Phase)

---

## Troubleshooting Summary
| Issue                               | Resolution                                                       |
|-------------------------------------|-------------------------------------------------------------------|
| Wazuh Dashboard service failure     | Correct permissions, review logs, restart service                |
| pfSense VLAN routing inconsistencies| Validate pfSense interface assignments, check firewall rules     |
| VirtualBox NIC instability          | Standardize adapter type (Intel PRO/1000), enable promiscuous mode |
| Security Onion installation failure | Deferred, pending stable reattempt                               |

---

## Future Expansion Opportunities
- Full Security Onion integration for layered NIDS capabilities
- Integration with Target VLAN via secure Sysmon agent deployment
- Wazuh agent roll-out to additional lab VMs (optional Ubuntu target)
- Exploration of Proxmox or ESXi as a more robust virtualization backend

---

## Conclusion
The Security Management VLAN forms the technical and operational core of the SOC lab. It provides a secure, isolated environment to:
- Host detection and monitoring infrastructure
- Develop and tune detection rules
- Manage lab-wide visibility and telemetry
- Replicate real-world analyst workflows

This VLAN demonstrates the candidate's ability to design, deploy, and manage security tooling in a controlled environment, aligned with professional detection engineering practices.
