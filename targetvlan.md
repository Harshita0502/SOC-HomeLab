# Target VLAN Documentation (targetvlan)

## Overview
The **Target VLAN (192.168.10.0/24)** simulates a typical enterprise environment containing vulnerable hosts. It serves as the primary zone for adversary activity simulation, detection validation, and endpoint telemetry collection.

This VLAN is **strictly segmented** from both the Attack and Security Management VLANs, with access controlled via pfSense. It replicates real-world conditions where attackers pivot from compromised endpoints and security teams rely on host and network telemetry for detection.

---

## VLAN Configuration
- **VLAN ID:** Target VLAN implemented through pfSense on VirtualBox host-only adapters
- **Subnet:** 192.168.10.0/24
- **Gateway:** 192.168.10.1 (pfSense interface on targetvlan)
- **DHCP:** Disabled — static IP addressing applied for consistent lab behavior
- **Network Isolation:** Enforced through pfSense firewall rules
- **Promiscuous Mode:** Enabled on VirtualBox adapters for traffic analysis compatibility

---

## Devices & Roles

### 1. Windows 10/11 Target (192.168.10.3)
- **Purpose:** Simulated endpoint for attacker compromise, lateral movement, and detection validation
- **Configuration:**
  - Static IP: 192.168.10.3
  - Default Gateway: 192.168.10.1
  - DNS Server: Typically pfSense or external via pfSense
- **Security Telemetry:**
  - Planned: Sysmon deployment with custom configuration
  - Sysmon logs to be forwarded to Wazuh Manager on Security Management VLAN
- **Attack Scenarios:**
  - Powershell misuse
  - Suspicious process creation
  - Lateral movement (RDP/SMB exploitation)
  - Malicious file transfers
- **Known Issues:**
  - Initial networking instability resolved via static IP configuration
  - Ensured proper VLAN assignment and pfSense routing

### 2. Ubuntu Target (Optional) (192.168.10.4)
- **Purpose:** Optional Linux endpoint for expanding detection scenarios
- **Use Cases:**
  - SSH brute-force simulations
  - Linux-specific malware testing
  - Syslog forwarding to Wazuh (future phase)

---

## Detection Considerations
- **Host-Based Detection (Planned):**
  - Sysmon with Wazuh Agent
  - Powershell and process monitoring
  - File integrity monitoring
- **Network-Based Detection:**
  - pfSense firewall and Snort IPS monitoring traffic
  - Optional: Security Onion (Zeek/Suricata) for enriched visibility

---

## Hardening & Best Practices
- Strict VLAN segmentation prevents unauthorized inbound access
- Static IPs ensure predictable host mapping
- Sysmon to be configured with minimal logging overhead, focusing on high-fidelity events
- Windows system hardened with:
  - Disabled unnecessary services
  - Applied security patches
  - Limited RDP/SMB exposure (except for controlled attack scenarios)

---

## Simulated Attack Scenarios
- Nmap scanning from Attack VLAN to identify open ports
- Powershell-based attacks (e.g., reverse shells, malicious scripts)
- Brute-force password attempts (RDP/SSH)
- File-based malware delivery via SMB or USB simulation
- Lateral movement from Windows to Ubuntu target (future phase)

Each scenario validates detection efficacy through Wazuh alerts, Snort logs, and (optionally) Security Onion telemetry.

---

## Troubleshooting Summary
| Issue                               | Resolution                                                        |
|-------------------------------------|--------------------------------------------------------------------|
| No internet access                  | Verified pfSense gateway settings, corrected static IP config     |
| Inaccessible from Security VLAN     | Checked pfSense firewall rules and VLAN assignments               |
| Windows not receiving telemetry     | Wazuh Agent installation pending, Sysmon deployment planned       |

---

## Future Expansion Opportunities
- Automated Sysmon deployment via PowerShell scripts
- Sysmon to Sigma rule conversion for enhanced detection engineering
- Ubuntu target integrated into detection pipeline
- Integration with enterprise-grade logging solutions (Graylog, Elastic) if lab scales
- Active Directory simulation for realistic attack surface

---

## Conclusion
The Target VLAN introduces controlled, vulnerable endpoints into the lab, essential for:
- Testing detection rule effectiveness
- Validating adversary simulation exercises
- Emulating real-world SOC environments
- Demonstrating practical detection engineering skills

It highlights the candidate's capability to design and secure an isolated attack surface, suitable for detection validation aligned with industry standards.
