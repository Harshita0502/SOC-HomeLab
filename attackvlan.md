# Attack VLAN Documentation (attackvlan)

## Overview
The **Attack VLAN (192.168.30.0/24)** simulates the adversary environment within the SOC detection lab. It provides an isolated, controlled network where offensive operations can be safely executed to test the effectiveness of detection tools and incident response workflows. This VLAN is segmented from the Target and Security Management VLANs by pfSense, with strict firewall rules regulating traffic flow.

---

## VLAN Configuration
- **VLAN ID:** Configured via pfSense on VirtualBox internal adapters
- **Subnet:** 192.168.30.0/24
- **Gateway:** 192.168.30.1 (pfSense interface on attackvlan)
- **DHCP:** Disabled — attacker machines use static IPs for reproducibility
- **Network Isolation:** Enforced through pfSense VLAN segmentation and firewall rules
- **Promiscuous Mode:** Enabled for traffic visibility and packet crafting tools

---

## Devices & Roles

### 1. Parrot OS (192.168.30.10)
- **Purpose:** Dedicated attack simulation machine
- **OS:** Parrot Security OS (Penetration testing-focused Debian-based distro)
- **Installed Tooling:**
  - Nmap (Network scanning)
  - Metasploit Framework (Exploit development)
  - CrackMapExec (Lateral movement testing)
  - Netcat (Basic backdoors, reverse shells)
  - hping3 (Custom packet crafting)
  - Powershell exploit tools (targeting Windows machines)
- **Usage:**
  - Conduct port scans against Target VLAN
  - Simulate common attack vectors (reconnaissance, initial access, lateral movement)
  - Generate detectable events for Wazuh and other monitoring tools

### 2. pfSense (Attack VLAN Interface - 192.168.30.1)
- **Purpose:** Default gateway for attackvlan, traffic control, and segmentation
- **Services:**
  - VLAN interface for attackvlan
  - Firewall rules restricting outbound traffic beyond Target VLAN as needed
  - Optional packet capture for testing and visibility validation

---

## Common Attack Scenarios Executed
- **Network Scans:**
  - Full TCP SYN scans using `nmap`
  - Stealthy scans (FIN, XMAS, NULL)
- **Service Enumeration:**
  - Version detection scans
  - Banner grabbing
- **Exploit Simulation:**
  - Metasploit against known vulnerable services (if configured)
  - Powershell-based attacks on Windows target (mimicking real-world TTPs)
- **Lateral Movement (Planned):**
  - SMB enumeration with CrackMapExec
  - Credential testing if target is domain-joined (optional future phase)
- **Custom Payload Delivery:**
  - Netcat reverse shells
  - hping3-crafted packets for IDS/IPS evasion tests

---

## Detection Engineering Implications
- Attack VLAN provides consistent, repeatable adversary behavior to:
  - Validate Wazuh rule effectiveness
  - Test pfSense firewall configurations
  - Benchmark Security Onion detection coverage (if deployed)
  - Refine alert tuning for false-positive reduction

---

## Hardening & Control Measures
- Attack VLAN completely isolated from Security Management VLAN
- Only permitted to interact with Target VLAN through strictly controlled pfSense rules
- No internet access from Attack VLAN to prevent unintended risk
- Static IP addressing simplifies rule creation and event correlation
- Traffic monitored passively by Security Onion sensors (planned)

---

## Troubleshooting Summary
| Issue                               | Resolution                                                       |
|-------------------------------------|-------------------------------------------------------------------|
| Parrot OS network instability       | Verify VirtualBox NIC attachment to correct VLAN interface       |
| No connectivity to Target VLAN      | Validate pfSense firewall rules and VLAN assignments             |
| Detection tools not triggering      | Review attack methodology, ensure realistic traffic patterns      |
| Excessive false positives           | Tune Wazuh rules, adjust pfSense logging granularity              |

---

## Future Expansion Opportunities
- Integration of additional attacker VMs (Kali, C2 frameworks)
- Red team simulation tooling (Covenant, Empire)
- Adversary emulation frameworks (Atomic Red Team, Caldera)
- Automated attack scripts for continuous detection validation (Purple teaming workflows)

---

## Conclusion
The Attack VLAN serves as a critical adversary simulation environment, enabling:
- Safe, controlled execution of offensive operations
- Continuous validation of detection and monitoring tools
- Hands-on development of detection engineering skills
- Realistic SOC simulation through active red team style engagement

This VLAN demonstrates the candidate's understanding of:
- Offensive tooling
- Safe lab network design
- Integration of attack simulation into blue team processes
- Practical threat emulation aligned with professional SOC workflows
