# pfSense Configuration Documentation

## Overview
pfSense serves as the central firewall, router, and VLAN controller for this cybersecurity SOC simulation lab. It enforces strict network segmentation, manages routing between VLANs, provides internet connectivity (as required), and offers key network services to support detection and threat simulation.

---

## VirtualBox Network Configuration
- **Adapter 1 (WAN):**
  - Attached to: NAT or Bridged (for internet access)
  - Interface: `em0`
- **Adapter 2 (Security Management VLAN):**
  - Attached to: Host-only Adapter (custom for secmgmtvlan)
  - Interface: `em1`
- **Adapter 3 (Target VLAN):**
  - Attached to: Host-only Adapter (custom for targetvlan)
  - Interface: `em2`
- **Adapter 4 (Attack VLAN):**
  - Attached to: Host-only Adapter (custom for attackvlan)
  - Interface: `em3`

---

## VLAN & Interface Configuration

### Interfaces:
| Interface | Role                    | IP Address       | DHCP  |
|------------|-------------------------|------------------|-------|
| `em0`      | WAN (Internet)          | DHCP or Static   | N/A   |
| `em1`      | Security Management VLAN| 192.168.20.1/24  | Disabled |
| `em2`      | Target VLAN             | 192.168.10.1/24  | Disabled |
| `em3`      | Attack VLAN             | 192.168.30.1/24  | Disabled |

### DHCP:
- **Disabled** on all VLANs for static IP management
- Optional: Enable DHCP on Attack VLAN for easier attacker machine setup (if desired)

### Promiscuous Mode:
- Enabled in VirtualBox for all Host-only Adapters to allow traffic inspection and sniffing by security tools

---

## Firewall Rules
### General Policies:
- Default deny-all inbound policy on all VLANs
- Explicit rules to:
  - Allow traffic from Security Management VLAN to pfSense Web GUI (HTTPS)
  - Allow necessary DNS, DHCP, and ICMP as per VLAN requirements
  - Allow limited outbound internet access from Security Management VLAN (if needed)

### Example: Target VLAN Rules
| Action | Protocol | Source         | Destination    | Description                |
|--------|----------|----------------|----------------|----------------------------|
| Pass   | Any      | 192.168.10.0/24 | 192.168.20.10 | Allow target to send logs to Wazuh |
| Block  | Any      | 192.168.10.0/24 | Any            | Block other outbound traffic |

---

## Services Configured
- **DNS Forwarder/Resolver:** Enabled for VLANs
- **Web GUI Access:** Available on Security Management VLAN IP (`https://192.168.20.1`)
- **Packet Capture:** Useful for troubleshooting network issues
- **VLAN Segmentation:** Enforced at pfSense level

---

## Troubleshooting Summary
| Issue                     | Resolution                                           |
|---------------------------|-----------------------------------------------------|
| VLAN machines can't ping  | Verify VirtualBox adapter settings & pfSense config |
| pfSense Web UI unreachable| Confirm firewall rules & correct VLAN interface     |
| No internet on VLANs      | Check NAT rules and outbound firewall policies      |

---

## Hardening Recommendations
- Change default admin password
- Restrict Web UI access to trusted IPs only
- Disable unnecessary services (e.g., SSH, unless needed)
- Regularly update pfSense
- Backup configuration snapshots regularly

---

## Future Enhancements
- Implement IDS/IPS using Snort or Suricata directly on pfSense (optional)
- Explore VPN setup for remote lab access
- Integrate pfSense syslogs with Wazuh SIEM for firewall event visibility

---

## Conclusion
pfSense acts as the security and segmentation backbone of the lab, enabling:
- Robust VLAN isolation
- Controlled internet connectivity
- Centralized firewall rule management
- Reliable foundation for SOC lab simulations

Proper pfSense configuration demonstrates practical network engineering skills critical for real-world SOC environments.
