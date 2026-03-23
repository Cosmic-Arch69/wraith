# Wraith Network Topology Guide

## Current Setup (Broken "External")

```
10.0.0.0/24 (same L2 broadcast domain)
├── Mac (10.0.0.x)
├── Kali Parallels VM (10.0.0.223) -- Bridged mode
├── pfSense WAN (10.0.0.183) -- Dell Proxmox VM 100
├── Dell Proxmox (10.0.0.31)
└── Lenovo Proxmox (10.0.0.21)

Behind pfSense (vmbr1):
├── VLAN 20 - Corporate (172.16.20.0/24) -- DC1, Win10, Win11
├── VLAN 30 - SecOps (172.16.30.0/24) -- Wazuh, MISP
└── VLAN 40 - DMZ (172.16.40.0/24) -- future
```

**Problem:** Kali and pfSense WAN are on the same L2 subnet. Kali can ARP pfSense directly -- no routing, no NAT traversal. This is NOT external per NIST 800-115 ("external tests are conducted from outside the security perimeter").

**Actual classification:** Adjacent network attack / internal segmentation test.

## Target Topology: Parallels Dual NIC

```
Kali VM (Parallels):
  NIC 1: Shared NAT (10.211.55.x) --> internet only (tool updates, apt)
  NIC 2: Custom vnet "attack-wan" (192.168.200.x) --> pfSense WAN

pfSense VM (Dell Proxmox):
  WAN: 192.168.200.1 (attack-wan segment)
  LAN: 172.16.20.1 (internal, unreachable from Kali)
```

### Setup Steps

1. Create custom network in Parallels:
   ```bash
   prlsrvctl net add attack-wan --type host-only
   ```

2. Add NIC 2 to Kali VM:
   ```bash
   prlctl set wraith-kali --device-add net --type custom --network attack-wan
   ```

3. Configure Kali NIC 2 (inside Kali):
   ```bash
   # /etc/network/interfaces.d/eth1
   auto eth1
   iface eth1 inet static
     address 192.168.200.10
     netmask 255.255.255.0
   ```

4. pfSense: Add WAN adapter on attack-wan segment
   - Option A: Add a new NIC to pfSense VM on Proxmox connected to a new bridge that routes to the Mac's custom vnet
   - Option B: Use Mac iptables/pf to route between attack-wan vnet and 10.0.0.183

5. Update Wraith config:
   ```yaml
   # configs/yashnet-external.yaml
   engagement:
     wan_ip: "192.168.200.1"
   ```

6. Verify:
   ```bash
   # From Kali
   ping 192.168.200.1       # pfSense WAN on attack-wan segment
   traceroute 172.16.20.5   # Should show pfSense hop, then DC1
   ping 10.0.0.183          # Should FAIL (not on 10.0.0.x anymore)
   ```

### Alternative (Simpler, No Proxmox Changes)

Keep Kali on Shared NAT, add Mac route:
```bash
sudo route add -host 10.0.0.183 10.0.0.1
```

Kali attacks via Mac's NAT -- traffic is routed, not L2 switched.
Less realistic but zero infrastructure changes.

## Engagement Mode Mapping

| Mode | Kali Position | What It Tests |
|------|--------------|---------------|
| External | NIC 2 (attack-wan) | Perimeter hardening, exposed services, firewall bypass |
| Internal | Behind pfSense (172.16.20.x) | AD attacks, lateral movement, segmentation |
| Assumed Breach | Behind pfSense + domain creds | Post-exploitation, detection/response |

## Sources

- NIST SP 800-115: "external tests from outside the security perimeter"
- PTES: scope definition separates internal/external IP ranges
- Parallels KB4948: network modes (Shared, Bridged, Host-Only)
