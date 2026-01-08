# Networking Guide

This document explains the default network layout and common alternatives.

## Default (Dual-Bridge)
- Ollama runs on an internal bridge (no WAN access).
- SploitGPT runs on a WAN bridge (outbound only).
- Metasploit RPC binds to localhost.

Recommended for most users.

## Host Network Mode
Use when you need direct access to host VPN/WiFi interfaces.

High-level steps:
1. Disable the Ollama container and run Ollama on the host.
2. Set `SPLOITGPT_OLLAMA_HOST` to the host URL.
3. Run SploitGPT in host network mode.

## VLAN Isolation (Advanced)
Use VLANs for VM isolation with a dedicated subnet.

Typical pattern:
- Create VLAN on OPNsense (e.g., VLAN 30, subnet 192.168.56.0/24).
- Trunk VLAN to the host switch port.
- Create a VLAN interface (e.g., `br0.30`) on the host.
- Attach the isolated VM NIC to that VLAN interface.
- Apply OPNsense rules:
  - Allow VLAN -> WAN
  - Allow VLAN -> NGINX (specific IP/ports)
  - Block VLAN -> LAN

## Notes
- If your host has `br0` instead of `eno1`, that is normal for bridged VM networking.
- `virbr0`/`virbr1` are libvirt NAT networks (optional).

