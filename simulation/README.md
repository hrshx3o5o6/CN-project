# Network simulation (Cisco Packet Tracer)

The P2P software is demonstrated on localhost. This folder models the **WAN the hospitals would run it on**,
so the networking side of the project (addressing, routing, inter-site reachability) is verifiable.

> The `.pkt` binary can only be authored inside Cisco Packet Tracer. Build it in ~15 min from the
> steps below, then save it as `F?_Team?_Simulation.pkt` in this folder.

## Topology (hub-and-spoke over a core router, 4 hospital LANs)

```
 Chennai LAN 10.1.0.0/24 --[R-CHN]--\                        /--[R-BLR]-- Bengaluru LAN 10.3.0.0/24
                                    [R-CORE]  (ISP / WAN)---
 Vellore LAN 10.2.0.0/24 --[R-VLR]--/                        \--[R-DEL]-- Delhi LAN       10.4.0.0/24
```

Each hospital LAN: 1 switch (2960), 1 server (the MedMesh node, `.10`), 1 PC (clinician workstation, `.20`).
Each hospital router connects to R-CORE over a /30 serial/ethernet link (`172.16.X.0/30`).

| Link | Subnet | Hospital-router side | R-CORE side |
|------|--------|----------------------|-------------|
| R-CHN – R-CORE | 172.16.1.0/30 | .2 | .1 |
| R-VLR – R-CORE | 172.16.2.0/30 | .2 | .1 |
| R-BLR – R-CORE | 172.16.3.0/30 | .2 | .1 |
| R-DEL – R-CORE | 172.16.4.0/30 | .2 | .1 |

Device configs are in `configs/` (paste into each router CLI). Routing is static for clarity
(OSPF alternative included in comments). ACL on each hospital router allows **only TCP 5001-5004 (MedMesh P2P)
and ICMP** between hospital LANs, mirroring the app's port usage.

## Packet Tracer build steps
1. Add 5 routers (2911), 4 switches (2960), 4 servers, 4 PCs. Use GigabitEthernet for all links.
2. Wire LAN: PC & Server -> switch -> hospital router `Gig0/0`. Router `Gig0/1` -> R-CORE (`Gig0/0`..`Gig0/3`).
3. Set server IPs `10.X.0.10/24` (gw `10.X.0.1`), PCs `10.X.0.20/24`.
4. Paste `configs/*.txt` into the routers.
5. On every server open *Services > HTTP* ON (stands in for the MedMesh dashboard port).
6. Test (record screenshots into `../screenshots/`):
   - `ping 10.3.0.10` from Chennai PC -> success (cross-hospital reachability)
   - `show ip route` on R-CORE -> 4 LAN routes
   - `show access-lists` on R-CHN -> hit counters after traffic
   - Browser on Chennai PC -> `http://10.2.0.10` (Vellore server) works
   - Simulation mode: trace an HTTP packet Chennai -> Vellore across the core.
7. Save as `F?_Team?_Simulation.pkt`.

## Mapping to the software
Real deployment: run `run_network.py --node chennai --port 5001 --bootstrap http://10.2.0.10:5002`
on each hospital's server. Nodes only need ONE reachable peer (gossip discovers the rest).
