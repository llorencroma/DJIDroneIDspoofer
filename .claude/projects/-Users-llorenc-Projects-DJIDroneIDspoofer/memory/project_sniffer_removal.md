---
name: sniffer_removal
description: User plans to completely remove the wifi_sniffer component from the project
type: project
---

User will remove the wifi_sniffer/ directory entirely. Do not make changes to sniffer files.

**Why:** User decision to simplify the project — sniffer is a separate concern.
**How to apply:** Skip any improvements targeting wifi_sniffer/. Focus only on the spoofer components (main.py, Drone.py, Beacon.py, replay_mavic.py).
