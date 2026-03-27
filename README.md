# DJI DroneID Spoofer

Advertises multiple fake Remote IDs recognised by DJI Aeroscope as flying drones. Based on the Department 13 report "Anatomy of DJI Drone ID Implementation re Aeroscope" and further protocol reverse engineering from Kismet, `proto17/dji_droneid`, and the NDSS 2023 DroneSecurity paper.

DJI drones broadcast flight information in 802.11 Beacon frames as a vendor-specific IE (OUI `26:37:12`). This tool crafts those frames using Scapy, allowing full control over all telemetry fields.

**Disclaimer**: Proof of concept only. Not intended for production use. The authors take no responsibility for misuse. Use only in authorised environments.

**Note:** A [Remote ID spoofer](https://github.com/cyber-defence-campus/droneRemoteID_spoofer) supporting both DJI proprietary and ASD-STAN formats is maintained separately.

**Note:** A [drone monitoring system](https://github.com/cyber-defence-campus/RemoteIDReceiver) based on Remote IDs is published in another repository.

---

## Project Structure

```
.
├── main.py               — Spoofer entry point: CLI, packet assembly, threading, input handling
├── Drone.py              — DroneID data model, telemetry/flight-info encoding, factory functions
├── Beacon.py             — 802.11 beacon frame construction (Scapy)
├── interface-monitor.sh  — Set WiFi interface to monitor mode
├── requirements.txt      — Python dependencies
└── README.md
```

---

## Requirements

- WiFi adapter capable of monitor mode and packet injection
- Root/sudo privileges
- Python 3.x
- Optional: XBOX controller or keyboard for single-drone control

---

## Setup

### Install dependencies

```bash
pip3 install -r requirements.txt
```

### Set interface to monitor mode

```bash
ip a                                      # find your interface name
sudo ./interface-monitor.sh <interface>
```

---

## Usage

### 1. Spoof a single DroneID

Prompts for SSID, coordinates, altitude, home location, UUID, identification, and flight info. If a gamepad is connected, use it to control latitude, longitude, pilot location, altitude, speed, and yaw in real time. Otherwise, arrow keys control latitude/longitude.

```bash
sudo python3 main.py -i <interface>
```

### 2. Spoof N random DroneIDs

Spoofs N drones with randomised parameters. Drones move continuously based on their velocity vectors.

```bash
sudo python3 main.py -i <interface> -r <N>
```

### 3. Spoof N random DroneIDs around a location

Same as above, but positions are clustered around the given coordinates.

```bash
sudo python3 main.py -i <interface> -r <N> -a '<latitude> <longitude>'
```

---

## CLI Flags

| Flag | Extended | Parameter | Default | Description |
|------|----------|-----------|---------|-------------|
| `-h` | `--help` | — | — | Help message |
| `-i` | `--interface` | `str` | required | WiFi interface in monitor mode |
| `-r` | `--random` | `int` | — | Spoof N random drones |
| `-a` | `--area` | `'lat lon'` | — | Center point for random drones, e.g. `'46.76 7.62'` |
| `-p` | `--product-type` | `str` | random | DJI model: `mavic_air`, `mavic_pro`, `spark`, `mavic_2`, `mavic_air_2`, `mavic_mini`, `mini_2`, `mavic_3`, `mini_3_pro` |
| — | `--identification` | `str` | `identification` | Identification string in flight info payload |
| — | `--flight-info` | `str` | `info` | Flight info string in flight info payload |

---

## Protocol Notes

The DJI DroneID telemetry payload is 91 bytes, embedded as the `info` field of a vendor-specific IE (ID=221, OUI=`0x263712`):

| Offset | Bytes | Field | Encoding |
|--------|-------|-------|----------|
| 0–2 | 3 | Magic header | `58 62 13` |
| 3 | 1 | Type | `10` (telemetry) / `11` (flight info) |
| 4 | 1 | Protocol version | `0x02` |
| 5–6 | 2 | Sequence number | u16 LE, increments each frame |
| 7–8 | 2 | State bitmask | u16 LE (motors, GPS, validity flags) |
| 9–24 | 16 | Serial number | ASCII |
| 25–28 | 4 | Longitude | s32 LE × 174533.0 |
| 29–32 | 4 | Latitude | s32 LE × 174533.0 |
| 33–34 | 2 | Altitude | u16 LE |
| 35–36 | 2 | Height AGL | u16 LE |
| 37–42 | 6 | Velocity N/E/Up | s16 LE × 100 |
| 43–44 | 2 | Yaw | s16 LE, `(deg − 180) × 100` |
| 45–46 | 2 | Roll | s16 LE |
| 47–48 | 2 | Pitch | s16 LE |
| 49–56 | 8 | Controller GPS time | u64 LE milliseconds (zeroed) |
| 57–60 | 4 | Pilot latitude | s32 LE × 174533.0 |
| 61–64 | 4 | Pilot longitude | s32 LE × 174533.0 |
| 65–68 | 4 | Home longitude | s32 LE × 174533.0 |
| 69–72 | 4 | Home latitude | s32 LE × 174533.0 |
| 73 | 1 | Product type | See `PRODUCT_TYPES` in Drone.py |
| 74 | 1 | UUID length | u8 |
| 75+ | var | UUID | ASCII, zero-padded to 91 bytes |

Sources: [Kismet dot11_ie_221_dji_droneid.h](https://github.com/kismetwireless/kismet), [proto17/dji_droneid](https://github.com/proto17/dji_droneid), [RUB-SysSec/DroneSecurity (NDSS 2023)](https://github.com/RUB-SysSec/DroneSecurity), Department 13 report.

---

## Troubleshooting

- **`Network is down` error** — Re-run `sudo ./interface-monitor.sh <interface>`.
- **`sudo` required** — Scapy needs root privileges to send raw packets.
- **No gamepad detected** — Falls back to keyboard arrow keys automatically.

