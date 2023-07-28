# DJI DroneID Spoofer
It can advertise multiple fake Remote ID recognised by the DJI Aeroscope device as flying drones. Mainly based on the report from Department13 "Anatomy of dji drone id implementation re aeroscope". 

DJI drones broadcast flight information. In the case of models controlled through 802.11 standard, this informations is added as a payload to 802.11 Beacon type 
packets, in the Vendor ID tag. Therefore, using Scapy in that case, 802.11 Beacon packets can be created, and the payload can be modified at will.

The user can spoof: (a) 1 controlled DroneID (b) X drones with random values  (c) X drones with random values around a location point. When spoofing a single DroneID, the parameters location, speed, altitude, pilot location and others can be controlled using an XBOX controller/keyboard.

**Disclaimer**: This repository is not meant to be maintained nor updated. It is a proof of concept and is not intended for production use. The authors do not take any responsibility or liability for the use of the software. Please exercise caution and use at your own risk.

**Note:** A [spoofer program](https://github.com/cyber-defence-campus/droneRemoteID_spoofer),  which is able to spoof fake Remote ID information is kept in a separate repository. The spoofed Remote IDs can be DJI's proprietary format as well as the ASD-STAN format and can be used to test the drone monitoring system in this repository.

**Note:** A [drone monitoring system](https://github.com/cyber-defence-campus/RemoteIDReceiver) based on Remote IDs was also developed and is is published in another repository. The spoofed Remote IDs can be  can be used to test the drone monitoring system.

## Project structure
```bash
.
├── Beacon.py: Class reprenting the Beacon object, with all the fields according to 802.11. It builds a Beacon with Scapy
├── Beacon.pyc: Python generated file wiht the compiled bytecode from Beacon.py
├── Drone.py: Class reprenting a DroneID object. It builds the necessary DroneID fields according to the DJI format
├── README.md
├── __init__.py
├── interface-monitor.sh: Script to set WiFi interface in monitor mode, which is necessary to send/receive all wifi traffic.
├── main.py: Implement the logic of the spoofer. Creating DroneIDs objects from Drone class, creating Beacons associated to the DroneIDs, generating the whole 802.11 packet and transmiting them in a loop.
├── replay_mavic.py: Basic replay attack example. We replay a real Beacon captured (with Wireshark) from a DJI Mavic drone. 
├── requiremets.txt: Python modules to be installed.
```

## What do you need?
A WiFi adapter able to send packets is required.
A game controller (e.g., XBOX) or keyboard if you want to control more parameters of the DroneID.
A receiver GUI to visualize the spoofed drones (e.g., DJI Aeroscope or [Remote ID Monitoring System program](https://github.com/cyber-defence-campus/RemoteIDReceiver)).


## Usage

### Install requirements
The spoofer uses `scapy` to craft the 802.11 beacons with the DroneID info and to send it. To get the input from the keyboard or game controller `inputs` is used.

`$ pip3 install -r requirements.txt` 


### Set interface in monitor mode
First, you need to know the name of the interface that you will use to send the packets. Run the following command and copy the name of the interface to be used for transmiting:

`$ ip a` 

Second: 

`$ sudo ./interface-monitor.sh <interface-name>`

### 1. Spoof a single DroneID
If you have an XBOX controller or keyboard, you will be able to control: latitude, longitude, pilot longitude, pilot latitude, speed, altitude and yaw (where the aircraft is pointing to).
Otherwise, keyboard arrow can be used to modify latitude and longitude.

`$ sudo python3 main.py -i <interface-name> `



### 2. Spoof X DroneIDs
With that feature, X packets with random payloads will be spoofed. Parameters cannot be controlled. The drones will be spoofed at fixed random position.

`$ sudo python3 main.py -i <interface-name> -r <X>`

### 3. Spoof X DroneIDs around a specific location
With that feature, X packets with random payloads will be spoofed around a certai coordinates. Parameters cannot be controlled. The drones will be spoofed at fixed random position.

`$ sudo python3 main.py -i <interface-name> -r <X> -a '<latitude> <longitude>'`

### Script Flags:

The script can be customized with the following parameters.

| Flag short | Flag extended | Parameter                  | Default                                           | Description                                    |
|------------|---------------|----------------------------|---------------------------------------------------|------------------------------------------------|
| `-h`       | `--help`      | -                          | -                                                 | Displays help message                          |
| `-i`       | `--interface` | `n`: str                   | -                                   | Interface name                                 |
| `-r`       | `--random`    | `X`: int                   | 1                                                 | Spoof `X` DroneID with random values. Static location.       |
| `-a`       | `--area`   | `s`: str                   | -                                                 | Coordinates around which the DroneID location will be spoofed e.g.: -a '46.76 7.62 '                 |


## Other considerations / Troubleshooting
1. Sometimes the interface will stop transmiting with `Network is down` error. Run `./interface-monitor.sh` again.
2. Send packets with Scapy requires privileges, that is why `sudo` command is required.

## Contributors
DroneIDspoofer:  Llorenç Romá

WifiSniffer:     Beatrice Dallomo, @beatricedall
