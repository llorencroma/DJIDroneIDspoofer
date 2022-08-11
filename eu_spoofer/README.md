# EU DroneID Spoofer
It can advertise fake drones compliant to the European standard ASD-STAN. The EU Spoofer was designed starting from a replay attack of the Parrot Anafi drone. This drone broadcasts while flying Remote ID information in beacon frames 802.11, where this information is added in the Vendor ID tag (with OUI equal to fa:0b:bc). Therefore, using Scapy 802.11 beacon frames can be created, and the Remote ID data can be modified at will.

The user can spoof: (a) 1 controlled DroneID (b) X drones with random values
While spoofing 1 controlled DroneID the user inputs some parameters that are:
* SSID
* Drone location
* Operator location
* Operator registration number (if any)
* Drone serial number

## What do you need?
* A WiFi adapter able to send packets is required. 
* A receiver able to detect drones compliant to the ASD-STAN standard. For test this code the Android receiver provided by [OpenDroneID](https://github.com/opendroneid/) project was used.

## Usage
For run the EU Spoofer the interface name must be known in advance and the interface must be set in monitor mode.

### Set interface in monitor mode
The following commands allow to set the interface in monitor mode.

`sudo ip link set <interface-name> down`

`sudo iwconfig <interface-name> mode monitor`

`sudo ip link set <interface-name> up`

### 1. Spoof a single DroneID
In order to run the EU Spoofer and spoof one drone the following command must be used:

`sudo python3 main.py -i <interface-name>`

Then the program waits for the user's input before spoofing the drone.

### 2. Spoof X DroneIDs
In order to run the EU Spoofer and spoof multiple drones with random parameters the following command must be used:

`sudo python3 main.py -i <interface-name> -r <X>`


## Limitations
The Android receiver used for testing is not official, indeed it is not present in any usual application stores and the application was built through Android Studio. Moreover, it only works with a group of devices and the reception could fail for various reasons.

The ASD-STAN standard as well as the security protocol on top of it are still under change and review. Hence, the format of the DroneID could change and maybe it will no longer be possible to spoof drones, it depends on the security protocol that might be implemented on top of the standard.
