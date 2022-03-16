# DJI DroneID Spoofer
It can advertise thousands of fake drones recognised by the DJI Aeroscope device. Mainly based on the report from Department13 "Anatomy of dji drone id implementation re aeroscope". 

DJI drones broadcast flight information. In the case of models controlled through 802.11 standard, this informations is added as a payload to 802.11 Beacon type 
packets, in the Vendor ID tag. Therefore, using Scapy in that case, 802.11 Beacon packets can be created, and the payload can be modified at will.

The user can spoof: (a) 1 controlled DroneID (b) X drones with random values  (c) X drones with random values around a location point.
When spoofing a single DronwID, the location can be controlled using keyboard arrows. Location, speed, altitude, pilot location and others can be controlled using an XBOX controller.
 

## What do you need?
A WiFi adapter able to send packets is required.
XBOX controller if you want to control more parameters of the DroneID
An Aeroscope to visualize how the drone is visualised (working on a cheap Aeroscope)


## Usage
Now you can directly run `run-demo.sh` and choose one spoofing mode. You need to know the interface name in advance.
### Set interface in monitor mode
First, you need to know the interface's name. Run the following command and copy the name of the interface to be used for transmiting:

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

## Other considerations / Troubleshooting
1. Sometimes the interface will stop transmiting with `Network is down` error. Run `./interface-monitor.sh` again.
2. Send packets with Scapy requires privileges, that is why `sudo` command is required.
<<<<<<< HEAD
<<<<<<< HEAD
3. If you see 0 kb/s in the Aeroscope (top-left corner): do step 1 or unplug/plug usb from aeroscope
=======
=======
