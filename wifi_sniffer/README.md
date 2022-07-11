# DJI Remote ID Sniffer
The project provides the source code for an example receiver implementation of WiFi-based DJI drones. It is able to detect DJI drones that are flying nearby by considering the reverse engineering work from Department 13 on DJI Remote ID.
For further information see the white paper from Department 13: *"Anatomy of DJI Drone ID Implementation"*.

The application continuously sniffs for beacon frame packets on the interface specified by the user as input and when a packet matches the specifiers from DJI Remote ID, it is processed to retrieve the information about the drone encoded. After retrieving this information, the drone is displayed on a map and a table shows all the information about that drone.

# Motivation
This project proves that everyone with basic knowledge and cheap hardware can build its own receiver for drone detection in order to stop relying on expensive product like the DJI Aeroscope. In this way, also possible disclosure of data could be avoided and custom receivers can be implemented based on the needs. Moreover, this work also considers the actual Regulation on Remote ID in drones that mandates the open broadcast of this information over standard communication protocols (e.g., Bluetooth or WiFi).

For more information about the Regulation on Remote ID see the [References](#references)

# Build status
The current implementation offers several functionalities:
  * TABLE showing drones information updated in real-time
  * MAP showing drones detected with a marker without tracking the path
  * LOG file created while the application is running. It contains all the detections along with the related timestamps
  * JSON file created while the application is running. Two JSON files are generated: one only stores the drones detected with last location and the other stores all the detections (both with the related timestamps)
  * TIMER (configurable) maintained for each drone detected to allow the application to stop detecting a drone if no more DJI Remote IDs are received from that drone

## Limitations / Bugs
The map does not update the changing position of a flying drone and it does not track the path.

The timer may not be respected if there are many drones nearby to detect. This happens for some delays such as the time wasted during the execution time.

The sniffer detects drones and shows them on the screen. When all the drones nearby disappear, the sniffer still continues showing drones until new drones appear, so until new packets are received.

# Technology and Frameworks
The application is written in Python by using Scapy tool to capture and manipulate the packets.

Two Python GUI frameworks are employed that are *Tkinter* and *TkinterMapView*.

To run the application a WiFi adapter is necessary.

# Installation 
Install the requirements for the application to run:

`pip install scapy`

`pip install tk`

`pip install tkintermapview`


Put the WiFi adapter in monitor mode to allow the laptop to monitor all the traffic received on a wireless channel:

`sudo ip link set <interface-name> down`

`sudo iwconfig <interface-name> mode monitor`

`sudo ip link set <interface-name> up`


Run the sniffer with the command:

`sudo python3 sniffer.py -i <interface-name>`

# Future version
This work is a first version of a DJI Remote ID Sniffer, but more functionalities can be added in order to have an application offering the same features of the DJI Aeroscope. Hence, the future developments include:
  * Add the tracking path of drones by using the methods provided by the [*TkinterMapView*](https://github.com/TomSchimansky/TkinterMapView) framework
  * Add mouse events when the user clicks on drones in the map view to show the drone's related information

# References
[FAA rule](https://www.faa.gov/uas/getting_started/remote_id)\
[EU rules 945/2019](https://eur-lex.europa.eu/eli/reg_del/2019/945/2020-08-09) and [EU rules 947/2019](https://eur-lex.europa.eu/eli/reg_impl/2019/947/2021-08-05)\
[ASTM standard](https://www.astm.org/f3411-22.html)\
[ASD-STAN standard](https://asd-stan.org/wp-content/uploads/ASD-STAN_DRI_Introduction_to_the_European_digital_RID_UAS_Standard.pdf)\
[Scapy](https://scapy.net/)\
[TkinterMapView](https://github.com/TomSchimansky/TkinterMapView)
