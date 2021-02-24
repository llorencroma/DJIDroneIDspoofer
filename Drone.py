import random, string
from math import floor
import time, os
import struct


class Drone:
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
                   
        self.ssid = kwargs['ssid'] if "ssid" in kwargs and len(kwargs["ssid"]) > 0 else ''.join(["FAKE-", str(index + 1)])
        self.mac_address = "60:60:1f:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
        self.state = b'\x02M\x063\x1f' # Dunno what's exactly that
        self.sernum = ''.join(random.choice(Drone.random_source) for i in range(16))
        
        # INPUT * 174533.0 little endian
        # ====== Locations ===========

        self.longitude = float(kwargs['lon']) if "lon" in kwargs and len(kwargs["lon"]) > 0  else self.random_location(point)[0]
        #self.longitude_bytes = self.location2bytes(self.longitude)
        self.latitude = float(kwargs['lat']) if "lat" in kwargs and len(kwargs["lat"]) > 0  else self.random_location(point)[1]
        #self.latitude_bytes = self.location2bytes(self.latitude)

        self.longitude_home = float(kwargs['home_lon']) if "home_lon" in kwargs and len(kwargs["home_lon"]) > 0  else self.random_location()[0]
        #self.longitude_home = self.location2bytes(longitude_home)
        self.latitude_home = float(kwargs['home_lat']) if "home_lat" in kwargs and len(kwargs["home_lat"]) > 0  else self.random_location()[1] 
        #self.latitude_home = self.location2bytes(latitude_home)

        # home and pilot location will be the same
        self.pilot_lon = self.longitude_home
        self.pilot_lat = self.latitude_home

        self.altitude = int(kwargs['altitude']) if "altitude" in kwargs and len(kwargs['altitude']) > 0  else self.randomN(0,2**16-1) # Max 16 bits little endian unsgined
        self.height = self.randomN(0,2**16-1)  # Max 16 bits little endian unsgined

        # ====== Drone axes motion and axis speed========

        #speed_aeroscope = (speed / 100)
        self.v_north =  100 * self.randomN(-50, 50) # self.randomN((-2**15),2**15-1) # X
        self.v_east = 100 * self.randomN(-50, 50) #self.randomN((-2**15),2**15-1) # Y
        self.v_up =  100 * self.randomN(-50, 50) #self.randomN((-2**15),2**15-1)
        self.pitch = self.randomN((-2**15),2**15-1)       
        self.roll = self.randomN((-2**15),2**15-1)          
        self.yaw = self.randomN((-2**15),2**15-1)            

        # ===== Drone's info =========
        self.prod_type = os.urandom(1) # b'x\10' # One byte length value
        self.uuid = kwargs['uuid'] if "uuid" in kwargs and len(kwargs['uuid']) > 0 else ''.join(random.choice(string.digits) for i in range(7))
        self.uuid_len = len(self.uuid)

        [print(attribute, getattr(self, attribute)) for attribute in dir(self) if not attribute.startswith("__") and not callable(self)]

  
    '''
    Returns the payload containing the DroneID  telemetry info in bytes
    '''
    def build_telemetry(self):

        drone2bytes = b''.join([Drone.common_header,
        Drone.telemetry_byte,
        self.state,
        self.attribute2byte(self.sernum),
        self.location2bytes(self.longitude),
        self.location2bytes(self.latitude),
        self.attribute2byte(self.altitude, signed=True),
        self.attribute2byte(self.height, signed=True),
        self.attribute2byte(self.v_north),
        self.attribute2byte(self.v_east),
        self.attribute2byte(self.v_up),
        self.attribute2byte(self.yaw), # that changed from report.. it said pich here
        self.attribute2byte(self.roll),
        self.attribute2byte(self.pitch),
        b'\x00\x00\x00\x00', # Don't know what is going on with that field. It somehow modifies home location
        self.location2bytes(self.pilot_lat),
        self.location2bytes(self.pilot_lon),
        self.location2bytes(self.longitude_home),
        self.location2bytes(self.latitude_home),
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

        finfo_bytes = b''.join([Drone.common_header,
        Drone.flight_info_byte,  # 11
        self.attribute2byte(self.sernum),
        self.attribute2byte(str(len(identification))),  # ToDo-> max 0x7f, minimum of 10 bytes
        self.attribute2byte(identification),
        self.attribute2byte(str(len(flight_info))),
        self.attribute2byte(flight_info)])
        finfo_bytes = b''.join([finfo_bytes,b'\x00'*(147 - len(finfo_bytes))])  # some padding ...
        
        return finfo_bytes


    '''
    Conversion for the location coordinates. From Department's 13 report
    '''
    def location2bytes(self, location):
        a = struct.pack('<i', floor(float(location) * 174533.0))
        return a

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
    def random_location(self, point= None):

        
        if point is None:
            return random.uniform(-180,180), random.uniform(-90, 90)
        else:
            # https://en.wikipedia.org/wiki/Decimal_degrees  
            area_range = 100 # Modify the 2 decimal value
            lat_new = float(point[0]) + self.randomN(0, 9) / area_range
            lon_new = float(point[1]) + self.randomN(0, 9) / area_range
            return lon_new, lat_new



    '''
    Random number between 'a' and 'b'
    If number is negative return the binary complement
    To handle the signed integers
    '''
    def randomN(self, a,b):
        r = random.randint(a,b)
        if r < 0:
            r = ~r
        return r
