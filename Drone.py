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
        elif len(args) == 3:

                   
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
        self.pilot_lon = float(kwargs['home_lon']) if "home_lon" in kwargs and len(kwargs["home_lon"]) > 0  else self.random_location()[0]
        self.pilot_lat = float(kwargs['home_lat']) if "home_lat" in kwargs and len(kwargs["home_lat"]) > 0  else self.random_location()[1] 

        # Make ranges reasonable
        self.altitude = int(kwargs['altitude']) if "altitude" in kwargs and len(kwargs['altitude']) > 0  else self.randomN(0,150) #2**16-1) # Max 16 bits little endian unsgined
        self.height = self.randomN(0,500)# 2**16-1)  # Max 16 bits little endian unsgined

        # ====== Drone axes motion and axis speed========

        #speed_aeroscope = (speed / 100)
        self.v_north =  100 * self.randomN(-50, 50) # self.randomN((-2**15),2**15-1) # X
        self.v_east = 100 * self.randomN(-50, 50) #self.randomN((-2**15),2**15-1) # Y
        self.v_up =  100 * self.randomN(-50, 50) #self.randomN((-2**15),2**15-1)

        # Aeroscope defaul value is 180. If we sent \x00\x00 it will show 180
        # From here it shows:   180 + (received/100) / 57.296
        # If we want to show 190 we send (190-180) * 100
        self.pitch = self.randomN((-2**15),2**15-1)       
        self.roll = self.randomN((-2**15),2**15-1)          
        self.yaw = self.randomN(0,360)            

        # ===== Drone's info =========
        self.prod_type = os.urandom(1) # b'x\10' # One byte length value
        self.uuid = kwargs['uuid'] if "uuid" in kwargs and len(kwargs['uuid']) > 0 else ''.join(random.choice(string.digits) for i in range(7))
        self.uuid_len = len(self.uuid)


        if(verbose): ## TODO Include Verbose option to print all Fields Values
            [print(attribute, getattr(self, attribute)) for attribute in dir(self) if not attribute.startswith("__") and not callable(self)]
        else:
            print("Longitud -->  %s \nLatitude --> %s " % (self.longitude,self.latitude))

  
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
        self.attribute2byte(int(floor((self.yaw - 180) * 100))), # that changed from report.. it said pich here
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
    Update longitude and speed on the direction of the aircraft motion's according to the XBOX event
    '''
    def update_longitude(self, axis_direction):
        self.longitude = self.longitude +  float("{:.4f}".format(float(axis_direction/ 1000))) 
        self.v_east =  floor((self.v_east + 100 * axis_direction))   # Increase speed on this direction so it pointer points to that way
        self.v_north =  floor((self.v_north - 50)) if self.v_north > 0 else floor(self.v_north + 50) # To reduce the speed on the other axis
    
    '''
    Update longitude and speed on the direction of the aircraft motion's according to the XBOX event
    '''
    def update_latitude(self, axis_direction):
        self.latitude = self.latitude + float("{:.4f}".format(float(axis_direction / 1000))) * (-1) # -1 to correct the inverted sign on the XBOX controller Y axis 
        self.v_north =  floor(self.v_north +  (-axis_direction) * 100)
        self.v_east =  floor(self.v_east - 50) if self.v_east > 0 else floor(self.v_east + 50)

   
    def update_pilot_longitude(self, axis_direction):
        self.pilot_lon = self.pilot_lon +  float("{:.4f}".format(float(axis_direction/ 1000))) 
        
    def update_pilot_latitude(self, axis_direction):
        self.pilot_lat = self.pilot_lat + float("{:.4f}".format(float(axis_direction / 1000))) * (-1) # -1 to correct the inverted sign on the XBOX controller Y axis 
       

    '''
    Update yaw 
    0º and 180º point to the southand north respectively
    90º and 270 point to the weast and east respectively
    '''
    def update_yaw(self, axis_direction):
        print("DIRECTION {}".format(axis_direction))
        self.yaw = (self.yaw + (axis_direction/3)) % 360  # positive rotates right, negative left. Reduce the effect of so many events
       

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
        # Signed should be the contrary
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
