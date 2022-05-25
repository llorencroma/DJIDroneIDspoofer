import random, string
from math import floor
import struct

UINT8_MAX = 255
INT8_MIN = -128
INT8_MAX = 127
UINT16_MAX = 65535

class Drone:
    oui_type = b'\x0d'
    # msg counter and the timestamp are set to 0 since the receiver does not do any check on these values
    msg_counter = b'\x00'
    timestamp_loc = b'\x00\x00'
    timestamp_sys = b'\x00\x00\x00\x00'
    msg_size = b'\x19'
    msg_pack_id = b'\xf0'
    basic_id = b'\x00'
    location_id = b'\x10'
    system_id = b'\x40'
    operator_id = b'\x50'

    def __init__(self, *args, **kwargs):
        print('args: ', args, ' kwargs: ', kwargs)

        if len(args) == 1:
            index = args[0]

        # From user input or generated randomly in multiple spoofed drones
        self.ssid = kwargs['ssid'] if "ssid" in kwargs and len(kwargs["ssid"]) > 0 else ''.join(["Fake - ", str(index + 1)])
        self.lon = float(kwargs['lon']) if "lon" in kwargs and len(kwargs["lon"]) > 0 else self.random_location()[0]
        self.lat = float(kwargs['lat']) if "lat" in kwargs and len(kwargs["lat"]) > 0 else self.random_location()[1]
        self.op_lon = float(kwargs['op_lon']) if "op_lon" in kwargs and len(kwargs["op_lon"]) > 0 else self.random_location()[0]
        self.op_lat = float(kwargs['op_lat']) if "op_lat" in kwargs and len(kwargs["op_lat"]) > 0 else self.random_location()[1]
        self.op_rn = str(kwargs['op_rn']) if "op_rn" in kwargs and len(kwargs["op_rn"]) > 0 else ''.join(random.choice(string.ascii_lowercase + string.digits) for i in range(20))
        self.sernum = str(kwargs['sernum']) if "sernum" in kwargs and len(kwargs["sernum"]) > 0 else ''.join(random.choice(string.ascii_uppercase + string.digits) for i in range(20))

        # Fixed parameters
        self.status = b'\x20'  # it may change due to the speed multiplier and the EWDirection flag
        self.hori_vertical_accuracy = b'\x00'
        self.speed_baro_accuracy = b'\x00'
        self.time_accuracy = b'\x00'
        self.ua_id_type = b'\x12'  # serial number
        self.classification_loc_type = b'\x04'  # classification=EU, location type=TakeOff
        self.area_count = b'\x00\x00'
        self.area_radius = b'\x00'
        self.area_ceiling = b'\x00\x00'
        self.area_floor = b'\x00\x00'
        self.category_class_type = b'\x12'  # category=EU_open, class=EU_Class_1
        self.operator_id_type = b'\x01'  # Type 1

        # Random parameters
        self.direction = randomN(0, 360)  # East (0-179 degrees) or West (180-359)
        self.hori_speed = randomN(0, 254.25)
        self.vert_speed = randomN(-62, 62)
        self.alt_baro = randomN(-1000, 31767.5)
        self.alt_geo = randomN(-1000, 31767.5)
        self.height = randomN(-1000, 31767.5)
        self.op_alt = randomN(-1000, 31767.5)
        self.mac_address = "90:3a:e6:%02x:%02x:%02x" % (
            random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))

        [print(attribute, getattr(self, attribute)) for attribute in dir(self) if
         not attribute.startswith("__") and not callable(self)]

    # Build packet 33 bytes length
    def build_location(self):
        # to update the status field in case multiplier or EWDirection flag need to be set to 1
        direction = self.encode_direction(self.direction)
        hori_speed = self.encode_hori_speed(self.hori_speed)
        drone2bytes = b''.join([Drone.oui_type,
                                Drone.msg_counter,
                                Drone.msg_pack_id,
                                Drone.msg_size,
                                b'\x01',  # msg pack size
                                Drone.location_id,
                                self.status,
                                direction,
                                hori_speed,
                                self.encode_vert_speed(self.vert_speed),
                                self.encode_loc(self.lat),
                                self.encode_loc(self.lon),
                                self.encode_altitude(self.alt_baro),
                                self.encode_altitude(self.alt_geo),
                                self.encode_altitude(self.height),
                                self.hori_vertical_accuracy,
                                self.speed_baro_accuracy,
                                Drone.timestamp_loc,
                                self.time_accuracy,
                                b'\x00'  # reserved for future use
                                ])
        return drone2bytes

    # Build packet 108 bytes length
    def build_finfo(self):
        # to update the status field in case multiplier or EWDirection flag need to be set to 1
        direction = self.encode_direction(self.direction)
        hori_speed = self.encode_hori_speed(self.hori_speed)
        finfo2bytes = b''.join([Drone.oui_type,
                                Drone.msg_counter,
                                Drone.msg_pack_id,
                                Drone.msg_size,
                                b'\x04',  # msg pack size
                                Drone.basic_id,
                                self.ua_id_type,
                                self.sernum.encode(),
                                b'\x00\x00\x00',  # reserved for future use
                                Drone.location_id,
                                self.status,
                                direction,
                                hori_speed,
                                self.encode_vert_speed(self.vert_speed),
                                self.encode_loc(self.lat),
                                self.encode_loc(self.lon),
                                self.encode_altitude(self.alt_baro),
                                self.encode_altitude(self.alt_geo),
                                self.encode_altitude(self.height),
                                self.hori_vertical_accuracy,
                                self.speed_baro_accuracy,
                                Drone.timestamp_loc,
                                self.time_accuracy,
                                b'\x00',  # reserved for future use
                                Drone.system_id,
                                self.classification_loc_type,
                                self.encode_loc(self.op_lat),
                                self.encode_loc(self.op_lon),
                                self.area_count,
                                self.area_radius,
                                self.area_ceiling,
                                self.area_floor,
                                self.category_class_type,
                                self.encode_altitude(self.op_alt),
                                Drone.timestamp_sys,  # operator timestamp
                                b'\x00',  # reserved for future use
                                Drone.operator_id,
                                self.operator_id_type,
                                self.op_rn.encode(),
                                b'\x00\x00\x00'  # reserved for future use
                                ])
        # Padding to have the same length as de original payload in case RN is not present or it is a short string
        finfo2bytes = b''.join([finfo2bytes, b'\x00' * (105 - len(finfo2bytes))])
        return finfo2bytes

    # Encode location value into bytes
    def encode_loc(self, location):
        a = struct.pack('<i', floor(float(location) * 10 ** 7))
        return a

    # Encode direction - unsigned
    def encode_direction(self, direction):
        if direction < 180:
            # EWDirection=0
            self.status = clear_bit(int.from_bytes(self.status, byteorder='little'), 1)
        else:
            # EWDirection=1
            self.status = set_bit(int.from_bytes(self.status, byteorder='little'), 1)
            direction = direction - 180
        a = check_range(direction, 0, UINT8_MAX)
        a = struct.pack('<B', floor(a))
        return a

    # Encode Altitude and Height
    def encode_altitude(self, altitude):
        a = check_range((altitude + 1000) / 0.5, 0, UINT16_MAX)
        a = struct.pack('<H', floor(a))
        return a

    # Encode Vertical Speed
    def encode_vert_speed(self, speed):
        value = speed / 0.5
        a = check_range(value, INT8_MIN, INT8_MAX)
        a = struct.pack('<b', floor(a))
        return a

    # Encode Horizontal Speed - unsigned
    def encode_hori_speed(self, speed):
        if speed <= UINT8_MAX * 0.25:
            # multiplier=0
            self.status = clear_bit(int.from_bytes(self.status, byteorder='little'), 0)
            a = speed / 0.25
            a = struct.pack('<B', floor(a))
            return a
        else:
            # multiplier=1
            self.status = set_bit(int.from_bytes(self.status, byteorder='little'), 0)
            value = (speed - (UINT8_MAX * 0.25)) / 0.75
            a = check_range(value, 0, UINT8_MAX)
            a = struct.pack('<B', floor(a))
            return a

    # Generate random location
    def random_location(self, point=None):
        return random.uniform(-180, 180), random.uniform(-90, 90)
# Generate random number between a and b, returning a float if a and b are float numbers, otherwise an int
def randomN(a, b):
    if isinstance(a, float) or isinstance(b, float):
        r = random.uniform(a, b)
    else:
        r = random.randint(a, b)
    return r


# Check range for a value and return the minimum or max within the range if exceeded
def check_range(inValue, startRange, endRange):
    if inValue < startRange:
        return startRange
    elif inValue > endRange:
        return endRange
    else:
        return inValue


def set_bit(value, bit):
    a = value | (1 << bit)
    return a.to_bytes(1, byteorder='little')


def clear_bit(value, bit):
    a = value & ~(1 << bit)
    return a.to_bytes(1, byteorder='little')
