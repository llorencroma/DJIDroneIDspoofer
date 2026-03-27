import random
import string
import struct
from math import floor

# DJI DroneID protocol constants
DJI_OUI = 0x263712
DJI_COMMON_HEADER = b'Xb\x13'
DJI_TELEMETRY_TYPE = b'\x10'
DJI_FLIGHT_INFO_TYPE = b'\x11'
LOCATION_SCALE = 174533.0
SPEED_SCALE = 100  # Aeroscope divides speed values by this factor
TELEMETRY_PAYLOAD_LEN = 91
FLIGHT_INFO_PAYLOAD_LEN = 147
YAW_OFFSET = 180  # Aeroscope yaw offset in degrees
YAW_SCALE = 100  # Aeroscope yaw scale factor

# 802.11 Beacon constants
BEACON_SUBTYPE = 8
BEACON_FRAME_TYPE = 0
BEACON_INTERVAL = 102
BEACON_CAP_FLAGS = 0x0431
BROADCAST_ADDR = 'ff:ff:ff:ff:ff:ff'
DJI_MAC_PREFIX = "60:60:1f"
DEFAULT_SSID = "MAVIC_AIR_REAL"
SUPPORTED_RATES = b'\x82\x84\x8b\x96\x0c\x12\x18\x24'

# Microsoft vendor tag (appears in real DJI beacons)
MICROSOFT_OUI = 0x0050f2
MICROSOFT_VENDOR_INFO = b'\x02\x01\x01\x00\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00'

# Input limits
MAX_ALTITUDE = 2**16 - 1
LAT_RANGE = (-90, 90)
LON_RANGE = (-180, 180)

# The 5-byte "state" block (bytes 4-8 of the flat payload) is actually three fields
# of the inner flight_reg_info record (Kismet/Kaitai format):
#
#   Byte 4      version    u8    Protocol version. 0x02 = version 2.
#   Bytes 5-6   seq        u16   Frame sequence counter — should increment each packet.
#   Bytes 7-8   state_info u16   Bitmask of drone/sensor status:
#
#     Bit 0x0001  Serial number valid
#     Bit 0x0002  Private mode disabled (user visible to Aeroscope)
#     Bit 0x0004  Home point set
#     Bit 0x0008  UUID set
#     Bit 0x0010  Motors on
#     Bit 0x0020  In air (in flight)
#     Bit 0x0040  GPS valid
#     Bit 0x0080  Altitude valid
#     Bit 0x0100  Height valid
#     Bit 0x0200  Horizontal velocity valid
#     Bit 0x0400  V_up velocity valid
#     Bit 0x0800  Pitch/roll/yaw valid
#
# DEFAULT_STATE = 02 4D 06 33 1F decodes as:
#   version=2, seq=0x064D (1613), state_info=0x1F33
#   0x1F33 = motors on, in air, serial valid, private mode off,
#            height/velocity/attitude valid — GPS valid NOT set.
#
# Sources: kismet dot11_ie_221_dji_droneid.h, anarkiwi/samples2djidroneid,
#          proto17/dji_droneid, RUB-SysSec/DroneSecurity (NDSS 2023)
PROTOCOL_VERSION = b'\x02'
DEFAULT_STATE_INFO = 0x1F33  # All validity flags set, motors on, in air, no GPS
# seq is set per-packet in build_telemetry(); this is just the initial value
DEFAULT_SEQ = 0

# Known DJI product type bytes (as seen on Aeroscope)
PRODUCT_TYPES = {
    'mavic_air':   b'\x03',
    'mavic_pro':   b'\x04',
    'spark':       b'\x05',
    'mavic_2':     b'\x06',
    'mavic_air_2': b'\x0a',
    'mavic_mini':  b'\x0b',
    'mini_2':      b'\x0e',
    'mavic_3':     b'\x10',
    'mini_3_pro':  b'\x13',
}


# --- Explicit pack functions (replace polymorphic attribute2byte) ---

def pack_uint16(value):
    return struct.pack('<H', value)

def pack_int16(value):
    return struct.pack('<h', value)

def pack_uint8(value):
    return struct.pack('B', value)

def pack_str(value):
    return value.encode() if isinstance(value, str) else value

def location2bytes(location):
    return struct.pack('<i', floor(float(location) * LOCATION_SCALE))

def random_location(point=None):
    """Returns (longitude, latitude) — longitude first."""
    if point is None:
        return random.uniform(-180, 180), random.uniform(-90, 90)
    else:
        area_range = 100
        lat_new = float(point[0]) + random.randint(0, 9) / area_range
        lon_new = float(point[1]) + random.randint(0, 9) / area_range
        return lon_new, lat_new

def random_mac():
    return "{}:%02x:%02x:%02x".format(DJI_MAC_PREFIX) % (
        random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))


class Drone:
    random_source = string.ascii_uppercase + string.digits

    def __init__(self, ssid, serial, mac_address, longitude, latitude,
                 altitude, height, home_lon, home_lat, pilot_lon, pilot_lat,
                 v_north, v_east, v_up, yaw, roll, pitch,
                 product_type, uuid, state_info=DEFAULT_STATE_INFO):
        self.ssid = ssid
        self.mac_address = mac_address
        self.state_info = state_info
        self.seq = DEFAULT_SEQ
        self.sernum = serial

        self.longitude = longitude
        self.latitude = latitude
        self.longitude_home = home_lon
        self.latitude_home = home_lat
        self.pilot_lon = pilot_lon
        self.pilot_lat = pilot_lat

        self.altitude = altitude
        self.height = height

        self.v_north = v_north
        self.v_east = v_east
        self.v_up = v_up

        self.pitch = pitch
        self.roll = roll
        self.yaw = yaw

        self.prod_type = product_type
        self.uuid = uuid
        self.uuid_len = len(uuid)

        print("Longitude --> %s \nLatitude --> %s" % (self.longitude, self.latitude))

    def build_telemetry(self):
        # Increment sequence counter each frame (wraps at u16 max)
        self.seq = (self.seq + 1) % 0x10000

        # The 5 header bytes (bytes 4-8) are three separate fields:
        #   version (1 byte) + seq (2 bytes, u16 LE) + state_info (2 bytes, u16 LE)
        inner_header = (
            PROTOCOL_VERSION
            + struct.pack('<H', self.seq)
            + struct.pack('<H', self.state_info)
        )

        drone2bytes = b''.join([
            DJI_COMMON_HEADER,
            DJI_TELEMETRY_TYPE,
            inner_header,           # version + seq + state_info
            pack_str(self.sernum),
            location2bytes(self.longitude),
            location2bytes(self.latitude),
            pack_uint16(self.altitude),
            pack_uint16(self.height),
            pack_int16(self.v_north),
            pack_int16(self.v_east),
            pack_int16(self.v_up),
            pack_int16(int(floor((self.yaw - YAW_OFFSET) * YAW_SCALE))),
            pack_int16(self.roll),
            pack_int16(self.pitch),
            # phone_app_gps_time: 8-byte u64 LE Unix millisecond timestamp from
            # the controller app's GPS. Present in V2 frames between pitch and
            # pilot coordinates. Zeroed here since we have no real controller GPS.
            # This field caused the "home location display" confusion: the original
            # code only zeroed 4 of the 8 bytes, shifting all downstream fields by
            # 4 bytes and causing Aeroscope to read garbage home coordinates.
            b'\x00\x00\x00\x00\x00\x00\x00\x00',  # phone_app_gps_time (u64)
            location2bytes(self.pilot_lat),
            location2bytes(self.pilot_lon),
            location2bytes(self.longitude_home),
            location2bytes(self.latitude_home),
            self.prod_type,
            pack_uint8(self.uuid_len),
            pack_str(self.uuid),
        ])

        drone2bytes = b''.join([drone2bytes, b'\x00' * (TELEMETRY_PAYLOAD_LEN - len(drone2bytes))])
        return drone2bytes

    def build_finfo(self, identification="identification", flight_info="info"):
        ident_bytes = pack_str(identification)
        finfo_str_bytes = pack_str(flight_info)

        finfo_bytes = b''.join([
            DJI_COMMON_HEADER,
            DJI_FLIGHT_INFO_TYPE,
            pack_str(self.sernum),
            pack_uint8(len(ident_bytes)),
            ident_bytes,
            pack_uint8(len(finfo_str_bytes)),
            finfo_str_bytes,
        ])
        finfo_bytes = b''.join([finfo_bytes, b'\x00' * (FLIGHT_INFO_PAYLOAD_LEN - len(finfo_bytes))])
        return finfo_bytes

    def update_longitude(self, axis_direction):
        self.longitude = self.longitude + float("{:.4f}".format(float(axis_direction / 1000)))
        self.v_east = floor(self.v_east + SPEED_SCALE * axis_direction)
        self.v_north = floor(self.v_north - 50) if self.v_north > 0 else floor(self.v_north + 50)

    def update_latitude(self, axis_direction):
        self.latitude = self.latitude + float("{:.4f}".format(float(axis_direction / 1000))) * (-1)
        self.v_north = floor(self.v_north + (-axis_direction) * SPEED_SCALE)
        self.v_east = floor(self.v_east - 50) if self.v_east > 0 else floor(self.v_east + 50)

    def update_pilot_longitude(self, axis_direction):
        self.pilot_lon = self.pilot_lon + float("{:.4f}".format(float(axis_direction / 1000)))

    def update_pilot_latitude(self, axis_direction):
        self.pilot_lat = self.pilot_lat + float("{:.4f}".format(float(axis_direction / 1000))) * (-1)

    def update_yaw(self, axis_direction):
        self.yaw = (self.yaw + (axis_direction / 3)) % 360


# --- Factory functions ---

def create_random_drone(index=0, point=None, product_type=None):
    """Create a Drone with randomized parameters."""
    ssid = "FAKE-{}".format(index + 1)
    serial = ''.join(random.choice(Drone.random_source) for _ in range(16))
    mac = random_mac()

    lon, lat = random_location(point)
    home_lon, home_lat = random_location()
    pilot_lon, pilot_lat = random_location()

    if product_type and product_type in PRODUCT_TYPES:
        prod = PRODUCT_TYPES[product_type]
    else:
        prod = random.choice(list(PRODUCT_TYPES.values()))

    return Drone(
        ssid=ssid,
        serial=serial,
        mac_address=mac,
        longitude=lon,
        latitude=lat,
        altitude=random.randint(0, 150),
        height=random.randint(0, 500),
        home_lon=home_lon,
        home_lat=home_lat,
        pilot_lon=pilot_lon,
        pilot_lat=pilot_lat,
        v_north=SPEED_SCALE * random.randint(-50, 50),
        v_east=SPEED_SCALE * random.randint(-50, 50),
        v_up=SPEED_SCALE * random.randint(-50, 50),
        yaw=random.randint(0, 360),
        roll=random.randint(-2**15, 2**15 - 1),
        pitch=random.randint(-2**15, 2**15 - 1),
        product_type=prod,
        uuid=''.join(random.choice(string.digits) for _ in range(7)),
    )


def create_drone_from_input(ssid="", lat="", lon="", altitude="",
                            home_lat="", home_lon="", uuid="",
                            product_type=None):
    """Create a Drone from user input strings, using random defaults for empty fields."""
    serial = ''.join(random.choice(Drone.random_source) for _ in range(16))
    mac = random_mac()

    longitude = float(lon) if lon else random_location()[0]
    latitude = float(lat) if lat else random_location()[1]
    home_longitude = float(home_lon) if home_lon else random_location()[0]
    home_latitude = float(home_lat) if home_lat else random_location()[1]
    alt = int(altitude) if altitude else random.randint(0, 150)
    uuid_val = uuid if uuid else ''.join(random.choice(string.digits) for _ in range(7))
    ssid_val = ssid if ssid else "FAKE-1"

    if product_type and product_type in PRODUCT_TYPES:
        prod = PRODUCT_TYPES[product_type]
    else:
        prod = random.choice(list(PRODUCT_TYPES.values()))

    return Drone(
        ssid=ssid_val,
        serial=serial,
        mac_address=mac,
        longitude=longitude,
        latitude=latitude,
        altitude=alt,
        height=random.randint(0, 500),
        home_lon=home_longitude,
        home_lat=home_latitude,
        pilot_lon=home_longitude,
        pilot_lat=home_latitude,
        v_north=SPEED_SCALE * random.randint(-50, 50),
        v_east=SPEED_SCALE * random.randint(-50, 50),
        v_up=SPEED_SCALE * random.randint(-50, 50),
        yaw=random.randint(0, 360),
        roll=random.randint(-2**15, 2**15 - 1),
        pitch=random.randint(-2**15, 2**15 - 1),
        product_type=prod,
        uuid=uuid_val,
    )
