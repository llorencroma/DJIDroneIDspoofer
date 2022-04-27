import random, string
import sys
from math import floor
import time, os
import struct


class Drone:

    def __init__(self, *args, **kwargs):

        self.sernum = kwargs['sernum'] if "sernum" in kwargs and len(kwargs["sernum"]) > 0 else b''
        self.lat = kwargs['lat'] if "lat" in kwargs and len(kwargs["lat"]) > 0 else b''
        self.long = kwargs['long'] if "long" in kwargs and len(kwargs["long"]) > 0 else b''
        self.type = kwargs['type'] if "type" in kwargs and len(kwargs["type"]) > 0 else b''
        self.pilotlat = kwargs['pilotlat'] if "pilotlat" in kwargs and len(kwargs["pilotlat"]) > 0 else b''
        self.pilotlong = kwargs['pilotlong'] if "pilotlong" in kwargs and len(kwargs["pilotlong"]) > 0 else b''
        self.altitude = kwargs['altitude'] if "altitude" in kwargs and len(kwargs["altitude"]) > 0 else b''
        self.height = kwargs['height'] if "height" in kwargs and len(kwargs["height"]) > 0 else b''
        self.v_north = kwargs['v_north'] if "v_north" in kwargs and len(kwargs["v_north"]) > 0 else b''
        self.v_east = kwargs['v_east'] if "v_east" in kwargs and len(kwargs["v_east"]) > 0 else b''
        self.v_up = kwargs['v_up'] if "v_up" in kwargs and len(kwargs["v_up"]) > 0 else b''
        self.yaw = kwargs['yaw'] if "yaw" in kwargs and len(kwargs["yaw"]) > 0 else b''
        self.roll = kwargs['roll'] if "roll" in kwargs and len(kwargs["roll"]) > 0 else b''
        self.pitch = kwargs['pitch'] if "pitch" in kwargs and len(kwargs["pitch"]) > 0 else b''
        self.homelat = kwargs['homelat'] if "homelat" in kwargs and len(kwargs["homelat"]) > 0 else b''
        self.homelong = kwargs['homelong'] if "homelong" in kwargs and len(kwargs["homelong"]) > 0 else b''
        self.uuid = kwargs['uuid'] if "uuid" in kwargs and len(kwargs["uuid"]) > 0 else b''
        self.id = kwargs['id'] if "id" in kwargs and len(kwargs["id"]) > 0 else b''
        self.flightinfo = kwargs['flightinfo'] if "flightinfo" in kwargs and len(kwargs["flightinfo"]) > 0 else b''

    def build_telemetry(self, payload):
        long = payload[25:29]
        lat = payload[29:33]
        altitude = payload[33:35]
        height = payload[35:37]
        v_north=payload[37:39]
        v_east=payload[39:41]
        v_up=payload[41:43]
        yaw=payload[43:45]
        roll=payload[45:47]
        pitch=payload[47:49]
        pilotlat = payload[53:57]
        pilotlong = payload[57:61]
        homelong = payload[61:65]
        homelat = payload[65:69]
        type = payload[69:70]
        uuidlen = payload[70:71]
        uuid =payload[71:71 + int.from_bytes(uuidlen, byteorder=sys.byteorder)]

        # fill the other fields of the drone
        self.lat = float('.'.join(str(elem) for elem in (struct.unpack('<i', lat))))/174533.0
        self.long = float('.'.join(str(elem) for elem in (struct.unpack('<i', long))))/174533.0
        self.altitude = float('.'.join(str(elem) for elem in (struct.unpack(''.join(['<', 'H']), altitude))))
        self.height = float('.'.join(str(elem) for elem in (struct.unpack(''.join(['<', 'H']), height))))
        self.v_north=float('.'.join(str(elem) for elem in (struct.unpack(''.join(['<', 'h']), v_north))))
        self.v_east=float('.'.join(str(elem) for elem in (struct.unpack(''.join(['<', 'h']), v_east))))
        self.v_up=float('.'.join(str(elem) for elem in (struct.unpack(''.join(['<', 'h']), v_up))))
        self.yaw=(float('.'.join(str(elem) for elem in (struct.unpack(''.join(['<', 'h']), yaw))))/100)+180
        self.roll=float('.'.join(str(elem) for elem in (struct.unpack(''.join(['<', 'h']), roll))))
        self.pitch = float('.'.join(str(elem) for elem in (struct.unpack(''.join(['<', 'h']), pitch))))
        self.pilotlat = float('.'.join(str(elem) for elem in (struct.unpack('<i', pilotlat))))/174533.0
        self.pilotlong = float('.'.join(str(elem) for elem in (struct.unpack('<i', pilotlong))))/174533.0
        self.homelong = float('.'.join(str(elem) for elem in (struct.unpack('<i', homelong))))/174533.0
        self.homelat = float('.'.join(str(elem) for elem in (struct.unpack('<i', homelat))))/174533.0
        self.type = type  # TODO think to an enum in which there are the association between the hex bytes and the aircraft type
        self.uuid = uuid.decode()

    def build_info(self, payload):
        # if it is a n info payload
        idlen = payload[20:21]
        id = payload[21:21 + int.from_bytes(idlen, byteorder=sys.byteorder)]
        flightinfolen = payload[31:32]
        flightinfo = payload[32:32 + int.from_bytes(flightinfolen, byteorder=sys.byteorder)]

        # fill the other fields of the drone
        self.id = id.decode()
        self.flightinfo = flightinfo.decode()

    def show(self):
        print("Serial Number: " + str(self.sernum))
        print("Latitude: " + str(self.lat))
        print("Longitude: " + str(self.long))
        print("Aircraft Type: " + str(self.type))
        print("Altitude: " + str(self.altitude))
        print("Height: " + str(self.height))
        print("Velocity north: " + str(self.v_north))
        print("Velocity east " + str(self.v_east))
        print("Velocity up: " + str(self.v_up))
        print("Yaw: " + str(self.yaw))
        print("Roll: " + str(self.roll))
        print("Pitch: " + str(self.pitch))
        print("Pilot Latitude: " + str(self.pilotlat))
        print("Pilot Longitude: " + str(self.pilotlong))
        print("Home Latitude: " + str(self.homelat))
        print("Home Longitude: " + str(self.homelong))
        print("UUID: " + str(self.uuid))
        print("Identification: " + str(self.id))
        print("Flight Information: " + str(self.flightinfo))
        print('\n\n')