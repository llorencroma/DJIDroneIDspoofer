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
        self.hs = kwargs['hs'] if "hs" in kwargs and len(kwargs["hs"]) > 0 else b''
        self.altitude = kwargs['altitude'] if "altitude" in kwargs and len(kwargs["altitude"]) > 0 else b''
        self.height = kwargs['height'] if "height" in kwargs and len(kwargs["height"]) > 0 else b''
        self.vs = kwargs['vs'] if "vs" in kwargs and len(kwargs["vs"]) > 0 else b''
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
        hs = payload[37:41]
        vs = payload[41:43]
        pilotlat = payload[53:57]
        pilotlong = payload[57:61]
        homelong = payload[61:65]
        homelat = payload[65:69]
        type = payload[69:70]
        uuidlen = payload[70:71]
        uuid =payload[71:71 + int.from_bytes(uuidlen, byteorder=sys.byteorder)]

        # fill the other fields of the drone
        self.lat = int.from_bytes(lat, byteorder=sys.byteorder) / 174533.0
        self.long = int.from_bytes(long, byteorder=sys.byteorder) / 174533.0
        self.altitude = int.from_bytes(altitude, byteorder=sys.byteorder)
        self.height = int.from_bytes(height, byteorder=sys.byteorder)
        self.hs = int.from_bytes(hs, byteorder=sys.byteorder)  # TODO it is not the real one, problem of conversion
        self.vs = int.from_bytes(vs, byteorder=sys.byteorder)  # TODO it is not the real one, problem of conversion
        self.pilotlat = int.from_bytes(pilotlat, byteorder=sys.byteorder) / 174533.0
        self.pilotlong = int.from_bytes(pilotlong, byteorder=sys.byteorder) / 174533.0
        self.homelong = int.from_bytes(homelong, byteorder=sys.byteorder) / 174533.0
        self.homelat = int.from_bytes(homelat, byteorder=sys.byteorder) / 174533.0
        self.type = type  # TODO think to an enum in which there are the association between the hex bytes and the aircraft type
        self.uuid = uuid

    def build_info(self, payload):
        # if it is a n info payload
        idlen = payload[20:21]
        id = payload[21:21 + int.from_bytes(idlen, byteorder=sys.byteorder)]
        flightinfolen = payload[31:32]
        flightinfo = payload[32:32 + int.from_bytes(flightinfolen, byteorder=sys.byteorder)]

        # fill the other fields of the drone
        self.id = id
        self.flightinfo = flightinfo

    def show(self):
        print("Serial Number: " + str(self.sernum))
        print("Latitude: " + str(self.lat))
        print("Longitude: " + str(self.long))
        print("Aircraft Type: " + str(self.type))
        print("Pilot Latitude: " + str(self.pilotlat))
        print("Pilot Longitude: " + str(self.pilotlong))
        print("HS: " + str(self.hs))
        print("Altitude: " + str(self.altitude))
        print("Height: " + str(self.height))
        print("VS: " + str(self.vs))
        print("Home Latitude: " + str(self.homelat))
        print("Home Longitude: " + str(self.homelong))
        print("UUID: " + str(self.uuid))
        print("Identification: " + str(self.id))
        print("Flight Information: " + str(self.flightinfo))
        print('\n\n')