from scapy.all import Dot11, Dot11Elt, sniff
from scapy.layers.dot11 import Dot11EltVendorSpecific

from Drone import *

# TODO organize the display of info, don't show again if they don't change

# There is a problem with the spoofer in the line "self.attribute2byte(self.uuid_len)", it adds an additional \x00 to uuid len so that it represents the first character of the UUID. For this reason the log does not work since it cannot print \x00 as a character

# think a smarter method to keep track of drones instead of using a list
drones = []

def parse_packet(payload):
    sernum = b''
    telemetry_payload = b''
    info_payload = b''
    if payload[0:4] == b'Xb\x13\x10':  # if it is a telemetry payload
        print("telemetry packet")
        telemetry_payload = payload
        sernum = telemetry_payload[9:25]
        # check already existing drone
        if drones:
            presence=False
            for d in drones:
                if d.sernum == sernum:
                    print("drone already present")
                    d.build_telemetry(telemetry_payload)
                    presence=True
            if not presence:
                print("new drone")
                drone = Drone(sernum=sernum)
                drone.build_telemetry(telemetry_payload)
                drones.append(drone)
        else:
            print("list is empty")
            print("new drone")
            drone = Drone(sernum=sernum)
            drone.build_telemetry(telemetry_payload)
            drones.append(drone)

    else:  # if it is a flight info payload
        print("info packet")
        info_payload = payload
        sernum = info_payload[4:20]
        if drones:
            presence = False
            for d in drones:
                if d.sernum == sernum:
                    print("drone already present")
                    d.build_info(info_payload)
                    presence = True
            if not presence:
                print("new drone")
                drone = Drone(sernum=sernum)
                drone.build_info(info_payload)
                drones.append(drone)

        else:
            print("list is empty")
            print("new drone")
            drone = Drone(sernum=sernum)
            drone.build_info(info_payload)
            drones.append(drone)

    for d in drones:
        print(len(drones))
        d.log()
        d.add_db()
        d.show()


def packet_handler(packet):
    if packet.haslayer(Dot11):
        dot11elt = packet.getlayer(Dot11EltVendorSpecific)

        while dot11elt and dot11elt.oui != 2504466: #decimal conversion of \x26\x37\x12'
            dot11elt = dot11elt.payload.getlayer(Dot11Elt)
        if dot11elt:
            payload = dot11elt.info
            payload = payload[3:len(payload)] #to remove oui bytes
            parse_packet(payload)


sniff(iface="wlx801f02f1e3d2", prn=packet_handler)
