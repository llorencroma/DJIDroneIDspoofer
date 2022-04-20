from scapy.all import Dot11, Dot11Elt, sniff
from scapy.layers.dot11 import Dot11EltVendorSpecific

from Drone import *

# TODO organize the display of info, don't show again if they don't change
# TODO think how to capture drones from other manufacturer

# think a smarter method to keep track of drones instead of using a list
drones = []
presence=False

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
        presence = False
        if drones:
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
            print(len(drones))

    for d in drones:

        d.show()


def packet_handler(packet):
    print(len(drones))
    if packet.haslayer(Dot11):
        dot11elt = packet.getlayer(Dot11EltVendorSpecific)

        while dot11elt and dot11elt.oui != 2504466: #decimal conversion of \x26\x37\x12'
            dot11elt = dot11elt.payload.getlayer(Dot11Elt)
        if dot11elt:
            payload = dot11elt.info
            payload = payload[3:255] #to remove oui bytes
            parse_packet(payload)


sniff(filter="ether src 60:60:1f:16:74:77", iface="wlx801f02f1e3d2", prn=packet_handler) #TODO make automatic the filter for the mac

# data from max_djipayload
# sernum=0K1CG6G3AH8V2M
# lat=484.019161
# long=0.013201
# Altitude=4079.0
# Distance=8641.40km
# aircraft type=Mavic Air
# height=1.2
# Pilot lat= 46.762552
# pilot long=7.600514
# Pilot distance=134.65km
# HS=327
# VS=0.04
# home lat=0.004400
# home long=-10766.152357
# home distance=5806.71km
# uuid= ABCDEFGHIPQRABCDEFGHIPQRABCDEFGHIPQRABCDEFGHIPQRABCDEFGHIPQRABCDEFGHIPQRABCDEFGHIPQRABCDEFGHIPQRABCDEFGHIPQRABCDEFGHIPQRABCDEFG
# identification=JKLMNOPQRS <VWJKLMNOPQRSTUVWJKLMNOPQRSTUVWJKLMNOPQRSTUVWJKLMNOPQRSTUVWJKLMNOPQRSTUVWJKLMNOPQRSTUVWJKLMNOPQRSTUVWJKLMNOPQRSTUV
# flight info=<VWJKLMNOPQRSTUVWJKLMNOPQRSTUVWJKLMNOPQRSTUVWJKLMNOPQRSTUVWJKLMNOPQRSTUVWJKLMNOPQRSTUVWJKLMNOPQRSTUVWJKLMNOPQRSTUVWEE1234567891
