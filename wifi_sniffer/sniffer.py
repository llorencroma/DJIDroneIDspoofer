import argparse
import threading
import time
from tkinter import *
from tkinter import ttk

from scapy.all import Dot11, Dot11Elt, sniff
from scapy.layers.dot11 import Dot11EltVendorSpecific

from Drone import *


# TODO organize the display of info, don't show again if they don't change
# TODO update table if parameters like location changes

# There is a problem with the spoofer in the line "self.attribute2byte(self.uuid_len)", it adds an additional \x00 to uuid len so that it represents the first character of the UUID. For this reason the log does not work since it cannot print \x00 as a character


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
            presence = False
            for d in drones:
                if d.sernum == sernum:
                    print("drone already present")
                    d.build_telemetry(telemetry_payload)
                    presence = True
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

        while dot11elt and dot11elt.oui != 2504466:  # decimal conversion of \x26\x37\x12'
            dot11elt = dot11elt.payload.getlayer(Dot11Elt)
        if dot11elt:
            payload = dot11elt.info
            payload = payload[3:len(payload)]  # to remove oui bytes
            parse_packet(payload)


def update_data():
    drones_in_table = []

    while True:
        if drones:

            if drones_in_table:
                drones_in_table_sn = {d.sernum for d in drones_in_table}
                for d in drones:
                    if not d.sernum in drones_in_table_sn:
                        drones_in_table.append(d)
                        data = [d.sernum, d.lat, d.long, d.type, d.altitude, d.height, d.v_north, d.v_east, d.v_up,
                                d.yaw, d.roll,
                                d.pitch, d.pilotlat, d.pilotlong, d.homelat, d.homelong, d.uuid, d.id, d.flightinfo]

                        table.insert(parent='', index='end', iid=d.sernum, text='',
                                     values=data)

                    else:

                        for d1 in drones_in_table:
                            if str(d.sernum) == str(d1.sernum):

                                if str(d.lat) != str(d1.lat) or str(d.long) != str(d1.long) or str(d.altitude) != str(
                                        d1.altitude) or str(d.height) != str(d1.height) or str(d.v_north) != str(
                                        d1.v_north) or str(d.v_east) != str(d1.v_east) or str(d.v_up) != str(
                                        d1.v_up) or str(d.yaw) != str(d1.yaw) or str(d.roll) != str(d1.roll) or str(
                                        d.pitch) != str(d1.pitch) or str(d.pilotlat) != str(d1.pilotlat) or str(
                                        d.pilotlong) != str(d1.pilotlong) or str(d.homelat) != str(d1.homelat) or str(
                                        d.homelong) != str(d1.homelong):
                                    print("update dataaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                                    d1.lat = d.lat
                                    d1.long = d.long
                                    d1.type = d.type
                                    d1.altitude = d.altitude
                                    d1.height = d.height
                                    d1.v_north = d.v_north
                                    d1.v_east = d.v_east
                                    d1.v_up = d.v_up
                                    d1.yaw = d.yaw
                                    d1.roll = d.roll
                                    d1.pitch = d.pitch
                                    d1.pilotlat = d.pilotlat
                                    d1.pilotlong = d.pilotlong
                                    d1.homelat = d.homelat
                                    d1.homelong = d.homelong
                                    data = [d1.sernum, d1.lat, d1.long, d1.type, d1.altitude, d1.height, d1.v_north,
                                            d1.v_east, d1.v_up, d1.yaw, d1.roll, d1.pitch, d1.pilotlat, d1.pilotlong,
                                            d1.homelat, d1.homelong, d1.uuid, d1.id, d1.flightinfo]

                                    for item in table.selection():
                                        iid = table.focus()
                                        if str(iid) == str(d1.sernum):
                                            item_to_update = table.item(item)
                                            table.item(item_to_update, values=data)

                                elif str(d1.id) != str(d.id) or str(d1.flightinfo) != str(d.flightinfo):
                                    print("update dataaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

                                    d1.id = d.id
                                    d1.flightinfo = d.flightinfo
                                    data = [d1.sernum, d1.lat, d1.long, d1.type, d1.altitude, d1.height, d1.v_north,
                                            d1.v_east, d1.v_up, d1.yaw, d1.roll, d1.pitch, d1.pilotlat, d1.pilotlong,
                                            d1.homelat, d1.homelong, d1.uuid, d1.id, d1.flightinfo]
                                    for item in table.selection():
                                        iid = table.focus()
                                        if str(iid) == str(d1.sernum):
                                            item_to_update = table.item(item)
                                            table.item(item_to_update, values=data)
            else:
                for d in drones:
                    drones_in_table.append(d)
                    data = [d.sernum, d.lat, d.long, d.type, d.altitude, d.height, d.v_north, d.v_east, d.v_up, d.yaw,
                            d.roll, d.pitch, d.pilotlat, d.pilotlong, d.homelat, d.homelong, d.uuid, d.id, d.flightinfo]
                    table.insert(parent='', index='end', iid=d.sernum, text='', values=data)
            table.update()
            table.pack()


def build_gui():
    table['columns'] = (
        'sn', 'lat', 'long', 'airtype', 'alt', 'height', 'vnorth', 'veast',
        'vup', 'yaw', 'roll', 'pitch', 'pilotlat', 'pilotlong', 'homelat', 'homelong', 'uuid',
        'id', 'flightinfo')

    table.column("#0", width=0, stretch=NO)
    table.column("sn", anchor=CENTER, width=90)
    table.column("lat", anchor=CENTER, width=90)
    table.column("long", anchor=CENTER, width=90)
    table.column("airtype", anchor=CENTER, width=90)
    table.column("alt", anchor=CENTER, width=90)
    table.column("height", anchor=CENTER, width=90)
    table.column("vnorth", anchor=CENTER, width=90)
    table.column("veast", anchor=CENTER, width=90)
    table.column("vup", anchor=CENTER, width=90)
    table.column("yaw", anchor=CENTER, width=90)
    table.column("roll", anchor=CENTER, width=90)
    table.column("pitch", anchor=CENTER, width=90)
    table.column("pilotlat", anchor=CENTER, width=90)
    table.column("pilotlong", anchor=CENTER, width=90)
    table.column("homelat", anchor=CENTER, width=90)
    table.column("homelong", anchor=CENTER, width=90)
    table.column("uuid", anchor=CENTER, width=90)
    table.column("id", anchor=CENTER, width=90)
    table.column("flightinfo", anchor=CENTER, width=90)

    table.heading("#0", text="", anchor=CENTER)
    table.heading("sn", text="Serial Number", anchor=CENTER)
    table.heading("lat", text="Latitude", anchor=CENTER)
    table.heading("long", text="Longitude", anchor=CENTER)
    table.heading("airtype", text="Aircraft Type", anchor=CENTER)
    table.heading("alt", text="Altitude", anchor=CENTER)
    table.heading("height", text="Height", anchor=CENTER)
    table.heading("vnorth", text="Speed North", anchor=CENTER)
    table.heading("veast", text="Speed East", anchor=CENTER)
    table.heading("vup", text="Speed Up", anchor=CENTER)
    table.heading("yaw", text="Yaw", anchor=CENTER)
    table.heading("roll", text="Roll", anchor=CENTER)
    table.heading("pitch", text="Pitch", anchor=CENTER)
    table.heading("pilotlat", text="Pilot Latitude", anchor=CENTER)
    table.heading("pilotlong", text="Pilot Longitude", anchor=CENTER)
    table.heading("homelat", text="Home Latitude", anchor=CENTER)
    table.heading("homelong", text="Home Longitude", anchor=CENTER)
    table.heading("uuid", text="UUID", anchor=CENTER)
    table.heading("id", text="ID", anchor=CENTER)
    table.heading("flightinfo", text="Flight Info", anchor=CENTER)

    table.pack()
    ws.update()
    ws.mainloop()


def sniff_work(iface):
    sniff(iface=iface, prn=packet_handler)


if __name__ == '__main__':
    # think a smarter method to keep track of drones instead of using a list
    drones = []
    table = None
    ws = None
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="Sniff through the interface")
    args = parser.parse_args()
    print("Arguments: {}".format(args))

    ws = Tk()
    ws.title('Drones')
    frame = Frame(ws)
    frame.pack()
    # scrollbar
    scroll = Scrollbar(frame)
    scroll.pack(side=RIGHT, fill=Y)
    scroll = Scrollbar(frame, orient='horizontal')
    scroll.pack(side=BOTTOM, fill=X)
    table = ttk.Treeview(frame, yscrollcommand=scroll.set, xscrollcommand=scroll.set)

    if not args.interface:
        raise SystemExit("  Usage: {sys.argv[0]} -i  <interface> \n  Interface must be in monitor mode")
    else:
        interface = args.interface
        sniff_thread = threading.Thread(target=sniff_work, args=(interface,))
        sniff_thread.start()
        update_thread = threading.Thread(target=update_data)
        update_thread.start()
        build_gui()
