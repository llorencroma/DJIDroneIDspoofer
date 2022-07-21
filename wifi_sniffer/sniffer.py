import argparse
import threading
from tkinter import *
from tkinter import ttk
from scapy.all import Dot11, Dot11Elt, sniff
from scapy.layers.dot11 import Dot11EltVendorSpecific
from Drone import *
from App import *

# Due to limitations in how the sniffer is implemented, small timer leads to lose drones even if packets are received
# This is due to the elapsed time lost in the execution of the code
TIMER = 30


# In the spoofer the line "self.attribute2byte(self.uuid_len)" adds '\x00' to uuid len so that it represents the first
# character of the UUID. For this reason the log does not work since it cannot print '\x00' as a character
def parse_packet(payload):
    if payload[0:4] == b'Xb\x13\x10':
        # It is a telemetry payload
        telemetry_payload = payload
        sernum = telemetry_payload[9:25]
        # Check if it is a new drone detection
        if drones:
            presence = False
            for d in drones:
                if d.sernum == sernum:
                    # Drone already present
                    # Update the drone start_time
                    d.start_time = time.time()
                    d.build_telemetry(telemetry_payload)
                    presence = True
                    # Check if it is needed to update the marker
                    d.update_marker(app.map_widget)
            if not presence:
                # New drone
                drone = Drone(sernum=sernum)
                # Update the drone start_time
                drone.start_time = time.time()
                drone.build_telemetry(telemetry_payload)
                drones.append(drone)
                # Add marker in the map for the drone detected
                drone.marker=app.map_widget.set_position(drone.lat, drone.long, marker=True)
        else:
            # New drone
            drone = Drone(sernum=sernum)
            # Update the drone start_time
            drone.start_time = time.time()
            drone.build_telemetry(telemetry_payload)
            drones.append(drone)
            # Add marker in the map for the drone detected
            drone.marker=app.map_widget.set_position(drone.lat, drone.long, marker=True)
    else:
        # It is a flight info payload
        info_payload = payload
        sernum = info_payload[4:20]
        # Check if it is a new drone detection
        if drones:
            presence = False
            for d in drones:
                if d.sernum == sernum:
                    # Drone already present
                    # Update the drone start_time
                    d.start_time = time.time()
                    d.build_info(info_payload)
                    presence = True
                    # Check if it is needed to update the marker
                    d.update_marker(app.map_widget)
            if not presence:
                # New drone
                drone = Drone(sernum=sernum)
                # Update the drone start_time
                drone.start_time = time.time()
                drone.build_info(info_payload)
                drones.append(drone)
                # Add marker in the map for the drone detected
                drone.marker=app.map_widget.set_position(drone.lat, drone.long, marker=True)
        else:
            # New drone
            drone = Drone(sernum=sernum)
            # Update the drone start_time
            drone.start_time = time.time()
            drone.build_info(info_payload)
            drones.append(drone)
            # Add marker in the map for the drone detected
            drone.marker = app.map_widget.set_position(drone.lat, drone.long, marker=True)

    for d in drones:
        print("Drones detected: " + str(len(drones)))
        d.log()  # Logging
        d.db()  # Save data in a json file
        # Check timer: if no packets received within 30 sec the drone is removed and not showed in the console
        if (time.time() - d.start_time) < TIMER:
            d.show()  # Print drone's information in the console
        else:
            # Timer elapsed
            drones.remove(d)
            # Remove drone from the map
            d.marker.delete()


def packet_handler(packet):
    if packet.haslayer(Dot11):
        dot11elt = packet.getlayer(Dot11EltVendorSpecific)

        while dot11elt and dot11elt.oui != 2504466:  # Decimal conversion for '\x26\x37\x12'
            dot11elt = dot11elt.payload.getlayer(Dot11Elt)
        if dot11elt:
            payload = dot11elt.info
            payload = payload[3:len(payload)]  # Remove OUI bytes
            parse_packet(payload)  # Parse the vendor dji payload


# Build table with real-time drone information
def build_table():
    ws = Tk()
    ws.title('Drones')
    frame = Frame(ws)
    frame.pack()

    # Scrollbar
    scroll = Scrollbar(frame)
    scroll.pack(side=RIGHT, fill=Y)
    scroll = Scrollbar(frame, orient='horizontal')
    scroll.pack(side=BOTTOM, fill=X)
    table = ttk.Treeview(frame, yscrollcommand=scroll.set, xscrollcommand=scroll.set)

    # Format of the table
    table['columns'] = (
        'sn', 'lat', 'long', 'airtype', 'alt', 'height', 'vnorth', 'veast',
        'vup', 'yaw', 'roll', 'pitch', 'pilotlat', 'pilotlong', 'homelat', 'homelong', 'uuid',
        'id', 'flightinfo')

    table.column("#0", width=0, stretch=YES)
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

    # Loop that shows detected drones with data updated in realtime
    while True:
        if drones:
            for d in drones:
                data = [d.sernum, d.lat, d.long, d.type, d.altitude, d.height, d.v_north, d.v_east, d.v_up,
                        d.yaw, d.roll, d.pitch, d.pilotlat, d.pilotlong, d.homelat, d.homelong, d.uuid, d.id,
                        d.flightinfo]
                table.insert(parent='', index='end', iid=d.sernum, text='', values=data)

        ws.update()
        table.delete(*table.get_children())


def sniff_work(iface):
    sniff(iface=iface, prn=packet_handler)


if __name__ == '__main__':
    # List to keep track of detected drones
    drones = []
    app = App()  # Map Thread
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="Sniff through the interface")
    args = parser.parse_args()
    print("Arguments: {}".format(args))

    if not args.interface:
        raise SystemExit("  Usage: {sys.argv[0]} -i  <interface> \n  Interface must be in monitor mode")
    else:
        interface = args.interface
        # Start the three threads: sniffer, the Table and the Map
        sniff_thread = threading.Thread(target=sniff_work, args=(interface,))
        sniff_thread.start()
        gui_thread = threading.Thread(target=build_table, )
        gui_thread.start()
        app.start()
