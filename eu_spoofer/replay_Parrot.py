from __future__ import print_function
from scapy.all import(hexdump, RadioTap)
from scapy.layers.dot11 import *
from scapy.utils import rdpcap
from scapy.sendrecv import sendp
from binascii import unhexlify, hexlify
import string
import random

iface = 'wlx801f02f1e3d2'

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
src_addr = '90:3a:e6:5b:c8:a8'  # address 2
bssid = src_addr # addr 3

# ==== Sequence Control 2 bytes ====

fragment_number = 0
seq_number = 490

# ==== Frame Body -- 802.11 Management Beacon =========

# == Mandatory ================================ #
b_timestamp = 181453192 # Timestamp 8 bytes
b_interval = 102            # Beacon Interval 2 Bytes
cap_flags = 0x0431          # Capability Info 2 Bytes. We can also pass strings: "ESS+privacy+othercapabilities"

beacon_fields = Dot11Beacon(timestamp = b_timestamp, beacon_interval = b_interval, cap = 'ESS+privacy') # Scapy

# === Information Elements:
# Each scapy Information Element is defined in Dot11Elt(ID, len, info)
# Inside info there might be other fields, check standard

# == Mandatory IE:SSID == #
ie_ssid_id = 0 # Information Element  SSID. We can use a string as "SSID"
ie_ssid_info = 'AnafiThermal - fake'
ie_ssie_len = len(ie_ssid_info)

ie_ssid = Dot11Elt(ID = ie_ssid_id, len= ie_ssie_len, info = ie_ssid_info) 

# == Mandatory IE:Supported Rates == #
ie_rates = Dot11Elt(ID='Rates', len=1, info = b'\x8c')

#other fields non mandatory
#Vendor specific Parrot Sa
parrot_payload=b'\x09\x19\x50\x49\x30\x34\x30\x34\x34\x35\x41\x43\x30\x41\x30\x30\x34\x34\x31\x38\x00\x00\x00\x00'
vendor_parrot = Dot11EltVendorSpecific(ID=221, len = len(parrot_payload) + 3 ,oui=0x9003b7, info = parrot_payload)



# payload 33
dri_payload = b'\x0d\xaa\xf0\x19\x01\x10\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd0\x07\x00\x00\x4b\x3d\x00\x00'
# payload 108
dri_payload2=b'\x0d\xab\xf0\x19\x04\x00\x121588E040445AC004418\x00\x00\x00\x00\x10\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd0\x07\x00\x00\x55\x3d\x00\x00\x40\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

#tests
# payload 33
dri_payload_t = b'\x0d\xaa\xf0\x19\x01\x10\x21\x40\x12\x90\x34\x34\x34\x34\x35\x35\x35\x35\x02\x02\x34\x08\x34\x08\x23\x23\x02\x03\x32\x00'
# payload 108
dri_payload2_t=b'\x0d\xab\xf0\x19\x04\x00\x121588E040445AC004418\x00\x00\x00\x00\x10\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd0\x07\x00\x00\x55\x3d\x00\x00\x40\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00\x00\x00\x00\x00\x00\x50\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

ie_vendor_parrot = Dot11EltVendorSpecific(ID=221, len = len(dri_payload_t) + 3 ,oui=0xfa0bbc, info = dri_payload_t)
# Flight Info
ie_vendor_parrot2 = Dot11EltVendorSpecific(ID=221, len = len(dri_payload2_t) + 3 ,oui=0xfa0bbc, info = dri_payload2_t)

packet = RadioTap() / Dot11() / beacon_fields / ie_ssid / ie_rates #/ vendor_parrot
packet.subtype = frame_subtype
packet.type = frame_type
packet.addr1 = dest_addr
packet.addr2 = src_addr
packet.addr3 = src_addr
packet.SC = fragment_number + seq_number

packet2 = packet

packet = packet / ie_vendor_parrot
packet2 = packet2 / ie_vendor_parrot2

packet_list = [packet, packet2] #to send both packets in a list
print(packet_list)
sendp(packet, iface=iface, loop=1, inter=0.3)
