from __future__ import print_function
from scapy.layers.dot11 import *
from scapy.utils import rdpcap, hexdump
from scapy.sendrecv import sendp
import random

class Beacon:
    def __init__(self, source_address, ssid ):


        """ if len(source_address) == 0:
            source_address = "60:60:1f:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
        if len(ssid) == 0:
            ssid = "MAVIC_AIR_REAL" """

        # Frame Control Field> 0x8000
        self.version = 0
        self.frame_type = 0         # Managemnet frame 00
        self.frame_subtype = 8      # Beacon 1000
        self.flags = 0              # hardcoded

        # Address fields
        self.dest_addr = 'ff:ff:ff:ff:ff:ff'    # address 1
        self.src_addr = source_address          # address 2
        self.bssid = self.src_addr              # address 3
        self.fragment_number = 0                # hardcoded
        self.seq_number = 0                     # hardcoded

        # Frame Body -- 802.11 Management Beacon
        self.b_timestamp = 1608204089   # hardcoded
        self.b_interval = 102           # hardcoded
        self.cap_flags = 0x0431         # Capability flags... hardcoded

        self.ssid = ssid
    

    '''
    It returns the scapy packet corresponding to the main fields of a Beacon packet
    Returns a Dot11 scapy object type Beacon
    '''
    def get_beacon(self):

        beacon_base = RadioTap() / Dot11() / Dot11Beacon(timestamp = self.b_timestamp, beacon_interval= self.b_interval, cap=self.cap_flags) 

        beacon_base.addr1 = self.dest_addr
        beacon_base.addr2 = self.src_addr
        beacon_base.addr3 = self.src_addr
        beacon_base.SC = self.seq_number # Normally fragment_number + seq_number

        beacon_base.subtype = self.frame_subtype
        beacon_base.type = self.frame_type

        # Mandatory Elements in Beacon packet type

        tag_ssid = Dot11Elt(ID=0, len= len(self.ssid), info = self.ssid) # TAG Parameters - SSID
        tag_rates = Dot11Elt(ID='Rates', len=8, info = b'\x82\x84\x8b\x96\x0c\x12\x18\x24') # ToDo -> customize , # hardcoded

        beacon_base = beacon_base / tag_ssid / tag_rates
        return beacon_base


    '''
    Changes the source address and the BSSID of the Beacon packet
    '''
    def set_addr2(self, beacon_base_packet, new_address):
        beacon_base_packet.addr2 = new_address
        beacon_base_packet.addr3 = new_address
    

    '''
    Changes the SSID of the Beacon packet
    '''
    def set_ssid(self, beacon_base_packet, ssid_value):
        self.ssid = ssid_value
        beacon_base_packet.ssid = ssid_value

    