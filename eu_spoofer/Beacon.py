from __future__ import print_function
from scapy.layers.dot11 import *
import random
import calendar;
import time;


class Beacon:
    def __init__(self, source_address, ssid):

        if len(source_address) == 0:
            source_address = "90:3a:e6:%02x:%02x:%02x" % (
                random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
        if len(ssid) == 0:
            ssid = "Parrot-Anafi-real"

        # Frame Control Field> 0x8000
        self.version = 0
        self.frame_type = 0  # Managemnet frame 00
        self.frame_subtype = 8  # Beacon 1000
        self.flags = 0  # hardcoded

        # Address fields
        self.dest_addr = 'ff:ff:ff:ff:ff:ff'  # address 1
        self.src_addr = source_address  # address 2
        self.bssid = self.src_addr  # address 3
        self.fragment_number = 0  # hardcoded
        self.seq_number = 0  # hardcoded

        # Frame Body -- 802.11 Management Beacon
        ts = calendar.timegm(time.gmtime())

        self.b_timestamp = ts  # hardcoded
        self.b_interval = 102  # hardcoded
        self.cap_flags = 0x0431  # Capability flags... hardcoded

        self.ssid = ssid

    # Manadatory fields of a beacon frame concatenated together ssid and supported rates
    def get_beacon(self):

        beacon_base = RadioTap() / Dot11() / Dot11Beacon(timestamp=self.b_timestamp, beacon_interval=self.b_interval,
                                                         cap=self.cap_flags)

        beacon_base.addr1 = self.dest_addr
        beacon_base.addr2 = self.src_addr
        beacon_base.addr3 = self.src_addr
        beacon_base.SC = self.seq_number  # Normally fragment_number + seq_number

        beacon_base.subtype = self.frame_subtype
        beacon_base.type = self.frame_type


        tag_ssid = Dot11Elt(ID=0, len=len(self.ssid), info=self.ssid)  # TAG Parameters - SSID
        tag_rates = Dot11Elt(ID='Rates', len=1, info=b'\x8c')

        beacon_base = beacon_base / tag_ssid / tag_rates
        return beacon_base
