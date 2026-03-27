from scapy.layers.dot11 import *
from scapy.utils import rdpcap, hexdump
from scapy.sendrecv import sendp
import random
import calendar
import time

from Drone import (
    DJI_MAC_PREFIX, DEFAULT_SSID, BROADCAST_ADDR,
    BEACON_SUBTYPE, BEACON_FRAME_TYPE, BEACON_INTERVAL,
    BEACON_CAP_FLAGS, SUPPORTED_RATES,
)


class Beacon:
    def __init__(self, source_address, ssid):

        if len(source_address) == 0:
            source_address = "{}:%02x:%02x:%02x".format(DJI_MAC_PREFIX) % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
        if len(ssid) == 0:
            ssid = DEFAULT_SSID

        self.frame_type = BEACON_FRAME_TYPE
        self.frame_subtype = BEACON_SUBTYPE
        self.dest_addr = BROADCAST_ADDR
        self.src_addr = source_address
        self.bssid = self.src_addr
        self.seq_number = 0

        ts = calendar.timegm(time.gmtime())
        self.b_timestamp = ts
        self.b_interval = BEACON_INTERVAL
        self.cap_flags = BEACON_CAP_FLAGS

        self.ssid = ssid

    def get_beacon(self):
        beacon_base = RadioTap() / Dot11() / Dot11Beacon(timestamp=self.b_timestamp, beacon_interval=self.b_interval, cap=self.cap_flags)

        beacon_base.addr1 = self.dest_addr
        beacon_base.addr2 = self.src_addr
        beacon_base.addr3 = self.src_addr
        beacon_base.SC = self.seq_number

        beacon_base.subtype = self.frame_subtype
        beacon_base.type = self.frame_type

        tag_ssid = Dot11Elt(ID=0, len=len(self.ssid), info=self.ssid)
        tag_rates = Dot11Elt(ID='Rates', len=8, info=SUPPORTED_RATES)

        beacon_base = beacon_base / tag_ssid / tag_rates
        return beacon_base

    def set_addr2(self, beacon_base_packet, new_address):
        beacon_base_packet.addr2 = new_address
        beacon_base_packet.addr3 = new_address

    def set_ssid(self, beacon_base_packet, ssid_value):
        self.ssid = ssid_value
        beacon_base_packet.ssid = ssid_value
