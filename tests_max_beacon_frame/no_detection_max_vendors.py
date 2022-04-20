from scapy.all import *
import random
import string

# Maximum payload

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


# == Non Mandatory IE == #
ie_ds = Dot11Elt(ID = 3, len= 1, info = b'\xf3')

# == Non Mandatory IE:TIM max 259 bytes == #
payload=''
for i in range(200):
	a=''.join(random.choices(string.digits + 'abcdef', k=2))
	payload=payload+a
payload=bytes.fromhex(payload)
ie_tim = Dot11Elt(ID=5, len=200, info = payload)

# == Non Mandatory IE:Country == #
payload=''
for i in range(200):
	a=''.join(random.choices(string.digits + 'abcdef', k=2))
	payload=payload+a
payload=bytes.fromhex(payload)
ie_country=Dot11Elt(ID=7, len=len(payload), info=payload)

# == Non Mandatory IE:ERP Information == #
#ie_erp = Dot11EltERP(ID=42, len=1, NonERP_Present=0, Use_Protection=0, Barker_Preamble_Mode=0, res=0)
ie_erp=Dot11Elt(ID=42, len=1, info=b'\x00')

# == Non Mandatory IE:Extended Supported Rates == #
payload=''
for i in range(200):
	a=''.join(random.choices(string.digits + 'abcdef', k=2))
	payload=payload+a
payload=bytes.fromhex(payload)

ie_supprates = Dot11Elt(ID=50, len=len(payload), info = payload)
# == Non Mandatory IE:HT Capabilities == #
#ie_htcap=Dot11EltHTCapabilities(ID=45, len=26, L_SIG_TXOP_Protection=0, Forty_Mhz_Intolerant=0, PSMP=0, DSSS_CCK=0, Max_A_MSDU=0, Delayed_BlockAck=0,Rx_STBC=1,Tx_STBC=1, Short_GI_40Mhz=0, Short_GI_20Mhz=1, Green_Field=0, SM_Power_Save=3, Supported_Channel_Width=0, LDPC_Coding_Capability=0, res1=0, Min_MPDCU_Start_Spacing=0, Max_A_MPDU_Length_Exponent=2, res2=0,TX_Unequal_Modulation=0, TX_Max_Spatial_Streams=0, TX_RX_MCS_Set_Not_Equal=0, TX_MCS_Set_Defined=0, res3=0,RX_Highest_Supported_Data_Rate=0, res4=0, RX_MSC_Bitmask=65535, res5=0,RD_Responder=0, HTC_HT_Support=0, MCS_Feedback=0,res6=0, PCO_Transition_Time=0, PCO=0,res7=0, Channel_Estimation_Capability=0, CSI_max_n_Rows_Beamformer_Supported=0, Compressed_Steering_n_Beamformer_Antennas_Supported=0, Noncompressed_Steering_n_Beamformer_Antennas_Supported=0, CSI_n_Beamformer_Antennas_Supported=0, Minimal_Grouping=0, Explicit_Compressed_Beamforming_Feedback=0, Explicit_Noncompressed_Beamforming_Feedback=0, Explicit_Transmit_Beamforming_CSI_Feedback=0, Explicit_Compressed_Steering=0, Explicit_Noncompressed_Steering=0, Explicit_CSI_Transmit_Beamforming=0, Calibration=0, Implicit_Trasmit_Beamforming=0, Transmit_NDP=0, Receive_NDP=0, Transmit_Staggered_Sounding=0, Receive_Staggered_Sounding=0, Implicit_Transmit_Beamforming_Receiving=0, ASEL=0)
#ie_htcap=Dot11Elt(ID=45, len=26, info=b'\xac\x01\x02\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
payload=''
for i in range(200):
	a=''.join(random.choices(string.digits + 'abcdef', k=2))
	payload=payload+a
payload=bytes.fromhex(payload)

ie_htcap = Dot11Elt(ID=45, len=len(payload), info = payload)

# == Non Mandatory IE:HT Information == #
#ie_htinfo=Dot11Elt(ID=61, len=22, info=b'\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
payload=''
for i in range(151):
	a=''.join(random.choices(string.digits + 'abcdef', k=2))
	payload=payload+a
payload=bytes.fromhex(payload)

ie_htinfo = Dot11Elt(ID=61, len=len(payload), info = payload)

# == Non Mandatory IE:RSN Information == #
#ie_rsn=Dot11EltRSN(ID=48, len=20, version=1, group_cipher_suite='00:0f:ac', nb_pairwise_cipher_suites=1, pairwise_cipher_suites='00:0f:ac', nb_akm_suites=1, akm_suites='00:0f:ac', mfp_capable=0, mfp_required=0, gtksa_replay_counter=0, ptksa_replay_counter=3, no_pairwise=0, pre_auth=0, reserved=0)
#ie_rsn=Dot11Elt(ID=48, len=20, info=b'\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x0c\x00')
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
for i in range(252):
	a=''.join(random.choices(string.digits + 'abcdef', k=2))
	payload=payload+a
payload=bytes.fromhex(payload)
vendor2_payload=payload

vendor2 = Dot11EltVendorSpecific(ID=221, len=len(vendor2_payload)+3, oui= 0x4545f2, info = vendor2_payload)

#random payload vendor3
payload=''
for i in range(252):
	a=''.join(random.choices(string.digits + 'abcdef', k=2))
	payload=payload+a
payload=bytes.fromhex(payload)
vendor3_payload=payload

vendor3 = Dot11EltVendorSpecific(ID=221, len=len(vendor3_payload)+3, oui= 0x014ac2, info = vendor3_payload)

#random payload vendor4
payload=''
for i in range(252):
	a=''.join(random.choices(string.digits + 'abcdef', k=2))
	payload=payload+a
payload=bytes.fromhex(payload)
vendor4_payload=payload

vendor4 = Dot11EltVendorSpecific(ID=221, len=len(vendor4_payload)+3, oui= 0xdf45f2, info = vendor4_payload)

#random payload vendor5
payload=''
for i in range(136):
	a=''.join(random.choices(string.digits + 'abcdef', k=2))
	payload=payload+a
payload=bytes.fromhex(payload)
vendor5_payload=payload

vendor5 = Dot11EltVendorSpecific(ID=221, len=len(vendor5_payload)+3, oui= 0x6745f2, info = vendor5_payload)

# == Information Element: Vendor Specifics (221)
#telemetry
dji_payload=b'Xb\x13\x10\x02M\x063\x1f0K1CG6G3AH8V2y\x00\x30\x30\xf0\x00\x05\x00\x00\x00\x00\xef\xff\x0c\x00\x00\x00\x00\x00\x00\x00\x00C\x00\x00\x00\x00\x99\x01\x00\x00A\xf9|\x00\xcc=\x14\x00\x00\x00\x00\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf0\x00\x00\x00\x00\x00\x00\xef\xff\x0c\x00\x00\x00\x00\x00\x00\x00\x00C\x00\x00\x00\x00\x99\x01\x00\x00A\xf9|\x00\xcc=\x14\x00\x00\x00\x00\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x18\x54\x00\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x00\x18\x54\x00\x00\x00\x18\x54\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf0\x00\x00\x00\x00\x00'

# Vendor Specific: 26:37:12 (DJI)
ie_vendor_dji = Dot11EltVendorSpecific(ID=221, len = len(dji_payload)+3 ,oui=0x263712, info = dji_payload)

packet = RadioTap() / Dot11() / beacon_fields / ie_ssid / ie_rates /vendor1/vendor2/vendor3/vendor4/vendor5/ie_vendor_dji
packet.subtype = frame_subtype
packet.type = frame_type
packet.addr1 = dest_addr
packet.addr2 = src_addr
packet.addr3 = src_addr
packet.SC = fragment_number + seq_number

packet.show()

sendp(packet,iface= iface, loop = 1, inter= 0.3)

#NO - this is the max payload that scapy support in sending but the Aeroscope does not detect anything

