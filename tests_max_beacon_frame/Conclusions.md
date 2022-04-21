# Conclusions

## Beacon Frame

  * Mac header: 24 bytes
  * Frame body: variable length (0 - 2320 bytes)
  * Fixed parameters (12 bytes): timestamp (8 bytes), beacon interval (2 bytes), capability info (2 bytes)
  * Tagged parameters (<=2308 bytes): SSID and supported rates are mandatory fields, vendor specific are at the end (<=252 bytes)
  * FCS: 4 bytes

The maximum length of a beacon frame is 2348 bytes.


## Script

|  Script                           |  Info                                                                                                                                                               |
|-----------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| max_fields_before_dji_presence.py | The max number of bytes before detecting a dji presence are 835. In the Raw data only the 16 (=\x10) is present and the other bytes are not the one in the remote ID|
|                                   |                                                                                                                                                                     |
| max_vendors_before_dji_presence.py| The max number of bytes before detecting a dji presence are 841. In the Raw data only the 16 (=\x10) is present and the other bytes are not the one in the remote ID|
|                                   |                                                                                                                                                                     |
| max_fields_before_dji_payload.py  | The Raw data contains all the dji vendor specific data. The uuid bytes of the dji vendor specific are ascii characters.                                             |
|                                   | The Aeroscope accepts as maximum 842 bytes and the last 54 bytes of the dji vendor are not parsed.                                                                  |
|                                   |                                                                                                                                                                     |
| max_flightLog_entry.py            | The dji payload is equal to the one in max_fields_before_dji_payload.py but with bytes related to uuid different from ascii characters.                             |
|                                   | The remaining 54 bytes that are not parsed but present in the raw data are chosen in a way that they generate decimals of 3 numbers                                 |
|                                   |                                                                                                                                                                     |
| max_fields_max_flightLog.py       | Same as max_fields_before_dji_payload.py but with the payload of max_flightLog_entry.py                                                                             |


## Results
The Aeroscope accepts a maximum number of bytes that is around 842 (if more bytes are sent: if they are sent after the dji payload the Aeroscope discards them, if they are sent before the dji payload the Aeroscope does not show properly the information contained in the Remote ID). So, by sending a bigger beacon frame the Aeroscope simply discards the other bytes.

  * The maximum length in scapy for a beacon field is 255 bytes
  * The maximum length in scapy for a beacon frame is ~1490 bytes
  * From the scripts under the folder Tests, it is possible to state that before detecting the **presence** of a dji drone, the Aeroscope accepts from 835 to 841 bytes (maximum limit to detect presence)


*See pdf for results targeting the Aeroscope storage*