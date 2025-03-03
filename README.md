# LinkQUIC: QUIC Traffic Identification in Kernel Space Using a Heuristic Technique with eBPF 

This project provides tools to monitor QUIC network connections using eBPF (Extended Berkeley Packet Filter) programs. It includes two components: an Endpoint Monitor (designed to run on a QUIC client or server host) and a Middlebox Monitor (for deployment on a network device that observes traffic). 

For any questions, please contact [Kokthay Poeng](mailto:kokthay.poeng@unamur.be).

## Dependencies

- Python 3.10
- eBPF [BCC](https://github.com/iovisor/bcc/blob/master/INSTALL.md) (Requires Linux Kernel 5.15.0 or later)

## Code Execution Flow

1. Initial:
- Create five BPF maps: `connections_map`, `dcids_map`, `dest_map`, `sip_map`, and `potential_quic`.
- When `udp_send_skb` or `xdp` is triggered, capture Source IP, Source Port, Destination IP, Destination Port, and the first 48 bytes of the payload.
- Determine whether the packet is a Long Header or Short Header QUIC packet.

2. Long Header:
- Dissect the payload into QUIC header fields, including version, DCID length, DCID, SCID length, and SCID.
- Validate that the QUIC version is recognized by [IANA](https://www.iana.org/assignments/quic/quic.xhtml).
- Validate DCID and SCID lengths to align with [RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000).
- If the packet passes all validations, it is confirmed as a QUIC connection:
  - Capture DCID, SCID, their lengths, and first_CID and store them in the BPF maps.
- If the connection already exists, update only the new DCID, DCID length, and timestamp.

3. Short Header:
- Validate UDP payload length.
- Verify Fixed Bit (must be `0b1`).
- Look up the connection in `connections_map` & `potential_quic`:
  - If found → Update `connections_map` and `sip_map`.
  - If not found → The packet might indicate Connection Migration, Probing Phase, QUIC Multipath, or be Non-QUIC.
- To avoid unnecessary execution, first check if Destination IP and Port exist in `dest_map`:
  - If not present → The packet is not QUIC.
- Connection Migration Handling:
  - Capture DCID and check `dcids_map`:
    - If found → Update `connections_map` and `sip_map` (Confirming connection migration).
    - If not found → The packet could be in Probing Phase, QUIC Multipath, or Non-QUIC.
- Probing Phase / QUIC Multipath Handling:
  - Look up Source IP, Destination IP, and Destination Port in `sip_map`:
    - If not found → Packet is not QUIC.
    - If found → Update `potential_quic` with observed details.


## Output Format

This project utilizes multiple eBPF maps to store and process QUIC traffic information efficiently. Below are the key maps used:

1. Connections Map (`connections_map`)
   - Key: Source IP, Destination IP, Source Port, Destination Port
   - Value: DCID, SCID, First DCID, and Timestamp
   - Purpose: Tracks active QUIC connections, storing the observed connection identifiers and last seen timestamp.

2. DCID Map (`dcids_map`)
   - Key: Destination Connection ID (DCID)
   - Value: SCID Length and First DCID
   - Purpose: Maps observed connection IDs to their original First DCID, allowing tracking of QUIC connection migration.

3. Destination Map (`dest_map`)
   - Key: Destination IP and Destination Port
   - Value: First DCID
   - Purpose: Recognizes if a packet’s destination was previously observed in a QUIC handshake to avoid unnecessary execution.

4. SIP Map (`sip_map`)
   - Key: Source IP, Destination IP, Destination Port
   - Value: First DCID, DCID Length, SCID Length
   - Purpose: Helps identify QUIC Probing Phase or QUIC Multipath packets.

5. Potential QUIC Map (`potential_quic`)
   - Key: Source IP, Destination IP, Source Port, Destination Port
   - Value: DCID, First DCID
   - Purpose: Stores flows suspected to be QUIC but not yet confirmed, helping to detect Probing Phase or QUIC Multipath Handling.

Each of these maps can provide insights into QUIC connections, their transitions, and potential anomalies. The maps ensure that QUIC traffic is efficiently tracked and analyzed without requiring decryption.

## Installation Guide for Ubuntu 22.04.04 LTS
### 1. Clone the Repository
```bash
git clone https://github.com/kokthay/LinkQUIC.git
```
### 2. Install BCC
```bash
cd LinkQUIC
chmod +x install_bcc(ubuntu22.04).sh
./install_bcc(ubuntu22.04).sh
```
### 3. Configure Network Interfaces
Add or update the network interfaces in `middlebox/middlebox.py` or `endpoint/endpoint.py` to match your system's network configuration.
### 4. Run LinkQUIC
On the Endpoint Machine:
```bash
sudo python3 endpoint/endpoint.py
```
On the Middlebox Machine:
```bash
sudo python3 middlebox/middlebox.py
```
## Credits and Acknowledgments
- This work  is supported by Belgium Walloon Region [CyberExcellence](https://cyberexcellence.be/) Program (Grant #2110186).
- BCC and eBPF: This project builds on the BCC framework and Linux eBPF technology. Thanks to the open-source community around eBPF and BCC for providing the tools and examples that made this project possible. For more information on BCC, visit the BCC GitHub repository.
- QUIC Protocol: QUIC header parsing logic is based on the protocol’s specification (IETF RFC 9000 for QUIC Transport). The project specifically targets QUIC version 1. Future versions or variants might require adjustments.