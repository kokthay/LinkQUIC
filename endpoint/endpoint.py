from bcc import BPF
import socket
from struct import pack
import ctypes
import struct
import time

with open("endpoint.c", "r") as f:
    bpf_program = f.read()
bpf = BPF(text=bpf_program)
fn = bpf.load_func("ingress_xdp", BPF.XDP)
# Attach XDP to network interfaces
bpf.attach_xdp("ens21", fn)
# Attach trace_udp_send_skb to udp_send_skb kernel function
bpf.attach_kprobe(event="udp_send_skb", fn_name="trace_udp_send_skb")
# Convert IPv4 from integer format to string
def ipv4_to_str(ip):
    """Convert an IPv4 address from integer to dotted-decimal format."""
    return socket.inet_ntoa(ctypes.c_uint32(ip).value.to_bytes(4, 'big'))
class QUICEventKey(ctypes.Structure):
    _fields_ = [
        ("sip", ctypes.c_uint32),
        ("dip", ctypes.c_uint32),
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
    ]
class QUICEvent(ctypes.Structure):
    _fields_ = [
        ("dcid_length", ctypes.c_ubyte),
        ("dcid", ctypes.c_ubyte * 20),
        ("scid_length", ctypes.c_ubyte),
        ("scid", ctypes.c_ubyte * 20),
        ("first_dcid", ctypes.c_ubyte * 20),
        ("timestamp", ctypes.c_uint64),
    ]
class DcidKey(ctypes.Structure):
    _fields_ = [
        ("dcid_length", ctypes.c_ubyte),
        ("dcid", ctypes.c_ubyte * 20),
    ]
class DcidValue(ctypes.Structure):
    _fields_ = [
        ("scid_length", ctypes.c_ubyte),
        ("first_dcid", ctypes.c_ubyte * 20),
    ]
class DestKey(ctypes.Structure):
    _fields_ = [
        ("dip", ctypes.c_uint32),
        ("dport", ctypes.c_uint16),
    ]
class DestValue(ctypes.Structure):
    _fields_ = [
        ("first_dcid", ctypes.c_ubyte * 20),
    ]
class SipKey(ctypes.Structure):
    _fields_ = [
        ("sip", ctypes.c_uint32),
        ("dip", ctypes.c_uint32),
        ("dport", ctypes.c_uint16),
    ]
class SipValue(ctypes.Structure):
    _fields_ = [
        ("dcid_length", ctypes.c_ubyte),
        ("scid_length", ctypes.c_ubyte),
        ("first_dcid", ctypes.c_ubyte * 20),
    ]
class FirstDcidKey(ctypes.Structure):
    _fields_ = [
        ("first_dcid", ctypes.c_ubyte * 20),
    ]
def print_connections_map(bpf):
    print("\nConnections Map:")
    connections_map = bpf["connections_map"]
    for key_bytes, value_bytes in connections_map.items():
        key = QUICEventKey.from_buffer_copy(key_bytes)
        value = QUICEvent.from_buffer_copy(value_bytes)
        sip = ipv4_to_str(key.sip)
        dip = ipv4_to_str(key.dip)
        dcid = " ".join(f"{b:02x}" for b in value.dcid[:value.dcid_length])
        scid = " ".join(f"{b:02x}" for b in value.scid[:value.scid_length])
        first_dcid = " ".join(f"{b:02x}" for b in value.first_dcid)
        timestamp_ns = value.timestamp  
        timestamp_sec = timestamp_ns / 1e9 
        print(f"Source IP: {sip}, Dest IP: {dip}, Sport: {key.sport}, Dport: {key.dport}, "
              f"DCID Length: {value.dcid_length}, DCID: {dcid}, "
              f"SCID Length: {value.scid_length}, SCID: {scid}, "
              f"First DCID: {first_dcid}, "
              f"Timestamp: {timestamp_sec:.6f} sec")
def print_dcid_map(bpf):
    print("\nDcids Map:")
    dcids_map = bpf["dcids_map"]
    for key_bytes, value_bytes in dcids_map.items():
        key = DcidKey.from_buffer_copy(key_bytes)
        value = DcidValue.from_buffer_copy(value_bytes)
        first_dcid = " ".join(f"{b:02x}" for b in value.first_dcid)
        
        dcid = " ".join(f"{b:02x}" for b in key.dcid[:key.dcid_length])
        print(f"DCID Length: {key.dcid_length}, DCID: {dcid}, "
              f"SCID Length: {value.scid_length}, First DCID: {first_dcid}")
def print_dest_map(bpf):
    print("\nDest Map:")
    dest_map = bpf["dest_map"]
    for key_bytes, value_bytes in dest_map.items():
        key = DestKey.from_buffer_copy(key_bytes)
        value = DestValue.from_buffer_copy(value_bytes)
        dip = ipv4_to_str(key.dip)
        first_dcid = " ".join(f"{b:02x}" for b in value.first_dcid)
        print(f"Dest IP: {dip}, Dport: {key.dport}, First DCID: {first_dcid}")
def print_sip_map(bpf):
    print("\nSIP Map:")
    sip_map = bpf["sip_map"]
    for key_bytes, value_bytes in sip_map.items():
        key = SipKey.from_buffer_copy(key_bytes)
        value = SipValue.from_buffer_copy(value_bytes)
        sip = ipv4_to_str(key.sip)
        dip = ipv4_to_str(key.dip)
        first_dcid = " ".join(f"{b:02x}" for b in value.first_dcid)
        print(f"Source IP: {sip}, Dest IP: {dip},Dport: {key.dport}, "
              f"DCID Length: {value.dcid_length}, SCID Length: {value.scid_length}, First DCID: {first_dcid}")
def print_potential_quic(bpf):
    print("\nPotential QUIC Map:")
    potential_quic = bpf["potential_quic"]
    for key_bytes, value_bytes in potential_quic.items():
        key = QUICEventKey.from_buffer_copy(key_bytes)
        value = QUICEvent.from_buffer_copy(value_bytes)
        sip = ipv4_to_str(key.sip)
        dip = ipv4_to_str(key.dip)
        dcid = " ".join(f"{b:02x}" for b in value.dcid[:value.dcid_length])
        first_dcid = " ".join(f"{b:02x}" for b in value.first_dcid)
        print(f"Source IP: {sip}, Dest IP: {dip}, Sport: {key.sport}, Dport: {key.dport}, "
              f"DCID Length: {value.dcid_length}, DCID: {dcid}, First DCID: {first_dcid}")
print("Tracing... Press Ctrl+C to stop.")
try:
    while True:
        print_connections_map(bpf)
        print_dcid_map(bpf)
        print_dest_map(bpf)
        print_sip_map(bpf)
        print_potential_quic(bpf)
        time.sleep(2) #sleep 2s
except KeyboardInterrupt:
    bpf.remove_xdp("ens21", 0)
    print("Detaching...")