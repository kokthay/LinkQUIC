# Endpoint Monitor

The Endpoint Monitor is designed to run on a QUIC endpoint (a host that is either a client or server in a QUIC connection). It consists of two files:

- `endpoint.c` – an eBPF program written in C, which will be loaded into the kernel. It hooks into the network stack to inspect UDP packets.
- `endpoint.py` – a Python script that uses BCC to compile and load the eBPF program, attach it to the appropriate hooks, and then retrieve and display the collected data.

## Captured Data
The Endpoint Monitor captures:
- Outgoing QUIC packets from the local host (using a kprobe on the kernel function `udp_send_skb`).
- Incoming QUIC packets to the local host (using XDP attached to network interfaces).

We tested the endpoint monitoring on Ubuntu 22.04.4 LTS, but it should work with other versions. Make sure to update the correct interface name in `endpoint.py`.

## Example Usage

To illustrate, let’s assume we run the Endpoint Monitor on a QUIC client machine.

### Start the monitor:
```bash
sudo python3 endpoint.py 
```

### Expected Output:
```
Tracing... Press Ctrl+C to stop.

Connections Map:

Dcids Map:

Dest Map:

SIP Map:

Potential QUIC Map:
```

### Testing QUIC Monitoring
The easiest way to test it after starting the monitor is to open a web browser and access websites that use the QUIC protocol (e.g., `youtube.com`, `facebook.com`, etc.). The maps displayed will show all QUIC connection information.