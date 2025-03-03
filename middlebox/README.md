# Middlebox Monitor

The Middlebox Monitor is designed to run on a middlebox (e.g., switch, firewall, etc.). It consists of two files:

- `middlebox.c` – an eBPF program written in C, which will be loaded into the kernel. It hooks into the XDP network interface to inspect UDP packets.
- `middlebox.py` – a Python script that uses BCC to compile and load the eBPF program, attach it to the appropriate hooks, and then retrieve and display the collected data.

## Captured Data
The Middlebox Monitor captures incoming and outgoing QUIC packets using XDP attached to all network interfaces of the middlebox.

We tested the middlebox monitoring on **Ubuntu 22.04.4 LTS**, but it should work with other versions. Make sure to update the correct interface name in `middlebox.py`.

# Example Usage

To illustrate, let’s assume we run the Middlebox Monitor on an Ubuntu server running [Open vSwitch](https://www.openvswitch.org/). Then, update all network interfaces of the virtual switch in `middlebox.py`. This switch must be used for switching between a client and server or a client and the internet.

### Start the monitor:
```bash
sudo python3 middlebox.py 
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
The easiest way to test it after starting the monitor on the switch is to open a web browser on the client endpoint and access websites that use the QUIC protocol (e.g., `youtube.com`, `facebook.com`, etc.). The maps displayed will show all QUIC connection information in the middlebox machine.
