# LinkQUIC: QUIC Traffic Identification in Kernel Space with a Heuristic Technique Using eBPF 

LinkQUIC is a novel framework capable of distinguishing QUIC from normal UDP streams in kernel space without kernel modification, decrypting QUIC payloads, or prior knowledge of QUIC protocol implementations in user space. This framework can identify QUIC in both endpoints (e.g., client and server) and middleboxes (e.g., switches, routers, firewalls, etc.).
