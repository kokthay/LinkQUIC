#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <net/inet_sock.h>
#include <net/inet_common.h>
#include <linux/if_ether.h>
struct quic_event_key {
    __u32 sip;
    __u32 dip;
    __u16 sport;
    __u16 dport;
};
struct quic_event {
    __u8 dcid_length;
    __u8 dcid[20];
    __u8 scid_length;
    __u8 scid[20];
    __u8 first_dcid[20];
   __u64 timestamp;
};
struct dcid_key {
    __u8 dcid_length;
    __u8 dcid[20];
};
struct dcid_value {
    __u8 scid_length;
    __u8 first_dcid[20];
};
struct dest_key {
    __u32 dip;
    __u16 dport;
};
struct sip_key {
    __u32 sip;
    __u32 dip;
    __u16 dport;
};
struct sip_value {
    __u8 dcid_length;
    __u8 scid_length;
    __u8 first_dcid[20];
};
struct firstdcid {
    __u8 first_dcid[20];
};
BPF_HASH(connections_map, struct quic_event_key, struct quic_event, 50000);
BPF_HASH(dcids_map, struct dcid_key, struct dcid_value, 50000);
BPF_HASH(dest_map, struct dest_key, struct firstdcid, 50000);
BPF_HASH(sip_map, struct sip_key, struct sip_value, 50000);
BPF_HASH(potential_quic,  struct quic_event_key, struct quic_event, 50000);
BPF_HASH(potential_quic_dcid, struct dcid_key, struct firstdcid, 50000);
int ingress_xdp(struct xdp_md *ctx){
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;
    struct iphdr *ip4 = (void *)(eth + 1);
    if ((void *)(ip4 + 1) > data_end) return XDP_PASS;
    if (ip4->protocol != IPPROTO_UDP) return XDP_PASS;
    struct udphdr *udp = (void *)(ip4 + 1);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    __u8 offset;
    __u16 udp_len;
    __u8 payload[48];
    __u8 tmp_dcid[20];
    struct quic_event_key key = {};
    struct quic_event event = {};
    struct quic_event *existing_event;
    struct dcid_key dcid_key = {}; 
    struct dcid_value dcid_val = {}; 
    struct dcid_value *existing_dcid_val; 
    struct dest_key dest = {};
    struct sip_key sip = {};
    struct sip_value sip_val = {};
    struct sip_value *exitsing_sip_val;
    struct firstdcid firstdcid = {};
    struct firstdcid *existing_firstdcid;
    udp_len = ntohs(udp->len) - sizeof(*udp);
    if (udp_len <= 10) return XDP_PASS;
    void *payload_start = (void *)(udp + 1);
    bpf_probe_read_kernel(payload, sizeof(payload), payload_start);    
    key.sip = ntohl(ip4->saddr);
    key.dip = ntohl(ip4->daddr);
    key.sport = ntohs(udp->source);
    key.dport = ntohs(udp->dest);    
    if ((payload[0] & 0x80) != 0){//LONG Packet
        existing_event = connections_map.lookup(&key);
        if (!existing_event) { //LONG: New connection
                //verify verison
            if (payload[1] != 0x00 || payload[2] != 0x00 || payload[3] != 0x00 || payload[4] != 0x01) return XDP_PASS;
                //caputre dcid length
            event.dcid_length = payload[5];
                //verify dicd length must <20
            if (event.dcid_length > 20) return XDP_PASS;
                //capture dcid
            bpf_probe_read_kernel(event.dcid, event.dcid_length, payload + 6);
                //capture scid length
            offset = 6 + payload[5];
            if (offset + 1 > 24 ) return XDP_PASS;
            event.scid_length = payload[offset];
                //verify dicd length must <20
            if (event.scid_length > 20) return XDP_PASS;
                //caputre scid
            offset = offset+1;
            if (offset > 48) return XDP_PASS;
            bpf_probe_read_kernel(event.scid, event.scid_length, payload + offset);
            if(event.dcid_length==0){
                __builtin_memcpy(tmp_dcid, event.scid, 20);
                tmp_dcid[19]++;
            }else{
                __builtin_memcpy(tmp_dcid, event.dcid, 20); 
            }
            __builtin_memcpy(event.first_dcid, tmp_dcid, 20);
            event.timestamp =bpf_ktime_get_ns();
            connections_map.update(&key, &event);
            __builtin_memcpy(dcid_val.first_dcid, tmp_dcid, 20);
            // Insert DCID into dcids_map
            if (event.dcid_length!=0){ 
                dcid_key.dcid_length = event.dcid_length;
                __builtin_memcpy(dcid_key.dcid, event.dcid, 20);
                dcid_val.scid_length = event.scid_length;
                dcids_map.update(&dcid_key, &dcid_val);
            }
            // Insert SCID into dcids_map (SCID is DCID of the reply)
            if (event.scid_length!=0){
                dcid_key.dcid_length = event.scid_length;
                __builtin_memcpy(dcid_key.dcid, event.scid, 20);
                dcid_val.scid_length = event.scid_length;
                dcids_map.update(&dcid_key, &dcid_val);
            }
            // Insert into dest_map
            __builtin_memcpy(&dest.dip, &key.dip, 4);
            dest.dport = key.dport;
            __builtin_memcpy(firstdcid.first_dcid, tmp_dcid, 20);
            dest_map.update(&dest, &firstdcid);
            // Insert into sip_map
            __builtin_memcpy(&sip.sip, &key.sip, 4);
            __builtin_memcpy(&sip.dip, &key.dip, 4);
            sip.dport = key.dport;
            __builtin_memcpy(sip_val.first_dcid, tmp_dcid, 20);
            sip_val.dcid_length = event.dcid_length;
            sip_val.scid_length = event.scid_length;
            sip_map.update(&sip, &sip_val);
            return XDP_PASS;
        }
        else{ // LONG: existed connection, update only DCID and DCID length
            event = *existing_event;
            event.dcid_length = payload[5];
            if (event.dcid_length > 20) return XDP_PASS;
            event.timestamp = bpf_ktime_get_ns();
            if(event.dcid_length !=0){
                bpf_probe_read_kernel(event.dcid, event.dcid_length, payload + 6);
                connections_map.update(&key, &event);
                //Insert new DCID to DCID map
                dcid_key.dcid_length = event.dcid_length;
                __builtin_memcpy(dcid_key.dcid, event.dcid, 20);
                dcid_val.scid_length = event.scid_length;
                __builtin_memcpy(dcid_val.first_dcid, event.first_dcid, 20);
                dcids_map.update(&dcid_key,&dcid_val);
                //Insert new DCID length to SIP map
                __builtin_memcpy(&sip.sip, &key.sip, 4);
                __builtin_memcpy(&sip.dip, &key.dip, 4);
                sip.dport = key.dport;
                __builtin_memcpy(sip_val.first_dcid, event.first_dcid, 20);
                sip_val.dcid_length = event.dcid_length;
                sip_val.scid_length = event.scid_length;
                sip_map.update(&sip, &sip_val);
                return XDP_PASS;
            }
            else {
                connections_map.update(&key, &event);
                return XDP_PASS;
            }  
        }
        return XDP_PASS;
    }
    else{ //SHORT HEADER
        if (udp_len < 19) return XDP_PASS;
        if ((payload[0] & 0x40) == 0) return 0; 
        existing_event = connections_map.lookup(&key);
        if (!existing_event) { //can be connection migration or potential QUIC or not QUIC
            __builtin_memcpy(&dest.dip, &key.dip, 4);
            dest.dport = key.dport;
            existing_firstdcid = dest_map.lookup(&dest);
            if(!existing_firstdcid) return XDP_PASS;//destination not exited => NOT QUIC
            __builtin_memcpy(tmp_dcid, payload+1, 20);
            //Look up in Potential QUIC map
            existing_event = potential_quic.lookup(&key);
            if (!existing_event){//connection migration or new poential QUIC
                for (__u8 len = 1; len <= 20; len++) {
                    dcid_key.dcid_length = len;
                    // Adjust the key's DCID for the current length
                    __builtin_memcpy(dcid_key.dcid, tmp_dcid, len);
                    // Perform the lookup with the adjusted key
                    existing_dcid_val = dcids_map.lookup(&dcid_key);
                    if (existing_dcid_val) {break;} 
                }
                if (!existing_dcid_val){//can be QUIC
                    __builtin_memcpy(&sip.sip, &key.sip, 4);
                    __builtin_memcpy(&sip.dip, &key.dip, 4);
                    sip.dport = key.dport;
                    exitsing_sip_val = sip_map.lookup(&sip);
                    if (!exitsing_sip_val) {return XDP_PASS;} // not QUIC
                    else {//determined poential QUIC insert to Potential QUIC map
                        if(exitsing_sip_val->dcid_length==0)return XDP_PASS;
                        struct quic_event event = {};
                        __builtin_memcpy(event.first_dcid, exitsing_sip_val->first_dcid, 20);
                        __builtin_memcpy(firstdcid.first_dcid, exitsing_sip_val->first_dcid, 20);
                        event.dcid_length = exitsing_sip_val->dcid_length;
                        event.scid_length = exitsing_sip_val->scid_length;
                        if (event.dcid_length>20) return XDP_PASS;
                        bpf_probe_read_kernel(&event.dcid, event.dcid_length, tmp_dcid);
                        potential_quic.update(&key,&event);
                        // Insert DCID into potential_quic_dcid
                        dcid_key.dcid_length = event.dcid_length;
                        __builtin_memcpy(dcid_key.dcid, event.dcid, 20);
                        potential_quic_dcid.update(&dcid_key, &firstdcid);
                        return XDP_PASS;
                    }
                    return XDP_PASS;
                }
                else { // Connecntion Migration with the same CID
                    struct quic_event event = {};
                    event.dcid_length= dcid_key.dcid_length;
                    event.scid_length= existing_dcid_val->scid_length;
                    __builtin_memcpy(event.dcid,dcid_key.dcid,20);
                    __builtin_memcpy(event.first_dcid, existing_dcid_val->first_dcid, 20);
                    event.timestamp =bpf_ktime_get_ns();
                    connections_map.update(&key, &event);
                    // Insert into sip_map
                    __builtin_memcpy(&sip.sip, &key.sip, 4);
                    __builtin_memcpy(&sip.dip, &key.dip, 4);
                    sip.dport = key.dport;
                    sip_val.dcid_length=dcid_key.dcid_length;
                    sip_val.scid_length=existing_dcid_val->scid_length;
                    __builtin_memcpy(sip_val.first_dcid, existing_dcid_val->first_dcid, 20);
                    sip_map.update(&sip, &sip_val);
                    //pre-insert for reply
                    if (event.scid_length==0){
                        key.sip = ntohl(ip4->daddr);
                        key.dip = ntohl(ip4->saddr);
                        key.sport = ntohs(udp->dest);
                        key.dport = ntohs(udp->source);
                        event.scid_length = dcid_key.dcid_length;
                        event.dcid_length = 0;
                        __builtin_memcpy(event.scid, dcid_key.dcid, 20);
                        event.dcid[19]++; 
                        __builtin_memcpy(event.first_dcid, event.dcid, 20);
                        __builtin_memset(event.dcid, 0, sizeof(event.dcid));
                        connections_map.update(&key, &event);
                        return XDP_PASS;
                    }
                    return XDP_PASS;
                }
                return XDP_PASS;
            }
            else{ //new packet existed in Potential QUIC map 
                dcid_key.dcid_length = existing_event->dcid_length;
                event.dcid_length= dcid_key.dcid_length;
                if (dcid_key.dcid_length > 20)return XDP_PASS;
                bpf_probe_read_kernel(&dcid_key.dcid, dcid_key.dcid_length, tmp_dcid);
                existing_firstdcid = potential_quic_dcid.lookup(&dcid_key);
                if (!existing_firstdcid){// not QUIC
                    __builtin_memcpy(dcid_key.dcid, existing_event->dcid, 20);
                    potential_quic_dcid.delete(&dcid_key);
                    potential_quic.delete(&key);
                    return XDP_PASS;
                }
                else{ //QUIC identified
                    //sip_map update
                    __builtin_memcpy(&sip.sip, &key.sip, 4);
                    __builtin_memcpy(&sip.dip, &key.dip, 4);
                    sip.dport = key.dport;
                    __builtin_memcpy(sip_val.first_dcid, existing_event->first_dcid, 20);
                    sip_val.dcid_length = existing_event->dcid_length;
                    sip_val.scid_length = existing_event->scid_length;
                    sip_map.update(&sip, &sip_val);
                    //connection map udpate
                    struct quic_event event = {};
                    event = *existing_event;
                    event.timestamp = bpf_ktime_get_ns();
                    connections_map.update(&key, &event);
                    if(event.scid_length!=0){
                        __builtin_memcpy(&sip.sip, &key.dip, 4);
                        __builtin_memcpy(&sip.dip, &key.sip, 4);
                        sip.dport = key.sport;
                        __builtin_memcpy(sip_val.first_dcid, existing_event->first_dcid, 20);
                        sip_val.first_dcid[19]++;
                        sip_val.dcid_length = existing_event->scid_length;
                        sip_val.scid_length = existing_event->dcid_length;
                        sip_map.update(&sip, &sip_val);
                        potential_quic_dcid.delete(&dcid_key);
                        potential_quic.delete(&key);
                    }
                    else{//connection map udpate the reply only if SCID is 0
                        key.sip = ntohl(ip4->daddr);
                        key.dip = ntohl(ip4->saddr);
                        key.sport = ntohs(udp->dest);
                        key.dport = ntohs(udp->source);
                        event.scid_length= existing_event->dcid_length;
                        event.dcid_length= 0;
                        __builtin_memset(event.dcid, 0, sizeof(event.dcid));
                        if (event.scid_length>20){return XDP_PASS;}
                        __builtin_memcpy(event.scid, existing_event->dcid, 20);
                        __builtin_memcpy(event.first_dcid, existing_event->first_dcid, 20);
                        event.first_dcid[19]++;
                        event.timestamp = bpf_ktime_get_ns();
                        connections_map.update(&key, &event);
                        key.sip = ntohl(ip4->saddr);
                        key.dip = ntohl(ip4->daddr);
                        key.sport = ntohs(udp->source);
                        key.dport = ntohs(udp->dest);
                        potential_quic_dcid.delete(&dcid_key);
                        potential_quic.delete(&key);
                    }
                    return XDP_PASS;
                }
                return XDP_PASS;
            }
            return XDP_PASS;
        }
        else{ //SHORT: existed connection
            event = *existing_event;
            event.timestamp = bpf_ktime_get_ns();
            connections_map.update(&key, &event);
            return XDP_PASS;
        }
        return XDP_PASS;
    }
    return XDP_PASS;
}
int trace_udp_send_skb(struct pt_regs *ctx, struct sk_buff *skb, struct flowi4 *fl4) {
    __u8 offset;
    __u16 udp_len;
    __u8 payload[48];
    __u8 tmp_dcid[20];
    struct quic_event_key key = {};
    struct quic_event *existing_event;
    struct dcid_key dcid_key = {}; 
    struct dcid_value dcid_val = {}; 
    struct dcid_value *existing_dcid_val; 
    struct dest_key dest = {};
    struct sip_key sip = {};
    struct quic_event event = {};
    struct sip_value sip_val = {};
    struct sip_value *exitsing_sip_val;
    struct firstdcid firstdcid = {};
    struct firstdcid *existing_firstdcid;
    struct flowi4 local_fl4;
    bpf_probe_read_kernel(&udp_len, sizeof(udp_len), &skb->len);
    if (udp_len <= 10) return 0; 
    bpf_probe_read_kernel(&local_fl4, sizeof(local_fl4), fl4);
    bpf_probe_read_kernel(&payload, sizeof(payload), skb->data + sizeof(struct iphdr) + sizeof(struct udphdr));
    key.sip = ntohl(local_fl4.saddr);
    key.sport = ntohs(local_fl4.fl4_sport);
    key.dip = ntohl(local_fl4.daddr);
    key.dport = ntohs(local_fl4.fl4_dport);    
    if ((payload[0] & 0x80) != 0) { //LONG HEADER
        existing_event = connections_map.lookup(&key);
        if (!existing_event) { //LONG: New connection
            struct quic_event event = {};
                //verify verison
            if (payload[1] != 0x00 || payload[2] != 0x00 || payload[3] != 0x00 || payload[4] != 0x01) return 0;
                //caputre dcid length
            event.dcid_length = payload[5];
                //verify dicd length must <20
            if (event.dcid_length > 20) return 0;
                //capture dcid
            bpf_probe_read_kernel(event.dcid, event.dcid_length, payload + 6);
                //capture scid length
            offset = 6 + payload[5];
            if (offset + 1 > 24 ) return 0;
            event.scid_length = payload[offset];
            if (event.scid_length > 20) return 0;
                //caputre scid
            offset = offset+1;
            if (offset > 48) return 0;
            bpf_probe_read_kernel(event.scid, event.scid_length, payload + offset);
            if(event.dcid_length==0){
                __builtin_memcpy(tmp_dcid, event.scid, 20);
                tmp_dcid[19]++;
            }else{
                __builtin_memcpy(tmp_dcid, event.dcid, 20); 
            }
            __builtin_memcpy(event.first_dcid, tmp_dcid, 20);
            event.timestamp =bpf_ktime_get_ns();
            connections_map.update(&key, &event);            
            __builtin_memcpy(dcid_val.first_dcid, tmp_dcid, 20);
            // Insert DCID into dcids_map
            if (event.dcid_length!=0){ 
                dcid_key.dcid_length = event.dcid_length;
                __builtin_memcpy(dcid_key.dcid, event.dcid, 20);
                dcid_val.scid_length = event.scid_length;
                dcids_map.update(&dcid_key, &dcid_val);
            }
            // Insert SCID into dcids_map (SCID is DCID of the reply)
            if (event.scid_length!=0){
                dcid_key.dcid_length = event.scid_length;
                __builtin_memcpy(dcid_key.dcid, event.scid, 20);
                dcid_val.scid_length = event.scid_length;
                dcids_map.update(&dcid_key, &dcid_val);
            }        
            // Insert into dest_map
            __builtin_memcpy(&dest.dip, &key.dip, 4);
            dest.dport = key.dport;
            __builtin_memcpy(firstdcid.first_dcid, tmp_dcid, 20);
            dest_map.update(&dest, &firstdcid);            
            // Insert into sip_map
            __builtin_memcpy(&sip.sip, &key.sip, 4);
            __builtin_memcpy(&sip.dip, &key.dip, 4);
            sip.dport = key.dport;
            __builtin_memcpy(sip_val.first_dcid, tmp_dcid, 20);
            sip_val.dcid_length = event.dcid_length;
            sip_val.scid_length = event.scid_length;
            sip_map.update(&sip, &sip_val);
            return 0;
        }
        else{ // LONG: existed connection, update only DCID and DCID length
            event = *existing_event;
            event.dcid_length = payload[5];
            if (event.dcid_length > 20) return 0;
            event.timestamp = bpf_ktime_get_ns();
            if(event.dcid_length !=0){
                bpf_probe_read_kernel(event.dcid, event.dcid_length, payload + 6);
                connections_map.update(&key, &event);
                //Insert new DCID to DCID map
                dcid_key.dcid_length = event.dcid_length;
                __builtin_memcpy(dcid_key.dcid, event.dcid, 20);
                dcid_val.scid_length = event.scid_length;
                __builtin_memcpy(dcid_val.first_dcid, event.first_dcid, 20);
                dcids_map.update(&dcid_key,&dcid_val);
                //Insert new DCID length to SIP map
                __builtin_memcpy(&sip.sip, &key.sip, 4);
                __builtin_memcpy(&sip.dip, &key.dip, 4);
                sip.dport = key.dport;
                __builtin_memcpy(sip_val.first_dcid, event.first_dcid, 20);
                sip_val.dcid_length = event.dcid_length;
                sip_val.scid_length = event.scid_length;
                sip_map.update(&sip, &sip_val);
                return 0;
            }
            else {
                connections_map.update(&key, &event);
                return 0;
            }  
        }
    }
    else{ //SHORT HEADER
        if (udp_len < 19) return 0;  
        if ((payload[0] & 0x40) == 0) return 0;
        existing_event = connections_map.lookup(&key);
        if (!existing_event) { //can be connection migration or potential QUIC or not QUIC            
            __builtin_memcpy(&dest.dip, &key.dip, 4);
            dest.dport = key.dport;
            existing_firstdcid = dest_map.lookup(&dest);
            if(!existing_firstdcid) return 0;//destination not exited => NOT QUIC
            __builtin_memcpy(tmp_dcid, payload+1, 20);
            //Look up in Potential QUIC map
            existing_event = potential_quic.lookup(&key);
            if (!existing_event){//connection migration or new poential QUIC
                for (__u8 len = 1; len <= 20; len++) {
                    dcid_key.dcid_length = len;
                    // Adjust the key's DCID for the current length
                    __builtin_memcpy(dcid_key.dcid, tmp_dcid, len);
                    // Perform the lookup with the adjusted key
                    existing_dcid_val = dcids_map.lookup(&dcid_key);
                    if (existing_dcid_val) {break;} 
                }
                if (!existing_dcid_val){//can be QUIC
                    __builtin_memcpy(&sip.sip, &key.sip, 4);
                    __builtin_memcpy(&sip.dip, &key.dip, 4);
                    sip.dport = key.dport;
                    exitsing_sip_val = sip_map.lookup(&sip);
                    if (!exitsing_sip_val) {return 0;} // not QUIC
                    else {//determined poential QUIC insert to Potential QUIC map
                        if(exitsing_sip_val->dcid_length==0)return 0;
                        struct quic_event event = {};
                        __builtin_memcpy(event.first_dcid, exitsing_sip_val->first_dcid, 20);
                        __builtin_memcpy(firstdcid.first_dcid, exitsing_sip_val->first_dcid, 20);
                        event.dcid_length = exitsing_sip_val->dcid_length;
                        event.scid_length = exitsing_sip_val->scid_length;
                        if (event.dcid_length>20) return 0;
                        bpf_probe_read_kernel(&event.dcid, event.dcid_length, tmp_dcid);
                        potential_quic.update(&key,&event);
                        // Insert DCID into potential_quic_dcid
                        dcid_key.dcid_length = event.dcid_length;
                        __builtin_memcpy(dcid_key.dcid, event.dcid, 20);
                        potential_quic_dcid.update(&dcid_key, &firstdcid);
                        return 0;
                    }
                    return 0;
                }
                else { // Connecntion Migration with the same CID
                    struct quic_event event = {};
                    event.dcid_length= dcid_key.dcid_length;
                    event.scid_length= existing_dcid_val->scid_length;
                    __builtin_memcpy(event.dcid,dcid_key.dcid,20);
                    __builtin_memcpy(event.first_dcid, existing_dcid_val->first_dcid, 20);
                    event.timestamp =bpf_ktime_get_ns();
                    connections_map.update(&key, &event);
                    // Insert into sip_map
                    __builtin_memcpy(&sip.sip, &key.sip, 4);
                    __builtin_memcpy(&sip.dip, &key.dip, 4);
                    sip.dport = key.dport;
                    sip_val.dcid_length=dcid_key.dcid_length;
                    sip_val.scid_length=existing_dcid_val->scid_length;
                    __builtin_memcpy(sip_val.first_dcid, existing_dcid_val->first_dcid, 20);
                    sip_map.update(&sip, &sip_val);
                    //pre-insert for reply
                    if (event.scid_length==0){
                        key.sip = ntohl(local_fl4.daddr);
                        key.sport = ntohs(local_fl4.fl4_dport);
                        key.dip = ntohl(local_fl4.saddr);
                        key.dport = ntohs(local_fl4.fl4_sport);
                        event.scid_length = dcid_key.dcid_length;
                        event.dcid_length = 0;
                        __builtin_memcpy(event.scid, dcid_key.dcid, 20);
                        event.dcid[19]++; 
                        __builtin_memcpy(event.first_dcid, event.dcid, 20);
                        __builtin_memset(event.dcid, 0, sizeof(event.dcid));
                        connections_map.update(&key, &event);
                        return 0;
                    }
                    return 0;
                }
                return 0;                
            }
            else{ //new packet existed in Potential QUIC map 
                dcid_key.dcid_length = existing_event->dcid_length;
                event.dcid_length= dcid_key.dcid_length;
                if (dcid_key.dcid_length > 20)return 0;
                bpf_probe_read_kernel(&dcid_key.dcid, dcid_key.dcid_length, tmp_dcid);
                existing_firstdcid = potential_quic_dcid.lookup(&dcid_key);
                if (!existing_firstdcid){// not QUIC
                    __builtin_memcpy(dcid_key.dcid, existing_event->dcid, 20);
                    potential_quic_dcid.delete(&dcid_key);
                    potential_quic.delete(&key);
                    return 0;
                }
                else{ //QUIC identified
                    //sip_map update
                    __builtin_memcpy(&sip.sip, &key.sip, 4);
                    __builtin_memcpy(&sip.dip, &key.dip, 4);
                    sip.dport = key.dport;
                    __builtin_memcpy(sip_val.first_dcid, existing_event->first_dcid, 20);
                    sip_val.dcid_length = existing_event->dcid_length;
                    sip_val.scid_length = existing_event->scid_length;
                    sip_map.update(&sip, &sip_val);
                    //connection map udpate
                    struct quic_event event = {};
                    event = *existing_event;
                    event.timestamp = bpf_ktime_get_ns();
                    connections_map.update(&key, &event);
                    if(event.scid_length!=0){
                        __builtin_memcpy(&sip.sip, &key.dip, 4);
                        __builtin_memcpy(&sip.dip, &key.sip, 4);
                        sip.dport = key.sport;
                        __builtin_memcpy(sip_val.first_dcid, existing_event->first_dcid, 20);
                        sip_val.first_dcid[19]++;
                        sip_val.dcid_length = existing_event->scid_length;
                        sip_val.scid_length = existing_event->dcid_length;
                        sip_map.update(&sip, &sip_val);
                        potential_quic_dcid.delete(&dcid_key);
                        potential_quic.delete(&key);
                    }
                    else{//connection map udpate the reply only if SCID is 0
                        key.sip = ntohl(local_fl4.daddr);
                        key.sport = ntohs(local_fl4.fl4_dport);
                        key.dip = ntohl(local_fl4.saddr);
                        key.dport = ntohs(local_fl4.fl4_sport);                        
                        event.scid_length= existing_event->dcid_length;
                        event.dcid_length= 0;
                        __builtin_memset(event.dcid, 0, sizeof(event.dcid));
                        if (event.scid_length>20){return 0;}
                        __builtin_memcpy(event.scid, existing_event->dcid, 20);
                        __builtin_memcpy(event.first_dcid, existing_event->first_dcid, 20);
                        event.first_dcid[19]++;
                        event.timestamp = bpf_ktime_get_ns();
                        connections_map.update(&key, &event);
                        key.sip = ntohl(local_fl4.saddr);
                        key.sport = ntohs(local_fl4.fl4_sport);
                        key.dip = ntohl(local_fl4.daddr);
                        key.dport = ntohs(local_fl4.fl4_dport);
                        potential_quic_dcid.delete(&dcid_key);
                        potential_quic.delete(&key);
                    }
                    return 0;
                }
                
                return 0;
            }
            return 0;
        }
        else{ //SHORT: existed connection
            event = *existing_event;
            event.timestamp = bpf_ktime_get_ns();
            connections_map.update(&key, &event);
            return 0;
        }
        return 0;
    }
    return 0;
}