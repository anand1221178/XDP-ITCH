// Declares
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h> 
#include <linux/if_ether.h>
#include <linux/ip.h>      
#include <linux/ipv6.h> 
#include <linux/udp.h>     
#include <linux/in.h> 
#include "itch_common.h"

//license declares
char LICENSE[] SEC("license") = "Dual BSD/GPL";


// Hash map struct for the stock filter:
struct{
    __uint(type, BPF_MAP_TYPE_HASH); //type hash map
    __type(key, __u16); //key 
    __type(value, __u8); //value
    __uint(max_entries, 10240); //max number of things we want in here
}stock_filter SEC(".maps");

// the itch ring buffer struct
struct{
    __uint(type, BPF_MAP_TYPE_RINGBUF); //declare as a ring buff type
    __uint(max_entries, 256 * 1024);
}itch_ringbuf SEC(".maps");

// Hdr cursor to keep track of where we are:
struct hdr_cursor{
    void *pos;
};


// MOLDUDP hdr 20 bytes
struct moldudp64_hdr{
    __u8 session_id[10]; //10 bytes - for the session name
    __u64 sequence_number; //8 bytes for the packet sequence num
    __u16 message_count; //Number of ITCH messages in this packet
}__attribute__((packed)); //For mem and compiler optimisations

//Helper functiosn for the parser:
static __always_inline int parse_ethhdr(struct hdr_cursor *nh, void *data_end, struct ethhdr **ethhdr)
{
    struct ethhdr *eth = nh->pos;
    
    // Bounds check for verifier
    if(eth + 1 > data_end)
    {
        return -1;
    }

    nh->pos = eth + 1;

    // Point the output var to our parsed hdr
    *ethhdr = eth;
    
    // We return the type of the harware proto so the main function can check it (IPV4/IPV6)
    return eth->h_proto; //2 byte code that tells the network card what kind of data the eth frame is wrapping
                        //0x0800 means IPV4 and 0x86DD means IPV6
}

static __always_inline int parse_ip4hdr(struct hdr_cursor *nh, void *data_end, struct iphdr **ip4hdr)
{
    struct iphdr *ip4h = nh->pos;
    int hdrsize;

    if(ip4h + 1 > data_end)
    {
        return -1;
    }

    // calculate dynamic header size
    hdrsize = ip4h->ihl * 4;

    if(hdrsize < sizeof(struct iphdr))
    {
        return -1;
    }

    if (nh->pos + hdrsize > data_end) {
        return -1;
    }

    nh->pos += hdrsize;

    *ip4hdr = ip4h;

    return ip4h->protocol; // Tells the IP layer which transport layer protocol is inside the payload
    //6 = TCP; 1 = ICMP (ping); 17 = UDP
}

static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,void *data_end,struct ipv6hdr **ip6hdr)
{
    struct ipv6hdr *ip6h = nh->pos;

    if(ip6h + 1 > data_end)
    {
        return -1;
    }

    nh->pos = ip6h + 1;

    *ip6hdr = ip6h;

    return ip6h->nexthdr; //next hdr which will say my next header is Routing Extenstion -> Fragmentation Extension -> UDP
}

static __always_inline int parse_udphdr(struct hdr_cursor *nh,void *data_end,struct udphdr **udphdr)
{
     struct udphdr *udph = nh->pos;

     if(udph + 1 > data_end)
     return -1;

     nh->pos = udph + 1;

     *udphdr = udph;

     return udph->dest; //big endian dont forget to flip to little endian to read!
}

static __always_inline int parse_moldudp64(struct hdr_cursor *nh, void *data_end, struct moldudp64_hdr **moldhdr)
{
    struct moldudp64_hdr *mold = nh->pos;

    // Bounds check:
    if(mold+1 > data_end)
    {
        return -1;
    }

    // Advance the ptr one forward
    nh->pos = mold +1;

    *moldhdr = mold;

    return mold->message_count;
}

// ITCH message parser:
static __always_inline int parse_itch_add_order(struct hdr_cursor *nh, void *data_end, struct itch_add_order **itch_msg)
{
    // Mold prefixes every message with a 2 byte length
    __u16 *msg_len_ptr = nh->pos;
    if((void*)(msg_len_ptr + 1) > data_end)
    {
        return -1; //junk packet
    }

    // move past the 2 byte length field to get to the actual mesasge:
    nh->pos = msg_len_ptr + 1;

    // map the Add order struct over the data;
    struct itch_add_order *msg = nh->pos;

    // Check for the verifer that the message length is 36 bytees:
    if((void*)(msg+1) > data_end)
    {
        return -1;
    }

    // Point output vvar to the parsed message
    *itch_msg = msg;

    // move the cursor past this entire 36 bytess message 
    // (This prepares the cursor for the foillowing  message in the loop!)
    nh->pos = msg + 1;

    return msg->msg_type;
}

static __always_inline int submit_add_order_to_ringbuf(struct itch_add_order *msg)
{
    struct itch_add_order *ring_slot;

    // reserve the mem:
    ring_slot = bpf_ringbuf_reserve(&itch_ringbuf, sizeof(struct itch_add_order), 0);
    if(!ring_slot)
    {
        return -1; //buffer full
    }

    // memcpy
    __builtin_memcpy(ring_slot, msg, sizeof(struct itch_add_order));

    bpf_ringbuf_submit(ring_slot, 0);

    return 0;
}

SEC("xdp")
int xdp_itch_parser(struct xdp_md *ctx)
{
    void *data_end = (void*)(long)ctx->data_end;
    void *data = (void*)(long)ctx->data;
    struct hdr_cursor nh;

    // start our cursor at byte 0:
    nh.pos = data;

    // ETH CHECKS:
    struct ethhdr *eth;
    int eth_type;

    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type < 0) {
        return XDP_PASS; // Packet too small let kernel handle it
    }
    // Check if  IPv4
    if (eth_type != bpf_htons(ETH_P_IP)) {
        return XDP_PASS; // Not IPv4 pass it to the normal network stack
    }

    // IPV4 checks:
    struct iphdr *iph;
    int ip_protocol;

    ip_protocol = parse_ip4hdr(&nh, data_end, &iph);
    if(ip_protocol < 0)
    {
        return XDP_PASS; //junk packet;
    }

    // Check if the protocool; inside IPv4 is UDP:
    if(ip_protocol != IPPROTO_UDP)
    {
        return XDP_PASS;
    }


    // UDP checks:
    struct udphdr *udph;
    int dest_port;
    
    dest_port = parse_udphdr(&nh, data_end, &udph);

    if (dest_port < 0) {
        return XDP_PASS; // Packet cut off before UDP header finishes
    }

    // Check if comingd for our market data port 
    if (dest_port != bpf_htons(1234)) {
        return XDP_PASS; // Not our market data leave it
    }

    // Mold checks:
    struct moldudp64_hdr *moldh;
    int msg_count;

    // From here on if a packet it broken we will drop it instead of pass it
    //since we know if a packet gets here it is for the trading port
    msg_count = parse_moldudp64(&nh, data_end, &moldh);

    if(msg_count < 0)
    {
        return XDP_DROP; //corrupted
    }

    msg_count = bpf_ntohs(msg_count); //we need to flip from big endian to little endian

    if(msg_count == 0)
    {
        return XDP_DROP;
    }

    // IF WE REACH HERE WE ARE SITTING AT THE START OF THE PAYLOAD - FINALLY FFS
    for(int i = 0 ; i < MAX_ITCH_MESSAGES; i++)
    {
        // break early if we have processed all msgs in this packet
        if(i >= msg_count)
        {
            break;
        }

        // Re-establish trust for verifier on every iteration
        if(nh.pos + sizeof(__u16) > data_end) break;

        // Get msg length:
        __u16 *msg_len_ptr = nh.pos;

        if((void*)(msg_len_ptr + 1) > data_end)
        {
            break; //broken packet leave loop
        }

        __u16 msg_len = bpf_ntohs(*msg_len_ptr);
        if (msg_len == 0 || msg_len > 200) {
            break;
        }
        nh.pos = msg_len_ptr + 1; //move past the 2 byte length field

        // BOund check the entire message for the verifier
        void *msg_start = msg_len_ptr +1;
        if(msg_start + msg_len > data_end)
        {
            break;
        }

        if (msg_start + 1 > data_end) {
            break;
        }

        // read the messfaege type:
        __u8 *msg_type_ptr = msg_start;

        // if an Add order -> proc it:
        if (*msg_type_ptr == 'A' && msg_len == sizeof(struct itch_add_order)) {
            struct itch_add_order *itch_msg = msg_start;
            if ((void *)(itch_msg + 1) > data_end) break;
            
            __u16 stock_loc = bpf_ntohs(itch_msg->stock_locate);
            __u8 *track_this_stock = bpf_map_lookup_elem(&stock_filter, &stock_loc);
            
            if (track_this_stock && *track_this_stock == 1) {
                // Reserve exactly 36 bytes
                void *ring_slot = bpf_ringbuf_reserve(&itch_ringbuf, sizeof(struct itch_add_order), 0);
                if (ring_slot) {
                    __builtin_memcpy(ring_slot, itch_msg, sizeof(struct itch_add_order));
                    bpf_ringbuf_submit(ring_slot, 0);
                }
            }
        } 
        else if (*msg_type_ptr == 'E' && msg_len == sizeof(struct itch_execute_order)) {
            struct itch_execute_order *itch_msg = msg_start;
            if ((void *)(itch_msg + 1) > data_end) break;
            
            __u16 stock_loc = bpf_ntohs(itch_msg->stock_locate);
            __u8 *track_this_stock = bpf_map_lookup_elem(&stock_filter, &stock_loc);
            
            if (track_this_stock && *track_this_stock == 1) {
                // Reserve exactly 31 bytes
                void *ring_slot = bpf_ringbuf_reserve(&itch_ringbuf, sizeof(struct itch_execute_order), 0);
                if (ring_slot) {
                    __builtin_memcpy(ring_slot, itch_msg, sizeof(struct itch_execute_order));
                    bpf_ringbuf_submit(ring_slot, 0);
                }
            }
        }
        else if (*msg_type_ptr == 'D' && msg_len == sizeof(struct itch_delete_order)) {
            struct itch_delete_order *itch_msg = msg_start;
            if ((void *)(itch_msg + 1) > data_end) break;
            
            __u16 stock_loc = bpf_ntohs(itch_msg->stock_locate);
            __u8 *track_this_stock = bpf_map_lookup_elem(&stock_filter, &stock_loc);
            
            if (track_this_stock && *track_this_stock == 1) {
                // Reserve exactly 19 bytes
                void *ring_slot = bpf_ringbuf_reserve(&itch_ringbuf, sizeof(struct itch_delete_order), 0);
                if (ring_slot) {
                    __builtin_memcpy(ring_slot, itch_msg, sizeof(struct itch_delete_order));
                    bpf_ringbuf_submit(ring_slot, 0);
                }
            }
        }

        nh.pos = msg_start + msg_len;
    }

    return XDP_DROP;
}