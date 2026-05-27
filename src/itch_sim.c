#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>

#include "itch_common.h"

#define DEST_PORT 1234
#define SRC_PORT  5678

// MoldUDP64 Header (NASDAQ Standard)
struct moldudp64_hdr {
    char     session[10];
    uint64_t sequence_number;
    uint16_t message_count;
} __attribute__((packed));

// IP Checksum func:
// When we build a raw IP packet, the kernel network stack does not calculate the IPv4 header checksum for us
//so if it is wrong itll be dropped:
//We use RFC 1071 one's complement sum, which folds 32-bit overflows back into 16 bits

static uint16_t ip_checksum(void *vdata, size_t length)
{
    // cast data ptr to 16 bit int ptr
    uint16_t *data = (uint16_t *)vdata;
    uint32_t sum = 0;

    // SUm all the 16 bit words:
    while(length > 1)
    {
        sum+=*data++;
        length-=2;
    }

    // add any left overs:
    if(length > 0)
    {
        sum += *(uint8_t *)data;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Return the one's complement
    return ~sum;
}

// Building the packet:
static size_t build_packet(uint8_t *buf, uint64_t seq_num, uint16_t locate_code)
{
    // Ptr setup to overlay struct:
    struct ethhdr *eth = (struct ethhdr *)buf;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    struct udphdr *udp = (struct udphdr *)(ip + 1);
    struct moldudp64_hdr *mold = (struct moldudp64_hdr *)(udp+1);

    // 2byte itch length field comes right before the ITCH message:
    uint16_t *itch_len = (uint16_t *)(mold + 1);
    struct itch_add_order *itch = (struct itch_add_order *)(itch_len + 1);

    // ETH HEADER:
    // FOR LO interface the MAC addr dopesnt matter:
    memset(eth->h_dest, 0x00, ETH_ALEN);
    memset(eth->h_source, 0x00, ETH_ALEN);
    eth->h_proto = htons(ETH_P_IP);

    // IPV4 HDR:
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;

    // TOTAL IP LEN = IP + UDP + mold + len field(itch) + ITCH mesage:
    uint16_t ip_len = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct moldudp64_hdr) + 2 + sizeof(struct itch_add_order);

    ip->tot_len = htons(ip_len);
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = inet_addr("127.0.0.1");
    ip->daddr = inet_addr("127.0.0.1");

    // Checksum must be 0 before calculating:
    ip->check = 0;
    ip->check = ip_checksum(ip, sizeof(struct iphdr));

    // UDP hdr:
    udp->source = htons(SRC_PORT);
    udp->dest = htons(DEST_PORT);
    udp->len = htons(ip_len - sizeof(struct iphdr));
    udp->check = 0;

    // MOld hdr:
    memcpy(mold->session, "SIM          ", 10);
    mold->sequence_number = htobe64(seq_num);
    mold->message_count = htons(1);

    // ITCH payload:
    // 6. ITCH Payload (Randomized Market Behavior)
    int rand_action = rand() % 100;
    
    // Pick a random past order reference to execute or delete
    uint64_t target_ref = (seq_num > 10) ? (seq_num - (rand() % 10)) : seq_num;

    if (rand_action < 70) {
        // 70% chance: ADD ORDER ('A')
        *itch_len = htons(sizeof(struct itch_add_order));
        struct itch_add_order *itch = (struct itch_add_order *)(itch_len + 1);
        memset(itch, 0, sizeof(struct itch_add_order));
        
        itch->msg_type = 'A';
        itch->stock_locate = htons(locate_code);
        itch->order_ref_number = htobe64(seq_num); 
        itch->buy_sell_indicator = (seq_num % 2 == 0) ? 'B' : 'S'; 
        itch->shares = htonl(100);
        
        // Random price between $150.20 and $150.30 to create a moving spread
        uint32_t random_price = 1450000 + (rand() % 1000);
        itch->price = htonl(random_price); 
        
        ip_len += 2 + sizeof(struct itch_add_order);
    } 
    else if (rand_action < 90) {
        // 20% chance: EXECUTE ORDER ('E')
        *itch_len = htons(sizeof(struct itch_execute_order));
        struct itch_execute_order *itch = (struct itch_execute_order *)(itch_len + 1);
        memset(itch, 0, sizeof(struct itch_execute_order));
        
        itch->msg_type = 'E';
        itch->stock_locate = htons(locate_code);
        itch->order_ref_number = htobe64(target_ref);
        itch->executed_shares = htonl(100); // Execute the full 100 shares
        
        ip_len += 2 + sizeof(struct itch_execute_order);
    } 
    else {
        // 10% chance: DELETE ORDER ('D')
        *itch_len = htons(sizeof(struct itch_delete_order));
        struct itch_delete_order *itch = (struct itch_delete_order *)(itch_len + 1);
        memset(itch, 0, sizeof(struct itch_delete_order));
        
        itch->msg_type = 'D';
        itch->stock_locate = htons(locate_code);
        itch->order_ref_number = htobe64(target_ref);
        
        ip_len += 2 + sizeof(struct itch_delete_order);
    }

    // Now that ip_len is finalized based on the message type, update the headers
    ip->tot_len = htons(ip_len);
    ip->check = 0; 
    ip->check = ip_checksum(ip, sizeof(struct iphdr));
    
    udp->len = htons(ip_len - sizeof(struct iphdr));

    return sizeof(struct ethhdr) + ip_len;
}


int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <interface> <rate_msgs_per_sec> <stock_locate>\n", argv[0]);
        fprintf(stderr, "Example: %s lo 100000 15\n", argv[0]);
        return 1;
    }

    const char *iface = argv[1];
    uint64_t target_rate = atoll(argv[2]);
    uint16_t locate_code = (uint16_t)atoi(argv[3]);

    if (target_rate == 0) {
        fprintf(stderr, "Rate must be greater than 0.\n");
        return 1;
    }


    unsigned int ifindex = if_nametoindex(iface);
    if (!ifindex) {
        perror("Failed to resolve interface index");
        return 1;
    }


    // AF_PACKET + SOCK_RAW tells the kernel
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("Failed to create raw socket. Are you running with sudo?");
        return 1;
    }

    //Setup Link-Level Destination Address
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = ifindex;
    sa.sll_halen = ETH_ALEN;

    // Allocate our raw memory buffer
    uint8_t buffer[2048];
    
    // Rate Control Variables
    uint64_t ns_per_packet = 1000000000ULL / target_rate;
    uint64_t seq_num = 1;
    uint64_t packets_this_sec = 0;

    struct timespec start, now, last_print;
    clock_gettime(CLOCK_MONOTONIC, &start);
    last_print = start;

    printf("Starting ITCH Simulator...\n");
    printf("Interface: %s | Target: %lu msgs/sec | Locate: %u\n", iface, target_rate, locate_code);
    printf("--------------------------------------------------\n");

    // Spin Loop
    while (1) {
        clock_gettime(CLOCK_MONOTONIC, &now);

        // Calculate total nanoseconds since we started the simulator
        uint64_t elapsed_total_ns = (now.tv_sec - start.tv_sec) * 1000000000ULL + 
                                    (now.tv_nsec - start.tv_nsec);
        
        // Calculate how many packets SHOULD have been sent by this exact nanosecond
        uint64_t expected_packets = elapsed_total_ns / ns_per_packet;


        if (seq_num <= expected_packets) {
            size_t frame_len = build_packet(buffer, seq_num, locate_code);
            
            int bytes_sent = sendto(sock, buffer, frame_len, 0, (struct sockaddr *)&sa, sizeof(sa));
            if (bytes_sent < 0) {
                perror("sendto failed");
                break;
            }

            seq_num++;
            packets_this_sec++;
        }


        uint64_t elapsed_print_ns = (now.tv_sec - last_print.tv_sec) * 1000000000ULL + 
                                    (now.tv_nsec - last_print.tv_nsec);
        
        if (elapsed_print_ns >= 1000000000ULL) {
            printf("[STATS] Achieved Rate: %lu msgs/sec (Target: %lu)\n", packets_this_sec, target_rate);
            packets_this_sec = 0;
            last_print = now;
        }
    }

    close(sock);
    return 0;
}