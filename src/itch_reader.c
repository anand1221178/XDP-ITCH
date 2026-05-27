// Includes
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>   // For ntohs() and ntohl() (16 and 32 bit byte-flipping)
#include <endian.h>      // For be64toh() (64-bit byte-flipping)
#include <bpf/libbpf.h>
#include <net/if.h>      // For network interface names
#include "itch_common.h"
#include <bpf/bpf.h>
#include "xdp_itch.skel.h"
#include "orderbook.h"


// global flag ti handle ctrl-c 
static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

// Libbpf callback
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    void *book = ctx;
    
    // Catch the NULL pointer before C++ segfaults!
    if (!book) {
        fprintf(stderr, "CRITICAL: OrderBook context is NULL!\n");
        return 0; 
    }
    
    // The very first byte of ANY ITCH message is always the message type
    __u8 msg_type = *((__u8 *)data);

    if (msg_type == 'A' && data_sz == sizeof(struct itch_add_order)) {
        struct itch_add_order *msg = (struct itch_add_order *)data;
        uint32_t shares = ntohl(msg->shares);
        uint32_t raw_price = ntohl(msg->price);
        uint64_t order_ref = be64toh(msg->order_ref_number);

        orderbook_add(book, order_ref, msg->buy_sell_indicator, raw_price, shares);
        printf("[ADD] Ref: %lu | %c %u shares\n", order_ref, msg->buy_sell_indicator, shares);
    } 
    else if (msg_type == 'E' && data_sz == sizeof(struct itch_execute_order)) {
        struct itch_execute_order *msg = (struct itch_execute_order *)data;
        uint32_t exec_shares = ntohl(msg->executed_shares);
        uint64_t order_ref = be64toh(msg->order_ref_number);

        orderbook_execute(book, order_ref, exec_shares);
        printf("[EXECUTE] Ref: %lu | %u shares traded\n", order_ref, exec_shares);
    } 
    else if (msg_type == 'D' && data_sz == sizeof(struct itch_delete_order)) {
        struct itch_delete_order *msg = (struct itch_delete_order *)data;
        uint64_t order_ref = be64toh(msg->order_ref_number);

        orderbook_delete(book, order_ref);
        printf("[DELETE] Ref: %lu | Order removed\n", order_ref);
    }

    // Print the dynamic state of the market
    uint32_t best_bid = orderbook_best_bid(book);
    uint32_t best_ask = orderbook_best_ask(book);
    printf("   -> Spread: $%.4f - $%.4f\n", (double)best_bid / 10000.0, (double)best_ask / 10000.0);

    return 0; 
}

int main(int argc, char **argv)
{
    struct xdp_itch_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err = 0;

    void *book = orderbook_create();

    // Default to the local lo interface for sim trading:
    const char *iface = "lo";
    unsigned int ifindex = if_nametoindex(iface);
    if(!ifindex)
    {
        fprintf(stderr, "Failed to get ifindex for %s: %s\n", iface, strerror(errno));
        return 1;
    }

    // Setup the singla handler to cathc the ctrlc 
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("Starting ITCH reader. Press Ctrl+C to stop.\n");

    // Open adn load the skeleton:
    skel = xdp_itch_bpf__open_and_load();
    if(!skel)
    {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // Popualte the stock filter map:
    int filter_map_fd = bpf_map__fd(skel->maps.stock_filter);

    uint16_t aapl_locate = 15;
    uint16_t tsla_locate = 32;
    uint8_t track_flag = 1;

    err = bpf_map_update_elem(filter_map_fd, &aapl_locate, &track_flag, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to add AAPL to filter map: %s\n", strerror(-err));
        goto cleanup;
    }
    
    err = bpf_map_update_elem(filter_map_fd, &tsla_locate, &track_flag, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to add TSLA to filter map: %s\n", strerror(-err));
        goto cleanup;
    }

    printf("Successfully populated stock filter map.\n");

    // Attasch the XDP program to the nic
    skel->links.xdp_itch_parser = bpf_program__attach_xdp(skel->progs.xdp_itch_parser, ifindex);
    if (!skel->links.xdp_itch_parser) {
        err = -errno;
        fprintf(stderr, "Failed to attach XDP program to %s: %s\n", iface, strerror(-err));
        goto cleanup;
    }

    printf("XDP program successfully attached to %s.\n", iface);

    // Setup the ring buffer:
    int ringbuf_fd = bpf_map__fd(skel->maps.itch_ringbuf);

    // Wire the kernal map to our handle_event callbakc:
    rb = ring_buffer__new(ringbuf_fd, handle_event, book, NULL);
    if (!rb) {
        err = -errno;
        fprintf(stderr, "Failed to create ring buffer: %s\n", strerror(-err));
        goto cleanup;
    }

    printf("Ring buffer established. Polling for market data...\n");

    // MAIN POLLING LLOOP:
    while(!exiting)
    {
        err = ring_buffer__poll(rb,100);

        if (err == -EINTR)
        {
            err = 0;
            break;
        }

        if(err < 0)
        {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }
    printf("\nExiting. Detaching XDP program and freeing memory...\n");

cleanup:
    if (book) {
        orderbook_destroy(book);
    }
// Free the userspace ring buffer memory
    if (rb) {
        ring_buffer__free(rb);
    }
    // This destroys the links, unhooks from the NIC, and unloads the kernel program
    if (skel) {
        xdp_itch_bpf__destroy(skel);
    }

    return err != 0 ? 1 : 0;
}