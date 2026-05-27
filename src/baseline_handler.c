// src/baseline_handler.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <endian.h>
#include <sys/socket.h>

#include "itch_common.h"
#include "orderbook.h"

// MoldUDP64 Header (Must match the simulator)
struct moldudp64_hdr {
    char     session[10];
    uint64_t sequence_number;
    uint16_t message_count;
} __attribute__((packed));

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

int main() {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 1. Create standard UDP Socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    // 2. Bind to Port 1234 (This is where the simulator sends packets)
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1234);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Bind failed");
        close(sock);
        return 1;
    }

    void *book = orderbook_create();
    uint8_t buffer[2048];

    printf("Starting Baseline (UDP Socket) Reader. Press Ctrl+C to stop.\n");

    // 3. The Standard recv() Loop
    while (!exiting) {
        // This syscall is what causes the 1-2 microsecond delay in traditional architecture
        ssize_t bytes_read = recv(sock, buffer, sizeof(buffer), 0);
        if (bytes_read < 0) break;

        // The kernel stripped ETH/IP/UDP. We are left with MoldUDP64 + ITCH Length + ITCH
        if (bytes_read < sizeof(struct moldudp64_hdr) + 2) continue;

        // Skip the MoldUDP64 header (12 bytes) and the 2-byte Length prefix
        uint8_t *itch_data = buffer + sizeof(struct moldudp64_hdr) + 2;
        size_t itch_sz = bytes_read - sizeof(struct moldudp64_hdr) - 2;
        
        __u8 msg_type = itch_data[0];

        // Process exact same way as the eBPF reader
        if (msg_type == 'A' && itch_sz == sizeof(struct itch_add_order)) {
            struct itch_add_order *msg = (struct itch_add_order *)itch_data;
            uint32_t shares = ntohl(msg->shares);
            uint32_t raw_price = ntohl(msg->price);
            uint64_t order_ref = be64toh(msg->order_ref_number);

            orderbook_add(book, order_ref, msg->buy_sell_indicator, raw_price, shares);
            printf("[ADD] Ref: %lu | %c %u shares\n", order_ref, msg->buy_sell_indicator, shares);
        }
        else if (msg_type == 'E' && itch_sz == sizeof(struct itch_execute_order)) {
            struct itch_execute_order *msg = (struct itch_execute_order *)itch_data;
            uint32_t exec_shares = ntohl(msg->executed_shares);
            uint64_t order_ref = be64toh(msg->order_ref_number);

            orderbook_execute(book, order_ref, exec_shares);
            printf("[EXECUTE] Ref: %lu | %u shares traded\n", order_ref, exec_shares);
        }
        else if (msg_type == 'D' && itch_sz == sizeof(struct itch_delete_order)) {
            struct itch_delete_order *msg = (struct itch_delete_order *)itch_data;
            uint64_t order_ref = be64toh(msg->order_ref_number);

            orderbook_delete(book, order_ref);
            printf("[DELETE] Ref: %lu | Order removed\n", order_ref);
        }

        uint32_t best_bid = orderbook_best_bid(book);
        uint32_t best_ask = orderbook_best_ask(book);
        printf("   -> Spread: $%.4f - $%.4f\n", (double)best_bid / 10000.0, (double)best_ask / 10000.0);
    }

    orderbook_destroy(book);
    close(sock);
    return 0;
}