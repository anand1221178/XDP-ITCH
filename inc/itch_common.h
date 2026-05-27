// itch_common.h
#ifndef __ITCH_COMMON_H
#define __ITCH_COMMON_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <asm/types.h>
#endif

#define MAX_ITCH_MESSAGES 64

struct itch_add_order {
    __u8  msg_type;              /* 1 byte  - Always 'A' */
    __u16 stock_locate;          /* 2 bytes - Integer ID of the stock */
    __u16 tracking_number;       /* 2 bytes - Internal NASDAQ tracking */
    __u8  timestamp[6];          /* 6 bytes - Nanoseconds since midnight */
    __u64 order_ref_number;      /* 8 bytes - Unique ID for this order */
    __u8  buy_sell_indicator;    /* 1 byte  - 'B' for Buy, 'S' for Sell */
    __u32 shares;                /* 4 bytes - Number of shares */
    __u8  stock[8];              /* 8 bytes - Ticker symbol (e.g., "AAPL    ") */
    __u32 price;                 /* 4 bytes - Price (Implied 4 decimal places) */
} __attribute__((packed)); //We need this to remove compiler optimisations of the compiler trying to 
                            // align the vars to mem boundaries, so we dont want that padding else we are cooked, when we try to parse this

struct itch_execute_order {
    __u8  msg_type;
    __u16 stock_locate;
    __u16 tracking_number;
    __u8  timestamp[6];
    __u64 order_ref_number;
    __u32 executed_shares;
    __u64 match_number;
} __attribute__((packed)); // Exactly 31 bytes

struct itch_delete_order {
    __u8  msg_type;
    __u16 stock_locate;
    __u16 tracking_number;
    __u8  timestamp[6];
    __u64 order_ref_number;
} __attribute__((packed)); // Exactly 19 bytes
// key
// __u64 order_ref_number;

// value
struct active_order_info {
    __u16 stock_locate;
    __u32 price;
    __u32 shares;
    char     side;
};


#endif /* __ITCH_COMMON_H */