// Declares
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


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
                            

SEC("XDP")
int xdp_itch_parses(struct xdp_md *ctx)
{
    return XDP_PASS;
}