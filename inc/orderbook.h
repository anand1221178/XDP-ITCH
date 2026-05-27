#ifndef __ORDERBOOK_H
#define __ORDERBOOK_H

#include <stdint.h>

// These includes are hidden from the c compiler:
#ifdef __cplusplus
#include <map>
#include <list>
#include <unordered_map>

struct OrderNode{
    uint64_t order_ref;
    uint32_t shares;
};

struct PriceLevel{
    uint32_t total_volume;
    std::list<OrderNode> order_queue;
};

struct OrderLocation{
    char side; //Buy or Sell -> B or S
    std::map<uint32_t, PriceLevel>::iterator price_iter;
    std::list<OrderNode>::iterator order_iter;
};



class OrderBook {
public:
    void add_order(uint64_t order_ref, char side, uint32_t price, uint32_t shares);
    void execute_order(uint64_t order_ref, uint32_t shares);
    void delete_order(uint64_t order_ref);
    uint32_t best_bid();
    uint32_t best_ask();
private:
    //std greater makes sure bids.begin() is always the highest price
    std::map<uint32_t, PriceLevel, std::greater<uint32_t>> bids;
    //std less makes sure bids.begin() is always the lowest price
    std::map<uint32_t, PriceLevel, std::less<uint32_t>> asks;

    std::unordered_map<uint64_t, OrderLocation> active_orders;

};
#endif

// This is now only visible to the c compiler:
#ifdef __cplusplus
extern "C" {
#endif

void* orderbook_create();
void  orderbook_add(void *book, uint64_t order_ref, char side, uint32_t price, uint32_t shares);
void  orderbook_delete(void *book, uint64_t order_ref);
void  orderbook_execute(void *book, uint64_t order_ref, uint32_t shares);
uint32_t orderbook_best_bid(void *book);
uint32_t orderbook_best_ask(void *book);
void  orderbook_destroy(void *book);

#ifdef __cplusplus
}
#endif

#endif /* __ORDERBOOK_H */