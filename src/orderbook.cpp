#include "orderbook.h"

void OrderBook::add_order(uint64_t order_ref, char side, uint32_t price, uint32_t shares)
{
    OrderLocation loc;
    loc.side = side;

    if(side == 'B')
    {
        auto& level = bids[price];//create the price level if it odesnt exisit
        level.total_volume += shares;
        level.order_queue.push_back({order_ref, shares});

        loc.price_iter = bids.find(price);
        loc.order_iter = std::prev(level.order_queue.end());

    } else if (side == 'S') {
        auto& level = asks[price];
        level.total_volume += shares;
        level.order_queue.push_back({order_ref, shares});
        
        loc.price_iter = asks.find(price);
        loc.order_iter = std::prev(level.order_queue.end());
        
    } else {
        // Safety: If the network packet had a corrupted side indicator, drop it.
        return; 
    }

    // Save mem locs in o(1) has map
    active_orders[order_ref] = loc;
}

void OrderBook::execute_order(uint64_t order_ref, uint32_t shares)
{
    auto it = active_orders.find(order_ref);

    // Check -> if we joined mis session and dont know this order -> ignore it
    if(it == active_orders.end())
    {
        return;
    }

    OrderLocation& loc = it->second;
    loc.order_iter->shares -= shares;
    loc.price_iter->second.total_volume -= shares;

    auto price_iter = loc.price_iter;
    char side = loc.side;

    // If the order is completely filled remove it 
    if(loc.order_iter->shares ==0)
    {
        loc.price_iter->second.order_queue.erase(loc.order_iter);
        active_orders.erase(it);
    }

    // Cleanup:
    if (price_iter->second.total_volume == 0) {  
        if (side == 'B') bids.erase(price_iter);  
        else asks.erase(price_iter);               
    }
}

void OrderBook::delete_order(uint64_t order_ref) {
    auto it = active_orders.find(order_ref);
    if (it == active_orders.end()) {
        return;
    }

    OrderLocation& loc = it->second;
    uint32_t remaining_shares = loc.order_iter->shares;
    
    loc.price_iter->second.total_volume -= remaining_shares;
    
    // O(1) removal from the middle of the linked list
    loc.price_iter->second.order_queue.erase(loc.order_iter);

    // MANDATORY CLEANUP
    if (loc.price_iter->second.total_volume == 0) {
        if (loc.side == 'B') bids.erase(loc.price_iter);
        else asks.erase(loc.price_iter);
    }

    active_orders.erase(it);
}

uint32_t OrderBook::best_bid() {
    if (bids.empty()) return 0;
    return bids.begin()->first; // std::greater guarantees this is highest
}

uint32_t OrderBook::best_ask() {
    if (asks.empty()) return 0;
    return asks.begin()->first; // std::less guarantees this is lowest
}

// Extern C wrapper implementation:
void* orderbook_create() {
    return new OrderBook();
}

void orderbook_add(void *book, uint64_t order_ref, char side, uint32_t price, uint32_t shares) {
    static_cast<OrderBook*>(book)->add_order(order_ref, side, price, shares);
}

void orderbook_delete(void *book, uint64_t order_ref) {
    static_cast<OrderBook*>(book)->delete_order(order_ref);
}

void orderbook_execute(void *book, uint64_t order_ref, uint32_t shares) {
    static_cast<OrderBook*>(book)->execute_order(order_ref, shares);
}

uint32_t orderbook_best_bid(void *book) {
    return static_cast<OrderBook*>(book)->best_bid();
}

uint32_t orderbook_best_ask(void *book) {
    return static_cast<OrderBook*>(book)->best_ask();
}

void orderbook_destroy(void *book) {
    delete static_cast<OrderBook*>(book);
}