# XDP-ITCH: Kernel-Level Market Data Parsing

This project is a high-performance, kernel-bypass market data feed handler for the NASDAQ ITCH 5.0 protocol. By utilizing XDP (eXpress Data Path) and eBPF, this engine processes network packets at the NIC level, bypassing the Linux kernel network stack and `recv()` syscall overhead to achieve sub-microsecond latency.

---

## Architecture
This engine bridges the gap between high-performance kernel networking and low-latency HFT order book management.



### Core Components
* **XDP Parser (`xdp_itch.bpf.c`)**: A high-speed eBPF program that executes in the NIC driver, performing symbol filtering and raw header parsing.
* **Feed Simulator (`itch_sim.c`)**: A configurable ITCH 5.0 simulator capable of injecting raw L2 frames or UDP packets at wire speed.
* **Matching Engine (`orderbook.cpp`)**: A C++ based, lock-free, price-level order book that handles Add, Execute, and Delete operations.
* **Readers**: Includes both an `itch_reader` (using BPF ring buffer for zero-copy delivery) and a `baseline_handler` (standard socket) for comparative analysis.

## Performance
By eliminating context switches and minimizing buffer copies, the engine achieves industry-leading parsing efficiency:
* **Benchmark Results**: ~930 ns per packet.
* **Throughput**: Sustained 100k+ msgs/sec in test environments.

## Getting Started

### Prerequisites
* Linux 5.15+ (BPF ring buffer support required)
* `clang`, `llvm`, `libbpf`, `libxdp`
* `bpftool`

### Build and Run
The project includes an automated pipeline manager to handle setup, compilation, execution, and cleanup.

1. **Clone the repository.**
2. **Execute the pipeline**:
   ```bash
   chmod +x run.sh
   sudo ./run.sh