#!/bin/bash

set -e

echo "======================================================"
echo "    XDP-ITCH: Automated Kernel Bypass Benchmark       "
echo "======================================================"

echo "[1/6] Cleaning up old network ghosts..."
sudo ip link set dev lo xdp off 2>/dev/null || true
sudo fuser -k 1234/udp 2>/dev/null || true

echo "[2/6] Compiling the C/C++ engine..."
make clean > /dev/null && make > /dev/null
echo "      -> Compilation successful."

echo "[3/6] Enabling Kernel eBPF Statistics..."
sudo sysctl -w kernel.bpf_stats_enabled=1 > /dev/null

echo "[4/6] Spinning up the eBPF ITCH Reader (Background)..."
sudo ./xdp_itch > orderbook_output.log 2>&1 &
READER_PID=$!
sleep 1

echo "[5/6] Firing the Simulator: 100,000 msgs/sec for 5 seconds..."
# Added stdbuf -oL to force the simulator to flush its prints to the log file instantly!
sudo stdbuf -oL timeout 5 ./itch_sim lo 100000 15 > sim_output.log 2>&1 || true

echo "[6/6] Extracting Kernel Stats..."
# GRAB THE STATS FIRST!
RAW_STATS=$(sudo bpftool prog show name xdp_itch_parser)

echo "      Tearing down the pipeline..."
# THEN kill the reader to detach from the NIC
sudo kill -SIGINT $READER_PID
sleep 1

echo ""
echo "======================================================"
echo "               eBPF LATENCY RESULTS                   "
echo "======================================================"

RUN_TIME_NS=$(echo "$RAW_STATS" | grep -oP 'run_time_ns \K\d+')
RUN_CNT=$(echo "$RAW_STATS" | grep -oP 'run_cnt \K\d+')

if [[ -n "$RUN_TIME_NS" && -n "$RUN_CNT" && "$RUN_CNT" -gt 0 ]]; then
    LATENCY=$(( RUN_TIME_NS / RUN_CNT ))
    echo "Total Packets Processed: $RUN_CNT"
    echo "Total eBPF CPU Time:     $RUN_TIME_NS ns"
    echo "------------------------------------------------------"
    echo "Average Latency:         $LATENCY nanoseconds/packet"
    echo "======================================================"
else
    echo "Failed to extract BPF statistics."
    echo "Raw output: $RAW_STATS"
fi