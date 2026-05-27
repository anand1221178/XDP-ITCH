CC      = clang
CXX     = g++
BPFTOOL = bpftool

SRC_DIR = src
INC_DIR = inc
OBJ_DIR = obj

# Include flags so compilers can find headers in inc/ and generated skeleton in obj/
CFLAGS   = -g -O2 -Wall -I$(INC_DIR) -I$(OBJ_DIR)
CXXFLAGS = -g -O2 -Wall -std=c++17 -I$(INC_DIR)
LDFLAGS  = -lbpf -lelf

# Artifact paths
TARGET        = xdp_itch
BPF_OBJ       = $(OBJ_DIR)/xdp_itch.bpf.o
SKEL          = $(OBJ_DIR)/xdp_itch.skel.h
READER_OBJ    = $(OBJ_DIR)/itch_reader.o
ORDERBOOK_OBJ = $(OBJ_DIR)/orderbook.o

SIM_APP = itch_sim
SIM_SRC = $(SRC_DIR)/itch_sim.c
SIM_OBJ = $(OBJ_DIR)/itch_sim.o

BASELINE_APP = baseline_handler
BASELINE_SRC = $(SRC_DIR)/baseline_handler.c
BASELINE_OBJ = $(OBJ_DIR)/baseline_handler.o

all: $(TARGET) $(SIM_APP) $(BASELINE_APP)

# 1. Compile the BPF Kernel program
# Needs -I$(INC_DIR) so it can find itch_common.h
$(BPF_OBJ): $(SRC_DIR)/xdp_itch.bpf.c | $(OBJ_DIR)
	$(CC) -g -O2 -target bpf -I$(INC_DIR) -c $< -o $@

# 2. Generate the Skeleton Header
$(SKEL): $(BPF_OBJ) | $(OBJ_DIR)
	$(BPFTOOL) gen skeleton $< > $@

# 3. Compile the Userspace C Reader
# Depends on SKEL so the header is generated before compiling
$(READER_OBJ): $(SRC_DIR)/itch_reader.c $(SKEL) | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# 4. Compile the Userspace C++ Order Book
$(ORDERBOOK_OBJ): $(SRC_DIR)/orderbook.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# 5. Link everything into the final binary
# We use $(CXX) here so the C++ standard library (libstdc++) is automatically linked
$(TARGET): $(READER_OBJ) $(ORDERBOOK_OBJ)
	$(CXX) $^ $(LDFLAGS) -o $@

# Utility to create the object directory if it doesn't exist
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(SIM_OBJ): $(SIM_SRC) | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(SIM_APP): $(SIM_OBJ)
	$(CC) $^ -o $@

$(BASELINE_OBJ): $(BASELINE_SRC) | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BASELINE_APP): $(BASELINE_OBJ) $(ORDERBOOK_OBJ)
	$(CXX) $^ -o $@

# Cleanup
clean:
	rm -rf $(OBJ_DIR) $(TARGET) $(SIM_APP) $(BASELINE_APP)