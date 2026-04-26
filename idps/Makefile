# IDPS eBPF-based Intrusion Detection and Prevention System
# Makefile

.PHONY: all clean build test install help

# Directories
SRC_DIR := src
BPF_DIR := bpf
LIB_DIR := lib
INCLUDE_DIR := include

# Build flags - clang for BPF target with userspace headers
# Use aarch64-linux-gnu cross-compiler headers to avoid kernel header issues
CLANG_FLAGS := -O2 -target bpf -Wall \
	-I. \
	-I$(INCLUDE_DIR) \
	-I/usr/include/aarch64-linux-gnu \
	-I/usr/include
LLD_FLAGS := -r -m elf64lr_bpf

# Output
BPF_OBJ := $(BPF_DIR)/idps.bpf.o

# Default target - just build BPF object for now
all: build

## Build eBPF object file
$(BPF_OBJ): $(BPF_DIR)/idps.bpf.c $(INCLUDE_DIR)/*.h
	@mkdir -p $(dir $@)
	clang $(CLANG_FLAGS) -c $< -o $@

## Build everything
build: $(BPF_OBJ)

## Clean
clean:
	rm -rf $(BPF_DIR)/*.o $(SRC_DIR)/*.o

## Help
help:
	@echo "IDPS Makefile targets:"
	@echo "  all      - Build BPF object (default)"
	@echo "  build   - Build BPF object"
	@echo "  clean   - Remove built files"
	@echo "  help    - Show this help message"
