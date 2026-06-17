CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -pedantic
LDFLAGS ?=

BIN_DIR := bin
OBJ_DIR := build
INC_DIR := include
SRC_DIR := src

MITM := $(BIN_DIR)/mitm_proxy

all: $(MITM)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

$(MITM): $(OBJ_DIR)/mitm_proxy.o $(OBJ_DIR)/net.o $(OBJ_DIR)/util.o $(OBJ_DIR)/crypto_sha256.o $(OBJ_DIR)/crypto_aes256.o $(OBJ_DIR)/crypto_gcm.o $(OBJ_DIR)/crypto_dh.o | $(BIN_DIR)
	$(CC) $(CFLAGS) -I$(INC_DIR) $^ -o $@ -pthread $(LDFLAGS)

clean:
	rm -rf $(BIN_DIR) $(OBJ_DIR)

.PHONY: all clean
