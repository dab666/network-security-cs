CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -pedantic
LDFLAGS ?=

BIN_DIR := bin
OBJ_DIR := build
INC_DIR := include
SRC_DIR := src

SERVER := $(BIN_DIR)/server
CLIENT := $(BIN_DIR)/client

COMMON_OBJS := $(OBJ_DIR)/net.o $(OBJ_DIR)/util.o

all: $(SERVER) $(CLIENT)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

$(SERVER): $(SRC_DIR)/server.c $(COMMON_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -I$(INC_DIR) $^ -o $@ -pthread $(LDFLAGS)

$(CLIENT): $(SRC_DIR)/client.c $(COMMON_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -I$(INC_DIR) $^ -o $@ -pthread $(LDFLAGS)

clean:
	rm -rf $(BIN_DIR) $(OBJ_DIR)

.PHONY: all clean
