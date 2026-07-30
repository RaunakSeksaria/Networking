CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
LDFLAGS = -lm

# Source files
SRC_CLIENT = client.c
SRC_SERVER = server.c
SRC_COMMON = sham.c
HDR = sham.h

# Object files
OBJ_CLIENT = client.o
OBJ_SERVER = server.o
OBJ_COMMON = sham.o

# Executables
CLIENT = client
SERVER = server

# Default target
all: $(CLIENT) $(SERVER)

# Build client
$(CLIENT): $(OBJ_CLIENT) $(OBJ_COMMON) $(HDR)
	$(CC) $(CFLAGS) -o $(CLIENT) $(OBJ_CLIENT) $(OBJ_COMMON) $(LDFLAGS)

# Build server
$(SERVER): $(OBJ_SERVER) $(OBJ_COMMON) $(HDR)
	$(CC) $(CFLAGS) -o $(SERVER) $(OBJ_SERVER) $(OBJ_COMMON) $(LDFLAGS)

# Compile client object
$(OBJ_CLIENT): $(SRC_CLIENT) $(HDR)
	$(CC) $(CFLAGS) -c $(SRC_CLIENT)

# Compile server object
$(OBJ_SERVER): $(SRC_SERVER) $(HDR)
	$(CC) $(CFLAGS) -c $(SRC_SERVER)

# Compile common object
$(OBJ_COMMON): $(SRC_COMMON) $(HDR)
	$(CC) $(CFLAGS) -c $(SRC_COMMON)

# Clean build artifacts
clean:
	rm -f $(CLIENT) $(SERVER) $(OBJ_CLIENT) $(OBJ_SERVER) $(OBJ_COMMON) *.o

# Rebuild everything
re: clean all

# Run server in background
run-server: $(SERVER)
	./$(SERVER) 8080

# Run server in chat mode
run-server-chat: $(SERVER)
	./$(SERVER) 8080 --chat

# Test file transfer
test-file: $(CLIENT) $(SERVER)
	@echo "Starting server in background..."
	@./$(SERVER) 8080 &
	@sleep 2
	@echo "Sending test file..."
	@echo "Hello, World!" > test_input.txt
	@./$(CLIENT) 127.0.0.1 8080 test_input.txt test_output.txt
	@echo "Test completed. Check received_file.bin and test_output.txt"
	@pkill -f "./$(SERVER)" || true
	@rm -f test_input.txt

# Test chat mode
test-chat: $(CLIENT) $(SERVER)
	@echo "Starting server in chat mode..."
	@./$(SERVER) 8080 --chat &
	@sleep 2
	@echo "Starting client in chat mode..."
	@./$(CLIENT) 127.0.0.1 8080 --chat
	@pkill -f "./$(SERVER)" || true

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: clean all

# Help
help:
	@echo "Available targets:"
	@echo "  all          - Build both client and server (default)"
	@echo "  client       - Build client only"
	@echo "  server       - Build server only"
	@echo "  clean        - Remove all build artifacts"
	@echo "  re           - Clean and rebuild everything"
	@echo "  run-server   - Run server on port 8080"
	@echo "  run-server-chat - Run server in chat mode on port 8080"
	@echo "  test-file    - Test file transfer functionality"
	@echo "  test-chat    - Test chat functionality"
	@echo "  debug        - Build with debug symbols"
	@echo "  help         - Show this help message"

.PHONY: all clean re run-server run-server-chat test-file test-chat debug help

