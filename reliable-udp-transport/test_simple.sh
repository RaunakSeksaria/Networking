#!/bin/bash

echo "Testing networking2 implementation..."

# Clean up any existing processes
pkill -f server 2>/dev/null || true
pkill -f client 2>/dev/null || true
sleep 1

# Create test file
echo "Hello, World! This is a test file for networking2." > test_input.txt

# Start server in background
echo "Starting server..."
./server 8080 &
SERVER_PID=$!
sleep 2

# Test file transfer
echo "Testing file transfer..."
./client 127.0.0.1 8080 test_input.txt test_output.txt

# Wait a moment
sleep 1

# Check if file was received
if [ -f "received_file.bin" ]; then
    echo "PASS: file transfer successful"
    echo "Received file content:"
    cat received_file.bin
    echo ""
else
    echo "FAIL: no received file"
fi

# Clean up
kill $SERVER_PID 2>/dev/null || true
rm -f test_input.txt test_output.txt received_file.bin

echo "Test completed."
