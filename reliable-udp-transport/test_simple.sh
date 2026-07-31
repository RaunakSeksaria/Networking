#!/bin/bash
# End to end file transfer over loopback. Starts its own server, sends a file,
# and checks that what arrived matches what was sent.

set -u

PORT=8080
INPUT=test_input.txt
OUTPUT=test_output.txt

cleanup() {
    [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null
    rm -f "$INPUT" "$OUTPUT"
}
trap cleanup EXIT

echo "Building..."
make >/dev/null || { echo "FAIL: build error"; exit 1; }

echo "Hello, World! This is a test file for the reliable UDP transport." > "$INPUT"

echo "Starting server on port $PORT..."
./server "$PORT" >/dev/null 2>&1 &
SERVER_PID=$!
sleep 1

echo "Transferring $INPUT as $OUTPUT..."
./client 127.0.0.1 "$PORT" "$INPUT" "$OUTPUT" >/dev/null 2>&1
sleep 1

if [ ! -f "$OUTPUT" ]; then
    echo "FAIL: server did not produce $OUTPUT"
    exit 1
fi

if cmp -s "$INPUT" "$OUTPUT"; then
    echo "PASS: received file is identical to the one sent ($(stat -c%s "$OUTPUT") bytes)"
    exit 0
else
    echo "FAIL: received file differs from the one sent"
    echo "  sent:     $(stat -c%s "$INPUT") bytes"
    echo "  received: $(stat -c%s "$OUTPUT") bytes"
    exit 1
fi
