# Reliable UDP Transport

A connection oriented, reliable byte stream implemented on top of UDP datagrams. UDP provides no
ordering, no delivery guarantee, and no flow control, so this layer adds all three: a handshake to
establish shared sequence state, per packet timers to recover losses, cumulative acknowledgements to
keep the sender moving, and a receiver advertised window to stop a fast sender from overrunning a
slow receiver.

Two binaries are produced: `client` and `server`. They speak the same protocol and share one
implementation module.

## Building

```bash
make          # builds ./client and ./server
make debug    # same, with -g -DDEBUG
make clean
```

## Running

File transfer, which is the default mode:

```bash
./server <port>
./client <server_ip> <port> <input_file> <output_file_name>
```

The client sends the destination filename as the first data packet, then streams the file. The
server writes it under that name in its own working directory, so run the two from different
directories if the names would collide.

Chat mode, where both sides multiplex stdin and the socket with `select()`:

```bash
./server <port> --chat
./client <server_ip> <port> --chat
```

Type `/quit` to begin connection teardown.

Both binaries accept an optional trailing `loss_rate` argument. See Known limitations below before
relying on it.

## Protocol

Every datagram carries a 12 byte header ahead of the payload:

| Field | Width | Meaning |
| --- | --- | --- |
| `seq_num` | 32 bits | Byte stream offset of the first payload byte |
| `ack_num` | 32 bits | Next byte expected, cumulative |
| `flags` | 16 bits | `SYN` 0x1, `ACK` 0x2, `FIN` 0x4 |
| `window_size` | 16 bits | Bytes of receive buffer currently free |

Header fields go on the wire in network byte order. Conversion happens only inside
`send_sham_packet` and `recv_sham_packet`; every other part of the code works in host order.

Connection setup is the usual three way exchange: the client sends `SYN` with its initial sequence
number, the server replies `SYN|ACK` acknowledging it, and the client completes with an `ACK`.
Teardown is four way, with each side sending its own `FIN` and acknowledging the other.

Tuning constants live in `sham.h`:

| Constant | Value | Role |
| --- | --- | --- |
| `DATA_CHUNK_SIZE` | 1024 | Payload bytes per packet |
| `SLIDING_WINDOW_SIZE` | 10 | Maximum unacknowledged packets in flight |
| `RTO_TIMEOUT_MS` | 500 | Per packet retransmission timeout |
| `MAX_RETRIES` | 5 | Retransmission attempts before giving up |
| `RECEIVE_BUFFER_SIZE` | 4096 | Receiver buffer backing the advertised window |
| `MAX_WINDOW_SIZE` | 2048 | Ceiling on the advertised window |

## Design notes

**Two counters that look alike and are not.** `seq_num`, `last_byte_sent`, and `ack_num` are byte
offsets and advance by the payload length. `window_base` and `next_seq_num` in `sender_state_t` are
packet indices, used to address `sliding_window[i % SLIDING_WINDOW_SIZE]`. Acknowledgements are
cumulative over bytes, while the window slides over packets.

**The sender is a poll loop, not blocking I/O.** Each iteration sends while the window has room,
checks for expired retransmission timers, then waits up to 10 ms in `select()` for acknowledgements.
This lets one thread make progress on sending and receiving without blocking on either.

**Loss recovery retransmits only what timed out.** A cumulative acknowledgement above a packet's
sequence range retires that packet's timer rather than triggering a resend, so recovering one lost
packet does not resend the ones behind it.

**Out of order arrivals are buffered, not dropped.** The receiver holds packets ahead of the
expected sequence number and drains them once the gap fills.

## Verbose logging

Set `RUDP_LOG=1` to write a protocol event log to `client_log.txt` or `server_log.txt`. Without it,
no log file is created.

```
[2026-07-30 23:41:30.735658] [LOG] SND SYN SEQ=500
[2026-07-30 23:41:30.735890] [LOG] RCV SYN SEQ=1000
[2026-07-30 23:41:30.735968] [LOG] SND ACK=1001 WIN=1024
[2026-07-30 23:41:30.736102] [LOG] SND DATA SEQ=501 LEN=17
[2026-07-30 23:41:30.736228] [LOG] RCV ACK=518
```

Timestamps come from `gettimeofday`, so they carry microsecond resolution.

`PACKET_LOSS=1` makes the sender deliberately drop the second and fourth data packets without
sending them, which exercises the retransmission timer path end to end. It is a fixed pattern, not a
probability.

## Testing

```bash
bash test_simple.sh    # loopback file transfer, starts and stops its own server
make test-file
make test-chat
```

A useful manual check is to transfer a file and compare checksums:

```bash
head -c 1000000 /dev/urandom > /tmp/in.bin
./server 8080 &
./client 127.0.0.1 8080 /tmp/in.bin out.bin
md5sum /tmp/in.bin out.bin
```

Adding `PACKET_LOSS=1` to both sides should still produce matching checksums, with `RETX DATA` lines
appearing in the client log.

## Known limitations

- **No MD5 verification.** The receiving side does not compute or print a checksum of the file it
  received. Verification is left to an external tool such as `md5sum`.
- **The `loss_rate` argument is parsed but not used.** It is accepted on the command line and echoed
  at startup, but no packet is dropped on its account. Use `PACKET_LOSS=1` for deterministic loss
  injection instead.
- **Chat mode teardown is unreliable.** Sending `/quit` initiates the `FIN` exchange, but the
  handshake has been observed to hang when stdin is a pipe rather than a terminal.
- **Three log events are never emitted.** `FLOW WIN UPDATE`, `RCV FIN`, and `SND ACK FOR FIN` have
  helper functions but no call sites, so they never appear in the log even though the corresponding
  protocol behavior does occur.
- **Server output is verbose.** The server prints handshake and flow control detail to stdout, which
  is useful when watching a transfer and noisy when scripting one.
