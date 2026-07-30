CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lpcap

OBJ = main.o sniff.o decode.o util.o session.o

TARGET = cshark

.DEFAULT_GOAL := all

.PHONY: all clean re

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o $(TARGET)

re: clean all

# Traffic generators for manual testing. Run one of these in a second terminal
# while `sudo ./cshark` is capturing, then compare against Wireshark.
.PHONY: test test-phase1 test-phase2 test-phase3 test-phase4 test-phase5 test-filters test-robustness

test:
	@echo "Traffic generators (run while cshark is capturing):"
	@echo "  make test-phase1      # basic capture traffic"
	@echo "  make test-phase2      # L2/L3 traffic (IPv4/IPv6/ARP)"
	@echo "  make test-phase3      # L4 traffic (TCP/UDP)"
	@echo "  make test-phase4      # payload traffic (HTTP/HTTPS/DNS)"
	@echo "  make test-phase5      # mixed session traffic"
	@echo "  make test-filters     # per-protocol traffic for filters"
	@echo "  make test-robustness  # edge-case traffic"
	@echo ""
	@echo "Optional env: IFACE=<real interface>, GATEWAY=<ipv4 gateway>"

test-phase1:
	@bash tests/phase1.sh

test-phase2:
	@bash tests/phase2.sh

test-phase3:
	@bash tests/phase3.sh

test-phase4:
	@bash tests/phase4.sh

test-phase5:
	@bash tests/phase5.sh

test-filters:
	@bash tests/filters.sh

test-robustness:
	@bash tests/robustness.sh
