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
.PHONY: test test-basic test-l2-l3 test-l4 test-payload test-mixed test-filters test-robustness

test:
	@echo "Traffic generators (run while cshark is capturing):"
	@echo "  make test-basic       # ping and HTTP HEAD"
	@echo "  make test-l2-l3       # IPv4, IPv6, and ARP"
	@echo "  make test-l4          # TCP and UDP"
	@echo "  make test-payload     # HTTP, HTTPS, and DNS payloads"
	@echo "  make test-mixed       # combined session traffic"
	@echo "  make test-filters     # per-protocol traffic for filters"
	@echo "  make test-robustness  # edge-case traffic"
	@echo ""
	@echo "Optional env: IFACE=<real interface>, GATEWAY=<ipv4 gateway>"

test-basic:
	@bash tests/basic.sh

test-l2-l3:
	@bash tests/l2-l3.sh

test-l4:
	@bash tests/l4.sh

test-payload:
	@bash tests/payload.sh

test-mixed:
	@bash tests/mixed.sh

test-filters:
	@bash tests/filters.sh

test-robustness:
	@bash tests/robustness.sh
