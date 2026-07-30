############## LLM Generated Code Begins ################

 .DEFAULT_GOAL := all
## Test harness targets for Part B (traffic generators)
.PHONY: test-b test-b-phase1 test-b-phase2 test-b-phase3 test-b-phase4 test-b-phase5 test-b-filters test-b-robustness

test-b:
	@echo "See B/TESTING.md for instructions. Available targets:"
	@echo "  make -C B test-b-phase1      # basic capture traffic"
	@echo "  make -C B test-b-phase2      # L2/L3 traffic (IPv4/IPv6/ARP)"
	@echo "  make -C B test-b-phase3      # L4 traffic (TCP/UDP)"
	@echo "  make -C B test-b-phase4      # payload traffic (HTTP/HTTPS/DNS)"
	@echo "  make -C B test-b-phase5      # mixed session traffic"
	@echo "  make -C B test-b-filters     # per-protocol traffic for filters"
	@echo "  make -C B test-b-robustness  # edge-case traffic"

test-b-phase1:
	@bash tests/phase1.sh

test-b-phase2:
	@bash tests/phase2.sh

test-b-phase3:
	@bash tests/phase3.sh

test-b-phase4:
	@bash tests/phase4.sh

test-b-phase5:
	@bash tests/phase5.sh

test-b-filters:
	@bash tests/filters.sh

test-b-robustness:
	@bash tests/robustness.sh
CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lpcap

OBJ = main.o sniff.o decode.o util.o session.o

TARGET = cshark

.PHONY: all clean re

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o $(TARGET)

re: clean all

########### LLM Generated Code Ends ################
