CC = gcc
CFLAGS = -I./include -Wall -Wextra -O2
LDFLAGS = -lpcap

SRCDIR = src
INCDIR = include
OBJ = $(SRCDIR)/main.o $(SRCDIR)/sniff.o $(SRCDIR)/decode.o $(SRCDIR)/util.o

TARGET = cshark

.PHONY: all clean re

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(SRCDIR)/*.o $(TARGET)

re: clean all