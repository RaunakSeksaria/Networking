CC = gcc
CFLAGS = -Wall -Wextra -O2

SRC = client.c server.c
HDR = sham.h

all: client server

client: client.c sham.h
	$(CC) $(CFLAGS) -o client client.c

server: server.c sham.h
	$(CC) $(CFLAGS) -o server server.c

clean:
	rm -f client server