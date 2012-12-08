CC = gcc
AS = gas
LD = ld
CFLAGS = -g -Wall

all:	arp.c rarp.c ping.c
	$(CC) arp.c $(CFLAGS) -o arp
	$(CC) rarp.c $(CFLAGS) -o rarp
	$(CC) ping.c $(CFLAGS) -o ping

clean:
	rm -f ping
	rm -f arp
	rm -f rarp
