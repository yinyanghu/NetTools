CC = gcc
AS = gas
LD = ld
CFLAGS = -g -Wall

all:	dos_attack.c arp_attack.c
	$(CC) dos_attack.c $(CFLAGS) -o dos_attack
	$(CC) arp_attack.c $(CFLAGS) -o arp_attack

clean:
	rm -f arp_attack
	rm -f dos_attack
