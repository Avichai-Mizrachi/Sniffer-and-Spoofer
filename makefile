CC = gcc
CFLAGS = -Wall -g -fPIC

sniffer: sniffer.o
	$(CC) $(CFLAGS) sniffer.o -o sniffer -lpcap

spoofer: spoofer.o
	$(CC) $(CFLAGS) spoofer.o -o spoofer -lpcap

snoofer: snoofer.o
	$(CC) $(CFLAGS) snoofer.o -o snoofer -lpcap

snoofer.o: snoofer.c
	$(CC) $(CFLAGS) -c snoofer.c -o snoofer.o

sniffer.o: sniffer.c
	$(CC) $(CFLAGS) -c sniffer.c -o sniffer.o

spoofer.o: spoofer.c
	$(CC) $(CFLAGS) -c spoofer.c -o spoofer.o

all: sniffer spoofer snoofer
	clear

.Phony: clean

clean:
	rm *.o sniffer spoofer 208465872_323968859.txt snoofer