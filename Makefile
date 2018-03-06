all:
	$(CC) $(CFLAGS) beacon-sniffer.c -lpcap -o beacon-sniffer -ggdb
