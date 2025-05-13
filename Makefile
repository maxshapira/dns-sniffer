CC = gcc
CFLAGS = -Wall -Wextra -g
LIBS = -lpcap

OBJS = main.o capture.o dns_parser.o net_utils.o

dns-sniffer: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o dns-sniffer