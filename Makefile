CFLAGS += -O3

all: mkap pcap2tap

mkap: mkap.o
	$(CC) -o $@ $^

pcap2tap: pcap2tap.o
	$(CC) -o $@ $^

clean:
	rm -rf mkap pcap2tap *.o
