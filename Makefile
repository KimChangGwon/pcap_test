all : pcap_test

pcap_test: 9_26.o
	gcc -g -o pcap_test 9_26.o -lpcap

9_26.o:
	gcc -g -c -o 9_26.o 9_26.c

clean:
	rm -f pcap_test
	rm -f *.o

