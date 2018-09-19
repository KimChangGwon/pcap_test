all : pcap_test

pcap_test: 9_19.o
	g++ -g -o pcap_test 9_19.o -lpcap

9_19.o:
	g++ -g -c -o 9_19.o 9_19.cpp

clean:
	rm -f pcap_test
	rm -f *.o

