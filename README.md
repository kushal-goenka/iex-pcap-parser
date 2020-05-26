# ie498_sp20_kgoenka2

PCAP Parser Final Project for Spring 2020 IE 498 - Electronic Trading 


Run the parser by: 
1. cd working
2. running make to compile and then ./parse to run the program, or:
3. g++ -Wall -Wno-unused-variable -lpcap -I/usr/local/Cellar/libpcap parse.cpp -o parse to compile and ./parse to run


This will output two different CSV files under the names:

1. packet_information - Raw Packet Header Information from IP and UDP
2. order_book.csv - Updates on the order book after every end of event for every intrument we care about



There are a few define directives that can be modified before compiling the program. These are at the top of p

NUM_PACKETS 100000
PCAP_FILE_NAME "data_feeds.pcap"
PACKET_INFO_FILE "packet_information.csv"
ORDER_BOOK_FILE "order_book.csv"
NUM_LEVELS 2

