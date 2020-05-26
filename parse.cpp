#include <stdio.h>
#include <string.h>

#include <string>
#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <fstream>
#include <math.h>
#include<map>

using namespace std;

#define NUM_PACKETS 100000
#define PCAP_FILE_NAME "data_feeds.pcap" // "data_feeds_20191030_20191030_IEXTP1_DEEP1.0_converted_pcap.pcap" // 
#define PACKET_INFO_FILE "packet_information.csv"
#define ORDER_BOOK_FILE "order_book.csv"
#define NUM_LEVELS 2
#define TRADES_OUTPUT_FILE "trades.csv"
#define TIMESTAMP_OUTPUT_FILE "message_timestamps.csv"

string instruments[] = {"AMD"};
int message_id = 1;


// Message timestamps

unsigned long long int packet_capture_time_in_nanoseconds;
unsigned long long int send_time;
unsigned long long int message_event_timestamp;


std::map<double, int,std::greater<int> > bid;
std::map<double, int> ask;

struct book_struct{

    std::map<double, int,std::greater<int> > bid;
    std::map<double, int> ask;

};


std::map<string, book_struct> order_book;



// Function Definitions

void handlePacket(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
int parse_iex_message(unsigned int message_len,u_char* message_payload);


void match_order_on_bid(double price_float, int size,string symbol_raw);

void match_order_on_ask(double price_float, int size,string symbol_raw);

void print_order_book(string symbol_raw,string type);

string convert_trade_sale_condition_to_string(char sale_condition_flags);

void print_order_book(string symbol_raw,string type){


    ofstream order_book_file;
    order_book_file.open(ORDER_BOOK_FILE,ios::app);

    map<double, int>::iterator itr;
    int i = 0;
    // order_book_file << message_id<<",";
    if(type.compare("BID")==0){
        order_book_file << message_id<<","<<"BID_UPDATE"<<",";
    }
    else{
        order_book_file << message_id<<","<<"ASK_UPDATE"<<",";
    }

    for(itr=order_book[symbol_raw].bid.begin();itr!=order_book[symbol_raw].bid.end();itr++){
        if(i<NUM_LEVELS){
            
            if(itr->second>0){
                order_book_file << itr->first <<","<<itr->second<<",";
                i++;
            }
            
        }
        else{
            break;
        }
        
    }

    while(i<NUM_LEVELS){
        order_book_file << "NULL,"<<"NULL,";
        i++;
    }

    i = 0;
    for(itr=order_book[symbol_raw].ask.begin();itr!=order_book[symbol_raw].ask.end();itr++){
        if(i<NUM_LEVELS){
            
            if(itr->second>0){
                 order_book_file << itr->first <<","<<itr->second<<",";
                 i++;
            }
            
        }
        else{
            break;
        }
        
    }

    while(i<NUM_LEVELS){
        order_book_file << "NULL,"<<"NULL,";
        i++;
    }
    order_book_file << symbol_raw<<'\n';

    order_book_file.close();


}


void match_order_on_bid(double price_float, int size,string symbol_raw){

    // loop through the asks

    map<double, int>::iterator itr;

    itr = order_book[symbol_raw].ask.begin();
    while(size>0){
        if(itr!=order_book[symbol_raw].ask.end()){
            if(price_float > itr->first){
                if(size < itr->second){
                    // cout << "Match at Price: " << price_float <<endl;;
                    itr->second -= size;
                    size = 0;
                }
                else{
                    size = size - itr->second;
                    itr->second = 0;
                    // cout << "ON BID" <<endl;
                    // cout << "KEY TO REMOVE: " << itr->first<<endl;
                    // order_book[symbol_raw].ask.erase(itr->first);
                }
            }
            itr++;
        }
        else{
            // add the remaining to the orderbook on the bid side
            if(order_book[symbol_raw].bid.count(price_float)==1){
                order_book[symbol_raw].bid[price_float] += size;
            }
            else{
                order_book[symbol_raw].bid[price_float] = size;
            }
            break;

        }


    }

}

void match_order_on_ask(double price_float, int size,string symbol_raw){

    map<double, int>::iterator itr;

    itr = order_book[symbol_raw].bid.begin();
    // cout << "Price Ask Float " << price_float << " " <<size <<endl;
    while(size>0){
        // cout << "Reached Here " <<endl;
        if(itr!=order_book[symbol_raw].bid.end()){
            // cout << "First: "<<itr->first <<endl;
            if(price_float < itr->first){
                if(size < itr->second){
                    itr->second -= size;
                    size = 0;
                    // break;
                }
                else{
                    size = size - itr->second;
                    itr->second = 0;
                    // order_book[symbol_raw].bid.erase(itr->first);
                }
            }
            itr++;
        }
        else{
            // cout << "Append to the list" << endl;
            // add the remaining to the orderbook on the ask side
            if(order_book[symbol_raw].ask.count(price_float)==1){
                order_book[symbol_raw].ask[price_float] += size;
            }
            else{
                order_book[symbol_raw].ask[price_float] = size;
            }
            break;

        }

    }





}


// Define Structs

struct iex_packet_header{
    unsigned char version; //1
    unsigned char reserved; //1
    u_short protocol_id; //2
    unsigned int channel_id; //4
    unsigned int session_id; //4
    u_short payload_len; //2
    u_short message_count; //2
    unsigned long long int stream_offset; //8
    unsigned long long int first_msg_seq_num; //8
    unsigned long long int send_time; //8
   
};

struct price_level_update{

    char event_flags;
    u_long timestamp_raw;
    char symbol_raw[8];
    u_int32_t size;
    u_long price_raw;

};

struct trading_status_message{

    char trading_status;
    u_long timestamp_raw;
    char symbol_raw[8];
    char reason_raw[4];

};

// Main Function 

int main(int argc, char *argv[]){

    pcap_t *descr;
    

    char errbuf[PCAP_ERRBUF_SIZE];

    descr = pcap_open_offline(PCAP_FILE_NAME, errbuf);

    if (descr == NULL) {
        cout << "pcap_open_live() failed: " << errbuf << endl;
        return 1;
    }

    // cout << instruments[0].compare("AAPL") <<endl;

    //Create Order book

    // order_book o;

    for(int i=0;i<2;i++){
        book_struct empty_book;
        order_book[instruments[i]] = empty_book;
    }

    // cout << o.bid.begin()->first<<endl;

    // map<string, order_book>::iterator itr;
    // for (itr = order_books.begin(); itr != order_books.end(); itr++) {
    // for(auto const& itr: bid){
        // cout << "Instrument Names: ";
        // cout << '\t' << itr->first;
        // cout << "First " << (itr->second).bid.begin()->first << '\n'; 
    // }

    ofstream trades_output;
    trades_output.open (TRADES_OUTPUT_FILE);
    trades_output <<"MESSAGE_ID," << "MESSAGE_TYPE,"<<"SYMBOL" << "," << "PRICE" << "," << "SIZE," << "TRADE_ID,"<< "TRADE_FLAGS"<< "\n";
    trades_output.close();

    ofstream message_timestamps;
    message_timestamps.open (TIMESTAMP_OUTPUT_FILE);
    message_timestamps <<"MESSAGE_ID," << "NETWORK_TIMESTAMP,"<<"SENDING_TIMESTAMP," << "EVENT_TIMESTAMP" << "\n";
    message_timestamps.close();


    ofstream packet_information;
    packet_information.open (PACKET_INFO_FILE);
    packet_information << "Source Port" << "," << "Destination Port" << "," << "Data Length" << ","<< hex << "Checksum," << "Source IP,"<<"Destination IP"<< "\n";
    packet_information.close();

    ofstream order_book_file;
    order_book_file.open(ORDER_BOOK_FILE);
    // packet_information << "Source Port" << "," << "Destination Port" << "," << "Data Length" << ","<< hex << "Checksum," << "Source IP,"<<"Destination IP"<< "\n";
    order_book_file << "MESSAGE_ID,MESSAGE_TYPE,";
    for(int i=0;i<NUM_LEVELS;i++){

        order_book_file << "BID"<<i<<".Price,"<<"BID"<<i<<".Size,";
    }
    
    for(int i=0;i<NUM_LEVELS;i++){
        if(i<NUM_LEVELS-1)
            order_book_file << "ASK"<<i<<".Price,"<<"ASK"<<i<<".Size,";
        else
            order_book_file << "ASK"<<i<<".Price,"<<"ASK"<<i<<".Size";
    }

        order_book_file << ",Symbol"<<'\n';

    order_book_file.close();


    // cout << "First"<< bid.begin()->second <<endl;

    if (pcap_loop(descr, NUM_PACKETS, handlePacket, NULL) < 0) { // change the second argument to the number of packets to decode
      cout << "pcap_loop() failed: " << pcap_geterr(descr);
      return 1;
    }

    // CODE TO PRINT OUT THE BID AND ASK MAP

    map<double, int>::iterator itr;
    for (itr = order_book[instruments[0]].bid.begin(); itr != order_book[instruments[0]].bid.end(); itr++) {
    // for(auto const& itr: bid){
        
        cout << '\t' << itr->first;
        cout << '\t' << itr->second << '\n'; 
    }
    cout << "Starting Ask:" << endl;
    for (itr = order_book[instruments[0]].ask.begin(); itr != order_book[instruments[0]].ask.end(); itr++) {
    // for(auto const& itr: bid){
        
        cout << '\t' << itr->first;
        cout << '\t' << itr->second << '\n'; 
    }
    
    // cout << "First Value is big:" << bid.begin()->first <<endl;
    // cout << "First Value is ask:" << ask.begin()->first <<endl;

    cout << descr << endl;

    return 0;


}

// Function to handle the packet and parse the data

void handlePacket(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  
  
    const struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    const struct udphdr* udpHeader;
    const struct iex_packet_header* iexHeader;
    // cout << "TIME NS: "<<(pkthdr->ts).tv_sec<<endl;

    packet_capture_time_in_nanoseconds = ((pkthdr->ts).tv_sec)*pow(10,9) + ((pkthdr->ts).tv_usec)*pow(10,3);
    
    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];
    // u_int sourcePort, destPort;
    u_char *message_bytes;
    int dataLength = 0;

    string sourceIP = "";
    string destIP = "";

    ethernetHeader = (struct ether_header*)packet;
    ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
    udpHeader = (udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

    // Get the IP addresses from the ipHeader
    inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);

    for(int i =0;i<INET_ADDRSTRLEN;i++){

        if ((sourceIp[i] >= 32 && sourceIp[i] <= 126) || sourceIp[i] == 10 || sourceIp[i] == 11 || sourceIp[i] == 13) {
            sourceIP = sourceIP + (char)sourceIp[i] ;
        }
    }

    for(int i =0;i<INET_ADDRSTRLEN-4;i++){
        if ((destIP[i] >= 32 && destIP[i] <= 126) || destIP[i] == 10 || destIP[i] == 11 || destIP[i] == 13) {
            destIP = destIP + (char)destIp[i];
        }
        else{
            destIP += (int)(char)destIp[i];
        }
    }
    


    // cout << "Source IP:"<< sourceIP <<endl;
    // cout << "Destination IP:"<< destIP <<endl;
    // cout << "Source Port:" << ntohs(udpHeader->uh_sport) <<endl;
    // cout << "Destination Port:" << ntohs(udpHeader->uh_dport) <<endl;
    // cout << "Length:" << ntohs(udpHeader->uh_ulen) <<endl;
    // cout << "Checksum:" << hex << ntohs(udpHeader->uh_sum) <<endl;


    ofstream packet_information;
    packet_information.open (PACKET_INFO_FILE,ios::app); // Append to existing file
    packet_information << ntohs(udpHeader->uh_sport) << "," << ntohs(udpHeader->uh_dport) << "," << ntohs(udpHeader->uh_ulen) << ","<< hex << ntohs(udpHeader->uh_sum) <<"," <<sourceIP<<","<<destIP<<"\n";
    packet_information.close();




    iexHeader = (iex_packet_header*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));


    message_bytes = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct iex_packet_header));

    dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr)+ sizeof(struct iex_packet_header));

    unsigned int current_offset = 0;
    unsigned int message_len = 0;

    send_time = iexHeader->send_time;

    for(int i = 0; i < (unsigned int)(iexHeader->message_count);i++){

        message_len = (unsigned int)*(u_short*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct iex_packet_header)+current_offset);

        parse_iex_message(message_len,(u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct iex_packet_header) +current_offset + 2  ));
        message_id +=1;
        current_offset += 2 + message_len;
    }


}



int parse_iex_message(unsigned int message_len,u_char* message_payload){

    char message_type;

    message_type = (char)*(u_char*)(message_payload);

    message_event_timestamp = 0;
    // cout<<"Message Type: "<<message_type<<endl;
    // Create the order book for each stock

    // Use Switch Case Here
    if(message_type == 'S'){
        char system_event = (char)*(u_char*)(message_payload+1);
        u_long timestamp_raw = (u_long)*(u_long*)(message_payload+1+1);
        message_event_timestamp = timestamp_raw;
        // cout << "TIMESTAMP RAW:" << system_event << " " <<timestamp_raw <<endl;

    }
    else if(message_type == 'H'){

        char trading_status = (char)*(u_char*)(message_payload+1);

        // cout << "Trading_Status: " <<trading_status << endl;

        u_long timestamp_raw = (u_long)*(u_long*)(message_payload+2);
         message_event_timestamp = timestamp_raw;

        // cout << "Timestamp_Raw: " << timestamp_raw << endl;

        char symbol_raw[8];
        
        for(int i=0; i<8;i++){
            symbol_raw[i] = (char)*(char*)(message_payload+2+8+i);
            // cout << symbol_raw[i];
        }


    }
    else if(message_type == 'O'){

        char halt_status = (char)*(u_char*)(message_payload+1);

        // cout << "Halt_Status: " <<trading_status << endl;

        u_long timestamp_raw = (u_long)*(u_long*)(message_payload+2);
         message_event_timestamp = timestamp_raw;

        // cout << "Timestamp_Raw: " << timestamp_raw << endl;

        char symbol_raw[8];
        
        for(int i=0; i<8;i++){
            symbol_raw[i] = (char)*(char*)(message_payload+2+8+i);
            // cout << symbol_raw[i];
        }
        
    }
    else if(message_type == 'P'){

        
        char short_sale_price_status = (char)*(u_char*)(message_payload+1);

        // cout << "Halt_Status: " <<trading_status << endl;

        u_long timestamp_raw = (u_long)*(u_long*)(message_payload+2);
         message_event_timestamp = timestamp_raw;

        // cout << "Timestamp_Raw: " << timestamp_raw << endl;

        char symbol_raw[8];
        
        for(int i=0; i<8;i++){
            symbol_raw[i] = (char)*(char*)(message_payload+2+8+i);
            // cout << symbol_raw[i];
        }

        char detail_raw = (char)*(u_char*)(message_payload+2+8+8);
        
        
    }
    else if(message_type == '8'){ // BID

        char event_flags = (char)*(u_char*)(message_payload+1);


        u_long timestamp_raw = (u_long)*(u_long*)(message_payload+2);
        message_event_timestamp = timestamp_raw;

        string symbol_raw((char*)(message_payload+2+8),8);

        // Remove trailing whitespaces
        std::string::iterator end_pos = std::remove(symbol_raw.begin(), symbol_raw.end(), ' ');
        symbol_raw.erase(end_pos, symbol_raw.end());

        int size = (int)*(int*)(message_payload+2+8+8);

        u_long price_raw = (u_long)*(u_long*)(message_payload+2+8+8+4);

        double price_float = price_raw * pow(10,-4);

        // change to false to have correct execution for symbols we are interested in
        bool if_relevant = false;

        
        for(int i=0;i<sizeof(instruments)/sizeof(instruments[0]);i++){
            // cout << instruments[i] << endl;
            if(symbol_raw.compare(instruments[i])==0){
                // cout <<symbol_raw <<instruments[i]<<endl;
                if_relevant = true;
            }
            else{
                // cout <<symbol_raw <<instruments[i]<<endl;

            }
                
        }


        if(if_relevant==false)
            return 0;

        // cout << symbol_raw <<"Price is: " << price_float <<endl;
        match_order_on_bid(price_float,size,symbol_raw);
        
        if((int)event_flags==1){
            // cout <<"Event Flags: " << (int)event_flags <<endl;
            print_order_book(symbol_raw,"BID");

        }


    }
    else if(message_type == '5'){ // SELL

        char event_flags = (char)*(u_char*)(message_payload+1);


        u_long timestamp_raw = (u_long)*(u_long*)(message_payload+2);
         message_event_timestamp = timestamp_raw;


        string symbol_raw((char*)(message_payload+2+8),8);

        // Remove trailing whitespaces
        std::string::iterator end_pos = std::remove(symbol_raw.begin(), symbol_raw.end(), ' ');
        symbol_raw.erase(end_pos, symbol_raw.end());

        int size = (int)*(int*)(message_payload+2+8+8);

        u_long price_raw = (u_long)*(u_long*)(message_payload+2+8+8+4);

        // cout << symbol_raw << endl;
        double price_float = price_raw * pow(10,-4);

        // cout << symbol_raw <<;

        // change to false to have correct execution for symbols we are interested in
        bool if_relevant = false;


        for(int i=0;i<sizeof(instruments)/sizeof(instruments[0]);i++){
            // cout << instruments[i] << endl;
            if(symbol_raw.compare(instruments[i])==0)
                if_relevant = true;
        }

        // cout << if_relevant <<symbol_raw << endl;

        if(!if_relevant)
            return 0;

        match_order_on_ask(price_float,size,symbol_raw);


        if((int)event_flags==1){
            // cout <<"Event Flags: " << (int)event_flags <<endl;
            print_order_book(symbol_raw,"ASK");
        }
        
    }
    else if(message_type == 'T'){
        char sale_condition_flags = (char)*(u_char*)(message_payload+1);
        u_long timestamp_raw = (u_long)*(u_long*)(message_payload+1+1);
         message_event_timestamp = timestamp_raw;

        string symbol_raw((char*)(message_payload+2+8),8);

         // Remove trailing whitespaces
        std::string::iterator end_pos = std::remove(symbol_raw.begin(), symbol_raw.end(), ' ');
        symbol_raw.erase(end_pos, symbol_raw.end());

         // change to false to have correct execution for symbols we are interested in
        bool if_relevant = false;


        for(int i=0;i<sizeof(instruments)/sizeof(instruments[0]);i++){
            // cout << instruments[i] << endl;
            if(symbol_raw.compare(instruments[i])==0)
                if_relevant = true;
        }

        // cout << if_relevant <<symbol_raw << endl;

        if(!if_relevant)
            return 0;

        int size = (int)*(int*)(message_payload+2+8+8);

        u_long price_raw = (u_long)*(u_long*)(message_payload+2+8+8+4);

        u_long trade_id = (u_long)*(u_long*)(message_payload+2+8+8+4+8);

        double price_float = price_raw * pow(10,-4);
    
        string sale_condition_string = convert_trade_sale_condition_to_string(sale_condition_flags);

        ofstream trades_output;
        trades_output.open (TRADES_OUTPUT_FILE,ios::app);
        trades_output << message_id<<",TRADE,"<<symbol_raw << "," << price_float << "," << size << ","<<trade_id<<","<< sale_condition_string<< "\n";
        trades_output.close();


        
    }
    else if(message_type == 'E'){
        
        char sale_condition_flags = (char)*(u_char*)(message_payload+1);
        u_long timestamp_raw = (u_long)*(u_long*)(message_payload+1+1);
         message_event_timestamp = timestamp_raw;
        string symbol_raw((char*)(message_payload+2+8),8);

    }
    else if(message_type == 'D'){
        // DONT CARE
    }
    else if(message_type == 'A'){
        // DONT CARE
    }
    else if(message_type == 'X'){
        // DONT CARE
    }
    else{
        cout << "Unhandled message type: "<< message_type <<endl;
    }

    if(message_event_timestamp!=0){

        ofstream message_timestamps;
        message_timestamps.open (TIMESTAMP_OUTPUT_FILE,ios::app);
        message_timestamps << message_id<<","<<packet_capture_time_in_nanoseconds<<","<<send_time<<","<< message_event_timestamp << "\n";


        message_timestamps.close();
        message_event_timestamp = 0;

    }
    else{
        // cout <<message_id<<endl;
    }


    // ofstream message_timestamps;
    // message_timestamps.open (TIMESTAMP_OUTPUT_FILE);
    // message_timestamps <<"MESSAGE_ID," << "NETWORK_TIMESTAMP,"<<"SENDING_TIMESTAMP," << "EVENT_TIMESTAMP" << "\n";
    // message_timestamps.close();


    return 0;
}



string convert_trade_sale_condition_to_string(char sale_condition_flags){

    string sale_condition_string = "";
    // cout << "Sale Condition: " << hex<<(int)sale_condition_flags <<"Result" <<(sale_condition_flags & 0x80)<<endl;

    
    if((sale_condition_flags & 0x80) != 0){
        sale_condition_string += "INTERMARKET_SWEEP";
    }
    
    if((sale_condition_flags & 0x40) != 0){
        sale_condition_string += "| EXTENDED_HOURS";
    }
    else{
        sale_condition_string += "| REGULAR_HOURS";

    }
    if((sale_condition_flags & 0x20) != 0){
        sale_condition_string += "| ODD_LOT";
    }
    if((sale_condition_flags & 0x10) != 0){
        sale_condition_string += "| TRADE_THROUGH_EXEMPT";
    }
    if((sale_condition_flags & 0x08) != 0){
        sale_condition_string += "| SINGLE_PRICE_CROSS";
    }
    
    return sale_condition_string;


}

//REFERENCES 

// https://www.cs.swarthmore.edu/~newhall/unixhelp/howto_makefiles.html
// http://tonylukasavage.com/blog/2010/11/17/packet-capture-with-c----amp--linux/
// https://stackoverflow.com/questions/10599068/how-do-i-print-bytes-as-hexadecimal
// https://stackoverflow.com/questions/8060170/printing-hexadecimal-characters-in-c
// https://godoc.org/github.com/timpalpant/go-iex
// https://stackoverflow.com/questions/83439/remove-spaces-from-stdstring-in-c


// IEX References

// https://iextrading.com/docs/IEX%20Transport%20Specification.pdf
// https://iextrading.com/docs/IEX%20DEEP%20Specification.pdf