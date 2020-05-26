# CC	=	g++
# TARGET	=	pcap_parser

# INCLUDES	=	-I/usr/local/Cellar/libpcap

# LIBS	=	-lpcap

# SRCS	=	parse.cpp

# OBJS	=	$(SRCS:.cpp=.o)

# # define the executable file 
# MAIN	=	mycc
# all:	$(MAIN)
# $(MAIN): $(OBJS) 
#         $(CC)	$(CFLAGS)	$(INCLUDES)	-o	$(MAIN)	$(OBJS)	$(LIBS)
# .cpp.o:
#         $(CC) $(INCLUDES) -c $<  -o $@
all:
	g++ -Wall -Wno-unused-variable -lpcap -I/usr/local/Cellar/libpcap parse.cpp -o parse
clean:
	rm *.o *.csv parse