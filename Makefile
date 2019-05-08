# File:   Makefile
# Author: robertomaldonado

# Declare variables
CC=g++ -std=c++11
CFLAGS= -O2

#Declare processes
all: ./parser 

parser:
	$(CC) $(CFLAGS) packetInspector.cpp -o packetInspector

clean: 
	rm -rf *.o packetInspector