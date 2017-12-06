# File:   Makefile
# Author: robertomaldonado

# Declare variables
CC=g++ -std=c++11
CFLAGS= -O2

#Declare processes
all: ./parser 

parser:
	$(CC) $(CFLAGS) parser3.cpp -o parser3

clean: 
	rm -rf *.o parser