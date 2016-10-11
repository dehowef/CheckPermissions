CPP = g++
CPPFLAGS = -Wall -g -ansi -c

all: 
		g++ runpriv.cpp -o runpriv -std=c++11

sniff:
		g++ sniff.cpp -o sniff -std=c++11
		chmod 700 sniff
clean:
		rm -rf *o runpriv sniff

