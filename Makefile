CFLAGS = -g -Wall
LDFLAGS = -g
CC = gcc

test: test.o rsa.o rsa.h

rsa: 

.PHONY: clean, all

clean:
	rm -f *.o a.out rsa.o rsa

all: clean rsa
