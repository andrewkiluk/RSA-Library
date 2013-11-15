CFLAGS = -g -Wall
LDFLAGS = -g
CC = gcc
LIBS_PATH = -L.
LDLIBS = $(LIBS_PATH) -lrsa -lm

test: test.o librsa.a rsa.h

librsa.a: rsa.o
	ar rc librsa.a rsa.o
	ranlib librsa.a

rsa.o: rsa.c rsa.h
	gcc -c rsa.c

.PHONY: clean, all

clean:
	rm -f *.o a.out rsa.o rsa librsa.a

all: clean rsa
