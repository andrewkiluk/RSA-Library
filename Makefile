CFLAGS = -g -Wall
LDFLAGS = -g
CC = gcc
LIBS_PATH = -L.
LDLIBS = $(LIBS_PATH) -lrsa -lm

test: test.o librsa.a rsa.h
	gcc test.c sha-256.c -o test $(LDLIBS)
librsa.a: rsa.o
	ar rc librsa.a rsa.o
	ranlib librsa.a

rsa.o: rsa.c rsa.h sha-256.c
	gcc -c rsa.c sha-256.c

.PHONY: clean, all

clean:
	rm -f *.o a.out rsa.o rsa librsa.a

all: clean rsa
