CC=cc
CFLAGS=-Wall -I/usr/local/opt/openssl/include

SRC=libssl_patch.c
LIB=libssl_patch.o

all:
	$(CC) $(CFLAGS)  -o $(LIB)  -c $(SRC)

clean:
	rm -f $(LIB)