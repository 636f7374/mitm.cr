CC=cc
CFLAGS=-Wall -I/usr/local/opt/openssl/include

test: shard
	crystal spec
shard:
	$(CC) $(CFLAGS) -c patch/libssl_patch.c -o patch/libssl_patch.o
	shards build
clean:
	rm -rf lib && rm -f shard.lock