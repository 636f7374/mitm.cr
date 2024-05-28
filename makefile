CC=cc
CFLAGS=-Wall -I$(shell pkg-config --silence-errors --variable=includedir libssl)

test: shard
	crystal spec
shard:
	$(CC) $(CFLAGS) -c patch/libssl_patch.c -o patch/libssl_patch.o
	shards build
clean:
	rm -rf lib && rm -f shard.lock