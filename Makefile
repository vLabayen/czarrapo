CC=gcc

num_threads=7
test_file_size=1M

CFLAGS=-O3 -std=c11 -Wall -D NUM_THREADS=$(num_threads) -z noexecstack -fstack-protector -D_FORTIFY_SOURCE=2

BIN_FLAGS=-fPIE
SHARED_FLAGS=-fPIC -shared

LDFLAGS=-lcrypto -lssl -lm -pthread
DEBUG_FLAGS=-g -D DEBUG

czarrapo: src/*.c
	$(CC) $(CFLAGS) $(BIN_FLAGS) $(LDFLAGS) $^ -o bin/czarrapo

debug: src/*.c
	$(CC) $(CFLAGS) $(DEBUG_FLAGS) $(LDFLAGS) $^ -o bin/czarrapo

shared: src/common.c src/decrypt.c src/thread.c src/context.c src/encrypt.c src/rsa.c
	$(CC) $(CFLAGS) $(SHARED_FLAGS) $(LDFLAGS) $^ -o bin/czarrapo.so

all: czarrapo shared

testfile:
	bash test/generate_file.bash $(test_file_size) "test/test.txt"
	ls -lh test/test.txt

clean:
	rm -f bin/czarrapo*
	rm -f test/czarrapo_rsa test/czarrapo_rsa.pub
	rm -f test/test.txt test/test.crypt test/test.decrypt
