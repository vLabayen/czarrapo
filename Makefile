CC=gcc

num_threads=7
test_file_size=1M

CFLAGS=-O3 -flto -std=c11 -fPIE -Wall -D NUM_THREADS=$(num_threads)
LDFLAGS=-lcrypto -lssl -lm -pthread
DEBUG_FLAGS=-D DEBUG

czarrapo: src/*.c
	$(CC) $(CFLAGS) $? $(LDFLAGS) -o bin/czarrapo

debug: src/*.c
	$(CC) $(CFLAGS) $(DEBUG_FLAGS) $? $(LDFLAGS) -o bin/czarrapo

testfile:
	dd if=/dev/urandom of=test/test.txt bs=$(test_file_size) count=1
	ls -lh test/test.txt

shared: src/common.c src/decrypt.c src/thread.c src/context.c src/encrypt.c src/rsa.c
	gcc $(CFLAGS) -fPIC -shared $(LDFLAGS) $(DEBUG_FLAGS) $^ -o bin/czarrapo.so

all: czarrapo shared

clean:
	rm -f bin/czarrapo*
	rm -f test/czarrapo_rsa test/czarrapo_rsa.pub
	rm -f test/test.txt test/test.crypt test/test.decrypt
