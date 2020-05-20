CC=gcc
CFLAGS=-O3 -flto -std=c11 -fPIE -Wall
LDFLAGS=-lcrypto -lssl -lm -pthread
DEBUG_FLAGS=-D DEBUG

num_threads=7
DEFINE_FLAGS=-D NUM_THREADS=$(num_threads)

czarrapo: src/*.c
	$(CC) $(CFLAGS) $(DEFINE_FLAGS) $? $(LDFLAGS) -o bin/czarrapo

debug: src/*.c
	$(CC) $(CFLAGS) $(DEFINE_FLAGS) $(DEBUG_FLAGS) $? $(LDFLAGS) -o bin/czarrapo

testfile:
	bash test/generate_test_file.bash

clean:
	rm -f bin/czarrapo
	rm -f test/czarrapo_rsa test/czarrapo_rsa.pub
	rm -f test/test.txt test/test.crypt test/test.decrypt
