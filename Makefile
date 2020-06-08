CC=gcc

num_threads=7
test_file_size=1M

CFLAGS=-O3 -std=c11 -Wall -Wpedantic -D NUM_THREADS=$(num_threads) -z noexecstack -fstack-protector -D_FORTIFY_SOURCE=2
LDFLAGS=-lcrypto -lssl -lm -pthread

BIN_FLAGS=-fPIE
SO_FLAGS=-fPIC -shared
DEBUG_FLAGS=-g -D DEBUG

LIBPATH=src/tlock-queue/bin/tlock_queue.a

czarrapo: submodules
	$(CC) $(CFLAGS) $(BIN_FLAGS) src/*.c $(LIBPATH) $(LDFLAGS) -o bin/czarrapo

debug: submodules
	$(CC) $(CFLAGS) $(DEBUG_FLAGS) src/*.c $(LIBPATH) $(LDFLAGS) -o bin/czarrapo

shared: submodules
	$(CC) $(CFLAGS) $(SO_FLAGS) \
	src/common.c src/decrypt.c src/thread.c src/context.c src/encrypt.c src/rsa.c $(LIBPATH) \
	$(LDFLAGS) -o bin/czarrapo.so

all: czarrapo shared

submodules:
	cd src/tlock-queue && make static

update-submodules:
	git submodule update --remote

testfile:
	bash test/generate_file.bash $(test_file_size) "test/test.txt"
	ls -lh test/test.txt

clean:
	rm -f bin/czarrapo.*
	rm -f test/czarrapo_rsa test/czarrapo_rsa.pub
	rm -f test/test.txt test/test.crypt test/test.decrypt
