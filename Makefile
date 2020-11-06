CC=gcc

num_threads=7
test_file_size=1M

CFLAGS=-Wall -Wpedantic -std=c11 -O3 -fPIC -D NUM_THREADS=$(num_threads) -I ./lib -z noexecstack -fstack-protector -D_FORTIFY_SOURCE=2 $(flags)
LDFLAGS=-lcrypto -lssl -lm -pthread
SO_FLAGS=-fPIC -shared

# Our compiled objects
OBJECTS = bin/common.o bin/context.o bin/decrypt.o bin/encrypt.o bin/rsa.o bin/thread.o
OBJ_MAIN = bin/main.o
# Our generated libraries
STATIC_LIB = libczarrapo.a
SHARED_LIB = libczarrapo.so
# Libraries we depend on
SUBMODULES = lib/tlock-queue/libtlockqueue.a
# Temporary script used to bundle all of our dependencies into our static library
ARSCRIPT = ar.script

.PHONY =  static shared submodules all update-submodules testfile clean

bin/%.o: src/%.c
	$(CC) $(CFLAGS) -c $^ -o $@

czarrapo: $(OBJ_MAIN) static submodules
	$(CC) -fPIE $< $(STATIC_LIB) -o $@ $(LDFLAGS)

static: $(OBJECTS) submodules
	echo "CREATE $(STATIC_LIB)" > $(ARSCRIPT)
	for dependency in $(SUBMODULES); do (echo "ADDLIB $$dependency" >> $(ARSCRIPT)); done
	echo "ADDMOD $(OBJECTS)" >> $(ARSCRIPT)
	echo "SAVE" >> $(ARSCRIPT)
	echo "END" >> $(ARSCRIPT)
	ar -M < $(ARSCRIPT)
	rm $(ARSCRIPT)

shared: $(OBJECTS) submodules
	$(CC) $(SO_FLAGS) $(OBJECTS) $(SUBMODULES) $(LDFLAGS) -o $(SHARED_LIB)

submodules:
	cd lib/tlock-queue && make static

all: static shared czarrapo

update-submodules:
	git submodule update --remote

testfile:
	bash test/generate_file.bash $(test_file_size) "test/test.txt"
	ls -lh test/test.txt

clean:
	rm -f test/czarrapo_rsa test/czarrapo_rsa.pub
	rm -f test/test.*
	rm -f $(OBJECTS) $(OBJ_MAIN)
	rm -f $(STATIC_LIB) $(SHARED_LIB)
	rm -f czarrapo
	cd lib/tlock-queue && make clean


