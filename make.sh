#!/bin/sh

if [ "$1" = "nodebug" ]; then
	debug=""
else
	debug="-DDEBUG"
fi

gcc src/main.c src/common.c src/context.c src/rsa.c src/encrypt.c src/decrypt.c src/thread.c \
-o bin/czarrapo \
-lcrypto -lssl -lm -pthread \
-O3 -flto -std=c11 \
$debug \
-fPIE -Wall

