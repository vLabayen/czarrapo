#!/bin/sh

if [ "$1" = "nodebug" ]; then
	debug=""
else
	debug="-DDEBUG"
fi

gcc src/main.c src/common.c src/context.c src/rsa.c src/encrypt.c src/decrypt.c -o bin/czarrapo -lcrypto -lssl -lm -O3 -Wall $debug -std=c99
