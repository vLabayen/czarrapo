#!/bin/sh

if [ "$1" = "nodebug" ]; then
	debug=""
else
	debug="-DDEBUG"
fi

gcc src/czarrapo.c src/rsa.c src/encrypt.c -o bin/czarrapo -lcrypto -lssl -lm -O3 $debug
