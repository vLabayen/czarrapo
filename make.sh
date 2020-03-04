#!/bin/sh

if [ "$1" = "nodebug" ]; then
	debug=""
else
	debug="-DDEBUG"
fi

gcc src/crrapo.c src/rsa.c src/encrypt.c -o bin/crrapo -lcrypto -lssl -lm -O3 $debug
