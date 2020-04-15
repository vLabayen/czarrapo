#!/bin/sh

if [ "$1" = "nodebug" ]; then
	debug=""
else
	debug="-DDEBUG"
fi

gcc src/main.c src/common.c src/context.c src/rsa.c src/encrypt.c src/decrypt.c \
-o bin/czarrapo \
-lcrypto -lssl -lm \
-Ofast -flto -std=c99 \
$debug \
-fPIE -Wall
