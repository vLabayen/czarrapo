#!/bin/bash
openssl rand -out test/test.txt -base64 $(( 2**15 * 3/4 )) && ls -lh test/test.txt
