#!/bin/bash
openssl rand -out test/test.txt -base64 $(( 2**30 * 3/4 )) && ls -lh test/test.txt
