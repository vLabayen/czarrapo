#!/bin/bash
openssl rand -out test/test.txt -base64 $(( 2**22 * 3/4 )) && ls -lh test/test.txt
