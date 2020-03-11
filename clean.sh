#!/bin/sh
echo "Removing RSA keypair"
rm -f test/czarrapo_rsa test/czarrapo_rsa.pub

echo "Removing input/output test files"
rm -f test/test.txt test/test.enc test/test.dec

echo "Removing compiled binary"
rm -f bin/czarrapo
