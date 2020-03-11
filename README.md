# czarrapo #

## Description ##
czarrapo is a file encryption algorithm which uses RSA, AES and several hashing functions underneath. It solves the problem of delivering a symmetric key to encrypt/decrypt files, and also avoids using asymmetric ciphers for great amounts of bytes, which can in turn become slow.

## Compiling and running ##
NOTE: run everything from the project root directory as indicated, since relative file paths are being used.
Compile: `sh make.sh`\
Create random file to run program on: `bash test/generate_big_file.sh`\
Run: `bin/crrapo`\
