#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

/* Generate a keypair and save to directory/key_name[.pub] */
void generate_RSA_pair_to_files(char* passphrase, char* directory, char* key_name, int keylen);