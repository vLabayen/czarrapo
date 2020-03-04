
/* Standard library */
#include <stdlib.h>
#include <stdbool.h>

/* OpenSSL */
 #include <openssl/opensslv.h>

/* Internal modules */
#include "crrapo.h"
#include "rsa.h"
#include "encrypt.h"

void main(int argc, char* argv[]) {

	DEBUG_PRINT(("Using %s\n", OPENSSL_VERSION_TEXT));

	/* Keypair generation */
	char* passphrase = "asdf";
	char* directory = "test/";
	generate_RSA_pair_to_files(passphrase, directory, "crrapo_rsa", 4096);

	/* File encryption */
	char* plaintext_file = "test/test.txt";
	char* encrypted_file = "test/test.enc";
	char* public_key = "test/crrapo_rsa.pub";
	size_t block_size = 512;
	char* password = "1234";
	int selected_block = -1;
	bool fast = true;
	encrypt_file(plaintext_file, encrypted_file, block_size, password, public_key, selected_block, fast);
}
