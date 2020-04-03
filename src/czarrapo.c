
/* Standard library */
#include <stdlib.h>

/* OpenSSL */
 #include <openssl/opensslv.h>

/* Internal modules */
#include "czarrapo.h"
#include "rsa.h"
#include "encrypt.h"
#include "decrypt.h"

int main(int argc, char* argv[]) {

	DEBUG_PRINT(("[DEBUG] Using %s\n", OPENSSL_VERSION_TEXT));

	/* Keypair generation */
	char* passphrase = "asdf";
	/*char* rsa_directory = "test/";
	DEBUG_PRINT(("[GENERATING RSA KEYPAIR]\n"));
	generate_RSA_pair_to_files(passphrase, rsa_directory, "czarrapo_rsa", 4096);
	*/

	/* File encryption */
	char* plaintext_file = "test/test.txt";
	char* encrypted_file = "test/test.enc";
	char* public_key = "test/czarrapo_rsa.pub";
	char* password = "1234";
	int selected_block = 7;
	bool fast = false;
	DEBUG_PRINT(("[STARTING ENCRYPTION ROUTINE]\n"));
	encrypt_file(plaintext_file, encrypted_file, password, public_key, selected_block, fast);

	/* File decryption */
	char* decrypted_file = "test/test.dec";
	char* private_key = "test/czarrapo_rsa";
	DEBUG_PRINT(("[STARTING DECRYPTION ROUTINE]\n"));
	decrypt_file(encrypted_file, decrypted_file, password, private_key, passphrase, selected_block);

	return 0;
}

