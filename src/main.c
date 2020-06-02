/* Standard library */
#include <stdio.h>

/* Internal modules */
#include "rsa.h"		// generate_RSA_pair_to_files()
#include "context.h"		// czarrapo_init() and czarrapo_free()
#include "encrypt.h"		// czarrapo_encrypt()
#include "decrypt.h"		// czarrapo_decrypt()

/* Sample error handling function */
static void handle_error(CzarrapoContext* ctx) {
	printf("Error\n");
	czarrapo_free(ctx);
	exit(1);
}

int main() {

	CzarrapoContext* ctx;
	char* passphrase = "asdf";
	char* password = "1234";
	bool fast_mode = true;

	/* Generate keypair */
	/*printf("[GENERATING RSA KEYPAIR]\n");
	if (generate_RSA_pair_to_files(passphrase, "test/", "czarrapo_rsa", 4096) < 0) {
		handle_error(NULL);
	}*/

	/* Initialize context */
	printf("[INITIALIZING CONTEXT]\n");
	if ( (ctx = czarrapo_init("test/czarrapo_rsa.pub", "test/czarrapo_rsa", passphrase, password, fast_mode)) == NULL )
		handle_error(NULL);

	/* Encrypt file */
	printf("[STARTING ENCRYPTION ROUTINE]\n");
	if (czarrapo_encrypt(ctx, "test/test.txt", "test/test.crypt", -1) < 0)
		handle_error(ctx);

	/* Decrypt file */
	printf("[STARTING DECRYPTION ROUTINE]\n");
	if (czarrapo_decrypt(ctx, "test/test.crypt", "test/test.decrypt", -1) < 0)
		handle_error(ctx);

	/* Free up resources */
	czarrapo_free(ctx);

	return 0;
}
