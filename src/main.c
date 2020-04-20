/* Standard library */
#include <stdio.h>

/* Internal modules */
#include "common.h"		// DEBUG_PRINT() definition
#include "rsa.h"		// generate_RSA_pair_to_files()
#include "context.h"		// czarrapo_init() and czarrapo_free()
#include "encrypt.h"		// czarrapo_encrypt()
#include "decrypt.h"		// czarrapo_decrypt()

/* Sample error handling function */
void handle_error(CzarrapoContext* ctx) {
	printf("Error\n");
	czarrapo_free(ctx);
	exit(1);
}

int main() {

	CzarrapoContext* ctx;
	char* passphrase = "asdf";
	char* password = "1234";
	bool fast_mode = false;

	/* Generate keypair */
	DEBUG_PRINT(("[GENERATING RSA KEYPAIR]\n"));
	if (generate_RSA_pair_to_files(passphrase, "test/", "czarrapo_rsa", 4096) < 0) {
		handle_error(NULL);
	}

	/* Initialize context */
	DEBUG_PRINT(("[INITIALIZING CONTEXT]\n"));
	if ( (ctx = czarrapo_init("test/czarrapo_rsa.pub", "test/czarrapo_rsa", passphrase, password, fast_mode)) == NULL )
		handle_error(NULL);

	/* Encrypt file */
	DEBUG_PRINT(("[STARTING ENCRYPTION ROUTINE]\n"));
	if (czarrapo_encrypt(ctx, "test/test.txt", "test/test.crypt", -1) < 0)
		handle_error(ctx);

	/* Decrypt file */
	DEBUG_PRINT(("[STARTING DECRYPTION ROUTINE]\n"));
	if (czarrapo_decrypt(ctx, "test/test.crypt", "test/test.decrypt", -1) < 0)
		handle_error(ctx);

	/* Free up resources */
	czarrapo_free(ctx);

	return 0;
}
