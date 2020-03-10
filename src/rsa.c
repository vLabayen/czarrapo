
/* Standard library */
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

/* OpenSSL */
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

/* Internal modules */
#include "czarrapo.h"
#include "rsa.h"
#include "error_handling.h"

#define MAX_DIRECTORY_SIZE 60

void generate_RSA_pair_to_files(char* passphrase, char* directory, char* key_name, int keylen) {
	RSA* rsa;					/* RSA struct */
	BIGNUM* e;					/* Public exponent */
	char output_file[MAX_DIRECTORY_SIZE];		/* Buffer to store key output path */
	FILE* fp;					/* File descriptor to write files */
	int n_chars_written;				/* Variable to check if output directory fits in our buffer */

	/* Initialize RSA struct */
	if ( (rsa = RSA_new()) == NULL) {
		_handle_RSA_error("Error: could not allocate RSA struct.\n", true, NULL, NULL, NULL, NULL, NULL);
	}

	/* Initialize public exponent */
	if ( (e = BN_new()) == NULL ) {
		_handle_RSA_error("Error: could not allocate BIGNUM struct.\n", true, rsa, NULL, NULL, NULL, NULL);
	}
	if ( !(BN_set_word(e, RSA_F4)) ) {
		_handle_RSA_error("Error: BN_set_word().\n", true, rsa, e, NULL, NULL, NULL);
	}

	/* Generate keys */
	DEBUG_PRINT(("[DEBUG] Generating RSA keypair\n"));
	if ( RSA_generate_key_ex(rsa, keylen, e, NULL) == 0 ){
		_handle_RSA_error("Error: Could not generate RSA keypair.\n", true, rsa, e, NULL, NULL, NULL);
	}

	/* Save private key */
	n_chars_written = sprintf(output_file, "%s%s", directory, key_name);
	if ( n_chars_written < 0 || n_chars_written > MAX_DIRECTORY_SIZE ) {
		_handle_RSA_error("Error: RSA keypair output directory too long.\n", true, rsa, e, NULL, NULL, NULL);
	}

	DEBUG_PRINT(("[DEBUG] Saving private key to %s\n", output_file));
	fp = fopen(output_file, "w");
	if ( !PEM_write_RSAPrivateKey(fp, rsa, EVP_aes_256_cbc(), passphrase, strlen(passphrase), NULL, NULL)) {
		_handle_RSA_error("Error: could not write private key to file.\n", true, rsa, e, fp, NULL, NULL);
	}
	fclose(fp);

	/* Save public key*/
	n_chars_written = sprintf(output_file, "%s%s%s", directory, key_name, ".pub");
	if ( n_chars_written < 0 || n_chars_written > MAX_DIRECTORY_SIZE ) {
		_handle_RSA_error("Error: RSA keypair output directory too long.\n", true, rsa, e, NULL, NULL, NULL);
	}

	DEBUG_PRINT(("[DEBUG] Saving public key to %s\n", output_file));
	fp = fopen(output_file, "w");
	if ( !PEM_write_RSAPublicKey(fp, rsa) ){
		_handle_RSA_error("Error: could not write public key to file.", true, rsa, e, fp, NULL, NULL);
	}
	fclose(fp);

	/* Free variables */
	RSA_free(rsa);
	BN_clear_free(e);
}
