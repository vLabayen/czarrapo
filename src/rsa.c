
/* Standard library */
#include <stdio.h>
#include <string.h>

/* OpenSSL */
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

/* Internal modules */
#include "czarrapo.h"
#include "rsa.h"

#define MAX_DIRECTORY_SIZE 60

static void _handle_RSA_error(char* msg, RSA* rsa, BIGNUM* e, FILE* fp) {
	printf("%s\n", msg);
	RSA_free(rsa);
	BN_free(e);
	fclose(fp);
	exit(1);
}

void generate_RSA_pair_to_files(char* passphrase, char* directory, char* key_name, int keylen) {

	RSA* rsa;									// RSA struct
	BIGNUM* e;									// Public exponent
	char output_file[MAX_DIRECTORY_SIZE];		// Buffer to store key output path
	FILE* fp;									// File descriptor to write files
	int n_chars_written;						// Variable to check if output directory fits in our buffer

	/* Initialize RSA struct */
	rsa = RSA_new();

	/* Initialize public exponent */
	e = BN_new();
	if ( !(BN_set_word(e, RSA_F4)) ) {
		_handle_RSA_error("Error: BN_set_word()", rsa, e, NULL);
	}

	/* Generate keys */
	DEBUG_PRINT(("[DEBUG] Generating RSA keypair\n"));
	if ( !RSA_generate_key_ex(rsa, keylen, e, NULL)){
		_handle_RSA_error("Error: RSA_generate_key_ex()", rsa, e, NULL);
	}

	/* Save private key */
	n_chars_written = sprintf(output_file, "%s%s", directory, key_name);
	if ( n_chars_written < 0 || n_chars_written > MAX_DIRECTORY_SIZE ) {
		_handle_RSA_error("Error: RSA keypair output directory too long", rsa, e, NULL);
	}
	DEBUG_PRINT(("[DEBUG] Saving private key to %s\n", output_file));

	fp = fopen(output_file, "w");
	if ( !PEM_write_RSAPrivateKey(fp, rsa, EVP_aes_256_cbc(), passphrase, strlen(passphrase), NULL, NULL)) {
		_handle_RSA_error("Error: could not write private key to file.", rsa, e, fp);
	}
	fclose(fp);

	/* Save public key*/
	n_chars_written = sprintf(output_file, "%s%s%s", directory, key_name, ".pub");
	if ( n_chars_written < 0 || n_chars_written > MAX_DIRECTORY_SIZE ) {
		_handle_RSA_error("Error: RSA keypair output directory too long\n", rsa, e, NULL);
	}
	DEBUG_PRINT(("[DEBUG] Saving public key to %s\n", output_file));

	fp = fopen(output_file, "w");
	if ( !PEM_write_RSAPublicKey(fp, rsa) ){
		_handle_RSA_error("Error: could not write public key to file.", rsa, e, fp);
	}
	fclose(fp);

	/* Free variables */
	RSA_free(rsa);
	BN_free(e);
}