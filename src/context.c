/* Standard library */
#include <stdio.h>
#include <string.h>

/* OpenSSL */
#include <openssl/pem.h>

/* Internal modules */
#include "common.h"
#include "context.h"

/* Loads a public key into an RSA* struct */
static RSA* _load_public_key(const char* public_key_file) {
	RSA* rsa;
	FILE* pk;

	/* Allocate RSA struct */
	if ( (rsa = RSA_new()) == NULL ){
		return NULL;
	}

	/* Read public key from file, assign to RSA struct and close file */
	if ( (pk = fopen(public_key_file, "r")) == NULL ) {
		RSA_free(rsa);
		return NULL;
	}
	if ( (rsa = PEM_read_RSAPublicKey(pk, &rsa, NULL, NULL)) == NULL ) {
		fclose(pk);
		RSA_free(rsa);
		return NULL;
	}
	DEBUG_PRINT(("[DEBUG] Public key at %s read correctly.\n", public_key_file));

	fclose(pk);
	return rsa;
}

/* Loads a private key into an RSA* struct, using a passphrase */
static RSA* _load_private_key(const char* private_key_file, const char* passphrase) {
	RSA* rsa;
	FILE *pk;

	/* Allocate RSA struct */
	if ( (rsa = RSA_new()) == NULL ){
		return NULL;
	}

	/* Read private key from file, assign to RSA struct and close file */
	if ( (pk = fopen(private_key_file, "r")) == NULL ) {
		RSA_free(rsa);
		return NULL;
	}
	if ( (rsa = PEM_read_RSAPrivateKey(pk, &rsa, NULL, (void*) passphrase)) == NULL ) {
		fclose(pk);
		RSA_free(rsa);
		return NULL;
	}
	DEBUG_PRINT(("[DEBUG] Private key at %s read correctly.\n", private_key_file));

	fclose(pk);
	return rsa;
}

/* Returns an initialized context struct based on input parameters */
CzarrapoContext* czarrapo_init(const char* public_key_file, const char* private_key_file, const char* passphrase, const char* password, bool fast_mode) {
	CzarrapoContext* ctx;

	/* Allocate initial struct */
	if ((ctx = malloc(sizeof(CzarrapoContext))) == NULL) {
		return NULL;
	}

	/* Load cipher mode */
	ctx->fast = fast_mode;

	/* Load password - strncpy() fills remaining space with zeros */
	if (password == NULL) {
		czarrapo_free(ctx);
		return NULL;
	}
	if ( (ctx->password = malloc(MAX_PASSWORD_LENGTH)) == NULL ) {
		czarrapo_free(ctx);
		return NULL;
	}
	strncpy(ctx->password, password, MAX_PASSWORD_LENGTH);

	/* Load public key */
	if (public_key_file != NULL) {
		if ( (ctx->public_rsa = _load_public_key(public_key_file)) == NULL ){
			czarrapo_free(ctx);
			return NULL;
		}
	} else {
		ctx->public_rsa = NULL;
	}

	/* Load private key */
	if (private_key_file != NULL) {
		if ( (ctx->private_rsa = _load_private_key(private_key_file, passphrase)) == NULL ) {
			czarrapo_free(ctx);
			return NULL;
		}
	} else {
		ctx->private_rsa = NULL;
	}

	return ctx;

}

/* Frees the context struct and zeroes out the password */
void czarrapo_free(CzarrapoContext* ctx) {
	if (ctx != NULL) {
		RSA_free(ctx->public_rsa);
		RSA_free(ctx->private_rsa);

		if (ctx->password != NULL) {
			memset(ctx->password, 0, MAX_PASSWORD_LENGTH);
			free(ctx->password);
		}

		free(ctx);
	}
}
