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

CzarrapoContext* czarrapo_copy(const CzarrapoContext* ctx) {
	CzarrapoContext* new_ctx;

	if ( (new_ctx = malloc(sizeof(CzarrapoContext))) == NULL)
		return NULL;

	/* Copy fast mode flag */
	new_ctx->fast = ctx->fast;

	/* Copy password */
	if (ctx->password == NULL) {
		czarrapo_free(new_ctx);
		return NULL;
	}
	if ( (new_ctx->password = malloc(MAX_PASSWORD_LENGTH)) == NULL) {
		czarrapo_free(new_ctx);
		return NULL;
	}
	strncpy(new_ctx->password, ctx->password, MAX_PASSWORD_LENGTH);

	/* Copy public key */
	if (ctx->public_rsa != NULL) {
		if ( (new_ctx->public_rsa = RSAPublicKey_dup(ctx->public_rsa)) == NULL){
			czarrapo_free(new_ctx);
			return NULL;
		}
	} else {
		new_ctx->public_rsa = NULL;
	}

	/* Copy private key */
	if (ctx->private_rsa != NULL) {
		if ( (new_ctx->private_rsa = RSAPrivateKey_dup(ctx->private_rsa)) == NULL){
			czarrapo_free(new_ctx);
			return NULL;
		}
	} else {
		new_ctx->private_rsa = NULL;
	}

	return new_ctx;
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
