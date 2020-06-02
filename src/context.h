#ifndef _CZCONTEXT_H
#define _CZCONTEXT_H

#include <stdbool.h>

#include <openssl/rsa.h>

#define MAX_PASSWORD_LENGTH 30

/* Context struct to be passed to API functions */
typedef struct {
	RSA* public_rsa;
	RSA* private_rsa;
	char* password;
	bool fast;
} CzarrapoContext;

/*
 * Initializes an encryption/decryption context. The private key can be omitted for only-encryption operations; the
 * public key can be omitted for only-decryption operations. Uses a passphrase to open the private key, and a user
 * password to perform file cipher operations. The context returned must be freed by the caller with czarrapo_free().
 * RETURNS: a pointer to a CzarrapoContext struct on success, NULL on failure.
 */
CzarrapoContext* czarrapo_init(const char* public_key_file, const char* private_key_file, const char* passphrase, const char* password, bool fast_mode);

/*
 * Performs a deep copy on an encryption/decryption context. The context returned must be freed by the caller with
 * czarrapo_free().
 * RETURNS: a pointer to an identical copy of the original context, NULL on failure.
 */
CzarrapoContext* czarrapo_copy(const CzarrapoContext* ctx);

/*
 * Frees a context struct and zeroes-out the user password.
 * RETURNS: nothing.
 */
void czarrapo_free(CzarrapoContext* ctx);

#endif
