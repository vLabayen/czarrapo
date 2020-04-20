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

/* Context initialization */
CzarrapoContext* czarrapo_init(const char* public_key_file, const char* private_key_file, const char* passphrase, const char* password, bool fast_mode);

/* Free context and zero out password */
void czarrapo_free(CzarrapoContext* ctx);

#endif
