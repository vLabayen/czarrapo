#include <stdbool.h>

#include <openssl/rsa.h>

typedef struct {
	RSA* public_rsa;
	RSA* private_rsa;
	char* password;
	bool fast;
} CzarrapoContext;

CzarrapoContext* czarrapo_init(const char* public_key_file, const char* private_key_file, const char* passphrase, const char* password, bool fast_mode);

void czarrapo_free(CzarrapoContext* ctx);