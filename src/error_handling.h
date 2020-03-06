
/* Standard library */
#include <stdio.h>
#include <stdbool.h>

/* OpenSSL */
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

void _handle_file_action_error(const char* msg, bool exit_on_handle, FILE* fp);

void _handle_RSA_error(const char* msg, bool exit_on_handle, RSA* rsa, BIGNUM* e, FILE* fp, EVP_PKEY* pkey, EVP_PKEY_CTX* pkey_ctx);

void _handle_EVP_MD_error(const char* msg, bool exit_on_handle, EVP_MD_CTX* evp_ctx);

void _handle_EVP_CIPHER_error(const char* msg, bool exit_on_handle, EVP_CIPHER_CTX* evp_ctx, FILE* f1, FILE* f2);
