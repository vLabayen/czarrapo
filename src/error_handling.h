
/*
 * This file contains declarations for functions to be used internally
 * when handling errors. 'exit_on_handle' just serves as a flag to call
 * exit(1) at the end of the function. Arguments to the right of
 * 'exit_on_handle' are to be freed or closed accordingly 
 * /

/* Standard library */
#include <stdio.h>
#include <stdbool.h>

/* OpenSSL */
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#define ERR_MSG_BUF_SIZE	120

void _handle_simple_error(const char* msg);

/* Function to be called to handle errors when opening, writing or reading from file */
void _handle_file_action_error(const char* msg, bool exit_on_handle, FILE* fp);

/* Function to be called RSA operation errors. */
void _handle_RSA_error(const char* msg, bool exit_on_handle, RSA* rsa, BIGNUM* e, FILE* fp, EVP_PKEY* pkey, EVP_PKEY_CTX* pkey_ctx);

/* Function to be called during hashing errors. */
void _handle_EVP_MD_error(const char* msg, bool exit_on_handle, EVP_MD_CTX* evp_ctx);

/* Function to be called during symmetric cipher errors */
void _handle_EVP_CIPHER_error(const char* msg, bool exit_on_handle, EVP_CIPHER_CTX* evp_ctx, FILE* f1, FILE* f2);
