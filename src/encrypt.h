#ifndef _CZENCRYPT_H
#define _CZENCRYPT_H

#include "context.h"

#define NUM_RANDOM_BLOCKS	100

/*
 * Ciphers a plaintext file into an ecnrypted file. Needs a context, and optionally takes a manually selected block
 * index to use during encryption. The block index can be set to a negative value so it is selected automatically.
 * RETURNS: zero on success, negative value on error.
 */
int czarrapo_encrypt(CzarrapoContext* ctx, const char* plaintext_file, const char* encrypted_file, long long int selected_block_index);

#endif