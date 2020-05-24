#ifndef _CZDECRYPT_H
#define _CZDECRYPT_H

#include "context.h"

/*
 * Deciphers a file into a plaintext file. Needs a context, and optionally takes a manually selected block to use during
 * decryiption. It needs to be the same block selected during encryption. This value can be -1 so the block is found
 * manually.
 * RETURNS: zero on success, negative value on error.
 */
int czarrapo_decrypt(CzarrapoContext* ctx, const char* encrypted_file, const char* decrypted_file, long long int selected_block_index);

#endif