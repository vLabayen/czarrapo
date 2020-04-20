#ifndef _CZENCRYPT_H
#define _CZENCRYPT_H

#include "context.h"

#define NUM_RANDOM_BLOCKS	5

int czarrapo_encrypt(CzarrapoContext* ctx, const char* plaintext_file, const char* encrypted_file, long long int selected_block_index);

#endif