#ifndef _CZDECRYPT_H
#define _CZDECRYPT_H

#include "context.h"

int czarrapo_decrypt(CzarrapoContext* ctx, const char* encrypted_file, const char* decrypted_file, long long int selected_block_index);

#endif