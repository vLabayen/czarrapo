#ifndef _CZRSA_H
#define _CZRSA_H

/*
 * Generates RSA public and private keys with the specified passphrase. Saves them to directory/key_name and
 * directory/key_name.pub
 * RETURNS: zero on success, negative value on error.
 */
int generate_RSA_pair_to_files(char* passphrase, const char* directory, const char* key_name, int keylen);

#endif
