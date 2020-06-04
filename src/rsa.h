#ifndef _CZRSA_H
#define _CZRSA_H

/*
 * Generates RSA public and private keys with the specified passphrase. Keylen is the RSA modulus size.
 * RETURNS: zero on success, negative value on error.
 */
int generate_RSA_keypair(char* passphrase, const char* pubkey, const char* privkey, int keylen);

#endif
