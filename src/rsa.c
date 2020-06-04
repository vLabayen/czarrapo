#include <string.h>

/* OpenSSL */
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#include "common.h"
#include "rsa.h"

int generate_RSA_keypair(char* passphrase, const char* pubkey, const char* privkey, int keylen) {
	RSA* rsa;						/* RSA struct */
	BIGNUM* e;						/* Public exponent */
	FILE* fp;

	/* Initialize RSA struct */
	if ( (rsa = RSA_new()) == NULL)
		return ERR_FAILURE;

	/* Initialize public exponent */
	if ( (e = BN_new()) == NULL ) {
		RSA_free(rsa);
		return ERR_FAILURE;
	}
	if ( !(BN_set_word(e, RSA_F4)) ) {
		RSA_free(rsa);
		BN_clear_free(e);
		return ERR_FAILURE;
	}

	/* Generate keys */
	if ( RSA_generate_key_ex(rsa, keylen, e, NULL) == 0 ){
		RSA_free(rsa);
		BN_clear_free(e);
		return ERR_FAILURE;
	}

	/* Save private key */
	fp = fopen(privkey, "w");
	if (PEM_write_RSAPrivateKey(fp, rsa, EVP_aes_256_cbc(), (unsigned char*) passphrase, strlen(passphrase), NULL, NULL) == 0) {
		RSA_free(rsa);
		BN_clear_free(e);
		fclose(fp);
		return ERR_FAILURE;
	}
	fclose(fp);

	/* Save public key */
	fp = fopen(pubkey, "w");
	if (PEM_write_RSAPublicKey(fp, rsa) == 0) {
		RSA_free(rsa);
		BN_clear_free(e);
		fclose(fp);
		return ERR_FAILURE;
	}
	fclose(fp);

	/* Free variables */
	RSA_free(rsa);
	BN_clear_free(e);

	return 0;
}
