#include <string.h>

/* OpenSSL */
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#include "common.h"
#include "rsa.h"

int generate_RSA_pair_to_files(char* passphrase, const char* directory, const char* key_name, int keylen) {
	RSA* rsa;						/* RSA struct */
	BIGNUM* e;						/* Public exponent */
	FILE* fp;						/* File handle for output files*/
	int dirlen = strlen(directory) + strlen(key_name) + 1;			/* Output directory length */

	/* Private key file name */
	char privfile[dirlen];
	snprintf(privfile, sizeof(privfile), "%s%s", directory, key_name);

	/* Public key file name */
	char pubfile[dirlen + 4];
	snprintf(pubfile, sizeof(pubfile), "%s%s.pub", directory, key_name);

	/* Initialize RSA struct */
	if ( (rsa = RSA_new()) == NULL) {
		return ERR_FAILURE;
	}

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
	fp = fopen(privfile, "w");
	if (PEM_write_RSAPrivateKey(fp, rsa, EVP_aes_256_cbc(), (unsigned char*) passphrase, strlen(passphrase), NULL, NULL) == 0) {
		RSA_free(rsa);
		BN_clear_free(e);
		fclose(fp);
		return ERR_FAILURE;
	}
	fclose(fp);

	/* Save public key */
	fp = fopen(pubfile, "w");
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