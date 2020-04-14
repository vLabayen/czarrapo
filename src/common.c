
#include <openssl/evp.h>

#include "common.h"

long int _get_file_size(const char* filename) {
	FILE* fp;
	long int file_size;

	if ( (fp = fopen(filename, "rb")) == NULL ) {
		return ERR_FAILURE;
	}
	if (fseek(fp, 0, SEEK_END) != 0) {
		return ERR_FAILURE;
	}
	file_size = ftell(fp);
	fclose(fp);

	return file_size;
}

int _hash_individual_block(unsigned char* output, const unsigned char* input, int input_size, const char* hash_name) {
	EVP_MD_CTX* evp_ctx;					/* EVP hashing context struct */
	const EVP_MD* hash_type;				/* Selected hash type for encryption block*/

	if ( (hash_type = EVP_get_digestbyname(hash_name)) == NULL) {
		return ERR_FAILURE;
	}

	if ( (evp_ctx = EVP_MD_CTX_new()) == NULL ) {
		EVP_MD_CTX_free(evp_ctx);
		return ERR_FAILURE;
	}
	if ( (EVP_DigestInit_ex(evp_ctx, hash_type, NULL)) != 1) {
		EVP_MD_CTX_free(evp_ctx);
		return ERR_FAILURE;
	}
	if ( (EVP_DigestUpdate(evp_ctx, input, input_size)) != 1 ) {
		EVP_MD_CTX_free(evp_ctx);
		return ERR_FAILURE;
	}
	if ( (EVP_DigestFinal_ex(evp_ctx, output, NULL)) != 1) {
		EVP_MD_CTX_free(evp_ctx);
		return ERR_FAILURE;
	}

	EVP_MD_CTX_free(evp_ctx);
	return 0;
}

void _hexarr(const unsigned char* arr, int len) {
	for (int j=0; j<len; ++j) {
		printf("%x ", arr[j]);
	}
	printf("\n");
}