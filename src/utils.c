
/* OpenSSL */
#include <openssl/evp.h>

/* Internal modules */
#include "utils.h"
#include "error_handling.h"

void _print_hex_array(unsigned char* arr, size_t len){
	for (int j=0; j<len; ++j) {
		printf("%x ", arr[j]);
	}
	printf("\n");
}

void _hash_individual_block(unsigned char* block_hash, const unsigned char* input, int input_size, const char* hash_name) {
	EVP_MD_CTX* evp_ctx;					/* EVP hashing context struct */
	EVP_MD* hash_type = EVP_get_digestbyname(hash_name);	/* Selected hash type for encryption block*/

	if ( (evp_ctx = EVP_MD_CTX_new()) == NULL ) {
		_handle_EVP_MD_error("[ERROR] Could not allocate hashing context.", true, NULL);
	}
	if ( (EVP_DigestInit_ex(evp_ctx, hash_type, NULL)) != 1) {
		_handle_EVP_MD_error("[ERROR] Could not init EVP hashing context.", true, evp_ctx);
	}
	if ( (EVP_DigestUpdate(evp_ctx, input, input_size)) != 1 ) {
		_handle_EVP_MD_error("[ERROR] Could not update EVP context.", true, evp_ctx);
	}
	if ( (EVP_DigestFinal_ex(evp_ctx, block_hash, NULL)) != 1) {
		_handle_EVP_MD_error("[ERROR] Could not retrieve hash for encryption block.", true, evp_ctx);
	}
	EVP_MD_CTX_free(evp_ctx);
}

bool _ispowerof2(unsigned int x) {
	return x && !(x & (x - 1));
}

size_t _get_file_size(char* filename) {

	FILE* fp;
	size_t file_size;

	if ( (fp = fopen(filename, "rb")) == NULL ) {
		char err_msg[ERR_MSG_BUF_SIZE];
		sprintf(err_msg, "Error opening file %s.\n", filename);
		_handle_simple_error(err_msg);
	}
	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	fclose(fp);

	return file_size;

}