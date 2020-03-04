
/* Standard library */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>

/* OpenSSL */
#include <openssl/evp.h>

/* Internal modules */
#include "crrapo.h"

#define NUM_RANDOM_BLOCKS 5
#define EARLY_BLOCK_SELECT_PARAM 2

static bool _ispowerof2(unsigned int x) {
   return x && !(x & (x - 1));
}

static void _handle_EVP_error(char* msg, EVP_MD_CTX* evp_ctx) {
	printf("%s\n", msg);
	EVP_MD_CTX_free(evp_ctx);
	exit(1);
}

static double _block_entropy(unsigned char* buf, size_t block_size) {

	/* Order bytes in input block */
	int i, j;
	char tmp;
	for (i = 0; i<block_size-1; ++i){
		for (j=i+1; j<block_size; ++j) {
			if (buf[i] > buf[j]) {
				tmp = buf[i];
				buf[i] = buf[j];
				buf[j] = tmp;
			}
		}
	}

	/* Find Shannon entropy for this block */
	int count = 0;
	double p;
	double entropy = 0.0;
	unsigned int prev_byte = buf[0];

	for (i = 0; i<block_size; ++i) {
		if (prev_byte == buf[i]) {
			++count;
		} else {
			p = (double) count / (double) block_size;
			entropy += p * log2(p);
			count = 1;
		}
		prev_byte = buf[i];
	}
	p = (double) count / (double) block_size;
	entropy += p * log2(p);

	return -entropy;

}

static unsigned int _select_block(char* plaintext_file, size_t block_size, long int num_blocks) {
	FILE* fp;							/* File handle */
	double block_entropy;				/* Entropy for current block */
	double max_entropy = -1;			/* Max. entropy seen */
	int i, random_index;				/* Loop variable and random access index */
	int selected_block_index = -1;		/* Index of max. entropy block */
	unsigned char block[block_size];	/* Current extracted block */
	
	fp = fopen(plaintext_file, "rb");
	for (i = 0; i<NUM_RANDOM_BLOCKS; ++i) {

		/* Get random block index */
		random_index = rand() % num_blocks;

		/* Get block with selected index */
		fseek(fp, (random_index) * block_size, SEEK_SET);
		fread(block, sizeof(unsigned char), block_size, fp);

		/* Get entropy for current block and update selected block */
		if ( (block_entropy = _block_entropy(block, block_size)) > max_entropy) {
			max_entropy = block_entropy;
			selected_block_index = random_index;
		}
		DEBUG_PRINT(("[DEBUG] Checking entropy for block %i: %f\n", random_index, block_entropy));
	}
	fclose(fp);
	return selected_block_index;
}

void encrypt_file(char* plaintext_file, char* encrypted_file, size_t block_size, char* password, char* public_key_file, unsigned int selected_block_index, bool fast) {

	FILE* fp;							/* File handle */
	size_t file_size, num_blocks;		/* Variables on the input file */
	size_t password_len = 0;			/* Length of input password */
	if (password != NULL) {
		password_len = strlen(password);
	}
	unsigned char selected_block[block_size + password_len];	/* Selected block for encryption */

	if (!_ispowerof2(block_size)) {
		printf("Error: block_size %li must be a power of 2\n", block_size);
		exit(1);
	}

	/* Get file size (platform independent) */
	if ( !(fp = fopen(plaintext_file, "rb")) ) {
		printf("Error opening file %s\n", plaintext_file);
		exit(1);
	}
	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	fclose(fp);
	DEBUG_PRINT(("[DEBUG] Selected %s for encryption, size of %li bytes.\n", plaintext_file, file_size));

	/* Get number of blocks in input file for current block size */
	num_blocks = file_size / block_size;
	if ( (file_size % block_size) > 0 ) {
		++num_blocks;
	}
	DEBUG_PRINT(("[DEBUG] Dividing file into %li blocks of size %lu.\n", num_blocks, block_size));

	/* Select random block if not already passed in */
	while (selected_block_index < 0 || selected_block_index > num_blocks) {
		srand(time(NULL));
		selected_block_index = _select_block(plaintext_file, block_size, num_blocks);
	}
	DEBUG_PRINT(("[DEBUG] Encryption block has offset %i\n", selected_block_index));

	/* Extract selected block */
	fp = fopen(plaintext_file, "rb");
	fseek(fp, selected_block_index*block_size, SEEK_SET);
	fread(selected_block, sizeof(unsigned char), block_size, fp);
	fclose(fp);

	/* Append password */
	memcpy(&selected_block[block_size], password, password_len);

	/* Hash block with SHA512 (this could be put into a separate function) */
	/* The function would look like: unsigned char* hash_block(block, blocksize, hash_type) */
	EVP_MD_CTX* evp_ctx;										/* EVP hashing context struct */
	EVP_MD* hash_type = EVP_get_digestbyname("SHA512");			/* Selected hash type for encryption block*/
	unsigned char block_hash[EVP_MD_size(hash_type)];			/* Output buffer for hash */

	if ( (evp_ctx = EVP_MD_CTX_new()) == NULL ) {
		_handle_EVP_error("Error: could not allocate hashing context.", NULL);
	}
	if ( (EVP_DigestInit_ex(evp_ctx, hash_type, NULL)) != 1){
		_handle_EVP_error("Error: could not init EVP context.", evp_ctx);
	}
	if ( (EVP_DigestUpdate(evp_ctx, selected_block, sizeof(selected_block))) != 1 ){
		_handle_EVP_error("Error: could not update EVP context.", evp_ctx);
	}
	if ( (EVP_DigestFinal_ex(evp_ctx, block_hash, NULL)) != 1){
		_handle_EVP_error("Error: could not retrieve hash for encryption block.", evp_ctx);
	}
	EVP_MD_CTX_free(evp_ctx);

	#ifdef DEBUG
		printf("[DEBUG] Hashed encryption block:\n");
		for (int i=0; i<sizeof(block_hash); ++i) {
			printf("0x%x ", block_hash[i]);
		}
		printf(" (%li bytes)\n", sizeof(block_hash));
	#endif

}
