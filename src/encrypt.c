/* Standard library */
#include <math.h>
#include <string.h>

/* OpenSSL */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

/* Internal modules */
#include "common.h"
#include "context.h"
#include "encrypt.h"

/*
 * Returns the Shannon entropy for a buffer of 'block_size'. This function
 * will modify the input buffer always.
 */
static double __block_entropy(unsigned char* buf, unsigned int block_size) {

	/* Order bytes in input block */
	int i, j;
	char tmp;
	for (i = 0; i<block_size-1; ++i) {
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
	unsigned char prev_byte = buf[0];

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

/*
 * Helper function that returns a random index from 0 to num_blocks.
 * We need this function in case RAND_MAX < num_blocks, as it is implementation
 * dependent. It always satisfies RAND_MAX >= 32767
 */
static long long int __get_random_index(long long int num_blocks) {

	if (RAND_MAX >= num_blocks)
		return ((long long int)rand() % num_blocks);

	long long int output = 0;
	for (int i=0; i<(num_blocks / RAND_MAX); ++i) {
		output += rand();
	}

	return output;
}

/*
 * Checks entropy for NUM_RANDOM_BLOCKS blocks in 'plaintext_file' and returns the index
 * for the most entropic one. Blocks are selected randomly, but the caller must seed the
 * RNG with srand() previously.
 */
static long long int _select_block(const char* plaintext_file, unsigned int block_size, long long int num_blocks) {
	FILE* fp;					/* File handle */
	double block_entropy;				/* Entropy for current block */
	double max_entropy = -1;			/* Max. entropy seen */
	int i, random_index;				/* Loop variable and random access index */
	int amount_read;				/* Amount of bytes read for each block */
	long long int selected_block_index = -1;	/* Index of max. entropy block */
	unsigned char block[block_size];		/* Current extracted block */

	fp = fopen(plaintext_file, "rb");
	for (i = 0; i<NUM_RANDOM_BLOCKS; ++i) {

		random_index = __get_random_index(num_blocks);

		/* Get block with selected index */
		fseek(fp, (random_index) * block_size, SEEK_SET);
		amount_read = fread(block, sizeof(unsigned char), block_size, fp);

		/* Prevent selecting last block if size is not big enough */
		/* TODO: allow selecting last block by adding padding */
		if (amount_read < block_size) {
			continue;
		}

		/* Get entropy for current block and update selected block */
		if ( (block_entropy = __block_entropy(block, block_size)) > max_entropy) {
			max_entropy = block_entropy;
			selected_block_index = random_index;
		}
		DEBUG_PRINT(("[DEBUG] ++ Checking entropy for block %i: %f ++ \n", random_index, block_entropy));
	}
	fclose(fp);
	return selected_block_index;
}

/*
 * Write header to outfile. Format:
 * Fast mode disabled: fast flag (1 byte) + challenge (_CHALLENGE_SIZE bytes)
 * Fast mode enabled: fast flag (1 byte) + challenge (_CHALLENGE_SIZE bytes) + auth (_AUTH_SIZE bytes)
 */
static int _write_header(const CzarrapoContext* ctx, const char* encrypted_file, const unsigned char* challenge, long long int selected_block_index) {
	FILE* ef;
	int amount_written, total_written = 0;

	/* Open file */
	if ( (ef = fopen(encrypted_file, "wb")) == NULL )
		return ERR_FAILURE;

	/* 1 byte - fast mode */
	if ( (amount_written = fwrite(&(ctx->fast), sizeof(bool), 1, ef)) < sizeof(bool) ) {
		fclose(ef);
		return ERR_FAILURE;
	}
	total_written += amount_written;

	/* 20 bytes - challenge */
	if ( (amount_written = fwrite(challenge, sizeof(unsigned char), _CHALLENGE_SIZE, ef)) < _CHALLENGE_SIZE ) {
		fclose(ef);
		return ERR_FAILURE;
	}
	total_written += amount_written;

	/* 64 bytes - auth = SHA512(challenge + selected_block_index + password) */
	if (ctx->fast == true) {

		/* Buffer for hash input */
		unsigned char pre_auth[_CHALLENGE_SIZE + sizeof(long long int) + MAX_PASSWORD_LENGTH];

		/* Buffer for hash output */
		unsigned char auth[_AUTH_SIZE];

		/* Copy bytes to hash input buffer: pre_auth = challenge + selected_block_index + password */
		memcpy(&pre_auth[0], challenge, _CHALLENGE_SIZE * sizeof(unsigned char));
		memcpy(&pre_auth[_CHALLENGE_SIZE * sizeof(unsigned char)], &selected_block_index, sizeof(long long int));
		memcpy(&pre_auth[_CHALLENGE_SIZE * sizeof(unsigned char) + sizeof(long long int)], ctx->password, MAX_PASSWORD_LENGTH);

		/* Hash and write to file */
		_hash_individual_block(auth, pre_auth, sizeof(pre_auth), _AUTH_HASH);
		if ( (amount_written = fwrite(auth, sizeof(unsigned char), _AUTH_SIZE, ef)) < _AUTH_SIZE ) {
			fclose(ef);
			return ERR_FAILURE;
		}
		total_written += amount_written;
	}

	fclose(ef);
	return total_written;

}

static int _encrypt_file(const CzarrapoContext* ctx, const char* plaintext_file, const char* encrypted_file, const unsigned char* key, const unsigned char* iv, long long int selected_block_index) {
	FILE *fp, *ef;					/* input/output file handles */
	int block_size = RSA_size(ctx->public_rsa);	/* Size of buffers to read and write */
	int amount_read, amount_written;		/* Result of fread() and fwrite() */
	unsigned char block[block_size];		/* Buffer for current read block */
	long long int index = -1;			/* Index of current block */
	int written_cipher_bytes;			/* Amount of bytes written with each call to EVP_EncryptUpdate() */

	EVP_CIPHER_CTX* evp_ctx;			/* Cipher context struct */
	const EVP_CIPHER* cipher_type;			/* Cipher mode, selected with input parameter */

	/* Select cipher */
	if ( (cipher_type = EVP_get_cipherbyname(_SYMMETRIC_CIPHER)) == NULL )
		return ERR_FAILURE;

	// Size: https://www.openssl.org/docs/man1.1.1/man3/EVP_EncryptUpdate.html
	unsigned char cipher_block[block_size + EVP_CIPHER_block_size(cipher_type) - 1];	/* Buffer to store ciphered block*/

	/* Allocate and init cipher context */
	if ( (evp_ctx = EVP_CIPHER_CTX_new()) == NULL ) {
		return ERR_FAILURE;
	}
	if ( (EVP_EncryptInit_ex(evp_ctx, cipher_type, NULL, key, iv)) != 1) {
		EVP_CIPHER_CTX_free(evp_ctx);
		return ERR_FAILURE;
	}

	/* Read file in blocks. Encrypt each block and write to file. */
	fp = fopen(plaintext_file, "rb");
	ef = fopen(encrypted_file, "ab");
	while ( (amount_read = fread(block, sizeof(unsigned char), block_size, fp)) ) {

		++index;

		/* RSA block */
		if (index == selected_block_index) {

			/* Encrypt using RSA*/
			if ( RSA_public_encrypt(amount_read, block, cipher_block, ctx->public_rsa, RSA_NO_PADDING) < block_size ) {
				int ecode = ERR_get_error();
 				char* err_msg = ERR_error_string(ecode, NULL);
 				printf("[ERROR] %s\n", err_msg);

 				EVP_CIPHER_CTX_free(evp_ctx);
 				fclose(fp);
 				fclose(ef);
 				return ERR_FAILURE;
			}

			/* Write to file */
			if ( (amount_written = fwrite(cipher_block, sizeof(unsigned char), block_size, ef)) < block_size ) {
				EVP_CIPHER_CTX_free(evp_ctx);
 				fclose(fp);
 				fclose(ef);
 				return ERR_FAILURE;
			}

		/* Normal AES block */
		} else {

			/* Encrypt next block */
			if ( (EVP_EncryptUpdate(evp_ctx, cipher_block, &written_cipher_bytes, block, amount_read) != 1) ) {
				EVP_CIPHER_CTX_free(evp_ctx);
 				fclose(fp);
 				fclose(ef);
 				return ERR_FAILURE;
			}

			/* Write to file */
			if ( (amount_written = fwrite(cipher_block, sizeof(unsigned char), written_cipher_bytes, ef)) != written_cipher_bytes) {
				EVP_CIPHER_CTX_free(evp_ctx);
 				fclose(fp);
 				fclose(ef);
 				return ERR_FAILURE;
			}
		}
	}

	/* End symmetric cipher */
	if ( (EVP_EncryptFinal_ex(evp_ctx, cipher_block, &written_cipher_bytes)) != 1) {
		EVP_CIPHER_CTX_free(evp_ctx);
		fclose(fp);
		fclose(ef);
		return ERR_FAILURE;
	}

	/* Write remaining data to file */
	if ( (amount_written = fwrite(cipher_block, sizeof(unsigned char), written_cipher_bytes, ef)) != written_cipher_bytes) {
		EVP_CIPHER_CTX_free(evp_ctx);
		fclose(fp);
		fclose(ef);
		return ERR_FAILURE;
	}

	EVP_CIPHER_CTX_free(evp_ctx);
	fclose(fp);
	fclose(ef);

	return 0;
}

int czarrapo_encrypt(CzarrapoContext* ctx, const char* plaintext_file, const char* encrypted_file, long long int selected_block_index) {
	int block_size;
	int header_size;
	long long int file_size, num_blocks;
	FILE* fp;

	/* We need the public key to encrypt files */
	if (ctx->public_rsa == NULL) {
		return ERR_FAILURE;
	}

	/* Get file and block size */
	if ( (file_size = _get_file_size(plaintext_file)) == ERR_FAILURE) {
		return ERR_FAILURE;
	}
	if ( (block_size = RSA_size(ctx->public_rsa)) > file_size) {
		return ERR_FAILURE;
	}
	DEBUG_PRINT(("[DEBUG] Selected %s for encryption, size of %lld bytes.\n", plaintext_file, file_size));

	/* Buffer for the selected block + password */
	unsigned char selected_block[block_size + MAX_PASSWORD_LENGTH];

	/* Compute number of blocks in file */
	num_blocks = file_size / block_size;
	if ( (file_size % block_size) > 0 ) {
		++num_blocks;
	}
	DEBUG_PRINT(("[DEBUG] Dividing file into %lld blocks of size %i.\n", num_blocks, block_size));

	/* Select random block for encryption if not already passed in */
	if (selected_block_index < 0) {
		srand(time(NULL));
		selected_block_index = _select_block(plaintext_file, block_size, num_blocks);
	} else if (selected_block_index > num_blocks) {
		return ERR_FAILURE;
	}
	DEBUG_PRINT(("[DEBUG] Encryption block has index %lld.\n", selected_block_index));

	/* Extract selected block */
	if ( (fp = fopen(plaintext_file, "rb")) == NULL) {
		return ERR_FAILURE;
	}
	if ( (fseek(fp, selected_block_index * block_size, SEEK_SET)) != 0 ) {
		fclose(fp);
		return ERR_FAILURE;
	}
	if ( (fread(selected_block, sizeof(unsigned char), block_size, fp)) < block_size ) {
		fclose(fp);
		return ERR_FAILURE;
	}
	fclose(fp);

	/* Append password and hash: block_hash = _BLOCK_HASH(selected_block) */
	memcpy(&selected_block[block_size], ctx->password, MAX_PASSWORD_LENGTH);
	unsigned char block_hash[_BLOCK_HASH_SIZE];
	if ( _hash_individual_block(block_hash, selected_block, sizeof(selected_block), _BLOCK_HASH) == ERR_FAILURE ) {
		return ERR_FAILURE;
	}

	/* Get file challenge: challenge = _CHALLENGE_HASH(block_hash) */
	unsigned char challenge[_CHALLENGE_SIZE];
	if (_hash_individual_block(challenge, block_hash, _BLOCK_HASH_SIZE, _CHALLENGE_HASH) ) {
		return ERR_FAILURE;	
	}

	/* Write encryption header to output file */
	if ( (header_size = _write_header(ctx, encrypted_file, challenge, selected_block_index)) == ERR_FAILURE ) {
		return ERR_FAILURE;
	}
	DEBUG_PRINT(("[DEBUG] Encryption header fully written (%i bytes).\n", header_size));

	/* Encrypt with challenge as IV and write to output file */
	if (_encrypt_file(ctx, plaintext_file, encrypted_file, block_hash, challenge, selected_block_index) == ERR_FAILURE ) {
		return ERR_FAILURE;
	}
	DEBUG_PRINT(("[DEBUG] File fully encrypted at %s.\n", encrypted_file));

	/* Zero out symmetric key, IV and selected block */
	memset(block_hash, 0, _BLOCK_HASH_SIZE);
	memset(challenge, 0, _CHALLENGE_SIZE);
	selected_block_index = -1;

	return 0;
}
