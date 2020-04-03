
/* Standard library */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>

/* OpenSSL */
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

/* Internal modules */
#include "czarrapo.h"
#include "utils.h"
#include "error_handling.h"

#define NUM_RANDOM_BLOCKS	5

/*
 * Returns the Shannon entropy for a buffer of 'block_size'. This function
 * will modify the input buffer always. On the other hand, it avoids copying
 * the entire buffer to get its entropy.
 */
static double _block_entropy(unsigned char* buf, unsigned int block_size) {

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
 * Checks entropy for NUM_RANDOM_BLOCKS blocks in 'plaintext_file' and returns the index
 * for the most entropic one. Blocks are selected randomly, but the caller must seed the
 * RNG with srand() previously.
 */
static size_t _select_block(const char* plaintext_file, unsigned int block_size, long int num_blocks) {
	FILE* fp;				/* File handle */
	double block_entropy;			/* Entropy for current block */
	double max_entropy = -1;		/* Max. entropy seen */
	int i, random_index;			/* Loop variable and random access index */
	int amount_read;			/* Amount of bytes read for each block */
	size_t selected_block_index = -1;	/* Index of max. entropy block */
	unsigned char block[block_size];	/* Current extracted block */

	fp = fopen(plaintext_file, "rb");
	for (i = 0; i<NUM_RANDOM_BLOCKS; ++i) {

		random_index = rand() % num_blocks;

		/* Get block with selected index */
		fseek(fp, (random_index) * block_size, SEEK_SET);
		amount_read = fread(block, sizeof(unsigned char), block_size, fp);

		/* Prevent selecting last block if size is not big enough */
		/* TODO: allow selecting last block by adding padding */
		if (amount_read < block_size) {
			continue;
		}

		/* Get entropy for current block and update selected block */
		if ( (block_entropy = _block_entropy(block, block_size)) > max_entropy) {
			max_entropy = block_entropy;
			selected_block_index = random_index;
		}
		DEBUG_PRINT(("[DEBUG] ++ Checking entropy for block %i: %f ++ \n", random_index, block_entropy));
	}
	fclose(fp);
	return selected_block_index;
}

/*
 * Reads a public key file into an RSA struct or returns
 * NULL on failure.
 */
static RSA* _load_public_key(const char* public_key_file) {
	RSA* rsa;
	FILE* pk;

	if ( (rsa = RSA_new()) == NULL ){
		return NULL;
	}
	if ( (pk = fopen(public_key_file, "r")) == NULL ) {
		RSA_free(rsa);
		return NULL;
	}
	if ( (rsa = PEM_read_RSAPublicKey(pk, &rsa, NULL, NULL)) == NULL ) {
		fclose(pk);
		RSA_free(rsa);
		return NULL;
	}
	DEBUG_PRINT(("[DEBUG] Public key at %s read correctly.\n", public_key_file));

	fclose(pk);
	return rsa;
}

/*
 * Reads plaintext_file in blocks of size 'block_size. Each block is then encrypted and written to 'encrypted_file'.
 * 'cipher_name' selects which symmetric mode to use, with 'key' and 'iv'. 'selected_block_index' needs to be passed also
 * so it is not encrypted with AES, but with RSA.
 */
static void _encrypt_file(const char* plaintext_file, const char* encrypted_file, const char* cipher_name, const unsigned char* key,  const unsigned char* iv, unsigned int block_size, size_t selected_block_index, const char* public_key_file) {
	FILE* fp;					/* File handles */
	FILE* ef;
	unsigned char block[block_size];		/* Buffer for each block in plaintext file */
	int written_cipher_bytes;			/* Amount of bytes written with each call to EVP_EncryptUpdate() */
	size_t i = -1;					/* Block number for each iteration */
	size_t amount_read, amount_written;		/* Number of bytes read or written to files in each fread() or fwrite() call */

	EVP_CIPHER_CTX* evp_ctx;			/* Cipher context struct */
	const EVP_CIPHER* cipher_type;			/* Cipher mode, selected with input parameter */

	/* Select cipher */
	if ( (cipher_type = EVP_get_cipherbyname(cipher_name)) == NULL ){
		_handle_simple_error("[ERROR] Invalid symmetric cipher selected.\n");
	}

	// Size: https://www.openssl.org/docs/man1.1.1/man3/EVP_EncryptUpdate.html
	unsigned char cipher_block[block_size + EVP_CIPHER_block_size(cipher_type) - 1];	/* Buffer to store ciphered block*/

	/* Allocate and init cipher context */
	if ( (evp_ctx = EVP_CIPHER_CTX_new()) == NULL ) {
		_handle_simple_error("[ERROR] Could not allocate cipher context for file encryption.\n");
	}
	if ( (EVP_EncryptInit_ex(evp_ctx, cipher_type, NULL, key, iv)) != 1) {
		_handle_EVP_CIPHER_error("[ERROR] Could not init EVP cipher context.\n", true, evp_ctx, NULL, NULL);
	}

	/* Read file in blocks. Encrypt each block and write to file. */
	fp = fopen(plaintext_file, "rb");
	ef = fopen(encrypted_file, "ab");
	while( (amount_read = fread(block, sizeof(unsigned char), block_size, fp)) ){

		++i;

		/* RSA block */
		if (i == selected_block_index) {
			RSA* rsa;

			/* Read public key */
			if ( (rsa = _load_public_key(public_key_file)) == NULL) {
				_handle_EVP_CIPHER_error("[ERROR] Could not read public key file. Make sure that the file exists and has proper permissions and format.\n", true, evp_ctx, fp, ef);
			}

			/* Prepare RSA output buffer and encrypt */
			if ( RSA_public_encrypt(amount_read, block, cipher_block, rsa, RSA_NO_PADDING) < block_size ) {
				int ecode = ERR_get_error();
 				char* err_msg = ERR_error_string(ecode, NULL);

 				_handle_RSA_error(err_msg, false, rsa, NULL);
				_handle_EVP_CIPHER_error("\n", true, evp_ctx, fp, ef);
			}

			/* Write to file */
			if ( (amount_written = fwrite(cipher_block, sizeof(unsigned char), block_size, ef)) < block_size ) {
				_handle_RSA_error("[ERROR] Could not write RSA block to encrypted file.\n", false, rsa, NULL);
				_handle_EVP_CIPHER_error("", true, evp_ctx, fp, ef);
			}
			DEBUG_PRINT(("[DEBUG] RSA block (index: %lu) found and encrypted (%lu bytes).\n", i, amount_written));

			RSA_free(rsa);

		/* Normal AES block */
		} else {

			/* Encrypt next block */
			if ( (EVP_EncryptUpdate(evp_ctx, cipher_block, &written_cipher_bytes, block, amount_read) != 1) ) {
				char err_msg[ERR_MSG_BUF_SIZE];
				snprintf(err_msg, ERR_MSG_BUF_SIZE, "[ERROR] Failure encrypting block %lu.\n", i);
				_handle_EVP_CIPHER_error(err_msg, true, evp_ctx, fp, ef);
			}

			/* Write to file */
			amount_written = fwrite(cipher_block, sizeof(unsigned char), written_cipher_bytes, ef);
			if (amount_written != written_cipher_bytes) {
				char err_msg[ERR_MSG_BUF_SIZE];
				snprintf(err_msg, ERR_MSG_BUF_SIZE, "[ERROR] Failure writing block %lu to output file.\n", i);
				_handle_EVP_CIPHER_error(err_msg, true, evp_ctx, fp, ef);
			}
		}

		//printf("Block %lu (%s) %i -> ", i, i==selected_block_index ? "rsa" : "aes", amount_read);
		//printf("written %i\n", amount_written);
	}

	/* End symmetric cipher */
	if ( (EVP_EncryptFinal_ex(evp_ctx, cipher_block, &written_cipher_bytes)) != 1) {
		_handle_EVP_CIPHER_error("[ERROR] Failure ciphering final data.\n", true, evp_ctx, fp, ef);
	}

	/* Write remaining data to file */
	amount_written = fwrite(cipher_block, sizeof(unsigned char), written_cipher_bytes, ef);
	if (amount_written != written_cipher_bytes) {
		char err_msg[ERR_MSG_BUF_SIZE];
		snprintf(err_msg, ERR_MSG_BUF_SIZE, "[ERROR] Failure writing block %lu to output file.\n", i);
		_handle_EVP_CIPHER_error(err_msg, true, evp_ctx, fp, ef);
	}

	EVP_CIPHER_CTX_free(evp_ctx);
	fclose(fp);
	fclose(ef);
}

/*
 * Writes header to output file:
 * if fast == false: fast (1 byte) + challenge (20 bytes)
 * if fast == true: fast (1 byte) + challenge (20 bytes) + SHA512(challenge + selected_block_index + password) (64 bytes)
 * This makes _encrypt_file() have to use fopen() in 'ab' mode instead of 'wb'.
 */
static void _write_header(const char* encrypted_file, bool fast, const unsigned char* challenge, size_t selected_block_index, const char* password) {
	FILE* ef;
	int amount_written;

	/* Open file */
	if ( (ef = fopen(encrypted_file, "wb")) == NULL )
		_handle_simple_error("[ERROR] Could not open output file for encryption header write.\n");

	/* 1 byte - fast mode */
	if ( (amount_written = fwrite(&fast, sizeof(bool), 1, ef)) < sizeof(bool) )
		_handle_file_action_error("[ERROR] Failure during header write to encrypted file.", true, ef);

	/* 20 bytes - challenge */
	if ( (amount_written = fwrite(challenge, sizeof(unsigned char), _CHALLENGE_SIZE, ef)) < _CHALLENGE_SIZE )
		_handle_file_action_error("[ERROR] Failure during header write to encrypted file.", true, ef);

	/* 64 bytes - auth = SHA512(challenge + selected_block_index + password) */
	if (fast == true) {

		/* Buffer for hash output */
		unsigned char auth[_AUTH_SIZE];

		/* Bytes to be hashed */
		unsigned char pre_auth[_CHALLENGE_SIZE + sizeof(size_t)/sizeof(unsigned char) + strlen(password)];

		/* Copy bytes to hash input buffer */
		memcpy(&pre_auth[0], challenge, _CHALLENGE_SIZE * sizeof(unsigned char));
		memcpy(&pre_auth[_CHALLENGE_SIZE * sizeof(unsigned char)], &selected_block_index, sizeof(size_t));
		memcpy(&pre_auth[_CHALLENGE_SIZE * sizeof(unsigned char) + sizeof(size_t)], password, strlen(password));

		/* Hash and write to file */
		_hash_individual_block(auth, pre_auth, sizeof(pre_auth), _AUTH_HASH);
		if ( (amount_written = fwrite(auth, sizeof(unsigned char), _AUTH_SIZE, ef)) < _AUTH_SIZE )
			_handle_file_action_error("[ERROR] Failure during header write to encrypted file.", true, ef);

	}
	fclose(ef);
}

void encrypt_file(const char* plaintext_file, const char* encrypted_file, const char* password, const char* public_key_file, long int selected_block_index, bool fast) {
	FILE* fp;			/* File handle */
	size_t file_size, num_blocks;	/* Variables on the input file */
	unsigned int block_size;	/* Size of blocks to be encrypted */

	if (password == NULL) {
		_handle_simple_error("[ERROR] Invalid password.\n");
	}

	/* Determine block size */
	RSA* rsa = _load_public_key(public_key_file);
	block_size = RSA_size(rsa); 			//check block_size < file_size
	RSA_free(rsa);

	/* Buffer for the _BLOCK_HASH input */
	unsigned char selected_block[block_size + strlen(password)];

	/* Get size of plaintext file */
	file_size = _get_file_size(plaintext_file);
	DEBUG_PRINT(("[DEBUG] Selected %s for encryption, size of %lu bytes.\n", plaintext_file, file_size));

	/* Get number of blocks in input file for current
	 block size. Int division always rounds down. */
	num_blocks = file_size / block_size;
	if ( (file_size % block_size) > 0 ) {
		++num_blocks;
	}
	DEBUG_PRINT(("[DEBUG] Dividing file into %li blocks of size %i.\n", num_blocks, block_size));

	/* Select random block if not already passed in */
	if (selected_block_index < 0) {
		srand(time(NULL));
		selected_block_index = _select_block(plaintext_file, block_size, num_blocks);
	} else if (selected_block_index > num_blocks) {
		char err_msg[ERR_MSG_BUF_SIZE];
		snprintf(err_msg, ERR_MSG_BUF_SIZE, "[ERROR] Maximum block index for current file is %lu.\n", num_blocks-1);
		_handle_simple_error(err_msg);
	}
	DEBUG_PRINT(("[DEBUG] Encryption block has index %lu\n", selected_block_index));

	/* Extract selected block */
	fp = fopen(plaintext_file, "rb");
	if ( (fseek(fp, selected_block_index * block_size, SEEK_SET)) != 0 ) {
		char err_msg[ERR_MSG_BUF_SIZE];
		snprintf(err_msg, ERR_MSG_BUF_SIZE, "Failed to find block %lu at %s.", selected_block_index, plaintext_file);
		_handle_file_action_error(err_msg, true, fp);
	}
	if ( (fread(selected_block, sizeof(unsigned char), block_size, fp)) < block_size ) {
		char err_msg[ERR_MSG_BUF_SIZE];
		snprintf(err_msg, ERR_MSG_BUF_SIZE, "Failed to read block %lu from %s. Try selecting a lower block.\n", selected_block_index, plaintext_file);
		_handle_file_action_error(err_msg, true, fp);
	}
	fclose(fp);

	/* Append password */
	memcpy(&selected_block[block_size], password, strlen(password));

	/* Hash block to use with AES */
	unsigned char block_hash[_BLOCK_HASH_SIZE];
	_hash_individual_block(block_hash, selected_block, sizeof(selected_block), _BLOCK_HASH);
	DEBUG_PRINT(("[DEBUG] Hashed encryption block into block hash with %s (%i bytes)\n", _BLOCK_HASH, _BLOCK_HASH_SIZE));

	/* Get file challenge */
	unsigned char challenge[_CHALLENGE_SIZE];
	_hash_individual_block(challenge, block_hash, _BLOCK_HASH_SIZE, _CHALLENGE_HASH);
	DEBUG_PRINT(("[DEBUG] Hashed block hash into challenge with %s (%i bytes)\n", _CHALLENGE_HASH, _CHALLENGE_SIZE));

	/* Add file header with relevant information */
	_write_header(encrypted_file, fast, challenge, selected_block_index, password);
	DEBUG_PRINT(("[DEBUG] Encryption header fully written.\n"));

	/* Encrypt file. Use challenge as IV (128 out of 160 bits from SHA1) */
	DEBUG_PRINT(("[DEBUG] Starting file encryption with %s.\n", _SYMMETRIC_CIPHER));
	_encrypt_file(plaintext_file, encrypted_file, _SYMMETRIC_CIPHER, block_hash, challenge, block_size, selected_block_index, public_key_file);
	DEBUG_PRINT(("[DEBUG] File fully encrypted at %s.\n", encrypted_file));
}
