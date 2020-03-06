
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

/* Internal modules */
#include "czarrapo.h"
#include "error_handling.h"

#define NUM_RANDOM_BLOCKS	5
#define ERR_MSG_BUF_SIZE	120

/* Hash to generate symmetric key from block (256 bits) */
#define _BLOCK_HASH		"SHA256"
#define _BLOCK_HASH_SIZE	32

/* Hash to produce challenge with (160 bits) */
#define _CHALLENGE_HASH		"SHA1"
#define _CHALLENGE_SIZE		20

/* Hash type and size for the auth buffer (512 bits) */
#define _AUTH_HASH		"SHA512"
#define _AUTH_SIZE		64

/* Symmetric cipher to use (256 bit key size, 128 bit IV size) */
#define _SYMMETRIC_CIPHER	"AES-256-CBC"
#define IV_SIZE			16

static bool _ispowerof2(unsigned int x) {
   return x && !(x & (x - 1));
}

/*
 * Returns the Shannon entropy for a buffer of 'block_size'. This function
 * will modify the input buffer always. On the other hand, it avoids copying
 * the entire buffer to get its entropy.
 */
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
static size_t _select_block(char* plaintext_file, size_t block_size, long int num_blocks) {
	FILE* fp;				/* File handle */
	double block_entropy;			/* Entropy for current block */
	double max_entropy = -1;		/* Max. entropy seen */
	int i, random_index;			/* Loop variable and random access index */
	int amount_read;			/* Amount of bytes read for each block */
	size_t selected_block_index = -1;		/* Index of max. entropy block */
	unsigned char block[block_size];	/* Current extracted block */

	fp = fopen(plaintext_file, "rb");
	for (i = 0; i<NUM_RANDOM_BLOCKS; ++i) {

		/* Get random block index */
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
 * Hashes array 'input' of size 'input_size' with hash 'hash_name'. Fills 'block_hash' with the result.
 * This function is generic enough to support any hash, as long as the caller has enough size to receive
 * the output in 'block_hash'.
 */
static void _hash_individual_block(unsigned char* block_hash, unsigned char* input, int input_size, const char* hash_name) {
	EVP_MD_CTX* evp_ctx;					/* EVP hashing context struct */
	EVP_MD* hash_type = EVP_get_digestbyname(hash_name);	/* Selected hash type for encryption block*/

	if ( (evp_ctx = EVP_MD_CTX_new()) == NULL ) {
		_handle_EVP_MD_error("Error: could not allocate hashing context.", true, NULL);
	}
	if ( (EVP_DigestInit_ex(evp_ctx, hash_type, NULL)) != 1) {
		_handle_EVP_MD_error("Error: could not init EVP hashing context.", true, evp_ctx);
	}
	if ( (EVP_DigestUpdate(evp_ctx, input, input_size)) != 1 ) {
		_handle_EVP_MD_error("Error: could not update EVP context.", true, evp_ctx);
	}
	if ( (EVP_DigestFinal_ex(evp_ctx, block_hash, NULL)) != 1) {
		_handle_EVP_MD_error("Error: could not retrieve hash for encryption block.", true, evp_ctx);
	}
	EVP_MD_CTX_free(evp_ctx);
}

/*
 * Reads plaintext_file in blocks of size 'block_size' (this is the same block size as chosen to select an RSA block, but does not need to be that way).
 * Each block is then encrypted and written to 'encrypted_file'. 'cipher_name' selects which symmetric mode to use, with 'key' and 'iv'. 'selected_block_index'
 * needs to be passed also so it is not encrypted.
 */
static void _encrypt_file(const char* plaintext_file, const char* encrypted_file, const char* cipher_name, const unsigned char* key,  const unsigned char* iv, size_t block_size, size_t selected_block_index, char* public_key_file) {
	FILE* fp;					/* File handles */
	FILE* ef;
	unsigned char block[block_size];		/* Buffer for each block in plaintext file */
	int written_cipher_bytes;			/* Amount of bytes written with each call to EVP_EncryptUpdate() */
	size_t i = 0;					/* Block number for each iteration */
	size_t amount_read, amount_written;		/* Number of bytes read or written to files in each fread() or fwrite() call */

	EVP_CIPHER_CTX* evp_ctx;								/* Cipher context struct */
	EVP_CIPHER* cipher_type = EVP_get_cipherbyname(cipher_name);				/* Cipher mode, selectec with input param */
	unsigned char cipher_block[block_size + EVP_CIPHER_block_size(cipher_type) - 1];	// https://www.openssl.org/docs/man1.1.1/man3/EVP_EncryptUpdate.html

	RSA* rsa;					/* RSA struct */

	/* Allocate and init cipher context */
	if ( (evp_ctx = EVP_CIPHER_CTX_new()) == NULL ) {
		_handle_EVP_CIPHER_error("Error: could not allocate cipher context.", true, NULL, NULL, NULL);
	}
	if ( (EVP_EncryptInit_ex(evp_ctx, cipher_type, NULL, key, iv)) != 1) {
		_handle_EVP_CIPHER_error("Error: could not init EVP cipher context.", true, evp_ctx, NULL, NULL);
	}

	/* Read file in blocks. Encrypt each block and write to file. */
	fp = fopen(plaintext_file, "rb");
	ef = fopen(encrypted_file, "ab");
	while( (amount_read = fread(block, sizeof(unsigned char), block_size, fp)) ){

		++i;

		#ifdef DEBUG
			if ((i%50000) == 0) {
				printf("[DEBUG] ++ Encrypting block %li ++\n", i);
			}
		#endif

		/* RSA block */
		if (i == selected_block_index) {

			FILE* pk;
			RSA* rsa;
			EVP_PKEY* pkey;
			EVP_PKEY_CTX* pkey_ctx;

			/* Allocate RSA struct */
			if ( (rsa = RSA_new()) == NULL ){
				_handle_RSA_error("Could not allocate RSA struct.\n", false, NULL, NULL, pk, NULL, NULL);
				_handle_EVP_CIPHER_error("", true, evp_ctx, fp, ef);
			}

			/* Read public key from file, assign to RSA struct and close file */
			if ( (pk = fopen(public_key_file, "r")) == NULL ) {
				_handle_file_action_error("Could not open public key file.\n", false, pk);
				_handle_EVP_CIPHER_error("", true, evp_ctx, fp, ef);
			}
			if ( (rsa = PEM_read_RSAPublicKey(pk, &rsa, NULL, NULL)) == NULL ) {
				_handle_RSA_error("Public key format not understood.\n", false, rsa, NULL, pk, NULL, NULL);
				_handle_EVP_CIPHER_error("", true, evp_ctx, fp, ef);
			}
			fclose(pk);
			DEBUG_PRINT(("[DEBUG] Public key file at %s read correctly.\n", public_key_file));

			/* Allocate EVP_PKEY struct and assign public key to it. By calling EVP_PKEY_assign_RSA() successfully, we no longer have to free the RSA struct ourselves */
			if ( (pkey = EVP_PKEY_new()) == NULL ) {
				_handle_RSA_error("Error: could not allocate EPV_PKEY struct.\n", false, rsa, NULL, NULL, pkey, NULL);
				_handle_EVP_CIPHER_error("", true, evp_ctx, fp, ef);
			}
			if ( (EVP_PKEY_assign_RSA(pkey, rsa)) != 1 ) {
				_handle_RSA_error("Error: could not assign public key to EVP_PKEY struct.\n", false, rsa, NULL, NULL, pkey, NULL);
				_handle_EVP_CIPHER_error("", true, evp_ctx, fp, ef);
			}

			/* Allocate EVP_PKEY_CTX struct and init */
			if ( (pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL ) {
				_handle_RSA_error("Error: could not allocate EVP_PKEY_CTX struct.\n", false, NULL, NULL, NULL, pkey, NULL);
				_handle_EVP_CIPHER_error("", true, evp_ctx, fp, ef);
			}
			if ( (EVP_PKEY_encrypt_init(pkey_ctx)) != 1 ) {
				_handle_RSA_error("Error: could not init EVP_PKEY_CTX struct.\n", false, NULL, NULL, NULL, pkey, pkey_ctx);
				_handle_EVP_CIPHER_error("", true, evp_ctx, fp, ef);
			}

			/* Set padding. This assumes that block_size <= RSA_size(rsa). The condition block_size>RSA_size(rsa) should be checked beforehand */
			// https://crypto.stackexchange.com/a/42100
			if (block_size == RSA_size(rsa)) {
				EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_NO_PADDING);
			} else {
				EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_OAEP_PADDING);
			}

			/* Get output length */
			size_t rsa_output_len;
			if ( (EVP_PKEY_encrypt(pkey_ctx, NULL, &rsa_output_len, block, block_size)) <= 0 ) {
				_handle_RSA_error("Error: could not encrypt RSA block.\n", false, NULL, NULL, NULL, pkey, pkey_ctx);
				_handle_EVP_CIPHER_error("", true, evp_ctx, fp, ef);
			}

			/* Encrypt and free structs */
			unsigned char rsa_output[rsa_output_len];
			if ( EVP_PKEY_encrypt(pkey_ctx, rsa_output, &rsa_output_len, block, block_size) <= 0 ) {
				_handle_RSA_error("Error: could not encrypt RSA block.\n", false, NULL, NULL, NULL, pkey, pkey_ctx);
				_handle_EVP_CIPHER_error("", true, evp_ctx, fp, ef);
			}
			EVP_PKEY_CTX_free(pkey_ctx);
			EVP_PKEY_free(pkey);

			/* Write to file */
			if ( (amount_written = fwrite(rsa_output, sizeof(unsigned char), rsa_output_len, ef)) < rsa_output_len ) {
				_handle_EVP_CIPHER_error("Error: could not write RSA block to encrypted file.\n", true, evp_ctx, fp, ef);
			}
			DEBUG_PRINT(("[DEBUG] ++ RSA block (index: %lu) found and encrypted (%lu bytes).\n", i, rsa_output_len));

		/* Normal AES block */
		} else {

			/* Encrypt next block */ 
			if ( (EVP_EncryptUpdate(evp_ctx, cipher_block, &written_cipher_bytes, block, amount_read) != 1) ) {
				char err_msg[ERR_MSG_BUF_SIZE];
				sprintf(err_msg, "Error: failure encrypting block %lu.", i);
				_handle_EVP_CIPHER_error(err_msg, true, evp_ctx, fp, ef);
			}

			/* Write to file */
			amount_written = fwrite(cipher_block, sizeof(unsigned char), written_cipher_bytes, ef);
			if (amount_written != written_cipher_bytes) {
				char err_msg[ERR_MSG_BUF_SIZE];
				sprintf(err_msg, "Error: failure writing block %lu to output file.", i);
				_handle_EVP_CIPHER_error(err_msg, true, evp_ctx, fp, ef);
			}

			/* Last block */
			if (amount_read < block_size) {

				/* End AES. This call will add padding to remaning data */
				if ( (EVP_EncryptFinal_ex(evp_ctx, cipher_block, &written_cipher_bytes)) != 1) {
					_handle_EVP_CIPHER_error("Error: failure ciphering final data.", true, evp_ctx, fp, ef);
				}

				/* Write remaining data to file */
				amount_written = fwrite(cipher_block, sizeof(unsigned char), written_cipher_bytes, ef);
				if (amount_written != written_cipher_bytes) {
					char err_msg[ERR_MSG_BUF_SIZE];
					sprintf(err_msg, "Error: failure writing block %lu to output file.", i);
					_handle_EVP_CIPHER_error(err_msg, true, evp_ctx, fp, ef);
				}

				break;
			}
		}
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
static void _write_header(char* encrypted_file, bool fast, unsigned char* challenge, size_t selected_block_index, char* password, size_t password_len) {
	FILE* ef;
	int amount_written;

	if ( (ef = fopen(encrypted_file, "wb")) == NULL ) {
		char err_msg[ERR_MSG_BUF_SIZE];
		sprintf(err_msg, "Error opening file %s at _write_header().", encrypted_file);
		_handle_file_action_error(err_msg, true, NULL);
	}

	/* 1 byte - fast mode */
	if ( (amount_written = fwrite(&fast, sizeof(bool), 1, ef)) < sizeof(bool) ) {
		_handle_file_action_error("Error: failure during header write to encrypted file.", true, ef);
	}
	DEBUG_PRINT(("[DEBUG] ++ HEADER: Fast mode flag written (%i bytes)\n", amount_written));

	/* 20 bytes - challenge */
	if ( (amount_written = fwrite(challenge, sizeof(unsigned char), _CHALLENGE_SIZE, ef)) < _CHALLENGE_SIZE ) {
		_handle_file_action_error("Error: failure during header write to encrypted file.", true, ef);
	}
	DEBUG_PRINT(("[DEBUG] ++ HEADER: Challenge written (%i bytes)\n", amount_written));

	/* 64 bytes - auth = SHA512(challenge + selected_block_index + password) */
	if (fast == true) {

		/* Buffer for hash output */
		unsigned char auth[_AUTH_SIZE];

		/* Bytes to be hashed */
		unsigned char pre_auth[_CHALLENGE_SIZE + sizeof(size_t)/sizeof(unsigned char) + password_len];

		/* Copy bytes to hash input buffer */
		memcpy(&pre_auth[0], challenge, _CHALLENGE_SIZE * sizeof(unsigned char));
		memcpy(&pre_auth[_CHALLENGE_SIZE * sizeof(unsigned char)], &selected_block_index, sizeof(size_t));
		memcpy(&pre_auth[_CHALLENGE_SIZE * sizeof(unsigned char) + sizeof(size_t)], password, password_len);

		/* Run hash and write output to file */
		_hash_individual_block(auth, pre_auth, sizeof(pre_auth), _AUTH_HASH);
		DEBUG_PRINT(("[DEBUG] ++ HEADER: Hashing pre_auth (%lu bytes) into auth with %s (%i bytes).\n", sizeof(pre_auth), _AUTH_HASH, _AUTH_SIZE));
		if ( (amount_written = fwrite(auth, sizeof(unsigned char), _AUTH_SIZE, ef)) < _AUTH_SIZE ) {
			_handle_file_action_error("Error: failure during header write to encrypted file.", true, ef);
		}
		DEBUG_PRINT(("[DEBUG] ++ HEADER: Auth written (%i bytes)\n", amount_written));

	}
	fclose(ef);
}

void encrypt_file(char* plaintext_file, char* encrypted_file, size_t block_size, char* password, char* public_key_file, size_t selected_block_index, bool fast) {
	FILE* fp;					/* File handle */
	size_t file_size, num_blocks;			/* Variables on the input file */
	size_t password_len = 0;			/* Length of input password */
	if (password != NULL) {
		password_len = strlen(password);
	}
	unsigned char selected_block[block_size + password_len];	/* Selected block for encryption */

	/* Check that block size is a power of 2 and TODO: that is not too big for selected key size */
	if (!_ispowerof2(block_size)) {
		printf("Error: block_size %li must be a power of 2\n", block_size);
		exit(1);
	}
	//TODO: _check_block_size(public_key_file, block_size);

	/* Get file size (platform independent) */
	if ( (fp = fopen(plaintext_file, "rb")) == NULL ) {
		char err_msg[ERR_MSG_BUF_SIZE];
		sprintf(err_msg, "Error opening file %s at encrypt_file().", plaintext_file);
		_handle_file_action_error(err_msg, true, NULL);
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
	DEBUG_PRINT(("[DEBUG] Encryption block has offset %lu\n", selected_block_index));

	/* Extract selected block */
	fp = fopen(plaintext_file, "rb");
	if ( (fseek(fp, selected_block_index*block_size, SEEK_SET)) != 0 ) {
		char err_msg[ERR_MSG_BUF_SIZE];
		sprintf(err_msg, "Failed to extract block %lu from file %s.", selected_block_index, plaintext_file);
		_handle_file_action_error(err_msg, true, fp);
	}
	if ( (fread(selected_block, sizeof(unsigned char), block_size, fp)) < block_size ) {
		char err_msg[ERR_MSG_BUF_SIZE];
		sprintf(err_msg, "Failed to extract block %lu from file %s.", selected_block_index, plaintext_file);
		_handle_file_action_error(err_msg, true, fp);
	}
	fclose(fp);

	/* Append password */
	memcpy(&selected_block[block_size], password, password_len);

	/* Hash block to use with AES */
	unsigned char block_hash[_BLOCK_HASH_SIZE];
	_hash_individual_block(block_hash, selected_block, sizeof(selected_block), _BLOCK_HASH);
	DEBUG_PRINT(("[DEBUG] Hashed encryption block with %s (%i bytes)\n", _BLOCK_HASH, _BLOCK_HASH_SIZE));

	/* Get file challenge */
	unsigned char challenge[_CHALLENGE_SIZE];
	_hash_individual_block(challenge, block_hash, _BLOCK_HASH_SIZE, _CHALLENGE_HASH);
	DEBUG_PRINT(("[DEBUG] Generated challenge (%i bytes)\n", _CHALLENGE_SIZE));

	/* Add file header with relevant information */
	_write_header(encrypted_file, fast, challenge, selected_block_index, password, password_len);
	DEBUG_PRINT(("[DEBUG] Encryption header fully written to %s\n", encrypted_file));

	/* Encrypt file. Use challenge as IV (128 out of 160 bits from SHA1) */
	DEBUG_PRINT(("[DEBUG] Starting file encryption.\n"));
	_encrypt_file(plaintext_file, encrypted_file, _SYMMETRIC_CIPHER, block_hash, challenge, block_size, selected_block_index, public_key_file);
	DEBUG_PRINT(("[DEBUG] File fully encrypted.\n"));
}
