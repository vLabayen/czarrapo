
#include <string.h>

/* */
#include <openssl/evp.h>
#include <openssl/rsa.h>

/* Internal modules */
#include "common.h"
#include "context.h"
#include "decrypt.h"

static int _read_header(const char* encrypted_file, CzarrapoHeader* header) {

	FILE* efp;
	int min_header_size = sizeof(bool) + sizeof(unsigned char) * _CHALLENGE_SIZE;

	/* Open file */
	if ((efp = fopen(encrypted_file, "rb")) == NULL) {
			return ERR_FAILURE;
	}

	/* Read fast flag and challenge */
	if ( (fread(header, 1, min_header_size, efp)) < min_header_size) {
		fclose(efp);
		return ERR_FAILURE;
	}

	/* Read auth */
	if (header->fast == true) {
		if ( fread(header->auth, sizeof(unsigned char), _AUTH_SIZE, efp) < (sizeof(unsigned char) * _AUTH_SIZE) ) {
			fclose(efp);
			return ERR_FAILURE;
		}
	}

	header->end_offset = ftell(efp);
	fclose(efp);
	return 0;
}

/* Fills the 'output' buffer with _BLOCK_HASH(RSA_decrypt(input_block) + ctx->password) */
static int __get_key_from_block(unsigned char* output, const CzarrapoContext* ctx, int padding, const unsigned char* input_block, int input_len) {
	int decrypt_len;
	unsigned char decrypted_block[RSA_size(ctx->private_rsa) + strlen(ctx->password)];

	/* Decrypt RSA block */
	if ( (decrypt_len = RSA_private_decrypt(input_len, input_block, decrypted_block, ctx->private_rsa, padding)) < 0 ) {
		return ERR_FAILURE;
	}

	/* Concatenate with password and get block hash (aka symmetric key) */
	memcpy(&decrypted_block[decrypt_len], ctx->password, strlen(ctx->password));
	if (_hash_individual_block(output, decrypted_block, decrypt_len + strlen(ctx->password), _BLOCK_HASH) == ERR_FAILURE) {
		return ERR_FAILURE;
	}
	return 0;
}

/* Gets the symmetric key from a given block index */
static int _get_symmetric_key_from_block_index(unsigned char* key, CzarrapoContext* ctx, const char* encrypted_file, CzarrapoHeader* header, long long int selected_block_index) {
	FILE* ifp;
	unsigned int block_size = RSA_size(ctx->private_rsa);
	unsigned char rsa_block[block_size];
	int amount_read;

	/* Open file */
	if ( (ifp = fopen(encrypted_file, "rb")) == NULL) {
		return ERR_FAILURE;
	}

	/* Move pointer to the selected block and read it */
	if (fseek(ifp, header->end_offset + (selected_block_index * block_size), SEEK_SET) != 0) {
		return ERR_FAILURE;
	}
	if ( (amount_read = fread(rsa_block, sizeof(unsigned char), block_size, ifp)) < block_size ) {
		return ERR_FAILURE;
	}
	fclose(ifp);

	/* Try to compute the symmetric key from the read block */
	return __get_key_from_block(key, ctx, RSA_NO_PADDING, rsa_block, amount_read);
}

/* Finds the RSA block and gets the symmetric key from it, using SLOW mode */
static int _find_block_slow(unsigned char* output, CzarrapoContext* ctx, const char* encrypted_file, CzarrapoHeader* header) {
	FILE* efp;					/* Encrypted file handle */
	int amount_read;				/* Output of fread() */
	int block_size = RSA_size(ctx->private_rsa);	/* Size of blocks to decrypt */
	long long int index = -1;			/* Index for each read block */
	unsigned char rsa_block[block_size];		/* Buffer to store each read block */
	unsigned char new_challenge[_CHALLENGE_SIZE];	/* Buffer to store computed challenge */

	/* Open file */
	if ( (efp = fopen(encrypted_file, "rb")) == NULL ) {
		return ERR_FAILURE;
	}

	/* Read each block and try to compute the challenge from it */
	fseek(efp, header->end_offset, SEEK_SET);
	while ( (amount_read = fread(rsa_block, sizeof(unsigned char), block_size, efp)) ) {
		
		++index;

		/* output = _BLOCK_HASH(RSA_decrypt(rsa_block) + password) */
		if (__get_key_from_block(output, ctx, RSA_NO_PADDING, rsa_block, amount_read) == ERR_FAILURE) {
			continue;
		}

		/* challenge = _CHALLENGE_HASH(key) */
		if (_hash_individual_block(new_challenge, output, _BLOCK_HASH_SIZE, _CHALLENGE_HASH) == ERR_FAILURE) {
			return ERR_FAILURE;
		}

		/* Compare with challenge read from header */
		if (memcmp(new_challenge, header->challenge, _CHALLENGE_SIZE) == 0) {
			fclose(efp);
			return index;
		}
	}

	fclose(efp);
	return ERR_FAILURE;
}

/* Finds the RSA block and gets the symmetric key from it, using FAST mode */
static int _find_block_fast(unsigned char* output, CzarrapoContext* ctx, const char* encrypted_file, CzarrapoHeader* header) {
	int block_size = RSA_size(ctx->private_rsa);	/* Size of blocks to decrypt */
	long long int index;				/* Index for each read block */
	int num_blocks;

	unsigned char pre_auth[_CHALLENGE_SIZE + sizeof(long long int) + strlen(ctx->password)];	/* Buffer for the hash input */
	unsigned char new_auth[_AUTH_SIZE];								/* Buffer for the hash output */

	/* Prepare input buffer: pre_auth = challenge + index (to be filled) + password */
	memcpy(&pre_auth[0], header->challenge, _CHALLENGE_SIZE);
	memcpy(&pre_auth[_CHALLENGE_SIZE + sizeof(long long int)], ctx->password, strlen(ctx->password));

	/* Fills the index in pre_auth and computes auth from it */
	num_blocks = _get_file_size(encrypted_file) / block_size;
	for (index = 0; index < num_blocks; ++index) {

		/* Form new pre_auth and hash into auth */
		memcpy(&pre_auth[_CHALLENGE_SIZE], &index, sizeof(long long int));
		if (_hash_individual_block(new_auth, pre_auth, sizeof(pre_auth), _AUTH_HASH) == ERR_FAILURE) {
			return ERR_FAILURE;
		}

		/* If auth matches, compute symmetric key for this block */
		if (memcmp(header->auth, new_auth, _AUTH_SIZE) == 0 ){
			if (_get_symmetric_key_from_block_index(output, ctx, encrypted_file, header, index) == ERR_FAILURE) {
				return ERR_FAILURE;
			}
			return index;
		}
	}

	return ERR_FAILURE;
}

static int _decrypt_file(CzarrapoContext* ctx, const char* encrypted_file, const char* decrypted_file, const unsigned char* key, const CzarrapoHeader* header, long long int selected_block_index) {
	FILE *ifp, *ofp;				/* File handles for input and output files */
	int block_size = RSA_size(ctx->private_rsa);	/* Size of each read block */
	unsigned char block[block_size];		/* Buffer for each read block */
	long long int index = -1;			/* Index of each read block */
	int amount_read, amount_written;		/* Variables to store results of fread() and fwrite() */
	int written_decipher_bytes;			/* Cipher output length */

	const EVP_CIPHER* cipher_type;		/* Cipher mode, selected with input parameter */
	EVP_CIPHER_CTX* evp_ctx;		/* Cipher context */

	/* Select cipher */
	if ( (cipher_type = EVP_get_cipherbyname(_SYMMETRIC_CIPHER)) == NULL ) {
		return ERR_FAILURE;
	}

	/* Allocate and init cipher context */
	if ( (evp_ctx = EVP_CIPHER_CTX_new()) == NULL ) {
		return ERR_FAILURE;
	}
	if ( (EVP_DecryptInit_ex(evp_ctx, cipher_type, NULL, key, header->challenge)) != 1) {
		EVP_CIPHER_CTX_free(evp_ctx);
		return ERR_FAILURE;
	}

	/* Buffer for the decrypted block */
	unsigned char decipher_block[block_size + EVP_CIPHER_block_size(cipher_type) - 1];

	/* Open files */
	if ( (ifp = fopen(encrypted_file, "rb")) == NULL || (ofp = fopen(decrypted_file, "wb")) == NULL ) {
		EVP_CIPHER_CTX_free(evp_ctx);
		return ERR_FAILURE;
	}
	
	/* Decrypt each block */
	fseek(ifp, header->end_offset, SEEK_SET);
	while ( (amount_read = fread(block, sizeof(unsigned char), block_size, ifp)) ) {

		++index;

		/* RSA block */
		if (index == selected_block_index) {

			/* Decrypt block */
			if ( (written_decipher_bytes = RSA_private_decrypt(amount_read, block, decipher_block, ctx->private_rsa, RSA_NO_PADDING)) < 0) {
				EVP_CIPHER_CTX_free(evp_ctx);
				fclose(ifp);
				fclose(ofp);
				return ERR_FAILURE;
			}

			/* Write to file */
			if ( (amount_written = fwrite(decipher_block, sizeof(unsigned char), written_decipher_bytes, ofp)) != written_decipher_bytes ) {
				EVP_CIPHER_CTX_free(evp_ctx);
				fclose(ifp);
				fclose(ofp);
				return ERR_FAILURE;
			}

		/* Regular AES block */
		} else {

			/* Update with read data */
			if ( EVP_DecryptUpdate(evp_ctx, decipher_block, &written_decipher_bytes, block, amount_read) != 1 ) {
				EVP_CIPHER_CTX_free(evp_ctx);
				fclose(ifp);
				fclose(ofp);
				return ERR_FAILURE;
			}

			/* Write to file */
			if ( (amount_written = fwrite(decipher_block, sizeof(unsigned char), written_decipher_bytes, ofp)) != written_decipher_bytes) {
				EVP_CIPHER_CTX_free(evp_ctx);
				fclose(ifp);
				fclose(ofp);
				return ERR_FAILURE;
			}
		}
	}

	/* End symmetric cipher */
	if ( EVP_DecryptFinal_ex(evp_ctx, decipher_block, &written_decipher_bytes) != 1 ) {
		EVP_CIPHER_CTX_free(evp_ctx);
		fclose(ifp);
		fclose(ofp);
		return ERR_FAILURE;
	}

	/* Write remaining data to file */
	if ( (amount_written = fwrite(decipher_block, sizeof(unsigned char), written_decipher_bytes, ofp)) != written_decipher_bytes ) {
		EVP_CIPHER_CTX_free(evp_ctx);
		fclose(ifp);
		fclose(ofp);
		return ERR_FAILURE;
	}

	EVP_CIPHER_CTX_free(evp_ctx);
	fclose(ifp);
	fclose(ofp);

	return 0;
}

int czarrapo_decrypt(CzarrapoContext* ctx, const char* encrypted_file, const char* decrypted_file, long long int selected_block_index) {
	long long int file_size;		/* Input file size */
	int block_size;				/* Block size determined from RSA key size */
	CzarrapoHeader header;			/* Encrypted file header */
	unsigned char key[_BLOCK_HASH_SIZE];	/* Buffer to hold the key, to be filled when the selected block is found */

	/* We need the private key to encrypt files */
	if (ctx->private_rsa == NULL) {
		return ERR_FAILURE;
	}

	/* Get file and block size */
	if ( (file_size = _get_file_size(encrypted_file)) == ERR_FAILURE){
		return ERR_FAILURE;
	}
	if ( (block_size = RSA_size(ctx->private_rsa)) > file_size) {
		return ERR_FAILURE;
	}
	DEBUG_PRINT(("[DEBUG] Selected %s for decryption, size of %lld bytes.\n", encrypted_file, file_size));

	/* Read header information (fast, challenge, auth) */
	if ( _read_header(encrypted_file, &header) == ERR_FAILURE ) {
		return ERR_FAILURE;
	}
	DEBUG_PRINT(("[DEBUG] File header read correctly (%i bytes).\n", header.end_offset));

	/* Determine RSA block index and retrieve symmetric key = _BLOCK_HASH(RSA_decrypt(selected_block)+password) */
	if ( selected_block_index < 0 ) {
		if (header.fast) {
			selected_block_index = _find_block_fast(key, ctx, encrypted_file, &header);
		} else {
			selected_block_index = _find_block_slow(key, ctx, encrypted_file, &header);
		}

		if (selected_block_index == ERR_FAILURE) {
			return ERR_FAILURE;
		}

	} else {
		if (selected_block_index * block_size > file_size) {
			return ERR_FAILURE;
		}

		if (_get_symmetric_key_from_block_index(key, ctx, encrypted_file, &header, selected_block_index) == ERR_FAILURE ) {
			return ERR_FAILURE;
		}
	}
	DEBUG_PRINT(("[DEBUG] Found selected block at index %lld.\n", selected_block_index));

	/* Decrypt and save to output file */
	if ( _decrypt_file(ctx, encrypted_file, decrypted_file, key, &header, selected_block_index) ) {
		return ERR_FAILURE;
	}
	DEBUG_PRINT(("[DEBUG] File decrypted correctly at %s.\n", decrypted_file));

	return 0;
}