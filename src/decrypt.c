/* Standard library */
#include <stdlib.h>
#include <string.h>

/* OpenSSL */
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/* Internal modules */
#include "czarrapo.h"
#include "utils.h"
#include "error_handling.h"

RSA* _load_private_key(const char* private_key_file, const char* passphrase) {
	RSA* rsa;
	FILE *pk;

	/* Allocate RSA struct */
	if ( (rsa = RSA_new()) == NULL ){
		return NULL;
	}

	/* Read private key from file, assign to RSA struct and close file */
	if ( (pk = fopen(private_key_file, "r")) == NULL ) {
		RSA_free(rsa);
		return NULL;
	}
	if ( (rsa = PEM_read_RSAPrivateKey(pk, &rsa, NULL, (void*) passphrase)) == NULL ) {
		fclose(pk);
		RSA_free(rsa);
		return NULL;
	}

	fclose(pk);
	return rsa;
}

int _read_header(const char* encrypted_file, CzarrapoHeader* header) {

	FILE* efp;
	int header_end_offset;
	int min_header_size = sizeof(bool) + sizeof(unsigned char) * _CHALLENGE_SIZE;

	/* Open file */
	if ((efp = fopen(encrypted_file, "rb")) == NULL) {
			return -1;
	}

	/* Read fast flag and challenge */
	if ( (fread(header, 1, min_header_size, efp)) < min_header_size) {
		fclose(efp);
		return -1;
	}

	/* Read auth */
	if (header->fast == true) {
		if ( fread(header->auth, sizeof(unsigned char), _AUTH_SIZE, efp) < (sizeof(unsigned char) * _AUTH_SIZE) ) {
			fclose(efp);
			return -1;
		}
	}

	header_end_offset = ftell(efp);
	fclose(efp);
	return header_end_offset;
}

static int _get_key_from_block(unsigned char* key, RSA* rsa, int padding, const unsigned char* input_block, int input_len, const char* password) {
	int decrypt_len;
	unsigned char decrypted_block[RSA_size(rsa) + strlen(password)];

	/* Decrypt RSA block */
	if ( (decrypt_len = RSA_private_decrypt(input_len, input_block, decrypted_block, rsa, padding)) < 0 ) {
		return -1;
	}

	/* Concatenate with password and get block hash (aka symmetric key) */
	memcpy(&decrypted_block[decrypt_len], password, strlen(password));
	_hash_individual_block(key, decrypted_block, decrypt_len + strlen(password), _BLOCK_HASH);
	return 0;
}

/*
 * Finds the RSA block index based on the header challenge, and fills 'key' with the symmetric key.
 * If _CHALLENGE_HASH(_BLOCK_HASH(rsa_block)) == header.challenge, the block is found.
 */
static long int _find_block_slow(unsigned char* key, const char* encrypted_file, int header_end_offset, RSA* rsa, const char* password, CzarrapoHeader header) {
	FILE* efp;					/* Encrypted file handle */
	unsigned int block_size = RSA_size(rsa);	/* Size of blocks to decrypt */
	unsigned char rsa_block[block_size];		/* Buffer to store each read block */
	size_t i = -1;					/* Block index for each iteration */
	int amount_read;				/* Number of bytes read from file */
	unsigned char new_challenge[_CHALLENGE_SIZE];	/* Buffer to store computed challenge */

	/* Open file */
	if ( (efp = fopen(encrypted_file, "rb")) == NULL ) {
		_handle_RSA_error("[ERROR] Could not open encrypted file.\n", true, rsa, NULL);
	}

	fseek(efp, header_end_offset, SEEK_SET);
	while ( (amount_read = fread(rsa_block, sizeof(unsigned char), block_size, efp)) ) {

		++i;

		/* key = _BLOCK_HASH(RSA_decrypt(rsa_block) + password) */
		_print_hex_array(rsa_block, 5);
		if (_get_key_from_block(key, rsa, RSA_NO_PADDING, rsa_block, amount_read, password) == -1) {
			continue;
		}

		/* challenge = _CHALLENGE_HASH(key) */
		_hash_individual_block(new_challenge, key, _BLOCK_HASH_SIZE, _CHALLENGE_HASH);

		/* Compare with challenge read from header */
		if (memcmp(new_challenge, header.challenge, _CHALLENGE_SIZE) == 0) {
			fclose(efp);
			return i;
		}
	}

	fclose(efp);
	return -1;
}

/*
 * Finds the RSA block based on the auth header field, and fills 'key' with the symmetric key.
 * If _AUTH_HASH(header.challenge + block_index + password) == header.auth: the block is found.
 */
static long int _find_block_fast(unsigned char* key, const char* encrypted_file, int header_end_offset, RSA* rsa, const char* password, CzarrapoHeader header) {

	//_AUTH_HASH(challenge + selected_block_index + password))
	return 0;
}

static void _decrypt_file(const char* encrypted_file, const char* decrypted_file, RSA* rsa, long int selected_block_index, unsigned int block_size, const char* cipher_name, const unsigned char* key, const unsigned char* iv, int header_end_offset) {
	FILE *ifp, *ofp;			/* File handles for input and output files */
	unsigned char block[block_size];	/* Buffer for each read block */
	int amount_read, amount_written;	/* Variables to store results of fread() and fwrite() */
	int written_decipher_bytes;		/* RSA output length */
	size_t block_index = 0;			/*  */

	const EVP_CIPHER* cipher_type;		/* Cipher mode, selected with input parameter */
	EVP_CIPHER_CTX* evp_ctx;		/* Cipher context */

	/* Select cipher */
	if ( (cipher_type = EVP_get_cipherbyname(cipher_name)) == NULL ) {
		RSA_free(rsa);
		_handle_simple_error("[ERROR] Invalid symmetric cipher selected.\n");
	}

	/* Allocate and init cipher context */
	if ( (evp_ctx = EVP_CIPHER_CTX_new()) == NULL ) {
		RSA_free(rsa);
		_handle_simple_error("[ERROR] Could not allocate cipher context for file encryption.\n");
	}
	if ( (EVP_DecryptInit_ex(evp_ctx, cipher_type, NULL, key, iv)) != 1) {
		RSA_free(rsa);
		_handle_EVP_CIPHER_error("[ERROR] Could not init EVP cipher context.\n", true, evp_ctx, NULL, NULL);
	}

	/* Buffer for the decrypted block */
	unsigned char decipher_block[block_size + EVP_CIPHER_block_size(cipher_type) - 1];

	/* Open files */
	if ( (ifp = fopen(encrypted_file, "rb")) == NULL || (ofp = fopen(decrypted_file, "wb")) == NULL ) {
		RSA_free(rsa);
		_handle_EVP_CIPHER_error("[ERROR] Could not open encrypted or output file.\n", true, evp_ctx, NULL, NULL);
	}
	
	/* Decrypt each block */
	fseek(ifp, header_end_offset, SEEK_SET);
	while ( (amount_read = fread(block, sizeof(unsigned char), RSA_size(rsa), ifp)) ) {

		/* RSA block */
		if (block_index == selected_block_index) {
			int padding;

			/* Determine padding */
			if (block_size == RSA_size(rsa)) {
				padding = RSA_NO_PADDING;
			} else {
				padding = RSA_PKCS1_OAEP_PADDING;
			}

			/* Decrypt block */
			if ( (written_decipher_bytes = RSA_private_decrypt(RSA_size(rsa), block, decipher_block, rsa, padding)) < 0) {
				
				RSA_free(rsa);
				_handle_EVP_CIPHER_error("[ERROR] Could not decrypt RSA block.\n", true, evp_ctx, ifp, ofp);
			}

			/* Write to file */
			if ( (amount_written = fwrite(decipher_block, sizeof(unsigned char), written_decipher_bytes, ofp)) != written_decipher_bytes ) {
				RSA_free(rsa);
				_handle_EVP_CIPHER_error("[ERROR] Could not write decrypted RSA block to file.\n", true, evp_ctx, ifp, ofp);
			}

			
		/* Regular AES block */
		} else {

			/* Update with read data */
			if ( EVP_DecryptUpdate(evp_ctx, decipher_block, &written_decipher_bytes, block, amount_read) != 1 ) {
				RSA_free(rsa);
				char err_msg[ERR_MSG_BUF_SIZE];
				snprintf(err_msg, ERR_MSG_BUF_SIZE, "[ERROR] Failure encrypting block %lu.\n", block_index);
				_handle_EVP_CIPHER_error(err_msg, true, evp_ctx, ifp, ofp);
			}

			/* Write to file */
			if ( (amount_written = fwrite(decipher_block, sizeof(unsigned char), written_decipher_bytes, ofp)) != written_decipher_bytes) {
				RSA_free(rsa);
				char err_msg[ERR_MSG_BUF_SIZE];
				snprintf(err_msg, ERR_MSG_BUF_SIZE, "[ERROR] Failure writing block %lu to output file.\n", block_index);
				_handle_EVP_CIPHER_error(err_msg, true, evp_ctx, ifp, ofp);
			}
		}

		//printf("Block %lu (%s) %i bytes -> ", block_index, block_index==selected_block_index ? "rsa" : "aes", amount_read);
		//printf("written %i\n", amount_written);

		++block_index;
	}

	/* End symmetric cipher */
	if ( EVP_DecryptFinal_ex(evp_ctx, decipher_block, &written_decipher_bytes) != 1 ) {
		RSA_free(rsa);
		_handle_EVP_CIPHER_error("[ERROR] Failure decrypting final block.\n", true, evp_ctx, ifp, ofp);
	}

	/* Write remaining data to file */
	if ( (amount_written = fwrite(decipher_block, sizeof(unsigned char), written_decipher_bytes, ofp)) != written_decipher_bytes ) {
		RSA_free(rsa);
		_handle_EVP_CIPHER_error("[ERROR] Failure writing final block to output file.\n", true, evp_ctx, ifp, ofp);
	}

	fclose(ifp);
	fclose(ofp);
	EVP_CIPHER_CTX_free(evp_ctx);

}

static int _get_symmetric_key_from_block_index(unsigned char* key, const char* encrypted_file, int header_end_offset, RSA* rsa, const char* password, CzarrapoHeader header, long int selected_block_index) {
	FILE* ifp;
	unsigned int block_size = RSA_size(rsa);
	unsigned char rsa_block[block_size];
	int amount_read;

	if ( (ifp = fopen(encrypted_file, "rb")) == NULL) {
		return -1;
	}
	if (fseek(ifp, header_end_offset + (selected_block_index * block_size), SEEK_SET) != 0) {
		return -1;
	}
	if ( (amount_read = fread(rsa_block, sizeof(unsigned char), block_size, ifp)) < block_size ) {
		return -1;
	}
	fclose(ifp);

	return _get_key_from_block(key, rsa, RSA_NO_PADDING, rsa_block, amount_read, password);
}



void decrypt_file(const char* encrypted_file, const char* decrypted_file, const char* password, const char* private_key_file, const char* passphrase, long int selected_block_index) {
	RSA* rsa;						/* RSA struct for the private key */
	size_t file_size = _get_file_size(encrypted_file);	/* Size of the input file */
	unsigned char key[_BLOCK_HASH_SIZE];			/* Buffer to hold the key, to be filled when the selected block is found */
	unsigned int block_size;				/* Block size, determined by RSA key length */
	CzarrapoHeader header;					/* Struct to hold encrypted file header */
	int header_end_offset;					/* Offset of the beginning of actual encrypted data */

	if (password == NULL) {
		_handle_simple_error("[ERROR] Invalid password\n");
	}

	/* Load private key */
	if ( (rsa = _load_private_key(private_key_file, passphrase)) == NULL ) {
		_handle_simple_error("[ERROR] Could not open private key file.\n");
	}
	DEBUG_PRINT(("[DEBUG] Private key file at %s read correctly.\n", private_key_file));

	/* Determine block size */
	if ( (block_size = RSA_size(rsa)) > file_size ) {
		_handle_RSA_error("[ERROR] Encrypted file is too small.\n", true, rsa, NULL);
	}

	/* Read header information (fast, challenge, auth) */
	if ( (header_end_offset = _read_header(encrypted_file, &header)) < 0 ) {
		_handle_RSA_error("[ERROR] Could not read header from encrypted file.\n", true, rsa, NULL);
	}
	DEBUG_PRINT(("[DEBUG] File header read correctly (%i bytes).\n", header_end_offset));

	/* Determine RSA block index and retrieve symmetric key = _BLOCK_HASH(RSA_decrypt(selected_block)+password) */
	if ( selected_block_index < 0 ) {

		if (header.fast) {
			selected_block_index = _find_block_fast(key, encrypted_file, header_end_offset, rsa, password, header);
		} else {
			selected_block_index = _find_block_slow(key, encrypted_file, header_end_offset, rsa, password, header);
		}

		if (selected_block_index < 0) {
			_handle_RSA_error("[ERROR] Could not find RSA block.\n", true, rsa, NULL);
		}

	} else {

		if (selected_block_index * block_size > file_size) {
			char err_msg[ERR_MSG_BUF_SIZE];
			snprintf(err_msg, ERR_MSG_BUF_SIZE, "[ERROR] Maximum block index for current file is %lu\n", file_size/block_size);
			_handle_RSA_error(err_msg, true, rsa, NULL);
		}

		if (_get_symmetric_key_from_block_index(key, encrypted_file, header_end_offset, rsa, password, header, selected_block_index) < 0 ) {
			_handle_RSA_error("[ERROR] Could not read selected RSA block.\n", true, rsa, NULL);
		}
	}
	DEBUG_PRINT(("[DEBUG] Selected block index is %lu.\n", selected_block_index));

	/* Decrypt file with challenge as IV */
	_decrypt_file(encrypted_file, decrypted_file, rsa, selected_block_index, block_size, _SYMMETRIC_CIPHER, key, header.challenge, header_end_offset);
	DEBUG_PRINT(("[DEBUG] File decrypted correctly at %s.\n", decrypted_file));

	RSA_free(rsa);
}