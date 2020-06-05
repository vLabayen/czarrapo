/* Standard library */
#include <string.h>
#ifndef __STDC_NO_THREADS__
	#include <threads.h>
#endif

/* OpenSSL */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

/* Internal modules */
#include "common.h"
#include "decrypt.h"
#ifndef __STDC_NO_THREADS__
	#include "thread.h"
	#ifndef NUM_THREADS
		#define NUM_THREADS 7
	#endif
#endif

static int _read_header(CzarrapoHeader* header, const char* encrypted_file) {
	FILE* efp;

	/* Open file */
	if ((efp = fopen(encrypted_file, "rb")) == NULL)
		return ERR_FAILURE;

	/* Read fast flag */
	if ( (fread(&(header->fast), sizeof(bool), 1, efp)) < sizeof(bool)) {
		fclose(efp);
		return ERR_FAILURE;
	}

	/* Read challenge */
	if ( (fread(header->challenge, sizeof(unsigned char), _CHALLENGE_SIZE, efp)) < (sizeof(unsigned char) * _CHALLENGE_SIZE)) {
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
	unsigned char decrypted_block[RSA_size(ctx->private_rsa) + MAX_PASSWORD_LENGTH];

	/* Decrypt RSA block */
	if ( (decrypt_len = RSA_private_decrypt(input_len, input_block, decrypted_block, ctx->private_rsa, padding)) < 0 ) {
		return ERR_FAILURE;
	}

	/* Concatenate with password and get block hash (aka symmetric key) */
	memcpy(&decrypted_block[decrypt_len], ctx->password, MAX_PASSWORD_LENGTH);
	if (_hash_individual_block(output, decrypted_block, decrypt_len + MAX_PASSWORD_LENGTH, _BLOCK_HASH) == ERR_FAILURE) {
		return ERR_FAILURE;
	}
	return 0;
}

/* Computes the symmetric key from a given block index */
static int _get_symmetric_key_from_block_index(unsigned char* key, CzarrapoContext* ctx, const char* encrypted_file, const CzarrapoHeader* header, long long int selected_block_index) {
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
		fclose(ifp);
		return ERR_FAILURE;
	}
	fclose(ifp);

	/* Try to compute the symmetric key from the read block */
	return __get_key_from_block(key, ctx, RSA_NO_PADDING, rsa_block, amount_read);
}

#ifndef __STDC_NO_THREADS__

static int _find_block_slow_worker(void* thread_context_ptr) {

	#ifdef DEBUG
	int exit_status = 0;
	#endif
	
	/* Retrieve context */
	thread_context_t* thread_context = (thread_context_t*) thread_context_ptr;
	thread_data_t* thread_data;

	unsigned char local_output[_BLOCK_HASH_SIZE];	/* Buffer to be filled by __get_key_from_block() */
	unsigned char new_challenge[_CHALLENGE_SIZE];	/* Buffer to be filled by  _hash_individual_block() */

	DEBUG_PRINT(("[DEBUG] Starting main loop @ thread %li\n", thrd_current()));

	while (true) {

		if ( (thread_data = tlock_pop(thread_context->queue)) != NULL ) {

			/* Break loop on kill signal */
			if (thread_data->block == NULL) {
				__thread_data_free(thread_data);
				break;
			}

			/* Do not process block if search is done */
			if (*(thread_context->output_index) < 0) {

				/* local_output = _BLOCK_HASH(RSA_decrypt(block) + ctx->password) */
				if (__get_key_from_block(local_output, thread_context->ctx, RSA_NO_PADDING, thread_data->block, thread_data->size) == ERR_FAILURE) {
					__thread_data_free(thread_data);
					continue;
				}

				/* new_challenge = _CHALLENGE_HASH(local_output) */
				if (_hash_individual_block(new_challenge, local_output, _BLOCK_HASH_SIZE, _CHALLENGE_HASH) == ERR_FAILURE) {
					__thread_data_free(thread_data);
					continue;
				}

				/* Compare with challenge read from header. If found, copy found block index and computed key to their expected locations */
				if (memcmp(new_challenge, thread_context->header->challenge, _CHALLENGE_SIZE) == 0) {
					memcpy(thread_context->output, local_output, _BLOCK_HASH_SIZE);
					memcpy(thread_context->output_index, &thread_data->index, sizeof(long long int));

					#ifdef DEBUG
					exit_status = 1;
					#endif
				}
			}

			__thread_data_free(thread_data);
		}
	}

	DEBUG_PRINT(("[DEBUG] Exiting @ thread %li (found block: %s)\n", thrd_current(), exit_status ? "yes": "no"));
	__thread_context_free(thread_context);
	thrd_exit(0);
}

static int _find_block_slow_reader(void* reader_data_ptr) {
	reader_data_t* reader_data = (reader_data_t*) reader_data_ptr;
	int amount_read;
	long long int index = 0;
	thread_data_t* thread_data;
	FILE* efp;

	DEBUG_PRINT(("[DEBUG] Starting file read @ thread %li\n", thrd_current()));

	/* Open file */
	if ( (efp = fopen(reader_data->input_file, "rb")) == NULL ) {
		__reader_data_free(reader_data);
		thrd_exit(ERR_FAILURE);
	}

	/* Move pointer to beginning of data */
	if ( fseek(efp, reader_data->header->end_offset, SEEK_SET) != 0 ){
		__reader_data_free(reader_data);
		thrd_exit(ERR_FAILURE);
	}

	/* Read file into heap-allocated structs */
	thread_data = __thread_data_init(reader_data->block_size, index);
	while ( (amount_read = fread(thread_data->block, sizeof(unsigned char), reader_data->block_size, efp)) ) {

		/* Update with amount read and push to queue */
		thread_data->size = amount_read;
		tlock_push(reader_data->queue, thread_data);

		/* Prepare next item */
		thread_data = __thread_data_init(reader_data->block_size, ++index);
	}
	fclose(efp);
	__thread_data_free(thread_data);

	/* Send kill signals */
	for (int i=0; i<NUM_THREADS; ++i) {
		thread_data = __thread_data_init(0, i - 2*i -1);
		tlock_push(reader_data->queue, thread_data);
	}

	/* Free resources and exit */
	__reader_data_free(reader_data);
	thrd_exit(0);
}

/* Finds the RSA block and gets the symmetric key from it, using SLOW mode. Uses C11 threads. */
static int _find_block_slow_threads(unsigned char* output, CzarrapoContext* ctx, const char* encrypted_file, const CzarrapoHeader* header) {
	int block_size = RSA_size(ctx->private_rsa);	/* Size of blocks to decrypt */
	
	thrd_t threads[NUM_THREADS+1];			/* Array of threads */
	thread_context_t* thread_context;		/* Initial data passed to thread */
	tlock_queue_t* queue;				/* Synchronized queue */
	int res;					/* Thread exit status */

	/* Threads will store the found index here. there should only be one result, so no need to make it atomic */
	long long int output_index = -1;		

	/* Initialize queue */
	if ( (queue = tlock_init()) == NULL )
		return ERR_FAILURE;

	/* Start file reading thread */
	reader_data_t* reader_data = __reader_data_init(encrypted_file, block_size, queue, header);
	if ( thrd_create(&threads[0], _find_block_slow_reader, reader_data) != thrd_success ) {
		return ERR_FAILURE;
	}

	/* Start processing threads, each with its context */
	DEBUG_PRINT(("[DEBUG] Starting %i threads for block search.\n", NUM_THREADS));
	for (int i=1; i<NUM_THREADS+1; ++i) {
		if ( (thread_context = __thread_context_init(output, &output_index, queue, ctx, header)) == NULL ) {
			printf("[ERROR] Could not init context for thread %i.\n", i);
			continue;
		}
		if ( thrd_create(&threads[i], _find_block_slow_worker, thread_context) != thrd_success ){
			printf("[ERROR] Could not start thread %i\n", i);
			__thread_context_free(thread_context);
			continue;
		}
	}

	/* Join file read thread */
	if ( thrd_join(threads[0], &res) != thrd_success) {
		;;
	}
	DEBUG_PRINT(("[DEBUG] Reading thread exited %s.\n", !res ? "successfully": "with error"));

	/* Join processing threads */
	for (int i=1; i<NUM_THREADS+1; ++i) {
		if ( thrd_join(threads[i], NULL) != thrd_success )
			continue;
	}

	/* Free queue */
	tlock_free(queue);

	if (output_index >= 0)
		return output_index;
	return ERR_FAILURE;
}

#else

/* Finds the RSA block and gets the symmetric key from it, using SLOW mode */
static int _find_block_slow(unsigned char* output, CzarrapoContext* ctx, const char* encrypted_file, const CzarrapoHeader* header) {
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

#endif

/* Finds the RSA block and gets the symmetric key from it, using FAST mode */
static int _find_block_fast(unsigned char* output, CzarrapoContext* ctx, const char* encrypted_file, const CzarrapoHeader* header) {
	int block_size = RSA_size(ctx->private_rsa);			/* Size of blocks to decrypt */
	long long int* index;						/* Index for the block search */
	long long int file_size = _get_file_size(encrypted_file);	/* Size of input file */
	int num_blocks;

	unsigned char pre_auth[_CHALLENGE_SIZE + sizeof(long long int) + MAX_PASSWORD_LENGTH];	/* Buffer for the hash input */
	unsigned char new_auth[_AUTH_SIZE];							/* Buffer for the hash output */

	/* Prepare input buffer: pre_auth = challenge + index (to be filled) + password */
	memcpy(&pre_auth[0], header->challenge, _CHALLENGE_SIZE);
	memcpy(&pre_auth[_CHALLENGE_SIZE + sizeof(long long int)], ctx->password, MAX_PASSWORD_LENGTH);

	/* Compute number of blocks */
	num_blocks = (file_size - header->end_offset) / block_size;
	if ( ((file_size - header->end_offset) % block_size) > 0 ) {
		++num_blocks;
	}

	/*
	 * Index points to the location in the pre_auth buffer that will hold the block index.
	 * The layout is the following:
	 * [challenge (_CHALLENGE_SIZE)] [index (sizeof(long long int))] [password (MAX_PASSWORD_LEN)]
	 */
	index = (long long int*) &pre_auth[_CHALLENGE_SIZE];

	/* Try with different values for the index */
	for (*index=0; *index < num_blocks; ++(*index)) {

		// Hash into auth
		if (_hash_individual_block(new_auth, pre_auth, sizeof(pre_auth), _AUTH_HASH) == ERR_FAILURE) {
			return ERR_FAILURE;
		}

		// If auth matches, compute symmetric key for this block
		if (memcmp(header->auth, new_auth, _AUTH_SIZE) == 0 ){
			// output = _BLOCK_HASH(RSA_decrypt(file_blocks[index]) + ctx->password)
			if (_get_symmetric_key_from_block_index(output, ctx, encrypted_file, header, *index) == ERR_FAILURE) {
				return ERR_FAILURE;
			}
			return *index;
		}
	}

	return ERR_FAILURE;
}

/* Decrypts input and saves to output. */
static int _decrypt_file(CzarrapoContext* ctx, const char* encrypted_file, const char* decrypted_file, const unsigned char* key, const CzarrapoHeader* header, long long int selected_block_index) {
	FILE *ifp, *ofp;				/* File handles for input and output files */
	int block_size = RSA_size(ctx->private_rsa);	/* Size of each read block */
	unsigned char block[block_size];		/* Buffer for each read block */
	long long int index = -1;			/* Index of each read block */
	int amount_read, amount_written;		/* Variables to store results of fread() and fwrite() */
	int written_decipher_bytes;			/* Cipher output length */

	const EVP_CIPHER* cipher_type;			/* Cipher mode, selected with input parameter */
	EVP_CIPHER_CTX* evp_ctx;			/* Cipher context */

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
	if ((ifp = fopen(encrypted_file, "rb")) == NULL) {
		EVP_CIPHER_CTX_free(evp_ctx);
		return ERR_FAILURE;
	}
	if ((ofp = fopen(decrypted_file, "wb")) == NULL) {
		fclose(ifp);
		EVP_CIPHER_CTX_free(evp_ctx);
		return ERR_FAILURE;
	}

	/* Decrypt each block */
	setvbuf(ofp, NULL, _IOFBF, 16384);
	fseek(ifp, header->end_offset, SEEK_SET);
	while ( (amount_read = fread(block, sizeof(unsigned char), block_size, ifp)) ) {

		++index;

		/* RSA block */
		if (index == selected_block_index) {

			/* Decrypt block */
			if ( (written_decipher_bytes = RSA_private_decrypt(amount_read, block, decipher_block, ctx->private_rsa, RSA_NO_PADDING)) < 0) {
				int ecode = ERR_get_error();
 				char* err_msg = ERR_error_string(ecode, NULL);
 				fprintf(stderr, "[ERROR] %s\n", err_msg);

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
	if (ctx->private_rsa == NULL)
		return ERR_FAILURE;

	/* Get file and block size */
	if ( (file_size = _get_file_size(encrypted_file)) == ERR_FAILURE)
		return ERR_FAILURE;
	if ( (block_size = RSA_size(ctx->private_rsa)) > file_size)
		return ERR_FAILURE;
	DEBUG_PRINT(("[DEBUG] Selected %s for decryption, size of %lld bytes.\n", encrypted_file, file_size));

	/* Read header information (fast, challenge, auth) */
	if ( _read_header(&header, encrypted_file) == ERR_FAILURE ) {
		return ERR_FAILURE;
	}
	DEBUG_PRINT(("[DEBUG] File header read correctly (%i bytes).\n", header.end_offset));

	/* Determine RSA block index and retrieve symmetric key = _BLOCK_HASH(RSA_decrypt(selected_block)+password) */
	if ( selected_block_index < 0 ) {
		if (header.fast) {
			selected_block_index = _find_block_fast(key, ctx, encrypted_file, &header);
		} else {
			#ifndef __STDC_NO_THREADS__
			DEBUG_PRINT(("[DEBUG] C11 threads support found.\n"));
			selected_block_index = _find_block_slow_threads(key, ctx, encrypted_file, &header);
			#else
			DEBUG_PRINT(("[DEBUG] C11 threads support not found.\n"));
			selected_block_index = _find_block_slow(key, ctx, encrypted_file, &header);
			#endif
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
