#include <stdlib.h>
#include <string.h>

#ifndef __STDC_NO_THREADS__

#include "thread.h"

thread_data_t* __thread_data_init(int block_size, long long int index) {
	thread_data_t* thread_data = malloc(sizeof(thread_data_t));

	if (block_size > 0) { 
		thread_data->block = malloc(block_size);
	} else {
		thread_data->block = NULL;
	}

	thread_data->index = index;

	return thread_data;
}

void __thread_data_free(thread_data_t* thread_data) {
	if (thread_data->block != NULL) {
		free(thread_data->block);
	}
	free(thread_data);
}

thread_context_t* __thread_context_init(unsigned char* output, long long int* output_index, tlock_queue_t* queue, const CzarrapoContext* ctx, const CzarrapoHeader* header){
	thread_context_t* thread_context;

	if ( (thread_context = malloc(sizeof(thread_context_t))) == NULL )
		return NULL;

	thread_context->output = output;
	thread_context->output_index = output_index;
	thread_context->queue = queue;
	thread_context->header = header;

	/* Init a new context with no RSA keys */
	if ( (thread_context->ctx = czarrapo_init(NULL, NULL, NULL, ctx->password, ctx->fast)) == NULL ) {
		free(thread_context);
		return NULL;
	}

	/* Manually copy the private key */
	if ( (thread_context->ctx->private_rsa = RSAPrivateKey_dup(ctx->private_rsa)) == NULL ) {
		czarrapo_free(thread_context->ctx);
		free(thread_context);
		return NULL;
	}

	return thread_context;
}

void __thread_context_free(thread_context_t* thread_context) {
	czarrapo_free(thread_context->ctx);
	free(thread_context);
}

reader_data_t* __reader_data_init(const char* input_file, int block_size, tlock_queue_t* queue, const CzarrapoHeader* header) {
	reader_data_t* reader_data = malloc(sizeof(reader_data_t));

	reader_data->input_file = input_file;
	reader_data->block_size = block_size;
	reader_data->queue = queue;
	reader_data->header = header;

	return reader_data;
}

void __reader_data_free(reader_data_t* reader_data) {
	free(reader_data);
}

#endif