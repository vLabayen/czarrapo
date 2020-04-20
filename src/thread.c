#include <stdlib.h>
#include <string.h>

#ifndef __STDC_NO_THREADS__

#include "thread.h"

/* Allocates and initializes queue node */
inline static _tlock_node_t* _tlock_node_init(void* value, _tlock_node_t* next) {
	_tlock_node_t* node;

	if ( (node = malloc(sizeof(_tlock_node_t))) == NULL )
		return NULL;

	node->value = value;
	node->next = next;

	return node;
}

/* Frees queue node */
inline static void _tlock_node_free(_tlock_node_t* node) {
	free(node);
}

/* Initializes queue */
tlock_queue_t* tlock_init() {
	tlock_queue_t* queue;
	_tlock_node_t* free_node;

	/* Allocate queue */
	if ( (queue = malloc(sizeof(tlock_queue_t))) == NULL )
		return NULL;

	/* Allocate mutexes */
	if ( (queue->first_mutex = malloc(sizeof(mtx_t))) == NULL ) {
		free(queue);
		return NULL;
	}
	if ( (queue->last_mutex = malloc(sizeof(mtx_t))) == NULL ) {
		free(queue->first_mutex);
		free(queue);
		return NULL;		
	}

	/* Initialize mutexes */
	if (mtx_init(queue->first_mutex, mtx_plain) != thrd_success || mtx_init(queue->last_mutex, mtx_plain) != thrd_success) {
		tlock_free(queue);
		return NULL;
	}

	/* Allocate dummy node */
	if ( (free_node = _tlock_node_init(NULL, NULL)) == NULL ) {
		tlock_free(queue);
		return NULL;
	}

	/* Initialize ends of queue */
	queue->first = free_node;
	queue->last = free_node;

	return queue;
}

/* Frees queue resources. Assumes the queue is depleted */
void tlock_free(tlock_queue_t* queue) {

	/* Free the dummy node */
	if (queue->first != NULL) {
		free(queue->first);
	}

	/* Destroy and free mutexes */
	if (queue->first_mutex != NULL ){
		mtx_destroy(queue->first_mutex);
		free(queue->first_mutex);
	}
	if (queue->last_mutex != NULL) {
		mtx_destroy(queue->last_mutex);
		free(queue->last_mutex);
	}

	free(queue);
}

/* Push at the end of the queue */
int tlock_push(tlock_queue_t* queue, void* new_element) {
	_tlock_node_t* node;

	/* Prepare new node */
	if ( (node = _tlock_node_init(new_element, NULL)) == NULL )
		return PUSH_FAILURE;

	/* Add to queue with lock */
	mtx_lock(queue->last_mutex);
	queue->last->next = node;
	queue->last = node;
	mtx_unlock(queue->last_mutex);

	return PUSH_OK;
}

/* Pop from beginning of queue */
void* tlock_pop(tlock_queue_t* queue) {
	_tlock_node_t* node;
	_tlock_node_t* new_header;
	void* return_value;

	mtx_lock(queue->first_mutex);
	
	node = queue->first;
	new_header = queue->first->next;

	/* Queue empty */
	if (new_header == NULL) {
		mtx_unlock(queue->first_mutex);
		return NULL;
	}

	/* Queue not empty */
	return_value = new_header->value;
	queue->first = new_header;

	mtx_unlock(queue->first_mutex);

	/* Free note struct and return */
	_tlock_node_free(node);
	return return_value;
}

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
	if ( (thread_context->ctx = czarrapo_init(NULL, NULL, NULL, ctx->password, ctx->fast)) == NULL ) {
		free(thread_context);
		return NULL;
	}

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