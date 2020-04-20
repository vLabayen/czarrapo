#ifndef _CZTHREAD_H
#define _CZTHREAD_H

/* Standard library */
#include <stdbool.h>
#include <threads.h>

/* Internal modules */
#include "common.h"
#include "context.h"

#define PUSH_FAILURE -2		/* Error pushing value into queue */
#define PUSH_OK 0		/* Value pushed correctly */

/* Queue node. For internal use only */
typedef struct {
	void* value;
	void* next;
} _tlock_node_t;

/* Concurrent queue */
typedef struct {
	_tlock_node_t* first;
	_tlock_node_t* last;
	mtx_t* first_mutex;
	mtx_t* last_mutex;
} tlock_queue_t;

/* Initialization and free functions */
tlock_queue_t* tlock_init();
void tlock_free(tlock_queue_t* queue);

/* Add and remove elements from queue */
int tlock_push(tlock_queue_t* queue, void* new_element);
void* tlock_pop(tlock_queue_t* queue);

/* Struct and functions for the actual data passed to the queue */
typedef struct {
	unsigned char* block;
	long long int index;
	int size;
} thread_data_t;
thread_data_t* __thread_data_init(int block_size, long long int index);
void __thread_data_free(thread_data_t* thread_data);

/* Struct and functions for the inital data passed to each processing thread */
typedef struct {
	unsigned char* output;
	long long int* output_index;
	tlock_queue_t* queue;
	const CzarrapoHeader* header;
	CzarrapoContext* ctx;
} thread_context_t;
thread_context_t* __thread_context_init(unsigned char* output, long long int* output_index, tlock_queue_t* queue, const CzarrapoContext* ctx, const CzarrapoHeader* header);
void __thread_context_free(thread_context_t* thread_context);

/* Struct and functions for the inital data passed to the file read thread */
typedef struct {
	const char* input_file;
	tlock_queue_t* queue;
	const CzarrapoHeader* header;
	int block_size;
} reader_data_t;
reader_data_t* __reader_data_init(const char* input_file, int block_size, tlock_queue_t* queue, const CzarrapoHeader* header);
void __reader_data_free(reader_data_t* reader_data);

#endif