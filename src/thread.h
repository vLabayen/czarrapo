#ifndef _CZTHREAD_H
#define _CZTHREAD_H

/* Standard library */
#include <stdbool.h>
#include <threads.h>

/* Internal modules */
#include "common.h"
#include "context.h"
#include "tlock-queue/src/tlock_queue.h"

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