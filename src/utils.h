
/*
 * This file contains declarations for several varied functions used throughout the code.
 * The general rule is to declare functions inside the files they are used as static, unless
 * they are going to be used by several modules of the program, in which case they can be 
 * placed here.
 */

#include <stdio.h>
#include <stdbool.h>

/* Returns true if input is a power of 2 */
bool _ispowerof2(unsigned int x);

/* Returns file size in bytes for a given filename */
size_t _get_file_size(char* filename);

/*
 * Hashes array 'input' of size 'input_size' with hash 'hash_name'. Fills 'block_hash' with the result.
 * This function is generic enough to support any hash, as long as the caller has enough size to receive
 * the output in 'block_hash'.
 */
void _hash_individual_block(unsigned char* block_hash, const unsigned char* input, int input_size, const char* hash_name);

/*
 * Prints 'len' bytes of the buffer 'arr' with hex representation.
 * Should probably only be used for debugging purposes.
 */
void _print_hex_array(unsigned char* arr, size_t len);