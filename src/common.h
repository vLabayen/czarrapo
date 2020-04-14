/*
 * This file contains a series of constant values that are required in several files.
 */

#include <stdbool.h>

/* Prints if DEBUG compilation flag is set */
#ifdef DEBUG
# define DEBUG_PRINT(x) printf x
#else
# define DEBUG_PRINT(x) do {} while (0)
#endif

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
#define _SYMMETRIC_CIPHER	"AES-256-CFB"

/* Return value for failure */
#define ERR_FAILURE		-1

/* Encrypted file header */
typedef struct {
	bool fast;
	unsigned char challenge[_CHALLENGE_SIZE];
	unsigned char auth[_AUTH_SIZE];
	int end_offset;
} CzarrapoHeader;

/* Utility function to get a file size */
long int _get_file_size(const char* filename);

/* Utility function to hash an input buffer into an output buffer, using 'hash_name' as a hashing function */
int _hash_individual_block(unsigned char* output, const unsigned char* input, int input_size, const char* hash_name);

void _hexarr(const unsigned char* arr, int len);