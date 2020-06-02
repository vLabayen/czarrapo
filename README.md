# czarrapo #

## Description ##
czarrapo (derived from [giltzarrapo](https://hiztegiak.elhuyar.eus/eu/giltzarrapo]), *padlock*) is a file encryption library with a very simple public API. It solves the problem of delivering a symmetric key to perform cipher operations, and at the same time avoids using assymetric ciphers for great amounts of data, which can in turn become slow.

## Dependencies ##
* OpenSSL 1.1.1 (`apt install openssl-dev`)

## Compiling and running a test ##
1. Generate test file for encryption and decryption.
	* `make testfile` (defaults to file size of 1 MB)
	* `make testfile test_file_size=5M` (5 MB)
2. Compile program:
	* Standard compilation: `make`
	* Compile with debug messages during execution: `make debug`
	* Specify number of threads when using slow mode: `make num_threads=4`, `make debug num_threads=4`
3. Run test program: `bin/czarrapo`
4. Compare original and decrypted file: `md5sum test/test.txt; md5sum test/test.decrypt`
5. Clean up test files, compiled binary and RSA keypair: `make clean`

NOTE: the source code an also be compiled as a shared library for external use: `make shared`

## Usage ##
The main example is written in [main.c](src/main.c). The API consists of the following functions:

```C
/*
 * Generates RSA public and private keys with the specified passphrase. Saves them to directory/key_name and
 * directory/key_name.pub
 * RETURNS: zero on success, negative value on error.
 */
int generate_RSA_pair_to_files(char* passphrase, const char* directory, const char* key_name, int keylen);

/*
 * Initializes an encryption/decryption context. The private key can be omitted for only-encryption operations; the
 * public key can be omitted for only-decryption operations. Uses a passphrase to open the private key, and a user
 * password to perform file cipher operations. The context returned must be freed by the caller with czarrapo_free().
 * RETURNS: a pointer to a CzarrapoContext struct on success, NULL on failure.
 */
CzarrapoContext* czarrapo_init(const char* public_key_file, const char* private_key_file, const char* passphrase,
	const char* password, bool fast_mode);

/*
 * Performs a deep copy on an encryption/decryption context. The context returned must be freed by the caller with
 * czarrapo_free().
 * RETURNS: a pointer to an identical copy of the original context, NULL on failure.
 */
CzarrapoContext* czarrapo_copy(const CzarrapoContext* ctx);

/*
 * Frees a context struct and zeroes-out the user password.
 * RETURNS: nothing.
 */
void czarrapo_free(CzarrapoContext* ctx);

/*
 * Ciphers a plaintext file into an encrypted file. Needs a context, and optionally takes a manually selected block
 * index to use during encryption. The block index can be set to a negative value so it is selected automatically.
 * RETURNS: zero on success, negative value on error.
 */
int czarrapo_encrypt(CzarrapoContext* ctx, const char* plaintext_file, const char* encrypted_file,
	long long int selected_block_index);

/*
 * Deciphers a file into a plaintext file. Needs a context, and optionally takes a manually selected block to use during
 * decryiption. It needs to be the same block selected during encryption. This value can be negative so the block is
 * found automatically.
 * RETURNS: zero on success, negative value on error.
 */
int czarrapo_decrypt(CzarrapoContext* ctx, const char* encrypted_file, const char* decrypted_file,
	long long int selected_block_index);

```

## TO-DO ##
* If selected_block_index is passed in with a valid value, check the block with `__check_block_bn()` before using it.
* Better random block selection (in `_select_block()`). Do not use max. entropy as criterion.
* Add error codes for different types of errors (currently the public API just returns -1 on error).
* Better interrupt handling (SIGINT and SIGTERM on Linux).
* Parallel encryption and decryption for big files.