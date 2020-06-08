# czarrapo #

czarrapo (derived from [giltzarrapo](https://hiztegiak.elhuyar.eus/eu/giltzarrapo]), *padlock*) is a file encryption library with a very simple public API. It solves the problem of delivering a symmetric key to perform cipher operations, and at the same time avoids using assymetric ciphers for great amounts of data, which can in turn become slow.

## Dependencies ##
* OpenSSL 1.1.1 (`apt install openssl-dev`)

## Compilation and use ##
NOTE: do not forget to add `--recusive` to `git clone`.
### Test program ###
The test program generates a RSA keypair, encrypts a file and then decrypts it. To run it:
1. Generate an random file for encryption:
	* `make testfile` (defaults to file size of 1 MB)
	*  Select a different size: `make testfile test_file_size=5M`
2. Compile program:
	* Standard compilation: `make`
	* Compile with debug messages during execution: `make debug`
3. Run the test program: `bin/czarrapo`
4. Compare original and decrypted file: `md5sum test/test.txt; md5sum test/test.decrypt`
5. Clean up test files, compiled binary and RSA keypair: `make clean`

### As a shared library ###
To compile as a shared library to use from your own code, use `make shared`. An example on how to use as a shared library from Python can be found in [giltzarrapo.py](examples/giltzarrapo.py).

### Running a benchmark ###
An example benchmark is included in [benchmarks.py](examples/benchmark.py). Sample output:
```
$ python3 examples/benchmark.py 
 *** RUNNING 10 TESTS ***
 *** Using files with size: 5M ***
######################################################|
[*] Errors: 0/10
[*] Total encryption time: 1.034 seconds (9.668 files/second)
[*] Total decryption time: 1.346 seconds (7.43 files/second)
[*] Encryption time: avg: 0.103; max: 0.128; min: 0.094
[*] Decryption time: avg: 0.135; max: 0.225; min: 0.118
[*] Encryption throughput: avg: 48.9 MiB/s; max: 53.4 MiB/s; min: 39.1 MiB/s
[*] Decryption throughput: avg: 38.4 MiB/s; max: 42.4 MiB/s; min: 22.2 MiB/s
```

## Public API ##
The main example is written in [main.c](src/main.c). The API consists of the following functions:

```C
/*
 * Generates RSA public and private keys with the specified passphrase. Keylen is the RSA modulus size.
 * RETURNS: zero on success, negative value on error.
 */
int generate_RSA_keypair(char* passphrase, const char* pubkey, const char* privkey, int keylen);

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
* Add error codes for different types of errors (currently the public API just returns -1 on error).
* Better interrupt handling (SIGINT and SIGTERM on Linux).
* Parallel encryption and decryption for big files.