# czarrapo #

czarrapo (derived from [giltzarrapo](https://hiztegiak.elhuyar.eus/eu/giltzarrapo]), *padlock*) is a file encryption library with a very simple public API. It solves the problem of delivering a symmetric key to perform cipher operations, and at the same time avoids using assymetric ciphers for great amounts of data, which can in turn become slow.

## Dependencies ##
* OpenSSL 1.1.1 (`apt install openssl-dev`)

## Compilation and use ##
czarrapo can be compiled as a static or shared library. This repository includes also an [example program](src/main.c) which uses the static library, as well as as [two Python programs](examples/) which make use of the shared library.

### Using the example program ###
1. Clone repository: `git clone https://github.com/vLabayen/czarrapo.git --recursive`
2. Generate a random 1MB file with `make testfile`. Use a different size with `make testfile test_file_size=5M`.
3. Compile test program: `make`. To output additional information during execution, use: `make flags=-DDEBUG`
4. Run the program: `./czarrapo`
5. Compare the original, encrypted and decrypted file: `md5sum test/test.*`
6. Clean up test files and compiled objects: `make clean`

### Using the Python program ###
[giltzarrapo.py](examples/giltzarrapo.py) contains a class that acts as a wrapper (given the shared library) to use the public API from Python. [benchmark.py](examples/benchmark.py) uses this wrapper to encrypt and decrypt several files and report results. Example output:
```
$ python3 examples/benchmark.py 
*** RUNNING 10 TESTS ***
 *** Using files with size: 10M ***
######################################################|
[*] Successful tests: 10/10
[*] Total encryption time: 0.126 seconds (79.177 files/second)
[*] Total decryption time: 1.261 seconds (7.93 files/second)
[*] Encryption time: avg: 0.013; max: 0.013; min: 0.012
[*] Decryption time: avg: 0.126; max: 0.198; min: 0.02
[*] Encryption throughput: avg: 792.6 MiB/s; max: 853.1 MiB/s; min: 745.6 MiB/s
[*] Decryption throughput: avg: 145.6 MiB/s; max: 492.1 MiB/s; min: 50.4 MiB/s
```

### Compiling as a static library ###
1. Compile as a static library: `make static`
2. Compile your program: `gcc -I <path to czarrapo/src> yourprogram.c libczarrapo.a -lcrypto -lssl -lm -pthread`.

### Compiling as a shared library ###
1. Compile as a shared library: `make shared`
2. Link against it like with any shared library. An example on how to do so with Python can be found in [giltzarrapo.py](examples/giltzarrapo.py).

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
* Add parallel encryption and decryption for big files.