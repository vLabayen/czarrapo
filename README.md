# czarrapo #

## Description ##
czarrapo is a file encryption engine which uses RSA, AES and several hashing functions underneath. It solves the problem of delivering a symmetric key to encrypt/decrypt files, and also avoids using asymmetric ciphers for great amounts of data, which can in turn become slow.

## Compiling and running a test ##
1. Generate test file for encryption and decryption:
`make testfile`
2. Compile program:
	* Standard compilation: `make` or `make czarrapo`
	* Compile specifying number of threads in slow mode: `make num_threads=4`
	* Compile with additional debug printing (can also take a number of threads): `make debug`
3. Run test program: `bin/czarrapo`
4. Compare original and decrypted file:\
`md5sum test/test.txt; md5sum test/test.decrypt`
5. Clean up RSA keypair, test files and output binary: `make clean`

## Usage ##
The main example is written in `src/main.c`. The API consists of 5 functions:

### `generate_RSA_pair_to_files()` ###
This function generates an RSA keypair from a passphrase, an output directory, an output file name and a key size. For example:
```
generate_RSA_pair_to_files("passphrase", "my_keys/", "my_rsa", 4096);
```
Will generate `my_keys/my_rsa` (private key) and `my_keys/my_rsa.pub` (public key). This function is optional, as you can supply your own keypair for the rest of the operations.

### `czarrapo_init()` and `czarrapo_free()` ###
The first function initializes a context struct to be passed to the encryption and decryption routines. This allows the client code to pass in several parameters just once for any amount of files, namely the RSA keypair location (with their associated passphrase), the user password and the block search mode (fast/slow). It returns NULL on failure.

Note that it can be initialized with only one half of the keypair. That is, either the public or the private key can be omitted (by passing `NULL`). This is useful if you just want to do one type of operation. For example, if you want to encrypt several files but not decrypt them, you can omit the private key.

After the struct has been used to encrypt or decrypt any amount of files, it should be freed with `czarrapo_free()`. Does not return any value.

### `czarrapo_encrypt()` ###
This function takes a context (initialized with `czarrapo_init()`), a plaintext file, the desired name of the encrypted file, and a selected block to perform encryption with. If the user does not want to select the block manually, a negative value can be passed in its place and one will be selected automatically.

Returns a negative value on error.

### `czarrapo_decrypt()` ###
The parameters are analogue to the encryption function: a context, an encrypted file, an output file, and a manually selected block. Again, this last value can be negative.

Returns a negative value on error.
