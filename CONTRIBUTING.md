Contributing to `dheluks`
=========================


Overview
--------

At the heart of the `dheluks` protocol sits the `dheluks` library, which is split into declarations (`dheluks.h	`) and definitions (`dheluks.c`). The following guide is meant to illustrate the inner-workings of the library, and so enable the reader to expand, improve, or replace aspects of the library’s functionality. The guide assumes knowledge of the basic `dheluks` specification, which can be found in README.md. Please document any proposed changes. 


Error Handling
------------------------

Because of the sensitive positioning of the `dheluks` protocol (within a boot-time function that grants or denies access to the disk), comprehensive error handling is a top priority. Functions that contain operations with the potential to produce a fatal error return a generic error flag (currently -1 on error and 0 on success) that indicates an operational failure or incompletion. Specific operational errors usually produce a more detailed error message, which is logged to stderr. Each error has a corresponding `is_err` error check function, which takes in the object to be checked (and sometimes a message), and returns true if there is an error and false if not. `dheluks` operations can produce the following errors:

* `ERR_NUL`: produced when a pointer is null. The corresponding error check function prototype is `bool not_valid(void *ptr)`.

* `ERR_SZE`: produced when the size of an object does not match expectation. The corresponding error check function prototype is `bool not_size(size_t act, size_t exp, char *msg)`. Another size check comes from the function `bool not_block(size_t size)`, which returns true if the inputted size is not a multiple of the ciphertext block size.

* `ERR_EQL`: produced when two supposedly equivalent blocks of memory are not identical. The corresponding error check function prototype is `bool not_equal(void *m1, void *m2, size_t size, char *msg)`.

* `ERR_VSN`: produced when a dheluks header contains a non-existent version number. The corresponding error check function prototype is `bool not_supported(int v)`.

* `ERR_FMT`: produced when the formatting of a dheluks string does not match the formatting specified by the version number. The corresponding error check function prototype is `bool not_formatted(unsigned char *str)`.

* `ERR_B64`: produced when a particular character is not base64-encoded. The corresponding error check function prototype is `bool not_base64(char c)`. 

* `bool not_dheluks(unsigned char *in)` returns true if the input string does not match the `dheluks` string specification. It is not an error per se, but it helps avoid any errors that will arise from trying to parse a non-`dheluks` string.


Structures
--------------------

The `dheluks` structures serve two purposes: to organize data that is unique to the `dheluks` configuration, and to physically separate the handling of “public” material from that which must be kept private and subsequently destroyed. There are four fundamental dheluks structures and several corresponding initators.

* `dheluks_ctx_t`: the `dheluks` context struct, which holds the randomness and cipher contexts.
    1. `struct yarrow256_ctx rand`: the `yarrow256` pseudo-random number generator (PRNG) context 
    2. `int init_random(dheluks_ctx_t *ctx)`: PRNG context initiator, which returns -1 if there is insufficient randomness at the system level to seed the PRNG
    3. `void gen_random(struct yarrow256_ctx *ctx, size_t s, uint8_t *r)`: generates `s` bytes of randomness using the seeded PRNG and stores them in `r` 
    4. `struct chacha_poly1305_ctx ciph`: the `chacha-poly1305` cipher struct 
    5. `void init_cipher(dheluks_ctx_t *ctx, uint8_t *sk)`: cipher context initiator, which takes an input the 32-byte symmetric shared key


* `dheluks_pkg_t`: the `dheluks` "data-in-transit" struct, which holds the information that will be sent over an insecure channel.
    1. `uint8_t pubkey[CURVE_SIZE]`: a 32-byte public key 
    2. `uint8_t nonce[NONCE_SIZE]`: a 12-byte nonce 
    3. `uint8_t digest[DIGEST_SIZE]`: a 16-byte ciphertext digest
	4. `uint8_t *cphtxt`: a dynamically-allocated ciphertext
    5. `uint32_t csize`: the number of bytes in the ciphertext (inferred rather than transferred directly)
    6. `size_t interp_csize(dheluks_txt_t *txt)`: returns the size of the ciphertext based on the size of the password and password header
    7. `size_t extrap_csize(unsigned char *str)`: returns the size of the ciphertext based on the size of the inputted `dheluks` string and the sizes of fixed package params
	8. `size_t get_pkg_size(dheluks_pkg_t *pkg, bool has_msg)`: the number of bytes needed to represent the package in transit (i.e. the length of the corresponding `dheluks` string), where the `has_msg` flag determines whether or not the nonce and ciphertext are included in the calculation.


* `dheluks_kys_t`: the `dheluks` secret keyring struct, which holds the private and shared secret keys.
	1. `uint8_t privkey[KEY_SIZE]`: a 32-byte secret key
	2. `uint8_t sharekey[KEY_SIZE]`: a 32-byte shared key
    3. `void gen_privkey(dheluks_ctx_t *ctx, dheluks_kys_t *skr)`: generates the secret key at random using seeded PRNG
    4. `void gen_sharekey(dheluks_kys_t *skr, dheluks_pkg_t *ext)`: generates the shared key using elliptic curve Diffie-Hellman (ECDH)


* `dheluks_txt_t`: the `dheluks` “private plaintext” struct, which holds all of the dynamically-allocated private data corresponding to the administrator’s password.
    1. `uint8_t *pwd`: the password
    2. `uint8_t *plntxt`: the pre-encryption or post-decryption string containing the plaintext header, password, and padding
	3. `uint32_t plen`: the length of the password
	4. `uint32_t interp_plen(char *pwd)`: returns the length of the password from the password itself (assumes entered via `\n` on `stdin`)
    5. `int extrap_plen(dheluks_txt_t *txt)`: copies the length of the password from the plaintext header into `txt.plen`; returns -1 if the value is longer than the entire ciphertext
    6. `void init_ptxt(dheluks_txt_t *txt)`: constructs the plaintext `plntxt` from `pwd` and `plen`
    7. `void unpack_ptxt(dheluks_pkg_t *pkg, dheluks_txt_t *txt)`: extracts `pwd` from `plntxt` using `plen`


* `void init_ptrs(dheluks_pkg_t *pkg, dheluks_txt_t *txt)`: initializes all of the dynamically-allocated fields in `pkg` and `txt` to `NULL`.

* `void decon_ptrs(dheluks_pkg_t *pkg, dheluks_txt_t *txt)`: frees all dynamically-allocated memory in `pkg` and `txt` that is not set to `NULL`.

* `void clean_up(dheluks_pkg *pkg, dheluks_kys_t *skr, dheluks_txt_t *txt)`: overwrites sensitive data with zeros.

String and Package Handling
-------------------------------------

The `dheluks` string and the `dheluks` package are designed to represent equivalent information in different ways. Translating seamlessly between the two involves constructing and validating given `dheluks` string inputs, `base64` encoding and decoding between `char` and `uint8_t`, and copying or extracting results to or from a dheluks package. This functionality is accomplished using the following two functions:

* `int str_to_pkg(unsigned char *str, dheluks_pkg_t *pkg, bool has_msg)`: this function takes as input an arbitrary string `str` and, if it is a `dheluks` string, tranlates the contents into the `dheluks` package `pkg`.
    1. It first checks whether or not `str` is a valid dheluks string by verifying the size of the string (must contain at least a header and public key), the contents of the header (must be `dheluks0:`), the version number (currently 0), and the encoding (all `base64`). 
    2. If the string is not dheluks, the function immediately returns -1.
    3. If the string is valid, it decodes the string (sans header) using the function `size_t str_to_uint8(unsigned char *in, uint8_t *out, size_t insize)`, which returns the number of decoded bytes.
    4. It then copies the public key into `pkg`.
    5. If the flag `has_msg` is set to `true`, it copies the nonce and digest into `pkg` and computes the size of the ciphertext by taking the length of the entire decoded string and subtracting the known-size fields.
    6. If the ciphertext size is not a multiple of the block size, it returns -1. Else, it reads the ciphertext into `pkg` and returns 0.

* `int pkg_to_str(dheluks_pkg_t *pkg, unsigned char *str, bool has_msg)`: this function takes as input a `dheluks` package and translates it into a `dheluks` string.
    1. It first prepares a temporary `uint8_t` array for encoding based.
    2. If `has_msg` is `true`, it copies the public key, nonce, and ciphertext into the array. 
    3. If `has_msg` is `false`, it transfers the public key only.
    4. Then, it encodes the entire array into a string using the function `size_t uint8_to_str(uint8_t *in, unsigned char *out, size_t insize)`, which returns the number of encoded bytes.
    5. Finally, it concatenates the header and the encoded string to produce the final output, returning 0 on success.

Cryptography
----------------------

Precise cryptographic parameters are listed in README.md. The full origin story of `dheluks` crypto can be found in the [nettle library](http://www.lysator.liu.se/~nisse/nettle/nettle.html).

* `void encrypt_phrase(dheluks_ctx_t *ctx, dheluks_pkg_t *pkg, dheluks_kys_t *skr, dheluks_txt_t *txt)`: this function encrypts the fully-formatted plaintext in `txt` with the shared key in `skr`. 
    1. It first initializes the cipher in `ctx` with the shared key in `skr` and a random nonce.
    2. Then it encrypts the plaintext and stores the result as ciphertext in `pkg`. 
    3. Finally, it produces the digest of the ciphertext and stores the result in `pkg`.
    4. Note that this function expects initializations for `ctx.rand`, `pkg.pubkey`, `pkg.csize`, `txt.plntxt`, and `skr.sharekey`, as well a memory allocation of `pkg.csize` bytes for `pkg.cphtxt`. 

* `int decrypt_phrase(dheluks_ctx_t *ctx, dheluks_pkg_t *pkg, dheluks_kys_t *skr, dheluks_txt_t *txt)`: this function decrypts the ciphertext `pkg.cphtxt` and stores it as the plaintext `txt.plntxt`. 
    1. It first initializes `ctx` with `skr.sharekey` and `pkg.nonce`. 
	2. Then it decrypts the ciphertext and stores the result as plaintext in `txt`. 
    3. Finally, it produces the digest of the ciphertext and checks it against `pkg.digest`. If the digests are different, it returns -1; else, it returns 0 on success.
	4. Note that this function expects initializations for `ctx.rand`, a full `pkg`, and a memory allocation of `pkg.csize` bytes for `txt.plntxt`.


Future Work
-----------

There are several aspects of `dheluks` that we would like to improve moving forward.

* Testing and error handling: a run-time test suite and work with a fuzzer would likely bring some unforeseen errors to light. We would very much appreciate any security commentary or edge-case patching...please try to break anything and everything (and ideally propose a way to fix it)!

* Insufficient randomness handling: the `dheluks` `init_random` function gets its seed from the system via `getrandom`. There is a chance that the entropy pool will not be sufficiently large to fill 32 bytes at boot. An insufficient entropy pool usually causes `getrandom` to block, disallowing any operations until sufficient entropy is obtained. This is not a practical solution when it comes to freezing a server mid-boot, so the `GRND_NONBLOCK` flag is set. If there is insufficient entropy, `get_random` produces a warning and `dheluks` processing in askpass is abandoned. Because the entropy of the server will increase over time, a better solution might be to re-check the pool during the process, and re-prompt the client when the pool is ready.

* Future versions of dheluks: we hope to provide security against an active attacker who can intercept and reroute packets by using the extended triple Diffie-Hellman key exchange protocol. The server's authentication key would be generated and stored at shutdown and sent to the administrator over a secure line. This would allow the server to prove knowledge of the corresponding secret key at boot. The problem of how to defend against an adversary who can see inside the server between shutdown and boot remains open. 
