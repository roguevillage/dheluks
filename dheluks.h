/*******************************************************
|           	// DHELUKS HEADER //
| description:  declarations for the dheluks library,
|		including dependencies, macros,
|		structs, and function prototypes.
********************************************************/

#ifndef DHELUKS_H_
#define DHELUKS_H_

#define _GNU_SOURCE

/* LIBRARIES */

// Standards
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// I/O
#include <unistd.h>
#include <arpa/inet.h>	//ntohl() and htonl()

// System Calls
#include <sys/types.h>
#include <sys/syscall.h>
#include <linux/random.h>

// Nettle
#include <nettle/yarrow.h>		//PRNG
#include <nettle/base64.h>		//coding
#include <nettle/curve25519.h> 		//ec
#include <nettle/chacha-poly1305.h> //enc/dec

/* MACROS */

// Version
#define CURRENT_VERSION '0'

// Encoding
#define B64_ENCODE_LEN(x) (((x+2)/3)*4)

// Sizes
#define CURVE_SIZE CURVE25519_SIZE 	//points and scalars are 32 bytes

#define KEY_SIZE CHACHA_POLY1305_KEY_SIZE	//32 bytes
#define E_KEY_SIZE B64_ENCODE_LEN(KEY_SIZE)

#define NONCE_SIZE CHACHA_POLY1305_NONCE_SIZE	//12 bytes
#define E_NONCE_SIZE B64_ENCODE_LEN(NONCE_SIZE)

#define DIGEST_SIZE CHACHA_POLY1305_DIGEST_SIZE //16 bytes
#define E_DIGEST_SIZE B64_ENCODE_LEN(DIGEST_SIZE)

#define BLOCK_SIZE CHACHA_POLY1305_BLOCK_SIZE	//64 bytes
#define E_BLOCK_SIZE B64_ENCODE_LEN(BLOCK_SIZE)

#define PWD_HEADER_SIZE 4 			//size of plaintext header

#define DHELUKS_STR_MIN_SIZE (HEADER_LEN + E_KEY_SIZE)

// Formatting
#define HEADER "dheluks0:"
#define HEADER_LEN (sizeof(HEADER) - 1)
#define VSN_POSITION (HEADER_LEN - 2) //version is last char before sep
#define KEY_POSITION HEADER_LEN
#define NONCE_POSITION (KEY_POSITION + KEY_SIZE)
#define DIGEST_POSITION (NONCE_POSITION + NONCE_SIZE)
#define CPHTXT_POSITION (DIGEST_POSITION + DIGEST_SIZE)

// Error Handling
#define ERR_NUL "Null Pointer"
#define ERR_SZE "Size"
#define ERR_EQL "Data"
#define ERR_VSN "Version"
#define ERR_FMT "Format"
#define ERR_B64 "Coding"

/* STRUCTURES */

/* PUBLIC  := non-sensitive data that can be distributed freely */
/* PRIVATE := sensitive data that should be contained then destroyed */
/* Future work: allocate secure memory for private structures */

// Dheluks context (PUBLIC)
typedef struct {
    struct yarrow256_ctx rand;		//PRNG
    struct chacha_poly1305_ctx ciph;//cipher
} dheluks_ctx_t;

// Package for data in transit (PUBLIC)
typedef struct {
    uint8_t pubkey[CURVE_SIZE];     //public key
    uint8_t nonce[NONCE_SIZE];		//initialization vector
	uint8_t digest[DIGEST_SIZE];	//authentication code
    uint8_t *cphtxt;				//ciphertext
	uint32_t csize;					//size of ciphertext
} dheluks_pkg_t;

// Keyring for local & shared secret keys (PRIVATE)
typedef struct {
    uint8_t privkey[KEY_SIZE]; 	//secret key
    uint8_t sharekey[KEY_SIZE];	//shared key
} dheluks_kys_t;

// Package for local data (PRIVATE)
typedef struct {
	uint8_t *plntxt;	//plaintext
	uint8_t *pwd;		//passphrase
	uint32_t plen; 		//pwd length
} dheluks_txt_t;


/* FUNCTION PROTOTYPES */


// CONTEXTS //

// Initialize yarrow256 random generator; returns -1 on error
int init_random(dheluks_ctx_t *ctx);

// Initialize chacha-poly1305 cipher
void init_cipher(dheluks_ctx_t *ctx, uint8_t *sk);


// KEYS //

// Returns randomly generated uint8 value of specified size; store in r
void gen_random(struct yarrow256_ctx *ctx, size_t s, uint8_t *r);

// Initialize secret keyring with local private key
void gen_privkey(dheluks_ctx_t *ctx, dheluks_kys_t *skr);

// Returns EC public key Q = dP
void gen_pubkey(dheluks_pkg_t *pkg, dheluks_kys_t *skr);

// Generates shared key according to ECDH protocol (local private key EC_MULT external public key)
void gen_sharekey(dheluks_kys_t *skr, dheluks_pkg_t *ext);


// PACKAGES //

// Initialzes all dynamically allocated memory
void init_ptrs(dheluks_pkg_t *pkg, dheluks_txt_t *txt);

// Frees all non-null dynamically allocated memory
void decon_ptrs(dheluks_pkg_t *pkg, dheluks_txt_t *txt);

// Frees a pointer whose value is not null
void free_mem(void *ptr);

// Converts package to string; returns -1 on error
int pkg_to_str(dheluks_pkg_t *pkg, unsigned char *str, bool has_msg);

// Converts string to package; returns -1 on error
int str_to_pkg(unsigned char *str, dheluks_pkg_t *pkg, bool has_msg);

// Calculates total number of bytes needed to represent package in transit
size_t get_pkg_size(dheluks_pkg_t *pkg, bool has_msg);


// CODING, PADDING, and PARSING //

// Returns true if input is not a dheluks string
bool not_dheluks(unsigned char *in);

// Converts string to uint8 array, returns outsize
size_t str_to_uint8(unsigned char *in, uint8_t *out, size_t insize);

// Converts uint8 array to string, returns outsize
size_t uint8_to_str(uint8_t *in, unsigned char *out, size_t insize);

// Initializes padded plaintext for encryption
void init_ptxt(dheluks_txt_t *txt);

// Removes header and padding from decrypted plaintext, stores in pwd;
void unpack_ptxt(dheluks_txt_t *txt);


// SIZING //

// Interpolates csize based on pwd length and crypto params
size_t interp_csize(dheluks_txt_t *txt);

// Extrapolates csize based on length of string and crypto params
size_t extrap_csize(size_t len);

// Interpolates plen based on pwd length
uint32_t interp_plen(char *pwd);

// Extrapolates plen based on plaintext header; returns -1 if plen > csize
int extrap_plen(dheluks_pkg_t *pkg, dheluks_txt_t *txt);


// CRYPTO //

// Encrypts plaintext ptxt, stores in ciphertext ctxt
void encrypt_phrase(dheluks_ctx_t *ctx, dheluks_pkg_t *pkg, dheluks_kys_t *skr, dheluks_txt_t *txt);

// Decrypts passphrase, stores as encoded text
int decrypt_phrase(dheluks_ctx_t *ctx, dheluks_pkg_t *pkg, dheluks_kys_t *skr, dheluks_txt_t *txt);


// SECURITY and ERROR HANDLING //

// Cleans up (writes over) sensitive memory
void clean_up(dheluks_pkg_t *pkg, dheluks_kys_t *skr, dheluks_txt_t *txt);

// Prints errors to stderr
void err(char *type, char *msg);

// Returns true if pointer is not valid (null)
bool not_valid(void *ptr);

// Returns true if actual size does not match expectation
bool not_size(size_t act, size_t exp, char *msg);

// Returns true if size is not a multiple of the ciphertext block size
bool not_block(size_t size);

// Returns true if memory blocks of specified size are not equivalent
bool not_equal(void *m1, void *m2, size_t size, char *msg);

// Returns true if character is not base64
bool not_base64(char c);

// Returns true if version is not current
bool not_supported(int v);

// Returns true if string does not contain correct formatting
bool not_formatted(unsigned char *str);

// Returns length of the base64 encoded string (ignores newlines/stray chars)
size_t b64len(unsigned char *str);


// PRINTING //

// Prints a full dheluks package
void print_pkg(char *desc, dheluks_pkg_t *pkg);

// Prints a uint8 array described by the string desc
void print_uint8(char *desc, uint8_t *num, size_t size);

#endif // DHELUKS_H_
