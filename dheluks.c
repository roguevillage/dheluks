/*****************************************************
|            	// DHELUKS LIBRARY //
| description:  definitions for the dheluks library,
|               including dheluks string generation
|               and parsing, dheluks structure
|		initialization and manipulation,
|		and cryptographic primitives.
******************************************************/

#include "dheluks.h" //corresponding preprocessor directives

// Initialize yarrow256 random generator with seed from pool
int init_random(dheluks_ctx_t *ctx) {

	uint8_t seed[CURVE_SIZE]; //max randomness must be CURVE_SIZE bytes
	unsigned int bytes; //bytes returned by syscall

	bytes = syscall(SYS_getrandom, seed, sizeof(seed), GRND_NONBLOCK); //get sys randomness

	if (bytes == -1) {
		err(ERR_SZE, "WARNING: Insufficient randomness to seed PRNG");
		return -1; //if it's not the right size, produce an error
	}

	not_size(bytes, CURVE_SIZE, "WARNING: Insufficient randomness to fully seed PRNG");

    yarrow256_init(&ctx->rand, 0, NULL);   //will not need to reseed, flag = 0
    yarrow256_seed(&ctx->rand, CURVE_SIZE, seed); //seed the PRNG

	return 0;

}

//Return randomly generated uint8 value of specified size
void gen_random(struct yarrow256_ctx *ctx, size_t s, uint8_t *r) {

    yarrow256_random(ctx, s, r); //generate s bytes of PR, store in r

}

// Initialize secret keyring with random secret key
void gen_privkey(dheluks_ctx_t *ctx, dheluks_kys_t *skr) {

    gen_random(&ctx->rand, KEY_SIZE, skr->privkey); //generate private key

}

// Generate public key Qa = d*P (Qa, P are EC points; * is EC mult)
void gen_pubkey(dheluks_pkg_t *pkg, dheluks_kys_t *skr) {

    curve25519_mul_g(pkg->pubkey, skr->privkey); //generate pubkey

}

// Generate shared key S = d*Qb (Qb, P are EC points; * is EC mult)
void gen_sharekey(dheluks_kys_t *skr, dheluks_pkg_t *ext) {

    curve25519_mul(skr->sharekey, skr->privkey, ext->pubkey); //generate sharekey

}

// Initialize chacha-poly1305 cipher
void init_cipher(dheluks_ctx_t *ctx, uint8_t *sk) {

	chacha_poly1305_set_key(&ctx->ciph, sk); //initialize symm cipher with key sk

}

// Initialzes all dynamically allocated memory
void init_ptrs(dheluks_pkg_t *pkg, dheluks_txt_t *txt) {

	pkg->cphtxt = NULL;
	txt->plntxt = NULL;
	txt->pwd = NULL;
}

// Frees all non-null dynamically allocated memory
void decon_ptrs(dheluks_pkg_t *pkg, dheluks_txt_t *txt) {

	free_mem(pkg->cphtxt);
	free_mem(txt->plntxt);
	free_mem(txt->pwd);

}

// Frees a pointer whose value is not null
void free_mem(void *ptr) {

	if(not_valid(ptr) == false) //if ptr is not null,
		free(ptr);				//free it

}

// Convert dheluks data package to encoded string
// has_msg = false: package contains bare minimum (header + pubkey)
// has_msg = true: package contains a message (header + pubkey + nonce + cphtxt)
int pkg_to_str(dheluks_pkg_t *pkg, unsigned char *str, bool has_msg) {

	size_t datalen; 	//length of package data
	size_t max_datalen; //max length of pkg data
	uint8_t *data;		//stores data
	size_t codelen;		//length of encoded data
	unsigned char *code;//stores code

	datalen = KEY_SIZE; //min length
	max_datalen = KEY_SIZE + NONCE_SIZE + DIGEST_SIZE + pkg->csize; //max length
	data = malloc(max_datalen); //allocate max length

	memcpy(data, pkg->pubkey, KEY_SIZE); //put the public key in first

	if (has_msg == true) { //if there is supposed to be a message

		if(not_valid(pkg->cphtxt)) { //but there actually isn't one
			err(ERR_NUL, "has_msg is true, but there is no ciphertext.");
			return -1;	//raise an error
		} //else,

		datalen += (NONCE_SIZE + DIGEST_SIZE + pkg->csize); //increase datalen for nonce/cphtxt
		memcpy(data + KEY_SIZE, pkg->nonce, NONCE_SIZE); //add nonce to data
		memcpy(data + KEY_SIZE + NONCE_SIZE, pkg->digest, DIGEST_SIZE);
		memcpy(data + KEY_SIZE + NONCE_SIZE + DIGEST_SIZE, pkg->cphtxt, pkg->csize); //add ctxt

	}

	codelen = B64_ENCODE_LEN(datalen); //size of encoded data
	code = malloc(codelen);	//allocate memory for code
	uint8_to_str(data, code, datalen); //convert data to code

	memcpy(str, HEADER, HEADER_LEN); //place the header
	memcpy(str+HEADER_LEN, code, codelen); //place the encoded data

	free(data); //clean up

	return 0; //there were no errors

}

// Convert encoded string to dheluks data package
// has_msg = false: package contains bare minimum (header + pubkey)
// has_msg = true: package contains a message (header + pubkey + nonce + cphtxt)
int str_to_pkg(unsigned char *str, dheluks_pkg_t *pkg, bool has_msg) {

	if (not_dheluks(str)) //if the string is not a dheluks string,
		return -1;	//return error

	if (str[VSN_POSITION] == '0') {

		int codelen; //length of encoded data (not including header)
		size_t datalen; //length of decoded data (not including header)
		uint8_t *data; //holds decoded data

		codelen = b64len(str+HEADER_LEN); //codlen = length of b64 chars after header
		data = malloc(codelen); //it will be less than size of code
		datalen = str_to_uint8(str+HEADER_LEN, data, codelen); //convert string to data

		memcpy(pkg->pubkey, data, KEY_SIZE); //place key into package

		if (has_msg == true) { //if there supposed to be a message

			if (datalen - KEY_SIZE - NONCE_SIZE - DIGEST_SIZE < BLOCK_SIZE) { //but there actually isn't one,
				err(ERR_SZE, "Ciphertext not found");
				return -1; //raise an error
			}

			pkg->csize = extrap_csize(datalen); //set cphtxt size
			pkg->cphtxt = malloc(pkg->csize); //allocate mem for cphtxt
			memcpy(pkg->nonce, data + KEY_SIZE, NONCE_SIZE); //place nonce
			memcpy(pkg->digest, data + KEY_SIZE + NONCE_SIZE, DIGEST_SIZE);
			memcpy(pkg->cphtxt, data + KEY_SIZE + NONCE_SIZE + DIGEST_SIZE, pkg->csize); //place cphtxt

			if (not_block(pkg->csize)) //if cphtxt not correct block size,
				return -1; //return error

		}

		return 0; //there were no errors

	}

	else //we were expecting version 0
		return -1;

}

// Convert string to uint8 array; return outsize
size_t str_to_uint8(unsigned char *in, uint8_t *out, size_t insize) {

    int errU; //update error
	int errF; //final error
    size_t outsize; //outgoing decoded bytes
    struct base64_decode_ctx decoder; //nettle decoder

	base64_decode_init(&decoder); //init decoder

    errU = base64_decode_update(&decoder, &outsize, out, insize, in); //decode
	errF = base64_decode_final(&decoder); //check padding size

	if (errU == 0) //throw b64 errors
		err(ERR_B64, "Decode update error");
	if (errF == 0)
		err(ERR_B64, "Decode final error");

	return outsize; //return number of bytes written to out

}

// Convert uint8 array to string; return outsize
size_t uint8_to_str(uint8_t *in, unsigned char *out, size_t insize) {

    size_t outsize; //number of outgoing encoded bytes
    struct base64_encode_ctx encoder; //nettle encoder

    base64_encode_init(&encoder); //init encoder

    outsize = base64_encode_update(&encoder, out, insize, in); //encode first chunk
	out += outsize; //increment pointer
	outsize += base64_encode_final(&encoder, out); //encode final chunk, add padding

	return outsize; //return number of bytes written to out

}

// Interpolates csize based on pwd length and crypto params
size_t interp_csize(dheluks_txt_t *txt) {

	int quo; //number of whole blocks
	float rem; //unruled data

	quo = 1; //must have at least 1 whole block
	rem = txt->plen + PWD_HEADER_SIZE; //data size = pwdlen + size header

	while ((rem -= BLOCK_SIZE) > 0) //while there is still stuff in rem
		quo++; //add whole block, keep subtracting

	return quo*BLOCK_SIZE; //return num blocks*size of block

}

// Extrapolates csize based on length of decoded string and crypto params
size_t extrap_csize(size_t len) {

	return len - KEY_SIZE - NONCE_SIZE - DIGEST_SIZE;

}

// Interpolates plen based on pwd length
uint32_t interp_plen(char *pwd) {

	return strlen(pwd) - 1; //strip newline

}

// Extrapolates plen based on plaintext header; returns -1 if plen > csize
int extrap_plen(dheluks_pkg_t *pkg, dheluks_txt_t *txt) {

	memcpy(&txt->plen, txt->plntxt, PWD_HEADER_SIZE); //get size header
	txt->plen = ntohl(txt->plen);

	if(txt->plen > pkg->csize - PWD_HEADER_SIZE) //if the plaintext size is supposedly bigger than the whole ciphertext,
		return -1; //something went wrong

	return 0;

}

// Encrypts plaintext ptxt, stores as ciphertext ctxt
void encrypt_phrase(dheluks_ctx_t *ctx, dheluks_pkg_t *pkg, dheluks_kys_t *skr, dheluks_txt_t *txt) {

	chacha_poly1305_set_key(&ctx->ciph, skr->sharekey); //set key

	gen_random(&ctx->rand, NONCE_SIZE, pkg->nonce);	//generate nonce

	chacha_poly1305_set_nonce(&ctx->ciph, pkg->nonce);	//set nonce

	chacha_poly1305_encrypt(&ctx->ciph, pkg->csize, pkg->cphtxt, txt->plntxt); //encrypt

	chacha_poly1305_digest(&ctx->ciph, DIGEST_SIZE, pkg->digest);

}

// Decrypts ctxt, stores as an encoded uint8
int decrypt_phrase(dheluks_ctx_t *ctx, dheluks_pkg_t *pkg, dheluks_kys_t *skr, dheluks_txt_t *txt) {

	uint8_t dig[DIGEST_SIZE];

	chacha_poly1305_set_key(&ctx->ciph, skr->sharekey); //set key

	chacha_poly1305_set_nonce(&ctx->ciph, pkg->nonce); //set nonce

	chacha_poly1305_decrypt(&ctx->ciph, pkg->csize, txt->plntxt, pkg->cphtxt); //decrypt

	chacha_poly1305_digest(&ctx->ciph, DIGEST_SIZE, dig);

	if (not_equal(dig, pkg->digest, DIGEST_SIZE, "Message authentication failed.")) //if the digests aren't equal,
		return -1; //return an error

	return 0;

}

// Initializes headed and padded plaintext for encryption
void init_ptxt(dheluks_txt_t *txt) {

	uint32_t header;

	header = htonl(txt->plen); //uniform pad header

	memcpy(txt->plntxt, &header, PWD_HEADER_SIZE); //copy header
	memcpy(txt->plntxt + PWD_HEADER_SIZE, txt->pwd, txt->plen); //copy pwd

}

// Removes header and padding from decrypted plaintext, stores in pwd
void unpack_ptxt(dheluks_txt_t *txt) {

	memcpy(txt->pwd, txt->plntxt + PWD_HEADER_SIZE, txt->plen);

}

// Calculates total number of bytes needed to represent package in transit
size_t get_pkg_size(dheluks_pkg_t *pkg, bool has_msg) {

	size_t data; 	//pkg data
	size_t format;	//format data

	data = format = 0;

	format += HEADER_LEN; //header size

	data += E_KEY_SIZE; //encoded pubkey

	if (has_msg) {
		data += E_NONCE_SIZE; //encoded nonce
		data += E_DIGEST_SIZE;
		data += B64_ENCODE_LEN(pkg->csize); //ciphertext
	}

	return data + format; //return sum of data and formatting

}

// Cleans up (writes over) sensitive memory
void clean_up(dheluks_pkg_t *pkg, dheluks_kys_t *skr, dheluks_txt_t *txt) {

	memset(skr->privkey, 0, KEY_SIZE); //write over keys
	memset(skr->sharekey, 0, KEY_SIZE);
	memset(txt->plntxt, 0, pkg->csize); //write over plaintext and pwd
	memset(txt->pwd, 0, txt->plen);
	memset(&txt->plen, 0, PWD_HEADER_SIZE);

}

// Prints errors to stderr
void err(char *type, char *msg) {

    fprintf(stderr, "%s Error: %s\n", type, msg);

}

// Prints a dheluks package
void print_pkg(char *desc, dheluks_pkg_t *pkg) {

	printf("%s Package: \n", desc);

	print_uint8("Pubkey", pkg->pubkey, CURVE_SIZE);
	print_uint8("Initvec", pkg->nonce, NONCE_SIZE);
	print_uint8("Ciphtxt", pkg->cphtxt, strlen((char *)pkg->cphtxt));

}

// Prints a uint8 array described by the string desc
void print_uint8(char *desc, uint8_t *num, size_t size) {

    int i;

    printf("%s: ", desc);

    for (i = 0; i < size; i++)
        printf("%02x", num[i]);

    printf("\n");

}

// Returns true if input is not a dheluks string
bool not_dheluks(unsigned char *str) {

	if (strlen((char *)str) < DHELUKS_STR_MIN_SIZE) //must be at least min size
		return true;

	if (not_equal(str, HEADER, HEADER_LEN, "Dheluks header not found"))
		return true; //first HEADER_LEN chars must be header

	if (not_supported(str[VSN_POSITION])) //must be a supported version
		return true;

	if (str[VSN_POSITION] == '0' && not_formatted(str+HEADER_LEN))
		return true; //must have formatting according to version spec

	return false;

}

// Returns true if pointer is not valid (null)
bool not_valid(void *ptr) {

	if (ptr == NULL)
		return true;

	return false;

}

// Returns true if actual size does not match expectation
bool not_size(size_t act, size_t exp, char *msg) {

    if (act != exp) {
        err(ERR_SZE, msg);
		return true;
	}

	return false;

}

// Returns true if size is not a multiple of the ciphertext block size
bool not_block(size_t size) {

	if (size % 64 != 0) {
		err(ERR_SZE, "Size does not match ciphertext block size");
		return true;
	}

	return false;

}

// Returns true if memory blocks of specified size are not equivalent
bool not_equal(void *m1, void *m2, size_t size, char *msg) {

    if (memcmp(m1, m2, size) != 0) {
        err(ERR_EQL, msg);
		return true;
	}

	return false;

}

// Returns true if character is not base64
bool not_base64(char c) {

	if (c >= 65 && c <= 90) //A-Z
		return false;

	if (c >= 97 && c <= 122) //a-z
		return false;

	if (c >= 48 && c <= 57) //0-9
		return false;

	if (c == 43 || c == 47 || c == 61) //+/=
		return false;

	return true;

}

// Returns true if version is not current
bool not_supported(int v) {

	if (v < 0 || v > CURRENT_VERSION) {
		err(ERR_VSN, "Unsupported version");
		return true;
	}

	return false;

}

// Returns true if string is not correctly formatted
bool not_formatted(unsigned char *str) {

	if (b64len(str) < E_KEY_SIZE) {
		err(ERR_FMT, "Number of Base64 encoded characters less than keysize");
		return true;
	}

	return false;

}

// Returns length of the base64 encoded string (ignores newlines/stray chars)
size_t b64len(unsigned char *str) {

	int i;
	int ctrl = strlen((char *)str);

	for (i = 0; i < ctrl; i++) {
		if (not_base64(str[i]))
			break;
	}

	return i;

}
