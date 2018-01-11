/************************************************
|	 		// DHELUKS CLIENT //
| input:		n/a
| output: 		client dheluks string
| description: 	this module takes the
| 				server's dheluks string and
|				admin password at prompting,
|				computes the ECDH shared key,
|				encrypts the password, and
|				and writes the resulting dheluks
|				string to stdio.
*************************************************/


// DHELUKS LIBRARY //

#include "dheluks.h"
#include <termios.h>

// FUNCTION PROTOTYPES //

// Read package string from stdin
void get_pkg(dheluks_pkg_t *ext);

// Read passphrase from keyboard
void get_pwd(dheluks_txt_t *txt);

// Encode + encrypt admin passphrase
void set_pkg(dheluks_ctx_t *ctx, dheluks_pkg_t *loc, dheluks_kys_t *skr, dheluks_txt_t *txt);
void set_ptxt(dheluks_ctx_t *ctx, dheluks_pkg_t *loc, dheluks_kys_t *skr, dheluks_txt_t *txt);
void set_ctxt(dheluks_ctx_t *ctx, dheluks_pkg_t *loc, dheluks_kys_t *skr, dheluks_txt_t *txt);

// Write local package to file
void write_out(dheluks_pkg_t *loc);

// MAIN FUNCTION //

int main (void) {

	// Declarations //

	dheluks_ctx_t context;

	dheluks_pkg_t local_package;
	dheluks_pkg_t external_package;

	dheluks_kys_t keyring;

	dheluks_txt_t plaintext;

	// Initializations //

	init_random(&context); //initialize PRNG

	gen_privkey(&context, &keyring); //generte local privkey
	gen_pubkey(&local_package, &keyring); //generate local pubkey


	// Diffie-Hellman Exchange //

	get_pkg(&external_package);
	gen_sharekey(&keyring, &external_package); //generate shared key


	// Get Passphrase //

	plaintext.pwd = malloc(1000); //CHANGE TO DYNAMIC INPUT: WHILE NOT \N, FGET(C)
	get_pwd(&plaintext);


	// Encode and Encrypt //

	set_pkg(&context, &local_package, &keyring, &plaintext);
	set_ptxt(&context, &local_package, &keyring, &plaintext);
	set_ctxt(&context, &local_package, &keyring, &plaintext);

	// Export //
	write_out(&local_package);


	// Wipe Memory //

	clean_up(&local_package, &keyring, &plaintext);


	return EXIT_SUCCESS;

}


// FUNCTION DEFINITIONS //

// Read package string from stdin
void get_pkg(dheluks_pkg_t *ext) {

    size_t pkg_size;
    unsigned char *to_get;

    pkg_size = 1000;
    to_get = calloc(pkg_size, sizeof(unsigned char));

	printf("\nPlease enter the server's dheluks string: ");

    fgets((char *)to_get, pkg_size, stdin);

    ext->cphtxt = calloc(1000, sizeof(unsigned char));

    str_to_pkg(to_get, ext, 0);

    free(to_get);
}


// Read passphrase from keyboard w/out echo
void get_pwd(dheluks_txt_t *txt) {

	int fd; //file descriptor
	struct termios on, off;

	fd = fileno(stdin);

	tcgetattr(fd, &on);
	off = on; //save onstate for later
	off.c_lflag &= ~ECHO;
	tcsetattr(fd, TCSANOW, &off);

	printf("\nPlease enter your passphrase: ");

	fgets((char *)txt->pwd, 1000, stdin);

	txt->plen = strlen((char *)txt->pwd) - 1; //strip newline

	tcsetattr(fd, TCSANOW, &on);

}

void set_pkg(dheluks_ctx_t *ctx, dheluks_pkg_t *loc, dheluks_kys_t *skr, dheluks_txt_t *txt) {

	set_ptxt(ctx, loc, skr, txt);
	set_ctxt(ctx, loc, skr, txt);

}

void set_ptxt(dheluks_ctx_t *ctx, dheluks_pkg_t *loc, dheluks_kys_t *skr, dheluks_txt_t *txt) {

	loc->csize = interp_csize(txt);
	txt->plntxt = calloc(loc->csize, sizeof(unsigned char));
    init_ptxt(txt);

}

void set_ctxt(dheluks_ctx_t *ctx, dheluks_pkg_t *loc, dheluks_kys_t *skr, dheluks_txt_t *txt) {

	loc->cphtxt = calloc(loc->csize, sizeof(unsigned char));
    encrypt_phrase(ctx, loc, skr, txt);

}

// Write local package to file
void write_out(dheluks_pkg_t *loc) {

	size_t pkg_size;
	unsigned char *output;

	pkg_size = get_pkg_size(loc, true);
	output = calloc(pkg_size, sizeof(unsigned char));
	pkg_to_str(loc, output, 1);

	printf("\n\n%s\n\n", output);

	printf("Paste the above string (including header) into the dheluks-enabled server prompt.\n");

	free(output);

}
