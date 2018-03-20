/* 
 * aes-test.c
 * by John Heidemann
 *
 * inspired by code by Ben Miller
 * (Small sample for how to use Blowfish from OpenSSL
 *  http://www.eecis.udel.edu/~bmiller/cis364/2012s/hw/hw3/code/blowfish-test.c)
 *
 * Sadly, as of 2012-10-01 and openssl-1.0.0j
 * there are no manual pages for AES in openssl's libcrypto.
 * However, the header file /usr/include/openssl/aes.h
 * and the manual pages for blowfish(3) are a reasonable starting point.
 *
 * Compile in Linux (tested with Fedora-17) with:
 *	gcc -o $@ -g aes-test.c -lcrypto
 *
 */

/* uncomment next line to build a library by removing main(). */
/* #define IS_LIBRARY */

#include "main_header.h"





#ifndef IS_LIBRARY
void encryption_process(unsigned char *key_text, unsigned char *clear_text)
{
	int clear_text_len = strlen(clear_text) + 1; /* add one for null termination */

	unsigned char *crypt_text;
	int crypt_text_len;
	unsigned char *clear_crypt_text;
	int clear_crypt_text_len;

	AES_KEY enc_key;
	AES_KEY dec_key;

	/* test out encryption */

	unsigned char *crypt_text;
	int crypt_text_len;
	unsigned char *clear_crypt_text;
	int clear_crypt_text_len;

	AES_KEY enc_key;
	AES_KEY dec_key;


	unsigned char *key_text = "a397a25553bef1fcf9796b521413e9e2";
	unsigned char *clear_text = "234002340023400234002340023400234002340023400234002340023400234002340";
	int clear_text_len = strlen(clear_text) + 1;

	class_AES_set_encrypt_key(key_text, &enc_key);
	class_AES_encrypt_with_padding(clear_text, clear_text_len, &crypt_text, &crypt_text_len, &enc_key);
	printf("%s and crypt size=%d and clear text len =%d\n", crypt_text, crypt_text_len, clear_text_len);

	class_AES_set_decrypt_key(key_text, &dec_key);
	class_AES_decrypt_with_padding(crypt_text, crypt_text_len, &clear_crypt_text, &clear_crypt_text_len, &dec_key);
	printf("%s\n", clear_crypt_text);

	/* caller must free the buffers */
	free(crypt_text);
	free(clear_crypt_text);

	exit(0);
}
#endif