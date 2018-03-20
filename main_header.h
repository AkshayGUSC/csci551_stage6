#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
//ask about errno.h, <netinet/in.h>, <netdb.h>
#include <errno.h>
#include <netinet/in.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <openssl/aes.h>
#include <limits.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <limits.h>
#include <assert.h>

int read_file(char* path);
int server_connection();
int client_connection();
uint8_t* circuit_creation(int x, int y);
void class_AES_set_encrypt_key(unsigned char *key_text, AES_KEY *enc_key);
void class_AES_set_decrypt_key(unsigned char *key_text, AES_KEY *dec_key);
void class_AES_encrypt_with_padding(unsigned char *in, int len, unsigned char **out, int *out_len, AES_KEY *enc_key);
void class_AES_decrypt_with_padding(unsigned char *in, int len, unsigned char **out, int *out_len, AES_KEY *dec_key);


extern int port_number_proxy;
extern int port_number_router;
extern int sockfd_proxy;
extern int port_number_router_int_global[6];
extern FILE *out_proxy;
extern char pid_router_char[100];
extern uint32_t address_list_global[6];
extern char stage;
int number_routers;