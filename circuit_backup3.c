#include "main_header.h"

#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))

const int AES_KEY_LENGTH_IN_BITS = 128;
const int AES_KEY_LENGTH_IN_CHARS = 128 / CHAR_BIT;

void class_AES_set_encrypt_key(unsigned char *key_text, AES_KEY *enc_key)
{
    AES_set_encrypt_key(key_text, AES_KEY_LENGTH_IN_BITS, enc_key);
}

void class_AES_set_decrypt_key(unsigned char *key_text, AES_KEY *dec_key)
{
    AES_set_decrypt_key(key_text, AES_KEY_LENGTH_IN_BITS, dec_key);
}

void class_AES_encrypt_with_padding(unsigned char *in, int len, unsigned char **out, int *out_len, AES_KEY *enc_key)
{
   
    unsigned char ivec[AES_KEY_LENGTH_IN_BITS/8];
    memset(ivec, 0, sizeof(ivec)); 

    int padding_required = AES_KEY_LENGTH_IN_CHARS - len % AES_KEY_LENGTH_IN_CHARS;
    if (padding_required == 0) /* always must pad */
        padding_required += AES_KEY_LENGTH_IN_CHARS;
    assert(padding_required > 0 && padding_required <= AES_KEY_LENGTH_IN_CHARS);
    int padded_len = len + padding_required;
    unsigned char *padded_in = malloc(padded_len);
    assert(padded_in != NULL);
    memcpy(padded_in, in, len);
    memset(padded_in + len, 0, padded_len - len);
    padded_in[padded_len-1] = padding_required;

    *out = malloc(padded_len);
    assert(*out);  /* or out of memory */
    *out_len = padded_len;

    /* finally do it */
    AES_cbc_encrypt(padded_in, *out, padded_len, enc_key, ivec, AES_ENCRYPT);
}
void class_AES_decrypt_with_padding(unsigned char *in, int len, unsigned char **out, int *out_len, AES_KEY *dec_key)
{
    unsigned char ivec[AES_KEY_LENGTH_IN_BITS/8];
   
    memset(ivec, 0, sizeof(ivec));

    *out = malloc(len);
    assert(*out);

    AES_cbc_encrypt(in, *out, len, dec_key, ivec, AES_DECRYPT);

    
    int padding_used = (int)(*out)[len-1];
    assert(padding_used > 0 && padding_used <= AES_KEY_LENGTH_IN_CHARS); /* or corrupted data */
    *out_len = len - padding_used;
}

/*copied attribute feature from https://stackoverflow.com/questions/6732127/is-there-a-way-to-enforce-specific-endianness-for-a-c-or-c-struct*/
struct __attribute__((packed, scalar_storage_order("big-endian")))encrypt_header{
    uint8_t type;
    uint16_t circuit_id;
    unsigned char key[96];
};

struct cntrl_header{
	uint8_t type;
	uint16_t circuit_id;
	uint16_t next_name;		
};

char buf[40], encrypt_message[40], encrypt_message_new[40];
int numbytes;
struct sockaddr_in my_addr, router_addr;
struct sockaddr_in incoming_addr;
socklen_t incoming_addr_len = sizeof(struct sockaddr_in);
static uint8_t key[16*6] = {0};
int first_message =1;
socklen_t router_addr_len;
unsigned char *key_text;

void sending_first_key(int m_hops){
            int k =1;
            int temp;
            fprintf(stderr,"%%%%%%%%%%%%%%%%!!!\n");
            while(k<=m_hops){
                temp = 16*(k-1);
                for(int i=temp;i<temp+16;i++){
                    key[i]= rand()%255;
                    fprintf(stderr,"%x",key[i]);
                }
                k++;
            }
            struct iphdr *ip_encrypt = (struct iphdr*) encrypt_message;
            struct encrypt_header *encrypt_h = (struct encrypt_header *) (encrypt_message+ sizeof(struct iphdr));
            ip_encrypt->saddr = inet_addr(ip_address_info_stage6("eth0"));
            ip_encrypt->daddr = address_list_global[1]; // sending next hop address
            ip_encrypt->protocol = 250;

            router_addr.sin_family = AF_INET;
            router_addr.sin_port = htons(port_number_router_int_global[0]);
            router_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
            memset(router_addr.sin_zero,'\0',sizeof router_addr.sin_zero);
            router_addr_len = sizeof(struct sockaddr_in);
            encrypt_h->type = 0x65;
            encrypt_h->circuit_id = 0x01;

            
            fprintf(stderr, "printing KEY IN CHAR\n");
            for(int i=0;i<16;i++){
                encrypt_h->key[i] = key[i];
            }
            key_text = (unsigned char*)encrypt_h->key;
            for(int i=0;i<16;i++){
                fprintf(stderr, "%x",key_text[i]);
            }
            fprintf(stderr, "\n");

            out_proxy = fopen("stage6.proxy.out","a+");
            fprintf(out_proxy,"new-fake-diffe-hellman, router index: 1 circuit outgoing: 0x01, key: ");
            for(int i=0;i<16;i++){
                fprintf(out_proxy, "%x",key_text[i]);
            } 
            fprintf(out_proxy,"\n");
            fclose(out_proxy); 

            if ((numbytes = sendto(sockfd_proxy,encrypt_message,sizeof(encrypt_message), 0,
                    (struct sockaddr *)&router_addr, router_addr_len)) == -1) {
                perror("talker_circuit: sendto");
                exit(1);
            } 
}

uint8_t* circuit_creation(int n_routers, int m_hops){

    memset(&encrypt_message, 0, sizeof(encrypt_message));
    memset(&encrypt_message_new, 0, sizeof(encrypt_message_new));

    for(int i=1;i<=m_hops;i++){
        out_proxy = fopen("stage6.proxy.out","a+");
        fprintf(out_proxy,"hop: %d, router: %d\n",i,i);
        fclose(out_proxy);
    }

    for(int i=1;i<=m_hops;i++){
        if(first_message == 1){
            sending_first_key(m_hops); 
            first_message =0;
        }
        unsigned char *crypt_text;
        int crypt_text_len;
        AES_KEY enc_key;
        unsigned char next_node[6];
        sprintf((char*)next_node,"%d",port_number_router_int_global[i-1]);

        if(i==m_hops){
            //cnt_h->next_name = 0xffff;
            sprintf((char*)next_node,"%d",0xffff);
        }

        unsigned char clear_text[100];
        memcpy(clear_text,next_node,strlen((char*)next_node)+1);
        int clear_text_len = strlen((char*)clear_text) + 1;
        fprintf(stderr, "Port Number = %s\n", clear_text);
        for(int outer=i;outer>0;outer--){
            int m=0;
            for(int inner=16*(outer-1);inner<16*outer;inner++){
                key_text[m] = key[inner];
                m++;
            }
            class_AES_set_encrypt_key(key_text, &enc_key);
            class_AES_encrypt_with_padding(clear_text, clear_text_len, &crypt_text, &crypt_text_len, &enc_key);
            fprintf(stderr, "%s and crypt size=%d and clear text len =%d\n", crypt_text, crypt_text_len, clear_text_len);
            memset(&clear_text, 0, sizeof(clear_text));
            memcpy(clear_text,crypt_text,strlen((char*)crypt_text)+1);
            clear_text_len = strlen((char*)clear_text)+1;
            fprintf(stderr, "!!!!!%s and crypt size=%d and clear text len =%d\n", crypt_text, crypt_text_len, clear_text_len);
        }
        struct iphdr *ip_encrypt_new = (struct iphdr*) encrypt_message_new;
        struct encrypt_header *encrypt_h_new = (struct encrypt_header *) (encrypt_message_new+ sizeof(struct iphdr));
        ip_encrypt_new->saddr = inet_addr(ip_address_info_stage6("eth0"));
        ip_encrypt_new->daddr = address_list_global[i]; // sending next hop address
        ip_encrypt_new->protocol = 250;
        encrypt_h_new->type = 0x62;
        encrypt_h_new->circuit_id = 0x01;
        memcpy(encrypt_h_new->key,crypt_text,strlen((char*)crypt_text)+1);
        router_addr.sin_family = AF_INET;
        router_addr.sin_port = htons(port_number_router_int_global[i-1]);
        router_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        memset(router_addr.sin_zero,'\0',sizeof router_addr.sin_zero);
        router_addr_len = sizeof(struct sockaddr_in);

        if ((numbytes = sendto(sockfd_proxy,encrypt_message_new,sizeof(encrypt_message_new), 0,
                (struct sockaddr *)&router_addr, router_addr_len)) == -1) {
            perror("talker_circuit: sendto");
            exit(1);
        }
        fprintf(stderr, "Sent key to router\n");
        free(crypt_text);
        if ((numbytes = recvfrom(sockfd_proxy, buf,sizeof(buf), 0,
                (struct sockaddr *)&incoming_addr, &(incoming_addr_len))) == -1) {
            perror("recvfrom_proxy_circuit");
            exit(1);
        }
        fprintf(stderr, "Received ACK from router\n");
        struct encrypt_header * encrypt_h_recv =  (struct encrypt_header *) (buf+ sizeof(struct iphdr));
        out_proxy = fopen("stage6.proxy.out","a+");
        fprintf(out_proxy,"pkt from port: %u, length: 3, contents: 0x%x%04x\n",ntohs(incoming_addr.sin_port),encrypt_h_recv->type,encrypt_h_recv->circuit_id);
        fprintf(out_proxy,"incoming extend-done circuit, incoming: 0x%x from port: %u\n",encrypt_h_recv->circuit_id,ntohs(incoming_addr.sin_port));
        fclose(out_proxy);   
    }

    printf("Circuit Completed %d\n", numbytes);
    return key;
}