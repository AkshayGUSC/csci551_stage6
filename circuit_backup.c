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

    /*
     * Now undo padding.
     */
    int padding_used = (int)(*out)[len-1];
    assert(padding_used > 0 && padding_used <= AES_KEY_LENGTH_IN_CHARS); /* or corrupted data */
    *out_len = len - padding_used;
}

/*copied attribute feature from https://stackoverflow.com/questions/6732127/is-there-a-way-to-enforce-specific-endianness-for-a-c-or-c-struct*/
struct __attribute__((packed, scalar_storage_order("big-endian")))encrypt_header{
    uint8_t type;
    uint16_t circuit_id;
    uint8_t key[16];
};

struct cntrl_header{
	uint8_t type;
	uint16_t circuit_id;
	uint16_t next_name;		
};

uint8_t* circuit_creation(int n_routers, int m_hops){
	char control_message[30], buf[30], encrypt_message[40];
	int numbytes;
	struct sockaddr_in my_addr, router_addr;
    struct sockaddr_in incoming_addr;
    socklen_t incoming_addr_len = sizeof(struct sockaddr_in);

    static uint8_t key[16*6] = {0};
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
    ip_encrypt->saddr = inet_addr("10.0.2.15");
    ip_encrypt->daddr = address_list_global[1]; // sending next hop address
    ip_encrypt->protocol = 250;

    router_addr.sin_family = AF_INET;
    router_addr.sin_port = htons(port_number_router_int_global[0]);
    router_addr.sin_addr.s_addr = address_list_global[0];
    memset(router_addr.sin_zero,'\0',sizeof router_addr.sin_zero);
    socklen_t router_addr_len = sizeof(struct sockaddr_in);
    encrypt_h->type = 0x65;
    encrypt_h->circuit_id = 0x01;

    

    fprintf(stderr, "printing KEY IN CHAR\n");
    for(int i=0;i<16;i++){
       encrypt_h->key[i] = key[i];
    } 

    unsigned char *key_text = (unsigned char*)encrypt_h->key;

    fprintf(stderr, "%s",key_text); 

    if ((numbytes = sendto(sockfd_proxy,encrypt_message,40, 0,
                (struct sockaddr *)&router_addr, router_addr_len)) == -1) {
        perror("talker_circuit: sendto");
        exit(1);
    }

    fprintf(stderr, "Sent key to router\n");

    // unsigned char *crypt_text;
    // int crypt_text_len;
    // unsigned char *clear_crypt_text;
    // int clear_crypt_text_len;

    // AES_KEY enc_key;
    // AES_KEY dec_key;

    // unsigned char *clear_text;
    // sprintf((char*)clear_text,"%d",port_number_router_int_global[0]);
    // int clear_text_len = strlen(clear_text) + 1;

    // class_AES_set_encrypt_key(key_text, &enc_key);
    // class_AES_encrypt_with_padding(clear_text, clear_text_len, &crypt_text, &crypt_text_len, &enc_key);
    // fprintf(stderr, "%s and crypt size=%d and clear text len =%d\n", crypt_text, crypt_text_len, clear_text_len);

    // class_AES_set_decrypt_key(key_text, &enc_key);
    // class_AES_decrypt_with_padding(crypt_text, crypt_text_len, &clear_crypt_text, &clear_crypt_text_len, &enc_key);
    // fprintf(stderr, "%s\n", clear_crypt_text);

    // /* caller must free the buffers */
    // free(crypt_text);
    // free(clear_crypt_text);

    for(int i=1;i<=m_hops;i++){
        memset(&control_message, 0, sizeof(control_message));   
        memset(&buf, 0, sizeof(buf));
        struct iphdr *ip = (struct iphdr*) control_message;
        struct cntrl_header * cnt_h =  (struct cntrl_header *) (control_message+ sizeof(struct iphdr));
    
        //memset(&ip, 0x00, sizeof(ip));
        ip->saddr = inet_addr("127.0.0.1");
        ip->daddr = inet_addr("127.0.0.1");
        ip->protocol = 253;
        my_addr.sin_family = AF_INET;
        my_addr.sin_port = htons(port_number_router_int_global[0]);
        my_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        memset(my_addr.sin_zero,'\0',sizeof my_addr.sin_zero);
        socklen_t my_addr_len = sizeof(struct sockaddr_in);

        cnt_h->type = 0x52;
        cnt_h->circuit_id = 0x01;
        cnt_h->next_name = port_number_router_int_global[i];
        if(i==m_hops){
            cnt_h->next_name = 0xffff;
        }
        
        if ((numbytes = sendto(sockfd_proxy,control_message,30, 0,
                (struct sockaddr *)&my_addr, my_addr_len)) == -1) {
            perror("talker_circuit: sendto");
            exit(1);
        }
        if(i==1){
            fprintf(stderr, "Circuit: %d. Port-%d -> %d. Port-%u \n",i, port_number_proxy,i+1,port_number_router_int_global[0]);
        }
        else{
            fprintf(stderr, "Circuit: %d. Port-%d -> %d. Port-%u \n\n",i,port_number_router_int_global[i],i+1,port_number_router_int_global[i+1]);
        }


        if ((numbytes = recvfrom(sockfd_proxy, buf,30, 0,
                (struct sockaddr *)&incoming_addr, &(incoming_addr_len))) == -1) {
            perror("recvfrom_proxy_circuit");
            exit(1);
        }
        if(i==0){
            fprintf(stderr, "Circuit: %d. Port-%d -> %d. Port-%u \n",i, port_number_proxy,i+1,port_number_router_int_global[0]);
        }
        else{   
            fprintf(stderr, "Circuit: %d. Port-%d -> %d. Port-%u \n\n",i,port_number_router_int_global[i],i+1,port_number_router_int_global[i+1]);
        }    
    }

    printf("Circuit Completed %d\n", numbytes);
    return key;
}