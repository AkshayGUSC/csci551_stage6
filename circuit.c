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
    uint8_t key[16];
};

struct cntrl_header{
	uint8_t type;
	uint16_t circuit_id;
	uint16_t next_name;		
};

bool is_duplicate(int h, int val){
    for(int i=0;i<h;i++){
        if(val == hops_router_index_list[i]){
            return 1;
        }
    }
    return 0;
}

void generate_random_router(int routers, int hops){
    srand (time(NULL));
    memset(&hops_router_index_list,-1,sizeof hops_router_index_list);
    for(int i=0;i<hops;){
        int num_x = rand()%routers;
        if(is_duplicate(hops, num_x)){
            continue;
        }
        else{
            hops_router_index_list[i] = num_x;
            i++;
        }
    }
}

void generate_set_router(int routers, int hops){
    memset(&hops_router_index_list,-1,sizeof hops_router_index_list);
    for(int i=0;i<hops;i++){
        hops_router_index_list[i] = i;
    }
}

uint8_t* circuit_creation(int n_routers, int m_hops){

    fprintf(stderr,"Generating random numbers\n");
    generate_random_router(n_routers, m_hops);
    for(int i=0;i<m_hops;i++){
        fprintf(stderr,"hop %d = %d\n",i, hops_router_index_list[i]);
    }

	char control_message[30], buf[30], encrypt_message[40];
	int numbytes;
	struct sockaddr_in my_addr, router_addr;
    struct sockaddr_in incoming_addr;
    socklen_t incoming_addr_len = sizeof(struct sockaddr_in);

    for(int i=1;i<=m_hops;i++){
        out_proxy = fopen("stage7.proxy.out","a+");
        fprintf(out_proxy,"hop: %d, router: %d\n",i,i);
        fclose(out_proxy);
    }

    static uint8_t key[16*6] = {0};
    int k =1;
    int temp;
    //fprintf(stderr,"%%%%%%%%%%%%%%%%!!!\n");
    while(k<=m_hops){
        temp = 16*(k-1);
        for(int i=temp;i<temp+16;i++){
            key[i]= rand()%255;
           // fprintf(stderr,"%x",key[i]);
        }
        k++;
    }

    // struct iphdr *ip_encrypt = (struct iphdr*) encrypt_message;
    // struct encrypt_header *encrypt_h = (struct encrypt_header *) (encrypt_message+ sizeof(struct iphdr));
    // ip_encrypt->saddr = inet_addr(ip_address_info_stage6("eth0"));
    // ip_encrypt->daddr = address_list_global[1]; // sending next hop address
    // ip_encrypt->protocol = 250;

    // router_addr.sin_family = AF_INET;
    // router_addr.sin_port = htons(port_number_router_int_global[0]);
    // router_addr.sin_addr.s_addr = address_list_global[0];
    // memset(router_addr.sin_zero,'\0',sizeof router_addr.sin_zero);
    // socklen_t router_addr_len = sizeof(struct sockaddr_in);
    // encrypt_h->type = 0x65;
    // encrypt_h->circuit_id = 0x01;

    // unsigned char *key_text;
    // //fprintf(stderr, "printing KEY IN CHAR\n");
    // for(int i=0;i<16;i++){
    //    encrypt_h->key[i] = key[i];
    // }
    // key_text = (unsigned char*)encrypt_h->key;
    // for(int i=0;i<16;i++){
    //     //fprintf(stderr, "%x",key_text[i]);
    // }

    //     out_proxy = fopen("stage7.proxy.out","a+");
    //     fprintf(out_proxy,"new-fake-diffe-hellman, router index: 1 circuit outgoing: 0x01, key: ");
    //     for(int i=0;i<16;i++){
    //         fprintf(out_proxy, "%x",key_text[i]);
    //     }
    //     fprintf(out_proxy,"\n");
    //     fclose(out_proxy);

    // if ((numbytes = sendto(sockfd_proxy,encrypt_message,40, 0,
    //             (struct sockaddr *)&router_addr, router_addr_len)) == -1) {
    //     perror("talker_circuit: sendto");
    //     exit(1);
    // }

    //fprintf(stderr, "Sent key to router\n");

    for(int i=0;i<m_hops;i++){

        memset(&control_message, '\0', sizeof(control_message));   
        memset(&buf, '\0', sizeof(buf));
        struct iphdr *ip = (struct iphdr*) control_message;
        struct cntrl_header * cnt_h =  (struct cntrl_header *) (control_message+ sizeof(struct iphdr));
    
        //memset(&ip, 0x00, sizeof(ip));

        if(i==0){
            ip->saddr = inet_addr(ip_address_info_stage6("eth0"));         // proxy address for 1st router
            ip->daddr = address_list_global[hops_router_index_list[i+1]]; // next_hop ip address
        }
        else{
            ip->saddr = address_list_global[hops_router_index_list[i-1]]; // previous router ip address
            ip->daddr = address_list_global[hops_router_index_list[i+1]]; // next_hop ip address
            fprintf(stderr, "in circuit incoming ip=%s\n",inet_ntoa(*(struct in_addr*)&ip->saddr));
            fprintf(stderr, "in circuit outgoing ip=%s\n",inet_ntoa(*(struct in_addr*)&ip->daddr));
        }
        
        ip->protocol = 253;
        my_addr.sin_family = AF_INET;
        my_addr.sin_port = htons(port_number_router_int_global[hops_router_index_list[0]]);
        my_addr.sin_addr.s_addr = address_list_global[hops_router_index_list[0]];
        memset(my_addr.sin_zero,'\0',sizeof my_addr.sin_zero);
        socklen_t my_addr_len = sizeof(struct sockaddr_in);

        cnt_h->type = 0x62;
        cnt_h->circuit_id = 0x01;
        cnt_h->next_name = port_number_router_int_global[hops_router_index_list[i+1]];
        if(i==(m_hops-1)){
            cnt_h->next_name = 0xffff;
        }
        
        if ((numbytes = sendto(sockfd_proxy,control_message,30, 0,
                (struct sockaddr *)&my_addr, my_addr_len)) == -1) {
            perror("talker_circuit: sendto");
            exit(1);
        }
        fprintf(stderr, "Sent from circuit \n" );

        if ((numbytes = recvfrom(sockfd_proxy, buf,30, 0,
                (struct sockaddr *)&incoming_addr, &(incoming_addr_len))) == -1) {
            perror("recvfrom_proxy_circuit");
            exit(1);
        }

        struct cntrl_header * cnt_h_recv =  (struct cntrl_header *) (buf+ sizeof(struct iphdr));

        out_proxy = fopen("stage7.proxy.out","a+");
        fprintf(out_proxy,"pkt from port: %u, length: 3, contents: 0x%x%04x\n",ntohs(incoming_addr.sin_port),cnt_h_recv->type,cnt_h_recv->circuit_id);

        fprintf(out_proxy,"incoming extend-done circuit, incoming: 0x%x from port: %u\n",cnt_h_recv->circuit_id,ntohs(incoming_addr.sin_port));
        fclose(out_proxy); 
    }

    printf("Here Circuit Completed %d\n", numbytes);
    return key;
}