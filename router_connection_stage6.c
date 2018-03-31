/*
This file contains code for router used for stage 5.

Here in client_connection_stage5 sends all its required details to proxy and handles the incomeing 
and outgoing messages of the routers.
This is actually a child process forked to create routers

*/
#include "main_header.h"

struct cntrl_header{
    uint8_t type; 
    uint16_t circuit_id;
    uint16_t next_name;     
};

struct relay_header{
    uint16_t type;
    uint16_t circuit_id;   
};

/*copied attribute feature from https://stackoverflow.com/questions/6732127/is-there-a-way-to-enforce-specific-endianness-for-a-c-or-c-struct*/
struct __attribute__((packed, scalar_storage_order("big-endian")))encrypt_header{
    uint8_t type;
    uint16_t circuit_id;
    unsigned char key[96];
};

uint16_t in_c_id;
uint16_t out_c_id;
uint16_t in_port;
uint16_t out_port;
unsigned char key[16];
int client_connection_stage6(int x){

    int sockfd, sockfd_raw, sockfd_loopback;
    int rv, n;
    int numbytes;
    struct sockaddr_in their_addr, binding, router_addr, send_addr;
    socklen_t addr_len = sizeof(struct sockaddr);
    struct ifreq ifr;
    int flag_extend =1;
    int flag_key = 1;
    address_list_global[0]=inet_addr(ip_address_info("eth1"));
    address_list_global[1]=inet_addr(ip_address_info("eth2"));
    address_list_global[2]=inet_addr(ip_address_info("eth3"));
    address_list_global[3]=inet_addr(ip_address_info("eth4"));
    address_list_global[4]=inet_addr(ip_address_info("eth5"));
    address_list_global[5]=inet_addr(ip_address_info("eth6"));
    char if_name[5];
    char router_ip[16];
    unsigned char key_text[16];
    sprintf(if_name,"%s","eth");
    sprintf(if_name+strlen(if_name),"%d",x);
    strcpy(router_ip,ip_address_info(if_name));

    //fprintf(stderr, "routers ip address is this %s\n",router_ip);

    /*sockfd is binded to the routers IP address for UDP*/
    if ((sockfd = socket(AF_INET, SOCK_DGRAM,0)) == -1) {
            perror("Router: UDP socket");
    }  
    router_addr.sin_addr.s_addr = inet_addr(router_ip);
    router_addr.sin_family = AF_INET;
    router_addr.sin_port = htons(0);
    if (bind(sockfd, (struct sockaddr *)&router_addr, sizeof(router_addr)) == -1) {
        close(sockfd);
        perror("Bind to IP ERROR:  UDP sockfd");
    }
    /* Getting the router UDP port number*/
    char child_pid[100];
    sprintf(child_pid,"%d", getpid());
    struct sockaddr_in socket_addr;
    socklen_t length = sizeof(socket_addr);

    if(getsockname(sockfd, (struct sockaddr *)&socket_addr,&length) == -1){
        perror("error in getsocketname()");
        exit(-1);
    }
    port_number_router = (int)ntohs(socket_addr.sin_port);

    sprintf(child_pid+strlen(child_pid),"a");
    sprintf(child_pid+strlen(child_pid),"%d", port_number_router);

    /*sockfd_raw is binded to the routers IP address & also ethernet interface for Internet*/
    if ((sockfd_raw = socket(AF_INET, SOCK_RAW,
            IPPROTO_ICMP)) == -1) {
        perror("talker: raw socket");
    }     
    char interface_index[10];
    sprintf(interface_index,"eth"); 
    sprintf(interface_index+strlen(interface_index),"%d",x); 
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name),interface_index);
    fprintf(stderr,"router ip address %s binded to %s\n", router_ip,interface_index);
    if((rv = setsockopt(sockfd_raw, SOL_SOCKET, SO_BINDTODEVICE, (void*)&ifr, sizeof(ifr)))<0){
        perror("Router-error binding to eth1: sockfd_raw");
        close(sockfd_raw);
        exit(-1);
    }       
    binding.sin_addr.s_addr = inet_addr(router_ip);
    binding.sin_family = AF_INET;
    binding.sin_port = htons(0);
    if (bind(sockfd_raw, (struct sockaddr *)&binding, sizeof(binding)) == -1) {
        close(sockfd_raw);
        perror("listener: raw bind");
    }

    /*sockfd_loopback is binded to the loopback address on same port as UDP for circuit creation*/
    if ((sockfd_loopback = socket(AF_INET, SOCK_DGRAM,0)) == -1) {
            perror("Router: UDP socket");
    } 
    router_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    router_addr.sin_family = AF_INET;
    router_addr.sin_port = htons(port_number_router);
    if (bind(sockfd_loopback, (struct sockaddr *)&router_addr, sizeof(router_addr)) == -1) {
        close(sockfd);
        perror("Bind to IP ERROR:  UDP sockfd");
    }

    char filename[100];
    sprintf(filename,"stage6.router");
    sprintf(filename+strlen(filename),"%d",x);
    sprintf(filename+strlen(filename),".out");

    FILE *out_router = fopen(filename,"a+");
    fprintf(out_router,"router:%d, pid:%d, port:%d IP:%s\n", x, getpid(), port_number_router, router_ip);
    fclose(out_router);

    send_addr.sin_family = AF_INET;
    send_addr.sin_port = htons(port_number_proxy);
    send_addr.sin_addr.s_addr = inet_addr(ip_address_info("eth0"));
    memset(send_addr.sin_zero,'\0',sizeof send_addr.sin_zero);

    if ((numbytes = sendto(sockfd,child_pid,strlen(child_pid), 0,
         (struct sockaddr *)&send_addr, sizeof send_addr)) == -1) {
        perror("talker_router_config_info_to_proxy: sendto");
        exit(1);
    }
    
    char buffer[88];

    n = sockfd_loopback +1;
    while(1){

        fd_set readfds;

        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        FD_SET(sockfd_raw, &readfds);
        FD_SET(sockfd_loopback, &readfds);

        rv = select(n, &readfds, NULL, NULL, NULL);

        if (rv == -1) {
            perror("select"); // error occurred in select()
        }

        else{
            // ICMP packet coming from proxy
            if (FD_ISSET(sockfd, &readfds)) {

                memset(&buffer, 0, sizeof buffer);

                if ((numbytes = recvfrom(sockfd, buffer, 88, 0,
                    (struct sockaddr *)&their_addr, &addr_len)) == -1) {
                    perror("recvfrom");
                    exit(1);
                }

                if(buffer[0] == '-'){
                    fprintf(stderr, "Exiting router Message received %c\n", buffer[0]);
                    fclose(out_router);
                    close(sockfd);
                    close(sockfd_raw);
                    exit(0);
                }
                
                struct relay_header *relay_data = (struct relay_header*)(buffer);
                struct iphdr *ip = (struct iphdr *)(buffer+sizeof(struct relay_header));
                struct icmphdr *icmp = (struct icmphdr *)(buffer+sizeof(struct iphdr)+ sizeof(struct relay_header));
                
                out_router = fopen(filename,"a+");
                fprintf(out_router, "pkt from port: %u, length: 87, contents: \n",ntohs(their_addr.sin_port));
                fprintf(out_router,"0x");
                for(int i=0;i<88;i++){
                    fprintf(out_router,"%02x",buffer[i]);
                }
                fprintf(out_router,"\n");
                fclose(out_router);
                

                if((relay_data->type == 97) && (relay_data->circuit_id == in_c_id)){
                    if(out_port == 65535){
                        // sendmsg format referred from http://www.microhowto.info/howto/send_an_arbitrary_ipv4_datagram_using_a_raw_socket_in_c.html
                        ip->saddr = inet_addr(router_ip);
                        their_addr.sin_addr.s_addr = ip->daddr;

                         out_router = fopen(filename,"a+");
                        fprintf(out_router, "outgoing packet, circuit incoming: 0x%02x, incoming src: %s, ",in_c_id, inet_ntoa(*(struct in_addr*)&their_addr.sin_addr.s_addr));
                        fprintf(out_router, "outgoing src: %s",router_ip);
                        fprintf(out_router, "dst: %s\n",inet_ntoa(*(struct in_addr*)&ip->daddr));
                        fclose(out_router);


                        fprintf(stderr, "sending internet address destination id =%s\n",inet_ntoa(*(struct in_addr*)&ip->daddr));
                        fprintf(stderr, "sending internet address source id =%s\n",inet_ntoa(*(struct in_addr*)&ip->saddr));
                        char buffer_tosend[84];
                        for(int i=0;i<84;i++){
                            buffer_tosend[i] = buffer[4+i]; 
                        }
                        struct msghdr buf;
                        struct iovec iov[1];
                        iov[0].iov_base= icmp;
                        iov[0].iov_len= sizeof(buffer_tosend) - sizeof(struct iphdr);
                        buf.msg_name= &(their_addr); // here their_addr is sockaddr_in
                        buf.msg_namelen= sizeof(struct sockaddr);
                        buf.msg_iov= iov;
                        buf.msg_iovlen= 1;
                        buf.msg_control=0;
                        buf.msg_controllen=0;
                        if ((numbytes = sendmsg(sockfd_raw,&buf, 0)) == -1) {
                            perror("talker_router _hello: sendmsg");
                            exit(1);
                        }
                        fprintf(stderr,"!!!!! raw packet sent + numbytes = %d\n",numbytes);
                        //fflush(NULL); 
                    }
                    else{
                        fprintf(stderr, "Relay data to router %d out_c_id=%u\n",(x+1),out_c_id);
                        ip->saddr = inet_addr(router_ip);
                        relay_data->circuit_id = out_c_id;
                        struct sockaddr_in forward_addr;
                        forward_addr.sin_family = AF_INET;
                        forward_addr.sin_port = htons(out_port);
                        forward_addr.sin_addr.s_addr = address_list_global[x]; // forward to index+1 router
                        memset(forward_addr.sin_zero,'\0',sizeof forward_addr.sin_zero);
                        fprintf(stderr, "Relay data to router %d out_c_id=%u\n",(x+1), relay_data->circuit_id);

                        out_router = fopen(filename,"a+");
                        fprintf(out_router, "relay packet, circuit incoming:0x%02x, outgoing:0x%02x, incoming src:%s, ",in_c_id, out_c_id, inet_ntoa(*(struct in_addr*)&their_addr.sin_addr.s_addr));
                        fprintf(out_router, "outgoing src:%s",router_ip);
                        fprintf(out_router, "dst:%s\n",inet_ntoa(*(struct in_addr*)&ip->daddr));
                        fclose(out_router);
                        fprintf(stderr, "Relay data to router %d out_c_id=%u\n",(x+1), relay_data->circuit_id);

                        if ((numbytes = sendto(sockfd,buffer,88, 0,
                            (struct sockaddr *)&forward_addr, sizeof forward_addr)) == -1) {
                            perror("talker_router_forwarddata_to_next_router: sendto");
                            exit(1);
                        }
                    }
                } 
                else if((relay_data->type == 100) /*&& (relay_data->circuit_id == out_c_id)*/){
                    // if router 1 send to proxy
                    if(x==1){
                        send_addr.sin_family = AF_INET;
                        send_addr.sin_port = htons(port_number_proxy);
                        send_addr.sin_addr.s_addr = inet_addr(ip_address_info("eth0"));
                        memset(send_addr.sin_zero,'\0',sizeof send_addr.sin_zero);

                        out_router = fopen(filename,"a+");
                        fprintf(out_router, "relay reply packet, circuit incoming: 0x%02x, outgoing: 0x%02x, src:%s, ",out_c_id, in_c_id, inet_ntoa(*(struct in_addr*)&ip->saddr));
                        fprintf(out_router, "incoming dst: %s ",inet_ntoa(*(struct in_addr*)&address_list_global[x-1]));
                        fprintf(out_router, "outgoing dest: %s\n",ip_address_info("eth0"));
                        fclose(out_router);
                        fprintf(stderr, "Relay data to router %d out_c_id=%u\n",(x+1), relay_data->circuit_id);

                        if ((numbytes = sendto(sockfd,buffer,88, 0,
                            (struct sockaddr *)&send_addr, sizeof send_addr)) == -1) {
                            perror("talker_router: sendto");
                            exit(1);
                        } 
                    }
                    else{
                        struct sockaddr_in forward_relay_addr;
                        forward_relay_addr.sin_family = AF_INET;
                        forward_relay_addr.sin_port = htons(in_port);
                        forward_relay_addr.sin_addr.s_addr = address_list_global[x-2]; // forward to index+1 router
                        memset(forward_relay_addr.sin_zero,'\0',sizeof forward_relay_addr.sin_zero);

                        out_router = fopen(filename,"a+");
                        fprintf(out_router, "relay reply packet, circuit incoming: 0x%02x, outgoing: 0x%02x, src: %s, ",out_c_id, in_c_id, inet_ntoa(*(struct in_addr*)&ip->daddr));
                        fprintf(out_router, "incoming dst: %s ",inet_ntoa(*(struct in_addr*)&address_list_global[x-1]));
                        fprintf(out_router, "outgoing dst: %s\n",inet_ntoa(*(struct in_addr*)&address_list_global[x-2]));
                        fclose(out_router);

                        fprintf(stderr, "Relay data to router %d out_c_id=%u\n",(x-1), relay_data->circuit_id);

                        if ((numbytes = sendto(sockfd,buffer,88, 0,
                            (struct sockaddr *)&forward_relay_addr, sizeof forward_relay_addr)) == -1) {
                            perror("talker_router_relaydata_to_next_router: sendto");
                            exit(1);
                        }
                    }
                }
                else{
                    fprintf(stderr, "The packet is not having correct id\n");
                    continue;
                }       
            }
            //icmp packet coming from internet at raw socket
            if (FD_ISSET(sockfd_raw, &readfds)) {

                printf("Receiving at raw socket from Internet\n");
                char buffer_torecv[84];
                memset(&buffer_torecv, 0, sizeof buffer_torecv);
                struct msghdr buf;
                struct iovec iov[1];
                iov[0].iov_base = buffer_torecv;
                buf.msg_iov = iov;
                iov[0].iov_len= sizeof(buffer_torecv);
                buf.msg_iovlen= 1;


                if ((numbytes = recvmsg(sockfd_raw, &buf, 0)) == -1) {
                    perror("recvfrom from raw scoket");
                    exit(1);
                }                
                fprintf(stderr, "Message from Internet = %d\n", numbytes);
                struct iphdr *ip = (struct iphdr *)(buffer_torecv);

                out_router = fopen(filename,"a+");
                fprintf(out_router, "incoming packet, src: %s, ", inet_ntoa(*(struct in_addr*)&ip->saddr));
                fprintf(out_router, "dst: %s, outgoing circuit: 0x%02x\n", router_ip, in_c_id);
                fclose(out_router);

                fprintf(out_router, "ICMP from raw sock, src: %s, dst: %s, type: 0\n", inet_ntoa(*(struct in_addr*)&ip->saddr), router_ip);
                //fflush(NULL);
                //fprintf(out_proxy, "ICMP from port: %d, src: %s, dst: 10.0.2.15, type: 0\n",port_number_proxy, inet_ntoa(*(struct in_addr*)&ip->saddr));
               // fflush(NULL);

                memset(&buffer, 0, sizeof buffer);
                struct relay_header *relay_data = (struct relay_header*)(buffer);
                relay_data->type = 0x64;
                relay_data->circuit_id = in_c_id;

                for(int i=0;i<84;i++){
                    buffer[4+i] = buffer_torecv[i];
                }
                // if router 1 send to proxy
                if(x==1){
                    send_addr.sin_family = AF_INET;
                    send_addr.sin_port = htons(port_number_proxy);
                    send_addr.sin_addr.s_addr = inet_addr(ip_address_info("eth0"));
                    memset(send_addr.sin_zero,'\0',sizeof send_addr.sin_zero);
                    if ((numbytes = sendto(sockfd,buffer,88, 0,
                        (struct sockaddr *)&send_addr, sizeof send_addr)) == -1) {
                        perror("talker_router: sendto");
                        exit(1);
                    } 
                }
                else{
                    struct sockaddr_in forward_relay_addr;
                    forward_relay_addr.sin_family = AF_INET;
                    forward_relay_addr.sin_port = htons(in_port);
                    forward_relay_addr.sin_addr.s_addr = address_list_global[x-2]; // forward to index+1 router
                    memset(forward_relay_addr.sin_zero,'\0',sizeof forward_relay_addr.sin_zero);
                    fprintf(stderr, "Relay data to router %d c_id=%u\n",(x-1), relay_data->circuit_id);

                    if ((numbytes = sendto(sockfd,buffer,88, 0,
                        (struct sockaddr *)&forward_relay_addr, sizeof forward_relay_addr)) == -1) {
                        perror("talker_router_relaydata_to_next_router: sendto");
                        exit(1);
                    }
                }
                  
            }

            if (FD_ISSET(sockfd_loopback, &readfds)) {
                char incoming_buf[88];
                struct sockaddr_in incoming_addr;
                socklen_t incoming_addr_len = sizeof(struct sockaddr_in);
                struct sockaddr_in send_addr;
                socklen_t addr_len = sizeof(struct sockaddr);

                memset(&incoming_buf, 0, sizeof incoming_buf);


                if ((numbytes = recvfrom(sockfd_loopback, incoming_buf,sizeof(incoming_buf), 0,
                    (struct sockaddr *)&incoming_addr, &incoming_addr_len)) == -1) {
                    perror("recvfrom in scokfd_loopback");
                    exit(1);
                }
                fprintf(stderr,"Received packet at ROuter !!!\n");
                struct iphdr *ip = (struct iphdr *)(incoming_buf);
                struct encrypt_header *encrypt_h = (struct encrypt_header *) (incoming_buf+ sizeof(struct iphdr));

                fprintf(stderr, "############# encrypt_h->type = 0x%x\n",encrypt_h->type);
                if(encrypt_h->type == 0x65 && flag_key ==1 && x==1){
                    out_proxy = fopen(filename,"a+");
                    fprintf(out_router, "pkt from port: %u, length: 19, contents: ",ntohs(their_addr.sin_port));
                    fprintf(out_router,"0x");
                    for(int i=0;i<16;i++){
                        fprintf(out_router,"%02x",incoming_buf[i]);
                    }
                    fprintf(out_router,"\n");
                    fprintf(out_proxy,"fake-diffe-hellman, router index: 1 circuit outgoing: 0x01, key: 0x");
                    for(int i=0;i<16;i++){
                        fprintf(out_proxy, "%x",encrypt_h->key[i]);
                    }                    
                    for(int i=0;i<16;i++){
                        key_text[i] = encrypt_h->key[i];
                        fprintf(stderr, "%x",key_text[i]);
                    }
                    fprintf(stderr, "\n");
                    fprintf(out_proxy,"\n");
                    fclose(out_proxy);
                    flag_key =0;
                    continue;
                }

                else if(encrypt_h->type == 0x65 && flag_key ==1 && x!=1){

                    fprintf(stderr, "Now at router %d receiving key\n",x);
                    out_proxy = fopen(filename,"a+");
                    fprintf(out_router, "pkt from port: %u, length: 16, contents: ",ntohs(their_addr.sin_port));
                    fprintf(out_router,"0x");
                    for(int i=0;i<16;i++){
                        fprintf(out_router,"%02x",incoming_buf[i]);
                    }
                    fprintf(out_router,"\n");
                    fprintf(out_proxy,"fake-diffe-hellman, router index: %d circuit outgoing: 0x01, key: 0x",x);
                    for(int i=0;i<16;i++){
                        fprintf(out_proxy, "%x",encrypt_h->key[i]);
                    }                    
                    for(int i=0;i<16;i++){
                        key_text[i] = encrypt_h->key[i];
                        fprintf(stderr, "%x",key_text[i]);
                    }
                    fprintf(stderr, "\n");
                    fprintf(out_proxy,"\n");
                    fclose(out_proxy);
                    flag_key =0;
                    continue;
                }

                else if(encrypt_h->type == 0x65 && flag_key ==0){
                    fprintf(stderr, "At router %d forwarding key\n",x);
                    unsigned char *clear_crypt_text;
                    int clear_crypt_text_len;
                    AES_KEY dec_key;
                    unsigned char crypt_text[strlen((char*)encrypt_h->key)+1]; 
                    fprintf(stderr, "Length of crypt text received from proxy = %d\n",strlen((char*)encrypt_h->key));                  
                    memcpy(crypt_text,encrypt_h->key,strlen((char*)encrypt_h->key)+1);
                    int crypt_text_len = strlen((char*)crypt_text); 

                    for(int i=0;i<16;i++){
                        fprintf(stderr, "%x",key_text[i]);
                    }  
                    fprintf(stderr, "\n crypt_text_len=%d\n",crypt_text_len);

                    class_AES_set_decrypt_key(key_text, &dec_key);
                    class_AES_decrypt_with_padding(crypt_text, crypt_text_len, &clear_crypt_text, &clear_crypt_text_len, &dec_key);
                    send_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
                    send_addr.sin_family = AF_INET;
                    send_addr.sin_port = htons(out_port);
                    memset(send_addr.sin_zero,'\0',sizeof send_addr.sin_zero);

                    memcpy(encrypt_h->key,clear_crypt_text,strlen(clear_crypt_text)+1);

                    fprintf(stderr,"out_port = %u",out_port);

                    for(int i=0;i<16;i++){
                        fprintf(stderr, "%x",clear_crypt_text[i]);
                    } 

                    if ((numbytes = sendto(sockfd,incoming_buf,sizeof(incoming_buf), 0,
                            (struct sockaddr *)&send_addr, addr_len)) == -1) {
                        perror("talker_router_circuit: sendto");
                        exit(1);
                    }

                    free(clear_crypt_text);
                }

                else if(encrypt_h->type == 0x62 && (flag_extend == 1) && (x==1)){

                    fprintf(stderr,"Received packet at router no.= %d\n", x);

                    in_c_id = encrypt_h->circuit_id;
                    out_c_id = x*256 +1;
                    in_port = ntohs(incoming_addr.sin_port);
                    unsigned char *clear_crypt_text;
                    int clear_crypt_text_len;
                    AES_KEY dec_key;
                    unsigned char *crypt_text;                   
                    crypt_text = encrypt_h->key;
                    int crypt_text_len = strlen(crypt_text);

                    for(int i=0;i<16;i++){
                        fprintf(stderr, "%x",key_text[i]);
                    }
                    fprintf(stderr, "\n");

                    //fprintf(stderr, "!!!!! Recieved encrypted message crypt_text length =%ld & buffer length= %d and size=%d\n",strlen(crypt_text),strlen(incoming_buf),sizeof(crypt_text));
                    class_AES_set_decrypt_key(key_text, &dec_key);
                    class_AES_decrypt_with_padding(crypt_text, crypt_text_len, &clear_crypt_text, &clear_crypt_text_len, &dec_key);

                    //fprintf(stderr, "!!!!!!!!!! clear_crypt_text length = %d @@@@@@\n",strlen(clear_crypt_text));
                    sscanf(clear_crypt_text,"%u",&out_port);
                    send_addr.sin_addr.s_addr = inet_addr(ip_address_info("eth0"));
                    send_addr.sin_family = AF_INET;
                    send_addr.sin_port = htons(in_port);

                    if ((numbytes = sendto(sockfd,incoming_buf,sizeof(incoming_buf), 0,
                                (struct sockaddr *)&send_addr, addr_len)) == -1) {
                        perror("talker_router_circuit: sendto");
                        exit(1);
                    }
                    flag_extend =0;

                    free(clear_crypt_text);
                }
                else if((encrypt_h->type == 0x62) && (flag_extend == 1) && (x!=1)){

                    fprintf(stderr,"Received packet at ROuter NO. = %d\n", x);

                    in_c_id = encrypt_h->circuit_id;
                    out_c_id = x*256 +1;
                    in_port = ntohs(incoming_addr.sin_port);
                    encrypt_h->type = 0x63;
                    unsigned char *clear_crypt_text;
                    int clear_crypt_text_len;
                    AES_KEY dec_key;
                    unsigned char *crypt_text;
                    fprintf(stderr,"Here encrypt_h = %d\n",strlen((char*)encrypt_h->key));                   
                    crypt_text = encrypt_h->key;
                    int crypt_text_len = strlen((char*)crypt_text);

                    fprintf(stderr, "crypt_text_len = %d\n", crypt_text_len);

                    for(int i=0;i<16;i++){
                        fprintf(stderr, "%x",key_text[i]);
                    }
                    fprintf(stderr,"\n");


                    class_AES_set_decrypt_key(key_text, &dec_key);
                    class_AES_decrypt_with_padding(crypt_text, crypt_text_len, &clear_crypt_text, &clear_crypt_text_len, &dec_key);

                    sscanf(clear_crypt_text,"%u",&out_port);

                    send_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
                    send_addr.sin_family = AF_INET;
                    send_addr.sin_port = htons(in_port);

                    if ((numbytes = sendto(sockfd,incoming_buf,sizeof(incoming_buf), 0,
                                (struct sockaddr *)&send_addr, addr_len)) == -1) {
                        perror("talker_router_circuit: sendto");
                        exit(1);
                    }
                    flag_extend =0;
                    free(clear_crypt_text);
                }
                else{
                    if((encrypt_h->type == 0x62) && (flag_extend == 0)){

                        send_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
                        send_addr.sin_family = AF_INET;
                        send_addr.sin_port = htons(out_port);
                        out_router = fopen(filename,"a+");
                        fprintf(out_router, "pkt from port: %u, length: 5, contents: 0x%02x%04x%04x\n",ntohs(incoming_addr.sin_port), encrypt_h->type, encrypt_h->circuit_id,encrypt_h->key);
                        fprintf(out_router, "forwarding extend circuit: incoming: 0x%02x, outgoing: 0x%02x at %u\n", in_c_id, out_c_id, out_port);
                        fclose(out_router);

                        fprintf(stderr,"**In router:%d, Forwarding Circuit Extend:IID=0x%x OID=0x%x,Incoming Port=%u Outgoing Port=%u Next_Hop=%u\n",x, in_c_id, out_c_id, in_port,out_port,encrypt_h->key);
                        encrypt_h->circuit_id = out_c_id;

                        unsigned char *clear_crypt_text;
                        int clear_crypt_text_len;
                        AES_KEY dec_key;
                        unsigned char *crypt_text;
                        crypt_text = encrypt_h->key;
                        int crypt_text_len = strlen((char*)crypt_text);

                        fprintf(stderr, "crypt_text_len=%d\n", crypt_text_len);

                        for(int i=0;i<16;i++){
                            fprintf(stderr, "%x",key_text[i]);
                        }
                        fprintf(stderr,"\n");

                        class_AES_set_decrypt_key(key_text, &dec_key);
                        class_AES_decrypt_with_padding(crypt_text, crypt_text_len, &clear_crypt_text, &clear_crypt_text_len, &dec_key);

                        memcpy(encrypt_h->key,clear_crypt_text,clear_crypt_text_len+1);

                        fprintf(stderr, "clear_crypt_text_len = %d and encrypt_h=%d\n",clear_crypt_text_len, strlen((char*)encrypt_h->key));

                        if ((numbytes = sendto(sockfd,incoming_buf,sizeof(incoming_buf), 0,
                                (struct sockaddr *)&send_addr, addr_len)) == -1) {
                            perror("talker_router_circuit: sendto");
                            exit(1);
                        }
                        free(clear_crypt_text);
                    }
                    else if((encrypt_h->type == 0x63) && (x!=1)){
                        send_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
                        send_addr.sin_family = AF_INET;
                        send_addr.sin_port = htons(in_port);
                        out_router = fopen(filename,"a+");
                        fprintf(out_router, "pkt from port: %u, length: 3, contents: 0x%02x%04x\n",ntohs(incoming_addr.sin_port), encrypt_h->type, encrypt_h->circuit_id);                            
                        fprintf(out_router, "forwarding extend-done circuit: incoming: 0x%02x, outgoing: 0x%02x at %u\n", out_c_id, in_c_id, in_port);
                        fclose(out_router);

                        fprintf(stderr,"**In router:%d, Forwarding Reply:IID=0x%x OID=0x%x,Incoming Port=%u Outgoing Port=%u Next_Hop=%u\n",x, in_c_id, out_c_id, in_port,out_port, encrypt_h->key);
                        if ((numbytes = sendto(sockfd,incoming_buf,sizeof(incoming_buf), 0,
                                (struct sockaddr *)&send_addr, addr_len)) == -1) {
                            perror("talker_router_circuit: sendto");
                            exit(1);
                        }
                    }
                    else if((encrypt_h->type == 0x63) && (x==1)){
                        send_addr.sin_addr.s_addr = inet_addr(ip_address_info("eth0"));
                        send_addr.sin_family = AF_INET;
                        send_addr.sin_port = htons(in_port);

                        out_router = fopen(filename,"a+");
                        fprintf(out_router, "pkt from port: %u, length: 3, contents: 0x%02x%04x\n",ntohs(incoming_addr.sin_port), encrypt_h->type, encrypt_h->circuit_id);                            
                        fprintf(out_router, "forwarding extend-done circuit: incoming: 0x%02x, outgoing: 0x%02x at %u\n", out_c_id, in_c_id, in_port);
                        fclose(out_router);

                        fprintf(stderr,"!!In router:%d, Forwarding Reply:IID=0x%x OID=0x%x,Incoming Port=%u Outgoing Port=%u Next_Hop=%u\n",x, in_c_id, out_c_id, in_port,out_port, encrypt_h->key);
                        if ((numbytes = sendto(sockfd,incoming_buf,sizeof(incoming_buf), 0,
                                (struct sockaddr *)&send_addr, addr_len)) == -1) {
                            perror("talker_router_circuit: sendto");
                            exit(1);
                        }
                    }
                    flag_extend =0;
                }
            }
        }  
    }
    close(sockfd);  
    exit(0);
}