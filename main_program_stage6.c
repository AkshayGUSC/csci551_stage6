/*
This file contains the code stage 6 This acts as proxy and also defines tunneling.
functions:
ip_address_info_stage6 : used for getting ip address from ethernet interfaces
server_connection_stage6: for creating proxy connection
ip_checksum_stage6- for computing the checksum (// copied the entire code for calculating checksum from http://www.microhowto.info/howto/calculate_an_internet_protocol_checksum_in_c.html#idp22752)
tunnel_reader_stage6 function handles the proxy packets
*/
#include "main_header.h"

FILE *out_proxy; 
int hops_router_index_list[6]={0};
int flag_circuit =1;
// int port_number_proxy;
// int port_number_router;
// int sockfd_proxy;
// int port_number_router_int_global[6] ={0};
// uint32_t address_list_global[6] ={0};
// char pid_router_char[100];    
// int number_routers;
// int manitor_hops =0;
uint8_t* global_key;

struct relay_header{ 
    uint8_t type;
    uint16_t circuit_id;
};

// copied entire from https://www.binarytides.com/raw-sockets-c-code-linux/
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

char* ip_address_info_stage6(char *ifname){
    int fd_ip;
    struct ifreq ifr;
    char *interface_name = ifname;
    fd_ip = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , interface_name , IFNAMSIZ-1);
    ioctl(fd_ip, SIOCGIFADDR, &ifr);
    close(fd_ip);
    char *ip_address_eth0 = inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr);
    //display result
    //printf("%s - %s\n" , interface_name , inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr) );
    return ip_address_eth0;
}

int server_connection_stage6(){ 
    /*Socket connection code copied from BEEJ TUTORIAL*/
    int sockfd;
    struct sockaddr_in proxy_addr;
    
    if ((sockfd = socket(AF_INET, SOCK_DGRAM,0)) == -1) {
        perror("talker: raw socket");
    }

    memset(&proxy_addr, 0x00, sizeof(struct sockaddr_in));    
    proxy_addr.sin_addr.s_addr = inet_addr(ip_address_info_stage6("eth0"));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(0);
    if (bind(sockfd, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) == -1) {
        close(sockfd);
        perror("listener: raw bind");
    }
    
    struct sockaddr_in socket_addr;
    socklen_t length = sizeof(socket_addr);
    if(getsockname(sockfd, (struct sockaddr *)&socket_addr,&length) == -1){
        perror("error in getsocketname()");
        exit(-1);
    }
    port_number_proxy = (int)ntohs(socket_addr.sin_port);

    out_proxy = fopen("stage7.proxy.out","a+");
    fprintf(out_proxy,"proxy port: %d\n",port_number_proxy);
    fclose(out_proxy);
    //fflush(NULL);
    return sockfd;
}

// copied the entire code for calculating checksum from http://www.microhowto.info/howto/calculate_an_internet_protocol_checksum_in_c.html#idp22752
uint16_t ip_checksum_stage6(void* vdata,size_t length) {
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint32_t acc=0xffff;

    // Handle complete 16-bit blocks.
    for (size_t i=0;i+1<length;i+=2) {
        uint16_t word;
        memcpy(&word,data+i,2);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Handle any partial block at the end of the data.
    if (length&1) {
        uint16_t word=0;
        memcpy(&word,data+length-1,1);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}
int tun_alloc_stage6(char *dev, int flags) 
{
    struct ifreq ifr;
    int fd, err;
    char *clonedev = (char*)"/dev/net/tun";

    if( (fd = open(clonedev , O_RDWR)) < 0 ) 
    {
    perror("Opening /dev/net/tun");
    return fd;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;

    if (*dev) 
    {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) 
    {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
    }

    strcpy(dev, ifr.ifr_name);
    return fd;
}


int tunnel_reader_stage6()
{
    char tun_name[IFNAMSIZ];
    char buffer[MAX_TCP_BUF_LEN];
    int n, numbytes;
    struct sockaddr_in my_addr;
    int rv =0;
    /* Connect to the tunnel interface (make sure you create the tunnel interface first) */
    strcpy(tun_name, "tun1");
    int tun_fd = tun_alloc_stage6(tun_name, IFF_TUN | IFF_NO_PI);

    if(tun_fd < 0)
    {
        perror("Open tunnel interface");
        exit(1);
    }

    n = tun_fd + 1;     

    while(1) 
    {
        struct timeval tv;
        fd_set readfds;

        tv.tv_sec = 10;
        tv.tv_usec = 500000;

        FD_ZERO(&readfds);
        FD_SET(sockfd_proxy, &readfds);
        FD_SET(tun_fd, &readfds);


        rv = select(n, &readfds, NULL, NULL, &tv);


        if (rv == -1) {
            perror("select"); // error occurred in select()
        } 
        else if(rv == 0){
            ////fprintf(stderr, "exiting proxy\n");
            char close_router[10];
            sprintf(close_router,"%s","-1\0");
            for(int i=0;i<number_routers;i++){ 

                struct sockaddr_in send_addr;
                send_addr.sin_family = AF_INET;
                send_addr.sin_port = htons(port_number_router_int_global[i]);
                send_addr.sin_addr.s_addr = address_list_global[i];
                memset(send_addr.sin_zero,'\0',sizeof send_addr.sin_zero);

                ////fprintf(stderr,"now sending from main_program.c\n");
                //fprintf(stderr, "address is %u and port number is %d\n",address_list_global[i], port_number_router_int_global[i]);

                if ((numbytes = sendto(sockfd_proxy,close_router,strlen(close_router), 0,
                            (struct sockaddr *)&send_addr, sizeof send_addr)) == -1) {
                    perror("talker_PROXY: sendto");
                    exit(1);
                }
            }   
            close(sockfd_proxy);
            exit(0);
        } 
        else {
        // one or both of the descriptors have data
            if (FD_ISSET(sockfd_proxy, &readfds)) {

                char incoming_buf[MAX_TCP_BUF_LEN];
                struct sockaddr_in incoming_addr;
                socklen_t incoming_addr_len = sizeof(struct sockaddr_in);
                memset(&incoming_buf, '\0', sizeof incoming_buf);

                if ((numbytes = recvfrom(sockfd_proxy, incoming_buf,sizeof incoming_buf, 0,
                    (struct sockaddr *)&incoming_addr, &incoming_addr_len)) == -1) {
                    perror("recvfrom in scokfd_proxy");
                    exit(1);
                }
               
                struct relay_header *relay_data = (struct relay_header*)(incoming_buf);
                struct iphdr *ip_incoming = (struct iphdr *)(incoming_buf+sizeof(struct relay_header));

                ////fprintf(stderr, "In proxy, type=%x, id=%x\n", relay_data->type, relay_data->circuit_id);
                out_proxy = fopen("stage7.proxy.out","a+");
                fprintf(out_proxy, "pkt from port: %u, length: 87, contents:\n",ntohs(incoming_addr.sin_port));
                fprintf(out_proxy,"0x");
                for(int i=0;i<numbytes;i++){
                    fprintf(out_proxy,"%02x",incoming_buf[i]);
                }
                fprintf(out_proxy,"\n");
                fprintf(out_proxy, "incoming packet, circuit incoming:0x%02x, src:%s, ",relay_data->circuit_id, inet_ntoa(*(struct in_addr*)&ip_incoming->saddr));
                fprintf(out_proxy, "dst:%s\n",ip_address_info_stage6("eth0"));
                fclose(out_proxy);

                char buf_write[MAX_TCP_BUF_LEN];
                for(int i=0;i<(numbytes-CNTRL_HEADER_SIZE);i++){
                    buf_write[i] = incoming_buf[CNTRL_HEADER_SIZE+i];
                }

                struct iphdr *ip = (struct iphdr *)(buf_write);
                struct tcphdr *tcp_h = (struct tcphdr*)(buf_write+ sizeof (struct iphdr));
                ip->daddr = inet_addr(ip_address_info_stage6("eth0"));
                ip->check = 0;           
                ip->check = ip_checksum_stage6(ip,TCP_HEADER_SIZE);
                ////fprintf(stderr, "writing back to tunnel\n");
                tcp_h->check = 0;

                if(ip->protocol == 6){
                    //Copied code from https://www.binarytides.com/raw-sockets-c-code-linux/
                    struct pseudo_header psh;
                    psh.source_address = ip->saddr;
                    psh.dest_address = ip->daddr;
                    psh.placeholder = 0;
                    psh.protocol = IPPROTO_TCP;
                    int tcp_segment_size = numbytes-CNTRL_HEADER_SIZE-sizeof(struct iphdr);
                    psh.tcp_length = htons(tcp_segment_size);
                    int psize = sizeof(struct pseudo_header) + tcp_segment_size;
                    char *pseudogram = malloc(psize);
                    memcpy(pseudogram ,(char*)&psh ,sizeof (struct pseudo_header));
                    memcpy(pseudogram + sizeof(struct pseudo_header) , tcp_h , tcp_segment_size);
                    tcp_h->check = checksum_tcp((unsigned short*) pseudogram, psize);
                    free(pseudogram);
                }
                write(tun_fd, buf_write, numbytes-CNTRL_HEADER_SIZE);
            }
            if (FD_ISSET(tun_fd, &readfds)) {

                /* Now read data coming from the tunnel */
                int nread = read(tun_fd,buffer,sizeof(buffer));

                if(nread < 0) 
                {
                    perror("Reading from tunnel interface");
                    close(tun_fd);
                    exit(1);
                }
                else
                {                    
                    struct iphdr *ip = (struct iphdr *)(buffer);
                    struct tcphdr *tcp_h = (struct tcphdr*)(buffer+sizeof(struct iphdr));

                    if(ip->protocol == 6){
                        //fprintf(stderr,"hello tcp\n");
                        if(flag_circuit == 1){
                            global_key = circuit_creation(number_routers,manitor_hops);
                            flag_circuit =0;
                        }
                        char buf_whole[MAX_TCP_BUF_LEN];
                        memset(&buf_whole,'\0',sizeof buf_whole);

                        struct relay_header *relay_data = (struct relay_header*)(buf_whole);
                        relay_data->type = 0x61;
                        relay_data->circuit_id = 0x01;

                        for(int i=0;i<nread;i++){
                            buf_whole[CNTRL_HEADER_SIZE+i] = buffer[i];
                        }
                        out_proxy = fopen("stage7.proxy.out","a+");
                        fprintf(out_proxy, "TCP from tunnel, src IP/port: %s:%d, ",inet_ntoa(*(struct in_addr*)&ip->saddr), ntohs(tcp_h->th_sport));
                        fprintf(out_proxy, "dst IP/port: %s:%d, ",inet_ntoa(*(struct in_addr*)&ip->daddr), ntohs(tcp_h->th_dport));
                        fprintf(out_proxy, "seqno: %d, ackno: %d\n",ntohs(tcp_h->seq), ntohs(tcp_h->ack_seq));
                        fclose(out_proxy);
                        //int index = ntohl(ip->daddr) % number_routers; 
                        //index++;
                        //int index =1;
                        //fprintf(stderr, "index value hashmap = %d\n", index);
                        my_addr.sin_family = AF_INET;
                        my_addr.sin_port = htons(port_number_router_int_global[hops_router_index_list[0]]);
                        my_addr.sin_addr.s_addr = address_list_global[hops_router_index_list[0]];
                        memset(my_addr.sin_zero,'\0',sizeof my_addr.sin_zero);
                        if ((numbytes = sendto(sockfd_proxy,buf_whole,(nread+CNTRL_HEADER_SIZE), 0,
                            (struct sockaddr *)&my_addr, sizeof my_addr)) == -1) {
                            perror("talker_PROXY: sendto");
                            exit(1);
                        }

                    }

                    else if(ip->protocol ==1){

                        if(flag_circuit == 1){
                            global_key = circuit_creation(number_routers,manitor_hops);
                            flag_circuit =0;
                        }

                        char buf_whole[88];
                        memset(&buf_whole,'\0',sizeof buf_whole);

                        struct relay_header *relay_data = (struct relay_header*)(buf_whole);
                        relay_data->type = 0x61;
                        relay_data->circuit_id = 0x01;

                        for(int i=0;i<nread;i++){
                            buf_whole[CNTRL_HEADER_SIZE+i] = buffer[i];
                        }

                        //fprintf(stderr, "In proxy: type=0x%x and circuit_id=0x%x\n",relay_data->type , relay_data->circuit_id);
                        out_proxy = fopen("stage7.proxy.out","a+");
                        fprintf(out_proxy, "ICMP from tunnel, src: %s, ",inet_ntoa(*(struct in_addr*)&ip->saddr));
                        fprintf(out_proxy, "dst: %s, type: 8\n",inet_ntoa(*(struct in_addr*)&ip->daddr));
                        fclose(out_proxy);
                        // int index = ntohl(ip->daddr) % number_routers; 
                        // index++;
                        //fprintf(stderr, "index value hashmap = %d\n", index);
                        my_addr.sin_family = AF_INET;
                        my_addr.sin_port = htons(port_number_router_int_global[hops_router_index_list[0]]);
                        my_addr.sin_addr.s_addr = address_list_global[hops_router_index_list[0]];
                        memset(my_addr.sin_zero,'\0',sizeof my_addr.sin_zero);
                        //fprintf(stderr, "port number =%d and address =%u\n",port_number_router_int_global[index-1],address_list_global[index-1]);
                        if ((numbytes = sendto(sockfd_proxy,buf_whole,88, 0,
                            (struct sockaddr *)&my_addr, sizeof my_addr)) == -1) {
                            perror("talker_PROXY: sendto");
                            exit(1);
                        }                     
                    }
                }

            }
        }

    
    }
}

int main_stage6() 
{
    address_list_global[0]=inet_addr(ip_address_info_stage6("eth1"));
    address_list_global[1]=inet_addr(ip_address_info_stage6("eth2"));
    address_list_global[2]=inet_addr(ip_address_info_stage6("eth3"));
    address_list_global[3]=inet_addr(ip_address_info_stage6("eth4"));
    address_list_global[4]=inet_addr(ip_address_info_stage6("eth5"));
    address_list_global[5]=inet_addr(ip_address_info_stage6("eth6"));

    sockfd_proxy = server_connection_stage6();
    // Starting the index with 1 so for accessing router do index-1
    for(int index_router =1; index_router<=number_routers;index_router++){
        if (fork() == 0){
            client_connection_stage6(index_router);
        }
        else{
            char buf[100];
            int numbytes;
            struct sockaddr_storage their_addr_router;
            socklen_t addr_len_router;

            addr_len_router = sizeof their_addr_router;

            if ((numbytes = recvfrom(sockfd_proxy, buf, 100-1, 0,
                (struct sockaddr *)&their_addr_router, &addr_len_router)) == -1) {

                perror("recvfrom_proxy");
                exit(1);
            }
            int i=0;

        while(buf[i]>=48 && buf[i]<=57){
            pid_router_char[i] = buf[i];
            i++;
        }
        pid_router_char[i] = '\0';
        char port_number_router_char[strlen(buf)-i];
        int index=0;
        for(int k=i+1;k<strlen(buf);k++){ 
            port_number_router_char[index] = buf[k];
            index++;
        }
        port_number_router_char[index] = '\0';

        ////////////////////////////
        port_number_router_int_global[index_router-1] = atoi(port_number_router_char);
        out_proxy = fopen("stage7.proxy.out","a+");

        fprintf(out_proxy,"router:%d, pid:%s, port:%d\n",index_router,pid_router_char, port_number_router_int_global[index_router-1]);
        fclose(out_proxy);
        }  
    }
    //global_key = circuit_creation(number_routers,manitor_hops); 
    tunnel_reader_stage6();  
    close(sockfd_proxy);
    return 0;
}
