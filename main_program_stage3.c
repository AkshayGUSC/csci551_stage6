/*
This file contains the code stage 3 This acts as proxy and also defines tunneling.
functions:
ip_address_info_stage3 : used for getting ip address from ethernet interfaces
server_connection_stage3: for creating proxy connection
ip_checksum_stage3- for computing the checksum (// copied the entire code for calculating checksum from http://www.microhowto.info/howto/calculate_an_internet_protocol_checksum_in_c.html#idp22752)
tunnel_reader_stage3 function handles the proxy packets
*/
#include "main_header.h"
int port_number_proxy;
int port_number_router;
int sockfd_proxy;
char port_number_router_char_global[100];
FILE *out_proxy, *out_router;
char pid_router_char[100];
char n_router[50];      
char stage;
uint16_t checksum;

char* ip_address_info_stage3(char *ifname){
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

int server_connection_stage3(){
    /*Socket connection code copied from BEEJ TUTORIAL*/
    struct addrinfo hints, *servinfo, *p;
    int rv;
    int sockfd;
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // set to AF_INET to force IPv4
    hints.ai_socktype = SOCK_DGRAM;
/*Code for getting ip address of the interface copied from https://www.binarytides.com/c-program-to-get-ip-address-from-interface-name-on-linux/*/

    if ((rv = getaddrinfo(ip_address_info_stage3("eth0"), "0", &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo_server: %s\n", gai_strerror(rv));
        exit(1);
    }   
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("listener: socket");
            continue;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("listener: bind_server");
            continue;
        }
        break;
    }
    if (p == NULL) {
        fprintf(stderr, "listener: failed to bind socket\n");
        exit(2);
    }
    struct sockaddr_in socket_addr;
    socklen_t length = sizeof(socket_addr);
    if(getsockname(sockfd, (struct sockaddr *)&socket_addr,&length) == -1){
        perror("error in getsocketname()");
        exit(-1);
    }
    port_number_proxy = (int)ntohs(socket_addr.sin_port);
    freeaddrinfo(servinfo);
    //printf("listener: waiting to recvfrom...\n");
    return sockfd;
}

// copied the entire code for calculating checksum from http://www.microhowto.info/howto/calculate_an_internet_protocol_checksum_in_c.html#idp22752
uint16_t ip_checksum_stage3(void* vdata,size_t length) {
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

int tun_alloc_stage3(char *dev, int flags) 
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


int tunnel_reader_stage3()
{
    char tun_name[IFNAMSIZ];
    char buffer[2048];
    char buf1[2048];
    int n, numbytes;

    /* Connect to the tunnel interface (make sure you create the tunnel interface first) */
    strcpy(tun_name, "tun1");
    int tun_fd = tun_alloc_stage3(tun_name, IFF_TUN | IFF_NO_PI);

    if(tun_fd < 0)
    {
        perror("Open tunnel interface");
        exit(1);
    }

    out_proxy = fopen("stage3.proxy.out","a+");
    fprintf(out_proxy,"proxy port: %d\nrouter:1, pid:%s, port:%s\n",port_number_proxy,pid_router_char, port_number_router_char_global);
    fclose(out_proxy);
    out_router = fopen("stage3.router1.out","a+");
    fprintf(out_router,"router:1, pid:%s, port:%s\n",pid_router_char, port_number_router_char_global);
    fclose(out_router);
    /* Taken the select() code from Beej*/

    struct addrinfo hints, *p, *clientinfo;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // set to AF_INET to force IPv4
    hints.ai_socktype = SOCK_DGRAM;
    //hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(ip_address_info_stage3("eth1"), port_number_router_char_global, &hints, &clientinfo)) != 0) {
        fprintf(stderr, "getaddrinfo _router1: %s\n", gai_strerror(rv));
        exit(1);
    }

    p = clientinfo;
    

    n = tun_fd + 1;     

    while(1) 
    {

        struct timeval tv;
        fd_set readfds;

        tv.tv_sec = 15;
        tv.tv_usec = 500000;

        FD_ZERO(&readfds);
        FD_SET(sockfd_proxy, &readfds);
        FD_SET(tun_fd, &readfds);


        rv = select(n, &readfds, NULL, NULL, &tv);


        if (rv == -1) {
            perror("select"); // error occurred in select()
        } 
        else if(rv == 0){
            printf("exiting proxy\n");
            char close_router[10];
            sprintf(close_router,"%s","1\0");
            if ((numbytes = sendto(sockfd_proxy,close_router,strlen(close_router), 0,
                            p->ai_addr, p->ai_addrlen)) == -1) {
                    perror("talker_PROXY: sendto");
                    exit(1);
            }
            close(sockfd_proxy);
            exit(0);
        } 
        else {
        // one or both of the descriptors have data
            if (FD_ISSET(sockfd_proxy, &readfds)) {

                
                recv(sockfd_proxy, buf1, 84, 0);

                //printf("receiving packet from router\n");
                /*struct iphdr *ip = (struct iphdr *)(buf1);
                struct sockaddr_in dest_change, src_change;
                inet_aton("10.0.2.15", &dest_change.sin_addr); 
                inet_aton("128.30.2.32", &src_change.sin_addr);*/ 
                struct iphdr *ip = (struct iphdr *)(buf1);
                ip->daddr = inet_addr(ip_address_info_stage3("eth0"));
                //ip->saddr = src_change.sin_addr.s_addr;
                //printf("Sending back to tunnel BY PROXY src address=%s\n", inet_ntoa(*(struct in_addr*)&ip->saddr));
                //printf("Sending back to tunnel BY PROXY des address=%s\n", inet_ntoa(*(struct in_addr*)&ip->daddr));
                
                //struct icmphdr *icmp = (struct icmphdr *)(buf1+sizeof(struct iphdr));
                ip->check = 0;
                
                ip->check = ip_checksum_stage3(ip,20);
                fprintf(stderr, "writing back to tunnel address!!!!!! %s\n", ip_address_info_stage3("eth0"));
                //printf("new checksum -> %u", ip->check);
                //printf("Sending back to tunnel icmp type%d\n", icmp->type);
                out_proxy = fopen("stage3.proxy.out","a+");
                fprintf(out_proxy, "ICMP from port: %s, src: %s, ",port_number_router_char_global, inet_ntoa(*(struct in_addr*)&ip->saddr));
                fprintf(out_proxy, "dst: %s, type: 0\n", ip_address_info_stage3("eth0"));
                fclose(out_proxy);
                write(tun_fd, buf1, 84);

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
                    struct icmphdr *icmp = (struct icmphdr *)(buffer+sizeof(struct iphdr));
                    //printf("original checksum -> %u", ip->check);
                    checksum = ip->check;
                    printf("Read a packet from tunnel, packet length:%d, dest address=%s\n", 
                        nread, inet_ntoa(*(struct in_addr*)&ip->daddr));

                    if(icmp->type == 8){
                        out_proxy = fopen("stage3.proxy.out","a+");
                        fprintf(out_proxy, "ICMP from tunnel, src: %s, ",ip_address_info_stage3("eth0"));
                        fprintf(out_proxy, "dst: %s, type: 8\n",inet_ntoa(*(struct in_addr*)&ip->daddr));
                        fclose(out_proxy);
                        out_router = fopen("stage3.router1.out","a+");
                        fprintf(out_router, "ICMP from port: %d, src: %s, ",port_number_proxy, ip_address_info_stage3("eth0"));
                        fprintf(out_router, "dst: %s, type: 8\n", inet_ntoa(*(struct in_addr*)&ip->daddr));
                        fclose(out_router);
                        if ((numbytes = sendto(sockfd_proxy,buffer,nread, 0,
                            p->ai_addr, p->ai_addrlen)) == -1) {
                            perror("talker_PROXY: sendto");
                            exit(1);
                        }
                    }

                }

            }
        }

    
    }
    freeaddrinfo(clientinfo);

}

int main_stage3()
{

    sockfd_proxy = server_connection_stage3();
    //printf("number of routers %d\n",number_routers);

    if (fork() == 0){
        client_connection_stage3();
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
        buf[numbytes] = '\0';

        /////////////////////////
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
        strncpy(port_number_router_char_global, port_number_router_char, strlen(port_number_router_char));
        tunnel_reader_stage3();    
    }
    close(sockfd_proxy);

    return 0;
}
