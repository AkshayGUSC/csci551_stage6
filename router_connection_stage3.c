/*
This file contains code for router used for stage 3.

Here in client_connection_stage5 sends all its required details to proxy and handles the incomeing 
and outgoing messages of the routers.
This is actually a child process forked to create routers

*/

#include "main_header.h"

FILE *out_router;

int client_connection_stage3(){
    int sockfd, sockfd_raw;
    struct addrinfo hints, *servinfo, *p, *clientinfo, *c;
    int rv, n;
    int numbytes;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // set to AF_INET to force IPv4
    hints.ai_socktype = SOCK_DGRAM;
    struct sockaddr_in their_addr, binding;
    socklen_t addr_len = sizeof(struct sockaddr);

    char port_number_proxy_char[10];
    sprintf(port_number_proxy_char,"%d",port_number_proxy);
    if ((rv = getaddrinfo(ip_address_info("eth0"), port_number_proxy_char, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo_server_in_client: %s\n", gai_strerror(rv));
        exit(1);
    }

    //printf("@@@@address is =%s\n",(inet_ntoa(*(struct in_addr*)&((struct sockaddr_in *)servinfo->ai_addr)->sin_addr.s_addr)));

    if ((rv = getaddrinfo(ip_address_info("eth1"), "0", &hints, &clientinfo)) != 0) {
        fprintf(stderr, "getaddrinfo_client: %s\n", gai_strerror(rv));
        exit(1);
    }
    
    for(c = clientinfo; c!= NULL; c = c->ai_next) {
        if ((sockfd = socket(c->ai_family, c->ai_socktype,
                c->ai_protocol)) == -1) {
            perror("talker: client socket");
            continue;
        }

        if (bind(sockfd, c->ai_addr, c->ai_addrlen) == -1) {
            close(sockfd);
            perror("listener: client bind");
            continue;
        }
        break;
    }

    
        if ((sockfd_raw = socket(AF_INET, SOCK_RAW,
                IPPROTO_ICMP)) == -1) {
            perror("talker: raw socket");
        }
        
        binding.sin_addr.s_addr = inet_addr(ip_address_info("eth1"));
        binding.sin_family = AF_INET;
        binding.sin_port = htons(0);

        if (bind(sockfd_raw, (struct sockaddr *)&binding, sizeof(binding)) == -1) {
            close(sockfd_raw);
            perror("listener: raw bind");
        }
        // using setsockopt(IP_HRINCL)
        

    if (c == NULL) {
        fprintf(stderr, "talker: client failed to create socket\n");
        exit(2);
    }
    p = servinfo;
    
    char child_pid[100];
    sprintf(child_pid,"%d", getpid());
    //printf("length of pid=%lu & pid =%s\n",strlen(child_pid), child_pid);
    struct sockaddr_in socket_addr;
    socklen_t length = sizeof(socket_addr);
    if(getsockname(sockfd, (struct sockaddr *)&socket_addr,&length) == -1){
        perror("error in getsocketname()");
        exit(-1);
    }

    port_number_router = (int)ntohs(socket_addr.sin_port);

    sprintf(child_pid+strlen(child_pid),"a");
    sprintf(child_pid+strlen(child_pid),"%d", port_number_router);

    if ((numbytes = sendto(sockfd,child_pid,strlen(child_pid), 0,
         p->ai_addr, p->ai_addrlen)) == -1) {
        perror("talker_router: sendto");
        exit(1);
    }
    
    char buffer[84];

    n = sockfd_raw +1;
    while(1){

        fd_set readfds;

        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        FD_SET(sockfd_raw, &readfds);

        rv = select(n, &readfds, NULL, NULL, NULL);

        if (rv == -1) {
            perror("select"); // error occurred in select()
        }

        else{
            // ICMP packet coming from proxy
            if (FD_ISSET(sockfd, &readfds)) {

                if ((numbytes = recvfrom(sockfd, buffer, 84 , 0,
                    (struct sockaddr *)&their_addr, &addr_len)) == -1) {
                    perror("recvfrom");
                    exit(1);
                }

                if(buffer[0] == '1'){
                    printf("Exiting router\n");
                    close(sockfd);
                    close(sockfd_raw);
                    exit(0);
                } 
                struct iphdr *ip = (struct iphdr *)(buffer);
                struct icmphdr *icmp = (struct icmphdr *)(buffer+sizeof(struct iphdr));

                // check for ip address & correspondingly send
                if(((ip->daddr) ^ (inet_addr(ip_address_info("eth1")))) == 0){
                    uint32_t temp;
                    temp = ip->saddr;
                    ip->saddr = ip->daddr;
                    ip->daddr = temp;

                    icmp->type =0;
                    if ((numbytes = sendto(sockfd,buffer,84, 0,
                            p->ai_addr, p->ai_addrlen)) == -1) {
                        perror("talker_router: sendto");
                        exit(1);
                    }
                }
                else{
                    // sendmsg format referred from http://www.microhowto.info/howto/send_an_arbitrary_ipv4_datagram_using_a_raw_socket_in_c.html
                    //inet_aton("192.168.201.2", &src_change.sin_addr);
                    ip->saddr = inet_addr(ip_address_info("eth1"));
                    //inet_aton("128.30.2.32", &dest_change.sin_addr);
                    their_addr.sin_addr.s_addr = ip->daddr;
                    struct msghdr buf;
                    struct iovec iov[1];
                    iov[0].iov_base= icmp;
                    iov[0].iov_len= sizeof(buffer) - sizeof(struct iphdr);
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
                    printf("!!!!! Raw Packet sent to Internet + numbytes = %d\n",numbytes);
                } 
            }
            //icmp packet coming from internet at raw socket
            if (FD_ISSET(sockfd_raw, &readfds)) {
                memset(&buffer, 0, sizeof buffer);
                struct msghdr buf;
                struct iovec iov[1];
                iov[0].iov_base = buffer;
                buf.msg_iov = iov;
                iov[0].iov_len= sizeof(buffer);
                buf.msg_iovlen= 1;

                if ((numbytes = recvmsg(sockfd_raw, &buf, 0)) == -1) {
                    perror("recvfrom from raw scoket");
                    exit(1);
                }
                struct iphdr *ip = (struct iphdr *)(buffer);

                out_router = fopen("stage3.router1.out","a+");
                fprintf(out_router, "ICMP from raw socket: src: %s ",inet_ntoa(*(struct in_addr*)&ip->saddr));
                fprintf(out_router, "dst: %s, type: 0\n", inet_ntoa(*(struct in_addr*)&ip->daddr));
                fclose(out_router);

                printf("Message received  from Internet + numbytes = %d\n", numbytes);

                if ((numbytes = sendto(sockfd,buffer,84, 0,
                        p->ai_addr, p->ai_addrlen)) == -1) {
                    perror("talker_router: sendto");
                    exit(1);
                }
            }
        }  
    }
    freeaddrinfo(servinfo);
    close(sockfd);  
    exit(0);
}