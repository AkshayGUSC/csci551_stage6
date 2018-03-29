/*
This file contains code for router used for stage 4.

Here in client_connection_stage5 sends all its required details to proxy and handles the incomeing 
and outgoing messages of the routers.
This is actually a child process forked to create routers

*/
#include "main_header.h"

int client_connection_stage4(int x){

    int sockfd, sockfd_raw;
    int rv, n;
    int numbytes;
    struct sockaddr_in their_addr, binding, router_addr, send_addr;
    socklen_t addr_len = sizeof(struct sockaddr);
    struct ifreq ifr;
    char if_name[5];
    char router_ip[16];

    sprintf(if_name,"%s","eth");
    sprintf(if_name+strlen(if_name),"%d",x);
    strcpy(router_ip,ip_address_info(if_name));

    fprintf(stderr, "routers ip address is this %s\n",router_ip);

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
    /*sockfd_raw is binded to the routers IP address for Internet*/
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
        /*if((rv = setsockopt(sockfd_raw, SOL_SOCKET, SO_BINDTODEVICE, (void*)&ifr, sizeof(ifr)))<0){
            perror("Router-error binding to eth1: sockfd_raw");
            close(sockfd_raw);
            exit(-1);
        }*/       
        binding.sin_addr.s_addr = inet_addr(router_ip);
        binding.sin_family = AF_INET;
        binding.sin_port = htons(0);
        if (bind(sockfd_raw, (struct sockaddr *)&binding, sizeof(binding)) == -1) {
            close(sockfd_raw);
            perror("listener: raw bind");
        }
    
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

    char filename[100];
    sprintf(filename,"stage4.router");
    sprintf(filename+strlen(filename),"%d",x);
    sprintf(filename+strlen(filename),".out");

    FILE *out_router = fopen(filename,"a+");
    fprintf(out_router,"router:%d, pid:%d, port:%d\n", x, getpid(), port_number_router);
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
                    fprintf(stderr, "Exiting router\n");
                    close(sockfd);
                    close(sockfd_raw);
                    exit(0);
                } 
                struct iphdr *ip = (struct iphdr *)(buffer);
                struct icmphdr *icmp = (struct icmphdr *)(buffer+sizeof(struct iphdr));
                out_router = fopen(filename,"a+");
                fprintf(out_router, "ICMP from port: %d, src: %s, ",port_number_proxy, inet_ntoa(*(struct in_addr*)&ip->saddr));
                fprintf(out_router, "dst: %s, type: 8\n",inet_ntoa(*(struct in_addr*)&ip->daddr));
                fclose(out_router);
                if( ((ip->daddr) ^ inet_addr(router_ip)) == 0){
                    uint32_t temp;
                    temp = ip->saddr;
                    ip->saddr = ip->daddr;
                    ip->daddr = temp;

                    icmp->type =0;
                    if ((numbytes = sendto(sockfd,buffer,84, 0,
                            (struct sockaddr *)&send_addr, sizeof send_addr)) == -1) {
                        perror("talker_router: sendto");
                        exit(1);
                    }
                }
                else{
                    // sendmsg format referred from http://www.microhowto.info/howto/send_an_arbitrary_ipv4_datagram_using_a_raw_socket_in_c.html
                    ip->saddr = inet_addr(router_ip);
                    their_addr.sin_addr.s_addr = ip->daddr;
                    fprintf(stderr, "sending internet address destination id =%s\n",inet_ntoa(*(struct in_addr*)&ip->daddr));
                    fprintf(stderr, "sending internet address source id =%s\n",inet_ntoa(*(struct in_addr*)&ip->saddr));

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
                    fprintf(stderr,"Packet Send to Internet via raw socket + sent numbytes = %d\n",numbytes);
                    fflush(NULL); 
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
                
                fprintf(stderr, "Message received from Internet + numbytes = %d\n", numbytes);
                struct iphdr *ip = (struct iphdr *)(buffer);

                out_router = fopen(filename,"a+");
                fprintf(out_router, "ICMP from raw sock, src: %s, ", inet_ntoa(*(struct in_addr*)&ip->saddr));
                fprintf(out_router, "dst: %s, type: 0\n",router_ip);
                fclose(out_router);
                out_proxy = fopen("stage4.proxy.out","a+");
                fprintf(out_proxy, "ICMP from port: %d, src: %s, ",port_number_proxy, inet_ntoa(*(struct in_addr*)&ip->saddr));
                fprintf(out_proxy, "dst: %s, type: 0\n",ip_address_info("eth0"));
                fclose(out_proxy);
                if ((numbytes = sendto(sockfd,buffer,84, 0,
                        (struct sockaddr *)&send_addr, sizeof send_addr)) == -1) {
                    perror("talker_router: sendto");
                    exit(1);
                }
            }
        }  
    }
    close(sockfd);  
    exit(0);
}