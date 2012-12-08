#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_packet.h>

extern int errno;

#define BUFFER_MAX 2048
#define ICMP_DATA_SIZE	56
#define ICMP_4_SIZE		sizeof(struct icmphdr)+ICMP_DATA_SIZE
#define PING_4_SIZE		ICMP_4_SIZE+sizeof(struct iphdr)

typedef unsigned char		uint_8;
typedef	char				int_8;
typedef unsigned short		uint_16;
typedef short				int_16;
typedef unsigned int		uint_32;
typedef int					int_32;
typedef unsigned char		boolean;



uint_8 send_buffer[BUFFER_MAX];
uint_8 recv_buffer[BUFFER_MAX];

struct sockaddr_in	addr;

int sock_fd;

char ip_addr[20];

int send_frame;

//miscellaneous

uint_16 get_checksum(uint_16 *ptr, int length)
{
	int ret = 0;
	int i;
	for (i = 0; i < (length >> 1); ++ i, ++ ptr)
		ret += *ptr;
	while (ret >> 16)
		ret = (ret & 0xffff) + (ret >> 16);
	return (~ret);
}


inline void Print_Data(uint_8 *header, int length)
{
	int i;
	for (i = 0; i < length; ++ i)
	{
		printf("%02X", header[i]);
		if ((i & 15) == 15)
			printf("\n");
		else
			printf(" ");
	}

}


void send_ICMP(void)
{
	struct icmphdr *Frame = (struct icmphdr *)send_buffer;
	Frame -> type = ICMP_ECHO;
	Frame -> code = 0;
	Frame -> checksum = 0;
	Frame -> un.echo.id = htons(getpid());
	Frame -> un.echo.sequence = htons(++ send_frame);


	gettimeofday((struct timeval *)(send_buffer + sizeof(struct icmphdr)), NULL);

	int i;
	uint_8 *ptr = send_buffer + sizeof(struct icmphdr) + sizeof(struct timeval);
	for (i = sizeof(struct timeval); i < ICMP_DATA_SIZE; ++ i)
		*ptr = rand() % 10;

	Frame -> checksum = get_checksum((uint_16 *)send_buffer, ICMP_4_SIZE);

	if (sendto(sock_fd, send_buffer, ICMP_4_SIZE, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		fprintf(stderr, "Send Error!\n");
		exit(-1);
	}
	/*
	else
	{
		printf("Send ICMP Request to %s.\n", ip_addr);
	}
	*/
}


void receive_ICMP(void)
{
	struct timeval sendtime;
	struct timeval recvtime;
	int n_read;

	int recv_frame = 0;

	while (1)
	{
		if ((n_read = recvfrom(sock_fd, recv_buffer, BUFFER_MAX, 0, NULL, NULL)) < 0)
		{
			if (errno == EINTR)
				continue;
			else
			{
				fprintf(stderr, "Receive Error!\n");
				exit(-1);
			}
		}
		gettimeofday(&recvtime, NULL);
		//Print_Data(recv_buffer, n_read);
		struct iphdr *IP_Frame = (struct iphdr *)recv_buffer;
		if (*(uint_32 *)(&(IP_Frame -> saddr)) != *(uint_32 *)(&addr.sin_addr))
		{
			fprintf(stderr, "IP is not suit!\n");
			continue;
		}

		struct icmphdr *ICMP_Frame = (struct icmphdr *)(recv_buffer + sizeof(struct iphdr));

		if (htons(ICMP_Frame -> un.echo.id) != getpid())
		{
			fprintf(stderr, "Not for this process!\n");
			continue;
		}
		++ recv_frame;

		sendtime = *((struct timeval *)(recv_buffer + sizeof(struct icmphdr) + sizeof(struct iphdr)));

		//printf("%d %d\n", recvtime.tv_sec, sendtime.tv_sec);
		int sec = recvtime.tv_sec - sendtime.tv_sec;
		int usec = recvtime.tv_usec - sendtime.tv_usec;
		if (usec < 0)
		{
			-- sec;
			usec = -usec;
		}
		int icmp_len = n_read - sizeof(struct iphdr);

		printf("%d bytes from %s: icmp_req=%d ttl=%d time=%d.%06d s\n", icmp_len, ip_addr, ntohs(ICMP_Frame -> un.echo.sequence), IP_Frame -> ttl, sec, usec);
	}
	
}

struct sigaction	exit_signal, alarm_send;

void alarm_handler(int signo)
{
	send_ICMP();
	alarm(1);
}


void exit_pipe(int signo)
{
	fflush(stdout);
	fprintf(stderr, "BYE~\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	if ((sock_fd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
	{
		fprintf(stderr, "Error create Raw Socket\n");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;

	if (argc != 2)
	{
		fprintf(stderr, "Address error!\n");
		return -1;
	}
	int ret = inet_pton(AF_INET, argv[1], &addr.sin_addr);
	if (ret != 1)
	{
		/*
		struct hostent *host_info = gethostbyname(argv[1]);
		if (host_info == NULL)
		{
		}
		*/
		fprintf(stderr, "Address error!\n");
		return -1;
	}

	strcpy(ip_addr, argv[1]);
	
	printf("PING %s (%s) %d(%lu) bytes of data.\n", ip_addr, ip_addr, ICMP_DATA_SIZE, PING_4_SIZE);

	exit_signal.sa_handler = exit_pipe;
	sigemptyset(&exit_signal.sa_mask);
	exit_signal.sa_flags = 0;
	sigaction(SIGINT, &exit_signal, 0);
	
	alarm_send.sa_handler = alarm_handler;
	sigemptyset(&alarm_send.sa_mask);
	alarm_send.sa_flags = 0;
	sigaction(SIGALRM, &alarm_send, 0);
	
	srand(time(NULL));

	send_frame = 0;

	alarm(1);
	receive_ICMP();
	return 0;
}
