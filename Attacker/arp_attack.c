#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
//#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
//#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/if_packet.h>

//extern int errno;

#define BUFFER_MAX 2048

#define ARPHRD_ETHER    1
#define ARPOP_REQUEST   1       /* ARP request */
#define ARPOP_REPLY		2       /* ARP reply   */
#define ARPOP_RREQUEST  3       /* RARP request*/
#define ARPOP_RREPLY    4       /* RARP reply  */



typedef unsigned char		uint_8;
typedef	char				int_8;
typedef unsigned short		uint_16;
typedef short				int_16;
typedef unsigned int		uint_32;
typedef int					int_32;
typedef unsigned char		boolean;


uint_8 broadcast_mac[ETH_ALEN] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

struct arphdr
{
	uint_16		hardware;
	uint_16		proto;
	uint_8		hardlen;
	uint_8		pln;
	uint_16		op;

	uint_8		smac[ETH_ALEN];
	uint_8		sip[4];
	uint_8		tmac[ETH_ALEN];
	uint_8		tip[4];
};

#define ARP_SIZE	sizeof(struct arphdr)+sizeof(struct ethhdr)

uint_8 send_buffer[BUFFER_MAX];
uint_8 recv_buffer[BUFFER_MAX];

struct sockaddr_ll	interface;

int sock_fd;

uint_8 target_ip[4];
uint_8 source_ip[4];
uint_8 source_mac[ETH_ALEN];
uint_8 target_mac[ETH_ALEN];
uint_8 send_to_mac[ETH_ALEN];

//miscellaneous
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

inline void Print_MAC(uint_8 *header)
{
	printf("%02X:%02X:%02X:%02X:%02X:%02X\n", header[0], header[1], header[2], header[3], header[4], header[5]);
}

inline void Print_IP(uint_8 *header)
{
	printf("%d.%d.%d.%d\n", header[0], header[1], header[2], header[3]);
}


inline void Mac2Bin(char *MAC, uint_8 *dest)
{
	sscanf(MAC, "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX", dest, dest + 1, dest + 2, dest + 3, dest + 4, dest + 5);
}

inline void Ip2Bin(char *Ip, uint_8 *dest)
{
	sscanf(Ip, "%hhd.%hhd.%hhd.%hhd", dest, dest + 1, dest + 2, dest + 3);
}

void send_ARP(void)
{
	struct ethhdr *ETH_Frame = (struct ethhdr *)send_buffer;
	memcpy(ETH_Frame -> h_dest, send_to_mac, ETH_ALEN);
	memcpy(ETH_Frame -> h_source, source_mac, ETH_ALEN);
	ETH_Frame -> h_proto = htons(ETH_P_ARP);
	
	struct arphdr *ARP_Frame = (struct arphdr *)(send_buffer + sizeof(struct ethhdr));
	ARP_Frame -> hardware = htons(ARPHRD_ETHER);
	ARP_Frame -> proto = htons(ETH_P_IP);
	ARP_Frame -> hardlen = 6;
	ARP_Frame -> pln = 4;
	ARP_Frame -> op = htons(ARPOP_REPLY);

	memcpy(ARP_Frame -> smac, source_mac, ETH_ALEN);
	memcpy(ARP_Frame -> tmac, target_mac, ETH_ALEN);
	memcpy(ARP_Frame -> sip, source_ip, 4);
	memcpy(ARP_Frame -> tip, target_ip, 4);


	if (sendto(sock_fd, send_buffer, ARP_SIZE, 0, (struct sockaddr *)&interface, sizeof(interface)) < 0)
	{
		fprintf(stderr, "Send Error!\n");
		exit(-1);
	}
	else
		printf("Send!\n");
}

struct sigaction	exit_signal, alarm_send;

void alarm_handler(int signo)
{
	send_ARP();
	alarm(1);
}

void exit_pipe(int signo)
{
	fflush(stdout);
	fprintf(stderr, "BYE~\n");
	exit(0);
}

int main(int argc, char *argv[]) //interface, send_to_mac, source_mac, target_mac, source_ip, target_ip
{
	if ((sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0)
	{
		fprintf(stderr, "Error create Raw Socket\n");
		return -1;
	}

	if (argc != 7)
	{
		fprintf(stderr, "Address error!\n");
		return -1;
	}

	//should be check address here!

	Mac2Bin(argv[2], send_to_mac);
	Mac2Bin(argv[3], source_mac);
	Mac2Bin(argv[4], target_mac);
	Ip2Bin(argv[5], source_ip);
	Ip2Bin(argv[6], target_ip);
	
	exit_signal.sa_handler = exit_pipe;
	sigemptyset(&exit_signal.sa_mask);
	exit_signal.sa_flags = 0;
	sigaction(SIGINT, &exit_signal, 0);
	
	alarm_send.sa_handler = alarm_handler;
	sigemptyset(&alarm_send.sa_mask);
	alarm_send.sa_flags = 0;
	sigaction(SIGALRM, &alarm_send, 0);
	
	/*
	Print_IP(source_ip);
	Print_IP(target_ip);
	Print_MAC(source_mac);
	*/

	memset(&interface, 0, sizeof(interface));
	interface.sll_family = PF_PACKET;
	interface.sll_ifindex = if_nametoindex(argv[1]);

//	alarm(1);

	while (1)
	send_ARP();
	return 0;
}
