#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <termios.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
//#include <linux/in.h>
//#include <linux/in6.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_packet.h>


#define BUFFER_MAX 2048


#define RED		"\E[1;31m"
#define BLUE	"\E[1;34m"
#define GREEN	"\E[1;32m"
#define PURPLE	"\E[1;35m"
#define NORMAL	"\E[m"


/*
#define MACPROTO_IPv4	0x0800
#define MACPROTO_IPv6	0x86dd
#define MACPROTO_IPX	0x8137
#define MACPROTO_ARP	0x0806

#define ICMP_REPLY		0x00
#define ICMP_DU			0x03
#define ICMP_REQUEST	0x08
#define ICMP_TLE		0x0B
*/

typedef unsigned char		uint_8;
typedef	char				int_8;
typedef unsigned short		uint_16;
typedef short				int_16;
typedef unsigned int		uint_32;
typedef int					int_32;
typedef unsigned char		boolean;


/* struct ipv6hdr defined in <linux/ipv6.h> is incorrect, so redefine here.*/


struct ipv6vtf{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u32		flow_lbl:20,
				traffic_class:8,
				version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u32		version:4,
				traffic_class:8,
				flow_lbl:20;
#else
#error "Please fix <asm/byteorder.h>"
#endif
};

struct ipv6hdr {

	__u32				vtf;	

	__be16				payload_len;
	__u8				nexthdr;
	__u8				hop_limit;

	struct in6_addr		saddr;
	struct in6_addr		daddr;
};

void MAC(uint_8 *);

void IPv4(uint_8 *);
void ARP(uint_8 *);
void IPv6(uint_8 *);
void IPX(uint_8 *);
void RARP(uint_8 *);

void ICMP(uint_8 *);
void ICMPv6(uint_8 *);
void IGMP(uint_8 *);
void TCP(uint_8 *);
void UDP(uint_8 *);
void DCCP(uint_8 *);

uint_8 buffer[BUFFER_MAX];

//miscellaneous
inline void Print_MAC(uint_8 *header)
{
	fflush(stdout);
	fprintf(stderr, RED);
	printf("%02X:%02X:%02X:%02X:%02X:%02X\n", header[0], header[1], header[2], header[3], header[4], header[5]);
	fprintf(stderr, NORMAL);
}

inline void Print_IP(uint_8 *header)
{
	fflush(stdout);
	fprintf(stderr, RED);
	printf("%d.%d.%d.%d\n", header[0], header[1], header[2], header[3]);
	fprintf(stderr, NORMAL);
}

inline void Print_IP6(struct in6_addr *header)
{
	fflush(stdout);
	fprintf(stderr, RED);
	printf("%X", ntohs(header -> s6_addr16[0]));
	int i;
	for (i = 1; i < 8; ++ i)
		printf(":%X", ntohs(header -> s6_addr16[i]));
	printf("\n");
	fprintf(stderr, NORMAL);
}

// 1st
void MAC(uint_8 *header) //return the type of Ethernet
{
	fflush(stdout);
	fprintf(stderr, BLUE);
	printf("Ethernet:\n");
	fprintf(stderr, NORMAL);

	struct ethhdr *Frame = (struct ethhdr *)header;

	printf("Destination: ");
	Print_MAC(Frame -> h_dest);
	printf("Source: ");
	Print_MAC(Frame -> h_source);
	
	//uint_16 T = ntohs(*((uint_16 *)(header + 12)));

	fflush(stdout);
	fprintf(stderr, GREEN);
	printf("Type: (0x%04X)", ntohs(Frame -> h_proto));

	switch (ntohs(Frame -> h_proto))
	{
		case ETH_P_IP:
			printf("IPv4\n"); fprintf(stderr, NORMAL); IPv4(header + sizeof(struct ethhdr)); break;
		case ETH_P_IPV6:
			printf("IPv6\n"); fprintf(stderr, NORMAL); IPv6(header + sizeof(struct ethhdr)); break;
		case ETH_P_IPX:
			printf("IPX\n"); fprintf(stderr, NORMAL); IPX(header + sizeof(struct ethhdr)); break;
		case ETH_P_ARP:
			printf("ARP\n"); fprintf(stderr, NORMAL); ARP(header + sizeof(struct ethhdr)); break;
		case ETH_P_RARP:
			printf("RARP\n"); fprintf(stderr, NORMAL); RARP(header + sizeof(struct ethhdr)); break;
		default:
			printf("Unknown @_@\n"); fprintf(stderr, NORMAL); break;
	}
}


// 2nd
void IPv4(uint_8 *header)
{
	fflush(stdout);
	fprintf(stderr, BLUE);
	printf("Internet Protocol version 4:\n");
	fprintf(stderr, NORMAL);

	struct iphdr *Frame = (struct iphdr *)header;

	printf("Version: %d\n", Frame -> version);
	int Frame_ihl = (Frame -> ihl) * 4;
	printf("Header length: %d bytes\n", Frame_ihl);
	printf("Total length: %d\n", ntohs(Frame -> tot_len));
	printf("Identification: 0x%04X\n", ntohs(Frame -> id));
	printf("Time to live: %d\n", ntohs(Frame -> ttl));
	printf("Header checksum: 0x%04X\n", ntohs(Frame -> check));

	printf("Source: ");
	Print_IP((uint_8 *)&(Frame -> saddr));
	printf("Destination: ");
	Print_IP((uint_8 *)&(Frame -> daddr));

	fflush(stdout);
	fprintf(stderr, GREEN);
	printf("Protocol: (0x%02X)", Frame -> protocol);
	switch (Frame -> protocol)
	{
		case IPPROTO_ICMP:
			printf("ICMP\n"); fprintf(stderr, NORMAL); ICMP(header + Frame_ihl); break;
		case IPPROTO_IGMP:
			printf("IGMP\n"); fprintf(stderr, NORMAL); IGMP(header + Frame_ihl); break;
		case IPPROTO_TCP:
			printf("TCP\n"); fprintf(stderr, NORMAL); TCP(header + Frame_ihl); break;
		case IPPROTO_UDP:
			printf("UDP\n"); fprintf(stderr, NORMAL); UDP(header + Frame_ihl); break;
		case IPPROTO_DCCP:
			printf("DCCP\n"); fprintf(stderr, NORMAL); DCCP(header + Frame_ihl); break;
		default:
			printf("Unknown @_@\n"); fprintf(stderr, NORMAL); break;
	}

}

void ARP(uint_8 *header)
{
	//printf("***********************************\n");
	fflush(stdout);
	fprintf(stderr, BLUE);
	printf("Address Resolution Protocol:\n");
	fprintf(stderr, NORMAL);

	struct arphdr *Frame = (struct arphdr *)header;

	printf("Hardware type: (0x%04X)", ntohs(Frame -> ar_hrd));
	switch (ntohs(Frame -> ar_hrd))
	{
		case ARPHRD_ETHER:
			printf("Ethernet\n"); break;
		case ARPHRD_ATM:
			printf("ATM\n"); break;
		default:
			printf("Unknown @_@\n"); break;
	}

	printf("Protocol type: (0x%04X)", ntohs(Frame -> ar_pro));

	switch (ntohs(Frame -> ar_pro))
	{
		case ETH_P_IP:
			printf("IPv4\n"); break;
		case ETH_P_IPV6:
			printf("IPv6\n"); break;
		case ETH_P_IPX:
			printf("IPX\n"); break;
		case ETH_P_ARP:
			printf("ARP\n"); break;
		default:
			printf("Unknown @_@\n"); break;
	}

	printf("Hardware size: %d\n", Frame -> ar_hln);
	printf("Protocol size: %d\n", Frame -> ar_pln);

	uint_16 Opcode = ntohs(Frame -> ar_op);
	printf("Opcode: (0x%04X)", Opcode);
	switch (Opcode)
	{
		case ARPOP_REPLY:
			printf("Reply\n"); break;
		case ARPOP_REQUEST:
			printf("Request\n"); break;
		default:
			printf("Unknown @_@\n"); break;
	}
	printf("Sender MAC address: ");
	Print_MAC(header + sizeof(struct arphdr));
	printf("Sender IP address: ");
	Print_IP(header + sizeof(struct arphdr) + 6);
	printf("Target MAC address: ");
	Print_MAC(header + sizeof(struct arphdr) + 10);
	printf("Target IP address: ");
	Print_IP(header + sizeof(struct arphdr) + 16);
}

void RARP(uint_8 *header)
{
	//printf("***********************************\n");
	fflush(stdout);
	fprintf(stderr, BLUE);
	printf("Reverse Address Resolution Protocol:\n");
	fprintf(stderr, NORMAL);

	struct arphdr *Frame = (struct arphdr *)header;

	printf("Hardware type: (0x%04X)", ntohs(Frame -> ar_hrd));
	switch (ntohs(Frame -> ar_hrd))
	{
		case ARPHRD_ETHER:
			printf("Ethernet\n"); break;
		case ARPHRD_ATM:
			printf("ATM\n"); break;
		default:
			printf("Unknown @_@\n"); break;
	}

	printf("Protocol type: (0x%04X)", ntohs(Frame -> ar_pro));

	switch (ntohs(Frame -> ar_pro))
	{
		case ETH_P_IP:
			printf("IPv4\n"); break;
		case ETH_P_IPV6:
			printf("IPv6\n"); break;
		case ETH_P_IPX:
			printf("IPX\n"); break;
		case ETH_P_ARP:
			printf("ARP\n"); break;
		default:
			printf("Unknown @_@\n"); break;
	}

	printf("Hardware size: %d\n", Frame -> ar_hln);
	printf("Protocol size: %d\n", Frame -> ar_pln);

	uint_16 Opcode = ntohs(Frame -> ar_op);
	printf("Opcode: (0x%04X)", Opcode);
	switch (Opcode)
	{
		case ARPOP_RREPLY:
			printf("Reply Reverse\n"); break;
		case ARPOP_RREQUEST:
			printf("Request Reverse\n"); break;
		default:
			printf("Unknown @_@\n"); break;
	}
	printf("Sender MAC address: ");
	Print_MAC(header + sizeof(struct arphdr));
	printf("Sender IP address: ");
	Print_IP(header + sizeof(struct arphdr) + 6);
	printf("Target MAC address: ");
	Print_MAC(header + sizeof(struct arphdr) + 10);
	printf("Target IP address: ");
	Print_IP(header + sizeof(struct arphdr) + 16);
}

void IPX(uint_8 *header)
{
	fflush(stdout);
	fprintf(stderr, BLUE);
	printf("Internetwork Packet Exchange\n");
	fprintf(stderr, NORMAL);
	//to be continued...
}



void IPv6(uint_8 *header)
{
	fflush(stdout);
	fprintf(stderr, BLUE);
	printf("Internet Protocol Version 6:\n");
	fprintf(stderr, NORMAL);
	struct ipv6hdr *Frame = (struct ipv6hdr *)header;

	uint_32	temp = ntohl(Frame -> vtf);
	struct ipv6vtf *VTF = (struct ipv6vtf *)(&temp);

	printf("Version: %d\n", VTF -> version);
	printf("Traffic class: 0x%02X\n", VTF -> traffic_class);
	printf("Flow Label: 0x%05X\n", VTF -> flow_lbl);
	/*
	printf("%02X %02X %02X %02X\n", header[0], header[1], header[2], header[3]);
	header[0] = 0x12;
	header[1] = 0x34;
	header[2] = 0x56;
	header[3] = 0x78;

	printf("temp: %08X\n", Frame -> temp);
	printf("temp2: %08X\n", ntohl(Frame -> temp));
	*/

	printf("Payload length: %d\n", ntohs(Frame -> payload_len));
	printf("Hop limit: %d\n", Frame -> hop_limit);
	
	printf("Source: ");
	Print_IP6(&(Frame -> saddr));
	printf("Destination: ");
	Print_IP6(&(Frame -> daddr));

	fflush(stdout);
	fprintf(stderr, GREEN);
	printf("Next header: (0x%02X)", Frame -> nexthdr);
	switch (Frame -> nexthdr)
	{
		case IPPROTO_ICMPV6:
			printf("ICMPv6\n"); fprintf(stderr, NORMAL); ICMPv6(header + sizeof(struct ipv6hdr)); break;
		case IPPROTO_TCP:
			printf("TCP\n"); fprintf(stderr, NORMAL); TCP(header + sizeof(struct ipv6hdr)); break;
		case IPPROTO_UDP:
			printf("UDP\n"); fprintf(stderr, NORMAL); UDP(header + sizeof(struct ipv6hdr)); break;
		default:
			printf("Unknown @_@\n"); fprintf(stderr, NORMAL); break;
	}
}



// 3rd
inline void ICMP(uint_8 *header)
{
	fflush(stdout);
	fprintf(stderr, BLUE);
	printf("Internet Control Message Protocol:\n");
	fprintf(stderr, NORMAL);

	struct icmphdr *Frame = (struct icmphdr *)header;

	printf("Type: (%d)", Frame -> type);
	switch (Frame -> type)
	{
		case ICMP_ECHOREPLY:
			printf("Echo Reply\n"); break;
		case ICMP_DEST_UNREACH:
			printf("Destination Unreachable\n"); break;
		case ICMP_ECHO:
			printf("Echo Request\n"); break;
		case ICMP_TIME_EXCEEDED:
			printf("Time Exceeded\n"); break;
		default:
			printf("Unknown @_@\n"); break;
	}
	printf("Code: %d\n", Frame -> code);
	printf("Checksum: 0x%04X\n", ntohs(Frame -> checksum));
	//to be continued...
}


inline void ICMPv6(uint_8 *header)
{
	fflush(stdout);
	fprintf(stderr, BLUE);
	printf("Internet Control Message Protocol version 6:\n");
	fprintf(stderr, NORMAL);

	struct icmp6hdr *Frame = (struct icmp6hdr *)header;

	printf("Type: (%d)", Frame -> icmp6_type);
	switch (Frame -> icmp6_type)
	{
		case ICMPV6_ECHO_REPLY:
			printf("Echo Reply\n"); break;
		case ICMPV6_DEST_UNREACH:
			printf("Destination Unreachable\n"); break;
		case ICMPV6_ECHO_REQUEST:
			printf("Echo Request\n"); break;
		case ICMPV6_TIME_EXCEED:
			printf("Time Exceeded\n"); break;
		case 134:
			printf("Router advertisement\n"); break;
		case 135:
			printf("Neighbor solicitation\n"); break;
		case 136:
			printf("Neighbor advertisement\n"); break;
		default:
			printf("Unknown @_@\n"); break;
	}
	printf("Code: %d\n", Frame -> icmp6_code);
	printf("Checksum: 0x%04X\n", ntohs(Frame -> icmp6_cksum));
	//while (1);
	//to be continued...
}

inline void IGMP(uint_8 *header)
{
	fflush(stdout);
	fprintf(stderr, BLUE);
	printf("Internet Group Management Protocol\n");
	fprintf(stderr, NORMAL);
	//to be continued...
}


inline void TCP(uint_8 *header)
{
	fflush(stdout);
	fprintf(stderr, BLUE);
	printf("Transmission Control Protocol:\n");
	fprintf(stderr, NORMAL);

	struct tcphdr *Frame = (struct tcphdr *)header;

	printf("Source port: %d\n", ntohs(Frame -> source));
	printf("Destination port: %d\n", ntohs(Frame -> dest));
	printf("Sequence number(not relative): %u\n", Frame -> seq);

	if (Frame -> ack)
	{
		printf("Acknowledgement number(not relative): %u\n", Frame -> ack_seq);
	}
	printf("Header length: %d bytes\n", (Frame -> doff) * 4);

	printf("Flags:");
	if (Frame -> ece)
		printf(" ECE");
	if (Frame -> urg)
		printf(" URG");
	if (Frame -> ack)
		printf(" ACK");
	if (Frame -> psh)
		printf(" PSH");
	if (Frame -> rst)
		printf(" RST");
	if (Frame -> syn)
		printf(" SYN");
	if (Frame -> fin)
		printf(" FIN");
	printf("\n");

	printf("Window size: %d\n", ntohs(Frame -> window));
	printf("Checksum: 0x%04X\n", ntohs(Frame -> check));
	if (Frame -> urg)
		printf("Urgent pointer: 0x%04X\n", ntohs(Frame -> urg_ptr));

}

inline void UDP(uint_8 *header)
{
	fflush(stdout);
	fprintf(stderr, BLUE);
	printf("User Datagram Protocol:\n");
	fprintf(stderr, NORMAL);

	struct udphdr *Frame = (struct udphdr *)header;

	printf("Source port: %d\n", ntohs(Frame -> source));
	printf("Destination port: %d\n", ntohs(Frame -> dest));
	printf("Length: %d\n", ntohs(Frame -> len));
	printf("Checksum: 0x%04X\n", ntohs(Frame -> check));
	//Data(header + 8)
}

inline void DCCP(uint_8 *header)
{
	fflush(stdout);
	fprintf(stderr, BLUE);
	printf("Datagram Congestion Control Protocol\n");
	fprintf(stderr, NORMAL);
	//to be continued...
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


struct ifreq		interface;
struct sockaddr_ll	sll;
struct packet_mreq	pmr;

struct sigaction	exit_signal;
struct termios		new_setting, init_setting;



void exit_pipe(int signo)
{
	fflush(stdout);
	fprintf(stderr, NORMAL);
	fprintf(stderr, "BYE~\n");
	tcsetattr(0, TCSANOW, &init_setting);
	exit(0);
}

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		fprintf(stderr, RED);
		fprintf(stderr, "Device Error(argc)!\n");
		fprintf(stderr, NORMAL);
		return -1;
	}

	int sock_fd;
	int n_read;
	if ((sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	//if ((sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
	{
		fprintf(stderr, RED);
		fprintf(stderr, "Error create Raw Socket\n");
		fprintf(stderr, NORMAL);
		return -1;
	}


	if (strcmp("all", argv[1]) != 0)
	{
		memset(&interface, 0, sizeof(interface));
		strncpy(interface.ifr_name, argv[1], IFNAMSIZ);
		//if (setsockopt(sock_fd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&interface, sizeof(interface)) < 0)
		if (ioctl(sock_fd, SIOCGIFINDEX, &interface) < 0)
		{
			fprintf(stderr, RED);
			fprintf(stderr, "Device Error(ioctl)!\n");
			fprintf(stderr, NORMAL);
			return -1;
		}
		sll.sll_family = AF_PACKET;
		sll.sll_ifindex = interface.ifr_ifindex;
		sll.sll_protocol = htons(ETH_P_ALL);
		if (bind(sock_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0)
		{
			fprintf(stderr, RED);
			fprintf(stderr, "Device Error(bind)!\n");
			fprintf(stderr, NORMAL);
			return -1;
		}
	}
	
	memset(&pmr, 0, sizeof(pmr));
	pmr.mr_ifindex = interface.ifr_ifindex;
	pmr.mr_type = PACKET_MR_PROMISC;
	if (setsockopt(sock_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &pmr, sizeof(pmr)) < 0)
	{
			fprintf(stderr, RED);
			fprintf(stderr, "Device Error(promisc)!\n");
			fprintf(stderr, NORMAL);
			return -1;
	}

	exit_signal.sa_handler = exit_pipe;
	sigemptyset(&exit_signal.sa_mask);
	exit_signal.sa_flags = 0;
	sigaction(SIGINT, &exit_signal, 0);

	tcgetattr(0, &init_setting);
	new_setting = init_setting;
	new_setting.c_lflag &= ~ECHO;
	tcsetattr(0, TCSANOW, &new_setting);

	int total = 0;
	while (1)
	{
		++ total;

		n_read = recvfrom(sock_fd, buffer, BUFFER_MAX, 0, NULL, NULL);

		fflush(stdout);
		fprintf(stderr, PURPLE);
		printf("No.%d:===============================\n", total);
		printf("Length = %d\n", n_read);
		fprintf(stderr, NORMAL);

		if (n_read < 42)
		{
			Print_Data(buffer, n_read);
			fflush(stdout);	
			fprintf(stderr, RED);
			fprintf(stderr, "Error when receive message\n");
			fprintf(stderr, "Length = %d\n", n_read);
			fprintf(stderr, NORMAL);
			return -1;
		}
		
		MAC(buffer);
		printf("\n");
	}

	return 0;
}
