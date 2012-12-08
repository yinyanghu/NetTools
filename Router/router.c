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
#include <net/if.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
//#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/if_packet.h>


#define RED		"\E[1;31m"
#define BLUE	"\E[1;34m"
#define GREEN	"\E[1;32m"
#define PURPLE	"\E[1;35m"
#define NORMAL	"\E[m"

typedef unsigned char		uint_8;
typedef	char				int_8;
typedef unsigned short		uint_16;
typedef short				int_16;
typedef unsigned int		uint_32;
typedef int					int_32;
typedef unsigned char		boolean;


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


#define ARPHRD_ETHER    1
#define ARPOP_REQUEST   1       /* ARP request */
#define ARPOP_REPLY		2       /* ARP reply   */
#define ARPOP_RREQUEST  3       /* RARP request*/
#define ARPOP_RREPLY    4       /* RARP reply  */



#define BUFFER_MAX 2048
#define ARP_SIZE	sizeof(struct arphdr)+sizeof(struct ethhdr)
#define SMALL_BUFFER 1024
#define Pool_Size	100
#define INTERFACE_MAX	10
#define ARP_MAX			100
#define ROUTE_MAX		100


uint_8 broadcast_mac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

struct interface_list_type
{
	char name[IFNAMSIZ];
	int index;
	int socket_fd;
	uint_32	ip;
	uint_8 mac[6];
};

struct route_type
{
	uint_32		dest;
	uint_32		gw;
	uint_32		mask;
	char		interface[IFNAMSIZ];
};

struct arp_type
{
	uint_8		mac[6];
	uint_32		ip;
};

struct packet_pool_type
{
	uint_8		data[BUFFER_MAX];
	int			size;
	int			flag;
	uint_32		dest;
	uint_32		src;
};

struct request_arp_type
{
	uint_32		addr;
	char		*dev;
};


struct request_arp_type		request_arp;

uint_8		ARP_Buffer[ARP_SIZE];

struct arp_type arp[ARP_MAX];

int total_arp;

struct packet_pool_type		Packet_Pool[Pool_Size];

int	Pool_ptr;

struct route_type route[ROUTE_MAX];

int total_route;

uint_8 socket_buffer[BUFFER_MAX];

int total_if;

struct interface_list_type if_list[INTERFACE_MAX];

int socket_raw;



//miscellaneous
inline void Print_MAC(uint_8 *header)
{
	fflush(stdout);
	fprintf(stderr, RED);
	printf("%02X:%02X:%02X:%02X:%02X:%02X", header[0], header[1], header[2], header[3], header[4], header[5]);
	fprintf(stderr, NORMAL);
}

inline void Print_IP(uint_8 *header)
{
	fflush(stdout);
	fprintf(stderr, RED);
	printf("%d.%d.%d.%d", header[0], header[1], header[2], header[3]);
	fprintf(stderr, NORMAL);
}

struct sigaction	exit_signal;
struct termios		new_setting, init_setting;


void Exit_pipe(int signo)
{
	fflush(stdout);
	fprintf(stderr, NORMAL);
	fprintf(stderr, "BYE~\n");
	tcsetattr(0, TCSANOW, &init_setting);
	exit(0);
}


void Environment(void)
{
	exit_signal.sa_handler = Exit_pipe;
	sigemptyset(&exit_signal.sa_mask);
	exit_signal.sa_flags = 0;
	sigaction(SIGINT, &exit_signal, 0);

	tcgetattr(0, &init_setting);
	new_setting = init_setting;
	new_setting.c_lflag &= ~ECHO;
	tcsetattr(0, TCSANOW, &new_setting);
}

void Error(char *s)
{
	fprintf(stderr, RED);
	fprintf(stderr, "%s", s);
	fprintf(stderr, NORMAL);
	tcsetattr(0, TCSANOW, &init_setting);
	exit(-1);
}


void Get_Route_table(void)
{
	FILE *fp = fopen("/proc/net/route", "r");
	if (fp == NULL)
		Error("Get Route table Error!\n");

	int i;

	char s[20];

	for (i = 0; i < 11; ++ i)
		fscanf(fp, "%s", s);

	total_route = 0;
	int useless;


	printf("=============== Route Table ===============\n");

	while (fscanf(fp, "%s %X %X %d %d %d %d %X %d %d %d", route[total_route].interface, &route[total_route].dest, &route[total_route].gw, &useless, &useless, &useless, &useless, &route[total_route].mask, &useless, &useless, &useless) != EOF)
	{

		printf("%s ", route[total_route].interface);
		Print_IP((uint_8 *)&route[total_route].dest);
		printf(" ");
		Print_IP((uint_8 *)&route[total_route].gw);
		printf(" ");
		Print_IP((uint_8 *)&route[total_route].mask);
		printf("\n");

		++ total_route;
	}

	fclose(fp);
}


void Get_ARP_table(void)
{
	FILE *fp = fopen("/proc/net/arp", "r");
	if (fp == NULL)
		Error("Get ARP table Error!\n");

	int i;

	char useless[20];

	for (i = 0 ; i < 9; ++ i)
		fscanf(fp, "%s", useless);

	total_arp = 0;

	char ip[20];

	printf("=============== ARP Table ===============\n");
	while (fscanf(fp, "%s %s %s %02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX %s %s", ip, useless, useless, arp[total_arp].mac, arp[total_arp].mac + 1, arp[total_arp].mac + 2, arp[total_arp].mac + 3, arp[total_arp].mac + 4, arp[total_arp].mac + 5, useless, useless) != EOF)
	{
		inet_aton(ip, (struct in_addr *)&arp[total_arp].ip);

		//printf("%X ", arp[total_arp].ip);
		Print_IP((uint_8 *)&arp[total_arp].ip);
		printf(" <---> ");
		Print_MAC(arp[total_arp].mac);
		printf("\n");

		++ total_arp;
	}

	fclose(fp);
}

/* return 0 -> IPv4, 1 -> ARP, 2 -> Send by Myself, 3 -> Send to me, -1 -> Otherwise */
int Analysis(struct packet_pool_type *ptr)
{
	uint_8 *header = ptr -> data;
	struct ethhdr *MAC_Frame = (struct ethhdr *)header;

	/* Checking who Send it */
	int i;
	for (i = 0; i < total_if; ++ i)
		if (memcmp(MAC_Frame -> h_source, if_list[i].mac, 6) == 0)
			return 2;
	
	struct iphdr *IP_Frame;
	switch (ntohs(MAC_Frame -> h_proto))
	{
		case ETH_P_IP:
			/* Get Packet Destination IP Address */	
			IP_Frame = (struct iphdr *)(header + sizeof(struct ethhdr));
			ptr -> dest = IP_Frame -> daddr;
			ptr -> src = IP_Frame -> saddr;
			for (i = 0; i < total_if; ++ i)
				if (IP_Frame -> daddr == if_list[i].ip)
					return 3;

			return 0;
		case ETH_P_ARP:
			return 1;
		default:
			return -1;
	}
}


inline uint_8 * Find_ARP(uint_32 ipaddr)
{
	int i;
	for (i = 0; i < total_arp; ++ i)
		if (arp[i].ip == ipaddr) return arp[i].mac;
	return NULL;
}


inline int Find_DEV(char *name)
{
	int i;
	for (i = 0; i < total_if; ++ i)
		if (strcmp(name, if_list[i].name) == 0) return i;
	return -1;
}




void Packet_Forward(struct packet_pool_type *ptr, uint_8 *mac_dest, char *dev)
{
	int dev_id = Find_DEV(dev);
	if (dev_id == -1)
		Error("Cannot find the device of forwarding!\n");

	uint_8 *mac_src = if_list[dev_id].mac;
	
	struct ethhdr *Frame = (struct ethhdr *)(ptr -> data);
	int i;
	for (i = 0; i < 6; ++ i)
	{
		Frame -> h_dest[i] = mac_dest[i];
		Frame -> h_source[i] = mac_src[i];
	}
	
	if (sendto(if_list[dev_id].socket_fd, ptr -> data, ptr -> size, 0, NULL, 0) < 0)
		Error("Forwarding Packet Error!\n");
}


void Send_ARP(void)
{
	int dev_id = Find_DEV(request_arp.dev);

	printf("Send ARP to %s for requesting ", if_list[dev_id].name);
	Print_IP((uint_8 *)&request_arp.addr);
	printf("\n");

	struct ethhdr *ETH_Frame = (struct ethhdr *)ARP_Buffer;
	memcpy(ETH_Frame -> h_dest, broadcast_mac, 6);
	memcpy(ETH_Frame -> h_source, if_list[dev_id].mac, 6);
	ETH_Frame -> h_proto = htons(ETH_P_ARP);
	
	struct arphdr *ARP_Frame = (struct arphdr *)(ARP_Buffer + sizeof(struct ethhdr));
	ARP_Frame -> hardware = htons(ARPHRD_ETHER);
	ARP_Frame -> proto = htons(ETH_P_IP);
	ARP_Frame -> hardlen = 6;
	ARP_Frame -> pln = 4;
	ARP_Frame -> op = htons(ARPOP_REQUEST);

	uint_32	source_ip = if_list[dev_id].ip;
	uint_32	target_ip = request_arp.addr;
	memcpy(ARP_Frame -> smac, if_list[dev_id].mac, 6);
	memcpy(ARP_Frame -> sip, (uint_8 *)&source_ip, 4);
	memcpy(ARP_Frame -> tip, (uint_8 *)&target_ip, 4);

	if (sendto(if_list[dev_id].socket_fd, ARP_Buffer, ARP_SIZE, 0, NULL, 0) < 0)
		Error("Send ARP Packet Error!\n");
}




int Receive_ARP(struct packet_pool_type *Packet)
{
	struct arphdr *ARP_Frame = (struct arphdr *)((Packet -> data) + sizeof(struct ethhdr));

	arp[total_arp].ip = *((uint_32 *)ARP_Frame -> sip);
	memcpy(arp[total_arp].mac, ARP_Frame -> smac, 6);

	printf("Receive ARP from ");
	Print_IP((uint_8 *)&arp[total_arp].ip);
	printf(": ");

	int i;
	for (i = 0; i < total_arp; ++ i)
		if (arp[i].ip == arp[total_arp].ip)
		{
			printf("Exist...\n");
			return -1;
		}
	++ total_arp;
	printf("New!\n");
	return 0;
}



//return 0 -> Waiting ARP, 1 -> Successful, -1 -> Failed
int Try_to_Forward(struct packet_pool_type *Packet)
{
	int i;
	uint_8		matching = 0;
	uint_32		final = 0;
	
	int			next_hop;

	for (i = 0; i < total_route; ++ i)
	{
		uint_32 subnet = Packet -> dest & route[i].mask;
		if (subnet == route[i].dest)
		{
			matching = 1;
			if (subnet >= final)
			{
				final = subnet;
				next_hop = i;
			}
		}
	}


	Print_IP((uint_8 *)&(Packet -> src));
	printf(" ---> ");
	Print_IP((uint_8 *)&(Packet -> dest));
	printf(": ");

	/* No matching in Routing Table */
	if (matching == 0)
	{
		printf("Warning! No matching in Routing Table!\n");
		return -1;
	}

	uint_32		ip_addr;
	if (route[next_hop].gw == 0)
		ip_addr = Packet -> dest;
	else
		ip_addr = route[next_hop].gw;

	printf("via ");
	Print_IP((uint_8 *)&ip_addr);

	/* Fing Destination MAC Address in ARP Table */
	uint_8 *arp_addr = Find_ARP(ip_addr);

	/* Waiting */
	if (arp_addr == NULL)
	{
		printf("(Warning! No cached MAC address in ARP Table!)\n");
		request_arp.addr = ip_addr;
		request_arp.dev = route[next_hop].interface;
		return 0;
	}

	/* Forwarding */
	printf("(%s)\n", route[next_hop].interface);
	Packet_Forward(Packet, arp_addr, route[next_hop].interface);
	return 1;
}

inline int Pool_next_ptr(void)
{
	int i;
	for (i = Pool_ptr + 1; i != Pool_ptr; ++ i)
	{
		if (i == Pool_Size) i = 0;
		if (Packet_Pool[i].flag == 1) return i;
	}
	printf("Warning! The Packet Pool is full!\n");
	Packet_Pool[Pool_ptr].flag = 1;
	return Pool_ptr;
}


void Router(void)
{
	int i;
	int status;

	fprintf(stderr, RED);
	printf("Router Starting......\n");
	fprintf(stderr, NORMAL);

	while (1)
	{
		/* Receive Packet from Raw Socket */
		Packet_Pool[Pool_ptr].size = recvfrom(socket_raw, Packet_Pool[Pool_ptr].data, BUFFER_MAX, 0, NULL, NULL);	
		if (Packet_Pool[Pool_ptr].size < 42)
			Error("Receive from Raw Socket Error!\n");

		/* Analysis the Packet */
		int packet_type = Analysis(Packet_Pool + Pool_ptr);
		if (packet_type == 0)
		{
			status = Try_to_Forward(Packet_Pool + Pool_ptr);
			//printf("Status = %d\n", status);
			if (status == 0)
			{
				Send_ARP();
				Packet_Pool[Pool_ptr].flag = 0;
				Pool_ptr = Pool_next_ptr();
			}
		}
		else if (packet_type == 1)
		{
			//Get_ARP_table();
			if (Receive_ARP(Packet_Pool + Pool_ptr) == 0)
			{
				/* Retry Forward Cached Packet */
				for (i = 0; i < Pool_Size; ++ i)
					if (Packet_Pool[i].flag == 0)
						if (Try_to_Forward(Packet_Pool + i) == 1)
							Packet_Pool[i].flag = 1;
			}
		}
	}
}


void Initialize(void)
{
	uint_8				interface_buffer[SMALL_BUFFER];
	struct ifconf		ifc;
	struct ifreq		interface;
	struct sockaddr_ll	sll;

	int i;

	/* Create Raw Socket */
	if ((socket_raw = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		Error("Create Raw Socket Error!\n");


	/* Get all network interfaces */
	memset(interface_buffer, 0, sizeof(interface_buffer));
	ifc.ifc_len = sizeof(interface_buffer);
	ifc.ifc_buf = interface_buffer;
	if (ioctl(socket_raw, SIOCGIFCONF, &ifc) < 0)
		Error("Get network interfaces (name) Error!\n");


	total_if = ifc.ifc_len / sizeof(struct ifreq);
	printf("Total interface: %d\n", total_if);

	for (i = 0; i < total_if; ++ i)
	{
		struct ifreq *ptr = (ifc.ifc_req + i);
	
		/* Interface Name */
		strncpy(if_list[i].name, ptr -> ifr_name, IFNAMSIZ);

		/* Interface IP Address */
		if_list[i].ip = (((struct sockaddr_in *)&(ptr -> ifr_addr)) -> sin_addr).s_addr;

		/* Interface Index */
		memset(&interface, 0, sizeof(interface));
		strncpy(interface.ifr_name, ptr -> ifr_name, IFNAMSIZ);
		if (ioctl(socket_raw, SIOCGIFINDEX, &interface) < 0)
			Error("Get network interfaces (index) Error!\n");
		if_list[i].index = interface.ifr_ifindex;

		//if_list[i].index = if_nametoindex(if_list[i].name);
		
		/* Interface MAC Address */
		if (ioctl(socket_raw, SIOCGIFHWADDR, &interface) < 0)
			Error("Get network interfaces (MAC) Error!\n");
		memcpy(if_list[i].mac, interface.ifr_hwaddr.sa_data, 6);

	}

	printf("=============== Network Device Info ===============\n");
	/* Create various Socket */
	for (i = 0; i < total_if; ++ i)
	{
		printf("%d %s ", if_list[i].index, if_list[i].name);
		Print_MAC((uint_8 *)if_list[i].mac);	
		printf(" ");
		Print_IP((uint_8 *)&if_list[i].ip);
		printf("\n");

		if_list[i].socket_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));	
		sll.sll_family = AF_PACKET;
		sll.sll_ifindex = if_list[i].index;
		sll.sll_protocol = htons(ETH_P_ALL);
		if (bind(if_list[i].socket_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0)
			Error("Create device socket Error!\n");

	}

	/* Initialize the router */
	Pool_ptr = 0;
	for (i = 0; i < Pool_Size; ++ i)
		Packet_Pool[i].flag = 1;
}


int main(int argc, char *argv[])
{
	Environment();
	Initialize();

	Get_ARP_table();
	Get_Route_table();

	Router();
	
	return 0;
}
