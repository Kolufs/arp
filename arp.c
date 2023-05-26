#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <stdlib.h>

struct arphdr_full {
	__be16		ar_hrd;		/* format of hardware address	*/
	__be16		ar_pro;		/* format of protocol address	*/
	unsigned char	ar_hln;		/* length of hardware address	*/
	unsigned char	ar_pln;		/* length of protocol address	*/
	__be16		ar_op;		/* ARP opcode (command)		*/
	unsigned char		ar_sha[ETH_ALEN];	/* sender hardware address	*/
	unsigned char		ar_sip[4];		/* sender IP address		*/
	unsigned char		ar_tha[ETH_ALEN];	/* target hardware address	*/
	unsigned char		ar_tip[4];		/* target IP address		*/
} __attribute__((packed));

unsigned char *serialize(struct ethhdr *ether_header, struct arphdr_full *arp_header) {
	int packet_size = sizeof(struct ethhdr) + sizeof(struct arphdr_full);
	unsigned char *buffer = (unsigned char *)malloc(packet_size);
	unsigned char *ptr = buffer; 

	memcpy(ptr, ether_header->h_dest, ETH_ALEN);
	ptr += ETH_ALEN;
	
	memcpy(ptr, ether_header->h_source, ETH_ALEN);
	ptr += ETH_ALEN;

	*((unsigned short *)ptr) = htons(ether_header->h_proto);
	ptr += sizeof(unsigned short);

	*((unsigned short *)ptr) = htons(arp_header->ar_hrd);
	ptr += sizeof(unsigned short);

	*((unsigned short *)ptr) = htons(arp_header->ar_pro);
	ptr += sizeof(unsigned short);

	*((unsigned char *)ptr) = arp_header->ar_hln;
	ptr += sizeof(unsigned char);

	*((unsigned char *)ptr) = arp_header->ar_pln;
	ptr += sizeof(unsigned char);

	*((unsigned short *)ptr) = htons(arp_header->ar_op);
	ptr += sizeof(unsigned short);

	memcpy(ptr, arp_header->ar_sha, ETH_ALEN);
	ptr += ETH_ALEN;

	memcpy(ptr, arp_header->ar_sip, 4);
	ptr += 4;

	memcpy(ptr, arp_header->ar_tha, ETH_ALEN);
	ptr += ETH_ALEN;

	memcpy(ptr, arp_header->ar_tip, 4);
	ptr += 4;

	return buffer;
}


void print_buffer(unsigned char *buffer, int size) {
    for (int i = 0; i < size; i++) {
        printf("0x%02x ", buffer[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n"); 
        }
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    // Get the interface and IP address to broadcast to from command-line arguments
    if (argc != 3) {
        printf("Usage: %s <interface> <IP address>\n", argv[0]);
        return 1;
    }
    char interface[IF_NAMESIZE];
    strncpy(interface, argv[1], sizeof(argv[1]));
    char redir[4];
    inet_pton(AF_INET, argv[2], redir);

    // Create a raw socket and set the broadcast option
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    int broadcast = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

    // Get the source MAC and IP addresses for the ARP request
    struct ifreq ifr_dev;
    memset(&ifr_dev, '\0', sizeof(ifr_dev));
    strncpy(ifr_dev.ifr_name, interface, IFNAMSIZ);
    ioctl(sock, SIOCGIFADDR, &ifr_dev);
    ioctl(sock, SIOCGIFHWADDR, &ifr_dev);

    // Prepare the broadcast address and Ethernet and ARP headers
    struct sockaddr_ll broadcast_addr;
    memset(&broadcast_addr, '\0', sizeof(struct sockaddr_in));
    broadcast_addr.sll_ifindex = if_nametoindex(interface);
    broadcast_addr.sll_family = AF_PACKET;
    broadcast_addr.sll_halen = ETH_ALEN;
    broadcast_addr.sll_protocol = htons(ETH_P_ARP);

    struct ethhdr ether_header;
    memset(&ether_header, '\0', sizeof(ether_header));
    memcpy(ether_header.h_source, ifr_dev.ifr_ifru.ifru_hwaddr.sa_data, 6);
    memset(ether_header.h_dest, 0xff, 6);
    ether_header.h_proto = (ETH_P_ARP);

    struct arphdr_full arp_header;
    memset(&arp_header, '\0', sizeof(arp_header));
    arp_header.ar_hrd = ARPHRD_ETHER;
    arp_header.ar_pro = (ETH_P_IP);
    arp_header.ar_hln = ETH_ALEN;
    arp_header.ar_pln = 4;
    arp_header.ar_op = (ARPOP_REQUEST);
    memcpy(arp_header.ar_sha, ifr_dev.ifr_ifru.ifru_hwaddr.sa_data, 6);
    memcpy(arp_header.ar_sip, &ifr_dev.ifr_addr.sa_data[2], 4);
    memset(arp_header.ar_tha, 0, 6);
    memcpy(arp_header.ar_tip, redir, 4);

    // Serialize the headers and send the ARP request
    unsigned char *net_package = serialize(&ether_header, &arp_header);
    print_buffer(net_package, sizeof(arp_header) + sizeof(ether_header));
    if (sendto(sock, net_package, sizeof(arp_header) + sizeof(ether_header), 0, (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr)) < 0) {
        perror("sendto");
        return 1;
    } else {
        printf("ARP request sent.\n");
        close(sock);
        return 0;
    }
}
