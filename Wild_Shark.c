
#include <stdio.h>      // Standard I/O library for printf and fprintf
#include <stdlib.h>     // Standard library for memory allocation
#include <pcap.h>       // Libpcap library for packet capturing
#include <netinet/ip.h> // Definitions for IP headers
#include <netinet/tcp.h> // Definitions for TCP headers
#include <netinet/udp.h> // Definitions for UDP headers
#include <netinet/ip_icmp.h> // Definitions for ICMP headers
#include <arpa/inet.h>  // Functions for IP address manipulation
#include <string.h>     // String manipulation functions


#define SNAP_LEN 1518 // Maximum bytes to capture from each packet



void print_welcome_message() {
    // Function to print the welcome message when the shell starts.
    const char *welcome_message = 
        "                                                                             ++++++\n"
        "                                                                       =======++++*\n"
        "                                                                   ==========++++*                   \n"
        "                                                               +=============+++*                      \n"
        "                                             =-::::-+       ================++++*                   \n"
        "                             =---------:::::::::-:::::::::::-----==---======+++*                    \n"
        "                     =------------------------------------------------======+++*                    \n"
        "                =-------:---:-------------------==--=--------------========+*+*                     \n"
        "            ----========@#+@@==-----------------==--+---=--=----===============                                \n"
        "        ==-=======------@@@@@-------------------=---=---=--=-------===============                       \n"
        "     ==-====-----::::::::....:::::.::::::::::::::::----=---=---------==============+                 \n"
        "   ====----:::::::...................................:::::::-----------===========++++                \n"
        " +===-==--::::..............................................::::::::--=============++++*            \n"
        " =----::::::::.::.:.::::::::::::..:.......:.....................:::::::::::::::--====++++           \n"
        " =----::::::::::::::::::::::-+**#**+=-::::::.:::::...............:::--==+==--------==---=++                  \n"
        " ==+---:::::::::::::::+++*+-*=:.......:::::::::::::::::.............::---===+++++====++*********         \n"
        "   ===----:-:::::::+*+*:::::..:::::::::::::::::::::.::::::::...........:::::---::--======+++* ##%%%  \n"
        "      ===---------**-+=:::::::::::::::::::::::::::::::::::::::...........:::::::::::-====++++*      \n"   
        "           =====--#*==-------------::::::::::::::::::::::::::::::::..........:::::::::--==++++*     \n"
        "                    =====---------------------::::::::::::::::::::::::::........:::::::--=++++*     \n"
        "                              =+============---------::::::::::::::::::::.........:::::::-==+++*    \n"
        "                                         ==========-------:::::::::::::::::::::...:.:::::--=+++**        \n"
        "                                         =-----===++++====-----::::::::::::.::::::.::::::::-=++**   \n"
        "                                        =---::---==++*    +===------::::::::::::::::::::::::-+++*    \n"
        "                                        =--::::---=**          +==-----::::::::::::::::::::--=++**   \n"
        "                                       +=--:::---=*                ++==---::::::::::::::::::--++**  \n"
        "                                       +=------=+                     **+=---:::::::::::::::--=+**               \n"
        "                                       +=-----+#                         **+=--:::::::::::::--=+**        \n"
        "                                       +=--=+*%                            *++=--:::::::::::--=+**     \n"
        "                                      #+==+*#%                               ++=--::::::::::--=+**          \n"
        "                                      ######                                  ++=--::::::::::--**      \n"
        "                                       %%%%                                   *+=-::::::::::---+*   \n"
        "                                                                               +=-::::::::::---=*#           \n"
        "                                                                             #*+=-::::::::::--==+#%       \n"
        "                                                                             #*+=-:::::::::--==+*#%  \n"
        "                                                                               +*=::::::::--=+####  \n"   
        "                                                                               ++-:::::---==+*      \n"
        "                                                                              ++=-:::---==+*        \n"
        "                                      ++++==============+                    ++=--:----=+*#                      \n"
        "                                         #***+++++++=========++++          *++=-------=*#                          \n"
        "                                              ##***++++==========+++++   +++==------=+                       \n"
        "                                                  ###**++++======++++++++++==---====+                 \n"
        "                                                      ###**+++++++++++++======++  ++                 \n"
        "                                                          ###**+++++++++++++*                        \n"
        "                                                             ###************                                       \n"
        "                                                                ##**++******                                \n"
        "                                                                 #*********                           \n"
        "                                                                 #********                                 \n"
        "                                                                 #*******                              \n"
        "                                                                #*******                               \n"
        "                                                                #******                                  \n"
        "                                                                #*****                                  \n"
        "                                                               ##*##                                 \n"
        "                                                               ##*#                                  \n"    
        "                                                               ##                                     \n"
        "  \n"
        "  \n";                            

    printf("%s\n", welcome_message);  // Print the welcome message.
}




// Base structure for packets
typedef struct Packet {
    void (*parse)(struct Packet*, const u_char*, struct pcap_pkthdr*); // Function pointer for parsing packets
} Packet;




// Derived structure for IP packets
typedef struct IPPacket {
    Packet base;           // Base packet structure
    struct ip *ip_header;  // Pointer to the IP header
} IPPacket;




// Function to parse an IP packet
void parse_ip_packet(Packet *self, const u_char *packet, struct pcap_pkthdr *header) {
    IPPacket *ip_pkt = (IPPacket *)self; // Typecasting base to IPPacket
    ip_pkt->ip_header = (struct ip *)(packet + 14); // Extracting the IP header (after Ethernet header)
    printf("IP Packet: %s -> %s\n", inet_ntoa(ip_pkt->ip_header->ip_src), inet_ntoa(ip_pkt->ip_header->ip_dst));
}





// Function to create and initialize an IPPacket structure
IPPacket* create_ip_packet() {
    IPPacket *pkt = (IPPacket*)malloc(sizeof(IPPacket)); // Allocating memory for the IP packet
    pkt->base.parse = parse_ip_packet; // Assigning the parse function
    return pkt;
}





// Derived structure for TCP packets
typedef struct TCPPacket {
    Packet base;           // Base packet structure
    struct tcphdr *tcp_header; // Pointer to the TCP header
} TCPPacket;




// Function to parse a TCP packet
void parse_tcp_packet(Packet *self, const u_char *packet, struct pcap_pkthdr *header) {
    TCPPacket *tcp_pkt = (TCPPacket *)self; // Typecasting base to TCPPacket
    struct ip *ip_header = (struct ip *)(packet + 14); // Extracting the IP header
    tcp_pkt->tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl * 4)); // Extracting the TCP header
    printf("TCP Packet: Src Port: %d -> Dst Port: %d\n", ntohs(tcp_pkt->tcp_header->th_sport), ntohs(tcp_pkt->tcp_header->th_dport));
}





// Function to create and initialize a TCPPacket structure
TCPPacket* create_tcp_packet() {
    TCPPacket *pkt = (TCPPacket*)malloc(sizeof(TCPPacket)); // Allocating memory for the TCP packet
    pkt->base.parse = parse_tcp_packet; // Assigning the parse function
    return pkt;
}

// Derived structure for UDP packets
typedef struct UDPPacket {
    Packet base;           // Base packet structure
    struct udphdr *udp_header; // Pointer to the UDP header
} UDPPacket;

// Function to parse a UDP packet
void parse_udp_packet(Packet *self, const u_char *packet, struct pcap_pkthdr *header) {
    UDPPacket *udp_pkt = (UDPPacket *)self; // Typecasting base to UDPPacket
    struct ip *ip_header = (struct ip *)(packet + 14); // Extracting the IP header
    udp_pkt->udp_header = (struct udphdr *)(packet + 14 + (ip_header->ip_hl * 4)); // Extracting the UDP header
    printf("UDP Packet: Src Port: %d -> Dst Port: %d\n", ntohs(udp_pkt->udp_header->uh_sport), ntohs(udp_pkt->udp_header->uh_dport));
}

// Function to create and initialize a UDPPacket structure
UDPPacket* create_udp_packet() {
    UDPPacket *pkt = (UDPPacket*)malloc(sizeof(UDPPacket)); // Allocating memory for the UDP packet
    pkt->base.parse = parse_udp_packet; // Assigning the parse function
    return pkt;
}




// Sniffer structure for managing packet capturing
typedef struct Sniffer {
    pcap_t *handle;         // Handle for the pcap session
    char filter_exp[256];   // Filter expression for packet capture
    struct bpf_program fp;  // Compiled filter program
} Sniffer;




// Function to start packet sniffing
void start_sniffing(Sniffer *sniffer, const char *dev) {
    char errbuf[PCAP_ERRBUF_SIZE]; // Buffer for error messages
    struct pcap_pkthdr header; // Packet header information
    const u_char *packet; // Pointer to the captured packet data

    // Open the device for live packet capture
    sniffer->handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (sniffer->handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return;
    }

    // Compile and apply the filter expression
    if (pcap_compile(sniffer->handle, &sniffer->fp, sniffer->filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s\n", sniffer->filter_exp);
        return;
    }
    pcap_setfilter(sniffer->handle, &sniffer->fp);




    // Capture packets in a loop
    while ((packet = pcap_next(sniffer->handle, &header)) != NULL) {
        struct ip *ip_header = (struct ip *)(packet + 14); // Extract IP header
        
        // Check the protocol and parse accordingly
        if (ip_header->ip_p == IPPROTO_TCP) {
            TCPPacket *tcp_pkt = create_tcp_packet();
            tcp_pkt->base.parse((Packet*)tcp_pkt, packet, &header);
            free(tcp_pkt); // Free allocated memory
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            UDPPacket *udp_pkt = create_udp_packet();
            udp_pkt->base.parse((Packet*)udp_pkt, packet, &header);
            free(udp_pkt); // Free allocated memory
        } else {
            IPPacket *ip_pkt = create_ip_packet();
            ip_pkt->base.parse((Packet*)ip_pkt, packet, &header);
            free(ip_pkt); // Free allocated memory
        }
    }
    pcap_close(sniffer->handle); // Close the pcap session
}





// Main function
int main(int argc, char *argv[]) {

	print_welcome_message(); // Print the welcome message when the shell starts.
	

    if (argc < 3) { // Ensure correct number of arguments
        printf("Usage: %s <interface> <filter-expression>\n", argv[0]);
        return 1;
    }
    
    Sniffer sniffer; // Create a Sniffer instance
    snprintf(sniffer.filter_exp, sizeof(sniffer.filter_exp), "%s", argv[2]); // Copy filter expression
    start_sniffing(&sniffer, argv[1]); // Start the sniffing process
    return 0;
}

