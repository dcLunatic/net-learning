#include<sys/socket.h>
#include<sys/types.h>
#include<pcap.h>
#include<netinet/in.h>
#include<netinet/tcp.h>
#include<arpa/inet.h>
#include<ctype.h>
#include<getopt.h>
#include<unistd.h>
#include<time.h>
#include<stdlib.h>
#define ETHER_ADDR_LEN 6

#define AC_NAME_LEN 9
#define AC_COOKIE_LEN 16
u_char AC_Name[] = {
    0x64,0x63,0x4c,0x75,0x6e, 0x61, 0x74, 0x69, 0x63
};
u_char MY_MAC[] = {
	0x8c, 0x90, 0xd3, 0xa8, 0x8b, 0x51
};

bool g_is_quiet = false;
u_char AC_Cookie[] = {
     0xc1, 0x13, 0x03, 0xf4, 0x73, /* .......s */
     0xab, 0x72, 0x69, 0x00, 0x32, 0x93, 0x50, 0xd9, /* .ri.2.P. */
     0x14, 0x89, 0xc7
};

/*header of ethernet*/
struct sniff_ethernet{
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};
u_char MAC_POOL[6 * 255];
int FINISHED = 0;
/*header of ip*/
struct sniff_ip{
	u_char ip_vhl;//4 bit version and 4 bit header length(32bit)
	u_char ip_tos;
	u_short ip_len;
	u_short ip_id;
	u_short ip_off;//3 bit flag and 13 offset
	#define IP_RF 0X8000
	#define IP_DF 0x4000
	#define IP_MF 0X2000
	#define IP_OFFMASK 0x1fff
	u_char ip_ttl;
	u_char ip_type;
	u_char ip_sum;
	struct in_addr ip_src;
	struct in_addr ip_dst;
};
/*header of tcp*/
typedef u_int tcp_seq;
struct sniff_tcp{
	u_short th_sport;
	u_short th_dport;
	tcp_seq th_seq;
	tcp_seq th_ack;
	u_char th_offx2;
	u_char th_flags;
	u_short th_win;
	u_short th_sum;
	u_short th_urp;
};
/*header of udp*/
struct sniff_udp{
	u_short udp_sport;
	u_short udp_dport;
	u_short udp_len;
	u_short udp_sum;
};
/*header of dns*/
struct sniff_dns{
	u_short dns_id;
	u_short dns_flag;
	u_short dns_ques;
	u_short dns_ans;
	u_short dns_auth;
	u_short dns_add;
	u_int8_t *dns_data;
};
/*header of icmp*/
struct sniff_icmp{
	u_char icmp_type;
	u_char icmp_code;
	u_char icmp_sum;
};
/*ethertype*/
struct sniff_ethertype{
	u_short value;
	char statement[48];
};
#define ETHER_TYPE_COUNT 34
struct sniff_ethertype ethertypes[]={
	{0x0006, "XEROX NS IDP"},
	{0x6006, "DLOG"},
	{0x6106, "DLOG"},
	{0x0008, "IP"},
	{0x0108, "X.75 Internet"},
	{0x0208, "NBS Internet"},
	{0x0308, "ECMA Internet"},
	{0x0408, "Chaosnet"},
	{0x0508, "X.25 Level 3"},
	{0x0608, "ARP"},
	{0x0808, "Frame Relay ARP"},
	{0x5965, "Raw Frame Relay"},
	{0x3580, "DRARP | RARP"},
	{0x3780, "Novell Netware IPX"},
	{0x9B80, "EtherTalk"},
	{0xD580, "IBM SNA Services over Ethernet"},
	{0xF380, "AARP"},
	{0x0081, "EAPS"},
	{0x3781, "IPX"},
	{0x4C81, "SNMP"},
	{0xDD86, "IPv6"},
	{0x0B88, "PPP"},
	{0x0C88, "GSMP"},
	{0x4788, "MPLS-u"},
	{0x4888, "MPLS-m"},
	{0x6388, "PPPoE：PPP Over Ethernet <Discovery Stage>"},
	{0x6488, "PPPoE，PPP Over Ethernet<PPP Session Stage>"},
	{0xBB88, "LWAPP"},
	{0xCC88, "LLDP"},
	{0x888E, "EAPOL"},
	{0x0090, "Loopback"},
	{0x0091, "VLAN Tag Protocol Identifier"},
	{0x0092, "VLAN Tag Protocol Identifier"},
	{0xFFFF, "Reserve"}
};

/*options*/
struct sniffer_option{
	bool is_quiet=false;
	bool is_help=false;
	//char interface[32]={0};
	//char filter[1024]={0};
	char* interface=NULL;
	char* filter=NULL;
	int count=-1;
};

/*long option*/
option long_options[]={
	{"filter", 1, 0, 'f'},
	{"interface", 1, 0, 'i'},
	{"quiet", 0, 0, 'q'},
	{"help", 0, 0, 'h'},
	{"count", 0, 0, 'c'}
};
/*short option*/
const char* short_options="f:i:c:qh";
struct sniffer_option* deal_option(int argc, char* argv[]);

void err(int ret);
int addr_ntoa(int i_addr, char* str_addr);
char* get_pack_ethernettype(u_short type);
void print_packet_content(const u_char* packet, int packet_len);
void print_packet_ether_header(const u_char* packet, int packet_len);
void print_packet_ip_header(const u_char* packet, int packet_len);
void print_packet_dns_header(const u_char* packet, int packet_len);
void print_packet_tcp_header(const u_char* packet, int packet_len);
void print_packet_udp_header(const u_char* packet, int packet_len);
void print_packet_icmp_header(const u_char* packet, int packet_len);
void print_help();
void packet_callback(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void send_PADO(const u_char* packet, int packet_len, u_char* source_mac, pcap_t* handle);
bool get_ppp_tag(const u_char* packet, int packet_len, u_char* tag, int* tag_len, int* tag_offset);
void send_PADS(const u_char* packet, int packet_len, u_char* source_mac, pcap_t* handle);
void send_last(const u_char* packet, int packet_len, u_char* source_mac, pcap_t* handle);
bool is_exist_mac(const u_char* mac);
void print_mac(const u_char* mac);
