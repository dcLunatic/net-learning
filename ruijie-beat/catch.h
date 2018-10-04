
#include<pcap.h>
#include<netinet/in.h>
#include<getopt.h>


static u_int32_t echoKey = 0, echoNo = 0;
char errbuf[PCAP_ERRBUF_SIZE];
char* interface;
u_char localMAC[6], destMAC[6];
static bool bIsHelp = false;
/*long option*/
option long_options[]={
	{"interface", 1, 0, 'i'},
	{"help", 0, 0, 'h'}
};
/*short option*/
const char* short_options="i:h";
static void sig_handle(int);
bool dealOption(int, char**);
void err(int);
static u_char encode(u_char);
void getEchoKey(const u_char*);
static void pcap_handle(u_char*, const struct pcap_pkthdr*, const u_char*);
void printMAC(uint8_t*);
static void printHelp();
