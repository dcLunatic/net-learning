#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <ctype.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <time.h>
#define MAXBYTE2CAPTURE 2048
bool is_quiet = false;
char *interface = NULL;
char *filter = NULL;
char errbuf[PCAP_ERRBUF_SIZE];
void err(int ret){
	fprintf(stderr, "%s\n", errbuf);
	exit(ret);
}
int addr_ntoa(int i_addr, char* str_addr){
	if(str_addr == NULL)
		return -1;
	struct in_addr addr;
	addr.s_addr = i_addr;
	char* tmp = inet_ntoa(addr);
	strcpy(str_addr, tmp);
	return 0;
}
void print_packet(const u_char* packet, const struct pcap_pkthdr *pkthdr){
	int i;
	for(i=0; i<pkthdr->len/16; i++){
		for(int j = 0; j < 16; j++)
			printf("%01x ", packet[i*16+j]);
		printf("\t");
		for(int k = 0; k < 16; k++)
			if(isprint(packet[16*i+k]))
				printf("%c ", packet[16*i+k]);
			else
				printf(". ");
		printf("\n");
	}
	int l = i*16;
	for(;l<pkthdr->len;l++)
		printf("%02x ", packet[l]);
	l = i*16;
	for(int j = 0; j < (i+1)*16 - pkthdr->len; j++)
		printf("   ");
	printf("\t");
	for(;l<pkthdr->len;l++)
		if(isprint(packet[l]))
			printf("%c ", packet[l]);
		else
			printf(". ");
	printf("\n\n\n");
}
//打印出ip数据报的信息
void print_packet_ip(const u_char* packet, int length){
	printf("Version:%x\nHeader length:%x\n", packet[0] & 0xF0, packet[0] & 0x0F);
	printf("Ip packet length:%02x%02x\n", packet[2], packet[3]);
	printf("Flag:MF=%x DF=%x\n", packet[6] & 0x20, packet[6] & 0x40);
	printf("Fragment offset: %02x%02x\n", packet[6] & 0x1F, packet[7]);
	printf("TTL:%02x\n", packet[8]);
	printf("Protocol:%02x\n", packet[9]);
	printf("Source ip:%d.%d.%d.%d\n", packet[12], packet[13], packet[14], packet[15]);
	printf("Destination ip:%d.%d.%d.%d\n", packet[16], packet[17], packet[18], packet[19]);
	printf("Content:略\n");
}

//打印出以太网帧的一些信息
void print_packet_short(const u_char* packet, const struct pcap_pkthdr *pkthdr){
	int pos = 0;
	int len = 0;
	printf("Destination MAC:");
	for(pos = 0; pos < 6; pos++){
		printf("%02x", packet[pos]);
		if(pos+1<6)
			printf(":");
	}
	printf("\nSource MAC:");
	for(pos = 6; pos < 12; pos++){
		printf("%02x", packet[pos]);
		if(pos+1<12)
			printf(":");
	}
	printf("\nType:%02x%02x\n", packet[12], packet[13]);
	print_packet_ip(packet+14, pkthdr->len - 14 - 4);	

}

void processPacket( u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet )
{
	int i = 0, *counter = (int *) arg;

	printf( "Packet Count: %d\n", ++(*counter) );
	printf( "MAC Packet Size: %d\n", pkthdr->len );
	print_packet_short(packet, pkthdr);
	if(is_quiet)
		return;
	printf( "Payload:\n" );
	print_packet(packet, pkthdr);
	/*
	for ( i = 0; i < pkthdr->len; i++ )
	{
		if ( isprint( packet[i] ) )
			printf( "%c ", packet[i] );
		else
			printf( ". " );

		if ( (i % 16 == 0 && i != 0) || i == pkthdr->len - 1 )
			printf( "\n" );
	}
	*/
	return;
}
void print_help(){
	puts("-f	--filter,	后面跟上过滤规则");
	puts("-i	--interface,	指定监听的网卡");
	puts("-q	--quiet,	安静模式，只显示数据包的分析信息");
	puts("-h	--help,		显示此帮助信息");
}
void deal_option(int argc, char* argv[]){
	option long_options[]={
		{"filter", 1, 0, 'f'},
		{"interface", 1, 0, 'i'},
		{"quiet", 0, 0, 'q'},
		{"help", 0, 0, 'h'}
	};
	opterr=0;
	int c;
	while((c=getopt_long(argc, argv, "f:i:qh", long_options, 0))!=-1){
		switch(c){
			case 'q':is_quiet=true;break;
			case 'h':print_help();exit(0);
			case 'f':filter=optarg;break;
			case 'i':interface=optarg;break;
			case '?':
				if(optopt=='f' || optopt=='i'){
					fprintf(stderr, "Error: option %c must have an argument\n", optopt);
					
				}
				else{
					fprintf(stderr, "Error: unknown option %c\n", optopt);
					
				}
				exit(-1);
				
					
		}
	}
	if(interface == NULL){
		fprintf(stderr, "Error: must specified a device\n");
		exit(-1);
	}

}
int main(int argc, char** argv)
{
	deal_option(argc, argv);
	int	i	= 0, count = 0;
	pcap_t	*descr	= NULL;
	bpf_u_int32 net, mask;
	char *device=NULL;
	memset( errbuf, 0, PCAP_ERRBUF_SIZE );

	/* Get the name of the first device suitable for capture */
	device = pcap_lookupdev( errbuf );
	if(device == NULL){
		exit(-1);
	}

	printf( "Opening device %s\n", device );
	strcpy(device, interface);

	if(pcap_lookupnet(device, &net, &mask, errbuf) == -1){
		err(-1);
	}
	char strnet[16];
	char strmask[16];
	addr_ntoa(net, strnet);
	addr_ntoa(mask, strmask);
	printf("\nMonitoring: %s/ %s/ %s\n\n", device, strnet, strmask);
	/* Open device in promiscuous mode */
	descr = pcap_open_live( device, MAXBYTE2CAPTURE, 1, 512, errbuf );
	if(descr == NULL)
		err(-1);
	/* Loop forever & call processPacket() for every received packet */
	if((pcap_loop( descr, -1, processPacket, (u_char *) &count )) < 0)
		err(-1);

	return(0);
}
