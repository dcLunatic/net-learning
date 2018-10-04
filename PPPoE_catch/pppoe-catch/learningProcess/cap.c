#include<stdio.h>
#include"cap.h"

#define SIZE_ETHERNET 14

char errbuf[PCAP_ERRBUF_SIZE];

int addr_ntoa(int i_addr, char* str_addr){
	if(str_addr == NULL){
		return -1;
	}
	struct in_addr addr;
	addr.s_addr = i_addr;
	char* tmp = inet_ntoa(addr);
	strcpy(str_addr, tmp);
	return 0;
}
int errstr(int ret, char* str){
	if(str != NULL)
		fprintf(stderr, "%s\n", str);
	exit(ret);
}
int err(int ret){
	errstr(ret, errbuf);
}


void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet){
	static int count = 0;
	u_int size_ip;
	u_int size_tcp;
	const struct sniff_ethernet* ethernet;
	const struct sniff_ip* ip;
	const struct sniff_tcp* tcp;
	const char* payload;

	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	if((size_ip = IP_HL(ip) * 4) < 20)
		return;
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	if((size_tcp = TH_OFF(tcp) * 4) < 20)
		return;

	char ip_src[16];
	char ip_dst[16];
	addr_ntoa(ip->ip_src.s_addr, ip_src);
	addr_ntoa(ip->ip_dst.s_addr, ip_dst);
	printf("%s:%d>>%s:%d\n", ip_src, ntohs(tcp->th_sport), ip_dst, ntohs(tcp->th_dport));
	struct ether_header* eptr = (struct ether_header*)packet;
	u_int8_t* ptr;
	ptr = eptr->ether_shost;
	int i = ETHER_ADDR_LEN;
	printf("src MAC:[");
	do{
		printf("%s%x", (i == ETHER_ADDR_LEN)? "":":",*ptr++);
	}
	while(--i>0);
	printf("]\n");

	ptr = eptr->ether_dhost;
	i = ETHER_ADDR_LEN;
	printf("dest MAC:[");
	do{
		printf("%s%x", (i == ETHER_ADDR_LEN)?"":":",*ptr++);
	}
	while(--i>0);
	printf("]\n");

	struct tm* local = localtime(&(header->ts.tv_sec));

	printf("time: %d:%d:%d\n", local->tm_hour, local->tm_min, local->tm_sec);
	printf("package length:%d\n", header->len);
	printf("TTL:%d\n", ip->ip_ttl);
	puts("");
	printf("\nfinish deal with %d packet\n", ++count);
}


int main(){
	char* dev;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	pcap_t* handle;

	if((dev = pcap_lookupdev(errbuf)) == NULL)
		err(-1);
	if((pcap_lookupnet(dev, &net, &mask, errbuf) == -1))
		err(-1);
	char strnet[16];
	char strmask[16];
	u_char* args = NULL;
	addr_ntoa(net, strnet);
	addr_ntoa(mask, strmask);
	printf("\nMonitoring: %s/%s/%s\n\n", dev, strnet, strmask);

	if((handle = pcap_open_live(dev, 65535, 1, 1000, errbuf)) == NULL)
		err(-1);
	if((pcap_loop(handle, -1, got_packet, args)) < 0)
		err(-1);
}

