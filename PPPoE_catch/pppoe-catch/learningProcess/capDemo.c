#include<stdio.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<pcap.h>
#include<netinet/in.h>
#include<netinet/tcp.h>
#include<string.h>
#include<stdlib.h>
#include<arpa/inet.h>
#include<ctype.h>
#define ETHER_ADDR_LEN 6
/*以太网头*/
struct sniff_ethernet 
{
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
}
;
/*IP头*/
struct sniff_ip 
{
	u_char ip_vhl;
	u_char ip_tos;
	u_short ip_len;
	u_short ip_id;
	u_short ip_off;
	#define IP_RF 0x8000
	        #define IP_DF 0x4000
	        #define IP_MF 0x2000
	        #define IP_OFFMASK 0x1fff
	        u_char ip_ttl;
	u_char ip_p;
	u_short ip_sum;
	struct in_addr ip_src,ip_dst;
}
;
/*TCP头*/
typedef u_int tcp_seq;
struct sniff_tcp 
{
	u_short th_sport;
	u_short th_dport;
	tcp_seq th_seq;
	tcp_seq th_ack;
	u_char th_offx2;
	u_char th_flags;
	u_short th_win;
	u_short th_sum;
	u_short th_urp;
}
;
/*UDP报头*/
struct sniff_udp 
{
	u_short udp_sport;
	u_short udp_dport;
	u_short udp_len;
	u_short udp_sum;
}
;
/*DNS报头*/
struct sniff_dns 
{
	u_short dns_id;
	u_short dns_flag;
	u_short dns_ques;
	u_short dns_ans;
	u_short dns_auth;
	u_short dns_add;
	u_int8_t *dsn_data;
}
;
//数据包到达回调函数
void packetcall(u_char *user,const struct pcap_pkthdr *pcap_head,const u_char *packet);
char *ipstr(struct in_addr s_addr);
char* getpackettype(u_short packet_type);
char* toString(u_long s);
//由u_char[6]获取网卡地址字符串
char *getMac(u_char *host);
int main(int argc,char **argv) 
{
	char *dev,errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handler;
	struct bpf_program fp;
	char filter_exp[50]="ip and dst 172.20.92.118";
	if(argc==3) 
	{
		sprintf(filter_exp,"dst %s and dst port %s",argv[1],argv[2]);
	}
	if(argc==5) 
	{
		sprintf(filter_exp,"dst %s and dst port %s or src %s and src port %s",argv[1],argv[2],argv[3],argv[4]);
	}
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr header;
	const u_char *packet;
	dev=pcap_lookupdev(errbuf);
	if(dev==NULL) 
	{
		fprintf(stderr,"could not find default device:%s\n",errbuf);
		return 2;
	}
	printf("device:%s\n",dev);
	if(pcap_lookupnet(dev,&net,&mask,errbuf)==-1) 
	{
		fprintf(stderr,"counld not get netmask for device %s;%s\n",dev,errbuf);
		net=0;
		mask=0;
	}
	handler=pcap_open_live(dev,BUFSIZ,1,10000,errbuf);
	if(handler==NULL) 
	{
		fprintf(stderr,"could not open device %s;%s",dev,errbuf);
		return 2;
	}
	if(pcap_compile(handler,&fp,filter_exp,0,net)==-1) 
	{
		fprintf(stderr,"counld not parse filter %s;%s\n",filter_exp,pcap_geterr(handler));
		return 2;
	}
	if(pcap_setfilter(handler,&fp)==-1) 
	{
		fprintf(stderr,"counld not install filter %s;%s\n",filter_exp,pcap_geterr(handler));
		return 2;
	}
	//捕获数据包
	int packetnums=20;
	pcap_loop(handler,packetnums,packetcall,NULL);
	pcap_close(handler);
	return 0;
}
//数据包到达回调函数
void packetcall(u_char *user,const struct pcap_pkthdr *pcap_head,const u_char *packet) 
{
	static int count=1;
	//数据包计数
	struct sniff_ethernet *ethernet;
	//以太网包头
	struct sniff_ip *ip;
	//ip包头
	struct sniff_udp *udp;
	//udp包头
	struct sniff_dns *dns;
	//dns报头
	const u_char *payload;
	//数据包负载的数据
	int pay_size;
	//数据包负载的数据大小
	ethernet=(struct sniff_ethernet*)(packet);
	ip=(struct sniff_ip*)(packet + sizeof(struct sniff_ethernet));
	udp=(struct sniff_udp*)(packet + sizeof(struct sniff_ethernet)+sizeof(struct sniff_ip));
	dns=(struct sniff_dns*)(packet + sizeof(struct sniff_ethernet) + sizeof(struct sniff_ip) + sizeof(struct sniff_udp));
	payload=(u_char *)(packet+sizeof(struct sniff_ethernet)+sizeof(struct sniff_ip)+sizeof(struct sniff_udp)+sizeof(struct sniff_dns));
	pay_size=ntohs(udp->udp_len)-sizeof(struct sniff_udp)-sizeof(struct sniff_dns);
	printf("-------------数据包:%d\n",count);
	printf("数据包类型:%s\n",getpackettype(ethernet->ether_type));
	printf("源地址:%X:%X:%X:%X:%X:%X\n",
	                (ethernet->ether_shost)[0],
	                (ethernet->ether_shost)[1],
	                (ethernet->ether_shost)[2],
	                (ethernet->ether_shost)[3],
	                (ethernet->ether_shost)[4],
	                (ethernet->ether_shost)[5]);
	printf("目的地址:%X:%X:%X:%X:%X:%X\n",
	                (ethernet->ether_dhost)[0],
	                (ethernet->ether_dhost)[1],
	                (ethernet->ether_dhost)[2],
	                (ethernet->ether_dhost)[3],
	                (ethernet->ether_dhost)[4],
	                (ethernet->ether_dhost)[5]);
	printf("From:%s\n",inet_ntoa(ip->ip_src));
	printf("To:%s\n",inet_ntoa(ip->ip_dst));
	printf("源端口:%d\n",ntohs(udp->udp_sport));
	printf("目的端口:%d\n",ntohs(udp->udp_dport));
	printf("DNS查询问题数%d\n",ntohs(dns->dns_ques));
	if(pay_size>0) 
	{
		printf("Payload    data size %d\n",pay_size);
		const u_char *ch=payload;
		int i,j;
		for (i=0;i<ntohs(dns->dns_ques);i++) 
		{
			//获取各查询名
			printf("第%d个查询名\n",i);
			int k=1;
			//标志符号;
			while(1) 
			{
				if(*ch==0)
				                                        break;
				u_int8_t identify_size=*ch;
				printf("\t第%d个标志符号\n",k);
				ch++;
				for (j=0;j<identify_size;j++,ch++) 
				{
					if(isprint(*ch)) 
					{
						printf("%c",*ch);
					} else 
					{
						printf(".");
					}
				}
				k++;
			}
		}
	}
	count++;
}
