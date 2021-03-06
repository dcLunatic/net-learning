#include<pcap.h>
#include<netinet/in.h>
#include<getopt.h>
#include <fcntl.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<unistd.h>
#include<signal.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <syslog.h>
#include <sys/param.h>
#include <sys/stat.h>
#include<time.h>
#include<ctype.h>
char errbuf[PCAP_ERRBUF_SIZE];			//pcap错误缓冲区
static pcap_t* gHandle = 0;			//全局句柄
/* Frame (576 bytes) */
// 	54EE7586D915
//10.10.10.73 	00 1a a9 15 49 07
//F48E38E9582E
static const unsigned char pkt10314[576] = {
//0x00, 0x1a, 0xa9, 0x15, 0x49, 0x07, 0xf4, 0x8e, /* ........ */
0x54, 0xab, 0x3a, 0x5c, 0xc8, 0xf9, 0x80, 0xfa,
//0x38, 0xe9, 0x58, 0x2e, 0x88, 0x8e, 0x01, 0x02, /* ...P.... */
0x5b, 0x35, 0x61, 0x30, 0x88, 0x8e, 0x01, 0x02, /* ........ */
0x00, 0x00, 0xff, 0xff, 0x37, 0x77, 0xff, 0xaf, /* ....7w.. */
0x47, 0x27, 0xc0, 0x00, 0x00, 0x00, 0xff, 0xaf, /* G'...... */
0x47, 0x27, 0x80, 0xef, 0xef, 0xef, 0xef, 0x06, /* G'...... */
0x71, 0x00, 0x00, 0x13, 0x11, 0x38, 0x30, 0x32, /* q....802 */
0x31, 0x78, 0x2e, 0x65, 0x78, 0x65, 0x00, 0x00, /* 1x.exe.. */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x46, 0x00, /* ......F. */
0x00, 0x01, 0x00, 0x00, 0x13, 0x11, 0x01, 0xe8, /* ........ */
0x1a, 0x28, 0x00, 0x00, 0x13, 0x11, 0x17, 0x22, /* .(....." */
0x31, 0x43, 0x41, 0x32, 0x33, 0x45, 0x30, 0x46, /* 1CA23E0F */
0x31, 0x35, 0x36, 0x44, 0x35, 0x34, 0x44, 0x39, /* 156D54D9 */
0x31, 0x43, 0x42, 0x33, 0x42, 0x46, 0x41, 0x31, /* 1CB3BFA1 */
0x34, 0x46, 0x33, 0x31, 0x33, 0x38, 0x38, 0x34, /* 4F313884 */
0x1a, 0x0c, 0x00, 0x00, 0x13, 0x11, 0x18, 0x06, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x1a, 0x0e, 0x00, 0x00, /* ........ */
0x13, 0x11, 0x2d, 0x08, 0x8c, 0x91, 0xd3, 0xa8, /* ..-..... */
0x8b, 0x50, 0x1a, 0x18, 0x00, 0x00, 0x13, 0x11, /* .P...... */
0x2f, 0x12, 0x0a, 0x08, 0x26, 0xa7, 0xbc, 0x0a, /* /...&... */
0x7c, 0x7d, 0x8a, 0x3b, 0xb1, 0x34, 0x7d, 0x9b, /* |}.;.4}. */
0x86, 0xfa, 0x1a, 0x09, 0x00, 0x00, 0x13, 0x11, /* ........ */
0x35, 0x03, 0x01, 0x1a, 0x18, 0x00, 0x00, 0x13, /* 5....... */
0x11, 0x36, 0x12, 0xfe, 0x80, 0x00, 0x00, 0x00, /* .6...... */
0x00, 0x00, 0x00, 0xa0, 0x97, 0x63, 0x64, 0x35, /* .....cd5 */
0x7f, 0x93, 0x4f, 0x1a, 0x18, 0x00, 0x00, 0x13, /* ..O..... */
0x11, 0x38, 0x12, 0xfe, 0x80, 0x00, 0x00, 0x00, /* .8...... */
0x00, 0x00, 0x00, 0x25, 0x88, 0x9c, 0x4a, 0xd0, /* ...%..J. */
0x7e, 0x33, 0xf5, 0x1a, 0x18, 0x00, 0x00, 0x13, /* ~3...... */
0x11, 0x4e, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, /* .N...... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x1a, 0x88, 0x00, 0x00, 0x13, /* ........ */
0x11, 0x4d, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00, /* .M...... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x1a, 0x28, 0x00, 0x00, 0x13, /* ....(... */
0x11, 0x39, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, /* .9"..... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x1a, 0x48, 0x00, 0x00, 0x13, /* ....H... */
0x11, 0x54, 0x42, 0x56, 0x42, 0x31, 0x38, 0x61, /* .TBVB18a */
0x30, 0x33, 0x36, 0x62, 0x37, 0x2d, 0x61, 0x63, /* 036b7-ac */
0x62, 0x64, 0x31, 0x36, 0x35, 0x63, 0x00, 0x00, /* bd165c.. */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x1a, 0x09, 0x00, 0x00, 0x13, /* ........ */
0x11, 0x62, 0x03, 0x00, 0x1a, 0x09, 0x00, 0x00, /* .b...... */
0x13, 0x11, 0x6b, 0x03, 0x00, 0x1a, 0x10, 0x00, /* ..k..... */
0x00, 0x13, 0x11, 0x7e, 0x0a, 0x00, 0x00, 0x01, /* ...~.... */
0x00, 0x00, 0x04, 0x00, 0x00, 0x1a, 0x09, 0x00, /* ........ */
0x00, 0x13, 0x11, 0x70, 0x03, 0x40, 0x1a, 0x09, /* ...p.@.. */
0x00, 0x00, 0x13, 0x11, 0x6f, 0x03, 0x00, 0x1a, /* ....o... */
0x09, 0x00, 0x00, 0x13, 0x11, 0x79, 0x03, 0x02, /* .....y.. */
0x1a, 0x08, 0x00, 0x00, 0x13, 0x11, 0x76, 0x02  /* ......v. */
};
/* Frame (64 bytes) */
static const unsigned char pkt20572[64] = {
0x54, 0xab, 0x3a, 0x5c, 0xc8, 0xf9, 0x80, 0xfa, /* .....P.. */
0x5b, 0x35, 0x61, 0x30, 0x88, 0x8e, 0x01, 0x00, /* ........ */
0x00, 0x01, 0x01, 0x04, 0x00, 0x04, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  /* ........ */
};
//err退出函数
void err(int ret){
	fprintf(stderr, "%s\n", errbuf);
	exit(ret);
}
int main(int argc, char* argv[]){
	pcap_t* handle = NULL;
	char* device = NULL;
    char interface[] = "eth0";
	bpf_u_int32 net, mask;
	device = pcap_lookupdev(errbuf);
	if(device == NULL){
		err(-2);
	}
	strcpy(device, interface);
	if(pcap_lookupnet(device, &net, &mask, errbuf) == -1){
		err(-2);
	}
	handle = pcap_open_live(device, 65535, 1, 1024, errbuf);
	if(handle == NULL)
		err(-2);
	gHandle = handle;
        int res = pcap_sendpacket(gHandle, pkt10314, 572);
        printf("res: %d\n发送完毕\n", res);

}

