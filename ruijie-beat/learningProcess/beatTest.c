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
#include <arpa/inet.h>
#include<time.h>

#include<ctype.h>
static u_int32_t echoKey = 0, echoNo = 0;	//心跳包的特殊值
char localMAC[] = {0,0,0,0,0,0};
char destMAC[] = {0,0,0,0,0,0};
int sendCount = 0;
static u_char sendPacket[0x2D];			//发包
/* 锐捷算法，颠倒一个字节的8位 */
static u_char encode(u_char base)
{
	u_char result = 0;
	int i;
	for (i=0; i<8; i++)
	{
		result <<= 1;
		result |= base&0x01;
		base >>= 1;
	}
	return ~result;
}
//填充以太网帧
static void fillEtherAddr(u_int32_t protocol)
{
	/* 填充MAC地址和协议 */
	memset(sendPacket, 0, 0x2D);
	memcpy(sendPacket, destMAC, 6);
	memcpy(sendPacket+0x06, localMAC, 6);
	*(u_int32_t *)(sendPacket+0x0C) = htonl(protocol);
}
void print_packet_content(const u_char* packet, int packet_len){
	int i;
	for(i=0; i<packet_len/16; i++){
		printf("%04x:   ", i*16);
		for(int j = 0; j < 16; j++)
			printf("%02x ", packet[i*16+j]);
		printf("\t");
		for(int k = 0; k < 16; k++)
			if(isprint(packet[16*i+k]))
				printf("%c ", packet[16*i+k]);
			else
				printf(". ");
		printf("\n");
	}
	printf("%04x:   ", i*16);
	int l = i*16;
	for(;l<packet_len;l++)
		printf("%02x ", packet[l]);
	l = i*16;
	for(int j = 0; j < (i+1)*16 - packet_len; j++)
		printf("   ");
	printf("\t");
	for(;l<packet_len;l++)
		if(isprint(packet[l]))
			printf("%c ", packet[l]);
		else
			printf(". ");
	printf("\n\n\n");
}
//填充心跳包
void fillEchoPacket(u_char *echoBuf)
{
	int i;
	u_int32_t dd1=htonl(echoKey + echoNo), dd2=htonl(echoNo);
	u_char *bt1=(u_char *)&dd1, *bt2=(u_char *)&dd2;
	echoNo++;
	for (i=3; i<4; i++)
	{
		echoBuf[0x18+i] = encode(bt1[i]);
		echoBuf[0x22+i] = encode(bt2[i]);
	}
}
//发送心跳包
static int sendEchoPacket(){
	if(sendCount++ == 0){
		u_char echo[] =
		{
			0x00,0x1E,0xFF,0xFF,0x37,0x77,0x7F,0x9F,0xFF,0xFF,0x21,0x13,0xFF,0xFF,0x37,0x77,
			0x7F,0x9F,0xFF,0xFF,0xF7,0x2B,0xFF,0xFF,0x37,0x77,0x7F,0x3F,0xFF
		};
		fprintf(stdout, ">> 发送心跳包以保持在线...\n");
		fillEtherAddr(0x888E01BF);
		memcpy(sendPacket+0x10, echo, sizeof(echo));
		
	}
	fillEchoPacket(sendPacket);
	//return pcap_sendpacket(gHandle, sendPacket, 0x2D);
	printf("No.%d\n", echoNo);
	print_packet_content(sendPacket, 0x2D);
	return 1;
}

int main(){
	echoKey = 4322;
	for(echoNo = 0; echoNo < 10; ){
		sendEchoPacket();
	}
	return 0;
}
