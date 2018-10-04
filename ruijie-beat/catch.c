#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<signal.h>
#include"catch.h"
int main(int argc, char* argv[]){
	if(!dealOption(argc, argv))
		return -1;
	signal(SIGINT, sig_handle);	 /* Ctrl+C */
	fprintf(stdout, "本程序要锐捷拨号前运行\n然后将自动捕获锐捷认证成功信息作为心跳包依据,并显示必要信息\n\n");
	pcap_t* handle = NULL;
	char* device = NULL;
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
	fprintf(stdout, ">> 等待锐捷拨号中...\n");
	if((pcap_loop(handle, -1, pcap_handle, (u_char*)handle)) == -1)
		err(-2);	

}
//信号处理函数
static void sig_handle(int sig){
	fprintf(stdout, "\b\bThanks for your using.\n");
	exit(0);
}
//处理命令行参数
bool dealOption(int argc, char* argv[]){
	opterr=0;
	int c;
	while((c=getopt_long(argc, argv, short_options, long_options, 0))!=-1){
		switch(c){
			case 'h':bIsHelp=true;break;
			case 'i':interface=optarg;break;
			case '?':
				if(optopt=='i'){
					fprintf(stderr, "Error: option %c must have an argument\n\n", optopt);
					printHelp();
				}
				else{
					fprintf(stderr, "Error: unknown option %c\n\n", optopt);
					printHelp();
				}
				return false;


		}
	}
	if(bIsHelp){
		printHelp();
		exit(0);
	}
	if(interface == NULL){
		fprintf(stderr, "Error: must specified a device\n\n");
		printHelp();
		return false;
	}
	return true;
}
//err退出函数
void err(int ret){
	fprintf(stderr, "%s\n", errbuf);
	exit(ret);
}
//锐捷算法，颠倒一个字节的8位
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
//拿认证成功的success包计算出来的
void getEchoKey(const u_char *capBuf)
{

	int i, offset = 0x1c+capBuf[0x1b]+0x69+24;	/* 通过比较了大量抓包，通用的提取点就是这样的 */
	u_char *base = (u_char *)(&echoKey);
	for (i=0; i<4; i++)
		base[i] = encode(capBuf[offset+i]);
	echoKey = ntohl(echoKey);
	echoKey += 0x102b;
	fprintf(stdout, "\b\bEcho Key = 0x%x\n", echoKey);
}
//回调函数
static void pcap_handle(u_char *user, const struct pcap_pkthdr *h, const u_char *buf)
{
	if (buf[0x0c]==0x88 && buf[0x0d]==0x8e) {
		if (buf[0x0F]==0x00 && buf[0x12]==0x03) {	/* 认证成功 */
			echoNo = 0;
			fprintf(stdout, ">> 捕获认证成功包相关信息成功\n\n");
			for(int i = 0; i < 6; i++){
				localMAC[i] = buf[i];
				destMAC[i] = buf[i + 6];
			}
			fprintf(stdout, "DestMac:  ");
			printMAC((uint8_t*)destMAC);
			fprintf(stdout, "\nSrcMac:   ");
			printMAC((uint8_t*)localMAC);
			fprintf(stdout, "\n");
			getEchoKey(buf);
		}
		if (buf[0x10] == 0 && buf[0x11] == 0x1e && buf[0x12] == 0xff && buf[0x13] == 0xff && buf[0x2c] == 0xff){
			//随便简单判断一下是否是心跳包
			echoNo++;
			fprintf(stdout, "已发送心跳包个数:%-4d\n", echoNo);
			//这里还可以考虑计算发送心跳包的时间，来决定下一个包几时发
		}
	}
}
static void printHelp(){
	fprintf(stdout, "本程序要锐捷拨号前运行\n然后将自动捕获锐捷认证成功信息作为心跳包依据,并显示必要信息\n\n");
	fprintf(stdout, "-i\t--interface\t指定网卡名称\n");
	fprintf(stdout, "-h\t--help\t\t显示该信息\n");



}
//输出MAC
void printMAC(uint8_t* mac){
	for(int i = 0; i < 6; i++){
		fprintf(stdout, "%02x", mac[i]);
		if(i != 5)
			fprintf(stdout, ":");
	}
	fprintf(stdout, "(");
	for(int i = 0; i < 6; i++){
		fprintf(stdout, "%02x", mac[i]);
	}
	fprintf(stdout, ")");
}
