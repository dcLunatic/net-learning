#include"beat.h"
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
/****************************************
*           author: dcLunatic           *
*                                       *
****************************************/
int main(int argc, char* argv[]){
	if(check_running() <= 0)
		return 0;
	if(dealOption(argc, argv) == false)
		return -1;
	signal(SIGALRM, sig_handle);	/* 定时器 */
	signal(SIGHUP, sig_handle);	 /* 注销时 */
	signal(SIGINT, sig_handle);	 /* Ctrl+C */
	signal(SIGQUIT, sig_handle);	/* Ctrl+\ */
	signal(SIGTSTP, sig_handle);	/* Ctrl+Z */
	signal(SIGTERM, sig_handle);	/* 被结束时 */
	fprintf(stdout, "本程序要锐捷拨号前运行\n然后将自动捕获锐捷认证成功信息作为心跳包依据\n锐捷拨号成功后，直接**杀死**锐捷进程\n然后按下Ctrl+C通知本程序开始模拟发送心跳包\n");
	
	
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
	gHandle = handle;
	fprintf(stdout, ">> 等待锐捷拨号中...\n");
	if(bIsAuto){
		if((pcap_loop(handle, -1, pcap_handle, (u_char*)handle)) == -1)
			err(-2);
	}
	else{
		fprintf(stdout, "使用提供的echoKey:0x%x echoNo:0x%x\n", echoKey, echoNo);
		bCapture = true;
		bIsStart = true;
	}
	if(bIsDebug)
		fprintf(stdout, "\b\bechoInterval = %d\n", echoInterval);
	if(bIsUpdateMac)
		setFackMac(interface);
	if(bIsWindows){
		fprintf(stdout, "\b\b>> 在此之前，Windows锐捷已经发送了 %d 次心跳包\n", echoNo/2);
		echoNo /= 2;
	}
	else
		fprintf(stdout, "\b\b>> 在此之前，锐捷已经发送了 %d 次心跳包\n", echoNo);
	if(bIsBackground){
		fprintf(stdout, "\n>> 程序转入后台运行\n");
		fprintf(stdout, ">> 相关信息输出到日志文件%s中.\n", logFile);
		init_daemon();
		time_t now;
		FILE *file = fopen(logFile, "a+");
		time(&now);
		if(lock()){
			fprintf(file, ">> %s: 为锁文件加锁失败,程序结束!\n", ctime(&now));
			fclose(file);
			return -1;
		}
		
		time(&now);
		fprintf(file, "\n\n-------------------------------------------------------\n");
		fprintf(file, "%sRunning ruijie-beat program\nfileName: %s\n", ctime(&now), argv[0]);
		fprintf(file, "\t  interface: %s\n\t  echointerval: %d\n\t  updatemac: %d\n\t  bIsAuto: %d\n**echoKey: 0x%x**\n", interface, echoInterval, bIsUpdateMac, bIsAuto, echoKey);
		fprintf(file, "Before running, the ruijie already sended %d echoPackets.\n", echoNo);

		if(bIsDebug){
			fprintf(file, "\n\nSuccess Packet Content\n");
			fprint_packet_content(successPacket, 448);
		}
		fclose(file);
		while(1){
			
			file = fopen("/var/log/ruijie-beat.log", "a+");
			if(file){
				time(&now);
				fprintf(file, "%s\t\t\tsend the No.%d echoPacket.\n", ctime(&now), echoNo+1);
				fclose(file); 	
			}
			sendEchoPacket();
			sleep(echoInterval);		
		}
	
	}
	else{
		//signal
		while(1){
			sendEchoPacket();
			time_t now;
			if(sendCount % 10 == 0){
				time(&now);
				fprintf(stdout, "%s发送了 No.%d 模拟心跳包\n\n", ctime(&now), echoNo);
			}	
			sleep(echoInterval);
		}
	}
	return 0;
}

//处理命令行参数
bool dealOption(int argc, char* argv[]){
	opterr=0;
	int c;
	int time = -1;
	uint64_t remoteMac = 0, sourceMac = 0;
	while((c=getopt_long(argc, argv, short_options, long_options, 0))!=-1){
		switch(c){
			case 'h':bIsHelp=true;break;
			case 'i':interface=optarg;break;
			case 'w':bIsWindows=true;break;
			case 'b':bIsBackground=true;break;
			case 'e':time=atoi(optarg);break;
			case 'u':bIsUpdateMac=true;break;
			case 'd':bIsDebug=true;break;
			case 'k':echoKey=atoi(optarg);break;
			case 'n':echoNo=atoi(optarg);break;
			case 'r':remoteMac=htoi(optarg);break;
			case 's':sourceMac=htoi(optarg);break;
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
	if(echoKey > 0 && echoNo > 0 && remoteMac > 0 && sourceMac > 0){
		bIsAuto = false;
		for(int i = 5; i >= 0; i--){
			destMAC[i] = remoteMac%256;
			localMAC[i] = sourceMac%256;
			remoteMac /= 256;
			sourceMac /= 256;
		}
	}
	else if(!echoKey && !echoNo && !remoteMac && !sourceMac){
		;
	}
	else{
		fprintf(stderr, "you must specified remoteMac, sourceMac, echoKey, echoNo at one time.\n\n");
		printHelp();
		return false;
	}
	if(time > 0)
		echoInterval = time;
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
//设置指定网卡的mac
int macAddrSet(uint8_t* mac, char* dev)  
{  
    struct ifreq temp;  
    struct sockaddr* addr;  
  
    int fd = 0;  
    int ret = -1;  
      
    if((0 != getuid()) && (0 != geteuid()))  
        return -1;  
  
    if((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)  
    {  
        return -1;  
    }  
  
    strcpy(temp.ifr_name, dev);  
    addr = (struct sockaddr*)&temp.ifr_hwaddr;  
      
    addr->sa_family = ARPHRD_ETHER;  
    memcpy(addr->sa_data, mac, 6);  
      
    ret = ioctl(fd, SIOCSIFHWADDR, &temp);  
      
    close(fd);  
    return ret;  
}
//获取指定网卡的mac
int macAddrGet(uint8_t* mac, char* dev)  
{  
    struct ifreq temp;  
    struct sockaddr* addr;  
  
    int fd = 0;  
    int ret = -1;  
      
    if((0 != getuid()) && (0 != geteuid()))  
        return -1;  
  
    if((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)  
    {  
        return -1;  
    }  
  
    strcpy(temp.ifr_name, dev);
    addr = (struct sockaddr*)&temp.ifr_hwaddr;  
      
    addr->sa_family = ARPHRD_ETHER;  
      
    ret = ioctl(fd, SIOCGIFHWADDR, &temp);  
    close(fd);  
  
    if(ret < 0)  
        return -1;  
  
    memcpy(mac, addr->sa_data, 6);  
  
    return ret;  
}
//设置指定网卡的开启或者关闭
int if_updown(char *ifname, int flag)
{
    int fd, rtn;
    struct ifreq ifr;        

    if (!ifname) {
        return -1;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0 );
    if ( fd < 0 ) {
        perror("socket");
        return -1;
    }
    
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, (const char *)ifname, IFNAMSIZ - 1 );

    if ( (rtn = ioctl(fd, SIOCGIFFLAGS, &ifr) ) == 0 ) {
        if ( flag == DOWN )
            ifr.ifr_flags &= ~IFF_UP;
        else if ( flag == UP ) 
            ifr.ifr_flags |= IFF_UP;
        
    }

    if ( (rtn = ioctl(fd, SIOCSIFFLAGS, &ifr) ) != 0) {
        perror("SIOCSIFFLAGS");
    }

    close(fd);

    return rtn;
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

	if(bIsDebug){
		if(!bIsBackground){
			fprintf(stdout, "Success Packet Content\n");
			print_packet_content(capBuf, 448);
		}
		else{
			successPacket = (u_char*)malloc(448);
			for(int i = 0; i < 448; i++)successPacket[i] = capBuf[i];
		}
	}
	int i, offset = 0x1c+capBuf[0x1b]+0x69+24;	/* 通过比较了大量抓包，通用的提取点就是这样的 */
	u_char *base = (u_char *)(&echoKey);
	for (i=0; i<4; i++)
		base[i] = encode(capBuf[offset+i]);
	echoKey = ntohl(echoKey);
	echoKey += 0x102b;
	if(bIsDebug)
		fprintf(stdout, "\b\bEcho Key = 0x%x\n", echoKey);
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
//填充心跳包
void fillEchoPacket(u_char *echoBuf)
{
	int i;
	u_int32_t dd1=htonl(echoKey + echoNo), dd2=htonl(echoNo);
	u_char *bt1=(u_char *)&dd1, *bt2=(u_char *)&dd2;
	echoNo++;
	for (i=0; i<4; i++)
	{
		echoBuf[0x18+i] = encode(bt1[i]);
		echoBuf[0x22+i] = encode(bt2[i]);
	}
	echoBuf[0x22+2] = encode(bt2[2]+0x10);
	echoBuf[0x22+3] = encode(bt2[3]+0x2b);
}
//发送心跳包
static int sendEchoPacket(){
	if(sendCount++ == 0){
		u_char echo[] =
		{
			0x00,0x1E,0xFF,0xFF,0x37,0x77,0x7F,0x9F,0xFF,0xFF,0xD9,0x13,0xFF,0xFF,0x37,0x77,
			0x7F,0x9F,0xFF,0xFF,0xF7,0x2B,0xFF,0xFF,0x37,0x77,0x7F,0x3F,0xFF
		};
		fprintf(stdout, ">> 发送心跳包以保持在线...\n");
		fillEtherAddr(0x888E01BF);
		memcpy(sendPacket+0x10, echo, sizeof(echo));
		
	}
	fillEchoPacket(sendPacket);
	if(bIsDebug){
		if(!bIsBackground){
			printf("No.%d\n", echoNo);
			print_packet_content(sendPacket, 0x2D);
		}
		else{
			fprint_packet_content(sendPacket, 0x2D);
		}
	}
	return pcap_sendpacket(gHandle, sendPacket, 0x2D);

	//return 1;
}
//回调函数
static void pcap_handle(u_char *user, const struct pcap_pkthdr *h, const u_char *buf)
{
	if (buf[0x0c]==0x88 && buf[0x0d]==0x8e) {
		if (buf[0x0F]==0x00 && buf[0x12]==0x03) {	/* 认证成功 */
			echoNo = 0;
			fprintf(stdout, ">> 捕获认证成功包相关信息成功\n请按Ctrl+C开始发送心跳包\n\n");
			for(int i = 0; i < 6; i++){
				localMAC[i] = buf[i];
				destMAC[i] = buf[i + 6];
			}
			bCapture = true;
			getEchoKey(buf);
		}
		if (buf[0x10] == 0 && buf[0x11] == 0x1e && buf[0x12] == 0xff && buf[0x13] == 0xff && buf[0x2c] == 0xff){
			//随便简单判断一下是否是心跳包
			echoNo++;
			//printf("心跳包:%d\n", echoNo);
			//这里还可以考虑计算发送心跳包的时间，来决定下一个包几时发
		}
	}
}
//信号处理函数
static void sig_handle(int sig){
	if(bCapture == false)
		//在等待拨号的过程中还没成功等待数据包按下Ctrl+C退出
		exit(-2);
	if(bIsStart){
		fprintf(stdout, "\b\bThanks for you using.\n");
		macAddrSet((uint8_t*)orignMAC, interface);
		if_updown(interface, DOWN);
		if_updown(interface, UP);
		exit(0);
	}
	else{
		bIsStart = true;
		pcap_breakloop(gHandle);
	}

}
//输出帮助信息
void printHelp(){
	fprintf(stdout, "本程序要锐捷拨号前运行\n然后将自动捕获锐捷认证成功信息作为心跳包依据\n锐捷拨号成功后，直接**杀死**锐捷进程\n然后按下Ctrl+C通知本程序开始模拟发送心跳包\n");
	fprintf(stdout, "***如果程序已在后台运行，会直接结束后台程序，然后退出程序***\n\n");
	fprintf(stdout, "----------------------------------Usage---------------------------------------\n\n");
	fprintf(stdout, "-w\t--windows\t\t表明是在windows环境下，默认在非windows环境下\n");
	fprintf(stdout, "\t\t\t\t该参数已废弃\n");
	fprintf(stdout, "-i\t--interface\t\t指定上网的网卡名称\n");
	fprintf(stdout, "-e\t--echointerval\t\t心跳包间隔(单位:秒)(默认30)\n");
	fprintf(stdout, "-b\t--background\t\t成功运行后后台运行程序\n");
	fprintf(stdout, "-u\t--updatemac\t\t更新指定网卡的mac(会重启网卡)\n");
	fprintf(stdout, "-d\t--debug\t\t\t调试模式\n");
	fprintf(stdout, "-h\t--help\t\t\t显示该信息\n");
	fprintf(stdout, "\n\n手动指定必要信息，来使得程序不等待抓取信息，立即开始模拟发送心跳包\n***需要同时指定下面四个参数***\n");
	fprintf(stdout, "-k\t--echokey\n");
	fprintf(stdout, "-n\t--echono\n");
	fprintf(stdout, "-r\t--remotemac\n");
	fprintf(stdout, "-s\t--sourcemac\n");
	fprintf(stdout, "\n--------------------------------注意事项----------------------------------------\n\n");
	fprintf(stdout, "该程序自行计算提供的echokey似乎有一两位有问题，所以当发送256个包之后会断开连接\n所以这里建议把心跳包间隔调大一点，广金的大概是6分钟检测一次把目前\n\n");
	fprintf(stdout, "    echointerval(s)    activetime\n");
	fprintf(stdout, "    30                 128m\n");
	fprintf(stdout, "    60                 256m\n");
	fprintf(stdout, "    113                8h\n");
	fprintf(stdout, "    256                18.2h\n");
	fprintf(stdout, "    300                21.3h\n\n\n");
	

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
//设置指定网卡的mac，以及一些相关操作
void setFackMac(char* dev){
	macAddrGet((uint8_t*)orignMAC, dev);
	fprintf(stdout, "\n\n>> 将设置设备: %s 的mac为:  ", dev);
	for(int i = 0; i < 6; i++){
		fprintf(stdout, "%02x", localMAC[i]);
		if(i != 5)
			fprintf(stdout, ":");
	}
	fprintf(stdout, "  , 并重启该设备\n");
	pcap_close(gHandle);
	macAddrSet((uint8_t*)localMAC, dev);
	if_updown(dev, DOWN);
	if_updown(dev, UP);
	fprintf(stdout, ">> 设置设备MAC成功\n");
	fprintf(stdout, ">> 重新打开设备: %s \n", dev);
	gHandle = pcap_open_live(dev, 65535, 1, 1024, errbuf);
	if(gHandle == NULL)
		err(-2);
	fprintf(stdout, ">> 打开成功\n");
}
//使程序后台运行
int init_daemon(void)   
{   
    int pid;   
    int i;   
  
    //忽略终端I/O信号，STOP信号  
    signal(SIGTTOU,SIG_IGN);  
    signal(SIGTTIN,SIG_IGN);  
    signal(SIGTSTP,SIG_IGN);  
    signal(SIGHUP,SIG_IGN);  
      
    pid = fork();  
    if(pid > 0) {  
        exit(0); //结束父进程，使得子进程成为后台进程  
    }  
    else if(pid < 0) {   
        return -1;  
    }  
  
    //建立一个新的进程组,在这个新的进程组中,子进程成为这个进程组的首进程,以使该进程脱离所有终端  
    setsid();  
  
    //再次新建一个子进程，退出父进程，保证该进程不是进程组长，同时让该进程无法再打开一个新的终端  
    pid=fork();  
    if( pid > 0) {  
        exit(0);  
    }  
    else if( pid< 0) {  
        return -1;  
    }  
  
    //关闭所有从父进程继承的不再需要的文件描述符  
    //for(i=0;i< NOFILE;close(i++));  
  
    //改变工作目录，使得进程不与任何文件系统联系  
    chdir("/");  
  
    //将文件当时创建屏蔽字设置为0  
    umask(0);  
  
    //忽略SIGCHLD信号  
    signal(SIGCHLD,SIG_IGN);   
      
    return 0;  
}
int check_running(){
	lockfd = open (lockFile, O_RDWR|O_CREAT, LOCKMODE);
	if (lockfd < 0) {
		fprintf(stderr, ">> !! 打开锁文件失败");
		return -1;
	}
	fl.l_start = 0;
	fl.l_whence = SEEK_SET;
	fl.l_len = 0;
	fl.l_type = F_WRLCK;
	if (fcntl(lockfd, F_GETLK, &fl) < 0) {
		fprintf(stderr, ">> !! 获取文件锁失败");
		return -1;
	}
    if(fl.l_type != F_UNLCK){
    	fprintf(stdout, ">> 锐捷心跳模拟程序已经运行.\n");
        fprintf(stdout, ">> 发送结束信号给对应进程(PID=%d).\n", fl.l_pid);
        if(kill(fl.l_pid, SIGINT) == -1){
            fprintf(stderr, ">> 结束进程失败\n");
            return -1;
        }
        else{
            fprintf(stdout, ">> 结束进程成功\n");   
            return 0;
        }
    }
    return 1;

}
int lock(){
	fl.l_type = 1;
	fl.l_pid = getpid();
	int result = fcntl(lockfd, F_SETLKW, &fl);
	if(result < 0){
		return -1;
	}
	return 0;
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
void fprint_packet_content(const u_char* packet, int packet_len){
	int i;
	FILE* file = fopen(logFile, "a+");
	for(i=0; i<packet_len/16; i++){
		fprintf(file, "%04x:   ", i*16);
		for(int j = 0; j < 16; j++)
			fprintf(file, "%02x ", packet[i*16+j]);
		fprintf(file, "\t");
		for(int k = 0; k < 16; k++)
			if(isprint(packet[16*i+k]))
				fprintf(file, "%c ", packet[16*i+k]);
			else
				fprintf(file, ". ");
		fprintf(file, "\n");
	}
	fprintf(file, "%04x:   ", i*16);
	int l = i*16;
	for(;l<packet_len;l++)
		fprintf(file, "%02x ", packet[l]);
	l = i*16;
	for(int j = 0; j < (i+1)*16 - packet_len; j++)
		fprintf(file, "   ");
	fprintf(file, "\t");
	for(;l<packet_len;l++)
		if(isprint(packet[l]))
			fprintf(file, "%c ", packet[l]);
		else
			fprintf(file, ". ");
	fprintf(file, "\n\n\n");
	fclose(file);
}
//将十六进制字符串转成整型数值
uint64_t htoi(char s[])  
{  
    int i;  
    uint64_t n = 0;  
    if (s[0] == '0' && (s[1]=='x' || s[1]=='X'))  
    {  
        i = 2;  
    }  
    else  
    {  
        i = 0;  
    }  
    for (; (s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'z') || (s[i] >='A' && s[i] <= 'Z');++i)  
    {  
        if (tolower(s[i]) > '9')  
        {  
            n = 16 * n + (10 + tolower(s[i]) - 'a');  
        }  
        else  
        {  
            n = 16 * n + (tolower(s[i]) - '0');  
        }  
    }  
    return n;  
}
