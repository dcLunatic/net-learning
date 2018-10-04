#include<pcap.h>
#include<netinet/in.h>
#include<getopt.h>
#include <fcntl.h>
#define ETHER_ADDR_LEN    6
#define UP    1
#define DOWN    0
#define LOCKMODE (S_IRWXU | S_IRWXG | S_IRWXO)	//锁文件掩码
static const char lockFile[] = "/var/run/ruijie-beat.lock";//锁文件
static const char logFile[] = "/var/log/ruijie-beat.log";//日志文件(后台模式下会用到)
static u_char *successPacket;			//Success包
int lockfd;					//锁文件值
flock fl;					//锁文件相关信息
static u_int32_t echoKey = 0, echoNo = 0;	//心跳包的特殊值
static u_char sendPacket[0x2D];			//发包
static u_int32_t sendCount = 0;			//本已经发送心跳包的次数
static char* interface = NULL;			//参数指定的网卡名称
static bool bIsHelp = false;			//是否打印帮助信息
static bool bIsWindows = false;			//锐捷是否工作在windows环境下
char errbuf[PCAP_ERRBUF_SIZE];			//pcap错误缓冲区
static pcap_t* gHandle = 0;		    	//全局句柄
static bool bIsStart = false;			//是否开始模拟发送心跳包了
static bool bCapture = false;			//是否已经捕获了认证成功相关信息
static bool bIsBackground = false;		//是否后台运行
static bool bIsDebug = false;			//是否输出调试信息
static bool bIsUpdateMac = false;		//是否修改网卡MAC
static int echoInterval = 30;			//心跳间隔
static bool bIsAuto = true;			    //是否自动获取echoKey echoNo
u_char localMAC[6], destMAC[6], orignMAC[6];	//本机mac，目的mac, 本机源mac
/*long option*/
option long_options[]={
	{"interface", 1, 0, 'i'},
	{"help", 0, 0, 'h'},
	{"windows", 0, 0, 'w'},
	{"background", 0, 0, 'b'},
	{"echointerval", 1, 0, 'e'},
	{"updatemac", 0, 0, 'u'},
	{"debug", 0, 0, 'd'},
	{"echokey", 1, 0, 'k'},
	{"echono", 1, 0, 'n'},
	{"remotemac", 1, 0, 'r'},
	{"sourcemac", 1, 0, 's'}
};
/*short option*/
const char* short_options="i:e:hwbudk:n:r:s:";
bool dealOption(int argc, char* argv[]);	//处理命令行参数
void err(int ret);				//err退出函数
int macAddrSet(uint8_t* mac, char* dev);	//设置指定网卡的mac
int macAddrGet(uint8_t* mac, char* dev);	//获取指定网卡的mac
int if_updown(char *ifname, int flag);		//设置指定网卡的开启或者关闭
void getEchoKey(const u_char *capBuf);		//拿认证成功的success包计算出来的,计算锐捷心跳包参数
static u_char encode(u_char base);		//锐捷算法，颠倒一个字节的8位
static void fillEtherAddr(u_int32_t protocol);	//填充以太网帧
void fillEchoPacket(u_char *echoBuf);		//填充心跳包
static void pcap_handle(u_char *user, const struct pcap_pkthdr *h, const u_char *buf);	//回调函数
static void sig_handle(int sig);		//信号处理函数
void printHelp();				//输出帮助
void printMAC(uint8_t* mac);			//输出MAC
void setFackMac(char* dev);			//设置指定网卡的mac，以及一些相关操作
static int sendEchoPacket();			//发送心跳包
int init_daemon();				//初始化，使程序后台运行
int check_running();				//检查是否后台运行，如果后台，杀死，成功返回0，其他返回非0
int lock();					//对锁文件进行加锁
void print_packet_content(const u_char* packet, int packet_len);//打印包的内容
void fprint_packet_content(const u_char* packet, int packet_len);//打印包的内容
uint64_t htoi(char s[]);				//将十六进制字符串转成整型数值
