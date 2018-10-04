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
//just to cacl echoNo and echoKey using
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

int main(){
	int x = 0xb1;
	for(int i = 0; i < 50; i++){
		printf("%02x\n", encode(x+i));
	}
	printf("Input something to test.\n");
	int input;
	while(1){
		printf("0x");
		scanf("%x", &input);
		input = encode(input);
		printf("    0x%2x\n", input);
	}
	return 0;

}
