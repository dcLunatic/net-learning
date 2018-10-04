#include <stdio.h>  
#include <sys/types.h>  
#include <unistd.h>  
#include <signal.h>  
#include <sys/param.h>  
#include <sys/stat.h>  
#include <time.h>  
#include <syslog.h>  
#include <stdlib.h>
#include <fcntl.h>
#define LOCKMODE (S_IRWXU | S_IRWXG | S_IRWXO)	/* 创建掩码 */
char lockFile[] = "/var/run/test.pid";
struct flock fl;
int g_pid;
int lockfd;
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
  
    //改变工作目录，使得进程不与任何文件系统联系  
    chdir("/");  
  
    //将文件当时创建屏蔽字设置为0  
    umask(0);  
  
    //忽略SIGCHLD信号  
    signal(SIGCHLD,SIG_IGN);   
      
    return 0;  
}  
  
int main(int argc, char* argv[])   
{   
	lockfd = open (lockFile, O_RDWR|O_CREAT, LOCKMODE);
	if (lockfd < 0) {
		fprintf(stderr, "!! 打开锁文件失败");
		return -1;
	}
	fl.l_start = 0;
	fl.l_whence = SEEK_SET;
	fl.l_len = 0;
	fl.l_type = F_WRLCK;
	if (fcntl(lockfd, F_GETLK, &fl) < 0) {
		fprintf(stderr, "!! 获取文件锁失败");
		return -1;
	}
    printf("Status: %d\nF_UNLCK: %d F_WRLCK: %d\n", fl.l_type, F_UNLCK, F_WRLCK);
    if(fl.l_type != F_UNLCK){
        fprintf(stdout, "发送结束信号给进程(PID=%d).\n", fl.l_pid);
        if(kill(fl.l_pid, SIGINT) == -1){
            fprintf(stderr, "结束进程失败\n");
            return -1;
        }
        else{
            fprintf(stdout, "结束进程成功\n");   
            return 0;
        }
    }
	
	init_daemon();
	fl.l_type = 1;
	fl.l_pid = getpid();
	int result = fcntl(lockfd, F_SETLKW, &fl);
	printf("result:%d\n", result);
	if (result < 0) {
		return -1;
	}
    fcntl(lockfd, F_GETLK, &fl);
    printf("STATUS:%d\n", fl.l_type);
    time_t now;  
    
    while(1) {
		FILE *file = fopen("/var/log/ruijie-beat.log", "a+");   
        sleep(8);  
        time(&now);   
        fprintf(file,"SystemTime: \t%s\t\t\n",ctime(&now));
		fclose(file);
    }   
} 
