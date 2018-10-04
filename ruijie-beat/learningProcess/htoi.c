#include <unistd.h> 
#include <signal.h> 
#include <sys/param.h> 
#include <sys/types.h> 
#include <sys/stat.h> 
#include <stdlib.h>
#include<stdio.h>
#include<ctype.h>
int myhtoi(char s[])  
{  
    int i;  
    int n = 0;  
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
int main(){

	int value = myhtoi("0x141B");
	printf("value = %d\n", value);





}
