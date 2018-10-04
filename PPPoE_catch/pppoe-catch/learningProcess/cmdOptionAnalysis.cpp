#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<getopt.h>


/*
int main(int argc, char* argv[]){
	int opt = 0;
	int a = 0;
	int b = 0;
	char s[50];
	while((opt=getopt(argc, argv, "ab:\n"))!=-1){
		switch(opt){
			case 'a':a=1;break;
			case 'b':b=1;strcpy(s, optarg);break;
			default:printf("Error: unknown option(-%s)\n", opt);return -1;
		}
	}
	if(a)
		printf("option a\n\n");
	if(b)
		printf("option b:%s\n", s);
	return 0;
}
*/
static char filterContent[256] = {0};
static const char* short_options="hf:q";
static const option long_options[]={
	{"help", 0, 0, 'h'},
	{"filter", 1, 0, 'f'},
	{"quiet", 2, 0, 'q'},
};
int main(int argc, char* argv[]){

	opterr=0;
	int c;
	while((c=getopt_long(argc, argv, short_options, long_options, 0))!=-1){
		switch(c){
			case 'q':
				printf("quiet\n");
				break;
			case 'h':
				printf("help\n");
				break;
			case 'f':
				printf("filter:%s\n", optarg);
				break;
			case '?':
				if(optopt=='f')
					printf("Error: option f must have an argument\n");
				else{
					printf("Unknow option:%c%s\n", optopt, optstring);
					return -1;
				}
		}
	}	
	return 0;
}
