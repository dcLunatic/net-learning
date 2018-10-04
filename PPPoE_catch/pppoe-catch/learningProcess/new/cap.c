#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<ctype.h>
#include"cap.h"

char errbuf[PCAP_ERRBUF_SIZE];


void err(int ret){
	fprintf(stderr, "%s\n", errbuf);
	exit(ret);
}
int addr_ntoa(int i_addr, char* str_addr){
	if(str_addr == NULL)
		return -1;
	struct in_addr addr;
	addr.s_addr = i_addr;
	char* tmp = inet_ntoa(addr);
	strcpy(str_addr, tmp);
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
char* get_pack_ethernettype(u_short ether_type){
	for(int i = 0; i < ETHER_TYPE_COUNT; i++){
		if(ether_type == ethertypes[i].value){
			return ethertypes[i].statement;
		}
	}
	return NULL;
}
void print_packet_ether_header(const u_char* packet, int packet_len){
	puts("------------------------Ethernet MAC Frame Headers-------------------");
	struct sniff_ethernet* ethernet	= (struct sniff_ethernet*)packet;
	printf("Ethernet MAC length: %d\n", packet_len);
	printf("Destination MAC: ");
	for(int i = 0; i < ETHER_ADDR_LEN; i++){
		printf("%02x", ethernet->ether_dhost[i]);
		if(i+1 < ETHER_ADDR_LEN)
			printf(":");
	}
	printf("\nSource MAC: ");
	for(int i = 0; i < ETHER_ADDR_LEN; i++){
		printf("%02x", ethernet->ether_shost[i]);
		if(i+1 < ETHER_ADDR_LEN)
			printf(":");
	}
	//printf("\nType: %02x%02x\n", packet[12], packet[13]);
	printf("\nType: %s\n", get_pack_ethernettype(ethernet->ether_type));

	puts("------------------------------End-----------------------------------");
}
void print_packet_ip_header(const u_char* packet, int packet_len){

	puts("--------------------------IP Datagram headers---------------------");


	puts("------------------------------End-----------------------------------");
}
void print_packet_dns_header(const u_char* packet, int packet_len){


	puts("------------------------------End-----------------------------------");
}
void print_packet_tcp_header(const u_char* packet, int packet_len){

	puts("--------------------------TCP Segment headers---------------------");


	puts("------------------------------End-----------------------------------");
}
void print_packet_udp_header(const u_char* packet, int packet_len){

	puts("--------------------------UDP Segment headers---------------------");

	puts("------------------------------End-----------------------------------");
}
void print_packet_icmp_header(const u_char* packet, int packet_len){

	puts("--------------------------ICMP Segment headers---------------------");


	puts("------------------------------End-----------------------------------");
}
void print_help(){
	puts("\n\n--------------SnifferDemo Usage----------------------\n\n");
	puts("-f	--filter,	后面跟上过滤规则");
	puts("-i	--interface,	指定监听的网卡");
	puts("-q	--quiet,	安静模式，只显示数据包的分析信息");
	puts("-h	--help,		显示此帮助信息");
	puts("\n\n");
}
void send_last(const u_char* packet, int packet_len, u_char* source_mac, pcap_t* handle){

	//等待对端发送Request包，拆包，得到SessionID,得到MagicNumber,得到MRU,等
	//然后封装在一个Request包中，并包含其他信息，发送回去
	//然后发送一个ACK包
	//等待对方发送ACK包
	//然后对方发送一个Echo Request包
	//再发送一个PPP LCP包，内含验证信息
	//此时，得到数据
	//向对方发送一个Echo Reply包
	//发送验证失败（如密码错误）的包
	//结束


	//拆开Request包
	int d_identifier = packet[23];
	int d_mru_offset = 0;
	int d_magic_number_offset = 0;
	for(int i = 26; i < packet_len;){
		if(packet[i] == 0x01){
			d_mru_offset = i;
		}
		else if(packet[i] == 0x05){
			d_magic_number_offset = i;
		}
		if(d_mru_offset && d_magic_number_offset)
			break;
		i += packet[i+1];
	}
	if(!(d_mru_offset || d_magic_number_offset))
		return;

	int length1 = packet[d_mru_offset + 1] + 10 + 4 + 2;
	u_char* configuration_request_packet;
	int alloc_space_len_r = (length1+20)<64?64:length1;
	configuration_request_packet = (u_char*)malloc(alloc_space_len_r);
	//开始封装Configuration Request
	int pos = 0;
	for(int i = 0; i < 6; i++)
		configuration_request_packet[pos++] = packet[6 + i];
	for(int i = 0; i < 6; i++)
		configuration_request_packet[pos++] = source_mac[i];
	u_char some_request_msg1[]={
		0x88,0x64,//Type: PPPoE Session
		0x11,0x00,
		0x00,0x09,//Session ID uniq
		length1/0x100,length1%0x100,
		0xc0,0x21,//PPP LCP
		0x01,	//Configuration Request
		0x99,	//My-Identifier
		(length1-2)/0x100,(length1-2)%0x100
	};
	for(int i = 0; i < 14; i++)
		configuration_request_packet[pos++] = some_request_msg1[i];
	for(int i = 0; i < packet[d_mru_offset + 1]; i++)
		configuration_request_packet[pos++] = packet[i + d_mru_offset];

	u_char some_request_msg2[]={
		0x03,0x04,
		0xc0,0x23,//Authentication Protocol
		0x05,0x06,
		0x12,0x34,0x56,0x78
	};
	for(int i = 0; i < 10; i++)
		configuration_request_packet[pos++] = some_request_msg2[i];
	while(pos < 64)
		configuration_request_packet[pos++] = 0;

	//发送一个Configuration Request
    printf("Send Configuration Request\n");
    pcap_sendpacket(handle, configuration_request_packet, alloc_space_len_r);
    if(!g_is_quiet){
        printf("\n\nSend My Configuration Request\n");
        print_packet_ether_header(configuration_request_packet, alloc_space_len_r);
        print_packet_content(configuration_request_packet, alloc_space_len_r);
    }
	free(configuration_request_packet);

	//构造一个ACK包
	/*pos=0;
	int length2 = packet[18] * 0x100 + packet[19];
	u_char* configuration_ack_packet;
	int alloc_space_len_a = (length2+20)<64?64:length2;
	configuration_ack_packet = (u_char*)malloc(alloc_space_len_a);
	for(int i = 0; i < 6; i++)
		configuration_ack_packet[pos++] = packet[6 + i];
	for(int i = 0; i < 6; i++)
		configuration_ack_packet[pos++] = source_mac[i];
	u_char some_ack_msg1[]={
		0x88,0x64,//Type: PPPoE Session
		0x11,0x00,
		0x00,0x09,//Session ID uniq
		packet[18],packet[19],
		0xc0,0x21,//PPP LCP
		0x02,	//Configuration Ack
		d_identifier,	//Identifier
		packet[24],packet[25]
	};
	for(int i = 0; i < 14; i++)
		configuration_ack_packet[pos++] = some_ack_msg1[i];
	for(int i = 0; i < packet[d_mru_offset + 1]; i++)
		configuration_ack_packet[pos++] = packet[i + d_mru_offset];
	for(int i = 0; i < packet[d_magic_number_offset + 1]; i++)
		configuration_ack_packet[pos++] = packet[i + d_magic_number_offset];
	while(pos < 64)
		configuration_request_packet[pos++] = 0;
	*/
	u_char* configuration_ack_packet = (u_char*)malloc(packet_len);
	//strncpy(configuration_ack_packet, packet, packet_len);
	for(int i = 0; i < packet_len; i++)
		configuration_ack_packet[i] = packet[i];
	pos=0;
	for(int i = 0; i < 6; i++)
		configuration_ack_packet[pos++] = packet[6 + i];
	for(int i = 0; i < 6; i++)
		configuration_ack_packet[pos++] = source_mac[i];
	configuration_ack_packet[22] = 0x02;
	//发送一个Configuration Ack
    pcap_sendpacket(handle, configuration_ack_packet, packet_len);
    printf("Send Configuration Ack");
    if(!g_is_quiet){
        printf("\n\nSend My Configuration Ack\n");
        print_packet_ether_header(configuration_request_packet, packet_len);
        print_packet_content(configuration_request_packet, packet_len);
    }
	free(configuration_ack_packet);
}
bool is_exist_mac(const u_char* mac){
    for(int i = 0; i < FINISHED; i++){
        bool flag = true;
        for(int j = 0; j < 6; j++){
            if(mac[j] != MAC_POOL[i*6+j]){
                flag = false;
                break;
            }
        }
        if(flag){
/*
            print_mac(mac);
            printf("is _exist_mac inside\nnow the mac pool:\n");
            for(int i = 0; i< FINISHED; i++){
                print_mac(MAC_POOL + i*6);
                printf("\nEnd\n\n");
            }
            */
            return flag;

        }
    }
    return false;
}
void print_mac(const u_char* mac){
    for(int i = 0; i < 6; i++){
        printf("%02x", mac[i]);
        if(i != 5)
            printf(":");
    }
}
void packet_callback(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet){
    u_char source_mac[6];
    //strncpy(source_mac, packet + 6, 6);
    for(int i = 0; i < 6; i++)
        source_mac[i]=packet[6+i];
    if(is_exist_mac(source_mac)){
       // print_mac(source_mac);
       // printf(" is exist.\n");
        return;
    }
	static long count = 0;
    struct sniff_ethernet* ethernet;
    ethernet = (struct sniff_ethernet*)packet;
    if(ethernet->ether_type == 0x6388){//PPPoED
        if(packet[15] == 0x09){
            printf("Receive PADI Packet from: ");
            print_mac(source_mac);
            printf("\n");
            if(!g_is_quiet){
            printf("The packet number: %d\n", ++count);
            print_packet_ether_header(packet, pkthdr->len);
            print_packet_content(packet, pkthdr->len);
            printf("\n\n");
            }
            send_PADO(packet, pkthdr->len, MY_MAC, (pcap_t*)args);
        }
        if(packet[15] == 0x19){
		for(int i = 0; i < 6; i++)
			if(packet[i] != MY_MAC[i])
    				return;
            printf("Receive a PADR Packet from: ");
            print_mac(source_mac);
            printf("\n");
            if(!g_is_quiet){
            printf("The packet number: %d\n", ++count);
            print_packet_ether_header(packet, pkthdr->len);
            print_packet_content(packet, pkthdr->len);
            printf("\n\n");
            }
            send_PADS(packet, pkthdr->len, MY_MAC, (pcap_t*)args);
        }

    }
    else if(ethernet->ether_type == 0x6488){//PPP
    	if(packet[20] == 0xc0 && packet[21] == 0x21){//LCP
    		if(packet[22] == 0x01){//Configuration Request
    			for(int i = 0; i < 6; i++)
    				if(packet[i] != MY_MAC[i])
    					return;
                printf("Receive A Configuration Request from: ");
                print_mac(source_mac);
                printf("\n");
                if(!g_is_quiet){
                    printf("The packet number: %d\n", ++count);
                    print_packet_ether_header(packet, pkthdr->len);
                    print_packet_content(packet, pkthdr->len);
                    printf("\n\n");
                }
                send_last(packet, pkthdr->len, MY_MAC, (pcap_t*)args);
    		}
            if(packet[22] == 0x02){//Configuration Ack
    			for(int i = 0; i < 6; i++)
    				if(packet[i] != MY_MAC[i])
    					return;
                printf("Receive A Configuration ACK from:");
                print_mac(source_mac);
                printf("\n");
                if(!g_is_quiet){
                    printf("The packet number: %d\n", ++count);
                    print_packet_ether_header(packet, pkthdr->len);
                    print_packet_content(packet, pkthdr->len);
                    printf("\n\n");
                }
    		}

    	}
    	if(packet[20] == 0xc0 && packet[21] == 0x23){//PAP
            printf("Receive A PAP Packet from: ");
            print_mac(source_mac);
            printf("\n");
            if(!g_is_quiet){
                printf("----------------------------------------------------------------------------\n");
                print_packet_ether_header(packet, pkthdr->len);
                print_packet_content(packet, pkthdr->len);
                printf("----------------------------------------------------------------------------\n");
            }
            printf("some information of ");
            print_mac(source_mac);
            printf("is like as follow.\n");
            printf("---------------------------------------\n");
            printf("Peer-ID:");
            for(int i = 0; i < packet[26]; i++)
                printf("%c", packet[27 + i]);
            printf("\nPassword:");
            for(int i = 0; i < packet[26 + packet[26] + 1]; i++)
                printf("%c", packet[27+1+packet[26]+i]);
            printf("\n---------------------------------------\n");
            printf("In here should send a nck packet but not do it not.\nif not, they will occured 718 error.\n\n");
            //strncpy(MAC_POOL + FINISHED*6, source_mac, 6);
            for(int i = 0; i < 6; i++){
                MAC_POOL[FINISHED*6+i]=source_mac[i];
            }
            FINISHED++;
            /*printf("Exist mac list:\n");
            for(int i = 0; i< FINISHED; i++){
                print_mac(MAC_POOL + i*6);
                printf("\n");
            }*/
    	}
    }

}
bool get_ppp_tag(const u_char* packet, int packet_len, u_char* tag, int* tag_len, int* tag_offset){
	for(int i = 20; i < packet_len;){
		int my_tag_len = packet[i+2] * 0x100 + packet[i+3];
		if(packet[i] == tag[0] && packet[i+1] == tag[1]){
			*tag_len = my_tag_len;
			*tag_offset = i + 4;
			return true;
		}
		i += 4 + my_tag_len;
	}
	return false;
}
void send_PADO(const u_char* packet, int packet_len, u_char* source_mac, pcap_t* handle){
    u_char* pado_packet;

    char *host_uniq;
    int host_uniq_len;
    int host_uniq_offset;

    //int padi_payload_length = packet[18] * 0x100 + packet[19];
    for(int i = 20; i < packet_len;){
        int len = packet[i+2] * 0x100 + packet[i+3];
        if(packet[i] == 0x01 && packet[i+1] == 0x03){
            //Host-Uniq
            host_uniq_len = len;
            host_uniq_offset = i+4;
            break;

        }


        i += 4 + len;
    }
    int pppoe_len = 4 + 4 + AC_NAME_LEN + 4 + host_uniq_len + 4 + AC_COOKIE_LEN;
    int pado_packet_len = 14 + 6 + pppoe_len;
    int alloc_space_len = pado_packet_len < 64? 64:pado_packet_len;
    pado_packet = (u_char*)malloc(pado_packet_len);
    int pos = 0;
    for(int i = 0; i < 6; i++)
        pado_packet[pos++] = packet[6 + i];
    for(int i = 0; i < 6; i++)
        pado_packet[pos++] = source_mac[i];
    pado_packet[pos++] = 0x88;
    pado_packet[pos++] = 0x63;
    pado_packet[pos++] = 0x11;
    pado_packet[pos++] = 0x07;
    pado_packet[pos++] = 0x00;
    pado_packet[pos++] = 0x00;
    pado_packet[pos++] = pppoe_len / 0x100;
    pado_packet[pos++] = pppoe_len % 0x100;
    u_char service_tlv[]={
       0x01,0x01,0x00,0x00
    };
    for(int i = 0; i < 4; i++)
        pado_packet[pos++] = service_tlv[i];

    u_char ac_name_tl[] = {
        0x01,0x02,AC_NAME_LEN/0x100,AC_NAME_LEN%0x100
    };
    for(int i = 0; i < 4; i++)
        pado_packet[pos++] = ac_name_tl[i];
    for(int i = 0; i < AC_NAME_LEN; i++)
        pado_packet[pos++] = AC_Name[i];
    int h_host_uniq_len = host_uniq_len/0x100;
    int l_host_uniq_len = host_uniq_len%0x100;
    u_char host_uniq_tl[] = {
        0x01,0x03,h_host_uniq_len,l_host_uniq_len
    };
    for(int i = 0; i < 4; i++)
        pado_packet[pos++] = host_uniq_tl[i];
    for(int i = host_uniq_offset; i < host_uniq_offset + host_uniq_len; i++)
        pado_packet[pos++] = packet[i];
    int h_ac_cookie_len = AC_COOKIE_LEN/0x100;
    int l_ac_cookie_len = AC_COOKIE_LEN%0x100;
    u_char ac_cookie_al[]={
        0x01,0x04,h_ac_cookie_len, l_ac_cookie_len
    };
    for(int i = 0; i < 4; i++)
        pado_packet[pos++] = ac_cookie_al[i];
    for(int i = 0; i < AC_COOKIE_LEN; i++)
        pado_packet[pos++] = AC_Cookie[i];
    if(pos < 64)
        pado_packet[pos++] = 0;
    pcap_sendpacket(handle, pado_packet, alloc_space_len);
    if(!g_is_quiet){
        printf("\n\nMy PADO Packet:\n");
        print_packet_ether_header(pado_packet, alloc_space_len);
        print_packet_content(pado_packet, alloc_space_len);
    }
    else
        printf("Send PADO Packet\n");
    free(pado_packet);

}
void send_PADS(const u_char* packet, int packet_len, u_char* source_mac, pcap_t* handle){
	int pads_packet_len = 14;
	u_char* pads_packet;
    /*
	//verify destination mac is equal to MY_MAC
	for(int i = 0; i < 6; i++)
		if(packet[i] != MY_MAC[i])
			return;
	//get the ac_cookie tag information and verify it
	u_char ac_cookie_tag[] = {0x01,0x04};
	int ac_cookie_len;
	int ac_cookie_offset;
	get_ppp_tag(packet, packet_len, ac_cookie_tag, &ac_cookie_len, &ac_cookie_offset);
	if(ac_cookie_len != AC_COOKIE_LEN)
		return;
	for(int i = 0; i < AC_COOKIE_LEN; i++)
		if(packet[i+ac_cookie_offset] != AC_Cookie[i])
			return;
    */
	//get the host_uniq tag information
	u_char host_uniq_tag[] = {0x01,0x03};
	int host_uniq_len;
	int host_uniq_offset;
	get_ppp_tag(packet, packet_len, host_uniq_tag, &host_uniq_len, &host_uniq_offset);

	int pppoe_len = 4 + 4 + host_uniq_len;
	pads_packet_len = 14 + 6 + pppoe_len;
	int alloc_space_len = pads_packet_len < 64? 64:pads_packet_len;
	pads_packet = (u_char*)malloc(alloc_space_len);
    int pos = 0;
    for(int i = 0; i < 6; i++)
		pads_packet[pos++] = packet[6 + i];
  	for(int i = 0; i < 6; i++)
		pads_packet[pos++] = source_mac[i];
	u_char some_pads_msg[]={
		0x88,0x63,//pppoe type
		0x11,0x65,
		0x00,0x09,//session id, should be uniq, but here is not
		pppoe_len/0x100,pppoe_len%0x100,//pppoe_len
		0x01,0x01,0x00,0x00,//service_tlv
		0x01,0x03,host_uniq_len/0x100,host_uniq_len%0x100//host_uniq_tl
	};
	for(int i = 0; i < 16; i++)
		pads_packet[pos++] = some_pads_msg[i];
	for(int i = 0; i < host_uniq_len; i++)
		pads_packet[pos++] = packet[i+host_uniq_offset];
	while(pos < alloc_space_len){
		pads_packet[pos++] = 0;
	}
	pcap_sendpacket(handle, pads_packet, alloc_space_len);
    if(!g_is_quiet){
        printf("\n\nMy PADS Packet:\n");
        print_packet_ether_header(pads_packet, alloc_space_len);
        print_packet_content(pads_packet, alloc_space_len);
    }
    else
        printf("Send PADS Packet\n");
	free(pads_packet);
}
struct sniffer_option* deal_option(int argc, char* argv[]){
	struct sniffer_option* my_option;
	my_option = (sniffer_option*)calloc(1, sizeof(struct sniffer_option));
	opterr=0;
	bool is_count = false;
	int c;
	while((c=getopt_long(argc, argv, short_options, long_options, 0))!=-1){
		switch(c){
			case 'q':my_option->is_quiet=true;break;
			case 'h':my_option->is_help=true;break;
			//case 'f':strcpy(my_option->filter, optarg);break;
			case 'f':my_option->filter=optarg;break;
			//case 'i':strcpy(my_option->interface, optarg);break;
			case 'i':my_option->interface=optarg;break;
			case 'c':is_count=true;my_option->count=atoi(optarg);break;
			case '?':
				if(optopt=='f' || optopt=='i'){
					fprintf(stderr, "Error: option %c must have an argument\n", optopt);

				}
				else{
					fprintf(stderr, "Error: unknown option %c\n", optopt);

				}
				my_option = NULL;
				break;


		}
	}
	if(my_option->is_help){
		print_help();
		exit(0);
	}
	if(my_option->interface == NULL){
		fprintf(stderr, "Error: must specified a device\n");
		return NULL;
	}
	if(is_count && my_option->count < 1){
		fprintf(stderr, "Error: the argument of option c must be a number and greater than 0\n");
		return NULL;
	}
	return my_option;
}
int main(int argc, char** argv){
	struct sniffer_option* my_option;
	my_option = deal_option(argc, argv);
	if(my_option == NULL)
		err(-1);
    g_is_quiet = my_option->is_quiet;

	pcap_t* handle = NULL;
	char* device = NULL;
	bpf_u_int32 net, mask;

	device = pcap_lookupdev(errbuf);
	if(device == NULL){
		err(-2);
	}
	//printf("Opening device %s\n", device);
	strcpy(device, my_option->interface);
	if(pcap_lookupnet(device, &net, &mask, errbuf) == -1){
		err(-2);
	}
	char strnet[16];
	char strmask[16];
	addr_ntoa(net, strnet);
	addr_ntoa(mask, strmask);
	printf("\nMonitoring: %s/ %s/ %s\n\n", device, strnet, strmask);

	handle = pcap_open_live(device, 65535, 1, 1024, errbuf);
	if(handle == NULL)
		err(-2);
	if((pcap_loop(handle, my_option->count, packet_callback, (u_char*)handle)) < 0)
		err(-2);

	return(0);
}
