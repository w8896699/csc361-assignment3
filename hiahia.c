
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#include <pcap.h>

//#include <sys/socket.h>
//#include <netinet/in.h>
#include <arpa/inet.h>


#define MAX_HOPS 20  
#define MAX_STR_LEN 4096               /* maximum string length */
#define MAX_NUM_CONNECTION 1000
struct outgoing{
int ip_id;
int fragments;
int offset;
int srcport;
int dstport;
int sequence;

};
struct UDP_hdr {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* datagram length */
	u_short	uh_sum;			/* datagram checksum */
};
struct icmphdr
{
  u_int8_t type;		/* message type */
  u_int8_t code;		/* type sub-code */
  u_int16_t checksum;
  union
  {
    struct
    {
      u_int16_t	id;
      u_int16_t	sequence;
    } echo;			/* echo datagram */
    u_int32_t	gateway;	/* gateway address */
    struct
    {
      u_int16_t	__unused;
      u_int16_t	mtu;
    } frag;			/* path mtu discovery */
  } un;
};
struct router{
	char ip_src[20];  /*source ip*/ 
        char ip_dst[20];  /*destination ip*/ 
        int port_src;      /*source port number*/ 
        int port_dst;      /*destination port number*/ 
        int thflags;
        int ttl;
        int ip_p;
        int type;
        int code;
        int ip_off;
        int ip_id;
        int ip_len;
        int seq;
        int syn_count;          /*flag count*/ 
	int fin_count; 
	int rst_count; 
	struct timeval starting_time; 
	struct timeval ending_time; 
        double duration; 
	int num_packet_src;     /*number of packets sent out by source*/ 
	int num_packet_dst;     /*number of packets sent out by destination*/ 
	int num_total_packets; 
        int cur_data_len;
	int cur_data_len_src;  
	int cur_data_len_dst; 
	int cur_total_data_len; 
        double max_win_size;  /*max window size*/ 
       // uint16_t 
        double min_win_size;  /*min window size*/ 
        double sum_win_size; 
	int is_set; 
} ;	
struct outgoing record[2048];

int protocols [3];
int os;
int k =0;
int h=0;
int ttl=0;
int founded=0;
int numbercount=0;
//char *routenumber[1024];
struct routernumber{
	char routenumber[1024];
};
struct router con [MAX_HOPS];

struct routernumber routerip[1024];

void add_protocol(int protocols[MAX_STR_LEN], int protocol){
	
	int p=0;
	int check=0;		//printf("dst is: %s\n", con[0].ip_dst);
	
		if(h==0){
				protocols[h]=protocol;
				//printf("protocol is:%d\n",protocols[h]);
				h++;
				
			}else if(k>0){

			for(p=0;p<h;p++){
				
				if(protocol==protocols[p]){
					//printf("we r same\n");
					check=1;
				}
			}
				if(check==0){
				//printf("k now is : %d\n",k);
				protocols[h]=protocol;
				//printf("protocol is:%d\n",protocols[h]);
				h++;
				
				}		
			}
	}
			
			
	

void add_to_list(struct router con [MAX_HOPS],struct ip* ip){
	int i=0;
	int check=0;
	char *src= inet_ntoa(ip->ip_src);
//	struct UDP_hdr *udp;
	struct ip *temp;
		//printf("dst is: %s\n", con[0].ip_dst);
	
		if(k==0){
				strcpy(routerip[k].routenumber,src);
				k++;
				//printf("route11 %d: %s\n",k-1, routerip[k-1].routenumber);
			}else if(k>0){

			for(i=0;i<k;i++){
				
				if(strcmp(src,routerip[i].routenumber)==0){
				//	printf("we r happy\n");
					check=1;
				}
				//printf("we r different\n");
			}
				if(check==0){
				//printf("k now is : %d\n",k);
				strcpy(routerip[k].routenumber,src);
				//try to jump to udp hdr
				
				//packet+=sizeof(struct icmphdr);
				//temp=(struct ip*)packet;
				k++;
				//printf("route %d: %s\n",k-1, routerip[k-1].routenumber);
			}		
			
			
			
		}			
}
		//}printf("route %d: %s\n",k, routenumber[k]);k++;
	

int dump_packet(const unsigned  char *packet, unsigned int capture_len,struct router con[MAX_HOPS], int protocols[MAX_STR_LEN],struct timeval ts, struct router times[MAX_HOPS],struct pcap_pkthdr header)  {
	struct ip* ip;
	unsigned int IP_header_len;
	//printf("hahahacheck`7");
	// Skip Ethernet  header
	packet += sizeof(struct ether_header);
	capture_len-= sizeof(struct ether_header);
	// Copy data to IP struct
	 ip = (struct ip*)  packet;
	IP_header_len = ip->ip_hl* 4;
	// Skip IP header
	packet += IP_header_len;
	capture_len-= IP_header_len;
	//printf("hahahacheck`2\n");
	// Analyze  contents of packet
	if  (analyze_packet(ip,  packet, con,  protocols, ts, times))  {
		return  1;
	}
		return  0;
}
int analyze_packet(struct ip* ip, const unsigned  char *packet,struct router con [MAX_HOPS], int protocols[MAX_STR_LEN],struct timeval ts, struct router  times[MAX_HOPS],struct pcap_pkthdr header) {
	struct icmphdr *icmp;
	char * firstdst;  
        char * firstsrc; 
	uint16_t  port;
	int mua,i=0;
	unsigned  short temp, id,  offset;
	int mf,first_id,ult_dst,src;
	int fragments,last_frag;
	///////////jugement
if(ip->ip_p == 1&&ip->ip_ttl==  1){

os=1;
}
if(ip->ip_p == 17&&ip->ip_ttl==  1){
ttl++;
os=2;
}
	temp = ip->ip_id;
	id  = (temp>>8)  | (temp<<8);
/////////////////////////////////////////////////////////////////////////////2 linumix
//if(os==2){
	// Packet is  ICMP///////////////////////////////
	if  (ip->ip_p == 1){
//printf("hahahacheck`9\n");
	 	icmp= (struct icmphdr*)  packet;
	// Add protocol
	add_protocol(protocols,  1);
	// Packe t time d out
	if (icmp->type==11) {
	// Add inter mediate  router to list
		add_to_list(con,ip);
	// First packet sent in trace  route
	} else if ( (icmp->type == 8) && (ip->ip_ttl==  1) && (first_id==  0) ){
	// Set source and ultimate  destination addresses
	//printf("hahahacheck`3");
	founded=1;
		strcpy(con[i].ip_src,inet_ntoa(ip->ip_src));
                strcpy(con[i].ip_dst,inet_ntoa(ip->ip_dst));
		ult_dst= ip->ip_dst.s_addr;
		src= ip->ip_src.s_addr;
	// Record time packet was  sent
	//add_time(ip,  id, ts, times);
	// Se t ID of firs t packe t
	temp = ip->ip_id;
	first_id= (temp>>8) | (temp<<8);
	// Ge t MF flag value
	mf = (ip->ip_off& 0x0020)  >> 5;
	// If  MF  is set, increment  total  number  of fragments
	if (mf  == 1)  {
		fragments++;
	}
	// Packet is a fragment  of  the first packet  sent in traceroute
	} else if  ( (first_id== id) ) {
	// Get  MF  flag value
		mf  = (ip->ip_off& 0x0020)  >>  5;// Increment  total  number  of  fragments
		fragments++;
	// Get  offset value
	temp = ip->ip_off& 0xFF1F;
	offset = (temp>>8)  | (temp<<8);
	// Calculate  value  of offset  if there  are no more  fragments
	if (mf  == 0)  {
		last_frag= offset * 8;
	}
	// Record  time packet  was  sent
	//add_time(ip,  id, ts, times);
	// Packet is outgoing,  record  time sent
	} else if  (icmp->type  ==  8) {
	// Record  time packet  was  sent
	//add_time(ip,  id, ts, times);
	// Packet signifies that the  destination  has been  reached
	} else if  ( (icmp->type  ==  0) ||  (icmp->type  == 3) ) {
	add_to_list(con, ip);
	// list_index--;
	return 1;
	}
}else if  (ip->ip_p == 17){//UDP.................../////////////////////////////////
	 
		add_protocol(protocols,  17);
		//printf("hahahacheck`31\n");
		if(ip->ip_ttl== 1&&founded!=1){
ttl++;
			//printf("hahahacheck`32\n");
			founded=1;

			strcpy(con[i].ip_src,inet_ntoa(ip->ip_src));
			//firstsrc=inet_ntoa(ip->ip_src);
		        strcpy(con[i].ip_dst,inet_ntoa(ip->ip_dst));
			//firstdst=inet_ntoa(ip->ip_src);
		        con[i].ttl=ip->ip_ttl;
		        con[i].ip_p=ip->ip_p;
		        con[i].ip_id=ntohs(ip->ip_id);
		        con[i].ip_len=ntohs(ip->ip_len);
		        con[i].starting_time=header.ts;
			
			
	
	}
}
	if (founded == 1 && !strcmp(inet_ntoa(ip->ip_src), con[i].ip_src)) {
        int a, check;
        check = 1;
	//printf("reached here2\n");
        for (a = 0;a < numbercount;a++) {
            if (record[a].ip_id == ip->ip_id) {
		//printf("hahahacheck`35\n");
                record[a].fragments++;
		    temp = ip->ip_off & 0xFF1F;
     		   offset = (temp>>8)  | (temp<<8);
		record[a].offset=offset*8;
                check = 0;
                break;
            } 
        }
        if (check) {
//printf("hahahacheck`36\n");
            	record[numbercount].ip_id = ip->ip_id;
                record[numbercount].fragments = 1;
		//printf("reached here1\n");
		/*if(os=2){
			record[numbercount].srcport=ip->ip_src;
			record[numbercount].dstport=ip->ip_dst;
		}*/
          	 numbercount++;
           
        }

    }
	
//printf("number fo count: %d\n", numbercount);
return 0;
}
int main(int argc, char *argv[]){

//printf("hahahacheck`5");
	pcap_t *pcap;
	const u_char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	int protocols  [MAX_STR_LEN];
	int mua;
	struct router times [MAX_HOPS];
	
	//printf("%d\n",argc);
	if ( argc != 2 )
		{
		printf("Usage:  <trace_file>\n");
		exit(1);
		}
	pcap = pcap_open_offline(argv[1], errbuf);
		if (pcap == NULL)
		{
		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
		exit(1);
		}
	/* Now just loop through extracting packets as long as we have
	 * some to read.
	 */
//printf("hahahacheck`4");
	while ((packet = pcap_next(pcap, &header)) != NULL){
		if (dump_packet(packet,header.caplen,  con,  protocols, header.ts,times,header)) {
		
		break;
	}
		
	}
	int i=0;
	printf("The IP address of the source node: %s\n",con[i].ip_src);
       printf("The IP address of ultimate destination node: %s\n",con[i].ip_dst);   
       printf("The IP addresses of the intermediate destination nodes:\n"); 
       int m,n,l=0;
       for(n=0;n<k-1;n++){
     
      		 printf("	router%d: %s\n",n+1,routerip[n].routenumber);
        }
	printf("\nThe values in the protocol field of IP headers:\n");
	//for(l=0;l<3;l++){
	//printf("protocols are: %d\n",protocols[l]);
	//	}
	//for(l=0;l<3;l++){
		if(os==1){
		        printf("	1: ICMP\n");
        	}
	//}
       // for(n=0;n<3;n++){
	         if(os==2) {
		 printf("	1: ICMP\n");
       		 printf("	17: UDP\n");
        	}
	printf("number of count: %d\n", numbercount);
	for(mua=0;mua<numbercount;mua++){
		printf("\nThe number of fragments created from the original datagram D%d is: %d\n",mua+1,record[mua].fragments);
		printf("The offset of the last fragment is: %d\n\n",record[mua].offset);
	}
	//printf("ttl: %d\n", ttl);
	return 0;
	}

