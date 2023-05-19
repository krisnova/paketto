#include <libpaketto.h>
#include "g711.h"

struct rtp_hdr{
       //unsigned short pt:7,m:1,cc:4,x:1,p:1,version:2;
       unsigned short version:2,p:1,x:1,cc:4,m:1,pt:7;
       unsigned short seq;              /* sequence number */
       unsigned int ts;               /* timestamp */
       unsigned int ssrc;             /* synchronization source */
       //unsigned int csrc[1];          /* optional CSRC list */
}__attribute__ ((packed));

char ok_vomit_you_were_right[] = {0x80, 0x00};
/*char wav_head[] = { 0x49, 0x52, 0x46, 0x46, 0x00, 0x24, 0x00, 0x00,
                  0x41, 0x57, 0x45, 0x56, 0x6d, 0x66, 0x20, 0x74,
                  0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
                  0x1f, 0x40, 0x00, 0x00, 0x3e, 0x80, 0x00, 0x00,
                  0x00, 0x02, 0x00, 0x10, 0x61, 0x64, 0x61, 0x74,
                  0xff, 0xff};*/

char wav_head[] = {0x52, 0x49, 0x46, 0x46, 0x24, 0x00, 0x00, 0x00,
                   0x57, 0x41, 0x56, 0x45, 0x66, 0x6d, 0x74, 0x20,
                   0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
                   0x40, 0x1f, 0x00, 0x00, 0x80, 0x3e, 0x00, 0x00,
                   0x02, 0x00, 0x10, 0x00, 0x64, 0x61, 0x74, 0x61,
                   0xff, 0xff};

struct voip_stream {
   unsigned short sport;
   unsigned short dport;
};



int main (int argc, char **argv)
{

	int i;
	struct link *link;
	struct frame x;
	struct rtp_hdr *rtp;
	char *payload, *udp_p;
	int p_len;
	FILE *wavdump;
	short sample;
	short sbuf[2000];
	struct voip_stream voip;
	int mode=0;


	int count=0;

	setvbuf(stdout, NULL, _IONBF, 0);
	link = pk_link_preinit(NULL);

	if(argv[1]) mode=1;

	snprintf(link->dev, MX_B, "tx0");
	pk_link_init(link);
	pk_fastnet(link->pcap);

	fwrite(wav_head, sizeof(wav_head), 1, stdout);

	while(1){
		if(pk_sniff_getnext(link)>0)
		{
		  pk_parse_layers_from_link (link, &x, 0);
		  if(x.ip && x.udp){
		    if(mode==0) {if(ntohs(x.udp->uh_sport) <= 10000) continue;}
		    if(mode==1) {if(ntohs(x.udp->uh_sport) > 10000) continue;}

		    udp_p = (char *)x.udp + 8;
		    if(!memcmp(ok_vomit_you_were_right, udp_p, 2)) {
			rtp=udp_p;
			count++;
			payload=(char *)rtp + sizeof(struct rtp_hdr);
			p_len = ntohs(x.udp->uh_ulen) - sizeof(struct rtp_hdr) - LIBNET_UDP_H;
			fprintf(stderr, "%i: %i %i\n", htons(x.udp->uh_sport), payload, p_len);
			for(i=0;i<=p_len;i++){
			   sbuf[i]=ulaw2linear(*(payload+i));
			}
			fwrite(sbuf, 2, p_len, stdout);
		    }
		  }
		}
	}
}

int pk_print_rtp(struct rtp_hdr *rtp)
{
	fprintf(stderr, "v=%u p=%u x=%u cc=%u m=%u pt=%u seq=%u ts=%u\n",
		rtp->version,
		rtp->p,
		rtp->x,
		rtp->cc,
		rtp->m,
		rtp->pt,
		ntohs(rtp->seq),
		ntohl(rtp->ts),
		ntohl(rtp->ssrc));
}
