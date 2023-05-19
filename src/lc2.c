#include <libpaketto.h>
#include <pthread.h>

int pk_lc_sniff(struct link *link);
int pk_lc_spoof(struct link *link);

int debug=0;

int main(int argc, char **argv)
{

   int i;
   struct link *sniff_link;
   struct link *spoof_link;


   pthread_t p_sniff;
   pthread_t p_spoof;

   //setvbuf(stdin, NULL, _IONBF, 0);
   //setvbuf(stdout, NULL, _IONBF, 0);



   int opt;
   extern char *optarg;
   extern int   opterr;

   int sniff=0;
   int spoof=0;

   sniff_link = pk_link_preinit(NULL);
   spoof_link = pk_link_preinit(NULL);

   snprintf(spoof_link->dev, MX_B, "any");

   while ((opt = getopt(argc, argv, "p:P:l:m:v")) != EOF){
      switch(opt){
         case 'p':
	    snprintf(sniff_link->pfprogram, sizeof(sniff_link->pfprogram), optarg);
	    break;
         case 'P':
	    snprintf(spoof_link->pfprogram, sizeof(spoof_link->pfprogram), optarg);
	    break;
	 case 'l':
	    sniff++;
	    if(!strncmp(optarg, "00", 3)){
		snprintf(sniff_link->dev, sizeof(sniff_link->dev), "%s", pcap_lookupdev(sniff_link->error));
	   } else {
		snprintf(sniff_link->dev, sizeof(sniff_link->dev), "%s", optarg);
	   }
	    break;
	 case 'm':
	    spoof++;
	    if(!strncmp(optarg, "00", 3)){
		snprintf(spoof_link->dev, sizeof(spoof_link->dev), "%s", pcap_lookupdev(spoof_link->error));
	   } else {
		snprintf(spoof_link->dev, sizeof(spoof_link->dev), "%s", optarg);
	   }
	    break;
	 case 'v':
	    debug++;
	 }
   }

   if(sniff) pthread_create(&p_sniff, NULL, (void *)pk_lc_sniff, sniff_link);
   if(spoof) pthread_create(&p_spoof, NULL, (void *)pk_lc_spoof, spoof_link);

   while(1) sleep(100000);
}


int pk_lc_sniff(struct link *link)
{
   int i;
   while(1){
      i=pk_sniff_getnext(link);
      if(i>0) pk_hexdump(stdout, link->pkthdr.caplen, link->packet);
      if(i>0 && debug) pk_hexdump(stderr, link->pkthdr.caplen, link->packet);
      fflush(stdout);
   }
}



int pk_lc_spoof(struct link *link)
{
   int i,j;
   char buf[MX_B], pbuf[MX_B];
   while(pk_fgets(buf, sizeof(buf), stdin)){
	i=0;
	j=0;
	while(buf[i]==' '  && i<sizeof(buf))i++;
	while(i<sizeof(buf) &&
	pk_is_hex(buf[i]) &&
	pk_is_hex(buf[i+1])){
		pbuf[j]=pk_htoc(buf[i], buf[i+1]);
		i+=2;
		j++;
		while(buf[i]==' ' && i<sizeof(buf)){
			i++;
		}
	}
	if(j) i=pk_spoof_raw(link, 2, pbuf, j);
	if(j>0 && debug) {
	   fprintf(stdout, "SENT %i bytes (%s):\n", i, link->error);
	   pk_hexdump(stderr, i, pbuf);
	}
   }
   exit(0);
}
