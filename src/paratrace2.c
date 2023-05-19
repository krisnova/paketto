#include <libpaketto.h>

struct pt_batch {
   struct link *link;
   struct frame *pt;
};

void pk_pt_usage();
void pk_pt_spew(struct pt_batch *pt_batch);

int main(int argc, char **argv)
{
   int opt;
   extern char *optarg;
   extern int   opterr;

   pthread_t p_spew;

   struct pt_batch pt_batch;
   struct pk_sr_conf *sr_conf;

   int i,j,seeking;

   struct timeval now, then, diff;

   struct frame *pt;  // prototype
   struct frame ic;  // parsed icmp header

   struct link *link;

   sr_conf = pk_sr_conf_init(NULL);


   if(!argv[1]) pk_pt_usage();

   link = pk_link_preinit(NULL);

   snprintf(link->pfprogram, sizeof(link->pfprogram), "icmp or (src host %s)", argv[1]);
   pk_link_init(link);

   seeking=1;
   while(seeking){
      i=pk_sniff_getnext(link);
      if(i && link->x.tcp) seeking=0;
   }

   /* Before, we modified an existing packet.  Now, we synthesize one
    * to spec.  This is safer for all sorts of reasons. */
   pt = pk_build_generic_syn(NULL);
   pt->ip->ip_src = link->x.ip->ip_dst;
   pt->ip->ip_dst = link->x.ip->ip_src;
   pt->ip->ip_ttl = link->x.ip->ip_ttl;
   pt->tcp->th_sport = link->x.tcp->th_dport;
   pt->tcp->th_dport = link->x.tcp->th_sport;
   pt->tcp->th_flags = TH_ACK;

   pt_batch.link = link;
   pt_batch.pt = pt;

   pthread_create(&p_spew, NULL, (void *)pk_pt_spew, &pt_batch);

   gettimeofday(&then, NULL);
   diff.tv_sec=0;
   while(diff.tv_sec < 5)
   {
      i=pk_sniff_getnext(link);

      if(i) pk_sr_report(sr_conf, &link->pkthdr, link->packet);

      gettimeofday(&now, NULL);
      pk_timeval_subtract(&diff, &now, &then);
      i=0;
   }
}


void pk_pt_spew(struct pt_batch *pt_batch)
{
   int i, hops;

   hops = pk_estimate_hopcount(pt_batch->pt->ip->ip_ttl);
   hops+=5;
   for(i=0;i<hops;i++)
   {
      pt_batch->pt->ip->ip_ttl = i;
      pt_batch->pt->ip->ip_id =  htons(i*256);

      pk_spoof_framed(pt_batch->link, 3, pt_batch->pt);
      usleep(50000);
   }
}

void pk_pt_usage()
{
   fprintf(stdout, "paratrace2 host\n");
   fprintf(stdout, "Traceroute over an extant TCP session to the named host.\n");
   fprintf(stdout, "Demo using new PK2 architecture.\n");
   exit(1);
}
