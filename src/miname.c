#include <libpaketto.h>

struct pk_mm_listener
{
   struct link *link;
   int cookie;
   int mismatch_only;
   int sql;
};

void pk_mm_usage(void);
void pk_mm_sniff(struct pk_mm_listener *listen);

struct pk_mm_info
{
   struct in_addr psrc,src,dst;
   struct timeval stamp;
   char padding;
}__attribute__ ((packed));

/*int pk_break_ip(struct inaddr ip, char &a, char &b, char &c, char &d)
{
	char *ex;

	int foo = ntohl(ip.s_addr);
	ex = &foo;

	*a=ex[0];
	*b=ex[1];
	*c=ex[2];
	*d=ex[3];
	return 1;
}*/


	
	

int main(int argc, char **argv)
{
   int opt;
   extern char *optarg;
   extern int opterr;

   struct frame *dnsq;
   struct link *link;

   struct pk_mm_listener listener;

   struct pk_iterator_ip it_ip;

   pthread_t p_sniff;

   int i,verbose;
   char dest[MX_B];
   char buf[256];
   char name[256];
   char extension[256];

   char forcename[256];
   char type[256];

   long ip;

   int listen=1;
   int send=1;

   int simple;
   struct pk_mm_info info;

   link = pk_link_preinit(NULL);
   dnsq = pk_build_generic_dns(NULL, name, "A");
   snprintf(link->bandwidth, sizeof(link->bandwidth), "20k");
   snprintf(link->pfprogram, sizeof(link->pfprogram), "udp and port 53");

   listener.mismatch_only=0;
   listener.sql=0;

   while ((opt = getopt(argc, argv, "LSd:i:D:Vvb:T:F:sm")) != EOF) {
      switch (opt) {
	case 'L':
	   send=0;
	   break;
	case 'S':
	   listen=0;
	   break;
	case 'V':
	   fprintf(stdout, "miname %s\n", VERSION);
	   exit(1);
	   break;
	case 'd':
	   snprintf(link->dev, MX_B, "%s", optarg);
	   break;
	case 'i':
	   ip = libnet_name_resolve(optarg, 1);
	   dnsq->ip->ip_src.s_addr = ip;
	   break;
	case 'D':
	   snprintf(extension, sizeof(extension), "%s", optarg);
	   break;
	case 'v':
	   verbose++;
	   break;
	case 'b':
	   snprintf(link->bandwidth, MX_B, "%s", optarg);
	   break;
	case 'F':
	   snprintf(forcename, 256, "%s", optarg);
	   break;
	case 'T':
	   snprintf(type, 256, "%s", optarg);
	   break;
        case 's':
	   simple++;
	   break;
	case 'm':
	   listener.mismatch_only=1;
	   break;
	default:
	   pk_mm_usage();
	   break;
     }
   }

   pk_link_init(link);

   pk_lookupdev_ip(link->dev, &ip);
   if(!dnsq->ip->ip_src.s_addr){
     /* lookupdev_ip and name_resolve return different byte orders.*/
     dnsq->ip->ip_src.s_addr = ntohl(ip);
   }
   info.psrc.s_addr = ntohl(ip);

   if(!type[0]) snprintf(type, sizeof(type), "A");

   if(!argv[optind]) pk_mm_usage();
   if(!extension[0] && !forcename[0]) {
      snprintf(forcename, sizeof(forcename), "1.0.0.127.in-addr.arpa");
      snprintf(type, sizeof(type), "PTR");
   }

   pk_iterator_ip_init(&it_ip, argv[optind]);
   listener.link = link;
   listener.cookie = extension[0];
   if(listen && send) pthread_create(&p_sniff, NULL, (void *)pk_mm_sniff, &listener), sleep(1);
   if(listen && !send)pk_mm_sniff(&listener); 
   while(send && pk_iterator_ip_getnext(&it_ip))
   {
      snprintf(dest, sizeof(dest), "%i.%i.%i.%i", it_ip.a, it_ip.b, it_ip.c, it_ip.d);
      if(!forcename[0])
	 if(simple)
            snprintf(name, sizeof(name), "%i-%i-%i-%i.%s", it_ip.a, it_ip.b, it_ip.c, it_ip.d, extension);
	 else {
	    inet_aton(dest, &info.dst);
	    info.src.s_addr = dnsq->ip->ip_src.s_addr;
	    gettimeofday(&info.stamp, NULL);
            to64frombits(buf, &info, sizeof(struct pk_mm_info));
	    snprintf(name, sizeof(name), "%s.%s", buf, extension);
	 }
      else
         snprintf(name, sizeof(name), "%s", forcename);

      pk_build_generic_dns(dnsq, name, type);
      inet_aton(dest, &dnsq->ip->ip_dst);
      dnsq->udp->uh_sport = htons(10053);
      pk_spoof_framed(link, 3, dnsq);
      if(verbose) fprintf(stdout, "%s: %s\n", inet_ntoa(dnsq->ip->ip_dst), name);
   }
   sleep(5);
}

enum {
   PK_MM_INFO_TEXT,
   PK_MM_INFO_SQL
};

void pk_mm_sniff(struct pk_mm_listener *listen)
{
   int i;
   struct frame *x;
   struct tm *ptm;
   char timestring[256];
   long ms;
   struct timeval now, diff;

   char *dnsdata;
   struct pk_mm_info info;

   char ipsrc_buf[256], psrc_buf[256], src_buf[256], dst_buf[256];


   while(1){
    i=pk_sniff_getnext(listen->link);
    if(i>0) {
     x = &listen->link->x;
     if(x->udp && x->udp->uh_ulen > LIBNET_UDP_H + LIBNET_DNS_H)
     {
        (char *)x->dns = (char *)x->udp + LIBNET_UDP_H;
	if(x->dns->num_q && !x->dns->num_answ_rr/* && x->dns->id == htons(DNS_MAGIC)*/)
	{
	   if(listen->cookie){
	    dnsdata = (char *)x->dns + sizeof(struct libnet_dns_hdr);
	   
	    from64tobits(&info, dnsdata+1);
	    if(info.padding) continue;

	    ptm = localtime (&info.stamp.tv_sec);
	    ms  = info.stamp.tv_usec;
	    strftime(timestring, sizeof(timestring), "%Y-%m-%d %H:%M:%S", ptm);

	    pk_timeval_subtract(&diff, &listen->link->pkthdr.ts, &info.stamp);

	    if(!diff.tv_sec < 3 /*!listen->mismatch_only || info.dst.s_addr != x->ip->ip_src.s_addr*/){
	      snprintf(ipsrc_buf, sizeof(ipsrc_buf), "%s", inet_ntoa(x->ip->ip_src));
	      snprintf(psrc_buf, sizeof(psrc_buf), "%s", inet_ntoa(info.psrc));
	      snprintf(src_buf, sizeof(src_buf), "%s", inet_ntoa(info.src));
	      snprintf(dst_buf, sizeof(dst_buf), "%s", inet_ntoa(info.dst));
	      if(!listen->sql) fprintf(stdout, "%s:\t%s / %s -> %s @ %s.%ld (Delta %i.%03is)\n", ipsrc_buf, psrc_buf, src_buf, dst_buf, timestring, ms, diff.tv_sec, diff.tv_usec/1000);
	    }
	   } else fprintf(stdout, "%s\n", inet_ntoa(x->ip->ip_src));
	}
     }
   }
   }
}


void pk_mm_usage(void)
{
   fprintf(stderr, "miname %s: Large Scale DNS Scanner\n", VERSION);
   fprintf(stderr, "Component of:  Paketto Keiretsu %s;    Dan Kaminsky  (dan@doxpara.com)\n", VERSION);
   fprintf(stderr,  "     Example:  miname 1.2.1-254.1-254\n");

   fprintf(stderr, "     Options:  -D:  Extension to scan for (prefaced with IP)\n");
   fprintf(stderr, "               -F:  Site to scan for.\n");
   fprintf(stderr, "                    (Default Target:  PTR for 127.0.0.1)\n");
   fprintf(stderr, "               -b:  Set scan bandwidth, in kbps/mbps/gbps\n");
   fprintf(stderr, "               -T:  Change Type -- A, MX, PTR supported\n");
   fprintf(stderr, "               -v:  Verbose Mode\n");
   fprintf(stderr, "               -V:  Display Version\n");
   fprintf(stderr, "  Addressing:  -d   [device]: Send requests from this L2 hardware device\n");
   fprintf(stderr, "               -i   [source]: Send requests from this L3 IP address\n");
   exit(1);
}
