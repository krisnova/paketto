#include <libpaketto.h>
#define BIOCIMMEDIATE        _IOW('B',112, u_int)

int pk_recalc_checksums(struct frame *x);

int pk_parse_layers_from_link(struct link *link, struct frame *x, int allow_short_tcp)
{
	return pk_parse_layers(link->packet, link->pkthdr.caplen, x, 2, link->datalink, allow_short_tcp);
}

int pk_parse_icmp(struct frame *x, struct frame *ic)
{
	return  pk_parse_layers((char *)&(x->icmp->icmp_data),
		x->caplen-x->l2_offset-(int)x->ip->ip_hl*4-8, /* XXX slight chance of bug */
		ic, 3, DLT_EN10MB , 1); /* 3 because ICMP doesn't clone ether */
}


int pk_parse_layers(char *packet, int length, struct frame *x, int input_layer, int datalink, int allow_short_tcp)
{
   int l2_offset=0;
   int i=0,ok=0;

   x->forcelen = -1;
   /* no support for non-ether datalink yet*/

   /* All structs are defined in
    * /usr/include/libnet/libnet-headers.h
    */

    memset(x, 0, sizeof(struct frame));

   /* Layer 2: libnet_ethernet_hdr structs */
   /* (Side Note:  Did somebody kick me in the head when I wrote
      this section for HPYN2e?  If not, someone should have.)*/
   /* XXX: NO SUPPORT FOR NON ETHERNET INTERFACES, INCLUDING LOCALHOST -- though this is changing */

   if(!packet) return(-4);

   x->eth = NULL;
   if(input_layer != 2 && input_layer != 3) return(-3);
   if(input_layer == 2)
      {
      if(datalink != DLT_EN10MB) return(-2); /* validate is our ethernet */
      if(length < LIBNET_ETH_H) return(-1);  /* validate can be ethernet */

      (char *)x->eth = (char *)packet;
      l2_offset=LIBNET_ETH_H;
      ok += l2_offset;

      /* Layer 2 -> Layer 3 ARP check */
      switch(ntohs(x->eth->ether_type)){
      	case ETHERTYPE_ARP:
   		if(length < LIBNET_ETH_H + LIBNET_ARP_H)
   		   return(0);
      		(char *)x->arp = (char *)x->eth + LIBNET_ETH_H;
      		ok+=LIBNET_ARP_H;
      		return(ok);
      		break;
      	case ETHERTYPE_IP:
      		break; /* we'll deal with this in L3 */
      	default:
   		return(0);
      }
   }
   /* OK, we must be IP at this point, either because L2 liked us or
      because we were passed here by input_layer = 3. */
   if(length < l2_offset + LIBNET_IP_H)  /* Could we be IP? */
      return(0);
   ok+=LIBNET_IP_H;
   if(x->eth) (char *)x->ip  = (char *)x->eth + l2_offset;
   else       (char *)x->ip  = (char *)packet;

   if(x->ip->ip_off != 0 && x->ip->ip_off != ntohs(16384)) return(0);
   if(x->ip->ip_v   != 4) return(0);

   if(length < l2_offset + ntohs(x->ip->ip_len)) /* Not long enough? */
      if(!allow_short_tcp)return(0);
   if(length < l2_offset + (int)x->ip->ip_hl*4)  /* Not enough head? */
      return(0);
   ok+=((int)x->ip->ip_hl*4-LIBNET_IP_H);

   /* Support for IP Options */
   if((int)x->ip->ip_hl*4 != LIBNET_IP_H) (char *)x->ipopt = (char *)x->ip + LIBNET_IP_H;
   /*
    * Layer 4:  libnet_icmp_hdr / libnet_tcp_hdr /
    * libnet_udp_hdr structs
    * XXX I doubt that * 4 works on big endian
    */

      switch(x->ip->ip_p){
   	case IPPROTO_TCP:
	   if(allow_short_tcp)
	   {
	      /* here for ICMP error support.  Basically, ICMP errors contain
	         (if we're lucky) TCP ports and the sequence number -- 8 bytes. */
	      if(length < l2_offset + (int)x->ip->ip_hl*4 + 8)
	         return(0);
	      ok+=8;
	   } else {
	      if(length < l2_offset + (int)x->ip->ip_hl*4 + LIBNET_TCP_H)
	         return(0);
	      ok+=LIBNET_TCP_H;
	   }
   	   (char *)x->tcp = (char *)x->ip + ((int)x->ip->ip_hl*4);
   	   break;
   	case IPPROTO_UDP:
	   if(length < l2_offset + (int)x->ip->ip_hl*4 + LIBNET_UDP_H)
	      return(0);
	   ok+=LIBNET_UDP_H;
   	   (char *)x->udp = (char *)x->ip + ((int)x->ip->ip_hl*4);
   	   break;
   	case IPPROTO_ICMP:
	   if(length < l2_offset + (int)x->ip->ip_hl*4 + 8)
	        return(0);
	   ok+=LIBNET_ICMP_H;
   	   (char *)x->icmp= (char *)x->ip + ((int)x->ip->ip_hl*4);
	   break;
   	default:
	   return(0);
      }
   x->l2_offset = l2_offset;
   x->caplen    = length;
   x->packet	= packet;
   return(ok);
   }


int pk_spoof_raw(struct link *link, int layer, char *packet, int length)
{
	int i;

	if(!link || !packet || length<1) return(0);


	if(layer==2)
	{
		if(!link->dev[0]){
			snprintf(link->error, MX_B, "No device found.\n");
			return(0);
		}
		if(link->l2_spoofer==NULL)
		link->l2_spoofer= libnet_open_link_interface(link->dev, link->error);
		if(!link->l2_spoofer) return(0);

		gettimeofday(&link->bench_pre, NULL);
		i=libnet_write_link_layer(link->l2_spoofer, link->dev, packet, length);
		gettimeofday(&link->bench_post, NULL);

		if(i) link->sleepcount++;
		pk_link_sleep(link);

		return(i);
	} else if (layer == 3) {
		if(link->l3_spoofer==0)
		link->l3_spoofer= libnet_open_raw_sock(IPPROTO_RAW);
		if(link->l3_spoofer==0){
			snprintf(link->error, MX_B, "Unable to open raw socket.\n");
		}

		gettimeofday(&link->bench_pre, NULL);
		i = libnet_write_ip(link->l3_spoofer, packet, length);
		gettimeofday(&link->bench_post, NULL);

		if(i) link->sleepcount++;
		pk_link_sleep(link);

		return(i);
	}
}

void pk_link_sleep(struct link *link)
{
	int i;
	struct timeval diff;

	if(link->packetsleep && link->sleepcount == link->sleepinterval){
	  pk_timeval_subtract(&diff, &link->bench_post, &link->bench_pre);
	  i = (link->packetsleep*link->sleepinterval) - ((diff.tv_sec * 1000000) + diff.tv_usec);
	  if(i>0) usleep(i);
	  link->sleepcount=0;
	}
}


int pk_spoof_framed(struct link *link, int layer, struct frame *x)
{
	int i;

	if(!link || !x) return(0);

	if(link->auto_checksums) pk_recalc_checksums(x);

	if(layer==2){
		i=pk_spoof_raw(link, 2, x->packet, x->caplen);
	} else if (layer==3) {
		if(x->forcelen != -1) i=pk_spoof_raw(link, 3, x->ip, x->forcelen);
		i=pk_spoof_raw(link, 3, x->ip, ntohs(x->ip->ip_len));
	}
	return i;
}


int pk_link_destroy(struct link *link)
{
	if(!link) return(-1);
	if(link->l2_spoofer) libnet_close_link_interface(link->l2_spoofer);
	if(link->l3_spoofer) libnet_close_raw_sock(link->l3_spoofer);
	if(link->pcap) pcap_close(link->pcap);
	if(link->self_malloc) free(link);
	return(0);
}

void pk_memswp(char *a, char *b, int length)
{
	/* i could be vastly more efficient by aligning on 32 bit boundries, but heh */
	while(length--)
	{
		a[length]=a[length]^b[length];
		b[length]=a[length]^b[length];
		a[length]=b[length]^a[length];
	}
}


int pk_recalc_checksums(struct frame *x)
{
	pk_recalc_checksums_direct(x->ip);
}

int pk_recalc_checksums_direct(char *ip_p)
{
	struct libnet_ip_hdr *ip = (void *)ip_p;

	/* Recalculate IP and TCP/UDP/ICMP checksums */
	libnet_do_checksum((char *)ip, IPPROTO_IP, (int)ip->ip_hl*4);
	libnet_do_checksum((char *)ip, ip->ip_p,(ntohs(ip->ip_len))-(ip->ip_hl * 4));
	return(1);
}


int pk_sniff_dispatch(struct link *link, float timeout, pcap_handler *handler, void *params)
{
	struct timeval diff, now, then;

	if(link==NULL) return(-1);

	if(link->pfprogram &&
	  strncmp(link->pfprogram_loaded, link->pfprogram, sizeof(link->pfprogram_loaded)))
	  if(pk_link_init(link) == NULL) return(-1);


	pcap_setnonblock(link->pcap, 1, link->error);
	//pk_fastnet(link->pcap);

	if (handler)
	{
		gettimeofday(&then, NULL);
		do
		{
			usleep(10000); /* This prevents dispatch from taking 100% CPU -- the function itself reads all buffered packets */
			pcap_dispatch(link->pcap, 0, (void*)handler, params);
			gettimeofday(&now, NULL);
			pk_timeval_subtract(&diff, &now, &then);
		} while(!(timeout ==  0) &&  /* If  0, try once and return */
			((timeout <   0) ||  /* If -1, loop forever. */
			  (float)diff.tv_sec + (float)(diff.tv_usec)/1000000< timeout)); /* If >0, respond for timeout milliseconds */
	}
	return 1;
}

int pk_sniff_getnext(struct link *link)
{
	int i;
	if(!link->pcap) pk_link_init(link);
	i=pk_sniff_getnext_direct(link->pcap, &link->pkthdr, &(link->packet));
	if(link->auto_frame) pk_parse_layers_from_link(link, &link->x, 2);

	return i;
}

int pk_sniff_getnext_direct(pcap_t *pcap, struct pcap_pkthdr *pkthdr, char **packet)
{
	int i;
	struct pcap_pkthdr *temp;
	//pcap_setnonblock(pcap, 1, global_error);

	i=pcap_next_ex(pcap, &temp, packet);
	memcpy(pkthdr, temp, sizeof(struct pcap_pkthdr));
	if(i<=0) usleep(20000);
	return i;
}

struct link *pk_link_preinit(struct link *link)
{
	if(link==NULL){
		link = calloc(1, (sizeof(struct link)));
		if(link==NULL) return(NULL);
		link->self_malloc=1;
	}
	/* 1:  Name the device */
	if(!link->dev[0]) snprintf(link->dev, MX_B, "%s", pk_lookupdev(link->error));

	return link;
}

struct link *pk_link_init(struct link *link)
{
	int i;
	int promisc = 1;

	if(link == NULL) link = pk_link_preinit(link);

	if(link->bandwidth[0]){
   	   i=pk_parse_bw(link->bandwidth);
	   if(i==0) return(1);
	   link->packetsleep=(1000000*64)/i;
	   while(link->packetsleep*link->sleepinterval < 50000) link->sleepinterval++;
        }


	if(link->pcap==NULL)\
	{
		if(link->tracefile[0] != '\0' || link->dev[0] == '-' && link->dev[1] == '\0') {
			if(link->dev[0]='-' && link->dev[1] == '\0') link->tracefile[0]='-', link->tracefile[1]='\0';

			link->pcap = pcap_open_offline(link->tracefile, link->error);
			if (link->pcap == NULL){
				fprintf(stderr, "%s\n", link->tracefile);
				perror("pcap_open_offline");
				exit(EXIT_FAILURE);
			snprintf(link->dev, sizeof(link->dev), "%s", link->tracefile);
			}
		} else {
			/* 1:  Name the device */
			if(!link->dev[0]) snprintf(link->dev, MX_B, "%s", pk_lookupdev(link->error));

			/* 2:  Open the device */
			link->pcap = pcap_open_live(link->dev, 65535, promisc, 1, link->error);
			if (link->pcap == NULL) {
				perror("pcap_open_live");
				exit(EXIT_FAILURE);
			}
		}

	}
	/* this actually starts the sniff process */
	pk_link_filter(link, link->pfprogram, sizeof(link->pfprogram));
	/* 5:  Set non-blocking -- XXX -1 to retain compatibility with pcap_loop/pcap_next */
	//if(timeout >= 0){
	pcap_setnonblock(link->pcap, 1, global_error);
	pk_fastnet(link->pcap);
	//}

	/*  6:  Define the interface type */

	link->datalink = pcap_datalink(link->pcap);

	/*  Recalc checksums on framed packets by default */
	link->auto_checksums = 1;
	link->auto_frame     = 1;



	return(link);
}

int pk_link_filter(struct link *link, char *filter, int length)
{
	/* 3:  Compile the filters */

	if (pcap_compile(link->pcap, &link->fp, link->pfprogram, 1, 0x0) == -1) {
		pcap_perror(link->pcap, "pcap_compile");
		return(0);
	}
	/* 4:  Install the filters */
	if (pcap_setfilter(link->pcap, &link->fp) == -1) {
		pcap_perror(link->pcap, "pcap_setfilter");
		return(0);
	}
	return(1);
}


int pk_fastnet(pcap_t *foo)
{
//#ifndef WIN32
//#ifdef BIOCIMMEDIATE
	int i,immediate=1;
	i = ioctl(pcap_fileno(foo), BIOCIMMEDIATE, &immediate);
	return i;
//#endif
//#endif
//	fprintf(stderr, "Fastnet not supported here");
}

char* pk_lookupdev(char *error)
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	char errbuf[PCAP_ERRBUF_SIZE+1];

	/* Retrieve the interfaces list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n",errbuf);
		exit(1);
	}
	d=alldevs;
	while(d)
	{
		if(d->addresses) return(d->name);
		d=d->next;
	}
	return NULL;
	/* Everyone else actually implements the function :-) */
//	return pcap_lookupdev(link->error);
}

char* pk_lookupdev_ip(char *dev, long *source_ip)
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	pcap_addr_t *a;
	char errbuf[PCAP_ERRBUF_SIZE+1];
	long temp;

	usleep(100);

	/* Retrieve the interfaces list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n",errbuf);
		exit(1);
	}
	d=alldevs;


	while(d)
	{
		if(d->addresses){
		   while(d->addresses){
		        a=d->addresses;
		   	if(a->addr->sa_family == AF_INET)
			   {
			      temp = ((struct sockaddr_in *)a->addr)->sin_addr.s_addr;
			      *source_ip = htonl(temp);
			      memcpy(dev, d->name, 256);
			      return(d->name);
			   }
		        d->addresses=d->addresses->next;
		   }
		}
		d=d->next;
	   }
	return dev;

}




int pk_timeval_subtract (struct timeval *result, struct timeval *rem_x, struct timeval *rem_y)
{
  struct timeval x,y;
  memcpy(&x, rem_x, sizeof(struct timeval));
  memcpy(&y, rem_y, sizeof(struct timeval));
  
  /* Perform the carry for the later subtraction by updating y. */
  if (x.tv_usec < y.tv_usec) {
    int nsec = (y.tv_usec - x.tv_usec) / 1000000 + 1;
    y.tv_usec -= 1000000 * nsec;
    y.tv_sec += nsec;
  }
  if (x.tv_usec - y.tv_usec > 1000000) {
    int nsec = (x.tv_usec - y.tv_usec) / 1000000;
    y.tv_usec += 1000000 * nsec;
    y.tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = x.tv_sec - y.tv_sec;
  result->tv_usec = x.tv_usec - y.tv_usec;

  /* Return 1 if result is negative. */
  return x.tv_sec < y.tv_sec;
}

void pk_print_ip(void *target)
{
	char buf[MX_B], buf2[MX_B];
	struct frame x;

	(char *)x.ip = 	target;
        snprintf(buf, sizeof(buf),   "%s", inet_ntoa(x.ip->ip_src));
        snprintf(buf2, sizeof(buf2), "%s", inet_ntoa(x.ip->ip_dst));
     	fprintf(stderr, " IP: i=%s->%s v=%hu p=%hu hl=%hu s=%hu id=%i o=%hu ttl=%hu pay=%u\n",
     	        buf, buf2,
     	        x.ip->ip_v, x.ip->ip_p, x.ip->ip_hl, x.ip->ip_tos, ntohs(x.ip->ip_id),
     	        x.ip->ip_off, x.ip->ip_ttl, ntohs(x.ip->ip_len)-((int)x.ip->ip_hl*4)
     	        );
}

void pk_print_tcp(void *target, int short_tcp)
{
	char buf[MX_B], buf2[MX_B];
	struct frame x;
	char tmp = '\n';

	if(!short_tcp)tmp=' ';
	(char *)x.tcp = target;
	fprintf(stderr, "TCP: p=%u->%u, s/a=%u%c",
	ntohs(x.tcp->th_sport), ntohs(x.tcp->th_dport), ntohl(x.tcp->th_seq),tmp);
	if(!short_tcp) fprintf(stderr, "-> %u o=%hu f=%hu w=%u u=%u optl=%i\n",
	           ntohl(x.tcp->th_ack), x.tcp->th_off, x.tcp->th_flags,
	           ntohs(x.tcp->th_win), ntohs(x.tcp->th_urp),
	           -(LIBNET_TCP_H - (int)x.tcp->th_off*4));
}

/* CRYPTO */

int pk_hmac(u_char *hash, u_char *key, u_char *message, int size)
{
   int idx, i;
   hmac_state hmac;

  /* register SHA-1 */
   if (i=register_hash(&sha1_desc) == -1) {
      printf("Error registering SHA1: %s\n", error_to_string(i));
      exit(1);
   }
   /* get index of SHA1 in hash descriptor table */
   idx = find_hash("sha1");

   /* start the HMAC */
   if (i=hmac_init(&hmac, idx, key, sizeof(key)) != CRYPT_OK) {
      printf("Error setting up hmac: %s\n", error_to_string(i));
      exit(1);
   }

   hmac_process(&hmac, message, size);

   hmac_done(&hmac, hash);

   /*libnet_hex_dump(message, size, 1, stderr);
   libnet_hex_dump(key, 20, 1, stderr);
   libnet_hex_dump(hash, 20, 1, stderr);*/

   return(0);
}

int pk_sha1(u_char *hash, u_char *message, int size)
{
   int i;
   hash_state hs;

   sha1_init(&hs);
   sha1_process(&hs, message, size);
   sha1_done(&hs, hash);

   /*libnet_hex_dump(hash, 20, 0, stderr);
   libnet_hex_dump(message, size, 0, stderr);*/

   return(20);
}

int pk_initrng(prng_state *prng)
{
   int i;
   long li;

   /* The following is an absolutely horrifying way of seeding a RNG.
      If it wasn't for the even more horrifying crypto it was replacing,
      I wouldn't put my name on it.  Oh well. */

   /* register yarrow */
   if (i=register_prng(&yarrow_desc) != CRYPT_OK) {
      printf("Error registering Yarrow: %s\n", error_to_string(i));
      return -1;
   }

   /* setup the PRNG */
   if (i=yarrow_start(prng) != CRYPT_OK) {
      printf("Start error: %s\n", error_to_string(i));
   }
   /* add entropy */
   libnet_seed_prand();
   for(i=0,li=libnet_get_prand(PRu32);i<libnet_get_prand(PR8);i++)
   {
       libnet_seed_prand();
       if (i=yarrow_add_entropy((char *)&li, 4, prng) != CRYPT_OK) {
          printf("Add_entropy error: %s\n", error_to_string(i));
       }
   }
   /* ready and read */
   if (i=yarrow_ready(prng) != CRYPT_OK) {
      printf("Ready error: %s\n", error_to_string(i));
   }
}

/* pk_bake_syncookie:
   Given the IP pointer and a key, generate a token for the
   SYN cookie.  This version can't embed any information in the
   token itself, so we can only authenticate those values guaranteed
   to be exposed in the server's alleged response. */
long pk_bake_syncookie(u_char *ipp, u_char *key)
{
   u_char buf[MX_B];
   struct libnet_ip_hdr *ip = NULL;
   struct libnet_tcp_hdr *tcp = NULL;

   u_char syncookie[20];
   long synbits;

   (char *)ip  = (char *)ipp;
   (char *)tcp = (char *)ip + (int)ip->ip_hl*4;


    memset(buf, 0, sizeof(buf));
    memcpy(buf,   &ip->ip_src, 4);
    memcpy(buf+4, &ip->ip_dst, 4);
    memcpy(buf+8, &tcp->th_sport, 2);
    memcpy(buf+10,&tcp->th_dport, 2);

   pk_hmac(syncookie, key, buf, 12);
   memcpy(&synbits, &syncookie, sizeof(synbits));

   /*fprintf(stderr, "Sending: %lx vs. %lx from %i/%i\n", ntohl(synbits), 0,
      ntohs(tcp->th_sport), ntohs(tcp->th_dport));*/

   return(synbits);
}


int pk_estimate_hopcount(int ttl)
{
   /* tip of the hat to nomad's despoof -- no, this ain't supposed to be perfect */
   int passive_factor=32; /* may be low but i found a host w/ base TTL 32 */
   		  /* i've heard rumors of hosts w/ ttl base 240 but
   		     haven't found any yet */
   		  /* when wrong, it'll usually be off by 4 (damn 60 ttl hosts)*/
   int distco_factor = 216; /* any less and we hit win32 ttl=128, any more and valid */

   if(ttl > distco_factor)
   {
   	return(255-ttl);
   }
   else if(ttl < (distco_factor-80) || ttl > distco_factor) /* handles up to 40 hops */
   {
      if(ttl%passive_factor == 0) return(0);
      return(passive_factor - (ttl%passive_factor));
   } else {
      return((distco_factor - ttl + 1) / 2); /* they don't adjust ttl when they RST! */
   }
}


int pk_print_hex(FILE *stream, u_char *data, int size)
{
	int i=0;
	int j=size-1;
	int k;
	for(/*i already set*/k=0;i<=j; i++)
	{
		if(k>HEX_WIDTH){
		       	fprintf(stream, "\\\n");
		        k=0;
			}
		fprintf(stream, "%2.2x ", data[i]);
		k+=3;
	}
	fprintf(stream, "\n");
	return(i);
}





int pk_ackmon_process(ght_hash_table_t *session_table, struct frame *x)
{
	struct session_key key;
	struct session_state *session;
	int skip=0;


	key.ip_src.s_addr = x->ip->ip_src.s_addr;
	key.ip_dst.s_addr = x->ip->ip_dst.s_addr;
	key.th_sport      = ntohs(x->tcp->th_sport);
	key.th_dport      = ntohs(x->tcp->th_dport);

	session = ght_get(session_table, sizeof(struct session_key), &key);

	if(!session){
		session=malloc(sizeof(struct session_state));
		if(!session)exit(5);
		memset(session, 0, sizeof(struct session_state));
		session->th_seq_isn = session->th_seq_max = ntohl(x->tcp->th_seq);
		gettimeofday(&session->start, NULL);
		session->then = session->last_seen = session->last_monitor = session->start;
		memcpy(&session->key, &key, sizeof(struct session_key));
		ght_insert(session_table, session, sizeof(struct session_key), &key);
	} else {
		gettimeofday(&session->last_seen, NULL);
		if(session->th_ack_isn == 0)
		session->th_ack_max = session->th_ack_isn = ntohl(x->tcp->th_ack);

		if
		((ntohl(x->tcp->th_ack) > session->th_ack_isn) &&
		((ntohl(x->tcp->th_ack) - session->th_ack_max) < 65536)){
		session->counter_in += ntohl(x->tcp->th_ack) - session->th_ack_max;
		session->th_ack_max = ntohl(x->tcp->th_ack);
		}

		if
		((ntohl(x->tcp->th_seq) > session->th_seq_isn) &&
		((ntohl(x->tcp->th_seq) - session->th_seq_max) < 65536)){
		session->counter_out += ntohl(x->tcp->th_seq) - session->th_seq_max;
		session->th_seq_max = ntohl(x->tcp->th_seq);
		}
	}
}

/*		i=ntohl
		if(session->th_seq_max <= ntohl(x->tcp->th_seq))
		   session->th_seq_max  = ntohl(x->tcp->th_seq);

		i=ntohl(x->tcp->th_ack) - session->th_ack_max;
		if(session->th_ack_max <= ntohl(x->tcp->th_ack) && i>0 && i<65535)
		   session->counter_in += i;

		i=ntohl(x->tcp->th_seq) - session->th_seq_max;
		if(session->th_seq_max <= ntohl(x->tcp->th_seq) && i>0 && i<65535)
		   session->counter_out += i;*/


int pk_ackmon_monitor(ght_hash_table_t *session_table, int clear)
{
	int total_in, total_out, average, i;
	char src[32], dst[32];

	struct session_key key;
	struct session_state *session;

	ght_iterator_t   iterator;

	struct timeval now, diff;

	i=0;
	if(clear) system("clear");
	for(session = ght_first(session_table, &iterator, &key);
	session;
	session = ght_next(session_table, &iterator, &key)){
		i++;
		total_in=session->th_ack_max - session->th_ack_isn;
		total_out=session->th_seq_max - session->th_seq_isn;
		snprintf(src, sizeof(src), "%s", inet_ntoa(session->key.ip_src));
		snprintf(dst, sizeof(dst), "%s", inet_ntoa(session->key.ip_dst));

		//gettimeofday(&now, NULL);
		//pk_timeval_subtract(&diff, &now, &session->start);

		//if(diff.tv_sec) average = total / diff.tv_sec;
		//else            average = 0;
		//average = diff.tv_sec ? (total / diff.tv_sec) : 0;
/*		fprintf(stdout, "[%i]\t%s:%u -> %s:%u\t%uK->%uK\t\t%uK/s->%uK/s\n",
				i,
				dst,
				session->key.th_dport,
				src,
				session->key.th_sport,
				total_in/1024,
				total_out/1024,
				session->counter_in / 1024,
				session->counter_out/ 1024);*/
		gettimeofday(&now, NULL);
		pk_timeval_subtract(&diff, &now, &session->last_monitor);
		if(diff.tv_sec == 0) diff.tv_sec = 1;
		fprintf(stdout, "[%u] %s:%u\t(%uK, %uK/s)\t%s:%u\t(%uK, %uK/s)\n",
				i,
				src,
				session->key.th_sport,
				total_out/1024,
				session->counter_out / 1024 / diff.tv_sec, /*XXX*/
				dst,
				session->key.th_dport,
				total_in/1024,
				session->counter_in / 1024 / diff.tv_sec   /*XXX*/
				);
		session->counter_in = 0;
		session->counter_out=0;
		gettimeofday(&session->last_monitor, NULL);
	}
}

int pk_ackmon_clean(ght_hash_table_t *session_table, int timeout)
{
	struct session_key key;
	struct session_state *session;

	ght_iterator_t   iterator;

	struct timeval now, diff;

	gettimeofday(&now, NULL);

	for(session = ght_first(session_table, &iterator, &key);
	session;
	session = ght_next(session_table, &iterator, &key)){
		gettimeofday(&now, NULL);
		pk_timeval_subtract(&diff, &now, &session->last_seen);
		if(diff.tv_sec > timeout){
			ght_remove(session_table, sizeof(struct session_key), &session->key);
			free(session);
		}
	}
}

int pk_ackmon(struct pk_ackmon_state *state, struct frame *x, int clear, int timeout)
{
	struct timeval now,diff;

	pk_ackmon_process(state->session_table, x);

	gettimeofday(&now, NULL);
	pk_timeval_subtract(&diff, &now, &state->report);
	if(diff.tv_sec) {
		pk_ackmon_monitor(state->session_table, clear);
		gettimeofday(&state->report, NULL);
	}

	gettimeofday(&now, NULL);
	pk_timeval_subtract(&diff, &now, &state->clean);
	if(diff.tv_sec > timeout){
		pk_ackmon_clean(state->session_table, timeout);
		gettimeofday(&state->clean, NULL);
	}
}

struct pk_ackmon_state *pk_ackmon_init(struct pk_ackmon_state *state)
{
	if(state == NULL) state = malloc(sizeof(struct pk_ackmon_state));

	state->session_table = ght_create(1024);

	gettimeofday(&state->clean, NULL);
	gettimeofday(&state->report, NULL);
	return(state);
}


char *pk_fgets(char *buf, int length, FILE *stream)
{
	int i, j;
	memset(buf, 0, length);
	if(feof(stream)) return(NULL);

	for(i=0; i<length; i++)
	{
		buf[i]=getc(stream);
		if(buf[i]=='\\'){
			while(getc(stream)!='\n') if(feof(stream)) return(NULL);
			buf[i]=getc(stream);
		}
		if(buf[i]=='\r'){
			getc(stream);
			buf[i]=getc(stream);
		}
		if(buf[i]=='\n') return(buf);
	}
	return(buf);
}

int pk_is_hex(char val)
{
	if((val >= '0' && val <= '9') ||
	   (val >= 'a' && val <= 'f')) {
		return(1);
	}
	return(0);
}

char pk_htoc(char b1, char b2)
{
	int i;
	char buf[3];
	buf[0] = b1;
	buf[1] = b2;
	buf[2] = 0 ;
	if(i=strtoul(buf, NULL, 16)){
		return(i);
	} else  return(0);
}

int pk_ether_aton(char *dest, char *src)
{
	int i = sscanf(src, "%2X:%2X:%2X:%2X:%2X:%2X",
	        &dest[0], &dest[1], &dest[2],
	        &dest[3], &dest[4], &dest[5]);
        prng_state prng;
        pk_initrng(&prng);

	if(i == ETHER_ADDR_LEN) return(i);

	i = sscanf(optarg, "%c%c", &dest[0], &dest[1]);

	if(i == 1 && dest[0] == 'B') return(ether_aton(dest, "FF:FF:FF:FF:FF:FF"));
	if(i == 1 && dest[0] == 'M') return(ether_aton(dest, "01:00:5E:11:22:33"));

	if(i == 1 && dest[0] == 'R'){
		dest[0] = '\x00';
		yarrow_read(dest+1, ETHER_ADDR_LEN-1, &prng);
		return(ETHER_ADDR_LEN);
	}
	if((i == 2 && dest[0] == 'M' && dest[1] == 'R') ||
	   (i == 2 && dest[0] == 'R' && dest[1] == 'M')){
		dest[0] = '\x01';
		dest[1] = '\x00';
		dest[2] = '\x5E';
		yarrow_read(dest+3, ETHER_ADDR_LEN-3, &prng);
		return(ETHER_ADDR_LEN);
	}
	return(1);
}

int pk_hexdump(FILE *stream, int length, u_char *packet)
{
	int i=0;
	int j=length-1;
	int max=76;
	int k;

	for(/*i already set*/k=0;i<=j; i++)
	{
		if(k>max){
			fprintf(stream, "\\\n");
			k=0;
		}
		fprintf(stream, "%2.2x ", packet[i]);
		k+=3;

	}

	fprintf(stream, "\n");
	return(i);
}


void pk_translate_flags(int th_flags)
{
   char desc[1024];
   if((th_flags | TH_SYN) == th_flags) fprintf(stdout, "TH_SYN ");
   if((th_flags | TH_ACK) == th_flags) fprintf(stdout, "TH_ACK ");
   if((th_flags | TH_RST) == th_flags) fprintf(stdout, "TH_RST ");
   if((th_flags | TH_PUSH) == th_flags) fprintf(stdout, "TH_PSH ");
   if((th_flags | TH_URG) == th_flags) fprintf(stdout, "TH_URG ");
}

int pk_tr(char *string, int length, char from, char to)
{
   int i,count;
   for(i=0; i<=length; i++) {
      if(string[i]==from) string[i]=to;
      count++;
   }
   return(count);
}
