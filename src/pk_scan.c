#include "libpaketto.h"
#include <pthread.h>

int pk_scanrand(struct pk_sr_conf *conf)
{
	int pid;
	pthread_t p_recv;
	pthread_t p_send;
	int i;

	if(geteuid() != 0)
        {
                perror("PK requires root to access the network directly.");
		return(0);
        }

	if(conf->send_packets && !pk_parse_dest(conf->dest, sizeof(conf->dest), conf->shortdest, conf->ttlrange || conf->targets) && !conf->targets)
	{
		return(0);
	}

	if(conf->verbose)
	{
		fprintf(stderr, "Stat|=====IP_Address==|Port=|Hops|==Time==|=============Details============|\n");
	}

	if( conf->send_packets  && !conf->recv_packets) pk_sr_send(conf);
	if(!conf->send_packets &&   conf->recv_packets) pk_sr_recv(conf);
	if(!conf->send_packets &&  !conf->recv_packets) return(0); /* what are we supposed to do? */

	if( conf->send_packets &&   conf->recv_packets)
	{
		/*pid=fork();
		if(!pid) pk_sr_send(conf);
		else     pk_sr_recv(conf);*/
		conf->working=2 + conf->targets_threadmax;
		pthread_create(&p_recv, NULL, (void *)pk_sr_recv, conf);
		while(!conf->link->pcap) usleep(5000);
		pthread_create(&p_send, NULL, (void *)pk_sr_send, conf);

		while(conf->working) usleep(100000);
	}
}


struct pk_sr_conf *pk_sr_conf_init(struct pk_sr_conf *conf)
{
	struct timeval now;

	if(conf == NULL) {
		conf = malloc(sizeof(struct pk_sr_conf));
		memset(conf, 0, sizeof(struct pk_sr_conf));
	}
	if(conf->link == NULL)  conf->link = pk_link_preinit(NULL);


	pk_initrng(&conf->prng);
	yarrow_read(conf->seed, 20, &conf->prng);

	conf->verbose = 0;
	conf->timeout = 10;
	conf->show_accepted = 1;
	conf->bandwidth = "50k";
	conf->output = stdout;
	//conf->fullscan_verifier = pk_sr_verify;
	//conf->fullscan_verifier_params = conf;
	gettimeofday(&(conf->start), NULL);
	gettimeofday(&(conf->then), NULL);

	conf->send_packets = 1;
	conf->recv_packets = 1;

	conf->dev = conf->link->dev;
	pk_lookupdev_ip(conf->dev, &(conf->source_ip));

	gettimeofday(&now, NULL);
	//yarrow_read((char *)&conf->source_port, 2, &prng);

	//conf->source_port  = now.tv_sec%64 + now.tv_usec/100;

	conf->check_icmp_seq = 1;
	//conf->reporter = pk_sr_report_print;
	conf->fp_reporter = pk_sr_report;
	conf->fp_printer  = pk_sr_report_print;
	conf->reportmode = PK_SR_MODE_HUMAN;

	conf->targets_sleep = 1;

	gettimeofday(&conf->lastgood, NULL);

	if(conf->table[0]){
		snprintf(conf->table, sizeof(conf->table), "scanrand");
	}
	return conf;
}

long pk_munch_syncookie(u_char *ipp, u_char *key)
{
   u_char buf[MX_B];
   struct libnet_ip_hdr *ip = NULL;
   struct libnet_tcp_hdr *tcp = NULL;
   int i = 1;

   u_char syncookie[20];
   long synbits;

   (char *)ip  = (char *)ipp;
   (char *)tcp = (char *)ip + (int)ip->ip_hl*4;


   memset(buf, 0, sizeof(buf));
   memcpy(buf,   &ip->ip_dst, 4);
   memcpy(buf+4, &ip->ip_src, 4);
   memcpy(buf+8, &tcp->th_dport, 2);
   memcpy(buf+10,&tcp->th_sport, 2);

   pk_hmac(syncookie, key, buf, 12);

   memcpy(&synbits, &syncookie, sizeof(synbits));

   if(tcp->th_flags == TH_RST) /* Distco st00 rides again */
   {
      if(!(ntohl(tcp->th_ack))) tcp->th_ack = tcp->th_seq; /* WEIRD fix */
      i=0;/* RST's don't increment */
   }

   if(ntohl(tcp->th_ack)-i == ntohl(synbits))
   {

	return(synbits);
   }

   else{
	return(0); // this screws up 1/2^32 times.
   }
}
int pk_parse_dest(char *dest, int length, char *shortdest, int multi)
{
       char buf[MX_B], buf2[MX_B], destbuf[1024], rangebuf[1024], portbuf[1024];
       int i,j,k,l;
       struct in_addr temp_ip;
       const char quickbuf[] = "80,443,445,53,20-23,25,135,139,8080,110,111,143,1025,5000,465,993,31337,79,8010,8000,6667,2049,3306,1234,1080,6000";
       const char squickbuf[] = "80,443,139,21,22,23";

       char shortbuf[MX_B];

       if(shortdest == NULL) shortdest = &shortbuf;
       /* there's gotta be an easier way to do this :-)
        * basically we're splitting the destination string into
        * destination, CIDR range, and ports...the whole purpose of
        * this function is to take whatever garbage the user gave us
        * and convert it to my canonical form -- or die trying.
        */
       sscanf(shortdest, "%1024[^/]/%1024s", buf, rangebuf); /* only need range */
       sscanf(shortdest, "%1024[^:/]:%1024[^:/]:%1024s", destbuf, portbuf, buf);


       if(!destbuf[0]){
       return(0);
       }

     /* So, here's the deal.  By default, I want to scan the bejesus out of a single host, but
        I don't want to throw out thousands of packets per host for a simple
        traceroute or netsweep.  So there's differential default behavior, but it's doing
        the Right Thing.  Manual override of course can do anything. */

       i=0;
       k=0;

       while(i<1024 && destbuf[i]!=0){
	    if((destbuf[i]=='-' || destbuf[i]==',')){
		    k=2; /* might be plural */
	    }
	    else if((destbuf[i]>='A' && destbuf[i]<='Z') ||
	            (destbuf[i]>='a' && destbuf[i]<='z')){
	    	j++;
	    }
	    if(destbuf[i]=='\n' || destbuf[i] == '\r'){
	        destbuf[i]=0; /* chomp, DNS resolver needs no trailing newline */
		}
	    i++;
       }

	if(k==2 && !j) multi=2;/* found dash/comma w/o DNS -- must be multi */
	if(j){ /* found ASCII character */
	        temp_ip.s_addr = libnet_name_resolve(destbuf, 1);
		if(!memcmp(&temp_ip.s_addr, "\xff\xff\xff\xff", IPV4_ADDR_LEN)){
			//fprintf(stderr, "Couldn't resolve name: %s\n", destbuf);
			return(0);
		} else  snprintf(destbuf, 1024, "%s", inet_ntoa(temp_ip));
	}

       if(sscanf(destbuf, "%1024[^.].%1024[^.].%1024[^.].%1024s", buf,buf,buf,buf) != 4){
       	  fprintf(stderr, "Invalid IP Specification:  Not enough octets(four needed).\n");
       	  return(0);
       }

       if(!atoi(rangebuf) || atoi(rangebuf)>32 || j+k==2) snprintf(rangebuf, sizeof(rangebuf), "32");
       if(atoi(rangebuf) < 32) multi=3;

       if(!portbuf[0]){  /* no default ports?  Whatever shall we do! */
       	if(multi) snprintf(portbuf, sizeof(portbuf), "80");
       	else      snprintf(portbuf, sizeof(portbuf), "quick"); /* was d */
       }
       /* ok lets set up some defaults */
       if(!strncmp(portbuf, "quick", sizeof(portbuf))){
          snprintf(portbuf, sizeof(portbuf), "%s", quickbuf);
       }
       if(!strncmp(portbuf, "squick", sizeof(portbuf))){
	  snprintf(portbuf, sizeof(portbuf), "%s", squickbuf);
       }
       if(!strncmp(portbuf, "all", sizeof(portbuf))){
	  snprintf(portbuf, sizeof(portbuf), "0-65535");
       }
       /* we set up knownscan in raw_sock itself */

       snprintf(dest, length, "%s:%s/%s", destbuf, portbuf, rangebuf);
       return(1);
}

unsigned int pk_parse_bw(char *bandwidth)
{
	char buf[MX_B];
	char buf2[MX_B];

	int base, multiple, i;

   	i=sscanf(bandwidth, "%1024[^BbKkMmGg]%1024s", buf, buf2);
	if(i==0)return(0);
	base=atoi(buf);
	if(i==1){buf2[0]='B'; i=2;}
	if(i==2)switch(buf2[0]){
		case 'B':
			multiple=1;
			break;
		case 'b':
			multiple=1;
			break;
		case 'K':
			multiple=1024;
			break;
		case 'k':
			multiple=1024;
			break;
		case 'M':
			multiple=1024*1024;
			break;
		case 'm':
			multiple=1024*1024;
			break;
		case 'G':
			multiple=1024*1024*1024;
			break;
		case 'g':
			multiple=1024*1024*1024;
			break;
		}
	return(base*multiple);
}

struct frame *pk_build_generic_syn(struct frame *x)
{
   char *ipopt;

   if(x == NULL){
      x = malloc(sizeof(struct frame));
      if(!x) return(NULL);
      memset(x, 0, sizeof(struct frame));
   }

   if(!x->packet){
      x->packet = malloc(2048);
      memset(x->packet, 0, 2048);
      }

   x->eth = x->packet;

   //memcpy(x->eth->ether_dhost, "000000", 6);
   //memcpy(x->eth->ether_shost, "000000", 6);
   snprintf(x->eth->ether_dhost, 6, "%c%c%c%c%c%c", 0x00, 0xd0, 0x58, 0xe0, 0x21, 0x4d);
   snprintf(x->eth->ether_shost, 6, "%c%c%c%c%c%c", 0x00, 0x01, 0x03, 0xdc, 0x88, 0x8a);
   x->eth->ether_type = htons(ETHERTYPE_IP);

   (char *)x->ip = (char *)x->eth + LIBNET_ETH_H;
   x->ip->ip_v  = 4;
   x->ip->ip_hl = 5;
   x->ip->ip_tos = 0;
   x->ip->ip_len = htons(40);
   x->ip->ip_id  = htons(1234);
   x->ip->ip_off = 64;  /* Set DF */
   x->ip->ip_ttl = 255;
   x->ip->ip_p   = IPPROTO_TCP;
   //x->ip->ip_sum = LATER

   /* experiment with options */
   /*(char *)ipopt = (char *)x->ip + (int)x->ip->ip_hl*4;
   x->ip->ip_len = htons(ntohs(x->ip->ip_len) + 36);
   x->ip->ip_hl  = x->ip->ip_hl + (36 / 4);*/

   /*ipopt[0] = 131;
   ipopt[1] = 7;
   ipopt[2] = 4;
   inet_aton("66.192.252.34", (void *)&ipopt[3]);

   ipopt[7] = 1;*/

   /*ipopt[0] = 68;
   ipopt[1] = 36;
   ipopt[2] = 5;
   ipopt[3] = 4;*/
   /*inet_aton("168.215.54.102", (void *)&ipopt[4]);
   inet_aton("66.185.151.237", (void *)&ipopt[12]);*/
   /*inet_aton("216.64.175.2", (void *)&ipopt[20]);
   inet_aton("216.64.175.1", (void *)&ipopt[28]);*/

   (char *)x->tcp = (char *)x->ip + (int)x->ip->ip_hl*4;
   x->tcp->th_sport = htons(12345);
   x->tcp->th_dport = htons(139);
   x->tcp->th_seq =   htonl(420);
   x->tcp->th_ack =   htonl(0);
   x->tcp->th_x2  =   0;
   x->tcp->th_off =   5;
   x->tcp->th_flags = TH_SYN;
   x->tcp->th_win =   htons(4096);
   //x->tcp->th_sum =  LATER
   x->tcp->th_urp =   htons(0);

   pk_recalc_checksums(x);
   x->caplen = 54;

   return(x);
}

struct frame *pk_build_generic_dns(struct frame *x, char *name, char *type)
{
   if(x == NULL){
      x = malloc(sizeof(struct frame));
      if(!x) return(NULL);
      memset(x, 0, sizeof(struct frame));
   }

   if(!x->packet){
      x->packet = malloc(2048);
      memset(x->packet, 0, 2048);
      }

   x->eth = x->packet;

   snprintf(x->eth->ether_dhost, 6, "%c%c%c%c%c%c", 0x00, 0xd0, 0x58, 0xe0, 0x21, 0x4d);
   snprintf(x->eth->ether_shost, 6, "%c%c%c%c%c%c", 0x00, 0x01, 0x03, 0xdc, 0x88, 0x8a);
   x->eth->ether_type = htons(ETHERTYPE_IP);

   (char *)x->ip = (char *)x->eth + LIBNET_ETH_H;
   x->ip->ip_v  = 4;
   x->ip->ip_hl = 5;
   x->ip->ip_tos = 0;
   x->ip->ip_len = htons(40);
   x->ip->ip_id  = htons(1234);
   x->ip->ip_off = 64;  /* Set DF */
   x->ip->ip_ttl = 255;
   x->ip->ip_p   = IPPROTO_UDP;
   //x->ip->ip_sum = LATER

   (char *)x->udp = (char *)x->ip + ((int)x->ip->ip_hl*4);
   x->udp->uh_sport = htons(53);
   x->udp->uh_dport = htons(53);
   x->udp->uh_ulen  = htons(20);
   x->udp->uh_sum   = 0;

   (char *)x->dns=(char *)x->udp+LIBNET_UDP_H;
   x->dns->id=htons(DNS_MAGIC);
   x->dns->flags=1;
   x->dns->num_q=0;
   x->dns->num_answ_rr=0;
   x->dns->num_auth_rr=0;
   x->dns->num_addi_rr=0;

   pk_recalc_checksums(x);
   x->caplen = LIBNET_ETH_H + (int)x->ip->ip_hl*4 + LIBNET_UDP_H + LIBNET_DNS_H;

   if(name) pk_add_dns_query(x, name, type);

   return x;
}

struct frame *pk_add_dns_query(struct frame *x, char *name, char *type)
{
   char *dns_data;
   char *ptr;
   char len;
   int num_secs;
   char secs[16][65];
   int i;
   short j;
   int bytes=0;
   short typecode;


   if(x == NULL){
      x = pk_build_generic_dns(NULL, name, type);
   }

   if(!strncmp(type, "A", 16)) typecode=htons(1);
   if(!strncmp(type, "MX", 16)) typecode=htons(0x0f);
   if(!strncmp(type, "PTR", 16)) typecode=htons(0x0c);


   dns_data = (char *)x->ip + ntohs(x->ip->ip_len);

   num_secs=sscanf(name, "%64[^.].%64[^.].%64[^.].%64[^.].%64[^.].%64[^.].%64[^.].%64[^.].%64[^.].%64[^.].%64[^.].%64[^.].%64[^.].%64[^.].%64[^.].%64[^.].",secs[0],secs[1],secs[2],secs[3],secs[4],secs[5],secs[6],secs[7],secs[8],secs[9],secs[10],secs[11],secs[12],secs[13],secs[14],secs[15]);

   for(i=0; i<num_secs; i++)
   {
   	len=strlen(secs[i]);
	memcpy(&dns_data[bytes], &len, 1); bytes+=1;
	memcpy(&dns_data[bytes], &secs[i], len); bytes+=len;
   }
//   dns_data[bytes]='.'; bytes++;
   dns_data[bytes]=0; bytes++;

   j=htons(1);
   memcpy(&dns_data[bytes], &typecode, 2); bytes +=2;
   memcpy(&dns_data[bytes], &j, 2); bytes +=2;

   x->dns->num_q=ntohs(htons(x->dns->num_q)+1);
   x->ip->ip_len= htons(ntohs(x->ip->ip_len)+bytes);
   x->udp->uh_ulen=htons(ntohs(x->udp->uh_ulen)+bytes);
   x->caplen+=bytes;

   return x;
}

pcap_handler pk_sr_report(struct pk_sr_conf *conf, struct pcap_pkthdr *pkthdr, char *packet)
{
	int i, dport, local_conf = 0;
	char buf[MX_B], buf2[MX_B], type[5];

	struct in_addr *ip;

	struct frame x, ic;
	struct timeval now, diff, virtual_now, virtual_then, virtual_max, virtual_offset;
	struct scanrand_report *report;

	report = malloc(sizeof(struct scanrand_report));

	i=pk_parse_layers(packet, pkthdr->caplen, &x, 2, DLT_EN10MB, 0);
	if(!i){
	  return(0);
	}

	if(conf==NULL)
	{
		conf = pk_sr_conf_init(NULL);
		local_conf++;
	}
	memset(buf, 0, sizeof(buf));
	memset(buf2, 0, sizeof(buf2));
	memset(type, 0, sizeof(type));
	memset(report, 0, sizeof(struct scanrand_report));

	//pk_timeval_subtract(&diff, &(pkthdr->ts), &conf->start);

	report->frame = &x;
	report->conf = conf;
	report->hopcount = pk_estimate_hopcount(x.ip->ip_ttl);

	if(!conf->timescale){
		virtual_now.tv_sec = pkthdr->ts.tv_sec % 6;
		virtual_now.tv_usec= (pkthdr->ts.tv_usec / 100) * 100;
		virtual_max.tv_sec = 5;
		virtual_max.tv_usec = 999900;
	} else {
		virtual_now.tv_sec = pkthdr->ts.tv_sec % 65;
		virtual_now.tv_usec= (pkthdr->ts.tv_usec / 1000) * 1000;
		virtual_max.tv_sec = 64;
		virtual_max.tv_usec = 999000;
	}

	if( ntohs(x.eth->ether_type) == ETHERTYPE_IP &&
	          x.ip->ip_p         == IPPROTO_TCP  &&
		  (conf->disable_seq || pk_munch_syncookie((u_char *)x.ip, conf->seed))){
		gettimeofday(&conf->lastgood, NULL);

		if(!conf->timescale){
			virtual_then.tv_sec = ntohs(x.tcp->th_dport) / 10000;
			virtual_then.tv_usec= (ntohs(x.tcp->th_dport) % 10000) * 100;
		} else {
			virtual_then.tv_sec = ntohs(x.tcp->th_dport) / 1000;
			virtual_then.tv_usec= (ntohs(x.tcp->th_dport) % 1000) * 1000;
		}

		if((virtual_now.tv_sec  < virtual_then.tv_sec ) ||
		  ((virtual_now.tv_sec == virtual_then.tv_sec ) &&
		   (virtual_now.tv_usec < virtual_then.tv_usec))){
		      pk_timeval_subtract(&virtual_offset, &virtual_then, &virtual_now);
		      pk_timeval_subtract(&diff, &virtual_max, &virtual_offset);
		}else pk_timeval_subtract(&diff, &virtual_now, &virtual_then); 


		report->diff = diff;

		report->target   = x.ip->ip_src;
		report->receiver   = x.ip->ip_dst;
		report->port = ntohs(x.tcp->th_sport);
		report->qos  = x.ip->ip_tos;

		switch(x.tcp->th_flags){
			case (TH_SYN | TH_ACK):
				if(conf->show_accepted) snprintf(report->status, sizeof(report->status), "UP");
				break;
			case (TH_RST | TH_ACK):
				if(conf->show_rejected) snprintf(report->status, sizeof(report->status), "DOWN");
				break;
			case (TH_RST):
				if(conf->rst_dist) snprintf(report->status, sizeof(report->status), "RDST");
				break;
			//report->info_src=x.ip->ip_src;
			//report->info_dst=x.ip->ip_dst;
		}
		if(conf->verbose){
			fprintf(stderr, "Got %i on %s:\n", pkthdr->caplen, conf->dev);
			fprintf(stderr, " "); pk_print_ip((char *)x.ip);
			fprintf(stderr, " "); pk_print_tcp((char *)x.tcp, 0);
		}
	}

	if( ntohs(x.eth->ether_type) == ETHERTYPE_IP &&
	          x.ip->ip_p == IPPROTO_ICMP){
		i=pk_parse_layers((char *)&x.icmp->icmp_data,
			pkthdr->caplen-LIBNET_ETH_H-(int)x.ip->ip_hl*4-8, /* XXX slight chance of bug */
			&ic, 3, DLT_EN10MB , 1);

		if(ic.tcp){

			if(!conf->timescale){
				virtual_then.tv_sec = ntohs(ic.tcp->th_sport) / 10000;
				virtual_then.tv_usec= (ntohs(ic.tcp->th_sport) % 10000) * 100;
			} else {
				virtual_then.tv_sec = ntohs(ic.tcp->th_sport) / 1000;
				virtual_then.tv_usec= (ntohs(ic.tcp->th_sport) % 1000) * 1000;
			}
		}

		if((virtual_now.tv_sec  < virtual_then.tv_sec ) ||
		  ((virtual_now.tv_sec == virtual_then.tv_sec ) &&
		   (virtual_now.tv_usec < virtual_then.tv_usec))){
		      pk_timeval_subtract(&virtual_offset, &virtual_then, &virtual_now);
		      pk_timeval_subtract(&diff, &virtual_max, &virtual_offset);
		}else pk_timeval_subtract(&diff, &virtual_now, &virtual_then);

		report->diff.tv_sec = diff.tv_sec;
		report->diff.tv_usec= diff.tv_usec;

		if(i && ic.ip->ip_p == IPPROTO_TCP &&
			x.icmp->icmp_type == ICMP_TIMXCEED){
			/* Some firewalls collapse on large numbers of connections from
			* the same local port to the same remote host.  So I varied the
			* local port according to the TTL, figuring I could extract the hops
			* travelled from the port number that returned.  But firewalls w/
			* local port randomizers don't translate the TCP chunk in the ICMP
			* error!  So we'll throw the actual info into IPID, on the assumption
			* that IPID *has* to be translated back for ICMP errors to work.
			* Ah, fun with layers...*/
			dport = ic.tcp->th_dport;
			if((!conf->disable_seq || !conf->check_icmp_seq || ic.tcp->th_seq == pk_bake_syncookie((char *)&ic.ip, conf->seed)))
			{
				gettimeofday(&conf->lastgood, NULL);
				if(conf->verbose){
					fprintf(stderr, "Got %i on %s:\n", pkthdr->caplen, conf->dev);
					fprintf(stderr, " "); pk_print_ip((char *)x.ip);
					fprintf(stderr, "ICMP: "); pk_print_ip((char *)ic.ip);
					fprintf(stderr, "ICMP: "); pk_print_tcp((char *)ic.tcp, 1);
				}
				//report->trace_hop= (255 - (conf->source_port - ntohs(ic.tcp->th_sport)));
				report->trace_hop= ntohs(ic.ip->ip_id)/256;
				snprintf(report->status, sizeof(report->status), "%3.3i ", report->trace_hop);
				report->target   = x.ip->ip_src;
				report->receiver = x.ip->ip_dst;
				report->port = ntohs(dport);
				report->original_qos = ntohs(ic.ip->ip_id)%256;
				report->qos = ic.ip->ip_tos;
				report->trace_src=ic.ip->ip_src;
				report->trace_dst=ic.ip->ip_dst;
				report->trace_mid=x.ip->ip_src;

			}
		}
		else if(x.icmp->icmp_type == ICMP_UNREACH && (conf->ttlrange || conf->show_rejected))
			{
			if(ic.ip->ip_p == IPPROTO_TCP && /* no TCP flags in ICMP's TCP chunklet */
			(!conf->disable_seq || conf->check_icmp_seq || ic.tcp->th_seq ==
			  pk_bake_syncookie((u_char *)ic.ip, conf->seed)))
				{
				snprintf(report->status, sizeof(report->status), "un%2.2i", x.icmp->icmp_code);
				report->target   = x.ip->ip_src;
				report->port = ntohs(ic.tcp->th_dport);
				report->qos  = ic.ip->ip_tos;
				report->trace_src=ic.ip->ip_src;
				report->trace_dst=ic.ip->ip_dst;
				report->trace_mid=x.ip->ip_src;
			}
		}
	}


	if((int)report->status[0]) /* Basically, this function is called for every packet -- but status is only set for valid ones.  Meh design. */
	{
		/*if(ic.ipopt)// fprintf(stdout, "IP OPT DETECTED, TYPE %i\n", x.ipopt->type);
		{
			for(i=0;i<=4;i+=2){
				//ts=&ic.ipopt->data[i];
				ip = &ic.ipopt->data[i];
				fprintf(stdout, "%s, ", inet_ntoa(*ip));
				fprintf(stdout, "%u, ", ntohl(ic.ipopt->data[i+1]));
				fprintf(stdout, "\n");
			}
			fprintf(stdout, "%i, %s", ntohs(ic.ip->ip_len), inet_ntoa(ic.ip->ip_dst));
			fprintf(stdout, "\n");
		}*/
		pk_sr_report_print(report);
	}
	if(local_conf==1) free(conf);
	free(report);
}

pk_sr_printer pk_sr_report_print(struct scanrand_report *report)
{
	int local_conf = 0;
	char src[MX_B], dst[MX_B];
	char csv[MX_B];
	char t_src[32], t_dst[32], t_mid[32];
	struct timeval now;

	snprintf(t_src, sizeof(t_src), "%s", inet_ntoa(report->trace_src));
	snprintf(t_dst, sizeof(t_dst), "%s", inet_ntoa(report->trace_dst));
	snprintf(t_mid, sizeof(t_mid), "%s", inet_ntoa(report->trace_mid));



	if(report->conf==NULL)
	{
		report->conf = pk_sr_conf_init(NULL);
		local_conf++;
	}
	if(!report->conf->resolve){
	   if(report->trace_src.s_addr && report->trace_dst.s_addr){
	      snprintf(src, sizeof(src), "%s", inet_ntoa(report->trace_src));
	      snprintf(dst, sizeof(dst), "%s", inet_ntoa(report->trace_dst));
	   } else {
	      snprintf(src, sizeof(src), "%s", inet_ntoa(report->receiver));
	      snprintf(dst, sizeof(dst), "%s", inet_ntoa(report->target));
	   }
	} else {
	   if(report->trace_src.s_addr && report->trace_dst.s_addr){
	      snprintf(src, sizeof(src), "%35.35s", libnet_host_lookup(report->trace_mid.s_addr, 1));
	      snprintf(dst, sizeof(dst), "");// libnet_host_lookup(report->trace_dst.s_addr, 1));
	   } else {
	      snprintf(src, sizeof(src), "%s", libnet_host_lookup(report->receiver.s_addr, 1));
	      snprintf(dst, sizeof(dst), "%s", libnet_host_lookup(report->target.s_addr, 1));
	   }
	}

	if(report->conf->reportmode == PK_SR_MODE_HUMAN){
		fprintf(report->conf->output, "%4.4s: %16.16s:%-5i [%2.2hu]", report->status, inet_ntoa(report->target), report->port, report->hopcount);
		if(!report->conf->timescale){
		   fprintf(report->conf->output, "%4lu.%1.1ums", report->diff.tv_sec*1000 + report->diff.tv_usec/1000, (report->diff.tv_usec%1000)/100);
		} else {
		   fprintf(report->conf->output, "%4lu.%3.3lus", report->diff.tv_sec, report->diff.tv_usec/1000);
		}

		// "%4lu.%4.4lus", report->diff.tv_sec, report->diff.tv_usec/100);
		if(!report->conf->resolve)
			fprintf(report->conf->output, "(%16.16s -> %-16.16s)", src, dst);
		else    fprintf(report->conf->output, "(%16.16s -> %16.16s)", src, dst);
		if(report->conf->qosrange && strncmp(report->conf->qosrange, "0-0", 1024)){
			fprintf(report->conf->output, " {%3.3u->%3.3u}", report->original_qos, report->qos);
		}
	} else {
		gettimeofday(&now, NULL);
		snprintf(csv, sizeof(csv), "%u,%u,%u,%u,\'%s\',\'%s\',\'%s\',%u,%u,%u,%u,%u,\'%s\',\'%s\',\'%s\'",
			now.tv_sec,
			now.tv_usec,
			report->diff.tv_sec,
			report->diff.tv_usec,
			report->status,
			src,
			dst,
			report->port,
			report->hopcount,
			report->trace_hop,
			report->original_qos,
			report->qos,
			t_src,
			t_dst,
			t_mid);
	}

	if(report->conf->reportmode == PK_SR_MODE_SQL)
		fprintf(report->conf->output, "insert into %s values(", report->conf->table);
	else if(report->conf->reportmode == PK_SR_MODE_SQL) /* do nothing */;
	fprintf(report->conf->output, "%s", csv);
	if(report->conf->reportmode == PK_SR_MODE_SQL)
		fprintf(report->conf->output, ");");

	fprintf(report->conf->output, "\n");

	if(local_conf) free(report->conf);
	return(0);
}


int pk_sr_send(struct pk_sr_conf *conf)
{
	int i,dport,start_p,end_p,knownscan;
	char buf[MX_B], buf2[MX_B];
	char pbuf_temp[MX_B];
	struct libnet_plist_chain *plist2;
	pthread_t p_rst;
	pthread_t p_filesend;
	struct pk_sr_conf sendconf;
	FILE *new_targets;
	int linenum;
	struct pk_sr_conf rstconf;
	int begin, end;

	struct frame *x = pk_build_generic_syn(NULL);
	x->ip->ip_src.s_addr = htonl(conf->source_ip);

	/* the thread handling code that follows is truly an abomination */

	if(conf->targets && !conf->targets_lines && !conf->targets_offset && conf->targets_threadmax>1){
		while(fgets(buf, MX_B, conf->targets)) conf->targets_lines++;
		fseek(conf->targets, 0, SEEK_SET);
	}



	sleep(conf->targets_offset * conf->targets_sleep);
	if(conf->targets && (conf->targets_offset+1 < conf->targets_threadmax)){
		memcpy(&sendconf, conf, sizeof(struct pk_sr_conf));
		sendconf.targets_offset+=1;
		sendconf.targets = fopen(sendconf.targets_filename, "r");
		pthread_create(&p_filesend, NULL, (void *)pk_sr_send, &sendconf);
	}

	x->tcp->th_sport     = htons(conf->source_port);
	if(conf->overload_seconds && !conf->overload_thread) {
	   memcpy(&rstconf, conf, sizeof(struct pk_sr_conf));
	   rstconf.overload_thread = 1;
	   pthread_create(&p_rst, NULL, (void *)pk_sr_send, &rstconf);
	}

	if(conf->overload_thread) {
	   x->tcp->th_flags = TH_RST;
	   sleep(conf->overload_seconds);
	} else if(conf->payload_size){
	   x->ip->ip_len = htons(ntohs(x->ip->ip_len) + conf->payload_size);
	   x->caplen += conf->payload_size;
	}

	if(conf->targets_ports) memcpy(pbuf_temp, conf->targets_ports, MX_B);

	if(conf->dest[0] && !conf->targets) pk_sr_spew_tcp(conf, x);
	if(conf->targets){
	   while(fgets(buf, MX_B, conf->targets)){
	     linenum++;
	     if(conf->targets_threadmax > 1){
		begin = ((conf->targets_lines / conf->targets_threadmax) * conf->targets_offset)+1;
		end   = ((conf->targets_lines / conf->targets_threadmax) *(conf->targets_offset+1))+1;
		if((linenum<begin) || (linenum >=end)) continue;
	     }
	     if(conf->targets_append[0]){
		buf[strlen(buf)-1]='\0';
	        snprintf(buf2, sizeof(buf2), "%s%s ", buf, conf->targets_append);
		snprintf(buf, sizeof(buf), "%s", buf2);
	     }
	     /*if(conf->target_ports){
	       libnet_plist_chain_new(&plist2, pbuf_temp);
	       while(libnet_plist_chain_next_pair(plist2, &start_p, &end_p)){
		  for(dport=start_p; dport<=end_p; dport++){
		     i=strlen(buf);
		     if(buf[i-1]=='\n') buf[i-1]='\0';
		     snprintf(buf2, sizeof(buf2), "%s:%i", buf, dport);
		     conf->shortdest = buf2;
	             if(pk_parse_dest(conf->dest, sizeof(conf->dest), conf->shortdest, conf->ttlrange)) pk_sr_spew_tcp(conf, x);
		  }
		}
		libnet_plist_chain_free(plist2);
		memcpy(pbuf_temp, conf->target_ports, MX_B);
	      } else*/ {
		 i=strlen(buf);
	         buf[i-1]='\0';
	         conf->shortdest = buf;
	         if(pk_parse_dest(conf->dest, sizeof(conf->dest), conf->shortdest, conf->ttlrange)) pk_sr_spew_tcp(conf, x);

	      }
	   }
	}

	conf->working--;
	return(1);
}


int pk_iterator_ip_init(struct pk_iterator_ip *it_ip, char *dest)
{
   if(it_ip == NULL) it_ip = calloc(sizeof(struct pk_iterator_ip), 1);

   if(sscanf(dest, "%1024[^.].%1024[^.].%1024[^.].%1024s",
	  it_ip->abuf, it_ip->bbuf, it_ip->cbuf, it_ip->dbuf) != 4) return(0);
   if(sscanf(dest, "%1024[^.].%1024[^.].%1024[^.].%1024s",
	  it_ip->abuf_temp, it_ip->bbuf_temp, it_ip->cbuf_temp, it_ip->dbuf_temp) != 4) return(0);

   libnet_plist_chain_new(&it_ip->alist, it_ip->abuf_temp);
   libnet_plist_chain_new(&it_ip->blist, it_ip->bbuf_temp);
   libnet_plist_chain_new(&it_ip->clist, it_ip->cbuf_temp);
   libnet_plist_chain_new(&it_ip->dlist, it_ip->dbuf_temp);

   libnet_plist_chain_next_pair(it_ip->alist, &it_ip->start_a, &it_ip->end_a);
   libnet_plist_chain_next_pair(it_ip->blist, &it_ip->start_b, &it_ip->end_b);
   libnet_plist_chain_next_pair(it_ip->clist, &it_ip->start_c, &it_ip->end_c);
   libnet_plist_chain_next_pair(it_ip->dlist, &it_ip->start_d, &it_ip->end_d);


   if(it_ip->start_a > 255) it_ip->start_a = 255;
   if(it_ip->end_a > 255) it_ip->end_a = 255;
   if(it_ip->start_b > 255) it_ip->start_b = 255;
   if(it_ip->end_b > 255) it_ip->end_b = 255;
   if(it_ip->start_c > 255) it_ip->start_c = 255;
   if(it_ip->end_c > 255) it_ip->end_c = 255;
   if(it_ip->start_d > 255) it_ip->start_d = 255;
   if(it_ip->end_d > 255) it_ip->end_d = 255;

   it_ip->a = it_ip->start_a;
   it_ip->b = it_ip->start_b;
   it_ip->c = it_ip->start_c;
   it_ip->d = it_ip->start_d;

   it_ip->fencepost=0;

   return(1);
}

int pk_iterator_ip_getnext (struct pk_iterator_ip *it_ip)
{
   if(!it_ip->fencepost){
      it_ip->fencepost++;
      return(1);
   }

   if(it_ip->d < it_ip->end_d){
      it_ip->d++;
      return(1);
   } else {
      it_ip->d = it_ip->start_d;
      if(it_ip->c < it_ip->end_c){
         it_ip->c++;
         return(1);
      } else {
         it_ip->c = it_ip->start_c;
	 if(it_ip->b < it_ip->end_b){
	    it_ip->b++;
	    return(1);
	 } else {
	    it_ip->b = it_ip->start_b;
	    if(it_ip->a < it_ip->end_a){
	       it_ip->a++;
	       return(1);
	    } else {
	      return(0);
	      }
	    }
	   }
	}
  return(0);

}


int pk_sr_spew_tcp(struct pk_sr_conf *conf, struct frame *scanx)
{
   char abuf[1024], bbuf[1024], cbuf[1024], dbuf[1024], pbuf[1024], tbuf[1024], rbuf[1024], qbuf[1024];
   char abuf_temp[1024], bbuf_temp[1024], cbuf_temp[1024], dbuf_temp[1024], pbuf_temp[1024], tbuf_temp[1024], rbuf_temp[1024], qbuf_temp[1024];

   unsigned short a, b, c, d, ttl, q, start_a, end_a, start_b, end_b;
   unsigned short start_c, end_c, start_d, end_d, start_p, end_p;
   unsigned short start_ttl, end_ttl, start_q, end_q;
   unsigned int dport;

   int knownscan = 0;
   int flag = 0;

   int packetsleep;
   int sleepcount = 0;
   int sleepinterval = 1;

   int bps, ppq, ppq_counter, delay;
   double quanta = 0.1;

   struct timeval now, then, bench_pre, bench_post, diff;

   int i,j,source_port = ntohs(scanx->tcp->th_sport);
   int keep_ipid = 0;
   char buf[MX_B], buf2[MX_B];

   struct in_addr temp_ip;
   struct libnet_plist_chain *alist, *blist, *clist, *dlist, *plist, *tlist, *qlist;


   struct scanrand_report *report = malloc(sizeof(struct scanrand_report));
#include "pk_serv.h"

   conf->link->auto_checksums = 0;
   memset(report, sizeof(struct scanrand_report), 0);

   gettimeofday(&bench_pre, NULL);

   gettimeofday(&then, NULL);

   if(sscanf(conf->dest, "%1024[^.].%1024[^.].%1024[^.].%1024[^:]:%1024[^/]%1024s",
	  abuf, bbuf, cbuf, dbuf, pbuf, rbuf) != 6) return(0);
   if(sscanf(conf->dest, "%1024[^.].%1024[^.].%1024[^.].%1024[^:]:%1024[^/]%1024s",
	  abuf_temp, bbuf_temp, cbuf_temp, dbuf_temp, pbuf_temp, rbuf_temp) != 6) return(0);

   if(conf->rst_dist) scanx->ip->ip_ttl = 216;

   if(!conf->ttlrange){
   	conf->ttlrange = malloc(1024);
   	snprintf(conf->ttlrange, 1024, "%i-%i", scanx->ip->ip_ttl, scanx->ip->ip_ttl);
  }
   memcpy(tbuf_temp, conf->ttlrange, 1024);

   if(!conf->qosrange){
	conf->qosrange = malloc(1024);
	snprintf(conf->qosrange, 1024, "%i-%i", scanx->ip->ip_tos, scanx->ip->ip_tos);
  }
   memcpy(qbuf_temp, conf->qosrange, 1024);

   if(!strncmp(pbuf, "known", sizeof(pbuf))){
	   knownscan++;
	   snprintf(pbuf, sizeof(pbuf), "0-%i", 1149);
	   snprintf(pbuf_temp, sizeof(pbuf_temp), "%s", pbuf);
   }

   libnet_plist_chain_new(&alist, abuf_temp);
   while(libnet_plist_chain_next_pair(alist, &start_a, &end_a)){
    libnet_plist_chain_new(&blist, bbuf_temp);
    while(libnet_plist_chain_next_pair(blist, &start_b, &end_b)){
     libnet_plist_chain_new(&clist, cbuf_temp);
     while(libnet_plist_chain_next_pair(clist, &start_c, &end_c)){
      libnet_plist_chain_new(&dlist, dbuf_temp);
      while(libnet_plist_chain_next_pair(dlist, &start_d, &end_d)){
       libnet_plist_chain_new(&plist, pbuf_temp);
       while(libnet_plist_chain_next_pair(plist, &start_p, &end_p)){
         libnet_plist_chain_new(&tlist, tbuf_temp);
         while(libnet_plist_chain_next_pair(tlist, &start_ttl, &end_ttl)){
	   libnet_plist_chain_new(&qlist, qbuf_temp);
	   while(libnet_plist_chain_next_pair(qlist, &start_q, &end_q)){
          /* libnet_plist was meant for port lists, but we're hacking it
             to do IP/TTL lists as well.  Though an IP is 32 bytes, ports are
             16 bytes, and each range is an 8 byte range.  So, we clamp the
             iteration to an 8 byte range. */
          if(start_a > 255) start_a = 255;     if(end_a > 255) end_a = 255;
          if(start_b > 255) start_b = 255;     if(end_b > 255) end_b = 255;
          if(start_c > 255) start_c = 255;     if(end_c > 255) end_c = 255;
          if(start_d > 255) start_d = 255;     if(end_d > 255) end_d = 255;
          if(start_ttl > 255) start_ttl = 255; if(end_ttl > 255) end_ttl = 255;
	  if(start_q > 255) start_q = 255;     if(end_q > 255) end_q = 255;

          //fprintf(stderr, "%u-%u.%u-%u.%u-%u.%u-%u:%u-%u\n", start_a, end_a, start_b,
    	   //	   end_b, start_c, end_c, start_d, end_d, start_p, end_p);

          for(dport=start_p; dport<=end_p; dport++){
          for(d=start_d; d<=end_d; d++){
          for(c=start_c; c<=end_c; c++){
          for(b=start_b; b<=end_b; b++){
          for(a=start_a; a<=end_a; a++){
          for(ttl=start_ttl; ttl<=end_ttl; ttl++){
	  for(q=start_q; q<=end_q; q++){

	     gettimeofday(&now, NULL);
	     scanx->ip->ip_dst.s_addr = ntohl(a*256*256*256 + b*256*256 + c*256 + d);
             /*bzero(buf, sizeof(buf));
             snprintf(buf, sizeof(buf), "%u.%u.%u.%u", a, b, c, d);
             inet_aton(buf, &scanx->ip->ip_dst);*/ /* cheap trick */

	     scanx->ip->ip_ttl = ttl;
             scanx->ip->ip_id =  htons(ttl*256 + q); /* redundant hop capacity, for your convenience */
	     scanx->ip->ip_tos = q;

	     if(conf->rst_dist) scanx->tcp->th_flags = TH_ACK;


             if(knownscan){
		     scanx->tcp->th_dport = htons(knownports[dport].port);
	     } else scanx->tcp->th_dport = htons(dport);



	     //if(conf->bad_ip_sum) yarrow_read(&scanx->ip->ip_sum, 2, &conf->prng);
	     if(conf->bad_th_sum) yarrow_read(&scanx->tcp->th_sum, 2, &conf->prng);
	     gettimeofday(&now, NULL);

	     if(!conf->timescale){
	     	i=((now.tv_sec%6)*10000)+(now.tv_usec/100);
	     } else {
	        i=((now.tv_sec%65)*1000)+(now.tv_usec/1000);
	     }
	     scanx->tcp->th_sport=htons(i);

	     if(!conf->disable_seq){
        	     //scanx->tcp->th_sport = htons(source_port - 255 + ttl ); /* XXX i know, i know -- this needs to be time */
	             i=pk_bake_syncookie((u_char *)scanx->ip, conf->seed);
	             memcpy(&scanx->tcp->th_seq, &i, 4);
		     if(scanx->tcp->th_flags == TH_ACK) memcpy(&scanx->tcp->th_ack, &i, 4);
	     }


	     pk_recalc_checksums(scanx);
	     if(!conf->quiet_run) i=pk_spoof_framed(conf->link, 3, scanx);
	     else(fprintf(conf->output, "%i.%i.%i.%i:%u\n", a, b, c, d, ntohs(scanx->tcp->th_dport)));
	     sleepcount++;

	     if(conf->verbose>=1){
             	   gettimeofday(&now, NULL);
             	   pk_timeval_subtract(&diff, &now, &then);
		   if(scanx->tcp->th_flags != TH_RST) fprintf(stderr, "%s: %16.16s:%-5i [%2.2hu]", "SENT", inet_ntoa(scanx->ip->ip_dst), ntohs(scanx->tcp->th_dport), 0);
		   else                               fprintf(stderr, "%s: %16.16s:%-5i [%2.2hu]", " RST", inet_ntoa(scanx->ip->ip_dst), ntohs(scanx->tcp->th_dport), 0);

		   fprintf(stderr, "%4lu.%3.3lus", diff.tv_sec, diff.tv_usec/1000);
		   if(conf->resolve)fprintf(stderr, "(%35.35s)\n", libnet_host_lookup(scanx->ip->ip_dst.s_addr, 1));
		   else       fprintf(stderr, "\n"); /*fprintf(stdout, "(%29.29s)\n", buf); */
		}
             if(conf->verbose>=2){
             	fprintf(stderr, "Sent %i on %s:\n", i, conf->dev);
		pk_print_ip(scanx->ip);
		pk_print_tcp(scanx->tcp, 0);
             	//fprintf(stderr, " "); print_ip((char *)scanx->ip);
		//fprintf(stderr, " "); print_tcp((char *)scanx->tcp, 0);
		}

		report->frame = &scanx;
		report->conf = conf;
		report->hopcount = pk_estimate_hopcount(scanx->ip->ip_ttl);

		//report->diff = 0;
		report->diff.tv_sec = 0;
		report->diff.tv_usec = 0;

		report->target   = scanx->ip->ip_dst;
		report->receiver   = scanx->ip->ip_src;
		report->port = ntohs(scanx->tcp->th_dport);
		report->qos  = scanx->ip->ip_tos;
		snprintf(report->status, sizeof(report->status), "SENT");
		if(conf->log_sent)pk_sr_report_print(report);
		free(report);

	  }}}}}}}} /* all those for loops */
	  libnet_plist_chain_free(qlist);
	  memcpy(qbuf_temp, conf->qosrange, 1024);
         }libnet_plist_chain_free(tlist);
	  memcpy(tbuf_temp, conf->ttlrange, 1024);
	} libnet_plist_chain_free(plist);
	  memcpy(pbuf_temp, pbuf, sizeof(pbuf));
       }  libnet_plist_chain_free(dlist);
	  memcpy(dbuf_temp, dbuf, sizeof(dbuf));
      }   libnet_plist_chain_free(clist);
	  memcpy(cbuf_temp, cbuf, sizeof(bbuf));
     }    libnet_plist_chain_free(blist);
	  memcpy(bbuf_temp, bbuf, sizeof(cbuf));
    }     libnet_plist_chain_free(alist);
	  memcpy(abuf_temp, abuf, sizeof(abuf));

    return(1);
}


int pk_sr_recv(struct pk_sr_conf *conf)
{
   struct timeval now;
   int i;

   snprintf(conf->link->pfprogram, sizeof(conf->link->pfprogram), "tcp or icmp");

   gettimeofday(&now, NULL);
   gettimeofday(&conf->lastgood, NULL);
   while(!conf->timeout || (now.tv_sec < (conf->lastgood.tv_sec + conf->timeout))){
	//pk_sniff_dispatch(conf->link, 1000, pk_sr_report, conf);
	i=pk_sniff_getnext(conf->link);
	if(i>0) pk_sr_report(conf, &(conf->link->pkthdr), conf->link->packet);
	else usleep(20000);
	gettimeofday(&now, NULL);
   }
   conf->working--;

}

int pk_sr_force_seed(char *seed, char *forced_seed, int length, int *source_port)
{
	char buf[20];

	pk_sha1(seed, forced_seed, length);
	/* fix source_port */
      	 pk_sha1(buf, seed, 20);      /* if you understand how paranoid this is, */
         memcpy(&source_port, buf, 2);/* you get a cookie.  This process is so a */
                                      /* single seed is sufficient to sync ports.*/
	return(1);
}

