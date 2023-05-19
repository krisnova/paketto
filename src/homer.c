#include <linux/netfilter.h>
#include <libipq.h>
#include <stdio.h>
#include <libpaketto.h>
#include <ght_hash_table.h>

#define BUFSIZE 2048

enum {
	 PK_HR_LB_USE_SOURCE_PORT,
	 PK_HR_LB_USE_SOURCE_IP,
	 PK_HR_LB_USE_SOURCE_C,
	 PK_HR_LB_USE_SOURCE_B
};

void homer_usage()
{
   fprintf(stderr, "    HomeR %s:  Home Redirector for Experimental Bandwidth Brokering\n\n", VERSION);
   fprintf(stderr, "Component of:  Paketto Keiretsu %s;    Dan Kaminsky (dan@doxpara.com)\n", VERSION);
   fprintf(stderr, "       Usage:  homer [-T|-U port] [-l mode] [-tD] server1 server2...\n");
   fprintf(stderr, "     Options:  -T [port]: Redirect TCP traffic on this port\n");
   fprintf(stderr, "               -U [port]: Redirect UDP traffic on this port\n");
   fprintf(stderr,"                -l [mode]: Choose target anonymous server via mode:\n");
   fprintf(stderr,"                           1 = Client's Source Port   (Stateless)\n");
   fprintf(stderr,"                           2 = Client's Source IP     (Stateless)\n");
   fprintf(stderr,"                           3 = Client's Source Net(C) (Stateless)\n");
   fprintf(stderr,"                           4 = Client's Source Net(B) (Stateless)\n");
   fprintf(stderr,"                -t       : Track User Sessions\n");
   fprintf(stderr,"                -D       : Do not fork\n\n");
   fprintf(stderr,"NOTES:          Use \"iptables -L\" to view QUEUE forwards, and\n");
   fprintf(stderr,"                    \"iptables -F\" to clear them.\n");
   exit(1);
}

static void die(struct ipq_handle *h)
{
        ipq_perror("passer");
        ipq_destroy_handle(h);
        exit(1);
}

struct pk_hr_conf {
   int drop_acks;
   int verbose;
   struct in_addr *server_pool;
   int server_pool_size;
   int load_balancer;
   int track_sessions;
   int fork;

};

struct pk_hr_conf *pk_hr_conf_init(struct pk_hr_conf *conf)
{
	if(conf == NULL) {
	  conf = malloc(sizeof(struct pk_hr_conf));
	  memset(conf, 0, sizeof(struct pk_hr_conf));
	  }
	conf->fork=1;
	return conf;
}

int pk_hr_parse_options(int argc, char **argv, struct pk_hr_conf *conf)
{
   int opt;
   extern char *optarg;
   extern int   opterr;

   char buf[MX_B], buf2[MX_B];
   char protocol[MX_B];
   unsigned int  port;
   int i=0;


   while ((opt = getopt(argc, argv, "Dl:tT:U:")) != EOF) {
      switch (opt) {
	case 'D':
		conf->fork=0;
		break;
	case 'l':
		conf->load_balancer = atoi(optarg);
		break;
	case 't':
		conf->track_sessions++;
		break;
	case 'T':
		port = atoi(optarg);
		snprintf(buf, sizeof(buf), "iptables -D INPUT -p tcp --destination-port %i -j QUEUE 2> /dev/null", port);
		i=system(buf);
		if(i) i=system("modprobe iptable_filter");
		if(i) {
		   fprintf(stderr, "Unable to install iptable_filter module.\n");
		   exit(1);
		}
		snprintf(buf, sizeof(buf), "iptables -A INPUT -p tcp --destination-port %i -j QUEUE", port);
		i=system(buf);
		if(i){
		   fprintf(stderr, "Unable to execute iptables command successfully:\n%s\n", buf);
		   homer_usage();
		   }
		break;
	case 'U':
		port = atoi(optarg);
		snprintf(buf, sizeof(buf), "iptables -D INPUT -p udp --destination-port %i -j QUEUE", port);
		i=system(buf);
		if(i) i=system("modprobe iptable_filter");
		if(i) {
		   fprintf(stderr, "Unable to install iptable_filter module.\n");
		   exit(1);
		}
		snprintf(buf, sizeof(buf), "iptables -A INPUT -p udp --destination-port %i -j QUEUE", port);
		i=system(buf);
		if(i){
		   fprintf(stderr, "Unable to execute iptables command successfully:\n%s\n", buf);
		   homer_usage();
		   }
		break;
	default:
		homer_usage();
		break;
      }
   }

   if(!argv[optind]) homer_usage();
   while(argv[optind]){
	if(!conf->server_pool_size) {
		conf->server_pool = malloc(sizeof(struct in_addr));
		conf->server_pool_size = 1;
	} else {
		conf->server_pool_size++;
		conf->server_pool = realloc(conf->server_pool, sizeof(struct in_addr) * conf->server_pool_size);
	}
	conf->server_pool[conf->server_pool_size-1].s_addr = libnet_name_resolve(argv[optind], 1);
	optind++;
    }
}


int main(int argc, char **argv)
{
        int status;
        unsigned char buf[BUFSIZE];
        struct ipq_handle *h;
	ipq_packet_msg_t *m;
	struct frame x;
	struct in_addr test_ip, new_ip;
	int i,send;

	struct link *link;
	char src[1024], dst[1024];

	struct pk_hr_conf *conf;

	ght_hash_table_t *session_table;

	int total;

	struct timeval now, clean, report, diff;
	struct pk_ackmon_state *amstate;


	conf = pk_hr_conf_init(NULL);
	pk_hr_parse_options(argc, argv, conf);

	if(conf->fork && !conf->track_sessions) i=fork();
	if(i) exit(0);

	amstate = pk_ackmon_init(NULL);
	session_table = ght_create(1024);

	link = pk_link_init(NULL);

	conf->drop_acks = 0;
	conf->verbose   = 1;

	test_ip.s_addr = 0;

	gettimeofday(&clean, NULL);
	gettimeofday(&report, NULL);

        h = ipq_create_handle(0, PF_INET);
        if (!h)
                die(h);

        status = ipq_set_mode(h, IPQ_COPY_PACKET, BUFSIZE);
        if (status < 0)
                die(h);

        do{
                status = ipq_read(h, buf, BUFSIZE, 0);
                if (status < 0)
                        die(h);

                switch (ipq_message_type(buf)) {
                        case NLMSG_ERROR:
                                fprintf(stderr, "Received error message %d\n",
                                        ipq_get_msgerr(buf));
                                break;

                        case IPQM_PACKET: {
                                m = ipq_get_packet(buf);

				send=1;
				/* and now the fun begins */

				pk_parse_layers(m->payload, m->data_len, &x, 3, DLT_EN10MB, 0);
				if(x.ip && (!test_ip.s_addr || x.ip->ip_dst.s_addr == test_ip.s_addr)) {
					if(!test_ip.s_addr) test_ip.s_addr = x.ip->ip_dst.s_addr;
					if(x.tcp){
						if(conf->load_balancer == PK_HR_LB_USE_SOURCE_PORT) i=htons(x.tcp->th_sport);
						if(conf->load_balancer == PK_HR_LB_USE_SOURCE_IP)   i=htonl(x.ip->ip_src.s_addr);
						if(conf->load_balancer == PK_HR_LB_USE_SOURCE_C)    i=htonl(x.ip->ip_src.s_addr)/(2^8);
						if(conf->load_balancer == PK_HR_LB_USE_SOURCE_B)    i=htonl(x.ip->ip_src.s_addr)/(2^16);
						x.ip->ip_dst.s_addr = conf->server_pool[i % conf->server_pool_size].s_addr;

						if(conf->track_sessions) pk_ackmon(amstate, &x, 1, 30);

					} else if(x.udp) {
						if(conf->load_balancer == PK_HR_LB_USE_SOURCE_PORT) i=htons(x.udp->uh_sport);
						if(conf->load_balancer == PK_HR_LB_USE_SOURCE_IP)   i=htonl(x.ip->ip_src.s_addr);
						if(conf->load_balancer == PK_HR_LB_USE_SOURCE_C)    i=htonl(x.ip->ip_src.s_addr)/(2^8);
						if(conf->load_balancer == PK_HR_LB_USE_SOURCE_B)    i=htonl(x.ip->ip_src.s_addr)/(2^16);
						x.ip->ip_dst.s_addr = conf->server_pool[i % conf->server_pool_size].s_addr;
					} else if(x.icmp) {
						if(conf->load_balancer == PK_HR_LB_USE_SOURCE_PORT) i=PK_HR_LB_USE_SOURCE_IP;
						if(conf->load_balancer == PK_HR_LB_USE_SOURCE_IP)   i=htonl(x.ip->ip_src.s_addr);
						if(conf->load_balancer == PK_HR_LB_USE_SOURCE_C)    i=htonl(x.ip->ip_src.s_addr)/(2^8);
						if(conf->load_balancer == PK_HR_LB_USE_SOURCE_B)    i=htonl(x.ip->ip_src.s_addr)/(2^16);
						x.ip->ip_dst.s_addr = conf->server_pool[i % conf->server_pool_size].s_addr;
					}
				}
			}

				pk_recalc_checksums(&x);
				i=pk_spoof_framed(link, 3, &x);

                                status = ipq_set_verdict(h, m->packet_id,
                                                         NF_DROP, x.caplen, x.ip);


                                if (status < 0)
                                        die(h);
                                break;
                        default:
                                fprintf(stderr, "Unknown message type!\n");
                                break;
		}
        } while (1);

        ipq_destroy_handle(h);
        return 0;
}
