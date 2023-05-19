/*
 * This code is GPL.
 */

#include <linux/netfilter.h>
#include <libipq.h>
#include <stdio.h>
#include <libpaketto.h>

#define BUFSIZE 2048

struct pk_donut_conf {
   int track_sessions;
   int fork;
};

static void die(struct ipq_handle *h)
{
        ipq_perror("passer");
        ipq_destroy_handle(h);
        exit(1);
}

struct pk_donut_conf *pk_donut_conf_init(struct pk_donut_conf *conf)
{
	if(conf == NULL) {
	  conf = malloc(sizeof(struct pk_donut_conf));
	  memset(conf, 0, sizeof(struct pk_donut_conf));
	  }
	conf->fork=1;
	return conf;
}

void donut_usage()
{
   fprintf(stderr, "    DonuT %s:  Anonymous Spoofer for Experimental Bandwidth Brokering\n", VERSION);
   fprintf(stderr, "Component of:  Paketto Keiretsu %s;    Dan Kaminsky (dan@doxpara.com)\n", VERSION);
   fprintf(stderr, "       Usage:  homer [-T|-U port] [-tD] redirector\n");
   fprintf(stderr, "     Options:  -T [port]: Redirect TCP traffic on this port\n");
   fprintf(stderr, "               -U [port]: Redirect UDP traffic on this port\n");
   fprintf(stderr, "               -t       : Track User Sessions\n");
   fprintf(stderr, "               -D       : Do not fork\n\n");
   fprintf(stderr, "NOTES:         Use \"iptables -L\" to view QUEUE forwards, and\n");
   fprintf(stderr, "                   \"iptables -F\" to clear them.\n");
   exit(1);
}


int pk_donut_parse_options(int argc, char **argv, struct pk_donut_conf *conf)
{
   int opt;
   extern char *optarg;
   extern int   opterr;

   char buf[MX_B], buf2[MX_B];
   char protocol[MX_B];
   unsigned int  port;
   int i=0;


   while ((opt = getopt(argc, argv, "DtT:U:")) != EOF) {
      switch (opt) {
	case 'D':
		conf->fork=0;
		break;
	case 't':
		conf->track_sessions++;
		break;
	case 'T':
		port = atoi(optarg);
		snprintf(buf, sizeof(buf), "iptables -D OUTPUT -p tcp --source-port %hu -j QUEUE 2> /dev/null", port);
		i=system(buf);
		if(i) i=system("modprobe iptable_filter");
		if(i) {
		   fprintf(stderr, "Unable to install iptable_filter module.\n");
		   exit(1);
		}
		snprintf(buf, sizeof(buf), "iptables -A OUTPUT -p tcp --source-port %hu -j QUEUE", port);
		i=system(buf);
		if(i){
		   fprintf(stderr, "Unable to execute iptables command successfully:\n%s\n", buf);
		   donut_usage();
		   }
		break;
	case 'U':
		port = atoi(optarg);
		snprintf(buf, sizeof(buf), "iptables -D OUTPUT -p udp --source-port %i -j QUEUE", port);
		i=system(buf);
		if(i) i=system("modprobe iptable_filter");
		if(i) {
		   fprintf(stderr, "Unable to install iptable_filter module.\n");
		   exit(1);
		}
		snprintf(buf, sizeof(buf), "iptables -A OUTPUT -p udp --source-port %i -j QUEUE", port);
		i=system(buf);
		if(i){
		   fprintf(stderr, "Unable to execute iptables command successfully:\n%s\n", buf);
		   donut_usage();
		   }
		break;
	default:
		donut_usage();
		break;
      }
   }
   if(!argv[optind]) donut_usage();
}


int main(int argc, char **argv)
{
        int status;
        unsigned char buf[BUFSIZE];
        struct ipq_handle *h;
	struct frame x;
	struct in_addr test_ip;
	ipq_packet_msg_t *m;

	int i;

	struct timeval now, diff, clean, report;
	struct session_key key;
	struct session_state *session;
	ght_hash_table_t *session_table;
	struct pk_ackmon_state *amstate;

	struct pk_donut_conf *conf;

	conf = pk_donut_conf_init(NULL);
	pk_donut_parse_options(argc, argv, conf);

	if(conf->fork && !conf->track_sessions){
		i=fork();
		if(i) exit(1);
		}
	amstate = pk_ackmon_init(NULL);

	session_table = ght_create(1024);

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

				pk_parse_layers(m->payload, m->data_len, &x, 3, DLT_EN10MB, 0);
				if(x.ip) {
					x.ip->ip_src.s_addr = libnet_name_resolve(argv[optind], 1);
					pk_recalc_checksums(&x);
					if(1) {
						if(x.tcp && conf->track_sessions) pk_ackmon(amstate, &x, 1, 15);
				   	}
				}

                                status = ipq_set_verdict(h, m->packet_id,
                                                         NF_ACCEPT, m->data_len, m->payload);
                                if (status < 0)
                                        die(h);
                                break;
                        }

                        default:
                                fprintf(stderr, "Unknown message type!\n");
                                break;
                }
        } while (1);

        ipq_destroy_handle(h);
        return 0;
}
