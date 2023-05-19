#include <libpaketto.h>
#include <pthread.h>

void pk_scanrand_usage();


int main(int argc, char **argv)
{
	int i;
	int bps, packetsize;
	float quanta;

	struct pk_sr_conf *conf = (void *)pk_sr_conf_init(NULL);

	pk_sr_parse_options(argc, argv, conf);

	setvbuf(stdout, NULL, _IONBF, 0);

	pk_scanrand(conf);
}



int pk_sr_parse_options(int argc, char **argv, struct pk_sr_conf *conf)
{
   int opt;
   extern char *optarg;
   extern int   opterr;

   int i;
   char buf[MX_B];

   int show_usage=0;

   while ((opt = getopt(argc, argv, "gVy:z:P:q:QO:d:f:i:l:NSLeEs:p:t:b:cCvT:DM:x:Hr")) != EOF) {
      switch (opt) {
	case 'V':
	   fprintf(stdout, "scanrand %s\n", VERSION);
	   exit(1);
	case 'g':
	   conf->log_sent = 1;
	   break;
	case 'y':
	   conf->targets_threadmax = atoi(optarg);
	   break;
	case 'z':
	   conf->targets_sleep = atoi(optarg);
	   break;
	case 'P':
	   conf->payload_size = atoi(optarg);
	   break;
	case 'Q':
	   conf->quiet_run = 1;
	   break;
	case 'q':
	   conf->qosrange = malloc(1024);
	   snprintf(conf->qosrange, 1024, "%s", optarg);
	   break;
        case 'r':
	   conf->timescale = 1;
	   break;
	/*case 'Q':
	   conf->disable_seq = 1;
	   break;*/
	case 'O':
	   conf->overload_seconds = atoi(optarg);
	   break;
        case 'd':
	   conf->dev = malloc(MX_B);
           snprintf(conf->dev, MX_B, "%s", optarg);
           break;
	case 'f':
	   i=sscanf(optarg, "%8192[^+]+%8192s", buf, conf->targets_append);
	   snprintf(conf->targets_filename, 1024, "%s", buf);
	   if(buf[0]=='-' && buf[1]=='\0') conf->targets = stdin;
	   else conf->targets = fopen(buf, "r");
	   break;
        case 'i':
           conf->source_ip = ntohl(libnet_name_resolve(optarg, 1));
           break;
	case 'l':
	   conf->ttlrange = malloc(1024);
	   snprintf(conf->ttlrange, 1024, "%s", optarg);
	   break;
	case 'N':
	   conf->resolve++;
	   break;
	case 'S':
	   conf->recv_packets = 0;
	   break;
	case 'L':
	   conf->send_packets = 0;
	   break;
        case 'e':
           conf->show_rejected=1;
           break;
        case 'E':
           conf->show_rejected=1;
           conf->show_accepted=0;
           break;
        case 's':
	   pk_sr_force_seed(conf->seed, optarg, strlen(optarg), &conf->source_port);
           break;
        case 'p':
           conf->source_port = atoi(optarg);
           break;
      	case 't':
      	   conf->timeout = atof(optarg);
      	   break;
        case 'b':
           snprintf(conf->link->bandwidth, MX_B, "%s", optarg);
           break;
	case 'c':
	   conf->check_icmp_seq = 1;
	   break;
	case 'C':
	   conf->check_icmp_seq = 0;
	   break;
	case 'v':
	   conf->verbose++;
	   break;
	case 'D':
	   conf->rst_dist++;
	   break;
	case 'M':
	   conf->reportmode = atoi(optarg);
	   break;
	case 'x':
//	   if(!strncmp(optarg, "ip_sum", 12)) conf->bad_ip_sum++;
	   if(!strncmp(optarg, "th_sum", 12)) conf->bad_th_sum++;
	   break;
	case 'T':
	   snprintf(conf->table, sizeof(conf->table), "%s", optarg);
	   break;
	case 'H':
	   show_usage++;
	   break;
	default:
      	   pk_scanrand_usage();
         }
         if(!conf->table[0]) snprintf(conf->table, sizeof(conf->table), "scanrand");
   }

   if(show_usage) fprintf(conf->output, "create table %s (abs_tv_sec integer unsigned, abs_tv_usec integer unsigned, rel_tv_sec integer unsigned, rel_tv_usec integer unsigned, stat char(5), src varchar(64), dst varchar(64), port integer unsigned, hopcount integer unsigned, trace_hop integer unsigned, original_qos integer unsigned, qos integer unsigned, trace_src varchar(64), trace_dst varchar(64), trace_mid varchar(64));\n", conf->table);

   if(argv[optind] != NULL)
   {
	conf->shortdest = argv[optind];
   }
   if(!conf->shortdest && !conf->targets && conf->send_packets && !show_usage) pk_scanrand_usage();
   return 0;
}

void pk_scanrand_usage()
{
   fprintf(stderr, "scanrand %s: Stateless TCP Scanner w/ Inverse SYN Cookies(HMAC-SHA1/32 in SEQ)\n", VERSION);
   fprintf(stderr, "Component of:  Paketto Keiretsu %s;    Dan Kaminsky  (dan@doxpara.com)\n", VERSION);
   fprintf(stderr,  "     Example:  scanrand 10.0.1.1-254:80,20-25,139\n");
   fprintf(stderr, "  Def. Ports:  Use  [quick/squick/known/all] instead of explicitly naming ports\n");
   fprintf(stderr, "     Options:  -S/-L:    Only send requests      / Only listen for responses\n");
   fprintf(stderr, "               -e/-E:    Show negative responses / Only show negative responses\n");
   fprintf(stderr, "               -t  [timeout]: Wait n full seconds for the last response   (10s)\n");
   fprintf(stderr, "               -b[bandwidth]: Limit bandwidth consumption to b/k/m/g bytes(100k)\n");
   fprintf(stderr, "                              (0 supresses timeouts or maximizes bw utilization)\n");
   fprintf(stderr, "               -N/-NN       : Enable name resolution (Prefer Source/Dest)\n");
   fprintf(stderr, "               -v           : Mark packets being sent, as well as received\n");
   fprintf(stderr, "               -vv          : Output full packet traces to stderr\n");
   fprintf(stderr, "  Addressing:  -d   [device]: Send requests from this L2 hardware device\n");
   fprintf(stderr, "               -i   [source]: Send requests from this L3 IP address\n");
   fprintf(stderr, "               -p   [  port]: Send requests from this L4 TCP Port\n");
   fprintf(stderr, "               -s   [  seed]: Use prespecified seed for scan verification\n");
   fprintf(stderr, "               -Q           : Quiet run -- output list of potential targets\n");
   fprintf(stderr, "               -f   [  file]: Read list of targets from file\n");
   fprintf(stderr, " Threading:    -y      [num]: Split file-based scan across n threads\n");
   fprintf(stderr, "               -z      [sec]: Delay initialization of each thread by n secs\n");
   fprintf(stderr, " Experiments:  -l  [ttl-ttl]: Statelessly TCP Traceroute\n");
   fprintf(stderr, "               -D           : Distco (Distance Discover) via forced RSTs\n");
   fprintf(stderr, "               -C           : Disable checking Inverse SYN Cookie on Traceroute\n");
//   fprintf(stderr, "               -x ip_sum    : Send invalid IP Checksum\n");
   fprintf(stderr, "               -x th_sum    : Send invalid TCP Checksum\n");
   fprintf(stderr, "               -T           : Select SQL Table Name (scanrand)\n");
   fprintf(stderr, "               -M1/2        : Print SQL(1) or CSV(2) output.\n");
   fprintf(stderr, "               -H           : Print SQL Schema\n");
   fprintf(stderr, "               -g           : Log sent packets\n");
   fprintf(stderr, "               -O sec       : Overload Protection (RST scans n seconds later)\n");
   fprintf(stderr, "               -r           : Increase range of latency measurement\n");
   fprintf(stderr, "               -q [tos-tos] : Set QoS/Diffserv values for outgoing packets\n");
   fprintf(stderr, "               -P [bytes]   : Add null payload to SYNs (for diff latencies)\n");
   fprintf(stderr, "       Notes:                 Use Control-C to exit before scanrand times out.\n");
   fprintf(stderr, "                              Be sure to use a longer timeout for slow scans!\n");
   fprintf(stderr, "                              [n]: estimated network distance from target host.\n");
   fprintf(stderr, "                              Use -b0 to disable bandwidth limitation\n");
   fprintf(stderr, "                              -q w/ -l discovers routers modding diffserv.\n");
   fprintf(stderr, "                              scanrand2 -Tfoo -H -M1 -b10k 10.0.1.1-254:quick\\\n");
   fprintf(stderr, "                              | mysql db # Basic syntax for outputting to mysql\n");
   exit(1);
}


