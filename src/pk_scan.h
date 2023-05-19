 #ifndef PK_SCAN
#define PK_SCAN
#ifndef MX_B
#define MX_B      8192
#endif

enum {
   PK_SR_MODE_HUMAN,
   PK_SR_MODE_SQL,
   PK_SR_MODE_CSV
};

#define DNS_MAGIC 65530

struct scanrand_report;

typedef int (*pk_sr_printer)(struct scanrand_report *);

#define PK_SR_FORK 0
#define PK_SR_NONBLOCK 1
struct pk_sr_conf
{
	char dest[MX_B];
	char *shortdest;
	char *dev;
	FILE *targets;
	char *targets_append[MX_B];
	char *targets_ports[MX_B];
	int targets_threadmax;
	int targets_offset;
	int targets_lines;
	int targets_sleep;
	char targets_filename[MX_B];
	long source_ip;
	int source_port;
	char *ttlrange;
	int resolve;
	int recv_packets;
	int send_packets;
	int show_accepted;
	int show_rejected;
	u_char seed[20];
	int force_seed;
	int timeout;
	char *bandwidth;
	int check_icmp_seq;
	int verbose;
	int rst_dist;
	int scanmode;
	struct link *link;
	pcap_handler *fp_reporter;
	pk_sr_printer *fp_printer;
	int self_malloc;
	FILE *output;
	struct timeval start, then, now;
	int working;
	int disable_seq;
	struct frame *scanx;
	int bad_ip_sum;
	int bad_th_sum;
	prng_state prng;
	int reportmode;
	char table[MX_B];
	int overload_thread;
	int overload_seconds;
	int timescale;
	char *qosrange;
	int quiet_run;
	struct timeval lastgood;
	int payload_size;
	char *payload;
	int log_sent;
};

struct scanrand_report{
	struct pk_sr_conf *conf;
	char status[5];
	struct in_addr target;
	struct in_addr receiver;
	unsigned short port;
	int hopcount;
	struct in_addr trace_src;
	struct in_addr trace_dst;
	struct in_addr trace_mid;
	int trace_hop;
	int original_qos;
	int qos;
	char *info;
	struct timeval diff;
	struct frame *frame;
};


int pk_scanrand(struct pk_sr_conf *conf);
struct pk_sr_conf *pk_sr_conf_init(struct pk_sr_conf *conf);
long pk_munch_syncookie(u_char *ipp, u_char *key);
int pk_parse_dest(char *dest, int length, char *shortdest, int multi);
unsigned int pk_parse_bw(char *bandwidth);
struct frame *pk_build_generic_syn(struct frame *x);
pcap_handler pk_sr_report(struct pk_sr_conf *conf, struct pcap_pkthdr *pkthdr, char *packet);
pk_sr_printer pk_sr_report_print(struct scanrand_report *report);
int pk_sr_send(struct pk_sr_conf *conf);
int pk_sr_spew_tcp(struct pk_sr_conf *conf, struct frame *scanx);
int pk_sr_recv(struct pk_sr_conf *conf);
int pk_sr_force_seed(char *seed, char *forced_seed, int length, int *source_port);
struct frame *pk_add_dns_query(struct frame *x, char *name, char *type);
struct frame *pk_build_generic_dns(struct frame *x, char *name, char *type);


struct pk_iterator_ip
{
   unsigned short start_a, end_a;
   unsigned short start_b, end_b;
   unsigned short start_c, end_c;
   unsigned short start_d, end_d;
   unsigned short a,b,c,d;

   char abuf[1024],abuf_temp[1024];
   char bbuf[1024],bbuf_temp[1024];
   char cbuf[1024],cbuf_temp[1024];
   char dbuf[1024],dbuf_temp[1024];

   struct libnet_plist_chain *alist, *blist, *clist, *dlist;

   char fencepost;
};

int pk_iterator_ip_getnext(struct pk_iterator_ip *it_ip);


#endif

