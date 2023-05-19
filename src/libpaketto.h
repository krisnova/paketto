#ifndef LIB_PAKETTO
#define LIB_PAKETTO

#include "config.h"
#include <stdio.h>
#include <pthread.h>
#include <pcap.h>
#include <libnet.h>
#include <mycrypt.h>
#include <ght_hash_table.h>

#include "pk_scan.h"
#include "base64.h"

#ifndef NULL
#define NULL 0
#endif


#if defined(WIN32) && !defined(__MINGW32__) && 1
#include "getopt.h"
#else
#include <getopt.h>
#endif

#ifndef EXIT_FAILURE
#define EXIT_FAILURE 1
#endif

/* UNIX ONLY INCLUDES */
#ifndef WIN32

#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif
#ifdef HAVE_SYS_IOCCOM_H
//#include <sys/ioccom.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#define MX_B 8192
#define HEX_WIDTH 76
#define TCPDUMP_MAGIC 0xa1b2c3d4
#define PATCHED_TCPDUMP_MAGIC 0xa1b2cd34
#ifndef MX_B
#define MX_B      8192
#endif
#ifndef IPV4_ADDR_LEN
#define IPV4_ADDR_LEN 4
#endif

#ifndef MAGIC
#define MAGIC 12341212
#endif

#endif
#endif

//#include "d_services.h"

char global_error[MX_B];

struct pk_ipopt
{
	unsigned char type;
	struct {
		unsigned char length;
		unsigned char pointer;
#if (LIBNET_LIL_ENDIAN)
		unsigned char overflow:4,flag:4;
#endif
#if (LIBNET_BIG_ENDIAN)
		unsigned char flag:4,overflow:4;
#endif
		unsigned int data[8];
	};
}__attribute__ ((packed));





struct frame
{
	struct libnet_ethernet_hdr *eth;
	struct libnet_ip_hdr *ip;
	struct pk_ipopt *ipopt;
	struct libnet_tcp_hdr *tcp;
	struct libnet_arp_hdr *arp;
	struct libnet_icmp_hdr *icmp;
	struct libnet_udp_hdr *udp;
	struct libnet_dns_hdr *dns;
	char   *packet;
	int    len;
	int    caplen;
	struct timeval ts;
	int    forcelen;
	int    l2_offset;
}__attribute__ ((packed));

struct link
{
	char            dev[MX_B];
	char		tracefile[MX_B];
	char		error[MX_B];

	int self_malloc;
	int flag;

	/* PCAP SNIFFER COMPONENTS */
	pcap_t         *pcap;	/* PCAP descriptor */
	u_char         *packet;	/* Our newly captured packet */
	struct pcap_pkthdr pkthdr;	/* PCAP packet information structure */
	struct bpf_program fp;	/* Structure to hold the compiled prog */
	char            pfprogram[MX_B];
	char 		pfprogram_loaded[MX_B];
	struct pcap_dumper_t *dump;
	int 		datalink;

	/* LIBNET SPOOFER COMPONENTS */
	char buf[2048];
	struct libnet_link_int *l2_spoofer;
	int l3_spoofer;
	int auto_checksums;
	int auto_frame;
	struct frame x;

	/* RATE LIMIT COMPONENTS */
	int sleepcount;
        int packetsleep;
	int sleepinterval;
	char bandwidth[MX_B];
	struct timeval bench_pre, bench_post;
};

struct session_key {
  struct in_addr ip_src;
  struct in_addr ip_dst;
  unsigned int th_sport;
  unsigned int th_dport;
};

struct session_state {
   unsigned int th_seq_isn;
   unsigned int th_ack_isn;
   unsigned int th_seq_max;
   unsigned int th_ack_max;
   struct timeval last_seen;
   struct timeval then;
   struct timeval start;
   struct timeval last_monitor;
   unsigned int counter_in;
   unsigned int counter_out;
   struct session_key key;
};




struct pk_ackmon_state
{
	ght_hash_table_t *session_table;
	struct timeval clean, report;
};






int pk_parse_layers(char *packet, int length, struct frame *x,
                 int input_layer, int datalink, int allow_short_tcp);


int pk_sniff_dispatch(struct link *link, float timeout, pcap_handler *handler, void *params);
char* pk_lookupdev(char *error);
void pk_print_ip(void *target);
void pk_print_tcp(void *target, int short_tcp);
struct link *pk_link_preinit(struct link *link);
struct link *pk_link_init(struct link *link);
int pk_sr_parse_options(int argc, char **argv, struct pk_sr_conf *conf);



