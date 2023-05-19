#include <libpaketto.h>
enum
{
  PK_P2_SQL,
  PK_P2_CSV
};
struct pk_p2_conf
{
  int ip_string, ip_num;
  struct frame mask;
  struct pcap_pkthdr maskhdr;
  struct link *link;
  int pnum;
  int m_sa, m_sb, m_sc, m_sd;
  int m_da, m_db, m_dc, m_dd;
  int transaction_rate;
  int mode;
  char pfprogram[MX_B];
  int partial;
  int verbose;
  char tracefile[MX_B];
  char table[MX_B];
  int schema;
};
struct pk_p2_conf *
pk_p2_conf_init (struct pk_p2_conf *conf)
{
  if (conf == NULL)
    conf = malloc (sizeof (struct pk_p2_conf));
  memset (conf, 0, sizeof (struct pk_p2_conf));
  conf->ip_string = 1;
  conf->mask.ip = malloc (sizeof (struct libnet_ip_hdr));
  conf->mask.tcp = malloc (sizeof (struct libnet_tcp_hdr));
  snprintf (conf->table, sizeof (conf->table), "iptcp");
  memset (&conf->maskhdr.ts, 0xFF, sizeof (conf->maskhdr.ts));
  memset (conf->mask.ip, 0xFF, sizeof (struct libnet_ip_hdr));
  memset (conf->mask.tcp, 0xFF, sizeof (struct libnet_tcp_hdr));
  conf->ip_num = 0;
  return conf;
}

void
p2_usage ()
{
  fprintf (stderr, "packet2sql %s: Packet Translator\n", VERSION);
fprintf (stderr, "Component of:  Paketto Keiretsu %s;    Dan Kaminsky
	   (dan @ doxpara.com) \ n ", VERSION);
	   fprintf (stderr,
		      "     Options:  -M     [type]:  Translation Mode -- SQL
		      or CSV \ n ");
		      fprintf (stderr,
				 "               -c  [columns]:  Columns to output for
				 restricted view \ n ");
				 fprintf (stderr,
					    "               -p   [filter]:  Filter packets through
					    tcpdump expression \ n ");
					    exit (1);}
					  struct pk_p2_conf
					  *pk_p2_parse_options (int argc,
								char **argv,
								struct
								pk_p2_conf
								*conf)
					  {
					  int opt;
					  extern char *optarg;
					  extern int opterr;
					  char buf[MX_B], buf2[MX_B];
					  int i = 0;
					  char *ptr;
					  if (conf == NULL)
					  conf = pk_p2_conf_init (NULL);
					  while ((opt =
						  getopt (argc, argv,
							  "M:Ip:t:T:vc:s")) !=
						 EOF)
					  {
					  switch (opt)
					  {
case 'M':
if (!strncmp (optarg, "SQL", MX_B) || !strncmp (optarg, "sql", MX_B)) conf->mode = PK_P2_SQL; if (!strncmp (optarg, "CSV", MX_B) || !strncmp (optarg, "csv", MX_B)) conf->mode = PK_P2_CSV; break; case 'I':
					  if (conf->ip_string)
					  {
					  conf->ip_string = 0;
					  conf->ip_num = 1;}
					  else
					  {
					  conf->ip_string = 1;
					  conf->ip_num = 1;}
break; case 'p':
snprintf (conf->pfprogram, sizeof (conf->pfprogram), "%s", optarg); break; case 't':
snprintf (conf->table, sizeof (conf->table), "%s", optarg); break; case 'T':
conf->transaction_rate = atoi (optarg); break; case 'v':
conf->verbose++; break; case 'c':
					  if (!conf->partial)
					  {
					  memset (&conf->maskhdr.ts, 0,
						  sizeof (conf->maskhdr.ts));
					  memset (conf->mask.ip, 0,
						  sizeof (struct
							  libnet_ip_hdr));
					  memset (conf->mask.tcp, 0,
						  sizeof (struct
							  libnet_tcp_hdr));
					  conf->partial++;}
					  ptr = strtok (optarg, ",");
					  do
					  {
					  if (!strncmp (ptr, "pnum", MX_B))
					  conf->pnum++;
					  if (!strncmp (ptr, "tv_sec", MX_B))
					  conf->maskhdr.ts.tv_sec++;
					  if (!strncmp (ptr, "tv_usec", MX_B))
					  conf->maskhdr.ts.tv_usec++;
					  if (!strncmp (ptr, "ip_hl", MX_B))
					  conf->mask.ip->ip_hl++;
					  if (!strncmp (ptr, "ip_v", MX_B))
					  conf->mask.ip->ip_v++;
					  if (!strncmp (ptr, "ip_tos", MX_B))
					  conf->mask.ip->ip_tos++;
					  if (!strncmp (ptr, "ip_len", MX_B))
					  conf->mask.ip->ip_len++;
					  if (!strncmp (ptr, "ip_id", MX_B))
					  conf->mask.ip->ip_id++;
					  if (!strncmp (ptr, "ip_off", MX_B))
					  conf->mask.ip->ip_off++;
					  if (!strncmp (ptr, "ip_ttl", MX_B))
					  conf->mask.ip->ip_ttl++;
					  if (!strncmp (ptr, "ip_p", MX_B))
					  conf->mask.ip->ip_p++;
					  if (!strncmp (ptr, "ip_sum", MX_B))
					  conf->mask.ip->ip_sum++;
					  if (!strncmp (ptr, "ip_src", MX_B))
					  conf->mask.ip->ip_src.s_addr++;
					  if (!strncmp (ptr, "ip_dst", MX_B))
					  conf->mask.ip->ip_dst.s_addr++;
					  if (!strncmp (ptr, "sa", MX_B))
					  conf->m_sa++;
					  if (!strncmp (ptr, "sb", MX_B))
					  conf->m_sb++;
					  if (!strncmp (ptr, "sc", MX_B))
					  conf->m_sc++;
					  if (!strncmp (ptr, "sd", MX_B))
					  conf->m_sd++;
					  if (!strncmp (ptr, "da", MX_B))
					  conf->m_da++;
					  if (!strncmp (ptr, "db", MX_B))
					  conf->m_db++;
					  if (!strncmp (ptr, "dc", MX_B))
					  conf->m_dc++;
					  if (!strncmp (ptr, "dd", MX_B))
					  conf->m_dd++;
					  if (!strncmp
					      (ptr, "th_sport",
					       MX_B)) conf->mask.tcp->
					  th_sport++;
					  if (!strncmp
					      (ptr, "th_dport",
					       MX_B)) conf->mask.tcp->
					  th_dport++;
					  if (!strncmp (ptr, "th_seq", MX_B))
					  conf->mask.tcp->th_seq++;
					  if (!strncmp (ptr, "th_ack", MX_B))
					  conf->mask.tcp->th_ack++;
					  if (!strncmp (ptr, "th_x2", MX_B))
					  conf->mask.tcp->th_x2++;
					  if (!strncmp (ptr, "th_off", MX_B))
					  conf->mask.tcp->th_off++;
					  if (!strncmp
					      (ptr, "th_flags",
					       MX_B)) conf->mask.tcp->
					  th_flags++;
					  if (!strncmp (ptr, "th_win", MX_B))
					  conf->mask.tcp->th_win++;
					  if (!strncmp (ptr, "th_sum", MX_B))
					  conf->mask.tcp->th_sum++;
					  if (!strncmp (ptr, "th_urp", MX_B))
					  conf->mask.tcp->th_urp++;}
while (ptr = strtok (NULL, ",")); break; case 's':
conf->schema++; break; default:
					  p2_usage ();}
					  }
					  if (argv[optind])
					  snprintf (conf->tracefile,
						    sizeof (conf->tracefile),
						    "%s", argv[optind]);}
					  int main (int argc, char **argv)
					  {
					  int i = 0, j = 0;
					  struct link *link =
					  pk_link_preinit (NULL);
					  struct frame x;
					  unsigned char *ipsrc_b;
					  unsigned char *ipdst_b;
					  unsigned char table[MX_B];
					  char delim; struct pk_p2_conf *conf;
					  conf = pk_p2_conf_init (NULL);
					  conf->link = link;
					  pk_p2_parse_options (argc, argv,
							       conf);
					  if (conf->
					      tracefile) snprintf (link->
								   tracefile,
								   sizeof
								   (link->
								    tracefile),
								   conf->
								   tracefile);
					  if (conf->
					      pfprogram[0]) snprintf (link->
								      pfprogram,
								      sizeof
								      (link->
								       pfprogram),
								      conf->
								      pfprogram);
#define S_UINT8  "tinyint unsigned"
#define S_UINT16 "smallint unsigned"
#define S_UINT32 "int unsigned"
#define S_IP     "char(16)"
					  if (conf->schema)
					  {
					  fprintf (stdout,
						   "create table %s (",
						   conf->table);
					  if (conf->pnum) fprintf (stdout,
								   "%c%s %s",
								   delim,
								   "pnum",
								   S_UINT32)
					  && (delim = ',');
					  if (conf->maskhdr.ts.
					      tv_sec) fprintf (stdout,
							       "%c%s %s",
							       delim,
							       "tv_sec",
							       S_UINT32)
					  && (delim = ',');
					  if (conf->maskhdr.ts.
					      tv_usec) fprintf (stdout,
								"%c%s %s",
								delim,
								"tv_usec",
								S_UINT32)
					  && (delim = ',');
					  if (conf->mask.ip->
					      ip_hl) fprintf (stdout,
							      "%c%s %s",
							      delim, "ip_hl",
							      S_UINT8)
					  && (delim = ',');
					  if (conf->mask.ip->
					      ip_v) fprintf (stdout,
							     "%c%s %s", delim,
							     "ip_v", S_UINT8)
					  && (delim = ',');
					  if (conf->mask.ip->
					      ip_tos) fprintf (stdout,
							       "%c%s %s",
							       delim,
							       "ip_tos",
							       S_UINT8)
					  && (delim = ',');
					  if (conf->mask.ip->
					      ip_len) fprintf (stdout,
							       "%c%s %s",
							       delim,
							       "ip_len",
							       S_UINT16)
					  && (delim = ',');
					  if (conf->mask.ip->
					      ip_id) fprintf (stdout,
							      "%c%s %s",
							      delim, "ip_id",
							      S_UINT16)
					  && (delim = ',');
					  if (conf->mask.ip->
					      ip_off) fprintf (stdout,
							       "%c%s %s",
							       delim,
							       "ip_off",
							       S_UINT16)
					  && (delim = ',');
					  if (conf->mask.ip->
					      ip_ttl) fprintf (stdout,
							       "%c%s %s",
							       delim,
							       "ip_ttl",
							       S_UINT8)
					  && (delim = ',');
					  if (conf->mask.ip->
					      ip_p) fprintf (stdout,
							     "%c%s %s", delim,
							     "ip_p", S_UINT8)
					  && (delim = ',');
					  if (conf->mask.ip->
					      ip_sum) fprintf (stdout,
							       "%c%s %s",
							       delim,
							       "ip_sum",
							       S_UINT16)
					  && (delim = ',');
					  if (conf->ip_string)
					  {
					  if (conf->mask.ip->ip_src.s_addr)
					  fprintf (stdout, "%c%s %s", delim,
						   "ip_src", S_IP)
					  && (delim = ',');
					  if (conf->mask.ip->ip_dst.
					      s_addr) fprintf (stdout,
							       "%c%s %s",
							       delim,
							       "ip_dst", S_IP)
					  && (delim = ',');}
					  if (conf->ip_num)
					  {
					  if (conf->mask.ip->ip_src.s_addr)
					  fprintf (stdout, "%c%s %s,%s %s,%s
						   % s,
						   %s %
						   s ", delim, " sa
						   ", S_UINT8, " sb
						   ", S_UINT8, " sc
						   ", S_UINT8, " sd
						   ", S_UINT8);
						   if (conf->mask.ip->ip_dst.
						       s_addr)
						   fprintf (stdout,
							    "%c%s %s,%s %s,%s
							    % s,
							    %s %
							    s ", delim, " da
							    ", S_UINT8, " db
							    ", S_UINT8, " dc
							    ", S_UINT8, " dd
							    ", S_UINT8);}
							    if (conf->
								m_sa)
							    fprintf (stdout,
								     "%c%s %s",
								     delim,
								     "sa",
								     S_UINT8)
							    && (delim = ',');
							    if (conf->
								m_sb)
							    fprintf (stdout,
								     "%c%s %s",
								     delim,
								     "sb",
								     S_UINT8)
							    && (delim = ',');
							    if (conf->
								m_sc)
							    fprintf (stdout,
								     "%c%s %s",
								     delim,
								     "sc",
								     S_UINT8)
							    && (delim = ',');
							    if (conf->
								m_sd)
							    fprintf (stdout,
								     "%c%s %s",
								     delim,
								     "sd",
								     S_UINT8)
							    && (delim = ',');
							    if (conf->
								m_da)
							    fprintf (stdout,
								     "%c%s %s",
								     delim,
								     "da",
								     S_UINT8)
							    && (delim = ',');
							    if (conf->
								m_db)
							    fprintf (stdout,
								     "%c%s %s",
								     delim,
								     "db",
								     S_UINT8)
							    && (delim = ',');
							    if (conf->
								m_dc)
							    fprintf (stdout,
								     "%c%s %s",
								     delim,
								     "dc",
								     S_UINT8)
							    && (delim = ',');
							    if (conf->
								m_dd)
							    fprintf (stdout,
								     "%c%s %s",
								     delim,
								     "dd",
								     S_UINT8)
							    && (delim = ',');
							    if (conf->mask.
								tcp->
								th_sport)
							    fprintf (stdout,
								     "%c%s %s",
								     delim,
								     "th_sport",
								     S_UINT16)
							    && (delim = ',');
							    if (conf->mask.
								tcp->
								th_dport)
							    fprintf (stdout,
								     "%c%s %s",
								     delim,
								     "th_dport",
								     S_UINT16)
							    && (delim = ',');
							    if (conf->mask.
								tcp->
								th_seq)
							    fprintf (stdout,
								     "%c%s %s",
								     delim,
								     "th_seq",
								     S_UINT32)
							    && (delim = ',');
							    if (conf->mask.
								tcp->
								th_ack)
							    fprintf (stdout,
								     "%c%s %s",
								     delim,
								     "th_ack",
								     S_UINT32)
							    && (delim = ',');
							    if (conf->mask.
								tcp->
								th_x2)
							    fprintf (stdout,
								     "%c%s %s",
								     delim,
								     "th_x2",
								     S_UINT8)
							    && (delim = ',');
							    if (conf->mask.
								tcp->
								th_off)
							    fprintf (stdout,
								     "%c%s %s",
								     delim,
								     "th_off",
								     S_UINT8)
							    && (delim = ',');
							    if (conf->mask.
								tcp->
								th_flags)
							    fprintf (stdout,
								     "%c%s %s",
								     delim,
								     "th_flags",
								     S_UINT8)
							    && (delim = ',');
							    if (conf->mask.
								tcp->
								th_win)
							    fprintf (stdout,
								     "%c%s %s",
								     delim,
								     "th_win",
								     S_UINT16)
							    && (delim = ',');
							    if (conf->mask.
								tcp->
								th_sum)
							    fprintf (stdout,
								     "%c%s %s",
								     delim,
								     "th_sum",
								     S_UINT16)
							    && (delim = ',');
							    if (conf->mask.
								tcp->
								th_urp)
							    fprintf (stdout,
								     "%c%s %s",
								     delim,
								     "th_urp",
								     S_UINT16)
							    && (delim = ',');
							    fprintf (stdout,
								     ");\n");
							    if (conf->schema >
								1) exit (0);}
							    pk_link_init
							    (link);
							    if (conf->mode ==
								PK_P2_SQL
								&& conf->
								transaction_rate)
							    fprintf (stdout,
								     "BEGIN TRANSACTION;\n");
							    pcap_setnonblock
							    (link->pcap, 0,
							     global_error);
							    while
							    (pk_sniff_getnext
							     (link))
							    {
							    pk_parse_layers_from_link
							    (link, &x, 0);
							    if (x.tcp)
							    {
							    if (conf->pnum)
							    conf->pnum++;
							    delim = ' ';
							    ipsrc_b =
							    (unsigned char *)
							    &x.ip->ip_src;
							    ipdst_b =
							    (unsigned char *)
							    &x.ip->ip_dst;
							    if (conf->mode ==
								PK_P2_SQL)
							    fprintf (stdout,
								     "insert into %s values (",
								     conf->
								     table);
							    if (conf->
								pnum)
							    fprintf (stdout,
								     "%c%u",
								     delim,
								     conf->
								     pnum)
							    && (delim = ',');
							    if (conf->maskhdr.
								ts.
								tv_sec)
							    fprintf (stdout,
								     "%c%u",
								     delim,
								     link->
								     pkthdr.
								     ts.
								     tv_sec)
							    && (delim = ',');
							    if (conf->maskhdr.
								ts.
								tv_usec)
							    fprintf (stdout,
								     "%c%u",
								     delim,
								     link->
								     pkthdr.
								     ts.
								     tv_usec)
							    && (delim = ',');
							    if (conf->mask.
								ip->
								ip_hl)
							    fprintf (stdout,
								     "%c%u",
								     delim,
								     x.ip->
								     ip_hl)
							    && (delim = ',');
							    if (conf->mask.
								ip->
								ip_v)
							    fprintf (stdout,
								     "%c%u",
								     delim,
								     x.ip->
								     ip_v)
							    && (delim = ',');
							    if (conf->mask.
								ip->
								ip_tos)
							    fprintf (stdout,
								     "%c%u",
								     delim,
								     x.ip->
								     ip_tos)
							    && (delim = ',');
							    if (conf->mask.
								ip->
								ip_len)
							    fprintf (stdout,
								     "%c%hu",
								     delim,
								     ntohs (x.
									    ip->
									    ip_len))
							    && (delim = ',');
							    if (conf->mask.
								ip->
								ip_id)
							    fprintf (stdout,
								     "%c%hu",
								     delim,
								     ntohs (x.
									    ip->
									    ip_id))
							    && (delim = ',');
							    if (conf->mask.
								ip->
								ip_off)
							    fprintf (stdout,
								     "%c%hu",
								     delim,
								     ntohs (x.
									    ip->
									    ip_off))
							    && (delim = ',');
							    if (conf->mask.
								ip->
								ip_ttl)
							    fprintf (stdout,
								     "%c%u",
								     delim,
								     x.ip->
								     ip_ttl)
							    && (delim = ',');
							    if (conf->mask.
								ip->
								ip_p)
							    fprintf (stdout,
								     "%c%u",
								     delim,
								     x.ip->
								     ip_p)
							    && (delim = ',');
							    if (conf->mask.
								ip->
								ip_sum)
							    fprintf (stdout,
								     "%c%hu",
								     delim,
								     ntohs (x.
									    ip->
									    ip_sum))
							    && (delim = ',');
							    if (conf->
								ip_string)
							    {
							    if (conf->mode ==
								PK_P2_SQL)
							    {
							    if (conf->mask.
								ip->ip_src.
								s_addr)
							    fprintf (stdout,
								     "%c'%s'",
								     delim,
								     inet_ntoa
								     (x.ip->
								      ip_src))
							    && (delim = ',');
							    if (conf->mask.
								ip->ip_dst.
								s_addr)
							    fprintf (stdout,
								     "%c'%s'",
								     delim,
								     inet_ntoa
								     (x.ip->
								      ip_dst))
							    && (delim = ',');}
							    else
							    if (conf->mode ==
								PK_P2_CSV)
							    {
							    if (conf->mask.
								ip->ip_src.
								s_addr)
							    fprintf (stdout,
								     "%c%s",
								     delim,
								     inet_ntoa
								     (x.ip->
								      ip_src))
							    && (delim = ',');
							    if (conf->mask.
								ip->ip_dst.
								s_addr)
							    fprintf (stdout,
								     "%c%s",
								     delim,
								     inet_ntoa
								     (x.ip->
								      ip_dst))
							    && (delim = ',');}
							    }
							    if (conf->ip_num)
							    {
							    if (conf->mask.
								ip->ip_src.
								s_addr)
							    fprintf (stdout,
								     "%c%hu,%hu,%hu,%hu",
								     delim,
								     ipsrc_b
								     [0],
								     ipsrc_b
								     [1],
								     ipsrc_b
								     [2],
								     ipsrc_b
								     [3])
							    && (delim = ',');
							    if (conf->mask.
								ip->ip_dst.
								s_addr)
							    fprintf (stdout,
								     "%c%hu,%hu,%hu,%hu",
								     delim,
								     ipdst_b
								     [0],
								     ipdst_b
								     [1],
								     ipdst_b
								     [2],
								     ipdst_b
								     [3])
							    && (delim = ',');}
							    if (conf->
								m_sa)
							    fprintf (stdout,
								     "%c%hu",
								     delim,
								     ipsrc_b
								     [0])
							    && (delim = ',');
							    if (conf->
								m_sb)
							    fprintf (stdout,
								     "%c%hu",
								     delim,
								     ipsrc_b
								     [1])
							    && (delim = ',');
							    if (conf->
								m_sc)
							    fprintf (stdout,
								     "%c%hu",
								     delim,
								     ipsrc_b
								     [2])
							    && (delim = ',');
							    if (conf->
								m_sd)
							    fprintf (stdout,
								     "%c%hu",
								     delim,
								     ipsrc_b
								     [3])
							    && (delim = ',');
							    if (conf->
								m_da)
							    fprintf (stdout,
								     "%c%hu",
								     delim,
								     ipdst_b
								     [0])
							    && (delim = ',');
							    if (conf->
								m_db)
							    fprintf (stdout,
								     "%c%hu",
								     delim,
								     ipdst_b
								     [1])
							    && (delim = ',');
							    if (conf->
								m_dc)
							    fprintf (stdout,
								     "%c%hu",
								     delim,
								     ipdst_b
								     [2])
							    && (delim = ',');
							    if (conf->
								m_dd)
							    fprintf (stdout,
								     "%c%hu",
								     delim,
								     ipdst_b
								     [3])
							    && (delim = ',');
							    if (conf->mask.
								tcp->
								th_sport)
							    fprintf (stdout,
								     "%c%hu",
								     delim,
								     ntohs (x.
									    tcp->
									    th_sport))
							    && (delim = ',');
							    if (conf->mask.
								tcp->
								th_dport)
							    fprintf (stdout,
								     "%c%hu",
								     delim,
								     ntohs (x.
									    tcp->
									    th_dport))
							    && (delim = ',');
							    if (conf->mask.
								tcp->
								th_seq)
							    fprintf (stdout,
								     "%c%hu",
								     delim,
								     ntohs (x.
									    tcp->
									    th_seq))
							    && (delim = ',');
							    if (conf->mask.
								tcp->
								th_ack)
							    fprintf (stdout,
								     "%c%hu",
								     delim,
								     ntohs (x.
									    tcp->
									    th_ack))
							    && (delim = ',');
							    if (conf->mask.
								tcp->
								th_x2)
							    fprintf (stdout,
								     "%c%u",
								     delim,
								     x.tcp->
								     th_x2)
							    && (delim = ',');
							    if (conf->mask.
								tcp->
								th_off)
							    fprintf (stdout,
								     "%c%u",
								     delim,
								     x.tcp->
								     th_off)
							    && (delim = ',');
							    if (conf->mask.
								tcp->
								th_flags)
							    fprintf (stdout,
								     "%c%u",
								     delim,
								     x.tcp->
								     th_flags)
							    && (delim = ',');
							    if (conf->mask.
								tcp->
								th_win)
							    fprintf (stdout,
								     "%c%hu",
								     delim,
								     ntohs (x.
									    tcp->
									    th_win))
							    && (delim = ',');
							    if (conf->mask.
								tcp->
								th_sum)
							    fprintf (stdout,
								     "%c%hu",
								     delim,
								     ntohs (x.
									    tcp->
									    th_sum))
							    && (delim = ',');
							    if (conf->mask.
								tcp->
								th_urp)
							    fprintf (stdout,
								     "%c%hu",
								     delim,
								     ntohs (x.
									    tcp->
									    th_urp))
							    && (delim = ',');
							    if (conf->mode ==
								PK_P2_SQL)
							    fprintf (stdout,
								     ");");
							    fprintf (stdout,
								     "\n");
							    j++; i++;
							    if (i == 1000)
							    {
							    fprintf (stderr,
								     "%i INSERTs completed\n",
								     j);
							    i = 0;}
							    }
							    }
							    if (conf->mode ==
								PK_P2_SQL
								&& conf->
								transaction_rate)
							    fprintf (stdout,
								     "COMMIT;");}
