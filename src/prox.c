#include <libpaketto.h>


int main(int argc, char **argv)
{
	struct link *link;
	struct frame *scanx;
	int i;
	FILE *whatever;
	char buf[1024];
	char target[1024];
	
        setvbuf(stdout, NULL, _IONBF, 0);
	
	link = pk_link_preinit(NULL);
	snprintf(link->pfprogram, MX_B, "port 25 or port 1080 or port 8080");
	link->auto_checksums=1;
	pk_link_init(link);

	scanx = pk_build_generic_syn(NULL);
	pk_lookupdev_ip(link->dev, &scanx->ip->ip_src);
	scanx->ip->ip_src.s_addr = htonl(scanx->ip->ip_src.s_addr);
	scanx->tcp->th_sport = htons(8989);

	while(1){
	  i=pk_sniff_getnext(link);
	  if(i){
	    if(link->x.tcp->th_dport==htons(25) 
	    && link->x.tcp->th_flags==TH_SYN){

		scanx->ip->ip_dst.s_addr = link->x.ip->ip_src.s_addr;
		scanx->tcp->th_dport = htons(1080);
		pk_spoof_framed(link, 3, scanx);
		scanx->tcp->th_dport = htons(8080);
		pk_spoof_framed(link, 3, scanx);
		fprintf(stderr, "sent scan to %s\n", inet_ntoa(scanx->ip->ip_dst));
	   }
	    else if( link->x.tcp && link->x.tcp->th_flags==(TH_SYN|TH_ACK) && (link->x.tcp->th_sport==htons(1080) || link->x.tcp->th_sport == htons(8080))) {
		snprintf(target, sizeof(target), "%s", inet_ntoa(link->x.ip->ip_src));
		snprintf(buf, sizeof(buf), "if [ `iptables -L -n | grep %s | wc -l | tr -d \" \"` -lt 1 ]; then iptables -A INPUT --source %s -p tcp --destination-port 25 -j DROP 2> /dev/null; fi", target, target);
		fprintf(stderr, "%s", buf);

		whatever = popen(buf, "r");
		fclose(whatever);
		fprintf(stderr, "%s\n", inet_ntoa(link->x.ip->ip_src));
	   }

	  }
	}
}




