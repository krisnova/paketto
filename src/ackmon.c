#include <libpaketto.h>
#include <ght_hash_table.h>

int main(int argc, char **argv)
{
	int i;
	struct frame x;

	char src[MX_B], dst[MX_B];
	struct link *link;
	struct pk_ackmon_state *amstate;

	amstate = pk_ackmon_init(NULL);
	link  = pk_link_preinit(NULL);
	if(argv[1]) snprintf(link->dev, sizeof(link->dev), "%s", argv[1]);
	pk_link_init(link);

	while(1){
	 if(pk_sniff_getnext(link)){
	   if(pk_parse_layers_from_link(link, &x, 0) &&
	   x.tcp){
		pk_ackmon(amstate, &x, 1, 30);
		}
	 }
	}
}

