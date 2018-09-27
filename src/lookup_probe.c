#include "config.h"
#include "probes.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	probe *p;

	if (argc != 2)
		fprintf(stderr, "%s <probe id>\n", argv[0]);

	else if ((p = lookup_probe(atoi(argv[1])))) {
		printf("prb_id: %6d\n", (int)p->prb_id);
		printf("asn_v4: %6d\n", p->asn_v4);
		printf("asn_v6: %6d\n", p->asn_v6);
		printf("lat.  : %11.4f\n", p->latitude);
		printf("long. : %11.4f\n", p->longitude);
		if (p->cc_0) printf("CC    :     %c%c\n", p->cc_0, p->cc_1);
	} else 
		printf("probe %d not found\n", atoi(argv[1]));
	return 0;
}
