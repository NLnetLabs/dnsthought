#include "config.h"
#include "ranges.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

int main(int argc, char **argv)
{
	uint8_t addr[16];
	int asn;

	if (argc != 2)
		fprintf(stderr, "%s <ip address>\n", argv[0]);
	else if (strchr(argv[1], ':')) {
		inet_pton(AF_INET6, argv[1], addr);
		asn = lookup_asn6(addr);
		printf("%d\n", asn);
	} else {
		inet_pton(AF_INET, argv[1], addr);
		asn = lookup_asn4(addr);
		printf("%d\n", asn);
	}
	return 0;
}
