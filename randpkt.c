/*
 * randpkt.c
 * ---------
 * Creates random packet traces. Useful for debugging sniffers by testing
 * assumptions about the veracity of the data found in the packet.
 *
 * $Id: randpkt.c,v 1.7 2000/05/19 23:06:11 gram Exp $
 *
 * Copyright (C) 1999 by Gilbert Ramirez <gram@xiexie.org>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <time.h>
#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include "wiretap/wtap.h"

#define array_length(x)	(sizeof x / sizeof x[0])

/* Types of produceable packets */
enum {
	PKT_ARP,
	PKT_DNS,
	PKT_ETHERNET,
	PKT_FDDI,
	PKT_ICMP,
	PKT_IP,
	PKT_LLC,
	PKT_NBNS,
	PKT_TCP,
	PKT_TR,
	PKT_UDP
};

typedef struct {
	char	*abbrev;
	char	*longname;
	int	produceable_type;
	guint8	*sample_buffer;
	int	sample_wtap_encap;
	int	sample_length;
} pkt_example;

/* Ethernet, indicating ARP */
guint8 pkt_arp[] = {
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0x00, 0x00,
	0x32, 0x25, 0x0f, 0xff,
	0x08, 0x06
};

/* Ethernet+IP+UP, indicating DNS */
guint8 pkt_dns[] = {
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01,
	0x08, 0x00,

	0x45, 0x00, 0x00, 0x3c,
	0xc5, 0x9e, 0x40, 0x00,
	0xff, 0x11, 0xd7, 0xe0,
	0xd0, 0x15, 0x02, 0xb8,
	0x0a, 0x01, 0x01, 0x63,

	0x05, 0xe8, 0x00, 0x35,
	0x00, 0x00, 0x2a, 0xb9,
	0x30
};

/* Ethernet+IP, indicating ICMP */
guint8 pkt_icmp[] = {
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01,
	0x08, 0x00,

	0x45, 0x00, 0x00, 0x54,
	0x8f, 0xb3, 0x40, 0x00,
	0xfd, 0x01, 0x8a, 0x99,
	0xcc, 0xfc, 0x66, 0x0b,
	0xce, 0x41, 0x62, 0x12
};

/* Ethernet, indicating IP */
guint8 pkt_ip[] = {
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01,
	0x08, 0x00
};

/* TR, indicating LLC */
guint8 pkt_llc[] = {
	0x10, 0x40, 0x68, 0x00,
	0x19, 0x69, 0x95, 0x8b,
	0x00, 0x01, 0xfa, 0x68,
	0xc4, 0x67
};

/* Ethernet+IP+UP, indicating NBNS */
guint8 pkt_nbns[] = {
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01,
	0x08, 0x00,

	0x45, 0x00, 0x00, 0x3c,
	0xc5, 0x9e, 0x40, 0x00,
	0xff, 0x11, 0xd7, 0xe0,
	0xd0, 0x15, 0x02, 0xb8,
	0x0a, 0x01, 0x01, 0x63,

	0x00, 0x89, 0x00, 0x89,
	0x00, 0x00, 0x2a, 0xb9,
	0x30
};

/* TR+LLC+IP, indicating TCP */
guint8 pkt_tcp[] = {
	0x10, 0x40, 0x68, 0x00,
	0x19, 0x69, 0x95, 0x8b,
	0x00, 0x01, 0xfa, 0x68,
	0xc4, 0x67,

	0xaa, 0xaa, 0x03, 0x00,
	0x00, 0x00, 0x08, 0x00,

	0x45, 0x00, 0x00, 0x28,
	0x0b, 0x0b, 0x40, 0x00,
	0x20, 0x06, 0x85, 0x37,
	0xc0, 0xa8, 0x27, 0x01,
	0xc0, 0xa8, 0x22, 0x3c
};

/* Ethernet+IP, indicating UDP */
guint8 pkt_udp[] = {
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01,
	0x08, 0x00,

	0x45, 0x00, 0x00, 0x3c,
	0xc5, 0x9e, 0x40, 0x00,
	0xff, 0x11, 0xd7, 0xe0,
	0xd0, 0x15, 0x02, 0xb8,
	0x0a, 0x01, 0x01, 0x63
};

/* This little data table drives the whole program */
pkt_example examples[] = {
	{ "arp", "Address Resolution Protocol",
		PKT_ARP,	pkt_arp,	WTAP_ENCAP_ETHERNET,	array_length(pkt_arp) },

	{ "dns", "Domain Name Service",
		PKT_DNS,	pkt_dns,	WTAP_ENCAP_ETHERNET,	array_length(pkt_dns) },

	{ "eth", "Ethernet",
		PKT_ETHERNET,	NULL,		WTAP_ENCAP_ETHERNET,	0 },

	{ "fddi", "Fiber Distributed Data Interface",
		PKT_FDDI,	NULL,		WTAP_ENCAP_FDDI,	0 },

	{ "icmp", "Internet Control Message Protocol",
		PKT_ICMP,	pkt_icmp,	WTAP_ENCAP_ETHERNET,	array_length(pkt_icmp) },

	{ "ip", "Internet Protocol",
		PKT_IP,		pkt_ip,		WTAP_ENCAP_ETHERNET,	array_length(pkt_ip) },

	{ "llc", "Logical Link Control",
		PKT_LLC,	pkt_llc,	WTAP_ENCAP_TR,		array_length(pkt_llc) },

	{ "nbns", "NetBIOS-over-TCP Name Service",
		PKT_NBNS,	pkt_nbns,	WTAP_ENCAP_ETHERNET,	array_length(pkt_nbns) },

	{ "tcp", "Transmission Control Protocol",
		PKT_TCP,	pkt_tcp,	WTAP_ENCAP_TR,		array_length(pkt_tcp) },

	{ "tr",	 "Token-Ring",
		PKT_TR,		NULL,		WTAP_ENCAP_TR,		0 },

	{ "udp", "User Datagram Protocol",
		PKT_UDP,	pkt_udp,	WTAP_ENCAP_ETHERNET,	array_length(pkt_udp) }
};



static int parse_type(char *string);
static void usage(void);
static void seed(void);

static pkt_example* find_example(int type);

int
main(int argc, char **argv)
{

	wtap_dumper		*dump;
	struct wtap_pkthdr	pkthdr;
	union wtap_pseudo_header	ps_header;
	int 			i, j, len_this_pkt, len_random, err;
	guint8			buffer[65536];

	int			opt;
	extern char		*optarg;
	extern int		optind;

	int			produce_count = 1000; /* number of pkts to produce */
	int			produce_type = PKT_ETHERNET;
	char			*produce_filename = NULL;
	int			produce_max_bytes = 5000;
	pkt_example		*example;

	while ((opt = getopt(argc, argv, "b:c:t:")) != EOF) {
		switch (opt) {
			case 'b':	/* max bytes */
				produce_max_bytes = atoi(optarg);
				if (produce_max_bytes > 65536) {
					printf("Max bytes is 65536\n");
					exit(0);
				}
				break;

			case 'c':	/* count */
				produce_count = atoi(optarg);
				break;

			case 't':	/* type of packet to produce */
				produce_type = parse_type(optarg);
				break;

			default:
				usage();
				break;
		}
	}

	/* any more command line parameters? */
	if (argc > optind) {
		produce_filename = argv[optind];
	}
	else {
		usage();
	}

	example = find_example(produce_type);

	pkthdr.ts.tv_sec = 0;
	pkthdr.ts.tv_usec = 0;
	pkthdr.pkt_encap = example->sample_wtap_encap;

	dump = wtap_dump_open(produce_filename, WTAP_FILE_PCAP,
		example->sample_wtap_encap, produce_max_bytes, &err);

	seed();

	/* reduce max_bytes by # of bytes already in sample */
	if (produce_max_bytes <= example->sample_length) {
		printf("Sample packet length is %d, which is greater than or equal to\n", example->sample_length);
		printf("your requested max_bytes value of %d\n", produce_max_bytes);
		exit(0);
	}
	else {
		produce_max_bytes -= example->sample_length;
	}

	/* Load the sample into our buffer */
	if (example->sample_buffer)
		memcpy(&buffer[0], example->sample_buffer, example->sample_length);

	/* Produce random packets */
	for (i = 0; i < produce_count; i++) {
		if (produce_max_bytes > 0) {
			len_random = (rand() % produce_max_bytes + 1);
		}
		else {
			len_random = 0;
		}

		len_this_pkt = example->sample_length + len_random;

		pkthdr.caplen = len_this_pkt;
		pkthdr.len = len_this_pkt;
		pkthdr.ts.tv_sec = i; /* just for variety */

		for (j = example->sample_length; j < len_random; j++) {
			buffer[j] = (rand() % 0x100);
		}

		wtap_dump(dump, &pkthdr, &ps_header, &buffer[0], &err);
	}

	wtap_dump_close(dump, &err);

	return 0;

}

/* Print usage statement and exit program */
static
void usage(void)
{
	int	num_entries = array_length(examples);
	int	i;

	printf("Usage: randpkt [-b maxbytes] [-c count] [-t type] filename\n");
	printf("Default max bytes (per packet) is 5000\n");
	printf("Default count is 1000.\n");
	printf("Types:\n");

	for (i = 0; i < num_entries; i++) {
		printf("\t%s\t%s\n", examples[i].abbrev, examples[i].longname);
	}

	printf("\n");

	exit(0);
}

/* Parse command-line option "type" and return enum type */
static
int parse_type(char *string)
{
	int	num_entries = array_length(examples);
	int	i;

	for (i = 0; i < num_entries; i++) {
		if (strcmp(examples[i].abbrev, string) == 0) {
			return examples[i].produceable_type;
		}
	}

	/* default type */
	return PKT_ETHERNET;
}

/* Find pkt_example record and return pointer to it */
static
pkt_example* find_example(int type)
{
	int	num_entries = array_length(examples);
	int	i;

	for (i = 0; i < num_entries; i++) {
		if (examples[i].produceable_type == type) {
			return &examples[i];
		}
	}

	printf("Internal error. Type %d has no entry in examples table.\n", type);
	exit(0);
}

/* Seed the random-number generator */
void
seed(void)
{
	unsigned int	randomness;

#if defined(linux)
	/* Okay, I should use #ifdef HAVE_DEV_RANDOM, but this is a quick hack */
	int 		fd;

	fd = open("/dev/random", O_RDONLY);
	if (fd < 0) {
		printf("Could not open /dev/random for reading: %s\n", strerror(errno));
		exit(0);
	}

	read(fd, &randomness, sizeof(randomness));
#else
	time_t now;

	now = time(NULL);
	randomness = (unsigned int) now;
#endif

	srand(randomness);
}
