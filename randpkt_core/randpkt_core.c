/*
 * randpkt_core.c
 * ---------
 * Creates random packet traces. Useful for debugging sniffers by testing
 * assumptions about the veracity of the data found in the packet.
 *
 * Copyright (C) 1999 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#define WS_LOG_DOMAIN "randpkt"

#include "randpkt_core.h"

#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <wsutil/array.h>
#include <wsutil/file_util.h>
#include <wsutil/wslog.h>
#include <wiretap/wtap_opttypes.h>

#include "ui/failure_message.h"

#define INVALID_LEN 1
#define WRITE_ERROR 2

GRand *pkt_rand;

/* Types of produceable packets */
enum {
	PKT_ARP,
	PKT_BGP,
	PKT_BVLC,
	PKT_DNS,
	PKT_ETHERNET,
	PKT_FDDI,
	PKT_GIOP,
	PKT_ICMP,
	PKT_IEEE802154,
	PKT_IP,
	PKT_IPv6,
	PKT_LLC,
	PKT_M2M,
	PKT_MEGACO,
	PKT_NBNS,
	PKT_NCP2222,
	PKT_SCTP,
	PKT_SYSLOG,
	PKT_TCP,
	PKT_TDS,
	PKT_TR,
	PKT_UDP,
	PKT_USB,
	PKT_USB_LINUX
};

/* Ethernet, indicating ARP */
uint8_t pkt_arp[] = {
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0x00, 0x00,
	0x32, 0x25, 0x0f, 0xff,
	0x08, 0x06
};

/* Ethernet+IP+UDP, indicating DNS */
uint8_t pkt_dns[] = {
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
	0xff, 0xff, 0x2a, 0xb9,
	0x30
};

/* Ethernet+IP, indicating ICMP */
uint8_t pkt_icmp[] = {
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
uint8_t pkt_ip[] = {
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01,
	0x08, 0x00
};

/* Ethernet, indicating IPv6 */
uint8_t pkt_ipv6[] = {
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01,
	0x86, 0xdd, 0x60
};

/* TR, indicating LLC */
uint8_t pkt_llc[] = {
	0x10, 0x40, 0x68, 0x00,
	0x19, 0x69, 0x95, 0x8b,
	0x00, 0x01, 0xfa, 0x68,
	0xc4, 0x67
};

/* Ethernet, indicating WiMAX M2M */
uint8_t pkt_m2m[] = {
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0x00, 0x00,
	0x32, 0x25, 0x0f, 0xff,
	0x08, 0xf0
};

/* Ethernet+IP+UDP, indicating NBNS */
uint8_t pkt_nbns[] = {
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

/* Ethernet+IP+UDP, indicating syslog */
uint8_t pkt_syslog[] = {
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01,
	0x08, 0x00,

	0x45, 0x00, 0x00, 0x64,
	0x20, 0x48, 0x00, 0x00,
	0xfc, 0x11, 0xf8, 0x03,
	0xd0, 0x15, 0x02, 0xb8,
	0x0a, 0x01, 0x01, 0x63,

	0x05, 0xe8, 0x02, 0x02,
	0x00, 0x50, 0x51, 0xe1,
	0x3c
};

/* TR+LLC+IP, indicating TCP */
uint8_t pkt_tcp[] = {
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
uint8_t pkt_udp[] = {
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

/* Ethernet+IP+UDP, indicating BVLC */
uint8_t pkt_bvlc[] = {
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01,
	0x08, 0x00,

	0x45, 0x00, 0x00, 0x3c,
	0xc5, 0x9e, 0x40, 0x00,
	0xff, 0x11, 0x01, 0xaa,
	0xc1, 0xff, 0x19, 0x1e,
	0xc1, 0xff, 0x19, 0xff,
	0xba, 0xc0, 0xba, 0xc0,
	0x00, 0xff, 0x2d, 0x5e,
	0x81
};

/* TR+LLC+IPX, indicating NCP, with NCP Type == 0x2222 */
uint8_t pkt_ncp2222[] = {
	0x10, 0x40, 0x00, 0x00,
	0xf6, 0x7c, 0x9b, 0x70,
	0x68, 0x00, 0x19, 0x69,
	0x95, 0x8b, 0xe0, 0xe0,
	0x03, 0xff, 0xff, 0x00,
	0x25, 0x02, 0x11, 0x00,
	0x00, 0x74, 0x14, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x01, 0x04, 0x51, 0x00,
	0x00, 0x00, 0x04, 0x00,
	0x02, 0x16, 0x19, 0x7a,
	0x84, 0x40, 0x01, 0x22,
	0x22
};

/* Ethernet+IP+TCP, indicating GIOP */
uint8_t pkt_giop[] = {
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01,
	0x08, 0x00,

	0x45, 0x00, 0x00, 0xa6,
	0x00, 0x2f, 0x40, 0x00,
	0x40, 0x06, 0x3c, 0x21,
	0x7f, 0x00, 0x00, 0x01,
	0x7f, 0x00, 0x00, 0x01,

	0x30, 0x39, 0x04, 0x05,
	0xac, 0x02, 0x1e, 0x69,
	0xab, 0x74, 0xab, 0x64,
	0x80, 0x18, 0x79, 0x60,
	0xc4, 0xb8, 0x00, 0x00,
	0x01, 0x01, 0x08, 0x0a,
	0x00, 0x00, 0x48, 0xf5,
	0x00, 0x00, 0x48, 0xf5,

	0x47, 0x49, 0x4f, 0x50,
	0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x30,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01,
	0x01
};

/* Ethernet+IP+TCP, indicating BGP */
uint8_t pkt_bgp[] = {
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01,
	0x08, 0x00,

	0x45, 0x00, 0x00, 0xa6,
	0x00, 0x2f, 0x40, 0x00,
	0x40, 0x06, 0x3c, 0x21,
	0x7f, 0x00, 0x00, 0x01,
	0x7f, 0x00, 0x00, 0x01,

	0x30, 0x39, 0x00, 0xb3,
	0xac, 0x02, 0x1e, 0x69,
	0xab, 0x74, 0xab, 0x64,
	0x80, 0x18, 0x79, 0x60,
	0xc4, 0xb8, 0x00, 0x00,
	0x01, 0x01, 0x08, 0x0a,
	0x00, 0x00, 0x48, 0xf5,
	0x00, 0x00, 0x48, 0xf5,

	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
};

/* Ethernet+IP+TCP, indicating TDS NetLib */
uint8_t pkt_tds[] = {
	0x00, 0x50, 0x8b, 0x0d,
	0x7a, 0xed, 0x00, 0x08,
	0xa3, 0x98, 0x39, 0x81,
	0x08, 0x00,

	0x45, 0x00, 0x03, 0x8d,
	0x90, 0xd4, 0x40, 0x00,
	0x7c, 0x06, 0xc3, 0x1b,
	0xac, 0x14, 0x02, 0x22,
	0x0a, 0xc2, 0xee, 0x82,

	0x05, 0x99, 0x08, 0xf8,
	0xff, 0x4e, 0x85, 0x46,
	0xa2, 0xb4, 0x42, 0xaa,
	0x50, 0x18, 0x3c, 0x28,
	0x0f, 0xda, 0x00, 0x00,
};

/* Ethernet+IP, indicating SCTP */
uint8_t pkt_sctp[] = {
	0x00, 0xa0, 0x80, 0x00,
	0x5e, 0x46, 0x08, 0x00,
	0x03, 0x4a, 0x00, 0x35,
	0x08, 0x00,

	0x45, 0x00, 0x00, 0x7c,
	0x14, 0x1c, 0x00, 0x00,
	0x3b, 0x84, 0x4a, 0x54,
	0x0a, 0x1c, 0x06, 0x2b,
	0x0a, 0x1c, 0x06, 0x2c,
};


/* Ethernet+IP+SCTP, indicating MEGACO */
uint8_t pkt_megaco[] = {
	0x00, 0xa0, 0x80, 0x00,
	0x5e, 0x46, 0x08, 0x00,
	0x03, 0x4a, 0x00, 0x35,
	0x08, 0x00,

	0x45, 0x00, 0x00, 0x7c,
	0x14, 0x1c, 0x00, 0x00,
	0x3b, 0x84, 0x4a, 0x54,
	0x0a, 0x1c, 0x06, 0x2b,
	0x0a, 0x1c, 0x06, 0x2c,

	0x40, 0x00, 0x0b, 0x80,
	0x00, 0x01, 0x6f, 0x0a,
	0x6d, 0xb0, 0x18, 0x82,
	0x00, 0x03, 0x00, 0x5b,
	0x28, 0x02, 0x43, 0x45,
	0x00, 0x00, 0xa0, 0xbd,
	0x00, 0x00, 0x00, 0x07,
};

/* This little data table drives the whole program */
static randpkt_example examples[] = {
	{ "arp", "Address Resolution Protocol",
		PKT_ARP,	WTAP_ENCAP_ETHERNET,
		pkt_arp,	array_length(pkt_arp),
		NULL,		0,
		NULL,		NULL,
		1000,
	},

	{ "bgp", "Border Gateway Protocol",
		PKT_BGP,	WTAP_ENCAP_ETHERNET,
		pkt_bgp,	array_length(pkt_bgp),
		NULL,		0,
		NULL,		NULL,
		1000,
	},

	{ "bvlc", "BACnet Virtual Link Control",
		PKT_BVLC,	WTAP_ENCAP_ETHERNET,
		pkt_bvlc,	array_length(pkt_bvlc),
		NULL,		0,
		NULL,		NULL,
		1000,
	},

	{ "dns", "Domain Name Service",
		PKT_DNS,	WTAP_ENCAP_ETHERNET,
		pkt_dns,	array_length(pkt_dns),
		NULL,		0,
		NULL,		NULL,
		1000,
	},

	{ "eth", "Ethernet",
		PKT_ETHERNET,	WTAP_ENCAP_ETHERNET,
		NULL,		0,
		NULL,		0,
		NULL,		NULL,
		1000,
	},

	{ "fddi", "Fiber Distributed Data Interface",
		PKT_FDDI,	WTAP_ENCAP_FDDI,
		NULL,		0,
		NULL,		0,
		NULL,		NULL,
		1000,
	},

	{ "giop", "General Inter-ORB Protocol",
		PKT_GIOP,	WTAP_ENCAP_ETHERNET,
		pkt_giop,	array_length(pkt_giop),
		NULL,		0,
		NULL,		NULL,
		1000,
	},

	{ "icmp", "Internet Control Message Protocol",
		PKT_ICMP,	WTAP_ENCAP_ETHERNET,
		pkt_icmp,	array_length(pkt_icmp),
		NULL,		0,
		NULL,		NULL,
		1000,
	},

	{ "ieee802.15.4", "IEEE 802.15.4",
		PKT_IEEE802154, WTAP_ENCAP_IEEE802_15_4,
		NULL,		0,
		NULL,           0,
		NULL,           NULL,
		127,
	},

	{ "ip", "Internet Protocol",
		PKT_IP,		WTAP_ENCAP_ETHERNET,
		pkt_ip,		array_length(pkt_ip),
		NULL,		0,
		NULL,		NULL,
		1000,
	},

	{ "ipv6", "Internet Protocol Version 6",
		PKT_IPv6,	WTAP_ENCAP_ETHERNET,
		pkt_ipv6,	array_length(pkt_ipv6),
		NULL,		0,
		NULL,		NULL,
		1000,
	},

	{ "llc", "Logical Link Control",
		PKT_LLC,	WTAP_ENCAP_TOKEN_RING,
		pkt_llc,	array_length(pkt_llc),
		NULL,		0,
		NULL,		NULL,
		1000,
	},

	{ "m2m", "WiMAX M2M Encapsulation Protocol",
		PKT_M2M,	WTAP_ENCAP_ETHERNET,
		pkt_m2m,	array_length(pkt_m2m),
		NULL,		0,
		NULL,		NULL,
		1000,
	},

	{ "megaco", "MEGACO",
		PKT_MEGACO,	WTAP_ENCAP_ETHERNET,
		pkt_megaco,	array_length(pkt_megaco),
		NULL,		0,
		NULL,		NULL,
		1000,
	},

	{ "nbns", "NetBIOS-over-TCP Name Service",
		PKT_NBNS,	WTAP_ENCAP_ETHERNET,
		pkt_nbns,	array_length(pkt_nbns),
		NULL,		0,
		NULL,		NULL,
		1000,
	},

	{ "ncp2222", "NetWare Core Protocol",
		PKT_NCP2222,	WTAP_ENCAP_TOKEN_RING,
		pkt_ncp2222,	array_length(pkt_ncp2222),
		NULL,		0,
		NULL,		NULL,
		1000,
	},

	{ "sctp", "Stream Control Transmission Protocol",
		PKT_SCTP,	WTAP_ENCAP_ETHERNET,
		pkt_sctp,	array_length(pkt_sctp),
		NULL,		0,
		NULL,		NULL,
		1000,
	},

	{ "syslog", "Syslog message",
		PKT_SYSLOG,	WTAP_ENCAP_ETHERNET,
		pkt_syslog,	array_length(pkt_syslog),
		NULL,		0,
		NULL,		NULL,
		1000,
	},

	{ "tds", "TDS NetLib",
		PKT_TDS,	WTAP_ENCAP_ETHERNET,
		pkt_tds,	array_length(pkt_tds),
		NULL,		0,
		NULL,		NULL,
		1000,
	},

	{ "tcp", "Transmission Control Protocol",
		PKT_TCP,	WTAP_ENCAP_TOKEN_RING,
		pkt_tcp,	array_length(pkt_tcp),
		NULL,		0,
		NULL,		NULL,
		1000,
	},

	{ "tr",	 "Token-Ring",
		PKT_TR,		WTAP_ENCAP_TOKEN_RING,
		NULL,		0,
		NULL,		0,
		NULL,		NULL,
		1000,
	},

	{ "udp", "User Datagram Protocol",
		PKT_UDP,	WTAP_ENCAP_ETHERNET,
		pkt_udp,	array_length(pkt_udp),
		NULL,		0,
		NULL,		NULL,
		1000,
	},

	{ "usb-linux", "Universal Serial Bus with Linux specific header",
		PKT_USB_LINUX,	WTAP_ENCAP_USB_LINUX,
		NULL,		0,
		NULL,		0,
		NULL,		NULL,
		1000,
	},

};

unsigned randpkt_example_count(void)
{
	return array_length(examples);
}

/* Find pkt_example record and return pointer to it */
randpkt_example* randpkt_find_example(int type)
{
	int	num_entries = array_length(examples);
	int	i;

	for (i = 0; i < num_entries; i++) {
		if (examples[i].produceable_type == type) {
			return &examples[i];
		}
	}

	fprintf(stderr, "randpkt: Internal error. Type %d has no entry in examples table.\n",
	    type);
	return NULL;
}

void randpkt_loop(randpkt_example* example, uint64_t produce_count, uint64_t packet_delay_ms)
{
	unsigned i, j;
	int err;
	unsigned len_random;
	unsigned len_this_pkt;
	char* err_info;
	union wtap_pseudo_header* ps_header;
	uint8_t* buffer;
	wtap_rec* rec;

	rec = g_new0(wtap_rec, 1);
	buffer = (uint8_t*)g_malloc0(65536);

	rec->rec_type = REC_TYPE_PACKET;
	rec->presence_flags = WTAP_HAS_TS;
	rec->rec_header.packet_header.pkt_encap = example->sample_wtap_encap;

	ps_header = &rec->rec_header.packet_header.pseudo_header;

	/* Load the sample pseudoheader into our pseudoheader buffer */
	if (example->pseudo_buffer)
		memcpy(ps_header, example->pseudo_buffer, example->pseudo_length);

	/* Load the sample into our buffer */
	if (example->sample_buffer)
		memcpy(buffer, example->sample_buffer, example->sample_length);

	/* Produce random packets */
	for (i = 0; i < produce_count; i++) {
		if (example->produce_max_bytes > 0) {
			len_random = g_rand_int_range(pkt_rand, 0, example->produce_max_bytes + 1);
		}
		else {
			len_random = 0;
		}

		len_this_pkt = example->sample_length + len_random;
		if (len_this_pkt > WTAP_MAX_PACKET_SIZE_STANDARD) {
			/*
			 * Wiretap will fail when trying to read packets
			 * bigger than WTAP_MAX_PACKET_SIZE_STANDARD.
			 */
			len_this_pkt = WTAP_MAX_PACKET_SIZE_STANDARD;
		}

		rec->rec_header.packet_header.caplen = len_this_pkt;
		rec->rec_header.packet_header.len = len_this_pkt;
		rec->ts.secs = i; /* just for variety */

		for (j = example->pseudo_length; j < (int) sizeof(*ps_header); j++) {
			((uint8_t*)ps_header)[j] = g_rand_int_range(pkt_rand, 0, 0x100);
		}

		for (j = example->sample_length; j < len_this_pkt; j++) {
			/* Add format strings here and there */
			if ((int) (100.0*g_rand_double(pkt_rand)) < 3 && j < (len_random - 3)) {
				memcpy(&buffer[j], "%s", 3);
				j += 2;
			} else {
				buffer[j] = g_rand_int_range(pkt_rand, 0, 0x100);
			}
		}

		if (!wtap_dump(example->dump, rec, buffer, &err, &err_info)) {
			cfile_write_failure_message(NULL,
			    example->filename, err, err_info, 0,
			    wtap_dump_file_type_subtype(example->dump));
		}
		if (packet_delay_ms) {
			g_usleep(1000 * (unsigned long)packet_delay_ms);
			if (!wtap_dump_flush(example->dump, &err)) {
				cfile_write_failure_message(NULL,
				    example->filename, err, NULL, 0,
				    wtap_dump_file_type_subtype(example->dump));
			}
		}
	}

	g_free(rec);
	g_free(buffer);
}

bool randpkt_example_close(randpkt_example* example)
{
	int err;
	char *err_info;
	bool ok = true;

	if (!wtap_dump_close(example->dump, NULL, &err, &err_info)) {
		cfile_close_failure_message(example->filename, err, err_info);
		ok = false;
	}

	if (pkt_rand != NULL) {
		g_rand_free(pkt_rand);
		pkt_rand = NULL;
	}

	return ok;
}

int randpkt_example_init(randpkt_example* example, char* produce_filename, int produce_max_bytes, int file_type_subtype)
{
	int err;
	char *err_info;

	if (pkt_rand == NULL) {
		pkt_rand = g_rand_new();
	}

	const wtap_dump_params params = {
		.encap = example->sample_wtap_encap,
		.snaplen = produce_max_bytes,
	};
	if (strcmp(produce_filename, "-") == 0) {
		/* Write to the standard output. */
		example->dump = wtap_dump_open_stdout(file_type_subtype,
			WTAP_UNCOMPRESSED, &params, &err, &err_info);
		example->filename = "the standard output";
	} else {
		example->dump = wtap_dump_open(produce_filename, file_type_subtype,
			WTAP_UNCOMPRESSED, &params, &err, &err_info);
		example->filename = produce_filename;
	}
	if (!example->dump) {
		cfile_dump_open_failure_message(produce_filename,
			err, err_info, file_type_subtype);
		return WRITE_ERROR;
	}

	/* reduce max_bytes by # of bytes already in sample */
	if (produce_max_bytes <= example->sample_length) {
		fprintf(stderr, "randpkt: Sample packet length is %d, which is greater than "
			"or equal to\n", example->sample_length);
		fprintf(stderr, "your requested max_bytes value of %d\n", produce_max_bytes);
		return INVALID_LEN;
	} else {
		example->produce_max_bytes = produce_max_bytes - example->sample_length;
	}

	return EXIT_SUCCESS;
}

/* Parse command-line option "type" and return enum type */
int randpkt_parse_type(char *string)
{
	int	num_entries = array_length(examples);
	int	i;

	/* If called with NULL, or empty string, choose a random packet */
	if (!string || !g_strcmp0(string, "")) {
		return examples[g_random_int_range(0, num_entries)].produceable_type;
	}

	for (i = 0; i < num_entries; i++) {
		if (g_strcmp0(examples[i].abbrev, string) == 0) {
			return examples[i].produceable_type;
		}
	}

	/* Complain */
	ws_error("randpkt: Type %s not known.\n", string);
	return -1;
}

void randpkt_example_list(char*** abbrev_list, char*** longname_list)
{
	unsigned i;
	unsigned list_num;
	list_num = randpkt_example_count();
	*abbrev_list = g_new0(char*, list_num + 1);
	*longname_list = g_new0(char*, list_num + 1);
	for (i = 0; i < list_num; i++) {
		(*abbrev_list)[i] = g_strdup(examples[i].abbrev);
		(*longname_list)[i] = g_strdup(examples[i].longname);
	}
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
