/*
 * A generic packet generator application for U-SIG radiotap packets.
 *
 * Copyright Richard Sharpe, 2022.
 *
 * You will need libpcap installed.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * A sample program showing how to create packets with radiotap headers. This
 * is mainly useful for those situations where you are adding a new radiotap
 * TLV but the drivers for the hardware is not ready yet and you need to
 * test your radiotap dissector.
 */

#include <errno.h>
#include <glib.h>
#include "wspcap.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct u_sig_hdr {
	uint16_t type;
	uint16_t len;
	uint32_t common;
	uint32_t value;
	uint32_t mask;
} __attribute__((packed));

struct radiotap_hdr {
	uint8_t vers;
	uint8_t pad;
	uint16_t len;
	uint32_t presence_flags;
	uint32_t MAC_timestamp[2];
	uint8_t flags;
	uint8_t data_rate;
	uint16_t channel_freq;
	uint16_t pad2;
	uint16_t pad3;
	struct u_sig_hdr u_sig_hdr;
} __attribute__((packed));

struct complete_pkt {
	struct radiotap_hdr radiotap;
	uint8_t pkt_data[26];
} __attribute__((packed));

/* Some random 802.11 packet, an S1G beacon, I think */
uint8_t pkt_data[26] = { 0x1c, 0x0b, 0x00, 0x00, 0x02, 0x00, 0xeb, 0x4b,
			 0x02, 0x8b, 0x12, 0x52, 0xa7, 0x6b, 0x00, 0x62,
			 0x9c, 0x6b, 0x64, 0x4e, 0x35, 0xae, 0x05, 0x02,
			 0x00, 0x02 };

#define PHY_VERSION_ID_KNOWN 0x00000001
#define BW_KNOWN             0x00000002
#define UL_DL_KNOWN          0x00000004
#define BSS_COLOR_KNOWN      0x00000008
#define UL_DL                0x00040000

/*
 * Generate some u_sig packets.
 */
static void gen_u_sig_pkts(pcap_dumper_t *dumper)
{
	struct pcap_pkthdr hdr;
	struct complete_pkt pkt;
	struct timeval ts;
	/*
	 * Create the complete packet.
	 *
	 * 1. Set up the radiotap headers we need, including the TLVs.
	 */
	pkt.radiotap.vers = 0;
	pkt.radiotap.pad = 0;
	pkt.radiotap.len = sizeof(struct radiotap_hdr);
	pkt.radiotap.presence_flags = 0x1000000F;
	pkt.radiotap.MAC_timestamp[0] = 0x17860500;
	pkt.radiotap.MAC_timestamp[1] = 0x22ac9b1a;
	pkt.radiotap.flags = 0;
	pkt.radiotap.data_rate = 0x02;
	pkt.radiotap.channel_freq = 5600;
	pkt.radiotap.pad2 = 0x0100;
	pkt.radiotap.pad3 = 0x0000;
	pkt.radiotap.u_sig_hdr.type = 33;   /* The TLV we want U-SIG */
	pkt.radiotap.u_sig_hdr.len = 12;

	/* Set the BW to 80MHz for the moment */
	pkt.radiotap.u_sig_hdr.common = PHY_VERSION_ID_KNOWN | BW_KNOWN | \
					UL_DL_KNOWN | 0x00012000;
	/*
	 * The bits are:          U-SIG-1 B20-25: all 1s.
	 *               PPDU Type and Comp mode: 0
	 *                              Validate: 1
	 *         Punctured Channel Information: 0 (no puncturing)
	 *                              Validate: 1
	 *                           EHT SIG MCS: 0 (EHT-MCS 0)
	 */
	pkt.radiotap.u_sig_hdr.value = 0x0000413F;
	pkt.radiotap.u_sig_hdr.mask =  0x003fbec0;  /* The Intel value */

	/* Copy the packet data in */
	memcpy(pkt.pkt_data, pkt_data, sizeof(pkt.pkt_data));

	gettimeofday(&ts, NULL);
	hdr.ts = ts;
	hdr.caplen = sizeof(struct complete_pkt);
	hdr.len = sizeof(struct complete_pkt);

	pcap_dump((u_char *)dumper, &hdr, (u_char *)&pkt);

	/* Dump another with different 160MHz */
	/*
	 * The bits are:          U-SIG-1 B20-25: all 1s.
	 *               PPDU Type and Comp mode: 0
	 *                              Validate: 1
	 *         Punctured Channel Information: 1 ([x 1 1 1]puncturing)
	 *                              Validate: 1
	 *                           EHT SIG MCS: 1 (EHT-MCS 1)
	 */
	pkt.radiotap.u_sig_hdr.common = PHY_VERSION_ID_KNOWN | BW_KNOWN | \
					UL_DL_KNOWN | 0x00018000;;
	pkt.radiotap.u_sig_hdr.mask =  0x003fbec0;
	pkt.radiotap.u_sig_hdr.value = 0x0001183F;

	/* We should probably update the timestamp */
	pcap_dump((u_char *)dumper, &hdr, (u_char *)&pkt);

	/* Dump another with different 160MHz */
	/*
	 * The bits are:          U-SIG-1 B20-25: all 1s.
	 *               PPDU Type and Comp mode: 0
	 *                              Validate: 1
	 *         Punctured Channel Information: 1 ([x 1 1 1]puncturing)
	 *                              Validate: 1
	 *                           EHT SIG MCS: 1 (EHT-MCS 1)
	 */
	pkt.radiotap.u_sig_hdr.common = PHY_VERSION_ID_KNOWN | BW_KNOWN | \
					UL_DL_KNOWN | UL_DL | 0x00018000;
	pkt.radiotap.u_sig_hdr.mask =  0x003fbec0;
	pkt.radiotap.u_sig_hdr.value = 0x0001183F;

	pcap_dump((u_char *)dumper, &hdr, (u_char *)&pkt);
}

int main(int argc, char *argv[])
{
	int err = -1;
	pcap_t *pd = NULL;
	pcap_dumper_t *dumper = NULL;

	if (argc < 2) {
		printf("Usage: %s <pcap-file-name>\n", argv[0]);
		return 1;
	}

	pd = pcap_open_dead(DLT_IEEE802_11_RADIO, 65535);
	if (pd == NULL) {
		fprintf(stderr, "Unable to open pcap device: %s\n",
			g_strerror(errno));
		return -1;
	}

	dumper = pcap_dump_open(pd, argv[1]);
        if (dumper == NULL) {
		fprintf(stderr, "Unable to create dump file %s: %s\n",
			argv[1], pcap_geterr(pd));
		goto close_pd;
	}

	/*
	 * Add calls to any functions that generate packets.
	 */
	gen_u_sig_pkts(dumper);

	pcap_dump_close(dumper);
close_pd:
	pcap_close(pd);
	return err;
}
