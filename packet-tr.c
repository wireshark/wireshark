/* packet-tr.c
 * Routines for Token-Ring packet disassembly
 * Gilbert Ramirez <gram@xiexie.org>
 *
 * $Id: packet-tr.c,v 1.36 2000/03/20 22:22:45 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>
#include <glib.h>
#include "packet.h"
#include "packet-llc.h"
#include "packet-trmac.h"
	
static int proto_tr = -1;
static int hf_tr_dst = -1;
static int hf_tr_src = -1;
static int hf_tr_addr = -1;
static int hf_tr_sr = -1;
static int hf_tr_ac = -1;
static int hf_tr_priority = -1;
static int hf_tr_frame = -1;
static int hf_tr_monitor_cnt = -1;
static int hf_tr_priority_reservation = -1;
static int hf_tr_fc = -1;
static int hf_tr_fc_type = -1;
static int hf_tr_fc_pcf = -1;
static int hf_tr_rif_bytes = -1;
static int hf_tr_broadcast = -1;
static int hf_tr_max_frame_size = -1;
static int hf_tr_direction = -1;
static int hf_tr_rif = -1;
static int hf_tr_rif_ring = -1;
static int hf_tr_rif_bridge = -1;

static gint ett_token_ring = -1;
static gint ett_token_ring_ac = -1;
static gint ett_token_ring_fc = -1;

#define TR_MIN_HEADER_LEN 14
#define TR_MAX_HEADER_LEN 32

static const true_false_string ac_truth = { "Frame", "Token" };

static const value_string pcf_vals[] = {
	{ 0,	"Normal buffer" },
	{ 1,	"Express buffer" },
	{ 2,	"Purge" },
	{ 3,	"Claim Token" },
	{ 4,	"Beacon" },
	{ 5,	"Active Monitor Present" },
	{ 6,	"Standby Monitor Present" },
	{ 0,	NULL },
};

static const value_string frame_vals[] = {
	{ 0,	"MAC" },
	{ 1,	"LLC" },
	{ 2,	"Reserved" },
	{ 0,	NULL },
};

static const value_string broadcast_vals[] = {
	{ 0 << 5,	"Non-broadcast" },
	{ 1 << 5,	"Non-broadcast" },
	{ 2 << 5,	"Non-broadcast" },
	{ 3 << 5,	"Non-broadcast" },
	{ 4 << 5,	"All-routes broadcast" },
	{ 5 << 5,	"All-routes broadcast" },
	{ 6 << 5,	"Single-route broadcast" },
	{ 7 << 5,	"Single-route broadcast" },
	{ 0,		NULL }
};

static const value_string max_frame_size_vals[] = {
	{ 0,	"516" },
	{ 1,	"1500" },
	{ 2,	"2052" },
	{ 3,	"4472" },
	{ 4,	"8144" },
	{ 5,	"11407" },
	{ 6,	"17800" },
	{ 0,	NULL }
};

static const value_string direction_vals[] = {
	{ 0,	"From originating station (-->)" },
	{ 128,	"To originating station (<--)" },
	{ 0,	NULL }
};

/*
 * DODGY LINUX HACK DODGY LINUX HACK
 * Linux 2.0.x always passes frames to the Token Ring driver for transmission with 
 * 18 bytes padding for source routing information.  Some drivers copy the first 
 * (18 - srlen) bytes up the frame (18 - srlen) bytes thus removing the padding.
 * Other drivers just make a copy of the entire frame and then hack about with it
 * so the frame the sniffer gets is fine (just has extra sr routing).
 * In the first instance (driver hacking frame in situ) the sniffer gets a garbled
 * frame.
 * This function trys to detect this and returns the offset of where
 * the frame really starts.
 * This only detects frames that we have sent ourselves so if we are packet sniffing
 * on the machine we are watching this is useful.
 * Compare offset 0 with offset x+1 for a length of x bytes for all value of x = 1 to 18
 * if match then Linux driver has done in situ source route compression of the crappy 
 * Linux 2.0.x frame so the beginning of the real frame is x bytes in.
 * (And this real frame x bytes in looks like a proper TR frame that goes on the wire
 * with none of the Linux idiosyncrasies).
 */
int check_for_old_linux(const u_char * pd)
{
	int x;
	for(x=1;x<=18;x++)
	{
		if (memcmp(&pd[0],&pd[x],x) == 0)
		{
			return x;
		}
	}
	return 0;		
}

static void
add_ring_bridge_pairs(int rcf_len, const u_char *pd, int offset, proto_tree *tree);

void
capture_tr(const u_char *pd, int offset, packet_counts *ld) {

	int			source_routed = 0;
	int			frame_type;
	int			x;
	guint8			trn_rif_bytes;
	guint8			actual_rif_bytes;

	/* The trn_hdr struct, as separate variables */
	guint8			trn_fc;		/* field control field */
	guint8			trn_shost[6];	/* source host */

	if (!BYTES_ARE_IN_FRAME(offset, TR_MIN_HEADER_LEN)) {
		ld->other++;
		return;
	}

	if ((x = check_for_old_linux(pd)))
	{
		/* Actually packet starts x bytes into what we have got but with all
		   source routing compressed 
		*/
		 /* pd = &pd[x]; */ offset+=x;
	}

	/* get the data */
	memcpy(&trn_fc, &pd[offset + 1], sizeof(guint8));
	memcpy(trn_shost, &pd[offset + 8], 6 * sizeof(guint8));

	frame_type = (trn_fc & 192) >> 6;

	/* if the high bit on the first byte of src hwaddr is 1, then
		this packet is source-routed */
	source_routed = trn_shost[0] & 128;

	trn_rif_bytes = pd[offset + 14] & 31;

	/* sometimes we have a RCF but no RIF... half source-routed? */
	if (!source_routed && trn_rif_bytes > 0) {
		 /* I'll check for 2 bytes of RIF and mark the packet as source
		  * routed even though I'm not sure _what_ that kind of packet is */
		if (trn_rif_bytes == 2) {
			source_routed = 1;
		}
		/* the Linux 2.0 TR code strips source-route bits in
		 * order to test for SR. This can be removed from most
		 * packets with oltr, but not all. So, I try to figure out
		 * which packets should have been SR here. I'll check to
		 * see if there's a SNAP or IPX field right after
		 * my RIF fields.
		 */
		else if ( (
			pd[offset + 0x0e + trn_rif_bytes] == 0xaa &&
			pd[offset + 0x0f + trn_rif_bytes] == 0xaa &&
			pd[offset + 0x10 + trn_rif_bytes] == 0x03) ||
			  (
			pd[offset + 0x0e + trn_rif_bytes] == 0xe0 &&
			pd[offset + 0x0f + trn_rif_bytes] == 0xe0) ) {

			source_routed = 1;
		}

	}

	if (source_routed) {
		actual_rif_bytes = trn_rif_bytes;
	}
	else {
		trn_rif_bytes = 0;
		actual_rif_bytes = 0;
	}

	/* this is a silly hack for Linux 2.0.x. Read the comment below,
	in front of the other #ifdef linux. If we're sniffing our own NIC,
	 we get a full RIF, sometimes with garbage */
	if ((source_routed && trn_rif_bytes == 2 && frame_type == 1) ||
		(!source_routed && frame_type == 1)) {
		/* look for SNAP or IPX only */
		if ( (pd[offset + 0x20] == 0xaa && pd[offset + 0x21] == 0xaa && pd[offset + 0x22] == 03) ||
			 (pd[offset + 0x20] == 0xe0 && pd[offset + 0x21] == 0xe0) ) {
			actual_rif_bytes = 18;
		} else if (
			pd[offset + 0x23] == 0 &&
			pd[offset + 0x24] == 0 &&
			pd[offset + 0x25] == 0 &&
			pd[offset + 0x26] == 0x00 &&
			pd[offset + 0x27] == 0x11) {

                        actual_rif_bytes = 18;

                       /* Linux 2.0.x also requires drivers pass up a fake SNAP and LLC header before th
                          real LLC hdr for all Token Ring frames that arrive with DSAP and SSAP != 0xAA
                          (i.e. for non SNAP frames e.g. for Netware frames)
                          the fake SNAP header has the ETH_P_TR_802_2 ether type (0x0011) and the protocol id
                          bytes as zero frame looks like :-
                          TR Header | Fake LLC | Fake SNAP | Wire LLC | Rest of data */
                       offset += 8; /* Skip fake LLC and SNAP */
                }
	}
	
	offset += actual_rif_bytes + 14;

	/* The package is either MAC or LLC */
	switch (frame_type) {
		/* MAC */
		case 0:
			ld->other++;
			break;
		case 1:
			capture_llc(pd, offset, ld);
			break;
		default:
			/* non-MAC, non-LLC, i.e., "Reserved" */
			ld->other++;
			break;
	}
}


void
dissect_tr(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

	proto_tree	*tr_tree, *bf_tree;
	proto_item	*ti;
	int		fixoffset = 0;
	int			source_routed = 0;
	int			frame_type;
	guint8		trn_rif_bytes;
	guint8		actual_rif_bytes;

	/* The trn_hdr struct, as separate variables */
	guint8			trn_ac;		/* access control field */
	guint8			trn_fc;		/* field control field */
	guint8			trn_dhost[6];	/* destination host */
	guint8			trn_shost[6];	/* source host */
	guint16			trn_rcf;	/* routing control field */
	guint16			trn_rseg[8];	/* routing registers */

	/* non-source-routed version of source addr */
	static guint8		trn_shost_nonsr[6];
	int			x;
	
	/* Token-Ring Strings */
	char *fc[] = { "MAC", "LLC", "Reserved", "Unknown" };

	if (!BYTES_ARE_IN_FRAME(offset, TR_MIN_HEADER_LEN)) {
		dissect_data(pd, offset, fd, tree);
		return;
	}

	if ((x = check_for_old_linux(pd)))
	{
		/* Actually packet starts x bytes into what we have got but with all
		   source routing compressed. See comment above */
		offset += x;
		/* pd = &pd[x]; */
	}


	/* get the data */
	memcpy(&trn_ac, &pd[offset+0], sizeof(guint8));
	memcpy(&trn_fc, &pd[offset+1], sizeof(guint8));
	memcpy(trn_dhost, &pd[offset+2], 6 * sizeof(guint8));
	memcpy(trn_shost, &pd[offset+8], 6 * sizeof(guint8));
	memcpy(&trn_rcf, &pd[offset+14], sizeof(guint16));
	memcpy(trn_rseg, &pd[offset+16], 8 * sizeof(guint16));

	memcpy(trn_shost_nonsr, &pd[offset+8], 6 * sizeof(guint8));
	trn_shost_nonsr[0] &= 127;
	frame_type = (trn_fc & 192) >> 6;

	/* if the high bit on the first byte of src hwaddr is 1, then
		this packet is source-routed */
	source_routed = trn_shost[0] & 128;

	trn_rif_bytes = pd[offset+14] & 31;

	/* sometimes we have a RCF but no RIF... half source-routed? */
	/* I'll check for 2 bytes of RIF and the 0x70 byte */
	if (!source_routed && trn_rif_bytes > 0) {
		if (trn_rif_bytes == 2) {
			source_routed = 1;
		}
		/* the Linux 2.0 TR code strips source-route bits in
		 * order to test for SR. This can be removed from most
		 * packets with oltr, but not all. So, I try to figure out
		 * which packets should have been SR here. I'll check to
		 * see if there's a SNAP or IPX field right after
		 * my RIF fields.
		 */
		else if ( (
			pd[offset + 0x0e + trn_rif_bytes] == 0xaa &&
			pd[offset + 0x0f + trn_rif_bytes] == 0xaa &&
			pd[offset + 0x10 + trn_rif_bytes] == 0x03) ||
			  (
			pd[offset + 0x0e + trn_rif_bytes] == 0xe0 &&
			pd[offset + 0x0f + trn_rif_bytes] == 0xe0) ) {

			source_routed = 1;
		}
/*		else {
			printf("0e+%d = %02X   0f+%d = %02X\n", trn_rif_bytes,
					pd[offset + 0x0e + trn_rif_bytes],
					trn_rif_bytes,
					pd[offset + 0x0f + trn_rif_bytes]);
		} */

	}

	if (source_routed) {
		actual_rif_bytes = trn_rif_bytes;
	}
	else {
		trn_rif_bytes = 0;
		actual_rif_bytes = 0;
	}

	/* this is a silly hack for Linux 2.0.x. Read the comment below,
	in front of the other #ifdef linux. If we're sniffing our own NIC,
	 we get a full RIF, sometimes with garbage */
	if ((source_routed && trn_rif_bytes == 2 && frame_type == 1) ||
		(!source_routed && frame_type == 1)) {
		/* look for SNAP or IPX only */
		if ( 	(pd[offset + 0x20] == 0xaa &&
		      	pd[offset + 0x21] == 0xaa &&
		      	pd[offset + 0x22] == 03)
		 ||
		     	(pd[offset + 0x20] == 0xe0 &&
		      	pd[offset + 0x21] == 0xe0) ) {

			actual_rif_bytes = 18;
               }
		else if (
			pd[0x23] == 0 &&
			pd[0x24] == 0 &&
			pd[0x25] == 0 &&
			pd[0x26] == 0x00 &&
			pd[0x27] == 0x11) {

                        actual_rif_bytes = 18;

                       /* Linux 2.0.x also requires drivers pass up a fake SNAP and LLC header before th
                          real LLC hdr for all Token Ring frames that arrive with DSAP and SSAP != 0xAA
                          (i.e. for non SNAP frames e.g. for Netware frames)
                          the fake SNAP header has the ETH_P_TR_802_2 ether type (0x0011) and the protocol id
                          bytes as zero frame looks like :-
                          TR Header | Fake LLC | Fake SNAP | Wire LLC | Rest of data */
                       fixoffset += 8; /* Skip fake LLC and SNAP */
                }
	}

	/* XXX - copy it to some buffer associated with "pi", rather than
	   just making "trn_shost_nonsr" static? */
	SET_ADDRESS(&pi.dl_src, AT_ETHER, 6, &trn_shost_nonsr[0]);
	SET_ADDRESS(&pi.src, AT_ETHER, 6, &trn_shost_nonsr[0]);
	SET_ADDRESS(&pi.dl_dst, AT_ETHER, 6, &pd[offset + 2]);
	SET_ADDRESS(&pi.dst, AT_ETHER, 6, &pd[offset + 2]);

	/* information window */
	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "TR");
	if (check_col(fd, COL_INFO))
		col_add_fstr(fd, COL_INFO, "Token-Ring %s", fc[frame_type]);

	/* protocol analysis tree */
	if (tree) {
		/* Create Token-Ring Tree */
		ti = proto_tree_add_item(tree, proto_tr, offset, 14 + actual_rif_bytes, NULL);
		tr_tree = proto_item_add_subtree(ti, ett_token_ring);

		/* Create the Access Control bitfield tree */
		ti = proto_tree_add_item(tr_tree, hf_tr_ac, offset, 1, trn_ac);
		bf_tree = proto_item_add_subtree(ti, ett_token_ring_ac);

		proto_tree_add_item(bf_tree, hf_tr_priority, offset, 1, trn_ac);
		proto_tree_add_item(bf_tree, hf_tr_frame, offset, 1, trn_ac);
		proto_tree_add_item(bf_tree, hf_tr_monitor_cnt, offset, 1, trn_ac);
		proto_tree_add_item(bf_tree, hf_tr_priority_reservation, offset, 1, trn_ac);

		/* Create the Frame Control bitfield tree */
		ti = proto_tree_add_item(tr_tree, hf_tr_fc, offset + 1, 1, trn_fc);
		bf_tree = proto_item_add_subtree(ti, ett_token_ring_fc);

		proto_tree_add_item(bf_tree, hf_tr_fc_type, offset + 1, 1, trn_fc);
		proto_tree_add_item(bf_tree, hf_tr_fc_pcf,  offset + 1, 1, trn_fc);
		proto_tree_add_item(tr_tree, hf_tr_dst, offset + 2, 6, trn_dhost);
		proto_tree_add_item(tr_tree, hf_tr_src, offset + 8, 6, trn_shost);
		proto_tree_add_item_hidden(tr_tree, hf_tr_addr, offset + 2, 6, trn_dhost);
		proto_tree_add_item_hidden(tr_tree, hf_tr_addr, offset + 8, 6, trn_shost);

		proto_tree_add_item_hidden(tr_tree, hf_tr_sr, offset + 8, 1, source_routed);

		/* non-source-routed version of src addr */
		proto_tree_add_item_hidden(tr_tree, hf_tr_src, offset + 8, 6, trn_shost_nonsr);

		if (source_routed) {
			/* RCF Byte 1 */
			proto_tree_add_item(tr_tree, hf_tr_rif_bytes, offset + 14, 1, trn_rif_bytes);
			proto_tree_add_item(tr_tree, hf_tr_broadcast, offset + 14, 1, pd[offset + 14] & 224);

			/* RCF Byte 2 */
			proto_tree_add_item(tr_tree, hf_tr_max_frame_size, offset + 15, 1, pd[offset + 15] & 112);
			proto_tree_add_item(tr_tree, hf_tr_direction, offset + 15, 1, pd[offset + 15] & 128);

			/* if we have more than 2 bytes of RIF, then we have
				ring/bridge pairs */
			if ((trn_rif_bytes > 2) && BYTES_ARE_IN_FRAME(offset + 14, trn_rif_bytes)) {
				add_ring_bridge_pairs(trn_rif_bytes,
					pd, offset, tr_tree);
			}
		}

		/* Linux 2.0.x has a problem in that the 802.5 code creates
		an emtpy full (18-byte) RIF area. It's up to the tr driver to
		either fill it in or remove it before sending the bytes out
		to the wire. If you run tcpdump on a Linux 2.0.x machine running
		token-ring, tcpdump will capture these 18 filler bytes. They
		are filled with garbage. The best way to detect this problem is
		to know the src hwaddr of the machine from which you were running
		tcpdump. W/o that, however, I'm guessing that DSAP == SSAP if the
		frame type is LLC.  It's very much a hack. -- Gilbert Ramirez */
		if (actual_rif_bytes > trn_rif_bytes) {
			proto_tree_add_text(tr_tree, 14 + trn_rif_bytes, actual_rif_bytes - trn_rif_bytes,
				"Empty RIF from Linux 2.0.x driver. The sniffing NIC "
				"is also running a protocol stack.");
		}
		if (fixoffset) {
			proto_tree_add_text(tr_tree, 14 + 18,8,"Linux 2.0.x fake LLC and SNAP header");
		}
	}
	offset += 14 + actual_rif_bytes + fixoffset;

	if (IS_DATA_IN_FRAME(offset)) {
		/* The package is either MAC or LLC */
		switch (frame_type) {
			/* MAC */
			case 0:
				dissect_trmac(pd, offset, fd, tree);
				break;
			case 1:
				dissect_llc(pd, offset, fd, tree);
				break;
			default:
				/* non-MAC, non-LLC, i.e., "Reserved" */
				dissect_data(pd, offset, fd, tree);
				break;
		}
	}
}

/* this routine is taken from the Linux net/802/tr.c code, which shows
ring-bridge pairs in the /proc/net/tr_rif virtual file. */
static void
add_ring_bridge_pairs(int rcf_len, const u_char *pd, int offset, proto_tree *tree)
{
	int 	j, size;
	int 	segment, brdgnmb, unprocessed_rif;
	int	buff_offset=0;

#define RIF_BYTES_TO_PROCESS 30

	char	buffer[3 + (RIF_BYTES_TO_PROCESS / 2) * 6 + 1];

	/* Only process so many  bytes of RIF, as per TR spec, and not overflow
	 * static buffer above */
	unprocessed_rif = rcf_len - RIF_BYTES_TO_PROCESS;
	rcf_len = MIN(rcf_len, RIF_BYTES_TO_PROCESS);

	/* Ignore the 2 RCF bytes, since they don't make up the ring/bride pairs */
	rcf_len -= 2;

	for(j = 1; j < rcf_len - 1; j += 2) {
		if (j==1) {
			segment=pntohs(&pd[offset + 16]) >> 4;
			size = sprintf(buffer, "%03X",segment);
			proto_tree_add_item_hidden(tree, hf_tr_rif_ring, offset + 16, 2, segment);
			buff_offset += size;
		}
		segment=pntohs(&pd[offset+17+j]) >> 4;
		brdgnmb=pd[offset+16+j] & 0x0f;
		size = sprintf(buffer+buff_offset, "-%01X-%03X",brdgnmb,segment);
		proto_tree_add_item_hidden(tree, hf_tr_rif_ring, offset+17+j, 2, segment);
		proto_tree_add_item_hidden(tree, hf_tr_rif_bridge, offset+16+j, 1, brdgnmb);
		buff_offset += size;	
	}
	proto_tree_add_item(tree, hf_tr_rif, offset+16, rcf_len, buffer);

	if (unprocessed_rif > 0) {
		proto_tree_add_text(tree, offset+14+RIF_BYTES_TO_PROCESS, unprocessed_rif,
				"Extra RIF bytes beyond spec: %d", unprocessed_rif);
	}
}

void
proto_register_tr(void)
{
	static hf_register_info hf[] = {
		{ &hf_tr_ac,
		{ "Access Control",	"tr.ac", FT_UINT8, BASE_HEX, NULL, 0x0,
			"" }},

		{ &hf_tr_priority,
		{ "Priority",		"tr.priority", FT_UINT8, BASE_DEC, NULL, 0xe0,
			"" }},

		{ &hf_tr_frame,
		{ "Frame",		"tr.frame", FT_BOOLEAN, 8, TFS(&ac_truth), 0x10,
			"" }},

		{ &hf_tr_monitor_cnt,
		{ "Monitor Count",	"tr.monitor_cnt", FT_UINT8, BASE_DEC, NULL, 0x08,
			"" }},

		{ &hf_tr_priority_reservation,
		{ "Priority Reservation","tr.priority_reservation", FT_UINT8, BASE_DEC, NULL, 0x07,
			"" }},

		{ &hf_tr_fc,
		{ "Frame Control",	"tr.fc", FT_UINT8, BASE_HEX, NULL, 0x0,
			"" }},

		{ &hf_tr_fc_type,
		{ "Frame Type",		"tr.frame_type", FT_UINT8, BASE_DEC, VALS(frame_vals), 0xc0,
			"" }},

		{ &hf_tr_fc_pcf,
		{ "Frame PCF",		"tr.frame_pcf", FT_UINT8, BASE_DEC, VALS(pcf_vals), 0x0f,
			"" }},

		{ &hf_tr_dst,
		{ "Destination",	"tr.dst", FT_ETHER, BASE_NONE,  NULL, 0x0,
			"Destination Hardware Address" }},

		{ &hf_tr_src,
		{ "Source",		"tr.src", FT_ETHER, BASE_NONE, NULL, 0x0,
			"Source Hardware Address" }},

		{ &hf_tr_addr,
		{ "Source or Destination Address", "tr.addr", FT_ETHER, BASE_NONE, NULL, 0x0,
			"Source or Destination Hardware Address" }},

		{ &hf_tr_sr,
		{ "Source Routed",	"tr.sr", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Source Routed" }},

		{ &hf_tr_rif_bytes,
		{ "RIF Bytes",		"tr.rif_bytes", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Number of bytes in Routing Information Fields, including "
			"the two bytes of Routing Control Field" }},

		{ &hf_tr_broadcast,
		{ "Broadcast Type",	"tr.broadcast", FT_UINT8, BASE_DEC, VALS(broadcast_vals), 0x0,
			"Type of Token-Ring Broadcast" }},

		{ &hf_tr_max_frame_size,
		{ "Maximum Frame Size",	"tr.max_frame_size", FT_UINT8, BASE_DEC, VALS(max_frame_size_vals),
			0x0,
			"" }},

		{ &hf_tr_direction,
		{ "Direction",		"tr.direction", FT_UINT8, BASE_DEC, VALS(direction_vals), 0x0,
			"Direction of RIF" }},

		{ &hf_tr_rif,
		{ "Ring-Bridge Pairs",	"tr.rif", FT_STRING, BASE_NONE, NULL, 0x0,
			"String representing Ring-Bridge Pairs" }},

		{ &hf_tr_rif_ring,
		{ "RIF Ring",		"tr.rif.ring", FT_UINT16, BASE_HEX, NULL, 0x0,
			"" }},

		{ &hf_tr_rif_bridge,
		{ "RIF Bridge",		"tr.rif.bridge", FT_UINT8, BASE_HEX, NULL, 0x0,
			"" }},
	};
	static gint *ett[] = {
		&ett_token_ring,
		&ett_token_ring_ac,
		&ett_token_ring_fc,
	};

	proto_tr = proto_register_protocol("Token-Ring", "tr");
	proto_register_field_array(proto_tr, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

