/* packet-tr.c
 * Routines for Token-Ring packet disassembly
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
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

#include <string.h>
#include <stdio.h>
#include <glib.h>
#include <epan/packet.h>
#include "packet-tr.h"
#include "packet-llc.h"
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/emem.h>

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

static int tr_tap = -1;

/*
 * Check for and attempt to fix Linux link-layer header mangling.
 */
static gboolean fix_linux_botches = FALSE;

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
	{ 0 << 4,	"516" },
	{ 1 << 4,	"1500" },
	{ 2 << 4,	"2052" },
	{ 3 << 4,	"4472" },
	{ 4 << 4,	"8144" },
	{ 5 << 4,	"11407" },
	{ 6 << 4,	"17800" },
	{ 7 << 4,	"65535" },
	{ 0,		NULL }
};

static const value_string direction_vals[] = {
	{ 0,	"From originating station (-->)" },
	{ 128,	"To originating station (<--)" },
	{ 0,	NULL }
};

static dissector_handle_t trmac_handle;
static dissector_handle_t llc_handle;
static dissector_handle_t data_handle;

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
 *
 * XXX - there should perhaps be a preference setting to turn this off,
 * as sometimes it can, and does, get a false hit.
 */
static
int check_for_old_linux_tvb(tvbuff_t *tvb)
{
	const guint8	*data;
	int		x, bytes;

	/* Restrict our looping to the boundaries of the frame */
	bytes = tvb_length(tvb);
	if (bytes > 19) {
		bytes = 19;
	}

	data = tvb_get_ptr(tvb, 0, bytes);

	for(x = 1; x <= bytes-1 ;x++)
	{
		if (memcmp(&data[0], &data[x], x) == 0)
		{
			return x;
		}
	}
	return 0;
}

static
int check_for_old_linux(const guchar * pd)
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
add_ring_bridge_pairs(int rcf_len, tvbuff_t*, proto_tree *tree);

void
capture_tr(const guchar *pd, int offset, int len, packet_counts *ld) {

	int			source_routed = 0;
	int			frame_type;
	int			x;
	guint8			trn_rif_bytes;
	guint8			actual_rif_bytes;
	guint16			first2_sr;

	/* The trn_hdr struct, as separate variables */
	guint8			trn_fc;		/* field control field */
	const guint8		*trn_shost;	/* source host */

	if (!BYTES_ARE_IN_FRAME(offset, len, TR_MIN_HEADER_LEN)) {
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
	trn_fc = pd[offset + 1];
	trn_shost = &pd[offset + 8];

	frame_type = (trn_fc & 192) >> 6;

	/* if the high bit on the first byte of src hwaddr is 1, then
		this packet is source-routed */
	source_routed = trn_shost[0] & 128;

	trn_rif_bytes = pd[offset + 14] & 31;

	if (fix_linux_botches) {
		/* the Linux 2.0 TR code strips source-route bits in
		 * order to test for SR. This can be removed from most
		 * packets with oltr, but not all. So, I try to figure out
		 * which packets should have been SR here. I'll check to
		 * see if there's a SNAP or IPX field right after
		 * my RIF fields.
		 *
		 * The Linux 2.4.18 code, at least appears to do the
		 * same thing, from a capture I got from somebody running
		 * 2.4.18 (RH 7.1, so perhaps this is a Red Hat
		 * "improvement").
		 */
		if (!source_routed && trn_rif_bytes > 0) {
			if (pd[offset + 0x0e] != pd[offset + 0x0f]) {
				first2_sr = pntohs(&pd[offset + 0xe0 + trn_rif_bytes]);
				if (
					(first2_sr == 0xaaaa &&
					pd[offset + 0x10 + trn_rif_bytes] == 0x03) ||

					first2_sr == 0xe0e0 ||
					first2_sr == 0xe0aa ) {

					source_routed = 1;
				}
			}
		}
	}

	if (source_routed) {
		actual_rif_bytes = trn_rif_bytes;
	}
	else {
		trn_rif_bytes = 0;
		actual_rif_bytes = 0;
	}

	if (fix_linux_botches) {
		/* this is a silly hack for Linux 2.0.x. Read the comment
		 * below, in front of the other #ifdef linux.
		 * If we're sniffing our own NIC, we get a full RIF,
		 * sometimes with garbage
		 */
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

			       /* Linux 2.0.x also requires drivers pass up
			        * a fake SNAP and LLC header before the
				* real LLC hdr for all Token Ring frames
				* that arrive with DSAP and SSAP != 0xAA
				* (i.e. for non SNAP frames e.g. for Netware
				* frames) the fake SNAP header has the
				* ETH_P_TR_802_2 ether type (0x0011) and the protocol id
				* bytes as zero frame looks like :-
				* TR Header | Fake LLC | Fake SNAP | Wire LLC | Rest of data
				*/
			       offset += 8; /* Skip fake LLC and SNAP */
			}
		}
	}

	offset += actual_rif_bytes + TR_MIN_HEADER_LEN;

	/* The package is either MAC or LLC */
	switch (frame_type) {
		/* MAC */
		case 0:
			ld->other++;
			break;
		case 1:
			capture_llc(pd, offset, len, ld);
			break;
		default:
			/* non-MAC, non-LLC, i.e., "Reserved" */
			ld->other++;
			break;
	}
}


static void
dissect_tr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*tr_tree, *bf_tree;
	proto_item	*ti;
	int		frame_type;
	guint8		rcf1, rcf2;
	tvbuff_t	*next_tvb;

	volatile int		fixoffset = 0;
	volatile int		source_routed = 0;
	volatile guint8		trn_rif_bytes;
	volatile guint8		actual_rif_bytes;
	volatile guint8		c1_nonsr;
	volatile guint8		c2_nonsr;
	volatile guint16	first2_sr;
	tvbuff_t		*volatile tr_tvb;

	static tr_hdr trh_arr[4];
	static int trh_current=0;
	tr_hdr *volatile trh;

	/* non-source-routed version of source addr */
	static guint8		trn_shost_nonsr[6];
	int			x;

	/* Token-Ring Strings */
	const char *fc[] = { "MAC", "LLC", "Reserved", "Unknown" };


	trh_current++;
	if(trh_current==4){
		trh_current=0;
	}
	trh=&trh_arr[trh_current];

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "TR");

	if (fix_linux_botches)
		x = check_for_old_linux_tvb((tvbuff_t*) tvb);
	else
		x = 0;
	if (x != 0) {
		/* Actually packet starts x bytes into what we have got but with all
		   source routing compressed. See comment above */
		tr_tvb = tvb_new_subset((tvbuff_t*) tvb, x, -1, -1);
	}
	else {
		tr_tvb = tvb;
	}

	/* Get the data */
	trh->fc		= tvb_get_guint8(tr_tvb, 1);
	SET_ADDRESS(&trh->src,	AT_ETHER, 6, tvb_get_ptr(tr_tvb, 8, 6));
	SET_ADDRESS(&trh->dst,	AT_ETHER, 6, tvb_get_ptr(tr_tvb, 2, 6));

	memcpy(trn_shost_nonsr, trh->src.data, 6);
	trn_shost_nonsr[0] &= 127;
	frame_type = (trh->fc & 192) >> 6;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_fstr(pinfo->cinfo, COL_INFO, "Token-Ring %s", fc[frame_type]);

	/* if the high bit on the first byte of src hwaddr is 1, then
		this packet is source-routed */
	source_routed = trh->src.data[0] & 128;

	trn_rif_bytes = tvb_get_guint8(tr_tvb, 14) & 31;

	if (fix_linux_botches) {
		/* the Linux 2.0 TR code strips source-route bits in
		 * order to test for SR. This can be removed from most
		 * packets with oltr, but not all. So, I try to figure out
		 * which packets should have been SR here. I'll check to
		 * see if there's a SNAP or IPX field right after
		 * my RIF fields.
		 *
		 * The Linux 2.4.18 code, at least appears to do the
		 * same thing, from a capture I got from somebody running
		 * 2.4.18 (RH 7.1, so perhaps this is a Red Hat
		 * "improvement").
		 */
		if (frame_type == 1 && !source_routed && trn_rif_bytes > 0) {
			TRY {

				c1_nonsr = tvb_get_guint8(tr_tvb, 14);
				c2_nonsr = tvb_get_guint8(tr_tvb, 15);

				if (c1_nonsr != c2_nonsr) {

					first2_sr = tvb_get_ntohs(tr_tvb, trn_rif_bytes + 0x0e);

					if ( ( first2_sr == 0xaaaa &&
						tvb_get_guint8(tr_tvb, trn_rif_bytes + 0x10) == 0x03)   ||

						first2_sr == 0xe0e0 ||
						first2_sr == 0xe0aa ) {

						source_routed = 1;
					}
				}
			}
			CATCH(BoundsError) {
				/* We had no information beyond the TR header. Just assume
				 * this is a normal (non-Linux) TR header. */
				;
			}
			ENDTRY;
		}
	}

	if (source_routed) {
		actual_rif_bytes = trn_rif_bytes;
	}
	else {
		trn_rif_bytes = 0;
		actual_rif_bytes = 0;
	}

	if (fix_linux_botches) {
		/* this is a silly hack for Linux 2.0.x. Read the comment
		 * below, in front of the other #ifdef linux. If we're
		 * sniffing our own NIC, we get a full RIF, sometimes with
		 * garbage
		 */
		TRY {
			if (frame_type == 1 && ( (source_routed && trn_rif_bytes == 2) ||
						 !source_routed) ) {
				/* look for SNAP or IPX only */
				if (
					(tvb_get_ntohs(tr_tvb, 0x20) == 0xaaaa &&
					tvb_get_guint8(tr_tvb, 0x22) == 0x03)
				 ||
					tvb_get_ntohs(tr_tvb, 0x20) == 0xe0e0 ) {

					actual_rif_bytes = 18;
				}
				else if (
					tvb_get_ntohl(tr_tvb, 0x23) == 0 &&
					tvb_get_guint8(tr_tvb, 0x27) == 0x11) {

					actual_rif_bytes = 18;

				       /* Linux 2.0.x also requires drivers
				        * pass up a fake SNAP and LLC header
					* before the real LLC hdr for all
					* Token Ring frames that arrive with
					* DSAP and SSAP != 0xAA
					* (i.e. for non SNAP frames e.g. for
					* Netware frames)
					* the fake SNAP header has the
					* ETH_P_TR_802_2 ether type (0x0011)
					* and the protocol id bytes as zero frame looks like :-
					* TR Header | Fake LLC | Fake SNAP | Wire LLC | Rest of data
					*/
					fixoffset += 8; /* Skip fake LLC and SNAP */
				}
			}
		}
		CATCH(BoundsError) {
			/* We had no information beyond the TR header. Just assume
			 * this is a normal (non-Linux) TR header. */
			;
		}
		ENDTRY;
	}

	/* XXX - copy it to some buffer associated with "*pinfo", rather than
	   just making "trn_shost_nonsr" static? */
	SET_ADDRESS(&pinfo->dl_src,	AT_ETHER, 6, trn_shost_nonsr);
	SET_ADDRESS(&pinfo->src,	AT_ETHER, 6, trn_shost_nonsr);
	SET_ADDRESS(&pinfo->dl_dst,	AT_ETHER, 6, trh->dst.data);
	SET_ADDRESS(&pinfo->dst,	AT_ETHER, 6, trh->dst.data);

	/* protocol analysis tree */
	if (tree) {
		/* Create Token-Ring Tree */
		ti = proto_tree_add_item(tree, proto_tr, tr_tvb, 0, TR_MIN_HEADER_LEN + actual_rif_bytes, FALSE);
		tr_tree = proto_item_add_subtree(ti, ett_token_ring);

		/* Create the Access Control bitfield tree */
		trh->ac = tvb_get_guint8(tr_tvb, 0);
		ti = proto_tree_add_uint(tr_tree, hf_tr_ac, tr_tvb, 0, 1, trh->ac);
		bf_tree = proto_item_add_subtree(ti, ett_token_ring_ac);

		proto_tree_add_uint(bf_tree, hf_tr_priority, tr_tvb, 0, 1, trh->ac);
		proto_tree_add_boolean(bf_tree, hf_tr_frame, tr_tvb, 0, 1, trh->ac);
		proto_tree_add_uint(bf_tree, hf_tr_monitor_cnt, tr_tvb, 0, 1, trh->ac);
		proto_tree_add_uint(bf_tree, hf_tr_priority_reservation, tr_tvb, 0, 1, trh->ac);

		/* Create the Frame Control bitfield tree */
		ti = proto_tree_add_uint(tr_tree, hf_tr_fc, tr_tvb, 1, 1, trh->fc);
		bf_tree = proto_item_add_subtree(ti, ett_token_ring_fc);

		proto_tree_add_uint(bf_tree, hf_tr_fc_type, tr_tvb, 1, 1, trh->fc);
		proto_tree_add_uint(bf_tree, hf_tr_fc_pcf, tr_tvb,  1, 1, trh->fc);
		proto_tree_add_ether(tr_tree, hf_tr_dst, tr_tvb, 2, 6, trh->dst.data);
		proto_tree_add_ether(tr_tree, hf_tr_src, tr_tvb, 8, 6, trh->src.data);
		proto_tree_add_ether_hidden(tr_tree, hf_tr_addr, tr_tvb, 2, 6, trh->dst.data);
		proto_tree_add_ether_hidden(tr_tree, hf_tr_addr, tr_tvb, 8, 6, trh->src.data);

		proto_tree_add_boolean(tr_tree, hf_tr_sr, tr_tvb, 8, 1, source_routed);

		/* non-source-routed version of src addr */
		proto_tree_add_ether_hidden(tr_tree, hf_tr_src, tr_tvb, 8, 6, trn_shost_nonsr);

		if (source_routed) {
			/* RCF Byte 1 */
			rcf1 = tvb_get_guint8(tr_tvb, 14);
			proto_tree_add_uint(tr_tree, hf_tr_rif_bytes, tr_tvb, 14, 1, trn_rif_bytes);
			proto_tree_add_uint(tr_tree, hf_tr_broadcast, tr_tvb, 14, 1, rcf1 & 224);

			/* RCF Byte 2 */
			rcf2 = tvb_get_guint8(tr_tvb, 15);
			proto_tree_add_uint(tr_tree, hf_tr_max_frame_size, tr_tvb, 15, 1, rcf2 & 112);
			proto_tree_add_uint(tr_tree, hf_tr_direction, tr_tvb, 15, 1, rcf2 & 128);

			/* if we have more than 2 bytes of RIF, then we have
				ring/bridge pairs */
			if (trn_rif_bytes > 2) {
				add_ring_bridge_pairs(trn_rif_bytes, tr_tvb, tr_tree);
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
		frame type is LLC.  It's very much a hack. */
		if (actual_rif_bytes > trn_rif_bytes) {
			proto_tree_add_text(tr_tree, tr_tvb, TR_MIN_HEADER_LEN + trn_rif_bytes, actual_rif_bytes - trn_rif_bytes,
				"Empty RIF from Linux 2.0.x driver. The sniffing NIC "
				"is also running a protocol stack.");
		}
		if (fixoffset) {
			proto_tree_add_text(tr_tree, tr_tvb, TR_MIN_HEADER_LEN + 18,8,"Linux 2.0.x fake LLC and SNAP header");
		}
	}

	next_tvb = tvb_new_subset(tr_tvb, TR_MIN_HEADER_LEN + actual_rif_bytes + fixoffset, -1, -1);

	/* The package is either MAC or LLC */
	switch (frame_type) {
		/* MAC */
		case 0:
			call_dissector(trmac_handle, next_tvb, pinfo, tree);
			break;
		case 1:
			call_dissector(llc_handle, next_tvb, pinfo, tree);
			break;
		default:
			/* non-MAC, non-LLC, i.e., "Reserved" */
			call_dissector(data_handle,next_tvb, pinfo, tree);
			break;
	}

	tap_queue_packet(tr_tap, pinfo, trh);
}

/* this routine is taken from the Linux net/802/tr.c code, which shows
ring-bridge pairs in the /proc/net/tr_rif virtual file. */
static void
add_ring_bridge_pairs(int rcf_len, tvbuff_t *tvb, proto_tree *tree)
{
	int 	j, size;
	int 	segment, brdgnmb, unprocessed_rif;
	int	buff_offset=0;

#define RIF_OFFSET		16
#define RIF_BYTES_TO_PROCESS	30

	char	*buffer;
#define MAX_BUF_LEN 3 + (RIF_BYTES_TO_PROCESS / 2) * 6 + 1

	buffer=ep_alloc(MAX_BUF_LEN);
	/* Only process so many  bytes of RIF, as per TR spec, and not overflow
	 * static buffer above */
	unprocessed_rif = rcf_len - RIF_BYTES_TO_PROCESS;
	rcf_len = MIN(rcf_len, RIF_BYTES_TO_PROCESS);

	/* Ignore the 2 RCF bytes, since they don't make up the ring/bride pairs */
	rcf_len -= 2;

	for(j = 1; j < rcf_len - 1; j += 2) {
		if (j==1) {
			segment = tvb_get_ntohs(tvb, RIF_OFFSET) >> 4;
			size = g_snprintf(buffer, MAX_BUF_LEN, "%03X",segment);
			proto_tree_add_uint_hidden(tree, hf_tr_rif_ring, tvb, TR_MIN_HEADER_LEN + 2, 2, segment);
			buff_offset += size;
		}
		segment = tvb_get_ntohs(tvb, RIF_OFFSET + 1 + j) >> 4;
		brdgnmb = tvb_get_guint8(tvb, RIF_OFFSET + j) & 0x0f;
		size = g_snprintf(buffer+buff_offset, MAX_BUF_LEN-buff_offset, "-%01X-%03X",brdgnmb,segment);
		proto_tree_add_uint_hidden(tree, hf_tr_rif_ring, tvb, TR_MIN_HEADER_LEN + 3 + j, 2, segment);
		proto_tree_add_uint_hidden(tree, hf_tr_rif_bridge, tvb, TR_MIN_HEADER_LEN + 2 + j, 1, brdgnmb);
		buff_offset += size;
	}
	proto_tree_add_string(tree, hf_tr_rif, tvb, TR_MIN_HEADER_LEN + 2, rcf_len, buffer);

	if (unprocessed_rif > 0) {
		proto_tree_add_text(tree, tvb, TR_MIN_HEADER_LEN + RIF_BYTES_TO_PROCESS, unprocessed_rif,
				"Extra RIF bytes beyond spec: %d", unprocessed_rif);
	}
}

void
proto_register_tr(void)
{
	static hf_register_info hf[] = {
		{ &hf_tr_ac,
		{ "Access Control",	"tr.ac", FT_UINT8, BASE_HEX, NULL, 0x0,
			"", HFILL }},

		{ &hf_tr_priority,
		{ "Priority",		"tr.priority", FT_UINT8, BASE_DEC, NULL, 0xe0,
			"", HFILL }},

		{ &hf_tr_frame,
		{ "Frame",		"tr.frame", FT_BOOLEAN, 8, TFS(&ac_truth), 0x10,
			"", HFILL }},

		{ &hf_tr_monitor_cnt,
		{ "Monitor Count",	"tr.monitor_cnt", FT_UINT8, BASE_DEC, NULL, 0x08,
			"", HFILL }},

		{ &hf_tr_priority_reservation,
		{ "Priority Reservation","tr.priority_reservation", FT_UINT8, BASE_DEC, NULL, 0x07,
			"", HFILL }},

		{ &hf_tr_fc,
		{ "Frame Control",	"tr.fc", FT_UINT8, BASE_HEX, NULL, 0x0,
			"", HFILL }},

		{ &hf_tr_fc_type,
		{ "Frame Type",		"tr.frame_type", FT_UINT8, BASE_DEC, VALS(frame_vals), 0xc0,
			"", HFILL }},

		{ &hf_tr_fc_pcf,
		{ "Frame PCF",		"tr.frame_pcf", FT_UINT8, BASE_DEC, VALS(pcf_vals), 0x0f,
			"", HFILL }},

		{ &hf_tr_dst,
		{ "Destination",	"tr.dst", FT_ETHER, BASE_NONE,  NULL, 0x0,
			"Destination Hardware Address", HFILL }},

		{ &hf_tr_src,
		{ "Source",		"tr.src", FT_ETHER, BASE_NONE, NULL, 0x0,
			"Source Hardware Address", HFILL }},

		{ &hf_tr_addr,
		{ "Source or Destination Address", "tr.addr", FT_ETHER, BASE_NONE, NULL, 0x0,
			"Source or Destination Hardware Address", HFILL }},

		{ &hf_tr_sr,
		{ "Source Routed",	"tr.sr", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Source Routed", HFILL }},

		{ &hf_tr_rif_bytes,
		{ "RIF Bytes",		"tr.rif_bytes", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Number of bytes in Routing Information Fields, including "
			"the two bytes of Routing Control Field", HFILL }},

		{ &hf_tr_broadcast,
		{ "Broadcast Type",	"tr.broadcast", FT_UINT8, BASE_DEC, VALS(broadcast_vals), 0x0,
			"Type of Token-Ring Broadcast", HFILL }},

		{ &hf_tr_max_frame_size,
		{ "Maximum Frame Size",	"tr.max_frame_size", FT_UINT8, BASE_DEC, VALS(max_frame_size_vals),
			0x0,
			"", HFILL }},

		{ &hf_tr_direction,
		{ "Direction",		"tr.direction", FT_UINT8, BASE_DEC, VALS(direction_vals), 0x0,
			"Direction of RIF", HFILL }},

		{ &hf_tr_rif,
		{ "Ring-Bridge Pairs",	"tr.rif", FT_STRING, BASE_NONE, NULL, 0x0,
			"String representing Ring-Bridge Pairs", HFILL }},

		{ &hf_tr_rif_ring,
		{ "RIF Ring",		"tr.rif.ring", FT_UINT16, BASE_HEX, NULL, 0x0,
			"", HFILL }},

		{ &hf_tr_rif_bridge,
		{ "RIF Bridge",		"tr.rif.bridge", FT_UINT8, BASE_HEX, NULL, 0x0,
			"", HFILL }},
	};
	static gint *ett[] = {
		&ett_token_ring,
		&ett_token_ring_ac,
		&ett_token_ring_fc,
	};
	module_t *tr_module;

	proto_tr = proto_register_protocol("Token-Ring", "Token-Ring", "tr");
	proto_register_field_array(proto_tr, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register configuration options */
	tr_module = prefs_register_protocol(proto_tr, NULL);
	prefs_register_bool_preference(tr_module, "fix_linux_botches",
	    "Attempt to compensate for Linux mangling of the link-layer header",
	    "Whether Linux mangling of the link-layer header should be checked for and worked around",
	    &fix_linux_botches);

	register_dissector("tr", dissect_tr, proto_tr);
	tr_tap=register_tap("tr");
}

void
proto_reg_handoff_tr(void)
{
	dissector_handle_t tr_handle;

	/*
	 * Get handles for the TR MAC and LLC dissectors.
	 */
	trmac_handle = find_dissector("trmac");
	llc_handle = find_dissector("llc");
	data_handle = find_dissector("data");

	tr_handle = find_dissector("tr");
	dissector_add("wtap_encap", WTAP_ENCAP_TOKEN_RING, tr_handle);
}
