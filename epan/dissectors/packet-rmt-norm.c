/* packet-rmt-norm.c
 * Reliable Multicast Transport (RMT)
 * NORM Protocol Instantiation dissector
 * Copyright 2005, Stefano Pettini <spettini@users.sourceforge.net>
 *
 * Extensive changes to decode more information Julian Onions
 *
 * Negative-acknowledgment (NACK)-Oriented Reliable Multicast (NORM):
 * ------------------------------------------------------------------
 *
 * This protocol is designed to provide end-to-end reliable transport of
 * bulk data objects or streams over generic IP multicast routing and
 * forwarding services.  NORM uses a selective, negative acknowledgment
 * mechanism for transport reliability and offers additional protocol
 * mechanisms to allow for operation with minimal "a priori"
 * coordination among senders and receivers.
 *
 * References:
 *     RFC 3940, Negative-acknowledgment (NACK)-Oriented Reliable Multicast (NORM) Protocol
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/strutil.h>

#include "packet-rmt-norm.h"
#include <math.h>

/* String tables */
static const value_string string_norm_type[] =
{
	{ NORM_INFO, "INFO" },
	{ NORM_DATA, "DATA" },
	{ NORM_CMD, "CMD" },
	{ NORM_NACK, "NACK" },
	{ NORM_ACK, "ACK" },
	{ NORM_REPORT, "REPORT" },
	{ 0, NULL }
};

static const value_string string_norm_cmd_type[] =
{
	{ NORM_CMD_FLUSH, "FLUSH" },
	{ NORM_CMD_EOT, "EOT" },
	{ NORM_CMD_SQUELCH, "SQUELCH" },
	{ NORM_CMD_CC, "CC" },
	{ NORM_CMD_REPAIR_ADV, "REPAIR_ADV" },
	{ NORM_CMD_ACK_REQ, "ACK_REQ" },
	{ NORM_CMD_APPLICATION, "APPLICATION" },
	{ 0, NULL }
};

static const value_string string_norm_ack_type[] =
{
	{ NORM_ACK_CC, "ACK CC" },
	{ NORM_ACK_FLUSH, "ACK FLUSH" },
	{ 0, NULL }
};

static const value_string string_norm_nack_form[] =
{
	{ NORM_NACK_ITEMS, "Items" },
	{ NORM_NACK_RANGES, "Ranges" },
	{ NORM_NACK_ERASURES, "Erasures" },
	{ 0, NULL }
};

#define hdrlen2bytes(x) ((x)*4U)

/* Initialize the protocol and registered fields */
/* ============================================= */

static int proto = -1;
static gboolean global_norm_heur = FALSE;

static struct _norm_hf hf;
static struct _norm_ett ett;

static gboolean preferences_initialized = FALSE;
static struct _norm_prefs preferences;
static struct _norm_prefs preferences_old;

/* Preferences */
/* =========== */

/* Set/Reset preferences to default values */
static void norm_prefs_set_default(struct _norm_prefs *prefs)
{
	fec_prefs_set_default(&prefs->fec);
}

/* Register preferences */
static void norm_prefs_register(struct _norm_prefs *prefs, module_t *module)
{
	fec_prefs_register(&prefs->fec, module);
}

/* Save preferences to alc_prefs_old */
static void norm_prefs_save(struct _norm_prefs *p, struct _norm_prefs *p_old)
{
	*p_old = *p;
}

static const double RTT_MIN = 1.0e-06;
static const double RTT_MAX = 1000;

static double UnquantizeRtt(unsigned char qrtt)
{
	 return ((qrtt <= 31) ? (((double)(qrtt+1))*(double)RTT_MIN) :
		(RTT_MAX/exp(((double)(255-qrtt))/(double)13.0)));
}

static double UnquantizeGSize(guint8 gsize)
{
	guint mant = (gsize & 0x8) ? 5 : 1;
	guint exponent = gsize & 0x7;
	exponent ++;
	return mant * pow(10, exponent);
}

static double UnquantizeSendRate(guint16 send_rate)
{
	return (send_rate >> 4) * 10.0 / 4096.0 * pow(10.0, (send_rate & 0x000f));
}

/* code to dissect fairly common sequence in NORM packets */
static guint dissect_grrtetc(proto_tree *tree, tvbuff_t *tvb, guint offset)
{
	guint8 backoff;
	double gsize;
	double grtt;
	proto_tree_add_item(tree, hf.instance_id, tvb, offset, 2, FALSE); offset+=2;
	grtt = UnquantizeRtt(tvb_get_guint8(tvb, offset));
	proto_tree_add_double(tree, hf.grtt, tvb, offset, 1, grtt); offset++;
	backoff = hi_nibble(tvb_get_guint8(tvb, offset));
	gsize = UnquantizeGSize((guint8)lo_nibble(tvb_get_guint8(tvb, offset)));
	proto_tree_add_uint(tree, hf.backoff, tvb, offset, 1, backoff);
	proto_tree_add_double(tree, hf.gsize, tvb, offset, 1, gsize);
	offset++;
	return offset;
}

/* split out some common FEC handling */
static guint dissect_feccode(struct _norm *norm, struct _fec_ptr *f, proto_tree *tree,
							 tvbuff_t *tvb, guint offset, packet_info *pinfo, gint reserved)
{
	f->fec = &norm->fec;
	f->hf = &hf.fec;
	f->ett = &ett.fec;
	f->prefs = &preferences.fec;


	norm->fec.encoding_id = tvb_get_guint8(tvb, offset);
	norm->fec.encoding_id_present = 1;
	proto_tree_add_item(tree, hf.fec.encoding_id, tvb, offset, 1, FALSE); offset++;
	if (reserved) {
		proto_tree_add_item(tree, hf.reserved, tvb, offset, 1, FALSE); offset++;
	}
	proto_tree_add_item(tree, hf.object_transport_id, tvb, offset, 2, FALSE); offset+=2;

	if (norm->fec.encoding_id_present &&
	    tvb_reported_length_remaining(tvb, offset) > 0) {
		fec_dissector(*f, tvb, tree, &offset);
		if (check_col(pinfo->cinfo, COL_INFO))
			fec_info_column(f->fec, pinfo);
	}
	return offset;
}

static guint dissect_norm_hdrext(struct _norm *norm, struct _fec_ptr *f, proto_tree *tree,
							 tvbuff_t *tvb, guint offset, packet_info *pinfo _U_)
{
	guint i;
	proto_item *ti;
	/* Allocate an array of _ext elements */
	GArray *ext;
	guint offset_old = offset;
	proto_tree *ext_tree;

	ext = g_array_new(FALSE, TRUE, sizeof(struct _ext));

	rmt_ext_parse(ext, tvb, &offset, hdrlen2bytes(norm->hlen));

	if (ext->len > 0)
	{
		struct _lct_prefs lctp;
		memset(&lctp, 0, sizeof(lctp));
		if (tree)
		{
			/* Add the extensions subtree */
			ti = proto_tree_add_uint(tree, hf.extension,
				tvb, offset_old,
				offset - offset_old, ext->len);
			ext_tree = proto_item_add_subtree(ti, ett.hdrext);
		} else
			ext_tree = NULL;

		/* Add the extensions to the subtree */
		for (i = 0; i < ext->len; i++) {
			struct _ext *e = &g_array_index(ext, struct _ext, i);

			lct_ext_decode(e, &lctp, tvb, ext_tree, ett.hdrext, *f);
			/* fec_decode_ext_fti(e, tvb, ext_tree, ett.hdrext, *f); */
		}
	}
	g_array_free(ext, TRUE);
	return offset;
}

static guint dissect_nack_data(struct _norm *norm, proto_tree *tree,
							 tvbuff_t *tvb, guint offset, packet_info *pinfo)
{
	proto_item *ti, *tif;
	proto_tree *nack_tree, *flag_tree;
	guint16 len;
	ti = proto_tree_add_text(tree, tvb, offset, -1, "NACK Data");
	nack_tree = proto_item_add_subtree(ti, ett.nackdata);
	proto_tree_add_item(nack_tree, hf.nack_form, tvb, offset, 1, FALSE); offset += 1;

	tif = proto_tree_add_item(nack_tree, hf.nack_flags, tvb, offset, 1, FALSE);
	flag_tree = proto_item_add_subtree(tif, ett.flags);
	proto_tree_add_item(flag_tree, hf.nack_flags_segment, tvb, offset, 1, FALSE);
	proto_tree_add_item(flag_tree, hf.nack_flags_block, tvb, offset, 1, FALSE);
	proto_tree_add_item(flag_tree, hf.nack_flags_info, tvb, offset, 1, FALSE);
	proto_tree_add_item(flag_tree, hf.nack_flags_object, tvb, offset, 1, FALSE);
	offset += 1;
	len = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(nack_tree, hf.nack_length, tvb, offset, 2, FALSE); offset += 2;
	proto_item_set_len(ti, 4+len);
	if (len > 4) {
		struct _fec_ptr f;
		dissect_feccode(norm, &f, nack_tree, tvb, offset, pinfo, 1);
	}
	offset += len;
	return offset;
}


/* code to dissect NORM data packets */
static void dissect_norm_data(struct _norm *norm, proto_tree *tree,
	tvbuff_t *tvb, guint offset, packet_info *pinfo)
{
	guint8 flags;
	proto_item *ti;
	proto_tree *flag_tree;
	struct _fec_ptr f;

	offset = dissect_grrtetc(tree, tvb, offset);


	ti = proto_tree_add_item(tree, hf.flags, tvb, offset, 1, FALSE);
	flags = tvb_get_guint8(tvb, offset);
	flag_tree = proto_item_add_subtree(ti, ett.flags);
	proto_tree_add_item(flag_tree, hf.flag.repair, tvb, offset, 1, FALSE);
	proto_tree_add_item(flag_tree, hf.flag.explicit, tvb, offset, 1, FALSE);
	proto_tree_add_item(flag_tree, hf.flag.info, tvb, offset, 1, FALSE);
	proto_tree_add_item(flag_tree, hf.flag.unreliable, tvb, offset, 1, FALSE);
	proto_tree_add_item(flag_tree, hf.flag.file, tvb, offset, 1, FALSE);
	proto_tree_add_item(flag_tree, hf.flag.stream, tvb, offset, 1, FALSE);
	proto_tree_add_item(flag_tree, hf.flag.msgstart, tvb, offset, 1, FALSE);
	offset++;

	offset = dissect_feccode(norm, &f, tree, tvb, offset, pinfo, 0);

	if (offset < hdrlen2bytes(norm->hlen)) {
		offset = dissect_norm_hdrext(norm, &f, tree, tvb, offset, pinfo);
	}
	if (flags & NORM_FLAG_STREAM) {
		ti = proto_tree_add_text(tree, tvb, offset, 8, "Stream Data");
		flag_tree = proto_item_add_subtree(ti, ett.streampayload);
		proto_tree_add_item(flag_tree, hf.reserved, tvb, offset, 2, FALSE); offset+=2;
		proto_tree_add_item(flag_tree, hf.payload_len, tvb, offset, 2, FALSE); offset+=2;
		proto_tree_add_item(flag_tree, hf.payload_offset, tvb, offset, 4, FALSE); offset+=4;

	}
	if (tvb_reported_length_remaining(tvb, offset) > 0)
		proto_tree_add_none_format(tree, hf.payload, tvb, offset, -1, "Payload (%u bytes)", tvb_reported_length_remaining(tvb, offset));

}

/* code to dissect NORM info packets */
static void dissect_norm_info(struct _norm *norm, proto_tree *tree,
	tvbuff_t *tvb, guint offset, packet_info *pinfo _U_)
{
	guint8 flags;
	proto_item *ti;
	proto_tree *flag_tree;

	offset = dissect_grrtetc(tree, tvb, offset);

	ti = proto_tree_add_item(tree, hf.flags, tvb, offset, 1, FALSE);
	flags = tvb_get_guint8(tvb, offset);
	flag_tree = proto_item_add_subtree(ti, ett.flags);
	proto_tree_add_item(flag_tree, hf.flag.repair, tvb, offset, 1, FALSE);
	proto_tree_add_item(flag_tree, hf.flag.explicit, tvb, offset, 1, FALSE);
	proto_tree_add_item(flag_tree, hf.flag.info, tvb, offset, 1, FALSE);
	proto_tree_add_item(flag_tree, hf.flag.unreliable, tvb, offset, 1, FALSE);
	proto_tree_add_item(flag_tree, hf.flag.file, tvb, offset, 1, FALSE);
	proto_tree_add_item(flag_tree, hf.flag.stream, tvb, offset, 1, FALSE);
	proto_tree_add_item(flag_tree, hf.flag.msgstart, tvb, offset, 1, FALSE);
	offset++;

	norm->fec.encoding_id = tvb_get_guint8(tvb, offset);
	norm->fec.encoding_id_present = 1;
	proto_tree_add_item(tree, hf.fec.encoding_id, tvb, offset, 1, FALSE); offset++;
	proto_tree_add_item(tree, hf.object_transport_id, tvb, offset, 2, FALSE); offset+=2;

	if (offset < hdrlen2bytes(norm->hlen)) {
		struct _fec_ptr f;
		memset(&f, 0, sizeof f);
		f.fec = &norm->fec;
		f.hf = &hf.fec;
		f.ett = &ett.fec;
		f.prefs = &preferences.fec;
		offset = dissect_norm_hdrext(norm, &f, tree, tvb, offset, pinfo);
	}
	if (tvb_reported_length_remaining(tvb, offset) > 0)
		proto_tree_add_none_format(tree, hf.payload, tvb, offset, -1, "Payload (%u bytes)", tvb_reported_length_remaining(tvb, offset));

}
/* code to dissect NORM cmd(flush) packets */
static guint dissect_norm_cmd_flush(struct _norm *norm, proto_tree *tree,
	tvbuff_t *tvb, guint offset, packet_info *pinfo)
{
	struct _fec_ptr f;
	offset = dissect_feccode(norm, &f, tree, tvb, offset, pinfo, 0);
	if (offset < hdrlen2bytes(norm->hlen)) {
		offset = dissect_norm_hdrext(norm, &f, tree, tvb, offset, pinfo);
	}
	return offset;
}

/* code to dissect NORM cmd(flush) packets */
static guint dissect_norm_cmd_repairadv(struct _norm *norm, proto_tree *tree,
	tvbuff_t *tvb, guint offset, packet_info *pinfo)
{
	proto_tree_add_item(tree, hf.flags, tvb, offset, 1, FALSE); offset ++;
	proto_tree_add_item(tree, hf.reserved, tvb, offset, 2, FALSE); offset +=2;

	if (offset < hdrlen2bytes(norm->hlen)) {
		struct _fec_ptr f;
		memset(&f, 0, sizeof f);
		f.fec = &norm->fec;
		f.hf = &hf.fec;
		f.ett = &ett.fec;
		f.prefs = &preferences.fec;
		offset = dissect_norm_hdrext(norm, &f, tree, tvb, offset, pinfo);
	}
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		offset = dissect_nack_data(norm, tree, tvb, offset, pinfo);
	}
	return offset;
}

/* code to dissect NORM cmd(cc) packets */
static guint dissect_norm_cmd_cc(struct _norm *norm, proto_tree *tree,
	tvbuff_t *tvb, guint offset, packet_info *pinfo _U_)
{
	proto_tree_add_item(tree, hf.reserved, tvb, offset, 1, FALSE); offset ++;
	proto_tree_add_item(tree, hf.cc_sequence, tvb, offset, 2, FALSE); offset += 2;

	proto_tree_add_item(tree, hf.cc_sts, tvb, offset, 4, FALSE); offset += 4;
	proto_tree_add_item(tree, hf.cc_stus, tvb, offset, 4, FALSE); offset += 4;
	if (offset < hdrlen2bytes(norm->hlen)) {
		struct _fec_ptr f;
		memset(&f, 0, sizeof f);
		f.fec = &norm->fec;
		f.hf = &hf.fec;
		f.ett = &ett.fec;
		f.prefs = &preferences.fec;
		offset = dissect_norm_hdrext(norm, &f, tree, tvb, offset, pinfo);
	}
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		proto_item *ti, *tif;
		proto_tree *cc_tree, *flag_tree;
		double grtt;
		ti = proto_tree_add_text(tree, tvb, offset, 8, "Congestion Control");
		cc_tree = proto_item_add_subtree(ti, ett.congestioncontrol);
		proto_tree_add_item(cc_tree, hf.cc_node_id, tvb, offset, 4, FALSE); offset += 4;
		tif = proto_tree_add_item(cc_tree, hf.cc_flags, tvb, offset, 1, FALSE);
		flag_tree = proto_item_add_subtree(tif, ett.flags);
		proto_tree_add_item(flag_tree, hf.cc_flags_clr, tvb, offset, 1, FALSE);
		proto_tree_add_item(flag_tree, hf.cc_flags_plr, tvb, offset, 1, FALSE);
		proto_tree_add_item(flag_tree, hf.cc_flags_rtt, tvb, offset, 1, FALSE);
		proto_tree_add_item(flag_tree, hf.cc_flags_start, tvb, offset, 1, FALSE);
		proto_tree_add_item(flag_tree, hf.cc_flags_leave, tvb, offset, 1, FALSE);
		offset += 1;
		grtt = UnquantizeRtt(tvb_get_guint8(tvb, offset));
		proto_tree_add_double(cc_tree, hf.cc_rtt, tvb, offset, 1, grtt); offset += 1;
		grtt = UnquantizeSendRate(tvb_get_ntohs(tvb, offset));
		proto_tree_add_double(cc_tree, hf.cc_rate, tvb, offset, 2, grtt); offset += 2;
	}
	return offset;
}

/* code to dissect NORM cmd(squelch) packets */
static guint dissect_norm_cmd_squelch(struct _norm *norm, proto_tree *tree,
	tvbuff_t *tvb, guint offset, packet_info *pinfo)
{
	struct _fec_ptr f;
	offset = dissect_feccode(norm, &f, tree, tvb, offset, pinfo, 0);

	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		proto_tree_add_item(tree, hf.cc_transport_id, tvb, offset, 4, FALSE); offset += 2;
	}
	return offset;
}

/* code to dissect NORM cmd(squelch) packets */
static guint dissect_norm_cmd_ackreq(struct _norm *norm _U_, proto_tree *tree,
	tvbuff_t *tvb, guint offset, packet_info *pinfo _U_)
{
	proto_tree_add_item(tree, hf.reserved, tvb, offset, 1, FALSE); offset ++;
	proto_tree_add_item(tree, hf.ack_type, tvb, offset, 1, FALSE); offset += 1;
	proto_tree_add_item(tree, hf.ack_id, tvb, offset, 1, FALSE); offset += 1;
	return offset;
}

/* code to dissect NORM cmd packets */
static void dissect_norm_cmd(struct _norm *norm, proto_tree *tree,
	tvbuff_t *tvb, guint offset, packet_info *pinfo)
{
	guint8 flavor;

	offset = dissect_grrtetc(tree, tvb, offset);
	flavor = tvb_get_guint8(tvb, offset);
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_sep_str(pinfo->cinfo, COL_INFO, " ",
		val_to_str(flavor, string_norm_cmd_type, "Unknown Cmd Type (0x%04x)"));
	proto_tree_add_item(tree, hf.cmd_flavor, tvb, offset, 1, FALSE); offset ++;
	switch(flavor) {
	case NORM_CMD_CC:
		offset = dissect_norm_cmd_cc(norm, tree, tvb, offset, pinfo);
		break;
	case NORM_CMD_FLUSH:
		offset = dissect_norm_cmd_flush(norm, tree, tvb, offset, pinfo);
		break;
	case NORM_CMD_SQUELCH:
		offset = dissect_norm_cmd_squelch(norm, tree, tvb, offset, pinfo);
		break;
	case NORM_CMD_REPAIR_ADV:
		offset = dissect_norm_cmd_repairadv(norm, tree, tvb, offset, pinfo);
		break;
	case NORM_CMD_ACK_REQ:
		offset = dissect_norm_cmd_ackreq(norm, tree, tvb, offset, pinfo);
		break;
	}
	if (tvb_reported_length_remaining(tvb, offset) > 0)
		proto_tree_add_none_format(tree, hf.payload, tvb, offset, -1, "Payload (%u bytes)", tvb_reported_length_remaining(tvb, offset));
}

/* code to dissect NORM ack packets */
static void dissect_norm_ack(struct _norm *norm, proto_tree *tree,
	tvbuff_t *tvb, guint offset, packet_info *pinfo)
{
	guint8 acktype;

	proto_tree_add_item(tree, hf.ack_source, tvb, offset, 4, FALSE); offset += 4;
	proto_tree_add_item(tree, hf.instance_id, tvb, offset, 2, FALSE); offset += 2;
	acktype = tvb_get_guint8(tvb, offset);
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_sep_str(pinfo->cinfo, COL_INFO, " ",
		val_to_str(acktype, string_norm_ack_type, "Unknown Ack Type (0x%04x)"));
	proto_tree_add_item(tree, hf.ack_type, tvb, offset, 1, FALSE); offset += 1;
	proto_tree_add_item(tree, hf.ack_id, tvb, offset, 1, FALSE); offset += 1;
	proto_tree_add_item(tree, hf.ack_grtt_sec, tvb, offset, 4, FALSE); offset += 4;
	proto_tree_add_item(tree, hf.ack_grtt_usec, tvb, offset, 4, FALSE); offset += 4;
	if (offset < hdrlen2bytes(norm->hlen)) {
		struct _fec_ptr f;
		memset(&f, 0, sizeof f);
		f.fec = &norm->fec;
		f.hf = &hf.fec;
		f.ett = &ett.fec;
		f.prefs = &preferences.fec;
		offset = dissect_norm_hdrext(norm, &f, tree, tvb, offset, pinfo);
	}

	if (tvb_reported_length_remaining(tvb, offset) > 0)
		proto_tree_add_none_format(tree, hf.payload, tvb, offset, -1, "Payload (%u bytes)", tvb_reported_length_remaining(tvb, offset));

}



/* code to dissect NORM nack packets */
static void dissect_norm_nack(struct _norm *norm, proto_tree *tree,
	tvbuff_t *tvb, guint offset, packet_info *pinfo)
{
	proto_tree_add_item(tree, hf.nack_server, tvb, offset, 4, FALSE); offset += 4;
	proto_tree_add_item(tree, hf.instance_id, tvb, offset, 2, FALSE); offset += 2;
	proto_tree_add_item(tree, hf.reserved, tvb, offset, 2, FALSE); offset += 2;
	proto_tree_add_item(tree, hf.nack_grtt_sec, tvb, offset, 4, FALSE); offset += 4;
	proto_tree_add_item(tree, hf.nack_grtt_usec, tvb, offset, 4, FALSE); offset += 4;
	if (offset < hdrlen2bytes(norm->hlen)) {
		struct _fec_ptr f;
		memset(&f, 0, sizeof f);
		f.fec = &norm->fec;
		f.hf = &hf.fec;
		f.ett = &ett.fec;
		f.prefs = &preferences.fec;
		offset = dissect_norm_hdrext(norm, &f, tree, tvb, offset, pinfo);
	}

	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		offset = dissect_nack_data(norm, tree, tvb, offset, pinfo);
	}
	if (tvb_reported_length_remaining(tvb, offset) > 0)
		proto_tree_add_none_format(tree, hf.payload, tvb, offset, -1, "Payload (%u bytes)", tvb_reported_length_remaining(tvb, offset));

}
/* Code to actually dissect the packets */
/* ==================================== */

static void dissect_norm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/* Logical packet representation */
	struct _norm norm;

	/* Offset for subpacket dissection */
	guint offset;

	/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *norm_tree;

	/* Structures and variables initialization */
	offset = 0;
	memset(&norm, 0, sizeof(struct _norm));

	/* Update packet info */
	pinfo->current_proto = "NORM";

	/* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "NORM");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	/* NORM header dissection, part 1 */
	/* ------------------------------ */

	norm.version = hi_nibble(tvb_get_guint8(tvb, offset));

	if (tree)
	{
		/* Create subtree for the NORM protocol */
		ti = proto_tree_add_item(tree, proto, tvb, offset, -1, FALSE);
		norm_tree = proto_item_add_subtree(ti, ett.main);

		/* Fill the NORM subtree */
		proto_tree_add_uint(norm_tree, hf.version, tvb, offset, 1, norm.version);

	} else
		norm_tree = NULL;

	/* This dissector supports only NORMv1 packets.
	 * If norm.version > 1 print only version field and quit.
	 */
	if (norm.version == 1) {

		/* NORM header dissection, part 2 */
		/* ------------------------------ */

		norm.type = lo_nibble(tvb_get_guint8(tvb, offset));
		norm.hlen = tvb_get_guint8(tvb, offset+1);
		norm.sequence = tvb_get_ntohs(tvb, offset+2);
		norm.source_id = tvb_get_ntohl(tvb, offset+4);

		if (tree)
		{
			proto_tree_add_uint(norm_tree, hf.type, tvb, offset, 1, norm.type);
			proto_tree_add_uint(norm_tree, hf.hlen, tvb, offset+1, 1, norm.hlen);
			proto_tree_add_uint(norm_tree, hf.sequence, tvb, offset+2, 2, norm.sequence);
			proto_tree_add_item(norm_tree, hf.source_id, tvb, offset+4, 4, FALSE);
		}

		offset += 8;


		/* Complete entry in Info column on summary display */
		/* ------------------------------------------------ */
		if (check_col(pinfo->cinfo, COL_INFO))
				col_append_sep_str(pinfo->cinfo, COL_INFO, " ",
				val_to_str(norm.type, string_norm_type, "Unknown Type (0x%04x)"));


		switch(norm.type) {
		case NORM_INFO:
			dissect_norm_info(&norm, norm_tree, tvb, offset, pinfo);
			break;
		case NORM_DATA:
			dissect_norm_data(&norm, norm_tree, tvb, offset, pinfo);
			break;
		case NORM_CMD:
			dissect_norm_cmd(&norm, norm_tree, tvb, offset, pinfo);
			break;
		case NORM_ACK:
			dissect_norm_ack(&norm, norm_tree, tvb, offset, pinfo);
			break;
		case NORM_NACK:
			dissect_norm_nack(&norm, norm_tree, tvb, offset, pinfo);
			break;
		default:
			/* Add the Payload item */
			if (tvb_reported_length_remaining(tvb, offset) > 0)
				proto_tree_add_none_format(norm_tree, hf.payload, tvb, offset, -1, "Payload (%u bytes)", tvb_reported_length_remaining(tvb, offset));
			break;
		}

	} else {

		if (tree)
			proto_tree_add_text(norm_tree, tvb, 0, -1, "Sorry, this dissector supports NORM version 1 only");

		/* Complete entry in Info column on summary display */
		if (check_col(pinfo->cinfo, COL_INFO))
			col_add_fstr(pinfo->cinfo, COL_INFO, "Version: %u (not supported)", norm.version);
	}
}

static gboolean
dissect_norm_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 byte1;
	if (!global_norm_heur)
		return FALSE;
	if (!tvb_bytes_exist(tvb, 0, 2))
		return FALSE;	/* not enough to check */
	byte1 = tvb_get_guint8(tvb, 0);

	if (hi_nibble(byte1) != 1) return FALSE;
	if (lo_nibble(byte1) < 1 || lo_nibble(byte1) > 6) return FALSE;
	if (tvb_get_guint8(tvb, 1) > 20) return FALSE;
	if (tvb_length_remaining(tvb, 0) < 12)
		return FALSE;
	dissect_norm(tvb, pinfo, tree);
	return TRUE; /* appears to be a NORM packet */
}

void proto_reg_handoff_norm(void)
{
	static dissector_handle_t handle;

	if (!preferences_initialized)
	{
		preferences_initialized = TRUE;
		handle = create_dissector_handle(dissect_norm, proto);
		dissector_add_handle("udp.port", handle);
		heur_dissector_add("udp", dissect_norm_heur, proto);
	}

	norm_prefs_save(&preferences, &preferences_old);
}

void proto_register_norm(void)
{
	/* Setup NORM header fields */
	static hf_register_info hf_ptr[] = {

		{ &hf.version,
			{ "Version", "norm.version", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf.type,
			{ "Message Type", "norm.type", FT_UINT8, BASE_DEC, VALS(string_norm_type), 0x0, "", HFILL }},
		{ &hf.hlen,
			{ "Header length", "norm.hlen", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf.sequence,
			{ "Sequence", "norm.sequence", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf.source_id,
			{ "Source ID", "norm.source_id", FT_IPv4, BASE_NONE, NULL, 0x0, "", HFILL }},
		{ &hf.instance_id,
			{ "Instance", "norm.instance_id", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL}},
		{ &hf.grtt,
			{ "grtt", "norm.grtt", FT_DOUBLE, BASE_DEC, NULL, 0x0, "", HFILL}},
		{ &hf.backoff,
			{ "Backoff", "norm.backoff", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL}},
		{ &hf.gsize,
			{ "Group Size", "norm.gsize", FT_DOUBLE, BASE_DEC, NULL, 0x0, "", HFILL}},
		{ &hf.flags,
			{ "Flags", "norm.flags", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL}},
	    { &hf.flag.repair,
		    { "Repair Flag", "norm.flag.repair", FT_BOOLEAN, 8, NULL, NORM_FLAG_REPAIR, "", HFILL }},
	    { &hf.flag.explicit,
		    { "Explicit Flag", "norm.flag.explicit", FT_BOOLEAN, 8, NULL, NORM_FLAG_EXPLICIT, "", HFILL }},
	    { &hf.flag.info,
		    { "Info Flag", "norm.flag.info", FT_BOOLEAN, 8, NULL, NORM_FLAG_INFO, "", HFILL }},
	    { &hf.flag.unreliable,
		    { "Unreliable Flag", "norm.flag.unreliable", FT_BOOLEAN, 8, NULL, NORM_FLAG_UNRELIABLE, "", HFILL }},
	    { &hf.flag.file,
		    { "File Flag", "norm.flag.file", FT_BOOLEAN, 8, NULL, NORM_FLAG_FILE, "", HFILL }},
	    { &hf.flag.stream,
		    { "Stream Flag", "norm.flag.stream", FT_BOOLEAN, 8, NULL, NORM_FLAG_STREAM, "", HFILL }},
	    { &hf.flag.msgstart,
		    { "Msg Start Flag", "norm.flag.msgstart", FT_BOOLEAN, 8, NULL, NORM_FLAG_MSG_START, "", HFILL }},
		{ &hf.object_transport_id,
			{ "Object Transport ID", "norm.object_transport_id", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL}},
		{ &hf.extension,
			{ "Hdr Extension", "norm.hexext", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL}},
		{ &hf.reserved,
			{ "Reserved", "norm.reserved", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL}},
		{ &hf.payload_len,
			{ "Payload Len", "norm.payload.len", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL}},
		{ &hf.payload_offset,
			{ "Payload Offset", "norm.payload.offset", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},

		{ &hf.cmd_flavor,
			{ "Flavor", "norm.flavor", FT_UINT8, BASE_DEC, VALS(string_norm_cmd_type), 0x0, "", HFILL}},
		{ &hf.cc_sequence,
			{ "CC Sequence", "norm.ccsequence", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL}},
		{ &hf.cc_sts,
			{ "Send Time secs", "norm.cc_sts", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},
		{ &hf.cc_stus,
			{ "Send Time usecs", "norm.cc_stus", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},
		{ &hf.cc_node_id,
			{ "CC Node ID", "norm.cc_node_id", FT_IPv4, BASE_NONE, NULL, 0x0, "", HFILL}},
		{ &hf.cc_flags,
			{ "CC Flags", "norm.cc_flags", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL}},
		{ &hf.cc_flags_clr,
			{ "CLR", "norm.cc_flags.clr", FT_BOOLEAN, 8, NULL, NORM_FLAG_CC_CLR, "", HFILL}},
		{ &hf.cc_flags_plr,
			{ "PLR", "norm.cc_flags.plr", FT_BOOLEAN, 8, NULL, NORM_FLAG_CC_PLR, "", HFILL}},
		{ &hf.cc_flags_rtt,
			{ "RTT", "norm.cc_flags.rtt", FT_BOOLEAN, 8, NULL, NORM_FLAG_CC_RTT, "", HFILL}},
		{ &hf.cc_flags_start,
			{ "Start", "norm.cc_flags.start", FT_BOOLEAN, 8, NULL, NORM_FLAG_CC_START, "", HFILL}},
		{ &hf.cc_flags_leave,
			{ "Leave", "norm.cc_flags.leave", FT_BOOLEAN, 8, NULL, NORM_FLAG_CC_LEAVE, "", HFILL}},
		{ &hf.cc_rtt,
			{ "CC RTT", "norm.cc_rtt", FT_DOUBLE, BASE_DEC, NULL, 0x0, "", HFILL}},
		{ &hf.cc_rate,
			{ "CC Rate", "norm.cc_rate", FT_DOUBLE, BASE_DEC, NULL, 0x0, "", HFILL}},
		{ &hf.cc_transport_id,
			{ "CC Transport ID", "norm.cc_transport_id", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL}},

		{ &hf.ack_source,
			{ "Ack Source", "norm.ack.source", FT_IPv4, BASE_DEC, NULL, 0x0, "", HFILL}},
		{ &hf.ack_type,
			{ "Ack Type", "norm.ack.type", FT_UINT8, BASE_DEC, VALS(string_norm_ack_type), 0x0, "", HFILL}},
		{ &hf.ack_id,
			{ "Ack ID", "norm.ack.id", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL}},
		{ &hf.ack_grtt_sec,
			{ "Ack GRTT Sec", "norm.ack.grtt_sec", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},
		{ &hf.ack_grtt_usec,
			{ "Ack GRTT usec", "norm.ack.grtt_usec", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},

		{ &hf.nack_server,
			{ "NAck Server", "norm.nack.server", FT_IPv4, BASE_DEC, NULL, 0x0, "", HFILL}},
		{ &hf.nack_grtt_sec,
			{ "NAck GRTT Sec", "norm.nack.grtt_sec", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},
		{ &hf.nack_grtt_usec,
			{ "NAck GRTT usec", "norm.nack.grtt_usec", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},
		{ &hf.nack_form,
			{ "NAck FORM", "norm.nack.form", FT_UINT8, BASE_DEC, VALS(string_norm_nack_form), 0x0, "", HFILL}},
		{ &hf.nack_flags,
			{ "NAck Flags", "norm.nack.flags", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL}},
		{ &hf.nack_flags_segment,
			{ "Segment", "norm.nack.flags.segment", FT_BOOLEAN, 8, NULL, NORM_NACK_SEGMENT, "", HFILL}},
		{ &hf.nack_flags_block,
			{ "Block", "norm.nack.flags.block", FT_BOOLEAN, 8, NULL, NORM_NACK_BLOCK, "", HFILL}},
		{ &hf.nack_flags_info,
			{ "Info", "norm.nack.flags.info", FT_BOOLEAN, 8, NULL, NORM_NACK_INFO, "", HFILL}},
		{ &hf.nack_flags_object,
			{ "Object", "norm.nack.flags.object", FT_BOOLEAN, 8, NULL, NORM_NACK_OBJECT, "", HFILL}},
		{ &hf.nack_length,
			{ "NAck Length", "norm.nack.length", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL}},


		FEC_FIELD_ARRAY(hf.fec, "NORM"),

		{ &hf.payload,
			{ "Payload", "norm.payload", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }}
	};

	/* Setup protocol subtree array */
	static gint *ett_ptr[] = {
		&ett.main,
		&ett.hdrext,
		&ett.flags,
		&ett.streampayload,
		&ett.congestioncontrol,
		&ett.nackdata,
		FEC_SUBTREE_ARRAY(ett.fec)
	};

	module_t *module;

	/* Clear hf and ett fields */
	memset(&hf, 0xff, sizeof(struct _norm_hf));
	memset(&ett, 0xff, sizeof(struct _norm_ett));

	/* Register the protocol name and description */
	proto = proto_register_protocol("Negative-acknowledgment Oriented Reliable Multicast", "NORM", "norm");

	/* Register the header fields and subtrees used */
	proto_register_field_array(proto, hf_ptr, array_length(hf_ptr));
	proto_register_subtree_array(ett_ptr, array_length(ett_ptr));

	/* Reset preferences */
	norm_prefs_set_default(&preferences);
	norm_prefs_save(&preferences, &preferences_old);

	/* Register preferences */
	module = prefs_register_protocol(proto, proto_reg_handoff_norm);
	norm_prefs_register(&preferences, module);
	prefs_register_bool_preference(module, "heuristic_norm",
	                "Try to decode UDP packets as NORM packets",
	                "Check this to decode NORM traffic between clients",
	                &global_norm_heur);

}
