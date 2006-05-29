/* packet-rmt-lct.c
 * Reliable Multicast Transport (RMT)
 * LCT Building Block dissector
 * Copyright 2005, Stefano Pettini <spettini@users.sourceforge.net>
 *
 * Layered Coding Transport (LCT):
 * -------------------------------
 *
 * Provides transport level support for reliable content delivery
 * and stream delivery protocols. LCT is specifically designed to
 * support protocols using IP multicast, but also provides support
 * to protocols that use unicast. LCT is compatible with congestion
 * control that provides multiple rate delivery to receivers and
 * is also compatible with coding techniques that provide
 * reliable delivery of content.
 *
 * References:
 *     RFC 3451, Layered Coding Transport (LCT) Building Block
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

#include <math.h>

#include "packet-rmt-lct.h"

/* Enumerated data types for LCT preferences */
static const enum_val_t enum_lct_ext_192[] =
{
	{ "none", "Don't decode", LCT_PREFS_EXT_192_NONE },
	{ "flute", "Decode as FLUTE extension (EXT_FDT)", LCT_PREFS_EXT_192_FLUTE },
	{ NULL, NULL, 0 }
};

static const enum_val_t enum_lct_ext_193[] =
{
	{ "none", "Don't decode", LCT_PREFS_EXT_193_NONE },
	{ "flute", "Decode as FLUTE extension (EXT_CENC)", LCT_PREFS_EXT_193_FLUTE },
	{ NULL, NULL, 0 }
};

/* LCT helper functions */
/* ==================== */

static void lct_timestamp_parse(guint32 t, nstime_t* s)
{
	s->secs = t / 1000;
	s->nsecs = (t % 1000) * 1000000;
}

void lct_ext_decode(struct _ext *e, struct _lct_prefs *prefs, tvbuff_t *tvb, proto_tree *tree, gint ett, struct _fec_ptr f)
{
	guint32 buffer32;
	proto_item *ti;
	proto_tree *ext_tree;

	switch (e->het)
	{

	/* EXT_NOP */
	case 0:
		if (tree)
		{
			ti = proto_tree_add_text(tree, tvb, e->offset, e->length,
				"EXT_NOP, No-Operation (0)");

			rmt_ext_decode_default_subtree(e, tvb, ti, ett);
		}
		break;

	/* EXT_AUTH */
	case 1:
		if (tree)
		{
			ti = proto_tree_add_text(tree, tvb, e->offset, e->length,
				"EXT_AUTH, Packet authentication (1)");

			rmt_ext_decode_default_subtree(e, tvb, ti, ett);
		}
		break;

    /* EXT_CC RATE */
    case 3:
        if (tree) {
			ti = proto_tree_add_text(tree, tvb, e->offset, e->length,
				"EXT_CC, Congestion Control Feedback (%u)", e->het);

			ext_tree = proto_item_add_subtree(ti, ett);
			rmt_ext_decode_default_header(e, tvb, ext_tree);
			proto_tree_add_text(ext_tree, tvb, e->offset+2, 2,
					"CC Sequence: %u", tvb_get_ntohs(tvb, e->offset+2));
			proto_tree_add_text(ext_tree, tvb, e->offset+4, 1,
					"CC Flags: 0x%x", tvb_get_guint8(tvb, e->offset+4));
			proto_tree_add_text(ext_tree, tvb, e->offset+5, 1,
					"CC RTT: %u", tvb_get_guint8(tvb, e->offset+5));
			proto_tree_add_text(ext_tree, tvb, e->offset+6, 2,
					"CC Loss: %g", tvb_get_ntohs(tvb, e->offset+6)/65535.0);
			proto_tree_add_text(ext_tree, tvb, e->offset+8, 2,
					"CC Rate: %u", tvb_get_ntohs(tvb, e->offset+8));

		}
		break;
	/* EXT_FTI */
	case 64:
		fec_decode_ext_fti(e, tvb, tree, ett, f);
		break;

	/* EXT_RATE */
    case 128:
        if (tree) {
			guint16 send_rate;
			double value;
			ti = proto_tree_add_text(tree, tvb, e->offset, e->length,
				"EXT_RATE, Send Rate (%u)", e->het);

			ext_tree = proto_item_add_subtree(ti, ett);
			rmt_ext_decode_default_header(e, tvb, ext_tree);
			send_rate = tvb_get_ntohs(tvb, e->offset+2);
			value = (send_rate >> 4) * 10.0 / 4096.0 * pow(10.0, (send_rate & 0xf));
			proto_tree_add_text(ext_tree, tvb, e->offset+2, 2,
					"Send Rate: %g", value);
		}
		break;

	/* EXT_FDT */
	case 192:
		switch (prefs->ext_192)
		{
		case LCT_PREFS_EXT_192_NONE:
			rmt_ext_decode_default(e, tvb, tree, ett);
			break;

		case LCT_PREFS_EXT_192_FLUTE:
			if (tree)
			{
				ti = proto_tree_add_text(tree, tvb, e->offset, e->length,
					"EXT_FDT, FDT Instance Header (192)");

				ext_tree = proto_item_add_subtree(ti, ett);
				buffer32 = tvb_get_ntohl(tvb, e->offset);

				rmt_ext_decode_default_header(e, tvb, ext_tree);

				proto_tree_add_text(ext_tree, tvb, e->offset+1, 1,
					"FLUTE version (V): %u", (buffer32 & 0x00F00000) >> 20);

				proto_tree_add_text(ext_tree, tvb, e->offset+1, 3,
					"FDT Instance ID: %u", buffer32 & 0x000FFFFF);
			}
			break;
		}
		break;

	/* EXT_CENC */
	case 193:
		switch (prefs->ext_193)
		{
		case LCT_PREFS_EXT_193_NONE:
			rmt_ext_decode_default(e, tvb, tree, ett);
			break;

		case LCT_PREFS_EXT_193_FLUTE:
			if (tree)
			{
				ti = proto_tree_add_text(tree, tvb, e->offset, e->length,
					"EXT_CENC, FDT Instance Content Encoding (193)");

				ext_tree = proto_item_add_subtree(ti, ett);
				buffer32 = tvb_get_ntohl(tvb, e->offset);

				rmt_ext_decode_default_header(e, tvb, ext_tree);

				proto_tree_add_text(ext_tree, tvb, e->offset+1, 1,
					"Content Encoding Algorithm (CENC): %u", (buffer32 & 0x00FF0000) >> 16);
			}
			break;
		}
		break;

	default:
		rmt_ext_decode_default(e, tvb, tree, ett);
	}
}

/* LCT exported functions */
/* ====================== */

/* Info */
/* ---- */

void lct_info_column(struct _lct *lct, packet_info *pinfo)
{
	if (lct->tsi_present)
		col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "TSI: %" PRIu64, lct->tsi);

	if (lct->toi_present)
	{
		if (lct->toi_size <= 8)
			col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "TOI: %" PRIu64, lct->toi);
		else
			col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "TOI: 0x%s", bytes_to_str(lct->toi_extended, lct->toi_size));
	}

	if (lct->close_session)
		col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "Close session");

	if (lct->close_object)
		col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "Close object");
}

/* Dissection */
/* ---------- */

/* Dissect an LCT header:
 * l - ptr to the logical LCT packet representation to fill, and related wireshark stuffs
 * f - ptr to the FEC infos to fill (EXT_FTI), and related wireshark stuffs
 * tvb - buffer
 * pinfo - packet info
 * tree - tree where to add LCT header subtree
 * offset - ptr to offset to use and update
 */
void lct_dissector(struct _lct_ptr l, struct _fec_ptr f, tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
	guint i;
	guint offset_old;
	guint offset_start;
	guint16 buffer16;

	/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *lct_tree;
	proto_tree *lct_fsize_tree;
	proto_tree *lct_flags_tree;
	proto_tree *lct_ext_tree;

	/* LCT fixed-size fields dissection */
	/* -------------------------------- */

	offset_start = *offset;

	buffer16 = tvb_get_ntohs(tvb, *offset);

	l.lct->version = ((buffer16 & 0xF000) >> 12);

	l.lct->cci_size = ((buffer16 & 0x0C00) >> 10) * 4 + 4;
	l.lct->tsi_size = ((buffer16 & 0x0080) >> 7) * 4 + ((buffer16 & 0x0010) >> 4) * 2;
	l.lct->toi_size = ((buffer16 & 0x0060) >> 5) * 4 + ((buffer16 & 0x0010) >> 4) * 2;

	l.lct->tsi_present = (l.lct->tsi_size > 0);
	l.lct->toi_present = (l.lct->toi_size > 0);
	l.lct->sct_present = (buffer16 & 0x0008) != 0;
	l.lct->ert_present = (buffer16 & 0x0004) != 0;
	l.lct->close_session = (buffer16 & 0x0002) != 0;
	l.lct->close_object = (buffer16 & 0x0001) != 0;

	l.lct->hlen = tvb_get_guint8(tvb, *offset+2) * 4;
	l.lct->codepoint = tvb_get_guint8(tvb, *offset+3);

	if (l.prefs->codepoint_as_fec_encoding)
	{
		f.fec->encoding_id_present = TRUE;
		f.fec->encoding_id = l.lct->codepoint;
	}

	if (tree)
	{
		/* Create the LCT subtree */
		ti = proto_tree_add_item(tree, l.hf->header, tvb, *offset, l.lct->hlen, FALSE);
		lct_tree = proto_item_add_subtree(ti, l.ett->main);

		/* Fill the LCT subtree */
		proto_tree_add_uint(lct_tree, l.hf->version, tvb, *offset, 1, l.lct->version);

		ti = proto_tree_add_item(lct_tree, l.hf->fsize_header, tvb, *offset, 2, FALSE);
		lct_fsize_tree = proto_item_add_subtree(ti, l.ett->fsize);

		ti = proto_tree_add_item(lct_tree, l.hf->flags_header, tvb, *offset, 2, FALSE);
		lct_flags_tree = proto_item_add_subtree(ti, l.ett->flags);

		proto_tree_add_uint(lct_tree, l.hf->hlen, tvb, *offset+2, 1, l.lct->hlen);
		proto_tree_add_uint(lct_tree, l.hf->codepoint, tvb, *offset+3, 1, l.lct->codepoint);

		/* Fill the LCT fsize subtree */
		proto_tree_add_uint(lct_fsize_tree, l.hf->fsize_cci, tvb, *offset, 1, l.lct->cci_size);
		proto_tree_add_uint(lct_fsize_tree, l.hf->fsize_tsi, tvb, *offset+1, 1, l.lct->tsi_size);
		proto_tree_add_uint(lct_fsize_tree, l.hf->fsize_toi, tvb, *offset+1, 1, l.lct->toi_size);

		/* Fill the LCT flags subtree */
		proto_tree_add_boolean(lct_flags_tree, l.hf->flags_sct_present, tvb, *offset+1, 1, l.lct->sct_present);
		proto_tree_add_boolean(lct_flags_tree, l.hf->flags_ert_present, tvb, *offset+1, 1, l.lct->ert_present);
		proto_tree_add_boolean(lct_flags_tree, l.hf->flags_close_session, tvb, *offset+1, 1, l.lct->close_session);
		proto_tree_add_boolean(lct_flags_tree, l.hf->flags_close_object, tvb, *offset+1, 1, l.lct->close_object);

	} else {
		lct_tree = NULL;
		lct_fsize_tree = NULL;
		lct_flags_tree = NULL;
	}

	*offset += 4;

	/* LCT variable-size and optional fields dissection */
	/* ------------------------------------------------ */

	/* Congestion Control Information (CCI) */
	if (l.lct->cci_size > 0) {
		l.lct->cci = (guint8*) tvb_get_ptr(tvb, *offset, l.lct->cci_size);
		if (tree)
			proto_tree_add_bytes(lct_tree, l.hf->cci, tvb, *offset, l.lct->cci_size, l.lct->cci);
		*offset += l.lct->cci_size;
	}

	/* Transmission Session Identifier (TSI) */
	if (l.lct->tsi_present) {

		switch (l.lct->tsi_size)
		{
			case 0:
				l.lct->tsi = 0;
				break;

			case 2:
				l.lct->tsi = tvb_get_ntohs(tvb, *offset);
				break;

			case 4:
				l.lct->tsi = tvb_get_ntohl(tvb, *offset);
				break;

			case 6:
				l.lct->tsi = tvb_get_ntoh64(tvb, *offset-2) & G_GINT64_CONSTANT(0x0000FFFFFFFFFFFFU);
				break;
		}

		if (tree)
			proto_tree_add_uint64(lct_tree, l.hf->tsi, tvb, *offset, l.lct->tsi_size, l.lct->tsi);
		*offset += l.lct->tsi_size;
	}

	/* Transmission Object Identifier (TOI) */
	if (l.lct->toi_present) {

		switch (l.lct->toi_size)
		{
			case 0:
				l.lct->toi = 0;
				break;

			case 2:
				l.lct->toi = tvb_get_ntohs(tvb, *offset);
				break;

			case 4:
				l.lct->toi = tvb_get_ntohl(tvb, *offset);
				break;

			case 6:
				l.lct->toi = tvb_get_ntoh64(tvb, *offset-2) & G_GINT64_CONSTANT(0x0000FFFFFFFFFFFFU);
				break;

			case 8:
				l.lct->toi = tvb_get_ntoh64(tvb, *offset);
				break;

			case 10:
				l.lct->toi = tvb_get_ntoh64(tvb, *offset+2);
				break;

			case 12:
				l.lct->toi = tvb_get_ntoh64(tvb, *offset+4);
				break;

			case 14:
				l.lct->toi = tvb_get_ntoh64(tvb, *offset)+6;
				break;
		}

		l.lct->toi_extended = (guint8*) tvb_get_ptr(tvb, *offset, l.lct->toi_size);

		if (tree)
		{
			if (l.lct->toi_size > 8)
				proto_tree_add_uint64(lct_tree, l.hf->toi, tvb, *offset+(l.lct->toi_size-8), 8, l.lct->toi);
			else
				proto_tree_add_uint64(lct_tree, l.hf->toi, tvb, *offset, l.lct->toi_size, l.lct->toi);

			proto_tree_add_bytes(lct_tree, l.hf->toi_extended, tvb, *offset, l.lct->toi_size, l.lct->toi_extended);
		}

		*offset += l.lct->toi_size;
	}

	/* Sender Current Time (SCT) */
	if (l.lct->sct_present) {
		lct_timestamp_parse(tvb_get_ntohl(tvb, *offset), &l.lct->sct);
		if (tree)
			proto_tree_add_time(lct_tree, l.hf->sct, tvb, *offset, 4, &l.lct->sct);
		*offset += 4;
	}

	/* Expected Residual Time (ERT) */
	if (l.lct->ert_present) {
		lct_timestamp_parse(tvb_get_ntohl(tvb, *offset), &l.lct->ert);
		if (tree)
			proto_tree_add_time(lct_tree, l.hf->ert, tvb, *offset, 4, &l.lct->ert);
		*offset += 4;
	}

	/* LCT header extensions, if applicable */
	/* ------------------------------------ */

	/* Allocate an array of _ext elements */
	l.lct->ext = g_array_new(FALSE, TRUE, sizeof(struct _ext));

	offset_old = *offset;
	rmt_ext_parse(l.lct->ext, tvb, offset, offset_start + l.lct->hlen);

	/* Resync the offset with the end of LCT header */
	*offset = offset_start + l.lct->hlen;

	if (l.lct->ext->len > 0)
	{
		if (tree)
		{
			/* Add the extensions subtree */
			ti = proto_tree_add_uint(lct_tree, l.hf->ext, tvb, offset_old, *offset - offset_old, l.lct->ext->len);
			lct_ext_tree = proto_item_add_subtree(ti, l.ett->ext);
		} else
			lct_ext_tree = NULL;

		/* Add the extensions to the subtree */
		for (i = 0; i < l.lct->ext->len; i++)
			lct_ext_decode(&g_array_index(l.lct->ext, struct _ext, i), l.prefs, tvb, lct_ext_tree, l.ett->ext_ext, f);
	}
}

void lct_dissector_free(struct _lct *lct)
{
	g_array_free(lct->ext, TRUE);
}

/* Preferences */
/* ----------- */

/* Set/Reset preferences to default values */
void lct_prefs_set_default(struct _lct_prefs *prefs)
{
	prefs->codepoint_as_fec_encoding = TRUE;
	prefs->ext_192 = LCT_PREFS_EXT_192_FLUTE;
	prefs->ext_193 = LCT_PREFS_EXT_193_FLUTE;
}

/* Register preferences */
void lct_prefs_register(struct _lct_prefs *prefs, module_t *module)
{
 	prefs_register_bool_preference(module,
		"lct.codepoint_as_fec_id",
		"LCT Codepoint as FEC Encoding ID",
		"Whether the LCT header Codepoint field should be considered the FEC Encoding ID of carried object",
		 &prefs->codepoint_as_fec_encoding);

	prefs_register_enum_preference(module,
		"lct.ext.192",
		"LCT header extention 192",
		"How to decode LCT header extention 192",
		&prefs->ext_192,
		enum_lct_ext_192,
		FALSE);

	prefs_register_enum_preference(module,
		"lct.ext.193",
		"LCT header extention 193",
		"How to decode LCT header extention 193",
		&prefs->ext_193,
		enum_lct_ext_193,
		FALSE);
}
