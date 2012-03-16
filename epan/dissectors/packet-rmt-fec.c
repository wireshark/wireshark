/* packet-rmt-fec.c
 * Reliable Multicast Transport (RMT)
 * FEC Building Block dissector
 * Copyright 2005, Stefano Pettini <spettini@users.sourceforge.net>
 *
 * Forward Error Correction (ALC):
 * -------------------------------
 *
 * The goal of the FEC building block is to describe functionality
 * directly related to FEC codes that is common to all reliable content
 * delivery IP multicast protocols, and to leave out any additional
 * functionality that is specific to particular protocols.
 *
 * References:
 *     RFC 3452, Forward Error Correction Building Block
 *     RFC 3695, Compact Forward Error Correction (FEC) Schemes
 *     Simple XOR, Reed-Solomon, and Parity Check Matrix-based FEC Schemes draft-peltotalo-rmt-bb-fec-supp-xor-pcm-rs-00
 *     IANA RMT FEC parameters (http://www.iana.org/assignments/rmt-fec-parameters)
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

#include <stdlib.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-rmt-fec.h"

/* String tables */
const value_string string_fec_encoding_id[] =
{
	{ 0, "Compact No-Code" },
	{ 1, "Raptor" },
	{ 2, "Reed-Solomon Codes over GF(2^^m)" },
	{ 3, "LDPC Staircase Codes" },
	{ 4, "LDPC Triangle Codes" },
	{ 5, "Reed-Solomon Codes over GF(2^^8)" },
	{ 6, "RaptorQ Code" },
	/* 7-127 Unassigned  */
	{ 128, "Small Block, Large Block and Expandable FEC Codes" },
	{ 129, "Small Block Systematic FEC Codes" },
	{ 130, "Compact FEC Codes" },
	/* 131-255 Unassigned  */
	{ 0, NULL }
};

/* FEC exported functions */
/* ====================== */

/* Info */
/* ---- */

void fec_info_column(struct _fec *fec, packet_info *pinfo)
{
	if (fec->sbn_present)
		col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "SBN: %u", fec->sbn);

	if (fec->esi_present)
		col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "ESI: 0x%X", fec->esi);
}

/* Dissection */
/* ---------- */

/* Decode an EXT_FTI extension and fill FEC array */
void fec_decode_ext_fti(struct _ext *e, tvbuff_t *tvb, proto_tree *tree, gint ett, struct _fec_ptr f)
{
	proto_item* ti = NULL;
	proto_tree *ext_tree;

	if (tree)
		ti = proto_tree_add_none_format(tree, f.hf->fti_header, tvb, e->offset, e->length,
			"EXT_FTI, FEC Object Transmission Information (%u)", e->het);

	if (f.fec->encoding_id_present)
	{
		ext_tree = proto_item_add_subtree(ti, ett);
		rmt_ext_decode_default_header(e, tvb, ext_tree);

		/* Decode 48-bit length field */
		f.fec->transfer_length = tvb_get_ntoh64(tvb, e->offset) & G_GINT64_CONSTANT(0xFFFFFFFFFFFFU);

		if (f.fec->encoding_id >= 128)
		{
			/* Decode FEC Instance ID */
			f.fec->instance_id_present = TRUE;
			f.fec->instance_id = (guint8) tvb_get_ntohs(tvb, e->offset+8);
		}

		if (tree)
			proto_tree_add_uint64(ext_tree, f.hf->fti_transfer_length, tvb, e->offset+2, 6, f.fec->transfer_length);

		switch (f.fec->encoding_id)
		{
		case 0:
		case 2:
		case 128:
		case 130:
			f.fec->encoding_symbol_length = tvb_get_ntohs(tvb, e->offset+10);
			f.fec->max_source_block_length = tvb_get_ntohl(tvb, e->offset+12);

			if (tree)
			{
				proto_tree_add_uint(ext_tree, f.hf->fti_encoding_symbol_length, tvb, e->offset+10, 2, f.fec->encoding_symbol_length);
				proto_tree_add_uint(ext_tree, f.hf->fti_max_source_block_length, tvb, e->offset+12, 4, f.fec->max_source_block_length);
			}
			break;

		case 129:
			f.fec->encoding_symbol_length = tvb_get_ntohs(tvb, e->offset+10);
			f.fec->max_source_block_length = tvb_get_ntohs(tvb, e->offset+12);
			f.fec->max_number_encoding_symbols = tvb_get_ntohs(tvb, e->offset+14);

			if (tree)
			{
				proto_tree_add_uint(ext_tree, f.hf->fti_encoding_symbol_length, tvb, e->offset+10, 2, f.fec->encoding_symbol_length);
				proto_tree_add_uint(ext_tree, f.hf->fti_max_source_block_length, tvb, e->offset+12, 2, f.fec->max_source_block_length);
				proto_tree_add_uint(ext_tree, f.hf->fti_max_number_encoding_symbols, tvb, e->offset+14, 2, f.fec->max_number_encoding_symbols);
			}
			break;

		case 132:
			f.fec->encoding_symbol_length = tvb_get_ntohs(tvb, e->offset+10);
			f.fec->max_source_block_length = tvb_get_ntohl(tvb, e->offset+12);
			f.fec->max_number_encoding_symbols = tvb_get_ntohl(tvb, e->offset+16);

			if (tree)
			{
				proto_tree_add_uint(ext_tree, f.hf->fti_encoding_symbol_length, tvb, e->offset+10, 2, f.fec->encoding_symbol_length);
				proto_tree_add_uint(ext_tree, f.hf->fti_max_source_block_length, tvb, e->offset+12, 4, f.fec->max_source_block_length);
				proto_tree_add_uint(ext_tree, f.hf->fti_max_number_encoding_symbols, tvb, e->offset+16, 4, f.fec->max_number_encoding_symbols);
			}
			break;
		}

	} else
		if (tree)
			rmt_ext_decode_default_subtree(e, tvb, ti, ett);
}

/* Dissect a FEC header:
 * fec - ptr to the logical FEC packet representation to fill
 * hf - ptr to header fields array
 * ett - ptr to ett array
 * prefs - ptr to FEC prefs array
 * tvb - buffer
 * pinfo - packet info
 * tree - tree where to add FEC header subtree
 * offset - ptr to offset to use and update
 */
void fec_dissector(struct _fec_ptr f, tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
	proto_item *ti;
	proto_tree *fec_tree;
	guint offset_save = *offset;

	/* Create the FEC subtree */
	if (tree)
	{
		ti = proto_tree_add_item(tree, f.hf->header, tvb, *offset, -1, ENC_NA);
		fec_tree = proto_item_add_subtree(ti, f.ett->main);
	} else
	{
		ti = NULL;
		fec_tree = NULL;
	}

	/* FEC Encoding ID and FEC Instance ID processing */
	if (f.fec->encoding_id_present)
	{
		if (tree)
		{
			proto_tree_add_uint(fec_tree, f.hf->encoding_id, tvb, *offset, 0, f.fec->encoding_id);

			if (f.fec->encoding_id >= 128 && f.fec->instance_id_present)
				proto_tree_add_uint(fec_tree, f.hf->instance_id, tvb, *offset, 0, f.fec->instance_id);
		}

		switch (f.fec->encoding_id)
		{
		case 0:
		case 130:
			f.fec->sbn = tvb_get_ntohs(tvb, *offset);
			f.fec->esi = tvb_get_ntohs(tvb, *offset+2);

			if (tree)
			{
				proto_tree_add_uint(fec_tree, f.hf->sbn, tvb, *offset, 2, f.fec->sbn);
				proto_tree_add_uint(fec_tree, f.hf->esi, tvb, *offset+2, 2, f.fec->esi);
			}

			f.fec->sbn_present = TRUE;
			f.fec->esi_present = TRUE;
			*offset += 4;
			break;

		case 2:
		case 128:
		case 132:
			f.fec->sbn = tvb_get_ntohl(tvb, *offset);
			f.fec->esi = tvb_get_ntohl(tvb, *offset+4);

			if (tree)
			{
				proto_tree_add_uint(fec_tree, f.hf->sbn, tvb, *offset, 4, f.fec->sbn);
				proto_tree_add_uint(fec_tree, f.hf->esi, tvb, *offset+4, 4, f.fec->esi);
			}

			f.fec->sbn_present = TRUE;
			f.fec->esi_present = TRUE;
			*offset += 8;
			break;

		case 129:
			f.fec->sbn = tvb_get_ntohl(tvb, *offset);
			f.fec->sbl = tvb_get_ntohs(tvb, *offset+4);
			f.fec->esi = tvb_get_ntohs(tvb, *offset+6);

			if (tree)
			{
				proto_tree_add_uint(fec_tree, f.hf->sbn, tvb, *offset, 4, f.fec->sbn);
				proto_tree_add_uint(fec_tree, f.hf->sbl, tvb, *offset+4, 2, f.fec->sbl);
				proto_tree_add_uint(fec_tree, f.hf->esi, tvb, *offset+6, 2, f.fec->esi);
			}

			f.fec->sbn_present = TRUE;
			f.fec->sbl_present = TRUE;
			f.fec->esi_present = TRUE;
			*offset += 8;
			break;
		}
	}
	if (tree)
		proto_item_set_len(ti, *offset - offset_save);
}

void fec_dissector_free(struct _fec *fec _U_)
{

}

/* Preferences */
/* ----------- */

/* Set/Reset preferences to default values */
void fec_prefs_set_default(struct _fec_prefs *fec_prefs _U_)
{

}

/* Register preferences */
void fec_prefs_register(struct _fec_prefs *fec_prefs _U_, module_t *module _U_)
{

}
