/* packet-rmt-fec.h
 * Reliable Multicast Transport (RMT)
 * FEC Building Block function definitions
 * Copyright 2005, Stefano Pettini <spettini@users.sourceforge.net>
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
 
#ifndef __PACKET_RMT_FEC__
#define __PACKET_RMT_FEC__

#include "packet-rmt-common.h"

/* String tables external references */
extern const value_string string_fec_encoding_id[];

/* Type definitions */
/* ================ */

struct _fec
{
	gboolean encoding_id_present;
	gboolean instance_id_present;
	guint8 encoding_id;
	guint8 instance_id;
	guint64 transfer_length;
	guint32 encoding_symbol_length;
	guint32 max_source_block_length;
	guint32 max_number_encoding_symbols;
	gboolean sbn_present;
	gboolean sbl_present;
	gboolean esi_present;
	guint32 sbn;
	guint32 sbl;
	guint32 esi;
};

/* Wireshark stuff */
/* ============== */

/* FEC header field definitions */
struct _fec_hf
{
	int header;
	int encoding_id;
	int instance_id;
	int sbn;
	int sbl;
	int esi;
	int fti_header;
	int fti_transfer_length;
	int fti_encoding_symbol_length;
	int fti_max_source_block_length;
	int fti_max_number_encoding_symbols;
};

/* FEC subtrees */
struct _fec_ett
{
	gint main;
};

/* FEC preferences */
struct _fec_prefs
{
	gboolean dummy;
};

/* FEC pointers */
struct _fec_ptr
{
	struct _fec *fec;
	struct _fec_hf *hf;
	struct _fec_ett *ett;
	struct _fec_prefs *prefs;
};

/* Macros to generate static arrays */

#define FEC_FIELD_ARRAY(base_structure, base_protocol)	\
	{ &base_structure.header,	\
		{ "Forward Error Correction (FEC) header", base_protocol ".fec", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},	\
	{ &base_structure.encoding_id,	\
		{ "FEC Encoding ID", base_protocol ".fec.encoding_id", FT_UINT8, BASE_DEC, VALS(string_fec_encoding_id), 0x0, "", HFILL }},	\
	{ &base_structure.instance_id,	\
		{ "FEC Instance ID", base_protocol ".fec.instance_id", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},	\
	{ &base_structure.sbn,	\
		{ "Source Block Number", base_protocol ".fec.sbn", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},	\
	{ &base_structure.sbl,	\
		{ "Source Block Length", base_protocol ".fec.sbl", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},	\
	{ &base_structure.esi,	\
		{ "Encoding Symbol ID", base_protocol ".fec.esi", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},	\
	{ &base_structure.fti_header,	\
		{ "FEC Object Transmission Information", base_protocol ".fec.fti", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},	\
	{ &base_structure.fti_transfer_length,	\
		{ "Transfer Length", base_protocol ".fec.fti.transfer_length", FT_UINT64, BASE_DEC, NULL, 0x0, "", HFILL }},	\
	{ &base_structure.fti_encoding_symbol_length,	\
		{ "Encoding Symbol Length", base_protocol ".fec.fti.encoding_symbol_length", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},	\
	{ &base_structure.fti_max_source_block_length,	\
		{ "Maximum Source Block Length", base_protocol ".fec.fti.max_source_block_length", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},	\
	{ &base_structure.fti_max_number_encoding_symbols,	\
		{ "Maximum Number of Encoding Symbols", base_protocol ".fec.fti.max_number_encoding_symbols", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }}

#define FEC_SUBTREE_ARRAY(base_structure) \
	&base_structure.main
	
/* FEC exported functions */
/* ====================== */

void fec_info_column(struct _fec *fec, packet_info *pinfo);

void fec_dissector(struct _fec_ptr f, tvbuff_t *tvb, proto_tree *tree, guint *offset);
void fec_dissector_free(struct _fec *fec);

void fec_decode_ext_fti(struct _ext *e, tvbuff_t *tvb, proto_tree *tree, gint ett, struct _fec_ptr f);

void fec_prefs_set_default(struct _fec_prefs *prefs);
void fec_prefs_register(struct _fec_prefs *prefs, module_t *module);

#endif
