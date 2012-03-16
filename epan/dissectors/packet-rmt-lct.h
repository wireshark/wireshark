/* packet-rmt-lct.h
 * Reliable Multicast Transport (RMT)
 * LCT Building Block function definitions
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

#ifndef __PACKET_RMT_LCT__
#define __PACKET_RMT_LCT__

#include "packet-rmt-common.h"
#include "packet-rmt-fec.h"

/* Type definitions */
/* ================ */

/* Logical LCT header representation */
struct _lct
{
	guint8 version;
	guint8 cci_size;
	guint8 tsi_size;
	guint8 toi_size;
	gboolean tsi_present;
	gboolean toi_present;
	gboolean sct_present;
	gboolean ert_present;
	gboolean close_session;
	gboolean close_object;
	guint16 hlen;
	guint8 codepoint;
	guint64 tsi;
	guint64 toi;
	const guint8 *toi_extended;
	nstime_t sct;
	nstime_t ert;
	GArray *ext;
};

/* Wireshark stuff */
/* ============== */

/* LCT header field definitions */
struct _lct_hf
{
	int header;
	int version;
	int fsize_header;
	int fsize_cci;
	int fsize_tsi;
	int fsize_toi;
	int flags_header;
	int flags_sct_present;
	int flags_ert_present;
	int flags_close_session;
	int flags_close_object;
	int hlen;
	int codepoint;
	int cci;
	int tsi;
	int toi;
	int toi_extended;
	int sct;
	int ert;
	int ext;
};

/* LCT subtrees */
struct _lct_ett
{
	gint main;

	gint fsize;
	gint flags;
	gint ext;
	gint ext_ext;
};

/* LCT preferences */

#define LCT_PREFS_EXT_192_NONE 0
#define LCT_PREFS_EXT_192_FLUTE 1

#define LCT_PREFS_EXT_193_NONE 0
#define LCT_PREFS_EXT_193_FLUTE 1

struct _lct_prefs
{
	gboolean codepoint_as_fec_encoding;
	gint ext_192;
	gint ext_193;
};

/* LCT pointers */
struct _lct_ptr
{
	struct _lct *lct;
	struct _lct_hf *hf;
	struct _lct_ett *ett;
	struct _lct_prefs *prefs;
};

/* Macros to generate static arrays */

#define LCT_FIELD_ARRAY(base_structure, base_protocol)	\
		{ &base_structure.header,	\
			{ "Layered Coding Transport (LCT) header", base_protocol ".lct", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},	\
		{ &base_structure.version,	\
			{ "Version", base_protocol ".lct.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},	\
		{ &base_structure.fsize_header,	\
			{ "Field sizes (bytes)", base_protocol ".lct.fsize", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},	\
		{ &base_structure.fsize_cci,	\
			{ "Congestion Control Information field size", base_protocol ".lct.fsize.cci", FT_UINT8,	BASE_DEC, NULL, 0x0, NULL, HFILL }},	\
		{ &base_structure.fsize_tsi,	\
			{ "Transport Session Identifier field size", base_protocol ".lct.fsize.tsi", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},	\
		{ &base_structure.fsize_toi,	\
			{ "Transport Object Identifier field size", base_protocol ".lct.fsize.toi", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},	\
		{ &base_structure.flags_header,	\
			{ "Flags", base_protocol ".lct.flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},	\
		{ &base_structure.flags_sct_present,	\
			{ "Sender Current Time present flag", base_protocol ".lct.flags.sct_present", FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0, NULL, HFILL }},	\
		{ &base_structure.flags_ert_present,	\
			{ "Expected Residual Time present flag", base_protocol ".lct.flags.ert_present", FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0, NULL, HFILL }},	\
		{ &base_structure.flags_close_session,	\
			{ "Close Session flag", base_protocol ".lct.flags.close_session", FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0, NULL, HFILL }},	\
		{ &base_structure.flags_close_object,	\
			{ "Close Object flag", base_protocol ".lct.flags.close_object", FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0, NULL, HFILL }},	\
		{ &base_structure.hlen,	\
			{ "Header length", base_protocol ".lct.hlen", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},	\
		{ &base_structure.codepoint,	\
			{ "Codepoint", base_protocol ".lct.codepoint", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},	\
		{ &base_structure.cci,	\
			{ "Congestion Control Information", base_protocol ".lct.cci", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},	\
		{ &base_structure.tsi,	\
			{ "Transport Session Identifier", base_protocol ".lct.tsi", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},	\
		{ &base_structure.toi,	\
			{ "Transport Object Identifier (up to 64 bits)", base_protocol ".lct.toi", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},	\
		{ &base_structure.toi_extended,	\
			{ "Transport Object Identifier (up to 112 bits)", base_protocol ".lct.toi_extended", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},	\
		{ &base_structure.sct,	\
			{ "Sender Current Time", base_protocol ".lct.sct", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL }},	\
		{ &base_structure.ert,	\
			{ "Expected Residual Time", base_protocol ".lct.ert", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL }},	\
		{ &base_structure.ext,	\
			{ "Extension count", base_protocol ".lct.ext", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }}

#define LCT_SUBTREE_ARRAY(base_structure) \
	&base_structure.main,	\
	&base_structure.fsize,	\
	&base_structure.flags,	\
	&base_structure.ext,	\
	&base_structure.ext_ext

/* LCT exported functions */
/* ====================== */

void lct_info_column(struct _lct *lct, packet_info *pinfo);

gboolean lct_dissector(struct _lct_ptr l, struct _fec_ptr f, tvbuff_t *tvb, proto_tree *tree, guint *offset);
void lct_dissector_free(struct _lct *lct);

void lct_prefs_set_default(struct _lct_prefs *prefs);
void lct_prefs_register(struct _lct_prefs *prefs, module_t *module);
gboolean lct_ext_decode(struct _ext *e, struct _lct_prefs *prefs, tvbuff_t *tvb, proto_tree *tree, gint ett, struct _fec_ptr f);

#endif
