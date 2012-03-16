/* packet-mpeg-sect.c
 * Routines for MPEG2 (ISO/ISO 13818-1) Section dissection
 * Copyright 2012, Guy Martin <gmsoft@tuxicoman.be>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from WHATEVER_FILE_YOU_USED (where "WHATEVER_FILE_YOU_USED"
 * is a dissector file; if you just copied this from README.developer,
 * don't bother with the "Copied from" - you don't even need to put
 * in a "Copied from" if you copied an existing dissector, especially
 * if the bulk of the code in the new dissector is your code)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/crc32-tvb.h>
#include <epan/expert.h>
#include <epan/dissectors/packet-mpeg-sect.h>

static int proto_mpeg_sect = -1;
static int hf_mpeg_sect_table_id = -1;
static int hf_mpeg_sect_syntax_indicator = -1;
static int hf_mpeg_sect_reserved = -1;
static int hf_mpeg_sect_length = -1;
static int hf_mpeg_sect_crc = -1;

static gint ett_mpeg_sect = -1;

static dissector_table_t mpeg_sect_tid_dissector_table;

static gboolean mpeg_sect_check_crc = FALSE;

#define MPEG_SECT_SYNTAX_INDICATOR_MASK	0x8000
#define MPEG_SECT_RESERVED_MASK		0x7000
#define MPEG_SECT_LENGTH_MASK		0x0FFF

/* From ISO/IEC 13818-1 */
enum {
	TID_PAT,
	TID_CA,
	TID_PMT,
	TID_TS_DESC,
	TID_SCENE_DESC,
	TID_OBJECT_DESC,
	TID_FORBIDEN = 0xFF
};

/* From ETSI EN 300 468 */
enum {
	TID_NIT = 0x40,
	TID_NIT_OTHER,
	TID_SDT,
	TID_SDT_OTHER = 0x46,
	TID_BAT = 0x4A,
	TID_EIT = 0x4E,
	TID_EIT_OTHER,
	TID_TDT = 0x70,
	TID_RST,
	TID_ST,
	TID_TOT
};

/* From ETSI EN 301 790 */
enum {

	TID_RMT = 0x41, /* Conflict with TID_NIT_OTHER */
	TID_SCT = 0xA0,
	TID_FCT,
	TID_TCT,
	TID_SPT,
	TID_CMT,
	TID_TBTP,
	TID_PCR,
	TID_TIM = 0xB0
};

/* From ESTI EN 301 192 */
enum {
	TID_DVB_MPE = 0x3E
};

/* From OC-SP-ETV-AM 1.0-IO5 */
enum {
	TID_ETV_EISS = 0xE0
};

static const value_string mpeg_sect_table_id_vals[] = {

	{ TID_PAT, "Program Association Table (PAT)" },
	{ TID_CA, "Conditional Access (CA)" },
	{ TID_PMT, "Program Map Table (PMT)" },
	{ TID_TS_DESC, "Transport Stream Description" },
	{ TID_SCENE_DESC, "ISO/IEC 14496 Scene Description" },
	{ TID_OBJECT_DESC, "ISO/IEC 14496 Object Description" },
	{ TID_NIT, "Network Information Table (NIT), current network" },
	{ TID_NIT_OTHER, "Network Information Table (NIT), other network" },
	{ TID_SDT, "Service Description Table (SDT), current network" },
	{ TID_SDT_OTHER, "Service Description (SDT), other network" },
	{ TID_BAT, "Bouquet Associatoin Table (BAT)" },
	{ TID_EIT, "Event Information Table (EIT), actual TS" },
	{ TID_EIT_OTHER, "Event Information Table (EIT), other TS" },
	{ TID_TDT, "Time and Date Table (TDT)" },
	{ TID_RST, "Running Status Table (RST)" },
	{ TID_ST, "Stuffing Table (ST)" },
	{ TID_TOT, "Time Offset Table (TOT)" },
	{ TID_SCT, "Superframe Composition Table (SCT)" },
	{ TID_FCT, "Frame Composition Table (FCT)" },
	{ TID_TCT, "Time-Slot Composition Table (TCT)" },
	{ TID_SPT, "Satellite Position Table (SPT)" },
	{ TID_CMT, "Correction Message Table (CMT)" },
	{ TID_TBTP, "Terminal Burst Time Plan (TBTP)" },
	{ TID_TIM, "Terminal Information Message (TIM)" },
	{ TID_DVB_MPE, "DVB MultiProtocol Encapsulation (MPE)" },
	{ TID_ETV_EISS, "ETV Integrated Signaling Stream (EISS)" },
	{ TID_FORBIDEN, "Forbidden" },
	{ 0, NULL }
};

guint
packet_mpeg_sect_header(tvbuff_t *tvb, guint offset,
			proto_tree *tree, guint *sect_len, gboolean *ssi)
{
	return packet_mpeg_sect_header_extra(tvb, offset, tree, sect_len,
					     NULL, ssi, NULL);
}

guint
packet_mpeg_sect_header_extra(tvbuff_t *tvb, guint offset, proto_tree *tree,
				guint *sect_len, guint *reserved, gboolean *ssi,
				proto_item **items)
{
	guint tmp;
	guint len = 0;
	proto_item *pi[PACKET_MPEG_SECT_PI__SIZE];
	gint i;

	for (i = 0; i < PACKET_MPEG_SECT_PI__SIZE; i++) {
		pi[i] = NULL;
	}

	if (tree) {
		pi[PACKET_MPEG_SECT_PI__TABLE_ID] =
			proto_tree_add_item(tree, hf_mpeg_sect_table_id,
					tvb, offset + len, 1, ENC_BIG_ENDIAN);
	}

	len++;

	if (tree) {
		pi[PACKET_MPEG_SECT_PI__SSI] =
			proto_tree_add_item(tree, hf_mpeg_sect_syntax_indicator,
					tvb, offset + len, 2, ENC_BIG_ENDIAN);

		pi[PACKET_MPEG_SECT_PI__RESERVED] =
			proto_tree_add_item(tree, hf_mpeg_sect_reserved, tvb,
					offset + len, 2, ENC_BIG_ENDIAN);

		pi[PACKET_MPEG_SECT_PI__LENGTH] =
			proto_tree_add_item(tree, hf_mpeg_sect_length, tvb,
					offset + len, 2, ENC_BIG_ENDIAN);
	}

	tmp = tvb_get_ntohs(tvb, offset + len);

	if (sect_len)
		*sect_len = MPEG_SECT_LENGTH_MASK & tmp;

	if (reserved)
		*reserved = (MPEG_SECT_RESERVED_MASK & tmp) >> 12;

	if (ssi)
		*ssi = (MPEG_SECT_SYNTAX_INDICATOR_MASK & tmp);

	if (items) {
		for (i = 0; i < PACKET_MPEG_SECT_PI__SIZE; i++) {
			items[i] = pi[i];
		}
	}

	len += 2;

	return len;
}


void
packet_mpeg_sect_crc(tvbuff_t *tvb, packet_info *pinfo,
		     proto_tree *tree, guint start, guint end)
{
	guint32 crc, calculated_crc;
	const char *label;

	crc = tvb_get_ntohl(tvb, end);

	calculated_crc = crc;
	label = "Unverified";
	if (mpeg_sect_check_crc) {
		label = "Verified";
		calculated_crc = crc32_mpeg2_tvb_offset(tvb, start, end);
	}

	if (calculated_crc == crc) {
		proto_tree_add_uint_format( tree, hf_mpeg_sect_crc, tvb,
			end, 4, crc, "CRC: 0x%08x [%s]", crc, label);
	} else {
		proto_item *msg_error = NULL;

		msg_error = proto_tree_add_uint_format( tree, hf_mpeg_sect_crc, tvb,
							end, 4, crc,
							"CRC: 0x%08x [Failed Verification (Calculated: 0x%08x)]",
							crc, calculated_crc );
		PROTO_ITEM_SET_GENERATED(msg_error);
		expert_add_info_format( pinfo, msg_error, PI_MALFORMED,
					PI_ERROR, "Invalid CRC" );
	}
}


static void
dissect_mpeg_sect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint offset = 0;
	guint8 table_id = 0;
	guint section_length = 0;
	gboolean syntax_indicator = 0;

	proto_item *ti = NULL;
	proto_tree *mpeg_sect_tree = NULL;

	table_id = tvb_get_guint8(tvb, offset);

	/* Check if a dissector can parse the current table */
	if (dissector_try_uint(mpeg_sect_tid_dissector_table, table_id, tvb, pinfo, tree))
		return;

	/* If no dissector is registered, use the common one */
	if (tree) {

		col_set_str(pinfo->cinfo, COL_PROTOCOL, "MPEG SECT");
		col_add_fstr(pinfo->cinfo, COL_INFO, "Table ID 0x%02x", table_id);

		ti = proto_tree_add_item(tree, proto_mpeg_sect, tvb, offset, -1, ENC_NA);
		mpeg_sect_tree = proto_item_add_subtree(ti, ett_mpeg_sect);

		proto_item_append_text(ti, " Table_ID=0x%02x", table_id);

		packet_mpeg_sect_header(tvb, offset, mpeg_sect_tree,
								&section_length, &syntax_indicator);

	}

	if (syntax_indicator)
		packet_mpeg_sect_crc(tvb, pinfo, mpeg_sect_tree, 0, (section_length-1));
}


void
proto_register_mpeg_sect(void)
{
	static hf_register_info hf[] = {
		{ &hf_mpeg_sect_table_id, {
			"Table ID", "mpeg_sect.tid",
			FT_UINT8, BASE_HEX, VALS(mpeg_sect_table_id_vals), 0, NULL, HFILL
		} },

		{ &hf_mpeg_sect_syntax_indicator, {
			"Syntax indicator", "mpeg_sect.syntax_indicator",
			FT_UINT16, BASE_DEC, NULL, MPEG_SECT_SYNTAX_INDICATOR_MASK, NULL, HFILL
		} },

		{ &hf_mpeg_sect_reserved, {
			"Reserved", "mpeg_sect.reserved",
			FT_UINT16, BASE_HEX, NULL, MPEG_SECT_RESERVED_MASK, NULL, HFILL
		} },

		{ &hf_mpeg_sect_length, {
			"Length", "mpeg_sect.len",
			FT_UINT16, BASE_DEC, NULL, MPEG_SECT_LENGTH_MASK, NULL, HFILL
		} },

		{ &hf_mpeg_sect_crc, {
			"CRC 32", "mpeg_sect.crc",
			FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
		} }
	};

	static gint *ett[] = {
		&ett_mpeg_sect
	};
	module_t *mpeg_sect_module;

	proto_mpeg_sect = proto_register_protocol("MPEG2 Section", "MPEG SECT", "mpeg_sect");
	register_dissector("mpeg_sect", dissect_mpeg_sect, proto_mpeg_sect);

	proto_register_field_array(proto_mpeg_sect, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	mpeg_sect_module = prefs_register_protocol(proto_mpeg_sect, NULL);

	prefs_register_bool_preference(mpeg_sect_module, "verify_crc",
		"Verify the section CRC",
		"Whether the section dissector should verify the CRC",
		&mpeg_sect_check_crc);

	mpeg_sect_tid_dissector_table = register_dissector_table("mpeg_sect.tid", "MPEG SECT Table ID", FT_UINT8, BASE_HEX);

}
