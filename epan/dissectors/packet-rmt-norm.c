/* packet-rmt-norm.c
 * Reliable Multicast Transport (RMT)
 * NORM Protocol Instantiation dissector
 * Copyright 2005, Stefano Pettini <spettini@users.sourceforge.net>
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
 *     RFC 3490, Negative-acknowledgment (NACK)-Oriented Reliable Multicast (NORM) Protocol
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

#include "packet-rmt-norm.h"

/* String tables */
const value_string string_norm_type[] =
{
	{ 1, "NORM_INFO" },
	{ 2, "NORM_DATA" },
	{ 3, "NORM_CMD" },
	{ 4, "NORM_NACK" },
	{ 5, "NORM_ACK" },
	{ 6, "NORM_REPORT" },
	{ 0, NULL }
};

/* Initialize the protocol and registered fields */
/* ============================================= */

static int proto = -1;

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
			proto_tree_add_uint(norm_tree, hf.source_id, tvb, offset+4, 4, norm.source_id);
		}
		
		offset += 8;
	
		/* Add the Payload item */
		if (tvb_length(tvb) > offset)
			proto_tree_add_none_format(norm_tree, hf.payload, tvb, offset, -1, "Payload (%u bytes)", tvb_length(tvb) - offset);
		
		/* Complete entry in Info column on summary display */
		/* ------------------------------------------------ */
		
		if (check_col(pinfo->cinfo, COL_INFO))
			switch (norm.type)
			{
			case 1:
				col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "INFO");
				break;
			
			case 2:
				col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "DATA");
				break;
			
			case 3:
				col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "CMD");
				break;
			
			case 4:
				col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "NACK");
				break;
			
			case 5:
				col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "ACK");
				break;
			
			case 6:
				col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "REPORT");
				break;
			
			default:
				col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "Unknown type");
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

void proto_reg_handoff_norm(void)
{
	static dissector_handle_t handle;

	if (!preferences_initialized)
	{
		preferences_initialized = TRUE;		
		handle = create_dissector_handle(dissect_norm, proto);
		dissector_add_handle("udp.port", handle);
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
			{ "Source ID", "norm.source_id", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
		
		FEC_FIELD_ARRAY(hf.fec, "alc"),

		{ &hf.payload,
			{ "Payload", "norm.payload", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }}
	};

	/* Setup protocol subtree array */
	static gint *ett_ptr[] = {
		&ett.main,
		
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
}
