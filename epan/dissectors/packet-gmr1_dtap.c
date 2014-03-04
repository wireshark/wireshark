/* packet-gmr1_dtap.c
 *
 * Routines for GMR-1 DTAP dissection in wireshark.
 * Copyright (c) 2011 Sylvain Munaut <tnt@246tNt.com>
 *
 * References:
 *  [1] ETSI TS 101 376-4-8 V1.3.1 - GMR-1 04.008
 *  [2] ETSI TS 101 376-4-8 V2.2.1 - GMPRS-1 04.008
 *  [3] ETSI TS 101 376-4-8 V3.1.1 - GMR-1 3G 44.008
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>

#include "packet-gmr1_common.h"

void proto_register_gmr1_dtap(void);
void proto_reg_handoff_gmr1_dtap(void);

/* GMR-1 DTAP proto */
static int proto_gmr1_dtap = -1;

/* GMR-1 DTAP sub tree */
static gint ett_gmr1_dtap = -1;
static gint ett_gmr1_pd = -1;

/* Handoffs */
static dissector_handle_t gsm_dtap_handle;


static void
dissect_gmr1_dtap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 len, offset;
	gmr1_msg_func_t msg_func;
	const gchar *msg_str;
	gint ett_tree;
	int hf_idx;
	proto_item *dtap_item = NULL/*, *pd_item = NULL*/;
	proto_tree *dtap_tree = NULL/*, *pd_tree = NULL*/;
	guint32 oct[2];
	guint8 pd;

	/* Scan init */
	len = tvb_length(tvb);
	offset = 0;

	/* Protocol descriptor */
	oct[0] = tvb_get_guint8(tvb, offset++);

	if ((oct[0] & GMR1_PD_EXT_MSK) == GMR1_PD_EXT_VAL)
		pd = oct[0] & 0xff;
	else
		pd = oct[0] & 0x0f;

	/* HACK: Quick delegation hack to GSM */
	if (pd != GMR1_PD_RR) {
		call_dissector(gsm_dtap_handle, tvb, pinfo, tree);
		return;
	}

	/* Fill up some info */
	col_append_str(pinfo->cinfo, COL_INFO, " (DTAP) ");

	col_append_fstr(pinfo->cinfo, COL_INFO, "(%s) ",
		val_to_str(pd, gmr1_pd_short_vals, "Unknown (%u)"));

	/* Get message parameters */
	oct[1] = tvb_get_guint8(tvb, offset);

	gmr1_get_msg_params((gmr1_pd_e)pd, oct[1], &msg_str, &ett_tree, &hf_idx, &msg_func);

	/* Create protocol tree */
	if (msg_str == NULL)
	{
		dtap_item = proto_tree_add_protocol_format(
			tree, proto_gmr1_dtap, tvb, 0, len,
			"GMR-1 DTAP - Message Type (0x%02x)", oct[1]);
		dtap_tree = proto_item_add_subtree(dtap_item, ett_gmr1_dtap);

		col_append_fstr(pinfo->cinfo, COL_INFO, "Message Type (0x%02x) ", oct[1]);
	}
	else
	{
		dtap_item = proto_tree_add_protocol_format(
			tree, proto_gmr1_dtap, tvb, 0, -1,
			"GMR-1 DTAP - %s", msg_str);
		dtap_tree = proto_item_add_subtree(dtap_item, ett_gmr1_dtap);

		col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", msg_str);
	}

	/* Start over */
	offset = 0;

	/* Protocol discriminator item */
	/*pd_item =*/ proto_tree_add_text(
		dtap_tree, tvb, 1, 1,
		"Protocol Discriminator: %s",
		val_to_str(pd, gmr1_pd_vals, "Unknown (%u)")
	);

	/*pd_tree = proto_item_add_subtree(pd_item, ett_gmr1_pd);*/

		/* Move on */
	offset++;

	/* Message type - [1] 11.4 */
	proto_tree_add_uint_format(
		dtap_tree, hf_idx, tvb, offset, 1, oct[1],
		"Message Type: %s", msg_str ? msg_str : "(Unknown)"
	);

	offset++;

	/* Decode elements */
	if (msg_func) {
		(*msg_func)(tvb, dtap_tree, pinfo, offset, len - offset);
	} else {
		proto_tree_add_text(dtap_tree, tvb, offset, len - offset,
		                    "Message Elements");
	}

	/* Done ! */
	return;
}


void
proto_register_gmr1_dtap(void)
{
#if 0
	static hf_register_info hf[] = {
	};
#endif
	static gint *ett[] = {
		&ett_gmr1_dtap,
		&ett_gmr1_pd,
	};

	/* Setup protocol subtree array */
	proto_register_subtree_array(ett, array_length(ett));

	/* Register the protocol name and field description */
	proto_gmr1_dtap = proto_register_protocol("GEO-Mobile Radio (1) DTAP", "GMR-1 DTAP", "gmr1.dtap");
#if 0
	proto_register_field_array(proto_gmr1_dtap, hf, array_length(hf));
#endif
	/* Register dissector */
	register_dissector("gmr1_dtap", dissect_gmr1_dtap, proto_gmr1_dtap);
}

void
proto_reg_handoff_gmr1_dtap(void)
{
	dissector_handle_t dtap_handle;

	dtap_handle = find_dissector("gmr1_dtap");
	dissector_add_uint("lapsat.sapi", 0 , dtap_handle); /* LAPSat: CC/RR/MM */
	dissector_add_uint("lapsat.sapi", 3 , dtap_handle); /* LAPSat: SMS/SS */

	gsm_dtap_handle = find_dissector("gsm_a_dtap");
}
