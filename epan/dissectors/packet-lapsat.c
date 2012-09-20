/* packet-lapsat.c
 *
 * Routines for GMR-1 LAPSat dissection in wireshark.
 *
 * Link Access Procedures (LAP) for the Satellite Channel (LAPSat).
 * LAPSat is the protocol for signalling transfer between an Access
 * Terminal (MES) and a Gateway Station (GS) in the GeoMobile (GMR-1) network.
 *
 * Copyright (c) 2011 Sylvain Munaut <tnt@246tNt.com>
 * Inspired on LAPDm code by Duncan Salerno <duncan.salerno@googlemail.com>
 *
 * References:
 *  [1] ETSI TS 101 376-4-6 V1.2.1 - GMR-1 04.006
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/reassemble.h>


static int proto_lapsat = -1;

static GHashTable *lapsat_fragment_table = NULL;
static GHashTable *lapsat_reassembled_table = NULL;

static dissector_table_t lapsat_sapi_dissector_table;

static dissector_handle_t data_handle;

static gint ett_lapsat = -1;
static gint ett_lapsat_address = -1;
static gint ett_lapsat_control = -1;
static gint ett_lapsat_fragment = -1;
static gint ett_lapsat_fragments = -1;

static int hf_lapsat_addr = -1;
static int hf_lapsat_addr_sst = -1;
static int hf_lapsat_addr_cr = -1;
static int hf_lapsat_addr_sapi = -1;
static int hf_lapsat_addr_si = -1;
static int hf_lapsat_addr_lpd = -1;
static int hf_lapsat_addr_lfi = -1;

static int hf_lapsat_ctl = -1;
static int hf_lapsat_ctl_ftype_i = -1;
static int hf_lapsat_ctl_ftype_s_u = -1;
static int hf_lapsat_ctl_s_ftype = -1;
static int hf_lapsat_ctl_u_modifier_cmd = -1;
static int hf_lapsat_ctl_u_modifier_resp = -1;
static int hf_lapsat_ctl_n_r = -1;
static int hf_lapsat_ctl_n_s = -1;
static int hf_lapsat_ctl_p = -1;
static int hf_lapsat_ctl_f = -1;
static int hf_lapsat_ctl_mii = -1;

static int hf_lapsat_payload_last_nibble = -1;

static int hf_lapsat_len = -1;

static int hf_lapsat_fragments = -1;
static int hf_lapsat_fragment = -1;
static int hf_lapsat_fragment_overlap = -1;
static int hf_lapsat_fragment_overlap_conflicts = -1;
static int hf_lapsat_fragment_multiple_tails = -1;
static int hf_lapsat_fragment_too_long_fragment = -1;
static int hf_lapsat_fragment_error = -1;
static int hf_lapsat_fragment_count = -1;
static int hf_lapsat_reassembled_in = -1;
static int hf_lapsat_reassembled_length = -1;


#define LAPSAT_HEADER_LEN		3

#define LAPSAT_SAPI_RR_CC_MM		0
#define LAPSAT_SAPI_SMS			3


/*
 * Address field bits
 */

#define LAPSAT_SST			0x01	/* SACCH status bit */
#define LAPSAT_CR			0x02	/* Command/Response bit */
#define LAPSAT_SAPI_MSK			0x0c	/* Service Access Point Identifier */
#define LAPSAT_SAPI_SHIFT		2
#define LAPSAT_SI			0x10	/* Segment Indicator */
#define LAPSAT_LPD_MSK			0x60	/* DL for LAPSat or SMS-CB */
#define LAPSAT_LPD_SHIFT		6
#define LAPSAT_LFI			0x80	/* Length Field Indicator */

static const value_string lapsat_addr_sst_vals[] = {
	{ 0, "FACCH and all other messages" },
	{ 1, "SACCH message" },
	{ 0 , NULL }
};

static const value_string lapsat_addr_sapi_vals[] = {
	{ LAPSAT_SAPI_RR_CC_MM, "RR/MM/CC" },
	{ LAPSAT_SAPI_SMS, "SMS/SS" },
	{ 0, NULL }
};

static const value_string lapsat_addr_lpd_vals[] = {
	{ 0, "Normal GMR-1" },
	{ 1, "Cell broadcast service" },
	{ 0, NULL }
};

static const value_string lapsat_addr_si_vals[] = {
	{ 0, "Complete/Last Segment of L3 message" },
	{ 1, "Segment only" },
	{ 0, NULL }
};

static const value_string lapsat_addr_lfi_vals[] = {
	{ 0, "Length Field not present (all data valid)" },
	{ 1, "Length Field present" },
	{ 0, NULL }
};


/*
 * Frame types
 */

#define LAPSAT_CTL_TYPE_S		0x001
#define	LAPSAT_CTL_TYPE_U		0x003
#define LAPSAT_CTL_TYPE_S_U_MSK		0x003

#define	LAPSAT_CTL_TYPE_I		0x000
#define	LAPSAT_CTL_TYPE_I_MSK		0x001

static const value_string lapsat_ctl_ftype_vals[] = {
	{ LAPSAT_CTL_TYPE_I, "Information frame" },
	{ LAPSAT_CTL_TYPE_S, "Supervisory frame" },
	{ LAPSAT_CTL_TYPE_U, "Unnumbered frame" },
	{ 0, NULL }
};


/*
 * S-format frame types
 */

#define LAPSAT_CTL_S_FTYPE_MSK		0x00c

#define LAPSAT_RR			0x000
#define LAPSAT_GREJ			0x008

static const value_string lapsat_ctl_s_ftype_vals[] = {
	{ LAPSAT_RR >> 2,   "Receiver ready" },
	{ LAPSAT_GREJ >> 2, "Group reject" },
	{ 0, NULL}
};


/*
 * U-format modifiers
 */

#define LAPSAT_CTL_U_MODIFIER_MSK	0x18c

#define LAPSAT_SABM			0x08c
#define LAPSAT_DM			0x00c
#define LAPSAT_DISC			0x100
#define LAPSAT_UA			0x180
#define LAPSAT_UI			0x000

static const value_string lapsat_ctl_u_modifier_vals_cmd[] = {
	{ LAPSAT_SABM >> 2, "Set Asynchronous Balanced Mode" },
	{ LAPSAT_DISC >> 2, "Disconnect" },
	{ LAPSAT_UI >> 2,   "Unnumbered Information" },
	{ 0, NULL}
};

static const value_string lapsat_ctl_u_modifier_vals_resp[] = {
	{ LAPSAT_DM >> 2,   "Disconnected mode" },
	{ LAPSAT_UA >> 2,   "Unnumbered Acknowledge" },
	{ 0, NULL}
};


/*
 * Control fields
 */

#define LAPSAT_CTL_P_F			0x040
#define LAPSAT_CTL_MII			0x200
#define LAPSAT_CTL_N_R_MSK		0xf80
#define LAPSAT_CTL_N_R_SHIFT		7
#define LAPSAT_CTL_N_S_MSK		0x03e
#define LAPSAT_CTL_N_S_SHIFT		1


/*
 * Fragment stuff
 */

static const value_string true_false_vals[] = {
	{ 0, "False" },
	{ 1, "True" },
	{ 0, NULL },
};


static const fragment_items lapsat_frag_items = {
	/* Fragment subtrees */
	&ett_lapsat_fragment,
	&ett_lapsat_fragments,
	/* Fragment fields */
	&hf_lapsat_fragments,
	&hf_lapsat_fragment,
	&hf_lapsat_fragment_overlap,
	&hf_lapsat_fragment_overlap_conflicts,
	&hf_lapsat_fragment_multiple_tails,
	&hf_lapsat_fragment_too_long_fragment,
	&hf_lapsat_fragment_error,
	&hf_lapsat_fragment_count,
	/* Reassembled in field */
	&hf_lapsat_reassembled_in,
	/* Reassembled length field */
	&hf_lapsat_reassembled_length,
	/* Reassembled data field */
	NULL,
	/* Tag */
	"fragments"
};

static void
lapsat_defragment_init(void)
{
	fragment_table_init(&lapsat_fragment_table);
	reassembled_table_init(&lapsat_reassembled_table);
}


/*
 * Main dissection functions
 */

static guint16
dissect_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int is_response)
{
	proto_tree *ctl_tree;
	proto_item *ctl_ti;
	guint16 ctl, poll_final;
	const char *frame_type;
	char *info;

	info = ep_alloc(80);

	/* Grab complete control field */
	ctl = tvb_get_ntohs(tvb, 1) >> 4;

	poll_final = ctl & LAPSAT_CTL_P_F;

	/* Generate small 'descriptive' text */
	switch (ctl & LAPSAT_CTL_TYPE_S_U_MSK) {
	case LAPSAT_CTL_TYPE_S:
		/*
		 * Supervisory frame.
		 */
		switch (ctl & LAPSAT_CTL_S_FTYPE_MSK) {
		case LAPSAT_RR:
			frame_type = "RR";
			break;
		case LAPSAT_GREJ:
			frame_type = "GREJ";
			break;
		default:
			frame_type = "Unknown";
			break;
		}

		g_snprintf(info, 80, "S%s, func=%s, N(R)=%u",
			poll_final ? (is_response ? " F" : " P") : "",
			frame_type,
			(ctl & LAPSAT_CTL_N_R_MSK) >> LAPSAT_CTL_N_R_SHIFT);

		break;

	case LAPSAT_CTL_TYPE_U:
		/*
		 * Unnumbered frame
		 */
		switch (ctl & LAPSAT_CTL_U_MODIFIER_MSK) {
		case LAPSAT_SABM:
			frame_type = (ctl & LAPSAT_CTL_MII) ?
				"SABM, MII=1" : "SABM, MII=0";
			break;
		case LAPSAT_DM:
			frame_type = "DM";
			break;
		case LAPSAT_DISC:
			frame_type = "DISC";
			break;
		case LAPSAT_UA:
			frame_type = "UA";
			break;
		case LAPSAT_UI:
			frame_type = "UI";
			break;
		default:
			frame_type = "Unknown";
			break;
		}

		g_snprintf(info, 80, "U%s, func=%s",
			poll_final ? (is_response ? " F" : " P") : "",
			frame_type);

		break;

	default:
		/*
		 * Information frame
		 */
		g_snprintf(info, 80, "I%s, N(R)=%u, N(S)=%u",
			poll_final ? " P" : "",
			(ctl & LAPSAT_CTL_N_R_MSK) >> LAPSAT_CTL_N_R_SHIFT,
			(ctl & LAPSAT_CTL_N_S_MSK) >> LAPSAT_CTL_N_S_SHIFT);

		break;
	}

	/* Add info */
	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_str(pinfo->cinfo, COL_INFO, info);

	/* Create item & subtree */
	ctl_ti = proto_tree_add_uint_format_value(
			tree, hf_lapsat_ctl,
			tvb, 1, 2, (guint32)ctl,
			"%s (0x%03x)", info, ctl
	);

	ctl_tree = proto_item_add_subtree(ctl_ti, ett_lapsat_control);

	/* Add all fields */
	switch (ctl & LAPSAT_CTL_TYPE_S_U_MSK) {
	case LAPSAT_CTL_TYPE_S:
		/*
		 * Supervisory frame.
		 */

		proto_tree_add_item(ctl_tree, hf_lapsat_ctl_ftype_s_u,
		                    tvb, 1, 2, ENC_BIG_ENDIAN);

		proto_tree_add_item(ctl_tree, hf_lapsat_ctl_s_ftype,
		                    tvb, 1, 2, ENC_BIG_ENDIAN);

		proto_tree_add_item(ctl_tree, hf_lapsat_ctl_n_r,
		                    tvb, 1, 2, ENC_BIG_ENDIAN);

		if (poll_final)
			proto_tree_add_item(ctl_tree,
				is_response ? hf_lapsat_ctl_f : hf_lapsat_ctl_p,
				tvb, 1, 2, ENC_BIG_ENDIAN);

		break;

	case LAPSAT_CTL_TYPE_U:
		/*
		 * Unnumbered frame
		 */

		proto_tree_add_item(ctl_tree, hf_lapsat_ctl_ftype_s_u,
		                    tvb, 1, 2, ENC_BIG_ENDIAN);

		proto_tree_add_item(ctl_tree,
			is_response ?	hf_lapsat_ctl_u_modifier_resp :
					hf_lapsat_ctl_u_modifier_cmd,
			tvb, 1, 2, ENC_BIG_ENDIAN);

		if (poll_final)
			proto_tree_add_item(ctl_tree,
				is_response ? hf_lapsat_ctl_f : hf_lapsat_ctl_p,
				tvb, 1, 2, ENC_BIG_ENDIAN);

		if (((ctl & LAPSAT_CTL_U_MODIFIER_MSK) == LAPSAT_SABM) &&
		     (ctl & LAPSAT_CTL_MII))
			proto_tree_add_item(ctl_tree, hf_lapsat_ctl_mii,
			                    tvb, 1, 2, ENC_BIG_ENDIAN);

		break;

	default:
		/*
		 * Information frame
		 */

		proto_tree_add_item(ctl_tree, hf_lapsat_ctl_ftype_i,
		                    tvb, 1, 2, ENC_BIG_ENDIAN);

		proto_tree_add_item(ctl_tree, hf_lapsat_ctl_n_r,
		                    tvb, 1, 2, ENC_BIG_ENDIAN);

		proto_tree_add_item(ctl_tree, hf_lapsat_ctl_n_s,
		                    tvb, 1, 2, ENC_BIG_ENDIAN);

		if (poll_final)
			proto_tree_add_item(ctl_tree, hf_lapsat_ctl_p,
					    tvb, 1, 2, ENC_BIG_ENDIAN);

		break;
	}

	return ctl;
}

static void
dissect_lapsat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *lapsat_tree, *addr_tree;
	proto_item *lapsat_ti, *addr_ti;
	tvbuff_t *payload;
	guint8 addr, sapi, cr;
	guint16 control;
	unsigned int hlen, is_response = 0, plen;

	/* Check that there's enough data */
	if (tvb_length(tvb) < LAPSAT_HEADER_LEN)
		return;

	/* Set protocol column */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "LAPSat");

	/* Grab a couple of fields */
	addr = tvb_get_guint8(tvb, 0);

	sapi = (addr & LAPSAT_SAPI_MSK) >> LAPSAT_SAPI_SHIFT;

	cr = addr & LAPSAT_CR;
	if (pinfo->p2p_dir == P2P_DIR_RECV) {
		is_response = cr ? FALSE : TRUE;
	}
	else if (pinfo->p2p_dir == P2P_DIR_SENT) {
		is_response = cr ? TRUE : FALSE;
	}

	hlen = LAPSAT_HEADER_LEN;

	if (addr & LAPSAT_LFI)
		hlen++;

		/* FIXME if "S func=GREJ", extend */

	/* Create LAPSat tree */
	lapsat_ti = proto_tree_add_item(tree, proto_lapsat, tvb, 0, hlen, ENC_BIG_ENDIAN);
	lapsat_tree = proto_item_add_subtree(lapsat_ti, ett_lapsat);

	/* Dissect address field */
	addr_ti = proto_tree_add_item(lapsat_tree, hf_lapsat_addr, tvb, 0, 1, ENC_BIG_ENDIAN);
	addr_tree = proto_item_add_subtree(addr_ti, ett_lapsat_address);

	proto_tree_add_item(addr_tree, hf_lapsat_addr_sst,  tvb, 0, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(addr_tree, hf_lapsat_addr_cr,   tvb, 0, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(addr_tree, hf_lapsat_addr_sapi, tvb, 0, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(addr_tree, hf_lapsat_addr_si,   tvb, 0, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(addr_tree, hf_lapsat_addr_lpd,  tvb, 0, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(addr_tree, hf_lapsat_addr_lfi,  tvb, 0, 1, ENC_BIG_ENDIAN);

	/* Dissect control field */
	control = dissect_control(tvb, pinfo, lapsat_tree, is_response);

	/* Last payload nibble */
	proto_tree_add_item(lapsat_tree, hf_lapsat_payload_last_nibble, tvb, 2, 1, ENC_BIG_ENDIAN);

	/* Optional length field */
	if (addr & LAPSAT_LFI)
		proto_tree_add_item(lapsat_tree, hf_lapsat_len, tvb, 3, 1, ENC_BIG_ENDIAN);

	/* If frame is "S func=GREJ", then add Na(R) & Nb(R) */
		/* FIXME */

	/* Get the payload */
	plen = (addr & LAPSAT_LFI) ?
		tvb_get_guint8(tvb, 3) : tvb_length(tvb) - hlen;

	if (!plen)
		return;	/* No point in doing more if there is no payload */

	DISSECTOR_ASSERT((plen + hlen) <= tvb_length(tvb));

	if ((plen + hlen) == tvb_length(tvb)) {
		/* Need to integrate the last nibble */
		guint8 *data = ep_alloc(plen);
		tvb_memcpy(tvb, data, hlen, plen);
		data[plen-1] |= tvb_get_guint8(tvb, 2) << 4;
		payload = tvb_new_child_real_data(tvb, data, plen, plen);
	} else {
		/* Last nibble doesn't need merging */
		payload = tvb_new_subset(tvb, hlen, plen, -1);
	}

	add_new_data_source(pinfo, payload, "LAPSat Payload");

	/* Handle fragments */
	if ((control & LAPSAT_CTL_TYPE_I_MSK) == LAPSAT_CTL_TYPE_I) {
		/*
		 * Potentially fragmented I frames
		 */
		fragment_data *fd_m = NULL;
		tvbuff_t *reassembled = NULL;
		guint32 fragment_id;
		gboolean save_fragmented = pinfo->fragmented;

		/* Is this a fragment ? */
		pinfo->fragmented = !!(addr & LAPSAT_SI);

		/* Rely on caller to provide a way to group fragments */
		fragment_id = (pinfo->circuit_id << 3) | (sapi << 1) | pinfo->p2p_dir;

		/* Fragment reconstruction helpers */
		fd_m = fragment_add_seq_next(
			payload, 0, pinfo,
			fragment_id,		/* To group fragments */
			lapsat_fragment_table,
			lapsat_reassembled_table,
			plen,
			!!(addr & LAPSAT_SI)	/* More fragment ? */
		);

		reassembled = process_reassembled_data(
			payload, 0, pinfo,
			"Reassembled LAPSat", fd_m, &lapsat_frag_items,
			NULL, lapsat_tree
		);

		/* Reassembled into this packet ? */
		if (fd_m && pinfo->fd->num == fd_m->reassembled_in) {
			/* Yes, so handoff to upper layers */
			if (!dissector_try_uint(lapsat_sapi_dissector_table, sapi,
			                        reassembled, pinfo, tree))
				call_dissector(data_handle, reassembled, pinfo, tree);
		} else {
			/* No, just add infos */
			col_append_str(pinfo->cinfo, COL_INFO, " (Fragment)");
			proto_tree_add_text(lapsat_tree, payload, 0, -1, "Fragment Data");
		}

		/* Now reset fragmentation information in pinfo */
		pinfo->fragmented = save_fragmented;
	} else {
		/*
		 * Whole frame
		 */
		if (!dissector_try_uint(lapsat_sapi_dissector_table, sapi, payload, pinfo, tree))
			call_dissector(data_handle, payload, pinfo, tree);
	}
}

void
proto_register_lapsat(void)
{
	static hf_register_info hf[] = {
		/* Address field */
		{ &hf_lapsat_addr,
		  { "Address Field", "lapsat.address",
		    FT_UINT8, BASE_HEX, NULL, 0x00,
		    NULL, HFILL },
		},
		{ &hf_lapsat_addr_sst,
		  { "SST", "lapsat.address.sst",
		    FT_UINT8, BASE_DEC, VALS(lapsat_addr_sst_vals), LAPSAT_SST,
		    "SACCH status bit", HFILL },
		},
		{ &hf_lapsat_addr_cr,
		  { "C/R", "lapsat.address.cr",
		    FT_UINT8, BASE_DEC, NULL, LAPSAT_CR,
		    "Command/response bit", HFILL },
		},
		{ &hf_lapsat_addr_sapi,
		  { "SAPI", "lapsat.address.sapi",
		    FT_UINT8, BASE_DEC, VALS(lapsat_addr_sapi_vals), LAPSAT_SAPI_MSK,
		    "Service access point identifier", HFILL },
		},
		{ &hf_lapsat_addr_si,
		  { "SI", "lapsat.address.si",
		    FT_UINT8, BASE_DEC, VALS(lapsat_addr_si_vals), LAPSAT_SI,
		    "Segment Indicator", HFILL },
		},
		{ &hf_lapsat_addr_lpd,
		  { "LPD", "lapsat.address.lpd",
		    FT_UINT8, BASE_DEC, VALS(lapsat_addr_lpd_vals), LAPSAT_LPD_MSK,
		    "Link Protocol Discriminator", HFILL },
		},
		{ &hf_lapsat_addr_lfi,
		  { "LFI", "lapsat.address.lfi",
		    FT_UINT8, BASE_DEC, VALS(lapsat_addr_lfi_vals), LAPSAT_LFI,
		    "Length Field Indicator", HFILL },
		},

		/* Control field */
		{ &hf_lapsat_ctl,
		  { "Control Field", "lapsat.control_field",
		    FT_UINT16, BASE_HEX, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_lapsat_ctl_ftype_i,
		  { "Frame type", "lapsat.control.ftype",
		    FT_UINT16, BASE_DEC, VALS(lapsat_ctl_ftype_vals), LAPSAT_CTL_TYPE_I_MSK << 4,
		    NULL, HFILL }
		},
		{ &hf_lapsat_ctl_ftype_s_u,
		  { "Frame type", "lapsat.control.ftype",
		    FT_UINT16, BASE_DEC, VALS(lapsat_ctl_ftype_vals), LAPSAT_CTL_TYPE_S_U_MSK << 4,
		    NULL, HFILL }
		},
		{ &hf_lapsat_ctl_s_ftype,
		  { "Supervisory frame type", "lapsat.control.s_ftype",
		    FT_UINT16, BASE_DEC, VALS(lapsat_ctl_s_ftype_vals), LAPSAT_CTL_S_FTYPE_MSK << 4,
		    NULL, HFILL }
		},
		{ &hf_lapsat_ctl_u_modifier_cmd,
		  { "Command", "lapsat.control.u_modifier_cmd",
		    FT_UINT16, BASE_HEX, VALS(lapsat_ctl_u_modifier_vals_cmd),
		    LAPSAT_CTL_U_MODIFIER_MSK << 4,
		    NULL, HFILL }
		},
		{ &hf_lapsat_ctl_u_modifier_resp,
		  { "Response", "lapsat.control.u_modifier_resp",
		    FT_UINT16, BASE_HEX, VALS(lapsat_ctl_u_modifier_vals_resp),
		    LAPSAT_CTL_U_MODIFIER_MSK << 4,
		    NULL, HFILL }
		},
		{ &hf_lapsat_ctl_n_r,
		  { "N(R)", "lapsat.control.n_r",
		    FT_UINT16, BASE_DEC, NULL, LAPSAT_CTL_N_R_MSK << 4,
		    NULL, HFILL }
		},
		{ &hf_lapsat_ctl_n_s,
		  { "N(S)", "lapsat.control.n_s",
		    FT_UINT16, BASE_DEC, NULL, LAPSAT_CTL_N_S_MSK << 4,
		    NULL, HFILL }
		},
		{ &hf_lapsat_ctl_p,
		  { "Poll", "lapsat.control.p",
		    FT_UINT16, BASE_DEC, VALS(true_false_vals), LAPSAT_CTL_P_F << 4,
		    NULL, HFILL }
		},
		{ &hf_lapsat_ctl_f,
		  { "Final", "lapsat.control.f",
		    FT_UINT16, BASE_DEC, VALS(true_false_vals), LAPSAT_CTL_P_F << 4,
		    NULL, HFILL }
		},
		{ &hf_lapsat_ctl_mii,
		  { "MII", "lapsat.control.mii",
		    FT_UINT16, BASE_DEC, VALS(true_false_vals), LAPSAT_CTL_MII << 4,
		    "Mobile Identity Indicator", HFILL }
		},

		/* Payload last nibble */
		{ &hf_lapsat_payload_last_nibble,
		  { "Payload last nibble", "lapsat.payload.last_nibble",
		    FT_UINT8, BASE_HEX, NULL, 0x0f,
		    NULL, HFILL }
		},

		/* Length field */
		{ &hf_lapsat_len,
		  { "Length Field", "lapsat.length",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL },
		},

		/* Fragment reassembly */
		{ &hf_lapsat_fragments,
		  { "Message fragments", "lapsat.fragments",
		    FT_NONE, BASE_NONE, NULL, 0x00,
		    "LAPSat Message fragments", HFILL }
		},
		{ &hf_lapsat_fragment,
		  { "Message fragment", "lapsat.fragment",
		    FT_FRAMENUM, BASE_NONE, NULL, 0x00,
		    "LAPSat Message fragment", HFILL }
		},
		{ &hf_lapsat_fragment_overlap,
		  { "Message fragment overlap", "lapsat.fragment.overlap",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "LAPSat Message fragment overlaps with other fragment(s)", HFILL }
		},
		{ &hf_lapsat_fragment_overlap_conflicts,
		  { "Message fragment overlapping with conflicting data",
		    "lapsat.fragment.overlap.conflicts",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "LAPSat Message fragment overlaps with conflicting data", HFILL }
		},
		{ &hf_lapsat_fragment_multiple_tails,
		  { "Message has multiple tail fragments", "lapsat.fragment.multiple_tails",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "LAPSat Message fragment has multiple tail fragments", HFILL }
		},
		{ &hf_lapsat_fragment_too_long_fragment,
		  { "Message fragment too long", "lapsat.fragment.too_long_fragment",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "LAPSat Message fragment data goes beyond the packet end", HFILL }
		},
		{ &hf_lapsat_fragment_error,
		  { "Message defragmentation error", "lapsat.fragment.error",
		    FT_FRAMENUM, BASE_NONE, NULL, 0x00,
		    "LAPSat Message defragmentation error due to illegal fragments", HFILL }
		},
		{ &hf_lapsat_fragment_count,
		  { "Message fragment count", "lapsat.fragment.count",
		    FT_UINT32, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_lapsat_reassembled_in,
		  { "Reassembled in", "lapsat.reassembled.in",
		    FT_FRAMENUM, BASE_NONE, NULL, 0x00,
		    "LAPSat Message has been reassembled in this packet.", HFILL }
		},
		{ &hf_lapsat_reassembled_length,
		  { "Reassembled LAPSat length", "lapsat.reassembled.length",
		    FT_UINT32, BASE_DEC, NULL, 0x00,
		    "The total length of the reassembled payload", HFILL }
		},
	};

	static gint *ett[] = {
		&ett_lapsat,
		&ett_lapsat_address,
		&ett_lapsat_control,
		&ett_lapsat_fragment,
		&ett_lapsat_fragments,
	};

	proto_lapsat = proto_register_protocol("Link Access Procedure, Satellite channel (LAPSat)", "LAPSat", "lapsat");

	proto_register_field_array (proto_lapsat, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("lapsat", dissect_lapsat, proto_lapsat);

	lapsat_sapi_dissector_table = register_dissector_table("lapsat.sapi", "LAPSat SAPI", FT_UINT8, BASE_DEC);

	register_init_routine (lapsat_defragment_init);
}

void
proto_reg_handoff_lapsat(void)
{
	data_handle = find_dissector("data");
}
