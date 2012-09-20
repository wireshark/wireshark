/* packet-lon.c
 * Traffic analyzer for Lontalk/EIA-709.1 networks
 * Daniel Willmann <daniel@totalueberwachung.de>
 * (c) 2011 Daniel Willmann
 *
 * Used some code by habibi_khalid <khalidhabibi@gmx.de> and
 * Honorine_KEMGNE_NGUIFFO <honorinekemgne@yahoo.fr> from
 * http://bugs.wireshark.org/bugzilla/show_bug.cgi?id=4704
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
#include <epan/expert.h>


static const value_string pdu_fmt_vs[]=
{
	{0x00, "TPDU"},
	{0x01, "SPDU"},
	{0x02, "AuthPDU"},
	{0x03, "APDU"},
	{0, NULL}
};

static const value_string addr_fmt_vs[]=
{
	{0x00, "Broadcast (0)"},
	{0x01, "Multicast (1)"},
	{0x02, "Unicast (2a)/Multicast (2b)"},
	{0x03, "Unicast (3)"},
	{0, NULL}
};

static const value_string domain_length_vs[]=
{
	{0x00, "0 bit"},
	{0x01, "8 bit"},
	{0x02, "24 bit"},
	{0x03, "48 bit"},
	{0, NULL}
};

static const value_string tpdu_type_vs[]=
{
	{0x00, "ACKD"},
	{0x01, "UnACKD_RPT"},
	{0x02, "ACK"},
	{0x04, "REMINDER"},
	{0x05, "REM/MSG"},
	{0, NULL}
};

static const value_string spdu_type_vs[]=
{
	{0x00, "REQUEST"},
	{0x02, "RESPONSE"},
	{0x04, "REMINDER"},
	{0x05, "REM/MSG"},
	{0, NULL}
};

static const value_string authpdu_type_vs[]=
{
	{0x00, "CHALLENGE"},
	{0x02, "REPLY"},
	{0, NULL}
};

static const value_string nm_code_vs[]=
{
	{0x61, "NM_QUERY_ID"},
	{0x62, "NM_RESPOND_TO_QUERY"},
	{0x63, "NM_UPDATE_DOMAIN"},
	{0x64, "NM_LEAVE_DOMAIN"},
	{0x65, "NM_UPDATE_KEY"},
	{0x66, "NM_UPDATE_ADDR"},
	{0x67, "NM_QUERY_ADDR"},
	{0x68, "NM_QUERY_NV_CNFG"},
	{0x69, "NM_UPDATE_GROUP_ADDR"},
	{0x6A, "NM_QUERY_DOMAIN"},
	{0x6B, "NM_UPDATE_NV_CNFG"},
	{0x6C, "NM_SET_NODE_MODE"},
	{0x6D, "NM_READ_MEMORY"},
	{0x6E, "NM_WRITE_MEMORY"},
	{0x6F, "NM_CHECKSUM_RECALC"},
	{0x70, "NM_WINK"},
	{0x71, "NM_MEMORY_REFRESH"},
	{0x72, "NM_QUERY_SNVT"},
	{0x73, "NM_NV_FETCH"},
	{0x7F, "NM_MANUAL_SERVICE_REQUEST"},
	{ 0, NULL}
};

static const value_string nd_code_vs[]=
{
	{0x51, "ND_QUERY_STATUS"},
	{0x52, "ND_PROXY_COMMAND"},
	{0x53, "ND_CLEAR_STATUS"},
	{0x54, "ND_QUERY_XCVR"},
	{0, NULL}
};

void proto_reg_handoff_lon(void);

static gint hf_lon_ppdu			= -1;
static gint hf_lon_ppdu_prio		= -1;
static gint hf_lon_ppdu_alt		= -1;
static gint hf_lon_ppdu_deltabl		= -1;
static gint hf_lon_npdu			= -1;
static gint hf_lon_npdu_version		= -1;
static gint hf_lon_npdu_pdu_fmt		= -1;
static gint hf_lon_npdu_addr_fmt	= -1;
static gint hf_lon_npdu_dom_len		= -1;
static gint hf_lon_addr_srcsub		= -1;
static gint hf_lon_addr_srcnode		= -1;
static gint hf_lon_addr_dstsub		= -1;
static gint hf_lon_addr_dstgrp		= -1;
static gint hf_lon_addr_dstnode		= -1;
static gint hf_lon_addr_grp		= -1;
static gint hf_lon_addr_grpmem		= -1;
static gint hf_lon_addr_uid		= -1;
static gint hf_lon_name			= -1;
static gint hf_lon_domain		= -1;
static gint hf_lon_tpdu			= -1;
static gint hf_lon_auth			= -1;
static gint hf_lon_tpdu_tpdu_type	= -1;
static gint hf_lon_trans_no		= -1;
static gint hf_lon_spdu			= -1;
static gint hf_lon_spdu_spdu_type	= -1;
static gint hf_lon_mlen			= -1;
static gint hf_lon_mlist		= -1;
static gint hf_lon_authpdu		= -1;
static gint hf_lon_authpdu_fmt		= -1;
static gint hf_lon_authpdu_authpdu_type	= -1;
static gint hf_lon_nv_dir		= -1;
static gint hf_lon_nv_selector		= -1;
static gint hf_lon_app_code		= -1;
static gint hf_lon_nm_code		= -1;
static gint hf_lon_nd_code		= -1;
static gint hf_lon_ff_code		= -1;
static gint hf_lon_nv			= -1;
static gint hf_lon_app			= -1;
static gint hf_lon_nm			= -1;
static gint hf_lon_nd			= -1;
static gint hf_lon_ff			= -1;
static gint hf_lon_checksum		= -1;
static gint proto_lon			= -1;


static gint ett_lon                     = -1;
static gint ett_ppdu			= -1;
static gint ett_npdu			= -1;
static gint ett_tpdu                    = -1;
static gint ett_spdu                    = -1;
static gint ett_authpdu                 = -1;
static gint ett_apdu                    = -1;
static gint ett_nv                      = -1;
static gint ett_app                     = -1;
static gint ett_nm                      = -1;
static gint ett_nd                      = -1;
static gint ett_ff                      = -1;

static gint ett_address			= -1;

static dissector_handle_t data_handle;

static gint dissect_apdu(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
		gint offset);

static gint
dissect_lon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	gint offset = 0;

	gint pdu_fmt, addr_fmt, dom_len, pdutype, length;
	gint addr_a;

	proto_tree *ti;
	proto_item *pi;
	proto_tree *lon_tree;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "LON");
	col_clear(pinfo->cinfo, COL_INFO);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		gint npdu, type;
		npdu = tvb_get_guint8(tvb, 0);
		type = tvb_get_guint8(tvb, 1);
		type = (type&0x30)>>4;
		col_add_fstr(pinfo->cinfo, COL_INFO,
			     "%sDelta_BL: %i Type: %s",
			     npdu&0x80?"Priority ":"",
			     npdu&0x3F,
			     val_to_str_const(type, pdu_fmt_vs, "Unknown"));
	}


	ti = proto_tree_add_item(tree, proto_lon, tvb, offset, -1, ENC_NA);
	lon_tree = proto_item_add_subtree(ti, ett_lon);

	{
		static const gint *ppdu_fields[] = {
			&hf_lon_ppdu_prio,
			&hf_lon_ppdu_alt,
			&hf_lon_ppdu_deltabl,
			NULL
		};
		proto_tree_add_bitmask(lon_tree, tvb, offset, hf_lon_ppdu,
					ett_ppdu, ppdu_fields, ENC_BIG_ENDIAN);
		offset++;
	}
	{
		static const gint *npdu_fields[] = {
			&hf_lon_npdu_version,
			&hf_lon_npdu_pdu_fmt,
			&hf_lon_npdu_addr_fmt,
			&hf_lon_npdu_dom_len,
			NULL
		};
		proto_tree_add_bitmask(lon_tree, tvb, offset, hf_lon_npdu,
					ett_npdu, npdu_fields, ENC_BIG_ENDIAN);

		pdu_fmt  = (tvb_get_guint8(tvb, offset) >> 4) & 0x03;
		addr_fmt = (tvb_get_guint8(tvb, offset) >> 2) & 0x03;
		dom_len  = tvb_get_guint8(tvb, offset) & 0x03;
		offset++;
	}
	/* Address part */
	if (addr_fmt == 0) { /* Broadcast */
		pi = proto_tree_add_text(lon_tree, tvb, offset, 3, "Address type 0 (broadcast)");
		ti = proto_item_add_subtree(pi, ett_address);
		proto_tree_add_item(ti, hf_lon_addr_srcsub, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(ti, hf_lon_addr_srcnode, tvb, offset+1, 1, ENC_NA);
		proto_tree_add_item(ti, hf_lon_addr_dstsub, tvb, offset+2, 1, ENC_NA);
		offset += 3;
	} else if (addr_fmt == 1) { /* Multicast */
		pi = proto_tree_add_text(lon_tree, tvb, offset, 3, "Address type 1 (multicast)");
		ti = proto_item_add_subtree(pi, ett_address);
		proto_tree_add_item(ti, hf_lon_addr_srcsub, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(ti, hf_lon_addr_srcnode, tvb, offset+1, 1, ENC_NA);
		proto_tree_add_item(ti, hf_lon_addr_dstgrp, tvb, offset+2, 1, ENC_NA);
		offset += 3;
	} else if (addr_fmt == 2) { /* Unicast/Multicast */
		addr_a = tvb_get_guint8(tvb, offset+1) >> 7;
		if (addr_a) { /* Type 2a */
			pi = proto_tree_add_text(lon_tree, tvb, offset, 4, "Address type 2a (unicast)");
			ti = proto_item_add_subtree(pi, ett_address);
			proto_tree_add_item(ti, hf_lon_addr_srcsub, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(ti, hf_lon_addr_srcnode, tvb, offset+1, 1, ENC_NA);
			proto_tree_add_item(ti, hf_lon_addr_dstsub, tvb, offset+2, 1, ENC_NA);
			proto_tree_add_item(ti, hf_lon_addr_dstnode, tvb, offset+3, 1, ENC_NA);
			offset += 4;
		} else { /* Type 2b */
			pi = proto_tree_add_text(lon_tree, tvb, offset, 6, "Address type 2b (multicast)");
			ti = proto_item_add_subtree(pi, ett_address);
			proto_tree_add_item(ti, hf_lon_addr_srcsub, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(ti, hf_lon_addr_srcnode, tvb, offset+1, 1, ENC_NA);
			proto_tree_add_item(ti, hf_lon_addr_dstgrp, tvb, offset+2, 1, ENC_NA);
			proto_tree_add_item(ti, hf_lon_addr_dstnode, tvb, offset+3, 1, ENC_NA);
			proto_tree_add_item(ti, hf_lon_addr_grp, tvb, offset+4, 1, ENC_NA);
			proto_tree_add_item(ti, hf_lon_addr_grpmem, tvb, offset+5, 1, ENC_NA);
			offset += 6;
		}
	} else if (addr_fmt == 3) { /* UID */
		pi = proto_tree_add_text(lon_tree, tvb, offset, 9, "Address type 3 (UID)");
		ti = proto_item_add_subtree(pi, ett_address);
		proto_tree_add_item(ti, hf_lon_addr_srcsub, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(ti, hf_lon_addr_srcnode, tvb, offset+1, 1, ENC_NA);
		proto_tree_add_item(ti, hf_lon_addr_dstsub, tvb, offset+2, 1, ENC_NA);
		proto_tree_add_item(ti, hf_lon_addr_uid, tvb, offset+3, 6, ENC_NA);
		offset += 9;
	}
	/* END Address part */
	/* Domain */
	if (dom_len == 0) { /* Domain-wide */
		proto_tree_add_text(lon_tree, tvb, offset, 0, "Domain wide addressing");
	} else if (dom_len == 1) {
		proto_tree_add_item(lon_tree, hf_lon_domain, tvb, offset, 1, ENC_NA);
		offset++;
	} else if (dom_len == 2) {
		proto_tree_add_item(lon_tree, hf_lon_domain, tvb, offset, 3, ENC_NA);
		offset += 3;
	} else if (dom_len == 3) {
		proto_tree_add_item(lon_tree, hf_lon_domain, tvb, offset, 6, ENC_NA);
		offset += 6;
	}
	/* END Domain */
	/* *PDU */
	if (pdu_fmt == 0) {        /* TPDU */
		static const gint *tpdu_fields[] = {
			&hf_lon_auth,
			&hf_lon_tpdu_tpdu_type,
			&hf_lon_trans_no,
			NULL
		};
		proto_tree_add_bitmask(lon_tree, tvb, offset, hf_lon_tpdu,
					ett_tpdu, tpdu_fields, ENC_BIG_ENDIAN);

		pdutype = (tvb_get_guint8(tvb, offset)>>4)& 0x07;
		offset++;
		if ((pdutype == 0) || (pdutype == 1)) { /* ACKD and UnACKD_RPT */
			offset += dissect_apdu(lon_tree, pinfo, tvb, offset);
		} else if (pdutype == 2) { /* ACK */
		} else if (pdutype == 4) { /* REMINDER */
			length = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(lon_tree, hf_lon_mlen, tvb, offset, 1, ENC_NA);
			offset++;
			proto_tree_add_item(lon_tree, hf_lon_mlist, tvb, offset, length, ENC_NA);
			offset += length;
		} else if (pdutype == 5) { /* REM/MSG */
			length = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(lon_tree, hf_lon_mlen, tvb, offset, 1, ENC_NA);
			offset++;
			if (length > 0)
				proto_tree_add_item(lon_tree, hf_lon_mlist, tvb, offset, length, ENC_NA);
			offset += length;
			offset += dissect_apdu(lon_tree, pinfo, tvb, offset);
		} else {
			expert_add_info_format(pinfo, lon_tree, PI_MALFORMED, PI_WARN, "Unexpected TPDU type %i", pdutype);
		}
	} else if (pdu_fmt == 1) { /* SPDU */
		static const gint *spdu_fields[] = {
			&hf_lon_auth,
			&hf_lon_spdu_spdu_type,
			&hf_lon_trans_no,
			NULL
		};
		proto_tree_add_bitmask(lon_tree, tvb, offset, hf_lon_spdu,
					ett_spdu, spdu_fields, ENC_BIG_ENDIAN);
		pdutype = (tvb_get_guint8(tvb, offset)>>4)& 0x07;
		offset++;
		if (pdutype == 0) { /* REQUEST */
			offset += dissect_apdu(lon_tree, pinfo, tvb, offset);
		} else if (pdutype == 2) { /* RESPONSE */
			offset += dissect_apdu(lon_tree, pinfo, tvb, offset);
		} else if (pdutype == 4) { /* REMINDER */
			length = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(lon_tree, hf_lon_mlen, tvb, offset, 1, ENC_NA);
			offset++;
			proto_tree_add_item(lon_tree, hf_lon_mlist, tvb, offset, length, ENC_NA);
			offset += length;
		} else if (pdutype == 5) { /* REM/MSG */
			length = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(lon_tree, hf_lon_mlen, tvb, offset, 1, ENC_NA);
			offset++;
			if (length > 0)
				proto_tree_add_item(lon_tree, hf_lon_mlist, tvb, offset, length, ENC_NA);
			offset += length;
			offset += dissect_apdu(lon_tree, pinfo, tvb, offset);
		} else {
			expert_add_info_format(pinfo, lon_tree, PI_MALFORMED, PI_WARN, "Unexpected SPDU type %i", pdutype);
		}
	} else if (pdu_fmt == 2) { /* AuthPDU */
		static const gint *authpdu_fields[] = {
			&hf_lon_authpdu_fmt,
			&hf_lon_authpdu_authpdu_type,
			&hf_lon_trans_no,
			NULL
		};
		proto_tree_add_bitmask(lon_tree, tvb, offset, hf_lon_authpdu,
					ett_authpdu, authpdu_fields, ENC_BIG_ENDIAN);

		pdutype = (tvb_get_guint8(tvb, offset)>>4)& 0x03;
		offset++;
		if (pdutype == 0) { /* CHALLENGE */
			offset += 9;
		} else if (pdutype == 2) { /* REPLY */
			offset += 9;
		} else {
			expert_add_info_format(pinfo, lon_tree,
                                               PI_MALFORMED, PI_WARN, "Unexpected AuthPDU type %i", pdutype);
		}
	} else if (pdu_fmt == 3) { /* APDU */
		offset += dissect_apdu(lon_tree, pinfo, tvb, offset);
	}
	/* END *PDU */

	return offset;
}

static gint
dissect_apdu(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
		gint offset)
{
	tvbuff_t *next_tvb;
	gint old_offset = offset, dest_type;

	dest_type = tvb_get_guint8(tvb, offset);

	if ((dest_type&0x80) == 0x80) { /* Network variable */
		static const gint *nv_fields[] = {
			&hf_lon_nv_dir,
			&hf_lon_nv_selector,
			NULL
		};
		proto_tree_add_bitmask(tree, tvb, offset, hf_lon_nv,
					ett_nv, nv_fields, ENC_BIG_ENDIAN);
		offset += 2;
	} else if ((dest_type&0xc0) == 0) { /* Application */
		static const gint *app_fields[] = {
			&hf_lon_app_code,
			NULL
		};
		proto_tree_add_bitmask(tree, tvb, offset, hf_lon_app,
					ett_app, app_fields, ENC_BIG_ENDIAN);
		offset++;
	} else if ((dest_type&0xe0) == 0x60) { /* Network Management */
		static const gint *nm_fields[] = {
			&hf_lon_nm_code,
			NULL
		};
		proto_tree_add_bitmask(tree, tvb, offset, hf_lon_nm,
					ett_nm, nm_fields, ENC_BIG_ENDIAN);
		offset++;

		if (dest_type == 0x7F) {
			proto_tree_add_item(tree, hf_lon_addr_uid, tvb, offset, 6, ENC_NA);
			offset += 6;
			proto_tree_add_item(tree, hf_lon_name, tvb, offset, 8, ENC_NA);
			offset += 8;
		}

	} else if ((dest_type&0xf0) == 0x50) { /* Network Diagnostic */
		static const gint *nd_fields[] = {
			&hf_lon_nd_code,
			NULL
		};
		proto_tree_add_bitmask(tree, tvb, offset, hf_lon_nd,
					ett_nd, nd_fields, ENC_BIG_ENDIAN);
		offset++;
	} else if ((dest_type&0xf0) == 0x40) { /* Foreign Frame */
		static const gint *ff_fields[] = {
			&hf_lon_ff_code,
			NULL
		};
		proto_tree_add_bitmask(tree, tvb, offset, hf_lon_ff,
					ett_ff, ff_fields, ENC_BIG_ENDIAN);
		offset++;
	} else { /* Shouldn't get here */
		expert_add_info_format(pinfo, tree, PI_MALFORMED, PI_WARN, "Malformed APDU destin&type %i", dest_type);
	}

	next_tvb = tvb_new_subset_remaining(tvb, offset);

	return offset - old_offset + call_dissector(data_handle, next_tvb, pinfo, tree);
}

void
proto_register_lon(void)
{
	static hf_register_info hf[] =
	{
		{&hf_lon_ppdu,
			{"PPDU", "lon.ppdu",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL }
		},
		{&hf_lon_ppdu_prio,
			{"Priority", "lon.prio",
			FT_UINT8, BASE_DEC, NULL, 0x80,
			"Priority packet", HFILL }
		},
		{&hf_lon_ppdu_alt,
			{"Alt path", "lon.alt_path",
			FT_UINT8, BASE_DEC, NULL, 0x40,
			"Alternate path", HFILL }
		},
		{&hf_lon_ppdu_deltabl,
			{"Delta BL", "lon.delta_bl",
			FT_UINT8, BASE_DEC, NULL, 0x3f,
			"How many packets to expect from this one", HFILL }
		},
		{&hf_lon_npdu,
			{"NPDU", "lon.npdu",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{&hf_lon_npdu_version,
			{"version", "lon.vers",
			FT_UINT8, BASE_HEX, NULL, 0xc0,
			"LON protocol version", HFILL }
		},
		{&hf_lon_npdu_pdu_fmt,
			{"PDU format", "lon.pdufmt",
			FT_UINT8, BASE_HEX, VALS(pdu_fmt_vs), 0x30,
			NULL, HFILL }
		},
		{&hf_lon_npdu_addr_fmt,
			{"Address format", "lon.addrfmt",
			FT_UINT8, BASE_HEX, VALS(addr_fmt_vs), 0x0c,
			NULL, HFILL }
		},
		{&hf_lon_npdu_dom_len,
			{"Domain length", "lon.domainlen",
			FT_UINT8, BASE_HEX, VALS(domain_length_vs), 0x03,
			NULL, HFILL }
		},
		{&hf_lon_addr_srcsub,
			{"Source subnet", "lon.srcnet",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL }
		},
		{&hf_lon_addr_srcnode,
			{"Source node", "lon.srcnode",
			FT_UINT8, BASE_HEX, NULL, 0x7f,
			NULL, HFILL }
		},
		{&hf_lon_addr_dstsub,
			{"Destination subnet", "lon.dstnet",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL }
		},
		{&hf_lon_addr_dstgrp,
			{"Destination group", "lon.dstgrp",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL }
		},
		{&hf_lon_addr_dstnode,
			{"Destination node", "lon.dstnode",
			FT_UINT8, BASE_HEX, NULL, 0x7f,
			NULL, HFILL }
		},
		{&hf_lon_addr_grp,
			{"Group", "lon.grp",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL }
		},
		{&hf_lon_addr_grpmem,
			{"Group member", "lon.grpmem",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL }
		},
		{&hf_lon_addr_uid,
			{"Unique node ID", "lon.uid",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{&hf_lon_domain,
			{"Domain", "lon.domain",
			FT_BYTES, BASE_NONE, NULL , 0,
			NULL, HFILL }
		},
		{&hf_lon_tpdu,
			{"TDPU", "lon.tpdu",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL }
		},
		{&hf_lon_auth,
			{"Auth", "lon.auth",
			FT_UINT8, BASE_HEX, NULL, 0x80,
			NULL, HFILL }
		},
		{&hf_lon_tpdu_tpdu_type,
			{"TPDU type", "lon.tpdu_type",
			FT_UINT8, BASE_HEX, VALS(tpdu_type_vs), 0x70,
			NULL, HFILL }
		},
		{&hf_lon_trans_no,
			{"Transaction number", "lon.trans_no",
			FT_UINT8, BASE_HEX, NULL, 0x0f,
			NULL, HFILL }
		},
		{&hf_lon_spdu,
			{"SDPU", "lon.spdu",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL }
		},
		{&hf_lon_spdu_spdu_type,
			{"SPDU type", "lon.spdu_type",
			FT_UINT8, BASE_HEX, VALS(spdu_type_vs), 0x70,
			NULL, HFILL }
		},
		{&hf_lon_mlen,
			{"Length of M_List", "lon.spdu.mlen",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL }
		},
		{&hf_lon_mlist,
			{"M_List", "lon.spdu.mlist",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL }
		},
		{&hf_lon_authpdu,
			{"AuthPDU", "lon.authpdu",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL }
		},
		{&hf_lon_authpdu_fmt,
			{"FMT (same as AddrFmt)", "lon.authpdu_addrfmt",
			FT_UINT8, BASE_HEX, NULL, 0xc,
			NULL, HFILL }
		},
		{&hf_lon_authpdu_authpdu_type,
			{"AuthPDU type", "lon.authpdu_type",
			FT_UINT8, BASE_HEX, VALS(authpdu_type_vs), 0x2,
			NULL, HFILL }
		},
		{&hf_lon_nv,
			{"Network Variable", "lon.nv",
			FT_UINT16, BASE_HEX, NULL, 0,
			NULL, HFILL }
		},
		{&hf_lon_nv_dir,
			{"NV direction", "lon.nv.dir",
			FT_UINT16, BASE_HEX, NULL, 0x4000,
			NULL, HFILL }
		},
		{&hf_lon_nv_selector,
			{"NV selector", "lon.nv.selector",
			FT_UINT16, BASE_HEX, NULL, 0x3fff,
			NULL, HFILL }
		},
		{&hf_lon_app,
			{"Application", "lon.application",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL }
		},
		{&hf_lon_app_code,
			{"Code", "lon.code",
			FT_UINT8, BASE_HEX, NULL, 0x3f,
			NULL, HFILL }
		},
		{&hf_lon_nm,
			{"Network Management", "lon.nm",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL }
		},
		{&hf_lon_nm_code,
			{"Code", "lon.code",
			FT_UINT8, BASE_HEX, VALS(nm_code_vs), 0xff,
			NULL, HFILL }
		},
		{&hf_lon_nd,
			{"Network Diagnostic", "lon.nd",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL }
		},
		{&hf_lon_nd_code,
			{"Code", "lon.code",
			FT_UINT8, BASE_HEX, VALS(nd_code_vs), 0xff,
			NULL, HFILL }
		},
		{&hf_lon_ff,
			{"Foreign Frame", "lon.ff",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL }
		},
		{&hf_lon_ff_code,
			{"Code", "lon.code",
			FT_UINT8, BASE_HEX, NULL, 0x0f,
			NULL, HFILL }
		},
		{&hf_lon_name,
			{"Node name", "lon.name",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{&hf_lon_checksum,
			{"Checksum", "lon.chksum",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL }
		}
	};

	static gint *ett[] =
	{
		&ett_lon,
		&ett_address,
		&ett_ppdu,
		&ett_npdu,
		&ett_tpdu,
		&ett_spdu,
		&ett_authpdu,
		&ett_apdu,
		&ett_nv,
		&ett_app,
		&ett_nm,
		&ett_nd,
		&ett_ff
	};

	proto_lon = proto_register_protocol("Local Operating Network",
			"LON", "lon");

	proto_register_field_array (proto_lon, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}


void
proto_reg_handoff_lon(void)
{
	dissector_handle_t lon_handle;

	lon_handle = new_create_dissector_handle(dissect_lon, proto_lon);
	data_handle = find_dissector("data");

	dissector_add_uint("cnip.protocol", 0, lon_handle);
}
