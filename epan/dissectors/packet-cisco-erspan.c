/* packet-erspan.c
 * Routines for the disassembly of Cisco's ERSPAN protocol
 *
 * Copyright 2005 Joerg Mayer (see AUTHORS file)
 * Updates for newer versions by Jason Masker <jason at masker.net>
 * Updates to support ERSPAN3 by Peter Membrey <peter@membrey.hk>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Protocol Spec:
 *   https://tools.ietf.org/html/draft-foschiano-erspan-03
 *
 * For ERSPAN packets, the "protocol type" field value in the GRE header
 * is 0x88BE (types I and II) or 0x22EB (type III).
 *   ERSPAN type I   has no extra gre header bytes (all flags 0), e.g. Broadcom Trident 2 ASIC
 *   ERSPAN type II  has version = 1
 *   ERSPAN type III has version = 2
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include "packet-gre.h"

void proto_register_erspan(void);
void proto_reg_handoff_erspan(void);

static int proto_erspan = -1;

static gint ett_erspan = -1;

static int hf_erspan_version = -1;
static int hf_erspan_vlan = -1;
static int hf_erspan_cos = -1;
static int hf_erspan_encap = -1;
static int hf_erspan_truncated = -1;
static int hf_erspan_spanid = -1;
static int hf_erspan_reserved = -1;
static int hf_erspan_index = -1;
static int hf_erspan_timestamp = -1;
static int hf_erspan_direction = -1;

static int hf_erspan_bso = -1;
static int hf_erspan_sgt = -1;
static int hf_erspan_p = -1;
static int hf_erspan_ft = -1;
static int hf_erspan_hw = -1;
static int hf_erspan_gra = -1;
static int hf_erspan_o = -1;

/* Optional Sub-header */
static int hf_erspan_platid = -1;
/* Platform ID = 1 */
static int hf_erspan_pid1_rsvd1 = -1;
static int hf_erspan_pid1_domain_id = -1;
static int hf_erspan_pid1_port_index = -1;
/* Platform ID = 3 */
static int hf_erspan_pid3_rsvd1 = -1;
static int hf_erspan_pid3_port_index = -1;
static int hf_erspan_pid3_timestamp = -1;
/* Platform ID = 4 */
static int hf_erspan_pid4_rsvd1 = -1;
static int hf_erspan_pid4_rsvd2 = -1;
static int hf_erspan_pid4_rsvd3 = -1;
/* Platform ID = 5 or 6 */
static int hf_erspan_pid5_switchid = -1;
static int hf_erspan_pid5_port_index = -1;
static int hf_erspan_pid5_timestamp = -1;
/* Platform ID = 7 (or 0) */
static int hf_erspan_pid7_rsvd1 = -1;
static int hf_erspan_pid7_source_index = -1;
static int hf_erspan_pid7_timestamp = -1;
/* ID: 0x0, 0x2, 0x8-0x63 are reserved. */
static int hf_erspan_pid_rsvd = -1;

static expert_field ei_erspan_version_unknown = EI_INIT;

#define PROTO_SHORT_NAME "ERSPAN"
#define PROTO_LONG_NAME "Encapsulated Remote Switch Packet ANalysis"

static const true_false_string tfs_direction = { "Egress", "Ingress" };

#define ERSPAN_ENCAP_00 0
#define ERSPAN_ENCAP_01 1
#define ERSPAN_ENCAP_10 2
#define ERSPAN_ENCAP_11 3
static const value_string erspan_encap_vals[] = {
	{ERSPAN_ENCAP_00, "Originally without VLAN tag"},
	{ERSPAN_ENCAP_01, "Originally ISL encapsulated"},
	{ERSPAN_ENCAP_10, "Originally 802.1Q encapsulated"},
	{ERSPAN_ENCAP_11, "VLAN tag preserved in frame"},

	{0, NULL}
};

static const value_string erspan_truncated_vals[] = {
	{0, "Not truncated"},
	{1, "Truncated"},

	{0, NULL},
};

static const value_string erspan_version_vals[] = {
	{1, "Type II"},
	{2, "Type III"},
	{G_MAXUINT16, "Type I"},

	{0, NULL},
};

static const value_string erspan_granularity_vals[] = {
	{0, "100 microseconds"},
	{1, "100 nanoseconds"},
	{2, "IEEE 1588"},
	{3, "Custom granularity"},

	{0, NULL}
};

static dissector_handle_t ethnofcs_handle;

static int
dissect_erspan(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	proto_item *ti;
	proto_tree *erspan_tree = NULL;
	tvbuff_t *eth_tvb;
	guint32 offset = 0;
	guint16 version;

	if (data == NULL) {
		/*
		 * We weren't handed the GRE flags or version.
		 *
		 * This can happen if a Linux cooked capture is done and
		 * we get a packet from an "ipgre" interface.
		 */
		version = G_MAXUINT16; /* Possible values are 0...15 */
	} else {
		guint16 gre_flags_and_ver = *(guint16 *)data;

		if (gre_flags_and_ver == 0) {
			version = G_MAXUINT16; /* Possible values are 0...15 */
		} else {
			version = tvb_get_ntohs(tvb, offset) >> 12;
		}
	}

	ti = proto_tree_add_item(tree, proto_erspan, tvb, offset, -1,
	    ENC_NA);
	proto_item_append_text(ti, " %s", val_to_str_const(version, erspan_version_vals, "Unknown"));
	erspan_tree = proto_item_add_subtree(ti, ett_erspan);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_SHORT_NAME);
	col_set_str(pinfo->cinfo, COL_INFO, PROTO_SHORT_NAME ":");

	switch (version) {
	case G_MAXUINT16:
		/* Nothing to do, GRE header only */
		break;
	case 1: {
		guint32 vlan, vlan_encap;

		proto_tree_add_item(erspan_tree, hf_erspan_version, tvb, offset, 2,
			ENC_BIG_ENDIAN);
		proto_tree_add_item_ret_uint(erspan_tree, hf_erspan_vlan, tvb, offset, 2,
			ENC_BIG_ENDIAN, &vlan);
		offset += 2;

		proto_tree_add_item(erspan_tree, hf_erspan_cos, tvb, offset, 2,
			ENC_BIG_ENDIAN);
		proto_tree_add_item_ret_uint(erspan_tree, hf_erspan_encap, tvb,
			offset, 2, ENC_BIG_ENDIAN, &vlan_encap);
		if (pinfo->vlan_id == 0 && vlan_encap != ERSPAN_ENCAP_11) {
			pinfo->vlan_id = vlan;
		}
		proto_tree_add_item(erspan_tree, hf_erspan_truncated, tvb, offset, 2,
			ENC_BIG_ENDIAN);
		proto_tree_add_item(erspan_tree, hf_erspan_spanid, tvb, offset, 2,
			ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(erspan_tree, hf_erspan_reserved, tvb,
			offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(erspan_tree, hf_erspan_index, tvb,
			offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		break;
		}
	case 2: {
		guint32 subheader = 0;
		guint32 vlan;

		proto_tree_add_item(erspan_tree, hf_erspan_version, tvb, offset, 2,
			ENC_BIG_ENDIAN);
		proto_tree_add_item_ret_uint(erspan_tree, hf_erspan_vlan, tvb, offset, 2,
			ENC_BIG_ENDIAN, &vlan);
		pinfo->vlan_id = vlan;
		offset += 2;

		proto_tree_add_item(erspan_tree, hf_erspan_cos, tvb, offset, 2,
			ENC_BIG_ENDIAN);
		proto_tree_add_item(erspan_tree, hf_erspan_bso, tvb, offset, 2,
			ENC_BIG_ENDIAN);
		proto_tree_add_item(erspan_tree, hf_erspan_truncated, tvb, offset, 2,
			ENC_BIG_ENDIAN);
		proto_tree_add_item(erspan_tree, hf_erspan_spanid, tvb, offset, 2,
			ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(erspan_tree, hf_erspan_timestamp, tvb,
			offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		proto_tree_add_item(erspan_tree, hf_erspan_sgt, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(erspan_tree, hf_erspan_p, tvb,
			offset, 2, ENC_BIG_ENDIAN);

		proto_tree_add_item(erspan_tree, hf_erspan_ft, tvb,
			offset, 2, ENC_BIG_ENDIAN);

		proto_tree_add_item(erspan_tree, hf_erspan_hw, tvb,
			offset, 2, ENC_BIG_ENDIAN);

		proto_tree_add_item(erspan_tree, hf_erspan_direction, tvb,
			offset, 2, ENC_BIG_ENDIAN);

		proto_tree_add_item(erspan_tree, hf_erspan_gra, tvb,
			offset, 2, ENC_BIG_ENDIAN);

		proto_tree_add_item_ret_uint(erspan_tree, hf_erspan_o, tvb,
			offset, 2, ENC_BIG_ENDIAN, &subheader);
		offset += 2;

		/* Platform Sepcific SubHeader, 8 octets, optional */
		if (subheader) {
			gint32 platform_id = tvb_get_ntohl(tvb, offset) >> 26;

			proto_tree_add_item(erspan_tree, hf_erspan_platid, tvb,
					offset, 4, ENC_BIG_ENDIAN);

			switch (platform_id) {
				case 1:
					proto_tree_add_item(erspan_tree, hf_erspan_pid1_rsvd1,
						tvb, offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(erspan_tree, hf_erspan_pid1_domain_id,
						tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;

					proto_tree_add_item(erspan_tree, hf_erspan_pid1_port_index,
						tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					break;

				case 3:
					proto_tree_add_item(erspan_tree, hf_erspan_pid3_rsvd1,
						tvb, offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(erspan_tree, hf_erspan_pid3_port_index,
						tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;

					proto_tree_add_item(erspan_tree, hf_erspan_pid3_timestamp,
						tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					break;

				case 4:
					proto_tree_add_item(erspan_tree, hf_erspan_pid4_rsvd1, tvb,
						offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(erspan_tree, hf_erspan_pid4_rsvd2, tvb,
						offset, 4, ENC_BIG_ENDIAN);
					offset += 4;

					proto_tree_add_item(erspan_tree, hf_erspan_pid4_rsvd3, tvb,
						offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					break;

				case 5:
				case 6:
					proto_tree_add_item(erspan_tree, hf_erspan_pid5_switchid,
						tvb, offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(erspan_tree, hf_erspan_pid5_port_index,
						tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;

					proto_tree_add_item(erspan_tree, hf_erspan_pid5_timestamp,
						tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					break;

				case 7:
				case 0: /* In some implementations it is used as an alias to 0x07. */
					proto_tree_add_item(erspan_tree, hf_erspan_pid7_rsvd1,
						tvb, offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(erspan_tree, hf_erspan_pid7_source_index,
						tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;

					proto_tree_add_item(erspan_tree, hf_erspan_pid7_timestamp,
						tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					break;
				default:
					/* ID: 0x0, 0x2, 0x8-0x63 are reserved. */
					proto_tree_add_item(erspan_tree, hf_erspan_pid_rsvd,
						tvb, offset, 8, ENC_BIG_ENDIAN);
					offset += 8;
					break;

			}
		}
		break;
		}
	default: {
		proto_item *ti_ver;

		ti_ver = proto_tree_add_item(erspan_tree, hf_erspan_version, tvb, offset, 2,
			ENC_BIG_ENDIAN);
		expert_add_info(pinfo, ti_ver, &ei_erspan_version_unknown);
		return 2;
		}
	}

	eth_tvb = tvb_new_subset_remaining(tvb, offset);
	call_dissector(ethnofcs_handle, eth_tvb, pinfo, tree);
	return tvb_captured_length(tvb);
}

void
proto_register_erspan(void)
{
	expert_module_t* expert_erspan;

	static hf_register_info hf[] = {

		{ &hf_erspan_version,
		{ "Version",	"erspan.version", FT_UINT16, BASE_DEC, VALS(erspan_version_vals),
			0xf000, NULL, HFILL }},

		{ &hf_erspan_vlan,
		{ "Vlan",	"erspan.vlan", FT_UINT16, BASE_DEC, NULL,
			0x0fff, NULL, HFILL }},

		{ &hf_erspan_cos,
		{ "COS",	"erspan.cos", FT_UINT16, BASE_DEC, NULL,
			0xe000, NULL, HFILL }},

		{ &hf_erspan_encap,
		{ "Encap",	"erspan.encap", FT_UINT16, BASE_DEC, VALS(erspan_encap_vals),
			0x1800, NULL, HFILL }},

		{ &hf_erspan_bso,
		{ "Bad/Short/Oversized",	"erspan.bso", FT_UINT16, BASE_DEC, VALS(erspan_truncated_vals),
			0x1800, NULL, HFILL }},


		{ &hf_erspan_truncated,
		{ "Truncated",	"erspan.truncated", FT_UINT16, BASE_DEC, VALS(erspan_truncated_vals),
			0x0400, "ERSPAN packet exceeded the MTU size", HFILL }},

		{ &hf_erspan_spanid,
		{ "SpanID",	"erspan.spanid", FT_UINT16, BASE_DEC, NULL,
			0x03ff, NULL, HFILL }},

		{ &hf_erspan_reserved,
		{ "Reserved",	"erspan.reserved", FT_UINT32, BASE_DEC, NULL,
			0xfff00000, NULL, HFILL }},

		{ &hf_erspan_index,
		{ "Index",	"erspan.index", FT_UINT32, BASE_DEC, NULL,
			0x000fffff, NULL, HFILL }},

		{ &hf_erspan_timestamp,
		{ "Timestamp",	"erspan.timestamp", FT_UINT32, BASE_DEC, NULL,
			0xffffffff, NULL, HFILL }},


		{ &hf_erspan_sgt,
		{ "Security Group Tag",	"erspan.sgt", FT_UINT16, BASE_DEC, NULL,
			0xffff, NULL, HFILL }},

		{ &hf_erspan_p,
		{ "Has Ethernet PDU",	"erspan.p", FT_UINT16, BASE_DEC, NULL,
			0x8000, NULL, HFILL }},


		{ &hf_erspan_ft,
		{ "Frame Type",	"erspan.ft", FT_UINT16, BASE_DEC, NULL,
			0x7C00, NULL, HFILL }},

		{ &hf_erspan_hw,
		{ "Hardware ID", "erspan.hw", FT_UINT16, BASE_DEC, NULL,
			0x03f0, NULL, HFILL }},

		{ &hf_erspan_gra,
		{ "Timestamp granularity", "erspan.gra", FT_UINT16, BASE_DEC, VALS(erspan_granularity_vals),
			0x0006, NULL, HFILL }},

		{ &hf_erspan_direction,
		{ "Direction",	"erspan.direction", FT_BOOLEAN, 16, TFS(&tfs_direction),
			0x0008, NULL, HFILL }},

		{ &hf_erspan_o,
		{ "Optional Sub headers", "erspan.o", FT_UINT16, BASE_DEC, NULL,
			0x0001, NULL, HFILL }},

		/* Sub-header Fields, optional */
		{ &hf_erspan_platid,
		{ "Platform ID", "erspan.platid", FT_UINT32, BASE_DEC, NULL,
			0xfc000000, NULL, HFILL }},

		/* ID = 1 */
		{ &hf_erspan_pid1_rsvd1,
		{ "Reserved", "erspan.pid1.rsvd1", FT_UINT32, BASE_DEC, NULL,
			0x03fff000, NULL, HFILL }},

		{ &hf_erspan_pid1_domain_id,
		{ "VSM Domain ID", "erspan.pid1.vsmid", FT_UINT16, BASE_DEC, NULL,
			0x00000fff, NULL, HFILL }},

		{ &hf_erspan_pid1_port_index,
		{ "Port ID/Index", "erspan.pid1.port_index", FT_UINT32, BASE_DEC, NULL,
			0xffffffff, NULL, HFILL }},

		/* ID = 3 */
		{ &hf_erspan_pid3_rsvd1,
		{ "Reserved", "erspan.pid3.rsvd1", FT_UINT32, BASE_DEC, NULL,
			0x03ffc000, NULL, HFILL }},

		{ &hf_erspan_pid3_port_index,
		{ "Port ID/Index", "erspan.pid3.port_index", FT_UINT16, BASE_DEC, NULL,
			0x00003fff, NULL, HFILL }},

		{ &hf_erspan_pid3_timestamp,
		{ "Upper 32-bit Timestamp", "erspan.pid3.timestamp", FT_UINT32, BASE_DEC, NULL,
			0xffffffff, NULL, HFILL }},

		/* ID = 4 */
		{ &hf_erspan_pid4_rsvd1,
		{ "Reserved", "erspan.pid4.rsvd1", FT_UINT32, BASE_DEC, NULL,
			0x03ffc000, NULL, HFILL }},

		{ &hf_erspan_pid4_rsvd2,
		{ "Reserved", "erspan.pid4.rsvd2", FT_UINT32, BASE_DEC, NULL,
			0x00003fff, NULL, HFILL }},

		{ &hf_erspan_pid4_rsvd3,
		{ "Reserved", "erspan.pid4.rsvd3", FT_UINT32, BASE_DEC, NULL,
			0xffffffff, NULL, HFILL }},

		/* ID = 5 or 6 */
		{ &hf_erspan_pid5_switchid,
		{ "Switch ID", "erspan.pid5.switchid", FT_UINT16, BASE_DEC, NULL,
			0x03ff0000, NULL, HFILL }},

		{ &hf_erspan_pid5_port_index,
		{ "Port ID/Index", "erspan.pid5.port_index", FT_UINT16, BASE_DEC, NULL,
			0x0000ffff, NULL, HFILL }},

		{ &hf_erspan_pid5_timestamp,
		{ "Timestamp (seconds)", "erspan.pid5.timestamp", FT_UINT32, BASE_DEC, NULL,
			0xffffffff, NULL, HFILL }},

		/* ID = 7 (or 0) */
		{ &hf_erspan_pid7_rsvd1,
		{ "Reserved", "erspan.pid7.rsvd1", FT_UINT32, BASE_DEC, NULL,
			0x03f00000, NULL, HFILL }},

		{ &hf_erspan_pid7_source_index,
		{ "Source Index", "erspan.pid7.source_index", FT_UINT32, BASE_DEC, NULL,
			0x000fffff, NULL, HFILL }},

		{ &hf_erspan_pid7_timestamp,
		{ "Upper 32-bit Timestamp", "erspan.pid7.timestamp", FT_UINT32, BASE_DEC, NULL,
			0xffffffff, NULL, HFILL }},

		/* Reserved */
		{ &hf_erspan_pid_rsvd,
		{ "Reserved", "erspan.pid.rsvd", FT_UINT64, BASE_DEC, NULL,
			0x03ffffff, NULL, HFILL }},

	};

	static gint *ett[] = {
		&ett_erspan,
	};

	static ei_register_info ei[] = {
		{ &ei_erspan_version_unknown, { "erspan.version.unknown", PI_UNDECODED, PI_WARN, "Unknown version, please report or test to use fake ERSPAN preference", EXPFILL }},
	};

	proto_erspan = proto_register_protocol(PROTO_LONG_NAME, PROTO_SHORT_NAME, "erspan");
	proto_register_field_array(proto_erspan, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_erspan = expert_register_protocol(proto_erspan);
	expert_register_field_array(expert_erspan, ei, array_length(ei));
}

void
proto_reg_handoff_erspan(void)
{
	dissector_handle_t erspan_handle;

	ethnofcs_handle = find_dissector_add_dependency("eth_withoutfcs", proto_erspan);

	erspan_handle = create_dissector_handle(dissect_erspan, proto_erspan);
	dissector_add_uint("gre.proto", GRE_ERSPAN_88BE, erspan_handle);
	dissector_add_uint("gre.proto", GRE_ERSPAN_22EB, erspan_handle);

}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
