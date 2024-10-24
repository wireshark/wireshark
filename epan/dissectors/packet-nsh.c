/* packet-nsh.c
 * Routines for Network Service Header
 *
 * RFC8300
 * Author: Vanson Lim <vlim@cisco.com>
 * (c) Copyright 2020, Cisco Systems Inc.
 *
 * draft-ietf-sfc-nsh-01
 * Author: Chidambaram Arunachalam <carunach@cisco.com>
 * Copyright 2016, ciscoSystems Inc.
 *
 * (c) Copyright 2016, Sumit Kumar Jha <sjha3@ncsu.edu>
 * Support for VXLAN GPE encapsulation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/expert.h>
#include <epan/ipproto.h>
#include "packet-nsh.h"
#include "packet-vxlan.h"

#define MD_TYPE_1 1
#define MD_TYPE_2 2

#define MD_MAX_VERSION 0

/* Prototypes */
void proto_reg_handoff_nsh(void);
void proto_register_nsh(void);

static dissector_handle_t nsh_handle;

static const value_string nsh_next_protocols[] = {
	{ NSH_NONE, "None" },
	{ NSH_IPV4, "IPv4" },
	{ NSH_IPV6, "IPv6" },
	{ NSH_ETHERNET, "Ethernet" },
	{ NSH_NSH, "NSH" },
	{ NSH_MPLS, "MPLS" },
	{ NSH_EXPERIMENT_1, "Experiment 1" },
	{ NSH_EXPERIMENT_2, "Experiment 2" },
	{ 0, NULL }
};


static int proto_nsh;
static int hf_nsh_version;
static int hf_nsh_oam;
static int hf_nsh_critical_metadata;
static int hf_nsh_ttl;
static int hf_nsh_length;
static int hf_nsh_md_type;
static int hf_nsh_next_proto;
static int hf_nsh_service_pathID;
static int hf_nsh_service_index;
static int hf_nsh_context_header;
static int hf_nsh_metadata_class;
static int hf_nsh_metadata_type;
static int hf_nsh_metadata_length;
static int hf_nsh_metadata;
static int hf_nsh_bbf_logical_port_id;
static int hf_nsh_bbf_logical_port_id_str;
static int hf_nsh_bbf_mac;
static int hf_nsh_bbf_network_instance;
static int hf_nsh_bbf_interface_id;

static expert_field ei_nsh_length_invalid;
static expert_field ei_nsh_tlv_incomplete_dissection;

static int ett_nsh;
static int ett_nsh_tlv;

static dissector_table_t subdissector_table;
static dissector_table_t tlv_table;

/*
 *Dissect Fixed Length Context headers
 *
 */
static void
dissect_nsh_md_type_1(tvbuff_t *tvb, proto_tree *nsh_tree, int offset)
{
	proto_tree_add_item(nsh_tree, hf_nsh_context_header, tvb, offset, 4, ENC_NA);
	proto_tree_add_item(nsh_tree, hf_nsh_context_header, tvb, offset + 4, 4, ENC_NA);
	proto_tree_add_item(nsh_tree, hf_nsh_context_header, tvb, offset + 8, 4, ENC_NA);
	proto_tree_add_item(nsh_tree, hf_nsh_context_header, tvb, offset + 12, 4, ENC_NA);
}

/*
 *Dissect Variable Length Context headers
 *
 */

static void
dissect_nsh_md_type_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *nsh_tree, int offset, int nsh_bytes_len)
{
	while (offset < nsh_bytes_len) {
		uint16_t tlv_class = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
		uint8_t  tlv_type = tvb_get_uint8(tvb, offset + 2);
		uint8_t  tlv_len = tvb_get_uint8(tvb, offset + 3) & 0x7F;

		proto_item *tlv_item;
		proto_tree *tlv_tree = proto_tree_add_subtree_format(nsh_tree, tvb, offset, 4 + tlv_len, ett_nsh_tlv, &tlv_item, "TLV: Class %u Type %u", tlv_class, tlv_type);

		proto_tree_add_item(tlv_tree, hf_nsh_metadata_class, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tlv_tree, hf_nsh_metadata_type, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tlv_tree, hf_nsh_metadata_length, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
		offset += 4;

		if (tlv_len > 0)
		{
			tvbuff_t *tlv_tvb = tvb_new_subset_length(tvb, offset, tlv_len);
			const uint32_t key = ((uint32_t) tlv_class << 8) | tlv_type;
			int dissected = dissector_try_uint(tlv_table, key, tlv_tvb, pinfo, tlv_tree);

			if (dissected == 0) {
				proto_tree_add_item(tlv_tree, hf_nsh_metadata, tlv_tvb, 0, -1, ENC_NA);
			} else if (dissected > 0 && (unsigned) dissected != tlv_len) {
				expert_add_info_format(pinfo, tlv_tree, &ei_nsh_tlv_incomplete_dissection, "TLV dissector did not dissect the whole data (%d != %d)", dissected, tlv_len);
			}

			offset += ((tlv_len + 3) / 4) * 4; // aligned up on 4-byte boundary
		}
	}
}


/*
 *Dissect Network Service Header
 *
 */

static int
dissect_nsh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

	int offset = 0;
	int md_type = -1;
	uint32_t nsh_bytes_len;
	int nsh_next_proto = -1;
	proto_item *length_pi;
	tvbuff_t *next_tvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NSH");
	col_set_str(pinfo->cinfo, COL_INFO, "Network Service Header");

	proto_item *ti;
	proto_tree *nsh_tree;

	ti = proto_tree_add_item(tree, proto_nsh, tvb, offset, 2, ENC_NA);
	nsh_tree = proto_item_add_subtree(ti, ett_nsh);

	/*NSH Base Header*/

	proto_tree_add_item(nsh_tree, hf_nsh_version, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(nsh_tree, hf_nsh_oam, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(nsh_tree, hf_nsh_critical_metadata, tvb, offset, 2, ENC_BIG_ENDIAN);


	/*NSH Time to live Bits 4 - 9*/
	proto_tree_add_item(nsh_tree, hf_nsh_ttl, tvb, offset, 2, ENC_BIG_ENDIAN);
	length_pi = proto_tree_add_item_ret_uint(nsh_tree, hf_nsh_length, tvb, offset, 2, ENC_BIG_ENDIAN, &nsh_bytes_len);
	nsh_bytes_len *= 4;
	proto_item_set_len(ti, nsh_bytes_len);


	md_type = tvb_get_uint8(tvb, offset + 2);
	proto_tree_add_item(nsh_tree, hf_nsh_md_type, tvb, offset + 2, 1, ENC_BIG_ENDIAN);

	nsh_next_proto = tvb_get_uint8(tvb, offset + 3);
	proto_tree_add_item(nsh_tree, hf_nsh_next_proto, tvb, offset + 3, 1, ENC_BIG_ENDIAN);

	/*NSH Service Path Header */
	offset = offset + 4;
	proto_tree_add_item(nsh_tree, hf_nsh_service_pathID, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(nsh_tree, hf_nsh_service_index, tvb, offset + 3, 1, ENC_BIG_ENDIAN);

	/* Decode Context Headers */
	offset = offset + 4;
	switch (md_type) {

	case MD_TYPE_1:
		/* The Length MUST be of value 0x6 for MD Type equal to 0x1 */
		if (nsh_bytes_len != 4 * 6) {
			expert_add_info_format(pinfo, length_pi, &ei_nsh_length_invalid,
					"Length MUST be of value 0x6 for MD Type equal to 0x1");
			nsh_bytes_len = 4 * 6;
		}
		dissect_nsh_md_type_1(tvb, nsh_tree, offset);
		break;

	case MD_TYPE_2:

		/* The Length MUST be of value 0x2 or greater for MD Type equal to 0x2 */
		if (nsh_bytes_len < 4 * 2) {
			expert_add_info_format(pinfo, length_pi, &ei_nsh_length_invalid,
					"Length MUST be of value 0x2 or greater for MD Type equal to 0x2");
			nsh_bytes_len = 4 * 2;
		}
		/* MD Type 2 indicates ZERO or more Variable Length Context headers*/
		if (nsh_bytes_len > 8)
			dissect_nsh_md_type_2(tvb, pinfo, nsh_tree, offset, nsh_bytes_len);
		break;

	default:
		/*
			* Unknown type, but assume presence of at least the NSH
			* Base Header (32 bits, 4 bytes).
			*/
		if (nsh_bytes_len < 4) {
			expert_add_info_format(pinfo, length_pi, &ei_nsh_length_invalid,
					"Length must be at least 0x1 for NSH Base Header");
			nsh_bytes_len = 4;
		}
		break;

	}

	/*Decode next protocol payload */

	if (tvb_captured_length_remaining(tvb, nsh_bytes_len) > 0) {
		next_tvb = tvb_new_subset_remaining(tvb, nsh_bytes_len);
		if (!dissector_try_uint(subdissector_table, nsh_next_proto, next_tvb, pinfo, tree)) {
			call_data_dissector(next_tvb, pinfo, tree);
		}
	}

	return tvb_captured_length(tvb);

}

typedef struct {
	uint16_t    class;
	uint8_t     type;
	const char* name;
	dissector_t dissector;
} nsh_tlv;

static int dissect_tlv_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, void *cb_data)
{
	const nsh_tlv* tlv = cb_data;
	proto_item_set_text(proto_tree_get_parent(tree), "TLV: %s", tlv->name);
	return tlv->dissector(tvb, pinfo, tree, data);
}

static int dissect_tlv_logical_port(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
	if (tvb_ascii_isprint(tvb, 0, -1))
	{
		const uint8_t* string_value;
		proto_tree_add_item_ret_string(tree, hf_nsh_bbf_logical_port_id_str, tvb, 0, -1, ENC_ASCII | ENC_NA, pinfo->pool, &string_value);
		proto_item_append_text(proto_tree_get_parent(tree), ": %s", string_value);
	}
	else
	{
		proto_tree_add_item(tree, hf_nsh_bbf_logical_port_id, tvb, 0, -1, ENC_NA);
	}

	return tvb_reported_length(tvb);
}

static int dissect_tlv_mac(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
	proto_tree_add_item(tree, hf_nsh_bbf_mac, tvb, 0, 6, ENC_NA);
	return 6;
}

static int dissect_tlv_network_instance(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
	const uint8_t* string_value;
	proto_tree_add_item_ret_string(tree, hf_nsh_bbf_network_instance, tvb, 0, -1, ENC_ASCII | ENC_NA, pinfo->pool, &string_value);
	proto_item_append_text(proto_tree_get_parent(tree), ": %s", string_value);
	return tvb_reported_length(tvb);
}

static int dissect_tlv_iface_identifier(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
	proto_tree_add_item(tree, hf_nsh_bbf_interface_id, tvb, 0, 8, ENC_NA);
	return 8;
}

static void register_tlv_dissectors(void)
{
	/* The TLV subdissector table contains all dissectors for the TLV data.
	   The key for the dissector is a combination of class + type.
	   In order to be able to use a dissector-table easily, these 2 bytes are combined into a
	   24-bit integer, containing the concatenation of class and type (as they appear on the wire in network-order).

	   Relevant RFC section: https://datatracker.ietf.org/doc/html/rfc8300#section-9.1.4
	   */
	static const nsh_tlv tlvs[] = {
		// TLVs defined by BBF in TR-459i2:
		{0x0200, 0x00, "Logical Port",         dissect_tlv_logical_port},
		{0x0200, 0x01, "MAC",                  dissect_tlv_mac},
		{0x0200, 0x02, "Network Instance",     dissect_tlv_network_instance},
		{0x0200, 0x03, "Interface Identifier", dissect_tlv_iface_identifier},
	};

	for (unsigned i = 0; i < sizeof(tlvs)/sizeof(tlvs[0]); i++) {
		const uint32_t key = ((uint32_t) tlvs[i].class << 8) | tlvs[i].type;
		dissector_add_uint("nsh.tlv", key, create_dissector_handle_with_data(dissect_tlv_data, -1, (void*) &tlvs[i]));
	}
}

static bool
dissect_nsh_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	const int tvb_length = tvb_captured_length(tvb);
	if (tvb_length < 8) return false;

	const uint8_t version = tvb_get_uint8(tvb, 0) >> 6;
	const uint8_t length  = tvb_get_uint8(tvb, 1) & 0x3F;
	const uint8_t md_type = tvb_get_uint8(tvb, 2) & 0x0F;
	const uint8_t proto   = tvb_get_uint8(tvb, 3);

	if (version > MD_MAX_VERSION)     return false;
	if (md_type != 1 && md_type != 2) return false;
	if (md_type == 1 && length != 6)  return false;
	if (md_type == 2 && length <  2)  return false;
	if (length * 4 > tvb_length)      return false;
	if (proto == 0)                   return false;
	if (proto > NSH_MAX_PROTOCOL)     return false;

	// Note: md_type = 0x0 and md_type = 0xf are strictly speaking also valid.
	// For the heuristic to work as good as possible, it is best to restrict
	// as much as possible and only allow md_type 1 and 2.

	dissect_nsh(tvb, pinfo, tree, data);
	return true;
}

void
proto_register_nsh(void)
{
	expert_module_t *expert_nsh;

	static hf_register_info nsh_info[] = {

		/* Network Service Header fields */
		{ &hf_nsh_version,
		{ "Version", "nsh.version",
		FT_UINT16, BASE_DEC_HEX, NULL, 0xC000,
		NULL, HFILL }
		},

		{ &hf_nsh_oam,
		{ "O Bit", "nsh.Obit",
		FT_UINT16, BASE_DEC, NULL, 0x2000,
		"OAM Bit", HFILL }
		},


		{ &hf_nsh_critical_metadata,
		{ "C Bit", "nsh.CBit",
		FT_UINT16, BASE_DEC, NULL, 0x1000,
		"Critical Metadata Bit", HFILL }
		},


		{ &hf_nsh_ttl,
		{ "Time to live", "nsh.ttl",
		FT_UINT16, BASE_HEX, NULL, 0x0FC0,
		"Maximum SFF hops for an SFP, this field is used for service-plane loop detection", HFILL }
		},


		{ &hf_nsh_length,
		{ "Length", "nsh.length",
		FT_UINT16, BASE_DEC_HEX, NULL, 0x003F,
		"Total length, in 4-byte words, of NSH including Base, Service Path headers and optional variable TLVs", HFILL }
		},


		{ &hf_nsh_md_type,
		{ "MD Type", "nsh.mdtype",
		FT_UINT8, BASE_DEC_HEX, NULL, 0x00,
		"Metadata Type defines the format of the metadata being carried", HFILL }
		},


		{ &hf_nsh_next_proto,
		{ "Next Protocol", "nsh.nextproto",
		FT_UINT8, BASE_DEC_HEX, VALS(nsh_next_protocols), 0x00,
		"Protocol type of the original packet", HFILL }
		},


		{ &hf_nsh_service_pathID,
		{ "SPI", "nsh.spi",
		FT_UINT24, BASE_DEC_HEX, NULL, 0x00,
		"Service Path Identifier", HFILL }
		},


		{ &hf_nsh_service_index,
		{ "SI", "nsh.si",
		FT_UINT8, BASE_DEC_HEX, NULL, 0x00,
		"Service Index", HFILL }
		},



		{ &hf_nsh_context_header,
		{ "Context Header", "nsh.contextheader",
		FT_BYTES, BASE_NONE, NULL, 0x00,
		"Mandatory Context Header", HFILL }
		},


		{ &hf_nsh_metadata_class,
		{ "TLV Class", "nsh.metadataclass",
		FT_UINT16, BASE_DEC_HEX, NULL, 0x00,
		"TLV class describes the scope of the metadata type field", HFILL }
		},


		{ &hf_nsh_metadata_type,
		{ "Type", "nsh.metadatatype",
		FT_UINT8, BASE_DEC_HEX, NULL, 0x00,
		"Type of metadata", HFILL }
		},


		{ &hf_nsh_metadata_length,
		{ "Length", "nsh.metadatalen",
		FT_UINT8, BASE_HEX, NULL, 0x7F,
		"Length of the variable metadata in bytes", HFILL }
		},


		{ &hf_nsh_metadata,
		{ "Variable Metadata", "nsh.metadata",
		FT_BYTES, BASE_NONE, NULL, 0x00,
		"Variable length metadata", HFILL }
		},

		{ &hf_nsh_bbf_logical_port_id,
		{ "Logical Port", "nsh.tlv.bbf.logical_port_id",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_nsh_bbf_logical_port_id_str,
		{ "Logical Port", "nsh.tlv.bbf.logical_port_id_str",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_nsh_bbf_mac,
		{ "MAC Address", "nsh.tlv.bbf.mac",
			FT_ETHER, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_nsh_bbf_network_instance,
		{ "Network Instance", "nsh.tlv.bbf.network_instance",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_nsh_bbf_interface_id,
		{ "Interface Identifier", "nsh.tlv.bbf.interface_id",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},

	};


	static int *ett[] = {
		&ett_nsh,
		&ett_nsh_tlv,
	};

	static ei_register_info ei[] = {
		{ &ei_nsh_length_invalid, { "nsh.length.invalid", PI_PROTOCOL, PI_WARN, "Invalid total length", EXPFILL }},
		{ &ei_nsh_tlv_incomplete_dissection, { "nsh.tlv.incomplete", PI_PROTOCOL, PI_WARN, "Incomplete TLV dissection", EXPFILL }},
	};

	proto_nsh = proto_register_protocol("Network Service Header", "NSH", "nsh");
	proto_register_field_array(proto_nsh, nsh_info, array_length(nsh_info));
	proto_register_subtree_array(ett, array_length(ett));

	expert_nsh = expert_register_protocol(proto_nsh);
	expert_register_field_array(expert_nsh, ei, array_length(ei));

	subdissector_table = register_dissector_table("nsh.next_proto", "NSH Next Protocol", proto_nsh, FT_UINT32, BASE_DEC);
	tlv_table = register_dissector_table("nsh.tlv", "NSH TLV", proto_nsh, FT_UINT24, BASE_HEX);

	register_tlv_dissectors();

	nsh_handle = register_dissector("nsh", dissect_nsh, proto_nsh);
}

void
proto_reg_handoff_nsh(void)
{
	dissector_add_uint("ethertype", ETHERTYPE_NSH, nsh_handle);
	dissector_add_uint("gre.proto", ETHERTYPE_NSH, nsh_handle);
	dissector_add_uint("vxlan.next_proto", VXLAN_NSH, nsh_handle);
	dissector_add_uint("nsh.next_proto", NSH_NSH, nsh_handle);
	dissector_add_uint("ip.proto", IP_PROTO_NSH, nsh_handle);

	heur_dissector_add("gtp.tpdu", dissect_nsh_heur, "NSH over GTP", "nsh_gtp.tpdu", proto_nsh, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
