/* packet-mrd.c   2001 Ronnie Sahlberg <See AUTHORS for email>
 * Routines for IGMP/MRD packet disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
/*


			MRDISC
	code

	0x24		draft-06
	0x25		draft-06
	0x26		draft-06

	0x30		RFC 4286
	0x31		RFC 4286
	0x32		RFC 4286

	MRD: IGMP Multicast Router Discovery

	Originally defined in draft-ietf-idmr-igmp-mrd-06.txt
	TTL==1 and IP.DST==224.0.0.2 (All-Routers) for all packets.

	In draft 08 to draft 10, MRA and MRT IPv4 destination is
	All-Systems (224.0.0.1),

	https://datatracker.ietf.org/doc/html/rfc4286
	As defined in RFC 4286, MRA and MRT IPv4 destination is
	All-Snoopers (224.0.0.106).
*/

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/unit_strings.h>

#include <wsutil/inet_addr.h>
#include <wsutil/pint.h>

#include "packet-igmp.h"

void proto_register_mrd(void);
void proto_reg_handoff_mrd(void);

static dissector_handle_t mrd_handle;

static int proto_mrd;
static int hf_checksum;
static int hf_checksum_status;
static int hf_type;
static int hf_advint;
static int hf_numopts;
static int hf_options;
static int hf_option;
static int hf_option_len;
static int hf_qi;
static int hf_rv;
static int hf_option_bytes;

static int ett_mrd;
static int ett_options;

static expert_field ei_checksum;
static expert_field ei_mrd_type_deprecated;
static expert_field ei_mrd_dest_not_local;

#define MRDISC_MRA_OLD	0x24
#define MRDISC_MRS_OLD	0x25
#define MRDISC_MRT_OLD	0x26
#define MRDISC_MRA	0x30
#define MRDISC_MRS	0x31
#define MRDISC_MRT	0x32
static const value_string mrd_types[] = {
	{MRDISC_MRA_OLD,	"Multicast Router Advertisement"},
	{MRDISC_MRS_OLD,	"Multicast Router Solicitation"},
	{MRDISC_MRT_OLD,	"Multicast Router Termination"},
	{MRDISC_MRA,	"Multicast Router Advertisement"},
	{MRDISC_MRS,	"Multicast Router Solicitation"},
	{MRDISC_MRT,	"Multicast Router Termination"},
	{0,					NULL}
};

#define MRDISC_QI	0x01
#define MRDISC_RV	0x02
static const value_string mrd_options[] = {
	{MRDISC_QI,	"Query Interval"},
	{MRDISC_RV,	"Robustness Variable"},
	{0,					NULL}
};


static int
dissect_mrd_mra_old(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	uint16_t num;

	/* Advertising Interval */
	proto_tree_add_item(parent_tree, hf_advint, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* checksum */
	igmp_checksum(parent_tree, tvb, hf_checksum, hf_checksum_status, &ei_checksum, pinfo, 0);
	offset += 2;

	/* skip unused bytes */
	offset += 2;

	/* number of options */
	num = tvb_get_ntohs(tvb, offset);
	proto_tree_add_uint(parent_tree, hf_numopts, tvb,
		offset, 2, num);
	offset += 2;

	/* process any options */
	while (num--) {
		proto_tree *tree;
		proto_item *item;
		uint8_t type,len;
		int old_offset = offset;

		item = proto_tree_add_item(parent_tree, hf_options,
			tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_options);

		type = tvb_get_uint8(tvb, offset);
		proto_tree_add_uint(tree, hf_option, tvb, offset, 1, type);
		offset += 1;

		len = tvb_get_uint8(tvb, offset);
		proto_tree_add_uint(tree, hf_option_len, tvb, offset, 1, len);
		offset += 1;

		switch (type) {
		case MRDISC_QI:
			proto_item_set_text(item,"Option: %s == %d",
					val_to_str(pinfo->pool, type, mrd_options, "unknown %x"),
					tvb_get_ntohs(tvb, offset));
			proto_tree_add_item(tree, hf_qi, tvb, offset, len,
				ENC_BIG_ENDIAN);
			offset += len;
			break;
		case MRDISC_RV:
			proto_item_set_text(item,"Option: %s == %d",
					val_to_str(pinfo->pool, type, mrd_options, "unknown %x"),
					tvb_get_ntohs(tvb, offset));
			proto_tree_add_item(tree, hf_rv, tvb, offset, len,
				ENC_BIG_ENDIAN);
			offset += len;
			break;
		default:
			proto_item_set_text(item,"Option: unknown");

			proto_tree_add_item(tree, hf_option_bytes,
				tvb, offset, len, ENC_NA);
			offset += len;
		}
		proto_item_set_len(item, offset-old_offset);
	}

	return offset;
}


static int
dissect_mrd_mra(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	/* Advertising Interval */
	proto_tree_add_item(parent_tree, hf_advint, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* checksum */
	igmp_checksum(parent_tree, tvb, hf_checksum, hf_checksum_status, &ei_checksum, pinfo, 0);
	offset += 2;

	/* Query Interval */
	proto_tree_add_item(parent_tree, hf_qi, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* Robustness Variable */
	proto_tree_add_item(parent_tree, hf_rv, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	return offset;
}


static int
dissect_mrd_mrst(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	/* skip reserved byte */
	offset += 1;

	/* checksum */
	igmp_checksum(parent_tree, tvb, hf_checksum, hf_checksum_status, &ei_checksum, pinfo, 0);
	offset += 2;

	return offset;
}


/* This function is only called from the IGMP dissector.
 * It's also part of ICMPv6 MLD, but that has a separate implementation. */
static int
dissect_mrd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
	proto_tree *tree;
	proto_item *item;
	uint8_t type;
	int offset = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MRD");
	col_clear(pinfo->cinfo, COL_INFO);

	item = proto_tree_add_item(parent_tree, proto_mrd, tvb, offset, 4, ENC_NA);
	tree = proto_item_add_subtree(item, ett_mrd);

	type = tvb_get_uint8(tvb, offset);
	col_add_str(pinfo->cinfo, COL_INFO,
			val_to_str(pinfo->pool, type, mrd_types,
				"Unknown Type:0x%02x"));

	/* type of command */
	item = proto_tree_add_uint(tree, hf_type, tvb, offset, 1, type);
	offset += 1;
	if ((pinfo->dst.type == AT_IPv4) && !in4_addr_is_local_network_control_block(pntohu32(pinfo->dst.data))) {
		proto_tree_add_expert(tree, pinfo, &ei_mrd_dest_not_local, tvb, 0, 0);
	}

	switch (type) {
	case MRDISC_MRA_OLD:
		expert_add_info(pinfo, item, &ei_mrd_type_deprecated);
		offset = dissect_mrd_mra_old(tvb, pinfo, tree, offset);
		break;
	case MRDISC_MRA:
		offset = dissect_mrd_mra(tvb, pinfo, tree, offset);
		break;
	case MRDISC_MRS_OLD:
	case MRDISC_MRT_OLD:
		expert_add_info(pinfo, item, &ei_mrd_type_deprecated);
		/* FALLTHROUGH */
	case MRDISC_MRS:
	case MRDISC_MRT:
		/* MRS and MRT packets looks the same */
		offset = dissect_mrd_mrst(tvb, pinfo, tree, offset);
		break;
	}
        proto_item_set_end(tree, tvb, offset);
	return offset;
}


void
proto_register_mrd(void)
{
	static hf_register_info hf[] = {
		{ &hf_type,
			{ "Type", "mrd.type", FT_UINT8, BASE_HEX,
			  VALS(mrd_types), 0, "MRDISC Packet Type", HFILL }},

		{ &hf_checksum,
			{ "Checksum", "mrd.checksum", FT_UINT16, BASE_HEX,
			  NULL, 0, "MRDISC Checksum", HFILL }},

		{ &hf_checksum_status,
			{ "Checksum Status", "mrd.checksum.status", FT_UINT8, BASE_NONE,
			  VALS(proto_checksum_vals), 0x0, NULL, HFILL }},

		{ &hf_advint,
			{ "Advertising Interval", "mrd.adv_int", FT_UINT8, BASE_DEC|BASE_UNIT_STRING,
			  UNS(&units_seconds), 0, NULL, HFILL }},

		{ &hf_numopts,
			{ "Number Of Options", "mrd.num_opts", FT_UINT16, BASE_DEC,
			  NULL, 0, "MRDISC Number Of Options", HFILL }},

		{ &hf_options,
			{ "Options", "mrd.options", FT_NONE, BASE_NONE,
			  NULL, 0, "MRDISC Options", HFILL }},

		{ &hf_option,
			{ "Option", "mrd.option", FT_UINT8, BASE_DEC,
			  VALS(mrd_options), 0, "MRDISC Option Type", HFILL }},

		{ &hf_option_len,
			{ "Length", "mrd.opt_len", FT_UINT8, BASE_DEC,
			  NULL, 0, "MRDISC Option Length", HFILL }},

		{ &hf_qi,
			{ "Query Interval", "mrd.query_int", FT_UINT16, BASE_DEC,
			  NULL, 0, "MRDISC Query Interval", HFILL }},

		{ &hf_rv,
			{ "Robustness Variable", "mrd.rob_var", FT_UINT16, BASE_DEC,
			  NULL, 0, "MRDISC Robustness Variable", HFILL }},

		{ &hf_option_bytes,
			{ "Data", "mrd.option_data", FT_BYTES, BASE_NONE,
			  NULL, 0, "MRDISC Unknown Option Data", HFILL }},

	};
	static int *ett[] = {
		&ett_mrd,
		&ett_options,
	};

	static ei_register_info ei[] = {
		{ &ei_checksum, { "mrd.bad_checksum", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
		{ &ei_mrd_type_deprecated, { "mrd.type.deprecated", PI_DEPRECATED, PI_NOTE, "Draft 06 or earlier type (IANA unassigned)", EXPFILL }},
		{ &ei_mrd_dest_not_local, { "mrd.dest.not_local", PI_PROTOCOL, PI_WARN, "Destination address must be in the local network control block (224.0.0/24)", EXPFILL }},
	};

	expert_module_t* expert_mrd;

	proto_mrd = proto_register_protocol("Multicast Router Discovery", "MRD", "mrd");
	proto_register_alias(proto_mrd, "mrdisc");
	proto_register_field_array(proto_mrd, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_mrd = expert_register_protocol(proto_mrd);
	expert_register_field_array(expert_mrd, ei, array_length(ei));

	mrd_handle = register_dissector("mrd", dissect_mrd, proto_mrd);
}

void
proto_reg_handoff_mrd(void)
{
	/* XXX - 0x24 and 0x25 conflict with another draft, MSNIP. Adding them
	 * doesn't really work since the IGMP type table isn't Decode As. */
	dissector_add_uint("igmp.type", IGMP_TYPE_0x24, mrd_handle);
	dissector_add_uint("igmp.type", IGMP_TYPE_0x25, mrd_handle);
	dissector_add_uint("igmp.type", IGMP_TYPE_0x26, mrd_handle);
	dissector_add_uint("igmp.type", MRDISC_MRA, mrd_handle);
	dissector_add_uint("igmp.type", MRDISC_MRS, mrd_handle);
	dissector_add_uint("igmp.type", MRDISC_MRT, mrd_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
