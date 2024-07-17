/* packet-eiss.c
 *
 * Routines for ETV-AM EISS (OC-SP-ETV-AM1.0-I05)
 * Copyright 2012, Weston Schmidt <weston_schmidt@alumni.purdue.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include "packet-mpeg-sect.h"

void proto_register_eiss(void);
void proto_reg_handoff_eiss(void);

static dissector_handle_t eiss_handle;

static int proto_eiss;

static int hf_eiss_reserved2;
static int hf_eiss_section_number;
static int hf_eiss_last_section_number;
static int hf_eiss_protocol_version_major;
static int hf_eiss_protocol_version_minor;
static int hf_eiss_application_type;

/* application_identifier() */
static int hf_eiss_organisation_id;
static int hf_eiss_application_id;

static int hf_eiss_platform_id_length;

/* platform id information */
static int hf_pdtHWManufacturer;
static int hf_pdtHWModel;
static int hf_pdtHWVersionMajor;
static int hf_pdtHWVersionMinor;
static int hf_pdtSWManufacturer;
static int hf_pdtSWModel;
static int hf_pdtSWVersionMajor;
static int hf_pdtSWVersionMinor;
static int hf_pdtProfile;

/* common to all eiss descriptors */
static int hf_eiss_descriptor_tag;
static int hf_eiss_descriptor_length;

/* application info descriptor */
static int hf_eiss_aid_app_control_code;
static int hf_eiss_aid_app_version_major;
static int hf_eiss_aid_app_version_minor;
static int hf_eiss_aid_max_proto_version_major;
static int hf_eiss_aid_max_proto_version_minor;
static int hf_eiss_aid_test_flag;
static int hf_eiss_aid_reserved;
static int hf_eiss_aid_priority;
static int hf_eiss_irl_type;
static int hf_eiss_irl_length;
static int hf_eiss_irl_string;

/* media time descriptor */
static int hf_eiss_mtd_time_value;

/* stream event descriptor */
static int hf_eiss_sed_time_value;
static int hf_eiss_sed_reserved;
static int hf_eiss_sed_descriptor_length;

static int ett_eiss;
static int ett_eiss_platform_id;
static int ett_eiss_desc;

static expert_field ei_eiss_platform_id_length;
static expert_field ei_eiss_invalid_section_length;
static expert_field ei_eiss_invalid_section_syntax_indicator;
static expert_field ei_eiss_unknown_descriptor;
static expert_field ei_eiss_section_number;
static expert_field ei_eiss_application_type;
static expert_field ei_eiss_invalid_reserved_bits;

#define MPEG_SECT_SYNTAX_INDICATOR_MASK	0x8000
#define MPEG_SECT_RESERVED_MASK		0x7000
#define MPEG_SECT_LENGTH_MASK		0x0FFF

static const value_string eiss_descriptor_values[] = {
	{ 0xe0, "ETV Application Information Descriptor" },
	{ 0xe1, "ETV Media Time Descriptor" },
	{ 0xe2, "ETV Stream Event Descriptor" },
	{    0, NULL }
};

/* ETSI TS 101 812 - DVB-MHP Specification section 10.5 */
static const range_string application_id_values[] = {
	{ 0x0000, 0x3fff, "Unsigned Application" },
	{ 0x4000, 0x7fff, "Signed Application" },
	{ 0x8000, 0xfffd, "Reserved by DVB" },
	{ 0xfffe, 0xfffe, "Wildcard for signed applications of an organisation" },
	{ 0xffff, 0xffff, "Wildcard for all applications of an organisation" },
	{      0,      0, NULL }
};

static const range_string aid_control_code_values[] = {
	{ 0x00, 0x00, "Reserved" },
	{ 0x01, 0x01, "AUTOSTART" },
	{ 0x02, 0x02, "PRESENT" },
	{ 0x03, 0x03, "DESTROY" },
	{ 0x04, 0xff, "Reserved" },
	{    0,    0, NULL }
};

static unsigned
dissect_etv_bif_platform_ids(tvbuff_t *tvb, proto_tree *tree, unsigned offset)
{
	proto_tree *platform_tree;

	platform_tree = proto_tree_add_subtree(tree, tvb, offset, 15, ett_eiss_platform_id, NULL, "Platform Id");
	proto_tree_add_item(platform_tree, hf_pdtHWManufacturer, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;
	proto_tree_add_item(platform_tree, hf_pdtHWModel,	 tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(platform_tree, hf_pdtHWVersionMajor, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(platform_tree, hf_pdtHWVersionMinor, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(platform_tree, hf_pdtSWManufacturer, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;
	proto_tree_add_item(platform_tree, hf_pdtSWModel,	 tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(platform_tree, hf_pdtSWVersionMajor, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(platform_tree, hf_pdtSWVersionMinor, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(platform_tree, hf_pdtProfile,	 tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	return 15;
}

static unsigned
dissect_eiss_descriptors(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
	proto_tree *sub_tree;
	unsigned    tag;

	tag = tvb_get_uint8(tvb, offset);

	if (0xe0 == tag) {
		unsigned total_length;

		total_length = tvb_get_uint8(tvb, offset+1);
		sub_tree = proto_tree_add_subtree(tree, tvb, offset, (2+total_length),
					ett_eiss_desc, NULL, "ETV Application Information Descriptor");
		proto_tree_add_item(sub_tree, hf_eiss_descriptor_tag,
					tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(sub_tree, hf_eiss_descriptor_length, tvb,
					offset, 1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(sub_tree, hf_eiss_aid_app_control_code, tvb,
					offset, 1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(sub_tree, hf_eiss_aid_app_version_major, tvb,
					offset, 1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(sub_tree, hf_eiss_aid_app_version_minor, tvb,
					offset, 1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(sub_tree, hf_eiss_aid_max_proto_version_major,
					tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(sub_tree, hf_eiss_aid_max_proto_version_minor,
					tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(sub_tree, hf_eiss_aid_test_flag, tvb, offset,
					1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(sub_tree, hf_eiss_aid_reserved, tvb, offset,
					3, ENC_BIG_ENDIAN);
		offset += 3;
		proto_tree_add_item(sub_tree, hf_eiss_aid_priority, tvb, offset,
					1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(sub_tree, hf_eiss_irl_type, tvb, offset, 2,
					ENC_BIG_ENDIAN);
		proto_tree_add_item(sub_tree, hf_eiss_irl_length, tvb, offset,
					2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(sub_tree, hf_eiss_irl_string, tvb, offset, 2,
					ENC_ASCII|ENC_BIG_ENDIAN);
		return (2+total_length);
	} else if (0xe1 == tag) {
		sub_tree = proto_tree_add_subtree(tree, tvb, offset, 6,
					ett_eiss_desc, NULL, "ETV Media Time Descriptor");
		proto_tree_add_item(sub_tree, hf_eiss_descriptor_tag,
					tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(sub_tree, hf_eiss_descriptor_length, tvb,
					offset, 1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(sub_tree, hf_eiss_mtd_time_value, tvb,
					offset, 4, ENC_BIG_ENDIAN);
		return 6;
	} else if (0xe2 == tag) {
		unsigned  tmp;
		tvbuff_t *payload;

		tmp = tvb_get_ntohs(tvb, offset+1);
		sub_tree = proto_tree_add_subtree(tree, tvb, offset, (3+tmp),
					ett_eiss_desc, NULL, "ETV Stream Event Descriptor");
		proto_tree_add_item(sub_tree, hf_eiss_descriptor_tag,
					tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(sub_tree, hf_eiss_sed_reserved, tvb,
					offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(sub_tree, hf_eiss_sed_descriptor_length, tvb,
					offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(sub_tree, hf_eiss_sed_time_value, tvb,
					offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		payload = tvb_new_subset_length(tvb, offset, tmp-4);
		call_data_dissector(payload, pinfo, sub_tree);

		return (3+tmp);
	} else {
		proto_tree_add_expert(tree, pinfo, &ei_eiss_unknown_descriptor, tvb, offset, -1);

		/* skip the rest of the section... for now */
		return 1000;
	}
}

static int
dissect_eiss(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	unsigned    offset = 0, packet_length, sect_len;
	proto_item *ti;
	proto_item *pi;
	proto_tree *eiss_tree;
	proto_item *items[PACKET_MPEG_SECT_PI__SIZE];
	bool        ssi;
	unsigned    reserved;
	uint8_t     reserved2;
	uint8_t     sect_num, last_sect_num;

	uint16_t eiss_application_type;
	uint8_t platform_id_length;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "EISS");

	ti = proto_tree_add_item(tree, proto_eiss, tvb, offset, -1, ENC_NA);
	eiss_tree = proto_item_add_subtree(ti, ett_eiss);

	offset += packet_mpeg_sect_header_extra(tvb, offset, eiss_tree, &sect_len,
						&reserved, &ssi, items);

	packet_length = sect_len + 3 - 4; /* + for the header, - for the crc */

	if (false != ssi) {
		proto_item *msg_error;
		msg_error = items[PACKET_MPEG_SECT_PI__SSI];

		proto_item_set_generated(msg_error);
		expert_add_info(pinfo, msg_error, &ei_eiss_invalid_section_syntax_indicator);
	}

	if (0 != reserved) {
		proto_item *msg_error;
		msg_error = items[PACKET_MPEG_SECT_PI__RESERVED];

		proto_item_set_generated(msg_error);
		expert_add_info_format(pinfo, msg_error, &ei_eiss_invalid_reserved_bits, "Invalid reserved1 bits (should all be 0)");
	}

	if (1021 < sect_len) {
		proto_item *msg_error;
		msg_error = items[PACKET_MPEG_SECT_PI__LENGTH];

		proto_item_set_generated(msg_error);
		expert_add_info(pinfo, msg_error, &ei_eiss_invalid_section_length);
	}

	reserved2 = tvb_get_uint8(tvb, offset);
	pi = proto_tree_add_item(eiss_tree, hf_eiss_reserved2, tvb, offset, 1, ENC_BIG_ENDIAN);
	if (0 != reserved2) {
		expert_add_info_format(pinfo, pi, &ei_eiss_invalid_reserved_bits, "Invalid reserved2 bits (should all be 0)");
	}
	offset++;

	sect_num = tvb_get_uint8(tvb, offset);
	last_sect_num = tvb_get_uint8(tvb, offset + 1);
	pi = proto_tree_add_item(eiss_tree, hf_eiss_section_number, tvb, offset, 1, ENC_BIG_ENDIAN);
	if (last_sect_num < sect_num) {
		expert_add_info(pinfo, pi, &ei_eiss_section_number);
	}
	offset++;
	proto_tree_add_item(eiss_tree, hf_eiss_last_section_number,     tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(eiss_tree, hf_eiss_protocol_version_major,  tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(eiss_tree, hf_eiss_protocol_version_minor,  tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	eiss_application_type = tvb_get_ntohs(tvb, offset);
	pi = proto_tree_add_item(eiss_tree, hf_eiss_application_type,   tvb, offset, 2, ENC_BIG_ENDIAN);
	if (8 != eiss_application_type) {
		expert_add_info(pinfo, pi, &ei_eiss_application_type);
	}
	offset += 2;
	proto_tree_add_item(eiss_tree, hf_eiss_organisation_id,         tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(eiss_tree, hf_eiss_application_id,          tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	platform_id_length = tvb_get_uint8(tvb, offset);
	pi = proto_tree_add_item(eiss_tree, hf_eiss_platform_id_length, tvb, offset, 1, ENC_BIG_ENDIAN);
	if (0 != platform_id_length % 15) {
		expert_add_info(pinfo, pi, &ei_eiss_platform_id_length);
	}
	offset++;

	while (0 < platform_id_length) {
		unsigned tmp;

		tmp = dissect_etv_bif_platform_ids(tvb, eiss_tree, offset);
		offset += tmp;
		if (platform_id_length < tmp) {
			platform_id_length = 0;
			/* error */
		} else {
			platform_id_length -= tmp;
		}
	}

	if (0 < packet_length) {
		proto_tree *eiss_desc_tree;
		eiss_desc_tree = proto_tree_add_subtree(eiss_tree, tvb, offset,
					packet_length-offset, ett_eiss_desc, NULL, "EISS Descriptor(s)");
		while (offset < packet_length) {
			offset += dissect_eiss_descriptors(tvb, pinfo,
							eiss_desc_tree, offset);
		}
	}

	packet_mpeg_sect_crc(tvb, pinfo, eiss_tree, 0, sect_len - 1);
	return tvb_captured_length(tvb);
}


void
proto_register_eiss(void)
{

	static hf_register_info hf[] = {
		{ &hf_eiss_reserved2, {
			"Reserved", "eiss.reserved",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_eiss_section_number, {
			"Section Number", "eiss.sect_num",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_eiss_last_section_number, {
			"Last Section Number", "eiss.last_sect_num",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_eiss_protocol_version_major, {
			"Major Version Number", "eiss.version_major",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_eiss_protocol_version_minor, {
			"Minor Version Number", "eiss.version_minor",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_eiss_application_type, {
			"Application Type", "eiss.app_type",
			FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_eiss_organisation_id, {
			"Organisation Id", "eiss.org_id",
			FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_eiss_application_id, {
			"Application Id", "eiss.app_id",
			FT_UINT16, BASE_HEX|BASE_RANGE_STRING, RVALS(application_id_values), 0, NULL, HFILL
		} },

		{ &hf_eiss_platform_id_length, {
			"Platform Id Length", "eiss.platform_id_length",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_pdtHWManufacturer, {
			"Platform Hardware Manufacturer", "eiss.plat_hw_man",
			FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_pdtHWModel, {
			"Platform Hardware Model", "eiss.plat_hw_model",
			FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_pdtHWVersionMajor, {
			"Platform Hardware Major Version", "eiss.plat_hw_major",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_pdtHWVersionMinor, {
			"Platform Hardware Minor Version", "eiss.plat_hw_minor",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_pdtSWManufacturer, {
			"Platform Software Manufacturer", "eiss.plat_sw_man",
			FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_pdtSWModel, {
			"Platform Software Model", "eiss.plat_sw_model",
			FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_pdtSWVersionMajor, {
			"Platform Software Major Version", "eiss.plat_sw_major",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_pdtSWVersionMinor, {
			"Platform Software Minor Version", "eiss.plat_sw_minor",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_pdtProfile, {
			"Platform Profile", "eiss.plat_profile",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_eiss_descriptor_tag, {
			"EISS Descriptor Tag", "eiss.desc.tag",
			FT_UINT8, BASE_HEX, VALS(eiss_descriptor_values), 0, NULL, HFILL
		} },

		{ &hf_eiss_descriptor_length, {
			"Descriptor Length", "eiss.desc.length",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_eiss_aid_app_control_code, {
			"Application Control Code", "eiss.aid.app_control_code",
			FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(aid_control_code_values), 0, NULL, HFILL
		} },

		{ &hf_eiss_aid_app_version_major, {
			"Application Version Major", "eiss.aid.app_version_major",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_eiss_aid_app_version_minor, {
			"Application Version Minor", "eiss.aid.app_version_minor",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_eiss_aid_max_proto_version_major, {
			"Max Protocol Version Major", "eiss.aid.max_proto_version_major",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_eiss_aid_max_proto_version_minor, {
			"Max Protocol Version Minor", "eiss.aid.max_proto_version_minor",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_eiss_aid_test_flag, {
			"Application Test Flag", "eiss.aid.test_flag",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_eiss_aid_reserved, {
			"Reserved", "eiss.aid.reserved",
			FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_eiss_aid_priority, {
			"Application Priority", "eiss.aid.priority",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_eiss_irl_type, {
			"Initial Resource Locator Type", "eiss.aid.irl.type",
			FT_UINT16, BASE_HEX, NULL, 0xfc00, NULL, HFILL
		} },

		{ &hf_eiss_irl_length, {
			"Initial Resource Locator Length", "eiss.aid.irl.length",
			FT_UINT16, BASE_DEC, NULL, 0x03ff, NULL, HFILL
		} },

		{ &hf_eiss_irl_string, {
			"Initial Resource Locator String", "eiss.aid.irl.string",
			FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
		} },

		{ &hf_eiss_mtd_time_value, {
			"Time Value (ms)", "eiss.mtd.time_value",
			FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_eiss_sed_reserved, {
			"Reserved", "eiss.sed.reserved",
			FT_UINT16, BASE_DEC, NULL, 0xf000, NULL, HFILL
		} },

		{ &hf_eiss_sed_descriptor_length, {
			"Descriptor Length", "eiss.desc.length",
			FT_UINT16, BASE_DEC, NULL, 0x0fff, NULL, HFILL
		} },

		{ &hf_eiss_sed_time_value, {
			"Time Value (ms)", "eiss.sed.time_value",
			FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
		} }
	};

	static int *ett[] = {
		&ett_eiss,
		&ett_eiss_platform_id,
		&ett_eiss_desc,
	};

	static ei_register_info ei[] = {
		{ &ei_eiss_unknown_descriptor, { "eiss.unknown_descriptor", PI_MALFORMED, PI_ERROR, "Unknown Descriptor", EXPFILL }},
		{ &ei_eiss_invalid_section_syntax_indicator, { "eiss.invalid_section_syntax_indicator", PI_MALFORMED, PI_ERROR, "Invalid section_syntax_indicator (should be 0)", EXPFILL }},
		{ &ei_eiss_invalid_reserved_bits, { "eiss.invalid_reserved_bits", PI_MALFORMED, PI_ERROR, "Invalid reserved bits", EXPFILL }},
		{ &ei_eiss_invalid_section_length, { "eiss.invalid_section_length", PI_MALFORMED, PI_ERROR, "Invalid section_length (must not exceed 1021)", EXPFILL }},
		{ &ei_eiss_section_number, { "eiss.sect_num.invalid", PI_MALFORMED, PI_ERROR, "Invalid section_number (must be <= last_section_number)", EXPFILL }},
		{ &ei_eiss_application_type, { "eiss.app_type.invalid", PI_MALFORMED, PI_ERROR, "Invalid application_type (must be 0x0008)", EXPFILL }},
		{ &ei_eiss_platform_id_length, { "eiss.platform_id_length.invalid", PI_MALFORMED, PI_ERROR, "Invalid platform_id_length (must be a multiple of sizeof(etv_bif_platform_ids) == 15)", EXPFILL }},
	};

	expert_module_t* expert_eiss;

	proto_eiss = proto_register_protocol("ETV-AM EISS Section", "ETV-AM EISS", "eiss");

	proto_register_field_array(proto_eiss, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_eiss = expert_register_protocol(proto_eiss);
	expert_register_field_array(expert_eiss, ei, array_length(ei));

	eiss_handle = register_dissector("eiss", dissect_eiss, proto_eiss);
}


void
proto_reg_handoff_eiss(void)
{
	dissector_add_uint("mpeg_sect.tid", EISS_SECTION_TID, eiss_handle);
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
