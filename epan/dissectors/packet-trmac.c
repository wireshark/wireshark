/* packet-trmac.c
 * Routines for Token-Ring Media Access Control
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/expert.h>

void proto_register_trmac(void);

static int proto_trmac;
static int hf_trmac_mv;
static int hf_trmac_length;
static int hf_trmac_srcclass;
static int hf_trmac_dstclass;
static int hf_trmac_sv_len;
static int hf_trmac_sv_id;
static int hf_trmac_errors_iso;
static int hf_trmac_errors_line;
static int hf_trmac_errors_internal;
static int hf_trmac_errors_burst;
static int hf_trmac_errors_ac;
static int hf_trmac_errors_abort;
static int hf_trmac_errors_noniso;
static int hf_trmac_errors_lost;
static int hf_trmac_errors_congestion;
static int hf_trmac_errors_fc;
static int hf_trmac_errors_freq;
static int hf_trmac_errors_token;
static int hf_trmac_naun;
static int hf_trmac_beacon_type;
static int hf_trmac_assign_physical_drop_number;
static int hf_trmac_error_code;
static int hf_trmac_group_address32;
static int hf_trmac_transmit_status_code;
static int hf_trmac_station_identifier;
static int hf_trmac_sa_of_last_amp_or_smp_frame;
static int hf_trmac_error_report_timer_value;
static int hf_trmac_individual_address_count;
static int hf_trmac_correlator;
static int hf_trmac_group_address_ether;
static int hf_trmac_authorized_access_priority;
static int hf_trmac_physical_drop_number;
static int hf_trmac_authorized_function_classes;
static int hf_trmac_local_ring_number;
static int hf_trmac_functional_addresses;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_trmac_unknown_subvector;
static int hf_trmac_response_code48;
static int hf_trmac_product_instance_id;
static int hf_trmac_ring_station_version_number;
static int hf_trmac_wrap_data;
static int hf_trmac_ring_station_status;
static int hf_trmac_frame_forward;
static int hf_trmac_response_code32;

static int ett_tr_mac;
static int ett_tr_sv;
static int ett_tr_ierr_cnt;
static int ett_tr_nerr_cnt;

static expert_field ei_trmac_sv_len;

/* Major Vector */
static const value_string major_vector_vs[] = {
	{ 0x00, "Response" },
	{ 0x02, "Beacon" },
	{ 0x03, "Claim Token" },
	{ 0x04, "Ring Purge" },
	{ 0x05, "Active Monitor Present" },
	{ 0x06, "Standby Monitor Present" },
	{ 0x07, "Duplicate Address Test" },
	{ 0x09, "Transmit Forward" },
	{ 0x0B, "Remove Ring Station" },
	{ 0x0C, "Change Parameters" },
	{ 0x0D, "Initialize Ring Station" },
	{ 0x0E, "Request Ring Station Address" },
	{ 0x0F, "Request Ring Station Address" },
	{ 0x10, "Request Ring Station Attachments" },
	{ 0x20, "Request Initialization" },
	{ 0x22, "Report Ring Station Address" },
	{ 0x23, "Report Ring Station State" },
	{ 0x24, "Report Ring Station Attachments" },
	{ 0x25, "Report New Active Monitor" },
	{ 0x26, "Report NAUN Change" },
	{ 0x27, "Report Poll Error" },
	{ 0x28, "Report Monitor Errors" },
	{ 0x29, "Report Error" },
	{ 0x2A, "Report Transmit Forward" },
	{ 0x00, NULL }
};
static value_string_ext major_vector_vs_ext = VALUE_STRING_EXT_INIT(major_vector_vs);

/* Src. and Dest. Classes */
static const value_string classes_vs[] = {
	{ 0x00, "Ring Station" },
	{ 0x01, "LLC Manager" },
	{ 0x04, "Configuration Report Server" },
	{ 0x05, "Ring Parameter Server" },
	{ 0x06, "Ring Error Monitor" },
	{ 0x00, NULL }
};

static const value_string subvector_vs[] = {
	{ 0x01, "Beacon Type" },
	{ 0x02, "Upstream Neighbor's Address" },
	{ 0x03, "Local Ring Number" },
	{ 0x04, "Assign Physical Drop Number" },
	{ 0x05, "Error Report Timer Value" },
	{ 0x06, "Authorized Function Classes" },
	{ 0x07, "Authorized Access Priority" },
	{ 0x09, "Correlator" },
	{ 0x0A, "SA of Last AMP or SMP Frame" },
	{ 0x0B, "Physical Drop Number" },
	{ 0x20, "Response Code" },
	{ 0x21, "Individual Address Count" },
	{ 0x22, "Product Instance ID" },
	{ 0x23, "Ring Station Version Number" },
	{ 0x26, "Wrap Data" },
	{ 0x27, "Frame Forward" },
	{ 0x28, "Station Identifier" },
	{ 0x29, "Ring Station Status" },
	{ 0x2A, "Transmit Forward Status Code" },
	{ 0x2B, "Group Addresses" },
	{ 0x2C, "Functional Addresses" },
	{ 0x2D, "Isolating Error Counts" },
	{ 0x2E, "Non-Isolating Error Counts" },
	{ 0x2F, "Function Request ID" },
	{ 0x30, "Error Code" },
	{ 0x00, NULL }
};
static value_string_ext subvector_vs_ext = VALUE_STRING_EXT_INIT(subvector_vs);

static const value_string beacon_vs[] = {
	{ 0x00, "Recovery mode set" },
	{ 0x01, "Signal loss error" },
	{ 0x02, "Streaming signal not Claim Token MAC frame" },
	{ 0x03, "Streaming signal, Claim Token MAC frame" },
	{ 0x00, NULL }
};

/* Sub-vectors */
static int
sv_text(tvbuff_t *tvb, int svoff, packet_info *pinfo, proto_tree *tree)
{
	unsigned	sv_length, sv_id;
	uint16_t	beacon_type, ring;
	uint32_t	error_report_timer_value;

	proto_tree	*sv_tree, *sv_subtree;
	proto_item	*sv_item, *len_item, *ti;

	unsigned char		errors[6];	/* isolating or non-isolating */

	sv_tree = proto_tree_add_subtree(tree, tvb, svoff+0, 1, ett_tr_sv, &sv_item, "Subvector");

	sv_length = tvb_get_uint8(tvb, svoff+0);
	len_item = proto_tree_add_item(sv_tree, hf_trmac_sv_len, tvb, svoff+0, 1, ENC_BIG_ENDIAN);

	/* Check the SV length; it must be at least 2, to include
	   the subvector length and indicator. */
	if (sv_length < 2) {
		expert_add_info_format(pinfo, len_item, &ei_trmac_sv_len,
			"Invalid subvector: length < 2");
		return 0;	/* tells our caller to give up */
	}

	sv_id = tvb_get_uint8(tvb, svoff+1);
	proto_tree_add_item(sv_tree, hf_trmac_sv_id, tvb, svoff+1, 1, ENC_BIG_ENDIAN);
	proto_item_append_text(sv_item, " (%s)", val_to_str_ext(sv_id, &subvector_vs_ext, "Unknown subvector ID 0x%02X"));

	switch(sv_id) {
		case 0x01: /* Beacon Type */
			if (sv_length != 4) {
				expert_add_info_format(pinfo, len_item, &ei_trmac_sv_len,
				    "Subvector length is != 4");
				break;
			}
			beacon_type = tvb_get_ntohs(tvb, svoff+2);
			proto_tree_add_item(sv_tree, hf_trmac_beacon_type, tvb, svoff+2, sv_length-2, ENC_BIG_ENDIAN);
			proto_item_append_text(sv_item,
					": %s", val_to_str(beacon_type, beacon_vs, "Illegal value: %d"));
			break;

		case 0x02: /* Upstream Neighbor's Address */
			if (sv_length != 8) {
				expert_add_info_format(pinfo, len_item, &ei_trmac_sv_len,
				    "Subvector length is != 8");
				break;
			}
			proto_tree_add_item(sv_tree, hf_trmac_naun, tvb, svoff+2, sv_length-2, ENC_NA);
			proto_item_append_text(sv_item, ": %s",
					tvb_ether_to_str(pinfo->pool, tvb, svoff+2));
			break;

		case 0x03: /* Local Ring Number */
			if (sv_length != 4) {
				expert_add_info_format(pinfo, len_item, &ei_trmac_sv_len,
				    "Subvector length is != 4");
				break;
			}
			ring = tvb_get_ntohs(tvb, svoff+2);
			proto_tree_add_item(sv_tree, hf_trmac_local_ring_number, tvb, svoff+2, sv_length-2, ENC_BIG_ENDIAN);
			proto_item_append_text(sv_item,
				": 0x%04X (%d)", ring, ring);
			break;

		case 0x04: /* Assign Physical Drop Number */
			if (sv_length != 6) {
				expert_add_info_format(pinfo, len_item, &ei_trmac_sv_len,
				    "Subvector length is != 6");
				break;
			}
			proto_tree_add_item(sv_tree, hf_trmac_assign_physical_drop_number, tvb, svoff+2, sv_length-2, ENC_BIG_ENDIAN);
			proto_item_append_text(sv_item,
				": 0x%08X", tvb_get_ntohl(tvb, svoff+2) );
			break;

		case 0x05: /* Error Report Timer Value */
			if (sv_length != 4) {
				expert_add_info_format(pinfo, len_item, &ei_trmac_sv_len,
				    "Subvector length is != 4");
				break;
			}

			error_report_timer_value = 10 * tvb_get_ntohs(tvb, svoff+2);
			proto_tree_add_uint(sv_tree, hf_trmac_error_report_timer_value, tvb, svoff+2, sv_length-2, error_report_timer_value);
			proto_item_append_text(sv_item,
				": %u ms", error_report_timer_value );
			break;

		case 0x06: /* Authorized Function Classes */
			if (sv_length != 4) {
				expert_add_info_format(pinfo, len_item, &ei_trmac_sv_len,
				    "Subvector length is != 4");
				break;
			}
			proto_tree_add_item(sv_tree, hf_trmac_authorized_function_classes, tvb, svoff+2, sv_length-2, ENC_BIG_ENDIAN);
			proto_item_append_text(sv_item,
				": %04X",  tvb_get_ntohs(tvb, svoff+2) );
			break;

		case 0x07: /* Authorized Access Priority */
			if (sv_length != 4) {
				expert_add_info_format(pinfo, len_item, &ei_trmac_sv_len,
				    "Subvector length is != 4");
				break;
			}
			proto_tree_add_item(sv_tree, hf_trmac_authorized_access_priority, tvb, svoff+2, sv_length-2, ENC_BIG_ENDIAN);
			proto_item_append_text(sv_item,
				": %04X",  tvb_get_ntohs(tvb, svoff+2) );
			break;

		case 0x09: /* Correlator */
			if (sv_length != 4) {
				expert_add_info_format(pinfo, len_item, &ei_trmac_sv_len,
				    "Subvector length is != 4");
				break;
			}
			proto_tree_add_item(sv_tree, hf_trmac_correlator, tvb, svoff+2, sv_length-2, ENC_BIG_ENDIAN);
			proto_item_append_text(sv_item,
				": %04X",  tvb_get_ntohs(tvb, svoff+2) );
			break;

		case 0x0A: /* SA of Last AMP or SMP Frame */
			if (sv_length != 8) {
				expert_add_info_format(pinfo, len_item, &ei_trmac_sv_len,
				    "Subvector length is != 8");
				break;
			}
			proto_tree_add_item(sv_tree, hf_trmac_sa_of_last_amp_or_smp_frame, tvb, svoff+2, sv_length-2, ENC_NA);
			proto_item_append_text(sv_item,
				": %s",
				tvb_ether_to_str(pinfo->pool, tvb, svoff+2));
			break;

		case 0x0B: /* Physical Drop Number */
			if (sv_length != 6) {
				expert_add_info_format(pinfo, len_item, &ei_trmac_sv_len,
				    "Subvector length is != 6");
				break;
			}
			proto_tree_add_item(sv_tree, hf_trmac_physical_drop_number, tvb, svoff+2, sv_length-2, ENC_BIG_ENDIAN);
			proto_item_append_text(sv_item,
				": 0x%08X", tvb_get_ntohl(tvb, svoff+2) );
			break;

		case 0x20: /* Response Code */
			if (sv_length != 4 && sv_length != 6) {
				expert_add_info_format(pinfo, len_item, &ei_trmac_sv_len,
				    "Subvector length is != 4 and != 6");
				break;
			}
			if (sv_length == 4) {
				proto_tree_add_uint_format_value(sv_tree, hf_trmac_response_code32, tvb, svoff+2, sv_length-2,
					tvb_get_ntohl(tvb, svoff+2), "0x%04X 0x%02X 0x%02x",
					tvb_get_ntohs(tvb, svoff+2), tvb_get_uint8(tvb, svoff+4), tvb_get_uint8(tvb, svoff+5));
				proto_item_append_text(sv_item,
					": 0x%04X 0x%02X 0x%02x",
					tvb_get_ntohs(tvb, svoff+2),
					tvb_get_uint8(tvb, svoff+4),
					tvb_get_uint8(tvb, svoff+5));
			} else {
				proto_tree_add_uint64_format_value(sv_tree, hf_trmac_response_code48, tvb, svoff+2, sv_length-2,
					tvb_get_ntoh48(tvb, svoff+2), "0x%04X 0x%02X 0x%06X",
					tvb_get_ntohs(tvb, svoff+2),
					tvb_get_uint8(tvb, svoff+4),
					tvb_get_ntoh24(tvb, svoff+5));
				proto_item_append_text(sv_item,
					": 0x%04X 0x%02X 0x%06X",
					tvb_get_ntohs(tvb, svoff+2),
					tvb_get_uint8(tvb, svoff+4),
					tvb_get_ntoh24(tvb, svoff+5));
			}
			break;

		case 0x21: /* Individual Address Count */
			if (sv_length != 4) {
				expert_add_info_format(pinfo, len_item, &ei_trmac_sv_len,
				    "Subvector length is != 4");
				break;
			}
			proto_tree_add_item(sv_tree, hf_trmac_individual_address_count, tvb, svoff+2, sv_length-2, ENC_BIG_ENDIAN);
			proto_item_append_text(sv_item,
				": %u", tvb_get_ntohs(tvb, svoff+2) );
			break;

		case 0x22: /* Product Instance ID */
			proto_tree_add_item(sv_tree, hf_trmac_product_instance_id, tvb, svoff+2, sv_length-2, ENC_NA);
			break;

		case 0x23: /* Ring Station Version Number */
			proto_tree_add_item(sv_tree, hf_trmac_ring_station_version_number, tvb, svoff+2, sv_length-2, ENC_NA);
			break;

		case 0x26: /* Wrap data */
			proto_tree_add_item(sv_tree, hf_trmac_wrap_data, tvb, svoff+2, sv_length-2, ENC_NA);
			break;

		case 0x27: /* Frame Forward */
			proto_tree_add_item(sv_tree, hf_trmac_frame_forward, tvb, svoff+2, sv_length-2, ENC_NA);
			break;

		case 0x28: /* Station Identifier */
			if (sv_length != 8) {
				expert_add_info_format(pinfo, len_item, &ei_trmac_sv_len,
				    "Subvector length is != 8");
				break;
			}
			proto_tree_add_item(sv_tree, hf_trmac_station_identifier, tvb, svoff+2, sv_length-2, ENC_NA);
			proto_item_append_text(sv_item,
				": %s",
				tvb_ether_to_str(pinfo->pool, tvb, svoff+2));
			break;

		case 0x29: /* Ring Station Status */
			proto_tree_add_item(sv_tree, hf_trmac_ring_station_status, tvb, svoff+2, sv_length-2, ENC_NA);
			break;

		case 0x2A: /* Transmit Status Code */
			if (sv_length != 4) {
				expert_add_info_format(pinfo, len_item, &ei_trmac_sv_len,
				    "Subvector length is != 4");
				break;
			}
			proto_tree_add_item(sv_tree, hf_trmac_transmit_status_code, tvb, svoff+2, sv_length-2, ENC_BIG_ENDIAN);
			proto_item_append_text(sv_item,
				": %04X", tvb_get_ntohs(tvb, svoff+2) );
			break;

		case 0x2B: /* Group Address */
			if (sv_length != 6 && sv_length != 8) {
				expert_add_info_format(pinfo, len_item, &ei_trmac_sv_len,
				    "Subvector length is != 6 and != 8");
				break;
			}
			if (sv_length == 6) {
				proto_tree_add_item(sv_tree, hf_trmac_group_address32, tvb, svoff+2, sv_length-2, ENC_BIG_ENDIAN);
				proto_item_append_text(sv_item,
					": %08X", tvb_get_ntohl(tvb, svoff+2) );
			} else {
				proto_tree_add_item(sv_tree, hf_trmac_group_address_ether, tvb, svoff+2, sv_length-2, ENC_NA);
				proto_item_append_text(sv_item,
					": %s",
					tvb_ether_to_str(pinfo->pool, tvb, svoff+2));
			}
			break;

		case 0x2C: /* Functional Addresses */
			if (sv_length != 6) {
				expert_add_info_format(pinfo, len_item, &ei_trmac_sv_len,
				    "Subvector length is != 6");
				break;
			}
			proto_tree_add_item(sv_tree, hf_trmac_functional_addresses, tvb, svoff+2, sv_length-2, ENC_BIG_ENDIAN);
			proto_item_append_text(sv_item,
				": %08X", tvb_get_ntohl(tvb, svoff+2) );
			break;

		case 0x2D: /* Isolating Error Counts */
			if (sv_length != 8) {
				expert_add_info_format(pinfo, len_item, &ei_trmac_sv_len,
				    "Subvector length is != 8");
				break;
			}
			tvb_memcpy(tvb, errors, svoff+2, 6);
			ti = proto_tree_add_uint(sv_tree, hf_trmac_errors_iso, tvb, svoff+2, sv_length-2,
				errors[0] + errors[1] + errors[2] + errors[3] + errors[4]);
			sv_subtree = proto_item_add_subtree(ti, ett_tr_ierr_cnt);

			proto_tree_add_uint(sv_subtree, hf_trmac_errors_line, tvb, svoff+2, 1, errors[0]);
			proto_tree_add_uint(sv_subtree, hf_trmac_errors_internal, tvb, svoff+3, 1, errors[1]);
			proto_tree_add_uint(sv_subtree, hf_trmac_errors_burst, tvb, svoff+4, 1, errors[2]);
			proto_tree_add_uint(sv_subtree, hf_trmac_errors_ac, tvb, svoff+5, 1, errors[3]);
			proto_tree_add_uint(sv_subtree, hf_trmac_errors_abort, tvb, svoff+6, 1, errors[4]);

			break;

		case 0x2E: /* Non-Isolating Error Counts */
			if (sv_length != 8) {
				expert_add_info_format(pinfo, len_item, &ei_trmac_sv_len,
				    "Subvector length is != 8");
				break;
			}
			tvb_memcpy(tvb, errors, svoff+2, 6);
			ti = proto_tree_add_uint(sv_tree, hf_trmac_errors_noniso, tvb, svoff+2, sv_length-2,
				errors[0] + errors[1] + errors[2] + errors[3] + errors[4]);
			sv_subtree = proto_item_add_subtree(ti, ett_tr_nerr_cnt);

			proto_tree_add_uint(sv_subtree, hf_trmac_errors_lost, tvb, svoff+2, 1, errors[0]);
			proto_tree_add_uint(sv_subtree, hf_trmac_errors_congestion, tvb, svoff+3, 1, errors[1]);
			proto_tree_add_uint(sv_subtree, hf_trmac_errors_fc, tvb, svoff+4, 1, errors[2]);
			proto_tree_add_uint(sv_subtree, hf_trmac_errors_freq, tvb, svoff+5, 1, errors[3]);
			proto_tree_add_uint(sv_subtree, hf_trmac_errors_token, tvb, svoff+6, 1, errors[4]);
			break;

		case 0x30: /* Error Code */
			if (sv_length != 4) {
				expert_add_info_format(pinfo, len_item, &ei_trmac_sv_len,
				    "Subvector length is != 4");
				break;
			}
			proto_tree_add_item(sv_tree, hf_trmac_error_code, tvb, svoff+2, sv_length-2, ENC_BIG_ENDIAN);
			proto_item_append_text(sv_item,
				": %04X", tvb_get_ntohs(tvb, svoff+2) );
			break;

		default: /* Unknown */
			proto_tree_add_item(sv_tree, hf_trmac_unknown_subvector, tvb, svoff+2, sv_length-2, ENC_NA);
			break;
	}
	return sv_length;
}

static int
dissect_trmac(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree	*mac_tree;
	proto_item	*ti;
	int		sv_additional;
	uint32_t		mv_val, mv_length, sv_offset;

	if (tvb_captured_length(tvb) < 3)
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "TR MAC");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_trmac, tvb, 0, -1, ENC_NA);
	mac_tree = proto_item_add_subtree(ti, ett_tr_mac);

	proto_tree_add_item_ret_uint(mac_tree, hf_trmac_mv, tvb, 3, 1, ENC_NA, &mv_val);
	proto_tree_add_item_ret_uint(mac_tree, hf_trmac_length, tvb, 0, 2, ENC_BIG_ENDIAN, &mv_length);
	proto_item_set_len(ti, mv_length);
	proto_tree_add_item(mac_tree, hf_trmac_srcclass, tvb, 2, 1, ENC_NA);
	proto_tree_add_item(mac_tree, hf_trmac_dstclass, tvb, 2, 1, ENC_NA);

	/* Interpret the major vector */
	col_add_str(pinfo->cinfo, COL_INFO,
		    val_to_str_ext(mv_val, &major_vector_vs_ext, "Unknown Major Vector: %u"));

	/* interpret the subvectors */
	sv_offset = 4;
	while (sv_offset < mv_length) {
		sv_additional = sv_text(tvb, sv_offset, pinfo, mac_tree);

		/* if this is a bad packet, we could get a 0-length added here,
			* looping forever */
		if (sv_additional > 0)
			sv_offset += sv_additional;
		else
			break;
	}

	return tvb_captured_length(tvb);
}

void
proto_register_trmac(void)
{
	static hf_register_info hf[] = {
		{ &hf_trmac_mv,
		{ "Major Vector",			"trmac.mvec", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &major_vector_vs_ext, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_length,
		{ "Total Length",			"trmac.length", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_srcclass,
		{ "Source Class",			"trmac.srcclass", FT_UINT8, BASE_HEX, VALS(classes_vs), 0x0F,
			NULL, HFILL }},

		{ &hf_trmac_dstclass,
		{ "Destination Class",			"trmac.dstclass", FT_UINT8, BASE_HEX, VALS(classes_vs), 0xF0,
			NULL, HFILL }},

		{ &hf_trmac_sv_len,
		{ "Subvector Length",			"trmac.svec.len", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_sv_id,
		{ "Subvector Identifier",		"trmac.svec.id", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &subvector_vs_ext, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_errors_iso,
		{ "Isolating Errors",			"trmac.errors.iso", FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_errors_line,
		{ "Line Errors",			"trmac.errors.line", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_errors_internal,
		{ "Internal Errors",			"trmac.errors.internal", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_errors_burst,
		{ "Burst Errors",			"trmac.errors.burst", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_errors_ac,
		{ "A/C Errors",				"trmac.errors.ac", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_errors_abort,
		{ "Abort Delimiter Transmitted Errors",	"trmac.errors.abort", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_errors_noniso,
		{ "Non-Isolating Errors",		"trmac.errors.noniso", FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_errors_lost,
		{ "Lost Frame Errors",			"trmac.errors.lost", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_errors_congestion,
		{ "Receiver Congestion Errors",		"trmac.errors.congestion", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_errors_fc,
		{ "Frame-Copied Errors",		"trmac.errors.fc", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_errors_freq,
		{ "Frequency Errors",			"trmac.errors.freq", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_errors_token,
		{ "Token Errors",			"trmac.errors.token", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_naun,
		{ "Upstream Neighbor's Address",	"trmac.naun", FT_ETHER, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_beacon_type,
		{ "Beacon Type",			"trmac.beacon_type", FT_UINT16, BASE_DEC, VALS(beacon_vs), 0x0,
			NULL, HFILL }},

		{ &hf_trmac_local_ring_number,
		{ "Local Ring Number",			"trmac.local_ring_number", FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_assign_physical_drop_number,
		{ "Assign Physical Drop Number",	"trmac.assign_physical_drop_number", FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_error_report_timer_value,
		{ "Error Report Timer Value",		"trmac.error_report_timer_value", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_authorized_function_classes,
		{ "Authorized Function Classes",	"trmac.authorized_function_classes", FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_authorized_access_priority,
		{ "Authorized Access Priority",		"trmac.authorized_access_priority", FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_correlator,
		{ "Correlator",				"trmac.correlator", FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_sa_of_last_amp_or_smp_frame,
		{ "SA of Last AMP or SMP Frame",	"trmac.sa_of_last_amp_or_smp_frame", FT_ETHER, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_physical_drop_number,
		{ "Physical Drop Number",		"trmac.physical_drop_number", FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_individual_address_count,
		{ "Individual Address Count",		"trmac.individual_address_count", FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_station_identifier,
		{ "Station Identifier",			"trmac.station_identifier", FT_ETHER, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_transmit_status_code,
		{ "Transmit Status Code",		"trmac.transmit_status_code", FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_group_address32,
		{ "Group Address",			"trmac.group_address32s", FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_group_address_ether,
		{ "Group Address",			"trmac.group_address_ether", FT_ETHER, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_functional_addresses,
		{ "Functional Addresses",		"trmac.functional_addresses", FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_trmac_error_code,
		{ "Error Code",				"trmac.error_code", FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},

		/* Generated from convert_proto_tree_add_text.pl */
		{ &hf_trmac_response_code32, { "Response Code", "trmac.response_code", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_trmac_response_code48, { "Response Code", "trmac.response_code48", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_trmac_product_instance_id, { "Product Instance ID", "trmac.product_instance_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_trmac_ring_station_version_number, { "Ring Station Version Number", "trmac.ring_station_version_number", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_trmac_wrap_data, { "Wrap Data", "trmac.wrap_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_trmac_frame_forward, { "Frame Forward", "trmac.frame_forward", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_trmac_ring_station_status, { "Ring Station Status", "trmac.ring_station_status", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_trmac_unknown_subvector, { "Unknown Subvector", "trmac.unknown_subvector", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

	};
	static int *ett[] = {
		&ett_tr_mac,
		&ett_tr_sv,
		&ett_tr_ierr_cnt,
		&ett_tr_nerr_cnt,
	};

	static ei_register_info ei[] = {
		{ &ei_trmac_sv_len, { "trmac.svec.len.invalid", PI_MALFORMED, PI_ERROR, "Invalid length", EXPFILL }},
	};

	expert_module_t* expert_trmac;

	proto_trmac = proto_register_protocol("Token-Ring Media Access Control", "TR MAC", "trmac");
	proto_register_field_array(proto_trmac, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_trmac = expert_register_protocol(proto_trmac);
	expert_register_field_array(expert_trmac, ei, array_length(ei));

	register_dissector("trmac", dissect_trmac, proto_trmac);
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
