/* packet-trmac.c
 * Routines for Token-Ring Media Access Control
 * Gilbert Ramirez <gram@alumni.rice.edu>
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

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>

static int proto_trmac = -1;
static int hf_trmac_mv = -1;
static int hf_trmac_length = -1;
static int hf_trmac_srcclass = -1;
static int hf_trmac_dstclass = -1;
static int hf_trmac_sv_len = -1;
static int hf_trmac_sv_id = -1;
static int hf_trmac_errors_iso = -1;
static int hf_trmac_errors_line = -1;
static int hf_trmac_errors_internal = -1;
static int hf_trmac_errors_burst = -1;
static int hf_trmac_errors_ac = -1;
static int hf_trmac_errors_abort = -1;
static int hf_trmac_errors_noniso = -1;
static int hf_trmac_errors_lost = -1;
static int hf_trmac_errors_congestion = -1;
static int hf_trmac_errors_fc = -1;
static int hf_trmac_errors_freq = -1;
static int hf_trmac_errors_token = -1;
static int hf_trmac_naun = -1;

static gint ett_tr_mac = -1;
static gint ett_tr_sv = -1;
static gint ett_tr_ierr_cnt = -1;
static gint ett_tr_nerr_cnt = -1;

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


/* Sub-vectors */
static int
sv_text(tvbuff_t *tvb, int svoff, packet_info *pinfo, proto_tree *tree)
{
	guint	sv_length, sv_id;
	guint16	beacon_type, ring;

	const char *beacon[] = {
		"Recovery mode set", "Signal loss error",
		"Streaming signal not Claim Token MAC frame",
		"Streaming signal, Claim Token MAC frame"
	};

	proto_tree	*sv_tree, *sv_subtree;
	proto_item	*sv_item, *len_item, *ti;

	guchar		errors[6];	/* isolating or non-isolating */

	sv_length = tvb_get_guint8(tvb, svoff+0);

	/* Check the SV length; it must be at least 2, to include
	   the subvector length and indicator. */
	if (sv_length < 2) {
		ti = proto_tree_add_text(tree, tvb, svoff+0, 1,
		    "Invalid subvector: length < 2");
		sv_tree = proto_item_add_subtree(ti, ett_tr_sv);
		len_item = proto_tree_add_uint(sv_tree, hf_trmac_sv_len, tvb, svoff+0, 1, sv_length);
		expert_add_info_format(pinfo, len_item, PI_MALFORMED, PI_ERROR,
		    "Subvector length is zero");
		return 0;	/* tells our caller to give up */
	}

	sv_item = proto_tree_add_text(tree, tvb, svoff+0, sv_length,
	    "Subvector: length %u", sv_length);
	sv_tree = proto_item_add_subtree(sv_item, ett_tr_sv);
	len_item = proto_tree_add_uint(sv_tree, hf_trmac_sv_len, tvb, svoff+0, 1, sv_length);
	sv_id = tvb_get_guint8(tvb, svoff+1);
	proto_tree_add_uint(sv_tree, hf_trmac_sv_id, tvb, svoff+1, 1, sv_id);
	proto_item_set_text(sv_item, "%s", val_to_str(sv_id, subvector_vs, "Unknown subvector ID 0x%02X"));

	switch(sv_id) {
		case 0x01: /* Beacon Type */
			if (sv_length != 4) {
				expert_add_info_format(pinfo, len_item, PI_MALFORMED, PI_ERROR,
				    "Subvector length is != 4");
				break;
			}
			beacon_type = tvb_get_ntohs(tvb, svoff+2);
			if (beacon_type < array_length(beacon)) {
				proto_tree_add_text(sv_tree, tvb, svoff+2, sv_length-2,
					"Beacon Type: %s", beacon[beacon_type] );
				proto_item_append_text(sv_item,
					": %s", beacon[beacon_type] );
			} else {
				proto_tree_add_text(sv_tree, tvb, svoff+2, sv_length-2,
					"Beacon Type: Illegal value: %d", beacon_type );
				proto_item_append_text(sv_item,
					": Illegal value: %d", beacon_type );
			}
			break;

		case 0x02: /* Upstream Neighbor's Address */
			if (sv_length != 8) {
				expert_add_info_format(pinfo, len_item, PI_MALFORMED, PI_ERROR,
				    "Subvector length is != 8");
				break;
			}
			proto_tree_add_item(sv_tree, hf_trmac_naun, tvb, svoff+2, sv_length-2, ENC_NA);
			proto_item_append_text(sv_item, ": %s",
					tvb_ether_to_str(tvb, svoff+2));
			break;

		case 0x03: /* Local Ring Number */
			if (sv_length != 4) {
				expert_add_info_format(pinfo, len_item, PI_MALFORMED, PI_ERROR,
				    "Subvector length is != 4");
				break;
			}
			ring = tvb_get_ntohs(tvb, svoff+2);
			proto_tree_add_text(sv_tree, tvb, svoff+2, sv_length-2,
				"Local Ring Number: 0x%04X (%d)", ring, ring);
			proto_item_append_text(sv_item,
				": 0x%04X (%d)", ring, ring);
			break;

		case 0x04: /* Assign Physical Drop Number */
			if (sv_length != 6) {
				expert_add_info_format(pinfo, len_item, PI_MALFORMED, PI_ERROR,
				    "Subvector length is != 6");
				break;
			}
			proto_tree_add_text(sv_tree, tvb, svoff+2, sv_length-2,
				"Assign Physical Drop Number: 0x%08X", tvb_get_ntohl(tvb, svoff+2) );
			proto_item_append_text(sv_item,
				": 0x%08X", tvb_get_ntohl(tvb, svoff+2) );
			break;

		case 0x05: /* Error Report Timer Value */
			if (sv_length != 4) {
				expert_add_info_format(pinfo, len_item, PI_MALFORMED, PI_ERROR,
				    "Subvector length is != 4");
				break;
			}
			proto_tree_add_text(sv_tree, tvb, svoff+2, sv_length-2,
				"Error Report Timer Value: %d ms", 10 * tvb_get_ntohs(tvb, svoff+2) );
			proto_item_append_text(sv_item,
				": %d ms", 10 * tvb_get_ntohs(tvb, svoff+2) );
			break;

		case 0x06: /* Authorized Function Classes */
			if (sv_length != 4) {
				expert_add_info_format(pinfo, len_item, PI_MALFORMED, PI_ERROR,
				    "Subvector length is != 4");
				break;
			}
			proto_tree_add_text(sv_tree, tvb, svoff+2, sv_length-2,
				"Authorized Function Classes: %04X",  tvb_get_ntohs(tvb, svoff+2) );
			proto_item_append_text(sv_item,
				": %04X",  tvb_get_ntohs(tvb, svoff+2) );
			break;

		case 0x07: /* Authorized Access Priority */
			if (sv_length != 4) {
				expert_add_info_format(pinfo, len_item, PI_MALFORMED, PI_ERROR,
				    "Subvector length is != 4");
				break;
			}
			proto_tree_add_text(sv_tree, tvb, svoff+2, sv_length-2,
				"Authorized Access Priority: %04X",  tvb_get_ntohs(tvb, svoff+2) );
			proto_item_append_text(sv_item,
				": %04X",  tvb_get_ntohs(tvb, svoff+2) );
			break;

		case 0x09: /* Correlator */
			if (sv_length != 4) {
				expert_add_info_format(pinfo, len_item, PI_MALFORMED, PI_ERROR,
				    "Subvector length is != 4");
				break;
			}
			proto_tree_add_text(sv_tree, tvb, svoff+2, sv_length-2,
				"Correlator: %04X",  tvb_get_ntohs(tvb, svoff+2) );
			proto_item_append_text(sv_item,
				": %04X",  tvb_get_ntohs(tvb, svoff+2) );
			break;

		case 0x0A: /* SA of Last AMP or SMP Frame */
			if (sv_length != 8) {
				expert_add_info_format(pinfo, len_item, PI_MALFORMED, PI_ERROR,
				    "Subvector length is != 8");
				break;
			}
			proto_tree_add_text(sv_tree, tvb, svoff+2, sv_length-2,
				"SA of Last AMP or SMP Frame: %s",
				tvb_ether_to_str(tvb, svoff+2));
			proto_item_append_text(sv_item,
				": %s",
				tvb_ether_to_str(tvb, svoff+2));
			break;

		case 0x0B: /* Physical Drop Number */
			if (sv_length != 6) {
				expert_add_info_format(pinfo, len_item, PI_MALFORMED, PI_ERROR,
				    "Subvector length is != 6");
				break;
			}
			proto_tree_add_text(sv_tree, tvb, svoff+2, sv_length-2,
				"Physical Drop Number: 0x%08X", tvb_get_ntohl(tvb, svoff+2) );
			proto_item_append_text(sv_item,
				": 0x%08X", tvb_get_ntohl(tvb, svoff+2) );
			break;

		case 0x20: /* Response Code */
			if (sv_length != 4 && sv_length != 6) {
				expert_add_info_format(pinfo, len_item, PI_MALFORMED, PI_ERROR,
				    "Subvector length is != 4 and != 6");
				break;
			}
			if (sv_length == 4) {
				proto_tree_add_text(sv_tree, tvb, svoff+2, sv_length-2,
					"Response Code: 0x%04X 0x%02X 0x%02x",
					tvb_get_ntohs(tvb, svoff+2),
					tvb_get_guint8(tvb, svoff+4),
					tvb_get_guint8(tvb, svoff+5));
				proto_item_append_text(sv_item,
					": 0x%04X 0x%02X 0x%02x",
					tvb_get_ntohs(tvb, svoff+2),
					tvb_get_guint8(tvb, svoff+4),
					tvb_get_guint8(tvb, svoff+5));
			} else {
				proto_tree_add_text(sv_tree, tvb, svoff+2, sv_length-2,
					"Response Code: 0x%04X 0x%02X 0x%06X",
					tvb_get_ntohs(tvb, svoff+2),
					tvb_get_guint8(tvb, svoff+4),
					tvb_get_ntoh24(tvb, svoff+5));
				proto_item_append_text(sv_item,
					": 0x%04X 0x%02X 0x%06X",
					tvb_get_ntohs(tvb, svoff+2),
					tvb_get_guint8(tvb, svoff+4),
					tvb_get_ntoh24(tvb, svoff+5));
			}
			break;

		case 0x21: /* Individual Address Count */
			if (sv_length != 4) {
				expert_add_info_format(pinfo, len_item, PI_MALFORMED, PI_ERROR,
				    "Subvector length is != 4");
				break;
			}
			proto_tree_add_text(sv_tree, tvb, svoff+2, sv_length-2,
				"Individual Address Count: %u", tvb_get_ntohs(tvb, svoff+2) );
			proto_item_append_text(sv_item,
				": %u", tvb_get_ntohs(tvb, svoff+2) );
			break;

		case 0x22: /* Product Instance ID */
			proto_tree_add_text(sv_tree, tvb, svoff+2, sv_length-2,
				"Product Instance ID: ...");
			break;

		case 0x23: /* Ring Station Version Number */
			proto_tree_add_text(sv_tree, tvb, svoff+2, sv_length-2,
				"Ring Station Version Number: ...");
			break;

		case 0x26: /* Wrap data */
			proto_tree_add_text(sv_tree, tvb, svoff+2, sv_length-2,
				"Wrap Data: ... (%u bytes)", sv_length - 2);
			break;

		case 0x27: /* Frame Forward */
			proto_tree_add_text(sv_tree, tvb, svoff+2, sv_length-2,
				"Frame Forward: ... (%d bytes)", sv_length - 2);
			break;

		case 0x28: /* Station Identifier */
			if (sv_length != 8) {
				expert_add_info_format(pinfo, len_item, PI_MALFORMED, PI_ERROR,
				    "Subvector length is != 8");
				break;
			}
			proto_tree_add_text(sv_tree, tvb, svoff+2, sv_length-2,
				"Station Identifier: %s",
				tvb_ether_to_str(tvb, svoff+2));
			proto_item_append_text(sv_item,
				": %s",
				tvb_ether_to_str(tvb, svoff+2));
			break;

		case 0x29: /* Ring Station Status */
			proto_tree_add_text(sv_tree, tvb, svoff+2, sv_length-2,
				"Ring Station Status: ...");
			break;

		case 0x2A: /* Transmit Status Code */
			if (sv_length != 4) {
				expert_add_info_format(pinfo, len_item, PI_MALFORMED, PI_ERROR,
				    "Subvector length is != 4");
				break;
			}
			proto_tree_add_text(sv_tree, tvb, svoff+2, sv_length-2,
				"Transmit Status Code: %04X", tvb_get_ntohs(tvb, svoff+2) );
			proto_item_append_text(sv_item,
				": %04X", tvb_get_ntohs(tvb, svoff+2) );
			break;

		case 0x2B: /* Group Address */
			if (sv_length != 6 && sv_length != 8) {
				expert_add_info_format(pinfo, len_item, PI_MALFORMED, PI_ERROR,
				    "Subvector length is != 6 and != 8");
				break;
			}
			if (sv_length == 6) {
				proto_tree_add_text(sv_tree, tvb, svoff+2, sv_length-2,
					"Group Address: %08X", tvb_get_ntohl(tvb, svoff+2) );
				proto_item_append_text(sv_item,
					": %08X", tvb_get_ntohl(tvb, svoff+2) );
			} else {
				proto_tree_add_text(sv_tree, tvb, svoff+2, sv_length-2,
					"Group Address: %s",
					tvb_ether_to_str(tvb, svoff+2));
				proto_item_append_text(sv_item,
					": %s",
					tvb_ether_to_str(tvb, svoff+2));
			}
			break;

		case 0x2C: /* Functional Addresses */
			if (sv_length != 6) {
				expert_add_info_format(pinfo, len_item, PI_MALFORMED, PI_ERROR,
				    "Subvector length is != 6");
				break;
			}
			proto_tree_add_text(sv_tree, tvb, svoff+2, sv_length-2,
				"Functional Addresses: %08X", tvb_get_ntohl(tvb, svoff+2) );
			proto_item_append_text(sv_item,
				": %08X", tvb_get_ntohl(tvb, svoff+2) );
			break;

		case 0x2D: /* Isolating Error Counts */
			if (sv_length != 8) {
				expert_add_info_format(pinfo, len_item, PI_MALFORMED, PI_ERROR,
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
				expert_add_info_format(pinfo, len_item, PI_MALFORMED, PI_ERROR,
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
				expert_add_info_format(pinfo, len_item, PI_MALFORMED, PI_ERROR,
				    "Subvector length is != 4");
				break;
			}
			proto_tree_add_text(sv_tree, tvb, svoff+2, sv_length-2,
				"Error Code: %04X", tvb_get_ntohs(tvb, svoff+2) );
			proto_item_append_text(sv_item,
				": %04X", tvb_get_ntohs(tvb, svoff+2) );
			break;

		default: /* Unknown */
			proto_tree_add_text(sv_tree, tvb, svoff+2, sv_length-2,
				"Unknown Subvector");
			break;
	}
	return sv_length;
}

static void
dissect_trmac(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*mac_tree = NULL;
	proto_item	*ti;
	int		mv_length, sv_offset, sv_additional;
	guint8		mv_val;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "TR MAC");
	col_clear(pinfo->cinfo, COL_INFO);

	mv_val = tvb_get_guint8(tvb, 3);

	/* Interpret the major vector */
	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_str(pinfo->cinfo, COL_INFO,
		    val_to_str(mv_val, major_vector_vs, "Unknown Major Vector: %u"));

	if (tree) {
		mv_length = tvb_get_ntohs(tvb, 0);
		ti = proto_tree_add_item(tree, proto_trmac, tvb, 0, mv_length, ENC_NA);
		mac_tree = proto_item_add_subtree(ti, ett_tr_mac);

		proto_tree_add_uint(mac_tree, hf_trmac_mv, tvb, 3, 1, mv_val);
		proto_tree_add_uint_format(mac_tree, hf_trmac_length, tvb, 0, 2, mv_length,
				"Total Length: %d bytes", mv_length);
		proto_tree_add_uint(mac_tree, hf_trmac_srcclass, tvb, 2, 1, tvb_get_guint8(tvb, 2) & 0x0f);
		proto_tree_add_uint(mac_tree, hf_trmac_dstclass, tvb, 2, 1, tvb_get_guint8(tvb, 2) >> 4 );

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
	}
}

void
proto_register_trmac(void)
{
        static hf_register_info hf[] = {
                { &hf_trmac_mv,
                { "Major Vector",			"trmac.mvec", FT_UINT8, BASE_HEX, major_vector_vs, 0x0,
			NULL, HFILL }},

                { &hf_trmac_length,
                { "Total Length",			"trmac.length", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

                { &hf_trmac_srcclass,
                { "Source Class",			"trmac.srcclass", FT_UINT8, BASE_HEX, classes_vs, 0x0,
			NULL, HFILL }},

                { &hf_trmac_dstclass,
                { "Destination Class",			"trmac.dstclass", FT_UINT8, BASE_HEX, classes_vs, 0x0,
			NULL, HFILL }},

                { &hf_trmac_sv_len,
                { "Subvector Length",			"trmac.svec.len", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

                { &hf_trmac_sv_id,
                { "Subvector Identifier",		"trmac.svec.id", FT_UINT8, BASE_HEX, VALS(subvector_vs), 0x0,
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
        };
	static gint *ett[] = {
		&ett_tr_mac,
		&ett_tr_sv,
		&ett_tr_ierr_cnt,
		&ett_tr_nerr_cnt,
	};

        proto_trmac = proto_register_protocol("Token-Ring Media Access Control",
	    "TR MAC", "trmac");
	proto_register_field_array(proto_trmac, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("trmac", dissect_trmac, proto_trmac);
}
