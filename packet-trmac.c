/* packet-trmac.c
 * Routines for Token-Ring Media Access Control
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
 *
 * $Id: packet-trmac.c,v 1.17 1999/11/16 11:43:01 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
 * Copyright 1998 Gerald Combs
 *
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <glib.h>
#include "packet.h"

static int proto_trmac = -1;
static int hf_trmac_mv = -1;
static int hf_trmac_length = -1;
static int hf_trmac_srcclass = -1;
static int hf_trmac_dstclass = -1;
static int hf_trmac_sv = -1;
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
static gint ett_tr_ierr_cnt = -1;
static gint ett_tr_nerr_cnt = -1;

/* Major Vector */
static value_string major_vector_vs[] = {
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
static value_string classes_vs[] = {
	{ 0x00, "Ring Station" },
	{ 0x01, "LLC Manager" },
	{ 0x04, "Configuration Report Server" },
	{ 0x05, "Ring Parameter Server" },
	{ 0x06, "Ring Error Monitor" },
	{ 0x00, NULL }
};


/* Sub-vectors */
static int
sv_text(const u_char *pd, int pkt_offset, proto_tree *tree)
{
	int	sv_length = pd[0];
	guint16	beacon_type;

	char *beacon[] = {"Recovery mode set", "Signal loss error",
		"Streaming signal not Claim Token MAC frame",
		"Streaming signal, Claim Token MAC frame"};

	proto_tree	*sv_tree;
	proto_item	*ti;

	u_char		errors[6];	/* isolating or non-isolating */

	/* this just adds to the clutter on the screen...
	proto_tree_add_text(tree, pkt_offset, 1,
		"Subvector Length: %d bytes", sv_length);*/

	proto_tree_add_item_hidden(tree, hf_trmac_sv, pkt_offset+1, 1, pd[1]);

	switch(pd[1]) {
		case 0x01: /* Beacon Type */
			beacon_type = pntohs(&pd[2]);
			if (beacon_type < array_length(beacon)) {
				proto_tree_add_text(tree, pkt_offset+1, sv_length-1,
					"Beacon Type: %s", beacon[beacon_type] );
			} else {
				proto_tree_add_text(tree, pkt_offset+1, sv_length-1,
					"Beacon Type: Illegal value: %d", beacon_type );
			}
			break;

		case 0x02: /* NAUN */
			proto_tree_add_item(tree, hf_trmac_naun, pkt_offset+1, sv_length-1, (guint8*)&pd[2]);
			break;

		case 0x03: /* Local Ring Number */
			proto_tree_add_text(tree, pkt_offset+1, sv_length-1,
				"Local Ring Number: 0x%04X (%d)",
				pntohs( &pd[2] ), pntohs( &pd[2] ));
			break;

		case 0x04: /* Assign Physical Location */
			proto_tree_add_text(tree, pkt_offset+1, sv_length-1,
				"Assign Physical Location: 0x%08X", pntohl( &pd[2] ) );
			break;

		case 0x05: /* Soft Error Report Value */
			proto_tree_add_text(tree, pkt_offset+1, sv_length-1,
				"Soft Error Report Value: %d ms", 10 * pntohs( &pd[2] ) );
			break;

		case 0x06: /* Enabled Function Classes */
			proto_tree_add_text(tree, pkt_offset+1, sv_length-1,
				"Enabled Function Classes: %04X",  pntohs( &pd[2] ) );
			break;

		case 0x07: /* Allowed Access Priority */
			proto_tree_add_text(tree, pkt_offset+1, sv_length-1,
				"Allowed Access Priority: %04X",  pntohs( &pd[2] ) );
			break;

		case 0x09: /* Correlator */
			proto_tree_add_text(tree, pkt_offset+1, sv_length-1,
				"Correlator: %04X",  pntohs( &pd[2] ) );
			break;

		case 0x0A: /* Address of last neighbor notification */
			proto_tree_add_text(tree, pkt_offset+1, sv_length-1,
				"Address of Last Neighbor Notification: %s",
				ether_to_str((guint8*)&pd[2]));
			break;

		case 0x0B: /* Physical Location */
			proto_tree_add_text(tree, pkt_offset+1, sv_length-1,
				"Physical Location: 0x%08X", pntohl( &pd[2] ) );
			break;

		case 0x20: /* Response Code */
			proto_tree_add_text(tree, pkt_offset+1, sv_length-1,
				"Response Code: 0x%04X 0x%04X", pntohl( &pd[2] ),
				pntohl( &pd[4] ) );
			break;

		case 0x21: /* Reserved */
			proto_tree_add_text(tree, pkt_offset+1, sv_length-1,
				"Reserved: 0x%04X", pntohs( &pd[2] ) );
			break;

		case 0x22: /* Product Instance ID */
			proto_tree_add_text(tree, pkt_offset+1, sv_length-1,
				"Product Instance ID: ...");
			break;

		case 0x23: /* Ring Station Microcode Level */
			proto_tree_add_text(tree, pkt_offset+1, sv_length-1,
				"Ring Station Microcode Level: ...");
			break;

		case 0x26: /* Wrap data */
			proto_tree_add_text(tree, pkt_offset+1, sv_length-1,
				"Wrap Data: ... (%d bytes)", sv_length - 2);
			break;

		case 0x27: /* Frame Forward */
			proto_tree_add_text(tree, pkt_offset+1, sv_length-1,
				"Frame Forward: ... (%d bytes)", sv_length - 2);
			break;

		case 0x29: /* Ring Station Status Subvector */
			proto_tree_add_text(tree, pkt_offset+1, sv_length-1,
				"Ring Station Status Subvector: ...");
			break;

		case 0x2A: /* Transmit Status Code */
			proto_tree_add_text(tree, pkt_offset+1, sv_length-1,
				"Transmit Status Code: %04X", pntohs( &pd[2] ) );
			break;

		case 0x2B: /* Group Address */
			proto_tree_add_text(tree, pkt_offset+1, sv_length-1,
				"Group Address: %08X", pntohl( &pd[2] ) );
			break;

		case 0x2C: /* Functional Address */
			proto_tree_add_text(tree, pkt_offset+1, sv_length-1,
				"Functional Address: %08X", pntohl( &pd[2] ) );
			break;

		case 0x2D: /* Isolating Error Counts */
			memcpy(errors, &pd[2], 6);
			ti = proto_tree_add_item(tree, hf_trmac_errors_iso, pkt_offset+1, sv_length-1,
				errors[0] + errors[1] + errors[2] + errors[3] + errors[4]);
			sv_tree = proto_item_add_subtree(ti, ett_tr_ierr_cnt);

			proto_tree_add_item(sv_tree, hf_trmac_errors_line, pkt_offset+2, 1, errors[0]);
			proto_tree_add_item(sv_tree, hf_trmac_errors_internal, pkt_offset+3, 1, errors[1]);
			proto_tree_add_item(sv_tree, hf_trmac_errors_burst, pkt_offset+4, 1, errors[2]);
			proto_tree_add_item(sv_tree, hf_trmac_errors_ac, pkt_offset+5, 1, errors[3]);
			proto_tree_add_item(sv_tree, hf_trmac_errors_abort, pkt_offset+6, 1, errors[4]);

			break;

		case 0x2E: /* Non-Isolating Error Counts */
			memcpy(errors, &pd[2], 6);
			ti = proto_tree_add_item(tree, hf_trmac_errors_noniso, pkt_offset+1, sv_length-1,
				errors[0] + errors[1] + errors[2] + errors[3] + errors[4]);
			sv_tree = proto_item_add_subtree(ti, ett_tr_nerr_cnt);

			proto_tree_add_item(sv_tree, hf_trmac_errors_lost, pkt_offset+2, 1, errors[0]);
			proto_tree_add_item(sv_tree, hf_trmac_errors_congestion, pkt_offset+3, 1, errors[1]);
			proto_tree_add_item(sv_tree, hf_trmac_errors_fc, pkt_offset+4, 1, errors[2]);
			proto_tree_add_item(sv_tree, hf_trmac_errors_freq, pkt_offset+5, 1, errors[3]);
			proto_tree_add_item(sv_tree, hf_trmac_errors_token, pkt_offset+6, 1, errors[4]);
			break;

		case 0x30: /* Error Code */
			proto_tree_add_text(tree, pkt_offset+1, sv_length-1,
				"Error Code: %04X", pntohs( &pd[2] ) );
			break;

		default: /* Unknown */
			proto_tree_add_text(tree, pkt_offset+1, 1,
				"Unknown Sub-Vector: 0x%02X", pd[1]);
	}
	return sv_length;
}

void
dissect_trmac(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

	proto_tree	*mac_tree = NULL;
	proto_item	*ti;
	int		mv_length, sv_length, sv_offset, sv_additional;
	guint8		mv_val;
	char		*mv_text;

	mv_val = pd[offset+3];
	mv_length = pntohs(&pd[offset]);

	/* Interpret the major vector */
	mv_text = val_to_str(mv_val, major_vector_vs, "Unknown Major Vector: %d\n");

	/* Summary information */
	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "TR MAC");
	if (check_col(fd, COL_INFO))
		col_add_str(fd, COL_INFO, mv_text);

	if (tree) {

		ti = proto_tree_add_item(tree, proto_trmac, offset, mv_length, NULL);
		mac_tree = proto_item_add_subtree(ti, ett_tr_mac);

		proto_tree_add_item(mac_tree, hf_trmac_mv, offset+3, 1, mv_val);
		proto_tree_add_item_format(mac_tree, hf_trmac_length, offset, 2, mv_length,
				"Total Length: %d bytes", mv_length);
		proto_tree_add_item(mac_tree, hf_trmac_srcclass, offset+2, 1, pd[offset+2] & 0x0f);
		proto_tree_add_item(mac_tree, hf_trmac_dstclass, offset+2, 1, pd[offset+2] >> 4 );

		/* interpret the subvectors */
		sv_offset = 0;
		offset += 4;
		sv_length = mv_length - 4;
		while (sv_offset < sv_length) {
			sv_additional = sv_text(&pd[offset + sv_offset], offset + sv_offset,
								mac_tree);

			/* if this is a bad packet, we could get a 0-length added here,
			 * looping forever */
			if (sv_additional)
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
			"" }},

                { &hf_trmac_length,
                { "Total Length",			"trmac.length", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},

                { &hf_trmac_srcclass,
                { "Source Class",			"trmac.srcclass", FT_UINT8, BASE_HEX, classes_vs, 0x0,
			"" }},

                { &hf_trmac_dstclass,
                { "Destination Class",			"trmac.dstclass", FT_UINT8, BASE_HEX, classes_vs, 0x0,
			"" }},

                { &hf_trmac_sv,
                { "Sub-Vector",				"trmac.svec", FT_UINT8, BASE_HEX, NULL, 0x0,
			"" }},

		{ &hf_trmac_errors_iso,
		{ "Isolating Errors",			"trmac.errors.iso", FT_UINT16, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_trmac_errors_line,
		{ "Line Errors",			"trmac.errors.line", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_trmac_errors_internal,
		{ "Internal Errors",			"trmac.errors.internal", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_trmac_errors_burst,
		{ "Burst Errors",			"trmac.errors.burst", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_trmac_errors_ac,
		{ "A/C Errors",				"trmac.errors.ac", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_trmac_errors_abort,
		{ "Abort Delimiter Transmitted Errors",	"trmac.errors.abort", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_trmac_errors_noniso,
		{ "Non-Isolating Errors",		"trmac.errors.noniso", FT_UINT16, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_trmac_errors_lost,
		{ "Lost Frame Errors",			"trmac.errors.lost", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_trmac_errors_congestion,
		{ "Receiver Congestion Errors",		"trmac.errors.congestion", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_trmac_errors_fc,
		{ "Frame-Copied Errors",		"trmac.errors.fc", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_trmac_errors_freq,
		{ "Frequency Errors",			"trmac.errors.freq", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_trmac_errors_token,
		{ "Token Errors",			"trmac.errors.token", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_trmac_naun,
		{ "NAUN",				"trmac.naun", FT_ETHER, BASE_DEC, NULL, 0x0,
			"" }},
        };
	static gint *ett[] = {
		&ett_tr_mac,
		&ett_tr_ierr_cnt,
		&ett_tr_nerr_cnt,
	};

        proto_trmac = proto_register_protocol("Token-Ring Media Access Control", "trmac");
	proto_register_field_array(proto_trmac, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
