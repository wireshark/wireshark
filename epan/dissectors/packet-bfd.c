/* packet-bfd.c
 * Routines for Bi-directional Fault Detection (BFD) message dissection
 *
 * Copyright 2003, Hannes Gredler <hannes@juniper.net>
 * Copyright 2006, Balint Reczey <Balint.Reczey@ericsson.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <string.h>
#include <glib.h>
#include <epan/packet.h>

#define UDP_PORT_BFD_CONTROL 3784 /* draft-katz-ward-bfd-v4v6-1hop-00.txt */

static const value_string bfd_control_v0_diag_values[] = {
    { 0, "No Diagnostic" },
    { 1, "Control Detection Time Expired" },
    { 2, "Echo Function Failed" },
    { 3, "Neighbor Signaled Session Down" },
    { 4, "Forwarding Plane Reset" },
    { 5, "Path Down" },
    { 6, "Concatenated Path Down" },
    { 7, "Administratively Down" },
    { 0, NULL }
};

static const value_string bfd_control_v1_diag_values[] = {
    { 0, "No Diagnostic" },
    { 1, "Control Detection Time Expired" },
    { 2, "Echo Function Failed" },
    { 3, "Neighbor Signaled Session Down" },
    { 4, "Forwarding Plane Reset" },
    { 5, "Path Down" },
    { 6, "Concatenated Path Down" },
    { 7, "Administratively Down" },
    { 8, "Reverse Concatenated Path Down" },
    { 0, NULL }
};

static const value_string bfd_control_sta_values[] = {
    { 0, "AdminDown" },
    { 1, "Down" },
    { 2, "Init" },
    { 3, "Up" },
    { 0, NULL }
};

static gint proto_bfd = -1;

static gint hf_bfd_version = -1;
static gint hf_bfd_diag = -1;
static gint hf_bfd_sta = -1;
static gint hf_bfd_flags = -1;
static gint hf_bfd_flags_h = -1;
static gint hf_bfd_flags_p = -1;
static gint hf_bfd_flags_f = -1;
static gint hf_bfd_flags_c = -1;
static gint hf_bfd_flags_a = -1;
static gint hf_bfd_flags_d = -1;
static gint hf_bfd_flags_d_v0 = -1;
static gint hf_bfd_detect_time_multiplier = -1;
static gint hf_bfd_my_discriminator = -1;
static gint hf_bfd_your_discriminator = -1;
static gint hf_bfd_desired_min_tx_interval = -1;
static gint hf_bfd_required_min_rx_interval = -1;
static gint hf_bfd_required_min_echo_interval = -1;

static gint ett_bfd = -1;
static gint ett_bfd_flags = -1;

/*
 * Control packet version 0, draft-katz-ward-bfd-01.txt
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |Vers |  Diag   |H|D|P|F| Rsvd  |  Detect Mult  |    Length     |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                       My Discriminator                        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                      Your Discriminator                       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                    Desired Min TX Interval                    |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                   Required Min RX Interval                    |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                 Required Min Echo RX Interval                 |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/*
 * Control packet version 1, draft-ietf-bfd-base-04.txt
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |Vers |  Diag   |Sta|P|F|C|A|D|R|  Detect Mult  |    Length     |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                       My Discriminator                        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                      Your Discriminator                       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                    Desired Min TX Interval                    |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                   Required Min RX Interval                    |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                 Required Min Echo RX Interval                 |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *    An optional Authentication Section may be present:
 *    Dissection is not implemented yet.
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |   Auth Type   |   Auth Len    |    Authentication Data...     |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 *                          
 */

static void dissect_bfd_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint bfd_version = -1;
    gint bfd_diag = -1;
    gint bfd_sta = -1;
    gint bfd_flags = -1;
    gint bfd_flags_h = -1;
    gint bfd_flags_p = -1;
    gint bfd_flags_f = -1;
    gint bfd_flags_c = -1;
    gint bfd_flags_a = -1;
    gint bfd_flags_d = -1;
    gint bfd_flags_d_v0 = -1;
    gint bfd_detect_time_multiplier = -1;
    gint bfd_length = -1;
    gint bfd_my_discriminator = -1;
    gint bfd_your_discriminator = -1;
    gint bfd_desired_min_tx_interval = -1;
    gint bfd_required_min_rx_interval = -1;
    gint bfd_required_min_echo_interval = -1;

    proto_item *ti;
    proto_tree *bfd_tree;
    proto_tree *bfd_flags_tree;
    
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "BFD Control");
    if (check_col(pinfo->cinfo, COL_INFO))
        col_clear(pinfo->cinfo, COL_INFO);

    bfd_version = ((tvb_get_guint8(tvb, 0) & 0xe0) >> 5);
    bfd_diag = (tvb_get_guint8(tvb, 0) & 0x1f);
    switch (bfd_version) {
    case 0:
	bfd_flags = tvb_get_guint8(tvb, 1 );
        bfd_flags_h = (tvb_get_guint8(tvb, 1) & 0x80);
        bfd_flags_d_v0 = (tvb_get_guint8(tvb, 1) & 0x40);
	break;
    case 1:
    default:
	bfd_sta = (tvb_get_guint8(tvb, 1) & 0xc0);
        bfd_flags = (tvb_get_guint8(tvb, 1) & 0x3e);
        bfd_flags_p = (tvb_get_guint8(tvb, 1) & 0x20);
        bfd_flags_f = (tvb_get_guint8(tvb, 1) & 0x10);
        bfd_flags_c = (tvb_get_guint8(tvb, 1) & 0x08);
        bfd_flags_a = (tvb_get_guint8(tvb, 1) & 0x04);
        bfd_flags_d = (tvb_get_guint8(tvb, 1) & 0x02);
	break;
    }
    bfd_detect_time_multiplier = tvb_get_guint8(tvb, 2);
    bfd_length = tvb_get_guint8(tvb, 3);

    bfd_my_discriminator = tvb_get_ntohl(tvb, 4);
    bfd_your_discriminator = tvb_get_ntohl(tvb, 8);
    bfd_desired_min_tx_interval = tvb_get_ntohl(tvb, 12);
    bfd_required_min_rx_interval = tvb_get_ntohl(tvb, 16);
    bfd_required_min_echo_interval = tvb_get_ntohl(tvb, 20);

    if (check_col(pinfo->cinfo, COL_INFO)) {
	switch (bfd_version) {
	case 0:
            col_add_fstr(pinfo->cinfo, COL_INFO, "Diag: %s, Flags: 0x%02x",
                     val_to_str(bfd_diag, bfd_control_v0_diag_values, "UNKNOWN"),
                     bfd_flags);
	    break;
	case 1:
	default:
            col_add_fstr(pinfo->cinfo, COL_INFO, "Diag: %s, State: %s, Flags: 0x%02x",
                     val_to_str(bfd_diag, bfd_control_v1_diag_values, "UNKNOWN"),
                     val_to_str(bfd_sta >> 6 , bfd_control_sta_values, "UNKNOWN"),
                     bfd_flags);
	    break;
	}
    }

    if (tree) {
        ti = proto_tree_add_protocol_format(tree, proto_bfd, tvb, 0, -1,
                                            "BFD Control message");

        bfd_tree = proto_item_add_subtree(ti, ett_bfd);

        ti = proto_tree_add_uint(bfd_tree, hf_bfd_version, tvb, 0,
                                 1, bfd_version << 5);

        ti = proto_tree_add_uint(bfd_tree, hf_bfd_diag, tvb, 0,
                                 1, bfd_diag);

	switch (bfd_version) {
	case 0:
	    break;
	case 1:
	default:
            ti = proto_tree_add_uint(bfd_tree, hf_bfd_sta, tvb, 1,
                                1, bfd_sta);
	    
	    break;
	}
	switch (bfd_version) {
	case 0:
            ti = proto_tree_add_text ( bfd_tree, tvb, 1, 1, "Message Flags: 0x%02x",
			               bfd_flags);
	    bfd_flags_tree = proto_item_add_subtree(bfd_tree, ett_bfd_flags);
	    ti =  proto_tree_add_boolean(bfd_flags_tree, hf_bfd_flags_h, tvb, 8, 1, bfd_flags_h);
	    ti =  proto_tree_add_boolean(bfd_flags_tree, hf_bfd_flags_d_v0, tvb, 8, 1, bfd_flags_d_v0);
	    break;
	case 1:
	default:
            ti = proto_tree_add_text ( bfd_tree, tvb, 1, 1, "Message Flags: 0x%02x",
			               bfd_flags);
	    bfd_flags_tree = proto_item_add_subtree(bfd_tree, ett_bfd_flags);
	    ti =  proto_tree_add_boolean(bfd_flags_tree, hf_bfd_flags_p, tvb, 6, 1, bfd_flags_p);
	    ti =  proto_tree_add_boolean(bfd_flags_tree, hf_bfd_flags_f, tvb, 6, 1, bfd_flags_f);
	    ti =  proto_tree_add_boolean(bfd_flags_tree, hf_bfd_flags_c, tvb, 6, 1, bfd_flags_c);
	    ti =  proto_tree_add_boolean(bfd_flags_tree, hf_bfd_flags_a, tvb, 6, 1, bfd_flags_a);
	    ti =  proto_tree_add_boolean(bfd_flags_tree, hf_bfd_flags_d, tvb, 6, 1, bfd_flags_d);
	    break;
	}

        ti = proto_tree_add_uint_format_value(bfd_tree, hf_bfd_detect_time_multiplier, tvb, 2,
                                              1, bfd_detect_time_multiplier,
                                              "%u (= %u ms Detection time)",
                                              bfd_detect_time_multiplier,
                                              bfd_detect_time_multiplier * bfd_desired_min_tx_interval/1000);

        ti = proto_tree_add_text ( bfd_tree, tvb, 3, 1, "Message Length: %u Bytes", bfd_length );
        
        ti = proto_tree_add_uint(bfd_tree, hf_bfd_my_discriminator, tvb, 4,
                                 4, bfd_my_discriminator);

        ti = proto_tree_add_uint(bfd_tree, hf_bfd_your_discriminator, tvb, 8,
                                 4, bfd_your_discriminator);

        ti = proto_tree_add_uint_format_value(bfd_tree, hf_bfd_desired_min_tx_interval, tvb, 12,
                                              4, bfd_desired_min_tx_interval,
                                              "%4u ms",
                                              bfd_desired_min_tx_interval/1000);

        ti = proto_tree_add_uint_format_value(bfd_tree, hf_bfd_required_min_rx_interval, tvb, 16,
                                              4, bfd_required_min_rx_interval,
                                              "%4u ms",
                                              bfd_required_min_rx_interval/1000);

        ti = proto_tree_add_uint_format_value(bfd_tree, hf_bfd_required_min_echo_interval, tvb, 20,
                                              4, bfd_required_min_echo_interval,
                                              "%4u ms",
                                              bfd_required_min_echo_interval/1000);

    }
    return;
}

/* Register the protocol with Wireshark */
void proto_register_bfd(void)
{

    /* Setup list of header fields */
    static hf_register_info hf[] = {
        { &hf_bfd_version,
          { "Protocol Version", "bfd.version",
            FT_UINT8, BASE_DEC, NULL , 0xe0,
            "", HFILL }
        },
        { &hf_bfd_diag,
          { "Diagnostic Code", "bfd.diag",
            FT_UINT8, BASE_HEX, VALS(bfd_control_v1_diag_values), 0x1f,
            "", HFILL }
        },
        { &hf_bfd_sta,
          { "Session State", "bfd.sta",
            FT_UINT8, BASE_HEX, VALS(bfd_control_sta_values), 0xc0,
            "", HFILL }
        },
        { &hf_bfd_flags,
          { "Message Flags", "bfd.flags",
            FT_UINT8, BASE_HEX, NULL, 0xf0,
            "", HFILL }
        },
        { &hf_bfd_flags_h,
          { "I hear you", "bfd.flags.h",
            FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x80,
            "", HFILL }
        },
        { &hf_bfd_flags_d_v0,
          { "Demand", "bfd.flags.d",
            FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x40,
            "", HFILL }
        },
        { &hf_bfd_flags_p,
          { "Poll", "bfd.flags.p",
            FT_BOOLEAN, 6, TFS(&flags_set_truth), 0x20,
            "", HFILL }
        },
        { &hf_bfd_flags_f,
          { "Final", "bfd.flags.f",
            FT_BOOLEAN, 6, TFS(&flags_set_truth), 0x10,
            "", HFILL }
        },
        { &hf_bfd_flags_c,
          { "Control Plane Independent", "bfd.flags.c",
            FT_BOOLEAN, 6, TFS(&flags_set_truth), 0x08,
            "", HFILL }
        },
        { &hf_bfd_flags_a,
          { "Authentication Present", "bfd.flags.a",
            FT_BOOLEAN, 6, TFS(&flags_set_truth), 0x04,
            "", HFILL }
        },
        { &hf_bfd_flags_d,
          { "Demand", "bfd.flags.d",
            FT_BOOLEAN, 6, TFS(&flags_set_truth), 0x02,
            "", HFILL }
        },
        { &hf_bfd_detect_time_multiplier,
          { "Detect Time Multiplier", "bfd.detect_time_multiplier",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "", HFILL }
        },
        { &hf_bfd_my_discriminator,
          { "My Discriminator", "bfd.my_discriminator",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "", HFILL }
        },
        { &hf_bfd_your_discriminator,
          { "Your Discriminator", "bfd.your_discriminator",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "", HFILL }
        },
        { &hf_bfd_desired_min_tx_interval,
          { "Desired Min TX Interval", "bfd.desired_min_tx_interval",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "", HFILL }
        },
        { &hf_bfd_required_min_rx_interval,
          { "Required Min RX Interval", "bfd.required_min_rx_interval",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "", HFILL }
        },
        { &hf_bfd_required_min_echo_interval,
          { "Required Min Echo Interval", "bfd.required_min_echo_interval",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "", HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_bfd,
        &ett_bfd_flags
    };

    /* Register the protocol name and description */
    proto_bfd = proto_register_protocol("Bi-directional Fault Detection Control Message",
                                        "BFD Control",
                                        "bfdcontrol");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_bfd, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_bfd(void)
{
    dissector_handle_t bfd_control_handle;

    bfd_control_handle = create_dissector_handle(dissect_bfd_control, proto_bfd);
    dissector_add("udp.port", UDP_PORT_BFD_CONTROL, bfd_control_handle);
}
