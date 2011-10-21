/* packet-aruba-erm.c
 * Routines for the disassembly of Aruba encapsulated remote mirroring frames
 * (Adapted from packet-hp-erm.c and packet-cisco-erspan.c)
 *
 * $Id$
 *
 * Copyright 2010  Alexis La Goutte <alexis.lagoutte at gmail dot com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/*
 * Format:
 *  Use the Header of Record (Packet) Header
 *
 * typedef struct pcaprec_hdr_s {
 *       guint32 ts_sec;          timestamp seconds
 *       guint32 ts_usec;         timestamp microseconds
 *       guint32 incl_len;        number of octets of packet saved in file
 *       guint32 orig_len;        actual length of packet
 * } pcaprec_hdr_t;
 *
 * Following with 802.11 header
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>

#define PROTO_SHORT_NAME "ARUBA_ERM"
#define PROTO_LONG_NAME  "ARUBA encapsulated remote mirroring"

static range_t *global_aruba_erm_port_range;

static int  proto_aruba_erm       = -1;

static int  hf_aruba_erm_time     = -1;
static int  hf_aruba_erm_incl_len = -1;
static int  hf_aruba_erm_orig_len = -1;

static gint ett_aruba_erm         = -1;

static dissector_handle_t aruba_erm_handle;
static dissector_handle_t ieee80211_handle;

static void
dissect_aruba_erm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *aruba_erm_tree;
    tvbuff_t   *eth_tvb;
    nstime_t ts;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_SHORT_NAME);
    col_set_str(pinfo->cinfo, COL_INFO, PROTO_SHORT_NAME ":");

    if (tree) {
        ti = proto_tree_add_item(tree, proto_aruba_erm, tvb, 0, -1, ENC_NA);
        aruba_erm_tree = proto_item_add_subtree(ti, ett_aruba_erm);

        ts.secs = tvb_get_ntohl(tvb, 0);
        ts.nsecs = tvb_get_ntohl(tvb,4)*1000;
        proto_tree_add_time(aruba_erm_tree, hf_aruba_erm_time, tvb, 0, 8,&ts);
        proto_tree_add_item(aruba_erm_tree, hf_aruba_erm_incl_len, tvb, 8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(aruba_erm_tree, hf_aruba_erm_orig_len, tvb, 12, 4, ENC_BIG_ENDIAN);
    }

    eth_tvb = tvb_new_subset_remaining(tvb, 16);
    call_dissector(ieee80211_handle, eth_tvb, pinfo, tree);
}

void
proto_register_aruba_erm(void)
{
    void proto_reg_handoff_aruba_erm(void);

    static hf_register_info hf[] = {

        { &hf_aruba_erm_time,
          { "Packet Capture Timestamp", "aruba_erm.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL,
            0x00, NULL, HFILL }},
        { &hf_aruba_erm_incl_len,
          { "Packet Captured Length", "aruba_erm.incl_len", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL }},
        { &hf_aruba_erm_orig_len,
          { "Packet Length", "aruba_erm.orig_len", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_aruba_erm,
    };

    module_t *aruba_erm_module;

    proto_aruba_erm = proto_register_protocol(PROTO_LONG_NAME, PROTO_SHORT_NAME, "aruba_erm");

    range_convert_str (&global_aruba_erm_port_range, "0", MAX_UDP_PORT);
    aruba_erm_module = prefs_register_protocol(proto_aruba_erm, proto_reg_handoff_aruba_erm);
    prefs_register_range_preference(aruba_erm_module, "udp.ports", "ARUBA_ERM UDP Port numbers",
                                    "Set the UDP port numbers (by default is range 5555 to 5560) used for ARUBA"
                                    " encapsulated remote mirroring frames;\n"
                                    "0 (default) means that the ARUBA_ERM dissector is not active\n",
                                    &global_aruba_erm_port_range, MAX_UDP_PORT);

    proto_register_field_array(proto_aruba_erm, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

static void range_delete_callback (guint32 port)
{
    dissector_delete_uint("udp.port", port, aruba_erm_handle);
}

static void range_add_callback (guint32 port)
{
    dissector_add_uint("udp.port", port, aruba_erm_handle);
}

void
proto_reg_handoff_aruba_erm(void)
{
    static range_t *aruba_erm_port_range;
    static gboolean initialized = FALSE;

    if (!initialized) {
        ieee80211_handle = find_dissector("wlan");
        aruba_erm_handle = create_dissector_handle(dissect_aruba_erm, proto_aruba_erm);
        initialized = TRUE;
    } else {
        range_foreach(aruba_erm_port_range, range_delete_callback);
        g_free(aruba_erm_port_range);
    }

    aruba_erm_port_range = range_copy(global_aruba_erm_port_range);

    range_foreach(aruba_erm_port_range, range_add_callback);
}

