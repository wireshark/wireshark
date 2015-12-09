/* packet-time.c
 * Routines for Time Protocol (RFC 868) packet dissection
 *
 * Richard Sharpe <rsharpe@ns.aus.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
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

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/to_str.h>

void proto_reg_handoff_time(void);
void proto_register_time(void);

static const enum_val_t time_display_types[] = {
    { "UTC", "UTC", ABSOLUTE_TIME_UTC },
    { "Local", "Local", ABSOLUTE_TIME_LOCAL},
    { NULL, NULL, 0 }
};

static int proto_time = -1;
static int hf_time_time = -1;
static int hf_time_response = -1;

static gint ett_time = -1;
/* Instead of using absolute_time_display_e as the type for
 * time_display_type, we use gint to avoid a type-punning problem
 * with prefs_register_enum_preference(). This variable is also
 * used with abs_time_secs_to_ep_str(), which _does_ take
 * an absolute_time_display_e, but gcc doesn't complain about
 * casting the gint to absolute_time_display_e */
static gint time_display_type = ABSOLUTE_TIME_LOCAL;

/* This dissector works for TCP and UDP time packets */
#define TIME_PORT 37

static int
dissect_time(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree    *time_tree;
    proto_item    *ti;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TIME");

    col_add_fstr(pinfo->cinfo, COL_INFO, "TIME %s",
            pinfo->srcport == pinfo->match_uint ? "Response":"Request");

    ti = proto_tree_add_item(tree, proto_time, tvb, 0, -1, ENC_NA);
    time_tree = proto_item_add_subtree(ti, ett_time);

    proto_tree_add_boolean(time_tree, hf_time_response, tvb, 0, 0, pinfo->srcport==pinfo->match_uint);
    if (pinfo->srcport == pinfo->match_uint) {
        /* seconds since 1900-01-01 00:00:00 GMT, *not* 1970 */
        guint32 delta_seconds = tvb_get_ntohl(tvb, 0);
        proto_tree_add_uint_format(time_tree, hf_time_time, tvb, 0, 4,
                delta_seconds, "%s",
                abs_time_secs_to_str(wmem_packet_scope(), delta_seconds-2208988800U,
                    (absolute_time_display_e)time_display_type, TRUE));
    }
    return tvb_captured_length(tvb);
}

void
proto_register_time(void)
{
    static hf_register_info hf[] = {
        { &hf_time_time,
            { "Time", "time.time",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Seconds since 00:00 (midnight) 1 January 1900 GMT", HFILL }},
        { &hf_time_response,
            { "Type", "time.response",
                FT_BOOLEAN, BASE_NONE, TFS(&tfs_response_request), 0x0,
                "Response or Request", HFILL }}
    };

    static gint *ett[] = {
        &ett_time,
    };

    module_t *time_pref ;

    proto_time = proto_register_protocol("Time Protocol", "TIME", "time");
    proto_register_field_array(proto_time, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    time_pref = prefs_register_protocol(proto_time, NULL);
    prefs_register_enum_preference(time_pref,
            "display_time_type",
            "Time Display",
            "Time display type",
            (gint *)&time_display_type,
            time_display_types,
            FALSE);
}

void
proto_reg_handoff_time(void)
{
    dissector_handle_t time_handle;

    time_handle = create_dissector_handle(dissect_time, proto_time);
    dissector_add_uint("udp.port", TIME_PORT, time_handle);
    dissector_add_uint("tcp.port", TIME_PORT, time_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
