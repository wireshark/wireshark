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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/to_str.h>

#include <wsutil/epochs.h>

void proto_reg_handoff_time(void);
void proto_register_time(void);

static dissector_handle_t time_handle;

static const enum_val_t time_display_types[] = {
    { "UTC", "UTC", ABSOLUTE_TIME_UTC },
    { "Local", "Local", ABSOLUTE_TIME_LOCAL},
    { NULL, NULL, 0 }
};

static int proto_time;
static int hf_time_time;
static int hf_time_response;

static int ett_time;

/* Use int instead of a field_display_type_e enum to avoid incompatible
 * pointer type warnings with prefs_register_enum_preference() */
static int time_display_type = ABSOLUTE_TIME_LOCAL;

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
        uint32_t delta_seconds = tvb_get_ntohl(tvb, 0);
        proto_tree_add_uint_format(time_tree, hf_time_time, tvb, 0, 4,
                delta_seconds, "%s",
                abs_time_secs_to_str(pinfo->pool, delta_seconds-EPOCH_DELTA_1900_01_01_00_00_00_UTC,
                                        time_display_type, true));
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

    static int *ett[] = {
        &ett_time,
    };

    module_t *time_pref ;

    proto_time = proto_register_protocol("Time Protocol", "TIME", "time");
    proto_register_field_array(proto_time, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    time_handle = register_dissector("time", dissect_time, proto_time);

    time_pref = prefs_register_protocol(proto_time, NULL);
    prefs_register_enum_preference(time_pref,
            "display_time_type",
            "Time Display",
            "Time display type",
            &time_display_type,
            time_display_types,
            false);
}

void
proto_reg_handoff_time(void)
{
    dissector_add_uint_with_preference("udp.port", TIME_PORT, time_handle);
    dissector_add_uint_with_preference("tcp.port", TIME_PORT, time_handle);
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
