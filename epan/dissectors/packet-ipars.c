/* packet-ipars.c
 * Routines for IPARS/ALC (International Passenger Airline Reservation System/Airline Link Control) WAN protocol dissection
 * Copyright 2007, Fulko Hew, SITA INC Canada, Inc.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* NOTE:    This should be rewritten to be more in line with how packet-uts.c is
 *          written so that there are filterable fields available for IPARS too.
 */

#include "config.h"

#include <epan/packet.h>
#include <wsutil/str_util.h>
void proto_register_ipars(void);

static int      proto_ipars;
static int      ett_ipars;

#define S1      (0x00)
#define S2      (0x20)
#define GA      (0x03)
#define EOMpb   (0x10)
#define EOMc    (0x11)
#define EOMu    (0x12)
#define EOMi    (0x13)

#define MAX_EOM_MSG_SIZE    (24)            /* max size of an EOMx indicator string */

static int
dissect_ipars(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int       bytes;
    uint8_t   ia     = 0, ta = 0, cmd = 0, la = 0;
    tvbuff_t *next_tvb;
    int       offset = 0;
    char     *eom_msg;
    uint8_t   ipars_eomtype;

    eom_msg    = (char *)wmem_alloc(pinfo->pool, MAX_EOM_MSG_SIZE);
    eom_msg[0] = 0;

    col_clear(pinfo->cinfo, COL_INFO);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPARS");

    if (tvb_captured_length_remaining(tvb, 0) >= 2 ) {
        ia = tvb_get_uint8(tvb, 0) & 0x3f;
        ta = tvb_get_uint8(tvb, 1) & 0x3f;
        if (ia == S1 && ta == S2) { /* if the first two bytes are S1/S2 skip over them */
            offset = 2;
        }
    }
    if (tvb_captured_length_remaining(tvb, offset) >= 1) ia = tvb_get_uint8(tvb, offset + 0);
    if (tvb_captured_length_remaining(tvb, offset) >= 2) ta = tvb_get_uint8(tvb, offset + 1);

    if (ia == 0x83 || ia == 0x43 || ia == GA) { /* if it's an FPGA or 'corresponsdance code' 'go ahead'... */
        if (tvb_captured_length_remaining(tvb, offset) > 2) { /* if the msg is long, it must have been a 'poll' */
            col_add_fstr(pinfo->cinfo, COL_INFO, "Poll IA: %2.2X", ta);
        } else { /* if it's short, then it was a 'no traffic' response */
            if (tvb_captured_length_remaining(tvb, offset) >= 2 ) {
                col_add_fstr(pinfo->cinfo, COL_INFO, "GoAhead NextIA (0x%2.2X)", ta);
            } else {
                col_set_str(pinfo->cinfo, COL_INFO, "GoAhead NextIA");
            }
        }
    } else { /* if it's not a 'go ahead'... it must be some kind of data message */
        ia &= 0x3f;
        ta &= 0x3f;
        if (ta == 0x20) {
            col_add_fstr(pinfo->cinfo, COL_INFO, "Reset IA: %2.2X", ia); /* the TA character was the 'reset' command */
        }
        if (tvb_captured_length_remaining(tvb, offset) >= 3) cmd = tvb_get_uint8(tvb, offset + 2) & 0x3f;   /* get the first two bytes of the data message */
        if (tvb_captured_length_remaining(tvb, offset) >= 4) la  = tvb_get_uint8(tvb, offset + 3) & 0x3f;
        if (cmd == 0x1f && la == 0x38) {
            col_add_fstr(pinfo->cinfo, COL_INFO, "Please Resend - IA: %2.2X TA: %2.2X", ia, ta); /* light the resend indicator */
        } else if (cmd == 0x2a && la == 0x05) {
            col_add_fstr(pinfo->cinfo, COL_INFO, "Unsolicited Msg Indicator - IA: %2.2X TA: %2.2X", ia, ta);    /* light the unsolicited msg indicator */
        } else {
            col_add_fstr(pinfo->cinfo, COL_INFO, "Data Msg - IA: %2.2X TA: %2.2X", ia, ta); /* it was a data message (display or printer */
        }
    }

    bytes = tvb_captured_length_remaining(tvb, 0);
    if (bytes > 0) {
        proto_tree  *ipars_tree;
        proto_item  *ti;

        ia = tvb_get_uint8(tvb, 0) & 0x3f;

        ti = proto_tree_add_protocol_format(tree, proto_ipars, tvb, 0, -1, "Ipars");
        ipars_tree = proto_item_add_subtree(ti, ett_ipars);

        if (ia == 0x03) {
            proto_tree_add_protocol_format(ipars_tree, proto_ipars, tvb, 0, 1, "GoAhead Next IA");
            col_set_str(pinfo->cinfo, COL_INFO, "GoAhead");
            return tvb_captured_length(tvb);
        } else if (ia != S1) {
            proto_tree_add_protocol_format(ipars_tree, proto_ipars, tvb,
                0,
                bytes, "Unknown format - Data (%d byte%s)", bytes,
                plurality(bytes, "", "s"));
            return tvb_captured_length(tvb);
        }
        proto_tree_add_protocol_format(ipars_tree, proto_ipars, tvb, 0, 1, "S1");
        ia = tvb_get_uint8(tvb, 1) & 0x3f;
        if (ia != S2) {
            proto_tree_add_protocol_format(ipars_tree, proto_ipars, tvb,
                0,
                bytes, "Unknown format - Data (%d byte%s)", bytes,
                plurality(bytes, "", "s"));
                return tvb_captured_length(tvb);
        }
        proto_tree_add_protocol_format(ipars_tree, proto_ipars, tvb, 1, 1, "S2");
        ia = tvb_get_uint8(tvb, 2) & 0x3f;
        if (ia == GA) {
            ia = tvb_get_uint8(tvb, 3) & 0x3f;
            proto_tree_add_protocol_format(ipars_tree, proto_ipars, tvb, 2, 2, "GoAhead IA: %2.2X", ia);
            ipars_eomtype = tvb_get_uint8(tvb, 4) & 0x3f;
            switch (ipars_eomtype) {
                case EOMc:  snprintf(eom_msg, MAX_EOM_MSG_SIZE, "EOMc");                              break;
                case EOMi:  snprintf(eom_msg, MAX_EOM_MSG_SIZE, "EOMi");                              break;
                case EOMu:  snprintf(eom_msg, MAX_EOM_MSG_SIZE, "EOMu");                              break;
                case EOMpb: snprintf(eom_msg, MAX_EOM_MSG_SIZE, "EOMpb");                             break;
                default:    snprintf(eom_msg, MAX_EOM_MSG_SIZE, "Unknown EOM type (0x%2.2X)", ia);    break;
            }
            proto_tree_add_protocol_format(ipars_tree, proto_ipars, tvb, 4, 1, "%s", eom_msg);
            proto_tree_add_protocol_format(ipars_tree, proto_ipars, tvb, 5, 1, "Good BCC");
        } else {
            next_tvb = tvb_new_subset_remaining(tvb, 3);
            proto_tree_add_protocol_format(ipars_tree, proto_ipars, next_tvb,
                0,
                bytes, "Data (%d byte%s)", bytes,
                plurality(bytes, "", "s"));
            return tvb_captured_length(tvb);
        }
    }
    return tvb_captured_length(tvb);
}

void
proto_register_ipars(void)
{
    static int *ett[] = {
        &ett_ipars,
    };

    proto_ipars = proto_register_protocol("International Passenger Airline Reservation System", "IPARS", "ipars");
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("ipars", dissect_ipars, proto_ipars);
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
