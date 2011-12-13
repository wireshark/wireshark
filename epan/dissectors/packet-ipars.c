/* packet-ipars.c
 * Routines for IPARS/ALC (International Passenger Airline Reservation System/Airline Link Control) WAN protocol dissection
 * Copyright 2007, Fulko Hew, SITA INC Canada, Inc.
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

/* NOTE:	This should be rewritten to be more in line with how packet-uts.c is
 *			written so that there are filterable fields available for IPARS too.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/emem.h>

static int      proto_ipars     = -1;
static guint8   ipars_eomtype   = G_MAXUINT8;
static gint     ett_ipars       = -1;

#define S1      (0x00)
#define S2      (0x20)
#define GA      (0x03)
#define EOMpb   (0x10)
#define EOMc    (0x11)
#define EOMu    (0x12)
#define EOMi    (0x13)

#define MAX_EOM_MSG_SIZE    (16)            /* max size of an EOMx indicator string */

static void
dissect_ipars(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree)
{
    proto_tree  *ipars_tree = NULL;
    proto_item  *ti;
    int         bytes;
    guint8      ia = 0, ta = 0, cmd = 0, la = 0;
    tvbuff_t    *next_tvb;
    int         offset = 0;
    gchar       *eom_msg;

    eom_msg = ep_alloc(MAX_EOM_MSG_SIZE);
    eom_msg[0] = 0;

    col_clear(pinfo->cinfo, COL_INFO);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPARS");

    if (tvb_length_remaining(tvb, 0) >= 2 ) {
        ia = tvb_get_guint8(tvb, 0) & 0x3f;
        ta = tvb_get_guint8(tvb, 1) & 0x3f;
        if (ia == S1 && ta == S2) { /* if the first two bytes are S1/S2 skip over them */
            offset = 2;
        }
    }
    if (tvb_length_remaining(tvb, offset) >= 1) ia = tvb_get_guint8(tvb, offset + 0);
    if (tvb_length_remaining(tvb, offset) >= 2) ta = tvb_get_guint8(tvb, offset + 1);

    if (ia == 0x83 || ia == 0x43 || ia == GA) { /* if its an FPGA or 'corresponsdance code' 'go ahead'... */
        if (tvb_length_remaining(tvb, offset) > 2) { /* if the msg is long, it must have been a 'poll' */
            if (check_col(pinfo->cinfo, COL_INFO))
                col_add_fstr(pinfo->cinfo, COL_INFO, "Poll IA: %2.2X", ta);
        } else { /* if its short, then it was a 'no traffic' response */
            if (tvb_length_remaining(tvb, offset) >= 2 ) {
                if (check_col(pinfo->cinfo, COL_INFO))
                    col_add_fstr(pinfo->cinfo, COL_INFO, "GoAhead NextIA (0x%2.2X)", ta);
            } else {
                if (check_col(pinfo->cinfo, COL_INFO))
                    col_set_str(pinfo->cinfo, COL_INFO, "GoAhead NextIA");
            }
        }
    } else { /* if its not a 'go ahead'... it must be some kind of data message */
        ia &= 0x3f;
        ta &= 0x3f;
        if (ta == 0x20) {
            if (check_col(pinfo->cinfo, COL_INFO))
                col_add_fstr(pinfo->cinfo, COL_INFO, "Reset IA: %2.2X", ia); /* the TA character was the 'reset' command */
        }
        if (tvb_length_remaining(tvb, offset) >= 3) cmd = tvb_get_guint8(tvb, offset + 2) & 0x3f;   /* get the first two bytes of the data message */
        if (tvb_length_remaining(tvb, offset) >= 4) la  = tvb_get_guint8(tvb, offset + 3) & 0x3f;
        if (cmd == 0x1f && la == 0x38) {
            if (check_col(pinfo->cinfo, COL_INFO))
                col_add_fstr(pinfo->cinfo, COL_INFO, "Please Resend - IA: %2.2X TA: %2.2X", ia, ta); /* light the resend indicator */
        } else if (cmd == 0x2a && la == 0x05) {
            if (check_col(pinfo->cinfo, COL_INFO))
                col_add_fstr(pinfo->cinfo, COL_INFO, "Unsolicited Msg Indicator - IA: %2.2X TA: %2.2X", ia, ta);    /* light the unsolicited msg indicator */
        } else {
            if (check_col(pinfo->cinfo, COL_INFO))
                col_add_fstr(pinfo->cinfo, COL_INFO, "Data Msg - IA: %2.2X TA: %2.2X", ia, ta); /* it was a data message (display or printer */
        }
    }

    if (tree) {
        bytes = tvb_length_remaining(tvb, 0);
        if (bytes > 0) {
            ia = tvb_get_guint8(tvb, 0) & 0x3f;

            ti = proto_tree_add_protocol_format(tree, proto_ipars, tvb, 0, -1, "Ipars");
            ipars_tree = proto_item_add_subtree(ti, ett_ipars);

            if (ia == 0x03) {
                proto_tree_add_protocol_format(ipars_tree, proto_ipars, tvb, 0, 1, "GoAhead Next IA");
                if (check_col(pinfo->cinfo, COL_INFO))
                    col_set_str(pinfo->cinfo, COL_INFO, "GoAhead");
                return;
            } else if (ia != S1) {
                proto_tree_add_protocol_format(ipars_tree, proto_ipars, tvb,
                    0,
                    bytes, "Unknown format - Data (%d byte%s)", bytes,
                    plurality(bytes, "", "s"));
                return;
            }
            proto_tree_add_protocol_format(ipars_tree, proto_ipars, tvb, 0, 1, "S1");
            ia = tvb_get_guint8(tvb, 1) & 0x3f;
            if (ia != S2) {
                proto_tree_add_protocol_format(ipars_tree, proto_ipars, tvb,
                    0,
                    bytes, "Unknown format - Data (%d byte%s)", bytes,
                    plurality(bytes, "", "s"));
                return;
            }
            proto_tree_add_protocol_format(ipars_tree, proto_ipars, tvb, 1, 1, "S2");
            ia = tvb_get_guint8(tvb, 2) & 0x3f;
            if (ia == GA) {
                ia = tvb_get_guint8(tvb, 3) & 0x3f;
                proto_tree_add_protocol_format(ipars_tree, proto_ipars, tvb, 2, 2, "GoAhead IA: %2.2X", ia);
                ipars_eomtype = tvb_get_guint8(tvb, 4) & 0x3f;
                switch (ipars_eomtype) {
                    case EOMc:  g_snprintf(eom_msg, MAX_EOM_MSG_SIZE, "EOMc");                              break;
                    case EOMi:  g_snprintf(eom_msg, MAX_EOM_MSG_SIZE, "EOMi");                              break;
                    case EOMu:  g_snprintf(eom_msg, MAX_EOM_MSG_SIZE, "EOMu");                              break;
                    case EOMpb: g_snprintf(eom_msg, MAX_EOM_MSG_SIZE, "EOMpb");                             break;
                    default:    g_snprintf(eom_msg, MAX_EOM_MSG_SIZE, "Unknown EOM type (0x%2.2X)", ia);    break;
                }
                proto_tree_add_protocol_format(ipars_tree, proto_ipars, tvb, 4, 1, "%s", eom_msg);
                ia = tvb_get_guint8(tvb, 5) & 0x3f;
                proto_tree_add_protocol_format(ipars_tree, proto_ipars, tvb, 5, 1, "Good BCC");
            } else {
                next_tvb = tvb_new_subset_remaining(tvb, 3);
                proto_tree_add_protocol_format(ipars_tree, proto_ipars, next_tvb,
                    0,
                    bytes, "Data (%d byte%s)", bytes,
                    plurality(bytes, "", "s"));
                return;

            }
        }
    }
}

void
proto_register_ipars(void)
{
    static gint *ett[] = {
        &ett_ipars,
    };

    proto_ipars = proto_register_protocol("International Passenger Airline Reservation System", "IPARS", "ipars");
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("ipars", dissect_ipars, proto_ipars);
}
