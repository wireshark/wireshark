/* packet-xcsl.c
 *
 * Routines for the Xcsl dissection (Call Specification Language)
 *
 * Copyright 2008, Dick Gooris (gooris@alcatel-lucent.com)
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include <epan/packet.h>

/* string array size */
#define MAXLEN 4096

/* Initialize the protocol and registered fields */
static int proto_xcsl = -1;
static int hf_xcsl_protocol_version = -1;
static int hf_xcsl_transaction_id = -1;
static int hf_xcsl_command = -1;
static int hf_xcsl_result = -1;
static int hf_xcsl_information = -1;
static int hf_xcsl_parameter = -1;

/* Initialize the subtree pointers */
static gint ett_xcsl = -1;

/* Xcsl result codes */
#define XCSL_SUCCESS      0
#define XCSL_UNKNOWN      1
#define XCSL_USRUNKN      2
#define XCSL_ERROR        3
#define XCSL_BUSY         4
#define XCSL_UNDEFINED    5
#define XCSL_MORE         6
#define XCSL_MAINT        7
#define XCSL_PROTSEQERR   8
#define XCSL_NONE         9

/* Result code meanings. */
static const value_string xcsl_action_vals[] = {
    { XCSL_SUCCESS,    "Success" },
    { XCSL_UNKNOWN,    "Unknown" },
    { XCSL_USRUNKN,    "User unknown" },
    { XCSL_ERROR,      "Error" },
    { XCSL_BUSY,       "Busy" },
    { XCSL_UNDEFINED,  "Undefined" },
    { XCSL_MORE,       "More" },
    { XCSL_MAINT,      "Maintenance" },
    { XCSL_PROTSEQERR, "Protocol Sequence Error" },
    { 0, NULL }
};

/* This routine gets the next item from the ';' separated list */
static gboolean get_next_item(tvbuff_t *tvb, gint offset, gint maxlen, guint8 *str, gint *next_offset, guint *len)
{
    guint  idx = 0;
    guint8 ch;

    /* Obtain items */
    while (maxlen > 1) {
        ch = tvb_get_guint8(tvb, offset+idx);
        if (ch == ';' || ch == '\r' || ch == '\n')
            break;
        /* Array protect */
        if (idx==MAXLEN) {
            *next_offset = offset + idx;
            *len = idx;
            return FALSE;
        }
        /* Copy data into string array */
        str[idx++] = ch;
        maxlen--;
    }
    /* Null terminate the item */
    str[idx] = '\0';

    /* Update admin for next item */
    *next_offset = offset + idx;
    *len = idx;

    return TRUE;
}

/* Dissector for xcsl */
static void dissect_xcsl_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {

    guint        offset = 0;
    gint         length_remaining;
    guint8       idx;
    gboolean     request;
    guint8       par;
    guint8       str[MAXLEN];
    guint8       result;
    const gchar *code;
    guint        len;
    gint         next_offset;
    proto_tree  *xcsl_tree = NULL;

    /* color support */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Xcsl");
    col_clear(pinfo->cinfo, COL_INFO);

    /* Create display tree for the xcsl protocol */
    if (tree) {
        proto_item  *xcsl_item;
        xcsl_item = proto_tree_add_item(tree, proto_xcsl, tvb, offset, -1, FALSE);
        xcsl_tree = proto_item_add_subtree(xcsl_item, ett_xcsl);
    }

    /* reset idx */
    idx = 0;

    /* reset the parameter count */
    par = 0;

    /* switch whether it concerns a command or an answer */
    request = FALSE;

    while (tvb_reported_length_remaining(tvb, offset) != 0) {

        length_remaining = tvb_ensure_length_remaining(tvb, offset);
        if ( length_remaining == -1 ) {
            return;
        }

        /* get next item */
        if (!(get_next_item(tvb, offset, length_remaining, str, &next_offset, &len))) {
            /* do not continue when get_next_item returns false */
            return;
        }

        /* do not add to the tree when the string is of zero length */
        if ( strlen(str) == 0 ) {
            offset = next_offset + 1;
            continue;
        }

        /* Xcsl (Call Specification Language) protocol in brief :
         *
         * Request :
         *
         *    <xcsl-version>;<transaction-id>;<command>;[parameter1;parameter2;parameter3;....]
         *
         * Reply :
         *
         *    <xcsl-version>;transaction-id;<result>;[answer data;answer data];...
         *
         * If result is one or more digits, this is determined as a Reply.
         *
         * Example :
         *
         * -->      xcsl-1.0;1000;offhook;+31356871234
         * <--      xcsl-1.0;1000;0                              <- success
         *
         * -->      xcsl-1.0;1001;dial;+31356871234;+31356875678
         * <--      xcsl-1.0;1001;0                              <- success
         *
         *
         * index :  0        1    2    3            4
         *
         * Index 2 represents the return code (see the xcsl_action_vals[] definitions)
         *
         */

        /* One by one go through each item ';' separated */
        switch (idx) {

            /* This is the protocol item */
            case 0:
                proto_tree_add_item(xcsl_tree, hf_xcsl_protocol_version, tvb, offset, len, ENC_ASCII|ENC_NA);
                break;

                /* This should be the transaction ID, if non-digit, it is treated as info */
            case 1:
                if ( isdigit(str[0]) ) {
                    proto_tree_add_item(xcsl_tree, hf_xcsl_transaction_id, tvb, offset, len, ENC_ASCII|ENC_NA);
                } else {
                    proto_tree_add_item(xcsl_tree, hf_xcsl_information, tvb, offset, len, ENC_ASCII|ENC_NA);
                }
                if (check_col(pinfo->cinfo, COL_INFO))
                    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",str);
                break;

                /* Starting with non-digit -> Command, if it starts with a digit -> reply */
            case 2:
                if ( isdigit(str[0]) ) {
                    proto_item *xcsl_item;

                    request = FALSE;
                    result = atoi(str);
                    if ( result >= XCSL_NONE ) {
                        result = XCSL_UNDEFINED;
                    }
                    code = val_to_str(result, xcsl_action_vals, "Unknown: %d");

                    /* Print result code and description */
                    xcsl_item = proto_tree_add_item(xcsl_tree, hf_xcsl_result, tvb, offset, len, ENC_ASCII|ENC_NA);
                    proto_item_append_text(xcsl_item, " (%s)", code);

                    if (result != 0 && check_col(pinfo->cinfo, COL_INFO))
                        col_append_fstr(pinfo->cinfo, COL_INFO, "[%s] ", code);

                } else {

                    request = TRUE;
                    proto_tree_add_item(xcsl_tree, hf_xcsl_command, tvb, offset, len, ENC_ASCII|ENC_NA);

                    if (check_col(pinfo->cinfo, COL_INFO))
                        col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", str);

                }
                break;

                /* This is a command parameter */
            default:
                proto_tree_add_item(xcsl_tree, hf_xcsl_parameter, tvb, offset, len, ENC_ASCII|ENC_NA);

                if (check_col(pinfo->cinfo, COL_INFO)) {
                    if ( request == TRUE ) {
                        col_append_fstr(pinfo->cinfo, COL_INFO, ": %s ",str);
                    } else {
                        if (par == 0) {
                            col_append_fstr(pinfo->cinfo, COL_INFO, "reply: %s ",str);
                        } else {
                            col_append_fstr(pinfo->cinfo, COL_INFO, ": %s ",str);
                        }
                    }
                }

                /* increment the parameter count */
                par++;

                break;
        }

        offset = next_offset + 1;
        idx++;

    }


    return;
}


/* This function determines whether the first 4 octets equals to xcsl and the fifth is an ; or - */
static gboolean dissect_xcsl_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {

    gint offset = 0;
    guint8 *protocol;

    if (tvb_length_remaining (tvb, offset) >= 5) {
        protocol = tvb_get_ephemeral_string(tvb, offset, 5);

        if (strncmp(protocol,"xcsl",4) == 0 && (protocol[4] == ';' || protocol[4] == '-')) {

            /* Disssect it as being an xcsl message */
            dissect_xcsl_tcp(tvb, pinfo, tree);

            return TRUE;
        }
    }

    return FALSE;
}


/* register the various xcsl protocol filters */
void proto_register_xcsl(void) {

    static hf_register_info hf[] = {

        { &hf_xcsl_protocol_version,
          { "Protocol Version", "xcsl.protocol_version",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL
          }
        },

        { &hf_xcsl_transaction_id,
          { "Transaction ID", "xcsl.transacion_id",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL
          }
        },

        { &hf_xcsl_command,
          { "Command", "xcsl.command",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL
          }
        },

        { &hf_xcsl_result,
          { "Result", "xcsl.result",
            FT_STRING, BASE_NONE,NULL, 0x0,
            NULL, HFILL
          }
        },

        { &hf_xcsl_parameter,
          { "Parameter", "xcsl.parameter",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL
          }
        },

        { &hf_xcsl_information,
          { "Information", "xcsl.information",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL
          }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_xcsl
    };

    /* Register the protocol name and description */
    proto_xcsl = proto_register_protocol("Call Specification Language (Xcsl)", "XCSL", "xcsl");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_xcsl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

/* In case it concerns TCP, try to match on the xcsl header */
void proto_reg_handoff_xcsl(void) {
    heur_dissector_add("tcp", dissect_xcsl_tcp_heur, proto_xcsl);
}
