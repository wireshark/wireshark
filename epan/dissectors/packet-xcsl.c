/* packet-xcsl.c
 *
 * Routines for the Xcsl dissection (Call Specification Language)
 *
 * Copyright 2008, Dick Gooris (gooris@alcatel-lucent.com)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <stdlib.h>

#include <epan/packet.h>

#include <wsutil/strtoi.h>

/* string array size */
#define MAXLEN 4096

void proto_register_xcsl(void);
void proto_reg_handoff_xcsl(void);

static int proto_xcsl;

static int hf_xcsl_command;
static int hf_xcsl_information;
static int hf_xcsl_parameter;
static int hf_xcsl_protocol_version;
static int hf_xcsl_result;
static int hf_xcsl_transaction_id;

/* Initialize the subtree pointers */
static int ett_xcsl;

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

/* patterns used for tvb_ws_mempbrk_pattern_guint8 */
static ws_mempbrk_pattern pbrk_param_end;

/* Dissector for xcsl */
static void dissect_xcsl_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {

    unsigned     offset = 0;
    int          length_remaining;
    uint8_t      idx;
    bool         request;
    uint8_t      par;
    uint8_t     *str;
    uint8_t      result;
    const char *code;
    unsigned     len;
    int          next_offset;
    proto_tree  *xcsl_tree = NULL;

    /* color support */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Xcsl");
    col_clear(pinfo->cinfo, COL_INFO);

    /* Create display tree for the xcsl protocol */
    if (tree) {
        proto_item  *xcsl_item;
        xcsl_item = proto_tree_add_item(tree, proto_xcsl, tvb, offset, -1, ENC_NA);
        xcsl_tree = proto_item_add_subtree(xcsl_item, ett_xcsl);
    }

    /* reset idx */
    idx = 0;

    /* reset the parameter count */
    par = 0;

    /* switch whether it concerns a command or an answer */
    request = false;

    while ((length_remaining = tvb_reported_length_remaining(tvb, offset)) > 0) {

        /* get next item */
        next_offset = tvb_ws_mempbrk_pattern_guint8(tvb, offset, length_remaining, &pbrk_param_end, NULL);
        if (next_offset == -1) {
            len = length_remaining;
            next_offset = offset + len;
        } else {
            len = next_offset - offset;
        }

        /* do not add to the tree when the string is of zero length */
        if ( len == 0 ) {
            offset = next_offset + 1;
            continue;
        }

        str = tvb_get_string_enc(pinfo->pool, tvb, offset, len, ENC_ASCII);

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
                proto_tree_add_item(xcsl_tree, hf_xcsl_protocol_version, tvb, offset, len, ENC_ASCII);
                break;

                /* This should be the transaction ID, if non-digit, it is treated as info */
            case 1:
                if ( g_ascii_isdigit(str[0]) ) {
                    proto_tree_add_item(xcsl_tree, hf_xcsl_transaction_id, tvb, offset, len, ENC_ASCII);
                } else {
                    proto_tree_add_item(xcsl_tree, hf_xcsl_information, tvb, offset, len, ENC_ASCII);
                }
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",str);
                break;

                /* Starting with non-digit -> Command, if it starts with a digit -> reply */
            case 2:
                if ( g_ascii_isdigit(str[0]) ) {
                    proto_item *xcsl_item;

                    request = false;
                    result = XCSL_UNDEFINED;
                    ws_strtou8(str, NULL, &result);
                    if ( result >= XCSL_NONE ) {
                        result = XCSL_UNDEFINED;
                    }
                    code = val_to_str(result, xcsl_action_vals, "Unknown: %d");

                    /* Print result code and description */
                    xcsl_item = proto_tree_add_item(xcsl_tree, hf_xcsl_result, tvb, offset, len, ENC_ASCII);
                    proto_item_append_text(xcsl_item, " (%s)", code);

                    if (result != 0)
                        col_append_fstr(pinfo->cinfo, COL_INFO, "[%s] ", code);

                } else {

                    request = true;
                    proto_tree_add_item(xcsl_tree, hf_xcsl_command, tvb, offset, len, ENC_ASCII);

                    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", str);

                }
                break;

                /* This is a command parameter */
            default:
                proto_tree_add_item(xcsl_tree, hf_xcsl_parameter, tvb, offset, len, ENC_ASCII);

                if ( request == true ) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s ",str);
                } else {
                    if (par == 0) {
                        col_append_fstr(pinfo->cinfo, COL_INFO, "reply: %s ",str);
                    } else {
                        col_append_fstr(pinfo->cinfo, COL_INFO, ": %s ",str);
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
static bool dissect_xcsl_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {

    uint8_t *protocol;

    if (tvb_captured_length (tvb) >= 5) {
        protocol = tvb_get_string_enc(pinfo->pool, tvb, 0, 5, ENC_ASCII);

        if (strncmp(protocol,"xcsl",4) == 0 && (protocol[4] == ';' || protocol[4] == '-')) {

            /* Disssect it as being an xcsl message */
            dissect_xcsl_tcp(tvb, pinfo, tree);

            return true;
        }
    }

    return false;
}


/* register the various xcsl protocol filters */
void proto_register_xcsl(void) {
    static hf_register_info hf[] = {
        { &hf_xcsl_protocol_version,
            { "Protocol Version", "xcsl.protocol_version",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_xcsl_transaction_id,
            { "Transaction ID", "xcsl.transaction_id",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_xcsl_command,
            { "Command", "xcsl.command",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_xcsl_result,
            { "Result", "xcsl.result",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_xcsl_information,
            { "Information", "xcsl.information",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_xcsl_parameter,
            { "Parameter", "xcsl.parameter",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_xcsl
    };

    /* Register the protocol name and description */
    proto_xcsl = proto_register_protocol("Call Specification Language (Xcsl)", "XCSL", "xcsl");
    proto_register_field_array(proto_xcsl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* compile patterns */
    ws_mempbrk_compile(&pbrk_param_end, ";\r\n");
}

/* In case it concerns TCP, try to match on the xcsl header */
void proto_reg_handoff_xcsl(void) {
    heur_dissector_add("tcp", dissect_xcsl_tcp_heur, "XCSL over TCP", "xcsl_tcp", proto_xcsl, HEURISTIC_ENABLE);
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
