/* packet-msn-messenger.c
 * Routines for MSN Messenger Service packet dissection
 * Copyright 2003, Chris Waters <chris@waters.co.nz>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/strutil.h>

void proto_register_msnms(void);
void proto_reg_handoff_msnms(void);

static dissector_handle_t msnms_handle;

/*
 * The now-expired Internet-Draft for the MSN Messenger 1.0 protocol
 * can, as of the time of the writing of this comment, be found at:
 *
 *      http://praya.sourceforge.net/draft-movva-msn-messenger-protocol-00.txt
 *
 *      http://mono.es.gnome.org/imsharp/tutoriales/msn/appendixa.html
 *
 *      http://www.hypothetic.org/docs/msn/ietf_draft.php
 *
 *      http://babble.wundsam.net/docs/protocol-msn-im.txt
 *
 * Note that it's Yet Another FTP-Like Command/Response Protocol,
 * so it arguably should be dissected as such, although you do have
 * to worry about the MSG command, as only the first line of it
 * should be parsed as a command, the rest should be parsed as the
 * message body.  We therefore leave "hf_msnms_command", "tokenlen",
 * and "next_token", even though they're unused, as reminders that
 * this should be done.
 */

static int proto_msnms;
/* static int hf_msnms_command; */

static int ett_msnms;

#define TCP_PORT_MSNMS    1863

static int
dissect_msnms(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree   *msnms_tree;
    proto_item   *ti;
    int           offset = 0;
    const unsigned char *line;
    int           next_offset;
    int           linelen;
    /* int              tokenlen; */
    /* const unsigned char     *next_token; */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MSNMS");

    /*
     * Find the end of the first line.
     *
     * Note that "tvb_find_line_end()" will return a value that is
     * not longer than what's in the buffer, so the "tvb_get_ptr()"
     * call won't throw an exception.
     */
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, false);
    line = tvb_get_ptr(tvb, offset, linelen);


    /*
     * Put the first line from the buffer into the summary.
     */
    col_add_str(pinfo->cinfo, COL_INFO,
                format_text(pinfo->pool, line, linelen));

    if (tree) {
        ti = proto_tree_add_item(tree, proto_msnms, tvb, offset, -1,
                                 ENC_NA);
        msnms_tree = proto_item_add_subtree(ti, ett_msnms);

        /*
         * Show the rest of the packet as text,
         * a line at a time.
         */
        while (tvb_offset_exists(tvb, offset)) {
            /*
             * Find the end of the line.
             */
            tvb_find_line_end(tvb, offset, -1,
                              &next_offset, false);

            /*
             * Put this line.
             */
            proto_tree_add_format_text(msnms_tree, tvb, offset, next_offset - offset);
            offset = next_offset;
        }
    }
    return tvb_captured_length(tvb);
}

void
proto_register_msnms(void)
{
    static int *ett[] = {
        &ett_msnms,
    };

    proto_msnms = proto_register_protocol("MSN Messenger Service", "MSNMS", "msnms");
    proto_register_subtree_array(ett, array_length(ett));

    msnms_handle = register_dissector("msnms", dissect_msnms, proto_msnms);
}

void
proto_reg_handoff_msnms(void)
{
    dissector_add_uint_with_preference("tcp.port", TCP_PORT_MSNMS, msnms_handle);
    /*
     * For MSN Messenger Protocol over HTTP
     */
    dissector_add_string("media_type", "application/x-msn-messenger", msnms_handle);
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
