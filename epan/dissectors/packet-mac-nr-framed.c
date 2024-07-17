/* Routines for MAC NR format files with context info as header.
 *
 * Based on mac-lte-framed.c
 *
 * Martin Mathieson
 * Pedro Alvarez
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <epan/packet.h>
#include <epan/proto_data.h>

#include "config.h"
#include "packet-mac-nr.h"

void proto_register_mac_nr_framed(void);

/* Initialize the protocol and registered fields. */
static int proto_mac_nr_framed;

extern int proto_mac_nr;

/* Main dissection function. */
static int dissect_mac_nr_framed(tvbuff_t *tvb, packet_info *pinfo,
                                 proto_tree *tree, void *data _U_) {
    int offset = 0;
    struct mac_nr_info *p_mac_nr_info;
    tvbuff_t *mac_tvb;
    bool infoAlreadySet = false;

    /* Need to find enabled mac-nr dissector */
    dissector_handle_t mac_nr_handle = find_dissector("mac-nr");
    if (!mac_nr_handle) {
        return 0;
    }

    /* Do this again on re-dissection to re-discover offset of actual PDU */

    /* Needs to be at least as long as:
       - fixed header bytes
       - tag for data
       - at least one byte of MAC PDU payload */
    if ((size_t)tvb_reported_length_remaining(tvb, offset) < (3 + 2)) {
        return 5;
    }

    /* If redissecting, use previous info struct (if available) */
    p_mac_nr_info = (struct mac_nr_info *)p_get_proto_data(
        wmem_file_scope(), pinfo, proto_mac_nr, 0);
    if (p_mac_nr_info == NULL) {
        /* Allocate new info struct for this frame */
        p_mac_nr_info = wmem_new0(wmem_file_scope(), struct mac_nr_info);
    } else {
        infoAlreadySet = true;
    }

    /* Dissect the fields to populate p_mac_nr */
    if (!dissect_mac_nr_context_fields(p_mac_nr_info, tvb, pinfo, tree,
                                       &offset)) {
        return offset;
    }

    /* Store info in packet (first time) */
    if (!infoAlreadySet) {
        p_add_proto_data(wmem_file_scope(), pinfo, proto_mac_nr, 0,
                         p_mac_nr_info);
    }

    /**************************************/
    /* OK, now dissect as MAC NR         */

    /* Create tvb that starts at actual MAC PDU */
    mac_tvb = tvb_new_subset_remaining(tvb, offset);
    call_dissector_only(mac_nr_handle, mac_tvb, pinfo, tree, NULL);
    return tvb_captured_length(tvb);
}

void proto_register_mac_nr_framed(void) {
    /* Register protocol. */
    proto_mac_nr_framed = proto_register_protocol(
        "mac-nr-framed", "MAC-NR-FRAMED", "mac-nr-framed");

    /* Allow other dissectors to find this one by name. */
    register_dissector("mac-nr-framed", dissect_mac_nr_framed,
                       proto_mac_nr_framed);
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
