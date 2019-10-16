/* Routines for MAC LTE format files with context info as header.
 *
 * Martin Mathieson
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/proto_data.h>
#include "packet-mac-lte.h"

void proto_register_mac_lte_framed(void);

/* Initialize the protocol and registered fields. */
static int proto_mac_lte_framed = -1;

extern int proto_mac_lte;

/* Main dissection function. */
static int dissect_mac_lte_framed(tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree, void* data _U_)
{
    gint                 offset = 0;
    struct mac_lte_info  *p_mac_lte_info;
    tvbuff_t             *mac_tvb;
    gboolean             infoAlreadySet = FALSE;

    /* Need to find enabled mac-lte dissector */
    dissector_handle_t   mac_lte_handle = find_dissector("mac-lte");
    if (!mac_lte_handle) {
        return 0;
    }

    /* Do this again on re-dissection to re-discover offset of actual PDU */

    /* Needs to be at least as long as:
       - fixed header bytes
       - tag for data
       - at least one byte of MAC PDU payload */
    if ((size_t)tvb_reported_length_remaining(tvb, offset) < (3+2)) {
        return 5;
    }

    /* If redissecting, use previous info struct (if available) */
    p_mac_lte_info = (struct mac_lte_info*)p_get_proto_data(wmem_file_scope(), pinfo, proto_mac_lte, 0);
    if (p_mac_lte_info == NULL) {
        /* Allocate new info struct for this frame */
        p_mac_lte_info = (struct mac_lte_info*)wmem_alloc0(wmem_file_scope(), sizeof(struct mac_lte_info));
        infoAlreadySet = FALSE;
    }
    else {
        infoAlreadySet = TRUE;
    }

    /* Dissect the fields to populate p_mac_lte */
    if (!dissect_mac_lte_context_fields(p_mac_lte_info, tvb, pinfo, tree, &offset)) {
        return offset;
    }

    /* Store info in packet (first time) */
    if (!infoAlreadySet) {
        p_add_proto_data(wmem_file_scope(), pinfo, proto_mac_lte, 0, p_mac_lte_info);
    }

    /**************************************/
    /* OK, now dissect as MAC LTE         */

    /* Create tvb that starts at actual MAC PDU */
    mac_tvb = tvb_new_subset_remaining(tvb, offset);
    call_dissector_only(mac_lte_handle, mac_tvb, pinfo, tree, NULL);
    return tvb_captured_length(tvb);
}

void proto_register_mac_lte_framed(void)
{
    /* Register protocol. */
    proto_mac_lte_framed = proto_register_protocol("mac-lte-framed", "MAC-LTE-FRAMED", "mac-lte-framed");

    /* Allow other dissectors to find this one by name. */
    register_dissector("mac-lte-framed", dissect_mac_lte_framed, proto_mac_lte_framed);
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
