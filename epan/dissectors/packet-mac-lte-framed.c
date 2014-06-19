/* Routines for MAC LTE format files with context info as header.
 *
 * Martin Mathieson
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/wmem/wmem.h>

#include "packet-mac-lte.h"

void proto_register_mac_lte_framed(void);

/* Initialize the protocol and registered fields. */
static int proto_mac_lte_framed = -1;

extern int proto_mac_lte;

/* Main dissection function. */
static void dissect_mac_lte_framed(tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree)
{
    gint                 offset = 0;
    struct mac_lte_info  *p_mac_lte_info;
    tvbuff_t             *mac_tvb;
    gboolean             infoAlreadySet = FALSE;

    /* Need to find enabled mac-lte dissector */
    dissector_handle_t   mac_lte_handle = find_dissector("mac-lte");
    if (!mac_lte_handle) {
        return;
    }

    /* Do this again on re-dissection to re-discover offset of actual PDU */

    /* Needs to be at least as long as:
       - fixed header bytes
       - tag for data
       - at least one byte of MAC PDU payload */
    if ((size_t)tvb_length_remaining(tvb, offset) < (3+2)) {
        return;
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
    if (!dissect_mac_lte_context_fields(p_mac_lte_info, tvb, &offset)) {
        return;
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
}

void proto_register_mac_lte_framed(void)
{
    /* Register protocol. */
    proto_mac_lte_framed = proto_register_protocol("mac-lte-framed", "MAC-LTE-FRAMED", "mac-lte-framed");

    /* Allow other dissectors to find this one by name. */
    register_dissector("mac-lte-framed", dissect_mac_lte_framed, proto_mac_lte_framed);
}

