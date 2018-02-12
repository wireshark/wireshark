/* packet-msrp.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Info to save in MSRP conversation / packet-info. */
#define MAX_MSRP_SETUP_METHOD_SIZE 7
struct _msrp_conversation_info
{
    guchar  setup_method_set;
    gchar   setup_method[MAX_MSRP_SETUP_METHOD_SIZE + 1];
    guint32 setup_frame_number;
};


/* Add an MSRP conversation with the given details */
void msrp_add_address(packet_info *pinfo,
                      address *addr, int port,
                      const gchar *setup_method, guint32 setup_frame_number);

