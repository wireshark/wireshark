/* packet-rdt.h
 *
 * Routines for RDT dissection
 * RDT = Real Data Transport
 *
 * Written by Martin Mathieson
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Info to save in RDT conversation / packet-info */
#define MAX_RDT_SETUP_METHOD_SIZE 7
struct _rdt_conversation_info
{
    gchar   method[MAX_RDT_SETUP_METHOD_SIZE + 1];
    guint32 frame_number;
    gint    feature_level;
};

/* Add an RDT conversation with the given details */
void rdt_add_address(packet_info *pinfo,
                     address *addr, int port,
                     int other_port,
                     const gchar *setup_method,
                     gint  rdt_feature_level);

