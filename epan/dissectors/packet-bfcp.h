/* packet-bfcp.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_BFCP_H__
#define __PACKET_BFCP_H__

/* Info to save in BFCP conversation / packet-info. */
#define MAX_BFCP_SETUP_METHOD_SIZE 7
struct _bfcp_conversation_info
{
    guchar  setup_method_set;
    gchar   setup_method[MAX_BFCP_SETUP_METHOD_SIZE + 1];
    guint32 setup_frame_number;
};


/* Add an BFCP conversation with the given details */
void bfcp_add_address(packet_info *pinfo, port_type ptype,
                      address *addr, int port,
                      const gchar *setup_method, guint32 setup_frame_number);

#endif /* __PACKET_BFCP_H__ */
