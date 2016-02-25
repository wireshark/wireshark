/* packet-lbtrm.h
 * Routines for LBT-RM Packet dissection
 *
 * Copyright (c) 2005-2014 Informatica Corporation. All Rights Reserved.
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

#ifndef PACKET_LBTRM_H_INCLUDED
#define PACKET_LBTRM_H_INCLUDED

typedef struct
{
    address source_address;
    guint16 source_port;
    guint32 session_id;
    address multicast_group;
    guint16 dest_port;
    guint64 channel;
    wmem_tree_t * frame;
    lbm_transport_frame_t * last_frame;
    lbm_transport_frame_t * last_data_frame;
    lbm_transport_frame_t * last_sm_frame;
    lbm_transport_frame_t * last_nak_frame;
    lbm_transport_frame_t * last_ncf_frame;
    wmem_tree_t * data_sqn;
    wmem_tree_t * sm_sqn;
    guint32 data_high_sqn;
    guint32 sm_high_sqn;
} lbtrm_transport_t;

lbtrm_transport_t * lbtrm_transport_add(const address * source_address, guint16 source_port, guint32 session_id, const address * multicast_group, guint16 dest_port, guint32 frame);
char * lbtrm_transport_source_string(const address * source_address, guint16 source_port, guint32 session_id, const address * multicast_group, guint16 dest_port);

#endif

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
