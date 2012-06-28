/* packet-infiniband.h
 * Routines for Infiniband/ERF Dissection
 * Copyright 2008 Endace Technology Limited
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Modified 2010 by Mellanox Technologies Ltd.
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
#ifndef __PACKET_INFINIBAND_H_
#define __PACKET_INFINIBAND_H_

#define MAD_DATA_SIZE     232     /* size of data field a MAD payload carries */
#define GID_SIZE          16      /* size of GID = 128bit (same as IPv6) */

/* infiniband-specific information for conversations */
typedef struct {
    guint64 service_id;         /* service id specified when the (RC) channel was set-up */
} conversation_infiniband_data;

#endif
