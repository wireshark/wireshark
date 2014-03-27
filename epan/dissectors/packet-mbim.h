/* packet-mbim.h
 * Routines for MBIM dissection
 * Copyright 2013, Pascal Quantin <pascal.quantin@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __PACKET_MBIM_H__
#define __PACKET_MBIM_H__

#include "ws_symbol_export.h"

#define MBIM_COMMAND_QUERY 0
#define MBIM_COMMAND_SET   1

struct mbim_info {
    guint32 req_frame;
    guint32 resp_frame;
    guint32 cmd_type;
};

typedef void (*mbim_dissect_fct) (tvbuff_t *, packet_info *, proto_tree *, gint /* offset */, struct mbim_info *);

/* Structure listing the dissection function to be called for a given CID */
struct mbim_cid_dissect {
    mbim_dissect_fct cmd_set;
    mbim_dissect_fct cmd_query;
    mbim_dissect_fct cmd_done;
    mbim_dissect_fct ind_status;
};

/* Structure handling the description of the UUID extension to be registered */
struct mbim_uuid_ext {
    /* UUID value stored in network byte order */
    guint32 uuid[4];
    /* UUID name to be displayed during dissection */
    const gchar *uuid_name;
    /* value_string array containing the CID list for this UUID */
    const value_string *uuid_cid_list;
    /* Array of the dissection functions per CID. Pointers can be NULL when no dissection is expected */
    /* BEWARE: the array must be ordered the same way as uuid_cid_list as it will be accessed with the CID index */
    const struct mbim_cid_dissect *uuid_fct_list;
    /* Handle used for the DSS of this UUID. Set it to NULL if unused */
    dissector_handle_t dss_handle;
};

/* Function allowing to register a new UUID used during MBIM dissection */
WS_DLL_PUBLIC void mbim_register_uuid_ext(struct mbim_uuid_ext *uuid_ext);

#endif /* __PACKET_MBIM_H__ */
