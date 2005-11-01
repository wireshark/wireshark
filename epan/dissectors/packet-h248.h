/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* ./packet-h248.h                                                            */
/* ../../tools/asn2eth.py -X -b -e -p h248 -c h248.cnf -s packet-h248-template MEGACO.asn */

/* Input file: packet-h248-template.h */

/* packet-h248.h
 * Routines for H.248/MEGACO packet dissection
 * Ronnie Sahlberg 2004
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef PACKET_H248_H
#define PACKET_H248_H

/*#include "packet-h248-exp.h"*/

typedef enum {
    H248_CMD_NONE,
    H248_CMD_ADD,
    H248_CMD_MOVE,
    H248_CMD_MOD,
    H248_CMD_SUB,
    H248_CMD_AUDITCAP,
    H248_CMD_AUDITVAL,
    H248_CMD_NOTIFY,
    H248_CMD_SVCCHG,
} h248_cmd_type_t;

typedef enum {
    H248_TRX_NONE,
    H248_TRX_REQUEST,
    H248_TRX_PENDING,
    H248_TRX_REPLY,
    H248_TRX_ACK,
} h248_msg_type_t;

/* per command info */
typedef struct _h248_cmd_info_t h248_cmd_info_t;

/* per context info */
typedef struct _h248_context_info_t h248_context_info_t;

/* per command message info */
typedef struct _h248_cmdmsg_info_t {
    guint32 transaction_id;
    guint32 context_id;
    guint offset;
    h248_cmd_type_t cmd_type;
    h248_msg_type_t msg_type;
    guint error_code;
    gboolean term_is_wildcard;
    gchar* term_id;
    h248_cmd_info_t* cmd_info;
} h248_cmdmsg_info_t;


struct _h248_cmd_info_t {
    gchar* key;
    
    guint32 trx_id;
    h248_cmd_type_t type;

    guint request_frame;
    guint response_frame;
    guint pendings;
    
    gboolean choose_ctx;
    guint error_code;
     
    h248_context_info_t* context;
    
    h248_cmd_info_t* next;
    h248_cmd_info_t* last;
};

struct _h248_context_info_t {
    gchar* key;

    guint32 ctx_id;

    guint creation_frame;
    guint last_frame;

    h248_cmd_info_t* cmds;
    h248_context_info_t* prior;
};

typedef void (*h248_dissect_pkg_item_t)(gboolean implicit_tag, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

extern void h248_add_package_property(guint package, guint property, h248_dissect_pkg_item_t);
extern void h248_add_package_event(guint package, guint property, h248_dissect_pkg_item_t);
extern void h248_add_package_signal(guint package, guint property, h248_dissect_pkg_item_t);

#endif  /* PACKET_H248_H */
