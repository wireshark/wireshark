/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* ./packet-h248.h                                                            */
/* ../../tools/asn2eth.py -X -b -e -p h248 -c h248.cnf -s packet-h248-template MEGACO.asn */

/* Input file: packet-h248-template.h */

#line 1 "packet-h248-template.h"
/* packet-h248.h
 * Definitions for H.248/MEGACO packet dissection
 *
 * Ronnie Sahlberg 2004
 * Luis Ontanon 2005
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
    H248_CMD_ADD_REQ,
    H248_CMD_MOVE_REQ,
    H248_CMD_MOD_REQ,
    H248_CMD_SUB_REQ,
    H248_CMD_AUDITCAP_REQ,
    H248_CMD_AUDITVAL_REQ,
    H248_CMD_NOTIFY_REQ,
    H248_CMD_SVCCHG_REQ,
    H248_CMD_TOPOLOGY_REQ,
    H248_CMD_CTX_ATTR_AUDIT_REQ,
    H248_CMD_ADD_REPLY,
    H248_CMD_MOVE_REPLY,
    H248_CMD_MOD_REPLY,
    H248_CMD_SUB_REPLY,
    H248_CMD_AUDITCAP_REPLY,
    H248_CMD_AUDITVAL_REPLY,
    H248_CMD_NOTIFY_REPLY,
    H248_CMD_SVCCHG_REPLY,
    H248_CMD_TOPOLOGY_REPLY,
    H248_CMD_REPLY
} h248_cmd_type_t;

typedef enum {
    H248_TRX_NONE,
    H248_TRX_REQUEST,
    H248_TRX_PENDING,
    H248_TRX_REPLY,
    H248_TRX_ACK
} h248_trx_type_t;


typedef struct _h248_msg_t {
    guint32 lo_addr;
    guint32 hi_addr;
    guint32 framenum;
    struct _h248_trx_msg_t* trxs;
    gboolean commited;
} h248_msg_t;

typedef struct _h248_trx_msg_t {
    struct _h248_trx_t* trx;
    struct _h248_trx_msg_t* next;
    struct _h248_trx_msg_t* last;
} h248_trx_msg_t;

typedef struct _h248_cmd_msg_t {
    struct _h248_cmd_t* cmd;
    struct _h248_cmd_msg_t* next;
    struct _h248_cmd_msg_t* last;
} h248_cmd_msg_t;

typedef struct _h248_trx_t {
    h248_msg_t* initial;
    guint32 id;
    h248_trx_type_t type;
    guint pendings;
    struct _h248_cmd_msg_t* cmds;
    struct _h248_trx_ctx_t* ctxs;
    guint error;
} h248_trx_t;

#define H248_TERM_TYPE_UNKNOWN 0
#define H248_TERM_TYPE_AAL1 1
#define H248_TERM_TYPE_AAL2 2
#define H248_TERM_TYPE_AAL1_STRUCT 3
#define H248_TERM_TYPE_IP_RTP 4
#define H248_TERM_TYPE_TDM 5

typedef enum _h248_wildcard_t {
    H248_WILDCARD_NONE,
    H248_WILDCARD_CHOOSE,
    H248_WILDCARD_ALL
} h248_wildcard_t;

typedef struct _h248_term_t {
    gchar* str;
    
    guint8* buffer;
    guint len;

    guint type;
    gchar* bir;
    gchar* nsap;

    h248_msg_t* start;
    
    /*
    guint16 vp;
    guint16 vc;
    guint32 ts_mask;
    address* src_addr;
    address* dst_addr;
    guint16 src_pt;
    guint16 dst_pt;
    */

} h248_term_t;

typedef struct _h248_terms_t {
    h248_term_t* term;
    struct _h248_terms_t* next;
    struct _h248_terms_t* last;
} h248_terms_t;

typedef struct _h248_cmd_t {
    guint offset;
    h248_cmd_type_t type;
    h248_terms_t terms;
    struct _h248_msg_t* msg;
    struct _h248_trx_t* trx;
    struct _h248_ctx_t* ctx;
    guint error;
} h248_cmd_t;


typedef struct _h248_ctx_t {
    h248_msg_t* initial;
    guint32 id;
    struct _h248_cmd_msg_t* cmds;
    struct _h248_ctx_t* prev;
    h248_terms_t terms;
} h248_ctx_t;


#endif  /* PACKET_H248_H */
