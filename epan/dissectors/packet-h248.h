/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* ./packet-h248.h                                                            */
/* ../../tools/asn2wrs.py -b -e -p h248 -c h248.cnf -s packet-h248-template h248v3.asn */

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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef PACKET_H248_H
#define PACKET_H248_H
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/strutil.h>
#include <epan/emem.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/to_str.h>

#include <stdio.h>
#include <string.h>

#include <epan/dissectors/packet-ber.h>
#include <epan/dissectors/packet-q931.h>
#include <epan/dissectors/packet-mtp3.h>
#include <epan/dissectors/packet-alcap.h>
#include <epan/dissectors/packet-isup.h>

#include <epan/sctpppids.h>

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

typedef struct _h248_curr_info_t h248_curr_info_t;

typedef void (*h248_pkg_param_dissector_t)(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo _U_, int hfid, h248_curr_info_t*, void*);

extern void h248_param_item(proto_tree*, tvbuff_t*, packet_info* , int, h248_curr_info_t*,void* ignored);
extern void h248_param_ber_integer(proto_tree*, tvbuff_t*, packet_info* , int, h248_curr_info_t*,void* ignored);
extern void h248_param_ber_octetstring(proto_tree*, tvbuff_t*, packet_info* , int, h248_curr_info_t*,void* ignored);
extern void h248_param_ber_boolean(proto_tree*, tvbuff_t*, packet_info* , int, h248_curr_info_t*,void* ignored);
extern void external_dissector(proto_tree*, tvbuff_t*, packet_info* , int, h248_curr_info_t*,void* dissector_handle);


typedef struct _h248_pkg_param_t {
	guint32 id;
	int* hfid;
	h248_pkg_param_dissector_t dissector;
	void* data;
} h248_pkg_param_t;

typedef struct _h248_pkg_sig_t {
	guint32 id;
	int* hfid;
	gint* ett;
	h248_pkg_param_t* parameters;	
} h248_pkg_sig_t;

typedef struct _h248_pkg_evt_t {
	guint32 id;
	int* hfid;
	gint* ett;
	h248_pkg_param_t* parameters;	
} h248_pkg_evt_t;

typedef struct _h248_pkg_stat_t {
	guint32 id;
	int* hfid;
	gint* ett;
	h248_pkg_param_t* parameters;	
} h248_pkg_stat_t;

typedef struct _h248_package_t {
	guint32 id;
	int* hfid;
	int* hfid_params;
	gint* ett;
	h248_pkg_param_t* properties;
	h248_pkg_sig_t* signals;
	h248_pkg_evt_t* events;
	h248_pkg_stat_t* statistics;
} h248_package_t;

struct _h248_curr_info_t {
	h248_ctx_t* ctx;
	h248_trx_t* trx;
	h248_msg_t* msg;
	h248_term_t* term;
	h248_cmd_t* cmd;
	h248_package_t* pkg;
	h248_pkg_evt_t* evt;
	h248_pkg_sig_t* sig;
	h248_pkg_stat_t* stat;
	h248_pkg_param_t* par;
};

void h248_register_package(h248_package_t*);

#endif  /* PACKET_H248_H */
