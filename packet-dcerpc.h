/* packet-dcerpc.h
 * Copyright 2001, Todd Sabin <tas@webspan.net>
 *
 * $Id: packet-dcerpc.h,v 1.5 2001/12/06 23:30:35 guy Exp $
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

#ifndef __PACKET_DCERPC_H__
#define __PACKET_DCERPC_H__

typedef struct _e_uuid_t {
    guint32 Data1;
    guint16 Data2;
    guint16 Data3;
    guint8 Data4[8];
} e_uuid_t;

typedef struct _e_ctx_hnd {
    guint32 Data1;
    e_uuid_t uuid;
} e_ctx_hnd;

typedef struct _e_dce_cn_common_hdr_t {
    guint8 rpc_ver;
    guint8 rpc_ver_minor;
    guint8 ptype;
    guint8 flags;
    guint8 drep[4];
    guint16 frag_len;
    guint16 auth_len;
    guint32 call_id;
} e_dce_cn_common_hdr_t;

typedef struct _e_dce_dg_common_hdr_t {
    guint8 rpc_ver;
    guint8 ptype;
    guint8 flags1;
    guint8 flags2;
    guint8 drep[3];
    guint8 serial_hi;
    e_uuid_t obj_id;
    e_uuid_t if_id;
    e_uuid_t act_id;
    guint32 server_boot;
    guint32 if_ver;
    guint32 seqnum;
    guint16 opnum;
    guint16 ihint;
    guint16 ahint;
    guint16 frag_len;
    guint16 frag_num;
    guint8 auth_proto;
    guint8 serial_lo;
} e_dce_dg_common_hdr_t;



#define PDU_REQ        0
#define PDU_PING       1
#define PDU_RESP       2
#define PDU_FAULT      3
#define PDU_WORKING    4
#define PDU_NOCALL     5
#define PDU_REJECT     6
#define PDU_ACK        7
#define PDU_FACK       9
#define PDU_BIND      11
#define PDU_BIND_ACK  12
#define PDU_BIND_NAK  13
#define PDU_ALTER     14
#define PDU_ALTER_ACK 15
#define PDU_AUTH3     16

/*
 * helpers for packet-dcerpc.c and packet-dcerpc-ndr.c
 * If you're writing a subdissector, you almost certainly want the
 * NDR functions below.
 */
guint16 dcerpc_tvb_get_ntohs (tvbuff_t *tvb, gint offset, char *drep);
guint32 dcerpc_tvb_get_ntohl (tvbuff_t *tvb, gint offset, char *drep);
void dcerpc_tvb_get_uuid (tvbuff_t *tvb, gint offset, char *drep, e_uuid_t *uuid);
int dissect_dcerpc_uint8 (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                          proto_tree *tree, char *drep, 
                          int hfindex, guint8 *pdata);
int dissect_dcerpc_uint16 (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                           proto_tree *tree, char *drep, 
                           int hfindex, guint16 *pdata);
int dissect_dcerpc_uint32 (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                           proto_tree *tree, char *drep, 
                           int hfindex, guint32 *pdata);


/*
 * NDR routines for subdissectors.
 */
int dissect_ndr_uint8 (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, char *drep, 
                       int hfindex, guint8 *pdata);
int dissect_ndr_uint16 (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                        proto_tree *tree, char *drep, 
                        int hfindex, guint16 *pdata);
int dissect_ndr_uint32 (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                        proto_tree *tree, char *drep, 
                        int hfindex, guint32 *pdata);
int dissect_ndr_uuid_t (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                        proto_tree *tree, char *drep, 
                        int hfindex, e_uuid_t *pdata);
int dissect_ndr_ctx_hnd (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                         proto_tree *tree, char *drep, 
                         int hfindex, e_ctx_hnd *pdata);


typedef int (dcerpc_dissect_fnct_t)(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, char *drep);

typedef struct _dcerpc_sub_dissector {
    guint16 num;
    gchar   *name;
    dcerpc_dissect_fnct_t *dissect_rqst;
    dcerpc_dissect_fnct_t *dissect_resp;
} dcerpc_sub_dissector;

/* registration function for subdissectors */
void dcerpc_init_uuid (int proto, int ett, e_uuid_t *uuid, guint16 ver, dcerpc_sub_dissector *procs);

/* Private data structure to pass to DCERPC dissector. This is used to
   pass transport specific information down to the dissector from the
   dissector that parsed this encapsulated calls. */

#define DCERPC_TRANSPORT_SMB  1

typedef struct _dcerpc_private_info {
    int transport_type;		/* Tag */

    union {
	struct {		/* DCERPC_TRANSPORT_SMB */
	    guint16 fid;
	} smb;
    } data;
} dcerpc_private_info;

#endif /* packet-dcerpc.h */
