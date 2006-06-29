/* packet-dcerpc.h
 * Copyright 2001, Todd Sabin <tas@webspan.net>
 * Copyright 2003, Tim Potter <tpot@samba.org>
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

#ifndef __PACKET_DCERPC_H__
#define __PACKET_DCERPC_H__

#include <epan/conversation.h>

typedef struct _e_uuid_t {
    guint32 Data1;
    guint16 Data2;
    guint16 Data3;
    guint8 Data4[8];
} e_uuid_t;

/* %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x */
#define DCERPC_UUID_STR_LEN 36+1

typedef struct _e_ctx_hnd {
    guint32 attributes;
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

typedef struct _dcerpc_auth_info {
  guint8 auth_pad_len;
  guint8 auth_level;
  guint8 auth_type;
  guint32 auth_size;
  tvbuff_t *auth_data;
} dcerpc_auth_info;

#define PDU_REQ         0
#define PDU_PING        1
#define PDU_RESP        2
#define PDU_FAULT       3
#define PDU_WORKING     4
#define PDU_NOCALL      5
#define PDU_REJECT      6
#define PDU_ACK         7
#define PDU_CL_CANCEL   8
#define PDU_FACK        9
#define PDU_CANCEL_ACK 10
#define PDU_BIND       11
#define PDU_BIND_ACK   12
#define PDU_BIND_NAK   13
#define PDU_ALTER      14
#define PDU_ALTER_ACK  15
#define PDU_AUTH3      16
#define PDU_SHUTDOWN   17
#define PDU_CO_CANCEL  18
#define PDU_ORPHANED   19


/*
 * helpers for packet-dcerpc.c and packet-dcerpc-ndr.c
 * If you're writing a subdissector, you almost certainly want the
 * NDR functions below.
 */
guint16 dcerpc_tvb_get_ntohs (tvbuff_t *tvb, gint offset, guint8 *drep);
guint32 dcerpc_tvb_get_ntohl (tvbuff_t *tvb, gint offset, guint8 *drep);
void dcerpc_tvb_get_uuid (tvbuff_t *tvb, gint offset, guint8 *drep, e_uuid_t *uuid);
int dissect_dcerpc_uint8 (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                          proto_tree *tree, guint8 *drep,
                          int hfindex, guint8 *pdata);
int dissect_dcerpc_uint16 (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                           proto_tree *tree, guint8 *drep,
                           int hfindex, guint16 *pdata);
int dissect_dcerpc_uint32 (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                           proto_tree *tree, guint8 *drep,
                           int hfindex, guint32 *pdata);
int dissect_dcerpc_uint64 (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                           proto_tree *tree, guint8 *drep,
                           int hfindex, guint64 *pdata);
int dissect_dcerpc_float  (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                           proto_tree *tree, guint8 *drep, 
                           int hfindex, gfloat *pdata);
int dissect_dcerpc_double (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                           proto_tree *tree, guint8 *drep, 
                           int hfindex, gdouble *pdata);
int dissect_dcerpc_time_t (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                           proto_tree *tree, guint8 *drep, 
                           int hfindex, guint32 *pdata);
int dissect_dcerpc_uuid_t (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                           proto_tree *tree, guint8 *drep,
                           int hfindex, e_uuid_t *pdata);

/*
 * NDR routines for subdissectors.
 */
int dissect_ndr_uint8 (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, guint8 *drep,
                       int hfindex, guint8 *pdata);
int dissect_ndr_uint16 (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                        proto_tree *tree, guint8 *drep,
                        int hfindex, guint16 *pdata);
int dissect_ndr_uint32 (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                        proto_tree *tree, guint8 *drep,
                        int hfindex, guint32 *pdata);
int dissect_ndr_duint32 (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                        proto_tree *tree, guint8 *drep,
                        int hfindex, guint64 *pdata);
int dissect_ndr_uint64 (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                        proto_tree *tree, guint8 *drep,
                        int hfindex, guint64 *pdata);
int dissect_ndr_float (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                        proto_tree *tree, guint8 *drep, 
                        int hfindex, gfloat *pdata);
int dissect_ndr_double (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                        proto_tree *tree, guint8 *drep, 
                        int hfindex, gdouble *pdata);
int dissect_ndr_time_t (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                        proto_tree *tree, guint8 *drep, 
                        int hfindex, guint32 *pdata);
int dissect_ndr_uuid_t (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                        proto_tree *tree, guint8 *drep,
                        int hfindex, e_uuid_t *pdata);
int dissect_ndr_ctx_hnd (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                         proto_tree *tree, guint8 *drep,
                         int hfindex, e_ctx_hnd *pdata);

typedef int (dcerpc_dissect_fnct_t)(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);

typedef void (dcerpc_callback_fnct_t)(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb, int start_offset, int end_offset, void *callback_args);

#define NDR_POINTER_REF		1
#define NDR_POINTER_UNIQUE	2
#define NDR_POINTER_PTR		3

int dissect_ndr_pointer_cb(tvbuff_t *tvb, gint offset, packet_info *pinfo,
			   proto_tree *tree, guint8 *drep,
			   dcerpc_dissect_fnct_t *fnct, int type, const char *text, 
			   int hf_index, dcerpc_callback_fnct_t *callback,
			   void *callback_args);

int dissect_ndr_pointer(tvbuff_t *tvb, gint offset, packet_info *pinfo,
			proto_tree *tree, guint8 *drep,
			dcerpc_dissect_fnct_t *fnct, int type, const char *text, 
			int hf_index);
int dissect_deferred_pointers(packet_info *pinfo, tvbuff_t *tvb, int offset, guint8 *drep);
int dissect_ndr_embedded_pointer(tvbuff_t *tvb, gint offset, packet_info *pinfo,
			proto_tree *tree, guint8 *drep,
			dcerpc_dissect_fnct_t *fnct, int type, const char *text, 
			int hf_index);
int dissect_ndr_toplevel_pointer(tvbuff_t *tvb, gint offset, packet_info *pinfo,
			proto_tree *tree, guint8 *drep,
			dcerpc_dissect_fnct_t *fnct, int type, const char *text, 
			int hf_index);

/* dissect a NDR unidimensional conformant array */
int dissect_ndr_ucarray(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                        proto_tree *tree, guint8 *drep,
                        dcerpc_dissect_fnct_t *fnct);

/* dissect a NDR unidimensional conformant and varying array */
int dissect_ndr_ucvarray(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                        proto_tree *tree, guint8 *drep,
                        dcerpc_dissect_fnct_t *fnct);

/* dissect a NDR unidimensional varying array */
int dissect_ndr_uvarray(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                        proto_tree *tree, guint8 *drep,
                        dcerpc_dissect_fnct_t *fnct);

int dissect_ndr_byte_array(tvbuff_t *tvb, int offset, packet_info *pinfo, 
                           proto_tree *tree, guint8 *drep);

int dissect_ndr_cvstring(tvbuff_t *tvb, int offset, packet_info *pinfo, 
			 proto_tree *tree, guint8 *drep, int size_is,
			 int hfinfo, gboolean add_subtree,
			 char **data);
int dissect_ndr_char_cvstring(tvbuff_t *tvb, int offset, packet_info *pinfo, 
                           proto_tree *tree, guint8 *drep);
int dissect_ndr_wchar_cvstring(tvbuff_t *tvb, int offset, packet_info *pinfo, 
                            proto_tree *tree, guint8 *drep);
int dissect_ndr_vstring(tvbuff_t *tvb, int offset, packet_info *pinfo, 
			 proto_tree *tree, guint8 *drep, int size_is,
			 int hfinfo, gboolean add_subtree,
			 char **data);
int dissect_ndr_char_vstring(tvbuff_t *tvb, int offset, packet_info *pinfo, 
                           proto_tree *tree, guint8 *drep);
int dissect_ndr_wchar_vstring(tvbuff_t *tvb, int offset, packet_info *pinfo, 
                            proto_tree *tree, guint8 *drep);

typedef struct _dcerpc_sub_dissector {
    guint16 num;
    const gchar   *name;
    dcerpc_dissect_fnct_t *dissect_rqst;
    dcerpc_dissect_fnct_t *dissect_resp;
} dcerpc_sub_dissector;

/* registration function for subdissectors */
void dcerpc_init_uuid (int proto, int ett, e_uuid_t *uuid, guint16 ver, dcerpc_sub_dissector *procs, int opnum_hf);
const char *dcerpc_get_proto_name(e_uuid_t *uuid, guint16 ver);
int dcerpc_get_proto_hf_opnum(e_uuid_t *uuid, guint16 ver);
dcerpc_sub_dissector *dcerpc_get_proto_sub_dissector(e_uuid_t *uuid, guint16 ver);

/* Create a opnum, name value_string from a subdissector list */

value_string *value_string_from_subdissectors(dcerpc_sub_dissector *sd);

/* try to get protocol name registered for this uuid */
const gchar *dcerpc_get_uuid_name(e_uuid_t *uuid, guint16 ver);

/* Private data passed to subdissectors from the main DCERPC dissector. */
typedef struct _dcerpc_call_value {
    e_uuid_t uuid;
    guint16 ver;
    guint16 opnum;
    guint32 req_frame;
    nstime_t req_time;
    guint32 rep_frame;
    guint32 max_ptr;
    void *private_data;
} dcerpc_call_value;

typedef struct _dcerpc_info {
	conversation_t *conv;	/* Which TCP stream we are in */
	guint32 call_id;	/* Context id for this call */
	guint16 smb_fid;	/* FID for DCERPC over SMB */
    guint8 ptype;       /* packet type: PDU_REQ, PDU_RESP, ... */
	gboolean conformant_run;
	gint32 conformant_eaten; /* how many bytes did the conformant run eat?*/
	guint32 array_max_count;	/* max_count for conformant arrays */
	guint32 array_max_count_offset;
	guint32 array_offset;
	guint32 array_offset_offset;
	guint32 array_actual_count;
	guint32 array_actual_count_offset;
	int hf_index;
	dcerpc_call_value *call_data;
	void *private_data;
} dcerpc_info;


/* the init_protocol hooks. With MSVC and a 
 * libwireshark.dll, we need a special declaration.
 */
WS_VAR_IMPORT GHookList dcerpc_hooks_init_protos;

/* the registered subdissectors. With MSVC and a 
 * libwireshark.dll, we need a special declaration.
 */
WS_VAR_IMPORT GHashTable *dcerpc_uuids;

typedef struct _dcerpc_uuid_key {
    e_uuid_t uuid;
    guint16 ver;
} dcerpc_uuid_key;

typedef struct _dcerpc_uuid_value {
    protocol_t *proto;
    int proto_id;
    int ett;
    const gchar *name;
    dcerpc_sub_dissector *procs;
    int opnum_hf;
} dcerpc_uuid_value;

/* Authenticated pipe registration functions and miscellanea */

typedef tvbuff_t *(dcerpc_decode_data_fnct_t)(tvbuff_t *data_tvb, 
					      tvbuff_t *auth_tvb,
					      int offset, 
					      packet_info *pinfo,
					      dcerpc_auth_info *auth_info);

typedef struct _dcerpc_auth_subdissector_fns {

	/* Dissect credentials and verifiers */

	dcerpc_dissect_fnct_t *bind_fn;
	dcerpc_dissect_fnct_t *bind_ack_fn;
	dcerpc_dissect_fnct_t *auth3_fn;
	dcerpc_dissect_fnct_t *req_verf_fn;
	dcerpc_dissect_fnct_t *resp_verf_fn;

	/* Decrypt encrypted requests/response PDUs */

	dcerpc_decode_data_fnct_t *req_data_fn;
	dcerpc_decode_data_fnct_t *resp_data_fn;

} dcerpc_auth_subdissector_fns;

void register_dcerpc_auth_subdissector(guint8 auth_level, guint8 auth_type,
				       dcerpc_auth_subdissector_fns *fns);

/* all values needed to (re-)build a dcerpc binding */
typedef struct decode_dcerpc_bind_values_s {
    /* values of a typical conversation */
    address addr_a;
    address addr_b;
    port_type ptype;
    guint32 port_a;
    guint32 port_b;
    /* dcerpc conversation specific */
    guint16 ctx_id;
    guint16 smb_fid;
    /* corresponding "interface" */
    GString *ifname;
    e_uuid_t uuid;
    guint16 ver;
} decode_dcerpc_bind_values_t;

/* Helper for "decode as" dialog to set up a UUID/conversation binding. */
struct _dcerpc_bind_value *
dcerpc_add_conv_to_bind_table(decode_dcerpc_bind_values_t *binding);

guint16 
dcerpc_get_transport_salt (packet_info *pinfo);

/* Authentication services */

/* 
 * For MS-specific SSPs (Security Service Provider), see
 *
 * http://msdn.microsoft.com/library/en-us/rpc/rpc/authentication_level_constants.asp
 */
 
#define DCE_C_RPC_AUTHN_PROTOCOL_NONE		0
#define DCE_C_RPC_AUTHN_PROTOCOL_KRB5		1
#define DCE_C_RPC_AUTHN_PROTOCOL_SPNEGO         9
#define DCE_C_RPC_AUTHN_PROTOCOL_NTLMSSP	10
#define DCE_C_RPC_AUTHN_PROTOCOL_GSS_SCHANNEL	14
#define DCE_C_RPC_AUTHN_PROTOCOL_GSS_KERBEROS	16
#define DCE_C_RPC_AUTHN_PROTOCOL_DPA		17
#define DCE_C_RPC_AUTHN_PROTOCOL_MSN		18
#define DCE_C_RPC_AUTHN_PROTOCOL_DIGEST		21
#define DCE_C_RPC_AUTHN_PROTOCOL_SEC_CHAN       68
#define DCE_C_RPC_AUTHN_PROTOCOL_MQ		100

/* Protection levels */

#define DCE_C_AUTHN_LEVEL_NONE		1
#define DCE_C_AUTHN_LEVEL_CONNECT	2
#define DCE_C_AUTHN_LEVEL_CALL		3
#define DCE_C_AUTHN_LEVEL_PKT		4
#define DCE_C_AUTHN_LEVEL_PKT_INTEGRITY	5
#define DCE_C_AUTHN_LEVEL_PKT_PRIVACY	6

void
init_ndr_pointer_list(packet_info *pinfo);

#endif /* packet-dcerpc.h */
