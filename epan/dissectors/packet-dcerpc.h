/* packet-dcerpc.h
 * Copyright 2001, Todd Sabin <tas@webspan.net>
 * Copyright 2003, Tim Potter <tpot@samba.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_DCERPC_H__
#define __PACKET_DCERPC_H__

#include <epan/conversation.h>
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define DCERPC_TABLE_NAME "dcerpc.uuid"
/*
 * Data representation.
 */
#define DREP_LITTLE_ENDIAN	0x10

#define DREP_EBCDIC		0x01

/*
 * Data representation to integer byte order.
 */
#define DREP_ENC_INTEGER(drep)	\
	(((drep)[0] & DREP_LITTLE_ENDIAN) ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN)

/*
 * Data representation to (octet-string) character encoding.
 */
#define DREP_ENC_CHAR(drep)	\
	(((drep)[0] & DREP_EBCDIC) ? ENC_EBCDIC|ENC_NA : ENC_ASCII|ENC_NA)

#ifdef PT_R4
/* now glib always includes signal.h and on linux PPC
 * signal.h defines PT_R4
*/
#undef PT_R4
#endif

#define DCERPC_UUID_NULL { 0,0,0, {0,0,0,0,0,0,0,0} }

/* %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x */
#define DCERPC_UUID_STR_LEN 36+1

typedef struct _e_ctx_hnd {
    uint32_t attributes;
    e_guid_t uuid;
} e_ctx_hnd;

typedef struct _e_dce_cn_common_hdr_t {
    uint8_t rpc_ver;
    uint8_t rpc_ver_minor;
    uint8_t ptype;
    uint8_t flags;
    uint8_t drep[4];
    uint16_t frag_len;
    uint16_t auth_len;
    uint32_t call_id;
} e_dce_cn_common_hdr_t;

typedef struct _e_dce_dg_common_hdr_t {
    uint8_t rpc_ver;
    uint8_t ptype;
    uint8_t flags1;
    uint8_t flags2;
    uint8_t drep[3];
    uint8_t serial_hi;
    e_guid_t obj_id;
    e_guid_t if_id;
    e_guid_t act_id;
    uint32_t server_boot;
    uint32_t if_ver;
    uint32_t seqnum;
    uint16_t opnum;
    uint16_t ihint;
    uint16_t ahint;
    uint16_t frag_len;
    uint16_t frag_num;
    uint8_t auth_proto;
    uint8_t serial_lo;
} e_dce_dg_common_hdr_t;

struct _dcerpc_auth_subdissector_fns;

typedef struct _dcerpc_auth_info {
  bool hdr_signing;
  uint8_t auth_type;
  uint8_t auth_level;
  uint32_t auth_context_id;
  uint8_t auth_pad_len;
  uint32_t auth_size;
  struct _dcerpc_auth_subdissector_fns *auth_fns;
  tvbuff_t *auth_hdr_tvb;
  tvbuff_t *auth_tvb;
  proto_item *auth_item;
  proto_tree *auth_tree;
} dcerpc_auth_info;

typedef struct dcerpcstat_tap_data
{
	const char *prog;
	e_guid_t uuid;
	uint16_t ver;
	int num_procedures;
} dcerpcstat_tap_data_t;

/* Private data passed to subdissectors from the main DCERPC dissector.
 * One unique instance of this structure is created for each
 * DCERPC request/response transaction when we see the initial request
 * of the transaction.
 * These instances are persistent and will remain available until the
 * capture file is closed and a new one is read.
 *
 * For transactions where we never saw the request (missing from the trace)
 * the dcerpc runtime will create a temporary "fake" such structure to pass
 * to the response dissector. These fake structures are not persistent
 * and can not be used to keep data hanging around.
 */
typedef struct _dcerpc_call_value {
    e_guid_t uuid;          /* interface UUID */
    uint16_t ver;            /* interface version */
    e_guid_t object_uuid;   /* optional object UUID (or DCERPC_UUID_NULL) */
    uint16_t opnum;
    uint32_t req_frame;
    nstime_t req_time;
    uint32_t rep_frame;
    uint32_t max_ptr;
    void *se_data;          /* This holds any data with se allocation scope
                             * that we might want to keep
                             * for this request/response transaction.
                             * The pointer is initialized to NULL and must be
                             * checked before being dereferenced.
                             * This is useful for such things as when we
                             * need to pass persistent data from the request
                             * to the reply, such as LSA/OpenPolicy2() that
                             * uses this to pass the domain name from the
                             * request to the reply.
                             */
    void *private_data;      /* XXX This will later be renamed as ep_data */
    e_ctx_hnd *pol;	     /* policy handle tracked between request/response*/
#define DCERPC_IS_NDR64 0x00000001
    uint32_t flags;	     /* flags for this transaction */
} dcerpc_call_value;

typedef struct _dcerpc_info {
	conversation_t *conv;	/* Which TCP stream we are in */
	uint32_t call_id;	/* Call ID for this call */
	uint64_t transport_salt; /* e.g. FID for DCERPC over SMB */
	uint8_t ptype;       /* packet type: PDU_REQ, PDU_RESP, ... */
	bool conformant_run;
	bool no_align; /* are data aligned? (default yes) */
	int32_t conformant_eaten; /* how many bytes did the conformant run eat?*/
	uint32_t array_max_count;	/* max_count for conformant arrays */
	uint32_t array_max_count_offset;
	uint32_t array_offset;
	uint32_t array_offset_offset;
	uint32_t array_actual_count;
	uint32_t array_actual_count_offset;
	int hf_index;
	dcerpc_call_value *call_data;
    const char *dcerpc_procedure_name;	/* Used by PIDL to store the name of the current dcerpc procedure */
	struct _dcerpc_auth_info *auth_info;
	void *private_data;

	/* ndr pointer handling */
	struct {
		/* Should we re-read the size of the list ?
		 * Instead of re-calculating the size every time, use the stored value unless this
		 * flag is set which means: re-read the size of the list
		 */
		bool must_check_size;
		/*
		 * List of pointers encountered so far in the current level. Points to an
		 * element of list_ndr_pointer_list.
		 */
		GSList *list;
		GHashTable *hash;
		/*
		 * List of pointer list, in order to avoid huge performance penalty
		 * when dealing with list bigger than 100 elements due to the way we
		 * try to insert in the list.
		 * We instead maintain a stack of pointer list
		 * To make it easier to manage we just use a list to materialize the stack
		 */
		GSList *list_list;

		/* Boolean controlling whether pointers are top-level or embedded */
		bool are_top_level;
	} pointers;
} dcerpc_info;

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
#define PDU_RTS        20

/*
 * helpers for packet-dcerpc.c and packet-dcerpc-ndr.c
 * If you're writing a subdissector, you almost certainly want the
 * NDR functions below.
 */
uint16_t dcerpc_tvb_get_ntohs (tvbuff_t *tvb, int offset, uint8_t *drep);
uint32_t dcerpc_tvb_get_ntohl (tvbuff_t *tvb, int offset, uint8_t *drep);
void dcerpc_tvb_get_uuid (tvbuff_t *tvb, int offset, uint8_t *drep, e_guid_t *uuid);
WS_DLL_PUBLIC
int dissect_dcerpc_char (tvbuff_t *tvb, int offset, packet_info *pinfo,
                         proto_tree *tree, uint8_t *drep,
                         int hfindex, uint8_t *pdata);
WS_DLL_PUBLIC
int dissect_dcerpc_uint8 (tvbuff_t *tvb, int offset, packet_info *pinfo,
                          proto_tree *tree, uint8_t *drep,
                          int hfindex, uint8_t *pdata);
WS_DLL_PUBLIC
int dissect_dcerpc_uint16 (tvbuff_t *tvb, int offset, packet_info *pinfo,
                           proto_tree *tree, uint8_t *drep,
                           int hfindex, uint16_t *pdata);
WS_DLL_PUBLIC
int dissect_dcerpc_uint32 (tvbuff_t *tvb, int offset, packet_info *pinfo,
                           proto_tree *tree, uint8_t *drep,
                           int hfindex, uint32_t *pdata);
WS_DLL_PUBLIC
int dissect_dcerpc_uint64 (tvbuff_t *tvb, int offset, packet_info *pinfo,
                           proto_tree *tree, dcerpc_info *di, uint8_t *drep,
                           int hfindex, uint64_t *pdata);
int dissect_dcerpc_float  (tvbuff_t *tvb, int offset, packet_info *pinfo,
                           proto_tree *tree, uint8_t *drep,
                           int hfindex, float *pdata);
int dissect_dcerpc_double (tvbuff_t *tvb, int offset, packet_info *pinfo,
                           proto_tree *tree, uint8_t *drep,
                           int hfindex, double *pdata);
int dissect_dcerpc_time_t (tvbuff_t *tvb, int offset, packet_info *pinfo,
                           proto_tree *tree, uint8_t *drep,
                           int hfindex, uint32_t *pdata);
WS_DLL_PUBLIC
int dissect_dcerpc_uuid_t (tvbuff_t *tvb, int offset, packet_info *pinfo,
                           proto_tree *tree, uint8_t *drep,
                           int hfindex, e_guid_t *pdata);

/*
 * NDR routines for subdissectors.
 */
WS_DLL_PUBLIC
int dissect_ndr_uint8 (tvbuff_t *tvb, int offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, uint8_t *drep,
                       int hfindex, uint8_t *pdata);
int PIDL_dissect_uint8 (tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep, int hfindex, uint32_t param);
int PIDL_dissect_uint8_val (tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep, int hfindex, uint32_t param, uint8_t *pval);
WS_DLL_PUBLIC
int dissect_ndr_uint16 (tvbuff_t *tvb, int offset, packet_info *pinfo,
                        proto_tree *tree, dcerpc_info *di, uint8_t *drep,
                        int hfindex, uint16_t *pdata);
int PIDL_dissect_uint16 (tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep, int hfindex, uint32_t param);
int PIDL_dissect_uint16_val (tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep, int hfindex, uint32_t param, uint16_t *pval);
WS_DLL_PUBLIC
int dissect_ndr_uint32 (tvbuff_t *tvb, int offset, packet_info *pinfo,
                        proto_tree *tree, dcerpc_info *di, uint8_t *drep,
                        int hfindex, uint32_t *pdata);
int PIDL_dissect_uint32 (tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep, int hfindex, uint32_t param);
int PIDL_dissect_uint32_val (tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep, int hfindex, uint32_t param, uint32_t *rval);
WS_DLL_PUBLIC
int dissect_ndr_duint32 (tvbuff_t *tvb, int offset, packet_info *pinfo,
                        proto_tree *tree, dcerpc_info *di, uint8_t *drep,
                        int hfindex, uint64_t *pdata);
WS_DLL_PUBLIC
int dissect_ndr_uint64 (tvbuff_t *tvb, int offset, packet_info *pinfo,
                        proto_tree *tree, dcerpc_info *di, uint8_t *drep,
                        int hfindex, uint64_t *pdata);
int PIDL_dissect_uint64 (tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep, int hfindex, uint32_t param);
int PIDL_dissect_uint64_val (tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep, int hfindex, uint32_t param, uint64_t *pval);
WS_DLL_PUBLIC
int dissect_ndr_float (tvbuff_t *tvb, int offset, packet_info *pinfo,
                        proto_tree *tree, dcerpc_info *di, uint8_t *drep,
                        int hfindex, float *pdata);
WS_DLL_PUBLIC
int dissect_ndr_double (tvbuff_t *tvb, int offset, packet_info *pinfo,
                        proto_tree *tree, dcerpc_info *di, uint8_t *drep,
                        int hfindex, double *pdata);

WS_DLL_PUBLIC
int dissect_ndr_time_t (tvbuff_t *tvb, int offset, packet_info *pinfo,
                        proto_tree *tree, dcerpc_info *di, uint8_t *drep,
                        int hfindex, uint32_t *pdata);
WS_DLL_PUBLIC
int dissect_ndr_uuid_t (tvbuff_t *tvb, int offset, packet_info *pinfo,
                        proto_tree *tree, dcerpc_info *di, uint8_t *drep,
                        int hfindex, e_guid_t *pdata);
int dissect_ndr_ctx_hnd (tvbuff_t *tvb, int offset, packet_info *pinfo,
                        proto_tree *tree, dcerpc_info *di, uint8_t *drep,
                        int hfindex, e_ctx_hnd *pdata);

#define FT_UINT1632 FT_UINT32
typedef uint32_t uint1632_t;

WS_DLL_PUBLIC
int dissect_ndr_uint1632 (tvbuff_t *tvb, int offset, packet_info *pinfo,
		        proto_tree *tree, dcerpc_info *di, uint8_t *drep,
		        int hfindex, uint1632_t *pdata);

typedef uint64_t uint3264_t;

WS_DLL_PUBLIC
int dissect_ndr_uint3264 (tvbuff_t *tvb, int offset, packet_info *pinfo,
		        proto_tree *tree, dcerpc_info *di, uint8_t *drep,
		        int hfindex, uint3264_t *pdata);

typedef int (dcerpc_dissect_fnct_t)(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep);
typedef int (dcerpc_dissect_fnct_blk_t)(tvbuff_t *tvb, int offset, int length, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep);

typedef void (dcerpc_callback_fnct_t)(packet_info *pinfo, proto_tree *tree, proto_item *item, dcerpc_info *di, tvbuff_t *tvb, int start_offset, int end_offset, void *callback_args);

#define NDR_POINTER_REF		1
#define NDR_POINTER_UNIQUE	2
#define NDR_POINTER_PTR		3

int dissect_ndr_pointer_cb(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, dcerpc_info *di, uint8_t *drep,
			   dcerpc_dissect_fnct_t *fnct, int type, const char *text,
			   int hf_index, dcerpc_callback_fnct_t *callback,
			   void *callback_args);

int dissect_ndr_pointer(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, dcerpc_info *di, uint8_t *drep,
			dcerpc_dissect_fnct_t *fnct, int type, const char *text,
			int hf_index);
int dissect_deferred_pointers(packet_info *pinfo, tvbuff_t *tvb, int offset, dcerpc_info *di, uint8_t *drep);
int dissect_ndr_embedded_pointer(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, dcerpc_info *di, uint8_t *drep,
			dcerpc_dissect_fnct_t *fnct, int type, const char *text,
			int hf_index);
int dissect_ndr_toplevel_pointer(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, dcerpc_info *di, uint8_t *drep,
			dcerpc_dissect_fnct_t *fnct, int type, const char *text,
			int hf_index);

/* dissect a NDR unidimensional conformant array */
int dissect_ndr_ucarray(tvbuff_t *tvb, int offset, packet_info *pinfo,
                        proto_tree *tree, dcerpc_info *di, uint8_t *drep,
                        dcerpc_dissect_fnct_t *fnct);

int dissect_ndr_ucarray_block(tvbuff_t *tvb, int offset, packet_info *pinfo,
                              proto_tree *tree, dcerpc_info *di, uint8_t *drep,
                              dcerpc_dissect_fnct_blk_t *fnct);

/* dissect a NDR unidimensional conformant and varying array
 * each byte in the array is processed separately
 */
int dissect_ndr_ucvarray(tvbuff_t *tvb, int offset, packet_info *pinfo,
                         proto_tree *tree, dcerpc_info *di, uint8_t *drep,
                         dcerpc_dissect_fnct_t *fnct);

int dissect_ndr_ucvarray_block(tvbuff_t *tvb, int offset, packet_info *pinfo,
                               proto_tree *tree, dcerpc_info *di, uint8_t *drep,
                               dcerpc_dissect_fnct_blk_t *fnct);

/* dissect a NDR unidimensional varying array */
int dissect_ndr_uvarray(tvbuff_t *tvb, int offset, packet_info *pinfo,
                        proto_tree *tree, dcerpc_info *di, uint8_t *drep,
                        dcerpc_dissect_fnct_t *fnct);

int dissect_ndr_byte_array(tvbuff_t *tvb, int offset, packet_info *pinfo,
                           proto_tree *tree, dcerpc_info *di, uint8_t *drep);

int dissect_ndr_cvstring(tvbuff_t *tvb, int offset, packet_info *pinfo,
			 proto_tree *tree, dcerpc_info *di, uint8_t *drep, int size_is,
			 int hfinfo, bool add_subtree,
			 char **data);
int dissect_ndr_char_cvstring(tvbuff_t *tvb, int offset, packet_info *pinfo,
                           proto_tree *tree, dcerpc_info *di, uint8_t *drep);
int dissect_ndr_wchar_cvstring(tvbuff_t *tvb, int offset, packet_info *pinfo,
                            proto_tree *tree, dcerpc_info *di, uint8_t *drep);
int PIDL_dissect_cvstring(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep, int chsize, int hfindex, uint32_t param);

int dissect_ndr_cstring(tvbuff_t *tvb, int offset, packet_info *pinfo,
                        proto_tree *tree, dcerpc_info *di, uint8_t *drep, int size_is,
                        int hfindex, bool add_subtree, char **data);
int dissect_ndr_vstring(tvbuff_t *tvb, int offset, packet_info *pinfo,
			 proto_tree *tree, dcerpc_info *di, uint8_t *drep, int size_is,
			 int hfinfo, bool add_subtree,
			 char **data);
int dissect_ndr_char_vstring(tvbuff_t *tvb, int offset, packet_info *pinfo,
                           proto_tree *tree, dcerpc_info *di, uint8_t *drep);
int dissect_ndr_wchar_vstring(tvbuff_t *tvb, int offset, packet_info *pinfo,
                            proto_tree *tree, dcerpc_info *di, uint8_t *drep);

typedef struct _dcerpc_sub_dissector {
    uint16_t num;
    const char    *name;
    dcerpc_dissect_fnct_t *dissect_rqst;
    dcerpc_dissect_fnct_t *dissect_resp;
} dcerpc_sub_dissector;

/* registration function for subdissectors */
WS_DLL_PUBLIC
void dcerpc_init_uuid (int proto, int ett, e_guid_t *uuid, uint16_t ver, const dcerpc_sub_dissector *procs, int opnum_hf);
WS_DLL_PUBLIC
void dcerpc_init_from_handle(int proto, e_guid_t *uuid, uint16_t ver, dissector_handle_t guid_handle);
WS_DLL_PUBLIC
const char *dcerpc_get_proto_name(e_guid_t *uuid, uint16_t ver);
WS_DLL_PUBLIC
int dcerpc_get_proto_hf_opnum(e_guid_t *uuid, uint16_t ver);
WS_DLL_PUBLIC
const dcerpc_sub_dissector *dcerpc_get_proto_sub_dissector(e_guid_t *uuid, uint16_t ver);

/* Create a opnum, name value_string from a subdissector list */

value_string *value_string_from_subdissectors(const dcerpc_sub_dissector *sd);

/* Decode As... functionality */
typedef void (*decode_add_show_list_func)(void *data, void *user_data);
WS_DLL_PUBLIC void decode_dcerpc_add_show_list(decode_add_show_list_func func, void *user_data);


typedef struct _dcerpc_uuid_value {
    protocol_t *proto;
    int proto_id;
    int ett;
    const char *name;
    const dcerpc_sub_dissector *procs;
    int opnum_hf;
} dcerpc_uuid_value;

/* Authenticated pipe registration functions and miscellanea */

typedef tvbuff_t *(dcerpc_decode_data_fnct_t)(tvbuff_t *header_tvb,
					      tvbuff_t *payload_tvb,
					      tvbuff_t *trailer_tvb,
					      tvbuff_t *auth_tvb,
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

void register_dcerpc_auth_subdissector(uint8_t auth_level, uint8_t auth_type,
				       dcerpc_auth_subdissector_fns *fns);

/* all values needed to (re-)build a dcerpc binding */
typedef struct decode_dcerpc_bind_values_s {
    /* values of a typical conversation */
    address addr_a;
    address addr_b;
    port_type ptype;
    uint32_t port_a;
    uint32_t port_b;
    /* dcerpc conversation specific */
    uint16_t ctx_id;
    uint64_t transport_salt;
    /* corresponding "interface" */
    GString *ifname;
    e_guid_t uuid;
    uint16_t ver;
} decode_dcerpc_bind_values_t;

WS_DLL_PUBLIC uint64_t dcerpc_get_transport_salt(packet_info *pinfo);
WS_DLL_PUBLIC void dcerpc_set_transport_salt(uint64_t dcetransportsalt, packet_info *pinfo);

/* Authentication services */

/*
 * For MS-specific SSPs (Security Service Provider), see
 *
 *     https://docs.microsoft.com/en-us/windows/win32/rpc/authentication-level-constants
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
free_ndr_pointer_list(dcerpc_info *di);
void
init_ndr_pointer_list(dcerpc_info *di);



/* These defines are used in the PIDL conformance files when using
 * the PARAM_VALUE directive.
 */
/* Policy handle tracking. Describes in which function a handle is
 * opened/closed.  See "winreg.cnf" for example.
 *
 * The uint32_t param is divided up into multiple fields
 *
 * +--------+--------+--------+--------+
 * | Flags  | Type   |        |        |
 * +--------+--------+--------+--------+
 */
/* Flags : */
#define PIDL_POLHND_OPEN		0x80000000
#define PIDL_POLHND_CLOSE		0x40000000
#define PIDL_POLHND_USE			0x00000000 /* just use, not open or cose */
/* To "save" a pointer to the string in dcv->private_data */
#define PIDL_STR_SAVE			0x20000000
/* To make this value appear on the summary line for the packet */
#define PIDL_SET_COL_INFO		0x10000000

/* Type */
#define PIDL_POLHND_TYPE_MASK		0x00ff0000
#define PIDL_POLHND_TYPE_SAMR_USER	0x00010000
#define PIDL_POLHND_TYPE_SAMR_CONNECT	0x00020000
#define PIDL_POLHND_TYPE_SAMR_DOMAIN	0x00030000
#define PIDL_POLHND_TYPE_SAMR_GROUP	0x00040000
#define PIDL_POLHND_TYPE_SAMR_ALIAS	0x00050000

#define PIDL_POLHND_TYPE_LSA_POLICY	0x00060000
#define PIDL_POLHND_TYPE_LSA_ACCOUNT	0x00070000
#define PIDL_POLHND_TYPE_LSA_SECRET	0x00080000
#define PIDL_POLHND_TYPE_LSA_DOMAIN	0x00090000

/* a structure we store for all policy handles we track */
typedef struct pol_value {
	struct pol_value *next;          /* Next entry in hash bucket */
	uint32_t open_frame, close_frame; /* Frame numbers for open/close */
	uint32_t first_frame;             /* First frame in which this instance was seen */
	uint32_t last_frame;              /* Last frame in which this instance was seen */
	char *name;			 /* Name of policy handle */
	uint32_t type;			 /* policy handle type */
} pol_value;


extern int hf_dcerpc_drep_byteorder;
extern int hf_dcerpc_ndr_padding;

#define FAKE_DCERPC_INFO_STRUCTURE      \
    /* Fake dcerpc_info structure */    \
    dcerpc_info di;                     \
    dcerpc_call_value call_data;        \
                                        \
    di.conformant_run = false;          \
    di.no_align = true;                 \
                                        \
	/* we need di->call_data->flags.NDR64 == 0 */  \
    call_data.flags = 0;                \
	di.call_data = &call_data;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* packet-dcerpc.h */
