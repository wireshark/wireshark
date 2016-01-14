/* packet-rpc.h
 *
 * (c) 1999 Uwe Girlich
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

#ifndef __PACKET_RPC_H__
#define __PACKET_RPC_H__

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define RPC_CALL 0
#define RPC_REPLY 1

#define AUTH_NULL 0
#define AUTH_UNIX 1
#define AUTH_SHORT 2
#define AUTH_DES 3
#define AUTH_KRB4 4
#define AUTH_RSA 5
#define RPCSEC_GSS 6
#define AUTH_GSSAPI 300001
/* Pseudo-flavors used for security mechanisms while using
 * RPCSEC_GSS
 */
#define RPCSEC_GSS_KRB5 390003
#define RPCSEC_GSS_KRB5I 390004
#define RPCSEC_GSS_KRB5P 390005
#define RPCSEC_GSS_LIPKEY 390006
#define RPCSEC_GSS_LIPKEY_I 390007
#define RPCSEC_GSS_LIPKEY_P 390008
#define RPCSEC_GSS_SPKM3 390009
#define RPCSEC_GSS_SPKM3I 390010
#define RPCSEC_GSS_SPKM3P 390011
/* GlusterFS requested an RPC-AUTH number from IANA,
 * until a number has been granted 390039 is used.
 * See also: http://review.gluster.com/3230
 */
#define AUTH_GLUSTERFS 390039

#define MSG_ACCEPTED 0
#define MSG_DENIED 1

#define SUCCESS 0
#define PROG_UNAVAIL 1
#define PROG_MISMATCH 2
#define PROC_UNAVAIL 3
#define GARBAGE_ARGS 4
#define SYSTEM_ERROR 5

#define RPC_MISMATCH 0
#define AUTH_ERROR 1

#define AUTH_BADCRED 1
#define AUTH_REJECTEDCRED 2
#define AUTH_BADVERF 3
#define AUTH_REJECTEDVERF 4
#define AUTH_TOOWEAK 5
#define RPCSEC_GSSCREDPROB 13
#define RPCSEC_GSSCTXPROB 14

#define RPCSEC_GSS_DATA 0
#define RPCSEC_GSS_INIT 1
#define RPCSEC_GSS_CONTINUE_INIT 2
#define RPCSEC_GSS_DESTROY 3

#define	AUTH_GSSAPI_EXIT 0
#define	AUTH_GSSAPI_INIT 1
#define	AUTH_GSSAPI_CONTINUE_INIT 2
#define	AUTH_GSSAPI_MSG 3
#define	AUTH_GSSAPI_DESTROY 4

#define RPCSEC_GSS_SVC_NONE 1
#define RPCSEC_GSS_SVC_INTEGRITY 2
#define RPCSEC_GSS_SVC_PRIVACY 3

#define AUTHDES_NAMEKIND_FULLNAME 0
#define AUTHDES_NAMEKIND_NICKNAME 1

#define RPC_STRING_EMPTY "<EMPTY>"
#define RPC_STRING_DATA "<DATA>"
#define RPC_STRING_TRUNCATED "<TRUNCATED>"

#define RPC_RM_LASTFRAG	0x80000000U
#define RPC_RM_FRAGLEN	0x7fffffffU

extern const value_string rpc_authgss_svc[];
typedef enum {
	FLAVOR_UNKNOWN,		/* authentication flavor unknown */
	FLAVOR_NOT_GSSAPI,	/* flavor isn't GSSAPI */
	FLAVOR_GSSAPI_NO_INFO,	/* flavor is GSSAPI, procedure & service unknown */
	FLAVOR_GSSAPI,		/* flavor is GSSAPI, procedure & service known */
	FLAVOR_AUTHGSSAPI,	/* AUTH_GSSAPI flavor */
	FLAVOR_AUTHGSSAPI_MSG	/* AUTH_GSSAPI flavor, AUTH_GSSAPI message */
} flavor_t;

typedef struct _rpc_call_info_value {
	guint32	req_num;	/* frame number of first request seen */
	guint32	rep_num;	/* frame number of first reply seen */
	guint32	prog;
	guint32	vers;
	guint32	proc;
	guint32	xid;
	flavor_t flavor;
	guint32 gss_proc;
	guint32 gss_svc;
	gboolean request;	/* Is this a request or not ?*/
	nstime_t req_time;
	void *private_data;
} rpc_call_info_value;


typedef int (dissect_function_t)(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree* tree, void* data);

/*
 * Information about a particular version of a program.
 */
typedef struct _vsff {
	guint32	value;
	const gchar   *strptr;
	dissector_t dissect_call;
	dissector_t dissect_reply;
} vsff;

typedef struct _rpc_proc_list {
	guint vers;
	const vsff *proc_table;
	int *procedure_hf;
} rpc_prog_vers_info;

extern const value_string rpc_auth_flavor[];

WS_DLL_PUBLIC void rpc_init_prog(int proto, guint32 prog, int ett, size_t nvers,
    const rpc_prog_vers_info *versions);
WS_DLL_PUBLIC const char *rpc_prog_name(guint32 prog);
WS_DLL_PUBLIC const char *rpc_proc_name(guint32 prog, guint32 vers, guint32 proc);
WS_DLL_PUBLIC int rpc_prog_hf(guint32 prog, guint32 vers);

WS_DLL_PUBLIC unsigned int rpc_roundup(unsigned int a);
WS_DLL_PUBLIC int dissect_rpc_void(tvbuff_t *tvb,
        packet_info *pinfo, proto_tree *tree, void *data);
WS_DLL_PUBLIC int dissect_rpc_unknown(tvbuff_t *tvb,
        packet_info *pinfo, proto_tree *tree, void *data);
WS_DLL_PUBLIC int dissect_rpc_bool(tvbuff_t *tvb,
	proto_tree *tree, int hfindex, int offset);
WS_DLL_PUBLIC int dissect_rpc_string(tvbuff_t *tvb,
	proto_tree *tree, int hfindex, int offset, const char **string_buffer_ret);
WS_DLL_PUBLIC
int dissect_rpc_opaque_data(tvbuff_t *tvb, int offset,
    proto_tree *tree,
    packet_info *pinfo,
    int hfindex,
    gboolean fixed_length, guint32 length,
    gboolean string_data, const char **string_buffer_ret,
    dissect_function_t *dissect_it);
WS_DLL_PUBLIC int dissect_rpc_data(tvbuff_t *tvb,
	proto_tree *tree, int hfindex, int offset);
WS_DLL_PUBLIC int dissect_rpc_bytes(tvbuff_t *tvb,
	proto_tree *tree, int hfindex, int offset, guint32 length,
	gboolean string_data, const char **string_buffer_ret);
WS_DLL_PUBLIC int dissect_rpc_list(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int offset, dissect_function_t *rpc_list_dissector,
	void *data);
WS_DLL_PUBLIC int dissect_rpc_array(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int offset, dissect_function_t *rpc_array_dissector,
	int hfindex);
WS_DLL_PUBLIC int dissect_rpc_uint32(tvbuff_t *tvb,
	proto_tree *tree, int hfindex, int offset);
WS_DLL_PUBLIC int dissect_rpc_uint64(tvbuff_t *tvb,
	proto_tree *tree, int hfindex, int offset);

WS_DLL_PUBLIC int dissect_rpc_indir_call(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int offset, int args_id, guint32 prog, guint32 vers,
	guint32 proc);
WS_DLL_PUBLIC int dissect_rpc_indir_reply(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int offset, int result_id, int prog_id, int vers_id,
	int proc_id);
WS_DLL_PUBLIC int dissect_rpc_opaque_auth(tvbuff_t* tvb, proto_tree* tree,
	int offset, packet_info *pinfo);

typedef struct _rpc_prog_info_value {
	protocol_t *proto;
	int proto_id;
	int ett;
	const char* progname;
	GArray *procedure_hfs; /* int */
} rpc_prog_info_value;

/* rpc_progs is also used in tap. With MSVC and a
 * libwireshark.dll, we need a special declaration.
 */
/* Key: Program number (guint32)
 * Value: rpc_prog_info_value *
 */
WS_DLL_PUBLIC GHashTable *rpc_progs;

typedef struct _rpc_proc_info_key {
	guint32	prog;
	guint32	vers;
	guint32	proc;
} rpc_proc_info_key;

typedef struct rpcstat_tap_data
{
	const char *prog;
	guint32 program;
	guint32 version;
	int num_procedures;
} rpcstat_tap_data_t;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* packet-rpc.h */
