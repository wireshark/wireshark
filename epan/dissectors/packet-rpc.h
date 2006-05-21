/* packet-rpc.h
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __PACKET_RPC_H__
#define __PACKET_RPC_H__

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#define RPC_CALL 0
#define RPC_REPLY 1

#define AUTH_NULL 0
#define AUTH_UNIX 1
#define AUTH_SHORT 2
#define AUTH_DES 3
#define RPCSEC_GSS 6
#define AUTH_GSSAPI 300001

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

extern value_string rpc_authgss_svc[];
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
	struct _rpc_proc_info_value*	proc_info;
	gboolean request;	/* Is this a request or not ?*/
	nstime_t req_time;
	void *private_data;
} rpc_call_info_value;


typedef int (dissect_function_t)(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree* tree);

typedef struct _vsff {
	guint32	value;
	const gchar   *strptr;
	dissect_function_t *dissect_call;
	dissect_function_t *dissect_reply;
} vsff;

extern const value_string rpc_auth_flavor[];

extern void rpc_init_proc_table(guint prog, guint vers, const vsff *proc_table,
    int procedure_hf);
extern void rpc_init_prog(int proto, guint32 prog, int ett);
extern const char *rpc_prog_name(guint32 prog);
extern const char *rpc_proc_name(guint32 prog, guint32 vers, guint32 proc);
extern int rpc_prog_hf(guint32 prog, guint32 vers);

extern unsigned int rpc_roundup(unsigned int a);
extern int dissect_rpc_bool(tvbuff_t *tvb,
	proto_tree *tree, int hfindex, int offset);
extern int dissect_rpc_string(tvbuff_t *tvb,
	proto_tree *tree, int hfindex, int offset, char **string_buffer_ret);
int dissect_rpc_opaque_data(tvbuff_t *tvb, int offset,
    proto_tree *tree,
    packet_info *pinfo,
    int hfindex,
    gboolean fixed_length, guint32 length,
    gboolean string_data, char **string_buffer_ret,
    dissect_function_t *dissect_it);
extern int dissect_rpc_data(tvbuff_t *tvb,
	proto_tree *tree, int hfindex, int offset);
extern int dissect_rpc_bytes(tvbuff_t *tvb,
	proto_tree *tree, int hfindex, int offset, guint32 length,
	gboolean string_data, char **string_buffer_ret);
extern int dissect_rpc_list(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int offset, dissect_function_t *rpc_list_dissector);
extern int dissect_rpc_array(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int offset, dissect_function_t *rpc_array_dissector,
	int hfindex);
extern int dissect_rpc_uint32(tvbuff_t *tvb,
	proto_tree *tree, int hfindex, int offset);
extern int dissect_rpc_uint64(tvbuff_t *tvb,
	proto_tree *tree, int hfindex, int offset);

extern int dissect_rpc_indir_call(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int offset, int args_id, guint32 prog, guint32 vers,
	guint32 proc);
extern int dissect_rpc_indir_reply(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int offset, int result_id, int prog_id, int vers_id,
	int proc_id);


typedef struct _rpc_prog_info_key {
	guint32 prog;
} rpc_prog_info_key;

typedef struct _rpc_prog_info_value {
	protocol_t *proto;
	int proto_id;
	int ett;
	const char* progname;
	GArray *procedure_hfs;
} rpc_prog_info_value;

/* rpc_progs is also used in tap. With MSVC and a 
 * libwireshark.dll, we need a special declaration.
 */
ETH_VAR_IMPORT GHashTable *rpc_progs;

typedef struct _rpc_proc_info_key {
	guint32	prog;
	guint32	vers;
	guint32	proc;
} rpc_proc_info_key;

typedef struct _rpc_proc_info_value {
	const gchar	*name;
	dissect_function_t *dissect_call;
	dissect_function_t *dissect_reply;
} rpc_proc_info_value;

/* rpc_procs is also used in tap. With MSVC and a 
 * libwireshark.dll, we need a special declaration.
 */
ETH_VAR_IMPORT GHashTable *rpc_procs;

#endif /* packet-rpc.h */

