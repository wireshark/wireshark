/* packet-rpc.h
 *
 * $Id: packet-rpc.h,v 1.20 2000/11/21 14:58:07 girlich Exp $
 *
 * (c) 1999 Uwe Girlich
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
#include "packet.h"
#include "conversation.h"

#define EXTRACT_UINT(p,o)    pntohl(&p[o])

#define RPC_CALL 0
#define RPC_REPLY 1

#define AUTH_NULL 0
#define AUTH_UNIX 1
#define AUTH_SHORT 2
#define AUTH_DES 3
#define RPCSEC_GSS 6

#define MSG_ACCEPTED 0
#define MSG_DENIED 1

#define SUCCESS 0
#define PROG_UNAVAIL 1
#define PROG_MISMATCH 2
#define PROC_UNAVAIL 3
#define GARBAGE_ARGS 4

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

#define RPCSEC_GSS_SVC_NONE 1
#define RPCSEC_GSS_SVC_INTEGRITY 2
#define RPCSEC_GSS_SVC_PRIVACY 3

typedef int (dissect_function_t)(const u_char* pd, int offset, frame_data* fd, proto_tree* tree);

typedef struct _vsff {
	guint32	value;
	gchar   *strptr;
	dissect_function_t *dissect_call;
	dissect_function_t *dissect_reply;
} vsff;

typedef struct _rpc_proc_info_key {
	guint32	prog;
	guint32	vers;
	guint32	proc;
} rpc_proc_info_key;

typedef struct _rpc_proc_info_value {
	gchar		*name;
	dissect_function_t	*dissect_call;
	dissect_function_t	*dissect_reply;
} rpc_proc_info_value;

typedef struct _rpc_prog_info_key {
	guint32 prog;
} rpc_prog_info_key;

typedef struct _rpc_prog_info_value {
	int proto;
	int ett;
	char* progname;
} rpc_prog_info_value;

extern const value_string rpc_auth_flavor[];

extern void rpc_init_proc_table(guint prog, guint vers, const vsff *proc_table);
extern void rpc_init_prog(int proto, guint32 prog, int ett);
extern char *rpc_prog_name(guint32 prog);

extern void init_dissect_rpc();
extern void cleanup_dissect_rpc();

extern unsigned int rpc_roundup(unsigned int a);
extern gboolean dissect_rpc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern int dissect_rpc_bool(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, int hfindex);
extern int dissect_rpc_bool_tvb(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int hfindex, int offset);
extern int dissect_rpc_string(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, int hfindex, char **string_buffer_ret);
extern int dissect_rpc_string_tvb(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int hfindex, int offset, char **string_buffer_ret);
extern int dissect_rpc_data(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, int hfindex);
extern int dissect_rpc_data_tvb(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int hfindex, int offset);
extern int dissect_rpc_list(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, dissect_function_t *rpc_list_dissector);
extern int dissect_rpc_uint32(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char* name);
extern int dissect_rpc_uint32_tvb(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int hfindex, int offset);
extern int dissect_rpc_uint64(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char* name);
extern int dissect_rpc_uint64_tvb(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int hfindex, int offset);


#endif /* packet-rpc.h */

