/* packet-rpc.h (c) 1999 Uwe Girlich */
/* $Id: packet-rpc.h,v 1.2 1999/11/05 07:16:23 guy Exp $ */

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

#define MSG_ACCEPTED 0
#define MSG_DENIED 1

#define AUTH_NULL 0
#define AUTH_UNIX 1
#define AUTH_SHORT 2
#define AUTH_DES 3

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

typedef int (dissect_function_t)(const u_char* pd, int offset, frame_data* fd, proto_tree* tree);

extern GHashTable *rpc_progs;

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

typedef struct _rpc_call_info {
	guint32	xid;
	conversation_t *conversation;
	guint32	replies;
	guint32	prog;
	guint32	vers;
	guint32	proc;
	rpc_proc_info_value*	proc_info;
} rpc_call_info;

#define RPC_CALL_TABLE_LENGTH 1000

extern void rpc_call_insert(rpc_call_info *call);
extern rpc_call_info* rpc_call_lookup(rpc_call_info *call);

extern void rpc_init_proc_table(guint prog, guint vers, const vsff *proc_table);
extern void rpc_init_prog(int proto, guint32 prog, int ett);

extern void init_dissect_rpc();
extern void cleanup_dissect_rpc();

extern unsigned int roundup(unsigned int a);
extern int dissect_rpc_uint32(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char* name, char* type);
extern int dissect_rpc_uint64(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char* name, char* type);


#endif /* packet-rpc.h */

