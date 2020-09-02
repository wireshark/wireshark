/* packet-smb2.h
 * Defines for SMB2 packet dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998, 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_SMB2_H__
#define __PACKET_SMB2_H__

#include "packet-dcerpc.h"
#include "packet-smb.h"
#include "packet-ntlmssp.h"

/* SMB2 command codes. With MSVC and a
 * libwireshark.dll, we need a special declaration.
 */
WS_DLL_PUBLIC value_string_ext smb2_cmd_vals_ext;

/* Structure to keep track of information specific to a single
 * SMB2 transaction. Here we store things we need to remember between
 * a specific request and a specific response.
 *
 * There is no guarantee we will have this structure available for all
 * SMB2 packets so a dissector must check this pointer for NULL
 * before dereferencing it.
 *
 * private data is set to NULL when the structure is created.  It is used
 * for communications between the Request and the Response packets.
 */

/* extra info needed by export object smb */
typedef struct _smb2_eo_file_info_t {
	guint32	attr_mask;
	gint64 	end_of_file;
} smb2_eo_file_info_t;

typedef struct _smb2_fid_info_t {
	guint64 fid_persistent;
	guint64 fid_volatile;
	guint64 sesid;		/* *host* byte order - not necessarily little-endian! */
	guint32 tid;
	/* only used for key lookup in equal func, must be zero when inserting */
	guint32 frame_key;
	/* first and last frame nums this FID is valid */
	guint32 frame_beg;
	guint32 frame_end;
	/* file name used to open this FID */
	char *name;
} smb2_fid_info_t;

typedef enum {
	SMB2_EI_NONE,		/* Unassigned / NULL */
	SMB2_EI_TREENAME,	/* tid tracking  char * */
	SMB2_EI_FILENAME,	/* fid tracking  char * */
	SMB2_EI_FINDPATTERN	/* find tracking  char * */
} smb2_extra_info_t;
typedef struct _smb2_saved_info_t {
	guint8 smb2_class;
	guint8 infolevel;
	guint64 msg_id;
	guint32 frame_req, frame_res;
	nstime_t req_time;
	guint8 *preauth_hash_req, *preauth_hash_res;
	smb2_fid_info_t *file;
	e_ctx_hnd policy_hnd; 		/* for eo_smb tracking */
	smb_eo_t	*eo_info_t;	/* for storing eo_smb infos */
	guint64		file_offset;	/* needed file_offset for eo_smb */
	guint32		bytes_moved;	/* needed for eo_smb */
	void *extra_info;
	smb2_extra_info_t extra_info_type;
} smb2_saved_info_t;

typedef struct _smb2_tid_info_t {
	guint32 tid;
	guint32 connect_frame;
	guint8 share_type;
	char *name;
} smb2_tid_info_t;

#define SMB2_PREAUTH_HASH_SIZE 64
#define AES_KEY_SIZE 16

typedef struct _smb2_sesid_info_t {
	guint64 sesid;		/* *host* byte order - not necessarily little-endian! */
	guint32 auth_frame;
	char *acct_name;
	char *domain_name;
	char *host_name;
	guint16 server_port;
	guint8 session_key[NTLMSSP_KEY_LEN];
	guint8 signing_key[NTLMSSP_KEY_LEN];
	guint8 client_decryption_key[AES_KEY_SIZE];
	guint8 server_decryption_key[AES_KEY_SIZE];

	wmem_map_t *tids;
	GHashTable *fids;
	/* table to store some infos for smb export object */
	GHashTable *files;

	guint8 preauth_hash[SMB2_PREAUTH_HASH_SIZE];
} smb2_sesid_info_t;

/* Structure to keep track of conversations and the hash tables.
 * There is one such structure for each conversation.
 */
typedef struct _smb2_conv_info_t {
	/* these two tables are used to match requests with responses */
	GHashTable *unmatched;
	GHashTable *matched;
	guint16 dialect;
	guint16 enc_alg;

	/* preauth hash before session setup */
	guint8 *preauth_hash_current;
	guint8 preauth_hash_con[SMB2_PREAUTH_HASH_SIZE];
	guint8 preauth_hash_ses[SMB2_PREAUTH_HASH_SIZE];
} smb2_conv_info_t;


/* This structure contains information from the SMB2 header
 * as well as pointers to the conversation and the transaction specific
 * structures.
 */
#define SMB2_FLAGS_RESPONSE	0x00000001
#define SMB2_FLAGS_ASYNC_CMD	0x00000002
#define SMB2_FLAGS_CHAINED	0x00000004
#define SMB2_FLAGS_SIGNATURE	0x00000008
#define SMB2_FLAGS_PRIORITY_MASK	0x00000070
#define SMB2_FLAGS_DFS_OP	0x10000000
#define SMB2_FLAGS_REPLAY_OPERATION	0x20000000

#define SMB2_FLAGS_PRIORITY1    0x00000010
#define SMB2_FLAGS_PRIORITY2    0x00000020
#define SMB2_FLAGS_PRIORITY3    0x00000030
#define SMB2_FLAGS_PRIORITY4    0x00000040
#define SMB2_FLAGS_PRIORITY5    0x00000050
#define SMB2_FLAGS_PRIORITY6    0x00000060
#define SMB2_FLAGS_PRIORITY7    0x00000070

/* SMB2 FLAG MASKS */
#define SMB2_FLAGS_ATTR_ENCRYPTED	0x00004000
#define SMB2_FLAGS_ATTR_INDEXED		0x00002000
#define SMB2_FLAGS_ATTR_OFFLINE		0x00001000
#define SMB2_FLAGS_ATTR_COMPRESSED	0x00000800
#define SMB2_FLAGS_ATTR_REPARSEPOINT	0x00000400
#define SMB2_FLAGS_ATTR_SPARSE		0x00000200
#define SMB2_FLAGS_ATTR_TEMPORARY	0x00000100
#define SMB2_FLAGS_ATTR_NORMAL		0x00000080
#define SMB2_FLAGS_ATTR_DEVICE		0x00000040
#define SMB2_FLAGS_ATTR_ARCHIVE		0x00000020
#define SMB2_FLAGS_ATTR_DIRECTORY	0x00000010
#define SMB2_FLAGS_ATTR_VOLUMEID	0x00000008
#define SMB2_FLAGS_ATTR_SYSTEM		0x00000004
#define SMB2_FLAGS_ATTR_HIDDEN		0x00000002
#define SMB2_FLAGS_ATTR_READONLY	0x00000001

/* SMB2 FILE TYPES ASIGNED TO EXPORT OBJECTS */
#define SMB2_FID_TYPE_UNKNOWN			0
#define SMB2_FID_TYPE_FILE			1
#define SMB2_FID_TYPE_DIR			2
#define SMB2_FID_TYPE_PIPE			3
#define SMB2_FID_TYPE_OTHER			4

/* SMB2 COMMAND CODES */
#define SMB2_COM_NEGOTIATE_PROTOCOL 	0x00
#define SMB2_COM_SESSION_SETUP 		0x01
#define SMB2_COM_SESSION_LOGOFF 	0x02
#define SMB2_COM_TREE_CONNECT 		0x03
#define SMB2_COM_TREE_DISCONNECT 	0x04
#define SMB2_COM_CREATE 		0x05
#define SMB2_COM_CLOSE 			0x06
#define SMB2_COM_FLUSH 			0x07
#define SMB2_COM_READ 			0x08
#define SMB2_COM_WRITE 			0x09
#define SMB2_COM_LOCK 			0x0A
#define SMB2_COM_IOCTL 			0x0B
#define SMB2_COM_CANCEL 		0x0C
#define SMB2_COM_KEEPALIVE 		0x0D
#define SMB2_COM_FIND 			0x0E
#define SMB2_COM_NOTIFY 		0x0F
#define SMB2_COM_GETINFO 		0x10
#define SMB2_COM_SETINFO 		0x11
#define SMB2_COM_BREAK 			0x12

typedef struct _smb2_info_t {
	guint16 opcode;
	guint32 ioctl_function;
	guint32 status;
	guint32 tid;
	guint64 sesid;		/* *host* byte order - not necessarily little-endian! */
	guint64  msg_id;
	guint32 flags;
	smb2_eo_file_info_t	*eo_file_info; /* eo_smb extra info */
	smb2_conv_info_t	*conv;
	smb2_saved_info_t	*saved;
	smb2_tid_info_t		*tree;
	smb2_sesid_info_t	*session;
	smb2_fid_info_t		*file;
	proto_tree *top_tree;
} smb2_info_t;

/* for transform content information */

typedef struct _smb2_transform_info_t {
	guint8  nonce[16];
	guint32 size;
	guint16 flags;
	guint64 sesid;		/* *host* byte order - not necessarily little-endian! */
	smb2_conv_info_t *conv;
	smb2_sesid_info_t *session;
} smb2_transform_info_t;

typedef struct _smb2_comp_transform_info_t {
	guint orig_size;
	guint alg;
	guint comp_offset;
	smb2_conv_info_t *conv;
	smb2_sesid_info_t *session;
} smb2_comp_transform_info_t;


int dissect_smb2_FILE_OBJECTID_BUFFER(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset);
int dissect_smb2_ioctl_function(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset, guint32 *ioctl_function);
void dissect_smb2_ioctl_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *top_tree, guint32 ioctl_function, gboolean data_in, void *private_data);

#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
