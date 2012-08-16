/* packet-smb2.h
 * Defines for SMB2 packet dissection
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998, 1999 Gerald Combs
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

#ifndef __PACKET_SMB2_H__
#define __PACKET_SMB2_H__

/* SMB2 command codes. With MSVC and a
 * libwireshark.dll, we need a special declaration.
 */
WS_VAR_IMPORT value_string_ext smb2_cmd_vals_ext;

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
typedef enum {
	SMB2_EI_NONE,		/* Unassigned / NULL */
	SMB2_EI_TREENAME,	/* tid tracking  char * */
	SMB2_EI_FILENAME,	/* fid tracking  char * */
	SMB2_EI_FINDPATTERN	/* find tracking  char * */
} smb2_extra_info_t;
typedef struct _smb2_saved_info_t {
	guint8 class;
	guint8 infolevel;
	guint64 seqnum;
	guint32 frame_req, frame_res;
	nstime_t req_time;
	void *extra_info;
	smb2_extra_info_t extra_info_type;
} smb2_saved_info_t;

typedef struct _smb2_tid_info_t {
	guint32 tid;
	guint32 connect_frame;
	guint16 share_type;
	char *name;
} smb2_tid_info_t;

typedef struct _smb2_sesid_info_t {
	guint64 sesid;
	guint32 auth_frame;
	char *acct_name;
	char *domain_name;
	char *host_name;
	guint16 server_port;
	guint8 client_decryption_key[16];
	guint8 server_decryption_key[16];
	GHashTable *tids;
} smb2_sesid_info_t;

/* Structure to keep track of conversations and the hash tables.
 * There is one such structure for each conversation.
 */
typedef struct _smb2_conv_info_t {
	/* these two tables are used to match requests with responses */
	GHashTable *unmatched;
	GHashTable *matched;
	GHashTable *sesids;
} smb2_conv_info_t;

/* This structure contains information from the SMB2 header
 * as well as pointers to the conversation and the transaction specific
 * structures.
 */
#define SMB2_FLAGS_RESPONSE	0x00000001
#define SMB2_FLAGS_ASYNC_CMD	0x00000002
#define SMB2_FLAGS_CHAINED	0x00000004
#define SMB2_FLAGS_SIGNATURE	0x00000008
#define SMB2_FLAGS_DFS_OP	0x10000000
#define SMB2_FLAGS_REPLAY_OPERATION	0x20000000
typedef struct _smb2_info_t {
	guint16 opcode;
	guint32 ioctl_function;
	guint32 status;
	guint32 tid;
	guint64 sesid;
	gint64  seqnum;
	guint32 flags;
	smb2_conv_info_t	*conv;
	smb2_saved_info_t	*saved;
	smb2_tid_info_t		*tree;
	smb2_sesid_info_t	*session;
	proto_tree *top_tree;	
} smb2_info_t;

/* for transform content information */

typedef struct _smb2_transform_info_t {
	guint8  nonce[16];
	guint32 size;
	guint16 alg;
	guint64 sesid;
	smb2_conv_info_t *conv;
	smb2_sesid_info_t *session;
} smb2_transform_info_t;


int dissect_smb2_FILE_OBJECTID_BUFFER(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset);
int dissect_smb2_ioctl_function(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset, guint32 *ioctl_function);
void dissect_smb2_ioctl_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *top_tree, guint32 ioctl_function, gboolean data_in);

#endif
