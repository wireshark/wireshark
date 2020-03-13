/* packet-ntlmssp.h
 * Declarations for NTLM Secure Service Provider
 * Copyright 2003, Tim Potter <tpot@samba.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_NTLMSSP_H__
#define __PACKET_NTLMSSP_H__

/* Message types */

#define NTLMSSP_NEGOTIATE 1
#define NTLMSSP_CHALLENGE 2
#define NTLMSSP_AUTH      3
#define NTLMSSP_UNKNOWN   4

#define NTLMSSP_KEY_LEN 16

#define NTLMSSP_MAX_ORIG_LEN 256

typedef struct _md4_pass {
  guint8 md4[NTLMSSP_KEY_LEN];
  char key_origin[NTLMSSP_MAX_ORIG_LEN+1];
} md4_pass;

guint32
get_md4pass_list(md4_pass** p_pass_list);

/* Dissect a ntlmv2 response */

int
dissect_ntlmv2_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ntlmssp_tree, int offset, int len);

/* the ntlmssp data passed to tap listeners */
typedef struct _ntlmssp_header_t {
	guint32		type;
	const guint8	*domain_name;
	const guint8	*acct_name;
	const guint8	*host_name;
	guint8		session_key[NTLMSSP_KEY_LEN];
} ntlmssp_header_t;

#define NTLMSSP_BLOB_MAX_SIZE 10240
typedef struct _ntlmssp_blob {
  guint16 length;
  guint8* contents;
} ntlmssp_blob;

void
ntlmssp_create_session_key(packet_info *pinfo,
                           proto_tree *tree,
                           ntlmssp_header_t *ntlmssph,
                           int flags,
                           const guint8 *server_challenge,
                           const guint8 *encryptedsessionkey,
                           const ntlmssp_blob *ntlm_response,
                           const ntlmssp_blob *lm_response);

#endif
