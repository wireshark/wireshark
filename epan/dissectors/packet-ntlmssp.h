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
  uint8_t md4[NTLMSSP_KEY_LEN];
  char key_origin[NTLMSSP_MAX_ORIG_LEN+1];
} md4_pass;

uint32_t
get_md4pass_list(wmem_allocator_t *pool, md4_pass** p_pass_list);

/* Dissect a ntlmv2 response */

int
dissect_ntlmv2_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ntlmssp_tree, int offset, int len);

/* the ntlmssp data passed to tap listeners */
typedef struct _ntlmssp_header_t {
	uint32_t		type;
	const uint8_t	*domain_name;
	const uint8_t	*acct_name;
	const uint8_t	*host_name;
	uint8_t		session_key[NTLMSSP_KEY_LEN];
} ntlmssp_header_t;

#define NTLMSSP_BLOB_MAX_SIZE 10240
typedef struct _ntlmssp_blob {
  uint16_t length;
  uint8_t* contents;
} ntlmssp_blob;

void
ntlmssp_create_session_key(packet_info *pinfo,
                           proto_tree *tree,
                           ntlmssp_header_t *ntlmssph,
                           int flags,
                           const uint8_t *server_challenge,
                           const uint8_t *encryptedsessionkey,
                           const ntlmssp_blob *ntlm_response,
                           const ntlmssp_blob *lm_response);

int
dissect_ntlmssp_NTLM_REMOTE_SUPPLEMENTAL_CREDENTIAL(tvbuff_t *tvb, int offset, proto_tree *tree);

#endif
