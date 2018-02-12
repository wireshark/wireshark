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

/* Dissect a ntlmv2 response */

int
dissect_ntlmv2_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ntlmssp_tree, int offset, int len);

/* the ntlmssp data passed to tap listeners */
typedef struct _ntlmssp_header_t {
	guint32		type;
	const char 	*domain_name;
	const char 	*acct_name;
	const char 	*host_name;
	guint8		session_key[NTLMSSP_KEY_LEN];
} ntlmssp_header_t;

#endif
