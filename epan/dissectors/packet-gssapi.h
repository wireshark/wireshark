/* packet-gssapi.h
 * Dissector for GSS-API tokens as described in rfc2078, section 3.1
 * Copyright 2002, Tim Potter <tpot@samba.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_GSSAPI_H
#define __PACKET_GSSAPI_H

/* Structures needed outside */

typedef struct _gssapi_oid_value {
	protocol_t *proto;
	int ett;
	dissector_handle_t handle;
	dissector_handle_t wrap_handle;
	const gchar *comment;  /* For the comment */
} gssapi_oid_value;

#define DECRYPT_GSSAPI_NORMAL   1
#define DECRYPT_GSSAPI_DCE  2

/**< Extra data for handling of decryption of GSSAPI wrapped tvbuffs.
	Caller sets decrypt_gssapi_tvb if this service is requested.
	If gssapi_encrypted_tvb is NULL, then the rest of the tvb data following
	the gssapi blob itself is decrypted othervise the gssapi_encrypted_tvb
	tvb will be decrypted (DCERPC has the data before the gssapi blob)
	If, on return, gssapi_data_encrypted is FALSE, the wrapped tvbuff
	was signed (i.e., an encrypted signature was present, to check
	whether the data was modified by a man in the middle) but not sealed
	(i.e., the data itself wasn't encrypted).
*/
typedef struct _gssapi_encrypt_info
{
	guint16 decrypt_gssapi_tvb;
	tvbuff_t *gssapi_wrap_tvb;
	tvbuff_t *gssapi_header_tvb;
	tvbuff_t *gssapi_encrypted_tvb;
	tvbuff_t *gssapi_trailer_tvb;
	tvbuff_t *gssapi_decrypted_tvb;
	gboolean gssapi_data_encrypted;
} gssapi_encrypt_info_t;

/* Function prototypes */

void
gssapi_init_oid(const char *oid, int proto, int ett, dissector_handle_t handle,
		dissector_handle_t wrap_handle, const gchar *comment);

gssapi_oid_value *
gssapi_lookup_oid_str(const gchar *oid_key);

int wrap_dissect_gssapi_verf(tvbuff_t *tvb, int offset,
			     packet_info *pinfo,
			     proto_tree *tree, dcerpc_info *di, guint8 *drep);

tvbuff_t *
wrap_dissect_gssapi_payload(tvbuff_t *header_tvb _U_,
			    tvbuff_t *payload_tvb,
			    tvbuff_t *trailer_tvb _U_,
			    tvbuff_t *auth_tvb,
			    packet_info *pinfo,
			    dcerpc_auth_info *auth_info _U_);

#endif /* __PACKET_GSSAPI_H */
