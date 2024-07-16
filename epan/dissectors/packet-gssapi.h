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
	const char *comment;  /* For the comment */
} gssapi_oid_value;

#define DECRYPT_GSSAPI_NORMAL   1
#define DECRYPT_GSSAPI_DCE  2

/**< Extra data for handling of decryption of GSSAPI wrapped tvbuffs.
	Caller sets decrypt_gssapi_tvb if this service is requested.
	If, on a successful return, gssapi_data_encrypted is false, the wrapped
	tvbuff was signed (i.e., an encrypted signature was present, to check
	whether the data was modified by a man in the middle) but not sealed
	(i.e., the data itself wasn't encrypted).
	If gssapi_encrypted_tvb is NULL, then the rest of the tvb data following
	the gssapi blob itself is decrypted otherwise the gssapi_encrypted_tvb
	tvb will be decrypted (DCERPC has the data before the gssapi blob).
	In the latter case, gssapi_decrypted_tvb contains the decrypted data if
	decryption is successful and is NULL if not.
	If gssapi_data_encrypted is false and gssapi_decrypted_tvb is not NULL,
	then it contains the plaintext data, for cases when the plaintext data
	was followed by the checksum, e.g. KRB_TOKEN_CFX_WRAP (RFC 4121),
	as the calling dissector cannot simply dissect all the data after
	the returned offset.
*/
typedef struct _gssapi_encrypt_info
{
	uint16_t decrypt_gssapi_tvb;
	tvbuff_t *gssapi_wrap_tvb;
	tvbuff_t *gssapi_header_tvb;
	tvbuff_t *gssapi_encrypted_tvb;
	tvbuff_t *gssapi_trailer_tvb;
	tvbuff_t *gssapi_decrypted_tvb;
	bool gssapi_data_encrypted;
} gssapi_encrypt_info_t;

/* Function prototypes */

void
gssapi_init_oid(const char *oid, int proto, int ett, dissector_handle_t handle,
		dissector_handle_t wrap_handle, const char *comment);

gssapi_oid_value *
gssapi_lookup_oid_str(const char *oid_key);

typedef struct _dcerpc_info dcerpc_info;
typedef struct _dcerpc_auth_info dcerpc_auth_info;

int wrap_dissect_gssapi_verf(tvbuff_t *tvb, int offset,
			     packet_info *pinfo,
			     proto_tree *tree, dcerpc_info *di, uint8_t *drep);

tvbuff_t *
wrap_dissect_gssapi_payload(tvbuff_t *header_tvb _U_,
			    tvbuff_t *payload_tvb,
			    tvbuff_t *trailer_tvb _U_,
			    tvbuff_t *auth_tvb,
			    packet_info *pinfo,
			    dcerpc_auth_info *auth_info _U_);

#endif /* __PACKET_GSSAPI_H */
