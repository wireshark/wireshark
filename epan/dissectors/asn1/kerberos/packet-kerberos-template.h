/* packet-kerberos.h
 * Routines for kerberos packet dissection
 * Copyright 2007, Anders Broman <anders.broman@ericsson.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __PACKET_KERBEROS_H
#define __PACKET_KERBEROS_H

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* This is a list of callback functions a caller can use to specify that
   octet strings in kerberos to be passed back to application specific
   dissectors, outside of kerberos.
   This is used for dissection of application specific data for PacketCable
   KRB_SAFE user data and eventually to pass kerberos session keys
   to future DCERPC decryption and other uses.
   The list is terminated by {0, NULL }
*/
#define KRB_CBTAG_SAFE_USER_DATA	        1
#define KRB_CBTAG_PRIV_USER_DATA	        2
typedef struct _kerberos_callbacks {
	int tag;
	int (*callback)(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree);
} kerberos_callbacks;

/* Function prototypes */

gint
dissect_kerberos_main(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean do_col_info, kerberos_callbacks *cb);

int
dissect_krb5_Checksum(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_);

int
dissect_krb5_ctime(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_);

int dissect_krb5_cname(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_);
int dissect_krb5_realm(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_);
guint32 kerberos_output_keytype(void);

guint get_krb_pdu_len(packet_info *, tvbuff_t *tvb, int offset, void *data _U_);

gint kerberos_rm_to_reclen(guint krb_rm);

void
show_krb_recordmark(proto_tree *tree, tvbuff_t *tvb, gint start, guint32 krb_rm);

#ifdef HAVE_KERBEROS
#define KRB_MAX_ORIG_LEN	256

#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)
typedef struct _enc_key_t {
	struct _enc_key_t	*next;
	int keytype;
	int keylength;
	char *keyvalue;
	char 			key_origin[KRB_MAX_ORIG_LEN+1];
	int fd_num; /* remember where we learned a key */
} enc_key_t;
extern enc_key_t *enc_key_list;

guint8 *
decrypt_krb5_data(proto_tree *tree, packet_info *pinfo,
			int usage,
			tvbuff_t *crypototvb,
			int keytype,
			int *datalen);

#endif /* HAVE_HEIMDAL_KERBEROS || HAVE_MIT_KERBEROS */

extern gboolean krb_decrypt;

WS_DLL_PUBLIC
void read_keytab_file(const char *);

WS_DLL_PUBLIC
void read_keytab_file_from_preferences(void);

#endif /* HAVE_KERBEROS */

/* encryption type constants */
#define KRB5_ENCTYPE_NULL		0
#define KRB5_ENCTYPE_DES_CBC_CRC	1
#define KRB5_ENCTYPE_DES_CBC_MD4	2
#define KRB5_ENCTYPE_DES_CBC_MD5	3
#define KRB5_ENCTYPE_DES_CBC_RAW	4
#define KRB5_ENCTYPE_DES3_CBC_SHA	5
#define KRB5_ENCTYPE_DES3_CBC_RAW	6
#define KRB5_ENCTYPE_DES_HMAC_SHA1	8
#define KRB5_ENCTYPE_DSA_SHA1_CMS	9
#define KRB5_ENCTYPE_RSA_MD5_CMS	10
#define KRB5_ENCTYPE_RSA_SHA1_CMS	11
#define KRB5_ENCTYPE_RC2_CBC_ENV	12
#define KRB5_ENCTYPE_RSA_ENV		13
#define KRB5_ENCTYPE_RSA_ES_OEAP_ENV	14
#define KRB5_ENCTYPE_DES_EDE3_CBC_ENV	15
#define KRB5_ENCTYPE_DES3_CBC_SHA1	16
#define KRB5_ENCTYPE_AES128_CTS_HMAC_SHA1_96 17
#define KRB5_ENCTYPE_AES256_CTS_HMAC_SHA1_96 18
#define KRB5_ENCTYPE_DES_CBC_MD5_NT	20
#define KERB_ENCTYPE_RC4_HMAC		23
#define KERB_ENCTYPE_RC4_HMAC_EXP	24
#define KRB5_ENCTYPE_UNKNOWN		0x1ff
#define KRB5_ENCTYPE_LOCAL_DES3_HMAC_SHA1	0x7007
#define KRB5_ENCTYPE_RC4_PLAIN_EXP	0xffffff73
#define KRB5_ENCTYPE_RC4_PLAIN		0xffffff74
#define KRB5_ENCTYPE_RC4_PLAIN_OLD_EXP	0xffffff78
#define KRB5_ENCTYPE_RC4_HMAC_OLD_EXP	0xffffff79
#define KRB5_ENCTYPE_RC4_PLAIN_OLD	0xffffff7a
#define KRB5_ENCTYPE_RC4_HMAC_OLD	0xffffff7b
#define KRB5_ENCTYPE_DES_PLAIN		0xffffff7c
#define KRB5_ENCTYPE_RC4_SHA		0xffffff7d
#define KRB5_ENCTYPE_RC4_LM		0xffffff7e
#define KRB5_ENCTYPE_RC4_PLAIN2		0xffffff7f
#define KRB5_ENCTYPE_RC4_MD4		0xffffff80

#include "packet-kerberos-exp.h"

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  /* __PACKET_KERBEROS_H */
