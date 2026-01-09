/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-kerberos.h                                                          */
/* asn2wrs.py -b -q -L -p kerberos -c ./kerberos.cnf -s ./packet-kerberos-template -D . -O ../.. KerberosV5Spec2.asn k5.asn RFC3244.asn RFC6113.asn SPAKE.asn */

/* packet-kerberos.h
 * Routines for kerberos packet dissection
 * Copyright 2007, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_KERBEROS_H
#define __PACKET_KERBEROS_H

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef KRB5_KU_USAGE_ACCEPTOR_SEAL
#define KRB5_KU_USAGE_ACCEPTOR_SEAL     22
#endif
#ifndef KRB5_KU_USAGE_ACCEPTOR_SIGN
#define KRB5_KU_USAGE_ACCEPTOR_SIGN     23
#endif
#ifndef KRB5_KU_USAGE_INITIATOR_SEAL
#define KRB5_KU_USAGE_INITIATOR_SEAL    24
#endif
#ifndef KRB5_KU_USAGE_INITIATOR_SIGN
#define KRB5_KU_USAGE_INITIATOR_SIGN    25
#endif

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

bool
kerberos_is_win2k_pkinit(asn1_ctx_t *actx);

int
dissect_kerberos_main(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, bool do_col_info, kerberos_callbacks *cb);

int
dissect_krb5_Checksum(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_);

int
dissect_krb5_ctime(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_);

int dissect_krb5_cname(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_);
int dissect_krb5_realm(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_);
uint32_t kerberos_output_keytype(void);

unsigned get_krb_pdu_len(packet_info *, tvbuff_t *tvb, int offset, void *data _U_);

int kerberos_rm_to_reclen(unsigned krb_rm);

void
show_krb_recordmark(proto_tree *tree, tvbuff_t *tvb, int start, uint32_t krb_rm);

int
dissect_kerberos_KERB_TICKET_LOGON(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree);

#ifdef HAVE_KERBEROS

#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)

uint8_t *
decrypt_krb5_data(proto_tree *tree, packet_info *pinfo,
			int usage,
			tvbuff_t *crypototvb,
			int keytype,
			int *datalen);

tvbuff_t *
decrypt_krb5_krb_cfx_dce(proto_tree *tree,
			 packet_info *pinfo,
			 int usage,
			 int keytype,
			 tvbuff_t *gssapi_header_tvb,
			 tvbuff_t *gssapi_encrypted_tvb,
			 tvbuff_t *gssapi_trailer_tvb,
			 tvbuff_t *checksum_tvb);

#endif /* HAVE_HEIMDAL_KERBEROS || HAVE_MIT_KERBEROS */

extern bool krb_decrypt;

WS_DLL_PUBLIC
void read_keytab_file_from_preferences(void);

#endif /* HAVE_KERBEROS */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#include <epan/asn1.h>


/* enumerated values for Applications */
#define KERBEROS_APPLICATIONS_TICKET   1
#define KERBEROS_APPLICATIONS_AUTHENTICATOR   2
#define KERBEROS_APPLICATIONS_ENCTICKETPART   3
#define KERBEROS_APPLICATIONS_AS_REQ  10
#define KERBEROS_APPLICATIONS_AS_REP  11
#define KERBEROS_APPLICATIONS_TGS_REQ  12
#define KERBEROS_APPLICATIONS_TGS_REP  13
#define KERBEROS_APPLICATIONS_AP_REQ  14
#define KERBEROS_APPLICATIONS_AP_REP  15
#define KERBEROS_APPLICATIONS_KRB_SAFE  20
#define KERBEROS_APPLICATIONS_KRB_PRIV  21
#define KERBEROS_APPLICATIONS_KRB_CRED  22
#define KERBEROS_APPLICATIONS_ENCASREPPART  25
#define KERBEROS_APPLICATIONS_ENCTGSREPPART  26
#define KERBEROS_APPLICATIONS_ENCAPREPPART  27
#define KERBEROS_APPLICATIONS_ENCKRBPRIVPART  28
#define KERBEROS_APPLICATIONS_ENCKRBCREDPART  29
#define KERBEROS_APPLICATIONS_KRB_ERROR  30
unsigned dissect_kerberos_TGT_REQ(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
unsigned dissect_kerberos_TGT_REP(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
unsigned dissect_kerberos_ChangePasswdData(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

#endif  /* __PACKET_KERBEROS_H */
