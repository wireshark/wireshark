/* packet-kerberos.c
 * Routines for Kerberos
 * Wes Hardaker (c) 2000
 * wjhardaker@ucdavis.edu
 * Richard Sharpe (C) 2002, rsharpe@samba.org, modularized a bit more and
 *                          added AP-REQ and AP-REP dissection
 *
 * Ronnie Sahlberg (C) 2004, major rewrite for new ASN.1/BER API.
 *
 * See RFC 1510, and various I-Ds and other documents showing additions,
 * e.g. ones listed under
 *
 *	http://www.isi.edu/people/bcn/krb-revisions/
 *
 * and
 *
 *	http://www.ietf.org/internet-drafts/draft-ietf-krb-wg-kerberos-clarifications-03.txt
 *
 * $Id: packet-kerberos.c,v 1.47 2004/02/20 10:04:10 sahlberg Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include <epan/packet.h>

#include <epan/strutil.h>

#include "packet-netbios.h"
#include "packet-tcp.h"
#include "prefs.h"
#include "packet-ber.h"

#define UDP_PORT_KERBEROS		88
#define TCP_PORT_KERBEROS		88

/* Desegment Kerberos over TCP messages */
static gboolean krb_desegment = TRUE;

static gint proto_kerberos = -1;
static gint hf_krb_rm_reserved = -1;
static gint hf_krb_rm_reclen = -1;

static gint hf_krb_padata = -1;
static gint hf_krb_error_code = -1;
static gint hf_krb_ticket = -1;
static gint hf_krb_AP_REP_enc = -1;
static gint hf_krb_KDC_REP_enc = -1;
static gint hf_krb_tkt_vno = -1;
static gint hf_krb_e_data = -1;
static gint hf_krb_PA_PAC_REQUEST_flag = -1;
static gint hf_krb_encrypted_authenticator_data = -1;
static gint hf_krb_encrypted_PA_ENC_TIMESTAMP = -1;
static gint hf_krb_encrypted_Ticket_data = -1;
static gint hf_krb_encrypted_AP_REP_data = -1;
static gint hf_krb_encrypted_KDC_REP_data = -1;
static gint hf_krb_PA_DATA_type = -1;
static gint hf_krb_PA_DATA_value = -1;
static gint hf_krb_realm = -1;
static gint hf_krb_crealm = -1;
static gint hf_krb_sname = -1;
static gint hf_krb_cname = -1;
static gint hf_krb_name_string = -1;
static gint hf_krb_e_text = -1;
static gint hf_krb_name_type = -1;
static gint hf_krb_from = -1;
static gint hf_krb_till = -1;
static gint hf_krb_rtime = -1;
static gint hf_krb_ctime = -1;
static gint hf_krb_cusec = -1;
static gint hf_krb_stime = -1;
static gint hf_krb_susec = -1;
static gint hf_krb_nonce = -1;
static gint hf_krb_etype = -1;
static gint hf_krb_etypes = -1;
static gint hf_krb_addr_type = -1;
static gint hf_krb_address_ip = -1;
static gint hf_krb_address_netbios = -1;
static gint hf_krb_msg_type = -1;
static gint hf_krb_pvno = -1;
static gint hf_krb_kvno = -1;
static gint hf_krb_HostAddress = -1;
static gint hf_krb_HostAddresses = -1;
static gint hf_krb_APOptions = -1;
static gint hf_krb_APOptions_use_session_key = -1;
static gint hf_krb_APOptions_mutual_required = -1;
static gint hf_krb_KDCOptions = -1;
static gint hf_krb_KDCOptions_forwardable = -1;
static gint hf_krb_KDCOptions_forwarded = -1;
static gint hf_krb_KDCOptions_proxyable = -1;
static gint hf_krb_KDCOptions_proxy = -1;
static gint hf_krb_KDCOptions_allow_postdate = -1;
static gint hf_krb_KDCOptions_postdated = -1;
static gint hf_krb_KDCOptions_renewable = -1;
static gint hf_krb_KDCOptions_renewable_ok = -1;
static gint hf_krb_KDCOptions_enc_tkt_in_skey = -1;
static gint hf_krb_KDCOptions_renew = -1;
static gint hf_krb_KDCOptions_validate = -1;
static gint hf_krb_KDC_REQ_BODY = -1;
static gint hf_krb_authenticator_enc = -1;
static gint hf_krb_ticket_enc = -1;

static gint ett_krb_kerberos = -1;
static gint ett_krb_KDC_REP_enc = -1;
static gint ett_krb_sname = -1;
static gint ett_krb_cname = -1;
static gint ett_krb_AP_REP_enc = -1;
static gint ett_krb_padata = -1;
static gint ett_krb_etypes = -1;
static gint ett_krb_PA_DATA_tree = -1;
static gint ett_krb_HostAddress = -1;
static gint ett_krb_HostAddresses = -1;
static gint ett_krb_authenticator_enc = -1;
static gint ett_krb_AP_Options = -1;
static gint ett_krb_KDC_Options = -1;
static gint ett_krb_request = -1;
static gint ett_krb_recordmark = -1;
static gint ett_krb_ticket = -1;
static gint ett_krb_ticket_enc = -1;


guint32 krb5_error_code;


static int do_col_info;

/* TCP Record Mark */
#define	KRB_RM_RESERVED	0x80000000L
#define	KRB_RM_RECLEN	0x7fffffffL

#define KRB5_MSG_AS_REQ   10	/* AS-REQ type */
#define KRB5_MSG_AS_REP   11	/* AS-REP type */
#define KRB5_MSG_TGS_REQ  12	/* TGS-REQ type */
#define KRB5_MSG_TGS_REP  13	/* TGS-REP type */
#define KRB5_MSG_AP_REQ   14	/* AP-REQ type */
#define KRB5_MSG_AP_REP   15	/* AP-REP type */

#define KRB5_MSG_SAFE     20	/* KRB-SAFE type */
#define KRB5_MSG_PRIV     21	/* KRB-PRIV type */
#define KRB5_MSG_CRED     22	/* KRB-CRED type */
#define KRB5_MSG_ERROR    30	/* KRB-ERROR type */

/* address type constants */
#define KRB5_ADDR_IPv4       0x02
#define KRB5_ADDR_CHAOS      0x05
#define KRB5_ADDR_XEROX      0x06
#define KRB5_ADDR_ISO        0x07
#define KRB5_ADDR_DECNET     0x0c
#define KRB5_ADDR_APPLETALK  0x10
#define KRB5_ADDR_NETBIOS    0x14
#define KRB5_ADDR_IPv6       0x18

/* encryption type constants */
#define KRB5_ENCTYPE_NULL                0
#define KRB5_ENCTYPE_DES_CBC_CRC         1
#define KRB5_ENCTYPE_DES_CBC_MD4         2
#define KRB5_ENCTYPE_DES_CBC_MD5         3
#define KRB5_ENCTYPE_DES_CBC_RAW         4
#define KRB5_ENCTYPE_DES3_CBC_SHA        5
#define KRB5_ENCTYPE_DES3_CBC_RAW        6
#define KRB5_ENCTYPE_DES_HMAC_SHA1       8
#define KRB5_ENCTYPE_DES3_CBC_SHA1       16
#define KERB_ENCTYPE_RC4_HMAC            23 
#define KERB_ENCTYPE_RC4_HMAC_EXP        24
#define KRB5_ENCTYPE_UNKNOWN                0x1ff
#define KRB5_ENCTYPE_LOCAL_DES3_HMAC_SHA1   0x7007

/*
 * For KERB_ENCTYPE_RC4_HMAC and KERB_ENCTYPE_RC4_HMAC_EXP, see
 *
 *	http://www.ietf.org/internet-drafts/draft-brezak-win2k-krb-rc4-hmac-04.txt
 *
 * unless it's expired.
 */

/* pre-authentication type constants */
#define KRB5_PA_TGS_REQ                1
#define KRB5_PA_ENC_TIMESTAMP          2
#define KRB5_PA_PW_SALT                3
#define KRB5_PA_ENC_ENCKEY             4
#define KRB5_PA_ENC_UNIX_TIME          5
#define KRB5_PA_ENC_SANDIA_SECURID     6
#define KRB5_PA_SESAME                 7
#define KRB5_PA_OSF_DCE                8
#define KRB5_PA_CYBERSAFE_SECUREID     9
#define KRB5_PA_AFS3_SALT              10
#define KRB5_PA_ENCTYPE_INFO           11
#define KRB5_PA_SAM_CHALLENGE          12
#define KRB5_PA_SAM_RESPONSE           13
#define KRB5_PA_DASS                   16
#define KRB5_PA_USE_SPECIFIED_KVNO     20
#define KRB5_PA_SAM_REDIRECT           21
#define KRB5_PA_GET_FROM_TYPED_DATA    22
#define KRB5_PA_SAM_ETYPE_INFO         23
#define KRB5_PA_ALT_PRINC              24
#define KRB5_PA_SAM_CHALLENGE2         30
#define KRB5_PA_SAM_RESPONSE2          31
#define KRB5_PA_PAC_REQUEST            128

/* Principal name-type */
#define KRB5_NT_UNKNOWN     0
#define KRB5_NT_PRINCIPAL   1
#define KRB5_NT_SRV_INST    2	
#define KRB5_NT_SRV_HST     3
#define KRB5_NT_SRV_XHST    4
#define KRB5_NT_UID     5

/* error table constants */
/* I prefixed the krb5_err.et constant names with KRB5_ET_ for these */
#define KRB5_ET_KRB5KDC_ERR_NONE                         0
#define KRB5_ET_KRB5KDC_ERR_NAME_EXP                     1
#define KRB5_ET_KRB5KDC_ERR_SERVICE_EXP                  2
#define KRB5_ET_KRB5KDC_ERR_BAD_PVNO                     3
#define KRB5_ET_KRB5KDC_ERR_C_OLD_MAST_KVNO              4
#define KRB5_ET_KRB5KDC_ERR_S_OLD_MAST_KVNO              5
#define KRB5_ET_KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN          6
#define KRB5_ET_KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN          7
#define KRB5_ET_KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE         8
#define KRB5_ET_KRB5KDC_ERR_NULL_KEY                     9
#define KRB5_ET_KRB5KDC_ERR_CANNOT_POSTDATE              10
#define KRB5_ET_KRB5KDC_ERR_NEVER_VALID                  11
#define KRB5_ET_KRB5KDC_ERR_POLICY                       12
#define KRB5_ET_KRB5KDC_ERR_BADOPTION                    13
#define KRB5_ET_KRB5KDC_ERR_ETYPE_NOSUPP                 14
#define KRB5_ET_KRB5KDC_ERR_SUMTYPE_NOSUPP               15
#define KRB5_ET_KRB5KDC_ERR_PADATA_TYPE_NOSUPP           16
#define KRB5_ET_KRB5KDC_ERR_TRTYPE_NOSUPP                17
#define KRB5_ET_KRB5KDC_ERR_CLIENT_REVOKED               18
#define KRB5_ET_KRB5KDC_ERR_SERVICE_REVOKED              19
#define KRB5_ET_KRB5KDC_ERR_TGT_REVOKED                  20
#define KRB5_ET_KRB5KDC_ERR_CLIENT_NOTYET                21
#define KRB5_ET_KRB5KDC_ERR_SERVICE_NOTYET               22
#define KRB5_ET_KRB5KDC_ERR_KEY_EXP                      23
#define KRB5_ET_KRB5KDC_ERR_PREAUTH_FAILED               24
#define KRB5_ET_KRB5KDC_ERR_PREAUTH_REQUIRED             25
#define KRB5_ET_KRB5KDC_ERR_SERVER_NOMATCH               26
#define KRB5_ET_KRB5KRB_AP_ERR_BAD_INTEGRITY             31
#define KRB5_ET_KRB5KRB_AP_ERR_TKT_EXPIRED               32
#define KRB5_ET_KRB5KRB_AP_ERR_TKT_NYV                   33
#define KRB5_ET_KRB5KRB_AP_ERR_REPEAT                    34
#define KRB5_ET_KRB5KRB_AP_ERR_NOT_US                    35
#define KRB5_ET_KRB5KRB_AP_ERR_BADMATCH                  36
#define KRB5_ET_KRB5KRB_AP_ERR_SKEW                      37
#define KRB5_ET_KRB5KRB_AP_ERR_BADADDR                   38
#define KRB5_ET_KRB5KRB_AP_ERR_BADVERSION                39
#define KRB5_ET_KRB5KRB_AP_ERR_MSG_TYPE                  40
#define KRB5_ET_KRB5KRB_AP_ERR_MODIFIED                  41
#define KRB5_ET_KRB5KRB_AP_ERR_BADORDER                  42
#define KRB5_ET_KRB5KRB_AP_ERR_ILL_CR_TKT                43
#define KRB5_ET_KRB5KRB_AP_ERR_BADKEYVER                 44
#define KRB5_ET_KRB5KRB_AP_ERR_NOKEY                     45
#define KRB5_ET_KRB5KRB_AP_ERR_MUT_FAIL                  46
#define KRB5_ET_KRB5KRB_AP_ERR_BADDIRECTION              47
#define KRB5_ET_KRB5KRB_AP_ERR_METHOD                    48
#define KRB5_ET_KRB5KRB_AP_ERR_BADSEQ                    49
#define KRB5_ET_KRB5KRB_AP_ERR_INAPP_CKSUM               50
#define KRB5_ET_KRB5KRB_ERR_RESPONSE_TOO_BIG             52
#define KRB5_ET_KRB5KRB_ERR_GENERIC                      60
#define KRB5_ET_KRB5KRB_ERR_FIELD_TOOLONG                61

static const value_string krb5_error_codes[] = {
	{ KRB5_ET_KRB5KDC_ERR_NONE, "KRB5KDC_ERR_NONE" },
	{ KRB5_ET_KRB5KDC_ERR_NAME_EXP, "KRB5KDC_ERR_NAME_EXP" },
	{ KRB5_ET_KRB5KDC_ERR_SERVICE_EXP, "KRB5KDC_ERR_SERVICE_EXP" },
	{ KRB5_ET_KRB5KDC_ERR_BAD_PVNO, "KRB5KDC_ERR_BAD_PVNO" },
	{ KRB5_ET_KRB5KDC_ERR_C_OLD_MAST_KVNO, "KRB5KDC_ERR_C_OLD_MAST_KVNO" },
	{ KRB5_ET_KRB5KDC_ERR_S_OLD_MAST_KVNO, "KRB5KDC_ERR_S_OLD_MAST_KVNO" },
	{ KRB5_ET_KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN, "KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN" },
	{ KRB5_ET_KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN, "KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN" },
	{ KRB5_ET_KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE, "KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE" },
	{ KRB5_ET_KRB5KDC_ERR_NULL_KEY, "KRB5KDC_ERR_NULL_KEY" },
	{ KRB5_ET_KRB5KDC_ERR_CANNOT_POSTDATE, "KRB5KDC_ERR_CANNOT_POSTDATE" },
	{ KRB5_ET_KRB5KDC_ERR_NEVER_VALID, "KRB5KDC_ERR_NEVER_VALID" },
	{ KRB5_ET_KRB5KDC_ERR_POLICY, "KRB5KDC_ERR_POLICY" },
	{ KRB5_ET_KRB5KDC_ERR_BADOPTION, "KRB5KDC_ERR_BADOPTION" },
	{ KRB5_ET_KRB5KDC_ERR_ETYPE_NOSUPP, "KRB5KDC_ERR_ETYPE_NOSUPP" },
	{ KRB5_ET_KRB5KDC_ERR_SUMTYPE_NOSUPP, "KRB5KDC_ERR_SUMTYPE_NOSUPP" },
	{ KRB5_ET_KRB5KDC_ERR_PADATA_TYPE_NOSUPP, "KRB5KDC_ERR_PADATA_TYPE_NOSUPP" },
	{ KRB5_ET_KRB5KDC_ERR_TRTYPE_NOSUPP, "KRB5KDC_ERR_TRTYPE_NOSUPP" },
	{ KRB5_ET_KRB5KDC_ERR_CLIENT_REVOKED, "KRB5KDC_ERR_CLIENT_REVOKED" },
	{ KRB5_ET_KRB5KDC_ERR_SERVICE_REVOKED, "KRB5KDC_ERR_SERVICE_REVOKED" },
	{ KRB5_ET_KRB5KDC_ERR_TGT_REVOKED, "KRB5KDC_ERR_TGT_REVOKED" },
	{ KRB5_ET_KRB5KDC_ERR_CLIENT_NOTYET, "KRB5KDC_ERR_CLIENT_NOTYET" },
	{ KRB5_ET_KRB5KDC_ERR_SERVICE_NOTYET, "KRB5KDC_ERR_SERVICE_NOTYET" },
	{ KRB5_ET_KRB5KDC_ERR_KEY_EXP, "KRB5KDC_ERR_KEY_EXP" },
	{ KRB5_ET_KRB5KDC_ERR_PREAUTH_FAILED, "KRB5KDC_ERR_PREAUTH_FAILED" },
	{ KRB5_ET_KRB5KDC_ERR_PREAUTH_REQUIRED, "KRB5KDC_ERR_PREAUTH_REQUIRED" },
	{ KRB5_ET_KRB5KDC_ERR_SERVER_NOMATCH, "KRB5KDC_ERR_SERVER_NOMATCH" },
	{ KRB5_ET_KRB5KRB_AP_ERR_BAD_INTEGRITY, "KRB5KRB_AP_ERR_BAD_INTEGRITY" },
	{ KRB5_ET_KRB5KRB_AP_ERR_TKT_EXPIRED, "KRB5KRB_AP_ERR_TKT_EXPIRED" },
	{ KRB5_ET_KRB5KRB_AP_ERR_TKT_NYV, "KRB5KRB_AP_ERR_TKT_NYV" },
	{ KRB5_ET_KRB5KRB_AP_ERR_REPEAT, "KRB5KRB_AP_ERR_REPEAT" },
	{ KRB5_ET_KRB5KRB_AP_ERR_NOT_US, "KRB5KRB_AP_ERR_NOT_US" },
	{ KRB5_ET_KRB5KRB_AP_ERR_BADMATCH, "KRB5KRB_AP_ERR_BADMATCH" },
	{ KRB5_ET_KRB5KRB_AP_ERR_SKEW, "KRB5KRB_AP_ERR_SKEW" },
	{ KRB5_ET_KRB5KRB_AP_ERR_BADADDR, "KRB5KRB_AP_ERR_BADADDR" },
	{ KRB5_ET_KRB5KRB_AP_ERR_BADVERSION, "KRB5KRB_AP_ERR_BADVERSION" },
	{ KRB5_ET_KRB5KRB_AP_ERR_MSG_TYPE, "KRB5KRB_AP_ERR_MSG_TYPE" },
	{ KRB5_ET_KRB5KRB_AP_ERR_MODIFIED, "KRB5KRB_AP_ERR_MODIFIED" },
	{ KRB5_ET_KRB5KRB_AP_ERR_BADORDER, "KRB5KRB_AP_ERR_BADORDER" },
	{ KRB5_ET_KRB5KRB_AP_ERR_ILL_CR_TKT, "KRB5KRB_AP_ERR_ILL_CR_TKT" },
	{ KRB5_ET_KRB5KRB_AP_ERR_BADKEYVER, "KRB5KRB_AP_ERR_BADKEYVER" },
	{ KRB5_ET_KRB5KRB_AP_ERR_NOKEY, "KRB5KRB_AP_ERR_NOKEY" },
	{ KRB5_ET_KRB5KRB_AP_ERR_MUT_FAIL, "KRB5KRB_AP_ERR_MUT_FAIL" },
	{ KRB5_ET_KRB5KRB_AP_ERR_BADDIRECTION, "KRB5KRB_AP_ERR_BADDIRECTION" },
	{ KRB5_ET_KRB5KRB_AP_ERR_METHOD, "KRB5KRB_AP_ERR_METHOD" },
	{ KRB5_ET_KRB5KRB_AP_ERR_BADSEQ, "KRB5KRB_AP_ERR_BADSEQ" },
	{ KRB5_ET_KRB5KRB_AP_ERR_INAPP_CKSUM, "KRB5KRB_AP_ERR_INAPP_CKSUM" },
	{ KRB5_ET_KRB5KRB_ERR_RESPONSE_TOO_BIG, "KRB5KRB_ERR_RESPONSE_TOO_BIG"},
	{ KRB5_ET_KRB5KRB_ERR_GENERIC, "KRB5KRB_ERR_GENERIC" },
	{ KRB5_ET_KRB5KRB_ERR_FIELD_TOOLONG, "KRB5KRB_ERR_FIELD_TOOLONG" },
	{ 0, NULL }
};


static const value_string krb5_princ_types[] = {
    { KRB5_NT_UNKNOWN              , "Unknown" },
    { KRB5_NT_PRINCIPAL            , "Principal" },
    { KRB5_NT_SRV_INST             , "Service and Instance" },
    { KRB5_NT_SRV_HST              , "Service and Host" },
    { KRB5_NT_SRV_XHST             , "Service and Host Components" },
    { KRB5_NT_UID                  , "Unique ID" },
    { 0                            , NULL },
};

static const value_string krb5_preauthentication_types[] = {
    { KRB5_PA_TGS_REQ              , "PA-TGS-REQ" },
    { KRB5_PA_ENC_TIMESTAMP        , "PA-ENC-TIMESTAMP" },
    { KRB5_PA_PW_SALT              , "PA-PW-SALT" },
    { KRB5_PA_ENC_ENCKEY           , "PA-ENC-ENCKEY" },
    { KRB5_PA_ENC_UNIX_TIME        , "PA-ENC-UNIX-TIME" },
    { KRB5_PA_ENC_SANDIA_SECURID   , "PA-PW-SALT" },
    { KRB5_PA_SESAME               , "PA-SESAME" },
    { KRB5_PA_OSF_DCE              , "PA-OSF-DCE" },
    { KRB5_PA_CYBERSAFE_SECUREID   , "PA-CYBERSAFE-SECURID" },
    { KRB5_PA_AFS3_SALT            , "PA-AFS3-SALT" },
    { KRB5_PA_ENCTYPE_INFO         , "PA-ENCTYPE-INFO" },
    { KRB5_PA_SAM_CHALLENGE        , "PA-SAM-CHALLENGE" },
    { KRB5_PA_SAM_RESPONSE         , "PA-SAM-RESPONSE" },
    { KRB5_PA_DASS                 , "PA-DASS" },
    { KRB5_PA_USE_SPECIFIED_KVNO   , "PA-USE-SPECIFIED-KVNO" },
    { KRB5_PA_SAM_REDIRECT         , "PA-SAM-REDIRECT" },
    { KRB5_PA_GET_FROM_TYPED_DATA  , "PA-GET-FROM-TYPED-DATA" },
    { KRB5_PA_SAM_ETYPE_INFO       , "PA-SAM-ETYPE-INFO" },
    { KRB5_PA_ALT_PRINC            , "PA-ALT-PRINC" },
    { KRB5_PA_SAM_CHALLENGE2       , "PA-SAM-CHALLENGE2" },
    { KRB5_PA_SAM_RESPONSE2        , "PA-SAM-RESPONSE2" },
    { KRB5_PA_PAC_REQUEST          , "PA-PAC-REQUEST" },
    { 0                            , NULL },
};

static const value_string krb5_encryption_types[] = {
    { KRB5_ENCTYPE_NULL           , "NULL" },
    { KRB5_ENCTYPE_DES_CBC_CRC    , "des-cbc-crc" },
    { KRB5_ENCTYPE_DES_CBC_MD4    , "des-cbc-md4" },
    { KRB5_ENCTYPE_DES_CBC_MD5    , "des-cbc-md5" },
    { KRB5_ENCTYPE_DES_CBC_RAW    , "des-cbc-raw" },
    { KRB5_ENCTYPE_DES3_CBC_SHA   , "des3-cbc-sha" },
    { KRB5_ENCTYPE_DES3_CBC_RAW   , "des3-cbc-raw" },
    { KRB5_ENCTYPE_DES_HMAC_SHA1  , "des-hmac-sha1" },
    { KRB5_ENCTYPE_DES3_CBC_SHA1  , "des3-cbc-sha1" },
    { KERB_ENCTYPE_RC4_HMAC       , "rc4-hmac" },
    { KERB_ENCTYPE_RC4_HMAC_EXP   , "rc4-hmac-exp" },
    { KRB5_ENCTYPE_UNKNOWN        , "unknown" },
    { KRB5_ENCTYPE_LOCAL_DES3_HMAC_SHA1    , "local-des3-hmac-sha1" },
    { 0                            , NULL },
};

static const value_string krb5_address_types[] = {
    { KRB5_ADDR_IPv4,		"IPv4"},
    { KRB5_ADDR_CHAOS,		"CHAOS"},
    { KRB5_ADDR_XEROX,		"XEROX"},
    { KRB5_ADDR_ISO,		"ISO"},
    { KRB5_ADDR_DECNET,		"DECNET"},
    { KRB5_ADDR_APPLETALK,	"APPLETALK"},
    { KRB5_ADDR_NETBIOS,     	"NETBIOS"},
    { KRB5_ADDR_IPv6,		"IPv6"},
    { 0,                        NULL },
};

static const value_string krb5_msg_types[] = {
	{ KRB5_MSG_TGS_REQ,	"TGS-REQ" },
	{ KRB5_MSG_TGS_REP,	"TGS-REP" },
	{ KRB5_MSG_AS_REQ,	"AS-REQ" },
	{ KRB5_MSG_AS_REP,	"AS-REP" },
	{ KRB5_MSG_AP_REQ,	"AP-REQ" },
	{ KRB5_MSG_AP_REP,	"AP-REP" },
	{ KRB5_MSG_SAFE,	"KRB-SAFE" },
	{ KRB5_MSG_PRIV,	"KRB-PRIV" },
	{ KRB5_MSG_CRED,	"KRB-CRED" },
	{ KRB5_MSG_ERROR,	"KRB-ERROR" },
        { 0,                    NULL },
};




static int dissect_krb5_application_choice(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_krb5_KDC_REQ(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_krb5_KDC_REP(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_krb5_AP_REQ(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_krb5_AP_REP(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_krb5_ERROR(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);

static const ber_choice kerberos_applications_choice[] = {
	{ BER_CLASS_APP,	10,	dissect_krb5_KDC_REQ },
	{ BER_CLASS_APP,	11,	dissect_krb5_KDC_REP },
	{ BER_CLASS_APP,	12,	dissect_krb5_KDC_REQ },
	{ BER_CLASS_APP,	13,	dissect_krb5_KDC_REP },
	{ BER_CLASS_APP,	14,	dissect_krb5_AP_REQ },
	{ BER_CLASS_APP,	15,	dissect_krb5_AP_REP },
	{ BER_CLASS_APP,	30,	dissect_krb5_ERROR },
	{ 0, 0, NULL }
};


static int 
dissect_krb5_application_choice(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_choice(pinfo, tree, tvb, offset, kerberos_applications_choice, -1, -1);
	return offset;
}


static const true_false_string krb5_apoptions_use_session_key = {
	"USE SESSION KEY to encrypt the ticket",
	"Do NOT use the session key to encrypt the ticket"
};
static const true_false_string krb5_apoptions_mutual_required = {
	"MUTUAL authentication is REQUIRED",
	"Mutual authentication is NOT required"
};

static int
dissect_krb5_APOptions(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	unsigned char options[4]={0,0,0,0};
	proto_item *item;
	proto_tree *flags_tree;

	offset=dissect_ber_bitstring(pinfo, tree, tvb, offset, hf_krb_APOptions, ett_krb_AP_Options, options, 4, &item, &flags_tree);

	/* use session key */
	proto_tree_add_boolean(flags_tree, hf_krb_APOptions_use_session_key , tvb, 0, 0, (options[0]&0x40)?0x40000000:0);
	if(options[0]&0x40){
		if(item){
			proto_item_append_text(item, " Use-Session-Key");
		}
	}
	/* mutual required */
	proto_tree_add_boolean(flags_tree, hf_krb_APOptions_mutual_required , tvb, 0, 0, (options[0]&0x20)?0x20000000:0);
	if(options[0]&0x20){
		if(item){
			proto_item_append_text(item, " Mutual-Required");
		}
	}

	return offset;
}







static const true_false_string krb5_kdcoptions_forwardable = {
	"FORWARDABLE tickets are allowed/requested",
	"Do NOT use forwardable tickets"
};
static const true_false_string krb5_kdcoptions_forwarded = {
	"This ticket has been FORWARDED",
	"This is NOT a forwarded ticket"
};
static const true_false_string krb5_kdcoptions_proxyable = {
	"PROXIABLE tickets are allowed/requested",
	"Do NOT use proxiable tickets"
};
static const true_false_string krb5_kdcoptions_proxy = {
	"This is a PROXY ticket",
	"This ticket has NOT been proxied"
};
static const true_false_string krb5_kdcoptions_allow_postdate = {
	"We allow the ticket to be POSTDATED",
	"We do NOT allow the ticket to be postdated"
};
static const true_false_string krb5_kdcoptions_postdated = {
	"This ticket is POSTDATED",
	"This ticket is NOT postdated"
};
static const true_false_string krb5_kdcoptions_renewable = {
	"This ticket is RENEWABLE",
	"This ticket is NOT renewable"
};
static const true_false_string krb5_kdcoptions_renewable_ok = {
	"We accept RENEWED tickets",
	"We do NOT accept renewed tickets"
};
static const true_false_string krb5_kdcoptions_enc_tkt_in_skey = {
	"ENCrypt TKT in SKEY",
	"Do NOT encrypt the tkt inside the skey"
};
static const true_false_string krb5_kdcoptions_renew = {
	"This is a request to RENEW a ticket",
	"This is NOT a request to renew a ticket"
};
static const true_false_string krb5_kdcoptions_validate = {
	"This is a request to VALIDATE a postdated ticket",
	"This is NOT a request to validate a postdated ticket"
};

static int
dissect_krb5_KDCOptions(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	unsigned char options[4]={0,0,0,0};
	proto_item *item;
	proto_tree *flags_tree;

	offset=dissect_ber_bitstring(pinfo, tree, tvb, offset, hf_krb_KDCOptions, ett_krb_KDC_Options, options, 4, &item, &flags_tree);

	/* forwardable */
	proto_tree_add_boolean(flags_tree, hf_krb_KDCOptions_forwardable , tvb, 0, 0, (options[0]&0x40)?0x40000000:0);
	if(options[0]&0x40){
		if(item){
			proto_item_append_text(item, " Forwardable");
		}
	}
	/* forwarded */
	proto_tree_add_boolean(flags_tree, hf_krb_KDCOptions_forwarded , tvb, 0, 0, (options[0]&0x20)?0x20000000:0);
	if(options[0]&0x20){
		if(item){
			proto_item_append_text(item, " Forwarded");
		}
	}
	/* proxyable */
	proto_tree_add_boolean(flags_tree, hf_krb_KDCOptions_proxyable , tvb, 0, 0, (options[0]&0x10)?0x10000000:0);
	if(options[0]&0x10){
		if(item){
			proto_item_append_text(item, " Proxyable");
		}
	}
	/* proxy */
	proto_tree_add_boolean(flags_tree, hf_krb_KDCOptions_proxy , tvb, 0, 0, (options[0]&0x08)?0x08000000:0);
	if(options[0]&0x08){
		if(item){
			proto_item_append_text(item, " Proxy");
		}
	}
	/* allow-postdate */
	proto_tree_add_boolean(flags_tree, hf_krb_KDCOptions_allow_postdate , tvb, 0, 0, (options[0]&0x04)?0x04000000:0);
	if(options[0]&0x04){
		if(item){
			proto_item_append_text(item, " Allow-Postdate");
		}
	}
	/* postdated */
	proto_tree_add_boolean(flags_tree, hf_krb_KDCOptions_postdated , tvb, 0, 0, (options[0]&0x02)?0x02000000:0);
	if(options[0]&0x02){
		if(item){
			proto_item_append_text(item, " Postdated");
		}
	}
	/* renewable */
	proto_tree_add_boolean(flags_tree, hf_krb_KDCOptions_renewable , tvb, 0, 0, (options[1]&0x80)?0x00800000:0);
	if(options[1]&0x80){
		if(item){
			proto_item_append_text(item, " Renewable");
		}
	}
	/* renewable_ok */
	proto_tree_add_boolean(flags_tree, hf_krb_KDCOptions_renewable_ok , tvb, 0, 0, (options[3]&0x10)?0x00000010:0);
	if(options[3]&0x10){
		if(item){
			proto_item_append_text(item, " Renewable_Ok");
		}
	}
	/* enc_tkt_in_skey */
	proto_tree_add_boolean(flags_tree, hf_krb_KDCOptions_enc_tkt_in_skey , tvb, 0, 0, (options[3]&0x08)?0x00000008:0);
	if(options[3]&0x08){
		if(item){
			proto_item_append_text(item, " Enc-Tkt-in-Skey");
		}
	}
	/* renew */
	proto_tree_add_boolean(flags_tree, hf_krb_KDCOptions_renew , tvb, 0, 0, (options[3]&0x02)?0x00000002:0);
	if(options[3]&0x02){
		if(item){
			proto_item_append_text(item, " Renew");
		}
	}
	/* validate */
	proto_tree_add_boolean(flags_tree, hf_krb_KDCOptions_validate , tvb, 0, 0, (options[3]&0x01)?0x00000001:0);
	if(options[3]&0x01){
		if(item){
			proto_item_append_text(item, " Validate");
		}
	}

	return offset;
}

static int 
dissect_krb5_rtime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_generalized_time(pinfo, tree, tvb, offset, hf_krb_rtime);
	return offset;
}

static int 
dissect_krb5_ctime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_generalized_time(pinfo, tree, tvb, offset, hf_krb_ctime);
	return offset;
}
static int
dissect_krb5_cusec(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(pinfo, tree, tvb, offset, hf_krb_cusec, NULL);
	return offset;
}

static int 
dissect_krb5_stime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_generalized_time(pinfo, tree, tvb, offset, hf_krb_stime);
	return offset;
}
static int
dissect_krb5_susec(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(pinfo, tree, tvb, offset, hf_krb_susec, NULL);
	return offset;
}


static int
dissect_krb5_error_code(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(pinfo, tree, tvb, offset, hf_krb_error_code, &krb5_error_code);
	if(krb5_error_code && check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, 
			"KRB Error: %s",
			val_to_str(krb5_error_code, krb5_error_codes,
			"Unknown error code %#x"));
	}

	return offset;
}


static int 
dissect_krb5_till(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_generalized_time(pinfo, tree, tvb, offset, hf_krb_till);
	return offset;
}
static int 
dissect_krb5_from(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_generalized_time(pinfo, tree, tvb, offset, hf_krb_from);
	return offset;
}



static int 
dissect_krb5_nonce(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(pinfo, tree, tvb, offset, hf_krb_nonce, NULL);
	return offset;
}


/*
 *          etype[8]             SEQUENCE OF INTEGER, -- EncryptionType,
 */
static int 
dissect_krb5_etype(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	guint32 etype;

	offset=dissect_ber_integer(pinfo, tree, tvb, offset, hf_krb_etype, &etype);
	if(tree){
		proto_item_append_text(tree, " %s", 
			val_to_str(etype, krb5_encryption_types,
			"%#x"));
	}
	return offset;
}
static int
dissect_krb5_etype_sequence_of(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence_of(pinfo, tree, tvb, offset, dissect_krb5_etype, hf_krb_etypes, ett_krb_etypes);

	return offset;
}



/*
 *  HostAddress ::=    SEQUENCE  {
 *                     addr-type[0]             INTEGER,
 *                     address[1]               OCTET STRING
 *  }
 */
static guint32 addr_type;
static int dissect_krb5_addr_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(pinfo, tree, tvb, offset, hf_krb_addr_type, &addr_type);
	return offset;
}
static int dissect_krb5_address(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	guint8 class;
	gboolean pc;
	guint32 tag;
	guint32 len;
	char address_str[256];
	proto_item *it=NULL;

	/* read header and len for the octet string */
	offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
	offset=dissect_ber_length(pinfo, tree, tvb, offset, &len);


	address_str[0]=0;
	address_str[255]=0;
	switch(addr_type){
	case KRB5_ADDR_IPv4:
		it=proto_tree_add_item(tree, hf_krb_address_ip, tvb, offset, 4, FALSE);
		sprintf(address_str,"%d.%d.%d.%d",tvb_get_guint8(tvb, offset),tvb_get_guint8(tvb, offset+1),tvb_get_guint8(tvb, offset+2),tvb_get_guint8(tvb, offset+3));
		break;
	case KRB5_ADDR_NETBIOS:
		{
		char netbios_name[(NETBIOS_NAME_LEN - 1)*4 + 1];
		int netbios_name_type;

		netbios_name_type = process_netbios_name(tvb_get_ptr(tvb, offset, 16), netbios_name);
		snprintf(address_str, 255, "%s<%02d>", netbios_name, netbios_name_type); 
		it=proto_tree_add_string_format(tree, hf_krb_address_netbios, tvb, offset, 16, netbios_name, "NetBIOS Name: %s (%s)", address_str, netbios_name_type_descr(netbios_name_type));
		}
		break;
	default:
		proto_tree_add_text(tree, tvb, offset, len, "KRB Address: I dont know how to parse this type of address yet");

	}

	/* push it up two levels in the decode pane */
	if(it){
		proto_item_append_text(it->parent, "  %s",address_str);
		proto_item_append_text(it->parent->parent, "  %s",address_str);
	}

	offset+=len;
	return offset;
}
static ber_sequence HostAddress_sequence[] = {
	{ BER_CLASS_CON, 0, 0, dissect_krb5_addr_type },
	{ BER_CLASS_CON, 1, 0, dissect_krb5_address },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_HostAddress(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{

	offset=dissect_ber_sequence(pinfo, tree, tvb, offset, HostAddress_sequence, hf_krb_HostAddress, ett_krb_HostAddress);

	return offset;
}

/*
 *  HostAddresses ::=   SEQUENCE OF SEQUENCE {
 *                      addr-type[0]             INTEGER,
 *                      address[1]               OCTET STRING
 *  }
 *
 */
static int
dissect_krb5_HostAddresses(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence_of(pinfo, tree, tvb, offset, dissect_krb5_HostAddress, hf_krb_HostAddresses, ett_krb_HostAddresses);

	return offset;
}



static int
dissect_krb5_msg_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	guint32 msgtype;

	offset=dissect_ber_integer(pinfo, tree, tvb, offset, hf_krb_msg_type, &msgtype);

	if (do_col_info & check_col(pinfo->cinfo, COL_INFO)) {
		col_add_str(pinfo->cinfo, COL_INFO, 
			val_to_str(msgtype, krb5_msg_types,
			"Unknown msg type %#x"));
	}
	do_col_info=FALSE;

	return offset;
}



static int
dissect_krb5_pvno(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(pinfo, tree, tvb, offset, hf_krb_pvno, NULL);

	return offset;
}


/*
 * PrincipalName ::=   SEQUENCE {
 *                     name-type[0]     INTEGER,
 *                     name-string[1]   SEQUENCE OF GeneralString
 * }
 */
static guint32 name_type;
static int 
dissect_krb5_name_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(pinfo, tree, tvb, offset, hf_krb_name_type, &name_type);
	if(tree){
		proto_item_append_text(tree, "  (%s):", 
			val_to_str(name_type, krb5_princ_types,
			"Unknown:%d"));
	}
	return offset;
}
static int 
dissect_krb5_name_string(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	char name_string[256];

	offset=dissect_ber_GeneralString(pinfo, tree, tvb, offset, hf_krb_name_string, name_string, 255);
	if(tree){
		proto_item_append_text(tree, " %s", name_string);
	}

	return offset;
}
static int 
dissect_krb5_name_strings(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence_of(pinfo, tree, tvb, offset, dissect_krb5_name_string, -1, -1);

	return offset;
}
static ber_sequence PrincipalName_sequence[] = {
	{ BER_CLASS_CON, 0, 0, dissect_krb5_name_type },
	{ BER_CLASS_CON, 1, 0, dissect_krb5_name_strings },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_sname(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{

	offset=dissect_ber_sequence(pinfo, tree, tvb, offset, PrincipalName_sequence, hf_krb_sname, ett_krb_sname);

	return offset;
}
static int
dissect_krb5_cname(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{

	offset=dissect_ber_sequence(pinfo, tree, tvb, offset, PrincipalName_sequence, hf_krb_cname, ett_krb_cname);

	return offset;
}


static int 
dissect_krb5_realm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_GeneralString(pinfo, tree, tvb, offset, hf_krb_realm, NULL, 0);
	return offset;
}

static int 
dissect_krb5_crealm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_GeneralString(pinfo, tree, tvb, offset, hf_krb_crealm, NULL, 0);
	return offset;
}



static int
dissect_krb5_PA_PAC_REQUEST_flag(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_boolean(pinfo, tree, tvb, offset, hf_krb_PA_PAC_REQUEST_flag);
	return offset;
}


static ber_sequence PA_PAC_REQUEST_sequence[] = {
	{ BER_CLASS_CON, 0, 0, dissect_krb5_PA_PAC_REQUEST_flag },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_PA_PAC_REQUEST(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{

	offset=dissect_ber_sequence(pinfo, tree, tvb, offset, PA_PAC_REQUEST_sequence, -1, -1);

	return offset;
}




static int
dissect_krb5_kvno(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(pinfo, tree, tvb, offset, hf_krb_kvno, NULL);

	return offset;
}




static int
dissect_krb5_encrypted_PA_ENC_TIMESTAMP(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_octet_string(pinfo, tree, tvb, offset, hf_krb_encrypted_PA_ENC_TIMESTAMP, NULL);
	return offset;
/*qqq*/
}
static ber_sequence PA_ENC_TIMESTAMP_sequence[] = {
	{ BER_CLASS_CON, 0, 0, 
		dissect_krb5_etype },
	{ BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL,
		dissect_krb5_kvno },
	{ BER_CLASS_CON, 2, 0,
		dissect_krb5_encrypted_PA_ENC_TIMESTAMP },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_PA_ENC_TIMESTAMP(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(pinfo, tree, tvb, offset, PA_ENC_TIMESTAMP_sequence, -1, -1);

	return offset;
}



/*
 * PA-DATA ::=        SEQUENCE {
 *          padata-type[1]        INTEGER,
 *          padata-value[2]       OCTET STRING,
 *                        -- might be encoded AP-REQ
 * }
 */
guint32 krb_PA_DATA_type;
static int
dissect_krb5_PA_DATA_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(pinfo, tree, tvb, offset, hf_krb_PA_DATA_type, &krb_PA_DATA_type);

	if(tree){
		proto_item_append_text(tree, " %s", 
			val_to_str(krb_PA_DATA_type, krb5_preauthentication_types,
			"Unknown:%d"));
	}
	return offset;
}
static int
dissect_krb5_PA_DATA_value(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
	proto_tree *tree=parent_tree;

	if(ber_last_created_item){
		tree=proto_item_add_subtree(ber_last_created_item, ett_krb_PA_DATA_tree);
	}


	switch(krb_PA_DATA_type){
	case KRB5_PA_TGS_REQ:
		offset=dissect_ber_octet_string(pinfo, tree, tvb, offset,hf_krb_PA_DATA_value, dissect_krb5_application_choice);
 		break;
	case KRB5_PA_PAC_REQUEST:
		offset=dissect_ber_octet_string(pinfo, tree, tvb, offset,hf_krb_PA_DATA_value, dissect_krb5_PA_PAC_REQUEST);
 		break;
	case KRB5_PA_ENC_TIMESTAMP:
		offset=dissect_ber_octet_string(pinfo, tree, tvb, offset,hf_krb_PA_DATA_value, dissect_krb5_PA_ENC_TIMESTAMP);
 		break;
	default:
		offset=dissect_ber_octet_string(pinfo, tree, tvb, offset,hf_krb_PA_DATA_value, NULL);
	}
	return offset;
/*qqq*/
}

static ber_sequence PA_DATA_sequence[] = {
	{ BER_CLASS_CON, 1, 0, dissect_krb5_PA_DATA_type },
	{ BER_CLASS_CON, 2, 0, dissect_krb5_PA_DATA_value },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_PA_DATA(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(pinfo, tree, tvb, offset, PA_DATA_sequence, -1, -1);

	return offset;
}




/*
 * padata[3]             SEQUENCE OF PA-DATA OPTIONAL,
 *
 */
static int
dissect_krb5_padata(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence_of(pinfo, tree, tvb, offset, dissect_krb5_PA_DATA, hf_krb_padata, ett_krb_padata);

	return offset;
}



/*
 * KDC-REQ-BODY ::=   SEQUENCE {
 *           kdc-options[0]       KDCOptions,
 *           cname[1]             PrincipalName OPTIONAL,
 *                        -- Used only in AS-REQ
 *           realm[2]             Realm, -- Server's realm
 *                        -- Also client's in AS-REQ
 *           sname[3]             PrincipalName OPTIONAL,
 *           from[4]              KerberosTime OPTIONAL,
 *           till[5]              KerberosTime,
 *           rtime[6]             KerberosTime OPTIONAL,
 *           nonce[7]             INTEGER,
 *           etype[8]             SEQUENCE OF INTEGER, -- EncryptionType,
 *                        -- in preference order
 *           addresses[9]         HostAddresses OPTIONAL,
 *           enc-authorization-data[10]   EncryptedData OPTIONAL,
 *                        -- Encrypted AuthorizationData encoding
 *           additional-tickets[11]       SEQUENCE OF Ticket OPTIONAL
 * }
 *
 */
static ber_sequence KDC_REQ_BODY_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_KDCOptions },
	{ BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL,
		dissect_krb5_cname },
	{ BER_CLASS_CON, 2, 0,
		dissect_krb5_realm},
	{ BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL,
		dissect_krb5_sname },
	{ BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL,
		dissect_krb5_from },
	{ BER_CLASS_CON, 5, 0,
		dissect_krb5_till },
	{ BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL,
		dissect_krb5_rtime },
	{ BER_CLASS_CON, 7, 0,
		dissect_krb5_nonce },
	{ BER_CLASS_CON, 8, 0,
		dissect_krb5_etype_sequence_of },
	{ BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL,
		dissect_krb5_HostAddresses },
/* XXX [10] and [11] enc-authorization-data and additional-tickets should be added */
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_KDC_REQ_BODY(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{

	offset=dissect_ber_sequence(pinfo, tree, tvb, offset, KDC_REQ_BODY_sequence, hf_krb_KDC_REQ_BODY, ett_krb_request);

	return offset;
}



/*
 * KDC-REQ ::=        SEQUENCE {
 *          pvno[1]               INTEGER,
 *          msg-type[2]           INTEGER,
 *          padata[3]             SEQUENCE OF PA-DATA OPTIONAL,
 *          req-body[4]           KDC-REQ-BODY
 * }
 */
static ber_sequence KDC_REQ_sequence[] = {
	{ BER_CLASS_CON, 1, 0, 
		dissect_krb5_pvno },
	{ BER_CLASS_CON, 2, 0, 
		dissect_krb5_msg_type },
	{ BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL,
		dissect_krb5_padata },
	{ BER_CLASS_CON, 4, 0,
		dissect_krb5_KDC_REQ_BODY },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_KDC_REQ(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(pinfo, tree, tvb, offset, KDC_REQ_sequence, -1, -1);

	return offset;
}


/*
 *  EncryptedData ::=   SEQUENCE {
 *                      etype[0]     INTEGER, -- EncryptionType
 *                      kvno[1]      INTEGER OPTIONAL,
 *                      cipher[2]    OCTET STRING -- ciphertext
 *  }
 */
static int
dissect_krb5_encrypted_authenticator_data(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_octet_string(pinfo, tree, tvb, offset, hf_krb_encrypted_authenticator_data, NULL);
	return offset;
/*qqq*/
}
static ber_sequence encrypted_authenticator_sequence[] = {
	{ BER_CLASS_CON, 0, 0, 
		dissect_krb5_etype },
	{ BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL,
		dissect_krb5_kvno },
	{ BER_CLASS_CON, 2, 0,
		dissect_krb5_encrypted_authenticator_data },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_encrypted_authenticator(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(pinfo, tree, tvb, offset, encrypted_authenticator_sequence, hf_krb_authenticator_enc, ett_krb_authenticator_enc);

	return offset;
}




static int 
dissect_krb5_tkt_vno(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(pinfo, tree, tvb, offset, hf_krb_tkt_vno, NULL);
	return offset;
}




static int
dissect_krb5_encrypted_Ticket_data(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_octet_string(pinfo, tree, tvb, offset, hf_krb_encrypted_Ticket_data, NULL);
	return offset;
/*qqq*/
}
static ber_sequence encrypted_Ticket_sequence[] = {
	{ BER_CLASS_CON, 0, 0, 
		dissect_krb5_etype },
	{ BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL,
		dissect_krb5_kvno },
	{ BER_CLASS_CON, 2, 0,
		dissect_krb5_encrypted_Ticket_data },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_Ticket_encrypted(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(pinfo, tree, tvb, offset, encrypted_Ticket_sequence, hf_krb_ticket_enc, ett_krb_ticket_enc);

	return offset;
}

static ber_sequence Application_1_sequence[] = {
	{ BER_CLASS_CON, 0, 0, 
		dissect_krb5_tkt_vno },
	{ BER_CLASS_CON, 1, 0, 
		dissect_krb5_realm },
	{ BER_CLASS_CON, 2, 0, 
		dissect_krb5_sname },
	{ BER_CLASS_CON, 3, 0, 
		dissect_krb5_Ticket_encrypted },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_Application_1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(pinfo, tree, tvb, offset, Application_1_sequence, hf_krb_ticket, ett_krb_ticket);

	return offset;
}



static const ber_choice Ticket_choice[] = {
	{ BER_CLASS_APP, 1,  
		dissect_krb5_Application_1 },
	{ 0, 0, NULL }
};
static int
dissect_krb5_Ticket(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_choice(pinfo, tree, tvb, offset, Ticket_choice, -1, -1);

	return offset;
}




/*
 *  AP-REQ ::=      [APPLICATION 14] SEQUENCE {
 *                  pvno[0]                       INTEGER,
 *                  msg-type[1]                   INTEGER,
 *                  ap-options[2]                 APOptions,
 *                  ticket[3]                     Ticket,
 *                  authenticator[4]              EncryptedData
 *  }
 */
static ber_sequence AP_REQ_sequence[] = {
	{ BER_CLASS_CON, 0, 0, 
		dissect_krb5_pvno },
	{ BER_CLASS_CON, 1, 0, 
		dissect_krb5_msg_type },
	{ BER_CLASS_CON, 2, 0, 
		dissect_krb5_APOptions },
	{ BER_CLASS_CON, 3, 0, 
		dissect_krb5_Ticket },
	{ BER_CLASS_CON, 4, 0, 
		dissect_krb5_encrypted_authenticator },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_AP_REQ(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(pinfo, tree, tvb, offset, AP_REQ_sequence, -1, -1);

	return offset;
}




static int
dissect_krb5_encrypted_AP_REP_data(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_octet_string(pinfo, tree, tvb, offset, hf_krb_encrypted_AP_REP_data, NULL);
	return offset;
/*qqq*/
}
static ber_sequence encrypted_AP_REP_sequence[] = {
	{ BER_CLASS_CON, 0, 0, 
		dissect_krb5_etype },
	{ BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL,
		dissect_krb5_kvno },
	{ BER_CLASS_CON, 2, 0,
		dissect_krb5_encrypted_AP_REP_data },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_encrypted_AP_REP(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(pinfo, tree, tvb, offset, encrypted_AP_REP_sequence, hf_krb_AP_REP_enc, ett_krb_AP_REP_enc);

	return offset;
}

/*
 *  AP-REP ::=         [APPLICATION 15] SEQUENCE {
 *             pvno[0]                   INTEGER,
 *             msg-type[1]               INTEGER,
 *             enc-part[2]               EncryptedData
 *  }
 */
static ber_sequence AP_REP_sequence[] = {
	{ BER_CLASS_CON, 0, 0, 
		dissect_krb5_pvno },
	{ BER_CLASS_CON, 1, 0, 
		dissect_krb5_msg_type },
	{ BER_CLASS_CON, 2, 0, 
		dissect_krb5_encrypted_AP_REP },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_AP_REP(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(pinfo, tree, tvb, offset, AP_REP_sequence, -1, -1);

	return offset;
}








static int
dissect_krb5_encrypted_KDC_REP_data(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_octet_string(pinfo, tree, tvb, offset, hf_krb_encrypted_KDC_REP_data, NULL);
	return offset;
/*qqq*/
}
static ber_sequence encrypted_KDC_REP_sequence[] = {
	{ BER_CLASS_CON, 0, 0, 
		dissect_krb5_etype },
	{ BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL,
		dissect_krb5_kvno },
	{ BER_CLASS_CON, 2, 0,
		dissect_krb5_encrypted_KDC_REP_data },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_encrypted_KDC_REP(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(pinfo, tree, tvb, offset, encrypted_KDC_REP_sequence, hf_krb_KDC_REP_enc, ett_krb_KDC_REP_enc);

	return offset;
}

/*
 *  KDC-REP ::=   SEQUENCE {
 *                pvno[0]                    INTEGER,
 *                msg-type[1]                INTEGER,
 *                padata[2]                  SEQUENCE OF PA-DATA OPTIONAL,
 *                crealm[3]                  Realm,
 *                cname[4]                   PrincipalName,
 *                ticket[5]                  Ticket,
 *                enc-part[6]                EncryptedData
 *  }
 */
static ber_sequence KDC_REP_sequence[] = {
	{ BER_CLASS_CON, 0, 0, 
		dissect_krb5_pvno },
	{ BER_CLASS_CON, 1, 0, 
		dissect_krb5_msg_type },
	{ BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL,
		dissect_krb5_padata },
	{ BER_CLASS_CON, 3, 0, 
		dissect_krb5_crealm },
	{ BER_CLASS_CON, 4, 0,
		dissect_krb5_cname },
	{ BER_CLASS_CON, 5, 0, 
		dissect_krb5_Ticket },
	{ BER_CLASS_CON, 6, 0, 
		dissect_krb5_encrypted_KDC_REP },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_KDC_REP(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(pinfo, tree, tvb, offset, KDC_REP_sequence, -1, -1);

	return offset;
}




static int 
dissect_krb5_e_text(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_GeneralString(pinfo, tree, tvb, offset, hf_krb_e_text, NULL, 0);
	return offset;
}
static int 
dissect_krb5_e_data(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	switch(krb5_error_code){
	case KRB5_ET_KRB5KDC_ERR_PREAUTH_REQUIRED:
		offset=dissect_ber_octet_string(pinfo, tree, tvb, offset, hf_krb_e_data, dissect_krb5_application_choice);
		break;
	default:
		offset=dissect_ber_octet_string(pinfo, tree, tvb, offset, hf_krb_e_data, NULL);
	}
	return offset;
}


/*
 *  KRB-ERROR ::=   [APPLICATION 30] SEQUENCE {
 *                  pvno[0]               INTEGER,
 *                  msg-type[1]           INTEGER,
 *                  ctime[2]              KerberosTime OPTIONAL,
 *                  cusec[3]              INTEGER OPTIONAL,
 *                  stime[4]              KerberosTime,
 *                  susec[5]              INTEGER,
 *                  error-code[6]         INTEGER,
 *                  crealm[7]             Realm OPTIONAL,
 *                  cname[8]              PrincipalName OPTIONAL,
 *                  realm[9]              Realm, -- Correct realm
 *                  sname[10]             PrincipalName, -- Correct name
 *                  e-text[11]            GeneralString OPTIONAL,
 *                  e-data[12]            OCTET STRING OPTIONAL
 *  }
 *
 *  e-data    This field contains additional data about the error for use
 *            by the application to help it recover from or handle the
 *            error.  If the errorcode is KDC_ERR_PREAUTH_REQUIRED, then
 *            the e-data field will contain an encoding of a sequence of
 *            padata fields, each corresponding to an acceptable pre-
 *            authentication method and optionally containing data for
 *            the method:
 */
static ber_sequence ERROR_sequence[] = {
	{ BER_CLASS_CON, 0, 0, 
		dissect_krb5_pvno },
	{ BER_CLASS_CON, 1, 0,
		dissect_krb5_msg_type },
	{ BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL,
		dissect_krb5_ctime },
	{ BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL,
		dissect_krb5_cusec },
	{ BER_CLASS_CON, 4, 0,
		dissect_krb5_stime },
	{ BER_CLASS_CON, 5, 0,
		dissect_krb5_susec },
	{ BER_CLASS_CON, 6, 0,
		dissect_krb5_error_code },
	{ BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL,
		dissect_krb5_crealm },
	{ BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL,
		dissect_krb5_cname },
	{ BER_CLASS_CON, 9, 0,
		dissect_krb5_realm },
	{ BER_CLASS_CON, 10, 0, 
		dissect_krb5_sname },
	{ BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL,
		dissect_krb5_e_text },
	{ BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL,
		dissect_krb5_e_data },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_ERROR(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(pinfo, tree, tvb, offset, ERROR_sequence, -1, -1);

	return offset;
}



static struct { char *set; char *unset; } bitval = { "Set", "Not set" };

static void dissect_kerberos_udp(tvbuff_t *tvb, packet_info *pinfo,
				 proto_tree *tree);
static void dissect_kerberos_tcp(tvbuff_t *tvb, packet_info *pinfo,
				 proto_tree *tree);
static gint dissect_kerberos_common(tvbuff_t *tvb, packet_info *pinfo,
					proto_tree *tree, int do_col_info,
					gboolean have_rm);
static gint kerberos_rm_to_reclen(guint krb_rm);
static void dissect_kerberos_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo,
				proto_tree *tree);
static guint get_krb_pdu_len(tvbuff_t *tvb, int offset);



gint
dissect_kerberos_main(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int do_col_info)
{
    return (dissect_kerberos_common(tvb, pinfo, tree, do_col_info, FALSE));
}

static void
dissect_kerberos_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "KRB5");

    (void)dissect_kerberos_common(tvb, pinfo, tree, TRUE, FALSE);
}

static gint
kerberos_rm_to_reclen(guint krb_rm)
{
    return (krb_rm & KRB_RM_RECLEN);
}

static guint
get_krb_pdu_len(tvbuff_t *tvb, int offset)
{
    guint krb_rm;
    gint pdulen;

    krb_rm = tvb_get_ntohl(tvb, offset);
    pdulen = kerberos_rm_to_reclen(krb_rm);
    return (pdulen + 4);
}

static void
dissect_kerberos_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    pinfo->fragmented = TRUE;
    if (dissect_kerberos_common(tvb, pinfo, tree, TRUE, TRUE) < 0) {
	/*
	 * The dissector failed to recognize this as a valid
	 * Kerberos message.  Mark it as a continuation packet.
	 */
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_set_str(pinfo->cinfo, COL_INFO, "Continuation");
	}
    }
}

static void
dissect_kerberos_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "KRB5");

    tcp_dissect_pdus(tvb, pinfo, tree, krb_desegment, 4, get_krb_pdu_len,
	dissect_kerberos_tcp_pdu);
}

/*
 * Display the TCP record mark.
 */
static void
show_krb_recordmark(proto_tree *tree, tvbuff_t *tvb, gint start, guint32 krb_rm)
{
    gint rec_len;
    proto_item *rm_item;
    proto_tree *rm_tree;

    if (tree == NULL)
	return;

    rec_len = kerberos_rm_to_reclen(krb_rm);
    rm_item = proto_tree_add_text(tree, tvb, start, 4,
	"Record Mark: %u %s", rec_len, plurality(rec_len, "byte", "bytes"));
    rm_tree = proto_item_add_subtree(rm_item, ett_krb_recordmark);
    proto_tree_add_boolean(rm_tree, hf_krb_rm_reserved, tvb, start, 4, krb_rm);
    proto_tree_add_uint(rm_tree, hf_krb_rm_reclen, tvb, start, 4, krb_rm);
}


static gint
dissect_kerberos_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int dci, gboolean have_rm)
{
    int offset = 0;
    proto_tree *kerberos_tree = NULL;
    proto_item *item = NULL;

    /* TCP record mark and length */
    guint32 krb_rm = 0;
    gint krb_reclen = 0;

    do_col_info=dci;

    if (tree) {
        item = proto_tree_add_item(tree, proto_kerberos, tvb, 0, -1, FALSE);
        kerberos_tree = proto_item_add_subtree(item, ett_krb_kerberos);
    }

    if (have_rm) {
	krb_rm = tvb_get_ntohl(tvb, offset);
	krb_reclen = kerberos_rm_to_reclen(krb_rm);
	/*
	 * What is a reasonable size limit?
	 */
	if (krb_reclen > 10 * 1024 * 1024) {
	    return (-1);
	}
	show_krb_recordmark(kerberos_tree, tvb, offset, krb_rm);
	offset += 4;
    }


    offset=dissect_ber_choice(pinfo, kerberos_tree, tvb, offset, kerberos_applications_choice, -1, -1);
    return offset;
}


void
proto_register_kerberos(void)
{
    static hf_register_info hf[] = {
	{ &hf_krb_rm_reserved, {
	    "Reserved", "kerberos.rm.reserved", FT_BOOLEAN, 32,
	    &bitval, KRB_RM_RESERVED, "Record mark reserved bit", HFILL }},
	{ &hf_krb_rm_reclen, {
	    "Record Length", "kerberos.rm.length", FT_UINT32, BASE_DEC,
	    NULL, KRB_RM_RECLEN, "Record length", HFILL }},
	{ &hf_krb_etype, {
	    "Encryption type", "kerberos.etype", FT_UINT32, BASE_DEC,
	    VALS(krb5_encryption_types), 0, "Encryption Type", HFILL }},
	{ &hf_krb_addr_type, {
	    "Addr-type", "kerberos.addr_type", FT_UINT32, BASE_DEC,
	    VALS(krb5_address_types), 0, "Address Type", HFILL }},
	{ &hf_krb_name_type, {
	    "Name-type", "kerberos.name_type", FT_UINT32, BASE_DEC,
	    VALS(krb5_princ_types), 0, "Type of principal name", HFILL }},
	{ &hf_krb_address_ip, {
	    "IP Address", "kerberos.addr_ip", FT_IPv4, BASE_NONE,
	    NULL, 0, "IP Address", HFILL }},
	{ &hf_krb_address_netbios, {
	    "NetBIOS Address", "kerberos.addr_nb", FT_STRING, BASE_NONE,
	    NULL, 0, "NetBIOS Address and type", HFILL }},
	{ &hf_krb_rtime, {
	    "rtime", "kerberos.rtime", FT_STRING, BASE_NONE,
	    NULL, 0, "Renew Until timestamp", HFILL }},
	{ &hf_krb_ctime, {
	    "ctime", "kerberos.ctime", FT_STRING, BASE_NONE,
	    NULL, 0, "Current Time on the client host", HFILL }},
	{ &hf_krb_cusec, {
	    "cusec", "kerberos.cusec", FT_UINT32, BASE_DEC,
	    NULL, 0, "micro second component of client time", HFILL }},
	{ &hf_krb_stime, {
	    "stime", "kerberos.stime", FT_STRING, BASE_NONE,
	    NULL, 0, "Current Time on the server host", HFILL }},
	{ &hf_krb_susec, {
	    "susec", "kerberos.susec", FT_UINT32, BASE_DEC,
	    NULL, 0, "micro second component of server time", HFILL }},
	{ &hf_krb_error_code, {
	    "error_code", "kerberos.error_code", FT_UINT32, BASE_DEC,
	    VALS(krb5_error_codes), 0, "Kerberos error code", HFILL }},
	{ &hf_krb_from, {
	    "from", "kerberos.from", FT_STRING, BASE_NONE,
	    NULL, 0, "From when the ticket is to be valid (postdating)", HFILL }},
	{ &hf_krb_till, {
	    "till", "kerberos.till", FT_STRING, BASE_NONE,
	    NULL, 0, "When the ticket will expire", HFILL }},
	{ &hf_krb_name_string, {
	    "Name", "kerberos.name_string", FT_STRING, BASE_NONE,
	    NULL, 0, "String component that is part of a PrincipalName", HFILL }},
	{ &hf_krb_e_text, {
	    "e-text", "kerberos.e_text", FT_STRING, BASE_NONE,
	    NULL, 0, "Additional (human readable) error description", HFILL }},
	{ &hf_krb_realm, {
	    "Realm", "kerberos.realm", FT_STRING, BASE_NONE,
	    NULL, 0, "Name of the Kerberos Realm", HFILL }},
	{ &hf_krb_crealm, {
	    "Client Realm", "kerberos.crealm", FT_STRING, BASE_NONE,
	    NULL, 0, "Name of the Clients Kerberos Realm", HFILL }},
	{ &hf_krb_msg_type, {
	    "MSG Type", "kerberos.msg.type", FT_UINT32, BASE_DEC,
	    VALS(krb5_msg_types), 0, "Kerberos Message Type", HFILL }},
	{ &hf_krb_APOptions, {
	    "APOptions", "kerberos.apoptions", FT_NONE, BASE_NONE,
	    NULL, 0, "Kerberos APOptions bitstring", HFILL }},
	{ &hf_krb_APOptions_use_session_key, {
	    "Use Session Key", "kerberos.apoptions.use_session_key", FT_BOOLEAN, 32,
	    TFS(&krb5_apoptions_use_session_key), 0x40000000, "", HFILL }},
	{ &hf_krb_APOptions_mutual_required, {
	    "Mutual required", "kerberos.apoptions.mutual_required", FT_BOOLEAN, 32,
	    TFS(&krb5_apoptions_mutual_required), 0x20000000, "", HFILL }},
	{ &hf_krb_KDCOptions, {
	    "KDCOptions", "kerberos.kdcoptions", FT_NONE, BASE_NONE,
	    NULL, 0, "Kerberos KDCOptions bitstring", HFILL }},
	{ &hf_krb_KDC_REQ_BODY, {
	    "KDC_REQ_BODY", "kerberos.kdc_req_body", FT_NONE, BASE_NONE,
	    NULL, 0, "Kerberos KDC REQuest BODY", HFILL }},
	{ &hf_krb_KDCOptions_forwardable, {
	    "Forwardable", "kerberos.kdcoptions.forwardable", FT_BOOLEAN, 32,
	    TFS(&krb5_kdcoptions_forwardable), 0x40000000, "Flag controlling whether the tickes are forwardable or not", HFILL }},
	{ &hf_krb_KDCOptions_forwarded, {
	    "Forwarded", "kerberos.kdcoptions.forwarded", FT_BOOLEAN, 32,
	    TFS(&krb5_kdcoptions_forwarded), 0x20000000, "Has this ticket been forwarded?", HFILL }},
	{ &hf_krb_KDCOptions_proxyable, {
	    "Proxyable", "kerberos.kdcoptions.proxyable", FT_BOOLEAN, 32,
	    TFS(&krb5_kdcoptions_proxyable), 0x10000000, "Flag controlling whether the tickes are proxyable or not", HFILL }},
	{ &hf_krb_KDCOptions_proxy, {
	    "Proxy", "kerberos.kdcoptions.proxy", FT_BOOLEAN, 32,
	    TFS(&krb5_kdcoptions_proxy), 0x08000000, "Has this ticket been proxied?", HFILL }},
	{ &hf_krb_KDCOptions_allow_postdate, {
	    "Allow Postdate", "kerberos.kdcoptions.allow_postdate", FT_BOOLEAN, 32,
	    TFS(&krb5_kdcoptions_allow_postdate), 0x04000000, "Flag controlling whether we allow postdated tickets or not", HFILL }},
	{ &hf_krb_KDCOptions_postdated, {
	    "Postdated", "kerberos.kdcoptions.postdated", FT_BOOLEAN, 32,
	    TFS(&krb5_kdcoptions_postdated), 0x02000000, "Whether this ticket is postdated or not", HFILL }},
	{ &hf_krb_KDCOptions_renewable, {
	    "Renewable", "kerberos.kdcoptions.renewable", FT_BOOLEAN, 32,
	    TFS(&krb5_kdcoptions_renewable), 0x00800000, "Whether this ticket is renewable or not", HFILL }},
	{ &hf_krb_KDCOptions_renewable_ok, {
	    "Renewable OK", "kerberos.kdcoptions.renewable_ok", FT_BOOLEAN, 32,
	    TFS(&krb5_kdcoptions_renewable_ok), 0x00000010, "Whether we accept renewed tickets or not", HFILL }},
	{ &hf_krb_KDCOptions_enc_tkt_in_skey, {
	    "Enc-Tkt-in-Skey", "kerberos.kdcoptions.enc_tkt_in_skey", FT_BOOLEAN, 32,
	    TFS(&krb5_kdcoptions_enc_tkt_in_skey), 0x00000008, "Whether the ticket is encrypted in the skey or not", HFILL }},
	{ &hf_krb_KDCOptions_renew, {
	    "Renew", "kerberos.kdcoptions.renew", FT_BOOLEAN, 32,
	    TFS(&krb5_kdcoptions_renew), 0x00000002, "Is this a request to renew a ticket?", HFILL }},
	{ &hf_krb_KDCOptions_validate, {
	    "Validate", "kerberos.kdcoptions.validate", FT_BOOLEAN, 32,
	    TFS(&krb5_kdcoptions_validate), 0x00000001, "Is this a request to validate a postdated ticket?", HFILL }},
	{ &hf_krb_pvno, {
	    "Pvno", "kerberos.pvno", FT_UINT32, BASE_DEC,
	    NULL, 0, "Kerberos Protocol Version Number", HFILL }},
	{ &hf_krb_kvno, {
	    "Kvno", "kerberos.kvno", FT_UINT32, BASE_DEC,
	    NULL, 0, "Version Number for the encryption Key", HFILL }},
	{ &hf_krb_encrypted_authenticator_data, {
	    "Authenticator data", "kerberos.authenticator.data", FT_BYTES, BASE_HEX,
	    NULL, 0, "Data content of an encrypted authenticator", HFILL }},
	{ &hf_krb_encrypted_PA_ENC_TIMESTAMP, {
	    "enc PA_ENC_TIMESTAMP", "kerberos.PA_ENC_TIMESTAMP.encrypted", FT_BYTES, BASE_HEX,
	    NULL, 0, "Encrypted PA-ENC-TIMESTAMP blob", HFILL }},
	{ &hf_krb_encrypted_Ticket_data, {
	    "enc-part", "kerberos.ticket.data", FT_BYTES, BASE_HEX,
	    NULL, 0, "The encrypted part of a ticket", HFILL }},
	{ &hf_krb_encrypted_AP_REP_data, {
	    "enc-part", "kerberos.aprep.data", FT_BYTES, BASE_HEX,
	    NULL, 0, "The encrypted part of AP-REP", HFILL }},
	{ &hf_krb_encrypted_KDC_REP_data, {
	    "enc-part", "kerberos.kdcrep.data", FT_BYTES, BASE_HEX,
	    NULL, 0, "The encrypted part of KDC-REP", HFILL }},
	{ &hf_krb_PA_DATA_value, {
	    "Value", "kerberos.padata.value", FT_BYTES, BASE_HEX,
	    NULL, 0, "Content of the PADATA blob", HFILL }},
	{ &hf_krb_PA_DATA_type, {
	    "Type", "kerberos.padata.type", FT_UINT32, BASE_DEC,
	    VALS(krb5_preauthentication_types), 0, "Type of preauthentication data", HFILL }},
	{ &hf_krb_nonce, {
	    "Nonce", "kerberos.nonce", FT_UINT32, BASE_DEC,
	    NULL, 0, "Kerberos Nonce random number", HFILL }},
	{ &hf_krb_tkt_vno, {
	    "Tkt-vno", "kerberos.tkt_vno", FT_UINT32, BASE_DEC,
	    NULL, 0, "Version number for the Ticket format", HFILL }},
	{ &hf_krb_HostAddress, {
	    "HostAddress", "kerberos.hostaddress", FT_NONE, BASE_DEC,
	    NULL, 0, "This is a Kerberos HostAddress sequence", HFILL }},
	{ &hf_krb_HostAddresses, {
	    "HostAddresses", "kerberos.hostaddresses", FT_NONE, BASE_DEC,
	    NULL, 0, "This is a list of Kerberos HostAddress sequences", HFILL }},
	{ &hf_krb_etypes, {
	    "Encryption Types", "kerberos.etypes", FT_NONE, BASE_DEC,
	    NULL, 0, "This is a list of Kerberos encryption types", HFILL }},
	{ &hf_krb_sname, {
	    "Server Name", "kerberos.sname", FT_NONE, BASE_DEC,
	    NULL, 0, "This is the name part server's identity", HFILL }},
	{ &hf_krb_cname, {
	    "Client Name", "kerberos.cname", FT_NONE, BASE_DEC,
	    NULL, 0, "The name part of the client principal identifier", HFILL }},
	{ &hf_krb_authenticator_enc, {
	    "Authenticator", "kerberos.authenticator", FT_NONE, BASE_DEC,
	    NULL, 0, "Encrypted authenticator blob", HFILL }},
	{ &hf_krb_ticket_enc, {
	    "enc-part", "kerberos.ticket.enc_part", FT_NONE, BASE_DEC,
	    NULL, 0, "The structure holding the encrypted part of a ticket", HFILL }},
	{ &hf_krb_AP_REP_enc, {
	    "enc-part", "kerberos.aprep.enc_part", FT_NONE, BASE_DEC,
	    NULL, 0, "The structure holding the encrypted part of AP-REP", HFILL }},
	{ &hf_krb_KDC_REP_enc, {
	    "enc-part", "kerberos.kdcrep.enc_part", FT_NONE, BASE_DEC,
	    NULL, 0, "The structure holding the encrypted part of KDC-REP", HFILL }},
	{ &hf_krb_e_data, {
	    "e-data", "kerberos.e_data", FT_NONE, BASE_DEC,
	    NULL, 0, "The e-data blob", HFILL }},
	{ &hf_krb_padata, {
	    "padata", "kerberos.padata", FT_NONE, BASE_DEC,
	    NULL, 0, "Sequence of preauthentication data", HFILL }},
	{ &hf_krb_ticket, {
	    "Ticket", "kerberos.ticket", FT_NONE, BASE_DEC,
	    NULL, 0, "This is a Kerberos Ticket", HFILL }},
	{ &hf_krb_PA_PAC_REQUEST_flag, {
	    "PAC Request", "kerberos.pac_request.flag", FT_UINT32, BASE_DEC,
	    NULL, 0, "This is a MS PAC Request Flag", HFILL }},
    };

    static gint *ett[] = {
        &ett_krb_kerberos,
	&ett_krb_KDC_REP_enc,
        &ett_krb_sname,
        &ett_krb_cname,
	&ett_krb_AP_REP_enc,
        &ett_krb_padata,
        &ett_krb_etypes,
	&ett_krb_PA_DATA_tree,
        &ett_krb_HostAddress,
        &ett_krb_HostAddresses,
	&ett_krb_authenticator_enc,
        &ett_krb_AP_Options,
        &ett_krb_KDC_Options,
        &ett_krb_request,
        &ett_krb_recordmark,
        &ett_krb_ticket,
	&ett_krb_ticket_enc,
    };
    module_t *krb_module;

    proto_kerberos = proto_register_protocol("Kerberos", "KRB5", "kerberos");
    proto_register_field_array(proto_kerberos, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register preferences */
    krb_module = prefs_register_protocol(proto_kerberos, NULL);
    prefs_register_bool_preference(krb_module, "desegment",
	"Desegment Kerberos over TCP messages",
	"Whether the dissector should desegment "
	"multi-segment Kerberos messages", &krb_desegment);
}

void
proto_reg_handoff_kerberos(void)
{
    dissector_handle_t kerberos_handle_udp;
    dissector_handle_t kerberos_handle_tcp;

    kerberos_handle_udp = create_dissector_handle(dissect_kerberos_udp,
	proto_kerberos);
    kerberos_handle_tcp = create_dissector_handle(dissect_kerberos_tcp,
	proto_kerberos);
    dissector_add("udp.port", UDP_PORT_KERBEROS, kerberos_handle_udp);
    dissector_add("tcp.port", TCP_PORT_KERBEROS, kerberos_handle_tcp);

}

/*

  MISC definitions from RFC1510:

   Realm ::=           GeneralString

   KerberosTime ::=   GeneralizedTime

   AuthorizationData ::=   SEQUENCE OF SEQUENCE {
                           ad-type[0]               INTEGER,
                           ad-data[1]               OCTET STRING
   }
                   APOptions ::=   BIT STRING {
                                   reserved(0),
                                   use-session-key(1),
                                   mutual-required(2)
                   }


                   TicketFlags ::=   BIT STRING {
                                     reserved(0),
                                     forwardable(1),
                                     forwarded(2),
                                     proxiable(3),
                                     proxy(4),
                                     may-postdate(5),
                                     postdated(6),
                                     invalid(7),
                                     renewable(8),
                                     initial(9),
                                     pre-authent(10),
                                     hw-authent(11)
                   }

                  KDCOptions ::=   BIT STRING {
                                   reserved(0),
                                   forwardable(1),
                                   forwarded(2),
                                   proxiable(3),
                                   proxy(4),
                                   allow-postdate(5),
                                   postdated(6),
                                   unused7(7),
                                   renewable(8),
                                   unused9(9),
                                   unused10(10),
                                   unused11(11),
                                   renewable-ok(27),
                                   enc-tkt-in-skey(28),
                                   renew(30),
                                   validate(31)
                  }


            LastReq ::=   SEQUENCE OF SEQUENCE {
                          lr-type[0]               INTEGER,
                          lr-value[1]              KerberosTime
            }

   Ticket ::=                    [APPLICATION 1] SEQUENCE {
                                 tkt-vno[0]                   INTEGER,
                                 realm[1]                     Realm,
                                 sname[2]                     PrincipalName,
                                 enc-part[3]                  EncryptedData
   }

  -- Encrypted part of ticket
  EncTicketPart ::=     [APPLICATION 3] SEQUENCE {
                        flags[0]             TicketFlags,
                        key[1]               EncryptionKey,
                        crealm[2]            Realm,
                        cname[3]             PrincipalName,
                        transited[4]         TransitedEncoding,
                        authtime[5]          KerberosTime,
                        starttime[6]         KerberosTime OPTIONAL,
                        endtime[7]           KerberosTime,
                        renew-till[8]        KerberosTime OPTIONAL,
                        caddr[9]             HostAddresses OPTIONAL,
                        authorization-data[10]   AuthorizationData OPTIONAL
  }

  -- encoded Transited field
  TransitedEncoding ::=         SEQUENCE {
                                tr-type[0]  INTEGER, -- must be registered
                                contents[1]          OCTET STRING
  }

  -- Unencrypted authenticator
  Authenticator ::=    [APPLICATION 2] SEQUENCE    {
                 authenticator-vno[0]          INTEGER,
                 crealm[1]                     Realm,
                 cname[2]                      PrincipalName,
                 cksum[3]                      Checksum OPTIONAL,
                 cusec[4]                      INTEGER,
                 ctime[5]                      KerberosTime,
                 subkey[6]                     EncryptionKey OPTIONAL,
                 seq-number[7]                 INTEGER OPTIONAL,
                 authorization-data[8]         AuthorizationData OPTIONAL
  }

  PA-DATA ::=        SEQUENCE {
           padata-type[1]        INTEGER,
           padata-value[2]       OCTET STRING,
                         -- might be encoded AP-REQ
  }

   padata-type     ::= PA-ENC-TIMESTAMP
   padata-value    ::= EncryptedData -- PA-ENC-TS-ENC

   PA-ENC-TS-ENC   ::= SEQUENCE {
           patimestamp[0]               KerberosTime, -- client's time
           pausec[1]                    INTEGER OPTIONAL
   }

   EncASRepPart ::=    [APPLICATION 25[25]] EncKDCRepPart
   EncTGSRepPart ::=   [APPLICATION 26] EncKDCRepPart

   EncKDCRepPart ::=   SEQUENCE {
               key[0]                       EncryptionKey,
               last-req[1]                  LastReq,
               nonce[2]                     INTEGER,
               key-expiration[3]            KerberosTime OPTIONAL,
               flags[4]                     TicketFlags,
               authtime[5]                  KerberosTime,
               starttime[6]                 KerberosTime OPTIONAL,
               endtime[7]                   KerberosTime,
               renew-till[8]                KerberosTime OPTIONAL,
               srealm[9]                    Realm,
               sname[10]                    PrincipalName,
               caddr[11]                    HostAddresses OPTIONAL
   }

   APOptions ::=   BIT STRING {
                   reserved(0),
                   use-session-key(1),
                   mutual-required(2)
   }

   EncAPRepPart ::=   [APPLICATION 27]     SEQUENCE {
              ctime[0]                  KerberosTime,
              cusec[1]                  INTEGER,
              subkey[2]                 EncryptionKey OPTIONAL,
              seq-number[3]             INTEGER OPTIONAL
   }

   KRB-SAFE ::=        [APPLICATION 20] SEQUENCE {
               pvno[0]               INTEGER,
               msg-type[1]           INTEGER,
               safe-body[2]          KRB-SAFE-BODY,
               cksum[3]              Checksum
   }

   KRB-SAFE-BODY ::=   SEQUENCE {
               user-data[0]          OCTET STRING,
               timestamp[1]          KerberosTime OPTIONAL,
               usec[2]               INTEGER OPTIONAL,
               seq-number[3]         INTEGER OPTIONAL,
               s-address[4]          HostAddress,
               r-address[5]          HostAddress OPTIONAL
   }

   KRB-PRIV ::=         [APPLICATION 21] SEQUENCE {
                pvno[0]                   INTEGER,
                msg-type[1]               INTEGER,
                enc-part[3]               EncryptedData
   }

   EncKrbPrivPart ::=   [APPLICATION 28] SEQUENCE {
                user-data[0]              OCTET STRING,
                timestamp[1]              KerberosTime OPTIONAL,
                usec[2]                   INTEGER OPTIONAL,
                seq-number[3]             INTEGER OPTIONAL,
                s-address[4]              HostAddress, -- sender's addr
                r-address[5]              HostAddress OPTIONAL
                                                      -- recip's addr
   }

   KRB-CRED         ::= [APPLICATION 22]   SEQUENCE {
                    pvno[0]                INTEGER,
                    msg-type[1]            INTEGER, -- KRB_CRED
                    tickets[2]             SEQUENCE OF Ticket,
                    enc-part[3]            EncryptedData
   }

   EncKrbCredPart   ::= [APPLICATION 29]   SEQUENCE {
                    ticket-info[0]         SEQUENCE OF KrbCredInfo,
                    nonce[1]               INTEGER OPTIONAL,
                    timestamp[2]           KerberosTime OPTIONAL,
                    usec[3]                INTEGER OPTIONAL,
                    s-address[4]           HostAddress OPTIONAL,
                    r-address[5]           HostAddress OPTIONAL
   }

   KrbCredInfo      ::=                    SEQUENCE {
                    key[0]                 EncryptionKey,
                    prealm[1]              Realm OPTIONAL,
                    pname[2]               PrincipalName OPTIONAL,
                    flags[3]               TicketFlags OPTIONAL,
                    authtime[4]            KerberosTime OPTIONAL,
                    starttime[5]           KerberosTime OPTIONAL,
                    endtime[6]             KerberosTime OPTIONAL
                    renew-till[7]          KerberosTime OPTIONAL,
                    srealm[8]              Realm OPTIONAL,
                    sname[9]               PrincipalName OPTIONAL,
                    caddr[10]              HostAddresses OPTIONAL
   }

      METHOD-DATA ::=    SEQUENCE of PA-DATA

   If the error-code is KRB_AP_ERR_METHOD, then the e-data field will
   contain an encoding of the following sequence:

      METHOD-DATA ::=    SEQUENCE {
                         method-type[0]   INTEGER,
                         method-data[1]   OCTET STRING OPTIONAL
      }

      EncryptionKey ::=   SEQUENCE {
                         keytype[0]    INTEGER,
                         keyvalue[1]   OCTET STRING
      }

      Checksum ::=   SEQUENCE {
                         cksumtype[0]   INTEGER,
                         checksum[1]    OCTET STRING
      }

*/
