/* packet-kerberos.c
 * Routines for Kerberos
 * Wes Hardaker (c) 2000
 * wjhardaker@ucdavis.edu
 *
 * $Id: packet-kerberos.c,v 1.13 2001/01/03 16:41:06 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Didier Jorand
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <glib.h>

#include "packet.h"

#include "strutil.h"

#include "asn1.h"

#define UDP_PORT_KERBEROS		88
#define TCP_PORT_KERBEROS		88

static gint ett_kerberos   = -1;
static gint ett_preauth    = -1;
static gint ett_addresses  = -1;
static gint ett_request    = -1;
static gint ett_princ      = -1;
static gint ett_ticket     = -1;
static gint ett_encrypted  = -1;
static gint ett_etype      = -1;
static gint proto_kerberos = -1;

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

/* Type tags within KDC-REQ */
#define KRB5_KDC_REQ_PVNO     1
#define KRB5_KDC_REQ_MSG_TYPE 2
#define KRB5_KDC_REQ_PADATA   3
#define KRB5_KDC_REQ_REQBODY  4

/* Type tags within KDC-REP */
#define KRB5_KDC_REP_PVNO     0
#define KRB5_KDC_REP_MSG_TYPE 1
#define KRB5_KDC_REP_PADATA   2
#define KRB5_KDC_REP_CREALM   3
#define KRB5_KDC_REP_CNAME    4
#define KRB5_KDC_REP_TICKET   5
#define KRB5_KDC_REP_ENC_PART 6

/* Type tags within KDC-REQ-BODY */
#define KRB5_BODY_KDC_OPTIONS            0
#define KRB5_BODY_CNAME                  1
#define KRB5_BODY_REALM                  2
#define KRB5_BODY_SNAME                  3
#define KRB5_BODY_FROM                   4
#define KRB5_BODY_TILL                   5
#define KRB5_BODY_RTIME                  6
#define KRB5_BODY_NONCE                  7
#define KRB5_BODY_ENCTYPE                8
#define KRB5_BODY_ADDRESSES              9
#define KRB5_BODY_ENC_AUTHORIZATION_DATA 10
#define KRB5_BODY_ADDITIONAL_TICKETS     11

/* Type tags within KRB-ERROR */
#define KRB5_ERROR_PVNO       0
#define KRB5_ERROR_MSG_TYPE   1
#define KRB5_ERROR_CTIME      2
#define KRB5_ERROR_CUSEC      3
#define KRB5_ERROR_STIME      4
#define KRB5_ERROR_SUSEC      5
#define KRB5_ERROR_ERROR_CODE 6
#define KRB5_ERROR_CREALM     7
#define KRB5_ERROR_CNAME      8
#define KRB5_ERROR_REALM      9
#define KRB5_ERROR_SNAME      10
#define KRB5_ERROR_ETEXT      11
#define KRB5_ERROR_EDATA      12

/* address type constants */
#define KRB5_ADDR_IPv4       0x02
#define KRB5_ADDR_CHAOS      0x05
#define KRB5_ADDR_XEROX      0x06
#define KRB5_ADDR_ISO        0x07
#define KRB5_ADDR_DECNET     0x0c
#define KRB5_ADDR_APPLETALK  0x10

/* encryption type constants */
#define KRB5_ENCTYPE_NULL                0
#define KRB5_ENCTYPE_DES_CBC_CRC         1
#define KRB5_ENCTYPE_DES_CBC_MD4         2
#define KRB5_ENCTYPE_DES_CBC_MD5         3
#define KRB5_ENCTYPE_DES_CBC_RAW         4
#define KRB5_ENCTYPE_DES3_CBC_SHA        5
#define KRB5_ENCTYPE_DES3_CBC_RAW        6
#define KRB5_ENCTYPE_DES_HMAC_SHA1       8
#define KRB5_ENCTYPE_DES3_CBC_SHA1          0x10 
#define KRB5_ENCTYPE_UNKNOWN                0x1ff
#define KRB5_ENCTYPE_LOCAL_DES3_HMAC_SHA1   0x7007

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
#define KRB5_PA_ENCTYPE_INFO             11
#define KRB5_PA_SAM_CHALLENGE          12
#define KRB5_PA_SAM_RESPONSE           13
#define KRB5_PA_DASS                   16

/* Type tags within Ticket */
#define KRB5_TKT_TKT_VNO  0
#define KRB5_TKT_REALM    1
#define KRB5_TKT_SNAME    2
#define KRB5_TKT_ENC_PART 3

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

static int dissect_PrincipalName(char *title, ASN1_SCK *asn1p,
                                 frame_data *fd, proto_tree *tree,
                                 int start_offset);
static int dissect_Ticket(char *title, ASN1_SCK *asn1p, frame_data *fd,
                          proto_tree *tree, int start_offset);
static int dissect_EncryptedData(char *title, ASN1_SCK *asn1p, frame_data *fd,
                                 proto_tree *tree, int start_offset);
static int dissect_Addresses(char *title, ASN1_SCK *asn1p, frame_data *fd,
                             proto_tree *tree, int start_offset);

static const char *
to_error_str(int ret) {
    switch (ret) {

        case ASN1_ERR_EMPTY:
            return("Ran out of data");

        case ASN1_ERR_EOC_MISMATCH:
            return("EOC mismatch");

        case ASN1_ERR_WRONG_TYPE:
            return("Wrong type for that item");

        case ASN1_ERR_LENGTH_NOT_DEFINITE:
            return("Length was indefinite");

        case ASN1_ERR_LENGTH_MISMATCH:
            return("Length mismatch");

        case ASN1_ERR_WRONG_LENGTH_FOR_TYPE:
            return("Wrong length for that item's type");

    }
    return("Unknown error");
}

static void
krb_proto_tree_add_time(proto_tree *tree, int offset, int str_len,
                        char *name, guchar *str) {
    if (tree)
        proto_tree_add_text(tree, NullTVB, offset, str_len,
                            "%s: %.4s-%.2s-%.2s %.2s:%.2s:%.2s (%.1s)",
                            name, str, str+4, str+6,
                            str+8, str+10, str+12,
                            str+14);
}


/*
 * You must be kidding.  I'm going to actually use a macro to do something?
 *   bad me.  Bad me.
 */

#define KRB_HEAD_DECODE_OR_DIE(token) \
   start = asn1p->pointer; \
   ret = asn1_header_decode (asn1p, &cls, &con, &tag, &def, &item_len); \
   if (ret != ASN1_ERR_NOERROR && ret != ASN1_ERR_EMPTY) {\
       if (check_col(fd, COL_INFO)) \
           col_add_fstr(fd, COL_INFO, "ERROR: Problem at %s: %s", \
                    token, to_error_str(ret)); \
       return -1; \
   } \
   if (!def) {\
       if (check_col(fd, COL_INFO)) \
           col_add_fstr(fd, COL_INFO, "not definite: %s", token); \
       fprintf(stderr,"not definite: %s\n", token); \
       return -1; \
   } \
   offset += (asn1p->pointer - start);

#define CHECK_APPLICATION_TYPE(expected_tag) \
    (cls == ASN1_APL && con == ASN1_CON && tag == expected_tag)

#define DIE_IF_NOT_APPLICATION_TYPE(token, expected_tag) \
    if (!CHECK_APPLICATION_TYPE(expected_tag)) \
        DIE_WITH_BAD_TYPE(token, expected_tag);

#define CHECK_CONTEXT_TYPE(expected_tag) \
    (cls == ASN1_CTX && con == ASN1_CON && tag == expected_tag)

#define DIE_IF_NOT_CONTEXT_TYPE(token, expected_tag) \
    if (!CHECK_CONTEXT_TYPE(expected_tag)) \
        DIE_WITH_BAD_TYPE(token, expected_tag);

#define DIE_WITH_BAD_TYPE(token, expected_tag) \
    { \
      if (check_col(fd, COL_INFO)) \
         col_add_fstr(fd, COL_INFO, "ERROR: Problem at %s: %s (tag=%d exp=%d)", \
                      token, to_error_str(ASN1_ERR_WRONG_TYPE), tag, expected_tag); \
      return -1; \
    }

#define KRB_DECODE_APPLICATION_TAGGED_HEAD_OR_DIE(token, expected_tag) \
    KRB_HEAD_DECODE_OR_DIE(token); \
    DIE_IF_NOT_APPLICATION_TYPE(token, expected_tag);

#define KRB_DECODE_CONTEXT_HEAD_OR_DIE(token, expected_tag) \
    KRB_HEAD_DECODE_OR_DIE(token); \
    DIE_IF_NOT_CONTEXT_TYPE(token, expected_tag);

#define KRB_SEQ_HEAD_DECODE_OR_DIE(token) \
   ret = asn1_sequence_decode (asn1p, &item_len, &header_len); \
   if (ret != ASN1_ERR_NOERROR && ret != ASN1_ERR_EMPTY) {\
       if (check_col(fd, COL_INFO)) \
           col_add_fstr(fd, COL_INFO, "ERROR: Problem at %s: %s", \
                    token, to_error_str(ret)); \
       return -1; \
   } \
   offset += header_len;

#define KRB_DECODE_OR_DIE(token, fn, val) \
    ret = fn (asn1p, &val, &length); \
    if (ret != ASN1_ERR_NOERROR) { \
       if (check_col(fd, COL_INFO)) \
         col_add_fstr(fd, COL_INFO, "ERROR: Problem at %s: %s", \
                     token, to_error_str(ret)); \
        return -1; \
    } \

#define KRB_DECODE_UINT32_OR_DIE(token, val) \
    KRB_DECODE_OR_DIE(token, asn1_uint32_decode, val);

#define KRB_DECODE_STRING_OR_DIE(token, expected_tag, val, val_len, item_len) \
    ret = asn1_string_decode (asn1p, &val, &val_len, &item_len, expected_tag); \
    if (ret != ASN1_ERR_NOERROR) { \
       if (check_col(fd, COL_INFO)) \
         col_add_fstr(fd, COL_INFO, "ERROR: Problem at %s: %s", \
                     token, to_error_str(ret)); \
        return -1; \
    }

#define KRB_DECODE_OCTET_STRING_OR_DIE(token, val, val_len, item_len) \
    KRB_DECODE_STRING_OR_DIE(token, ASN1_OTS, val, val_len, item_len)

#define KRB_DECODE_GENERAL_STRING_OR_DIE(token, val, val_len, item_len) \
    KRB_DECODE_STRING_OR_DIE(token, ASN1_GENSTR, val, val_len, item_len)

#define KRB_DECODE_GENERAL_TIME_OR_DIE(token, val, val_len, item_len) \
    KRB_DECODE_STRING_OR_DIE(token, ASN1_GENTIM, val, val_len, item_len)

/* dissect_type_value_pair decodes (roughly) this:

    SEQUENCE  {
                        INTEGER,
                        OCTET STRING
    }

    which is all over the place in krb5 */

static void
dissect_type_value_pair(ASN1_SCK *asn1p, int *inoff,
                        guint32 *type, int *type_len, int *type_off,
                        guchar **val, int *val_len, int *val_off) {
    int offset = *inoff;
    guint cls, con, tag;
    gboolean def;
    const guchar *start;
    guint tmp_len;
    int ret;

    /* SEQUENCE */
    start = asn1p->pointer;
    asn1_header_decode (asn1p, &cls, &con, &tag, &def, &tmp_len);
    offset += (asn1p->pointer - start);

    /* INT */
    /* wrapper */
    start = asn1p->pointer;
    asn1_header_decode (asn1p, &cls, &con, &tag, &def, &tmp_len);
    offset += (asn1p->pointer - start);

    if (type_off)
        *type_off = offset;

    /* value */
    ret =  asn1_uint32_decode(asn1p, type, type_len);
    if (ret != ASN1_ERR_NOERROR) {
        fprintf(stderr,"die: type_value_pair: type, %s\n", to_error_str(ret));
        return;
    }
    offset += tmp_len;

    /* OCTET STRING (or generic data) */
    /* wrapper */
    start = asn1p->pointer;
    asn1_header_decode (asn1p, &cls, &con, &tag, &def, val_len);
    asn1_header_decode (asn1p, &cls, &con, &tag, &def, val_len);
    offset += asn1p->pointer - start;
    
    if (val_off)
        *val_off = offset;

    /* value */
    asn1_string_value_decode (asn1p, *val_len, val);

    *inoff = offset + *val_len;
}

static gboolean
dissect_kerberos_main(const u_char *pd, int offset, frame_data *fd,
                      proto_tree *tree)
{
    proto_tree *kerberos_tree = NULL;
    proto_tree *etype_tree = NULL;
    proto_tree *preauth_tree = NULL;
    proto_tree *request_tree = NULL;
    ASN1_SCK asn1, *asn1p = &asn1;
    proto_item *item = NULL;

    guint length;
    guint cls, con, tag;
    gboolean def;
    guint item_len, total_len;
    const guchar *start;

    int ret;

    guint protocol_message_type;
    
    guint32 version;
    guint32 msg_type;
    guint32 preauth_type;
    guint32 tmp_int;

    /* simple holders */
    int str_len;
    guchar *str;
    int tmp_pos1, tmp_pos2;

    if (tree) {
        item = proto_tree_add_item(tree, proto_kerberos, NullTVB, offset,
                                   END_OF_FRAME, FALSE);
        kerberos_tree = proto_item_add_subtree(item, ett_kerberos);
    }

    asn1_open(&asn1, &pd[offset], END_OF_FRAME);

    /* top header */
    KRB_HEAD_DECODE_OR_DIE("top");
    protocol_message_type = tag;
    
    /* second header */
    KRB_HEAD_DECODE_OR_DIE("top2");

    /* version number */
    KRB_HEAD_DECODE_OR_DIE("version-wrap");
    KRB_DECODE_UINT32_OR_DIE("version", version);

    if (kerberos_tree) {
        proto_tree_add_text(kerberos_tree, NullTVB, offset, length,
                            "Version: %d",
                            version);
    }
    offset += length;

    /* message type */
    KRB_HEAD_DECODE_OR_DIE("message-type-wrap");
    KRB_DECODE_UINT32_OR_DIE("message-type", msg_type);

    if (kerberos_tree) {
        proto_tree_add_text(kerberos_tree, NullTVB, offset, length,
                            "MSG Type: %s",
                            val_to_str(msg_type, krb5_msg_types,
                                       "Unknown msg type %#x"));
    }
    offset += length;

    if (check_col(fd, COL_INFO))
        col_add_str(fd, COL_INFO, val_to_str(msg_type, krb5_msg_types,
                                             "Unknown msg type %#x"));

        /* is preauthentication present? */
    KRB_HEAD_DECODE_OR_DIE("padata-or-body");
    if (((protocol_message_type == KRB5_MSG_AS_REQ ||
          protocol_message_type == KRB5_MSG_TGS_REQ) &&
         tag == KRB5_KDC_REQ_PADATA) ||
        ((protocol_message_type == KRB5_MSG_AS_REP ||
          protocol_message_type == KRB5_MSG_TGS_REP) &&
         tag == KRB5_KDC_REP_PADATA)) {
        /* pre-authentication supplied */

        if (tree) {
            item = proto_tree_add_text(kerberos_tree, NullTVB, offset,
                                       item_len, "Pre-Authentication");
            preauth_tree = proto_item_add_subtree(item, ett_preauth);
        }

        KRB_HEAD_DECODE_OR_DIE("sequence of pa-data");
        start = asn1p->pointer + item_len;

        while(start > asn1p->pointer) {
            dissect_type_value_pair(asn1p, &offset,
                                    &preauth_type, &item_len, &tmp_pos1,
                                    &str, &str_len, &tmp_pos2);

            if (preauth_tree) {
                proto_tree_add_text(preauth_tree, NullTVB, tmp_pos1,
                                    item_len, "Type: %s",
                                    val_to_str(preauth_type,
                                               krb5_preauthentication_types,
                                               "Unknown preauth type %#x"));
                proto_tree_add_text(preauth_tree, NullTVB, tmp_pos2,
                                    str_len, "Value: %s",
                                    bytes_to_str(str, str_len));
            }
        }
        KRB_HEAD_DECODE_OR_DIE("message-body");
    }

    switch (protocol_message_type) {

    case KRB5_MSG_AS_REQ:
    case KRB5_MSG_TGS_REQ:
/*
  AS-REQ ::=         [APPLICATION 10] KDC-REQ
  TGS-REQ ::=        [APPLICATION 12] KDC-REQ
    
  KDC-REQ ::=        SEQUENCE {
           pvno[1]               INTEGER,
           msg-type[2]           INTEGER,
           padata[3]             SEQUENCE OF PA-DATA OPTIONAL,
           req-body[4]           KDC-REQ-BODY
  }

  KDC-REQ-BODY ::=   SEQUENCE {
            kdc-options[0]       KDCOptions,
            cname[1]             PrincipalName OPTIONAL,
                         -- Used only in AS-REQ
            realm[2]             Realm, -- Server's realm
                         -- Also client's in AS-REQ
            sname[3]             PrincipalName OPTIONAL,
            from[4]              KerberosTime OPTIONAL,
            till[5]              KerberosTime,
            rtime[6]             KerberosTime OPTIONAL,
            nonce[7]             INTEGER,
            etype[8]             SEQUENCE OF INTEGER, -- EncryptionType,
                         -- in preference order
            addresses[9]         HostAddresses OPTIONAL,
            enc-authorization-data[10]   EncryptedData OPTIONAL,
                         -- Encrypted AuthorizationData encoding
            additional-tickets[11]       SEQUENCE OF Ticket OPTIONAL
  }

*/
        /* request body */
        KRB_HEAD_DECODE_OR_DIE("body-sequence");
        if (tree) {
            item = proto_tree_add_text(kerberos_tree, NullTVB, offset,
                                       item_len, "Request");
            request_tree = proto_item_add_subtree(item, ett_request);
        }

        /* kdc options */
        KRB_HEAD_DECODE_OR_DIE("kdc options");

        KRB_HEAD_DECODE_OR_DIE("kdc options:bits");

        if (request_tree) {
                proto_tree_add_text(request_tree, NullTVB, offset, item_len,
                                    "Options: %s",
                                    bytes_to_str(asn1.pointer, item_len));
        }
        offset += item_len;
        asn1.pointer += item_len;

        KRB_HEAD_DECODE_OR_DIE("Client Name or Realm");

        if (CHECK_CONTEXT_TYPE(KRB5_BODY_CNAME)) {
            item_len = dissect_PrincipalName("Client Name", asn1p, fd,
                                             request_tree, offset);
            if (item_len == -1)
                return -1;
            offset += item_len;
            KRB_HEAD_DECODE_OR_DIE("Realm");
        }

        DIE_IF_NOT_CONTEXT_TYPE("Realm", KRB5_BODY_REALM);
        KRB_DECODE_GENERAL_STRING_OR_DIE("Realm", str, str_len, item_len);
        if (request_tree) {
            proto_tree_add_text(request_tree, NullTVB, offset, item_len,
                                "Realm: %.*s", str_len, str);
        }
        offset += item_len;

        KRB_HEAD_DECODE_OR_DIE("Server Name");
        if (CHECK_CONTEXT_TYPE(KRB5_BODY_SNAME)) {
            item_len = dissect_PrincipalName("Server Name", asn1p, fd,
                                             request_tree, offset);
            if (item_len == -1)
                return -1;
            offset += item_len;
            KRB_HEAD_DECODE_OR_DIE("From or Till");
        }

        if (CHECK_CONTEXT_TYPE(KRB5_BODY_FROM)) {
            KRB_DECODE_GENERAL_TIME_OR_DIE("From", str, str_len, item_len);
            krb_proto_tree_add_time(request_tree, offset, item_len,
                                    "Start Time", str);
            offset += item_len;
            KRB_HEAD_DECODE_OR_DIE("Till");
        }

        DIE_IF_NOT_CONTEXT_TYPE("Till", KRB5_BODY_TILL);
        KRB_DECODE_GENERAL_TIME_OR_DIE("Till", str, str_len, item_len);
        krb_proto_tree_add_time(request_tree, offset, item_len,
                                "End Time", str);
        offset += item_len;

        KRB_HEAD_DECODE_OR_DIE("Renewable Until or Nonce");
        if (CHECK_CONTEXT_TYPE(KRB5_BODY_RTIME)) {
            KRB_DECODE_GENERAL_TIME_OR_DIE("Renewable Until", str, str_len, item_len);
            krb_proto_tree_add_time(request_tree, offset, item_len,
                                    "Renewable Until", str);
            offset += item_len;
            KRB_HEAD_DECODE_OR_DIE("Nonce");
        }
            
        DIE_IF_NOT_CONTEXT_TYPE("Nonce", KRB5_BODY_NONCE);
        KRB_DECODE_UINT32_OR_DIE("Nonce", tmp_int);
        if (request_tree) {
            proto_tree_add_text(request_tree, NullTVB, offset, length,
                                "Random Number: %u",
                                tmp_int);
        }
        offset += length;
        
        KRB_DECODE_CONTEXT_HEAD_OR_DIE("encryption type spot",
                                              KRB5_BODY_ENCTYPE);
        KRB_HEAD_DECODE_OR_DIE("encryption type list");
        if (kerberos_tree) {
            item = proto_tree_add_text(request_tree, NullTVB, offset,
                                       item_len, "Encryption Types");
            etype_tree = proto_item_add_subtree(item, ett_etype);
        }
        total_len = item_len;
        while(total_len > 0) {
            KRB_DECODE_UINT32_OR_DIE("encryption type", tmp_int);
            if (etype_tree) {
                proto_tree_add_text(etype_tree, NullTVB, offset, length,
                                    "Type: %s",
                                    val_to_str(tmp_int,
                                               krb5_encryption_types,
                                               "Unknown encryption type %#x"));
            }
            offset += length;
            total_len -= length;
        }

        KRB_HEAD_DECODE_OR_DIE("addresses");
        if (CHECK_CONTEXT_TYPE(KRB5_BODY_ADDRESSES)) {
            /* pre-authentication supplied */

            offset = dissect_Addresses("Addresses", asn1p, fd, kerberos_tree,
                                       offset);
            if (offset == -1)
                return -1;
            KRB_HEAD_DECODE_OR_DIE("auth-data");
        }
        break;

    case KRB5_MSG_AS_REP:
    case KRB5_MSG_TGS_REP:
/*
   AS-REP ::=    [APPLICATION 11] KDC-REP
   TGS-REP ::=   [APPLICATION 13] KDC-REP

   KDC-REP ::=   SEQUENCE {
                 pvno[0]                    INTEGER,
                 msg-type[1]                INTEGER,
                 padata[2]                  SEQUENCE OF PA-DATA OPTIONAL,
                 crealm[3]                  Realm,
                 cname[4]                   PrincipalName,
                 ticket[5]                  Ticket,
                 enc-part[6]                EncryptedData
   }
*/

		DIE_IF_NOT_CONTEXT_TYPE("crealm", KRB5_KDC_REP_CREALM);
        KRB_DECODE_GENERAL_STRING_OR_DIE("realm name", str, str_len, item_len);
        if (kerberos_tree) {
            proto_tree_add_text(kerberos_tree, NullTVB, offset, item_len,
                                "Realm: %.*s", str_len, str);
        }
        offset += item_len;

        KRB_DECODE_CONTEXT_HEAD_OR_DIE("cname", KRB5_KDC_REP_CNAME);
        item_len = dissect_PrincipalName("Client Name", asn1p, fd,
                                         kerberos_tree, offset);
        if (item_len == -1)
            return -1;
        offset += item_len;
        
        KRB_DECODE_CONTEXT_HEAD_OR_DIE("ticket", KRB5_KDC_REP_TICKET);
        offset = dissect_Ticket("ticket", asn1p, fd, kerberos_tree, offset);
        if (offset == -1)
            return -1;

        KRB_DECODE_CONTEXT_HEAD_OR_DIE("enc-msg-part",
                                              KRB5_KDC_REP_ENC_PART);
        offset = dissect_EncryptedData("Encrypted Payload", asn1p, fd,
                                       kerberos_tree, offset);
        if (offset == -1)
            return -1;
        break;

    case KRB5_MSG_ERROR:
/*
  KRB-ERROR ::=   [APPLICATION 30] SEQUENCE {
                   pvno[0]               INTEGER,
                   msg-type[1]           INTEGER,
                   ctime[2]              KerberosTime OPTIONAL,
                   cusec[3]              INTEGER OPTIONAL,
                   stime[4]              KerberosTime,
                   susec[5]              INTEGER,
                   error-code[6]         INTEGER,
                   crealm[7]             Realm OPTIONAL,
                   cname[8]              PrincipalName OPTIONAL,
                   realm[9]              Realm, -- Correct realm
                   sname[10]             PrincipalName, -- Correct name
                   e-text[11]            GeneralString OPTIONAL,
                   e-data[12]            OCTET STRING OPTIONAL
   }
  }

*/

		/* ctime */
        if (CHECK_CONTEXT_TYPE(KRB5_ERROR_CTIME)) {
            KRB_DECODE_GENERAL_TIME_OR_DIE("ctime", str, str_len, item_len);
            krb_proto_tree_add_time(kerberos_tree, offset, item_len,
                                    "ctime", str);
            offset += item_len;
			KRB_HEAD_DECODE_OR_DIE("cusec");
        }

		/* cusec */
        if (CHECK_CONTEXT_TYPE(KRB5_ERROR_CUSEC)) {
			KRB_DECODE_UINT32_OR_DIE("cusec", tmp_int);
	        if (kerberos_tree) {
	            proto_tree_add_text(kerberos_tree, NullTVB, offset, length,
	                                "cusec: %u",
	                                tmp_int);
	        }

            offset += item_len;
			KRB_HEAD_DECODE_OR_DIE("sutime");
        }

		DIE_IF_NOT_CONTEXT_TYPE("sutime", KRB5_ERROR_STIME);
	    KRB_DECODE_GENERAL_TIME_OR_DIE("stime", str, str_len, item_len);
	    krb_proto_tree_add_time(kerberos_tree, offset, item_len,
	                            "stime", str);
    	offset += item_len;

		KRB_HEAD_DECODE_OR_DIE("susec");
		DIE_IF_NOT_CONTEXT_TYPE("susec", KRB5_ERROR_SUSEC);		
		KRB_DECODE_UINT32_OR_DIE("susec", tmp_int);
		if (kerberos_tree) {
		    proto_tree_add_text(kerberos_tree, NullTVB, offset, length,
		                        "susec: %u",
		                        tmp_int);
		}
	    offset += item_len;

		KRB_HEAD_DECODE_OR_DIE("errcode");
		DIE_IF_NOT_CONTEXT_TYPE("errcode", KRB5_ERROR_ERROR_CODE);		
		KRB_DECODE_UINT32_OR_DIE("errcode", tmp_int);
	    if (kerberos_tree) {
	        proto_tree_add_text(kerberos_tree, NullTVB, offset, length,
	                            "Error Code: %s",
								val_to_str(tmp_int,
                                               krb5_error_codes,
                                               "Unknown error code %#x"));
	    }
        offset += item_len;
		KRB_HEAD_DECODE_OR_DIE("crealm");

        if (CHECK_CONTEXT_TYPE(KRB5_ERROR_CREALM)) {
        	KRB_DECODE_GENERAL_STRING_OR_DIE("crealm", str, str_len, item_len);
        	if (kerberos_tree) {
            	proto_tree_add_text(kerberos_tree, NullTVB, offset, item_len,
                                	"crealm: %.*s", str_len, str);
        	}
        	offset += item_len;
			KRB_HEAD_DECODE_OR_DIE("cname");
		}

		if (CHECK_CONTEXT_TYPE(KRB5_ERROR_CNAME)) {
	        item_len = dissect_PrincipalName("cname", asn1p, fd,
                                         kerberos_tree, offset);
	        if (item_len == -1)
	            return -1;
	        offset += item_len;
			KRB_HEAD_DECODE_OR_DIE("realm");
		}

		DIE_IF_NOT_CONTEXT_TYPE("realm", KRB5_ERROR_REALM);
        KRB_DECODE_GENERAL_STRING_OR_DIE("realm", str, str_len, item_len);
        if (kerberos_tree) {
            proto_tree_add_text(kerberos_tree, NullTVB, offset, item_len,
                                "realm: %.*s", str_len, str);
        }
        offset += item_len;
		KRB_HEAD_DECODE_OR_DIE("sname");

		DIE_IF_NOT_CONTEXT_TYPE("sname", KRB5_ERROR_SNAME);
	    item_len = dissect_PrincipalName("sname", asn1p, fd,
                                     kerberos_tree, offset);
	    if (item_len == -1)
	        return -1;
	    offset += item_len;
		KRB_HEAD_DECODE_OR_DIE("e-text");

		if ( CHECK_CONTEXT_TYPE(KRB5_ERROR_ETEXT) ) {
        	KRB_DECODE_GENERAL_STRING_OR_DIE("etext", str, str_len, item_len);
        	if (kerberos_tree) {
            	proto_tree_add_text(kerberos_tree, NullTVB, offset, item_len,
                                	"etext: %.*s", str_len, str);
        	}
        	offset += item_len;
			KRB_HEAD_DECODE_OR_DIE("e-data");
		}

		if ( CHECK_CONTEXT_TYPE(KRB5_ERROR_EDATA) ) {
		   guchar *data;
		   guint data_len;

 		   KRB_DECODE_OCTET_STRING_OR_DIE("e-data", data, data_len, item_len);

	       if (kerberos_tree) {
               proto_tree_add_text(kerberos_tree, NullTVB, offset, data_len,
                            "Error Data: %s", bytes_to_str(data, item_len));
           }
           offset += data_len;
		}

        break;
    }
    return offset;
}

static void
dissect_kerberos(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
    OLD_CHECK_DISPLAY_AS_DATA(proto_kerberos, pd, offset, fd, tree);

    if (check_col(fd, COL_PROTOCOL))
        col_set_str(fd, COL_PROTOCOL, "KRB5");

    dissect_kerberos_main(pd, offset, fd, tree);
}

static int
dissect_PrincipalName(char *title, ASN1_SCK *asn1p, frame_data *fd,
                       proto_tree *tree, int start_offset)
{
/*
   PrincipalName ::=   SEQUENCE {
                       name-type[0]     INTEGER,
                       name-string[1]   SEQUENCE OF GeneralString
   }
*/
    proto_tree *princ_tree = NULL;
    int offset = start_offset;

    guint32 princ_type;

    const guchar *start;
    guint cls, con, tag;
    guint header_len, item_len, total_len, type_len;
    int ret;

    proto_item *item = NULL;
    guint length;
    gboolean def;

    int type_offset;

    guchar *name;
    guint name_len;

    /* principal name */
    KRB_SEQ_HEAD_DECODE_OR_DIE("principal section");

    if (tree) {
      item = proto_tree_add_text(tree, NullTVB, start_offset,
                                 (offset - start_offset) + item_len, "%s",
                                 title);
      princ_tree = proto_item_add_subtree(item, ett_princ);
    } else {
      item = NULL;
      princ_tree = NULL;
    }

    KRB_DECODE_CONTEXT_HEAD_OR_DIE("principal type", 0);
    KRB_DECODE_UINT32_OR_DIE("princ-type", princ_type);
    type_offset = offset;
    type_len = item_len;
    offset += length;

    if (princ_tree) {
      proto_tree_add_text(princ_tree, NullTVB, type_offset, type_len,
						"Type: %s",
						val_to_str(princ_type, krb5_princ_types,
                                           "Unknown name type %#x"));
    }

    KRB_DECODE_CONTEXT_HEAD_OR_DIE("principal name-string", 1);
    KRB_SEQ_HEAD_DECODE_OR_DIE("principal name-string sequence-of");
    total_len = item_len;
    if (total_len == 0) {
      /* There are no name strings in this PrincipalName, so we can't
         put any in the top-level item. */
      return offset - start_offset;
    }

    /* Put the first name string in the top-level item. */
    KRB_DECODE_GENERAL_STRING_OR_DIE("principal name", name, name_len, item_len);
    if (princ_tree) {
        proto_item_set_text(item, "%s: %.*s", title, (int) name_len, name);
        proto_tree_add_text(princ_tree, NullTVB, offset, item_len,
                            "Name: %.*s", (int) name_len, name);
    }
    total_len -= item_len;
    offset += item_len;

    /* Now process the rest of the strings.
       XXX - put them in the item as well? */
    while (total_len > 0) {
        KRB_DECODE_GENERAL_STRING_OR_DIE("principal name", name, name_len, item_len);
        if (princ_tree) {
            proto_tree_add_text(princ_tree, NullTVB, offset, item_len,
                                "Name: %.*s", (int) name_len, name);
        }
        total_len -= item_len;
        offset += item_len;
    }
    return offset - start_offset;
}

static int
dissect_Addresses(char *title, ASN1_SCK *asn1p, frame_data *fd,
                  proto_tree *tree, int start_offset) {
    proto_tree *address_tree = NULL;
    int offset = start_offset;

    const guchar *start;
    guint cls, con, tag;
    guint item_len;
    int ret;

    proto_item *item = NULL;
    gboolean def;

    int tmp_pos1, tmp_pos2;
    guint32 address_type;

    int str_len;
    guchar *str;

    KRB_HEAD_DECODE_OR_DIE("sequence of addresses");
    if (tree) {
        item = proto_tree_add_text(tree, NullTVB, offset,
                                   item_len, "Addresses");
        address_tree = proto_item_add_subtree(item, ett_addresses);
    }

    start = asn1p->pointer + item_len;

    while(start > asn1p->pointer) {
        dissect_type_value_pair(asn1p, &offset,
                                &address_type, &item_len, &tmp_pos1,
                                &str, &str_len, &tmp_pos2);

        if (address_tree) {
            proto_tree_add_text(address_tree, NullTVB, tmp_pos1,
                                item_len, "Type: %s",
                                val_to_str(address_type, krb5_address_types,
                                           "Unknown address type %#x"));
            switch(address_type) {
                case KRB5_ADDR_IPv4:
                    proto_tree_add_text(address_tree, NullTVB, tmp_pos2,
                                        str_len, "Value: %d.%d.%d.%d",
                                        str[0], str[1], str[2], str[3]);
                    break;
                    
                default:
                    proto_tree_add_text(address_tree, NullTVB, tmp_pos2,
                                        str_len, "Value: %s",
                                        bytes_to_str(str, str_len));
            }
        }
    }
    
    return offset;
}

static int
dissect_EncryptedData(char *title, ASN1_SCK *asn1p, frame_data *fd,
                      proto_tree *tree, int start_offset)
{
/*
   EncryptedData ::=   SEQUENCE {
                       etype[0]     INTEGER, -- EncryptionType
                       kvno[1]      INTEGER OPTIONAL,
                       cipher[2]    OCTET STRING -- ciphertext
   }
*/
    proto_tree *encr_tree = NULL;
    int offset = start_offset;

    const guchar *start;
    guint cls, con, tag;
    guint header_len, item_len, data_len;
    int ret;

    proto_item *item = NULL;
    guint length;
    gboolean def;
    guint32 val;

    guchar *data;

    KRB_SEQ_HEAD_DECODE_OR_DIE("encrypted data section");

    if (tree) {
        item = proto_tree_add_text(tree, NullTVB, start_offset,
                                   (offset - start_offset) + item_len,
                                   "Encrypted Data: %s", title);
        encr_tree = proto_item_add_subtree(item, ett_princ);
    }

    /* type */
    KRB_DECODE_CONTEXT_HEAD_OR_DIE("encryption type", 0);
    KRB_DECODE_UINT32_OR_DIE("encr-type", val);
    if (encr_tree) {
        proto_tree_add_text(encr_tree, NullTVB, offset, length,
                            "Type: %s",
                            val_to_str(val, krb5_encryption_types,
                                       "Unknown encryption type %#x"));
    }
    offset += length;

    /* kvno */
    KRB_HEAD_DECODE_OR_DIE("kvno-wrap or cipher-wrap");
    if (CHECK_CONTEXT_TYPE(1)) {
      KRB_DECODE_UINT32_OR_DIE("kvno", val);
      if (encr_tree) {
          proto_tree_add_text(encr_tree, NullTVB, offset, length,
                              "KVNO: %d", val);
      }
      offset += length;
      KRB_HEAD_DECODE_OR_DIE("cipher-wrap");
    }

    DIE_IF_NOT_CONTEXT_TYPE("cipher-wrap", 2);
    KRB_DECODE_OCTET_STRING_OR_DIE("cipher", data, data_len, item_len);

    if (encr_tree) {
        proto_tree_add_text(encr_tree, NullTVB, offset, data_len,
                            "CipherText: %s", bytes_to_str(data, item_len));
    }
    offset += data_len;
    
    return offset;
}

static int
dissect_Ticket(char *title, ASN1_SCK *asn1p, frame_data *fd, proto_tree *tree,
               int start_offset)
{
/*
   Ticket ::=                    [APPLICATION 1] SEQUENCE {
                                 tkt-vno[0]                   INTEGER,
                                 realm[1]                     Realm,
                                 sname[2]                     PrincipalName,
                                 enc-part[3]                  EncryptedData
   }
*/
    proto_tree *ticket_tree = NULL;
    int offset = start_offset;

    const guchar *start;
    guint cls, con, tag;
    guint header_len, item_len, total_len;
    int ret;

    proto_item *item = NULL;
    guint length;
    gboolean def;
    guint32 val;

    int str_len;
    guchar *str;

    KRB_DECODE_APPLICATION_TAGGED_HEAD_OR_DIE("Ticket section", 1);
    KRB_SEQ_HEAD_DECODE_OR_DIE("Ticket sequence");
    total_len = item_len;

    if (tree) {
        item = proto_tree_add_text(tree, NullTVB, start_offset,
                                   (offset - start_offset) + item_len,
                                   "Ticket");
        ticket_tree = proto_item_add_subtree(item, ett_ticket);
    }

    /* type */
    KRB_DECODE_CONTEXT_HEAD_OR_DIE("Ticket tkt-vno", KRB5_TKT_TKT_VNO);
    KRB_DECODE_UINT32_OR_DIE("Ticket tkt-vno", val);
    if (ticket_tree) {
        proto_tree_add_text(ticket_tree, NullTVB, offset, length,
                            "Version: %u", val);
    }
    offset += length;
    total_len -= length;

    /* realm name */
    KRB_DECODE_CONTEXT_HEAD_OR_DIE("Ticket realm", KRB5_TKT_REALM);
    KRB_DECODE_GENERAL_STRING_OR_DIE("Ticket realm string", str, str_len, item_len);
    if (ticket_tree) {
        proto_tree_add_text(ticket_tree, NullTVB, offset, item_len,
                            "Realm: %.*s", str_len, str);
    }
    offset += item_len;
    total_len -= item_len;

    /* server name (sname) */
    KRB_DECODE_CONTEXT_HEAD_OR_DIE("Ticket sname", KRB5_TKT_SNAME);
    item_len = dissect_PrincipalName("Service Name", asn1p, fd, ticket_tree,
                                     offset);
    if (item_len == -1)
        return -1;
    offset += item_len;

    /* encrypted part */
    KRB_DECODE_CONTEXT_HEAD_OR_DIE("enc-part", KRB5_TKT_ENC_PART);
    offset = dissect_EncryptedData("Ticket data", asn1p, fd, ticket_tree,
                                   offset);
    if (offset == -1)
        return -1;

    return offset;
}


void
proto_register_kerberos(void) {
/*
    static hf_register_info hf[] = {
    };
*/
    static gint *ett[] = {
        &ett_kerberos,
        &ett_preauth,
        &ett_request,
        &ett_princ,
        &ett_encrypted,
        &ett_ticket,
        &ett_addresses,
        &ett_etype,
    };
    proto_kerberos = proto_register_protocol("Kerberos", "KRB5", "kerberos");
/*
    proto_register_field_array(proto_kerberos, hf, array_length(hf));
*/
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_kerberos(void)
{
	old_dissector_add("udp.port", UDP_PORT_KERBEROS, dissect_kerberos);
	old_dissector_add("tcp.port", TCP_PORT_KERBEROS, dissect_kerberos);
}

/*

  MISC definitions from RFC1510:
  
   Realm ::=           GeneralString

   KerberosTime ::=   GeneralizedTime

   HostAddress ::=    SEQUENCE  {
                      addr-type[0]             INTEGER,
                      address[1]               OCTET STRING
   }

   HostAddresses ::=   SEQUENCE OF SEQUENCE {
                       addr-type[0]             INTEGER,
                       address[1]               OCTET STRING
   }

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

   AP-REQ ::=      [APPLICATION 14] SEQUENCE {
                   pvno[0]                       INTEGER,
                   msg-type[1]                   INTEGER,
                   ap-options[2]                 APOptions,
                   ticket[3]                     Ticket,
                   authenticator[4]              EncryptedData
   }

   APOptions ::=   BIT STRING {
                   reserved(0),
                   use-session-key(1),
                   mutual-required(2)
   }

   AP-REP ::=         [APPLICATION 15] SEQUENCE {
              pvno[0]                   INTEGER,
              msg-type[1]               INTEGER,
              enc-part[2]               EncryptedData
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

   KRB-ERROR ::=   [APPLICATION 30] SEQUENCE {
                   pvno[0]               INTEGER,
                   msg-type[1]           INTEGER,
                   ctime[2]              KerberosTime OPTIONAL,
                   cusec[3]              INTEGER OPTIONAL,
                   stime[4]              KerberosTime,
                   susec[5]              INTEGER,
                   error-code[6]         INTEGER,
                   crealm[7]             Realm OPTIONAL,
                   cname[8]              PrincipalName OPTIONAL,
                   realm[9]              Realm, -- Correct realm
                   sname[10]             PrincipalName, -- Correct name
                   e-text[11]            GeneralString OPTIONAL,
                   e-data[12]            OCTET STRING OPTIONAL
   }

   e-data    This field contains additional data about the error for use
             by the application to help it recover from or handle the
             error.  If the errorcode is KDC_ERR_PREAUTH_REQUIRED, then
             the e-data field will contain an encoding of a sequence of
             padata fields, each corresponding to an acceptable pre-
             authentication method and optionally containing data for
             the method:

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
