/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* .\packet-h235.c                                                            */
/* ../../tools/asn2wrs.py -e -p h235 -c h235.cnf -s packet-h235-template H235-SECURITY-MESSAGES.asn H235-SRTP.asn */

/* Input file: packet-h235-template.c */

#line 1 "packet-h235-template.c"
/* packet-h235.c
 * Routines for H.235 packet dissection
 * 2004  Tomas Kukosa
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/oid_resolv.h>

#include <stdio.h>
#include <string.h>

#include "packet-per.h"
#include "packet-h235.h"
#include "packet-h225.h"

#define PNAME  "H235-SECURITY-MESSAGES"
#define PSNAME "H.235"
#define PFNAME "h235"

/* Initialize the protocol and registered fields */
int proto_h235 = -1;

/*--- Included file: packet-h235-hf.c ---*/
#line 1 "packet-h235-hf.c"
static int hf_h235_nonStandardIdentifier = -1;    /* OBJECT_IDENTIFIER */
static int hf_h235_data = -1;                     /* OCTET_STRING */
static int hf_h235_halfkey = -1;                  /* BIT_STRING_SIZE_0_2048 */
static int hf_h235_modSize = -1;                  /* BIT_STRING_SIZE_0_2048 */
static int hf_h235_generator = -1;                /* BIT_STRING_SIZE_0_2048 */
static int hf_h235_x = -1;                        /* BIT_STRING_SIZE_0_511 */
static int hf_h235_y = -1;                        /* BIT_STRING_SIZE_0_511 */
static int hf_h235_eckasdhp = -1;                 /* T_eckasdhp */
static int hf_h235_public_key = -1;               /* ECpoint */
static int hf_h235_modulus = -1;                  /* BIT_STRING_SIZE_0_511 */
static int hf_h235_base = -1;                     /* ECpoint */
static int hf_h235_weierstrassA = -1;             /* BIT_STRING_SIZE_0_511 */
static int hf_h235_weierstrassB = -1;             /* BIT_STRING_SIZE_0_511 */
static int hf_h235_eckasdh2 = -1;                 /* T_eckasdh2 */
static int hf_h235_fieldSize = -1;                /* BIT_STRING_SIZE_0_511 */
static int hf_h235_type = -1;                     /* OBJECT_IDENTIFIER */
static int hf_h235_certificatedata = -1;          /* OCTET_STRING */
static int hf_h235_default = -1;                  /* NULL */
static int hf_h235_radius = -1;                   /* NULL */
static int hf_h235_dhExch = -1;                   /* NULL */
static int hf_h235_pwdSymEnc = -1;                /* NULL */
static int hf_h235_pwdHash = -1;                  /* NULL */
static int hf_h235_certSign = -1;                 /* NULL */
static int hf_h235_ipsec = -1;                    /* NULL */
static int hf_h235_tls = -1;                      /* NULL */
static int hf_h235_nonStandard = -1;              /* NonStandardParameter */
static int hf_h235_authenticationBES = -1;        /* AuthenticationBES */
static int hf_h235_keyExch = -1;                  /* OBJECT_IDENTIFIER */
static int hf_h235_tokenOID = -1;                 /* OBJECT_IDENTIFIER */
static int hf_h235_timeStamp = -1;                /* TimeStamp */
static int hf_h235_password = -1;                 /* Password */
static int hf_h235_dhkey = -1;                    /* DHset */
static int hf_h235_challenge = -1;                /* ChallengeString */
static int hf_h235_random = -1;                   /* RandomVal */
static int hf_h235_certificate = -1;              /* TypedCertificate */
static int hf_h235_generalID = -1;                /* Identifier */
static int hf_h235_eckasdhkey = -1;               /* ECKASDH */
static int hf_h235_sendersID = -1;                /* Identifier */
static int hf_h235_h235Key = -1;                  /* H235Key */
static int hf_h235_profileInfo = -1;              /* SEQUENCE_OF_ProfileElement */
static int hf_h235_profileInfo_item = -1;         /* ProfileElement */
static int hf_h235_elementID = -1;                /* INTEGER_0_255 */
static int hf_h235_paramS = -1;                   /* Params */
static int hf_h235_element = -1;                  /* Element */
static int hf_h235_octets = -1;                   /* OCTET_STRING */
static int hf_h235_integer = -1;                  /* INTEGER */
static int hf_h235_bits = -1;                     /* BIT_STRING */
static int hf_h235_name = -1;                     /* BMPString */
static int hf_h235_flag = -1;                     /* BOOLEAN */
static int hf_h235_toBeSigned = -1;               /* ToBeSigned */
static int hf_h235_algorithmOID = -1;             /* OBJECT_IDENTIFIER */
static int hf_h235_signaturedata = -1;            /* BIT_STRING */
static int hf_h235_encryptedData = -1;            /* OCTET_STRING */
static int hf_h235_hash = -1;                     /* BIT_STRING */
static int hf_h235_ranInt = -1;                   /* INTEGER */
static int hf_h235_iv8 = -1;                      /* IV8 */
static int hf_h235_iv16 = -1;                     /* IV16 */
static int hf_h235_iv = -1;                       /* OCTET_STRING */
static int hf_h235_clearSalt = -1;                /* OCTET_STRING */
static int hf_h235_cryptoEncryptedToken = -1;     /* T_cryptoEncryptedToken */
static int hf_h235_encryptedToken = -1;           /* ENCRYPTEDxxx */
static int hf_h235_cryptoSignedToken = -1;        /* T_cryptoSignedToken */
static int hf_h235_signedToken = -1;              /* SIGNEDxxx */
static int hf_h235_cryptoHashedToken = -1;        /* T_cryptoHashedToken */
static int hf_h235_hashedVals = -1;               /* ClearToken */
static int hf_h235_hashedToken = -1;              /* HASHEDxxx */
static int hf_h235_cryptoPwdEncr = -1;            /* ENCRYPTEDxxx */
static int hf_h235_secureChannel = -1;            /* KeyMaterial */
static int hf_h235_sharedSecret = -1;             /* ENCRYPTEDxxx */
static int hf_h235_certProtectedKey = -1;         /* SIGNEDxxx */
static int hf_h235_secureSharedSecret = -1;       /* V3KeySyncMaterial */
static int hf_h235_generalId = -1;                /* Identifier */
static int hf_h235_mrandom = -1;                  /* RandomVal */
static int hf_h235_srandom = -1;                  /* RandomVal */
static int hf_h235_encrptval = -1;                /* ENCRYPTEDxxx */
static int hf_h235_responseRandom = -1;           /* RandomVal */
static int hf_h235_requestRandom = -1;            /* RandomVal */
static int hf_h235_keyMaterial = -1;              /* KeyMaterial */
static int hf_h235_encryptedSessionKey = -1;      /* OCTET_STRING */
static int hf_h235_encryptedSaltingKey = -1;      /* OCTET_STRING */
static int hf_h235_clearSaltingKey = -1;          /* OCTET_STRING */
static int hf_h235_paramSsalt = -1;               /* Params */
static int hf_h235_keyDerivationOID = -1;         /* OBJECT_IDENTIFIER */
static int hf_h235_genericKeyMaterial = -1;       /* OCTET_STRING */
static int hf_h235_SrtpCryptoCapability_item = -1;  /* SrtpCryptoInfo */
static int hf_h235_cryptoSuite = -1;              /* OBJECT_IDENTIFIER */
static int hf_h235_sessionParams = -1;            /* SrtpSessionParameters */
static int hf_h235_allowMKI = -1;                 /* BOOLEAN */
static int hf_h235_SrtpKeys_item = -1;            /* SrtpKeyParameters */
static int hf_h235_masterKey = -1;                /* OCTET_STRING */
static int hf_h235_masterSalt = -1;               /* OCTET_STRING */
static int hf_h235_lifetime = -1;                 /* T_lifetime */
static int hf_h235_powerOfTwo = -1;               /* INTEGER */
static int hf_h235_specific = -1;                 /* INTEGER */
static int hf_h235_mki = -1;                      /* T_mki */
static int hf_h235_length = -1;                   /* INTEGER_1_128 */
static int hf_h235_value = -1;                    /* OCTET_STRING */
static int hf_h235_kdr = -1;                      /* INTEGER_0_24 */
static int hf_h235_unencryptedSrtp = -1;          /* BOOLEAN */
static int hf_h235_unencryptedSrtcp = -1;         /* BOOLEAN */
static int hf_h235_unauthenticatedSrtp = -1;      /* BOOLEAN */
static int hf_h235_fecOrder = -1;                 /* FecOrder */
static int hf_h235_windowSizeHint = -1;           /* INTEGER_64_65535 */
static int hf_h235_newParameter = -1;             /* SEQUENCE_OF_GenericData */
static int hf_h235_newParameter_item = -1;        /* GenericData */
static int hf_h235_fecBeforeSrtp = -1;            /* NULL */
static int hf_h235_fecAfterSrtp = -1;             /* NULL */

/*--- End of included file: packet-h235-hf.c ---*/
#line 49 "packet-h235-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-h235-ett.c ---*/
#line 1 "packet-h235-ett.c"
static gint ett_h235_NonStandardParameter = -1;
static gint ett_h235_DHset = -1;
static gint ett_h235_ECpoint = -1;
static gint ett_h235_ECKASDH = -1;
static gint ett_h235_T_eckasdhp = -1;
static gint ett_h235_T_eckasdh2 = -1;
static gint ett_h235_TypedCertificate = -1;
static gint ett_h235_AuthenticationBES = -1;
static gint ett_h235_AuthenticationMechanism = -1;
static gint ett_h235_ClearToken = -1;
static gint ett_h235_SEQUENCE_OF_ProfileElement = -1;
static gint ett_h235_ProfileElement = -1;
static gint ett_h235_Element = -1;
static gint ett_h235_SIGNEDxxx = -1;
static gint ett_h235_ENCRYPTEDxxx = -1;
static gint ett_h235_HASHEDxxx = -1;
static gint ett_h235_Params = -1;
static gint ett_h235_CryptoToken = -1;
static gint ett_h235_T_cryptoEncryptedToken = -1;
static gint ett_h235_T_cryptoSignedToken = -1;
static gint ett_h235_T_cryptoHashedToken = -1;
static gint ett_h235_H235Key = -1;
static gint ett_h235_KeySignedMaterial = -1;
static gint ett_h235_ReturnSig = -1;
static gint ett_h235_KeySyncMaterial = -1;
static gint ett_h235_V3KeySyncMaterial = -1;
static gint ett_h235_SrtpCryptoCapability = -1;
static gint ett_h235_SrtpCryptoInfo = -1;
static gint ett_h235_SrtpKeys = -1;
static gint ett_h235_SrtpKeyParameters = -1;
static gint ett_h235_T_lifetime = -1;
static gint ett_h235_T_mki = -1;
static gint ett_h235_SrtpSessionParameters = -1;
static gint ett_h235_SEQUENCE_OF_GenericData = -1;
static gint ett_h235_FecOrder = -1;

/*--- End of included file: packet-h235-ett.c ---*/
#line 52 "packet-h235-template.c"

static int
dissect_xxx_ToBeSigned(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) {
PER_NOT_DECODED_YET("ToBeSigned");
  return offset;
}


/*--- Included file: packet-h235-fn.c ---*/
#line 1 "packet-h235-fn.c"


static int
dissect_h235_ChallengeString(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 128, NULL);

  return offset;
}



int
dissect_h235_TimeStamp(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              1U, 4294967295U, NULL, FALSE);

  return offset;
}



static int
dissect_h235_RandomVal(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_h235_Password(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_BMPString(tvb, offset, actx, tree, hf_index,
                                          1, 128);

  return offset;
}



static int
dissect_h235_Identifier(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_BMPString(tvb, offset, actx, tree, hf_index,
                                          1, 128);

  return offset;
}



static int
dissect_h235_KeyMaterial(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 2048, FALSE, NULL);

  return offset;
}



static int
dissect_h235_OBJECT_IDENTIFIER(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_h235_OCTET_STRING(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, NULL);

  return offset;
}


static const per_sequence_t NonStandardParameter_sequence[] = {
  { &hf_h235_nonStandardIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_OBJECT_IDENTIFIER },
  { &hf_h235_data           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_h235_NonStandardParameter(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h235_NonStandardParameter, NonStandardParameter_sequence);

  return offset;
}



static int
dissect_h235_BIT_STRING_SIZE_0_2048(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     0, 2048, FALSE, NULL);

  return offset;
}


static const per_sequence_t DHset_sequence[] = {
  { &hf_h235_halfkey        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h235_BIT_STRING_SIZE_0_2048 },
  { &hf_h235_modSize        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h235_BIT_STRING_SIZE_0_2048 },
  { &hf_h235_generator      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h235_BIT_STRING_SIZE_0_2048 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h235_DHset(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h235_DHset, DHset_sequence);

  return offset;
}



static int
dissect_h235_BIT_STRING_SIZE_0_511(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     0, 511, FALSE, NULL);

  return offset;
}


static const per_sequence_t ECpoint_sequence[] = {
  { &hf_h235_x              , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_BIT_STRING_SIZE_0_511 },
  { &hf_h235_y              , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_BIT_STRING_SIZE_0_511 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h235_ECpoint(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h235_ECpoint, ECpoint_sequence);

  return offset;
}


static const per_sequence_t T_eckasdhp_sequence[] = {
  { &hf_h235_public_key     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_ECpoint },
  { &hf_h235_modulus        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_BIT_STRING_SIZE_0_511 },
  { &hf_h235_base           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_ECpoint },
  { &hf_h235_weierstrassA   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_BIT_STRING_SIZE_0_511 },
  { &hf_h235_weierstrassB   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_BIT_STRING_SIZE_0_511 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h235_T_eckasdhp(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h235_T_eckasdhp, T_eckasdhp_sequence);

  return offset;
}


static const per_sequence_t T_eckasdh2_sequence[] = {
  { &hf_h235_public_key     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_ECpoint },
  { &hf_h235_fieldSize      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_BIT_STRING_SIZE_0_511 },
  { &hf_h235_base           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_ECpoint },
  { &hf_h235_weierstrassA   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_BIT_STRING_SIZE_0_511 },
  { &hf_h235_weierstrassB   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_BIT_STRING_SIZE_0_511 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h235_T_eckasdh2(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h235_T_eckasdh2, T_eckasdh2_sequence);

  return offset;
}


static const value_string h235_ECKASDH_vals[] = {
  {   0, "eckasdhp" },
  {   1, "eckasdh2" },
  { 0, NULL }
};

static const per_choice_t ECKASDH_choice[] = {
  {   0, &hf_h235_eckasdhp       , ASN1_EXTENSION_ROOT    , dissect_h235_T_eckasdhp },
  {   1, &hf_h235_eckasdh2       , ASN1_EXTENSION_ROOT    , dissect_h235_T_eckasdh2 },
  { 0, NULL, 0, NULL }
};

static int
dissect_h235_ECKASDH(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h235_ECKASDH, ECKASDH_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t TypedCertificate_sequence[] = {
  { &hf_h235_type           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h235_OBJECT_IDENTIFIER },
  { &hf_h235_certificatedata, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h235_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_h235_TypedCertificate(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h235_TypedCertificate, TypedCertificate_sequence);

  return offset;
}



static int
dissect_h235_NULL(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string h235_AuthenticationBES_vals[] = {
  {   0, "default" },
  {   1, "radius" },
  { 0, NULL }
};

static const per_choice_t AuthenticationBES_choice[] = {
  {   0, &hf_h235_default        , ASN1_EXTENSION_ROOT    , dissect_h235_NULL },
  {   1, &hf_h235_radius         , ASN1_EXTENSION_ROOT    , dissect_h235_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h235_AuthenticationBES(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h235_AuthenticationBES, AuthenticationBES_choice,
                                 NULL);

  return offset;
}


const value_string h235_AuthenticationMechanism_vals[] = {
  {   0, "dhExch" },
  {   1, "pwdSymEnc" },
  {   2, "pwdHash" },
  {   3, "certSign" },
  {   4, "ipsec" },
  {   5, "tls" },
  {   6, "nonStandard" },
  {   7, "authenticationBES" },
  {   8, "keyExch" },
  { 0, NULL }
};

static const per_choice_t AuthenticationMechanism_choice[] = {
  {   0, &hf_h235_dhExch         , ASN1_EXTENSION_ROOT    , dissect_h235_NULL },
  {   1, &hf_h235_pwdSymEnc      , ASN1_EXTENSION_ROOT    , dissect_h235_NULL },
  {   2, &hf_h235_pwdHash        , ASN1_EXTENSION_ROOT    , dissect_h235_NULL },
  {   3, &hf_h235_certSign       , ASN1_EXTENSION_ROOT    , dissect_h235_NULL },
  {   4, &hf_h235_ipsec          , ASN1_EXTENSION_ROOT    , dissect_h235_NULL },
  {   5, &hf_h235_tls            , ASN1_EXTENSION_ROOT    , dissect_h235_NULL },
  {   6, &hf_h235_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_h235_NonStandardParameter },
  {   7, &hf_h235_authenticationBES, ASN1_NOT_EXTENSION_ROOT, dissect_h235_AuthenticationBES },
  {   8, &hf_h235_keyExch        , ASN1_NOT_EXTENSION_ROOT, dissect_h235_OBJECT_IDENTIFIER },
  { 0, NULL, 0, NULL }
};

int
dissect_h235_AuthenticationMechanism(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h235_AuthenticationMechanism, AuthenticationMechanism_choice,
                                 NULL);

  return offset;
}



static int
dissect_h235_INTEGER(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_h235_IV8(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, NULL);

  return offset;
}



static int
dissect_h235_IV16(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       16, 16, NULL);

  return offset;
}


static const per_sequence_t Params_sequence[] = {
  { &hf_h235_ranInt         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_INTEGER },
  { &hf_h235_iv8            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_IV8 },
  { &hf_h235_iv16           , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h235_IV16 },
  { &hf_h235_iv             , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h235_OCTET_STRING },
  { &hf_h235_clearSalt      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h235_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_h235_Params(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h235_Params, Params_sequence);

  return offset;
}


static const per_sequence_t ENCRYPTEDxxx_sequence[] = {
  { &hf_h235_algorithmOID   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_OBJECT_IDENTIFIER },
  { &hf_h235_paramS         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_Params },
  { &hf_h235_encryptedData  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

int
dissect_h235_ENCRYPTEDxxx(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 49 "h235.cnf"
  proto_tree_add_item_hidden(tree, proto_h235, tvb, offset, 0, FALSE);

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h235_ENCRYPTEDxxx, ENCRYPTEDxxx_sequence);

  return offset;
}



static int
dissect_h235_BIT_STRING(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t SIGNEDxxx_sequence[] = {
  { &hf_h235_toBeSigned     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xxx_ToBeSigned },
  { &hf_h235_algorithmOID   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_OBJECT_IDENTIFIER },
  { &hf_h235_paramS         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_Params },
  { &hf_h235_signaturedata  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_BIT_STRING },
  { NULL, 0, 0, NULL }
};

int
dissect_h235_SIGNEDxxx(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 46 "h235.cnf"
  proto_tree_add_item_hidden(tree, proto_h235, tvb, offset, 0, FALSE);

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h235_SIGNEDxxx, SIGNEDxxx_sequence);

  return offset;
}


static const per_sequence_t V3KeySyncMaterial_sequence[] = {
  { &hf_h235_generalID      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_Identifier },
  { &hf_h235_algorithmOID   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_OBJECT_IDENTIFIER },
  { &hf_h235_paramS         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h235_Params },
  { &hf_h235_encryptedSessionKey, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_OCTET_STRING },
  { &hf_h235_encryptedSaltingKey, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_OCTET_STRING },
  { &hf_h235_clearSaltingKey, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_OCTET_STRING },
  { &hf_h235_paramSsalt     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_Params },
  { &hf_h235_keyDerivationOID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_OBJECT_IDENTIFIER },
  { &hf_h235_genericKeyMaterial, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h235_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_h235_V3KeySyncMaterial(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h235_V3KeySyncMaterial, V3KeySyncMaterial_sequence);

  return offset;
}


static const value_string h235_H235Key_vals[] = {
  {   0, "secureChannel" },
  {   1, "sharedSecret" },
  {   2, "certProtectedKey" },
  {   3, "secureSharedSecret" },
  { 0, NULL }
};

static const per_choice_t H235Key_choice[] = {
  {   0, &hf_h235_secureChannel  , ASN1_EXTENSION_ROOT    , dissect_h235_KeyMaterial },
  {   1, &hf_h235_sharedSecret   , ASN1_EXTENSION_ROOT    , dissect_h235_ENCRYPTEDxxx },
  {   2, &hf_h235_certProtectedKey, ASN1_EXTENSION_ROOT    , dissect_h235_SIGNEDxxx },
  {   3, &hf_h235_secureSharedSecret, ASN1_NOT_EXTENSION_ROOT, dissect_h235_V3KeySyncMaterial },
  { 0, NULL, 0, NULL }
};

static int
dissect_h235_H235Key(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h235_H235Key, H235Key_choice,
                                 NULL);

  return offset;
}



static int
dissect_h235_INTEGER_0_255(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_h235_BMPString(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_BMPString(tvb, offset, actx, tree, hf_index,
                                          NO_BOUND, NO_BOUND);

  return offset;
}



static int
dissect_h235_BOOLEAN(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string h235_Element_vals[] = {
  {   0, "octets" },
  {   1, "integer" },
  {   2, "bits" },
  {   3, "name" },
  {   4, "flag" },
  { 0, NULL }
};

static const per_choice_t Element_choice[] = {
  {   0, &hf_h235_octets         , ASN1_EXTENSION_ROOT    , dissect_h235_OCTET_STRING },
  {   1, &hf_h235_integer        , ASN1_EXTENSION_ROOT    , dissect_h235_INTEGER },
  {   2, &hf_h235_bits           , ASN1_EXTENSION_ROOT    , dissect_h235_BIT_STRING },
  {   3, &hf_h235_name           , ASN1_EXTENSION_ROOT    , dissect_h235_BMPString },
  {   4, &hf_h235_flag           , ASN1_EXTENSION_ROOT    , dissect_h235_BOOLEAN },
  { 0, NULL, 0, NULL }
};

static int
dissect_h235_Element(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h235_Element, Element_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ProfileElement_sequence[] = {
  { &hf_h235_elementID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h235_INTEGER_0_255 },
  { &hf_h235_paramS         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_Params },
  { &hf_h235_element        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_Element },
  { NULL, 0, 0, NULL }
};

static int
dissect_h235_ProfileElement(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h235_ProfileElement, ProfileElement_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_ProfileElement_sequence_of[1] = {
  { &hf_h235_profileInfo_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_ProfileElement },
};

static int
dissect_h235_SEQUENCE_OF_ProfileElement(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h235_SEQUENCE_OF_ProfileElement, SEQUENCE_OF_ProfileElement_sequence_of);

  return offset;
}


static const per_sequence_t ClearToken_sequence[] = {
  { &hf_h235_tokenOID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h235_OBJECT_IDENTIFIER },
  { &hf_h235_timeStamp      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_TimeStamp },
  { &hf_h235_password       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_Password },
  { &hf_h235_dhkey          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_DHset },
  { &hf_h235_challenge      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_ChallengeString },
  { &hf_h235_random         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_RandomVal },
  { &hf_h235_certificate    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_TypedCertificate },
  { &hf_h235_generalID      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_Identifier },
  { &hf_h235_nonStandard    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_NonStandardParameter },
  { &hf_h235_eckasdhkey     , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h235_ECKASDH },
  { &hf_h235_sendersID      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h235_Identifier },
  { &hf_h235_h235Key        , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h235_H235Key },
  { &hf_h235_profileInfo    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h235_SEQUENCE_OF_ProfileElement },
  { NULL, 0, 0, NULL }
};

int
dissect_h235_ClearToken(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 56 "h235.cnf"
  proto_tree_add_item_hidden(tree, proto_h235, tvb, offset, 0, FALSE);

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h235_ClearToken, ClearToken_sequence);

  return offset;
}


static const per_sequence_t HASHEDxxx_sequence[] = {
  { &hf_h235_algorithmOID   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_OBJECT_IDENTIFIER },
  { &hf_h235_paramS         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_Params },
  { &hf_h235_hash           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_BIT_STRING },
  { NULL, 0, 0, NULL }
};

int
dissect_h235_HASHEDxxx(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 52 "h235.cnf"
  proto_tree_add_item_hidden(tree, proto_h235, tvb, offset, 0, FALSE);

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h235_HASHEDxxx, HASHEDxxx_sequence);

  return offset;
}



static int
dissect_h235_EncodedGeneralToken(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, dissect_h235_ClearToken);

  return offset;
}



static int
dissect_h235_PwdCertToken(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h235_ClearToken(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_h235_EncodedPwdCertToken(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, dissect_h235_PwdCertToken);

  return offset;
}


static const per_sequence_t T_cryptoEncryptedToken_sequence[] = {
  { &hf_h235_tokenOID       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_OBJECT_IDENTIFIER },
  { &hf_h235_encryptedToken , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_ENCRYPTEDxxx },
  { NULL, 0, 0, NULL }
};

static int
dissect_h235_T_cryptoEncryptedToken(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h235_T_cryptoEncryptedToken, T_cryptoEncryptedToken_sequence);

  return offset;
}


static const per_sequence_t T_cryptoSignedToken_sequence[] = {
  { &hf_h235_tokenOID       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_OBJECT_IDENTIFIER },
  { &hf_h235_signedToken    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_SIGNEDxxx },
  { NULL, 0, 0, NULL }
};

static int
dissect_h235_T_cryptoSignedToken(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h235_T_cryptoSignedToken, T_cryptoSignedToken_sequence);

  return offset;
}


static const per_sequence_t T_cryptoHashedToken_sequence[] = {
  { &hf_h235_tokenOID       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_OBJECT_IDENTIFIER },
  { &hf_h235_hashedVals     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_ClearToken },
  { &hf_h235_hashedToken    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_HASHEDxxx },
  { NULL, 0, 0, NULL }
};

static int
dissect_h235_T_cryptoHashedToken(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h235_T_cryptoHashedToken, T_cryptoHashedToken_sequence);

  return offset;
}


const value_string h235_CryptoToken_vals[] = {
  {   0, "cryptoEncryptedToken" },
  {   1, "cryptoSignedToken" },
  {   2, "cryptoHashedToken" },
  {   3, "cryptoPwdEncr" },
  { 0, NULL }
};

static const per_choice_t CryptoToken_choice[] = {
  {   0, &hf_h235_cryptoEncryptedToken, ASN1_EXTENSION_ROOT    , dissect_h235_T_cryptoEncryptedToken },
  {   1, &hf_h235_cryptoSignedToken, ASN1_EXTENSION_ROOT    , dissect_h235_T_cryptoSignedToken },
  {   2, &hf_h235_cryptoHashedToken, ASN1_EXTENSION_ROOT    , dissect_h235_T_cryptoHashedToken },
  {   3, &hf_h235_cryptoPwdEncr  , ASN1_EXTENSION_ROOT    , dissect_h235_ENCRYPTEDxxx },
  { 0, NULL, 0, NULL }
};

int
dissect_h235_CryptoToken(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 60 "h235.cnf"
  proto_tree_add_item_hidden(tree, proto_h235, tvb, offset, 0, FALSE);

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h235_CryptoToken, CryptoToken_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t KeySignedMaterial_sequence[] = {
  { &hf_h235_generalId      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_Identifier },
  { &hf_h235_mrandom        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_RandomVal },
  { &hf_h235_srandom        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_h235_RandomVal },
  { &hf_h235_timeStamp      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_h235_TimeStamp },
  { &hf_h235_encrptval      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_ENCRYPTEDxxx },
  { NULL, 0, 0, NULL }
};

static int
dissect_h235_KeySignedMaterial(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h235_KeySignedMaterial, KeySignedMaterial_sequence);

  return offset;
}



static int
dissect_h235_EncodedKeySignedMaterial(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, dissect_h235_KeySignedMaterial);

  return offset;
}


static const per_sequence_t ReturnSig_sequence[] = {
  { &hf_h235_generalId      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_Identifier },
  { &hf_h235_responseRandom , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_RandomVal },
  { &hf_h235_requestRandom  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_h235_RandomVal },
  { &hf_h235_certificate    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_h235_TypedCertificate },
  { NULL, 0, 0, NULL }
};

static int
dissect_h235_ReturnSig(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h235_ReturnSig, ReturnSig_sequence);

  return offset;
}



static int
dissect_h235_EncodedReturnSig(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, dissect_h235_ReturnSig);

  return offset;
}


static const per_sequence_t KeySyncMaterial_sequence[] = {
  { &hf_h235_generalID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h235_Identifier },
  { &hf_h235_keyMaterial    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h235_KeyMaterial },
  { NULL, 0, 0, NULL }
};

static int
dissect_h235_KeySyncMaterial(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h235_KeySyncMaterial, KeySyncMaterial_sequence);

  return offset;
}



static int
dissect_h235_EncodedKeySyncMaterial(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, dissect_h235_KeySyncMaterial);

  return offset;
}



static int
dissect_h235_INTEGER_0_24(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 24U, NULL, FALSE);

  return offset;
}


static const per_sequence_t FecOrder_sequence[] = {
  { &hf_h235_fecBeforeSrtp  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_NULL },
  { &hf_h235_fecAfterSrtp   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_NULL },
  { NULL, 0, 0, NULL }
};

static int
dissect_h235_FecOrder(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h235_FecOrder, FecOrder_sequence);

  return offset;
}



static int
dissect_h235_INTEGER_64_65535(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              64U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_GenericData_sequence_of[1] = {
  { &hf_h235_newParameter_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h225_GenericData },
};

static int
dissect_h235_SEQUENCE_OF_GenericData(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h235_SEQUENCE_OF_GenericData, SEQUENCE_OF_GenericData_sequence_of);

  return offset;
}


static const per_sequence_t SrtpSessionParameters_sequence[] = {
  { &hf_h235_kdr            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_INTEGER_0_24 },
  { &hf_h235_unencryptedSrtp, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_BOOLEAN },
  { &hf_h235_unencryptedSrtcp, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_BOOLEAN },
  { &hf_h235_unauthenticatedSrtp, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_BOOLEAN },
  { &hf_h235_fecOrder       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_FecOrder },
  { &hf_h235_windowSizeHint , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_INTEGER_64_65535 },
  { &hf_h235_newParameter   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_SEQUENCE_OF_GenericData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h235_SrtpSessionParameters(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h235_SrtpSessionParameters, SrtpSessionParameters_sequence);

  return offset;
}


static const per_sequence_t SrtpCryptoInfo_sequence[] = {
  { &hf_h235_cryptoSuite    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_OBJECT_IDENTIFIER },
  { &hf_h235_sessionParams  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_SrtpSessionParameters },
  { &hf_h235_allowMKI       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h235_SrtpCryptoInfo(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h235_SrtpCryptoInfo, SrtpCryptoInfo_sequence);

  return offset;
}


static const per_sequence_t SrtpCryptoCapability_sequence_of[1] = {
  { &hf_h235_SrtpCryptoCapability_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_SrtpCryptoInfo },
};

int
dissect_h235_SrtpCryptoCapability(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h235_SrtpCryptoCapability, SrtpCryptoCapability_sequence_of);

  return offset;
}


static const value_string h235_T_lifetime_vals[] = {
  {   0, "powerOfTwo" },
  {   1, "specific" },
  { 0, NULL }
};

static const per_choice_t T_lifetime_choice[] = {
  {   0, &hf_h235_powerOfTwo     , ASN1_EXTENSION_ROOT    , dissect_h235_INTEGER },
  {   1, &hf_h235_specific       , ASN1_EXTENSION_ROOT    , dissect_h235_INTEGER },
  { 0, NULL, 0, NULL }
};

static int
dissect_h235_T_lifetime(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h235_T_lifetime, T_lifetime_choice,
                                 NULL);

  return offset;
}



static int
dissect_h235_INTEGER_1_128(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              1U, 128U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_mki_sequence[] = {
  { &hf_h235_length         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h235_INTEGER_1_128 },
  { &hf_h235_value          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h235_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_h235_T_mki(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h235_T_mki, T_mki_sequence);

  return offset;
}


static const per_sequence_t SrtpKeyParameters_sequence[] = {
  { &hf_h235_masterKey      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h235_OCTET_STRING },
  { &hf_h235_masterSalt     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h235_OCTET_STRING },
  { &hf_h235_lifetime       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_T_lifetime },
  { &hf_h235_mki            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h235_T_mki },
  { NULL, 0, 0, NULL }
};

static int
dissect_h235_SrtpKeyParameters(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h235_SrtpKeyParameters, SrtpKeyParameters_sequence);

  return offset;
}


static const per_sequence_t SrtpKeys_sequence_of[1] = {
  { &hf_h235_SrtpKeys_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h235_SrtpKeyParameters },
};

int
dissect_h235_SrtpKeys(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h235_SrtpKeys, SrtpKeys_sequence_of);

  return offset;
}


/*--- End of included file: packet-h235-fn.c ---*/
#line 60 "packet-h235-template.c"


/*--- proto_register_h235 ----------------------------------------------*/
void proto_register_h235(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-h235-hfarr.c ---*/
#line 1 "packet-h235-hfarr.c"
    { &hf_h235_nonStandardIdentifier,
      { "nonStandardIdentifier", "h235.nonStandardIdentifier",
        FT_OID, BASE_NONE, NULL, 0,
        "NonStandardParameter/nonStandardIdentifier", HFILL }},
    { &hf_h235_data,
      { "data", "h235.data",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NonStandardParameter/data", HFILL }},
    { &hf_h235_halfkey,
      { "halfkey", "h235.halfkey",
        FT_BYTES, BASE_HEX, NULL, 0,
        "DHset/halfkey", HFILL }},
    { &hf_h235_modSize,
      { "modSize", "h235.modSize",
        FT_BYTES, BASE_HEX, NULL, 0,
        "DHset/modSize", HFILL }},
    { &hf_h235_generator,
      { "generator", "h235.generator",
        FT_BYTES, BASE_HEX, NULL, 0,
        "DHset/generator", HFILL }},
    { &hf_h235_x,
      { "x", "h235.x",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ECpoint/x", HFILL }},
    { &hf_h235_y,
      { "y", "h235.y",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ECpoint/y", HFILL }},
    { &hf_h235_eckasdhp,
      { "eckasdhp", "h235.eckasdhp",
        FT_NONE, BASE_NONE, NULL, 0,
        "ECKASDH/eckasdhp", HFILL }},
    { &hf_h235_public_key,
      { "public-key", "h235.public_key",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h235_modulus,
      { "modulus", "h235.modulus",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ECKASDH/eckasdhp/modulus", HFILL }},
    { &hf_h235_base,
      { "base", "h235.base",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h235_weierstrassA,
      { "weierstrassA", "h235.weierstrassA",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_h235_weierstrassB,
      { "weierstrassB", "h235.weierstrassB",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_h235_eckasdh2,
      { "eckasdh2", "h235.eckasdh2",
        FT_NONE, BASE_NONE, NULL, 0,
        "ECKASDH/eckasdh2", HFILL }},
    { &hf_h235_fieldSize,
      { "fieldSize", "h235.fieldSize",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ECKASDH/eckasdh2/fieldSize", HFILL }},
    { &hf_h235_type,
      { "type", "h235.type",
        FT_OID, BASE_NONE, NULL, 0,
        "TypedCertificate/type", HFILL }},
    { &hf_h235_certificatedata,
      { "certificate", "h235.certificate",
        FT_BYTES, BASE_HEX, NULL, 0,
        "TypedCertificate/certificate", HFILL }},
    { &hf_h235_default,
      { "default", "h235.default",
        FT_NONE, BASE_NONE, NULL, 0,
        "AuthenticationBES/default", HFILL }},
    { &hf_h235_radius,
      { "radius", "h235.radius",
        FT_NONE, BASE_NONE, NULL, 0,
        "AuthenticationBES/radius", HFILL }},
    { &hf_h235_dhExch,
      { "dhExch", "h235.dhExch",
        FT_NONE, BASE_NONE, NULL, 0,
        "AuthenticationMechanism/dhExch", HFILL }},
    { &hf_h235_pwdSymEnc,
      { "pwdSymEnc", "h235.pwdSymEnc",
        FT_NONE, BASE_NONE, NULL, 0,
        "AuthenticationMechanism/pwdSymEnc", HFILL }},
    { &hf_h235_pwdHash,
      { "pwdHash", "h235.pwdHash",
        FT_NONE, BASE_NONE, NULL, 0,
        "AuthenticationMechanism/pwdHash", HFILL }},
    { &hf_h235_certSign,
      { "certSign", "h235.certSign",
        FT_NONE, BASE_NONE, NULL, 0,
        "AuthenticationMechanism/certSign", HFILL }},
    { &hf_h235_ipsec,
      { "ipsec", "h235.ipsec",
        FT_NONE, BASE_NONE, NULL, 0,
        "AuthenticationMechanism/ipsec", HFILL }},
    { &hf_h235_tls,
      { "tls", "h235.tls",
        FT_NONE, BASE_NONE, NULL, 0,
        "AuthenticationMechanism/tls", HFILL }},
    { &hf_h235_nonStandard,
      { "nonStandard", "h235.nonStandard",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h235_authenticationBES,
      { "authenticationBES", "h235.authenticationBES",
        FT_UINT32, BASE_DEC, VALS(h235_AuthenticationBES_vals), 0,
        "AuthenticationMechanism/authenticationBES", HFILL }},
    { &hf_h235_keyExch,
      { "keyExch", "h235.keyExch",
        FT_OID, BASE_NONE, NULL, 0,
        "AuthenticationMechanism/keyExch", HFILL }},
    { &hf_h235_tokenOID,
      { "tokenOID", "h235.tokenOID",
        FT_OID, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h235_timeStamp,
      { "timeStamp", "h235.timeStamp",
        FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h235_password,
      { "password", "h235.password",
        FT_STRING, BASE_NONE, NULL, 0,
        "ClearToken/password", HFILL }},
    { &hf_h235_dhkey,
      { "dhkey", "h235.dhkey",
        FT_NONE, BASE_NONE, NULL, 0,
        "ClearToken/dhkey", HFILL }},
    { &hf_h235_challenge,
      { "challenge", "h235.challenge",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ClearToken/challenge", HFILL }},
    { &hf_h235_random,
      { "random", "h235.random",
        FT_INT32, BASE_DEC, NULL, 0,
        "ClearToken/random", HFILL }},
    { &hf_h235_certificate,
      { "certificate", "h235.certificate",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h235_generalID,
      { "generalID", "h235.generalID",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h235_eckasdhkey,
      { "eckasdhkey", "h235.eckasdhkey",
        FT_UINT32, BASE_DEC, VALS(h235_ECKASDH_vals), 0,
        "ClearToken/eckasdhkey", HFILL }},
    { &hf_h235_sendersID,
      { "sendersID", "h235.sendersID",
        FT_STRING, BASE_NONE, NULL, 0,
        "ClearToken/sendersID", HFILL }},
    { &hf_h235_h235Key,
      { "h235Key", "h235.h235Key",
        FT_UINT32, BASE_DEC, VALS(h235_H235Key_vals), 0,
        "ClearToken/h235Key", HFILL }},
    { &hf_h235_profileInfo,
      { "profileInfo", "h235.profileInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ClearToken/profileInfo", HFILL }},
    { &hf_h235_profileInfo_item,
      { "Item", "h235.profileInfo_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ClearToken/profileInfo/_item", HFILL }},
    { &hf_h235_elementID,
      { "elementID", "h235.elementID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProfileElement/elementID", HFILL }},
    { &hf_h235_paramS,
      { "paramS", "h235.paramS",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h235_element,
      { "element", "h235.element",
        FT_UINT32, BASE_DEC, VALS(h235_Element_vals), 0,
        "ProfileElement/element", HFILL }},
    { &hf_h235_octets,
      { "octets", "h235.octets",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Element/octets", HFILL }},
    { &hf_h235_integer,
      { "integer", "h235.integer",
        FT_INT32, BASE_DEC, NULL, 0,
        "Element/integer", HFILL }},
    { &hf_h235_bits,
      { "bits", "h235.bits",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Element/bits", HFILL }},
    { &hf_h235_name,
      { "name", "h235.name",
        FT_STRING, BASE_NONE, NULL, 0,
        "Element/name", HFILL }},
    { &hf_h235_flag,
      { "flag", "h235.flag",
        FT_BOOLEAN, 8, NULL, 0,
        "Element/flag", HFILL }},
    { &hf_h235_toBeSigned,
      { "toBeSigned", "h235.toBeSigned",
        FT_NONE, BASE_NONE, NULL, 0,
        "SIGNEDxxx/toBeSigned", HFILL }},
    { &hf_h235_algorithmOID,
      { "algorithmOID", "h235.algorithmOID",
        FT_OID, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h235_signaturedata,
      { "signature", "h235.signature",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SIGNEDxxx/signature", HFILL }},
    { &hf_h235_encryptedData,
      { "encryptedData", "h235.encryptedData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ENCRYPTEDxxx/encryptedData", HFILL }},
    { &hf_h235_hash,
      { "hash", "h235.hash",
        FT_BYTES, BASE_HEX, NULL, 0,
        "HASHEDxxx/hash", HFILL }},
    { &hf_h235_ranInt,
      { "ranInt", "h235.ranInt",
        FT_INT32, BASE_DEC, NULL, 0,
        "Params/ranInt", HFILL }},
    { &hf_h235_iv8,
      { "iv8", "h235.iv8",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Params/iv8", HFILL }},
    { &hf_h235_iv16,
      { "iv16", "h235.iv16",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Params/iv16", HFILL }},
    { &hf_h235_iv,
      { "iv", "h235.iv",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Params/iv", HFILL }},
    { &hf_h235_clearSalt,
      { "clearSalt", "h235.clearSalt",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Params/clearSalt", HFILL }},
    { &hf_h235_cryptoEncryptedToken,
      { "cryptoEncryptedToken", "h235.cryptoEncryptedToken",
        FT_NONE, BASE_NONE, NULL, 0,
        "CryptoToken/cryptoEncryptedToken", HFILL }},
    { &hf_h235_encryptedToken,
      { "token", "h235.token",
        FT_NONE, BASE_NONE, NULL, 0,
        "CryptoToken/cryptoEncryptedToken/token", HFILL }},
    { &hf_h235_cryptoSignedToken,
      { "cryptoSignedToken", "h235.cryptoSignedToken",
        FT_NONE, BASE_NONE, NULL, 0,
        "CryptoToken/cryptoSignedToken", HFILL }},
    { &hf_h235_signedToken,
      { "token", "h235.token",
        FT_NONE, BASE_NONE, NULL, 0,
        "CryptoToken/cryptoSignedToken/token", HFILL }},
    { &hf_h235_cryptoHashedToken,
      { "cryptoHashedToken", "h235.cryptoHashedToken",
        FT_NONE, BASE_NONE, NULL, 0,
        "CryptoToken/cryptoHashedToken", HFILL }},
    { &hf_h235_hashedVals,
      { "hashedVals", "h235.hashedVals",
        FT_NONE, BASE_NONE, NULL, 0,
        "CryptoToken/cryptoHashedToken/hashedVals", HFILL }},
    { &hf_h235_hashedToken,
      { "token", "h235.token",
        FT_NONE, BASE_NONE, NULL, 0,
        "CryptoToken/cryptoHashedToken/token", HFILL }},
    { &hf_h235_cryptoPwdEncr,
      { "cryptoPwdEncr", "h235.cryptoPwdEncr",
        FT_NONE, BASE_NONE, NULL, 0,
        "CryptoToken/cryptoPwdEncr", HFILL }},
    { &hf_h235_secureChannel,
      { "secureChannel", "h235.secureChannel",
        FT_BYTES, BASE_HEX, NULL, 0,
        "H235Key/secureChannel", HFILL }},
    { &hf_h235_sharedSecret,
      { "sharedSecret", "h235.sharedSecret",
        FT_NONE, BASE_NONE, NULL, 0,
        "H235Key/sharedSecret", HFILL }},
    { &hf_h235_certProtectedKey,
      { "certProtectedKey", "h235.certProtectedKey",
        FT_NONE, BASE_NONE, NULL, 0,
        "H235Key/certProtectedKey", HFILL }},
    { &hf_h235_secureSharedSecret,
      { "secureSharedSecret", "h235.secureSharedSecret",
        FT_NONE, BASE_NONE, NULL, 0,
        "H235Key/secureSharedSecret", HFILL }},
    { &hf_h235_generalId,
      { "generalId", "h235.generalId",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h235_mrandom,
      { "mrandom", "h235.mrandom",
        FT_INT32, BASE_DEC, NULL, 0,
        "KeySignedMaterial/mrandom", HFILL }},
    { &hf_h235_srandom,
      { "srandom", "h235.srandom",
        FT_INT32, BASE_DEC, NULL, 0,
        "KeySignedMaterial/srandom", HFILL }},
    { &hf_h235_encrptval,
      { "encrptval", "h235.encrptval",
        FT_NONE, BASE_NONE, NULL, 0,
        "KeySignedMaterial/encrptval", HFILL }},
    { &hf_h235_responseRandom,
      { "responseRandom", "h235.responseRandom",
        FT_INT32, BASE_DEC, NULL, 0,
        "ReturnSig/responseRandom", HFILL }},
    { &hf_h235_requestRandom,
      { "requestRandom", "h235.requestRandom",
        FT_INT32, BASE_DEC, NULL, 0,
        "ReturnSig/requestRandom", HFILL }},
    { &hf_h235_keyMaterial,
      { "keyMaterial", "h235.keyMaterial",
        FT_BYTES, BASE_HEX, NULL, 0,
        "KeySyncMaterial/keyMaterial", HFILL }},
    { &hf_h235_encryptedSessionKey,
      { "encryptedSessionKey", "h235.encryptedSessionKey",
        FT_BYTES, BASE_HEX, NULL, 0,
        "V3KeySyncMaterial/encryptedSessionKey", HFILL }},
    { &hf_h235_encryptedSaltingKey,
      { "encryptedSaltingKey", "h235.encryptedSaltingKey",
        FT_BYTES, BASE_HEX, NULL, 0,
        "V3KeySyncMaterial/encryptedSaltingKey", HFILL }},
    { &hf_h235_clearSaltingKey,
      { "clearSaltingKey", "h235.clearSaltingKey",
        FT_BYTES, BASE_HEX, NULL, 0,
        "V3KeySyncMaterial/clearSaltingKey", HFILL }},
    { &hf_h235_paramSsalt,
      { "paramSsalt", "h235.paramSsalt",
        FT_NONE, BASE_NONE, NULL, 0,
        "V3KeySyncMaterial/paramSsalt", HFILL }},
    { &hf_h235_keyDerivationOID,
      { "keyDerivationOID", "h235.keyDerivationOID",
        FT_OID, BASE_NONE, NULL, 0,
        "V3KeySyncMaterial/keyDerivationOID", HFILL }},
    { &hf_h235_genericKeyMaterial,
      { "genericKeyMaterial", "h235.genericKeyMaterial",
        FT_BYTES, BASE_HEX, NULL, 0,
        "V3KeySyncMaterial/genericKeyMaterial", HFILL }},
    { &hf_h235_SrtpCryptoCapability_item,
      { "Item", "h235.SrtpCryptoCapability_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SrtpCryptoCapability/_item", HFILL }},
    { &hf_h235_cryptoSuite,
      { "cryptoSuite", "h235.cryptoSuite",
        FT_OID, BASE_NONE, NULL, 0,
        "SrtpCryptoInfo/cryptoSuite", HFILL }},
    { &hf_h235_sessionParams,
      { "sessionParams", "h235.sessionParams",
        FT_NONE, BASE_NONE, NULL, 0,
        "SrtpCryptoInfo/sessionParams", HFILL }},
    { &hf_h235_allowMKI,
      { "allowMKI", "h235.allowMKI",
        FT_BOOLEAN, 8, NULL, 0,
        "SrtpCryptoInfo/allowMKI", HFILL }},
    { &hf_h235_SrtpKeys_item,
      { "Item", "h235.SrtpKeys_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SrtpKeys/_item", HFILL }},
    { &hf_h235_masterKey,
      { "masterKey", "h235.masterKey",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SrtpKeyParameters/masterKey", HFILL }},
    { &hf_h235_masterSalt,
      { "masterSalt", "h235.masterSalt",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SrtpKeyParameters/masterSalt", HFILL }},
    { &hf_h235_lifetime,
      { "lifetime", "h235.lifetime",
        FT_UINT32, BASE_DEC, VALS(h235_T_lifetime_vals), 0,
        "SrtpKeyParameters/lifetime", HFILL }},
    { &hf_h235_powerOfTwo,
      { "powerOfTwo", "h235.powerOfTwo",
        FT_INT32, BASE_DEC, NULL, 0,
        "SrtpKeyParameters/lifetime/powerOfTwo", HFILL }},
    { &hf_h235_specific,
      { "specific", "h235.specific",
        FT_INT32, BASE_DEC, NULL, 0,
        "SrtpKeyParameters/lifetime/specific", HFILL }},
    { &hf_h235_mki,
      { "mki", "h235.mki",
        FT_NONE, BASE_NONE, NULL, 0,
        "SrtpKeyParameters/mki", HFILL }},
    { &hf_h235_length,
      { "length", "h235.length",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SrtpKeyParameters/mki/length", HFILL }},
    { &hf_h235_value,
      { "value", "h235.value",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SrtpKeyParameters/mki/value", HFILL }},
    { &hf_h235_kdr,
      { "kdr", "h235.kdr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SrtpSessionParameters/kdr", HFILL }},
    { &hf_h235_unencryptedSrtp,
      { "unencryptedSrtp", "h235.unencryptedSrtp",
        FT_BOOLEAN, 8, NULL, 0,
        "SrtpSessionParameters/unencryptedSrtp", HFILL }},
    { &hf_h235_unencryptedSrtcp,
      { "unencryptedSrtcp", "h235.unencryptedSrtcp",
        FT_BOOLEAN, 8, NULL, 0,
        "SrtpSessionParameters/unencryptedSrtcp", HFILL }},
    { &hf_h235_unauthenticatedSrtp,
      { "unauthenticatedSrtp", "h235.unauthenticatedSrtp",
        FT_BOOLEAN, 8, NULL, 0,
        "SrtpSessionParameters/unauthenticatedSrtp", HFILL }},
    { &hf_h235_fecOrder,
      { "fecOrder", "h235.fecOrder",
        FT_NONE, BASE_NONE, NULL, 0,
        "SrtpSessionParameters/fecOrder", HFILL }},
    { &hf_h235_windowSizeHint,
      { "windowSizeHint", "h235.windowSizeHint",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SrtpSessionParameters/windowSizeHint", HFILL }},
    { &hf_h235_newParameter,
      { "newParameter", "h235.newParameter",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SrtpSessionParameters/newParameter", HFILL }},
    { &hf_h235_newParameter_item,
      { "Item", "h235.newParameter_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SrtpSessionParameters/newParameter/_item", HFILL }},
    { &hf_h235_fecBeforeSrtp,
      { "fecBeforeSrtp", "h235.fecBeforeSrtp",
        FT_NONE, BASE_NONE, NULL, 0,
        "FecOrder/fecBeforeSrtp", HFILL }},
    { &hf_h235_fecAfterSrtp,
      { "fecAfterSrtp", "h235.fecAfterSrtp",
        FT_NONE, BASE_NONE, NULL, 0,
        "FecOrder/fecAfterSrtp", HFILL }},

/*--- End of included file: packet-h235-hfarr.c ---*/
#line 68 "packet-h235-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-h235-ettarr.c ---*/
#line 1 "packet-h235-ettarr.c"
    &ett_h235_NonStandardParameter,
    &ett_h235_DHset,
    &ett_h235_ECpoint,
    &ett_h235_ECKASDH,
    &ett_h235_T_eckasdhp,
    &ett_h235_T_eckasdh2,
    &ett_h235_TypedCertificate,
    &ett_h235_AuthenticationBES,
    &ett_h235_AuthenticationMechanism,
    &ett_h235_ClearToken,
    &ett_h235_SEQUENCE_OF_ProfileElement,
    &ett_h235_ProfileElement,
    &ett_h235_Element,
    &ett_h235_SIGNEDxxx,
    &ett_h235_ENCRYPTEDxxx,
    &ett_h235_HASHEDxxx,
    &ett_h235_Params,
    &ett_h235_CryptoToken,
    &ett_h235_T_cryptoEncryptedToken,
    &ett_h235_T_cryptoSignedToken,
    &ett_h235_T_cryptoHashedToken,
    &ett_h235_H235Key,
    &ett_h235_KeySignedMaterial,
    &ett_h235_ReturnSig,
    &ett_h235_KeySyncMaterial,
    &ett_h235_V3KeySyncMaterial,
    &ett_h235_SrtpCryptoCapability,
    &ett_h235_SrtpCryptoInfo,
    &ett_h235_SrtpKeys,
    &ett_h235_SrtpKeyParameters,
    &ett_h235_T_lifetime,
    &ett_h235_T_mki,
    &ett_h235_SrtpSessionParameters,
    &ett_h235_SEQUENCE_OF_GenericData,
    &ett_h235_FecOrder,

/*--- End of included file: packet-h235-ettarr.c ---*/
#line 73 "packet-h235-template.c"
  };

  /* Register protocol */
  proto_h235 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_h235, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* OID names */
  /* H.235.1, Chapter 15, Table 3 */
    /* A */
    add_oid_str_name("0.0.8.235.0.1.1","itu-t(0) recommendation(0) h(8) 235 version(0) 1 1 - all fields in RAS/CS");
    add_oid_str_name("0.0.8.235.0.2.1","itu-t(0) recommendation(0) h(8) 235 version(0) 2 1 - all fields in RAS/CS");
    /* T */
    add_oid_str_name("0.0.8.235.0.1.5","itu-t(0) recommendation(0) h(8) 235 version(0) 1 5 - ClearToken");
    add_oid_str_name("0.0.8.235.0.2.5","itu-t(0) recommendation(0) h(8) 235 version(0) 2 5 - ClearToken");
    /* U */
    add_oid_str_name("0.0.8.235.0.1.6","itu-t(0) recommendation(0) h(8) 235 version(0) 1 6 - HMAC-SHA1-96");
    add_oid_str_name("0.0.8.235.0.2.6","itu-t(0) recommendation(0) h(8) 235 version(0) 2 6 - HMAC-SHA1-96");
}


/*--- proto_reg_handoff_h235 -------------------------------------------*/
void proto_reg_handoff_h235(void) {
}

