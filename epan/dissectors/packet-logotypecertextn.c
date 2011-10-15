/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-logotypecertextn.c                                                  */
/* ../../tools/asn2wrs.py -b -p logotypecertextn -c ./logotypecertextn.cnf -s ./packet-logotypecertextn-template -D . -O ../../epan/dissectors LogotypeCertExtn.asn */

/* Input file: packet-logotypecertextn-template.c */

#line 1 "../../asn1/logotypecertextn/packet-logotypecertextn-template.c"
/* packet-logotypecertextn.c
 * Routines for RFC3709 Logotype Certificate Extensions packet dissection
 *   Ronnie Sahlberg 2004
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

#include "packet-ber.h"
#include "packet-logotypecertextn.h"
#include "packet-x509af.h"

#define PNAME  "Logotype Certificate Extensions"
#define PSNAME "LogotypeCertExtn"
#define PFNAME "logotypecertextn"

/* Initialize the protocol and registered fields */
static int proto_logotypecertextn = -1;

/*--- Included file: packet-logotypecertextn-hf.c ---*/
#line 1 "../../asn1/logotypecertextn/packet-logotypecertextn-hf.c"
static int hf_logotypecertextn_LogotypeExtn_PDU = -1;  /* LogotypeExtn */
static int hf_logotypecertextn_communityLogos = -1;  /* SEQUENCE_OF_LogotypeInfo */
static int hf_logotypecertextn_communityLogos_item = -1;  /* LogotypeInfo */
static int hf_logotypecertextn_issuerLogo = -1;   /* LogotypeInfo */
static int hf_logotypecertextn_subjectLogo = -1;  /* LogotypeInfo */
static int hf_logotypecertextn_otherLogos = -1;   /* SEQUENCE_OF_OtherLogotypeInfo */
static int hf_logotypecertextn_otherLogos_item = -1;  /* OtherLogotypeInfo */
static int hf_logotypecertextn_direct = -1;       /* LogotypeData */
static int hf_logotypecertextn_indirect = -1;     /* LogotypeReference */
static int hf_logotypecertextn_image = -1;        /* SEQUENCE_OF_LogotypeImage */
static int hf_logotypecertextn_image_item = -1;   /* LogotypeImage */
static int hf_logotypecertextn_audio = -1;        /* SEQUENCE_OF_LogotypeAudio */
static int hf_logotypecertextn_audio_item = -1;   /* LogotypeAudio */
static int hf_logotypecertextn_imageDetails = -1;  /* LogotypeDetails */
static int hf_logotypecertextn_imageInfo = -1;    /* LogotypeImageInfo */
static int hf_logotypecertextn_audioDetails = -1;  /* LogotypeDetails */
static int hf_logotypecertextn_audioInfo = -1;    /* LogotypeAudioInfo */
static int hf_logotypecertextn_mediaType = -1;    /* IA5String */
static int hf_logotypecertextn_logotypeHash = -1;  /* SEQUENCE_SIZE_1_MAX_OF_HashAlgAndValue */
static int hf_logotypecertextn_logotypeHash_item = -1;  /* HashAlgAndValue */
static int hf_logotypecertextn_logotypeURI = -1;  /* T_logotypeURI */
static int hf_logotypecertextn_logotypeURI_item = -1;  /* T_logotypeURI_item */
static int hf_logotypecertextn_type = -1;         /* LogotypeImageType */
static int hf_logotypecertextn_fileSize = -1;     /* INTEGER */
static int hf_logotypecertextn_xSize = -1;        /* INTEGER */
static int hf_logotypecertextn_ySize = -1;        /* INTEGER */
static int hf_logotypecertextn_resolution = -1;   /* LogotypeImageResolution */
static int hf_logotypecertextn_language = -1;     /* IA5String */
static int hf_logotypecertextn_numBits = -1;      /* INTEGER */
static int hf_logotypecertextn_tableSize = -1;    /* INTEGER */
static int hf_logotypecertextn_playTime = -1;     /* INTEGER */
static int hf_logotypecertextn_channels = -1;     /* INTEGER */
static int hf_logotypecertextn_sampleRate = -1;   /* INTEGER */
static int hf_logotypecertextn_logotypeType = -1;  /* OBJECT_IDENTIFIER */
static int hf_logotypecertextn_info = -1;         /* LogotypeInfo */
static int hf_logotypecertextn_refStructHash = -1;  /* SEQUENCE_SIZE_1_MAX_OF_HashAlgAndValue */
static int hf_logotypecertextn_refStructHash_item = -1;  /* HashAlgAndValue */
static int hf_logotypecertextn_refStructURI = -1;  /* T_refStructURI */
static int hf_logotypecertextn_refStructURI_item = -1;  /* T_refStructURI_item */
static int hf_logotypecertextn_hashAlg = -1;      /* AlgorithmIdentifier */
static int hf_logotypecertextn_hashValue = -1;    /* OCTET_STRING */

/*--- End of included file: packet-logotypecertextn-hf.c ---*/
#line 44 "../../asn1/logotypecertextn/packet-logotypecertextn-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-logotypecertextn-ett.c ---*/
#line 1 "../../asn1/logotypecertextn/packet-logotypecertextn-ett.c"
static gint ett_logotypecertextn_LogotypeExtn = -1;
static gint ett_logotypecertextn_SEQUENCE_OF_LogotypeInfo = -1;
static gint ett_logotypecertextn_SEQUENCE_OF_OtherLogotypeInfo = -1;
static gint ett_logotypecertextn_LogotypeInfo = -1;
static gint ett_logotypecertextn_LogotypeData = -1;
static gint ett_logotypecertextn_SEQUENCE_OF_LogotypeImage = -1;
static gint ett_logotypecertextn_SEQUENCE_OF_LogotypeAudio = -1;
static gint ett_logotypecertextn_LogotypeImage = -1;
static gint ett_logotypecertextn_LogotypeAudio = -1;
static gint ett_logotypecertextn_LogotypeDetails = -1;
static gint ett_logotypecertextn_SEQUENCE_SIZE_1_MAX_OF_HashAlgAndValue = -1;
static gint ett_logotypecertextn_T_logotypeURI = -1;
static gint ett_logotypecertextn_LogotypeImageInfo = -1;
static gint ett_logotypecertextn_LogotypeImageResolution = -1;
static gint ett_logotypecertextn_LogotypeAudioInfo = -1;
static gint ett_logotypecertextn_OtherLogotypeInfo = -1;
static gint ett_logotypecertextn_LogotypeReference = -1;
static gint ett_logotypecertextn_T_refStructURI = -1;
static gint ett_logotypecertextn_HashAlgAndValue = -1;

/*--- End of included file: packet-logotypecertextn-ett.c ---*/
#line 47 "../../asn1/logotypecertextn/packet-logotypecertextn-template.c"



/*--- Included file: packet-logotypecertextn-fn.c ---*/
#line 1 "../../asn1/logotypecertextn/packet-logotypecertextn-fn.c"


static int
dissect_logotypecertextn_IA5String(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_logotypecertextn_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t HashAlgAndValue_sequence[] = {
  { &hf_logotypecertextn_hashAlg, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_logotypecertextn_hashValue, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_logotypecertextn_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_logotypecertextn_HashAlgAndValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   HashAlgAndValue_sequence, hf_index, ett_logotypecertextn_HashAlgAndValue);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_HashAlgAndValue_sequence_of[1] = {
  { &hf_logotypecertextn_logotypeHash_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_logotypecertextn_HashAlgAndValue },
};

static int
dissect_logotypecertextn_SEQUENCE_SIZE_1_MAX_OF_HashAlgAndValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_HashAlgAndValue_sequence_of, hf_index, ett_logotypecertextn_SEQUENCE_SIZE_1_MAX_OF_HashAlgAndValue);

  return offset;
}



static int
dissect_logotypecertextn_T_logotypeURI_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

#line 18 "../../asn1/logotypecertextn/logotypecertextn.cnf"
	   PROTO_ITEM_SET_URL(actx->created_item);


  return offset;
}


static const ber_sequence_t T_logotypeURI_sequence_of[1] = {
  { &hf_logotypecertextn_logotypeURI_item, BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_logotypecertextn_T_logotypeURI_item },
};

static int
dissect_logotypecertextn_T_logotypeURI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_logotypeURI_sequence_of, hf_index, ett_logotypecertextn_T_logotypeURI);

  return offset;
}


static const ber_sequence_t LogotypeDetails_sequence[] = {
  { &hf_logotypecertextn_mediaType, BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_logotypecertextn_IA5String },
  { &hf_logotypecertextn_logotypeHash, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_logotypecertextn_SEQUENCE_SIZE_1_MAX_OF_HashAlgAndValue },
  { &hf_logotypecertextn_logotypeURI, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_logotypecertextn_T_logotypeURI },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_logotypecertextn_LogotypeDetails(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LogotypeDetails_sequence, hf_index, ett_logotypecertextn_LogotypeDetails);

  return offset;
}


static const value_string logotypecertextn_LogotypeImageType_vals[] = {
  {   0, "grayScale" },
  {   1, "color" },
  { 0, NULL }
};


static int
dissect_logotypecertextn_LogotypeImageType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_logotypecertextn_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string logotypecertextn_LogotypeImageResolution_vals[] = {
  {   1, "numBits" },
  {   2, "tableSize" },
  { 0, NULL }
};

static const ber_choice_t LogotypeImageResolution_choice[] = {
  {   1, &hf_logotypecertextn_numBits, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_logotypecertextn_INTEGER },
  {   2, &hf_logotypecertextn_tableSize, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_logotypecertextn_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_logotypecertextn_LogotypeImageResolution(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 LogotypeImageResolution_choice, hf_index, ett_logotypecertextn_LogotypeImageResolution,
                                 NULL);

  return offset;
}


static const ber_sequence_t LogotypeImageInfo_sequence[] = {
  { &hf_logotypecertextn_type, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_logotypecertextn_LogotypeImageType },
  { &hf_logotypecertextn_fileSize, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_logotypecertextn_INTEGER },
  { &hf_logotypecertextn_xSize, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_logotypecertextn_INTEGER },
  { &hf_logotypecertextn_ySize, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_logotypecertextn_INTEGER },
  { &hf_logotypecertextn_resolution, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_logotypecertextn_LogotypeImageResolution },
  { &hf_logotypecertextn_language, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_logotypecertextn_IA5String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_logotypecertextn_LogotypeImageInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LogotypeImageInfo_sequence, hf_index, ett_logotypecertextn_LogotypeImageInfo);

  return offset;
}


static const ber_sequence_t LogotypeImage_sequence[] = {
  { &hf_logotypecertextn_imageDetails, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_logotypecertextn_LogotypeDetails },
  { &hf_logotypecertextn_imageInfo, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_logotypecertextn_LogotypeImageInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_logotypecertextn_LogotypeImage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LogotypeImage_sequence, hf_index, ett_logotypecertextn_LogotypeImage);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_LogotypeImage_sequence_of[1] = {
  { &hf_logotypecertextn_image_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_logotypecertextn_LogotypeImage },
};

static int
dissect_logotypecertextn_SEQUENCE_OF_LogotypeImage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_LogotypeImage_sequence_of, hf_index, ett_logotypecertextn_SEQUENCE_OF_LogotypeImage);

  return offset;
}


static const ber_sequence_t LogotypeAudioInfo_sequence[] = {
  { &hf_logotypecertextn_fileSize, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_logotypecertextn_INTEGER },
  { &hf_logotypecertextn_playTime, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_logotypecertextn_INTEGER },
  { &hf_logotypecertextn_channels, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_logotypecertextn_INTEGER },
  { &hf_logotypecertextn_sampleRate, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_logotypecertextn_INTEGER },
  { &hf_logotypecertextn_language, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_logotypecertextn_IA5String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_logotypecertextn_LogotypeAudioInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LogotypeAudioInfo_sequence, hf_index, ett_logotypecertextn_LogotypeAudioInfo);

  return offset;
}


static const ber_sequence_t LogotypeAudio_sequence[] = {
  { &hf_logotypecertextn_audioDetails, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_logotypecertextn_LogotypeDetails },
  { &hf_logotypecertextn_audioInfo, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_logotypecertextn_LogotypeAudioInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_logotypecertextn_LogotypeAudio(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LogotypeAudio_sequence, hf_index, ett_logotypecertextn_LogotypeAudio);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_LogotypeAudio_sequence_of[1] = {
  { &hf_logotypecertextn_audio_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_logotypecertextn_LogotypeAudio },
};

static int
dissect_logotypecertextn_SEQUENCE_OF_LogotypeAudio(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_LogotypeAudio_sequence_of, hf_index, ett_logotypecertextn_SEQUENCE_OF_LogotypeAudio);

  return offset;
}


static const ber_sequence_t LogotypeData_sequence[] = {
  { &hf_logotypecertextn_image, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_logotypecertextn_SEQUENCE_OF_LogotypeImage },
  { &hf_logotypecertextn_audio, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_logotypecertextn_SEQUENCE_OF_LogotypeAudio },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_logotypecertextn_LogotypeData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LogotypeData_sequence, hf_index, ett_logotypecertextn_LogotypeData);

  return offset;
}



static int
dissect_logotypecertextn_T_refStructURI_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

#line 21 "../../asn1/logotypecertextn/logotypecertextn.cnf"
	   PROTO_ITEM_SET_URL(actx->created_item);


  return offset;
}


static const ber_sequence_t T_refStructURI_sequence_of[1] = {
  { &hf_logotypecertextn_refStructURI_item, BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_logotypecertextn_T_refStructURI_item },
};

static int
dissect_logotypecertextn_T_refStructURI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_refStructURI_sequence_of, hf_index, ett_logotypecertextn_T_refStructURI);

  return offset;
}


static const ber_sequence_t LogotypeReference_sequence[] = {
  { &hf_logotypecertextn_refStructHash, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_logotypecertextn_SEQUENCE_SIZE_1_MAX_OF_HashAlgAndValue },
  { &hf_logotypecertextn_refStructURI, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_logotypecertextn_T_refStructURI },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_logotypecertextn_LogotypeReference(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LogotypeReference_sequence, hf_index, ett_logotypecertextn_LogotypeReference);

  return offset;
}


static const value_string logotypecertextn_LogotypeInfo_vals[] = {
  {   0, "direct" },
  {   1, "indirect" },
  { 0, NULL }
};

static const ber_choice_t LogotypeInfo_choice[] = {
  {   0, &hf_logotypecertextn_direct, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_logotypecertextn_LogotypeData },
  {   1, &hf_logotypecertextn_indirect, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_logotypecertextn_LogotypeReference },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_logotypecertextn_LogotypeInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 LogotypeInfo_choice, hf_index, ett_logotypecertextn_LogotypeInfo,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_LogotypeInfo_sequence_of[1] = {
  { &hf_logotypecertextn_communityLogos_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_logotypecertextn_LogotypeInfo },
};

static int
dissect_logotypecertextn_SEQUENCE_OF_LogotypeInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_LogotypeInfo_sequence_of, hf_index, ett_logotypecertextn_SEQUENCE_OF_LogotypeInfo);

  return offset;
}



static int
dissect_logotypecertextn_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t OtherLogotypeInfo_sequence[] = {
  { &hf_logotypecertextn_logotypeType, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_logotypecertextn_OBJECT_IDENTIFIER },
  { &hf_logotypecertextn_info, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_logotypecertextn_LogotypeInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_logotypecertextn_OtherLogotypeInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OtherLogotypeInfo_sequence, hf_index, ett_logotypecertextn_OtherLogotypeInfo);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_OtherLogotypeInfo_sequence_of[1] = {
  { &hf_logotypecertextn_otherLogos_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_logotypecertextn_OtherLogotypeInfo },
};

static int
dissect_logotypecertextn_SEQUENCE_OF_OtherLogotypeInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_OtherLogotypeInfo_sequence_of, hf_index, ett_logotypecertextn_SEQUENCE_OF_OtherLogotypeInfo);

  return offset;
}


static const ber_sequence_t LogotypeExtn_sequence[] = {
  { &hf_logotypecertextn_communityLogos, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_logotypecertextn_SEQUENCE_OF_LogotypeInfo },
  { &hf_logotypecertextn_issuerLogo, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_logotypecertextn_LogotypeInfo },
  { &hf_logotypecertextn_subjectLogo, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_logotypecertextn_LogotypeInfo },
  { &hf_logotypecertextn_otherLogos, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_logotypecertextn_SEQUENCE_OF_OtherLogotypeInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_logotypecertextn_LogotypeExtn(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LogotypeExtn_sequence, hf_index, ett_logotypecertextn_LogotypeExtn);

  return offset;
}

/*--- PDUs ---*/

static void dissect_LogotypeExtn_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_logotypecertextn_LogotypeExtn(FALSE, tvb, 0, &asn1_ctx, tree, hf_logotypecertextn_LogotypeExtn_PDU);
}


/*--- End of included file: packet-logotypecertextn-fn.c ---*/
#line 50 "../../asn1/logotypecertextn/packet-logotypecertextn-template.c"


/*--- proto_register_logotypecertextn ----------------------------------------------*/
void proto_register_logotypecertextn(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-logotypecertextn-hfarr.c ---*/
#line 1 "../../asn1/logotypecertextn/packet-logotypecertextn-hfarr.c"
    { &hf_logotypecertextn_LogotypeExtn_PDU,
      { "LogotypeExtn", "logotypecertextn.LogotypeExtn",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_logotypecertextn_communityLogos,
      { "communityLogos", "logotypecertextn.communityLogos",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_LogotypeInfo", HFILL }},
    { &hf_logotypecertextn_communityLogos_item,
      { "LogotypeInfo", "logotypecertextn.LogotypeInfo",
        FT_UINT32, BASE_DEC, VALS(logotypecertextn_LogotypeInfo_vals), 0,
        NULL, HFILL }},
    { &hf_logotypecertextn_issuerLogo,
      { "issuerLogo", "logotypecertextn.issuerLogo",
        FT_UINT32, BASE_DEC, VALS(logotypecertextn_LogotypeInfo_vals), 0,
        "LogotypeInfo", HFILL }},
    { &hf_logotypecertextn_subjectLogo,
      { "subjectLogo", "logotypecertextn.subjectLogo",
        FT_UINT32, BASE_DEC, VALS(logotypecertextn_LogotypeInfo_vals), 0,
        "LogotypeInfo", HFILL }},
    { &hf_logotypecertextn_otherLogos,
      { "otherLogos", "logotypecertextn.otherLogos",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_OtherLogotypeInfo", HFILL }},
    { &hf_logotypecertextn_otherLogos_item,
      { "OtherLogotypeInfo", "logotypecertextn.OtherLogotypeInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_logotypecertextn_direct,
      { "direct", "logotypecertextn.direct",
        FT_NONE, BASE_NONE, NULL, 0,
        "LogotypeData", HFILL }},
    { &hf_logotypecertextn_indirect,
      { "indirect", "logotypecertextn.indirect",
        FT_NONE, BASE_NONE, NULL, 0,
        "LogotypeReference", HFILL }},
    { &hf_logotypecertextn_image,
      { "image", "logotypecertextn.image",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_LogotypeImage", HFILL }},
    { &hf_logotypecertextn_image_item,
      { "LogotypeImage", "logotypecertextn.LogotypeImage",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_logotypecertextn_audio,
      { "audio", "logotypecertextn.audio",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_LogotypeAudio", HFILL }},
    { &hf_logotypecertextn_audio_item,
      { "LogotypeAudio", "logotypecertextn.LogotypeAudio",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_logotypecertextn_imageDetails,
      { "imageDetails", "logotypecertextn.imageDetails",
        FT_NONE, BASE_NONE, NULL, 0,
        "LogotypeDetails", HFILL }},
    { &hf_logotypecertextn_imageInfo,
      { "imageInfo", "logotypecertextn.imageInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "LogotypeImageInfo", HFILL }},
    { &hf_logotypecertextn_audioDetails,
      { "audioDetails", "logotypecertextn.audioDetails",
        FT_NONE, BASE_NONE, NULL, 0,
        "LogotypeDetails", HFILL }},
    { &hf_logotypecertextn_audioInfo,
      { "audioInfo", "logotypecertextn.audioInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "LogotypeAudioInfo", HFILL }},
    { &hf_logotypecertextn_mediaType,
      { "mediaType", "logotypecertextn.mediaType",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String", HFILL }},
    { &hf_logotypecertextn_logotypeHash,
      { "logotypeHash", "logotypecertextn.logotypeHash",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_HashAlgAndValue", HFILL }},
    { &hf_logotypecertextn_logotypeHash_item,
      { "HashAlgAndValue", "logotypecertextn.HashAlgAndValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_logotypecertextn_logotypeURI,
      { "logotypeURI", "logotypecertextn.logotypeURI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_logotypecertextn_logotypeURI_item,
      { "logotypeURI item", "logotypecertextn.logotypeURI_item",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_logotypecertextn_type,
      { "type", "logotypecertextn.type",
        FT_INT32, BASE_DEC, VALS(logotypecertextn_LogotypeImageType_vals), 0,
        "LogotypeImageType", HFILL }},
    { &hf_logotypecertextn_fileSize,
      { "fileSize", "logotypecertextn.fileSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_logotypecertextn_xSize,
      { "xSize", "logotypecertextn.xSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_logotypecertextn_ySize,
      { "ySize", "logotypecertextn.ySize",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_logotypecertextn_resolution,
      { "resolution", "logotypecertextn.resolution",
        FT_UINT32, BASE_DEC, VALS(logotypecertextn_LogotypeImageResolution_vals), 0,
        "LogotypeImageResolution", HFILL }},
    { &hf_logotypecertextn_language,
      { "language", "logotypecertextn.language",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String", HFILL }},
    { &hf_logotypecertextn_numBits,
      { "numBits", "logotypecertextn.numBits",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_logotypecertextn_tableSize,
      { "tableSize", "logotypecertextn.tableSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_logotypecertextn_playTime,
      { "playTime", "logotypecertextn.playTime",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_logotypecertextn_channels,
      { "channels", "logotypecertextn.channels",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_logotypecertextn_sampleRate,
      { "sampleRate", "logotypecertextn.sampleRate",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_logotypecertextn_logotypeType,
      { "logotypeType", "logotypecertextn.logotypeType",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_logotypecertextn_info,
      { "info", "logotypecertextn.info",
        FT_UINT32, BASE_DEC, VALS(logotypecertextn_LogotypeInfo_vals), 0,
        "LogotypeInfo", HFILL }},
    { &hf_logotypecertextn_refStructHash,
      { "refStructHash", "logotypecertextn.refStructHash",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_HashAlgAndValue", HFILL }},
    { &hf_logotypecertextn_refStructHash_item,
      { "HashAlgAndValue", "logotypecertextn.HashAlgAndValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_logotypecertextn_refStructURI,
      { "refStructURI", "logotypecertextn.refStructURI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_logotypecertextn_refStructURI_item,
      { "refStructURI item", "logotypecertextn.refStructURI_item",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_logotypecertextn_hashAlg,
      { "hashAlg", "logotypecertextn.hashAlg",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_logotypecertextn_hashValue,
      { "hashValue", "logotypecertextn.hashValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},

/*--- End of included file: packet-logotypecertextn-hfarr.c ---*/
#line 58 "../../asn1/logotypecertextn/packet-logotypecertextn-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-logotypecertextn-ettarr.c ---*/
#line 1 "../../asn1/logotypecertextn/packet-logotypecertextn-ettarr.c"
    &ett_logotypecertextn_LogotypeExtn,
    &ett_logotypecertextn_SEQUENCE_OF_LogotypeInfo,
    &ett_logotypecertextn_SEQUENCE_OF_OtherLogotypeInfo,
    &ett_logotypecertextn_LogotypeInfo,
    &ett_logotypecertextn_LogotypeData,
    &ett_logotypecertextn_SEQUENCE_OF_LogotypeImage,
    &ett_logotypecertextn_SEQUENCE_OF_LogotypeAudio,
    &ett_logotypecertextn_LogotypeImage,
    &ett_logotypecertextn_LogotypeAudio,
    &ett_logotypecertextn_LogotypeDetails,
    &ett_logotypecertextn_SEQUENCE_SIZE_1_MAX_OF_HashAlgAndValue,
    &ett_logotypecertextn_T_logotypeURI,
    &ett_logotypecertextn_LogotypeImageInfo,
    &ett_logotypecertextn_LogotypeImageResolution,
    &ett_logotypecertextn_LogotypeAudioInfo,
    &ett_logotypecertextn_OtherLogotypeInfo,
    &ett_logotypecertextn_LogotypeReference,
    &ett_logotypecertextn_T_refStructURI,
    &ett_logotypecertextn_HashAlgAndValue,

/*--- End of included file: packet-logotypecertextn-ettarr.c ---*/
#line 63 "../../asn1/logotypecertextn/packet-logotypecertextn-template.c"
  };

  /* Register protocol */
  proto_logotypecertextn = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_logotypecertextn, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_logotypecertextn -------------------------------------------*/
void proto_reg_handoff_logotypecertextn(void) {

/*--- Included file: packet-logotypecertextn-dis-tab.c ---*/
#line 1 "../../asn1/logotypecertextn/packet-logotypecertextn-dis-tab.c"
  register_ber_oid_dissector("1.3.6.1.5.5.7.1.12", dissect_LogotypeExtn_PDU, proto_logotypecertextn, "id-pe-logotype");
  register_ber_oid_dissector("1.3.6.1.5.5.7.20.1", dissect_LogotypeExtn_PDU, proto_logotypecertextn, "id-pe-logo-loyalty");
  register_ber_oid_dissector("1.3.6.1.5.5.7.20.2", dissect_LogotypeExtn_PDU, proto_logotypecertextn, "id-pe-logo-background");


/*--- End of included file: packet-logotypecertextn-dis-tab.c ---*/
#line 78 "../../asn1/logotypecertextn/packet-logotypecertextn-template.c"
}

