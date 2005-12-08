/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* ./packet-logotypecertextn.c                                                */
/* ../../tools/asn2eth.py -X -b -e -p logotypecertextn -c logotype-cert-extn.cnf -s packet-logotype-cert-extn-template LogotypeCertExtn.asn */

/* Input file: packet-logotype-cert-extn-template.c */

#line 1 "packet-logotype-cert-extn-template.c"
/* packet-logotype-cert-extn.c
 * Routines for RFC3709 Logotype Certificate Extensions packet dissection
 *   Ronnie Sahlberg 2004
 *
 * $Id$
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

#include <glib.h>
#include <epan/packet.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-logotypecertextn.h"
#include "packet-x509af.h"

#define PNAME  "Logotype Certificate Extensions"
#define PSNAME "LogotypeCertExtn"
#define PFNAME "logotypecertextn"

/* Initialize the protocol and registered fields */
static int proto_logotypecertextn = -1;

/*--- Included file: packet-logotypecertextn-hf.c ---*/
#line 1 "packet-logotypecertextn-hf.c"
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
static int hf_logotypecertextn_logotypeURI_item = -1;  /* IA5String */
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
static int hf_logotypecertextn_refStructURI_item = -1;  /* IA5String */
static int hf_logotypecertextn_hashAlg = -1;      /* AlgorithmIdentifier */
static int hf_logotypecertextn_hashValue = -1;    /* OCTET_STRING */

/*--- End of included file: packet-logotypecertextn-hf.c ---*/
#line 47 "packet-logotype-cert-extn-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-logotypecertextn-ett.c ---*/
#line 1 "packet-logotypecertextn-ett.c"
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
#line 50 "packet-logotype-cert-extn-template.c"



/*--- Included file: packet-logotypecertextn-fn.c ---*/
#line 1 "packet-logotypecertextn-fn.c"
/*--- Fields for imported types ---*/

static int dissect_hashAlg(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_hashAlg);
}



static int
dissect_logotypecertextn_IA5String(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_mediaType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_IA5String(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_mediaType);
}
static int dissect_logotypeURI_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_IA5String(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_logotypeURI_item);
}
static int dissect_language_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_IA5String(TRUE, tvb, offset, pinfo, tree, hf_logotypecertextn_language);
}
static int dissect_refStructURI_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_IA5String(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_refStructURI_item);
}



static int
dissect_logotypecertextn_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_hashValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_hashValue);
}


static const ber_sequence_t HashAlgAndValue_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_hashAlg },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_hashValue },
  { 0, 0, 0, NULL }
};

static int
dissect_logotypecertextn_HashAlgAndValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   HashAlgAndValue_sequence, hf_index, ett_logotypecertextn_HashAlgAndValue);

  return offset;
}
static int dissect_logotypeHash_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_HashAlgAndValue(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_logotypeHash_item);
}
static int dissect_refStructHash_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_HashAlgAndValue(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_refStructHash_item);
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_HashAlgAndValue_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_logotypeHash_item },
};

static int
dissect_logotypecertextn_SEQUENCE_SIZE_1_MAX_OF_HashAlgAndValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_HashAlgAndValue_sequence_of, hf_index, ett_logotypecertextn_SEQUENCE_SIZE_1_MAX_OF_HashAlgAndValue);

  return offset;
}
static int dissect_logotypeHash(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_SEQUENCE_SIZE_1_MAX_OF_HashAlgAndValue(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_logotypeHash);
}
static int dissect_refStructHash(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_SEQUENCE_SIZE_1_MAX_OF_HashAlgAndValue(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_refStructHash);
}


static const ber_sequence_t T_logotypeURI_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_logotypeURI_item },
};

static int
dissect_logotypecertextn_T_logotypeURI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_logotypeURI_sequence_of, hf_index, ett_logotypecertextn_T_logotypeURI);

  return offset;
}
static int dissect_logotypeURI(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_T_logotypeURI(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_logotypeURI);
}


static const ber_sequence_t LogotypeDetails_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_mediaType },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_logotypeHash },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_logotypeURI },
  { 0, 0, 0, NULL }
};

static int
dissect_logotypecertextn_LogotypeDetails(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LogotypeDetails_sequence, hf_index, ett_logotypecertextn_LogotypeDetails);

  return offset;
}
static int dissect_imageDetails(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_LogotypeDetails(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_imageDetails);
}
static int dissect_audioDetails(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_LogotypeDetails(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_audioDetails);
}


static const value_string logotypecertextn_LogotypeImageType_vals[] = {
  {   0, "grayScale" },
  {   1, "color" },
  { 0, NULL }
};


static int
dissect_logotypecertextn_LogotypeImageType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_type_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_LogotypeImageType(TRUE, tvb, offset, pinfo, tree, hf_logotypecertextn_type);
}



static int
dissect_logotypecertextn_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_fileSize(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_fileSize);
}
static int dissect_xSize(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_xSize);
}
static int dissect_ySize(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_ySize);
}
static int dissect_numBits_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_logotypecertextn_numBits);
}
static int dissect_tableSize_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_logotypecertextn_tableSize);
}
static int dissect_playTime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_playTime);
}
static int dissect_channels(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_channels);
}
static int dissect_sampleRate_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_logotypecertextn_sampleRate);
}


static const value_string logotypecertextn_LogotypeImageResolution_vals[] = {
  {   1, "numBits" },
  {   2, "tableSize" },
  { 0, NULL }
};

static const ber_choice_t LogotypeImageResolution_choice[] = {
  {   1, BER_CLASS_CON, 1, 0, dissect_numBits_impl },
  {   2, BER_CLASS_CON, 2, 0, dissect_tableSize_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_logotypecertextn_LogotypeImageResolution(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 LogotypeImageResolution_choice, hf_index, ett_logotypecertextn_LogotypeImageResolution,
                                 NULL);

  return offset;
}
static int dissect_resolution(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_LogotypeImageResolution(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_resolution);
}


static const ber_sequence_t LogotypeImageInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_type_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_fileSize },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_xSize },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_ySize },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_resolution },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_language_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_logotypecertextn_LogotypeImageInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LogotypeImageInfo_sequence, hf_index, ett_logotypecertextn_LogotypeImageInfo);

  return offset;
}
static int dissect_imageInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_LogotypeImageInfo(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_imageInfo);
}


static const ber_sequence_t LogotypeImage_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_imageDetails },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_imageInfo },
  { 0, 0, 0, NULL }
};

static int
dissect_logotypecertextn_LogotypeImage(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LogotypeImage_sequence, hf_index, ett_logotypecertextn_LogotypeImage);

  return offset;
}
static int dissect_image_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_LogotypeImage(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_image_item);
}


static const ber_sequence_t SEQUENCE_OF_LogotypeImage_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_image_item },
};

static int
dissect_logotypecertextn_SEQUENCE_OF_LogotypeImage(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_LogotypeImage_sequence_of, hf_index, ett_logotypecertextn_SEQUENCE_OF_LogotypeImage);

  return offset;
}
static int dissect_image(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_SEQUENCE_OF_LogotypeImage(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_image);
}


static const ber_sequence_t LogotypeAudioInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_fileSize },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_playTime },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_channels },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sampleRate_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_language_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_logotypecertextn_LogotypeAudioInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LogotypeAudioInfo_sequence, hf_index, ett_logotypecertextn_LogotypeAudioInfo);

  return offset;
}
static int dissect_audioInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_LogotypeAudioInfo(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_audioInfo);
}


static const ber_sequence_t LogotypeAudio_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_audioDetails },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_audioInfo },
  { 0, 0, 0, NULL }
};

static int
dissect_logotypecertextn_LogotypeAudio(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LogotypeAudio_sequence, hf_index, ett_logotypecertextn_LogotypeAudio);

  return offset;
}
static int dissect_audio_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_LogotypeAudio(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_audio_item);
}


static const ber_sequence_t SEQUENCE_OF_LogotypeAudio_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_audio_item },
};

static int
dissect_logotypecertextn_SEQUENCE_OF_LogotypeAudio(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_LogotypeAudio_sequence_of, hf_index, ett_logotypecertextn_SEQUENCE_OF_LogotypeAudio);

  return offset;
}
static int dissect_audio_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_SEQUENCE_OF_LogotypeAudio(TRUE, tvb, offset, pinfo, tree, hf_logotypecertextn_audio);
}


static const ber_sequence_t LogotypeData_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_image },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_audio_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_logotypecertextn_LogotypeData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LogotypeData_sequence, hf_index, ett_logotypecertextn_LogotypeData);

  return offset;
}
static int dissect_direct_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_LogotypeData(TRUE, tvb, offset, pinfo, tree, hf_logotypecertextn_direct);
}


static const ber_sequence_t T_refStructURI_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_refStructURI_item },
};

static int
dissect_logotypecertextn_T_refStructURI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_refStructURI_sequence_of, hf_index, ett_logotypecertextn_T_refStructURI);

  return offset;
}
static int dissect_refStructURI(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_T_refStructURI(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_refStructURI);
}


static const ber_sequence_t LogotypeReference_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_refStructHash },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_refStructURI },
  { 0, 0, 0, NULL }
};

static int
dissect_logotypecertextn_LogotypeReference(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LogotypeReference_sequence, hf_index, ett_logotypecertextn_LogotypeReference);

  return offset;
}
static int dissect_indirect_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_LogotypeReference(TRUE, tvb, offset, pinfo, tree, hf_logotypecertextn_indirect);
}


static const value_string logotypecertextn_LogotypeInfo_vals[] = {
  {   0, "direct" },
  {   1, "indirect" },
  { 0, NULL }
};

static const ber_choice_t LogotypeInfo_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_direct_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_indirect_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_logotypecertextn_LogotypeInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 LogotypeInfo_choice, hf_index, ett_logotypecertextn_LogotypeInfo,
                                 NULL);

  return offset;
}
static int dissect_communityLogos_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_LogotypeInfo(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_communityLogos_item);
}
static int dissect_issuerLogo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_LogotypeInfo(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_issuerLogo);
}
static int dissect_subjectLogo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_LogotypeInfo(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_subjectLogo);
}
static int dissect_info(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_LogotypeInfo(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_info);
}


static const ber_sequence_t SEQUENCE_OF_LogotypeInfo_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_communityLogos_item },
};

static int
dissect_logotypecertextn_SEQUENCE_OF_LogotypeInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_LogotypeInfo_sequence_of, hf_index, ett_logotypecertextn_SEQUENCE_OF_LogotypeInfo);

  return offset;
}
static int dissect_communityLogos(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_SEQUENCE_OF_LogotypeInfo(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_communityLogos);
}



static int
dissect_logotypecertextn_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_logotypeType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_logotypeType);
}


static const ber_sequence_t OtherLogotypeInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_logotypeType },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_info },
  { 0, 0, 0, NULL }
};

static int
dissect_logotypecertextn_OtherLogotypeInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   OtherLogotypeInfo_sequence, hf_index, ett_logotypecertextn_OtherLogotypeInfo);

  return offset;
}
static int dissect_otherLogos_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_OtherLogotypeInfo(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_otherLogos_item);
}


static const ber_sequence_t SEQUENCE_OF_OtherLogotypeInfo_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_otherLogos_item },
};

static int
dissect_logotypecertextn_SEQUENCE_OF_OtherLogotypeInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_OtherLogotypeInfo_sequence_of, hf_index, ett_logotypecertextn_SEQUENCE_OF_OtherLogotypeInfo);

  return offset;
}
static int dissect_otherLogos(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_logotypecertextn_SEQUENCE_OF_OtherLogotypeInfo(FALSE, tvb, offset, pinfo, tree, hf_logotypecertextn_otherLogos);
}


static const ber_sequence_t LogotypeExtn_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_communityLogos },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_issuerLogo },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_subjectLogo },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_otherLogos },
  { 0, 0, 0, NULL }
};

static int
dissect_logotypecertextn_LogotypeExtn(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LogotypeExtn_sequence, hf_index, ett_logotypecertextn_LogotypeExtn);

  return offset;
}

/*--- PDUs ---*/

static void dissect_LogotypeExtn_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_logotypecertextn_LogotypeExtn(FALSE, tvb, 0, pinfo, tree, hf_logotypecertextn_LogotypeExtn_PDU);
}


/*--- End of included file: packet-logotypecertextn-fn.c ---*/
#line 53 "packet-logotype-cert-extn-template.c"


/*--- proto_register_logotypecertextn ----------------------------------------------*/
void proto_register_logotypecertextn(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-logotypecertextn-hfarr.c ---*/
#line 1 "packet-logotypecertextn-hfarr.c"
    { &hf_logotypecertextn_LogotypeExtn_PDU,
      { "LogotypeExtn", "logotypecertextn.LogotypeExtn",
        FT_NONE, BASE_NONE, NULL, 0,
        "LogotypeExtn", HFILL }},
    { &hf_logotypecertextn_communityLogos,
      { "communityLogos", "logotypecertextn.communityLogos",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LogotypeExtn/communityLogos", HFILL }},
    { &hf_logotypecertextn_communityLogos_item,
      { "Item", "logotypecertextn.communityLogos_item",
        FT_UINT32, BASE_DEC, VALS(logotypecertextn_LogotypeInfo_vals), 0,
        "LogotypeExtn/communityLogos/_item", HFILL }},
    { &hf_logotypecertextn_issuerLogo,
      { "issuerLogo", "logotypecertextn.issuerLogo",
        FT_UINT32, BASE_DEC, VALS(logotypecertextn_LogotypeInfo_vals), 0,
        "LogotypeExtn/issuerLogo", HFILL }},
    { &hf_logotypecertextn_subjectLogo,
      { "subjectLogo", "logotypecertextn.subjectLogo",
        FT_UINT32, BASE_DEC, VALS(logotypecertextn_LogotypeInfo_vals), 0,
        "LogotypeExtn/subjectLogo", HFILL }},
    { &hf_logotypecertextn_otherLogos,
      { "otherLogos", "logotypecertextn.otherLogos",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LogotypeExtn/otherLogos", HFILL }},
    { &hf_logotypecertextn_otherLogos_item,
      { "Item", "logotypecertextn.otherLogos_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "LogotypeExtn/otherLogos/_item", HFILL }},
    { &hf_logotypecertextn_direct,
      { "direct", "logotypecertextn.direct",
        FT_NONE, BASE_NONE, NULL, 0,
        "LogotypeInfo/direct", HFILL }},
    { &hf_logotypecertextn_indirect,
      { "indirect", "logotypecertextn.indirect",
        FT_NONE, BASE_NONE, NULL, 0,
        "LogotypeInfo/indirect", HFILL }},
    { &hf_logotypecertextn_image,
      { "image", "logotypecertextn.image",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LogotypeData/image", HFILL }},
    { &hf_logotypecertextn_image_item,
      { "Item", "logotypecertextn.image_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "LogotypeData/image/_item", HFILL }},
    { &hf_logotypecertextn_audio,
      { "audio", "logotypecertextn.audio",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LogotypeData/audio", HFILL }},
    { &hf_logotypecertextn_audio_item,
      { "Item", "logotypecertextn.audio_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "LogotypeData/audio/_item", HFILL }},
    { &hf_logotypecertextn_imageDetails,
      { "imageDetails", "logotypecertextn.imageDetails",
        FT_NONE, BASE_NONE, NULL, 0,
        "LogotypeImage/imageDetails", HFILL }},
    { &hf_logotypecertextn_imageInfo,
      { "imageInfo", "logotypecertextn.imageInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "LogotypeImage/imageInfo", HFILL }},
    { &hf_logotypecertextn_audioDetails,
      { "audioDetails", "logotypecertextn.audioDetails",
        FT_NONE, BASE_NONE, NULL, 0,
        "LogotypeAudio/audioDetails", HFILL }},
    { &hf_logotypecertextn_audioInfo,
      { "audioInfo", "logotypecertextn.audioInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "LogotypeAudio/audioInfo", HFILL }},
    { &hf_logotypecertextn_mediaType,
      { "mediaType", "logotypecertextn.mediaType",
        FT_STRING, BASE_NONE, NULL, 0,
        "LogotypeDetails/mediaType", HFILL }},
    { &hf_logotypecertextn_logotypeHash,
      { "logotypeHash", "logotypecertextn.logotypeHash",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LogotypeDetails/logotypeHash", HFILL }},
    { &hf_logotypecertextn_logotypeHash_item,
      { "Item", "logotypecertextn.logotypeHash_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "LogotypeDetails/logotypeHash/_item", HFILL }},
    { &hf_logotypecertextn_logotypeURI,
      { "logotypeURI", "logotypecertextn.logotypeURI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LogotypeDetails/logotypeURI", HFILL }},
    { &hf_logotypecertextn_logotypeURI_item,
      { "Item", "logotypecertextn.logotypeURI_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "LogotypeDetails/logotypeURI/_item", HFILL }},
    { &hf_logotypecertextn_type,
      { "type", "logotypecertextn.type",
        FT_INT32, BASE_DEC, VALS(logotypecertextn_LogotypeImageType_vals), 0,
        "LogotypeImageInfo/type", HFILL }},
    { &hf_logotypecertextn_fileSize,
      { "fileSize", "logotypecertextn.fileSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_logotypecertextn_xSize,
      { "xSize", "logotypecertextn.xSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "LogotypeImageInfo/xSize", HFILL }},
    { &hf_logotypecertextn_ySize,
      { "ySize", "logotypecertextn.ySize",
        FT_INT32, BASE_DEC, NULL, 0,
        "LogotypeImageInfo/ySize", HFILL }},
    { &hf_logotypecertextn_resolution,
      { "resolution", "logotypecertextn.resolution",
        FT_UINT32, BASE_DEC, VALS(logotypecertextn_LogotypeImageResolution_vals), 0,
        "LogotypeImageInfo/resolution", HFILL }},
    { &hf_logotypecertextn_language,
      { "language", "logotypecertextn.language",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_logotypecertextn_numBits,
      { "numBits", "logotypecertextn.numBits",
        FT_INT32, BASE_DEC, NULL, 0,
        "LogotypeImageResolution/numBits", HFILL }},
    { &hf_logotypecertextn_tableSize,
      { "tableSize", "logotypecertextn.tableSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "LogotypeImageResolution/tableSize", HFILL }},
    { &hf_logotypecertextn_playTime,
      { "playTime", "logotypecertextn.playTime",
        FT_INT32, BASE_DEC, NULL, 0,
        "LogotypeAudioInfo/playTime", HFILL }},
    { &hf_logotypecertextn_channels,
      { "channels", "logotypecertextn.channels",
        FT_INT32, BASE_DEC, NULL, 0,
        "LogotypeAudioInfo/channels", HFILL }},
    { &hf_logotypecertextn_sampleRate,
      { "sampleRate", "logotypecertextn.sampleRate",
        FT_INT32, BASE_DEC, NULL, 0,
        "LogotypeAudioInfo/sampleRate", HFILL }},
    { &hf_logotypecertextn_logotypeType,
      { "logotypeType", "logotypecertextn.logotypeType",
        FT_OID, BASE_NONE, NULL, 0,
        "OtherLogotypeInfo/logotypeType", HFILL }},
    { &hf_logotypecertextn_info,
      { "info", "logotypecertextn.info",
        FT_UINT32, BASE_DEC, VALS(logotypecertextn_LogotypeInfo_vals), 0,
        "OtherLogotypeInfo/info", HFILL }},
    { &hf_logotypecertextn_refStructHash,
      { "refStructHash", "logotypecertextn.refStructHash",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LogotypeReference/refStructHash", HFILL }},
    { &hf_logotypecertextn_refStructHash_item,
      { "Item", "logotypecertextn.refStructHash_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "LogotypeReference/refStructHash/_item", HFILL }},
    { &hf_logotypecertextn_refStructURI,
      { "refStructURI", "logotypecertextn.refStructURI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LogotypeReference/refStructURI", HFILL }},
    { &hf_logotypecertextn_refStructURI_item,
      { "Item", "logotypecertextn.refStructURI_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "LogotypeReference/refStructURI/_item", HFILL }},
    { &hf_logotypecertextn_hashAlg,
      { "hashAlg", "logotypecertextn.hashAlg",
        FT_NONE, BASE_NONE, NULL, 0,
        "HashAlgAndValue/hashAlg", HFILL }},
    { &hf_logotypecertextn_hashValue,
      { "hashValue", "logotypecertextn.hashValue",
        FT_BYTES, BASE_HEX, NULL, 0,
        "HashAlgAndValue/hashValue", HFILL }},

/*--- End of included file: packet-logotypecertextn-hfarr.c ---*/
#line 61 "packet-logotype-cert-extn-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-logotypecertextn-ettarr.c ---*/
#line 1 "packet-logotypecertextn-ettarr.c"
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
#line 66 "packet-logotype-cert-extn-template.c"
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
#line 1 "packet-logotypecertextn-dis-tab.c"
  register_ber_oid_dissector("1.3.6.1.5.5.7.1.12", dissect_LogotypeExtn_PDU, proto_logotypecertextn, "id-pe-logotype");
  register_ber_oid_dissector("1.3.6.1.5.5.7.20.1", dissect_LogotypeExtn_PDU, proto_logotypecertextn, "id-pe-logo-loyalty");
  register_ber_oid_dissector("1.3.6.1.5.5.7.20.2", dissect_LogotypeExtn_PDU, proto_logotypecertextn, "id-pe-logo-background");


/*--- End of included file: packet-logotypecertextn-dis-tab.c ---*/
#line 81 "packet-logotype-cert-extn-template.c"
}

