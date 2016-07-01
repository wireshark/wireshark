/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-h283.c                                                              */
/* asn2wrs.py -p h283 -c ./h283.cnf -s ./packet-h283-template -D . -O ../.. LCT-PROTOCOL.asn */

/* Input file: packet-h283-template.c */

#line 1 "./asn1/h283/packet-h283-template.c"
/* packet-h283.c
 * Routines for H.283 packet dissection
 * 2007  Tomas Kukosa
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

#include "config.h"

#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-per.h"

#define PNAME  "H.283 Logical Channel Transport"
#define PSNAME "LCT"
#define PFNAME "lct"

void proto_register_h283(void);
void proto_reg_handoff_h283(void);

/* Initialize the protocol and registered fields */
static int proto_h283 = -1;

/*--- Included file: packet-h283-hf.c ---*/
#line 1 "./asn1/h283/packet-h283-hf.c"
static int hf_h283_LCTPDU_PDU = -1;               /* LCTPDU */
static int hf_h283_t35CountryCode = -1;           /* INTEGER_0_255 */
static int hf_h283_t35Extension = -1;             /* INTEGER_0_255 */
static int hf_h283_manufacturerCode = -1;         /* INTEGER_0_65535 */
static int hf_h283_object = -1;                   /* OBJECT_IDENTIFIER */
static int hf_h283_h221NonStandard = -1;          /* H221NonStandard */
static int hf_h283_nonStandardIdentifier = -1;    /* NonStandardIdentifier */
static int hf_h283_data = -1;                     /* OCTET_STRING */
static int hf_h283_srcAddr = -1;                  /* MTAddress */
static int hf_h283_dstAddr = -1;                  /* MTAddress */
static int hf_h283_timestamp = -1;                /* INTEGER_0_4294967295 */
static int hf_h283_seqNumber = -1;                /* INTEGER_0_65535 */
static int hf_h283_pduType = -1;                  /* T_pduType */
static int hf_h283_ack = -1;                      /* NULL */
static int hf_h283_rdcData = -1;                  /* RDCData */
static int hf_h283_nonStandardParameters = -1;    /* SEQUENCE_OF_NonStandardParameter */
static int hf_h283_nonStandardParameters_item = -1;  /* NonStandardParameter */
static int hf_h283_mAddress = -1;                 /* INTEGER_0_65535 */
static int hf_h283_tAddress = -1;                 /* INTEGER_0_65535 */
static int hf_h283_reliable = -1;                 /* BOOLEAN */
static int hf_h283_dataType = -1;                 /* T_dataType */
static int hf_h283_lctMessage = -1;               /* LCTMessage */
static int hf_h283_rdcPDU = -1;                   /* T_rdcPDU */
static int hf_h283_lctRequest = -1;               /* LCTRequest */
static int hf_h283_lctResponse = -1;              /* LCTResponse */
static int hf_h283_lctIndication = -1;            /* LCTIndication */
static int hf_h283_nonStandardMessage = -1;       /* NonStandardMessage */
static int hf_h283_announceReq = -1;              /* NULL */
static int hf_h283_deviceListReq = -1;            /* NULL */
static int hf_h283_announceResp = -1;             /* NULL */
static int hf_h283_deviceListResp = -1;           /* T_deviceListResp */
static int hf_h283_deviceChange = -1;             /* NULL */

/*--- End of included file: packet-h283-hf.c ---*/
#line 42 "./asn1/h283/packet-h283-template.c"

/* Initialize the subtree pointers */
static int ett_h283 = -1;

/*--- Included file: packet-h283-ett.c ---*/
#line 1 "./asn1/h283/packet-h283-ett.c"
static gint ett_h283_H221NonStandard = -1;
static gint ett_h283_NonStandardIdentifier = -1;
static gint ett_h283_NonStandardParameter = -1;
static gint ett_h283_LCTPDU = -1;
static gint ett_h283_T_pduType = -1;
static gint ett_h283_SEQUENCE_OF_NonStandardParameter = -1;
static gint ett_h283_MTAddress = -1;
static gint ett_h283_RDCData = -1;
static gint ett_h283_T_dataType = -1;
static gint ett_h283_LCTMessage = -1;
static gint ett_h283_LCTRequest = -1;
static gint ett_h283_LCTResponse = -1;
static gint ett_h283_LCTIndication = -1;
static gint ett_h283_NonStandardMessage = -1;

/*--- End of included file: packet-h283-ett.c ---*/
#line 46 "./asn1/h283/packet-h283-template.c"

/* Subdissectors */
static dissector_handle_t rdc_pdu_handle;
static dissector_handle_t rdc_device_list_handle;
static dissector_handle_t data_handle;
static dissector_handle_t h283_udp_handle;


static gboolean info_is_set;


/*--- Included file: packet-h283-fn.c ---*/
#line 1 "./asn1/h283/packet-h283-fn.c"


static int
dissect_h283_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_h283_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t H221NonStandard_sequence[] = {
  { &hf_h283_t35CountryCode , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h283_INTEGER_0_255 },
  { &hf_h283_t35Extension   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h283_INTEGER_0_255 },
  { &hf_h283_manufacturerCode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h283_INTEGER_0_65535 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h283_H221NonStandard(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h283_H221NonStandard, H221NonStandard_sequence);

  return offset;
}



static int
dissect_h283_OBJECT_IDENTIFIER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string h283_NonStandardIdentifier_vals[] = {
  {   0, "object" },
  {   1, "h221NonStandard" },
  { 0, NULL }
};

static const per_choice_t NonStandardIdentifier_choice[] = {
  {   0, &hf_h283_object         , ASN1_EXTENSION_ROOT    , dissect_h283_OBJECT_IDENTIFIER },
  {   1, &hf_h283_h221NonStandard, ASN1_EXTENSION_ROOT    , dissect_h283_H221NonStandard },
  { 0, NULL, 0, NULL }
};

static int
dissect_h283_NonStandardIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h283_NonStandardIdentifier, NonStandardIdentifier_choice,
                                 NULL);

  return offset;
}



static int
dissect_h283_OCTET_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t NonStandardParameter_sequence[] = {
  { &hf_h283_nonStandardIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h283_NonStandardIdentifier },
  { &hf_h283_data           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h283_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_h283_NonStandardParameter(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h283_NonStandardParameter, NonStandardParameter_sequence);

  return offset;
}


static const per_sequence_t MTAddress_sequence[] = {
  { &hf_h283_mAddress       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h283_INTEGER_0_65535 },
  { &hf_h283_tAddress       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h283_INTEGER_0_65535 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h283_MTAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h283_MTAddress, MTAddress_sequence);

  return offset;
}



static int
dissect_h283_INTEGER_0_4294967295(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}



static int
dissect_h283_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_h283_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string h283_LCTRequest_vals[] = {
  {   0, "announceReq" },
  {   1, "deviceListReq" },
  { 0, NULL }
};

static const per_choice_t LCTRequest_choice[] = {
  {   0, &hf_h283_announceReq    , ASN1_EXTENSION_ROOT    , dissect_h283_NULL },
  {   1, &hf_h283_deviceListReq  , ASN1_EXTENSION_ROOT    , dissect_h283_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h283_LCTRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 56 "./asn1/h283/h283.cnf"
  gint32 msg_type = -1;
  const gchar *p = NULL;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h283_LCTRequest, LCTRequest_choice,
                                 &msg_type);

#line 59 "./asn1/h283/h283.cnf"
  p = try_val_to_str(msg_type, VALS(h283_LCTRequest_vals));
  if (!info_is_set && p ) {
    col_add_fstr(actx->pinfo->cinfo, COL_INFO, "LCTRequest/%s", p);
    info_is_set = TRUE;
  }

  return offset;
}



static int
dissect_h283_T_deviceListResp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 103 "./asn1/h283/h283.cnf"
  tvbuff_t *next_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &next_tvb);

  if (next_tvb && tvb_reported_length(next_tvb)) {
    call_dissector((rdc_device_list_handle)?rdc_device_list_handle:data_handle, next_tvb, actx->pinfo, tree);
  }


  return offset;
}


static const value_string h283_LCTResponse_vals[] = {
  {   0, "announceResp" },
  {   1, "deviceListResp" },
  { 0, NULL }
};

static const per_choice_t LCTResponse_choice[] = {
  {   0, &hf_h283_announceResp   , ASN1_EXTENSION_ROOT    , dissect_h283_NULL },
  {   1, &hf_h283_deviceListResp , ASN1_EXTENSION_ROOT    , dissect_h283_T_deviceListResp },
  { 0, NULL, 0, NULL }
};

static int
dissect_h283_LCTResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 69 "./asn1/h283/h283.cnf"
  gint32 msg_type = -1;
  const gchar *p = NULL;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h283_LCTResponse, LCTResponse_choice,
                                 &msg_type);

#line 72 "./asn1/h283/h283.cnf"
  p = try_val_to_str(msg_type, VALS(h283_LCTResponse_vals));
  if (!info_is_set && p ) {
    col_add_fstr(actx->pinfo->cinfo, COL_INFO, "LCTResponse/%s", p);
    info_is_set = TRUE;
  }

  return offset;
}


static const value_string h283_LCTIndication_vals[] = {
  {   0, "deviceChange" },
  { 0, NULL }
};

static const per_choice_t LCTIndication_choice[] = {
  {   0, &hf_h283_deviceChange   , ASN1_EXTENSION_ROOT    , dissect_h283_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h283_LCTIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 82 "./asn1/h283/h283.cnf"
  gint32 msg_type = -1;
  const gchar *p = NULL;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h283_LCTIndication, LCTIndication_choice,
                                 &msg_type);

#line 85 "./asn1/h283/h283.cnf"
  p = try_val_to_str(msg_type, VALS(h283_LCTIndication_vals));
  if (!info_is_set && p ) {
    col_add_fstr(actx->pinfo->cinfo, COL_INFO, "LCTIndication/%s", p);
    info_is_set = TRUE;
  }

  return offset;
}


static const per_sequence_t SEQUENCE_OF_NonStandardParameter_sequence_of[1] = {
  { &hf_h283_nonStandardParameters_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h283_NonStandardParameter },
};

static int
dissect_h283_SEQUENCE_OF_NonStandardParameter(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h283_SEQUENCE_OF_NonStandardParameter, SEQUENCE_OF_NonStandardParameter_sequence_of);

  return offset;
}


static const per_sequence_t NonStandardMessage_sequence[] = {
  { &hf_h283_nonStandardParameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h283_SEQUENCE_OF_NonStandardParameter },
  { NULL, 0, 0, NULL }
};

static int
dissect_h283_NonStandardMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h283_NonStandardMessage, NonStandardMessage_sequence);

  return offset;
}


static const value_string h283_LCTMessage_vals[] = {
  {   0, "lctRequest" },
  {   1, "lctResponse" },
  {   2, "lctIndication" },
  {   3, "nonStandardMessage" },
  { 0, NULL }
};

static const per_choice_t LCTMessage_choice[] = {
  {   0, &hf_h283_lctRequest     , ASN1_EXTENSION_ROOT    , dissect_h283_LCTRequest },
  {   1, &hf_h283_lctResponse    , ASN1_EXTENSION_ROOT    , dissect_h283_LCTResponse },
  {   2, &hf_h283_lctIndication  , ASN1_EXTENSION_ROOT    , dissect_h283_LCTIndication },
  {   3, &hf_h283_nonStandardMessage, ASN1_EXTENSION_ROOT    , dissect_h283_NonStandardMessage },
  { 0, NULL, 0, NULL }
};

static int
dissect_h283_LCTMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 43 "./asn1/h283/h283.cnf"
  gint32 msg_type = -1;
  const gchar *p = NULL;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h283_LCTMessage, LCTMessage_choice,
                                 &msg_type);

#line 46 "./asn1/h283/h283.cnf"
  p = try_val_to_str(msg_type, VALS(h283_LCTMessage_vals));
  if (!info_is_set && p ) {
    col_add_fstr(actx->pinfo->cinfo, COL_INFO, "LCTMessage/%s", p);
    info_is_set = TRUE;
  }

  return offset;
}



static int
dissect_h283_T_rdcPDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 93 "./asn1/h283/h283.cnf"
  tvbuff_t *next_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &next_tvb);

  if (next_tvb && tvb_reported_length(next_tvb)) {
    call_dissector((rdc_pdu_handle)?rdc_pdu_handle:data_handle, next_tvb, actx->pinfo, proto_tree_get_root(tree));
  }
  info_is_set = TRUE;


  return offset;
}


static const value_string h283_T_dataType_vals[] = {
  {   0, "lctMessage" },
  {   1, "rdcPDU" },
  { 0, NULL }
};

static const per_choice_t T_dataType_choice[] = {
  {   0, &hf_h283_lctMessage     , ASN1_NO_EXTENSIONS     , dissect_h283_LCTMessage },
  {   1, &hf_h283_rdcPDU         , ASN1_NO_EXTENSIONS     , dissect_h283_T_rdcPDU },
  { 0, NULL, 0, NULL }
};

static int
dissect_h283_T_dataType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 30 "./asn1/h283/h283.cnf"
  gint32 data_type = -1;
  const gchar *p = NULL;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h283_T_dataType, T_dataType_choice,
                                 &data_type);

#line 33 "./asn1/h283/h283.cnf"
  p = try_val_to_str(data_type, VALS(h283_T_dataType_vals));
  if (!info_is_set && p ) {
    col_add_fstr(actx->pinfo->cinfo, COL_INFO, "RDCData/%s", p);
    info_is_set = TRUE;
  }

  return offset;
}


static const per_sequence_t RDCData_sequence[] = {
  { &hf_h283_reliable       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h283_BOOLEAN },
  { &hf_h283_dataType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h283_T_dataType },
  { NULL, 0, 0, NULL }
};

static int
dissect_h283_RDCData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h283_RDCData, RDCData_sequence);

  return offset;
}


static const value_string h283_T_pduType_vals[] = {
  {   0, "ack" },
  {   1, "rdcData" },
  { 0, NULL }
};

static const per_choice_t T_pduType_choice[] = {
  {   0, &hf_h283_ack            , ASN1_NO_EXTENSIONS     , dissect_h283_NULL },
  {   1, &hf_h283_rdcData        , ASN1_NO_EXTENSIONS     , dissect_h283_RDCData },
  { 0, NULL, 0, NULL }
};

static int
dissect_h283_T_pduType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 17 "./asn1/h283/h283.cnf"
  gint32 pdu_type = -1;
  const gchar *p = NULL;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h283_T_pduType, T_pduType_choice,
                                 &pdu_type);

#line 20 "./asn1/h283/h283.cnf"
  p = try_val_to_str(pdu_type, VALS(h283_T_pduType_vals));
  if (!info_is_set && p ) {
    col_set_str(actx->pinfo->cinfo, COL_INFO, p);
    info_is_set = TRUE;
  }

  return offset;
}


static const per_sequence_t LCTPDU_sequence[] = {
  { &hf_h283_srcAddr        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h283_MTAddress },
  { &hf_h283_dstAddr        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h283_MTAddress },
  { &hf_h283_timestamp      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h283_INTEGER_0_4294967295 },
  { &hf_h283_seqNumber      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h283_INTEGER_0_65535 },
  { &hf_h283_pduType        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h283_T_pduType },
  { &hf_h283_nonStandardParameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h283_SEQUENCE_OF_NonStandardParameter },
  { NULL, 0, 0, NULL }
};

static int
dissect_h283_LCTPDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h283_LCTPDU, LCTPDU_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_LCTPDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h283_LCTPDU(tvb, offset, &asn1_ctx, tree, hf_h283_LCTPDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-h283-fn.c ---*/
#line 57 "./asn1/h283/packet-h283-template.c"

static int
dissect_h283_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item  *ti = NULL;
  proto_tree  *h283_tree = NULL;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);

  info_is_set = FALSE;

  ti = proto_tree_add_item(tree, proto_h283, tvb, 0, -1, ENC_NA);
  h283_tree = proto_item_add_subtree(ti, ett_h283);

  return dissect_LCTPDU_PDU(tvb, pinfo, h283_tree, NULL);
}

/*--- proto_register_h283 ----------------------------------------------*/
void proto_register_h283(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-h283-hfarr.c ---*/
#line 1 "./asn1/h283/packet-h283-hfarr.c"
    { &hf_h283_LCTPDU_PDU,
      { "LCTPDU", "h283.LCTPDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h283_t35CountryCode,
      { "t35CountryCode", "h283.t35CountryCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h283_t35Extension,
      { "t35Extension", "h283.t35Extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h283_manufacturerCode,
      { "manufacturerCode", "h283.manufacturerCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h283_object,
      { "object", "h283.object",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_h283_h221NonStandard,
      { "h221NonStandard", "h283.h221NonStandard_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h283_nonStandardIdentifier,
      { "nonStandardIdentifier", "h283.nonStandardIdentifier",
        FT_UINT32, BASE_DEC, VALS(h283_NonStandardIdentifier_vals), 0,
        NULL, HFILL }},
    { &hf_h283_data,
      { "data", "h283.data",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_h283_srcAddr,
      { "srcAddr", "h283.srcAddr_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MTAddress", HFILL }},
    { &hf_h283_dstAddr,
      { "dstAddr", "h283.dstAddr_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MTAddress", HFILL }},
    { &hf_h283_timestamp,
      { "timestamp", "h283.timestamp",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_h283_seqNumber,
      { "seqNumber", "h283.seqNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h283_pduType,
      { "pduType", "h283.pduType",
        FT_UINT32, BASE_DEC, VALS(h283_T_pduType_vals), 0,
        NULL, HFILL }},
    { &hf_h283_ack,
      { "ack", "h283.ack_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h283_rdcData,
      { "rdcData", "h283.rdcData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h283_nonStandardParameters,
      { "nonStandardParameters", "h283.nonStandardParameters",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_NonStandardParameter", HFILL }},
    { &hf_h283_nonStandardParameters_item,
      { "NonStandardParameter", "h283.NonStandardParameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h283_mAddress,
      { "mAddress", "h283.mAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h283_tAddress,
      { "tAddress", "h283.tAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h283_reliable,
      { "reliable", "h283.reliable",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h283_dataType,
      { "dataType", "h283.dataType",
        FT_UINT32, BASE_DEC, VALS(h283_T_dataType_vals), 0,
        NULL, HFILL }},
    { &hf_h283_lctMessage,
      { "lctMessage", "h283.lctMessage",
        FT_UINT32, BASE_DEC, VALS(h283_LCTMessage_vals), 0,
        NULL, HFILL }},
    { &hf_h283_rdcPDU,
      { "rdcPDU", "h283.rdcPDU",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h283_lctRequest,
      { "lctRequest", "h283.lctRequest",
        FT_UINT32, BASE_DEC, VALS(h283_LCTRequest_vals), 0,
        NULL, HFILL }},
    { &hf_h283_lctResponse,
      { "lctResponse", "h283.lctResponse",
        FT_UINT32, BASE_DEC, VALS(h283_LCTResponse_vals), 0,
        NULL, HFILL }},
    { &hf_h283_lctIndication,
      { "lctIndication", "h283.lctIndication",
        FT_UINT32, BASE_DEC, VALS(h283_LCTIndication_vals), 0,
        NULL, HFILL }},
    { &hf_h283_nonStandardMessage,
      { "nonStandardMessage", "h283.nonStandardMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h283_announceReq,
      { "announceReq", "h283.announceReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h283_deviceListReq,
      { "deviceListReq", "h283.deviceListReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h283_announceResp,
      { "announceResp", "h283.announceResp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h283_deviceListResp,
      { "deviceListResp", "h283.deviceListResp",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h283_deviceChange,
      { "deviceChange", "h283.deviceChange_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/*--- End of included file: packet-h283-hfarr.c ---*/
#line 80 "./asn1/h283/packet-h283-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_h283,

/*--- Included file: packet-h283-ettarr.c ---*/
#line 1 "./asn1/h283/packet-h283-ettarr.c"
    &ett_h283_H221NonStandard,
    &ett_h283_NonStandardIdentifier,
    &ett_h283_NonStandardParameter,
    &ett_h283_LCTPDU,
    &ett_h283_T_pduType,
    &ett_h283_SEQUENCE_OF_NonStandardParameter,
    &ett_h283_MTAddress,
    &ett_h283_RDCData,
    &ett_h283_T_dataType,
    &ett_h283_LCTMessage,
    &ett_h283_LCTRequest,
    &ett_h283_LCTResponse,
    &ett_h283_LCTIndication,
    &ett_h283_NonStandardMessage,

/*--- End of included file: packet-h283-ettarr.c ---*/
#line 86 "./asn1/h283/packet-h283-template.c"
  };

  /* Register protocol */
  proto_h283 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_h283, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  h283_udp_handle = register_dissector(PFNAME, dissect_h283_udp, proto_h283);

}

/*--- proto_reg_handoff_h283 -------------------------------------------*/
void proto_reg_handoff_h283(void)
{
  dissector_add_for_decode_as("udp.port", h283_udp_handle);

  rdc_pdu_handle = find_dissector_add_dependency("rdc", proto_h283);
  rdc_device_list_handle = find_dissector_add_dependency("rdc.device_list", proto_h283);
  data_handle = find_dissector("data");
}

