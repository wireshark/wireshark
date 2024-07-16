/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-t125.c                                                              */
/* asn2wrs.py -b -q -L -p t125 -c ./t125.cnf -s ./packet-t125-template -D . -O ../.. MCS-PROTOCOL.asn */

/* packet-t125.c
 * Routines for t125 packet dissection
 * Copyright 2007, Ronnie Sahlberg
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>

#include <epan/asn1.h>
#include "packet-ber.h"
#include "packet-per.h"

#include "packet-t124.h"

#define PNAME  "MULTIPOINT-COMMUNICATION-SERVICE T.125"
#define PSNAME "T.125"
#define PFNAME "t125"


#define HF_T125_ERECT_DOMAIN_REQUEST 1
#define HF_T125_DISCONNECT_PROVIDER_ULTIMATUM 8
#define HF_T125_ATTACH_USER_REQUEST 10
#define HF_T125_ATTACH_USER_CONFIRM 11
#define HF_T125_CHANNEL_JOIN_REQUEST 14
#define HF_T125_CHANNEL_JOIN_CONFIRM 15
#define HF_T125_SEND_DATA_REQUEST 25
#define HF_T125_SEND_DATA_INDICATION 26

void proto_register_t125(void);
void proto_reg_handoff_t125(void);

/* Initialize the protocol and registered fields */
static int proto_t125;
static proto_tree *top_tree;
static int hf_t125_ConnectMCSPDU_PDU;             /* ConnectMCSPDU */
static int hf_t125_maxChannelIds;                 /* INTEGER_0_MAX */
static int hf_t125_maxUserIds;                    /* INTEGER_0_MAX */
static int hf_t125_maxTokenIds;                   /* INTEGER_0_MAX */
static int hf_t125_numPriorities;                 /* INTEGER_0_MAX */
static int hf_t125_minThroughput;                 /* INTEGER_0_MAX */
static int hf_t125_maxHeight;                     /* INTEGER_0_MAX */
static int hf_t125_maxMCSPDUsize;                 /* INTEGER_0_MAX */
static int hf_t125_protocolVersion;               /* INTEGER_0_MAX */
static int hf_t125_callingDomainSelector;         /* OCTET_STRING */
static int hf_t125_calledDomainSelector;          /* OCTET_STRING */
static int hf_t125_upwardFlag;                    /* BOOLEAN */
static int hf_t125_targetParameters;              /* DomainParameters */
static int hf_t125_minimumParameters;             /* DomainParameters */
static int hf_t125_maximumParameters;             /* DomainParameters */
static int hf_t125_userData;                      /* T_userData */
static int hf_t125_result;                        /* Result */
static int hf_t125_calledConnectId;               /* INTEGER_0_MAX */
static int hf_t125_domainParameters;              /* DomainParameters */
static int hf_t125_userData_01;                   /* T_userData_01 */
static int hf_t125_dataPriority;                  /* DataPriority */
static int hf_t125_connect_initial;               /* Connect_Initial */
static int hf_t125_connect_response;              /* Connect_Response */
static int hf_t125_connect_additional;            /* Connect_Additional */
static int hf_t125_connect_result;                /* Connect_Result */

/* Initialize the subtree pointers */
static int ett_t125;

static int ett_t125_DomainParameters;
static int ett_t125_Connect_Initial_U;
static int ett_t125_Connect_Response_U;
static int ett_t125_Connect_Additional_U;
static int ett_t125_Connect_Result_U;
static int ett_t125_ConnectMCSPDU;

static heur_dissector_list_t t125_heur_subdissector_list;


static const value_string t125_DataPriority_vals[] = {
  {   0, "top" },
  {   1, "high" },
  {   2, "medium" },
  {   3, "low" },
  { 0, NULL }
};


static int
dissect_t125_DataPriority(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_t125_INTEGER_0_MAX(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer64(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t DomainParameters_sequence[] = {
  { &hf_t125_maxChannelIds  , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_INTEGER_0_MAX },
  { &hf_t125_maxUserIds     , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_INTEGER_0_MAX },
  { &hf_t125_maxTokenIds    , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_INTEGER_0_MAX },
  { &hf_t125_numPriorities  , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_INTEGER_0_MAX },
  { &hf_t125_minThroughput  , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_INTEGER_0_MAX },
  { &hf_t125_maxHeight      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_INTEGER_0_MAX },
  { &hf_t125_maxMCSPDUsize  , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_INTEGER_0_MAX },
  { &hf_t125_protocolVersion, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_INTEGER_0_MAX },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_DomainParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DomainParameters_sequence, hf_index, ett_t125_DomainParameters);

  return offset;
}



static int
dissect_t125_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_t125_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_t125_T_userData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    tvbuff_t	*next_tvb = NULL;
	heur_dtbl_entry_t *hdtbl_entry;
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &next_tvb);

    if(next_tvb)
    	dissector_try_heuristic(t125_heur_subdissector_list, next_tvb,
	     actx->pinfo, top_tree, &hdtbl_entry, NULL);

  return offset;
}


static const ber_sequence_t Connect_Initial_U_sequence[] = {
  { &hf_t125_callingDomainSelector, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_t125_OCTET_STRING },
  { &hf_t125_calledDomainSelector, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_t125_OCTET_STRING },
  { &hf_t125_upwardFlag     , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_t125_BOOLEAN },
  { &hf_t125_targetParameters, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_t125_DomainParameters },
  { &hf_t125_minimumParameters, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_t125_DomainParameters },
  { &hf_t125_maximumParameters, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_t125_DomainParameters },
  { &hf_t125_userData       , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_t125_T_userData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_Connect_Initial_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Connect_Initial_U_sequence, hf_index, ett_t125_Connect_Initial_U);

  return offset;
}



static int
dissect_t125_Connect_Initial(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 101, true, dissect_t125_Connect_Initial_U);

  return offset;
}


static const value_string t125_Result_vals[] = {
  {   0, "rt-successful" },
  {   1, "rt-domain-merging" },
  {   2, "rt-domain-not-hierarchical" },
  {   3, "rt-no-such-channel" },
  {   4, "rt-no-such-domain" },
  {   5, "rt-no-such-user" },
  {   6, "rt-not-admitted" },
  {   7, "rt-other-user-id" },
  {   8, "rt-parameters-unacceptable" },
  {   9, "rt-token-not-available" },
  {  10, "rt-token-not-possessed" },
  {  11, "rt-too-many-channels" },
  {  12, "rt-too-many-tokens" },
  {  13, "rt-too-many-users" },
  {  14, "rt-unspecified-failure" },
  {  15, "rt-user-rejected" },
  { 0, NULL }
};


static int
dissect_t125_Result(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_t125_T_userData_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    tvbuff_t	*next_tvb = NULL;
	heur_dtbl_entry_t *hdtbl_entry;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &next_tvb);

    if(next_tvb)
    	dissector_try_heuristic(t125_heur_subdissector_list, next_tvb,
	     actx->pinfo, top_tree, &hdtbl_entry, NULL);

  return offset;
}


static const ber_sequence_t Connect_Response_U_sequence[] = {
  { &hf_t125_result         , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t125_Result },
  { &hf_t125_calledConnectId, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_INTEGER_0_MAX },
  { &hf_t125_domainParameters, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_t125_DomainParameters },
  { &hf_t125_userData_01    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_t125_T_userData_01 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_Connect_Response_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Connect_Response_U_sequence, hf_index, ett_t125_Connect_Response_U);

  return offset;
}



static int
dissect_t125_Connect_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 102, true, dissect_t125_Connect_Response_U);

  return offset;
}


static const ber_sequence_t Connect_Additional_U_sequence[] = {
  { &hf_t125_calledConnectId, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_INTEGER_0_MAX },
  { &hf_t125_dataPriority   , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t125_DataPriority },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_Connect_Additional_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Connect_Additional_U_sequence, hf_index, ett_t125_Connect_Additional_U);

  return offset;
}



static int
dissect_t125_Connect_Additional(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 103, true, dissect_t125_Connect_Additional_U);

  return offset;
}


static const ber_sequence_t Connect_Result_U_sequence[] = {
  { &hf_t125_result         , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t125_Result },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_Connect_Result_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Connect_Result_U_sequence, hf_index, ett_t125_Connect_Result_U);

  return offset;
}



static int
dissect_t125_Connect_Result(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 104, true, dissect_t125_Connect_Result_U);

  return offset;
}


static const value_string t125_ConnectMCSPDU_vals[] = {
  { 101, "connect-initial" },
  { 102, "connect-response" },
  { 103, "connect-additional" },
  { 104, "connect-result" },
  { 0, NULL }
};

static const ber_choice_t ConnectMCSPDU_choice[] = {
  { 101, &hf_t125_connect_initial, BER_CLASS_APP, 101, BER_FLAGS_NOOWNTAG, dissect_t125_Connect_Initial },
  { 102, &hf_t125_connect_response, BER_CLASS_APP, 102, BER_FLAGS_NOOWNTAG, dissect_t125_Connect_Response },
  { 103, &hf_t125_connect_additional, BER_CLASS_APP, 103, BER_FLAGS_NOOWNTAG, dissect_t125_Connect_Additional },
  { 104, &hf_t125_connect_result , BER_CLASS_APP, 104, BER_FLAGS_NOOWNTAG, dissect_t125_Connect_Result },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_ConnectMCSPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ConnectMCSPDU_choice, hf_index, ett_t125_ConnectMCSPDU,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_ConnectMCSPDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_t125_ConnectMCSPDU(false, tvb, offset, &asn1_ctx, tree, hf_t125_ConnectMCSPDU_PDU);
  return offset;
}


static int
dissect_t125(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int8_t ber_class;
  bool pc;
  int32_t tag;

  top_tree = parent_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "T.125");
  col_clear(pinfo->cinfo, COL_INFO);

  item = proto_tree_add_item(parent_tree, proto_t125, tvb, 0, tvb_captured_length(tvb), ENC_NA);
  tree = proto_item_add_subtree(item, ett_t125);

  get_ber_identifier(tvb, 0, &ber_class, &pc, &tag);

  if ( (ber_class==BER_CLASS_APP) && (tag>=101) && (tag<=104) ){
    dissect_ConnectMCSPDU_PDU(tvb, pinfo, tree, NULL);
  } else  {
    t124_set_top_tree(top_tree);
    dissect_DomainMCSPDU_PDU(tvb, pinfo, tree);
  }

  return tvb_captured_length(tvb);
}

static bool
dissect_t125_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
  int8_t ber_class;
  bool pc;
  int32_t tag;
  volatile bool failed;

  /*
   * We must catch all the "ran past the end of the packet" exceptions
   * here and, if we catch one, just return false.  It's too painful
   * to have a version of dissect_per_sequence() that checks all
   * references to the tvbuff before making them and returning "no"
   * if they would fail.
   */
  failed = false;
  TRY {
    /* could be BER */
    get_ber_identifier(tvb, 0, &ber_class, &pc, &tag);
  } CATCH_BOUNDS_ERRORS {
    failed = true;
  } ENDTRY;

  if (failed) {
      return false;
  }

  if (((ber_class==BER_CLASS_APP) && ((tag>=101) && (tag<=104)))) {
    dissect_t125(tvb, pinfo, parent_tree, NULL);

    return true;
  }

  /*
   * Check that the first byte of the packet is a valid t125/MCS header.
   * This might not be enough, but since t125 only catch COTP packets,
   * it should not be a problem.
   */
  uint8_t first_byte = tvb_get_uint8(tvb, 0) >> 2;
  switch (first_byte) {
    case HF_T125_ERECT_DOMAIN_REQUEST:
    case HF_T125_ATTACH_USER_REQUEST:
    case HF_T125_ATTACH_USER_CONFIRM:
    case HF_T125_CHANNEL_JOIN_REQUEST:
    case HF_T125_CHANNEL_JOIN_CONFIRM:
    case HF_T125_DISCONNECT_PROVIDER_ULTIMATUM:
    case HF_T125_SEND_DATA_REQUEST:
    case HF_T125_SEND_DATA_INDICATION:
      dissect_t125(tvb, pinfo, parent_tree, NULL);
      return true;
  }

  return false;
}


/*--- proto_register_t125 -------------------------------------------*/
void proto_register_t125(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_t125_ConnectMCSPDU_PDU,
      { "ConnectMCSPDU", "t125.ConnectMCSPDU",
        FT_UINT32, BASE_DEC, VALS(t125_ConnectMCSPDU_vals), 0,
        NULL, HFILL }},
    { &hf_t125_maxChannelIds,
      { "maxChannelIds", "t125.maxChannelIds",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t125_maxUserIds,
      { "maxUserIds", "t125.maxUserIds",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t125_maxTokenIds,
      { "maxTokenIds", "t125.maxTokenIds",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t125_numPriorities,
      { "numPriorities", "t125.numPriorities",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t125_minThroughput,
      { "minThroughput", "t125.minThroughput",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t125_maxHeight,
      { "maxHeight", "t125.maxHeight",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t125_maxMCSPDUsize,
      { "maxMCSPDUsize", "t125.maxMCSPDUsize",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t125_protocolVersion,
      { "protocolVersion", "t125.protocolVersion",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t125_callingDomainSelector,
      { "callingDomainSelector", "t125.callingDomainSelector",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_t125_calledDomainSelector,
      { "calledDomainSelector", "t125.calledDomainSelector",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_t125_upwardFlag,
      { "upwardFlag", "t125.upwardFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t125_targetParameters,
      { "targetParameters", "t125.targetParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DomainParameters", HFILL }},
    { &hf_t125_minimumParameters,
      { "minimumParameters", "t125.minimumParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DomainParameters", HFILL }},
    { &hf_t125_maximumParameters,
      { "maximumParameters", "t125.maximumParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DomainParameters", HFILL }},
    { &hf_t125_userData,
      { "userData", "t125.userData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_result,
      { "result", "t125.result",
        FT_UINT32, BASE_DEC, VALS(t125_Result_vals), 0,
        NULL, HFILL }},
    { &hf_t125_calledConnectId,
      { "calledConnectId", "t125.calledConnectId",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t125_domainParameters,
      { "domainParameters", "t125.domainParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_userData_01,
      { "userData", "t125.userData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_userData_01", HFILL }},
    { &hf_t125_dataPriority,
      { "dataPriority", "t125.dataPriority",
        FT_UINT32, BASE_DEC, VALS(t125_DataPriority_vals), 0,
        NULL, HFILL }},
    { &hf_t125_connect_initial,
      { "connect-initial", "t125.connect_initial_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_connect_response,
      { "connect-response", "t125.connect_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_connect_additional,
      { "connect-additional", "t125.connect_additional_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_connect_result,
      { "connect-result", "t125.connect_result_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
	  &ett_t125,
    &ett_t125_DomainParameters,
    &ett_t125_Connect_Initial_U,
    &ett_t125_Connect_Response_U,
    &ett_t125_Connect_Additional_U,
    &ett_t125_Connect_Result_U,
    &ett_t125_ConnectMCSPDU,
  };

  /* Register protocol */
  proto_t125 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_t125, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  t125_heur_subdissector_list= register_heur_dissector_list_with_description("t125", "T.125 User data", proto_t125);

  register_dissector("t125", dissect_t125, proto_t125);
}


/*--- proto_reg_handoff_t125 ---------------------------------------*/
void proto_reg_handoff_t125(void) {

  heur_dissector_add("cotp", dissect_t125_heur, "T.125 over COTP", "t125_cotp", proto_t125, HEURISTIC_ENABLE);
  heur_dissector_add("cotp_is", dissect_t125_heur, "T.125 over COTP (inactive subset)", "t125_cotp_is", proto_t125, HEURISTIC_ENABLE);
}
