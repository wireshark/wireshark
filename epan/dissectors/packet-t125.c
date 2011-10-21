/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-t125.c                                                              */
/* ../../tools/asn2wrs.py -b -p t125 -c ./t125.cnf -s ./packet-t125-template -D . -O ../../epan/dissectors MCS-PROTOCOL.asn */

/* Input file: packet-t125-template.c */

#line 1 "../../asn1/t125/packet-t125-template.c"
/* packet-t125.c
 * Routines for t125 packet dissection
 * Copyright 2007, Ronnie Sahlberg
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
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <epan/asn1.h>
#include "packet-ber.h"
#include "packet-per.h"

#include "packet-t124.h"

#define PNAME  "MULTIPOINT-COMMUNICATION-SERVICE T.125"
#define PSNAME "T.125"
#define PFNAME "t125"


/* Initialize the protocol and registered fields */
static int proto_t125 = -1;
static proto_tree *top_tree = NULL;

/*--- Included file: packet-t125-hf.c ---*/
#line 1 "../../asn1/t125/packet-t125-hf.c"
static int hf_t125_ConnectMCSPDU_PDU = -1;        /* ConnectMCSPDU */
static int hf_t125_maxChannelIds = -1;            /* INTEGER_0_MAX */
static int hf_t125_maxUserIds = -1;               /* INTEGER_0_MAX */
static int hf_t125_maxTokenIds = -1;              /* INTEGER_0_MAX */
static int hf_t125_numPriorities = -1;            /* INTEGER_0_MAX */
static int hf_t125_minThroughput = -1;            /* INTEGER_0_MAX */
static int hf_t125_maxHeight = -1;                /* INTEGER_0_MAX */
static int hf_t125_maxMCSPDUsize = -1;            /* INTEGER_0_MAX */
static int hf_t125_protocolVersion = -1;          /* INTEGER_0_MAX */
static int hf_t125_callingDomainSelector = -1;    /* OCTET_STRING */
static int hf_t125_calledDomainSelector = -1;     /* OCTET_STRING */
static int hf_t125_upwardFlag = -1;               /* BOOLEAN */
static int hf_t125_targetParameters = -1;         /* DomainParameters */
static int hf_t125_minimumParameters = -1;        /* DomainParameters */
static int hf_t125_maximumParameters = -1;        /* DomainParameters */
static int hf_t125_userData = -1;                 /* T_userData */
static int hf_t125_result = -1;                   /* Result */
static int hf_t125_calledConnectId = -1;          /* INTEGER_0_MAX */
static int hf_t125_domainParameters = -1;         /* DomainParameters */
static int hf_t125_userData_01 = -1;              /* T_userData_01 */
static int hf_t125_dataPriority = -1;             /* DataPriority */
static int hf_t125_heightLimit = -1;              /* INTEGER_0_MAX */
static int hf_t125_subHeight = -1;                /* INTEGER_0_MAX */
static int hf_t125_subInterval = -1;              /* INTEGER_0_MAX */
static int hf_t125_static = -1;                   /* T_static */
static int hf_t125_channelId = -1;                /* StaticChannelId */
static int hf_t125_userId = -1;                   /* T_userId */
static int hf_t125_joined = -1;                   /* BOOLEAN */
static int hf_t125_userId_01 = -1;                /* UserId */
static int hf_t125_private = -1;                  /* T_private */
static int hf_t125_channelId_01 = -1;             /* PrivateChannelId */
static int hf_t125_manager = -1;                  /* UserId */
static int hf_t125_admitted = -1;                 /* SET_OF_UserId */
static int hf_t125_admitted_item = -1;            /* UserId */
static int hf_t125_assigned = -1;                 /* T_assigned */
static int hf_t125_channelId_02 = -1;             /* AssignedChannelId */
static int hf_t125_mergeChannels = -1;            /* SET_OF_ChannelAttributes */
static int hf_t125_mergeChannels_item = -1;       /* ChannelAttributes */
static int hf_t125_purgeChannelIds = -1;          /* SET_OF_ChannelId */
static int hf_t125_purgeChannelIds_item = -1;     /* ChannelId */
static int hf_t125_detachUserIds = -1;            /* SET_OF_UserId */
static int hf_t125_detachUserIds_item = -1;       /* UserId */
static int hf_t125_grabbed = -1;                  /* T_grabbed */
static int hf_t125_tokenId = -1;                  /* TokenId */
static int hf_t125_grabber = -1;                  /* UserId */
static int hf_t125_inhibited = -1;                /* T_inhibited */
static int hf_t125_inhibitors = -1;               /* SET_OF_UserId */
static int hf_t125_inhibitors_item = -1;          /* UserId */
static int hf_t125_giving = -1;                   /* T_giving */
static int hf_t125_recipient = -1;                /* UserId */
static int hf_t125_ungivable = -1;                /* T_ungivable */
static int hf_t125_given = -1;                    /* T_given */
static int hf_t125_mergeTokens = -1;              /* SET_OF_TokenAttributes */
static int hf_t125_mergeTokens_item = -1;         /* TokenAttributes */
static int hf_t125_purgeTokenIds = -1;            /* SET_OF_TokenId */
static int hf_t125_purgeTokenIds_item = -1;       /* TokenId */
static int hf_t125_reason = -1;                   /* Reason */
static int hf_t125_diagnostic = -1;               /* Diagnostic */
static int hf_t125_initialOctets = -1;            /* OCTET_STRING */
static int hf_t125_initiator = -1;                /* UserId */
static int hf_t125_userIds = -1;                  /* SET_OF_UserId */
static int hf_t125_userIds_item = -1;             /* UserId */
static int hf_t125_channelId_03 = -1;             /* ChannelId */
static int hf_t125_requested = -1;                /* ChannelId */
static int hf_t125_channelIds = -1;               /* SET_OF_ChannelId */
static int hf_t125_channelIds_item = -1;          /* ChannelId */
static int hf_t125_segmentation = -1;             /* Segmentation */
static int hf_t125_userData_02 = -1;              /* OCTET_STRING */
static int hf_t125_tokenStatus = -1;              /* TokenStatus */
static int hf_t125_connect_initial = -1;          /* Connect_Initial */
static int hf_t125_connect_response = -1;         /* Connect_Response */
static int hf_t125_connect_additional = -1;       /* Connect_Additional */
static int hf_t125_connect_result = -1;           /* Connect_Result */
static int hf_t125_plumbDomainIndication = -1;    /* PlumbDomainIndication */
static int hf_t125_erectDomainRequest = -1;       /* ErectDomainRequest */
static int hf_t125_mergeChannelsRequest = -1;     /* MergeChannelsRequest */
static int hf_t125_mergeChannelsConfirm = -1;     /* MergeChannelsConfirm */
static int hf_t125_purgeChannelsIndication = -1;  /* PurgeChannelsIndication */
static int hf_t125_mergeTokensRequest = -1;       /* MergeTokensRequest */
static int hf_t125_mergeTokensConfirm = -1;       /* MergeTokensConfirm */
static int hf_t125_purgeTokensIndication = -1;    /* PurgeTokensIndication */
static int hf_t125_disconnectProviderUltimatum = -1;  /* DisconnectProviderUltimatum */
static int hf_t125_rejectMCSPDUUltimatum = -1;    /* RejectMCSPDUUltimatum */
static int hf_t125_attachUserRequest = -1;        /* AttachUserRequest */
static int hf_t125_attachUserConfirm = -1;        /* AttachUserConfirm */
static int hf_t125_detachUserRequest = -1;        /* DetachUserRequest */
static int hf_t125_detachUserIndication = -1;     /* DetachUserIndication */
static int hf_t125_channelJoinRequest = -1;       /* ChannelJoinRequest */
static int hf_t125_channelJoinConfirm = -1;       /* ChannelJoinConfirm */
static int hf_t125_channelLeaveRequest = -1;      /* ChannelLeaveRequest */
static int hf_t125_channelConveneRequest = -1;    /* ChannelConveneRequest */
static int hf_t125_channelConveneConfirm = -1;    /* ChannelConveneConfirm */
static int hf_t125_channelDisbandRequest = -1;    /* ChannelDisbandRequest */
static int hf_t125_channelDisbandIndication = -1;  /* ChannelDisbandIndication */
static int hf_t125_channelAdmitRequest = -1;      /* ChannelAdmitRequest */
static int hf_t125_channelAdmitIndication = -1;   /* ChannelAdmitIndication */
static int hf_t125_channelExpelRequest = -1;      /* ChannelExpelRequest */
static int hf_t125_channelExpelIndication = -1;   /* ChannelExpelIndication */
static int hf_t125_sendDataRequest = -1;          /* SendDataRequest */
static int hf_t125_sendDataIndication = -1;       /* SendDataIndication */
static int hf_t125_uniformSendDataRequest = -1;   /* UniformSendDataRequest */
static int hf_t125_uniformSendDataIndication = -1;  /* UniformSendDataIndication */
static int hf_t125_tokenGrabRequest = -1;         /* TokenGrabRequest */
static int hf_t125_tokenGrabConfirm = -1;         /* TokenGrabConfirm */
static int hf_t125_tokenInhibitRequest = -1;      /* TokenInhibitRequest */
static int hf_t125_tokenInhibitConfirm = -1;      /* TokenInhibitConfirm */
static int hf_t125_tokenGiveRequest = -1;         /* TokenGiveRequest */
static int hf_t125_tokenGiveIndication = -1;      /* TokenGiveIndication */
static int hf_t125_tokenGiveResponse = -1;        /* TokenGiveResponse */
static int hf_t125_tokenGiveConfirm = -1;         /* TokenGiveConfirm */
static int hf_t125_tokenPleaseRequest = -1;       /* TokenPleaseRequest */
static int hf_t125_tokenPleaseIndication = -1;    /* TokenPleaseIndication */
static int hf_t125_tokenReleaseRequest = -1;      /* TokenReleaseRequest */
static int hf_t125_tokenReleaseConfirm = -1;      /* TokenReleaseConfirm */
static int hf_t125_tokenTestRequest = -1;         /* TokenTestRequest */
static int hf_t125_tokenTestConfirm = -1;         /* TokenTestConfirm */
/* named bits */
static int hf_t125_Segmentation_begin = -1;
static int hf_t125_Segmentation_end = -1;

/*--- End of included file: packet-t125-hf.c ---*/
#line 49 "../../asn1/t125/packet-t125-template.c"

/* Initialize the subtree pointers */
static int ett_t125 = -1;

static int hf_t125_connectData = -1;
static int hf_t125_heur = -1;


/*--- Included file: packet-t125-ett.c ---*/
#line 1 "../../asn1/t125/packet-t125-ett.c"
static gint ett_t125_Segmentation = -1;
static gint ett_t125_DomainParameters = -1;
static gint ett_t125_Connect_Initial_U = -1;
static gint ett_t125_Connect_Response_U = -1;
static gint ett_t125_Connect_Additional_U = -1;
static gint ett_t125_Connect_Result_U = -1;
static gint ett_t125_PlumbDomainIndication_U = -1;
static gint ett_t125_ErectDomainRequest_U = -1;
static gint ett_t125_ChannelAttributes = -1;
static gint ett_t125_T_static = -1;
static gint ett_t125_T_userId = -1;
static gint ett_t125_T_private = -1;
static gint ett_t125_SET_OF_UserId = -1;
static gint ett_t125_T_assigned = -1;
static gint ett_t125_MergeChannelsRequest_U = -1;
static gint ett_t125_SET_OF_ChannelAttributes = -1;
static gint ett_t125_SET_OF_ChannelId = -1;
static gint ett_t125_MergeChannelsConfirm_U = -1;
static gint ett_t125_PurgeChannelsIndication_U = -1;
static gint ett_t125_TokenAttributes = -1;
static gint ett_t125_T_grabbed = -1;
static gint ett_t125_T_inhibited = -1;
static gint ett_t125_T_giving = -1;
static gint ett_t125_T_ungivable = -1;
static gint ett_t125_T_given = -1;
static gint ett_t125_MergeTokensRequest_U = -1;
static gint ett_t125_SET_OF_TokenAttributes = -1;
static gint ett_t125_SET_OF_TokenId = -1;
static gint ett_t125_MergeTokensConfirm_U = -1;
static gint ett_t125_PurgeTokensIndication_U = -1;
static gint ett_t125_DisconnectProviderUltimatum_U = -1;
static gint ett_t125_RejectMCSPDUUltimatum_U = -1;
static gint ett_t125_AttachUserRequest_U = -1;
static gint ett_t125_AttachUserConfirm_U = -1;
static gint ett_t125_DetachUserRequest_U = -1;
static gint ett_t125_DetachUserIndication_U = -1;
static gint ett_t125_ChannelJoinRequest_U = -1;
static gint ett_t125_ChannelJoinConfirm_U = -1;
static gint ett_t125_ChannelLeaveRequest_U = -1;
static gint ett_t125_ChannelConveneRequest_U = -1;
static gint ett_t125_ChannelConveneConfirm_U = -1;
static gint ett_t125_ChannelDisbandRequest_U = -1;
static gint ett_t125_ChannelDisbandIndication_U = -1;
static gint ett_t125_ChannelAdmitRequest_U = -1;
static gint ett_t125_ChannelAdmitIndication_U = -1;
static gint ett_t125_ChannelExpelRequest_U = -1;
static gint ett_t125_ChannelExpelIndication_U = -1;
static gint ett_t125_SendDataRequest_U = -1;
static gint ett_t125_SendDataIndication_U = -1;
static gint ett_t125_UniformSendDataRequest_U = -1;
static gint ett_t125_UniformSendDataIndication_U = -1;
static gint ett_t125_TokenGrabRequest_U = -1;
static gint ett_t125_TokenGrabConfirm_U = -1;
static gint ett_t125_TokenInhibitRequest_U = -1;
static gint ett_t125_TokenInhibitConfirm_U = -1;
static gint ett_t125_TokenGiveRequest_U = -1;
static gint ett_t125_TokenGiveIndication_U = -1;
static gint ett_t125_TokenGiveResponse_U = -1;
static gint ett_t125_TokenGiveConfirm_U = -1;
static gint ett_t125_TokenPleaseRequest_U = -1;
static gint ett_t125_TokenPleaseIndication_U = -1;
static gint ett_t125_TokenReleaseRequest_U = -1;
static gint ett_t125_TokenReleaseConfirm_U = -1;
static gint ett_t125_TokenTestRequest_U = -1;
static gint ett_t125_TokenTestConfirm_U = -1;
static gint ett_t125_ConnectMCSPDU = -1;
static gint ett_t125_DomainMCSPDU = -1;

/*--- End of included file: packet-t125-ett.c ---*/
#line 57 "../../asn1/t125/packet-t125-template.c"

static heur_dissector_list_t t125_heur_subdissector_list;


/*--- Included file: packet-t125-fn.c ---*/
#line 1 "../../asn1/t125/packet-t125-fn.c"


static int
dissect_t125_ChannelId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_t125_StaticChannelId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_t125_ChannelId(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_t125_DynamicChannelId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_t125_ChannelId(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_t125_UserId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_t125_DynamicChannelId(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_t125_PrivateChannelId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_t125_DynamicChannelId(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_t125_AssignedChannelId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_t125_DynamicChannelId(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_t125_TokenId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string t125_TokenStatus_vals[] = {
  {   0, "notInUse" },
  {   1, "selfGrabbed" },
  {   2, "otherGrabbed" },
  {   3, "selfInhibited" },
  {   4, "otherInhibited" },
  {   5, "selfRecipient" },
  {   6, "selfGiving" },
  {   7, "otherGiving" },
  { 0, NULL }
};


static int
dissect_t125_TokenStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string t125_DataPriority_vals[] = {
  {   0, "top" },
  {   1, "high" },
  {   2, "medium" },
  {   3, "low" },
  { 0, NULL }
};


static int
dissect_t125_DataPriority(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const asn_namedbit Segmentation_bits[] = {
  {  0, &hf_t125_Segmentation_begin, -1, -1, "begin", NULL },
  {  1, &hf_t125_Segmentation_end, -1, -1, "end", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_t125_Segmentation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Segmentation_bits, hf_index, ett_t125_Segmentation,
                                    NULL);

  return offset;
}



static int
dissect_t125_INTEGER_0_MAX(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
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
dissect_t125_DomainParameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DomainParameters_sequence, hf_index, ett_t125_DomainParameters);

  return offset;
}



static int
dissect_t125_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_t125_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_t125_T_userData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 39 "../../asn1/t125/t125.cnf"
    tvbuff_t	*next_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &next_tvb);

    if(next_tvb) 
    	dissector_try_heuristic(t125_heur_subdissector_list, next_tvb,
	     actx->pinfo, top_tree);


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
dissect_t125_Connect_Initial_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Connect_Initial_U_sequence, hf_index, ett_t125_Connect_Initial_U);

  return offset;
}



static int
dissect_t125_Connect_Initial(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 101, TRUE, dissect_t125_Connect_Initial_U);

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
dissect_t125_Result(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_t125_T_userData_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 48 "../../asn1/t125/t125.cnf"
    tvbuff_t	*next_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &next_tvb);

    if(next_tvb) 
    	dissector_try_heuristic(t125_heur_subdissector_list, next_tvb,
	     actx->pinfo, top_tree);


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
dissect_t125_Connect_Response_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Connect_Response_U_sequence, hf_index, ett_t125_Connect_Response_U);

  return offset;
}



static int
dissect_t125_Connect_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 102, TRUE, dissect_t125_Connect_Response_U);

  return offset;
}


static const ber_sequence_t Connect_Additional_U_sequence[] = {
  { &hf_t125_calledConnectId, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_INTEGER_0_MAX },
  { &hf_t125_dataPriority   , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t125_DataPriority },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_Connect_Additional_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Connect_Additional_U_sequence, hf_index, ett_t125_Connect_Additional_U);

  return offset;
}



static int
dissect_t125_Connect_Additional(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 103, TRUE, dissect_t125_Connect_Additional_U);

  return offset;
}


static const ber_sequence_t Connect_Result_U_sequence[] = {
  { &hf_t125_result         , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t125_Result },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_Connect_Result_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Connect_Result_U_sequence, hf_index, ett_t125_Connect_Result_U);

  return offset;
}



static int
dissect_t125_Connect_Result(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 104, TRUE, dissect_t125_Connect_Result_U);

  return offset;
}


static const ber_sequence_t PlumbDomainIndication_U_sequence[] = {
  { &hf_t125_heightLimit    , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_INTEGER_0_MAX },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_PlumbDomainIndication_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PlumbDomainIndication_U_sequence, hf_index, ett_t125_PlumbDomainIndication_U);

  return offset;
}



static int
dissect_t125_PlumbDomainIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 0, TRUE, dissect_t125_PlumbDomainIndication_U);

  return offset;
}


static const ber_sequence_t ErectDomainRequest_U_sequence[] = {
  { &hf_t125_subHeight      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_INTEGER_0_MAX },
  { &hf_t125_subInterval    , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_INTEGER_0_MAX },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_ErectDomainRequest_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ErectDomainRequest_U_sequence, hf_index, ett_t125_ErectDomainRequest_U);

  return offset;
}



static int
dissect_t125_ErectDomainRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 1, TRUE, dissect_t125_ErectDomainRequest_U);

  return offset;
}


static const ber_sequence_t T_static_sequence[] = {
  { &hf_t125_channelId      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_StaticChannelId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_T_static(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_static_sequence, hf_index, ett_t125_T_static);

  return offset;
}


static const ber_sequence_t T_userId_sequence[] = {
  { &hf_t125_joined         , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_t125_BOOLEAN },
  { &hf_t125_userId_01      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_T_userId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_userId_sequence, hf_index, ett_t125_T_userId);

  return offset;
}


static const ber_sequence_t SET_OF_UserId_set_of[1] = {
  { &hf_t125_admitted_item  , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
};

static int
dissect_t125_SET_OF_UserId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_UserId_set_of, hf_index, ett_t125_SET_OF_UserId);

  return offset;
}


static const ber_sequence_t T_private_sequence[] = {
  { &hf_t125_joined         , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_t125_BOOLEAN },
  { &hf_t125_channelId_01   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_PrivateChannelId },
  { &hf_t125_manager        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_admitted       , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_t125_SET_OF_UserId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_T_private(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_private_sequence, hf_index, ett_t125_T_private);

  return offset;
}


static const ber_sequence_t T_assigned_sequence[] = {
  { &hf_t125_channelId_02   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_AssignedChannelId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_T_assigned(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_assigned_sequence, hf_index, ett_t125_T_assigned);

  return offset;
}


static const value_string t125_ChannelAttributes_vals[] = {
  {   0, "static" },
  {   1, "userId" },
  {   2, "private" },
  {   3, "assigned" },
  { 0, NULL }
};

static const ber_choice_t ChannelAttributes_choice[] = {
  {   0, &hf_t125_static         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_t125_T_static },
  {   1, &hf_t125_userId         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_t125_T_userId },
  {   2, &hf_t125_private        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_t125_T_private },
  {   3, &hf_t125_assigned       , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_t125_T_assigned },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_ChannelAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChannelAttributes_choice, hf_index, ett_t125_ChannelAttributes,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_ChannelAttributes_set_of[1] = {
  { &hf_t125_mergeChannels_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_t125_ChannelAttributes },
};

static int
dissect_t125_SET_OF_ChannelAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_ChannelAttributes_set_of, hf_index, ett_t125_SET_OF_ChannelAttributes);

  return offset;
}


static const ber_sequence_t SET_OF_ChannelId_set_of[1] = {
  { &hf_t125_purgeChannelIds_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_ChannelId },
};

static int
dissect_t125_SET_OF_ChannelId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_ChannelId_set_of, hf_index, ett_t125_SET_OF_ChannelId);

  return offset;
}


static const ber_sequence_t MergeChannelsRequest_U_sequence[] = {
  { &hf_t125_mergeChannels  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_t125_SET_OF_ChannelAttributes },
  { &hf_t125_purgeChannelIds, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_t125_SET_OF_ChannelId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_MergeChannelsRequest_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MergeChannelsRequest_U_sequence, hf_index, ett_t125_MergeChannelsRequest_U);

  return offset;
}



static int
dissect_t125_MergeChannelsRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 2, TRUE, dissect_t125_MergeChannelsRequest_U);

  return offset;
}


static const ber_sequence_t MergeChannelsConfirm_U_sequence[] = {
  { &hf_t125_mergeChannels  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_t125_SET_OF_ChannelAttributes },
  { &hf_t125_purgeChannelIds, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_t125_SET_OF_ChannelId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_MergeChannelsConfirm_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MergeChannelsConfirm_U_sequence, hf_index, ett_t125_MergeChannelsConfirm_U);

  return offset;
}



static int
dissect_t125_MergeChannelsConfirm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 3, TRUE, dissect_t125_MergeChannelsConfirm_U);

  return offset;
}


static const ber_sequence_t PurgeChannelsIndication_U_sequence[] = {
  { &hf_t125_detachUserIds  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_t125_SET_OF_UserId },
  { &hf_t125_purgeChannelIds, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_t125_SET_OF_ChannelId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_PurgeChannelsIndication_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PurgeChannelsIndication_U_sequence, hf_index, ett_t125_PurgeChannelsIndication_U);

  return offset;
}



static int
dissect_t125_PurgeChannelsIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 4, TRUE, dissect_t125_PurgeChannelsIndication_U);

  return offset;
}


static const ber_sequence_t T_grabbed_sequence[] = {
  { &hf_t125_tokenId        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_TokenId },
  { &hf_t125_grabber        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_T_grabbed(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_grabbed_sequence, hf_index, ett_t125_T_grabbed);

  return offset;
}


static const ber_sequence_t T_inhibited_sequence[] = {
  { &hf_t125_tokenId        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_TokenId },
  { &hf_t125_inhibitors     , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_t125_SET_OF_UserId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_T_inhibited(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_inhibited_sequence, hf_index, ett_t125_T_inhibited);

  return offset;
}


static const ber_sequence_t T_giving_sequence[] = {
  { &hf_t125_tokenId        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_TokenId },
  { &hf_t125_grabber        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_recipient      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_T_giving(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_giving_sequence, hf_index, ett_t125_T_giving);

  return offset;
}


static const ber_sequence_t T_ungivable_sequence[] = {
  { &hf_t125_tokenId        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_TokenId },
  { &hf_t125_grabber        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_T_ungivable(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_ungivable_sequence, hf_index, ett_t125_T_ungivable);

  return offset;
}


static const ber_sequence_t T_given_sequence[] = {
  { &hf_t125_tokenId        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_TokenId },
  { &hf_t125_recipient      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_T_given(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_given_sequence, hf_index, ett_t125_T_given);

  return offset;
}


static const value_string t125_TokenAttributes_vals[] = {
  {   0, "grabbed" },
  {   1, "inhibited" },
  {   2, "giving" },
  {   3, "ungivable" },
  {   4, "given" },
  { 0, NULL }
};

static const ber_choice_t TokenAttributes_choice[] = {
  {   0, &hf_t125_grabbed        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_t125_T_grabbed },
  {   1, &hf_t125_inhibited      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_t125_T_inhibited },
  {   2, &hf_t125_giving         , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_t125_T_giving },
  {   3, &hf_t125_ungivable      , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_t125_T_ungivable },
  {   4, &hf_t125_given          , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_t125_T_given },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_TokenAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TokenAttributes_choice, hf_index, ett_t125_TokenAttributes,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_TokenAttributes_set_of[1] = {
  { &hf_t125_mergeTokens_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_t125_TokenAttributes },
};

static int
dissect_t125_SET_OF_TokenAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_TokenAttributes_set_of, hf_index, ett_t125_SET_OF_TokenAttributes);

  return offset;
}


static const ber_sequence_t SET_OF_TokenId_set_of[1] = {
  { &hf_t125_purgeTokenIds_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_TokenId },
};

static int
dissect_t125_SET_OF_TokenId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_TokenId_set_of, hf_index, ett_t125_SET_OF_TokenId);

  return offset;
}


static const ber_sequence_t MergeTokensRequest_U_sequence[] = {
  { &hf_t125_mergeTokens    , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_t125_SET_OF_TokenAttributes },
  { &hf_t125_purgeTokenIds  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_t125_SET_OF_TokenId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_MergeTokensRequest_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MergeTokensRequest_U_sequence, hf_index, ett_t125_MergeTokensRequest_U);

  return offset;
}



static int
dissect_t125_MergeTokensRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 5, TRUE, dissect_t125_MergeTokensRequest_U);

  return offset;
}


static const ber_sequence_t MergeTokensConfirm_U_sequence[] = {
  { &hf_t125_mergeTokens    , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_t125_SET_OF_TokenAttributes },
  { &hf_t125_purgeTokenIds  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_t125_SET_OF_TokenId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_MergeTokensConfirm_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MergeTokensConfirm_U_sequence, hf_index, ett_t125_MergeTokensConfirm_U);

  return offset;
}



static int
dissect_t125_MergeTokensConfirm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 6, TRUE, dissect_t125_MergeTokensConfirm_U);

  return offset;
}


static const ber_sequence_t PurgeTokensIndication_U_sequence[] = {
  { &hf_t125_purgeTokenIds  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_t125_SET_OF_TokenId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_PurgeTokensIndication_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PurgeTokensIndication_U_sequence, hf_index, ett_t125_PurgeTokensIndication_U);

  return offset;
}



static int
dissect_t125_PurgeTokensIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 7, TRUE, dissect_t125_PurgeTokensIndication_U);

  return offset;
}


static const value_string t125_Reason_vals[] = {
  {   0, "rn-domain-disconnected" },
  {   1, "rn-provider-initiated" },
  {   2, "rn-token-purged" },
  {   3, "rn-user-requested" },
  {   4, "rn-channel-purged" },
  { 0, NULL }
};


static int
dissect_t125_Reason(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t DisconnectProviderUltimatum_U_sequence[] = {
  { &hf_t125_reason         , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t125_Reason },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_DisconnectProviderUltimatum_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DisconnectProviderUltimatum_U_sequence, hf_index, ett_t125_DisconnectProviderUltimatum_U);

  return offset;
}



static int
dissect_t125_DisconnectProviderUltimatum(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 8, TRUE, dissect_t125_DisconnectProviderUltimatum_U);

  return offset;
}


static const value_string t125_Diagnostic_vals[] = {
  {   0, "dc-inconsistent-merge" },
  {   1, "dc-forbidden-PDU-downward" },
  {   2, "dc-forbidden-PDU-upward" },
  {   3, "dc-invalid-BER-encoding" },
  {   4, "dc-invalid-PER-encoding" },
  {   5, "dc-misrouted-user" },
  {   6, "dc-unrequested-confirm" },
  {   7, "dc-wrong-transport-priority" },
  {   8, "dc-channel-id-conflict" },
  {   9, "dc-token-id-conflict" },
  {  10, "dc-not-user-id-channel" },
  {  11, "dc-too-many-channels" },
  {  12, "dc-too-many-tokens" },
  {  13, "dc-too-many-users" },
  { 0, NULL }
};


static int
dissect_t125_Diagnostic(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t RejectMCSPDUUltimatum_U_sequence[] = {
  { &hf_t125_diagnostic     , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t125_Diagnostic },
  { &hf_t125_initialOctets  , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_t125_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_RejectMCSPDUUltimatum_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RejectMCSPDUUltimatum_U_sequence, hf_index, ett_t125_RejectMCSPDUUltimatum_U);

  return offset;
}



static int
dissect_t125_RejectMCSPDUUltimatum(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 9, TRUE, dissect_t125_RejectMCSPDUUltimatum_U);

  return offset;
}


static const ber_sequence_t AttachUserRequest_U_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_AttachUserRequest_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttachUserRequest_U_sequence, hf_index, ett_t125_AttachUserRequest_U);

  return offset;
}



static int
dissect_t125_AttachUserRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 10, TRUE, dissect_t125_AttachUserRequest_U);

  return offset;
}


static const ber_sequence_t AttachUserConfirm_U_sequence[] = {
  { &hf_t125_result         , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t125_Result },
  { &hf_t125_initiator      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_AttachUserConfirm_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttachUserConfirm_U_sequence, hf_index, ett_t125_AttachUserConfirm_U);

  return offset;
}



static int
dissect_t125_AttachUserConfirm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 11, TRUE, dissect_t125_AttachUserConfirm_U);

  return offset;
}


static const ber_sequence_t DetachUserRequest_U_sequence[] = {
  { &hf_t125_reason         , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t125_Reason },
  { &hf_t125_userIds        , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_t125_SET_OF_UserId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_DetachUserRequest_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DetachUserRequest_U_sequence, hf_index, ett_t125_DetachUserRequest_U);

  return offset;
}



static int
dissect_t125_DetachUserRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 12, TRUE, dissect_t125_DetachUserRequest_U);

  return offset;
}


static const ber_sequence_t DetachUserIndication_U_sequence[] = {
  { &hf_t125_reason         , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t125_Reason },
  { &hf_t125_userIds        , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_t125_SET_OF_UserId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_DetachUserIndication_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DetachUserIndication_U_sequence, hf_index, ett_t125_DetachUserIndication_U);

  return offset;
}



static int
dissect_t125_DetachUserIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 13, TRUE, dissect_t125_DetachUserIndication_U);

  return offset;
}


static const ber_sequence_t ChannelJoinRequest_U_sequence[] = {
  { &hf_t125_initiator      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_channelId_03   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_ChannelId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_ChannelJoinRequest_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChannelJoinRequest_U_sequence, hf_index, ett_t125_ChannelJoinRequest_U);

  return offset;
}



static int
dissect_t125_ChannelJoinRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 14, TRUE, dissect_t125_ChannelJoinRequest_U);

  return offset;
}


static const ber_sequence_t ChannelJoinConfirm_U_sequence[] = {
  { &hf_t125_result         , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t125_Result },
  { &hf_t125_initiator      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_requested      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_ChannelId },
  { &hf_t125_channelId_03   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_t125_ChannelId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_ChannelJoinConfirm_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChannelJoinConfirm_U_sequence, hf_index, ett_t125_ChannelJoinConfirm_U);

  return offset;
}



static int
dissect_t125_ChannelJoinConfirm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 15, TRUE, dissect_t125_ChannelJoinConfirm_U);

  return offset;
}


static const ber_sequence_t ChannelLeaveRequest_U_sequence[] = {
  { &hf_t125_channelIds     , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_t125_SET_OF_ChannelId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_ChannelLeaveRequest_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChannelLeaveRequest_U_sequence, hf_index, ett_t125_ChannelLeaveRequest_U);

  return offset;
}



static int
dissect_t125_ChannelLeaveRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 16, TRUE, dissect_t125_ChannelLeaveRequest_U);

  return offset;
}


static const ber_sequence_t ChannelConveneRequest_U_sequence[] = {
  { &hf_t125_initiator      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_ChannelConveneRequest_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChannelConveneRequest_U_sequence, hf_index, ett_t125_ChannelConveneRequest_U);

  return offset;
}



static int
dissect_t125_ChannelConveneRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 17, TRUE, dissect_t125_ChannelConveneRequest_U);

  return offset;
}


static const ber_sequence_t ChannelConveneConfirm_U_sequence[] = {
  { &hf_t125_result         , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t125_Result },
  { &hf_t125_initiator      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_channelId_01   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_t125_PrivateChannelId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_ChannelConveneConfirm_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChannelConveneConfirm_U_sequence, hf_index, ett_t125_ChannelConveneConfirm_U);

  return offset;
}



static int
dissect_t125_ChannelConveneConfirm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 18, TRUE, dissect_t125_ChannelConveneConfirm_U);

  return offset;
}


static const ber_sequence_t ChannelDisbandRequest_U_sequence[] = {
  { &hf_t125_initiator      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_channelId_01   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_PrivateChannelId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_ChannelDisbandRequest_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChannelDisbandRequest_U_sequence, hf_index, ett_t125_ChannelDisbandRequest_U);

  return offset;
}



static int
dissect_t125_ChannelDisbandRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 19, TRUE, dissect_t125_ChannelDisbandRequest_U);

  return offset;
}


static const ber_sequence_t ChannelDisbandIndication_U_sequence[] = {
  { &hf_t125_channelId_01   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_PrivateChannelId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_ChannelDisbandIndication_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChannelDisbandIndication_U_sequence, hf_index, ett_t125_ChannelDisbandIndication_U);

  return offset;
}



static int
dissect_t125_ChannelDisbandIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 20, TRUE, dissect_t125_ChannelDisbandIndication_U);

  return offset;
}


static const ber_sequence_t ChannelAdmitRequest_U_sequence[] = {
  { &hf_t125_initiator      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_channelId_01   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_PrivateChannelId },
  { &hf_t125_userIds        , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_t125_SET_OF_UserId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_ChannelAdmitRequest_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChannelAdmitRequest_U_sequence, hf_index, ett_t125_ChannelAdmitRequest_U);

  return offset;
}



static int
dissect_t125_ChannelAdmitRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 21, TRUE, dissect_t125_ChannelAdmitRequest_U);

  return offset;
}


static const ber_sequence_t ChannelAdmitIndication_U_sequence[] = {
  { &hf_t125_initiator      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_channelId_01   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_PrivateChannelId },
  { &hf_t125_userIds        , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_t125_SET_OF_UserId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_ChannelAdmitIndication_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChannelAdmitIndication_U_sequence, hf_index, ett_t125_ChannelAdmitIndication_U);

  return offset;
}



static int
dissect_t125_ChannelAdmitIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 22, TRUE, dissect_t125_ChannelAdmitIndication_U);

  return offset;
}


static const ber_sequence_t ChannelExpelRequest_U_sequence[] = {
  { &hf_t125_initiator      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_channelId_01   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_PrivateChannelId },
  { &hf_t125_userIds        , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_t125_SET_OF_UserId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_ChannelExpelRequest_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChannelExpelRequest_U_sequence, hf_index, ett_t125_ChannelExpelRequest_U);

  return offset;
}



static int
dissect_t125_ChannelExpelRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 23, TRUE, dissect_t125_ChannelExpelRequest_U);

  return offset;
}


static const ber_sequence_t ChannelExpelIndication_U_sequence[] = {
  { &hf_t125_channelId_01   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_PrivateChannelId },
  { &hf_t125_userIds        , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_t125_SET_OF_UserId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_ChannelExpelIndication_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChannelExpelIndication_U_sequence, hf_index, ett_t125_ChannelExpelIndication_U);

  return offset;
}



static int
dissect_t125_ChannelExpelIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 24, TRUE, dissect_t125_ChannelExpelIndication_U);

  return offset;
}


static const ber_sequence_t SendDataRequest_U_sequence[] = {
  { &hf_t125_initiator      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_channelId_03   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_ChannelId },
  { &hf_t125_dataPriority   , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t125_DataPriority },
  { &hf_t125_segmentation   , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_t125_Segmentation },
  { &hf_t125_userData_02    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_t125_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_SendDataRequest_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SendDataRequest_U_sequence, hf_index, ett_t125_SendDataRequest_U);

  return offset;
}



static int
dissect_t125_SendDataRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 25, TRUE, dissect_t125_SendDataRequest_U);

  return offset;
}


static const ber_sequence_t SendDataIndication_U_sequence[] = {
  { &hf_t125_initiator      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_channelId_03   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_ChannelId },
  { &hf_t125_dataPriority   , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t125_DataPriority },
  { &hf_t125_segmentation   , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_t125_Segmentation },
  { &hf_t125_userData_02    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_t125_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_SendDataIndication_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SendDataIndication_U_sequence, hf_index, ett_t125_SendDataIndication_U);

  return offset;
}



static int
dissect_t125_SendDataIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 26, TRUE, dissect_t125_SendDataIndication_U);

  return offset;
}


static const ber_sequence_t UniformSendDataRequest_U_sequence[] = {
  { &hf_t125_initiator      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_channelId_03   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_ChannelId },
  { &hf_t125_dataPriority   , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t125_DataPriority },
  { &hf_t125_segmentation   , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_t125_Segmentation },
  { &hf_t125_userData_02    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_t125_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_UniformSendDataRequest_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UniformSendDataRequest_U_sequence, hf_index, ett_t125_UniformSendDataRequest_U);

  return offset;
}



static int
dissect_t125_UniformSendDataRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 27, TRUE, dissect_t125_UniformSendDataRequest_U);

  return offset;
}


static const ber_sequence_t UniformSendDataIndication_U_sequence[] = {
  { &hf_t125_initiator      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_channelId_03   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_ChannelId },
  { &hf_t125_dataPriority   , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t125_DataPriority },
  { &hf_t125_segmentation   , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_t125_Segmentation },
  { &hf_t125_userData_02    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_t125_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_UniformSendDataIndication_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UniformSendDataIndication_U_sequence, hf_index, ett_t125_UniformSendDataIndication_U);

  return offset;
}



static int
dissect_t125_UniformSendDataIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 28, TRUE, dissect_t125_UniformSendDataIndication_U);

  return offset;
}


static const ber_sequence_t TokenGrabRequest_U_sequence[] = {
  { &hf_t125_initiator      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_tokenId        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_TokenId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_TokenGrabRequest_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TokenGrabRequest_U_sequence, hf_index, ett_t125_TokenGrabRequest_U);

  return offset;
}



static int
dissect_t125_TokenGrabRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 29, TRUE, dissect_t125_TokenGrabRequest_U);

  return offset;
}


static const ber_sequence_t TokenGrabConfirm_U_sequence[] = {
  { &hf_t125_result         , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t125_Result },
  { &hf_t125_initiator      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_tokenId        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_TokenId },
  { &hf_t125_tokenStatus    , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t125_TokenStatus },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_TokenGrabConfirm_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TokenGrabConfirm_U_sequence, hf_index, ett_t125_TokenGrabConfirm_U);

  return offset;
}



static int
dissect_t125_TokenGrabConfirm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 30, TRUE, dissect_t125_TokenGrabConfirm_U);

  return offset;
}


static const ber_sequence_t TokenInhibitRequest_U_sequence[] = {
  { &hf_t125_initiator      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_tokenId        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_TokenId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_TokenInhibitRequest_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TokenInhibitRequest_U_sequence, hf_index, ett_t125_TokenInhibitRequest_U);

  return offset;
}



static int
dissect_t125_TokenInhibitRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 31, TRUE, dissect_t125_TokenInhibitRequest_U);

  return offset;
}


static const ber_sequence_t TokenInhibitConfirm_U_sequence[] = {
  { &hf_t125_result         , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t125_Result },
  { &hf_t125_initiator      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_tokenId        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_TokenId },
  { &hf_t125_tokenStatus    , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t125_TokenStatus },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_TokenInhibitConfirm_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TokenInhibitConfirm_U_sequence, hf_index, ett_t125_TokenInhibitConfirm_U);

  return offset;
}



static int
dissect_t125_TokenInhibitConfirm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 32, TRUE, dissect_t125_TokenInhibitConfirm_U);

  return offset;
}


static const ber_sequence_t TokenGiveRequest_U_sequence[] = {
  { &hf_t125_initiator      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_tokenId        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_TokenId },
  { &hf_t125_recipient      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_TokenGiveRequest_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TokenGiveRequest_U_sequence, hf_index, ett_t125_TokenGiveRequest_U);

  return offset;
}



static int
dissect_t125_TokenGiveRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 33, TRUE, dissect_t125_TokenGiveRequest_U);

  return offset;
}


static const ber_sequence_t TokenGiveIndication_U_sequence[] = {
  { &hf_t125_initiator      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_tokenId        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_TokenId },
  { &hf_t125_recipient      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_TokenGiveIndication_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TokenGiveIndication_U_sequence, hf_index, ett_t125_TokenGiveIndication_U);

  return offset;
}



static int
dissect_t125_TokenGiveIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 34, TRUE, dissect_t125_TokenGiveIndication_U);

  return offset;
}


static const ber_sequence_t TokenGiveResponse_U_sequence[] = {
  { &hf_t125_result         , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t125_Result },
  { &hf_t125_recipient      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_tokenId        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_TokenId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_TokenGiveResponse_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TokenGiveResponse_U_sequence, hf_index, ett_t125_TokenGiveResponse_U);

  return offset;
}



static int
dissect_t125_TokenGiveResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 35, TRUE, dissect_t125_TokenGiveResponse_U);

  return offset;
}


static const ber_sequence_t TokenGiveConfirm_U_sequence[] = {
  { &hf_t125_result         , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t125_Result },
  { &hf_t125_initiator      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_tokenId        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_TokenId },
  { &hf_t125_tokenStatus    , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t125_TokenStatus },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_TokenGiveConfirm_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TokenGiveConfirm_U_sequence, hf_index, ett_t125_TokenGiveConfirm_U);

  return offset;
}



static int
dissect_t125_TokenGiveConfirm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 36, TRUE, dissect_t125_TokenGiveConfirm_U);

  return offset;
}


static const ber_sequence_t TokenPleaseRequest_U_sequence[] = {
  { &hf_t125_initiator      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_tokenId        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_TokenId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_TokenPleaseRequest_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TokenPleaseRequest_U_sequence, hf_index, ett_t125_TokenPleaseRequest_U);

  return offset;
}



static int
dissect_t125_TokenPleaseRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 37, TRUE, dissect_t125_TokenPleaseRequest_U);

  return offset;
}


static const ber_sequence_t TokenPleaseIndication_U_sequence[] = {
  { &hf_t125_initiator      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_tokenId        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_TokenId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_TokenPleaseIndication_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TokenPleaseIndication_U_sequence, hf_index, ett_t125_TokenPleaseIndication_U);

  return offset;
}



static int
dissect_t125_TokenPleaseIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 38, TRUE, dissect_t125_TokenPleaseIndication_U);

  return offset;
}


static const ber_sequence_t TokenReleaseRequest_U_sequence[] = {
  { &hf_t125_initiator      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_tokenId        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_TokenId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_TokenReleaseRequest_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TokenReleaseRequest_U_sequence, hf_index, ett_t125_TokenReleaseRequest_U);

  return offset;
}



static int
dissect_t125_TokenReleaseRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 39, TRUE, dissect_t125_TokenReleaseRequest_U);

  return offset;
}


static const ber_sequence_t TokenReleaseConfirm_U_sequence[] = {
  { &hf_t125_result         , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t125_Result },
  { &hf_t125_initiator      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_tokenId        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_TokenId },
  { &hf_t125_tokenStatus    , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t125_TokenStatus },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_TokenReleaseConfirm_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TokenReleaseConfirm_U_sequence, hf_index, ett_t125_TokenReleaseConfirm_U);

  return offset;
}



static int
dissect_t125_TokenReleaseConfirm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 40, TRUE, dissect_t125_TokenReleaseConfirm_U);

  return offset;
}


static const ber_sequence_t TokenTestRequest_U_sequence[] = {
  { &hf_t125_initiator      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_tokenId        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_TokenId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_TokenTestRequest_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TokenTestRequest_U_sequence, hf_index, ett_t125_TokenTestRequest_U);

  return offset;
}



static int
dissect_t125_TokenTestRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 41, TRUE, dissect_t125_TokenTestRequest_U);

  return offset;
}


static const ber_sequence_t TokenTestConfirm_U_sequence[] = {
  { &hf_t125_initiator      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_UserId },
  { &hf_t125_tokenId        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_t125_TokenId },
  { &hf_t125_tokenStatus    , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t125_TokenStatus },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_TokenTestConfirm_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TokenTestConfirm_U_sequence, hf_index, ett_t125_TokenTestConfirm_U);

  return offset;
}



static int
dissect_t125_TokenTestConfirm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 42, TRUE, dissect_t125_TokenTestConfirm_U);

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
dissect_t125_ConnectMCSPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ConnectMCSPDU_choice, hf_index, ett_t125_ConnectMCSPDU,
                                 NULL);

  return offset;
}


static const value_string t125_DomainMCSPDU_vals[] = {
  {   0, "plumbDomainIndication" },
  {   1, "erectDomainRequest" },
  {   2, "mergeChannelsRequest" },
  {   3, "mergeChannelsConfirm" },
  {   4, "purgeChannelsIndication" },
  {   5, "mergeTokensRequest" },
  {   6, "mergeTokensConfirm" },
  {   7, "purgeTokensIndication" },
  {   8, "disconnectProviderUltimatum" },
  {   9, "rejectMCSPDUUltimatum" },
  {  10, "attachUserRequest" },
  {  11, "attachUserConfirm" },
  {  12, "detachUserRequest" },
  {  13, "detachUserIndication" },
  {  14, "channelJoinRequest" },
  {  15, "channelJoinConfirm" },
  {  16, "channelLeaveRequest" },
  {  17, "channelConveneRequest" },
  {  18, "channelConveneConfirm" },
  {  19, "channelDisbandRequest" },
  {  20, "channelDisbandIndication" },
  {  21, "channelAdmitRequest" },
  {  22, "channelAdmitIndication" },
  {  23, "channelExpelRequest" },
  {  24, "channelExpelIndication" },
  {  25, "sendDataRequest" },
  {  26, "sendDataIndication" },
  {  27, "uniformSendDataRequest" },
  {  28, "uniformSendDataIndication" },
  {  29, "tokenGrabRequest" },
  {  30, "tokenGrabConfirm" },
  {  31, "tokenInhibitRequest" },
  {  32, "tokenInhibitConfirm" },
  {  33, "tokenGiveRequest" },
  {  34, "tokenGiveIndication" },
  {  35, "tokenGiveResponse" },
  {  36, "tokenGiveConfirm" },
  {  37, "tokenPleaseRequest" },
  {  38, "tokenPleaseIndication" },
  {  39, "tokenReleaseRequest" },
  {  40, "tokenReleaseConfirm" },
  {  41, "tokenTestRequest" },
  {  42, "tokenTestConfirm" },
  { 0, NULL }
};

static const ber_choice_t DomainMCSPDU_choice[] = {
  {   0, &hf_t125_plumbDomainIndication, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_t125_PlumbDomainIndication },
  {   1, &hf_t125_erectDomainRequest, BER_CLASS_APP, 1, BER_FLAGS_NOOWNTAG, dissect_t125_ErectDomainRequest },
  {   2, &hf_t125_mergeChannelsRequest, BER_CLASS_APP, 2, BER_FLAGS_NOOWNTAG, dissect_t125_MergeChannelsRequest },
  {   3, &hf_t125_mergeChannelsConfirm, BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_t125_MergeChannelsConfirm },
  {   4, &hf_t125_purgeChannelsIndication, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_t125_PurgeChannelsIndication },
  {   5, &hf_t125_mergeTokensRequest, BER_CLASS_APP, 5, BER_FLAGS_NOOWNTAG, dissect_t125_MergeTokensRequest },
  {   6, &hf_t125_mergeTokensConfirm, BER_CLASS_APP, 6, BER_FLAGS_NOOWNTAG, dissect_t125_MergeTokensConfirm },
  {   7, &hf_t125_purgeTokensIndication, BER_CLASS_APP, 7, BER_FLAGS_NOOWNTAG, dissect_t125_PurgeTokensIndication },
  {   8, &hf_t125_disconnectProviderUltimatum, BER_CLASS_APP, 8, BER_FLAGS_NOOWNTAG, dissect_t125_DisconnectProviderUltimatum },
  {   9, &hf_t125_rejectMCSPDUUltimatum, BER_CLASS_APP, 9, BER_FLAGS_NOOWNTAG, dissect_t125_RejectMCSPDUUltimatum },
  {  10, &hf_t125_attachUserRequest, BER_CLASS_APP, 10, BER_FLAGS_NOOWNTAG, dissect_t125_AttachUserRequest },
  {  11, &hf_t125_attachUserConfirm, BER_CLASS_APP, 11, BER_FLAGS_NOOWNTAG, dissect_t125_AttachUserConfirm },
  {  12, &hf_t125_detachUserRequest, BER_CLASS_APP, 12, BER_FLAGS_NOOWNTAG, dissect_t125_DetachUserRequest },
  {  13, &hf_t125_detachUserIndication, BER_CLASS_APP, 13, BER_FLAGS_NOOWNTAG, dissect_t125_DetachUserIndication },
  {  14, &hf_t125_channelJoinRequest, BER_CLASS_APP, 14, BER_FLAGS_NOOWNTAG, dissect_t125_ChannelJoinRequest },
  {  15, &hf_t125_channelJoinConfirm, BER_CLASS_APP, 15, BER_FLAGS_NOOWNTAG, dissect_t125_ChannelJoinConfirm },
  {  16, &hf_t125_channelLeaveRequest, BER_CLASS_APP, 16, BER_FLAGS_NOOWNTAG, dissect_t125_ChannelLeaveRequest },
  {  17, &hf_t125_channelConveneRequest, BER_CLASS_APP, 17, BER_FLAGS_NOOWNTAG, dissect_t125_ChannelConveneRequest },
  {  18, &hf_t125_channelConveneConfirm, BER_CLASS_APP, 18, BER_FLAGS_NOOWNTAG, dissect_t125_ChannelConveneConfirm },
  {  19, &hf_t125_channelDisbandRequest, BER_CLASS_APP, 19, BER_FLAGS_NOOWNTAG, dissect_t125_ChannelDisbandRequest },
  {  20, &hf_t125_channelDisbandIndication, BER_CLASS_APP, 20, BER_FLAGS_NOOWNTAG, dissect_t125_ChannelDisbandIndication },
  {  21, &hf_t125_channelAdmitRequest, BER_CLASS_APP, 21, BER_FLAGS_NOOWNTAG, dissect_t125_ChannelAdmitRequest },
  {  22, &hf_t125_channelAdmitIndication, BER_CLASS_APP, 22, BER_FLAGS_NOOWNTAG, dissect_t125_ChannelAdmitIndication },
  {  23, &hf_t125_channelExpelRequest, BER_CLASS_APP, 23, BER_FLAGS_NOOWNTAG, dissect_t125_ChannelExpelRequest },
  {  24, &hf_t125_channelExpelIndication, BER_CLASS_APP, 24, BER_FLAGS_NOOWNTAG, dissect_t125_ChannelExpelIndication },
  {  25, &hf_t125_sendDataRequest, BER_CLASS_APP, 25, BER_FLAGS_NOOWNTAG, dissect_t125_SendDataRequest },
  {  26, &hf_t125_sendDataIndication, BER_CLASS_APP, 26, BER_FLAGS_NOOWNTAG, dissect_t125_SendDataIndication },
  {  27, &hf_t125_uniformSendDataRequest, BER_CLASS_APP, 27, BER_FLAGS_NOOWNTAG, dissect_t125_UniformSendDataRequest },
  {  28, &hf_t125_uniformSendDataIndication, BER_CLASS_APP, 28, BER_FLAGS_NOOWNTAG, dissect_t125_UniformSendDataIndication },
  {  29, &hf_t125_tokenGrabRequest, BER_CLASS_APP, 29, BER_FLAGS_NOOWNTAG, dissect_t125_TokenGrabRequest },
  {  30, &hf_t125_tokenGrabConfirm, BER_CLASS_APP, 30, BER_FLAGS_NOOWNTAG, dissect_t125_TokenGrabConfirm },
  {  31, &hf_t125_tokenInhibitRequest, BER_CLASS_APP, 31, BER_FLAGS_NOOWNTAG, dissect_t125_TokenInhibitRequest },
  {  32, &hf_t125_tokenInhibitConfirm, BER_CLASS_APP, 32, BER_FLAGS_NOOWNTAG, dissect_t125_TokenInhibitConfirm },
  {  33, &hf_t125_tokenGiveRequest, BER_CLASS_APP, 33, BER_FLAGS_NOOWNTAG, dissect_t125_TokenGiveRequest },
  {  34, &hf_t125_tokenGiveIndication, BER_CLASS_APP, 34, BER_FLAGS_NOOWNTAG, dissect_t125_TokenGiveIndication },
  {  35, &hf_t125_tokenGiveResponse, BER_CLASS_APP, 35, BER_FLAGS_NOOWNTAG, dissect_t125_TokenGiveResponse },
  {  36, &hf_t125_tokenGiveConfirm, BER_CLASS_APP, 36, BER_FLAGS_NOOWNTAG, dissect_t125_TokenGiveConfirm },
  {  37, &hf_t125_tokenPleaseRequest, BER_CLASS_APP, 37, BER_FLAGS_NOOWNTAG, dissect_t125_TokenPleaseRequest },
  {  38, &hf_t125_tokenPleaseIndication, BER_CLASS_APP, 38, BER_FLAGS_NOOWNTAG, dissect_t125_TokenPleaseIndication },
  {  39, &hf_t125_tokenReleaseRequest, BER_CLASS_APP, 39, BER_FLAGS_NOOWNTAG, dissect_t125_TokenReleaseRequest },
  {  40, &hf_t125_tokenReleaseConfirm, BER_CLASS_APP, 40, BER_FLAGS_NOOWNTAG, dissect_t125_TokenReleaseConfirm },
  {  41, &hf_t125_tokenTestRequest, BER_CLASS_APP, 41, BER_FLAGS_NOOWNTAG, dissect_t125_TokenTestRequest },
  {  42, &hf_t125_tokenTestConfirm, BER_CLASS_APP, 42, BER_FLAGS_NOOWNTAG, dissect_t125_TokenTestConfirm },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_t125_DomainMCSPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 21 "../../asn1/t125/t125.cnf"
  	gint domainmcs_value;

  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DomainMCSPDU_choice, hf_index, ett_t125_DomainMCSPDU,
                                 &domainmcs_value);

	switch(domainmcs_value) {
	case 25: /* sendDataRequest */
	case 26: /* sendDataIndication */
	case 27: /* uniformSendDataRequest */
	case 28: /* uniformSendDataIndication */
		/* Do nothing */
		break;
	default:
		col_append_sep_fstr(actx->pinfo->cinfo, COL_INFO, " ", "MCS: %s ", val_to_str(domainmcs_value, t125_DomainMCSPDU_vals, "Unknown"));
		break;
	}


  return offset;
}

/*--- PDUs ---*/

static int dissect_ConnectMCSPDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_t125_ConnectMCSPDU(FALSE, tvb, offset, &asn1_ctx, tree, hf_t125_ConnectMCSPDU_PDU);
  return offset;
}


/*--- End of included file: packet-t125-fn.c ---*/
#line 61 "../../asn1/t125/packet-t125-template.c"

static int
dissect_t125(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree)
{
  proto_item *item = NULL;
  proto_tree *tree = NULL;
  gint8 class;
  gboolean pc;
  gint32 tag;

  top_tree = parent_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "T.125");
  col_clear(pinfo->cinfo, COL_INFO);

  item = proto_tree_add_item(parent_tree, proto_t125, tvb, 0, tvb_length(tvb), ENC_NA);
  tree = proto_item_add_subtree(item, ett_t125);

  get_ber_identifier(tvb, 0, &class, &pc, &tag);

  if ( (class==BER_CLASS_APP) && (tag>=101) && (tag<=104) ){
    dissect_ConnectMCSPDU_PDU(tvb, pinfo, tree);
  } else  {
    t124_set_top_tree(top_tree);
    dissect_DomainMCSPDU_PDU(tvb, pinfo, tree);
  }

  return tvb_length(tvb);
}

static gboolean
dissect_t125_heur(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree)
{
  gint8 class;
  gboolean pc;
  gint32 tag;
  guint32 choice_index = 100;
  asn1_ctx_t asn1_ctx;

  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);

  /* could be BER */
  get_ber_identifier(tvb, 0, &class, &pc, &tag);
  /* or PER */
  dissect_per_constrained_integer(tvb, 0, &asn1_ctx,
				  NULL, hf_t125_heur, 0, 42,
				  &choice_index, FALSE);

  /* is this strong enough ? */
  if ( ((class==BER_CLASS_APP) && ((tag>=101) && (tag<=104))) ||
       (choice_index <=42)) {

    dissect_t125(tvb, pinfo, parent_tree);

    return TRUE;
  }

  return FALSE;
}


/*--- proto_register_t125 -------------------------------------------*/
void proto_register_t125(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_t125_connectData,
      { "connectData", "t125.connectData",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_heur,
      { "heuristic", "t125.heuristic",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},

/*--- Included file: packet-t125-hfarr.c ---*/
#line 1 "../../asn1/t125/packet-t125-hfarr.c"
    { &hf_t125_ConnectMCSPDU_PDU,
      { "ConnectMCSPDU", "t125.ConnectMCSPDU",
        FT_UINT32, BASE_DEC, VALS(t125_ConnectMCSPDU_vals), 0,
        NULL, HFILL }},
    { &hf_t125_maxChannelIds,
      { "maxChannelIds", "t125.maxChannelIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t125_maxUserIds,
      { "maxUserIds", "t125.maxUserIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t125_maxTokenIds,
      { "maxTokenIds", "t125.maxTokenIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t125_numPriorities,
      { "numPriorities", "t125.numPriorities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t125_minThroughput,
      { "minThroughput", "t125.minThroughput",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t125_maxHeight,
      { "maxHeight", "t125.maxHeight",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t125_maxMCSPDUsize,
      { "maxMCSPDUsize", "t125.maxMCSPDUsize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t125_protocolVersion,
      { "protocolVersion", "t125.protocolVersion",
        FT_UINT32, BASE_DEC, NULL, 0,
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
      { "targetParameters", "t125.targetParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "DomainParameters", HFILL }},
    { &hf_t125_minimumParameters,
      { "minimumParameters", "t125.minimumParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "DomainParameters", HFILL }},
    { &hf_t125_maximumParameters,
      { "maximumParameters", "t125.maximumParameters",
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
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t125_domainParameters,
      { "domainParameters", "t125.domainParameters",
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
    { &hf_t125_heightLimit,
      { "heightLimit", "t125.heightLimit",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t125_subHeight,
      { "subHeight", "t125.subHeight",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t125_subInterval,
      { "subInterval", "t125.subInterval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t125_static,
      { "static", "t125.static",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_channelId,
      { "channelId", "t125.channelId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "StaticChannelId", HFILL }},
    { &hf_t125_userId,
      { "userId", "t125.userId",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_joined,
      { "joined", "t125.joined",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t125_userId_01,
      { "userId", "t125.userId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_private,
      { "private", "t125.private",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_channelId_01,
      { "channelId", "t125.channelId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrivateChannelId", HFILL }},
    { &hf_t125_manager,
      { "manager", "t125.manager",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserId", HFILL }},
    { &hf_t125_admitted,
      { "admitted", "t125.admitted",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_UserId", HFILL }},
    { &hf_t125_admitted_item,
      { "UserId", "t125.UserId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_assigned,
      { "assigned", "t125.assigned",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_channelId_02,
      { "channelId", "t125.channelId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AssignedChannelId", HFILL }},
    { &hf_t125_mergeChannels,
      { "mergeChannels", "t125.mergeChannels",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ChannelAttributes", HFILL }},
    { &hf_t125_mergeChannels_item,
      { "ChannelAttributes", "t125.ChannelAttributes",
        FT_UINT32, BASE_DEC, VALS(t125_ChannelAttributes_vals), 0,
        NULL, HFILL }},
    { &hf_t125_purgeChannelIds,
      { "purgeChannelIds", "t125.purgeChannelIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ChannelId", HFILL }},
    { &hf_t125_purgeChannelIds_item,
      { "ChannelId", "t125.ChannelId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_detachUserIds,
      { "detachUserIds", "t125.detachUserIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_UserId", HFILL }},
    { &hf_t125_detachUserIds_item,
      { "UserId", "t125.UserId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_grabbed,
      { "grabbed", "t125.grabbed",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_tokenId,
      { "tokenId", "t125.tokenId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_grabber,
      { "grabber", "t125.grabber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserId", HFILL }},
    { &hf_t125_inhibited,
      { "inhibited", "t125.inhibited",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_inhibitors,
      { "inhibitors", "t125.inhibitors",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_UserId", HFILL }},
    { &hf_t125_inhibitors_item,
      { "UserId", "t125.UserId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_giving,
      { "giving", "t125.giving",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_recipient,
      { "recipient", "t125.recipient",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserId", HFILL }},
    { &hf_t125_ungivable,
      { "ungivable", "t125.ungivable",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_given,
      { "given", "t125.given",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_mergeTokens,
      { "mergeTokens", "t125.mergeTokens",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_TokenAttributes", HFILL }},
    { &hf_t125_mergeTokens_item,
      { "TokenAttributes", "t125.TokenAttributes",
        FT_UINT32, BASE_DEC, VALS(t125_TokenAttributes_vals), 0,
        NULL, HFILL }},
    { &hf_t125_purgeTokenIds,
      { "purgeTokenIds", "t125.purgeTokenIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_TokenId", HFILL }},
    { &hf_t125_purgeTokenIds_item,
      { "TokenId", "t125.TokenId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_reason,
      { "reason", "t125.reason",
        FT_UINT32, BASE_DEC, VALS(t125_Reason_vals), 0,
        NULL, HFILL }},
    { &hf_t125_diagnostic,
      { "diagnostic", "t125.diagnostic",
        FT_UINT32, BASE_DEC, VALS(t125_Diagnostic_vals), 0,
        NULL, HFILL }},
    { &hf_t125_initialOctets,
      { "initialOctets", "t125.initialOctets",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_t125_initiator,
      { "initiator", "t125.initiator",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserId", HFILL }},
    { &hf_t125_userIds,
      { "userIds", "t125.userIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_UserId", HFILL }},
    { &hf_t125_userIds_item,
      { "UserId", "t125.UserId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_channelId_03,
      { "channelId", "t125.channelId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_requested,
      { "requested", "t125.requested",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ChannelId", HFILL }},
    { &hf_t125_channelIds,
      { "channelIds", "t125.channelIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ChannelId", HFILL }},
    { &hf_t125_channelIds_item,
      { "ChannelId", "t125.ChannelId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_segmentation,
      { "segmentation", "t125.segmentation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_userData_02,
      { "userData", "t125.userData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_t125_tokenStatus,
      { "tokenStatus", "t125.tokenStatus",
        FT_UINT32, BASE_DEC, VALS(t125_TokenStatus_vals), 0,
        NULL, HFILL }},
    { &hf_t125_connect_initial,
      { "connect-initial", "t125.connect_initial",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_connect_response,
      { "connect-response", "t125.connect_response",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_connect_additional,
      { "connect-additional", "t125.connect_additional",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_connect_result,
      { "connect-result", "t125.connect_result",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_plumbDomainIndication,
      { "plumbDomainIndication", "t125.plumbDomainIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_erectDomainRequest,
      { "erectDomainRequest", "t125.erectDomainRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_mergeChannelsRequest,
      { "mergeChannelsRequest", "t125.mergeChannelsRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_mergeChannelsConfirm,
      { "mergeChannelsConfirm", "t125.mergeChannelsConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_purgeChannelsIndication,
      { "purgeChannelsIndication", "t125.purgeChannelsIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_mergeTokensRequest,
      { "mergeTokensRequest", "t125.mergeTokensRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_mergeTokensConfirm,
      { "mergeTokensConfirm", "t125.mergeTokensConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_purgeTokensIndication,
      { "purgeTokensIndication", "t125.purgeTokensIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_disconnectProviderUltimatum,
      { "disconnectProviderUltimatum", "t125.disconnectProviderUltimatum",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_rejectMCSPDUUltimatum,
      { "rejectMCSPDUUltimatum", "t125.rejectMCSPDUUltimatum",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_attachUserRequest,
      { "attachUserRequest", "t125.attachUserRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_attachUserConfirm,
      { "attachUserConfirm", "t125.attachUserConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_detachUserRequest,
      { "detachUserRequest", "t125.detachUserRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_detachUserIndication,
      { "detachUserIndication", "t125.detachUserIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_channelJoinRequest,
      { "channelJoinRequest", "t125.channelJoinRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_channelJoinConfirm,
      { "channelJoinConfirm", "t125.channelJoinConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_channelLeaveRequest,
      { "channelLeaveRequest", "t125.channelLeaveRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_channelConveneRequest,
      { "channelConveneRequest", "t125.channelConveneRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_channelConveneConfirm,
      { "channelConveneConfirm", "t125.channelConveneConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_channelDisbandRequest,
      { "channelDisbandRequest", "t125.channelDisbandRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_channelDisbandIndication,
      { "channelDisbandIndication", "t125.channelDisbandIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_channelAdmitRequest,
      { "channelAdmitRequest", "t125.channelAdmitRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_channelAdmitIndication,
      { "channelAdmitIndication", "t125.channelAdmitIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_channelExpelRequest,
      { "channelExpelRequest", "t125.channelExpelRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_channelExpelIndication,
      { "channelExpelIndication", "t125.channelExpelIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_sendDataRequest,
      { "sendDataRequest", "t125.sendDataRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_sendDataIndication,
      { "sendDataIndication", "t125.sendDataIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_uniformSendDataRequest,
      { "uniformSendDataRequest", "t125.uniformSendDataRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_uniformSendDataIndication,
      { "uniformSendDataIndication", "t125.uniformSendDataIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_tokenGrabRequest,
      { "tokenGrabRequest", "t125.tokenGrabRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_tokenGrabConfirm,
      { "tokenGrabConfirm", "t125.tokenGrabConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_tokenInhibitRequest,
      { "tokenInhibitRequest", "t125.tokenInhibitRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_tokenInhibitConfirm,
      { "tokenInhibitConfirm", "t125.tokenInhibitConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_tokenGiveRequest,
      { "tokenGiveRequest", "t125.tokenGiveRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_tokenGiveIndication,
      { "tokenGiveIndication", "t125.tokenGiveIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_tokenGiveResponse,
      { "tokenGiveResponse", "t125.tokenGiveResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_tokenGiveConfirm,
      { "tokenGiveConfirm", "t125.tokenGiveConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_tokenPleaseRequest,
      { "tokenPleaseRequest", "t125.tokenPleaseRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_tokenPleaseIndication,
      { "tokenPleaseIndication", "t125.tokenPleaseIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_tokenReleaseRequest,
      { "tokenReleaseRequest", "t125.tokenReleaseRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_tokenReleaseConfirm,
      { "tokenReleaseConfirm", "t125.tokenReleaseConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_tokenTestRequest,
      { "tokenTestRequest", "t125.tokenTestRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_tokenTestConfirm,
      { "tokenTestConfirm", "t125.tokenTestConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_Segmentation_begin,
      { "begin", "t125.begin",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_t125_Segmentation_end,
      { "end", "t125.end",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},

/*--- End of included file: packet-t125-hfarr.c ---*/
#line 136 "../../asn1/t125/packet-t125-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_t125,

/*--- Included file: packet-t125-ettarr.c ---*/
#line 1 "../../asn1/t125/packet-t125-ettarr.c"
    &ett_t125_Segmentation,
    &ett_t125_DomainParameters,
    &ett_t125_Connect_Initial_U,
    &ett_t125_Connect_Response_U,
    &ett_t125_Connect_Additional_U,
    &ett_t125_Connect_Result_U,
    &ett_t125_PlumbDomainIndication_U,
    &ett_t125_ErectDomainRequest_U,
    &ett_t125_ChannelAttributes,
    &ett_t125_T_static,
    &ett_t125_T_userId,
    &ett_t125_T_private,
    &ett_t125_SET_OF_UserId,
    &ett_t125_T_assigned,
    &ett_t125_MergeChannelsRequest_U,
    &ett_t125_SET_OF_ChannelAttributes,
    &ett_t125_SET_OF_ChannelId,
    &ett_t125_MergeChannelsConfirm_U,
    &ett_t125_PurgeChannelsIndication_U,
    &ett_t125_TokenAttributes,
    &ett_t125_T_grabbed,
    &ett_t125_T_inhibited,
    &ett_t125_T_giving,
    &ett_t125_T_ungivable,
    &ett_t125_T_given,
    &ett_t125_MergeTokensRequest_U,
    &ett_t125_SET_OF_TokenAttributes,
    &ett_t125_SET_OF_TokenId,
    &ett_t125_MergeTokensConfirm_U,
    &ett_t125_PurgeTokensIndication_U,
    &ett_t125_DisconnectProviderUltimatum_U,
    &ett_t125_RejectMCSPDUUltimatum_U,
    &ett_t125_AttachUserRequest_U,
    &ett_t125_AttachUserConfirm_U,
    &ett_t125_DetachUserRequest_U,
    &ett_t125_DetachUserIndication_U,
    &ett_t125_ChannelJoinRequest_U,
    &ett_t125_ChannelJoinConfirm_U,
    &ett_t125_ChannelLeaveRequest_U,
    &ett_t125_ChannelConveneRequest_U,
    &ett_t125_ChannelConveneConfirm_U,
    &ett_t125_ChannelDisbandRequest_U,
    &ett_t125_ChannelDisbandIndication_U,
    &ett_t125_ChannelAdmitRequest_U,
    &ett_t125_ChannelAdmitIndication_U,
    &ett_t125_ChannelExpelRequest_U,
    &ett_t125_ChannelExpelIndication_U,
    &ett_t125_SendDataRequest_U,
    &ett_t125_SendDataIndication_U,
    &ett_t125_UniformSendDataRequest_U,
    &ett_t125_UniformSendDataIndication_U,
    &ett_t125_TokenGrabRequest_U,
    &ett_t125_TokenGrabConfirm_U,
    &ett_t125_TokenInhibitRequest_U,
    &ett_t125_TokenInhibitConfirm_U,
    &ett_t125_TokenGiveRequest_U,
    &ett_t125_TokenGiveIndication_U,
    &ett_t125_TokenGiveResponse_U,
    &ett_t125_TokenGiveConfirm_U,
    &ett_t125_TokenPleaseRequest_U,
    &ett_t125_TokenPleaseIndication_U,
    &ett_t125_TokenReleaseRequest_U,
    &ett_t125_TokenReleaseConfirm_U,
    &ett_t125_TokenTestRequest_U,
    &ett_t125_TokenTestConfirm_U,
    &ett_t125_ConnectMCSPDU,
    &ett_t125_DomainMCSPDU,

/*--- End of included file: packet-t125-ettarr.c ---*/
#line 142 "../../asn1/t125/packet-t125-template.c"
  };

  /* Register protocol */
  proto_t125 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_t125, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_heur_dissector_list("t125", &t125_heur_subdissector_list);

  new_register_dissector("t125", dissect_t125, proto_t125);
}


/*--- proto_reg_handoff_t125 ---------------------------------------*/
void proto_reg_handoff_t125(void) {

  heur_dissector_add("cotp", dissect_t125_heur, proto_t125);
  heur_dissector_add("cotp_is", dissect_t125_heur, proto_t125);
}
