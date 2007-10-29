/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-t125.c                                                              */
/* ../../tools/asn2wrs.py -b -p t125 -c ./t125.cnf -s ./packet-t125-template -D . MCS-PROTOCOL.asn */

/* Input file: packet-t125-template.c */

#line 1 "packet-t125-template.c"
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
 * To quote the author of the previous H245 dissector:
 *   "This is a complete replacement of the previous limitied dissector
 * that Ronnie was crazy enough to write by hand. It was a lot of time
 * to hack it by hand, but it is incomplete and buggy and it is good when
 * it will go away."
 * Ronnie did a great job and all the VoIP users had made good use of it!
 * Credit to Tomas Kukosa for developing the asn2wrs compiler.
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/asn1.h>
#include "packet-ber.h"

#define PNAME  "MULTIPOINT-COMMUNICATION-SERVICE T.125"
#define PSNAME "T.125"
#define PFNAME "t125"


/* Initialize the protocol and registered fields */
int proto_t125 = -1;

/*--- Included file: packet-t125-hf.c ---*/
#line 1 "packet-t125-hf.c"
static int hf_t125_ConnectMCSPDU_PDU = -1;        /* ConnectMCSPDU */
static int hf_t125_DomainMCSPDU_PDU = -1;         /* DomainMCSPDU */
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
static int hf_t125_userData = -1;                 /* OCTET_STRING */
static int hf_t125_result = -1;                   /* Result */
static int hf_t125_calledConnectId = -1;          /* INTEGER_0_MAX */
static int hf_t125_domainParameters = -1;         /* DomainParameters */
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
#line 59 "packet-t125-template.c"

/* Initialize the subtree pointers */
static int ett_t125 = -1;

/*--- Included file: packet-t125-ett.c ---*/
#line 1 "packet-t125-ett.c"
static gint ett_t125_Segmentation = -1;
static gint ett_t125_DomainParameters = -1;
static gint ett_t125_Connect_Initial = -1;
static gint ett_t125_Connect_Response = -1;
static gint ett_t125_Connect_Additional = -1;
static gint ett_t125_Connect_Result = -1;
static gint ett_t125_PlumbDomainIndication = -1;
static gint ett_t125_ErectDomainRequest = -1;
static gint ett_t125_ChannelAttributes = -1;
static gint ett_t125_T_static = -1;
static gint ett_t125_T_userId = -1;
static gint ett_t125_T_private = -1;
static gint ett_t125_SET_OF_UserId = -1;
static gint ett_t125_T_assigned = -1;
static gint ett_t125_MergeChannelsRequest = -1;
static gint ett_t125_SET_OF_ChannelAttributes = -1;
static gint ett_t125_SET_OF_ChannelId = -1;
static gint ett_t125_MergeChannelsConfirm = -1;
static gint ett_t125_PurgeChannelsIndication = -1;
static gint ett_t125_TokenAttributes = -1;
static gint ett_t125_T_grabbed = -1;
static gint ett_t125_T_inhibited = -1;
static gint ett_t125_T_giving = -1;
static gint ett_t125_T_ungivable = -1;
static gint ett_t125_T_given = -1;
static gint ett_t125_MergeTokensRequest = -1;
static gint ett_t125_SET_OF_TokenAttributes = -1;
static gint ett_t125_SET_OF_TokenId = -1;
static gint ett_t125_MergeTokensConfirm = -1;
static gint ett_t125_PurgeTokensIndication = -1;
static gint ett_t125_DisconnectProviderUltimatum = -1;
static gint ett_t125_RejectMCSPDUUltimatum = -1;
static gint ett_t125_AttachUserRequest = -1;
static gint ett_t125_AttachUserConfirm = -1;
static gint ett_t125_DetachUserRequest = -1;
static gint ett_t125_DetachUserIndication = -1;
static gint ett_t125_ChannelJoinRequest = -1;
static gint ett_t125_ChannelJoinConfirm = -1;
static gint ett_t125_ChannelLeaveRequest = -1;
static gint ett_t125_ChannelConveneRequest = -1;
static gint ett_t125_ChannelConveneConfirm = -1;
static gint ett_t125_ChannelDisbandRequest = -1;
static gint ett_t125_ChannelDisbandIndication = -1;
static gint ett_t125_ChannelAdmitRequest = -1;
static gint ett_t125_ChannelAdmitIndication = -1;
static gint ett_t125_ChannelExpelRequest = -1;
static gint ett_t125_ChannelExpelIndication = -1;
static gint ett_t125_SendDataRequest = -1;
static gint ett_t125_SendDataIndication = -1;
static gint ett_t125_UniformSendDataRequest = -1;
static gint ett_t125_UniformSendDataIndication = -1;
static gint ett_t125_TokenGrabRequest = -1;
static gint ett_t125_TokenGrabConfirm = -1;
static gint ett_t125_TokenInhibitRequest = -1;
static gint ett_t125_TokenInhibitConfirm = -1;
static gint ett_t125_TokenGiveRequest = -1;
static gint ett_t125_TokenGiveIndication = -1;
static gint ett_t125_TokenGiveResponse = -1;
static gint ett_t125_TokenGiveConfirm = -1;
static gint ett_t125_TokenPleaseRequest = -1;
static gint ett_t125_TokenPleaseIndication = -1;
static gint ett_t125_TokenReleaseRequest = -1;
static gint ett_t125_TokenReleaseConfirm = -1;
static gint ett_t125_TokenTestRequest = -1;
static gint ett_t125_TokenTestConfirm = -1;
static gint ett_t125_ConnectMCSPDU = -1;
static gint ett_t125_DomainMCSPDU = -1;

/*--- End of included file: packet-t125-ett.c ---*/
#line 63 "packet-t125-template.c"


/*--- Included file: packet-t125-fn.c ---*/
#line 1 "packet-t125-fn.c"
/*--- Fields for imported types ---*/




static int
dissect_t125_ChannelId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_purgeChannelIds_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_ChannelId(FALSE, tvb, offset, actx, tree, hf_t125_purgeChannelIds_item);
}
static int dissect_channelId_03(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_ChannelId(FALSE, tvb, offset, actx, tree, hf_t125_channelId_03);
}
static int dissect_requested(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_ChannelId(FALSE, tvb, offset, actx, tree, hf_t125_requested);
}
static int dissect_channelIds_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_ChannelId(FALSE, tvb, offset, actx, tree, hf_t125_channelIds_item);
}



static int
dissect_t125_StaticChannelId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_t125_ChannelId(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_channelId(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_StaticChannelId(FALSE, tvb, offset, actx, tree, hf_t125_channelId);
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
static int dissect_userId_01(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_UserId(FALSE, tvb, offset, actx, tree, hf_t125_userId_01);
}
static int dissect_manager(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_UserId(FALSE, tvb, offset, actx, tree, hf_t125_manager);
}
static int dissect_admitted_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_UserId(FALSE, tvb, offset, actx, tree, hf_t125_admitted_item);
}
static int dissect_detachUserIds_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_UserId(FALSE, tvb, offset, actx, tree, hf_t125_detachUserIds_item);
}
static int dissect_grabber(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_UserId(FALSE, tvb, offset, actx, tree, hf_t125_grabber);
}
static int dissect_inhibitors_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_UserId(FALSE, tvb, offset, actx, tree, hf_t125_inhibitors_item);
}
static int dissect_recipient(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_UserId(FALSE, tvb, offset, actx, tree, hf_t125_recipient);
}
static int dissect_initiator(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_UserId(FALSE, tvb, offset, actx, tree, hf_t125_initiator);
}
static int dissect_userIds_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_UserId(FALSE, tvb, offset, actx, tree, hf_t125_userIds_item);
}



static int
dissect_t125_PrivateChannelId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_t125_DynamicChannelId(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_channelId_01(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_PrivateChannelId(FALSE, tvb, offset, actx, tree, hf_t125_channelId_01);
}



static int
dissect_t125_AssignedChannelId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_t125_DynamicChannelId(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_channelId_02(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_AssignedChannelId(FALSE, tvb, offset, actx, tree, hf_t125_channelId_02);
}



static int
dissect_t125_TokenId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_tokenId(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_TokenId(FALSE, tvb, offset, actx, tree, hf_t125_tokenId);
}
static int dissect_purgeTokenIds_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_TokenId(FALSE, tvb, offset, actx, tree, hf_t125_purgeTokenIds_item);
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
static int dissect_tokenStatus(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_TokenStatus(FALSE, tvb, offset, actx, tree, hf_t125_tokenStatus);
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
static int dissect_dataPriority(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_DataPriority(FALSE, tvb, offset, actx, tree, hf_t125_dataPriority);
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
static int dissect_segmentation(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_Segmentation(FALSE, tvb, offset, actx, tree, hf_t125_segmentation);
}



static int
dissect_t125_INTEGER_0_MAX(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_maxChannelIds(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_INTEGER_0_MAX(FALSE, tvb, offset, actx, tree, hf_t125_maxChannelIds);
}
static int dissect_maxUserIds(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_INTEGER_0_MAX(FALSE, tvb, offset, actx, tree, hf_t125_maxUserIds);
}
static int dissect_maxTokenIds(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_INTEGER_0_MAX(FALSE, tvb, offset, actx, tree, hf_t125_maxTokenIds);
}
static int dissect_numPriorities(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_INTEGER_0_MAX(FALSE, tvb, offset, actx, tree, hf_t125_numPriorities);
}
static int dissect_minThroughput(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_INTEGER_0_MAX(FALSE, tvb, offset, actx, tree, hf_t125_minThroughput);
}
static int dissect_maxHeight(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_INTEGER_0_MAX(FALSE, tvb, offset, actx, tree, hf_t125_maxHeight);
}
static int dissect_maxMCSPDUsize(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_INTEGER_0_MAX(FALSE, tvb, offset, actx, tree, hf_t125_maxMCSPDUsize);
}
static int dissect_protocolVersion(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_INTEGER_0_MAX(FALSE, tvb, offset, actx, tree, hf_t125_protocolVersion);
}
static int dissect_calledConnectId(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_INTEGER_0_MAX(FALSE, tvb, offset, actx, tree, hf_t125_calledConnectId);
}
static int dissect_heightLimit(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_INTEGER_0_MAX(FALSE, tvb, offset, actx, tree, hf_t125_heightLimit);
}
static int dissect_subHeight(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_INTEGER_0_MAX(FALSE, tvb, offset, actx, tree, hf_t125_subHeight);
}
static int dissect_subInterval(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_INTEGER_0_MAX(FALSE, tvb, offset, actx, tree, hf_t125_subInterval);
}


static const ber_old_sequence_t DomainParameters_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_maxChannelIds },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_maxUserIds },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_maxTokenIds },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_numPriorities },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_minThroughput },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_maxHeight },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_maxMCSPDUsize },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_protocolVersion },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_DomainParameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       DomainParameters_sequence, hf_index, ett_t125_DomainParameters);

  return offset;
}
static int dissect_targetParameters(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_DomainParameters(FALSE, tvb, offset, actx, tree, hf_t125_targetParameters);
}
static int dissect_minimumParameters(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_DomainParameters(FALSE, tvb, offset, actx, tree, hf_t125_minimumParameters);
}
static int dissect_maximumParameters(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_DomainParameters(FALSE, tvb, offset, actx, tree, hf_t125_maximumParameters);
}
static int dissect_domainParameters(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_DomainParameters(FALSE, tvb, offset, actx, tree, hf_t125_domainParameters);
}



static int
dissect_t125_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_callingDomainSelector(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_OCTET_STRING(FALSE, tvb, offset, actx, tree, hf_t125_callingDomainSelector);
}
static int dissect_calledDomainSelector(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_OCTET_STRING(FALSE, tvb, offset, actx, tree, hf_t125_calledDomainSelector);
}
static int dissect_userData(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_OCTET_STRING(FALSE, tvb, offset, actx, tree, hf_t125_userData);
}
static int dissect_initialOctets(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_OCTET_STRING(FALSE, tvb, offset, actx, tree, hf_t125_initialOctets);
}



static int
dissect_t125_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_upwardFlag(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_BOOLEAN(FALSE, tvb, offset, actx, tree, hf_t125_upwardFlag);
}
static int dissect_joined(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_BOOLEAN(FALSE, tvb, offset, actx, tree, hf_t125_joined);
}


static const ber_old_sequence_t Connect_Initial_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_callingDomainSelector },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_calledDomainSelector },
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_upwardFlag },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_targetParameters },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_minimumParameters },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_maximumParameters },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_userData },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_Connect_Initial(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       Connect_Initial_sequence, hf_index, ett_t125_Connect_Initial);

  return offset;
}
static int dissect_connect_initial(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_Connect_Initial(FALSE, tvb, offset, actx, tree, hf_t125_connect_initial);
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
static int dissect_result(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_Result(FALSE, tvb, offset, actx, tree, hf_t125_result);
}


static const ber_old_sequence_t Connect_Response_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_result },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_calledConnectId },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_domainParameters },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_userData },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_Connect_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       Connect_Response_sequence, hf_index, ett_t125_Connect_Response);

  return offset;
}
static int dissect_connect_response(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_Connect_Response(FALSE, tvb, offset, actx, tree, hf_t125_connect_response);
}


static const ber_old_sequence_t Connect_Additional_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_calledConnectId },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_dataPriority },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_Connect_Additional(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       Connect_Additional_sequence, hf_index, ett_t125_Connect_Additional);

  return offset;
}
static int dissect_connect_additional(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_Connect_Additional(FALSE, tvb, offset, actx, tree, hf_t125_connect_additional);
}


static const ber_old_sequence_t Connect_Result_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_result },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_Connect_Result(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       Connect_Result_sequence, hf_index, ett_t125_Connect_Result);

  return offset;
}
static int dissect_connect_result(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_Connect_Result(FALSE, tvb, offset, actx, tree, hf_t125_connect_result);
}


static const ber_old_sequence_t PlumbDomainIndication_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_heightLimit },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_PlumbDomainIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       PlumbDomainIndication_sequence, hf_index, ett_t125_PlumbDomainIndication);

  return offset;
}
static int dissect_plumbDomainIndication(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_PlumbDomainIndication(FALSE, tvb, offset, actx, tree, hf_t125_plumbDomainIndication);
}


static const ber_old_sequence_t ErectDomainRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_subHeight },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_subInterval },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_ErectDomainRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ErectDomainRequest_sequence, hf_index, ett_t125_ErectDomainRequest);

  return offset;
}
static int dissect_erectDomainRequest(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_ErectDomainRequest(FALSE, tvb, offset, actx, tree, hf_t125_erectDomainRequest);
}


static const ber_old_sequence_t T_static_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_channelId },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_T_static(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_static_sequence, hf_index, ett_t125_T_static);

  return offset;
}
static int dissect_static_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_T_static(TRUE, tvb, offset, actx, tree, hf_t125_static);
}


static const ber_old_sequence_t T_userId_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_joined },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_userId_01 },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_T_userId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_userId_sequence, hf_index, ett_t125_T_userId);

  return offset;
}
static int dissect_userId_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_T_userId(TRUE, tvb, offset, actx, tree, hf_t125_userId);
}


static const ber_old_sequence_t SET_OF_UserId_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_admitted_item },
};

static int
dissect_t125_SET_OF_UserId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_set_of(implicit_tag, actx, tree, tvb, offset,
                                     SET_OF_UserId_set_of, hf_index, ett_t125_SET_OF_UserId);

  return offset;
}
static int dissect_admitted(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_SET_OF_UserId(FALSE, tvb, offset, actx, tree, hf_t125_admitted);
}
static int dissect_detachUserIds(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_SET_OF_UserId(FALSE, tvb, offset, actx, tree, hf_t125_detachUserIds);
}
static int dissect_inhibitors(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_SET_OF_UserId(FALSE, tvb, offset, actx, tree, hf_t125_inhibitors);
}
static int dissect_userIds(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_SET_OF_UserId(FALSE, tvb, offset, actx, tree, hf_t125_userIds);
}


static const ber_old_sequence_t T_private_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_joined },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_channelId_01 },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_manager },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_admitted },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_T_private(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_private_sequence, hf_index, ett_t125_T_private);

  return offset;
}
static int dissect_private_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_T_private(TRUE, tvb, offset, actx, tree, hf_t125_private);
}


static const ber_old_sequence_t T_assigned_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_channelId_02 },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_T_assigned(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_assigned_sequence, hf_index, ett_t125_T_assigned);

  return offset;
}
static int dissect_assigned_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_T_assigned(TRUE, tvb, offset, actx, tree, hf_t125_assigned);
}


static const value_string t125_ChannelAttributes_vals[] = {
  {   0, "static" },
  {   1, "userId" },
  {   2, "private" },
  {   3, "assigned" },
  { 0, NULL }
};

static const ber_old_choice_t ChannelAttributes_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_static_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_userId_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_private_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_assigned_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_t125_ChannelAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     ChannelAttributes_choice, hf_index, ett_t125_ChannelAttributes,
                                     NULL);

  return offset;
}
static int dissect_mergeChannels_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_ChannelAttributes(FALSE, tvb, offset, actx, tree, hf_t125_mergeChannels_item);
}


static const ber_old_sequence_t SET_OF_ChannelAttributes_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mergeChannels_item },
};

static int
dissect_t125_SET_OF_ChannelAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_set_of(implicit_tag, actx, tree, tvb, offset,
                                     SET_OF_ChannelAttributes_set_of, hf_index, ett_t125_SET_OF_ChannelAttributes);

  return offset;
}
static int dissect_mergeChannels(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_SET_OF_ChannelAttributes(FALSE, tvb, offset, actx, tree, hf_t125_mergeChannels);
}


static const ber_old_sequence_t SET_OF_ChannelId_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_purgeChannelIds_item },
};

static int
dissect_t125_SET_OF_ChannelId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_set_of(implicit_tag, actx, tree, tvb, offset,
                                     SET_OF_ChannelId_set_of, hf_index, ett_t125_SET_OF_ChannelId);

  return offset;
}
static int dissect_purgeChannelIds(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_SET_OF_ChannelId(FALSE, tvb, offset, actx, tree, hf_t125_purgeChannelIds);
}
static int dissect_channelIds(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_SET_OF_ChannelId(FALSE, tvb, offset, actx, tree, hf_t125_channelIds);
}


static const ber_old_sequence_t MergeChannelsRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_mergeChannels },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_purgeChannelIds },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_MergeChannelsRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       MergeChannelsRequest_sequence, hf_index, ett_t125_MergeChannelsRequest);

  return offset;
}
static int dissect_mergeChannelsRequest(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_MergeChannelsRequest(FALSE, tvb, offset, actx, tree, hf_t125_mergeChannelsRequest);
}


static const ber_old_sequence_t MergeChannelsConfirm_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_mergeChannels },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_purgeChannelIds },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_MergeChannelsConfirm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       MergeChannelsConfirm_sequence, hf_index, ett_t125_MergeChannelsConfirm);

  return offset;
}
static int dissect_mergeChannelsConfirm(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_MergeChannelsConfirm(FALSE, tvb, offset, actx, tree, hf_t125_mergeChannelsConfirm);
}


static const ber_old_sequence_t PurgeChannelsIndication_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_detachUserIds },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_purgeChannelIds },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_PurgeChannelsIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       PurgeChannelsIndication_sequence, hf_index, ett_t125_PurgeChannelsIndication);

  return offset;
}
static int dissect_purgeChannelsIndication(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_PurgeChannelsIndication(FALSE, tvb, offset, actx, tree, hf_t125_purgeChannelsIndication);
}


static const ber_old_sequence_t T_grabbed_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tokenId },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_grabber },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_T_grabbed(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_grabbed_sequence, hf_index, ett_t125_T_grabbed);

  return offset;
}
static int dissect_grabbed_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_T_grabbed(TRUE, tvb, offset, actx, tree, hf_t125_grabbed);
}


static const ber_old_sequence_t T_inhibited_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tokenId },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_inhibitors },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_T_inhibited(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_inhibited_sequence, hf_index, ett_t125_T_inhibited);

  return offset;
}
static int dissect_inhibited_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_T_inhibited(TRUE, tvb, offset, actx, tree, hf_t125_inhibited);
}


static const ber_old_sequence_t T_giving_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tokenId },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_grabber },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_recipient },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_T_giving(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_giving_sequence, hf_index, ett_t125_T_giving);

  return offset;
}
static int dissect_giving_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_T_giving(TRUE, tvb, offset, actx, tree, hf_t125_giving);
}


static const ber_old_sequence_t T_ungivable_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tokenId },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_grabber },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_T_ungivable(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_ungivable_sequence, hf_index, ett_t125_T_ungivable);

  return offset;
}
static int dissect_ungivable_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_T_ungivable(TRUE, tvb, offset, actx, tree, hf_t125_ungivable);
}


static const ber_old_sequence_t T_given_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tokenId },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_recipient },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_T_given(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_given_sequence, hf_index, ett_t125_T_given);

  return offset;
}
static int dissect_given_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_T_given(TRUE, tvb, offset, actx, tree, hf_t125_given);
}


static const value_string t125_TokenAttributes_vals[] = {
  {   0, "grabbed" },
  {   1, "inhibited" },
  {   2, "giving" },
  {   3, "ungivable" },
  {   4, "given" },
  { 0, NULL }
};

static const ber_old_choice_t TokenAttributes_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_grabbed_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_inhibited_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_giving_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ungivable_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_given_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_t125_TokenAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     TokenAttributes_choice, hf_index, ett_t125_TokenAttributes,
                                     NULL);

  return offset;
}
static int dissect_mergeTokens_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_TokenAttributes(FALSE, tvb, offset, actx, tree, hf_t125_mergeTokens_item);
}


static const ber_old_sequence_t SET_OF_TokenAttributes_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mergeTokens_item },
};

static int
dissect_t125_SET_OF_TokenAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_set_of(implicit_tag, actx, tree, tvb, offset,
                                     SET_OF_TokenAttributes_set_of, hf_index, ett_t125_SET_OF_TokenAttributes);

  return offset;
}
static int dissect_mergeTokens(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_SET_OF_TokenAttributes(FALSE, tvb, offset, actx, tree, hf_t125_mergeTokens);
}


static const ber_old_sequence_t SET_OF_TokenId_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_purgeTokenIds_item },
};

static int
dissect_t125_SET_OF_TokenId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_set_of(implicit_tag, actx, tree, tvb, offset,
                                     SET_OF_TokenId_set_of, hf_index, ett_t125_SET_OF_TokenId);

  return offset;
}
static int dissect_purgeTokenIds(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_SET_OF_TokenId(FALSE, tvb, offset, actx, tree, hf_t125_purgeTokenIds);
}


static const ber_old_sequence_t MergeTokensRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_mergeTokens },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_purgeTokenIds },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_MergeTokensRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       MergeTokensRequest_sequence, hf_index, ett_t125_MergeTokensRequest);

  return offset;
}
static int dissect_mergeTokensRequest(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_MergeTokensRequest(FALSE, tvb, offset, actx, tree, hf_t125_mergeTokensRequest);
}


static const ber_old_sequence_t MergeTokensConfirm_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_mergeTokens },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_purgeTokenIds },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_MergeTokensConfirm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       MergeTokensConfirm_sequence, hf_index, ett_t125_MergeTokensConfirm);

  return offset;
}
static int dissect_mergeTokensConfirm(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_MergeTokensConfirm(FALSE, tvb, offset, actx, tree, hf_t125_mergeTokensConfirm);
}


static const ber_old_sequence_t PurgeTokensIndication_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_purgeTokenIds },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_PurgeTokensIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       PurgeTokensIndication_sequence, hf_index, ett_t125_PurgeTokensIndication);

  return offset;
}
static int dissect_purgeTokensIndication(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_PurgeTokensIndication(FALSE, tvb, offset, actx, tree, hf_t125_purgeTokensIndication);
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
static int dissect_reason(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_Reason(FALSE, tvb, offset, actx, tree, hf_t125_reason);
}


static const ber_old_sequence_t DisconnectProviderUltimatum_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_reason },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_DisconnectProviderUltimatum(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       DisconnectProviderUltimatum_sequence, hf_index, ett_t125_DisconnectProviderUltimatum);

  return offset;
}
static int dissect_disconnectProviderUltimatum(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_DisconnectProviderUltimatum(FALSE, tvb, offset, actx, tree, hf_t125_disconnectProviderUltimatum);
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
static int dissect_diagnostic(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_Diagnostic(FALSE, tvb, offset, actx, tree, hf_t125_diagnostic);
}


static const ber_old_sequence_t RejectMCSPDUUltimatum_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_diagnostic },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_initialOctets },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_RejectMCSPDUUltimatum(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       RejectMCSPDUUltimatum_sequence, hf_index, ett_t125_RejectMCSPDUUltimatum);

  return offset;
}
static int dissect_rejectMCSPDUUltimatum(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_RejectMCSPDUUltimatum(FALSE, tvb, offset, actx, tree, hf_t125_rejectMCSPDUUltimatum);
}


static const ber_old_sequence_t AttachUserRequest_sequence[] = {
  { 0, 0, 0, NULL }
};

static int
dissect_t125_AttachUserRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       AttachUserRequest_sequence, hf_index, ett_t125_AttachUserRequest);

  return offset;
}
static int dissect_attachUserRequest(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_AttachUserRequest(FALSE, tvb, offset, actx, tree, hf_t125_attachUserRequest);
}


static const ber_old_sequence_t AttachUserConfirm_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_result },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_initiator },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_AttachUserConfirm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       AttachUserConfirm_sequence, hf_index, ett_t125_AttachUserConfirm);

  return offset;
}
static int dissect_attachUserConfirm(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_AttachUserConfirm(FALSE, tvb, offset, actx, tree, hf_t125_attachUserConfirm);
}


static const ber_old_sequence_t DetachUserRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_reason },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_userIds },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_DetachUserRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       DetachUserRequest_sequence, hf_index, ett_t125_DetachUserRequest);

  return offset;
}
static int dissect_detachUserRequest(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_DetachUserRequest(FALSE, tvb, offset, actx, tree, hf_t125_detachUserRequest);
}


static const ber_old_sequence_t DetachUserIndication_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_reason },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_userIds },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_DetachUserIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       DetachUserIndication_sequence, hf_index, ett_t125_DetachUserIndication);

  return offset;
}
static int dissect_detachUserIndication(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_DetachUserIndication(FALSE, tvb, offset, actx, tree, hf_t125_detachUserIndication);
}


static const ber_old_sequence_t ChannelJoinRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_initiator },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_channelId_03 },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_ChannelJoinRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ChannelJoinRequest_sequence, hf_index, ett_t125_ChannelJoinRequest);

  return offset;
}
static int dissect_channelJoinRequest(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_ChannelJoinRequest(FALSE, tvb, offset, actx, tree, hf_t125_channelJoinRequest);
}


static const ber_old_sequence_t ChannelJoinConfirm_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_result },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_initiator },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_requested },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_channelId_03 },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_ChannelJoinConfirm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ChannelJoinConfirm_sequence, hf_index, ett_t125_ChannelJoinConfirm);

  return offset;
}
static int dissect_channelJoinConfirm(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_ChannelJoinConfirm(FALSE, tvb, offset, actx, tree, hf_t125_channelJoinConfirm);
}


static const ber_old_sequence_t ChannelLeaveRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_channelIds },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_ChannelLeaveRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ChannelLeaveRequest_sequence, hf_index, ett_t125_ChannelLeaveRequest);

  return offset;
}
static int dissect_channelLeaveRequest(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_ChannelLeaveRequest(FALSE, tvb, offset, actx, tree, hf_t125_channelLeaveRequest);
}


static const ber_old_sequence_t ChannelConveneRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_initiator },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_ChannelConveneRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ChannelConveneRequest_sequence, hf_index, ett_t125_ChannelConveneRequest);

  return offset;
}
static int dissect_channelConveneRequest(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_ChannelConveneRequest(FALSE, tvb, offset, actx, tree, hf_t125_channelConveneRequest);
}


static const ber_old_sequence_t ChannelConveneConfirm_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_result },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_initiator },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_channelId_01 },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_ChannelConveneConfirm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ChannelConveneConfirm_sequence, hf_index, ett_t125_ChannelConveneConfirm);

  return offset;
}
static int dissect_channelConveneConfirm(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_ChannelConveneConfirm(FALSE, tvb, offset, actx, tree, hf_t125_channelConveneConfirm);
}


static const ber_old_sequence_t ChannelDisbandRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_initiator },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_channelId_01 },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_ChannelDisbandRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ChannelDisbandRequest_sequence, hf_index, ett_t125_ChannelDisbandRequest);

  return offset;
}
static int dissect_channelDisbandRequest(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_ChannelDisbandRequest(FALSE, tvb, offset, actx, tree, hf_t125_channelDisbandRequest);
}


static const ber_old_sequence_t ChannelDisbandIndication_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_channelId_01 },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_ChannelDisbandIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ChannelDisbandIndication_sequence, hf_index, ett_t125_ChannelDisbandIndication);

  return offset;
}
static int dissect_channelDisbandIndication(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_ChannelDisbandIndication(FALSE, tvb, offset, actx, tree, hf_t125_channelDisbandIndication);
}


static const ber_old_sequence_t ChannelAdmitRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_initiator },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_channelId_01 },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_userIds },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_ChannelAdmitRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ChannelAdmitRequest_sequence, hf_index, ett_t125_ChannelAdmitRequest);

  return offset;
}
static int dissect_channelAdmitRequest(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_ChannelAdmitRequest(FALSE, tvb, offset, actx, tree, hf_t125_channelAdmitRequest);
}


static const ber_old_sequence_t ChannelAdmitIndication_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_initiator },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_channelId_01 },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_userIds },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_ChannelAdmitIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ChannelAdmitIndication_sequence, hf_index, ett_t125_ChannelAdmitIndication);

  return offset;
}
static int dissect_channelAdmitIndication(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_ChannelAdmitIndication(FALSE, tvb, offset, actx, tree, hf_t125_channelAdmitIndication);
}


static const ber_old_sequence_t ChannelExpelRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_initiator },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_channelId_01 },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_userIds },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_ChannelExpelRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ChannelExpelRequest_sequence, hf_index, ett_t125_ChannelExpelRequest);

  return offset;
}
static int dissect_channelExpelRequest(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_ChannelExpelRequest(FALSE, tvb, offset, actx, tree, hf_t125_channelExpelRequest);
}


static const ber_old_sequence_t ChannelExpelIndication_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_channelId_01 },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_userIds },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_ChannelExpelIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ChannelExpelIndication_sequence, hf_index, ett_t125_ChannelExpelIndication);

  return offset;
}
static int dissect_channelExpelIndication(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_ChannelExpelIndication(FALSE, tvb, offset, actx, tree, hf_t125_channelExpelIndication);
}


static const ber_old_sequence_t SendDataRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_initiator },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_channelId_03 },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_dataPriority },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_segmentation },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_userData },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_SendDataRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       SendDataRequest_sequence, hf_index, ett_t125_SendDataRequest);

  return offset;
}
static int dissect_sendDataRequest(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_SendDataRequest(FALSE, tvb, offset, actx, tree, hf_t125_sendDataRequest);
}


static const ber_old_sequence_t SendDataIndication_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_initiator },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_channelId_03 },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_dataPriority },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_segmentation },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_userData },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_SendDataIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       SendDataIndication_sequence, hf_index, ett_t125_SendDataIndication);

  return offset;
}
static int dissect_sendDataIndication(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_SendDataIndication(FALSE, tvb, offset, actx, tree, hf_t125_sendDataIndication);
}


static const ber_old_sequence_t UniformSendDataRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_initiator },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_channelId_03 },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_dataPriority },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_segmentation },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_userData },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_UniformSendDataRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       UniformSendDataRequest_sequence, hf_index, ett_t125_UniformSendDataRequest);

  return offset;
}
static int dissect_uniformSendDataRequest(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_UniformSendDataRequest(FALSE, tvb, offset, actx, tree, hf_t125_uniformSendDataRequest);
}


static const ber_old_sequence_t UniformSendDataIndication_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_initiator },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_channelId_03 },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_dataPriority },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_segmentation },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_userData },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_UniformSendDataIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       UniformSendDataIndication_sequence, hf_index, ett_t125_UniformSendDataIndication);

  return offset;
}
static int dissect_uniformSendDataIndication(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_UniformSendDataIndication(FALSE, tvb, offset, actx, tree, hf_t125_uniformSendDataIndication);
}


static const ber_old_sequence_t TokenGrabRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_initiator },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tokenId },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_TokenGrabRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       TokenGrabRequest_sequence, hf_index, ett_t125_TokenGrabRequest);

  return offset;
}
static int dissect_tokenGrabRequest(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_TokenGrabRequest(FALSE, tvb, offset, actx, tree, hf_t125_tokenGrabRequest);
}


static const ber_old_sequence_t TokenGrabConfirm_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_result },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_initiator },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tokenId },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_tokenStatus },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_TokenGrabConfirm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       TokenGrabConfirm_sequence, hf_index, ett_t125_TokenGrabConfirm);

  return offset;
}
static int dissect_tokenGrabConfirm(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_TokenGrabConfirm(FALSE, tvb, offset, actx, tree, hf_t125_tokenGrabConfirm);
}


static const ber_old_sequence_t TokenInhibitRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_initiator },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tokenId },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_TokenInhibitRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       TokenInhibitRequest_sequence, hf_index, ett_t125_TokenInhibitRequest);

  return offset;
}
static int dissect_tokenInhibitRequest(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_TokenInhibitRequest(FALSE, tvb, offset, actx, tree, hf_t125_tokenInhibitRequest);
}


static const ber_old_sequence_t TokenInhibitConfirm_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_result },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_initiator },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tokenId },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_tokenStatus },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_TokenInhibitConfirm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       TokenInhibitConfirm_sequence, hf_index, ett_t125_TokenInhibitConfirm);

  return offset;
}
static int dissect_tokenInhibitConfirm(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_TokenInhibitConfirm(FALSE, tvb, offset, actx, tree, hf_t125_tokenInhibitConfirm);
}


static const ber_old_sequence_t TokenGiveRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_initiator },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tokenId },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_recipient },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_TokenGiveRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       TokenGiveRequest_sequence, hf_index, ett_t125_TokenGiveRequest);

  return offset;
}
static int dissect_tokenGiveRequest(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_TokenGiveRequest(FALSE, tvb, offset, actx, tree, hf_t125_tokenGiveRequest);
}


static const ber_old_sequence_t TokenGiveIndication_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_initiator },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tokenId },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_recipient },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_TokenGiveIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       TokenGiveIndication_sequence, hf_index, ett_t125_TokenGiveIndication);

  return offset;
}
static int dissect_tokenGiveIndication(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_TokenGiveIndication(FALSE, tvb, offset, actx, tree, hf_t125_tokenGiveIndication);
}


static const ber_old_sequence_t TokenGiveResponse_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_result },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_recipient },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tokenId },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_TokenGiveResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       TokenGiveResponse_sequence, hf_index, ett_t125_TokenGiveResponse);

  return offset;
}
static int dissect_tokenGiveResponse(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_TokenGiveResponse(FALSE, tvb, offset, actx, tree, hf_t125_tokenGiveResponse);
}


static const ber_old_sequence_t TokenGiveConfirm_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_result },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_initiator },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tokenId },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_tokenStatus },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_TokenGiveConfirm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       TokenGiveConfirm_sequence, hf_index, ett_t125_TokenGiveConfirm);

  return offset;
}
static int dissect_tokenGiveConfirm(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_TokenGiveConfirm(FALSE, tvb, offset, actx, tree, hf_t125_tokenGiveConfirm);
}


static const ber_old_sequence_t TokenPleaseRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_initiator },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tokenId },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_TokenPleaseRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       TokenPleaseRequest_sequence, hf_index, ett_t125_TokenPleaseRequest);

  return offset;
}
static int dissect_tokenPleaseRequest(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_TokenPleaseRequest(FALSE, tvb, offset, actx, tree, hf_t125_tokenPleaseRequest);
}


static const ber_old_sequence_t TokenPleaseIndication_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_initiator },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tokenId },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_TokenPleaseIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       TokenPleaseIndication_sequence, hf_index, ett_t125_TokenPleaseIndication);

  return offset;
}
static int dissect_tokenPleaseIndication(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_TokenPleaseIndication(FALSE, tvb, offset, actx, tree, hf_t125_tokenPleaseIndication);
}


static const ber_old_sequence_t TokenReleaseRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_initiator },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tokenId },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_TokenReleaseRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       TokenReleaseRequest_sequence, hf_index, ett_t125_TokenReleaseRequest);

  return offset;
}
static int dissect_tokenReleaseRequest(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_TokenReleaseRequest(FALSE, tvb, offset, actx, tree, hf_t125_tokenReleaseRequest);
}


static const ber_old_sequence_t TokenReleaseConfirm_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_result },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_initiator },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tokenId },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_tokenStatus },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_TokenReleaseConfirm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       TokenReleaseConfirm_sequence, hf_index, ett_t125_TokenReleaseConfirm);

  return offset;
}
static int dissect_tokenReleaseConfirm(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_TokenReleaseConfirm(FALSE, tvb, offset, actx, tree, hf_t125_tokenReleaseConfirm);
}


static const ber_old_sequence_t TokenTestRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_initiator },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tokenId },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_TokenTestRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       TokenTestRequest_sequence, hf_index, ett_t125_TokenTestRequest);

  return offset;
}
static int dissect_tokenTestRequest(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_TokenTestRequest(FALSE, tvb, offset, actx, tree, hf_t125_tokenTestRequest);
}


static const ber_old_sequence_t TokenTestConfirm_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_initiator },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tokenId },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_tokenStatus },
  { 0, 0, 0, NULL }
};

static int
dissect_t125_TokenTestConfirm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       TokenTestConfirm_sequence, hf_index, ett_t125_TokenTestConfirm);

  return offset;
}
static int dissect_tokenTestConfirm(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_t125_TokenTestConfirm(FALSE, tvb, offset, actx, tree, hf_t125_tokenTestConfirm);
}


static const value_string t125_ConnectMCSPDU_vals[] = {
  { 101, "connect-initial" },
  { 102, "connect-response" },
  { 103, "connect-additional" },
  { 104, "connect-result" },
  { 0, NULL }
};

static const ber_old_choice_t ConnectMCSPDU_choice[] = {
  { 101, BER_CLASS_APP, 101, BER_FLAGS_NOOWNTAG, dissect_connect_initial },
  { 102, BER_CLASS_APP, 102, BER_FLAGS_NOOWNTAG, dissect_connect_response },
  { 103, BER_CLASS_APP, 103, BER_FLAGS_NOOWNTAG, dissect_connect_additional },
  { 104, BER_CLASS_APP, 104, BER_FLAGS_NOOWNTAG, dissect_connect_result },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_t125_ConnectMCSPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 22 "t125.cnf"
  	guint32 connectmcs_value;

  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     ConnectMCSPDU_choice, hf_index, ett_t125_ConnectMCSPDU,
                                     &connectmcs_value);

	if (check_col(actx->pinfo->cinfo, COL_INFO)){
		col_add_fstr(actx->pinfo->cinfo, COL_INFO, "MCS: %s ",
			val_to_str(connectmcs_value, t125_ConnectMCSPDU_vals, "<unknown>"));
	}


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

static const ber_old_choice_t DomainMCSPDU_choice[] = {
  {   0, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_plumbDomainIndication },
  {   1, BER_CLASS_APP, 1, BER_FLAGS_NOOWNTAG, dissect_erectDomainRequest },
  {   2, BER_CLASS_APP, 2, BER_FLAGS_NOOWNTAG, dissect_mergeChannelsRequest },
  {   3, BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_mergeChannelsConfirm },
  {   4, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_purgeChannelsIndication },
  {   5, BER_CLASS_APP, 5, BER_FLAGS_NOOWNTAG, dissect_mergeTokensRequest },
  {   6, BER_CLASS_APP, 6, BER_FLAGS_NOOWNTAG, dissect_mergeTokensConfirm },
  {   7, BER_CLASS_APP, 7, BER_FLAGS_NOOWNTAG, dissect_purgeTokensIndication },
  {   8, BER_CLASS_APP, 8, BER_FLAGS_NOOWNTAG, dissect_disconnectProviderUltimatum },
  {   9, BER_CLASS_APP, 9, BER_FLAGS_NOOWNTAG, dissect_rejectMCSPDUUltimatum },
  {  10, BER_CLASS_APP, 10, BER_FLAGS_NOOWNTAG, dissect_attachUserRequest },
  {  11, BER_CLASS_APP, 11, BER_FLAGS_NOOWNTAG, dissect_attachUserConfirm },
  {  12, BER_CLASS_APP, 12, BER_FLAGS_NOOWNTAG, dissect_detachUserRequest },
  {  13, BER_CLASS_APP, 13, BER_FLAGS_NOOWNTAG, dissect_detachUserIndication },
  {  14, BER_CLASS_APP, 14, BER_FLAGS_NOOWNTAG, dissect_channelJoinRequest },
  {  15, BER_CLASS_APP, 15, BER_FLAGS_NOOWNTAG, dissect_channelJoinConfirm },
  {  16, BER_CLASS_APP, 16, BER_FLAGS_NOOWNTAG, dissect_channelLeaveRequest },
  {  17, BER_CLASS_APP, 17, BER_FLAGS_NOOWNTAG, dissect_channelConveneRequest },
  {  18, BER_CLASS_APP, 18, BER_FLAGS_NOOWNTAG, dissect_channelConveneConfirm },
  {  19, BER_CLASS_APP, 19, BER_FLAGS_NOOWNTAG, dissect_channelDisbandRequest },
  {  20, BER_CLASS_APP, 20, BER_FLAGS_NOOWNTAG, dissect_channelDisbandIndication },
  {  21, BER_CLASS_APP, 21, BER_FLAGS_NOOWNTAG, dissect_channelAdmitRequest },
  {  22, BER_CLASS_APP, 22, BER_FLAGS_NOOWNTAG, dissect_channelAdmitIndication },
  {  23, BER_CLASS_APP, 23, BER_FLAGS_NOOWNTAG, dissect_channelExpelRequest },
  {  24, BER_CLASS_APP, 24, BER_FLAGS_NOOWNTAG, dissect_channelExpelIndication },
  {  25, BER_CLASS_APP, 25, BER_FLAGS_NOOWNTAG, dissect_sendDataRequest },
  {  26, BER_CLASS_APP, 26, BER_FLAGS_NOOWNTAG, dissect_sendDataIndication },
  {  27, BER_CLASS_APP, 27, BER_FLAGS_NOOWNTAG, dissect_uniformSendDataRequest },
  {  28, BER_CLASS_APP, 28, BER_FLAGS_NOOWNTAG, dissect_uniformSendDataIndication },
  {  29, BER_CLASS_APP, 29, BER_FLAGS_NOOWNTAG, dissect_tokenGrabRequest },
  {  30, BER_CLASS_APP, 30, BER_FLAGS_NOOWNTAG, dissect_tokenGrabConfirm },
  {  31, BER_CLASS_APP, 31, BER_FLAGS_NOOWNTAG, dissect_tokenInhibitRequest },
  {  32, BER_CLASS_APP, 32, BER_FLAGS_NOOWNTAG, dissect_tokenInhibitConfirm },
  {  33, BER_CLASS_APP, 33, BER_FLAGS_NOOWNTAG, dissect_tokenGiveRequest },
  {  34, BER_CLASS_APP, 34, BER_FLAGS_NOOWNTAG, dissect_tokenGiveIndication },
  {  35, BER_CLASS_APP, 35, BER_FLAGS_NOOWNTAG, dissect_tokenGiveResponse },
  {  36, BER_CLASS_APP, 36, BER_FLAGS_NOOWNTAG, dissect_tokenGiveConfirm },
  {  37, BER_CLASS_APP, 37, BER_FLAGS_NOOWNTAG, dissect_tokenPleaseRequest },
  {  38, BER_CLASS_APP, 38, BER_FLAGS_NOOWNTAG, dissect_tokenPleaseIndication },
  {  39, BER_CLASS_APP, 39, BER_FLAGS_NOOWNTAG, dissect_tokenReleaseRequest },
  {  40, BER_CLASS_APP, 40, BER_FLAGS_NOOWNTAG, dissect_tokenReleaseConfirm },
  {  41, BER_CLASS_APP, 41, BER_FLAGS_NOOWNTAG, dissect_tokenTestRequest },
  {  42, BER_CLASS_APP, 42, BER_FLAGS_NOOWNTAG, dissect_tokenTestConfirm },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_t125_DomainMCSPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 32 "t125.cnf"
  	guint32 domainmcs_value;

  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     DomainMCSPDU_choice, hf_index, ett_t125_DomainMCSPDU,
                                     &domainmcs_value);

	if (check_col(actx->pinfo->cinfo, COL_INFO)){
		col_add_fstr(actx->pinfo->cinfo, COL_INFO, "MCS: %s ",
			val_to_str(domainmcs_value, t125_DomainMCSPDU_vals, "<unknown>"));
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
static int dissect_DomainMCSPDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_t125_DomainMCSPDU(FALSE, tvb, offset, &asn1_ctx, tree, hf_t125_DomainMCSPDU_PDU);
  return offset;
}


/*--- End of included file: packet-t125-fn.c ---*/
#line 65 "packet-t125-template.c"

static int
dissect_t125(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree)
{
  proto_item *item = NULL;
  proto_tree *tree = NULL;

  if (check_col(pinfo->cinfo, COL_PROTOCOL)){
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "T.125");
  }
  if (check_col(pinfo->cinfo, COL_INFO)){
    col_clear(pinfo->cinfo, COL_INFO);
  }

  item = proto_tree_add_item(parent_tree, proto_t125, tvb, 0, tvb_length(tvb), FALSE);
  tree = proto_item_add_subtree(item, ett_t125);


  dissect_ConnectMCSPDU_PDU(tvb, pinfo, tree);

  return tvb_length(tvb);
}


/*--- proto_register_t125 -------------------------------------------*/
void proto_register_t125(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-t125-hfarr.c ---*/
#line 1 "packet-t125-hfarr.c"
    { &hf_t125_ConnectMCSPDU_PDU,
      { "ConnectMCSPDU", "t125.ConnectMCSPDU",
        FT_UINT32, BASE_DEC, VALS(t125_ConnectMCSPDU_vals), 0,
        "t125.ConnectMCSPDU", HFILL }},
    { &hf_t125_DomainMCSPDU_PDU,
      { "DomainMCSPDU", "t125.DomainMCSPDU",
        FT_UINT32, BASE_DEC, VALS(t125_DomainMCSPDU_vals), 0,
        "t125.DomainMCSPDU", HFILL }},
    { &hf_t125_maxChannelIds,
      { "maxChannelIds", "t125.maxChannelIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.INTEGER_0_MAX", HFILL }},
    { &hf_t125_maxUserIds,
      { "maxUserIds", "t125.maxUserIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.INTEGER_0_MAX", HFILL }},
    { &hf_t125_maxTokenIds,
      { "maxTokenIds", "t125.maxTokenIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.INTEGER_0_MAX", HFILL }},
    { &hf_t125_numPriorities,
      { "numPriorities", "t125.numPriorities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.INTEGER_0_MAX", HFILL }},
    { &hf_t125_minThroughput,
      { "minThroughput", "t125.minThroughput",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.INTEGER_0_MAX", HFILL }},
    { &hf_t125_maxHeight,
      { "maxHeight", "t125.maxHeight",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.INTEGER_0_MAX", HFILL }},
    { &hf_t125_maxMCSPDUsize,
      { "maxMCSPDUsize", "t125.maxMCSPDUsize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.INTEGER_0_MAX", HFILL }},
    { &hf_t125_protocolVersion,
      { "protocolVersion", "t125.protocolVersion",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.INTEGER_0_MAX", HFILL }},
    { &hf_t125_callingDomainSelector,
      { "callingDomainSelector", "t125.callingDomainSelector",
        FT_BYTES, BASE_HEX, NULL, 0,
        "t125.OCTET_STRING", HFILL }},
    { &hf_t125_calledDomainSelector,
      { "calledDomainSelector", "t125.calledDomainSelector",
        FT_BYTES, BASE_HEX, NULL, 0,
        "t125.OCTET_STRING", HFILL }},
    { &hf_t125_upwardFlag,
      { "upwardFlag", "t125.upwardFlag",
        FT_BOOLEAN, 8, NULL, 0,
        "t125.BOOLEAN", HFILL }},
    { &hf_t125_targetParameters,
      { "targetParameters", "t125.targetParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.DomainParameters", HFILL }},
    { &hf_t125_minimumParameters,
      { "minimumParameters", "t125.minimumParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.DomainParameters", HFILL }},
    { &hf_t125_maximumParameters,
      { "maximumParameters", "t125.maximumParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.DomainParameters", HFILL }},
    { &hf_t125_userData,
      { "userData", "t125.userData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "t125.OCTET_STRING", HFILL }},
    { &hf_t125_result,
      { "result", "t125.result",
        FT_UINT32, BASE_DEC, VALS(t125_Result_vals), 0,
        "t125.Result", HFILL }},
    { &hf_t125_calledConnectId,
      { "calledConnectId", "t125.calledConnectId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.INTEGER_0_MAX", HFILL }},
    { &hf_t125_domainParameters,
      { "domainParameters", "t125.domainParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.DomainParameters", HFILL }},
    { &hf_t125_dataPriority,
      { "dataPriority", "t125.dataPriority",
        FT_UINT32, BASE_DEC, VALS(t125_DataPriority_vals), 0,
        "t125.DataPriority", HFILL }},
    { &hf_t125_heightLimit,
      { "heightLimit", "t125.heightLimit",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.INTEGER_0_MAX", HFILL }},
    { &hf_t125_subHeight,
      { "subHeight", "t125.subHeight",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.INTEGER_0_MAX", HFILL }},
    { &hf_t125_subInterval,
      { "subInterval", "t125.subInterval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.INTEGER_0_MAX", HFILL }},
    { &hf_t125_static,
      { "static", "t125.static",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.T_static", HFILL }},
    { &hf_t125_channelId,
      { "channelId", "t125.channelId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.StaticChannelId", HFILL }},
    { &hf_t125_userId,
      { "userId", "t125.userId",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.T_userId", HFILL }},
    { &hf_t125_joined,
      { "joined", "t125.joined",
        FT_BOOLEAN, 8, NULL, 0,
        "t125.BOOLEAN", HFILL }},
    { &hf_t125_userId_01,
      { "userId", "t125.userId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.UserId", HFILL }},
    { &hf_t125_private,
      { "private", "t125.private",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.T_private", HFILL }},
    { &hf_t125_channelId_01,
      { "channelId", "t125.channelId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.PrivateChannelId", HFILL }},
    { &hf_t125_manager,
      { "manager", "t125.manager",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.UserId", HFILL }},
    { &hf_t125_admitted,
      { "admitted", "t125.admitted",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.SET_OF_UserId", HFILL }},
    { &hf_t125_admitted_item,
      { "Item", "t125.admitted_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.UserId", HFILL }},
    { &hf_t125_assigned,
      { "assigned", "t125.assigned",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.T_assigned", HFILL }},
    { &hf_t125_channelId_02,
      { "channelId", "t125.channelId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.AssignedChannelId", HFILL }},
    { &hf_t125_mergeChannels,
      { "mergeChannels", "t125.mergeChannels",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.SET_OF_ChannelAttributes", HFILL }},
    { &hf_t125_mergeChannels_item,
      { "Item", "t125.mergeChannels_item",
        FT_UINT32, BASE_DEC, VALS(t125_ChannelAttributes_vals), 0,
        "t125.ChannelAttributes", HFILL }},
    { &hf_t125_purgeChannelIds,
      { "purgeChannelIds", "t125.purgeChannelIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.SET_OF_ChannelId", HFILL }},
    { &hf_t125_purgeChannelIds_item,
      { "Item", "t125.purgeChannelIds_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.ChannelId", HFILL }},
    { &hf_t125_detachUserIds,
      { "detachUserIds", "t125.detachUserIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.SET_OF_UserId", HFILL }},
    { &hf_t125_detachUserIds_item,
      { "Item", "t125.detachUserIds_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.UserId", HFILL }},
    { &hf_t125_grabbed,
      { "grabbed", "t125.grabbed",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.T_grabbed", HFILL }},
    { &hf_t125_tokenId,
      { "tokenId", "t125.tokenId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.TokenId", HFILL }},
    { &hf_t125_grabber,
      { "grabber", "t125.grabber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.UserId", HFILL }},
    { &hf_t125_inhibited,
      { "inhibited", "t125.inhibited",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.T_inhibited", HFILL }},
    { &hf_t125_inhibitors,
      { "inhibitors", "t125.inhibitors",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.SET_OF_UserId", HFILL }},
    { &hf_t125_inhibitors_item,
      { "Item", "t125.inhibitors_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.UserId", HFILL }},
    { &hf_t125_giving,
      { "giving", "t125.giving",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.T_giving", HFILL }},
    { &hf_t125_recipient,
      { "recipient", "t125.recipient",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.UserId", HFILL }},
    { &hf_t125_ungivable,
      { "ungivable", "t125.ungivable",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.T_ungivable", HFILL }},
    { &hf_t125_given,
      { "given", "t125.given",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.T_given", HFILL }},
    { &hf_t125_mergeTokens,
      { "mergeTokens", "t125.mergeTokens",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.SET_OF_TokenAttributes", HFILL }},
    { &hf_t125_mergeTokens_item,
      { "Item", "t125.mergeTokens_item",
        FT_UINT32, BASE_DEC, VALS(t125_TokenAttributes_vals), 0,
        "t125.TokenAttributes", HFILL }},
    { &hf_t125_purgeTokenIds,
      { "purgeTokenIds", "t125.purgeTokenIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.SET_OF_TokenId", HFILL }},
    { &hf_t125_purgeTokenIds_item,
      { "Item", "t125.purgeTokenIds_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.TokenId", HFILL }},
    { &hf_t125_reason,
      { "reason", "t125.reason",
        FT_UINT32, BASE_DEC, VALS(t125_Reason_vals), 0,
        "t125.Reason", HFILL }},
    { &hf_t125_diagnostic,
      { "diagnostic", "t125.diagnostic",
        FT_UINT32, BASE_DEC, VALS(t125_Diagnostic_vals), 0,
        "t125.Diagnostic", HFILL }},
    { &hf_t125_initialOctets,
      { "initialOctets", "t125.initialOctets",
        FT_BYTES, BASE_HEX, NULL, 0,
        "t125.OCTET_STRING", HFILL }},
    { &hf_t125_initiator,
      { "initiator", "t125.initiator",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.UserId", HFILL }},
    { &hf_t125_userIds,
      { "userIds", "t125.userIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.SET_OF_UserId", HFILL }},
    { &hf_t125_userIds_item,
      { "Item", "t125.userIds_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.UserId", HFILL }},
    { &hf_t125_channelId_03,
      { "channelId", "t125.channelId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.ChannelId", HFILL }},
    { &hf_t125_requested,
      { "requested", "t125.requested",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.ChannelId", HFILL }},
    { &hf_t125_channelIds,
      { "channelIds", "t125.channelIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.SET_OF_ChannelId", HFILL }},
    { &hf_t125_channelIds_item,
      { "Item", "t125.channelIds_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "t125.ChannelId", HFILL }},
    { &hf_t125_segmentation,
      { "segmentation", "t125.segmentation",
        FT_BYTES, BASE_HEX, NULL, 0,
        "t125.Segmentation", HFILL }},
    { &hf_t125_tokenStatus,
      { "tokenStatus", "t125.tokenStatus",
        FT_UINT32, BASE_DEC, VALS(t125_TokenStatus_vals), 0,
        "t125.TokenStatus", HFILL }},
    { &hf_t125_connect_initial,
      { "connect-initial", "t125.connect_initial",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.Connect_Initial", HFILL }},
    { &hf_t125_connect_response,
      { "connect-response", "t125.connect_response",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.Connect_Response", HFILL }},
    { &hf_t125_connect_additional,
      { "connect-additional", "t125.connect_additional",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.Connect_Additional", HFILL }},
    { &hf_t125_connect_result,
      { "connect-result", "t125.connect_result",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.Connect_Result", HFILL }},
    { &hf_t125_plumbDomainIndication,
      { "plumbDomainIndication", "t125.plumbDomainIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.PlumbDomainIndication", HFILL }},
    { &hf_t125_erectDomainRequest,
      { "erectDomainRequest", "t125.erectDomainRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.ErectDomainRequest", HFILL }},
    { &hf_t125_mergeChannelsRequest,
      { "mergeChannelsRequest", "t125.mergeChannelsRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.MergeChannelsRequest", HFILL }},
    { &hf_t125_mergeChannelsConfirm,
      { "mergeChannelsConfirm", "t125.mergeChannelsConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.MergeChannelsConfirm", HFILL }},
    { &hf_t125_purgeChannelsIndication,
      { "purgeChannelsIndication", "t125.purgeChannelsIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.PurgeChannelsIndication", HFILL }},
    { &hf_t125_mergeTokensRequest,
      { "mergeTokensRequest", "t125.mergeTokensRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.MergeTokensRequest", HFILL }},
    { &hf_t125_mergeTokensConfirm,
      { "mergeTokensConfirm", "t125.mergeTokensConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.MergeTokensConfirm", HFILL }},
    { &hf_t125_purgeTokensIndication,
      { "purgeTokensIndication", "t125.purgeTokensIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.PurgeTokensIndication", HFILL }},
    { &hf_t125_disconnectProviderUltimatum,
      { "disconnectProviderUltimatum", "t125.disconnectProviderUltimatum",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.DisconnectProviderUltimatum", HFILL }},
    { &hf_t125_rejectMCSPDUUltimatum,
      { "rejectMCSPDUUltimatum", "t125.rejectMCSPDUUltimatum",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.RejectMCSPDUUltimatum", HFILL }},
    { &hf_t125_attachUserRequest,
      { "attachUserRequest", "t125.attachUserRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.AttachUserRequest", HFILL }},
    { &hf_t125_attachUserConfirm,
      { "attachUserConfirm", "t125.attachUserConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.AttachUserConfirm", HFILL }},
    { &hf_t125_detachUserRequest,
      { "detachUserRequest", "t125.detachUserRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.DetachUserRequest", HFILL }},
    { &hf_t125_detachUserIndication,
      { "detachUserIndication", "t125.detachUserIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.DetachUserIndication", HFILL }},
    { &hf_t125_channelJoinRequest,
      { "channelJoinRequest", "t125.channelJoinRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.ChannelJoinRequest", HFILL }},
    { &hf_t125_channelJoinConfirm,
      { "channelJoinConfirm", "t125.channelJoinConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.ChannelJoinConfirm", HFILL }},
    { &hf_t125_channelLeaveRequest,
      { "channelLeaveRequest", "t125.channelLeaveRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.ChannelLeaveRequest", HFILL }},
    { &hf_t125_channelConveneRequest,
      { "channelConveneRequest", "t125.channelConveneRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.ChannelConveneRequest", HFILL }},
    { &hf_t125_channelConveneConfirm,
      { "channelConveneConfirm", "t125.channelConveneConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.ChannelConveneConfirm", HFILL }},
    { &hf_t125_channelDisbandRequest,
      { "channelDisbandRequest", "t125.channelDisbandRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.ChannelDisbandRequest", HFILL }},
    { &hf_t125_channelDisbandIndication,
      { "channelDisbandIndication", "t125.channelDisbandIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.ChannelDisbandIndication", HFILL }},
    { &hf_t125_channelAdmitRequest,
      { "channelAdmitRequest", "t125.channelAdmitRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.ChannelAdmitRequest", HFILL }},
    { &hf_t125_channelAdmitIndication,
      { "channelAdmitIndication", "t125.channelAdmitIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.ChannelAdmitIndication", HFILL }},
    { &hf_t125_channelExpelRequest,
      { "channelExpelRequest", "t125.channelExpelRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.ChannelExpelRequest", HFILL }},
    { &hf_t125_channelExpelIndication,
      { "channelExpelIndication", "t125.channelExpelIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.ChannelExpelIndication", HFILL }},
    { &hf_t125_sendDataRequest,
      { "sendDataRequest", "t125.sendDataRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.SendDataRequest", HFILL }},
    { &hf_t125_sendDataIndication,
      { "sendDataIndication", "t125.sendDataIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.SendDataIndication", HFILL }},
    { &hf_t125_uniformSendDataRequest,
      { "uniformSendDataRequest", "t125.uniformSendDataRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.UniformSendDataRequest", HFILL }},
    { &hf_t125_uniformSendDataIndication,
      { "uniformSendDataIndication", "t125.uniformSendDataIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.UniformSendDataIndication", HFILL }},
    { &hf_t125_tokenGrabRequest,
      { "tokenGrabRequest", "t125.tokenGrabRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.TokenGrabRequest", HFILL }},
    { &hf_t125_tokenGrabConfirm,
      { "tokenGrabConfirm", "t125.tokenGrabConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.TokenGrabConfirm", HFILL }},
    { &hf_t125_tokenInhibitRequest,
      { "tokenInhibitRequest", "t125.tokenInhibitRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.TokenInhibitRequest", HFILL }},
    { &hf_t125_tokenInhibitConfirm,
      { "tokenInhibitConfirm", "t125.tokenInhibitConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.TokenInhibitConfirm", HFILL }},
    { &hf_t125_tokenGiveRequest,
      { "tokenGiveRequest", "t125.tokenGiveRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.TokenGiveRequest", HFILL }},
    { &hf_t125_tokenGiveIndication,
      { "tokenGiveIndication", "t125.tokenGiveIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.TokenGiveIndication", HFILL }},
    { &hf_t125_tokenGiveResponse,
      { "tokenGiveResponse", "t125.tokenGiveResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.TokenGiveResponse", HFILL }},
    { &hf_t125_tokenGiveConfirm,
      { "tokenGiveConfirm", "t125.tokenGiveConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.TokenGiveConfirm", HFILL }},
    { &hf_t125_tokenPleaseRequest,
      { "tokenPleaseRequest", "t125.tokenPleaseRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.TokenPleaseRequest", HFILL }},
    { &hf_t125_tokenPleaseIndication,
      { "tokenPleaseIndication", "t125.tokenPleaseIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.TokenPleaseIndication", HFILL }},
    { &hf_t125_tokenReleaseRequest,
      { "tokenReleaseRequest", "t125.tokenReleaseRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.TokenReleaseRequest", HFILL }},
    { &hf_t125_tokenReleaseConfirm,
      { "tokenReleaseConfirm", "t125.tokenReleaseConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.TokenReleaseConfirm", HFILL }},
    { &hf_t125_tokenTestRequest,
      { "tokenTestRequest", "t125.tokenTestRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.TokenTestRequest", HFILL }},
    { &hf_t125_tokenTestConfirm,
      { "tokenTestConfirm", "t125.tokenTestConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        "t125.TokenTestConfirm", HFILL }},
    { &hf_t125_Segmentation_begin,
      { "begin", "t125.begin",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_t125_Segmentation_end,
      { "end", "t125.end",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},

/*--- End of included file: packet-t125-hfarr.c ---*/
#line 95 "packet-t125-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_t125,

/*--- Included file: packet-t125-ettarr.c ---*/
#line 1 "packet-t125-ettarr.c"
    &ett_t125_Segmentation,
    &ett_t125_DomainParameters,
    &ett_t125_Connect_Initial,
    &ett_t125_Connect_Response,
    &ett_t125_Connect_Additional,
    &ett_t125_Connect_Result,
    &ett_t125_PlumbDomainIndication,
    &ett_t125_ErectDomainRequest,
    &ett_t125_ChannelAttributes,
    &ett_t125_T_static,
    &ett_t125_T_userId,
    &ett_t125_T_private,
    &ett_t125_SET_OF_UserId,
    &ett_t125_T_assigned,
    &ett_t125_MergeChannelsRequest,
    &ett_t125_SET_OF_ChannelAttributes,
    &ett_t125_SET_OF_ChannelId,
    &ett_t125_MergeChannelsConfirm,
    &ett_t125_PurgeChannelsIndication,
    &ett_t125_TokenAttributes,
    &ett_t125_T_grabbed,
    &ett_t125_T_inhibited,
    &ett_t125_T_giving,
    &ett_t125_T_ungivable,
    &ett_t125_T_given,
    &ett_t125_MergeTokensRequest,
    &ett_t125_SET_OF_TokenAttributes,
    &ett_t125_SET_OF_TokenId,
    &ett_t125_MergeTokensConfirm,
    &ett_t125_PurgeTokensIndication,
    &ett_t125_DisconnectProviderUltimatum,
    &ett_t125_RejectMCSPDUUltimatum,
    &ett_t125_AttachUserRequest,
    &ett_t125_AttachUserConfirm,
    &ett_t125_DetachUserRequest,
    &ett_t125_DetachUserIndication,
    &ett_t125_ChannelJoinRequest,
    &ett_t125_ChannelJoinConfirm,
    &ett_t125_ChannelLeaveRequest,
    &ett_t125_ChannelConveneRequest,
    &ett_t125_ChannelConveneConfirm,
    &ett_t125_ChannelDisbandRequest,
    &ett_t125_ChannelDisbandIndication,
    &ett_t125_ChannelAdmitRequest,
    &ett_t125_ChannelAdmitIndication,
    &ett_t125_ChannelExpelRequest,
    &ett_t125_ChannelExpelIndication,
    &ett_t125_SendDataRequest,
    &ett_t125_SendDataIndication,
    &ett_t125_UniformSendDataRequest,
    &ett_t125_UniformSendDataIndication,
    &ett_t125_TokenGrabRequest,
    &ett_t125_TokenGrabConfirm,
    &ett_t125_TokenInhibitRequest,
    &ett_t125_TokenInhibitConfirm,
    &ett_t125_TokenGiveRequest,
    &ett_t125_TokenGiveIndication,
    &ett_t125_TokenGiveResponse,
    &ett_t125_TokenGiveConfirm,
    &ett_t125_TokenPleaseRequest,
    &ett_t125_TokenPleaseIndication,
    &ett_t125_TokenReleaseRequest,
    &ett_t125_TokenReleaseConfirm,
    &ett_t125_TokenTestRequest,
    &ett_t125_TokenTestConfirm,
    &ett_t125_ConnectMCSPDU,
    &ett_t125_DomainMCSPDU,

/*--- End of included file: packet-t125-ettarr.c ---*/
#line 101 "packet-t125-template.c"
  };

  /* Register protocol */
  proto_t125 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_t125, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  new_register_dissector("t125", dissect_t125, proto_t125);
}


/*--- proto_reg_handoff_t125 ---------------------------------------*/
void proto_reg_handoff_t125(void) {
}
