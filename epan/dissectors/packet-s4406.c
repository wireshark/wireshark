/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-s4406.c                                                             */
/* ../../tools/asn2wrs.py -b -p s4406 -c ./s4406.cnf -s ./packet-s4406-template -D . s4406.asn */

/* Input file: packet-s4406-template.c */

#line 1 "packet-s4406-template.c"
/* packet-s4406.c
 * Routines for STANAG 4406 (X.400 Military Message Extensions)  packet dissection
 * Graeme Lunt 2005
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
#include <epan/asn1.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"

#include "packet-x509if.h"

#include "packet-s4406.h"
#include "packet-x411.h" 
#include "packet-x420.h" 

#define PNAME  "STANAG 4406 Military Message"
#define PSNAME "STANAG 4406"
#define PFNAME "s4406"

/* Initialize the protocol and registered fields */
int proto_s4406 = -1;


/*--- Included file: packet-s4406-hf.c ---*/
#line 1 "packet-s4406-hf.c"
static int hf_s4406_InformationObject_PDU = -1;   /* InformationObject */
static int hf_s4406_MMMessageData_PDU = -1;       /* MMMessageData */
static int hf_s4406_MMMessageParameters_PDU = -1;  /* MMMessageParameters */
static int hf_s4406_ExemptedAddressSeq_PDU = -1;  /* ExemptedAddressSeq */
static int hf_s4406_ExtendedAuthorisationInfo_PDU = -1;  /* ExtendedAuthorisationInfo */
static int hf_s4406_DistributionCodes_PDU = -1;   /* DistributionCodes */
static int hf_s4406_HandlingInstructions_PDU = -1;  /* HandlingInstructions */
static int hf_s4406_MessageInstructions_PDU = -1;  /* MessageInstructions */
static int hf_s4406_CodressMessage_PDU = -1;      /* CodressMessage */
static int hf_s4406_OriginatorReference_PDU = -1;  /* OriginatorReference */
static int hf_s4406_PrimaryPrecedence_PDU = -1;   /* PrimaryPrecedence */
static int hf_s4406_CopyPrecedence_PDU = -1;      /* CopyPrecedence */
static int hf_s4406_MessageType_PDU = -1;         /* MessageType */
static int hf_s4406_AddressListDesignatorSeq_PDU = -1;  /* AddressListDesignatorSeq */
static int hf_s4406_OtherRecipientDesignatorSeq_PDU = -1;  /* OtherRecipientDesignatorSeq */
static int hf_s4406_PilotInformationSeq_PDU = -1;  /* PilotInformationSeq */
static int hf_s4406_Acp127MessageIdentifier_PDU = -1;  /* Acp127MessageIdentifier */
static int hf_s4406_OriginatorPlad_PDU = -1;      /* OriginatorPlad */
static int hf_s4406_Acp127NotificationType_PDU = -1;  /* Acp127NotificationType */
static int hf_s4406_SecurityInformationLabels_PDU = -1;  /* SecurityInformationLabels */
static int hf_s4406_PriorityLevelQualifier_PDU = -1;  /* PriorityLevelQualifier */
static int hf_s4406_mm = -1;                      /* IPM */
static int hf_s4406_mn = -1;                      /* IPN */
static int hf_s4406_ExemptedAddressSeq_item = -1;  /* ExemptedAddress */
static int hf_s4406_sics = -1;                    /* SEQUENCE_OF_Sic */
static int hf_s4406_sics_item = -1;               /* Sic */
static int hf_s4406_dist_Extensions = -1;         /* SEQUENCE_OF_DistributionExtensionField */
static int hf_s4406_dist_Extensions_item = -1;    /* DistributionExtensionField */
static int hf_s4406_dist_type = -1;               /* OBJECT_IDENTIFIER */
static int hf_s4406_dist_value = -1;              /* T_dist_value */
static int hf_s4406_HandlingInstructions_item = -1;  /* MilitaryString */
static int hf_s4406_MessageInstructions_item = -1;  /* MilitaryString */
static int hf_s4406_message_type_type = -1;       /* TypeMessage */
static int hf_s4406_identifier = -1;              /* MessageIdentifier */
static int hf_s4406_AddressListDesignatorSeq_item = -1;  /* AddressListDesignator */
static int hf_s4406_address_list_type = -1;       /* AddressListType */
static int hf_s4406_listName = -1;                /* ORDescriptor */
static int hf_s4406_notificationRequest = -1;     /* AddressListRequest */
static int hf_s4406_replyRequest = -1;            /* AddressListRequest */
static int hf_s4406_OtherRecipientDesignatorSeq_item = -1;  /* OtherRecipientDesignator */
static int hf_s4406_other_recipient_type = -1;    /* OtherRecipientType */
static int hf_s4406_designator = -1;              /* MilitaryString */
static int hf_s4406_PilotInformationSeq_item = -1;  /* PilotInformation */
static int hf_s4406_pilotPrecedence = -1;         /* PilotPrecedence */
static int hf_s4406_pilotRecipient = -1;          /* SEQUENCE_OF_ORDescriptor */
static int hf_s4406_pilotRecipient_item = -1;     /* ORDescriptor */
static int hf_s4406_pilotSecurity = -1;           /* SecurityLabel */
static int hf_s4406_pilotHandling = -1;           /* SEQUENCE_OF_MilitaryString */
static int hf_s4406_pilotHandling_item = -1;      /* MilitaryString */
static int hf_s4406_content_security_label = -1;  /* SecurityLabel */
static int hf_s4406_heading_security_label = -1;  /* SecurityLabel */
static int hf_s4406_body_part_security_labels = -1;  /* SEQUENCE_OF_BodyPartSecurityLabel */
static int hf_s4406_body_part_security_labels_item = -1;  /* BodyPartSecurityLabel */
static int hf_s4406_body_part_security_label = -1;  /* SecurityLabel */
static int hf_s4406_body_part_sequence_number = -1;  /* BodyPartSequenceNumber */
/* named bits */
static int hf_s4406_Acp127NotificationType_negative = -1;
static int hf_s4406_Acp127NotificationType_positive = -1;
static int hf_s4406_Acp127NotificationType_transfer = -1;

/*--- End of included file: packet-s4406-hf.c ---*/
#line 53 "packet-s4406-template.c"

/* Initialize the subtree pointers */
static gint ett_s4406 = -1;

/*--- Included file: packet-s4406-ett.c ---*/
#line 1 "packet-s4406-ett.c"
static gint ett_s4406_InformationObject = -1;
static gint ett_s4406_ExemptedAddressSeq = -1;
static gint ett_s4406_DistributionCodes = -1;
static gint ett_s4406_SEQUENCE_OF_Sic = -1;
static gint ett_s4406_SEQUENCE_OF_DistributionExtensionField = -1;
static gint ett_s4406_DistributionExtensionField = -1;
static gint ett_s4406_HandlingInstructions = -1;
static gint ett_s4406_MessageInstructions = -1;
static gint ett_s4406_MessageType = -1;
static gint ett_s4406_AddressListDesignatorSeq = -1;
static gint ett_s4406_AddressListDesignator = -1;
static gint ett_s4406_OtherRecipientDesignatorSeq = -1;
static gint ett_s4406_OtherRecipientDesignator = -1;
static gint ett_s4406_PilotInformationSeq = -1;
static gint ett_s4406_PilotInformation = -1;
static gint ett_s4406_SEQUENCE_OF_ORDescriptor = -1;
static gint ett_s4406_SEQUENCE_OF_MilitaryString = -1;
static gint ett_s4406_Acp127NotificationType = -1;
static gint ett_s4406_SecurityInformationLabels = -1;
static gint ett_s4406_SEQUENCE_OF_BodyPartSecurityLabel = -1;
static gint ett_s4406_BodyPartSecurityLabel = -1;

/*--- End of included file: packet-s4406-ett.c ---*/
#line 57 "packet-s4406-template.c"


/*--- Included file: packet-s4406-fn.c ---*/
#line 1 "packet-s4406-fn.c"

static const value_string s4406_InformationObject_vals[] = {
  {   0, "mm" },
  {   1, "mn" },
  { 0, NULL }
};

static const ber_choice_t InformationObject_choice[] = {
  {   0, &hf_s4406_mm            , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x420_IPM },
  {   1, &hf_s4406_mn            , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x420_IPN },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_s4406_InformationObject(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 InformationObject_choice, hf_index, ett_s4406_InformationObject,
                                 NULL);

  return offset;
}



static int
dissect_s4406_MMMessageData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x420_IPM(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_s4406_MMMessageParameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x420_MessageParameters(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_s4406_ExemptedAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x420_ORDescriptor(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t ExemptedAddressSeq_sequence_of[1] = {
  { &hf_s4406_ExemptedAddressSeq_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_s4406_ExemptedAddress },
};

static int
dissect_s4406_ExemptedAddressSeq(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      ExemptedAddressSeq_sequence_of, hf_index, ett_s4406_ExemptedAddressSeq);

  return offset;
}



static int
dissect_s4406_ExtendedAuthorisationInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_UTCTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_s4406_Sic(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Sic_sequence_of[1] = {
  { &hf_s4406_sics_item     , BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_s4406_Sic },
};

static int
dissect_s4406_SEQUENCE_OF_Sic(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Sic_sequence_of, hf_index, ett_s4406_SEQUENCE_OF_Sic);

  return offset;
}



static int
dissect_s4406_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_s4406_T_dist_value(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 67 "s4406.cnf"
/* XXX: not implemented */



  return offset;
}


static const ber_sequence_t DistributionExtensionField_sequence[] = {
  { &hf_s4406_dist_type     , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_s4406_OBJECT_IDENTIFIER },
  { &hf_s4406_dist_value    , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_s4406_T_dist_value },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_s4406_DistributionExtensionField(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DistributionExtensionField_sequence, hf_index, ett_s4406_DistributionExtensionField);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_DistributionExtensionField_sequence_of[1] = {
  { &hf_s4406_dist_Extensions_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_s4406_DistributionExtensionField },
};

static int
dissect_s4406_SEQUENCE_OF_DistributionExtensionField(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_DistributionExtensionField_sequence_of, hf_index, ett_s4406_SEQUENCE_OF_DistributionExtensionField);

  return offset;
}


static const ber_sequence_t DistributionCodes_set[] = {
  { &hf_s4406_sics          , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_s4406_SEQUENCE_OF_Sic },
  { &hf_s4406_dist_Extensions, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_s4406_SEQUENCE_OF_DistributionExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_s4406_DistributionCodes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              DistributionCodes_set, hf_index, ett_s4406_DistributionCodes);

  return offset;
}



static int
dissect_s4406_MilitaryString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t HandlingInstructions_sequence_of[1] = {
  { &hf_s4406_HandlingInstructions_item, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_s4406_MilitaryString },
};

static int
dissect_s4406_HandlingInstructions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      HandlingInstructions_sequence_of, hf_index, ett_s4406_HandlingInstructions);

  return offset;
}


static const ber_sequence_t MessageInstructions_sequence_of[1] = {
  { &hf_s4406_MessageInstructions_item, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_s4406_MilitaryString },
};

static int
dissect_s4406_MessageInstructions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      MessageInstructions_sequence_of, hf_index, ett_s4406_MessageInstructions);

  return offset;
}



static int
dissect_s4406_CodressMessage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_s4406_OriginatorReference(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_s4406_MilitaryString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string s4406_PrimaryPrecedence_vals[] = {
  {   0, "deferred" },
  {   1, "routine" },
  {   2, "priority" },
  {   3, "immediate" },
  {   4, "flash" },
  {   5, "override" },
  {  16, "ecp" },
  {  17, "critic" },
  {  18, "override" },
  { 0, NULL }
};


static int
dissect_s4406_PrimaryPrecedence(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 72 "s4406.cnf"
  int precedence = -1;
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &precedence);

  if((precedence != -1) && check_col(actx->pinfo->cinfo, COL_INFO))
   col_append_fstr(actx->pinfo->cinfo, COL_INFO, " (primary=%s)", val_to_str(precedence, s4406_PrimaryPrecedence_vals, "precedence(%d)"));



  return offset;
}


static const value_string s4406_CopyPrecedence_vals[] = {
  {   0, "deferred" },
  {   1, "routine" },
  {   2, "priority" },
  {   3, "immediate" },
  {   4, "flash" },
  {   5, "override" },
  {  16, "ecp" },
  {  17, "critic" },
  {  18, "override" },
  { 0, NULL }
};


static int
dissect_s4406_CopyPrecedence(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 80 "s4406.cnf"
  int precedence = -1;
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &precedence);

  if((precedence != -1) && check_col(actx->pinfo->cinfo, COL_INFO))
   col_append_fstr(actx->pinfo->cinfo, COL_INFO, " (copy=%s)", val_to_str(precedence, s4406_CopyPrecedence_vals, "precedence(%d)"));


  return offset;
}


static const value_string s4406_TypeMessage_vals[] = {
  {   0, "exercise" },
  {   1, "operation" },
  {   2, "project" },
  {   3, "drill" },
  { 0, NULL }
};


static int
dissect_s4406_TypeMessage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_s4406_MessageIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_s4406_MilitaryString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t MessageType_set[] = {
  { &hf_s4406_message_type_type, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_s4406_TypeMessage },
  { &hf_s4406_identifier    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_s4406_MessageIdentifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_s4406_MessageType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              MessageType_set, hf_index, ett_s4406_MessageType);

  return offset;
}


static const value_string s4406_AddressListType_vals[] = {
  {   0, "primaryAddressList" },
  {   1, "copyAddressList" },
  { 0, NULL }
};


static int
dissect_s4406_AddressListType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string s4406_AddressListRequest_vals[] = {
  {   0, "action" },
  {   1, "info" },
  {   2, "both" },
  { 0, NULL }
};


static int
dissect_s4406_AddressListRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t AddressListDesignator_set[] = {
  { &hf_s4406_address_list_type, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_s4406_AddressListType },
  { &hf_s4406_listName      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x420_ORDescriptor },
  { &hf_s4406_notificationRequest, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_s4406_AddressListRequest },
  { &hf_s4406_replyRequest  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_s4406_AddressListRequest },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_s4406_AddressListDesignator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              AddressListDesignator_set, hf_index, ett_s4406_AddressListDesignator);

  return offset;
}


static const ber_sequence_t AddressListDesignatorSeq_sequence_of[1] = {
  { &hf_s4406_AddressListDesignatorSeq_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_s4406_AddressListDesignator },
};

static int
dissect_s4406_AddressListDesignatorSeq(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      AddressListDesignatorSeq_sequence_of, hf_index, ett_s4406_AddressListDesignatorSeq);

  return offset;
}


static const value_string s4406_OtherRecipientType_vals[] = {
  {   0, "primary" },
  {   1, "copy" },
  { 0, NULL }
};


static int
dissect_s4406_OtherRecipientType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t OtherRecipientDesignator_set[] = {
  { &hf_s4406_other_recipient_type, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_s4406_OtherRecipientType },
  { &hf_s4406_designator    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_s4406_MilitaryString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_s4406_OtherRecipientDesignator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              OtherRecipientDesignator_set, hf_index, ett_s4406_OtherRecipientDesignator);

  return offset;
}


static const ber_sequence_t OtherRecipientDesignatorSeq_sequence_of[1] = {
  { &hf_s4406_OtherRecipientDesignatorSeq_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_s4406_OtherRecipientDesignator },
};

static int
dissect_s4406_OtherRecipientDesignatorSeq(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      OtherRecipientDesignatorSeq_sequence_of, hf_index, ett_s4406_OtherRecipientDesignatorSeq);

  return offset;
}


static const value_string s4406_PilotPrecedence_vals[] = {
  {   0, "deferred" },
  {   1, "routine" },
  {   2, "priority" },
  {   3, "immediate" },
  {   4, "flash" },
  {   5, "override" },
  {  16, "ecp" },
  {  17, "critic" },
  {  18, "override" },
  { 0, NULL }
};


static int
dissect_s4406_PilotPrecedence(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ORDescriptor_sequence_of[1] = {
  { &hf_s4406_pilotRecipient_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x420_ORDescriptor },
};

static int
dissect_s4406_SEQUENCE_OF_ORDescriptor(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ORDescriptor_sequence_of, hf_index, ett_s4406_SEQUENCE_OF_ORDescriptor);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_MilitaryString_sequence_of[1] = {
  { &hf_s4406_pilotHandling_item, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_s4406_MilitaryString },
};

static int
dissect_s4406_SEQUENCE_OF_MilitaryString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_MilitaryString_sequence_of, hf_index, ett_s4406_SEQUENCE_OF_MilitaryString);

  return offset;
}


static const ber_sequence_t PilotInformation_sequence[] = {
  { &hf_s4406_pilotPrecedence, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_s4406_PilotPrecedence },
  { &hf_s4406_pilotRecipient, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_s4406_SEQUENCE_OF_ORDescriptor },
  { &hf_s4406_pilotSecurity , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SecurityLabel },
  { &hf_s4406_pilotHandling , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_s4406_SEQUENCE_OF_MilitaryString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_s4406_PilotInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PilotInformation_sequence, hf_index, ett_s4406_PilotInformation);

  return offset;
}


static const ber_sequence_t PilotInformationSeq_sequence_of[1] = {
  { &hf_s4406_PilotInformationSeq_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_s4406_PilotInformation },
};

static int
dissect_s4406_PilotInformationSeq(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      PilotInformationSeq_sequence_of, hf_index, ett_s4406_PilotInformationSeq);

  return offset;
}



static int
dissect_s4406_Acp127MessageIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_s4406_MilitaryString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_s4406_OriginatorPlad(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_s4406_MilitaryString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const asn_namedbit Acp127NotificationType_bits[] = {
  {  0, &hf_s4406_Acp127NotificationType_negative, -1, -1, "negative", NULL },
  {  1, &hf_s4406_Acp127NotificationType_positive, -1, -1, "positive", NULL },
  {  2, &hf_s4406_Acp127NotificationType_transfer, -1, -1, "transfer", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_s4406_Acp127NotificationType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Acp127NotificationType_bits, hf_index, ett_s4406_Acp127NotificationType,
                                    NULL);

  return offset;
}



static int
dissect_s4406_BodyPartSequenceNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t BodyPartSecurityLabel_set[] = {
  { &hf_s4406_body_part_security_label, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_SecurityLabel },
  { &hf_s4406_body_part_sequence_number, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_s4406_BodyPartSequenceNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_s4406_BodyPartSecurityLabel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              BodyPartSecurityLabel_set, hf_index, ett_s4406_BodyPartSecurityLabel);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_BodyPartSecurityLabel_sequence_of[1] = {
  { &hf_s4406_body_part_security_labels_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_s4406_BodyPartSecurityLabel },
};

static int
dissect_s4406_SEQUENCE_OF_BodyPartSecurityLabel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_BodyPartSecurityLabel_sequence_of, hf_index, ett_s4406_SEQUENCE_OF_BodyPartSecurityLabel);

  return offset;
}


static const ber_sequence_t SecurityInformationLabels_sequence[] = {
  { &hf_s4406_content_security_label, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_SecurityLabel },
  { &hf_s4406_heading_security_label, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SecurityLabel },
  { &hf_s4406_body_part_security_labels, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_s4406_SEQUENCE_OF_BodyPartSecurityLabel },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_s4406_SecurityInformationLabels(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SecurityInformationLabels_sequence, hf_index, ett_s4406_SecurityInformationLabels);

  return offset;
}


static const value_string s4406_PriorityLevelQualifier_vals[] = {
  {   0, "low" },
  {   1, "high" },
  { 0, NULL }
};


static int
dissect_s4406_PriorityLevelQualifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}

/*--- PDUs ---*/

static void dissect_InformationObject_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_s4406_InformationObject(FALSE, tvb, 0, &asn1_ctx, tree, hf_s4406_InformationObject_PDU);
}
static void dissect_MMMessageData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_s4406_MMMessageData(FALSE, tvb, 0, &asn1_ctx, tree, hf_s4406_MMMessageData_PDU);
}
static void dissect_MMMessageParameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_s4406_MMMessageParameters(FALSE, tvb, 0, &asn1_ctx, tree, hf_s4406_MMMessageParameters_PDU);
}
static void dissect_ExemptedAddressSeq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_s4406_ExemptedAddressSeq(FALSE, tvb, 0, &asn1_ctx, tree, hf_s4406_ExemptedAddressSeq_PDU);
}
static void dissect_ExtendedAuthorisationInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_s4406_ExtendedAuthorisationInfo(FALSE, tvb, 0, &asn1_ctx, tree, hf_s4406_ExtendedAuthorisationInfo_PDU);
}
static void dissect_DistributionCodes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_s4406_DistributionCodes(FALSE, tvb, 0, &asn1_ctx, tree, hf_s4406_DistributionCodes_PDU);
}
static void dissect_HandlingInstructions_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_s4406_HandlingInstructions(FALSE, tvb, 0, &asn1_ctx, tree, hf_s4406_HandlingInstructions_PDU);
}
static void dissect_MessageInstructions_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_s4406_MessageInstructions(FALSE, tvb, 0, &asn1_ctx, tree, hf_s4406_MessageInstructions_PDU);
}
static void dissect_CodressMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_s4406_CodressMessage(FALSE, tvb, 0, &asn1_ctx, tree, hf_s4406_CodressMessage_PDU);
}
static void dissect_OriginatorReference_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_s4406_OriginatorReference(FALSE, tvb, 0, &asn1_ctx, tree, hf_s4406_OriginatorReference_PDU);
}
static void dissect_PrimaryPrecedence_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_s4406_PrimaryPrecedence(FALSE, tvb, 0, &asn1_ctx, tree, hf_s4406_PrimaryPrecedence_PDU);
}
static void dissect_CopyPrecedence_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_s4406_CopyPrecedence(FALSE, tvb, 0, &asn1_ctx, tree, hf_s4406_CopyPrecedence_PDU);
}
static void dissect_MessageType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_s4406_MessageType(FALSE, tvb, 0, &asn1_ctx, tree, hf_s4406_MessageType_PDU);
}
static void dissect_AddressListDesignatorSeq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_s4406_AddressListDesignatorSeq(FALSE, tvb, 0, &asn1_ctx, tree, hf_s4406_AddressListDesignatorSeq_PDU);
}
static void dissect_OtherRecipientDesignatorSeq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_s4406_OtherRecipientDesignatorSeq(FALSE, tvb, 0, &asn1_ctx, tree, hf_s4406_OtherRecipientDesignatorSeq_PDU);
}
static void dissect_PilotInformationSeq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_s4406_PilotInformationSeq(FALSE, tvb, 0, &asn1_ctx, tree, hf_s4406_PilotInformationSeq_PDU);
}
static void dissect_Acp127MessageIdentifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_s4406_Acp127MessageIdentifier(FALSE, tvb, 0, &asn1_ctx, tree, hf_s4406_Acp127MessageIdentifier_PDU);
}
static void dissect_OriginatorPlad_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_s4406_OriginatorPlad(FALSE, tvb, 0, &asn1_ctx, tree, hf_s4406_OriginatorPlad_PDU);
}
static void dissect_Acp127NotificationType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_s4406_Acp127NotificationType(FALSE, tvb, 0, &asn1_ctx, tree, hf_s4406_Acp127NotificationType_PDU);
}
static void dissect_SecurityInformationLabels_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_s4406_SecurityInformationLabels(FALSE, tvb, 0, &asn1_ctx, tree, hf_s4406_SecurityInformationLabels_PDU);
}
static void dissect_PriorityLevelQualifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_s4406_PriorityLevelQualifier(FALSE, tvb, 0, &asn1_ctx, tree, hf_s4406_PriorityLevelQualifier_PDU);
}


/*--- End of included file: packet-s4406-fn.c ---*/
#line 59 "packet-s4406-template.c"


/*
* Dissect STANAG 4406 PDUs inside a PPDU.
*/
static void
dissect_s4406(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_s4406, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_s4406);
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "S4406");
	col_set_str(pinfo->cinfo, COL_INFO, "Military");

	dissect_s4406_InformationObject(TRUE, tvb, offset, &asn1_ctx , tree, -1);
}



/*--- proto_register_s4406 -------------------------------------------*/
void proto_register_s4406(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {

/*--- Included file: packet-s4406-hfarr.c ---*/
#line 1 "packet-s4406-hfarr.c"
    { &hf_s4406_InformationObject_PDU,
      { "InformationObject", "s4406.InformationObject",
        FT_UINT32, BASE_DEC, VALS(x420_InformationObject_vals), 0,
        "s4406.InformationObject", HFILL }},
    { &hf_s4406_MMMessageData_PDU,
      { "MMMessageData", "s4406.MMMessageData",
        FT_NONE, BASE_NONE, NULL, 0,
        "s4406.MMMessageData", HFILL }},
    { &hf_s4406_MMMessageParameters_PDU,
      { "MMMessageParameters", "s4406.MMMessageParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "s4406.MMMessageParameters", HFILL }},
    { &hf_s4406_ExemptedAddressSeq_PDU,
      { "ExemptedAddressSeq", "s4406.ExemptedAddressSeq",
        FT_UINT32, BASE_DEC, NULL, 0,
        "s4406.ExemptedAddressSeq", HFILL }},
    { &hf_s4406_ExtendedAuthorisationInfo_PDU,
      { "ExtendedAuthorisationInfo", "s4406.ExtendedAuthorisationInfo",
        FT_STRING, BASE_NONE, NULL, 0,
        "s4406.ExtendedAuthorisationInfo", HFILL }},
    { &hf_s4406_DistributionCodes_PDU,
      { "DistributionCodes", "s4406.DistributionCodes",
        FT_NONE, BASE_NONE, NULL, 0,
        "s4406.DistributionCodes", HFILL }},
    { &hf_s4406_HandlingInstructions_PDU,
      { "HandlingInstructions", "s4406.HandlingInstructions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "s4406.HandlingInstructions", HFILL }},
    { &hf_s4406_MessageInstructions_PDU,
      { "MessageInstructions", "s4406.MessageInstructions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "s4406.MessageInstructions", HFILL }},
    { &hf_s4406_CodressMessage_PDU,
      { "CodressMessage", "s4406.CodressMessage",
        FT_INT32, BASE_DEC, NULL, 0,
        "s4406.CodressMessage", HFILL }},
    { &hf_s4406_OriginatorReference_PDU,
      { "OriginatorReference", "s4406.OriginatorReference",
        FT_STRING, BASE_NONE, NULL, 0,
        "s4406.OriginatorReference", HFILL }},
    { &hf_s4406_PrimaryPrecedence_PDU,
      { "PrimaryPrecedence", "s4406.PrimaryPrecedence",
        FT_INT32, BASE_DEC, VALS(s4406_PrimaryPrecedence_vals), 0,
        "s4406.PrimaryPrecedence", HFILL }},
    { &hf_s4406_CopyPrecedence_PDU,
      { "CopyPrecedence", "s4406.CopyPrecedence",
        FT_INT32, BASE_DEC, VALS(s4406_CopyPrecedence_vals), 0,
        "s4406.CopyPrecedence", HFILL }},
    { &hf_s4406_MessageType_PDU,
      { "MessageType", "s4406.MessageType",
        FT_NONE, BASE_NONE, NULL, 0,
        "s4406.MessageType", HFILL }},
    { &hf_s4406_AddressListDesignatorSeq_PDU,
      { "AddressListDesignatorSeq", "s4406.AddressListDesignatorSeq",
        FT_UINT32, BASE_DEC, NULL, 0,
        "s4406.AddressListDesignatorSeq", HFILL }},
    { &hf_s4406_OtherRecipientDesignatorSeq_PDU,
      { "OtherRecipientDesignatorSeq", "s4406.OtherRecipientDesignatorSeq",
        FT_UINT32, BASE_DEC, NULL, 0,
        "s4406.OtherRecipientDesignatorSeq", HFILL }},
    { &hf_s4406_PilotInformationSeq_PDU,
      { "PilotInformationSeq", "s4406.PilotInformationSeq",
        FT_UINT32, BASE_DEC, NULL, 0,
        "s4406.PilotInformationSeq", HFILL }},
    { &hf_s4406_Acp127MessageIdentifier_PDU,
      { "Acp127MessageIdentifier", "s4406.Acp127MessageIdentifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "s4406.Acp127MessageIdentifier", HFILL }},
    { &hf_s4406_OriginatorPlad_PDU,
      { "OriginatorPlad", "s4406.OriginatorPlad",
        FT_STRING, BASE_NONE, NULL, 0,
        "s4406.OriginatorPlad", HFILL }},
    { &hf_s4406_Acp127NotificationType_PDU,
      { "Acp127NotificationType", "s4406.Acp127NotificationType",
        FT_BYTES, BASE_NONE, NULL, 0,
        "s4406.Acp127NotificationType", HFILL }},
    { &hf_s4406_SecurityInformationLabels_PDU,
      { "SecurityInformationLabels", "s4406.SecurityInformationLabels",
        FT_NONE, BASE_NONE, NULL, 0,
        "s4406.SecurityInformationLabels", HFILL }},
    { &hf_s4406_PriorityLevelQualifier_PDU,
      { "PriorityLevelQualifier", "s4406.PriorityLevelQualifier",
        FT_UINT32, BASE_DEC, VALS(s4406_PriorityLevelQualifier_vals), 0,
        "s4406.PriorityLevelQualifier", HFILL }},
    { &hf_s4406_mm,
      { "mm", "s4406.mm",
        FT_NONE, BASE_NONE, NULL, 0,
        "x420.IPM", HFILL }},
    { &hf_s4406_mn,
      { "mn", "s4406.mn",
        FT_NONE, BASE_NONE, NULL, 0,
        "x420.IPN", HFILL }},
    { &hf_s4406_ExemptedAddressSeq_item,
      { "ExemptedAddress", "s4406.ExemptedAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "s4406.ExemptedAddress", HFILL }},
    { &hf_s4406_sics,
      { "sics", "s4406.sics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "s4406.SEQUENCE_OF_Sic", HFILL }},
    { &hf_s4406_sics_item,
      { "Sic", "s4406.Sic",
        FT_STRING, BASE_NONE, NULL, 0,
        "s4406.Sic", HFILL }},
    { &hf_s4406_dist_Extensions,
      { "dist-Extensions", "s4406.dist_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "s4406.SEQUENCE_OF_DistributionExtensionField", HFILL }},
    { &hf_s4406_dist_Extensions_item,
      { "DistributionExtensionField", "s4406.DistributionExtensionField",
        FT_NONE, BASE_NONE, NULL, 0,
        "s4406.DistributionExtensionField", HFILL }},
    { &hf_s4406_dist_type,
      { "dist-type", "s4406.dist_type",
        FT_OID, BASE_NONE, NULL, 0,
        "s4406.OBJECT_IDENTIFIER", HFILL }},
    { &hf_s4406_dist_value,
      { "dist-value", "s4406.dist_value",
        FT_NONE, BASE_NONE, NULL, 0,
        "s4406.T_dist_value", HFILL }},
    { &hf_s4406_HandlingInstructions_item,
      { "MilitaryString", "s4406.MilitaryString",
        FT_STRING, BASE_NONE, NULL, 0,
        "s4406.MilitaryString", HFILL }},
    { &hf_s4406_MessageInstructions_item,
      { "MilitaryString", "s4406.MilitaryString",
        FT_STRING, BASE_NONE, NULL, 0,
        "s4406.MilitaryString", HFILL }},
    { &hf_s4406_message_type_type,
      { "type", "s4406.type",
        FT_INT32, BASE_DEC, VALS(s4406_TypeMessage_vals), 0,
        "s4406.TypeMessage", HFILL }},
    { &hf_s4406_identifier,
      { "identifier", "s4406.identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "s4406.MessageIdentifier", HFILL }},
    { &hf_s4406_AddressListDesignatorSeq_item,
      { "AddressListDesignator", "s4406.AddressListDesignator",
        FT_NONE, BASE_NONE, NULL, 0,
        "s4406.AddressListDesignator", HFILL }},
    { &hf_s4406_address_list_type,
      { "type", "s4406.type",
        FT_INT32, BASE_DEC, VALS(s4406_AddressListType_vals), 0,
        "s4406.AddressListType", HFILL }},
    { &hf_s4406_listName,
      { "listName", "s4406.listName",
        FT_NONE, BASE_NONE, NULL, 0,
        "x420.ORDescriptor", HFILL }},
    { &hf_s4406_notificationRequest,
      { "notificationRequest", "s4406.notificationRequest",
        FT_INT32, BASE_DEC, VALS(s4406_AddressListRequest_vals), 0,
        "s4406.AddressListRequest", HFILL }},
    { &hf_s4406_replyRequest,
      { "replyRequest", "s4406.replyRequest",
        FT_INT32, BASE_DEC, VALS(s4406_AddressListRequest_vals), 0,
        "s4406.AddressListRequest", HFILL }},
    { &hf_s4406_OtherRecipientDesignatorSeq_item,
      { "OtherRecipientDesignator", "s4406.OtherRecipientDesignator",
        FT_NONE, BASE_NONE, NULL, 0,
        "s4406.OtherRecipientDesignator", HFILL }},
    { &hf_s4406_other_recipient_type,
      { "type", "s4406.type",
        FT_INT32, BASE_DEC, VALS(s4406_OtherRecipientType_vals), 0,
        "s4406.OtherRecipientType", HFILL }},
    { &hf_s4406_designator,
      { "designator", "s4406.designator",
        FT_STRING, BASE_NONE, NULL, 0,
        "s4406.MilitaryString", HFILL }},
    { &hf_s4406_PilotInformationSeq_item,
      { "PilotInformation", "s4406.PilotInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "s4406.PilotInformation", HFILL }},
    { &hf_s4406_pilotPrecedence,
      { "pilotPrecedence", "s4406.pilotPrecedence",
        FT_INT32, BASE_DEC, VALS(s4406_PilotPrecedence_vals), 0,
        "s4406.PilotPrecedence", HFILL }},
    { &hf_s4406_pilotRecipient,
      { "pilotRecipient", "s4406.pilotRecipient",
        FT_UINT32, BASE_DEC, NULL, 0,
        "s4406.SEQUENCE_OF_ORDescriptor", HFILL }},
    { &hf_s4406_pilotRecipient_item,
      { "ORDescriptor", "s4406.ORDescriptor",
        FT_NONE, BASE_NONE, NULL, 0,
        "x420.ORDescriptor", HFILL }},
    { &hf_s4406_pilotSecurity,
      { "pilotSecurity", "s4406.pilotSecurity",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.SecurityLabel", HFILL }},
    { &hf_s4406_pilotHandling,
      { "pilotHandling", "s4406.pilotHandling",
        FT_UINT32, BASE_DEC, NULL, 0,
        "s4406.SEQUENCE_OF_MilitaryString", HFILL }},
    { &hf_s4406_pilotHandling_item,
      { "MilitaryString", "s4406.MilitaryString",
        FT_STRING, BASE_NONE, NULL, 0,
        "s4406.MilitaryString", HFILL }},
    { &hf_s4406_content_security_label,
      { "content-security-label", "s4406.content_security_label",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.SecurityLabel", HFILL }},
    { &hf_s4406_heading_security_label,
      { "heading-security-label", "s4406.heading_security_label",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.SecurityLabel", HFILL }},
    { &hf_s4406_body_part_security_labels,
      { "body-part-security-labels", "s4406.body_part_security_labels",
        FT_UINT32, BASE_DEC, NULL, 0,
        "s4406.SEQUENCE_OF_BodyPartSecurityLabel", HFILL }},
    { &hf_s4406_body_part_security_labels_item,
      { "BodyPartSecurityLabel", "s4406.BodyPartSecurityLabel",
        FT_NONE, BASE_NONE, NULL, 0,
        "s4406.BodyPartSecurityLabel", HFILL }},
    { &hf_s4406_body_part_security_label,
      { "body-part-security-label", "s4406.body_part_security_label",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.SecurityLabel", HFILL }},
    { &hf_s4406_body_part_sequence_number,
      { "body-part-sequence-number", "s4406.body_part_sequence_number",
        FT_INT32, BASE_DEC, NULL, 0,
        "s4406.BodyPartSequenceNumber", HFILL }},
    { &hf_s4406_Acp127NotificationType_negative,
      { "negative", "s4406.negative",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_s4406_Acp127NotificationType_positive,
      { "positive", "s4406.positive",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_s4406_Acp127NotificationType_transfer,
      { "transfer", "s4406.transfer",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},

/*--- End of included file: packet-s4406-hfarr.c ---*/
#line 93 "packet-s4406-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_s4406,

/*--- Included file: packet-s4406-ettarr.c ---*/
#line 1 "packet-s4406-ettarr.c"
    &ett_s4406_InformationObject,
    &ett_s4406_ExemptedAddressSeq,
    &ett_s4406_DistributionCodes,
    &ett_s4406_SEQUENCE_OF_Sic,
    &ett_s4406_SEQUENCE_OF_DistributionExtensionField,
    &ett_s4406_DistributionExtensionField,
    &ett_s4406_HandlingInstructions,
    &ett_s4406_MessageInstructions,
    &ett_s4406_MessageType,
    &ett_s4406_AddressListDesignatorSeq,
    &ett_s4406_AddressListDesignator,
    &ett_s4406_OtherRecipientDesignatorSeq,
    &ett_s4406_OtherRecipientDesignator,
    &ett_s4406_PilotInformationSeq,
    &ett_s4406_PilotInformation,
    &ett_s4406_SEQUENCE_OF_ORDescriptor,
    &ett_s4406_SEQUENCE_OF_MilitaryString,
    &ett_s4406_Acp127NotificationType,
    &ett_s4406_SecurityInformationLabels,
    &ett_s4406_SEQUENCE_OF_BodyPartSecurityLabel,
    &ett_s4406_BodyPartSecurityLabel,

/*--- End of included file: packet-s4406-ettarr.c ---*/
#line 99 "packet-s4406-template.c"
  };

  /* Register protocol */
  proto_s4406 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_s4406, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_s4406 --- */
void proto_reg_handoff_s4406(void) {

/*--- Included file: packet-s4406-dis-tab.c ---*/
#line 1 "packet-s4406-dis-tab.c"
  register_ber_oid_dissector("1.3.26.0.4406.0.2.0", dissect_PrimaryPrecedence_PDU, proto_s4406, "primary-precedence");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.1", dissect_CopyPrecedence_PDU, proto_s4406, "copy-precedence");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.2", dissect_MessageType_PDU, proto_s4406, "message-type");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.3", dissect_AddressListDesignatorSeq_PDU, proto_s4406, "address-list-indicator");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.4", dissect_ExemptedAddressSeq_PDU, proto_s4406, "exempted-address");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.5", dissect_ExtendedAuthorisationInfo_PDU, proto_s4406, "extended-authorisation-info");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.6", dissect_DistributionCodes_PDU, proto_s4406, "distribution-codes");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.7", dissect_HandlingInstructions_PDU, proto_s4406, "handling-instructions");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.8", dissect_MessageInstructions_PDU, proto_s4406, "message-instructions");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.9", dissect_CodressMessage_PDU, proto_s4406, "codress-message");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.10", dissect_OriginatorReference_PDU, proto_s4406, "originator-reference");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.11", dissect_OtherRecipientDesignatorSeq_PDU, proto_s4406, "other-recipients-indicator");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.12", dissect_PilotInformationSeq_PDU, proto_s4406, "pilot-forwarding-info");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.13", dissect_Acp127MessageIdentifier_PDU, proto_s4406, "acp127-message-identifier");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.14", dissect_OriginatorPlad_PDU, proto_s4406, "originator-plad");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.15", dissect_Acp127NotificationType_PDU, proto_s4406, "acp127-notification-request");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.17", dissect_SecurityInformationLabels_PDU, proto_s4406, "information-labels");
  register_ber_oid_dissector("1.3.26.0.4406.0.8.0", dissect_PriorityLevelQualifier_PDU, proto_s4406, "priority-level-qualifier");
  register_ber_oid_dissector("1.3.26.0.4406.0.7.9", dissect_MMMessageData_PDU, proto_s4406, "mm-message");
  register_ber_oid_dissector("1.3.26.0.4406.0.7.10", dissect_MMMessageParameters_PDU, proto_s4406, "mm-message-parameters");
  register_ber_oid_dissector("2.6.1.4.17.1.3.26.0.4406.0.4.1", dissect_InformationObject_PDU, proto_s4406, "id-et-content-p772");


/*--- End of included file: packet-s4406-dis-tab.c ---*/
#line 114 "packet-s4406-template.c"

  register_ber_oid_dissector("1.3.26.0.4406.0.4.1", dissect_s4406, proto_s4406, "Military Message");

  register_ber_syntax_dissector("MilitaryMessage", proto_s4406, dissect_s4406); 
  register_ber_oid_syntax(".p772", NULL, "MilitaryMessage");

}
