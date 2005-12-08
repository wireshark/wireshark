/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* ./packet-s4406.c                                                           */
/* ../../tools/asn2eth.py -X -b -e -p s4406 -c s4406.cnf -s packet-s4406-template s4406.asn */

/* Input file: packet-s4406-template.c */

#line 1 "packet-s4406-template.c"
/* packet-s4406.c
 * Routines for STANAG 4406 (X.400 Military Message Extensions)  packet dissection
 * Graeme Lunt 2005
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
#include <epan/conversation.h>

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
static int hf_s4406_ExemptedAddress_PDU = -1;     /* ExemptedAddress */
static int hf_s4406_ExtendedAuthorisationInfo_PDU = -1;  /* ExtendedAuthorisationInfo */
static int hf_s4406_DistributionCodes_PDU = -1;   /* DistributionCodes */
static int hf_s4406_HandlingInstructions_PDU = -1;  /* HandlingInstructions */
static int hf_s4406_MessageInstructions_PDU = -1;  /* MessageInstructions */
static int hf_s4406_CodressMessage_PDU = -1;      /* CodressMessage */
static int hf_s4406_OriginatorReference_PDU = -1;  /* OriginatorReference */
static int hf_s4406_PrimaryPrecedence_PDU = -1;   /* PrimaryPrecedence */
static int hf_s4406_CopyPrecedence_PDU = -1;      /* CopyPrecedence */
static int hf_s4406_MessageType_PDU = -1;         /* MessageType */
static int hf_s4406_AddressListDesignator_PDU = -1;  /* AddressListDesignator */
static int hf_s4406_OtherRecipientDesignator_PDU = -1;  /* OtherRecipientDesignator */
static int hf_s4406_PilotInformation_PDU = -1;    /* PilotInformation */
static int hf_s4406_Acp127MessageIdentifier_PDU = -1;  /* Acp127MessageIdentifier */
static int hf_s4406_OriginatorPlad_PDU = -1;      /* OriginatorPlad */
static int hf_s4406_SecurityInformationLabels_PDU = -1;  /* SecurityInformationLabels */
static int hf_s4406_PriorityLevelQualifier_PDU = -1;  /* PriorityLevelQualifier */
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
static int hf_s4406_address_list_type = -1;       /* AddressListType */
static int hf_s4406_listName = -1;                /* ORDescriptor */
static int hf_s4406_notificationRequest = -1;     /* AddressListRequest */
static int hf_s4406_replyRequest = -1;            /* AddressListRequest */
static int hf_s4406_other_recipient_type = -1;    /* OtherRecipientType */
static int hf_s4406_designator = -1;              /* MilitaryString */
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

/*--- End of included file: packet-s4406-hf.c ---*/
#line 53 "packet-s4406-template.c"

/* Initialize the subtree pointers */
static gint ett_s4406 = -1;

/*--- Included file: packet-s4406-ett.c ---*/
#line 1 "packet-s4406-ett.c"
static gint ett_s4406_DistributionCodes = -1;
static gint ett_s4406_SEQUENCE_OF_Sic = -1;
static gint ett_s4406_SEQUENCE_OF_DistributionExtensionField = -1;
static gint ett_s4406_DistributionExtensionField = -1;
static gint ett_s4406_HandlingInstructions = -1;
static gint ett_s4406_MessageInstructions = -1;
static gint ett_s4406_MessageType = -1;
static gint ett_s4406_AddressListDesignator = -1;
static gint ett_s4406_OtherRecipientDesignator = -1;
static gint ett_s4406_PilotInformation = -1;
static gint ett_s4406_SEQUENCE_OF_ORDescriptor = -1;
static gint ett_s4406_SEQUENCE_OF_MilitaryString = -1;
static gint ett_s4406_SecurityInformationLabels = -1;
static gint ett_s4406_SEQUENCE_OF_BodyPartSecurityLabel = -1;
static gint ett_s4406_BodyPartSecurityLabel = -1;

/*--- End of included file: packet-s4406-ett.c ---*/
#line 57 "packet-s4406-template.c"


/*--- Included file: packet-s4406-fn.c ---*/
#line 1 "packet-s4406-fn.c"
/*--- Fields for imported types ---*/

static int dissect_listName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_ORDescriptor(TRUE, tvb, offset, pinfo, tree, hf_s4406_listName);
}
static int dissect_pilotRecipient_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_ORDescriptor(FALSE, tvb, offset, pinfo, tree, hf_s4406_pilotRecipient_item);
}
static int dissect_pilotSecurity_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SecurityLabel(TRUE, tvb, offset, pinfo, tree, hf_s4406_pilotSecurity);
}
static int dissect_content_security_label_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SecurityLabel(TRUE, tvb, offset, pinfo, tree, hf_s4406_content_security_label);
}
static int dissect_heading_security_label_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SecurityLabel(TRUE, tvb, offset, pinfo, tree, hf_s4406_heading_security_label);
}
static int dissect_body_part_security_label_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SecurityLabel(TRUE, tvb, offset, pinfo, tree, hf_s4406_body_part_security_label);
}



static int
dissect_s4406_ExemptedAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x420_ORDescriptor(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_s4406_ExtendedAuthorisationInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTCTime,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_s4406_Sic(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_sics_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_s4406_Sic(FALSE, tvb, offset, pinfo, tree, hf_s4406_sics_item);
}


static const ber_sequence_t SEQUENCE_OF_Sic_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_sics_item },
};

static int
dissect_s4406_SEQUENCE_OF_Sic(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_Sic_sequence_of, hf_index, ett_s4406_SEQUENCE_OF_Sic);

  return offset;
}
static int dissect_sics_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_s4406_SEQUENCE_OF_Sic(TRUE, tvb, offset, pinfo, tree, hf_s4406_sics);
}



static int
dissect_s4406_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_dist_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_s4406_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_s4406_dist_type);
}



static int
dissect_s4406_T_dist_value(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 56 "s4406.cnf"
/* XXX: not implemented */



  return offset;
}
static int dissect_dist_value(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_s4406_T_dist_value(FALSE, tvb, offset, pinfo, tree, hf_s4406_dist_value);
}


static const ber_sequence_t DistributionExtensionField_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_dist_type },
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_dist_value },
  { 0, 0, 0, NULL }
};

static int
dissect_s4406_DistributionExtensionField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DistributionExtensionField_sequence, hf_index, ett_s4406_DistributionExtensionField);

  return offset;
}
static int dissect_dist_Extensions_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_s4406_DistributionExtensionField(FALSE, tvb, offset, pinfo, tree, hf_s4406_dist_Extensions_item);
}


static const ber_sequence_t SEQUENCE_OF_DistributionExtensionField_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dist_Extensions_item },
};

static int
dissect_s4406_SEQUENCE_OF_DistributionExtensionField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_DistributionExtensionField_sequence_of, hf_index, ett_s4406_SEQUENCE_OF_DistributionExtensionField);

  return offset;
}
static int dissect_dist_Extensions_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_s4406_SEQUENCE_OF_DistributionExtensionField(TRUE, tvb, offset, pinfo, tree, hf_s4406_dist_Extensions);
}


static const ber_sequence_t DistributionCodes_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sics_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dist_Extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_s4406_DistributionCodes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              DistributionCodes_set, hf_index, ett_s4406_DistributionCodes);

  return offset;
}



static int
dissect_s4406_MilitaryString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_HandlingInstructions_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_s4406_MilitaryString(FALSE, tvb, offset, pinfo, tree, hf_s4406_HandlingInstructions_item);
}
static int dissect_MessageInstructions_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_s4406_MilitaryString(FALSE, tvb, offset, pinfo, tree, hf_s4406_MessageInstructions_item);
}
static int dissect_designator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_s4406_MilitaryString(TRUE, tvb, offset, pinfo, tree, hf_s4406_designator);
}
static int dissect_pilotHandling_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_s4406_MilitaryString(FALSE, tvb, offset, pinfo, tree, hf_s4406_pilotHandling_item);
}


static const ber_sequence_t HandlingInstructions_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_HandlingInstructions_item },
};

static int
dissect_s4406_HandlingInstructions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      HandlingInstructions_sequence_of, hf_index, ett_s4406_HandlingInstructions);

  return offset;
}


static const ber_sequence_t MessageInstructions_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_MessageInstructions_item },
};

static int
dissect_s4406_MessageInstructions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      MessageInstructions_sequence_of, hf_index, ett_s4406_MessageInstructions);

  return offset;
}



static int
dissect_s4406_CodressMessage(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_s4406_OriginatorReference(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_s4406_MilitaryString(implicit_tag, tvb, offset, pinfo, tree, hf_index);

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
dissect_s4406_PrimaryPrecedence(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 61 "s4406.cnf"
  int precedence = -1;
    offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &precedence);

  if((precedence != -1) && check_col(pinfo->cinfo, COL_INFO))
   col_append_fstr(pinfo->cinfo, COL_INFO, " (primary=%s)", val_to_str(precedence, s4406_PrimaryPrecedence_vals, "precedence(%d)"));



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
dissect_s4406_CopyPrecedence(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 69 "s4406.cnf"
  int precedence = -1;
    offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &precedence);

  if((precedence != -1) && check_col(pinfo->cinfo, COL_INFO))
   col_append_fstr(pinfo->cinfo, COL_INFO, " (copy=%s)", val_to_str(precedence, s4406_CopyPrecedence_vals, "precedence(%d)"));


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
dissect_s4406_TypeMessage(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_message_type_type_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_s4406_TypeMessage(TRUE, tvb, offset, pinfo, tree, hf_s4406_message_type_type);
}



static int
dissect_s4406_MessageIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_s4406_MilitaryString(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_identifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_s4406_MessageIdentifier(TRUE, tvb, offset, pinfo, tree, hf_s4406_identifier);
}


static const ber_sequence_t MessageType_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_message_type_type_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_identifier_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_s4406_MessageType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              MessageType_set, hf_index, ett_s4406_MessageType);

  return offset;
}


static const value_string s4406_AddressListType_vals[] = {
  {   0, "primaryAddressList" },
  {   1, "copyAddressList" },
  { 0, NULL }
};


static int
dissect_s4406_AddressListType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_address_list_type_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_s4406_AddressListType(TRUE, tvb, offset, pinfo, tree, hf_s4406_address_list_type);
}


static const value_string s4406_AddressListRequest_vals[] = {
  {   0, "action" },
  {   1, "info" },
  {   2, "both" },
  { 0, NULL }
};


static int
dissect_s4406_AddressListRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_notificationRequest_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_s4406_AddressListRequest(TRUE, tvb, offset, pinfo, tree, hf_s4406_notificationRequest);
}
static int dissect_replyRequest_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_s4406_AddressListRequest(TRUE, tvb, offset, pinfo, tree, hf_s4406_replyRequest);
}


static const ber_sequence_t AddressListDesignator_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_address_list_type_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_listName_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_notificationRequest_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_replyRequest_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_s4406_AddressListDesignator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              AddressListDesignator_set, hf_index, ett_s4406_AddressListDesignator);

  return offset;
}


static const value_string s4406_OtherRecipientType_vals[] = {
  {   0, "primary" },
  {   1, "copy" },
  { 0, NULL }
};


static int
dissect_s4406_OtherRecipientType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_other_recipient_type_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_s4406_OtherRecipientType(TRUE, tvb, offset, pinfo, tree, hf_s4406_other_recipient_type);
}


static const ber_sequence_t OtherRecipientDesignator_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_other_recipient_type_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_designator_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_s4406_OtherRecipientDesignator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              OtherRecipientDesignator_set, hf_index, ett_s4406_OtherRecipientDesignator);

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
dissect_s4406_PilotPrecedence(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_pilotPrecedence_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_s4406_PilotPrecedence(TRUE, tvb, offset, pinfo, tree, hf_s4406_pilotPrecedence);
}


static const ber_sequence_t SEQUENCE_OF_ORDescriptor_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_pilotRecipient_item },
};

static int
dissect_s4406_SEQUENCE_OF_ORDescriptor(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_ORDescriptor_sequence_of, hf_index, ett_s4406_SEQUENCE_OF_ORDescriptor);

  return offset;
}
static int dissect_pilotRecipient_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_s4406_SEQUENCE_OF_ORDescriptor(TRUE, tvb, offset, pinfo, tree, hf_s4406_pilotRecipient);
}


static const ber_sequence_t SEQUENCE_OF_MilitaryString_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_pilotHandling_item },
};

static int
dissect_s4406_SEQUENCE_OF_MilitaryString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_MilitaryString_sequence_of, hf_index, ett_s4406_SEQUENCE_OF_MilitaryString);

  return offset;
}
static int dissect_pilotHandling_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_s4406_SEQUENCE_OF_MilitaryString(TRUE, tvb, offset, pinfo, tree, hf_s4406_pilotHandling);
}


static const ber_sequence_t PilotInformation_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pilotPrecedence_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pilotRecipient_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pilotSecurity_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pilotHandling_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_s4406_PilotInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PilotInformation_sequence, hf_index, ett_s4406_PilotInformation);

  return offset;
}



static int
dissect_s4406_Acp127MessageIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_s4406_MilitaryString(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_s4406_OriginatorPlad(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_s4406_MilitaryString(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_s4406_BodyPartSequenceNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_body_part_sequence_number_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_s4406_BodyPartSequenceNumber(TRUE, tvb, offset, pinfo, tree, hf_s4406_body_part_sequence_number);
}


static const ber_sequence_t BodyPartSecurityLabel_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_body_part_security_label_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_body_part_sequence_number_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_s4406_BodyPartSecurityLabel(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              BodyPartSecurityLabel_set, hf_index, ett_s4406_BodyPartSecurityLabel);

  return offset;
}
static int dissect_body_part_security_labels_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_s4406_BodyPartSecurityLabel(FALSE, tvb, offset, pinfo, tree, hf_s4406_body_part_security_labels_item);
}


static const ber_sequence_t SEQUENCE_OF_BodyPartSecurityLabel_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_body_part_security_labels_item },
};

static int
dissect_s4406_SEQUENCE_OF_BodyPartSecurityLabel(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_BodyPartSecurityLabel_sequence_of, hf_index, ett_s4406_SEQUENCE_OF_BodyPartSecurityLabel);

  return offset;
}
static int dissect_body_part_security_labels_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_s4406_SEQUENCE_OF_BodyPartSecurityLabel(TRUE, tvb, offset, pinfo, tree, hf_s4406_body_part_security_labels);
}


static const ber_sequence_t SecurityInformationLabels_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_content_security_label_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_heading_security_label_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_body_part_security_labels_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_s4406_SecurityInformationLabels(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SecurityInformationLabels_sequence, hf_index, ett_s4406_SecurityInformationLabels);

  return offset;
}


static const value_string s4406_PriorityLevelQualifier_vals[] = {
  {   0, "low" },
  {   1, "high" },
  { 0, NULL }
};


static int
dissect_s4406_PriorityLevelQualifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}

/*--- PDUs ---*/

static void dissect_ExemptedAddress_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_s4406_ExemptedAddress(FALSE, tvb, 0, pinfo, tree, hf_s4406_ExemptedAddress_PDU);
}
static void dissect_ExtendedAuthorisationInfo_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_s4406_ExtendedAuthorisationInfo(FALSE, tvb, 0, pinfo, tree, hf_s4406_ExtendedAuthorisationInfo_PDU);
}
static void dissect_DistributionCodes_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_s4406_DistributionCodes(FALSE, tvb, 0, pinfo, tree, hf_s4406_DistributionCodes_PDU);
}
static void dissect_HandlingInstructions_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_s4406_HandlingInstructions(FALSE, tvb, 0, pinfo, tree, hf_s4406_HandlingInstructions_PDU);
}
static void dissect_MessageInstructions_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_s4406_MessageInstructions(FALSE, tvb, 0, pinfo, tree, hf_s4406_MessageInstructions_PDU);
}
static void dissect_CodressMessage_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_s4406_CodressMessage(FALSE, tvb, 0, pinfo, tree, hf_s4406_CodressMessage_PDU);
}
static void dissect_OriginatorReference_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_s4406_OriginatorReference(FALSE, tvb, 0, pinfo, tree, hf_s4406_OriginatorReference_PDU);
}
static void dissect_PrimaryPrecedence_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_s4406_PrimaryPrecedence(FALSE, tvb, 0, pinfo, tree, hf_s4406_PrimaryPrecedence_PDU);
}
static void dissect_CopyPrecedence_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_s4406_CopyPrecedence(FALSE, tvb, 0, pinfo, tree, hf_s4406_CopyPrecedence_PDU);
}
static void dissect_MessageType_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_s4406_MessageType(FALSE, tvb, 0, pinfo, tree, hf_s4406_MessageType_PDU);
}
static void dissect_AddressListDesignator_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_s4406_AddressListDesignator(FALSE, tvb, 0, pinfo, tree, hf_s4406_AddressListDesignator_PDU);
}
static void dissect_OtherRecipientDesignator_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_s4406_OtherRecipientDesignator(FALSE, tvb, 0, pinfo, tree, hf_s4406_OtherRecipientDesignator_PDU);
}
static void dissect_PilotInformation_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_s4406_PilotInformation(FALSE, tvb, 0, pinfo, tree, hf_s4406_PilotInformation_PDU);
}
static void dissect_Acp127MessageIdentifier_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_s4406_Acp127MessageIdentifier(FALSE, tvb, 0, pinfo, tree, hf_s4406_Acp127MessageIdentifier_PDU);
}
static void dissect_OriginatorPlad_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_s4406_OriginatorPlad(FALSE, tvb, 0, pinfo, tree, hf_s4406_OriginatorPlad_PDU);
}
static void dissect_SecurityInformationLabels_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_s4406_SecurityInformationLabels(FALSE, tvb, 0, pinfo, tree, hf_s4406_SecurityInformationLabels_PDU);
}
static void dissect_PriorityLevelQualifier_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_s4406_PriorityLevelQualifier(FALSE, tvb, 0, pinfo, tree, hf_s4406_PriorityLevelQualifier_PDU);
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

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_s4406, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_s4406);
	}

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "S4406");
	if (check_col(pinfo->cinfo, COL_INFO))
	  col_add_str(pinfo->cinfo, COL_INFO, "Military");

	dissect_x420_InformationObject(TRUE, tvb, offset, pinfo , tree, -1);
}



/*--- proto_register_s4406 -------------------------------------------*/
void proto_register_s4406(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {

/*--- Included file: packet-s4406-hfarr.c ---*/
#line 1 "packet-s4406-hfarr.c"
    { &hf_s4406_ExemptedAddress_PDU,
      { "ExemptedAddress", "s4406.ExemptedAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExemptedAddress", HFILL }},
    { &hf_s4406_ExtendedAuthorisationInfo_PDU,
      { "ExtendedAuthorisationInfo", "s4406.ExtendedAuthorisationInfo",
        FT_STRING, BASE_NONE, NULL, 0,
        "ExtendedAuthorisationInfo", HFILL }},
    { &hf_s4406_DistributionCodes_PDU,
      { "DistributionCodes", "s4406.DistributionCodes",
        FT_NONE, BASE_NONE, NULL, 0,
        "DistributionCodes", HFILL }},
    { &hf_s4406_HandlingInstructions_PDU,
      { "HandlingInstructions", "s4406.HandlingInstructions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HandlingInstructions", HFILL }},
    { &hf_s4406_MessageInstructions_PDU,
      { "MessageInstructions", "s4406.MessageInstructions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MessageInstructions", HFILL }},
    { &hf_s4406_CodressMessage_PDU,
      { "CodressMessage", "s4406.CodressMessage",
        FT_INT32, BASE_DEC, NULL, 0,
        "CodressMessage", HFILL }},
    { &hf_s4406_OriginatorReference_PDU,
      { "OriginatorReference", "s4406.OriginatorReference",
        FT_STRING, BASE_NONE, NULL, 0,
        "OriginatorReference", HFILL }},
    { &hf_s4406_PrimaryPrecedence_PDU,
      { "PrimaryPrecedence", "s4406.PrimaryPrecedence",
        FT_INT32, BASE_DEC, VALS(s4406_PrimaryPrecedence_vals), 0,
        "PrimaryPrecedence", HFILL }},
    { &hf_s4406_CopyPrecedence_PDU,
      { "CopyPrecedence", "s4406.CopyPrecedence",
        FT_INT32, BASE_DEC, VALS(s4406_CopyPrecedence_vals), 0,
        "CopyPrecedence", HFILL }},
    { &hf_s4406_MessageType_PDU,
      { "MessageType", "s4406.MessageType",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageType", HFILL }},
    { &hf_s4406_AddressListDesignator_PDU,
      { "AddressListDesignator", "s4406.AddressListDesignator",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddressListDesignator", HFILL }},
    { &hf_s4406_OtherRecipientDesignator_PDU,
      { "OtherRecipientDesignator", "s4406.OtherRecipientDesignator",
        FT_NONE, BASE_NONE, NULL, 0,
        "OtherRecipientDesignator", HFILL }},
    { &hf_s4406_PilotInformation_PDU,
      { "PilotInformation", "s4406.PilotInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "PilotInformation", HFILL }},
    { &hf_s4406_Acp127MessageIdentifier_PDU,
      { "Acp127MessageIdentifier", "s4406.Acp127MessageIdentifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "Acp127MessageIdentifier", HFILL }},
    { &hf_s4406_OriginatorPlad_PDU,
      { "OriginatorPlad", "s4406.OriginatorPlad",
        FT_STRING, BASE_NONE, NULL, 0,
        "OriginatorPlad", HFILL }},
    { &hf_s4406_SecurityInformationLabels_PDU,
      { "SecurityInformationLabels", "s4406.SecurityInformationLabels",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityInformationLabels", HFILL }},
    { &hf_s4406_PriorityLevelQualifier_PDU,
      { "PriorityLevelQualifier", "s4406.PriorityLevelQualifier",
        FT_UINT32, BASE_DEC, VALS(s4406_PriorityLevelQualifier_vals), 0,
        "PriorityLevelQualifier", HFILL }},
    { &hf_s4406_sics,
      { "sics", "s4406.sics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DistributionCodes/sics", HFILL }},
    { &hf_s4406_sics_item,
      { "Item", "s4406.sics_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "DistributionCodes/sics/_item", HFILL }},
    { &hf_s4406_dist_Extensions,
      { "dist-Extensions", "s4406.dist_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DistributionCodes/dist-Extensions", HFILL }},
    { &hf_s4406_dist_Extensions_item,
      { "Item", "s4406.dist_Extensions_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "DistributionCodes/dist-Extensions/_item", HFILL }},
    { &hf_s4406_dist_type,
      { "dist-type", "s4406.dist_type",
        FT_OID, BASE_NONE, NULL, 0,
        "DistributionExtensionField/dist-type", HFILL }},
    { &hf_s4406_dist_value,
      { "dist-value", "s4406.dist_value",
        FT_NONE, BASE_NONE, NULL, 0,
        "DistributionExtensionField/dist-value", HFILL }},
    { &hf_s4406_HandlingInstructions_item,
      { "Item", "s4406.HandlingInstructions_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "HandlingInstructions/_item", HFILL }},
    { &hf_s4406_MessageInstructions_item,
      { "Item", "s4406.MessageInstructions_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "MessageInstructions/_item", HFILL }},
    { &hf_s4406_message_type_type,
      { "type", "s4406.type",
        FT_INT32, BASE_DEC, VALS(s4406_TypeMessage_vals), 0,
        "MessageType/type", HFILL }},
    { &hf_s4406_identifier,
      { "identifier", "s4406.identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "MessageType/identifier", HFILL }},
    { &hf_s4406_address_list_type,
      { "type", "s4406.type",
        FT_INT32, BASE_DEC, VALS(s4406_AddressListType_vals), 0,
        "AddressListDesignator/type", HFILL }},
    { &hf_s4406_listName,
      { "listName", "s4406.listName",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddressListDesignator/listName", HFILL }},
    { &hf_s4406_notificationRequest,
      { "notificationRequest", "s4406.notificationRequest",
        FT_INT32, BASE_DEC, VALS(s4406_AddressListRequest_vals), 0,
        "AddressListDesignator/notificationRequest", HFILL }},
    { &hf_s4406_replyRequest,
      { "replyRequest", "s4406.replyRequest",
        FT_INT32, BASE_DEC, VALS(s4406_AddressListRequest_vals), 0,
        "AddressListDesignator/replyRequest", HFILL }},
    { &hf_s4406_other_recipient_type,
      { "type", "s4406.type",
        FT_INT32, BASE_DEC, VALS(s4406_OtherRecipientType_vals), 0,
        "OtherRecipientDesignator/type", HFILL }},
    { &hf_s4406_designator,
      { "designator", "s4406.designator",
        FT_STRING, BASE_NONE, NULL, 0,
        "OtherRecipientDesignator/designator", HFILL }},
    { &hf_s4406_pilotPrecedence,
      { "pilotPrecedence", "s4406.pilotPrecedence",
        FT_INT32, BASE_DEC, VALS(s4406_PilotPrecedence_vals), 0,
        "PilotInformation/pilotPrecedence", HFILL }},
    { &hf_s4406_pilotRecipient,
      { "pilotRecipient", "s4406.pilotRecipient",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PilotInformation/pilotRecipient", HFILL }},
    { &hf_s4406_pilotRecipient_item,
      { "Item", "s4406.pilotRecipient_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "PilotInformation/pilotRecipient/_item", HFILL }},
    { &hf_s4406_pilotSecurity,
      { "pilotSecurity", "s4406.pilotSecurity",
        FT_NONE, BASE_NONE, NULL, 0,
        "PilotInformation/pilotSecurity", HFILL }},
    { &hf_s4406_pilotHandling,
      { "pilotHandling", "s4406.pilotHandling",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PilotInformation/pilotHandling", HFILL }},
    { &hf_s4406_pilotHandling_item,
      { "Item", "s4406.pilotHandling_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "PilotInformation/pilotHandling/_item", HFILL }},
    { &hf_s4406_content_security_label,
      { "content-security-label", "s4406.content_security_label",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityInformationLabels/content-security-label", HFILL }},
    { &hf_s4406_heading_security_label,
      { "heading-security-label", "s4406.heading_security_label",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityInformationLabels/heading-security-label", HFILL }},
    { &hf_s4406_body_part_security_labels,
      { "body-part-security-labels", "s4406.body_part_security_labels",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SecurityInformationLabels/body-part-security-labels", HFILL }},
    { &hf_s4406_body_part_security_labels_item,
      { "Item", "s4406.body_part_security_labels_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityInformationLabels/body-part-security-labels/_item", HFILL }},
    { &hf_s4406_body_part_security_label,
      { "body-part-security-label", "s4406.body_part_security_label",
        FT_NONE, BASE_NONE, NULL, 0,
        "BodyPartSecurityLabel/body-part-security-label", HFILL }},
    { &hf_s4406_body_part_sequence_number,
      { "body-part-sequence-number", "s4406.body_part_sequence_number",
        FT_INT32, BASE_DEC, NULL, 0,
        "BodyPartSecurityLabel/body-part-sequence-number", HFILL }},

/*--- End of included file: packet-s4406-hfarr.c ---*/
#line 93 "packet-s4406-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_s4406,

/*--- Included file: packet-s4406-ettarr.c ---*/
#line 1 "packet-s4406-ettarr.c"
    &ett_s4406_DistributionCodes,
    &ett_s4406_SEQUENCE_OF_Sic,
    &ett_s4406_SEQUENCE_OF_DistributionExtensionField,
    &ett_s4406_DistributionExtensionField,
    &ett_s4406_HandlingInstructions,
    &ett_s4406_MessageInstructions,
    &ett_s4406_MessageType,
    &ett_s4406_AddressListDesignator,
    &ett_s4406_OtherRecipientDesignator,
    &ett_s4406_PilotInformation,
    &ett_s4406_SEQUENCE_OF_ORDescriptor,
    &ett_s4406_SEQUENCE_OF_MilitaryString,
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
  register_ber_oid_dissector("1.3.26.0.4406.0.2.3", dissect_AddressListDesignator_PDU, proto_s4406, "address-list-indicator");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.4", dissect_ExemptedAddress_PDU, proto_s4406, "exempted-address");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.5", dissect_ExtendedAuthorisationInfo_PDU, proto_s4406, "extended-authorisation-info");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.6", dissect_DistributionCodes_PDU, proto_s4406, "distribution-codes");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.7", dissect_HandlingInstructions_PDU, proto_s4406, "handling-instructions");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.8", dissect_MessageInstructions_PDU, proto_s4406, "message-instructions");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.9", dissect_CodressMessage_PDU, proto_s4406, "codress-message");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.10", dissect_OriginatorReference_PDU, proto_s4406, "originator-reference");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.11", dissect_OtherRecipientDesignator_PDU, proto_s4406, "other-recipients-indicator");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.12", dissect_PilotInformation_PDU, proto_s4406, "pilot-forwarding-info");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.13", dissect_Acp127MessageIdentifier_PDU, proto_s4406, "acp127-message-identifierr");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.14", dissect_OriginatorPlad_PDU, proto_s4406, "originator-plad");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.17", dissect_SecurityInformationLabels_PDU, proto_s4406, "information-labels");
  register_ber_oid_dissector("1.3.26.0.4406.0.8.0", dissect_PriorityLevelQualifier_PDU, proto_s4406, "priority-level-qualifier");


/*--- End of included file: packet-s4406-dis-tab.c ---*/
#line 114 "packet-s4406-template.c"

  register_ber_oid_dissector("1.3.26.0.4406.0.4.1", dissect_s4406, proto_s4406, "Military Message");
}
