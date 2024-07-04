/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-p772.c                                                              */
/* asn2wrs.py -b -C -q -L -p p772 -c ./p772.cnf -s ./packet-p772-template -D . -O ../.. MMSAbstractService.asn MMSInformationObjects.asn MMSOtherNotificationTypeExtensions.asn MMSObjectIdentifiers.asn MMSHeadingExtensions.asn MMSUpperBounds.asn MMSExtendedBodyPartTypes.asn MMSPerRecipientSpecifierExtensions.asn */

/* packet-p772.c
 * Routines for STANAG 4406 (X.400 Military Message Extensions)  packet dissection
 * Graeme Lunt 2005
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/asn1.h>

#include "packet-ber.h"

#include "packet-x509if.h"

#include "packet-p772.h"
#include "packet-p1.h"
#include "packet-p22.h"

#define PNAME  "STANAG 4406 Message"
#define PSNAME "P772"
#define PFNAME "p772"

void proto_register_p772(void);
void proto_reg_handoff_p772(void);


/* Initialize the protocol and registered fields */
static int proto_p772;

#define id_mmhs                        "1.3.26.0.4406.0"
#define id_mod                         id_mmhs".0"
#define id_mm                          id_mmhs".2"
#define id_hat                         id_mmhs".3"
#define id_mcont                       id_mmhs".4"
#define id_policy                      id_mmhs".5"
#define id_cat                         id_mmhs".6"
#define id_et                          id_mmhs".7"
#define id_mmts                        id_mmhs".8"
#define id_nat                         id_mmhs".9"
#define id_mot                         id_mmhs".10"
#define id_mpt                         id_mmhs".11"
#define id_ref                         id_mmhs".12"
#define id_informationlabel            id_mmhs".13"
#define id_mod_upper_bounds            id_mod".0"
#define id_mod_mms                     id_mod".1"
#define id_mod_functional_objects      id_mod".2"
#define id_mod_abstract_service        id_mod".3"
#define id_mod_heading_extension       id_mod".6"
#define id_mod_extended_body_part_types id_mod".7"
#define id_mod_message_store_attributes id_mod".8"
#define id_mod_per_recipient_specifier_extensions id_mod".11"
#define id_mod_other_notification_type_extensions id_mod".12"
#define id_mot_mmme                    id_mot".0"
#define id_mot_mms_user                id_mot".1"
#define id_mot_mms                     id_mot".2"
#define id_mot_mms_ua                  id_mot".3"
#define id_mot_mms_ms                  id_mot".4"
#define id_mot_acp127au                id_mot".5"
#define id_mot_pdau                    id_mot".6"
#define id_mpt_origination             id_mpt".0"
#define id_mpt_reception               id_mpt".1"
#define id_mpt_management              id_mpt".2"
#define id_ref_primary                 id_ref".0"
#define id_ref_secondary               id_ref".1"
#define id_nato_mmhs_et_adatp3         id_et".0"
#define id_nato_mmhs_et_corrections    id_et".1"
#define id_nato_mmhs_et_adatp3_parameters id_et".2"
#define id_nato_mmhs_et_corrections_parameters id_et".3"
#define id_nato_mmhs_et_forwarded_encrypted id_et".6"
#define id_nato_mmhs_et_forwarded_encrypted_parameters id_et".7"
#define id_nato_mmhs_et_mm_message     id_et".9"
#define id_nato_mmhs_et_mm_message_parameters id_et".10"
#define id_nato_mmhs_et_mm_acp127data  id_et".12"
#define id_nato_mmhs_et_mm_acp127data_parameters id_et".13"
#define id_nato_mmhs_mm_primary_precedence id_mm".0"
#define id_nato_mmhs_mm_copy_precedence id_mm".1"
#define id_nato_mmhs_mm_message_type   id_mm".2"
#define id_nato_mmhs_mm_address_list_indicator id_mm".3"
#define id_nato_mmhs_mm_exempted_address id_mm".4"
#define id_nato_mmhs_mm_extended_authorisation_info id_mm".5"
#define id_nato_mmhs_mm_distribution_codes id_mm".6"
#define id_nato_mmhs_mm_handling_instructions id_mm".7"
#define id_nato_mmhs_mm_message_instructions id_mm".8"
#define id_nato_mmhs_mm_codress_message id_mm".9"
#define id_nato_mmhs_mm_originator_reference id_mm".10"
#define id_nato_mmhs_mm_other_recipients_indicator id_mm".11"
#define id_nato_mmhs_mm_pilot_forwarding_info id_mm".12"
#define id_nato_mmhs_mm_acp127_message_identifier id_mm".13"
#define id_nato_mmhs_mm_originator_plad id_mm".14"
#define id_nato_mmhs_mm_information_labels id_mm".17"
#define id_nato_mmhs_mm_acp127_notification_request id_mm".15"
#define id_nato_mmhs_mm_acp127_notification_response id_mm".16"
#define id_nato_mmhs_hat_primary_precedence id_hat".0"
#define id_nato_mmhs_hat_copy_precedence id_hat".1"
#define id_nato_mmhs_hat_message_type  id_hat".2"
#define id_nato_mmhs_hat_address_list_indicator id_hat".3"
#define id_nato_mmhs_hat_exempted_address id_hat".4"
#define id_nato_mmhs_hat_extended_authorisation_info id_hat".5"
#define id_nato_mmhs_hat_distribution_codes id_hat".6"
#define id_nato_mmhs_hat_handling_instructions id_hat".7"
#define id_nato_mmhs_hat_message_instructions id_hat".8"
#define id_nato_mmhs_hat_codress_message id_hat".9"
#define id_nato_mmhs_hat_originator_reference id_hat".10"
#define id_nato_mmhs_hat_other_recipients_indicator id_hat".11"
#define id_nato_mmhs_hat_pilot_forwarding_info id_hat".12"
#define id_nato_mmhs_hat_acp127_message_identifier id_hat".13"
#define id_nato_mmhs_hat_originator_plad id_hat".14"
#define id_nato_mmhs_hat_acp127_notification_request id_hat".15"
#define id_nato_mmhs_hat_sic_codes     id_hat".16"
#define id_nato_mmhs_hat_distribution_extensions id_hat".17"
#define id_nato_mmhs_hat_body_part_information_label id_hat".18"
#define id_nato_mmhs_hat_security_information_labels id_hat".19"
#define id_nato_mmhs_cat               id_cat".0"
#define id_nato_mmhs_cat_atomal        id_cat".1"
#define id_nato_mmhs_cat_cryptosecurity id_cat".2"
#define id_nato_mmhs_cat_specialhandlingintel id_cat".3"
#define id_nato_mmhs_cat_ussiopesi     id_cat".4"
#define id_nato_mmhs_cat_eyesonly      id_cat".5"
#define id_nato_mmhs_cat_exclusive     id_cat".6"
#define id_nato_mmhs_cat_information_label id_cat".7"
#define id_nato_mmhs_informationlabel_atomal id_informationlabel".1"
#define id_nato_mmhs_informationlabel_cryptosecurity id_informationlabel".2"
#define id_nato_mmhs_informationlabel_specialhandlingintel id_informationlabel".3"
#define id_nato_mmhs_informationlabel_ussiopesi id_informationlabel".4"
#define id_nato_mmhs_informationlabel_eyesonly id_informationlabel".5"
#define id_nato_mmhs_informationlabel_exclusive id_informationlabel".6"
#define id_nato_mmhs_nat_acp127_notification_response id_nat".0"
#define id_mct_p772                    id_mcont".1"
#define ub_military_string             69
#define ub_military_number_of_sics     8
#define lb_military_sic                3
#define ub_military_sic                8
#define ub_military_bigstring          128
#define ub_data_size                   65535

static int hf_p772_InformationObject_PDU;         /* InformationObject */
static int hf_p772_Acp127NotificationResponse_PDU;  /* Acp127NotificationResponse */
static int hf_p772_ExemptedAddressSeq_PDU;        /* ExemptedAddressSeq */
static int hf_p772_ExtendedAuthorisationInfo_PDU;  /* ExtendedAuthorisationInfo */
static int hf_p772_DistributionCodes_PDU;         /* DistributionCodes */
static int hf_p772_HandlingInstructions_PDU;      /* HandlingInstructions */
static int hf_p772_MessageInstructions_PDU;       /* MessageInstructions */
static int hf_p772_CodressMessage_PDU;            /* CodressMessage */
static int hf_p772_OriginatorReference_PDU;       /* OriginatorReference */
static int hf_p772_PrimaryPrecedence_PDU;         /* PrimaryPrecedence */
static int hf_p772_CopyPrecedence_PDU;            /* CopyPrecedence */
static int hf_p772_MessageType_PDU;               /* MessageType */
static int hf_p772_AddressListDesignatorSeq_PDU;  /* AddressListDesignatorSeq */
static int hf_p772_OtherRecipientDesignatorSeq_PDU;  /* OtherRecipientDesignatorSeq */
static int hf_p772_PilotInformationSeq_PDU;       /* PilotInformationSeq */
static int hf_p772_Acp127MessageIdentifier_PDU;   /* Acp127MessageIdentifier */
static int hf_p772_OriginatorPlad_PDU;            /* OriginatorPlad */
static int hf_p772_SecurityInformationLabels_PDU;  /* SecurityInformationLabels */
static int hf_p772_PriorityLevelQualifier_PDU;    /* PriorityLevelQualifier */
static int hf_p772_ADatP3Parameters_PDU;          /* ADatP3Parameters */
static int hf_p772_ADatP3Data_PDU;                /* ADatP3Data */
static int hf_p772_CorrectionsParameters_PDU;     /* CorrectionsParameters */
static int hf_p772_CorrectionsData_PDU;           /* CorrectionsData */
static int hf_p772_ForwardedEncryptedParameters_PDU;  /* ForwardedEncryptedParameters */
static int hf_p772_ForwardedEncryptedData_PDU;    /* ForwardedEncryptedData */
static int hf_p772_MMMessageParameters_PDU;       /* MMMessageParameters */
static int hf_p772_MMMessageData_PDU;             /* MMMessageData */
static int hf_p772_ACP127DataParameters_PDU;      /* ACP127DataParameters */
static int hf_p772_ACP127DataData_PDU;            /* ACP127DataData */
static int hf_p772_Acp127NotificationType_PDU;    /* Acp127NotificationType */
static int hf_p772_mm;                            /* IPM */
static int hf_p772_mn;                            /* IPN */
static int hf_p772_acp127_notification_type;      /* Acp127NotificationType */
static int hf_p772_receipt_time;                  /* ReceiptTimeField */
static int hf_p772_addressListIndicator;          /* AddressListIndicator */
static int hf_p772_acp127_recipient;              /* Acp127Recipient */
static int hf_p772_acp127_supp_info;              /* Acp127SuppInfo */
static int hf_p772_AddressListIndicator_item;     /* AddressListDesignator */
static int hf_p772_ExemptedAddressSeq_item;       /* ExemptedAddress */
static int hf_p772_sics;                          /* SEQUENCE_SIZE_1_ub_military_number_of_sics_OF_Sic */
static int hf_p772_sics_item;                     /* Sic */
static int hf_p772_dist_Extensions;               /* SEQUENCE_OF_DistributionExtensionField */
static int hf_p772_dist_Extensions_item;          /* DistributionExtensionField */
static int hf_p772_dist_type;                     /* OBJECT_IDENTIFIER */
static int hf_p772_dist_value;                    /* T_dist_value */
static int hf_p772_HandlingInstructions_item;     /* MilitaryString */
static int hf_p772_MessageInstructions_item;      /* MilitaryString */
static int hf_p772_message_type_type;             /* TypeMessage */
static int hf_p772_identifier;                    /* MessageIdentifier */
static int hf_p772_AddressListDesignatorSeq_item;  /* AddressListDesignator */
static int hf_p772_address_list_type;             /* AddressListType */
static int hf_p772_listName;                      /* ORDescriptor */
static int hf_p772_notificationRequest;           /* AddressListRequest */
static int hf_p772_replyRequest;                  /* AddressListRequest */
static int hf_p772_OtherRecipientDesignatorSeq_item;  /* OtherRecipientDesignator */
static int hf_p772_other_recipient_type;          /* OtherRecipientType */
static int hf_p772_designator;                    /* MilitaryString */
static int hf_p772_PilotInformationSeq_item;      /* PilotInformation */
static int hf_p772_pilotPrecedence;               /* MMHSPrecedence */
static int hf_p772_pilotRecipient;                /* SEQUENCE_OF_ORDescriptor */
static int hf_p772_pilotRecipient_item;           /* ORDescriptor */
static int hf_p772_pilotSecurity;                 /* SecurityLabel */
static int hf_p772_pilotHandling;                 /* SEQUENCE_OF_MilitaryString */
static int hf_p772_pilotHandling_item;            /* MilitaryString */
static int hf_p772_content_security_label;        /* SecurityLabel */
static int hf_p772_heading_security_label;        /* SecurityLabel */
static int hf_p772_body_part_security_labels;     /* SEQUENCE_OF_BodyPartSecurityLabel */
static int hf_p772_body_part_security_labels_item;  /* BodyPartSecurityLabel */
static int hf_p772_body_part_security_label;      /* SecurityLabel */
static int hf_p772_body_part_sequence_number;     /* BodyPartSequenceNumber */
static int hf_p772_lineOriented;                  /* IA5String */
static int hf_p772_setOriented;                   /* T_setOriented */
static int hf_p772_setOriented_item;              /* IA5String */
static int hf_p772_delivery_time;                 /* MessageDeliveryTime */
static int hf_p772_delivery_envelope;             /* OtherMessageDeliveryFields */
/* named bits */
static int hf_p772_Acp127NotificationType_acp127_nn;
static int hf_p772_Acp127NotificationType_acp127_pn;
static int hf_p772_Acp127NotificationType_acp127_tn;

/* Initialize the subtree pointers */
static int ett_p772;
static int ett_p772_InformationObject;
static int ett_p772_Acp127NotificationResponse;
static int ett_p772_AddressListIndicator;
static int ett_p772_ExemptedAddressSeq;
static int ett_p772_DistributionCodes;
static int ett_p772_SEQUENCE_SIZE_1_ub_military_number_of_sics_OF_Sic;
static int ett_p772_SEQUENCE_OF_DistributionExtensionField;
static int ett_p772_DistributionExtensionField;
static int ett_p772_HandlingInstructions;
static int ett_p772_MessageInstructions;
static int ett_p772_MessageType;
static int ett_p772_AddressListDesignatorSeq;
static int ett_p772_AddressListDesignator;
static int ett_p772_OtherRecipientDesignatorSeq;
static int ett_p772_OtherRecipientDesignator;
static int ett_p772_PilotInformationSeq;
static int ett_p772_PilotInformation;
static int ett_p772_SEQUENCE_OF_ORDescriptor;
static int ett_p772_SEQUENCE_OF_MilitaryString;
static int ett_p772_SecurityInformationLabels;
static int ett_p772_SEQUENCE_OF_BodyPartSecurityLabel;
static int ett_p772_BodyPartSecurityLabel;
static int ett_p772_ADatP3Data;
static int ett_p772_T_setOriented;
static int ett_p772_ForwardedEncryptedParameters;
static int ett_p772_MMMessageParameters;
static int ett_p772_Acp127NotificationType;


static const ber_choice_t InformationObject_choice[] = {
  {   0, &hf_p772_mm             , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p22_IPM },
  {   1, &hf_p772_mn             , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_p22_IPN },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p772_InformationObject(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 InformationObject_choice, hf_index, ett_p772_InformationObject,
                                 NULL);

  return offset;
}


static int * const Acp127NotificationType_bits[] = {
  &hf_p772_Acp127NotificationType_acp127_nn,
  &hf_p772_Acp127NotificationType_acp127_pn,
  &hf_p772_Acp127NotificationType_acp127_tn,
  NULL
};

static int
dissect_p772_Acp127NotificationType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Acp127NotificationType_bits, 3, hf_index, ett_p772_Acp127NotificationType,
                                    NULL);

  return offset;
}


static const value_string p772_AddressListType_vals[] = {
  {   0, "primaryAddressList" },
  {   1, "copyAddressList" },
  { 0, NULL }
};


static int
dissect_p772_AddressListType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string p772_AddressListRequest_vals[] = {
  {   0, "action" },
  {   1, "info" },
  {   2, "both" },
  { 0, NULL }
};


static int
dissect_p772_AddressListRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t AddressListDesignator_set[] = {
  { &hf_p772_address_list_type, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p772_AddressListType },
  { &hf_p772_listName       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_p22_ORDescriptor },
  { &hf_p772_notificationRequest, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p772_AddressListRequest },
  { &hf_p772_replyRequest   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p772_AddressListRequest },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p772_AddressListDesignator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              AddressListDesignator_set, hf_index, ett_p772_AddressListDesignator);

  return offset;
}


static const ber_sequence_t AddressListIndicator_sequence_of[1] = {
  { &hf_p772_AddressListIndicator_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p772_AddressListDesignator },
};

static int
dissect_p772_AddressListIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      AddressListIndicator_sequence_of, hf_index, ett_p772_AddressListIndicator);

  return offset;
}



static int
dissect_p772_Acp127Recipient(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_military_bigstring, hf_index, NULL);

  return offset;
}



static int
dissect_p772_Acp127SuppInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_military_bigstring, hf_index, NULL);

  return offset;
}


static const ber_sequence_t Acp127NotificationResponse_set[] = {
  { &hf_p772_acp127_notification_type, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p772_Acp127NotificationType },
  { &hf_p772_receipt_time   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_p22_ReceiptTimeField },
  { &hf_p772_addressListIndicator, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p772_AddressListIndicator },
  { &hf_p772_acp127_recipient, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p772_Acp127Recipient },
  { &hf_p772_acp127_supp_info, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p772_Acp127SuppInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p772_Acp127NotificationResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              Acp127NotificationResponse_set, hf_index, ett_p772_Acp127NotificationResponse);

  return offset;
}



static int
dissect_p772_ExemptedAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p22_ORDescriptor(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t ExemptedAddressSeq_sequence_of[1] = {
  { &hf_p772_ExemptedAddressSeq_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p772_ExemptedAddress },
};

static int
dissect_p772_ExemptedAddressSeq(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      ExemptedAddressSeq_sequence_of, hf_index, ett_p772_ExemptedAddressSeq);

  return offset;
}



static int
dissect_p772_ExtendedAuthorisationInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_UTCTime(implicit_tag, actx, tree, tvb, offset, hf_index, NULL, NULL);

  return offset;
}



static int
dissect_p772_Sic(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        lb_military_sic, ub_military_sic, hf_index, NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_ub_military_number_of_sics_OF_Sic_sequence_of[1] = {
  { &hf_p772_sics_item      , BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_p772_Sic },
};

static int
dissect_p772_SEQUENCE_SIZE_1_ub_military_number_of_sics_OF_Sic(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, ub_military_number_of_sics, SEQUENCE_SIZE_1_ub_military_number_of_sics_OF_Sic_sequence_of, hf_index, ett_p772_SEQUENCE_SIZE_1_ub_military_number_of_sics_OF_Sic);

  return offset;
}



static int
dissect_p772_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_p772_T_dist_value(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
/* XXX: not implemented */
  offset = dissect_unknown_ber(actx->pinfo, tvb, offset, tree);


  return offset;
}


static const ber_sequence_t DistributionExtensionField_sequence[] = {
  { &hf_p772_dist_type      , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_p772_OBJECT_IDENTIFIER },
  { &hf_p772_dist_value     , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_p772_T_dist_value },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p772_DistributionExtensionField(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DistributionExtensionField_sequence, hf_index, ett_p772_DistributionExtensionField);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_DistributionExtensionField_sequence_of[1] = {
  { &hf_p772_dist_Extensions_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_p772_DistributionExtensionField },
};

static int
dissect_p772_SEQUENCE_OF_DistributionExtensionField(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_DistributionExtensionField_sequence_of, hf_index, ett_p772_SEQUENCE_OF_DistributionExtensionField);

  return offset;
}


static const ber_sequence_t DistributionCodes_set[] = {
  { &hf_p772_sics           , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p772_SEQUENCE_SIZE_1_ub_military_number_of_sics_OF_Sic },
  { &hf_p772_dist_Extensions, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p772_SEQUENCE_OF_DistributionExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p772_DistributionCodes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              DistributionCodes_set, hf_index, ett_p772_DistributionCodes);

  return offset;
}



static int
dissect_p772_MilitaryString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_military_string, hf_index, NULL);

  return offset;
}


static const ber_sequence_t HandlingInstructions_sequence_of[1] = {
  { &hf_p772_HandlingInstructions_item, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_p772_MilitaryString },
};

static int
dissect_p772_HandlingInstructions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      HandlingInstructions_sequence_of, hf_index, ett_p772_HandlingInstructions);

  return offset;
}


static const ber_sequence_t MessageInstructions_sequence_of[1] = {
  { &hf_p772_MessageInstructions_item, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_p772_MilitaryString },
};

static int
dissect_p772_MessageInstructions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      MessageInstructions_sequence_of, hf_index, ett_p772_MessageInstructions);

  return offset;
}



static int
dissect_p772_CodressMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_p772_OriginatorReference(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p772_MilitaryString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string p772_MMHSPrecedence_vals[] = {
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
dissect_p772_MMHSPrecedence(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string p772_PrimaryPrecedence_vals[] = {
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
dissect_p772_PrimaryPrecedence(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int precedence = -1;
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &precedence);

  if(precedence != -1)
   col_append_fstr(actx->pinfo->cinfo, COL_INFO, " (primary=%s)", val_to_str(precedence, p772_PrimaryPrecedence_vals, "precedence(%d)"));


  return offset;
}


static const value_string p772_CopyPrecedence_vals[] = {
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
dissect_p772_CopyPrecedence(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int precedence = -1;
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &precedence);

  if(precedence != -1)
   col_append_fstr(actx->pinfo->cinfo, COL_INFO, " (copy=%s)", val_to_str(precedence, p772_CopyPrecedence_vals, "precedence(%d)"));

  return offset;
}


static const value_string p772_TypeMessage_vals[] = {
  {   0, "exercise" },
  {   1, "operation" },
  {   2, "project" },
  {   3, "drill" },
  { 0, NULL }
};


static int
dissect_p772_TypeMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_p772_MessageIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p772_MilitaryString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t MessageType_set[] = {
  { &hf_p772_message_type_type, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p772_TypeMessage },
  { &hf_p772_identifier     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p772_MessageIdentifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p772_MessageType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              MessageType_set, hf_index, ett_p772_MessageType);

  return offset;
}


static const ber_sequence_t AddressListDesignatorSeq_sequence_of[1] = {
  { &hf_p772_AddressListDesignatorSeq_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p772_AddressListDesignator },
};

static int
dissect_p772_AddressListDesignatorSeq(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      AddressListDesignatorSeq_sequence_of, hf_index, ett_p772_AddressListDesignatorSeq);

  return offset;
}


static const value_string p772_OtherRecipientType_vals[] = {
  {   0, "primary" },
  {   1, "copy" },
  { 0, NULL }
};


static int
dissect_p772_OtherRecipientType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t OtherRecipientDesignator_set[] = {
  { &hf_p772_other_recipient_type, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p772_OtherRecipientType },
  { &hf_p772_designator     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_p772_MilitaryString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p772_OtherRecipientDesignator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              OtherRecipientDesignator_set, hf_index, ett_p772_OtherRecipientDesignator);

  return offset;
}


static const ber_sequence_t OtherRecipientDesignatorSeq_sequence_of[1] = {
  { &hf_p772_OtherRecipientDesignatorSeq_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p772_OtherRecipientDesignator },
};

static int
dissect_p772_OtherRecipientDesignatorSeq(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      OtherRecipientDesignatorSeq_sequence_of, hf_index, ett_p772_OtherRecipientDesignatorSeq);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ORDescriptor_sequence_of[1] = {
  { &hf_p772_pilotRecipient_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p22_ORDescriptor },
};

static int
dissect_p772_SEQUENCE_OF_ORDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ORDescriptor_sequence_of, hf_index, ett_p772_SEQUENCE_OF_ORDescriptor);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_MilitaryString_sequence_of[1] = {
  { &hf_p772_pilotHandling_item, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_p772_MilitaryString },
};

static int
dissect_p772_SEQUENCE_OF_MilitaryString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_MilitaryString_sequence_of, hf_index, ett_p772_SEQUENCE_OF_MilitaryString);

  return offset;
}


static const ber_sequence_t PilotInformation_sequence[] = {
  { &hf_p772_pilotPrecedence, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p772_MMHSPrecedence },
  { &hf_p772_pilotRecipient , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p772_SEQUENCE_OF_ORDescriptor },
  { &hf_p772_pilotSecurity  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SecurityLabel },
  { &hf_p772_pilotHandling  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p772_SEQUENCE_OF_MilitaryString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p772_PilotInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PilotInformation_sequence, hf_index, ett_p772_PilotInformation);

  return offset;
}


static const ber_sequence_t PilotInformationSeq_sequence_of[1] = {
  { &hf_p772_PilotInformationSeq_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_p772_PilotInformation },
};

static int
dissect_p772_PilotInformationSeq(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      PilotInformationSeq_sequence_of, hf_index, ett_p772_PilotInformationSeq);

  return offset;
}



static int
dissect_p772_Acp127MessageIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p772_MilitaryString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p772_OriginatorPlad(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p772_MilitaryString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p772_BodyPartSequenceNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t BodyPartSecurityLabel_set[] = {
  { &hf_p772_body_part_security_label, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_SecurityLabel },
  { &hf_p772_body_part_sequence_number, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p772_BodyPartSequenceNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p772_BodyPartSecurityLabel(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              BodyPartSecurityLabel_set, hf_index, ett_p772_BodyPartSecurityLabel);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_BodyPartSecurityLabel_sequence_of[1] = {
  { &hf_p772_body_part_security_labels_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p772_BodyPartSecurityLabel },
};

static int
dissect_p772_SEQUENCE_OF_BodyPartSecurityLabel(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_BodyPartSecurityLabel_sequence_of, hf_index, ett_p772_SEQUENCE_OF_BodyPartSecurityLabel);

  return offset;
}


static const ber_sequence_t SecurityInformationLabels_sequence[] = {
  { &hf_p772_content_security_label, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_SecurityLabel },
  { &hf_p772_heading_security_label, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SecurityLabel },
  { &hf_p772_body_part_security_labels, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p772_SEQUENCE_OF_BodyPartSecurityLabel },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p772_SecurityInformationLabels(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SecurityInformationLabels_sequence, hf_index, ett_p772_SecurityInformationLabels);

  return offset;
}


static const value_string p772_PriorityLevelQualifier_vals[] = {
  {   0, "low" },
  {   1, "high" },
  { 0, NULL }
};


static int
dissect_p772_PriorityLevelQualifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_p772_ADatP3Parameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_p772_IA5String(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t T_setOriented_sequence_of[1] = {
  { &hf_p772_setOriented_item, BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_p772_IA5String },
};

static int
dissect_p772_T_setOriented(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_setOriented_sequence_of, hf_index, ett_p772_T_setOriented);

  return offset;
}


static const value_string p772_ADatP3Data_vals[] = {
  {   0, "lineOriented" },
  {   1, "setOriented" },
  { 0, NULL }
};

static const ber_choice_t ADatP3Data_choice[] = {
  {   0, &hf_p772_lineOriented   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p772_IA5String },
  {   1, &hf_p772_setOriented    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_p772_T_setOriented },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p772_ADatP3Data(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ADatP3Data_choice, hf_index, ett_p772_ADatP3Data,
                                 NULL);

  return offset;
}



static int
dissect_p772_CorrectionsParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_p772_CorrectionsData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t ForwardedEncryptedParameters_set[] = {
  { &hf_p772_delivery_time  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_MessageDeliveryTime },
  { &hf_p772_delivery_envelope, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_p1_OtherMessageDeliveryFields },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p772_ForwardedEncryptedParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ForwardedEncryptedParameters_set, hf_index, ett_p772_ForwardedEncryptedParameters);

  return offset;
}



static int
dissect_p772_ForwardedEncryptedData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t MMMessageParameters_set[] = {
  { &hf_p772_delivery_time  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_MessageDeliveryTime },
  { &hf_p772_delivery_envelope, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_p1_OtherMessageDeliveryFields },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p772_MMMessageParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              MMMessageParameters_set, hf_index, ett_p772_MMMessageParameters);

  return offset;
}



static int
dissect_p772_MMMessageData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p22_IPM(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p772_ACP127DataParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_p772_ACP127DataData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                                        actx, tree, tvb, offset,
                                                        1, ub_data_size, hf_index, NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_InformationObject_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_InformationObject(false, tvb, offset, &asn1_ctx, tree, hf_p772_InformationObject_PDU);
  return offset;
}
static int dissect_Acp127NotificationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_Acp127NotificationResponse(false, tvb, offset, &asn1_ctx, tree, hf_p772_Acp127NotificationResponse_PDU);
  return offset;
}
static int dissect_ExemptedAddressSeq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_ExemptedAddressSeq(false, tvb, offset, &asn1_ctx, tree, hf_p772_ExemptedAddressSeq_PDU);
  return offset;
}
static int dissect_ExtendedAuthorisationInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_ExtendedAuthorisationInfo(false, tvb, offset, &asn1_ctx, tree, hf_p772_ExtendedAuthorisationInfo_PDU);
  return offset;
}
static int dissect_DistributionCodes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_DistributionCodes(false, tvb, offset, &asn1_ctx, tree, hf_p772_DistributionCodes_PDU);
  return offset;
}
static int dissect_HandlingInstructions_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_HandlingInstructions(false, tvb, offset, &asn1_ctx, tree, hf_p772_HandlingInstructions_PDU);
  return offset;
}
static int dissect_MessageInstructions_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_MessageInstructions(false, tvb, offset, &asn1_ctx, tree, hf_p772_MessageInstructions_PDU);
  return offset;
}
static int dissect_CodressMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_CodressMessage(false, tvb, offset, &asn1_ctx, tree, hf_p772_CodressMessage_PDU);
  return offset;
}
static int dissect_OriginatorReference_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_OriginatorReference(false, tvb, offset, &asn1_ctx, tree, hf_p772_OriginatorReference_PDU);
  return offset;
}
static int dissect_PrimaryPrecedence_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_PrimaryPrecedence(false, tvb, offset, &asn1_ctx, tree, hf_p772_PrimaryPrecedence_PDU);
  return offset;
}
static int dissect_CopyPrecedence_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_CopyPrecedence(false, tvb, offset, &asn1_ctx, tree, hf_p772_CopyPrecedence_PDU);
  return offset;
}
static int dissect_MessageType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_MessageType(false, tvb, offset, &asn1_ctx, tree, hf_p772_MessageType_PDU);
  return offset;
}
static int dissect_AddressListDesignatorSeq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_AddressListDesignatorSeq(false, tvb, offset, &asn1_ctx, tree, hf_p772_AddressListDesignatorSeq_PDU);
  return offset;
}
static int dissect_OtherRecipientDesignatorSeq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_OtherRecipientDesignatorSeq(false, tvb, offset, &asn1_ctx, tree, hf_p772_OtherRecipientDesignatorSeq_PDU);
  return offset;
}
static int dissect_PilotInformationSeq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_PilotInformationSeq(false, tvb, offset, &asn1_ctx, tree, hf_p772_PilotInformationSeq_PDU);
  return offset;
}
static int dissect_Acp127MessageIdentifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_Acp127MessageIdentifier(false, tvb, offset, &asn1_ctx, tree, hf_p772_Acp127MessageIdentifier_PDU);
  return offset;
}
static int dissect_OriginatorPlad_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_OriginatorPlad(false, tvb, offset, &asn1_ctx, tree, hf_p772_OriginatorPlad_PDU);
  return offset;
}
static int dissect_SecurityInformationLabels_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_SecurityInformationLabels(false, tvb, offset, &asn1_ctx, tree, hf_p772_SecurityInformationLabels_PDU);
  return offset;
}
static int dissect_PriorityLevelQualifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_PriorityLevelQualifier(false, tvb, offset, &asn1_ctx, tree, hf_p772_PriorityLevelQualifier_PDU);
  return offset;
}
static int dissect_ADatP3Parameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_ADatP3Parameters(false, tvb, offset, &asn1_ctx, tree, hf_p772_ADatP3Parameters_PDU);
  return offset;
}
static int dissect_ADatP3Data_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_ADatP3Data(false, tvb, offset, &asn1_ctx, tree, hf_p772_ADatP3Data_PDU);
  return offset;
}
static int dissect_CorrectionsParameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_CorrectionsParameters(false, tvb, offset, &asn1_ctx, tree, hf_p772_CorrectionsParameters_PDU);
  return offset;
}
static int dissect_CorrectionsData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_CorrectionsData(false, tvb, offset, &asn1_ctx, tree, hf_p772_CorrectionsData_PDU);
  return offset;
}
static int dissect_ForwardedEncryptedParameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_ForwardedEncryptedParameters(false, tvb, offset, &asn1_ctx, tree, hf_p772_ForwardedEncryptedParameters_PDU);
  return offset;
}
static int dissect_ForwardedEncryptedData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_ForwardedEncryptedData(false, tvb, offset, &asn1_ctx, tree, hf_p772_ForwardedEncryptedData_PDU);
  return offset;
}
static int dissect_MMMessageParameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_MMMessageParameters(false, tvb, offset, &asn1_ctx, tree, hf_p772_MMMessageParameters_PDU);
  return offset;
}
static int dissect_MMMessageData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_MMMessageData(false, tvb, offset, &asn1_ctx, tree, hf_p772_MMMessageData_PDU);
  return offset;
}
static int dissect_ACP127DataParameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_ACP127DataParameters(false, tvb, offset, &asn1_ctx, tree, hf_p772_ACP127DataParameters_PDU);
  return offset;
}
static int dissect_ACP127DataData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_ACP127DataData(false, tvb, offset, &asn1_ctx, tree, hf_p772_ACP127DataData_PDU);
  return offset;
}
static int dissect_Acp127NotificationType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_p772_Acp127NotificationType(false, tvb, offset, &asn1_ctx, tree, hf_p772_Acp127NotificationType_PDU);
  return offset;
}



/*
* Dissect STANAG 4406 PDUs inside a PPDU.
*/
static int
dissect_p772(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
	int offset = 0;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, proto_p772, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_p772);
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "P772");
	col_set_str(pinfo->cinfo, COL_INFO, "Military");

	dissect_p772_InformationObject(true, tvb, offset, &asn1_ctx , tree, -1);
	return tvb_captured_length(tvb);
}



/*--- proto_register_p772 -------------------------------------------*/
void proto_register_p772(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
    { &hf_p772_InformationObject_PDU,
      { "InformationObject", "p772.InformationObject",
        FT_UINT32, BASE_DEC, VALS(p22_InformationObject_vals), 0,
        NULL, HFILL }},
    { &hf_p772_Acp127NotificationResponse_PDU,
      { "Acp127NotificationResponse", "p772.Acp127NotificationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_ExemptedAddressSeq_PDU,
      { "ExemptedAddressSeq", "p772.ExemptedAddressSeq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_ExtendedAuthorisationInfo_PDU,
      { "ExtendedAuthorisationInfo", "p772.ExtendedAuthorisationInfo",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_DistributionCodes_PDU,
      { "DistributionCodes", "p772.DistributionCodes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_HandlingInstructions_PDU,
      { "HandlingInstructions", "p772.HandlingInstructions",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_MessageInstructions_PDU,
      { "MessageInstructions", "p772.MessageInstructions",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_CodressMessage_PDU,
      { "CodressMessage", "p772.CodressMessage",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_OriginatorReference_PDU,
      { "OriginatorReference", "p772.OriginatorReference",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_PrimaryPrecedence_PDU,
      { "PrimaryPrecedence", "p772.PrimaryPrecedence",
        FT_INT32, BASE_DEC, VALS(p772_PrimaryPrecedence_vals), 0,
        NULL, HFILL }},
    { &hf_p772_CopyPrecedence_PDU,
      { "CopyPrecedence", "p772.CopyPrecedence",
        FT_INT32, BASE_DEC, VALS(p772_CopyPrecedence_vals), 0,
        NULL, HFILL }},
    { &hf_p772_MessageType_PDU,
      { "MessageType", "p772.MessageType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_AddressListDesignatorSeq_PDU,
      { "AddressListDesignatorSeq", "p772.AddressListDesignatorSeq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_OtherRecipientDesignatorSeq_PDU,
      { "OtherRecipientDesignatorSeq", "p772.OtherRecipientDesignatorSeq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_PilotInformationSeq_PDU,
      { "PilotInformationSeq", "p772.PilotInformationSeq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_Acp127MessageIdentifier_PDU,
      { "Acp127MessageIdentifier", "p772.Acp127MessageIdentifier",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_OriginatorPlad_PDU,
      { "OriginatorPlad", "p772.OriginatorPlad",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_SecurityInformationLabels_PDU,
      { "SecurityInformationLabels", "p772.SecurityInformationLabels_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_PriorityLevelQualifier_PDU,
      { "PriorityLevelQualifier", "p772.PriorityLevelQualifier",
        FT_UINT32, BASE_DEC, VALS(p772_PriorityLevelQualifier_vals), 0,
        NULL, HFILL }},
    { &hf_p772_ADatP3Parameters_PDU,
      { "ADatP3Parameters", "p772.ADatP3Parameters",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_ADatP3Data_PDU,
      { "ADatP3Data", "p772.ADatP3Data",
        FT_UINT32, BASE_DEC, VALS(p772_ADatP3Data_vals), 0,
        NULL, HFILL }},
    { &hf_p772_CorrectionsParameters_PDU,
      { "CorrectionsParameters", "p772.CorrectionsParameters",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_CorrectionsData_PDU,
      { "CorrectionsData", "p772.CorrectionsData",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_ForwardedEncryptedParameters_PDU,
      { "ForwardedEncryptedParameters", "p772.ForwardedEncryptedParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_ForwardedEncryptedData_PDU,
      { "ForwardedEncryptedData", "p772.ForwardedEncryptedData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_MMMessageParameters_PDU,
      { "MMMessageParameters", "p772.MMMessageParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_MMMessageData_PDU,
      { "MMMessageData", "p772.MMMessageData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_ACP127DataParameters_PDU,
      { "ACP127DataParameters", "p772.ACP127DataParameters",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_ACP127DataData_PDU,
      { "ACP127DataData", "p772.ACP127DataData",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_Acp127NotificationType_PDU,
      { "Acp127NotificationType", "p772.Acp127NotificationType",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_mm,
      { "mm", "p772.mm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IPM", HFILL }},
    { &hf_p772_mn,
      { "mn", "p772.mn_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IPN", HFILL }},
    { &hf_p772_acp127_notification_type,
      { "acp127-notification-type", "p772.acp127_notification_type",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Acp127NotificationType", HFILL }},
    { &hf_p772_receipt_time,
      { "receipt-time", "p772.receipt_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "ReceiptTimeField", HFILL }},
    { &hf_p772_addressListIndicator,
      { "addressListIndicator", "p772.addressListIndicator",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_acp127_recipient,
      { "acp127-recipient", "p772.acp127_recipient",
        FT_STRING, BASE_NONE, NULL, 0,
        "Acp127Recipient", HFILL }},
    { &hf_p772_acp127_supp_info,
      { "acp127-supp-info", "p772.acp127_supp_info",
        FT_STRING, BASE_NONE, NULL, 0,
        "Acp127SuppInfo", HFILL }},
    { &hf_p772_AddressListIndicator_item,
      { "AddressListDesignator", "p772.AddressListDesignator_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_ExemptedAddressSeq_item,
      { "ExemptedAddress", "p772.ExemptedAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_sics,
      { "sics", "p772.sics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_ub_military_number_of_sics_OF_Sic", HFILL }},
    { &hf_p772_sics_item,
      { "Sic", "p772.Sic",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_dist_Extensions,
      { "dist-Extensions", "p772.dist_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_DistributionExtensionField", HFILL }},
    { &hf_p772_dist_Extensions_item,
      { "DistributionExtensionField", "p772.DistributionExtensionField_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_dist_type,
      { "dist-type", "p772.dist_type",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_p772_dist_value,
      { "dist-value", "p772.dist_value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_dist_value", HFILL }},
    { &hf_p772_HandlingInstructions_item,
      { "MilitaryString", "p772.MilitaryString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_MessageInstructions_item,
      { "MilitaryString", "p772.MilitaryString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_message_type_type,
      { "type", "p772.type",
        FT_INT32, BASE_DEC, VALS(p772_TypeMessage_vals), 0,
        "TypeMessage", HFILL }},
    { &hf_p772_identifier,
      { "identifier", "p772.identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "MessageIdentifier", HFILL }},
    { &hf_p772_AddressListDesignatorSeq_item,
      { "AddressListDesignator", "p772.AddressListDesignator_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_address_list_type,
      { "type", "p772.type",
        FT_INT32, BASE_DEC, VALS(p772_AddressListType_vals), 0,
        "AddressListType", HFILL }},
    { &hf_p772_listName,
      { "listName", "p772.listName_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ORDescriptor", HFILL }},
    { &hf_p772_notificationRequest,
      { "notificationRequest", "p772.notificationRequest",
        FT_INT32, BASE_DEC, VALS(p772_AddressListRequest_vals), 0,
        "AddressListRequest", HFILL }},
    { &hf_p772_replyRequest,
      { "replyRequest", "p772.replyRequest",
        FT_INT32, BASE_DEC, VALS(p772_AddressListRequest_vals), 0,
        "AddressListRequest", HFILL }},
    { &hf_p772_OtherRecipientDesignatorSeq_item,
      { "OtherRecipientDesignator", "p772.OtherRecipientDesignator_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_other_recipient_type,
      { "type", "p772.type",
        FT_INT32, BASE_DEC, VALS(p772_OtherRecipientType_vals), 0,
        "OtherRecipientType", HFILL }},
    { &hf_p772_designator,
      { "designator", "p772.designator",
        FT_STRING, BASE_NONE, NULL, 0,
        "MilitaryString", HFILL }},
    { &hf_p772_PilotInformationSeq_item,
      { "PilotInformation", "p772.PilotInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_pilotPrecedence,
      { "pilotPrecedence", "p772.pilotPrecedence",
        FT_INT32, BASE_DEC, VALS(p772_MMHSPrecedence_vals), 0,
        "MMHSPrecedence", HFILL }},
    { &hf_p772_pilotRecipient,
      { "pilotRecipient", "p772.pilotRecipient",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ORDescriptor", HFILL }},
    { &hf_p772_pilotRecipient_item,
      { "ORDescriptor", "p772.ORDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_pilotSecurity,
      { "pilotSecurity", "p772.pilotSecurity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityLabel", HFILL }},
    { &hf_p772_pilotHandling,
      { "pilotHandling", "p772.pilotHandling",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_MilitaryString", HFILL }},
    { &hf_p772_pilotHandling_item,
      { "MilitaryString", "p772.MilitaryString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_content_security_label,
      { "content-security-label", "p772.content_security_label_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityLabel", HFILL }},
    { &hf_p772_heading_security_label,
      { "heading-security-label", "p772.heading_security_label_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityLabel", HFILL }},
    { &hf_p772_body_part_security_labels,
      { "body-part-security-labels", "p772.body_part_security_labels",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_BodyPartSecurityLabel", HFILL }},
    { &hf_p772_body_part_security_labels_item,
      { "BodyPartSecurityLabel", "p772.BodyPartSecurityLabel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_body_part_security_label,
      { "body-part-security-label", "p772.body_part_security_label_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityLabel", HFILL }},
    { &hf_p772_body_part_sequence_number,
      { "body-part-sequence-number", "p772.body_part_sequence_number",
        FT_INT32, BASE_DEC, NULL, 0,
        "BodyPartSequenceNumber", HFILL }},
    { &hf_p772_lineOriented,
      { "lineOriented", "p772.lineOriented",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String", HFILL }},
    { &hf_p772_setOriented,
      { "setOriented", "p772.setOriented",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p772_setOriented_item,
      { "setOriented item", "p772.setOriented_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String", HFILL }},
    { &hf_p772_delivery_time,
      { "delivery-time", "p772.delivery_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "MessageDeliveryTime", HFILL }},
    { &hf_p772_delivery_envelope,
      { "delivery-envelope", "p772.delivery_envelope_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "OtherMessageDeliveryFields", HFILL }},
    { &hf_p772_Acp127NotificationType_acp127_nn,
      { "acp127-nn", "p772.Acp127NotificationType.acp127.nn",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_p772_Acp127NotificationType_acp127_pn,
      { "acp127-pn", "p772.Acp127NotificationType.acp127.pn",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_p772_Acp127NotificationType_acp127_tn,
      { "acp127-tn", "p772.Acp127NotificationType.acp127.tn",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_p772,
    &ett_p772_InformationObject,
    &ett_p772_Acp127NotificationResponse,
    &ett_p772_AddressListIndicator,
    &ett_p772_ExemptedAddressSeq,
    &ett_p772_DistributionCodes,
    &ett_p772_SEQUENCE_SIZE_1_ub_military_number_of_sics_OF_Sic,
    &ett_p772_SEQUENCE_OF_DistributionExtensionField,
    &ett_p772_DistributionExtensionField,
    &ett_p772_HandlingInstructions,
    &ett_p772_MessageInstructions,
    &ett_p772_MessageType,
    &ett_p772_AddressListDesignatorSeq,
    &ett_p772_AddressListDesignator,
    &ett_p772_OtherRecipientDesignatorSeq,
    &ett_p772_OtherRecipientDesignator,
    &ett_p772_PilotInformationSeq,
    &ett_p772_PilotInformation,
    &ett_p772_SEQUENCE_OF_ORDescriptor,
    &ett_p772_SEQUENCE_OF_MilitaryString,
    &ett_p772_SecurityInformationLabels,
    &ett_p772_SEQUENCE_OF_BodyPartSecurityLabel,
    &ett_p772_BodyPartSecurityLabel,
    &ett_p772_ADatP3Data,
    &ett_p772_T_setOriented,
    &ett_p772_ForwardedEncryptedParameters,
    &ett_p772_MMMessageParameters,
    &ett_p772_Acp127NotificationType,
  };

  /* Register protocol */
  proto_p772 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("p772", dissect_p772, proto_p772);

  /* Register fields and subtrees */
  proto_register_field_array(proto_p772, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_ber_syntax_dissector("STANAG 4406", proto_p772, dissect_p772);
  register_ber_oid_syntax(".p772", NULL, "STANAG 4406");
}


/*--- proto_reg_handoff_p772 --- */
void proto_reg_handoff_p772(void) {
  register_ber_oid_dissector("1.3.26.0.4406.0.2.0", dissect_PrimaryPrecedence_PDU, proto_p772, "primary-precedence");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.1", dissect_CopyPrecedence_PDU, proto_p772, "copy-precedence");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.2", dissect_MessageType_PDU, proto_p772, "message-type");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.3", dissect_AddressListDesignatorSeq_PDU, proto_p772, "address-list-indicator");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.4", dissect_ExemptedAddressSeq_PDU, proto_p772, "exempted-address");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.5", dissect_ExtendedAuthorisationInfo_PDU, proto_p772, "extended-authorisation-info");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.6", dissect_DistributionCodes_PDU, proto_p772, "distribution-codes");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.7", dissect_HandlingInstructions_PDU, proto_p772, "handling-instructions");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.8", dissect_MessageInstructions_PDU, proto_p772, "message-instructions");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.9", dissect_CodressMessage_PDU, proto_p772, "codress-message");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.10", dissect_OriginatorReference_PDU, proto_p772, "originator-reference");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.11", dissect_OtherRecipientDesignatorSeq_PDU, proto_p772, "other-recipients-indicator");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.12", dissect_PilotInformationSeq_PDU, proto_p772, "pilot-forwarding-info");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.13", dissect_Acp127MessageIdentifier_PDU, proto_p772, "acp127-message-identifier");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.14", dissect_OriginatorPlad_PDU, proto_p772, "originator-plad");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.15", dissect_Acp127NotificationType_PDU, proto_p772, "acp127-notification-request");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.16", dissect_Acp127NotificationResponse_PDU, proto_p772, "acp127-notification-response");
  register_ber_oid_dissector("1.3.26.0.4406.0.2.17", dissect_SecurityInformationLabels_PDU, proto_p772, "information-labels");
  register_ber_oid_dissector("1.3.26.0.4406.0.8.0", dissect_PriorityLevelQualifier_PDU, proto_p772, "priority-level-qualifier");
  register_ber_oid_dissector(id_nato_mmhs_et_adatp3, dissect_ADatP3Data_PDU, proto_p772, "adatp3");
  register_ber_oid_dissector(id_nato_mmhs_et_adatp3_parameters, dissect_ADatP3Parameters_PDU, proto_p772, "adatp3-parameters");
  register_ber_oid_dissector(id_nato_mmhs_et_corrections, dissect_CorrectionsData_PDU, proto_p772, "corrections");
  register_ber_oid_dissector(id_nato_mmhs_et_corrections_parameters, dissect_CorrectionsParameters_PDU, proto_p772, "corrections-parameters");
  register_ber_oid_dissector(id_nato_mmhs_et_forwarded_encrypted, dissect_ForwardedEncryptedData_PDU, proto_p772, "forwarded-encrypted");
  register_ber_oid_dissector(id_nato_mmhs_et_forwarded_encrypted_parameters, dissect_ForwardedEncryptedParameters_PDU, proto_p772, "forwarded-encrypted-parameters");
  register_ber_oid_dissector(id_nato_mmhs_et_mm_message, dissect_MMMessageData_PDU, proto_p772, "mm-message");
  register_ber_oid_dissector(id_nato_mmhs_et_mm_message_parameters, dissect_MMMessageParameters_PDU, proto_p772, "mm-message-parameters");
  register_ber_oid_dissector(id_nato_mmhs_et_mm_acp127data, dissect_ACP127DataData_PDU, proto_p772, "acp127-data");
  register_ber_oid_dissector(id_nato_mmhs_et_mm_acp127data_parameters, dissect_ACP127DataParameters_PDU, proto_p772, "acp127-data-parameters");
  register_ber_oid_dissector("2.6.1.4.17.1.3.26.0.4406.0.4.1", dissect_InformationObject_PDU, proto_p772, "id-et-content-p772");


  register_ber_oid_dissector("1.3.26.0.4406.0.4.1", dissect_p772, proto_p772, "STANAG 4406");
}
