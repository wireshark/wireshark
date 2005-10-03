/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* .\packet-x420.c                                                            */
/* ../../tools/asn2eth.py -X -b -e -p x420 -c x420.cnf -s packet-x420-template x420.asn */

/* Input file: packet-x420-template.c */

/* packet-x420.c
 * Routines for X.420 (X.400 Message Transfer)  packet dissection
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
#include "packet-acse.h"
#include "packet-ros.h"

#include "packet-x509af.h"
#include "packet-x411.h"

#include "packet-x420.h"

#define PNAME  "X.420 OSI Information Object"
#define PSNAME "X420"
#define PFNAME "x420"

/* Initialize the protocol and registered fields */
int proto_x420 = -1;

static char object_identifier_id[BER_MAX_OID_STR_LEN]; /* content type identifier */


/*--- Included file: packet-x420-hf.c ---*/

static int hf_x420_OriginatingUA_PDU = -1;        /* OriginatingUA */
static int hf_x420_ipm = -1;                      /* IPM */
static int hf_x420_ipn = -1;                      /* IPN */
static int hf_x420_heading = -1;                  /* Heading */
static int hf_x420_body = -1;                     /* Body */
static int hf_x420_type = -1;                     /* T_type */
static int hf_x420_value = -1;                    /* T_value */
static int hf_x420_this_IPM = -1;                 /* ThisIPMField */
static int hf_x420_originator = -1;               /* OriginatorField */
static int hf_x420_authorizing_users = -1;        /* AuthorizingUsersField */
static int hf_x420_primary_recipients = -1;       /* PrimaryRecipientsField */
static int hf_x420_copy_recipients = -1;          /* CopyRecipientsField */
static int hf_x420_blind_copy_recipients = -1;    /* BlindCopyRecipientsField */
static int hf_x420_replied_to_IPM = -1;           /* RepliedToIPMField */
static int hf_x420_obsoleted_IPMs = -1;           /* ObsoletedIPMsField */
static int hf_x420_related_IPMs = -1;             /* RelatedIPMsField */
static int hf_x420_subject = -1;                  /* SubjectField */
static int hf_x420_expiry_time = -1;              /* ExpiryTimeField */
static int hf_x420_reply_time = -1;               /* ReplyTimeField */
static int hf_x420_reply_recipients = -1;         /* ReplyRecipientsField */
static int hf_x420_importance = -1;               /* ImportanceField */
static int hf_x420_sensitivity = -1;              /* SensitivityField */
static int hf_x420_auto_forwarded = -1;           /* AutoForwardedField */
static int hf_x420_extensions = -1;               /* ExtensionsField */
static int hf_x420_user = -1;                     /* ORName */
static int hf_x420_user_relative_identifier = -1;  /* LocalIPMIdentifier */
static int hf_x420_recipient = -1;                /* ORDescriptor */
static int hf_x420_notification_requests = -1;    /* NotificationRequests */
static int hf_x420_reply_requested = -1;          /* BOOLEAN */
static int hf_x420_recipient_extensions = -1;     /* RecipientExtensionsField */
static int hf_x420_formal_name = -1;              /* ORName */
static int hf_x420_free_form_name = -1;           /* FreeFormName */
static int hf_x420_telephone_number = -1;         /* TelephoneNumber */
static int hf_x420_RecipientExtensionsField_item = -1;  /* IPMSExtension */
static int hf_x420_AuthorizingUsersField_item = -1;  /* AuthorizingUsersSubfield */
static int hf_x420_PrimaryRecipientsField_item = -1;  /* PrimaryRecipientsSubfield */
static int hf_x420_CopyRecipientsField_item = -1;  /* CopyRecipientsSubfield */
static int hf_x420_BlindCopyRecipientsField_item = -1;  /* BlindCopyRecipientsSubfield */
static int hf_x420_ObsoletedIPMsField_item = -1;  /* ObsoletedIPMsSubfield */
static int hf_x420_RelatedIPMsField_item = -1;    /* RelatedIPMsSubfield */
static int hf_x420_ReplyRecipientsField_item = -1;  /* ReplyRecipientsSubfield */
static int hf_x420_ExtensionsField_item = -1;     /* IPMSExtension */
static int hf_x420_Body_item = -1;                /* BodyPart */
static int hf_x420_ia5_text = -1;                 /* IA5TextBodyPart */
static int hf_x420_g3_facsimile = -1;             /* G3FacsimileBodyPart */
static int hf_x420_g4_class1 = -1;                /* G4Class1BodyPart */
static int hf_x420_teletex = -1;                  /* TeletexBodyPart */
static int hf_x420_videotex = -1;                 /* VideotexBodyPart */
static int hf_x420_encrypted = -1;                /* EncryptedBodyPart */
static int hf_x420_message = -1;                  /* MessageBodyPart */
static int hf_x420_mixed_mode = -1;               /* MixedModeBodyPart */
static int hf_x420_bilaterally_defined = -1;      /* BilaterallyDefinedBodyPart */
static int hf_x420_nationally_defined = -1;       /* NationallyDefinedBodyPart */
static int hf_x420_extended = -1;                 /* ExtendedBodyPart */
static int hf_x420_extended_parameters = -1;      /* EXTERNAL */
static int hf_x420_extended_data = -1;            /* EXTERNAL */
static int hf_x420_ia5text_parameters = -1;       /* IA5TextParameters */
static int hf_x420_ia5text_data = -1;             /* IA5TextData */
static int hf_x420_repertoire = -1;               /* Repertoire */
static int hf_x420_g3facsimile_parameters = -1;   /* G3FacsimileParameters */
static int hf_x420_g3facsimile_data = -1;         /* G3FacsimileData */
static int hf_x420_number_of_pages = -1;          /* INTEGER */
static int hf_x420_g3facsimile_non_basic_parameters = -1;  /* G3FacsimileNonBasicParameters */
static int hf_x420_G3FacsimileData_item = -1;     /* BIT_STRING */
static int hf_x420_G4Class1BodyPart_item = -1;    /* Interchange_Data_Element */
static int hf_x420_MixedModeBodyPart_item = -1;   /* Interchange_Data_Element */
static int hf_x420_teletex_parameters = -1;       /* TeletexParameters */
static int hf_x420_teletex_data = -1;             /* TeletexData */
static int hf_x420_telex_compatible = -1;         /* BOOLEAN */
static int hf_x420_teletex_non_basic_parameters = -1;  /* TeletexNonBasicParameters */
static int hf_x420_TeletexData_item = -1;         /* TeletexString */
static int hf_x420_videotex_parameters = -1;      /* VideotexParameters */
static int hf_x420_videotex_data = -1;            /* VideotexData */
static int hf_x420_syntax = -1;                   /* VideotexSyntax */
static int hf_x420_encrypted_parameters = -1;     /* EncryptedParameters */
static int hf_x420_encrypted_data = -1;           /* EncryptedData */
static int hf_x420_algorithm_identifier = -1;     /* AlgorithmIdentifier */
static int hf_x420_originator_certificates = -1;  /* ExtendedCertificates */
static int hf_x420_message_parameters = -1;       /* MessageParameters */
static int hf_x420_message_data = -1;             /* MessageData */
static int hf_x420_delivery_time = -1;            /* MessageDeliveryTime */
static int hf_x420_delivery_envelope = -1;        /* OtherMessageDeliveryFields */
static int hf_x420_subject_ipm = -1;              /* SubjectIPMField */
static int hf_x420_ipn_originator = -1;           /* IPNOriginatorField */
static int hf_x420_ipm_intended_recipient = -1;   /* IPMIntendedRecipientField */
static int hf_x420_conversion_eits = -1;          /* ConversionEITsField */
static int hf_x420_notification_extensions = -1;  /* NotificationExtensionsField */
static int hf_x420_choice = -1;                   /* T_choice */
static int hf_x420_non_receipt_fields = -1;       /* NonReceiptFields */
static int hf_x420_receipt_fields = -1;           /* ReceiptFields */
static int hf_x420_other_notification_type_fields = -1;  /* OtherNotificationTypeFields */
static int hf_x420_non_receipt_reason = -1;       /* NonReceiptReasonField */
static int hf_x420_discard_reason = -1;           /* DiscardReasonField */
static int hf_x420_auto_forward_comment = -1;     /* AutoForwardCommentField */
static int hf_x420_returned_ipm = -1;             /* ReturnedIPMField */
static int hf_x420_nrn_extensions = -1;           /* NRNExtensionsField */
static int hf_x420_receipt_time = -1;             /* ReceiptTimeField */
static int hf_x420_acknowledgment_mode = -1;      /* AcknowledgmentModeField */
static int hf_x420_suppl_receipt_info = -1;       /* SupplReceiptInfoField */
static int hf_x420_rn_extensions = -1;            /* RNExtensionsField */
static int hf_x420_NotificationExtensionsField_item = -1;  /* IPMSExtension */
static int hf_x420_NRNExtensionsField_item = -1;  /* IPMSExtension */
static int hf_x420_RNExtensionsField_item = -1;   /* IPMSExtension */
static int hf_x420_OtherNotificationTypeFields_item = -1;  /* IPMSExtension */
static int hf_x420_advice = -1;                   /* BodyPart */
static int hf_x420_next_available = -1;           /* Time */
static int hf_x420_new_address = -1;              /* ORDescriptor */
static int hf_x420_effective_from = -1;           /* Time */
static int hf_x420_assembly_instructions = -1;    /* BodyPartReferences */
static int hf_x420_BodyPartReferences_item = -1;  /* BodyPartReference */
static int hf_x420_stored_entry = -1;             /* SequenceNumber */
static int hf_x420_stored_content = -1;           /* SequenceNumber */
static int hf_x420_submitted_body_part = -1;      /* INTEGER_1_MAX */
static int hf_x420_stored_body_part = -1;         /* T_stored_body_part */
static int hf_x420_message_entry = -1;            /* SequenceNumber */
static int hf_x420_body_part_number = -1;         /* INTEGER_1_MAX */
/* named bits */
static int hf_x420_NotificationRequests_rn = -1;
static int hf_x420_NotificationRequests_nrn = -1;
static int hf_x420_NotificationRequests_ipm_return = -1;
static int hf_x420_NotificationRequests_an_supported = -1;
static int hf_x420_NotificationRequests_suppress_an = -1;

/*--- End of included file: packet-x420-hf.c ---*/


/* Initialize the subtree pointers */
static gint ett_x420 = -1;

/*--- Included file: packet-x420-ett.c ---*/

static gint ett_x420_InformationObject = -1;
static gint ett_x420_IPM = -1;
static gint ett_x420_IPMSExtension = -1;
static gint ett_x420_Heading = -1;
static gint ett_x420_IPMIdentifier = -1;
static gint ett_x420_RecipientSpecifier = -1;
static gint ett_x420_ORDescriptor = -1;
static gint ett_x420_NotificationRequests = -1;
static gint ett_x420_RecipientExtensionsField = -1;
static gint ett_x420_AuthorizingUsersField = -1;
static gint ett_x420_PrimaryRecipientsField = -1;
static gint ett_x420_CopyRecipientsField = -1;
static gint ett_x420_BlindCopyRecipientsField = -1;
static gint ett_x420_ObsoletedIPMsField = -1;
static gint ett_x420_RelatedIPMsField = -1;
static gint ett_x420_ReplyRecipientsField = -1;
static gint ett_x420_ExtensionsField = -1;
static gint ett_x420_Body = -1;
static gint ett_x420_BodyPart = -1;
static gint ett_x420_ExtendedBodyPart = -1;
static gint ett_x420_IA5TextBodyPart = -1;
static gint ett_x420_IA5TextParameters = -1;
static gint ett_x420_G3FacsimileBodyPart = -1;
static gint ett_x420_G3FacsimileParameters = -1;
static gint ett_x420_G3FacsimileData = -1;
static gint ett_x420_G4Class1BodyPart = -1;
static gint ett_x420_MixedModeBodyPart = -1;
static gint ett_x420_TeletexBodyPart = -1;
static gint ett_x420_TeletexParameters = -1;
static gint ett_x420_TeletexData = -1;
static gint ett_x420_VideotexBodyPart = -1;
static gint ett_x420_VideotexParameters = -1;
static gint ett_x420_EncryptedBodyPart = -1;
static gint ett_x420_EncryptedParameters = -1;
static gint ett_x420_MessageBodyPart = -1;
static gint ett_x420_MessageParameters = -1;
static gint ett_x420_IPN = -1;
static gint ett_x420_T_choice = -1;
static gint ett_x420_CommonFields = -1;
static gint ett_x420_NonReceiptFields = -1;
static gint ett_x420_ReceiptFields = -1;
static gint ett_x420_NotificationExtensionsField = -1;
static gint ett_x420_NRNExtensionsField = -1;
static gint ett_x420_RNExtensionsField = -1;
static gint ett_x420_OtherNotificationTypeFields = -1;
static gint ett_x420_AbsenceAdvice = -1;
static gint ett_x420_ChangeOfAddressAdvice = -1;
static gint ett_x420_IPMAssemblyInstructions = -1;
static gint ett_x420_BodyPartReferences = -1;
static gint ett_x420_BodyPartReference = -1;
static gint ett_x420_T_stored_body_part = -1;

/*--- End of included file: packet-x420-ett.c ---*/



/*--- Included file: packet-x420-fn.c ---*/

/*--- Cyclic dependencies ---*/

/* IPM -> Body -> BodyPart -> MessageBodyPart -> MessageData -> IPM */
static int dissect_x420_IPM(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);

static int dissect_ipm_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_IPM(TRUE, tvb, offset, pinfo, tree, hf_x420_ipm);
}


/*--- Fields for imported types ---*/

static int dissect_user(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ORName(FALSE, tvb, offset, pinfo, tree, hf_x420_user);
}
static int dissect_formal_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ORName(FALSE, tvb, offset, pinfo, tree, hf_x420_formal_name);
}
static int dissect_extended_parameters_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acse_EXTERNAL(TRUE, tvb, offset, pinfo, tree, hf_x420_extended_parameters);
}
static int dissect_extended_data(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acse_EXTERNAL(FALSE, tvb, offset, pinfo, tree, hf_x420_extended_data);
}
static int dissect_g3facsimile_non_basic_parameters_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_G3FacsimileNonBasicParameters(TRUE, tvb, offset, pinfo, tree, hf_x420_g3facsimile_non_basic_parameters);
}
static int dissect_teletex_non_basic_parameters_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_TeletexNonBasicParameters(TRUE, tvb, offset, pinfo, tree, hf_x420_teletex_non_basic_parameters);
}
static int dissect_algorithm_identifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_x420_algorithm_identifier);
}
static int dissect_originator_certificates(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ExtendedCertificates(FALSE, tvb, offset, pinfo, tree, hf_x420_originator_certificates);
}
static int dissect_delivery_time_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MessageDeliveryTime(TRUE, tvb, offset, pinfo, tree, hf_x420_delivery_time);
}
static int dissect_delivery_envelope_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_OtherMessageDeliveryFields(TRUE, tvb, offset, pinfo, tree, hf_x420_delivery_envelope);
}



static int
dissect_x420_Time(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTCTime,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_next_available(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_Time(FALSE, tvb, offset, pinfo, tree, hf_x420_next_available);
}
static int dissect_effective_from_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_Time(TRUE, tvb, offset, pinfo, tree, hf_x420_effective_from);
}



static int
dissect_x420_LocalIPMIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_user_relative_identifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_LocalIPMIdentifier(FALSE, tvb, offset, pinfo, tree, hf_x420_user_relative_identifier);
}


static const ber_sequence_t IPMIdentifier_set[] = {
  { BER_CLASS_APP, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_user },
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_user_relative_identifier },
  { 0, 0, 0, NULL }
};

static int
dissect_x420_IPMIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              IPMIdentifier_set, hf_index, ett_x420_IPMIdentifier);

  return offset;
}



static int
dissect_x420_ThisIPMField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x420_IPMIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_this_IPM(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_ThisIPMField(FALSE, tvb, offset, pinfo, tree, hf_x420_this_IPM);
}



static int
dissect_x420_FreeFormName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_free_form_name_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_FreeFormName(TRUE, tvb, offset, pinfo, tree, hf_x420_free_form_name);
}



static int
dissect_x420_TelephoneNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_telephone_number_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_TelephoneNumber(TRUE, tvb, offset, pinfo, tree, hf_x420_telephone_number);
}


static const ber_sequence_t ORDescriptor_set[] = {
  { BER_CLASS_APP, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_formal_name },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_free_form_name_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_telephone_number_impl },
  { 0, 0, 0, NULL }
};

int
dissect_x420_ORDescriptor(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ORDescriptor_set, hf_index, ett_x420_ORDescriptor);

  return offset;
}
static int dissect_recipient_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_ORDescriptor(TRUE, tvb, offset, pinfo, tree, hf_x420_recipient);
}
static int dissect_new_address_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_ORDescriptor(TRUE, tvb, offset, pinfo, tree, hf_x420_new_address);
}



static int
dissect_x420_OriginatorField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x420_ORDescriptor(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_originator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_OriginatorField(TRUE, tvb, offset, pinfo, tree, hf_x420_originator);
}



static int
dissect_x420_AuthorizingUsersSubfield(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x420_ORDescriptor(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_AuthorizingUsersField_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_AuthorizingUsersSubfield(FALSE, tvb, offset, pinfo, tree, hf_x420_AuthorizingUsersField_item);
}


static const ber_sequence_t AuthorizingUsersField_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_AuthorizingUsersField_item },
};

static int
dissect_x420_AuthorizingUsersField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      AuthorizingUsersField_sequence_of, hf_index, ett_x420_AuthorizingUsersField);

  return offset;
}
static int dissect_authorizing_users_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_AuthorizingUsersField(TRUE, tvb, offset, pinfo, tree, hf_x420_authorizing_users);
}


static const asn_namedbit NotificationRequests_bits[] = {
  {  0, &hf_x420_NotificationRequests_rn, -1, -1, "rn", NULL },
  {  1, &hf_x420_NotificationRequests_nrn, -1, -1, "nrn", NULL },
  {  2, &hf_x420_NotificationRequests_ipm_return, -1, -1, "ipm-return", NULL },
  {  3, &hf_x420_NotificationRequests_an_supported, -1, -1, "an-supported", NULL },
  {  4, &hf_x420_NotificationRequests_suppress_an, -1, -1, "suppress-an", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x420_NotificationRequests(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    NotificationRequests_bits, hf_index, ett_x420_NotificationRequests,
                                    NULL);

  return offset;
}
static int dissect_notification_requests_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_NotificationRequests(TRUE, tvb, offset, pinfo, tree, hf_x420_notification_requests);
}



static int
dissect_x420_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_reply_requested_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_x420_reply_requested);
}
static int dissect_telex_compatible_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_x420_telex_compatible);
}



static int
dissect_x420_T_type(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {

  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                            object_identifier_id);


  return offset;
}
static int dissect_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_T_type(FALSE, tvb, offset, pinfo, tree, hf_x420_type);
}



static int
dissect_x420_T_value(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {

  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);


  return offset;
}
static int dissect_value(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_T_value(FALSE, tvb, offset, pinfo, tree, hf_x420_value);
}


static const ber_sequence_t IPMSExtension_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_type },
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_value },
  { 0, 0, 0, NULL }
};

static int
dissect_x420_IPMSExtension(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   IPMSExtension_sequence, hf_index, ett_x420_IPMSExtension);

  return offset;
}
static int dissect_RecipientExtensionsField_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_IPMSExtension(FALSE, tvb, offset, pinfo, tree, hf_x420_RecipientExtensionsField_item);
}
static int dissect_ExtensionsField_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_IPMSExtension(FALSE, tvb, offset, pinfo, tree, hf_x420_ExtensionsField_item);
}
static int dissect_NotificationExtensionsField_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_IPMSExtension(FALSE, tvb, offset, pinfo, tree, hf_x420_NotificationExtensionsField_item);
}
static int dissect_NRNExtensionsField_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_IPMSExtension(FALSE, tvb, offset, pinfo, tree, hf_x420_NRNExtensionsField_item);
}
static int dissect_RNExtensionsField_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_IPMSExtension(FALSE, tvb, offset, pinfo, tree, hf_x420_RNExtensionsField_item);
}
static int dissect_OtherNotificationTypeFields_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_IPMSExtension(FALSE, tvb, offset, pinfo, tree, hf_x420_OtherNotificationTypeFields_item);
}


static const ber_sequence_t RecipientExtensionsField_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_RecipientExtensionsField_item },
};

static int
dissect_x420_RecipientExtensionsField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 RecipientExtensionsField_set_of, hf_index, ett_x420_RecipientExtensionsField);

  return offset;
}
static int dissect_recipient_extensions_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_RecipientExtensionsField(TRUE, tvb, offset, pinfo, tree, hf_x420_recipient_extensions);
}


static const ber_sequence_t RecipientSpecifier_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_recipient_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_notification_requests_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_reply_requested_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_recipient_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x420_RecipientSpecifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              RecipientSpecifier_set, hf_index, ett_x420_RecipientSpecifier);

  return offset;
}



static int
dissect_x420_PrimaryRecipientsSubfield(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x420_RecipientSpecifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_PrimaryRecipientsField_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_PrimaryRecipientsSubfield(FALSE, tvb, offset, pinfo, tree, hf_x420_PrimaryRecipientsField_item);
}


static const ber_sequence_t PrimaryRecipientsField_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_PrimaryRecipientsField_item },
};

static int
dissect_x420_PrimaryRecipientsField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      PrimaryRecipientsField_sequence_of, hf_index, ett_x420_PrimaryRecipientsField);

  return offset;
}
static int dissect_primary_recipients_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_PrimaryRecipientsField(TRUE, tvb, offset, pinfo, tree, hf_x420_primary_recipients);
}



static int
dissect_x420_CopyRecipientsSubfield(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x420_RecipientSpecifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_CopyRecipientsField_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_CopyRecipientsSubfield(FALSE, tvb, offset, pinfo, tree, hf_x420_CopyRecipientsField_item);
}


static const ber_sequence_t CopyRecipientsField_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_CopyRecipientsField_item },
};

static int
dissect_x420_CopyRecipientsField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      CopyRecipientsField_sequence_of, hf_index, ett_x420_CopyRecipientsField);

  return offset;
}
static int dissect_copy_recipients_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_CopyRecipientsField(TRUE, tvb, offset, pinfo, tree, hf_x420_copy_recipients);
}



static int
dissect_x420_BlindCopyRecipientsSubfield(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x420_RecipientSpecifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_BlindCopyRecipientsField_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_BlindCopyRecipientsSubfield(FALSE, tvb, offset, pinfo, tree, hf_x420_BlindCopyRecipientsField_item);
}


static const ber_sequence_t BlindCopyRecipientsField_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_BlindCopyRecipientsField_item },
};

static int
dissect_x420_BlindCopyRecipientsField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      BlindCopyRecipientsField_sequence_of, hf_index, ett_x420_BlindCopyRecipientsField);

  return offset;
}
static int dissect_blind_copy_recipients_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_BlindCopyRecipientsField(TRUE, tvb, offset, pinfo, tree, hf_x420_blind_copy_recipients);
}



static int
dissect_x420_RepliedToIPMField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x420_IPMIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_replied_to_IPM_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_RepliedToIPMField(TRUE, tvb, offset, pinfo, tree, hf_x420_replied_to_IPM);
}



static int
dissect_x420_ObsoletedIPMsSubfield(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x420_IPMIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_ObsoletedIPMsField_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_ObsoletedIPMsSubfield(FALSE, tvb, offset, pinfo, tree, hf_x420_ObsoletedIPMsField_item);
}


static const ber_sequence_t ObsoletedIPMsField_sequence_of[1] = {
  { BER_CLASS_APP, 11, BER_FLAGS_NOOWNTAG, dissect_ObsoletedIPMsField_item },
};

static int
dissect_x420_ObsoletedIPMsField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      ObsoletedIPMsField_sequence_of, hf_index, ett_x420_ObsoletedIPMsField);

  return offset;
}
static int dissect_obsoleted_IPMs_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_ObsoletedIPMsField(TRUE, tvb, offset, pinfo, tree, hf_x420_obsoleted_IPMs);
}



static int
dissect_x420_RelatedIPMsSubfield(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x420_IPMIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_RelatedIPMsField_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_RelatedIPMsSubfield(FALSE, tvb, offset, pinfo, tree, hf_x420_RelatedIPMsField_item);
}


static const ber_sequence_t RelatedIPMsField_sequence_of[1] = {
  { BER_CLASS_APP, 11, BER_FLAGS_NOOWNTAG, dissect_RelatedIPMsField_item },
};

static int
dissect_x420_RelatedIPMsField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      RelatedIPMsField_sequence_of, hf_index, ett_x420_RelatedIPMsField);

  return offset;
}
static int dissect_related_IPMs_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_RelatedIPMsField(TRUE, tvb, offset, pinfo, tree, hf_x420_related_IPMs);
}



static int
dissect_x420_SubjectField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_subject(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_SubjectField(FALSE, tvb, offset, pinfo, tree, hf_x420_subject);
}



static int
dissect_x420_ExpiryTimeField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x420_Time(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_expiry_time_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_ExpiryTimeField(TRUE, tvb, offset, pinfo, tree, hf_x420_expiry_time);
}



static int
dissect_x420_ReplyTimeField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x420_Time(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_reply_time_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_ReplyTimeField(TRUE, tvb, offset, pinfo, tree, hf_x420_reply_time);
}



static int
dissect_x420_ReplyRecipientsSubfield(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x420_ORDescriptor(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_ReplyRecipientsField_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_ReplyRecipientsSubfield(FALSE, tvb, offset, pinfo, tree, hf_x420_ReplyRecipientsField_item);
}


static const ber_sequence_t ReplyRecipientsField_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_ReplyRecipientsField_item },
};

static int
dissect_x420_ReplyRecipientsField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      ReplyRecipientsField_sequence_of, hf_index, ett_x420_ReplyRecipientsField);

  return offset;
}
static int dissect_reply_recipients_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_ReplyRecipientsField(TRUE, tvb, offset, pinfo, tree, hf_x420_reply_recipients);
}


static const value_string x420_ImportanceField_vals[] = {
  {   0, "low" },
  {   1, "normal" },
  {   2, "high" },
  { 0, NULL }
};


static int
dissect_x420_ImportanceField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_importance_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_ImportanceField(TRUE, tvb, offset, pinfo, tree, hf_x420_importance);
}


static const value_string x420_SensitivityField_vals[] = {
  {   1, "personal" },
  {   2, "private" },
  {   3, "company-confidential" },
  { 0, NULL }
};


static int
dissect_x420_SensitivityField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_sensitivity_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_SensitivityField(TRUE, tvb, offset, pinfo, tree, hf_x420_sensitivity);
}



static int
dissect_x420_AutoForwardedField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_auto_forwarded_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_AutoForwardedField(TRUE, tvb, offset, pinfo, tree, hf_x420_auto_forwarded);
}


static const ber_sequence_t ExtensionsField_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ExtensionsField_item },
};

static int
dissect_x420_ExtensionsField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 ExtensionsField_set_of, hf_index, ett_x420_ExtensionsField);

  return offset;
}
static int dissect_extensions_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_ExtensionsField(TRUE, tvb, offset, pinfo, tree, hf_x420_extensions);
}


static const ber_sequence_t Heading_set[] = {
  { BER_CLASS_APP, 11, BER_FLAGS_NOOWNTAG, dissect_this_IPM },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originator_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authorizing_users_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_primary_recipients_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_copy_recipients_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_blind_copy_recipients_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_replied_to_IPM_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_obsoleted_IPMs_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_related_IPMs_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_subject },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_expiry_time_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_reply_time_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_reply_recipients_impl },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_importance_impl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sensitivity_impl },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_auto_forwarded_impl },
  { BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x420_Heading(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              Heading_set, hf_index, ett_x420_Heading);

  return offset;
}
static int dissect_heading(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_Heading(FALSE, tvb, offset, pinfo, tree, hf_x420_heading);
}


static const value_string x420_Repertoire_vals[] = {
  {   2, "ita2" },
  {   5, "ia5" },
  { 0, NULL }
};


static int
dissect_x420_Repertoire(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_repertoire_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_Repertoire(TRUE, tvb, offset, pinfo, tree, hf_x420_repertoire);
}


static const ber_sequence_t IA5TextParameters_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_repertoire_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x420_IA5TextParameters(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              IA5TextParameters_set, hf_index, ett_x420_IA5TextParameters);

  return offset;
}
static int dissect_ia5text_parameters(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_IA5TextParameters(FALSE, tvb, offset, pinfo, tree, hf_x420_ia5text_parameters);
}



static int
dissect_x420_IA5TextData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_ia5text_data(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_IA5TextData(FALSE, tvb, offset, pinfo, tree, hf_x420_ia5text_data);
}


static const ber_sequence_t IA5TextBodyPart_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_ia5text_parameters },
  { BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_ia5text_data },
  { 0, 0, 0, NULL }
};

static int
dissect_x420_IA5TextBodyPart(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   IA5TextBodyPart_sequence, hf_index, ett_x420_IA5TextBodyPart);

  return offset;
}
static int dissect_ia5_text_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_IA5TextBodyPart(TRUE, tvb, offset, pinfo, tree, hf_x420_ia5_text);
}



static int
dissect_x420_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_number_of_pages_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_x420_number_of_pages);
}


static const ber_sequence_t G3FacsimileParameters_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_number_of_pages_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_g3facsimile_non_basic_parameters_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x420_G3FacsimileParameters(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              G3FacsimileParameters_set, hf_index, ett_x420_G3FacsimileParameters);

  return offset;
}
static int dissect_g3facsimile_parameters(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_G3FacsimileParameters(FALSE, tvb, offset, pinfo, tree, hf_x420_g3facsimile_parameters);
}



static int
dissect_x420_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}
static int dissect_G3FacsimileData_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_BIT_STRING(FALSE, tvb, offset, pinfo, tree, hf_x420_G3FacsimileData_item);
}


static const ber_sequence_t G3FacsimileData_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_G3FacsimileData_item },
};

static int
dissect_x420_G3FacsimileData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      G3FacsimileData_sequence_of, hf_index, ett_x420_G3FacsimileData);

  return offset;
}
static int dissect_g3facsimile_data(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_G3FacsimileData(FALSE, tvb, offset, pinfo, tree, hf_x420_g3facsimile_data);
}


static const ber_sequence_t G3FacsimileBodyPart_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_g3facsimile_parameters },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_g3facsimile_data },
  { 0, 0, 0, NULL }
};

static int
dissect_x420_G3FacsimileBodyPart(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   G3FacsimileBodyPart_sequence, hf_index, ett_x420_G3FacsimileBodyPart);

  return offset;
}
static int dissect_g3_facsimile_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_G3FacsimileBodyPart(TRUE, tvb, offset, pinfo, tree, hf_x420_g3_facsimile);
}



static int
dissect_x420_Interchange_Data_Element(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
/* XXX Not implemented yet */


  return offset;
}
static int dissect_G4Class1BodyPart_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_Interchange_Data_Element(FALSE, tvb, offset, pinfo, tree, hf_x420_G4Class1BodyPart_item);
}
static int dissect_MixedModeBodyPart_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_Interchange_Data_Element(FALSE, tvb, offset, pinfo, tree, hf_x420_MixedModeBodyPart_item);
}


static const ber_sequence_t G4Class1BodyPart_sequence_of[1] = {
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_G4Class1BodyPart_item },
};

static int
dissect_x420_G4Class1BodyPart(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      G4Class1BodyPart_sequence_of, hf_index, ett_x420_G4Class1BodyPart);

  return offset;
}
static int dissect_g4_class1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_G4Class1BodyPart(TRUE, tvb, offset, pinfo, tree, hf_x420_g4_class1);
}


static const ber_sequence_t TeletexParameters_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_number_of_pages_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_telex_compatible_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_teletex_non_basic_parameters_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x420_TeletexParameters(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              TeletexParameters_set, hf_index, ett_x420_TeletexParameters);

  return offset;
}
static int dissect_teletex_parameters(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_TeletexParameters(FALSE, tvb, offset, pinfo, tree, hf_x420_teletex_parameters);
}



static int
dissect_x420_TeletexString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_TeletexData_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_TeletexString(FALSE, tvb, offset, pinfo, tree, hf_x420_TeletexData_item);
}


static const ber_sequence_t TeletexData_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_TeletexString, BER_FLAGS_NOOWNTAG, dissect_TeletexData_item },
};

static int
dissect_x420_TeletexData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      TeletexData_sequence_of, hf_index, ett_x420_TeletexData);

  return offset;
}
static int dissect_teletex_data(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_TeletexData(FALSE, tvb, offset, pinfo, tree, hf_x420_teletex_data);
}


static const ber_sequence_t TeletexBodyPart_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_teletex_parameters },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_teletex_data },
  { 0, 0, 0, NULL }
};

static int
dissect_x420_TeletexBodyPart(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   TeletexBodyPart_sequence, hf_index, ett_x420_TeletexBodyPart);

  return offset;
}
static int dissect_teletex_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_TeletexBodyPart(TRUE, tvb, offset, pinfo, tree, hf_x420_teletex);
}


static const value_string x420_VideotexSyntax_vals[] = {
  {   0, "ids" },
  {   1, "data-syntax1" },
  {   2, "data-syntax2" },
  {   3, "data-syntax3" },
  { 0, NULL }
};


static int
dissect_x420_VideotexSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_syntax_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_VideotexSyntax(TRUE, tvb, offset, pinfo, tree, hf_x420_syntax);
}


static const ber_sequence_t VideotexParameters_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_syntax_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x420_VideotexParameters(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              VideotexParameters_set, hf_index, ett_x420_VideotexParameters);

  return offset;
}
static int dissect_videotex_parameters(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_VideotexParameters(FALSE, tvb, offset, pinfo, tree, hf_x420_videotex_parameters);
}



static int
dissect_x420_VideotexData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VideotexString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_videotex_data(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_VideotexData(FALSE, tvb, offset, pinfo, tree, hf_x420_videotex_data);
}


static const ber_sequence_t VideotexBodyPart_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_videotex_parameters },
  { BER_CLASS_UNI, BER_UNI_TAG_VideotexString, BER_FLAGS_NOOWNTAG, dissect_videotex_data },
  { 0, 0, 0, NULL }
};

static int
dissect_x420_VideotexBodyPart(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   VideotexBodyPart_sequence, hf_index, ett_x420_VideotexBodyPart);

  return offset;
}
static int dissect_videotex_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_VideotexBodyPart(TRUE, tvb, offset, pinfo, tree, hf_x420_videotex);
}


static const ber_sequence_t EncryptedParameters_set[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithm_identifier },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_originator_certificates },
  { 0, 0, 0, NULL }
};

static int
dissect_x420_EncryptedParameters(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              EncryptedParameters_set, hf_index, ett_x420_EncryptedParameters);

  return offset;
}
static int dissect_encrypted_parameters(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_EncryptedParameters(FALSE, tvb, offset, pinfo, tree, hf_x420_encrypted_parameters);
}



static int
dissect_x420_EncryptedData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}
static int dissect_encrypted_data(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_EncryptedData(FALSE, tvb, offset, pinfo, tree, hf_x420_encrypted_data);
}


static const ber_sequence_t EncryptedBodyPart_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_encrypted_parameters },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted_data },
  { 0, 0, 0, NULL }
};

static int
dissect_x420_EncryptedBodyPart(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EncryptedBodyPart_sequence, hf_index, ett_x420_EncryptedBodyPart);

  return offset;
}
static int dissect_encrypted_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_EncryptedBodyPart(TRUE, tvb, offset, pinfo, tree, hf_x420_encrypted);
}


static const ber_sequence_t MessageParameters_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_delivery_time_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_delivery_envelope_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x420_MessageParameters(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              MessageParameters_set, hf_index, ett_x420_MessageParameters);

  return offset;
}
static int dissect_message_parameters(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_MessageParameters(FALSE, tvb, offset, pinfo, tree, hf_x420_message_parameters);
}



static int
dissect_x420_MessageData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x420_IPM(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_message_data(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_MessageData(FALSE, tvb, offset, pinfo, tree, hf_x420_message_data);
}


static const ber_sequence_t MessageBodyPart_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_message_parameters },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_message_data },
  { 0, 0, 0, NULL }
};

static int
dissect_x420_MessageBodyPart(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MessageBodyPart_sequence, hf_index, ett_x420_MessageBodyPart);

  return offset;
}
static int dissect_message_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_MessageBodyPart(TRUE, tvb, offset, pinfo, tree, hf_x420_message);
}


static const ber_sequence_t MixedModeBodyPart_sequence_of[1] = {
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_MixedModeBodyPart_item },
};

static int
dissect_x420_MixedModeBodyPart(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      MixedModeBodyPart_sequence_of, hf_index, ett_x420_MixedModeBodyPart);

  return offset;
}
static int dissect_mixed_mode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_MixedModeBodyPart(TRUE, tvb, offset, pinfo, tree, hf_x420_mixed_mode);
}



static int
dissect_x420_BilaterallyDefinedBodyPart(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_bilaterally_defined_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_BilaterallyDefinedBodyPart(TRUE, tvb, offset, pinfo, tree, hf_x420_bilaterally_defined);
}



static int
dissect_x420_NationallyDefinedBodyPart(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
/* XXX Not implemented yet */


  return offset;
}
static int dissect_nationally_defined_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_NationallyDefinedBodyPart(TRUE, tvb, offset, pinfo, tree, hf_x420_nationally_defined);
}


static const ber_sequence_t ExtendedBodyPart_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_extended_parameters_impl },
  { BER_CLASS_UNI, 8, BER_FLAGS_NOOWNTAG, dissect_extended_data },
  { 0, 0, 0, NULL }
};

static int
dissect_x420_ExtendedBodyPart(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ExtendedBodyPart_sequence, hf_index, ett_x420_ExtendedBodyPart);

  return offset;
}
static int dissect_extended_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_ExtendedBodyPart(TRUE, tvb, offset, pinfo, tree, hf_x420_extended);
}


static const value_string x420_BodyPart_vals[] = {
  {   0, "ia5-text" },
  {   3, "g3-facsimile" },
  {   4, "g4-class1" },
  {   5, "teletex" },
  {   6, "videotex" },
  {   8, "encrypted" },
  {   9, "message" },
  {  11, "mixed-mode" },
  {  14, "bilaterally-defined" },
  {   7, "nationally-defined" },
  {  15, "extended" },
  { 0, NULL }
};

static const ber_choice_t BodyPart_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_ia5_text_impl },
  {   3, BER_CLASS_CON, 3, 0, dissect_g3_facsimile_impl },
  {   4, BER_CLASS_CON, 4, 0, dissect_g4_class1_impl },
  {   5, BER_CLASS_CON, 5, 0, dissect_teletex_impl },
  {   6, BER_CLASS_CON, 6, 0, dissect_videotex_impl },
  {   8, BER_CLASS_CON, 8, 0, dissect_encrypted_impl },
  {   9, BER_CLASS_CON, 9, 0, dissect_message_impl },
  {  11, BER_CLASS_CON, 11, 0, dissect_mixed_mode_impl },
  {  14, BER_CLASS_CON, 14, 0, dissect_bilaterally_defined_impl },
  {   7, BER_CLASS_CON, 7, 0, dissect_nationally_defined_impl },
  {  15, BER_CLASS_CON, 15, 0, dissect_extended_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x420_BodyPart(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 BodyPart_choice, hf_index, ett_x420_BodyPart,
                                 NULL);

  return offset;
}
static int dissect_Body_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_BodyPart(FALSE, tvb, offset, pinfo, tree, hf_x420_Body_item);
}
static int dissect_advice(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_BodyPart(FALSE, tvb, offset, pinfo, tree, hf_x420_advice);
}


static const ber_sequence_t Body_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_Body_item },
};

static int
dissect_x420_Body(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      Body_sequence_of, hf_index, ett_x420_Body);

  return offset;
}
static int dissect_body(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_Body(FALSE, tvb, offset, pinfo, tree, hf_x420_body);
}


static const ber_sequence_t IPM_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_heading },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_body },
  { 0, 0, 0, NULL }
};

static int
dissect_x420_IPM(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   IPM_sequence, hf_index, ett_x420_IPM);

  return offset;
}



static int
dissect_x420_SubjectIPMField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x420_IPMIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_subject_ipm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_SubjectIPMField(FALSE, tvb, offset, pinfo, tree, hf_x420_subject_ipm);
}



static int
dissect_x420_IPNOriginatorField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x420_ORDescriptor(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_ipn_originator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_IPNOriginatorField(TRUE, tvb, offset, pinfo, tree, hf_x420_ipn_originator);
}



static int
dissect_x420_IPMIntendedRecipientField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x420_ORDescriptor(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_ipm_intended_recipient_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_IPMIntendedRecipientField(TRUE, tvb, offset, pinfo, tree, hf_x420_ipm_intended_recipient);
}



static int
dissect_x420_ConversionEITsField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_EncodedInformationTypes(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_conversion_eits(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_ConversionEITsField(FALSE, tvb, offset, pinfo, tree, hf_x420_conversion_eits);
}


static const ber_sequence_t NotificationExtensionsField_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_NotificationExtensionsField_item },
};

static int
dissect_x420_NotificationExtensionsField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 NotificationExtensionsField_set_of, hf_index, ett_x420_NotificationExtensionsField);

  return offset;
}
static int dissect_notification_extensions_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_NotificationExtensionsField(TRUE, tvb, offset, pinfo, tree, hf_x420_notification_extensions);
}


static const value_string x420_NonReceiptReasonField_vals[] = {
  {   0, "ipm-discarded" },
  {   1, "ipm-auto-forwarded" },
  { 0, NULL }
};


static int
dissect_x420_NonReceiptReasonField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_non_receipt_reason_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_NonReceiptReasonField(TRUE, tvb, offset, pinfo, tree, hf_x420_non_receipt_reason);
}


static const value_string x420_DiscardReasonField_vals[] = {
  {   0, "ipm-expired" },
  {   1, "ipm-obsoleted" },
  {   2, "user-subscription-terminated" },
  {   3, "not-used" },
  { 0, NULL }
};


static int
dissect_x420_DiscardReasonField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_discard_reason_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_DiscardReasonField(TRUE, tvb, offset, pinfo, tree, hf_x420_discard_reason);
}



static int
dissect_x420_AutoForwardComment(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x420_AutoForwardCommentField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x420_AutoForwardComment(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_auto_forward_comment_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_AutoForwardCommentField(TRUE, tvb, offset, pinfo, tree, hf_x420_auto_forward_comment);
}



static int
dissect_x420_ReturnedIPMField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x420_IPM(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_returned_ipm_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_ReturnedIPMField(TRUE, tvb, offset, pinfo, tree, hf_x420_returned_ipm);
}


static const ber_sequence_t NRNExtensionsField_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_NRNExtensionsField_item },
};

static int
dissect_x420_NRNExtensionsField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 NRNExtensionsField_set_of, hf_index, ett_x420_NRNExtensionsField);

  return offset;
}
static int dissect_nrn_extensions_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_NRNExtensionsField(TRUE, tvb, offset, pinfo, tree, hf_x420_nrn_extensions);
}


static const ber_sequence_t NonReceiptFields_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_non_receipt_reason_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_discard_reason_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_auto_forward_comment_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_returned_ipm_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nrn_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x420_NonReceiptFields(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              NonReceiptFields_set, hf_index, ett_x420_NonReceiptFields);

  return offset;
}
static int dissect_non_receipt_fields_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_NonReceiptFields(TRUE, tvb, offset, pinfo, tree, hf_x420_non_receipt_fields);
}



static int
dissect_x420_ReceiptTimeField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x420_Time(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_receipt_time_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_ReceiptTimeField(TRUE, tvb, offset, pinfo, tree, hf_x420_receipt_time);
}


static const value_string x420_AcknowledgmentModeField_vals[] = {
  {   0, "manual" },
  {   1, "automatic" },
  { 0, NULL }
};


static int
dissect_x420_AcknowledgmentModeField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_acknowledgment_mode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_AcknowledgmentModeField(TRUE, tvb, offset, pinfo, tree, hf_x420_acknowledgment_mode);
}



static int
dissect_x420_SupplReceiptInfoField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_SupplementaryInformation(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_suppl_receipt_info_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_SupplReceiptInfoField(TRUE, tvb, offset, pinfo, tree, hf_x420_suppl_receipt_info);
}


static const ber_sequence_t RNExtensionsField_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_RNExtensionsField_item },
};

static int
dissect_x420_RNExtensionsField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 RNExtensionsField_set_of, hf_index, ett_x420_RNExtensionsField);

  return offset;
}
static int dissect_rn_extensions_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_RNExtensionsField(TRUE, tvb, offset, pinfo, tree, hf_x420_rn_extensions);
}


static const ber_sequence_t ReceiptFields_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_receipt_time_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acknowledgment_mode_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_suppl_receipt_info_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rn_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x420_ReceiptFields(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ReceiptFields_set, hf_index, ett_x420_ReceiptFields);

  return offset;
}
static int dissect_receipt_fields_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_ReceiptFields(TRUE, tvb, offset, pinfo, tree, hf_x420_receipt_fields);
}


static const ber_sequence_t OtherNotificationTypeFields_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_OtherNotificationTypeFields_item },
};

static int
dissect_x420_OtherNotificationTypeFields(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 OtherNotificationTypeFields_set_of, hf_index, ett_x420_OtherNotificationTypeFields);

  return offset;
}
static int dissect_other_notification_type_fields_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_OtherNotificationTypeFields(TRUE, tvb, offset, pinfo, tree, hf_x420_other_notification_type_fields);
}


static const value_string x420_T_choice_vals[] = {
  {   0, "non-receipt-fields" },
  {   1, "receipt-fields" },
  {   2, "other-notification-type-fields" },
  { 0, NULL }
};

static const ber_choice_t T_choice_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_non_receipt_fields_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_receipt_fields_impl },
  {   2, BER_CLASS_CON, 2, 0, dissect_other_notification_type_fields_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x420_T_choice(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_choice_choice, hf_index, ett_x420_T_choice,
                                 NULL);

  return offset;
}
static int dissect_choice_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_T_choice(TRUE, tvb, offset, pinfo, tree, hf_x420_choice);
}


static const ber_sequence_t IPN_set[] = {
  { BER_CLASS_APP, 11, BER_FLAGS_NOOWNTAG, dissect_subject_ipm },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ipn_originator_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ipm_intended_recipient_impl },
  { BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_conversion_eits },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_notification_extensions_impl },
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_choice_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x420_IPN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              IPN_set, hf_index, ett_x420_IPN);

  return offset;
}
static int dissect_ipn_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_IPN(TRUE, tvb, offset, pinfo, tree, hf_x420_ipn);
}


static const value_string x420_InformationObject_vals[] = {
  {   0, "ipm" },
  {   1, "ipn" },
  { 0, NULL }
};

static const ber_choice_t InformationObject_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_ipm_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_ipn_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x420_InformationObject(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 InformationObject_choice, hf_index, ett_x420_InformationObject,
                                 NULL);

  return offset;
}


static const ber_sequence_t CommonFields_set[] = {
  { BER_CLASS_APP, 11, BER_FLAGS_NOOWNTAG, dissect_subject_ipm },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ipn_originator_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ipm_intended_recipient_impl },
  { BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_conversion_eits },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_notification_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x420_CommonFields(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              CommonFields_set, hf_index, ett_x420_CommonFields);

  return offset;
}


static const ber_sequence_t AbsenceAdvice_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_advice },
  { BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_next_available },
  { 0, 0, 0, NULL }
};

static int
dissect_x420_AbsenceAdvice(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AbsenceAdvice_sequence, hf_index, ett_x420_AbsenceAdvice);

  return offset;
}


static const ber_sequence_t ChangeOfAddressAdvice_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_new_address_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_effective_from_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x420_ChangeOfAddressAdvice(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ChangeOfAddressAdvice_sequence, hf_index, ett_x420_ChangeOfAddressAdvice);

  return offset;
}



static int
dissect_x420_SequenceNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_stored_entry_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_SequenceNumber(TRUE, tvb, offset, pinfo, tree, hf_x420_stored_entry);
}
static int dissect_stored_content_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_SequenceNumber(TRUE, tvb, offset, pinfo, tree, hf_x420_stored_content);
}
static int dissect_message_entry(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_SequenceNumber(FALSE, tvb, offset, pinfo, tree, hf_x420_message_entry);
}



static int
dissect_x420_INTEGER_1_MAX(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_submitted_body_part_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_INTEGER_1_MAX(TRUE, tvb, offset, pinfo, tree, hf_x420_submitted_body_part);
}
static int dissect_body_part_number(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_INTEGER_1_MAX(FALSE, tvb, offset, pinfo, tree, hf_x420_body_part_number);
}


static const ber_sequence_t T_stored_body_part_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_message_entry },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_body_part_number },
  { 0, 0, 0, NULL }
};

static int
dissect_x420_T_stored_body_part(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_stored_body_part_sequence, hf_index, ett_x420_T_stored_body_part);

  return offset;
}
static int dissect_stored_body_part_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_T_stored_body_part(TRUE, tvb, offset, pinfo, tree, hf_x420_stored_body_part);
}


static const value_string x420_BodyPartReference_vals[] = {
  {   0, "stored-entry" },
  {   1, "stored-content" },
  {   2, "submitted-body-part" },
  {   3, "stored-body-part" },
  { 0, NULL }
};

static const ber_choice_t BodyPartReference_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_stored_entry_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_stored_content_impl },
  {   2, BER_CLASS_CON, 2, 0, dissect_submitted_body_part_impl },
  {   3, BER_CLASS_CON, 3, 0, dissect_stored_body_part_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x420_BodyPartReference(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 BodyPartReference_choice, hf_index, ett_x420_BodyPartReference,
                                 NULL);

  return offset;
}
static int dissect_BodyPartReferences_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_BodyPartReference(FALSE, tvb, offset, pinfo, tree, hf_x420_BodyPartReferences_item);
}


static const ber_sequence_t BodyPartReferences_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_BodyPartReferences_item },
};

static int
dissect_x420_BodyPartReferences(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      BodyPartReferences_sequence_of, hf_index, ett_x420_BodyPartReferences);

  return offset;
}
static int dissect_assembly_instructions_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_BodyPartReferences(TRUE, tvb, offset, pinfo, tree, hf_x420_assembly_instructions);
}


static const ber_sequence_t IPMAssemblyInstructions_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_assembly_instructions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x420_IPMAssemblyInstructions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              IPMAssemblyInstructions_set, hf_index, ett_x420_IPMAssemblyInstructions);

  return offset;
}



static int
dissect_x420_OriginatingUA(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}

/*--- PDUs ---*/

static void dissect_OriginatingUA_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x420_OriginatingUA(FALSE, tvb, 0, pinfo, tree, hf_x420_OriginatingUA_PDU);
}


/*--- End of included file: packet-x420-fn.c ---*/


/*
* Dissect X420 PDUs inside a PPDU.
*/
static void
dissect_x420(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int (*x420_dissector)(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) = NULL;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_x420, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_x420);
	}
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "X420");
	if (check_col(pinfo->cinfo, COL_INFO))
	  col_add_str(pinfo->cinfo, COL_INFO, "Interpersonal Message");

	dissect_x420_InformationObject(TRUE, tvb, offset, pinfo , tree, -1);
}


/*--- proto_register_x420 -------------------------------------------*/
void proto_register_x420(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {

/*--- Included file: packet-x420-hfarr.c ---*/

    { &hf_x420_OriginatingUA_PDU,
      { "OriginatingUA", "x420.OriginatingUA",
        FT_STRING, BASE_NONE, NULL, 0,
        "OriginatingUA", HFILL }},
    { &hf_x420_ipm,
      { "ipm", "x420.ipm",
        FT_NONE, BASE_NONE, NULL, 0,
        "InformationObject/ipm", HFILL }},
    { &hf_x420_ipn,
      { "ipn", "x420.ipn",
        FT_NONE, BASE_NONE, NULL, 0,
        "InformationObject/ipn", HFILL }},
    { &hf_x420_heading,
      { "heading", "x420.heading",
        FT_NONE, BASE_NONE, NULL, 0,
        "IPM/heading", HFILL }},
    { &hf_x420_body,
      { "body", "x420.body",
        FT_UINT32, BASE_DEC, NULL, 0,
        "IPM/body", HFILL }},
    { &hf_x420_type,
      { "type", "x420.type",
        FT_STRING, BASE_NONE, NULL, 0,
        "IPMSExtension/type", HFILL }},
    { &hf_x420_value,
      { "value", "x420.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "IPMSExtension/value", HFILL }},
    { &hf_x420_this_IPM,
      { "this-IPM", "x420.this_IPM",
        FT_NONE, BASE_NONE, NULL, 0,
        "Heading/this-IPM", HFILL }},
    { &hf_x420_originator,
      { "originator", "x420.originator",
        FT_NONE, BASE_NONE, NULL, 0,
        "Heading/originator", HFILL }},
    { &hf_x420_authorizing_users,
      { "authorizing-users", "x420.authorizing_users",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Heading/authorizing-users", HFILL }},
    { &hf_x420_primary_recipients,
      { "primary-recipients", "x420.primary_recipients",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Heading/primary-recipients", HFILL }},
    { &hf_x420_copy_recipients,
      { "copy-recipients", "x420.copy_recipients",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Heading/copy-recipients", HFILL }},
    { &hf_x420_blind_copy_recipients,
      { "blind-copy-recipients", "x420.blind_copy_recipients",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Heading/blind-copy-recipients", HFILL }},
    { &hf_x420_replied_to_IPM,
      { "replied-to-IPM", "x420.replied_to_IPM",
        FT_NONE, BASE_NONE, NULL, 0,
        "Heading/replied-to-IPM", HFILL }},
    { &hf_x420_obsoleted_IPMs,
      { "obsoleted-IPMs", "x420.obsoleted_IPMs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Heading/obsoleted-IPMs", HFILL }},
    { &hf_x420_related_IPMs,
      { "related-IPMs", "x420.related_IPMs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Heading/related-IPMs", HFILL }},
    { &hf_x420_subject,
      { "subject", "x420.subject",
        FT_STRING, BASE_NONE, NULL, 0,
        "Heading/subject", HFILL }},
    { &hf_x420_expiry_time,
      { "expiry-time", "x420.expiry_time",
        FT_UINT32, BASE_DEC, VALS(x509af_Time_vals), 0,
        "Heading/expiry-time", HFILL }},
    { &hf_x420_reply_time,
      { "reply-time", "x420.reply_time",
        FT_UINT32, BASE_DEC, VALS(x509af_Time_vals), 0,
        "Heading/reply-time", HFILL }},
    { &hf_x420_reply_recipients,
      { "reply-recipients", "x420.reply_recipients",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Heading/reply-recipients", HFILL }},
    { &hf_x420_importance,
      { "importance", "x420.importance",
        FT_UINT32, BASE_DEC, VALS(x420_ImportanceField_vals), 0,
        "Heading/importance", HFILL }},
    { &hf_x420_sensitivity,
      { "sensitivity", "x420.sensitivity",
        FT_UINT32, BASE_DEC, VALS(x420_SensitivityField_vals), 0,
        "Heading/sensitivity", HFILL }},
    { &hf_x420_auto_forwarded,
      { "auto-forwarded", "x420.auto_forwarded",
        FT_BOOLEAN, 8, NULL, 0,
        "Heading/auto-forwarded", HFILL }},
    { &hf_x420_extensions,
      { "extensions", "x420.extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Heading/extensions", HFILL }},
    { &hf_x420_user,
      { "user", "x420.user",
        FT_NONE, BASE_NONE, NULL, 0,
        "IPMIdentifier/user", HFILL }},
    { &hf_x420_user_relative_identifier,
      { "user-relative-identifier", "x420.user_relative_identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "IPMIdentifier/user-relative-identifier", HFILL }},
    { &hf_x420_recipient,
      { "recipient", "x420.recipient",
        FT_NONE, BASE_NONE, NULL, 0,
        "RecipientSpecifier/recipient", HFILL }},
    { &hf_x420_notification_requests,
      { "notification-requests", "x420.notification_requests",
        FT_BYTES, BASE_HEX, NULL, 0,
        "RecipientSpecifier/notification-requests", HFILL }},
    { &hf_x420_reply_requested,
      { "reply-requested", "x420.reply_requested",
        FT_BOOLEAN, 8, NULL, 0,
        "RecipientSpecifier/reply-requested", HFILL }},
    { &hf_x420_recipient_extensions,
      { "recipient-extensions", "x420.recipient_extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RecipientSpecifier/recipient-extensions", HFILL }},
    { &hf_x420_formal_name,
      { "formal-name", "x420.formal_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "ORDescriptor/formal-name", HFILL }},
    { &hf_x420_free_form_name,
      { "free-form-name", "x420.free_form_name",
        FT_STRING, BASE_NONE, NULL, 0,
        "ORDescriptor/free-form-name", HFILL }},
    { &hf_x420_telephone_number,
      { "telephone-number", "x420.telephone_number",
        FT_STRING, BASE_NONE, NULL, 0,
        "ORDescriptor/telephone-number", HFILL }},
    { &hf_x420_RecipientExtensionsField_item,
      { "Item", "x420.RecipientExtensionsField_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RecipientExtensionsField/_item", HFILL }},
    { &hf_x420_AuthorizingUsersField_item,
      { "Item", "x420.AuthorizingUsersField_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "AuthorizingUsersField/_item", HFILL }},
    { &hf_x420_PrimaryRecipientsField_item,
      { "Item", "x420.PrimaryRecipientsField_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrimaryRecipientsField/_item", HFILL }},
    { &hf_x420_CopyRecipientsField_item,
      { "Item", "x420.CopyRecipientsField_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CopyRecipientsField/_item", HFILL }},
    { &hf_x420_BlindCopyRecipientsField_item,
      { "Item", "x420.BlindCopyRecipientsField_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "BlindCopyRecipientsField/_item", HFILL }},
    { &hf_x420_ObsoletedIPMsField_item,
      { "Item", "x420.ObsoletedIPMsField_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ObsoletedIPMsField/_item", HFILL }},
    { &hf_x420_RelatedIPMsField_item,
      { "Item", "x420.RelatedIPMsField_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RelatedIPMsField/_item", HFILL }},
    { &hf_x420_ReplyRecipientsField_item,
      { "Item", "x420.ReplyRecipientsField_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReplyRecipientsField/_item", HFILL }},
    { &hf_x420_ExtensionsField_item,
      { "Item", "x420.ExtensionsField_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExtensionsField/_item", HFILL }},
    { &hf_x420_Body_item,
      { "Item", "x420.Body_item",
        FT_UINT32, BASE_DEC, VALS(x420_BodyPart_vals), 0,
        "Body/_item", HFILL }},
    { &hf_x420_ia5_text,
      { "ia5-text", "x420.ia5_text",
        FT_NONE, BASE_NONE, NULL, 0,
        "BodyPart/ia5-text", HFILL }},
    { &hf_x420_g3_facsimile,
      { "g3-facsimile", "x420.g3_facsimile",
        FT_NONE, BASE_NONE, NULL, 0,
        "BodyPart/g3-facsimile", HFILL }},
    { &hf_x420_g4_class1,
      { "g4-class1", "x420.g4_class1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BodyPart/g4-class1", HFILL }},
    { &hf_x420_teletex,
      { "teletex", "x420.teletex",
        FT_NONE, BASE_NONE, NULL, 0,
        "BodyPart/teletex", HFILL }},
    { &hf_x420_videotex,
      { "videotex", "x420.videotex",
        FT_NONE, BASE_NONE, NULL, 0,
        "BodyPart/videotex", HFILL }},
    { &hf_x420_encrypted,
      { "encrypted", "x420.encrypted",
        FT_NONE, BASE_NONE, NULL, 0,
        "BodyPart/encrypted", HFILL }},
    { &hf_x420_message,
      { "message", "x420.message",
        FT_NONE, BASE_NONE, NULL, 0,
        "BodyPart/message", HFILL }},
    { &hf_x420_mixed_mode,
      { "mixed-mode", "x420.mixed_mode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BodyPart/mixed-mode", HFILL }},
    { &hf_x420_bilaterally_defined,
      { "bilaterally-defined", "x420.bilaterally_defined",
        FT_BYTES, BASE_HEX, NULL, 0,
        "BodyPart/bilaterally-defined", HFILL }},
    { &hf_x420_nationally_defined,
      { "nationally-defined", "x420.nationally_defined",
        FT_NONE, BASE_NONE, NULL, 0,
        "BodyPart/nationally-defined", HFILL }},
    { &hf_x420_extended,
      { "extended", "x420.extended",
        FT_NONE, BASE_NONE, NULL, 0,
        "BodyPart/extended", HFILL }},
    { &hf_x420_extended_parameters,
      { "parameters", "x420.parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExtendedBodyPart/parameters", HFILL }},
    { &hf_x420_extended_data,
      { "data", "x420.data",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExtendedBodyPart/data", HFILL }},
    { &hf_x420_ia5text_parameters,
      { "parameters", "x420.parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "IA5TextBodyPart/parameters", HFILL }},
    { &hf_x420_ia5text_data,
      { "data", "x420.data",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5TextBodyPart/data", HFILL }},
    { &hf_x420_repertoire,
      { "repertoire", "x420.repertoire",
        FT_UINT32, BASE_DEC, VALS(x420_Repertoire_vals), 0,
        "IA5TextParameters/repertoire", HFILL }},
    { &hf_x420_g3facsimile_parameters,
      { "parameters", "x420.parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "G3FacsimileBodyPart/parameters", HFILL }},
    { &hf_x420_g3facsimile_data,
      { "data", "x420.data",
        FT_UINT32, BASE_DEC, NULL, 0,
        "G3FacsimileBodyPart/data", HFILL }},
    { &hf_x420_number_of_pages,
      { "number-of-pages", "x420.number_of_pages",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x420_g3facsimile_non_basic_parameters,
      { "non-basic-parameters", "x420.non_basic_parameters",
        FT_BYTES, BASE_HEX, NULL, 0,
        "G3FacsimileParameters/non-basic-parameters", HFILL }},
    { &hf_x420_G3FacsimileData_item,
      { "Item", "x420.G3FacsimileData_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "G3FacsimileData/_item", HFILL }},
    { &hf_x420_G4Class1BodyPart_item,
      { "Item", "x420.G4Class1BodyPart_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "G4Class1BodyPart/_item", HFILL }},
    { &hf_x420_MixedModeBodyPart_item,
      { "Item", "x420.MixedModeBodyPart_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "MixedModeBodyPart/_item", HFILL }},
    { &hf_x420_teletex_parameters,
      { "parameters", "x420.parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "TeletexBodyPart/parameters", HFILL }},
    { &hf_x420_teletex_data,
      { "data", "x420.data",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TeletexBodyPart/data", HFILL }},
    { &hf_x420_telex_compatible,
      { "telex-compatible", "x420.telex_compatible",
        FT_BOOLEAN, 8, NULL, 0,
        "TeletexParameters/telex-compatible", HFILL }},
    { &hf_x420_teletex_non_basic_parameters,
      { "non-basic-parameters", "x420.non_basic_parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "TeletexParameters/non-basic-parameters", HFILL }},
    { &hf_x420_TeletexData_item,
      { "Item", "x420.TeletexData_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "TeletexData/_item", HFILL }},
    { &hf_x420_videotex_parameters,
      { "parameters", "x420.parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "VideotexBodyPart/parameters", HFILL }},
    { &hf_x420_videotex_data,
      { "data", "x420.data",
        FT_STRING, BASE_NONE, NULL, 0,
        "VideotexBodyPart/data", HFILL }},
    { &hf_x420_syntax,
      { "syntax", "x420.syntax",
        FT_INT32, BASE_DEC, VALS(x420_VideotexSyntax_vals), 0,
        "VideotexParameters/syntax", HFILL }},
    { &hf_x420_encrypted_parameters,
      { "parameters", "x420.parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptedBodyPart/parameters", HFILL }},
    { &hf_x420_encrypted_data,
      { "data", "x420.data",
        FT_BYTES, BASE_HEX, NULL, 0,
        "EncryptedBodyPart/data", HFILL }},
    { &hf_x420_algorithm_identifier,
      { "algorithm-identifier", "x420.algorithm_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptedParameters/algorithm-identifier", HFILL }},
    { &hf_x420_originator_certificates,
      { "originator-certificates", "x420.originator_certificates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EncryptedParameters/originator-certificates", HFILL }},
    { &hf_x420_message_parameters,
      { "parameters", "x420.parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageBodyPart/parameters", HFILL }},
    { &hf_x420_message_data,
      { "data", "x420.data",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageBodyPart/data", HFILL }},
    { &hf_x420_delivery_time,
      { "delivery-time", "x420.delivery_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "MessageParameters/delivery-time", HFILL }},
    { &hf_x420_delivery_envelope,
      { "delivery-envelope", "x420.delivery_envelope",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageParameters/delivery-envelope", HFILL }},
    { &hf_x420_subject_ipm,
      { "subject-ipm", "x420.subject_ipm",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x420_ipn_originator,
      { "ipn-originator", "x420.ipn_originator",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x420_ipm_intended_recipient,
      { "ipm-intended-recipient", "x420.ipm_intended_recipient",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x420_conversion_eits,
      { "conversion-eits", "x420.conversion_eits",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x420_notification_extensions,
      { "notification-extensions", "x420.notification_extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x420_choice,
      { "choice", "x420.choice",
        FT_UINT32, BASE_DEC, VALS(x420_T_choice_vals), 0,
        "IPN/choice", HFILL }},
    { &hf_x420_non_receipt_fields,
      { "non-receipt-fields", "x420.non_receipt_fields",
        FT_NONE, BASE_NONE, NULL, 0,
        "IPN/choice/non-receipt-fields", HFILL }},
    { &hf_x420_receipt_fields,
      { "receipt-fields", "x420.receipt_fields",
        FT_NONE, BASE_NONE, NULL, 0,
        "IPN/choice/receipt-fields", HFILL }},
    { &hf_x420_other_notification_type_fields,
      { "other-notification-type-fields", "x420.other_notification_type_fields",
        FT_UINT32, BASE_DEC, NULL, 0,
        "IPN/choice/other-notification-type-fields", HFILL }},
    { &hf_x420_non_receipt_reason,
      { "non-receipt-reason", "x420.non_receipt_reason",
        FT_UINT32, BASE_DEC, VALS(x420_NonReceiptReasonField_vals), 0,
        "NonReceiptFields/non-receipt-reason", HFILL }},
    { &hf_x420_discard_reason,
      { "discard-reason", "x420.discard_reason",
        FT_UINT32, BASE_DEC, VALS(x420_DiscardReasonField_vals), 0,
        "NonReceiptFields/discard-reason", HFILL }},
    { &hf_x420_auto_forward_comment,
      { "auto-forward-comment", "x420.auto_forward_comment",
        FT_STRING, BASE_NONE, NULL, 0,
        "NonReceiptFields/auto-forward-comment", HFILL }},
    { &hf_x420_returned_ipm,
      { "returned-ipm", "x420.returned_ipm",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonReceiptFields/returned-ipm", HFILL }},
    { &hf_x420_nrn_extensions,
      { "nrn-extensions", "x420.nrn_extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NonReceiptFields/nrn-extensions", HFILL }},
    { &hf_x420_receipt_time,
      { "receipt-time", "x420.receipt_time",
        FT_UINT32, BASE_DEC, VALS(x509af_Time_vals), 0,
        "ReceiptFields/receipt-time", HFILL }},
    { &hf_x420_acknowledgment_mode,
      { "acknowledgment-mode", "x420.acknowledgment_mode",
        FT_UINT32, BASE_DEC, VALS(x420_AcknowledgmentModeField_vals), 0,
        "ReceiptFields/acknowledgment-mode", HFILL }},
    { &hf_x420_suppl_receipt_info,
      { "suppl-receipt-info", "x420.suppl_receipt_info",
        FT_STRING, BASE_NONE, NULL, 0,
        "ReceiptFields/suppl-receipt-info", HFILL }},
    { &hf_x420_rn_extensions,
      { "rn-extensions", "x420.rn_extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ReceiptFields/rn-extensions", HFILL }},
    { &hf_x420_NotificationExtensionsField_item,
      { "Item", "x420.NotificationExtensionsField_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "NotificationExtensionsField/_item", HFILL }},
    { &hf_x420_NRNExtensionsField_item,
      { "Item", "x420.NRNExtensionsField_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "NRNExtensionsField/_item", HFILL }},
    { &hf_x420_RNExtensionsField_item,
      { "Item", "x420.RNExtensionsField_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RNExtensionsField/_item", HFILL }},
    { &hf_x420_OtherNotificationTypeFields_item,
      { "Item", "x420.OtherNotificationTypeFields_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "OtherNotificationTypeFields/_item", HFILL }},
    { &hf_x420_advice,
      { "advice", "x420.advice",
        FT_UINT32, BASE_DEC, VALS(x420_BodyPart_vals), 0,
        "AbsenceAdvice/advice", HFILL }},
    { &hf_x420_next_available,
      { "next-available", "x420.next_available",
        FT_UINT32, BASE_DEC, VALS(x509af_Time_vals), 0,
        "AbsenceAdvice/next-available", HFILL }},
    { &hf_x420_new_address,
      { "new-address", "x420.new_address",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChangeOfAddressAdvice/new-address", HFILL }},
    { &hf_x420_effective_from,
      { "effective-from", "x420.effective_from",
        FT_UINT32, BASE_DEC, VALS(x509af_Time_vals), 0,
        "ChangeOfAddressAdvice/effective-from", HFILL }},
    { &hf_x420_assembly_instructions,
      { "assembly-instructions", "x420.assembly_instructions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "IPMAssemblyInstructions/assembly-instructions", HFILL }},
    { &hf_x420_BodyPartReferences_item,
      { "Item", "x420.BodyPartReferences_item",
        FT_UINT32, BASE_DEC, VALS(x420_BodyPartReference_vals), 0,
        "BodyPartReferences/_item", HFILL }},
    { &hf_x420_stored_entry,
      { "stored-entry", "x420.stored_entry",
        FT_INT32, BASE_DEC, NULL, 0,
        "BodyPartReference/stored-entry", HFILL }},
    { &hf_x420_stored_content,
      { "stored-content", "x420.stored_content",
        FT_INT32, BASE_DEC, NULL, 0,
        "BodyPartReference/stored-content", HFILL }},
    { &hf_x420_submitted_body_part,
      { "submitted-body-part", "x420.submitted_body_part",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BodyPartReference/submitted-body-part", HFILL }},
    { &hf_x420_stored_body_part,
      { "stored-body-part", "x420.stored_body_part",
        FT_NONE, BASE_NONE, NULL, 0,
        "BodyPartReference/stored-body-part", HFILL }},
    { &hf_x420_message_entry,
      { "message-entry", "x420.message_entry",
        FT_INT32, BASE_DEC, NULL, 0,
        "BodyPartReference/stored-body-part/message-entry", HFILL }},
    { &hf_x420_body_part_number,
      { "body-part-number", "x420.body_part_number",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BodyPartReference/stored-body-part/body-part-number", HFILL }},
    { &hf_x420_NotificationRequests_rn,
      { "rn", "x420.rn",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x420_NotificationRequests_nrn,
      { "nrn", "x420.nrn",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x420_NotificationRequests_ipm_return,
      { "ipm-return", "x420.ipm-return",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_x420_NotificationRequests_an_supported,
      { "an-supported", "x420.an-supported",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_x420_NotificationRequests_suppress_an,
      { "suppress-an", "x420.suppress-an",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},

/*--- End of included file: packet-x420-hfarr.c ---*/

  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_x420,

/*--- Included file: packet-x420-ettarr.c ---*/

    &ett_x420_InformationObject,
    &ett_x420_IPM,
    &ett_x420_IPMSExtension,
    &ett_x420_Heading,
    &ett_x420_IPMIdentifier,
    &ett_x420_RecipientSpecifier,
    &ett_x420_ORDescriptor,
    &ett_x420_NotificationRequests,
    &ett_x420_RecipientExtensionsField,
    &ett_x420_AuthorizingUsersField,
    &ett_x420_PrimaryRecipientsField,
    &ett_x420_CopyRecipientsField,
    &ett_x420_BlindCopyRecipientsField,
    &ett_x420_ObsoletedIPMsField,
    &ett_x420_RelatedIPMsField,
    &ett_x420_ReplyRecipientsField,
    &ett_x420_ExtensionsField,
    &ett_x420_Body,
    &ett_x420_BodyPart,
    &ett_x420_ExtendedBodyPart,
    &ett_x420_IA5TextBodyPart,
    &ett_x420_IA5TextParameters,
    &ett_x420_G3FacsimileBodyPart,
    &ett_x420_G3FacsimileParameters,
    &ett_x420_G3FacsimileData,
    &ett_x420_G4Class1BodyPart,
    &ett_x420_MixedModeBodyPart,
    &ett_x420_TeletexBodyPart,
    &ett_x420_TeletexParameters,
    &ett_x420_TeletexData,
    &ett_x420_VideotexBodyPart,
    &ett_x420_VideotexParameters,
    &ett_x420_EncryptedBodyPart,
    &ett_x420_EncryptedParameters,
    &ett_x420_MessageBodyPart,
    &ett_x420_MessageParameters,
    &ett_x420_IPN,
    &ett_x420_T_choice,
    &ett_x420_CommonFields,
    &ett_x420_NonReceiptFields,
    &ett_x420_ReceiptFields,
    &ett_x420_NotificationExtensionsField,
    &ett_x420_NRNExtensionsField,
    &ett_x420_RNExtensionsField,
    &ett_x420_OtherNotificationTypeFields,
    &ett_x420_AbsenceAdvice,
    &ett_x420_ChangeOfAddressAdvice,
    &ett_x420_IPMAssemblyInstructions,
    &ett_x420_BodyPartReferences,
    &ett_x420_BodyPartReference,
    &ett_x420_T_stored_body_part,

/*--- End of included file: packet-x420-ettarr.c ---*/

  };

  /* Register protocol */
  proto_x420 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("x420", dissect_x420, proto_x420);
  /* Register fields and subtrees */
  proto_register_field_array(proto_x420, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_x420 --- */
void proto_reg_handoff_x420(void) {


/*--- Included file: packet-x420-dis-tab.c ---*/

  register_ber_oid_dissector("1.2.826.0.1004.10.1.1", dissect_OriginatingUA_PDU, proto_x420, "nexor-originating-ua");


/*--- End of included file: packet-x420-dis-tab.c ---*/


  register_ber_oid_dissector("2.6.1.10.0", dissect_x420, proto_x420, "InterPersonal Message (1984)");
  register_ber_oid_dissector("2.6.1.10.1", dissect_x420, proto_x420, "InterPersonal Message (1988)");
  register_ber_oid_dissector("1.3.26.0.4406.0.4.1", dissect_x420, proto_x420, "Military Message");

}
