/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler    */
/* ./packet-x411.c                                                            */
/* ../../tools/asn2eth.py -X -b -e -p x411 -c x411.cnf -s packet-x411-template x411.asn */

/* Input file: packet-x411-template.c */

#line 1 "packet-x411-template.c"
/* packet-x411.c
 * Routines for X.411 (X.400 Message Transfer)  packet dissection
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
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-ros.h"
#include "packet-rtse.h"

#include "packet-x509af.h"
#include "packet-x509ce.h"
#include "packet-x509if.h"
#include "packet-x509sat.h"

#include "packet-x411.h"
#include <epan/emem.h>
#include <epan/strutil.h>

#define PNAME  "X.411 Message Transfer Service"
#define PSNAME "X411"
#define PFNAME "x411"

/* Initialize the protocol and registered fields */
int proto_x411 = -1;

static struct SESSION_DATA_STRUCTURE* session = NULL;
static int extension_id = -1; /* integer extension id */
static const char *object_identifier_id; /* extensions identifier */
static const char *content_type_id; /* content type identifier */

#define MAX_ORA_STR_LEN     256
static char *oraddress = NULL;
static gboolean doing_address=FALSE;
static proto_item *address_item;

static proto_tree *top_tree=NULL;

static int
call_x411_oid_callback(char *base_oid, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);


/*--- Included file: packet-x411-hf.c ---*/
#line 1 "packet-x411-hf.c"
static int hf_x411_MTABindArgument_PDU = -1;      /* MTABindArgument */
static int hf_x411_MTABindResult_PDU = -1;        /* MTABindResult */
static int hf_x411_MTABindError_PDU = -1;         /* MTABindError */
static int hf_x411_MTS_APDU_PDU = -1;             /* MTS_APDU */
static int hf_x411_InternalTraceInformation_PDU = -1;  /* InternalTraceInformation */
static int hf_x411_TraceInformation_PDU = -1;     /* TraceInformation */
static int hf_x411_ReportDeliveryArgument_PDU = -1;  /* ReportDeliveryArgument */
static int hf_x411_ExtendedContentType_PDU = -1;  /* ExtendedContentType */
static int hf_x411_ContentLength_PDU = -1;        /* ContentLength */
static int hf_x411_RecipientReassignmentProhibited_PDU = -1;  /* RecipientReassignmentProhibited */
static int hf_x411_MTSOriginatorRequestedAlternateRecipient_PDU = -1;  /* MTSOriginatorRequestedAlternateRecipient */
static int hf_x411_DLExpansionProhibited_PDU = -1;  /* DLExpansionProhibited */
static int hf_x411_ConversionWithLossProhibited_PDU = -1;  /* ConversionWithLossProhibited */
static int hf_x411_LatestDeliveryTime_PDU = -1;   /* LatestDeliveryTime */
static int hf_x411_RequestedDeliveryMethod_PDU = -1;  /* RequestedDeliveryMethod */
static int hf_x411_PhysicalForwardingProhibited_PDU = -1;  /* PhysicalForwardingProhibited */
static int hf_x411_PhysicalForwardingAddressRequest_PDU = -1;  /* PhysicalForwardingAddressRequest */
static int hf_x411_PhysicalDeliveryModes_PDU = -1;  /* PhysicalDeliveryModes */
static int hf_x411_RegisteredMailType_PDU = -1;   /* RegisteredMailType */
static int hf_x411_RecipientNumberForAdvice_PDU = -1;  /* RecipientNumberForAdvice */
static int hf_x411_PhysicalRenditionAttributes_PDU = -1;  /* PhysicalRenditionAttributes */
static int hf_x411_OriginatorReturnAddress_PDU = -1;  /* OriginatorReturnAddress */
static int hf_x411_PhysicalDeliveryReportRequest_PDU = -1;  /* PhysicalDeliveryReportRequest */
static int hf_x411_OriginatorCertificate_PDU = -1;  /* OriginatorCertificate */
static int hf_x411_ContentConfidentialityAlgorithmIdentifier_PDU = -1;  /* ContentConfidentialityAlgorithmIdentifier */
static int hf_x411_ContentIntegrityCheck_PDU = -1;  /* ContentIntegrityCheck */
static int hf_x411_MessageOriginAuthenticationCheck_PDU = -1;  /* MessageOriginAuthenticationCheck */
static int hf_x411_MessageSecurityLabel_PDU = -1;  /* MessageSecurityLabel */
static int hf_x411_ProofOfSubmissionRequest_PDU = -1;  /* ProofOfSubmissionRequest */
static int hf_x411_ProofOfDeliveryRequest_PDU = -1;  /* ProofOfDeliveryRequest */
static int hf_x411_ContentCorrelator_PDU = -1;    /* ContentCorrelator */
static int hf_x411_ProbeOriginAuthenticationCheck_PDU = -1;  /* ProbeOriginAuthenticationCheck */
static int hf_x411_RedirectionHistory_PDU = -1;   /* RedirectionHistory */
static int hf_x411_DLExpansionHistory_PDU = -1;   /* DLExpansionHistory */
static int hf_x411_PhysicalForwardingAddress_PDU = -1;  /* PhysicalForwardingAddress */
static int hf_x411_OriginatorAndDLExpansionHistory_PDU = -1;  /* OriginatorAndDLExpansionHistory */
static int hf_x411_ReportingDLName_PDU = -1;      /* ReportingDLName */
static int hf_x411_ReportingMTACertificate_PDU = -1;  /* ReportingMTACertificate */
static int hf_x411_ReportOriginAuthenticationCheck_PDU = -1;  /* ReportOriginAuthenticationCheck */
static int hf_x411_ProofOfSubmission_PDU = -1;    /* ProofOfSubmission */
static int hf_x411_ReportingMTAName_PDU = -1;     /* ReportingMTAName */
static int hf_x411_ExtendedCertificates_PDU = -1;  /* ExtendedCertificates */
static int hf_x411_DLExemptedRecipients_PDU = -1;  /* DLExemptedRecipients */
static int hf_x411_CertificateSelectors_PDU = -1;  /* CertificateSelectors */
static int hf_x411_ORName_PDU = -1;               /* ORName */
static int hf_x411_ORAddress_PDU = -1;            /* ORAddress */
static int hf_x411_CommonName_PDU = -1;           /* CommonName */
static int hf_x411_TeletexCommonName_PDU = -1;    /* TeletexCommonName */
static int hf_x411_UniversalCommonName_PDU = -1;  /* UniversalCommonName */
static int hf_x411_TeletexOrganizationName_PDU = -1;  /* TeletexOrganizationName */
static int hf_x411_UniversalOrganizationName_PDU = -1;  /* UniversalOrganizationName */
static int hf_x411_TeletexPersonalName_PDU = -1;  /* TeletexPersonalName */
static int hf_x411_UniversalPersonalName_PDU = -1;  /* UniversalPersonalName */
static int hf_x411_TeletexOrganizationalUnitNames_PDU = -1;  /* TeletexOrganizationalUnitNames */
static int hf_x411_UniversalOrganizationalUnitNames_PDU = -1;  /* UniversalOrganizationalUnitNames */
static int hf_x411_PDSName_PDU = -1;              /* PDSName */
static int hf_x411_PhysicalDeliveryCountryName_PDU = -1;  /* PhysicalDeliveryCountryName */
static int hf_x411_PostalCode_PDU = -1;           /* PostalCode */
static int hf_x411_PhysicalDeliveryOfficeName_PDU = -1;  /* PhysicalDeliveryOfficeName */
static int hf_x411_ExtendedEncodedInformationType_PDU = -1;  /* ExtendedEncodedInformationType */
static int hf_x411_MTANameAndOptionalGDI_PDU = -1;  /* MTANameAndOptionalGDI */
static int hf_x411_AsymmetricToken_PDU = -1;      /* AsymmetricToken */
static int hf_x411_unauthenticated = -1;          /* NULL */
static int hf_x411_authenticated_argument = -1;   /* AuthenticatedArgument */
static int hf_x411_authenticated_initiator_name = -1;  /* MTAName */
static int hf_x411_initiator_credentials = -1;    /* InitiatorCredentials */
static int hf_x411_security_context = -1;         /* SecurityContext */
static int hf_x411_authenticated_result = -1;     /* AuthenticatedResult */
static int hf_x411_authenticated_responder_name = -1;  /* MTAName */
static int hf_x411_responder_credentials = -1;    /* ResponderCredentials */
static int hf_x411_message = -1;                  /* Message */
static int hf_x411_probe = -1;                    /* Probe */
static int hf_x411_report = -1;                   /* Report */
static int hf_x411_message_envelope = -1;         /* MessageTransferEnvelope */
static int hf_x411_content = -1;                  /* Content */
static int hf_x411_report_envelope = -1;          /* ReportTransferEnvelope */
static int hf_x411_report_content = -1;           /* ReportTransferContent */
static int hf_x411_message_identifier = -1;       /* MessageIdentifier */
static int hf_x411_mta_originator_name = -1;      /* MTAOriginatorName */
static int hf_x411_original_encoded_information_types = -1;  /* OriginalEncodedInformationTypes */
static int hf_x411_content_type = -1;             /* ContentType */
static int hf_x411_content_identifier = -1;       /* ContentIdentifier */
static int hf_x411_priority = -1;                 /* Priority */
static int hf_x411_per_message_indicators = -1;   /* PerMessageIndicators */
static int hf_x411_deferred_delivery_time = -1;   /* DeferredDeliveryTime */
static int hf_x411_per_domain_bilateral_information = -1;  /* SEQUENCE_OF_PerDomainBilateralInformation */
static int hf_x411_per_domain_bilateral_information_item = -1;  /* PerDomainBilateralInformation */
static int hf_x411_trace_information = -1;        /* TraceInformation */
static int hf_x411_extensions = -1;               /* SET_OF_ExtensionField */
static int hf_x411_extensions_item = -1;          /* ExtensionField */
static int hf_x411_per_recipient_message_fields = -1;  /* SEQUENCE_OF_PerRecipientMessageTransferFields */
static int hf_x411_per_recipient_message_fields_item = -1;  /* PerRecipientMessageTransferFields */
static int hf_x411_recipient_name = -1;           /* MTARecipientName */
static int hf_x411_originally_specified_recipient_number = -1;  /* OriginallySpecifiedRecipientNumber */
static int hf_x411_per_recipient_indicators = -1;  /* PerRecipientIndicators */
static int hf_x411_explicit_conversion = -1;      /* ExplicitConversion */
static int hf_x411_probe_identifier = -1;         /* ProbeIdentifier */
static int hf_x411_content_length = -1;           /* ContentLength */
static int hf_x411_per_recipient_probe_transfer_fields = -1;  /* SEQUENCE_OF_PerRecipientProbeTransferFields */
static int hf_x411_per_recipient_probe_transfer_fields_item = -1;  /* PerRecipientProbeTransferFields */
static int hf_x411_report_identifier = -1;        /* ReportIdentifier */
static int hf_x411_report_destination_name = -1;  /* ReportDestinationName */
static int hf_x411_subject_identifier = -1;       /* SubjectIdentifier */
static int hf_x411_subject_intermediate_trace_information = -1;  /* SubjectIntermediateTraceInformation */
static int hf_x411_returned_content = -1;         /* Content */
static int hf_x411_additional_information = -1;   /* AdditionalInformation */
static int hf_x411_per_recipient_report_fields = -1;  /* SEQUENCE_OF_PerRecipientReportTransferFields */
static int hf_x411_per_recipient_fields_item = -1;  /* PerRecipientReportTransferFields */
static int hf_x411_mta_actual_recipient_name = -1;  /* MTAActualRecipientName */
static int hf_x411_last_trace_information = -1;   /* LastTraceInformation */
static int hf_x411_report_originally_intended_recipient_name = -1;  /* MTAOriginallyIntendedRecipientName */
static int hf_x411_supplementary_information = -1;  /* SupplementaryInformation */
static int hf_x411_country_name = -1;             /* CountryName */
static int hf_x411_bilateral_domain = -1;         /* T_domain */
static int hf_x411_administration_domain_name = -1;  /* AdministrationDomainName */
static int hf_x411_private_domain = -1;           /* T_private_domain */
static int hf_x411_private_domain_identifier = -1;  /* PrivateDomainIdentifier */
static int hf_x411_arrival_time = -1;             /* ArrivalTime */
static int hf_x411_converted_encoded_information_types = -1;  /* ConvertedEncodedInformationTypes */
static int hf_x411_trace_report_type = -1;        /* ReportType */
static int hf_x411_InternalTraceInformation_item = -1;  /* InternalTraceInformationElement */
static int hf_x411_global_domain_identifier = -1;  /* GlobalDomainIdentifier */
static int hf_x411_mta_name = -1;                 /* MTAName */
static int hf_x411_mta_supplied_information = -1;  /* MTASuppliedInformation */
static int hf_x411_routing_action = -1;           /* RoutingAction */
static int hf_x411_attempted = -1;                /* T_attempted */
static int hf_x411_mta = -1;                      /* MTAName */
static int hf_x411_domain = -1;                   /* GlobalDomainIdentifier */
static int hf_x411_deferred_time = -1;            /* DeferredTime */
static int hf_x411_other_actions = -1;            /* OtherActions */
static int hf_x411_TraceInformation_item = -1;    /* TraceInformationElement */
static int hf_x411_domain_supplied_information = -1;  /* DomainSuppliedInformation */
static int hf_x411_attempted_domain = -1;         /* GlobalDomainIdentifier */
static int hf_x411_initiator_name = -1;           /* ObjectName */
static int hf_x411_messages_waiting = -1;         /* MessagesWaiting */
static int hf_x411_responder_name = -1;           /* ObjectName */
static int hf_x411_user_agent = -1;               /* ORAddressAndOptionalDirectoryName */
static int hf_x411_mTA = -1;                      /* MTAName */
static int hf_x411_message_store = -1;            /* ORAddressAndOptionalDirectoryName */
static int hf_x411_urgent = -1;                   /* DeliveryQueue */
static int hf_x411_normal = -1;                   /* DeliveryQueue */
static int hf_x411_non_urgent = -1;               /* DeliveryQueue */
static int hf_x411_messages = -1;                 /* INTEGER */
static int hf_x411_delivery_queue_octets = -1;    /* INTEGER */
static int hf_x411_simple = -1;                   /* Password */
static int hf_x411_strong = -1;                   /* StrongCredentials */
static int hf_x411_protected = -1;                /* ProtectedPassword */
static int hf_x411_ia5_string = -1;               /* IA5String */
static int hf_x411_octet_string = -1;             /* OCTET_STRING */
static int hf_x411_bind_token = -1;               /* Token */
static int hf_x411_certificate = -1;              /* Certificates */
static int hf_x411_certificate_selector = -1;     /* CertificateAssertion */
static int hf_x411_signature = -1;                /* Signature */
static int hf_x411_time1 = -1;                    /* UTCTime */
static int hf_x411_time2 = -1;                    /* UTCTime */
static int hf_x411_random1 = -1;                  /* BIT_STRING */
static int hf_x411_random2 = -1;                  /* BIT_STRING */
static int hf_x411_algorithmIdentifier = -1;      /* AlgorithmIdentifier */
static int hf_x411_encrypted = -1;                /* BIT_STRING */
static int hf_x411_SecurityContext_item = -1;     /* SecurityLabel */
static int hf_x411_message_submission_envelope = -1;  /* MessageSubmissionEnvelope */
static int hf_x411_message_submission_identifier = -1;  /* MessageSubmissionIdentifier */
static int hf_x411_message_submission_time = -1;  /* MessageSubmissionTime */
static int hf_x411_probe_submission_identifier = -1;  /* ProbeSubmissionIdentifier */
static int hf_x411_probe_submission_time = -1;    /* ProbeSubmissionTime */
static int hf_x411_ImproperlySpecifiedRecipients_item = -1;  /* MTSRecipientName */
static int hf_x411_waiting_operations = -1;       /* Operations */
static int hf_x411_waiting_messages = -1;         /* WaitingMessages */
static int hf_x411_waiting_content_types = -1;    /* SET_OF_ContentType */
static int hf_x411_waiting_content_types_item = -1;  /* ContentType */
static int hf_x411_waiting_encoded_information_types = -1;  /* EncodedInformationTypes */
static int hf_x411_message_delivery_identifier = -1;  /* MessageDeliveryIdentifier */
static int hf_x411_message_delivery_time = -1;    /* MessageDeliveryTime */
static int hf_x411_other_fields = -1;             /* OtherMessageDeliveryFields */
static int hf_x411_recipient_certificate = -1;    /* RecipientCertificate */
static int hf_x411_proof_of_delivery = -1;        /* ProofOfDelivery */
static int hf_x411_subject_submission_identifier = -1;  /* SubjectSubmissionIdentifier */
static int hf_x411_per_recipient_report_delivery_fields = -1;  /* SEQUENCE_OF_PerRecipientReportDeliveryFields */
static int hf_x411_per_recipient_report_delivery_fields_item = -1;  /* PerRecipientReportDeliveryFields */
static int hf_x411_empty_result = -1;             /* NULL */
static int hf_x411_restrict = -1;                 /* BOOLEAN */
static int hf_x411_permissible_operations = -1;   /* Operations */
static int hf_x411_permissible_maximum_content_length = -1;  /* ContentLength */
static int hf_x411_permissible_lowest_priority = -1;  /* Priority */
static int hf_x411_permissible_content_types = -1;  /* ContentTypes */
static int hf_x411_permissible_encoded_information_types = -1;  /* PermissibleEncodedInformationTypes */
static int hf_x411_permissible_security_context = -1;  /* SecurityContext */
static int hf_x411_refused_argument = -1;         /* T_refused_argument */
static int hf_x411_built_in_argument = -1;        /* RefusedArgument */
static int hf_x411_refused_extension = -1;        /* T_refused_extension */
static int hf_x411_refusal_reason = -1;           /* RefusalReason */
static int hf_x411_user_name = -1;                /* UserName */
static int hf_x411_user_address = -1;             /* UserAddress */
static int hf_x411_deliverable_class = -1;        /* SET_OF_DeliverableClass */
static int hf_x411_deliverable_class_item = -1;   /* DeliverableClass */
static int hf_x411_default_delivery_controls = -1;  /* DefaultDeliveryControls */
static int hf_x411_redirections = -1;             /* Redirections */
static int hf_x411_restricted_delivery = -1;      /* RestrictedDelivery */
static int hf_x411_retrieve_registrations = -1;   /* RegistrationTypes */
static int hf_x411_non_empty_result = -1;         /* T_non_empty_result */
static int hf_x411_registered_information = -1;   /* RegisterArgument */
static int hf_x411_old_credentials = -1;          /* Credentials */
static int hf_x411_new_credentials = -1;          /* Credentials */
static int hf_x411_x121 = -1;                     /* T_x121 */
static int hf_x411_x121_address = -1;             /* NumericString */
static int hf_x411_tsap_id = -1;                  /* PrintableString */
static int hf_x411_presentation = -1;             /* PSAPAddress */
static int hf_x411_Redirections_item = -1;        /* RecipientRedirection */
static int hf_x411_redirection_classes = -1;      /* SET_OF_RedirectionClass */
static int hf_x411_redirection_classes_item = -1;  /* RedirectionClass */
static int hf_x411_recipient_assigned_alternate_recipient = -1;  /* RecipientAssignedAlternateRecipient */
static int hf_x411_content_types = -1;            /* ContentTypes */
static int hf_x411_maximum_content_length = -1;   /* ContentLength */
static int hf_x411_encoded_information_types_constraints = -1;  /* EncodedInformationTypesConstraints */
static int hf_x411_security_labels = -1;          /* SecurityContext */
static int hf_x411_class_priority = -1;           /* SET_OF_Priority */
static int hf_x411_priority_item = -1;            /* Priority */
static int hf_x411_objects = -1;                  /* T_objects */
static int hf_x411_applies_only_to = -1;          /* SEQUENCE_OF_Restriction */
static int hf_x411_applies_only_to_item = -1;     /* Restriction */
static int hf_x411_unacceptable_eits = -1;        /* ExtendedEncodedInformationTypes */
static int hf_x411_acceptable_eits = -1;          /* ExtendedEncodedInformationTypes */
static int hf_x411_exclusively_acceptable_eits = -1;  /* ExtendedEncodedInformationTypes */
static int hf_x411_RestrictedDelivery_item = -1;  /* Restriction */
static int hf_x411_permitted = -1;                /* BOOLEAN */
static int hf_x411_source_type = -1;              /* T_source_type */
static int hf_x411_source_name = -1;              /* ExactOrPattern */
static int hf_x411_exact_match = -1;              /* ORName */
static int hf_x411_pattern_match = -1;            /* ORName */
static int hf_x411_standard_parameters = -1;      /* T_standard_parameters */
static int hf_x411_type_extensions = -1;          /* T_extensions */
static int hf_x411_type_extensions_item = -1;     /* T_extensions_item */
static int hf_x411_mts_originator_name = -1;      /* MTSOriginatorName */
static int hf_x411_per_recipient_message_submission_fields = -1;  /* SEQUENCE_OF_PerRecipientMessageSubmissionFields */
static int hf_x411_per_recipient_message_submission_fields_item = -1;  /* PerRecipientMessageSubmissionFields */
static int hf_x411_submission_recipient_name = -1;  /* MTSRecipientName */
static int hf_x411_originator_report_request = -1;  /* OriginatorReportRequest */
static int hf_x411_per_recipient_probe_submission_fields = -1;  /* SEQUENCE_OF_PerRecipientProbeSubmissionFields */
static int hf_x411_per_recipient_probe_submission_fields_item = -1;  /* PerRecipientProbeSubmissionFields */
static int hf_x411_probe_recipient_name = -1;     /* MTSRecipientName */
static int hf_x411_delivered_content_type = -1;   /* DeliveredContentType */
static int hf_x411_originator_name = -1;          /* DeliveredOriginatorName */
static int hf_x411_delivery_flags = -1;           /* DeliveryFlags */
static int hf_x411_other_recipient_names = -1;    /* OtherRecipientNames */
static int hf_x411_this_recipient_name = -1;      /* ThisRecipientName */
static int hf_x411_originally_intended_recipient_name = -1;  /* MTSOriginallyIntendedRecipientName */
static int hf_x411_actual_recipient_name = -1;    /* MTSActualRecipientName */
static int hf_x411_delivery_report_type = -1;     /* ReportType */
static int hf_x411_delivery = -1;                 /* DeliveryReport */
static int hf_x411_non_delivery = -1;             /* NonDeliveryReport */
static int hf_x411_type_of_MTS_user = -1;         /* TypeOfMTSUser */
static int hf_x411_non_delivery_reason_code = -1;  /* NonDeliveryReasonCode */
static int hf_x411_non_delivery_diagnostic_code = -1;  /* NonDeliveryDiagnosticCode */
static int hf_x411_ContentTypes_item = -1;        /* ContentType */
static int hf_x411_built_in = -1;                 /* BuiltInContentType */
static int hf_x411_extended = -1;                 /* ExtendedContentType */
static int hf_x411_OtherRecipientNames_item = -1;  /* OtherRecipientName */
static int hf_x411_standard_extension = -1;       /* INTEGER */
static int hf_x411_private_extension = -1;        /* OBJECT_IDENTIFIER */
static int hf_x411_extension_type = -1;           /* ExtensionType */
static int hf_x411_criticality = -1;              /* Criticality */
static int hf_x411_extension_value = -1;          /* ExtensionValue */
static int hf_x411_RequestedDeliveryMethod_item = -1;  /* RequestedDeliveryMethod_item */
static int hf_x411_ia5text = -1;                  /* IA5String */
static int hf_x411_octets = -1;                   /* OCTET_STRING */
static int hf_x411_RedirectionHistory_item = -1;  /* Redirection */
static int hf_x411_intended_recipient_name = -1;  /* IntendedRecipientName */
static int hf_x411_redirection_reason = -1;       /* RedirectionReason */
static int hf_x411_intended_recipient = -1;       /* ORAddressAndOptionalDirectoryName */
static int hf_x411_redirection_time = -1;         /* Time */
static int hf_x411_DLExpansionHistory_item = -1;  /* DLExpansion */
static int hf_x411_dl = -1;                       /* ORAddressAndOptionalDirectoryName */
static int hf_x411_dl_expansion_time = -1;        /* Time */
static int hf_x411_OriginatorAndDLExpansionHistory_item = -1;  /* OriginatorAndDLExpansion */
static int hf_x411_originator_or_dl_name = -1;    /* ORAddressAndOptionalDirectoryName */
static int hf_x411_origination_or_expansion_time = -1;  /* Time */
static int hf_x411_report_type = -1;              /* T_report_type */
static int hf_x411_report_type_delivery = -1;     /* PerRecipientDeliveryReportFields */
static int hf_x411_non_delivery_report = -1;      /* PerRecipientNonDeliveryReportFields */
static int hf_x411_mta_directory_name = -1;       /* Name */
static int hf_x411_ExtendedCertificates_item = -1;  /* ExtendedCertificate */
static int hf_x411_directory_entry = -1;          /* Name */
static int hf_x411_DLExemptedRecipients_item = -1;  /* ORAddressAndOrDirectoryName */
static int hf_x411_encryption_recipient = -1;     /* CertificateAssertion */
static int hf_x411_encryption_originator = -1;    /* CertificateAssertion */
static int hf_x411_content_integrity_check = -1;  /* CertificateAssertion */
static int hf_x411_token_signature = -1;          /* CertificateAssertion */
static int hf_x411_message_origin_authentication = -1;  /* CertificateAssertion */
static int hf_x411_local_identifier = -1;         /* LocalIdentifier */
static int hf_x411_numeric = -1;                  /* NumericString */
static int hf_x411_printable = -1;                /* PrintableString */
static int hf_x411_built_in_standard_attributes = -1;  /* BuiltInStandardAttributes */
static int hf_x411_built_in_domain_defined_attributes = -1;  /* BuiltInDomainDefinedAttributes */
static int hf_x411_extension_attributes = -1;     /* ExtensionAttributes */
static int hf_x411_directory_name = -1;           /* Name */
static int hf_x411_network_address = -1;          /* NetworkAddress */
static int hf_x411_terminal_identifier = -1;      /* TerminalIdentifier */
static int hf_x411_private_domain_name = -1;      /* PrivateDomainName */
static int hf_x411_organization_name = -1;        /* OrganizationName */
static int hf_x411_numeric_user_identifier = -1;  /* NumericUserIdentifier */
static int hf_x411_personal_name = -1;            /* PersonalName */
static int hf_x411_organizational_unit_names = -1;  /* OrganizationalUnitNames */
static int hf_x411_x121_dcc_code = -1;            /* NumericString */
static int hf_x411_iso_3166_alpha2_code = -1;     /* PrintableString */
static int hf_x411_printable_surname = -1;        /* PrintableString */
static int hf_x411_printable_given_name = -1;     /* PrintableString */
static int hf_x411_printable_initials = -1;       /* PrintableString */
static int hf_x411_printable_generation_qualifier = -1;  /* PrintableString */
static int hf_x411_OrganizationalUnitNames_item = -1;  /* OrganizationalUnitName */
static int hf_x411_BuiltInDomainDefinedAttributes_item = -1;  /* BuiltInDomainDefinedAttribute */
static int hf_x411_printable_type = -1;           /* PrintableString */
static int hf_x411_printable_value = -1;          /* PrintableString */
static int hf_x411_ExtensionAttributes_item = -1;  /* ExtensionAttribute */
static int hf_x411_extension_attribute_type = -1;  /* INTEGER */
static int hf_x411_extension_attribute_value = -1;  /* T_extension_attribute_value */
static int hf_x411_teletex_surname = -1;          /* TeletexString */
static int hf_x411_teletex_given_name = -1;       /* TeletexString */
static int hf_x411_teletex_initials = -1;         /* TeletexString */
static int hf_x411_teletex_generation_qualifier = -1;  /* TeletexString */
static int hf_x411_universal_surname = -1;        /* UniversalOrBMPString */
static int hf_x411_universal_given_name = -1;     /* UniversalOrBMPString */
static int hf_x411_universal_initials = -1;       /* UniversalOrBMPString */
static int hf_x411_universal_generation_qualifier = -1;  /* UniversalOrBMPString */
static int hf_x411_TeletexOrganizationalUnitNames_item = -1;  /* TeletexOrganizationalUnitName */
static int hf_x411_UniversalOrganizationalUnitNames_item = -1;  /* UniversalOrganizationalUnitName */
static int hf_x411_character_encoding = -1;       /* T_character_encoding */
static int hf_x411_two_octets = -1;               /* BMPString */
static int hf_x411_four_octets = -1;              /* UniversalString */
static int hf_x411_iso_639_language_code = -1;    /* PrintableString */
static int hf_x411_numeric_code = -1;             /* NumericString */
static int hf_x411_printable_code = -1;           /* PrintableString */
static int hf_x411_printable_address = -1;        /* T_printable_address */
static int hf_x411_printable_address_item = -1;   /* PrintableString */
static int hf_x411_teletex_string = -1;           /* TeletexString */
static int hf_x411_printable_string = -1;         /* PrintableString */
static int hf_x411_e163_4_address = -1;           /* T_e163_4_address */
static int hf_x411_number = -1;                   /* NumericString */
static int hf_x411_sub_address = -1;              /* NumericString */
static int hf_x411_psap_address = -1;             /* PresentationAddress */
static int hf_x411_TeletexDomainDefinedAttributes_item = -1;  /* TeletexDomainDefinedAttribute */
static int hf_x411_type = -1;                     /* TeletexString */
static int hf_x411_teletex_value = -1;            /* TeletexString */
static int hf_x411_UniversalDomainDefinedAttributes_item = -1;  /* UniversalDomainDefinedAttribute */
static int hf_x411_universal_type = -1;           /* UniversalOrBMPString */
static int hf_x411_universal_value = -1;          /* UniversalOrBMPString */
static int hf_x411_built_in_encoded_information_types = -1;  /* BuiltInEncodedInformationTypes */
static int hf_x411_g3_facsimile = -1;             /* G3FacsimileNonBasicParameters */
static int hf_x411_teletex = -1;                  /* TeletexNonBasicParameters */
static int hf_x411_extended_encoded_information_types = -1;  /* ExtendedEncodedInformationTypes */
static int hf_x411_ExtendedEncodedInformationTypes_item = -1;  /* ExtendedEncodedInformationType */
static int hf_x411_graphic_character_sets = -1;   /* TeletexString */
static int hf_x411_control_character_sets = -1;   /* TeletexString */
static int hf_x411_page_formats = -1;             /* OCTET_STRING */
static int hf_x411_miscellaneous_terminal_capabilities = -1;  /* TeletexString */
static int hf_x411_private_use = -1;              /* OCTET_STRING */
static int hf_x411_token_type_identifier = -1;    /* TokenTypeIdentifier */
static int hf_x411_token = -1;                    /* TokenTypeData */
static int hf_x411_signature_algorithm_identifier = -1;  /* AlgorithmIdentifier */
static int hf_x411_name = -1;                     /* T_name */
static int hf_x411_token_recipient_name = -1;     /* MTSRecipientName */
static int hf_x411_token_mta = -1;                /* MTANameAndOptionalGDI */
static int hf_x411_time = -1;                     /* Time */
static int hf_x411_signed_data = -1;              /* TokenData */
static int hf_x411_encryption_algorithm_identifier = -1;  /* AlgorithmIdentifier */
static int hf_x411_encrypted_data = -1;           /* BIT_STRING */
static int hf_x411_asymmetric_token_data = -1;    /* AsymmetricTokenData */
static int hf_x411_algorithm_identifier = -1;     /* AlgorithmIdentifier */
static int hf_x411_security_policy_identifier = -1;  /* SecurityPolicyIdentifier */
static int hf_x411_security_classification = -1;  /* SecurityClassification */
static int hf_x411_privacy_mark = -1;             /* PrivacyMark */
static int hf_x411_security_categories = -1;      /* SecurityCategories */
static int hf_x411_SecurityCategories_item = -1;  /* SecurityCategory */
static int hf_x411_category_type = -1;            /* OBJECT_IDENTIFIER */
static int hf_x411_category_value = -1;           /* CategoryValue */
/* named bits */
static int hf_x411_PerRecipientIndicators_responsibility = -1;
static int hf_x411_PerRecipientIndicators_originating_MTA_report = -1;
static int hf_x411_PerRecipientIndicators_originating_MTA_non_delivery_report = -1;
static int hf_x411_PerRecipientIndicators_originator_report = -1;
static int hf_x411_PerRecipientIndicators_originator_non_delivery_report = -1;
static int hf_x411_PerRecipientIndicators_reserved_5 = -1;
static int hf_x411_PerRecipientIndicators_reserved_6 = -1;
static int hf_x411_PerRecipientIndicators_reserved_7 = -1;
static int hf_x411_OtherActions_redirected = -1;
static int hf_x411_OtherActions_dl_operation = -1;
static int hf_x411_Operations_probe_submission_or_report_delivery = -1;
static int hf_x411_Operations_message_submission_or_message_delivery = -1;
static int hf_x411_WaitingMessages_long_content = -1;
static int hf_x411_WaitingMessages_low_priority = -1;
static int hf_x411_WaitingMessages_other_security_labels = -1;
static int hf_x411_T_source_type_originated_by = -1;
static int hf_x411_T_source_type_redirected_by = -1;
static int hf_x411_T_source_type_dl_expanded_by = -1;
static int hf_x411_T_standard_parameters_user_name = -1;
static int hf_x411_T_standard_parameters_user_address = -1;
static int hf_x411_T_standard_parameters_deliverable_class = -1;
static int hf_x411_T_standard_parameters_default_delivery_controls = -1;
static int hf_x411_T_standard_parameters_redirections = -1;
static int hf_x411_T_standard_parameters_restricted_delivery = -1;
static int hf_x411_PerMessageIndicators_disclosure_of_other_recipients = -1;
static int hf_x411_PerMessageIndicators_implicit_conversion_prohibited = -1;
static int hf_x411_PerMessageIndicators_alternate_recipient_allowed = -1;
static int hf_x411_PerMessageIndicators_content_return_request = -1;
static int hf_x411_PerMessageIndicators_reserved = -1;
static int hf_x411_PerMessageIndicators_bit_5 = -1;
static int hf_x411_PerMessageIndicators_bit_6 = -1;
static int hf_x411_PerMessageIndicators_service_message = -1;
static int hf_x411_OriginatorReportRequest_report = -1;
static int hf_x411_OriginatorReportRequest_non_delivery_report = -1;
static int hf_x411_DeliveryFlags_implicit_conversion_prohibited = -1;
static int hf_x411_Criticality_for_submission = -1;
static int hf_x411_Criticality_for_transfer = -1;
static int hf_x411_Criticality_for_delivery = -1;
static int hf_x411_PhysicalDeliveryModes_ordinary_mail = -1;
static int hf_x411_PhysicalDeliveryModes_special_delivery = -1;
static int hf_x411_PhysicalDeliveryModes_express_mail = -1;
static int hf_x411_PhysicalDeliveryModes_counter_collection = -1;
static int hf_x411_PhysicalDeliveryModes_counter_collection_with_telephone_advice = -1;
static int hf_x411_PhysicalDeliveryModes_counter_collection_with_telex_advice = -1;
static int hf_x411_PhysicalDeliveryModes_counter_collection_with_teletex_advice = -1;
static int hf_x411_PhysicalDeliveryModes_bureau_fax_delivery = -1;
static int hf_x411_BuiltInEncodedInformationTypes_unknown = -1;
static int hf_x411_BuiltInEncodedInformationTypes_ia5_text = -1;
static int hf_x411_BuiltInEncodedInformationTypes_g3_facsimile = -1;
static int hf_x411_BuiltInEncodedInformationTypes_g4_class_1 = -1;
static int hf_x411_BuiltInEncodedInformationTypes_teletex = -1;
static int hf_x411_BuiltInEncodedInformationTypes_videotex = -1;
static int hf_x411_BuiltInEncodedInformationTypes_voice = -1;
static int hf_x411_BuiltInEncodedInformationTypes_sfd = -1;
static int hf_x411_BuiltInEncodedInformationTypes_mixed_mode = -1;
static int hf_x411_G3FacsimileNonBasicParameters_two_dimensional = -1;
static int hf_x411_G3FacsimileNonBasicParameters_fine_resolution = -1;
static int hf_x411_G3FacsimileNonBasicParameters_unlimited_length = -1;
static int hf_x411_G3FacsimileNonBasicParameters_b4_length = -1;
static int hf_x411_G3FacsimileNonBasicParameters_a3_width = -1;
static int hf_x411_G3FacsimileNonBasicParameters_b4_width = -1;
static int hf_x411_G3FacsimileNonBasicParameters_t6_coding = -1;
static int hf_x411_G3FacsimileNonBasicParameters_uncompressed = -1;
static int hf_x411_G3FacsimileNonBasicParameters_width_middle_864_of_1728 = -1;
static int hf_x411_G3FacsimileNonBasicParameters_width_middle_1216_of_1728 = -1;
static int hf_x411_G3FacsimileNonBasicParameters_resolution_type = -1;
static int hf_x411_G3FacsimileNonBasicParameters_resolution_400x400 = -1;
static int hf_x411_G3FacsimileNonBasicParameters_resolution_300x300 = -1;
static int hf_x411_G3FacsimileNonBasicParameters_resolution_8x15 = -1;
static int hf_x411_G3FacsimileNonBasicParameters_edi = -1;
static int hf_x411_G3FacsimileNonBasicParameters_dtm = -1;
static int hf_x411_G3FacsimileNonBasicParameters_bft = -1;
static int hf_x411_G3FacsimileNonBasicParameters_mixed_mode = -1;
static int hf_x411_G3FacsimileNonBasicParameters_character_mode = -1;
static int hf_x411_G3FacsimileNonBasicParameters_twelve_bits = -1;
static int hf_x411_G3FacsimileNonBasicParameters_preferred_huffmann = -1;
static int hf_x411_G3FacsimileNonBasicParameters_full_colour = -1;
static int hf_x411_G3FacsimileNonBasicParameters_jpeg = -1;
static int hf_x411_G3FacsimileNonBasicParameters_processable_mode_26 = -1;

/*--- End of included file: packet-x411-hf.c ---*/
#line 74 "packet-x411-template.c"

/* Initialize the subtree pointers */
static gint ett_x411 = -1;

/*--- Included file: packet-x411-ett.c ---*/
#line 1 "packet-x411-ett.c"
static gint ett_x411_MTABindArgument = -1;
static gint ett_x411_AuthenticatedArgument = -1;
static gint ett_x411_MTABindResult = -1;
static gint ett_x411_AuthenticatedResult = -1;
static gint ett_x411_MTS_APDU = -1;
static gint ett_x411_Message = -1;
static gint ett_x411_Report = -1;
static gint ett_x411_MessageTransferEnvelope = -1;
static gint ett_x411_SEQUENCE_OF_PerDomainBilateralInformation = -1;
static gint ett_x411_SET_OF_ExtensionField = -1;
static gint ett_x411_SEQUENCE_OF_PerRecipientMessageTransferFields = -1;
static gint ett_x411_PerRecipientMessageTransferFields = -1;
static gint ett_x411_ProbeTransferEnvelope = -1;
static gint ett_x411_SEQUENCE_OF_PerRecipientProbeTransferFields = -1;
static gint ett_x411_PerRecipientProbeTransferFields = -1;
static gint ett_x411_ReportTransferEnvelope = -1;
static gint ett_x411_ReportTransferContent = -1;
static gint ett_x411_SEQUENCE_OF_PerRecipientReportTransferFields = -1;
static gint ett_x411_PerRecipientReportTransferFields = -1;
static gint ett_x411_PerDomainBilateralInformation = -1;
static gint ett_x411_T_domain = -1;
static gint ett_x411_T_private_domain = -1;
static gint ett_x411_PerRecipientIndicators = -1;
static gint ett_x411_LastTraceInformation = -1;
static gint ett_x411_InternalTraceInformation = -1;
static gint ett_x411_InternalTraceInformationElement = -1;
static gint ett_x411_MTASuppliedInformation = -1;
static gint ett_x411_T_attempted = -1;
static gint ett_x411_TraceInformation = -1;
static gint ett_x411_TraceInformationElement = -1;
static gint ett_x411_DomainSuppliedInformation = -1;
static gint ett_x411_OtherActions = -1;
static gint ett_x411_MTSBindArgument = -1;
static gint ett_x411_MTSBindResult = -1;
static gint ett_x411_ObjectName = -1;
static gint ett_x411_MessagesWaiting = -1;
static gint ett_x411_DeliveryQueue = -1;
static gint ett_x411_Credentials = -1;
static gint ett_x411_Password = -1;
static gint ett_x411_StrongCredentials = -1;
static gint ett_x411_ProtectedPassword = -1;
static gint ett_x411_Signature = -1;
static gint ett_x411_SecurityContext = -1;
static gint ett_x411_MessageSubmissionArgument = -1;
static gint ett_x411_MessageSubmissionResult = -1;
static gint ett_x411_ProbeSubmissionResult = -1;
static gint ett_x411_ImproperlySpecifiedRecipients = -1;
static gint ett_x411_Waiting = -1;
static gint ett_x411_SET_OF_ContentType = -1;
static gint ett_x411_Operations = -1;
static gint ett_x411_WaitingMessages = -1;
static gint ett_x411_MessageDeliveryArgument = -1;
static gint ett_x411_MessageDeliveryResult = -1;
static gint ett_x411_ReportDeliveryArgument = -1;
static gint ett_x411_SEQUENCE_OF_PerRecipientReportDeliveryFields = -1;
static gint ett_x411_ReportDeliveryResult = -1;
static gint ett_x411_DeliveryControlArgument = -1;
static gint ett_x411_DeliveryControlResult = -1;
static gint ett_x411_RefusedOperation = -1;
static gint ett_x411_T_refused_argument = -1;
static gint ett_x411_Controls = -1;
static gint ett_x411_RegisterArgument = -1;
static gint ett_x411_SET_OF_DeliverableClass = -1;
static gint ett_x411_RegisterResult = -1;
static gint ett_x411_T_non_empty_result = -1;
static gint ett_x411_ChangeCredentialsArgument = -1;
static gint ett_x411_UserAddress = -1;
static gint ett_x411_T_x121 = -1;
static gint ett_x411_Redirections = -1;
static gint ett_x411_RecipientRedirection = -1;
static gint ett_x411_SET_OF_RedirectionClass = -1;
static gint ett_x411_MessageClass = -1;
static gint ett_x411_SET_OF_Priority = -1;
static gint ett_x411_SEQUENCE_OF_Restriction = -1;
static gint ett_x411_EncodedInformationTypesConstraints = -1;
static gint ett_x411_RestrictedDelivery = -1;
static gint ett_x411_Restriction = -1;
static gint ett_x411_T_source_type = -1;
static gint ett_x411_ExactOrPattern = -1;
static gint ett_x411_RegistrationTypes = -1;
static gint ett_x411_T_standard_parameters = -1;
static gint ett_x411_T_extensions = -1;
static gint ett_x411_MessageSubmissionEnvelope = -1;
static gint ett_x411_SEQUENCE_OF_PerRecipientMessageSubmissionFields = -1;
static gint ett_x411_PerRecipientMessageSubmissionFields = -1;
static gint ett_x411_ProbeSubmissionEnvelope = -1;
static gint ett_x411_SEQUENCE_OF_PerRecipientProbeSubmissionFields = -1;
static gint ett_x411_PerRecipientProbeSubmissionFields = -1;
static gint ett_x411_MessageDeliveryEnvelope = -1;
static gint ett_x411_OtherMessageDeliveryFields = -1;
static gint ett_x411_ReportDeliveryEnvelope = -1;
static gint ett_x411_PerRecipientReportDeliveryFields = -1;
static gint ett_x411_ReportType = -1;
static gint ett_x411_DeliveryReport = -1;
static gint ett_x411_NonDeliveryReport = -1;
static gint ett_x411_ContentTypes = -1;
static gint ett_x411_ContentType = -1;
static gint ett_x411_DeliveredContentType = -1;
static gint ett_x411_PerMessageIndicators = -1;
static gint ett_x411_OriginatorReportRequest = -1;
static gint ett_x411_DeliveryFlags = -1;
static gint ett_x411_OtherRecipientNames = -1;
static gint ett_x411_ExtensionType = -1;
static gint ett_x411_Criticality = -1;
static gint ett_x411_ExtensionField = -1;
static gint ett_x411_RequestedDeliveryMethod = -1;
static gint ett_x411_PhysicalDeliveryModes = -1;
static gint ett_x411_ContentCorrelator = -1;
static gint ett_x411_RedirectionHistory = -1;
static gint ett_x411_Redirection = -1;
static gint ett_x411_IntendedRecipientName = -1;
static gint ett_x411_DLExpansionHistory = -1;
static gint ett_x411_DLExpansion = -1;
static gint ett_x411_OriginatorAndDLExpansionHistory = -1;
static gint ett_x411_OriginatorAndDLExpansion = -1;
static gint ett_x411_PerRecipientReportFields = -1;
static gint ett_x411_T_report_type = -1;
static gint ett_x411_PerRecipientDeliveryReportFields = -1;
static gint ett_x411_PerRecipientNonDeliveryReportFields = -1;
static gint ett_x411_ReportingMTAName = -1;
static gint ett_x411_ExtendedCertificates = -1;
static gint ett_x411_ExtendedCertificate = -1;
static gint ett_x411_DLExemptedRecipients = -1;
static gint ett_x411_CertificateSelectors = -1;
static gint ett_x411_MTSIdentifier = -1;
static gint ett_x411_GlobalDomainIdentifier = -1;
static gint ett_x411_PrivateDomainIdentifier = -1;
static gint ett_x411_ORName = -1;
static gint ett_x411_ORAddress = -1;
static gint ett_x411_BuiltInStandardAttributes = -1;
static gint ett_x411_CountryName = -1;
static gint ett_x411_AdministrationDomainName = -1;
static gint ett_x411_PrivateDomainName = -1;
static gint ett_x411_PersonalName = -1;
static gint ett_x411_OrganizationalUnitNames = -1;
static gint ett_x411_BuiltInDomainDefinedAttributes = -1;
static gint ett_x411_BuiltInDomainDefinedAttribute = -1;
static gint ett_x411_ExtensionAttributes = -1;
static gint ett_x411_ExtensionAttribute = -1;
static gint ett_x411_TeletexPersonalName = -1;
static gint ett_x411_UniversalPersonalName = -1;
static gint ett_x411_TeletexOrganizationalUnitNames = -1;
static gint ett_x411_UniversalOrganizationalUnitNames = -1;
static gint ett_x411_UniversalOrBMPString = -1;
static gint ett_x411_T_character_encoding = -1;
static gint ett_x411_PhysicalDeliveryCountryName = -1;
static gint ett_x411_PostalCode = -1;
static gint ett_x411_UnformattedPostalAddress = -1;
static gint ett_x411_T_printable_address = -1;
static gint ett_x411_PDSParameter = -1;
static gint ett_x411_ExtendedNetworkAddress = -1;
static gint ett_x411_T_e163_4_address = -1;
static gint ett_x411_TeletexDomainDefinedAttributes = -1;
static gint ett_x411_TeletexDomainDefinedAttribute = -1;
static gint ett_x411_UniversalDomainDefinedAttributes = -1;
static gint ett_x411_UniversalDomainDefinedAttribute = -1;
static gint ett_x411_EncodedInformationTypes = -1;
static gint ett_x411_BuiltInEncodedInformationTypes = -1;
static gint ett_x411_ExtendedEncodedInformationTypes = -1;
static gint ett_x411_NonBasicParameters = -1;
static gint ett_x411_G3FacsimileNonBasicParameters = -1;
static gint ett_x411_TeletexNonBasicParameters = -1;
static gint ett_x411_Token = -1;
static gint ett_x411_AsymmetricTokenData = -1;
static gint ett_x411_T_name = -1;
static gint ett_x411_MTANameAndOptionalGDI = -1;
static gint ett_x411_AsymmetricToken = -1;
static gint ett_x411_SecurityLabel = -1;
static gint ett_x411_SecurityCategories = -1;
static gint ett_x411_SecurityCategory = -1;

/*--- End of included file: packet-x411-ett.c ---*/
#line 78 "packet-x411-template.c"


/*--- Included file: packet-x411-fn.c ---*/
#line 1 "packet-x411-fn.c"
/*--- Fields for imported types ---*/

static int dissect_certificate_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_Certificates(TRUE, tvb, offset, pinfo, tree, hf_x411_certificate);
}
static int dissect_certificate_selector_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CertificateAssertion(TRUE, tvb, offset, pinfo, tree, hf_x411_certificate_selector);
}
static int dissect_algorithmIdentifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_x411_algorithmIdentifier);
}
static int dissect_mta_directory_name_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Name(TRUE, tvb, offset, pinfo, tree, hf_x411_mta_directory_name);
}
static int dissect_directory_entry_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Name(TRUE, tvb, offset, pinfo, tree, hf_x411_directory_entry);
}
static int dissect_encryption_recipient_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CertificateAssertion(TRUE, tvb, offset, pinfo, tree, hf_x411_encryption_recipient);
}
static int dissect_encryption_originator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CertificateAssertion(TRUE, tvb, offset, pinfo, tree, hf_x411_encryption_originator);
}
static int dissect_content_integrity_check_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CertificateAssertion(TRUE, tvb, offset, pinfo, tree, hf_x411_content_integrity_check);
}
static int dissect_token_signature_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CertificateAssertion(TRUE, tvb, offset, pinfo, tree, hf_x411_token_signature);
}
static int dissect_message_origin_authentication_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CertificateAssertion(TRUE, tvb, offset, pinfo, tree, hf_x411_message_origin_authentication);
}
static int dissect_directory_name_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Name(TRUE, tvb, offset, pinfo, tree, hf_x411_directory_name);
}
static int dissect_psap_address_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_PresentationAddress(TRUE, tvb, offset, pinfo, tree, hf_x411_psap_address);
}
static int dissect_signature_algorithm_identifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_x411_signature_algorithm_identifier);
}
static int dissect_encryption_algorithm_identifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_AlgorithmIdentifier(TRUE, tvb, offset, pinfo, tree, hf_x411_encryption_algorithm_identifier);
}
static int dissect_algorithm_identifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_x411_algorithm_identifier);
}



static int
dissect_x411_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_unauthenticated(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_NULL(FALSE, tvb, offset, pinfo, tree, hf_x411_unauthenticated);
}
static int dissect_empty_result(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_NULL(FALSE, tvb, offset, pinfo, tree, hf_x411_empty_result);
}



static int
dissect_x411_MTAName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 376 "x411.cnf"
	tvbuff_t	*mtaname = NULL;

	  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            pinfo, tree, tvb, offset, hf_index,
                                            &mtaname);


	if(doing_address) {

		proto_item_append_text(address_item, " %s", tvb_format_text(mtaname, 0, tvb_length(mtaname)));

	} else {

	if (check_col(pinfo->cinfo, COL_INFO) && mtaname) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s", tvb_format_text(mtaname, 0, tvb_length(mtaname)));
	}

	}



  return offset;
}
static int dissect_authenticated_initiator_name_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MTAName(TRUE, tvb, offset, pinfo, tree, hf_x411_authenticated_initiator_name);
}
static int dissect_authenticated_responder_name_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MTAName(TRUE, tvb, offset, pinfo, tree, hf_x411_authenticated_responder_name);
}
static int dissect_mta_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MTAName(FALSE, tvb, offset, pinfo, tree, hf_x411_mta_name);
}
static int dissect_mta(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MTAName(FALSE, tvb, offset, pinfo, tree, hf_x411_mta);
}
static int dissect_mTA_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MTAName(TRUE, tvb, offset, pinfo, tree, hf_x411_mTA);
}



static int
dissect_x411_IA5String(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_ia5_string(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_IA5String(FALSE, tvb, offset, pinfo, tree, hf_x411_ia5_string);
}
static int dissect_ia5text(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_IA5String(FALSE, tvb, offset, pinfo, tree, hf_x411_ia5text);
}



static int
dissect_x411_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_octet_string(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_x411_octet_string);
}
static int dissect_octets(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_x411_octets);
}
static int dissect_page_formats_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_x411_page_formats);
}
static int dissect_private_use_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_x411_private_use);
}


static const value_string x411_Password_vals[] = {
  {   0, "ia5-string" },
  {   1, "octet-string" },
  { 0, NULL }
};

static const ber_choice_t Password_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_ia5_string },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_octet_string },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_Password(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Password_choice, hf_index, ett_x411_Password,
                                 NULL);

  return offset;
}
static int dissect_simple(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_Password(FALSE, tvb, offset, pinfo, tree, hf_x411_simple);
}



static int
dissect_x411_TokenTypeIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_index, &object_identifier_id);

  return offset;
}
static int dissect_token_type_identifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_TokenTypeIdentifier(TRUE, tvb, offset, pinfo, tree, hf_x411_token_type_identifier);
}



static int
dissect_x411_TokenTypeData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 646 "x411.cnf"
	
	if(object_identifier_id) 
   	   call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);



  return offset;
}
static int dissect_token_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_TokenTypeData(TRUE, tvb, offset, pinfo, tree, hf_x411_token);
}


static const ber_sequence_t Token_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_token_type_identifier_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_token_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_Token(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Token_sequence, hf_index, ett_x411_Token);

  return offset;
}
static int dissect_bind_token_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_Token(TRUE, tvb, offset, pinfo, tree, hf_x411_bind_token);
}


static const ber_sequence_t StrongCredentials_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_bind_token_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_certificate_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_certificate_selector_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_StrongCredentials(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              StrongCredentials_set, hf_index, ett_x411_StrongCredentials);

  return offset;
}
static int dissect_strong_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_StrongCredentials(TRUE, tvb, offset, pinfo, tree, hf_x411_strong);
}



static int
dissect_x411_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}
static int dissect_random1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_BIT_STRING(TRUE, tvb, offset, pinfo, tree, hf_x411_random1);
}
static int dissect_random2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_BIT_STRING(TRUE, tvb, offset, pinfo, tree, hf_x411_random2);
}
static int dissect_encrypted(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_BIT_STRING(FALSE, tvb, offset, pinfo, tree, hf_x411_encrypted);
}
static int dissect_encrypted_data_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_BIT_STRING(TRUE, tvb, offset, pinfo, tree, hf_x411_encrypted_data);
}


static const ber_sequence_t Signature_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_Signature(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Signature_sequence, hf_index, ett_x411_Signature);

  return offset;
}
static int dissect_signature(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_Signature(FALSE, tvb, offset, pinfo, tree, hf_x411_signature);
}



static int
dissect_x411_UTCTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTCTime,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_time1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_UTCTime(TRUE, tvb, offset, pinfo, tree, hf_x411_time1);
}
static int dissect_time2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_UTCTime(TRUE, tvb, offset, pinfo, tree, hf_x411_time2);
}


static const ber_sequence_t ProtectedPassword_set[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signature },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_time1_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_time2_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_random1_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_random2_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_ProtectedPassword(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ProtectedPassword_set, hf_index, ett_x411_ProtectedPassword);

  return offset;
}
static int dissect_protected_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ProtectedPassword(TRUE, tvb, offset, pinfo, tree, hf_x411_protected);
}


static const value_string x411_Credentials_vals[] = {
  {   0, "simple" },
  {   1, "strong" },
  {   2, "protected" },
  { 0, NULL }
};

static const ber_choice_t Credentials_choice[] = {
  {   0, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_simple },
  {   1, BER_CLASS_CON, 0, 0, dissect_strong_impl },
  {   2, BER_CLASS_CON, 1, 0, dissect_protected_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_Credentials(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 654 "x411.cnf"
  guint32 credentials;

    offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Credentials_choice, hf_index, ett_x411_Credentials,
                                 &credentials);


  if (check_col(pinfo->cinfo, COL_INFO)) {
	if(credentials == -1) credentials = 0;
	col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(credentials, x411_Credentials_vals, "Credentials(%d)"));
  }



  return offset;
}
static int dissect_old_credentials_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_Credentials(TRUE, tvb, offset, pinfo, tree, hf_x411_old_credentials);
}
static int dissect_new_credentials_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_Credentials(TRUE, tvb, offset, pinfo, tree, hf_x411_new_credentials);
}



static int
dissect_x411_InitiatorCredentials(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_Credentials(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_initiator_credentials_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_InitiatorCredentials(TRUE, tvb, offset, pinfo, tree, hf_x411_initiator_credentials);
}



static int
dissect_x411_SecurityPolicyIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_security_policy_identifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SecurityPolicyIdentifier(FALSE, tvb, offset, pinfo, tree, hf_x411_security_policy_identifier);
}


static const value_string x411_SecurityClassification_vals[] = {
  {   0, "unmarked" },
  {   1, "unclassified" },
  {   2, "restricted" },
  {   3, "confidential" },
  {   4, "secret" },
  {   5, "top-secret" },
  { 0, NULL }
};


static int
dissect_x411_SecurityClassification(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_security_classification(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SecurityClassification(FALSE, tvb, offset, pinfo, tree, hf_x411_security_classification);
}



static int
dissect_x411_PrivacyMark(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_privacy_mark(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PrivacyMark(FALSE, tvb, offset, pinfo, tree, hf_x411_privacy_mark);
}



static int
dissect_x411_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 323 "x411.cnf"

	  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_index, &object_identifier_id);

	extension_id = -1;



  return offset;
}
static int dissect_private_extension_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_OBJECT_IDENTIFIER(TRUE, tvb, offset, pinfo, tree, hf_x411_private_extension);
}
static int dissect_category_type_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_OBJECT_IDENTIFIER(TRUE, tvb, offset, pinfo, tree, hf_x411_category_type);
}



static int
dissect_x411_CategoryValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 244 "x411.cnf"

	offset = dissect_unknown_ber(pinfo, tvb, offset, tree);



  return offset;
}
static int dissect_category_value_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_CategoryValue(TRUE, tvb, offset, pinfo, tree, hf_x411_category_value);
}


static const ber_sequence_t SecurityCategory_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_category_type_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_category_value_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_SecurityCategory(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SecurityCategory_sequence, hf_index, ett_x411_SecurityCategory);

  return offset;
}
static int dissect_SecurityCategories_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SecurityCategory(FALSE, tvb, offset, pinfo, tree, hf_x411_SecurityCategories_item);
}


static const ber_sequence_t SecurityCategories_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_SecurityCategories_item },
};

static int
dissect_x411_SecurityCategories(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SecurityCategories_set_of, hf_index, ett_x411_SecurityCategories);

  return offset;
}
static int dissect_security_categories(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SecurityCategories(FALSE, tvb, offset, pinfo, tree, hf_x411_security_categories);
}


static const ber_sequence_t SecurityLabel_set[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_security_policy_identifier },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_security_classification },
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_privacy_mark },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_security_categories },
  { 0, 0, 0, NULL }
};

int
dissect_x411_SecurityLabel(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              SecurityLabel_set, hf_index, ett_x411_SecurityLabel);

  return offset;
}
static int dissect_SecurityContext_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SecurityLabel(FALSE, tvb, offset, pinfo, tree, hf_x411_SecurityContext_item);
}


static const ber_sequence_t SecurityContext_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_SecurityContext_item },
};

int
dissect_x411_SecurityContext(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SecurityContext_set_of, hf_index, ett_x411_SecurityContext);

  return offset;
}
static int dissect_security_context_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SecurityContext(TRUE, tvb, offset, pinfo, tree, hf_x411_security_context);
}
static int dissect_permissible_security_context_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SecurityContext(TRUE, tvb, offset, pinfo, tree, hf_x411_permissible_security_context);
}
static int dissect_security_labels_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SecurityContext(TRUE, tvb, offset, pinfo, tree, hf_x411_security_labels);
}


static const ber_sequence_t AuthenticatedArgument_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_authenticated_initiator_name_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_initiator_credentials_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_security_context_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_AuthenticatedArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              AuthenticatedArgument_set, hf_index, ett_x411_AuthenticatedArgument);

  return offset;
}
static int dissect_authenticated_argument_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_AuthenticatedArgument(TRUE, tvb, offset, pinfo, tree, hf_x411_authenticated_argument);
}


static const value_string x411_MTABindArgument_vals[] = {
  {   0, "unauthenticated" },
  {   1, "authenticated" },
  { 0, NULL }
};

static const ber_choice_t MTABindArgument_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_unauthenticated },
  {   1, BER_CLASS_CON, 1, 0, dissect_authenticated_argument_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_MTABindArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 MTABindArgument_choice, hf_index, ett_x411_MTABindArgument,
                                 NULL);

  return offset;
}



static int
dissect_x411_ResponderCredentials(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_Credentials(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_responder_credentials_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ResponderCredentials(TRUE, tvb, offset, pinfo, tree, hf_x411_responder_credentials);
}


static const ber_sequence_t AuthenticatedResult_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_authenticated_responder_name_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_responder_credentials_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_AuthenticatedResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              AuthenticatedResult_set, hf_index, ett_x411_AuthenticatedResult);

  return offset;
}
static int dissect_authenticated_result_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_AuthenticatedResult(TRUE, tvb, offset, pinfo, tree, hf_x411_authenticated_result);
}


static const value_string x411_MTABindResult_vals[] = {
  {   0, "unauthenticated" },
  {   1, "authenticated" },
  { 0, NULL }
};

static const ber_choice_t MTABindResult_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_unauthenticated },
  {   1, BER_CLASS_CON, 1, 0, dissect_authenticated_result_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_MTABindResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 MTABindResult_choice, hf_index, ett_x411_MTABindResult,
                                 NULL);

  return offset;
}


static const value_string x411_MTABindError_vals[] = {
  {   0, "busy" },
  {   2, "authentication-error" },
  {   3, "unacceptable-dialogue-mode" },
  {   4, "unacceptable-security-context" },
  {   5, "inadequate-association-confidentiality" },
  { 0, NULL }
};


static int
dissect_x411_MTABindError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 637 "x411.cnf"
  int error = -1;
    offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &error);

  if((error != -1) && check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", val_to_str(error, x411_MTABindError_vals, "error(%d)"));



  return offset;
}



static int
dissect_x411_NumericString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 465 "x411.cnf"
	tvbuff_t	*nstring = NULL;

	  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            &nstring);


	if(doing_address && nstring)
		g_strlcat(oraddress, tvb_format_text(nstring, 0, tvb_length(nstring)), MAX_ORA_STR_LEN);



  return offset;
}
static int dissect_x121_address(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_NumericString(FALSE, tvb, offset, pinfo, tree, hf_x411_x121_address);
}
static int dissect_numeric(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_NumericString(FALSE, tvb, offset, pinfo, tree, hf_x411_numeric);
}
static int dissect_x121_dcc_code(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_NumericString(FALSE, tvb, offset, pinfo, tree, hf_x411_x121_dcc_code);
}
static int dissect_numeric_code(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_NumericString(FALSE, tvb, offset, pinfo, tree, hf_x411_numeric_code);
}
static int dissect_number_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_NumericString(TRUE, tvb, offset, pinfo, tree, hf_x411_number);
}
static int dissect_sub_address_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_NumericString(TRUE, tvb, offset, pinfo, tree, hf_x411_sub_address);
}



static int
dissect_x411_PrintableString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 487 "x411.cnf"
	tvbuff_t	*pstring = NULL;
	char 		*fmt = NULL;

	  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            &pstring);


	if(doing_address && pstring) {
  	  if(hf_index == hf_x411_printable_surname)			fmt = "/S=";
	  else if(hf_index == hf_x411_printable_given_name)		fmt = "/G=";
	  else if(hf_index == hf_x411_printable_initials)		fmt = "/I=";
	  else if(hf_index == hf_x411_printable_generation_qualifier)	fmt = "/GQ=";
	  else if(hf_index == hf_x411_printable_type)			fmt = "/DD.";
	  else if(hf_index == hf_x411_printable_value)			fmt = "=";
		
	  if(fmt)
	    g_strlcat(oraddress, fmt, MAX_ORA_STR_LEN);

	  g_strlcat(oraddress, tvb_format_text(pstring, 0, tvb_length(pstring)), MAX_ORA_STR_LEN);

	}



  return offset;
}
static int dissect_tsap_id(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PrintableString(FALSE, tvb, offset, pinfo, tree, hf_x411_tsap_id);
}
static int dissect_printable(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PrintableString(FALSE, tvb, offset, pinfo, tree, hf_x411_printable);
}
static int dissect_iso_3166_alpha2_code(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PrintableString(FALSE, tvb, offset, pinfo, tree, hf_x411_iso_3166_alpha2_code);
}
static int dissect_printable_surname_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PrintableString(TRUE, tvb, offset, pinfo, tree, hf_x411_printable_surname);
}
static int dissect_printable_given_name_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PrintableString(TRUE, tvb, offset, pinfo, tree, hf_x411_printable_given_name);
}
static int dissect_printable_initials_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PrintableString(TRUE, tvb, offset, pinfo, tree, hf_x411_printable_initials);
}
static int dissect_printable_generation_qualifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PrintableString(TRUE, tvb, offset, pinfo, tree, hf_x411_printable_generation_qualifier);
}
static int dissect_printable_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PrintableString(FALSE, tvb, offset, pinfo, tree, hf_x411_printable_type);
}
static int dissect_printable_value(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PrintableString(FALSE, tvb, offset, pinfo, tree, hf_x411_printable_value);
}
static int dissect_iso_639_language_code(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PrintableString(FALSE, tvb, offset, pinfo, tree, hf_x411_iso_639_language_code);
}
static int dissect_printable_code(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PrintableString(FALSE, tvb, offset, pinfo, tree, hf_x411_printable_code);
}
static int dissect_printable_address_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PrintableString(FALSE, tvb, offset, pinfo, tree, hf_x411_printable_address_item);
}
static int dissect_printable_string(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PrintableString(FALSE, tvb, offset, pinfo, tree, hf_x411_printable_string);
}


static const value_string x411_CountryName_vals[] = {
  {   0, "x121-dcc-code" },
  {   1, "iso-3166-alpha2-code" },
  { 0, NULL }
};

static const ber_choice_t CountryName_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_x121_dcc_code },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_iso_3166_alpha2_code },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_CountryName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 255 "x411.cnf"
 gint8 class;
 gboolean pc, ind_field;
 gint32 tag;
 guint32 len1;

 if(!implicit_tag){
   /* XXX  asn2eth can not yet handle tagged assignment yes so this
    * XXX is some conformance file magic to work around that bug
    */
    offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
    offset = get_ber_length(tree, tvb, offset, &len1, &ind_field);
 }

 if(doing_address)
    g_strlcat(oraddress, "/C=", MAX_ORA_STR_LEN);

  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              CountryName_choice, hf_index, ett_x411_CountryName, NULL);





  return offset;
}
static int dissect_country_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_CountryName(FALSE, tvb, offset, pinfo, tree, hf_x411_country_name);
}


static const value_string x411_AdministrationDomainName_vals[] = {
  {   0, "numeric" },
  {   1, "printable" },
  { 0, NULL }
};

static const ber_choice_t AdministrationDomainName_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_numeric },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_printable },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_AdministrationDomainName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 277 "x411.cnf"
 gint8 class;
 gboolean pc, ind_field;
 gint32 tag;
 guint32 len1;

 if(!implicit_tag){
   /* XXX  asn2eth can not yet handle tagged assignment yes so this
    * XXX is some conformance file magic to work around that bug
    */
    offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
    offset = get_ber_length(tree, tvb, offset, &len1, &ind_field);
 }

  if(doing_address)
    g_strlcat(oraddress, "/A=", MAX_ORA_STR_LEN);

  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              AdministrationDomainName_choice, hf_index, ett_x411_AdministrationDomainName, NULL);



  return offset;
}
static int dissect_administration_domain_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_AdministrationDomainName(FALSE, tvb, offset, pinfo, tree, hf_x411_administration_domain_name);
}
static int dissect_administration_domain_name_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_AdministrationDomainName(TRUE, tvb, offset, pinfo, tree, hf_x411_administration_domain_name);
}


static const value_string x411_PrivateDomainIdentifier_vals[] = {
  {   0, "numeric" },
  {   1, "printable" },
  { 0, NULL }
};

static const ber_choice_t PrivateDomainIdentifier_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_numeric },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_printable },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_PrivateDomainIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 427 "x411.cnf"

	if(doing_address)
		g_strlcat(oraddress, "/P=", MAX_ORA_STR_LEN);

	  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 PrivateDomainIdentifier_choice, hf_index, ett_x411_PrivateDomainIdentifier,
                                 NULL);




  return offset;
}
static int dissect_private_domain_identifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PrivateDomainIdentifier(FALSE, tvb, offset, pinfo, tree, hf_x411_private_domain_identifier);
}
static int dissect_private_domain_identifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PrivateDomainIdentifier(TRUE, tvb, offset, pinfo, tree, hf_x411_private_domain_identifier);
}


static const ber_sequence_t GlobalDomainIdentifier_sequence[] = {
  { BER_CLASS_APP, 1, BER_FLAGS_NOOWNTAG, dissect_country_name },
  { BER_CLASS_APP, 2, BER_FLAGS_NOOWNTAG, dissect_administration_domain_name },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_private_domain_identifier },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_GlobalDomainIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 534 "x411.cnf"
	
	oraddress = ep_alloc(MAX_ORA_STR_LEN); oraddress[0] = '\0';	
	address_item = tree;

	  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GlobalDomainIdentifier_sequence, hf_index, ett_x411_GlobalDomainIdentifier);


	if(*oraddress)
		proto_item_append_text(address_item, " (%s/", oraddress);




  return offset;
}
static int dissect_global_domain_identifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_GlobalDomainIdentifier(FALSE, tvb, offset, pinfo, tree, hf_x411_global_domain_identifier);
}
static int dissect_domain(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_GlobalDomainIdentifier(FALSE, tvb, offset, pinfo, tree, hf_x411_domain);
}
static int dissect_attempted_domain(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_GlobalDomainIdentifier(FALSE, tvb, offset, pinfo, tree, hf_x411_attempted_domain);
}



static int
dissect_x411_LocalIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 548 "x411.cnf"
	tvbuff_t 	*id = NULL;
	
	  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            pinfo, tree, tvb, offset, hf_index,
                                            &id);

	
	if(doing_address && id)
	  proto_item_append_text(address_item, " $ %s)", tvb_format_text(id, 0, tvb_length(id)));



  return offset;
}
static int dissect_local_identifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_LocalIdentifier(FALSE, tvb, offset, pinfo, tree, hf_x411_local_identifier);
}


static const ber_sequence_t MTSIdentifier_sequence[] = {
  { BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_global_domain_identifier },
  { BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_local_identifier },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_MTSIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 556 "x411.cnf"

	doing_address = TRUE;

	  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MTSIdentifier_sequence, hf_index, ett_x411_MTSIdentifier);


	doing_address = FALSE;



  return offset;
}



static int
dissect_x411_MessageIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_MTSIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_message_identifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MessageIdentifier(FALSE, tvb, offset, pinfo, tree, hf_x411_message_identifier);
}



static int
dissect_x411_X121Address(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 396 "x411.cnf"
	tvbuff_t	*string = NULL;

	  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            &string);


	if(doing_address && string) {
		g_strlcat(oraddress, "/X121=", MAX_ORA_STR_LEN);
		g_strlcat(oraddress, tvb_format_text(string, 0, tvb_length(string)), MAX_ORA_STR_LEN);
	}




  return offset;
}



static int
dissect_x411_NetworkAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_X121Address(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_network_address_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_NetworkAddress(TRUE, tvb, offset, pinfo, tree, hf_x411_network_address);
}



static int
dissect_x411_TerminalIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 410 "x411.cnf"
	tvbuff_t	*string = NULL;

	  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            &string);


	if(doing_address && string) {
		g_strlcat(oraddress, "/UA-ID=", MAX_ORA_STR_LEN);
		g_strlcat(oraddress, tvb_format_text(string, 0, tvb_length(string)), MAX_ORA_STR_LEN);
	}



  return offset;
}
static int dissect_terminal_identifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_TerminalIdentifier(TRUE, tvb, offset, pinfo, tree, hf_x411_terminal_identifier);
}


static const value_string x411_PrivateDomainName_vals[] = {
  {   0, "numeric" },
  {   1, "printable" },
  { 0, NULL }
};

static const ber_choice_t PrivateDomainName_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_numeric },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_printable },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_PrivateDomainName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 420 "x411.cnf"

	if(doing_address)
		g_strlcat(oraddress, "/P=", MAX_ORA_STR_LEN);

	  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 PrivateDomainName_choice, hf_index, ett_x411_PrivateDomainName,
                                 NULL);




  return offset;
}
static int dissect_private_domain_name_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PrivateDomainName(TRUE, tvb, offset, pinfo, tree, hf_x411_private_domain_name);
}



static int
dissect_x411_OrganizationName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 437 "x411.cnf"
	tvbuff_t	*string = NULL;

	  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            &string);


	if(doing_address && string) {
		g_strlcat(oraddress, "/O=", MAX_ORA_STR_LEN);
		g_strlcat(oraddress, tvb_format_text(string, 0, tvb_length(string)), MAX_ORA_STR_LEN);
	}



  return offset;
}
static int dissect_organization_name_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_OrganizationName(TRUE, tvb, offset, pinfo, tree, hf_x411_organization_name);
}



static int
dissect_x411_NumericUserIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_numeric_user_identifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_NumericUserIdentifier(TRUE, tvb, offset, pinfo, tree, hf_x411_numeric_user_identifier);
}


static const ber_sequence_t PersonalName_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_printable_surname_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_printable_given_name_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_printable_initials_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_printable_generation_qualifier_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_PersonalName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              PersonalName_set, hf_index, ett_x411_PersonalName);

  return offset;
}
static int dissect_personal_name_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PersonalName(TRUE, tvb, offset, pinfo, tree, hf_x411_personal_name);
}



static int
dissect_x411_OrganizationalUnitName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_OrganizationalUnitNames_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_OrganizationalUnitName(FALSE, tvb, offset, pinfo, tree, hf_x411_OrganizationalUnitNames_item);
}


static const ber_sequence_t OrganizationalUnitNames_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_OrganizationalUnitNames_item },
};

static int
dissect_x411_OrganizationalUnitNames(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      OrganizationalUnitNames_sequence_of, hf_index, ett_x411_OrganizationalUnitNames);

  return offset;
}
static int dissect_organizational_unit_names_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_OrganizationalUnitNames(TRUE, tvb, offset, pinfo, tree, hf_x411_organizational_unit_names);
}


static const ber_sequence_t BuiltInStandardAttributes_sequence[] = {
  { BER_CLASS_APP, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_country_name },
  { BER_CLASS_APP, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_administration_domain_name },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_network_address_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminal_identifier_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_private_domain_name_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_organization_name_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_numeric_user_identifier_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_personal_name_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_organizational_unit_names_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_BuiltInStandardAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 573 "x411.cnf"

	address_item = tree;	

	  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   BuiltInStandardAttributes_sequence, hf_index, ett_x411_BuiltInStandardAttributes);




  return offset;
}
static int dissect_built_in_standard_attributes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_BuiltInStandardAttributes(FALSE, tvb, offset, pinfo, tree, hf_x411_built_in_standard_attributes);
}


static const ber_sequence_t BuiltInDomainDefinedAttribute_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_printable_type },
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_printable_value },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_BuiltInDomainDefinedAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   BuiltInDomainDefinedAttribute_sequence, hf_index, ett_x411_BuiltInDomainDefinedAttribute);

  return offset;
}
static int dissect_BuiltInDomainDefinedAttributes_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_BuiltInDomainDefinedAttribute(FALSE, tvb, offset, pinfo, tree, hf_x411_BuiltInDomainDefinedAttributes_item);
}


static const ber_sequence_t BuiltInDomainDefinedAttributes_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_BuiltInDomainDefinedAttributes_item },
};

static int
dissect_x411_BuiltInDomainDefinedAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      BuiltInDomainDefinedAttributes_sequence_of, hf_index, ett_x411_BuiltInDomainDefinedAttributes);

  return offset;
}
static int dissect_built_in_domain_defined_attributes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_BuiltInDomainDefinedAttributes(FALSE, tvb, offset, pinfo, tree, hf_x411_built_in_domain_defined_attributes);
}



static int
dissect_x411_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &extension_id);

  return offset;
}
static int dissect_messages_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_x411_messages);
}
static int dissect_delivery_queue_octets_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_x411_delivery_queue_octets);
}
static int dissect_standard_extension_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_x411_standard_extension);
}
static int dissect_extension_attribute_type_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_x411_extension_attribute_type);
}



static int
dissect_x411_T_extension_attribute_value(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 248 "x411.cnf"

	offset=call_x411_oid_callback("x411.extension-attribute", tvb, offset, pinfo, tree);



  return offset;
}
static int dissect_extension_attribute_value_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_T_extension_attribute_value(TRUE, tvb, offset, pinfo, tree, hf_x411_extension_attribute_value);
}


static const ber_sequence_t ExtensionAttribute_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_extension_attribute_type_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_extension_attribute_value_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_ExtensionAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ExtensionAttribute_sequence, hf_index, ett_x411_ExtensionAttribute);

  return offset;
}
static int dissect_ExtensionAttributes_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ExtensionAttribute(FALSE, tvb, offset, pinfo, tree, hf_x411_ExtensionAttributes_item);
}


static const ber_sequence_t ExtensionAttributes_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ExtensionAttributes_item },
};

static int
dissect_x411_ExtensionAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 ExtensionAttributes_set_of, hf_index, ett_x411_ExtensionAttributes);

  return offset;
}
static int dissect_extension_attributes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ExtensionAttributes(FALSE, tvb, offset, pinfo, tree, hf_x411_extension_attributes);
}


static const ber_sequence_t ORName_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_built_in_standard_attributes },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_built_in_domain_defined_attributes },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extension_attributes },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_directory_name_impl },
  { 0, 0, 0, NULL }
};

int
dissect_x411_ORName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 521 "x411.cnf"
	
	oraddress = ep_alloc(MAX_ORA_STR_LEN); oraddress[0] = '\0';	
	address_item = NULL;
	doing_address = TRUE;

	  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ORName_sequence, hf_index, ett_x411_ORName);


	if(*oraddress && address_item)
		proto_item_append_text(address_item, " (%s/)", oraddress);

	doing_address = FALSE;



  return offset;
}
static int dissect_exact_match_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ORName(TRUE, tvb, offset, pinfo, tree, hf_x411_exact_match);
}
static int dissect_pattern_match_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ORName(TRUE, tvb, offset, pinfo, tree, hf_x411_pattern_match);
}



static int
dissect_x411_ORAddressAndOptionalDirectoryName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_ORName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_user_agent(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ORAddressAndOptionalDirectoryName(FALSE, tvb, offset, pinfo, tree, hf_x411_user_agent);
}
static int dissect_message_store_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ORAddressAndOptionalDirectoryName(TRUE, tvb, offset, pinfo, tree, hf_x411_message_store);
}
static int dissect_intended_recipient(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ORAddressAndOptionalDirectoryName(FALSE, tvb, offset, pinfo, tree, hf_x411_intended_recipient);
}
static int dissect_dl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ORAddressAndOptionalDirectoryName(FALSE, tvb, offset, pinfo, tree, hf_x411_dl);
}
static int dissect_originator_or_dl_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ORAddressAndOptionalDirectoryName(FALSE, tvb, offset, pinfo, tree, hf_x411_originator_or_dl_name);
}



static int
dissect_x411_MTAOriginatorName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_mta_originator_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MTAOriginatorName(FALSE, tvb, offset, pinfo, tree, hf_x411_mta_originator_name);
}


static const asn_namedbit BuiltInEncodedInformationTypes_bits[] = {
  {  0, &hf_x411_BuiltInEncodedInformationTypes_unknown, -1, -1, "unknown", NULL },
  {  2, &hf_x411_BuiltInEncodedInformationTypes_ia5_text, -1, -1, "ia5-text", NULL },
  {  3, &hf_x411_BuiltInEncodedInformationTypes_g3_facsimile, -1, -1, "g3-facsimile", NULL },
  {  4, &hf_x411_BuiltInEncodedInformationTypes_g4_class_1, -1, -1, "g4-class-1", NULL },
  {  5, &hf_x411_BuiltInEncodedInformationTypes_teletex, -1, -1, "teletex", NULL },
  {  6, &hf_x411_BuiltInEncodedInformationTypes_videotex, -1, -1, "videotex", NULL },
  {  7, &hf_x411_BuiltInEncodedInformationTypes_voice, -1, -1, "voice", NULL },
  {  8, &hf_x411_BuiltInEncodedInformationTypes_sfd, -1, -1, "sfd", NULL },
  {  9, &hf_x411_BuiltInEncodedInformationTypes_mixed_mode, -1, -1, "mixed-mode", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x411_BuiltInEncodedInformationTypes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    BuiltInEncodedInformationTypes_bits, hf_index, ett_x411_BuiltInEncodedInformationTypes,
                                    NULL);

  return offset;
}
static int dissect_built_in_encoded_information_types_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_BuiltInEncodedInformationTypes(TRUE, tvb, offset, pinfo, tree, hf_x411_built_in_encoded_information_types);
}


static const asn_namedbit G3FacsimileNonBasicParameters_bits[] = {
  {  8, &hf_x411_G3FacsimileNonBasicParameters_two_dimensional, -1, -1, "two-dimensional", NULL },
  {  9, &hf_x411_G3FacsimileNonBasicParameters_fine_resolution, -1, -1, "fine-resolution", NULL },
  { 20, &hf_x411_G3FacsimileNonBasicParameters_unlimited_length, -1, -1, "unlimited-length", NULL },
  { 21, &hf_x411_G3FacsimileNonBasicParameters_b4_length, -1, -1, "b4-length", NULL },
  { 22, &hf_x411_G3FacsimileNonBasicParameters_a3_width, -1, -1, "a3-width", NULL },
  { 23, &hf_x411_G3FacsimileNonBasicParameters_b4_width, -1, -1, "b4-width", NULL },
  { 25, &hf_x411_G3FacsimileNonBasicParameters_t6_coding, -1, -1, "t6-coding", NULL },
  { 30, &hf_x411_G3FacsimileNonBasicParameters_uncompressed, -1, -1, "uncompressed", NULL },
  { 37, &hf_x411_G3FacsimileNonBasicParameters_width_middle_864_of_1728, -1, -1, "width-middle-864-of-1728", NULL },
  { 38, &hf_x411_G3FacsimileNonBasicParameters_width_middle_1216_of_1728, -1, -1, "width-middle-1216-of-1728", NULL },
  { 44, &hf_x411_G3FacsimileNonBasicParameters_resolution_type, -1, -1, "resolution-type", NULL },
  { 45, &hf_x411_G3FacsimileNonBasicParameters_resolution_400x400, -1, -1, "resolution-400x400", NULL },
  { 46, &hf_x411_G3FacsimileNonBasicParameters_resolution_300x300, -1, -1, "resolution-300x300", NULL },
  { 47, &hf_x411_G3FacsimileNonBasicParameters_resolution_8x15, -1, -1, "resolution-8x15", NULL },
  { 49, &hf_x411_G3FacsimileNonBasicParameters_edi, -1, -1, "edi", NULL },
  { 50, &hf_x411_G3FacsimileNonBasicParameters_dtm, -1, -1, "dtm", NULL },
  { 51, &hf_x411_G3FacsimileNonBasicParameters_bft, -1, -1, "bft", NULL },
  { 58, &hf_x411_G3FacsimileNonBasicParameters_mixed_mode, -1, -1, "mixed-mode", NULL },
  { 60, &hf_x411_G3FacsimileNonBasicParameters_character_mode, -1, -1, "character-mode", NULL },
  { 65, &hf_x411_G3FacsimileNonBasicParameters_twelve_bits, -1, -1, "twelve-bits", NULL },
  { 66, &hf_x411_G3FacsimileNonBasicParameters_preferred_huffmann, -1, -1, "preferred-huffmann", NULL },
  { 67, &hf_x411_G3FacsimileNonBasicParameters_full_colour, -1, -1, "full-colour", NULL },
  { 68, &hf_x411_G3FacsimileNonBasicParameters_jpeg, -1, -1, "jpeg", NULL },
  { 71, &hf_x411_G3FacsimileNonBasicParameters_processable_mode_26, -1, -1, "processable-mode-26", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

int
dissect_x411_G3FacsimileNonBasicParameters(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    G3FacsimileNonBasicParameters_bits, hf_index, ett_x411_G3FacsimileNonBasicParameters,
                                    NULL);

  return offset;
}
static int dissect_g3_facsimile_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_G3FacsimileNonBasicParameters(TRUE, tvb, offset, pinfo, tree, hf_x411_g3_facsimile);
}



static int
dissect_x411_TeletexString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 475 "x411.cnf"
	tvbuff_t	*tstring = NULL;

	  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);


	if(doing_address && tstring) 
		g_strlcat(oraddress, tvb_format_text(tstring, 0, tvb_length(tstring)), MAX_ORA_STR_LEN);




  return offset;
}
static int dissect_teletex_surname_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_TeletexString(TRUE, tvb, offset, pinfo, tree, hf_x411_teletex_surname);
}
static int dissect_teletex_given_name_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_TeletexString(TRUE, tvb, offset, pinfo, tree, hf_x411_teletex_given_name);
}
static int dissect_teletex_initials_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_TeletexString(TRUE, tvb, offset, pinfo, tree, hf_x411_teletex_initials);
}
static int dissect_teletex_generation_qualifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_TeletexString(TRUE, tvb, offset, pinfo, tree, hf_x411_teletex_generation_qualifier);
}
static int dissect_teletex_string(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_TeletexString(FALSE, tvb, offset, pinfo, tree, hf_x411_teletex_string);
}
static int dissect_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_TeletexString(FALSE, tvb, offset, pinfo, tree, hf_x411_type);
}
static int dissect_teletex_value(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_TeletexString(FALSE, tvb, offset, pinfo, tree, hf_x411_teletex_value);
}
static int dissect_graphic_character_sets_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_TeletexString(TRUE, tvb, offset, pinfo, tree, hf_x411_graphic_character_sets);
}
static int dissect_control_character_sets_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_TeletexString(TRUE, tvb, offset, pinfo, tree, hf_x411_control_character_sets);
}
static int dissect_miscellaneous_terminal_capabilities_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_TeletexString(TRUE, tvb, offset, pinfo, tree, hf_x411_miscellaneous_terminal_capabilities);
}


static const ber_sequence_t TeletexNonBasicParameters_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_graphic_character_sets_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_control_character_sets_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_page_formats_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_miscellaneous_terminal_capabilities_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_private_use_impl },
  { 0, 0, 0, NULL }
};

int
dissect_x411_TeletexNonBasicParameters(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              TeletexNonBasicParameters_set, hf_index, ett_x411_TeletexNonBasicParameters);

  return offset;
}
static int dissect_teletex_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_TeletexNonBasicParameters(TRUE, tvb, offset, pinfo, tree, hf_x411_teletex);
}



static int
dissect_x411_ExtendedEncodedInformationType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_ExtendedEncodedInformationTypes_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ExtendedEncodedInformationType(FALSE, tvb, offset, pinfo, tree, hf_x411_ExtendedEncodedInformationTypes_item);
}


static const ber_sequence_t ExtendedEncodedInformationTypes_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_ExtendedEncodedInformationTypes_item },
};

static int
dissect_x411_ExtendedEncodedInformationTypes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 ExtendedEncodedInformationTypes_set_of, hf_index, ett_x411_ExtendedEncodedInformationTypes);

  return offset;
}
static int dissect_unacceptable_eits_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ExtendedEncodedInformationTypes(TRUE, tvb, offset, pinfo, tree, hf_x411_unacceptable_eits);
}
static int dissect_acceptable_eits_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ExtendedEncodedInformationTypes(TRUE, tvb, offset, pinfo, tree, hf_x411_acceptable_eits);
}
static int dissect_exclusively_acceptable_eits_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ExtendedEncodedInformationTypes(TRUE, tvb, offset, pinfo, tree, hf_x411_exclusively_acceptable_eits);
}
static int dissect_extended_encoded_information_types_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ExtendedEncodedInformationTypes(TRUE, tvb, offset, pinfo, tree, hf_x411_extended_encoded_information_types);
}


static const ber_sequence_t EncodedInformationTypes_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_built_in_encoded_information_types_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_g3_facsimile_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_teletex_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extended_encoded_information_types_impl },
  { 0, 0, 0, NULL }
};

int
dissect_x411_EncodedInformationTypes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              EncodedInformationTypes_set, hf_index, ett_x411_EncodedInformationTypes);

  return offset;
}
static int dissect_waiting_encoded_information_types(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_EncodedInformationTypes(FALSE, tvb, offset, pinfo, tree, hf_x411_waiting_encoded_information_types);
}



static int
dissect_x411_OriginalEncodedInformationTypes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_EncodedInformationTypes(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_original_encoded_information_types(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_OriginalEncodedInformationTypes(FALSE, tvb, offset, pinfo, tree, hf_x411_original_encoded_information_types);
}
static int dissect_original_encoded_information_types_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_OriginalEncodedInformationTypes(TRUE, tvb, offset, pinfo, tree, hf_x411_original_encoded_information_types);
}


static const value_string x411_BuiltInContentType_vals[] = {
  {   0, "unidentified" },
  {   1, "external" },
  {   2, "interpersonal-messaging-1984" },
  {  22, "interpersonal-messaging-1988" },
  {  35, "edi-messaging" },
  {  40, "voice-messaging" },
  { 0, NULL }
};


static int
dissect_x411_BuiltInContentType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 347 "x411.cnf"
  guint32	ict = -1;	

    offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &ict);


  /* convert integer content type to oid for dispatch when the content is found */
  switch(ict) {
	case 2:
	content_type_id = ep_strdup("2.6.1.10.0");
	break;
	case 22:
	content_type_id = ep_strdup("2.6.1.10.1");
	break;
	default:
	break;
	}



  return offset;
}
static int dissect_built_in(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_BuiltInContentType(FALSE, tvb, offset, pinfo, tree, hf_x411_built_in);
}
static int dissect_built_in_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_BuiltInContentType(TRUE, tvb, offset, pinfo, tree, hf_x411_built_in);
}



int
dissect_x411_ExtendedContentType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 331 "x411.cnf"
	const char *name = NULL;

	  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_index, &content_type_id);


	if(content_type_id) {
	  name = get_ber_oid_name(content_type_id);

  	  if(!name) name = content_type_id;

	  proto_item_append_text(tree, " (%s)", name);
	}



  return offset;
}
static int dissect_extended(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ExtendedContentType(FALSE, tvb, offset, pinfo, tree, hf_x411_extended);
}


static const value_string x411_ContentType_vals[] = {
  {   0, "built-in" },
  {   1, "extended" },
  { 0, NULL }
};

static const ber_choice_t ContentType_choice[] = {
  {   0, BER_CLASS_APP, 6, BER_FLAGS_NOOWNTAG, dissect_built_in },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_extended },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_ContentType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ContentType_choice, hf_index, ett_x411_ContentType,
                                 NULL);

  return offset;
}
static int dissect_content_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ContentType(FALSE, tvb, offset, pinfo, tree, hf_x411_content_type);
}
static int dissect_waiting_content_types_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ContentType(FALSE, tvb, offset, pinfo, tree, hf_x411_waiting_content_types_item);
}
static int dissect_ContentTypes_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ContentType(FALSE, tvb, offset, pinfo, tree, hf_x411_ContentTypes_item);
}



static int
dissect_x411_ContentIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 297 "x411.cnf"
 gint8 class;
 gboolean pc, ind_field;
 gint32 tag;
 guint32 len1;

 if(!implicit_tag){
   /* XXX  asn2eth can not yet handle tagged assignment yes so this
    * XXX is some conformance file magic to work around that bug
    */
    offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
    offset = get_ber_length(tree, tvb, offset, &len1, &ind_field);
 }

  /* this is magic I haven't seen used before - I've stripped the tag - but now I'm going to say it is IMPLICIT! */
  offset = dissect_ber_restricted_string(TRUE, BER_UNI_TAG_PrintableString,
                                         pinfo, tree, tvb, offset, hf_index,
                                         NULL);




  return offset;
}
static int dissect_content_identifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ContentIdentifier(FALSE, tvb, offset, pinfo, tree, hf_x411_content_identifier);
}
static int dissect_content_identifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ContentIdentifier(TRUE, tvb, offset, pinfo, tree, hf_x411_content_identifier);
}


static const value_string x411_Priority_vals[] = {
  {   0, "normal" },
  {   1, "non-urgent" },
  {   2, "urgent" },
  { 0, NULL }
};


static int
dissect_x411_Priority(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_priority(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_Priority(FALSE, tvb, offset, pinfo, tree, hf_x411_priority);
}
static int dissect_permissible_lowest_priority(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_Priority(FALSE, tvb, offset, pinfo, tree, hf_x411_permissible_lowest_priority);
}
static int dissect_priority_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_Priority(FALSE, tvb, offset, pinfo, tree, hf_x411_priority_item);
}


static const asn_namedbit PerMessageIndicators_bits[] = {
  {  0, &hf_x411_PerMessageIndicators_disclosure_of_other_recipients, -1, -1, "disclosure-of-other-recipients", NULL },
  {  1, &hf_x411_PerMessageIndicators_implicit_conversion_prohibited, -1, -1, "implicit-conversion-prohibited", NULL },
  {  2, &hf_x411_PerMessageIndicators_alternate_recipient_allowed, -1, -1, "alternate-recipient-allowed", NULL },
  {  3, &hf_x411_PerMessageIndicators_content_return_request, -1, -1, "content-return-request", NULL },
  {  4, &hf_x411_PerMessageIndicators_reserved, -1, -1, "reserved", NULL },
  {  5, &hf_x411_PerMessageIndicators_bit_5, -1, -1, "bit-5", NULL },
  {  6, &hf_x411_PerMessageIndicators_bit_6, -1, -1, "bit-6", NULL },
  {  7, &hf_x411_PerMessageIndicators_service_message, -1, -1, "service-message", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x411_PerMessageIndicators(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    PerMessageIndicators_bits, hf_index, ett_x411_PerMessageIndicators,
                                    NULL);

  return offset;
}
static int dissect_per_message_indicators(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PerMessageIndicators(FALSE, tvb, offset, pinfo, tree, hf_x411_per_message_indicators);
}



static int
dissect_x411_Time(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 616 "x411.cnf"
	tvbuff_t *arrival = NULL;

	  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTCTime,
                                            pinfo, tree, tvb, offset, hf_index,
                                            &arrival);


	if(arrival && doing_address)
		proto_item_append_text(address_item, " %s", tvb_format_text(arrival, 0, tvb_length(arrival)));



  return offset;
}
static int dissect_redirection_time(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_Time(FALSE, tvb, offset, pinfo, tree, hf_x411_redirection_time);
}
static int dissect_dl_expansion_time(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_Time(FALSE, tvb, offset, pinfo, tree, hf_x411_dl_expansion_time);
}
static int dissect_origination_or_expansion_time(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_Time(FALSE, tvb, offset, pinfo, tree, hf_x411_origination_or_expansion_time);
}
static int dissect_time(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_Time(FALSE, tvb, offset, pinfo, tree, hf_x411_time);
}



static int
dissect_x411_DeferredDeliveryTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_Time(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_deferred_delivery_time_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_DeferredDeliveryTime(TRUE, tvb, offset, pinfo, tree, hf_x411_deferred_delivery_time);
}


static const ber_sequence_t T_private_domain_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_administration_domain_name_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_private_domain_identifier_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_T_private_domain(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_private_domain_sequence, hf_index, ett_x411_T_private_domain);

  return offset;
}
static int dissect_private_domain(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_T_private_domain(FALSE, tvb, offset, pinfo, tree, hf_x411_private_domain);
}


static const value_string x411_T_domain_vals[] = {
  {   0, "administration-domain-name" },
  {   1, "private-domain" },
  { 0, NULL }
};

static const ber_choice_t T_domain_choice[] = {
  {   0, BER_CLASS_APP, 2, BER_FLAGS_NOOWNTAG, dissect_administration_domain_name },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_private_domain },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_T_domain(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_domain_choice, hf_index, ett_x411_T_domain,
                                 NULL);

  return offset;
}
static int dissect_bilateral_domain(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_T_domain(FALSE, tvb, offset, pinfo, tree, hf_x411_bilateral_domain);
}


static const ber_sequence_t PerDomainBilateralInformation_sequence[] = {
  { BER_CLASS_APP, 1, BER_FLAGS_NOOWNTAG, dissect_country_name },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_bilateral_domain },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_PerDomainBilateralInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PerDomainBilateralInformation_sequence, hf_index, ett_x411_PerDomainBilateralInformation);

  return offset;
}
static int dissect_per_domain_bilateral_information_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PerDomainBilateralInformation(FALSE, tvb, offset, pinfo, tree, hf_x411_per_domain_bilateral_information_item);
}


static const ber_sequence_t SEQUENCE_OF_PerDomainBilateralInformation_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_per_domain_bilateral_information_item },
};

static int
dissect_x411_SEQUENCE_OF_PerDomainBilateralInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_PerDomainBilateralInformation_sequence_of, hf_index, ett_x411_SEQUENCE_OF_PerDomainBilateralInformation);

  return offset;
}
static int dissect_per_domain_bilateral_information_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SEQUENCE_OF_PerDomainBilateralInformation(TRUE, tvb, offset, pinfo, tree, hf_x411_per_domain_bilateral_information);
}



static int
dissect_x411_ArrivalTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_Time(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_arrival_time_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ArrivalTime(TRUE, tvb, offset, pinfo, tree, hf_x411_arrival_time);
}


static const value_string x411_RoutingAction_vals[] = {
  {   0, "relayed" },
  {   1, "rerouted" },
  { 0, NULL }
};


static int
dissect_x411_RoutingAction(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 627 "x411.cnf"
	int action = 0;

	  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &action);


	proto_item_append_text(address_item, " %s", val_to_str(action, x411_RoutingAction_vals, "action(%d)"));



  return offset;
}
static int dissect_routing_action_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_RoutingAction(TRUE, tvb, offset, pinfo, tree, hf_x411_routing_action);
}



static int
dissect_x411_DeferredTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_Time(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_deferred_time_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_DeferredTime(TRUE, tvb, offset, pinfo, tree, hf_x411_deferred_time);
}



static int
dissect_x411_ConvertedEncodedInformationTypes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_EncodedInformationTypes(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_converted_encoded_information_types(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ConvertedEncodedInformationTypes(FALSE, tvb, offset, pinfo, tree, hf_x411_converted_encoded_information_types);
}
static int dissect_converted_encoded_information_types_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ConvertedEncodedInformationTypes(TRUE, tvb, offset, pinfo, tree, hf_x411_converted_encoded_information_types);
}


static const asn_namedbit OtherActions_bits[] = {
  {  0, &hf_x411_OtherActions_redirected, -1, -1, "redirected", NULL },
  {  1, &hf_x411_OtherActions_dl_operation, -1, -1, "dl-operation", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x411_OtherActions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    OtherActions_bits, hf_index, ett_x411_OtherActions,
                                    NULL);

  return offset;
}
static int dissect_other_actions_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_OtherActions(TRUE, tvb, offset, pinfo, tree, hf_x411_other_actions);
}


static const ber_sequence_t DomainSuppliedInformation_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_arrival_time_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_routing_action_impl },
  { BER_CLASS_APP, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_attempted_domain },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_deferred_time_impl },
  { BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_converted_encoded_information_types },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_other_actions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_DomainSuppliedInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 595 "x411.cnf"

	doing_address = FALSE;

	  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              DomainSuppliedInformation_set, hf_index, ett_x411_DomainSuppliedInformation);


	doing_address = TRUE;
	proto_item_append_text(tree, ")");



  return offset;
}
static int dissect_domain_supplied_information(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_DomainSuppliedInformation(FALSE, tvb, offset, pinfo, tree, hf_x411_domain_supplied_information);
}


static const ber_sequence_t TraceInformationElement_sequence[] = {
  { BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_global_domain_identifier },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_domain_supplied_information },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_TraceInformationElement(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 579 "x411.cnf"

	doing_address = TRUE;

	  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   TraceInformationElement_sequence, hf_index, ett_x411_TraceInformationElement);


	doing_address = FALSE;



  return offset;
}
static int dissect_TraceInformation_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_TraceInformationElement(FALSE, tvb, offset, pinfo, tree, hf_x411_TraceInformation_item);
}


static const ber_sequence_t TraceInformation_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_TraceInformation_item },
};

static int
dissect_x411_TraceInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      TraceInformation_sequence_of, hf_index, ett_x411_TraceInformation);

  return offset;
}
static int dissect_trace_information(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_TraceInformation(FALSE, tvb, offset, pinfo, tree, hf_x411_trace_information);
}


static const value_string x411_ExtensionType_vals[] = {
  {   0, "standard-extension" },
  {   3, "private-extension" },
  { 0, NULL }
};

static const ber_choice_t ExtensionType_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_standard_extension_impl },
  {   3, BER_CLASS_CON, 3, 0, dissect_private_extension_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_ExtensionType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ExtensionType_choice, hf_index, ett_x411_ExtensionType,
                                 NULL);

  return offset;
}
static int dissect_extension_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ExtensionType(FALSE, tvb, offset, pinfo, tree, hf_x411_extension_type);
}


static const asn_namedbit Criticality_bits[] = {
  {  0, &hf_x411_Criticality_for_submission, -1, -1, "for-submission", NULL },
  {  1, &hf_x411_Criticality_for_transfer, -1, -1, "for-transfer", NULL },
  {  2, &hf_x411_Criticality_for_delivery, -1, -1, "for-delivery", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x411_Criticality(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    Criticality_bits, hf_index, ett_x411_Criticality,
                                    NULL);

  return offset;
}
static int dissect_criticality_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_Criticality(TRUE, tvb, offset, pinfo, tree, hf_x411_criticality);
}



static int
dissect_x411_ExtensionValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 232 "x411.cnf"
	const char *name;

	if(extension_id != -1) 
		offset=call_x411_oid_callback("x411.extension", tvb, offset, pinfo, tree);
	else if(object_identifier_id) {
		call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);
		name = get_ber_oid_name(object_identifier_id);
		proto_item_append_text(tree, " (%s)", name ? name : object_identifier_id); 
	}
		



  return offset;
}
static int dissect_extension_value_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ExtensionValue(TRUE, tvb, offset, pinfo, tree, hf_x411_extension_value);
}


static const ber_sequence_t ExtensionField_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_extension_type },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_criticality_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_extension_value_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_ExtensionField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ExtensionField_sequence, hf_index, ett_x411_ExtensionField);

  return offset;
}
static int dissect_extensions_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ExtensionField(FALSE, tvb, offset, pinfo, tree, hf_x411_extensions_item);
}


static const ber_sequence_t SET_OF_ExtensionField_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_extensions_item },
};

static int
dissect_x411_SET_OF_ExtensionField(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_ExtensionField_set_of, hf_index, ett_x411_SET_OF_ExtensionField);

  return offset;
}
static int dissect_extensions(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SET_OF_ExtensionField(FALSE, tvb, offset, pinfo, tree, hf_x411_extensions);
}
static int dissect_extensions_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SET_OF_ExtensionField(TRUE, tvb, offset, pinfo, tree, hf_x411_extensions);
}



static int
dissect_x411_MTARecipientName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_recipient_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MTARecipientName(FALSE, tvb, offset, pinfo, tree, hf_x411_recipient_name);
}



static int
dissect_x411_OriginallySpecifiedRecipientNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_originally_specified_recipient_number_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_OriginallySpecifiedRecipientNumber(TRUE, tvb, offset, pinfo, tree, hf_x411_originally_specified_recipient_number);
}


static const asn_namedbit PerRecipientIndicators_bits[] = {
  {  0, &hf_x411_PerRecipientIndicators_responsibility, -1, -1, "responsibility", NULL },
  {  1, &hf_x411_PerRecipientIndicators_originating_MTA_report, -1, -1, "originating-MTA-report", NULL },
  {  2, &hf_x411_PerRecipientIndicators_originating_MTA_non_delivery_report, -1, -1, "originating-MTA-non-delivery-report", NULL },
  {  3, &hf_x411_PerRecipientIndicators_originator_report, -1, -1, "originator-report", NULL },
  {  4, &hf_x411_PerRecipientIndicators_originator_non_delivery_report, -1, -1, "originator-non-delivery-report", NULL },
  {  5, &hf_x411_PerRecipientIndicators_reserved_5, -1, -1, "reserved-5", NULL },
  {  6, &hf_x411_PerRecipientIndicators_reserved_6, -1, -1, "reserved-6", NULL },
  {  7, &hf_x411_PerRecipientIndicators_reserved_7, -1, -1, "reserved-7", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x411_PerRecipientIndicators(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    PerRecipientIndicators_bits, hf_index, ett_x411_PerRecipientIndicators,
                                    NULL);

  return offset;
}
static int dissect_per_recipient_indicators_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PerRecipientIndicators(TRUE, tvb, offset, pinfo, tree, hf_x411_per_recipient_indicators);
}


static const value_string x411_ExplicitConversion_vals[] = {
  {   0, "ia5-text-to-teletex" },
  {   8, "ia5-text-to-g3-facsimile" },
  {   9, "ia5-text-to-g4-class-1" },
  {  10, "ia5-text-to-videotex" },
  {  11, "teletex-to-ia5-text" },
  {  12, "teletex-to-g3-facsimile" },
  {  13, "teletex-to-g4-class-1" },
  {  14, "teletex-to-videotex" },
  {  16, "videotex-to-ia5-text" },
  {  17, "videotex-to-teletex" },
  { 0, NULL }
};


static int
dissect_x411_ExplicitConversion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_explicit_conversion_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ExplicitConversion(TRUE, tvb, offset, pinfo, tree, hf_x411_explicit_conversion);
}


static const ber_sequence_t PerRecipientMessageTransferFields_set[] = {
  { BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_recipient_name },
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_originally_specified_recipient_number_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_per_recipient_indicators_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_explicit_conversion_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_PerRecipientMessageTransferFields(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              PerRecipientMessageTransferFields_set, hf_index, ett_x411_PerRecipientMessageTransferFields);

  return offset;
}
static int dissect_per_recipient_message_fields_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PerRecipientMessageTransferFields(FALSE, tvb, offset, pinfo, tree, hf_x411_per_recipient_message_fields_item);
}


static const ber_sequence_t SEQUENCE_OF_PerRecipientMessageTransferFields_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_per_recipient_message_fields_item },
};

static int
dissect_x411_SEQUENCE_OF_PerRecipientMessageTransferFields(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_PerRecipientMessageTransferFields_sequence_of, hf_index, ett_x411_SEQUENCE_OF_PerRecipientMessageTransferFields);

  return offset;
}
static int dissect_per_recipient_message_fields_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SEQUENCE_OF_PerRecipientMessageTransferFields(TRUE, tvb, offset, pinfo, tree, hf_x411_per_recipient_message_fields);
}


static const ber_sequence_t MessageTransferEnvelope_set[] = {
  { BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_message_identifier },
  { BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_mta_originator_name },
  { BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_original_encoded_information_types },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_content_type },
  { BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_content_identifier },
  { BER_CLASS_APP, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_priority },
  { BER_CLASS_APP, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_per_message_indicators },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_deferred_delivery_time_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_per_domain_bilateral_information_impl },
  { BER_CLASS_APP, 9, BER_FLAGS_NOOWNTAG, dissect_trace_information },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_per_recipient_message_fields_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_MessageTransferEnvelope(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              MessageTransferEnvelope_set, hf_index, ett_x411_MessageTransferEnvelope);

  return offset;
}
static int dissect_message_envelope(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MessageTransferEnvelope(FALSE, tvb, offset, pinfo, tree, hf_x411_message_envelope);
}



static int
dissect_x411_Content(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 364 "x411.cnf"
  tvbuff_t *next_tvb;

  /* we can do this now constructed octet strings are supported */
  offset = dissect_ber_octet_string(FALSE, pinfo, NULL, tvb, offset, hf_index, &next_tvb);

  if (next_tvb && content_type_id)
    (void) call_ber_oid_callback(content_type_id, next_tvb, 0, pinfo, top_tree ? top_tree : tree);



  return offset;
}
static int dissect_content(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_Content(FALSE, tvb, offset, pinfo, tree, hf_x411_content);
}
static int dissect_returned_content_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_Content(TRUE, tvb, offset, pinfo, tree, hf_x411_returned_content);
}


static const ber_sequence_t Message_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_message_envelope },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_content },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_Message(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Message_sequence, hf_index, ett_x411_Message);

  return offset;
}
static int dissect_message_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_Message(TRUE, tvb, offset, pinfo, tree, hf_x411_message);
}



static int
dissect_x411_ProbeIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_MTSIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_probe_identifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ProbeIdentifier(FALSE, tvb, offset, pinfo, tree, hf_x411_probe_identifier);
}



int
dissect_x411_ContentLength(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_content_length_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ContentLength(TRUE, tvb, offset, pinfo, tree, hf_x411_content_length);
}
static int dissect_permissible_maximum_content_length_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ContentLength(TRUE, tvb, offset, pinfo, tree, hf_x411_permissible_maximum_content_length);
}
static int dissect_maximum_content_length_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ContentLength(TRUE, tvb, offset, pinfo, tree, hf_x411_maximum_content_length);
}


static const ber_sequence_t PerRecipientProbeTransferFields_set[] = {
  { BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_recipient_name },
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_originally_specified_recipient_number_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_per_recipient_indicators_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_explicit_conversion_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_PerRecipientProbeTransferFields(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              PerRecipientProbeTransferFields_set, hf_index, ett_x411_PerRecipientProbeTransferFields);

  return offset;
}
static int dissect_per_recipient_probe_transfer_fields_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PerRecipientProbeTransferFields(FALSE, tvb, offset, pinfo, tree, hf_x411_per_recipient_probe_transfer_fields_item);
}


static const ber_sequence_t SEQUENCE_OF_PerRecipientProbeTransferFields_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_per_recipient_probe_transfer_fields_item },
};

static int
dissect_x411_SEQUENCE_OF_PerRecipientProbeTransferFields(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_PerRecipientProbeTransferFields_sequence_of, hf_index, ett_x411_SEQUENCE_OF_PerRecipientProbeTransferFields);

  return offset;
}
static int dissect_per_recipient_probe_transfer_fields_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SEQUENCE_OF_PerRecipientProbeTransferFields(TRUE, tvb, offset, pinfo, tree, hf_x411_per_recipient_probe_transfer_fields);
}


static const ber_sequence_t ProbeTransferEnvelope_set[] = {
  { BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_probe_identifier },
  { BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_mta_originator_name },
  { BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_original_encoded_information_types },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_content_type },
  { BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_content_identifier },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_content_length_impl },
  { BER_CLASS_APP, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_per_message_indicators },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_per_domain_bilateral_information_impl },
  { BER_CLASS_APP, 9, BER_FLAGS_NOOWNTAG, dissect_trace_information },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_per_recipient_probe_transfer_fields_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_ProbeTransferEnvelope(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ProbeTransferEnvelope_set, hf_index, ett_x411_ProbeTransferEnvelope);

  return offset;
}



static int
dissect_x411_Probe(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_ProbeTransferEnvelope(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_probe_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_Probe(TRUE, tvb, offset, pinfo, tree, hf_x411_probe);
}



static int
dissect_x411_ReportIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_MTSIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_report_identifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ReportIdentifier(FALSE, tvb, offset, pinfo, tree, hf_x411_report_identifier);
}



static int
dissect_x411_ReportDestinationName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_report_destination_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ReportDestinationName(FALSE, tvb, offset, pinfo, tree, hf_x411_report_destination_name);
}


static const ber_sequence_t ReportTransferEnvelope_set[] = {
  { BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_report_identifier },
  { BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_report_destination_name },
  { BER_CLASS_APP, 9, BER_FLAGS_NOOWNTAG, dissect_trace_information },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_ReportTransferEnvelope(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ReportTransferEnvelope_set, hf_index, ett_x411_ReportTransferEnvelope);

  return offset;
}
static int dissect_report_envelope(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ReportTransferEnvelope(FALSE, tvb, offset, pinfo, tree, hf_x411_report_envelope);
}



static int
dissect_x411_MessageOrProbeIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_MTSIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_SubjectIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_MessageOrProbeIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_subject_identifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SubjectIdentifier(FALSE, tvb, offset, pinfo, tree, hf_x411_subject_identifier);
}



static int
dissect_x411_SubjectIntermediateTraceInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_TraceInformation(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_subject_intermediate_trace_information(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SubjectIntermediateTraceInformation(FALSE, tvb, offset, pinfo, tree, hf_x411_subject_intermediate_trace_information);
}



static int
dissect_x411_AdditionalInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 226 "x411.cnf"
/*XXX not implemented yet */



  return offset;
}
static int dissect_additional_information_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_AdditionalInformation(TRUE, tvb, offset, pinfo, tree, hf_x411_additional_information);
}



static int
dissect_x411_MTAActualRecipientName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_mta_actual_recipient_name_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MTAActualRecipientName(TRUE, tvb, offset, pinfo, tree, hf_x411_mta_actual_recipient_name);
}



int
dissect_x411_MessageDeliveryTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_Time(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_message_delivery_time(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MessageDeliveryTime(FALSE, tvb, offset, pinfo, tree, hf_x411_message_delivery_time);
}
static int dissect_message_delivery_time_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MessageDeliveryTime(TRUE, tvb, offset, pinfo, tree, hf_x411_message_delivery_time);
}


static const value_string x411_TypeOfMTSUser_vals[] = {
  {   0, "public" },
  {   1, "private" },
  {   2, "ms" },
  {   3, "dl" },
  {   4, "pdau" },
  {   5, "physical-recipient" },
  {   6, "other" },
  { 0, NULL }
};


static int
dissect_x411_TypeOfMTSUser(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_type_of_MTS_user(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_TypeOfMTSUser(FALSE, tvb, offset, pinfo, tree, hf_x411_type_of_MTS_user);
}
static int dissect_type_of_MTS_user_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_TypeOfMTSUser(TRUE, tvb, offset, pinfo, tree, hf_x411_type_of_MTS_user);
}


static const ber_sequence_t DeliveryReport_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_message_delivery_time_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_type_of_MTS_user_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_DeliveryReport(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              DeliveryReport_set, hf_index, ett_x411_DeliveryReport);

  return offset;
}
static int dissect_delivery_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_DeliveryReport(TRUE, tvb, offset, pinfo, tree, hf_x411_delivery);
}


static const value_string x411_NonDeliveryReasonCode_vals[] = {
  {   0, "transfer-failure" },
  {   1, "unable-to-transfer" },
  {   2, "conversion-not-performed" },
  {   3, "physical-rendition-not-performed" },
  {   4, "physical-delivery-not-performed" },
  {   5, "restricted-delivery" },
  {   6, "directory-operation-unsuccessful" },
  {   7, "deferred-delivery-not-performed" },
  {   8, "transfer-failure-for-security-reason" },
  { 0, NULL }
};


static int
dissect_x411_NonDeliveryReasonCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_non_delivery_reason_code(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_NonDeliveryReasonCode(FALSE, tvb, offset, pinfo, tree, hf_x411_non_delivery_reason_code);
}
static int dissect_non_delivery_reason_code_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_NonDeliveryReasonCode(TRUE, tvb, offset, pinfo, tree, hf_x411_non_delivery_reason_code);
}


static const value_string x411_NonDeliveryDiagnosticCode_vals[] = {
  {   0, "unrecognised-OR-name" },
  {   1, "ambiguous-OR-name" },
  {   2, "mts-congestion" },
  {   3, "loop-detected" },
  {   4, "recipient-unavailable" },
  {   5, "maximum-time-expired" },
  {   6, "encoded-information-types-unsupported" },
  {   7, "content-too-long" },
  {   8, "conversion-impractical" },
  {   9, "implicit-conversion-prohibited" },
  {  10, "implicit-conversion-not-subscribed" },
  {  11, "invalid-arguments" },
  {  12, "content-syntax-error" },
  {  13, "size-constraint-violation" },
  {  14, "protocol-violation" },
  {  15, "content-type-not-supported" },
  {  16, "too-many-recipients" },
  {  17, "no-bilateral-agreement" },
  {  18, "unsupported-critical-function" },
  {  19, "conversion-with-loss-prohibited" },
  {  20, "line-too-long" },
  {  21, "page-split" },
  {  22, "pictorial-symbol-loss" },
  {  23, "punctuation-symbol-loss" },
  {  24, "alphabetic-character-loss" },
  {  25, "multiple-information-loss" },
  {  26, "recipient-reassignment-prohibited" },
  {  27, "redirection-loop-detected" },
  {  28, "dl-expansion-prohibited" },
  {  29, "no-dl-submit-permission" },
  {  30, "dl-expansion-failure" },
  {  31, "physical-rendition-attributes-not-supported" },
  {  32, "undeliverable-mail-physical-delivery-address-incorrect" },
  {  33, "undeliverable-mail-physical-delivery-office-incorrect-or-invalid" },
  {  34, "undeliverable-mail-physical-delivery-address-incomplete" },
  {  35, "undeliverable-mail-recipient-unknown" },
  {  36, "undeliverable-mail-recipient-deceased" },
  {  37, "undeliverable-mail-organization-expired" },
  {  38, "undeliverable-mail-recipient-refused-to-accept" },
  {  39, "undeliverable-mail-recipient-did-not-claim" },
  {  40, "undeliverable-mail-recipient-changed-address-permanently" },
  {  41, "undeliverable-mail-recipient-changed-address-temporarily" },
  {  42, "undeliverable-mail-recipient-changed-temporary-address" },
  {  43, "undeliverable-mail-new-address-unknown" },
  {  44, "undeliverable-mail-recipient-did-not-want-forwarding" },
  {  45, "undeliverable-mail-originator-prohibited-forwarding" },
  {  46, "secure-messaging-error" },
  {  47, "unable-to-downgrade" },
  {  48, "unable-to-complete-transfer" },
  {  49, "transfer-attempts-limit-reached" },
  {  50, "incorrect-notification-type" },
  {  51, "dl-expansion-prohibited-by-security-policy" },
  {  52, "forbidden-alternate-recipient" },
  {  53, "security-policy-violation" },
  {  54, "security-services-refusal" },
  {  55, "unauthorised-dl-member" },
  {  56, "unauthorised-dl-name" },
  {  57, "unauthorised-originally-intended-recipient-name" },
  {  58, "unauthorised-originator-name" },
  {  59, "unauthorised-recipient-name" },
  {  60, "unreliable-system" },
  {  61, "authentication-failure-on-subject-message" },
  {  62, "decryption-failed" },
  {  63, "decryption-key-unobtainable" },
  {  64, "double-envelope-creation-failure" },
  {  65, "double-enveloping-message-restoring-failure" },
  {  66, "failure-of-proof-of-message" },
  {  67, "integrity-failure-on-subject-message" },
  {  68, "invalid-security-label" },
  {  69, "key-failure" },
  {  70, "mandatory-parameter-absence" },
  {  71, "operation-security-failure" },
  {  72, "repudiation-failure-of-message" },
  {  73, "security-context-failure" },
  {  74, "token-decryption-failed" },
  {  75, "token-error" },
  {  76, "unknown-security-label" },
  {  77, "unsupported-algorithm-identifier" },
  {  78, "unsupported-security-policy" },
  { 0, NULL }
};


static int
dissect_x411_NonDeliveryDiagnosticCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_non_delivery_diagnostic_code(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_NonDeliveryDiagnosticCode(FALSE, tvb, offset, pinfo, tree, hf_x411_non_delivery_diagnostic_code);
}
static int dissect_non_delivery_diagnostic_code_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_NonDeliveryDiagnosticCode(TRUE, tvb, offset, pinfo, tree, hf_x411_non_delivery_diagnostic_code);
}


static const ber_sequence_t NonDeliveryReport_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_non_delivery_reason_code_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_non_delivery_diagnostic_code_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_NonDeliveryReport(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              NonDeliveryReport_set, hf_index, ett_x411_NonDeliveryReport);

  return offset;
}
static int dissect_non_delivery_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_NonDeliveryReport(TRUE, tvb, offset, pinfo, tree, hf_x411_non_delivery);
}


static const value_string x411_ReportType_vals[] = {
  {   0, "delivery" },
  {   1, "non-delivery" },
  { 0, NULL }
};

static const ber_choice_t ReportType_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_delivery_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_non_delivery_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_ReportType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ReportType_choice, hf_index, ett_x411_ReportType,
                                 NULL);

  return offset;
}
static int dissect_trace_report_type_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ReportType(TRUE, tvb, offset, pinfo, tree, hf_x411_trace_report_type);
}
static int dissect_delivery_report_type_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ReportType(TRUE, tvb, offset, pinfo, tree, hf_x411_delivery_report_type);
}


static const ber_sequence_t LastTraceInformation_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_arrival_time_impl },
  { BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_converted_encoded_information_types },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_trace_report_type_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_LastTraceInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              LastTraceInformation_set, hf_index, ett_x411_LastTraceInformation);

  return offset;
}
static int dissect_last_trace_information_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_LastTraceInformation(TRUE, tvb, offset, pinfo, tree, hf_x411_last_trace_information);
}



static int
dissect_x411_MTAOriginallyIntendedRecipientName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_report_originally_intended_recipient_name_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MTAOriginallyIntendedRecipientName(TRUE, tvb, offset, pinfo, tree, hf_x411_report_originally_intended_recipient_name);
}



int
dissect_x411_SupplementaryInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_supplementary_information_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SupplementaryInformation(TRUE, tvb, offset, pinfo, tree, hf_x411_supplementary_information);
}


static const ber_sequence_t PerRecipientReportTransferFields_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mta_actual_recipient_name_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_originally_specified_recipient_number_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_per_recipient_indicators_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_last_trace_information_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_report_originally_intended_recipient_name_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_supplementary_information_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_PerRecipientReportTransferFields(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              PerRecipientReportTransferFields_set, hf_index, ett_x411_PerRecipientReportTransferFields);

  return offset;
}
static int dissect_per_recipient_fields_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PerRecipientReportTransferFields(FALSE, tvb, offset, pinfo, tree, hf_x411_per_recipient_fields_item);
}


static const ber_sequence_t SEQUENCE_OF_PerRecipientReportTransferFields_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_per_recipient_fields_item },
};

static int
dissect_x411_SEQUENCE_OF_PerRecipientReportTransferFields(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_PerRecipientReportTransferFields_sequence_of, hf_index, ett_x411_SEQUENCE_OF_PerRecipientReportTransferFields);

  return offset;
}
static int dissect_per_recipient_report_fields_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SEQUENCE_OF_PerRecipientReportTransferFields(TRUE, tvb, offset, pinfo, tree, hf_x411_per_recipient_report_fields);
}


static const ber_sequence_t ReportTransferContent_set[] = {
  { BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_subject_identifier },
  { BER_CLASS_APP, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_subject_intermediate_trace_information },
  { BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_original_encoded_information_types },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_content_type },
  { BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_content_identifier },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_returned_content_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_additional_information_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_per_recipient_report_fields_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_ReportTransferContent(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ReportTransferContent_set, hf_index, ett_x411_ReportTransferContent);

  return offset;
}
static int dissect_report_content(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ReportTransferContent(FALSE, tvb, offset, pinfo, tree, hf_x411_report_content);
}


static const ber_sequence_t Report_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_report_envelope },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_report_content },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_Report(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Report_sequence, hf_index, ett_x411_Report);

  return offset;
}
static int dissect_report_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_Report(TRUE, tvb, offset, pinfo, tree, hf_x411_report);
}


static const value_string x411_MTS_APDU_vals[] = {
  {   0, "message" },
  {   2, "probe" },
  {   1, "report" },
  { 0, NULL }
};

static const ber_choice_t MTS_APDU_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_message_impl },
  {   2, BER_CLASS_CON, 2, 0, dissect_probe_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_report_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_MTS_APDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 MTS_APDU_choice, hf_index, ett_x411_MTS_APDU,
                                 NULL);

  return offset;
}



static int
dissect_x411_MTAOriginatorRequestedAlternateRecipient(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const value_string x411_T_attempted_vals[] = {
  {   0, "mta" },
  {   1, "domain" },
  { 0, NULL }
};

static const ber_choice_t T_attempted_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_mta },
  {   1, BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_domain },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_T_attempted(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_attempted_choice, hf_index, ett_x411_T_attempted,
                                 NULL);

  return offset;
}
static int dissect_attempted(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_T_attempted(FALSE, tvb, offset, pinfo, tree, hf_x411_attempted);
}


static const ber_sequence_t MTASuppliedInformation_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_arrival_time_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_routing_action_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_attempted },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_deferred_time_impl },
  { BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_converted_encoded_information_types },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_other_actions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_MTASuppliedInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 604 "x411.cnf"

	doing_address = FALSE;

	  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              MTASuppliedInformation_set, hf_index, ett_x411_MTASuppliedInformation);


	doing_address = TRUE;
	proto_item_append_text(tree, ")");



  return offset;
}
static int dissect_mta_supplied_information(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MTASuppliedInformation(FALSE, tvb, offset, pinfo, tree, hf_x411_mta_supplied_information);
}


static const ber_sequence_t InternalTraceInformationElement_sequence[] = {
  { BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_global_domain_identifier },
  { BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_mta_name },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_mta_supplied_information },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_InternalTraceInformationElement(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 587 "x411.cnf"

	doing_address = TRUE;

	  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   InternalTraceInformationElement_sequence, hf_index, ett_x411_InternalTraceInformationElement);


	doing_address = FALSE;



  return offset;
}
static int dissect_InternalTraceInformation_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_InternalTraceInformationElement(FALSE, tvb, offset, pinfo, tree, hf_x411_InternalTraceInformation_item);
}


static const ber_sequence_t InternalTraceInformation_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_InternalTraceInformation_item },
};

static int
dissect_x411_InternalTraceInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      InternalTraceInformation_sequence_of, hf_index, ett_x411_InternalTraceInformation);

  return offset;
}


static const value_string x411_ObjectName_vals[] = {
  {   0, "user-agent" },
  {   1, "mTA" },
  {   2, "message-store" },
  { 0, NULL }
};

static const ber_choice_t ObjectName_choice[] = {
  {   0, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_user_agent },
  {   1, BER_CLASS_CON, 0, 0, dissect_mTA_impl },
  {   2, BER_CLASS_CON, 4, 0, dissect_message_store_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_ObjectName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ObjectName_choice, hf_index, ett_x411_ObjectName,
                                 NULL);

  return offset;
}
static int dissect_initiator_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ObjectName(FALSE, tvb, offset, pinfo, tree, hf_x411_initiator_name);
}
static int dissect_responder_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ObjectName(FALSE, tvb, offset, pinfo, tree, hf_x411_responder_name);
}


static const ber_sequence_t DeliveryQueue_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_messages_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_delivery_queue_octets_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_DeliveryQueue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              DeliveryQueue_set, hf_index, ett_x411_DeliveryQueue);

  return offset;
}
static int dissect_urgent_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_DeliveryQueue(TRUE, tvb, offset, pinfo, tree, hf_x411_urgent);
}
static int dissect_normal_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_DeliveryQueue(TRUE, tvb, offset, pinfo, tree, hf_x411_normal);
}
static int dissect_non_urgent_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_DeliveryQueue(TRUE, tvb, offset, pinfo, tree, hf_x411_non_urgent);
}


static const ber_sequence_t MessagesWaiting_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_urgent_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_normal_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_non_urgent_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_MessagesWaiting(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              MessagesWaiting_set, hf_index, ett_x411_MessagesWaiting);

  return offset;
}
static int dissect_messages_waiting(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MessagesWaiting(FALSE, tvb, offset, pinfo, tree, hf_x411_messages_waiting);
}


static const ber_sequence_t MTSBindArgument_set[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_initiator_name },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_messages_waiting },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_initiator_credentials_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_security_context_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_MTSBindArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              MTSBindArgument_set, hf_index, ett_x411_MTSBindArgument);

  return offset;
}


static const ber_sequence_t MTSBindResult_set[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_responder_name },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_messages_waiting },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_responder_credentials_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_MTSBindResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              MTSBindResult_set, hf_index, ett_x411_MTSBindResult);

  return offset;
}


static const value_string x411_MTSBindError_vals[] = {
  {   0, "busy" },
  {   2, "authentication-error" },
  {   3, "unacceptable-dialogue-mode" },
  {   4, "unacceptable-security-context" },
  {   5, "inadequate-association-confidentiality" },
  { 0, NULL }
};


static int
dissect_x411_MTSBindError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_x411_ORAddressAndOrDirectoryName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_ORName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_DLExemptedRecipients_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ORAddressAndOrDirectoryName(FALSE, tvb, offset, pinfo, tree, hf_x411_DLExemptedRecipients_item);
}



static int
dissect_x411_MTSOriginatorName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOrDirectoryName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_mts_originator_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MTSOriginatorName(FALSE, tvb, offset, pinfo, tree, hf_x411_mts_originator_name);
}



static int
dissect_x411_MTSRecipientName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOrDirectoryName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_ImproperlySpecifiedRecipients_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MTSRecipientName(FALSE, tvb, offset, pinfo, tree, hf_x411_ImproperlySpecifiedRecipients_item);
}
static int dissect_submission_recipient_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MTSRecipientName(FALSE, tvb, offset, pinfo, tree, hf_x411_submission_recipient_name);
}
static int dissect_probe_recipient_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MTSRecipientName(FALSE, tvb, offset, pinfo, tree, hf_x411_probe_recipient_name);
}
static int dissect_token_recipient_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MTSRecipientName(FALSE, tvb, offset, pinfo, tree, hf_x411_token_recipient_name);
}


static const asn_namedbit OriginatorReportRequest_bits[] = {
  {  3, &hf_x411_OriginatorReportRequest_report, -1, -1, "report", NULL },
  {  4, &hf_x411_OriginatorReportRequest_non_delivery_report, -1, -1, "non-delivery-report", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x411_OriginatorReportRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    OriginatorReportRequest_bits, hf_index, ett_x411_OriginatorReportRequest,
                                    NULL);

  return offset;
}
static int dissect_originator_report_request_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_OriginatorReportRequest(TRUE, tvb, offset, pinfo, tree, hf_x411_originator_report_request);
}


static const ber_sequence_t PerRecipientMessageSubmissionFields_set[] = {
  { BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_submission_recipient_name },
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_originator_report_request_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_explicit_conversion_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_PerRecipientMessageSubmissionFields(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              PerRecipientMessageSubmissionFields_set, hf_index, ett_x411_PerRecipientMessageSubmissionFields);

  return offset;
}
static int dissect_per_recipient_message_submission_fields_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PerRecipientMessageSubmissionFields(FALSE, tvb, offset, pinfo, tree, hf_x411_per_recipient_message_submission_fields_item);
}


static const ber_sequence_t SEQUENCE_OF_PerRecipientMessageSubmissionFields_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_per_recipient_message_submission_fields_item },
};

static int
dissect_x411_SEQUENCE_OF_PerRecipientMessageSubmissionFields(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_PerRecipientMessageSubmissionFields_sequence_of, hf_index, ett_x411_SEQUENCE_OF_PerRecipientMessageSubmissionFields);

  return offset;
}
static int dissect_per_recipient_message_submission_fields_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SEQUENCE_OF_PerRecipientMessageSubmissionFields(TRUE, tvb, offset, pinfo, tree, hf_x411_per_recipient_message_submission_fields);
}


static const ber_sequence_t MessageSubmissionEnvelope_set[] = {
  { BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_mts_originator_name },
  { BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_original_encoded_information_types },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_content_type },
  { BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_content_identifier },
  { BER_CLASS_APP, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_priority },
  { BER_CLASS_APP, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_per_message_indicators },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_deferred_delivery_time_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_per_recipient_message_submission_fields_impl },
  { 0, 0, 0, NULL }
};

int
dissect_x411_MessageSubmissionEnvelope(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              MessageSubmissionEnvelope_set, hf_index, ett_x411_MessageSubmissionEnvelope);

  return offset;
}
static int dissect_message_submission_envelope(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MessageSubmissionEnvelope(FALSE, tvb, offset, pinfo, tree, hf_x411_message_submission_envelope);
}


static const ber_sequence_t MessageSubmissionArgument_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_message_submission_envelope },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_content },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_MessageSubmissionArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MessageSubmissionArgument_sequence, hf_index, ett_x411_MessageSubmissionArgument);

  return offset;
}



static int
dissect_x411_MessageSubmissionIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_MTSIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_message_submission_identifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MessageSubmissionIdentifier(FALSE, tvb, offset, pinfo, tree, hf_x411_message_submission_identifier);
}



static int
dissect_x411_MessageSubmissionTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_Time(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_message_submission_time_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MessageSubmissionTime(TRUE, tvb, offset, pinfo, tree, hf_x411_message_submission_time);
}


static const ber_sequence_t MessageSubmissionResult_set[] = {
  { BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_message_submission_identifier },
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_message_submission_time_impl },
  { BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_content_identifier },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_MessageSubmissionResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              MessageSubmissionResult_set, hf_index, ett_x411_MessageSubmissionResult);

  return offset;
}


static const ber_sequence_t PerRecipientProbeSubmissionFields_set[] = {
  { BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_probe_recipient_name },
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_originator_report_request_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_explicit_conversion_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_PerRecipientProbeSubmissionFields(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              PerRecipientProbeSubmissionFields_set, hf_index, ett_x411_PerRecipientProbeSubmissionFields);

  return offset;
}
static int dissect_per_recipient_probe_submission_fields_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PerRecipientProbeSubmissionFields(FALSE, tvb, offset, pinfo, tree, hf_x411_per_recipient_probe_submission_fields_item);
}


static const ber_sequence_t SEQUENCE_OF_PerRecipientProbeSubmissionFields_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_per_recipient_probe_submission_fields_item },
};

static int
dissect_x411_SEQUENCE_OF_PerRecipientProbeSubmissionFields(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_PerRecipientProbeSubmissionFields_sequence_of, hf_index, ett_x411_SEQUENCE_OF_PerRecipientProbeSubmissionFields);

  return offset;
}
static int dissect_per_recipient_probe_submission_fields_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SEQUENCE_OF_PerRecipientProbeSubmissionFields(TRUE, tvb, offset, pinfo, tree, hf_x411_per_recipient_probe_submission_fields);
}


static const ber_sequence_t ProbeSubmissionEnvelope_set[] = {
  { BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_mts_originator_name },
  { BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_original_encoded_information_types },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_content_type },
  { BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_content_identifier },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_content_length_impl },
  { BER_CLASS_APP, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_per_message_indicators },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_per_recipient_probe_submission_fields_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_ProbeSubmissionEnvelope(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ProbeSubmissionEnvelope_set, hf_index, ett_x411_ProbeSubmissionEnvelope);

  return offset;
}



static int
dissect_x411_ProbeSubmissionArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_ProbeSubmissionEnvelope(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_ProbeSubmissionIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_MTSIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_probe_submission_identifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ProbeSubmissionIdentifier(FALSE, tvb, offset, pinfo, tree, hf_x411_probe_submission_identifier);
}



static int
dissect_x411_ProbeSubmissionTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_Time(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_probe_submission_time_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ProbeSubmissionTime(TRUE, tvb, offset, pinfo, tree, hf_x411_probe_submission_time);
}


static const ber_sequence_t ProbeSubmissionResult_set[] = {
  { BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_probe_submission_identifier },
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_probe_submission_time_impl },
  { BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_content_identifier },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_ProbeSubmissionResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ProbeSubmissionResult_set, hf_index, ett_x411_ProbeSubmissionResult);

  return offset;
}



static int
dissect_x411_CancelDeferredDeliveryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_MessageSubmissionIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_CancelDeferredDeliveryResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_x411_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_restrict_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_x411_restrict);
}
static int dissect_permitted(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_x411_permitted);
}


static const asn_namedbit Operations_bits[] = {
  {  0, &hf_x411_Operations_probe_submission_or_report_delivery, -1, -1, "probe-submission-or-report-delivery", NULL },
  {  1, &hf_x411_Operations_message_submission_or_message_delivery, -1, -1, "message-submission-or-message-delivery", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x411_Operations(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    Operations_bits, hf_index, ett_x411_Operations,
                                    NULL);

  return offset;
}
static int dissect_waiting_operations_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_Operations(TRUE, tvb, offset, pinfo, tree, hf_x411_waiting_operations);
}
static int dissect_permissible_operations_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_Operations(TRUE, tvb, offset, pinfo, tree, hf_x411_permissible_operations);
}


static const ber_sequence_t ContentTypes_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ContentTypes_item },
};

static int
dissect_x411_ContentTypes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 ContentTypes_set_of, hf_index, ett_x411_ContentTypes);

  return offset;
}
static int dissect_permissible_content_types_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ContentTypes(TRUE, tvb, offset, pinfo, tree, hf_x411_permissible_content_types);
}
static int dissect_content_types_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ContentTypes(TRUE, tvb, offset, pinfo, tree, hf_x411_content_types);
}


static const ber_sequence_t EncodedInformationTypesConstraints_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_unacceptable_eits_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acceptable_eits_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_exclusively_acceptable_eits_impl },
  { 0, 0, 0, NULL }
};

int
dissect_x411_EncodedInformationTypesConstraints(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EncodedInformationTypesConstraints_sequence, hf_index, ett_x411_EncodedInformationTypesConstraints);

  return offset;
}
static int dissect_encoded_information_types_constraints_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_EncodedInformationTypesConstraints(TRUE, tvb, offset, pinfo, tree, hf_x411_encoded_information_types_constraints);
}



static int
dissect_x411_PermissibleEncodedInformationTypes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_EncodedInformationTypesConstraints(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_permissible_encoded_information_types(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PermissibleEncodedInformationTypes(FALSE, tvb, offset, pinfo, tree, hf_x411_permissible_encoded_information_types);
}


static const ber_sequence_t Controls_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_restrict_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_permissible_operations_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_permissible_maximum_content_length_impl },
  { BER_CLASS_APP, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_permissible_lowest_priority },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_permissible_content_types_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_permissible_encoded_information_types },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_permissible_security_context_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_Controls(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              Controls_set, hf_index, ett_x411_Controls);

  return offset;
}



static int
dissect_x411_SubmissionControls(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_Controls(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_SubmissionControlArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_SubmissionControls(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const asn_namedbit WaitingMessages_bits[] = {
  {  0, &hf_x411_WaitingMessages_long_content, -1, -1, "long-content", NULL },
  {  1, &hf_x411_WaitingMessages_low_priority, -1, -1, "low-priority", NULL },
  {  2, &hf_x411_WaitingMessages_other_security_labels, -1, -1, "other-security-labels", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x411_WaitingMessages(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    WaitingMessages_bits, hf_index, ett_x411_WaitingMessages,
                                    NULL);

  return offset;
}
static int dissect_waiting_messages_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_WaitingMessages(TRUE, tvb, offset, pinfo, tree, hf_x411_waiting_messages);
}


static const ber_sequence_t SET_OF_ContentType_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_waiting_content_types_item },
};

static int
dissect_x411_SET_OF_ContentType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_ContentType_set_of, hf_index, ett_x411_SET_OF_ContentType);

  return offset;
}
static int dissect_waiting_content_types_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SET_OF_ContentType(TRUE, tvb, offset, pinfo, tree, hf_x411_waiting_content_types);
}


static const ber_sequence_t Waiting_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_waiting_operations_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_waiting_messages_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_waiting_content_types_impl },
  { BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_waiting_encoded_information_types },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_Waiting(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              Waiting_set, hf_index, ett_x411_Waiting);

  return offset;
}



static int
dissect_x411_SubmissionControlResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_Waiting(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const ber_sequence_t ImproperlySpecifiedRecipients_sequence_of[1] = {
  { BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_ImproperlySpecifiedRecipients_item },
};

static int
dissect_x411_ImproperlySpecifiedRecipients(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      ImproperlySpecifiedRecipients_sequence_of, hf_index, ett_x411_ImproperlySpecifiedRecipients);

  return offset;
}


static const value_string x411_SecurityProblem_vals[] = {
  {   0, "assemby-instructions-conflict-with-security-services" },
  {   1, "authentication-problem" },
  {   2, "authentication-failure-on-subject-message" },
  {   3, "confidentiality-association-problem" },
  {   4, "decryption-failed" },
  {   5, "decryption-key-unobtainable" },
  {   6, "failure-of-proof-of-message" },
  {   7, "forbidden-user-security-label-register" },
  {   8, "incompatible-change-with-original-security-context" },
  {   9, "integrity-failure-on-subject-message" },
  {  10, "invalid-security-label" },
  {  11, "invalid-security-label-update" },
  {  12, "key-failure" },
  {  13, "mandatory-parameter-absence" },
  {  14, "operation-security-failure" },
  {  15, "redirection-prohibited" },
  {  16, "refused-alternate-recipient-name" },
  {  17, "repudiation-failure-of-message" },
  {  18, "responder-credentials-checking-problem" },
  {  19, "security-context-failure" },
  {  20, "security-context-problem" },
  {  21, "security-policy-violation" },
  {  22, "security-services-refusal" },
  {  23, "token-decryption-failed" },
  {  24, "token-error" },
  {  25, "unable-to-aggregate-security-labels" },
  {  26, "unauthorised-dl-name" },
  {  27, "unauthorised-entry-class" },
  {  28, "unauthorised-originally-intended-recipient-name" },
  {  29, "unauthorised-originator-name" },
  {  30, "unauthorised-recipient-name" },
  {  31, "unauthorised-security-label-update" },
  {  32, "unauthorised-user-name" },
  {  33, "unknown-security-label" },
  {  34, "unsupported-algorithm-identifier" },
  {  35, "unsupported-security-policy" },
  { 0, NULL }
};


static int
dissect_x411_SecurityProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



int
dissect_x411_MessageDeliveryIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_MTSIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_message_delivery_identifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MessageDeliveryIdentifier(FALSE, tvb, offset, pinfo, tree, hf_x411_message_delivery_identifier);
}


static const value_string x411_DeliveredContentType_vals[] = {
  {   0, "built-in" },
  {   1, "extended" },
  { 0, NULL }
};

static const ber_choice_t DeliveredContentType_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_built_in_impl },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_extended },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_DeliveredContentType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 DeliveredContentType_choice, hf_index, ett_x411_DeliveredContentType,
                                 NULL);

  return offset;
}
static int dissect_delivered_content_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_DeliveredContentType(FALSE, tvb, offset, pinfo, tree, hf_x411_delivered_content_type);
}



static int
dissect_x411_DeliveredOriginatorName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_originator_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_DeliveredOriginatorName(FALSE, tvb, offset, pinfo, tree, hf_x411_originator_name);
}


static const asn_namedbit DeliveryFlags_bits[] = {
  {  1, &hf_x411_DeliveryFlags_implicit_conversion_prohibited, -1, -1, "implicit-conversion-prohibited", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x411_DeliveryFlags(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    DeliveryFlags_bits, hf_index, ett_x411_DeliveryFlags,
                                    NULL);

  return offset;
}
static int dissect_delivery_flags_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_DeliveryFlags(TRUE, tvb, offset, pinfo, tree, hf_x411_delivery_flags);
}



static int
dissect_x411_OtherRecipientName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_OtherRecipientNames_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_OtherRecipientName(FALSE, tvb, offset, pinfo, tree, hf_x411_OtherRecipientNames_item);
}


static const ber_sequence_t OtherRecipientNames_sequence_of[1] = {
  { BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_OtherRecipientNames_item },
};

static int
dissect_x411_OtherRecipientNames(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      OtherRecipientNames_sequence_of, hf_index, ett_x411_OtherRecipientNames);

  return offset;
}
static int dissect_other_recipient_names_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_OtherRecipientNames(TRUE, tvb, offset, pinfo, tree, hf_x411_other_recipient_names);
}



static int
dissect_x411_ThisRecipientName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_this_recipient_name_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ThisRecipientName(TRUE, tvb, offset, pinfo, tree, hf_x411_this_recipient_name);
}



static int
dissect_x411_MTSOriginallyIntendedRecipientName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_originally_intended_recipient_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MTSOriginallyIntendedRecipientName(FALSE, tvb, offset, pinfo, tree, hf_x411_originally_intended_recipient_name);
}
static int dissect_originally_intended_recipient_name_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MTSOriginallyIntendedRecipientName(TRUE, tvb, offset, pinfo, tree, hf_x411_originally_intended_recipient_name);
}


static const ber_sequence_t OtherMessageDeliveryFields_set[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_delivered_content_type },
  { BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_originator_name },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_original_encoded_information_types_impl },
  { BER_CLASS_APP, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_priority },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_delivery_flags_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_other_recipient_names_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_this_recipient_name_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originally_intended_recipient_name_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_converted_encoded_information_types_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_message_submission_time_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_content_identifier_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

int
dissect_x411_OtherMessageDeliveryFields(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              OtherMessageDeliveryFields_set, hf_index, ett_x411_OtherMessageDeliveryFields);

  return offset;
}
static int dissect_other_fields(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_OtherMessageDeliveryFields(FALSE, tvb, offset, pinfo, tree, hf_x411_other_fields);
}


static const ber_sequence_t MessageDeliveryArgument_sequence[] = {
  { BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_message_delivery_identifier },
  { BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_message_delivery_time },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_other_fields },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_content },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_MessageDeliveryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MessageDeliveryArgument_sequence, hf_index, ett_x411_MessageDeliveryArgument);

  return offset;
}



static int
dissect_x411_RecipientCertificate(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509af_Certificates(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_recipient_certificate_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_RecipientCertificate(TRUE, tvb, offset, pinfo, tree, hf_x411_recipient_certificate);
}



static int
dissect_x411_ProofOfDelivery(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_Signature(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_proof_of_delivery_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ProofOfDelivery(TRUE, tvb, offset, pinfo, tree, hf_x411_proof_of_delivery);
}


static const ber_sequence_t MessageDeliveryResult_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_recipient_certificate_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_proof_of_delivery_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_MessageDeliveryResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              MessageDeliveryResult_set, hf_index, ett_x411_MessageDeliveryResult);

  return offset;
}



static int
dissect_x411_SubjectSubmissionIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_MTSIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_subject_submission_identifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SubjectSubmissionIdentifier(FALSE, tvb, offset, pinfo, tree, hf_x411_subject_submission_identifier);
}



static int
dissect_x411_MTSActualRecipientName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOrDirectoryName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_actual_recipient_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MTSActualRecipientName(FALSE, tvb, offset, pinfo, tree, hf_x411_actual_recipient_name);
}
static int dissect_actual_recipient_name_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MTSActualRecipientName(TRUE, tvb, offset, pinfo, tree, hf_x411_actual_recipient_name);
}


static const ber_sequence_t PerRecipientReportDeliveryFields_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_actual_recipient_name_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_delivery_report_type_impl },
  { BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_converted_encoded_information_types },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originally_intended_recipient_name_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_supplementary_information_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_PerRecipientReportDeliveryFields(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              PerRecipientReportDeliveryFields_set, hf_index, ett_x411_PerRecipientReportDeliveryFields);

  return offset;
}
static int dissect_per_recipient_report_delivery_fields_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PerRecipientReportDeliveryFields(FALSE, tvb, offset, pinfo, tree, hf_x411_per_recipient_report_delivery_fields_item);
}


static const ber_sequence_t SEQUENCE_OF_PerRecipientReportDeliveryFields_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_per_recipient_report_delivery_fields_item },
};

static int
dissect_x411_SEQUENCE_OF_PerRecipientReportDeliveryFields(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_PerRecipientReportDeliveryFields_sequence_of, hf_index, ett_x411_SEQUENCE_OF_PerRecipientReportDeliveryFields);

  return offset;
}
static int dissect_per_recipient_report_delivery_fields(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SEQUENCE_OF_PerRecipientReportDeliveryFields(FALSE, tvb, offset, pinfo, tree, hf_x411_per_recipient_report_delivery_fields);
}


static const ber_sequence_t ReportDeliveryArgument_set[] = {
  { BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_subject_submission_identifier },
  { BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_content_identifier },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_content_type },
  { BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_original_encoded_information_types },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_per_recipient_report_delivery_fields },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_returned_content_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_ReportDeliveryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ReportDeliveryArgument_set, hf_index, ett_x411_ReportDeliveryArgument);

  return offset;
}


static const value_string x411_ReportDeliveryResult_vals[] = {
  {   0, "empty-result" },
  {   1, "extensions" },
  {   2, "extensions" },
  { 0, NULL }
};

static const ber_choice_t ReportDeliveryResult_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_empty_result },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_extensions },
  {   2, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_extensions },
  {   3, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_extensions },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_ReportDeliveryResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ReportDeliveryResult_choice, hf_index, ett_x411_ReportDeliveryResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t DeliveryControlArgument_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_restrict_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_permissible_operations_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_permissible_maximum_content_length_impl },
  { BER_CLASS_APP, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_permissible_lowest_priority },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_permissible_content_types_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_permissible_encoded_information_types },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_permissible_security_context_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_DeliveryControlArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              DeliveryControlArgument_set, hf_index, ett_x411_DeliveryControlArgument);

  return offset;
}


static const ber_sequence_t DeliveryControlResult_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_waiting_operations_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_waiting_messages_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_waiting_content_types_impl },
  { BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_waiting_encoded_information_types },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_DeliveryControlResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              DeliveryControlResult_set, hf_index, ett_x411_DeliveryControlResult);

  return offset;
}


static const value_string x411_RefusedArgument_vals[] = {
  {   0, "user-name" },
  {   1, "user-address" },
  {   2, "deliverable-content-types" },
  {   3, "deliverable-maximum-content-length" },
  {   4, "deliverable-encoded-information-types-constraints" },
  {   5, "deliverable-security-labels" },
  {   6, "recipient-assigned-redirections" },
  {   7, "restricted-delivery" },
  {   8, "retrieve-registrations" },
  {  10, "restrict" },
  {  11, "permissible-operations" },
  {  12, "permissible-lowest-priority" },
  {  13, "permissible-encoded-information-types" },
  {  14, "permissible-content-types" },
  {  15, "permissible-maximum-content-length" },
  {  16, "permissible-security-context" },
  { 0, NULL }
};


static int
dissect_x411_RefusedArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_built_in_argument_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_RefusedArgument(TRUE, tvb, offset, pinfo, tree, hf_x411_built_in_argument);
}



static int
dissect_x411_T_refused_extension(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 252 "x411.cnf"
/*XXX not implemented yet */



  return offset;
}
static int dissect_refused_extension(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_T_refused_extension(FALSE, tvb, offset, pinfo, tree, hf_x411_refused_extension);
}


static const value_string x411_T_refused_argument_vals[] = {
  {   0, "built-in-argument" },
  {   1, "refused-extension" },
  { 0, NULL }
};

static const ber_choice_t T_refused_argument_choice[] = {
  {   0, BER_CLASS_CON, 1, 0, dissect_built_in_argument_impl },
  {   1, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_refused_extension },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_T_refused_argument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_refused_argument_choice, hf_index, ett_x411_T_refused_argument,
                                 NULL);

  return offset;
}
static int dissect_refused_argument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_T_refused_argument(FALSE, tvb, offset, pinfo, tree, hf_x411_refused_argument);
}


static const value_string x411_RefusalReason_vals[] = {
  {   0, "facility-unavailable" },
  {   1, "facility-not-subscribed" },
  {   2, "parameter-unacceptable" },
  { 0, NULL }
};


static int
dissect_x411_RefusalReason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_refusal_reason_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_RefusalReason(TRUE, tvb, offset, pinfo, tree, hf_x411_refusal_reason);
}


static const ber_sequence_t RefusedOperation_set[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_refused_argument },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_refusal_reason_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_RefusedOperation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              RefusedOperation_set, hf_index, ett_x411_RefusedOperation);

  return offset;
}



static int
dissect_x411_ProofOfDeliveryAlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_DeliveryControls(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_Controls(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_UserName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_user_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_UserName(FALSE, tvb, offset, pinfo, tree, hf_x411_user_name);
}


static const ber_sequence_t T_x121_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x121_address },
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tsap_id },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_T_x121(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_x121_sequence, hf_index, ett_x411_T_x121);

  return offset;
}
static int dissect_x121_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_T_x121(TRUE, tvb, offset, pinfo, tree, hf_x411_x121);
}



static int
dissect_x411_PSAPAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509sat_PresentationAddress(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_presentation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PSAPAddress(TRUE, tvb, offset, pinfo, tree, hf_x411_presentation);
}


static const value_string x411_UserAddress_vals[] = {
  {   0, "x121" },
  {   1, "presentation" },
  { 0, NULL }
};

static const ber_choice_t UserAddress_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_x121_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_presentation_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_UserAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 UserAddress_choice, hf_index, ett_x411_UserAddress,
                                 NULL);

  return offset;
}
static int dissect_user_address_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_UserAddress(TRUE, tvb, offset, pinfo, tree, hf_x411_user_address);
}


static const ber_sequence_t SET_OF_Priority_set_of[1] = {
  { BER_CLASS_APP, 7, BER_FLAGS_NOOWNTAG, dissect_priority_item },
};

static int
dissect_x411_SET_OF_Priority(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_Priority_set_of, hf_index, ett_x411_SET_OF_Priority);

  return offset;
}
static int dissect_class_priority_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SET_OF_Priority(TRUE, tvb, offset, pinfo, tree, hf_x411_class_priority);
}


static const value_string x411_T_objects_vals[] = {
  {   0, "messages" },
  {   1, "reports" },
  {   2, "both" },
  { 0, NULL }
};


static int
dissect_x411_T_objects(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_objects_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_T_objects(TRUE, tvb, offset, pinfo, tree, hf_x411_objects);
}


static const asn_namedbit T_source_type_bits[] = {
  {  0, &hf_x411_T_source_type_originated_by, -1, -1, "originated-by", NULL },
  {  1, &hf_x411_T_source_type_redirected_by, -1, -1, "redirected-by", NULL },
  {  2, &hf_x411_T_source_type_dl_expanded_by, -1, -1, "dl-expanded-by", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x411_T_source_type(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    T_source_type_bits, hf_index, ett_x411_T_source_type,
                                    NULL);

  return offset;
}
static int dissect_source_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_T_source_type(FALSE, tvb, offset, pinfo, tree, hf_x411_source_type);
}


static const value_string x411_ExactOrPattern_vals[] = {
  {   0, "exact-match" },
  {   1, "pattern-match" },
  { 0, NULL }
};

static const ber_choice_t ExactOrPattern_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_exact_match_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_pattern_match_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_ExactOrPattern(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ExactOrPattern_choice, hf_index, ett_x411_ExactOrPattern,
                                 NULL);

  return offset;
}
static int dissect_source_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ExactOrPattern(FALSE, tvb, offset, pinfo, tree, hf_x411_source_name);
}


static const ber_sequence_t Restriction_set[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_permitted },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_source_type },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_source_name },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_Restriction(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              Restriction_set, hf_index, ett_x411_Restriction);

  return offset;
}
static int dissect_applies_only_to_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_Restriction(FALSE, tvb, offset, pinfo, tree, hf_x411_applies_only_to_item);
}
static int dissect_RestrictedDelivery_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_Restriction(FALSE, tvb, offset, pinfo, tree, hf_x411_RestrictedDelivery_item);
}


static const ber_sequence_t SEQUENCE_OF_Restriction_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_applies_only_to_item },
};

static int
dissect_x411_SEQUENCE_OF_Restriction(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_Restriction_sequence_of, hf_index, ett_x411_SEQUENCE_OF_Restriction);

  return offset;
}
static int dissect_applies_only_to_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SEQUENCE_OF_Restriction(TRUE, tvb, offset, pinfo, tree, hf_x411_applies_only_to);
}


static const ber_sequence_t MessageClass_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_content_types_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_maximum_content_length_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_encoded_information_types_constraints_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_security_labels_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_class_priority_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_objects_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_applies_only_to_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_MessageClass(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              MessageClass_set, hf_index, ett_x411_MessageClass);

  return offset;
}



static int
dissect_x411_DeliverableClass(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_MessageClass(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_deliverable_class_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_DeliverableClass(FALSE, tvb, offset, pinfo, tree, hf_x411_deliverable_class_item);
}


static const ber_sequence_t SET_OF_DeliverableClass_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_deliverable_class_item },
};

static int
dissect_x411_SET_OF_DeliverableClass(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_DeliverableClass_set_of, hf_index, ett_x411_SET_OF_DeliverableClass);

  return offset;
}
static int dissect_deliverable_class(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SET_OF_DeliverableClass(FALSE, tvb, offset, pinfo, tree, hf_x411_deliverable_class);
}



static int
dissect_x411_DefaultDeliveryControls(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_Controls(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_default_delivery_controls(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_DefaultDeliveryControls(FALSE, tvb, offset, pinfo, tree, hf_x411_default_delivery_controls);
}



static int
dissect_x411_RedirectionClass(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_MessageClass(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_redirection_classes_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_RedirectionClass(FALSE, tvb, offset, pinfo, tree, hf_x411_redirection_classes_item);
}


static const ber_sequence_t SET_OF_RedirectionClass_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_redirection_classes_item },
};

static int
dissect_x411_SET_OF_RedirectionClass(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_RedirectionClass_set_of, hf_index, ett_x411_SET_OF_RedirectionClass);

  return offset;
}
static int dissect_redirection_classes_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SET_OF_RedirectionClass(TRUE, tvb, offset, pinfo, tree, hf_x411_redirection_classes);
}



static int
dissect_x411_RecipientAssignedAlternateRecipient(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOrDirectoryName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_recipient_assigned_alternate_recipient_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_RecipientAssignedAlternateRecipient(TRUE, tvb, offset, pinfo, tree, hf_x411_recipient_assigned_alternate_recipient);
}


static const ber_sequence_t RecipientRedirection_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirection_classes_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_recipient_assigned_alternate_recipient_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_RecipientRedirection(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              RecipientRedirection_set, hf_index, ett_x411_RecipientRedirection);

  return offset;
}
static int dissect_Redirections_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_RecipientRedirection(FALSE, tvb, offset, pinfo, tree, hf_x411_Redirections_item);
}


static const ber_sequence_t Redirections_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_Redirections_item },
};

static int
dissect_x411_Redirections(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      Redirections_sequence_of, hf_index, ett_x411_Redirections);

  return offset;
}
static int dissect_redirections_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_Redirections(TRUE, tvb, offset, pinfo, tree, hf_x411_redirections);
}


static const ber_sequence_t RestrictedDelivery_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_RestrictedDelivery_item },
};

static int
dissect_x411_RestrictedDelivery(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      RestrictedDelivery_sequence_of, hf_index, ett_x411_RestrictedDelivery);

  return offset;
}
static int dissect_restricted_delivery_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_RestrictedDelivery(TRUE, tvb, offset, pinfo, tree, hf_x411_restricted_delivery);
}


static const asn_namedbit T_standard_parameters_bits[] = {
  {  0, &hf_x411_T_standard_parameters_user_name, -1, -1, "user-name", NULL },
  {  1, &hf_x411_T_standard_parameters_user_address, -1, -1, "user-address", NULL },
  {  2, &hf_x411_T_standard_parameters_deliverable_class, -1, -1, "deliverable-class", NULL },
  {  3, &hf_x411_T_standard_parameters_default_delivery_controls, -1, -1, "default-delivery-controls", NULL },
  {  4, &hf_x411_T_standard_parameters_redirections, -1, -1, "redirections", NULL },
  {  5, &hf_x411_T_standard_parameters_restricted_delivery, -1, -1, "restricted-delivery", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x411_T_standard_parameters(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    T_standard_parameters_bits, hf_index, ett_x411_T_standard_parameters,
                                    NULL);

  return offset;
}
static int dissect_standard_parameters_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_T_standard_parameters(TRUE, tvb, offset, pinfo, tree, hf_x411_standard_parameters);
}



static int
dissect_x411_T_extensions_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 229 "x411.cnf"
/*XXX not implemented yet */



  return offset;
}
static int dissect_type_extensions_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_T_extensions_item(FALSE, tvb, offset, pinfo, tree, hf_x411_type_extensions_item);
}


static const ber_sequence_t T_extensions_set_of[1] = {
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_type_extensions_item },
};

static int
dissect_x411_T_extensions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 T_extensions_set_of, hf_index, ett_x411_T_extensions);

  return offset;
}
static int dissect_type_extensions_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_T_extensions(TRUE, tvb, offset, pinfo, tree, hf_x411_type_extensions);
}


static const ber_sequence_t RegistrationTypes_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_standard_parameters_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_type_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_RegistrationTypes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RegistrationTypes_sequence, hf_index, ett_x411_RegistrationTypes);

  return offset;
}
static int dissect_retrieve_registrations_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_RegistrationTypes(TRUE, tvb, offset, pinfo, tree, hf_x411_retrieve_registrations);
}


static const ber_sequence_t RegisterArgument_set[] = {
  { BER_CLASS_APP, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_user_name },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_user_address_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_deliverable_class },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_default_delivery_controls },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirections_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_restricted_delivery_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_retrieve_registrations_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_RegisterArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              RegisterArgument_set, hf_index, ett_x411_RegisterArgument);

  return offset;
}
static int dissect_registered_information_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_RegisterArgument(TRUE, tvb, offset, pinfo, tree, hf_x411_registered_information);
}


static const ber_sequence_t T_non_empty_result_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_registered_information_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_T_non_empty_result(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              T_non_empty_result_set, hf_index, ett_x411_T_non_empty_result);

  return offset;
}
static int dissect_non_empty_result(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_T_non_empty_result(FALSE, tvb, offset, pinfo, tree, hf_x411_non_empty_result);
}


static const value_string x411_RegisterResult_vals[] = {
  {   0, "empty-result" },
  {   1, "non-empty-result" },
  { 0, NULL }
};

static const ber_choice_t RegisterResult_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_empty_result },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_non_empty_result },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_RegisterResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 RegisterResult_choice, hf_index, ett_x411_RegisterResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChangeCredentialsArgument_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_old_credentials_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_new_credentials_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_ChangeCredentialsArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ChangeCredentialsArgument_set, hf_index, ett_x411_ChangeCredentialsArgument);

  return offset;
}


static const ber_sequence_t MessageDeliveryEnvelope_sequence[] = {
  { BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_message_delivery_identifier },
  { BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_message_delivery_time },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_other_fields },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_MessageDeliveryEnvelope(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MessageDeliveryEnvelope_sequence, hf_index, ett_x411_MessageDeliveryEnvelope);

  return offset;
}


static const ber_sequence_t ReportDeliveryEnvelope_set[] = {
  { BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_subject_submission_identifier },
  { BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_content_identifier },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_content_type },
  { BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_original_encoded_information_types },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_per_recipient_report_delivery_fields },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_ReportDeliveryEnvelope(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ReportDeliveryEnvelope_set, hf_index, ett_x411_ReportDeliveryEnvelope);

  return offset;
}


static const value_string x411_RecipientReassignmentProhibited_vals[] = {
  {   0, "recipient-reassignment-allowed" },
  {   1, "recipient-reassignment-prohibited" },
  { 0, NULL }
};


static int
dissect_x411_RecipientReassignmentProhibited(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_x411_MTSOriginatorRequestedAlternateRecipient(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOrDirectoryName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const value_string x411_DLExpansionProhibited_vals[] = {
  {   0, "dl-expansion-allowed" },
  {   1, "dl-expansion-prohibited" },
  { 0, NULL }
};


static int
dissect_x411_DLExpansionProhibited(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string x411_ConversionWithLossProhibited_vals[] = {
  {   0, "conversion-with-loss-allowed" },
  {   1, "conversion-with-loss-prohibited" },
  { 0, NULL }
};


static int
dissect_x411_ConversionWithLossProhibited(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_x411_LatestDeliveryTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_Time(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const value_string x411_RequestedDeliveryMethod_item_vals[] = {
  {   0, "any-delivery-method" },
  {   1, "mhs-delivery" },
  {   2, "physical-delivery" },
  {   3, "telex-delivery" },
  {   4, "teletex-delivery" },
  {   5, "g3-facsimile-delivery" },
  {   6, "g4-facsimile-delivery" },
  {   7, "ia5-terminal-delivery" },
  {   8, "videotex-delivery" },
  {   9, "telephone-delivery" },
  { 0, NULL }
};


static int
dissect_x411_RequestedDeliveryMethod_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_RequestedDeliveryMethod_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_RequestedDeliveryMethod_item(FALSE, tvb, offset, pinfo, tree, hf_x411_RequestedDeliveryMethod_item);
}


static const ber_sequence_t RequestedDeliveryMethod_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_RequestedDeliveryMethod_item },
};

int
dissect_x411_RequestedDeliveryMethod(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      RequestedDeliveryMethod_sequence_of, hf_index, ett_x411_RequestedDeliveryMethod);

  return offset;
}


static const value_string x411_PhysicalForwardingProhibited_vals[] = {
  {   0, "physical-forwarding-allowed" },
  {   1, "physical-forwarding-prohibited" },
  { 0, NULL }
};


static int
dissect_x411_PhysicalForwardingProhibited(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string x411_PhysicalForwardingAddressRequest_vals[] = {
  {   0, "physical-forwarding-address-not-requested" },
  {   1, "physical-forwarding-address-requested" },
  { 0, NULL }
};


static int
dissect_x411_PhysicalForwardingAddressRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const asn_namedbit PhysicalDeliveryModes_bits[] = {
  {  0, &hf_x411_PhysicalDeliveryModes_ordinary_mail, -1, -1, "ordinary-mail", NULL },
  {  1, &hf_x411_PhysicalDeliveryModes_special_delivery, -1, -1, "special-delivery", NULL },
  {  2, &hf_x411_PhysicalDeliveryModes_express_mail, -1, -1, "express-mail", NULL },
  {  3, &hf_x411_PhysicalDeliveryModes_counter_collection, -1, -1, "counter-collection", NULL },
  {  4, &hf_x411_PhysicalDeliveryModes_counter_collection_with_telephone_advice, -1, -1, "counter-collection-with-telephone-advice", NULL },
  {  5, &hf_x411_PhysicalDeliveryModes_counter_collection_with_telex_advice, -1, -1, "counter-collection-with-telex-advice", NULL },
  {  6, &hf_x411_PhysicalDeliveryModes_counter_collection_with_teletex_advice, -1, -1, "counter-collection-with-teletex-advice", NULL },
  {  7, &hf_x411_PhysicalDeliveryModes_bureau_fax_delivery, -1, -1, "bureau-fax-delivery", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x411_PhysicalDeliveryModes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    PhysicalDeliveryModes_bits, hf_index, ett_x411_PhysicalDeliveryModes,
                                    NULL);

  return offset;
}


static const value_string x411_RegisteredMailType_vals[] = {
  {   0, "non-registered-mail" },
  {   1, "registered-mail" },
  {   2, "registered-mail-to-addressee-in-person" },
  { 0, NULL }
};


static int
dissect_x411_RegisteredMailType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_x411_RecipientNumberForAdvice(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x411_PhysicalRenditionAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t ORAddress_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_built_in_standard_attributes },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_built_in_domain_defined_attributes },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extension_attributes },
  { 0, 0, 0, NULL }
};

int
dissect_x411_ORAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 508 "x411.cnf"
	
	oraddress = ep_alloc(MAX_ORA_STR_LEN); oraddress[0] = '\0';	
	doing_address = TRUE;
	address_item = NULL;

	  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ORAddress_sequence, hf_index, ett_x411_ORAddress);


	if(*oraddress && address_item)
		proto_item_append_text(address_item, " %s/", oraddress);

	doing_address = FALSE;



  return offset;
}



static int
dissect_x411_OriginatorReturnAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_ORAddress(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const value_string x411_PhysicalDeliveryReportRequest_vals[] = {
  {   0, "return-of-undeliverable-mail-by-PDS" },
  {   1, "return-of-notification-by-PDS" },
  {   2, "return-of-notification-by-MHS" },
  {   3, "return-of-notification-by-MHS-and-PDS" },
  { 0, NULL }
};


static int
dissect_x411_PhysicalDeliveryReportRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_x411_OriginatorCertificate(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509af_Certificates(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_ContentConfidentialityAlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_ContentIntegrityCheck(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_Signature(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_ContentIntegrityAlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_MessageOriginAuthenticationCheck(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_Signature(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_MessageOriginAuthenticationAlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_MessageSecurityLabel(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_SecurityLabel(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const value_string x411_ProofOfSubmissionRequest_vals[] = {
  {   0, "proof-of-submission-not-requested" },
  {   1, "proof-of-submission-requested" },
  { 0, NULL }
};


static int
dissect_x411_ProofOfSubmissionRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string x411_ProofOfDeliveryRequest_vals[] = {
  {   0, "proof-of-delivery-not-requested" },
  {   1, "proof-of-delivery-requested" },
  { 0, NULL }
};


static int
dissect_x411_ProofOfDeliveryRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string x411_ContentCorrelator_vals[] = {
  {   0, "ia5text" },
  {   1, "octets" },
  { 0, NULL }
};

static const ber_choice_t ContentCorrelator_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_ia5text },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_octets },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_ContentCorrelator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ContentCorrelator_choice, hf_index, ett_x411_ContentCorrelator,
                                 NULL);

  return offset;
}



static int
dissect_x411_ProbeOriginAuthenticationCheck(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_Signature(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_ProbeOriginAuthenticationAlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const ber_sequence_t IntendedRecipientName_sequence[] = {
  { BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_intended_recipient },
  { BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_redirection_time },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_IntendedRecipientName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   IntendedRecipientName_sequence, hf_index, ett_x411_IntendedRecipientName);

  return offset;
}
static int dissect_intended_recipient_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_IntendedRecipientName(FALSE, tvb, offset, pinfo, tree, hf_x411_intended_recipient_name);
}


static const value_string x411_RedirectionReason_vals[] = {
  {   0, "recipient-assigned-alternate-recipient" },
  {   1, "originator-requested-alternate-recipient" },
  {   2, "recipient-MD-assigned-alternate-recipient" },
  {   3, "directory-look-up" },
  {   4, "alias" },
  { 0, NULL }
};


static int
dissect_x411_RedirectionReason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_redirection_reason(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_RedirectionReason(FALSE, tvb, offset, pinfo, tree, hf_x411_redirection_reason);
}


static const ber_sequence_t Redirection_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_intended_recipient_name },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_redirection_reason },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_Redirection(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Redirection_sequence, hf_index, ett_x411_Redirection);

  return offset;
}
static int dissect_RedirectionHistory_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_Redirection(FALSE, tvb, offset, pinfo, tree, hf_x411_RedirectionHistory_item);
}


static const ber_sequence_t RedirectionHistory_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_RedirectionHistory_item },
};

static int
dissect_x411_RedirectionHistory(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      RedirectionHistory_sequence_of, hf_index, ett_x411_RedirectionHistory);

  return offset;
}


static const ber_sequence_t DLExpansion_sequence[] = {
  { BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_dl },
  { BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_dl_expansion_time },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_DLExpansion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DLExpansion_sequence, hf_index, ett_x411_DLExpansion);

  return offset;
}
static int dissect_DLExpansionHistory_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_DLExpansion(FALSE, tvb, offset, pinfo, tree, hf_x411_DLExpansionHistory_item);
}


static const ber_sequence_t DLExpansionHistory_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_DLExpansionHistory_item },
};

static int
dissect_x411_DLExpansionHistory(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      DLExpansionHistory_sequence_of, hf_index, ett_x411_DLExpansionHistory);

  return offset;
}



static int
dissect_x411_PhysicalForwardingAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const ber_sequence_t OriginatorAndDLExpansion_sequence[] = {
  { BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_originator_or_dl_name },
  { BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_origination_or_expansion_time },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_OriginatorAndDLExpansion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   OriginatorAndDLExpansion_sequence, hf_index, ett_x411_OriginatorAndDLExpansion);

  return offset;
}
static int dissect_OriginatorAndDLExpansionHistory_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_OriginatorAndDLExpansion(FALSE, tvb, offset, pinfo, tree, hf_x411_OriginatorAndDLExpansionHistory_item);
}


static const ber_sequence_t OriginatorAndDLExpansionHistory_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_OriginatorAndDLExpansionHistory_item },
};

static int
dissect_x411_OriginatorAndDLExpansionHistory(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      OriginatorAndDLExpansionHistory_sequence_of, hf_index, ett_x411_OriginatorAndDLExpansionHistory);

  return offset;
}



static int
dissect_x411_ReportingDLName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_ReportingMTACertificate(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509af_Certificates(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_ReportOriginAuthenticationCheck(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_Signature(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_ReportOriginAuthenticationAlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const ber_sequence_t PerRecipientDeliveryReportFields_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_message_delivery_time },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_type_of_MTS_user },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_recipient_certificate_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_PerRecipientDeliveryReportFields(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PerRecipientDeliveryReportFields_sequence, hf_index, ett_x411_PerRecipientDeliveryReportFields);

  return offset;
}
static int dissect_report_type_delivery_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PerRecipientDeliveryReportFields(TRUE, tvb, offset, pinfo, tree, hf_x411_report_type_delivery);
}


static const ber_sequence_t PerRecipientNonDeliveryReportFields_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_non_delivery_reason_code },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_non_delivery_diagnostic_code },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_PerRecipientNonDeliveryReportFields(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PerRecipientNonDeliveryReportFields_sequence, hf_index, ett_x411_PerRecipientNonDeliveryReportFields);

  return offset;
}
static int dissect_non_delivery_report_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_PerRecipientNonDeliveryReportFields(TRUE, tvb, offset, pinfo, tree, hf_x411_non_delivery_report);
}


static const value_string x411_T_report_type_vals[] = {
  {   0, "delivery" },
  {   1, "non-delivery" },
  { 0, NULL }
};

static const ber_choice_t T_report_type_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_report_type_delivery_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_non_delivery_report_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_T_report_type(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_report_type_choice, hf_index, ett_x411_T_report_type,
                                 NULL);

  return offset;
}
static int dissect_report_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_T_report_type(FALSE, tvb, offset, pinfo, tree, hf_x411_report_type);
}


static const ber_sequence_t PerRecipientReportFields_sequence[] = {
  { BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_actual_recipient_name },
  { BER_CLASS_APP, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_originally_intended_recipient_name },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_report_type },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_PerRecipientReportFields(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PerRecipientReportFields_sequence, hf_index, ett_x411_PerRecipientReportFields);

  return offset;
}



int
dissect_x411_OriginatingMTACertificate(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509af_Certificates(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



int
dissect_x411_ProofOfSubmission(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_Signature(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const ber_sequence_t ReportingMTAName_sequence[] = {
  { BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_domain },
  { BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_mta_name },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mta_directory_name_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_ReportingMTAName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ReportingMTAName_sequence, hf_index, ett_x411_ReportingMTAName);

  return offset;
}


static const value_string x411_ExtendedCertificate_vals[] = {
  {   0, "directory-entry" },
  {   1, "certificate" },
  { 0, NULL }
};

static const ber_choice_t ExtendedCertificate_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_directory_entry_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_certificate_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_ExtendedCertificate(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ExtendedCertificate_choice, hf_index, ett_x411_ExtendedCertificate,
                                 NULL);

  return offset;
}
static int dissect_ExtendedCertificates_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ExtendedCertificate(FALSE, tvb, offset, pinfo, tree, hf_x411_ExtendedCertificates_item);
}


static const ber_sequence_t ExtendedCertificates_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ExtendedCertificates_item },
};

int
dissect_x411_ExtendedCertificates(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 ExtendedCertificates_set_of, hf_index, ett_x411_ExtendedCertificates);

  return offset;
}


static const ber_sequence_t DLExemptedRecipients_set_of[1] = {
  { BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_DLExemptedRecipients_item },
};

static int
dissect_x411_DLExemptedRecipients(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 DLExemptedRecipients_set_of, hf_index, ett_x411_DLExemptedRecipients);

  return offset;
}


static const ber_sequence_t CertificateSelectors_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_encryption_recipient_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_encryption_originator_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_content_integrity_check_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_token_signature_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_message_origin_authentication_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_CertificateSelectors(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              CertificateSelectors_set, hf_index, ett_x411_CertificateSelectors);

  return offset;
}



static int
dissect_x411_CommonName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 450 "x411.cnf"
	tvbuff_t	*string = NULL;

	  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            &string);


	if(doing_address && string) {
		g_strlcat(oraddress, "/CN=", MAX_ORA_STR_LEN);
		g_strlcat(oraddress, tvb_format_text(string, 0, tvb_length(string)), MAX_ORA_STR_LEN);
	}





  return offset;
}



static int
dissect_x411_TeletexCommonName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x411_BMPString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_BMPString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_two_octets(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_BMPString(FALSE, tvb, offset, pinfo, tree, hf_x411_two_octets);
}



static int
dissect_x411_UniversalString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UniversalString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_four_octets(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_UniversalString(FALSE, tvb, offset, pinfo, tree, hf_x411_four_octets);
}


static const value_string x411_T_character_encoding_vals[] = {
  {   0, "two-octets" },
  {   1, "four-octets" },
  { 0, NULL }
};

static const ber_choice_t T_character_encoding_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_BMPString, BER_FLAGS_NOOWNTAG, dissect_two_octets },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_UniversalString, BER_FLAGS_NOOWNTAG, dissect_four_octets },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_T_character_encoding(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_character_encoding_choice, hf_index, ett_x411_T_character_encoding,
                                 NULL);

  return offset;
}
static int dissect_character_encoding(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_T_character_encoding(FALSE, tvb, offset, pinfo, tree, hf_x411_character_encoding);
}


static const ber_sequence_t UniversalOrBMPString_set[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_character_encoding },
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_iso_639_language_code },
  { 0, 0, 0, NULL }
};

int
dissect_x411_UniversalOrBMPString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              UniversalOrBMPString_set, hf_index, ett_x411_UniversalOrBMPString);

  return offset;
}
static int dissect_universal_surname_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_UniversalOrBMPString(TRUE, tvb, offset, pinfo, tree, hf_x411_universal_surname);
}
static int dissect_universal_given_name_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_UniversalOrBMPString(TRUE, tvb, offset, pinfo, tree, hf_x411_universal_given_name);
}
static int dissect_universal_initials_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_UniversalOrBMPString(TRUE, tvb, offset, pinfo, tree, hf_x411_universal_initials);
}
static int dissect_universal_generation_qualifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_UniversalOrBMPString(TRUE, tvb, offset, pinfo, tree, hf_x411_universal_generation_qualifier);
}
static int dissect_universal_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_UniversalOrBMPString(FALSE, tvb, offset, pinfo, tree, hf_x411_universal_type);
}
static int dissect_universal_value(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_UniversalOrBMPString(FALSE, tvb, offset, pinfo, tree, hf_x411_universal_value);
}



static int
dissect_x411_UniversalCommonName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_UniversalOrBMPString(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_TeletexOrganizationName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x411_UniversalOrganizationName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_UniversalOrBMPString(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const ber_sequence_t TeletexPersonalName_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_teletex_surname_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_teletex_given_name_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_teletex_initials_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_teletex_generation_qualifier_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_TeletexPersonalName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              TeletexPersonalName_set, hf_index, ett_x411_TeletexPersonalName);

  return offset;
}


static const ber_sequence_t UniversalPersonalName_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_universal_surname_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_universal_given_name_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_universal_initials_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_universal_generation_qualifier_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_UniversalPersonalName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              UniversalPersonalName_set, hf_index, ett_x411_UniversalPersonalName);

  return offset;
}



static int
dissect_x411_TeletexOrganizationalUnitName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_TeletexOrganizationalUnitNames_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_TeletexOrganizationalUnitName(FALSE, tvb, offset, pinfo, tree, hf_x411_TeletexOrganizationalUnitNames_item);
}


static const ber_sequence_t TeletexOrganizationalUnitNames_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_TeletexString, BER_FLAGS_NOOWNTAG, dissect_TeletexOrganizationalUnitNames_item },
};

static int
dissect_x411_TeletexOrganizationalUnitNames(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      TeletexOrganizationalUnitNames_sequence_of, hf_index, ett_x411_TeletexOrganizationalUnitNames);

  return offset;
}



static int
dissect_x411_UniversalOrganizationalUnitName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_UniversalOrBMPString(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_UniversalOrganizationalUnitNames_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_UniversalOrganizationalUnitName(FALSE, tvb, offset, pinfo, tree, hf_x411_UniversalOrganizationalUnitNames_item);
}


static const ber_sequence_t UniversalOrganizationalUnitNames_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_UniversalOrganizationalUnitNames_item },
};

static int
dissect_x411_UniversalOrganizationalUnitNames(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      UniversalOrganizationalUnitNames_sequence_of, hf_index, ett_x411_UniversalOrganizationalUnitNames);

  return offset;
}



static int
dissect_x411_PDSName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string x411_PhysicalDeliveryCountryName_vals[] = {
  {   0, "x121-dcc-code" },
  {   1, "iso-3166-alpha2-code" },
  { 0, NULL }
};

static const ber_choice_t PhysicalDeliveryCountryName_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_x121_dcc_code },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_iso_3166_alpha2_code },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_PhysicalDeliveryCountryName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 PhysicalDeliveryCountryName_choice, hf_index, ett_x411_PhysicalDeliveryCountryName,
                                 NULL);

  return offset;
}


static const value_string x411_PostalCode_vals[] = {
  {   0, "numeric-code" },
  {   1, "printable-code" },
  { 0, NULL }
};

static const ber_choice_t PostalCode_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_numeric_code },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_printable_code },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_PostalCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 PostalCode_choice, hf_index, ett_x411_PostalCode,
                                 NULL);

  return offset;
}


static const ber_sequence_t PDSParameter_set[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_printable_string },
  { BER_CLASS_UNI, BER_UNI_TAG_TeletexString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_teletex_string },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_PDSParameter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              PDSParameter_set, hf_index, ett_x411_PDSParameter);

  return offset;
}



static int
dissect_x411_PhysicalDeliveryOfficeName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_PDSParameter(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_UniversalPDSParameter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_UniversalOrBMPString(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_UniversalPhysicalDeliveryOfficeName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_UniversalPDSParameter(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_PhysicalDeliveryOfficeNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_PDSParameter(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_UniversalPhysicalDeliveryOfficeNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_UniversalPDSParameter(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_ExtensionORAddressComponents(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_PDSParameter(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_UniversalExtensionORAddressComponents(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_UniversalPDSParameter(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_PhysicalDeliveryPersonalName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_PDSParameter(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_UniversalPhysicalDeliveryPersonalName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_UniversalPDSParameter(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_PhysicalDeliveryOrganizationName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_PDSParameter(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_UniversalPhysicalDeliveryOrganizationName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_UniversalPDSParameter(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_ExtensionPhysicalDeliveryAddressComponents(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_PDSParameter(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_UniversalExtensionPhysicalDeliveryAddressComponents(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_UniversalPDSParameter(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const ber_sequence_t T_printable_address_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_printable_address_item },
};

static int
dissect_x411_T_printable_address(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_printable_address_sequence_of, hf_index, ett_x411_T_printable_address);

  return offset;
}
static int dissect_printable_address(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_T_printable_address(FALSE, tvb, offset, pinfo, tree, hf_x411_printable_address);
}


static const ber_sequence_t UnformattedPostalAddress_set[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_printable_address },
  { BER_CLASS_UNI, BER_UNI_TAG_TeletexString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_teletex_string },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_UnformattedPostalAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              UnformattedPostalAddress_set, hf_index, ett_x411_UnformattedPostalAddress);

  return offset;
}



static int
dissect_x411_UniversalUnformattedPostalAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_UniversalOrBMPString(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_StreetAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_PDSParameter(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_UniversalStreetAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_UniversalPDSParameter(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_PostOfficeBoxAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_PDSParameter(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_UniversalPostOfficeBoxAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_UniversalPDSParameter(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_UniversalPosteRestanteAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_UniversalPDSParameter(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_UniquePostalName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_PDSParameter(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_UniversalUniquePostalName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_UniversalPDSParameter(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_LocalPostalAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_PDSParameter(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_UniversalLocalPostalAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_UniversalPDSParameter(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const ber_sequence_t T_e163_4_address_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_number_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sub_address_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_T_e163_4_address(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_e163_4_address_sequence, hf_index, ett_x411_T_e163_4_address);

  return offset;
}
static int dissect_e163_4_address(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_T_e163_4_address(FALSE, tvb, offset, pinfo, tree, hf_x411_e163_4_address);
}


static const value_string x411_ExtendedNetworkAddress_vals[] = {
  {   0, "e163-4-address" },
  {   1, "psap-address" },
  { 0, NULL }
};

static const ber_choice_t ExtendedNetworkAddress_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_e163_4_address },
  {   1, BER_CLASS_CON, 0, 0, dissect_psap_address_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_ExtendedNetworkAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ExtendedNetworkAddress_choice, hf_index, ett_x411_ExtendedNetworkAddress,
                                 NULL);

  return offset;
}


static const value_string x411_TerminalType_vals[] = {
  {   3, "telex" },
  {   4, "teletex" },
  {   5, "g3-facsimile" },
  {   6, "g4-facsimile" },
  {   7, "ia5-terminal" },
  {   8, "videotex" },
  { 0, NULL }
};


static int
dissect_x411_TerminalType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t TeletexDomainDefinedAttribute_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_TeletexString, BER_FLAGS_NOOWNTAG, dissect_type },
  { BER_CLASS_UNI, BER_UNI_TAG_TeletexString, BER_FLAGS_NOOWNTAG, dissect_teletex_value },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_TeletexDomainDefinedAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   TeletexDomainDefinedAttribute_sequence, hf_index, ett_x411_TeletexDomainDefinedAttribute);

  return offset;
}
static int dissect_TeletexDomainDefinedAttributes_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_TeletexDomainDefinedAttribute(FALSE, tvb, offset, pinfo, tree, hf_x411_TeletexDomainDefinedAttributes_item);
}


static const ber_sequence_t TeletexDomainDefinedAttributes_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_TeletexDomainDefinedAttributes_item },
};

static int
dissect_x411_TeletexDomainDefinedAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      TeletexDomainDefinedAttributes_sequence_of, hf_index, ett_x411_TeletexDomainDefinedAttributes);

  return offset;
}


static const ber_sequence_t UniversalDomainDefinedAttribute_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_universal_type },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_universal_value },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_UniversalDomainDefinedAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   UniversalDomainDefinedAttribute_sequence, hf_index, ett_x411_UniversalDomainDefinedAttribute);

  return offset;
}
static int dissect_UniversalDomainDefinedAttributes_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_UniversalDomainDefinedAttribute(FALSE, tvb, offset, pinfo, tree, hf_x411_UniversalDomainDefinedAttributes_item);
}


static const ber_sequence_t UniversalDomainDefinedAttributes_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_UniversalDomainDefinedAttributes_item },
};

static int
dissect_x411_UniversalDomainDefinedAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      UniversalDomainDefinedAttributes_sequence_of, hf_index, ett_x411_UniversalDomainDefinedAttributes);

  return offset;
}


static const ber_sequence_t NonBasicParameters_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_g3_facsimile_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_teletex_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_NonBasicParameters(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              NonBasicParameters_set, hf_index, ett_x411_NonBasicParameters);

  return offset;
}


static const ber_sequence_t MTANameAndOptionalGDI_sequence[] = {
  { BER_CLASS_APP, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_global_domain_identifier },
  { BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_mta_name },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_MTANameAndOptionalGDI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 564 "x411.cnf"

	doing_address = TRUE;

	  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MTANameAndOptionalGDI_sequence, hf_index, ett_x411_MTANameAndOptionalGDI);


	doing_address = FALSE;
	proto_item_append_text(tree, ")");



  return offset;
}
static int dissect_token_mta_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_MTANameAndOptionalGDI(TRUE, tvb, offset, pinfo, tree, hf_x411_token_mta);
}


static const value_string x411_T_name_vals[] = {
  {   0, "recipient-name" },
  {   1, "mta" },
  { 0, NULL }
};

static const ber_choice_t T_name_choice[] = {
  {   0, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_token_recipient_name },
  {   1, BER_CLASS_CON, 3, 0, dissect_token_mta_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x411_T_name(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_name_choice, hf_index, ett_x411_T_name,
                                 NULL);

  return offset;
}
static int dissect_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_T_name(FALSE, tvb, offset, pinfo, tree, hf_x411_name);
}



static int
dissect_x411_RandomNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_x411_BindTokenSignedData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_RandomNumber(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_x411_TokenData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_BindTokenSignedData(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_signed_data_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_TokenData(TRUE, tvb, offset, pinfo, tree, hf_x411_signed_data);
}


static const ber_sequence_t AsymmetricTokenData_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signature_algorithm_identifier },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_name },
  { BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_time },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_signed_data_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_encryption_algorithm_identifier_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_encrypted_data_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_AsymmetricTokenData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AsymmetricTokenData_sequence, hf_index, ett_x411_AsymmetricTokenData);

  return offset;
}
static int dissect_asymmetric_token_data(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_AsymmetricTokenData(FALSE, tvb, offset, pinfo, tree, hf_x411_asymmetric_token_data);
}


static const ber_sequence_t AsymmetricToken_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_asymmetric_token_data },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithm_identifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_x411_AsymmetricToken(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AsymmetricToken_sequence, hf_index, ett_x411_AsymmetricToken);

  return offset;
}

/*--- PDUs ---*/

static void dissect_MTABindArgument_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_MTABindArgument(FALSE, tvb, 0, pinfo, tree, hf_x411_MTABindArgument_PDU);
}
static void dissect_MTABindResult_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_MTABindResult(FALSE, tvb, 0, pinfo, tree, hf_x411_MTABindResult_PDU);
}
static void dissect_MTABindError_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_MTABindError(FALSE, tvb, 0, pinfo, tree, hf_x411_MTABindError_PDU);
}
static void dissect_MTS_APDU_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_MTS_APDU(FALSE, tvb, 0, pinfo, tree, hf_x411_MTS_APDU_PDU);
}
static void dissect_InternalTraceInformation_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_InternalTraceInformation(FALSE, tvb, 0, pinfo, tree, hf_x411_InternalTraceInformation_PDU);
}
static void dissect_TraceInformation_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_TraceInformation(TRUE, tvb, 0, pinfo, tree, hf_x411_TraceInformation_PDU);
}
static void dissect_ReportDeliveryArgument_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_ReportDeliveryArgument(FALSE, tvb, 0, pinfo, tree, hf_x411_ReportDeliveryArgument_PDU);
}
static void dissect_ExtendedContentType_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_ExtendedContentType(FALSE, tvb, 0, pinfo, tree, hf_x411_ExtendedContentType_PDU);
}
static void dissect_ContentLength_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_ContentLength(FALSE, tvb, 0, pinfo, tree, hf_x411_ContentLength_PDU);
}
static void dissect_RecipientReassignmentProhibited_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_RecipientReassignmentProhibited(FALSE, tvb, 0, pinfo, tree, hf_x411_RecipientReassignmentProhibited_PDU);
}
static void dissect_MTSOriginatorRequestedAlternateRecipient_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_MTSOriginatorRequestedAlternateRecipient(FALSE, tvb, 0, pinfo, tree, hf_x411_MTSOriginatorRequestedAlternateRecipient_PDU);
}
static void dissect_DLExpansionProhibited_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_DLExpansionProhibited(FALSE, tvb, 0, pinfo, tree, hf_x411_DLExpansionProhibited_PDU);
}
static void dissect_ConversionWithLossProhibited_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_ConversionWithLossProhibited(FALSE, tvb, 0, pinfo, tree, hf_x411_ConversionWithLossProhibited_PDU);
}
static void dissect_LatestDeliveryTime_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_LatestDeliveryTime(FALSE, tvb, 0, pinfo, tree, hf_x411_LatestDeliveryTime_PDU);
}
static void dissect_RequestedDeliveryMethod_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_RequestedDeliveryMethod(FALSE, tvb, 0, pinfo, tree, hf_x411_RequestedDeliveryMethod_PDU);
}
static void dissect_PhysicalForwardingProhibited_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_PhysicalForwardingProhibited(FALSE, tvb, 0, pinfo, tree, hf_x411_PhysicalForwardingProhibited_PDU);
}
static void dissect_PhysicalForwardingAddressRequest_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_PhysicalForwardingAddressRequest(FALSE, tvb, 0, pinfo, tree, hf_x411_PhysicalForwardingAddressRequest_PDU);
}
static void dissect_PhysicalDeliveryModes_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_PhysicalDeliveryModes(FALSE, tvb, 0, pinfo, tree, hf_x411_PhysicalDeliveryModes_PDU);
}
static void dissect_RegisteredMailType_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_RegisteredMailType(FALSE, tvb, 0, pinfo, tree, hf_x411_RegisteredMailType_PDU);
}
static void dissect_RecipientNumberForAdvice_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_RecipientNumberForAdvice(FALSE, tvb, 0, pinfo, tree, hf_x411_RecipientNumberForAdvice_PDU);
}
static void dissect_PhysicalRenditionAttributes_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_PhysicalRenditionAttributes(FALSE, tvb, 0, pinfo, tree, hf_x411_PhysicalRenditionAttributes_PDU);
}
static void dissect_OriginatorReturnAddress_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_OriginatorReturnAddress(FALSE, tvb, 0, pinfo, tree, hf_x411_OriginatorReturnAddress_PDU);
}
static void dissect_PhysicalDeliveryReportRequest_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_PhysicalDeliveryReportRequest(FALSE, tvb, 0, pinfo, tree, hf_x411_PhysicalDeliveryReportRequest_PDU);
}
static void dissect_OriginatorCertificate_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_OriginatorCertificate(FALSE, tvb, 0, pinfo, tree, hf_x411_OriginatorCertificate_PDU);
}
static void dissect_ContentConfidentialityAlgorithmIdentifier_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_ContentConfidentialityAlgorithmIdentifier(FALSE, tvb, 0, pinfo, tree, hf_x411_ContentConfidentialityAlgorithmIdentifier_PDU);
}
static void dissect_ContentIntegrityCheck_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_ContentIntegrityCheck(FALSE, tvb, 0, pinfo, tree, hf_x411_ContentIntegrityCheck_PDU);
}
static void dissect_MessageOriginAuthenticationCheck_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_MessageOriginAuthenticationCheck(FALSE, tvb, 0, pinfo, tree, hf_x411_MessageOriginAuthenticationCheck_PDU);
}
static void dissect_MessageSecurityLabel_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_MessageSecurityLabel(FALSE, tvb, 0, pinfo, tree, hf_x411_MessageSecurityLabel_PDU);
}
static void dissect_ProofOfSubmissionRequest_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_ProofOfSubmissionRequest(FALSE, tvb, 0, pinfo, tree, hf_x411_ProofOfSubmissionRequest_PDU);
}
static void dissect_ProofOfDeliveryRequest_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_ProofOfDeliveryRequest(FALSE, tvb, 0, pinfo, tree, hf_x411_ProofOfDeliveryRequest_PDU);
}
static void dissect_ContentCorrelator_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_ContentCorrelator(FALSE, tvb, 0, pinfo, tree, hf_x411_ContentCorrelator_PDU);
}
static void dissect_ProbeOriginAuthenticationCheck_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_ProbeOriginAuthenticationCheck(FALSE, tvb, 0, pinfo, tree, hf_x411_ProbeOriginAuthenticationCheck_PDU);
}
static void dissect_RedirectionHistory_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_RedirectionHistory(FALSE, tvb, 0, pinfo, tree, hf_x411_RedirectionHistory_PDU);
}
static void dissect_DLExpansionHistory_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_DLExpansionHistory(FALSE, tvb, 0, pinfo, tree, hf_x411_DLExpansionHistory_PDU);
}
static void dissect_PhysicalForwardingAddress_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_PhysicalForwardingAddress(FALSE, tvb, 0, pinfo, tree, hf_x411_PhysicalForwardingAddress_PDU);
}
static void dissect_OriginatorAndDLExpansionHistory_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_OriginatorAndDLExpansionHistory(FALSE, tvb, 0, pinfo, tree, hf_x411_OriginatorAndDLExpansionHistory_PDU);
}
static void dissect_ReportingDLName_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_ReportingDLName(FALSE, tvb, 0, pinfo, tree, hf_x411_ReportingDLName_PDU);
}
static void dissect_ReportingMTACertificate_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_ReportingMTACertificate(FALSE, tvb, 0, pinfo, tree, hf_x411_ReportingMTACertificate_PDU);
}
static void dissect_ReportOriginAuthenticationCheck_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_ReportOriginAuthenticationCheck(FALSE, tvb, 0, pinfo, tree, hf_x411_ReportOriginAuthenticationCheck_PDU);
}
static void dissect_ProofOfSubmission_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_ProofOfSubmission(FALSE, tvb, 0, pinfo, tree, hf_x411_ProofOfSubmission_PDU);
}
static void dissect_ReportingMTAName_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_ReportingMTAName(FALSE, tvb, 0, pinfo, tree, hf_x411_ReportingMTAName_PDU);
}
static void dissect_ExtendedCertificates_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_ExtendedCertificates(FALSE, tvb, 0, pinfo, tree, hf_x411_ExtendedCertificates_PDU);
}
static void dissect_DLExemptedRecipients_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_DLExemptedRecipients(FALSE, tvb, 0, pinfo, tree, hf_x411_DLExemptedRecipients_PDU);
}
static void dissect_CertificateSelectors_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_CertificateSelectors(FALSE, tvb, 0, pinfo, tree, hf_x411_CertificateSelectors_PDU);
}
static void dissect_ORName_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_ORName(TRUE, tvb, 0, pinfo, tree, hf_x411_ORName_PDU);
}
static void dissect_ORAddress_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_ORAddress(FALSE, tvb, 0, pinfo, tree, hf_x411_ORAddress_PDU);
}
static void dissect_CommonName_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_CommonName(FALSE, tvb, 0, pinfo, tree, hf_x411_CommonName_PDU);
}
static void dissect_TeletexCommonName_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_TeletexCommonName(FALSE, tvb, 0, pinfo, tree, hf_x411_TeletexCommonName_PDU);
}
static void dissect_UniversalCommonName_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_UniversalCommonName(FALSE, tvb, 0, pinfo, tree, hf_x411_UniversalCommonName_PDU);
}
static void dissect_TeletexOrganizationName_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_TeletexOrganizationName(FALSE, tvb, 0, pinfo, tree, hf_x411_TeletexOrganizationName_PDU);
}
static void dissect_UniversalOrganizationName_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_UniversalOrganizationName(FALSE, tvb, 0, pinfo, tree, hf_x411_UniversalOrganizationName_PDU);
}
static void dissect_TeletexPersonalName_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_TeletexPersonalName(FALSE, tvb, 0, pinfo, tree, hf_x411_TeletexPersonalName_PDU);
}
static void dissect_UniversalPersonalName_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_UniversalPersonalName(FALSE, tvb, 0, pinfo, tree, hf_x411_UniversalPersonalName_PDU);
}
static void dissect_TeletexOrganizationalUnitNames_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_TeletexOrganizationalUnitNames(FALSE, tvb, 0, pinfo, tree, hf_x411_TeletexOrganizationalUnitNames_PDU);
}
static void dissect_UniversalOrganizationalUnitNames_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_UniversalOrganizationalUnitNames(FALSE, tvb, 0, pinfo, tree, hf_x411_UniversalOrganizationalUnitNames_PDU);
}
static void dissect_PDSName_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_PDSName(FALSE, tvb, 0, pinfo, tree, hf_x411_PDSName_PDU);
}
static void dissect_PhysicalDeliveryCountryName_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_PhysicalDeliveryCountryName(FALSE, tvb, 0, pinfo, tree, hf_x411_PhysicalDeliveryCountryName_PDU);
}
static void dissect_PostalCode_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_PostalCode(FALSE, tvb, 0, pinfo, tree, hf_x411_PostalCode_PDU);
}
static void dissect_PhysicalDeliveryOfficeName_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_PhysicalDeliveryOfficeName(FALSE, tvb, 0, pinfo, tree, hf_x411_PhysicalDeliveryOfficeName_PDU);
}
static void dissect_ExtendedEncodedInformationType_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_ExtendedEncodedInformationType(FALSE, tvb, 0, pinfo, tree, hf_x411_ExtendedEncodedInformationType_PDU);
}
static void dissect_MTANameAndOptionalGDI_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_MTANameAndOptionalGDI(FALSE, tvb, 0, pinfo, tree, hf_x411_MTANameAndOptionalGDI_PDU);
}
static void dissect_AsymmetricToken_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x411_AsymmetricToken(FALSE, tvb, 0, pinfo, tree, hf_x411_AsymmetricToken_PDU);
}


/*--- End of included file: packet-x411-fn.c ---*/
#line 80 "packet-x411-template.c"

static int
call_x411_oid_callback(char *base_oid, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
  const char *name = NULL;
  char extension_oid[BER_MAX_OID_STR_LEN];

  sprintf(extension_oid, "%s.%d", base_oid, extension_id);	

  name = get_ber_oid_name(extension_oid);
  proto_item_append_text(tree, " (%s)", name ? name : extension_oid); 

  return call_ber_oid_callback(extension_oid, tvb, offset, pinfo, tree);

}


/*
 * Dissect X411 MTS APDU
 */
int 
dissect_x411_mts_apdu (tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	/* save parent_tree so subdissectors can create new top nodes */
	top_tree=parent_tree;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_x411, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_x411);
	}

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "P1");
  	if (check_col(pinfo->cinfo, COL_INFO))
  		col_set_str(pinfo->cinfo, COL_INFO, "Transfer");

	return dissect_x411_MTS_APDU (FALSE, tvb, 0, pinfo, tree, hf_x411_MTS_APDU_PDU);
}

/*
* Dissect X411 PDUs inside a PPDU.
*/
static void
dissect_x411(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	int old_offset;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int (*x411_dissector)(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) = NULL;
	char *x411_op_name;
	int hf_x411_index;

	/* save parent_tree so subdissectors can create new top nodes */
	top_tree=parent_tree;

	/* do we have operation information from the ROS dissector?  */
	if( !pinfo->private_data ){
		if(parent_tree){
			proto_tree_add_text(parent_tree, tvb, offset, -1,
				"Internal error: can't get operation information from ROS dissector.");
		} 
		return  ;
	} else {
		session  = ( (struct SESSION_DATA_STRUCTURE*)(pinfo->private_data) );
	}

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_x411, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_x411);
	}
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "P1");
  	if (check_col(pinfo->cinfo, COL_INFO))
  		col_clear(pinfo->cinfo, COL_INFO);

	switch(session->ros_op & ROS_OP_MASK) {
	case (ROS_OP_BIND | ROS_OP_ARGUMENT):	/*  BindInvoke */
	  x411_dissector = dissect_x411_MTABindArgument;
	  x411_op_name = "Bind-Argument";
	  hf_x411_index = hf_x411_MTABindArgument_PDU;
	  break;
	case (ROS_OP_BIND | ROS_OP_RESULT):	/*  BindResult */
	  x411_dissector = dissect_x411_MTABindResult;
	  x411_op_name = "Bind-Result";
	  hf_x411_index = hf_x411_MTABindResult_PDU;
	  break;
	case (ROS_OP_BIND | ROS_OP_ERROR):	/*  BindError */
	  x411_dissector = dissect_x411_MTABindError;
	  x411_op_name = "Bind-Error";
	  hf_x411_index = hf_x411_MTABindError_PDU;
	  break;
	case (ROS_OP_INVOKE | ROS_OP_ARGUMENT):	/*  Invoke Argument */
	  x411_dissector = dissect_x411_MTS_APDU;
	  x411_op_name = "Transfer";
	  hf_x411_index = hf_x411_MTS_APDU_PDU;
	  break;
	default:
	  proto_tree_add_text(tree, tvb, offset, -1,"Unsupported X411 PDU");
	  return;
	}

	if (check_col(pinfo->cinfo, COL_INFO))
	  col_add_str(pinfo->cinfo, COL_INFO, x411_op_name);

	while (tvb_reported_length_remaining(tvb, offset) > 0){
		old_offset=offset;
		offset=(*x411_dissector)(FALSE, tvb, offset, pinfo , tree, hf_x411_index);
		if(offset == old_offset){
			proto_tree_add_text(tree, tvb, offset, -1,"Internal error, zero-byte X411 PDU");
			offset = tvb_length(tvb);
			break;
		}
	}
}


/*--- proto_register_x411 -------------------------------------------*/
void proto_register_x411(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {

/*--- Included file: packet-x411-hfarr.c ---*/
#line 1 "packet-x411-hfarr.c"
    { &hf_x411_MTABindArgument_PDU,
      { "MTABindArgument", "x411.MTABindArgument",
        FT_UINT32, BASE_DEC, VALS(x411_MTABindArgument_vals), 0,
        "MTABindArgument", HFILL }},
    { &hf_x411_MTABindResult_PDU,
      { "MTABindResult", "x411.MTABindResult",
        FT_UINT32, BASE_DEC, VALS(x411_MTABindResult_vals), 0,
        "MTABindResult", HFILL }},
    { &hf_x411_MTABindError_PDU,
      { "MTABindError", "x411.MTABindError",
        FT_UINT32, BASE_DEC, VALS(x411_MTABindError_vals), 0,
        "MTABindError", HFILL }},
    { &hf_x411_MTS_APDU_PDU,
      { "MTS-APDU", "x411.MTS_APDU",
        FT_UINT32, BASE_DEC, VALS(x411_MTS_APDU_vals), 0,
        "MTS-APDU", HFILL }},
    { &hf_x411_InternalTraceInformation_PDU,
      { "InternalTraceInformation", "x411.InternalTraceInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "InternalTraceInformation", HFILL }},
    { &hf_x411_TraceInformation_PDU,
      { "TraceInformation", "x411.TraceInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TraceInformation", HFILL }},
    { &hf_x411_ReportDeliveryArgument_PDU,
      { "ReportDeliveryArgument", "x411.ReportDeliveryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportDeliveryArgument", HFILL }},
    { &hf_x411_ExtendedContentType_PDU,
      { "ExtendedContentType", "x411.ExtendedContentType",
        FT_OID, BASE_NONE, NULL, 0,
        "ExtendedContentType", HFILL }},
    { &hf_x411_ContentLength_PDU,
      { "ContentLength", "x411.ContentLength",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ContentLength", HFILL }},
    { &hf_x411_RecipientReassignmentProhibited_PDU,
      { "RecipientReassignmentProhibited", "x411.RecipientReassignmentProhibited",
        FT_UINT32, BASE_DEC, VALS(x411_RecipientReassignmentProhibited_vals), 0,
        "RecipientReassignmentProhibited", HFILL }},
    { &hf_x411_MTSOriginatorRequestedAlternateRecipient_PDU,
      { "MTSOriginatorRequestedAlternateRecipient", "x411.MTSOriginatorRequestedAlternateRecipient",
        FT_NONE, BASE_NONE, NULL, 0,
        "MTSOriginatorRequestedAlternateRecipient", HFILL }},
    { &hf_x411_DLExpansionProhibited_PDU,
      { "DLExpansionProhibited", "x411.DLExpansionProhibited",
        FT_UINT32, BASE_DEC, VALS(x411_DLExpansionProhibited_vals), 0,
        "DLExpansionProhibited", HFILL }},
    { &hf_x411_ConversionWithLossProhibited_PDU,
      { "ConversionWithLossProhibited", "x411.ConversionWithLossProhibited",
        FT_UINT32, BASE_DEC, VALS(x411_ConversionWithLossProhibited_vals), 0,
        "ConversionWithLossProhibited", HFILL }},
    { &hf_x411_LatestDeliveryTime_PDU,
      { "LatestDeliveryTime", "x411.LatestDeliveryTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "LatestDeliveryTime", HFILL }},
    { &hf_x411_RequestedDeliveryMethod_PDU,
      { "RequestedDeliveryMethod", "x411.RequestedDeliveryMethod",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RequestedDeliveryMethod", HFILL }},
    { &hf_x411_PhysicalForwardingProhibited_PDU,
      { "PhysicalForwardingProhibited", "x411.PhysicalForwardingProhibited",
        FT_UINT32, BASE_DEC, VALS(x411_PhysicalForwardingProhibited_vals), 0,
        "PhysicalForwardingProhibited", HFILL }},
    { &hf_x411_PhysicalForwardingAddressRequest_PDU,
      { "PhysicalForwardingAddressRequest", "x411.PhysicalForwardingAddressRequest",
        FT_UINT32, BASE_DEC, VALS(x411_PhysicalForwardingAddressRequest_vals), 0,
        "PhysicalForwardingAddressRequest", HFILL }},
    { &hf_x411_PhysicalDeliveryModes_PDU,
      { "PhysicalDeliveryModes", "x411.PhysicalDeliveryModes",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PhysicalDeliveryModes", HFILL }},
    { &hf_x411_RegisteredMailType_PDU,
      { "RegisteredMailType", "x411.RegisteredMailType",
        FT_UINT32, BASE_DEC, VALS(x411_RegisteredMailType_vals), 0,
        "RegisteredMailType", HFILL }},
    { &hf_x411_RecipientNumberForAdvice_PDU,
      { "RecipientNumberForAdvice", "x411.RecipientNumberForAdvice",
        FT_STRING, BASE_NONE, NULL, 0,
        "RecipientNumberForAdvice", HFILL }},
    { &hf_x411_PhysicalRenditionAttributes_PDU,
      { "PhysicalRenditionAttributes", "x411.PhysicalRenditionAttributes",
        FT_OID, BASE_NONE, NULL, 0,
        "PhysicalRenditionAttributes", HFILL }},
    { &hf_x411_OriginatorReturnAddress_PDU,
      { "OriginatorReturnAddress", "x411.OriginatorReturnAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "OriginatorReturnAddress", HFILL }},
    { &hf_x411_PhysicalDeliveryReportRequest_PDU,
      { "PhysicalDeliveryReportRequest", "x411.PhysicalDeliveryReportRequest",
        FT_INT32, BASE_DEC, VALS(x411_PhysicalDeliveryReportRequest_vals), 0,
        "PhysicalDeliveryReportRequest", HFILL }},
    { &hf_x411_OriginatorCertificate_PDU,
      { "OriginatorCertificate", "x411.OriginatorCertificate",
        FT_NONE, BASE_NONE, NULL, 0,
        "OriginatorCertificate", HFILL }},
    { &hf_x411_ContentConfidentialityAlgorithmIdentifier_PDU,
      { "ContentConfidentialityAlgorithmIdentifier", "x411.ContentConfidentialityAlgorithmIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContentConfidentialityAlgorithmIdentifier", HFILL }},
    { &hf_x411_ContentIntegrityCheck_PDU,
      { "ContentIntegrityCheck", "x411.ContentIntegrityCheck",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContentIntegrityCheck", HFILL }},
    { &hf_x411_MessageOriginAuthenticationCheck_PDU,
      { "MessageOriginAuthenticationCheck", "x411.MessageOriginAuthenticationCheck",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageOriginAuthenticationCheck", HFILL }},
    { &hf_x411_MessageSecurityLabel_PDU,
      { "MessageSecurityLabel", "x411.MessageSecurityLabel",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageSecurityLabel", HFILL }},
    { &hf_x411_ProofOfSubmissionRequest_PDU,
      { "ProofOfSubmissionRequest", "x411.ProofOfSubmissionRequest",
        FT_UINT32, BASE_DEC, VALS(x411_ProofOfSubmissionRequest_vals), 0,
        "ProofOfSubmissionRequest", HFILL }},
    { &hf_x411_ProofOfDeliveryRequest_PDU,
      { "ProofOfDeliveryRequest", "x411.ProofOfDeliveryRequest",
        FT_UINT32, BASE_DEC, VALS(x411_ProofOfDeliveryRequest_vals), 0,
        "ProofOfDeliveryRequest", HFILL }},
    { &hf_x411_ContentCorrelator_PDU,
      { "ContentCorrelator", "x411.ContentCorrelator",
        FT_UINT32, BASE_DEC, VALS(x411_ContentCorrelator_vals), 0,
        "ContentCorrelator", HFILL }},
    { &hf_x411_ProbeOriginAuthenticationCheck_PDU,
      { "ProbeOriginAuthenticationCheck", "x411.ProbeOriginAuthenticationCheck",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProbeOriginAuthenticationCheck", HFILL }},
    { &hf_x411_RedirectionHistory_PDU,
      { "RedirectionHistory", "x411.RedirectionHistory",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RedirectionHistory", HFILL }},
    { &hf_x411_DLExpansionHistory_PDU,
      { "DLExpansionHistory", "x411.DLExpansionHistory",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DLExpansionHistory", HFILL }},
    { &hf_x411_PhysicalForwardingAddress_PDU,
      { "PhysicalForwardingAddress", "x411.PhysicalForwardingAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "PhysicalForwardingAddress", HFILL }},
    { &hf_x411_OriginatorAndDLExpansionHistory_PDU,
      { "OriginatorAndDLExpansionHistory", "x411.OriginatorAndDLExpansionHistory",
        FT_UINT32, BASE_DEC, NULL, 0,
        "OriginatorAndDLExpansionHistory", HFILL }},
    { &hf_x411_ReportingDLName_PDU,
      { "ReportingDLName", "x411.ReportingDLName",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportingDLName", HFILL }},
    { &hf_x411_ReportingMTACertificate_PDU,
      { "ReportingMTACertificate", "x411.ReportingMTACertificate",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportingMTACertificate", HFILL }},
    { &hf_x411_ReportOriginAuthenticationCheck_PDU,
      { "ReportOriginAuthenticationCheck", "x411.ReportOriginAuthenticationCheck",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportOriginAuthenticationCheck", HFILL }},
    { &hf_x411_ProofOfSubmission_PDU,
      { "ProofOfSubmission", "x411.ProofOfSubmission",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProofOfSubmission", HFILL }},
    { &hf_x411_ReportingMTAName_PDU,
      { "ReportingMTAName", "x411.ReportingMTAName",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportingMTAName", HFILL }},
    { &hf_x411_ExtendedCertificates_PDU,
      { "ExtendedCertificates", "x411.ExtendedCertificates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ExtendedCertificates", HFILL }},
    { &hf_x411_DLExemptedRecipients_PDU,
      { "DLExemptedRecipients", "x411.DLExemptedRecipients",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DLExemptedRecipients", HFILL }},
    { &hf_x411_CertificateSelectors_PDU,
      { "CertificateSelectors", "x411.CertificateSelectors",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateSelectors", HFILL }},
    { &hf_x411_ORName_PDU,
      { "ORName", "x411.ORName",
        FT_NONE, BASE_NONE, NULL, 0,
        "ORName", HFILL }},
    { &hf_x411_ORAddress_PDU,
      { "ORAddress", "x411.ORAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "ORAddress", HFILL }},
    { &hf_x411_CommonName_PDU,
      { "CommonName", "x411.CommonName",
        FT_STRING, BASE_NONE, NULL, 0,
        "CommonName", HFILL }},
    { &hf_x411_TeletexCommonName_PDU,
      { "TeletexCommonName", "x411.TeletexCommonName",
        FT_STRING, BASE_NONE, NULL, 0,
        "TeletexCommonName", HFILL }},
    { &hf_x411_UniversalCommonName_PDU,
      { "UniversalCommonName", "x411.UniversalCommonName",
        FT_NONE, BASE_NONE, NULL, 0,
        "UniversalCommonName", HFILL }},
    { &hf_x411_TeletexOrganizationName_PDU,
      { "TeletexOrganizationName", "x411.TeletexOrganizationName",
        FT_STRING, BASE_NONE, NULL, 0,
        "TeletexOrganizationName", HFILL }},
    { &hf_x411_UniversalOrganizationName_PDU,
      { "UniversalOrganizationName", "x411.UniversalOrganizationName",
        FT_NONE, BASE_NONE, NULL, 0,
        "UniversalOrganizationName", HFILL }},
    { &hf_x411_TeletexPersonalName_PDU,
      { "TeletexPersonalName", "x411.TeletexPersonalName",
        FT_NONE, BASE_NONE, NULL, 0,
        "TeletexPersonalName", HFILL }},
    { &hf_x411_UniversalPersonalName_PDU,
      { "UniversalPersonalName", "x411.UniversalPersonalName",
        FT_NONE, BASE_NONE, NULL, 0,
        "UniversalPersonalName", HFILL }},
    { &hf_x411_TeletexOrganizationalUnitNames_PDU,
      { "TeletexOrganizationalUnitNames", "x411.TeletexOrganizationalUnitNames",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TeletexOrganizationalUnitNames", HFILL }},
    { &hf_x411_UniversalOrganizationalUnitNames_PDU,
      { "UniversalOrganizationalUnitNames", "x411.UniversalOrganizationalUnitNames",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UniversalOrganizationalUnitNames", HFILL }},
    { &hf_x411_PDSName_PDU,
      { "PDSName", "x411.PDSName",
        FT_STRING, BASE_NONE, NULL, 0,
        "PDSName", HFILL }},
    { &hf_x411_PhysicalDeliveryCountryName_PDU,
      { "PhysicalDeliveryCountryName", "x411.PhysicalDeliveryCountryName",
        FT_UINT32, BASE_DEC, VALS(x411_PhysicalDeliveryCountryName_vals), 0,
        "PhysicalDeliveryCountryName", HFILL }},
    { &hf_x411_PostalCode_PDU,
      { "PostalCode", "x411.PostalCode",
        FT_UINT32, BASE_DEC, VALS(x411_PostalCode_vals), 0,
        "PostalCode", HFILL }},
    { &hf_x411_PhysicalDeliveryOfficeName_PDU,
      { "PhysicalDeliveryOfficeName", "x411.PhysicalDeliveryOfficeName",
        FT_NONE, BASE_NONE, NULL, 0,
        "PhysicalDeliveryOfficeName", HFILL }},
    { &hf_x411_ExtendedEncodedInformationType_PDU,
      { "ExtendedEncodedInformationType", "x411.ExtendedEncodedInformationType",
        FT_OID, BASE_NONE, NULL, 0,
        "ExtendedEncodedInformationType", HFILL }},
    { &hf_x411_MTANameAndOptionalGDI_PDU,
      { "MTANameAndOptionalGDI", "x411.MTANameAndOptionalGDI",
        FT_NONE, BASE_NONE, NULL, 0,
        "MTANameAndOptionalGDI", HFILL }},
    { &hf_x411_AsymmetricToken_PDU,
      { "AsymmetricToken", "x411.AsymmetricToken",
        FT_NONE, BASE_NONE, NULL, 0,
        "AsymmetricToken", HFILL }},
    { &hf_x411_unauthenticated,
      { "unauthenticated", "x411.unauthenticated",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_authenticated_argument,
      { "authenticated", "x411.authenticated",
        FT_NONE, BASE_NONE, NULL, 0,
        "MTABindArgument/authenticated", HFILL }},
    { &hf_x411_authenticated_initiator_name,
      { "initiator-name", "x411.initiator_name",
        FT_STRING, BASE_NONE, NULL, 0,
        "MTABindArgument/authenticated/initiator-name", HFILL }},
    { &hf_x411_initiator_credentials,
      { "initiator-credentials", "x411.initiator_credentials",
        FT_UINT32, BASE_DEC, VALS(x411_Credentials_vals), 0,
        "", HFILL }},
    { &hf_x411_security_context,
      { "security-context", "x411.security_context",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x411_authenticated_result,
      { "authenticated", "x411.authenticated",
        FT_NONE, BASE_NONE, NULL, 0,
        "MTABindResult/authenticated", HFILL }},
    { &hf_x411_authenticated_responder_name,
      { "responder-name", "x411.responder_name",
        FT_STRING, BASE_NONE, NULL, 0,
        "MTABindResult/authenticated/responder-name", HFILL }},
    { &hf_x411_responder_credentials,
      { "responder-credentials", "x411.responder_credentials",
        FT_UINT32, BASE_DEC, VALS(x411_Credentials_vals), 0,
        "", HFILL }},
    { &hf_x411_message,
      { "message", "x411.message",
        FT_NONE, BASE_NONE, NULL, 0,
        "MTS-APDU/message", HFILL }},
    { &hf_x411_probe,
      { "probe", "x411.probe",
        FT_NONE, BASE_NONE, NULL, 0,
        "MTS-APDU/probe", HFILL }},
    { &hf_x411_report,
      { "report", "x411.report",
        FT_NONE, BASE_NONE, NULL, 0,
        "MTS-APDU/report", HFILL }},
    { &hf_x411_message_envelope,
      { "envelope", "x411.envelope",
        FT_NONE, BASE_NONE, NULL, 0,
        "Message/envelope", HFILL }},
    { &hf_x411_content,
      { "content", "x411.content",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_x411_report_envelope,
      { "envelope", "x411.envelope",
        FT_NONE, BASE_NONE, NULL, 0,
        "Report/envelope", HFILL }},
    { &hf_x411_report_content,
      { "content", "x411.content",
        FT_NONE, BASE_NONE, NULL, 0,
        "Report/content", HFILL }},
    { &hf_x411_message_identifier,
      { "message-identifier", "x411.message_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageTransferEnvelope/message-identifier", HFILL }},
    { &hf_x411_mta_originator_name,
      { "originator-name", "x411.originator_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_original_encoded_information_types,
      { "original-encoded-information-types", "x411.original_encoded_information_types",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_content_type,
      { "content-type", "x411.content_type",
        FT_UINT32, BASE_DEC, VALS(x411_ContentType_vals), 0,
        "", HFILL }},
    { &hf_x411_content_identifier,
      { "content-identifier", "x411.content_identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_priority,
      { "priority", "x411.priority",
        FT_UINT32, BASE_DEC, VALS(x411_Priority_vals), 0,
        "", HFILL }},
    { &hf_x411_per_message_indicators,
      { "per-message-indicators", "x411.per_message_indicators",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_x411_deferred_delivery_time,
      { "deferred-delivery-time", "x411.deferred_delivery_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_per_domain_bilateral_information,
      { "per-domain-bilateral-information", "x411.per_domain_bilateral_information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x411_per_domain_bilateral_information_item,
      { "Item", "x411.per_domain_bilateral_information_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_trace_information,
      { "trace-information", "x411.trace_information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x411_extensions,
      { "extensions", "x411.extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x411_extensions_item,
      { "Item", "x411.extensions_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_per_recipient_message_fields,
      { "per-recipient-fields", "x411.per_recipient_fields",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MessageTransferEnvelope/per-recipient-fields", HFILL }},
    { &hf_x411_per_recipient_message_fields_item,
      { "Item", "x411.per_recipient_fields_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageTransferEnvelope/per-recipient-fields/_item", HFILL }},
    { &hf_x411_recipient_name,
      { "recipient-name", "x411.recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_originally_specified_recipient_number,
      { "originally-specified-recipient-number", "x411.originally_specified_recipient_number",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x411_per_recipient_indicators,
      { "per-recipient-indicators", "x411.per_recipient_indicators",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_x411_explicit_conversion,
      { "explicit-conversion", "x411.explicit_conversion",
        FT_UINT32, BASE_DEC, VALS(x411_ExplicitConversion_vals), 0,
        "", HFILL }},
    { &hf_x411_probe_identifier,
      { "probe-identifier", "x411.probe_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProbeTransferEnvelope/probe-identifier", HFILL }},
    { &hf_x411_content_length,
      { "content-length", "x411.content_length",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x411_per_recipient_probe_transfer_fields,
      { "per-recipient-fields", "x411.per_recipient_fields",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProbeTransferEnvelope/per-recipient-fields", HFILL }},
    { &hf_x411_per_recipient_probe_transfer_fields_item,
      { "Item", "x411.per_recipient_fields_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProbeTransferEnvelope/per-recipient-fields/_item", HFILL }},
    { &hf_x411_report_identifier,
      { "report-identifier", "x411.report_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportTransferEnvelope/report-identifier", HFILL }},
    { &hf_x411_report_destination_name,
      { "report-destination-name", "x411.report_destination_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportTransferEnvelope/report-destination-name", HFILL }},
    { &hf_x411_subject_identifier,
      { "subject-identifier", "x411.subject_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportTransferContent/subject-identifier", HFILL }},
    { &hf_x411_subject_intermediate_trace_information,
      { "subject-intermediate-trace-information", "x411.subject_intermediate_trace_information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ReportTransferContent/subject-intermediate-trace-information", HFILL }},
    { &hf_x411_returned_content,
      { "returned-content", "x411.returned_content",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_x411_additional_information,
      { "additional-information", "x411.additional_information",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportTransferContent/additional-information", HFILL }},
    { &hf_x411_per_recipient_report_fields,
      { "per-recipient-fields", "x411.per_recipient_fields",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ReportTransferContent/per-recipient-fields", HFILL }},
    { &hf_x411_per_recipient_fields_item,
      { "Item", "x411.per_recipient_fields_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportTransferContent/per-recipient-fields/_item", HFILL }},
    { &hf_x411_mta_actual_recipient_name,
      { "actual-recipient-name", "x411.actual_recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "PerRecipientReportTransferFields/actual-recipient-name", HFILL }},
    { &hf_x411_last_trace_information,
      { "last-trace-information", "x411.last_trace_information",
        FT_NONE, BASE_NONE, NULL, 0,
        "PerRecipientReportTransferFields/last-trace-information", HFILL }},
    { &hf_x411_report_originally_intended_recipient_name,
      { "originally-intended-recipient-name", "x411.originally_intended_recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "PerRecipientReportTransferFields/originally-intended-recipient-name", HFILL }},
    { &hf_x411_supplementary_information,
      { "supplementary-information", "x411.supplementary_information",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_country_name,
      { "country-name", "x411.country_name",
        FT_UINT32, BASE_DEC, VALS(x411_CountryName_vals), 0,
        "", HFILL }},
    { &hf_x411_bilateral_domain,
      { "domain", "x411.domain",
        FT_UINT32, BASE_DEC, VALS(x411_T_domain_vals), 0,
        "PerDomainBilateralInformation/domain", HFILL }},
    { &hf_x411_administration_domain_name,
      { "administration-domain-name", "x411.administration_domain_name",
        FT_UINT32, BASE_DEC, VALS(x411_AdministrationDomainName_vals), 0,
        "", HFILL }},
    { &hf_x411_private_domain,
      { "private-domain", "x411.private_domain",
        FT_NONE, BASE_NONE, NULL, 0,
        "PerDomainBilateralInformation/domain/private-domain", HFILL }},
    { &hf_x411_private_domain_identifier,
      { "private-domain-identifier", "x411.private_domain_identifier",
        FT_UINT32, BASE_DEC, VALS(x411_PrivateDomainIdentifier_vals), 0,
        "", HFILL }},
    { &hf_x411_arrival_time,
      { "arrival-time", "x411.arrival_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_converted_encoded_information_types,
      { "converted-encoded-information-types", "x411.converted_encoded_information_types",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_trace_report_type,
      { "report-type", "x411.report_type",
        FT_UINT32, BASE_DEC, VALS(x411_ReportType_vals), 0,
        "LastTraceInformation/report-type", HFILL }},
    { &hf_x411_InternalTraceInformation_item,
      { "Item", "x411.InternalTraceInformation_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "InternalTraceInformation/_item", HFILL }},
    { &hf_x411_global_domain_identifier,
      { "global-domain-identifier", "x411.global_domain_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_mta_name,
      { "mta-name", "x411.mta_name",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_mta_supplied_information,
      { "mta-supplied-information", "x411.mta_supplied_information",
        FT_NONE, BASE_NONE, NULL, 0,
        "InternalTraceInformationElement/mta-supplied-information", HFILL }},
    { &hf_x411_routing_action,
      { "routing-action", "x411.routing_action",
        FT_UINT32, BASE_DEC, VALS(x411_RoutingAction_vals), 0,
        "", HFILL }},
    { &hf_x411_attempted,
      { "attempted", "x411.attempted",
        FT_UINT32, BASE_DEC, VALS(x411_T_attempted_vals), 0,
        "MTASuppliedInformation/attempted", HFILL }},
    { &hf_x411_mta,
      { "mta", "x411.mta",
        FT_STRING, BASE_NONE, NULL, 0,
        "MTASuppliedInformation/attempted/mta", HFILL }},
    { &hf_x411_domain,
      { "domain", "x411.domain",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_deferred_time,
      { "deferred-time", "x411.deferred_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_other_actions,
      { "other-actions", "x411.other_actions",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_x411_TraceInformation_item,
      { "Item", "x411.TraceInformation_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "TraceInformation/_item", HFILL }},
    { &hf_x411_domain_supplied_information,
      { "domain-supplied-information", "x411.domain_supplied_information",
        FT_NONE, BASE_NONE, NULL, 0,
        "TraceInformationElement/domain-supplied-information", HFILL }},
    { &hf_x411_attempted_domain,
      { "attempted-domain", "x411.attempted_domain",
        FT_NONE, BASE_NONE, NULL, 0,
        "DomainSuppliedInformation/attempted-domain", HFILL }},
    { &hf_x411_initiator_name,
      { "initiator-name", "x411.initiator_name",
        FT_UINT32, BASE_DEC, VALS(x411_ObjectName_vals), 0,
        "MTSBindArgument/initiator-name", HFILL }},
    { &hf_x411_messages_waiting,
      { "messages-waiting", "x411.messages_waiting",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_responder_name,
      { "responder-name", "x411.responder_name",
        FT_UINT32, BASE_DEC, VALS(x411_ObjectName_vals), 0,
        "MTSBindResult/responder-name", HFILL }},
    { &hf_x411_user_agent,
      { "user-agent", "x411.user_agent",
        FT_NONE, BASE_NONE, NULL, 0,
        "ObjectName/user-agent", HFILL }},
    { &hf_x411_mTA,
      { "mTA", "x411.mTA",
        FT_STRING, BASE_NONE, NULL, 0,
        "ObjectName/mTA", HFILL }},
    { &hf_x411_message_store,
      { "message-store", "x411.message_store",
        FT_NONE, BASE_NONE, NULL, 0,
        "ObjectName/message-store", HFILL }},
    { &hf_x411_urgent,
      { "urgent", "x411.urgent",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessagesWaiting/urgent", HFILL }},
    { &hf_x411_normal,
      { "normal", "x411.normal",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessagesWaiting/normal", HFILL }},
    { &hf_x411_non_urgent,
      { "non-urgent", "x411.non_urgent",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessagesWaiting/non-urgent", HFILL }},
    { &hf_x411_messages,
      { "messages", "x411.messages",
        FT_INT32, BASE_DEC, NULL, 0,
        "DeliveryQueue/messages", HFILL }},
    { &hf_x411_delivery_queue_octets,
      { "octets", "x411.octets",
        FT_INT32, BASE_DEC, NULL, 0,
        "DeliveryQueue/octets", HFILL }},
    { &hf_x411_simple,
      { "simple", "x411.simple",
        FT_UINT32, BASE_DEC, VALS(x411_Password_vals), 0,
        "Credentials/simple", HFILL }},
    { &hf_x411_strong,
      { "strong", "x411.strong",
        FT_NONE, BASE_NONE, NULL, 0,
        "Credentials/strong", HFILL }},
    { &hf_x411_protected,
      { "protected", "x411.protected",
        FT_NONE, BASE_NONE, NULL, 0,
        "Credentials/protected", HFILL }},
    { &hf_x411_ia5_string,
      { "ia5-string", "x411.ia5_string",
        FT_STRING, BASE_NONE, NULL, 0,
        "Password/ia5-string", HFILL }},
    { &hf_x411_octet_string,
      { "octet-string", "x411.octet_string",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Password/octet-string", HFILL }},
    { &hf_x411_bind_token,
      { "bind-token", "x411.bind_token",
        FT_NONE, BASE_NONE, NULL, 0,
        "StrongCredentials/bind-token", HFILL }},
    { &hf_x411_certificate,
      { "certificate", "x411.certificate",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_certificate_selector,
      { "certificate-selector", "x411.certificate_selector",
        FT_NONE, BASE_NONE, NULL, 0,
        "StrongCredentials/certificate-selector", HFILL }},
    { &hf_x411_signature,
      { "signature", "x411.signature",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtectedPassword/signature", HFILL }},
    { &hf_x411_time1,
      { "time1", "x411.time1",
        FT_STRING, BASE_NONE, NULL, 0,
        "ProtectedPassword/time1", HFILL }},
    { &hf_x411_time2,
      { "time2", "x411.time2",
        FT_STRING, BASE_NONE, NULL, 0,
        "ProtectedPassword/time2", HFILL }},
    { &hf_x411_random1,
      { "random1", "x411.random1",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ProtectedPassword/random1", HFILL }},
    { &hf_x411_random2,
      { "random2", "x411.random2",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ProtectedPassword/random2", HFILL }},
    { &hf_x411_algorithmIdentifier,
      { "algorithmIdentifier", "x411.algorithmIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "Signature/algorithmIdentifier", HFILL }},
    { &hf_x411_encrypted,
      { "encrypted", "x411.encrypted",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_x411_SecurityContext_item,
      { "Item", "x411.SecurityContext_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityContext/_item", HFILL }},
    { &hf_x411_message_submission_envelope,
      { "envelope", "x411.envelope",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageSubmissionArgument/envelope", HFILL }},
    { &hf_x411_message_submission_identifier,
      { "message-submission-identifier", "x411.message_submission_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageSubmissionResult/message-submission-identifier", HFILL }},
    { &hf_x411_message_submission_time,
      { "message-submission-time", "x411.message_submission_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_probe_submission_identifier,
      { "probe-submission-identifier", "x411.probe_submission_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProbeSubmissionResult/probe-submission-identifier", HFILL }},
    { &hf_x411_probe_submission_time,
      { "probe-submission-time", "x411.probe_submission_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "ProbeSubmissionResult/probe-submission-time", HFILL }},
    { &hf_x411_ImproperlySpecifiedRecipients_item,
      { "Item", "x411.ImproperlySpecifiedRecipients_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ImproperlySpecifiedRecipients/_item", HFILL }},
    { &hf_x411_waiting_operations,
      { "waiting-operations", "x411.waiting_operations",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_x411_waiting_messages,
      { "waiting-messages", "x411.waiting_messages",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_x411_waiting_content_types,
      { "waiting-content-types", "x411.waiting_content_types",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x411_waiting_content_types_item,
      { "Item", "x411.waiting_content_types_item",
        FT_UINT32, BASE_DEC, VALS(x411_ContentType_vals), 0,
        "", HFILL }},
    { &hf_x411_waiting_encoded_information_types,
      { "waiting-encoded-information-types", "x411.waiting_encoded_information_types",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_message_delivery_identifier,
      { "message-delivery-identifier", "x411.message_delivery_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_message_delivery_time,
      { "message-delivery-time", "x411.message_delivery_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_other_fields,
      { "other-fields", "x411.other_fields",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_recipient_certificate,
      { "recipient-certificate", "x411.recipient_certificate",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_proof_of_delivery,
      { "proof-of-delivery", "x411.proof_of_delivery",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageDeliveryResult/proof-of-delivery", HFILL }},
    { &hf_x411_subject_submission_identifier,
      { "subject-submission-identifier", "x411.subject_submission_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_per_recipient_report_delivery_fields,
      { "per-recipient-fields", "x411.per_recipient_fields",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x411_per_recipient_report_delivery_fields_item,
      { "Item", "x411.per_recipient_fields_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_empty_result,
      { "empty-result", "x411.empty_result",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_restrict,
      { "restrict", "x411.restrict",
        FT_BOOLEAN, 8, NULL, 0,
        "", HFILL }},
    { &hf_x411_permissible_operations,
      { "permissible-operations", "x411.permissible_operations",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_x411_permissible_maximum_content_length,
      { "permissible-maximum-content-length", "x411.permissible_maximum_content_length",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x411_permissible_lowest_priority,
      { "permissible-lowest-priority", "x411.permissible_lowest_priority",
        FT_UINT32, BASE_DEC, VALS(x411_Priority_vals), 0,
        "", HFILL }},
    { &hf_x411_permissible_content_types,
      { "permissible-content-types", "x411.permissible_content_types",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x411_permissible_encoded_information_types,
      { "permissible-encoded-information-types", "x411.permissible_encoded_information_types",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_permissible_security_context,
      { "permissible-security-context", "x411.permissible_security_context",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x411_refused_argument,
      { "refused-argument", "x411.refused_argument",
        FT_UINT32, BASE_DEC, VALS(x411_T_refused_argument_vals), 0,
        "RefusedOperation/refused-argument", HFILL }},
    { &hf_x411_built_in_argument,
      { "built-in-argument", "x411.built_in_argument",
        FT_UINT32, BASE_DEC, VALS(x411_RefusedArgument_vals), 0,
        "RefusedOperation/refused-argument/built-in-argument", HFILL }},
    { &hf_x411_refused_extension,
      { "refused-extension", "x411.refused_extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "RefusedOperation/refused-argument/refused-extension", HFILL }},
    { &hf_x411_refusal_reason,
      { "refusal-reason", "x411.refusal_reason",
        FT_UINT32, BASE_DEC, VALS(x411_RefusalReason_vals), 0,
        "RefusedOperation/refusal-reason", HFILL }},
    { &hf_x411_user_name,
      { "user-name", "x411.user_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegisterArgument/user-name", HFILL }},
    { &hf_x411_user_address,
      { "user-address", "x411.user_address",
        FT_UINT32, BASE_DEC, VALS(x411_UserAddress_vals), 0,
        "RegisterArgument/user-address", HFILL }},
    { &hf_x411_deliverable_class,
      { "deliverable-class", "x411.deliverable_class",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RegisterArgument/deliverable-class", HFILL }},
    { &hf_x411_deliverable_class_item,
      { "Item", "x411.deliverable_class_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegisterArgument/deliverable-class/_item", HFILL }},
    { &hf_x411_default_delivery_controls,
      { "default-delivery-controls", "x411.default_delivery_controls",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegisterArgument/default-delivery-controls", HFILL }},
    { &hf_x411_redirections,
      { "redirections", "x411.redirections",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RegisterArgument/redirections", HFILL }},
    { &hf_x411_restricted_delivery,
      { "restricted-delivery", "x411.restricted_delivery",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RegisterArgument/restricted-delivery", HFILL }},
    { &hf_x411_retrieve_registrations,
      { "retrieve-registrations", "x411.retrieve_registrations",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegisterArgument/retrieve-registrations", HFILL }},
    { &hf_x411_non_empty_result,
      { "non-empty-result", "x411.non_empty_result",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegisterResult/non-empty-result", HFILL }},
    { &hf_x411_registered_information,
      { "registered-information", "x411.registered_information",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegisterResult/non-empty-result/registered-information", HFILL }},
    { &hf_x411_old_credentials,
      { "old-credentials", "x411.old_credentials",
        FT_UINT32, BASE_DEC, VALS(x411_Credentials_vals), 0,
        "ChangeCredentialsArgument/old-credentials", HFILL }},
    { &hf_x411_new_credentials,
      { "new-credentials", "x411.new_credentials",
        FT_UINT32, BASE_DEC, VALS(x411_Credentials_vals), 0,
        "ChangeCredentialsArgument/new-credentials", HFILL }},
    { &hf_x411_x121,
      { "x121", "x411.x121",
        FT_NONE, BASE_NONE, NULL, 0,
        "UserAddress/x121", HFILL }},
    { &hf_x411_x121_address,
      { "x121-address", "x411.x121_address",
        FT_STRING, BASE_NONE, NULL, 0,
        "UserAddress/x121/x121-address", HFILL }},
    { &hf_x411_tsap_id,
      { "tsap-id", "x411.tsap_id",
        FT_STRING, BASE_NONE, NULL, 0,
        "UserAddress/x121/tsap-id", HFILL }},
    { &hf_x411_presentation,
      { "presentation", "x411.presentation",
        FT_NONE, BASE_NONE, NULL, 0,
        "UserAddress/presentation", HFILL }},
    { &hf_x411_Redirections_item,
      { "Item", "x411.Redirections_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "Redirections/_item", HFILL }},
    { &hf_x411_redirection_classes,
      { "redirection-classes", "x411.redirection_classes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RecipientRedirection/redirection-classes", HFILL }},
    { &hf_x411_redirection_classes_item,
      { "Item", "x411.redirection_classes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RecipientRedirection/redirection-classes/_item", HFILL }},
    { &hf_x411_recipient_assigned_alternate_recipient,
      { "recipient-assigned-alternate-recipient", "x411.recipient_assigned_alternate_recipient",
        FT_NONE, BASE_NONE, NULL, 0,
        "RecipientRedirection/recipient-assigned-alternate-recipient", HFILL }},
    { &hf_x411_content_types,
      { "content-types", "x411.content_types",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MessageClass/content-types", HFILL }},
    { &hf_x411_maximum_content_length,
      { "maximum-content-length", "x411.maximum_content_length",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MessageClass/maximum-content-length", HFILL }},
    { &hf_x411_encoded_information_types_constraints,
      { "encoded-information-types-constraints", "x411.encoded_information_types_constraints",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageClass/encoded-information-types-constraints", HFILL }},
    { &hf_x411_security_labels,
      { "security-labels", "x411.security_labels",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MessageClass/security-labels", HFILL }},
    { &hf_x411_class_priority,
      { "priority", "x411.priority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MessageClass/priority", HFILL }},
    { &hf_x411_priority_item,
      { "Item", "x411.priority_item",
        FT_UINT32, BASE_DEC, VALS(x411_Priority_vals), 0,
        "MessageClass/priority/_item", HFILL }},
    { &hf_x411_objects,
      { "objects", "x411.objects",
        FT_UINT32, BASE_DEC, VALS(x411_T_objects_vals), 0,
        "MessageClass/objects", HFILL }},
    { &hf_x411_applies_only_to,
      { "applies-only-to", "x411.applies_only_to",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MessageClass/applies-only-to", HFILL }},
    { &hf_x411_applies_only_to_item,
      { "Item", "x411.applies_only_to_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageClass/applies-only-to/_item", HFILL }},
    { &hf_x411_unacceptable_eits,
      { "unacceptable-eits", "x411.unacceptable_eits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EncodedInformationTypesConstraints/unacceptable-eits", HFILL }},
    { &hf_x411_acceptable_eits,
      { "acceptable-eits", "x411.acceptable_eits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EncodedInformationTypesConstraints/acceptable-eits", HFILL }},
    { &hf_x411_exclusively_acceptable_eits,
      { "exclusively-acceptable-eits", "x411.exclusively_acceptable_eits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EncodedInformationTypesConstraints/exclusively-acceptable-eits", HFILL }},
    { &hf_x411_RestrictedDelivery_item,
      { "Item", "x411.RestrictedDelivery_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RestrictedDelivery/_item", HFILL }},
    { &hf_x411_permitted,
      { "permitted", "x411.permitted",
        FT_BOOLEAN, 8, NULL, 0,
        "Restriction/permitted", HFILL }},
    { &hf_x411_source_type,
      { "source-type", "x411.source_type",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Restriction/source-type", HFILL }},
    { &hf_x411_source_name,
      { "source-name", "x411.source_name",
        FT_UINT32, BASE_DEC, VALS(x411_ExactOrPattern_vals), 0,
        "Restriction/source-name", HFILL }},
    { &hf_x411_exact_match,
      { "exact-match", "x411.exact_match",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExactOrPattern/exact-match", HFILL }},
    { &hf_x411_pattern_match,
      { "pattern-match", "x411.pattern_match",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExactOrPattern/pattern-match", HFILL }},
    { &hf_x411_standard_parameters,
      { "standard-parameters", "x411.standard_parameters",
        FT_BYTES, BASE_HEX, NULL, 0,
        "RegistrationTypes/standard-parameters", HFILL }},
    { &hf_x411_type_extensions,
      { "extensions", "x411.extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RegistrationTypes/extensions", HFILL }},
    { &hf_x411_type_extensions_item,
      { "Item", "x411.extensions_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegistrationTypes/extensions/_item", HFILL }},
    { &hf_x411_mts_originator_name,
      { "originator-name", "x411.originator_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_per_recipient_message_submission_fields,
      { "per-recipient-fields", "x411.per_recipient_fields",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MessageSubmissionEnvelope/per-recipient-fields", HFILL }},
    { &hf_x411_per_recipient_message_submission_fields_item,
      { "Item", "x411.per_recipient_fields_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageSubmissionEnvelope/per-recipient-fields/_item", HFILL }},
    { &hf_x411_submission_recipient_name,
      { "recipient-name", "x411.recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "PerRecipientMessageSubmissionFields/recipient-name", HFILL }},
    { &hf_x411_originator_report_request,
      { "originator-report-request", "x411.originator_report_request",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_x411_per_recipient_probe_submission_fields,
      { "per-recipient-fields", "x411.per_recipient_fields",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProbeSubmissionEnvelope/per-recipient-fields", HFILL }},
    { &hf_x411_per_recipient_probe_submission_fields_item,
      { "Item", "x411.per_recipient_fields_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProbeSubmissionEnvelope/per-recipient-fields/_item", HFILL }},
    { &hf_x411_probe_recipient_name,
      { "recipient-name", "x411.recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "PerRecipientProbeSubmissionFields/recipient-name", HFILL }},
    { &hf_x411_delivered_content_type,
      { "content-type", "x411.content_type",
        FT_UINT32, BASE_DEC, VALS(x411_DeliveredContentType_vals), 0,
        "OtherMessageDeliveryFields/content-type", HFILL }},
    { &hf_x411_originator_name,
      { "originator-name", "x411.originator_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "OtherMessageDeliveryFields/originator-name", HFILL }},
    { &hf_x411_delivery_flags,
      { "delivery-flags", "x411.delivery_flags",
        FT_BYTES, BASE_HEX, NULL, 0,
        "OtherMessageDeliveryFields/delivery-flags", HFILL }},
    { &hf_x411_other_recipient_names,
      { "other-recipient-names", "x411.other_recipient_names",
        FT_UINT32, BASE_DEC, NULL, 0,
        "OtherMessageDeliveryFields/other-recipient-names", HFILL }},
    { &hf_x411_this_recipient_name,
      { "this-recipient-name", "x411.this_recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "OtherMessageDeliveryFields/this-recipient-name", HFILL }},
    { &hf_x411_originally_intended_recipient_name,
      { "originally-intended-recipient-name", "x411.originally_intended_recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_actual_recipient_name,
      { "actual-recipient-name", "x411.actual_recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_delivery_report_type,
      { "report-type", "x411.report_type",
        FT_UINT32, BASE_DEC, VALS(x411_ReportType_vals), 0,
        "PerRecipientReportDeliveryFields/report-type", HFILL }},
    { &hf_x411_delivery,
      { "delivery", "x411.delivery",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportType/delivery", HFILL }},
    { &hf_x411_non_delivery,
      { "non-delivery", "x411.non_delivery",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportType/non-delivery", HFILL }},
    { &hf_x411_type_of_MTS_user,
      { "type-of-MTS-user", "x411.type_of_MTS_user",
        FT_UINT32, BASE_DEC, VALS(x411_TypeOfMTSUser_vals), 0,
        "", HFILL }},
    { &hf_x411_non_delivery_reason_code,
      { "non-delivery-reason-code", "x411.non_delivery_reason_code",
        FT_UINT32, BASE_DEC, VALS(x411_NonDeliveryReasonCode_vals), 0,
        "", HFILL }},
    { &hf_x411_non_delivery_diagnostic_code,
      { "non-delivery-diagnostic-code", "x411.non_delivery_diagnostic_code",
        FT_UINT32, BASE_DEC, VALS(x411_NonDeliveryDiagnosticCode_vals), 0,
        "", HFILL }},
    { &hf_x411_ContentTypes_item,
      { "Item", "x411.ContentTypes_item",
        FT_UINT32, BASE_DEC, VALS(x411_ContentType_vals), 0,
        "ContentTypes/_item", HFILL }},
    { &hf_x411_built_in,
      { "built-in", "x411.built_in",
        FT_INT32, BASE_DEC, VALS(x411_BuiltInContentType_vals), 0,
        "", HFILL }},
    { &hf_x411_extended,
      { "extended", "x411.extended",
        FT_OID, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_OtherRecipientNames_item,
      { "Item", "x411.OtherRecipientNames_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "OtherRecipientNames/_item", HFILL }},
    { &hf_x411_standard_extension,
      { "standard-extension", "x411.standard_extension",
        FT_INT32, BASE_DEC, NULL, 0,
        "ExtensionType/standard-extension", HFILL }},
    { &hf_x411_private_extension,
      { "private-extension", "x411.private_extension",
        FT_OID, BASE_NONE, NULL, 0,
        "ExtensionType/private-extension", HFILL }},
    { &hf_x411_extension_type,
      { "type", "x411.type",
        FT_UINT32, BASE_DEC, VALS(x411_ExtensionType_vals), 0,
        "ExtensionField/type", HFILL }},
    { &hf_x411_criticality,
      { "criticality", "x411.criticality",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ExtensionField/criticality", HFILL }},
    { &hf_x411_extension_value,
      { "value", "x411.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExtensionField/value", HFILL }},
    { &hf_x411_RequestedDeliveryMethod_item,
      { "Item", "x411.RequestedDeliveryMethod_item",
        FT_UINT32, BASE_DEC, VALS(x411_RequestedDeliveryMethod_item_vals), 0,
        "RequestedDeliveryMethod/_item", HFILL }},
    { &hf_x411_ia5text,
      { "ia5text", "x411.ia5text",
        FT_STRING, BASE_NONE, NULL, 0,
        "ContentCorrelator/ia5text", HFILL }},
    { &hf_x411_octets,
      { "octets", "x411.octets",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ContentCorrelator/octets", HFILL }},
    { &hf_x411_RedirectionHistory_item,
      { "Item", "x411.RedirectionHistory_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RedirectionHistory/_item", HFILL }},
    { &hf_x411_intended_recipient_name,
      { "intended-recipient-name", "x411.intended_recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "Redirection/intended-recipient-name", HFILL }},
    { &hf_x411_redirection_reason,
      { "redirection-reason", "x411.redirection_reason",
        FT_UINT32, BASE_DEC, VALS(x411_RedirectionReason_vals), 0,
        "Redirection/redirection-reason", HFILL }},
    { &hf_x411_intended_recipient,
      { "intended-recipient", "x411.intended_recipient",
        FT_NONE, BASE_NONE, NULL, 0,
        "IntendedRecipientName/intended-recipient", HFILL }},
    { &hf_x411_redirection_time,
      { "redirection-time", "x411.redirection_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "IntendedRecipientName/redirection-time", HFILL }},
    { &hf_x411_DLExpansionHistory_item,
      { "Item", "x411.DLExpansionHistory_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "DLExpansionHistory/_item", HFILL }},
    { &hf_x411_dl,
      { "dl", "x411.dl",
        FT_NONE, BASE_NONE, NULL, 0,
        "DLExpansion/dl", HFILL }},
    { &hf_x411_dl_expansion_time,
      { "dl-expansion-time", "x411.dl_expansion_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "DLExpansion/dl-expansion-time", HFILL }},
    { &hf_x411_OriginatorAndDLExpansionHistory_item,
      { "Item", "x411.OriginatorAndDLExpansionHistory_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "OriginatorAndDLExpansionHistory/_item", HFILL }},
    { &hf_x411_originator_or_dl_name,
      { "originator-or-dl-name", "x411.originator_or_dl_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "OriginatorAndDLExpansion/originator-or-dl-name", HFILL }},
    { &hf_x411_origination_or_expansion_time,
      { "origination-or-expansion-time", "x411.origination_or_expansion_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "OriginatorAndDLExpansion/origination-or-expansion-time", HFILL }},
    { &hf_x411_report_type,
      { "report-type", "x411.report_type",
        FT_UINT32, BASE_DEC, VALS(x411_T_report_type_vals), 0,
        "PerRecipientReportFields/report-type", HFILL }},
    { &hf_x411_report_type_delivery,
      { "delivery", "x411.delivery",
        FT_NONE, BASE_NONE, NULL, 0,
        "PerRecipientReportFields/report-type/delivery", HFILL }},
    { &hf_x411_non_delivery_report,
      { "non-delivery", "x411.non_delivery",
        FT_NONE, BASE_NONE, NULL, 0,
        "PerRecipientReportFields/report-type/non-delivery", HFILL }},
    { &hf_x411_mta_directory_name,
      { "mta-directory-name", "x411.mta_directory_name",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "ReportingMTAName/mta-directory-name", HFILL }},
    { &hf_x411_ExtendedCertificates_item,
      { "Item", "x411.ExtendedCertificates_item",
        FT_UINT32, BASE_DEC, VALS(x411_ExtendedCertificate_vals), 0,
        "ExtendedCertificates/_item", HFILL }},
    { &hf_x411_directory_entry,
      { "directory-entry", "x411.directory_entry",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "ExtendedCertificate/directory-entry", HFILL }},
    { &hf_x411_DLExemptedRecipients_item,
      { "Item", "x411.DLExemptedRecipients_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "DLExemptedRecipients/_item", HFILL }},
    { &hf_x411_encryption_recipient,
      { "encryption-recipient", "x411.encryption_recipient",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateSelectors/encryption-recipient", HFILL }},
    { &hf_x411_encryption_originator,
      { "encryption-originator", "x411.encryption_originator",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateSelectors/encryption-originator", HFILL }},
    { &hf_x411_content_integrity_check,
      { "content-integrity-check", "x411.content_integrity_check",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateSelectors/content-integrity-check", HFILL }},
    { &hf_x411_token_signature,
      { "token-signature", "x411.token_signature",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateSelectors/token-signature", HFILL }},
    { &hf_x411_message_origin_authentication,
      { "message-origin-authentication", "x411.message_origin_authentication",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateSelectors/message-origin-authentication", HFILL }},
    { &hf_x411_local_identifier,
      { "local-identifier", "x411.local_identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "MTSIdentifier/local-identifier", HFILL }},
    { &hf_x411_numeric,
      { "numeric", "x411.numeric",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_printable,
      { "printable", "x411.printable",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_built_in_standard_attributes,
      { "built-in-standard-attributes", "x411.built_in_standard_attributes",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_built_in_domain_defined_attributes,
      { "built-in-domain-defined-attributes", "x411.built_in_domain_defined_attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x411_extension_attributes,
      { "extension-attributes", "x411.extension_attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x411_directory_name,
      { "directory-name", "x411.directory_name",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "ORName/directory-name", HFILL }},
    { &hf_x411_network_address,
      { "network-address", "x411.network_address",
        FT_STRING, BASE_NONE, NULL, 0,
        "BuiltInStandardAttributes/network-address", HFILL }},
    { &hf_x411_terminal_identifier,
      { "terminal-identifier", "x411.terminal_identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "BuiltInStandardAttributes/terminal-identifier", HFILL }},
    { &hf_x411_private_domain_name,
      { "private-domain-name", "x411.private_domain_name",
        FT_UINT32, BASE_DEC, VALS(x411_PrivateDomainName_vals), 0,
        "BuiltInStandardAttributes/private-domain-name", HFILL }},
    { &hf_x411_organization_name,
      { "organization-name", "x411.organization_name",
        FT_STRING, BASE_NONE, NULL, 0,
        "BuiltInStandardAttributes/organization-name", HFILL }},
    { &hf_x411_numeric_user_identifier,
      { "numeric-user-identifier", "x411.numeric_user_identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "BuiltInStandardAttributes/numeric-user-identifier", HFILL }},
    { &hf_x411_personal_name,
      { "personal-name", "x411.personal_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "BuiltInStandardAttributes/personal-name", HFILL }},
    { &hf_x411_organizational_unit_names,
      { "organizational-unit-names", "x411.organizational_unit_names",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BuiltInStandardAttributes/organizational-unit-names", HFILL }},
    { &hf_x411_x121_dcc_code,
      { "x121-dcc-code", "x411.x121_dcc_code",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_iso_3166_alpha2_code,
      { "iso-3166-alpha2-code", "x411.iso_3166_alpha2_code",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_printable_surname,
      { "surname", "x411.surname",
        FT_STRING, BASE_NONE, NULL, 0,
        "PersonalName/surname", HFILL }},
    { &hf_x411_printable_given_name,
      { "given-name", "x411.given_name",
        FT_STRING, BASE_NONE, NULL, 0,
        "PersonalName/given-name", HFILL }},
    { &hf_x411_printable_initials,
      { "initials", "x411.initials",
        FT_STRING, BASE_NONE, NULL, 0,
        "PersonalName/initials", HFILL }},
    { &hf_x411_printable_generation_qualifier,
      { "generation-qualifier", "x411.generation_qualifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "PersonalName/generation-qualifier", HFILL }},
    { &hf_x411_OrganizationalUnitNames_item,
      { "Item", "x411.OrganizationalUnitNames_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "OrganizationalUnitNames/_item", HFILL }},
    { &hf_x411_BuiltInDomainDefinedAttributes_item,
      { "Item", "x411.BuiltInDomainDefinedAttributes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "BuiltInDomainDefinedAttributes/_item", HFILL }},
    { &hf_x411_printable_type,
      { "type", "x411.type",
        FT_STRING, BASE_NONE, NULL, 0,
        "BuiltInDomainDefinedAttribute/type", HFILL }},
    { &hf_x411_printable_value,
      { "value", "x411.value",
        FT_STRING, BASE_NONE, NULL, 0,
        "BuiltInDomainDefinedAttribute/value", HFILL }},
    { &hf_x411_ExtensionAttributes_item,
      { "Item", "x411.ExtensionAttributes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExtensionAttributes/_item", HFILL }},
    { &hf_x411_extension_attribute_type,
      { "extension-attribute-type", "x411.extension_attribute_type",
        FT_INT32, BASE_DEC, NULL, 0,
        "ExtensionAttribute/extension-attribute-type", HFILL }},
    { &hf_x411_extension_attribute_value,
      { "extension-attribute-value", "x411.extension_attribute_value",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExtensionAttribute/extension-attribute-value", HFILL }},
    { &hf_x411_teletex_surname,
      { "surname", "x411.surname",
        FT_STRING, BASE_NONE, NULL, 0,
        "TeletexPersonalName/surname", HFILL }},
    { &hf_x411_teletex_given_name,
      { "given-name", "x411.given_name",
        FT_STRING, BASE_NONE, NULL, 0,
        "TeletexPersonalName/given-name", HFILL }},
    { &hf_x411_teletex_initials,
      { "initials", "x411.initials",
        FT_STRING, BASE_NONE, NULL, 0,
        "TeletexPersonalName/initials", HFILL }},
    { &hf_x411_teletex_generation_qualifier,
      { "generation-qualifier", "x411.generation_qualifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "TeletexPersonalName/generation-qualifier", HFILL }},
    { &hf_x411_universal_surname,
      { "surname", "x411.surname",
        FT_NONE, BASE_NONE, NULL, 0,
        "UniversalPersonalName/surname", HFILL }},
    { &hf_x411_universal_given_name,
      { "given-name", "x411.given_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "UniversalPersonalName/given-name", HFILL }},
    { &hf_x411_universal_initials,
      { "initials", "x411.initials",
        FT_NONE, BASE_NONE, NULL, 0,
        "UniversalPersonalName/initials", HFILL }},
    { &hf_x411_universal_generation_qualifier,
      { "generation-qualifier", "x411.generation_qualifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "UniversalPersonalName/generation-qualifier", HFILL }},
    { &hf_x411_TeletexOrganizationalUnitNames_item,
      { "Item", "x411.TeletexOrganizationalUnitNames_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "TeletexOrganizationalUnitNames/_item", HFILL }},
    { &hf_x411_UniversalOrganizationalUnitNames_item,
      { "Item", "x411.UniversalOrganizationalUnitNames_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "UniversalOrganizationalUnitNames/_item", HFILL }},
    { &hf_x411_character_encoding,
      { "character-encoding", "x411.character_encoding",
        FT_UINT32, BASE_DEC, VALS(x411_T_character_encoding_vals), 0,
        "UniversalOrBMPString/character-encoding", HFILL }},
    { &hf_x411_two_octets,
      { "two-octets", "x411.two_octets",
        FT_STRING, BASE_NONE, NULL, 0,
        "UniversalOrBMPString/character-encoding/two-octets", HFILL }},
    { &hf_x411_four_octets,
      { "four-octets", "x411.four_octets",
        FT_STRING, BASE_NONE, NULL, 0,
        "UniversalOrBMPString/character-encoding/four-octets", HFILL }},
    { &hf_x411_iso_639_language_code,
      { "iso-639-language-code", "x411.iso_639_language_code",
        FT_STRING, BASE_NONE, NULL, 0,
        "UniversalOrBMPString/iso-639-language-code", HFILL }},
    { &hf_x411_numeric_code,
      { "numeric-code", "x411.numeric_code",
        FT_STRING, BASE_NONE, NULL, 0,
        "PostalCode/numeric-code", HFILL }},
    { &hf_x411_printable_code,
      { "printable-code", "x411.printable_code",
        FT_STRING, BASE_NONE, NULL, 0,
        "PostalCode/printable-code", HFILL }},
    { &hf_x411_printable_address,
      { "printable-address", "x411.printable_address",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UnformattedPostalAddress/printable-address", HFILL }},
    { &hf_x411_printable_address_item,
      { "Item", "x411.printable_address_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "UnformattedPostalAddress/printable-address/_item", HFILL }},
    { &hf_x411_teletex_string,
      { "teletex-string", "x411.teletex_string",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_printable_string,
      { "printable-string", "x411.printable_string",
        FT_STRING, BASE_NONE, NULL, 0,
        "PDSParameter/printable-string", HFILL }},
    { &hf_x411_e163_4_address,
      { "e163-4-address", "x411.e163_4_address",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExtendedNetworkAddress/e163-4-address", HFILL }},
    { &hf_x411_number,
      { "number", "x411.number",
        FT_STRING, BASE_NONE, NULL, 0,
        "ExtendedNetworkAddress/e163-4-address/number", HFILL }},
    { &hf_x411_sub_address,
      { "sub-address", "x411.sub_address",
        FT_STRING, BASE_NONE, NULL, 0,
        "ExtendedNetworkAddress/e163-4-address/sub-address", HFILL }},
    { &hf_x411_psap_address,
      { "psap-address", "x411.psap_address",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExtendedNetworkAddress/psap-address", HFILL }},
    { &hf_x411_TeletexDomainDefinedAttributes_item,
      { "Item", "x411.TeletexDomainDefinedAttributes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "TeletexDomainDefinedAttributes/_item", HFILL }},
    { &hf_x411_type,
      { "type", "x411.type",
        FT_STRING, BASE_NONE, NULL, 0,
        "TeletexDomainDefinedAttribute/type", HFILL }},
    { &hf_x411_teletex_value,
      { "value", "x411.value",
        FT_STRING, BASE_NONE, NULL, 0,
        "TeletexDomainDefinedAttribute/value", HFILL }},
    { &hf_x411_UniversalDomainDefinedAttributes_item,
      { "Item", "x411.UniversalDomainDefinedAttributes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "UniversalDomainDefinedAttributes/_item", HFILL }},
    { &hf_x411_universal_type,
      { "type", "x411.type",
        FT_NONE, BASE_NONE, NULL, 0,
        "UniversalDomainDefinedAttribute/type", HFILL }},
    { &hf_x411_universal_value,
      { "value", "x411.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "UniversalDomainDefinedAttribute/value", HFILL }},
    { &hf_x411_built_in_encoded_information_types,
      { "built-in-encoded-information-types", "x411.built_in_encoded_information_types",
        FT_BYTES, BASE_HEX, NULL, 0,
        "EncodedInformationTypes/built-in-encoded-information-types", HFILL }},
    { &hf_x411_g3_facsimile,
      { "g3-facsimile", "x411.g3_facsimile",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_x411_teletex,
      { "teletex", "x411.teletex",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x411_extended_encoded_information_types,
      { "extended-encoded-information-types", "x411.extended_encoded_information_types",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EncodedInformationTypes/extended-encoded-information-types", HFILL }},
    { &hf_x411_ExtendedEncodedInformationTypes_item,
      { "Item", "x411.ExtendedEncodedInformationTypes_item",
        FT_OID, BASE_NONE, NULL, 0,
        "ExtendedEncodedInformationTypes/_item", HFILL }},
    { &hf_x411_graphic_character_sets,
      { "graphic-character-sets", "x411.graphic_character_sets",
        FT_STRING, BASE_NONE, NULL, 0,
        "TeletexNonBasicParameters/graphic-character-sets", HFILL }},
    { &hf_x411_control_character_sets,
      { "control-character-sets", "x411.control_character_sets",
        FT_STRING, BASE_NONE, NULL, 0,
        "TeletexNonBasicParameters/control-character-sets", HFILL }},
    { &hf_x411_page_formats,
      { "page-formats", "x411.page_formats",
        FT_BYTES, BASE_HEX, NULL, 0,
        "TeletexNonBasicParameters/page-formats", HFILL }},
    { &hf_x411_miscellaneous_terminal_capabilities,
      { "miscellaneous-terminal-capabilities", "x411.miscellaneous_terminal_capabilities",
        FT_STRING, BASE_NONE, NULL, 0,
        "TeletexNonBasicParameters/miscellaneous-terminal-capabilities", HFILL }},
    { &hf_x411_private_use,
      { "private-use", "x411.private_use",
        FT_BYTES, BASE_HEX, NULL, 0,
        "TeletexNonBasicParameters/private-use", HFILL }},
    { &hf_x411_token_type_identifier,
      { "token-type-identifier", "x411.token_type_identifier",
        FT_OID, BASE_NONE, NULL, 0,
        "Token/token-type-identifier", HFILL }},
    { &hf_x411_token,
      { "token", "x411.token",
        FT_NONE, BASE_NONE, NULL, 0,
        "Token/token", HFILL }},
    { &hf_x411_signature_algorithm_identifier,
      { "signature-algorithm-identifier", "x411.signature_algorithm_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "AsymmetricTokenData/signature-algorithm-identifier", HFILL }},
    { &hf_x411_name,
      { "name", "x411.name",
        FT_UINT32, BASE_DEC, VALS(x411_T_name_vals), 0,
        "AsymmetricTokenData/name", HFILL }},
    { &hf_x411_token_recipient_name,
      { "recipient-name", "x411.recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "AsymmetricTokenData/name/recipient-name", HFILL }},
    { &hf_x411_token_mta,
      { "mta", "x411.mta",
        FT_NONE, BASE_NONE, NULL, 0,
        "AsymmetricTokenData/name/mta", HFILL }},
    { &hf_x411_time,
      { "time", "x411.time",
        FT_STRING, BASE_NONE, NULL, 0,
        "AsymmetricTokenData/time", HFILL }},
    { &hf_x411_signed_data,
      { "signed-data", "x411.signed_data",
        FT_BYTES, BASE_HEX, NULL, 0,
        "AsymmetricTokenData/signed-data", HFILL }},
    { &hf_x411_encryption_algorithm_identifier,
      { "encryption-algorithm-identifier", "x411.encryption_algorithm_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "AsymmetricTokenData/encryption-algorithm-identifier", HFILL }},
    { &hf_x411_encrypted_data,
      { "encrypted-data", "x411.encrypted_data",
        FT_BYTES, BASE_HEX, NULL, 0,
        "AsymmetricTokenData/encrypted-data", HFILL }},
    { &hf_x411_asymmetric_token_data,
      { "asymmetric-token-data", "x411.asymmetric_token_data",
        FT_NONE, BASE_NONE, NULL, 0,
        "AsymmetricToken/asymmetric-token-data", HFILL }},
    { &hf_x411_algorithm_identifier,
      { "algorithm-identifier", "x411.algorithm_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "AsymmetricToken/algorithm-identifier", HFILL }},
    { &hf_x411_security_policy_identifier,
      { "security-policy-identifier", "x411.security_policy_identifier",
        FT_OID, BASE_NONE, NULL, 0,
        "SecurityLabel/security-policy-identifier", HFILL }},
    { &hf_x411_security_classification,
      { "security-classification", "x411.security_classification",
        FT_UINT32, BASE_DEC, VALS(x411_SecurityClassification_vals), 0,
        "SecurityLabel/security-classification", HFILL }},
    { &hf_x411_privacy_mark,
      { "privacy-mark", "x411.privacy_mark",
        FT_STRING, BASE_NONE, NULL, 0,
        "SecurityLabel/privacy-mark", HFILL }},
    { &hf_x411_security_categories,
      { "security-categories", "x411.security_categories",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SecurityLabel/security-categories", HFILL }},
    { &hf_x411_SecurityCategories_item,
      { "Item", "x411.SecurityCategories_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityCategories/_item", HFILL }},
    { &hf_x411_category_type,
      { "type", "x411.type",
        FT_OID, BASE_NONE, NULL, 0,
        "SecurityCategory/type", HFILL }},
    { &hf_x411_category_value,
      { "value", "x411.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityCategory/value", HFILL }},
    { &hf_x411_PerRecipientIndicators_responsibility,
      { "responsibility", "x411.responsibility",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x411_PerRecipientIndicators_originating_MTA_report,
      { "originating-MTA-report", "x411.originating-MTA-report",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x411_PerRecipientIndicators_originating_MTA_non_delivery_report,
      { "originating-MTA-non-delivery-report", "x411.originating-MTA-non-delivery-report",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_x411_PerRecipientIndicators_originator_report,
      { "originator-report", "x411.originator-report",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_x411_PerRecipientIndicators_originator_non_delivery_report,
      { "originator-non-delivery-report", "x411.originator-non-delivery-report",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_x411_PerRecipientIndicators_reserved_5,
      { "reserved-5", "x411.reserved-5",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_x411_PerRecipientIndicators_reserved_6,
      { "reserved-6", "x411.reserved-6",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_x411_PerRecipientIndicators_reserved_7,
      { "reserved-7", "x411.reserved-7",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_x411_OtherActions_redirected,
      { "redirected", "x411.redirected",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x411_OtherActions_dl_operation,
      { "dl-operation", "x411.dl-operation",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x411_Operations_probe_submission_or_report_delivery,
      { "probe-submission-or-report-delivery", "x411.probe-submission-or-report-delivery",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x411_Operations_message_submission_or_message_delivery,
      { "message-submission-or-message-delivery", "x411.message-submission-or-message-delivery",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x411_WaitingMessages_long_content,
      { "long-content", "x411.long-content",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x411_WaitingMessages_low_priority,
      { "low-priority", "x411.low-priority",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x411_WaitingMessages_other_security_labels,
      { "other-security-labels", "x411.other-security-labels",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_x411_T_source_type_originated_by,
      { "originated-by", "x411.originated-by",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x411_T_source_type_redirected_by,
      { "redirected-by", "x411.redirected-by",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x411_T_source_type_dl_expanded_by,
      { "dl-expanded-by", "x411.dl-expanded-by",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_x411_T_standard_parameters_user_name,
      { "user-name", "x411.user-name",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x411_T_standard_parameters_user_address,
      { "user-address", "x411.user-address",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x411_T_standard_parameters_deliverable_class,
      { "deliverable-class", "x411.deliverable-class",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_x411_T_standard_parameters_default_delivery_controls,
      { "default-delivery-controls", "x411.default-delivery-controls",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_x411_T_standard_parameters_redirections,
      { "redirections", "x411.redirections",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_x411_T_standard_parameters_restricted_delivery,
      { "restricted-delivery", "x411.restricted-delivery",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_x411_PerMessageIndicators_disclosure_of_other_recipients,
      { "disclosure-of-other-recipients", "x411.disclosure-of-other-recipients",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x411_PerMessageIndicators_implicit_conversion_prohibited,
      { "implicit-conversion-prohibited", "x411.implicit-conversion-prohibited",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x411_PerMessageIndicators_alternate_recipient_allowed,
      { "alternate-recipient-allowed", "x411.alternate-recipient-allowed",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_x411_PerMessageIndicators_content_return_request,
      { "content-return-request", "x411.content-return-request",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_x411_PerMessageIndicators_reserved,
      { "reserved", "x411.reserved",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_x411_PerMessageIndicators_bit_5,
      { "bit-5", "x411.bit-5",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_x411_PerMessageIndicators_bit_6,
      { "bit-6", "x411.bit-6",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_x411_PerMessageIndicators_service_message,
      { "service-message", "x411.service-message",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_x411_OriginatorReportRequest_report,
      { "report", "x411.report",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_x411_OriginatorReportRequest_non_delivery_report,
      { "non-delivery-report", "x411.non-delivery-report",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_x411_DeliveryFlags_implicit_conversion_prohibited,
      { "implicit-conversion-prohibited", "x411.implicit-conversion-prohibited",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x411_Criticality_for_submission,
      { "for-submission", "x411.for-submission",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x411_Criticality_for_transfer,
      { "for-transfer", "x411.for-transfer",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x411_Criticality_for_delivery,
      { "for-delivery", "x411.for-delivery",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_x411_PhysicalDeliveryModes_ordinary_mail,
      { "ordinary-mail", "x411.ordinary-mail",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x411_PhysicalDeliveryModes_special_delivery,
      { "special-delivery", "x411.special-delivery",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x411_PhysicalDeliveryModes_express_mail,
      { "express-mail", "x411.express-mail",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_x411_PhysicalDeliveryModes_counter_collection,
      { "counter-collection", "x411.counter-collection",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_x411_PhysicalDeliveryModes_counter_collection_with_telephone_advice,
      { "counter-collection-with-telephone-advice", "x411.counter-collection-with-telephone-advice",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_x411_PhysicalDeliveryModes_counter_collection_with_telex_advice,
      { "counter-collection-with-telex-advice", "x411.counter-collection-with-telex-advice",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_x411_PhysicalDeliveryModes_counter_collection_with_teletex_advice,
      { "counter-collection-with-teletex-advice", "x411.counter-collection-with-teletex-advice",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_x411_PhysicalDeliveryModes_bureau_fax_delivery,
      { "bureau-fax-delivery", "x411.bureau-fax-delivery",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_x411_BuiltInEncodedInformationTypes_unknown,
      { "unknown", "x411.unknown",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x411_BuiltInEncodedInformationTypes_ia5_text,
      { "ia5-text", "x411.ia5-text",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_x411_BuiltInEncodedInformationTypes_g3_facsimile,
      { "g3-facsimile", "x411.g3-facsimile",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_x411_BuiltInEncodedInformationTypes_g4_class_1,
      { "g4-class-1", "x411.g4-class-1",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_x411_BuiltInEncodedInformationTypes_teletex,
      { "teletex", "x411.teletex",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_x411_BuiltInEncodedInformationTypes_videotex,
      { "videotex", "x411.videotex",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_x411_BuiltInEncodedInformationTypes_voice,
      { "voice", "x411.voice",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_x411_BuiltInEncodedInformationTypes_sfd,
      { "sfd", "x411.sfd",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x411_BuiltInEncodedInformationTypes_mixed_mode,
      { "mixed-mode", "x411.mixed-mode",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_two_dimensional,
      { "two-dimensional", "x411.two-dimensional",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_fine_resolution,
      { "fine-resolution", "x411.fine-resolution",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_unlimited_length,
      { "unlimited-length", "x411.unlimited-length",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_b4_length,
      { "b4-length", "x411.b4-length",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_a3_width,
      { "a3-width", "x411.a3-width",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_b4_width,
      { "b4-width", "x411.b4-width",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_t6_coding,
      { "t6-coding", "x411.t6-coding",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_uncompressed,
      { "uncompressed", "x411.uncompressed",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_width_middle_864_of_1728,
      { "width-middle-864-of-1728", "x411.width-middle-864-of-1728",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_width_middle_1216_of_1728,
      { "width-middle-1216-of-1728", "x411.width-middle-1216-of-1728",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_resolution_type,
      { "resolution-type", "x411.resolution-type",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_resolution_400x400,
      { "resolution-400x400", "x411.resolution-400x400",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_resolution_300x300,
      { "resolution-300x300", "x411.resolution-300x300",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_resolution_8x15,
      { "resolution-8x15", "x411.resolution-8x15",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_edi,
      { "edi", "x411.edi",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_dtm,
      { "dtm", "x411.dtm",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_bft,
      { "bft", "x411.bft",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_mixed_mode,
      { "mixed-mode", "x411.mixed-mode",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_character_mode,
      { "character-mode", "x411.character-mode",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_twelve_bits,
      { "twelve-bits", "x411.twelve-bits",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_preferred_huffmann,
      { "preferred-huffmann", "x411.preferred-huffmann",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_full_colour,
      { "full-colour", "x411.full-colour",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_jpeg,
      { "jpeg", "x411.jpeg",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_processable_mode_26,
      { "processable-mode-26", "x411.processable-mode-26",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},

/*--- End of included file: packet-x411-hfarr.c ---*/
#line 207 "packet-x411-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_x411,

/*--- Included file: packet-x411-ettarr.c ---*/
#line 1 "packet-x411-ettarr.c"
    &ett_x411_MTABindArgument,
    &ett_x411_AuthenticatedArgument,
    &ett_x411_MTABindResult,
    &ett_x411_AuthenticatedResult,
    &ett_x411_MTS_APDU,
    &ett_x411_Message,
    &ett_x411_Report,
    &ett_x411_MessageTransferEnvelope,
    &ett_x411_SEQUENCE_OF_PerDomainBilateralInformation,
    &ett_x411_SET_OF_ExtensionField,
    &ett_x411_SEQUENCE_OF_PerRecipientMessageTransferFields,
    &ett_x411_PerRecipientMessageTransferFields,
    &ett_x411_ProbeTransferEnvelope,
    &ett_x411_SEQUENCE_OF_PerRecipientProbeTransferFields,
    &ett_x411_PerRecipientProbeTransferFields,
    &ett_x411_ReportTransferEnvelope,
    &ett_x411_ReportTransferContent,
    &ett_x411_SEQUENCE_OF_PerRecipientReportTransferFields,
    &ett_x411_PerRecipientReportTransferFields,
    &ett_x411_PerDomainBilateralInformation,
    &ett_x411_T_domain,
    &ett_x411_T_private_domain,
    &ett_x411_PerRecipientIndicators,
    &ett_x411_LastTraceInformation,
    &ett_x411_InternalTraceInformation,
    &ett_x411_InternalTraceInformationElement,
    &ett_x411_MTASuppliedInformation,
    &ett_x411_T_attempted,
    &ett_x411_TraceInformation,
    &ett_x411_TraceInformationElement,
    &ett_x411_DomainSuppliedInformation,
    &ett_x411_OtherActions,
    &ett_x411_MTSBindArgument,
    &ett_x411_MTSBindResult,
    &ett_x411_ObjectName,
    &ett_x411_MessagesWaiting,
    &ett_x411_DeliveryQueue,
    &ett_x411_Credentials,
    &ett_x411_Password,
    &ett_x411_StrongCredentials,
    &ett_x411_ProtectedPassword,
    &ett_x411_Signature,
    &ett_x411_SecurityContext,
    &ett_x411_MessageSubmissionArgument,
    &ett_x411_MessageSubmissionResult,
    &ett_x411_ProbeSubmissionResult,
    &ett_x411_ImproperlySpecifiedRecipients,
    &ett_x411_Waiting,
    &ett_x411_SET_OF_ContentType,
    &ett_x411_Operations,
    &ett_x411_WaitingMessages,
    &ett_x411_MessageDeliveryArgument,
    &ett_x411_MessageDeliveryResult,
    &ett_x411_ReportDeliveryArgument,
    &ett_x411_SEQUENCE_OF_PerRecipientReportDeliveryFields,
    &ett_x411_ReportDeliveryResult,
    &ett_x411_DeliveryControlArgument,
    &ett_x411_DeliveryControlResult,
    &ett_x411_RefusedOperation,
    &ett_x411_T_refused_argument,
    &ett_x411_Controls,
    &ett_x411_RegisterArgument,
    &ett_x411_SET_OF_DeliverableClass,
    &ett_x411_RegisterResult,
    &ett_x411_T_non_empty_result,
    &ett_x411_ChangeCredentialsArgument,
    &ett_x411_UserAddress,
    &ett_x411_T_x121,
    &ett_x411_Redirections,
    &ett_x411_RecipientRedirection,
    &ett_x411_SET_OF_RedirectionClass,
    &ett_x411_MessageClass,
    &ett_x411_SET_OF_Priority,
    &ett_x411_SEQUENCE_OF_Restriction,
    &ett_x411_EncodedInformationTypesConstraints,
    &ett_x411_RestrictedDelivery,
    &ett_x411_Restriction,
    &ett_x411_T_source_type,
    &ett_x411_ExactOrPattern,
    &ett_x411_RegistrationTypes,
    &ett_x411_T_standard_parameters,
    &ett_x411_T_extensions,
    &ett_x411_MessageSubmissionEnvelope,
    &ett_x411_SEQUENCE_OF_PerRecipientMessageSubmissionFields,
    &ett_x411_PerRecipientMessageSubmissionFields,
    &ett_x411_ProbeSubmissionEnvelope,
    &ett_x411_SEQUENCE_OF_PerRecipientProbeSubmissionFields,
    &ett_x411_PerRecipientProbeSubmissionFields,
    &ett_x411_MessageDeliveryEnvelope,
    &ett_x411_OtherMessageDeliveryFields,
    &ett_x411_ReportDeliveryEnvelope,
    &ett_x411_PerRecipientReportDeliveryFields,
    &ett_x411_ReportType,
    &ett_x411_DeliveryReport,
    &ett_x411_NonDeliveryReport,
    &ett_x411_ContentTypes,
    &ett_x411_ContentType,
    &ett_x411_DeliveredContentType,
    &ett_x411_PerMessageIndicators,
    &ett_x411_OriginatorReportRequest,
    &ett_x411_DeliveryFlags,
    &ett_x411_OtherRecipientNames,
    &ett_x411_ExtensionType,
    &ett_x411_Criticality,
    &ett_x411_ExtensionField,
    &ett_x411_RequestedDeliveryMethod,
    &ett_x411_PhysicalDeliveryModes,
    &ett_x411_ContentCorrelator,
    &ett_x411_RedirectionHistory,
    &ett_x411_Redirection,
    &ett_x411_IntendedRecipientName,
    &ett_x411_DLExpansionHistory,
    &ett_x411_DLExpansion,
    &ett_x411_OriginatorAndDLExpansionHistory,
    &ett_x411_OriginatorAndDLExpansion,
    &ett_x411_PerRecipientReportFields,
    &ett_x411_T_report_type,
    &ett_x411_PerRecipientDeliveryReportFields,
    &ett_x411_PerRecipientNonDeliveryReportFields,
    &ett_x411_ReportingMTAName,
    &ett_x411_ExtendedCertificates,
    &ett_x411_ExtendedCertificate,
    &ett_x411_DLExemptedRecipients,
    &ett_x411_CertificateSelectors,
    &ett_x411_MTSIdentifier,
    &ett_x411_GlobalDomainIdentifier,
    &ett_x411_PrivateDomainIdentifier,
    &ett_x411_ORName,
    &ett_x411_ORAddress,
    &ett_x411_BuiltInStandardAttributes,
    &ett_x411_CountryName,
    &ett_x411_AdministrationDomainName,
    &ett_x411_PrivateDomainName,
    &ett_x411_PersonalName,
    &ett_x411_OrganizationalUnitNames,
    &ett_x411_BuiltInDomainDefinedAttributes,
    &ett_x411_BuiltInDomainDefinedAttribute,
    &ett_x411_ExtensionAttributes,
    &ett_x411_ExtensionAttribute,
    &ett_x411_TeletexPersonalName,
    &ett_x411_UniversalPersonalName,
    &ett_x411_TeletexOrganizationalUnitNames,
    &ett_x411_UniversalOrganizationalUnitNames,
    &ett_x411_UniversalOrBMPString,
    &ett_x411_T_character_encoding,
    &ett_x411_PhysicalDeliveryCountryName,
    &ett_x411_PostalCode,
    &ett_x411_UnformattedPostalAddress,
    &ett_x411_T_printable_address,
    &ett_x411_PDSParameter,
    &ett_x411_ExtendedNetworkAddress,
    &ett_x411_T_e163_4_address,
    &ett_x411_TeletexDomainDefinedAttributes,
    &ett_x411_TeletexDomainDefinedAttribute,
    &ett_x411_UniversalDomainDefinedAttributes,
    &ett_x411_UniversalDomainDefinedAttribute,
    &ett_x411_EncodedInformationTypes,
    &ett_x411_BuiltInEncodedInformationTypes,
    &ett_x411_ExtendedEncodedInformationTypes,
    &ett_x411_NonBasicParameters,
    &ett_x411_G3FacsimileNonBasicParameters,
    &ett_x411_TeletexNonBasicParameters,
    &ett_x411_Token,
    &ett_x411_AsymmetricTokenData,
    &ett_x411_T_name,
    &ett_x411_MTANameAndOptionalGDI,
    &ett_x411_AsymmetricToken,
    &ett_x411_SecurityLabel,
    &ett_x411_SecurityCategories,
    &ett_x411_SecurityCategory,

/*--- End of included file: packet-x411-ettarr.c ---*/
#line 213 "packet-x411-template.c"
  };

  /* Register protocol */
  proto_x411 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("x411", dissect_x411, proto_x411);
  /* Register fields and subtrees */
  proto_register_field_array(proto_x411, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_x411 --- */
void proto_reg_handoff_x411(void) {
  dissector_handle_t handle = NULL;


/*--- Included file: packet-x411-dis-tab.c ---*/
#line 1 "packet-x411-dis-tab.c"
  register_ber_oid_dissector("x411.extension.1", dissect_RecipientReassignmentProhibited_PDU, proto_x411, "recipient-reassignment-prohibited");
  register_ber_oid_dissector("x411.extension.2", dissect_MTSOriginatorRequestedAlternateRecipient_PDU, proto_x411, "originator-requested-alternate-recipient");
  register_ber_oid_dissector("x411.extension.3", dissect_DLExpansionProhibited_PDU, proto_x411, "dl-expansion-prohibited");
  register_ber_oid_dissector("x411.extension.4", dissect_ConversionWithLossProhibited_PDU, proto_x411, "conversion-with-loss-prohibited");
  register_ber_oid_dissector("x411.extension.5", dissect_LatestDeliveryTime_PDU, proto_x411, "latest-delivery-time");
  register_ber_oid_dissector("x411.extension.6", dissect_RequestedDeliveryMethod_PDU, proto_x411, "requested-delivery-method");
  register_ber_oid_dissector("x411.extension.7", dissect_PhysicalForwardingProhibited_PDU, proto_x411, "physical-forwarding-prohibited");
  register_ber_oid_dissector("x411.extension.8", dissect_PhysicalForwardingAddressRequest_PDU, proto_x411, "physical-forwarding-address-request");
  register_ber_oid_dissector("x411.extension.9", dissect_PhysicalDeliveryModes_PDU, proto_x411, "physical-delivery-modes");
  register_ber_oid_dissector("x411.extension.10", dissect_RegisteredMailType_PDU, proto_x411, "registered-mail-type");
  register_ber_oid_dissector("x411.extension.11", dissect_RecipientNumberForAdvice_PDU, proto_x411, "recipient-number-for-advice");
  register_ber_oid_dissector("x411.extension.12", dissect_PhysicalRenditionAttributes_PDU, proto_x411, "physical-rendition-attributes");
  register_ber_oid_dissector("x411.extension.13", dissect_OriginatorReturnAddress_PDU, proto_x411, "originator-return-address");
  register_ber_oid_dissector("x411.extension.14", dissect_PhysicalDeliveryReportRequest_PDU, proto_x411, "physical-delivery-report-request");
  register_ber_oid_dissector("x411.extension.15", dissect_OriginatorCertificate_PDU, proto_x411, "originator-certificate");
  register_ber_oid_dissector("x411.extension.17", dissect_ContentConfidentialityAlgorithmIdentifier_PDU, proto_x411, "content-confidentiality-algorithm-identifier");
  register_ber_oid_dissector("x411.extension.18", dissect_ContentIntegrityCheck_PDU, proto_x411, "content-integrity-check");
  register_ber_oid_dissector("x411.extension.19", dissect_MessageOriginAuthenticationCheck_PDU, proto_x411, "message-origin-authentication-check");
  register_ber_oid_dissector("x411.extension.20", dissect_MessageSecurityLabel_PDU, proto_x411, "message-security-label");
  register_ber_oid_dissector("x411.extension.21", dissect_ProofOfSubmissionRequest_PDU, proto_x411, "proof-of-submission-request");
  register_ber_oid_dissector("x411.extension.22", dissect_ProofOfDeliveryRequest_PDU, proto_x411, "proof-of-delivery-request");
  register_ber_oid_dissector("x411.extension.23", dissect_ContentCorrelator_PDU, proto_x411, "content-correlator");
  register_ber_oid_dissector("x411.extension.24", dissect_ProbeOriginAuthenticationCheck_PDU, proto_x411, "probe-origin-authentication-check");
  register_ber_oid_dissector("x411.extension.25", dissect_RedirectionHistory_PDU, proto_x411, "redirection-history");
  register_ber_oid_dissector("x411.extension.26", dissect_DLExpansionHistory_PDU, proto_x411, "dl-expansion-history");
  register_ber_oid_dissector("x411.extension.27", dissect_PhysicalForwardingAddress_PDU, proto_x411, "physical-forwarding-address");
  register_ber_oid_dissector("x411.extension.30", dissect_OriginatorAndDLExpansionHistory_PDU, proto_x411, "originator-and-DL-expansion-history");
  register_ber_oid_dissector("x411.extension.31", dissect_ReportingDLName_PDU, proto_x411, "reporting-DL-name");
  register_ber_oid_dissector("x411.extension.32", dissect_ReportingMTACertificate_PDU, proto_x411, "reporting-MTA-certificate");
  register_ber_oid_dissector("x411.extension.33", dissect_ReportOriginAuthenticationCheck_PDU, proto_x411, "report-origin-authentication-check");
  register_ber_oid_dissector("x411.extension.35", dissect_ProofOfSubmission_PDU, proto_x411, "proof-of-submission");
  register_ber_oid_dissector("x411.extension.37", dissect_TraceInformation_PDU, proto_x411, "trace-information");
  register_ber_oid_dissector("x411.extension.38", dissect_InternalTraceInformation_PDU, proto_x411, "internal-trace-information");
  register_ber_oid_dissector("x411.extension.39", dissect_ReportingMTAName_PDU, proto_x411, "reporting-MTA-name");
  register_ber_oid_dissector("x411.extension.40", dissect_ExtendedCertificates_PDU, proto_x411, "multiple-originator-certificates");
  register_ber_oid_dissector("x411.extension.42", dissect_DLExemptedRecipients_PDU, proto_x411, "dl-exempted-recipients");
  register_ber_oid_dissector("x411.extension.45", dissect_CertificateSelectors_PDU, proto_x411, "certificate-selectors");
  register_ber_oid_dissector("x411.extension-attribute.1", dissect_CommonName_PDU, proto_x411, "common-name");
  register_ber_oid_dissector("x411.extension-attribute.2", dissect_TeletexCommonName_PDU, proto_x411, "teletex-common-name");
  register_ber_oid_dissector("x411.extension-attribute.3", dissect_TeletexOrganizationName_PDU, proto_x411, "teletex-organization-name");
  register_ber_oid_dissector("x411.extension-attribute.4", dissect_TeletexPersonalName_PDU, proto_x411, "teletex-personal-name");
  register_ber_oid_dissector("x411.extension-attribute.5", dissect_TeletexOrganizationalUnitNames_PDU, proto_x411, "teletex-organizational-unit-names");
  register_ber_oid_dissector("x411.extension-attribute.7", dissect_PDSName_PDU, proto_x411, "pds-name");
  register_ber_oid_dissector("x411.extension-attribute.8", dissect_PhysicalDeliveryCountryName_PDU, proto_x411, "physical-delivery-country-name");
  register_ber_oid_dissector("x411.extension-attribute.9", dissect_PostalCode_PDU, proto_x411, "postal-code");
  register_ber_oid_dissector("x411.extension-attribute.10", dissect_PhysicalDeliveryOfficeName_PDU, proto_x411, "physical-delivery-office-name");
  register_ber_oid_dissector("x411.extension-attribute.24", dissect_UniversalCommonName_PDU, proto_x411, "universal-common-name");
  register_ber_oid_dissector("x411.extension-attribute.25", dissect_UniversalOrganizationName_PDU, proto_x411, "universal-organization-name");
  register_ber_oid_dissector("x411.extension-attribute.26", dissect_UniversalPersonalName_PDU, proto_x411, "universal-personal-name");
  register_ber_oid_dissector("x411.extension-attribute.27", dissect_UniversalOrganizationalUnitNames_PDU, proto_x411, "universal-organizational-unit-names");
  register_ber_oid_dissector("2.6.1.4.14", dissect_ReportDeliveryArgument_PDU, proto_x411, "id-et-report");
  register_ber_oid_dissector("2.6.3.6.0", dissect_AsymmetricToken_PDU, proto_x411, "id-tok-asymmetricToken");
  register_ber_oid_dissector("2.6.5.6.0", dissect_MTANameAndOptionalGDI_PDU, proto_x411, "id-on-mtaName");
  register_ber_oid_dissector("2.6.5.2.0", dissect_ContentLength_PDU, proto_x411, "id-at-mhs-maximum-content-length");
  register_ber_oid_dissector("2.6.5.2.1", dissect_ExtendedContentType_PDU, proto_x411, "id-at-mhs-deliverable-content-types");
  register_ber_oid_dissector("2.6.5.2.2", dissect_ExtendedEncodedInformationType_PDU, proto_x411, "id-at-mhs-exclusively-acceptable-eits");
  register_ber_oid_dissector("2.6.5.2.3", dissect_ORName_PDU, proto_x411, "id-at-mhs-dl-members");
  register_ber_oid_dissector("2.6.5.2.6", dissect_ORAddress_PDU, proto_x411, "id-at-mhs-or-addresses");
  register_ber_oid_dissector("2.6.5.2.9", dissect_ExtendedContentType_PDU, proto_x411, "id-at-mhs-supported-content-types");
  register_ber_oid_dissector("2.6.5.2.12", dissect_ORName_PDU, proto_x411, "id-at-mhs-dl-archive-service");
  register_ber_oid_dissector("2.6.5.2.15", dissect_ORName_PDU, proto_x411, "id-at-mhs-dl-subscription-service");
  register_ber_oid_dissector("2.6.5.2.17", dissect_ExtendedEncodedInformationType_PDU, proto_x411, "id-at-mhs-acceptable-eits");
  register_ber_oid_dissector("2.6.5.2.18", dissect_ExtendedEncodedInformationType_PDU, proto_x411, "id-at-mhs-unacceptable-eits");
  register_ber_oid_dissector("2.16.840.1.101.2.1.5.47", dissect_ORName_PDU, proto_x411, "id-at-aLExemptedAddressProcessor");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.134.1", dissect_ORAddress_PDU, proto_x411, "id-at-collective-mhs-or-addresses");


/*--- End of included file: packet-x411-dis-tab.c ---*/
#line 230 "packet-x411-template.c"

  /* APPLICATION CONTEXT */

  register_ber_oid_name("2.6.0.1.6", "id-ac-mts-transfer");

  /* ABSTRACT SYNTAXES */

  if((handle = find_dissector("x411")) != NULL) {
    register_rtse_oid_dissector_handle("2.6.0.2.12", handle, 0, "id-as-mta-rtse", TRUE); 
    register_rtse_oid_dissector_handle("2.6.0.2.7", handle, 0, "id-as-mtse", FALSE);

    register_rtse_oid_dissector_handle("applicationProtocol.1", handle, 0, "mts-transfer-protocol-1984", FALSE);
    register_rtse_oid_dissector_handle("applicationProtocol.12", handle, 0, "mta-transfer-protocol", FALSE);
  }


}
