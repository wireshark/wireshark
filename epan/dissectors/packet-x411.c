/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-x411.c                                                              */
/* ../../tools/asn2wrs.py -b -e -p x411 -c ./x411.cnf -s ./packet-x411-template -D . MTAAbstractService.asn MTSAbstractService.asn MTSAccessProtocol.asn MHSProtocolObjectIdentifiers.asn */

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
#include <epan/prefs.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/expert.h>

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
#include <epan/strutil.h>

#define PNAME  "X.411 Message Transfer Service"
#define PSNAME "X411"
#define PFNAME "x411"

static guint global_x411_tcp_port = 102;
static dissector_handle_t tpkt_handle;
void prefs_register_x411(void); /* forward declaration for use in preferences registration */

/* Initialize the protocol and registered fields */
int proto_x411 = -1;
int proto_p3 = -1;

static struct SESSION_DATA_STRUCTURE* session = NULL;
static int extension_id = -1; /* integer extension id */
static const char *object_identifier_id = NULL; /* extensions identifier */
static const char *content_type_id = NULL; /* content type identifier */

#define MAX_ORA_STR_LEN     256
static char *oraddress = NULL;
static char *ddatype = NULL;
static gboolean doing_address=FALSE;
static gboolean doing_subjectid=FALSE;
static proto_item *address_item = NULL;

static proto_tree *top_tree=NULL;

static int hf_x411_MTS_APDU_PDU = -1;
static int hf_x411_MTABindArgument_PDU = -1;
static int hf_x411_MTABindResult_PDU = -1;
static int hf_x411_MTABindError_PDU = -1;


/*--- Included file: packet-x411-hf.c ---*/
#line 1 "packet-x411-hf.c"
static int hf_x411_InternalTraceInformation_PDU = -1;  /* InternalTraceInformation */
static int hf_x411_InternalTraceInformationElement_PDU = -1;  /* InternalTraceInformationElement */
static int hf_x411_TraceInformation_PDU = -1;     /* TraceInformation */
static int hf_x411_TraceInformationElement_PDU = -1;  /* TraceInformationElement */
static int hf_x411_MTSBindArgument_PDU = -1;      /* MTSBindArgument */
static int hf_x411_MTSBindResult_PDU = -1;        /* MTSBindResult */
static int hf_x411_PAR_mts_bind_error_PDU = -1;   /* PAR_mts_bind_error */
static int hf_x411_MessageSubmissionArgument_PDU = -1;  /* MessageSubmissionArgument */
static int hf_x411_MessageSubmissionResult_PDU = -1;  /* MessageSubmissionResult */
static int hf_x411_ProbeSubmissionArgument_PDU = -1;  /* ProbeSubmissionArgument */
static int hf_x411_ProbeSubmissionResult_PDU = -1;  /* ProbeSubmissionResult */
static int hf_x411_CancelDeferredDeliveryArgument_PDU = -1;  /* CancelDeferredDeliveryArgument */
static int hf_x411_CancelDeferredDeliveryResult_PDU = -1;  /* CancelDeferredDeliveryResult */
static int hf_x411_SubmissionControlArgument_PDU = -1;  /* SubmissionControlArgument */
static int hf_x411_SubmissionControlResult_PDU = -1;  /* SubmissionControlResult */
static int hf_x411_PAR_submission_control_violated_PDU = -1;  /* PAR_submission_control_violated */
static int hf_x411_PAR_element_of_service_not_subscribed_PDU = -1;  /* PAR_element_of_service_not_subscribed */
static int hf_x411_PAR_deferred_delivery_cancellation_rejected_PDU = -1;  /* PAR_deferred_delivery_cancellation_rejected */
static int hf_x411_PAR_originator_invalid_PDU = -1;  /* PAR_originator_invalid */
static int hf_x411_ImproperlySpecifiedRecipients_PDU = -1;  /* ImproperlySpecifiedRecipients */
static int hf_x411_PAR_message_submission_identifier_invalid_PDU = -1;  /* PAR_message_submission_identifier_invalid */
static int hf_x411_PAR_inconsistent_request_PDU = -1;  /* PAR_inconsistent_request */
static int hf_x411_SecurityProblem_PDU = -1;      /* SecurityProblem */
static int hf_x411_PAR_unsupported_critical_function_PDU = -1;  /* PAR_unsupported_critical_function */
static int hf_x411_PAR_remote_bind_error_PDU = -1;  /* PAR_remote_bind_error */
static int hf_x411_MessageSubmissionTime_PDU = -1;  /* MessageSubmissionTime */
static int hf_x411_MessageDeliveryArgument_PDU = -1;  /* MessageDeliveryArgument */
static int hf_x411_MessageDeliveryResult_PDU = -1;  /* MessageDeliveryResult */
static int hf_x411_ReportDeliveryArgument_PDU = -1;  /* ReportDeliveryArgument */
static int hf_x411_ReportDeliveryResult_PDU = -1;  /* ReportDeliveryResult */
static int hf_x411_DeliveryControlArgument_PDU = -1;  /* DeliveryControlArgument */
static int hf_x411_DeliveryControlResult_PDU = -1;  /* DeliveryControlResult */
static int hf_x411_PAR_delivery_control_violated_PDU = -1;  /* PAR_delivery_control_violated */
static int hf_x411_PAR_control_violates_registration_PDU = -1;  /* PAR_control_violates_registration */
static int hf_x411_RefusedOperation_PDU = -1;     /* RefusedOperation */
static int hf_x411_RecipientCertificate_PDU = -1;  /* RecipientCertificate */
static int hf_x411_ProofOfDelivery_PDU = -1;      /* ProofOfDelivery */
static int hf_x411_RegisterArgument_PDU = -1;     /* RegisterArgument */
static int hf_x411_RegisterResult_PDU = -1;       /* RegisterResult */
static int hf_x411_ChangeCredentialsArgument_PDU = -1;  /* ChangeCredentialsArgument */
static int hf_x411_RES_change_credentials_PDU = -1;  /* RES_change_credentials */
static int hf_x411_PAR_register_rejected_PDU = -1;  /* PAR_register_rejected */
static int hf_x411_PAR_new_credentials_unacceptable_PDU = -1;  /* PAR_new_credentials_unacceptable */
static int hf_x411_PAR_old_credentials_incorrectly_specified_PDU = -1;  /* PAR_old_credentials_incorrectly_specified */
static int hf_x411_MessageSubmissionEnvelope_PDU = -1;  /* MessageSubmissionEnvelope */
static int hf_x411_PerRecipientMessageSubmissionFields_PDU = -1;  /* PerRecipientMessageSubmissionFields */
static int hf_x411_ProbeSubmissionEnvelope_PDU = -1;  /* ProbeSubmissionEnvelope */
static int hf_x411_PerRecipientProbeSubmissionFields_PDU = -1;  /* PerRecipientProbeSubmissionFields */
static int hf_x411_MessageDeliveryEnvelope_PDU = -1;  /* MessageDeliveryEnvelope */
static int hf_x411_ReportDeliveryEnvelope_PDU = -1;  /* ReportDeliveryEnvelope */
static int hf_x411_PerRecipientReportDeliveryFields_PDU = -1;  /* PerRecipientReportDeliveryFields */
static int hf_x411_ExtendedContentType_PDU = -1;  /* ExtendedContentType */
static int hf_x411_ContentIdentifier_PDU = -1;    /* ContentIdentifier */
static int hf_x411_PerMessageIndicators_PDU = -1;  /* PerMessageIndicators */
static int hf_x411_OriginatorReportRequest_PDU = -1;  /* OriginatorReportRequest */
static int hf_x411_DeferredDeliveryTime_PDU = -1;  /* DeferredDeliveryTime */
static int hf_x411_Priority_PDU = -1;             /* Priority */
static int hf_x411_ContentLength_PDU = -1;        /* ContentLength */
static int hf_x411_MessageDeliveryTime_PDU = -1;  /* MessageDeliveryTime */
static int hf_x411_DeliveryFlags_PDU = -1;        /* DeliveryFlags */
static int hf_x411_SubjectSubmissionIdentifier_PDU = -1;  /* SubjectSubmissionIdentifier */
static int hf_x411_RecipientReassignmentProhibited_PDU = -1;  /* RecipientReassignmentProhibited */
static int hf_x411_OriginatorRequestedAlternateRecipient_PDU = -1;  /* OriginatorRequestedAlternateRecipient */
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
static int hf_x411_MessageToken_PDU = -1;         /* MessageToken */
static int hf_x411_ContentConfidentialityAlgorithmIdentifier_PDU = -1;  /* ContentConfidentialityAlgorithmIdentifier */
static int hf_x411_ContentIntegrityCheck_PDU = -1;  /* ContentIntegrityCheck */
static int hf_x411_MessageOriginAuthenticationCheck_PDU = -1;  /* MessageOriginAuthenticationCheck */
static int hf_x411_MessageSecurityLabel_PDU = -1;  /* MessageSecurityLabel */
static int hf_x411_ProofOfSubmissionRequest_PDU = -1;  /* ProofOfSubmissionRequest */
static int hf_x411_ProofOfDeliveryRequest_PDU = -1;  /* ProofOfDeliveryRequest */
static int hf_x411_ContentCorrelator_PDU = -1;    /* ContentCorrelator */
static int hf_x411_ProbeOriginAuthenticationCheck_PDU = -1;  /* ProbeOriginAuthenticationCheck */
static int hf_x411_RedirectionHistory_PDU = -1;   /* RedirectionHistory */
static int hf_x411_Redirection_PDU = -1;          /* Redirection */
static int hf_x411_DLExpansionHistory_PDU = -1;   /* DLExpansionHistory */
static int hf_x411_DLExpansion_PDU = -1;          /* DLExpansion */
static int hf_x411_PhysicalForwardingAddress_PDU = -1;  /* PhysicalForwardingAddress */
static int hf_x411_OriginatorAndDLExpansionHistory_PDU = -1;  /* OriginatorAndDLExpansionHistory */
static int hf_x411_ReportingDLName_PDU = -1;      /* ReportingDLName */
static int hf_x411_ReportingMTACertificate_PDU = -1;  /* ReportingMTACertificate */
static int hf_x411_ReportOriginAuthenticationCheck_PDU = -1;  /* ReportOriginAuthenticationCheck */
static int hf_x411_OriginatingMTACertificate_PDU = -1;  /* OriginatingMTACertificate */
static int hf_x411_ProofOfSubmission_PDU = -1;    /* ProofOfSubmission */
static int hf_x411_ReportingMTAName_PDU = -1;     /* ReportingMTAName */
static int hf_x411_ExtendedCertificates_PDU = -1;  /* ExtendedCertificates */
static int hf_x411_DLExemptedRecipients_PDU = -1;  /* DLExemptedRecipients */
static int hf_x411_CertificateSelectors_PDU = -1;  /* CertificateSelectors */
static int hf_x411_Content_PDU = -1;              /* Content */
static int hf_x411_MTSIdentifier_PDU = -1;        /* MTSIdentifier */
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
static int hf_x411_UniversalPhysicalDeliveryOfficeName_PDU = -1;  /* UniversalPhysicalDeliveryOfficeName */
static int hf_x411_PhysicalDeliveryOfficeNumber_PDU = -1;  /* PhysicalDeliveryOfficeNumber */
static int hf_x411_UniversalPhysicalDeliveryOfficeNumber_PDU = -1;  /* UniversalPhysicalDeliveryOfficeNumber */
static int hf_x411_ExtensionORAddressComponents_PDU = -1;  /* ExtensionORAddressComponents */
static int hf_x411_UniversalExtensionORAddressComponents_PDU = -1;  /* UniversalExtensionORAddressComponents */
static int hf_x411_PhysicalDeliveryPersonalName_PDU = -1;  /* PhysicalDeliveryPersonalName */
static int hf_x411_UniversalPhysicalDeliveryPersonalName_PDU = -1;  /* UniversalPhysicalDeliveryPersonalName */
static int hf_x411_PhysicalDeliveryOrganizationName_PDU = -1;  /* PhysicalDeliveryOrganizationName */
static int hf_x411_UniversalPhysicalDeliveryOrganizationName_PDU = -1;  /* UniversalPhysicalDeliveryOrganizationName */
static int hf_x411_ExtensionPhysicalDeliveryAddressComponents_PDU = -1;  /* ExtensionPhysicalDeliveryAddressComponents */
static int hf_x411_UniversalExtensionPhysicalDeliveryAddressComponents_PDU = -1;  /* UniversalExtensionPhysicalDeliveryAddressComponents */
static int hf_x411_UnformattedPostalAddress_PDU = -1;  /* UnformattedPostalAddress */
static int hf_x411_UniversalUnformattedPostalAddress_PDU = -1;  /* UniversalUnformattedPostalAddress */
static int hf_x411_StreetAddress_PDU = -1;        /* StreetAddress */
static int hf_x411_UniversalStreetAddress_PDU = -1;  /* UniversalStreetAddress */
static int hf_x411_PostOfficeBoxAddress_PDU = -1;  /* PostOfficeBoxAddress */
static int hf_x411_UniversalPostOfficeBoxAddress_PDU = -1;  /* UniversalPostOfficeBoxAddress */
static int hf_x411_PosteRestanteAddress_PDU = -1;  /* PosteRestanteAddress */
static int hf_x411_UniversalPosteRestanteAddress_PDU = -1;  /* UniversalPosteRestanteAddress */
static int hf_x411_UniquePostalName_PDU = -1;     /* UniquePostalName */
static int hf_x411_UniversalUniquePostalName_PDU = -1;  /* UniversalUniquePostalName */
static int hf_x411_LocalPostalAttributes_PDU = -1;  /* LocalPostalAttributes */
static int hf_x411_UniversalLocalPostalAttributes_PDU = -1;  /* UniversalLocalPostalAttributes */
static int hf_x411_ExtendedNetworkAddress_PDU = -1;  /* ExtendedNetworkAddress */
static int hf_x411_TerminalType_PDU = -1;         /* TerminalType */
static int hf_x411_TeletexDomainDefinedAttributes_PDU = -1;  /* TeletexDomainDefinedAttributes */
static int hf_x411_UniversalDomainDefinedAttributes_PDU = -1;  /* UniversalDomainDefinedAttributes */
static int hf_x411_ExtendedEncodedInformationType_PDU = -1;  /* ExtendedEncodedInformationType */
static int hf_x411_MTANameAndOptionalGDI_PDU = -1;  /* MTANameAndOptionalGDI */
static int hf_x411_AsymmetricToken_PDU = -1;      /* AsymmetricToken */
static int hf_x411_BindTokenSignedData_PDU = -1;  /* BindTokenSignedData */
static int hf_x411_MessageTokenSignedData_PDU = -1;  /* MessageTokenSignedData */
static int hf_x411_MessageTokenEncryptedData_PDU = -1;  /* MessageTokenEncryptedData */
static int hf_x411_BindTokenEncryptedData_PDU = -1;  /* BindTokenEncryptedData */
static int hf_x411_SecurityClassification_PDU = -1;  /* SecurityClassification */
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
static int hf_x411_originator_name = -1;          /* MTAOriginatorName */
static int hf_x411_original_encoded_information_types = -1;  /* OriginalEncodedInformationTypes */
static int hf_x411_content_type = -1;             /* ContentType */
static int hf_x411_content_identifier = -1;       /* ContentIdentifier */
static int hf_x411_priority = -1;                 /* Priority */
static int hf_x411_per_message_indicators = -1;   /* PerMessageIndicators */
static int hf_x411_deferred_delivery_time = -1;   /* DeferredDeliveryTime */
static int hf_x411_per_domain_bilateral_information = -1;  /* SEQUENCE_SIZE_1_ub_transfers_OF_PerDomainBilateralInformation */
static int hf_x411_per_domain_bilateral_information_item = -1;  /* PerDomainBilateralInformation */
static int hf_x411_trace_information = -1;        /* TraceInformation */
static int hf_x411_extensions = -1;               /* SET_OF_ExtensionField */
static int hf_x411_extensions_item = -1;          /* ExtensionField */
static int hf_x411_recipient_name = -1;           /* MTARecipientName */
static int hf_x411_originally_specified_recipient_number = -1;  /* OriginallySpecifiedRecipientNumber */
static int hf_x411_per_recipient_indicators = -1;  /* PerRecipientIndicators */
static int hf_x411_explicit_conversion = -1;      /* ExplicitConversion */
static int hf_x411_probe_identifier = -1;         /* ProbeIdentifier */
static int hf_x411_content_length = -1;           /* ContentLength */
static int hf_x411_report_identifier = -1;        /* ReportIdentifier */
static int hf_x411_report_destination_name = -1;  /* ReportDestinationName */
static int hf_x411_subject_identifier = -1;       /* SubjectIdentifier */
static int hf_x411_subject_intermediate_trace_information = -1;  /* SubjectIntermediateTraceInformation */
static int hf_x411_returned_content = -1;         /* Content */
static int hf_x411_additional_information = -1;   /* AdditionalInformation */
static int hf_x411_mta_actual_recipient_name = -1;  /* MTAActualRecipientName */
static int hf_x411_last_trace_information = -1;   /* LastTraceInformation */
static int hf_x411_report_originally_intended_recipient_name = -1;  /* OriginallyIntendedRecipientName */
static int hf_x411_supplementary_information = -1;  /* SupplementaryInformation */
static int hf_x411_country_name = -1;             /* CountryName */
static int hf_x411_bilateral_domain = -1;         /* T_bilateral_domain */
static int hf_x411_administration_domain_name = -1;  /* AdministrationDomainName */
static int hf_x411_private_domain = -1;           /* T_private_domain */
static int hf_x411_private_domain_identifier = -1;  /* PrivateDomainIdentifier */
static int hf_x411_bilateral_information = -1;    /* T_bilateral_information */
static int hf_x411_domain = -1;                   /* T_domain */
static int hf_x411_private_domain_01 = -1;        /* T_private_domain_01 */
static int hf_x411_arrival_time = -1;             /* ArrivalTime */
static int hf_x411_converted_encoded_information_types = -1;  /* ConvertedEncodedInformationTypes */
static int hf_x411_trace_report_type = -1;        /* ReportType */
static int hf_x411_InternalTraceInformation_item = -1;  /* InternalTraceInformationElement */
static int hf_x411_global_domain_identifier = -1;  /* GlobalDomainIdentifier */
static int hf_x411_mta_name = -1;                 /* MTAName */
static int hf_x411_mta_supplied_information = -1;  /* MTASuppliedInformation */
static int hf_x411__untag_item = -1;              /* TraceInformationElement */
static int hf_x411_domain_supplied_information = -1;  /* DomainSuppliedInformation */
static int hf_x411_deferred_time = -1;            /* DeferredTime */
static int hf_x411_other_actions = -1;            /* OtherActions */
static int hf_x411_initiator_name = -1;           /* ObjectName */
static int hf_x411_messages_waiting = -1;         /* MessagesWaiting */
static int hf_x411_responder_name = -1;           /* ObjectName */
static int hf_x411_user_agent = -1;               /* ORAddressAndOptionalDirectoryName */
static int hf_x411_mTA = -1;                      /* MTAName */
static int hf_x411_message_store = -1;            /* ORAddressAndOptionalDirectoryName */
static int hf_x411_urgent = -1;                   /* DeliveryQueue */
static int hf_x411_normal = -1;                   /* DeliveryQueue */
static int hf_x411_non_urgent = -1;               /* DeliveryQueue */
static int hf_x411_messages = -1;                 /* INTEGER_0_ub_queue_size */
static int hf_x411_delivery_queue_octets = -1;    /* INTEGER_0_ub_content_length */
static int hf_x411_simple = -1;                   /* Password */
static int hf_x411_strong = -1;                   /* StrongCredentials */
static int hf_x411_protected = -1;                /* ProtectedPassword */
static int hf_x411_ia5_string = -1;               /* IA5String_SIZE_0_ub_password_length */
static int hf_x411_octet_string = -1;             /* OCTET_STRING_SIZE_0_ub_password_length */
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
static int hf_x411_ImproperlySpecifiedRecipients_item = -1;  /* RecipientName */
static int hf_x411_waiting_operations = -1;       /* Operations */
static int hf_x411_waiting_messages = -1;         /* WaitingMessages */
static int hf_x411_waiting_content_types = -1;    /* SET_SIZE_0_ub_content_types_OF_ContentType */
static int hf_x411_waiting_content_types_item = -1;  /* ContentType */
static int hf_x411_waiting_encoded_information_types = -1;  /* EncodedInformationTypes */
static int hf_x411_recipient_certificate = -1;    /* RecipientCertificate */
static int hf_x411_proof_of_delivery = -1;        /* ProofOfDelivery */
static int hf_x411_empty_result = -1;             /* NULL */
static int hf_x411_max_extensions = -1;           /* SET_SIZE_1_MAX_OF_ExtensionField */
static int hf_x411_max_extensions_item = -1;      /* ExtensionField */
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
static int hf_x411_deliverable_class = -1;        /* SET_SIZE_1_ub_deliverable_class_OF_DeliverableClass */
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
static int hf_x411_x121_address = -1;             /* AddrNumericString */
static int hf_x411_tsap_id = -1;                  /* PrintableString_SIZE_1_ub_tsap_id_length */
static int hf_x411_presentation = -1;             /* PSAPAddress */
static int hf_x411_Redirections_item = -1;        /* RecipientRedirection */
static int hf_x411_redirection_classes = -1;      /* SET_SIZE_1_ub_redirection_classes_OF_RedirectionClass */
static int hf_x411_redirection_classes_item = -1;  /* RedirectionClass */
static int hf_x411_recipient_assigned_alternate_recipient = -1;  /* RecipientAssignedAlternateRecipient */
static int hf_x411_content_types = -1;            /* ContentTypes */
static int hf_x411_maximum_content_length = -1;   /* ContentLength */
static int hf_x411_encoded_information_types_constraints = -1;  /* EncodedInformationTypesConstraints */
static int hf_x411_security_labels = -1;          /* SecurityContext */
static int hf_x411_class_priority = -1;           /* SET_OF_Priority */
static int hf_x411_class_priority_item = -1;      /* Priority */
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
static int hf_x411_type_extensions = -1;          /* T_type_extensions */
static int hf_x411_type_extensions_item = -1;     /* T_type_extensions_item */
static int hf_x411_originator_name_01 = -1;       /* OriginatorName */
static int hf_x411_submission_recipient_name = -1;  /* RecipientName */
static int hf_x411_originator_report_request = -1;  /* OriginatorReportRequest */
static int hf_x411_probe_recipient_name = -1;     /* RecipientName */
static int hf_x411_message_delivery_identifier = -1;  /* MessageDeliveryIdentifier */
static int hf_x411_message_delivery_time = -1;    /* MessageDeliveryTime */
static int hf_x411_other_fields = -1;             /* OtherMessageDeliveryFields */
static int hf_x411_delivered_content_type = -1;   /* DeliveredContentType */
static int hf_x411_delivered_originator_name = -1;  /* DeliveredOriginatorName */
static int hf_x411_delivery_flags = -1;           /* DeliveryFlags */
static int hf_x411_other_recipient_names = -1;    /* OtherRecipientNames */
static int hf_x411_this_recipient_name = -1;      /* ThisRecipientName */
static int hf_x411_originally_intended_recipient_name = -1;  /* OriginallyIntendedRecipientName */
static int hf_x411_subject_submission_identifier = -1;  /* SubjectSubmissionIdentifier */
static int hf_x411_actual_recipient_name = -1;    /* ActualRecipientName */
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
static int hf_x411_standard_extension = -1;       /* StandardExtension */
static int hf_x411_private_extension = -1;        /* T_private_extension */
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
static int hf_x411_domain_01 = -1;                /* GlobalDomainIdentifier */
static int hf_x411_mta_directory_name = -1;       /* Name */
static int hf_x411_ExtendedCertificates_item = -1;  /* ExtendedCertificate */
static int hf_x411_directory_entry = -1;          /* Name */
static int hf_x411_DLExemptedRecipients_item = -1;  /* ORAddressAndOrDirectoryName */
static int hf_x411_encryption_recipient = -1;     /* CertificateAssertion */
static int hf_x411_encryption_originator = -1;    /* CertificateAssertion */
static int hf_x411_selectors_content_integrity_check = -1;  /* CertificateAssertion */
static int hf_x411_token_signature = -1;          /* CertificateAssertion */
static int hf_x411_message_origin_authentication = -1;  /* CertificateAssertion */
static int hf_x411_local_identifier = -1;         /* LocalIdentifier */
static int hf_x411_numeric_private_domain_identifier = -1;  /* AddrNumericString */
static int hf_x411_printable_private_domain_identifier = -1;  /* AddrPrintableString */
static int hf_x411_built_in_standard_attributes = -1;  /* BuiltInStandardAttributes */
static int hf_x411_built_in_domain_defined_attributes = -1;  /* BuiltInDomainDefinedAttributes */
static int hf_x411_extension_attributes = -1;     /* ExtensionAttributes */
static int hf_x411_network_address = -1;          /* NetworkAddress */
static int hf_x411_terminal_identifier = -1;      /* TerminalIdentifier */
static int hf_x411_private_domain_name = -1;      /* PrivateDomainName */
static int hf_x411_organization_name = -1;        /* OrganizationName */
static int hf_x411_numeric_user_identifier = -1;  /* NumericUserIdentifier */
static int hf_x411_personal_name = -1;            /* PersonalName */
static int hf_x411_organizational_unit_names = -1;  /* OrganizationalUnitNames */
static int hf_x411_x121_dcc_code = -1;            /* AddrNumericString */
static int hf_x411_iso_3166_alpha2_code = -1;     /* AddrPrintableString */
static int hf_x411_numeric = -1;                  /* AddrNumericString */
static int hf_x411_printable = -1;                /* AddrPrintableString */
static int hf_x411_numeric_private_domain_name = -1;  /* AddrNumericString */
static int hf_x411_printable_private_domain_name = -1;  /* AddrPrintableString */
static int hf_x411_printable_surname = -1;        /* T_printable_surname */
static int hf_x411_printable_given_name = -1;     /* T_printable_given_name */
static int hf_x411_printable_initials = -1;       /* T_printable_initials */
static int hf_x411_printable_generation_qualifier = -1;  /* T_printable_generation_qualifier */
static int hf_x411_OrganizationalUnitNames_item = -1;  /* OrganizationalUnitName */
static int hf_x411_BuiltInDomainDefinedAttributes_item = -1;  /* BuiltInDomainDefinedAttribute */
static int hf_x411_printable_type = -1;           /* T_printable_type */
static int hf_x411_printable_value = -1;          /* T_printable_value */
static int hf_x411_ExtensionAttributes_item = -1;  /* ExtensionAttribute */
static int hf_x411_extension_attribute_type = -1;  /* ExtensionAttributeType */
static int hf_x411_extension_attribute_value = -1;  /* T_extension_attribute_value */
static int hf_x411_teletex_surname = -1;          /* AddrTeletexString */
static int hf_x411_teletex_given_name = -1;       /* AddrTeletexString */
static int hf_x411_teletex_initials = -1;         /* AddrTeletexString */
static int hf_x411_teletex_generation_qualifier = -1;  /* AddrTeletexString */
static int hf_x411_universal_surname = -1;        /* UniversalOrBMPString */
static int hf_x411_universal_given_name = -1;     /* UniversalOrBMPString */
static int hf_x411_universal_initials = -1;       /* UniversalOrBMPString */
static int hf_x411_universal_generation_qualifier = -1;  /* UniversalOrBMPString */
static int hf_x411_TeletexOrganizationalUnitNames_item = -1;  /* TeletexOrganizationalUnitName */
static int hf_x411_UniversalOrganizationalUnitNames_item = -1;  /* UniversalOrganizationalUnitName */
static int hf_x411_character_encoding = -1;       /* T_character_encoding */
static int hf_x411_two_octets = -1;               /* BMPString_SIZE_1_ub_string_length */
static int hf_x411_four_octets = -1;              /* UniversalString_SIZE_1_ub_string_length */
static int hf_x411_iso_639_language_code = -1;    /* PrintableString_SIZE_CONSTR13857016 */
static int hf_x411_numeric_code = -1;             /* AddrNumericString */
static int hf_x411_printable_code = -1;           /* PrintableString_SIZE_1_ub_postal_code_length */
static int hf_x411_printable_address = -1;        /* T_printable_address */
static int hf_x411_printable_address_item = -1;   /* PrintableString_SIZE_1_ub_pds_parameter_length */
static int hf_x411_teletex_string = -1;           /* TeletexString_SIZE_1_ub_unformatted_address_length */
static int hf_x411_printable_string = -1;         /* PrintableString_SIZE_1_ub_pds_parameter_length */
static int hf_x411_pds_teletex_string = -1;       /* TeletexString_SIZE_1_ub_pds_parameter_length */
static int hf_x411_e163_4_address = -1;           /* T_e163_4_address */
static int hf_x411_number = -1;                   /* NumericString_SIZE_1_ub_e163_4_number_length */
static int hf_x411_sub_address = -1;              /* NumericString_SIZE_1_ub_e163_4_sub_address_length */
static int hf_x411_psap_address = -1;             /* PresentationAddress */
static int hf_x411_TeletexDomainDefinedAttributes_item = -1;  /* TeletexDomainDefinedAttribute */
static int hf_x411_type = -1;                     /* AddrTeletexString */
static int hf_x411_teletex_value = -1;            /* AddrTeletexString */
static int hf_x411_UniversalDomainDefinedAttributes_item = -1;  /* UniversalDomainDefinedAttribute */
static int hf_x411_universal_type = -1;           /* UniversalOrBMPString */
static int hf_x411_universal_value = -1;          /* UniversalOrBMPString */
static int hf_x411_ExtendedEncodedInformationTypes_item = -1;  /* ExtendedEncodedInformationType */
static int hf_x411_g3_facsimile = -1;             /* G3FacsimileNonBasicParameters */
static int hf_x411_teletex = -1;                  /* TeletexNonBasicParameters */
static int hf_x411_graphic_character_sets = -1;   /* TeletexString */
static int hf_x411_control_character_sets = -1;   /* TeletexString */
static int hf_x411_page_formats = -1;             /* OCTET_STRING */
static int hf_x411_miscellaneous_terminal_capabilities = -1;  /* TeletexString */
static int hf_x411_private_use = -1;              /* OCTET_STRING */
static int hf_x411_token_type_identifier = -1;    /* TokenTypeIdentifier */
static int hf_x411_token = -1;                    /* TokenTypeData */
static int hf_x411_signature_algorithm_identifier = -1;  /* AlgorithmIdentifier */
static int hf_x411_name = -1;                     /* T_name */
static int hf_x411_token_recipient_name = -1;     /* RecipientName */
static int hf_x411_token_mta = -1;                /* MTANameAndOptionalGDI */
static int hf_x411_time = -1;                     /* Time */
static int hf_x411_signed_data = -1;              /* TokenData */
static int hf_x411_encryption_algorithm_identifier = -1;  /* AlgorithmIdentifier */
static int hf_x411_encrypted_data = -1;           /* BIT_STRING */
static int hf_x411_asymmetric_token_data = -1;    /* AsymmetricTokenData */
static int hf_x411_algorithm_identifier = -1;     /* AlgorithmIdentifier */
static int hf_x411_token_data_type = -1;          /* TokenDataType */
static int hf_x411_value = -1;                    /* T_value */
static int hf_x411_content_confidentiality_algorithm_identifier = -1;  /* ContentConfidentialityAlgorithmIdentifier */
static int hf_x411_content_integrity_check = -1;  /* ContentIntegrityCheck */
static int hf_x411_message_security_label = -1;   /* MessageSecurityLabel */
static int hf_x411_proof_of_delivery_request = -1;  /* ProofOfDeliveryRequest */
static int hf_x411_message_sequence_number = -1;  /* INTEGER */
static int hf_x411_content_confidentiality_key = -1;  /* EncryptionKey */
static int hf_x411_content_integrity_key = -1;    /* EncryptionKey */
static int hf_x411_security_policy_identifier = -1;  /* SecurityPolicyIdentifier */
static int hf_x411_security_classification = -1;  /* SecurityClassification */
static int hf_x411_privacy_mark = -1;             /* PrivacyMark */
static int hf_x411_security_categories = -1;      /* SecurityCategories */
static int hf_x411_SecurityCategories_item = -1;  /* SecurityCategory */
static int hf_x411_category_type = -1;            /* SecurityCategoryIdentifier */
static int hf_x411_category_value = -1;           /* CategoryValue */
static int hf_x411_rtorq_apdu = -1;               /* RTORQapdu */
static int hf_x411_rtoac_apdu = -1;               /* RTOACapdu */
static int hf_x411_rtorj_apdu = -1;               /* RTORJapdu */
static int hf_x411_rttp_apdu = -1;                /* RTTPapdu */
static int hf_x411_rttr_apdu = -1;                /* RTTRapdu */
static int hf_x411_rtab_apdu = -1;                /* RTABapdu */
static int hf_x411_abortReason = -1;              /* AbortReason */
static int hf_x411_reflectedParameter = -1;       /* BIT_STRING */
static int hf_x411_userdataAB = -1;               /* OBJECT_IDENTIFIER */
static int hf_x411_mta_originator_name = -1;      /* MTAOriginatorName */
static int hf_x411_per_recipient_message_fields = -1;  /* SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageTransferFields */
static int hf_x411_per_recipient_message_fields_item = -1;  /* PerRecipientMessageTransferFields */
static int hf_x411_per_recipient_probe_transfer_fields = -1;  /* SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeTransferFields */
static int hf_x411_per_recipient_probe_transfer_fields_item = -1;  /* PerRecipientProbeTransferFields */
static int hf_x411_per_recipient_report_fields = -1;  /* SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportTransferFields */
static int hf_x411_per_recipient_report_fields_item = -1;  /* PerRecipientReportTransferFields */
static int hf_x411_routing_action = -1;           /* RoutingAction */
static int hf_x411_attempted = -1;                /* T_attempted */
static int hf_x411_mta = -1;                      /* MTAName */
static int hf_x411_attempted_domain = -1;         /* GlobalDomainIdentifier */
static int hf_x411_per_recipient_report_delivery_fields = -1;  /* SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportDeliveryFields */
static int hf_x411_per_recipient_report_delivery_fields_item = -1;  /* PerRecipientReportDeliveryFields */
static int hf_x411_mts_originator_name = -1;      /* OriginatorName */
static int hf_x411_per_recipient_message_submission_fields = -1;  /* SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageSubmissionFields */
static int hf_x411_per_recipient_message_submission_fields_item = -1;  /* PerRecipientMessageSubmissionFields */
static int hf_x411_per_recipient_probe_submission_fields = -1;  /* SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeSubmissionFields */
static int hf_x411_per_recipient_probe_submission_fields_item = -1;  /* PerRecipientProbeSubmissionFields */
static int hf_x411_directory_name = -1;           /* Name */
static int hf_x411_built_in_encoded_information_types = -1;  /* BuiltInEncodedInformationTypes */
static int hf_x411_extended_encoded_information_types = -1;  /* ExtendedEncodedInformationTypes */
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
static int hf_x411_PerMessageIndicators_U_disclosure_of_other_recipients = -1;
static int hf_x411_PerMessageIndicators_U_implicit_conversion_prohibited = -1;
static int hf_x411_PerMessageIndicators_U_alternate_recipient_allowed = -1;
static int hf_x411_PerMessageIndicators_U_content_return_request = -1;
static int hf_x411_PerMessageIndicators_U_reserved = -1;
static int hf_x411_PerMessageIndicators_U_bit_5 = -1;
static int hf_x411_PerMessageIndicators_U_bit_6 = -1;
static int hf_x411_PerMessageIndicators_U_service_message = -1;
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
#line 85 "packet-x411-template.c"

/* Initialize the subtree pointers */
static gint ett_x411 = -1;
static gint ett_p3 = -1;
static gint ett_x411_content_unknown = -1;
static gint ett_x411_bilateral_information = -1;
static gint ett_x411_additional_information = -1;
static gint ett_x411_unknown_standard_extension = -1;
static gint ett_x411_unknown_extension_attribute_type = -1;
static gint ett_x411_unknown_tokendata_type = -1;

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
static gint ett_x411_PerMessageTransferFields = -1;
static gint ett_x411_SEQUENCE_SIZE_1_ub_transfers_OF_PerDomainBilateralInformation = -1;
static gint ett_x411_SET_OF_ExtensionField = -1;
static gint ett_x411_PerRecipientMessageTransferFields = -1;
static gint ett_x411_ProbeTransferEnvelope = -1;
static gint ett_x411_PerProbeTransferFields = -1;
static gint ett_x411_PerRecipientProbeTransferFields = -1;
static gint ett_x411_ReportTransferEnvelope = -1;
static gint ett_x411_ReportTransferContent = -1;
static gint ett_x411_PerReportTransferFields = -1;
static gint ett_x411_PerRecipientReportTransferFields = -1;
static gint ett_x411_PerDomainBilateralInformation = -1;
static gint ett_x411_T_bilateral_domain = -1;
static gint ett_x411_T_private_domain = -1;
static gint ett_x411_BilateralDomain = -1;
static gint ett_x411_T_domain = -1;
static gint ett_x411_T_private_domain_01 = -1;
static gint ett_x411_PerRecipientIndicators = -1;
static gint ett_x411_LastTraceInformation = -1;
static gint ett_x411_InternalTraceInformation = -1;
static gint ett_x411_InternalTraceInformationElement = -1;
static gint ett_x411_MTASuppliedInformation = -1;
static gint ett_x411_SEQUENCE_SIZE_1_ub_transfers_OF_TraceInformationElement = -1;
static gint ett_x411_TraceInformationElement = -1;
static gint ett_x411_DomainSuppliedInformation = -1;
static gint ett_x411_AdditionalActions = -1;
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
static gint ett_x411_SET_SIZE_0_ub_content_types_OF_ContentType = -1;
static gint ett_x411_Operations = -1;
static gint ett_x411_WaitingMessages = -1;
static gint ett_x411_MessageDeliveryArgument = -1;
static gint ett_x411_MessageDeliveryResult = -1;
static gint ett_x411_ReportDeliveryArgument = -1;
static gint ett_x411_ReportDeliveryResult = -1;
static gint ett_x411_SET_SIZE_1_MAX_OF_ExtensionField = -1;
static gint ett_x411_DeliveryControlArgument = -1;
static gint ett_x411_DeliveryControlResult = -1;
static gint ett_x411_RefusedOperation = -1;
static gint ett_x411_T_refused_argument = -1;
static gint ett_x411_Controls = -1;
static gint ett_x411_RegisterArgument = -1;
static gint ett_x411_SET_SIZE_1_ub_deliverable_class_OF_DeliverableClass = -1;
static gint ett_x411_RegisterResult = -1;
static gint ett_x411_T_non_empty_result = -1;
static gint ett_x411_ChangeCredentialsArgument = -1;
static gint ett_x411_UserAddress = -1;
static gint ett_x411_T_x121 = -1;
static gint ett_x411_Redirections = -1;
static gint ett_x411_RecipientRedirection = -1;
static gint ett_x411_SET_SIZE_1_ub_redirection_classes_OF_RedirectionClass = -1;
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
static gint ett_x411_T_type_extensions = -1;
static gint ett_x411_MessageSubmissionEnvelope = -1;
static gint ett_x411_PerMessageSubmissionFields = -1;
static gint ett_x411_PerRecipientMessageSubmissionFields = -1;
static gint ett_x411_ProbeSubmissionEnvelope = -1;
static gint ett_x411_PerProbeSubmissionFields = -1;
static gint ett_x411_PerRecipientProbeSubmissionFields = -1;
static gint ett_x411_MessageDeliveryEnvelope = -1;
static gint ett_x411_OtherMessageDeliveryFields = -1;
static gint ett_x411_ReportDeliveryEnvelope = -1;
static gint ett_x411_PerReportDeliveryFields = -1;
static gint ett_x411_PerRecipientReportDeliveryFields = -1;
static gint ett_x411_ReportType = -1;
static gint ett_x411_DeliveryReport = -1;
static gint ett_x411_NonDeliveryReport = -1;
static gint ett_x411_ContentTypes = -1;
static gint ett_x411_ContentType = -1;
static gint ett_x411_DeliveredContentType = -1;
static gint ett_x411_PerMessageIndicators_U = -1;
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
static gint ett_x411_MTSIdentifier_U = -1;
static gint ett_x411_GlobalDomainIdentifier_U = -1;
static gint ett_x411_PrivateDomainIdentifier = -1;
static gint ett_x411_ORName_U = -1;
static gint ett_x411_ORAddress = -1;
static gint ett_x411_BuiltInStandardAttributes = -1;
static gint ett_x411_CountryName_U = -1;
static gint ett_x411_AdministrationDomainName_U = -1;
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
static gint ett_x411_EncodedInformationTypes_U = -1;
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
static gint ett_x411_TokenData = -1;
static gint ett_x411_MessageTokenSignedData = -1;
static gint ett_x411_MessageTokenEncryptedData = -1;
static gint ett_x411_SecurityLabel = -1;
static gint ett_x411_SecurityCategories = -1;
static gint ett_x411_SecurityCategory = -1;
static gint ett_x411_RTSE_apdus = -1;
static gint ett_x411_RTABapdu = -1;
static gint ett_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageTransferFields = -1;
static gint ett_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeTransferFields = -1;
static gint ett_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportTransferFields = -1;
static gint ett_x411_T_attempted = -1;
static gint ett_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportDeliveryFields = -1;
static gint ett_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageSubmissionFields = -1;
static gint ett_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeSubmissionFields = -1;

/*--- End of included file: packet-x411-ett.c ---*/
#line 96 "packet-x411-template.c"

/* Dissector tables */
static dissector_table_t x411_extension_dissector_table;
static dissector_table_t x411_extension_attribute_dissector_table;
static dissector_table_t x411_tokendata_dissector_table;


/*--- Included file: packet-x411-val.h ---*/
#line 1 "packet-x411-val.h"
#define op_message_submission          3
#define op_probe_submission            4
#define op_cancel_deferred_delivery    7
#define op_submission_control          2
#define err_submission_control_violated 1
#define err_element_of_service_not_subscribed 4
#define err_deferred_delivery_cancellation_rejected 8
#define err_originator_invalid         2
#define err_recipient_improperly_specified 3
#define err_message_submission_identifier_invalid 7
#define err_inconsistent_request       11
#define err_security_error             12
#define err_unsupported_critical_function 13
#define err_remote_bind_error          15
#define op_message_delivery            5
#define op_report_delivery             6
#define op_delivery_control            2
#define err_delivery_control_violated  1
#define err_control_violates_registration 14
#define err_operation_refused          16
#define op_register                    1
#define op_change_credentials          8
#define err_register_rejected          10
#define err_new_credentials_unacceptable 6
#define err_old_credentials_incorrectly_specified 5
#define id_mhs_protocols               "2.6.0"
#define id_mod                         id_mhs_protocols".0"
#define id_ac                          id_mhs_protocols".1"
#define id_as                          id_mhs_protocols".2"
#define id_ase                         id_mhs_protocols".3"
#define id_mod_object_identifiers      id_mod".0"
#define id_mod_mts_access_protocol     id_mod".1"
#define id_mod_ms_access_protocol      id_mod".2"
#define id_mod_mts_transfer_protocol   id_mod".3"
#define id_ac_mts_access_88            id_ac".0"
#define id_ac_mts_forced_access_88     id_ac".1"
#define id_ac_mts_reliable_access_88   id_ac".2"
#define id_ac_mts_forced_reliable_access_88 id_ac".3"
#define id_ac_mts_access_94            id_ac".7"
#define id_ac_mts_forced_access_94     id_ac".8"
#define id_ac_mts_reliable_access_94   id_ac".9"
#define id_ac_mts_forced_reliable_access_94 id_ac".10"
#define id_ac_ms_access_88             id_ac".4"
#define id_ac_ms_reliable_access_88    id_ac".5"
#define id_ac_ms_access_94             id_ac".11"
#define id_ac_ms_reliable_access_94    id_ac".12"
#define id_ac_mts_transfer             id_ac".6"
#define id_as_msse                     id_as".1"
#define id_as_mdse_88                  id_as".2"
#define id_as_mrse_88                  id_as".5"
#define id_as_mase_88                  id_as".6"
#define id_as_mtse                     id_as".7"
#define id_as_mts_rtse                 id_as".8"
#define id_as_ms_88                    id_as".9"
#define id_as_ms_rtse                  id_as".10"
#define id_as_mts                      id_as".11"
#define id_as_mta_rtse                 id_as".12"
#define id_as_ms_msse                  id_as".13"
#define id_as_mdse_94                  id_as".14"
#define id_as_mrse_94                  id_as".15"
#define id_as_mase_94                  id_as".16"
#define id_as_ms_94                    id_as".17"
#define id_ase_msse                    id_ase".0"
#define id_ase_mdse                    id_ase".1"
#define id_ase_mrse                    id_ase".2"
#define id_ase_mase                    id_ase".3"
#define id_ase_mtse                    id_ase".4"

/*--- End of included file: packet-x411-val.h ---*/
#line 103 "packet-x411-template.c"


/*--- Included file: packet-x411-table.c ---*/
#line 1 "packet-x411-table.c"

/* P3 ABSTRACT-OPERATIONS */
const value_string p3_opr_code_string_vals[] = {
	{ op_ros_bind, "mts_bind" },
	{ op_message_submission, "message_submission" },
	{ op_probe_submission, "probe_submission" },
	{ op_cancel_deferred_delivery, "cancel_deferred_delivery" },
	{ op_submission_control, "submission_control" },
	{ op_message_delivery, "message_delivery" },
	{ op_report_delivery, "report_delivery" },
	{ op_delivery_control, "delivery_control" },
	{ op_register, "register" },
	{ op_change_credentials, "change_credentials" },
	{ 0, NULL }
};


/* P3 ERRORS */
static const value_string p3_err_code_string_vals[] = {
	{ err_ros_bind, "mts_bind_error" },  
	{ err_submission_control_violated, "submission_control_violated" },  
	{ err_element_of_service_not_subscribed, "element_of_service_not_subscribed" },  
	{ err_deferred_delivery_cancellation_rejected, "deferred_delivery_cancellation_rejected" },  
	{ err_originator_invalid, "originator_invalid" },  
	{ err_recipient_improperly_specified, "recipient_improperly_specified" },  
	{ err_message_submission_identifier_invalid, "message_submission_identifier_invalid" },  
	{ err_inconsistent_request, "inconsistent_request" },  
	{ err_security_error, "security_error" },  
	{ err_unsupported_critical_function, "unsupported_critical_function" },  
	{ err_remote_bind_error, "remote_bind_error" },  
	{ err_delivery_control_violated, "delivery_control_violated" },  
	{ err_control_violates_registration, "control_violates_registration" },  
	{ err_operation_refused, "operation_refused" },  
	{ err_register_rejected, "register_rejected" },  
	{ err_new_credentials_unacceptable, "new_credentials_unacceptable" },  
	{ err_old_credentials_incorrectly_specified, "old_credentials_incorrectly_specified" },  
	  { 0, NULL }
};


/*--- End of included file: packet-x411-table.c ---*/
#line 105 "packet-x411-template.c"


/*--- Included file: packet-x411-fn.c ---*/
#line 1 "packet-x411-fn.c"


static int
dissect_x411_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_x411_MTAName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 635 "x411.cnf"
	tvbuff_t	*mtaname = NULL;

	  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            &mtaname);


	if(doing_address) {

		proto_item_append_text(address_item, " %s", tvb_format_text(mtaname, 0, tvb_length(mtaname)));

	} else {

	if (check_col(actx->pinfo->cinfo, COL_INFO) && mtaname) {
		col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", tvb_format_text(mtaname, 0, tvb_length(mtaname)));
	}

	}



  return offset;
}



static int
dissect_x411_IA5String_SIZE_0_ub_password_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x411_OCTET_STRING_SIZE_0_ub_password_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string x411_Password_vals[] = {
  {   0, "ia5-string" },
  {   1, "octet-string" },
  { 0, NULL }
};

static const ber_choice_t Password_choice[] = {
  {   0, &hf_x411_ia5_string     , BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_x411_IA5String_SIZE_0_ub_password_length },
  {   1, &hf_x411_octet_string   , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_x411_OCTET_STRING_SIZE_0_ub_password_length },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_Password(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Password_choice, hf_index, ett_x411_Password,
                                 NULL);

  return offset;
}



static int
dissect_x411_TokenTypeIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &object_identifier_id);

  return offset;
}



static int
dissect_x411_TokenTypeData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 993 "x411.cnf"
	
	if(object_identifier_id) 
   	   call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t Token_sequence[] = {
  { &hf_x411_token_type_identifier, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_TokenTypeIdentifier },
  { &hf_x411_token          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x411_TokenTypeData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_Token(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Token_sequence, hf_index, ett_x411_Token);

  return offset;
}


static const ber_sequence_t StrongCredentials_set[] = {
  { &hf_x411_bind_token     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_Token },
  { &hf_x411_certificate    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509af_Certificates },
  { &hf_x411_certificate_selector, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_CertificateAssertion },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_StrongCredentials(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              StrongCredentials_set, hf_index, ett_x411_StrongCredentials);

  return offset;
}



static int
dissect_x411_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t Signature_sequence[] = {
  { &hf_x411_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_x411_encrypted      , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_x411_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_Signature(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Signature_sequence, hf_index, ett_x411_Signature);

  return offset;
}



static int
dissect_x411_UTCTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_UTCTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t ProtectedPassword_set[] = {
  { &hf_x411_signature      , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x411_Signature },
  { &hf_x411_time1          , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_UTCTime },
  { &hf_x411_time2          , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_UTCTime },
  { &hf_x411_random1        , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_BIT_STRING },
  { &hf_x411_random2        , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_ProtectedPassword(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ProtectedPassword_set, hf_index, ett_x411_ProtectedPassword);

  return offset;
}


const value_string x411_Credentials_vals[] = {
  {   0, "simple" },
  {   1, "strong" },
  {   2, "protected" },
  { 0, NULL }
};

static const ber_choice_t Credentials_choice[] = {
  {   0, &hf_x411_simple         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_x411_Password },
  {   1, &hf_x411_strong         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_StrongCredentials },
  {   2, &hf_x411_protected      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x411_ProtectedPassword },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_x411_Credentials(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1001 "x411.cnf"
  gint credentials = -1;

    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Credentials_choice, hf_index, ett_x411_Credentials,
                                 &credentials);


  if( (credentials!=-1) && x411_Credentials_vals[credentials].strptr ){
    if (check_col(actx->pinfo->cinfo, COL_INFO)) {
      col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", x411_Credentials_vals[credentials].strptr);
    }
  }



  return offset;
}



int
dissect_x411_InitiatorCredentials(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_Credentials(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_SecurityPolicyIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
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
dissect_x411_SecurityClassification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_x411_PrivacyMark(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x411_SecurityCategoryIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_x411_SecurityCategoryValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 525 "x411.cnf"

	offset = dissect_unknown_ber(actx->pinfo, tvb, offset, tree);



  return offset;
}



static int
dissect_x411_CategoryValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_SecurityCategoryValue(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t SecurityCategory_sequence[] = {
  { &hf_x411_category_type  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_SecurityCategoryIdentifier },
  { &hf_x411_category_value , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x411_CategoryValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_SecurityCategory(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SecurityCategory_sequence, hf_index, ett_x411_SecurityCategory);

  return offset;
}


static const ber_sequence_t SecurityCategories_set_of[1] = {
  { &hf_x411_SecurityCategories_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x411_SecurityCategory },
};

static int
dissect_x411_SecurityCategories(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SecurityCategories_set_of, hf_index, ett_x411_SecurityCategories);

  return offset;
}


static const ber_sequence_t SecurityLabel_set[] = {
  { &hf_x411_security_policy_identifier, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_SecurityPolicyIdentifier },
  { &hf_x411_security_classification, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_SecurityClassification },
  { &hf_x411_privacy_mark   , BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_PrivacyMark },
  { &hf_x411_security_categories, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_SecurityCategories },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x411_SecurityLabel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SecurityLabel_set, hf_index, ett_x411_SecurityLabel);

  return offset;
}


static const ber_sequence_t SecurityContext_set_of[1] = {
  { &hf_x411_SecurityContext_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x411_SecurityLabel },
};

int
dissect_x411_SecurityContext(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SecurityContext_set_of, hf_index, ett_x411_SecurityContext);

  return offset;
}


static const ber_sequence_t AuthenticatedArgument_set[] = {
  { &hf_x411_authenticated_initiator_name, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_MTAName },
  { &hf_x411_initiator_credentials, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_InitiatorCredentials },
  { &hf_x411_security_context, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SecurityContext },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_AuthenticatedArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              AuthenticatedArgument_set, hf_index, ett_x411_AuthenticatedArgument);

  return offset;
}


static const value_string x411_MTABindArgument_vals[] = {
  {   0, "unauthenticated" },
  {   1, "authenticated" },
  { 0, NULL }
};

static const ber_choice_t MTABindArgument_choice[] = {
  {   0, &hf_x411_unauthenticated, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_x411_NULL },
  {   1, &hf_x411_authenticated_argument, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x411_AuthenticatedArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_MTABindArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 MTABindArgument_choice, hf_index, ett_x411_MTABindArgument,
                                 NULL);

  return offset;
}



int
dissect_x411_ResponderCredentials(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_Credentials(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t AuthenticatedResult_set[] = {
  { &hf_x411_authenticated_responder_name, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_MTAName },
  { &hf_x411_responder_credentials, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_ResponderCredentials },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_AuthenticatedResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              AuthenticatedResult_set, hf_index, ett_x411_AuthenticatedResult);

  return offset;
}


static const value_string x411_MTABindResult_vals[] = {
  {   0, "unauthenticated" },
  {   1, "authenticated" },
  { 0, NULL }
};

static const ber_choice_t MTABindResult_choice[] = {
  {   0, &hf_x411_unauthenticated, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_x411_NULL },
  {   1, &hf_x411_authenticated_result, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x411_AuthenticatedResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_MTABindResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
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
dissect_x411_MTABindError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 984 "x411.cnf"
  int error = -1;
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &error);

  if((error != -1) && check_col(actx->pinfo->cinfo, COL_INFO))
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, " (%s)", val_to_str(error, x411_MTABindError_vals, "error(%d)"));



  return offset;
}



static int
dissect_x411_AddrNumericString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 746 "x411.cnf"
	tvbuff_t	*nstring = NULL;

	  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            &nstring);


	if(doing_address && nstring)
		g_strlcat(oraddress, tvb_format_text(nstring, 0, tvb_length(nstring)), MAX_ORA_STR_LEN);



  return offset;
}



static int
dissect_x411_AddrPrintableString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 735 "x411.cnf"
	tvbuff_t	*nstring = NULL;

	  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            &nstring);


	if(doing_address && nstring)
		g_strlcat(oraddress, tvb_format_text(nstring, 0, tvb_length(nstring)), MAX_ORA_STR_LEN);



  return offset;
}


static const value_string x411_CountryName_U_vals[] = {
  {   0, "x121-dcc-code" },
  {   1, "iso-3166-alpha2-code" },
  { 0, NULL }
};

static const ber_choice_t CountryName_U_choice[] = {
  {   0, &hf_x411_x121_dcc_code  , BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_x411_AddrNumericString },
  {   1, &hf_x411_iso_3166_alpha2_code, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_x411_AddrPrintableString },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_CountryName_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CountryName_U_choice, hf_index, ett_x411_CountryName_U,
                                 NULL);

  return offset;
}



static int
dissect_x411_CountryName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 552 "x411.cnf"
 if(doing_address)
    g_strlcat(oraddress, "/C=", MAX_ORA_STR_LEN);
 
   offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 1, TRUE, dissect_x411_CountryName_U);





  return offset;
}


static const value_string x411_AdministrationDomainName_U_vals[] = {
  {   0, "numeric" },
  {   1, "printable" },
  { 0, NULL }
};

static const ber_choice_t AdministrationDomainName_U_choice[] = {
  {   0, &hf_x411_numeric        , BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_x411_AddrNumericString },
  {   1, &hf_x411_printable      , BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_x411_AddrPrintableString },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_AdministrationDomainName_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AdministrationDomainName_U_choice, hf_index, ett_x411_AdministrationDomainName_U,
                                 NULL);

  return offset;
}



static int
dissect_x411_AdministrationDomainName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 559 "x411.cnf"
  if(doing_address)
    g_strlcat(oraddress, "/A=", MAX_ORA_STR_LEN);

   offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 2, TRUE, dissect_x411_AdministrationDomainName_U);





  return offset;
}


static const value_string x411_PrivateDomainIdentifier_vals[] = {
  {   0, "numeric" },
  {   1, "printable" },
  { 0, NULL }
};

static const ber_choice_t PrivateDomainIdentifier_choice[] = {
  {   0, &hf_x411_numeric_private_domain_identifier, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_x411_AddrNumericString },
  {   1, &hf_x411_printable_private_domain_identifier, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_x411_AddrPrintableString },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_PrivateDomainIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 686 "x411.cnf"

	if(doing_address)
		g_strlcat(oraddress, "/P=", MAX_ORA_STR_LEN);

	  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PrivateDomainIdentifier_choice, hf_index, ett_x411_PrivateDomainIdentifier,
                                 NULL);




  return offset;
}


static const ber_sequence_t GlobalDomainIdentifier_U_sequence[] = {
  { &hf_x411_country_name   , BER_CLASS_APP, 1, BER_FLAGS_NOOWNTAG, dissect_x411_CountryName },
  { &hf_x411_administration_domain_name, BER_CLASS_APP, 2, BER_FLAGS_NOOWNTAG, dissect_x411_AdministrationDomainName },
  { &hf_x411_private_domain_identifier, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_PrivateDomainIdentifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_GlobalDomainIdentifier_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GlobalDomainIdentifier_U_sequence, hf_index, ett_x411_GlobalDomainIdentifier_U);

  return offset;
}



static int
dissect_x411_GlobalDomainIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 864 "x411.cnf"
	
	oraddress = ep_alloc(MAX_ORA_STR_LEN); oraddress[0] = '\0';	
	address_item = tree;

	  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 3, TRUE, dissect_x411_GlobalDomainIdentifier_U);


	if(*oraddress) {
		proto_item_append_text(address_item, " (%s/", oraddress);

		if(doing_subjectid  && check_col(actx->pinfo->cinfo, COL_INFO)) {
			col_append_fstr(actx->pinfo->cinfo, COL_INFO, " (%s/", oraddress);
		}
	}




  return offset;
}



static int
dissect_x411_LocalIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 883 "x411.cnf"
	tvbuff_t 	*id = NULL;
	
	  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            &id);

	
	if(id) {
	  if(doing_address) 
		  proto_item_append_text(address_item, " $ %s)", tvb_format_text(id, 0, tvb_length(id)));

          if(doing_subjectid  && check_col(actx->pinfo->cinfo, COL_INFO)) 
		col_append_fstr(actx->pinfo->cinfo, COL_INFO, " $ %s)", tvb_format_text(id, 0, tvb_length(id)));
	}



  return offset;
}


static const ber_sequence_t MTSIdentifier_U_sequence[] = {
  { &hf_x411_global_domain_identifier, BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_x411_GlobalDomainIdentifier },
  { &hf_x411_local_identifier, BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_x411_LocalIdentifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_MTSIdentifier_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MTSIdentifier_U_sequence, hf_index, ett_x411_MTSIdentifier_U);

  return offset;
}



static int
dissect_x411_MTSIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 896 "x411.cnf"

	doing_address = TRUE;

	if(hf_index == hf_x411_subject_identifier)
		doing_subjectid = TRUE;

	  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 4, TRUE, dissect_x411_MTSIdentifier_U);


	doing_address = FALSE;

	if(hf_index == hf_x411_subject_identifier)
		doing_subjectid = FALSE;




  return offset;
}



static int
dissect_x411_MessageIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 858 "x411.cnf"

	address_item = NULL;

	  offset = dissect_x411_MTSIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);




  return offset;
}



static int
dissect_x411_X121Address(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 655 "x411.cnf"
	tvbuff_t	*string = NULL;

	  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            &string);


	if(doing_address && string) {
		g_strlcat(oraddress, "/X121=", MAX_ORA_STR_LEN);
		g_strlcat(oraddress, tvb_format_text(string, 0, tvb_length(string)), MAX_ORA_STR_LEN);
	}




  return offset;
}



static int
dissect_x411_NetworkAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_X121Address(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_TerminalIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 669 "x411.cnf"
	tvbuff_t	*string = NULL;

	  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            &string);


	if(doing_address && string) {
		g_strlcat(oraddress, "/UA-ID=", MAX_ORA_STR_LEN);
		g_strlcat(oraddress, tvb_format_text(string, 0, tvb_length(string)), MAX_ORA_STR_LEN);
	}



  return offset;
}


static const value_string x411_PrivateDomainName_vals[] = {
  {   0, "numeric" },
  {   1, "printable" },
  { 0, NULL }
};

static const ber_choice_t PrivateDomainName_choice[] = {
  {   0, &hf_x411_numeric_private_domain_name, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_x411_AddrNumericString },
  {   1, &hf_x411_printable_private_domain_name, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_x411_AddrPrintableString },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_PrivateDomainName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 679 "x411.cnf"

	if(doing_address)
		g_strlcat(oraddress, "/P=", MAX_ORA_STR_LEN);

	  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PrivateDomainName_choice, hf_index, ett_x411_PrivateDomainName,
                                 NULL);




  return offset;
}



static int
dissect_x411_OrganizationName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 696 "x411.cnf"
	tvbuff_t	*string = NULL;

	  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            &string);


	if(doing_address && string) {
		g_strlcat(oraddress, "/O=", MAX_ORA_STR_LEN);
		g_strlcat(oraddress, tvb_format_text(string, 0, tvb_length(string)), MAX_ORA_STR_LEN);
	}



  return offset;
}



static int
dissect_x411_NumericUserIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x411_T_printable_surname(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 766 "x411.cnf"
	tvbuff_t	*pstring = NULL;

	  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            &pstring);


	if(doing_address && pstring) {
	    g_strlcat(oraddress, "/S=", MAX_ORA_STR_LEN);
	  g_strlcat(oraddress, tvb_format_text(pstring, 0, tvb_length(pstring)), MAX_ORA_STR_LEN);
	}


  return offset;
}



static int
dissect_x411_T_printable_given_name(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 775 "x411.cnf"
	tvbuff_t	*pstring = NULL;

	  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            &pstring);


	if(doing_address && pstring) {
	    g_strlcat(oraddress, "/G=", MAX_ORA_STR_LEN);
	  g_strlcat(oraddress, tvb_format_text(pstring, 0, tvb_length(pstring)), MAX_ORA_STR_LEN);
	}


  return offset;
}



static int
dissect_x411_T_printable_initials(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 784 "x411.cnf"
	tvbuff_t	*pstring = NULL;

	  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            &pstring);


	if(doing_address && pstring) {
	    g_strlcat(oraddress, "/I=", MAX_ORA_STR_LEN);
	  g_strlcat(oraddress, tvb_format_text(pstring, 0, tvb_length(pstring)), MAX_ORA_STR_LEN);
	}


  return offset;
}



static int
dissect_x411_T_printable_generation_qualifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 793 "x411.cnf"
	tvbuff_t	*pstring = NULL;

	  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            &pstring);


	if(doing_address && pstring) {
	    g_strlcat(oraddress, "/GQ=", MAX_ORA_STR_LEN);
	  g_strlcat(oraddress, tvb_format_text(pstring, 0, tvb_length(pstring)), MAX_ORA_STR_LEN);
	}



  return offset;
}


static const ber_sequence_t PersonalName_set[] = {
  { &hf_x411_printable_surname, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_T_printable_surname },
  { &hf_x411_printable_given_name, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_T_printable_given_name },
  { &hf_x411_printable_initials, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_T_printable_initials },
  { &hf_x411_printable_generation_qualifier, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_T_printable_generation_qualifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_PersonalName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              PersonalName_set, hf_index, ett_x411_PersonalName);

  return offset;
}



static int
dissect_x411_OrganizationalUnitName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 709 "x411.cnf"
	tvbuff_t	*string = NULL;

	  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            &string);


	if(doing_address && string) {
		g_strlcat(oraddress, "/OU=", MAX_ORA_STR_LEN);
		g_strlcat(oraddress, tvb_format_text(string, 0, tvb_length(string)), MAX_ORA_STR_LEN);
	}



  return offset;
}


static const ber_sequence_t OrganizationalUnitNames_sequence_of[1] = {
  { &hf_x411_OrganizationalUnitNames_item, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_x411_OrganizationalUnitName },
};

static int
dissect_x411_OrganizationalUnitNames(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      OrganizationalUnitNames_sequence_of, hf_index, ett_x411_OrganizationalUnitNames);

  return offset;
}


static const ber_sequence_t BuiltInStandardAttributes_sequence[] = {
  { &hf_x411_country_name   , BER_CLASS_APP, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_CountryName },
  { &hf_x411_administration_domain_name, BER_CLASS_APP, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_AdministrationDomainName },
  { &hf_x411_network_address, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_NetworkAddress },
  { &hf_x411_terminal_identifier, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_TerminalIdentifier },
  { &hf_x411_private_domain_name, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_PrivateDomainName },
  { &hf_x411_organization_name, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_OrganizationName },
  { &hf_x411_numeric_user_identifier, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_NumericUserIdentifier },
  { &hf_x411_personal_name  , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_PersonalName },
  { &hf_x411_organizational_unit_names, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_OrganizationalUnitNames },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_BuiltInStandardAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 920 "x411.cnf"

	address_item = tree;	

	  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BuiltInStandardAttributes_sequence, hf_index, ett_x411_BuiltInStandardAttributes);




  return offset;
}



static int
dissect_x411_T_printable_type(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 803 "x411.cnf"
	tvbuff_t	*pstring = NULL;

	  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            &pstring);


	if(doing_address && pstring) {
	    g_strlcat(oraddress, "/DD.", MAX_ORA_STR_LEN);
	    g_strlcat(oraddress, tvb_format_text(pstring, 0, tvb_length(pstring)), MAX_ORA_STR_LEN);
	    g_strlcat(ddatype, tvb_format_text(pstring, 0, tvb_length(pstring)), MAX_ORA_STR_LEN);
	}
	


  return offset;
}



static int
dissect_x411_T_printable_value(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 814 "x411.cnf"
	tvbuff_t	*pstring = NULL;

	  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            &pstring);


	if(doing_address && pstring) {
	    g_strlcat(oraddress, "=", MAX_ORA_STR_LEN);
	    g_strlcat(oraddress, tvb_format_text(pstring, 0, tvb_length(pstring)), MAX_ORA_STR_LEN);
	    if (*ddatype) {
	       proto_item_append_text (tree, " (%s=%s)", ddatype, tvb_format_text(pstring, 0, tvb_length(pstring)));
	    }
	}
	


  return offset;
}


static const ber_sequence_t BuiltInDomainDefinedAttribute_sequence[] = {
  { &hf_x411_printable_type , BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_x411_T_printable_type },
  { &hf_x411_printable_value, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_x411_T_printable_value },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_BuiltInDomainDefinedAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 827 "x411.cnf"
        ddatype = ep_alloc(MAX_ORA_STR_LEN); ddatype[0] = '\0';

	  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BuiltInDomainDefinedAttribute_sequence, hf_index, ett_x411_BuiltInDomainDefinedAttribute);




  return offset;
}


static const ber_sequence_t BuiltInDomainDefinedAttributes_sequence_of[1] = {
  { &hf_x411_BuiltInDomainDefinedAttributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x411_BuiltInDomainDefinedAttribute },
};

static int
dissect_x411_BuiltInDomainDefinedAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      BuiltInDomainDefinedAttributes_sequence_of, hf_index, ett_x411_BuiltInDomainDefinedAttributes);

  return offset;
}


static const value_string x411_ExtensionAttributeType_vals[] = {
  {   1, "common-name" },
  {   2, "teletex-common-name" },
  {   3, "teletex-organization-name" },
  {   4, "teletex-personal-name" },
  {   5, "teletex-organizational-unit-names" },
  {   6, "teletex-domain-defined-attributes" },
  {   7, "pds-name" },
  {   8, "physical-delivery-country-name" },
  {   9, "postal-code" },
  {  10, "physical-delivery-office-name" },
  {  11, "physical-delivery-office-number" },
  {  12, "extension-OR-address-components" },
  {  13, "physical-delivery-personal-name" },
  {  14, "physical-delivery-organization-name" },
  {  15, "extension-physical-delivery-address-components" },
  {  16, "unformatted-postal-address" },
  {  17, "street-address" },
  {  18, "post-office-box-address" },
  {  19, "poste-restante-address" },
  {  20, "unique-postal-name" },
  {  21, "local-postal-attributes" },
  {  22, "extended-network-address" },
  {  23, "terminal-type" },
  {  24, "universal-common-name" },
  {  25, "universal-organization-name" },
  {  26, "universal-personal-name" },
  {  27, "universal-organizational-unit-names" },
  {  28, "universal-domain-defined-attributes" },
  {  29, "universal-physical-delivery-office-name" },
  {  30, "universal-physical-delivery-office-number" },
  {  31, "universal-extension-OR-address-components" },
  {  32, "universal-physical-delivery-personal-name" },
  {  33, "universal-physical-delivery-organization-name" },
  {  34, "universal-extension-physical-delivery-address-components" },
  {  35, "universal-unformatted-postal-address" },
  {  36, "universal-street-address" },
  {  37, "universal-post-office-box-address" },
  {  38, "universal-poste-restante-address" },
  {  39, "universal-unique-postal-name" },
  {  40, "universal-local-postal-attributes" },
  { 0, NULL }
};


static int
dissect_x411_ExtensionAttributeType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &extension_id);

  return offset;
}



static int
dissect_x411_T_extension_attribute_value(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 532 "x411.cnf"

	proto_item_append_text(tree, " (%s)", val_to_str(extension_id, x411_ExtensionAttributeType_vals, "extension-attribute-type %d")); 
	if (dissector_try_port(x411_extension_attribute_dissector_table, extension_id, tvb, actx->pinfo, tree)) {
		offset =tvb_length(tvb);
	} else {
		proto_item *item = NULL;
		proto_tree *next_tree = NULL;

		item = proto_tree_add_text(tree, tvb, 0, tvb_length_remaining(tvb, offset), 
			"Dissector for extension-attribute-type %d not implemented.  Contact Wireshark developers if you want this supported", extension_id);
		next_tree = proto_item_add_subtree(item, ett_x411_unknown_extension_attribute_type);
		offset = dissect_unknown_ber(actx->pinfo, tvb, offset, next_tree);
		expert_add_info_format(actx->pinfo, item, PI_UNDECODED, PI_WARN, "Unknown extension-attribute-type");
	}




  return offset;
}


static const ber_sequence_t ExtensionAttribute_sequence[] = {
  { &hf_x411_extension_attribute_type, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_ExtensionAttributeType },
  { &hf_x411_extension_attribute_value, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x411_T_extension_attribute_value },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_ExtensionAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExtensionAttribute_sequence, hf_index, ett_x411_ExtensionAttribute);

  return offset;
}


static const ber_sequence_t ExtensionAttributes_set_of[1] = {
  { &hf_x411_ExtensionAttributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x411_ExtensionAttribute },
};

static int
dissect_x411_ExtensionAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 ExtensionAttributes_set_of, hf_index, ett_x411_ExtensionAttributes);

  return offset;
}


static const ber_sequence_t ORName_U_sequence[] = {
  { &hf_x411_built_in_standard_attributes, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x411_BuiltInStandardAttributes },
  { &hf_x411_built_in_domain_defined_attributes, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_BuiltInDomainDefinedAttributes },
  { &hf_x411_extension_attributes, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_ExtensionAttributes },
  { &hf_x411_directory_name , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509if_Name },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_ORName_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ORName_U_sequence, hf_index, ett_x411_ORName_U);

  return offset;
}



int
dissect_x411_ORName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 845 "x411.cnf"
	
	oraddress = ep_alloc(MAX_ORA_STR_LEN); oraddress[0] = '\0';	
	address_item = NULL;
	doing_address = TRUE;

	  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 0, TRUE, dissect_x411_ORName_U);


	if(*oraddress && address_item)
		proto_item_append_text(address_item, " (%s/)", oraddress);

	doing_address = FALSE;



  return offset;
}



static int
dissect_x411_ORAddressAndOptionalDirectoryName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_ORName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_MTAOriginatorName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
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
dissect_x411_BuiltInEncodedInformationTypes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    BuiltInEncodedInformationTypes_bits, hf_index, ett_x411_BuiltInEncodedInformationTypes,
                                    NULL);

  return offset;
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
dissect_x411_G3FacsimileNonBasicParameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    G3FacsimileNonBasicParameters_bits, hf_index, ett_x411_G3FacsimileNonBasicParameters,
                                    NULL);

  return offset;
}



static int
dissect_x411_TeletexString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x411_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t TeletexNonBasicParameters_set[] = {
  { &hf_x411_graphic_character_sets, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_TeletexString },
  { &hf_x411_control_character_sets, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_TeletexString },
  { &hf_x411_page_formats   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_OCTET_STRING },
  { &hf_x411_miscellaneous_terminal_capabilities, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_TeletexString },
  { &hf_x411_private_use    , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x411_TeletexNonBasicParameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              TeletexNonBasicParameters_set, hf_index, ett_x411_TeletexNonBasicParameters);

  return offset;
}



static int
dissect_x411_ExtendedEncodedInformationType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t ExtendedEncodedInformationTypes_set_of[1] = {
  { &hf_x411_ExtendedEncodedInformationTypes_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x411_ExtendedEncodedInformationType },
};

static int
dissect_x411_ExtendedEncodedInformationTypes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 ExtendedEncodedInformationTypes_set_of, hf_index, ett_x411_ExtendedEncodedInformationTypes);

  return offset;
}


static const ber_sequence_t EncodedInformationTypes_U_set[] = {
  { &hf_x411_built_in_encoded_information_types, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_BuiltInEncodedInformationTypes },
  { &hf_x411_g3_facsimile   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_G3FacsimileNonBasicParameters },
  { &hf_x411_teletex        , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_TeletexNonBasicParameters },
  { &hf_x411_extended_encoded_information_types, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ExtendedEncodedInformationTypes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_EncodedInformationTypes_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              EncodedInformationTypes_U_set, hf_index, ett_x411_EncodedInformationTypes_U);

  return offset;
}



int
dissect_x411_EncodedInformationTypes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 5, TRUE, dissect_x411_EncodedInformationTypes_U);

  return offset;
}



int
dissect_x411_OriginalEncodedInformationTypes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_EncodedInformationTypes(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string x411_BuiltInContentType_U_vals[] = {
  {   0, "unidentified" },
  {   1, "external" },
  {   2, "interpersonal-messaging-1984" },
  {  22, "interpersonal-messaging-1988" },
  {  35, "edi-messaging" },
  {  40, "voice-messaging" },
  { 0, NULL }
};


static int
dissect_x411_BuiltInContentType_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 592 "x411.cnf"
  static guint32	ict = -1;	

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
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
	content_type_id = NULL;
	break;
	}



  return offset;
}



static int
dissect_x411_BuiltInContentType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 6, TRUE, dissect_x411_BuiltInContentType_U);

  return offset;
}



int
dissect_x411_ExtendedContentType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 577 "x411.cnf"
	const char *name = NULL;

	  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &content_type_id);


	if(content_type_id) {
	  name = oid_resolved_from_string(content_type_id);

  	  if(!name) name = content_type_id;

	  proto_item_append_text(tree, " (%s)", name);
	}



  return offset;
}


const value_string x411_ContentType_vals[] = {
  {   0, "built-in" },
  {   1, "extended" },
  { 0, NULL }
};

static const ber_choice_t ContentType_choice[] = {
  {   0, &hf_x411_built_in       , BER_CLASS_APP, 6, BER_FLAGS_NOOWNTAG, dissect_x411_BuiltInContentType },
  {   1, &hf_x411_extended       , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x411_ExtendedContentType },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_x411_ContentType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ContentType_choice, hf_index, ett_x411_ContentType,
                                 NULL);

  return offset;
}



static int
dissect_x411_PrintableString_SIZE_1_ub_content_id_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



int
dissect_x411_ContentIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 10, TRUE, dissect_x411_PrintableString_SIZE_1_ub_content_id_length);

  return offset;
}


static const value_string x411_Priority_U_vals[] = {
  {   0, "normal" },
  {   1, "non-urgent" },
  {   2, "urgent" },
  { 0, NULL }
};


static int
dissect_x411_Priority_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_x411_Priority(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 7, TRUE, dissect_x411_Priority_U);

  return offset;
}


static const asn_namedbit PerMessageIndicators_U_bits[] = {
  {  0, &hf_x411_PerMessageIndicators_U_disclosure_of_other_recipients, -1, -1, "disclosure-of-other-recipients", NULL },
  {  1, &hf_x411_PerMessageIndicators_U_implicit_conversion_prohibited, -1, -1, "implicit-conversion-prohibited", NULL },
  {  2, &hf_x411_PerMessageIndicators_U_alternate_recipient_allowed, -1, -1, "alternate-recipient-allowed", NULL },
  {  3, &hf_x411_PerMessageIndicators_U_content_return_request, -1, -1, "content-return-request", NULL },
  {  4, &hf_x411_PerMessageIndicators_U_reserved, -1, -1, "reserved", NULL },
  {  5, &hf_x411_PerMessageIndicators_U_bit_5, -1, -1, "bit-5", NULL },
  {  6, &hf_x411_PerMessageIndicators_U_bit_6, -1, -1, "bit-6", NULL },
  {  7, &hf_x411_PerMessageIndicators_U_service_message, -1, -1, "service-message", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x411_PerMessageIndicators_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    PerMessageIndicators_U_bits, hf_index, ett_x411_PerMessageIndicators_U,
                                    NULL);

  return offset;
}



int
dissect_x411_PerMessageIndicators(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 8, TRUE, dissect_x411_PerMessageIndicators_U);

  return offset;
}



static int
dissect_x411_Time(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 963 "x411.cnf"
	tvbuff_t *arrival = NULL;

	  offset = dissect_ber_UTCTime(implicit_tag, actx, tree, tvb, offset, hf_index);


	if(arrival && doing_address)
		proto_item_append_text(address_item, " %s", tvb_format_text(arrival, 0, tvb_length(arrival)));



  return offset;
}



static int
dissect_x411_DeferredDeliveryTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_Time(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t T_private_domain_sequence[] = {
  { &hf_x411_administration_domain_name, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_AdministrationDomainName },
  { &hf_x411_private_domain_identifier, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_PrivateDomainIdentifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_T_private_domain(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_private_domain_sequence, hf_index, ett_x411_T_private_domain);

  return offset;
}


static const value_string x411_T_bilateral_domain_vals[] = {
  {   0, "administration-domain-name" },
  {   1, "private-domain" },
  { 0, NULL }
};

static const ber_choice_t T_bilateral_domain_choice[] = {
  {   0, &hf_x411_administration_domain_name, BER_CLASS_APP, 2, BER_FLAGS_NOOWNTAG, dissect_x411_AdministrationDomainName },
  {   1, &hf_x411_private_domain , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x411_T_private_domain },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_T_bilateral_domain(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_bilateral_domain_choice, hf_index, ett_x411_T_bilateral_domain,
                                 NULL);

  return offset;
}



static int
dissect_x411_T_bilateral_information(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1031 "x411.cnf"
	proto_item *item = NULL;
	int 	    loffset = 0;
	guint32	    len = 0;

	/* work out the length */
	loffset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, NULL, NULL, NULL);
	(void) dissect_ber_length(actx->pinfo, tree, tvb, loffset, &len, NULL);

	/* create some structure so we can tell what this unknown ASN.1 represents */	
	item = proto_tree_add_item(tree, hf_index, tvb, offset, len, FALSE);
	tree = proto_item_add_subtree(item, ett_x411_bilateral_information);

	offset = dissect_unknown_ber(actx->pinfo, tvb, offset, tree);



  return offset;
}


static const ber_sequence_t PerDomainBilateralInformation_sequence[] = {
  { &hf_x411_country_name   , BER_CLASS_APP, 1, BER_FLAGS_NOOWNTAG, dissect_x411_CountryName },
  { &hf_x411_bilateral_domain, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_T_bilateral_domain },
  { &hf_x411_bilateral_information, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_x411_T_bilateral_information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_PerDomainBilateralInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PerDomainBilateralInformation_sequence, hf_index, ett_x411_PerDomainBilateralInformation);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_ub_transfers_OF_PerDomainBilateralInformation_sequence_of[1] = {
  { &hf_x411_per_domain_bilateral_information_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x411_PerDomainBilateralInformation },
};

static int
dissect_x411_SEQUENCE_SIZE_1_ub_transfers_OF_PerDomainBilateralInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_ub_transfers_OF_PerDomainBilateralInformation_sequence_of, hf_index, ett_x411_SEQUENCE_SIZE_1_ub_transfers_OF_PerDomainBilateralInformation);

  return offset;
}



static int
dissect_x411_ArrivalTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_Time(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string x411_RoutingAction_vals[] = {
  {   0, "relayed" },
  {   1, "rerouted" },
  { 0, NULL }
};


static int
dissect_x411_RoutingAction(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 974 "x411.cnf"
	int action = 0;

	  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  &action);


	proto_item_append_text(address_item, " %s", val_to_str(action, x411_RoutingAction_vals, "action(%d)"));



  return offset;
}



static int
dissect_x411_DeferredTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_Time(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_ConvertedEncodedInformationTypes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_EncodedInformationTypes(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const asn_namedbit OtherActions_bits[] = {
  {  0, &hf_x411_OtherActions_redirected, -1, -1, "redirected", NULL },
  {  1, &hf_x411_OtherActions_dl_operation, -1, -1, "dl-operation", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x411_OtherActions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    OtherActions_bits, hf_index, ett_x411_OtherActions,
                                    NULL);

  return offset;
}


static const ber_sequence_t DomainSuppliedInformation_set[] = {
  { &hf_x411_arrival_time   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_ArrivalTime },
  { &hf_x411_routing_action , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_x411_RoutingAction },
  { &hf_x411_attempted_domain, BER_CLASS_APP, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_GlobalDomainIdentifier },
  { &hf_x411_deferred_time  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_DeferredTime },
  { &hf_x411_converted_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_ConvertedEncodedInformationTypes },
  { &hf_x411_other_actions  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_OtherActions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_DomainSuppliedInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 942 "x411.cnf"

	doing_address = FALSE;

	  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              DomainSuppliedInformation_set, hf_index, ett_x411_DomainSuppliedInformation);


	doing_address = TRUE;
	proto_item_append_text(tree, ")");



  return offset;
}


static const ber_sequence_t TraceInformationElement_sequence[] = {
  { &hf_x411_global_domain_identifier, BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_x411_GlobalDomainIdentifier },
  { &hf_x411_domain_supplied_information, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x411_DomainSuppliedInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_TraceInformationElement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 926 "x411.cnf"

	doing_address = TRUE;

	  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TraceInformationElement_sequence, hf_index, ett_x411_TraceInformationElement);


	doing_address = FALSE;



  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_ub_transfers_OF_TraceInformationElement_sequence_of[1] = {
  { &hf_x411__untag_item    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x411_TraceInformationElement },
};

static int
dissect_x411_SEQUENCE_SIZE_1_ub_transfers_OF_TraceInformationElement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_ub_transfers_OF_TraceInformationElement_sequence_of, hf_index, ett_x411_SEQUENCE_SIZE_1_ub_transfers_OF_TraceInformationElement);

  return offset;
}



static int
dissect_x411_TraceInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 9, TRUE, dissect_x411_SEQUENCE_SIZE_1_ub_transfers_OF_TraceInformationElement);

  return offset;
}


static const value_string x411_StandardExtension_vals[] = {
  {   1, "recipient-reassignment-prohibited" },
  {   2, "originator-requested-alternate-recipient" },
  {   3, "dl-expansion-prohibited" },
  {   4, "conversion-with-loss-prohibited" },
  {   5, "latest-delivery-time" },
  {   6, "requested-delivery-method" },
  {   7, "physical-forwarding-prohibited" },
  {   8, "physical-forwarding-address-request" },
  {   9, "physical-delivery-modes" },
  {  10, "registered-mail-type" },
  {  11, "recipient-number-for-advice" },
  {  12, "physical-rendition-attributes" },
  {  13, "originator-return-address" },
  {  14, "physical-delivery-report-request" },
  {  15, "originator-certificate" },
  {  16, "message-token" },
  {  17, "content-confidentiality-algorithm-identifier" },
  {  18, "content-integrity-check" },
  {  19, "message-origin-authentication-check" },
  {  20, "message-security-label" },
  {  21, "proof-of-submission-request" },
  {  22, "proof-of-delivery-request" },
  {  23, "content-correlator" },
  {  24, "probe-origin-authentication-check" },
  {  25, "redirection-history" },
  {  26, "dl-expansion-history" },
  {  27, "physical-forwarding-address" },
  {  28, "recipient-certificate" },
  {  29, "proof-of-delivery" },
  {  30, "originator-and-DL-expansion-history" },
  {  31, "reporting-DL-name" },
  {  32, "reporting-MTA-certificate" },
  {  33, "report-origin-authentication-check" },
  {  34, "originating-MTA-certificate" },
  {  35, "proof-of-submission" },
  {  36, "forwarding-request" },
  {  37, "trace-information" },
  {  38, "internal-trace-information" },
  {  39, "reporting-MTA-name" },
  {  40, "multiple-originator-certificates" },
  {  41, "blind-copy-recipients" },
  {  42, "dl-exempted-recipients" },
  {  43, "body-part-encryption-token" },
  {  44, "forwarded-content-token" },
  {  45, "certificate-selectors" },
  { 0, NULL }
};


static int
dissect_x411_StandardExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &extension_id);

  return offset;
}



static int
dissect_x411_T_private_extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 569 "x411.cnf"

	  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &object_identifier_id);

	extension_id = -1;



  return offset;
}


static const value_string x411_ExtensionType_vals[] = {
  {   0, "standard-extension" },
  {   3, "private-extension" },
  { 0, NULL }
};

static const ber_choice_t ExtensionType_choice[] = {
  {   0, &hf_x411_standard_extension, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_StandardExtension },
  {   3, &hf_x411_private_extension, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_x411_T_private_extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_ExtensionType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ExtensionType_choice, hf_index, ett_x411_ExtensionType,
                                 NULL);

  return offset;
}


static const asn_namedbit Criticality_bits[] = {
  {  0, &hf_x411_Criticality_for_submission, -1, -1, "for-submission", NULL },
  {  1, &hf_x411_Criticality_for_transfer, -1, -1, "for-transfer", NULL },
  {  2, &hf_x411_Criticality_for_delivery, -1, -1, "for-delivery", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x411_Criticality(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Criticality_bits, hf_index, ett_x411_Criticality,
                                    NULL);

  return offset;
}



static int
dissect_x411_ExtensionValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 501 "x411.cnf"
	const char *name;

	if(extension_id != -1) {
		proto_item_append_text(tree, " (%s)", val_to_str(extension_id, x411_StandardExtension_vals, "standard-extension %d")); 
  		if (dissector_try_port(x411_extension_dissector_table, extension_id, tvb, actx->pinfo, tree)) {
			offset = tvb_length(tvb);
		} else {
			proto_item *item = NULL;
			proto_tree *next_tree = NULL;

			item = proto_tree_add_text(tree, tvb, 0, tvb_length_remaining(tvb, offset), 
				"Dissector for standard-extension %d not implemented.  Contact Wireshark developers if you want this supported", extension_id);
			next_tree = proto_item_add_subtree(item, ett_x411_unknown_standard_extension);
			offset = dissect_unknown_ber(actx->pinfo, tvb, offset, next_tree);
			expert_add_info_format(actx->pinfo, item, PI_UNDECODED, PI_WARN, "Unknown standard-extension");
		}
	} else if (object_identifier_id) {
		call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);
		name = oid_resolved_from_string(object_identifier_id);
		proto_item_append_text(tree, " (%s)", name ? name : object_identifier_id); 
	}
		



  return offset;
}


static const ber_sequence_t ExtensionField_sequence[] = {
  { &hf_x411_extension_type , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_ExtensionType },
  { &hf_x411_criticality    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_Criticality },
  { &hf_x411_extension_value, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ExtensionValue },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x411_ExtensionField(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExtensionField_sequence, hf_index, ett_x411_ExtensionField);

  return offset;
}


static const ber_sequence_t SET_OF_ExtensionField_set_of[1] = {
  { &hf_x411_extensions_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x411_ExtensionField },
};

static int
dissect_x411_SET_OF_ExtensionField(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_ExtensionField_set_of, hf_index, ett_x411_SET_OF_ExtensionField);

  return offset;
}



static int
dissect_x411_MTARecipientName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_OriginallySpecifiedRecipientNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
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
dissect_x411_PerRecipientIndicators(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    PerRecipientIndicators_bits, hf_index, ett_x411_PerRecipientIndicators,
                                    NULL);

  return offset;
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
dissect_x411_ExplicitConversion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t PerRecipientMessageTransferFields_set[] = {
  { &hf_x411_recipient_name , BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_x411_MTARecipientName },
  { &hf_x411_originally_specified_recipient_number, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_OriginallySpecifiedRecipientNumber },
  { &hf_x411_per_recipient_indicators, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x411_PerRecipientIndicators },
  { &hf_x411_explicit_conversion, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ExplicitConversion },
  { &hf_x411_extensions     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_PerRecipientMessageTransferFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              PerRecipientMessageTransferFields_set, hf_index, ett_x411_PerRecipientMessageTransferFields);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageTransferFields_sequence_of[1] = {
  { &hf_x411_per_recipient_message_fields_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x411_PerRecipientMessageTransferFields },
};

static int
dissect_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageTransferFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageTransferFields_sequence_of, hf_index, ett_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageTransferFields);

  return offset;
}


static const ber_sequence_t MessageTransferEnvelope_set[] = {
  { &hf_x411_message_identifier, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_x411_MessageIdentifier },
  { &hf_x411_mta_originator_name, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_x411_MTAOriginatorName },
  { &hf_x411_original_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_OriginalEncodedInformationTypes },
  { &hf_x411_content_type   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_ContentType },
  { &hf_x411_content_identifier, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_ContentIdentifier },
  { &hf_x411_priority       , BER_CLASS_APP, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_Priority },
  { &hf_x411_per_message_indicators, BER_CLASS_APP, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_PerMessageIndicators },
  { &hf_x411_deferred_delivery_time, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_DeferredDeliveryTime },
  { &hf_x411_per_domain_bilateral_information, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SEQUENCE_SIZE_1_ub_transfers_OF_PerDomainBilateralInformation },
  { &hf_x411_trace_information, BER_CLASS_APP, 9, BER_FLAGS_NOOWNTAG, dissect_x411_TraceInformation },
  { &hf_x411_extensions     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { &hf_x411_per_recipient_message_fields, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageTransferFields },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_MessageTransferEnvelope(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              MessageTransferEnvelope_set, hf_index, ett_x411_MessageTransferEnvelope);

  return offset;
}



int
dissect_x411_Content(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 610 "x411.cnf"
  tvbuff_t *next_tvb;

  /* we can do this now constructed octet strings are supported */
  offset = dissect_ber_octet_string(FALSE, actx, NULL, tvb, offset, hf_index, &next_tvb);

  if (next_tvb) {
    if (content_type_id) {
      (void) call_ber_oid_callback(content_type_id, next_tvb, 0, actx->pinfo, top_tree ? top_tree : tree);
    } else {
      proto_item *item = NULL;
      proto_tree *next_tree = NULL;

      item = proto_tree_add_text(top_tree ? top_tree : tree, next_tvb, 0, tvb_length_remaining(tvb, offset), "X.411 Unknown Content (unknown built-in content-type)");
      expert_add_info_format(actx->pinfo, item, PI_UNDECODED, PI_WARN, "Unknown built-in content-type");
      if (item) {
        next_tree=proto_item_add_subtree(item, ett_x411_content_unknown);
      }
      dissect_unknown_ber(actx->pinfo, next_tvb, 0, next_tree);
    }
  }



  return offset;
}


static const ber_sequence_t Message_sequence[] = {
  { &hf_x411_message_envelope, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x411_MessageTransferEnvelope },
  { &hf_x411_content        , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_x411_Content },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_Message(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Message_sequence, hf_index, ett_x411_Message);

  return offset;
}



static int
dissect_x411_ProbeIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_MTSIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_x411_ContentLength(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t PerRecipientProbeTransferFields_set[] = {
  { &hf_x411_recipient_name , BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_x411_MTARecipientName },
  { &hf_x411_originally_specified_recipient_number, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_OriginallySpecifiedRecipientNumber },
  { &hf_x411_per_recipient_indicators, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x411_PerRecipientIndicators },
  { &hf_x411_explicit_conversion, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ExplicitConversion },
  { &hf_x411_extensions     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_PerRecipientProbeTransferFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              PerRecipientProbeTransferFields_set, hf_index, ett_x411_PerRecipientProbeTransferFields);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeTransferFields_sequence_of[1] = {
  { &hf_x411_per_recipient_probe_transfer_fields_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x411_PerRecipientProbeTransferFields },
};

static int
dissect_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeTransferFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeTransferFields_sequence_of, hf_index, ett_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeTransferFields);

  return offset;
}


static const ber_sequence_t ProbeTransferEnvelope_set[] = {
  { &hf_x411_probe_identifier, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_x411_ProbeIdentifier },
  { &hf_x411_mta_originator_name, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_x411_MTAOriginatorName },
  { &hf_x411_original_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_OriginalEncodedInformationTypes },
  { &hf_x411_content_type   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_ContentType },
  { &hf_x411_content_identifier, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_ContentIdentifier },
  { &hf_x411_content_length , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ContentLength },
  { &hf_x411_per_message_indicators, BER_CLASS_APP, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_PerMessageIndicators },
  { &hf_x411_per_domain_bilateral_information, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SEQUENCE_SIZE_1_ub_transfers_OF_PerDomainBilateralInformation },
  { &hf_x411_trace_information, BER_CLASS_APP, 9, BER_FLAGS_NOOWNTAG, dissect_x411_TraceInformation },
  { &hf_x411_extensions     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { &hf_x411_per_recipient_probe_transfer_fields, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeTransferFields },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_ProbeTransferEnvelope(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ProbeTransferEnvelope_set, hf_index, ett_x411_ProbeTransferEnvelope);

  return offset;
}



static int
dissect_x411_Probe(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_ProbeTransferEnvelope(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_ReportIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_MTSIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_ReportDestinationName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t ReportTransferEnvelope_set[] = {
  { &hf_x411_report_identifier, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_x411_ReportIdentifier },
  { &hf_x411_report_destination_name, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_x411_ReportDestinationName },
  { &hf_x411_trace_information, BER_CLASS_APP, 9, BER_FLAGS_NOOWNTAG, dissect_x411_TraceInformation },
  { &hf_x411_extensions     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_ReportTransferEnvelope(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ReportTransferEnvelope_set, hf_index, ett_x411_ReportTransferEnvelope);

  return offset;
}



static int
dissect_x411_MessageOrProbeIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_MTSIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_SubjectIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_MessageOrProbeIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_SubjectIntermediateTraceInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_TraceInformation(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_AdditionalInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 483 "x411.cnf"
   proto_item *item = NULL;
   int         loffset = 0;
   guint32     len = 0;

   /* work out the length */
   loffset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, NULL, NULL, NULL);
   (void) dissect_ber_length(actx->pinfo, tree, tvb, loffset, &len, NULL);

   item = proto_tree_add_item(tree, hf_index, tvb, offset, len, FALSE);
   tree = proto_item_add_subtree(item, ett_x411_additional_information);
   proto_item_append_text(tree, " (The use of this field is \"strongly deprecated\".)"); 

   offset = dissect_unknown_ber(actx->pinfo, tvb, offset, tree);



  return offset;
}



static int
dissect_x411_MTAActualRecipientName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_x411_MessageDeliveryTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_Time(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
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
dissect_x411_TypeOfMTSUser(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t DeliveryReport_set[] = {
  { &hf_x411_message_delivery_time, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_MessageDeliveryTime },
  { &hf_x411_type_of_MTS_user, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_TypeOfMTSUser },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_DeliveryReport(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              DeliveryReport_set, hf_index, ett_x411_DeliveryReport);

  return offset;
}


const value_string x411_NonDeliveryReasonCode_vals[] = {
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


int
dissect_x411_NonDeliveryReasonCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


const value_string x411_NonDeliveryDiagnosticCode_vals[] = {
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


int
dissect_x411_NonDeliveryDiagnosticCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t NonDeliveryReport_set[] = {
  { &hf_x411_non_delivery_reason_code, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_NonDeliveryReasonCode },
  { &hf_x411_non_delivery_diagnostic_code, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_NonDeliveryDiagnosticCode },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_NonDeliveryReport(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              NonDeliveryReport_set, hf_index, ett_x411_NonDeliveryReport);

  return offset;
}


static const value_string x411_ReportType_vals[] = {
  {   0, "delivery" },
  {   1, "non-delivery" },
  { 0, NULL }
};

static const ber_choice_t ReportType_choice[] = {
  {   0, &hf_x411_delivery       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_DeliveryReport },
  {   1, &hf_x411_non_delivery   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x411_NonDeliveryReport },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_ReportType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1063 "x411.cnf"
	gint report = -1;

  	  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ReportType_choice, hf_index, ett_x411_ReportType,
                                 &report);

	
        if( (report!=-1) && x411_ReportType_vals[report].strptr ){
		if(check_col(actx->pinfo->cinfo, COL_INFO)) {
			col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", x411_ReportType_vals[report].strptr);
		}
	}



  return offset;
}


static const ber_sequence_t LastTraceInformation_set[] = {
  { &hf_x411_arrival_time   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_ArrivalTime },
  { &hf_x411_converted_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_ConvertedEncodedInformationTypes },
  { &hf_x411_trace_report_type, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_ReportType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_LastTraceInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              LastTraceInformation_set, hf_index, ett_x411_LastTraceInformation);

  return offset;
}



static int
dissect_x411_OriginallyIntendedRecipientName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_x411_SupplementaryInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t PerRecipientReportTransferFields_set[] = {
  { &hf_x411_mta_actual_recipient_name, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_MTAActualRecipientName },
  { &hf_x411_originally_specified_recipient_number, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x411_OriginallySpecifiedRecipientNumber },
  { &hf_x411_per_recipient_indicators, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_x411_PerRecipientIndicators },
  { &hf_x411_last_trace_information, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_x411_LastTraceInformation },
  { &hf_x411_report_originally_intended_recipient_name, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_OriginallyIntendedRecipientName },
  { &hf_x411_supplementary_information, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SupplementaryInformation },
  { &hf_x411_extensions     , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_PerRecipientReportTransferFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              PerRecipientReportTransferFields_set, hf_index, ett_x411_PerRecipientReportTransferFields);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportTransferFields_sequence_of[1] = {
  { &hf_x411_per_recipient_report_fields_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x411_PerRecipientReportTransferFields },
};

static int
dissect_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportTransferFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportTransferFields_sequence_of, hf_index, ett_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportTransferFields);

  return offset;
}


static const ber_sequence_t ReportTransferContent_set[] = {
  { &hf_x411_subject_identifier, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_x411_SubjectIdentifier },
  { &hf_x411_subject_intermediate_trace_information, BER_CLASS_APP, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_SubjectIntermediateTraceInformation },
  { &hf_x411_original_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_OriginalEncodedInformationTypes },
  { &hf_x411_content_type   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_ContentType },
  { &hf_x411_content_identifier, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_ContentIdentifier },
  { &hf_x411_returned_content, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_Content },
  { &hf_x411_additional_information, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_AdditionalInformation },
  { &hf_x411_extensions     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { &hf_x411_per_recipient_report_fields, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportTransferFields },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_ReportTransferContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ReportTransferContent_set, hf_index, ett_x411_ReportTransferContent);

  return offset;
}


static const ber_sequence_t Report_sequence[] = {
  { &hf_x411_report_envelope, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x411_ReportTransferEnvelope },
  { &hf_x411_report_content , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x411_ReportTransferContent },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_Report(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Report_sequence, hf_index, ett_x411_Report);

  return offset;
}


static const value_string x411_MTS_APDU_vals[] = {
  {   0, "message" },
  {   2, "probe" },
  {   1, "report" },
  { 0, NULL }
};

static const ber_choice_t MTS_APDU_choice[] = {
  {   0, &hf_x411_message        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_Message },
  {   2, &hf_x411_probe          , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_x411_Probe },
  {   1, &hf_x411_report         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x411_Report },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_MTS_APDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1049 "x411.cnf"
	gint apdu = -1;

  	  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 MTS_APDU_choice, hf_index, ett_x411_MTS_APDU,
                                 &apdu);

	
	if( (apdu!=-1) && x411_MTS_APDU_vals[apdu].strptr ){
		if(check_col(actx->pinfo->cinfo, COL_INFO) && (apdu != 0)) { /* we don't show "message" - sub-dissectors have better idea */
			col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", x411_MTS_APDU_vals[apdu].strptr);
		}
	}



  return offset;
}


static const ber_sequence_t PerMessageTransferFields_set[] = {
  { &hf_x411_message_identifier, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_x411_MessageIdentifier },
  { &hf_x411_originator_name, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_x411_MTAOriginatorName },
  { &hf_x411_original_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_OriginalEncodedInformationTypes },
  { &hf_x411_content_type   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_ContentType },
  { &hf_x411_content_identifier, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_ContentIdentifier },
  { &hf_x411_priority       , BER_CLASS_APP, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_Priority },
  { &hf_x411_per_message_indicators, BER_CLASS_APP, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_PerMessageIndicators },
  { &hf_x411_deferred_delivery_time, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_DeferredDeliveryTime },
  { &hf_x411_per_domain_bilateral_information, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SEQUENCE_SIZE_1_ub_transfers_OF_PerDomainBilateralInformation },
  { &hf_x411_trace_information, BER_CLASS_APP, 9, BER_FLAGS_NOOWNTAG, dissect_x411_TraceInformation },
  { &hf_x411_extensions     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_PerMessageTransferFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              PerMessageTransferFields_set, hf_index, ett_x411_PerMessageTransferFields);

  return offset;
}


static const ber_sequence_t PerProbeTransferFields_set[] = {
  { &hf_x411_probe_identifier, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_x411_ProbeIdentifier },
  { &hf_x411_originator_name, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_x411_MTAOriginatorName },
  { &hf_x411_original_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_OriginalEncodedInformationTypes },
  { &hf_x411_content_type   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_ContentType },
  { &hf_x411_content_identifier, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_ContentIdentifier },
  { &hf_x411_content_length , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ContentLength },
  { &hf_x411_per_message_indicators, BER_CLASS_APP, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_PerMessageIndicators },
  { &hf_x411_per_domain_bilateral_information, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SEQUENCE_SIZE_1_ub_transfers_OF_PerDomainBilateralInformation },
  { &hf_x411_trace_information, BER_CLASS_APP, 9, BER_FLAGS_NOOWNTAG, dissect_x411_TraceInformation },
  { &hf_x411_extensions     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_PerProbeTransferFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              PerProbeTransferFields_set, hf_index, ett_x411_PerProbeTransferFields);

  return offset;
}


static const ber_sequence_t PerReportTransferFields_set[] = {
  { &hf_x411_subject_identifier, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_x411_SubjectIdentifier },
  { &hf_x411_subject_intermediate_trace_information, BER_CLASS_APP, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_SubjectIntermediateTraceInformation },
  { &hf_x411_original_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_OriginalEncodedInformationTypes },
  { &hf_x411_content_type   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_ContentType },
  { &hf_x411_content_identifier, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_ContentIdentifier },
  { &hf_x411_returned_content, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_Content },
  { &hf_x411_additional_information, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_AdditionalInformation },
  { &hf_x411_extensions     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_PerReportTransferFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              PerReportTransferFields_set, hf_index, ett_x411_PerReportTransferFields);

  return offset;
}


static const ber_sequence_t T_private_domain_01_sequence[] = {
  { &hf_x411_administration_domain_name, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_AdministrationDomainName },
  { &hf_x411_private_domain_identifier, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_PrivateDomainIdentifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_T_private_domain_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_private_domain_01_sequence, hf_index, ett_x411_T_private_domain_01);

  return offset;
}


static const value_string x411_T_domain_vals[] = {
  {   0, "administration-domain-name" },
  {   1, "private-domain" },
  { 0, NULL }
};

static const ber_choice_t T_domain_choice[] = {
  {   0, &hf_x411_administration_domain_name, BER_CLASS_APP, 2, BER_FLAGS_NOOWNTAG, dissect_x411_AdministrationDomainName },
  {   1, &hf_x411_private_domain_01, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x411_T_private_domain_01 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_T_domain(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_domain_choice, hf_index, ett_x411_T_domain,
                                 NULL);

  return offset;
}


static const ber_sequence_t BilateralDomain_sequence[] = {
  { &hf_x411_country_name   , BER_CLASS_APP, 1, BER_FLAGS_NOOWNTAG, dissect_x411_CountryName },
  { &hf_x411_domain         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_T_domain },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_BilateralDomain(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BilateralDomain_sequence, hf_index, ett_x411_BilateralDomain);

  return offset;
}


static const value_string x411_T_attempted_vals[] = {
  {   0, "mta" },
  {   1, "domain" },
  { 0, NULL }
};

static const ber_choice_t T_attempted_choice[] = {
  {   0, &hf_x411_mta            , BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_x411_MTAName },
  {   1, &hf_x411_domain_01      , BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_x411_GlobalDomainIdentifier },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_T_attempted(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_attempted_choice, hf_index, ett_x411_T_attempted,
                                 NULL);

  return offset;
}


static const ber_sequence_t MTASuppliedInformation_set[] = {
  { &hf_x411_arrival_time   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_ArrivalTime },
  { &hf_x411_routing_action , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_x411_RoutingAction },
  { &hf_x411_attempted      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_T_attempted },
  { &hf_x411_deferred_time  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_DeferredTime },
  { &hf_x411_converted_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_ConvertedEncodedInformationTypes },
  { &hf_x411_other_actions  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_OtherActions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_MTASuppliedInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 951 "x411.cnf"

	doing_address = FALSE;

	  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              MTASuppliedInformation_set, hf_index, ett_x411_MTASuppliedInformation);


	doing_address = TRUE;
	proto_item_append_text(tree, ")");



  return offset;
}


static const ber_sequence_t InternalTraceInformationElement_sequence[] = {
  { &hf_x411_global_domain_identifier, BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_x411_GlobalDomainIdentifier },
  { &hf_x411_mta_name       , BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_x411_MTAName },
  { &hf_x411_mta_supplied_information, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x411_MTASuppliedInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_InternalTraceInformationElement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 934 "x411.cnf"

	doing_address = TRUE;

	  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InternalTraceInformationElement_sequence, hf_index, ett_x411_InternalTraceInformationElement);


	doing_address = FALSE;



  return offset;
}


static const ber_sequence_t InternalTraceInformation_sequence_of[1] = {
  { &hf_x411_InternalTraceInformation_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x411_InternalTraceInformationElement },
};

static int
dissect_x411_InternalTraceInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      InternalTraceInformation_sequence_of, hf_index, ett_x411_InternalTraceInformation);

  return offset;
}


static const ber_sequence_t AdditionalActions_set[] = {
  { &hf_x411_deferred_time  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_DeferredTime },
  { &hf_x411_converted_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_ConvertedEncodedInformationTypes },
  { &hf_x411_other_actions  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_OtherActions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_AdditionalActions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              AdditionalActions_set, hf_index, ett_x411_AdditionalActions);

  return offset;
}



static int
dissect_x411_InternalAdditionalActions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_AdditionalActions(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string x411_ObjectName_vals[] = {
  {   0, "user-agent" },
  {   1, "mTA" },
  {   2, "message-store" },
  { 0, NULL }
};

static const ber_choice_t ObjectName_choice[] = {
  {   0, &hf_x411_user_agent     , BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_x411_ORAddressAndOptionalDirectoryName },
  {   1, &hf_x411_mTA            , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_MTAName },
  {   2, &hf_x411_message_store  , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_x411_ORAddressAndOptionalDirectoryName },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_ObjectName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ObjectName_choice, hf_index, ett_x411_ObjectName,
                                 NULL);

  return offset;
}



static int
dissect_x411_INTEGER_0_ub_queue_size(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_x411_INTEGER_0_ub_content_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t DeliveryQueue_set[] = {
  { &hf_x411_messages       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_INTEGER_0_ub_queue_size },
  { &hf_x411_delivery_queue_octets, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_INTEGER_0_ub_content_length },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_DeliveryQueue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              DeliveryQueue_set, hf_index, ett_x411_DeliveryQueue);

  return offset;
}


static const ber_sequence_t MessagesWaiting_set[] = {
  { &hf_x411_urgent         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_DeliveryQueue },
  { &hf_x411_normal         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x411_DeliveryQueue },
  { &hf_x411_non_urgent     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_x411_DeliveryQueue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_MessagesWaiting(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              MessagesWaiting_set, hf_index, ett_x411_MessagesWaiting);

  return offset;
}


static const ber_sequence_t MTSBindArgument_set[] = {
  { &hf_x411_initiator_name , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_ObjectName },
  { &hf_x411_messages_waiting, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_x411_MessagesWaiting },
  { &hf_x411_initiator_credentials, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_InitiatorCredentials },
  { &hf_x411_security_context, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SecurityContext },
  { &hf_x411_extensions     , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_MTSBindArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              MTSBindArgument_set, hf_index, ett_x411_MTSBindArgument);

  return offset;
}


static const ber_sequence_t MTSBindResult_set[] = {
  { &hf_x411_responder_name , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_ObjectName },
  { &hf_x411_messages_waiting, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_x411_MessagesWaiting },
  { &hf_x411_responder_credentials, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_ResponderCredentials },
  { &hf_x411_extensions     , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_MTSBindResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              MTSBindResult_set, hf_index, ett_x411_MTSBindResult);

  return offset;
}


static const value_string x411_PAR_mts_bind_error_vals[] = {
  {   0, "busy" },
  {   2, "authentication-error" },
  {   3, "unacceptable-dialogue-mode" },
  {   4, "unacceptable-security-context" },
  {   5, "inadequate-association-confidentiality" },
  { 0, NULL }
};


static int
dissect_x411_PAR_mts_bind_error(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



int
dissect_x411_ORAddressAndOrDirectoryName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_ORName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_x411_OriginatorName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOrDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_RecipientName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOrDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const asn_namedbit OriginatorReportRequest_bits[] = {
  {  3, &hf_x411_OriginatorReportRequest_report, -1, -1, "report", NULL },
  {  4, &hf_x411_OriginatorReportRequest_non_delivery_report, -1, -1, "non-delivery-report", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x411_OriginatorReportRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    OriginatorReportRequest_bits, hf_index, ett_x411_OriginatorReportRequest,
                                    NULL);

  return offset;
}


static const ber_sequence_t PerRecipientMessageSubmissionFields_set[] = {
  { &hf_x411_submission_recipient_name, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_x411_RecipientName },
  { &hf_x411_originator_report_request, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_OriginatorReportRequest },
  { &hf_x411_explicit_conversion, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ExplicitConversion },
  { &hf_x411_extensions     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_PerRecipientMessageSubmissionFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              PerRecipientMessageSubmissionFields_set, hf_index, ett_x411_PerRecipientMessageSubmissionFields);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageSubmissionFields_sequence_of[1] = {
  { &hf_x411_per_recipient_message_submission_fields_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x411_PerRecipientMessageSubmissionFields },
};

static int
dissect_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageSubmissionFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageSubmissionFields_sequence_of, hf_index, ett_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageSubmissionFields);

  return offset;
}


static const ber_sequence_t MessageSubmissionEnvelope_set[] = {
  { &hf_x411_mts_originator_name, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_x411_OriginatorName },
  { &hf_x411_original_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_OriginalEncodedInformationTypes },
  { &hf_x411_content_type   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_ContentType },
  { &hf_x411_content_identifier, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_ContentIdentifier },
  { &hf_x411_priority       , BER_CLASS_APP, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_Priority },
  { &hf_x411_per_message_indicators, BER_CLASS_APP, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_PerMessageIndicators },
  { &hf_x411_deferred_delivery_time, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_DeferredDeliveryTime },
  { &hf_x411_extensions     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { &hf_x411_per_recipient_message_submission_fields, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageSubmissionFields },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x411_MessageSubmissionEnvelope(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              MessageSubmissionEnvelope_set, hf_index, ett_x411_MessageSubmissionEnvelope);

  return offset;
}


static const ber_sequence_t MessageSubmissionArgument_sequence[] = {
  { &hf_x411_message_submission_envelope, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x411_MessageSubmissionEnvelope },
  { &hf_x411_content        , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_x411_Content },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_MessageSubmissionArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MessageSubmissionArgument_sequence, hf_index, ett_x411_MessageSubmissionArgument);

  return offset;
}



int
dissect_x411_MessageSubmissionIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_MTSIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_x411_MessageSubmissionTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_Time(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t MessageSubmissionResult_set[] = {
  { &hf_x411_message_submission_identifier, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_x411_MessageSubmissionIdentifier },
  { &hf_x411_message_submission_time, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_MessageSubmissionTime },
  { &hf_x411_content_identifier, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_ContentIdentifier },
  { &hf_x411_extensions     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_MessageSubmissionResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              MessageSubmissionResult_set, hf_index, ett_x411_MessageSubmissionResult);

  return offset;
}


static const ber_sequence_t PerRecipientProbeSubmissionFields_set[] = {
  { &hf_x411_probe_recipient_name, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_x411_RecipientName },
  { &hf_x411_originator_report_request, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_OriginatorReportRequest },
  { &hf_x411_explicit_conversion, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ExplicitConversion },
  { &hf_x411_extensions     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x411_PerRecipientProbeSubmissionFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              PerRecipientProbeSubmissionFields_set, hf_index, ett_x411_PerRecipientProbeSubmissionFields);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeSubmissionFields_sequence_of[1] = {
  { &hf_x411_per_recipient_probe_submission_fields_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x411_PerRecipientProbeSubmissionFields },
};

static int
dissect_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeSubmissionFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeSubmissionFields_sequence_of, hf_index, ett_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeSubmissionFields);

  return offset;
}


static const ber_sequence_t ProbeSubmissionEnvelope_set[] = {
  { &hf_x411_mts_originator_name, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_x411_OriginatorName },
  { &hf_x411_original_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_OriginalEncodedInformationTypes },
  { &hf_x411_content_type   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_ContentType },
  { &hf_x411_content_identifier, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_ContentIdentifier },
  { &hf_x411_content_length , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ContentLength },
  { &hf_x411_per_message_indicators, BER_CLASS_APP, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_PerMessageIndicators },
  { &hf_x411_extensions     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { &hf_x411_per_recipient_probe_submission_fields, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeSubmissionFields },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x411_ProbeSubmissionEnvelope(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ProbeSubmissionEnvelope_set, hf_index, ett_x411_ProbeSubmissionEnvelope);

  return offset;
}



static int
dissect_x411_ProbeSubmissionArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_ProbeSubmissionEnvelope(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_x411_ProbeSubmissionIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_MTSIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_x411_ProbeSubmissionTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_Time(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t ProbeSubmissionResult_set[] = {
  { &hf_x411_probe_submission_identifier, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_x411_ProbeSubmissionIdentifier },
  { &hf_x411_probe_submission_time, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_ProbeSubmissionTime },
  { &hf_x411_content_identifier, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_ContentIdentifier },
  { &hf_x411_extensions     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_ProbeSubmissionResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ProbeSubmissionResult_set, hf_index, ett_x411_ProbeSubmissionResult);

  return offset;
}



static int
dissect_x411_CancelDeferredDeliveryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_MessageSubmissionIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_CancelDeferredDeliveryResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_x411_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const asn_namedbit Operations_bits[] = {
  {  0, &hf_x411_Operations_probe_submission_or_report_delivery, -1, -1, "probe-submission-or-report-delivery", NULL },
  {  1, &hf_x411_Operations_message_submission_or_message_delivery, -1, -1, "message-submission-or-message-delivery", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x411_Operations(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Operations_bits, hf_index, ett_x411_Operations,
                                    NULL);

  return offset;
}


static const ber_sequence_t ContentTypes_set_of[1] = {
  { &hf_x411_ContentTypes_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_ContentType },
};

static int
dissect_x411_ContentTypes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 ContentTypes_set_of, hf_index, ett_x411_ContentTypes);

  return offset;
}


static const ber_sequence_t EncodedInformationTypesConstraints_sequence[] = {
  { &hf_x411_unacceptable_eits, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ExtendedEncodedInformationTypes },
  { &hf_x411_acceptable_eits, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ExtendedEncodedInformationTypes },
  { &hf_x411_exclusively_acceptable_eits, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ExtendedEncodedInformationTypes },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x411_EncodedInformationTypesConstraints(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncodedInformationTypesConstraints_sequence, hf_index, ett_x411_EncodedInformationTypesConstraints);

  return offset;
}



static int
dissect_x411_PermissibleEncodedInformationTypes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_EncodedInformationTypesConstraints(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t Controls_set[] = {
  { &hf_x411_restrict       , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_BOOLEAN },
  { &hf_x411_permissible_operations, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_Operations },
  { &hf_x411_permissible_maximum_content_length, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ContentLength },
  { &hf_x411_permissible_lowest_priority, BER_CLASS_APP, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_Priority },
  { &hf_x411_permissible_content_types, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ContentTypes },
  { &hf_x411_permissible_encoded_information_types, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_PermissibleEncodedInformationTypes },
  { &hf_x411_permissible_security_context, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SecurityContext },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_Controls(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              Controls_set, hf_index, ett_x411_Controls);

  return offset;
}



static int
dissect_x411_SubmissionControls(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_Controls(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_SubmissionControlArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_SubmissionControls(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const asn_namedbit WaitingMessages_bits[] = {
  {  0, &hf_x411_WaitingMessages_long_content, -1, -1, "long-content", NULL },
  {  1, &hf_x411_WaitingMessages_low_priority, -1, -1, "low-priority", NULL },
  {  2, &hf_x411_WaitingMessages_other_security_labels, -1, -1, "other-security-labels", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x411_WaitingMessages(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    WaitingMessages_bits, hf_index, ett_x411_WaitingMessages,
                                    NULL);

  return offset;
}


static const ber_sequence_t SET_SIZE_0_ub_content_types_OF_ContentType_set_of[1] = {
  { &hf_x411_waiting_content_types_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_ContentType },
};

static int
dissect_x411_SET_SIZE_0_ub_content_types_OF_ContentType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_SIZE_0_ub_content_types_OF_ContentType_set_of, hf_index, ett_x411_SET_SIZE_0_ub_content_types_OF_ContentType);

  return offset;
}


static const ber_sequence_t Waiting_set[] = {
  { &hf_x411_waiting_operations, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_Operations },
  { &hf_x411_waiting_messages, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_WaitingMessages },
  { &hf_x411_waiting_content_types, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_SIZE_0_ub_content_types_OF_ContentType },
  { &hf_x411_waiting_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_EncodedInformationTypes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_Waiting(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              Waiting_set, hf_index, ett_x411_Waiting);

  return offset;
}



static int
dissect_x411_SubmissionControlResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_Waiting(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_PAR_submission_control_violated(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_x411_PAR_element_of_service_not_subscribed(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_x411_PAR_deferred_delivery_cancellation_rejected(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_x411_PAR_originator_invalid(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t ImproperlySpecifiedRecipients_sequence_of[1] = {
  { &hf_x411_ImproperlySpecifiedRecipients_item, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_x411_RecipientName },
};

int
dissect_x411_ImproperlySpecifiedRecipients(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      ImproperlySpecifiedRecipients_sequence_of, hf_index, ett_x411_ImproperlySpecifiedRecipients);

  return offset;
}



static int
dissect_x411_PAR_message_submission_identifier_invalid(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_x411_PAR_inconsistent_request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


const value_string x411_SecurityProblem_vals[] = {
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


int
dissect_x411_SecurityProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_x411_PAR_unsupported_critical_function(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_x411_PAR_remote_bind_error(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



int
dissect_x411_MessageDeliveryIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_MTSIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string x411_DeliveredContentType_vals[] = {
  {   0, "built-in" },
  {   1, "extended" },
  { 0, NULL }
};

static const ber_choice_t DeliveredContentType_choice[] = {
  {   0, &hf_x411_built_in       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_BuiltInContentType },
  {   1, &hf_x411_extended       , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x411_ExtendedContentType },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_DeliveredContentType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DeliveredContentType_choice, hf_index, ett_x411_DeliveredContentType,
                                 NULL);

  return offset;
}



static int
dissect_x411_DeliveredOriginatorName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const asn_namedbit DeliveryFlags_bits[] = {
  {  1, &hf_x411_DeliveryFlags_implicit_conversion_prohibited, -1, -1, "implicit-conversion-prohibited", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x411_DeliveryFlags(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    DeliveryFlags_bits, hf_index, ett_x411_DeliveryFlags,
                                    NULL);

  return offset;
}



static int
dissect_x411_OtherRecipientName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t OtherRecipientNames_sequence_of[1] = {
  { &hf_x411_OtherRecipientNames_item, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_x411_OtherRecipientName },
};

static int
dissect_x411_OtherRecipientNames(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      OtherRecipientNames_sequence_of, hf_index, ett_x411_OtherRecipientNames);

  return offset;
}



static int
dissect_x411_ThisRecipientName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t OtherMessageDeliveryFields_set[] = {
  { &hf_x411_delivered_content_type, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_DeliveredContentType },
  { &hf_x411_delivered_originator_name, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_x411_DeliveredOriginatorName },
  { &hf_x411_original_encoded_information_types, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_OriginalEncodedInformationTypes },
  { &hf_x411_priority       , BER_CLASS_APP, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_Priority },
  { &hf_x411_delivery_flags , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_DeliveryFlags },
  { &hf_x411_other_recipient_names, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_OtherRecipientNames },
  { &hf_x411_this_recipient_name, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_x411_ThisRecipientName },
  { &hf_x411_originally_intended_recipient_name, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_OriginallyIntendedRecipientName },
  { &hf_x411_converted_encoded_information_types, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ConvertedEncodedInformationTypes },
  { &hf_x411_message_submission_time, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_x411_MessageSubmissionTime },
  { &hf_x411_content_identifier, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ContentIdentifier },
  { &hf_x411_extensions     , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x411_OtherMessageDeliveryFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              OtherMessageDeliveryFields_set, hf_index, ett_x411_OtherMessageDeliveryFields);

  return offset;
}


static const ber_sequence_t MessageDeliveryArgument_sequence[] = {
  { &hf_x411_message_delivery_identifier, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_x411_MessageDeliveryIdentifier },
  { &hf_x411_message_delivery_time, BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_x411_MessageDeliveryTime },
  { &hf_x411_other_fields   , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x411_OtherMessageDeliveryFields },
  { &hf_x411_content        , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_x411_Content },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_MessageDeliveryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MessageDeliveryArgument_sequence, hf_index, ett_x411_MessageDeliveryArgument);

  return offset;
}



static int
dissect_x411_RecipientCertificate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_Certificates(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_ProofOfDelivery(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_Signature(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t MessageDeliveryResult_set[] = {
  { &hf_x411_recipient_certificate, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_RecipientCertificate },
  { &hf_x411_proof_of_delivery, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ProofOfDelivery },
  { &hf_x411_extensions     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_MessageDeliveryResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              MessageDeliveryResult_set, hf_index, ett_x411_MessageDeliveryResult);

  return offset;
}



static int
dissect_x411_SubjectSubmissionIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_MTSIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_ActualRecipientName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOrDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t PerRecipientReportDeliveryFields_set[] = {
  { &hf_x411_actual_recipient_name, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_ActualRecipientName },
  { &hf_x411_delivery_report_type, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_ReportType },
  { &hf_x411_converted_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_ConvertedEncodedInformationTypes },
  { &hf_x411_originally_intended_recipient_name, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_OriginallyIntendedRecipientName },
  { &hf_x411_supplementary_information, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SupplementaryInformation },
  { &hf_x411_extensions     , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_PerRecipientReportDeliveryFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              PerRecipientReportDeliveryFields_set, hf_index, ett_x411_PerRecipientReportDeliveryFields);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportDeliveryFields_sequence_of[1] = {
  { &hf_x411_per_recipient_report_delivery_fields_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x411_PerRecipientReportDeliveryFields },
};

static int
dissect_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportDeliveryFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportDeliveryFields_sequence_of, hf_index, ett_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportDeliveryFields);

  return offset;
}


static const ber_sequence_t ReportDeliveryArgument_set[] = {
  { &hf_x411_subject_submission_identifier, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_x411_SubjectSubmissionIdentifier },
  { &hf_x411_content_identifier, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_ContentIdentifier },
  { &hf_x411_content_type   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_ContentType },
  { &hf_x411_original_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_OriginalEncodedInformationTypes },
  { &hf_x411_extensions     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { &hf_x411_per_recipient_report_delivery_fields, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportDeliveryFields },
  { &hf_x411_returned_content, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_Content },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_ReportDeliveryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ReportDeliveryArgument_set, hf_index, ett_x411_ReportDeliveryArgument);

  return offset;
}


static const ber_sequence_t SET_SIZE_1_MAX_OF_ExtensionField_set_of[1] = {
  { &hf_x411_max_extensions_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x411_ExtensionField },
};

static int
dissect_x411_SET_SIZE_1_MAX_OF_ExtensionField(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_SIZE_1_MAX_OF_ExtensionField_set_of, hf_index, ett_x411_SET_SIZE_1_MAX_OF_ExtensionField);

  return offset;
}


static const value_string x411_ReportDeliveryResult_vals[] = {
  {   0, "empty-result" },
  {   1, "extensions" },
  { 0, NULL }
};

static const ber_choice_t ReportDeliveryResult_choice[] = {
  {   0, &hf_x411_empty_result   , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_x411_NULL },
  {   1, &hf_x411_max_extensions , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x411_SET_SIZE_1_MAX_OF_ExtensionField },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_ReportDeliveryResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ReportDeliveryResult_choice, hf_index, ett_x411_ReportDeliveryResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t DeliveryControlArgument_set[] = {
  { &hf_x411_restrict       , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_BOOLEAN },
  { &hf_x411_permissible_operations, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_Operations },
  { &hf_x411_permissible_maximum_content_length, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ContentLength },
  { &hf_x411_permissible_lowest_priority, BER_CLASS_APP, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_Priority },
  { &hf_x411_permissible_content_types, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ContentTypes },
  { &hf_x411_permissible_encoded_information_types, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_PermissibleEncodedInformationTypes },
  { &hf_x411_permissible_security_context, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SecurityContext },
  { &hf_x411_extensions     , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_DeliveryControlArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              DeliveryControlArgument_set, hf_index, ett_x411_DeliveryControlArgument);

  return offset;
}


static const ber_sequence_t DeliveryControlResult_set[] = {
  { &hf_x411_waiting_operations, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_Operations },
  { &hf_x411_waiting_messages, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_WaitingMessages },
  { &hf_x411_waiting_content_types, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_SIZE_0_ub_content_types_OF_ContentType },
  { &hf_x411_waiting_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_EncodedInformationTypes },
  { &hf_x411_extensions     , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_DeliveryControlResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              DeliveryControlResult_set, hf_index, ett_x411_DeliveryControlResult);

  return offset;
}



static int
dissect_x411_PAR_delivery_control_violated(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_x411_PAR_control_violates_registration(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

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
dissect_x411_RefusedArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_x411_T_refused_extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 549 "x411.cnf"
/*XXX not implemented yet */



  return offset;
}


static const value_string x411_T_refused_argument_vals[] = {
  {   0, "built-in-argument" },
  {   1, "refused-extension" },
  { 0, NULL }
};

static const ber_choice_t T_refused_argument_choice[] = {
  {   0, &hf_x411_built_in_argument, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x411_RefusedArgument },
  {   1, &hf_x411_refused_extension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_x411_T_refused_extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_T_refused_argument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_refused_argument_choice, hf_index, ett_x411_T_refused_argument,
                                 NULL);

  return offset;
}


static const value_string x411_RefusalReason_vals[] = {
  {   0, "facility-unavailable" },
  {   1, "facility-not-subscribed" },
  {   2, "parameter-unacceptable" },
  { 0, NULL }
};


static int
dissect_x411_RefusalReason(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t RefusedOperation_set[] = {
  { &hf_x411_refused_argument, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_T_refused_argument },
  { &hf_x411_refusal_reason , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_x411_RefusalReason },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_RefusedOperation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              RefusedOperation_set, hf_index, ett_x411_RefusedOperation);

  return offset;
}



static int
dissect_x411_UserName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_PrintableString_SIZE_1_ub_tsap_id_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t T_x121_sequence[] = {
  { &hf_x411_x121_address   , BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_AddrNumericString },
  { &hf_x411_tsap_id        , BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_PrintableString_SIZE_1_ub_tsap_id_length },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_T_x121(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_x121_sequence, hf_index, ett_x411_T_x121);

  return offset;
}



static int
dissect_x411_PSAPAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509sat_PresentationAddress(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string x411_UserAddress_vals[] = {
  {   0, "x121" },
  {   1, "presentation" },
  { 0, NULL }
};

static const ber_choice_t UserAddress_choice[] = {
  {   0, &hf_x411_x121           , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_T_x121 },
  {   1, &hf_x411_presentation   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x411_PSAPAddress },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_UserAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 UserAddress_choice, hf_index, ett_x411_UserAddress,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_Priority_set_of[1] = {
  { &hf_x411_class_priority_item, BER_CLASS_APP, 7, BER_FLAGS_NOOWNTAG, dissect_x411_Priority },
};

static int
dissect_x411_SET_OF_Priority(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_Priority_set_of, hf_index, ett_x411_SET_OF_Priority);

  return offset;
}


static const value_string x411_T_objects_vals[] = {
  {   0, "messages" },
  {   1, "reports" },
  {   2, "both" },
  { 0, NULL }
};


static int
dissect_x411_T_objects(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const asn_namedbit T_source_type_bits[] = {
  {  0, &hf_x411_T_source_type_originated_by, -1, -1, "originated-by", NULL },
  {  1, &hf_x411_T_source_type_redirected_by, -1, -1, "redirected-by", NULL },
  {  2, &hf_x411_T_source_type_dl_expanded_by, -1, -1, "dl-expanded-by", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x411_T_source_type(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_source_type_bits, hf_index, ett_x411_T_source_type,
                                    NULL);

  return offset;
}


static const value_string x411_ExactOrPattern_vals[] = {
  {   0, "exact-match" },
  {   1, "pattern-match" },
  { 0, NULL }
};

static const ber_choice_t ExactOrPattern_choice[] = {
  {   0, &hf_x411_exact_match    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_ORName },
  {   1, &hf_x411_pattern_match  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x411_ORName },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_ExactOrPattern(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ExactOrPattern_choice, hf_index, ett_x411_ExactOrPattern,
                                 NULL);

  return offset;
}


static const ber_sequence_t Restriction_set[] = {
  { &hf_x411_permitted      , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_BOOLEAN },
  { &hf_x411_source_type    , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_T_source_type },
  { &hf_x411_source_name    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_ExactOrPattern },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_Restriction(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              Restriction_set, hf_index, ett_x411_Restriction);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Restriction_sequence_of[1] = {
  { &hf_x411_applies_only_to_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x411_Restriction },
};

static int
dissect_x411_SEQUENCE_OF_Restriction(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Restriction_sequence_of, hf_index, ett_x411_SEQUENCE_OF_Restriction);

  return offset;
}


static const ber_sequence_t MessageClass_set[] = {
  { &hf_x411_content_types  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ContentTypes },
  { &hf_x411_maximum_content_length, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ContentLength },
  { &hf_x411_encoded_information_types_constraints, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_EncodedInformationTypesConstraints },
  { &hf_x411_security_labels, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SecurityContext },
  { &hf_x411_class_priority , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_Priority },
  { &hf_x411_objects        , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_T_objects },
  { &hf_x411_applies_only_to, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SEQUENCE_OF_Restriction },
  { &hf_x411_extensions     , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_MessageClass(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              MessageClass_set, hf_index, ett_x411_MessageClass);

  return offset;
}



static int
dissect_x411_DeliverableClass(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_MessageClass(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t SET_SIZE_1_ub_deliverable_class_OF_DeliverableClass_set_of[1] = {
  { &hf_x411_deliverable_class_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x411_DeliverableClass },
};

static int
dissect_x411_SET_SIZE_1_ub_deliverable_class_OF_DeliverableClass(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_SIZE_1_ub_deliverable_class_OF_DeliverableClass_set_of, hf_index, ett_x411_SET_SIZE_1_ub_deliverable_class_OF_DeliverableClass);

  return offset;
}



static int
dissect_x411_DefaultDeliveryControls(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_Controls(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_RedirectionClass(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_MessageClass(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t SET_SIZE_1_ub_redirection_classes_OF_RedirectionClass_set_of[1] = {
  { &hf_x411_redirection_classes_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x411_RedirectionClass },
};

static int
dissect_x411_SET_SIZE_1_ub_redirection_classes_OF_RedirectionClass(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_SIZE_1_ub_redirection_classes_OF_RedirectionClass_set_of, hf_index, ett_x411_SET_SIZE_1_ub_redirection_classes_OF_RedirectionClass);

  return offset;
}



static int
dissect_x411_RecipientAssignedAlternateRecipient(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOrDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t RecipientRedirection_set[] = {
  { &hf_x411_redirection_classes, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_SIZE_1_ub_redirection_classes_OF_RedirectionClass },
  { &hf_x411_recipient_assigned_alternate_recipient, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_RecipientAssignedAlternateRecipient },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_RecipientRedirection(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              RecipientRedirection_set, hf_index, ett_x411_RecipientRedirection);

  return offset;
}


static const ber_sequence_t Redirections_sequence_of[1] = {
  { &hf_x411_Redirections_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x411_RecipientRedirection },
};

static int
dissect_x411_Redirections(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Redirections_sequence_of, hf_index, ett_x411_Redirections);

  return offset;
}


static const ber_sequence_t RestrictedDelivery_sequence_of[1] = {
  { &hf_x411_RestrictedDelivery_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x411_Restriction },
};

static int
dissect_x411_RestrictedDelivery(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      RestrictedDelivery_sequence_of, hf_index, ett_x411_RestrictedDelivery);

  return offset;
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
dissect_x411_T_standard_parameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_standard_parameters_bits, hf_index, ett_x411_T_standard_parameters,
                                    NULL);

  return offset;
}



static int
dissect_x411_T_type_extensions_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 498 "x411.cnf"
/*XXX not implemented yet */



  return offset;
}


static const ber_sequence_t T_type_extensions_set_of[1] = {
  { &hf_x411_type_extensions_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_T_type_extensions_item },
};

static int
dissect_x411_T_type_extensions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_type_extensions_set_of, hf_index, ett_x411_T_type_extensions);

  return offset;
}


static const ber_sequence_t RegistrationTypes_sequence[] = {
  { &hf_x411_standard_parameters, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_T_standard_parameters },
  { &hf_x411_type_extensions, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_T_type_extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_RegistrationTypes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RegistrationTypes_sequence, hf_index, ett_x411_RegistrationTypes);

  return offset;
}


static const ber_sequence_t RegisterArgument_set[] = {
  { &hf_x411_user_name      , BER_CLASS_APP, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_UserName },
  { &hf_x411_user_address   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_UserAddress },
  { &hf_x411_deliverable_class, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_SET_SIZE_1_ub_deliverable_class_OF_DeliverableClass },
  { &hf_x411_default_delivery_controls, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_x411_DefaultDeliveryControls },
  { &hf_x411_redirections   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_Redirections },
  { &hf_x411_restricted_delivery, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_RestrictedDelivery },
  { &hf_x411_retrieve_registrations, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_RegistrationTypes },
  { &hf_x411_extensions     , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_RegisterArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              RegisterArgument_set, hf_index, ett_x411_RegisterArgument);

  return offset;
}


static const ber_sequence_t T_non_empty_result_set[] = {
  { &hf_x411_registered_information, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_RegisterArgument },
  { &hf_x411_extensions     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_T_non_empty_result(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              T_non_empty_result_set, hf_index, ett_x411_T_non_empty_result);

  return offset;
}


static const value_string x411_RegisterResult_vals[] = {
  {   0, "empty-result" },
  {   1, "non-empty-result" },
  { 0, NULL }
};

static const ber_choice_t RegisterResult_choice[] = {
  {   0, &hf_x411_empty_result   , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_x411_NULL },
  {   1, &hf_x411_non_empty_result, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x411_T_non_empty_result },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_RegisterResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RegisterResult_choice, hf_index, ett_x411_RegisterResult,
                                 NULL);

  return offset;
}



static int
dissect_x411_RES_change_credentials(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t ChangeCredentialsArgument_set[] = {
  { &hf_x411_old_credentials, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_Credentials },
  { &hf_x411_new_credentials, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_Credentials },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_ChangeCredentialsArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ChangeCredentialsArgument_set, hf_index, ett_x411_ChangeCredentialsArgument);

  return offset;
}



static int
dissect_x411_PAR_register_rejected(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_x411_PAR_new_credentials_unacceptable(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_x411_PAR_old_credentials_incorrectly_specified(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t PerMessageSubmissionFields_set[] = {
  { &hf_x411_originator_name_01, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_x411_OriginatorName },
  { &hf_x411_original_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_OriginalEncodedInformationTypes },
  { &hf_x411_content_type   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_ContentType },
  { &hf_x411_content_identifier, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_ContentIdentifier },
  { &hf_x411_priority       , BER_CLASS_APP, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_Priority },
  { &hf_x411_per_message_indicators, BER_CLASS_APP, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_PerMessageIndicators },
  { &hf_x411_deferred_delivery_time, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_DeferredDeliveryTime },
  { &hf_x411_extensions     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_PerMessageSubmissionFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              PerMessageSubmissionFields_set, hf_index, ett_x411_PerMessageSubmissionFields);

  return offset;
}


static const ber_sequence_t PerProbeSubmissionFields_set[] = {
  { &hf_x411_originator_name_01, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_x411_OriginatorName },
  { &hf_x411_original_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_OriginalEncodedInformationTypes },
  { &hf_x411_content_type   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_ContentType },
  { &hf_x411_content_identifier, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_ContentIdentifier },
  { &hf_x411_content_length , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ContentLength },
  { &hf_x411_per_message_indicators, BER_CLASS_APP, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_PerMessageIndicators },
  { &hf_x411_extensions     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_PerProbeSubmissionFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              PerProbeSubmissionFields_set, hf_index, ett_x411_PerProbeSubmissionFields);

  return offset;
}


static const ber_sequence_t MessageDeliveryEnvelope_sequence[] = {
  { &hf_x411_message_delivery_identifier, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_x411_MessageDeliveryIdentifier },
  { &hf_x411_message_delivery_time, BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_x411_MessageDeliveryTime },
  { &hf_x411_other_fields   , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x411_OtherMessageDeliveryFields },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_MessageDeliveryEnvelope(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MessageDeliveryEnvelope_sequence, hf_index, ett_x411_MessageDeliveryEnvelope);

  return offset;
}


static const ber_sequence_t ReportDeliveryEnvelope_set[] = {
  { &hf_x411_subject_submission_identifier, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_x411_SubjectSubmissionIdentifier },
  { &hf_x411_content_identifier, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_ContentIdentifier },
  { &hf_x411_content_type   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_ContentType },
  { &hf_x411_original_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_OriginalEncodedInformationTypes },
  { &hf_x411_extensions     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { &hf_x411_per_recipient_report_delivery_fields, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportDeliveryFields },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_ReportDeliveryEnvelope(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ReportDeliveryEnvelope_set, hf_index, ett_x411_ReportDeliveryEnvelope);

  return offset;
}


static const ber_sequence_t PerReportDeliveryFields_set[] = {
  { &hf_x411_subject_submission_identifier, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_x411_SubjectSubmissionIdentifier },
  { &hf_x411_content_identifier, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_ContentIdentifier },
  { &hf_x411_content_type   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_ContentType },
  { &hf_x411_original_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_OriginalEncodedInformationTypes },
  { &hf_x411_extensions     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_PerReportDeliveryFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              PerReportDeliveryFields_set, hf_index, ett_x411_PerReportDeliveryFields);

  return offset;
}


static const value_string x411_RecipientReassignmentProhibited_vals[] = {
  {   0, "recipient-reassignment-allowed" },
  {   1, "recipient-reassignment-prohibited" },
  { 0, NULL }
};


static int
dissect_x411_RecipientReassignmentProhibited(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_x411_OriginatorRequestedAlternateRecipient(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOrDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string x411_DLExpansionProhibited_vals[] = {
  {   0, "dl-expansion-allowed" },
  {   1, "dl-expansion-prohibited" },
  { 0, NULL }
};


static int
dissect_x411_DLExpansionProhibited(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string x411_ConversionWithLossProhibited_vals[] = {
  {   0, "conversion-with-loss-allowed" },
  {   1, "conversion-with-loss-prohibited" },
  { 0, NULL }
};


static int
dissect_x411_ConversionWithLossProhibited(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_x411_LatestDeliveryTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_Time(implicit_tag, tvb, offset, actx, tree, hf_index);

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
dissect_x411_RequestedDeliveryMethod_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t RequestedDeliveryMethod_sequence_of[1] = {
  { &hf_x411_RequestedDeliveryMethod_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x411_RequestedDeliveryMethod_item },
};

int
dissect_x411_RequestedDeliveryMethod(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      RequestedDeliveryMethod_sequence_of, hf_index, ett_x411_RequestedDeliveryMethod);

  return offset;
}


static const value_string x411_PhysicalForwardingProhibited_vals[] = {
  {   0, "physical-forwarding-allowed" },
  {   1, "physical-forwarding-prohibited" },
  { 0, NULL }
};


static int
dissect_x411_PhysicalForwardingProhibited(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string x411_PhysicalForwardingAddressRequest_vals[] = {
  {   0, "physical-forwarding-address-not-requested" },
  {   1, "physical-forwarding-address-requested" },
  { 0, NULL }
};


static int
dissect_x411_PhysicalForwardingAddressRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
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
dissect_x411_PhysicalDeliveryModes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
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
dissect_x411_RegisteredMailType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_x411_RecipientNumberForAdvice(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x411_PhysicalRenditionAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t ORAddress_sequence[] = {
  { &hf_x411_built_in_standard_attributes, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x411_BuiltInStandardAttributes },
  { &hf_x411_built_in_domain_defined_attributes, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_BuiltInDomainDefinedAttributes },
  { &hf_x411_extension_attributes, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_ExtensionAttributes },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x411_ORAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 832 "x411.cnf"
	
	oraddress = ep_alloc(MAX_ORA_STR_LEN); oraddress[0] = '\0';	
	doing_address = TRUE;
	address_item = NULL;

	  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ORAddress_sequence, hf_index, ett_x411_ORAddress);


	if(*oraddress && address_item)
		proto_item_append_text(address_item, " %s/", oraddress);

	doing_address = FALSE;



  return offset;
}



static int
dissect_x411_OriginatorReturnAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_ORAddress(implicit_tag, tvb, offset, actx, tree, hf_index);

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
dissect_x411_PhysicalDeliveryReportRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_x411_OriginatorCertificate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_Certificates(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_x411_MessageToken(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_Token(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_ContentConfidentialityAlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_x411_ContentIntegrityCheck(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_Signature(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_x411_MessageOriginAuthenticationCheck(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_Signature(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_x411_MessageSecurityLabel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_SecurityLabel(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string x411_ProofOfSubmissionRequest_vals[] = {
  {   0, "proof-of-submission-not-requested" },
  {   1, "proof-of-submission-requested" },
  { 0, NULL }
};


static int
dissect_x411_ProofOfSubmissionRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string x411_ProofOfDeliveryRequest_vals[] = {
  {   0, "proof-of-delivery-not-requested" },
  {   1, "proof-of-delivery-requested" },
  { 0, NULL }
};


static int
dissect_x411_ProofOfDeliveryRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_x411_IA5String(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string x411_ContentCorrelator_vals[] = {
  {   0, "ia5text" },
  {   1, "octets" },
  { 0, NULL }
};

static const ber_choice_t ContentCorrelator_choice[] = {
  {   0, &hf_x411_ia5text        , BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_x411_IA5String },
  {   1, &hf_x411_octets         , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_x411_OCTET_STRING },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_ContentCorrelator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ContentCorrelator_choice, hf_index, ett_x411_ContentCorrelator,
                                 NULL);

  return offset;
}



static int
dissect_x411_ProbeOriginAuthenticationCheck(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_Signature(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t IntendedRecipientName_sequence[] = {
  { &hf_x411_intended_recipient, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_x411_ORAddressAndOptionalDirectoryName },
  { &hf_x411_redirection_time, BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_x411_Time },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_IntendedRecipientName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IntendedRecipientName_sequence, hf_index, ett_x411_IntendedRecipientName);

  return offset;
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
dissect_x411_RedirectionReason(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t Redirection_sequence[] = {
  { &hf_x411_intended_recipient_name, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x411_IntendedRecipientName },
  { &hf_x411_redirection_reason, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_x411_RedirectionReason },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_Redirection(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Redirection_sequence, hf_index, ett_x411_Redirection);

  return offset;
}


static const ber_sequence_t RedirectionHistory_sequence_of[1] = {
  { &hf_x411_RedirectionHistory_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x411_Redirection },
};

static int
dissect_x411_RedirectionHistory(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      RedirectionHistory_sequence_of, hf_index, ett_x411_RedirectionHistory);

  return offset;
}


static const ber_sequence_t DLExpansion_sequence[] = {
  { &hf_x411_dl             , BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_x411_ORAddressAndOptionalDirectoryName },
  { &hf_x411_dl_expansion_time, BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_x411_Time },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_DLExpansion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DLExpansion_sequence, hf_index, ett_x411_DLExpansion);

  return offset;
}


static const ber_sequence_t DLExpansionHistory_sequence_of[1] = {
  { &hf_x411_DLExpansionHistory_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x411_DLExpansion },
};

static int
dissect_x411_DLExpansionHistory(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      DLExpansionHistory_sequence_of, hf_index, ett_x411_DLExpansionHistory);

  return offset;
}



static int
dissect_x411_PhysicalForwardingAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t OriginatorAndDLExpansion_sequence[] = {
  { &hf_x411_originator_or_dl_name, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_x411_ORAddressAndOptionalDirectoryName },
  { &hf_x411_origination_or_expansion_time, BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_x411_Time },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_OriginatorAndDLExpansion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OriginatorAndDLExpansion_sequence, hf_index, ett_x411_OriginatorAndDLExpansion);

  return offset;
}


static const ber_sequence_t OriginatorAndDLExpansionHistory_sequence_of[1] = {
  { &hf_x411_OriginatorAndDLExpansionHistory_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x411_OriginatorAndDLExpansion },
};

static int
dissect_x411_OriginatorAndDLExpansionHistory(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      OriginatorAndDLExpansionHistory_sequence_of, hf_index, ett_x411_OriginatorAndDLExpansionHistory);

  return offset;
}



static int
dissect_x411_ReportingDLName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_ReportingMTACertificate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_Certificates(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_ReportOriginAuthenticationCheck(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_Signature(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t PerRecipientDeliveryReportFields_sequence[] = {
  { &hf_x411_message_delivery_time, BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_x411_MessageDeliveryTime },
  { &hf_x411_type_of_MTS_user, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x411_TypeOfMTSUser },
  { &hf_x411_recipient_certificate, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_RecipientCertificate },
  { &hf_x411_proof_of_delivery, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ProofOfDelivery },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_PerRecipientDeliveryReportFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PerRecipientDeliveryReportFields_sequence, hf_index, ett_x411_PerRecipientDeliveryReportFields);

  return offset;
}


static const ber_sequence_t PerRecipientNonDeliveryReportFields_sequence[] = {
  { &hf_x411_non_delivery_reason_code, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x411_NonDeliveryReasonCode },
  { &hf_x411_non_delivery_diagnostic_code, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_NonDeliveryDiagnosticCode },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_PerRecipientNonDeliveryReportFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PerRecipientNonDeliveryReportFields_sequence, hf_index, ett_x411_PerRecipientNonDeliveryReportFields);

  return offset;
}


static const value_string x411_T_report_type_vals[] = {
  {   0, "delivery" },
  {   1, "non-delivery" },
  { 0, NULL }
};

static const ber_choice_t T_report_type_choice[] = {
  {   0, &hf_x411_report_type_delivery, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_PerRecipientDeliveryReportFields },
  {   1, &hf_x411_non_delivery_report, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x411_PerRecipientNonDeliveryReportFields },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_T_report_type(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_report_type_choice, hf_index, ett_x411_T_report_type,
                                 NULL);

  return offset;
}


static const ber_sequence_t PerRecipientReportFields_sequence[] = {
  { &hf_x411_actual_recipient_name, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_x411_ActualRecipientName },
  { &hf_x411_originally_intended_recipient_name, BER_CLASS_APP, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_OriginallyIntendedRecipientName },
  { &hf_x411_report_type    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_T_report_type },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_PerRecipientReportFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PerRecipientReportFields_sequence, hf_index, ett_x411_PerRecipientReportFields);

  return offset;
}



int
dissect_x411_OriginatingMTACertificate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_Certificates(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_x411_ProofOfSubmission(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_Signature(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_ProofOfSubmissionAlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t ReportingMTAName_sequence[] = {
  { &hf_x411_domain_01      , BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_x411_GlobalDomainIdentifier },
  { &hf_x411_mta_name       , BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_x411_MTAName },
  { &hf_x411_mta_directory_name, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509if_Name },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_ReportingMTAName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReportingMTAName_sequence, hf_index, ett_x411_ReportingMTAName);

  return offset;
}


static const value_string x411_ExtendedCertificate_vals[] = {
  {   0, "directory-entry" },
  {   1, "certificate" },
  { 0, NULL }
};

static const ber_choice_t ExtendedCertificate_choice[] = {
  {   0, &hf_x411_directory_entry, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x509if_Name },
  {   1, &hf_x411_certificate    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x509af_Certificates },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_ExtendedCertificate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ExtendedCertificate_choice, hf_index, ett_x411_ExtendedCertificate,
                                 NULL);

  return offset;
}


static const ber_sequence_t ExtendedCertificates_set_of[1] = {
  { &hf_x411_ExtendedCertificates_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_ExtendedCertificate },
};

int
dissect_x411_ExtendedCertificates(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 ExtendedCertificates_set_of, hf_index, ett_x411_ExtendedCertificates);

  return offset;
}


static const ber_sequence_t DLExemptedRecipients_set_of[1] = {
  { &hf_x411_DLExemptedRecipients_item, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_x411_ORAddressAndOrDirectoryName },
};

static int
dissect_x411_DLExemptedRecipients(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 DLExemptedRecipients_set_of, hf_index, ett_x411_DLExemptedRecipients);

  return offset;
}


static const ber_sequence_t CertificateSelectors_set[] = {
  { &hf_x411_encryption_recipient, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_CertificateAssertion },
  { &hf_x411_encryption_originator, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_CertificateAssertion },
  { &hf_x411_selectors_content_integrity_check, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_CertificateAssertion },
  { &hf_x411_token_signature, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_CertificateAssertion },
  { &hf_x411_message_origin_authentication, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_CertificateAssertion },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_CertificateSelectors(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              CertificateSelectors_set, hf_index, ett_x411_CertificateSelectors);

  return offset;
}



static int
dissect_x411_CommonName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 722 "x411.cnf"
	tvbuff_t	*string = NULL;

	  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            &string);


	if(doing_address && string) {
		g_strlcat(oraddress, "/CN=", MAX_ORA_STR_LEN);
		g_strlcat(oraddress, tvb_format_text(string, 0, tvb_length(string)), MAX_ORA_STR_LEN);
	}



  return offset;
}



static int
dissect_x411_TeletexCommonName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x411_BMPString_SIZE_1_ub_string_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_BMPString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x411_UniversalString_SIZE_1_ub_string_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UniversalString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string x411_T_character_encoding_vals[] = {
  {   0, "two-octets" },
  {   1, "four-octets" },
  { 0, NULL }
};

static const ber_choice_t T_character_encoding_choice[] = {
  {   0, &hf_x411_two_octets     , BER_CLASS_UNI, BER_UNI_TAG_BMPString, BER_FLAGS_NOOWNTAG, dissect_x411_BMPString_SIZE_1_ub_string_length },
  {   1, &hf_x411_four_octets    , BER_CLASS_UNI, BER_UNI_TAG_UniversalString, BER_FLAGS_NOOWNTAG, dissect_x411_UniversalString_SIZE_1_ub_string_length },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_T_character_encoding(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_character_encoding_choice, hf_index, ett_x411_T_character_encoding,
                                 NULL);

  return offset;
}



static int
dissect_x411_PrintableString_SIZE_CONSTR13857016(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t UniversalOrBMPString_set[] = {
  { &hf_x411_character_encoding, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_T_character_encoding },
  { &hf_x411_iso_639_language_code, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_PrintableString_SIZE_CONSTR13857016 },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x411_UniversalOrBMPString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              UniversalOrBMPString_set, hf_index, ett_x411_UniversalOrBMPString);

  return offset;
}



static int
dissect_x411_UniversalCommonName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_UniversalOrBMPString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_TeletexOrganizationName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x411_UniversalOrganizationName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_UniversalOrBMPString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_AddrTeletexString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 757 "x411.cnf"
	tvbuff_t	*tstring = NULL;

	  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            actx, tree, tvb, offset, hf_index,
                                            &tstring);


	if(doing_address && tstring) 
		g_strlcat(oraddress, tvb_format_text(tstring, 0, tvb_length(tstring)), MAX_ORA_STR_LEN);




  return offset;
}


static const ber_sequence_t TeletexPersonalName_set[] = {
  { &hf_x411_teletex_surname, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_AddrTeletexString },
  { &hf_x411_teletex_given_name, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_AddrTeletexString },
  { &hf_x411_teletex_initials, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_AddrTeletexString },
  { &hf_x411_teletex_generation_qualifier, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_AddrTeletexString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_TeletexPersonalName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              TeletexPersonalName_set, hf_index, ett_x411_TeletexPersonalName);

  return offset;
}


static const ber_sequence_t UniversalPersonalName_set[] = {
  { &hf_x411_universal_surname, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_UniversalOrBMPString },
  { &hf_x411_universal_given_name, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_UniversalOrBMPString },
  { &hf_x411_universal_initials, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_UniversalOrBMPString },
  { &hf_x411_universal_generation_qualifier, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_UniversalOrBMPString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_UniversalPersonalName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              UniversalPersonalName_set, hf_index, ett_x411_UniversalPersonalName);

  return offset;
}



static int
dissect_x411_TeletexOrganizationalUnitName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t TeletexOrganizationalUnitNames_sequence_of[1] = {
  { &hf_x411_TeletexOrganizationalUnitNames_item, BER_CLASS_UNI, BER_UNI_TAG_TeletexString, BER_FLAGS_NOOWNTAG, dissect_x411_TeletexOrganizationalUnitName },
};

static int
dissect_x411_TeletexOrganizationalUnitNames(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      TeletexOrganizationalUnitNames_sequence_of, hf_index, ett_x411_TeletexOrganizationalUnitNames);

  return offset;
}



static int
dissect_x411_UniversalOrganizationalUnitName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_UniversalOrBMPString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t UniversalOrganizationalUnitNames_sequence_of[1] = {
  { &hf_x411_UniversalOrganizationalUnitNames_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x411_UniversalOrganizationalUnitName },
};

static int
dissect_x411_UniversalOrganizationalUnitNames(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      UniversalOrganizationalUnitNames_sequence_of, hf_index, ett_x411_UniversalOrganizationalUnitNames);

  return offset;
}



static int
dissect_x411_PDSName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string x411_PhysicalDeliveryCountryName_vals[] = {
  {   0, "x121-dcc-code" },
  {   1, "iso-3166-alpha2-code" },
  { 0, NULL }
};

static const ber_choice_t PhysicalDeliveryCountryName_choice[] = {
  {   0, &hf_x411_x121_dcc_code  , BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_x411_AddrNumericString },
  {   1, &hf_x411_iso_3166_alpha2_code, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_x411_AddrPrintableString },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_PhysicalDeliveryCountryName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PhysicalDeliveryCountryName_choice, hf_index, ett_x411_PhysicalDeliveryCountryName,
                                 NULL);

  return offset;
}



static int
dissect_x411_PrintableString_SIZE_1_ub_postal_code_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string x411_PostalCode_vals[] = {
  {   0, "numeric-code" },
  {   1, "printable-code" },
  { 0, NULL }
};

static const ber_choice_t PostalCode_choice[] = {
  {   0, &hf_x411_numeric_code   , BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_x411_AddrNumericString },
  {   1, &hf_x411_printable_code , BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_x411_PrintableString_SIZE_1_ub_postal_code_length },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_PostalCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PostalCode_choice, hf_index, ett_x411_PostalCode,
                                 NULL);

  return offset;
}



static int
dissect_x411_PrintableString_SIZE_1_ub_pds_parameter_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x411_TeletexString_SIZE_1_ub_pds_parameter_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t PDSParameter_set[] = {
  { &hf_x411_printable_string, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_PrintableString_SIZE_1_ub_pds_parameter_length },
  { &hf_x411_pds_teletex_string, BER_CLASS_UNI, BER_UNI_TAG_TeletexString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_TeletexString_SIZE_1_ub_pds_parameter_length },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_PDSParameter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              PDSParameter_set, hf_index, ett_x411_PDSParameter);

  return offset;
}



static int
dissect_x411_PhysicalDeliveryOfficeName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_PDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_UniversalPDSParameter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_UniversalOrBMPString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_UniversalPhysicalDeliveryOfficeName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_UniversalPDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_PhysicalDeliveryOfficeNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_PDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_UniversalPhysicalDeliveryOfficeNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_UniversalPDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_ExtensionORAddressComponents(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_PDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_UniversalExtensionORAddressComponents(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_UniversalPDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_PhysicalDeliveryPersonalName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_PDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_UniversalPhysicalDeliveryPersonalName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_UniversalPDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_PhysicalDeliveryOrganizationName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_PDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_UniversalPhysicalDeliveryOrganizationName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_UniversalPDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_ExtensionPhysicalDeliveryAddressComponents(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_PDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_UniversalExtensionPhysicalDeliveryAddressComponents(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_UniversalPDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t T_printable_address_sequence_of[1] = {
  { &hf_x411_printable_address_item, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_x411_PrintableString_SIZE_1_ub_pds_parameter_length },
};

static int
dissect_x411_T_printable_address(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_printable_address_sequence_of, hf_index, ett_x411_T_printable_address);

  return offset;
}



static int
dissect_x411_TeletexString_SIZE_1_ub_unformatted_address_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t UnformattedPostalAddress_set[] = {
  { &hf_x411_printable_address, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_T_printable_address },
  { &hf_x411_teletex_string , BER_CLASS_UNI, BER_UNI_TAG_TeletexString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_TeletexString_SIZE_1_ub_unformatted_address_length },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_UnformattedPostalAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              UnformattedPostalAddress_set, hf_index, ett_x411_UnformattedPostalAddress);

  return offset;
}



static int
dissect_x411_UniversalUnformattedPostalAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_UniversalOrBMPString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_StreetAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_PDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_UniversalStreetAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_UniversalPDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_PostOfficeBoxAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_PDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_UniversalPostOfficeBoxAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_UniversalPDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_PosteRestanteAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_PDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_UniversalPosteRestanteAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_UniversalPDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_UniquePostalName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_PDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_UniversalUniquePostalName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_UniversalPDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_LocalPostalAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_PDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_UniversalLocalPostalAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_UniversalPDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_NumericString_SIZE_1_ub_e163_4_number_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x411_NumericString_SIZE_1_ub_e163_4_sub_address_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t T_e163_4_address_sequence[] = {
  { &hf_x411_number         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_NumericString_SIZE_1_ub_e163_4_number_length },
  { &hf_x411_sub_address    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_NumericString_SIZE_1_ub_e163_4_sub_address_length },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_T_e163_4_address(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_e163_4_address_sequence, hf_index, ett_x411_T_e163_4_address);

  return offset;
}


static const value_string x411_ExtendedNetworkAddress_vals[] = {
  {   0, "e163-4-address" },
  {   1, "psap-address" },
  { 0, NULL }
};

static const ber_choice_t ExtendedNetworkAddress_choice[] = {
  {   0, &hf_x411_e163_4_address , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x411_T_e163_4_address },
  {   1, &hf_x411_psap_address   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x509sat_PresentationAddress },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_ExtendedNetworkAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
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
dissect_x411_TerminalType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t TeletexDomainDefinedAttribute_sequence[] = {
  { &hf_x411_type           , BER_CLASS_UNI, BER_UNI_TAG_TeletexString, BER_FLAGS_NOOWNTAG, dissect_x411_AddrTeletexString },
  { &hf_x411_teletex_value  , BER_CLASS_UNI, BER_UNI_TAG_TeletexString, BER_FLAGS_NOOWNTAG, dissect_x411_AddrTeletexString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_TeletexDomainDefinedAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TeletexDomainDefinedAttribute_sequence, hf_index, ett_x411_TeletexDomainDefinedAttribute);

  return offset;
}


static const ber_sequence_t TeletexDomainDefinedAttributes_sequence_of[1] = {
  { &hf_x411_TeletexDomainDefinedAttributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x411_TeletexDomainDefinedAttribute },
};

static int
dissect_x411_TeletexDomainDefinedAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      TeletexDomainDefinedAttributes_sequence_of, hf_index, ett_x411_TeletexDomainDefinedAttributes);

  return offset;
}


static const ber_sequence_t UniversalDomainDefinedAttribute_sequence[] = {
  { &hf_x411_universal_type , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x411_UniversalOrBMPString },
  { &hf_x411_universal_value, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x411_UniversalOrBMPString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_UniversalDomainDefinedAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UniversalDomainDefinedAttribute_sequence, hf_index, ett_x411_UniversalDomainDefinedAttribute);

  return offset;
}


static const ber_sequence_t UniversalDomainDefinedAttributes_sequence_of[1] = {
  { &hf_x411_UniversalDomainDefinedAttributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x411_UniversalDomainDefinedAttribute },
};

static int
dissect_x411_UniversalDomainDefinedAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      UniversalDomainDefinedAttributes_sequence_of, hf_index, ett_x411_UniversalDomainDefinedAttributes);

  return offset;
}


static const ber_sequence_t NonBasicParameters_set[] = {
  { &hf_x411_g3_facsimile   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_G3FacsimileNonBasicParameters },
  { &hf_x411_teletex        , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_TeletexNonBasicParameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_NonBasicParameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              NonBasicParameters_set, hf_index, ett_x411_NonBasicParameters);

  return offset;
}


static const ber_sequence_t MTANameAndOptionalGDI_sequence[] = {
  { &hf_x411_global_domain_identifier, BER_CLASS_APP, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x411_GlobalDomainIdentifier },
  { &hf_x411_mta_name       , BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_x411_MTAName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_MTANameAndOptionalGDI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 911 "x411.cnf"

	doing_address = TRUE;

	  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MTANameAndOptionalGDI_sequence, hf_index, ett_x411_MTANameAndOptionalGDI);


	doing_address = FALSE;
	proto_item_append_text(tree, ")");



  return offset;
}


static const value_string x411_T_name_vals[] = {
  {   0, "recipient-name" },
  {   1, "mta" },
  { 0, NULL }
};

static const ber_choice_t T_name_choice[] = {
  {   0, &hf_x411_token_recipient_name, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_x411_RecipientName },
  {   1, &hf_x411_token_mta      , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_x411_MTANameAndOptionalGDI },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_T_name(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_name_choice, hf_index, ett_x411_T_name,
                                 NULL);

  return offset;
}


static const value_string x411_TokenDataType_vals[] = {
  {   1, "bind-token-signed-data" },
  {   2, "message-token-signed-data" },
  {   3, "message-token-encrypted-data" },
  {   4, "bind-token-encrypted-data" },
  { 0, NULL }
};


static int
dissect_x411_TokenDataType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &extension_id);

  return offset;
}



static int
dissect_x411_T_value(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1015 "x411.cnf"

	proto_item_append_text(tree, " (%s)", val_to_str(extension_id, x411_TokenDataType_vals, "tokendata-type %d")); 
	if (dissector_try_port(x411_tokendata_dissector_table, extension_id, tvb, actx->pinfo, tree)) {
		offset = tvb_length(tvb);
	} else {
		proto_item *item = NULL;
		proto_tree *next_tree = NULL;

		item = proto_tree_add_text(tree, tvb, 0, tvb_length_remaining(tvb, offset), 
			"Dissector for tokendata-type %d not implemented.  Contact Wireshark developers if you want this supported", extension_id);
		next_tree = proto_item_add_subtree(item, ett_x411_unknown_tokendata_type);
		offset = dissect_unknown_ber(actx->pinfo, tvb, offset, next_tree);
		expert_add_info_format(actx->pinfo, item, PI_UNDECODED, PI_WARN, "Unknown tokendata-type");
	}



  return offset;
}


static const ber_sequence_t TokenData_sequence[] = {
  { &hf_x411_token_data_type, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x411_TokenDataType },
  { &hf_x411_value          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x411_T_value },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_TokenData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TokenData_sequence, hf_index, ett_x411_TokenData);

  return offset;
}


static const ber_sequence_t AsymmetricTokenData_sequence[] = {
  { &hf_x411_signature_algorithm_identifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_x411_name           , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x411_T_name },
  { &hf_x411_time           , BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_x411_Time },
  { &hf_x411_signed_data    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_TokenData },
  { &hf_x411_encryption_algorithm_identifier, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_x411_encrypted_data , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_AsymmetricTokenData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AsymmetricTokenData_sequence, hf_index, ett_x411_AsymmetricTokenData);

  return offset;
}


static const ber_sequence_t AsymmetricToken_sequence[] = {
  { &hf_x411_asymmetric_token_data, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x411_AsymmetricTokenData },
  { &hf_x411_algorithm_identifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_x411_encrypted      , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_x411_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_AsymmetricToken(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AsymmetricToken_sequence, hf_index, ett_x411_AsymmetricToken);

  return offset;
}



static int
dissect_x411_RandomNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_x411_BindTokenSignedData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x411_RandomNumber(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t MessageTokenSignedData_sequence[] = {
  { &hf_x411_content_confidentiality_algorithm_identifier, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ContentConfidentialityAlgorithmIdentifier },
  { &hf_x411_content_integrity_check, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ContentIntegrityCheck },
  { &hf_x411_message_security_label, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_MessageSecurityLabel },
  { &hf_x411_proof_of_delivery_request, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ProofOfDeliveryRequest },
  { &hf_x411_message_sequence_number, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_MessageTokenSignedData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MessageTokenSignedData_sequence, hf_index, ett_x411_MessageTokenSignedData);

  return offset;
}



static int
dissect_x411_EncryptionKey(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t MessageTokenEncryptedData_sequence[] = {
  { &hf_x411_content_confidentiality_key, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_EncryptionKey },
  { &hf_x411_content_integrity_check, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_ContentIntegrityCheck },
  { &hf_x411_message_security_label, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_MessageSecurityLabel },
  { &hf_x411_content_integrity_key, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_EncryptionKey },
  { &hf_x411_message_sequence_number, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_MessageTokenEncryptedData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MessageTokenEncryptedData_sequence, hf_index, ett_x411_MessageTokenEncryptedData);

  return offset;
}



static int
dissect_x411_BindTokenEncryptedData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_external_type(implicit_tag, tree, tvb, offset, actx, hf_index, NULL);

  return offset;
}



static int
dissect_x411_RTTPapdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_x411_RTTRapdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string x411_AbortReason_vals[] = {
  {   0, "localSystemProblem" },
  {   1, "invalidParameter" },
  {   2, "unrecognizedActivity" },
  {   3, "temporaryProblem" },
  {   4, "protocolError" },
  {   5, "permanentProblem" },
  {   6, "userError" },
  {   7, "transferCompleted" },
  { 0, NULL }
};


static int
dissect_x411_AbortReason(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_x411_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t RTABapdu_set[] = {
  { &hf_x411_abortReason    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_AbortReason },
  { &hf_x411_reflectedParameter, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_BIT_STRING },
  { &hf_x411_userdataAB     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x411_OBJECT_IDENTIFIER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_RTABapdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              RTABapdu_set, hf_index, ett_x411_RTABapdu);

  return offset;
}


static const value_string x411_RTSE_apdus_vals[] = {
  {   0, "rtorq-apdu" },
  {   1, "rtoac-apdu" },
  {   2, "rtorj-apdu" },
  {   3, "rttp-apdu" },
  {   4, "rttr-apdu" },
  {   5, "rtab-apdu" },
  { 0, NULL }
};

static const ber_choice_t RTSE_apdus_choice[] = {
  {   0, &hf_x411_rtorq_apdu     , BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_rtse_RTORQapdu },
  {   1, &hf_x411_rtoac_apdu     , BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_rtse_RTOACapdu },
  {   2, &hf_x411_rtorj_apdu     , BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_rtse_RTORJapdu },
  {   3, &hf_x411_rttp_apdu      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x411_RTTPapdu },
  {   4, &hf_x411_rttr_apdu      , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_x411_RTTRapdu },
  {   5, &hf_x411_rtab_apdu      , BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_x411_RTABapdu },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x411_RTSE_apdus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RTSE_apdus_choice, hf_index, ett_x411_RTSE_apdus,
                                 NULL);

  return offset;
}



static int
dissect_x411_MTSInvokeIds(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ros_InvokeId(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x411_ID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}

/*--- PDUs ---*/

static void dissect_InternalTraceInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_InternalTraceInformation(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_InternalTraceInformation_PDU);
}
static void dissect_InternalTraceInformationElement_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_InternalTraceInformationElement(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_InternalTraceInformationElement_PDU);
}
static void dissect_TraceInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_TraceInformation(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_TraceInformation_PDU);
}
static void dissect_TraceInformationElement_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_TraceInformationElement(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_TraceInformationElement_PDU);
}
static int dissect_MTSBindArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_MTSBindArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_MTSBindArgument_PDU);
  return offset;
}
static int dissect_MTSBindResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_MTSBindResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_MTSBindResult_PDU);
  return offset;
}
static int dissect_PAR_mts_bind_error_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_PAR_mts_bind_error(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_PAR_mts_bind_error_PDU);
  return offset;
}
static int dissect_MessageSubmissionArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_MessageSubmissionArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_MessageSubmissionArgument_PDU);
  return offset;
}
static int dissect_MessageSubmissionResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_MessageSubmissionResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_MessageSubmissionResult_PDU);
  return offset;
}
static int dissect_ProbeSubmissionArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_ProbeSubmissionArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_ProbeSubmissionArgument_PDU);
  return offset;
}
static int dissect_ProbeSubmissionResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_ProbeSubmissionResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_ProbeSubmissionResult_PDU);
  return offset;
}
static int dissect_CancelDeferredDeliveryArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_CancelDeferredDeliveryArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_CancelDeferredDeliveryArgument_PDU);
  return offset;
}
static int dissect_CancelDeferredDeliveryResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_CancelDeferredDeliveryResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_CancelDeferredDeliveryResult_PDU);
  return offset;
}
static int dissect_SubmissionControlArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_SubmissionControlArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_SubmissionControlArgument_PDU);
  return offset;
}
static int dissect_SubmissionControlResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_SubmissionControlResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_SubmissionControlResult_PDU);
  return offset;
}
static int dissect_PAR_submission_control_violated_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_PAR_submission_control_violated(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_PAR_submission_control_violated_PDU);
  return offset;
}
static int dissect_PAR_element_of_service_not_subscribed_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_PAR_element_of_service_not_subscribed(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_PAR_element_of_service_not_subscribed_PDU);
  return offset;
}
static int dissect_PAR_deferred_delivery_cancellation_rejected_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_PAR_deferred_delivery_cancellation_rejected(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_PAR_deferred_delivery_cancellation_rejected_PDU);
  return offset;
}
static int dissect_PAR_originator_invalid_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_PAR_originator_invalid(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_PAR_originator_invalid_PDU);
  return offset;
}
static int dissect_ImproperlySpecifiedRecipients_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_ImproperlySpecifiedRecipients(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_ImproperlySpecifiedRecipients_PDU);
  return offset;
}
static int dissect_PAR_message_submission_identifier_invalid_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_PAR_message_submission_identifier_invalid(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_PAR_message_submission_identifier_invalid_PDU);
  return offset;
}
static int dissect_PAR_inconsistent_request_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_PAR_inconsistent_request(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_PAR_inconsistent_request_PDU);
  return offset;
}
static int dissect_SecurityProblem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_SecurityProblem(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_SecurityProblem_PDU);
  return offset;
}
static int dissect_PAR_unsupported_critical_function_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_PAR_unsupported_critical_function(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_PAR_unsupported_critical_function_PDU);
  return offset;
}
static int dissect_PAR_remote_bind_error_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_PAR_remote_bind_error(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_PAR_remote_bind_error_PDU);
  return offset;
}
static void dissect_MessageSubmissionTime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_MessageSubmissionTime(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_MessageSubmissionTime_PDU);
}
static int dissect_MessageDeliveryArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_MessageDeliveryArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_MessageDeliveryArgument_PDU);
  return offset;
}
static int dissect_MessageDeliveryResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_MessageDeliveryResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_MessageDeliveryResult_PDU);
  return offset;
}
static int dissect_ReportDeliveryArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_ReportDeliveryArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_ReportDeliveryArgument_PDU);
  return offset;
}
static int dissect_ReportDeliveryResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_ReportDeliveryResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_ReportDeliveryResult_PDU);
  return offset;
}
static int dissect_DeliveryControlArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_DeliveryControlArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_DeliveryControlArgument_PDU);
  return offset;
}
static int dissect_DeliveryControlResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_DeliveryControlResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_DeliveryControlResult_PDU);
  return offset;
}
static int dissect_PAR_delivery_control_violated_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_PAR_delivery_control_violated(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_PAR_delivery_control_violated_PDU);
  return offset;
}
static int dissect_PAR_control_violates_registration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_PAR_control_violates_registration(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_PAR_control_violates_registration_PDU);
  return offset;
}
static int dissect_RefusedOperation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_RefusedOperation(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_RefusedOperation_PDU);
  return offset;
}
static void dissect_RecipientCertificate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_RecipientCertificate(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_RecipientCertificate_PDU);
}
static void dissect_ProofOfDelivery_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_ProofOfDelivery(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_ProofOfDelivery_PDU);
}
static int dissect_RegisterArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_RegisterArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_RegisterArgument_PDU);
  return offset;
}
static int dissect_RegisterResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_RegisterResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_RegisterResult_PDU);
  return offset;
}
static int dissect_ChangeCredentialsArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_ChangeCredentialsArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_ChangeCredentialsArgument_PDU);
  return offset;
}
static int dissect_RES_change_credentials_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_RES_change_credentials(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_RES_change_credentials_PDU);
  return offset;
}
static int dissect_PAR_register_rejected_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_PAR_register_rejected(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_PAR_register_rejected_PDU);
  return offset;
}
static int dissect_PAR_new_credentials_unacceptable_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_PAR_new_credentials_unacceptable(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_PAR_new_credentials_unacceptable_PDU);
  return offset;
}
static int dissect_PAR_old_credentials_incorrectly_specified_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_x411_PAR_old_credentials_incorrectly_specified(FALSE, tvb, offset, &asn1_ctx, tree, hf_x411_PAR_old_credentials_incorrectly_specified_PDU);
  return offset;
}
static void dissect_MessageSubmissionEnvelope_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_MessageSubmissionEnvelope(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_MessageSubmissionEnvelope_PDU);
}
static void dissect_PerRecipientMessageSubmissionFields_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_PerRecipientMessageSubmissionFields(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_PerRecipientMessageSubmissionFields_PDU);
}
static void dissect_ProbeSubmissionEnvelope_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_ProbeSubmissionEnvelope(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_ProbeSubmissionEnvelope_PDU);
}
static void dissect_PerRecipientProbeSubmissionFields_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_PerRecipientProbeSubmissionFields(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_PerRecipientProbeSubmissionFields_PDU);
}
static void dissect_MessageDeliveryEnvelope_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_MessageDeliveryEnvelope(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_MessageDeliveryEnvelope_PDU);
}
static void dissect_ReportDeliveryEnvelope_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_ReportDeliveryEnvelope(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_ReportDeliveryEnvelope_PDU);
}
static void dissect_PerRecipientReportDeliveryFields_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_PerRecipientReportDeliveryFields(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_PerRecipientReportDeliveryFields_PDU);
}
static void dissect_ExtendedContentType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_ExtendedContentType(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_ExtendedContentType_PDU);
}
static void dissect_ContentIdentifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_ContentIdentifier(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_ContentIdentifier_PDU);
}
static void dissect_PerMessageIndicators_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_PerMessageIndicators(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_PerMessageIndicators_PDU);
}
static void dissect_OriginatorReportRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_OriginatorReportRequest(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_OriginatorReportRequest_PDU);
}
static void dissect_DeferredDeliveryTime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_DeferredDeliveryTime(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_DeferredDeliveryTime_PDU);
}
static void dissect_Priority_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_Priority(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_Priority_PDU);
}
static void dissect_ContentLength_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_ContentLength(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_ContentLength_PDU);
}
static void dissect_MessageDeliveryTime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_MessageDeliveryTime(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_MessageDeliveryTime_PDU);
}
static void dissect_DeliveryFlags_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_DeliveryFlags(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_DeliveryFlags_PDU);
}
static void dissect_SubjectSubmissionIdentifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_SubjectSubmissionIdentifier(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_SubjectSubmissionIdentifier_PDU);
}
static void dissect_RecipientReassignmentProhibited_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_RecipientReassignmentProhibited(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_RecipientReassignmentProhibited_PDU);
}
static void dissect_OriginatorRequestedAlternateRecipient_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_OriginatorRequestedAlternateRecipient(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_OriginatorRequestedAlternateRecipient_PDU);
}
static void dissect_DLExpansionProhibited_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_DLExpansionProhibited(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_DLExpansionProhibited_PDU);
}
static void dissect_ConversionWithLossProhibited_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_ConversionWithLossProhibited(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_ConversionWithLossProhibited_PDU);
}
static void dissect_LatestDeliveryTime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_LatestDeliveryTime(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_LatestDeliveryTime_PDU);
}
static void dissect_RequestedDeliveryMethod_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_RequestedDeliveryMethod(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_RequestedDeliveryMethod_PDU);
}
static void dissect_PhysicalForwardingProhibited_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_PhysicalForwardingProhibited(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_PhysicalForwardingProhibited_PDU);
}
static void dissect_PhysicalForwardingAddressRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_PhysicalForwardingAddressRequest(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_PhysicalForwardingAddressRequest_PDU);
}
static void dissect_PhysicalDeliveryModes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_PhysicalDeliveryModes(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_PhysicalDeliveryModes_PDU);
}
static void dissect_RegisteredMailType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_RegisteredMailType(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_RegisteredMailType_PDU);
}
static void dissect_RecipientNumberForAdvice_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_RecipientNumberForAdvice(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_RecipientNumberForAdvice_PDU);
}
static void dissect_PhysicalRenditionAttributes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_PhysicalRenditionAttributes(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_PhysicalRenditionAttributes_PDU);
}
static void dissect_OriginatorReturnAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_OriginatorReturnAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_OriginatorReturnAddress_PDU);
}
static void dissect_PhysicalDeliveryReportRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_PhysicalDeliveryReportRequest(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_PhysicalDeliveryReportRequest_PDU);
}
static void dissect_OriginatorCertificate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_OriginatorCertificate(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_OriginatorCertificate_PDU);
}
static void dissect_MessageToken_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_MessageToken(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_MessageToken_PDU);
}
static void dissect_ContentConfidentialityAlgorithmIdentifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_ContentConfidentialityAlgorithmIdentifier(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_ContentConfidentialityAlgorithmIdentifier_PDU);
}
static void dissect_ContentIntegrityCheck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_ContentIntegrityCheck(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_ContentIntegrityCheck_PDU);
}
static void dissect_MessageOriginAuthenticationCheck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_MessageOriginAuthenticationCheck(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_MessageOriginAuthenticationCheck_PDU);
}
static void dissect_MessageSecurityLabel_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_MessageSecurityLabel(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_MessageSecurityLabel_PDU);
}
static void dissect_ProofOfSubmissionRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_ProofOfSubmissionRequest(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_ProofOfSubmissionRequest_PDU);
}
static void dissect_ProofOfDeliveryRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_ProofOfDeliveryRequest(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_ProofOfDeliveryRequest_PDU);
}
static void dissect_ContentCorrelator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_ContentCorrelator(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_ContentCorrelator_PDU);
}
static void dissect_ProbeOriginAuthenticationCheck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_ProbeOriginAuthenticationCheck(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_ProbeOriginAuthenticationCheck_PDU);
}
static void dissect_RedirectionHistory_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_RedirectionHistory(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_RedirectionHistory_PDU);
}
static void dissect_Redirection_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_Redirection(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_Redirection_PDU);
}
static void dissect_DLExpansionHistory_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_DLExpansionHistory(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_DLExpansionHistory_PDU);
}
static void dissect_DLExpansion_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_DLExpansion(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_DLExpansion_PDU);
}
static void dissect_PhysicalForwardingAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_PhysicalForwardingAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_PhysicalForwardingAddress_PDU);
}
static void dissect_OriginatorAndDLExpansionHistory_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_OriginatorAndDLExpansionHistory(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_OriginatorAndDLExpansionHistory_PDU);
}
static void dissect_ReportingDLName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_ReportingDLName(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_ReportingDLName_PDU);
}
static void dissect_ReportingMTACertificate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_ReportingMTACertificate(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_ReportingMTACertificate_PDU);
}
static void dissect_ReportOriginAuthenticationCheck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_ReportOriginAuthenticationCheck(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_ReportOriginAuthenticationCheck_PDU);
}
static void dissect_OriginatingMTACertificate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_OriginatingMTACertificate(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_OriginatingMTACertificate_PDU);
}
static void dissect_ProofOfSubmission_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_ProofOfSubmission(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_ProofOfSubmission_PDU);
}
static void dissect_ReportingMTAName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_ReportingMTAName(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_ReportingMTAName_PDU);
}
static void dissect_ExtendedCertificates_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_ExtendedCertificates(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_ExtendedCertificates_PDU);
}
static void dissect_DLExemptedRecipients_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_DLExemptedRecipients(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_DLExemptedRecipients_PDU);
}
static void dissect_CertificateSelectors_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_CertificateSelectors(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_CertificateSelectors_PDU);
}
static void dissect_Content_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_Content(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_Content_PDU);
}
static void dissect_MTSIdentifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_MTSIdentifier(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_MTSIdentifier_PDU);
}
static void dissect_ORName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_ORName(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_ORName_PDU);
}
static void dissect_ORAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_ORAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_ORAddress_PDU);
}
static void dissect_CommonName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_CommonName(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_CommonName_PDU);
}
static void dissect_TeletexCommonName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_TeletexCommonName(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_TeletexCommonName_PDU);
}
static void dissect_UniversalCommonName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_UniversalCommonName(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_UniversalCommonName_PDU);
}
static void dissect_TeletexOrganizationName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_TeletexOrganizationName(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_TeletexOrganizationName_PDU);
}
static void dissect_UniversalOrganizationName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_UniversalOrganizationName(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_UniversalOrganizationName_PDU);
}
static void dissect_TeletexPersonalName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_TeletexPersonalName(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_TeletexPersonalName_PDU);
}
static void dissect_UniversalPersonalName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_UniversalPersonalName(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_UniversalPersonalName_PDU);
}
static void dissect_TeletexOrganizationalUnitNames_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_TeletexOrganizationalUnitNames(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_TeletexOrganizationalUnitNames_PDU);
}
static void dissect_UniversalOrganizationalUnitNames_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_UniversalOrganizationalUnitNames(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_UniversalOrganizationalUnitNames_PDU);
}
static void dissect_PDSName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_PDSName(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_PDSName_PDU);
}
static void dissect_PhysicalDeliveryCountryName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_PhysicalDeliveryCountryName(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_PhysicalDeliveryCountryName_PDU);
}
static void dissect_PostalCode_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_PostalCode(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_PostalCode_PDU);
}
static void dissect_PhysicalDeliveryOfficeName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_PhysicalDeliveryOfficeName(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_PhysicalDeliveryOfficeName_PDU);
}
static void dissect_UniversalPhysicalDeliveryOfficeName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_UniversalPhysicalDeliveryOfficeName(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_UniversalPhysicalDeliveryOfficeName_PDU);
}
static void dissect_PhysicalDeliveryOfficeNumber_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_PhysicalDeliveryOfficeNumber(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_PhysicalDeliveryOfficeNumber_PDU);
}
static void dissect_UniversalPhysicalDeliveryOfficeNumber_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_UniversalPhysicalDeliveryOfficeNumber(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_UniversalPhysicalDeliveryOfficeNumber_PDU);
}
static void dissect_ExtensionORAddressComponents_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_ExtensionORAddressComponents(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_ExtensionORAddressComponents_PDU);
}
static void dissect_UniversalExtensionORAddressComponents_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_UniversalExtensionORAddressComponents(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_UniversalExtensionORAddressComponents_PDU);
}
static void dissect_PhysicalDeliveryPersonalName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_PhysicalDeliveryPersonalName(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_PhysicalDeliveryPersonalName_PDU);
}
static void dissect_UniversalPhysicalDeliveryPersonalName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_UniversalPhysicalDeliveryPersonalName(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_UniversalPhysicalDeliveryPersonalName_PDU);
}
static void dissect_PhysicalDeliveryOrganizationName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_PhysicalDeliveryOrganizationName(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_PhysicalDeliveryOrganizationName_PDU);
}
static void dissect_UniversalPhysicalDeliveryOrganizationName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_UniversalPhysicalDeliveryOrganizationName(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_UniversalPhysicalDeliveryOrganizationName_PDU);
}
static void dissect_ExtensionPhysicalDeliveryAddressComponents_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_ExtensionPhysicalDeliveryAddressComponents(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_ExtensionPhysicalDeliveryAddressComponents_PDU);
}
static void dissect_UniversalExtensionPhysicalDeliveryAddressComponents_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_UniversalExtensionPhysicalDeliveryAddressComponents(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_UniversalExtensionPhysicalDeliveryAddressComponents_PDU);
}
static void dissect_UnformattedPostalAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_UnformattedPostalAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_UnformattedPostalAddress_PDU);
}
static void dissect_UniversalUnformattedPostalAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_UniversalUnformattedPostalAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_UniversalUnformattedPostalAddress_PDU);
}
static void dissect_StreetAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_StreetAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_StreetAddress_PDU);
}
static void dissect_UniversalStreetAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_UniversalStreetAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_UniversalStreetAddress_PDU);
}
static void dissect_PostOfficeBoxAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_PostOfficeBoxAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_PostOfficeBoxAddress_PDU);
}
static void dissect_UniversalPostOfficeBoxAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_UniversalPostOfficeBoxAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_UniversalPostOfficeBoxAddress_PDU);
}
static void dissect_PosteRestanteAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_PosteRestanteAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_PosteRestanteAddress_PDU);
}
static void dissect_UniversalPosteRestanteAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_UniversalPosteRestanteAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_UniversalPosteRestanteAddress_PDU);
}
static void dissect_UniquePostalName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_UniquePostalName(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_UniquePostalName_PDU);
}
static void dissect_UniversalUniquePostalName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_UniversalUniquePostalName(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_UniversalUniquePostalName_PDU);
}
static void dissect_LocalPostalAttributes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_LocalPostalAttributes(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_LocalPostalAttributes_PDU);
}
static void dissect_UniversalLocalPostalAttributes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_UniversalLocalPostalAttributes(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_UniversalLocalPostalAttributes_PDU);
}
static void dissect_ExtendedNetworkAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_ExtendedNetworkAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_ExtendedNetworkAddress_PDU);
}
static void dissect_TerminalType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_TerminalType(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_TerminalType_PDU);
}
static void dissect_TeletexDomainDefinedAttributes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_TeletexDomainDefinedAttributes(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_TeletexDomainDefinedAttributes_PDU);
}
static void dissect_UniversalDomainDefinedAttributes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_UniversalDomainDefinedAttributes(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_UniversalDomainDefinedAttributes_PDU);
}
static void dissect_ExtendedEncodedInformationType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_ExtendedEncodedInformationType(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_ExtendedEncodedInformationType_PDU);
}
static void dissect_MTANameAndOptionalGDI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_MTANameAndOptionalGDI(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_MTANameAndOptionalGDI_PDU);
}
static void dissect_AsymmetricToken_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_AsymmetricToken(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_AsymmetricToken_PDU);
}
static void dissect_BindTokenSignedData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_BindTokenSignedData(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_BindTokenSignedData_PDU);
}
static void dissect_MessageTokenSignedData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_MessageTokenSignedData(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_MessageTokenSignedData_PDU);
}
static void dissect_MessageTokenEncryptedData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_MessageTokenEncryptedData(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_MessageTokenEncryptedData_PDU);
}
static void dissect_BindTokenEncryptedData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_BindTokenEncryptedData(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_BindTokenEncryptedData_PDU);
}
static void dissect_SecurityClassification_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x411_SecurityClassification(FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_SecurityClassification_PDU);
}


/*--- End of included file: packet-x411-fn.c ---*/
#line 107 "packet-x411-template.c"


/*--- Included file: packet-x411-table11.c ---*/
#line 1 "packet-x411-table11.c"

static const ros_opr_t p3_opr_tab[] = {
  /* mts-bind */ 
  { op_ros_bind              ,	dissect_MTSBindArgument_PDU,	dissect_MTSBindResult_PDU }, 
  /* message-submission */ 
  { op_message_submission    ,	dissect_MessageSubmissionArgument_PDU,	dissect_MessageSubmissionResult_PDU }, 
  /* probe-submission */ 
  { op_probe_submission      ,	dissect_ProbeSubmissionArgument_PDU,	dissect_ProbeSubmissionResult_PDU }, 
  /* cancel-deferred-delivery */ 
  { op_cancel_deferred_delivery,	dissect_CancelDeferredDeliveryArgument_PDU,	dissect_CancelDeferredDeliveryResult_PDU }, 
  /* submission-control */ 
  { op_submission_control    ,	dissect_SubmissionControlArgument_PDU,	dissect_SubmissionControlResult_PDU }, 
  /* message-delivery */ 
  { op_message_delivery      ,	dissect_MessageDeliveryArgument_PDU,	dissect_MessageDeliveryResult_PDU }, 
  /* report-delivery */ 
  { op_report_delivery       ,	dissect_ReportDeliveryArgument_PDU,	dissect_ReportDeliveryResult_PDU }, 
  /* delivery-control */ 
  { op_delivery_control      ,	dissect_DeliveryControlArgument_PDU,	dissect_DeliveryControlResult_PDU }, 
  /* register */ 
  { op_register              ,	dissect_RegisterArgument_PDU,	dissect_RegisterResult_PDU }, 
  /* change-credentials */ 
  { op_change_credentials    ,	dissect_ChangeCredentialsArgument_PDU,	dissect_RES_change_credentials_PDU }, 
  { 0,				(new_dissector_t)(-1),	(new_dissector_t)(-1) },
};


/*--- End of included file: packet-x411-table11.c ---*/
#line 109 "packet-x411-template.c"

/*--- Included file: packet-x411-table21.c ---*/
#line 1 "packet-x411-table21.c"

static const ros_err_t p3_err_tab[] = {
  /* mts-bind-error*/ 
  { err_ros_bind,	dissect_PAR_mts_bind_error_PDU },
  /* submission-control-violated*/ 
  { err_submission_control_violated,	dissect_PAR_submission_control_violated_PDU },
  /* element-of-service-not-subscribed*/ 
  { err_element_of_service_not_subscribed,	dissect_PAR_element_of_service_not_subscribed_PDU },
  /* deferred-delivery-cancellation-rejected*/ 
  { err_deferred_delivery_cancellation_rejected,	dissect_PAR_deferred_delivery_cancellation_rejected_PDU },
  /* originator-invalid*/ 
  { err_originator_invalid,	dissect_PAR_originator_invalid_PDU },
  /* recipient-improperly-specified*/ 
  { err_recipient_improperly_specified,	dissect_ImproperlySpecifiedRecipients_PDU },
  /* message-submission-identifier-invalid*/ 
  { err_message_submission_identifier_invalid,	dissect_PAR_message_submission_identifier_invalid_PDU },
  /* inconsistent-request*/ 
  { err_inconsistent_request,	dissect_PAR_inconsistent_request_PDU },
  /* security-error*/ 
  { err_security_error,	dissect_SecurityProblem_PDU },
  /* unsupported-critical-function*/ 
  { err_unsupported_critical_function,	dissect_PAR_unsupported_critical_function_PDU },
  /* remote-bind-error*/ 
  { err_remote_bind_error,	dissect_PAR_remote_bind_error_PDU },
  /* delivery-control-violated*/ 
  { err_delivery_control_violated,	dissect_PAR_delivery_control_violated_PDU },
  /* control-violates-registration*/ 
  { err_control_violates_registration,	dissect_PAR_control_violates_registration_PDU },
  /* operation-refused*/ 
  { err_operation_refused,	dissect_RefusedOperation_PDU },
  /* register-rejected*/ 
  { err_register_rejected,	dissect_PAR_register_rejected_PDU },
  /* new-credentials-unacceptable*/ 
  { err_new_credentials_unacceptable,	dissect_PAR_new_credentials_unacceptable_PDU },
  /* old-credentials-incorrectly-specified*/ 
  { err_old_credentials_incorrectly_specified,	dissect_PAR_old_credentials_incorrectly_specified_PDU },
  { 0,	(new_dissector_t)(-1) },
};


/*--- End of included file: packet-x411-table21.c ---*/
#line 110 "packet-x411-template.c"

static const ros_info_t p3_ros_info = {
  "P3",
  &proto_p3,
  &ett_p3,
  p3_opr_code_string_vals,
  p3_opr_tab,
  p3_err_code_string_vals,
  p3_err_tab
};


char* x411_get_last_oraddress() { return oraddress; }

/*
 * Dissect X411 MTS APDU
 */
void
dissect_x411_mts_apdu (tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	/* save parent_tree so subdissectors can create new top nodes */
	top_tree=parent_tree;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_x411, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_x411);
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "P1");
  	col_set_str(pinfo->cinfo, COL_INFO, "Transfer");

	dissect_x411_MTS_APDU (FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_MTS_APDU_PDU);
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
	int (*x411_dissector)(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_) = NULL;
	char *x411_op_name;
	int hf_x411_index = -1;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

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
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "P1");
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
	  col_set_str(pinfo->cinfo, COL_INFO, x411_op_name);

	while (tvb_reported_length_remaining(tvb, offset) > 0){
		old_offset=offset;
		offset=(*x411_dissector)(FALSE, tvb, offset, &asn1_ctx , tree, hf_x411_index);
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
	  /* "Created by defining PDU in .cnf */
    { &hf_x411_MTABindArgument_PDU,
      { "MTABindArgument", "x411.MTABindArgument",
        FT_UINT32, BASE_DEC, VALS(x411_MTABindArgument_vals), 0,
        "x411.MTABindArgument", HFILL }},
    { &hf_x411_MTABindResult_PDU,
      { "MTABindResult", "x411.MTABindResult",
        FT_UINT32, BASE_DEC, VALS(x411_MTABindResult_vals), 0,
        "x411.MTABindResult", HFILL }},
    { &hf_x411_MTABindError_PDU,
      { "MTABindError", "x411.MTABindError",
        FT_UINT32, BASE_DEC, VALS(x411_MTABindError_vals), 0,
        "x411.MTABindError", HFILL }},
    { &hf_x411_MTS_APDU_PDU,
      { "MTS-APDU", "x411.MTS_APDU",
        FT_UINT32, BASE_DEC, VALS(x411_MTS_APDU_vals), 0,
        "x411.MTS_APDU", HFILL }},


/*--- Included file: packet-x411-hfarr.c ---*/
#line 1 "packet-x411-hfarr.c"
    { &hf_x411_InternalTraceInformation_PDU,
      { "InternalTraceInformation", "x411.InternalTraceInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.InternalTraceInformation", HFILL }},
    { &hf_x411_InternalTraceInformationElement_PDU,
      { "InternalTraceInformationElement", "x411.InternalTraceInformationElement",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.InternalTraceInformationElement", HFILL }},
    { &hf_x411_TraceInformation_PDU,
      { "TraceInformation", "x411.TraceInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.TraceInformation", HFILL }},
    { &hf_x411_TraceInformationElement_PDU,
      { "TraceInformationElement", "x411.TraceInformationElement",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.TraceInformationElement", HFILL }},
    { &hf_x411_MTSBindArgument_PDU,
      { "MTSBindArgument", "x411.MTSBindArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MTSBindArgument", HFILL }},
    { &hf_x411_MTSBindResult_PDU,
      { "MTSBindResult", "x411.MTSBindResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MTSBindResult", HFILL }},
    { &hf_x411_PAR_mts_bind_error_PDU,
      { "PAR-mts-bind-error", "x411.PAR_mts_bind_error",
        FT_UINT32, BASE_DEC, VALS(x411_PAR_mts_bind_error_vals), 0,
        "x411.PAR_mts_bind_error", HFILL }},
    { &hf_x411_MessageSubmissionArgument_PDU,
      { "MessageSubmissionArgument", "x411.MessageSubmissionArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MessageSubmissionArgument", HFILL }},
    { &hf_x411_MessageSubmissionResult_PDU,
      { "MessageSubmissionResult", "x411.MessageSubmissionResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MessageSubmissionResult", HFILL }},
    { &hf_x411_ProbeSubmissionArgument_PDU,
      { "ProbeSubmissionArgument", "x411.ProbeSubmissionArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ProbeSubmissionArgument", HFILL }},
    { &hf_x411_ProbeSubmissionResult_PDU,
      { "ProbeSubmissionResult", "x411.ProbeSubmissionResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ProbeSubmissionResult", HFILL }},
    { &hf_x411_CancelDeferredDeliveryArgument_PDU,
      { "CancelDeferredDeliveryArgument", "x411.CancelDeferredDeliveryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.CancelDeferredDeliveryArgument", HFILL }},
    { &hf_x411_CancelDeferredDeliveryResult_PDU,
      { "CancelDeferredDeliveryResult", "x411.CancelDeferredDeliveryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.CancelDeferredDeliveryResult", HFILL }},
    { &hf_x411_SubmissionControlArgument_PDU,
      { "SubmissionControlArgument", "x411.SubmissionControlArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.SubmissionControlArgument", HFILL }},
    { &hf_x411_SubmissionControlResult_PDU,
      { "SubmissionControlResult", "x411.SubmissionControlResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.SubmissionControlResult", HFILL }},
    { &hf_x411_PAR_submission_control_violated_PDU,
      { "PAR-submission-control-violated", "x411.PAR_submission_control_violated",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PAR_submission_control_violated", HFILL }},
    { &hf_x411_PAR_element_of_service_not_subscribed_PDU,
      { "PAR-element-of-service-not-subscribed", "x411.PAR_element_of_service_not_subscribed",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PAR_element_of_service_not_subscribed", HFILL }},
    { &hf_x411_PAR_deferred_delivery_cancellation_rejected_PDU,
      { "PAR-deferred-delivery-cancellation-rejected", "x411.PAR_deferred_delivery_cancellation_rejected",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PAR_deferred_delivery_cancellation_rejected", HFILL }},
    { &hf_x411_PAR_originator_invalid_PDU,
      { "PAR-originator-invalid", "x411.PAR_originator_invalid",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PAR_originator_invalid", HFILL }},
    { &hf_x411_ImproperlySpecifiedRecipients_PDU,
      { "ImproperlySpecifiedRecipients", "x411.ImproperlySpecifiedRecipients",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.ImproperlySpecifiedRecipients", HFILL }},
    { &hf_x411_PAR_message_submission_identifier_invalid_PDU,
      { "PAR-message-submission-identifier-invalid", "x411.PAR_message_submission_identifier_invalid",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PAR_message_submission_identifier_invalid", HFILL }},
    { &hf_x411_PAR_inconsistent_request_PDU,
      { "PAR-inconsistent-request", "x411.PAR_inconsistent_request",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PAR_inconsistent_request", HFILL }},
    { &hf_x411_SecurityProblem_PDU,
      { "SecurityProblem", "x411.SecurityProblem",
        FT_UINT32, BASE_DEC, VALS(x411_SecurityProblem_vals), 0,
        "x411.SecurityProblem", HFILL }},
    { &hf_x411_PAR_unsupported_critical_function_PDU,
      { "PAR-unsupported-critical-function", "x411.PAR_unsupported_critical_function",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PAR_unsupported_critical_function", HFILL }},
    { &hf_x411_PAR_remote_bind_error_PDU,
      { "PAR-remote-bind-error", "x411.PAR_remote_bind_error",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PAR_remote_bind_error", HFILL }},
    { &hf_x411_MessageSubmissionTime_PDU,
      { "MessageSubmissionTime", "x411.MessageSubmissionTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.MessageSubmissionTime", HFILL }},
    { &hf_x411_MessageDeliveryArgument_PDU,
      { "MessageDeliveryArgument", "x411.MessageDeliveryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MessageDeliveryArgument", HFILL }},
    { &hf_x411_MessageDeliveryResult_PDU,
      { "MessageDeliveryResult", "x411.MessageDeliveryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MessageDeliveryResult", HFILL }},
    { &hf_x411_ReportDeliveryArgument_PDU,
      { "ReportDeliveryArgument", "x411.ReportDeliveryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ReportDeliveryArgument", HFILL }},
    { &hf_x411_ReportDeliveryResult_PDU,
      { "ReportDeliveryResult", "x411.ReportDeliveryResult",
        FT_UINT32, BASE_DEC, VALS(x411_ReportDeliveryResult_vals), 0,
        "x411.ReportDeliveryResult", HFILL }},
    { &hf_x411_DeliveryControlArgument_PDU,
      { "DeliveryControlArgument", "x411.DeliveryControlArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.DeliveryControlArgument", HFILL }},
    { &hf_x411_DeliveryControlResult_PDU,
      { "DeliveryControlResult", "x411.DeliveryControlResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.DeliveryControlResult", HFILL }},
    { &hf_x411_PAR_delivery_control_violated_PDU,
      { "PAR-delivery-control-violated", "x411.PAR_delivery_control_violated",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PAR_delivery_control_violated", HFILL }},
    { &hf_x411_PAR_control_violates_registration_PDU,
      { "PAR-control-violates-registration", "x411.PAR_control_violates_registration",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PAR_control_violates_registration", HFILL }},
    { &hf_x411_RefusedOperation_PDU,
      { "RefusedOperation", "x411.RefusedOperation",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.RefusedOperation", HFILL }},
    { &hf_x411_RecipientCertificate_PDU,
      { "RecipientCertificate", "x411.RecipientCertificate",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.RecipientCertificate", HFILL }},
    { &hf_x411_ProofOfDelivery_PDU,
      { "ProofOfDelivery", "x411.ProofOfDelivery",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ProofOfDelivery", HFILL }},
    { &hf_x411_RegisterArgument_PDU,
      { "RegisterArgument", "x411.RegisterArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.RegisterArgument", HFILL }},
    { &hf_x411_RegisterResult_PDU,
      { "RegisterResult", "x411.RegisterResult",
        FT_UINT32, BASE_DEC, VALS(x411_RegisterResult_vals), 0,
        "x411.RegisterResult", HFILL }},
    { &hf_x411_ChangeCredentialsArgument_PDU,
      { "ChangeCredentialsArgument", "x411.ChangeCredentialsArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ChangeCredentialsArgument", HFILL }},
    { &hf_x411_RES_change_credentials_PDU,
      { "RES-change-credentials", "x411.RES_change_credentials",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.RES_change_credentials", HFILL }},
    { &hf_x411_PAR_register_rejected_PDU,
      { "PAR-register-rejected", "x411.PAR_register_rejected",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PAR_register_rejected", HFILL }},
    { &hf_x411_PAR_new_credentials_unacceptable_PDU,
      { "PAR-new-credentials-unacceptable", "x411.PAR_new_credentials_unacceptable",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PAR_new_credentials_unacceptable", HFILL }},
    { &hf_x411_PAR_old_credentials_incorrectly_specified_PDU,
      { "PAR-old-credentials-incorrectly-specified", "x411.PAR_old_credentials_incorrectly_specified",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PAR_old_credentials_incorrectly_specified", HFILL }},
    { &hf_x411_MessageSubmissionEnvelope_PDU,
      { "MessageSubmissionEnvelope", "x411.MessageSubmissionEnvelope",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MessageSubmissionEnvelope", HFILL }},
    { &hf_x411_PerRecipientMessageSubmissionFields_PDU,
      { "PerRecipientMessageSubmissionFields", "x411.PerRecipientMessageSubmissionFields",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PerRecipientMessageSubmissionFields", HFILL }},
    { &hf_x411_ProbeSubmissionEnvelope_PDU,
      { "ProbeSubmissionEnvelope", "x411.ProbeSubmissionEnvelope",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ProbeSubmissionEnvelope", HFILL }},
    { &hf_x411_PerRecipientProbeSubmissionFields_PDU,
      { "PerRecipientProbeSubmissionFields", "x411.PerRecipientProbeSubmissionFields",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PerRecipientProbeSubmissionFields", HFILL }},
    { &hf_x411_MessageDeliveryEnvelope_PDU,
      { "MessageDeliveryEnvelope", "x411.MessageDeliveryEnvelope",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MessageDeliveryEnvelope", HFILL }},
    { &hf_x411_ReportDeliveryEnvelope_PDU,
      { "ReportDeliveryEnvelope", "x411.ReportDeliveryEnvelope",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ReportDeliveryEnvelope", HFILL }},
    { &hf_x411_PerRecipientReportDeliveryFields_PDU,
      { "PerRecipientReportDeliveryFields", "x411.PerRecipientReportDeliveryFields",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PerRecipientReportDeliveryFields", HFILL }},
    { &hf_x411_ExtendedContentType_PDU,
      { "ExtendedContentType", "x411.ExtendedContentType",
        FT_OID, BASE_NONE, NULL, 0,
        "x411.ExtendedContentType", HFILL }},
    { &hf_x411_ContentIdentifier_PDU,
      { "ContentIdentifier", "x411.ContentIdentifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.ContentIdentifier", HFILL }},
    { &hf_x411_PerMessageIndicators_PDU,
      { "PerMessageIndicators", "x411.PerMessageIndicators",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.PerMessageIndicators", HFILL }},
    { &hf_x411_OriginatorReportRequest_PDU,
      { "OriginatorReportRequest", "x411.OriginatorReportRequest",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.OriginatorReportRequest", HFILL }},
    { &hf_x411_DeferredDeliveryTime_PDU,
      { "DeferredDeliveryTime", "x411.DeferredDeliveryTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.DeferredDeliveryTime", HFILL }},
    { &hf_x411_Priority_PDU,
      { "Priority", "x411.Priority",
        FT_UINT32, BASE_DEC, VALS(x411_Priority_U_vals), 0,
        "x411.Priority", HFILL }},
    { &hf_x411_ContentLength_PDU,
      { "ContentLength", "x411.ContentLength",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.ContentLength", HFILL }},
    { &hf_x411_MessageDeliveryTime_PDU,
      { "MessageDeliveryTime", "x411.MessageDeliveryTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.MessageDeliveryTime", HFILL }},
    { &hf_x411_DeliveryFlags_PDU,
      { "DeliveryFlags", "x411.DeliveryFlags",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.DeliveryFlags", HFILL }},
    { &hf_x411_SubjectSubmissionIdentifier_PDU,
      { "SubjectSubmissionIdentifier", "x411.SubjectSubmissionIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.SubjectSubmissionIdentifier", HFILL }},
    { &hf_x411_RecipientReassignmentProhibited_PDU,
      { "RecipientReassignmentProhibited", "x411.RecipientReassignmentProhibited",
        FT_UINT32, BASE_DEC, VALS(x411_RecipientReassignmentProhibited_vals), 0,
        "x411.RecipientReassignmentProhibited", HFILL }},
    { &hf_x411_OriginatorRequestedAlternateRecipient_PDU,
      { "OriginatorRequestedAlternateRecipient", "x411.OriginatorRequestedAlternateRecipient",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.OriginatorRequestedAlternateRecipient", HFILL }},
    { &hf_x411_DLExpansionProhibited_PDU,
      { "DLExpansionProhibited", "x411.DLExpansionProhibited",
        FT_UINT32, BASE_DEC, VALS(x411_DLExpansionProhibited_vals), 0,
        "x411.DLExpansionProhibited", HFILL }},
    { &hf_x411_ConversionWithLossProhibited_PDU,
      { "ConversionWithLossProhibited", "x411.ConversionWithLossProhibited",
        FT_UINT32, BASE_DEC, VALS(x411_ConversionWithLossProhibited_vals), 0,
        "x411.ConversionWithLossProhibited", HFILL }},
    { &hf_x411_LatestDeliveryTime_PDU,
      { "LatestDeliveryTime", "x411.LatestDeliveryTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.LatestDeliveryTime", HFILL }},
    { &hf_x411_RequestedDeliveryMethod_PDU,
      { "RequestedDeliveryMethod", "x411.RequestedDeliveryMethod",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.RequestedDeliveryMethod", HFILL }},
    { &hf_x411_PhysicalForwardingProhibited_PDU,
      { "PhysicalForwardingProhibited", "x411.PhysicalForwardingProhibited",
        FT_UINT32, BASE_DEC, VALS(x411_PhysicalForwardingProhibited_vals), 0,
        "x411.PhysicalForwardingProhibited", HFILL }},
    { &hf_x411_PhysicalForwardingAddressRequest_PDU,
      { "PhysicalForwardingAddressRequest", "x411.PhysicalForwardingAddressRequest",
        FT_UINT32, BASE_DEC, VALS(x411_PhysicalForwardingAddressRequest_vals), 0,
        "x411.PhysicalForwardingAddressRequest", HFILL }},
    { &hf_x411_PhysicalDeliveryModes_PDU,
      { "PhysicalDeliveryModes", "x411.PhysicalDeliveryModes",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.PhysicalDeliveryModes", HFILL }},
    { &hf_x411_RegisteredMailType_PDU,
      { "RegisteredMailType", "x411.RegisteredMailType",
        FT_UINT32, BASE_DEC, VALS(x411_RegisteredMailType_vals), 0,
        "x411.RegisteredMailType", HFILL }},
    { &hf_x411_RecipientNumberForAdvice_PDU,
      { "RecipientNumberForAdvice", "x411.RecipientNumberForAdvice",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.RecipientNumberForAdvice", HFILL }},
    { &hf_x411_PhysicalRenditionAttributes_PDU,
      { "PhysicalRenditionAttributes", "x411.PhysicalRenditionAttributes",
        FT_OID, BASE_NONE, NULL, 0,
        "x411.PhysicalRenditionAttributes", HFILL }},
    { &hf_x411_OriginatorReturnAddress_PDU,
      { "OriginatorReturnAddress", "x411.OriginatorReturnAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.OriginatorReturnAddress", HFILL }},
    { &hf_x411_PhysicalDeliveryReportRequest_PDU,
      { "PhysicalDeliveryReportRequest", "x411.PhysicalDeliveryReportRequest",
        FT_UINT32, BASE_DEC, VALS(x411_PhysicalDeliveryReportRequest_vals), 0,
        "x411.PhysicalDeliveryReportRequest", HFILL }},
    { &hf_x411_OriginatorCertificate_PDU,
      { "OriginatorCertificate", "x411.OriginatorCertificate",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.OriginatorCertificate", HFILL }},
    { &hf_x411_MessageToken_PDU,
      { "MessageToken", "x411.MessageToken",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MessageToken", HFILL }},
    { &hf_x411_ContentConfidentialityAlgorithmIdentifier_PDU,
      { "ContentConfidentialityAlgorithmIdentifier", "x411.ContentConfidentialityAlgorithmIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ContentConfidentialityAlgorithmIdentifier", HFILL }},
    { &hf_x411_ContentIntegrityCheck_PDU,
      { "ContentIntegrityCheck", "x411.ContentIntegrityCheck",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ContentIntegrityCheck", HFILL }},
    { &hf_x411_MessageOriginAuthenticationCheck_PDU,
      { "MessageOriginAuthenticationCheck", "x411.MessageOriginAuthenticationCheck",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MessageOriginAuthenticationCheck", HFILL }},
    { &hf_x411_MessageSecurityLabel_PDU,
      { "MessageSecurityLabel", "x411.MessageSecurityLabel",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MessageSecurityLabel", HFILL }},
    { &hf_x411_ProofOfSubmissionRequest_PDU,
      { "ProofOfSubmissionRequest", "x411.ProofOfSubmissionRequest",
        FT_UINT32, BASE_DEC, VALS(x411_ProofOfSubmissionRequest_vals), 0,
        "x411.ProofOfSubmissionRequest", HFILL }},
    { &hf_x411_ProofOfDeliveryRequest_PDU,
      { "ProofOfDeliveryRequest", "x411.ProofOfDeliveryRequest",
        FT_UINT32, BASE_DEC, VALS(x411_ProofOfDeliveryRequest_vals), 0,
        "x411.ProofOfDeliveryRequest", HFILL }},
    { &hf_x411_ContentCorrelator_PDU,
      { "ContentCorrelator", "x411.ContentCorrelator",
        FT_UINT32, BASE_DEC, VALS(x411_ContentCorrelator_vals), 0,
        "x411.ContentCorrelator", HFILL }},
    { &hf_x411_ProbeOriginAuthenticationCheck_PDU,
      { "ProbeOriginAuthenticationCheck", "x411.ProbeOriginAuthenticationCheck",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ProbeOriginAuthenticationCheck", HFILL }},
    { &hf_x411_RedirectionHistory_PDU,
      { "RedirectionHistory", "x411.RedirectionHistory",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.RedirectionHistory", HFILL }},
    { &hf_x411_Redirection_PDU,
      { "Redirection", "x411.Redirection",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.Redirection", HFILL }},
    { &hf_x411_DLExpansionHistory_PDU,
      { "DLExpansionHistory", "x411.DLExpansionHistory",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.DLExpansionHistory", HFILL }},
    { &hf_x411_DLExpansion_PDU,
      { "DLExpansion", "x411.DLExpansion",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.DLExpansion", HFILL }},
    { &hf_x411_PhysicalForwardingAddress_PDU,
      { "PhysicalForwardingAddress", "x411.PhysicalForwardingAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PhysicalForwardingAddress", HFILL }},
    { &hf_x411_OriginatorAndDLExpansionHistory_PDU,
      { "OriginatorAndDLExpansionHistory", "x411.OriginatorAndDLExpansionHistory",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.OriginatorAndDLExpansionHistory", HFILL }},
    { &hf_x411_ReportingDLName_PDU,
      { "ReportingDLName", "x411.ReportingDLName",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ReportingDLName", HFILL }},
    { &hf_x411_ReportingMTACertificate_PDU,
      { "ReportingMTACertificate", "x411.ReportingMTACertificate",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ReportingMTACertificate", HFILL }},
    { &hf_x411_ReportOriginAuthenticationCheck_PDU,
      { "ReportOriginAuthenticationCheck", "x411.ReportOriginAuthenticationCheck",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ReportOriginAuthenticationCheck", HFILL }},
    { &hf_x411_OriginatingMTACertificate_PDU,
      { "OriginatingMTACertificate", "x411.OriginatingMTACertificate",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.OriginatingMTACertificate", HFILL }},
    { &hf_x411_ProofOfSubmission_PDU,
      { "ProofOfSubmission", "x411.ProofOfSubmission",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ProofOfSubmission", HFILL }},
    { &hf_x411_ReportingMTAName_PDU,
      { "ReportingMTAName", "x411.ReportingMTAName",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ReportingMTAName", HFILL }},
    { &hf_x411_ExtendedCertificates_PDU,
      { "ExtendedCertificates", "x411.ExtendedCertificates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.ExtendedCertificates", HFILL }},
    { &hf_x411_DLExemptedRecipients_PDU,
      { "DLExemptedRecipients", "x411.DLExemptedRecipients",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.DLExemptedRecipients", HFILL }},
    { &hf_x411_CertificateSelectors_PDU,
      { "CertificateSelectors", "x411.CertificateSelectors",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.CertificateSelectors", HFILL }},
    { &hf_x411_Content_PDU,
      { "Content", "x411.Content",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.Content", HFILL }},
    { &hf_x411_MTSIdentifier_PDU,
      { "MTSIdentifier", "x411.MTSIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MTSIdentifier", HFILL }},
    { &hf_x411_ORName_PDU,
      { "ORName", "x411.ORName",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ORName", HFILL }},
    { &hf_x411_ORAddress_PDU,
      { "ORAddress", "x411.ORAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ORAddress", HFILL }},
    { &hf_x411_CommonName_PDU,
      { "CommonName", "x411.CommonName",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.CommonName", HFILL }},
    { &hf_x411_TeletexCommonName_PDU,
      { "TeletexCommonName", "x411.TeletexCommonName",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.TeletexCommonName", HFILL }},
    { &hf_x411_UniversalCommonName_PDU,
      { "UniversalCommonName", "x411.UniversalCommonName",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.UniversalCommonName", HFILL }},
    { &hf_x411_TeletexOrganizationName_PDU,
      { "TeletexOrganizationName", "x411.TeletexOrganizationName",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.TeletexOrganizationName", HFILL }},
    { &hf_x411_UniversalOrganizationName_PDU,
      { "UniversalOrganizationName", "x411.UniversalOrganizationName",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.UniversalOrganizationName", HFILL }},
    { &hf_x411_TeletexPersonalName_PDU,
      { "TeletexPersonalName", "x411.TeletexPersonalName",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.TeletexPersonalName", HFILL }},
    { &hf_x411_UniversalPersonalName_PDU,
      { "UniversalPersonalName", "x411.UniversalPersonalName",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.UniversalPersonalName", HFILL }},
    { &hf_x411_TeletexOrganizationalUnitNames_PDU,
      { "TeletexOrganizationalUnitNames", "x411.TeletexOrganizationalUnitNames",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.TeletexOrganizationalUnitNames", HFILL }},
    { &hf_x411_UniversalOrganizationalUnitNames_PDU,
      { "UniversalOrganizationalUnitNames", "x411.UniversalOrganizationalUnitNames",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.UniversalOrganizationalUnitNames", HFILL }},
    { &hf_x411_PDSName_PDU,
      { "PDSName", "x411.PDSName",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.PDSName", HFILL }},
    { &hf_x411_PhysicalDeliveryCountryName_PDU,
      { "PhysicalDeliveryCountryName", "x411.PhysicalDeliveryCountryName",
        FT_UINT32, BASE_DEC, VALS(x411_PhysicalDeliveryCountryName_vals), 0,
        "x411.PhysicalDeliveryCountryName", HFILL }},
    { &hf_x411_PostalCode_PDU,
      { "PostalCode", "x411.PostalCode",
        FT_UINT32, BASE_DEC, VALS(x411_PostalCode_vals), 0,
        "x411.PostalCode", HFILL }},
    { &hf_x411_PhysicalDeliveryOfficeName_PDU,
      { "PhysicalDeliveryOfficeName", "x411.PhysicalDeliveryOfficeName",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PhysicalDeliveryOfficeName", HFILL }},
    { &hf_x411_UniversalPhysicalDeliveryOfficeName_PDU,
      { "UniversalPhysicalDeliveryOfficeName", "x411.UniversalPhysicalDeliveryOfficeName",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.UniversalPhysicalDeliveryOfficeName", HFILL }},
    { &hf_x411_PhysicalDeliveryOfficeNumber_PDU,
      { "PhysicalDeliveryOfficeNumber", "x411.PhysicalDeliveryOfficeNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PhysicalDeliveryOfficeNumber", HFILL }},
    { &hf_x411_UniversalPhysicalDeliveryOfficeNumber_PDU,
      { "UniversalPhysicalDeliveryOfficeNumber", "x411.UniversalPhysicalDeliveryOfficeNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.UniversalPhysicalDeliveryOfficeNumber", HFILL }},
    { &hf_x411_ExtensionORAddressComponents_PDU,
      { "ExtensionORAddressComponents", "x411.ExtensionORAddressComponents",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ExtensionORAddressComponents", HFILL }},
    { &hf_x411_UniversalExtensionORAddressComponents_PDU,
      { "UniversalExtensionORAddressComponents", "x411.UniversalExtensionORAddressComponents",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.UniversalExtensionORAddressComponents", HFILL }},
    { &hf_x411_PhysicalDeliveryPersonalName_PDU,
      { "PhysicalDeliveryPersonalName", "x411.PhysicalDeliveryPersonalName",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PhysicalDeliveryPersonalName", HFILL }},
    { &hf_x411_UniversalPhysicalDeliveryPersonalName_PDU,
      { "UniversalPhysicalDeliveryPersonalName", "x411.UniversalPhysicalDeliveryPersonalName",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.UniversalPhysicalDeliveryPersonalName", HFILL }},
    { &hf_x411_PhysicalDeliveryOrganizationName_PDU,
      { "PhysicalDeliveryOrganizationName", "x411.PhysicalDeliveryOrganizationName",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PhysicalDeliveryOrganizationName", HFILL }},
    { &hf_x411_UniversalPhysicalDeliveryOrganizationName_PDU,
      { "UniversalPhysicalDeliveryOrganizationName", "x411.UniversalPhysicalDeliveryOrganizationName",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.UniversalPhysicalDeliveryOrganizationName", HFILL }},
    { &hf_x411_ExtensionPhysicalDeliveryAddressComponents_PDU,
      { "ExtensionPhysicalDeliveryAddressComponents", "x411.ExtensionPhysicalDeliveryAddressComponents",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ExtensionPhysicalDeliveryAddressComponents", HFILL }},
    { &hf_x411_UniversalExtensionPhysicalDeliveryAddressComponents_PDU,
      { "UniversalExtensionPhysicalDeliveryAddressComponents", "x411.UniversalExtensionPhysicalDeliveryAddressComponents",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.UniversalExtensionPhysicalDeliveryAddressComponents", HFILL }},
    { &hf_x411_UnformattedPostalAddress_PDU,
      { "UnformattedPostalAddress", "x411.UnformattedPostalAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.UnformattedPostalAddress", HFILL }},
    { &hf_x411_UniversalUnformattedPostalAddress_PDU,
      { "UniversalUnformattedPostalAddress", "x411.UniversalUnformattedPostalAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.UniversalUnformattedPostalAddress", HFILL }},
    { &hf_x411_StreetAddress_PDU,
      { "StreetAddress", "x411.StreetAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.StreetAddress", HFILL }},
    { &hf_x411_UniversalStreetAddress_PDU,
      { "UniversalStreetAddress", "x411.UniversalStreetAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.UniversalStreetAddress", HFILL }},
    { &hf_x411_PostOfficeBoxAddress_PDU,
      { "PostOfficeBoxAddress", "x411.PostOfficeBoxAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PostOfficeBoxAddress", HFILL }},
    { &hf_x411_UniversalPostOfficeBoxAddress_PDU,
      { "UniversalPostOfficeBoxAddress", "x411.UniversalPostOfficeBoxAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.UniversalPostOfficeBoxAddress", HFILL }},
    { &hf_x411_PosteRestanteAddress_PDU,
      { "PosteRestanteAddress", "x411.PosteRestanteAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PosteRestanteAddress", HFILL }},
    { &hf_x411_UniversalPosteRestanteAddress_PDU,
      { "UniversalPosteRestanteAddress", "x411.UniversalPosteRestanteAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.UniversalPosteRestanteAddress", HFILL }},
    { &hf_x411_UniquePostalName_PDU,
      { "UniquePostalName", "x411.UniquePostalName",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.UniquePostalName", HFILL }},
    { &hf_x411_UniversalUniquePostalName_PDU,
      { "UniversalUniquePostalName", "x411.UniversalUniquePostalName",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.UniversalUniquePostalName", HFILL }},
    { &hf_x411_LocalPostalAttributes_PDU,
      { "LocalPostalAttributes", "x411.LocalPostalAttributes",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.LocalPostalAttributes", HFILL }},
    { &hf_x411_UniversalLocalPostalAttributes_PDU,
      { "UniversalLocalPostalAttributes", "x411.UniversalLocalPostalAttributes",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.UniversalLocalPostalAttributes", HFILL }},
    { &hf_x411_ExtendedNetworkAddress_PDU,
      { "ExtendedNetworkAddress", "x411.ExtendedNetworkAddress",
        FT_UINT32, BASE_DEC, VALS(x411_ExtendedNetworkAddress_vals), 0,
        "x411.ExtendedNetworkAddress", HFILL }},
    { &hf_x411_TerminalType_PDU,
      { "TerminalType", "x411.TerminalType",
        FT_UINT32, BASE_DEC, VALS(x411_TerminalType_vals), 0,
        "x411.TerminalType", HFILL }},
    { &hf_x411_TeletexDomainDefinedAttributes_PDU,
      { "TeletexDomainDefinedAttributes", "x411.TeletexDomainDefinedAttributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.TeletexDomainDefinedAttributes", HFILL }},
    { &hf_x411_UniversalDomainDefinedAttributes_PDU,
      { "UniversalDomainDefinedAttributes", "x411.UniversalDomainDefinedAttributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.UniversalDomainDefinedAttributes", HFILL }},
    { &hf_x411_ExtendedEncodedInformationType_PDU,
      { "ExtendedEncodedInformationType", "x411.ExtendedEncodedInformationType",
        FT_OID, BASE_NONE, NULL, 0,
        "x411.ExtendedEncodedInformationType", HFILL }},
    { &hf_x411_MTANameAndOptionalGDI_PDU,
      { "MTANameAndOptionalGDI", "x411.MTANameAndOptionalGDI",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MTANameAndOptionalGDI", HFILL }},
    { &hf_x411_AsymmetricToken_PDU,
      { "AsymmetricToken", "x411.AsymmetricToken",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.AsymmetricToken", HFILL }},
    { &hf_x411_BindTokenSignedData_PDU,
      { "BindTokenSignedData", "x411.BindTokenSignedData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.BindTokenSignedData", HFILL }},
    { &hf_x411_MessageTokenSignedData_PDU,
      { "MessageTokenSignedData", "x411.MessageTokenSignedData",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MessageTokenSignedData", HFILL }},
    { &hf_x411_MessageTokenEncryptedData_PDU,
      { "MessageTokenEncryptedData", "x411.MessageTokenEncryptedData",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MessageTokenEncryptedData", HFILL }},
    { &hf_x411_BindTokenEncryptedData_PDU,
      { "BindTokenEncryptedData", "x411.BindTokenEncryptedData",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.BindTokenEncryptedData", HFILL }},
    { &hf_x411_SecurityClassification_PDU,
      { "SecurityClassification", "x411.SecurityClassification",
        FT_UINT32, BASE_DEC, VALS(x411_SecurityClassification_vals), 0,
        "x411.SecurityClassification", HFILL }},
    { &hf_x411_unauthenticated,
      { "unauthenticated", "x411.unauthenticated",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.NULL", HFILL }},
    { &hf_x411_authenticated_argument,
      { "authenticated", "x411.authenticated",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.AuthenticatedArgument", HFILL }},
    { &hf_x411_authenticated_initiator_name,
      { "initiator-name", "x411.initiator_name",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.MTAName", HFILL }},
    { &hf_x411_initiator_credentials,
      { "initiator-credentials", "x411.initiator_credentials",
        FT_UINT32, BASE_DEC, VALS(x411_Credentials_vals), 0,
        "x411.InitiatorCredentials", HFILL }},
    { &hf_x411_security_context,
      { "security-context", "x411.security_context",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.SecurityContext", HFILL }},
    { &hf_x411_authenticated_result,
      { "authenticated", "x411.authenticated",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.AuthenticatedResult", HFILL }},
    { &hf_x411_authenticated_responder_name,
      { "responder-name", "x411.responder_name",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.MTAName", HFILL }},
    { &hf_x411_responder_credentials,
      { "responder-credentials", "x411.responder_credentials",
        FT_UINT32, BASE_DEC, VALS(x411_Credentials_vals), 0,
        "x411.ResponderCredentials", HFILL }},
    { &hf_x411_message,
      { "message", "x411.message",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.Message", HFILL }},
    { &hf_x411_probe,
      { "probe", "x411.probe",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.Probe", HFILL }},
    { &hf_x411_report,
      { "report", "x411.report",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.Report", HFILL }},
    { &hf_x411_message_envelope,
      { "envelope", "x411.envelope",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MessageTransferEnvelope", HFILL }},
    { &hf_x411_content,
      { "content", "x411.content",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.Content", HFILL }},
    { &hf_x411_report_envelope,
      { "envelope", "x411.envelope",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ReportTransferEnvelope", HFILL }},
    { &hf_x411_report_content,
      { "content", "x411.content",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ReportTransferContent", HFILL }},
    { &hf_x411_message_identifier,
      { "message-identifier", "x411.message_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MessageIdentifier", HFILL }},
    { &hf_x411_originator_name,
      { "originator-name", "x411.originator_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MTAOriginatorName", HFILL }},
    { &hf_x411_original_encoded_information_types,
      { "original-encoded-information-types", "x411.original_encoded_information_types",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.OriginalEncodedInformationTypes", HFILL }},
    { &hf_x411_content_type,
      { "content-type", "x411.content_type",
        FT_UINT32, BASE_DEC, VALS(x411_ContentType_vals), 0,
        "x411.ContentType", HFILL }},
    { &hf_x411_content_identifier,
      { "content-identifier", "x411.content_identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.ContentIdentifier", HFILL }},
    { &hf_x411_priority,
      { "priority", "x411.priority",
        FT_UINT32, BASE_DEC, VALS(x411_Priority_U_vals), 0,
        "x411.Priority", HFILL }},
    { &hf_x411_per_message_indicators,
      { "per-message-indicators", "x411.per_message_indicators",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.PerMessageIndicators", HFILL }},
    { &hf_x411_deferred_delivery_time,
      { "deferred-delivery-time", "x411.deferred_delivery_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.DeferredDeliveryTime", HFILL }},
    { &hf_x411_per_domain_bilateral_information,
      { "per-domain-bilateral-information", "x411.per_domain_bilateral_information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.SEQUENCE_SIZE_1_ub_transfers_OF_PerDomainBilateralInformation", HFILL }},
    { &hf_x411_per_domain_bilateral_information_item,
      { "PerDomainBilateralInformation", "x411.PerDomainBilateralInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PerDomainBilateralInformation", HFILL }},
    { &hf_x411_trace_information,
      { "trace-information", "x411.trace_information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.TraceInformation", HFILL }},
    { &hf_x411_extensions,
      { "extensions", "x411.extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.SET_OF_ExtensionField", HFILL }},
    { &hf_x411_extensions_item,
      { "ExtensionField", "x411.ExtensionField",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ExtensionField", HFILL }},
    { &hf_x411_recipient_name,
      { "recipient-name", "x411.recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MTARecipientName", HFILL }},
    { &hf_x411_originally_specified_recipient_number,
      { "originally-specified-recipient-number", "x411.originally_specified_recipient_number",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.OriginallySpecifiedRecipientNumber", HFILL }},
    { &hf_x411_per_recipient_indicators,
      { "per-recipient-indicators", "x411.per_recipient_indicators",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.PerRecipientIndicators", HFILL }},
    { &hf_x411_explicit_conversion,
      { "explicit-conversion", "x411.explicit_conversion",
        FT_UINT32, BASE_DEC, VALS(x411_ExplicitConversion_vals), 0,
        "x411.ExplicitConversion", HFILL }},
    { &hf_x411_probe_identifier,
      { "probe-identifier", "x411.probe_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ProbeIdentifier", HFILL }},
    { &hf_x411_content_length,
      { "content-length", "x411.content_length",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.ContentLength", HFILL }},
    { &hf_x411_report_identifier,
      { "report-identifier", "x411.report_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ReportIdentifier", HFILL }},
    { &hf_x411_report_destination_name,
      { "report-destination-name", "x411.report_destination_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ReportDestinationName", HFILL }},
    { &hf_x411_subject_identifier,
      { "subject-identifier", "x411.subject_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.SubjectIdentifier", HFILL }},
    { &hf_x411_subject_intermediate_trace_information,
      { "subject-intermediate-trace-information", "x411.subject_intermediate_trace_information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.SubjectIntermediateTraceInformation", HFILL }},
    { &hf_x411_returned_content,
      { "returned-content", "x411.returned_content",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.Content", HFILL }},
    { &hf_x411_additional_information,
      { "additional-information", "x411.additional_information",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.AdditionalInformation", HFILL }},
    { &hf_x411_mta_actual_recipient_name,
      { "actual-recipient-name", "x411.actual_recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MTAActualRecipientName", HFILL }},
    { &hf_x411_last_trace_information,
      { "last-trace-information", "x411.last_trace_information",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.LastTraceInformation", HFILL }},
    { &hf_x411_report_originally_intended_recipient_name,
      { "originally-intended-recipient-name", "x411.originally_intended_recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.OriginallyIntendedRecipientName", HFILL }},
    { &hf_x411_supplementary_information,
      { "supplementary-information", "x411.supplementary_information",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.SupplementaryInformation", HFILL }},
    { &hf_x411_country_name,
      { "country-name", "x411.country_name",
        FT_UINT32, BASE_DEC, VALS(x411_CountryName_U_vals), 0,
        "x411.CountryName", HFILL }},
    { &hf_x411_bilateral_domain,
      { "domain", "x411.domain",
        FT_UINT32, BASE_DEC, VALS(x411_T_bilateral_domain_vals), 0,
        "x411.T_bilateral_domain", HFILL }},
    { &hf_x411_administration_domain_name,
      { "administration-domain-name", "x411.administration_domain_name",
        FT_UINT32, BASE_DEC, VALS(x411_AdministrationDomainName_U_vals), 0,
        "x411.AdministrationDomainName", HFILL }},
    { &hf_x411_private_domain,
      { "private-domain", "x411.private_domain",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.T_private_domain", HFILL }},
    { &hf_x411_private_domain_identifier,
      { "private-domain-identifier", "x411.private_domain_identifier",
        FT_UINT32, BASE_DEC, VALS(x411_PrivateDomainIdentifier_vals), 0,
        "x411.PrivateDomainIdentifier", HFILL }},
    { &hf_x411_bilateral_information,
      { "bilateral-information", "x411.bilateral_information",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.T_bilateral_information", HFILL }},
    { &hf_x411_domain,
      { "domain", "x411.domain",
        FT_UINT32, BASE_DEC, VALS(x411_T_domain_vals), 0,
        "x411.T_domain", HFILL }},
    { &hf_x411_private_domain_01,
      { "private-domain", "x411.private_domain",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.T_private_domain_01", HFILL }},
    { &hf_x411_arrival_time,
      { "arrival-time", "x411.arrival_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.ArrivalTime", HFILL }},
    { &hf_x411_converted_encoded_information_types,
      { "converted-encoded-information-types", "x411.converted_encoded_information_types",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ConvertedEncodedInformationTypes", HFILL }},
    { &hf_x411_trace_report_type,
      { "report-type", "x411.report_type",
        FT_UINT32, BASE_DEC, VALS(x411_ReportType_vals), 0,
        "x411.ReportType", HFILL }},
    { &hf_x411_InternalTraceInformation_item,
      { "InternalTraceInformationElement", "x411.InternalTraceInformationElement",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.InternalTraceInformationElement", HFILL }},
    { &hf_x411_global_domain_identifier,
      { "global-domain-identifier", "x411.global_domain_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.GlobalDomainIdentifier", HFILL }},
    { &hf_x411_mta_name,
      { "mta-name", "x411.mta_name",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.MTAName", HFILL }},
    { &hf_x411_mta_supplied_information,
      { "mta-supplied-information", "x411.mta_supplied_information",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MTASuppliedInformation", HFILL }},
    { &hf_x411__untag_item,
      { "TraceInformationElement", "x411.TraceInformationElement",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.TraceInformationElement", HFILL }},
    { &hf_x411_domain_supplied_information,
      { "domain-supplied-information", "x411.domain_supplied_information",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.DomainSuppliedInformation", HFILL }},
    { &hf_x411_deferred_time,
      { "deferred-time", "x411.deferred_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.DeferredTime", HFILL }},
    { &hf_x411_other_actions,
      { "other-actions", "x411.other_actions",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.OtherActions", HFILL }},
    { &hf_x411_initiator_name,
      { "initiator-name", "x411.initiator_name",
        FT_UINT32, BASE_DEC, VALS(x411_ObjectName_vals), 0,
        "x411.ObjectName", HFILL }},
    { &hf_x411_messages_waiting,
      { "messages-waiting", "x411.messages_waiting",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MessagesWaiting", HFILL }},
    { &hf_x411_responder_name,
      { "responder-name", "x411.responder_name",
        FT_UINT32, BASE_DEC, VALS(x411_ObjectName_vals), 0,
        "x411.ObjectName", HFILL }},
    { &hf_x411_user_agent,
      { "user-agent", "x411.user_agent",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ORAddressAndOptionalDirectoryName", HFILL }},
    { &hf_x411_mTA,
      { "mTA", "x411.mTA",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.MTAName", HFILL }},
    { &hf_x411_message_store,
      { "message-store", "x411.message_store",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ORAddressAndOptionalDirectoryName", HFILL }},
    { &hf_x411_urgent,
      { "urgent", "x411.urgent",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.DeliveryQueue", HFILL }},
    { &hf_x411_normal,
      { "normal", "x411.normal",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.DeliveryQueue", HFILL }},
    { &hf_x411_non_urgent,
      { "non-urgent", "x411.non_urgent",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.DeliveryQueue", HFILL }},
    { &hf_x411_messages,
      { "messages", "x411.messages",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.INTEGER_0_ub_queue_size", HFILL }},
    { &hf_x411_delivery_queue_octets,
      { "octets", "x411.octets",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.INTEGER_0_ub_content_length", HFILL }},
    { &hf_x411_simple,
      { "simple", "x411.simple",
        FT_UINT32, BASE_DEC, VALS(x411_Password_vals), 0,
        "x411.Password", HFILL }},
    { &hf_x411_strong,
      { "strong", "x411.strong",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.StrongCredentials", HFILL }},
    { &hf_x411_protected,
      { "protected", "x411.protected",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ProtectedPassword", HFILL }},
    { &hf_x411_ia5_string,
      { "ia5-string", "x411.ia5_string",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.IA5String_SIZE_0_ub_password_length", HFILL }},
    { &hf_x411_octet_string,
      { "octet-string", "x411.octet_string",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.OCTET_STRING_SIZE_0_ub_password_length", HFILL }},
    { &hf_x411_bind_token,
      { "bind-token", "x411.bind_token",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.Token", HFILL }},
    { &hf_x411_certificate,
      { "certificate", "x411.certificate",
        FT_NONE, BASE_NONE, NULL, 0,
        "x509af.Certificates", HFILL }},
    { &hf_x411_certificate_selector,
      { "certificate-selector", "x411.certificate_selector",
        FT_NONE, BASE_NONE, NULL, 0,
        "x509ce.CertificateAssertion", HFILL }},
    { &hf_x411_signature,
      { "signature", "x411.signature",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.Signature", HFILL }},
    { &hf_x411_time1,
      { "time1", "x411.time1",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.UTCTime", HFILL }},
    { &hf_x411_time2,
      { "time2", "x411.time2",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.UTCTime", HFILL }},
    { &hf_x411_random1,
      { "random1", "x411.random1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.BIT_STRING", HFILL }},
    { &hf_x411_random2,
      { "random2", "x411.random2",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.BIT_STRING", HFILL }},
    { &hf_x411_algorithmIdentifier,
      { "algorithmIdentifier", "x411.algorithmIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "x509af.AlgorithmIdentifier", HFILL }},
    { &hf_x411_encrypted,
      { "encrypted", "x411.encrypted",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.BIT_STRING", HFILL }},
    { &hf_x411_SecurityContext_item,
      { "SecurityLabel", "x411.SecurityLabel",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.SecurityLabel", HFILL }},
    { &hf_x411_message_submission_envelope,
      { "envelope", "x411.envelope",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MessageSubmissionEnvelope", HFILL }},
    { &hf_x411_message_submission_identifier,
      { "message-submission-identifier", "x411.message_submission_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MessageSubmissionIdentifier", HFILL }},
    { &hf_x411_message_submission_time,
      { "message-submission-time", "x411.message_submission_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.MessageSubmissionTime", HFILL }},
    { &hf_x411_probe_submission_identifier,
      { "probe-submission-identifier", "x411.probe_submission_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ProbeSubmissionIdentifier", HFILL }},
    { &hf_x411_probe_submission_time,
      { "probe-submission-time", "x411.probe_submission_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.ProbeSubmissionTime", HFILL }},
    { &hf_x411_ImproperlySpecifiedRecipients_item,
      { "RecipientName", "x411.RecipientName",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.RecipientName", HFILL }},
    { &hf_x411_waiting_operations,
      { "waiting-operations", "x411.waiting_operations",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.Operations", HFILL }},
    { &hf_x411_waiting_messages,
      { "waiting-messages", "x411.waiting_messages",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.WaitingMessages", HFILL }},
    { &hf_x411_waiting_content_types,
      { "waiting-content-types", "x411.waiting_content_types",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.SET_SIZE_0_ub_content_types_OF_ContentType", HFILL }},
    { &hf_x411_waiting_content_types_item,
      { "ContentType", "x411.ContentType",
        FT_UINT32, BASE_DEC, VALS(x411_ContentType_vals), 0,
        "x411.ContentType", HFILL }},
    { &hf_x411_waiting_encoded_information_types,
      { "waiting-encoded-information-types", "x411.waiting_encoded_information_types",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.EncodedInformationTypes", HFILL }},
    { &hf_x411_recipient_certificate,
      { "recipient-certificate", "x411.recipient_certificate",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.RecipientCertificate", HFILL }},
    { &hf_x411_proof_of_delivery,
      { "proof-of-delivery", "x411.proof_of_delivery",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ProofOfDelivery", HFILL }},
    { &hf_x411_empty_result,
      { "empty-result", "x411.empty_result",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.NULL", HFILL }},
    { &hf_x411_max_extensions,
      { "extensions", "x411.extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.SET_SIZE_1_MAX_OF_ExtensionField", HFILL }},
    { &hf_x411_max_extensions_item,
      { "ExtensionField", "x411.ExtensionField",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ExtensionField", HFILL }},
    { &hf_x411_restrict,
      { "restrict", "x411.restrict",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "x411.BOOLEAN", HFILL }},
    { &hf_x411_permissible_operations,
      { "permissible-operations", "x411.permissible_operations",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.Operations", HFILL }},
    { &hf_x411_permissible_maximum_content_length,
      { "permissible-maximum-content-length", "x411.permissible_maximum_content_length",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.ContentLength", HFILL }},
    { &hf_x411_permissible_lowest_priority,
      { "permissible-lowest-priority", "x411.permissible_lowest_priority",
        FT_UINT32, BASE_DEC, VALS(x411_Priority_U_vals), 0,
        "x411.Priority", HFILL }},
    { &hf_x411_permissible_content_types,
      { "permissible-content-types", "x411.permissible_content_types",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.ContentTypes", HFILL }},
    { &hf_x411_permissible_encoded_information_types,
      { "permissible-encoded-information-types", "x411.permissible_encoded_information_types",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PermissibleEncodedInformationTypes", HFILL }},
    { &hf_x411_permissible_security_context,
      { "permissible-security-context", "x411.permissible_security_context",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.SecurityContext", HFILL }},
    { &hf_x411_refused_argument,
      { "refused-argument", "x411.refused_argument",
        FT_UINT32, BASE_DEC, VALS(x411_T_refused_argument_vals), 0,
        "x411.T_refused_argument", HFILL }},
    { &hf_x411_built_in_argument,
      { "built-in-argument", "x411.built_in_argument",
        FT_UINT32, BASE_DEC, VALS(x411_RefusedArgument_vals), 0,
        "x411.RefusedArgument", HFILL }},
    { &hf_x411_refused_extension,
      { "refused-extension", "x411.refused_extension",
        FT_UINT32, BASE_DEC, VALS(x411_ExtensionType_vals), 0,
        "x411.T_refused_extension", HFILL }},
    { &hf_x411_refusal_reason,
      { "refusal-reason", "x411.refusal_reason",
        FT_UINT32, BASE_DEC, VALS(x411_RefusalReason_vals), 0,
        "x411.RefusalReason", HFILL }},
    { &hf_x411_user_name,
      { "user-name", "x411.user_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.UserName", HFILL }},
    { &hf_x411_user_address,
      { "user-address", "x411.user_address",
        FT_UINT32, BASE_DEC, VALS(x411_UserAddress_vals), 0,
        "x411.UserAddress", HFILL }},
    { &hf_x411_deliverable_class,
      { "deliverable-class", "x411.deliverable_class",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.SET_SIZE_1_ub_deliverable_class_OF_DeliverableClass", HFILL }},
    { &hf_x411_deliverable_class_item,
      { "DeliverableClass", "x411.DeliverableClass",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.DeliverableClass", HFILL }},
    { &hf_x411_default_delivery_controls,
      { "default-delivery-controls", "x411.default_delivery_controls",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.DefaultDeliveryControls", HFILL }},
    { &hf_x411_redirections,
      { "redirections", "x411.redirections",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.Redirections", HFILL }},
    { &hf_x411_restricted_delivery,
      { "restricted-delivery", "x411.restricted_delivery",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.RestrictedDelivery", HFILL }},
    { &hf_x411_retrieve_registrations,
      { "retrieve-registrations", "x411.retrieve_registrations",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.RegistrationTypes", HFILL }},
    { &hf_x411_non_empty_result,
      { "non-empty-result", "x411.non_empty_result",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.T_non_empty_result", HFILL }},
    { &hf_x411_registered_information,
      { "registered-information", "x411.registered_information",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.RegisterArgument", HFILL }},
    { &hf_x411_old_credentials,
      { "old-credentials", "x411.old_credentials",
        FT_UINT32, BASE_DEC, VALS(x411_Credentials_vals), 0,
        "x411.Credentials", HFILL }},
    { &hf_x411_new_credentials,
      { "new-credentials", "x411.new_credentials",
        FT_UINT32, BASE_DEC, VALS(x411_Credentials_vals), 0,
        "x411.Credentials", HFILL }},
    { &hf_x411_x121,
      { "x121", "x411.x121",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.T_x121", HFILL }},
    { &hf_x411_x121_address,
      { "x121-address", "x411.x121_address",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.AddrNumericString", HFILL }},
    { &hf_x411_tsap_id,
      { "tsap-id", "x411.tsap_id",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.PrintableString_SIZE_1_ub_tsap_id_length", HFILL }},
    { &hf_x411_presentation,
      { "presentation", "x411.presentation",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PSAPAddress", HFILL }},
    { &hf_x411_Redirections_item,
      { "RecipientRedirection", "x411.RecipientRedirection",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.RecipientRedirection", HFILL }},
    { &hf_x411_redirection_classes,
      { "redirection-classes", "x411.redirection_classes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.SET_SIZE_1_ub_redirection_classes_OF_RedirectionClass", HFILL }},
    { &hf_x411_redirection_classes_item,
      { "RedirectionClass", "x411.RedirectionClass",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.RedirectionClass", HFILL }},
    { &hf_x411_recipient_assigned_alternate_recipient,
      { "recipient-assigned-alternate-recipient", "x411.recipient_assigned_alternate_recipient",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.RecipientAssignedAlternateRecipient", HFILL }},
    { &hf_x411_content_types,
      { "content-types", "x411.content_types",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.ContentTypes", HFILL }},
    { &hf_x411_maximum_content_length,
      { "maximum-content-length", "x411.maximum_content_length",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.ContentLength", HFILL }},
    { &hf_x411_encoded_information_types_constraints,
      { "encoded-information-types-constraints", "x411.encoded_information_types_constraints",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.EncodedInformationTypesConstraints", HFILL }},
    { &hf_x411_security_labels,
      { "security-labels", "x411.security_labels",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.SecurityContext", HFILL }},
    { &hf_x411_class_priority,
      { "priority", "x411.priority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.SET_OF_Priority", HFILL }},
    { &hf_x411_class_priority_item,
      { "Priority", "x411.Priority",
        FT_UINT32, BASE_DEC, VALS(x411_Priority_U_vals), 0,
        "x411.Priority", HFILL }},
    { &hf_x411_objects,
      { "objects", "x411.objects",
        FT_UINT32, BASE_DEC, VALS(x411_T_objects_vals), 0,
        "x411.T_objects", HFILL }},
    { &hf_x411_applies_only_to,
      { "applies-only-to", "x411.applies_only_to",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.SEQUENCE_OF_Restriction", HFILL }},
    { &hf_x411_applies_only_to_item,
      { "Restriction", "x411.Restriction",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.Restriction", HFILL }},
    { &hf_x411_unacceptable_eits,
      { "unacceptable-eits", "x411.unacceptable_eits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.ExtendedEncodedInformationTypes", HFILL }},
    { &hf_x411_acceptable_eits,
      { "acceptable-eits", "x411.acceptable_eits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.ExtendedEncodedInformationTypes", HFILL }},
    { &hf_x411_exclusively_acceptable_eits,
      { "exclusively-acceptable-eits", "x411.exclusively_acceptable_eits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.ExtendedEncodedInformationTypes", HFILL }},
    { &hf_x411_RestrictedDelivery_item,
      { "Restriction", "x411.Restriction",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.Restriction", HFILL }},
    { &hf_x411_permitted,
      { "permitted", "x411.permitted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "x411.BOOLEAN", HFILL }},
    { &hf_x411_source_type,
      { "source-type", "x411.source_type",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.T_source_type", HFILL }},
    { &hf_x411_source_name,
      { "source-name", "x411.source_name",
        FT_UINT32, BASE_DEC, VALS(x411_ExactOrPattern_vals), 0,
        "x411.ExactOrPattern", HFILL }},
    { &hf_x411_exact_match,
      { "exact-match", "x411.exact_match",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ORName", HFILL }},
    { &hf_x411_pattern_match,
      { "pattern-match", "x411.pattern_match",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ORName", HFILL }},
    { &hf_x411_standard_parameters,
      { "standard-parameters", "x411.standard_parameters",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.T_standard_parameters", HFILL }},
    { &hf_x411_type_extensions,
      { "extensions", "x411.extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.T_type_extensions", HFILL }},
    { &hf_x411_type_extensions_item,
      { "extensions item", "x411.extensions_item",
        FT_UINT32, BASE_DEC, VALS(x411_ExtensionType_vals), 0,
        "x411.T_type_extensions_item", HFILL }},
    { &hf_x411_originator_name_01,
      { "originator-name", "x411.originator_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.OriginatorName", HFILL }},
    { &hf_x411_submission_recipient_name,
      { "recipient-name", "x411.recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.RecipientName", HFILL }},
    { &hf_x411_originator_report_request,
      { "originator-report-request", "x411.originator_report_request",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.OriginatorReportRequest", HFILL }},
    { &hf_x411_probe_recipient_name,
      { "recipient-name", "x411.recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.RecipientName", HFILL }},
    { &hf_x411_message_delivery_identifier,
      { "message-delivery-identifier", "x411.message_delivery_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MessageDeliveryIdentifier", HFILL }},
    { &hf_x411_message_delivery_time,
      { "message-delivery-time", "x411.message_delivery_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.MessageDeliveryTime", HFILL }},
    { &hf_x411_other_fields,
      { "other-fields", "x411.other_fields",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.OtherMessageDeliveryFields", HFILL }},
    { &hf_x411_delivered_content_type,
      { "content-type", "x411.content_type",
        FT_UINT32, BASE_DEC, VALS(x411_DeliveredContentType_vals), 0,
        "x411.DeliveredContentType", HFILL }},
    { &hf_x411_delivered_originator_name,
      { "originator-name", "x411.originator_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.DeliveredOriginatorName", HFILL }},
    { &hf_x411_delivery_flags,
      { "delivery-flags", "x411.delivery_flags",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.DeliveryFlags", HFILL }},
    { &hf_x411_other_recipient_names,
      { "other-recipient-names", "x411.other_recipient_names",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.OtherRecipientNames", HFILL }},
    { &hf_x411_this_recipient_name,
      { "this-recipient-name", "x411.this_recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ThisRecipientName", HFILL }},
    { &hf_x411_originally_intended_recipient_name,
      { "originally-intended-recipient-name", "x411.originally_intended_recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.OriginallyIntendedRecipientName", HFILL }},
    { &hf_x411_subject_submission_identifier,
      { "subject-submission-identifier", "x411.subject_submission_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.SubjectSubmissionIdentifier", HFILL }},
    { &hf_x411_actual_recipient_name,
      { "actual-recipient-name", "x411.actual_recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ActualRecipientName", HFILL }},
    { &hf_x411_delivery_report_type,
      { "report-type", "x411.report_type",
        FT_UINT32, BASE_DEC, VALS(x411_ReportType_vals), 0,
        "x411.ReportType", HFILL }},
    { &hf_x411_delivery,
      { "delivery", "x411.delivery",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.DeliveryReport", HFILL }},
    { &hf_x411_non_delivery,
      { "non-delivery", "x411.non_delivery",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.NonDeliveryReport", HFILL }},
    { &hf_x411_type_of_MTS_user,
      { "type-of-MTS-user", "x411.type_of_MTS_user",
        FT_UINT32, BASE_DEC, VALS(x411_TypeOfMTSUser_vals), 0,
        "x411.TypeOfMTSUser", HFILL }},
    { &hf_x411_non_delivery_reason_code,
      { "non-delivery-reason-code", "x411.non_delivery_reason_code",
        FT_UINT32, BASE_DEC, VALS(x411_NonDeliveryReasonCode_vals), 0,
        "x411.NonDeliveryReasonCode", HFILL }},
    { &hf_x411_non_delivery_diagnostic_code,
      { "non-delivery-diagnostic-code", "x411.non_delivery_diagnostic_code",
        FT_UINT32, BASE_DEC, VALS(x411_NonDeliveryDiagnosticCode_vals), 0,
        "x411.NonDeliveryDiagnosticCode", HFILL }},
    { &hf_x411_ContentTypes_item,
      { "ContentType", "x411.ContentType",
        FT_UINT32, BASE_DEC, VALS(x411_ContentType_vals), 0,
        "x411.ContentType", HFILL }},
    { &hf_x411_built_in,
      { "built-in", "x411.built_in",
        FT_UINT32, BASE_DEC, VALS(x411_BuiltInContentType_U_vals), 0,
        "x411.BuiltInContentType", HFILL }},
    { &hf_x411_extended,
      { "extended", "x411.extended",
        FT_OID, BASE_NONE, NULL, 0,
        "x411.ExtendedContentType", HFILL }},
    { &hf_x411_OtherRecipientNames_item,
      { "OtherRecipientName", "x411.OtherRecipientName",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.OtherRecipientName", HFILL }},
    { &hf_x411_standard_extension,
      { "standard-extension", "x411.standard_extension",
        FT_INT32, BASE_DEC, VALS(x411_StandardExtension_vals), 0,
        "x411.StandardExtension", HFILL }},
    { &hf_x411_private_extension,
      { "private-extension", "x411.private_extension",
        FT_OID, BASE_NONE, NULL, 0,
        "x411.T_private_extension", HFILL }},
    { &hf_x411_extension_type,
      { "type", "x411.type",
        FT_UINT32, BASE_DEC, VALS(x411_ExtensionType_vals), 0,
        "x411.ExtensionType", HFILL }},
    { &hf_x411_criticality,
      { "criticality", "x411.criticality",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.Criticality", HFILL }},
    { &hf_x411_extension_value,
      { "value", "x411.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ExtensionValue", HFILL }},
    { &hf_x411_RequestedDeliveryMethod_item,
      { "RequestedDeliveryMethod item", "x411.RequestedDeliveryMethod_item",
        FT_UINT32, BASE_DEC, VALS(x411_RequestedDeliveryMethod_item_vals), 0,
        "x411.RequestedDeliveryMethod_item", HFILL }},
    { &hf_x411_ia5text,
      { "ia5text", "x411.ia5text",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.IA5String", HFILL }},
    { &hf_x411_octets,
      { "octets", "x411.octets",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.OCTET_STRING", HFILL }},
    { &hf_x411_RedirectionHistory_item,
      { "Redirection", "x411.Redirection",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.Redirection", HFILL }},
    { &hf_x411_intended_recipient_name,
      { "intended-recipient-name", "x411.intended_recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.IntendedRecipientName", HFILL }},
    { &hf_x411_redirection_reason,
      { "redirection-reason", "x411.redirection_reason",
        FT_UINT32, BASE_DEC, VALS(x411_RedirectionReason_vals), 0,
        "x411.RedirectionReason", HFILL }},
    { &hf_x411_intended_recipient,
      { "intended-recipient", "x411.intended_recipient",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ORAddressAndOptionalDirectoryName", HFILL }},
    { &hf_x411_redirection_time,
      { "redirection-time", "x411.redirection_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.Time", HFILL }},
    { &hf_x411_DLExpansionHistory_item,
      { "DLExpansion", "x411.DLExpansion",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.DLExpansion", HFILL }},
    { &hf_x411_dl,
      { "dl", "x411.dl",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ORAddressAndOptionalDirectoryName", HFILL }},
    { &hf_x411_dl_expansion_time,
      { "dl-expansion-time", "x411.dl_expansion_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.Time", HFILL }},
    { &hf_x411_OriginatorAndDLExpansionHistory_item,
      { "OriginatorAndDLExpansion", "x411.OriginatorAndDLExpansion",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.OriginatorAndDLExpansion", HFILL }},
    { &hf_x411_originator_or_dl_name,
      { "originator-or-dl-name", "x411.originator_or_dl_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ORAddressAndOptionalDirectoryName", HFILL }},
    { &hf_x411_origination_or_expansion_time,
      { "origination-or-expansion-time", "x411.origination_or_expansion_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.Time", HFILL }},
    { &hf_x411_report_type,
      { "report-type", "x411.report_type",
        FT_UINT32, BASE_DEC, VALS(x411_T_report_type_vals), 0,
        "x411.T_report_type", HFILL }},
    { &hf_x411_report_type_delivery,
      { "delivery", "x411.delivery",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PerRecipientDeliveryReportFields", HFILL }},
    { &hf_x411_non_delivery_report,
      { "non-delivery", "x411.non_delivery",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PerRecipientNonDeliveryReportFields", HFILL }},
    { &hf_x411_domain_01,
      { "domain", "x411.domain",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.GlobalDomainIdentifier", HFILL }},
    { &hf_x411_mta_directory_name,
      { "mta-directory-name", "x411.mta_directory_name",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "x509if.Name", HFILL }},
    { &hf_x411_ExtendedCertificates_item,
      { "ExtendedCertificate", "x411.ExtendedCertificate",
        FT_UINT32, BASE_DEC, VALS(x411_ExtendedCertificate_vals), 0,
        "x411.ExtendedCertificate", HFILL }},
    { &hf_x411_directory_entry,
      { "directory-entry", "x411.directory_entry",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "x509if.Name", HFILL }},
    { &hf_x411_DLExemptedRecipients_item,
      { "ORAddressAndOrDirectoryName", "x411.ORAddressAndOrDirectoryName",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ORAddressAndOrDirectoryName", HFILL }},
    { &hf_x411_encryption_recipient,
      { "encryption-recipient", "x411.encryption_recipient",
        FT_NONE, BASE_NONE, NULL, 0,
        "x509ce.CertificateAssertion", HFILL }},
    { &hf_x411_encryption_originator,
      { "encryption-originator", "x411.encryption_originator",
        FT_NONE, BASE_NONE, NULL, 0,
        "x509ce.CertificateAssertion", HFILL }},
    { &hf_x411_selectors_content_integrity_check,
      { "content-integrity-check", "x411.content_integrity_check",
        FT_NONE, BASE_NONE, NULL, 0,
        "x509ce.CertificateAssertion", HFILL }},
    { &hf_x411_token_signature,
      { "token-signature", "x411.token_signature",
        FT_NONE, BASE_NONE, NULL, 0,
        "x509ce.CertificateAssertion", HFILL }},
    { &hf_x411_message_origin_authentication,
      { "message-origin-authentication", "x411.message_origin_authentication",
        FT_NONE, BASE_NONE, NULL, 0,
        "x509ce.CertificateAssertion", HFILL }},
    { &hf_x411_local_identifier,
      { "local-identifier", "x411.local_identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.LocalIdentifier", HFILL }},
    { &hf_x411_numeric_private_domain_identifier,
      { "numeric", "x411.numeric",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.AddrNumericString", HFILL }},
    { &hf_x411_printable_private_domain_identifier,
      { "printable", "x411.printable",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.AddrPrintableString", HFILL }},
    { &hf_x411_built_in_standard_attributes,
      { "built-in-standard-attributes", "x411.built_in_standard_attributes",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.BuiltInStandardAttributes", HFILL }},
    { &hf_x411_built_in_domain_defined_attributes,
      { "built-in-domain-defined-attributes", "x411.built_in_domain_defined_attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.BuiltInDomainDefinedAttributes", HFILL }},
    { &hf_x411_extension_attributes,
      { "extension-attributes", "x411.extension_attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.ExtensionAttributes", HFILL }},
    { &hf_x411_network_address,
      { "network-address", "x411.network_address",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.NetworkAddress", HFILL }},
    { &hf_x411_terminal_identifier,
      { "terminal-identifier", "x411.terminal_identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.TerminalIdentifier", HFILL }},
    { &hf_x411_private_domain_name,
      { "private-domain-name", "x411.private_domain_name",
        FT_UINT32, BASE_DEC, VALS(x411_PrivateDomainName_vals), 0,
        "x411.PrivateDomainName", HFILL }},
    { &hf_x411_organization_name,
      { "organization-name", "x411.organization_name",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.OrganizationName", HFILL }},
    { &hf_x411_numeric_user_identifier,
      { "numeric-user-identifier", "x411.numeric_user_identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.NumericUserIdentifier", HFILL }},
    { &hf_x411_personal_name,
      { "personal-name", "x411.personal_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PersonalName", HFILL }},
    { &hf_x411_organizational_unit_names,
      { "organizational-unit-names", "x411.organizational_unit_names",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.OrganizationalUnitNames", HFILL }},
    { &hf_x411_x121_dcc_code,
      { "x121-dcc-code", "x411.x121_dcc_code",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.AddrNumericString", HFILL }},
    { &hf_x411_iso_3166_alpha2_code,
      { "iso-3166-alpha2-code", "x411.iso_3166_alpha2_code",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.AddrPrintableString", HFILL }},
    { &hf_x411_numeric,
      { "numeric", "x411.numeric",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.AddrNumericString", HFILL }},
    { &hf_x411_printable,
      { "printable", "x411.printable",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.AddrPrintableString", HFILL }},
    { &hf_x411_numeric_private_domain_name,
      { "numeric", "x411.numeric",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.AddrNumericString", HFILL }},
    { &hf_x411_printable_private_domain_name,
      { "printable", "x411.printable",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.AddrPrintableString", HFILL }},
    { &hf_x411_printable_surname,
      { "surname", "x411.surname",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.T_printable_surname", HFILL }},
    { &hf_x411_printable_given_name,
      { "given-name", "x411.given_name",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.T_printable_given_name", HFILL }},
    { &hf_x411_printable_initials,
      { "initials", "x411.initials",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.T_printable_initials", HFILL }},
    { &hf_x411_printable_generation_qualifier,
      { "generation-qualifier", "x411.generation_qualifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.T_printable_generation_qualifier", HFILL }},
    { &hf_x411_OrganizationalUnitNames_item,
      { "OrganizationalUnitName", "x411.OrganizationalUnitName",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.OrganizationalUnitName", HFILL }},
    { &hf_x411_BuiltInDomainDefinedAttributes_item,
      { "BuiltInDomainDefinedAttribute", "x411.BuiltInDomainDefinedAttribute",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.BuiltInDomainDefinedAttribute", HFILL }},
    { &hf_x411_printable_type,
      { "type", "x411.type",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.T_printable_type", HFILL }},
    { &hf_x411_printable_value,
      { "value", "x411.value",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.T_printable_value", HFILL }},
    { &hf_x411_ExtensionAttributes_item,
      { "ExtensionAttribute", "x411.ExtensionAttribute",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ExtensionAttribute", HFILL }},
    { &hf_x411_extension_attribute_type,
      { "extension-attribute-type", "x411.extension_attribute_type",
        FT_INT32, BASE_DEC, VALS(x411_ExtensionAttributeType_vals), 0,
        "x411.ExtensionAttributeType", HFILL }},
    { &hf_x411_extension_attribute_value,
      { "extension-attribute-value", "x411.extension_attribute_value",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.T_extension_attribute_value", HFILL }},
    { &hf_x411_teletex_surname,
      { "surname", "x411.surname",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.AddrTeletexString", HFILL }},
    { &hf_x411_teletex_given_name,
      { "given-name", "x411.given_name",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.AddrTeletexString", HFILL }},
    { &hf_x411_teletex_initials,
      { "initials", "x411.initials",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.AddrTeletexString", HFILL }},
    { &hf_x411_teletex_generation_qualifier,
      { "generation-qualifier", "x411.generation_qualifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.AddrTeletexString", HFILL }},
    { &hf_x411_universal_surname,
      { "surname", "x411.surname",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.UniversalOrBMPString", HFILL }},
    { &hf_x411_universal_given_name,
      { "given-name", "x411.given_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.UniversalOrBMPString", HFILL }},
    { &hf_x411_universal_initials,
      { "initials", "x411.initials",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.UniversalOrBMPString", HFILL }},
    { &hf_x411_universal_generation_qualifier,
      { "generation-qualifier", "x411.generation_qualifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.UniversalOrBMPString", HFILL }},
    { &hf_x411_TeletexOrganizationalUnitNames_item,
      { "TeletexOrganizationalUnitName", "x411.TeletexOrganizationalUnitName",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.TeletexOrganizationalUnitName", HFILL }},
    { &hf_x411_UniversalOrganizationalUnitNames_item,
      { "UniversalOrganizationalUnitName", "x411.UniversalOrganizationalUnitName",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.UniversalOrganizationalUnitName", HFILL }},
    { &hf_x411_character_encoding,
      { "character-encoding", "x411.character_encoding",
        FT_UINT32, BASE_DEC, VALS(x411_T_character_encoding_vals), 0,
        "x411.T_character_encoding", HFILL }},
    { &hf_x411_two_octets,
      { "two-octets", "x411.two_octets",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.BMPString_SIZE_1_ub_string_length", HFILL }},
    { &hf_x411_four_octets,
      { "four-octets", "x411.four_octets",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.UniversalString_SIZE_1_ub_string_length", HFILL }},
    { &hf_x411_iso_639_language_code,
      { "iso-639-language-code", "x411.iso_639_language_code",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.PrintableString_SIZE_CONSTR13857016", HFILL }},
    { &hf_x411_numeric_code,
      { "numeric-code", "x411.numeric_code",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.AddrNumericString", HFILL }},
    { &hf_x411_printable_code,
      { "printable-code", "x411.printable_code",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.PrintableString_SIZE_1_ub_postal_code_length", HFILL }},
    { &hf_x411_printable_address,
      { "printable-address", "x411.printable_address",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.T_printable_address", HFILL }},
    { &hf_x411_printable_address_item,
      { "printable-address item", "x411.printable_address_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.PrintableString_SIZE_1_ub_pds_parameter_length", HFILL }},
    { &hf_x411_teletex_string,
      { "teletex-string", "x411.teletex_string",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.TeletexString_SIZE_1_ub_unformatted_address_length", HFILL }},
    { &hf_x411_printable_string,
      { "printable-string", "x411.printable_string",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.PrintableString_SIZE_1_ub_pds_parameter_length", HFILL }},
    { &hf_x411_pds_teletex_string,
      { "teletex-string", "x411.teletex_string",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.TeletexString_SIZE_1_ub_pds_parameter_length", HFILL }},
    { &hf_x411_e163_4_address,
      { "e163-4-address", "x411.e163_4_address",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.T_e163_4_address", HFILL }},
    { &hf_x411_number,
      { "number", "x411.number",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.NumericString_SIZE_1_ub_e163_4_number_length", HFILL }},
    { &hf_x411_sub_address,
      { "sub-address", "x411.sub_address",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.NumericString_SIZE_1_ub_e163_4_sub_address_length", HFILL }},
    { &hf_x411_psap_address,
      { "psap-address", "x411.psap_address",
        FT_NONE, BASE_NONE, NULL, 0,
        "x509sat.PresentationAddress", HFILL }},
    { &hf_x411_TeletexDomainDefinedAttributes_item,
      { "TeletexDomainDefinedAttribute", "x411.TeletexDomainDefinedAttribute",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.TeletexDomainDefinedAttribute", HFILL }},
    { &hf_x411_type,
      { "type", "x411.type",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.AddrTeletexString", HFILL }},
    { &hf_x411_teletex_value,
      { "value", "x411.value",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.AddrTeletexString", HFILL }},
    { &hf_x411_UniversalDomainDefinedAttributes_item,
      { "UniversalDomainDefinedAttribute", "x411.UniversalDomainDefinedAttribute",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.UniversalDomainDefinedAttribute", HFILL }},
    { &hf_x411_universal_type,
      { "type", "x411.type",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.UniversalOrBMPString", HFILL }},
    { &hf_x411_universal_value,
      { "value", "x411.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.UniversalOrBMPString", HFILL }},
    { &hf_x411_ExtendedEncodedInformationTypes_item,
      { "ExtendedEncodedInformationType", "x411.ExtendedEncodedInformationType",
        FT_OID, BASE_NONE, NULL, 0,
        "x411.ExtendedEncodedInformationType", HFILL }},
    { &hf_x411_g3_facsimile,
      { "g3-facsimile", "x411.g3_facsimile",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.G3FacsimileNonBasicParameters", HFILL }},
    { &hf_x411_teletex,
      { "teletex", "x411.teletex",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.TeletexNonBasicParameters", HFILL }},
    { &hf_x411_graphic_character_sets,
      { "graphic-character-sets", "x411.graphic_character_sets",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.TeletexString", HFILL }},
    { &hf_x411_control_character_sets,
      { "control-character-sets", "x411.control_character_sets",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.TeletexString", HFILL }},
    { &hf_x411_page_formats,
      { "page-formats", "x411.page_formats",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.OCTET_STRING", HFILL }},
    { &hf_x411_miscellaneous_terminal_capabilities,
      { "miscellaneous-terminal-capabilities", "x411.miscellaneous_terminal_capabilities",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.TeletexString", HFILL }},
    { &hf_x411_private_use,
      { "private-use", "x411.private_use",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.OCTET_STRING", HFILL }},
    { &hf_x411_token_type_identifier,
      { "token-type-identifier", "x411.token_type_identifier",
        FT_OID, BASE_NONE, NULL, 0,
        "x411.TokenTypeIdentifier", HFILL }},
    { &hf_x411_token,
      { "token", "x411.token",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.TokenTypeData", HFILL }},
    { &hf_x411_signature_algorithm_identifier,
      { "signature-algorithm-identifier", "x411.signature_algorithm_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "x509af.AlgorithmIdentifier", HFILL }},
    { &hf_x411_name,
      { "name", "x411.name",
        FT_UINT32, BASE_DEC, VALS(x411_T_name_vals), 0,
        "x411.T_name", HFILL }},
    { &hf_x411_token_recipient_name,
      { "recipient-name", "x411.recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.RecipientName", HFILL }},
    { &hf_x411_token_mta,
      { "mta", "x411.mta",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MTANameAndOptionalGDI", HFILL }},
    { &hf_x411_time,
      { "time", "x411.time",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.Time", HFILL }},
    { &hf_x411_signed_data,
      { "signed-data", "x411.signed_data",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.TokenData", HFILL }},
    { &hf_x411_encryption_algorithm_identifier,
      { "encryption-algorithm-identifier", "x411.encryption_algorithm_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "x509af.AlgorithmIdentifier", HFILL }},
    { &hf_x411_encrypted_data,
      { "encrypted-data", "x411.encrypted_data",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.BIT_STRING", HFILL }},
    { &hf_x411_asymmetric_token_data,
      { "asymmetric-token-data", "x411.asymmetric_token_data",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.AsymmetricTokenData", HFILL }},
    { &hf_x411_algorithm_identifier,
      { "algorithm-identifier", "x411.algorithm_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "x509af.AlgorithmIdentifier", HFILL }},
    { &hf_x411_token_data_type,
      { "type", "x411.type",
        FT_INT32, BASE_DEC, VALS(x411_TokenDataType_vals), 0,
        "x411.TokenDataType", HFILL }},
    { &hf_x411_value,
      { "value", "x411.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.T_value", HFILL }},
    { &hf_x411_content_confidentiality_algorithm_identifier,
      { "content-confidentiality-algorithm-identifier", "x411.content_confidentiality_algorithm_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ContentConfidentialityAlgorithmIdentifier", HFILL }},
    { &hf_x411_content_integrity_check,
      { "content-integrity-check", "x411.content_integrity_check",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.ContentIntegrityCheck", HFILL }},
    { &hf_x411_message_security_label,
      { "message-security-label", "x411.message_security_label",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MessageSecurityLabel", HFILL }},
    { &hf_x411_proof_of_delivery_request,
      { "proof-of-delivery-request", "x411.proof_of_delivery_request",
        FT_UINT32, BASE_DEC, VALS(x411_ProofOfDeliveryRequest_vals), 0,
        "x411.ProofOfDeliveryRequest", HFILL }},
    { &hf_x411_message_sequence_number,
      { "message-sequence-number", "x411.message_sequence_number",
        FT_INT32, BASE_DEC, NULL, 0,
        "x411.INTEGER", HFILL }},
    { &hf_x411_content_confidentiality_key,
      { "content-confidentiality-key", "x411.content_confidentiality_key",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.EncryptionKey", HFILL }},
    { &hf_x411_content_integrity_key,
      { "content-integrity-key", "x411.content_integrity_key",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.EncryptionKey", HFILL }},
    { &hf_x411_security_policy_identifier,
      { "security-policy-identifier", "x411.security_policy_identifier",
        FT_OID, BASE_NONE, NULL, 0,
        "x411.SecurityPolicyIdentifier", HFILL }},
    { &hf_x411_security_classification,
      { "security-classification", "x411.security_classification",
        FT_UINT32, BASE_DEC, VALS(x411_SecurityClassification_vals), 0,
        "x411.SecurityClassification", HFILL }},
    { &hf_x411_privacy_mark,
      { "privacy-mark", "x411.privacy_mark",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.PrivacyMark", HFILL }},
    { &hf_x411_security_categories,
      { "security-categories", "x411.security_categories",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.SecurityCategories", HFILL }},
    { &hf_x411_SecurityCategories_item,
      { "SecurityCategory", "x411.SecurityCategory",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.SecurityCategory", HFILL }},
    { &hf_x411_category_type,
      { "type", "x411.type",
        FT_OID, BASE_NONE, NULL, 0,
        "x411.SecurityCategoryIdentifier", HFILL }},
    { &hf_x411_category_value,
      { "value", "x411.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.CategoryValue", HFILL }},
    { &hf_x411_rtorq_apdu,
      { "rtorq-apdu", "x411.rtorq_apdu",
        FT_NONE, BASE_NONE, NULL, 0,
        "rtse.RTORQapdu", HFILL }},
    { &hf_x411_rtoac_apdu,
      { "rtoac-apdu", "x411.rtoac_apdu",
        FT_NONE, BASE_NONE, NULL, 0,
        "rtse.RTOACapdu", HFILL }},
    { &hf_x411_rtorj_apdu,
      { "rtorj-apdu", "x411.rtorj_apdu",
        FT_NONE, BASE_NONE, NULL, 0,
        "rtse.RTORJapdu", HFILL }},
    { &hf_x411_rttp_apdu,
      { "rttp-apdu", "x411.rttp_apdu",
        FT_INT32, BASE_DEC, NULL, 0,
        "x411.RTTPapdu", HFILL }},
    { &hf_x411_rttr_apdu,
      { "rttr-apdu", "x411.rttr_apdu",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.RTTRapdu", HFILL }},
    { &hf_x411_rtab_apdu,
      { "rtab-apdu", "x411.rtab_apdu",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.RTABapdu", HFILL }},
    { &hf_x411_abortReason,
      { "abortReason", "x411.abortReason",
        FT_INT32, BASE_DEC, VALS(x411_AbortReason_vals), 0,
        "x411.AbortReason", HFILL }},
    { &hf_x411_reflectedParameter,
      { "reflectedParameter", "x411.reflectedParameter",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.BIT_STRING", HFILL }},
    { &hf_x411_userdataAB,
      { "userdataAB", "x411.userdataAB",
        FT_OID, BASE_NONE, NULL, 0,
        "x411.OBJECT_IDENTIFIER", HFILL }},
    { &hf_x411_mta_originator_name,
      { "originator-name", "x411.originator_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.MTAOriginatorName", HFILL }},
    { &hf_x411_per_recipient_message_fields,
      { "per-recipient-fields", "x411.per_recipient_fields",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageTransferFields", HFILL }},
    { &hf_x411_per_recipient_message_fields_item,
      { "PerRecipientMessageTransferFields", "x411.PerRecipientMessageTransferFields",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PerRecipientMessageTransferFields", HFILL }},
    { &hf_x411_per_recipient_probe_transfer_fields,
      { "per-recipient-fields", "x411.per_recipient_fields",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeTransferFields", HFILL }},
    { &hf_x411_per_recipient_probe_transfer_fields_item,
      { "PerRecipientProbeTransferFields", "x411.PerRecipientProbeTransferFields",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PerRecipientProbeTransferFields", HFILL }},
    { &hf_x411_per_recipient_report_fields,
      { "per-recipient-fields", "x411.per_recipient_fields",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportTransferFields", HFILL }},
    { &hf_x411_per_recipient_report_fields_item,
      { "PerRecipientReportTransferFields", "x411.PerRecipientReportTransferFields",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PerRecipientReportTransferFields", HFILL }},
    { &hf_x411_routing_action,
      { "routing-action", "x411.routing_action",
        FT_UINT32, BASE_DEC, VALS(x411_RoutingAction_vals), 0,
        "x411.RoutingAction", HFILL }},
    { &hf_x411_attempted,
      { "attempted", "x411.attempted",
        FT_UINT32, BASE_DEC, VALS(x411_T_attempted_vals), 0,
        "x411.T_attempted", HFILL }},
    { &hf_x411_mta,
      { "mta", "x411.mta",
        FT_STRING, BASE_NONE, NULL, 0,
        "x411.MTAName", HFILL }},
    { &hf_x411_attempted_domain,
      { "attempted-domain", "x411.attempted_domain",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.GlobalDomainIdentifier", HFILL }},
    { &hf_x411_per_recipient_report_delivery_fields,
      { "per-recipient-fields", "x411.per_recipient_fields",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportDeliveryFields", HFILL }},
    { &hf_x411_per_recipient_report_delivery_fields_item,
      { "PerRecipientReportDeliveryFields", "x411.PerRecipientReportDeliveryFields",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PerRecipientReportDeliveryFields", HFILL }},
    { &hf_x411_mts_originator_name,
      { "originator-name", "x411.originator_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.OriginatorName", HFILL }},
    { &hf_x411_per_recipient_message_submission_fields,
      { "per-recipient-fields", "x411.per_recipient_fields",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageSubmissionFields", HFILL }},
    { &hf_x411_per_recipient_message_submission_fields_item,
      { "PerRecipientMessageSubmissionFields", "x411.PerRecipientMessageSubmissionFields",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PerRecipientMessageSubmissionFields", HFILL }},
    { &hf_x411_per_recipient_probe_submission_fields,
      { "per-recipient-fields", "x411.per_recipient_fields",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeSubmissionFields", HFILL }},
    { &hf_x411_per_recipient_probe_submission_fields_item,
      { "PerRecipientProbeSubmissionFields", "x411.PerRecipientProbeSubmissionFields",
        FT_NONE, BASE_NONE, NULL, 0,
        "x411.PerRecipientProbeSubmissionFields", HFILL }},
    { &hf_x411_directory_name,
      { "directory-name", "x411.directory_name",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "x509if.Name", HFILL }},
    { &hf_x411_built_in_encoded_information_types,
      { "built-in-encoded-information-types", "x411.built_in_encoded_information_types",
        FT_BYTES, BASE_NONE, NULL, 0,
        "x411.BuiltInEncodedInformationTypes", HFILL }},
    { &hf_x411_extended_encoded_information_types,
      { "extended-encoded-information-types", "x411.extended_encoded_information_types",
        FT_UINT32, BASE_DEC, NULL, 0,
        "x411.ExtendedEncodedInformationTypes", HFILL }},
    { &hf_x411_PerRecipientIndicators_responsibility,
      { "responsibility", "x411.responsibility",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_x411_PerRecipientIndicators_originating_MTA_report,
      { "originating-MTA-report", "x411.originating-MTA-report",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_x411_PerRecipientIndicators_originating_MTA_non_delivery_report,
      { "originating-MTA-non-delivery-report", "x411.originating-MTA-non-delivery-report",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_x411_PerRecipientIndicators_originator_report,
      { "originator-report", "x411.originator-report",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_x411_PerRecipientIndicators_originator_non_delivery_report,
      { "originator-non-delivery-report", "x411.originator-non-delivery-report",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_x411_PerRecipientIndicators_reserved_5,
      { "reserved-5", "x411.reserved-5",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_x411_PerRecipientIndicators_reserved_6,
      { "reserved-6", "x411.reserved-6",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_x411_PerRecipientIndicators_reserved_7,
      { "reserved-7", "x411.reserved-7",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_x411_OtherActions_redirected,
      { "redirected", "x411.redirected",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_x411_OtherActions_dl_operation,
      { "dl-operation", "x411.dl-operation",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_x411_Operations_probe_submission_or_report_delivery,
      { "probe-submission-or-report-delivery", "x411.probe-submission-or-report-delivery",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_x411_Operations_message_submission_or_message_delivery,
      { "message-submission-or-message-delivery", "x411.message-submission-or-message-delivery",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_x411_WaitingMessages_long_content,
      { "long-content", "x411.long-content",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_x411_WaitingMessages_low_priority,
      { "low-priority", "x411.low-priority",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_x411_WaitingMessages_other_security_labels,
      { "other-security-labels", "x411.other-security-labels",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_x411_T_source_type_originated_by,
      { "originated-by", "x411.originated-by",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_x411_T_source_type_redirected_by,
      { "redirected-by", "x411.redirected-by",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_x411_T_source_type_dl_expanded_by,
      { "dl-expanded-by", "x411.dl-expanded-by",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_x411_T_standard_parameters_user_name,
      { "user-name", "x411.user-name",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_x411_T_standard_parameters_user_address,
      { "user-address", "x411.user-address",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_x411_T_standard_parameters_deliverable_class,
      { "deliverable-class", "x411.deliverable-class",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_x411_T_standard_parameters_default_delivery_controls,
      { "default-delivery-controls", "x411.default-delivery-controls",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_x411_T_standard_parameters_redirections,
      { "redirections", "x411.redirections",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_x411_T_standard_parameters_restricted_delivery,
      { "restricted-delivery", "x411.restricted-delivery",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_x411_PerMessageIndicators_U_disclosure_of_other_recipients,
      { "disclosure-of-other-recipients", "x411.disclosure-of-other-recipients",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_x411_PerMessageIndicators_U_implicit_conversion_prohibited,
      { "implicit-conversion-prohibited", "x411.implicit-conversion-prohibited",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_x411_PerMessageIndicators_U_alternate_recipient_allowed,
      { "alternate-recipient-allowed", "x411.alternate-recipient-allowed",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_x411_PerMessageIndicators_U_content_return_request,
      { "content-return-request", "x411.content-return-request",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_x411_PerMessageIndicators_U_reserved,
      { "reserved", "x411.reserved",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_x411_PerMessageIndicators_U_bit_5,
      { "bit-5", "x411.bit-5",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_x411_PerMessageIndicators_U_bit_6,
      { "bit-6", "x411.bit-6",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_x411_PerMessageIndicators_U_service_message,
      { "service-message", "x411.service-message",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_x411_OriginatorReportRequest_report,
      { "report", "x411.report",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_x411_OriginatorReportRequest_non_delivery_report,
      { "non-delivery-report", "x411.non-delivery-report",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_x411_DeliveryFlags_implicit_conversion_prohibited,
      { "implicit-conversion-prohibited", "x411.implicit-conversion-prohibited",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_x411_Criticality_for_submission,
      { "for-submission", "x411.for-submission",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_x411_Criticality_for_transfer,
      { "for-transfer", "x411.for-transfer",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_x411_Criticality_for_delivery,
      { "for-delivery", "x411.for-delivery",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_x411_PhysicalDeliveryModes_ordinary_mail,
      { "ordinary-mail", "x411.ordinary-mail",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_x411_PhysicalDeliveryModes_special_delivery,
      { "special-delivery", "x411.special-delivery",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_x411_PhysicalDeliveryModes_express_mail,
      { "express-mail", "x411.express-mail",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_x411_PhysicalDeliveryModes_counter_collection,
      { "counter-collection", "x411.counter-collection",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_x411_PhysicalDeliveryModes_counter_collection_with_telephone_advice,
      { "counter-collection-with-telephone-advice", "x411.counter-collection-with-telephone-advice",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_x411_PhysicalDeliveryModes_counter_collection_with_telex_advice,
      { "counter-collection-with-telex-advice", "x411.counter-collection-with-telex-advice",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_x411_PhysicalDeliveryModes_counter_collection_with_teletex_advice,
      { "counter-collection-with-teletex-advice", "x411.counter-collection-with-teletex-advice",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_x411_PhysicalDeliveryModes_bureau_fax_delivery,
      { "bureau-fax-delivery", "x411.bureau-fax-delivery",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_x411_BuiltInEncodedInformationTypes_unknown,
      { "unknown", "x411.unknown",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_x411_BuiltInEncodedInformationTypes_ia5_text,
      { "ia5-text", "x411.ia5-text",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_x411_BuiltInEncodedInformationTypes_g3_facsimile,
      { "g3-facsimile", "x411.g3-facsimile",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_x411_BuiltInEncodedInformationTypes_g4_class_1,
      { "g4-class-1", "x411.g4-class-1",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_x411_BuiltInEncodedInformationTypes_teletex,
      { "teletex", "x411.teletex",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_x411_BuiltInEncodedInformationTypes_videotex,
      { "videotex", "x411.videotex",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_x411_BuiltInEncodedInformationTypes_voice,
      { "voice", "x411.voice",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_x411_BuiltInEncodedInformationTypes_sfd,
      { "sfd", "x411.sfd",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_x411_BuiltInEncodedInformationTypes_mixed_mode,
      { "mixed-mode", "x411.mixed-mode",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_two_dimensional,
      { "two-dimensional", "x411.two-dimensional",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_fine_resolution,
      { "fine-resolution", "x411.fine-resolution",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_unlimited_length,
      { "unlimited-length", "x411.unlimited-length",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_b4_length,
      { "b4-length", "x411.b4-length",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_a3_width,
      { "a3-width", "x411.a3-width",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_b4_width,
      { "b4-width", "x411.b4-width",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_t6_coding,
      { "t6-coding", "x411.t6-coding",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_uncompressed,
      { "uncompressed", "x411.uncompressed",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_width_middle_864_of_1728,
      { "width-middle-864-of-1728", "x411.width-middle-864-of-1728",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_width_middle_1216_of_1728,
      { "width-middle-1216-of-1728", "x411.width-middle-1216-of-1728",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_resolution_type,
      { "resolution-type", "x411.resolution-type",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_resolution_400x400,
      { "resolution-400x400", "x411.resolution-400x400",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_resolution_300x300,
      { "resolution-300x300", "x411.resolution-300x300",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_resolution_8x15,
      { "resolution-8x15", "x411.resolution-8x15",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_edi,
      { "edi", "x411.edi",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_dtm,
      { "dtm", "x411.dtm",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_bft,
      { "bft", "x411.bft",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_mixed_mode,
      { "mixed-mode", "x411.mixed-mode",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_character_mode,
      { "character-mode", "x411.character-mode",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_twelve_bits,
      { "twelve-bits", "x411.twelve-bits",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_preferred_huffmann,
      { "preferred-huffmann", "x411.preferred-huffmann",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_full_colour,
      { "full-colour", "x411.full-colour",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_jpeg,
      { "jpeg", "x411.jpeg",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_x411_G3FacsimileNonBasicParameters_processable_mode_26,
      { "processable-mode-26", "x411.processable-mode-26",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},

/*--- End of included file: packet-x411-hfarr.c ---*/
#line 252 "packet-x411-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_x411,
    &ett_p3,
    &ett_x411_content_unknown,
    &ett_x411_bilateral_information,
    &ett_x411_additional_information,
    &ett_x411_unknown_standard_extension,
    &ett_x411_unknown_extension_attribute_type,
    &ett_x411_unknown_tokendata_type,

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
    &ett_x411_PerMessageTransferFields,
    &ett_x411_SEQUENCE_SIZE_1_ub_transfers_OF_PerDomainBilateralInformation,
    &ett_x411_SET_OF_ExtensionField,
    &ett_x411_PerRecipientMessageTransferFields,
    &ett_x411_ProbeTransferEnvelope,
    &ett_x411_PerProbeTransferFields,
    &ett_x411_PerRecipientProbeTransferFields,
    &ett_x411_ReportTransferEnvelope,
    &ett_x411_ReportTransferContent,
    &ett_x411_PerReportTransferFields,
    &ett_x411_PerRecipientReportTransferFields,
    &ett_x411_PerDomainBilateralInformation,
    &ett_x411_T_bilateral_domain,
    &ett_x411_T_private_domain,
    &ett_x411_BilateralDomain,
    &ett_x411_T_domain,
    &ett_x411_T_private_domain_01,
    &ett_x411_PerRecipientIndicators,
    &ett_x411_LastTraceInformation,
    &ett_x411_InternalTraceInformation,
    &ett_x411_InternalTraceInformationElement,
    &ett_x411_MTASuppliedInformation,
    &ett_x411_SEQUENCE_SIZE_1_ub_transfers_OF_TraceInformationElement,
    &ett_x411_TraceInformationElement,
    &ett_x411_DomainSuppliedInformation,
    &ett_x411_AdditionalActions,
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
    &ett_x411_SET_SIZE_0_ub_content_types_OF_ContentType,
    &ett_x411_Operations,
    &ett_x411_WaitingMessages,
    &ett_x411_MessageDeliveryArgument,
    &ett_x411_MessageDeliveryResult,
    &ett_x411_ReportDeliveryArgument,
    &ett_x411_ReportDeliveryResult,
    &ett_x411_SET_SIZE_1_MAX_OF_ExtensionField,
    &ett_x411_DeliveryControlArgument,
    &ett_x411_DeliveryControlResult,
    &ett_x411_RefusedOperation,
    &ett_x411_T_refused_argument,
    &ett_x411_Controls,
    &ett_x411_RegisterArgument,
    &ett_x411_SET_SIZE_1_ub_deliverable_class_OF_DeliverableClass,
    &ett_x411_RegisterResult,
    &ett_x411_T_non_empty_result,
    &ett_x411_ChangeCredentialsArgument,
    &ett_x411_UserAddress,
    &ett_x411_T_x121,
    &ett_x411_Redirections,
    &ett_x411_RecipientRedirection,
    &ett_x411_SET_SIZE_1_ub_redirection_classes_OF_RedirectionClass,
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
    &ett_x411_T_type_extensions,
    &ett_x411_MessageSubmissionEnvelope,
    &ett_x411_PerMessageSubmissionFields,
    &ett_x411_PerRecipientMessageSubmissionFields,
    &ett_x411_ProbeSubmissionEnvelope,
    &ett_x411_PerProbeSubmissionFields,
    &ett_x411_PerRecipientProbeSubmissionFields,
    &ett_x411_MessageDeliveryEnvelope,
    &ett_x411_OtherMessageDeliveryFields,
    &ett_x411_ReportDeliveryEnvelope,
    &ett_x411_PerReportDeliveryFields,
    &ett_x411_PerRecipientReportDeliveryFields,
    &ett_x411_ReportType,
    &ett_x411_DeliveryReport,
    &ett_x411_NonDeliveryReport,
    &ett_x411_ContentTypes,
    &ett_x411_ContentType,
    &ett_x411_DeliveredContentType,
    &ett_x411_PerMessageIndicators_U,
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
    &ett_x411_MTSIdentifier_U,
    &ett_x411_GlobalDomainIdentifier_U,
    &ett_x411_PrivateDomainIdentifier,
    &ett_x411_ORName_U,
    &ett_x411_ORAddress,
    &ett_x411_BuiltInStandardAttributes,
    &ett_x411_CountryName_U,
    &ett_x411_AdministrationDomainName_U,
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
    &ett_x411_EncodedInformationTypes_U,
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
    &ett_x411_TokenData,
    &ett_x411_MessageTokenSignedData,
    &ett_x411_MessageTokenEncryptedData,
    &ett_x411_SecurityLabel,
    &ett_x411_SecurityCategories,
    &ett_x411_SecurityCategory,
    &ett_x411_RTSE_apdus,
    &ett_x411_RTABapdu,
    &ett_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageTransferFields,
    &ett_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeTransferFields,
    &ett_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportTransferFields,
    &ett_x411_T_attempted,
    &ett_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportDeliveryFields,
    &ett_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageSubmissionFields,
    &ett_x411_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeSubmissionFields,

/*--- End of included file: packet-x411-ettarr.c ---*/
#line 265 "packet-x411-template.c"
  };

  module_t *x411_module;

  /* Register protocol */
  proto_x411 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("x411", dissect_x411, proto_x411);

  proto_p3 = proto_register_protocol("X.411 Message Access Service", "P3", "p3");

  /* Register fields and subtrees */
  proto_register_field_array(proto_x411, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  x411_extension_dissector_table = register_dissector_table("x411.extension", "X411-EXTENSION", FT_UINT32, BASE_DEC);
  x411_extension_attribute_dissector_table = register_dissector_table("x411.extension-attribute", "X411-EXTENSION-ATTRIBUTE", FT_UINT32, BASE_DEC);
  x411_tokendata_dissector_table = register_dissector_table("x411.tokendata", "X411-TOKENDATA", FT_UINT32, BASE_DEC);

  /* Register our configuration options for X411, particularly our port */

  x411_module = prefs_register_protocol_subtree("OSI/X.400", proto_x411, prefs_register_x411);

  prefs_register_uint_preference(x411_module, "tcp.port", "X.411 TCP Port",
				 "Set the port for P1 operations (if other"
				 " than the default of 102)",
				 10, &global_x411_tcp_port);

}


/*--- proto_reg_handoff_x411 --- */
void proto_reg_handoff_x411(void) {
  dissector_handle_t x411_handle;


/*--- Included file: packet-x411-dis-tab.c ---*/
#line 1 "packet-x411-dis-tab.c"
  dissector_add("x411.extension", 1, create_dissector_handle(dissect_RecipientReassignmentProhibited_PDU, proto_x411));
  dissector_add("x411.extension", 2, create_dissector_handle(dissect_OriginatorRequestedAlternateRecipient_PDU, proto_x411));
  dissector_add("x411.extension", 3, create_dissector_handle(dissect_DLExpansionProhibited_PDU, proto_x411));
  dissector_add("x411.extension", 4, create_dissector_handle(dissect_ConversionWithLossProhibited_PDU, proto_x411));
  dissector_add("x411.extension", 5, create_dissector_handle(dissect_LatestDeliveryTime_PDU, proto_x411));
  dissector_add("x411.extension", 6, create_dissector_handle(dissect_RequestedDeliveryMethod_PDU, proto_x411));
  dissector_add("x411.extension", 7, create_dissector_handle(dissect_PhysicalForwardingProhibited_PDU, proto_x411));
  dissector_add("x411.extension", 8, create_dissector_handle(dissect_PhysicalForwardingAddressRequest_PDU, proto_x411));
  dissector_add("x411.extension", 9, create_dissector_handle(dissect_PhysicalDeliveryModes_PDU, proto_x411));
  dissector_add("x411.extension", 10, create_dissector_handle(dissect_RegisteredMailType_PDU, proto_x411));
  dissector_add("x411.extension", 11, create_dissector_handle(dissect_RecipientNumberForAdvice_PDU, proto_x411));
  dissector_add("x411.extension", 12, create_dissector_handle(dissect_PhysicalRenditionAttributes_PDU, proto_x411));
  dissector_add("x411.extension", 13, create_dissector_handle(dissect_OriginatorReturnAddress_PDU, proto_x411));
  dissector_add("x411.extension", 14, create_dissector_handle(dissect_PhysicalDeliveryReportRequest_PDU, proto_x411));
  dissector_add("x411.extension", 15, create_dissector_handle(dissect_OriginatorCertificate_PDU, proto_x411));
  dissector_add("x411.extension", 16, create_dissector_handle(dissect_MessageToken_PDU, proto_x411));
  dissector_add("x411.extension", 17, create_dissector_handle(dissect_ContentConfidentialityAlgorithmIdentifier_PDU, proto_x411));
  dissector_add("x411.extension", 18, create_dissector_handle(dissect_ContentIntegrityCheck_PDU, proto_x411));
  dissector_add("x411.extension", 19, create_dissector_handle(dissect_MessageOriginAuthenticationCheck_PDU, proto_x411));
  dissector_add("x411.extension", 20, create_dissector_handle(dissect_MessageSecurityLabel_PDU, proto_x411));
  dissector_add("x411.extension", 21, create_dissector_handle(dissect_ProofOfSubmissionRequest_PDU, proto_x411));
  dissector_add("x411.extension", 22, create_dissector_handle(dissect_ProofOfDeliveryRequest_PDU, proto_x411));
  dissector_add("x411.extension", 23, create_dissector_handle(dissect_ContentCorrelator_PDU, proto_x411));
  dissector_add("x411.extension", 24, create_dissector_handle(dissect_ProbeOriginAuthenticationCheck_PDU, proto_x411));
  dissector_add("x411.extension", 25, create_dissector_handle(dissect_RedirectionHistory_PDU, proto_x411));
  dissector_add("x411.extension", 26, create_dissector_handle(dissect_DLExpansionHistory_PDU, proto_x411));
  dissector_add("x411.extension", 27, create_dissector_handle(dissect_PhysicalForwardingAddress_PDU, proto_x411));
  dissector_add("x411.extension", 28, create_dissector_handle(dissect_RecipientCertificate_PDU, proto_x411));
  dissector_add("x411.extension", 29, create_dissector_handle(dissect_ProofOfDelivery_PDU, proto_x411));
  dissector_add("x411.extension", 30, create_dissector_handle(dissect_OriginatorAndDLExpansionHistory_PDU, proto_x411));
  dissector_add("x411.extension", 31, create_dissector_handle(dissect_ReportingDLName_PDU, proto_x411));
  dissector_add("x411.extension", 32, create_dissector_handle(dissect_ReportingMTACertificate_PDU, proto_x411));
  dissector_add("x411.extension", 33, create_dissector_handle(dissect_ReportOriginAuthenticationCheck_PDU, proto_x411));
  dissector_add("x411.extension", 35, create_dissector_handle(dissect_ProofOfSubmission_PDU, proto_x411));
  dissector_add("x411.extension", 37, create_dissector_handle(dissect_TraceInformation_PDU, proto_x411));
  dissector_add("x411.extension", 38, create_dissector_handle(dissect_InternalTraceInformation_PDU, proto_x411));
  dissector_add("x411.extension", 39, create_dissector_handle(dissect_ReportingMTAName_PDU, proto_x411));
  dissector_add("x411.extension", 40, create_dissector_handle(dissect_ExtendedCertificates_PDU, proto_x411));
  dissector_add("x411.extension", 42, create_dissector_handle(dissect_DLExemptedRecipients_PDU, proto_x411));
  dissector_add("x411.extension", 45, create_dissector_handle(dissect_CertificateSelectors_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 1, create_dissector_handle(dissect_CommonName_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 2, create_dissector_handle(dissect_TeletexCommonName_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 3, create_dissector_handle(dissect_TeletexOrganizationName_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 4, create_dissector_handle(dissect_TeletexPersonalName_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 5, create_dissector_handle(dissect_TeletexOrganizationalUnitNames_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 6, create_dissector_handle(dissect_TeletexDomainDefinedAttributes_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 7, create_dissector_handle(dissect_PDSName_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 8, create_dissector_handle(dissect_PhysicalDeliveryCountryName_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 9, create_dissector_handle(dissect_PostalCode_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 10, create_dissector_handle(dissect_PhysicalDeliveryOfficeName_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 11, create_dissector_handle(dissect_PhysicalDeliveryOfficeNumber_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 12, create_dissector_handle(dissect_ExtensionORAddressComponents_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 13, create_dissector_handle(dissect_PhysicalDeliveryPersonalName_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 14, create_dissector_handle(dissect_PhysicalDeliveryOrganizationName_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 15, create_dissector_handle(dissect_ExtensionPhysicalDeliveryAddressComponents_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 16, create_dissector_handle(dissect_UnformattedPostalAddress_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 17, create_dissector_handle(dissect_StreetAddress_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 18, create_dissector_handle(dissect_PostOfficeBoxAddress_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 19, create_dissector_handle(dissect_PosteRestanteAddress_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 20, create_dissector_handle(dissect_UniquePostalName_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 21, create_dissector_handle(dissect_LocalPostalAttributes_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 22, create_dissector_handle(dissect_ExtendedNetworkAddress_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 23, create_dissector_handle(dissect_TerminalType_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 24, create_dissector_handle(dissect_UniversalCommonName_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 25, create_dissector_handle(dissect_UniversalOrganizationName_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 26, create_dissector_handle(dissect_UniversalPersonalName_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 27, create_dissector_handle(dissect_UniversalOrganizationalUnitNames_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 28, create_dissector_handle(dissect_UniversalDomainDefinedAttributes_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 29, create_dissector_handle(dissect_UniversalPhysicalDeliveryOfficeName_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 30, create_dissector_handle(dissect_UniversalPhysicalDeliveryOfficeNumber_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 31, create_dissector_handle(dissect_UniversalExtensionORAddressComponents_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 32, create_dissector_handle(dissect_UniversalPhysicalDeliveryPersonalName_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 33, create_dissector_handle(dissect_UniversalPhysicalDeliveryOrganizationName_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 34, create_dissector_handle(dissect_UniversalExtensionPhysicalDeliveryAddressComponents_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 35, create_dissector_handle(dissect_UniversalUnformattedPostalAddress_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 36, create_dissector_handle(dissect_UniversalStreetAddress_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 37, create_dissector_handle(dissect_UniversalPostOfficeBoxAddress_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 38, create_dissector_handle(dissect_UniversalPosteRestanteAddress_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 39, create_dissector_handle(dissect_UniversalUniquePostalName_PDU, proto_x411));
  dissector_add("x411.extension-attribute", 40, create_dissector_handle(dissect_UniversalLocalPostalAttributes_PDU, proto_x411));
  register_ber_oid_dissector("2.6.3.6.0", dissect_AsymmetricToken_PDU, proto_x411, "id-tok-asymmetricToken");
  register_ber_oid_dissector("2.6.5.6.0", dissect_MTANameAndOptionalGDI_PDU, proto_x411, "id-on-mtaName");
  dissector_add("x411.tokendata", 1, create_dissector_handle(dissect_BindTokenSignedData_PDU, proto_x411));
  dissector_add("x411.tokendata", 2, create_dissector_handle(dissect_MessageTokenSignedData_PDU, proto_x411));
  dissector_add("x411.tokendata", 3, create_dissector_handle(dissect_MessageTokenEncryptedData_PDU, proto_x411));
  dissector_add("x411.tokendata", 4, create_dissector_handle(dissect_BindTokenEncryptedData_PDU, proto_x411));
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
  register_ber_oid_dissector("2.6.4.3.80", dissect_CertificateSelectors_PDU, proto_x411, "id-att-certificate-selectors");
  register_ber_oid_dissector("2.6.4.3.1", dissect_Content_PDU, proto_x411, "id-att-content");
  register_ber_oid_dissector("2.6.4.3.3", dissect_ContentCorrelator_PDU, proto_x411, "id-att-content-correlator");
  register_ber_oid_dissector("2.6.4.3.4", dissect_ContentIdentifier_PDU, proto_x411, "id-att-content-identifier");
  register_ber_oid_dissector("2.6.4.3.5", dissect_ContentIntegrityCheck_PDU, proto_x411, "id-att-content-inetgrity-check");
  register_ber_oid_dissector("2.6.4.3.6", dissect_ContentLength_PDU, proto_x411, "id-att-content-length");
  register_ber_oid_dissector("2.6.4.3.8", dissect_ExtendedContentType_PDU, proto_x411, "id-att-content-type");
  register_ber_oid_dissector("2.6.4.3.9", dissect_ConversionWithLossProhibited_PDU, proto_x411, "id-att-conversion-with-loss-prohibited");
  register_ber_oid_dissector("2.6.4.3.51", dissect_DeferredDeliveryTime_PDU, proto_x411, "id-att-deferred-delivery-time");
  register_ber_oid_dissector("2.6.4.3.13", dissect_DeliveryFlags_PDU, proto_x411, "id-att-delivery-flags");
  register_ber_oid_dissector("2.6.4.3.78", dissect_ORName_PDU, proto_x411, "id-att-dl-exempted-recipients");
  register_ber_oid_dissector("2.6.4.3.14", dissect_DLExpansion_PDU, proto_x411, "id-att-dl-expansion-history");
  register_ber_oid_dissector("2.6.4.3.53", dissect_DLExpansionProhibited_PDU, proto_x411, "id-att-dl-expansion-prohibited");
  register_ber_oid_dissector("2.6.4.3.54", dissect_InternalTraceInformationElement_PDU, proto_x411, "id-att-internal-trace-information");
  register_ber_oid_dissector("2.6.4.3.55", dissect_LatestDeliveryTime_PDU, proto_x411, "id-att-latest-delivery-time");
  register_ber_oid_dissector("2.6.4.3.18", dissect_MessageDeliveryEnvelope_PDU, proto_x411, "id-att-message-delivery-envelope");
  register_ber_oid_dissector("2.6.4.3.20", dissect_MessageDeliveryTime_PDU, proto_x411, "id-att-message-delivery-time");
  register_ber_oid_dissector("2.6.4.3.19", dissect_MTSIdentifier_PDU, proto_x411, "id-att-message-identifier");
  register_ber_oid_dissector("2.6.4.3.21", dissect_MessageOriginAuthenticationCheck_PDU, proto_x411, "id-at-message-orgin-authentication-check");
  register_ber_oid_dissector("2.6.4.3.22", dissect_MessageSecurityLabel_PDU, proto_x411, "id-att-message-security-label");
  register_ber_oid_dissector("2.6.4.3.59", dissect_MessageSubmissionEnvelope_PDU, proto_x411, "id-att-message-submission-envelope");
  register_ber_oid_dissector("2.6.4.3.23", dissect_MessageSubmissionTime_PDU, proto_x411, "id-att-message-submission-time");
  register_ber_oid_dissector("2.6.4.3.24", dissect_MessageToken_PDU, proto_x411, "id-att-message-token");
  register_ber_oid_dissector("2.6.4.3.81", dissect_ExtendedCertificates_PDU, proto_x411, "id-att-multiple-originator-certificates");
  register_ber_oid_dissector("2.6.4.3.17", dissect_ORName_PDU, proto_x411, "id-att-originally-intended-recipient-name");
  register_ber_oid_dissector("2.6.4.3.62", dissect_OriginatingMTACertificate_PDU, proto_x411, "id-att-originating-MTA-certificate");
  register_ber_oid_dissector("2.6.4.3.26", dissect_OriginatorCertificate_PDU, proto_x411, "id-att-originator-certificate");
  register_ber_oid_dissector("2.6.4.3.27", dissect_ORName_PDU, proto_x411, "id-att-originator-name");
  register_ber_oid_dissector("2.6.4.3.63", dissect_OriginatorReportRequest_PDU, proto_x411, "id-att-originator-report-request");
  register_ber_oid_dissector("2.6.4.3.64", dissect_OriginatorReturnAddress_PDU, proto_x411, "id-att-originator-return-address");
  register_ber_oid_dissector("2.6.4.3.28", dissect_ORName_PDU, proto_x411, "id-att-other-recipient-names");
  register_ber_oid_dissector("2.6.4.3.65", dissect_PerMessageIndicators_PDU, proto_x411, "id-att-per-message-indicators");
  register_ber_oid_dissector("2.6.4.3.66", dissect_PerRecipientMessageSubmissionFields_PDU, proto_x411, "id-att-per-recipient-message-submission-fields");
  register_ber_oid_dissector("2.6.4.3.67", dissect_PerRecipientProbeSubmissionFields_PDU, proto_x411, "id-att-per-recipient-probe-submission-fields");
  register_ber_oid_dissector("2.6.4.3.30", dissect_PerRecipientReportDeliveryFields_PDU, proto_x411, "id-att-per-recipient-report-delivery-fields");
  register_ber_oid_dissector("2.6.4.3.31", dissect_Priority_PDU, proto_x411, "id-att-priority");
  register_ber_oid_dissector("2.6.4.3.68", dissect_ProbeOriginAuthenticationCheck_PDU, proto_x411, "id-att-probe-origin-authentication-check");
  register_ber_oid_dissector("2.6.4.3.69", dissect_ProbeSubmissionEnvelope_PDU, proto_x411, "id-att-probe-submission-envelope");
  register_ber_oid_dissector("2.6.4.3.32", dissect_ProofOfDeliveryRequest_PDU, proto_x411, "id-att-proof-of-delivery-request");
  register_ber_oid_dissector("2.6.4.3.70", dissect_ProofOfSubmission_PDU, proto_x411, "id-att-proof-of-submission");
  register_ber_oid_dissector("2.6.4.3.82", dissect_ExtendedCertificates_PDU, proto_x411, "id-att-recipient-certificate");
  register_ber_oid_dissector("2.6.4.3.71", dissect_ORName_PDU, proto_x411, "id-att-recipient-names");
  register_ber_oid_dissector("2.6.4.3.72", dissect_RecipientReassignmentProhibited_PDU, proto_x411, "id-att-recipient-reassignment-prohibited");
  register_ber_oid_dissector("2.6.4.3.33", dissect_Redirection_PDU, proto_x411, "id-at-redirection-history");
  register_ber_oid_dissector("2.6.4.3.34", dissect_ReportDeliveryEnvelope_PDU, proto_x411, "id-att-report-delivery-envelope");
  register_ber_oid_dissector("2.6.4.3.35", dissect_ReportingDLName_PDU, proto_x411, "id-att-reporting-DL-name");
  register_ber_oid_dissector("2.6.4.3.36", dissect_ReportingMTACertificate_PDU, proto_x411, "id-att-reporting-MTA-certificate");
  register_ber_oid_dissector("2.6.4.3.37", dissect_ReportOriginAuthenticationCheck_PDU, proto_x411, "id-att-report-origin-authentication-check");
  register_ber_oid_dissector("2.6.4.3.38", dissect_SecurityClassification_PDU, proto_x411, "id-att-security-classification");
  register_ber_oid_dissector("2.6.4.3.40", dissect_SubjectSubmissionIdentifier_PDU, proto_x411, "id-att-subject-submission-identifier");
  register_ber_oid_dissector("2.6.4.3.41", dissect_ORName_PDU, proto_x411, "id-att-this-recipient-name");
  register_ber_oid_dissector("2.6.4.3.75", dissect_TraceInformationElement_PDU, proto_x411, "id-att-trace-information");
  register_ber_oid_dissector("2.6.1.7.36", dissect_MessageToken_PDU, proto_x411, "id-hat-forwarded-token");


/*--- End of included file: packet-x411-dis-tab.c ---*/
#line 300 "packet-x411-template.c"

  /* APPLICATION CONTEXT */

  oid_add_from_string("id-ac-mts-transfer","2.6.0.1.6");

  /* ABSTRACT SYNTAXES */

  x411_handle = find_dissector("x411");
  register_rtse_oid_dissector_handle("2.6.0.2.12", x411_handle, 0, "id-as-mta-rtse", TRUE); 
  register_rtse_oid_dissector_handle("2.6.0.2.7", x411_handle, 0, "id-as-mtse", FALSE);

  register_ber_syntax_dissector("X.411 Message", proto_x411, dissect_x411_mts_apdu);
  register_rtse_oid_dissector_handle("applicationProtocol.1", x411_handle, 0, "mts-transfer-protocol-1984", FALSE);
  register_rtse_oid_dissector_handle("applicationProtocol.12", x411_handle, 0, "mta-transfer-protocol", FALSE);

  /* remember the tpkt handler for change in preferences */
  tpkt_handle = find_dissector("tpkt");

  /* APPLICATION CONTEXT */

  oid_add_from_string("id-ac-mts-access-88", id_ac_mts_access_88);
  oid_add_from_string("id-ac-mts-forced-access-88", id_ac_mts_forced_access_88);
  oid_add_from_string("id-ac-mts-access-94", id_ac_mts_access_94);
  oid_add_from_string("id-ac-mts-forced-access-94", id_ac_mts_forced_access_94);


  /* Register P3 with ROS */
  register_ros_protocol_info(id_as_msse, &p3_ros_info, 0, "id-as-msse", FALSE); 

  register_ros_protocol_info(id_as_mdse_88, &p3_ros_info, 0, "id-as-mdse-88", FALSE); 
  register_ros_protocol_info(id_as_mdse_94, &p3_ros_info, 0, "id-as-mdse-94", FALSE); 

  register_ros_protocol_info(id_as_mase_88, &p3_ros_info, 0, "id-as-mase-88", FALSE); 
  register_ros_protocol_info(id_as_mase_94, &p3_ros_info, 0, "id-as-mase-94", FALSE); 

  register_ros_protocol_info(id_as_mts, &p3_ros_info, 0, "id-as-mts", FALSE); 

}

void prefs_register_x411(void) {
  static guint tcp_port = 0;

  /* de-register the old port */
  /* port 102 is registered by TPKT - don't undo this! */
  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_delete("tcp.port", tcp_port, tpkt_handle);

  /* Set our port number for future use */
  tcp_port = global_x411_tcp_port;

  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_add("tcp.port", tcp_port, tpkt_handle);

}
