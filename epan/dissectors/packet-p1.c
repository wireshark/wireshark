/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-p1.c                                                                */
/* ../../tools/asn2wrs.py -b -e -C -p p1 -c ./p1.cnf -s ./packet-p1-template -D . MTAAbstractService.asn MTSAbstractService.asn MTSAccessProtocol.asn MHSProtocolObjectIdentifiers.asn MTSUpperBounds.asn */

/* Input file: packet-p1-template.c */

#line 1 "../../asn1/p1/packet-p1-template.c"
/* packet-p1.c
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

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-ros.h"
#include "packet-rtse.h"

#include "packet-x509af.h"
#include "packet-x509ce.h"
#include "packet-x509if.h"
#include "packet-x509sat.h"

#include "packet-p1.h"
#include <epan/strutil.h>

#define PNAME  "X.411 Message Transfer Service"
#define PSNAME "P1"
#define PFNAME "p1"

static guint global_p1_tcp_port = 102;
static dissector_handle_t tpkt_handle;
static void prefs_register_p1(void); /* forward declaration for use in preferences registration */

/* Initialize the protocol and registered fields */
static int proto_p1 = -1;
static int proto_p3 = -1;

static struct SESSION_DATA_STRUCTURE* session = NULL;
static int extension_id = -1; /* integer extension id */
static const char *object_identifier_id = NULL; /* extensions identifier */
static const char *content_type_id = NULL; /* content type identifier */
static gboolean report_unknown_content_type = FALSE;

#define MAX_ORA_STR_LEN     256
static char *oraddress = NULL;
static char *ddatype = NULL;
static gboolean doing_address=FALSE;
static gboolean doing_subjectid=FALSE;
static proto_item *address_item = NULL;

static proto_tree *top_tree=NULL;

static int hf_p1_MTS_APDU_PDU = -1;
static int hf_p1_MTABindArgument_PDU = -1;
static int hf_p1_MTABindResult_PDU = -1;
static int hf_p1_MTABindError_PDU = -1;


/*--- Included file: packet-p1-hf.c ---*/
#line 1 "../../asn1/p1/packet-p1-hf.c"
static int hf_p1_InternalTraceInformation_PDU = -1;  /* InternalTraceInformation */
static int hf_p1_InternalTraceInformationElement_PDU = -1;  /* InternalTraceInformationElement */
static int hf_p1_TraceInformation_PDU = -1;       /* TraceInformation */
static int hf_p1_TraceInformationElement_PDU = -1;  /* TraceInformationElement */
static int hf_p1_MTSBindArgument_PDU = -1;        /* MTSBindArgument */
static int hf_p1_MTSBindResult_PDU = -1;          /* MTSBindResult */
static int hf_p1_PAR_mts_bind_error_PDU = -1;     /* PAR_mts_bind_error */
static int hf_p1_MessageSubmissionArgument_PDU = -1;  /* MessageSubmissionArgument */
static int hf_p1_MessageSubmissionResult_PDU = -1;  /* MessageSubmissionResult */
static int hf_p1_ProbeSubmissionArgument_PDU = -1;  /* ProbeSubmissionArgument */
static int hf_p1_ProbeSubmissionResult_PDU = -1;  /* ProbeSubmissionResult */
static int hf_p1_CancelDeferredDeliveryArgument_PDU = -1;  /* CancelDeferredDeliveryArgument */
static int hf_p1_CancelDeferredDeliveryResult_PDU = -1;  /* CancelDeferredDeliveryResult */
static int hf_p1_SubmissionControlArgument_PDU = -1;  /* SubmissionControlArgument */
static int hf_p1_SubmissionControlResult_PDU = -1;  /* SubmissionControlResult */
static int hf_p1_PAR_submission_control_violated_PDU = -1;  /* PAR_submission_control_violated */
static int hf_p1_PAR_element_of_service_not_subscribed_PDU = -1;  /* PAR_element_of_service_not_subscribed */
static int hf_p1_PAR_deferred_delivery_cancellation_rejected_PDU = -1;  /* PAR_deferred_delivery_cancellation_rejected */
static int hf_p1_PAR_originator_invalid_PDU = -1;  /* PAR_originator_invalid */
static int hf_p1_ImproperlySpecifiedRecipients_PDU = -1;  /* ImproperlySpecifiedRecipients */
static int hf_p1_PAR_message_submission_identifier_invalid_PDU = -1;  /* PAR_message_submission_identifier_invalid */
static int hf_p1_PAR_inconsistent_request_PDU = -1;  /* PAR_inconsistent_request */
static int hf_p1_SecurityProblem_PDU = -1;        /* SecurityProblem */
static int hf_p1_PAR_unsupported_critical_function_PDU = -1;  /* PAR_unsupported_critical_function */
static int hf_p1_PAR_remote_bind_error_PDU = -1;  /* PAR_remote_bind_error */
static int hf_p1_MessageSubmissionTime_PDU = -1;  /* MessageSubmissionTime */
static int hf_p1_MessageDeliveryArgument_PDU = -1;  /* MessageDeliveryArgument */
static int hf_p1_MessageDeliveryResult_PDU = -1;  /* MessageDeliveryResult */
static int hf_p1_ReportDeliveryArgument_PDU = -1;  /* ReportDeliveryArgument */
static int hf_p1_ReportDeliveryResult_PDU = -1;   /* ReportDeliveryResult */
static int hf_p1_DeliveryControlArgument_PDU = -1;  /* DeliveryControlArgument */
static int hf_p1_DeliveryControlResult_PDU = -1;  /* DeliveryControlResult */
static int hf_p1_PAR_delivery_control_violated_PDU = -1;  /* PAR_delivery_control_violated */
static int hf_p1_PAR_control_violates_registration_PDU = -1;  /* PAR_control_violates_registration */
static int hf_p1_RefusedOperation_PDU = -1;       /* RefusedOperation */
static int hf_p1_RecipientCertificate_PDU = -1;   /* RecipientCertificate */
static int hf_p1_ProofOfDelivery_PDU = -1;        /* ProofOfDelivery */
static int hf_p1_RegisterArgument_PDU = -1;       /* RegisterArgument */
static int hf_p1_RegisterResult_PDU = -1;         /* RegisterResult */
static int hf_p1_ChangeCredentialsArgument_PDU = -1;  /* ChangeCredentialsArgument */
static int hf_p1_RES_change_credentials_PDU = -1;  /* RES_change_credentials */
static int hf_p1_PAR_register_rejected_PDU = -1;  /* PAR_register_rejected */
static int hf_p1_PAR_new_credentials_unacceptable_PDU = -1;  /* PAR_new_credentials_unacceptable */
static int hf_p1_PAR_old_credentials_incorrectly_specified_PDU = -1;  /* PAR_old_credentials_incorrectly_specified */
static int hf_p1_MessageSubmissionEnvelope_PDU = -1;  /* MessageSubmissionEnvelope */
static int hf_p1_PerRecipientMessageSubmissionFields_PDU = -1;  /* PerRecipientMessageSubmissionFields */
static int hf_p1_ProbeSubmissionEnvelope_PDU = -1;  /* ProbeSubmissionEnvelope */
static int hf_p1_PerRecipientProbeSubmissionFields_PDU = -1;  /* PerRecipientProbeSubmissionFields */
static int hf_p1_MessageDeliveryEnvelope_PDU = -1;  /* MessageDeliveryEnvelope */
static int hf_p1_ReportDeliveryEnvelope_PDU = -1;  /* ReportDeliveryEnvelope */
static int hf_p1_PerRecipientReportDeliveryFields_PDU = -1;  /* PerRecipientReportDeliveryFields */
static int hf_p1_ExtendedContentType_PDU = -1;    /* ExtendedContentType */
static int hf_p1_ContentIdentifier_PDU = -1;      /* ContentIdentifier */
static int hf_p1_PerMessageIndicators_PDU = -1;   /* PerMessageIndicators */
static int hf_p1_OriginatorReportRequest_PDU = -1;  /* OriginatorReportRequest */
static int hf_p1_DeferredDeliveryTime_PDU = -1;   /* DeferredDeliveryTime */
static int hf_p1_Priority_PDU = -1;               /* Priority */
static int hf_p1_ContentLength_PDU = -1;          /* ContentLength */
static int hf_p1_MessageDeliveryTime_PDU = -1;    /* MessageDeliveryTime */
static int hf_p1_DeliveryFlags_PDU = -1;          /* DeliveryFlags */
static int hf_p1_SubjectSubmissionIdentifier_PDU = -1;  /* SubjectSubmissionIdentifier */
static int hf_p1_RecipientReassignmentProhibited_PDU = -1;  /* RecipientReassignmentProhibited */
static int hf_p1_OriginatorRequestedAlternateRecipient_PDU = -1;  /* OriginatorRequestedAlternateRecipient */
static int hf_p1_DLExpansionProhibited_PDU = -1;  /* DLExpansionProhibited */
static int hf_p1_ConversionWithLossProhibited_PDU = -1;  /* ConversionWithLossProhibited */
static int hf_p1_LatestDeliveryTime_PDU = -1;     /* LatestDeliveryTime */
static int hf_p1_RequestedDeliveryMethod_PDU = -1;  /* RequestedDeliveryMethod */
static int hf_p1_PhysicalForwardingProhibited_PDU = -1;  /* PhysicalForwardingProhibited */
static int hf_p1_PhysicalForwardingAddressRequest_PDU = -1;  /* PhysicalForwardingAddressRequest */
static int hf_p1_PhysicalDeliveryModes_PDU = -1;  /* PhysicalDeliveryModes */
static int hf_p1_RegisteredMailType_PDU = -1;     /* RegisteredMailType */
static int hf_p1_RecipientNumberForAdvice_PDU = -1;  /* RecipientNumberForAdvice */
static int hf_p1_PhysicalRenditionAttributes_PDU = -1;  /* PhysicalRenditionAttributes */
static int hf_p1_OriginatorReturnAddress_PDU = -1;  /* OriginatorReturnAddress */
static int hf_p1_PhysicalDeliveryReportRequest_PDU = -1;  /* PhysicalDeliveryReportRequest */
static int hf_p1_OriginatorCertificate_PDU = -1;  /* OriginatorCertificate */
static int hf_p1_MessageToken_PDU = -1;           /* MessageToken */
static int hf_p1_ContentConfidentialityAlgorithmIdentifier_PDU = -1;  /* ContentConfidentialityAlgorithmIdentifier */
static int hf_p1_ContentIntegrityCheck_PDU = -1;  /* ContentIntegrityCheck */
static int hf_p1_MessageOriginAuthenticationCheck_PDU = -1;  /* MessageOriginAuthenticationCheck */
static int hf_p1_MessageSecurityLabel_PDU = -1;   /* MessageSecurityLabel */
static int hf_p1_ProofOfSubmissionRequest_PDU = -1;  /* ProofOfSubmissionRequest */
static int hf_p1_ProofOfDeliveryRequest_PDU = -1;  /* ProofOfDeliveryRequest */
static int hf_p1_ContentCorrelator_PDU = -1;      /* ContentCorrelator */
static int hf_p1_ProbeOriginAuthenticationCheck_PDU = -1;  /* ProbeOriginAuthenticationCheck */
static int hf_p1_RedirectionHistory_PDU = -1;     /* RedirectionHistory */
static int hf_p1_Redirection_PDU = -1;            /* Redirection */
static int hf_p1_DLExpansionHistory_PDU = -1;     /* DLExpansionHistory */
static int hf_p1_DLExpansion_PDU = -1;            /* DLExpansion */
static int hf_p1_PhysicalForwardingAddress_PDU = -1;  /* PhysicalForwardingAddress */
static int hf_p1_OriginatorAndDLExpansionHistory_PDU = -1;  /* OriginatorAndDLExpansionHistory */
static int hf_p1_ReportingDLName_PDU = -1;        /* ReportingDLName */
static int hf_p1_ReportingMTACertificate_PDU = -1;  /* ReportingMTACertificate */
static int hf_p1_ReportOriginAuthenticationCheck_PDU = -1;  /* ReportOriginAuthenticationCheck */
static int hf_p1_OriginatingMTACertificate_PDU = -1;  /* OriginatingMTACertificate */
static int hf_p1_ProofOfSubmission_PDU = -1;      /* ProofOfSubmission */
static int hf_p1_ReportingMTAName_PDU = -1;       /* ReportingMTAName */
static int hf_p1_ExtendedCertificates_PDU = -1;   /* ExtendedCertificates */
static int hf_p1_DLExemptedRecipients_PDU = -1;   /* DLExemptedRecipients */
static int hf_p1_CertificateSelectors_PDU = -1;   /* CertificateSelectors */
static int hf_p1_Content_PDU = -1;                /* Content */
static int hf_p1_MTSIdentifier_PDU = -1;          /* MTSIdentifier */
static int hf_p1_ORName_PDU = -1;                 /* ORName */
static int hf_p1_ORAddress_PDU = -1;              /* ORAddress */
static int hf_p1_CommonName_PDU = -1;             /* CommonName */
static int hf_p1_TeletexCommonName_PDU = -1;      /* TeletexCommonName */
static int hf_p1_UniversalCommonName_PDU = -1;    /* UniversalCommonName */
static int hf_p1_TeletexOrganizationName_PDU = -1;  /* TeletexOrganizationName */
static int hf_p1_UniversalOrganizationName_PDU = -1;  /* UniversalOrganizationName */
static int hf_p1_TeletexPersonalName_PDU = -1;    /* TeletexPersonalName */
static int hf_p1_UniversalPersonalName_PDU = -1;  /* UniversalPersonalName */
static int hf_p1_TeletexOrganizationalUnitNames_PDU = -1;  /* TeletexOrganizationalUnitNames */
static int hf_p1_UniversalOrganizationalUnitNames_PDU = -1;  /* UniversalOrganizationalUnitNames */
static int hf_p1_PDSName_PDU = -1;                /* PDSName */
static int hf_p1_PhysicalDeliveryCountryName_PDU = -1;  /* PhysicalDeliveryCountryName */
static int hf_p1_PostalCode_PDU = -1;             /* PostalCode */
static int hf_p1_PhysicalDeliveryOfficeName_PDU = -1;  /* PhysicalDeliveryOfficeName */
static int hf_p1_UniversalPhysicalDeliveryOfficeName_PDU = -1;  /* UniversalPhysicalDeliveryOfficeName */
static int hf_p1_PhysicalDeliveryOfficeNumber_PDU = -1;  /* PhysicalDeliveryOfficeNumber */
static int hf_p1_UniversalPhysicalDeliveryOfficeNumber_PDU = -1;  /* UniversalPhysicalDeliveryOfficeNumber */
static int hf_p1_ExtensionORAddressComponents_PDU = -1;  /* ExtensionORAddressComponents */
static int hf_p1_UniversalExtensionORAddressComponents_PDU = -1;  /* UniversalExtensionORAddressComponents */
static int hf_p1_PhysicalDeliveryPersonalName_PDU = -1;  /* PhysicalDeliveryPersonalName */
static int hf_p1_UniversalPhysicalDeliveryPersonalName_PDU = -1;  /* UniversalPhysicalDeliveryPersonalName */
static int hf_p1_PhysicalDeliveryOrganizationName_PDU = -1;  /* PhysicalDeliveryOrganizationName */
static int hf_p1_UniversalPhysicalDeliveryOrganizationName_PDU = -1;  /* UniversalPhysicalDeliveryOrganizationName */
static int hf_p1_ExtensionPhysicalDeliveryAddressComponents_PDU = -1;  /* ExtensionPhysicalDeliveryAddressComponents */
static int hf_p1_UniversalExtensionPhysicalDeliveryAddressComponents_PDU = -1;  /* UniversalExtensionPhysicalDeliveryAddressComponents */
static int hf_p1_UnformattedPostalAddress_PDU = -1;  /* UnformattedPostalAddress */
static int hf_p1_UniversalUnformattedPostalAddress_PDU = -1;  /* UniversalUnformattedPostalAddress */
static int hf_p1_StreetAddress_PDU = -1;          /* StreetAddress */
static int hf_p1_UniversalStreetAddress_PDU = -1;  /* UniversalStreetAddress */
static int hf_p1_PostOfficeBoxAddress_PDU = -1;   /* PostOfficeBoxAddress */
static int hf_p1_UniversalPostOfficeBoxAddress_PDU = -1;  /* UniversalPostOfficeBoxAddress */
static int hf_p1_PosteRestanteAddress_PDU = -1;   /* PosteRestanteAddress */
static int hf_p1_UniversalPosteRestanteAddress_PDU = -1;  /* UniversalPosteRestanteAddress */
static int hf_p1_UniquePostalName_PDU = -1;       /* UniquePostalName */
static int hf_p1_UniversalUniquePostalName_PDU = -1;  /* UniversalUniquePostalName */
static int hf_p1_LocalPostalAttributes_PDU = -1;  /* LocalPostalAttributes */
static int hf_p1_UniversalLocalPostalAttributes_PDU = -1;  /* UniversalLocalPostalAttributes */
static int hf_p1_ExtendedNetworkAddress_PDU = -1;  /* ExtendedNetworkAddress */
static int hf_p1_TerminalType_PDU = -1;           /* TerminalType */
static int hf_p1_TeletexDomainDefinedAttributes_PDU = -1;  /* TeletexDomainDefinedAttributes */
static int hf_p1_UniversalDomainDefinedAttributes_PDU = -1;  /* UniversalDomainDefinedAttributes */
static int hf_p1_ExtendedEncodedInformationType_PDU = -1;  /* ExtendedEncodedInformationType */
static int hf_p1_MTANameAndOptionalGDI_PDU = -1;  /* MTANameAndOptionalGDI */
static int hf_p1_AsymmetricToken_PDU = -1;        /* AsymmetricToken */
static int hf_p1_BindTokenSignedData_PDU = -1;    /* BindTokenSignedData */
static int hf_p1_MessageTokenSignedData_PDU = -1;  /* MessageTokenSignedData */
static int hf_p1_MessageTokenEncryptedData_PDU = -1;  /* MessageTokenEncryptedData */
static int hf_p1_BindTokenEncryptedData_PDU = -1;  /* BindTokenEncryptedData */
static int hf_p1_SecurityClassification_PDU = -1;  /* SecurityClassification */
static int hf_p1_unauthenticated = -1;            /* NULL */
static int hf_p1_authenticated_argument = -1;     /* AuthenticatedArgument */
static int hf_p1_authenticated_initiator_name = -1;  /* MTAName */
static int hf_p1_initiator_credentials = -1;      /* InitiatorCredentials */
static int hf_p1_security_context = -1;           /* SecurityContext */
static int hf_p1_authenticated_result = -1;       /* AuthenticatedResult */
static int hf_p1_authenticated_responder_name = -1;  /* MTAName */
static int hf_p1_responder_credentials = -1;      /* ResponderCredentials */
static int hf_p1_message = -1;                    /* Message */
static int hf_p1_probe = -1;                      /* Probe */
static int hf_p1_report = -1;                     /* Report */
static int hf_p1_message_envelope = -1;           /* MessageTransferEnvelope */
static int hf_p1_content = -1;                    /* Content */
static int hf_p1_report_envelope = -1;            /* ReportTransferEnvelope */
static int hf_p1_report_content = -1;             /* ReportTransferContent */
static int hf_p1_message_identifier = -1;         /* MessageIdentifier */
static int hf_p1_originator_name = -1;            /* MTAOriginatorName */
static int hf_p1_original_encoded_information_types = -1;  /* OriginalEncodedInformationTypes */
static int hf_p1_content_type = -1;               /* ContentType */
static int hf_p1_content_identifier = -1;         /* ContentIdentifier */
static int hf_p1_priority = -1;                   /* Priority */
static int hf_p1_per_message_indicators = -1;     /* PerMessageIndicators */
static int hf_p1_deferred_delivery_time = -1;     /* DeferredDeliveryTime */
static int hf_p1_per_domain_bilateral_information = -1;  /* SEQUENCE_SIZE_1_ub_transfers_OF_PerDomainBilateralInformation */
static int hf_p1_per_domain_bilateral_information_item = -1;  /* PerDomainBilateralInformation */
static int hf_p1_trace_information = -1;          /* TraceInformation */
static int hf_p1_extensions = -1;                 /* SET_OF_ExtensionField */
static int hf_p1_extensions_item = -1;            /* ExtensionField */
static int hf_p1_recipient_name = -1;             /* MTARecipientName */
static int hf_p1_originally_specified_recipient_number = -1;  /* OriginallySpecifiedRecipientNumber */
static int hf_p1_per_recipient_indicators = -1;   /* PerRecipientIndicators */
static int hf_p1_explicit_conversion = -1;        /* ExplicitConversion */
static int hf_p1_probe_identifier = -1;           /* ProbeIdentifier */
static int hf_p1_content_length = -1;             /* ContentLength */
static int hf_p1_report_identifier = -1;          /* ReportIdentifier */
static int hf_p1_report_destination_name = -1;    /* ReportDestinationName */
static int hf_p1_subject_identifier = -1;         /* SubjectIdentifier */
static int hf_p1_subject_intermediate_trace_information = -1;  /* SubjectIntermediateTraceInformation */
static int hf_p1_returned_content = -1;           /* Content */
static int hf_p1_additional_information = -1;     /* AdditionalInformation */
static int hf_p1_mta_actual_recipient_name = -1;  /* MTAActualRecipientName */
static int hf_p1_last_trace_information = -1;     /* LastTraceInformation */
static int hf_p1_report_originally_intended_recipient_name = -1;  /* OriginallyIntendedRecipientName */
static int hf_p1_supplementary_information = -1;  /* SupplementaryInformation */
static int hf_p1_country_name = -1;               /* CountryName */
static int hf_p1_bilateral_domain = -1;           /* T_bilateral_domain */
static int hf_p1_administration_domain_name = -1;  /* AdministrationDomainName */
static int hf_p1_private_domain = -1;             /* T_private_domain */
static int hf_p1_private_domain_identifier = -1;  /* PrivateDomainIdentifier */
static int hf_p1_bilateral_information = -1;      /* T_bilateral_information */
static int hf_p1_arrival_time = -1;               /* ArrivalTime */
static int hf_p1_converted_encoded_information_types = -1;  /* ConvertedEncodedInformationTypes */
static int hf_p1_trace_report_type = -1;          /* ReportType */
static int hf_p1_InternalTraceInformation_item = -1;  /* InternalTraceInformationElement */
static int hf_p1_global_domain_identifier = -1;   /* GlobalDomainIdentifier */
static int hf_p1_mta_name = -1;                   /* MTAName */
static int hf_p1_mta_supplied_information = -1;   /* MTASuppliedInformation */
static int hf_p1__untag_item = -1;                /* TraceInformationElement */
static int hf_p1_domain_supplied_information = -1;  /* DomainSuppliedInformation */
static int hf_p1_deferred_time = -1;              /* DeferredTime */
static int hf_p1_other_actions = -1;              /* OtherActions */
static int hf_p1_initiator_name = -1;             /* ObjectName */
static int hf_p1_messages_waiting = -1;           /* MessagesWaiting */
static int hf_p1_responder_name = -1;             /* ObjectName */
static int hf_p1_user_agent = -1;                 /* ORAddressAndOptionalDirectoryName */
static int hf_p1_mTA = -1;                        /* MTAName */
static int hf_p1_message_store = -1;              /* ORAddressAndOptionalDirectoryName */
static int hf_p1_urgent = -1;                     /* DeliveryQueue */
static int hf_p1_normal = -1;                     /* DeliveryQueue */
static int hf_p1_non_urgent = -1;                 /* DeliveryQueue */
static int hf_p1_messages = -1;                   /* INTEGER_0_ub_queue_size */
static int hf_p1_delivery_queue_octets = -1;      /* INTEGER_0_ub_content_length */
static int hf_p1_simple = -1;                     /* Password */
static int hf_p1_strong = -1;                     /* StrongCredentials */
static int hf_p1_protected = -1;                  /* ProtectedPassword */
static int hf_p1_ia5_string = -1;                 /* IA5String_SIZE_0_ub_password_length */
static int hf_p1_octet_string = -1;               /* OCTET_STRING_SIZE_0_ub_password_length */
static int hf_p1_bind_token = -1;                 /* Token */
static int hf_p1_certificate = -1;                /* Certificates */
static int hf_p1_certificate_selector = -1;       /* CertificateAssertion */
static int hf_p1_signature = -1;                  /* Signature */
static int hf_p1_time1 = -1;                      /* UTCTime */
static int hf_p1_time2 = -1;                      /* UTCTime */
static int hf_p1_random1 = -1;                    /* BIT_STRING */
static int hf_p1_random2 = -1;                    /* BIT_STRING */
static int hf_p1_algorithmIdentifier = -1;        /* AlgorithmIdentifier */
static int hf_p1_encrypted = -1;                  /* BIT_STRING */
static int hf_p1_SecurityContext_item = -1;       /* SecurityLabel */
static int hf_p1_message_submission_envelope = -1;  /* MessageSubmissionEnvelope */
static int hf_p1_message_submission_identifier = -1;  /* MessageSubmissionIdentifier */
static int hf_p1_message_submission_time = -1;    /* MessageSubmissionTime */
static int hf_p1_probe_submission_identifier = -1;  /* ProbeSubmissionIdentifier */
static int hf_p1_probe_submission_time = -1;      /* ProbeSubmissionTime */
static int hf_p1_ImproperlySpecifiedRecipients_item = -1;  /* RecipientName */
static int hf_p1_waiting_operations = -1;         /* Operations */
static int hf_p1_waiting_messages = -1;           /* WaitingMessages */
static int hf_p1_waiting_content_types = -1;      /* SET_SIZE_0_ub_content_types_OF_ContentType */
static int hf_p1_waiting_content_types_item = -1;  /* ContentType */
static int hf_p1_waiting_encoded_information_types = -1;  /* EncodedInformationTypes */
static int hf_p1_recipient_certificate = -1;      /* RecipientCertificate */
static int hf_p1_proof_of_delivery = -1;          /* ProofOfDelivery */
static int hf_p1_empty_result = -1;               /* NULL */
static int hf_p1_max_extensions = -1;             /* SET_SIZE_1_MAX_OF_ExtensionField */
static int hf_p1_max_extensions_item = -1;        /* ExtensionField */
static int hf_p1_restrict = -1;                   /* BOOLEAN */
static int hf_p1_permissible_operations = -1;     /* Operations */
static int hf_p1_permissible_maximum_content_length = -1;  /* ContentLength */
static int hf_p1_permissible_lowest_priority = -1;  /* Priority */
static int hf_p1_permissible_content_types = -1;  /* ContentTypes */
static int hf_p1_permissible_encoded_information_types = -1;  /* PermissibleEncodedInformationTypes */
static int hf_p1_permissible_security_context = -1;  /* SecurityContext */
static int hf_p1_refused_argument = -1;           /* T_refused_argument */
static int hf_p1_built_in_argument = -1;          /* RefusedArgument */
static int hf_p1_refused_extension = -1;          /* T_refused_extension */
static int hf_p1_refusal_reason = -1;             /* RefusalReason */
static int hf_p1_user_name = -1;                  /* UserName */
static int hf_p1_user_address = -1;               /* UserAddress */
static int hf_p1_deliverable_class = -1;          /* SET_SIZE_1_ub_deliverable_class_OF_DeliverableClass */
static int hf_p1_deliverable_class_item = -1;     /* DeliverableClass */
static int hf_p1_default_delivery_controls = -1;  /* DefaultDeliveryControls */
static int hf_p1_redirections = -1;               /* Redirections */
static int hf_p1_restricted_delivery = -1;        /* RestrictedDelivery */
static int hf_p1_retrieve_registrations = -1;     /* RegistrationTypes */
static int hf_p1_non_empty_result = -1;           /* T_non_empty_result */
static int hf_p1_registered_information = -1;     /* RegisterArgument */
static int hf_p1_old_credentials = -1;            /* Credentials */
static int hf_p1_new_credentials = -1;            /* Credentials */
static int hf_p1_x121 = -1;                       /* T_x121 */
static int hf_p1_x121_address = -1;               /* T_x121_address */
static int hf_p1_tsap_id = -1;                    /* PrintableString_SIZE_1_ub_tsap_id_length */
static int hf_p1_presentation = -1;               /* PSAPAddress */
static int hf_p1_Redirections_item = -1;          /* RecipientRedirection */
static int hf_p1_redirection_classes = -1;        /* SET_SIZE_1_ub_redirection_classes_OF_RedirectionClass */
static int hf_p1_redirection_classes_item = -1;   /* RedirectionClass */
static int hf_p1_recipient_assigned_alternate_recipient = -1;  /* RecipientAssignedAlternateRecipient */
static int hf_p1_content_types = -1;              /* ContentTypes */
static int hf_p1_maximum_content_length = -1;     /* ContentLength */
static int hf_p1_encoded_information_types_constraints = -1;  /* EncodedInformationTypesConstraints */
static int hf_p1_security_labels = -1;            /* SecurityContext */
static int hf_p1_class_priority = -1;             /* SET_OF_Priority */
static int hf_p1_class_priority_item = -1;        /* Priority */
static int hf_p1_objects = -1;                    /* T_objects */
static int hf_p1_applies_only_to = -1;            /* SEQUENCE_OF_Restriction */
static int hf_p1_applies_only_to_item = -1;       /* Restriction */
static int hf_p1_unacceptable_eits = -1;          /* ExtendedEncodedInformationTypes */
static int hf_p1_acceptable_eits = -1;            /* ExtendedEncodedInformationTypes */
static int hf_p1_exclusively_acceptable_eits = -1;  /* ExtendedEncodedInformationTypes */
static int hf_p1_RestrictedDelivery_item = -1;    /* Restriction */
static int hf_p1_permitted = -1;                  /* BOOLEAN */
static int hf_p1_source_type = -1;                /* T_source_type */
static int hf_p1_source_name = -1;                /* ExactOrPattern */
static int hf_p1_exact_match = -1;                /* ORName */
static int hf_p1_pattern_match = -1;              /* ORName */
static int hf_p1_standard_parameters = -1;        /* T_standard_parameters */
static int hf_p1_type_extensions = -1;            /* T_type_extensions */
static int hf_p1_type_extensions_item = -1;       /* T_type_extensions_item */
static int hf_p1_originator_name_01 = -1;         /* OriginatorName */
static int hf_p1_submission_recipient_name = -1;  /* RecipientName */
static int hf_p1_originator_report_request = -1;  /* OriginatorReportRequest */
static int hf_p1_probe_recipient_name = -1;       /* RecipientName */
static int hf_p1_message_delivery_identifier = -1;  /* MessageDeliveryIdentifier */
static int hf_p1_message_delivery_time = -1;      /* MessageDeliveryTime */
static int hf_p1_other_fields = -1;               /* OtherMessageDeliveryFields */
static int hf_p1_delivered_content_type = -1;     /* DeliveredContentType */
static int hf_p1_delivered_originator_name = -1;  /* DeliveredOriginatorName */
static int hf_p1_delivery_flags = -1;             /* DeliveryFlags */
static int hf_p1_other_recipient_names = -1;      /* OtherRecipientNames */
static int hf_p1_this_recipient_name = -1;        /* ThisRecipientName */
static int hf_p1_originally_intended_recipient_name = -1;  /* OriginallyIntendedRecipientName */
static int hf_p1_subject_submission_identifier = -1;  /* SubjectSubmissionIdentifier */
static int hf_p1_actual_recipient_name = -1;      /* ActualRecipientName */
static int hf_p1_delivery_report_type = -1;       /* ReportType */
static int hf_p1_delivery = -1;                   /* DeliveryReport */
static int hf_p1_non_delivery = -1;               /* NonDeliveryReport */
static int hf_p1_type_of_MTS_user = -1;           /* TypeOfMTSUser */
static int hf_p1_non_delivery_reason_code = -1;   /* NonDeliveryReasonCode */
static int hf_p1_non_delivery_diagnostic_code = -1;  /* NonDeliveryDiagnosticCode */
static int hf_p1_ContentTypes_item = -1;          /* ContentType */
static int hf_p1_built_in = -1;                   /* BuiltInContentType */
static int hf_p1_extended = -1;                   /* ExtendedContentType */
static int hf_p1_OtherRecipientNames_item = -1;   /* OtherRecipientName */
static int hf_p1_standard_extension = -1;         /* StandardExtension */
static int hf_p1_private_extension = -1;          /* T_private_extension */
static int hf_p1_extension_type = -1;             /* ExtensionType */
static int hf_p1_criticality = -1;                /* Criticality */
static int hf_p1_extension_value = -1;            /* ExtensionValue */
static int hf_p1_RequestedDeliveryMethod_item = -1;  /* RequestedDeliveryMethod_item */
static int hf_p1_ia5text = -1;                    /* IA5String */
static int hf_p1_octets = -1;                     /* OCTET_STRING */
static int hf_p1_RedirectionHistory_item = -1;    /* Redirection */
static int hf_p1_intended_recipient_name = -1;    /* IntendedRecipientName */
static int hf_p1_redirection_reason = -1;         /* RedirectionReason */
static int hf_p1_intended_recipient = -1;         /* ORAddressAndOptionalDirectoryName */
static int hf_p1_redirection_time = -1;           /* Time */
static int hf_p1_DLExpansionHistory_item = -1;    /* DLExpansion */
static int hf_p1_dl = -1;                         /* ORAddressAndOptionalDirectoryName */
static int hf_p1_dl_expansion_time = -1;          /* Time */
static int hf_p1_OriginatorAndDLExpansionHistory_item = -1;  /* OriginatorAndDLExpansion */
static int hf_p1_originator_or_dl_name = -1;      /* ORAddressAndOptionalDirectoryName */
static int hf_p1_origination_or_expansion_time = -1;  /* Time */
static int hf_p1_report_type = -1;                /* T_report_type */
static int hf_p1_report_type_delivery = -1;       /* PerRecipientDeliveryReportFields */
static int hf_p1_non_delivery_report = -1;        /* PerRecipientNonDeliveryReportFields */
static int hf_p1_domain = -1;                     /* GlobalDomainIdentifier */
static int hf_p1_mta_directory_name = -1;         /* Name */
static int hf_p1_ExtendedCertificates_item = -1;  /* ExtendedCertificate */
static int hf_p1_directory_entry = -1;            /* Name */
static int hf_p1_DLExemptedRecipients_item = -1;  /* ORAddressAndOrDirectoryName */
static int hf_p1_encryption_recipient = -1;       /* CertificateAssertion */
static int hf_p1_encryption_originator = -1;      /* CertificateAssertion */
static int hf_p1_selectors_content_integrity_check = -1;  /* CertificateAssertion */
static int hf_p1_token_signature = -1;            /* CertificateAssertion */
static int hf_p1_message_origin_authentication = -1;  /* CertificateAssertion */
static int hf_p1_local_identifier = -1;           /* LocalIdentifier */
static int hf_p1_numeric_private_domain_identifier = -1;  /* T_numeric_private_domain_identifier */
static int hf_p1_printable_private_domain_identifier = -1;  /* T_printable_private_domain_identifier */
static int hf_p1_built_in_standard_attributes = -1;  /* BuiltInStandardAttributes */
static int hf_p1_built_in_domain_defined_attributes = -1;  /* BuiltInDomainDefinedAttributes */
static int hf_p1_extension_attributes = -1;       /* ExtensionAttributes */
static int hf_p1_network_address = -1;            /* NetworkAddress */
static int hf_p1_terminal_identifier = -1;        /* TerminalIdentifier */
static int hf_p1_private_domain_name = -1;        /* PrivateDomainName */
static int hf_p1_organization_name = -1;          /* OrganizationName */
static int hf_p1_numeric_user_identifier = -1;    /* NumericUserIdentifier */
static int hf_p1_personal_name = -1;              /* PersonalName */
static int hf_p1_organizational_unit_names = -1;  /* OrganizationalUnitNames */
static int hf_p1_x121_dcc_code = -1;              /* T_x121_dcc_code */
static int hf_p1_iso_3166_alpha2_code = -1;       /* T_iso_3166_alpha2_code */
static int hf_p1_numeric = -1;                    /* T_numeric */
static int hf_p1_printable = -1;                  /* T_printable */
static int hf_p1_numeric_private_domain_name = -1;  /* T_numeric_private_domain_name */
static int hf_p1_printable_private_domain_name = -1;  /* T_printable_private_domain_name */
static int hf_p1_printable_surname = -1;          /* T_printable_surname */
static int hf_p1_printable_given_name = -1;       /* T_printable_given_name */
static int hf_p1_printable_initials = -1;         /* T_printable_initials */
static int hf_p1_printable_generation_qualifier = -1;  /* T_printable_generation_qualifier */
static int hf_p1_OrganizationalUnitNames_item = -1;  /* OrganizationalUnitName */
static int hf_p1_BuiltInDomainDefinedAttributes_item = -1;  /* BuiltInDomainDefinedAttribute */
static int hf_p1_printable_type = -1;             /* T_printable_type */
static int hf_p1_printable_value = -1;            /* T_printable_value */
static int hf_p1_ExtensionAttributes_item = -1;   /* ExtensionAttribute */
static int hf_p1_extension_attribute_type = -1;   /* ExtensionAttributeType */
static int hf_p1_extension_attribute_value = -1;  /* T_extension_attribute_value */
static int hf_p1_teletex_surname = -1;            /* T_teletex_surname */
static int hf_p1_teletex_given_name = -1;         /* T_teletex_given_name */
static int hf_p1_teletex_initials = -1;           /* T_teletex_initials */
static int hf_p1_teletex_generation_qualifier = -1;  /* T_teletex_generation_qualifier */
static int hf_p1_universal_surname = -1;          /* UniversalOrBMPString */
static int hf_p1_universal_given_name = -1;       /* UniversalOrBMPString */
static int hf_p1_universal_initials = -1;         /* UniversalOrBMPString */
static int hf_p1_universal_generation_qualifier = -1;  /* UniversalOrBMPString */
static int hf_p1_TeletexOrganizationalUnitNames_item = -1;  /* TeletexOrganizationalUnitName */
static int hf_p1_UniversalOrganizationalUnitNames_item = -1;  /* UniversalOrganizationalUnitName */
static int hf_p1_character_encoding = -1;         /* T_character_encoding */
static int hf_p1_two_octets = -1;                 /* BMPString_SIZE_1_ub_string_length */
static int hf_p1_four_octets = -1;                /* UniversalString_SIZE_1_ub_string_length */
static int hf_p1_iso_639_language_code = -1;      /* PrintableString_SIZE_CONSTR001 */
static int hf_p1_x121_dcc_code_01 = -1;           /* T_x121_dcc_code_01 */
static int hf_p1_iso_3166_alpha2_code_01 = -1;    /* T_iso_3166_alpha2_code_01 */
static int hf_p1_numeric_code = -1;               /* T_numeric_code */
static int hf_p1_printable_code = -1;             /* PrintableString_SIZE_1_ub_postal_code_length */
static int hf_p1_printable_address = -1;          /* T_printable_address */
static int hf_p1_printable_address_item = -1;     /* PrintableString_SIZE_1_ub_pds_parameter_length */
static int hf_p1_teletex_string = -1;             /* TeletexString_SIZE_1_ub_unformatted_address_length */
static int hf_p1_printable_string = -1;           /* PrintableString_SIZE_1_ub_pds_parameter_length */
static int hf_p1_pds_teletex_string = -1;         /* TeletexString_SIZE_1_ub_pds_parameter_length */
static int hf_p1_e163_4_address = -1;             /* T_e163_4_address */
static int hf_p1_number = -1;                     /* NumericString_SIZE_1_ub_e163_4_number_length */
static int hf_p1_sub_address = -1;                /* NumericString_SIZE_1_ub_e163_4_sub_address_length */
static int hf_p1_psap_address = -1;               /* PresentationAddress */
static int hf_p1_TeletexDomainDefinedAttributes_item = -1;  /* TeletexDomainDefinedAttribute */
static int hf_p1_type = -1;                       /* T_type */
static int hf_p1_teletex_value = -1;              /* T_teletex_value */
static int hf_p1_UniversalDomainDefinedAttributes_item = -1;  /* UniversalDomainDefinedAttribute */
static int hf_p1_universal_type = -1;             /* UniversalOrBMPString */
static int hf_p1_universal_value = -1;            /* UniversalOrBMPString */
static int hf_p1_ExtendedEncodedInformationTypes_item = -1;  /* ExtendedEncodedInformationType */
static int hf_p1_g3_facsimile = -1;               /* G3FacsimileNonBasicParameters */
static int hf_p1_teletex = -1;                    /* TeletexNonBasicParameters */
static int hf_p1_graphic_character_sets = -1;     /* TeletexString */
static int hf_p1_control_character_sets = -1;     /* TeletexString */
static int hf_p1_page_formats = -1;               /* OCTET_STRING */
static int hf_p1_miscellaneous_terminal_capabilities = -1;  /* TeletexString */
static int hf_p1_private_use = -1;                /* OCTET_STRING */
static int hf_p1_token_type_identifier = -1;      /* TokenTypeIdentifier */
static int hf_p1_token = -1;                      /* TokenTypeData */
static int hf_p1_signature_algorithm_identifier = -1;  /* AlgorithmIdentifier */
static int hf_p1_name = -1;                       /* T_name */
static int hf_p1_token_recipient_name = -1;       /* RecipientName */
static int hf_p1_token_mta = -1;                  /* MTANameAndOptionalGDI */
static int hf_p1_time = -1;                       /* Time */
static int hf_p1_signed_data = -1;                /* TokenData */
static int hf_p1_encryption_algorithm_identifier = -1;  /* AlgorithmIdentifier */
static int hf_p1_encrypted_data = -1;             /* BIT_STRING */
static int hf_p1_asymmetric_token_data = -1;      /* AsymmetricTokenData */
static int hf_p1_algorithm_identifier = -1;       /* AlgorithmIdentifier */
static int hf_p1_token_data_type = -1;            /* TokenDataType */
static int hf_p1_value = -1;                      /* T_value */
static int hf_p1_content_confidentiality_algorithm_identifier = -1;  /* ContentConfidentialityAlgorithmIdentifier */
static int hf_p1_content_integrity_check = -1;    /* ContentIntegrityCheck */
static int hf_p1_message_security_label = -1;     /* MessageSecurityLabel */
static int hf_p1_proof_of_delivery_request = -1;  /* ProofOfDeliveryRequest */
static int hf_p1_message_sequence_number = -1;    /* INTEGER */
static int hf_p1_content_confidentiality_key = -1;  /* EncryptionKey */
static int hf_p1_content_integrity_key = -1;      /* EncryptionKey */
static int hf_p1_security_policy_identifier = -1;  /* SecurityPolicyIdentifier */
static int hf_p1_security_classification = -1;    /* SecurityClassification */
static int hf_p1_privacy_mark = -1;               /* PrivacyMark */
static int hf_p1_security_categories = -1;        /* SecurityCategories */
static int hf_p1_SecurityCategories_item = -1;    /* SecurityCategory */
static int hf_p1_category_type = -1;              /* SecurityCategoryIdentifier */
static int hf_p1_category_value = -1;             /* CategoryValue */
static int hf_p1_mta_originator_name = -1;        /* MTAOriginatorName */
static int hf_p1_per_recipient_message_fields = -1;  /* SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageTransferFields */
static int hf_p1_per_recipient_message_fields_item = -1;  /* PerRecipientMessageTransferFields */
static int hf_p1_per_recipient_probe_transfer_fields = -1;  /* SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeTransferFields */
static int hf_p1_per_recipient_probe_transfer_fields_item = -1;  /* PerRecipientProbeTransferFields */
static int hf_p1_per_recipient_report_fields = -1;  /* SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportTransferFields */
static int hf_p1_per_recipient_report_fields_item = -1;  /* PerRecipientReportTransferFields */
static int hf_p1_routing_action = -1;             /* RoutingAction */
static int hf_p1_attempted = -1;                  /* T_attempted */
static int hf_p1_mta = -1;                        /* MTAName */
static int hf_p1_attempted_domain = -1;           /* GlobalDomainIdentifier */
static int hf_p1_per_recipient_report_delivery_fields = -1;  /* SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportDeliveryFields */
static int hf_p1_per_recipient_report_delivery_fields_item = -1;  /* PerRecipientReportDeliveryFields */
static int hf_p1_mts_originator_name = -1;        /* OriginatorName */
static int hf_p1_per_recipient_message_submission_fields = -1;  /* SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageSubmissionFields */
static int hf_p1_per_recipient_message_submission_fields_item = -1;  /* PerRecipientMessageSubmissionFields */
static int hf_p1_per_recipient_probe_submission_fields = -1;  /* SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeSubmissionFields */
static int hf_p1_per_recipient_probe_submission_fields_item = -1;  /* PerRecipientProbeSubmissionFields */
static int hf_p1_directory_name = -1;             /* Name */
static int hf_p1_built_in_encoded_information_types = -1;  /* BuiltInEncodedInformationTypes */
static int hf_p1_extended_encoded_information_types = -1;  /* ExtendedEncodedInformationTypes */
/* named bits */
static int hf_p1_PerRecipientIndicators_responsibility = -1;
static int hf_p1_PerRecipientIndicators_originating_MTA_report = -1;
static int hf_p1_PerRecipientIndicators_originating_MTA_non_delivery_report = -1;
static int hf_p1_PerRecipientIndicators_originator_report = -1;
static int hf_p1_PerRecipientIndicators_originator_non_delivery_report = -1;
static int hf_p1_PerRecipientIndicators_reserved_5 = -1;
static int hf_p1_PerRecipientIndicators_reserved_6 = -1;
static int hf_p1_PerRecipientIndicators_reserved_7 = -1;
static int hf_p1_OtherActions_redirected = -1;
static int hf_p1_OtherActions_dl_operation = -1;
static int hf_p1_Operations_probe_submission_or_report_delivery = -1;
static int hf_p1_Operations_message_submission_or_message_delivery = -1;
static int hf_p1_WaitingMessages_long_content = -1;
static int hf_p1_WaitingMessages_low_priority = -1;
static int hf_p1_WaitingMessages_other_security_labels = -1;
static int hf_p1_T_source_type_originated_by = -1;
static int hf_p1_T_source_type_redirected_by = -1;
static int hf_p1_T_source_type_dl_expanded_by = -1;
static int hf_p1_T_standard_parameters_user_name = -1;
static int hf_p1_T_standard_parameters_user_address = -1;
static int hf_p1_T_standard_parameters_deliverable_class = -1;
static int hf_p1_T_standard_parameters_default_delivery_controls = -1;
static int hf_p1_T_standard_parameters_redirections = -1;
static int hf_p1_T_standard_parameters_restricted_delivery = -1;
static int hf_p1_PerMessageIndicators_U_disclosure_of_other_recipients = -1;
static int hf_p1_PerMessageIndicators_U_implicit_conversion_prohibited = -1;
static int hf_p1_PerMessageIndicators_U_alternate_recipient_allowed = -1;
static int hf_p1_PerMessageIndicators_U_content_return_request = -1;
static int hf_p1_PerMessageIndicators_U_reserved = -1;
static int hf_p1_PerMessageIndicators_U_bit_5 = -1;
static int hf_p1_PerMessageIndicators_U_bit_6 = -1;
static int hf_p1_PerMessageIndicators_U_service_message = -1;
static int hf_p1_OriginatorReportRequest_report = -1;
static int hf_p1_OriginatorReportRequest_non_delivery_report = -1;
static int hf_p1_DeliveryFlags_implicit_conversion_prohibited = -1;
static int hf_p1_Criticality_for_submission = -1;
static int hf_p1_Criticality_for_transfer = -1;
static int hf_p1_Criticality_for_delivery = -1;
static int hf_p1_PhysicalDeliveryModes_ordinary_mail = -1;
static int hf_p1_PhysicalDeliveryModes_special_delivery = -1;
static int hf_p1_PhysicalDeliveryModes_express_mail = -1;
static int hf_p1_PhysicalDeliveryModes_counter_collection = -1;
static int hf_p1_PhysicalDeliveryModes_counter_collection_with_telephone_advice = -1;
static int hf_p1_PhysicalDeliveryModes_counter_collection_with_telex_advice = -1;
static int hf_p1_PhysicalDeliveryModes_counter_collection_with_teletex_advice = -1;
static int hf_p1_PhysicalDeliveryModes_bureau_fax_delivery = -1;
static int hf_p1_BuiltInEncodedInformationTypes_unknown = -1;
static int hf_p1_BuiltInEncodedInformationTypes_ia5_text = -1;
static int hf_p1_BuiltInEncodedInformationTypes_g3_facsimile = -1;
static int hf_p1_BuiltInEncodedInformationTypes_g4_class_1 = -1;
static int hf_p1_BuiltInEncodedInformationTypes_teletex = -1;
static int hf_p1_BuiltInEncodedInformationTypes_videotex = -1;
static int hf_p1_BuiltInEncodedInformationTypes_voice = -1;
static int hf_p1_BuiltInEncodedInformationTypes_sfd = -1;
static int hf_p1_BuiltInEncodedInformationTypes_mixed_mode = -1;
static int hf_p1_G3FacsimileNonBasicParameters_two_dimensional = -1;
static int hf_p1_G3FacsimileNonBasicParameters_fine_resolution = -1;
static int hf_p1_G3FacsimileNonBasicParameters_unlimited_length = -1;
static int hf_p1_G3FacsimileNonBasicParameters_b4_length = -1;
static int hf_p1_G3FacsimileNonBasicParameters_a3_width = -1;
static int hf_p1_G3FacsimileNonBasicParameters_b4_width = -1;
static int hf_p1_G3FacsimileNonBasicParameters_t6_coding = -1;
static int hf_p1_G3FacsimileNonBasicParameters_uncompressed = -1;
static int hf_p1_G3FacsimileNonBasicParameters_width_middle_864_of_1728 = -1;
static int hf_p1_G3FacsimileNonBasicParameters_width_middle_1216_of_1728 = -1;
static int hf_p1_G3FacsimileNonBasicParameters_resolution_type = -1;
static int hf_p1_G3FacsimileNonBasicParameters_resolution_400x400 = -1;
static int hf_p1_G3FacsimileNonBasicParameters_resolution_300x300 = -1;
static int hf_p1_G3FacsimileNonBasicParameters_resolution_8x15 = -1;
static int hf_p1_G3FacsimileNonBasicParameters_edi = -1;
static int hf_p1_G3FacsimileNonBasicParameters_dtm = -1;
static int hf_p1_G3FacsimileNonBasicParameters_bft = -1;
static int hf_p1_G3FacsimileNonBasicParameters_mixed_mode = -1;
static int hf_p1_G3FacsimileNonBasicParameters_character_mode = -1;
static int hf_p1_G3FacsimileNonBasicParameters_twelve_bits = -1;
static int hf_p1_G3FacsimileNonBasicParameters_preferred_huffmann = -1;
static int hf_p1_G3FacsimileNonBasicParameters_full_colour = -1;
static int hf_p1_G3FacsimileNonBasicParameters_jpeg = -1;
static int hf_p1_G3FacsimileNonBasicParameters_processable_mode_26 = -1;

/*--- End of included file: packet-p1-hf.c ---*/
#line 83 "../../asn1/p1/packet-p1-template.c"

/* Initialize the subtree pointers */
static gint ett_p1 = -1;
static gint ett_p3 = -1;
static gint ett_p1_content_unknown = -1;
static gint ett_p1_bilateral_information = -1;
static gint ett_p1_additional_information = -1;
static gint ett_p1_unknown_standard_extension = -1;
static gint ett_p1_unknown_extension_attribute_type = -1;
static gint ett_p1_unknown_tokendata_type = -1;

/*--- Included file: packet-p1-ett.c ---*/
#line 1 "../../asn1/p1/packet-p1-ett.c"
static gint ett_p1_MTABindArgument = -1;
static gint ett_p1_AuthenticatedArgument = -1;
static gint ett_p1_MTABindResult = -1;
static gint ett_p1_AuthenticatedResult = -1;
static gint ett_p1_MTS_APDU = -1;
static gint ett_p1_Message = -1;
static gint ett_p1_Report = -1;
static gint ett_p1_MessageTransferEnvelope = -1;
static gint ett_p1_PerMessageTransferFields = -1;
static gint ett_p1_SEQUENCE_SIZE_1_ub_transfers_OF_PerDomainBilateralInformation = -1;
static gint ett_p1_SET_OF_ExtensionField = -1;
static gint ett_p1_PerRecipientMessageTransferFields = -1;
static gint ett_p1_ProbeTransferEnvelope = -1;
static gint ett_p1_PerProbeTransferFields = -1;
static gint ett_p1_PerRecipientProbeTransferFields = -1;
static gint ett_p1_ReportTransferEnvelope = -1;
static gint ett_p1_ReportTransferContent = -1;
static gint ett_p1_PerReportTransferFields = -1;
static gint ett_p1_PerRecipientReportTransferFields = -1;
static gint ett_p1_PerDomainBilateralInformation = -1;
static gint ett_p1_T_bilateral_domain = -1;
static gint ett_p1_T_private_domain = -1;
static gint ett_p1_PerRecipientIndicators = -1;
static gint ett_p1_LastTraceInformation = -1;
static gint ett_p1_InternalTraceInformation = -1;
static gint ett_p1_InternalTraceInformationElement = -1;
static gint ett_p1_MTASuppliedInformation = -1;
static gint ett_p1_SEQUENCE_SIZE_1_ub_transfers_OF_TraceInformationElement = -1;
static gint ett_p1_TraceInformationElement = -1;
static gint ett_p1_DomainSuppliedInformation = -1;
static gint ett_p1_AdditionalActions = -1;
static gint ett_p1_OtherActions = -1;
static gint ett_p1_MTSBindArgument = -1;
static gint ett_p1_MTSBindResult = -1;
static gint ett_p1_ObjectName = -1;
static gint ett_p1_MessagesWaiting = -1;
static gint ett_p1_DeliveryQueue = -1;
static gint ett_p1_Credentials = -1;
static gint ett_p1_Password = -1;
static gint ett_p1_StrongCredentials = -1;
static gint ett_p1_ProtectedPassword = -1;
static gint ett_p1_Signature = -1;
static gint ett_p1_SecurityContext = -1;
static gint ett_p1_MessageSubmissionArgument = -1;
static gint ett_p1_MessageSubmissionResult = -1;
static gint ett_p1_ProbeSubmissionResult = -1;
static gint ett_p1_ImproperlySpecifiedRecipients = -1;
static gint ett_p1_Waiting = -1;
static gint ett_p1_SET_SIZE_0_ub_content_types_OF_ContentType = -1;
static gint ett_p1_Operations = -1;
static gint ett_p1_WaitingMessages = -1;
static gint ett_p1_MessageDeliveryArgument = -1;
static gint ett_p1_MessageDeliveryResult = -1;
static gint ett_p1_ReportDeliveryArgument = -1;
static gint ett_p1_ReportDeliveryResult = -1;
static gint ett_p1_SET_SIZE_1_MAX_OF_ExtensionField = -1;
static gint ett_p1_DeliveryControlArgument = -1;
static gint ett_p1_DeliveryControlResult = -1;
static gint ett_p1_RefusedOperation = -1;
static gint ett_p1_T_refused_argument = -1;
static gint ett_p1_Controls = -1;
static gint ett_p1_RegisterArgument = -1;
static gint ett_p1_SET_SIZE_1_ub_deliverable_class_OF_DeliverableClass = -1;
static gint ett_p1_RegisterResult = -1;
static gint ett_p1_T_non_empty_result = -1;
static gint ett_p1_ChangeCredentialsArgument = -1;
static gint ett_p1_UserAddress = -1;
static gint ett_p1_T_x121 = -1;
static gint ett_p1_Redirections = -1;
static gint ett_p1_RecipientRedirection = -1;
static gint ett_p1_SET_SIZE_1_ub_redirection_classes_OF_RedirectionClass = -1;
static gint ett_p1_MessageClass = -1;
static gint ett_p1_SET_OF_Priority = -1;
static gint ett_p1_SEQUENCE_OF_Restriction = -1;
static gint ett_p1_EncodedInformationTypesConstraints = -1;
static gint ett_p1_RestrictedDelivery = -1;
static gint ett_p1_Restriction = -1;
static gint ett_p1_T_source_type = -1;
static gint ett_p1_ExactOrPattern = -1;
static gint ett_p1_RegistrationTypes = -1;
static gint ett_p1_T_standard_parameters = -1;
static gint ett_p1_T_type_extensions = -1;
static gint ett_p1_MessageSubmissionEnvelope = -1;
static gint ett_p1_PerMessageSubmissionFields = -1;
static gint ett_p1_PerRecipientMessageSubmissionFields = -1;
static gint ett_p1_ProbeSubmissionEnvelope = -1;
static gint ett_p1_PerProbeSubmissionFields = -1;
static gint ett_p1_PerRecipientProbeSubmissionFields = -1;
static gint ett_p1_MessageDeliveryEnvelope = -1;
static gint ett_p1_OtherMessageDeliveryFields = -1;
static gint ett_p1_ReportDeliveryEnvelope = -1;
static gint ett_p1_PerReportDeliveryFields = -1;
static gint ett_p1_PerRecipientReportDeliveryFields = -1;
static gint ett_p1_ReportType = -1;
static gint ett_p1_DeliveryReport = -1;
static gint ett_p1_NonDeliveryReport = -1;
static gint ett_p1_ContentTypes = -1;
static gint ett_p1_ContentType = -1;
static gint ett_p1_DeliveredContentType = -1;
static gint ett_p1_PerMessageIndicators_U = -1;
static gint ett_p1_OriginatorReportRequest = -1;
static gint ett_p1_DeliveryFlags = -1;
static gint ett_p1_OtherRecipientNames = -1;
static gint ett_p1_ExtensionType = -1;
static gint ett_p1_Criticality = -1;
static gint ett_p1_ExtensionField = -1;
static gint ett_p1_RequestedDeliveryMethod = -1;
static gint ett_p1_PhysicalDeliveryModes = -1;
static gint ett_p1_ContentCorrelator = -1;
static gint ett_p1_RedirectionHistory = -1;
static gint ett_p1_Redirection = -1;
static gint ett_p1_IntendedRecipientName = -1;
static gint ett_p1_DLExpansionHistory = -1;
static gint ett_p1_DLExpansion = -1;
static gint ett_p1_OriginatorAndDLExpansionHistory = -1;
static gint ett_p1_OriginatorAndDLExpansion = -1;
static gint ett_p1_PerRecipientReportFields = -1;
static gint ett_p1_T_report_type = -1;
static gint ett_p1_PerRecipientDeliveryReportFields = -1;
static gint ett_p1_PerRecipientNonDeliveryReportFields = -1;
static gint ett_p1_ReportingMTAName = -1;
static gint ett_p1_ExtendedCertificates = -1;
static gint ett_p1_ExtendedCertificate = -1;
static gint ett_p1_DLExemptedRecipients = -1;
static gint ett_p1_CertificateSelectors = -1;
static gint ett_p1_MTSIdentifier_U = -1;
static gint ett_p1_GlobalDomainIdentifier_U = -1;
static gint ett_p1_PrivateDomainIdentifier = -1;
static gint ett_p1_ORName_U = -1;
static gint ett_p1_ORAddress = -1;
static gint ett_p1_BuiltInStandardAttributes = -1;
static gint ett_p1_CountryName_U = -1;
static gint ett_p1_AdministrationDomainName_U = -1;
static gint ett_p1_PrivateDomainName = -1;
static gint ett_p1_PersonalName = -1;
static gint ett_p1_OrganizationalUnitNames = -1;
static gint ett_p1_BuiltInDomainDefinedAttributes = -1;
static gint ett_p1_BuiltInDomainDefinedAttribute = -1;
static gint ett_p1_ExtensionAttributes = -1;
static gint ett_p1_ExtensionAttribute = -1;
static gint ett_p1_TeletexPersonalName = -1;
static gint ett_p1_UniversalPersonalName = -1;
static gint ett_p1_TeletexOrganizationalUnitNames = -1;
static gint ett_p1_UniversalOrganizationalUnitNames = -1;
static gint ett_p1_UniversalOrBMPString = -1;
static gint ett_p1_T_character_encoding = -1;
static gint ett_p1_PhysicalDeliveryCountryName = -1;
static gint ett_p1_PostalCode = -1;
static gint ett_p1_UnformattedPostalAddress = -1;
static gint ett_p1_T_printable_address = -1;
static gint ett_p1_PDSParameter = -1;
static gint ett_p1_ExtendedNetworkAddress = -1;
static gint ett_p1_T_e163_4_address = -1;
static gint ett_p1_TeletexDomainDefinedAttributes = -1;
static gint ett_p1_TeletexDomainDefinedAttribute = -1;
static gint ett_p1_UniversalDomainDefinedAttributes = -1;
static gint ett_p1_UniversalDomainDefinedAttribute = -1;
static gint ett_p1_EncodedInformationTypes_U = -1;
static gint ett_p1_BuiltInEncodedInformationTypes = -1;
static gint ett_p1_ExtendedEncodedInformationTypes = -1;
static gint ett_p1_NonBasicParameters = -1;
static gint ett_p1_G3FacsimileNonBasicParameters = -1;
static gint ett_p1_TeletexNonBasicParameters = -1;
static gint ett_p1_Token = -1;
static gint ett_p1_AsymmetricTokenData = -1;
static gint ett_p1_T_name = -1;
static gint ett_p1_MTANameAndOptionalGDI = -1;
static gint ett_p1_AsymmetricToken = -1;
static gint ett_p1_TokenData = -1;
static gint ett_p1_MessageTokenSignedData = -1;
static gint ett_p1_MessageTokenEncryptedData = -1;
static gint ett_p1_SecurityLabel = -1;
static gint ett_p1_SecurityCategories = -1;
static gint ett_p1_SecurityCategory = -1;
static gint ett_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageTransferFields = -1;
static gint ett_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeTransferFields = -1;
static gint ett_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportTransferFields = -1;
static gint ett_p1_T_attempted = -1;
static gint ett_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportDeliveryFields = -1;
static gint ett_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageSubmissionFields = -1;
static gint ett_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeSubmissionFields = -1;

/*--- End of included file: packet-p1-ett.c ---*/
#line 94 "../../asn1/p1/packet-p1-template.c"

/* Dissector tables */
static dissector_table_t p1_extension_dissector_table;
static dissector_table_t p1_extension_attribute_dissector_table;
static dissector_table_t p1_tokendata_dissector_table;


/*--- Included file: packet-p1-table.c ---*/
#line 1 "../../asn1/p1/packet-p1-table.c"

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


/*--- End of included file: packet-p1-table.c ---*/
#line 101 "../../asn1/p1/packet-p1-template.c"


/*--- Included file: packet-p1-fn.c ---*/
#line 1 "../../asn1/p1/packet-p1-fn.c"


static int
dissect_p1_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_p1_MTAName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 681 "../../asn1/p1/p1.cnf"
	tvbuff_t	*mtaname = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                                        actx, tree, tvb, offset,
                                                        1, ub_mta_name_length, hf_index, &mtaname);


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
dissect_p1_IA5String_SIZE_0_ub_password_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                                        actx, tree, tvb, offset,
                                                        0, ub_password_length, hf_index, NULL);

  return offset;
}



static int
dissect_p1_OCTET_STRING_SIZE_0_ub_password_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   0, ub_password_length, hf_index, NULL);

  return offset;
}


static const value_string p1_Password_vals[] = {
  {   0, "ia5-string" },
  {   1, "octet-string" },
  { 0, NULL }
};

static const ber_choice_t Password_choice[] = {
  {   0, &hf_p1_ia5_string       , BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_p1_IA5String_SIZE_0_ub_password_length },
  {   1, &hf_p1_octet_string     , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_p1_OCTET_STRING_SIZE_0_ub_password_length },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_Password(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Password_choice, hf_index, ett_p1_Password,
                                 NULL);

  return offset;
}



static int
dissect_p1_TokenTypeIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &object_identifier_id);

  return offset;
}



static int
dissect_p1_TokenTypeData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1215 "../../asn1/p1/p1.cnf"
	
	if(object_identifier_id) 
   	   call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t Token_sequence[] = {
  { &hf_p1_token_type_identifier, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_TokenTypeIdentifier },
  { &hf_p1_token            , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_p1_TokenTypeData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_Token(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Token_sequence, hf_index, ett_p1_Token);

  return offset;
}


static const ber_sequence_t StrongCredentials_set[] = {
  { &hf_p1_bind_token       , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_Token },
  { &hf_p1_certificate      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509af_Certificates },
  { &hf_p1_certificate_selector, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_CertificateAssertion },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_StrongCredentials(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              StrongCredentials_set, hf_index, ett_p1_StrongCredentials);

  return offset;
}



static int
dissect_p1_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t Signature_sequence[] = {
  { &hf_p1_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_p1_encrypted        , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_p1_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_Signature(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Signature_sequence, hf_index, ett_p1_Signature);

  return offset;
}



static int
dissect_p1_UTCTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_UTCTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t ProtectedPassword_set[] = {
  { &hf_p1_signature        , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_p1_Signature },
  { &hf_p1_time1            , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_UTCTime },
  { &hf_p1_time2            , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_UTCTime },
  { &hf_p1_random1          , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_BIT_STRING },
  { &hf_p1_random2          , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_ProtectedPassword(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ProtectedPassword_set, hf_index, ett_p1_ProtectedPassword);

  return offset;
}


const value_string p1_Credentials_vals[] = {
  {   0, "simple" },
  {   1, "strong" },
  {   2, "protected" },
  { 0, NULL }
};

static const ber_choice_t Credentials_choice[] = {
  {   0, &hf_p1_simple           , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_p1_Password },
  {   1, &hf_p1_strong           , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_StrongCredentials },
  {   2, &hf_p1_protected        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_p1_ProtectedPassword },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_p1_Credentials(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1223 "../../asn1/p1/p1.cnf"
  gint credentials = -1;

    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Credentials_choice, hf_index, ett_p1_Credentials,
                                 &credentials);


  if( (credentials!=-1) && p1_Credentials_vals[credentials].strptr ){
    if (check_col(actx->pinfo->cinfo, COL_INFO)) {
      col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", p1_Credentials_vals[credentials].strptr);
    }
  }



  return offset;
}



int
dissect_p1_InitiatorCredentials(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_Credentials(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_SecurityPolicyIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string p1_SecurityClassification_vals[] = {
  {   0, "unmarked" },
  {   1, "unclassified" },
  {   2, "restricted" },
  {   3, "confidential" },
  {   4, "secret" },
  {   5, "top-secret" },
  { 0, NULL }
};


static int
dissect_p1_SecurityClassification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, ub_integer_options, hf_index, NULL);

  return offset;
}



static int
dissect_p1_PrivacyMark(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_privacy_mark_length, hf_index, NULL);

  return offset;
}



static int
dissect_p1_SecurityCategoryIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &object_identifier_id);

  return offset;
}



static int
dissect_p1_SecurityCategoryValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 561 "../../asn1/p1/p1.cnf"
	const char *name;

	if (object_identifier_id) {
		offset = call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);
		name = oid_resolved_from_string(object_identifier_id);
		proto_item_append_text(tree, " (%s)", name ? name : object_identifier_id); 
	} else {
		offset = dissect_unknown_ber(actx->pinfo, tvb, offset, tree);
	}



  return offset;
}



static int
dissect_p1_CategoryValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_SecurityCategoryValue(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t SecurityCategory_sequence[] = {
  { &hf_p1_category_type    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_SecurityCategoryIdentifier },
  { &hf_p1_category_value   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_p1_CategoryValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_SecurityCategory(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SecurityCategory_sequence, hf_index, ett_p1_SecurityCategory);

  return offset;
}


static const ber_sequence_t SecurityCategories_set_of[1] = {
  { &hf_p1_SecurityCategories_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_p1_SecurityCategory },
};

static int
dissect_p1_SecurityCategories(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_set_of(implicit_tag, actx, tree, tvb, offset,
                                             1, ub_security_categories, SecurityCategories_set_of, hf_index, ett_p1_SecurityCategories);

  return offset;
}


static const ber_sequence_t SecurityLabel_set[] = {
  { &hf_p1_security_policy_identifier, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_SecurityPolicyIdentifier },
  { &hf_p1_security_classification, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_SecurityClassification },
  { &hf_p1_privacy_mark     , BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_PrivacyMark },
  { &hf_p1_security_categories, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_SecurityCategories },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_p1_SecurityLabel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SecurityLabel_set, hf_index, ett_p1_SecurityLabel);

  return offset;
}


static const ber_sequence_t SecurityContext_set_of[1] = {
  { &hf_p1_SecurityContext_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p1_SecurityLabel },
};

int
dissect_p1_SecurityContext(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_set_of(implicit_tag, actx, tree, tvb, offset,
                                             1, ub_security_labels, SecurityContext_set_of, hf_index, ett_p1_SecurityContext);

  return offset;
}


static const ber_sequence_t AuthenticatedArgument_set[] = {
  { &hf_p1_authenticated_initiator_name, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_MTAName },
  { &hf_p1_initiator_credentials, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_InitiatorCredentials },
  { &hf_p1_security_context , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SecurityContext },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_AuthenticatedArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              AuthenticatedArgument_set, hf_index, ett_p1_AuthenticatedArgument);

  return offset;
}


static const value_string p1_MTABindArgument_vals[] = {
  {   0, "unauthenticated" },
  {   1, "authenticated" },
  { 0, NULL }
};

static const ber_choice_t MTABindArgument_choice[] = {
  {   0, &hf_p1_unauthenticated  , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_p1_NULL },
  {   1, &hf_p1_authenticated_argument, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_p1_AuthenticatedArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_MTABindArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 MTABindArgument_choice, hf_index, ett_p1_MTABindArgument,
                                 NULL);

  return offset;
}



int
dissect_p1_ResponderCredentials(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_Credentials(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t AuthenticatedResult_set[] = {
  { &hf_p1_authenticated_responder_name, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_MTAName },
  { &hf_p1_responder_credentials, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_ResponderCredentials },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_AuthenticatedResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              AuthenticatedResult_set, hf_index, ett_p1_AuthenticatedResult);

  return offset;
}


static const value_string p1_MTABindResult_vals[] = {
  {   0, "unauthenticated" },
  {   1, "authenticated" },
  { 0, NULL }
};

static const ber_choice_t MTABindResult_choice[] = {
  {   0, &hf_p1_unauthenticated  , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_p1_NULL },
  {   1, &hf_p1_authenticated_result, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_p1_AuthenticatedResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_MTABindResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 MTABindResult_choice, hf_index, ett_p1_MTABindResult,
                                 NULL);

  return offset;
}


static const value_string p1_MTABindError_vals[] = {
  {   0, "busy" },
  {   2, "authentication-error" },
  {   3, "unacceptable-dialogue-mode" },
  {   4, "unacceptable-security-context" },
  {   5, "inadequate-association-confidentiality" },
  { 0, NULL }
};


static int
dissect_p1_MTABindError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1206 "../../asn1/p1/p1.cnf"
  int error = -1;
    offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, ub_integer_options, hf_index, &error);

  if((error != -1) && check_col(actx->pinfo->cinfo, COL_INFO))
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, " (%s)", val_to_str(error, p1_MTABindError_vals, "error(%d)"));



  return offset;
}



static int
dissect_p1_T_x121_dcc_code(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 865 "../../asn1/p1/p1.cnf"
	tvbuff_t	*nstring = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                                        actx, tree, tvb, offset,
                                                        ub_country_name_numeric_length, ub_country_name_numeric_length, hf_index, &nstring);


	if(doing_address && nstring)
		g_strlcat(oraddress, tvb_format_text(nstring, 0, tvb_length(nstring)), MAX_ORA_STR_LEN);



  return offset;
}



static int
dissect_p1_T_iso_3166_alpha2_code(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 817 "../../asn1/p1/p1.cnf"
	tvbuff_t	*nstring = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        ub_country_name_alpha_length, ub_country_name_alpha_length, hf_index, &nstring);


	if(doing_address && nstring)
		g_strlcat(oraddress, tvb_format_text(nstring, 0, tvb_length(nstring)), MAX_ORA_STR_LEN);



  return offset;
}


static const value_string p1_CountryName_U_vals[] = {
  {   0, "x121-dcc-code" },
  {   1, "iso-3166-alpha2-code" },
  { 0, NULL }
};

static const ber_choice_t CountryName_U_choice[] = {
  {   0, &hf_p1_x121_dcc_code    , BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_p1_T_x121_dcc_code },
  {   1, &hf_p1_iso_3166_alpha2_code, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_p1_T_iso_3166_alpha2_code },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_CountryName_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CountryName_U_choice, hf_index, ett_p1_CountryName_U,
                                 NULL);

  return offset;
}



static int
dissect_p1_CountryName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 595 "../../asn1/p1/p1.cnf"
 if(doing_address)
    g_strlcat(oraddress, "/C=", MAX_ORA_STR_LEN);
 
   offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 1, TRUE, dissect_p1_CountryName_U);





  return offset;
}



static int
dissect_p1_T_numeric(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 873 "../../asn1/p1/p1.cnf"
	tvbuff_t	*nstring = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                                        actx, tree, tvb, offset,
                                                        0, ub_domain_name_length, hf_index, &nstring);


	if(doing_address && nstring)
		g_strlcat(oraddress, tvb_format_text(nstring, 0, tvb_length(nstring)), MAX_ORA_STR_LEN);



  return offset;
}



static int
dissect_p1_T_printable(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 825 "../../asn1/p1/p1.cnf"
	tvbuff_t	*nstring = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        0, ub_domain_name_length, hf_index, &nstring);


	if(doing_address && nstring)
		g_strlcat(oraddress, tvb_format_text(nstring, 0, tvb_length(nstring)), MAX_ORA_STR_LEN);



  return offset;
}


static const value_string p1_AdministrationDomainName_U_vals[] = {
  {   0, "numeric" },
  {   1, "printable" },
  { 0, NULL }
};

static const ber_choice_t AdministrationDomainName_U_choice[] = {
  {   0, &hf_p1_numeric          , BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_p1_T_numeric },
  {   1, &hf_p1_printable        , BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_p1_T_printable },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_AdministrationDomainName_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AdministrationDomainName_U_choice, hf_index, ett_p1_AdministrationDomainName_U,
                                 NULL);

  return offset;
}



static int
dissect_p1_AdministrationDomainName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 602 "../../asn1/p1/p1.cnf"
  if(doing_address)
    g_strlcat(oraddress, "/A=", MAX_ORA_STR_LEN);

   offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 2, TRUE, dissect_p1_AdministrationDomainName_U);





  return offset;
}



static int
dissect_p1_T_numeric_private_domain_identifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 889 "../../asn1/p1/p1.cnf"
	tvbuff_t	*nstring = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_domain_name_length, hf_index, &nstring);


	if(doing_address && nstring)
		g_strlcat(oraddress, tvb_format_text(nstring, 0, tvb_length(nstring)), MAX_ORA_STR_LEN);



  return offset;
}



static int
dissect_p1_T_printable_private_domain_identifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 841 "../../asn1/p1/p1.cnf"
	tvbuff_t	*nstring = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_domain_name_length, hf_index, &nstring);


	if(doing_address && nstring)
		g_strlcat(oraddress, tvb_format_text(nstring, 0, tvb_length(nstring)), MAX_ORA_STR_LEN);



  return offset;
}


static const value_string p1_PrivateDomainIdentifier_vals[] = {
  {   0, "numeric" },
  {   1, "printable" },
  { 0, NULL }
};

static const ber_choice_t PrivateDomainIdentifier_choice[] = {
  {   0, &hf_p1_numeric_private_domain_identifier, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_p1_T_numeric_private_domain_identifier },
  {   1, &hf_p1_printable_private_domain_identifier, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_p1_T_printable_private_domain_identifier },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_PrivateDomainIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 732 "../../asn1/p1/p1.cnf"

	if(doing_address)
		g_strlcat(oraddress, "/P=", MAX_ORA_STR_LEN);

	  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PrivateDomainIdentifier_choice, hf_index, ett_p1_PrivateDomainIdentifier,
                                 NULL);




  return offset;
}


static const ber_sequence_t GlobalDomainIdentifier_U_sequence[] = {
  { &hf_p1_country_name     , BER_CLASS_APP, 1, BER_FLAGS_NOOWNTAG, dissect_p1_CountryName },
  { &hf_p1_administration_domain_name, BER_CLASS_APP, 2, BER_FLAGS_NOOWNTAG, dissect_p1_AdministrationDomainName },
  { &hf_p1_private_domain_identifier, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_PrivateDomainIdentifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_GlobalDomainIdentifier_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GlobalDomainIdentifier_U_sequence, hf_index, ett_p1_GlobalDomainIdentifier_U);

  return offset;
}



static int
dissect_p1_GlobalDomainIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1086 "../../asn1/p1/p1.cnf"
	
	oraddress = ep_alloc(MAX_ORA_STR_LEN); oraddress[0] = '\0';	
	address_item = tree;

	  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 3, TRUE, dissect_p1_GlobalDomainIdentifier_U);


	if(*oraddress) {
		proto_item_append_text(address_item, " (%s/", oraddress);

		if(doing_subjectid  && check_col(actx->pinfo->cinfo, COL_INFO)) {
			col_append_fstr(actx->pinfo->cinfo, COL_INFO, " (%s/", oraddress);
		}
	}




  return offset;
}



static int
dissect_p1_LocalIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1105 "../../asn1/p1/p1.cnf"
	tvbuff_t 	*id = NULL;
	
	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                                        actx, tree, tvb, offset,
                                                        1, ub_local_id_length, hf_index, &id);

	
	if(id) {
	  if(doing_address) 
		  proto_item_append_text(address_item, " $ %s)", tvb_format_text(id, 0, tvb_length(id)));

          if(doing_subjectid  && check_col(actx->pinfo->cinfo, COL_INFO)) 
		col_append_fstr(actx->pinfo->cinfo, COL_INFO, " $ %s)", tvb_format_text(id, 0, tvb_length(id)));
	}



  return offset;
}


static const ber_sequence_t MTSIdentifier_U_sequence[] = {
  { &hf_p1_global_domain_identifier, BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_p1_GlobalDomainIdentifier },
  { &hf_p1_local_identifier , BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_p1_LocalIdentifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_MTSIdentifier_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MTSIdentifier_U_sequence, hf_index, ett_p1_MTSIdentifier_U);

  return offset;
}



static int
dissect_p1_MTSIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1118 "../../asn1/p1/p1.cnf"

	doing_address = TRUE;

	if(hf_index == hf_p1_subject_identifier)
		doing_subjectid = TRUE;

	  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 4, TRUE, dissect_p1_MTSIdentifier_U);


	doing_address = FALSE;

	if(hf_index == hf_p1_subject_identifier)
		doing_subjectid = FALSE;




  return offset;
}



static int
dissect_p1_MessageIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1080 "../../asn1/p1/p1.cnf"

	address_item = NULL;

	  offset = dissect_p1_MTSIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);




  return offset;
}



static int
dissect_p1_X121Address(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 701 "../../asn1/p1/p1.cnf"
	tvbuff_t	*string = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_x121_address_length, hf_index, &string);


	if(doing_address && string) {
		g_strlcat(oraddress, "/X121=", MAX_ORA_STR_LEN);
		g_strlcat(oraddress, tvb_format_text(string, 0, tvb_length(string)), MAX_ORA_STR_LEN);
	}




  return offset;
}



static int
dissect_p1_NetworkAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_X121Address(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_TerminalIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 715 "../../asn1/p1/p1.cnf"
	tvbuff_t	*string = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_terminal_id_length, hf_index, &string);


	if(doing_address && string) {
		g_strlcat(oraddress, "/UA-ID=", MAX_ORA_STR_LEN);
		g_strlcat(oraddress, tvb_format_text(string, 0, tvb_length(string)), MAX_ORA_STR_LEN);
	}



  return offset;
}



static int
dissect_p1_T_numeric_private_domain_name(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 881 "../../asn1/p1/p1.cnf"
	tvbuff_t	*nstring = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_domain_name_length, hf_index, &nstring);


	if(doing_address && nstring)
		g_strlcat(oraddress, tvb_format_text(nstring, 0, tvb_length(nstring)), MAX_ORA_STR_LEN);



  return offset;
}



static int
dissect_p1_T_printable_private_domain_name(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 833 "../../asn1/p1/p1.cnf"
	tvbuff_t	*nstring = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_domain_name_length, hf_index, &nstring);


	if(doing_address && nstring)
		g_strlcat(oraddress, tvb_format_text(nstring, 0, tvb_length(nstring)), MAX_ORA_STR_LEN);



  return offset;
}


static const value_string p1_PrivateDomainName_vals[] = {
  {   0, "numeric" },
  {   1, "printable" },
  { 0, NULL }
};

static const ber_choice_t PrivateDomainName_choice[] = {
  {   0, &hf_p1_numeric_private_domain_name, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_p1_T_numeric_private_domain_name },
  {   1, &hf_p1_printable_private_domain_name, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_p1_T_printable_private_domain_name },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_PrivateDomainName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 725 "../../asn1/p1/p1.cnf"

	if(doing_address)
		g_strlcat(oraddress, "/P=", MAX_ORA_STR_LEN);

	  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PrivateDomainName_choice, hf_index, ett_p1_PrivateDomainName,
                                 NULL);




  return offset;
}



static int
dissect_p1_OrganizationName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 742 "../../asn1/p1/p1.cnf"
	tvbuff_t	*string = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_organization_name_length, hf_index, &string);


	if(doing_address && string) {
		g_strlcat(oraddress, "/O=", MAX_ORA_STR_LEN);
		g_strlcat(oraddress, tvb_format_text(string, 0, tvb_length(string)), MAX_ORA_STR_LEN);
	}



  return offset;
}



static int
dissect_p1_NumericUserIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_numeric_user_id_length, hf_index, NULL);

  return offset;
}



static int
dissect_p1_T_printable_surname(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 945 "../../asn1/p1/p1.cnf"
	tvbuff_t	*pstring = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_surname_length, hf_index, &pstring);


	if(doing_address && pstring) {
	    g_strlcat(oraddress, "/S=", MAX_ORA_STR_LEN);
	  g_strlcat(oraddress, tvb_format_text(pstring, 0, tvb_length(pstring)), MAX_ORA_STR_LEN);
	}



  return offset;
}



static int
dissect_p1_T_printable_given_name(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 955 "../../asn1/p1/p1.cnf"
	tvbuff_t	*pstring = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_given_name_length, hf_index, &pstring);


	if(doing_address && pstring) {
	    g_strlcat(oraddress, "/G=", MAX_ORA_STR_LEN);
	  g_strlcat(oraddress, tvb_format_text(pstring, 0, tvb_length(pstring)), MAX_ORA_STR_LEN);
	}



  return offset;
}



static int
dissect_p1_T_printable_initials(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 965 "../../asn1/p1/p1.cnf"
	tvbuff_t	*pstring = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_initials_length, hf_index, &pstring);


	if(doing_address && pstring) {
	    g_strlcat(oraddress, "/I=", MAX_ORA_STR_LEN);
	  g_strlcat(oraddress, tvb_format_text(pstring, 0, tvb_length(pstring)), MAX_ORA_STR_LEN);
	}



  return offset;
}



static int
dissect_p1_T_printable_generation_qualifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 975 "../../asn1/p1/p1.cnf"
	tvbuff_t	*pstring = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_generation_qualifier_length, hf_index, &pstring);


	if(doing_address && pstring) {
	    g_strlcat(oraddress, "/Q=", MAX_ORA_STR_LEN);
	  g_strlcat(oraddress, tvb_format_text(pstring, 0, tvb_length(pstring)), MAX_ORA_STR_LEN);
	}



  return offset;
}


static const ber_sequence_t PersonalName_set[] = {
  { &hf_p1_printable_surname, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_T_printable_surname },
  { &hf_p1_printable_given_name, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_T_printable_given_name },
  { &hf_p1_printable_initials, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_T_printable_initials },
  { &hf_p1_printable_generation_qualifier, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_T_printable_generation_qualifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_PersonalName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              PersonalName_set, hf_index, ett_p1_PersonalName);

  return offset;
}



static int
dissect_p1_OrganizationalUnitName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 768 "../../asn1/p1/p1.cnf"
	tvbuff_t	*string = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_organizational_unit_name_length, hf_index, &string);


	if(doing_address && string) {
		g_strlcat(oraddress, "/OU=", MAX_ORA_STR_LEN);
		g_strlcat(oraddress, tvb_format_text(string, 0, tvb_length(string)), MAX_ORA_STR_LEN);
	}



  return offset;
}


static const ber_sequence_t OrganizationalUnitNames_sequence_of[1] = {
  { &hf_p1_OrganizationalUnitNames_item, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_p1_OrganizationalUnitName },
};

static int
dissect_p1_OrganizationalUnitNames(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, ub_organizational_units, OrganizationalUnitNames_sequence_of, hf_index, ett_p1_OrganizationalUnitNames);

  return offset;
}


static const ber_sequence_t BuiltInStandardAttributes_sequence[] = {
  { &hf_p1_country_name     , BER_CLASS_APP, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_CountryName },
  { &hf_p1_administration_domain_name, BER_CLASS_APP, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_AdministrationDomainName },
  { &hf_p1_network_address  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_NetworkAddress },
  { &hf_p1_terminal_identifier, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_TerminalIdentifier },
  { &hf_p1_private_domain_name, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_PrivateDomainName },
  { &hf_p1_organization_name, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_OrganizationName },
  { &hf_p1_numeric_user_identifier, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_NumericUserIdentifier },
  { &hf_p1_personal_name    , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_PersonalName },
  { &hf_p1_organizational_unit_names, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_OrganizationalUnitNames },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_BuiltInStandardAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1142 "../../asn1/p1/p1.cnf"

	address_item = tree;	

	  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BuiltInStandardAttributes_sequence, hf_index, ett_p1_BuiltInStandardAttributes);




  return offset;
}



static int
dissect_p1_T_printable_type(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1025 "../../asn1/p1/p1.cnf"
	tvbuff_t	*pstring = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_domain_defined_attribute_type_length, hf_index, &pstring);


	if(doing_address && pstring) {
	    g_strlcat(oraddress, "/DD.", MAX_ORA_STR_LEN);
	    g_strlcat(oraddress, tvb_format_text(pstring, 0, tvb_length(pstring)), MAX_ORA_STR_LEN);
	    g_strlcat(ddatype, tvb_format_text(pstring, 0, tvb_length(pstring)), MAX_ORA_STR_LEN);
	}
	


  return offset;
}



static int
dissect_p1_T_printable_value(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1036 "../../asn1/p1/p1.cnf"
	tvbuff_t	*pstring = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_domain_defined_attribute_value_length, hf_index, &pstring);


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
  { &hf_p1_printable_type   , BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_p1_T_printable_type },
  { &hf_p1_printable_value  , BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_p1_T_printable_value },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_BuiltInDomainDefinedAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1049 "../../asn1/p1/p1.cnf"
        ddatype = ep_alloc(MAX_ORA_STR_LEN); ddatype[0] = '\0';

	  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BuiltInDomainDefinedAttribute_sequence, hf_index, ett_p1_BuiltInDomainDefinedAttribute);




  return offset;
}


static const ber_sequence_t BuiltInDomainDefinedAttributes_sequence_of[1] = {
  { &hf_p1_BuiltInDomainDefinedAttributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_p1_BuiltInDomainDefinedAttribute },
};

static int
dissect_p1_BuiltInDomainDefinedAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, ub_domain_defined_attributes, BuiltInDomainDefinedAttributes_sequence_of, hf_index, ett_p1_BuiltInDomainDefinedAttributes);

  return offset;
}


static const value_string p1_ExtensionAttributeType_vals[] = {
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
dissect_p1_ExtensionAttributeType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &extension_id);

  return offset;
}



static int
dissect_p1_T_extension_attribute_value(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 575 "../../asn1/p1/p1.cnf"

	proto_item_append_text(tree, " (%s)", val_to_str(extension_id, p1_ExtensionAttributeType_vals, "extension-attribute-type %d")); 
	if (dissector_try_uint(p1_extension_attribute_dissector_table, extension_id, tvb, actx->pinfo, tree)) {
		offset =tvb_length(tvb);
	} else {
		proto_item *item = NULL;
		proto_tree *next_tree = NULL;

		item = proto_tree_add_text(tree, tvb, 0, tvb_length_remaining(tvb, offset), 
			"Dissector for extension-attribute-type %d not implemented.  Contact Wireshark developers if you want this supported", extension_id);
		next_tree = proto_item_add_subtree(item, ett_p1_unknown_extension_attribute_type);
		offset = dissect_unknown_ber(actx->pinfo, tvb, offset, next_tree);
		expert_add_info_format(actx->pinfo, item, PI_UNDECODED, PI_WARN, "Unknown extension-attribute-type");
	}




  return offset;
}


static const ber_sequence_t ExtensionAttribute_sequence[] = {
  { &hf_p1_extension_attribute_type, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_ExtensionAttributeType },
  { &hf_p1_extension_attribute_value, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_p1_T_extension_attribute_value },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_ExtensionAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExtensionAttribute_sequence, hf_index, ett_p1_ExtensionAttribute);

  return offset;
}


static const ber_sequence_t ExtensionAttributes_set_of[1] = {
  { &hf_p1_ExtensionAttributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_p1_ExtensionAttribute },
};

static int
dissect_p1_ExtensionAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_set_of(implicit_tag, actx, tree, tvb, offset,
                                             1, ub_extension_attributes, ExtensionAttributes_set_of, hf_index, ett_p1_ExtensionAttributes);

  return offset;
}


static const ber_sequence_t ORName_U_sequence[] = {
  { &hf_p1_built_in_standard_attributes, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_p1_BuiltInStandardAttributes },
  { &hf_p1_built_in_domain_defined_attributes, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_BuiltInDomainDefinedAttributes },
  { &hf_p1_extension_attributes, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_ExtensionAttributes },
  { &hf_p1_directory_name   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509if_Name },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_ORName_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ORName_U_sequence, hf_index, ett_p1_ORName_U);

  return offset;
}



int
dissect_p1_ORName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1067 "../../asn1/p1/p1.cnf"
	
	oraddress = ep_alloc(MAX_ORA_STR_LEN); oraddress[0] = '\0';	
	address_item = NULL;
	doing_address = TRUE;

	  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 0, TRUE, dissect_p1_ORName_U);


	if(*oraddress && address_item)
		proto_item_append_text(address_item, " (%s/)", oraddress);

	doing_address = FALSE;



  return offset;
}



static int
dissect_p1_ORAddressAndOptionalDirectoryName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_ORName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_MTAOriginatorName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const asn_namedbit BuiltInEncodedInformationTypes_bits[] = {
  {  0, &hf_p1_BuiltInEncodedInformationTypes_unknown, -1, -1, "unknown", NULL },
  {  2, &hf_p1_BuiltInEncodedInformationTypes_ia5_text, -1, -1, "ia5-text", NULL },
  {  3, &hf_p1_BuiltInEncodedInformationTypes_g3_facsimile, -1, -1, "g3-facsimile", NULL },
  {  4, &hf_p1_BuiltInEncodedInformationTypes_g4_class_1, -1, -1, "g4-class-1", NULL },
  {  5, &hf_p1_BuiltInEncodedInformationTypes_teletex, -1, -1, "teletex", NULL },
  {  6, &hf_p1_BuiltInEncodedInformationTypes_videotex, -1, -1, "videotex", NULL },
  {  7, &hf_p1_BuiltInEncodedInformationTypes_voice, -1, -1, "voice", NULL },
  {  8, &hf_p1_BuiltInEncodedInformationTypes_sfd, -1, -1, "sfd", NULL },
  {  9, &hf_p1_BuiltInEncodedInformationTypes_mixed_mode, -1, -1, "mixed-mode", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_p1_BuiltInEncodedInformationTypes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_bitstring(implicit_tag, actx, tree, tvb, offset,
                                                0, ub_built_in_encoded_information_types, BuiltInEncodedInformationTypes_bits, hf_index, ett_p1_BuiltInEncodedInformationTypes,
                                                NULL);

  return offset;
}


static const asn_namedbit G3FacsimileNonBasicParameters_bits[] = {
  {  8, &hf_p1_G3FacsimileNonBasicParameters_two_dimensional, -1, -1, "two-dimensional", NULL },
  {  9, &hf_p1_G3FacsimileNonBasicParameters_fine_resolution, -1, -1, "fine-resolution", NULL },
  { 20, &hf_p1_G3FacsimileNonBasicParameters_unlimited_length, -1, -1, "unlimited-length", NULL },
  { 21, &hf_p1_G3FacsimileNonBasicParameters_b4_length, -1, -1, "b4-length", NULL },
  { 22, &hf_p1_G3FacsimileNonBasicParameters_a3_width, -1, -1, "a3-width", NULL },
  { 23, &hf_p1_G3FacsimileNonBasicParameters_b4_width, -1, -1, "b4-width", NULL },
  { 25, &hf_p1_G3FacsimileNonBasicParameters_t6_coding, -1, -1, "t6-coding", NULL },
  { 30, &hf_p1_G3FacsimileNonBasicParameters_uncompressed, -1, -1, "uncompressed", NULL },
  { 37, &hf_p1_G3FacsimileNonBasicParameters_width_middle_864_of_1728, -1, -1, "width-middle-864-of-1728", NULL },
  { 38, &hf_p1_G3FacsimileNonBasicParameters_width_middle_1216_of_1728, -1, -1, "width-middle-1216-of-1728", NULL },
  { 44, &hf_p1_G3FacsimileNonBasicParameters_resolution_type, -1, -1, "resolution-type", NULL },
  { 45, &hf_p1_G3FacsimileNonBasicParameters_resolution_400x400, -1, -1, "resolution-400x400", NULL },
  { 46, &hf_p1_G3FacsimileNonBasicParameters_resolution_300x300, -1, -1, "resolution-300x300", NULL },
  { 47, &hf_p1_G3FacsimileNonBasicParameters_resolution_8x15, -1, -1, "resolution-8x15", NULL },
  { 49, &hf_p1_G3FacsimileNonBasicParameters_edi, -1, -1, "edi", NULL },
  { 50, &hf_p1_G3FacsimileNonBasicParameters_dtm, -1, -1, "dtm", NULL },
  { 51, &hf_p1_G3FacsimileNonBasicParameters_bft, -1, -1, "bft", NULL },
  { 58, &hf_p1_G3FacsimileNonBasicParameters_mixed_mode, -1, -1, "mixed-mode", NULL },
  { 60, &hf_p1_G3FacsimileNonBasicParameters_character_mode, -1, -1, "character-mode", NULL },
  { 65, &hf_p1_G3FacsimileNonBasicParameters_twelve_bits, -1, -1, "twelve-bits", NULL },
  { 66, &hf_p1_G3FacsimileNonBasicParameters_preferred_huffmann, -1, -1, "preferred-huffmann", NULL },
  { 67, &hf_p1_G3FacsimileNonBasicParameters_full_colour, -1, -1, "full-colour", NULL },
  { 68, &hf_p1_G3FacsimileNonBasicParameters_jpeg, -1, -1, "jpeg", NULL },
  { 71, &hf_p1_G3FacsimileNonBasicParameters_processable_mode_26, -1, -1, "processable-mode-26", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

int
dissect_p1_G3FacsimileNonBasicParameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    G3FacsimileNonBasicParameters_bits, hf_index, ett_p1_G3FacsimileNonBasicParameters,
                                    NULL);

  return offset;
}



static int
dissect_p1_TeletexString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_p1_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t TeletexNonBasicParameters_set[] = {
  { &hf_p1_graphic_character_sets, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_TeletexString },
  { &hf_p1_control_character_sets, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_TeletexString },
  { &hf_p1_page_formats     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_OCTET_STRING },
  { &hf_p1_miscellaneous_terminal_capabilities, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_TeletexString },
  { &hf_p1_private_use      , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_p1_TeletexNonBasicParameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              TeletexNonBasicParameters_set, hf_index, ett_p1_TeletexNonBasicParameters);

  return offset;
}



static int
dissect_p1_ExtendedEncodedInformationType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t ExtendedEncodedInformationTypes_set_of[1] = {
  { &hf_p1_ExtendedEncodedInformationTypes_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_p1_ExtendedEncodedInformationType },
};

static int
dissect_p1_ExtendedEncodedInformationTypes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_set_of(implicit_tag, actx, tree, tvb, offset,
                                             1, ub_encoded_information_types, ExtendedEncodedInformationTypes_set_of, hf_index, ett_p1_ExtendedEncodedInformationTypes);

  return offset;
}


static const ber_sequence_t EncodedInformationTypes_U_set[] = {
  { &hf_p1_built_in_encoded_information_types, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_BuiltInEncodedInformationTypes },
  { &hf_p1_g3_facsimile     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_G3FacsimileNonBasicParameters },
  { &hf_p1_teletex          , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_TeletexNonBasicParameters },
  { &hf_p1_extended_encoded_information_types, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_ExtendedEncodedInformationTypes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_EncodedInformationTypes_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              EncodedInformationTypes_U_set, hf_index, ett_p1_EncodedInformationTypes_U);

  return offset;
}



int
dissect_p1_EncodedInformationTypes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 5, TRUE, dissect_p1_EncodedInformationTypes_U);

  return offset;
}



int
dissect_p1_OriginalEncodedInformationTypes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_EncodedInformationTypes(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string p1_BuiltInContentType_U_vals[] = {
  {   0, "unidentified" },
  {   1, "external" },
  {   2, "interpersonal-messaging-1984" },
  {  22, "interpersonal-messaging-1988" },
  {  35, "edi-messaging" },
  {  40, "voice-messaging" },
  { 0, NULL }
};


static int
dissect_p1_BuiltInContentType_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 635 "../../asn1/p1/p1.cnf"
  static guint32	ict = -1;	

    offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, ub_built_in_content_type, hf_index, &ict);


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
dissect_p1_BuiltInContentType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 6, TRUE, dissect_p1_BuiltInContentType_U);

  return offset;
}



int
dissect_p1_ExtendedContentType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 620 "../../asn1/p1/p1.cnf"
	const char *name = NULL;

	  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &content_type_id);


	if(content_type_id) {
	  name = oid_resolved_from_string(content_type_id);

  	  if(!name) name = content_type_id;

	  proto_item_append_text(tree, " (%s)", name);
	}



  return offset;
}


const value_string p1_ContentType_vals[] = {
  {   0, "built-in" },
  {   1, "extended" },
  { 0, NULL }
};

static const ber_choice_t ContentType_choice[] = {
  {   0, &hf_p1_built_in         , BER_CLASS_APP, 6, BER_FLAGS_NOOWNTAG, dissect_p1_BuiltInContentType },
  {   1, &hf_p1_extended         , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_p1_ExtendedContentType },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_p1_ContentType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ContentType_choice, hf_index, ett_p1_ContentType,
                                 NULL);

  return offset;
}



static int
dissect_p1_PrintableString_SIZE_1_ub_content_id_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_content_id_length, hf_index, NULL);

  return offset;
}



int
dissect_p1_ContentIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 10, TRUE, dissect_p1_PrintableString_SIZE_1_ub_content_id_length);

  return offset;
}


static const value_string p1_Priority_U_vals[] = {
  {   0, "normal" },
  {   1, "non-urgent" },
  {   2, "urgent" },
  { 0, NULL }
};


static int
dissect_p1_Priority_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_p1_Priority(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 7, TRUE, dissect_p1_Priority_U);

  return offset;
}


static const asn_namedbit PerMessageIndicators_U_bits[] = {
  {  0, &hf_p1_PerMessageIndicators_U_disclosure_of_other_recipients, -1, -1, "disclosure-of-other-recipients", NULL },
  {  1, &hf_p1_PerMessageIndicators_U_implicit_conversion_prohibited, -1, -1, "implicit-conversion-prohibited", NULL },
  {  2, &hf_p1_PerMessageIndicators_U_alternate_recipient_allowed, -1, -1, "alternate-recipient-allowed", NULL },
  {  3, &hf_p1_PerMessageIndicators_U_content_return_request, -1, -1, "content-return-request", NULL },
  {  4, &hf_p1_PerMessageIndicators_U_reserved, -1, -1, "reserved", NULL },
  {  5, &hf_p1_PerMessageIndicators_U_bit_5, -1, -1, "bit-5", NULL },
  {  6, &hf_p1_PerMessageIndicators_U_bit_6, -1, -1, "bit-6", NULL },
  {  7, &hf_p1_PerMessageIndicators_U_service_message, -1, -1, "service-message", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_p1_PerMessageIndicators_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_bitstring(implicit_tag, actx, tree, tvb, offset,
                                                0, ub_bit_options, PerMessageIndicators_U_bits, hf_index, ett_p1_PerMessageIndicators_U,
                                                NULL);

  return offset;
}



int
dissect_p1_PerMessageIndicators(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 8, TRUE, dissect_p1_PerMessageIndicators_U);

  return offset;
}



static int
dissect_p1_Time(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1185 "../../asn1/p1/p1.cnf"
	tvbuff_t *arrival = NULL;

	  offset = dissect_ber_UTCTime(implicit_tag, actx, tree, tvb, offset, hf_index);


	if(arrival && doing_address)
		proto_item_append_text(address_item, " %s", tvb_format_text(arrival, 0, tvb_length(arrival)));



  return offset;
}



static int
dissect_p1_DeferredDeliveryTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_Time(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t T_private_domain_sequence[] = {
  { &hf_p1_administration_domain_name, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_AdministrationDomainName },
  { &hf_p1_private_domain_identifier, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_PrivateDomainIdentifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_T_private_domain(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_private_domain_sequence, hf_index, ett_p1_T_private_domain);

  return offset;
}


static const value_string p1_T_bilateral_domain_vals[] = {
  {   0, "administration-domain-name" },
  {   1, "private-domain" },
  { 0, NULL }
};

static const ber_choice_t T_bilateral_domain_choice[] = {
  {   0, &hf_p1_administration_domain_name, BER_CLASS_APP, 2, BER_FLAGS_NOOWNTAG, dissect_p1_AdministrationDomainName },
  {   1, &hf_p1_private_domain   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_p1_T_private_domain },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_T_bilateral_domain(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_bilateral_domain_choice, hf_index, ett_p1_T_bilateral_domain,
                                 NULL);

  return offset;
}



static int
dissect_p1_T_bilateral_information(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1253 "../../asn1/p1/p1.cnf"
	proto_item *item = NULL;
	int 	    loffset = 0;
	guint32	    len = 0;

	/* work out the length */
	loffset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, NULL, NULL, NULL);
	(void) dissect_ber_length(actx->pinfo, tree, tvb, loffset, &len, NULL);

	/* create some structure so we can tell what this unknown ASN.1 represents */	
	item = proto_tree_add_item(tree, hf_index, tvb, offset, len, FALSE);
	tree = proto_item_add_subtree(item, ett_p1_bilateral_information);

	offset = dissect_unknown_ber(actx->pinfo, tvb, offset, tree);



  return offset;
}


static const ber_sequence_t PerDomainBilateralInformation_sequence[] = {
  { &hf_p1_country_name     , BER_CLASS_APP, 1, BER_FLAGS_NOOWNTAG, dissect_p1_CountryName },
  { &hf_p1_bilateral_domain , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_T_bilateral_domain },
  { &hf_p1_bilateral_information, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_p1_T_bilateral_information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_PerDomainBilateralInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PerDomainBilateralInformation_sequence, hf_index, ett_p1_PerDomainBilateralInformation);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_ub_transfers_OF_PerDomainBilateralInformation_sequence_of[1] = {
  { &hf_p1_per_domain_bilateral_information_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_p1_PerDomainBilateralInformation },
};

static int
dissect_p1_SEQUENCE_SIZE_1_ub_transfers_OF_PerDomainBilateralInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, ub_transfers, SEQUENCE_SIZE_1_ub_transfers_OF_PerDomainBilateralInformation_sequence_of, hf_index, ett_p1_SEQUENCE_SIZE_1_ub_transfers_OF_PerDomainBilateralInformation);

  return offset;
}



static int
dissect_p1_ArrivalTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_Time(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string p1_RoutingAction_vals[] = {
  {   0, "relayed" },
  {   1, "rerouted" },
  { 0, NULL }
};


static int
dissect_p1_RoutingAction(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1196 "../../asn1/p1/p1.cnf"
	int action = 0;

	  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  &action);


	proto_item_append_text(address_item, " %s", val_to_str(action, p1_RoutingAction_vals, "action(%d)"));



  return offset;
}



static int
dissect_p1_DeferredTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_Time(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_ConvertedEncodedInformationTypes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_EncodedInformationTypes(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const asn_namedbit OtherActions_bits[] = {
  {  0, &hf_p1_OtherActions_redirected, -1, -1, "redirected", NULL },
  {  1, &hf_p1_OtherActions_dl_operation, -1, -1, "dl-operation", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_p1_OtherActions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_bitstring(implicit_tag, actx, tree, tvb, offset,
                                                0, ub_bit_options, OtherActions_bits, hf_index, ett_p1_OtherActions,
                                                NULL);

  return offset;
}


static const ber_sequence_t DomainSuppliedInformation_set[] = {
  { &hf_p1_arrival_time     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_ArrivalTime },
  { &hf_p1_routing_action   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_p1_RoutingAction },
  { &hf_p1_attempted_domain , BER_CLASS_APP, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_GlobalDomainIdentifier },
  { &hf_p1_deferred_time    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_DeferredTime },
  { &hf_p1_converted_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_ConvertedEncodedInformationTypes },
  { &hf_p1_other_actions    , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_OtherActions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_DomainSuppliedInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1164 "../../asn1/p1/p1.cnf"

	doing_address = FALSE;

	  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              DomainSuppliedInformation_set, hf_index, ett_p1_DomainSuppliedInformation);


	doing_address = TRUE;
	proto_item_append_text(tree, ")");



  return offset;
}


static const ber_sequence_t TraceInformationElement_sequence[] = {
  { &hf_p1_global_domain_identifier, BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_p1_GlobalDomainIdentifier },
  { &hf_p1_domain_supplied_information, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p1_DomainSuppliedInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_TraceInformationElement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1148 "../../asn1/p1/p1.cnf"

	doing_address = TRUE;

	  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TraceInformationElement_sequence, hf_index, ett_p1_TraceInformationElement);


	doing_address = FALSE;



  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_ub_transfers_OF_TraceInformationElement_sequence_of[1] = {
  { &hf_p1__untag_item      , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_p1_TraceInformationElement },
};

static int
dissect_p1_SEQUENCE_SIZE_1_ub_transfers_OF_TraceInformationElement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, ub_transfers, SEQUENCE_SIZE_1_ub_transfers_OF_TraceInformationElement_sequence_of, hf_index, ett_p1_SEQUENCE_SIZE_1_ub_transfers_OF_TraceInformationElement);

  return offset;
}



static int
dissect_p1_TraceInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 9, TRUE, dissect_p1_SEQUENCE_SIZE_1_ub_transfers_OF_TraceInformationElement);

  return offset;
}


static const value_string p1_StandardExtension_vals[] = {
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
dissect_p1_StandardExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &extension_id);

  return offset;
}



static int
dissect_p1_T_private_extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 612 "../../asn1/p1/p1.cnf"

	  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &object_identifier_id);

	extension_id = -1;



  return offset;
}


static const value_string p1_ExtensionType_vals[] = {
  {   0, "standard-extension" },
  {   3, "private-extension" },
  { 0, NULL }
};

static const ber_choice_t ExtensionType_choice[] = {
  {   0, &hf_p1_standard_extension, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_StandardExtension },
  {   3, &hf_p1_private_extension, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_p1_T_private_extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_ExtensionType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ExtensionType_choice, hf_index, ett_p1_ExtensionType,
                                 NULL);

  return offset;
}


static const asn_namedbit Criticality_bits[] = {
  {  0, &hf_p1_Criticality_for_submission, -1, -1, "for-submission", NULL },
  {  1, &hf_p1_Criticality_for_transfer, -1, -1, "for-transfer", NULL },
  {  2, &hf_p1_Criticality_for_delivery, -1, -1, "for-delivery", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_p1_Criticality(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_bitstring(implicit_tag, actx, tree, tvb, offset,
                                                0, ub_bit_options, Criticality_bits, hf_index, ett_p1_Criticality,
                                                NULL);

  return offset;
}



static int
dissect_p1_ExtensionValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 534 "../../asn1/p1/p1.cnf"
	const char *name;

	if(extension_id != -1) {
		proto_item_append_text(tree, " (%s)", val_to_str(extension_id, p1_StandardExtension_vals, "standard-extension %d")); 
  		if (dissector_try_uint(p1_extension_dissector_table, extension_id, tvb, actx->pinfo, tree)) {
			offset = tvb_length(tvb);
		} else {
			proto_item *item = NULL;
			proto_tree *next_tree = NULL;

			item = proto_tree_add_text(tree, tvb, 0, tvb_length_remaining(tvb, offset), 
				"Dissector for standard-extension %d not implemented.  Contact Wireshark developers if you want this supported", extension_id);
			next_tree = proto_item_add_subtree(item, ett_p1_unknown_standard_extension);
			offset = dissect_unknown_ber(actx->pinfo, tvb, offset, next_tree);
			expert_add_info_format(actx->pinfo, item, PI_UNDECODED, PI_WARN, "Unknown standard-extension");
		}
	} else if (object_identifier_id) {
		offset = call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);
		name = oid_resolved_from_string(object_identifier_id);
		proto_item_append_text(tree, " (%s)", name ? name : object_identifier_id); 
	}
		



  return offset;
}


static const ber_sequence_t ExtensionField_sequence[] = {
  { &hf_p1_extension_type   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_ExtensionType },
  { &hf_p1_criticality      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_Criticality },
  { &hf_p1_extension_value  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_ExtensionValue },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_p1_ExtensionField(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExtensionField_sequence, hf_index, ett_p1_ExtensionField);

  return offset;
}


static const ber_sequence_t SET_OF_ExtensionField_set_of[1] = {
  { &hf_p1_extensions_item  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_p1_ExtensionField },
};

static int
dissect_p1_SET_OF_ExtensionField(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_ExtensionField_set_of, hf_index, ett_p1_SET_OF_ExtensionField);

  return offset;
}



static int
dissect_p1_MTARecipientName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_OriginallySpecifiedRecipientNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            1U, ub_recipients, hf_index, NULL);

  return offset;
}


static const asn_namedbit PerRecipientIndicators_bits[] = {
  {  0, &hf_p1_PerRecipientIndicators_responsibility, -1, -1, "responsibility", NULL },
  {  1, &hf_p1_PerRecipientIndicators_originating_MTA_report, -1, -1, "originating-MTA-report", NULL },
  {  2, &hf_p1_PerRecipientIndicators_originating_MTA_non_delivery_report, -1, -1, "originating-MTA-non-delivery-report", NULL },
  {  3, &hf_p1_PerRecipientIndicators_originator_report, -1, -1, "originator-report", NULL },
  {  4, &hf_p1_PerRecipientIndicators_originator_non_delivery_report, -1, -1, "originator-non-delivery-report", NULL },
  {  5, &hf_p1_PerRecipientIndicators_reserved_5, -1, -1, "reserved-5", NULL },
  {  6, &hf_p1_PerRecipientIndicators_reserved_6, -1, -1, "reserved-6", NULL },
  {  7, &hf_p1_PerRecipientIndicators_reserved_7, -1, -1, "reserved-7", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_p1_PerRecipientIndicators(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_bitstring(implicit_tag, actx, tree, tvb, offset,
                                                8, ub_bit_options, PerRecipientIndicators_bits, hf_index, ett_p1_PerRecipientIndicators,
                                                NULL);

  return offset;
}


static const value_string p1_ExplicitConversion_vals[] = {
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
dissect_p1_ExplicitConversion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, ub_integer_options, hf_index, NULL);

  return offset;
}


static const ber_sequence_t PerRecipientMessageTransferFields_set[] = {
  { &hf_p1_recipient_name   , BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_p1_MTARecipientName },
  { &hf_p1_originally_specified_recipient_number, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_OriginallySpecifiedRecipientNumber },
  { &hf_p1_per_recipient_indicators, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_p1_PerRecipientIndicators },
  { &hf_p1_explicit_conversion, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_ExplicitConversion },
  { &hf_p1_extensions       , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_PerRecipientMessageTransferFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              PerRecipientMessageTransferFields_set, hf_index, ett_p1_PerRecipientMessageTransferFields);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageTransferFields_sequence_of[1] = {
  { &hf_p1_per_recipient_message_fields_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p1_PerRecipientMessageTransferFields },
};

static int
dissect_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageTransferFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, ub_recipients, SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageTransferFields_sequence_of, hf_index, ett_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageTransferFields);

  return offset;
}


static const ber_sequence_t MessageTransferEnvelope_set[] = {
  { &hf_p1_message_identifier, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_p1_MessageIdentifier },
  { &hf_p1_mta_originator_name, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_p1_MTAOriginatorName },
  { &hf_p1_original_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_OriginalEncodedInformationTypes },
  { &hf_p1_content_type     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_ContentType },
  { &hf_p1_content_identifier, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_ContentIdentifier },
  { &hf_p1_priority         , BER_CLASS_APP, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_Priority },
  { &hf_p1_per_message_indicators, BER_CLASS_APP, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_PerMessageIndicators },
  { &hf_p1_deferred_delivery_time, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_DeferredDeliveryTime },
  { &hf_p1_per_domain_bilateral_information, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SEQUENCE_SIZE_1_ub_transfers_OF_PerDomainBilateralInformation },
  { &hf_p1_trace_information, BER_CLASS_APP, 9, BER_FLAGS_NOOWNTAG, dissect_p1_TraceInformation },
  { &hf_p1_extensions       , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_OF_ExtensionField },
  { &hf_p1_per_recipient_message_fields, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageTransferFields },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_MessageTransferEnvelope(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              MessageTransferEnvelope_set, hf_index, ett_p1_MessageTransferEnvelope);

  return offset;
}



int
dissect_p1_Content(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 653 "../../asn1/p1/p1.cnf"
  tvbuff_t *next_tvb;

  /* we can do this now constructed octet strings are supported */
  offset = dissect_ber_octet_string(FALSE, actx, tree, tvb, offset, hf_index, &next_tvb);
  proto_item_set_text(actx->created_item, "content (%u bytes)", tvb_length (next_tvb));

  if (next_tvb) {
    if (content_type_id) {
      (void) call_ber_oid_callback(content_type_id, next_tvb, 0, actx->pinfo, top_tree ? top_tree : tree);
    } else if (report_unknown_content_type) {
      proto_item *item = NULL;
      proto_tree *next_tree = NULL;

      item = proto_tree_add_text(top_tree ? top_tree : tree, next_tvb, 0, tvb_length_remaining(tvb, offset), "P1 Unknown Content (unknown built-in content-type)");
      expert_add_info_format(actx->pinfo, item, PI_UNDECODED, PI_WARN, "Unknown built-in content-type");
      if (item) {
        next_tree=proto_item_add_subtree(item, ett_p1_content_unknown);
      }
      dissect_unknown_ber(actx->pinfo, next_tvb, 0, next_tree);
    } else {
      proto_item_append_text (actx->created_item, " (unknown content-type)");
    }
  }



  return offset;
}


static const ber_sequence_t Message_sequence[] = {
  { &hf_p1_message_envelope , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p1_MessageTransferEnvelope },
  { &hf_p1_content          , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_p1_Content },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_Message(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Message_sequence, hf_index, ett_p1_Message);

  return offset;
}



static int
dissect_p1_ProbeIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_MTSIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_p1_ContentLength(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, ub_content_length, hf_index, NULL);

  return offset;
}


static const ber_sequence_t PerRecipientProbeTransferFields_set[] = {
  { &hf_p1_recipient_name   , BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_p1_MTARecipientName },
  { &hf_p1_originally_specified_recipient_number, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_OriginallySpecifiedRecipientNumber },
  { &hf_p1_per_recipient_indicators, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_p1_PerRecipientIndicators },
  { &hf_p1_explicit_conversion, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_ExplicitConversion },
  { &hf_p1_extensions       , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_PerRecipientProbeTransferFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              PerRecipientProbeTransferFields_set, hf_index, ett_p1_PerRecipientProbeTransferFields);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeTransferFields_sequence_of[1] = {
  { &hf_p1_per_recipient_probe_transfer_fields_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p1_PerRecipientProbeTransferFields },
};

static int
dissect_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeTransferFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, ub_recipients, SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeTransferFields_sequence_of, hf_index, ett_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeTransferFields);

  return offset;
}


static const ber_sequence_t ProbeTransferEnvelope_set[] = {
  { &hf_p1_probe_identifier , BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_p1_ProbeIdentifier },
  { &hf_p1_mta_originator_name, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_p1_MTAOriginatorName },
  { &hf_p1_original_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_OriginalEncodedInformationTypes },
  { &hf_p1_content_type     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_ContentType },
  { &hf_p1_content_identifier, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_ContentIdentifier },
  { &hf_p1_content_length   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_ContentLength },
  { &hf_p1_per_message_indicators, BER_CLASS_APP, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_PerMessageIndicators },
  { &hf_p1_per_domain_bilateral_information, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SEQUENCE_SIZE_1_ub_transfers_OF_PerDomainBilateralInformation },
  { &hf_p1_trace_information, BER_CLASS_APP, 9, BER_FLAGS_NOOWNTAG, dissect_p1_TraceInformation },
  { &hf_p1_extensions       , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_OF_ExtensionField },
  { &hf_p1_per_recipient_probe_transfer_fields, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeTransferFields },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_ProbeTransferEnvelope(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ProbeTransferEnvelope_set, hf_index, ett_p1_ProbeTransferEnvelope);

  return offset;
}



static int
dissect_p1_Probe(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_ProbeTransferEnvelope(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_ReportIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_MTSIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_ReportDestinationName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t ReportTransferEnvelope_set[] = {
  { &hf_p1_report_identifier, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_p1_ReportIdentifier },
  { &hf_p1_report_destination_name, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_p1_ReportDestinationName },
  { &hf_p1_trace_information, BER_CLASS_APP, 9, BER_FLAGS_NOOWNTAG, dissect_p1_TraceInformation },
  { &hf_p1_extensions       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_ReportTransferEnvelope(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ReportTransferEnvelope_set, hf_index, ett_p1_ReportTransferEnvelope);

  return offset;
}



static int
dissect_p1_MessageOrProbeIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_MTSIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_SubjectIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_MessageOrProbeIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_SubjectIntermediateTraceInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_TraceInformation(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_AdditionalInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 516 "../../asn1/p1/p1.cnf"
   proto_item *item = NULL;
   int         loffset = 0;
   guint32     len = 0;

   /* work out the length */
   loffset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, NULL, NULL, NULL);
   (void) dissect_ber_length(actx->pinfo, tree, tvb, loffset, &len, NULL);

   item = proto_tree_add_item(tree, hf_index, tvb, offset, len, FALSE);
   tree = proto_item_add_subtree(item, ett_p1_additional_information);
   proto_item_append_text(tree, " (The use of this field is \"strongly deprecated\".)"); 

   offset = dissect_unknown_ber(actx->pinfo, tvb, offset, tree);



  return offset;
}



static int
dissect_p1_MTAActualRecipientName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_p1_MessageDeliveryTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_Time(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string p1_TypeOfMTSUser_vals[] = {
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
dissect_p1_TypeOfMTSUser(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, ub_mts_user_types, hf_index, NULL);

  return offset;
}


static const ber_sequence_t DeliveryReport_set[] = {
  { &hf_p1_message_delivery_time, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_MessageDeliveryTime },
  { &hf_p1_type_of_MTS_user , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_TypeOfMTSUser },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_DeliveryReport(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              DeliveryReport_set, hf_index, ett_p1_DeliveryReport);

  return offset;
}


const value_string p1_NonDeliveryReasonCode_vals[] = {
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
dissect_p1_NonDeliveryReasonCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, ub_reason_codes, hf_index, NULL);

  return offset;
}


const value_string p1_NonDeliveryDiagnosticCode_vals[] = {
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
dissect_p1_NonDeliveryDiagnosticCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, ub_diagnostic_codes, hf_index, NULL);

  return offset;
}


static const ber_sequence_t NonDeliveryReport_set[] = {
  { &hf_p1_non_delivery_reason_code, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_NonDeliveryReasonCode },
  { &hf_p1_non_delivery_diagnostic_code, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_NonDeliveryDiagnosticCode },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_NonDeliveryReport(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              NonDeliveryReport_set, hf_index, ett_p1_NonDeliveryReport);

  return offset;
}


static const value_string p1_ReportType_vals[] = {
  {   0, "delivery" },
  {   1, "non-delivery" },
  { 0, NULL }
};

static const ber_choice_t ReportType_choice[] = {
  {   0, &hf_p1_delivery         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_DeliveryReport },
  {   1, &hf_p1_non_delivery     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_p1_NonDeliveryReport },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_ReportType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1285 "../../asn1/p1/p1.cnf"
	gint report = -1;

  	  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ReportType_choice, hf_index, ett_p1_ReportType,
                                 &report);

	
        if( (report!=-1) && p1_ReportType_vals[report].strptr ){
		if(check_col(actx->pinfo->cinfo, COL_INFO)) {
			col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", p1_ReportType_vals[report].strptr);
		}
	}



  return offset;
}


static const ber_sequence_t LastTraceInformation_set[] = {
  { &hf_p1_arrival_time     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_ArrivalTime },
  { &hf_p1_converted_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_ConvertedEncodedInformationTypes },
  { &hf_p1_trace_report_type, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_ReportType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_LastTraceInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              LastTraceInformation_set, hf_index, ett_p1_LastTraceInformation);

  return offset;
}



static int
dissect_p1_OriginallyIntendedRecipientName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_p1_SupplementaryInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_supplementary_info_length, hf_index, NULL);

  return offset;
}


static const ber_sequence_t PerRecipientReportTransferFields_set[] = {
  { &hf_p1_mta_actual_recipient_name, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_MTAActualRecipientName },
  { &hf_p1_originally_specified_recipient_number, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_p1_OriginallySpecifiedRecipientNumber },
  { &hf_p1_per_recipient_indicators, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_p1_PerRecipientIndicators },
  { &hf_p1_last_trace_information, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_p1_LastTraceInformation },
  { &hf_p1_report_originally_intended_recipient_name, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_OriginallyIntendedRecipientName },
  { &hf_p1_supplementary_information, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SupplementaryInformation },
  { &hf_p1_extensions       , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_PerRecipientReportTransferFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              PerRecipientReportTransferFields_set, hf_index, ett_p1_PerRecipientReportTransferFields);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportTransferFields_sequence_of[1] = {
  { &hf_p1_per_recipient_report_fields_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p1_PerRecipientReportTransferFields },
};

static int
dissect_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportTransferFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, ub_recipients, SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportTransferFields_sequence_of, hf_index, ett_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportTransferFields);

  return offset;
}


static const ber_sequence_t ReportTransferContent_set[] = {
  { &hf_p1_subject_identifier, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_p1_SubjectIdentifier },
  { &hf_p1_subject_intermediate_trace_information, BER_CLASS_APP, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_SubjectIntermediateTraceInformation },
  { &hf_p1_original_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_OriginalEncodedInformationTypes },
  { &hf_p1_content_type     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_ContentType },
  { &hf_p1_content_identifier, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_ContentIdentifier },
  { &hf_p1_returned_content , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_Content },
  { &hf_p1_additional_information, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_AdditionalInformation },
  { &hf_p1_extensions       , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_OF_ExtensionField },
  { &hf_p1_per_recipient_report_fields, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportTransferFields },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_ReportTransferContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ReportTransferContent_set, hf_index, ett_p1_ReportTransferContent);

  return offset;
}


static const ber_sequence_t Report_sequence[] = {
  { &hf_p1_report_envelope  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p1_ReportTransferEnvelope },
  { &hf_p1_report_content   , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p1_ReportTransferContent },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_Report(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Report_sequence, hf_index, ett_p1_Report);

  return offset;
}


static const value_string p1_MTS_APDU_vals[] = {
  {   0, "message" },
  {   2, "probe" },
  {   1, "report" },
  { 0, NULL }
};

static const ber_choice_t MTS_APDU_choice[] = {
  {   0, &hf_p1_message          , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_Message },
  {   2, &hf_p1_probe            , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_p1_Probe },
  {   1, &hf_p1_report           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_p1_Report },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_MTS_APDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1271 "../../asn1/p1/p1.cnf"
	gint apdu = -1;

  	  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 MTS_APDU_choice, hf_index, ett_p1_MTS_APDU,
                                 &apdu);

	
	if( (apdu!=-1) && p1_MTS_APDU_vals[apdu].strptr ){
		if(check_col(actx->pinfo->cinfo, COL_INFO) && (apdu != 0)) { /* we don't show "message" - sub-dissectors have better idea */
			col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", p1_MTS_APDU_vals[apdu].strptr);
		}
	}



  return offset;
}





static const value_string p1_T_attempted_vals[] = {
  {   0, "mta" },
  {   1, "domain" },
  { 0, NULL }
};

static const ber_choice_t T_attempted_choice[] = {
  {   0, &hf_p1_mta              , BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_p1_MTAName },
  {   1, &hf_p1_domain           , BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_p1_GlobalDomainIdentifier },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_T_attempted(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_attempted_choice, hf_index, ett_p1_T_attempted,
                                 NULL);

  return offset;
}


static const ber_sequence_t MTASuppliedInformation_set[] = {
  { &hf_p1_arrival_time     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_ArrivalTime },
  { &hf_p1_routing_action   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_p1_RoutingAction },
  { &hf_p1_attempted        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_T_attempted },
  { &hf_p1_deferred_time    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_DeferredTime },
  { &hf_p1_converted_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_ConvertedEncodedInformationTypes },
  { &hf_p1_other_actions    , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_OtherActions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_MTASuppliedInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1173 "../../asn1/p1/p1.cnf"

	doing_address = FALSE;

	  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              MTASuppliedInformation_set, hf_index, ett_p1_MTASuppliedInformation);


	doing_address = TRUE;
	proto_item_append_text(tree, ")");



  return offset;
}


static const ber_sequence_t InternalTraceInformationElement_sequence[] = {
  { &hf_p1_global_domain_identifier, BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_p1_GlobalDomainIdentifier },
  { &hf_p1_mta_name         , BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_p1_MTAName },
  { &hf_p1_mta_supplied_information, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p1_MTASuppliedInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_InternalTraceInformationElement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1156 "../../asn1/p1/p1.cnf"

	doing_address = TRUE;

	  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InternalTraceInformationElement_sequence, hf_index, ett_p1_InternalTraceInformationElement);


	doing_address = FALSE;



  return offset;
}


static const ber_sequence_t InternalTraceInformation_sequence_of[1] = {
  { &hf_p1_InternalTraceInformation_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_p1_InternalTraceInformationElement },
};

static int
dissect_p1_InternalTraceInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, ub_transfers, InternalTraceInformation_sequence_of, hf_index, ett_p1_InternalTraceInformation);

  return offset;
}




static const value_string p1_ObjectName_vals[] = {
  {   0, "user-agent" },
  {   1, "mTA" },
  {   2, "message-store" },
  { 0, NULL }
};

static const ber_choice_t ObjectName_choice[] = {
  {   0, &hf_p1_user_agent       , BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_p1_ORAddressAndOptionalDirectoryName },
  {   1, &hf_p1_mTA              , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_MTAName },
  {   2, &hf_p1_message_store    , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_p1_ORAddressAndOptionalDirectoryName },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_ObjectName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ObjectName_choice, hf_index, ett_p1_ObjectName,
                                 NULL);

  return offset;
}



static int
dissect_p1_INTEGER_0_ub_queue_size(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, ub_queue_size, hf_index, NULL);

  return offset;
}



static int
dissect_p1_INTEGER_0_ub_content_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, ub_content_length, hf_index, NULL);

  return offset;
}


static const ber_sequence_t DeliveryQueue_set[] = {
  { &hf_p1_messages         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_INTEGER_0_ub_queue_size },
  { &hf_p1_delivery_queue_octets, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_INTEGER_0_ub_content_length },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_DeliveryQueue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              DeliveryQueue_set, hf_index, ett_p1_DeliveryQueue);

  return offset;
}


static const ber_sequence_t MessagesWaiting_set[] = {
  { &hf_p1_urgent           , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_DeliveryQueue },
  { &hf_p1_normal           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_p1_DeliveryQueue },
  { &hf_p1_non_urgent       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_p1_DeliveryQueue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_MessagesWaiting(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              MessagesWaiting_set, hf_index, ett_p1_MessagesWaiting);

  return offset;
}


static const ber_sequence_t MTSBindArgument_set[] = {
  { &hf_p1_initiator_name   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_ObjectName },
  { &hf_p1_messages_waiting , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_p1_MessagesWaiting },
  { &hf_p1_initiator_credentials, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_InitiatorCredentials },
  { &hf_p1_security_context , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SecurityContext },
  { &hf_p1_extensions       , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_MTSBindArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              MTSBindArgument_set, hf_index, ett_p1_MTSBindArgument);

  return offset;
}


static const ber_sequence_t MTSBindResult_set[] = {
  { &hf_p1_responder_name   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_ObjectName },
  { &hf_p1_messages_waiting , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_p1_MessagesWaiting },
  { &hf_p1_responder_credentials, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_ResponderCredentials },
  { &hf_p1_extensions       , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_MTSBindResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              MTSBindResult_set, hf_index, ett_p1_MTSBindResult);

  return offset;
}


static const value_string p1_PAR_mts_bind_error_vals[] = {
  {   0, "busy" },
  {   2, "authentication-error" },
  {   3, "unacceptable-dialogue-mode" },
  {   4, "unacceptable-security-context" },
  {   5, "inadequate-association-confidentiality" },
  { 0, NULL }
};


static int
dissect_p1_PAR_mts_bind_error(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, ub_integer_options, hf_index, NULL);

  return offset;
}



int
dissect_p1_ORAddressAndOrDirectoryName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_ORName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_p1_OriginatorName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_ORAddressAndOrDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_RecipientName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_ORAddressAndOrDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const asn_namedbit OriginatorReportRequest_bits[] = {
  {  3, &hf_p1_OriginatorReportRequest_report, -1, -1, "report", NULL },
  {  4, &hf_p1_OriginatorReportRequest_non_delivery_report, -1, -1, "non-delivery-report", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_p1_OriginatorReportRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_bitstring(implicit_tag, actx, tree, tvb, offset,
                                                0, ub_bit_options, OriginatorReportRequest_bits, hf_index, ett_p1_OriginatorReportRequest,
                                                NULL);

  return offset;
}


static const ber_sequence_t PerRecipientMessageSubmissionFields_set[] = {
  { &hf_p1_submission_recipient_name, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_p1_RecipientName },
  { &hf_p1_originator_report_request, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_OriginatorReportRequest },
  { &hf_p1_explicit_conversion, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_ExplicitConversion },
  { &hf_p1_extensions       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_PerRecipientMessageSubmissionFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              PerRecipientMessageSubmissionFields_set, hf_index, ett_p1_PerRecipientMessageSubmissionFields);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageSubmissionFields_sequence_of[1] = {
  { &hf_p1_per_recipient_message_submission_fields_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p1_PerRecipientMessageSubmissionFields },
};

static int
dissect_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageSubmissionFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, ub_recipients, SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageSubmissionFields_sequence_of, hf_index, ett_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageSubmissionFields);

  return offset;
}


static const ber_sequence_t MessageSubmissionEnvelope_set[] = {
  { &hf_p1_mts_originator_name, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_p1_OriginatorName },
  { &hf_p1_original_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_OriginalEncodedInformationTypes },
  { &hf_p1_content_type     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_ContentType },
  { &hf_p1_content_identifier, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_ContentIdentifier },
  { &hf_p1_priority         , BER_CLASS_APP, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_Priority },
  { &hf_p1_per_message_indicators, BER_CLASS_APP, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_PerMessageIndicators },
  { &hf_p1_deferred_delivery_time, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_DeferredDeliveryTime },
  { &hf_p1_extensions       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_OF_ExtensionField },
  { &hf_p1_per_recipient_message_submission_fields, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageSubmissionFields },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_p1_MessageSubmissionEnvelope(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              MessageSubmissionEnvelope_set, hf_index, ett_p1_MessageSubmissionEnvelope);

  return offset;
}


static const ber_sequence_t MessageSubmissionArgument_sequence[] = {
  { &hf_p1_message_submission_envelope, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p1_MessageSubmissionEnvelope },
  { &hf_p1_content          , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_p1_Content },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_MessageSubmissionArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1296 "../../asn1/p1/p1.cnf"
	p1_initialize_content_globals(tree, TRUE);
  	  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MessageSubmissionArgument_sequence, hf_index, ett_p1_MessageSubmissionArgument);

	p1_initialize_content_globals(NULL, FALSE);



  return offset;
}



int
dissect_p1_MessageSubmissionIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_MTSIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_p1_MessageSubmissionTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_Time(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t MessageSubmissionResult_set[] = {
  { &hf_p1_message_submission_identifier, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_p1_MessageSubmissionIdentifier },
  { &hf_p1_message_submission_time, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_MessageSubmissionTime },
  { &hf_p1_content_identifier, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_ContentIdentifier },
  { &hf_p1_extensions       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_MessageSubmissionResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              MessageSubmissionResult_set, hf_index, ett_p1_MessageSubmissionResult);

  return offset;
}


static const ber_sequence_t PerRecipientProbeSubmissionFields_set[] = {
  { &hf_p1_probe_recipient_name, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_p1_RecipientName },
  { &hf_p1_originator_report_request, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_OriginatorReportRequest },
  { &hf_p1_explicit_conversion, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_ExplicitConversion },
  { &hf_p1_extensions       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_p1_PerRecipientProbeSubmissionFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              PerRecipientProbeSubmissionFields_set, hf_index, ett_p1_PerRecipientProbeSubmissionFields);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeSubmissionFields_sequence_of[1] = {
  { &hf_p1_per_recipient_probe_submission_fields_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p1_PerRecipientProbeSubmissionFields },
};

static int
dissect_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeSubmissionFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, ub_recipients, SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeSubmissionFields_sequence_of, hf_index, ett_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeSubmissionFields);

  return offset;
}


static const ber_sequence_t ProbeSubmissionEnvelope_set[] = {
  { &hf_p1_mts_originator_name, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_p1_OriginatorName },
  { &hf_p1_original_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_OriginalEncodedInformationTypes },
  { &hf_p1_content_type     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_ContentType },
  { &hf_p1_content_identifier, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_ContentIdentifier },
  { &hf_p1_content_length   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_ContentLength },
  { &hf_p1_per_message_indicators, BER_CLASS_APP, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_PerMessageIndicators },
  { &hf_p1_extensions       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_OF_ExtensionField },
  { &hf_p1_per_recipient_probe_submission_fields, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeSubmissionFields },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_p1_ProbeSubmissionEnvelope(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ProbeSubmissionEnvelope_set, hf_index, ett_p1_ProbeSubmissionEnvelope);

  return offset;
}



static int
dissect_p1_ProbeSubmissionArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_ProbeSubmissionEnvelope(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_p1_ProbeSubmissionIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_MTSIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_p1_ProbeSubmissionTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_Time(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t ProbeSubmissionResult_set[] = {
  { &hf_p1_probe_submission_identifier, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_p1_ProbeSubmissionIdentifier },
  { &hf_p1_probe_submission_time, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_ProbeSubmissionTime },
  { &hf_p1_content_identifier, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_ContentIdentifier },
  { &hf_p1_extensions       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_ProbeSubmissionResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ProbeSubmissionResult_set, hf_index, ett_p1_ProbeSubmissionResult);

  return offset;
}



static int
dissect_p1_CancelDeferredDeliveryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_MessageSubmissionIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_CancelDeferredDeliveryResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_p1_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const asn_namedbit Operations_bits[] = {
  {  0, &hf_p1_Operations_probe_submission_or_report_delivery, -1, -1, "probe-submission-or-report-delivery", NULL },
  {  1, &hf_p1_Operations_message_submission_or_message_delivery, -1, -1, "message-submission-or-message-delivery", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_p1_Operations(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_bitstring(implicit_tag, actx, tree, tvb, offset,
                                                0, ub_bit_options, Operations_bits, hf_index, ett_p1_Operations,
                                                NULL);

  return offset;
}


static const ber_sequence_t ContentTypes_set_of[1] = {
  { &hf_p1_ContentTypes_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_ContentType },
};

static int
dissect_p1_ContentTypes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_set_of(implicit_tag, actx, tree, tvb, offset,
                                             1, ub_content_types, ContentTypes_set_of, hf_index, ett_p1_ContentTypes);

  return offset;
}


static const ber_sequence_t EncodedInformationTypesConstraints_sequence[] = {
  { &hf_p1_unacceptable_eits, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_ExtendedEncodedInformationTypes },
  { &hf_p1_acceptable_eits  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_ExtendedEncodedInformationTypes },
  { &hf_p1_exclusively_acceptable_eits, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_ExtendedEncodedInformationTypes },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_p1_EncodedInformationTypesConstraints(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncodedInformationTypesConstraints_sequence, hf_index, ett_p1_EncodedInformationTypesConstraints);

  return offset;
}



static int
dissect_p1_PermissibleEncodedInformationTypes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_EncodedInformationTypesConstraints(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t Controls_set[] = {
  { &hf_p1_restrict         , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_BOOLEAN },
  { &hf_p1_permissible_operations, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_Operations },
  { &hf_p1_permissible_maximum_content_length, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_ContentLength },
  { &hf_p1_permissible_lowest_priority, BER_CLASS_APP, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_Priority },
  { &hf_p1_permissible_content_types, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_ContentTypes },
  { &hf_p1_permissible_encoded_information_types, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_PermissibleEncodedInformationTypes },
  { &hf_p1_permissible_security_context, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SecurityContext },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_Controls(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              Controls_set, hf_index, ett_p1_Controls);

  return offset;
}



static int
dissect_p1_SubmissionControls(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_Controls(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_SubmissionControlArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_SubmissionControls(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const asn_namedbit WaitingMessages_bits[] = {
  {  0, &hf_p1_WaitingMessages_long_content, -1, -1, "long-content", NULL },
  {  1, &hf_p1_WaitingMessages_low_priority, -1, -1, "low-priority", NULL },
  {  2, &hf_p1_WaitingMessages_other_security_labels, -1, -1, "other-security-labels", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_p1_WaitingMessages(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_bitstring(implicit_tag, actx, tree, tvb, offset,
                                                0, ub_bit_options, WaitingMessages_bits, hf_index, ett_p1_WaitingMessages,
                                                NULL);

  return offset;
}


static const ber_sequence_t SET_SIZE_0_ub_content_types_OF_ContentType_set_of[1] = {
  { &hf_p1_waiting_content_types_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_ContentType },
};

static int
dissect_p1_SET_SIZE_0_ub_content_types_OF_ContentType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_set_of(implicit_tag, actx, tree, tvb, offset,
                                             0, ub_content_types, SET_SIZE_0_ub_content_types_OF_ContentType_set_of, hf_index, ett_p1_SET_SIZE_0_ub_content_types_OF_ContentType);

  return offset;
}


static const ber_sequence_t Waiting_set[] = {
  { &hf_p1_waiting_operations, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_Operations },
  { &hf_p1_waiting_messages , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_WaitingMessages },
  { &hf_p1_waiting_content_types, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_SIZE_0_ub_content_types_OF_ContentType },
  { &hf_p1_waiting_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_EncodedInformationTypes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_Waiting(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              Waiting_set, hf_index, ett_p1_Waiting);

  return offset;
}



static int
dissect_p1_SubmissionControlResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_Waiting(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_PAR_submission_control_violated(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_p1_PAR_element_of_service_not_subscribed(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_p1_PAR_deferred_delivery_cancellation_rejected(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_p1_PAR_originator_invalid(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t ImproperlySpecifiedRecipients_sequence_of[1] = {
  { &hf_p1_ImproperlySpecifiedRecipients_item, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_p1_RecipientName },
};

int
dissect_p1_ImproperlySpecifiedRecipients(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, ub_recipients, ImproperlySpecifiedRecipients_sequence_of, hf_index, ett_p1_ImproperlySpecifiedRecipients);

  return offset;
}



static int
dissect_p1_PAR_message_submission_identifier_invalid(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_p1_PAR_inconsistent_request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


const value_string p1_SecurityProblem_vals[] = {
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
dissect_p1_SecurityProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, ub_security_problems, hf_index, NULL);

  return offset;
}



static int
dissect_p1_PAR_unsupported_critical_function(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_p1_PAR_remote_bind_error(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



int
dissect_p1_MessageDeliveryIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_MTSIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string p1_DeliveredContentType_vals[] = {
  {   0, "built-in" },
  {   1, "extended" },
  { 0, NULL }
};

static const ber_choice_t DeliveredContentType_choice[] = {
  {   0, &hf_p1_built_in         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_BuiltInContentType },
  {   1, &hf_p1_extended         , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_p1_ExtendedContentType },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_DeliveredContentType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DeliveredContentType_choice, hf_index, ett_p1_DeliveredContentType,
                                 NULL);

  return offset;
}



static int
dissect_p1_DeliveredOriginatorName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const asn_namedbit DeliveryFlags_bits[] = {
  {  1, &hf_p1_DeliveryFlags_implicit_conversion_prohibited, -1, -1, "implicit-conversion-prohibited", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_p1_DeliveryFlags(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_bitstring(implicit_tag, actx, tree, tvb, offset,
                                                0, ub_bit_options, DeliveryFlags_bits, hf_index, ett_p1_DeliveryFlags,
                                                NULL);

  return offset;
}



static int
dissect_p1_OtherRecipientName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t OtherRecipientNames_sequence_of[1] = {
  { &hf_p1_OtherRecipientNames_item, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_p1_OtherRecipientName },
};

static int
dissect_p1_OtherRecipientNames(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, ub_recipients, OtherRecipientNames_sequence_of, hf_index, ett_p1_OtherRecipientNames);

  return offset;
}



static int
dissect_p1_ThisRecipientName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t OtherMessageDeliveryFields_set[] = {
  { &hf_p1_delivered_content_type, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_DeliveredContentType },
  { &hf_p1_delivered_originator_name, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_p1_DeliveredOriginatorName },
  { &hf_p1_original_encoded_information_types, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_OriginalEncodedInformationTypes },
  { &hf_p1_priority         , BER_CLASS_APP, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_Priority },
  { &hf_p1_delivery_flags   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_DeliveryFlags },
  { &hf_p1_other_recipient_names, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_OtherRecipientNames },
  { &hf_p1_this_recipient_name, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_p1_ThisRecipientName },
  { &hf_p1_originally_intended_recipient_name, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_OriginallyIntendedRecipientName },
  { &hf_p1_converted_encoded_information_types, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_ConvertedEncodedInformationTypes },
  { &hf_p1_message_submission_time, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_p1_MessageSubmissionTime },
  { &hf_p1_content_identifier, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_ContentIdentifier },
  { &hf_p1_extensions       , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_p1_OtherMessageDeliveryFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              OtherMessageDeliveryFields_set, hf_index, ett_p1_OtherMessageDeliveryFields);

  return offset;
}


static const ber_sequence_t MessageDeliveryArgument_sequence[] = {
  { &hf_p1_message_delivery_identifier, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_p1_MessageDeliveryIdentifier },
  { &hf_p1_message_delivery_time, BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_p1_MessageDeliveryTime },
  { &hf_p1_other_fields     , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p1_OtherMessageDeliveryFields },
  { &hf_p1_content          , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_p1_Content },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_MessageDeliveryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1301 "../../asn1/p1/p1.cnf"
	p1_initialize_content_globals(tree, TRUE);
  	  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MessageDeliveryArgument_sequence, hf_index, ett_p1_MessageDeliveryArgument);

	p1_initialize_content_globals(NULL, FALSE);



  return offset;
}



static int
dissect_p1_RecipientCertificate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_Certificates(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_ProofOfDelivery(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_Signature(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t MessageDeliveryResult_set[] = {
  { &hf_p1_recipient_certificate, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_RecipientCertificate },
  { &hf_p1_proof_of_delivery, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_ProofOfDelivery },
  { &hf_p1_extensions       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_MessageDeliveryResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              MessageDeliveryResult_set, hf_index, ett_p1_MessageDeliveryResult);

  return offset;
}



static int
dissect_p1_SubjectSubmissionIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_MTSIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_ActualRecipientName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_ORAddressAndOrDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t PerRecipientReportDeliveryFields_set[] = {
  { &hf_p1_actual_recipient_name, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_ActualRecipientName },
  { &hf_p1_delivery_report_type, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_ReportType },
  { &hf_p1_converted_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_ConvertedEncodedInformationTypes },
  { &hf_p1_originally_intended_recipient_name, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_OriginallyIntendedRecipientName },
  { &hf_p1_supplementary_information, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SupplementaryInformation },
  { &hf_p1_extensions       , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_PerRecipientReportDeliveryFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              PerRecipientReportDeliveryFields_set, hf_index, ett_p1_PerRecipientReportDeliveryFields);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportDeliveryFields_sequence_of[1] = {
  { &hf_p1_per_recipient_report_delivery_fields_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p1_PerRecipientReportDeliveryFields },
};

static int
dissect_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportDeliveryFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, ub_recipients, SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportDeliveryFields_sequence_of, hf_index, ett_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportDeliveryFields);

  return offset;
}


static const ber_sequence_t ReportDeliveryArgument_set[] = {
  { &hf_p1_subject_submission_identifier, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_p1_SubjectSubmissionIdentifier },
  { &hf_p1_content_identifier, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_ContentIdentifier },
  { &hf_p1_content_type     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_ContentType },
  { &hf_p1_original_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_OriginalEncodedInformationTypes },
  { &hf_p1_extensions       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_OF_ExtensionField },
  { &hf_p1_per_recipient_report_delivery_fields, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportDeliveryFields },
  { &hf_p1_returned_content , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_Content },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_ReportDeliveryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1306 "../../asn1/p1/p1.cnf"
	p1_initialize_content_globals(tree, TRUE);
  	  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ReportDeliveryArgument_set, hf_index, ett_p1_ReportDeliveryArgument);

	p1_initialize_content_globals(NULL, FALSE);



  return offset;
}


static const ber_sequence_t SET_SIZE_1_MAX_OF_ExtensionField_set_of[1] = {
  { &hf_p1_max_extensions_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_p1_ExtensionField },
};

static int
dissect_p1_SET_SIZE_1_MAX_OF_ExtensionField(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_set_of(implicit_tag, actx, tree, tvb, offset,
                                             1, NO_BOUND, SET_SIZE_1_MAX_OF_ExtensionField_set_of, hf_index, ett_p1_SET_SIZE_1_MAX_OF_ExtensionField);

  return offset;
}


static const value_string p1_ReportDeliveryResult_vals[] = {
  {   0, "empty-result" },
  {   1, "extensions" },
  { 0, NULL }
};

static const ber_choice_t ReportDeliveryResult_choice[] = {
  {   0, &hf_p1_empty_result     , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_p1_NULL },
  {   1, &hf_p1_max_extensions   , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p1_SET_SIZE_1_MAX_OF_ExtensionField },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_ReportDeliveryResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ReportDeliveryResult_choice, hf_index, ett_p1_ReportDeliveryResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t DeliveryControlArgument_set[] = {
  { &hf_p1_restrict         , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_BOOLEAN },
  { &hf_p1_permissible_operations, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_Operations },
  { &hf_p1_permissible_maximum_content_length, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_ContentLength },
  { &hf_p1_permissible_lowest_priority, BER_CLASS_APP, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_Priority },
  { &hf_p1_permissible_content_types, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_ContentTypes },
  { &hf_p1_permissible_encoded_information_types, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_PermissibleEncodedInformationTypes },
  { &hf_p1_permissible_security_context, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SecurityContext },
  { &hf_p1_extensions       , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_DeliveryControlArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              DeliveryControlArgument_set, hf_index, ett_p1_DeliveryControlArgument);

  return offset;
}


static const ber_sequence_t DeliveryControlResult_set[] = {
  { &hf_p1_waiting_operations, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_Operations },
  { &hf_p1_waiting_messages , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_WaitingMessages },
  { &hf_p1_waiting_content_types, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_SIZE_0_ub_content_types_OF_ContentType },
  { &hf_p1_waiting_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_EncodedInformationTypes },
  { &hf_p1_extensions       , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_DeliveryControlResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              DeliveryControlResult_set, hf_index, ett_p1_DeliveryControlResult);

  return offset;
}



static int
dissect_p1_PAR_delivery_control_violated(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_p1_PAR_control_violates_registration(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string p1_RefusedArgument_vals[] = {
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
dissect_p1_RefusedArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, ub_integer_options, hf_index, NULL);

  return offset;
}



static int
dissect_p1_T_refused_extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 592 "../../asn1/p1/p1.cnf"
/*XXX not implemented yet */



  return offset;
}


static const value_string p1_T_refused_argument_vals[] = {
  {   0, "built-in-argument" },
  {   1, "refused-extension" },
  { 0, NULL }
};

static const ber_choice_t T_refused_argument_choice[] = {
  {   0, &hf_p1_built_in_argument, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_p1_RefusedArgument },
  {   1, &hf_p1_refused_extension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_p1_T_refused_extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_T_refused_argument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_refused_argument_choice, hf_index, ett_p1_T_refused_argument,
                                 NULL);

  return offset;
}


static const value_string p1_RefusalReason_vals[] = {
  {   0, "facility-unavailable" },
  {   1, "facility-not-subscribed" },
  {   2, "parameter-unacceptable" },
  { 0, NULL }
};


static int
dissect_p1_RefusalReason(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, ub_integer_options, hf_index, NULL);

  return offset;
}


static const ber_sequence_t RefusedOperation_set[] = {
  { &hf_p1_refused_argument , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_T_refused_argument },
  { &hf_p1_refusal_reason   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_p1_RefusalReason },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_RefusedOperation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              RefusedOperation_set, hf_index, ett_p1_RefusedOperation);

  return offset;
}



static int
dissect_p1_UserName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_T_x121_address(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 857 "../../asn1/p1/p1.cnf"
	tvbuff_t	*nstring = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_x121_address_length, hf_index, &nstring);


	if(doing_address && nstring)
		g_strlcat(oraddress, tvb_format_text(nstring, 0, tvb_length(nstring)), MAX_ORA_STR_LEN);



  return offset;
}



static int
dissect_p1_PrintableString_SIZE_1_ub_tsap_id_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_tsap_id_length, hf_index, NULL);

  return offset;
}


static const ber_sequence_t T_x121_sequence[] = {
  { &hf_p1_x121_address     , BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_T_x121_address },
  { &hf_p1_tsap_id          , BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_PrintableString_SIZE_1_ub_tsap_id_length },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_T_x121(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_x121_sequence, hf_index, ett_p1_T_x121);

  return offset;
}



static int
dissect_p1_PSAPAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509sat_PresentationAddress(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string p1_UserAddress_vals[] = {
  {   0, "x121" },
  {   1, "presentation" },
  { 0, NULL }
};

static const ber_choice_t UserAddress_choice[] = {
  {   0, &hf_p1_x121             , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_T_x121 },
  {   1, &hf_p1_presentation     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_p1_PSAPAddress },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_UserAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 UserAddress_choice, hf_index, ett_p1_UserAddress,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_Priority_set_of[1] = {
  { &hf_p1_class_priority_item, BER_CLASS_APP, 7, BER_FLAGS_NOOWNTAG, dissect_p1_Priority },
};

static int
dissect_p1_SET_OF_Priority(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_Priority_set_of, hf_index, ett_p1_SET_OF_Priority);

  return offset;
}


static const value_string p1_T_objects_vals[] = {
  {   0, "messages" },
  {   1, "reports" },
  {   2, "both" },
  { 0, NULL }
};


static int
dissect_p1_T_objects(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const asn_namedbit T_source_type_bits[] = {
  {  0, &hf_p1_T_source_type_originated_by, -1, -1, "originated-by", NULL },
  {  1, &hf_p1_T_source_type_redirected_by, -1, -1, "redirected-by", NULL },
  {  2, &hf_p1_T_source_type_dl_expanded_by, -1, -1, "dl-expanded-by", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_p1_T_source_type(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_source_type_bits, hf_index, ett_p1_T_source_type,
                                    NULL);

  return offset;
}


static const value_string p1_ExactOrPattern_vals[] = {
  {   0, "exact-match" },
  {   1, "pattern-match" },
  { 0, NULL }
};

static const ber_choice_t ExactOrPattern_choice[] = {
  {   0, &hf_p1_exact_match      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_ORName },
  {   1, &hf_p1_pattern_match    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_p1_ORName },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_ExactOrPattern(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ExactOrPattern_choice, hf_index, ett_p1_ExactOrPattern,
                                 NULL);

  return offset;
}


static const ber_sequence_t Restriction_set[] = {
  { &hf_p1_permitted        , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_BOOLEAN },
  { &hf_p1_source_type      , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_T_source_type },
  { &hf_p1_source_name      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_ExactOrPattern },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_Restriction(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              Restriction_set, hf_index, ett_p1_Restriction);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Restriction_sequence_of[1] = {
  { &hf_p1_applies_only_to_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p1_Restriction },
};

static int
dissect_p1_SEQUENCE_OF_Restriction(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Restriction_sequence_of, hf_index, ett_p1_SEQUENCE_OF_Restriction);

  return offset;
}


static const ber_sequence_t MessageClass_set[] = {
  { &hf_p1_content_types    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_ContentTypes },
  { &hf_p1_maximum_content_length, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_ContentLength },
  { &hf_p1_encoded_information_types_constraints, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_EncodedInformationTypesConstraints },
  { &hf_p1_security_labels  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SecurityContext },
  { &hf_p1_class_priority   , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_OF_Priority },
  { &hf_p1_objects          , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_T_objects },
  { &hf_p1_applies_only_to  , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SEQUENCE_OF_Restriction },
  { &hf_p1_extensions       , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_MessageClass(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              MessageClass_set, hf_index, ett_p1_MessageClass);

  return offset;
}



static int
dissect_p1_DeliverableClass(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_MessageClass(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t SET_SIZE_1_ub_deliverable_class_OF_DeliverableClass_set_of[1] = {
  { &hf_p1_deliverable_class_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p1_DeliverableClass },
};

static int
dissect_p1_SET_SIZE_1_ub_deliverable_class_OF_DeliverableClass(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_set_of(implicit_tag, actx, tree, tvb, offset,
                                             1, ub_deliverable_class, SET_SIZE_1_ub_deliverable_class_OF_DeliverableClass_set_of, hf_index, ett_p1_SET_SIZE_1_ub_deliverable_class_OF_DeliverableClass);

  return offset;
}



static int
dissect_p1_DefaultDeliveryControls(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_Controls(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_RedirectionClass(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_MessageClass(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t SET_SIZE_1_ub_redirection_classes_OF_RedirectionClass_set_of[1] = {
  { &hf_p1_redirection_classes_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p1_RedirectionClass },
};

static int
dissect_p1_SET_SIZE_1_ub_redirection_classes_OF_RedirectionClass(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_set_of(implicit_tag, actx, tree, tvb, offset,
                                             1, ub_redirection_classes, SET_SIZE_1_ub_redirection_classes_OF_RedirectionClass_set_of, hf_index, ett_p1_SET_SIZE_1_ub_redirection_classes_OF_RedirectionClass);

  return offset;
}



static int
dissect_p1_RecipientAssignedAlternateRecipient(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_ORAddressAndOrDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t RecipientRedirection_set[] = {
  { &hf_p1_redirection_classes, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_SIZE_1_ub_redirection_classes_OF_RedirectionClass },
  { &hf_p1_recipient_assigned_alternate_recipient, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_RecipientAssignedAlternateRecipient },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_RecipientRedirection(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              RecipientRedirection_set, hf_index, ett_p1_RecipientRedirection);

  return offset;
}


static const ber_sequence_t Redirections_sequence_of[1] = {
  { &hf_p1_Redirections_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p1_RecipientRedirection },
};

static int
dissect_p1_Redirections(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, ub_redirections, Redirections_sequence_of, hf_index, ett_p1_Redirections);

  return offset;
}


static const ber_sequence_t RestrictedDelivery_sequence_of[1] = {
  { &hf_p1_RestrictedDelivery_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p1_Restriction },
};

static int
dissect_p1_RestrictedDelivery(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, ub_restrictions, RestrictedDelivery_sequence_of, hf_index, ett_p1_RestrictedDelivery);

  return offset;
}


static const asn_namedbit T_standard_parameters_bits[] = {
  {  0, &hf_p1_T_standard_parameters_user_name, -1, -1, "user-name", NULL },
  {  1, &hf_p1_T_standard_parameters_user_address, -1, -1, "user-address", NULL },
  {  2, &hf_p1_T_standard_parameters_deliverable_class, -1, -1, "deliverable-class", NULL },
  {  3, &hf_p1_T_standard_parameters_default_delivery_controls, -1, -1, "default-delivery-controls", NULL },
  {  4, &hf_p1_T_standard_parameters_redirections, -1, -1, "redirections", NULL },
  {  5, &hf_p1_T_standard_parameters_restricted_delivery, -1, -1, "restricted-delivery", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_p1_T_standard_parameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_standard_parameters_bits, hf_index, ett_p1_T_standard_parameters,
                                    NULL);

  return offset;
}



static int
dissect_p1_T_type_extensions_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 531 "../../asn1/p1/p1.cnf"
/*XXX not implemented yet */



  return offset;
}


static const ber_sequence_t T_type_extensions_set_of[1] = {
  { &hf_p1_type_extensions_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_T_type_extensions_item },
};

static int
dissect_p1_T_type_extensions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_type_extensions_set_of, hf_index, ett_p1_T_type_extensions);

  return offset;
}


static const ber_sequence_t RegistrationTypes_sequence[] = {
  { &hf_p1_standard_parameters, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_T_standard_parameters },
  { &hf_p1_type_extensions  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_T_type_extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_RegistrationTypes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RegistrationTypes_sequence, hf_index, ett_p1_RegistrationTypes);

  return offset;
}


static const ber_sequence_t RegisterArgument_set[] = {
  { &hf_p1_user_name        , BER_CLASS_APP, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_UserName },
  { &hf_p1_user_address     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_UserAddress },
  { &hf_p1_deliverable_class, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_SET_SIZE_1_ub_deliverable_class_OF_DeliverableClass },
  { &hf_p1_default_delivery_controls, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_p1_DefaultDeliveryControls },
  { &hf_p1_redirections     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_Redirections },
  { &hf_p1_restricted_delivery, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_RestrictedDelivery },
  { &hf_p1_retrieve_registrations, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_RegistrationTypes },
  { &hf_p1_extensions       , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_RegisterArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              RegisterArgument_set, hf_index, ett_p1_RegisterArgument);

  return offset;
}


static const ber_sequence_t T_non_empty_result_set[] = {
  { &hf_p1_registered_information, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_RegisterArgument },
  { &hf_p1_extensions       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_OF_ExtensionField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_T_non_empty_result(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              T_non_empty_result_set, hf_index, ett_p1_T_non_empty_result);

  return offset;
}


static const value_string p1_RegisterResult_vals[] = {
  {   0, "empty-result" },
  {   1, "non-empty-result" },
  { 0, NULL }
};

static const ber_choice_t RegisterResult_choice[] = {
  {   0, &hf_p1_empty_result     , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_p1_NULL },
  {   1, &hf_p1_non_empty_result , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p1_T_non_empty_result },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_RegisterResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RegisterResult_choice, hf_index, ett_p1_RegisterResult,
                                 NULL);

  return offset;
}



static int
dissect_p1_RES_change_credentials(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t ChangeCredentialsArgument_set[] = {
  { &hf_p1_old_credentials  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_Credentials },
  { &hf_p1_new_credentials  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_Credentials },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_ChangeCredentialsArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ChangeCredentialsArgument_set, hf_index, ett_p1_ChangeCredentialsArgument);

  return offset;
}



static int
dissect_p1_PAR_register_rejected(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_p1_PAR_new_credentials_unacceptable(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_p1_PAR_old_credentials_incorrectly_specified(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}




static const ber_sequence_t MessageDeliveryEnvelope_sequence[] = {
  { &hf_p1_message_delivery_identifier, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_p1_MessageDeliveryIdentifier },
  { &hf_p1_message_delivery_time, BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_p1_MessageDeliveryTime },
  { &hf_p1_other_fields     , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p1_OtherMessageDeliveryFields },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_MessageDeliveryEnvelope(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MessageDeliveryEnvelope_sequence, hf_index, ett_p1_MessageDeliveryEnvelope);

  return offset;
}


static const ber_sequence_t ReportDeliveryEnvelope_set[] = {
  { &hf_p1_subject_submission_identifier, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_p1_SubjectSubmissionIdentifier },
  { &hf_p1_content_identifier, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_ContentIdentifier },
  { &hf_p1_content_type     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_ContentType },
  { &hf_p1_original_encoded_information_types, BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_OriginalEncodedInformationTypes },
  { &hf_p1_extensions       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SET_OF_ExtensionField },
  { &hf_p1_per_recipient_report_delivery_fields, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportDeliveryFields },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_ReportDeliveryEnvelope(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ReportDeliveryEnvelope_set, hf_index, ett_p1_ReportDeliveryEnvelope);

  return offset;
}



static const value_string p1_RecipientReassignmentProhibited_vals[] = {
  {   0, "recipient-reassignment-allowed" },
  {   1, "recipient-reassignment-prohibited" },
  { 0, NULL }
};


static int
dissect_p1_RecipientReassignmentProhibited(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_p1_OriginatorRequestedAlternateRecipient(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_ORAddressAndOrDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string p1_DLExpansionProhibited_vals[] = {
  {   0, "dl-expansion-allowed" },
  {   1, "dl-expansion-prohibited" },
  { 0, NULL }
};


static int
dissect_p1_DLExpansionProhibited(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string p1_ConversionWithLossProhibited_vals[] = {
  {   0, "conversion-with-loss-allowed" },
  {   1, "conversion-with-loss-prohibited" },
  { 0, NULL }
};


static int
dissect_p1_ConversionWithLossProhibited(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_p1_LatestDeliveryTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_Time(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string p1_RequestedDeliveryMethod_item_vals[] = {
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
dissect_p1_RequestedDeliveryMethod_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, ub_integer_options, hf_index, NULL);

  return offset;
}


static const ber_sequence_t RequestedDeliveryMethod_sequence_of[1] = {
  { &hf_p1_RequestedDeliveryMethod_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_p1_RequestedDeliveryMethod_item },
};

int
dissect_p1_RequestedDeliveryMethod(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      RequestedDeliveryMethod_sequence_of, hf_index, ett_p1_RequestedDeliveryMethod);

  return offset;
}


static const value_string p1_PhysicalForwardingProhibited_vals[] = {
  {   0, "physical-forwarding-allowed" },
  {   1, "physical-forwarding-prohibited" },
  { 0, NULL }
};


static int
dissect_p1_PhysicalForwardingProhibited(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string p1_PhysicalForwardingAddressRequest_vals[] = {
  {   0, "physical-forwarding-address-not-requested" },
  {   1, "physical-forwarding-address-requested" },
  { 0, NULL }
};


static int
dissect_p1_PhysicalForwardingAddressRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const asn_namedbit PhysicalDeliveryModes_bits[] = {
  {  0, &hf_p1_PhysicalDeliveryModes_ordinary_mail, -1, -1, "ordinary-mail", NULL },
  {  1, &hf_p1_PhysicalDeliveryModes_special_delivery, -1, -1, "special-delivery", NULL },
  {  2, &hf_p1_PhysicalDeliveryModes_express_mail, -1, -1, "express-mail", NULL },
  {  3, &hf_p1_PhysicalDeliveryModes_counter_collection, -1, -1, "counter-collection", NULL },
  {  4, &hf_p1_PhysicalDeliveryModes_counter_collection_with_telephone_advice, -1, -1, "counter-collection-with-telephone-advice", NULL },
  {  5, &hf_p1_PhysicalDeliveryModes_counter_collection_with_telex_advice, -1, -1, "counter-collection-with-telex-advice", NULL },
  {  6, &hf_p1_PhysicalDeliveryModes_counter_collection_with_teletex_advice, -1, -1, "counter-collection-with-teletex-advice", NULL },
  {  7, &hf_p1_PhysicalDeliveryModes_bureau_fax_delivery, -1, -1, "bureau-fax-delivery", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_p1_PhysicalDeliveryModes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_bitstring(implicit_tag, actx, tree, tvb, offset,
                                                0, ub_bit_options, PhysicalDeliveryModes_bits, hf_index, ett_p1_PhysicalDeliveryModes,
                                                NULL);

  return offset;
}


static const value_string p1_RegisteredMailType_vals[] = {
  {   0, "non-registered-mail" },
  {   1, "registered-mail" },
  {   2, "registered-mail-to-addressee-in-person" },
  { 0, NULL }
};


static int
dissect_p1_RegisteredMailType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, ub_integer_options, hf_index, NULL);

  return offset;
}



static int
dissect_p1_RecipientNumberForAdvice(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_recipient_number_for_advice_length, hf_index, NULL);

  return offset;
}



static int
dissect_p1_PhysicalRenditionAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t ORAddress_sequence[] = {
  { &hf_p1_built_in_standard_attributes, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_p1_BuiltInStandardAttributes },
  { &hf_p1_built_in_domain_defined_attributes, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_BuiltInDomainDefinedAttributes },
  { &hf_p1_extension_attributes, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_ExtensionAttributes },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_p1_ORAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1054 "../../asn1/p1/p1.cnf"
	
	oraddress = ep_alloc(MAX_ORA_STR_LEN); oraddress[0] = '\0';	
	doing_address = TRUE;
	address_item = NULL;

	  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ORAddress_sequence, hf_index, ett_p1_ORAddress);


	if(*oraddress && address_item)
		proto_item_append_text(address_item, " %s/", oraddress);

	doing_address = FALSE;



  return offset;
}



static int
dissect_p1_OriginatorReturnAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_ORAddress(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string p1_PhysicalDeliveryReportRequest_vals[] = {
  {   0, "return-of-undeliverable-mail-by-PDS" },
  {   1, "return-of-notification-by-PDS" },
  {   2, "return-of-notification-by-MHS" },
  {   3, "return-of-notification-by-MHS-and-PDS" },
  { 0, NULL }
};


static int
dissect_p1_PhysicalDeliveryReportRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, ub_integer_options, hf_index, NULL);

  return offset;
}



static int
dissect_p1_OriginatorCertificate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_Certificates(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_p1_MessageToken(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_Token(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_ContentConfidentialityAlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_p1_ContentIntegrityCheck(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_Signature(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_p1_MessageOriginAuthenticationCheck(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_Signature(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_p1_MessageSecurityLabel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_SecurityLabel(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string p1_ProofOfSubmissionRequest_vals[] = {
  {   0, "proof-of-submission-not-requested" },
  {   1, "proof-of-submission-requested" },
  { 0, NULL }
};


static int
dissect_p1_ProofOfSubmissionRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string p1_ProofOfDeliveryRequest_vals[] = {
  {   0, "proof-of-delivery-not-requested" },
  {   1, "proof-of-delivery-requested" },
  { 0, NULL }
};


static int
dissect_p1_ProofOfDeliveryRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_p1_IA5String(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string p1_ContentCorrelator_vals[] = {
  {   0, "ia5text" },
  {   1, "octets" },
  { 0, NULL }
};

static const ber_choice_t ContentCorrelator_choice[] = {
  {   0, &hf_p1_ia5text          , BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_p1_IA5String },
  {   1, &hf_p1_octets           , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_p1_OCTET_STRING },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_ContentCorrelator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ContentCorrelator_choice, hf_index, ett_p1_ContentCorrelator,
                                 NULL);

  return offset;
}



static int
dissect_p1_ProbeOriginAuthenticationCheck(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_Signature(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t IntendedRecipientName_sequence[] = {
  { &hf_p1_intended_recipient, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_p1_ORAddressAndOptionalDirectoryName },
  { &hf_p1_redirection_time , BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_p1_Time },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_IntendedRecipientName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IntendedRecipientName_sequence, hf_index, ett_p1_IntendedRecipientName);

  return offset;
}


static const value_string p1_RedirectionReason_vals[] = {
  {   0, "recipient-assigned-alternate-recipient" },
  {   1, "originator-requested-alternate-recipient" },
  {   2, "recipient-MD-assigned-alternate-recipient" },
  {   3, "directory-look-up" },
  {   4, "alias" },
  { 0, NULL }
};


static int
dissect_p1_RedirectionReason(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t Redirection_sequence[] = {
  { &hf_p1_intended_recipient_name, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_p1_IntendedRecipientName },
  { &hf_p1_redirection_reason, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_p1_RedirectionReason },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_Redirection(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Redirection_sequence, hf_index, ett_p1_Redirection);

  return offset;
}


static const ber_sequence_t RedirectionHistory_sequence_of[1] = {
  { &hf_p1_RedirectionHistory_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_p1_Redirection },
};

static int
dissect_p1_RedirectionHistory(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, ub_redirections, RedirectionHistory_sequence_of, hf_index, ett_p1_RedirectionHistory);

  return offset;
}


static const ber_sequence_t DLExpansion_sequence[] = {
  { &hf_p1_dl               , BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_p1_ORAddressAndOptionalDirectoryName },
  { &hf_p1_dl_expansion_time, BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_p1_Time },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_DLExpansion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DLExpansion_sequence, hf_index, ett_p1_DLExpansion);

  return offset;
}


static const ber_sequence_t DLExpansionHistory_sequence_of[1] = {
  { &hf_p1_DLExpansionHistory_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_p1_DLExpansion },
};

static int
dissect_p1_DLExpansionHistory(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, ub_dl_expansions, DLExpansionHistory_sequence_of, hf_index, ett_p1_DLExpansionHistory);

  return offset;
}



static int
dissect_p1_PhysicalForwardingAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t OriginatorAndDLExpansion_sequence[] = {
  { &hf_p1_originator_or_dl_name, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_p1_ORAddressAndOptionalDirectoryName },
  { &hf_p1_origination_or_expansion_time, BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_p1_Time },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_OriginatorAndDLExpansion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OriginatorAndDLExpansion_sequence, hf_index, ett_p1_OriginatorAndDLExpansion);

  return offset;
}


static const ber_sequence_t OriginatorAndDLExpansionHistory_sequence_of[1] = {
  { &hf_p1_OriginatorAndDLExpansionHistory_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_p1_OriginatorAndDLExpansion },
};

static int
dissect_p1_OriginatorAndDLExpansionHistory(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  2, ub_orig_and_dl_expansions, OriginatorAndDLExpansionHistory_sequence_of, hf_index, ett_p1_OriginatorAndDLExpansionHistory);

  return offset;
}



static int
dissect_p1_ReportingDLName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_ORAddressAndOptionalDirectoryName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_ReportingMTACertificate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_Certificates(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_ReportOriginAuthenticationCheck(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_Signature(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t PerRecipientDeliveryReportFields_sequence[] = {
  { &hf_p1_message_delivery_time, BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_p1_MessageDeliveryTime },
  { &hf_p1_type_of_MTS_user , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_p1_TypeOfMTSUser },
  { &hf_p1_recipient_certificate, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_RecipientCertificate },
  { &hf_p1_proof_of_delivery, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_ProofOfDelivery },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_PerRecipientDeliveryReportFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PerRecipientDeliveryReportFields_sequence, hf_index, ett_p1_PerRecipientDeliveryReportFields);

  return offset;
}


static const ber_sequence_t PerRecipientNonDeliveryReportFields_sequence[] = {
  { &hf_p1_non_delivery_reason_code, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_p1_NonDeliveryReasonCode },
  { &hf_p1_non_delivery_diagnostic_code, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_NonDeliveryDiagnosticCode },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_PerRecipientNonDeliveryReportFields(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PerRecipientNonDeliveryReportFields_sequence, hf_index, ett_p1_PerRecipientNonDeliveryReportFields);

  return offset;
}


static const value_string p1_T_report_type_vals[] = {
  {   0, "delivery" },
  {   1, "non-delivery" },
  { 0, NULL }
};

static const ber_choice_t T_report_type_choice[] = {
  {   0, &hf_p1_report_type_delivery, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_PerRecipientDeliveryReportFields },
  {   1, &hf_p1_non_delivery_report, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_p1_PerRecipientNonDeliveryReportFields },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_T_report_type(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_report_type_choice, hf_index, ett_p1_T_report_type,
                                 NULL);

  return offset;
}




int
dissect_p1_OriginatingMTACertificate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_Certificates(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_p1_ProofOfSubmission(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_Signature(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t ReportingMTAName_sequence[] = {
  { &hf_p1_domain           , BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_p1_GlobalDomainIdentifier },
  { &hf_p1_mta_name         , BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_p1_MTAName },
  { &hf_p1_mta_directory_name, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509if_Name },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_ReportingMTAName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReportingMTAName_sequence, hf_index, ett_p1_ReportingMTAName);

  return offset;
}


static const value_string p1_ExtendedCertificate_vals[] = {
  {   0, "directory-entry" },
  {   1, "certificate" },
  { 0, NULL }
};

static const ber_choice_t ExtendedCertificate_choice[] = {
  {   0, &hf_p1_directory_entry  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x509if_Name },
  {   1, &hf_p1_certificate      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x509af_Certificates },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_ExtendedCertificate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ExtendedCertificate_choice, hf_index, ett_p1_ExtendedCertificate,
                                 NULL);

  return offset;
}


static const ber_sequence_t ExtendedCertificates_set_of[1] = {
  { &hf_p1_ExtendedCertificates_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_ExtendedCertificate },
};

int
dissect_p1_ExtendedCertificates(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_set_of(implicit_tag, actx, tree, tvb, offset,
                                             1, ub_certificates, ExtendedCertificates_set_of, hf_index, ett_p1_ExtendedCertificates);

  return offset;
}


static const ber_sequence_t DLExemptedRecipients_set_of[1] = {
  { &hf_p1_DLExemptedRecipients_item, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_p1_ORAddressAndOrDirectoryName },
};

static int
dissect_p1_DLExemptedRecipients(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 DLExemptedRecipients_set_of, hf_index, ett_p1_DLExemptedRecipients);

  return offset;
}


static const ber_sequence_t CertificateSelectors_set[] = {
  { &hf_p1_encryption_recipient, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_CertificateAssertion },
  { &hf_p1_encryption_originator, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_CertificateAssertion },
  { &hf_p1_selectors_content_integrity_check, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_CertificateAssertion },
  { &hf_p1_token_signature  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_CertificateAssertion },
  { &hf_p1_message_origin_authentication, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_CertificateAssertion },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_CertificateSelectors(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              CertificateSelectors_set, hf_index, ett_p1_CertificateSelectors);

  return offset;
}



static int
dissect_p1_CommonName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 794 "../../asn1/p1/p1.cnf"
	tvbuff_t	*string = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_common_name_length, hf_index, &string);


	if(doing_address && string) {
		g_strlcat(oraddress, "/CN=", MAX_ORA_STR_LEN);
		g_strlcat(oraddress, tvb_format_text(string, 0, tvb_length(string)), MAX_ORA_STR_LEN);
	}



  return offset;
}



static int
dissect_p1_TeletexCommonName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 807 "../../asn1/p1/p1.cnf"
	tvbuff_t	*string = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_common_name_length, hf_index, &string);


	if(doing_address && string) {
		g_strlcat(oraddress, "/CN=", MAX_ORA_STR_LEN);
		g_strlcat(oraddress, tvb_format_text(string, 0, tvb_length(string)), MAX_ORA_STR_LEN);
	}



  return offset;
}



static int
dissect_p1_BMPString_SIZE_1_ub_string_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_BMPString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_string_length, hf_index, NULL);

  return offset;
}



static int
dissect_p1_UniversalString_SIZE_1_ub_string_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_UniversalString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_string_length, hf_index, NULL);

  return offset;
}


static const value_string p1_T_character_encoding_vals[] = {
  {   0, "two-octets" },
  {   1, "four-octets" },
  { 0, NULL }
};

static const ber_choice_t T_character_encoding_choice[] = {
  {   0, &hf_p1_two_octets       , BER_CLASS_UNI, BER_UNI_TAG_BMPString, BER_FLAGS_NOOWNTAG, dissect_p1_BMPString_SIZE_1_ub_string_length },
  {   1, &hf_p1_four_octets      , BER_CLASS_UNI, BER_UNI_TAG_UniversalString, BER_FLAGS_NOOWNTAG, dissect_p1_UniversalString_SIZE_1_ub_string_length },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_T_character_encoding(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_character_encoding_choice, hf_index, ett_p1_T_character_encoding,
                                 NULL);

  return offset;
}



static int
dissect_p1_PrintableString_SIZE_CONSTR001(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        2, 5, hf_index, NULL);

  return offset;
}


static const ber_sequence_t UniversalOrBMPString_set[] = {
  { &hf_p1_character_encoding, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_T_character_encoding },
  { &hf_p1_iso_639_language_code, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_PrintableString_SIZE_CONSTR001 },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_p1_UniversalOrBMPString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              UniversalOrBMPString_set, hf_index, ett_p1_UniversalOrBMPString);

  return offset;
}



static int
dissect_p1_UniversalCommonName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_UniversalOrBMPString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_TeletexOrganizationName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 755 "../../asn1/p1/p1.cnf"
	tvbuff_t	*string = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_organization_name_length, hf_index, &string);


	if(doing_address && string) {
		g_strlcat(oraddress, "/O=", MAX_ORA_STR_LEN);
		g_strlcat(oraddress, tvb_format_text(string, 0, tvb_length(string)), MAX_ORA_STR_LEN);
	}



  return offset;
}



static int
dissect_p1_UniversalOrganizationName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_UniversalOrBMPString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_T_teletex_surname(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 985 "../../asn1/p1/p1.cnf"
	tvbuff_t	*tstring = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_surname_length, hf_index, &tstring);


	if(doing_address && tstring) {
	    g_strlcat(oraddress, "/S=", MAX_ORA_STR_LEN);
	  g_strlcat(oraddress, tvb_format_text(tstring, 0, tvb_length(tstring)), MAX_ORA_STR_LEN);
	}



  return offset;
}



static int
dissect_p1_T_teletex_given_name(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 995 "../../asn1/p1/p1.cnf"
	tvbuff_t	*tstring = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_given_name_length, hf_index, &tstring);


	if(doing_address && tstring) {
	    g_strlcat(oraddress, "/G=", MAX_ORA_STR_LEN);
	  g_strlcat(oraddress, tvb_format_text(tstring, 0, tvb_length(tstring)), MAX_ORA_STR_LEN);
	}



  return offset;
}



static int
dissect_p1_T_teletex_initials(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1005 "../../asn1/p1/p1.cnf"
	tvbuff_t	*tstring = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_initials_length, hf_index, &tstring);


	if(doing_address && tstring) {
	    g_strlcat(oraddress, "/I=", MAX_ORA_STR_LEN);
	  g_strlcat(oraddress, tvb_format_text(tstring, 0, tvb_length(tstring)), MAX_ORA_STR_LEN);
	}



  return offset;
}



static int
dissect_p1_T_teletex_generation_qualifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1015 "../../asn1/p1/p1.cnf"
	tvbuff_t	*tstring = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_generation_qualifier_length, hf_index, &tstring);


	if(doing_address && tstring) {
	    g_strlcat(oraddress, "/Q=", MAX_ORA_STR_LEN);
	  g_strlcat(oraddress, tvb_format_text(tstring, 0, tvb_length(tstring)), MAX_ORA_STR_LEN);
	}



  return offset;
}


static const ber_sequence_t TeletexPersonalName_set[] = {
  { &hf_p1_teletex_surname  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_T_teletex_surname },
  { &hf_p1_teletex_given_name, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_T_teletex_given_name },
  { &hf_p1_teletex_initials , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_T_teletex_initials },
  { &hf_p1_teletex_generation_qualifier, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_T_teletex_generation_qualifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_TeletexPersonalName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              TeletexPersonalName_set, hf_index, ett_p1_TeletexPersonalName);

  return offset;
}


static const ber_sequence_t UniversalPersonalName_set[] = {
  { &hf_p1_universal_surname, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_UniversalOrBMPString },
  { &hf_p1_universal_given_name, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_UniversalOrBMPString },
  { &hf_p1_universal_initials, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_UniversalOrBMPString },
  { &hf_p1_universal_generation_qualifier, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_UniversalOrBMPString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_UniversalPersonalName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              UniversalPersonalName_set, hf_index, ett_p1_UniversalPersonalName);

  return offset;
}



static int
dissect_p1_TeletexOrganizationalUnitName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 781 "../../asn1/p1/p1.cnf"
	tvbuff_t	*string = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_organizational_unit_name_length, hf_index, &string);


	if(doing_address && string) {
		g_strlcat(oraddress, "/OU=", MAX_ORA_STR_LEN);
		g_strlcat(oraddress, tvb_format_text(string, 0, tvb_length(string)), MAX_ORA_STR_LEN);
	}



  return offset;
}


static const ber_sequence_t TeletexOrganizationalUnitNames_sequence_of[1] = {
  { &hf_p1_TeletexOrganizationalUnitNames_item, BER_CLASS_UNI, BER_UNI_TAG_TeletexString, BER_FLAGS_NOOWNTAG, dissect_p1_TeletexOrganizationalUnitName },
};

static int
dissect_p1_TeletexOrganizationalUnitNames(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, ub_organizational_units, TeletexOrganizationalUnitNames_sequence_of, hf_index, ett_p1_TeletexOrganizationalUnitNames);

  return offset;
}



static int
dissect_p1_UniversalOrganizationalUnitName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_UniversalOrBMPString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t UniversalOrganizationalUnitNames_sequence_of[1] = {
  { &hf_p1_UniversalOrganizationalUnitNames_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p1_UniversalOrganizationalUnitName },
};

static int
dissect_p1_UniversalOrganizationalUnitNames(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, ub_organizational_units, UniversalOrganizationalUnitNames_sequence_of, hf_index, ett_p1_UniversalOrganizationalUnitNames);

  return offset;
}



static int
dissect_p1_PDSName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_pds_name_length, hf_index, NULL);

  return offset;
}



static int
dissect_p1_T_x121_dcc_code_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 897 "../../asn1/p1/p1.cnf"
	tvbuff_t	*nstring = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                                        actx, tree, tvb, offset,
                                                        ub_country_name_numeric_length, ub_country_name_numeric_length, hf_index, &nstring);


	if(doing_address && nstring)
		g_strlcat(oraddress, tvb_format_text(nstring, 0, tvb_length(nstring)), MAX_ORA_STR_LEN);



  return offset;
}



static int
dissect_p1_T_iso_3166_alpha2_code_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 849 "../../asn1/p1/p1.cnf"
	tvbuff_t	*nstring = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        ub_country_name_alpha_length, ub_country_name_alpha_length, hf_index, &nstring);


	if(doing_address && nstring)
		g_strlcat(oraddress, tvb_format_text(nstring, 0, tvb_length(nstring)), MAX_ORA_STR_LEN);



  return offset;
}


static const value_string p1_PhysicalDeliveryCountryName_vals[] = {
  {   0, "x121-dcc-code" },
  {   1, "iso-3166-alpha2-code" },
  { 0, NULL }
};

static const ber_choice_t PhysicalDeliveryCountryName_choice[] = {
  {   0, &hf_p1_x121_dcc_code_01 , BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_p1_T_x121_dcc_code_01 },
  {   1, &hf_p1_iso_3166_alpha2_code_01, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_p1_T_iso_3166_alpha2_code_01 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_PhysicalDeliveryCountryName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PhysicalDeliveryCountryName_choice, hf_index, ett_p1_PhysicalDeliveryCountryName,
                                 NULL);

  return offset;
}



static int
dissect_p1_T_numeric_code(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 905 "../../asn1/p1/p1.cnf"
	tvbuff_t	*nstring = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_postal_code_length, hf_index, &nstring);


	if(doing_address && nstring)
		g_strlcat(oraddress, tvb_format_text(nstring, 0, tvb_length(nstring)), MAX_ORA_STR_LEN);




  return offset;
}



static int
dissect_p1_PrintableString_SIZE_1_ub_postal_code_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_postal_code_length, hf_index, NULL);

  return offset;
}


static const value_string p1_PostalCode_vals[] = {
  {   0, "numeric-code" },
  {   1, "printable-code" },
  { 0, NULL }
};

static const ber_choice_t PostalCode_choice[] = {
  {   0, &hf_p1_numeric_code     , BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_p1_T_numeric_code },
  {   1, &hf_p1_printable_code   , BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_p1_PrintableString_SIZE_1_ub_postal_code_length },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_PostalCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PostalCode_choice, hf_index, ett_p1_PostalCode,
                                 NULL);

  return offset;
}



static int
dissect_p1_PrintableString_SIZE_1_ub_pds_parameter_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_pds_parameter_length, hf_index, NULL);

  return offset;
}



static int
dissect_p1_TeletexString_SIZE_1_ub_pds_parameter_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_pds_parameter_length, hf_index, NULL);

  return offset;
}


static const ber_sequence_t PDSParameter_set[] = {
  { &hf_p1_printable_string , BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_PrintableString_SIZE_1_ub_pds_parameter_length },
  { &hf_p1_pds_teletex_string, BER_CLASS_UNI, BER_UNI_TAG_TeletexString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_TeletexString_SIZE_1_ub_pds_parameter_length },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_PDSParameter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              PDSParameter_set, hf_index, ett_p1_PDSParameter);

  return offset;
}



static int
dissect_p1_PhysicalDeliveryOfficeName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_PDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_UniversalPDSParameter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_UniversalOrBMPString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_UniversalPhysicalDeliveryOfficeName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_UniversalPDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_PhysicalDeliveryOfficeNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_PDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_UniversalPhysicalDeliveryOfficeNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_UniversalPDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_ExtensionORAddressComponents(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_PDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_UniversalExtensionORAddressComponents(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_UniversalPDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_PhysicalDeliveryPersonalName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_PDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_UniversalPhysicalDeliveryPersonalName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_UniversalPDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_PhysicalDeliveryOrganizationName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_PDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_UniversalPhysicalDeliveryOrganizationName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_UniversalPDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_ExtensionPhysicalDeliveryAddressComponents(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_PDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_UniversalExtensionPhysicalDeliveryAddressComponents(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_UniversalPDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t T_printable_address_sequence_of[1] = {
  { &hf_p1_printable_address_item, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_p1_PrintableString_SIZE_1_ub_pds_parameter_length },
};

static int
dissect_p1_T_printable_address(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, ub_pds_physical_address_lines, T_printable_address_sequence_of, hf_index, ett_p1_T_printable_address);

  return offset;
}



static int
dissect_p1_TeletexString_SIZE_1_ub_unformatted_address_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_unformatted_address_length, hf_index, NULL);

  return offset;
}


static const ber_sequence_t UnformattedPostalAddress_set[] = {
  { &hf_p1_printable_address, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_T_printable_address },
  { &hf_p1_teletex_string   , BER_CLASS_UNI, BER_UNI_TAG_TeletexString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_TeletexString_SIZE_1_ub_unformatted_address_length },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_UnformattedPostalAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              UnformattedPostalAddress_set, hf_index, ett_p1_UnformattedPostalAddress);

  return offset;
}



static int
dissect_p1_UniversalUnformattedPostalAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_UniversalOrBMPString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_StreetAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_PDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_UniversalStreetAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_UniversalPDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_PostOfficeBoxAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_PDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_UniversalPostOfficeBoxAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_UniversalPDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_PosteRestanteAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_PDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_UniversalPosteRestanteAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_UniversalPDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_UniquePostalName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_PDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_UniversalUniquePostalName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_UniversalPDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_LocalPostalAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_PDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_UniversalLocalPostalAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_UniversalPDSParameter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_NumericString_SIZE_1_ub_e163_4_number_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_e163_4_number_length, hf_index, NULL);

  return offset;
}



static int
dissect_p1_NumericString_SIZE_1_ub_e163_4_sub_address_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_e163_4_sub_address_length, hf_index, NULL);

  return offset;
}


static const ber_sequence_t T_e163_4_address_sequence[] = {
  { &hf_p1_number           , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_NumericString_SIZE_1_ub_e163_4_number_length },
  { &hf_p1_sub_address      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_NumericString_SIZE_1_ub_e163_4_sub_address_length },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_T_e163_4_address(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_e163_4_address_sequence, hf_index, ett_p1_T_e163_4_address);

  return offset;
}


static const value_string p1_ExtendedNetworkAddress_vals[] = {
  {   0, "e163-4-address" },
  {   1, "psap-address" },
  { 0, NULL }
};

static const ber_choice_t ExtendedNetworkAddress_choice[] = {
  {   0, &hf_p1_e163_4_address   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_p1_T_e163_4_address },
  {   1, &hf_p1_psap_address     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x509sat_PresentationAddress },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_ExtendedNetworkAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ExtendedNetworkAddress_choice, hf_index, ett_p1_ExtendedNetworkAddress,
                                 NULL);

  return offset;
}


static const value_string p1_TerminalType_vals[] = {
  {   3, "telex" },
  {   4, "teletex" },
  {   5, "g3-facsimile" },
  {   6, "g4-facsimile" },
  {   7, "ia5-terminal" },
  {   8, "videotex" },
  { 0, NULL }
};


static int
dissect_p1_TerminalType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, ub_integer_options, hf_index, NULL);

  return offset;
}



static int
dissect_p1_T_type(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 914 "../../asn1/p1/p1.cnf"
	tvbuff_t	*tstring = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_domain_defined_attribute_type_length, hf_index, &tstring);


	if(doing_address && tstring) {
		g_strlcat(oraddress, "/DD.", MAX_ORA_STR_LEN);
		g_strlcat(oraddress, tvb_format_text(tstring, 0, tvb_length(tstring)), MAX_ORA_STR_LEN);
		g_strlcat(ddatype, tvb_format_text(tstring, 0, tvb_length(tstring)), MAX_ORA_STR_LEN);
	}




  return offset;
}



static int
dissect_p1_T_teletex_value(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 926 "../../asn1/p1/p1.cnf"
	tvbuff_t	*tstring = NULL;

	  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_domain_defined_attribute_value_length, hf_index, &tstring);


	if(doing_address && tstring) {
		g_strlcat(oraddress, "=", MAX_ORA_STR_LEN);
		g_strlcat(oraddress, tvb_format_text(tstring, 0, tvb_length(tstring)), MAX_ORA_STR_LEN);
		if (*ddatype) {
		   proto_item_append_text (tree, " (%s=%s)", ddatype, tvb_format_text(tstring, 0, tvb_length(tstring)));
		}
	}




  return offset;
}


static const ber_sequence_t TeletexDomainDefinedAttribute_sequence[] = {
  { &hf_p1_type             , BER_CLASS_UNI, BER_UNI_TAG_TeletexString, BER_FLAGS_NOOWNTAG, dissect_p1_T_type },
  { &hf_p1_teletex_value    , BER_CLASS_UNI, BER_UNI_TAG_TeletexString, BER_FLAGS_NOOWNTAG, dissect_p1_T_teletex_value },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_TeletexDomainDefinedAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 940 "../../asn1/p1/p1.cnf"
        ddatype = ep_alloc(MAX_ORA_STR_LEN); ddatype[0] = '\0';

	  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TeletexDomainDefinedAttribute_sequence, hf_index, ett_p1_TeletexDomainDefinedAttribute);




  return offset;
}


static const ber_sequence_t TeletexDomainDefinedAttributes_sequence_of[1] = {
  { &hf_p1_TeletexDomainDefinedAttributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_p1_TeletexDomainDefinedAttribute },
};

static int
dissect_p1_TeletexDomainDefinedAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, ub_domain_defined_attributes, TeletexDomainDefinedAttributes_sequence_of, hf_index, ett_p1_TeletexDomainDefinedAttributes);

  return offset;
}


static const ber_sequence_t UniversalDomainDefinedAttribute_sequence[] = {
  { &hf_p1_universal_type   , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p1_UniversalOrBMPString },
  { &hf_p1_universal_value  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_p1_UniversalOrBMPString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_UniversalDomainDefinedAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UniversalDomainDefinedAttribute_sequence, hf_index, ett_p1_UniversalDomainDefinedAttribute);

  return offset;
}


static const ber_sequence_t UniversalDomainDefinedAttributes_sequence_of[1] = {
  { &hf_p1_UniversalDomainDefinedAttributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_p1_UniversalDomainDefinedAttribute },
};

static int
dissect_p1_UniversalDomainDefinedAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, ub_domain_defined_attributes, UniversalDomainDefinedAttributes_sequence_of, hf_index, ett_p1_UniversalDomainDefinedAttributes);

  return offset;
}



static const ber_sequence_t MTANameAndOptionalGDI_sequence[] = {
  { &hf_p1_global_domain_identifier, BER_CLASS_APP, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_GlobalDomainIdentifier },
  { &hf_p1_mta_name         , BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_p1_MTAName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_MTANameAndOptionalGDI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1133 "../../asn1/p1/p1.cnf"

	doing_address = TRUE;

	  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MTANameAndOptionalGDI_sequence, hf_index, ett_p1_MTANameAndOptionalGDI);


	doing_address = FALSE;
	proto_item_append_text(tree, ")");



  return offset;
}


static const value_string p1_T_name_vals[] = {
  {   0, "recipient-name" },
  {   1, "mta" },
  { 0, NULL }
};

static const ber_choice_t T_name_choice[] = {
  {   0, &hf_p1_token_recipient_name, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_p1_RecipientName },
  {   1, &hf_p1_token_mta        , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_p1_MTANameAndOptionalGDI },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_T_name(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_name_choice, hf_index, ett_p1_T_name,
                                 NULL);

  return offset;
}


static const value_string p1_TokenDataType_vals[] = {
  {   1, "bind-token-signed-data" },
  {   2, "message-token-signed-data" },
  {   3, "message-token-encrypted-data" },
  {   4, "bind-token-encrypted-data" },
  { 0, NULL }
};


static int
dissect_p1_TokenDataType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &extension_id);

  return offset;
}



static int
dissect_p1_T_value(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1237 "../../asn1/p1/p1.cnf"

	proto_item_append_text(tree, " (%s)", val_to_str(extension_id, p1_TokenDataType_vals, "tokendata-type %d")); 
	if (dissector_try_uint(p1_tokendata_dissector_table, extension_id, tvb, actx->pinfo, tree)) {
		offset = tvb_length(tvb);
	} else {
		proto_item *item = NULL;
		proto_tree *next_tree = NULL;

		item = proto_tree_add_text(tree, tvb, 0, tvb_length_remaining(tvb, offset), 
			"Dissector for tokendata-type %d not implemented.  Contact Wireshark developers if you want this supported", extension_id);
		next_tree = proto_item_add_subtree(item, ett_p1_unknown_tokendata_type);
		offset = dissect_unknown_ber(actx->pinfo, tvb, offset, next_tree);
		expert_add_info_format(actx->pinfo, item, PI_UNDECODED, PI_WARN, "Unknown tokendata-type");
	}



  return offset;
}


static const ber_sequence_t TokenData_sequence[] = {
  { &hf_p1_token_data_type  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_TokenDataType },
  { &hf_p1_value            , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_p1_T_value },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_TokenData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TokenData_sequence, hf_index, ett_p1_TokenData);

  return offset;
}


static const ber_sequence_t AsymmetricTokenData_sequence[] = {
  { &hf_p1_signature_algorithm_identifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_p1_name             , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_p1_T_name },
  { &hf_p1_time             , BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_p1_Time },
  { &hf_p1_signed_data      , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_TokenData },
  { &hf_p1_encryption_algorithm_identifier, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_p1_encrypted_data   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_AsymmetricTokenData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AsymmetricTokenData_sequence, hf_index, ett_p1_AsymmetricTokenData);

  return offset;
}


static const ber_sequence_t AsymmetricToken_sequence[] = {
  { &hf_p1_asymmetric_token_data, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_p1_AsymmetricTokenData },
  { &hf_p1_algorithm_identifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_p1_encrypted        , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_p1_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_AsymmetricToken(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AsymmetricToken_sequence, hf_index, ett_p1_AsymmetricToken);

  return offset;
}



static int
dissect_p1_RandomNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_p1_BindTokenSignedData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_RandomNumber(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_p1_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t MessageTokenSignedData_sequence[] = {
  { &hf_p1_content_confidentiality_algorithm_identifier, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_ContentConfidentialityAlgorithmIdentifier },
  { &hf_p1_content_integrity_check, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_ContentIntegrityCheck },
  { &hf_p1_message_security_label, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_MessageSecurityLabel },
  { &hf_p1_proof_of_delivery_request, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_ProofOfDeliveryRequest },
  { &hf_p1_message_sequence_number, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_MessageTokenSignedData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MessageTokenSignedData_sequence, hf_index, ett_p1_MessageTokenSignedData);

  return offset;
}



static int
dissect_p1_EncryptionKey(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t MessageTokenEncryptedData_sequence[] = {
  { &hf_p1_content_confidentiality_key, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_EncryptionKey },
  { &hf_p1_content_integrity_check, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_ContentIntegrityCheck },
  { &hf_p1_message_security_label, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_MessageSecurityLabel },
  { &hf_p1_content_integrity_key, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_EncryptionKey },
  { &hf_p1_message_sequence_number, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_p1_MessageTokenEncryptedData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MessageTokenEncryptedData_sequence, hf_index, ett_p1_MessageTokenEncryptedData);

  return offset;
}



static int
dissect_p1_BindTokenEncryptedData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_external_type(implicit_tag, tree, tvb, offset, actx, hf_index, NULL);

  return offset;
}

/*--- PDUs ---*/

static void dissect_InternalTraceInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_InternalTraceInformation(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_InternalTraceInformation_PDU);
}
static void dissect_InternalTraceInformationElement_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_InternalTraceInformationElement(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_InternalTraceInformationElement_PDU);
}
static void dissect_TraceInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_TraceInformation(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_TraceInformation_PDU);
}
static void dissect_TraceInformationElement_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_TraceInformationElement(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_TraceInformationElement_PDU);
}
static int dissect_MTSBindArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_MTSBindArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_MTSBindArgument_PDU);
  return offset;
}
static int dissect_MTSBindResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_MTSBindResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_MTSBindResult_PDU);
  return offset;
}
static int dissect_PAR_mts_bind_error_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_PAR_mts_bind_error(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_PAR_mts_bind_error_PDU);
  return offset;
}
static int dissect_MessageSubmissionArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_MessageSubmissionArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_MessageSubmissionArgument_PDU);
  return offset;
}
static int dissect_MessageSubmissionResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_MessageSubmissionResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_MessageSubmissionResult_PDU);
  return offset;
}
static int dissect_ProbeSubmissionArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_ProbeSubmissionArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_ProbeSubmissionArgument_PDU);
  return offset;
}
static int dissect_ProbeSubmissionResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_ProbeSubmissionResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_ProbeSubmissionResult_PDU);
  return offset;
}
static int dissect_CancelDeferredDeliveryArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_CancelDeferredDeliveryArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_CancelDeferredDeliveryArgument_PDU);
  return offset;
}
static int dissect_CancelDeferredDeliveryResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_CancelDeferredDeliveryResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_CancelDeferredDeliveryResult_PDU);
  return offset;
}
static int dissect_SubmissionControlArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_SubmissionControlArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_SubmissionControlArgument_PDU);
  return offset;
}
static int dissect_SubmissionControlResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_SubmissionControlResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_SubmissionControlResult_PDU);
  return offset;
}
static int dissect_PAR_submission_control_violated_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_PAR_submission_control_violated(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_PAR_submission_control_violated_PDU);
  return offset;
}
static int dissect_PAR_element_of_service_not_subscribed_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_PAR_element_of_service_not_subscribed(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_PAR_element_of_service_not_subscribed_PDU);
  return offset;
}
static int dissect_PAR_deferred_delivery_cancellation_rejected_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_PAR_deferred_delivery_cancellation_rejected(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_PAR_deferred_delivery_cancellation_rejected_PDU);
  return offset;
}
static int dissect_PAR_originator_invalid_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_PAR_originator_invalid(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_PAR_originator_invalid_PDU);
  return offset;
}
static int dissect_ImproperlySpecifiedRecipients_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_ImproperlySpecifiedRecipients(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_ImproperlySpecifiedRecipients_PDU);
  return offset;
}
static int dissect_PAR_message_submission_identifier_invalid_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_PAR_message_submission_identifier_invalid(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_PAR_message_submission_identifier_invalid_PDU);
  return offset;
}
static int dissect_PAR_inconsistent_request_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_PAR_inconsistent_request(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_PAR_inconsistent_request_PDU);
  return offset;
}
static int dissect_SecurityProblem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_SecurityProblem(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_SecurityProblem_PDU);
  return offset;
}
static int dissect_PAR_unsupported_critical_function_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_PAR_unsupported_critical_function(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_PAR_unsupported_critical_function_PDU);
  return offset;
}
static int dissect_PAR_remote_bind_error_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_PAR_remote_bind_error(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_PAR_remote_bind_error_PDU);
  return offset;
}
static void dissect_MessageSubmissionTime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_MessageSubmissionTime(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_MessageSubmissionTime_PDU);
}
static int dissect_MessageDeliveryArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_MessageDeliveryArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_MessageDeliveryArgument_PDU);
  return offset;
}
static int dissect_MessageDeliveryResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_MessageDeliveryResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_MessageDeliveryResult_PDU);
  return offset;
}
static int dissect_ReportDeliveryArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_ReportDeliveryArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_ReportDeliveryArgument_PDU);
  return offset;
}
static int dissect_ReportDeliveryResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_ReportDeliveryResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_ReportDeliveryResult_PDU);
  return offset;
}
static int dissect_DeliveryControlArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_DeliveryControlArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_DeliveryControlArgument_PDU);
  return offset;
}
static int dissect_DeliveryControlResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_DeliveryControlResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_DeliveryControlResult_PDU);
  return offset;
}
static int dissect_PAR_delivery_control_violated_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_PAR_delivery_control_violated(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_PAR_delivery_control_violated_PDU);
  return offset;
}
static int dissect_PAR_control_violates_registration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_PAR_control_violates_registration(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_PAR_control_violates_registration_PDU);
  return offset;
}
static int dissect_RefusedOperation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_RefusedOperation(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_RefusedOperation_PDU);
  return offset;
}
static void dissect_RecipientCertificate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_RecipientCertificate(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_RecipientCertificate_PDU);
}
static void dissect_ProofOfDelivery_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_ProofOfDelivery(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_ProofOfDelivery_PDU);
}
static int dissect_RegisterArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_RegisterArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_RegisterArgument_PDU);
  return offset;
}
static int dissect_RegisterResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_RegisterResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_RegisterResult_PDU);
  return offset;
}
static int dissect_ChangeCredentialsArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_ChangeCredentialsArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_ChangeCredentialsArgument_PDU);
  return offset;
}
static int dissect_RES_change_credentials_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_RES_change_credentials(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_RES_change_credentials_PDU);
  return offset;
}
static int dissect_PAR_register_rejected_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_PAR_register_rejected(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_PAR_register_rejected_PDU);
  return offset;
}
static int dissect_PAR_new_credentials_unacceptable_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_PAR_new_credentials_unacceptable(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_PAR_new_credentials_unacceptable_PDU);
  return offset;
}
static int dissect_PAR_old_credentials_incorrectly_specified_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_p1_PAR_old_credentials_incorrectly_specified(FALSE, tvb, offset, &asn1_ctx, tree, hf_p1_PAR_old_credentials_incorrectly_specified_PDU);
  return offset;
}
static void dissect_MessageSubmissionEnvelope_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_MessageSubmissionEnvelope(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_MessageSubmissionEnvelope_PDU);
}
static void dissect_PerRecipientMessageSubmissionFields_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_PerRecipientMessageSubmissionFields(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_PerRecipientMessageSubmissionFields_PDU);
}
static void dissect_ProbeSubmissionEnvelope_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_ProbeSubmissionEnvelope(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_ProbeSubmissionEnvelope_PDU);
}
static void dissect_PerRecipientProbeSubmissionFields_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_PerRecipientProbeSubmissionFields(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_PerRecipientProbeSubmissionFields_PDU);
}
static void dissect_MessageDeliveryEnvelope_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_MessageDeliveryEnvelope(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_MessageDeliveryEnvelope_PDU);
}
static void dissect_ReportDeliveryEnvelope_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_ReportDeliveryEnvelope(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_ReportDeliveryEnvelope_PDU);
}
static void dissect_PerRecipientReportDeliveryFields_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_PerRecipientReportDeliveryFields(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_PerRecipientReportDeliveryFields_PDU);
}
static void dissect_ExtendedContentType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_ExtendedContentType(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_ExtendedContentType_PDU);
}
static void dissect_ContentIdentifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_ContentIdentifier(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_ContentIdentifier_PDU);
}
static void dissect_PerMessageIndicators_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_PerMessageIndicators(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_PerMessageIndicators_PDU);
}
static void dissect_OriginatorReportRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_OriginatorReportRequest(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_OriginatorReportRequest_PDU);
}
static void dissect_DeferredDeliveryTime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_DeferredDeliveryTime(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_DeferredDeliveryTime_PDU);
}
static void dissect_Priority_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_Priority(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_Priority_PDU);
}
static void dissect_ContentLength_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_ContentLength(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_ContentLength_PDU);
}
static void dissect_MessageDeliveryTime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_MessageDeliveryTime(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_MessageDeliveryTime_PDU);
}
static void dissect_DeliveryFlags_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_DeliveryFlags(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_DeliveryFlags_PDU);
}
static void dissect_SubjectSubmissionIdentifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_SubjectSubmissionIdentifier(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_SubjectSubmissionIdentifier_PDU);
}
static void dissect_RecipientReassignmentProhibited_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_RecipientReassignmentProhibited(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_RecipientReassignmentProhibited_PDU);
}
static void dissect_OriginatorRequestedAlternateRecipient_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_OriginatorRequestedAlternateRecipient(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_OriginatorRequestedAlternateRecipient_PDU);
}
static void dissect_DLExpansionProhibited_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_DLExpansionProhibited(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_DLExpansionProhibited_PDU);
}
static void dissect_ConversionWithLossProhibited_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_ConversionWithLossProhibited(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_ConversionWithLossProhibited_PDU);
}
static void dissect_LatestDeliveryTime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_LatestDeliveryTime(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_LatestDeliveryTime_PDU);
}
static void dissect_RequestedDeliveryMethod_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_RequestedDeliveryMethod(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_RequestedDeliveryMethod_PDU);
}
static void dissect_PhysicalForwardingProhibited_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_PhysicalForwardingProhibited(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_PhysicalForwardingProhibited_PDU);
}
static void dissect_PhysicalForwardingAddressRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_PhysicalForwardingAddressRequest(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_PhysicalForwardingAddressRequest_PDU);
}
static void dissect_PhysicalDeliveryModes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_PhysicalDeliveryModes(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_PhysicalDeliveryModes_PDU);
}
static void dissect_RegisteredMailType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_RegisteredMailType(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_RegisteredMailType_PDU);
}
static void dissect_RecipientNumberForAdvice_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_RecipientNumberForAdvice(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_RecipientNumberForAdvice_PDU);
}
static void dissect_PhysicalRenditionAttributes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_PhysicalRenditionAttributes(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_PhysicalRenditionAttributes_PDU);
}
static void dissect_OriginatorReturnAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_OriginatorReturnAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_OriginatorReturnAddress_PDU);
}
static void dissect_PhysicalDeliveryReportRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_PhysicalDeliveryReportRequest(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_PhysicalDeliveryReportRequest_PDU);
}
static void dissect_OriginatorCertificate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_OriginatorCertificate(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_OriginatorCertificate_PDU);
}
static void dissect_MessageToken_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_MessageToken(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_MessageToken_PDU);
}
static void dissect_ContentConfidentialityAlgorithmIdentifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_ContentConfidentialityAlgorithmIdentifier(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_ContentConfidentialityAlgorithmIdentifier_PDU);
}
static void dissect_ContentIntegrityCheck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_ContentIntegrityCheck(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_ContentIntegrityCheck_PDU);
}
static void dissect_MessageOriginAuthenticationCheck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_MessageOriginAuthenticationCheck(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_MessageOriginAuthenticationCheck_PDU);
}
static void dissect_MessageSecurityLabel_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_MessageSecurityLabel(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_MessageSecurityLabel_PDU);
}
static void dissect_ProofOfSubmissionRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_ProofOfSubmissionRequest(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_ProofOfSubmissionRequest_PDU);
}
static void dissect_ProofOfDeliveryRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_ProofOfDeliveryRequest(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_ProofOfDeliveryRequest_PDU);
}
static void dissect_ContentCorrelator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_ContentCorrelator(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_ContentCorrelator_PDU);
}
static void dissect_ProbeOriginAuthenticationCheck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_ProbeOriginAuthenticationCheck(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_ProbeOriginAuthenticationCheck_PDU);
}
static void dissect_RedirectionHistory_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_RedirectionHistory(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_RedirectionHistory_PDU);
}
static void dissect_Redirection_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_Redirection(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_Redirection_PDU);
}
static void dissect_DLExpansionHistory_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_DLExpansionHistory(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_DLExpansionHistory_PDU);
}
static void dissect_DLExpansion_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_DLExpansion(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_DLExpansion_PDU);
}
static void dissect_PhysicalForwardingAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_PhysicalForwardingAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_PhysicalForwardingAddress_PDU);
}
static void dissect_OriginatorAndDLExpansionHistory_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_OriginatorAndDLExpansionHistory(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_OriginatorAndDLExpansionHistory_PDU);
}
static void dissect_ReportingDLName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_ReportingDLName(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_ReportingDLName_PDU);
}
static void dissect_ReportingMTACertificate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_ReportingMTACertificate(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_ReportingMTACertificate_PDU);
}
static void dissect_ReportOriginAuthenticationCheck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_ReportOriginAuthenticationCheck(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_ReportOriginAuthenticationCheck_PDU);
}
static void dissect_OriginatingMTACertificate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_OriginatingMTACertificate(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_OriginatingMTACertificate_PDU);
}
static void dissect_ProofOfSubmission_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_ProofOfSubmission(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_ProofOfSubmission_PDU);
}
static void dissect_ReportingMTAName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_ReportingMTAName(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_ReportingMTAName_PDU);
}
static void dissect_ExtendedCertificates_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_ExtendedCertificates(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_ExtendedCertificates_PDU);
}
static void dissect_DLExemptedRecipients_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_DLExemptedRecipients(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_DLExemptedRecipients_PDU);
}
static void dissect_CertificateSelectors_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_CertificateSelectors(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_CertificateSelectors_PDU);
}
static void dissect_Content_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_Content(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_Content_PDU);
}
static void dissect_MTSIdentifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_MTSIdentifier(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_MTSIdentifier_PDU);
}
static void dissect_ORName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_ORName(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_ORName_PDU);
}
static void dissect_ORAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_ORAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_ORAddress_PDU);
}
static void dissect_CommonName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_CommonName(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_CommonName_PDU);
}
static void dissect_TeletexCommonName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_TeletexCommonName(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_TeletexCommonName_PDU);
}
static void dissect_UniversalCommonName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_UniversalCommonName(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_UniversalCommonName_PDU);
}
static void dissect_TeletexOrganizationName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_TeletexOrganizationName(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_TeletexOrganizationName_PDU);
}
static void dissect_UniversalOrganizationName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_UniversalOrganizationName(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_UniversalOrganizationName_PDU);
}
static void dissect_TeletexPersonalName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_TeletexPersonalName(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_TeletexPersonalName_PDU);
}
static void dissect_UniversalPersonalName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_UniversalPersonalName(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_UniversalPersonalName_PDU);
}
static void dissect_TeletexOrganizationalUnitNames_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_TeletexOrganizationalUnitNames(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_TeletexOrganizationalUnitNames_PDU);
}
static void dissect_UniversalOrganizationalUnitNames_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_UniversalOrganizationalUnitNames(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_UniversalOrganizationalUnitNames_PDU);
}
static void dissect_PDSName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_PDSName(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_PDSName_PDU);
}
static void dissect_PhysicalDeliveryCountryName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_PhysicalDeliveryCountryName(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_PhysicalDeliveryCountryName_PDU);
}
static void dissect_PostalCode_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_PostalCode(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_PostalCode_PDU);
}
static void dissect_PhysicalDeliveryOfficeName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_PhysicalDeliveryOfficeName(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_PhysicalDeliveryOfficeName_PDU);
}
static void dissect_UniversalPhysicalDeliveryOfficeName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_UniversalPhysicalDeliveryOfficeName(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_UniversalPhysicalDeliveryOfficeName_PDU);
}
static void dissect_PhysicalDeliveryOfficeNumber_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_PhysicalDeliveryOfficeNumber(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_PhysicalDeliveryOfficeNumber_PDU);
}
static void dissect_UniversalPhysicalDeliveryOfficeNumber_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_UniversalPhysicalDeliveryOfficeNumber(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_UniversalPhysicalDeliveryOfficeNumber_PDU);
}
static void dissect_ExtensionORAddressComponents_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_ExtensionORAddressComponents(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_ExtensionORAddressComponents_PDU);
}
static void dissect_UniversalExtensionORAddressComponents_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_UniversalExtensionORAddressComponents(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_UniversalExtensionORAddressComponents_PDU);
}
static void dissect_PhysicalDeliveryPersonalName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_PhysicalDeliveryPersonalName(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_PhysicalDeliveryPersonalName_PDU);
}
static void dissect_UniversalPhysicalDeliveryPersonalName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_UniversalPhysicalDeliveryPersonalName(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_UniversalPhysicalDeliveryPersonalName_PDU);
}
static void dissect_PhysicalDeliveryOrganizationName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_PhysicalDeliveryOrganizationName(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_PhysicalDeliveryOrganizationName_PDU);
}
static void dissect_UniversalPhysicalDeliveryOrganizationName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_UniversalPhysicalDeliveryOrganizationName(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_UniversalPhysicalDeliveryOrganizationName_PDU);
}
static void dissect_ExtensionPhysicalDeliveryAddressComponents_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_ExtensionPhysicalDeliveryAddressComponents(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_ExtensionPhysicalDeliveryAddressComponents_PDU);
}
static void dissect_UniversalExtensionPhysicalDeliveryAddressComponents_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_UniversalExtensionPhysicalDeliveryAddressComponents(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_UniversalExtensionPhysicalDeliveryAddressComponents_PDU);
}
static void dissect_UnformattedPostalAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_UnformattedPostalAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_UnformattedPostalAddress_PDU);
}
static void dissect_UniversalUnformattedPostalAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_UniversalUnformattedPostalAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_UniversalUnformattedPostalAddress_PDU);
}
static void dissect_StreetAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_StreetAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_StreetAddress_PDU);
}
static void dissect_UniversalStreetAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_UniversalStreetAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_UniversalStreetAddress_PDU);
}
static void dissect_PostOfficeBoxAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_PostOfficeBoxAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_PostOfficeBoxAddress_PDU);
}
static void dissect_UniversalPostOfficeBoxAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_UniversalPostOfficeBoxAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_UniversalPostOfficeBoxAddress_PDU);
}
static void dissect_PosteRestanteAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_PosteRestanteAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_PosteRestanteAddress_PDU);
}
static void dissect_UniversalPosteRestanteAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_UniversalPosteRestanteAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_UniversalPosteRestanteAddress_PDU);
}
static void dissect_UniquePostalName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_UniquePostalName(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_UniquePostalName_PDU);
}
static void dissect_UniversalUniquePostalName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_UniversalUniquePostalName(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_UniversalUniquePostalName_PDU);
}
static void dissect_LocalPostalAttributes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_LocalPostalAttributes(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_LocalPostalAttributes_PDU);
}
static void dissect_UniversalLocalPostalAttributes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_UniversalLocalPostalAttributes(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_UniversalLocalPostalAttributes_PDU);
}
static void dissect_ExtendedNetworkAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_ExtendedNetworkAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_ExtendedNetworkAddress_PDU);
}
static void dissect_TerminalType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_TerminalType(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_TerminalType_PDU);
}
static void dissect_TeletexDomainDefinedAttributes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_TeletexDomainDefinedAttributes(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_TeletexDomainDefinedAttributes_PDU);
}
static void dissect_UniversalDomainDefinedAttributes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_UniversalDomainDefinedAttributes(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_UniversalDomainDefinedAttributes_PDU);
}
static void dissect_ExtendedEncodedInformationType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_ExtendedEncodedInformationType(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_ExtendedEncodedInformationType_PDU);
}
static void dissect_MTANameAndOptionalGDI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_MTANameAndOptionalGDI(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_MTANameAndOptionalGDI_PDU);
}
static void dissect_AsymmetricToken_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_AsymmetricToken(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_AsymmetricToken_PDU);
}
static void dissect_BindTokenSignedData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_BindTokenSignedData(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_BindTokenSignedData_PDU);
}
static void dissect_MessageTokenSignedData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_MessageTokenSignedData(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_MessageTokenSignedData_PDU);
}
static void dissect_MessageTokenEncryptedData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_MessageTokenEncryptedData(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_MessageTokenEncryptedData_PDU);
}
static void dissect_BindTokenEncryptedData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_BindTokenEncryptedData(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_BindTokenEncryptedData_PDU);
}
static void dissect_SecurityClassification_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_p1_SecurityClassification(FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_SecurityClassification_PDU);
}


/*--- End of included file: packet-p1-fn.c ---*/
#line 103 "../../asn1/p1/packet-p1-template.c"


/*--- Included file: packet-p1-table11.c ---*/
#line 1 "../../asn1/p1/packet-p1-table11.c"

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


/*--- End of included file: packet-p1-table11.c ---*/
#line 105 "../../asn1/p1/packet-p1-template.c"

/*--- Included file: packet-p1-table21.c ---*/
#line 1 "../../asn1/p1/packet-p1-table21.c"

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


/*--- End of included file: packet-p1-table21.c ---*/
#line 106 "../../asn1/p1/packet-p1-template.c"

static const ros_info_t p3_ros_info = {
  "P3",
  &proto_p3,
  &ett_p3,
  p3_opr_code_string_vals,
  p3_opr_tab,
  p3_err_code_string_vals,
  p3_err_tab
};

void p1_initialize_content_globals (proto_tree *tree, gboolean report_unknown_cont_type)
{
	top_tree = tree;
	content_type_id = NULL;
	report_unknown_content_type = report_unknown_cont_type;
}

char* p1_get_last_oraddress (void) 
{ 
	return oraddress;
}

/*
 * Dissect P1 MTS APDU
 */
void
dissect_p1_mts_apdu (tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	/* save parent_tree so subdissectors can create new top nodes */
	p1_initialize_content_globals (parent_tree, TRUE);

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_p1, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_p1);
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "P1");
  	col_set_str(pinfo->cinfo, COL_INFO, "Transfer");

	dissect_p1_MTS_APDU (FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_MTS_APDU_PDU);
	p1_initialize_content_globals (NULL, FALSE);
}

/*
* Dissect P1 PDUs inside a PPDU.
*/
static void
dissect_p1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	int old_offset;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int (*p1_dissector)(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_) = NULL;
	char *p1_op_name;
	int hf_p1_index = -1;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	/* save parent_tree so subdissectors can create new top nodes */
	p1_initialize_content_globals (parent_tree, TRUE);

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
		item = proto_tree_add_item(parent_tree, proto_p1, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_p1);
	}
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "P1");
  	col_clear(pinfo->cinfo, COL_INFO);

	switch(session->ros_op & ROS_OP_MASK) {
	case (ROS_OP_BIND | ROS_OP_ARGUMENT):	/*  BindInvoke */
	  p1_dissector = dissect_p1_MTABindArgument;
	  p1_op_name = "Bind-Argument";
	  hf_p1_index = hf_p1_MTABindArgument_PDU;
	  break;
	case (ROS_OP_BIND | ROS_OP_RESULT):	/*  BindResult */
	  p1_dissector = dissect_p1_MTABindResult;
	  p1_op_name = "Bind-Result";
	  hf_p1_index = hf_p1_MTABindResult_PDU;
	  break;
	case (ROS_OP_BIND | ROS_OP_ERROR):	/*  BindError */
	  p1_dissector = dissect_p1_MTABindError;
	  p1_op_name = "Bind-Error";
	  hf_p1_index = hf_p1_MTABindError_PDU;
	  break;
	case (ROS_OP_INVOKE | ROS_OP_ARGUMENT):	/*  Invoke Argument */
	  p1_dissector = dissect_p1_MTS_APDU;
	  p1_op_name = "Transfer";
	  hf_p1_index = hf_p1_MTS_APDU_PDU;
	  break;
	default:
	  proto_tree_add_text(tree, tvb, offset, -1,"Unsupported P1 PDU");
	  return;
	}

	if (check_col(pinfo->cinfo, COL_INFO))
	  col_set_str(pinfo->cinfo, COL_INFO, p1_op_name);

	while (tvb_reported_length_remaining(tvb, offset) > 0){
		old_offset=offset;
		offset=(*p1_dissector)(FALSE, tvb, offset, &asn1_ctx , tree, hf_p1_index);
		if(offset == old_offset){
			proto_tree_add_text(tree, tvb, offset, -1,"Internal error, zero-byte P1 PDU");
			offset = tvb_length(tvb);
			break;
		}
	}
	p1_initialize_content_globals (NULL, FALSE);
}


/*--- proto_register_p1 -------------------------------------------*/
void proto_register_p1(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
	  /* "Created by defining PDU in .cnf */
    { &hf_p1_MTABindArgument_PDU,
      { "MTABindArgument", "p1.MTABindArgument",
        FT_UINT32, BASE_DEC, VALS(p1_MTABindArgument_vals), 0,
        "p1.MTABindArgument", HFILL }},
    { &hf_p1_MTABindResult_PDU,
      { "MTABindResult", "p1.MTABindResult",
        FT_UINT32, BASE_DEC, VALS(p1_MTABindResult_vals), 0,
        "p1.MTABindResult", HFILL }},
    { &hf_p1_MTABindError_PDU,
      { "MTABindError", "p1.MTABindError",
        FT_UINT32, BASE_DEC, VALS(p1_MTABindError_vals), 0,
        "p1.MTABindError", HFILL }},
    { &hf_p1_MTS_APDU_PDU,
      { "MTS-APDU", "p1.MTS_APDU",
        FT_UINT32, BASE_DEC, VALS(p1_MTS_APDU_vals), 0,
        "p1.MTS_APDU", HFILL }},


/*--- Included file: packet-p1-hfarr.c ---*/
#line 1 "../../asn1/p1/packet-p1-hfarr.c"
    { &hf_p1_InternalTraceInformation_PDU,
      { "InternalTraceInformation", "p1.InternalTraceInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_InternalTraceInformationElement_PDU,
      { "InternalTraceInformationElement", "p1.InternalTraceInformationElement",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_TraceInformation_PDU,
      { "TraceInformation", "p1.TraceInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_TraceInformationElement_PDU,
      { "TraceInformationElement", "p1.TraceInformationElement",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_MTSBindArgument_PDU,
      { "MTSBindArgument", "p1.MTSBindArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_MTSBindResult_PDU,
      { "MTSBindResult", "p1.MTSBindResult",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PAR_mts_bind_error_PDU,
      { "PAR-mts-bind-error", "p1.PAR_mts_bind_error",
        FT_UINT32, BASE_DEC, VALS(p1_PAR_mts_bind_error_vals), 0,
        NULL, HFILL }},
    { &hf_p1_MessageSubmissionArgument_PDU,
      { "MessageSubmissionArgument", "p1.MessageSubmissionArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_MessageSubmissionResult_PDU,
      { "MessageSubmissionResult", "p1.MessageSubmissionResult",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_ProbeSubmissionArgument_PDU,
      { "ProbeSubmissionArgument", "p1.ProbeSubmissionArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_ProbeSubmissionResult_PDU,
      { "ProbeSubmissionResult", "p1.ProbeSubmissionResult",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_CancelDeferredDeliveryArgument_PDU,
      { "CancelDeferredDeliveryArgument", "p1.CancelDeferredDeliveryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_CancelDeferredDeliveryResult_PDU,
      { "CancelDeferredDeliveryResult", "p1.CancelDeferredDeliveryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_SubmissionControlArgument_PDU,
      { "SubmissionControlArgument", "p1.SubmissionControlArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_SubmissionControlResult_PDU,
      { "SubmissionControlResult", "p1.SubmissionControlResult",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PAR_submission_control_violated_PDU,
      { "PAR-submission-control-violated", "p1.PAR_submission_control_violated",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PAR_element_of_service_not_subscribed_PDU,
      { "PAR-element-of-service-not-subscribed", "p1.PAR_element_of_service_not_subscribed",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PAR_deferred_delivery_cancellation_rejected_PDU,
      { "PAR-deferred-delivery-cancellation-rejected", "p1.PAR_deferred_delivery_cancellation_rejected",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PAR_originator_invalid_PDU,
      { "PAR-originator-invalid", "p1.PAR_originator_invalid",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_ImproperlySpecifiedRecipients_PDU,
      { "ImproperlySpecifiedRecipients", "p1.ImproperlySpecifiedRecipients",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PAR_message_submission_identifier_invalid_PDU,
      { "PAR-message-submission-identifier-invalid", "p1.PAR_message_submission_identifier_invalid",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PAR_inconsistent_request_PDU,
      { "PAR-inconsistent-request", "p1.PAR_inconsistent_request",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_SecurityProblem_PDU,
      { "SecurityProblem", "p1.SecurityProblem",
        FT_UINT32, BASE_DEC, VALS(p1_SecurityProblem_vals), 0,
        NULL, HFILL }},
    { &hf_p1_PAR_unsupported_critical_function_PDU,
      { "PAR-unsupported-critical-function", "p1.PAR_unsupported_critical_function",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PAR_remote_bind_error_PDU,
      { "PAR-remote-bind-error", "p1.PAR_remote_bind_error",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_MessageSubmissionTime_PDU,
      { "MessageSubmissionTime", "p1.MessageSubmissionTime",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_MessageDeliveryArgument_PDU,
      { "MessageDeliveryArgument", "p1.MessageDeliveryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_MessageDeliveryResult_PDU,
      { "MessageDeliveryResult", "p1.MessageDeliveryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_ReportDeliveryArgument_PDU,
      { "ReportDeliveryArgument", "p1.ReportDeliveryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_ReportDeliveryResult_PDU,
      { "ReportDeliveryResult", "p1.ReportDeliveryResult",
        FT_UINT32, BASE_DEC, VALS(p1_ReportDeliveryResult_vals), 0,
        NULL, HFILL }},
    { &hf_p1_DeliveryControlArgument_PDU,
      { "DeliveryControlArgument", "p1.DeliveryControlArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_DeliveryControlResult_PDU,
      { "DeliveryControlResult", "p1.DeliveryControlResult",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PAR_delivery_control_violated_PDU,
      { "PAR-delivery-control-violated", "p1.PAR_delivery_control_violated",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PAR_control_violates_registration_PDU,
      { "PAR-control-violates-registration", "p1.PAR_control_violates_registration",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_RefusedOperation_PDU,
      { "RefusedOperation", "p1.RefusedOperation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_RecipientCertificate_PDU,
      { "RecipientCertificate", "p1.RecipientCertificate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_ProofOfDelivery_PDU,
      { "ProofOfDelivery", "p1.ProofOfDelivery",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_RegisterArgument_PDU,
      { "RegisterArgument", "p1.RegisterArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_RegisterResult_PDU,
      { "RegisterResult", "p1.RegisterResult",
        FT_UINT32, BASE_DEC, VALS(p1_RegisterResult_vals), 0,
        NULL, HFILL }},
    { &hf_p1_ChangeCredentialsArgument_PDU,
      { "ChangeCredentialsArgument", "p1.ChangeCredentialsArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_RES_change_credentials_PDU,
      { "RES-change-credentials", "p1.RES_change_credentials",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PAR_register_rejected_PDU,
      { "PAR-register-rejected", "p1.PAR_register_rejected",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PAR_new_credentials_unacceptable_PDU,
      { "PAR-new-credentials-unacceptable", "p1.PAR_new_credentials_unacceptable",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PAR_old_credentials_incorrectly_specified_PDU,
      { "PAR-old-credentials-incorrectly-specified", "p1.PAR_old_credentials_incorrectly_specified",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_MessageSubmissionEnvelope_PDU,
      { "MessageSubmissionEnvelope", "p1.MessageSubmissionEnvelope",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PerRecipientMessageSubmissionFields_PDU,
      { "PerRecipientMessageSubmissionFields", "p1.PerRecipientMessageSubmissionFields",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_ProbeSubmissionEnvelope_PDU,
      { "ProbeSubmissionEnvelope", "p1.ProbeSubmissionEnvelope",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PerRecipientProbeSubmissionFields_PDU,
      { "PerRecipientProbeSubmissionFields", "p1.PerRecipientProbeSubmissionFields",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_MessageDeliveryEnvelope_PDU,
      { "MessageDeliveryEnvelope", "p1.MessageDeliveryEnvelope",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_ReportDeliveryEnvelope_PDU,
      { "ReportDeliveryEnvelope", "p1.ReportDeliveryEnvelope",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PerRecipientReportDeliveryFields_PDU,
      { "PerRecipientReportDeliveryFields", "p1.PerRecipientReportDeliveryFields",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_ExtendedContentType_PDU,
      { "ExtendedContentType", "p1.ExtendedContentType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_ContentIdentifier_PDU,
      { "ContentIdentifier", "p1.ContentIdentifier",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PerMessageIndicators_PDU,
      { "PerMessageIndicators", "p1.PerMessageIndicators",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_OriginatorReportRequest_PDU,
      { "OriginatorReportRequest", "p1.OriginatorReportRequest",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_DeferredDeliveryTime_PDU,
      { "DeferredDeliveryTime", "p1.DeferredDeliveryTime",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_Priority_PDU,
      { "Priority", "p1.Priority",
        FT_UINT32, BASE_DEC, VALS(p1_Priority_U_vals), 0,
        NULL, HFILL }},
    { &hf_p1_ContentLength_PDU,
      { "ContentLength", "p1.ContentLength",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_MessageDeliveryTime_PDU,
      { "MessageDeliveryTime", "p1.MessageDeliveryTime",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_DeliveryFlags_PDU,
      { "DeliveryFlags", "p1.DeliveryFlags",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_SubjectSubmissionIdentifier_PDU,
      { "SubjectSubmissionIdentifier", "p1.SubjectSubmissionIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_RecipientReassignmentProhibited_PDU,
      { "RecipientReassignmentProhibited", "p1.RecipientReassignmentProhibited",
        FT_UINT32, BASE_DEC, VALS(p1_RecipientReassignmentProhibited_vals), 0,
        NULL, HFILL }},
    { &hf_p1_OriginatorRequestedAlternateRecipient_PDU,
      { "OriginatorRequestedAlternateRecipient", "p1.OriginatorRequestedAlternateRecipient",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_DLExpansionProhibited_PDU,
      { "DLExpansionProhibited", "p1.DLExpansionProhibited",
        FT_UINT32, BASE_DEC, VALS(p1_DLExpansionProhibited_vals), 0,
        NULL, HFILL }},
    { &hf_p1_ConversionWithLossProhibited_PDU,
      { "ConversionWithLossProhibited", "p1.ConversionWithLossProhibited",
        FT_UINT32, BASE_DEC, VALS(p1_ConversionWithLossProhibited_vals), 0,
        NULL, HFILL }},
    { &hf_p1_LatestDeliveryTime_PDU,
      { "LatestDeliveryTime", "p1.LatestDeliveryTime",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_RequestedDeliveryMethod_PDU,
      { "RequestedDeliveryMethod", "p1.RequestedDeliveryMethod",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PhysicalForwardingProhibited_PDU,
      { "PhysicalForwardingProhibited", "p1.PhysicalForwardingProhibited",
        FT_UINT32, BASE_DEC, VALS(p1_PhysicalForwardingProhibited_vals), 0,
        NULL, HFILL }},
    { &hf_p1_PhysicalForwardingAddressRequest_PDU,
      { "PhysicalForwardingAddressRequest", "p1.PhysicalForwardingAddressRequest",
        FT_UINT32, BASE_DEC, VALS(p1_PhysicalForwardingAddressRequest_vals), 0,
        NULL, HFILL }},
    { &hf_p1_PhysicalDeliveryModes_PDU,
      { "PhysicalDeliveryModes", "p1.PhysicalDeliveryModes",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_RegisteredMailType_PDU,
      { "RegisteredMailType", "p1.RegisteredMailType",
        FT_UINT32, BASE_DEC, VALS(p1_RegisteredMailType_vals), 0,
        NULL, HFILL }},
    { &hf_p1_RecipientNumberForAdvice_PDU,
      { "RecipientNumberForAdvice", "p1.RecipientNumberForAdvice",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PhysicalRenditionAttributes_PDU,
      { "PhysicalRenditionAttributes", "p1.PhysicalRenditionAttributes",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_OriginatorReturnAddress_PDU,
      { "OriginatorReturnAddress", "p1.OriginatorReturnAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PhysicalDeliveryReportRequest_PDU,
      { "PhysicalDeliveryReportRequest", "p1.PhysicalDeliveryReportRequest",
        FT_UINT32, BASE_DEC, VALS(p1_PhysicalDeliveryReportRequest_vals), 0,
        NULL, HFILL }},
    { &hf_p1_OriginatorCertificate_PDU,
      { "OriginatorCertificate", "p1.OriginatorCertificate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_MessageToken_PDU,
      { "MessageToken", "p1.MessageToken",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_ContentConfidentialityAlgorithmIdentifier_PDU,
      { "ContentConfidentialityAlgorithmIdentifier", "p1.ContentConfidentialityAlgorithmIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_ContentIntegrityCheck_PDU,
      { "ContentIntegrityCheck", "p1.ContentIntegrityCheck",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_MessageOriginAuthenticationCheck_PDU,
      { "MessageOriginAuthenticationCheck", "p1.MessageOriginAuthenticationCheck",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_MessageSecurityLabel_PDU,
      { "MessageSecurityLabel", "p1.MessageSecurityLabel",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_ProofOfSubmissionRequest_PDU,
      { "ProofOfSubmissionRequest", "p1.ProofOfSubmissionRequest",
        FT_UINT32, BASE_DEC, VALS(p1_ProofOfSubmissionRequest_vals), 0,
        NULL, HFILL }},
    { &hf_p1_ProofOfDeliveryRequest_PDU,
      { "ProofOfDeliveryRequest", "p1.ProofOfDeliveryRequest",
        FT_UINT32, BASE_DEC, VALS(p1_ProofOfDeliveryRequest_vals), 0,
        NULL, HFILL }},
    { &hf_p1_ContentCorrelator_PDU,
      { "ContentCorrelator", "p1.ContentCorrelator",
        FT_UINT32, BASE_DEC, VALS(p1_ContentCorrelator_vals), 0,
        NULL, HFILL }},
    { &hf_p1_ProbeOriginAuthenticationCheck_PDU,
      { "ProbeOriginAuthenticationCheck", "p1.ProbeOriginAuthenticationCheck",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_RedirectionHistory_PDU,
      { "RedirectionHistory", "p1.RedirectionHistory",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_Redirection_PDU,
      { "Redirection", "p1.Redirection",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_DLExpansionHistory_PDU,
      { "DLExpansionHistory", "p1.DLExpansionHistory",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_DLExpansion_PDU,
      { "DLExpansion", "p1.DLExpansion",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PhysicalForwardingAddress_PDU,
      { "PhysicalForwardingAddress", "p1.PhysicalForwardingAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_OriginatorAndDLExpansionHistory_PDU,
      { "OriginatorAndDLExpansionHistory", "p1.OriginatorAndDLExpansionHistory",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_ReportingDLName_PDU,
      { "ReportingDLName", "p1.ReportingDLName",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_ReportingMTACertificate_PDU,
      { "ReportingMTACertificate", "p1.ReportingMTACertificate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_ReportOriginAuthenticationCheck_PDU,
      { "ReportOriginAuthenticationCheck", "p1.ReportOriginAuthenticationCheck",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_OriginatingMTACertificate_PDU,
      { "OriginatingMTACertificate", "p1.OriginatingMTACertificate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_ProofOfSubmission_PDU,
      { "ProofOfSubmission", "p1.ProofOfSubmission",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_ReportingMTAName_PDU,
      { "ReportingMTAName", "p1.ReportingMTAName",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_ExtendedCertificates_PDU,
      { "ExtendedCertificates", "p1.ExtendedCertificates",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_DLExemptedRecipients_PDU,
      { "DLExemptedRecipients", "p1.DLExemptedRecipients",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_CertificateSelectors_PDU,
      { "CertificateSelectors", "p1.CertificateSelectors",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_Content_PDU,
      { "Content", "p1.Content",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_MTSIdentifier_PDU,
      { "MTSIdentifier", "p1.MTSIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_ORName_PDU,
      { "ORName", "p1.ORName",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_ORAddress_PDU,
      { "ORAddress", "p1.ORAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_CommonName_PDU,
      { "CommonName", "p1.CommonName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_TeletexCommonName_PDU,
      { "TeletexCommonName", "p1.TeletexCommonName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_UniversalCommonName_PDU,
      { "UniversalCommonName", "p1.UniversalCommonName",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_TeletexOrganizationName_PDU,
      { "TeletexOrganizationName", "p1.TeletexOrganizationName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_UniversalOrganizationName_PDU,
      { "UniversalOrganizationName", "p1.UniversalOrganizationName",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_TeletexPersonalName_PDU,
      { "TeletexPersonalName", "p1.TeletexPersonalName",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_UniversalPersonalName_PDU,
      { "UniversalPersonalName", "p1.UniversalPersonalName",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_TeletexOrganizationalUnitNames_PDU,
      { "TeletexOrganizationalUnitNames", "p1.TeletexOrganizationalUnitNames",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_UniversalOrganizationalUnitNames_PDU,
      { "UniversalOrganizationalUnitNames", "p1.UniversalOrganizationalUnitNames",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PDSName_PDU,
      { "PDSName", "p1.PDSName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PhysicalDeliveryCountryName_PDU,
      { "PhysicalDeliveryCountryName", "p1.PhysicalDeliveryCountryName",
        FT_UINT32, BASE_DEC, VALS(p1_PhysicalDeliveryCountryName_vals), 0,
        NULL, HFILL }},
    { &hf_p1_PostalCode_PDU,
      { "PostalCode", "p1.PostalCode",
        FT_UINT32, BASE_DEC, VALS(p1_PostalCode_vals), 0,
        NULL, HFILL }},
    { &hf_p1_PhysicalDeliveryOfficeName_PDU,
      { "PhysicalDeliveryOfficeName", "p1.PhysicalDeliveryOfficeName",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_UniversalPhysicalDeliveryOfficeName_PDU,
      { "UniversalPhysicalDeliveryOfficeName", "p1.UniversalPhysicalDeliveryOfficeName",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PhysicalDeliveryOfficeNumber_PDU,
      { "PhysicalDeliveryOfficeNumber", "p1.PhysicalDeliveryOfficeNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_UniversalPhysicalDeliveryOfficeNumber_PDU,
      { "UniversalPhysicalDeliveryOfficeNumber", "p1.UniversalPhysicalDeliveryOfficeNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_ExtensionORAddressComponents_PDU,
      { "ExtensionORAddressComponents", "p1.ExtensionORAddressComponents",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_UniversalExtensionORAddressComponents_PDU,
      { "UniversalExtensionORAddressComponents", "p1.UniversalExtensionORAddressComponents",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PhysicalDeliveryPersonalName_PDU,
      { "PhysicalDeliveryPersonalName", "p1.PhysicalDeliveryPersonalName",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_UniversalPhysicalDeliveryPersonalName_PDU,
      { "UniversalPhysicalDeliveryPersonalName", "p1.UniversalPhysicalDeliveryPersonalName",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PhysicalDeliveryOrganizationName_PDU,
      { "PhysicalDeliveryOrganizationName", "p1.PhysicalDeliveryOrganizationName",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_UniversalPhysicalDeliveryOrganizationName_PDU,
      { "UniversalPhysicalDeliveryOrganizationName", "p1.UniversalPhysicalDeliveryOrganizationName",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_ExtensionPhysicalDeliveryAddressComponents_PDU,
      { "ExtensionPhysicalDeliveryAddressComponents", "p1.ExtensionPhysicalDeliveryAddressComponents",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_UniversalExtensionPhysicalDeliveryAddressComponents_PDU,
      { "UniversalExtensionPhysicalDeliveryAddressComponents", "p1.UniversalExtensionPhysicalDeliveryAddressComponents",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_UnformattedPostalAddress_PDU,
      { "UnformattedPostalAddress", "p1.UnformattedPostalAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_UniversalUnformattedPostalAddress_PDU,
      { "UniversalUnformattedPostalAddress", "p1.UniversalUnformattedPostalAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_StreetAddress_PDU,
      { "StreetAddress", "p1.StreetAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_UniversalStreetAddress_PDU,
      { "UniversalStreetAddress", "p1.UniversalStreetAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PostOfficeBoxAddress_PDU,
      { "PostOfficeBoxAddress", "p1.PostOfficeBoxAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_UniversalPostOfficeBoxAddress_PDU,
      { "UniversalPostOfficeBoxAddress", "p1.UniversalPostOfficeBoxAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_PosteRestanteAddress_PDU,
      { "PosteRestanteAddress", "p1.PosteRestanteAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_UniversalPosteRestanteAddress_PDU,
      { "UniversalPosteRestanteAddress", "p1.UniversalPosteRestanteAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_UniquePostalName_PDU,
      { "UniquePostalName", "p1.UniquePostalName",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_UniversalUniquePostalName_PDU,
      { "UniversalUniquePostalName", "p1.UniversalUniquePostalName",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_LocalPostalAttributes_PDU,
      { "LocalPostalAttributes", "p1.LocalPostalAttributes",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_UniversalLocalPostalAttributes_PDU,
      { "UniversalLocalPostalAttributes", "p1.UniversalLocalPostalAttributes",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_ExtendedNetworkAddress_PDU,
      { "ExtendedNetworkAddress", "p1.ExtendedNetworkAddress",
        FT_UINT32, BASE_DEC, VALS(p1_ExtendedNetworkAddress_vals), 0,
        NULL, HFILL }},
    { &hf_p1_TerminalType_PDU,
      { "TerminalType", "p1.TerminalType",
        FT_UINT32, BASE_DEC, VALS(p1_TerminalType_vals), 0,
        NULL, HFILL }},
    { &hf_p1_TeletexDomainDefinedAttributes_PDU,
      { "TeletexDomainDefinedAttributes", "p1.TeletexDomainDefinedAttributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_UniversalDomainDefinedAttributes_PDU,
      { "UniversalDomainDefinedAttributes", "p1.UniversalDomainDefinedAttributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_ExtendedEncodedInformationType_PDU,
      { "ExtendedEncodedInformationType", "p1.ExtendedEncodedInformationType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_MTANameAndOptionalGDI_PDU,
      { "MTANameAndOptionalGDI", "p1.MTANameAndOptionalGDI",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_AsymmetricToken_PDU,
      { "AsymmetricToken", "p1.AsymmetricToken",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_BindTokenSignedData_PDU,
      { "BindTokenSignedData", "p1.BindTokenSignedData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_MessageTokenSignedData_PDU,
      { "MessageTokenSignedData", "p1.MessageTokenSignedData",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_MessageTokenEncryptedData_PDU,
      { "MessageTokenEncryptedData", "p1.MessageTokenEncryptedData",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_BindTokenEncryptedData_PDU,
      { "BindTokenEncryptedData", "p1.BindTokenEncryptedData",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_SecurityClassification_PDU,
      { "SecurityClassification", "p1.SecurityClassification",
        FT_UINT32, BASE_DEC, VALS(p1_SecurityClassification_vals), 0,
        NULL, HFILL }},
    { &hf_p1_unauthenticated,
      { "unauthenticated", "p1.unauthenticated",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_authenticated_argument,
      { "authenticated", "p1.authenticated",
        FT_NONE, BASE_NONE, NULL, 0,
        "AuthenticatedArgument", HFILL }},
    { &hf_p1_authenticated_initiator_name,
      { "initiator-name", "p1.initiator_name",
        FT_STRING, BASE_NONE, NULL, 0,
        "MTAName", HFILL }},
    { &hf_p1_initiator_credentials,
      { "initiator-credentials", "p1.initiator_credentials",
        FT_UINT32, BASE_DEC, VALS(p1_Credentials_vals), 0,
        "InitiatorCredentials", HFILL }},
    { &hf_p1_security_context,
      { "security-context", "p1.security_context",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SecurityContext", HFILL }},
    { &hf_p1_authenticated_result,
      { "authenticated", "p1.authenticated",
        FT_NONE, BASE_NONE, NULL, 0,
        "AuthenticatedResult", HFILL }},
    { &hf_p1_authenticated_responder_name,
      { "responder-name", "p1.responder_name",
        FT_STRING, BASE_NONE, NULL, 0,
        "MTAName", HFILL }},
    { &hf_p1_responder_credentials,
      { "responder-credentials", "p1.responder_credentials",
        FT_UINT32, BASE_DEC, VALS(p1_Credentials_vals), 0,
        "ResponderCredentials", HFILL }},
    { &hf_p1_message,
      { "message", "p1.message",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_probe,
      { "probe", "p1.probe",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_report,
      { "report", "p1.report",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_message_envelope,
      { "envelope", "p1.envelope",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageTransferEnvelope", HFILL }},
    { &hf_p1_content,
      { "content", "p1.content",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_report_envelope,
      { "envelope", "p1.envelope",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportTransferEnvelope", HFILL }},
    { &hf_p1_report_content,
      { "content", "p1.content",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportTransferContent", HFILL }},
    { &hf_p1_message_identifier,
      { "message-identifier", "p1.message_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageIdentifier", HFILL }},
    { &hf_p1_originator_name,
      { "originator-name", "p1.originator_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "MTAOriginatorName", HFILL }},
    { &hf_p1_original_encoded_information_types,
      { "original-encoded-information-types", "p1.original_encoded_information_types",
        FT_NONE, BASE_NONE, NULL, 0,
        "OriginalEncodedInformationTypes", HFILL }},
    { &hf_p1_content_type,
      { "content-type", "p1.content_type",
        FT_UINT32, BASE_DEC, VALS(p1_ContentType_vals), 0,
        "ContentType", HFILL }},
    { &hf_p1_content_identifier,
      { "content-identifier", "p1.content_identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "ContentIdentifier", HFILL }},
    { &hf_p1_priority,
      { "priority", "p1.priority",
        FT_UINT32, BASE_DEC, VALS(p1_Priority_U_vals), 0,
        NULL, HFILL }},
    { &hf_p1_per_message_indicators,
      { "per-message-indicators", "p1.per_message_indicators",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PerMessageIndicators", HFILL }},
    { &hf_p1_deferred_delivery_time,
      { "deferred-delivery-time", "p1.deferred_delivery_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "DeferredDeliveryTime", HFILL }},
    { &hf_p1_per_domain_bilateral_information,
      { "per-domain-bilateral-information", "p1.per_domain_bilateral_information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_ub_transfers_OF_PerDomainBilateralInformation", HFILL }},
    { &hf_p1_per_domain_bilateral_information_item,
      { "PerDomainBilateralInformation", "p1.PerDomainBilateralInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_trace_information,
      { "trace-information", "p1.trace_information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TraceInformation", HFILL }},
    { &hf_p1_extensions,
      { "extensions", "p1.extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ExtensionField", HFILL }},
    { &hf_p1_extensions_item,
      { "ExtensionField", "p1.ExtensionField",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_recipient_name,
      { "recipient-name", "p1.recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "MTARecipientName", HFILL }},
    { &hf_p1_originally_specified_recipient_number,
      { "originally-specified-recipient-number", "p1.originally_specified_recipient_number",
        FT_UINT32, BASE_DEC, NULL, 0,
        "OriginallySpecifiedRecipientNumber", HFILL }},
    { &hf_p1_per_recipient_indicators,
      { "per-recipient-indicators", "p1.per_recipient_indicators",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PerRecipientIndicators", HFILL }},
    { &hf_p1_explicit_conversion,
      { "explicit-conversion", "p1.explicit_conversion",
        FT_UINT32, BASE_DEC, VALS(p1_ExplicitConversion_vals), 0,
        "ExplicitConversion", HFILL }},
    { &hf_p1_probe_identifier,
      { "probe-identifier", "p1.probe_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProbeIdentifier", HFILL }},
    { &hf_p1_content_length,
      { "content-length", "p1.content_length",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ContentLength", HFILL }},
    { &hf_p1_report_identifier,
      { "report-identifier", "p1.report_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportIdentifier", HFILL }},
    { &hf_p1_report_destination_name,
      { "report-destination-name", "p1.report_destination_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportDestinationName", HFILL }},
    { &hf_p1_subject_identifier,
      { "subject-identifier", "p1.subject_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubjectIdentifier", HFILL }},
    { &hf_p1_subject_intermediate_trace_information,
      { "subject-intermediate-trace-information", "p1.subject_intermediate_trace_information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SubjectIntermediateTraceInformation", HFILL }},
    { &hf_p1_returned_content,
      { "returned-content", "p1.returned_content",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Content", HFILL }},
    { &hf_p1_additional_information,
      { "additional-information", "p1.additional_information",
        FT_NONE, BASE_NONE, NULL, 0,
        "AdditionalInformation", HFILL }},
    { &hf_p1_mta_actual_recipient_name,
      { "actual-recipient-name", "p1.actual_recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "MTAActualRecipientName", HFILL }},
    { &hf_p1_last_trace_information,
      { "last-trace-information", "p1.last_trace_information",
        FT_NONE, BASE_NONE, NULL, 0,
        "LastTraceInformation", HFILL }},
    { &hf_p1_report_originally_intended_recipient_name,
      { "originally-intended-recipient-name", "p1.originally_intended_recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "OriginallyIntendedRecipientName", HFILL }},
    { &hf_p1_supplementary_information,
      { "supplementary-information", "p1.supplementary_information",
        FT_STRING, BASE_NONE, NULL, 0,
        "SupplementaryInformation", HFILL }},
    { &hf_p1_country_name,
      { "country-name", "p1.country_name",
        FT_UINT32, BASE_DEC, VALS(p1_CountryName_U_vals), 0,
        "CountryName", HFILL }},
    { &hf_p1_bilateral_domain,
      { "domain", "p1.domain",
        FT_UINT32, BASE_DEC, VALS(p1_T_bilateral_domain_vals), 0,
        "T_bilateral_domain", HFILL }},
    { &hf_p1_administration_domain_name,
      { "administration-domain-name", "p1.administration_domain_name",
        FT_UINT32, BASE_DEC, VALS(p1_AdministrationDomainName_U_vals), 0,
        "AdministrationDomainName", HFILL }},
    { &hf_p1_private_domain,
      { "private-domain", "p1.private_domain",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_private_domain_identifier,
      { "private-domain-identifier", "p1.private_domain_identifier",
        FT_UINT32, BASE_DEC, VALS(p1_PrivateDomainIdentifier_vals), 0,
        "PrivateDomainIdentifier", HFILL }},
    { &hf_p1_bilateral_information,
      { "bilateral-information", "p1.bilateral_information",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_arrival_time,
      { "arrival-time", "p1.arrival_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "ArrivalTime", HFILL }},
    { &hf_p1_converted_encoded_information_types,
      { "converted-encoded-information-types", "p1.converted_encoded_information_types",
        FT_NONE, BASE_NONE, NULL, 0,
        "ConvertedEncodedInformationTypes", HFILL }},
    { &hf_p1_trace_report_type,
      { "report-type", "p1.report_type",
        FT_UINT32, BASE_DEC, VALS(p1_ReportType_vals), 0,
        "ReportType", HFILL }},
    { &hf_p1_InternalTraceInformation_item,
      { "InternalTraceInformationElement", "p1.InternalTraceInformationElement",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_global_domain_identifier,
      { "global-domain-identifier", "p1.global_domain_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalDomainIdentifier", HFILL }},
    { &hf_p1_mta_name,
      { "mta-name", "p1.mta_name",
        FT_STRING, BASE_NONE, NULL, 0,
        "MTAName", HFILL }},
    { &hf_p1_mta_supplied_information,
      { "mta-supplied-information", "p1.mta_supplied_information",
        FT_NONE, BASE_NONE, NULL, 0,
        "MTASuppliedInformation", HFILL }},
    { &hf_p1__untag_item,
      { "TraceInformationElement", "p1.TraceInformationElement",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_domain_supplied_information,
      { "domain-supplied-information", "p1.domain_supplied_information",
        FT_NONE, BASE_NONE, NULL, 0,
        "DomainSuppliedInformation", HFILL }},
    { &hf_p1_deferred_time,
      { "deferred-time", "p1.deferred_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "DeferredTime", HFILL }},
    { &hf_p1_other_actions,
      { "other-actions", "p1.other_actions",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OtherActions", HFILL }},
    { &hf_p1_initiator_name,
      { "initiator-name", "p1.initiator_name",
        FT_UINT32, BASE_DEC, VALS(p1_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_p1_messages_waiting,
      { "messages-waiting", "p1.messages_waiting",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessagesWaiting", HFILL }},
    { &hf_p1_responder_name,
      { "responder-name", "p1.responder_name",
        FT_UINT32, BASE_DEC, VALS(p1_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_p1_user_agent,
      { "user-agent", "p1.user_agent",
        FT_NONE, BASE_NONE, NULL, 0,
        "ORAddressAndOptionalDirectoryName", HFILL }},
    { &hf_p1_mTA,
      { "mTA", "p1.mTA",
        FT_STRING, BASE_NONE, NULL, 0,
        "MTAName", HFILL }},
    { &hf_p1_message_store,
      { "message-store", "p1.message_store",
        FT_NONE, BASE_NONE, NULL, 0,
        "ORAddressAndOptionalDirectoryName", HFILL }},
    { &hf_p1_urgent,
      { "urgent", "p1.urgent",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeliveryQueue", HFILL }},
    { &hf_p1_normal,
      { "normal", "p1.normal",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeliveryQueue", HFILL }},
    { &hf_p1_non_urgent,
      { "non-urgent", "p1.non_urgent",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeliveryQueue", HFILL }},
    { &hf_p1_messages,
      { "messages", "p1.messages",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_ub_queue_size", HFILL }},
    { &hf_p1_delivery_queue_octets,
      { "octets", "p1.octets",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_ub_content_length", HFILL }},
    { &hf_p1_simple,
      { "simple", "p1.simple",
        FT_UINT32, BASE_DEC, VALS(p1_Password_vals), 0,
        "Password", HFILL }},
    { &hf_p1_strong,
      { "strong", "p1.strong",
        FT_NONE, BASE_NONE, NULL, 0,
        "StrongCredentials", HFILL }},
    { &hf_p1_protected,
      { "protected", "p1.protected",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtectedPassword", HFILL }},
    { &hf_p1_ia5_string,
      { "ia5-string", "p1.ia5_string",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_0_ub_password_length", HFILL }},
    { &hf_p1_octet_string,
      { "octet-string", "p1.octet_string",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_0_ub_password_length", HFILL }},
    { &hf_p1_bind_token,
      { "bind-token", "p1.bind_token",
        FT_NONE, BASE_NONE, NULL, 0,
        "Token", HFILL }},
    { &hf_p1_certificate,
      { "certificate", "p1.certificate",
        FT_NONE, BASE_NONE, NULL, 0,
        "Certificates", HFILL }},
    { &hf_p1_certificate_selector,
      { "certificate-selector", "p1.certificate_selector",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateAssertion", HFILL }},
    { &hf_p1_signature,
      { "signature", "p1.signature",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_time1,
      { "time1", "p1.time1",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTCTime", HFILL }},
    { &hf_p1_time2,
      { "time2", "p1.time2",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTCTime", HFILL }},
    { &hf_p1_random1,
      { "random1", "p1.random1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_p1_random2,
      { "random2", "p1.random2",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_p1_algorithmIdentifier,
      { "algorithmIdentifier", "p1.algorithmIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_encrypted,
      { "encrypted", "p1.encrypted",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_p1_SecurityContext_item,
      { "SecurityLabel", "p1.SecurityLabel",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_message_submission_envelope,
      { "envelope", "p1.envelope",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageSubmissionEnvelope", HFILL }},
    { &hf_p1_message_submission_identifier,
      { "message-submission-identifier", "p1.message_submission_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageSubmissionIdentifier", HFILL }},
    { &hf_p1_message_submission_time,
      { "message-submission-time", "p1.message_submission_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "MessageSubmissionTime", HFILL }},
    { &hf_p1_probe_submission_identifier,
      { "probe-submission-identifier", "p1.probe_submission_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProbeSubmissionIdentifier", HFILL }},
    { &hf_p1_probe_submission_time,
      { "probe-submission-time", "p1.probe_submission_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "ProbeSubmissionTime", HFILL }},
    { &hf_p1_ImproperlySpecifiedRecipients_item,
      { "RecipientName", "p1.RecipientName",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_waiting_operations,
      { "waiting-operations", "p1.waiting_operations",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Operations", HFILL }},
    { &hf_p1_waiting_messages,
      { "waiting-messages", "p1.waiting_messages",
        FT_BYTES, BASE_NONE, NULL, 0,
        "WaitingMessages", HFILL }},
    { &hf_p1_waiting_content_types,
      { "waiting-content-types", "p1.waiting_content_types",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_0_ub_content_types_OF_ContentType", HFILL }},
    { &hf_p1_waiting_content_types_item,
      { "ContentType", "p1.ContentType",
        FT_UINT32, BASE_DEC, VALS(p1_ContentType_vals), 0,
        NULL, HFILL }},
    { &hf_p1_waiting_encoded_information_types,
      { "waiting-encoded-information-types", "p1.waiting_encoded_information_types",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncodedInformationTypes", HFILL }},
    { &hf_p1_recipient_certificate,
      { "recipient-certificate", "p1.recipient_certificate",
        FT_NONE, BASE_NONE, NULL, 0,
        "RecipientCertificate", HFILL }},
    { &hf_p1_proof_of_delivery,
      { "proof-of-delivery", "p1.proof_of_delivery",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProofOfDelivery", HFILL }},
    { &hf_p1_empty_result,
      { "empty-result", "p1.empty_result",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_max_extensions,
      { "extensions", "p1.extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_MAX_OF_ExtensionField", HFILL }},
    { &hf_p1_max_extensions_item,
      { "ExtensionField", "p1.ExtensionField",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_restrict,
      { "restrict", "p1.restrict",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_p1_permissible_operations,
      { "permissible-operations", "p1.permissible_operations",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Operations", HFILL }},
    { &hf_p1_permissible_maximum_content_length,
      { "permissible-maximum-content-length", "p1.permissible_maximum_content_length",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ContentLength", HFILL }},
    { &hf_p1_permissible_lowest_priority,
      { "permissible-lowest-priority", "p1.permissible_lowest_priority",
        FT_UINT32, BASE_DEC, VALS(p1_Priority_U_vals), 0,
        "Priority", HFILL }},
    { &hf_p1_permissible_content_types,
      { "permissible-content-types", "p1.permissible_content_types",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ContentTypes", HFILL }},
    { &hf_p1_permissible_encoded_information_types,
      { "permissible-encoded-information-types", "p1.permissible_encoded_information_types",
        FT_NONE, BASE_NONE, NULL, 0,
        "PermissibleEncodedInformationTypes", HFILL }},
    { &hf_p1_permissible_security_context,
      { "permissible-security-context", "p1.permissible_security_context",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SecurityContext", HFILL }},
    { &hf_p1_refused_argument,
      { "refused-argument", "p1.refused_argument",
        FT_UINT32, BASE_DEC, VALS(p1_T_refused_argument_vals), 0,
        NULL, HFILL }},
    { &hf_p1_built_in_argument,
      { "built-in-argument", "p1.built_in_argument",
        FT_UINT32, BASE_DEC, VALS(p1_RefusedArgument_vals), 0,
        "RefusedArgument", HFILL }},
    { &hf_p1_refused_extension,
      { "refused-extension", "p1.refused_extension",
        FT_UINT32, BASE_DEC, VALS(p1_ExtensionType_vals), 0,
        NULL, HFILL }},
    { &hf_p1_refusal_reason,
      { "refusal-reason", "p1.refusal_reason",
        FT_UINT32, BASE_DEC, VALS(p1_RefusalReason_vals), 0,
        "RefusalReason", HFILL }},
    { &hf_p1_user_name,
      { "user-name", "p1.user_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "UserName", HFILL }},
    { &hf_p1_user_address,
      { "user-address", "p1.user_address",
        FT_UINT32, BASE_DEC, VALS(p1_UserAddress_vals), 0,
        "UserAddress", HFILL }},
    { &hf_p1_deliverable_class,
      { "deliverable-class", "p1.deliverable_class",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_ub_deliverable_class_OF_DeliverableClass", HFILL }},
    { &hf_p1_deliverable_class_item,
      { "DeliverableClass", "p1.DeliverableClass",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_default_delivery_controls,
      { "default-delivery-controls", "p1.default_delivery_controls",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefaultDeliveryControls", HFILL }},
    { &hf_p1_redirections,
      { "redirections", "p1.redirections",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_restricted_delivery,
      { "restricted-delivery", "p1.restricted_delivery",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RestrictedDelivery", HFILL }},
    { &hf_p1_retrieve_registrations,
      { "retrieve-registrations", "p1.retrieve_registrations",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegistrationTypes", HFILL }},
    { &hf_p1_non_empty_result,
      { "non-empty-result", "p1.non_empty_result",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_registered_information,
      { "registered-information", "p1.registered_information",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegisterArgument", HFILL }},
    { &hf_p1_old_credentials,
      { "old-credentials", "p1.old_credentials",
        FT_UINT32, BASE_DEC, VALS(p1_Credentials_vals), 0,
        "Credentials", HFILL }},
    { &hf_p1_new_credentials,
      { "new-credentials", "p1.new_credentials",
        FT_UINT32, BASE_DEC, VALS(p1_Credentials_vals), 0,
        "Credentials", HFILL }},
    { &hf_p1_x121,
      { "x121", "p1.x121",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_x121_address,
      { "x121-address", "p1.x121_address",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_tsap_id,
      { "tsap-id", "p1.tsap_id",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_1_ub_tsap_id_length", HFILL }},
    { &hf_p1_presentation,
      { "presentation", "p1.presentation",
        FT_NONE, BASE_NONE, NULL, 0,
        "PSAPAddress", HFILL }},
    { &hf_p1_Redirections_item,
      { "RecipientRedirection", "p1.RecipientRedirection",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_redirection_classes,
      { "redirection-classes", "p1.redirection_classes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_ub_redirection_classes_OF_RedirectionClass", HFILL }},
    { &hf_p1_redirection_classes_item,
      { "RedirectionClass", "p1.RedirectionClass",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_recipient_assigned_alternate_recipient,
      { "recipient-assigned-alternate-recipient", "p1.recipient_assigned_alternate_recipient",
        FT_NONE, BASE_NONE, NULL, 0,
        "RecipientAssignedAlternateRecipient", HFILL }},
    { &hf_p1_content_types,
      { "content-types", "p1.content_types",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ContentTypes", HFILL }},
    { &hf_p1_maximum_content_length,
      { "maximum-content-length", "p1.maximum_content_length",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ContentLength", HFILL }},
    { &hf_p1_encoded_information_types_constraints,
      { "encoded-information-types-constraints", "p1.encoded_information_types_constraints",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncodedInformationTypesConstraints", HFILL }},
    { &hf_p1_security_labels,
      { "security-labels", "p1.security_labels",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SecurityContext", HFILL }},
    { &hf_p1_class_priority,
      { "priority", "p1.priority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Priority", HFILL }},
    { &hf_p1_class_priority_item,
      { "Priority", "p1.Priority",
        FT_UINT32, BASE_DEC, VALS(p1_Priority_U_vals), 0,
        NULL, HFILL }},
    { &hf_p1_objects,
      { "objects", "p1.objects",
        FT_UINT32, BASE_DEC, VALS(p1_T_objects_vals), 0,
        NULL, HFILL }},
    { &hf_p1_applies_only_to,
      { "applies-only-to", "p1.applies_only_to",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Restriction", HFILL }},
    { &hf_p1_applies_only_to_item,
      { "Restriction", "p1.Restriction",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_unacceptable_eits,
      { "unacceptable-eits", "p1.unacceptable_eits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ExtendedEncodedInformationTypes", HFILL }},
    { &hf_p1_acceptable_eits,
      { "acceptable-eits", "p1.acceptable_eits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ExtendedEncodedInformationTypes", HFILL }},
    { &hf_p1_exclusively_acceptable_eits,
      { "exclusively-acceptable-eits", "p1.exclusively_acceptable_eits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ExtendedEncodedInformationTypes", HFILL }},
    { &hf_p1_RestrictedDelivery_item,
      { "Restriction", "p1.Restriction",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_permitted,
      { "permitted", "p1.permitted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_p1_source_type,
      { "source-type", "p1.source_type",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_source_name,
      { "source-name", "p1.source_name",
        FT_UINT32, BASE_DEC, VALS(p1_ExactOrPattern_vals), 0,
        "ExactOrPattern", HFILL }},
    { &hf_p1_exact_match,
      { "exact-match", "p1.exact_match",
        FT_NONE, BASE_NONE, NULL, 0,
        "ORName", HFILL }},
    { &hf_p1_pattern_match,
      { "pattern-match", "p1.pattern_match",
        FT_NONE, BASE_NONE, NULL, 0,
        "ORName", HFILL }},
    { &hf_p1_standard_parameters,
      { "standard-parameters", "p1.standard_parameters",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_type_extensions,
      { "extensions", "p1.extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_type_extensions", HFILL }},
    { &hf_p1_type_extensions_item,
      { "extensions item", "p1.extensions_item",
        FT_UINT32, BASE_DEC, VALS(p1_ExtensionType_vals), 0,
        "T_type_extensions_item", HFILL }},
    { &hf_p1_originator_name_01,
      { "originator-name", "p1.originator_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "OriginatorName", HFILL }},
    { &hf_p1_submission_recipient_name,
      { "recipient-name", "p1.recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "RecipientName", HFILL }},
    { &hf_p1_originator_report_request,
      { "originator-report-request", "p1.originator_report_request",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OriginatorReportRequest", HFILL }},
    { &hf_p1_probe_recipient_name,
      { "recipient-name", "p1.recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "RecipientName", HFILL }},
    { &hf_p1_message_delivery_identifier,
      { "message-delivery-identifier", "p1.message_delivery_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageDeliveryIdentifier", HFILL }},
    { &hf_p1_message_delivery_time,
      { "message-delivery-time", "p1.message_delivery_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "MessageDeliveryTime", HFILL }},
    { &hf_p1_other_fields,
      { "other-fields", "p1.other_fields",
        FT_NONE, BASE_NONE, NULL, 0,
        "OtherMessageDeliveryFields", HFILL }},
    { &hf_p1_delivered_content_type,
      { "content-type", "p1.content_type",
        FT_UINT32, BASE_DEC, VALS(p1_DeliveredContentType_vals), 0,
        "DeliveredContentType", HFILL }},
    { &hf_p1_delivered_originator_name,
      { "originator-name", "p1.originator_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeliveredOriginatorName", HFILL }},
    { &hf_p1_delivery_flags,
      { "delivery-flags", "p1.delivery_flags",
        FT_BYTES, BASE_NONE, NULL, 0,
        "DeliveryFlags", HFILL }},
    { &hf_p1_other_recipient_names,
      { "other-recipient-names", "p1.other_recipient_names",
        FT_UINT32, BASE_DEC, NULL, 0,
        "OtherRecipientNames", HFILL }},
    { &hf_p1_this_recipient_name,
      { "this-recipient-name", "p1.this_recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "ThisRecipientName", HFILL }},
    { &hf_p1_originally_intended_recipient_name,
      { "originally-intended-recipient-name", "p1.originally_intended_recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "OriginallyIntendedRecipientName", HFILL }},
    { &hf_p1_subject_submission_identifier,
      { "subject-submission-identifier", "p1.subject_submission_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubjectSubmissionIdentifier", HFILL }},
    { &hf_p1_actual_recipient_name,
      { "actual-recipient-name", "p1.actual_recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "ActualRecipientName", HFILL }},
    { &hf_p1_delivery_report_type,
      { "report-type", "p1.report_type",
        FT_UINT32, BASE_DEC, VALS(p1_ReportType_vals), 0,
        "ReportType", HFILL }},
    { &hf_p1_delivery,
      { "delivery", "p1.delivery",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeliveryReport", HFILL }},
    { &hf_p1_non_delivery,
      { "non-delivery", "p1.non_delivery",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonDeliveryReport", HFILL }},
    { &hf_p1_type_of_MTS_user,
      { "type-of-MTS-user", "p1.type_of_MTS_user",
        FT_UINT32, BASE_DEC, VALS(p1_TypeOfMTSUser_vals), 0,
        "TypeOfMTSUser", HFILL }},
    { &hf_p1_non_delivery_reason_code,
      { "non-delivery-reason-code", "p1.non_delivery_reason_code",
        FT_UINT32, BASE_DEC, VALS(p1_NonDeliveryReasonCode_vals), 0,
        "NonDeliveryReasonCode", HFILL }},
    { &hf_p1_non_delivery_diagnostic_code,
      { "non-delivery-diagnostic-code", "p1.non_delivery_diagnostic_code",
        FT_UINT32, BASE_DEC, VALS(p1_NonDeliveryDiagnosticCode_vals), 0,
        "NonDeliveryDiagnosticCode", HFILL }},
    { &hf_p1_ContentTypes_item,
      { "ContentType", "p1.ContentType",
        FT_UINT32, BASE_DEC, VALS(p1_ContentType_vals), 0,
        NULL, HFILL }},
    { &hf_p1_built_in,
      { "built-in", "p1.built_in",
        FT_UINT32, BASE_DEC, VALS(p1_BuiltInContentType_U_vals), 0,
        "BuiltInContentType", HFILL }},
    { &hf_p1_extended,
      { "extended", "p1.extended",
        FT_OID, BASE_NONE, NULL, 0,
        "ExtendedContentType", HFILL }},
    { &hf_p1_OtherRecipientNames_item,
      { "OtherRecipientName", "p1.OtherRecipientName",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_standard_extension,
      { "standard-extension", "p1.standard_extension",
        FT_INT32, BASE_DEC, VALS(p1_StandardExtension_vals), 0,
        "StandardExtension", HFILL }},
    { &hf_p1_private_extension,
      { "private-extension", "p1.private_extension",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_extension_type,
      { "type", "p1.type",
        FT_UINT32, BASE_DEC, VALS(p1_ExtensionType_vals), 0,
        "ExtensionType", HFILL }},
    { &hf_p1_criticality,
      { "criticality", "p1.criticality",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_extension_value,
      { "value", "p1.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExtensionValue", HFILL }},
    { &hf_p1_RequestedDeliveryMethod_item,
      { "RequestedDeliveryMethod item", "p1.RequestedDeliveryMethod_item",
        FT_UINT32, BASE_DEC, VALS(p1_RequestedDeliveryMethod_item_vals), 0,
        NULL, HFILL }},
    { &hf_p1_ia5text,
      { "ia5text", "p1.ia5text",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String", HFILL }},
    { &hf_p1_octets,
      { "octets", "p1.octets",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_p1_RedirectionHistory_item,
      { "Redirection", "p1.Redirection",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_intended_recipient_name,
      { "intended-recipient-name", "p1.intended_recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "IntendedRecipientName", HFILL }},
    { &hf_p1_redirection_reason,
      { "redirection-reason", "p1.redirection_reason",
        FT_UINT32, BASE_DEC, VALS(p1_RedirectionReason_vals), 0,
        "RedirectionReason", HFILL }},
    { &hf_p1_intended_recipient,
      { "intended-recipient", "p1.intended_recipient",
        FT_NONE, BASE_NONE, NULL, 0,
        "ORAddressAndOptionalDirectoryName", HFILL }},
    { &hf_p1_redirection_time,
      { "redirection-time", "p1.redirection_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_p1_DLExpansionHistory_item,
      { "DLExpansion", "p1.DLExpansion",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_dl,
      { "dl", "p1.dl",
        FT_NONE, BASE_NONE, NULL, 0,
        "ORAddressAndOptionalDirectoryName", HFILL }},
    { &hf_p1_dl_expansion_time,
      { "dl-expansion-time", "p1.dl_expansion_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_p1_OriginatorAndDLExpansionHistory_item,
      { "OriginatorAndDLExpansion", "p1.OriginatorAndDLExpansion",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_originator_or_dl_name,
      { "originator-or-dl-name", "p1.originator_or_dl_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "ORAddressAndOptionalDirectoryName", HFILL }},
    { &hf_p1_origination_or_expansion_time,
      { "origination-or-expansion-time", "p1.origination_or_expansion_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_p1_report_type,
      { "report-type", "p1.report_type",
        FT_UINT32, BASE_DEC, VALS(p1_T_report_type_vals), 0,
        "T_report_type", HFILL }},
    { &hf_p1_report_type_delivery,
      { "delivery", "p1.delivery",
        FT_NONE, BASE_NONE, NULL, 0,
        "PerRecipientDeliveryReportFields", HFILL }},
    { &hf_p1_non_delivery_report,
      { "non-delivery", "p1.non_delivery",
        FT_NONE, BASE_NONE, NULL, 0,
        "PerRecipientNonDeliveryReportFields", HFILL }},
    { &hf_p1_domain,
      { "domain", "p1.domain",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalDomainIdentifier", HFILL }},
    { &hf_p1_mta_directory_name,
      { "mta-directory-name", "p1.mta_directory_name",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_p1_ExtendedCertificates_item,
      { "ExtendedCertificate", "p1.ExtendedCertificate",
        FT_UINT32, BASE_DEC, VALS(p1_ExtendedCertificate_vals), 0,
        NULL, HFILL }},
    { &hf_p1_directory_entry,
      { "directory-entry", "p1.directory_entry",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_p1_DLExemptedRecipients_item,
      { "ORAddressAndOrDirectoryName", "p1.ORAddressAndOrDirectoryName",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_encryption_recipient,
      { "encryption-recipient", "p1.encryption_recipient",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateAssertion", HFILL }},
    { &hf_p1_encryption_originator,
      { "encryption-originator", "p1.encryption_originator",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateAssertion", HFILL }},
    { &hf_p1_selectors_content_integrity_check,
      { "content-integrity-check", "p1.content_integrity_check",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateAssertion", HFILL }},
    { &hf_p1_token_signature,
      { "token-signature", "p1.token_signature",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateAssertion", HFILL }},
    { &hf_p1_message_origin_authentication,
      { "message-origin-authentication", "p1.message_origin_authentication",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateAssertion", HFILL }},
    { &hf_p1_local_identifier,
      { "local-identifier", "p1.local_identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "LocalIdentifier", HFILL }},
    { &hf_p1_numeric_private_domain_identifier,
      { "numeric", "p1.numeric",
        FT_STRING, BASE_NONE, NULL, 0,
        "T_numeric_private_domain_identifier", HFILL }},
    { &hf_p1_printable_private_domain_identifier,
      { "printable", "p1.printable",
        FT_STRING, BASE_NONE, NULL, 0,
        "T_printable_private_domain_identifier", HFILL }},
    { &hf_p1_built_in_standard_attributes,
      { "built-in-standard-attributes", "p1.built_in_standard_attributes",
        FT_NONE, BASE_NONE, NULL, 0,
        "BuiltInStandardAttributes", HFILL }},
    { &hf_p1_built_in_domain_defined_attributes,
      { "built-in-domain-defined-attributes", "p1.built_in_domain_defined_attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BuiltInDomainDefinedAttributes", HFILL }},
    { &hf_p1_extension_attributes,
      { "extension-attributes", "p1.extension_attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ExtensionAttributes", HFILL }},
    { &hf_p1_network_address,
      { "network-address", "p1.network_address",
        FT_STRING, BASE_NONE, NULL, 0,
        "NetworkAddress", HFILL }},
    { &hf_p1_terminal_identifier,
      { "terminal-identifier", "p1.terminal_identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "TerminalIdentifier", HFILL }},
    { &hf_p1_private_domain_name,
      { "private-domain-name", "p1.private_domain_name",
        FT_UINT32, BASE_DEC, VALS(p1_PrivateDomainName_vals), 0,
        "PrivateDomainName", HFILL }},
    { &hf_p1_organization_name,
      { "organization-name", "p1.organization_name",
        FT_STRING, BASE_NONE, NULL, 0,
        "OrganizationName", HFILL }},
    { &hf_p1_numeric_user_identifier,
      { "numeric-user-identifier", "p1.numeric_user_identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumericUserIdentifier", HFILL }},
    { &hf_p1_personal_name,
      { "personal-name", "p1.personal_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "PersonalName", HFILL }},
    { &hf_p1_organizational_unit_names,
      { "organizational-unit-names", "p1.organizational_unit_names",
        FT_UINT32, BASE_DEC, NULL, 0,
        "OrganizationalUnitNames", HFILL }},
    { &hf_p1_x121_dcc_code,
      { "x121-dcc-code", "p1.x121_dcc_code",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_iso_3166_alpha2_code,
      { "iso-3166-alpha2-code", "p1.iso_3166_alpha2_code",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_numeric,
      { "numeric", "p1.numeric",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_printable,
      { "printable", "p1.printable",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_numeric_private_domain_name,
      { "numeric", "p1.numeric",
        FT_STRING, BASE_NONE, NULL, 0,
        "T_numeric_private_domain_name", HFILL }},
    { &hf_p1_printable_private_domain_name,
      { "printable", "p1.printable",
        FT_STRING, BASE_NONE, NULL, 0,
        "T_printable_private_domain_name", HFILL }},
    { &hf_p1_printable_surname,
      { "surname", "p1.surname",
        FT_STRING, BASE_NONE, NULL, 0,
        "T_printable_surname", HFILL }},
    { &hf_p1_printable_given_name,
      { "given-name", "p1.given_name",
        FT_STRING, BASE_NONE, NULL, 0,
        "T_printable_given_name", HFILL }},
    { &hf_p1_printable_initials,
      { "initials", "p1.initials",
        FT_STRING, BASE_NONE, NULL, 0,
        "T_printable_initials", HFILL }},
    { &hf_p1_printable_generation_qualifier,
      { "generation-qualifier", "p1.generation_qualifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "T_printable_generation_qualifier", HFILL }},
    { &hf_p1_OrganizationalUnitNames_item,
      { "OrganizationalUnitName", "p1.OrganizationalUnitName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_BuiltInDomainDefinedAttributes_item,
      { "BuiltInDomainDefinedAttribute", "p1.BuiltInDomainDefinedAttribute",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_printable_type,
      { "type", "p1.type",
        FT_STRING, BASE_NONE, NULL, 0,
        "T_printable_type", HFILL }},
    { &hf_p1_printable_value,
      { "value", "p1.value",
        FT_STRING, BASE_NONE, NULL, 0,
        "T_printable_value", HFILL }},
    { &hf_p1_ExtensionAttributes_item,
      { "ExtensionAttribute", "p1.ExtensionAttribute",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_extension_attribute_type,
      { "extension-attribute-type", "p1.extension_attribute_type",
        FT_INT32, BASE_DEC, VALS(p1_ExtensionAttributeType_vals), 0,
        "ExtensionAttributeType", HFILL }},
    { &hf_p1_extension_attribute_value,
      { "extension-attribute-value", "p1.extension_attribute_value",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_teletex_surname,
      { "surname", "p1.surname",
        FT_STRING, BASE_NONE, NULL, 0,
        "T_teletex_surname", HFILL }},
    { &hf_p1_teletex_given_name,
      { "given-name", "p1.given_name",
        FT_STRING, BASE_NONE, NULL, 0,
        "T_teletex_given_name", HFILL }},
    { &hf_p1_teletex_initials,
      { "initials", "p1.initials",
        FT_STRING, BASE_NONE, NULL, 0,
        "T_teletex_initials", HFILL }},
    { &hf_p1_teletex_generation_qualifier,
      { "generation-qualifier", "p1.generation_qualifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "T_teletex_generation_qualifier", HFILL }},
    { &hf_p1_universal_surname,
      { "surname", "p1.surname",
        FT_NONE, BASE_NONE, NULL, 0,
        "UniversalOrBMPString", HFILL }},
    { &hf_p1_universal_given_name,
      { "given-name", "p1.given_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "UniversalOrBMPString", HFILL }},
    { &hf_p1_universal_initials,
      { "initials", "p1.initials",
        FT_NONE, BASE_NONE, NULL, 0,
        "UniversalOrBMPString", HFILL }},
    { &hf_p1_universal_generation_qualifier,
      { "generation-qualifier", "p1.generation_qualifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "UniversalOrBMPString", HFILL }},
    { &hf_p1_TeletexOrganizationalUnitNames_item,
      { "TeletexOrganizationalUnitName", "p1.TeletexOrganizationalUnitName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_UniversalOrganizationalUnitNames_item,
      { "UniversalOrganizationalUnitName", "p1.UniversalOrganizationalUnitName",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_character_encoding,
      { "character-encoding", "p1.character_encoding",
        FT_UINT32, BASE_DEC, VALS(p1_T_character_encoding_vals), 0,
        NULL, HFILL }},
    { &hf_p1_two_octets,
      { "two-octets", "p1.two_octets",
        FT_STRING, BASE_NONE, NULL, 0,
        "BMPString_SIZE_1_ub_string_length", HFILL }},
    { &hf_p1_four_octets,
      { "four-octets", "p1.four_octets",
        FT_STRING, BASE_NONE, NULL, 0,
        "UniversalString_SIZE_1_ub_string_length", HFILL }},
    { &hf_p1_iso_639_language_code,
      { "iso-639-language-code", "p1.iso_639_language_code",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_CONSTR001", HFILL }},
    { &hf_p1_x121_dcc_code_01,
      { "x121-dcc-code", "p1.x121_dcc_code",
        FT_STRING, BASE_NONE, NULL, 0,
        "T_x121_dcc_code_01", HFILL }},
    { &hf_p1_iso_3166_alpha2_code_01,
      { "iso-3166-alpha2-code", "p1.iso_3166_alpha2_code",
        FT_STRING, BASE_NONE, NULL, 0,
        "T_iso_3166_alpha2_code_01", HFILL }},
    { &hf_p1_numeric_code,
      { "numeric-code", "p1.numeric_code",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_printable_code,
      { "printable-code", "p1.printable_code",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_1_ub_postal_code_length", HFILL }},
    { &hf_p1_printable_address,
      { "printable-address", "p1.printable_address",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_printable_address_item,
      { "printable-address item", "p1.printable_address_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_1_ub_pds_parameter_length", HFILL }},
    { &hf_p1_teletex_string,
      { "teletex-string", "p1.teletex_string",
        FT_STRING, BASE_NONE, NULL, 0,
        "TeletexString_SIZE_1_ub_unformatted_address_length", HFILL }},
    { &hf_p1_printable_string,
      { "printable-string", "p1.printable_string",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_1_ub_pds_parameter_length", HFILL }},
    { &hf_p1_pds_teletex_string,
      { "teletex-string", "p1.teletex_string",
        FT_STRING, BASE_NONE, NULL, 0,
        "TeletexString_SIZE_1_ub_pds_parameter_length", HFILL }},
    { &hf_p1_e163_4_address,
      { "e163-4-address", "p1.e163_4_address",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_number,
      { "number", "p1.number",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumericString_SIZE_1_ub_e163_4_number_length", HFILL }},
    { &hf_p1_sub_address,
      { "sub-address", "p1.sub_address",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumericString_SIZE_1_ub_e163_4_sub_address_length", HFILL }},
    { &hf_p1_psap_address,
      { "psap-address", "p1.psap_address",
        FT_NONE, BASE_NONE, NULL, 0,
        "PresentationAddress", HFILL }},
    { &hf_p1_TeletexDomainDefinedAttributes_item,
      { "TeletexDomainDefinedAttribute", "p1.TeletexDomainDefinedAttribute",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_type,
      { "type", "p1.type",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_teletex_value,
      { "value", "p1.value",
        FT_STRING, BASE_NONE, NULL, 0,
        "T_teletex_value", HFILL }},
    { &hf_p1_UniversalDomainDefinedAttributes_item,
      { "UniversalDomainDefinedAttribute", "p1.UniversalDomainDefinedAttribute",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_universal_type,
      { "type", "p1.type",
        FT_NONE, BASE_NONE, NULL, 0,
        "UniversalOrBMPString", HFILL }},
    { &hf_p1_universal_value,
      { "value", "p1.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "UniversalOrBMPString", HFILL }},
    { &hf_p1_ExtendedEncodedInformationTypes_item,
      { "ExtendedEncodedInformationType", "p1.ExtendedEncodedInformationType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_g3_facsimile,
      { "g3-facsimile", "p1.g3_facsimile",
        FT_BYTES, BASE_NONE, NULL, 0,
        "G3FacsimileNonBasicParameters", HFILL }},
    { &hf_p1_teletex,
      { "teletex", "p1.teletex",
        FT_NONE, BASE_NONE, NULL, 0,
        "TeletexNonBasicParameters", HFILL }},
    { &hf_p1_graphic_character_sets,
      { "graphic-character-sets", "p1.graphic_character_sets",
        FT_STRING, BASE_NONE, NULL, 0,
        "TeletexString", HFILL }},
    { &hf_p1_control_character_sets,
      { "control-character-sets", "p1.control_character_sets",
        FT_STRING, BASE_NONE, NULL, 0,
        "TeletexString", HFILL }},
    { &hf_p1_page_formats,
      { "page-formats", "p1.page_formats",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_p1_miscellaneous_terminal_capabilities,
      { "miscellaneous-terminal-capabilities", "p1.miscellaneous_terminal_capabilities",
        FT_STRING, BASE_NONE, NULL, 0,
        "TeletexString", HFILL }},
    { &hf_p1_private_use,
      { "private-use", "p1.private_use",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_p1_token_type_identifier,
      { "token-type-identifier", "p1.token_type_identifier",
        FT_OID, BASE_NONE, NULL, 0,
        "TokenTypeIdentifier", HFILL }},
    { &hf_p1_token,
      { "token", "p1.token",
        FT_NONE, BASE_NONE, NULL, 0,
        "TokenTypeData", HFILL }},
    { &hf_p1_signature_algorithm_identifier,
      { "signature-algorithm-identifier", "p1.signature_algorithm_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_p1_name,
      { "name", "p1.name",
        FT_UINT32, BASE_DEC, VALS(p1_T_name_vals), 0,
        NULL, HFILL }},
    { &hf_p1_token_recipient_name,
      { "recipient-name", "p1.recipient_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "RecipientName", HFILL }},
    { &hf_p1_token_mta,
      { "mta", "p1.mta",
        FT_NONE, BASE_NONE, NULL, 0,
        "MTANameAndOptionalGDI", HFILL }},
    { &hf_p1_time,
      { "time", "p1.time",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_signed_data,
      { "signed-data", "p1.signed_data",
        FT_NONE, BASE_NONE, NULL, 0,
        "TokenData", HFILL }},
    { &hf_p1_encryption_algorithm_identifier,
      { "encryption-algorithm-identifier", "p1.encryption_algorithm_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_p1_encrypted_data,
      { "encrypted-data", "p1.encrypted_data",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_p1_asymmetric_token_data,
      { "asymmetric-token-data", "p1.asymmetric_token_data",
        FT_NONE, BASE_NONE, NULL, 0,
        "AsymmetricTokenData", HFILL }},
    { &hf_p1_algorithm_identifier,
      { "algorithm-identifier", "p1.algorithm_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_p1_token_data_type,
      { "type", "p1.type",
        FT_INT32, BASE_DEC, VALS(p1_TokenDataType_vals), 0,
        "TokenDataType", HFILL }},
    { &hf_p1_value,
      { "value", "p1.value",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_content_confidentiality_algorithm_identifier,
      { "content-confidentiality-algorithm-identifier", "p1.content_confidentiality_algorithm_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContentConfidentialityAlgorithmIdentifier", HFILL }},
    { &hf_p1_content_integrity_check,
      { "content-integrity-check", "p1.content_integrity_check",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContentIntegrityCheck", HFILL }},
    { &hf_p1_message_security_label,
      { "message-security-label", "p1.message_security_label",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageSecurityLabel", HFILL }},
    { &hf_p1_proof_of_delivery_request,
      { "proof-of-delivery-request", "p1.proof_of_delivery_request",
        FT_UINT32, BASE_DEC, VALS(p1_ProofOfDeliveryRequest_vals), 0,
        "ProofOfDeliveryRequest", HFILL }},
    { &hf_p1_message_sequence_number,
      { "message-sequence-number", "p1.message_sequence_number",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_p1_content_confidentiality_key,
      { "content-confidentiality-key", "p1.content_confidentiality_key",
        FT_BYTES, BASE_NONE, NULL, 0,
        "EncryptionKey", HFILL }},
    { &hf_p1_content_integrity_key,
      { "content-integrity-key", "p1.content_integrity_key",
        FT_BYTES, BASE_NONE, NULL, 0,
        "EncryptionKey", HFILL }},
    { &hf_p1_security_policy_identifier,
      { "security-policy-identifier", "p1.security_policy_identifier",
        FT_OID, BASE_NONE, NULL, 0,
        "SecurityPolicyIdentifier", HFILL }},
    { &hf_p1_security_classification,
      { "security-classification", "p1.security_classification",
        FT_UINT32, BASE_DEC, VALS(p1_SecurityClassification_vals), 0,
        "SecurityClassification", HFILL }},
    { &hf_p1_privacy_mark,
      { "privacy-mark", "p1.privacy_mark",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrivacyMark", HFILL }},
    { &hf_p1_security_categories,
      { "security-categories", "p1.security_categories",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SecurityCategories", HFILL }},
    { &hf_p1_SecurityCategories_item,
      { "SecurityCategory", "p1.SecurityCategory",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_category_type,
      { "type", "p1.type",
        FT_OID, BASE_NONE, NULL, 0,
        "SecurityCategoryIdentifier", HFILL }},
    { &hf_p1_category_value,
      { "value", "p1.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "CategoryValue", HFILL }},
    { &hf_p1_mta_originator_name,
      { "originator-name", "p1.originator_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "MTAOriginatorName", HFILL }},
    { &hf_p1_per_recipient_message_fields,
      { "per-recipient-fields", "p1.per_recipient_fields",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageTransferFields", HFILL }},
    { &hf_p1_per_recipient_message_fields_item,
      { "PerRecipientMessageTransferFields", "p1.PerRecipientMessageTransferFields",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_per_recipient_probe_transfer_fields,
      { "per-recipient-fields", "p1.per_recipient_fields",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeTransferFields", HFILL }},
    { &hf_p1_per_recipient_probe_transfer_fields_item,
      { "PerRecipientProbeTransferFields", "p1.PerRecipientProbeTransferFields",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_per_recipient_report_fields,
      { "per-recipient-fields", "p1.per_recipient_fields",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportTransferFields", HFILL }},
    { &hf_p1_per_recipient_report_fields_item,
      { "PerRecipientReportTransferFields", "p1.PerRecipientReportTransferFields",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_routing_action,
      { "routing-action", "p1.routing_action",
        FT_UINT32, BASE_DEC, VALS(p1_RoutingAction_vals), 0,
        "RoutingAction", HFILL }},
    { &hf_p1_attempted,
      { "attempted", "p1.attempted",
        FT_UINT32, BASE_DEC, VALS(p1_T_attempted_vals), 0,
        NULL, HFILL }},
    { &hf_p1_mta,
      { "mta", "p1.mta",
        FT_STRING, BASE_NONE, NULL, 0,
        "MTAName", HFILL }},
    { &hf_p1_attempted_domain,
      { "attempted-domain", "p1.attempted_domain",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalDomainIdentifier", HFILL }},
    { &hf_p1_per_recipient_report_delivery_fields,
      { "per-recipient-fields", "p1.per_recipient_fields",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportDeliveryFields", HFILL }},
    { &hf_p1_per_recipient_report_delivery_fields_item,
      { "PerRecipientReportDeliveryFields", "p1.PerRecipientReportDeliveryFields",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_mts_originator_name,
      { "originator-name", "p1.originator_name",
        FT_NONE, BASE_NONE, NULL, 0,
        "OriginatorName", HFILL }},
    { &hf_p1_per_recipient_message_submission_fields,
      { "per-recipient-fields", "p1.per_recipient_fields",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageSubmissionFields", HFILL }},
    { &hf_p1_per_recipient_message_submission_fields_item,
      { "PerRecipientMessageSubmissionFields", "p1.PerRecipientMessageSubmissionFields",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_per_recipient_probe_submission_fields,
      { "per-recipient-fields", "p1.per_recipient_fields",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeSubmissionFields", HFILL }},
    { &hf_p1_per_recipient_probe_submission_fields_item,
      { "PerRecipientProbeSubmissionFields", "p1.PerRecipientProbeSubmissionFields",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_p1_directory_name,
      { "directory-name", "p1.directory_name",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_p1_built_in_encoded_information_types,
      { "built-in-encoded-information-types", "p1.built_in_encoded_information_types",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BuiltInEncodedInformationTypes", HFILL }},
    { &hf_p1_extended_encoded_information_types,
      { "extended-encoded-information-types", "p1.extended_encoded_information_types",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ExtendedEncodedInformationTypes", HFILL }},
    { &hf_p1_PerRecipientIndicators_responsibility,
      { "responsibility", "p1.responsibility",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_p1_PerRecipientIndicators_originating_MTA_report,
      { "originating-MTA-report", "p1.originating-MTA-report",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_p1_PerRecipientIndicators_originating_MTA_non_delivery_report,
      { "originating-MTA-non-delivery-report", "p1.originating-MTA-non-delivery-report",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_p1_PerRecipientIndicators_originator_report,
      { "originator-report", "p1.originator-report",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_p1_PerRecipientIndicators_originator_non_delivery_report,
      { "originator-non-delivery-report", "p1.originator-non-delivery-report",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_p1_PerRecipientIndicators_reserved_5,
      { "reserved-5", "p1.reserved-5",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_p1_PerRecipientIndicators_reserved_6,
      { "reserved-6", "p1.reserved-6",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_p1_PerRecipientIndicators_reserved_7,
      { "reserved-7", "p1.reserved-7",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_p1_OtherActions_redirected,
      { "redirected", "p1.redirected",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_p1_OtherActions_dl_operation,
      { "dl-operation", "p1.dl-operation",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_p1_Operations_probe_submission_or_report_delivery,
      { "probe-submission-or-report-delivery", "p1.probe-submission-or-report-delivery",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_p1_Operations_message_submission_or_message_delivery,
      { "message-submission-or-message-delivery", "p1.message-submission-or-message-delivery",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_p1_WaitingMessages_long_content,
      { "long-content", "p1.long-content",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_p1_WaitingMessages_low_priority,
      { "low-priority", "p1.low-priority",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_p1_WaitingMessages_other_security_labels,
      { "other-security-labels", "p1.other-security-labels",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_p1_T_source_type_originated_by,
      { "originated-by", "p1.originated-by",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_p1_T_source_type_redirected_by,
      { "redirected-by", "p1.redirected-by",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_p1_T_source_type_dl_expanded_by,
      { "dl-expanded-by", "p1.dl-expanded-by",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_p1_T_standard_parameters_user_name,
      { "user-name", "p1.user-name",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_p1_T_standard_parameters_user_address,
      { "user-address", "p1.user-address",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_p1_T_standard_parameters_deliverable_class,
      { "deliverable-class", "p1.deliverable-class",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_p1_T_standard_parameters_default_delivery_controls,
      { "default-delivery-controls", "p1.default-delivery-controls",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_p1_T_standard_parameters_redirections,
      { "redirections", "p1.redirections",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_p1_T_standard_parameters_restricted_delivery,
      { "restricted-delivery", "p1.restricted-delivery",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_p1_PerMessageIndicators_U_disclosure_of_other_recipients,
      { "disclosure-of-other-recipients", "p1.disclosure-of-other-recipients",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_p1_PerMessageIndicators_U_implicit_conversion_prohibited,
      { "implicit-conversion-prohibited", "p1.implicit-conversion-prohibited",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_p1_PerMessageIndicators_U_alternate_recipient_allowed,
      { "alternate-recipient-allowed", "p1.alternate-recipient-allowed",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_p1_PerMessageIndicators_U_content_return_request,
      { "content-return-request", "p1.content-return-request",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_p1_PerMessageIndicators_U_reserved,
      { "reserved", "p1.reserved",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_p1_PerMessageIndicators_U_bit_5,
      { "bit-5", "p1.bit-5",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_p1_PerMessageIndicators_U_bit_6,
      { "bit-6", "p1.bit-6",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_p1_PerMessageIndicators_U_service_message,
      { "service-message", "p1.service-message",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_p1_OriginatorReportRequest_report,
      { "report", "p1.report",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_p1_OriginatorReportRequest_non_delivery_report,
      { "non-delivery-report", "p1.non-delivery-report",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_p1_DeliveryFlags_implicit_conversion_prohibited,
      { "implicit-conversion-prohibited", "p1.implicit-conversion-prohibited",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_p1_Criticality_for_submission,
      { "for-submission", "p1.for-submission",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_p1_Criticality_for_transfer,
      { "for-transfer", "p1.for-transfer",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_p1_Criticality_for_delivery,
      { "for-delivery", "p1.for-delivery",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_p1_PhysicalDeliveryModes_ordinary_mail,
      { "ordinary-mail", "p1.ordinary-mail",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_p1_PhysicalDeliveryModes_special_delivery,
      { "special-delivery", "p1.special-delivery",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_p1_PhysicalDeliveryModes_express_mail,
      { "express-mail", "p1.express-mail",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_p1_PhysicalDeliveryModes_counter_collection,
      { "counter-collection", "p1.counter-collection",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_p1_PhysicalDeliveryModes_counter_collection_with_telephone_advice,
      { "counter-collection-with-telephone-advice", "p1.counter-collection-with-telephone-advice",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_p1_PhysicalDeliveryModes_counter_collection_with_telex_advice,
      { "counter-collection-with-telex-advice", "p1.counter-collection-with-telex-advice",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_p1_PhysicalDeliveryModes_counter_collection_with_teletex_advice,
      { "counter-collection-with-teletex-advice", "p1.counter-collection-with-teletex-advice",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_p1_PhysicalDeliveryModes_bureau_fax_delivery,
      { "bureau-fax-delivery", "p1.bureau-fax-delivery",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_p1_BuiltInEncodedInformationTypes_unknown,
      { "unknown", "p1.unknown",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_p1_BuiltInEncodedInformationTypes_ia5_text,
      { "ia5-text", "p1.ia5-text",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_p1_BuiltInEncodedInformationTypes_g3_facsimile,
      { "g3-facsimile", "p1.g3-facsimile",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_p1_BuiltInEncodedInformationTypes_g4_class_1,
      { "g4-class-1", "p1.g4-class-1",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_p1_BuiltInEncodedInformationTypes_teletex,
      { "teletex", "p1.teletex",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_p1_BuiltInEncodedInformationTypes_videotex,
      { "videotex", "p1.videotex",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_p1_BuiltInEncodedInformationTypes_voice,
      { "voice", "p1.voice",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_p1_BuiltInEncodedInformationTypes_sfd,
      { "sfd", "p1.sfd",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_p1_BuiltInEncodedInformationTypes_mixed_mode,
      { "mixed-mode", "p1.mixed-mode",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_p1_G3FacsimileNonBasicParameters_two_dimensional,
      { "two-dimensional", "p1.two-dimensional",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_p1_G3FacsimileNonBasicParameters_fine_resolution,
      { "fine-resolution", "p1.fine-resolution",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_p1_G3FacsimileNonBasicParameters_unlimited_length,
      { "unlimited-length", "p1.unlimited-length",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_p1_G3FacsimileNonBasicParameters_b4_length,
      { "b4-length", "p1.b4-length",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_p1_G3FacsimileNonBasicParameters_a3_width,
      { "a3-width", "p1.a3-width",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_p1_G3FacsimileNonBasicParameters_b4_width,
      { "b4-width", "p1.b4-width",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_p1_G3FacsimileNonBasicParameters_t6_coding,
      { "t6-coding", "p1.t6-coding",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_p1_G3FacsimileNonBasicParameters_uncompressed,
      { "uncompressed", "p1.uncompressed",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_p1_G3FacsimileNonBasicParameters_width_middle_864_of_1728,
      { "width-middle-864-of-1728", "p1.width-middle-864-of-1728",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_p1_G3FacsimileNonBasicParameters_width_middle_1216_of_1728,
      { "width-middle-1216-of-1728", "p1.width-middle-1216-of-1728",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_p1_G3FacsimileNonBasicParameters_resolution_type,
      { "resolution-type", "p1.resolution-type",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_p1_G3FacsimileNonBasicParameters_resolution_400x400,
      { "resolution-400x400", "p1.resolution-400x400",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_p1_G3FacsimileNonBasicParameters_resolution_300x300,
      { "resolution-300x300", "p1.resolution-300x300",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_p1_G3FacsimileNonBasicParameters_resolution_8x15,
      { "resolution-8x15", "p1.resolution-8x15",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_p1_G3FacsimileNonBasicParameters_edi,
      { "edi", "p1.edi",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_p1_G3FacsimileNonBasicParameters_dtm,
      { "dtm", "p1.dtm",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_p1_G3FacsimileNonBasicParameters_bft,
      { "bft", "p1.bft",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_p1_G3FacsimileNonBasicParameters_mixed_mode,
      { "mixed-mode", "p1.mixed-mode",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_p1_G3FacsimileNonBasicParameters_character_mode,
      { "character-mode", "p1.character-mode",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_p1_G3FacsimileNonBasicParameters_twelve_bits,
      { "twelve-bits", "p1.twelve-bits",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_p1_G3FacsimileNonBasicParameters_preferred_huffmann,
      { "preferred-huffmann", "p1.preferred-huffmann",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_p1_G3FacsimileNonBasicParameters_full_colour,
      { "full-colour", "p1.full-colour",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_p1_G3FacsimileNonBasicParameters_jpeg,
      { "jpeg", "p1.jpeg",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_p1_G3FacsimileNonBasicParameters_processable_mode_26,
      { "processable-mode-26", "p1.processable-mode-26",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},

/*--- End of included file: packet-p1-hfarr.c ---*/
#line 259 "../../asn1/p1/packet-p1-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_p1,
    &ett_p3,
    &ett_p1_content_unknown,
    &ett_p1_bilateral_information,
    &ett_p1_additional_information,
    &ett_p1_unknown_standard_extension,
    &ett_p1_unknown_extension_attribute_type,
    &ett_p1_unknown_tokendata_type,

/*--- Included file: packet-p1-ettarr.c ---*/
#line 1 "../../asn1/p1/packet-p1-ettarr.c"
    &ett_p1_MTABindArgument,
    &ett_p1_AuthenticatedArgument,
    &ett_p1_MTABindResult,
    &ett_p1_AuthenticatedResult,
    &ett_p1_MTS_APDU,
    &ett_p1_Message,
    &ett_p1_Report,
    &ett_p1_MessageTransferEnvelope,
    &ett_p1_PerMessageTransferFields,
    &ett_p1_SEQUENCE_SIZE_1_ub_transfers_OF_PerDomainBilateralInformation,
    &ett_p1_SET_OF_ExtensionField,
    &ett_p1_PerRecipientMessageTransferFields,
    &ett_p1_ProbeTransferEnvelope,
    &ett_p1_PerProbeTransferFields,
    &ett_p1_PerRecipientProbeTransferFields,
    &ett_p1_ReportTransferEnvelope,
    &ett_p1_ReportTransferContent,
    &ett_p1_PerReportTransferFields,
    &ett_p1_PerRecipientReportTransferFields,
    &ett_p1_PerDomainBilateralInformation,
    &ett_p1_T_bilateral_domain,
    &ett_p1_T_private_domain,
    &ett_p1_PerRecipientIndicators,
    &ett_p1_LastTraceInformation,
    &ett_p1_InternalTraceInformation,
    &ett_p1_InternalTraceInformationElement,
    &ett_p1_MTASuppliedInformation,
    &ett_p1_SEQUENCE_SIZE_1_ub_transfers_OF_TraceInformationElement,
    &ett_p1_TraceInformationElement,
    &ett_p1_DomainSuppliedInformation,
    &ett_p1_AdditionalActions,
    &ett_p1_OtherActions,
    &ett_p1_MTSBindArgument,
    &ett_p1_MTSBindResult,
    &ett_p1_ObjectName,
    &ett_p1_MessagesWaiting,
    &ett_p1_DeliveryQueue,
    &ett_p1_Credentials,
    &ett_p1_Password,
    &ett_p1_StrongCredentials,
    &ett_p1_ProtectedPassword,
    &ett_p1_Signature,
    &ett_p1_SecurityContext,
    &ett_p1_MessageSubmissionArgument,
    &ett_p1_MessageSubmissionResult,
    &ett_p1_ProbeSubmissionResult,
    &ett_p1_ImproperlySpecifiedRecipients,
    &ett_p1_Waiting,
    &ett_p1_SET_SIZE_0_ub_content_types_OF_ContentType,
    &ett_p1_Operations,
    &ett_p1_WaitingMessages,
    &ett_p1_MessageDeliveryArgument,
    &ett_p1_MessageDeliveryResult,
    &ett_p1_ReportDeliveryArgument,
    &ett_p1_ReportDeliveryResult,
    &ett_p1_SET_SIZE_1_MAX_OF_ExtensionField,
    &ett_p1_DeliveryControlArgument,
    &ett_p1_DeliveryControlResult,
    &ett_p1_RefusedOperation,
    &ett_p1_T_refused_argument,
    &ett_p1_Controls,
    &ett_p1_RegisterArgument,
    &ett_p1_SET_SIZE_1_ub_deliverable_class_OF_DeliverableClass,
    &ett_p1_RegisterResult,
    &ett_p1_T_non_empty_result,
    &ett_p1_ChangeCredentialsArgument,
    &ett_p1_UserAddress,
    &ett_p1_T_x121,
    &ett_p1_Redirections,
    &ett_p1_RecipientRedirection,
    &ett_p1_SET_SIZE_1_ub_redirection_classes_OF_RedirectionClass,
    &ett_p1_MessageClass,
    &ett_p1_SET_OF_Priority,
    &ett_p1_SEQUENCE_OF_Restriction,
    &ett_p1_EncodedInformationTypesConstraints,
    &ett_p1_RestrictedDelivery,
    &ett_p1_Restriction,
    &ett_p1_T_source_type,
    &ett_p1_ExactOrPattern,
    &ett_p1_RegistrationTypes,
    &ett_p1_T_standard_parameters,
    &ett_p1_T_type_extensions,
    &ett_p1_MessageSubmissionEnvelope,
    &ett_p1_PerMessageSubmissionFields,
    &ett_p1_PerRecipientMessageSubmissionFields,
    &ett_p1_ProbeSubmissionEnvelope,
    &ett_p1_PerProbeSubmissionFields,
    &ett_p1_PerRecipientProbeSubmissionFields,
    &ett_p1_MessageDeliveryEnvelope,
    &ett_p1_OtherMessageDeliveryFields,
    &ett_p1_ReportDeliveryEnvelope,
    &ett_p1_PerReportDeliveryFields,
    &ett_p1_PerRecipientReportDeliveryFields,
    &ett_p1_ReportType,
    &ett_p1_DeliveryReport,
    &ett_p1_NonDeliveryReport,
    &ett_p1_ContentTypes,
    &ett_p1_ContentType,
    &ett_p1_DeliveredContentType,
    &ett_p1_PerMessageIndicators_U,
    &ett_p1_OriginatorReportRequest,
    &ett_p1_DeliveryFlags,
    &ett_p1_OtherRecipientNames,
    &ett_p1_ExtensionType,
    &ett_p1_Criticality,
    &ett_p1_ExtensionField,
    &ett_p1_RequestedDeliveryMethod,
    &ett_p1_PhysicalDeliveryModes,
    &ett_p1_ContentCorrelator,
    &ett_p1_RedirectionHistory,
    &ett_p1_Redirection,
    &ett_p1_IntendedRecipientName,
    &ett_p1_DLExpansionHistory,
    &ett_p1_DLExpansion,
    &ett_p1_OriginatorAndDLExpansionHistory,
    &ett_p1_OriginatorAndDLExpansion,
    &ett_p1_PerRecipientReportFields,
    &ett_p1_T_report_type,
    &ett_p1_PerRecipientDeliveryReportFields,
    &ett_p1_PerRecipientNonDeliveryReportFields,
    &ett_p1_ReportingMTAName,
    &ett_p1_ExtendedCertificates,
    &ett_p1_ExtendedCertificate,
    &ett_p1_DLExemptedRecipients,
    &ett_p1_CertificateSelectors,
    &ett_p1_MTSIdentifier_U,
    &ett_p1_GlobalDomainIdentifier_U,
    &ett_p1_PrivateDomainIdentifier,
    &ett_p1_ORName_U,
    &ett_p1_ORAddress,
    &ett_p1_BuiltInStandardAttributes,
    &ett_p1_CountryName_U,
    &ett_p1_AdministrationDomainName_U,
    &ett_p1_PrivateDomainName,
    &ett_p1_PersonalName,
    &ett_p1_OrganizationalUnitNames,
    &ett_p1_BuiltInDomainDefinedAttributes,
    &ett_p1_BuiltInDomainDefinedAttribute,
    &ett_p1_ExtensionAttributes,
    &ett_p1_ExtensionAttribute,
    &ett_p1_TeletexPersonalName,
    &ett_p1_UniversalPersonalName,
    &ett_p1_TeletexOrganizationalUnitNames,
    &ett_p1_UniversalOrganizationalUnitNames,
    &ett_p1_UniversalOrBMPString,
    &ett_p1_T_character_encoding,
    &ett_p1_PhysicalDeliveryCountryName,
    &ett_p1_PostalCode,
    &ett_p1_UnformattedPostalAddress,
    &ett_p1_T_printable_address,
    &ett_p1_PDSParameter,
    &ett_p1_ExtendedNetworkAddress,
    &ett_p1_T_e163_4_address,
    &ett_p1_TeletexDomainDefinedAttributes,
    &ett_p1_TeletexDomainDefinedAttribute,
    &ett_p1_UniversalDomainDefinedAttributes,
    &ett_p1_UniversalDomainDefinedAttribute,
    &ett_p1_EncodedInformationTypes_U,
    &ett_p1_BuiltInEncodedInformationTypes,
    &ett_p1_ExtendedEncodedInformationTypes,
    &ett_p1_NonBasicParameters,
    &ett_p1_G3FacsimileNonBasicParameters,
    &ett_p1_TeletexNonBasicParameters,
    &ett_p1_Token,
    &ett_p1_AsymmetricTokenData,
    &ett_p1_T_name,
    &ett_p1_MTANameAndOptionalGDI,
    &ett_p1_AsymmetricToken,
    &ett_p1_TokenData,
    &ett_p1_MessageTokenSignedData,
    &ett_p1_MessageTokenEncryptedData,
    &ett_p1_SecurityLabel,
    &ett_p1_SecurityCategories,
    &ett_p1_SecurityCategory,
    &ett_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageTransferFields,
    &ett_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeTransferFields,
    &ett_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportTransferFields,
    &ett_p1_T_attempted,
    &ett_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientReportDeliveryFields,
    &ett_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientMessageSubmissionFields,
    &ett_p1_SEQUENCE_SIZE_1_ub_recipients_OF_PerRecipientProbeSubmissionFields,

/*--- End of included file: packet-p1-ettarr.c ---*/
#line 272 "../../asn1/p1/packet-p1-template.c"
  };

  module_t *p1_module;

  /* Register protocol */
  proto_p1 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("p1", dissect_p1, proto_p1);

  proto_p3 = proto_register_protocol("X.411 Message Access Service", "P3", "p3");

  /* Register fields and subtrees */
  proto_register_field_array(proto_p1, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  p1_extension_dissector_table = register_dissector_table("p1.extension", "P1-EXTENSION", FT_UINT32, BASE_DEC);
  p1_extension_attribute_dissector_table = register_dissector_table("p1.extension-attribute", "P1-EXTENSION-ATTRIBUTE", FT_UINT32, BASE_DEC);
  p1_tokendata_dissector_table = register_dissector_table("p1.tokendata", "P1-TOKENDATA", FT_UINT32, BASE_DEC);

  /* Register our configuration options for P1, particularly our port */

  p1_module = prefs_register_protocol_subtree("OSI/X.400", proto_p1, prefs_register_p1);

  prefs_register_uint_preference(p1_module, "tcp.port", "P1 TCP Port",
				 "Set the port for P1 operations (if other"
				 " than the default of 102)",
				 10, &global_p1_tcp_port);

  register_ber_syntax_dissector("P1 Message", proto_p1, dissect_p1_mts_apdu);
}


/*--- proto_reg_handoff_p1 --- */
void proto_reg_handoff_p1(void) {
  dissector_handle_t p1_handle;


/*--- Included file: packet-p1-dis-tab.c ---*/
#line 1 "../../asn1/p1/packet-p1-dis-tab.c"
  dissector_add_uint("p1.extension", 1, create_dissector_handle(dissect_RecipientReassignmentProhibited_PDU, proto_p1));
  dissector_add_uint("p1.extension", 2, create_dissector_handle(dissect_OriginatorRequestedAlternateRecipient_PDU, proto_p1));
  dissector_add_uint("p1.extension", 3, create_dissector_handle(dissect_DLExpansionProhibited_PDU, proto_p1));
  dissector_add_uint("p1.extension", 4, create_dissector_handle(dissect_ConversionWithLossProhibited_PDU, proto_p1));
  dissector_add_uint("p1.extension", 5, create_dissector_handle(dissect_LatestDeliveryTime_PDU, proto_p1));
  dissector_add_uint("p1.extension", 6, create_dissector_handle(dissect_RequestedDeliveryMethod_PDU, proto_p1));
  dissector_add_uint("p1.extension", 7, create_dissector_handle(dissect_PhysicalForwardingProhibited_PDU, proto_p1));
  dissector_add_uint("p1.extension", 8, create_dissector_handle(dissect_PhysicalForwardingAddressRequest_PDU, proto_p1));
  dissector_add_uint("p1.extension", 9, create_dissector_handle(dissect_PhysicalDeliveryModes_PDU, proto_p1));
  dissector_add_uint("p1.extension", 10, create_dissector_handle(dissect_RegisteredMailType_PDU, proto_p1));
  dissector_add_uint("p1.extension", 11, create_dissector_handle(dissect_RecipientNumberForAdvice_PDU, proto_p1));
  dissector_add_uint("p1.extension", 12, create_dissector_handle(dissect_PhysicalRenditionAttributes_PDU, proto_p1));
  dissector_add_uint("p1.extension", 13, create_dissector_handle(dissect_OriginatorReturnAddress_PDU, proto_p1));
  dissector_add_uint("p1.extension", 14, create_dissector_handle(dissect_PhysicalDeliveryReportRequest_PDU, proto_p1));
  dissector_add_uint("p1.extension", 15, create_dissector_handle(dissect_OriginatorCertificate_PDU, proto_p1));
  dissector_add_uint("p1.extension", 16, create_dissector_handle(dissect_MessageToken_PDU, proto_p1));
  dissector_add_uint("p1.extension", 17, create_dissector_handle(dissect_ContentConfidentialityAlgorithmIdentifier_PDU, proto_p1));
  dissector_add_uint("p1.extension", 18, create_dissector_handle(dissect_ContentIntegrityCheck_PDU, proto_p1));
  dissector_add_uint("p1.extension", 19, create_dissector_handle(dissect_MessageOriginAuthenticationCheck_PDU, proto_p1));
  dissector_add_uint("p1.extension", 20, create_dissector_handle(dissect_MessageSecurityLabel_PDU, proto_p1));
  dissector_add_uint("p1.extension", 21, create_dissector_handle(dissect_ProofOfSubmissionRequest_PDU, proto_p1));
  dissector_add_uint("p1.extension", 22, create_dissector_handle(dissect_ProofOfDeliveryRequest_PDU, proto_p1));
  dissector_add_uint("p1.extension", 23, create_dissector_handle(dissect_ContentCorrelator_PDU, proto_p1));
  dissector_add_uint("p1.extension", 24, create_dissector_handle(dissect_ProbeOriginAuthenticationCheck_PDU, proto_p1));
  dissector_add_uint("p1.extension", 25, create_dissector_handle(dissect_RedirectionHistory_PDU, proto_p1));
  dissector_add_uint("p1.extension", 26, create_dissector_handle(dissect_DLExpansionHistory_PDU, proto_p1));
  dissector_add_uint("p1.extension", 27, create_dissector_handle(dissect_PhysicalForwardingAddress_PDU, proto_p1));
  dissector_add_uint("p1.extension", 28, create_dissector_handle(dissect_RecipientCertificate_PDU, proto_p1));
  dissector_add_uint("p1.extension", 29, create_dissector_handle(dissect_ProofOfDelivery_PDU, proto_p1));
  dissector_add_uint("p1.extension", 30, create_dissector_handle(dissect_OriginatorAndDLExpansionHistory_PDU, proto_p1));
  dissector_add_uint("p1.extension", 31, create_dissector_handle(dissect_ReportingDLName_PDU, proto_p1));
  dissector_add_uint("p1.extension", 32, create_dissector_handle(dissect_ReportingMTACertificate_PDU, proto_p1));
  dissector_add_uint("p1.extension", 33, create_dissector_handle(dissect_ReportOriginAuthenticationCheck_PDU, proto_p1));
  dissector_add_uint("p1.extension", 35, create_dissector_handle(dissect_ProofOfSubmission_PDU, proto_p1));
  dissector_add_uint("p1.extension", 37, create_dissector_handle(dissect_TraceInformation_PDU, proto_p1));
  dissector_add_uint("p1.extension", 38, create_dissector_handle(dissect_InternalTraceInformation_PDU, proto_p1));
  dissector_add_uint("p1.extension", 39, create_dissector_handle(dissect_ReportingMTAName_PDU, proto_p1));
  dissector_add_uint("p1.extension", 40, create_dissector_handle(dissect_ExtendedCertificates_PDU, proto_p1));
  dissector_add_uint("p1.extension", 42, create_dissector_handle(dissect_DLExemptedRecipients_PDU, proto_p1));
  dissector_add_uint("p1.extension", 45, create_dissector_handle(dissect_CertificateSelectors_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 1, create_dissector_handle(dissect_CommonName_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 2, create_dissector_handle(dissect_TeletexCommonName_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 3, create_dissector_handle(dissect_TeletexOrganizationName_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 4, create_dissector_handle(dissect_TeletexPersonalName_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 5, create_dissector_handle(dissect_TeletexOrganizationalUnitNames_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 6, create_dissector_handle(dissect_TeletexDomainDefinedAttributes_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 7, create_dissector_handle(dissect_PDSName_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 8, create_dissector_handle(dissect_PhysicalDeliveryCountryName_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 9, create_dissector_handle(dissect_PostalCode_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 10, create_dissector_handle(dissect_PhysicalDeliveryOfficeName_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 11, create_dissector_handle(dissect_PhysicalDeliveryOfficeNumber_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 12, create_dissector_handle(dissect_ExtensionORAddressComponents_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 13, create_dissector_handle(dissect_PhysicalDeliveryPersonalName_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 14, create_dissector_handle(dissect_PhysicalDeliveryOrganizationName_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 15, create_dissector_handle(dissect_ExtensionPhysicalDeliveryAddressComponents_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 16, create_dissector_handle(dissect_UnformattedPostalAddress_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 17, create_dissector_handle(dissect_StreetAddress_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 18, create_dissector_handle(dissect_PostOfficeBoxAddress_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 19, create_dissector_handle(dissect_PosteRestanteAddress_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 20, create_dissector_handle(dissect_UniquePostalName_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 21, create_dissector_handle(dissect_LocalPostalAttributes_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 22, create_dissector_handle(dissect_ExtendedNetworkAddress_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 23, create_dissector_handle(dissect_TerminalType_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 24, create_dissector_handle(dissect_UniversalCommonName_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 25, create_dissector_handle(dissect_UniversalOrganizationName_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 26, create_dissector_handle(dissect_UniversalPersonalName_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 27, create_dissector_handle(dissect_UniversalOrganizationalUnitNames_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 28, create_dissector_handle(dissect_UniversalDomainDefinedAttributes_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 29, create_dissector_handle(dissect_UniversalPhysicalDeliveryOfficeName_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 30, create_dissector_handle(dissect_UniversalPhysicalDeliveryOfficeNumber_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 31, create_dissector_handle(dissect_UniversalExtensionORAddressComponents_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 32, create_dissector_handle(dissect_UniversalPhysicalDeliveryPersonalName_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 33, create_dissector_handle(dissect_UniversalPhysicalDeliveryOrganizationName_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 34, create_dissector_handle(dissect_UniversalExtensionPhysicalDeliveryAddressComponents_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 35, create_dissector_handle(dissect_UniversalUnformattedPostalAddress_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 36, create_dissector_handle(dissect_UniversalStreetAddress_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 37, create_dissector_handle(dissect_UniversalPostOfficeBoxAddress_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 38, create_dissector_handle(dissect_UniversalPosteRestanteAddress_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 39, create_dissector_handle(dissect_UniversalUniquePostalName_PDU, proto_p1));
  dissector_add_uint("p1.extension-attribute", 40, create_dissector_handle(dissect_UniversalLocalPostalAttributes_PDU, proto_p1));
  register_ber_oid_dissector("2.6.3.6.0", dissect_AsymmetricToken_PDU, proto_p1, "id-tok-asymmetricToken");
  register_ber_oid_dissector("2.6.5.6.0", dissect_MTANameAndOptionalGDI_PDU, proto_p1, "id-on-mtaName");
  dissector_add_uint("p1.tokendata", 1, create_dissector_handle(dissect_BindTokenSignedData_PDU, proto_p1));
  dissector_add_uint("p1.tokendata", 2, create_dissector_handle(dissect_MessageTokenSignedData_PDU, proto_p1));
  dissector_add_uint("p1.tokendata", 3, create_dissector_handle(dissect_MessageTokenEncryptedData_PDU, proto_p1));
  dissector_add_uint("p1.tokendata", 4, create_dissector_handle(dissect_BindTokenEncryptedData_PDU, proto_p1));
  register_ber_oid_dissector("2.6.5.2.0", dissect_ContentLength_PDU, proto_p1, "id-at-mhs-maximum-content-length");
  register_ber_oid_dissector("2.6.5.2.1", dissect_ExtendedContentType_PDU, proto_p1, "id-at-mhs-deliverable-content-types");
  register_ber_oid_dissector("2.6.5.2.2", dissect_ExtendedEncodedInformationType_PDU, proto_p1, "id-at-mhs-exclusively-acceptable-eits");
  register_ber_oid_dissector("2.6.5.2.3", dissect_ORName_PDU, proto_p1, "id-at-mhs-dl-members");
  register_ber_oid_dissector("2.6.5.2.6", dissect_ORAddress_PDU, proto_p1, "id-at-mhs-or-addresses");
  register_ber_oid_dissector("2.6.5.2.9", dissect_ExtendedContentType_PDU, proto_p1, "id-at-mhs-supported-content-types");
  register_ber_oid_dissector("2.6.5.2.12", dissect_ORName_PDU, proto_p1, "id-at-mhs-dl-archive-service");
  register_ber_oid_dissector("2.6.5.2.15", dissect_ORName_PDU, proto_p1, "id-at-mhs-dl-subscription-service");
  register_ber_oid_dissector("2.6.5.2.17", dissect_ExtendedEncodedInformationType_PDU, proto_p1, "id-at-mhs-acceptable-eits");
  register_ber_oid_dissector("2.6.5.2.18", dissect_ExtendedEncodedInformationType_PDU, proto_p1, "id-at-mhs-unacceptable-eits");
  register_ber_oid_dissector("2.16.840.1.101.2.1.5.47", dissect_ORName_PDU, proto_p1, "id-at-aLExemptedAddressProcessor");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.134.1", dissect_ORAddress_PDU, proto_p1, "id-at-collective-mhs-or-addresses");
  register_ber_oid_dissector("2.6.4.3.80", dissect_CertificateSelectors_PDU, proto_p1, "id-att-certificate-selectors");
  register_ber_oid_dissector("2.6.4.3.1", dissect_Content_PDU, proto_p1, "id-att-content");
  register_ber_oid_dissector("2.6.4.3.3", dissect_ContentCorrelator_PDU, proto_p1, "id-att-content-correlator");
  register_ber_oid_dissector("2.6.4.3.4", dissect_ContentIdentifier_PDU, proto_p1, "id-att-content-identifier");
  register_ber_oid_dissector("2.6.4.3.5", dissect_ContentIntegrityCheck_PDU, proto_p1, "id-att-content-inetgrity-check");
  register_ber_oid_dissector("2.6.4.3.6", dissect_ContentLength_PDU, proto_p1, "id-att-content-length");
  register_ber_oid_dissector("2.6.4.3.8", dissect_ExtendedContentType_PDU, proto_p1, "id-att-content-type");
  register_ber_oid_dissector("2.6.4.3.9", dissect_ConversionWithLossProhibited_PDU, proto_p1, "id-att-conversion-with-loss-prohibited");
  register_ber_oid_dissector("2.6.4.3.51", dissect_DeferredDeliveryTime_PDU, proto_p1, "id-att-deferred-delivery-time");
  register_ber_oid_dissector("2.6.4.3.13", dissect_DeliveryFlags_PDU, proto_p1, "id-att-delivery-flags");
  register_ber_oid_dissector("2.6.4.3.78", dissect_ORName_PDU, proto_p1, "id-att-dl-exempted-recipients");
  register_ber_oid_dissector("2.6.4.3.14", dissect_DLExpansion_PDU, proto_p1, "id-att-dl-expansion-history");
  register_ber_oid_dissector("2.6.4.3.53", dissect_DLExpansionProhibited_PDU, proto_p1, "id-att-dl-expansion-prohibited");
  register_ber_oid_dissector("2.6.4.3.54", dissect_InternalTraceInformationElement_PDU, proto_p1, "id-att-internal-trace-information");
  register_ber_oid_dissector("2.6.4.3.55", dissect_LatestDeliveryTime_PDU, proto_p1, "id-att-latest-delivery-time");
  register_ber_oid_dissector("2.6.4.3.18", dissect_MessageDeliveryEnvelope_PDU, proto_p1, "id-att-message-delivery-envelope");
  register_ber_oid_dissector("2.6.4.3.20", dissect_MessageDeliveryTime_PDU, proto_p1, "id-att-message-delivery-time");
  register_ber_oid_dissector("2.6.4.3.19", dissect_MTSIdentifier_PDU, proto_p1, "id-att-message-identifier");
  register_ber_oid_dissector("2.6.4.3.21", dissect_MessageOriginAuthenticationCheck_PDU, proto_p1, "id-at-message-orgin-authentication-check");
  register_ber_oid_dissector("2.6.4.3.22", dissect_MessageSecurityLabel_PDU, proto_p1, "id-att-message-security-label");
  register_ber_oid_dissector("2.6.4.3.59", dissect_MessageSubmissionEnvelope_PDU, proto_p1, "id-att-message-submission-envelope");
  register_ber_oid_dissector("2.6.4.3.23", dissect_MessageSubmissionTime_PDU, proto_p1, "id-att-message-submission-time");
  register_ber_oid_dissector("2.6.4.3.24", dissect_MessageToken_PDU, proto_p1, "id-att-message-token");
  register_ber_oid_dissector("2.6.4.3.81", dissect_ExtendedCertificates_PDU, proto_p1, "id-att-multiple-originator-certificates");
  register_ber_oid_dissector("2.6.4.3.17", dissect_ORName_PDU, proto_p1, "id-att-originally-intended-recipient-name");
  register_ber_oid_dissector("2.6.4.3.62", dissect_OriginatingMTACertificate_PDU, proto_p1, "id-att-originating-MTA-certificate");
  register_ber_oid_dissector("2.6.4.3.26", dissect_OriginatorCertificate_PDU, proto_p1, "id-att-originator-certificate");
  register_ber_oid_dissector("2.6.4.3.27", dissect_ORName_PDU, proto_p1, "id-att-originator-name");
  register_ber_oid_dissector("2.6.4.3.63", dissect_OriginatorReportRequest_PDU, proto_p1, "id-att-originator-report-request");
  register_ber_oid_dissector("2.6.4.3.64", dissect_OriginatorReturnAddress_PDU, proto_p1, "id-att-originator-return-address");
  register_ber_oid_dissector("2.6.4.3.28", dissect_ORName_PDU, proto_p1, "id-att-other-recipient-names");
  register_ber_oid_dissector("2.6.4.3.65", dissect_PerMessageIndicators_PDU, proto_p1, "id-att-per-message-indicators");
  register_ber_oid_dissector("2.6.4.3.66", dissect_PerRecipientMessageSubmissionFields_PDU, proto_p1, "id-att-per-recipient-message-submission-fields");
  register_ber_oid_dissector("2.6.4.3.67", dissect_PerRecipientProbeSubmissionFields_PDU, proto_p1, "id-att-per-recipient-probe-submission-fields");
  register_ber_oid_dissector("2.6.4.3.30", dissect_PerRecipientReportDeliveryFields_PDU, proto_p1, "id-att-per-recipient-report-delivery-fields");
  register_ber_oid_dissector("2.6.4.3.31", dissect_Priority_PDU, proto_p1, "id-att-priority");
  register_ber_oid_dissector("2.6.4.3.68", dissect_ProbeOriginAuthenticationCheck_PDU, proto_p1, "id-att-probe-origin-authentication-check");
  register_ber_oid_dissector("2.6.4.3.69", dissect_ProbeSubmissionEnvelope_PDU, proto_p1, "id-att-probe-submission-envelope");
  register_ber_oid_dissector("2.6.4.3.32", dissect_ProofOfDeliveryRequest_PDU, proto_p1, "id-att-proof-of-delivery-request");
  register_ber_oid_dissector("2.6.4.3.70", dissect_ProofOfSubmission_PDU, proto_p1, "id-att-proof-of-submission");
  register_ber_oid_dissector("2.6.4.3.82", dissect_ExtendedCertificates_PDU, proto_p1, "id-att-recipient-certificate");
  register_ber_oid_dissector("2.6.4.3.71", dissect_ORName_PDU, proto_p1, "id-att-recipient-names");
  register_ber_oid_dissector("2.6.4.3.72", dissect_RecipientReassignmentProhibited_PDU, proto_p1, "id-att-recipient-reassignment-prohibited");
  register_ber_oid_dissector("2.6.4.3.33", dissect_Redirection_PDU, proto_p1, "id-at-redirection-history");
  register_ber_oid_dissector("2.6.4.3.34", dissect_ReportDeliveryEnvelope_PDU, proto_p1, "id-att-report-delivery-envelope");
  register_ber_oid_dissector("2.6.4.3.35", dissect_ReportingDLName_PDU, proto_p1, "id-att-reporting-DL-name");
  register_ber_oid_dissector("2.6.4.3.36", dissect_ReportingMTACertificate_PDU, proto_p1, "id-att-reporting-MTA-certificate");
  register_ber_oid_dissector("2.6.4.3.37", dissect_ReportOriginAuthenticationCheck_PDU, proto_p1, "id-att-report-origin-authentication-check");
  register_ber_oid_dissector("2.6.4.3.38", dissect_SecurityClassification_PDU, proto_p1, "id-att-security-classification");
  register_ber_oid_dissector("2.6.4.3.40", dissect_SubjectSubmissionIdentifier_PDU, proto_p1, "id-att-subject-submission-identifier");
  register_ber_oid_dissector("2.6.4.3.41", dissect_ORName_PDU, proto_p1, "id-att-this-recipient-name");
  register_ber_oid_dissector("2.6.4.3.75", dissect_TraceInformationElement_PDU, proto_p1, "id-att-trace-information");
  register_ber_oid_dissector("2.6.1.7.36", dissect_MessageToken_PDU, proto_p1, "id-hat-forwarded-token");


/*--- End of included file: packet-p1-dis-tab.c ---*/
#line 308 "../../asn1/p1/packet-p1-template.c"

  /* APPLICATION CONTEXT */

  oid_add_from_string("id-ac-mts-transfer","2.6.0.1.6");

  /* ABSTRACT SYNTAXES */

  p1_handle = find_dissector("p1");
  register_rtse_oid_dissector_handle("2.6.0.2.12", p1_handle, 0, "id-as-mta-rtse", TRUE);
  register_rtse_oid_dissector_handle("2.6.0.2.7", p1_handle, 0, "id-as-mtse", FALSE);

  register_rtse_oid_dissector_handle("applicationProtocol.1", p1_handle, 0, "mts-transfer-protocol-1984", FALSE);
  register_rtse_oid_dissector_handle("applicationProtocol.12", p1_handle, 0, "mta-transfer-protocol", FALSE);

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

static void
prefs_register_p1(void)
{
  static guint tcp_port = 0;

  /* de-register the old port */
  /* port 102 is registered by TPKT - don't undo this! */
  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_delete_uint("tcp.port", tcp_port, tpkt_handle);

  /* Set our port number for future use */
  tcp_port = global_p1_tcp_port;

  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_add_uint("tcp.port", tcp_port, tpkt_handle);

}
