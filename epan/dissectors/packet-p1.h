/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-p1.h                                                                */
/* asn2wrs.py -b -C -q -L -p p1 -c ./p1.cnf -s ./packet-p1-template -D . -O ../.. MTAAbstractService.asn MTSAbstractService.asn MTSAccessProtocol.asn MHSProtocolObjectIdentifiers.asn MTSUpperBounds.asn */

/* packet-p3.h
 * Routines for X.411 (X.400 Message Transfer) packet dissection
 * Graeme Lunt 2005
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_P1_H
#define PACKET_P1_H

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
#define id_mhs_mod                     id_mhs_protocols".0"
#define id_ac                          id_mhs_protocols".1"
#define id_as                          id_mhs_protocols".2"
#define id_ase                         id_mhs_protocols".3"
#define id_mod_mts_access_protocol     id_mhs_mod".1"
#define id_mod_ms_access_protocol      id_mhs_mod".2"
#define id_mod_mts_transfer_protocol   id_mhs_mod".3"
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
#define ub_additional_info             1024
#define ub_bilateral_info              1024
#define ub_bit_options                 16
#define ub_built_in_content_type       32767
#define ub_built_in_encoded_information_types 32
#define ub_certificates                64
#define ub_common_name_length          64
#define ub_content_correlator_length   512
#define ub_content_id_length           16
#define ub_content_length              2147483647
#define ub_content_types               1024
#define ub_country_name_alpha_length   2
#define ub_country_name_numeric_length 3
#define ub_diagnostic_codes            32767
#define ub_deliverable_class           256
#define ub_dl_expansions               512
#define ub_domain_defined_attributes   4
#define ub_domain_defined_attribute_type_length 8
#define ub_domain_defined_attribute_value_length 128
#define ub_domain_name_length          16
#define ub_encoded_information_types   1024
#define ub_extension_attributes        256
#define ub_extension_types             256
#define ub_e163_4_number_length        15
#define ub_e163_4_sub_address_length   40
#define ub_generation_qualifier_length 3
#define ub_given_name_length           16
#define ub_initials_length             5
#define ub_integer_options             256
#define ub_labels_and_redirections     256
#define ub_local_id_length             32
#define ub_mta_name_length             32
#define ub_mts_user_types              256
#define ub_numeric_user_id_length      32
#define ub_organization_name_length    64
#define ub_organizational_unit_name_length 32
#define ub_organizational_units        4
#define ub_orig_and_dl_expansions      513
#define ub_password_length             62
#define ub_pds_name_length             16
#define ub_pds_parameter_length        30
#define ub_pds_physical_address_lines  6
#define ub_postal_code_length          16
#define ub_privacy_mark_length         128
#define ub_queue_size                  2147483647
#define ub_reason_codes                32767
#define ub_recipient_number_for_advice_length 32
#define ub_recipients                  32767
#define ub_redirection_classes         256
#define ub_redirections                512
#define ub_restrictions                1024
#define ub_security_categories         64
#define ub_security_labels             256
#define ub_security_problems           256
#define ub_string_length               2147483647
#define ub_supplementary_info_length   256
#define ub_surname_length              40
#define ub_teletex_private_use_length  128
#define ub_terminal_id_length          24
#define ub_transfers                   512
#define ub_tsap_id_length              16
#define ub_unformatted_address_length  180
#define ub_universal_generation_qualifier_length 16
#define ub_universal_given_name_length 40
#define ub_universal_initials_length   16
#define ub_universal_surname_length    64
#define ub_x121_address_length         16

void p1_initialize_content_globals (asn1_ctx_t* actx, proto_tree *tree, bool report_unknown_cont_type);
const char* p1_get_last_oraddress(asn1_ctx_t* actx);
int dissect_p1_mts_apdu (tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data);
extern const value_string p1_Credentials_vals[];
extern const value_string p1_SecurityProblem_vals[];
extern const value_string p1_ContentType_vals[];
extern const value_string p1_NonDeliveryReasonCode_vals[];
extern const value_string p1_NonDeliveryDiagnosticCode_vals[];
int dissect_p1_InitiatorCredentials(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_ResponderCredentials(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_Credentials(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_SecurityContext(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_ImproperlySpecifiedRecipients(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_SecurityProblem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_MessageSubmissionIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_MessageSubmissionTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_ProbeSubmissionIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_ProbeSubmissionTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_EncodedInformationTypesConstraints(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_MessageSubmissionEnvelope(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_ProbeSubmissionEnvelope(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_PerRecipientProbeSubmissionFields(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_OtherMessageDeliveryFields(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_OriginatorName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_OriginalEncodedInformationTypes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_ContentType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_ExtendedContentType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_ContentIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_PerMessageIndicators(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_ContentLength(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_MessageDeliveryIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_MessageDeliveryTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_NonDeliveryReasonCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_NonDeliveryDiagnosticCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_SupplementaryInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_ExtensionField(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_RequestedDeliveryMethod(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_MessageToken(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_ContentIntegrityCheck(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_MessageOriginAuthenticationCheck(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_MessageSecurityLabel(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_OriginatingMTACertificate(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_ProofOfSubmission(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_ExtendedCertificates(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_Content(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_ORAddressAndOrDirectoryName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_ORName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_ORAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_UniversalOrBMPString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_EncodedInformationTypes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_G3FacsimileNonBasicParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_TeletexNonBasicParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_SecurityLabel(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p1_MessageSecurityLabel_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

void proto_reg_handoff_p1(void);
void proto_register_p1(void);

#endif  /* PACKET_P1_H */
