/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-atn-ulcs.c                                                          */
/* asn2wrs.py -u -L -p atn-ulcs -c ./atn-ulcs.cnf -s ./packet-atn-ulcs-template -D . -O ../.. atn-ulcs.asn */

/* Input file: packet-atn-ulcs-template.c */

#line 1 "./asn1/atn-ulcs/packet-atn-ulcs-template.c"
/* packet-atn-ulcs.c
 * By Mathias Guettler <guettler@web.de>
 * Copyright 2013
 *
 * Routines for ATN upper layer
 * protocol packet disassembly

 * ATN upper layers are embedded within OSI Layer 4 (COTP).
 *
 * ATN upper layers contain:
 * Session Layer (NUL protocol option)
 * Presentation Layer (NUL protocol option)
 * ATN upper Layer/Application (ACSE PDU or PDV-list PDU)

 * ATN applications protocols (i.e. CM or CPDLC) are contained within
 * ACSE user-information or PDV presentation data.

 * details see:
 * http://en.wikipedia.org/wiki/CPDLC
 * http://members.optusnet.com.au/~cjr/introduction.htm

 * standards:
 * http://legacy.icao.int/anb/panels/acp/repository.cfm

 * note:
 * We are dealing with ATN/ULCS aka ICAO Doc 9705 Ed2 here
 * (don't think there is an ULCS equivalent for "FANS-1/A ").

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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 developer comments:
why not using existing ses, pres and acse dissectors ?
    ATN upper layers are derived from OSI standards for session,
    presentation and application but the encoding differs
    (it's PER instead of BER encoding to save bandwith).
    Session and presentation use the "null" encoding option,
    meaning that they are only present at connection establishment
    and ommitted otherwise.
    Instead of adapting existing dissectors it seemed simpler and cleaner
    to implement everything the new atn-ulcs dissector.

why using conversations ?
    PER encoded user data is ambigous; the same encoding may apply to a CM or
    CPDLC PDU. The workaround is to decode on a transport connection basis.
    I use my own version of conversations to identify
    the transport connection the PDU belongs to for the standard functions
    from "conversation.h" didn't work out.

what is the use of AARQ/AARE data ?
    Converstions should be maintained on the COTP layer in a standard way
    for there are usually more packets available than in the layers above.
    In the worst case my dissector is called from a DT packet which
    has destination references but no source reference.
    I have to guess the reference used the other way round
    (curently I am using ACSE PDU'S used during OSI connection establishment for that).
    The idea is that each ACSE AARQ is answered by ACSE AARE and having this sequence
    I have all the source/destination references for this transport connection.
    I use AARQ/AARE data to store the source/destination reference of AARQ as well
    as the optional ae-qualifier which tells me the application and
    the dissector I have to use.
    This approach donesn't work well when there are interleaving AARQ/AARE sequences for
    the same aircraft.

which ATN standard is supported ?
    The dissector has been tested with ICAO doc9705 Edition2 compliant traffic.
    No ATN Secutity is supported.
    note:
    The ATN upper layers are derived from OSI standards (ICAO DOC 9705)
    while ATN/IPS (ICAO DOC 9896) which is entirely based on IPV6.

*/

/*
 known defects/deficiencies:

- user-information within AARE is sometines not decoded due to an unset flag
    (the field is optional). As far as I can tell asn2wrs is right here,
    but on the other hand I know that in all of this cases user-information
    is present and is processed by the ATN end system.
    Maybe a true ATN expert may help me out here.

  - The conversation handling is based on src/dst addresses as well as
    source or destination references depending on the TP4 packet type.
    This means that after some time these references get reused for
    new conversations. This almost certain happens for traces longer
    than one day rendering this dissector unsuitable for captures exceeding
    this one day.

*/

#include "config.h"

#ifndef _MSC_VER
#include <stdint.h>
#endif


#include <epan/packet.h>
#include <epan/address.h>
#include <epan/conversation.h>
#include <epan/osi-utils.h>
#include "packet-ber.h"
#include "packet-per.h"
#include "packet-atn-ulcs.h"

#define ATN_ACSE_PROTO "ICAO Doc9705 ULCS ACSE (ISO 8649/8650-1:1996)"
#define ATN_ULCS_PROTO "ICAO Doc9705 ULCS"

void proto_register_atn_ulcs(void);
void proto_reg_handoff_atn_ulcs(void);

static heur_dissector_list_t atn_ulcs_heur_subdissector_list;

/* presentation subdissectors i.e. CM, CPDLC */
static dissector_handle_t atn_cm_handle = NULL;
static dissector_handle_t atn_cpdlc_handle = NULL;

static int proto_atn_ulcs          = -1;
static guint32 ulcs_context_value = 0;
static const char *object_identifier_id;

static wmem_tree_t *aarq_data_tree = NULL;
static wmem_tree_t *atn_conversation_tree = NULL;


static proto_tree *root_tree = NULL;

/* forward declarations for functions generated from asn1 */
static int dissect_atn_ulcs_T_externalt_encoding_single_asn1_type(
    tvbuff_t *tvb _U_,
    int offset _U_,
    asn1_ctx_t *actx _U_,
    proto_tree *tree _U_,
    int hf_index
    _U_);

static int dissect_atn_ulcs_T_externalt_encoding_octet_aligned(
    tvbuff_t *tvb _U_,
    int offset _U_,
    asn1_ctx_t *actx _U_,
    proto_tree *tree _U_,
    int hf_index _U_);

static int dissect_atn_ulcs_T_externalt_encoding_arbitrary(
    tvbuff_t *tvb _U_,
    int offset _U_,
    asn1_ctx_t *actx _U_,
    proto_tree *tree _U_,
    int hf_index _U_);

static int dissect_ACSE_apdu_PDU(
    tvbuff_t *tvb _U_,
    packet_info *pinfo _U_,
    proto_tree *tree _U_,
    void *data _U_);

guint32 dissect_per_object_descriptor_t(
    tvbuff_t *tvb,
    guint32 offset,
    asn1_ctx_t *actx,
    proto_tree *tree,
    int hf_index,
    tvbuff_t **value_tvb);

static gint dissect_atn_ulcs(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree  *tree,
    void *data _U_);


/*--- Included file: packet-atn-ulcs-hf.c ---*/
#line 1 "./asn1/atn-ulcs/packet-atn-ulcs-hf.c"
static int hf_atn_ulcs_Fully_encoded_data_PDU = -1;  /* Fully_encoded_data */
static int hf_atn_ulcs_ACSE_apdu_PDU = -1;        /* ACSE_apdu */
static int hf_atn_ulcs_Fully_encoded_data_item = -1;  /* PDV_list */
static int hf_atn_ulcs_transfer_syntax_name = -1;  /* Transfer_syntax_name */
static int hf_atn_ulcs_presentation_context_identifier = -1;  /* Presentation_context_identifier */
static int hf_atn_ulcs_presentation_data_values = -1;  /* T_presentation_data_values */
static int hf_atn_ulcs_pdv_list_presentation_data_values_single_asn1_type = -1;  /* T_pdv_list_presentation_data_values_single_asn1_type */
static int hf_atn_ulcs_octet_aligned = -1;        /* OCTET_STRING */
static int hf_atn_ulcs_pdv_list_presentation_data_values_arbitrary = -1;  /* T_pdv_list_presentation_data_values_arbitrary */
static int hf_atn_ulcs_direct_reference = -1;     /* OBJECT_IDENTIFIER */
static int hf_atn_ulcs_indirect_reference = -1;   /* INTEGER */
static int hf_atn_ulcs_data_value_descriptor = -1;  /* T_data_value_descriptor */
static int hf_atn_ulcs_encoding = -1;             /* T_encoding */
static int hf_atn_ulcs_externalt_encoding_single_asn1_type = -1;  /* T_externalt_encoding_single_asn1_type */
static int hf_atn_ulcs_externalt_encoding_octet_aligned = -1;  /* T_externalt_encoding_octet_aligned */
static int hf_atn_ulcs_externalt_encoding_arbitrary = -1;  /* T_externalt_encoding_arbitrary */
static int hf_atn_ulcs_aarq = -1;                 /* AARQ_apdu */
static int hf_atn_ulcs_aare = -1;                 /* AARE_apdu */
static int hf_atn_ulcs_rlrq = -1;                 /* RLRQ_apdu */
static int hf_atn_ulcs_rlre = -1;                 /* RLRE_apdu */
static int hf_atn_ulcs_abrt = -1;                 /* ABRT_apdu */
static int hf_atn_ulcs_aarq_apdu_protocol_version = -1;  /* T_aarq_apdu_protocol_version */
static int hf_atn_ulcs_application_context_name = -1;  /* Application_context_name */
static int hf_atn_ulcs_called_AP_title = -1;      /* AP_title */
static int hf_atn_ulcs_called_AE_qualifier = -1;  /* AE_qualifier */
static int hf_atn_ulcs_called_AP_invocation_identifier = -1;  /* AP_invocation_identifier */
static int hf_atn_ulcs_called_AE_invocation_identifier = -1;  /* AE_invocation_identifier */
static int hf_atn_ulcs_calling_AP_title = -1;     /* AP_title */
static int hf_atn_ulcs_calling_AE_qualifier = -1;  /* AE_qualifier */
static int hf_atn_ulcs_calling_AP_invocation_identifier = -1;  /* AP_invocation_identifier */
static int hf_atn_ulcs_calling_AE_invocation_identifier = -1;  /* AE_invocation_identifier */
static int hf_atn_ulcs_sender_acse_requirements = -1;  /* ACSE_requirements */
static int hf_atn_ulcs_mechanism_name = -1;       /* Mechanism_name */
static int hf_atn_ulcs_calling_authentication_value = -1;  /* Authentication_value */
static int hf_atn_ulcs_application_context_name_list = -1;  /* Application_context_name_list */
static int hf_atn_ulcs_implementation_information = -1;  /* Implementation_data */
static int hf_atn_ulcs_user_information = -1;     /* Association_information */
static int hf_atn_ulcs_aare_apdu_protocol_version = -1;  /* T_aare_apdu_protocol_version */
static int hf_atn_ulcs_result = -1;               /* Associate_result */
static int hf_atn_ulcs_result_source_diagnostic = -1;  /* Associate_source_diagnostic */
static int hf_atn_ulcs_responding_AP_title = -1;  /* AP_title */
static int hf_atn_ulcs_responding_AE_qualifier = -1;  /* AE_qualifier */
static int hf_atn_ulcs_responding_AP_invocation_identifier = -1;  /* AP_invocation_identifier */
static int hf_atn_ulcs_responding_AE_invocation_identifier = -1;  /* AE_invocation_identifier */
static int hf_atn_ulcs_responder_acse_requirements = -1;  /* ACSE_requirements */
static int hf_atn_ulcs_responding_authentication_value = -1;  /* Authentication_value */
static int hf_atn_ulcs_rlrq_apdu_request_reason = -1;  /* Release_request_reason */
static int hf_atn_ulcs_rlre_apdu_response_reason = -1;  /* Release_response_reason */
static int hf_atn_ulcs_abort_source = -1;         /* ABRT_source */
static int hf_atn_ulcs_abort_diagnostic = -1;     /* ABRT_diagnostic */
static int hf_atn_ulcs_Application_context_name_list_item = -1;  /* Application_context_name */
static int hf_atn_ulcs_ap_title_form2 = -1;       /* AP_title_form2 */
static int hf_atn_ulcs_ap_title_form1 = -1;       /* AP_title_form1 */
static int hf_atn_ulcs_ae_qualifier_form2 = -1;   /* AE_qualifier_form2 */
static int hf_atn_ulcs_ae_qualifier_form1 = -1;   /* AE_qualifier_form1 */
static int hf_atn_ulcs_acse_service_user = -1;    /* T_acse_service_user */
static int hf_atn_ulcs_acse_service_provider = -1;  /* T_acse_service_provider */
static int hf_atn_ulcs_Association_information_item = -1;  /* EXTERNALt */
static int hf_atn_ulcs_charstring = -1;           /* OCTET_STRING */
static int hf_atn_ulcs_bitstring = -1;            /* BIT_STRING */
static int hf_atn_ulcs_external = -1;             /* EXTERNAL */
static int hf_atn_ulcs_other = -1;                /* T_other */
static int hf_atn_ulcs_other_mechanism_name = -1;  /* OBJECT_IDENTIFIER */
static int hf_atn_ulcs_other_mechanism_value = -1;  /* T_other_mechanism_value */
static int hf_atn_ulcs_rdnSequence = -1;          /* RDNSequence */
static int hf_atn_ulcs_RDNSequence_item = -1;     /* RelativeDistinguishedName */
static int hf_atn_ulcs_RelativeDistinguishedName_item = -1;  /* AttributeTypeAndValue */
static int hf_atn_ulcs_null = -1;                 /* NULL */
/* named bits */
static int hf_atn_ulcs_T_aarq_apdu_protocol_version_version1 = -1;
static int hf_atn_ulcs_T_aare_apdu_protocol_version_version1 = -1;
static int hf_atn_ulcs_ACSE_requirements_authentication = -1;
static int hf_atn_ulcs_ACSE_requirements_application_context_negotiation = -1;

/*--- End of included file: packet-atn-ulcs-hf.c ---*/
#line 190 "./asn1/atn-ulcs/packet-atn-ulcs-template.c"


/*--- Included file: packet-atn-ulcs-ett.c ---*/
#line 1 "./asn1/atn-ulcs/packet-atn-ulcs-ett.c"
static gint ett_atn_ulcs_Fully_encoded_data = -1;
static gint ett_atn_ulcs_PDV_list = -1;
static gint ett_atn_ulcs_T_presentation_data_values = -1;
static gint ett_atn_ulcs_EXTERNALt = -1;
static gint ett_atn_ulcs_T_encoding = -1;
static gint ett_atn_ulcs_ACSE_apdu = -1;
static gint ett_atn_ulcs_AARQ_apdu = -1;
static gint ett_atn_ulcs_T_aarq_apdu_protocol_version = -1;
static gint ett_atn_ulcs_AARE_apdu = -1;
static gint ett_atn_ulcs_T_aare_apdu_protocol_version = -1;
static gint ett_atn_ulcs_RLRQ_apdu = -1;
static gint ett_atn_ulcs_RLRE_apdu = -1;
static gint ett_atn_ulcs_ABRT_apdu = -1;
static gint ett_atn_ulcs_ACSE_requirements = -1;
static gint ett_atn_ulcs_Application_context_name_list = -1;
static gint ett_atn_ulcs_AP_title = -1;
static gint ett_atn_ulcs_AE_qualifier = -1;
static gint ett_atn_ulcs_Associate_source_diagnostic = -1;
static gint ett_atn_ulcs_Association_information = -1;
static gint ett_atn_ulcs_Authentication_value = -1;
static gint ett_atn_ulcs_T_other = -1;
static gint ett_atn_ulcs_Name = -1;
static gint ett_atn_ulcs_RDNSequence = -1;
static gint ett_atn_ulcs_RelativeDistinguishedName = -1;
static gint ett_atn_ulcs_AttributeTypeAndValue = -1;

/*--- End of included file: packet-atn-ulcs-ett.c ---*/
#line 192 "./asn1/atn-ulcs/packet-atn-ulcs-template.c"
static gint ett_atn_ulcs = -1;
static gint ett_atn_acse = -1;


/*--- Included file: packet-atn-ulcs-fn.c ---*/
#line 1 "./asn1/atn-ulcs/packet-atn-ulcs-fn.c"


static int
dissect_atn_ulcs_Transfer_syntax_name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string atn_ulcs_Presentation_context_identifier_vals[] = {
  {   1, "acse-apdu" },
  {   2, "reserved" },
  {   3, "user-ase-apdu" },
  { 0, NULL }
};


static int
dissect_atn_ulcs_Presentation_context_identifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

    offset = dissect_per_constrained_integer(
        tvb,
        offset,
        actx,
        tree,
        hf_index,
        1U,
        127U,
        &ulcs_context_value,
        TRUE);


  return offset;
}



static int
dissect_atn_ulcs_T_pdv_list_presentation_data_values_single_asn1_type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_atn_ulcs_OCTET_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_atn_ulcs_T_pdv_list_presentation_data_values_arbitrary(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

    packet_info * pinfo = actx->pinfo;
    tvbuff_t *tvb_usr = NULL;
    proto_tree *atn_ulcs_tree = NULL;
    atn_conversation_t *atn_cv = NULL;
    heur_dtbl_entry_t *hdtbl_entry;

    /* extract bitstring into new tvb buffer */
    offset = dissect_per_bit_string(
        tvb,
        offset,
        actx,
        tree,
        hf_index,
        NO_BOUND,
        NO_BOUND,
        FALSE,
        &tvb_usr,
        NULL);

    if (tvb_usr) {
      /* call appropiate dissector for bitstring data */
      switch(ulcs_context_value){
          case  1: /* ACSE PDU*/
              atn_ulcs_tree = proto_tree_add_subtree(
                  root_tree, tvb, offset, 0,
                  ett_atn_acse, NULL, ATN_ACSE_PROTO );

              dissect_ACSE_apdu_PDU(
                  tvb_new_subset_remaining(tvb_usr, 0),
                  pinfo,
                  atn_ulcs_tree, NULL);
              break;
            case  3: /* USER data; call subdissector for CM, CPDLC ...  */

                /* using dstref for PDV-list only occurrs in DT */
                atn_cv = find_atn_conversation(
                    &pinfo->dst,
                    pinfo->clnp_dstref,
                    &pinfo->src);

                if(atn_cv) {
                    switch(atn_cv->ae_qualifier){
                        case cma: /* contact management */
                            call_dissector_with_data(
                                atn_cm_handle,
                                tvb_new_subset_remaining(tvb_usr, 0),
                                pinfo,
                                root_tree,
                                NULL);
                            break;
                        case cpdlc: /* plain old cpdlc */
                        case pmcpdlc: /* protected mode cpdlc */
                            call_dissector_with_data(
                                atn_cpdlc_handle,
                                tvb_new_subset_remaining(tvb_usr, 0),
                                pinfo,
                                root_tree,
                                NULL);
                            break;
                        default: /* unknown or unhandled datalink application */
                            dissector_try_heuristic(
                                atn_ulcs_heur_subdissector_list,
                                tvb_new_subset_remaining(tvb_usr,0),
                                actx->pinfo,
                                root_tree,
                                &hdtbl_entry,
                                NULL);
                            break;
                    }
                }
                else{
                    dissector_try_heuristic(
                        atn_ulcs_heur_subdissector_list,
                        tvb_new_subset_remaining(tvb_usr,0),
                        actx->pinfo,
                        root_tree,
                        &hdtbl_entry,
                        NULL);
                }
                break;
            default:
                break;
      } /* switch(ulcs_context_value) */
    }


  return offset;
}


static const value_string atn_ulcs_T_presentation_data_values_vals[] = {
  {   0, "single-ASN1-type" },
  {   1, "octet-aligned" },
  {   2, "arbitrary" },
  { 0, NULL }
};

static const per_choice_t T_presentation_data_values_choice[] = {
  {   0, &hf_atn_ulcs_pdv_list_presentation_data_values_single_asn1_type, ASN1_NO_EXTENSIONS     , dissect_atn_ulcs_T_pdv_list_presentation_data_values_single_asn1_type },
  {   1, &hf_atn_ulcs_octet_aligned, ASN1_NO_EXTENSIONS     , dissect_atn_ulcs_OCTET_STRING },
  {   2, &hf_atn_ulcs_pdv_list_presentation_data_values_arbitrary, ASN1_NO_EXTENSIONS     , dissect_atn_ulcs_T_pdv_list_presentation_data_values_arbitrary },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_ulcs_T_presentation_data_values(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_ulcs_T_presentation_data_values, T_presentation_data_values_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t PDV_list_sequence[] = {
  { &hf_atn_ulcs_transfer_syntax_name, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_ulcs_Transfer_syntax_name },
  { &hf_atn_ulcs_presentation_context_identifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_ulcs_Presentation_context_identifier },
  { &hf_atn_ulcs_presentation_data_values, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_ulcs_T_presentation_data_values },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_ulcs_PDV_list(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_ulcs_PDV_list, PDV_list_sequence);

  return offset;
}


static const per_sequence_t Fully_encoded_data_sequence_of[1] = {
  { &hf_atn_ulcs_Fully_encoded_data_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_ulcs_PDV_list },
};

static int
dissect_atn_ulcs_Fully_encoded_data(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_atn_ulcs_Fully_encoded_data, Fully_encoded_data_sequence_of,
                                                  1, 1, TRUE);

  return offset;
}



static int
dissect_atn_ulcs_OBJECT_IDENTIFIER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_atn_ulcs_INTEGER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_atn_ulcs_T_data_value_descriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_per_octet_string(
      tvb,
      offset,
      actx,
      tree,
      hf_index,
      -1,
      -1,
      FALSE,
      &actx->external.data_value_descriptor);
  actx->external.data_value_descr_present = TRUE;


  return offset;
}



static int
dissect_atn_ulcs_T_externalt_encoding_single_asn1_type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

    offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, NULL);



  return offset;
}



static int
dissect_atn_ulcs_T_externalt_encoding_octet_aligned(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);



  return offset;
}



static int
dissect_atn_ulcs_T_externalt_encoding_arbitrary(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *tvb_usr = NULL;
  packet_info * pinfo = actx->pinfo;
  atn_conversation_t *atn_cv = NULL;
  heur_dtbl_entry_t *hdtbl_entry;

  /* decode bit-string user data within ACSE  */
  offset = dissect_per_bit_string(
    tvb,
    offset,
    actx,
    tree, hf_index,
    NO_BOUND,
    NO_BOUND,
    FALSE,
    &tvb_usr,
    NULL);

  if (tvb_usr) {
    /* DT: dstref present, srcref is always zero */
    if((pinfo->clnp_dstref) && (!pinfo->clnp_srcref)){

      atn_cv = find_atn_conversation(
          &pinfo->dst,
          pinfo->clnp_dstref,
          &pinfo->src);
    }
    /* CR: srcref present, dstref always zero */
    if((pinfo->clnp_srcref) && (!pinfo->clnp_dstref)){

      atn_cv = find_atn_conversation(
          &pinfo->src,
          pinfo->clnp_srcref,
          &pinfo->dst);
    }
    /* CC: srcref and dstref present */
    if((pinfo->clnp_srcref) && (pinfo->clnp_dstref)){

      atn_cv = find_atn_conversation(
          &pinfo->src,
          pinfo->clnp_srcref,
          &pinfo->dst);
    }

    if(atn_cv) {
        switch(atn_cv->ae_qualifier){
          case cma: /* contact management */

              call_dissector_with_data(
                    atn_cm_handle,
                    tvb_new_subset_remaining(tvb_usr, 0),
                    pinfo,
                    root_tree,
                    NULL);
              break;
          case cpdlc: /* plain old cpdlc */
          case pmcpdlc: /* protected mode cpdlc */

              call_dissector_with_data(
                    atn_cpdlc_handle,
                    tvb_new_subset_remaining(tvb_usr, 0),
                    pinfo,
                    root_tree,
                    NULL);
              break;
          default: /* unknown or unhandled datalink application */

              dissector_try_heuristic(
                  atn_ulcs_heur_subdissector_list,
                  tvb_new_subset_remaining(tvb_usr,0),
                  actx->pinfo,
                  root_tree,
                  &hdtbl_entry,
                  NULL);
                break;
          }
    }else {

      dissector_try_heuristic(
              atn_ulcs_heur_subdissector_list,
              tvb_new_subset_remaining(tvb_usr,0),
              actx->pinfo,
              root_tree,
              &hdtbl_entry,
              NULL);
    }
  }

  offset += tvb_reported_length_remaining(tvb, offset);


  return offset;
}


static const value_string atn_ulcs_T_encoding_vals[] = {
  {   0, "single-ASN1-type" },
  {   1, "octet-aligned" },
  {   2, "arbitrary" },
  { 0, NULL }
};

static const per_choice_t T_encoding_choice[] = {
  {   0, &hf_atn_ulcs_externalt_encoding_single_asn1_type, ASN1_NO_EXTENSIONS     , dissect_atn_ulcs_T_externalt_encoding_single_asn1_type },
  {   1, &hf_atn_ulcs_externalt_encoding_octet_aligned, ASN1_NO_EXTENSIONS     , dissect_atn_ulcs_T_externalt_encoding_octet_aligned },
  {   2, &hf_atn_ulcs_externalt_encoding_arbitrary, ASN1_NO_EXTENSIONS     , dissect_atn_ulcs_T_externalt_encoding_arbitrary },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_ulcs_T_encoding(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_ulcs_T_encoding, T_encoding_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t EXTERNALt_sequence[] = {
  { &hf_atn_ulcs_direct_reference, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_ulcs_OBJECT_IDENTIFIER },
  { &hf_atn_ulcs_indirect_reference, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_ulcs_INTEGER },
  { &hf_atn_ulcs_data_value_descriptor, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_ulcs_T_data_value_descriptor },
  { &hf_atn_ulcs_encoding   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_ulcs_T_encoding },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_ulcs_EXTERNALt(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_ulcs_EXTERNALt, EXTERNALt_sequence);

  return offset;
}



static int
dissect_atn_ulcs_T_aarq_apdu_protocol_version(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     NO_BOUND, NO_BOUND, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_atn_ulcs_Application_context_name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_atn_ulcs_AP_title_form2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_atn_ulcs_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t AttributeTypeAndValue_sequence[] = {
  { &hf_atn_ulcs_null       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_ulcs_NULL },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_ulcs_AttributeTypeAndValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_ulcs_AttributeTypeAndValue, AttributeTypeAndValue_sequence);

  return offset;
}


static const per_sequence_t RelativeDistinguishedName_set_of[1] = {
  { &hf_atn_ulcs_RelativeDistinguishedName_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_ulcs_AttributeTypeAndValue },
};

static int
dissect_atn_ulcs_RelativeDistinguishedName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_atn_ulcs_RelativeDistinguishedName, RelativeDistinguishedName_set_of,
                                             1, NO_BOUND, FALSE);

  return offset;
}


static const per_sequence_t RDNSequence_sequence_of[1] = {
  { &hf_atn_ulcs_RDNSequence_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_ulcs_RelativeDistinguishedName },
};

static int
dissect_atn_ulcs_RDNSequence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_atn_ulcs_RDNSequence, RDNSequence_sequence_of);

  return offset;
}


static const value_string atn_ulcs_Name_vals[] = {
  {   0, "rdnSequence" },
  { 0, NULL }
};

static const per_choice_t Name_choice[] = {
  {   0, &hf_atn_ulcs_rdnSequence, ASN1_NO_EXTENSIONS     , dissect_atn_ulcs_RDNSequence },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_ulcs_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_ulcs_Name, Name_choice,
                                 NULL);

  return offset;
}



static int
dissect_atn_ulcs_AP_title_form1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_atn_ulcs_Name(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string atn_ulcs_AP_title_vals[] = {
  {   0, "ap-title-form2" },
  {   1, "ap-title-form1" },
  { 0, NULL }
};

static const per_choice_t AP_title_choice[] = {
  {   0, &hf_atn_ulcs_ap_title_form2, ASN1_EXTENSION_ROOT    , dissect_atn_ulcs_AP_title_form2 },
  {   1, &hf_atn_ulcs_ap_title_form1, ASN1_EXTENSION_ROOT    , dissect_atn_ulcs_AP_title_form1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_ulcs_AP_title(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_ulcs_AP_title, AP_title_choice,
                                 NULL);

  return offset;
}



static int
dissect_atn_ulcs_AE_qualifier_form2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    packet_info * pinfo = actx->pinfo;
    atn_conversation_t *atn_cv = NULL;
    guint32 ae_qualifier = 0;

    /* dissect  ae-qualifier */
    offset = dissect_per_integer(
        tvb,
        offset,
        actx,
        tree,
        hf_index,
        &ae_qualifier);


    /*note: */
    /* the field "calling-AE-qualifier" is optional, */
    /* which means that we can exploit it only if it is present. */
    /* We still depend on heuristical decoding of CM, CPDLC PDU's otherwise. */

    /* AARQ/DT: dstref present, srcref is always zero */
    if((pinfo->clnp_dstref) && (!pinfo->clnp_srcref)){
        atn_cv = find_atn_conversation(&pinfo->dst,
            pinfo->clnp_dstref,
            &pinfo->src );
    }

    /* AARQ/CR: srcref present, dstref is always zero */
    if((!pinfo->clnp_dstref) && (pinfo->clnp_srcref)){
        atn_cv = find_atn_conversation(&pinfo->src,
            pinfo->clnp_srcref,
            &pinfo->dst );
  }

  if(atn_cv){
      atn_cv->ae_qualifier = ae_qualifier;
  }

  return offset;
}



static int
dissect_atn_ulcs_AE_qualifier_form1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_atn_ulcs_RelativeDistinguishedName(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string atn_ulcs_AE_qualifier_vals[] = {
  {   0, "ae-qualifier-form2" },
  {   1, "ae-qualifier-form1" },
  { 0, NULL }
};

static const per_choice_t AE_qualifier_choice[] = {
  {   0, &hf_atn_ulcs_ae_qualifier_form2, ASN1_EXTENSION_ROOT    , dissect_atn_ulcs_AE_qualifier_form2 },
  {   1, &hf_atn_ulcs_ae_qualifier_form1, ASN1_EXTENSION_ROOT    , dissect_atn_ulcs_AE_qualifier_form1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_ulcs_AE_qualifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_ulcs_AE_qualifier, AE_qualifier_choice,
                                 NULL);

  return offset;
}



static int
dissect_atn_ulcs_AP_invocation_identifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_atn_ulcs_AE_invocation_identifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_atn_ulcs_ACSE_requirements(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     NO_BOUND, NO_BOUND, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_atn_ulcs_Mechanism_name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

    offset = dissect_per_object_identifier(
        tvb,
        offset,
        actx,
        tree,
        hf_index,
        NULL);


  offset = dissect_per_object_identifier(
      tvb,
      offset,
      actx,
      tree,
      hf_index,
      NULL);


  return offset;
}



static int
dissect_atn_ulcs_BIT_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     NO_BOUND, NO_BOUND, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_atn_ulcs_EXTERNAL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_external_type(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_atn_ulcs_T_other_mechanism_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

    offset=call_ber_oid_callback(
        object_identifier_id,
        tvb,
        offset,
        actx->pinfo,
        tree, NULL);


    offset=call_ber_oid_callback(
        object_identifier_id,
        tvb,
        offset,
        actx->pinfo,
        tree, NULL);


  return offset;
}


static const per_sequence_t T_other_sequence[] = {
  { &hf_atn_ulcs_other_mechanism_name, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_ulcs_OBJECT_IDENTIFIER },
  { &hf_atn_ulcs_other_mechanism_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_ulcs_T_other_mechanism_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_ulcs_T_other(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_ulcs_T_other, T_other_sequence);

  return offset;
}


static const value_string atn_ulcs_Authentication_value_vals[] = {
  {   0, "charstring" },
  {   1, "bitstring" },
  {   2, "external" },
  {   3, "other" },
  { 0, NULL }
};

static const per_choice_t Authentication_value_choice[] = {
  {   0, &hf_atn_ulcs_charstring , ASN1_NO_EXTENSIONS     , dissect_atn_ulcs_OCTET_STRING },
  {   1, &hf_atn_ulcs_bitstring  , ASN1_NO_EXTENSIONS     , dissect_atn_ulcs_BIT_STRING },
  {   2, &hf_atn_ulcs_external   , ASN1_NO_EXTENSIONS     , dissect_atn_ulcs_EXTERNAL },
  {   3, &hf_atn_ulcs_other      , ASN1_NO_EXTENSIONS     , dissect_atn_ulcs_T_other },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_ulcs_Authentication_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_ulcs_Authentication_value, Authentication_value_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Application_context_name_list_sequence_of[1] = {
  { &hf_atn_ulcs_Application_context_name_list_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_ulcs_Application_context_name },
};

static int
dissect_atn_ulcs_Application_context_name_list(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_atn_ulcs_Application_context_name_list, Application_context_name_list_sequence_of);

  return offset;
}



static int
dissect_atn_ulcs_Implementation_data(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t Association_information_sequence_of[1] = {
  { &hf_atn_ulcs_Association_information_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_ulcs_EXTERNALt },
};

static int
dissect_atn_ulcs_Association_information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_atn_ulcs_Association_information, Association_information_sequence_of,
                                                  1, 1, TRUE);

  return offset;
}


static const per_sequence_t AARQ_apdu_sequence[] = {
  { &hf_atn_ulcs_aarq_apdu_protocol_version, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_T_aarq_apdu_protocol_version },
  { &hf_atn_ulcs_application_context_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_atn_ulcs_Application_context_name },
  { &hf_atn_ulcs_called_AP_title, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_AP_title },
  { &hf_atn_ulcs_called_AE_qualifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_AE_qualifier },
  { &hf_atn_ulcs_called_AP_invocation_identifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_AP_invocation_identifier },
  { &hf_atn_ulcs_called_AE_invocation_identifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_AE_invocation_identifier },
  { &hf_atn_ulcs_calling_AP_title, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_AP_title },
  { &hf_atn_ulcs_calling_AE_qualifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_AE_qualifier },
  { &hf_atn_ulcs_calling_AP_invocation_identifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_AP_invocation_identifier },
  { &hf_atn_ulcs_calling_AE_invocation_identifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_AE_invocation_identifier },
  { &hf_atn_ulcs_sender_acse_requirements, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_ACSE_requirements },
  { &hf_atn_ulcs_mechanism_name, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_Mechanism_name },
  { &hf_atn_ulcs_calling_authentication_value, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_Authentication_value },
  { &hf_atn_ulcs_application_context_name_list, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_Application_context_name_list },
  { &hf_atn_ulcs_implementation_information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_Implementation_data },
  { &hf_atn_ulcs_user_information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_Association_information },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_ulcs_AARQ_apdu(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    packet_info * pinfo = actx->pinfo;
    aarq_data_t *aarq_data = NULL;
    atn_conversation_t *atn_cv = NULL;
    guint32 aircraft_24_bit_address = 0;

    /* AARQ/DT: dstref present, srcref is always zero */
    if((pinfo->clnp_dstref) && (!pinfo->clnp_srcref)){

        atn_cv = find_atn_conversation(
            &pinfo->dst,
            pinfo->clnp_dstref,
            &pinfo->src );
        if(!atn_cv){
            atn_cv = wmem_new(wmem_file_scope(), atn_conversation_t);
            atn_cv->ae_qualifier = unknown;
            create_atn_conversation(&pinfo->dst,
                pinfo->clnp_dstref,
                &pinfo->src ,
                atn_cv);
        }
    }

  /* AARQ/CR: srcref present, dstref is always zero */
    if((!pinfo->clnp_dstref) && (pinfo->clnp_srcref)){
        atn_cv = find_atn_conversation(&pinfo->src,
            pinfo->clnp_srcref,
            &pinfo->dst );
        if(!atn_cv){
            atn_cv = wmem_new(wmem_file_scope(), atn_conversation_t);
            atn_cv->ae_qualifier = unknown;
            create_atn_conversation(&pinfo->src,
                pinfo->clnp_srcref,
                &pinfo->dst ,
                atn_cv);
        }
    }

    /* conversation is to be created prior to decoding */
    /* of "AE-qualifier-form2" which takes place here: */
      offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_ulcs_AARQ_apdu, AARQ_apdu_sequence);



    /* save AARQ packet data to create a conversation  */
    /* when decoding the following AARE PDU */
    /* ATN applications CM and CPDLC are air/ground applications */
    /* so there is always an aircraft (with its 24-bit address) */
    /* and a ground facility. */
    /* the assumption is that there is only one open AARQ/AARE */
    /* dialog per aircraft at a time. */
    /* the aircraft's 24-bit address is used as a key to each AARQ */
    /* data. AARQ data is used to create a conversation with */
    /* air and ground endpoints (based on NSAP's and transport references) */
    /* when decoding AARE.*/
    /* note: */
    /* it may be more robust to create the conversation */
    /* in the "ositp" dissector an to merely use the conversation here */
    aircraft_24_bit_address =
        get_aircraft_24_bit_address_from_nsap(pinfo);

    /* search for aarq entry */
    aarq_data = (aarq_data_t *) wmem_tree_lookup32(
        aarq_data_tree,
        aircraft_24_bit_address);

    if(!aarq_data){  /* aarq data not found, create new record */

        /* alloc aarq data */
        aarq_data = wmem_new(wmem_file_scope(), aarq_data_t);
        aarq_data-> aarq_pending = FALSE;

        /* insert aarq data */
        wmem_tree_insert32(aarq_data_tree ,aircraft_24_bit_address,(void*)aarq_data);
    }

    /* check for pending AARQ/AARE sequences */
    /* if "aarq_data-> aarq_pending" is set this means that there is already one  */
    /* AARQ/AARE sequence pending (is unwise to overwrite AARE/AARQ) */
    if (aarq_data-> aarq_pending == FALSE ) {

      /* init aarq data */
      memset(aarq_data,0,sizeof(aarq_data_t));

      aarq_data->cv = atn_cv;
      aarq_data-> aarq_pending = TRUE;
    }


  return offset;
}



static int
dissect_atn_ulcs_T_aare_apdu_protocol_version(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     NO_BOUND, NO_BOUND, FALSE, NULL, NULL);

  return offset;
}


static const value_string atn_ulcs_Associate_result_vals[] = {
  {   0, "accepted" },
  {   1, "rejected-permanent" },
  {   2, "rejected-transient" },
  { 0, NULL }
};


static int
dissect_atn_ulcs_Associate_result(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
 /* extension present: last param set to true. asn2wrs didn't take notice of that */
 offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2U, NULL, TRUE);

  return offset;
}


static const value_string atn_ulcs_T_acse_service_user_vals[] = {
  {   0, "null" },
  {   1, "no-reason-given" },
  {   2, "application-context-name-not-supported" },
  {   3, "calling-AP-title-not-recognized" },
  {   4, "calling-AP-invocation-identifier-not-recognized" },
  {   5, "calling-AE-qualifier-not-recognized" },
  {   6, "calling-AE-invocation-identifier-not-recognized" },
  {   7, "called-AP-title-not-recognized" },
  {   8, "called-AP-invocation-identifier-not-recognized" },
  {   9, "called-AE-qualifier-not-recognized" },
  {  10, "called-AE-invocation-identifier-not-recognized" },
  {  11, "authentication-mechanism-name-not-recognized" },
  {  12, "authentication-mechanism-name-required" },
  {  13, "authentication-failure" },
  {  14, "authentication-required" },
  { 0, NULL }
};


static int
dissect_atn_ulcs_T_acse_service_user(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 14U, NULL, TRUE);

  return offset;
}


static const value_string atn_ulcs_T_acse_service_provider_vals[] = {
  {   0, "null" },
  {   1, "no-reason-given" },
  {   2, "no-common-acse-version" },
  { 0, NULL }
};


static int
dissect_atn_ulcs_T_acse_service_provider(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2U, NULL, TRUE);

  return offset;
}


static const value_string atn_ulcs_Associate_source_diagnostic_vals[] = {
  {   1, "acse-service-user" },
  {   2, "acse-service-provider" },
  { 0, NULL }
};

static const per_choice_t Associate_source_diagnostic_choice[] = {
  {   1, &hf_atn_ulcs_acse_service_user, ASN1_NO_EXTENSIONS     , dissect_atn_ulcs_T_acse_service_user },
  {   2, &hf_atn_ulcs_acse_service_provider, ASN1_NO_EXTENSIONS     , dissect_atn_ulcs_T_acse_service_provider },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_ulcs_Associate_source_diagnostic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_ulcs_Associate_source_diagnostic, Associate_source_diagnostic_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t AARE_apdu_sequence[] = {
  { &hf_atn_ulcs_aare_apdu_protocol_version, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_T_aare_apdu_protocol_version },
  { &hf_atn_ulcs_application_context_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_atn_ulcs_Application_context_name },
  { &hf_atn_ulcs_result     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_atn_ulcs_Associate_result },
  { &hf_atn_ulcs_result_source_diagnostic, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_atn_ulcs_Associate_source_diagnostic },
  { &hf_atn_ulcs_responding_AP_title, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_AP_title },
  { &hf_atn_ulcs_responding_AE_qualifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_AE_qualifier },
  { &hf_atn_ulcs_responding_AP_invocation_identifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_AP_invocation_identifier },
  { &hf_atn_ulcs_responding_AE_invocation_identifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_AE_invocation_identifier },
  { &hf_atn_ulcs_responder_acse_requirements, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_ACSE_requirements },
  { &hf_atn_ulcs_mechanism_name, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_Mechanism_name },
  { &hf_atn_ulcs_responding_authentication_value, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_Authentication_value },
  { &hf_atn_ulcs_application_context_name_list, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_Application_context_name_list },
  { &hf_atn_ulcs_implementation_information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_Implementation_data },
  { &hf_atn_ulcs_user_information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_Association_information },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_ulcs_AARE_apdu(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  packet_info * pinfo = actx->pinfo;
  guint32 aircraft_24_bit_address = 0 ;
  atn_conversation_t *atn_cv = NULL;
  aarq_data_t *aarq_data = NULL;

  /* get AARQ data and use it to create a new conversation, */
  /* the conversation is used along with  */
  /* AARQ's "calling ae qualifier" to determine the */
  /* type of air/ground application of each subsequent frame.*/
  /* we use this information to invoke the correct application dissector. */
  /* note: */
  /* heuristical decoding of ASN1 will not work for all cases, */
  /* for there may be CM PDU's which will exactly look like CPDLC PDU'S */

  /* get 24-bit icao address */
  aircraft_24_bit_address = get_aircraft_24_bit_address_from_nsap(pinfo);

  /* search for aarq entry */
  aarq_data = (aarq_data_t *) wmem_tree_lookup32(
      aarq_data_tree,
      aircraft_24_bit_address);

  /* no aarq data present, do nothing  */
  /* without both ends of the conversation and without */
  /* the "calling ae-qualifier there is no point in setting up "*/
  /* a conversation */
  if(!aarq_data) {

    return offset;
  }

  /* AARE/DT: dstref present, srcref is always zero */
  if((pinfo->clnp_dstref) && (!pinfo->clnp_srcref)){

    atn_cv = find_atn_conversation(&pinfo->dst,
                          pinfo->clnp_dstref,
                          &pinfo->src );

    if(!atn_cv){ /* conversation not fond */

      /* DT has only dstref - create new conversation */
      create_atn_conversation(&pinfo->dst,
                              pinfo->clnp_dstref,
                              &pinfo->src ,
                              aarq_data->cv);
    }
  }

  /* AARE/CC: srcref and dstref present  */
  if((pinfo->clnp_dstref) && (pinfo->clnp_srcref)){

    atn_cv = find_atn_conversation(
        &pinfo->src,
        pinfo->clnp_srcref,
        &pinfo->dst);

    if(atn_cv){ /* conversation found. */

      /* create new conversation for dstref */
      create_atn_conversation(&pinfo->dst,
                              pinfo->clnp_dstref,
                              &pinfo->src ,
                              aarq_data->cv);

    }else { /* no conversation found  */
      /* as CC contains srcref *and* dstref we use both to create new records  */
      create_atn_conversation(&pinfo->src,
                              pinfo->clnp_srcref,
                              &pinfo->dst ,
                              aarq_data->cv);
      create_atn_conversation(&pinfo->dst,
                              pinfo->clnp_dstref,
                              &pinfo->src ,
                              aarq_data->cv);
    }
  }

  /* clear aarq data */
  memset(aarq_data,0,sizeof(aarq_data_t));
  aarq_data-> aarq_pending  =  FALSE;

    offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_ulcs_AARE_apdu, AARE_apdu_sequence);




  return offset;
}


static const value_string atn_ulcs_Release_request_reason_vals[] = {
  {   0, "normal" },
  {   1, "urgent" },
  {  30, "user-defined" },
  { 0, NULL }
};


static int
dissect_atn_ulcs_Release_request_reason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
 /* extension present: last param set to true. asn2wrs didn't take notice of that */
 offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 30U, NULL, TRUE);

  return offset;
}


static const per_sequence_t RLRQ_apdu_sequence[] = {
  { &hf_atn_ulcs_rlrq_apdu_request_reason, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_Release_request_reason },
  { &hf_atn_ulcs_user_information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_Association_information },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_ulcs_RLRQ_apdu(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_ulcs_RLRQ_apdu, RLRQ_apdu_sequence);

  return offset;
}


static const value_string atn_ulcs_Release_response_reason_vals[] = {
  {   0, "normal" },
  {   1, "not-finished" },
  {  30, "user-defined" },
  { 0, NULL }
};


static int
dissect_atn_ulcs_Release_response_reason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

 /* extension present: last param set to true. asn2wrs didn't take notice of that */
 offset = dissect_per_constrained_integer(
    tvb,
    offset,
    actx,
    tree,
    hf_index,
    0U,
    30U,
    NULL,
    TRUE);


  return offset;
}


static const per_sequence_t RLRE_apdu_sequence[] = {
  { &hf_atn_ulcs_rlre_apdu_response_reason, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_Release_response_reason },
  { &hf_atn_ulcs_user_information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_Association_information },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_ulcs_RLRE_apdu(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_ulcs_RLRE_apdu, RLRE_apdu_sequence);

  return offset;
}


static const value_string atn_ulcs_ABRT_source_vals[] = {
  {   0, "acse-service-user" },
  {   1, "acse-service-provider" },
  { 0, NULL }
};


static int
dissect_atn_ulcs_ABRT_source(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1U, NULL, TRUE);

  return offset;
}


static const value_string atn_ulcs_ABRT_diagnostic_vals[] = {
  {   1, "no-reason-given" },
  {   2, "protocol-error" },
  {   3, "authentication-mechanism-name-not-recognized" },
  {   4, "authentication-mechanism-name-required" },
  {   5, "authentication-failure" },
  {   6, "authentication-required" },
  { 0, NULL }
};

static guint32 ABRT_diagnostic_value_map[6+0] = {1, 2, 3, 4, 5, 6};

static int
dissect_atn_ulcs_ABRT_diagnostic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, ABRT_diagnostic_value_map);

  return offset;
}


static const per_sequence_t ABRT_apdu_sequence[] = {
  { &hf_atn_ulcs_abort_source, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_atn_ulcs_ABRT_source },
  { &hf_atn_ulcs_abort_diagnostic, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_ABRT_diagnostic },
  { &hf_atn_ulcs_user_information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_atn_ulcs_Association_information },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_ulcs_ABRT_apdu(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_ulcs_ABRT_apdu, ABRT_apdu_sequence);

  return offset;
}


static const value_string atn_ulcs_ACSE_apdu_vals[] = {
  {   0, "aarq" },
  {   1, "aare" },
  {   2, "rlrq" },
  {   3, "rlre" },
  {   4, "abrt" },
  { 0, NULL }
};

static const per_choice_t ACSE_apdu_choice[] = {
  {   0, &hf_atn_ulcs_aarq       , ASN1_EXTENSION_ROOT    , dissect_atn_ulcs_AARQ_apdu },
  {   1, &hf_atn_ulcs_aare       , ASN1_EXTENSION_ROOT    , dissect_atn_ulcs_AARE_apdu },
  {   2, &hf_atn_ulcs_rlrq       , ASN1_EXTENSION_ROOT    , dissect_atn_ulcs_RLRQ_apdu },
  {   3, &hf_atn_ulcs_rlre       , ASN1_EXTENSION_ROOT    , dissect_atn_ulcs_RLRE_apdu },
  {   4, &hf_atn_ulcs_abrt       , ASN1_EXTENSION_ROOT    , dissect_atn_ulcs_ABRT_apdu },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_ulcs_ACSE_apdu(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_ulcs_ACSE_apdu, ACSE_apdu_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_Fully_encoded_data_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_atn_ulcs_Fully_encoded_data(tvb, offset, &asn1_ctx, tree, hf_atn_ulcs_Fully_encoded_data_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ACSE_apdu_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_atn_ulcs_ACSE_apdu(tvb, offset, &asn1_ctx, tree, hf_atn_ulcs_ACSE_apdu_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-atn-ulcs-fn.c ---*/
#line 196 "./asn1/atn-ulcs/packet-atn-ulcs-template.c"

#if 0
/* re-implementing external data: packet-per.c */
static const value_string per_External_encoding_vals[] = {
{   0, "single-ASN1-type" },
{   1, "octet-aligned" },
{   2, "arbitrary" },
{ 0, NULL }
};

/* re-implementing external data: packet-per.c */
static const per_choice_t External_encoding_choice[] =
{
    {   0,
        &hf_atn_ulcs_externalt_encoding_single_asn1_type,
        ASN1_NO_EXTENSIONS,
        dissect_atn_ulcs_T_externalt_encoding_single_asn1_type
    },
    {   1,
        &hf_atn_ulcs_externalt_encoding_octet_aligned,
        ASN1_NO_EXTENSIONS,
        dissect_atn_ulcs_T_externalt_encoding_octet_aligned
    },
    {   2,
        &hf_atn_ulcs_externalt_encoding_arbitrary,
        ASN1_NO_EXTENSIONS,
        dissect_atn_ulcs_T_externalt_encoding_arbitrary
    },
    {   0,
        NULL,
        0,
        NULL
    }
};
#endif

/* ATN Session layer */
#define SES_PDU_TYPE_MASK     0xf8
#define SES_PARAM_IND_MASK    0x04
#define SES_PARAM_B2_MASK     0x02
#define SES_PARAM_B1_MASK     0x01

static int hf_atn_ses_type = -1;
static int hf_atn_ses_param_ind = -1;
static int hf_atn_ses_param_b1 = -1;
static int hf_atn_ses_param_b2 = -1;

static gint ett_atn_ses = -1;

#define ATN_SES_PROTO "ICAO Doc9705 ULCS Session (ISO 8326/8327-1:1994)"

const value_string atn_ses_param_ind[] =
{
    {0, "No Parameter Indication "},
    {1, "Parameter Indication "},
    {0, NULL }
};

const value_string srf_b2[] =
{
    {0, "Transport Connection is kept"},
    {1, "Transport Connection is released" },
    {0, NULL }
};

const value_string srf_b1[] =
{
    {0, "Transport Connection is transient"},
    {1, "Transport Connection is persistent"},
    {0, NULL }
};

#define SES_ATN_SCN       0xe8
#define SES_ATN_SCNC      0xf8
#define SES_ATN_SAC       0xf0
#define SES_ATN_SACC      0xd8
#define SES_ATN_SRF       0xe0
#define SES_ATN_SRFC      0xa0

const value_string atn_ses_type[] =
{
    { 0x1d, "Short Connect (SCN) SPDU" },
    { 0x1f, "Short Connect Accept (SAC) SPDU" },
    { 0x1e, "Short Connect Accept Continue (SACC) SPDU" },
    { 0x1c, "Short Refuse (SRF) SPDU" },
    { 0x14, "Short Refuse Continue (SRFC) SPDU" },
    {0, NULL }
};

/* ATN Presentation layer */
#define ATN_PRES_PROTO "ICAO Doc9705 ULCS Presentation (ISO 8822/8823-1:1994)"

static int hf_atn_pres_err   = -1;
static int hf_atn_pres_pdu_type = -1;
static gint ett_atn_pres    = -1;

#define ATN_SES_PRES_MASK 0xf803
#define PRES_CPR_ER_MASK    0x70

/* type determined by SPDU and PPDU */
const value_string atn_pres_vals[] =
{
    { 0xe802, "Short Presentation Connect PPDU (CP) " },
    { 0xf802, "Short Presentation Connect PPDU (CP) " },
    { 0xf002, "Short Presentation Connect Accept PPDU (CPA)" },
    { 0xd802, "Short Presentation Connect Accept PPDU (CPA)" },
    { 0xe002, "Short Presentation Connect Reject PPDU (CPR)" },
    { 0xa002, "Short Presentation Connect Reject PPDU (CPR)" },
    {0,         NULL }
};

/* Short Presentation Connect Reject PPDU's 0yyy 00zz */
const value_string atn_pres_err[] =
{
    { 0x00, "Presentation-user" },
    { 0x01, "Reason not specified (transient)"},
    { 0x02, "Temporary congestion (transient)"},
    { 0x03, "Local limit exceeded (transient)"},
    { 0x04, "Called presentation-address unknown (permanent)"},
    { 0x05, "Protocol version not supported (permanent)"},
    { 0x06, "Default context not supported (permanent)"},
    { 0x07, "User data not readable (permanent)"},
    { 0,          NULL }
};

#if 0
/* re-implementing external data: packet-per.c */
static int  atn_ulcs_Externalt_encoding(
    tvbuff_t *tvb _U_,
    int offset _U_,
    asn1_ctx_t *actx _U_,
    proto_tree *tree _U_,
    int hf_index _U_)
{
    offset = dissect_per_choice(
        tvb,
        offset,
        actx,
        tree,
        hf_index,
        ett_atn_ulcs_EXTERNALt,
        External_encoding_choice,
        &actx->external.encoding);

    return offset;
}

/* re-implementing external data: packet-per.c */
static guint32  atn_per_external_type(
    tvbuff_t *tvb _U_,
    guint32 offset,
    asn1_ctx_t *actx,
    proto_tree *tree _U_,
    int hf_index _U_,
    per_type_fn type_cb)
{
    memset(&actx->external, '\0', sizeof(actx->external));
    actx->external.hf_index = -1;
    actx->external.encoding = -1;

    actx->external.u.per.type_cb = type_cb;
    offset = atn_ulcs_Externalt_encoding(
        tvb,
        offset,
        actx,
        tree,
        hf_index);

    memset(
        &actx->external,
        '\0',
        sizeof(actx->external));

    actx->external.hf_index = -1;
    actx->external.encoding = -1;

    return offset;
}
#endif

/* determine 24-bit aircraft address(ARS) */
/* from 20-byte ATN NSAP. */
guint32 get_aircraft_24_bit_address_from_nsap(
    packet_info *pinfo)
{
    const guint8* addr = NULL;
    guint32 ars =0;
    guint32 adr_prefix =0;

    /* check NSAP address type*/
    if( (pinfo->src.type != get_osi_address_type()) ||
        (pinfo->dst.type != get_osi_address_type())) {
        return ars; }

    /* 20 octets address length required */
    /* for ATN */
    if( (pinfo->src.len != 20) ||
        (pinfo->dst.len != 20)) {
        return ars; }

    /* first try source address */
    /* if the src address originates */
    /* from an aircraft it's downlink */

    /* convert addr into 32-bit integer */
    addr = (const guint8 *)pinfo->src.data;
    adr_prefix =
        ((addr[0]<<24) |
        (addr[1]<<16) |
        (addr[2]<<8) |
        addr[3] );

    /* according to ICAO doc9507 Ed2 SV5  */
    /* clause 5.4.3.8.1.5 and  5.4.3.8.1.3 */
    /* mobile addresses contain "c1" of "41" */
    /* in the VER subfield of the NSAP */
    if((adr_prefix == 0x470027c1) ||
        (adr_prefix == 0x47002741)) {
      /* ICAO doc9507 Ed2 SV5 5.4.3.8.4.4 */
      /* states that the ARS subfield containes */
      /* the  24-bitaddress of the aircraft */
        ars = ((addr[8])<<16) |
            ((addr[9])<<8) |
            (addr[10]);
    }

    /* try destination address */
    /* if the src address originates */
    /* from an aircraft it's downlink */

    /* convert addr into 32-bit integer */
    addr = (const guint8 *)pinfo->dst.data;
    adr_prefix = ((addr[0]<<24) |
        (addr[1]<<16) |
        (addr[2]<<8) |
        addr[3] );

    /* according to ICAO doc9507 Ed2 SV5  */
    /* clause 5.4.3.8.1.5 and  5.4.3.8.1.3 */
    /* mobile addresses contain "c1" of "41" */
    /* in the VER subfield of the NSAP */
    if((adr_prefix == 0x470027c1) ||
        (adr_prefix == 0x47002741)) {
      /* ICAO doc9507 Ed2 SV5 5.4.3.8.4.4 */
      /* states that the ARS subfield containes */
      /* the  24-bitaddress of the aircraft */
      ars = ((addr[8])<<16) |
            ((addr[9])<<8) |
            (addr[10]);
    }
    return ars;
}

/* determine whether a PDU is uplink or downlink */
/* by checking for known aircraft  address prefices*/
int check_heur_msg_type(packet_info *pinfo  _U_)
{
    int t = no_msg;
    const guint8* addr = NULL;
    guint32 adr_prefix =0;

    /* check NSAP address type*/
    if( (pinfo->src.type != get_osi_address_type()) || (pinfo->dst.type != get_osi_address_type())) {
        return t; }

    /* check NSAP address length; 20 octets address length required */
    if( (pinfo->src.len != 20) || (pinfo->dst.len != 20)) {
        return t; }

    addr = (const guint8 *)pinfo->src.data;

    /* convert address to 32-bit integer  */
    adr_prefix = ((addr[0]<<24) | (addr[1]<<16) | (addr[2]<<8) | addr[3] );

    /* According to the published ATN NSAP adddressing scheme */
    /* in ICAO doc9705 Ed2 SV5 5.4.3.8.1.3 and 5.4.3.8.1.5  */
    /* the "VER" field shall be 0x41 ("all Mobile AINSC") or */
    /* 0xc1 ("all Mobile ATSC") for mobile stations (aka aircraft).*/
    if((adr_prefix == 0x470027c1) || (adr_prefix == 0x47002741)) {
        t = dm; /* source is an aircraft: it's a downlink PDU */
    }

    addr = (const guint8 *)pinfo->dst.data;

    /* convert address to 32-bit integer  */
    adr_prefix = ((addr[0]<<24) | (addr[1]<<16) | (addr[2]<<8) | addr[3] );

    /* According to the published ATN NSAP adddressing scheme */
    /* in ICAO doc9705 Ed2 SV5 5.4.3.8.1.3 and 5.4.3.8.1.5  */
    /* the "VER" field shall be 0x41 ("all Mobile AINSC") or */
    /* 0xc1 ("all Mobile ATSC") for mobile stations (aka aircraft).*/
    if((adr_prefix == 0x470027c1) || (adr_prefix == 0x47002741)) {
        t = um; /* destination is aircraft: uplink PDU */
    }

    return t;
}

/* conversation may be used by other dissectors  */
wmem_tree_t *get_atn_conversation_tree(void){
    return atn_conversation_tree;
}


/* find a atn conversation tree node by an endpoint  */
/* an endpoint is identified by atn src and dst addresses */
/* and srcref or dstref (depends on the transport packet type) */
/* IMHO it's a hack - conversations should be maintained */
/* at transport layer (cotp) but this isn't working yet. */
atn_conversation_t * find_atn_conversation(
    address *address1,
    guint16 clnp_ref1,
    address *address2 )
{
    atn_conversation_t *cv = NULL;
    guint32 key = 0;
    guint32 tmp = 0;

    tmp = add_address_to_hash( tmp, address1);
    key = (tmp << 16) | clnp_ref1 ;

    tmp = add_address_to_hash( tmp, address2);
    key = (tmp << 24) | key ;

    /* search for atn conversation */
    cv = (atn_conversation_t *)
        wmem_tree_lookup32(get_atn_conversation_tree(),key);

    return cv;
}

/* create a atn conversation tree node  */
/* conversation data is to be allocated externally */
/* a conversation may be referenced from both endpoints */
atn_conversation_t * create_atn_conversation(
    address *address1,
    guint16 clnp_ref1,
    address *address2,
    atn_conversation_t *conversation)
{
    atn_conversation_t *cv = NULL;
    guint32 key = 0;
    guint32 tmp = 0;

    tmp = add_address_to_hash( tmp, address1);
    key = (tmp << 16) | clnp_ref1 ;

    tmp = add_address_to_hash( tmp, address2);
    key = (tmp << 24) | key ;

    /* search for aircraft entry */
    cv = (atn_conversation_t *)
    wmem_tree_lookup32(
        get_atn_conversation_tree(),
        key);

    /* tree node  already present  */
    if(cv) {
      return NULL; }

    /* insert conversation data in tree*/
    wmem_tree_insert32(
        get_atn_conversation_tree(),
        key,
        (void*)conversation);

    return conversation;
}

static int
dissect_atn_ulcs(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree,
    void *data _U_)
{
    int offset = 0;
    proto_item *ti = NULL;
    proto_tree *atn_ulcs_tree = NULL;
    guint8 value_pres = 0;
    guint8 value_ses = 0;
    guint16 value_ses_pres = 0;

    root_tree = tree;

    /* data pointer */
    /* decode as PDV-list */
    if ( (int)(intptr_t)  data == FALSE )
    {
        ti = proto_tree_add_item(
            tree,
            proto_atn_ulcs,
            tvb,
            0,
            0 ,
            ENC_NA);

        atn_ulcs_tree = proto_item_add_subtree(
            ti,
            ett_atn_ulcs);

        dissect_Fully_encoded_data_PDU(
            tvb,
            pinfo,
            atn_ulcs_tree, NULL);

        return offset +
          tvb_reported_length_remaining(tvb, offset ) ;
    }

    /* decode as SPDU, PPDU and ACSE PDU */
    if ( (int)(intptr_t)  data == TRUE )
    {
        /* get session and presentation PDU's */
        value_ses_pres = tvb_get_ntohs(tvb, offset);

        /* SPDU: dissect session layer */
        atn_ulcs_tree = proto_tree_add_subtree(
            tree, tvb, offset, 0,
            ett_atn_ses, NULL, ATN_SES_PROTO );

        /* get SPDU (1 octet) */
        value_ses = tvb_get_guint8(tvb, offset);

        /* SPDU type/identifier  */
        proto_tree_add_item(atn_ulcs_tree,
            hf_atn_ses_type,
            tvb,
            offset,
            1,
            ENC_BIG_ENDIAN );

        /* SPDU parameters may be present in Short Refuse */
        /* or Short Refuse Continue SPDU's */
        switch(value_ses & SES_PDU_TYPE_MASK){
            case SES_ATN_SRF:
            case SES_ATN_SRFC:

                /* SPDU parameter presence */
                proto_tree_add_item(atn_ulcs_tree,
                    hf_atn_ses_param_ind,
                    tvb,
                    offset,
                    1,
                    ENC_BIG_ENDIAN );

                /* parameter B2 */
                proto_tree_add_item(atn_ulcs_tree,
                    hf_atn_ses_param_b2,
                    tvb,
                    offset,
                    1,
                    ENC_BIG_ENDIAN );

                /* parameter B1 */
                proto_tree_add_item(atn_ulcs_tree,
                    hf_atn_ses_param_b1,
                    tvb,
                    offset,
                    1,
                    ENC_BIG_ENDIAN );

              break;
            default:
              break;
        }
        offset++;

        /* PPDU: dissect presentation layer */
        atn_ulcs_tree = proto_tree_add_subtree(
            tree, tvb, offset, 0,
            ett_atn_pres, NULL, ATN_PRES_PROTO );

        value_pres = tvb_get_guint8(tvb, offset);

        /* need session context to identify PPDU type */
        /* note: */
        proto_tree_add_uint_format(atn_ulcs_tree, hf_atn_pres_pdu_type,
            tvb,
            offset,
            1,
            value_ses_pres,
            "%s (0x%02x)",
            val_to_str( value_ses_pres & ATN_SES_PRES_MASK , atn_pres_vals, "?"),
            value_pres);

        /* PPDU errorcode in case of SRF/CPR */
        switch(value_ses & SES_PDU_TYPE_MASK){
            case SES_ATN_SRF:
            case SES_ATN_SRFC:
                proto_tree_add_item(
                    atn_ulcs_tree,
                    hf_atn_pres_err,
                    tvb,
                    offset,
                    1,
                    ENC_BIG_ENDIAN );
                break;
            default:
                break;
        }

        offset++;

        /* ACSE PDU: dissect application layer */
        atn_ulcs_tree = proto_tree_add_subtree(
            tree, tvb, offset, 0,
            ett_atn_acse, NULL, ATN_ACSE_PROTO );

        dissect_ACSE_apdu_PDU(
            tvb_new_subset_remaining(tvb, offset),
            pinfo,
            atn_ulcs_tree, NULL);

        return offset +
            tvb_reported_length_remaining(tvb, offset );
    }
    return offset;
}

static gboolean dissect_atn_ulcs_heur(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree,
    void *data _U_)
{
    /* do we have enough data*/
    /* at least session + presentation data or pdv-list */
    if (tvb_captured_length(tvb) < 2){
        return FALSE; }

    /* check for session/presentation/ACSE PDU's  */
    /* SPDU and PPDU are one octet each */
    switch( tvb_get_ntohs(tvb, 0) & 0xf8ff ){
        case 0xe802: /* SCN + CP*/
        case 0xf802: /* SCNC + CP */
        case 0xf002: /* SAC + CPA */
        case 0xd802: /* SACC + CPA */
        case 0xe002: /* SRF + CPR + R0 */
        case 0xe012: /* SRF + CPR + R1 */
        case 0xe022: /* SRF + CPR + R2 */
        case 0xe032: /* SRF + CPR + R3 */
        case 0xe042: /* SRF + CPR + R4 */
        case 0xe052: /* SRF + CPR + R5 */
        case 0xe062: /* SRF + CPR + R6 */
        case 0xe072: /* SRF + CPR + R7 */
        case 0xa002: /* SRFC + CPR + R0*/
        case 0xa012: /* SRFC + CPR + R1*/
        case 0xa022: /* SRFC + CPR + R2*/
        case 0xa032: /* SRFC + CPR + R3*/
        case 0xa042: /* SRFC + CPR + R4*/
        case 0xa052: /* SRFC + CPR + R5*/
        case 0xa062: /* SRFC + CPR + R6*/
        case 0xa072: /* SRFC + CPR + R7*/
            /* indicate to dissector routine */
            /* that a least SPDU, PPDU and */
            /* ACSE PDU is present */
            dissect_atn_ulcs(
                tvb,
                pinfo,
                tree,
                (void*) TRUE);
            return TRUE;
        default:  /* no SPDU */
            break;
    }

    /* try to detect "Fully-encoded-data" heuristically */
    /* the constants listed match the ASN.1 PER encoding */
    /* of PDV-List */
    switch(  tvb_get_ntohs(tvb, 0) & 0xfff0 ){
        case 0x0020: /* acse-apdu */
        case 0x00a0: /* user-ase-apdu */
        /* indicate to dissector routine */
        /* that a PDV-list PDU is present */
        /*  */
        /* PDV-list PDU may contain */
        /* application protocol data (CM, CPDLC) */
        /* or an ACSE PDU */
            dissect_atn_ulcs(tvb, pinfo, tree, (void*) FALSE);
            return TRUE;
            break;
        default:  /* no or unsupported PDU */
            break;
    }
    return FALSE;
}

void proto_register_atn_ulcs (void)
{
    static hf_register_info hf_atn_ulcs[] = {

/*--- Included file: packet-atn-ulcs-hfarr.c ---*/
#line 1 "./asn1/atn-ulcs/packet-atn-ulcs-hfarr.c"
    { &hf_atn_ulcs_Fully_encoded_data_PDU,
      { "Fully-encoded-data", "atn-ulcs.Fully_encoded_data",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_ulcs_ACSE_apdu_PDU,
      { "ACSE-apdu", "atn-ulcs.ACSE_apdu",
        FT_UINT32, BASE_DEC, VALS(atn_ulcs_ACSE_apdu_vals), 0,
        NULL, HFILL }},
    { &hf_atn_ulcs_Fully_encoded_data_item,
      { "PDV-list", "atn-ulcs.PDV_list_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_ulcs_transfer_syntax_name,
      { "transfer-syntax-name", "atn-ulcs.transfer_syntax_name",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_ulcs_presentation_context_identifier,
      { "presentation-context-identifier", "atn-ulcs.presentation_context_identifier",
        FT_UINT32, BASE_DEC, VALS(atn_ulcs_Presentation_context_identifier_vals), 0,
        NULL, HFILL }},
    { &hf_atn_ulcs_presentation_data_values,
      { "presentation-data-values", "atn-ulcs.presentation_data_values",
        FT_UINT32, BASE_DEC, VALS(atn_ulcs_T_presentation_data_values_vals), 0,
        NULL, HFILL }},
    { &hf_atn_ulcs_pdv_list_presentation_data_values_single_asn1_type,
      { "single-ASN1-type", "atn-ulcs.single_ASN1_type_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_pdv_list_presentation_data_values_single_asn1_type", HFILL }},
    { &hf_atn_ulcs_octet_aligned,
      { "octet-aligned", "atn-ulcs.octet_aligned",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_atn_ulcs_pdv_list_presentation_data_values_arbitrary,
      { "arbitrary", "atn-ulcs.arbitrary",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_pdv_list_presentation_data_values_arbitrary", HFILL }},
    { &hf_atn_ulcs_direct_reference,
      { "direct-reference", "atn-ulcs.direct_reference",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_atn_ulcs_indirect_reference,
      { "indirect-reference", "atn-ulcs.indirect_reference",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_atn_ulcs_data_value_descriptor,
      { "data-value-descriptor", "atn-ulcs.data_value_descriptor",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_ulcs_encoding,
      { "encoding", "atn-ulcs.encoding",
        FT_UINT32, BASE_DEC, VALS(atn_ulcs_T_encoding_vals), 0,
        NULL, HFILL }},
    { &hf_atn_ulcs_externalt_encoding_single_asn1_type,
      { "single-ASN1-type", "atn-ulcs.single_ASN1_type_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_externalt_encoding_single_asn1_type", HFILL }},
    { &hf_atn_ulcs_externalt_encoding_octet_aligned,
      { "octet-aligned", "atn-ulcs.octet_aligned",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_externalt_encoding_octet_aligned", HFILL }},
    { &hf_atn_ulcs_externalt_encoding_arbitrary,
      { "arbitrary", "atn-ulcs.arbitrary",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_externalt_encoding_arbitrary", HFILL }},
    { &hf_atn_ulcs_aarq,
      { "aarq", "atn-ulcs.aarq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AARQ_apdu", HFILL }},
    { &hf_atn_ulcs_aare,
      { "aare", "atn-ulcs.aare_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AARE_apdu", HFILL }},
    { &hf_atn_ulcs_rlrq,
      { "rlrq", "atn-ulcs.rlrq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RLRQ_apdu", HFILL }},
    { &hf_atn_ulcs_rlre,
      { "rlre", "atn-ulcs.rlre_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RLRE_apdu", HFILL }},
    { &hf_atn_ulcs_abrt,
      { "abrt", "atn-ulcs.abrt_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ABRT_apdu", HFILL }},
    { &hf_atn_ulcs_aarq_apdu_protocol_version,
      { "protocol-version", "atn-ulcs.protocol_version",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_aarq_apdu_protocol_version", HFILL }},
    { &hf_atn_ulcs_application_context_name,
      { "application-context-name", "atn-ulcs.application_context_name",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_ulcs_called_AP_title,
      { "called-AP-title", "atn-ulcs.called_AP_title",
        FT_UINT32, BASE_DEC, VALS(atn_ulcs_AP_title_vals), 0,
        "AP_title", HFILL }},
    { &hf_atn_ulcs_called_AE_qualifier,
      { "called-AE-qualifier", "atn-ulcs.called_AE_qualifier",
        FT_UINT32, BASE_DEC, VALS(atn_ulcs_AE_qualifier_vals), 0,
        "AE_qualifier", HFILL }},
    { &hf_atn_ulcs_called_AP_invocation_identifier,
      { "called-AP-invocation-identifier", "atn-ulcs.called_AP_invocation_identifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "AP_invocation_identifier", HFILL }},
    { &hf_atn_ulcs_called_AE_invocation_identifier,
      { "called-AE-invocation-identifier", "atn-ulcs.called_AE_invocation_identifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "AE_invocation_identifier", HFILL }},
    { &hf_atn_ulcs_calling_AP_title,
      { "calling-AP-title", "atn-ulcs.calling_AP_title",
        FT_UINT32, BASE_DEC, VALS(atn_ulcs_AP_title_vals), 0,
        "AP_title", HFILL }},
    { &hf_atn_ulcs_calling_AE_qualifier,
      { "calling-AE-qualifier", "atn-ulcs.calling_AE_qualifier",
        FT_UINT32, BASE_DEC, VALS(atn_ulcs_AE_qualifier_vals), 0,
        "AE_qualifier", HFILL }},
    { &hf_atn_ulcs_calling_AP_invocation_identifier,
      { "calling-AP-invocation-identifier", "atn-ulcs.calling_AP_invocation_identifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "AP_invocation_identifier", HFILL }},
    { &hf_atn_ulcs_calling_AE_invocation_identifier,
      { "calling-AE-invocation-identifier", "atn-ulcs.calling_AE_invocation_identifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "AE_invocation_identifier", HFILL }},
    { &hf_atn_ulcs_sender_acse_requirements,
      { "sender-acse-requirements", "atn-ulcs.sender_acse_requirements",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ACSE_requirements", HFILL }},
    { &hf_atn_ulcs_mechanism_name,
      { "mechanism-name", "atn-ulcs.mechanism_name",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_ulcs_calling_authentication_value,
      { "calling-authentication-value", "atn-ulcs.calling_authentication_value",
        FT_UINT32, BASE_DEC, VALS(atn_ulcs_Authentication_value_vals), 0,
        "Authentication_value", HFILL }},
    { &hf_atn_ulcs_application_context_name_list,
      { "application-context-name-list", "atn-ulcs.application_context_name_list",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_ulcs_implementation_information,
      { "implementation-information", "atn-ulcs.implementation_information",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Implementation_data", HFILL }},
    { &hf_atn_ulcs_user_information,
      { "user-information", "atn-ulcs.user_information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Association_information", HFILL }},
    { &hf_atn_ulcs_aare_apdu_protocol_version,
      { "protocol-version", "atn-ulcs.protocol_version",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_aare_apdu_protocol_version", HFILL }},
    { &hf_atn_ulcs_result,
      { "result", "atn-ulcs.result",
        FT_UINT32, BASE_DEC, VALS(atn_ulcs_Associate_result_vals), 0,
        "Associate_result", HFILL }},
    { &hf_atn_ulcs_result_source_diagnostic,
      { "result-source-diagnostic", "atn-ulcs.result_source_diagnostic",
        FT_UINT32, BASE_DEC, VALS(atn_ulcs_Associate_source_diagnostic_vals), 0,
        "Associate_source_diagnostic", HFILL }},
    { &hf_atn_ulcs_responding_AP_title,
      { "responding-AP-title", "atn-ulcs.responding_AP_title",
        FT_UINT32, BASE_DEC, VALS(atn_ulcs_AP_title_vals), 0,
        "AP_title", HFILL }},
    { &hf_atn_ulcs_responding_AE_qualifier,
      { "responding-AE-qualifier", "atn-ulcs.responding_AE_qualifier",
        FT_UINT32, BASE_DEC, VALS(atn_ulcs_AE_qualifier_vals), 0,
        "AE_qualifier", HFILL }},
    { &hf_atn_ulcs_responding_AP_invocation_identifier,
      { "responding-AP-invocation-identifier", "atn-ulcs.responding_AP_invocation_identifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "AP_invocation_identifier", HFILL }},
    { &hf_atn_ulcs_responding_AE_invocation_identifier,
      { "responding-AE-invocation-identifier", "atn-ulcs.responding_AE_invocation_identifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "AE_invocation_identifier", HFILL }},
    { &hf_atn_ulcs_responder_acse_requirements,
      { "responder-acse-requirements", "atn-ulcs.responder_acse_requirements",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ACSE_requirements", HFILL }},
    { &hf_atn_ulcs_responding_authentication_value,
      { "responding-authentication-value", "atn-ulcs.responding_authentication_value",
        FT_UINT32, BASE_DEC, VALS(atn_ulcs_Authentication_value_vals), 0,
        "Authentication_value", HFILL }},
    { &hf_atn_ulcs_rlrq_apdu_request_reason,
      { "reason", "atn-ulcs.reason",
        FT_UINT32, BASE_DEC, VALS(atn_ulcs_Release_request_reason_vals), 0,
        "Release_request_reason", HFILL }},
    { &hf_atn_ulcs_rlre_apdu_response_reason,
      { "reason", "atn-ulcs.reason",
        FT_UINT32, BASE_DEC, VALS(atn_ulcs_Release_response_reason_vals), 0,
        "Release_response_reason", HFILL }},
    { &hf_atn_ulcs_abort_source,
      { "abort-source", "atn-ulcs.abort_source",
        FT_UINT32, BASE_DEC, VALS(atn_ulcs_ABRT_source_vals), 0,
        "ABRT_source", HFILL }},
    { &hf_atn_ulcs_abort_diagnostic,
      { "abort-diagnostic", "atn-ulcs.abort_diagnostic",
        FT_UINT32, BASE_DEC, VALS(atn_ulcs_ABRT_diagnostic_vals), 0,
        "ABRT_diagnostic", HFILL }},
    { &hf_atn_ulcs_Application_context_name_list_item,
      { "Application-context-name", "atn-ulcs.Application_context_name",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_ulcs_ap_title_form2,
      { "ap-title-form2", "atn-ulcs.ap_title_form2",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_ulcs_ap_title_form1,
      { "ap-title-form1", "atn-ulcs.ap_title_form1",
        FT_UINT32, BASE_DEC, VALS(atn_ulcs_Name_vals), 0,
        NULL, HFILL }},
    { &hf_atn_ulcs_ae_qualifier_form2,
      { "ae-qualifier-form2", "atn-ulcs.ae_qualifier_form2",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_ulcs_ae_qualifier_form1,
      { "ae-qualifier-form1", "atn-ulcs.ae_qualifier_form1",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_ulcs_acse_service_user,
      { "acse-service-user", "atn-ulcs.acse_service_user",
        FT_UINT32, BASE_DEC, VALS(atn_ulcs_T_acse_service_user_vals), 0,
        NULL, HFILL }},
    { &hf_atn_ulcs_acse_service_provider,
      { "acse-service-provider", "atn-ulcs.acse_service_provider",
        FT_UINT32, BASE_DEC, VALS(atn_ulcs_T_acse_service_provider_vals), 0,
        NULL, HFILL }},
    { &hf_atn_ulcs_Association_information_item,
      { "EXTERNALt", "atn-ulcs.EXTERNALt_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_ulcs_charstring,
      { "charstring", "atn-ulcs.charstring",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_atn_ulcs_bitstring,
      { "bitstring", "atn-ulcs.bitstring",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_atn_ulcs_external,
      { "external", "atn-ulcs.external_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_ulcs_other,
      { "other", "atn-ulcs.other_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_ulcs_other_mechanism_name,
      { "other-mechanism-name", "atn-ulcs.other_mechanism_name",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_atn_ulcs_other_mechanism_value,
      { "other-mechanism-value", "atn-ulcs.other_mechanism_value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_ulcs_rdnSequence,
      { "rdnSequence", "atn-ulcs.rdnSequence",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_ulcs_RDNSequence_item,
      { "RelativeDistinguishedName", "atn-ulcs.RelativeDistinguishedName",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_ulcs_RelativeDistinguishedName_item,
      { "AttributeTypeAndValue", "atn-ulcs.AttributeTypeAndValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_ulcs_null,
      { "null", "atn-ulcs.null_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_ulcs_T_aarq_apdu_protocol_version_version1,
      { "version1", "atn-ulcs.version1",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_atn_ulcs_T_aare_apdu_protocol_version_version1,
      { "version1", "atn-ulcs.version1",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_atn_ulcs_ACSE_requirements_authentication,
      { "authentication", "atn-ulcs.authentication",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_atn_ulcs_ACSE_requirements_application_context_negotiation,
      { "application-context-negotiation", "atn-ulcs.application-context-negotiation",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},

/*--- End of included file: packet-atn-ulcs-hfarr.c ---*/
#line 788 "./asn1/atn-ulcs/packet-atn-ulcs-template.c"
        {&hf_atn_ses_type,
        { "SPDU Type",
          "atn-ulcs.ses.type",
          FT_UINT8,
          BASE_HEX,
          VALS(atn_ses_type),
          0xf8,
          "Indicates presence of session parameters",
          HFILL}},
        {&hf_atn_ses_param_ind,
        { "SPDU Parameter Indication",
          "atn-ulcs.ses.parameter-indication",
          FT_UINT8,
          BASE_HEX,
          VALS(atn_ses_param_ind),
          SES_PARAM_IND_MASK,
          "Indicates presence of session parameters",
          HFILL}},
      {&hf_atn_ses_param_b1,
        { "SRF Parameter B1",
          "atn-ulcs.ses.srf-b1",
          FT_UINT8,
          BASE_HEX,
          VALS(srf_b1),
          0x01,
          "Determines if transport connection reject is transient or persistent",
          HFILL}},
      {&hf_atn_ses_param_b2,
        { "SRF Parameter B2",
          "atn-ulcs.ses.srf-b2",
          FT_UINT8,
          BASE_HEX,
          VALS(srf_b2),
          0x02,
          "Determines if transport connection is retained or released",
          HFILL}},
      { &hf_atn_pres_err,
        { "Error Code", "atn-ulcs.pres.cpr-error",
          FT_UINT8,
          BASE_HEX,
          VALS(atn_pres_err),
          PRES_CPR_ER_MASK,
          NULL,
          HFILL}},
      { &hf_atn_pres_pdu_type,
        { "PDU type", "atn-ulcs.pres.pdu_type",
          FT_UINT8,
          BASE_HEX,
          NULL,
          ATN_SES_PRES_MASK,
          NULL,
          HFILL}},
    };

    static gint *ett[] = {

/*--- Included file: packet-atn-ulcs-ettarr.c ---*/
#line 1 "./asn1/atn-ulcs/packet-atn-ulcs-ettarr.c"
    &ett_atn_ulcs_Fully_encoded_data,
    &ett_atn_ulcs_PDV_list,
    &ett_atn_ulcs_T_presentation_data_values,
    &ett_atn_ulcs_EXTERNALt,
    &ett_atn_ulcs_T_encoding,
    &ett_atn_ulcs_ACSE_apdu,
    &ett_atn_ulcs_AARQ_apdu,
    &ett_atn_ulcs_T_aarq_apdu_protocol_version,
    &ett_atn_ulcs_AARE_apdu,
    &ett_atn_ulcs_T_aare_apdu_protocol_version,
    &ett_atn_ulcs_RLRQ_apdu,
    &ett_atn_ulcs_RLRE_apdu,
    &ett_atn_ulcs_ABRT_apdu,
    &ett_atn_ulcs_ACSE_requirements,
    &ett_atn_ulcs_Application_context_name_list,
    &ett_atn_ulcs_AP_title,
    &ett_atn_ulcs_AE_qualifier,
    &ett_atn_ulcs_Associate_source_diagnostic,
    &ett_atn_ulcs_Association_information,
    &ett_atn_ulcs_Authentication_value,
    &ett_atn_ulcs_T_other,
    &ett_atn_ulcs_Name,
    &ett_atn_ulcs_RDNSequence,
    &ett_atn_ulcs_RelativeDistinguishedName,
    &ett_atn_ulcs_AttributeTypeAndValue,

/*--- End of included file: packet-atn-ulcs-ettarr.c ---*/
#line 844 "./asn1/atn-ulcs/packet-atn-ulcs-template.c"
        &ett_atn_ses,
        &ett_atn_pres,
        &ett_atn_acse,
        &ett_atn_ulcs
    };

    proto_atn_ulcs = proto_register_protocol (
        ATN_ULCS_PROTO ,
        "ATN-ULCS",
        "atn-ulcs");

    proto_register_field_array (
        proto_atn_ulcs,
        hf_atn_ulcs,
        array_length(hf_atn_ulcs));

    proto_register_subtree_array (
        ett,
        array_length (ett));

    register_dissector(
        "atn-ulcs",
        dissect_atn_ulcs,
        proto_atn_ulcs);

    /* initiate sub dissector list */
    atn_ulcs_heur_subdissector_list = register_heur_dissector_list("atn-ulcs", proto_atn_ulcs);

    /* init aare/aare data */
    aarq_data_tree = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    atn_conversation_tree = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
}

void proto_reg_handoff_atn_ulcs(void)
{
    atn_cm_handle = find_dissector_add_dependency("atn-cm", proto_atn_ulcs);
    atn_cpdlc_handle = find_dissector_add_dependency("atn-cpdlc", proto_atn_ulcs);

    /* add session dissector to cotp dissector list dissector list*/
    heur_dissector_add(
        "cotp",
        dissect_atn_ulcs_heur,
        "ATN-ULCS over COTP",
        "atn-ucls_cotp",
        proto_atn_ulcs, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
