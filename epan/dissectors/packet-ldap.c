/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-ldap.c                                                              */
/* asn2wrs.py -b -q -L -p ldap -c ./ldap.cnf -s ./packet-ldap-template -D . -O ../.. Lightweight-Directory-Access-Protocol-V3.asn */

/* packet-ldap-template.c
 * Routines for ldap packet dissection
 *
* See RFC 3494 (LDAP v2), RFC 4511 (LDAP v3), and RFC 2222 (SASL).
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This is not a complete implementation. It doesn't handle the full version 3, more specifically,
 * it handles only the commands of version 2, but any additional characteristics of the ver3 command are supported.
 * It's also missing extensible search filters.
 *
 * There should probably be a lot more error checking, I simply assume that if we have a full packet, it will be a complete
 * and correct packet.
 *
 * AFAIK, it will handle all messages used by the OpenLDAP 1.2.9 server and libraries which was my goal. I do plan to add
 * the remaining commands as time permits but this is not a priority to me. Send me an email if you need it and I'll see what
 * I can do.
 *
 * Doug Nazar
 * nazard@dragoninc.on.ca
 */

/*
 * 11/11/2002 - Fixed problem when decoding LDAP with desegmentation enabled and the
 *              ASN.1 BER Universal Class Tag: "Sequence Of" header is encapsulated across 2
 *              TCP segments.
 *
 * Ronald W. Henderson
 * ronald.henderson@cognicaseusa.com
 */

/*
 * 20-JAN-2004 - added decoding of MS-CLDAP netlogon RPC
 *               using information from the SNIA 2003 conference paper :
 *               Active Directory Domain Controller Location Service
 *                    by Anthony Liguori
 * ronnie sahlberg
 */

/*
 * 17-DEC-2004 - added basic decoding for LDAP Controls
 * 20-DEC-2004 - added handling for GSS-API encrypted blobs
 *
 * Stefan Metzmacher <metze@samba.org>
 *
 * 15-NOV-2005 - Changed to use the asn2wrs compiler
 * Anders Broman <anders.broman@ericsson.com>
 */

/*
 * 3-AUG-2008 - Extended the cldap support to include all netlogon data types.
 *              Updated cldap_netlogon_flags to include Windows 2008 flags
 *              Expanded the ntver ldap option with bit field
 *
 * Gary Reynolds <gazzadownunder@yahoo.co.uk>
 */

/*
 * 09-DEC-2009 - Added support for RFC4533
 *               Content Synchronization Operation (aka syncrepl)
 * 11-DEC-2009 - Added support for IntermediateResponse (LDAP v3 from RFC 4511)
 * Mathieu Parent <math.parent@gmail.com>
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/srt_table.h>
#include <epan/oids.h>
#include <epan/strutil.h>
#include <epan/show_exception.h>
#include <epan/asn1.h>
#include <epan/proto_data.h>
#include <epan/expert.h>
#include <epan/uat.h>
#include <epan/charsets.h>
#include <wsutil/str_util.h>
#include "packet-frame.h"
#include "packet-tcp.h"
#include "packet-windows-common.h"
#include "packet-dcerpc.h"

#include "packet-ldap.h"
#include "packet-ntlmssp.h"
#include "packet-tls.h"
#include "packet-tls-utils.h"
#include "packet-gssapi.h"
#include "packet-acdr.h"

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-dns.h"

#define PNAME  "Lightweight Directory Access Protocol"
#define PSNAME "LDAP"
#define PFNAME "ldap"

void proto_register_ldap(void);
void proto_reg_handoff_ldap(void);

/* Initialize the protocol and registered fields */
static int ldap_tap;
static int proto_ldap;
static int proto_cldap;

static int hf_ldap_sasl_buffer_length;
static int hf_ldap_response_in;
static int hf_ldap_response_to;
static int hf_ldap_time;
static int hf_ldap_guid;

static int hf_mscldap_ntver_flags;
static int hf_mscldap_ntver_flags_v1;
static int hf_mscldap_ntver_flags_v5;
static int hf_mscldap_ntver_flags_v5ex;
static int hf_mscldap_ntver_flags_v5ep;
static int hf_mscldap_ntver_flags_vcs;
static int hf_mscldap_ntver_flags_vnt4;
static int hf_mscldap_ntver_flags_vpdc;
static int hf_mscldap_ntver_flags_vip;
static int hf_mscldap_ntver_flags_vl;
static int hf_mscldap_ntver_flags_vgc;

static int hf_mscldap_netlogon_ipaddress_family;
static int hf_mscldap_netlogon_ipaddress_port;
static int hf_mscldap_netlogon_ipaddress;
static int hf_mscldap_netlogon_ipaddress_ipv4;
static int hf_mscldap_netlogon_opcode;
static int hf_mscldap_netlogon_flags;
static int hf_mscldap_netlogon_flags_pdc;
static int hf_mscldap_netlogon_flags_gc;
static int hf_mscldap_netlogon_flags_ldap;
static int hf_mscldap_netlogon_flags_ds;
static int hf_mscldap_netlogon_flags_kdc;
static int hf_mscldap_netlogon_flags_timeserv;
static int hf_mscldap_netlogon_flags_closest;
static int hf_mscldap_netlogon_flags_writable;
static int hf_mscldap_netlogon_flags_good_timeserv;
static int hf_mscldap_netlogon_flags_ndnc;
static int hf_mscldap_netlogon_flags_fnc;
static int hf_mscldap_netlogon_flags_dnc;
static int hf_mscldap_netlogon_flags_dns;
static int hf_mscldap_netlogon_flags_wdc;
static int hf_mscldap_netlogon_flags_rodc;
static int hf_mscldap_domain_guid;
static int hf_mscldap_forest;
static int hf_mscldap_domain;
static int hf_mscldap_hostname;
static int hf_mscldap_nb_domain_z;
static int hf_mscldap_nb_domain;
static int hf_mscldap_nb_hostname_z;
static int hf_mscldap_nb_hostname;
static int hf_mscldap_username_z;
static int hf_mscldap_username;
static int hf_mscldap_sitename;
static int hf_mscldap_clientsitename;
static int hf_mscldap_netlogon_lm_token;
static int hf_mscldap_netlogon_nt_token;
static int hf_ldap_sid;
static int hf_ldap_AccessMask_ADS_CREATE_CHILD;
static int hf_ldap_AccessMask_ADS_DELETE_CHILD;
static int hf_ldap_AccessMask_ADS_LIST;
static int hf_ldap_AccessMask_ADS_SELF_WRITE;
static int hf_ldap_AccessMask_ADS_READ_PROP;
static int hf_ldap_AccessMask_ADS_WRITE_PROP;
static int hf_ldap_AccessMask_ADS_DELETE_TREE;
static int hf_ldap_AccessMask_ADS_LIST_OBJECT;
static int hf_ldap_AccessMask_ADS_CONTROL_ACCESS;
static int hf_ldap_LDAPMessage_PDU;
static int hf_ldap_object_security_flag;
static int hf_ldap_ancestor_first_flag;
static int hf_ldap_public_data_only_flag;
static int hf_ldap_incremental_value_flag;
static int hf_ldap_oid;
static int hf_ldap_gssapi_encrypted_payload;

static int hf_ldap_SearchControlValue_PDU;        /* SearchControlValue */
static int hf_ldap_SortKeyList_PDU;               /* SortKeyList */
static int hf_ldap_SortResult_PDU;                /* SortResult */
static int hf_ldap_DirSyncControlValue_PDU;       /* DirSyncControlValue */
static int hf_ldap_PasswdModifyRequestValue_PDU;  /* PasswdModifyRequestValue */
static int hf_ldap_CancelRequestValue_PDU;        /* CancelRequestValue */
static int hf_ldap_SyncRequestValue_PDU;          /* SyncRequestValue */
static int hf_ldap_SyncStateValue_PDU;            /* SyncStateValue */
static int hf_ldap_SyncDoneValue_PDU;             /* SyncDoneValue */
static int hf_ldap_SyncInfoValue_PDU;             /* SyncInfoValue */
static int hf_ldap_PasswordPolicyResponseValue_PDU;  /* PasswordPolicyResponseValue */
static int hf_ldap_messageID;                     /* MessageID */
static int hf_ldap_protocolOp;                    /* ProtocolOp */
static int hf_ldap_controls;                      /* Controls */
static int hf_ldap_bindRequest;                   /* BindRequest */
static int hf_ldap_bindResponse;                  /* BindResponse */
static int hf_ldap_unbindRequest;                 /* UnbindRequest */
static int hf_ldap_searchRequest;                 /* SearchRequest */
static int hf_ldap_searchResEntry;                /* SearchResultEntry */
static int hf_ldap_searchResDone;                 /* SearchResultDone */
static int hf_ldap_searchResRef;                  /* SearchResultReference */
static int hf_ldap_modifyRequest;                 /* ModifyRequest */
static int hf_ldap_modifyResponse;                /* ModifyResponse */
static int hf_ldap_addRequest;                    /* AddRequest */
static int hf_ldap_addResponse;                   /* AddResponse */
static int hf_ldap_delRequest;                    /* DelRequest */
static int hf_ldap_delResponse;                   /* DelResponse */
static int hf_ldap_modDNRequest;                  /* ModifyDNRequest */
static int hf_ldap_modDNResponse;                 /* ModifyDNResponse */
static int hf_ldap_compareRequest;                /* CompareRequest */
static int hf_ldap_compareResponse;               /* CompareResponse */
static int hf_ldap_abandonRequest;                /* AbandonRequest */
static int hf_ldap_extendedReq;                   /* ExtendedRequest */
static int hf_ldap_extendedResp;                  /* ExtendedResponse */
static int hf_ldap_intermediateResponse;          /* IntermediateResponse */
static int hf_ldap_AttributeDescriptionList_item;  /* AttributeDescription */
static int hf_ldap_attributeDesc;                 /* AttributeDescription */
static int hf_ldap_assertionValue;                /* AssertionValue */
static int hf_ldap_type;                          /* AttributeDescription */
static int hf_ldap_vals;                          /* SET_OF_AttributeValue */
static int hf_ldap_vals_item;                     /* AttributeValue */
static int hf_ldap_resultCode;                    /* T_resultCode */
static int hf_ldap_matchedDN;                     /* LDAPDN */
static int hf_ldap_errorMessage;                  /* ErrorMessage */
static int hf_ldap_referral;                      /* Referral */
static int hf_ldap_Referral_item;                 /* LDAPURL */
static int hf_ldap_Controls_item;                 /* Control */
static int hf_ldap_controlType;                   /* ControlType */
static int hf_ldap_criticality;                   /* BOOLEAN */
static int hf_ldap_controlValue;                  /* T_controlValue */
static int hf_ldap_version;                       /* INTEGER_1_127 */
static int hf_ldap_name;                          /* LDAPDN */
static int hf_ldap_authentication;                /* AuthenticationChoice */
static int hf_ldap_simple;                        /* Simple */
static int hf_ldap_sasl;                          /* SaslCredentials */
static int hf_ldap_ntlmsspNegotiate;              /* T_ntlmsspNegotiate */
static int hf_ldap_ntlmsspAuth;                   /* T_ntlmsspAuth */
static int hf_ldap_mechanism;                     /* Mechanism */
static int hf_ldap_credentials;                   /* Credentials */
static int hf_ldap_bindResponse_resultCode;       /* BindResponse_resultCode */
static int hf_ldap_bindResponse_matchedDN;        /* T_bindResponse_matchedDN */
static int hf_ldap_serverSaslCreds;               /* ServerSaslCreds */
static int hf_ldap_baseObject;                    /* LDAPDN */
static int hf_ldap_scope;                         /* T_scope */
static int hf_ldap_derefAliases;                  /* T_derefAliases */
static int hf_ldap_sizeLimit;                     /* INTEGER_0_maxInt */
static int hf_ldap_timeLimit;                     /* INTEGER_0_maxInt */
static int hf_ldap_typesOnly;                     /* BOOLEAN */
static int hf_ldap_filter;                        /* T_filter */
static int hf_ldap_searchRequest_attributes;      /* AttributeDescriptionList */
static int hf_ldap_and;                           /* T_and */
static int hf_ldap_and_item;                      /* T_and_item */
static int hf_ldap_or;                            /* T_or */
static int hf_ldap_or_item;                       /* T_or_item */
static int hf_ldap_not;                           /* T_not */
static int hf_ldap_equalityMatch;                 /* T_equalityMatch */
static int hf_ldap_substrings;                    /* SubstringFilter */
static int hf_ldap_greaterOrEqual;                /* T_greaterOrEqual */
static int hf_ldap_lessOrEqual;                   /* T_lessOrEqual */
static int hf_ldap_present;                       /* T_present */
static int hf_ldap_approxMatch;                   /* T_approxMatch */
static int hf_ldap_extensibleMatch;               /* T_extensibleMatch */
static int hf_ldap_substringFilter_substrings;    /* T_substringFilter_substrings */
static int hf_ldap_substringFilter_substrings_item;  /* T_substringFilter_substrings_item */
static int hf_ldap_initial;                       /* LDAPString */
static int hf_ldap_any;                           /* LDAPString */
static int hf_ldap_final;                         /* LDAPString */
static int hf_ldap_matchingRule;                  /* MatchingRuleId */
static int hf_ldap_matchValue;                    /* AssertionValue */
static int hf_ldap_dnAttributes;                  /* T_dnAttributes */
static int hf_ldap_objectName;                    /* LDAPDN */
static int hf_ldap_searchResultEntry_attributes;  /* PartialAttributeList */
static int hf_ldap_PartialAttributeList_item;     /* PartialAttributeList_item */
static int hf_ldap__untag_item;                   /* LDAPURL */
static int hf_ldap_object;                        /* LDAPDN */
static int hf_ldap_modifyRequest_modification;    /* ModifyRequest_modification */
static int hf_ldap_modifyRequest_modification_item;  /* T_modifyRequest_modification_item */
static int hf_ldap_operation;                     /* T_operation */
static int hf_ldap_modification;                  /* AttributeTypeAndValues */
static int hf_ldap_entry;                         /* LDAPDN */
static int hf_ldap_attributes;                    /* AttributeList */
static int hf_ldap_AttributeList_item;            /* AttributeList_item */
static int hf_ldap_newrdn;                        /* RelativeLDAPDN */
static int hf_ldap_deleteoldrdn;                  /* BOOLEAN */
static int hf_ldap_newSuperior;                   /* LDAPDN */
static int hf_ldap_ava;                           /* AttributeValueAssertion */
static int hf_ldap_requestName;                   /* LDAPOID */
static int hf_ldap_requestValue;                  /* T_requestValue */
static int hf_ldap_extendedResponse_resultCode;   /* ExtendedResponse_resultCode */
static int hf_ldap_responseName;                  /* ResponseName */
static int hf_ldap_response;                      /* OCTET_STRING */
static int hf_ldap_intermediateResponse_responseValue;  /* T_intermediateResponse_responseValue */
static int hf_ldap_size;                          /* INTEGER */
static int hf_ldap_cookie;                        /* OCTET_STRING */
static int hf_ldap_SortKeyList_item;              /* SortKeyList_item */
static int hf_ldap_attributeType;                 /* AttributeDescription */
static int hf_ldap_orderingRule;                  /* MatchingRuleId */
static int hf_ldap_reverseOrder;                  /* BOOLEAN */
static int hf_ldap_sortResult;                    /* T_sortResult */
static int hf_ldap_flags;                         /* DirSyncFlags */
static int hf_ldap_maxBytes;                      /* INTEGER */
static int hf_ldap_userIdentity;                  /* OCTET_STRING */
static int hf_ldap_oldPasswd;                     /* OCTET_STRING */
static int hf_ldap_newPasswd;                     /* OCTET_STRING */
static int hf_ldap_cancelID;                      /* MessageID */
static int hf_ldap_mode;                          /* T_mode */
static int hf_ldap_reloadHint;                    /* BOOLEAN */
static int hf_ldap_state;                         /* T_state */
static int hf_ldap_entryUUID;                     /* SyncUUID */
static int hf_ldap_refreshDeletes;                /* BOOLEAN */
static int hf_ldap_newcookie;                     /* OCTET_STRING */
static int hf_ldap_refreshDelete;                 /* T_refreshDelete */
static int hf_ldap_refreshDone;                   /* BOOLEAN */
static int hf_ldap_refreshPresent;                /* T_refreshPresent */
static int hf_ldap_syncIdSet;                     /* T_syncIdSet */
static int hf_ldap_syncUUIDs;                     /* SET_OF_SyncUUID */
static int hf_ldap_syncUUIDs_item;                /* SyncUUID */
static int hf_ldap_warning;                       /* T_warning */
static int hf_ldap_timeBeforeExpiration;          /* INTEGER_0_maxInt */
static int hf_ldap_graceAuthNsRemaining;          /* INTEGER_0_maxInt */
static int hf_ldap_error;                         /* T_error */

/* Initialize the subtree pointers */
static int ett_ldap;
static int ett_ldap_msg;
static int ett_ldap_sasl_blob;
static int ett_ldap_payload;
static int ett_mscldap_netlogon_flags;
static int ett_mscldap_ntver_flags;
static int ett_mscldap_ipdetails;
static int ett_ldap_DirSyncFlagsSubEntry;

static int ett_ldap_LDAPMessage;
static int ett_ldap_ProtocolOp;
static int ett_ldap_AttributeDescriptionList;
static int ett_ldap_AttributeValueAssertion;
static int ett_ldap_Attribute;
static int ett_ldap_SET_OF_AttributeValue;
static int ett_ldap_LDAPResult;
static int ett_ldap_Referral;
static int ett_ldap_Controls;
static int ett_ldap_Control;
static int ett_ldap_BindRequest_U;
static int ett_ldap_AuthenticationChoice;
static int ett_ldap_SaslCredentials;
static int ett_ldap_BindResponse_U;
static int ett_ldap_SearchRequest_U;
static int ett_ldap_Filter;
static int ett_ldap_T_and;
static int ett_ldap_T_or;
static int ett_ldap_SubstringFilter;
static int ett_ldap_T_substringFilter_substrings;
static int ett_ldap_T_substringFilter_substrings_item;
static int ett_ldap_MatchingRuleAssertion;
static int ett_ldap_SearchResultEntry_U;
static int ett_ldap_PartialAttributeList;
static int ett_ldap_PartialAttributeList_item;
static int ett_ldap_SEQUENCE_OF_LDAPURL;
static int ett_ldap_ModifyRequest_U;
static int ett_ldap_ModifyRequest_modification;
static int ett_ldap_T_modifyRequest_modification_item;
static int ett_ldap_AttributeTypeAndValues;
static int ett_ldap_AddRequest_U;
static int ett_ldap_AttributeList;
static int ett_ldap_AttributeList_item;
static int ett_ldap_ModifyDNRequest_U;
static int ett_ldap_CompareRequest_U;
static int ett_ldap_ExtendedRequest_U;
static int ett_ldap_ExtendedResponse_U;
static int ett_ldap_IntermediateResponse_U;
static int ett_ldap_SearchControlValue;
static int ett_ldap_SortKeyList;
static int ett_ldap_SortKeyList_item;
static int ett_ldap_SortResult;
static int ett_ldap_DirSyncControlValue;
static int ett_ldap_PasswdModifyRequestValue;
static int ett_ldap_CancelRequestValue;
static int ett_ldap_SyncRequestValue;
static int ett_ldap_SyncStateValue;
static int ett_ldap_SyncDoneValue;
static int ett_ldap_SyncInfoValue;
static int ett_ldap_T_refreshDelete;
static int ett_ldap_T_refreshPresent;
static int ett_ldap_T_syncIdSet;
static int ett_ldap_SET_OF_SyncUUID;
static int ett_ldap_PasswordPolicyResponseValue;
static int ett_ldap_T_warning;

static expert_field ei_ldap_exceeded_filter_length;
static expert_field ei_ldap_too_many_filter_elements;

static dissector_table_t ldap_name_dissector_table;
static const char *object_identifier_id; /* LDAP OID */

static bool do_protocolop;
static char     *attr_type;
static bool is_binary_attr_type;
static bool ldap_found_in_frame;

#define TCP_PORT_RANGE_LDAP             "389,3268" /* 3268 is Windows 2000 Global Catalog */
#define TCP_PORT_LDAPS                  636
#define UDP_PORT_CLDAP                  389

/* desegmentation of LDAP */
static bool ldap_desegment = true;
static unsigned global_ldaps_tcp_port = TCP_PORT_LDAPS;
static unsigned ssl_port;

static dissector_handle_t gssapi_handle;
static dissector_handle_t gssapi_wrap_handle;
static dissector_handle_t ntlmssp_handle;
static dissector_handle_t spnego_handle;
static dissector_handle_t tls_handle;
static dissector_handle_t ldap_handle;
static dissector_handle_t cldap_handle;

static void prefs_register_ldap(void); /* forward declaration for use in preferences registration */


/* different types of rpc calls ontop of ms cldap */
#define MSCLDAP_RPC_NETLOGON  1

/* Message type Choice values */
static const value_string ldap_ProtocolOp_choice_vals[] = {
  {   0, "bindRequest" },
  {   1, "bindResponse" },
  {   2, "unbindRequest" },
  {   3, "searchRequest" },
  {   4, "searchResEntry" },
  {   5, "searchResDone" },
  {   6, "searchResRef" },
  {   7, "modifyRequest" },
  {   8, "modifyResponse" },
  {   9, "addRequest" },
  {  10, "addResponse" },
  {  11, "delRequest" },
  {  12, "delResponse" },
  {  13, "modDNRequest" },
  {  14, "modDNResponse" },
  {  15, "compareRequest" },
  {  16, "compareResponse" },
  {  17, "abandonRequest" },
  {  18, "extendedReq" },
  {  19, "extendedResp" },
  {  20, "intermediateResponse" },
  { 0, NULL }
};

/* Procedure names (used in Service Response Time */
const value_string ldap_procedure_names[] = {
  {   0, "Bind" },
  {   3, "Search" },
  {   6, "Modify" },
  {   8, "Add" },
  {  10, "Delete" },
  {  12, "Modrdn" },
  {  14, "Compare" },
  {  23, "Extended" },
  { 0, NULL }
};

#define LOGON_PRIMARY_QUERY             7
#define LOGON_PRIMARY_RESPONSE         12
#define LOGON_SAM_LOGON_REQUEST        18
#define LOGON_SAM_LOGON_RESPONSE       19
#define LOGON_SAM_PAUSE_RESPONSE       20
#define LOGON_SAM_USER_UNKNOWN         21
#define LOGON_SAM_LOGON_RESPONSE_EX    23
#define LOGON_SAM_PAUSE_RESPONSE_EX    24
#define LOGON_SAM_USER_UNKNOWN_EX      25

static const value_string netlogon_opcode_vals[] = {
  { LOGON_PRIMARY_QUERY,         "LOGON_PRIMARY_QUERY" },
  { LOGON_PRIMARY_RESPONSE,      "LOGON_PRIMARY_RESPONSE" },
  { LOGON_SAM_LOGON_REQUEST,     "LOGON_SAM_LOGON_REQUEST" },
  { LOGON_SAM_LOGON_RESPONSE,    "LOGON_SAM_LOGON_RESPONSE" },
  { LOGON_SAM_PAUSE_RESPONSE,    "LOGON_SAM_PAUSE_RESPONSE" },
  { LOGON_SAM_LOGON_RESPONSE_EX, "LOGON_SAM_LOGON_RESPONSE_EX" },
  { LOGON_SAM_PAUSE_RESPONSE_EX, "LOGON_SAM_PAUSE_RESPONSE_EX" },
  { LOGON_SAM_USER_UNKNOWN_EX,   "LOGON_SAM_USER_UNKNOWN_EX" },
  { 0, NULL }
};

#define LDAP_NUM_PROCEDURES     24

static void
ldapstat_init(struct register_srt* srt _U_, GArray* srt_array)
{
  srt_stat_table *ldap_srt_table;
  uint32_t i;

  ldap_srt_table = init_srt_table("LDAP Commands", NULL, srt_array, LDAP_NUM_PROCEDURES, NULL, "ldap.protocolOp", NULL);
  for (i = 0; i < LDAP_NUM_PROCEDURES; i++)
  {
    init_srt_table_row(ldap_srt_table, i, val_to_str_const(i, ldap_procedure_names, "<unknown>"));
  }
}

static tap_packet_status
ldapstat_packet(void *pldap, packet_info *pinfo, epan_dissect_t *edt _U_, const void *psi, tap_flags_t flags _U_)
{
  unsigned i = 0;
  srt_stat_table *ldap_srt_table;
  const ldap_call_response_t *ldap=(const ldap_call_response_t *)psi;
  srt_data_t *data = (srt_data_t *)pldap;

  /* we are only interested in reply packets */
  if(ldap->is_request){
    return TAP_PACKET_DONT_REDRAW;
  }
  /* if we haven't seen the request, just ignore it */
  if(!ldap->req_frame){
    return TAP_PACKET_DONT_REDRAW;
  }

  /* only use the commands we know how to handle */
  switch(ldap->protocolOpTag){
  case LDAP_REQ_BIND:
  case LDAP_REQ_SEARCH:
  case LDAP_REQ_MODIFY:
  case LDAP_REQ_ADD:
  case LDAP_REQ_DELETE:
  case LDAP_REQ_MODRDN:
  case LDAP_REQ_COMPARE:
  case LDAP_REQ_EXTENDED:
    break;
  default:
    return TAP_PACKET_DONT_REDRAW;
  }

  ldap_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);

  add_srt_table_data(ldap_srt_table, ldap->protocolOpTag, &ldap->req_time, pinfo);
  return TAP_PACKET_REDRAW;
}

/*
 * Data structure attached to a conversation, giving authentication
 * information from a bind request.
 */
typedef struct ldap_conv_info_t {
  unsigned auth_type;    /* authentication type */
  char *auth_mech;    /* authentication mechanism */
  uint32_t first_auth_frame;  /* first frame that would use a security layer */
  wmem_map_t *unmatched;
  wmem_map_t *matched;
  bool is_mscldap;
  uint32_t num_results;
  bool start_tls_pending;
  uint32_t start_tls_frame;
} ldap_conv_info_t;

static unsigned
ldap_info_hash_matched(const void *k)
{
  const ldap_call_response_t *key = (const ldap_call_response_t *)k;

  return key->messageId;
}

static int
ldap_info_equal_matched(const void *k1, const void *k2)
{
  const ldap_call_response_t *key1 = (const ldap_call_response_t*)k1;
  const ldap_call_response_t *key2 = (const ldap_call_response_t*)k2;

  if( key1->req_frame && key2->req_frame && (key1->req_frame!=key2->req_frame) ){
    return 0;
  }
  /* a response may span multiple frames
  if( key1->rep_frame && key2->rep_frame && (key1->rep_frame!=key2->rep_frame) ){
    return 0;
  }
  */

  return key1->messageId==key2->messageId;
}

static unsigned
ldap_info_hash_unmatched(const void *k)
{
  const ldap_call_response_t *key = (const ldap_call_response_t*)k;

  return key->messageId;
}

static int
ldap_info_equal_unmatched(const void *k1, const void *k2)
{
  const ldap_call_response_t *key1 = (const ldap_call_response_t*)k1;
  const ldap_call_response_t *key2 = (const ldap_call_response_t*)k2;

  return key1->messageId==key2->messageId;
}


/* These are the NtVer flags from MS-ADTS section 6.3.1.1
 * https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts
 */

static const true_false_string tfs_ntver_v1 = {
  "Client requested version 1 netlogon response",
  "Version 1 netlogon response not requested"
};

static const true_false_string tfs_ntver_v5 = {
  "Client requested version 5 netlogon response",
  "Version 5 netlogon response not requested"
};
static const true_false_string tfs_ntver_v5ex = {
  "Client requested version 5 extended netlogon response",
  "Version 5 extended response not requested"
};
static const true_false_string tfs_ntver_v5ep = {
  "Client has requested IP address of the server",
  "IP address of server not requested"
};
static const true_false_string tfs_ntver_vcs = {
  "Client has asked for the closest site information",
  "Closest site information not requested"
};
static const true_false_string tfs_ntver_vnt4 = {
  "Client is requesting server to avoid NT4 emulation",
  "Only full AD DS requested"
};
static const true_false_string tfs_ntver_vpdc = {
  "Client has requested the Primary Domain Controller",
  "Primary Domain Controller not requested"
};
static const true_false_string tfs_ntver_vip = {
  "Client has requested IP details (obsolete)",
  "IP details not requested (obsolete)"
};
static const true_false_string tfs_ntver_vl = {
  "Client indicated that it is the local machine",
  "Client is not the local machine"
};static const true_false_string tfs_ntver_vgc = {
  "Client has requested a Global Catalog server",
  "Global Catalog not requested"
};

/* Stuff for generation/handling of fields for custom AttributeValues */
typedef struct _attribute_type_t {
  char* attribute_type;
  char* attribute_desc;
} attribute_type_t;

static attribute_type_t* attribute_types;
static unsigned num_attribute_types;

static GHashTable* attribute_types_hash;
static hf_register_info* dynamic_hf;
static unsigned dynamic_hf_size;

static bool
attribute_types_update_cb(void *r, char **err)
{
  attribute_type_t *rec = (attribute_type_t *)r;
  char c;

  if (rec->attribute_type == NULL) {
    *err = g_strdup("Attribute type can't be empty");
    return false;
  }

  g_strstrip(rec->attribute_type);
  if (rec->attribute_type[0] == 0) {
    *err = g_strdup("Attribute type can't be empty");
    return false;
  }

  /* Check for invalid characters (to avoid asserting out when
   * registering the field).
   */
  c = proto_check_field_name(rec->attribute_type);
  if (c) {
    *err = ws_strdup_printf("Attribute type can't contain '%c'", c);
    return false;
  }

  *err = NULL;
  return true;
}

static void *
attribute_types_copy_cb(void* n, const void* o, size_t siz _U_)
{
  attribute_type_t* new_rec = (attribute_type_t*)n;
  const attribute_type_t* old_rec = (const attribute_type_t*)o;

  new_rec->attribute_type = g_strdup(old_rec->attribute_type);
  new_rec->attribute_desc = g_strdup(old_rec->attribute_desc);

  return new_rec;
}

static void
attribute_types_free_cb(void*r)
{
  attribute_type_t* rec = (attribute_type_t*)r;

  g_free(rec->attribute_type);
  g_free(rec->attribute_desc);
}

UAT_CSTRING_CB_DEF(attribute_types, attribute_type, attribute_type_t)
UAT_CSTRING_CB_DEF(attribute_types, attribute_desc, attribute_type_t)

/*
 *
 */
static int*
get_hf_for_header(char* attribute_type)
{
  int* hf_id = NULL;

  if (attribute_types_hash) {
    hf_id = (int*) g_hash_table_lookup(attribute_types_hash, attribute_type);
  } else {
    hf_id = NULL;
  }

  return hf_id;
}

/*
 *
 */
static void
deregister_attribute_types(void)
{
  if (dynamic_hf) {
    /* Deregister all fields */
    for (unsigned i = 0; i < dynamic_hf_size; i++) {
      proto_deregister_field (proto_ldap, *(dynamic_hf[i].p_id));
      g_free (dynamic_hf[i].p_id);
    }

    proto_add_deregistered_data (dynamic_hf);
    dynamic_hf = NULL;
    dynamic_hf_size = 0;
  }

  if (attribute_types_hash) {
    g_hash_table_destroy (attribute_types_hash);
    attribute_types_hash = NULL;
  }
}

static void
attribute_types_post_update_cb(void)
{
  int* hf_id;
  char* attribute_type;

  deregister_attribute_types();

  if (num_attribute_types) {
    attribute_types_hash = g_hash_table_new(g_str_hash, g_str_equal);
    dynamic_hf = g_new0(hf_register_info,num_attribute_types);
    dynamic_hf_size = num_attribute_types;

    for (unsigned i = 0; i < dynamic_hf_size; i++) {
      hf_id = g_new(int,1);
      *hf_id = -1;
      attribute_type = g_strdup(attribute_types[i].attribute_type);

      dynamic_hf[i].p_id = hf_id;
      dynamic_hf[i].hfinfo.name = attribute_type;
      dynamic_hf[i].hfinfo.abbrev = ws_strdup_printf("ldap.AttributeValue.%s", attribute_type);
      dynamic_hf[i].hfinfo.type = FT_STRING;
      dynamic_hf[i].hfinfo.display = BASE_NONE;
      dynamic_hf[i].hfinfo.strings = NULL;
      dynamic_hf[i].hfinfo.bitmask = 0;
      dynamic_hf[i].hfinfo.blurb = g_strdup(attribute_types[i].attribute_desc);
      HFILL_INIT(dynamic_hf[i]);

      g_hash_table_insert(attribute_types_hash, attribute_type, hf_id);
    }

    proto_register_field_array(proto_ldap, dynamic_hf, dynamic_hf_size);
  }
}

static void
attribute_types_reset_cb(void)
{
  deregister_attribute_types();
}

/* MS-ADTS specification, section 6.3.1.1, NETLOGON_NT_VERSION Options Bits */
static int dissect_mscldap_ntver_flags(proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
  static int * const flags[] = {
    &hf_mscldap_ntver_flags_v1,
    &hf_mscldap_ntver_flags_v5,
    &hf_mscldap_ntver_flags_v5ex,
    &hf_mscldap_ntver_flags_v5ep,
    &hf_mscldap_ntver_flags_vcs,
    &hf_mscldap_ntver_flags_vnt4,
    &hf_mscldap_ntver_flags_vpdc,
    &hf_mscldap_ntver_flags_vip,
    &hf_mscldap_ntver_flags_vl,
    &hf_mscldap_ntver_flags_vgc,
    NULL
  };

  proto_tree_add_bitmask_with_flags(parent_tree, tvb, offset, hf_mscldap_ntver_flags,
                           ett_mscldap_ntver_flags, flags, ENC_LITTLE_ENDIAN, BMT_NO_FALSE);
  offset += 4;

  return offset;
}

/* This string contains the last LDAPString that was decoded */
static const char *attributedesc_string;

/* This string contains the last AssertionValue that was decoded */
static char *ldapvalue_string;

/* if the octet string contain all printable ASCII characters, then
 * display it as a string, othervise just display it in hex.
 */
static int
dissect_ldap_AssertionValue(bool implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index)
{
  int8_t ber_class;
  bool pc, ind, is_ascii;
  int32_t tag;
  uint32_t len;

  if(!implicit_tag){
    offset=get_ber_identifier(tvb, offset, &ber_class, &pc, &tag);
    offset=get_ber_length(tvb, offset, &len, &ind);
  } else {
    len=tvb_reported_length_remaining(tvb,offset);
  }

  if(len==0){
    return offset;
  }


  /*
   * Some special/wellknown attributes in common LDAP (read AD)
   * are neither ascii strings nor blobs of hex data.
   * Special case these attributes and decode them more nicely.
   *
   * Add more special cases as required to prettify further
   * (there can't be that many ones that are truly interesting)
   */
  if(attributedesc_string && !strncmp("DomainSid", attributedesc_string, 9)){
    tvbuff_t *sid_tvb;
    char *tmpstr;

    /* this octet string contains an NT SID */
    sid_tvb=tvb_new_subset_length(tvb, offset, len);
    dissect_nt_sid(sid_tvb, 0, tree, "SID", &tmpstr, hf_index);
    ldapvalue_string=tmpstr;

    goto finished;
  } else if ( (len==16) /* GUIDs are always 16 bytes */
  && (attributedesc_string && !strncmp("DomainGuid", attributedesc_string, 10))) {
    uint8_t drep[4] = { 0x10, 0x00, 0x00, 0x00}; /* fake DREP struct */
    e_guid_t uuid;

    /* This octet string contained a GUID */
    dissect_dcerpc_uuid_t(tvb, offset, actx->pinfo, tree, drep, hf_ldap_guid, &uuid);

    ldapvalue_string=(char*)wmem_alloc(actx->pinfo->pool, 1024);
    snprintf(ldapvalue_string, 1023, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
               uuid.data1, uuid.data2, uuid.data3, uuid.data4[0], uuid.data4[1],
               uuid.data4[2], uuid.data4[3], uuid.data4[4], uuid.data4[5],
               uuid.data4[6], uuid.data4[7]);

    goto finished;
  } else if (attributedesc_string && !strncmp("NtVer", attributedesc_string, 5)){
    uint32_t flags;

    len = 0;
    /* get flag value to populate ldapvalue_string */
    flags=tvb_get_letohl(tvb, offset);

    ldapvalue_string=(char*)wmem_alloc(actx->pinfo->pool, 1024);
    snprintf(ldapvalue_string, 1023, "0x%08x",flags);

    /* populate bitmask subtree */
    offset = dissect_mscldap_ntver_flags(tree, tvb, offset);

    goto finished;


  }

  /*
   * It was not one of our "wellknown" attributes so make the best
   * we can and just try to see if it is an ascii string or if it
   * is a binary blob.
   *
   * XXX - should we support reading RFC 2252-style schemas
   * for LDAP, and using that to determine how to display
   * attribute values and assertion values?
   *
   * -- I don't think there are full schemas available that describe the
   *  interesting cases i.e. AD -- ronnie
   */
  is_ascii=tvb_ascii_isprint(tvb, offset, len);

  /* convert the string into a printable string */
  if(is_ascii){
    ldapvalue_string= tvb_get_string_enc(actx->pinfo->pool, tvb, offset, len, ENC_UTF_8|ENC_NA);
  } else {
    ldapvalue_string= tvb_bytes_to_str_punct(actx->pinfo->pool, tvb, offset, len, ':');
  }

  proto_tree_add_string(tree, hf_index, tvb, offset, len, ldapvalue_string);


finished:
  offset+=len;
  return offset;
}

/* This string contains the last Filter item that was decoded */
static const char *Filter_string;
static const char *and_filter_string;
static const char *or_filter_string;
static const char *substring_value;
static const char *substring_item_init;
static const char *substring_item_any;
static const char *substring_item_final;
static const char *matching_rule_string;
static bool matching_rule_dnattr=false;

#define MAX_FILTER_LEN 4096
static int Filter_length;

#define MAX_FILTER_ELEMENTS 200
static int Filter_elements;

/* Global variables */
static int MessageID =-1;
static int ProtocolOp = -1;
static int result;
static proto_item *ldm_tree; /* item to add text to */

static void ldap_do_protocolop(packet_info *pinfo)
{
  const char* valstr;

  if (do_protocolop) {

    valstr = val_to_str(ProtocolOp, ldap_ProtocolOp_choice_vals, "Unknown (%u)");

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s(%u) ", valstr, MessageID);

    if(ldm_tree)
      proto_item_append_text(ldm_tree, " %s(%d)", valstr, MessageID);

    do_protocolop = false;

  }
}

static ldap_call_response_t *
ldap_match_call_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned messageId, unsigned protocolOpTag, ldap_conv_info_t *ldap_info)
{
  ldap_call_response_t lcr, *lcrp=NULL;

  /* first see if we have already matched this */

      lcr.messageId=messageId;
      switch(protocolOpTag){
        case LDAP_REQ_BIND:
        case LDAP_REQ_SEARCH:
        case LDAP_REQ_MODIFY:
        case LDAP_REQ_ADD:
        case LDAP_REQ_DELETE:
        case LDAP_REQ_MODRDN:
        case LDAP_REQ_COMPARE:
        case LDAP_REQ_EXTENDED:
          lcr.is_request=true;
          lcr.req_frame=pinfo->num;
          lcr.rep_frame=0;
          break;
        case LDAP_RES_BIND:
        case LDAP_RES_SEARCH_ENTRY:
        case LDAP_RES_SEARCH_REF:
        case LDAP_RES_SEARCH_RESULT:
        case LDAP_RES_MODIFY:
        case LDAP_RES_ADD:
        case LDAP_RES_DELETE:
        case LDAP_RES_MODRDN:
        case LDAP_RES_COMPARE:
        case LDAP_RES_EXTENDED:
        case LDAP_RES_INTERMEDIATE:
          lcr.is_request=false;
          lcr.req_frame=0;
          lcr.rep_frame=pinfo->num;
          break;
        default:
          return NULL;
      }
      lcrp=(ldap_call_response_t *)wmem_map_lookup(ldap_info->matched, &lcr);

      if(lcrp){

        lcrp->is_request=lcr.is_request;

      } else {

        /* we haven't found a match - try and match it up */

  switch(protocolOpTag){
      case LDAP_REQ_BIND:
      case LDAP_REQ_SEARCH:
      case LDAP_REQ_MODIFY:
      case LDAP_REQ_ADD:
      case LDAP_REQ_DELETE:
      case LDAP_REQ_MODRDN:
      case LDAP_REQ_COMPARE:
      case LDAP_REQ_EXTENDED:

        /* this is a request - add it to the unmatched list */

        /* check that we don't already have one of those in the
           unmatched list and if so remove it */

        lcr.messageId=messageId;
        lcrp=(ldap_call_response_t *)wmem_map_lookup(ldap_info->unmatched, &lcr);
        if(lcrp){
          wmem_map_remove(ldap_info->unmatched, lcrp);
        }
        /* if we can't reuse the old one, grab a new chunk */
        if(!lcrp){
          lcrp=wmem_new0(wmem_file_scope(), ldap_call_response_t);
        }
        lcrp->messageId=messageId;
        lcrp->req_frame=pinfo->num;
        lcrp->req_time=pinfo->abs_ts;
        lcrp->rep_frame=0;
        lcrp->protocolOpTag=protocolOpTag;
        lcrp->is_request=true;
        wmem_map_insert(ldap_info->unmatched, lcrp, lcrp);
        return NULL;
      case LDAP_RES_BIND:
      case LDAP_RES_SEARCH_ENTRY:
      case LDAP_RES_SEARCH_REF:
      case LDAP_RES_SEARCH_RESULT:
      case LDAP_RES_MODIFY:
      case LDAP_RES_ADD:
      case LDAP_RES_DELETE:
      case LDAP_RES_MODRDN:
      case LDAP_RES_COMPARE:
      case LDAP_RES_EXTENDED:
      case LDAP_RES_INTERMEDIATE:

      /* this is a result - it should be in our unmatched list */

        lcr.messageId=messageId;
        lcrp=(ldap_call_response_t *)wmem_map_lookup(ldap_info->unmatched, &lcr);

        if(lcrp){

          if(!lcrp->rep_frame){
            wmem_map_remove(ldap_info->unmatched, lcrp);
            lcrp->rep_frame=pinfo->num;
            lcrp->is_request=false;
            wmem_map_insert(ldap_info->matched, lcrp, lcrp);
          }
        }

        break;
      }

    }
    /* we have found a match */

    if(lcrp){
      proto_item *it;

      if(lcrp->is_request){
        it=proto_tree_add_uint(tree, hf_ldap_response_in, tvb, 0, 0, lcrp->rep_frame);
        proto_item_set_generated(it);
      } else {
        nstime_t ns;
        it=proto_tree_add_uint(tree, hf_ldap_response_to, tvb, 0, 0, lcrp->req_frame);
        proto_item_set_generated(it);
        nstime_delta(&ns, &pinfo->abs_ts, &lcrp->req_time);
        it=proto_tree_add_time(tree, hf_ldap_time, tvb, 0, 0, &ns);
        proto_item_set_generated(it);
      }
    }

    return lcrp;
}

/*--- Cyclic dependencies ---*/

/* Filter -> Filter/and -> Filter/and/_item -> Filter */
/* Filter -> Filter/or -> Filter/or/_item -> Filter */
/* Filter -> Filter/not -> Filter */
static int dissect_ldap_Filter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);




static int
dissect_ldap_MessageID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &MessageID);


  ldm_tree = tree;


  return offset;
}



static int
dissect_ldap_INTEGER_1_127(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ldap_LDAPString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t  *parameter_tvb = NULL;
  const char *ldapstring = NULL;
  char *sc = NULL; /* semi-colon pointer */

  offset = dissect_ber_octet_string_with_encoding(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb, ENC_UTF_8|ENC_NA);

  if (parameter_tvb || (hf_index == hf_ldap_baseObject)) {

  ldap_do_protocolop(actx->pinfo);

  if(parameter_tvb)
    ldapstring = tvb_get_string_enc(actx->pinfo->pool, parameter_tvb, 0, tvb_reported_length_remaining(parameter_tvb, 0), ENC_UTF_8|ENC_NA);

  if(hf_index == hf_ldap_baseObject) {
    /* this is search - put it on the scanline */
    if(!ldapstring || !*ldapstring)
      ldapstring = "<ROOT>";

    col_append_fstr(actx->pinfo->cinfo, COL_INFO, "\"%s\" ", format_text(actx->pinfo->pool, ldapstring, strlen(ldapstring)));

    if(ldm_tree)
      proto_item_append_text(ldm_tree, " \"%s\"", ldapstring);


    if(!parameter_tvb) {

      proto_item_append_text(actx->created_item, " (%s)", ldapstring);
    }

  } else if ((hf_index == hf_ldap_errorMessage) && ldapstring && *ldapstring) { /* only show message if not success */
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, "(%s) ", format_text(actx->pinfo->pool, ldapstring, strlen(ldapstring)));

    if(ldm_tree)
      proto_item_append_text(ldm_tree, " (%s)", ldapstring);

    } else if ((hf_index == hf_ldap_objectName) ||
               (hf_index == hf_ldap_name) ||
               (hf_index == hf_ldap_entry) ||
               (hf_index == hf_ldap_object) ||
               (hf_index == hf_ldap_delRequest) ) {

      if(!ldapstring || !*ldapstring)
        ldapstring = "<ROOT>";

      col_append_fstr(actx->pinfo->cinfo, COL_INFO, "\"%s\" ", format_text(actx->pinfo->pool, ldapstring, strlen(ldapstring)));

      if(ldm_tree)
        proto_item_append_text(ldm_tree, " \"%s\"", ldapstring);
      } else if (hf_index == hf_ldap_attributeDesc){
        /* remember the attribute description */
        attributedesc_string=ldapstring;
      } else if (hf_index == hf_ldap_initial){
        /* remember the substring item */
        substring_item_init=ldapstring;
      } else if (hf_index == hf_ldap_any){
        /* remember the substring item */
        substring_item_any=ldapstring;
      } else if (hf_index == hf_ldap_final){
        /* remember the substring item */
        substring_item_final=ldapstring;
      } else if (hf_index == hf_ldap_matchingRule){
        /* remember the matching rule */
        matching_rule_string=ldapstring;
      } else if (hf_index == hf_ldap_present){
        /* remember the present name */
        Filter_string=ldapstring;
      } else if (hf_index == hf_ldap_type) {
        /* remember attribute type name */
        attr_type = wmem_strdup(actx->pinfo->pool, ldapstring);

        /* append it to the parent entry */
        proto_item_append_text(tree, " %s", attr_type);

        /* remove the ";binary" component if present */
        if((sc = strchr(attr_type, ';')) != NULL) {
          if(!strcmp(sc, ";binary")) {
            *sc = '\0'; /* terminate the string */
            is_binary_attr_type = true;
          }
        } else {
          is_binary_attr_type = false;
        }
    }

  }


  return offset;
}



static int
dissect_ldap_LDAPDN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_LDAPString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ldap_Simple(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
ldap_conv_info_t *ldap_info;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);


  ldap_info = (ldap_conv_info_t *)actx->private_data;
  ldap_info->auth_type = LDAP_AUTH_SIMPLE;


  return offset;
}



static int
dissect_ldap_Mechanism(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

ldap_conv_info_t *ldap_info;
tvbuff_t  *parameter_tvb;
char *mechanism = NULL;
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

  ldap_info = (ldap_conv_info_t *)actx->private_data;
  ldap_info->auth_type = LDAP_AUTH_SASL;

  if (!parameter_tvb)
    return offset;

  /*
   * We need to remember the authentication type and mechanism for this
   * conversation.
   *
   * XXX - actually, we might need to remember more than one
   * type and mechanism, if you can unbind and rebind with a
   * different type and/or mechanism.
   */
  if(!actx->pinfo->fd->visited) {
    mechanism = tvb_get_string_enc(wmem_file_scope(), parameter_tvb, 0, tvb_reported_length_remaining(parameter_tvb,0), ENC_UTF_8|ENC_NA);
    ldap_info->first_auth_frame = 0; /* not known until we see the bind reply */
    /*
     * If the mechanism in this request is an empty string (which is
     * returned as a null pointer), use the saved mechanism instead.
     * Otherwise, if the saved mechanism is an empty string (null),
     * save this mechanism.
    */
    if (mechanism != NULL) {
      wmem_free(wmem_file_scope(), ldap_info->auth_mech);
      ldap_info->auth_mech = mechanism;
    }
  }

  return offset;
}



static int
dissect_ldap_Credentials(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

tvbuff_t *parameter_tvb;
ldap_conv_info_t *ldap_info;
int8_t ber_class;
bool pc;
int32_t tag;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


  if (!parameter_tvb)
    return offset;

  ldap_info = (ldap_conv_info_t *)actx->private_data;
  get_ber_identifier(parameter_tvb, 0, &ber_class, &pc, &tag);

  /*if ((ldap_info->auth_mech != NULL) && (strcmp(ldap_info->auth_mech, "GSS-SPNEGO") == 0) && (ber_class==BER_CLASS_CON)) {*/
  if ((ldap_info->auth_mech != NULL) && (ber_class==BER_CLASS_CON)) {
    /*
     * This is a GSS-API token ancapsulated within GSS-SPNEGO.
     * We need to check the first byte to check whether the blob
     * contains SPNEGO or GSSAPI.
     * All SPNEGO PDUs are of class CONSTRUCTED while
     * GSS PDUs are class APPLICATION
     */
    if (parameter_tvb && (tvb_reported_length(parameter_tvb) > 0))
      call_dissector(spnego_handle, parameter_tvb, actx->pinfo, tree);
  }
  /*if ((ldap_info->auth_mech != NULL) && ((strcmp(ldap_info->auth_mech, "GSSAPI") == 0) || (ber_class==BER_CLASS_APP))) {*/
  if ((ldap_info->auth_mech != NULL) && (ber_class==BER_CLASS_APP)) {
    /*
     * This is a raw GSS-API token.
     */
    if (parameter_tvb && (tvb_reported_length(parameter_tvb) > 0)) {
      call_dissector(gssapi_handle, parameter_tvb, actx->pinfo, tree);
    }
  }
  /* Restore private data */
  actx->private_data = ldap_info;



  return offset;
}


static const ber_sequence_t SaslCredentials_sequence[] = {
  { &hf_ldap_mechanism      , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_Mechanism },
  { &hf_ldap_credentials    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ldap_Credentials },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_SaslCredentials(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SaslCredentials_sequence, hf_index, ett_ldap_SaslCredentials);

  return offset;
}



static int
dissect_ldap_T_ntlmsspNegotiate(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  /* make sure the protocol op comes first */
  ldap_do_protocolop(actx->pinfo);

  call_dissector(ntlmssp_handle, tvb, actx->pinfo, tree);
  offset+=tvb_reported_length_remaining(tvb, offset);


  return offset;
}



static int
dissect_ldap_T_ntlmsspAuth(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  /* make sure the protocol op comes first */
  ldap_do_protocolop(actx->pinfo);

  call_dissector(ntlmssp_handle, tvb, actx->pinfo, tree);
  offset+=tvb_reported_length_remaining(tvb, offset);


  return offset;
}


static const value_string ldap_AuthenticationChoice_vals[] = {
  {   0, "simple" },
  {   3, "sasl" },
  {  10, "ntlmsspNegotiate" },
  {  11, "ntlmsspAuth" },
  { 0, NULL }
};

static const ber_choice_t AuthenticationChoice_choice[] = {
  {   0, &hf_ldap_simple         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ldap_Simple },
  {   3, &hf_ldap_sasl           , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ldap_SaslCredentials },
  {  10, &hf_ldap_ntlmsspNegotiate, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_ldap_T_ntlmsspNegotiate },
  {  11, &hf_ldap_ntlmsspAuth    , BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_ldap_T_ntlmsspAuth },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_AuthenticationChoice(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int branch = -1;
  int auth = -1;
  const char *valstr;

  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AuthenticationChoice_choice, hf_index, ett_ldap_AuthenticationChoice,
                                 &branch);


  ldap_do_protocolop(actx->pinfo);

  if((branch > -1) && (branch < (int)array_length(AuthenticationChoice_choice)))
    auth = AuthenticationChoice_choice[branch].value;

  valstr = val_to_str(auth, ldap_AuthenticationChoice_vals, "Unknown auth(%u)");

  /* If auth is NTLM (10 or 11) don't add to column as the NTLM dissection will do this */
  if ((auth !=  10) && (auth != 11))
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s ", valstr);

  if(ldm_tree)
    proto_item_append_text(ldm_tree, " %s", valstr);



  return offset;
}


static const ber_sequence_t BindRequest_U_sequence[] = {
  { &hf_ldap_version        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_ldap_INTEGER_1_127 },
  { &hf_ldap_name           , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_LDAPDN },
  { &hf_ldap_authentication , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ldap_AuthenticationChoice },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_BindRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BindRequest_U_sequence, hf_index, ett_ldap_BindRequest_U);

  return offset;
}



static int
dissect_ldap_BindRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 0, true, dissect_ldap_BindRequest_U);

  return offset;
}


static const value_string ldap_BindResponse_resultCode_vals[] = {
  {   0, "success" },
  {   1, "operationsError" },
  {   2, "protocolError" },
  {   3, "timeLimitExceeded" },
  {   4, "sizeLimitExceeded" },
  {   5, "compareFalse" },
  {   6, "compareTrue" },
  {   7, "authMethodNotSupported" },
  {   8, "strongAuthRequired" },
  {  10, "referral" },
  {  11, "adminLimitExceeded" },
  {  12, "unavailableCriticalExtension" },
  {  13, "confidentialityRequired" },
  {  14, "saslBindInProgress" },
  {  16, "noSuchAttribute" },
  {  17, "undefinedAttributeType" },
  {  18, "inappropriateMatching" },
  {  19, "constraintViolation" },
  {  20, "attributeOrValueExists" },
  {  21, "invalidAttributeSyntax" },
  {  32, "noSuchObject" },
  {  33, "aliasProblem" },
  {  34, "invalidDNSyntax" },
  {  36, "aliasDereferencingProblem" },
  {  48, "inappropriateAuthentication" },
  {  49, "invalidCredentials" },
  {  50, "insufficientAccessRights" },
  {  51, "busy" },
  {  52, "unavailable" },
  {  53, "unwillingToPerform" },
  {  54, "loopDetect" },
  {  64, "namingViolation" },
  {  65, "objectClassViolation" },
  {  66, "notAllowedOnNonLeaf" },
  {  67, "notAllowedOnRDN" },
  {  68, "entryAlreadyExists" },
  {  69, "objectClassModsProhibited" },
  {  71, "affectsMultipleDSAs" },
  {  80, "other" },
  { 118, "canceled" },
  { 119, "noSuchOperation" },
  { 120, "tooLate" },
  { 121, "cannotCancel" },
  { 0, NULL }
};


static int
dissect_ldap_BindResponse_resultCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  const char *valstr;

  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  &result);


  ldap_do_protocolop(actx->pinfo);

  valstr = val_to_str(result, ldap_BindResponse_resultCode_vals, "Unknown result(%u)");

  col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s ", valstr);

  if(ldm_tree)
    proto_item_append_text(ldm_tree, " %s", valstr);


  return offset;
}



static int
dissect_ldap_T_bindResponse_matchedDN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *new_tvb=NULL;

  offset = dissect_ber_octet_string(false, actx, tree, tvb, offset, hf_ldap_matchedDN, &new_tvb);

  if(  new_tvb
  &&  (tvb_reported_length(new_tvb)>=7)
  &&  (!tvb_memeql(new_tvb, 0, (const uint8_t*)"NTLMSSP", 7))){

    /* make sure the protocol op comes first */
    ldap_do_protocolop(actx->pinfo);

    call_dissector(ntlmssp_handle, new_tvb, actx->pinfo, tree);
  }


  return offset;
}



static int
dissect_ldap_ErrorMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_LDAPString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ldap_LDAPURL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  proto_item_set_url(actx->created_item);

  return offset;
}


static const ber_sequence_t Referral_sequence_of[1] = {
  { &hf_ldap_Referral_item  , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_LDAPURL },
};

static int
dissect_ldap_Referral(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Referral_sequence_of, hf_index, ett_ldap_Referral);

  return offset;
}



static int
dissect_ldap_ServerSaslCreds(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

tvbuff_t *parameter_tvb = NULL;
ldap_conv_info_t *ldap_info;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

  if (!parameter_tvb)
    return offset;
  ldap_info = (ldap_conv_info_t *)actx->private_data;
  switch (ldap_info->auth_type) {

    /* For Kerberos V4, dissect it as a ticket. */
    /* XXX - what about LDAP_AUTH_SIMPLE? */

  case LDAP_AUTH_SASL:
    /*
     * All frames after this are assumed to use a security layer.
     *
     * XXX - won't work if there's another reply, with the security
     * layer, starting in the same TCP segment that ends this
     * reply, but as LDAP is a request/response protocol, and
     * as the client probably can't start using authentication until
     * it gets the bind reply and the server won't send a reply until
     * it gets a request, that probably won't happen.
     *
     * XXX - that assumption is invalid; it's not clear where the
     * hell you find out whether there's any security layer.  In
     * one capture, we have two GSS-SPNEGO negotiations, both of
     * which select MS KRB5, and the only differences in the tokens
     * is in the RC4-HMAC ciphertext.  The various
     * draft-ietf--cat-sasl-gssapi-NN.txt drafts seem to imply
     * that the RFC 2222 spoo with the bitmask and maximum
     * output message size stuff is done - but where does that
     * stuff show up?  Is it in the ciphertext, which means it's
     * presumably encrypted?
     *
     * Grrr.  We have to do a gross heuristic, checking whether the
     * putative LDAP message begins with 0x00 or not, making the
     * assumption that we won't have more than 2^24 bytes of
     * encapsulated stuff.
     */
    ldap_info->first_auth_frame = actx->pinfo->num + 1;
    if (ldap_info->auth_mech != NULL &&
      strcmp(ldap_info->auth_mech, "GSS-SPNEGO") == 0) {
      /* It could be the second leg of GSS-SPNEGO wrapping NTLMSSP
       * which might not be wrapped in GSS-SPNEGO but be a raw
       * NTLMSSP blob
       */
      if ( (tvb_reported_length(parameter_tvb)>=7)
        &&   (!tvb_memeql(parameter_tvb, 0, (const uint8_t*)"NTLMSSP", 7))){
        call_dissector(ntlmssp_handle, parameter_tvb, actx->pinfo, tree);
        break;
      }
      /*
       * This is a GSS-API token.
       */
      if(parameter_tvb && (tvb_reported_length(parameter_tvb) > 0))
        call_dissector(spnego_handle, parameter_tvb, actx->pinfo, tree);
    } else if (ldap_info->auth_mech != NULL &&
      strcmp(ldap_info->auth_mech, "GSSAPI") == 0) {
      /*
       * This is a GSS-API token.
       */
      if(parameter_tvb && (tvb_reported_length(parameter_tvb) > 0))
          call_dissector(gssapi_handle, parameter_tvb, actx->pinfo, tree);
    }
  break;
  }
  actx->private_data = ldap_info;


  return offset;
}


static const ber_sequence_t BindResponse_U_sequence[] = {
  { &hf_ldap_bindResponse_resultCode, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_ldap_BindResponse_resultCode },
  { &hf_ldap_bindResponse_matchedDN, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_T_bindResponse_matchedDN },
  { &hf_ldap_errorMessage   , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_ErrorMessage },
  { &hf_ldap_referral       , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ldap_Referral },
  { &hf_ldap_serverSaslCreds, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ldap_ServerSaslCreds },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_BindResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BindResponse_U_sequence, hf_index, ett_ldap_BindResponse_U);

  return offset;
}



static int
dissect_ldap_BindResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 1, true, dissect_ldap_BindResponse_U);

  return offset;
}



static int
dissect_ldap_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_ldap_UnbindRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  implicit_tag = true; /* correct problem with asn2wrs */

  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 2, true, dissect_ldap_NULL);


  ldap_do_protocolop(actx->pinfo);






  return offset;
}


static const value_string ldap_T_scope_vals[] = {
  {   0, "baseObject" },
  {   1, "singleLevel" },
  {   2, "wholeSubtree" },
  { 0, NULL }
};


static int
dissect_ldap_T_scope(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  uint32_t scope = 0xffff;
  const char *valstr;

  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  &scope);


  ldap_do_protocolop(actx->pinfo);

  valstr = val_to_str(scope, ldap_T_scope_vals, "Unknown scope(%u)");

  col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s ", valstr);

  if(ldm_tree)
    proto_item_append_text(ldm_tree, " %s", valstr);


  return offset;
}


static const value_string ldap_T_derefAliases_vals[] = {
  {   0, "neverDerefAliases" },
  {   1, "derefInSearching" },
  {   2, "derefFindingBaseObj" },
  {   3, "derefAlways" },
  { 0, NULL }
};


static int
dissect_ldap_T_derefAliases(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ldap_INTEGER_0_maxInt(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ldap_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_ldap_T_and_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_Filter(implicit_tag, tvb, offset, actx, tree, hf_index);

  if(and_filter_string){
    and_filter_string=wmem_strdup_printf(actx->pinfo->pool, "(&%s%s)",and_filter_string,Filter_string);
  } else {
    and_filter_string=Filter_string;
  }

  return offset;
}


static const ber_sequence_t T_and_set_of[1] = {
  { &hf_ldap_and_item       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ldap_T_and_item },
};

static int
dissect_ldap_T_and(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  proto_tree *tr=NULL;
  proto_item *it=NULL;
  const char *old_and_filter_string=and_filter_string;

  and_filter_string=NULL;

  tr=proto_tree_add_subtree(tree, tvb, offset, -1, ett_ldap_T_and, &it, "and: ");
  tree = tr;

  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_and_set_of, hf_index, ett_ldap_T_and);


  if(and_filter_string) {
    proto_item_append_text(it, "%s", and_filter_string);
    Filter_string=wmem_strdup(actx->pinfo->pool, and_filter_string);
  }
  and_filter_string=old_and_filter_string;


  return offset;
}



static int
dissect_ldap_T_or_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_Filter(implicit_tag, tvb, offset, actx, tree, hf_index);

  if(or_filter_string){
    or_filter_string=wmem_strdup_printf(actx->pinfo->pool, "(|%s%s)",or_filter_string,Filter_string);
  } else {
    or_filter_string=Filter_string;
  }


  return offset;
}


static const ber_sequence_t T_or_set_of[1] = {
  { &hf_ldap_or_item        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ldap_T_or_item },
};

static int
dissect_ldap_T_or(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  proto_tree *tr;
  proto_item *it;
  const char *old_or_filter_string=or_filter_string;

  or_filter_string=NULL;
  tr=proto_tree_add_subtree(tree, tvb, offset, -1, ett_ldap_T_or, &it, "or: ");
  tree = tr;

  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_or_set_of, hf_index, ett_ldap_T_or);

  if(or_filter_string) {
    proto_item_append_text(it, "%s", or_filter_string);
    Filter_string=wmem_strdup(actx->pinfo->pool, or_filter_string);
  }
  or_filter_string=old_or_filter_string;


  return offset;
}



static int
dissect_ldap_T_not(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_Filter(implicit_tag, tvb, offset, actx, tree, hf_index);

  Filter_string=wmem_strdup_printf(actx->pinfo->pool, "(!%s)",string_or_null(Filter_string));

  return offset;
}



static int
dissect_ldap_AttributeDescription(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_LDAPString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static const ber_sequence_t AttributeValueAssertion_sequence[] = {
  { &hf_ldap_attributeDesc  , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_AttributeDescription },
  { &hf_ldap_assertionValue , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_AssertionValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_AttributeValueAssertion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeValueAssertion_sequence, hf_index, ett_ldap_AttributeValueAssertion);

  return offset;
}



static int
dissect_ldap_T_equalityMatch(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_AttributeValueAssertion(implicit_tag, tvb, offset, actx, tree, hf_index);

  Filter_string=wmem_strdup_printf(actx->pinfo->pool, "(%s=%s)",
                                   string_or_null(attributedesc_string),
                                   string_or_null(ldapvalue_string));


  return offset;
}


static const value_string ldap_T_substringFilter_substrings_item_vals[] = {
  {   0, "initial" },
  {   1, "any" },
  {   2, "final" },
  { 0, NULL }
};

static const ber_choice_t T_substringFilter_substrings_item_choice[] = {
  {   0, &hf_ldap_initial        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ldap_LDAPString },
  {   1, &hf_ldap_any            , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ldap_LDAPString },
  {   2, &hf_ldap_final          , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ldap_LDAPString },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_T_substringFilter_substrings_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_substringFilter_substrings_item_choice, hf_index, ett_ldap_T_substringFilter_substrings_item,
                                 NULL);

  if (substring_item_final) {
    substring_value=wmem_strdup_printf(actx->pinfo->pool, "%s%s",
                                      (substring_value?substring_value:"*"),
                                       substring_item_final);
  } else if (substring_item_any) {
    substring_value=wmem_strdup_printf(actx->pinfo->pool, "%s%s*",
                                      (substring_value?substring_value:"*"),
                                       substring_item_any);
  } else if (substring_item_init) {
    substring_value=wmem_strdup_printf(actx->pinfo->pool, "%s*",
                                       substring_item_init);
  }

  return offset;
}


static const ber_sequence_t T_substringFilter_substrings_sequence_of[1] = {
  { &hf_ldap_substringFilter_substrings_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ldap_T_substringFilter_substrings_item },
};

static int
dissect_ldap_T_substringFilter_substrings(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_substringFilter_substrings_sequence_of, hf_index, ett_ldap_T_substringFilter_substrings);

  return offset;
}


static const ber_sequence_t SubstringFilter_sequence[] = {
  { &hf_ldap_type           , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_AttributeDescription },
  { &hf_ldap_substringFilter_substrings, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ldap_T_substringFilter_substrings },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_SubstringFilter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  proto_tree *tr;
  proto_item *it;
  const char *old_substring_value=substring_value;

  attr_type=NULL;
  substring_value=NULL;
  substring_item_init=NULL;
  substring_item_any=NULL;
  substring_item_final=NULL;

  tr=proto_tree_add_subtree(tree, tvb, offset, -1, ett_ldap_SubstringFilter, &it, "substring: ");
  tree = tr;

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SubstringFilter_sequence, hf_index, ett_ldap_SubstringFilter);

  Filter_string=wmem_strdup_printf(actx->pinfo->pool, "(%s=%s)",
                                   string_or_null(attr_type),
                                   string_or_null(substring_value));
  proto_item_append_text(it, "%s", Filter_string);
  substring_value=old_substring_value;


  return offset;
}



static int
dissect_ldap_T_greaterOrEqual(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_AttributeValueAssertion(implicit_tag, tvb, offset, actx, tree, hf_index);

  Filter_string=wmem_strdup_printf(actx->pinfo->pool, "(%s>=%s)",
                                   string_or_null(attributedesc_string),
                                   string_or_null(ldapvalue_string));


  return offset;
}



static int
dissect_ldap_T_lessOrEqual(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_AttributeValueAssertion(implicit_tag, tvb, offset, actx, tree, hf_index);

  Filter_string=wmem_strdup_printf(actx->pinfo->pool, "(%s<=%s)",
                                   string_or_null(attributedesc_string),
                                   string_or_null(ldapvalue_string));


  return offset;
}



static int
dissect_ldap_T_present(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_AttributeDescription(implicit_tag, tvb, offset, actx, tree, hf_index);

  Filter_string=wmem_strdup_printf(actx->pinfo->pool, "(%s=*)",string_or_null(Filter_string));

  return offset;
}



static int
dissect_ldap_T_approxMatch(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_AttributeValueAssertion(implicit_tag, tvb, offset, actx, tree, hf_index);

  Filter_string=wmem_strdup_printf(actx->pinfo->pool, "(%s~=%s)",
                                   string_or_null(attributedesc_string),
                                   string_or_null(ldapvalue_string));

  return offset;
}



static int
dissect_ldap_MatchingRuleId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_LDAPString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ldap_T_dnAttributes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  bool val;

  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, &val);


  matching_rule_dnattr = val;



  return offset;
}


static const ber_sequence_t MatchingRuleAssertion_sequence[] = {
  { &hf_ldap_matchingRule   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ldap_MatchingRuleId },
  { &hf_ldap_type           , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ldap_AttributeDescription },
  { &hf_ldap_matchValue     , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ldap_AssertionValue },
  { &hf_ldap_dnAttributes   , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ldap_T_dnAttributes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_MatchingRuleAssertion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MatchingRuleAssertion_sequence, hf_index, ett_ldap_MatchingRuleAssertion);

  return offset;
}



static int
dissect_ldap_T_extensibleMatch(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  attr_type=NULL;
  matching_rule_string=NULL;
  ldapvalue_string=NULL;
  matching_rule_dnattr=false;

  offset = dissect_ldap_MatchingRuleAssertion(implicit_tag, tvb, offset, actx, tree, hf_index);

  Filter_string=wmem_strdup_printf(actx->pinfo->pool, "(%s:%s%s%s=%s)",
                                  (attr_type?attr_type:""),
                                  (matching_rule_dnattr?"dn:":""),
                                  (matching_rule_string?matching_rule_string:""),
                                  (matching_rule_string?":":""),
                                   string_or_null(ldapvalue_string));

  return offset;
}


static const value_string ldap_Filter_vals[] = {
  {   0, "and" },
  {   1, "or" },
  {   2, "not" },
  {   3, "equalityMatch" },
  {   4, "substrings" },
  {   5, "greaterOrEqual" },
  {   6, "lessOrEqual" },
  {   7, "present" },
  {   8, "approxMatch" },
  {   9, "extensibleMatch" },
  { 0, NULL }
};

static const ber_choice_t Filter_choice[] = {
  {   0, &hf_ldap_and            , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ldap_T_and },
  {   1, &hf_ldap_or             , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ldap_T_or },
  {   2, &hf_ldap_not            , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ldap_T_not },
  {   3, &hf_ldap_equalityMatch  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ldap_T_equalityMatch },
  {   4, &hf_ldap_substrings     , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_ldap_SubstringFilter },
  {   5, &hf_ldap_greaterOrEqual , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_ldap_T_greaterOrEqual },
  {   6, &hf_ldap_lessOrEqual    , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_ldap_T_lessOrEqual },
  {   7, &hf_ldap_present        , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_ldap_T_present },
  {   8, &hf_ldap_approxMatch    , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_ldap_T_approxMatch },
  {   9, &hf_ldap_extensibleMatch, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_ldap_T_extensibleMatch },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_Filter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // Filter -> Filter/and -> Filter/and/_item -> Filter
  actx->pinfo->dissection_depth += 3;
  increment_dissection_depth(actx->pinfo);
  proto_tree *tr;
  proto_item *it;
  attributedesc_string=NULL;

  if (Filter_length++ > MAX_FILTER_LEN) {
    expert_add_info_format(actx->pinfo, tree, &ei_ldap_exceeded_filter_length, "Filter length exceeds %u. Giving up.", MAX_FILTER_LEN);
    THROW(ReportedBoundsError);
  }

  if (Filter_elements++ > MAX_FILTER_ELEMENTS) {
    expert_add_info_format(actx->pinfo, tree, &ei_ldap_too_many_filter_elements, "Found more than %u filter elements. Giving up.", MAX_FILTER_ELEMENTS);
    THROW(ReportedBoundsError);
  }

  tr=proto_tree_add_subtree(tree, tvb, offset, -1, ett_ldap_Filter, &it, "Filter: ");
  tree = tr;

  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Filter_choice, hf_index, ett_ldap_Filter,
                                 NULL);

  if(Filter_string)
    proto_item_append_text(it, "%s", string_or_null(Filter_string));


  actx->pinfo->dissection_depth -= 3;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}



static int
dissect_ldap_T_filter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  Filter_string=NULL;
  Filter_elements = 0;
  Filter_length = 0;

  offset = dissect_ldap_Filter(implicit_tag, tvb, offset, actx, tree, hf_index);

  Filter_string=NULL;
  and_filter_string=NULL;
  Filter_elements = 0;
  Filter_length = 0;

  return offset;
}


static const ber_sequence_t AttributeDescriptionList_sequence_of[1] = {
  { &hf_ldap_AttributeDescriptionList_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_AttributeDescription },
};

static int
dissect_ldap_AttributeDescriptionList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      AttributeDescriptionList_sequence_of, hf_index, ett_ldap_AttributeDescriptionList);

  return offset;
}


static const ber_sequence_t SearchRequest_U_sequence[] = {
  { &hf_ldap_baseObject     , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_LDAPDN },
  { &hf_ldap_scope          , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_ldap_T_scope },
  { &hf_ldap_derefAliases   , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_ldap_T_derefAliases },
  { &hf_ldap_sizeLimit      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_ldap_INTEGER_0_maxInt },
  { &hf_ldap_timeLimit      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_ldap_INTEGER_0_maxInt },
  { &hf_ldap_typesOnly      , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_ldap_BOOLEAN },
  { &hf_ldap_filter         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ldap_T_filter },
  { &hf_ldap_searchRequest_attributes, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ldap_AttributeDescriptionList },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_SearchRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SearchRequest_U_sequence, hf_index, ett_ldap_SearchRequest_U);

  return offset;
}



static int
dissect_ldap_SearchRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 3, true, dissect_ldap_SearchRequest_U);

  return offset;
}



static int
dissect_ldap_AttributeValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  tvbuff_t  *next_tvb = NULL;
  char *string;
  int old_offset = offset;
  int *hf_id;

  /* attr_type, should be set before calling this function */

  /* extract the value of the octetstring */
  offset = dissect_ber_octet_string(false, actx, NULL, tvb, offset, hf_index, &next_tvb);

  /* first check if we have a custom attribute type configured */
  if ((hf_id = get_hf_for_header (attr_type)) != NULL)
    proto_tree_add_item (tree, *hf_id, next_tvb, 0, tvb_reported_length_remaining(next_tvb, 0), ENC_UTF_8|ENC_NA);

  /* if we have an attribute type that isn't binary see if there is a better dissector */
  else if(!attr_type || !next_tvb || !dissector_try_string_new(ldap_name_dissector_table, attr_type, next_tvb, actx->pinfo, tree, false, NULL)) {
    offset = old_offset;

    /* do the default thing */
    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);


    if(tvb_ascii_isprint(next_tvb, 0, tvb_reported_length(next_tvb))) {
      string = tvb_get_string_enc(actx->pinfo->pool, next_tvb, 0, tvb_reported_length_remaining(next_tvb, 0), ENC_UTF_8|ENC_NA);
      proto_item_set_text(actx->created_item, "AttributeValue: %s", string);
    }
  }


  return offset;
}


static const ber_sequence_t SET_OF_AttributeValue_set_of[1] = {
  { &hf_ldap_vals_item      , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_AttributeValue },
};

static int
dissect_ldap_SET_OF_AttributeValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_AttributeValue_set_of, hf_index, ett_ldap_SET_OF_AttributeValue);

  return offset;
}


static const ber_sequence_t PartialAttributeList_item_sequence[] = {
  { &hf_ldap_type           , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_AttributeDescription },
  { &hf_ldap_vals           , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_ldap_SET_OF_AttributeValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_PartialAttributeList_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PartialAttributeList_item_sequence, hf_index, ett_ldap_PartialAttributeList_item);

  return offset;
}


static const ber_sequence_t PartialAttributeList_sequence_of[1] = {
  { &hf_ldap_PartialAttributeList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ldap_PartialAttributeList_item },
};

static int
dissect_ldap_PartialAttributeList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      PartialAttributeList_sequence_of, hf_index, ett_ldap_PartialAttributeList);

  return offset;
}


static const ber_sequence_t SearchResultEntry_U_sequence[] = {
  { &hf_ldap_objectName     , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_LDAPDN },
  { &hf_ldap_searchResultEntry_attributes, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ldap_PartialAttributeList },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_SearchResultEntry_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SearchResultEntry_U_sequence, hf_index, ett_ldap_SearchResultEntry_U);

  return offset;
}



static int
dissect_ldap_SearchResultEntry(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 4, true, dissect_ldap_SearchResultEntry_U);

  return offset;
}


static const value_string ldap_T_resultCode_vals[] = {
  {   0, "success" },
  {   1, "operationsError" },
  {   2, "protocolError" },
  {   3, "timeLimitExceeded" },
  {   4, "sizeLimitExceeded" },
  {   5, "compareFalse" },
  {   6, "compareTrue" },
  {   7, "authMethodNotSupported" },
  {   8, "strongAuthRequired" },
  {  10, "referral" },
  {  11, "adminLimitExceeded" },
  {  12, "unavailableCriticalExtension" },
  {  13, "confidentialityRequired" },
  {  14, "saslBindInProgress" },
  {  16, "noSuchAttribute" },
  {  17, "undefinedAttributeType" },
  {  18, "inappropriateMatching" },
  {  19, "constraintViolation" },
  {  20, "attributeOrValueExists" },
  {  21, "invalidAttributeSyntax" },
  {  32, "noSuchObject" },
  {  33, "aliasProblem" },
  {  34, "invalidDNSyntax" },
  {  36, "aliasDereferencingProblem" },
  {  48, "inappropriateAuthentication" },
  {  49, "invalidCredentials" },
  {  50, "insufficientAccessRights" },
  {  51, "busy" },
  {  52, "unavailable" },
  {  53, "unwillingToPerform" },
  {  54, "loopDetect" },
  {  64, "namingViolation" },
  {  65, "objectClassViolation" },
  {  66, "notAllowedOnNonLeaf" },
  {  67, "notAllowedOnRDN" },
  {  68, "entryAlreadyExists" },
  {  69, "objectClassModsProhibited" },
  {  71, "affectsMultipleDSAs" },
  {  80, "other" },
  { 118, "canceled" },
  { 119, "noSuchOperation" },
  { 120, "tooLate" },
  { 121, "cannotCancel" },
  { 0, NULL }
};


static int
dissect_ldap_T_resultCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  const char *valstr;

  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  &result);


  ldap_do_protocolop(actx->pinfo);

  valstr = val_to_str(result, ldap_T_resultCode_vals, "Unknown result(%u)");

  col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s ", valstr);

  if(ldm_tree)
    proto_item_append_text(ldm_tree, " %s", valstr);



  return offset;
}


static const ber_sequence_t LDAPResult_sequence[] = {
  { &hf_ldap_resultCode     , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_ldap_T_resultCode },
  { &hf_ldap_matchedDN      , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_LDAPDN },
  { &hf_ldap_errorMessage   , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_ErrorMessage },
  { &hf_ldap_referral       , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ldap_Referral },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_LDAPResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LDAPResult_sequence, hf_index, ett_ldap_LDAPResult);

  return offset;
}



static int
dissect_ldap_SearchResultDone(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 5, true, dissect_ldap_LDAPResult);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_LDAPURL_sequence_of[1] = {
  { &hf_ldap__untag_item    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_LDAPURL },
};

static int
dissect_ldap_SEQUENCE_OF_LDAPURL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_LDAPURL_sequence_of, hf_index, ett_ldap_SEQUENCE_OF_LDAPURL);

  return offset;
}



static int
dissect_ldap_SearchResultReference(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 19, true, dissect_ldap_SEQUENCE_OF_LDAPURL);


  ldap_do_protocolop(actx->pinfo);



  return offset;
}


static const value_string ldap_T_operation_vals[] = {
  {   0, "add" },
  {   1, "delete" },
  {   2, "replace" },
  {   3, "increment" },
  { 0, NULL }
};


static int
dissect_ldap_T_operation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t AttributeTypeAndValues_sequence[] = {
  { &hf_ldap_type           , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_AttributeDescription },
  { &hf_ldap_vals           , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_ldap_SET_OF_AttributeValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_AttributeTypeAndValues(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeTypeAndValues_sequence, hf_index, ett_ldap_AttributeTypeAndValues);

  return offset;
}


static const ber_sequence_t T_modifyRequest_modification_item_sequence[] = {
  { &hf_ldap_operation      , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_ldap_T_operation },
  { &hf_ldap_modification   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ldap_AttributeTypeAndValues },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_T_modifyRequest_modification_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_modifyRequest_modification_item_sequence, hf_index, ett_ldap_T_modifyRequest_modification_item);

  return offset;
}


static const ber_sequence_t ModifyRequest_modification_sequence_of[1] = {
  { &hf_ldap_modifyRequest_modification_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ldap_T_modifyRequest_modification_item },
};

static int
dissect_ldap_ModifyRequest_modification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      ModifyRequest_modification_sequence_of, hf_index, ett_ldap_ModifyRequest_modification);

  return offset;
}


static const ber_sequence_t ModifyRequest_U_sequence[] = {
  { &hf_ldap_object         , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_LDAPDN },
  { &hf_ldap_modifyRequest_modification, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ldap_ModifyRequest_modification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_ModifyRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ModifyRequest_U_sequence, hf_index, ett_ldap_ModifyRequest_U);

  return offset;
}



static int
dissect_ldap_ModifyRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 6, true, dissect_ldap_ModifyRequest_U);

  return offset;
}



static int
dissect_ldap_ModifyResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 7, true, dissect_ldap_LDAPResult);

  return offset;
}


static const ber_sequence_t AttributeList_item_sequence[] = {
  { &hf_ldap_type           , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_AttributeDescription },
  { &hf_ldap_vals           , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_ldap_SET_OF_AttributeValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_AttributeList_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeList_item_sequence, hf_index, ett_ldap_AttributeList_item);

  return offset;
}


static const ber_sequence_t AttributeList_sequence_of[1] = {
  { &hf_ldap_AttributeList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ldap_AttributeList_item },
};

static int
dissect_ldap_AttributeList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      AttributeList_sequence_of, hf_index, ett_ldap_AttributeList);

  return offset;
}


static const ber_sequence_t AddRequest_U_sequence[] = {
  { &hf_ldap_entry          , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_LDAPDN },
  { &hf_ldap_attributes     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ldap_AttributeList },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_AddRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AddRequest_U_sequence, hf_index, ett_ldap_AddRequest_U);

  return offset;
}



static int
dissect_ldap_AddRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 8, true, dissect_ldap_AddRequest_U);

  return offset;
}



static int
dissect_ldap_AddResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 9, true, dissect_ldap_LDAPResult);

  return offset;
}



static int
dissect_ldap_DelRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 10, true, dissect_ldap_LDAPDN);

  return offset;
}



static int
dissect_ldap_DelResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 11, true, dissect_ldap_LDAPResult);

  return offset;
}



static int
dissect_ldap_RelativeLDAPDN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_LDAPString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t ModifyDNRequest_U_sequence[] = {
  { &hf_ldap_entry          , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_LDAPDN },
  { &hf_ldap_newrdn         , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_RelativeLDAPDN },
  { &hf_ldap_deleteoldrdn   , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_ldap_BOOLEAN },
  { &hf_ldap_newSuperior    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ldap_LDAPDN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_ModifyDNRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ModifyDNRequest_U_sequence, hf_index, ett_ldap_ModifyDNRequest_U);

  return offset;
}



static int
dissect_ldap_ModifyDNRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 12, true, dissect_ldap_ModifyDNRequest_U);

  return offset;
}



static int
dissect_ldap_ModifyDNResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 13, true, dissect_ldap_LDAPResult);

  return offset;
}


static const ber_sequence_t CompareRequest_U_sequence[] = {
  { &hf_ldap_entry          , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_LDAPDN },
  { &hf_ldap_ava            , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ldap_AttributeValueAssertion },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_CompareRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CompareRequest_U_sequence, hf_index, ett_ldap_CompareRequest_U);

  return offset;
}



static int
dissect_ldap_CompareRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 14, true, dissect_ldap_CompareRequest_U);

  return offset;
}



static int
dissect_ldap_CompareResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 15, true, dissect_ldap_LDAPResult);

  return offset;
}



static int
dissect_ldap_AbandonRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 16, true, dissect_ldap_MessageID);


  ldap_do_protocolop(actx->pinfo);


  return offset;
}



static int
dissect_ldap_LDAPOID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  tvbuff_t  *parameter_tvb;
  const char *name;
  ldap_conv_info_t *ldap_info = (ldap_conv_info_t *)actx->private_data;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


  object_identifier_id = NULL;

  if (!parameter_tvb)
    return offset;

  object_identifier_id = tvb_get_string_enc(actx->pinfo->pool, parameter_tvb, 0, tvb_reported_length_remaining(parameter_tvb,0), ENC_UTF_8|ENC_NA);
  name = oid_resolved_from_string(actx->pinfo->pool, object_identifier_id);

  if(name){
    proto_item_append_text(actx->created_item, " (%s)", name);

    if((hf_index == hf_ldap_requestName) || (hf_index == hf_ldap_responseName)) {
      ldap_do_protocolop(actx->pinfo);
      col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s ", name);
    }
  }

  /* Has the client requested the Start TLS operation? */
  if (ldap_info && hf_index == hf_ldap_requestName &&
    !strcmp(object_identifier_id, "1.3.6.1.4.1.1466.20037")) {
    /* remember we have asked to start_tls */
    ldap_info->start_tls_pending = true;
  }

  return offset;
}



static int
dissect_ldap_T_requestValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  if((object_identifier_id != NULL) && oid_has_dissector(object_identifier_id)) {
    offset = call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree, NULL);
  } else {
      offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  }


  return offset;
}


static const ber_sequence_t ExtendedRequest_U_sequence[] = {
  { &hf_ldap_requestName    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ldap_LDAPOID },
  { &hf_ldap_requestValue   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ldap_T_requestValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_ExtendedRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExtendedRequest_U_sequence, hf_index, ett_ldap_ExtendedRequest_U);

  return offset;
}



static int
dissect_ldap_ExtendedRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 23, true, dissect_ldap_ExtendedRequest_U);

  return offset;
}


static const value_string ldap_ExtendedResponse_resultCode_vals[] = {
  {   0, "success" },
  {   1, "operationsError" },
  {   2, "protocolError" },
  {   3, "timeLimitExceeded" },
  {   4, "sizeLimitExceeded" },
  {   5, "compareFalse" },
  {   6, "compareTrue" },
  {   7, "authMethodNotSupported" },
  {   8, "strongAuthRequired" },
  {  10, "referral" },
  {  11, "adminLimitExceeded" },
  {  12, "unavailableCriticalExtension" },
  {  13, "confidentialityRequired" },
  {  14, "saslBindInProgress" },
  {  16, "noSuchAttribute" },
  {  17, "undefinedAttributeType" },
  {  18, "inappropriateMatching" },
  {  19, "constraintViolation" },
  {  20, "attributeOrValueExists" },
  {  21, "invalidAttributeSyntax" },
  {  32, "noSuchObject" },
  {  33, "aliasProblem" },
  {  34, "invalidDNSyntax" },
  {  36, "aliasDereferencingProblem" },
  {  48, "inappropriateAuthentication" },
  {  49, "invalidCredentials" },
  {  50, "insufficientAccessRights" },
  {  51, "busy" },
  {  52, "unavailable" },
  {  53, "unwillingToPerform" },
  {  54, "loopDetect" },
  {  64, "namingViolation" },
  {  65, "objectClassViolation" },
  {  66, "notAllowedOnNonLeaf" },
  {  67, "notAllowedOnRDN" },
  {  68, "entryAlreadyExists" },
  {  69, "objectClassModsProhibited" },
  {  71, "affectsMultipleDSAs" },
  {  80, "other" },
  { 118, "canceled" },
  { 119, "noSuchOperation" },
  { 120, "tooLate" },
  { 121, "cannotCancel" },
  { 0, NULL }
};


static int
dissect_ldap_ExtendedResponse_resultCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t resultCode;
  ldap_conv_info_t *ldap_info = (ldap_conv_info_t *)actx->private_data;

  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                               &resultCode);
  /* If Start TLS request was sent and resultCode is success... */
  if (ldap_info && ldap_info->start_tls_pending &&
      hf_index == hf_ldap_extendedResponse_resultCode && resultCode == 0) {
    /* The conversation will continue using SSL */
    ssl_starttls_ack(find_dissector("tls"), actx->pinfo, ldap_handle);
    ldap_info->start_tls_pending = false;
  }



  return offset;
}



static int
dissect_ldap_ResponseName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_LDAPOID(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ldap_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t ExtendedResponse_U_sequence[] = {
  { &hf_ldap_extendedResponse_resultCode, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_ldap_ExtendedResponse_resultCode },
  { &hf_ldap_matchedDN      , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_LDAPDN },
  { &hf_ldap_errorMessage   , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_ErrorMessage },
  { &hf_ldap_referral       , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ldap_Referral },
  { &hf_ldap_responseName   , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ldap_ResponseName },
  { &hf_ldap_response       , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ldap_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_ExtendedResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExtendedResponse_U_sequence, hf_index, ett_ldap_ExtendedResponse_U);

  return offset;
}



static int
dissect_ldap_ExtendedResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 24, true, dissect_ldap_ExtendedResponse_U);

  return offset;
}



static int
dissect_ldap_T_intermediateResponse_responseValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  const char *name;

  if(ldm_tree && object_identifier_id) {
    proto_item_set_text(ldm_tree, "%s %s", "IntermediateResponse", object_identifier_id);
    name = oid_resolved_from_string(actx->pinfo->pool, object_identifier_id);
    if(name)
      proto_item_append_text(ldm_tree, " (%s)", name);
  }
  if((object_identifier_id != NULL) && oid_has_dissector(object_identifier_id)) {
    offset = call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree, NULL);
  } else {
      offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  }


  return offset;
}


static const ber_sequence_t IntermediateResponse_U_sequence[] = {
  { &hf_ldap_responseName   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ldap_ResponseName },
  { &hf_ldap_intermediateResponse_responseValue, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ldap_T_intermediateResponse_responseValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_IntermediateResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IntermediateResponse_U_sequence, hf_index, ett_ldap_IntermediateResponse_U);

  return offset;
}



static int
dissect_ldap_IntermediateResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 25, true, dissect_ldap_IntermediateResponse_U);

  return offset;
}


static const value_string ldap_ProtocolOp_vals[] = {
  {   0, "bindRequest" },
  {   1, "bindResponse" },
  {   2, "unbindRequest" },
  {   3, "searchRequest" },
  {   4, "searchResEntry" },
  {   5, "searchResDone" },
  {  19, "searchResRef" },
  {   6, "modifyRequest" },
  {   7, "modifyResponse" },
  {   8, "addRequest" },
  {   9, "addResponse" },
  {  10, "delRequest" },
  {  11, "delResponse" },
  {  12, "modDNRequest" },
  {  13, "modDNResponse" },
  {  14, "compareRequest" },
  {  15, "compareResponse" },
  {  16, "abandonRequest" },
  {  23, "extendedReq" },
  {  24, "extendedResp" },
  {  25, "intermediateResponse" },
  { 0, NULL }
};

static const ber_choice_t ProtocolOp_choice[] = {
  {   0, &hf_ldap_bindRequest    , BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_ldap_BindRequest },
  {   1, &hf_ldap_bindResponse   , BER_CLASS_APP, 1, BER_FLAGS_NOOWNTAG, dissect_ldap_BindResponse },
  {   2, &hf_ldap_unbindRequest  , BER_CLASS_APP, 2, BER_FLAGS_NOOWNTAG, dissect_ldap_UnbindRequest },
  {   3, &hf_ldap_searchRequest  , BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_ldap_SearchRequest },
  {   4, &hf_ldap_searchResEntry , BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_ldap_SearchResultEntry },
  {   5, &hf_ldap_searchResDone  , BER_CLASS_APP, 5, BER_FLAGS_NOOWNTAG, dissect_ldap_SearchResultDone },
  {  19, &hf_ldap_searchResRef   , BER_CLASS_APP, 19, BER_FLAGS_NOOWNTAG, dissect_ldap_SearchResultReference },
  {   6, &hf_ldap_modifyRequest  , BER_CLASS_APP, 6, BER_FLAGS_NOOWNTAG, dissect_ldap_ModifyRequest },
  {   7, &hf_ldap_modifyResponse , BER_CLASS_APP, 7, BER_FLAGS_NOOWNTAG, dissect_ldap_ModifyResponse },
  {   8, &hf_ldap_addRequest     , BER_CLASS_APP, 8, BER_FLAGS_NOOWNTAG, dissect_ldap_AddRequest },
  {   9, &hf_ldap_addResponse    , BER_CLASS_APP, 9, BER_FLAGS_NOOWNTAG, dissect_ldap_AddResponse },
  {  10, &hf_ldap_delRequest     , BER_CLASS_APP, 10, BER_FLAGS_NOOWNTAG, dissect_ldap_DelRequest },
  {  11, &hf_ldap_delResponse    , BER_CLASS_APP, 11, BER_FLAGS_NOOWNTAG, dissect_ldap_DelResponse },
  {  12, &hf_ldap_modDNRequest   , BER_CLASS_APP, 12, BER_FLAGS_NOOWNTAG, dissect_ldap_ModifyDNRequest },
  {  13, &hf_ldap_modDNResponse  , BER_CLASS_APP, 13, BER_FLAGS_NOOWNTAG, dissect_ldap_ModifyDNResponse },
  {  14, &hf_ldap_compareRequest , BER_CLASS_APP, 14, BER_FLAGS_NOOWNTAG, dissect_ldap_CompareRequest },
  {  15, &hf_ldap_compareResponse, BER_CLASS_APP, 15, BER_FLAGS_NOOWNTAG, dissect_ldap_CompareResponse },
  {  16, &hf_ldap_abandonRequest , BER_CLASS_APP, 16, BER_FLAGS_NOOWNTAG, dissect_ldap_AbandonRequest },
  {  23, &hf_ldap_extendedReq    , BER_CLASS_APP, 23, BER_FLAGS_NOOWNTAG, dissect_ldap_ExtendedRequest },
  {  24, &hf_ldap_extendedResp   , BER_CLASS_APP, 24, BER_FLAGS_NOOWNTAG, dissect_ldap_ExtendedResponse },
  {  25, &hf_ldap_intermediateResponse, BER_CLASS_APP, 25, BER_FLAGS_NOOWNTAG, dissect_ldap_IntermediateResponse },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_ProtocolOp(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  ldap_call_response_t *lcrp;
  ldap_conv_info_t *ldap_info = (ldap_conv_info_t *)actx->private_data;
  do_protocolop = true;

  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ProtocolOp_choice, hf_index, ett_ldap_ProtocolOp,
                                 &ProtocolOp);


  if (ProtocolOp == -1) {
    return offset;
  }

  /* ProtocolOp is the index, not the tag so convert it to the tag value */
  ProtocolOp = ldap_ProtocolOp_vals[ProtocolOp].value;

  lcrp=ldap_match_call_response(tvb, actx->pinfo, tree, MessageID, ProtocolOp, ldap_info);
  if(lcrp){
    tap_queue_packet(ldap_tap, actx->pinfo, lcrp);
  }

  /* XXX: the count will not work if the results span multiple TCP packets */

  if(ldap_info) { /* only count once */
    switch(ProtocolOp) {

    case LDAP_RES_SEARCH_ENTRY:
      if (!actx->pinfo->fd->visited)
        ldap_info->num_results++;

      proto_item_append_text(tree, " [%d result%s]",
                             ldap_info->num_results, ldap_info->num_results == 1 ? "" : "s");

    break;

    case LDAP_RES_SEARCH_RESULT:

      col_append_fstr(actx->pinfo->cinfo, COL_INFO, " [%d result%s]",
                      ldap_info->num_results, ldap_info->num_results == 1 ? "" : "s");

      proto_item_append_text(tree, " [%d result%s]",
                             ldap_info->num_results, ldap_info->num_results == 1 ? "" : "s");

    break;
    default:
    break;
    }
  }


  return offset;
}



static int
dissect_ldap_ControlType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_LDAPOID(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ldap_T_controlValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int8_t ber_class;
  bool pc, ind;
  int32_t tag;
  uint32_t len;

  if((object_identifier_id != NULL) && oid_has_dissector(object_identifier_id)) {
    /* remove the OCTET STRING encoding */
    offset=dissect_ber_identifier(actx->pinfo, NULL, tvb, offset, &ber_class, &pc, &tag);
    offset=dissect_ber_length(actx->pinfo, NULL, tvb, offset, &len, &ind);

    call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree, NULL);

    offset += len;
  } else {
      offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  }



  return offset;
}


static const ber_sequence_t Control_sequence[] = {
  { &hf_ldap_controlType    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_ControlType },
  { &hf_ldap_criticality    , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ldap_BOOLEAN },
  { &hf_ldap_controlValue   , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ldap_T_controlValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_Control(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Control_sequence, hf_index, ett_ldap_Control);

  return offset;
}


static const ber_sequence_t Controls_sequence_of[1] = {
  { &hf_ldap_Controls_item  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ldap_Control },
};

static int
dissect_ldap_Controls(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Controls_sequence_of, hf_index, ett_ldap_Controls);

  return offset;
}


static const ber_sequence_t LDAPMessage_sequence[] = {
  { &hf_ldap_messageID      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_ldap_MessageID },
  { &hf_ldap_protocolOp     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ldap_ProtocolOp },
  { &hf_ldap_controls       , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ldap_Controls },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_LDAPMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LDAPMessage_sequence, hf_index, ett_ldap_LDAPMessage);

  return offset;
}





static int
dissect_ldap_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SearchControlValue_sequence[] = {
  { &hf_ldap_size           , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_ldap_INTEGER },
  { &hf_ldap_cookie         , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_SearchControlValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SearchControlValue_sequence, hf_index, ett_ldap_SearchControlValue);

  return offset;
}


static const ber_sequence_t SortKeyList_item_sequence[] = {
  { &hf_ldap_attributeType  , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_AttributeDescription },
  { &hf_ldap_orderingRule   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ldap_MatchingRuleId },
  { &hf_ldap_reverseOrder   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ldap_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_SortKeyList_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SortKeyList_item_sequence, hf_index, ett_ldap_SortKeyList_item);

  return offset;
}


static const ber_sequence_t SortKeyList_sequence_of[1] = {
  { &hf_ldap_SortKeyList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ldap_SortKeyList_item },
};

static int
dissect_ldap_SortKeyList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SortKeyList_sequence_of, hf_index, ett_ldap_SortKeyList);

  return offset;
}


static const value_string ldap_T_sortResult_vals[] = {
  {   0, "success" },
  {   1, "operationsError" },
  {   3, "timeLimitExceeded" },
  {   8, "strongAuthRequired" },
  {  11, "adminLimitExceeded" },
  {  16, "noSuchAttribute" },
  {  18, "inappropriateMatching" },
  {  50, "insufficientAccessRights" },
  {  51, "busy" },
  {  53, "unwillingToPerform" },
  {  80, "other" },
  { 0, NULL }
};


static int
dissect_ldap_T_sortResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SortResult_sequence[] = {
  { &hf_ldap_sortResult     , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_ldap_T_sortResult },
  { &hf_ldap_attributeType  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ldap_AttributeDescription },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_SortResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SortResult_sequence, hf_index, ett_ldap_SortResult);

  return offset;
}



static int
dissect_ldap_DirSyncFlags(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int8_t ber_class;
  bool pc;
  int32_t tag;
  uint32_t len;
  int32_t val;

  int otheroffset = offset;
  if(!implicit_tag){
    dissect_ber_identifier(actx->pinfo, tree, tvb, otheroffset, &ber_class, &pc, &tag);
    otheroffset=dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, NULL);
  } else {
    int32_t remaining=tvb_reported_length_remaining(tvb, offset);
    len=remaining>0 ? remaining : 0;
  }

  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, -1, &val);

  if (val >0) {
    static int * const flags[] = {
      &hf_ldap_object_security_flag,
      &hf_ldap_ancestor_first_flag,
      &hf_ldap_public_data_only_flag,
      &hf_ldap_incremental_value_flag,
      NULL
    };

    proto_tree_add_bitmask_value_with_flags(tree, tvb, otheroffset+1, hf_index,
                                            ett_ldap_DirSyncFlagsSubEntry, flags, val, BMT_NO_APPEND);
  } else {
    proto_tree_add_uint(tree, hf_index, tvb, otheroffset+len, len, 0);
  }


  return offset;
}


static const ber_sequence_t DirSyncControlValue_sequence[] = {
  { &hf_ldap_flags          , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_ldap_DirSyncFlags },
  { &hf_ldap_maxBytes       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_ldap_INTEGER },
  { &hf_ldap_cookie         , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_DirSyncControlValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DirSyncControlValue_sequence, hf_index, ett_ldap_DirSyncControlValue);

  return offset;
}


static const ber_sequence_t PasswdModifyRequestValue_sequence[] = {
  { &hf_ldap_userIdentity   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ldap_OCTET_STRING },
  { &hf_ldap_oldPasswd      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ldap_OCTET_STRING },
  { &hf_ldap_newPasswd      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ldap_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_PasswdModifyRequestValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PasswdModifyRequestValue_sequence, hf_index, ett_ldap_PasswdModifyRequestValue);

  return offset;
}


static const ber_sequence_t CancelRequestValue_sequence[] = {
  { &hf_ldap_cancelID       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_ldap_MessageID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_CancelRequestValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CancelRequestValue_sequence, hf_index, ett_ldap_CancelRequestValue);

  return offset;
}


static const value_string ldap_T_mode_vals[] = {
  {   1, "refreshOnly" },
  {   3, "refreshAndPersist" },
  { 0, NULL }
};


static int
dissect_ldap_T_mode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SyncRequestValue_sequence[] = {
  { &hf_ldap_mode           , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_ldap_T_mode },
  { &hf_ldap_cookie         , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ldap_OCTET_STRING },
  { &hf_ldap_reloadHint     , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ldap_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_SyncRequestValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SyncRequestValue_sequence, hf_index, ett_ldap_SyncRequestValue);

  return offset;
}


static const value_string ldap_T_state_vals[] = {
  {   0, "present" },
  {   1, "add" },
  {   2, "modify" },
  {   3, "delete" },
  { 0, NULL }
};


static int
dissect_ldap_T_state(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ldap_SyncUUID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t SyncStateValue_sequence[] = {
  { &hf_ldap_state          , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_ldap_T_state },
  { &hf_ldap_entryUUID      , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_SyncUUID },
  { &hf_ldap_cookie         , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ldap_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_SyncStateValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SyncStateValue_sequence, hf_index, ett_ldap_SyncStateValue);

  return offset;
}


static const ber_sequence_t SyncDoneValue_sequence[] = {
  { &hf_ldap_cookie         , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ldap_OCTET_STRING },
  { &hf_ldap_refreshDeletes , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ldap_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_SyncDoneValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SyncDoneValue_sequence, hf_index, ett_ldap_SyncDoneValue);

  return offset;
}


static const ber_sequence_t T_refreshDelete_sequence[] = {
  { &hf_ldap_cookie         , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ldap_OCTET_STRING },
  { &hf_ldap_refreshDone    , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ldap_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_T_refreshDelete(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_refreshDelete_sequence, hf_index, ett_ldap_T_refreshDelete);

  return offset;
}


static const ber_sequence_t T_refreshPresent_sequence[] = {
  { &hf_ldap_cookie         , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ldap_OCTET_STRING },
  { &hf_ldap_refreshDone    , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ldap_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_T_refreshPresent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_refreshPresent_sequence, hf_index, ett_ldap_T_refreshPresent);

  return offset;
}


static const ber_sequence_t SET_OF_SyncUUID_set_of[1] = {
  { &hf_ldap_syncUUIDs_item , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_SyncUUID },
};

static int
dissect_ldap_SET_OF_SyncUUID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_SyncUUID_set_of, hf_index, ett_ldap_SET_OF_SyncUUID);

  return offset;
}


static const ber_sequence_t T_syncIdSet_sequence[] = {
  { &hf_ldap_cookie         , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ldap_OCTET_STRING },
  { &hf_ldap_refreshDeletes , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ldap_BOOLEAN },
  { &hf_ldap_syncUUIDs      , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_ldap_SET_OF_SyncUUID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_T_syncIdSet(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_syncIdSet_sequence, hf_index, ett_ldap_T_syncIdSet);

  return offset;
}


static const value_string ldap_SyncInfoValue_vals[] = {
  {   0, "newcookie" },
  {   1, "refreshDelete" },
  {   2, "refreshPresent" },
  {   3, "syncIdSet" },
  { 0, NULL }
};

static const ber_choice_t SyncInfoValue_choice[] = {
  {   0, &hf_ldap_newcookie      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ldap_OCTET_STRING },
  {   1, &hf_ldap_refreshDelete  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ldap_T_refreshDelete },
  {   2, &hf_ldap_refreshPresent , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ldap_T_refreshPresent },
  {   3, &hf_ldap_syncIdSet      , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ldap_T_syncIdSet },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_SyncInfoValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SyncInfoValue_choice, hf_index, ett_ldap_SyncInfoValue,
                                 NULL);

  return offset;
}


static const value_string ldap_T_warning_vals[] = {
  {   0, "timeBeforeExpiration" },
  {   1, "graceAuthNsRemaining" },
  { 0, NULL }
};

static const ber_choice_t T_warning_choice[] = {
  {   0, &hf_ldap_timeBeforeExpiration, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ldap_INTEGER_0_maxInt },
  {   1, &hf_ldap_graceAuthNsRemaining, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ldap_INTEGER_0_maxInt },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_T_warning(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_warning_choice, hf_index, ett_ldap_T_warning,
                                 NULL);

  return offset;
}


static const value_string ldap_T_error_vals[] = {
  {   0, "passwordExpired" },
  {   1, "accountLocked" },
  {   2, "changeAfterReset" },
  {   3, "passwordModNotAllowed" },
  {   4, "mustSupplyOldPassword" },
  {   5, "insufficientPasswordQuality" },
  {   6, "passwordTooShort" },
  {   7, "passwordTooYoung" },
  {   8, "passwordInHistory" },
  { 0, NULL }
};


static int
dissect_ldap_T_error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t PasswordPolicyResponseValue_sequence[] = {
  { &hf_ldap_warning        , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ldap_T_warning },
  { &hf_ldap_error          , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ldap_T_error },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_PasswordPolicyResponseValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PasswordPolicyResponseValue_sequence, hf_index, ett_ldap_PasswordPolicyResponseValue);

  return offset;
}

/*--- PDUs ---*/

static int dissect_SearchControlValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ldap_SearchControlValue(false, tvb, offset, &asn1_ctx, tree, hf_ldap_SearchControlValue_PDU);
  return offset;
}
static int dissect_SortKeyList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ldap_SortKeyList(false, tvb, offset, &asn1_ctx, tree, hf_ldap_SortKeyList_PDU);
  return offset;
}
static int dissect_SortResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ldap_SortResult(false, tvb, offset, &asn1_ctx, tree, hf_ldap_SortResult_PDU);
  return offset;
}
static int dissect_DirSyncControlValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ldap_DirSyncControlValue(false, tvb, offset, &asn1_ctx, tree, hf_ldap_DirSyncControlValue_PDU);
  return offset;
}
static int dissect_PasswdModifyRequestValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ldap_PasswdModifyRequestValue(false, tvb, offset, &asn1_ctx, tree, hf_ldap_PasswdModifyRequestValue_PDU);
  return offset;
}
static int dissect_CancelRequestValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ldap_CancelRequestValue(false, tvb, offset, &asn1_ctx, tree, hf_ldap_CancelRequestValue_PDU);
  return offset;
}
static int dissect_SyncRequestValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ldap_SyncRequestValue(false, tvb, offset, &asn1_ctx, tree, hf_ldap_SyncRequestValue_PDU);
  return offset;
}
static int dissect_SyncStateValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ldap_SyncStateValue(false, tvb, offset, &asn1_ctx, tree, hf_ldap_SyncStateValue_PDU);
  return offset;
}
static int dissect_SyncDoneValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ldap_SyncDoneValue(false, tvb, offset, &asn1_ctx, tree, hf_ldap_SyncDoneValue_PDU);
  return offset;
}
static int dissect_SyncInfoValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ldap_SyncInfoValue(false, tvb, offset, &asn1_ctx, tree, hf_ldap_SyncInfoValue_PDU);
  return offset;
}
static int dissect_PasswordPolicyResponseValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ldap_PasswordPolicyResponseValue(false, tvb, offset, &asn1_ctx, tree, hf_ldap_PasswordPolicyResponseValue_PDU);
  return offset;
}

static int dissect_LDAPMessage_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, ldap_conv_info_t *ldap_info) {

  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

  asn1_ctx.private_data = ldap_info;
  offset = dissect_ldap_LDAPMessage(false, tvb, offset, &asn1_ctx, tree, hf_ldap_LDAPMessage_PDU);
  return offset;
}

static void
dissect_ldap_payload(tvbuff_t *tvb, packet_info *pinfo,
                     proto_tree *tree, ldap_conv_info_t *ldap_info,
                     bool is_mscldap)
{
  int offset = 0;
  unsigned length_remaining;
  unsigned msg_len = 0;
  int messageOffset = 0;
  unsigned headerLength = 0;
  unsigned length = 0;
  tvbuff_t *msg_tvb = NULL;
  int8_t ber_class;
  bool pc, ind = 0;
  int32_t ber_tag;

  attributedesc_string=NULL;


one_more_pdu:

    length_remaining = tvb_ensure_captured_length_remaining(tvb, offset);

    if (length_remaining < 6) return;

    /*
     * OK, try to read the "Sequence Of" header; this gets the total
     * length of the LDAP message.
     */
        messageOffset = get_ber_identifier(tvb, offset, &ber_class, &pc, &ber_tag);
        messageOffset = get_ber_length(tvb, messageOffset, &msg_len, &ind);

    /* sanity check */
    if((msg_len<4) || (msg_len>10000000)) return;

    if ( (ber_class==BER_CLASS_UNI) && (ber_tag==BER_UNI_TAG_SEQUENCE) ) {
        /*
         * Add the length of the "Sequence Of" header to the message
         * length.
         */
        headerLength = messageOffset - offset;
        msg_len += headerLength;
        if (msg_len < headerLength) {
            /*
             * The message length was probably so large that the total length
             * overflowed.
             *
             * Report this as an error.
             */
            show_reported_bounds_error(tvb, pinfo, tree);
            return;
        }
    } else {
        /*
         * We couldn't parse the header; just make it the amount of data
         * remaining in the tvbuff, so we'll give up on this segment
         * after attempting to parse the message - there's nothing more
         * we can do.  "dissect_ldap_message()" will display the error.
         */
        msg_len = length_remaining;
    }

    /*
     * Construct a tvbuff containing the amount of the payload we have
     * available.  Make its reported length the amount of data in the
     * LDAP message.
     *
     * XXX - if reassembly isn't enabled. the subdissector will throw a
     * BoundsError exception, rather than a ReportedBoundsError exception.
     * We really want a tvbuff where the length is "length", the reported
     * length is "plen", and the "if the snapshot length were infinite"
     * length is the minimum of the reported length of the tvbuff handed
     * to us and "plen", with a new type of exception thrown if the offset
     * is within the reported length but beyond that third length, with
     * that exception getting the "Unreassembled Packet" error.
     */
    length = length_remaining;
    if (length > msg_len) length = msg_len;
    msg_tvb = tvb_new_subset_length_caplen(tvb, offset, length, msg_len);

    /*
     * Now dissect the LDAP message.
     */
    ldap_info->is_mscldap = is_mscldap;
    dissect_LDAPMessage_PDU(msg_tvb, pinfo, tree, ldap_info);

    offset += msg_len;

    /* If this was a sasl blob there might be another PDU following in the
     * same blob
     */
    if(tvb_reported_length_remaining(tvb, offset)>=6){
        tvb = tvb_new_subset_remaining(tvb, offset);
        offset = 0;

        goto one_more_pdu;
    }

}

static void
ldap_frame_end(void)
{
  ldap_found_in_frame = false;
  attr_type = NULL;
  ldapvalue_string = NULL;
/* ? */
  attributedesc_string = NULL;
  Filter_string = NULL;
  and_filter_string = NULL;
  object_identifier_id = NULL;
  or_filter_string = NULL;

  substring_item_any = NULL;
  substring_item_final = NULL;
  substring_item_init = NULL;
  substring_value = NULL;

  ldm_tree = NULL;

  Filter_elements = 0;
  Filter_length = 0;
  do_protocolop = false;
  result = 0;

/* seems to be ok, but reset just in case */
  matching_rule_string = NULL;
}

static void
  dissect_ldap_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, bool is_mscldap)
{
  int offset = 0;
  conversation_t *conversation;
  bool doing_sasl_security = false;
  unsigned length_remaining;
  ldap_conv_info_t *ldap_info = NULL;
  proto_item *ldap_item = NULL;
  proto_tree *ldap_tree = NULL;
  uint32_t sasl_length = 0;
  uint32_t remaining_length = 0;
  uint8_t sasl_start[2] = { 0, };
  bool detected_sasl_security = false;

  ldm_tree = NULL;

  conversation = find_or_create_conversation(pinfo);

  /*
  * Do we already have a type and mechanism?
  */
  ldap_info = (ldap_conv_info_t *)conversation_get_proto_data(conversation, proto_ldap);
  if (ldap_info == NULL) {
    /* No.  Attach that information to the conversation, and add
    * it to the list of information structures.
    */
    ldap_info = wmem_new0(wmem_file_scope(), ldap_conv_info_t);
    ldap_info->matched=wmem_map_new(wmem_file_scope(), ldap_info_hash_matched, ldap_info_equal_matched);
    ldap_info->unmatched=wmem_map_new(wmem_file_scope(), ldap_info_hash_unmatched, ldap_info_equal_unmatched);

    conversation_add_proto_data(conversation, proto_ldap, ldap_info);
  }

  switch (ldap_info->auth_type) {
  case LDAP_AUTH_SASL:
    /*
    * It's SASL; are we using a security layer?
    */
    if (ldap_info->first_auth_frame != 0 &&
      pinfo->num >= ldap_info->first_auth_frame) {
        doing_sasl_security = true; /* yes */
    }
  }

  length_remaining = tvb_ensure_captured_length_remaining(tvb, offset);

  /* It might still be a packet containing a SASL security layer
  * but it's just that we never saw the BIND packet.
  * check if it looks like it could be a SASL blob here
  * and in that case just assume it is GSS-SPNEGO
  */
  if(!doing_sasl_security && tvb_bytes_exist(tvb, offset, 6)) {
      sasl_length = tvb_get_ntohl(tvb, offset);
      remaining_length = tvb_reported_length_remaining(tvb, offset);
      sasl_start[0] = tvb_get_uint8(tvb, offset+4);
      sasl_start[1] = tvb_get_uint8(tvb, offset+5);
  }
  if ((sasl_length + 4) <= remaining_length) {
      if (sasl_start[0] == 0x05 && sasl_start[1] == 0x04) {
        /*
         * Likely modern kerberos signing
         */
        detected_sasl_security = true;
      } else if (sasl_start[0] == 0x60) {
        /*
         * Likely ASN.1 based kerberos
         */
        detected_sasl_security = true;
      }
  }
  if (detected_sasl_security) {
      ldap_info->auth_type=LDAP_AUTH_SASL;
      ldap_info->first_auth_frame=pinfo->num;
      ldap_info->auth_mech=wmem_strdup(wmem_file_scope(), "GSS-SPNEGO");
      doing_sasl_security=true;
  }

  /*
  * This is the first PDU, set the Protocol column and clear the
  * Info column.
  */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, pinfo->current_proto);

  if(ldap_found_in_frame) {
    /* we have already dissected an ldap PDU in this frame - add a separator and set a fence */
    col_append_str(pinfo->cinfo, COL_INFO, " | ");
    col_set_fence(pinfo->cinfo, COL_INFO);
  } else {
    col_clear(pinfo->cinfo, COL_INFO);
    register_frame_end_routine (pinfo, ldap_frame_end);
    ldap_found_in_frame = true;
  }

  ldap_item = proto_tree_add_item(tree, is_mscldap?proto_cldap:proto_ldap, tvb, 0, -1, ENC_NA);
  ldap_tree = proto_item_add_subtree(ldap_item, ett_ldap);

  /*
  * Might we be doing a SASL security layer and, if so, *are* we doing
  * one?
  *
  * Just because we've seen a bind reply for SASL, that doesn't mean
  * that we're using a SASL security layer; I've seen captures in
  * which some SASL negotiations lead to a security layer being used
  * and other negotiations don't, and it's not obvious what's different
  * in the two negotiations.  Therefore, we assume that if the first
  * byte is 0, it's a length for a SASL security layer (that way, we
  * never reassemble more than 16 megabytes, protecting us from
  * chewing up *too* much memory), and otherwise that it's an LDAP
  * message (actually, if it's an LDAP message it should begin with 0x30,
  * but we want to parse garbage as LDAP messages rather than really
  * huge lengths).
  */

  if (doing_sasl_security && tvb_get_uint8(tvb, offset) == 0) {
    proto_tree *sasl_tree;
    tvbuff_t *sasl_tvb;
    unsigned sasl_len, sasl_msg_len, length;
    /*
    * Yes.  The frame begins with a 4-byte big-endian length.
    * And we know we have at least 6 bytes
    */

    /*
    * Get the SASL length, which is the length of data in the buffer
    * following the length (i.e., it's 4 less than the total length).
    *
    * XXX - do we need to reassemble buffers?  For now, we
    * assume that each LDAP message is entirely contained within
    * a buffer.
    */
    sasl_len = tvb_get_ntohl(tvb, offset);
    sasl_msg_len = sasl_len + 4;
    if (sasl_msg_len < 4) {
      /*
      * The message length was probably so large that the total length
      * overflowed.
      *
      * Report this as an error.
      */
      show_reported_bounds_error(tvb, pinfo, tree);
      return;
    }

    /*
    * Construct a tvbuff containing the amount of the payload we have
    * available.  Make its reported length the amount of data in the PDU.
    *
    * XXX - if reassembly isn't enabled. the subdissector will throw a
    * BoundsError exception, rather than a ReportedBoundsError exception.
    * We really want a tvbuff where the length is "length", the reported
    * length is "plen", and the "if the snapshot length were infinite"
    * length is the minimum of the reported length of the tvbuff handed
    * to us and "plen", with a new type of exception thrown if the offset
    * is within the reported length but beyond that third length, with
    * that exception getting the "Unreassembled Packet" error.
    */
    length = length_remaining;
    if (length > sasl_msg_len) length = sasl_msg_len;
    sasl_tvb = tvb_new_subset_length_caplen(tvb, offset, length, sasl_msg_len);

    proto_tree_add_uint(ldap_tree, hf_ldap_sasl_buffer_length, sasl_tvb, 0, 4, sasl_len);

    sasl_tree = proto_tree_add_subtree(ldap_tree, sasl_tvb, 4, sasl_msg_len - 4, ett_ldap_sasl_blob, NULL, "SASL Buffer");

    if (ldap_info->auth_mech != NULL &&
      ((strcmp(ldap_info->auth_mech, "GSS-SPNEGO") == 0) ||
      /* auth_mech may have been set from the bind */
      (strcmp(ldap_info->auth_mech, "GSSAPI") == 0))) {
        tvbuff_t *gssapi_tvb = NULL;
        int ver_len;
        int tmp_length;
        gssapi_encrypt_info_t gssapi_encrypt;

        /*
        * This is GSS-API (using SPNEGO, but we should be done with
        * the negotiation by now).
        *
        * Dissect the GSS_Wrap() token; it'll return the length of
        * the token, from which we compute the offset in the tvbuff at
        * which the plaintext data, i.e. the LDAP message, begins.
        */
        tmp_length = tvb_reported_length_remaining(sasl_tvb, 4);
        if ((unsigned)tmp_length > sasl_len)
          tmp_length = sasl_len;
        gssapi_tvb = tvb_new_subset_length_caplen(sasl_tvb, 4, tmp_length, sasl_len);

        /* Attempt decryption of the GSSAPI wrapped data if possible */
        memset(&gssapi_encrypt, 0, sizeof(gssapi_encrypt));
        gssapi_encrypt.decrypt_gssapi_tvb=DECRYPT_GSSAPI_NORMAL;
        ver_len = call_dissector_with_data(gssapi_wrap_handle, gssapi_tvb, pinfo, sasl_tree, &gssapi_encrypt);
        /*
        * If ver_len is 0, it probably means that we got a PDU that is not
        * aligned to the start of the segment.
        */
        if(ver_len==0){
          return;
        }
        if (gssapi_encrypt.gssapi_data_encrypted) {
          if (gssapi_encrypt.gssapi_decrypted_tvb) {
            tvbuff_t *decr_tvb = gssapi_encrypt.gssapi_decrypted_tvb;
            proto_tree *enc_tree = NULL;

            /*
             * The LDAP payload (blob) was encrypted and we were able to decrypt it.
             * The data was signed via a MIC token, sealed (encrypted), and "wrapped"
             * within the mechanism's "blob." Call dissect_ldap_payload to dissect
             * one or more LDAPMessages such as searchRequest messages within this
             * payload.
             */
            col_set_str(pinfo->cinfo, COL_INFO, "SASL GSS-API Privacy (decrypted): ");

            if (sasl_tree) {
              unsigned decr_len = tvb_reported_length(decr_tvb);

              enc_tree = proto_tree_add_subtree_format(sasl_tree, decr_tvb, 0, -1,
                ett_ldap_payload, NULL, "GSS-API Encrypted payload (%d byte%s)",
                decr_len, plurality(decr_len, "", "s"));
            }

            dissect_ldap_payload(decr_tvb, pinfo, enc_tree, ldap_info, is_mscldap);
          } else {
            /*
            * The LDAP message was encrypted but couldn't be decrypted so just display the
            * encrypted data all of which is found in Packet Bytes.
            */
            col_add_fstr(pinfo->cinfo, COL_INFO, "SASL GSS-API Privacy: payload (%d byte%s)",
              sasl_len-ver_len, plurality(sasl_len-ver_len, "", "s"));

            proto_tree_add_item(sasl_tree, hf_ldap_gssapi_encrypted_payload, gssapi_tvb, ver_len, -1, ENC_NA);
          }
        } else {
          tvbuff_t *plain_tvb;
          if (gssapi_encrypt.gssapi_decrypted_tvb) {
            plain_tvb = gssapi_encrypt.gssapi_decrypted_tvb;
          } else {
            plain_tvb = tvb_new_subset_remaining(gssapi_tvb, ver_len);
          }
          proto_tree *plain_tree = NULL;

          /*
          * The payload was not encrypted (sealed) but was signed via a MIC token.
          * If krb5_tok_id == KRB_TOKEN_CFX_WRAP, the payload was wrapped within
          * the mechanism's blob. Call dissect_ldap_payload to dissect one or more
          * LDAPMessages within the payload.
          */
          col_set_str(pinfo->cinfo, COL_INFO, "SASL GSS-API Integrity: ");

          if (sasl_tree) {
            unsigned plain_len = tvb_reported_length(plain_tvb);

            plain_tree = proto_tree_add_subtree_format(sasl_tree, plain_tvb, 0, -1,
              ett_ldap_payload, NULL, "GSS-API payload (%d byte%s)",
              plain_len, plurality(plain_len, "", "s"));
          }

          dissect_ldap_payload(plain_tvb, pinfo, plain_tree, ldap_info, is_mscldap);
        }
    }
  } else {
    /*
    * The LDAP packet does not contain a SASL security layer. Such messages are typically sent
    * prior to the LDAP "bind" negotiation exchange which establishes the "context" of the session.
    * This means the data could neither be "signed" (no data origin auth or data integrity
    * check) nor "sealed" (encrypted).
    */
    dissect_ldap_payload(tvb, pinfo, ldap_tree, ldap_info, is_mscldap);
  }
}

int dissect_mscldap_string(wmem_allocator_t *scope, tvbuff_t *tvb, int offset, int max_len, char **str)
{
  int compr_len;
  const char *name;
  unsigned name_len;

  /* The name data MUST start at offset 0 of the tvb */
  compr_len = get_dns_name(tvb, offset, max_len, 0, &name, &name_len);
  *str = get_utf_8_string(scope, name, name_len);
  return offset + compr_len;
}


/* These are the cldap DC flags
   http://msdn.microsoft.com/en-us/library/cc201036.aspx
 */
static const true_false_string tfs_ads_pdc = {
  "This is a PDC",
  "This is NOT a pdc"
};
static const true_false_string tfs_ads_gc = {
  "This is a GLOBAL CATALOGUE of forest",
  "This is NOT a global catalog of forest"
};
static const true_false_string tfs_ads_ldap = {
  "This is an LDAP server",
  "This is NOT an ldap server"
};
static const true_false_string tfs_ads_ds = {
  "This dc supports DS",
  "This dc does NOT support ds"
};
static const true_false_string tfs_ads_kdc = {
  "This is a KDC (kerberos)",
  "This is NOT a kdc (kerberos)"
};
static const true_false_string tfs_ads_timeserv = {
  "This dc is running TIME SERVICES (ntp)",
  "This dc is NOT running time services (ntp)"
};
static const true_false_string tfs_ads_closest = {
  "This server is in the same site as the client",
  "This server is NOT in the same site as the client"
};
static const true_false_string tfs_ads_writable = {
  "This dc is WRITABLE",
  "This dc is NOT writable"
};
static const true_false_string tfs_ads_good_timeserv = {
  "This dc has a GOOD TIME SERVICE (i.e. hardware clock)",
  "This dc does NOT have a good time service (i.e. no hardware clock)"
};
static const true_false_string tfs_ads_ndnc = {
  "Domain is NON-DOMAIN NC serviced by ldap server",
  "Domain is NOT non-domain nc serviced by ldap server"
};
static const true_false_string tfs_ads_rodc = {
  "Domain controller is a Windows 2008 RODC",
  "Domain controller is not a Windows 2008 RODC"
};
static const true_false_string tfs_ads_wdc = {
  "Domain controller is a Windows 2008 writable NC",
  "Domain controller is not a Windows 2008 writable NC"
};
static const true_false_string tfs_ads_dns = {
  "Server name is in DNS format (Windows 2008)",
  "Server name is not in DNS format (Windows 2008)"
};
static const true_false_string tfs_ads_dnc = {
  "The NC is the default NC (Windows 2008)",
  "The NC is not the default NC (Windows 2008)"
};
static const true_false_string tfs_ads_fnc = {
  "The NC is the default forest NC(Windows 2008)",
  "The NC is not the default forest NC (Windows 2008)"
};
static int dissect_mscldap_netlogon_flags(proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
  static int * const flags[] = {
    &hf_mscldap_netlogon_flags_fnc,
    &hf_mscldap_netlogon_flags_dnc,
    &hf_mscldap_netlogon_flags_dns,
    &hf_mscldap_netlogon_flags_wdc,
    &hf_mscldap_netlogon_flags_rodc,
    &hf_mscldap_netlogon_flags_ndnc,
    &hf_mscldap_netlogon_flags_good_timeserv,
    &hf_mscldap_netlogon_flags_writable,
    &hf_mscldap_netlogon_flags_closest,
    &hf_mscldap_netlogon_flags_timeserv,
    &hf_mscldap_netlogon_flags_kdc,
    &hf_mscldap_netlogon_flags_ds,
    &hf_mscldap_netlogon_flags_ldap,
    &hf_mscldap_netlogon_flags_gc,
    &hf_mscldap_netlogon_flags_pdc,
    NULL
  };

  proto_tree_add_bitmask_with_flags(parent_tree, tvb, offset, hf_mscldap_netlogon_flags,
                           ett_mscldap_netlogon_flags, flags, ENC_LITTLE_ENDIAN, BMT_NO_FALSE);
  offset += 4;

  return offset;
}

static int dissect_NetLogon_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  int old_offset, offset=0;
  char *str;
  uint16_t itype;
  uint16_t len;
  uint32_t version;
  int fn_len;
  proto_item *item;

  ldm_tree = NULL;


  /* Get the length of the buffer */
  len=tvb_reported_length_remaining(tvb,offset);

  /* check the len if it is to small return */
  if (len < 10)
    return tvb_captured_length(tvb);

  /* Type */
  proto_tree_add_item(tree, hf_mscldap_netlogon_opcode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  itype = tvb_get_letohs(tvb, offset);
  offset += 2;

  switch(itype){

    case LOGON_SAM_LOGON_RESPONSE:
      /* logon server name; must be aligned on a 2-byte boundary */
      if ((offset & 1) != 0) {
        offset++;
      }
      proto_tree_add_item_ret_length(tree, hf_mscldap_nb_hostname_z, tvb,offset, -1, ENC_UTF_16|ENC_LITTLE_ENDIAN, &fn_len);
      offset +=fn_len;

      /* username; must be aligned on a 2-byte boundary */
      if ((offset & 1) != 0) {
        offset++;
      }
      proto_tree_add_item_ret_length(tree, hf_mscldap_username_z, tvb,offset, -1, ENC_UTF_16|ENC_LITTLE_ENDIAN, &fn_len);
      offset +=fn_len;

      /* domain name; must be aligned on a 2-byte boundary */
      if ((offset & 1) != 0) {
        offset++;
      }
      proto_tree_add_item_ret_length(tree, hf_mscldap_nb_domain_z, tvb,offset, -1, ENC_UTF_16|ENC_LITTLE_ENDIAN, &fn_len);
      offset +=fn_len;

      /* get the version number from the end of the buffer, as the
         length is variable and the version determines what fields
         need to be decoded */
      version = tvb_get_letohl(tvb,len-8);

      /* include the extra version 5 fields */
      if ((version & NETLOGON_NT_VERSION_5) == NETLOGON_NT_VERSION_5){

        /* domain guid */
        proto_tree_add_item(tree, hf_mscldap_domain_guid, tvb, offset, 16, ENC_LITTLE_ENDIAN);
        offset += 16;

        /* domain guid part 2
           there is another 16 byte guid but this is alway zero, so we will skip it */
        offset += 16;

        /* Forest */
        old_offset=offset;
        offset=dissect_mscldap_string(pinfo->pool, tvb, offset, 255, &str);
        proto_tree_add_string(tree, hf_mscldap_forest, tvb, old_offset, offset-old_offset, str);

        /* Domain */
        old_offset=offset;
        offset=dissect_mscldap_string(pinfo->pool, tvb, offset, 255, &str);
        proto_tree_add_string(tree, hf_mscldap_domain, tvb, old_offset, offset-old_offset, str);

        /* Hostname */
        old_offset=offset;
        offset=dissect_mscldap_string(pinfo->pool, tvb, offset, 255, &str);
        proto_tree_add_string(tree, hf_mscldap_hostname, tvb, old_offset, offset-old_offset, str);

        /* DC IP Address */
        proto_tree_add_item(tree, hf_mscldap_netlogon_ipaddress, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        /* Flags */
        dissect_mscldap_netlogon_flags(tree, tvb, offset);
      }

      break;

    case LOGON_SAM_LOGON_RESPONSE_EX:
      /* MS-ADTS 6.3.1.9 */
      offset += 2; /* Skip over "Sbz" field (MUST be set to 0) */

      /* Flags */
      offset = dissect_mscldap_netlogon_flags(tree, tvb, offset);

      /* Domain GUID */
      proto_tree_add_item(tree, hf_mscldap_domain_guid, tvb, offset, 16, ENC_LITTLE_ENDIAN);
      offset += 16;

      /* Forest */
      old_offset=offset;
      offset=dissect_mscldap_string(pinfo->pool, tvb, offset, 255, &str);
      proto_tree_add_string(tree, hf_mscldap_forest, tvb, old_offset, offset-old_offset, str);

      /* Domain */
      old_offset=offset;
      offset=dissect_mscldap_string(pinfo->pool, tvb, offset, 255, &str);
      proto_tree_add_string(tree, hf_mscldap_domain, tvb, old_offset, offset-old_offset, str);

      /* Hostname */
      old_offset=offset;
      offset=dissect_mscldap_string(pinfo->pool, tvb, offset, 255, &str);
      proto_tree_add_string(tree, hf_mscldap_hostname, tvb, old_offset, offset-old_offset, str);

      /* NetBIOS Domain */
      old_offset=offset;
      offset=dissect_mscldap_string(pinfo->pool, tvb, offset, 255, &str);
      proto_tree_add_string(tree, hf_mscldap_nb_domain, tvb, old_offset, offset-old_offset, str);

      /* NetBIOS Hostname */
      old_offset=offset;
      offset=dissect_mscldap_string(pinfo->pool, tvb, offset, 255, &str);
      proto_tree_add_string(tree, hf_mscldap_nb_hostname, tvb, old_offset, offset-old_offset, str);

      /* User */
      old_offset=offset;
      offset=dissect_mscldap_string(pinfo->pool, tvb, offset, 255, &str);
      proto_tree_add_string(tree, hf_mscldap_username, tvb, old_offset, offset-old_offset, str);

      /* Server Site */
      old_offset=offset;
      offset=dissect_mscldap_string(pinfo->pool, tvb, offset, 255, &str);
      proto_tree_add_string(tree, hf_mscldap_sitename, tvb, old_offset, offset-old_offset, str);

      /* Client Site */
      old_offset=offset;
      offset=dissect_mscldap_string(pinfo->pool, tvb, offset, 255, &str);
      proto_tree_add_string(tree, hf_mscldap_clientsitename, tvb, old_offset, offset-old_offset, str);

      /* get the version number from the end of the buffer, as the
         length is variable and the version determines what fields
         need to be decoded */
      version = tvb_get_letohl(tvb,len-8);

      /* include the extra fields for version 5 with IP s */
      if ((version & NETLOGON_NT_VERSION_5EX_WITH_IP) == NETLOGON_NT_VERSION_5EX_WITH_IP){
        /* The ip address is returned as a sockaddr_in structure
         *
         *  This section may need to be updated if the base Windows APIs
         *  are changed to support ipv6, which currently is not the case.
         *
         *  The dissector assumes the length is based on ipv4 and
         *  ignores the length
         */

        /* skip the length of the sockaddr_in */

        offset +=1;

        /* add IP address and dissect the sockaddr_in structure */

        old_offset = offset + 4;
        item = proto_tree_add_item(tree, hf_mscldap_netlogon_ipaddress, tvb, old_offset, 4, ENC_BIG_ENDIAN);

        if (tree) {
          proto_tree *subtree;

          subtree = proto_item_add_subtree(item, ett_mscldap_ipdetails);

          /* get sockaddr family */
          proto_tree_add_item(subtree, hf_mscldap_netlogon_ipaddress_family, tvb, offset, 2, ENC_LITTLE_ENDIAN);
          offset +=2;

          /* get sockaddr port */
          proto_tree_add_item(subtree, hf_mscldap_netlogon_ipaddress_port, tvb, offset, 2, ENC_LITTLE_ENDIAN);
          offset +=2;

          /* get IP address */
          proto_tree_add_item(subtree, hf_mscldap_netlogon_ipaddress_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        }

      }

      break;
  }


  /* complete the decode with the version and token details */

  offset = len - 8;

  /* NETLOGON_NT_VERSION Options (MS-ADTS 6.3.1.1) */
  offset = dissect_mscldap_ntver_flags(tree, tvb, offset);

  /* LM Token */
  proto_tree_add_item(tree, hf_mscldap_netlogon_lm_token, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  /* NT Token */
  proto_tree_add_item(tree, hf_mscldap_netlogon_nt_token, tvb, offset, 2, ENC_LITTLE_ENDIAN);

  return tvb_captured_length(tvb);
}


static unsigned
get_sasl_ldap_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                      int offset, void *data _U_)
{
  /* sasl encapsulated ldap is 4 bytes plus the length in size */
  return tvb_get_ntohl(tvb, offset)+4;
}

static int
dissect_sasl_ldap_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  dissect_ldap_pdu(tvb, pinfo, tree, false);
  return tvb_captured_length(tvb);
}

static unsigned
get_normal_ldap_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                        int offset, void *data _U_)
{
  uint32_t len;
  bool ind;
  int data_offset;

  /* normal ldap is tag+len bytes plus the length
   * offset is where the tag is
   * offset+1 is where length starts
   */
  data_offset=get_ber_length(tvb, offset+1, &len, &ind);
  return len+data_offset-offset;
}

static int
dissect_normal_ldap_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  dissect_ldap_pdu(tvb, pinfo, tree, false);
  return tvb_captured_length(tvb);
}

static int
dissect_ldap_oid(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
  char *oid;
  const char *oidname;

  /* tvb here contains an ascii string that is really an oid */
  /* XXX   we should convert the string oid into a real oid so we can use
   *       proto_tree_add_oid() instead.
   */

  oid=tvb_get_string_enc(pinfo->pool, tvb, 0, tvb_reported_length(tvb), ENC_UTF_8|ENC_NA);
  if(!oid){
    return tvb_captured_length(tvb);
  }

  oidname=oid_resolved_from_string(pinfo->pool, oid);

  if(oidname){
    proto_tree_add_string_format_value(tree, hf_ldap_oid, tvb, 0, tvb_reported_length(tvb), oid, "%s (%s)",oid,oidname);
  } else {
    proto_tree_add_string(tree, hf_ldap_oid, tvb, 0, tvb_captured_length(tvb), oid);
  }
  return tvb_captured_length(tvb);
}

#define LDAP_ACCESSMASK_ADS_CREATE_CHILD    0x00000001
#define LDAP_ACCESSMASK_ADS_DELETE_CHILD    0x00000002
#define LDAP_ACCESSMASK_ADS_LIST            0x00000004
#define LDAP_ACCESSMASK_ADS_SELF_WRITE      0x00000008
#define LDAP_ACCESSMASK_ADS_READ_PROP       0x00000010
#define LDAP_ACCESSMASK_ADS_WRITE_PROP      0x00000020
#define LDAP_ACCESSMASK_ADS_DELETE_TREE     0x00000040
#define LDAP_ACCESSMASK_ADS_LIST_OBJECT     0x00000080
#define LDAP_ACCESSMASK_ADS_CONTROL_ACCESS  0x00000100

static void
ldap_specific_rights(tvbuff_t *tvb, int offset, proto_tree *tree, uint32_t access)
{
  static int * const access_flags[] = {
    &hf_ldap_AccessMask_ADS_CONTROL_ACCESS,
    &hf_ldap_AccessMask_ADS_LIST_OBJECT,
    &hf_ldap_AccessMask_ADS_DELETE_TREE,
    &hf_ldap_AccessMask_ADS_WRITE_PROP,
    &hf_ldap_AccessMask_ADS_READ_PROP,
    &hf_ldap_AccessMask_ADS_SELF_WRITE,
    &hf_ldap_AccessMask_ADS_LIST,
    &hf_ldap_AccessMask_ADS_DELETE_CHILD,
    &hf_ldap_AccessMask_ADS_CREATE_CHILD,
    NULL
  };

  proto_tree_add_bitmask_list_value(tree, tvb, offset, 4, access_flags, access);
}

static struct access_mask_info ldap_access_mask_info = {
  "LDAP",                 /* Name of specific rights */
  ldap_specific_rights,   /* Dissection function */
  NULL,                   /* Generic mapping table */
  NULL                    /* Standard mapping table */
};

static int
dissect_ldap_nt_sec_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  dissect_nt_sec_desc(tvb, 0, pinfo, tree, NULL, true, tvb_reported_length(tvb), &ldap_access_mask_info);
  return tvb_captured_length(tvb);
}

static int
dissect_ldap_sid(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
  char *tmpstr;

  /* this octet string contains an NT SID */
  dissect_nt_sid(tvb, 0, tree, "SID", &tmpstr, hf_ldap_sid);
  ldapvalue_string=tmpstr;
  return tvb_captured_length(tvb);
}

static int
dissect_ldap_guid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  uint8_t drep[4] = { 0x10, 0x00, 0x00, 0x00}; /* fake DREP struct */
  e_guid_t uuid;

  /* This octet string contained a GUID */
  dissect_dcerpc_uuid_t(tvb, 0, pinfo, tree, drep, hf_ldap_guid, &uuid);

  ldapvalue_string=(char*)wmem_alloc(pinfo->pool, 1024);
  snprintf(ldapvalue_string, 1023, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             uuid.data1, uuid.data2, uuid.data3, uuid.data4[0], uuid.data4[1],
             uuid.data4[2], uuid.data4[3], uuid.data4[4], uuid.data4[5],
             uuid.data4[6], uuid.data4[7]);
  return tvb_captured_length(tvb);
}

static int
dissect_ldap_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  uint32_t sasl_len;
  uint32_t ldap_len;
  bool ind;
  conversation_t *conversation;
  ldap_conv_info_t *ldap_info = NULL;

  /*
   * Do we have a conversation for this connection?
   */
  conversation = find_conversation_pinfo(pinfo, 0);
  if(conversation){
    ldap_info = (ldap_conv_info_t *)conversation_get_proto_data(conversation, proto_ldap);
  }

  ldm_tree = NULL;

  /* This is a bit tricky. We have to find out whether SASL is used
   * so that we know how big a header we are supposed to pass
   * to tcp_dissect_pdus()
   * We must also cope with the case when a client connects to LDAP
   * and performs a few unauthenticated searches of LDAP before
   * it performs the bind on the same tcp connection.
   */
  /* check for a SASL header, i.e. assume it is SASL if
   * 1, first four bytes (SASL length) is an integer
   *    with a value that must be <LDAP_SASL_MAX_BUF and >2
   *    (>2 to fight false positives, 0x00000000 is a common
   *        "random" tcp payload)
   * (SASL ldap PDUs might be >64k in size, which is why
   * LDAP_SASL_MAX_BUF is used - defined in packet-ldap.h)
   *
   * 2, we must have a conversation and the auth type must
   *    be LDAP_AUTH_SASL
   */
  sasl_len=tvb_get_ntohl(tvb, 0);

  if( sasl_len<2 ){
    goto this_was_not_sasl;
  }

  if( sasl_len>LDAP_SASL_MAX_BUF ){
    goto this_was_not_sasl;
  }

  if((!ldap_info) || (ldap_info->auth_type!=LDAP_AUTH_SASL) ){
    goto this_was_not_sasl;
  }

  tcp_dissect_pdus(tvb, pinfo, tree, ldap_desegment, 4, get_sasl_ldap_pdu_len, dissect_sasl_ldap_pdu, data);
  return tvb_captured_length(tvb);

this_was_not_sasl:
  /* check if it is a normal BER encoded LDAP packet
   * i.e. first byte is 0x30 followed by a length that is
   * <64k
   * (no ldap PDUs are ever >64kb? )
   */
  if(tvb_get_uint8(tvb, 0)!=0x30){
    goto this_was_not_normal_ldap;
  }

  /* check that length makes sense */
  get_ber_length(tvb, 1, &ldap_len, &ind);

  /* don't check ind since indefinite length is never used for ldap (famous last words)*/
  if(ldap_len<2){
    goto this_was_not_normal_ldap;
  }

  /*
   * The minimum size of a LDAP pdu is 7 bytes
   *
   * dumpasn1 -hh ldap-unbind-min.dat
   *
   *     <30 05 02 01 09 42 00>
   *    0    5: SEQUENCE {
   *     <02 01 09>
   *    2    1:   INTEGER 9
   *     <42 00>
   *    5    0:   [APPLICATION 2]
   *          :     Error: Object has zero length.
   *          :   }
   *
   * dumpasn1 -hh ldap-unbind-windows.dat
   *
   *     <30 84 00 00 00 05 02 01 09 42 00>
   *    0    5: SEQUENCE {
   *     <02 01 09>
   *    6    1:   INTEGER 9
   *     <42 00>
   *    9    0:   [APPLICATION 2]
   *          :     Error: Object has zero length.
   *          :   }
   *
   * 6 bytes would also be ok to get the full length of
   * the pdu, but as the smallest pdu can be 7 bytes
   * we can use 7.
   */
  tcp_dissect_pdus(tvb, pinfo, tree, ldap_desegment, 7, get_normal_ldap_pdu_len, dissect_normal_ldap_pdu, data);

  goto end;

this_was_not_normal_ldap:

  /* Ok it might be a strange case of SASL still
   * It has been seen with Exchange setup to MS AD
   * when Exchange pretend that there is SASL but in fact data are still
   * in clear*/
  if ((sasl_len + 4) == (uint32_t)tvb_reported_length_remaining(tvb, 0))
    tcp_dissect_pdus(tvb, pinfo, tree, ldap_desegment, 4, get_sasl_ldap_pdu_len, dissect_sasl_ldap_pdu, data);
 end:
  return tvb_captured_length(tvb);
}

static int
dissect_mscldap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  dissect_ldap_pdu(tvb, pinfo, tree, true);
  return tvb_captured_length(tvb);
}


/*--- proto_register_ldap -------------------------------------------*/
void proto_register_ldap(void) {

  /* List of fields */

  static hf_register_info hf[] = {

    { &hf_ldap_sasl_buffer_length,
      { "SASL Buffer Length",   "ldap.sasl_buffer_length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_ldap_response_in,
      { "Response In", "ldap.response_in",
        FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "The response to this LDAP request is in this frame", HFILL }},
    { &hf_ldap_response_to,
      { "Response To", "ldap.response_to",
        FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "This is a response to the LDAP request in this frame", HFILL }},
    { &hf_ldap_time,
      { "Time", "ldap.time",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "The time between the Call and the Reply", HFILL }},

    { &hf_mscldap_netlogon_opcode,
      { "Operation code", "mscldap.netlogon.opcode",
        FT_UINT16, BASE_DEC, VALS(netlogon_opcode_vals), 0x0,
        "LDAP ping operation code", HFILL }},

    { &hf_mscldap_netlogon_ipaddress_family,
      { "Family", "mscldap.netlogon.ipaddress.family",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mscldap_netlogon_ipaddress_ipv4,
      { "IPv4", "mscldap.netlogon.ipaddress.ipv4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        "IP Address", HFILL }},

    { &hf_mscldap_netlogon_ipaddress_port,
      { "Port", "mscldap.netlogon.ipaddress.port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mscldap_netlogon_ipaddress,
      { "IP Address","mscldap.netlogon.ipaddress",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        "Domain Controller IP Address", HFILL }},

    { &hf_mscldap_netlogon_lm_token,
      { "LM Token", "mscldap.netlogon.lm_token",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "MUST be set to 0xFFFF", HFILL }},

    { &hf_mscldap_netlogon_nt_token,
      { "NT Token", "mscldap.netlogon.nt_token",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "MUST be set to 0xFFFF", HFILL }},

    { &hf_mscldap_netlogon_flags,
      { "Flags", "mscldap.netlogon.flags",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "Netlogon flags describing the DC properties", HFILL }},

    { &hf_mscldap_ntver_flags,
      { "Version Flags", "mscldap.ntver.flags",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "NETLOGON_NT_VERSION Options Bits", HFILL }},

    { &hf_mscldap_domain_guid,
      { "Domain GUID", "mscldap.domain.guid",
        FT_GUID, BASE_NONE, NULL, 0x0,
        "Value of the NC's GUID attribute", HFILL }},

    { &hf_mscldap_forest,
      { "Forest", "mscldap.forest",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "DNS name of the forest", HFILL }},

    { &hf_mscldap_domain,
      { "Domain", "mscldap.domain",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "DNS name of the NC", HFILL }},

    { &hf_mscldap_hostname,
      { "Hostname", "mscldap.hostname",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "DNS name of server", HFILL }},

    { &hf_mscldap_nb_domain_z,
      { "NetBIOS Domain", "mscldap.nb_domain",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "NetBIOS name of the NC", HFILL }},

    { &hf_mscldap_nb_domain,
      { "NetBIOS Domain", "mscldap.nb_domain",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "NetBIOS name of the NC", HFILL }},

    { &hf_mscldap_nb_hostname_z,
      { "NetBIOS Hostname", "mscldap.nb_hostname",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "NetBIOS name of the server", HFILL }},

    { &hf_mscldap_nb_hostname,
      { "NetBIOS Hostname", "mscldap.nb_hostname",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "NetBIOS name of the server", HFILL }},

    { &hf_mscldap_username_z,
      { "Username", "mscldap.username",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "User specified in client's request", HFILL }},

    { &hf_mscldap_username,
      { "Username", "mscldap.username",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "User specified in client's request", HFILL }},

    { &hf_mscldap_sitename,
      { "Server Site", "mscldap.sitename",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Site name of the server", HFILL }},

    { &hf_mscldap_clientsitename,
      { "Client Site", "mscldap.clientsitename",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Site name of the client", HFILL }},

    { &hf_ldap_sid,
      { "Sid", "ldap.sid",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mscldap_ntver_flags_v1,
      { "V1", "mscldap.ntver.searchflags.v1", FT_BOOLEAN, 32,
        TFS(&tfs_ntver_v1), 0x00000001, "See section 6.3.1.1 of MS-ADTS specification", HFILL }},

    { &hf_mscldap_ntver_flags_v5,
      { "V5", "mscldap.ntver.searchflags.v5", FT_BOOLEAN, 32,
        TFS(&tfs_ntver_v5), 0x00000002, "See section 6.3.1.1 of MS-ADTS specification", HFILL }},

    { &hf_mscldap_ntver_flags_v5ex,
      { "V5EX", "mscldap.ntver.searchflags.v5ex", FT_BOOLEAN, 32,
        TFS(&tfs_ntver_v5ex), 0x00000004, "See section 6.3.1.1 of MS-ADTS specification", HFILL }},

    { &hf_mscldap_ntver_flags_v5ep,
      { "V5EP", "mscldap.ntver.searchflags.v5ep", FT_BOOLEAN, 32,
        TFS(&tfs_ntver_v5ep), 0x00000008, "See section 6.3.1.1 of MS-ADTS specification", HFILL }},

    { &hf_mscldap_ntver_flags_vcs,
      { "VCS", "mscldap.ntver.searchflags.vcs", FT_BOOLEAN, 32,
        TFS(&tfs_ntver_vcs), 0x00000010, "See section 6.3.1.1 of MS-ADTS specification", HFILL }},

    { &hf_mscldap_ntver_flags_vnt4,
      { "VNT4", "mscldap.ntver.searchflags.vnt4", FT_BOOLEAN, 32,
        TFS(&tfs_ntver_vnt4), 0x01000000, "See section 6.3.1.1 of MS-ADTS specification", HFILL }},

    { &hf_mscldap_ntver_flags_vpdc,
      { "VPDC", "mscldap.ntver.searchflags.vpdc", FT_BOOLEAN, 32,
        TFS(&tfs_ntver_vpdc), 0x10000000, "See section 6.3.1.1 of MS-ADTS specification", HFILL }},

    { &hf_mscldap_ntver_flags_vip,
      { "VIP", "mscldap.ntver.searchflags.vip", FT_BOOLEAN, 32,
        TFS(&tfs_ntver_vip), 0x20000000, "See section 6.3.1.1 of MS-ADTS specification", HFILL }},

    { &hf_mscldap_ntver_flags_vl,
      { "VL", "mscldap.ntver.searchflags.vl", FT_BOOLEAN, 32,
        TFS(&tfs_ntver_vl), 0x40000000, "See section 6.3.1.1 of MS-ADTS specification", HFILL }},

    { &hf_mscldap_ntver_flags_vgc,
      { "VGC", "mscldap.ntver.searchflags.vgc", FT_BOOLEAN, 32,
        TFS(&tfs_ntver_vgc), 0x80000000, "See section 6.3.1.1 of MS-ADTS specification", HFILL }},


    { &hf_mscldap_netlogon_flags_pdc,
      { "PDC", "mscldap.netlogon.flags.pdc", FT_BOOLEAN, 32,
        TFS(&tfs_ads_pdc), 0x00000001, "Is this DC a PDC or not?", HFILL }},

    { &hf_mscldap_netlogon_flags_gc,
      { "GC", "mscldap.netlogon.flags.gc", FT_BOOLEAN, 32,
        TFS(&tfs_ads_gc), 0x00000004, "Does this dc service as a GLOBAL CATALOGUE?", HFILL }},

    { &hf_mscldap_netlogon_flags_ldap,
      { "LDAP", "mscldap.netlogon.flags.ldap", FT_BOOLEAN, 32,
        TFS(&tfs_ads_ldap), 0x00000008, "Does this DC act as an LDAP server?", HFILL }},

    { &hf_mscldap_netlogon_flags_ds,
      { "DS", "mscldap.netlogon.flags.ds", FT_BOOLEAN, 32,
        TFS(&tfs_ads_ds), 0x00000010, "Does this dc provide DS services?", HFILL }},

    { &hf_mscldap_netlogon_flags_kdc,
      { "KDC", "mscldap.netlogon.flags.kdc", FT_BOOLEAN, 32,
        TFS(&tfs_ads_kdc), 0x00000020, "Does this dc act as a KDC?", HFILL }},

    { &hf_mscldap_netlogon_flags_timeserv,
      { "Time Serv", "mscldap.netlogon.flags.timeserv", FT_BOOLEAN, 32,
        TFS(&tfs_ads_timeserv), 0x00000040, "Does this dc provide time services (ntp) ?", HFILL }},

    { &hf_mscldap_netlogon_flags_closest,
      { "Closest", "mscldap.netlogon.flags.closest", FT_BOOLEAN, 32,
        TFS(&tfs_ads_closest), 0x00000080, "Is this the closest dc?", HFILL }},

    { &hf_mscldap_netlogon_flags_writable,
      { "Writable", "mscldap.netlogon.flags.writable", FT_BOOLEAN, 32,
        TFS(&tfs_ads_writable), 0x00000100, "Is this dc writable?", HFILL }},

    { &hf_mscldap_netlogon_flags_good_timeserv,
      { "Good Time Serv", "mscldap.netlogon.flags.good_timeserv", FT_BOOLEAN, 32,
        TFS(&tfs_ads_good_timeserv), 0x00000200, "Is this a Good Time Server? (i.e. does it have a hardware clock)", HFILL }},

    { &hf_mscldap_netlogon_flags_ndnc,
      { "NDNC", "mscldap.netlogon.flags.ndnc", FT_BOOLEAN, 32,
        TFS(&tfs_ads_ndnc), 0x00000400, "Is this an NDNC dc?", HFILL }},

    { &hf_mscldap_netlogon_flags_rodc,
      { "RODC", "mscldap.netlogon.flags.rodc", FT_BOOLEAN, 32,
        TFS(&tfs_ads_rodc), 0x00000800, "Is this an read only dc?", HFILL }},

    { &hf_mscldap_netlogon_flags_wdc,
      { "WDC", "mscldap.netlogon.flags.writabledc", FT_BOOLEAN, 32,
        TFS(&tfs_ads_wdc), 0x00001000, "Is this an writable dc (Windows 2008)?", HFILL }},

    { &hf_mscldap_netlogon_flags_dns,
      { "DNS", "mscldap.netlogon.flags.dnsname", FT_BOOLEAN, 32,
        TFS(&tfs_ads_dns), 0x20000000, "Does the server have a dns name (Windows 2008)?", HFILL }},

    { &hf_mscldap_netlogon_flags_dnc,
      { "DNC", "mscldap.netlogon.flags.defaultnc", FT_BOOLEAN, 32,
        TFS(&tfs_ads_dnc), 0x40000000, "Is this the default NC (Windows 2008)?", HFILL }},

    { &hf_mscldap_netlogon_flags_fnc,
      { "FDC", "mscldap.netlogon.flags.forestnc", FT_BOOLEAN, 32,
        TFS(&tfs_ads_fnc), 0x80000000, "Is the NC the default forest root(Windows 2008)?", HFILL }},

    { &hf_ldap_guid,
      { "GUID", "ldap.guid", FT_GUID, BASE_NONE,
        NULL, 0, NULL, HFILL }},

    { &hf_ldap_AccessMask_ADS_CREATE_CHILD,
      { "Ads Create Child", "ldap.AccessMask.ADS_CREATE_CHILD", FT_BOOLEAN, 32, TFS(&tfs_set_notset), LDAP_ACCESSMASK_ADS_CREATE_CHILD, NULL, HFILL }},

    { &hf_ldap_AccessMask_ADS_DELETE_CHILD,
      { "Ads Delete Child", "ldap.AccessMask.ADS_DELETE_CHILD", FT_BOOLEAN, 32, TFS(&tfs_set_notset), LDAP_ACCESSMASK_ADS_DELETE_CHILD, NULL, HFILL }},

    { &hf_ldap_AccessMask_ADS_LIST,
      { "Ads List", "ldap.AccessMask.ADS_LIST", FT_BOOLEAN, 32, TFS(&tfs_set_notset), LDAP_ACCESSMASK_ADS_LIST, NULL, HFILL }},

    { &hf_ldap_AccessMask_ADS_SELF_WRITE,
      { "Ads Self Write", "ldap.AccessMask.ADS_SELF_WRITE", FT_BOOLEAN, 32, TFS(&tfs_set_notset), LDAP_ACCESSMASK_ADS_SELF_WRITE, NULL, HFILL }},

    { &hf_ldap_AccessMask_ADS_READ_PROP,
      { "Ads Read Prop", "ldap.AccessMask.ADS_READ_PROP", FT_BOOLEAN, 32, TFS(&tfs_set_notset), LDAP_ACCESSMASK_ADS_READ_PROP, NULL, HFILL }},

    { &hf_ldap_AccessMask_ADS_WRITE_PROP,
      { "Ads Write Prop", "ldap.AccessMask.ADS_WRITE_PROP", FT_BOOLEAN, 32, TFS(&tfs_set_notset), LDAP_ACCESSMASK_ADS_WRITE_PROP, NULL, HFILL }},

    { &hf_ldap_AccessMask_ADS_DELETE_TREE,
      { "Ads Delete Tree", "ldap.AccessMask.ADS_DELETE_TREE", FT_BOOLEAN, 32, TFS(&tfs_set_notset), LDAP_ACCESSMASK_ADS_DELETE_TREE, NULL, HFILL }},

    { &hf_ldap_AccessMask_ADS_LIST_OBJECT,
      { "Ads List Object", "ldap.AccessMask.ADS_LIST_OBJECT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), LDAP_ACCESSMASK_ADS_LIST_OBJECT, NULL, HFILL }},

    { &hf_ldap_AccessMask_ADS_CONTROL_ACCESS,
      { "Ads Control Access", "ldap.AccessMask.ADS_CONTROL_ACCESS", FT_BOOLEAN, 32, TFS(&tfs_set_notset), LDAP_ACCESSMASK_ADS_CONTROL_ACCESS, NULL, HFILL }},

    { &hf_ldap_LDAPMessage_PDU,
      { "LDAPMessage", "ldap.LDAPMessage_element", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},

    { &hf_ldap_object_security_flag,
      { "Flag Object_Security", "ldap.object_security_flag", FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL }},

    { &hf_ldap_ancestor_first_flag,
      { "Flag Ancestor_First", "ldap.ancestor_first_flag", FT_BOOLEAN, 32, NULL, 0x00000800, NULL, HFILL }},

    { &hf_ldap_public_data_only_flag,
      { "Flag Public_Data_Only", "ldap.public_data_only_flag", FT_BOOLEAN, 32, NULL, 0x00002000, NULL, HFILL }},

    { &hf_ldap_incremental_value_flag,
      { "Flag Incremental_Value", "ldap.incremental_value_flag", FT_BOOLEAN, 32, NULL, 0x80000000, NULL, HFILL }},

    { &hf_ldap_oid,
      { "OID", "ldap.oid", FT_STRING, BASE_NONE,
        NULL, 0, NULL, HFILL }},

    { &hf_ldap_gssapi_encrypted_payload,
      { "GSS-API Encrypted payload", "ldap.gssapi_encrypted_payload", FT_BYTES, BASE_NONE,
        NULL, 0, NULL, HFILL }},

    { &hf_ldap_SearchControlValue_PDU,
      { "SearchControlValue", "ldap.SearchControlValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_SortKeyList_PDU,
      { "SortKeyList", "ldap.SortKeyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_SortResult_PDU,
      { "SortResult", "ldap.SortResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_DirSyncControlValue_PDU,
      { "DirSyncControlValue", "ldap.DirSyncControlValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_PasswdModifyRequestValue_PDU,
      { "PasswdModifyRequestValue", "ldap.PasswdModifyRequestValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_CancelRequestValue_PDU,
      { "CancelRequestValue", "ldap.CancelRequestValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_SyncRequestValue_PDU,
      { "SyncRequestValue", "ldap.SyncRequestValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_SyncStateValue_PDU,
      { "SyncStateValue", "ldap.SyncStateValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_SyncDoneValue_PDU,
      { "SyncDoneValue", "ldap.SyncDoneValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_SyncInfoValue_PDU,
      { "SyncInfoValue", "ldap.SyncInfoValue",
        FT_UINT32, BASE_DEC, VALS(ldap_SyncInfoValue_vals), 0,
        NULL, HFILL }},
    { &hf_ldap_PasswordPolicyResponseValue_PDU,
      { "PasswordPolicyResponseValue", "ldap.PasswordPolicyResponseValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_messageID,
      { "messageID", "ldap.messageID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_protocolOp,
      { "protocolOp", "ldap.protocolOp",
        FT_UINT32, BASE_DEC, VALS(ldap_ProtocolOp_vals), 0,
        NULL, HFILL }},
    { &hf_ldap_controls,
      { "controls", "ldap.controls",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_bindRequest,
      { "bindRequest", "ldap.bindRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_bindResponse,
      { "bindResponse", "ldap.bindResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_unbindRequest,
      { "unbindRequest", "ldap.unbindRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_searchRequest,
      { "searchRequest", "ldap.searchRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_searchResEntry,
      { "searchResEntry", "ldap.searchResEntry_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SearchResultEntry", HFILL }},
    { &hf_ldap_searchResDone,
      { "searchResDone", "ldap.searchResDone_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SearchResultDone", HFILL }},
    { &hf_ldap_searchResRef,
      { "searchResRef", "ldap.searchResRef",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SearchResultReference", HFILL }},
    { &hf_ldap_modifyRequest,
      { "modifyRequest", "ldap.modifyRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_modifyResponse,
      { "modifyResponse", "ldap.modifyResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_addRequest,
      { "addRequest", "ldap.addRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_addResponse,
      { "addResponse", "ldap.addResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_delRequest,
      { "delRequest", "ldap.delRequest",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_delResponse,
      { "delResponse", "ldap.delResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_modDNRequest,
      { "modDNRequest", "ldap.modDNRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyDNRequest", HFILL }},
    { &hf_ldap_modDNResponse,
      { "modDNResponse", "ldap.modDNResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyDNResponse", HFILL }},
    { &hf_ldap_compareRequest,
      { "compareRequest", "ldap.compareRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_compareResponse,
      { "compareResponse", "ldap.compareResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_abandonRequest,
      { "abandonRequest", "ldap.abandonRequest",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_extendedReq,
      { "extendedReq", "ldap.extendedReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExtendedRequest", HFILL }},
    { &hf_ldap_extendedResp,
      { "extendedResp", "ldap.extendedResp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExtendedResponse", HFILL }},
    { &hf_ldap_intermediateResponse,
      { "intermediateResponse", "ldap.intermediateResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_AttributeDescriptionList_item,
      { "AttributeDescription", "ldap.AttributeDescription",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_attributeDesc,
      { "attributeDesc", "ldap.attributeDesc",
        FT_STRING, BASE_NONE, NULL, 0,
        "AttributeDescription", HFILL }},
    { &hf_ldap_assertionValue,
      { "assertionValue", "ldap.assertionValue",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_type,
      { "type", "ldap.type",
        FT_STRING, BASE_NONE, NULL, 0,
        "AttributeDescription", HFILL }},
    { &hf_ldap_vals,
      { "vals", "ldap.vals",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_AttributeValue", HFILL }},
    { &hf_ldap_vals_item,
      { "AttributeValue", "ldap.AttributeValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_resultCode,
      { "resultCode", "ldap.resultCode",
        FT_UINT32, BASE_DEC, VALS(ldap_T_resultCode_vals), 0,
        NULL, HFILL }},
    { &hf_ldap_matchedDN,
      { "matchedDN", "ldap.matchedDN",
        FT_STRING, BASE_NONE, NULL, 0,
        "LDAPDN", HFILL }},
    { &hf_ldap_errorMessage,
      { "errorMessage", "ldap.errorMessage",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_referral,
      { "referral", "ldap.referral",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_Referral_item,
      { "LDAPURL", "ldap.LDAPURL",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_Controls_item,
      { "Control", "ldap.Control_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_controlType,
      { "controlType", "ldap.controlType",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_criticality,
      { "criticality", "ldap.criticality",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ldap_controlValue,
      { "controlValue", "ldap.controlValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_version,
      { "version", "ldap.version",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_127", HFILL }},
    { &hf_ldap_name,
      { "name", "ldap.name",
        FT_STRING, BASE_NONE, NULL, 0,
        "LDAPDN", HFILL }},
    { &hf_ldap_authentication,
      { "authentication", "ldap.authentication",
        FT_UINT32, BASE_DEC, VALS(ldap_AuthenticationChoice_vals), 0,
        "AuthenticationChoice", HFILL }},
    { &hf_ldap_simple,
      { "simple", "ldap.simple",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_sasl,
      { "sasl", "ldap.sasl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SaslCredentials", HFILL }},
    { &hf_ldap_ntlmsspNegotiate,
      { "ntlmsspNegotiate", "ldap.ntlmsspNegotiate",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_ntlmsspAuth,
      { "ntlmsspAuth", "ldap.ntlmsspAuth",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_mechanism,
      { "mechanism", "ldap.mechanism",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_credentials,
      { "credentials", "ldap.credentials",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_bindResponse_resultCode,
      { "resultCode", "ldap.resultCode",
        FT_UINT32, BASE_DEC, VALS(ldap_BindResponse_resultCode_vals), 0,
        "BindResponse_resultCode", HFILL }},
    { &hf_ldap_bindResponse_matchedDN,
      { "matchedDN", "ldap.matchedDN",
        FT_STRING, BASE_NONE, NULL, 0,
        "T_bindResponse_matchedDN", HFILL }},
    { &hf_ldap_serverSaslCreds,
      { "serverSaslCreds", "ldap.serverSaslCreds",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_baseObject,
      { "baseObject", "ldap.baseObject",
        FT_STRING, BASE_NONE, NULL, 0,
        "LDAPDN", HFILL }},
    { &hf_ldap_scope,
      { "scope", "ldap.scope",
        FT_UINT32, BASE_DEC, VALS(ldap_T_scope_vals), 0,
        NULL, HFILL }},
    { &hf_ldap_derefAliases,
      { "derefAliases", "ldap.derefAliases",
        FT_UINT32, BASE_DEC, VALS(ldap_T_derefAliases_vals), 0,
        NULL, HFILL }},
    { &hf_ldap_sizeLimit,
      { "sizeLimit", "ldap.sizeLimit",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_maxInt", HFILL }},
    { &hf_ldap_timeLimit,
      { "timeLimit", "ldap.timeLimit",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_maxInt", HFILL }},
    { &hf_ldap_typesOnly,
      { "typesOnly", "ldap.typesOnly",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ldap_filter,
      { "filter", "ldap.filter",
        FT_UINT32, BASE_DEC, VALS(ldap_Filter_vals), 0,
        NULL, HFILL }},
    { &hf_ldap_searchRequest_attributes,
      { "attributes", "ldap.attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AttributeDescriptionList", HFILL }},
    { &hf_ldap_and,
      { "and", "ldap.and",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_and_item,
      { "and item", "ldap.and_item",
        FT_UINT32, BASE_DEC, VALS(ldap_Filter_vals), 0,
        NULL, HFILL }},
    { &hf_ldap_or,
      { "or", "ldap.or",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_or_item,
      { "or item", "ldap.or_item",
        FT_UINT32, BASE_DEC, VALS(ldap_Filter_vals), 0,
        NULL, HFILL }},
    { &hf_ldap_not,
      { "not", "ldap.not",
        FT_UINT32, BASE_DEC, VALS(ldap_Filter_vals), 0,
        NULL, HFILL }},
    { &hf_ldap_equalityMatch,
      { "equalityMatch", "ldap.equalityMatch_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_substrings,
      { "substrings", "ldap.substrings_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubstringFilter", HFILL }},
    { &hf_ldap_greaterOrEqual,
      { "greaterOrEqual", "ldap.greaterOrEqual_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_lessOrEqual,
      { "lessOrEqual", "ldap.lessOrEqual_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_present,
      { "present", "ldap.present",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_approxMatch,
      { "approxMatch", "ldap.approxMatch_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_extensibleMatch,
      { "extensibleMatch", "ldap.extensibleMatch_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_substringFilter_substrings,
      { "substrings", "ldap.substrings",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_substringFilter_substrings", HFILL }},
    { &hf_ldap_substringFilter_substrings_item,
      { "substrings item", "ldap.substrings_item",
        FT_UINT32, BASE_DEC, VALS(ldap_T_substringFilter_substrings_item_vals), 0,
        "T_substringFilter_substrings_item", HFILL }},
    { &hf_ldap_initial,
      { "initial", "ldap.initial",
        FT_STRING, BASE_NONE, NULL, 0,
        "LDAPString", HFILL }},
    { &hf_ldap_any,
      { "any", "ldap.any",
        FT_STRING, BASE_NONE, NULL, 0,
        "LDAPString", HFILL }},
    { &hf_ldap_final,
      { "final", "ldap.final",
        FT_STRING, BASE_NONE, NULL, 0,
        "LDAPString", HFILL }},
    { &hf_ldap_matchingRule,
      { "matchingRule", "ldap.matchingRule",
        FT_STRING, BASE_NONE, NULL, 0,
        "MatchingRuleId", HFILL }},
    { &hf_ldap_matchValue,
      { "matchValue", "ldap.matchValue",
        FT_STRING, BASE_NONE, NULL, 0,
        "AssertionValue", HFILL }},
    { &hf_ldap_dnAttributes,
      { "dnAttributes", "ldap.dnAttributes",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_objectName,
      { "objectName", "ldap.objectName",
        FT_STRING, BASE_NONE, NULL, 0,
        "LDAPDN", HFILL }},
    { &hf_ldap_searchResultEntry_attributes,
      { "attributes", "ldap.attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PartialAttributeList", HFILL }},
    { &hf_ldap_PartialAttributeList_item,
      { "PartialAttributeList item", "ldap.PartialAttributeList_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap__untag_item,
      { "LDAPURL", "ldap.LDAPURL",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_object,
      { "object", "ldap.object",
        FT_STRING, BASE_NONE, NULL, 0,
        "LDAPDN", HFILL }},
    { &hf_ldap_modifyRequest_modification,
      { "modification", "ldap.modification",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ModifyRequest_modification", HFILL }},
    { &hf_ldap_modifyRequest_modification_item,
      { "modification item", "ldap.modification_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_modifyRequest_modification_item", HFILL }},
    { &hf_ldap_operation,
      { "operation", "ldap.operation",
        FT_UINT32, BASE_DEC, VALS(ldap_T_operation_vals), 0,
        NULL, HFILL }},
    { &hf_ldap_modification,
      { "modification", "ldap.modification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeTypeAndValues", HFILL }},
    { &hf_ldap_entry,
      { "entry", "ldap.entry",
        FT_STRING, BASE_NONE, NULL, 0,
        "LDAPDN", HFILL }},
    { &hf_ldap_attributes,
      { "attributes", "ldap.attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AttributeList", HFILL }},
    { &hf_ldap_AttributeList_item,
      { "AttributeList item", "ldap.AttributeList_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_newrdn,
      { "newrdn", "ldap.newrdn",
        FT_STRING, BASE_NONE, NULL, 0,
        "RelativeLDAPDN", HFILL }},
    { &hf_ldap_deleteoldrdn,
      { "deleteoldrdn", "ldap.deleteoldrdn",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ldap_newSuperior,
      { "newSuperior", "ldap.newSuperior",
        FT_STRING, BASE_NONE, NULL, 0,
        "LDAPDN", HFILL }},
    { &hf_ldap_ava,
      { "ava", "ldap.ava_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeValueAssertion", HFILL }},
    { &hf_ldap_requestName,
      { "requestName", "ldap.requestName",
        FT_STRING, BASE_NONE, NULL, 0,
        "LDAPOID", HFILL }},
    { &hf_ldap_requestValue,
      { "requestValue", "ldap.requestValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_extendedResponse_resultCode,
      { "resultCode", "ldap.resultCode",
        FT_UINT32, BASE_DEC, VALS(ldap_ExtendedResponse_resultCode_vals), 0,
        "ExtendedResponse_resultCode", HFILL }},
    { &hf_ldap_responseName,
      { "responseName", "ldap.responseName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_response,
      { "response", "ldap.response",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_ldap_intermediateResponse_responseValue,
      { "responseValue", "ldap.responseValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_intermediateResponse_responseValue", HFILL }},
    { &hf_ldap_size,
      { "size", "ldap.size",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ldap_cookie,
      { "cookie", "ldap.cookie",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_ldap_SortKeyList_item,
      { "SortKeyList item", "ldap.SortKeyList_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_attributeType,
      { "attributeType", "ldap.attributeType",
        FT_STRING, BASE_NONE, NULL, 0,
        "AttributeDescription", HFILL }},
    { &hf_ldap_orderingRule,
      { "orderingRule", "ldap.orderingRule",
        FT_STRING, BASE_NONE, NULL, 0,
        "MatchingRuleId", HFILL }},
    { &hf_ldap_reverseOrder,
      { "reverseOrder", "ldap.reverseOrder",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ldap_sortResult,
      { "sortResult", "ldap.sortResult",
        FT_UINT32, BASE_DEC, VALS(ldap_T_sortResult_vals), 0,
        NULL, HFILL }},
    { &hf_ldap_flags,
      { "flags", "ldap.flags",
        FT_UINT32, BASE_HEX, NULL, 0,
        "DirSyncFlags", HFILL }},
    { &hf_ldap_maxBytes,
      { "maxBytes", "ldap.maxBytes",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ldap_userIdentity,
      { "userIdentity", "ldap.userIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_ldap_oldPasswd,
      { "oldPasswd", "ldap.oldPasswd",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_ldap_newPasswd,
      { "newPasswd", "ldap.newPasswd",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_ldap_cancelID,
      { "cancelID", "ldap.cancelID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MessageID", HFILL }},
    { &hf_ldap_mode,
      { "mode", "ldap.mode",
        FT_UINT32, BASE_DEC, VALS(ldap_T_mode_vals), 0,
        NULL, HFILL }},
    { &hf_ldap_reloadHint,
      { "reloadHint", "ldap.reloadHint",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ldap_state,
      { "state", "ldap.state",
        FT_UINT32, BASE_DEC, VALS(ldap_T_state_vals), 0,
        NULL, HFILL }},
    { &hf_ldap_entryUUID,
      { "entryUUID", "ldap.entryUUID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "SyncUUID", HFILL }},
    { &hf_ldap_refreshDeletes,
      { "refreshDeletes", "ldap.refreshDeletes",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ldap_newcookie,
      { "newcookie", "ldap.newcookie",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_ldap_refreshDelete,
      { "refreshDelete", "ldap.refreshDelete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_refreshDone,
      { "refreshDone", "ldap.refreshDone",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ldap_refreshPresent,
      { "refreshPresent", "ldap.refreshPresent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_syncIdSet,
      { "syncIdSet", "ldap.syncIdSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_syncUUIDs,
      { "syncUUIDs", "ldap.syncUUIDs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_SyncUUID", HFILL }},
    { &hf_ldap_syncUUIDs_item,
      { "SyncUUID", "ldap.SyncUUID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_warning,
      { "warning", "ldap.warning",
        FT_UINT32, BASE_DEC, VALS(ldap_T_warning_vals), 0,
        NULL, HFILL }},
    { &hf_ldap_timeBeforeExpiration,
      { "timeBeforeExpiration", "ldap.timeBeforeExpiration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_maxInt", HFILL }},
    { &hf_ldap_graceAuthNsRemaining,
      { "graceAuthNsRemaining", "ldap.graceAuthNsRemaining",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_maxInt", HFILL }},
    { &hf_ldap_error,
      { "error", "ldap.error",
        FT_UINT32, BASE_DEC, VALS(ldap_T_error_vals), 0,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_ldap,
    &ett_ldap_payload,
    &ett_ldap_sasl_blob,
    &ett_ldap_msg,
    &ett_mscldap_netlogon_flags,
    &ett_mscldap_ntver_flags,
    &ett_mscldap_ipdetails,
    &ett_ldap_DirSyncFlagsSubEntry,

    &ett_ldap_LDAPMessage,
    &ett_ldap_ProtocolOp,
    &ett_ldap_AttributeDescriptionList,
    &ett_ldap_AttributeValueAssertion,
    &ett_ldap_Attribute,
    &ett_ldap_SET_OF_AttributeValue,
    &ett_ldap_LDAPResult,
    &ett_ldap_Referral,
    &ett_ldap_Controls,
    &ett_ldap_Control,
    &ett_ldap_BindRequest_U,
    &ett_ldap_AuthenticationChoice,
    &ett_ldap_SaslCredentials,
    &ett_ldap_BindResponse_U,
    &ett_ldap_SearchRequest_U,
    &ett_ldap_Filter,
    &ett_ldap_T_and,
    &ett_ldap_T_or,
    &ett_ldap_SubstringFilter,
    &ett_ldap_T_substringFilter_substrings,
    &ett_ldap_T_substringFilter_substrings_item,
    &ett_ldap_MatchingRuleAssertion,
    &ett_ldap_SearchResultEntry_U,
    &ett_ldap_PartialAttributeList,
    &ett_ldap_PartialAttributeList_item,
    &ett_ldap_SEQUENCE_OF_LDAPURL,
    &ett_ldap_ModifyRequest_U,
    &ett_ldap_ModifyRequest_modification,
    &ett_ldap_T_modifyRequest_modification_item,
    &ett_ldap_AttributeTypeAndValues,
    &ett_ldap_AddRequest_U,
    &ett_ldap_AttributeList,
    &ett_ldap_AttributeList_item,
    &ett_ldap_ModifyDNRequest_U,
    &ett_ldap_CompareRequest_U,
    &ett_ldap_ExtendedRequest_U,
    &ett_ldap_ExtendedResponse_U,
    &ett_ldap_IntermediateResponse_U,
    &ett_ldap_SearchControlValue,
    &ett_ldap_SortKeyList,
    &ett_ldap_SortKeyList_item,
    &ett_ldap_SortResult,
    &ett_ldap_DirSyncControlValue,
    &ett_ldap_PasswdModifyRequestValue,
    &ett_ldap_CancelRequestValue,
    &ett_ldap_SyncRequestValue,
    &ett_ldap_SyncStateValue,
    &ett_ldap_SyncDoneValue,
    &ett_ldap_SyncInfoValue,
    &ett_ldap_T_refreshDelete,
    &ett_ldap_T_refreshPresent,
    &ett_ldap_T_syncIdSet,
    &ett_ldap_SET_OF_SyncUUID,
    &ett_ldap_PasswordPolicyResponseValue,
    &ett_ldap_T_warning,
  };
  /* UAT for header fields */
  static uat_field_t custom_attribute_types_uat_fields[] = {
     UAT_FLD_CSTRING(attribute_types, attribute_type, "Attribute type", "Attribute type"),
     UAT_FLD_CSTRING(attribute_types, attribute_desc, "Description", "Description of the value matching type"),
     UAT_END_FIELDS
  };

  static ei_register_info ei[] = {
     { &ei_ldap_exceeded_filter_length, { "ldap.exceeded_filter_length", PI_UNDECODED, PI_ERROR, "Filter length exceeds number. Giving up", EXPFILL }},
     { &ei_ldap_too_many_filter_elements, { "ldap.too_many_filter_elements", PI_UNDECODED, PI_ERROR, "Found more than %%u filter elements. Giving up.", EXPFILL }},
  };

  expert_module_t* expert_ldap;
  module_t *ldap_module;
  uat_t *attributes_uat;

  /* Register protocol */
  proto_ldap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_ldap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_ldap = expert_register_protocol(proto_ldap);
  expert_register_field_array(expert_ldap, ei, array_length(ei));

  ldap_handle = register_dissector("ldap", dissect_ldap_tcp, proto_ldap);

  ldap_module = prefs_register_protocol(proto_ldap, prefs_register_ldap);
  prefs_register_bool_preference(ldap_module, "desegment_ldap_messages",
    "Reassemble LDAP messages spanning multiple TCP segments",
    "Whether the LDAP dissector should reassemble messages spanning multiple TCP segments."
    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &ldap_desegment);

  prefs_register_uint_preference(ldap_module, "tls.port", "LDAPS TCP Port",
                                 "Set the port for LDAP operations over TLS",
                                 10, &global_ldaps_tcp_port);
  prefs_register_obsolete_preference(ldap_module, "ssl.port");
  /* UAT */
  attributes_uat = uat_new("Custom LDAP AttributeValue types",
                           sizeof(attribute_type_t),
                           "custom_ldap_attribute_types",
                           true,
                           &attribute_types,
                           &num_attribute_types,
                           /* specifies named fields, so affects dissection
                              and the set of named fields */
                           UAT_AFFECTS_DISSECTION|UAT_AFFECTS_FIELDS,
                           NULL,
                           attribute_types_copy_cb,
                           attribute_types_update_cb,
                           attribute_types_free_cb,
                           attribute_types_post_update_cb,
                           attribute_types_reset_cb,
                           custom_attribute_types_uat_fields);

  prefs_register_uat_preference(ldap_module, "custom_ldap_attribute_types",
                                "Custom AttributeValue types",
                                "A table to define custom LDAP attribute type values for which fields can be setup and used for filtering/data extraction etc.",
                                attributes_uat);

  prefs_register_obsolete_preference(ldap_module, "max_pdu");

  proto_cldap = proto_register_protocol("Connectionless Lightweight Directory Access Protocol", "CLDAP", "cldap");
  cldap_handle = register_dissector("cldap", dissect_mscldap, proto_cldap);

  ldap_tap=register_tap("ldap");

  ldap_name_dissector_table = register_dissector_table("ldap.name", "LDAP Attribute Type Dissectors", proto_cldap, FT_STRING, STRING_CASE_INSENSITIVE);

  register_srt_table(proto_ldap, NULL, 1, ldapstat_packet, ldapstat_init, NULL);
}


/*--- proto_reg_handoff_ldap ---------------------------------------*/
void
proto_reg_handoff_ldap(void)
{
  dissector_add_uint_with_preference("udp.port", UDP_PORT_CLDAP, cldap_handle);

  gssapi_handle = find_dissector_add_dependency("gssapi", proto_ldap);
  gssapi_wrap_handle = find_dissector_add_dependency("gssapi_verf", proto_ldap);
  spnego_handle = find_dissector_add_dependency("spnego", proto_ldap);

  ntlmssp_handle = find_dissector_add_dependency("ntlmssp", proto_ldap);

  tls_handle = find_dissector_add_dependency("tls", proto_ldap);

  prefs_register_ldap();

  oid_add_from_string("ISO assigned OIDs, USA",                                                     "1.2.840");

/*  http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dsml/dsml/ldap_controls_and_session_support.asp */
/*  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c5e87db-4728-4f29-b164-01dd7d7391ea */
  oid_add_from_string("LDAP_PAGED_RESULT_OID_STRING","1.2.840.113556.1.4.319");
  oid_add_from_string("LDAP_SERVER_SHOW_DELETED_OID","1.2.840.113556.1.4.417");
  oid_add_from_string("LDAP_SERVER_SORT_OID","1.2.840.113556.1.4.473");
  oid_add_from_string("LDAP_SERVER_RESP_SORT_OID","1.2.840.113556.1.4.474");
  oid_add_from_string("LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID","1.2.840.113556.1.4.521");
  oid_add_from_string("LDAP_SERVER_NOTIFICATION_OID","1.2.840.113556.1.4.528");
  oid_add_from_string("LDAP_SERVER_EXTENDED_DN_OID","1.2.840.113556.1.4.529");
  oid_add_from_string("meetingAdvertiseScope","1.2.840.113556.1.4.582");
  oid_add_from_string("LDAP_SERVER_LAZY_COMMIT_OID","1.2.840.113556.1.4.619");
  oid_add_from_string("mhsORAddress","1.2.840.113556.1.4.650");
  oid_add_from_string("managedObjects","1.2.840.113556.1.4.654");
  oid_add_from_string("LDAP_CAP_ACTIVE_DIRECTORY_OID","1.2.840.113556.1.4.800");
  oid_add_from_string("LDAP_SERVER_SD_FLAGS_OID","1.2.840.113556.1.4.801");
  oid_add_from_string("LDAP_SERVER_RANGE_OPTION_OID","1.2.840.113556.1.4.802");
  oid_add_from_string("LDAP_MATCHING_RULE_BIT_AND", "1.2.840.113556.1.4.803");
  oid_add_from_string("LDAP_MATCHING_RULE_BIT_OR","1.2.840.113556.1.4.804");
  oid_add_from_string("LDAP_SERVER_TREE_DELETE_OID","1.2.840.113556.1.4.805");
  oid_add_from_string("LDAP_SERVER_DIRSYNC_OID","1.2.840.113556.1.4.841");
  oid_add_from_string("LDAP_SERVER_GET_STATS_OID","1.2.840.113556.1.4.970");
  oid_add_from_string("LDAP_SERVER_VERIFY_NAME_OID","1.2.840.113556.1.4.1338");
  oid_add_from_string("LDAP_SERVER_DOMAIN_SCOPE_OID","1.2.840.113556.1.4.1339");
  oid_add_from_string("LDAP_SERVER_SEARCH_OPTIONS_OID","1.2.840.113556.1.4.1340");
  oid_add_from_string("LDAP_SERVER_RODC_DCPROMO_OID","1.2.840.113556.1.4.1341");
  oid_add_from_string("LDAP_SERVER_PERMISSIVE_MODIFY_OID","1.2.840.113556.1.4.1413");
  oid_add_from_string("LDAP_SERVER_ASQ_OID","1.2.840.113556.1.4.1504");
  oid_add_from_string("LDAP_CAP_ACTIVE_DIRECTORY_V51_OID","1.2.840.113556.1.4.1670");
  oid_add_from_string("msDS-SDReferenceDomain","1.2.840.113556.1.4.1711");
  oid_add_from_string("msDS-AdditionalDnsHostName","1.2.840.113556.1.4.1717");
  oid_add_from_string("LDAP_SERVER_FAST_BIND_OID","1.2.840.113556.1.4.1781");
  oid_add_from_string("LDAP_CAP_ACTIVE_DIRECTORY_LDAP_INTEG_OID","1.2.840.113556.1.4.1791");
  oid_add_from_string("msDS-ObjectReference","1.2.840.113556.1.4.1840");
  oid_add_from_string("msDS-QuotaEffective","1.2.840.113556.1.4.1848");
  oid_add_from_string("LDAP_CAP_ACTIVE_DIRECTORY_ADAM_OID","1.2.840.113556.1.4.1851");
  oid_add_from_string("LDAP_SERVER_QUOTA_CONTROL_OID","1.2.840.113556.1.4.1852");
  oid_add_from_string("msDS-PortSSL","1.2.840.113556.1.4.1860");
  oid_add_from_string("LDAP_CAP_ACTIVE_DIRECTORY_ADAM_DIGEST_OID", "1.2.840.113556.1.4.1880");
  oid_add_from_string("LDAP_SERVER_SHUTDOWN_NOTIFY_OID","1.2.840.113556.1.4.1907");
  oid_add_from_string("LDAP_CAP_ACTIVE_DIRECTORY_PARTIAL_SECRETS_OID", "1.2.840.113556.1.4.1920");
  oid_add_from_string("LDAP_CAP_ACTIVE_DIRECTORY_V60_OID", "1.2.840.113556.1.4.1935");
  oid_add_from_string("LDAP_MATCHING_RULE_TRANSITIVE_EVAL", "1.2.840.113556.1.4.1941");
  oid_add_from_string("LDAP_SERVER_RANGE_RETRIEVAL_NOERR_OID","1.2.840.113556.1.4.1948");
  oid_add_from_string("msDS-isRODC","1.2.840.113556.1.4.1960");
  oid_add_from_string("LDAP_SERVER_FORCE_UPDATE_OID","1.2.840.113556.1.4.1974");
  oid_add_from_string("LDAP_SERVER_DN_INPUT_OID","1.2.840.113556.1.4.2026");
  oid_add_from_string("LDAP_SERVER_SHOW_RECYCLED_OID","1.2.840.113556.1.4.2064");
  oid_add_from_string("LDAP_SERVER_SHOW_DEACTIVATED_LINK_OID","1.2.840.113556.1.4.2065");
  oid_add_from_string("LDAP_SERVER_POLICY_HINTS_DEPRECATED_OID","1.2.840.113556.1.4.2066");
  oid_add_from_string("LDAP_CAP_ACTIVE_DIRECTORY_V61_R2_OID", "1.2.840.113556.1.4.2080");
  oid_add_from_string("LDAP_SERVER_DIRSYNC_EX_OID","1.2.840.113556.1.4.2090");
  oid_add_from_string("LDAP_SERVER_TREE_DELETE_EX_OID","1.2.840.113556.1.4.2204");
  oid_add_from_string("LDAP_SERVER_UPDATE_STATS_OID","1.2.840.113556.1.4.2205");
  oid_add_from_string("LDAP_SERVER_SEARCH_HINTS_OID","1.2.840.113556.1.4.2206");
  oid_add_from_string("LDAP_SERVER_EXPECTED_ENTRY_COUNT_OID","1.2.840.113556.1.4.2211");
  oid_add_from_string("LDAP_SERVER_BATCH_REQUEST_OID", "1.2.840.113556.1.4.2212");
  oid_add_from_string("LDAP_CAP_ACTIVE_DIRECTORY_W8_OID", "1.2.840.113556.1.4.2237");
  oid_add_from_string("LDAP_SERVER_POLICY_HINTS_OID","1.2.840.113556.1.4.2239");
  oid_add_from_string("LDAP_MATCHING_RULE_DN_WITH_DATA", "1.2.840.113556.1.4.2253");
  oid_add_from_string("LDAP_SERVER_SET_OWNER_OID","1.2.840.113556.1.4.2255");
  oid_add_from_string("LDAP_SERVER_BYPASS_QUOTA_OID","1.2.840.113556.1.4.2256");
  oid_add_from_string("LDAP_SERVER_LINK_TTL_OID","1.2.840.113556.1.4.2309");
  oid_add_from_string("LDAP_SERVER_SET_CORRELATION_ID_OID","1.2.840.113556.1.4.2330");
  oid_add_from_string("LDAP_SERVER_THREAD_TRACE_OVERRIDE_OID","1.2.840.113556.1.4.2354");

  /* RFC4532 */
  oid_add_from_string("LDAP_SERVER_WHO_AM_I_OID", "1.3.6.1.4.1.4203.1.11.3");

  /* Mark Wahl (Critical Angle) */
  oid_add_from_string("DYNAMIC_REFRESH","1.3.6.1.4.1.1466.101.119.1");
  oid_add_from_string("LDAP_START_TLS_OID","1.3.6.1.4.1.1466.20037");

  oid_add_from_string("inetOrgPerson", "2.16.840.1.113730.3.2.2");
  /* RFC2798 */
  oid_add_from_string("US company arc",                                                             "2.16.840.1");

  /* http://www.alvestrand.no/objectid/2.16.840.1.113730.3.4.html */
  oid_add_from_string("Manage DSA IT LDAPv3 control",                                               "2.16.840.1.113730.3.4.2");
  oid_add_from_string("Persistent Search LDAPv3 control",                                           "2.16.840.1.113730.3.4.3");
  oid_add_from_string("Netscape Password Expired LDAPv3 control",                                   "2.16.840.1.113730.3.4.4");
  oid_add_from_string("Netscape Password Expiring LDAPv3 control",                                  "2.16.840.1.113730.3.4.5");
  oid_add_from_string("Netscape NT Synchronization Client LDAPv3 control",                          "2.16.840.1.113730.3.4.6");
  oid_add_from_string("Entry Change Notification LDAPv3 control",                                   "2.16.840.1.113730.3.4.7");
  oid_add_from_string("Transaction ID Request Control",                                             "2.16.840.1.113730.3.4.8");
  oid_add_from_string("VLV Request LDAPv3 control",                                                 "2.16.840.1.113730.3.4.9");
  oid_add_from_string("VLV Response LDAPv3 control",                                                "2.16.840.1.113730.3.4.10");
  oid_add_from_string("Transaction ID Response Control",                                            "2.16.840.1.113730.3.4.11");
  oid_add_from_string("Proxied Authorization (version 1) control",                                  "2.16.840.1.113730.3.4.12");
  oid_add_from_string("iPlanet Directory Server Replication Update Information Control",            "2.16.840.1.113730.3.4.13");
  oid_add_from_string("iPlanet Directory Server search on specific backend control",                "2.16.840.1.113730.3.4.14");
  oid_add_from_string("Authentication Response Control",                                            "2.16.840.1.113730.3.4.15");
  oid_add_from_string("Authentication Request Control",                                             "2.16.840.1.113730.3.4.16");
  oid_add_from_string("Real Attributes Only Request Control",                                       "2.16.840.1.113730.3.4.17");
  oid_add_from_string("Proxied Authorization (version 2) Control",                                  "2.16.840.1.113730.3.4.18");
  oid_add_from_string("Chaining loop detection",                                                    "2.16.840.1.113730.3.4.19");
  oid_add_from_string("iPlanet Replication Modrdn Extra Mods Control",                              "2.16.840.1.113730.3.4.999");


  dissector_add_string("ldap.name", "netlogon", create_dissector_handle(dissect_NetLogon_PDU, proto_cldap));
  dissector_add_string("ldap.name", "objectGUID", create_dissector_handle(dissect_ldap_guid, proto_ldap));
  dissector_add_string("ldap.name", "supportedControl", create_dissector_handle(dissect_ldap_oid, proto_ldap));
  dissector_add_string("ldap.name", "supportedCapabilities", create_dissector_handle(dissect_ldap_oid, proto_ldap));
  dissector_add_string("ldap.name", "objectSid", create_dissector_handle(dissect_ldap_sid, proto_ldap));
  dissector_add_string("ldap.name", "nTSecurityDescriptor", create_dissector_handle(dissect_ldap_nt_sec_desc, proto_ldap));

  register_ber_oid_dissector("1.2.840.113556.1.4.319", dissect_SearchControlValue_PDU, proto_ldap, "LDAP_PAGED_RESULT_OID_STRING");
  register_ber_oid_dissector("1.2.840.113556.1.4.473", dissect_SortKeyList_PDU, proto_ldap, "LDAP_SERVER_SORT_OID");
  register_ber_oid_dissector("1.2.840.113556.1.4.474", dissect_SortResult_PDU, proto_ldap, "LDAP_SERVER_RESP_SORT_OID");
  register_ber_oid_dissector("1.2.840.113556.1.4.841", dissect_DirSyncControlValue_PDU, proto_ldap, "LDAP_SERVER_DIRSYNC_OID");
  register_ber_oid_dissector("1.3.6.1.4.1.4203.1.11.1", dissect_PasswdModifyRequestValue_PDU, proto_ldap, "passwdModifyOID");
  register_ber_oid_dissector("1.3.6.1.1.8", dissect_CancelRequestValue_PDU, proto_ldap, "cancelRequestOID");
  register_ber_oid_dissector("1.3.6.1.4.1.4203.1.9.1.1", dissect_SyncRequestValue_PDU, proto_ldap, "syncRequestOID");
  register_ber_oid_dissector("1.3.6.1.4.1.4203.1.9.1.2", dissect_SyncStateValue_PDU, proto_ldap, "syncStateOID");
  register_ber_oid_dissector("1.3.6.1.4.1.4203.1.9.1.3", dissect_SyncDoneValue_PDU, proto_ldap, "syncDoneOID");
  register_ber_oid_dissector("1.3.6.1.4.1.4203.1.9.1.4", dissect_SyncInfoValue_PDU, proto_ldap, "syncInfoOID");
  register_ber_oid_dissector("1.3.6.1.4.1.42.2.27.8.5.1", dissect_PasswordPolicyResponseValue_PDU, proto_ldap, "passwordPolicy");


 dissector_add_uint_range_with_preference("tcp.port", TCP_PORT_RANGE_LDAP, ldap_handle);

 dissector_add_uint("acdr.tls_application_port", 636, ldap_handle);
 dissector_add_uint("acdr.tls_application", TLS_APP_LDAP, ldap_handle);
}

static void
prefs_register_ldap(void)
{
  if(ssl_port != global_ldaps_tcp_port) {
    if(ssl_port)
      ssl_dissector_delete(ssl_port, ldap_handle);

    /* Set our port number for future use */
    ssl_port = global_ldaps_tcp_port;

    if(ssl_port)
      ssl_dissector_add(ssl_port, ldap_handle);
  }

}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
