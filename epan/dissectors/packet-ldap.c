/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-ldap.c                                                              */
/* ../../tools/asn2wrs.py -b -p ldap -c ./ldap.cnf -s ./packet-ldap-template -D . -O ../../epan/dissectors Lightweight-Directory-Access-Protocol-V3.asn */

/* Input file: packet-ldap-template.c */

#line 1 "../../asn1/ldap/packet-ldap-template.c"
/* packet-ldap.c
 * Routines for ldap packet dissection
 *
 * See RFC 1777 (LDAP v2), RFC 2251 (LDAP v3), and RFC 2222 (SASL).
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

/*
 * This is not a complete implementation. It doesn't handle the full version 3, more specifically,
 * it handles only the commands of version 2, but any additional characteristics of the ver3 command are supported.
 * It's also missing extensible search filters.
 *
 * There should probably be alot more error checking, I simply assume that if we have a full packet, it will be a complete
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
 *				Updated cldap_netlogon_flags to include Windows 2008 flags
 *				Expanded the ntver ldap option with bit field
 *
 * Gary Reynolds <gazzadownunder@yahoo.co.uk>
 */

/*
 * 09-DEC-2009 - Added support for RFC4533
 *               Content Synchronization Operation (aka syncrepl)
 * 11-DEC-2009 - Added support for IntermediateResponse (LDAP v3 from RFC 4511)
 * Mathieu Parent <math.parent@gmail.com>
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <ctype.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/emem.h>
#include <epan/oids.h>
#include <epan/strutil.h>
#include <epan/dissectors/packet-frame.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/dissectors/packet-windows-common.h>
#include <epan/dissectors/packet-dcerpc.h>
#include <epan/asn1.h>
#include <epan/expert.h>

#include "packet-ldap.h"
#include "packet-ntlmssp.h"
#include "packet-ssl.h"
#include "packet-smb-common.h"

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-dns.h"

#define PNAME  "Lightweight Directory Access Protocol"
#define PSNAME "LDAP"
#define PFNAME "ldap"

/* Initialize the protocol and registered fields */
static int ldap_tap = -1;
static int proto_ldap = -1;
static int proto_cldap = -1;

static int hf_ldap_sasl_buffer_length = -1;
static int hf_ldap_response_in = -1;
static int hf_ldap_response_to = -1;
static int hf_ldap_time = -1;
static int hf_ldap_guid = -1;

static int hf_mscldap_ntver_flags = -1;
static int hf_mscldap_ntver_flags_v1 = -1;
static int hf_mscldap_ntver_flags_v5 = -1;
static int hf_mscldap_ntver_flags_v5ex = -1;
static int hf_mscldap_ntver_flags_v5ep = -1;
static int hf_mscldap_ntver_flags_vcs = -1;
static int hf_mscldap_ntver_flags_vnt4 = -1;
static int hf_mscldap_ntver_flags_vpdc = -1;
static int hf_mscldap_ntver_flags_vip = -1;
static int hf_mscldap_ntver_flags_vl = -1;
static int hf_mscldap_ntver_flags_vgc = -1;

static int hf_mscldap_netlogon_ipaddress_family = -1;
static int hf_mscldap_netlogon_ipaddress_port = -1;
static int hf_mscldap_netlogon_ipaddress = -1;
static int hf_mscldap_netlogon_ipaddress_ipv4 = -1;
static int hf_mscldap_netlogon_opcode = -1;
static int hf_mscldap_netlogon_flags = -1;
static int hf_mscldap_netlogon_flags_pdc = -1;
static int hf_mscldap_netlogon_flags_gc = -1;
static int hf_mscldap_netlogon_flags_ldap = -1;
static int hf_mscldap_netlogon_flags_ds = -1;
static int hf_mscldap_netlogon_flags_kdc = -1;
static int hf_mscldap_netlogon_flags_timeserv = -1;
static int hf_mscldap_netlogon_flags_closest = -1;
static int hf_mscldap_netlogon_flags_writable = -1;
static int hf_mscldap_netlogon_flags_good_timeserv = -1;
static int hf_mscldap_netlogon_flags_ndnc = -1;
static int hf_mscldap_netlogon_flags_fnc = -1;
static int hf_mscldap_netlogon_flags_dnc = -1;
static int hf_mscldap_netlogon_flags_dns = -1;
static int hf_mscldap_netlogon_flags_wdc = -1;
static int hf_mscldap_netlogon_flags_rodc = -1;
static int hf_mscldap_domain_guid = -1;
static int hf_mscldap_forest = -1;
static int hf_mscldap_domain = -1;
static int hf_mscldap_hostname = -1;
static int hf_mscldap_nb_domain = -1;
static int hf_mscldap_nb_hostname = -1;
static int hf_mscldap_username = -1;
static int hf_mscldap_sitename = -1;
static int hf_mscldap_clientsitename = -1;
static int hf_mscldap_netlogon_lm_token = -1;
static int hf_mscldap_netlogon_nt_token = -1;
static int hf_ldap_sid = -1;
static int hf_ldap_AccessMask_ADS_CREATE_CHILD = -1;
static int hf_ldap_AccessMask_ADS_DELETE_CHILD = -1;
static int hf_ldap_AccessMask_ADS_LIST = -1;
static int hf_ldap_AccessMask_ADS_SELF_WRITE = -1;
static int hf_ldap_AccessMask_ADS_READ_PROP = -1;
static int hf_ldap_AccessMask_ADS_WRITE_PROP = -1;
static int hf_ldap_AccessMask_ADS_DELETE_TREE = -1;
static int hf_ldap_AccessMask_ADS_LIST_OBJECT = -1;
static int hf_ldap_AccessMask_ADS_CONTROL_ACCESS = -1;


/*--- Included file: packet-ldap-hf.c ---*/
#line 1 "../../asn1/ldap/packet-ldap-hf.c"
static int hf_ldap_LDAPMessage_PDU = -1;          /* LDAPMessage */
static int hf_ldap_SearchControlValue_PDU = -1;   /* SearchControlValue */
static int hf_ldap_SortKeyList_PDU = -1;          /* SortKeyList */
static int hf_ldap_SortResult_PDU = -1;           /* SortResult */
static int hf_ldap_DirSyncControlValue_PDU = -1;  /* DirSyncControlValue */
static int hf_ldap_PasswdModifyRequestValue_PDU = -1;  /* PasswdModifyRequestValue */
static int hf_ldap_CancelRequestValue_PDU = -1;   /* CancelRequestValue */
static int hf_ldap_SyncRequestValue_PDU = -1;     /* SyncRequestValue */
static int hf_ldap_SyncStateValue_PDU = -1;       /* SyncStateValue */
static int hf_ldap_SyncDoneValue_PDU = -1;        /* SyncDoneValue */
static int hf_ldap_SyncInfoValue_PDU = -1;        /* SyncInfoValue */
static int hf_ldap_PasswordPolicyResponseValue_PDU = -1;  /* PasswordPolicyResponseValue */
static int hf_ldap_messageID = -1;                /* MessageID */
static int hf_ldap_protocolOp = -1;               /* ProtocolOp */
static int hf_ldap_controls = -1;                 /* Controls */
static int hf_ldap_bindRequest = -1;              /* BindRequest */
static int hf_ldap_bindResponse = -1;             /* BindResponse */
static int hf_ldap_unbindRequest = -1;            /* UnbindRequest */
static int hf_ldap_searchRequest = -1;            /* SearchRequest */
static int hf_ldap_searchResEntry = -1;           /* SearchResultEntry */
static int hf_ldap_searchResDone = -1;            /* SearchResultDone */
static int hf_ldap_searchResRef = -1;             /* SearchResultReference */
static int hf_ldap_modifyRequest = -1;            /* ModifyRequest */
static int hf_ldap_modifyResponse = -1;           /* ModifyResponse */
static int hf_ldap_addRequest = -1;               /* AddRequest */
static int hf_ldap_addResponse = -1;              /* AddResponse */
static int hf_ldap_delRequest = -1;               /* DelRequest */
static int hf_ldap_delResponse = -1;              /* DelResponse */
static int hf_ldap_modDNRequest = -1;             /* ModifyDNRequest */
static int hf_ldap_modDNResponse = -1;            /* ModifyDNResponse */
static int hf_ldap_compareRequest = -1;           /* CompareRequest */
static int hf_ldap_compareResponse = -1;          /* CompareResponse */
static int hf_ldap_abandonRequest = -1;           /* AbandonRequest */
static int hf_ldap_extendedReq = -1;              /* ExtendedRequest */
static int hf_ldap_extendedResp = -1;             /* ExtendedResponse */
static int hf_ldap_intermediateResponse = -1;     /* IntermediateResponse */
static int hf_ldap_AttributeDescriptionList_item = -1;  /* AttributeDescription */
static int hf_ldap_attributeDesc = -1;            /* AttributeDescription */
static int hf_ldap_assertionValue = -1;           /* AssertionValue */
static int hf_ldap_type = -1;                     /* AttributeDescription */
static int hf_ldap_vals = -1;                     /* SET_OF_AttributeValue */
static int hf_ldap_vals_item = -1;                /* AttributeValue */
static int hf_ldap_resultCode = -1;               /* T_resultCode */
static int hf_ldap_matchedDN = -1;                /* LDAPDN */
static int hf_ldap_errorMessage = -1;             /* ErrorMessage */
static int hf_ldap_referral = -1;                 /* Referral */
static int hf_ldap_Referral_item = -1;            /* LDAPURL */
static int hf_ldap_Controls_item = -1;            /* Control */
static int hf_ldap_controlType = -1;              /* ControlType */
static int hf_ldap_criticality = -1;              /* BOOLEAN */
static int hf_ldap_controlValue = -1;             /* T_controlValue */
static int hf_ldap_version = -1;                  /* INTEGER_1_127 */
static int hf_ldap_name = -1;                     /* LDAPDN */
static int hf_ldap_authentication = -1;           /* AuthenticationChoice */
static int hf_ldap_simple = -1;                   /* Simple */
static int hf_ldap_sasl = -1;                     /* SaslCredentials */
static int hf_ldap_ntlmsspNegotiate = -1;         /* T_ntlmsspNegotiate */
static int hf_ldap_ntlmsspAuth = -1;              /* T_ntlmsspAuth */
static int hf_ldap_mechanism = -1;                /* Mechanism */
static int hf_ldap_credentials = -1;              /* Credentials */
static int hf_ldap_bindResponse_resultCode = -1;  /* BindResponse_resultCode */
static int hf_ldap_bindResponse_matchedDN = -1;   /* T_bindResponse_matchedDN */
static int hf_ldap_serverSaslCreds = -1;          /* ServerSaslCreds */
static int hf_ldap_baseObject = -1;               /* LDAPDN */
static int hf_ldap_scope = -1;                    /* T_scope */
static int hf_ldap_derefAliases = -1;             /* T_derefAliases */
static int hf_ldap_sizeLimit = -1;                /* INTEGER_0_maxInt */
static int hf_ldap_timeLimit = -1;                /* INTEGER_0_maxInt */
static int hf_ldap_typesOnly = -1;                /* BOOLEAN */
static int hf_ldap_filter = -1;                   /* T_filter */
static int hf_ldap_searchRequest_attributes = -1;  /* AttributeDescriptionList */
static int hf_ldap_and = -1;                      /* T_and */
static int hf_ldap_and_item = -1;                 /* T_and_item */
static int hf_ldap_or = -1;                       /* T_or */
static int hf_ldap_or_item = -1;                  /* T_or_item */
static int hf_ldap_not = -1;                      /* T_not */
static int hf_ldap_equalityMatch = -1;            /* T_equalityMatch */
static int hf_ldap_substrings = -1;               /* SubstringFilter */
static int hf_ldap_greaterOrEqual = -1;           /* T_greaterOrEqual */
static int hf_ldap_lessOrEqual = -1;              /* T_lessOrEqual */
static int hf_ldap_present = -1;                  /* T_present */
static int hf_ldap_approxMatch = -1;              /* T_approxMatch */
static int hf_ldap_extensibleMatch = -1;          /* T_extensibleMatch */
static int hf_ldap_substringFilter_substrings = -1;  /* T_substringFilter_substrings */
static int hf_ldap_substringFilter_substrings_item = -1;  /* T_substringFilter_substrings_item */
static int hf_ldap_initial = -1;                  /* LDAPString */
static int hf_ldap_any = -1;                      /* LDAPString */
static int hf_ldap_final = -1;                    /* LDAPString */
static int hf_ldap_matchingRule = -1;             /* MatchingRuleId */
static int hf_ldap_matchValue = -1;               /* AssertionValue */
static int hf_ldap_dnAttributes = -1;             /* T_dnAttributes */
static int hf_ldap_objectName = -1;               /* LDAPDN */
static int hf_ldap_searchResultEntry_attributes = -1;  /* PartialAttributeList */
static int hf_ldap_PartialAttributeList_item = -1;  /* PartialAttributeList_item */
static int hf_ldap__untag_item = -1;              /* LDAPURL */
static int hf_ldap_object = -1;                   /* LDAPDN */
static int hf_ldap_modifyRequest_modification = -1;  /* ModifyRequest_modification */
static int hf_ldap_modifyRequest_modification_item = -1;  /* T_modifyRequest_modification_item */
static int hf_ldap_operation = -1;                /* T_operation */
static int hf_ldap_modification = -1;             /* AttributeTypeAndValues */
static int hf_ldap_entry = -1;                    /* LDAPDN */
static int hf_ldap_attributes = -1;               /* AttributeList */
static int hf_ldap_AttributeList_item = -1;       /* AttributeList_item */
static int hf_ldap_newrdn = -1;                   /* RelativeLDAPDN */
static int hf_ldap_deleteoldrdn = -1;             /* BOOLEAN */
static int hf_ldap_newSuperior = -1;              /* LDAPDN */
static int hf_ldap_ava = -1;                      /* AttributeValueAssertion */
static int hf_ldap_requestName = -1;              /* LDAPOID */
static int hf_ldap_requestValue = -1;             /* T_requestValue */
static int hf_ldap_extendedResponse_resultCode = -1;  /* ExtendedResponse_resultCode */
static int hf_ldap_responseName = -1;             /* ResponseName */
static int hf_ldap_response = -1;                 /* OCTET_STRING */
static int hf_ldap_intermediateResponse_responseValue = -1;  /* T_intermediateResponse_responseValue */
static int hf_ldap_size = -1;                     /* INTEGER */
static int hf_ldap_cookie = -1;                   /* OCTET_STRING */
static int hf_ldap_SortKeyList_item = -1;         /* SortKeyList_item */
static int hf_ldap_attributeType = -1;            /* AttributeDescription */
static int hf_ldap_orderingRule = -1;             /* MatchingRuleId */
static int hf_ldap_reverseOrder = -1;             /* BOOLEAN */
static int hf_ldap_sortResult = -1;               /* T_sortResult */
static int hf_ldap_value = -1;                    /* INTEGER */
static int hf_ldap_flags = -1;                    /* DirSyncFlags */
static int hf_ldap_maxBytes = -1;                 /* INTEGER */
static int hf_ldap_userIdentity = -1;             /* OCTET_STRING */
static int hf_ldap_oldPasswd = -1;                /* OCTET_STRING */
static int hf_ldap_newPasswd = -1;                /* OCTET_STRING */
static int hf_ldap_genPasswd = -1;                /* OCTET_STRING */
static int hf_ldap_cancelID = -1;                 /* MessageID */
static int hf_ldap_mode = -1;                     /* T_mode */
static int hf_ldap_reloadHint = -1;               /* BOOLEAN */
static int hf_ldap_state = -1;                    /* T_state */
static int hf_ldap_entryUUID = -1;                /* SyncUUID */
static int hf_ldap_refreshDeletes = -1;           /* BOOLEAN */
static int hf_ldap_newcookie = -1;                /* OCTET_STRING */
static int hf_ldap_refreshDelete = -1;            /* T_refreshDelete */
static int hf_ldap_refreshDone = -1;              /* BOOLEAN */
static int hf_ldap_refreshPresent = -1;           /* T_refreshPresent */
static int hf_ldap_syncIdSet = -1;                /* T_syncIdSet */
static int hf_ldap_syncUUIDs = -1;                /* SET_OF_SyncUUID */
static int hf_ldap_syncUUIDs_item = -1;           /* SyncUUID */
static int hf_ldap_warning = -1;                  /* T_warning */
static int hf_ldap_timeBeforeExpiration = -1;     /* INTEGER_0_maxInt */
static int hf_ldap_graceAuthNsRemaining = -1;     /* INTEGER_0_maxInt */
static int hf_ldap_error = -1;                    /* T_error */

/*--- End of included file: packet-ldap-hf.c ---*/
#line 188 "../../asn1/ldap/packet-ldap-template.c"

/* Initialize the subtree pointers */
static gint ett_ldap = -1;
static gint ett_ldap_msg = -1;
static gint ett_ldap_sasl_blob = -1;
static gint ett_ldap_payload = -1;
static gint ett_mscldap_netlogon_flags = -1;
static gint ett_mscldap_ntver_flags = -1;
static gint ett_mscldap_ipdetails = -1;


/*--- Included file: packet-ldap-ett.c ---*/
#line 1 "../../asn1/ldap/packet-ldap-ett.c"
static gint ett_ldap_LDAPMessage = -1;
static gint ett_ldap_ProtocolOp = -1;
static gint ett_ldap_AttributeDescriptionList = -1;
static gint ett_ldap_AttributeValueAssertion = -1;
static gint ett_ldap_Attribute = -1;
static gint ett_ldap_SET_OF_AttributeValue = -1;
static gint ett_ldap_LDAPResult = -1;
static gint ett_ldap_Referral = -1;
static gint ett_ldap_Controls = -1;
static gint ett_ldap_Control = -1;
static gint ett_ldap_BindRequest_U = -1;
static gint ett_ldap_AuthenticationChoice = -1;
static gint ett_ldap_SaslCredentials = -1;
static gint ett_ldap_BindResponse_U = -1;
static gint ett_ldap_SearchRequest_U = -1;
static gint ett_ldap_Filter = -1;
static gint ett_ldap_T_and = -1;
static gint ett_ldap_T_or = -1;
static gint ett_ldap_SubstringFilter = -1;
static gint ett_ldap_T_substringFilter_substrings = -1;
static gint ett_ldap_T_substringFilter_substrings_item = -1;
static gint ett_ldap_MatchingRuleAssertion = -1;
static gint ett_ldap_SearchResultEntry_U = -1;
static gint ett_ldap_PartialAttributeList = -1;
static gint ett_ldap_PartialAttributeList_item = -1;
static gint ett_ldap_SEQUENCE_OF_LDAPURL = -1;
static gint ett_ldap_ModifyRequest_U = -1;
static gint ett_ldap_ModifyRequest_modification = -1;
static gint ett_ldap_T_modifyRequest_modification_item = -1;
static gint ett_ldap_AttributeTypeAndValues = -1;
static gint ett_ldap_AddRequest_U = -1;
static gint ett_ldap_AttributeList = -1;
static gint ett_ldap_AttributeList_item = -1;
static gint ett_ldap_ModifyDNRequest_U = -1;
static gint ett_ldap_CompareRequest_U = -1;
static gint ett_ldap_ExtendedRequest_U = -1;
static gint ett_ldap_ExtendedResponse_U = -1;
static gint ett_ldap_IntermediateResponse_U = -1;
static gint ett_ldap_SearchControlValue = -1;
static gint ett_ldap_SortKeyList = -1;
static gint ett_ldap_SortKeyList_item = -1;
static gint ett_ldap_SortResult = -1;
static gint ett_ldap_DirSyncFlagsSubEntry = -1;
static gint ett_ldap_DirSyncControlValue = -1;
static gint ett_ldap_PasswdModifyRequestValue = -1;
static gint ett_ldap_PasswdModifyResponseValue = -1;
static gint ett_ldap_CancelRequestValue = -1;
static gint ett_ldap_SyncRequestValue = -1;
static gint ett_ldap_SyncStateValue = -1;
static gint ett_ldap_SyncDoneValue = -1;
static gint ett_ldap_SyncInfoValue = -1;
static gint ett_ldap_T_refreshDelete = -1;
static gint ett_ldap_T_refreshPresent = -1;
static gint ett_ldap_T_syncIdSet = -1;
static gint ett_ldap_SET_OF_SyncUUID = -1;
static gint ett_ldap_PasswordPolicyResponseValue = -1;
static gint ett_ldap_T_warning = -1;

/*--- End of included file: packet-ldap-ett.c ---*/
#line 199 "../../asn1/ldap/packet-ldap-template.c"

static dissector_table_t ldap_name_dissector_table=NULL;
static const char *object_identifier_id = NULL; /* LDAP OID */

static gboolean do_protocolop = FALSE;
static gchar    *attr_type = NULL;
static gboolean is_binary_attr_type = FALSE;
static gboolean ldap_found_in_frame = FALSE;

#define TCP_PORT_LDAP			389
#define TCP_PORT_LDAPS			636
#define UDP_PORT_CLDAP			389
#define TCP_PORT_GLOBALCAT_LDAP         3268 /* Windows 2000 Global Catalog */

/* desegmentation of LDAP */
static gboolean ldap_desegment = TRUE;
static guint global_ldap_tcp_port = TCP_PORT_LDAP;
static guint global_ldaps_tcp_port = TCP_PORT_LDAPS;
static guint tcp_port = 0;
static guint ssl_port = 0;

static dissector_handle_t gssapi_handle;
static dissector_handle_t gssapi_wrap_handle;
static dissector_handle_t ntlmssp_handle;
static dissector_handle_t spnego_handle;
static dissector_handle_t ssl_handle;
static dissector_handle_t ldap_handle ;

static void prefs_register_ldap(void); /* forward declaration for use in preferences registration */


/* different types of rpc calls ontop of ms cldap */
#define	MSCLDAP_RPC_NETLOGON 	1

/* Message type Choice values */
static const value_string ldap_ProtocolOp_choice_vals[] = {
  {   0, "bindRequest" },
  {   1, "bindResponse" },
  {   2, "unbindRequest" },
  {   3, "searchRequest" },
  {   4, "searchResEntry" },
  {   5, "searchResDone" },
  {	  6, "searchResRef" },
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

/*
 * Data structure attached to a conversation, giving authentication
 * information from a bind request.
 * We keep a linked list of them, so that we can free up all the
 * authentication mechanism strings.
 */
typedef struct ldap_conv_info_t {
  struct ldap_conv_info_t *next;
  guint auth_type;		/* authentication type */
  char *auth_mech;		/* authentication mechanism */
  guint32 first_auth_frame;	/* first frame that would use a security layer */
  GHashTable *unmatched;
  GHashTable *matched;
  gboolean is_mscldap;
  guint32  num_results;
  gboolean start_tls_pending;
  guint32  start_tls_frame;
} ldap_conv_info_t;
static ldap_conv_info_t *ldap_info_items;

static guint
ldap_info_hash_matched(gconstpointer k)
{
  const ldap_call_response_t *key = (const ldap_call_response_t *)k;

  return key->messageId;
}

static gint
ldap_info_equal_matched(gconstpointer k1, gconstpointer k2)
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

static guint
ldap_info_hash_unmatched(gconstpointer k)
{
  const ldap_call_response_t *key = (const ldap_call_response_t*)k;

  return key->messageId;
}

static gint
ldap_info_equal_unmatched(gconstpointer k1, gconstpointer k2)
{
  const ldap_call_response_t *key1 = (const ldap_call_response_t*)k1;
  const ldap_call_response_t *key2 = (const ldap_call_response_t*)k2;

  return key1->messageId==key2->messageId;
}


 /* These are the NtVer flags
	http://msdn.microsoft.com/en-us/library/cc201035.aspx
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


/* MS-ADTS specification, section 7.3.1.1, NETLOGON_NT_VERSION Options Bits */
static int dissect_mscldap_ntver_flags(proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
  guint32 flags;
  proto_item *item;
  proto_tree *tree=NULL;
  guint fields[] = {
		     hf_mscldap_ntver_flags_v1,
		     hf_mscldap_ntver_flags_v5,
		     hf_mscldap_ntver_flags_v5ex,
		     hf_mscldap_ntver_flags_v5ep,
		     hf_mscldap_ntver_flags_vcs,
		     hf_mscldap_ntver_flags_vnt4,
		     hf_mscldap_ntver_flags_vpdc,
		     hf_mscldap_ntver_flags_vip,
		     hf_mscldap_ntver_flags_vl,
		     hf_mscldap_ntver_flags_vgc,
		     0 };

  guint  *field;
  header_field_info *hfi;
  gboolean one_bit_set = FALSE;

  flags=tvb_get_letohl(tvb, offset);
  item=proto_tree_add_item(parent_tree, hf_mscldap_ntver_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  if(parent_tree){
    tree = proto_item_add_subtree(item, ett_mscldap_ntver_flags);
  }

  proto_item_append_text(item, " (");

  for(field = fields; *field; field++) {
    proto_tree_add_boolean(tree, *field, tvb, offset, 4, flags);
    hfi = proto_registrar_get_nth(*field);

    if(flags & hfi->bitmask) {

      if(one_bit_set)
	proto_item_append_text(item, ", ");
      else
	one_bit_set = TRUE;

      proto_item_append_text(item, "%s", hfi->name);

    }
  }

  proto_item_append_text(item, ")");

  offset += 4;

  return offset;
}

/* This string contains the last LDAPString that was decoded */
static const char *attributedesc_string=NULL;

/* This string contains the last AssertionValue that was decoded */
static char *ldapvalue_string=NULL;

/* if the octet string contain all printable ASCII characters, then
 * display it as a string, othervise just display it in hex.
 */
static int
dissect_ldap_AssertionValue(gboolean implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index)
{
	gint8 ber_class;
	gboolean pc, ind, is_ascii;
	gint32 tag;
	guint32 len, i;
	const guchar *str;

	if(!implicit_tag){
		offset=get_ber_identifier(tvb, offset, &ber_class, &pc, &tag);
		offset=get_ber_length(tvb, offset, &len, &ind);
	} else {
		len=tvb_length_remaining(tvb,offset);
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
	 * (there cant be that many ones that are truly interesting)
	 */
	if(attributedesc_string && !strncmp("DomainSid", attributedesc_string, 9)){
		tvbuff_t *sid_tvb;
		char *tmpstr;

		/* this octet string contains an NT SID */
		sid_tvb=tvb_new_subset(tvb, offset, len, len);
		dissect_nt_sid(sid_tvb, 0, tree, "SID", &tmpstr, hf_index);
		ldapvalue_string=tmpstr;

		goto finished;
	} else if ( (len==16) /* GUIDs are always 16 bytes */
	&& (attributedesc_string && !strncmp("DomainGuid", attributedesc_string, 10))) {
		guint8 drep[4] = { 0x10, 0x00, 0x00, 0x00}; /* fake DREP struct */
		e_uuid_t uuid;

		/* This octet string contained a GUID */
		dissect_dcerpc_uuid_t(tvb, offset, actx->pinfo, tree, drep, hf_ldap_guid, &uuid);

		ldapvalue_string=ep_alloc(1024);
		g_snprintf(ldapvalue_string, 1023, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                          uuid.Data1, uuid.Data2, uuid.Data3,
                          uuid.Data4[0], uuid.Data4[1],
                          uuid.Data4[2], uuid.Data4[3],
                          uuid.Data4[4], uuid.Data4[5],
                          uuid.Data4[6], uuid.Data4[7]);

		goto finished;
	} else if (attributedesc_string && !strncmp("NtVer", attributedesc_string, 5)){
		guint32 flags;

		len = 0;
		/* get flag value to populate ldapvalue_string */
		flags=tvb_get_letohl(tvb, offset);

		ldapvalue_string=ep_alloc(1024);
		g_snprintf(ldapvalue_string, 1023, "0x%08x",flags);

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
	 * -- I dont think there are full schemas available that describe the
	 *  interesting cases i.e. AD -- ronnie
	 */
	str=tvb_get_ptr(tvb, offset, len);
	is_ascii=TRUE;
	for(i=0;i<len;i++){
		if(!isascii(str[i]) || !isprint(str[i])){
			is_ascii=FALSE;
			break;
		}
	}

	/* convert the string into a printable string */
	if(is_ascii){
		ldapvalue_string=ep_strndup(str, len);
	} else {
		ldapvalue_string=ep_alloc(3*len);
		for(i=0;i<len;i++){
			g_snprintf(ldapvalue_string+i*3,3,"%02x",str[i]&0xff);
			ldapvalue_string[3*i+2]=':';
		}
		ldapvalue_string[3*len-1]=0;
	}

	proto_tree_add_string(tree, hf_index, tvb, offset, len, ldapvalue_string);


finished:
	offset+=len;
	return offset;
}

/* This string contains the last Filter item that was decoded */
static const char *Filter_string=NULL;
static const char *and_filter_string=NULL;
static const char *or_filter_string=NULL;
static const char *substring_value=NULL;
static const char *substring_item_init=NULL;
static const char *substring_item_any=NULL;
static const char *substring_item_final=NULL;
static const char *matching_rule_string=NULL;
static gboolean matching_rule_dnattr=FALSE;

#define MAX_FILTER_LEN 4096
static gint Filter_length;

#define MAX_FILTER_ELEMENTS 200
static gint Filter_elements;

/* Global variables */
char *mechanism = NULL;
static gint MessageID =-1;
static gint ProtocolOp = -1;
static gint result = 0;
static proto_item *ldm_tree = NULL; /* item to add text to */

static void ldap_do_protocolop(packet_info *pinfo)
{
  const gchar* valstr;

  if (do_protocolop)  {

    valstr = val_to_str(ProtocolOp, ldap_ProtocolOp_choice_vals, "Unknown (%%u)");

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s(%u) ", valstr, MessageID);

    if(ldm_tree)
      proto_item_append_text(ldm_tree, " %s(%d)", valstr, MessageID);

    do_protocolop = FALSE;

  }
}

static ldap_call_response_t *
ldap_match_call_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint messageId, guint protocolOpTag)
{
  ldap_call_response_t lcr, *lcrp=NULL;
  ldap_conv_info_t *ldap_info = (ldap_conv_info_t *)pinfo->private_data;

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
          lcr.is_request=TRUE;
          lcr.req_frame=pinfo->fd->num;
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
          lcr.is_request=FALSE;
          lcr.req_frame=0;
          lcr.rep_frame=pinfo->fd->num;
          break;
      }
      lcrp=(ldap_call_response_t *)g_hash_table_lookup(ldap_info->matched, &lcr);

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

		/* this a a request - add it to the unmatched list */

        /* check that we dont already have one of those in the
           unmatched list and if so remove it */

        lcr.messageId=messageId;
        lcrp=(ldap_call_response_t *)g_hash_table_lookup(ldap_info->unmatched, &lcr);
        if(lcrp){
          g_hash_table_remove(ldap_info->unmatched, lcrp);
        }
        /* if we cant reuse the old one, grab a new chunk */
        if(!lcrp){
          lcrp=se_alloc(sizeof(ldap_call_response_t));
        }
        lcrp->messageId=messageId;
        lcrp->req_frame=pinfo->fd->num;
        lcrp->req_time=pinfo->fd->abs_ts;
        lcrp->rep_frame=0;
        lcrp->protocolOpTag=protocolOpTag;
        lcrp->is_request=TRUE;
        g_hash_table_insert(ldap_info->unmatched, lcrp, lcrp);
        return NULL;
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

		/* this is a result - it should be in our unmatched list */

        lcr.messageId=messageId;
        lcrp=(ldap_call_response_t *)g_hash_table_lookup(ldap_info->unmatched, &lcr);

        if(lcrp){

          if(!lcrp->rep_frame){
            g_hash_table_remove(ldap_info->unmatched, lcrp);
            lcrp->rep_frame=pinfo->fd->num;
            lcrp->is_request=FALSE;
            g_hash_table_insert(ldap_info->matched, lcrp, lcrp);
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
        PROTO_ITEM_SET_GENERATED(it);
      } else {
        nstime_t ns;
        it=proto_tree_add_uint(tree, hf_ldap_response_to, tvb, 0, 0, lcrp->req_frame);
        PROTO_ITEM_SET_GENERATED(it);
        nstime_delta(&ns, &pinfo->fd->abs_ts, &lcrp->req_time);
        it=proto_tree_add_time(tree, hf_ldap_time, tvb, 0, 0, &ns);
        PROTO_ITEM_SET_GENERATED(it);
      }
    }

    return lcrp;
}


/*--- Included file: packet-ldap-fn.c ---*/
#line 1 "../../asn1/ldap/packet-ldap-fn.c"
/*--- Cyclic dependencies ---*/

/* Filter -> Filter/and -> Filter/and/_item -> Filter */
/* Filter -> Filter/or -> Filter/or/_item -> Filter */
/* Filter -> Filter/not -> Filter */
static int dissect_ldap_Filter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);




static int
dissect_ldap_MessageID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 98 "../../asn1/ldap/ldap.cnf"

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &MessageID);


  ldm_tree = tree;



  return offset;
}



static int
dissect_ldap_INTEGER_1_127(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ldap_LDAPString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 324 "../../asn1/ldap/ldap.cnf"
  tvbuff_t	*parameter_tvb = NULL;
  const char    *ldapstring = NULL;
  gchar		*sc = NULL; /* semi-colon pointer */

    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


  if (parameter_tvb || (hf_index == hf_ldap_baseObject)) {

     ldap_do_protocolop(actx->pinfo);

     if(parameter_tvb)
        ldapstring = tvb_get_ephemeral_string(parameter_tvb, 0, tvb_length_remaining(parameter_tvb, 0));

     if(hf_index == hf_ldap_baseObject) {
  	/* this is search - put it on the scanline */
	if(!ldapstring || !*ldapstring)
	  ldapstring = "<ROOT>";

    col_append_fstr(actx->pinfo->cinfo, COL_INFO, "\"%s\" ", ldapstring);

  	if(ldm_tree)
  	  proto_item_append_text(ldm_tree, " \"%s\"", ldapstring);


	if(!parameter_tvb) {

	  proto_item_append_text(actx->created_item, " (%s)", ldapstring);
	}

     } else if ((hf_index == hf_ldap_errorMessage) && ldapstring && *ldapstring) { /* only show message if not success */
        col_append_fstr(actx->pinfo->cinfo, COL_INFO, "(%s) ", ldapstring);

        if(ldm_tree)
  	  proto_item_append_text(ldm_tree, " (%s)", ldapstring);

     } else if ((hf_index == hf_ldap_objectName) ||
		(hf_index == hf_ldap_name) ||
	        (hf_index == hf_ldap_entry) ||
		(hf_index == hf_ldap_object) ||
		(hf_index == hf_ldap_delRequest) ) {

	if(!ldapstring || !*ldapstring)
	  ldapstring = "<ROOT>";

    col_append_fstr(actx->pinfo->cinfo, COL_INFO, "\"%s\" ", ldapstring);

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
	attr_type = ep_strdup(ldapstring);

	/* append it to the parent entry */
	proto_item_append_text(tree, " %s", attr_type);

	/* remove the ";binary" component if present */
	if((sc = strchr(attr_type, ';')) != NULL) {
		if(!strcmp(sc, ";binary")) {
			*sc = '\0'; /* terminate the string */
			is_binary_attr_type = TRUE;
		}
	} else {
		is_binary_attr_type = FALSE;
	}

     }

  }



  return offset;
}



static int
dissect_ldap_LDAPDN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_LDAPString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ldap_Simple(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 167 "../../asn1/ldap/ldap.cnf"
ldap_conv_info_t *ldap_info;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);


	ldap_info = actx->pinfo->private_data;
	ldap_info->auth_type = LDAP_AUTH_SIMPLE;

	actx->pinfo->private_data = ldap_info;



  return offset;
}



static int
dissect_ldap_Mechanism(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 177 "../../asn1/ldap/ldap.cnf"

ldap_conv_info_t *ldap_info;
tvbuff_t	*parameter_tvb;
char *mechanism = NULL;
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	ldap_info = actx->pinfo->private_data;
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
    if(!actx->pinfo->fd->flags.visited) {
        mechanism = tvb_get_string(parameter_tvb, 0, tvb_length_remaining(parameter_tvb,0));
        ldap_info->first_auth_frame = 0;	/* not known until we see the bind reply */
        /*
         * If the mechanism in this request is an empty string (which is
         * returned as a null pointer), use the saved mechanism instead.
         * Otherwise, if the saved mechanism is an empty string (null),
         * save this mechanism.
         */
        if (mechanism == NULL) {
            mechanism = ldap_info->auth_mech;
        } else {
          g_free(ldap_info->auth_mech);
          ldap_info->auth_mech = mechanism;
        }
	actx->pinfo->private_data = ldap_info;
    }


  return offset;
}



static int
dissect_ldap_Credentials(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 214 "../../asn1/ldap/ldap.cnf"

tvbuff_t	*parameter_tvb;
ldap_conv_info_t *ldap_info;
gint8 ber_class;
gboolean pc;
gint32 tag;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


	if (!parameter_tvb)
		return offset;

	ldap_info = actx->pinfo->private_data;
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
	  if (parameter_tvb && (tvb_length(parameter_tvb) > 0))
	    call_dissector(spnego_handle, parameter_tvb, actx->pinfo, tree);
	}
	/*if ((ldap_info->auth_mech != NULL) && ((strcmp(ldap_info->auth_mech, "GSSAPI") == 0) || (ber_class==BER_CLASS_APP))) {*/
	if ((ldap_info->auth_mech != NULL) && (ber_class==BER_CLASS_APP)) {
	  /*
	   * This is a raw GSS-API token.
	   */
	  if (parameter_tvb && (tvb_length(parameter_tvb) > 0)) {
	    call_dissector(gssapi_handle, parameter_tvb, actx->pinfo, tree);
	  }
	}
	actx->pinfo->private_data = ldap_info;




  return offset;
}


static const ber_sequence_t SaslCredentials_sequence[] = {
  { &hf_ldap_mechanism      , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_Mechanism },
  { &hf_ldap_credentials    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ldap_Credentials },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_SaslCredentials(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SaslCredentials_sequence, hf_index, ett_ldap_SaslCredentials);

  return offset;
}



static int
dissect_ldap_T_ntlmsspNegotiate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 701 "../../asn1/ldap/ldap.cnf"
	/* make sure the protocol op comes first */
       	ldap_do_protocolop(actx->pinfo);

	call_dissector(ntlmssp_handle, tvb, actx->pinfo, tree);
	offset+=tvb_length_remaining(tvb, offset);



  return offset;
}



static int
dissect_ldap_T_ntlmsspAuth(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 708 "../../asn1/ldap/ldap.cnf"
	/* make sure the protocol op comes first */
       	ldap_do_protocolop(actx->pinfo);

	call_dissector(ntlmssp_handle, tvb, actx->pinfo, tree);
	offset+=tvb_length_remaining(tvb, offset);



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
dissect_ldap_AuthenticationChoice(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 491 "../../asn1/ldap/ldap.cnf"
  gint branch = -1;
  gint auth = -1;
  const gchar *valstr;

    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AuthenticationChoice_choice, hf_index, ett_ldap_AuthenticationChoice,
                                 &branch);


  ldap_do_protocolop(actx->pinfo);

  if((branch > -1) && (branch < (gint)(sizeof AuthenticationChoice_choice/sizeof AuthenticationChoice_choice[0])))
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
dissect_ldap_BindRequest_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BindRequest_U_sequence, hf_index, ett_ldap_BindRequest_U);

  return offset;
}



static int
dissect_ldap_BindRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 0, TRUE, dissect_ldap_BindRequest_U);

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
dissect_ldap_BindResponse_resultCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 444 "../../asn1/ldap/ldap.cnf"

  const gchar *valstr;

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
dissect_ldap_T_bindResponse_matchedDN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 715 "../../asn1/ldap/ldap.cnf"
	tvbuff_t *new_tvb=NULL;

	offset = dissect_ber_octet_string(FALSE, actx, tree, tvb, offset, hf_ldap_matchedDN, &new_tvb);

	if(  new_tvb
	&&  (tvb_length(new_tvb)>=7)
	&&  (!tvb_memeql(new_tvb, 0, "NTLMSSP", 7))){

		/* make sure the protocol op comes first */
        	ldap_do_protocolop(actx->pinfo);

		call_dissector(ntlmssp_handle, new_tvb, actx->pinfo, tree);
	}
	return offset;



  return offset;
}



static int
dissect_ldap_ErrorMessage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_LDAPString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ldap_LDAPURL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

#line 51 "../../asn1/ldap/ldap.cnf"
	PROTO_ITEM_SET_URL(actx->created_item);


  return offset;
}


static const ber_sequence_t Referral_sequence_of[1] = {
  { &hf_ldap_Referral_item  , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_LDAPURL },
};

static int
dissect_ldap_Referral(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Referral_sequence_of, hf_index, ett_ldap_Referral);

  return offset;
}



static int
dissect_ldap_ServerSaslCreds(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 254 "../../asn1/ldap/ldap.cnf"

tvbuff_t	*parameter_tvb = NULL;
ldap_conv_info_t *ldap_info;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (!parameter_tvb)
		return offset;
	ldap_info = (ldap_conv_info_t *)actx->pinfo->private_data;
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
      ldap_info->first_auth_frame = actx->pinfo->fd->num + 1;
      if (ldap_info->auth_mech != NULL &&
          strcmp(ldap_info->auth_mech, "GSS-SPNEGO") == 0) {
	/* It could be the second leg of GSS-SPNEGO wrapping NTLMSSP
	 * which might not be wrapped in GSS-SPNEGO but be a raw
	 * NTLMSSP blob
	 */
	if ( (tvb_length(parameter_tvb)>=7)
	&&   (!tvb_memeql(parameter_tvb, 0, "NTLMSSP", 7))){
	  call_dissector(ntlmssp_handle, parameter_tvb, actx->pinfo, tree);
	  break;
	}
        /*
         * This is a GSS-API token.
         */
	if(parameter_tvb && (tvb_length(parameter_tvb) > 0))
	  call_dissector(spnego_handle, parameter_tvb, actx->pinfo, tree);
      } else if (ldap_info->auth_mech != NULL &&
          strcmp(ldap_info->auth_mech, "GSSAPI") == 0) {
        /*
         * This is a GSS-API token.
         */
        if(parameter_tvb && (tvb_length(parameter_tvb) > 0))
          call_dissector(gssapi_handle, parameter_tvb, actx->pinfo, tree);
		}
	break;
	}
	actx->pinfo->private_data = ldap_info;



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
dissect_ldap_BindResponse_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BindResponse_U_sequence, hf_index, ett_ldap_BindResponse_U);

  return offset;
}



static int
dissect_ldap_BindResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 1, TRUE, dissect_ldap_BindResponse_U);

  return offset;
}



static int
dissect_ldap_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_ldap_UnbindRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 513 "../../asn1/ldap/ldap.cnf"

 implicit_tag = TRUE; /* correct problem with asn2wrs */

   offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 2, TRUE, dissect_ldap_NULL);


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
dissect_ldap_T_scope(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 412 "../../asn1/ldap/ldap.cnf"

  guint32 scope = 0xffff;
  const gchar *valstr;

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
dissect_ldap_T_derefAliases(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ldap_INTEGER_0_maxInt(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ldap_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_ldap_T_and_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_Filter(implicit_tag, tvb, offset, actx, tree, hf_index);

#line 559 "../../asn1/ldap/ldap.cnf"
	if(and_filter_string){
		and_filter_string=ep_strdup_printf("(&%s%s)",and_filter_string,Filter_string);
	} else {
		and_filter_string=Filter_string;
	}


  return offset;
}


static const ber_sequence_t T_and_set_of[1] = {
  { &hf_ldap_and_item       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ldap_T_and_item },
};

static int
dissect_ldap_T_and(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 566 "../../asn1/ldap/ldap.cnf"
	proto_tree *tr=NULL;
	proto_item *it=NULL;
	const char *old_and_filter_string=and_filter_string;

	and_filter_string=NULL;
	if(tree){
		it=proto_tree_add_text(tree, tvb, offset, tvb_length_remaining(tvb, offset), "and: ");
		tr=proto_item_add_subtree(it, ett_ldap_T_and);
		tree = tr;
	}

  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_and_set_of, hf_index, ett_ldap_T_and);


	if(and_filter_string) {
		proto_item_append_text(it, "%s", and_filter_string);
		Filter_string=ep_strdup_printf("%s",and_filter_string);
	}
	and_filter_string=old_and_filter_string;



  return offset;
}



static int
dissect_ldap_T_or_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_Filter(implicit_tag, tvb, offset, actx, tree, hf_index);

#line 586 "../../asn1/ldap/ldap.cnf"
	if(or_filter_string){
		or_filter_string=ep_strdup_printf("(|%s%s)",or_filter_string,Filter_string);
	} else {
		or_filter_string=Filter_string;
	}



  return offset;
}


static const ber_sequence_t T_or_set_of[1] = {
  { &hf_ldap_or_item        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ldap_T_or_item },
};

static int
dissect_ldap_T_or(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 594 "../../asn1/ldap/ldap.cnf"
	proto_tree *tr=NULL;
	proto_item *it=NULL;
	const char *old_or_filter_string=or_filter_string;

	or_filter_string=NULL;
	if(tree){
		it=proto_tree_add_text(tree, tvb, offset, tvb_length_remaining(tvb, offset), "or: ");
		tr=proto_item_add_subtree(it, ett_ldap_T_or);
		tree = tr;
	}
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_or_set_of, hf_index, ett_ldap_T_or);

	if(or_filter_string) {
		proto_item_append_text(it, "%s", or_filter_string);
		Filter_string=ep_strdup_printf("%s",or_filter_string);
	}
	or_filter_string=old_or_filter_string;



  return offset;
}



static int
dissect_ldap_T_not(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_Filter(implicit_tag, tvb, offset, actx, tree, hf_index);

#line 615 "../../asn1/ldap/ldap.cnf"
	Filter_string=ep_strdup_printf("(!%s)",string_or_null(Filter_string));


  return offset;
}



static int
dissect_ldap_AttributeDescription(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_LDAPString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static const ber_sequence_t AttributeValueAssertion_sequence[] = {
  { &hf_ldap_attributeDesc  , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_AttributeDescription },
  { &hf_ldap_assertionValue , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_AssertionValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_AttributeValueAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeValueAssertion_sequence, hf_index, ett_ldap_AttributeValueAssertion);

  return offset;
}



static int
dissect_ldap_T_equalityMatch(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_AttributeValueAssertion(implicit_tag, tvb, offset, actx, tree, hf_index);

#line 536 "../../asn1/ldap/ldap.cnf"
	Filter_string=ep_strdup_printf("(%s=%s)",
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
dissect_ldap_T_substringFilter_substrings_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_substringFilter_substrings_item_choice, hf_index, ett_ldap_T_substringFilter_substrings_item,
                                 NULL);

#line 641 "../../asn1/ldap/ldap.cnf"
	if (substring_item_final) {
		substring_value=ep_strdup_printf("%s%s",
						 (substring_value?substring_value:"*"),
						 substring_item_final);
	} else if (substring_item_any) {
		substring_value=ep_strdup_printf("%s%s*",
						 (substring_value?substring_value:"*"),
						 substring_item_any);
	} else if (substring_item_init) {
		substring_value=ep_strdup_printf("%s*",
						 substring_item_init);
	}


  return offset;
}


static const ber_sequence_t T_substringFilter_substrings_sequence_of[1] = {
  { &hf_ldap_substringFilter_substrings_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ldap_T_substringFilter_substrings_item },
};

static int
dissect_ldap_T_substringFilter_substrings(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_SubstringFilter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 655 "../../asn1/ldap/ldap.cnf"
	proto_tree *tr=NULL;
	proto_item *it=NULL;
	const char *old_substring_value=substring_value;

	attr_type=NULL;
	substring_value=NULL;
	substring_item_init=NULL;
	substring_item_any=NULL;
	substring_item_final=NULL;
	if(tree){
		it=proto_tree_add_text(tree, tvb, offset, tvb_length_remaining(tvb, offset), "substring: ");
		tr=proto_item_add_subtree(it, ett_ldap_SubstringFilter);
		tree = tr;
	}
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SubstringFilter_sequence, hf_index, ett_ldap_SubstringFilter);

	Filter_string=ep_strdup_printf("(%s=%s)",
		string_or_null(attr_type),
		string_or_null(substring_value));
	proto_item_append_text(it, "%s", Filter_string);
	substring_value=old_substring_value;



  return offset;
}



static int
dissect_ldap_T_greaterOrEqual(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_AttributeValueAssertion(implicit_tag, tvb, offset, actx, tree, hf_index);

#line 542 "../../asn1/ldap/ldap.cnf"
	Filter_string=ep_strdup_printf("(%s>=%s)",
				       string_or_null(attributedesc_string),
				       string_or_null(ldapvalue_string));



  return offset;
}



static int
dissect_ldap_T_lessOrEqual(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_AttributeValueAssertion(implicit_tag, tvb, offset, actx, tree, hf_index);

#line 548 "../../asn1/ldap/ldap.cnf"
	Filter_string=ep_strdup_printf("(%s<=%s)",
				       string_or_null(attributedesc_string),
				       string_or_null(ldapvalue_string));



  return offset;
}



static int
dissect_ldap_T_present(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_AttributeDescription(implicit_tag, tvb, offset, actx, tree, hf_index);

#line 612 "../../asn1/ldap/ldap.cnf"
	Filter_string=ep_strdup_printf("(%s=*)",string_or_null(Filter_string));


  return offset;
}



static int
dissect_ldap_T_approxMatch(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_AttributeValueAssertion(implicit_tag, tvb, offset, actx, tree, hf_index);

#line 554 "../../asn1/ldap/ldap.cnf"
	Filter_string=ep_strdup_printf("(%s~=%s)",
				       string_or_null(attributedesc_string),
				       string_or_null(ldapvalue_string));


  return offset;
}



static int
dissect_ldap_MatchingRuleId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_LDAPString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ldap_T_dnAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 618 "../../asn1/ldap/ldap.cnf"
	gboolean val;

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
dissect_ldap_MatchingRuleAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MatchingRuleAssertion_sequence, hf_index, ett_ldap_MatchingRuleAssertion);

  return offset;
}



static int
dissect_ldap_T_extensibleMatch(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 627 "../../asn1/ldap/ldap.cnf"
	attr_type=NULL;
	matching_rule_string=NULL;
	ldapvalue_string=NULL;
	matching_rule_dnattr=FALSE;


  offset = dissect_ldap_MatchingRuleAssertion(implicit_tag, tvb, offset, actx, tree, hf_index);

#line 633 "../../asn1/ldap/ldap.cnf"
	Filter_string=ep_strdup_printf("(%s:%s%s%s=%s)",
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
dissect_ldap_Filter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 677 "../../asn1/ldap/ldap.cnf"
	proto_tree *tr=NULL;
	proto_item *it=NULL;
	attributedesc_string=NULL;

	if (Filter_length++ > MAX_FILTER_LEN) {
		expert_add_info_format(actx->pinfo, tree, PI_UNDECODED, PI_ERROR, "Filter length exceeds %u. Giving up.", MAX_FILTER_LEN);
		THROW(ReportedBoundsError);
	}

	if (Filter_elements++ > MAX_FILTER_ELEMENTS) {
		expert_add_info_format(actx->pinfo, tree, PI_UNDECODED, PI_ERROR, "Found more than %u filter elements. Giving up.", MAX_FILTER_ELEMENTS);
		THROW(ReportedBoundsError);
	}

	if(tree){
		it=proto_tree_add_text(tree, tvb, offset, tvb_length_remaining(tvb, offset), "Filter: ");
		tr=proto_item_add_subtree(it, ett_ldap_Filter);
		tree = tr;
	}
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Filter_choice, hf_index, ett_ldap_Filter,
                                 NULL);

	if(Filter_string)
		proto_item_append_text(it, "%s", string_or_null(Filter_string));



  return offset;
}



static int
dissect_ldap_T_filter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 525 "../../asn1/ldap/ldap.cnf"
	Filter_string=NULL;
	Filter_elements = 0;
	Filter_length = 0;


  offset = dissect_ldap_Filter(implicit_tag, tvb, offset, actx, tree, hf_index);

#line 530 "../../asn1/ldap/ldap.cnf"
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
dissect_ldap_AttributeDescriptionList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_SearchRequest_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SearchRequest_U_sequence, hf_index, ett_ldap_SearchRequest_U);

  return offset;
}



static int
dissect_ldap_SearchRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 3, TRUE, dissect_ldap_SearchRequest_U);

  return offset;
}



static int
dissect_ldap_AttributeValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 460 "../../asn1/ldap/ldap.cnf"

  tvbuff_t	*next_tvb = NULL;
  gchar		*string;
  guint32	i, len;
  int           old_offset = offset;

  /* attr_type, should be set before calling this function */

  /* extract the value of the octetstring */
  offset = dissect_ber_octet_string(FALSE, actx, NULL, tvb, offset, hf_index, &next_tvb);

  /* if we have an attribute type that isn't binary see if there is a better dissector */
  if(!attr_type || !next_tvb || !dissector_try_string(ldap_name_dissector_table, attr_type, next_tvb, actx->pinfo, tree)) {
    offset = old_offset;

    /* do the default thing */
      offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);


    len = tvb_length_remaining(next_tvb, 0);

    for(i = 0; i < len; i++)
      if(!g_ascii_isprint(tvb_get_guint8(next_tvb, i)))
        break;

    if(i == len) {
      string = tvb_get_ephemeral_string(next_tvb, 0, tvb_length_remaining(next_tvb, 0));
      proto_item_set_text(actx->created_item, "AttributeValue: %s", string);
    }
  }



  return offset;
}


static const ber_sequence_t SET_OF_AttributeValue_set_of[1] = {
  { &hf_ldap_vals_item      , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_AttributeValue },
};

static int
dissect_ldap_SET_OF_AttributeValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_PartialAttributeList_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PartialAttributeList_item_sequence, hf_index, ett_ldap_PartialAttributeList_item);

  return offset;
}


static const ber_sequence_t PartialAttributeList_sequence_of[1] = {
  { &hf_ldap_PartialAttributeList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ldap_PartialAttributeList_item },
};

static int
dissect_ldap_PartialAttributeList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_SearchResultEntry_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SearchResultEntry_U_sequence, hf_index, ett_ldap_SearchResultEntry_U);

  return offset;
}



static int
dissect_ldap_SearchResultEntry(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 4, TRUE, dissect_ldap_SearchResultEntry_U);

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
dissect_ldap_T_resultCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 428 "../../asn1/ldap/ldap.cnf"

  const gchar *valstr;

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
dissect_ldap_LDAPResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LDAPResult_sequence, hf_index, ett_ldap_LDAPResult);

  return offset;
}



static int
dissect_ldap_SearchResultDone(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 5, TRUE, dissect_ldap_LDAPResult);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_LDAPURL_sequence_of[1] = {
  { &hf_ldap__untag_item    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_LDAPURL },
};

static int
dissect_ldap_SEQUENCE_OF_LDAPURL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_LDAPURL_sequence_of, hf_index, ett_ldap_SEQUENCE_OF_LDAPURL);

  return offset;
}



static int
dissect_ldap_SearchResultReference(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 818 "../../asn1/ldap/ldap.cnf"

   offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 19, TRUE, dissect_ldap_SEQUENCE_OF_LDAPURL);


 ldap_do_protocolop(actx->pinfo);




  return offset;
}


static const value_string ldap_T_operation_vals[] = {
  {   0, "add" },
  {   1, "delete" },
  {   2, "replace" },
  { 0, NULL }
};


static int
dissect_ldap_T_operation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_AttributeTypeAndValues(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_T_modifyRequest_modification_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_modifyRequest_modification_item_sequence, hf_index, ett_ldap_T_modifyRequest_modification_item);

  return offset;
}


static const ber_sequence_t ModifyRequest_modification_sequence_of[1] = {
  { &hf_ldap_modifyRequest_modification_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ldap_T_modifyRequest_modification_item },
};

static int
dissect_ldap_ModifyRequest_modification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_ModifyRequest_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ModifyRequest_U_sequence, hf_index, ett_ldap_ModifyRequest_U);

  return offset;
}



static int
dissect_ldap_ModifyRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 6, TRUE, dissect_ldap_ModifyRequest_U);

  return offset;
}



static int
dissect_ldap_ModifyResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 7, TRUE, dissect_ldap_LDAPResult);

  return offset;
}


static const ber_sequence_t AttributeList_item_sequence[] = {
  { &hf_ldap_type           , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_AttributeDescription },
  { &hf_ldap_vals           , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_ldap_SET_OF_AttributeValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_AttributeList_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeList_item_sequence, hf_index, ett_ldap_AttributeList_item);

  return offset;
}


static const ber_sequence_t AttributeList_sequence_of[1] = {
  { &hf_ldap_AttributeList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ldap_AttributeList_item },
};

static int
dissect_ldap_AttributeList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_AddRequest_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AddRequest_U_sequence, hf_index, ett_ldap_AddRequest_U);

  return offset;
}



static int
dissect_ldap_AddRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 8, TRUE, dissect_ldap_AddRequest_U);

  return offset;
}



static int
dissect_ldap_AddResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 9, TRUE, dissect_ldap_LDAPResult);

  return offset;
}



static int
dissect_ldap_DelRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 10, TRUE, dissect_ldap_LDAPDN);

  return offset;
}



static int
dissect_ldap_DelResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 11, TRUE, dissect_ldap_LDAPResult);

  return offset;
}



static int
dissect_ldap_RelativeLDAPDN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_ModifyDNRequest_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ModifyDNRequest_U_sequence, hf_index, ett_ldap_ModifyDNRequest_U);

  return offset;
}



static int
dissect_ldap_ModifyDNRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 12, TRUE, dissect_ldap_ModifyDNRequest_U);

  return offset;
}



static int
dissect_ldap_ModifyDNResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 13, TRUE, dissect_ldap_LDAPResult);

  return offset;
}


static const ber_sequence_t CompareRequest_U_sequence[] = {
  { &hf_ldap_entry          , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_LDAPDN },
  { &hf_ldap_ava            , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ldap_AttributeValueAssertion },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_CompareRequest_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CompareRequest_U_sequence, hf_index, ett_ldap_CompareRequest_U);

  return offset;
}



static int
dissect_ldap_CompareRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 14, TRUE, dissect_ldap_CompareRequest_U);

  return offset;
}



static int
dissect_ldap_CompareResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 15, TRUE, dissect_ldap_LDAPResult);

  return offset;
}



static int
dissect_ldap_AbandonRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 825 "../../asn1/ldap/ldap.cnf"

   offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 16, TRUE, dissect_ldap_MessageID);


 ldap_do_protocolop(actx->pinfo);



  return offset;
}



static int
dissect_ldap_LDAPOID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 54 "../../asn1/ldap/ldap.cnf"

	tvbuff_t	*parameter_tvb;
	const gchar *name;


  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

#line 61 "../../asn1/ldap/ldap.cnf"

	object_identifier_id = NULL;

	if (!parameter_tvb)
		return offset;

	object_identifier_id = tvb_get_ephemeral_string(parameter_tvb, 0, tvb_length_remaining(parameter_tvb,0));
	name = oid_resolved_from_string(object_identifier_id);

	if(name){
		proto_item_append_text(actx->created_item, " (%s)", name);

		if((hf_index == hf_ldap_requestName) || (hf_index == hf_ldap_responseName)) {
			ldap_do_protocolop(actx->pinfo);
			col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s ", name);
		}
	}

	if(((hf_index == hf_ldap_responseName) || (hf_index == hf_ldap_requestName)) &&
	    !strcmp(object_identifier_id, "1.3.6.1.4.1.1466.20037")) {

		/* we have agreed start_tls */
		ldap_conv_info_t *ldap_info = NULL;

		ldap_info = (ldap_conv_info_t *)actx->pinfo->private_data;

		if(ldap_info) {
			if(hf_index == hf_ldap_responseName)
				/* TLS in the next frame */
				ldap_info->start_tls_frame = (actx->pinfo->fd->num) + 1;
			else
				/* remember we have asked to start_tls */
				ldap_info->start_tls_pending = TRUE;
		}
	}


  return offset;
}



static int
dissect_ldap_T_requestValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 750 "../../asn1/ldap/ldap.cnf"

	if((object_identifier_id != NULL) && oid_has_dissector(object_identifier_id)) {
		offset = call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);
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
dissect_ldap_ExtendedRequest_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExtendedRequest_U_sequence, hf_index, ett_ldap_ExtendedRequest_U);

  return offset;
}



static int
dissect_ldap_ExtendedRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 23, TRUE, dissect_ldap_ExtendedRequest_U);

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
dissect_ldap_ExtendedResponse_resultCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ldap_ResponseName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_LDAPOID(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ldap_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_ExtendedResponse_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExtendedResponse_U_sequence, hf_index, ett_ldap_ExtendedResponse_U);

  return offset;
}



static int
dissect_ldap_ExtendedResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 24, TRUE, dissect_ldap_ExtendedResponse_U);

  return offset;
}



static int
dissect_ldap_T_intermediateResponse_responseValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 758 "../../asn1/ldap/ldap.cnf"

	const gchar *name;


#line 762 "../../asn1/ldap/ldap.cnf"
	if(ldm_tree && object_identifier_id) {
		proto_item_set_text(ldm_tree, "%s %s", "IntermediateResponse", object_identifier_id);
		name = oid_resolved_from_string(object_identifier_id);
		if(name)
			proto_item_append_text(ldm_tree, " (%s)", name);
	}
	if((object_identifier_id != NULL) && oid_has_dissector(object_identifier_id)) {
		offset = call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);
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
dissect_ldap_IntermediateResponse_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IntermediateResponse_U_sequence, hf_index, ett_ldap_IntermediateResponse_U);

  return offset;
}



static int
dissect_ldap_IntermediateResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 25, TRUE, dissect_ldap_IntermediateResponse_U);

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
dissect_ldap_ProtocolOp(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 106 "../../asn1/ldap/ldap.cnf"

  ldap_call_response_t *lcrp;
  ldap_conv_info_t *ldap_info = (ldap_conv_info_t *)actx->pinfo->private_data;
  do_protocolop = TRUE;


  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ProtocolOp_choice, hf_index, ett_ldap_ProtocolOp,
                                 &ProtocolOp);

#line 112 "../../asn1/ldap/ldap.cnf"

  if (ProtocolOp == -1) {
    return offset;
  }

  /* ProtocolOp is the index, not the tag so convert it to the tag value */
  ProtocolOp = ldap_ProtocolOp_vals[ProtocolOp].value;

  lcrp=ldap_match_call_response(tvb, actx->pinfo, tree, MessageID, ProtocolOp);
  if(lcrp){
    tap_queue_packet(ldap_tap, actx->pinfo, lcrp);
  }

  /* XXX: the count will not work if the results span multiple TCP packets */

  if(ldap_info && tree) { /* only count once - on tree pass */
    switch(ProtocolOp) {

    case LDAP_RES_SEARCH_ENTRY:
  	ldap_info->num_results++;

  	proto_item_append_text(tree, " [%d result%s]",
  		        ldap_info->num_results, ldap_info->num_results == 1 ? "" : "s");

  	break;

    case LDAP_RES_SEARCH_RESULT:

        col_append_fstr(actx->pinfo->cinfo, COL_INFO, " [%d result%s]",
  	    	        ldap_info->num_results, ldap_info->num_results == 1 ? "" : "s");

  	proto_item_append_text(tree, " [%d result%s]",
  		        ldap_info->num_results, ldap_info->num_results == 1 ? "" : "s");

  	ldap_info->num_results = 0;
    	break;
     default:
   	break;
    }
  }

  if(ldap_info && (ProtocolOp == LDAP_RES_EXTENDED)) {
	/* this is an extend result */

	if(ldap_info->start_tls_pending && !ldap_info->start_tls_frame) {
		/* XXX: some directories do not correctly return the responseName in the extendedResponse so we don't know start_tls has been negotiated */

		col_append_str(actx->pinfo->cinfo, COL_INFO, "[LDAP_START_TLS_OID responseName missing] ");
		ldap_info->start_tls_frame = (actx->pinfo->fd->num) + 1;
	}

	ldap_info->start_tls_pending = FALSE;
  }


  return offset;
}



static int
dissect_ldap_ControlType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ldap_LDAPOID(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ldap_T_controlValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 731 "../../asn1/ldap/ldap.cnf"
	gint8 ber_class;
	gboolean pc, ind;
	gint32 tag;
	guint32 len;

	if((object_identifier_id != NULL) && oid_has_dissector(object_identifier_id)) {
		/* remove the OCTET STRING encoding */
		offset=dissect_ber_identifier(actx->pinfo, NULL, tvb, offset, &ber_class, &pc, &tag);
		offset=dissect_ber_length(actx->pinfo, NULL, tvb, offset, &len, &ind);

		call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);

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
dissect_ldap_Control(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Control_sequence, hf_index, ett_ldap_Control);

  return offset;
}


static const ber_sequence_t Controls_sequence_of[1] = {
  { &hf_ldap_Controls_item  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ldap_Control },
};

static int
dissect_ldap_Controls(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_LDAPMessage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LDAPMessage_sequence, hf_index, ett_ldap_LDAPMessage);

  return offset;
}





static int
dissect_ldap_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_SearchControlValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_SortKeyList_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SortKeyList_item_sequence, hf_index, ett_ldap_SortKeyList_item);

  return offset;
}


static const ber_sequence_t SortKeyList_sequence_of[1] = {
  { &hf_ldap_SortKeyList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ldap_SortKeyList_item },
};

static int
dissect_ldap_SortKeyList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_T_sortResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_SortResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SortResult_sequence, hf_index, ett_ldap_SortResult);

  return offset;
}


static const ber_sequence_t DirSyncFlagsSubEntry_sequence[] = {
  { &hf_ldap_value          , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ldap_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_DirSyncFlagsSubEntry(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DirSyncFlagsSubEntry_sequence, hf_index, ett_ldap_DirSyncFlagsSubEntry);

  return offset;
}



static int
dissect_ldap_DirSyncFlags(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 775 "../../asn1/ldap/ldap.cnf"
	gint8 ber_class;
	gboolean pc;
	gint32 tag;
	guint32 len;
	gint32 val;
	header_field_info *hfinfo;

	int otheroffset = offset;
	if(!implicit_tag){
		dissect_ber_identifier(actx->pinfo, tree, tvb, otheroffset, &ber_class, &pc, &tag);
		otheroffset=dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, NULL);
	} else {
		gint32 remaining=tvb_length_remaining(tvb, offset);
		len=remaining>0 ? remaining : 0;
	}

	offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, -1, &val);

	hfinfo = proto_registrar_get_nth(hf_index);

	if (val >0) {
		proto_tree *subtree = NULL;
		proto_item *item = NULL;
		item = proto_tree_add_text(tree, tvb, otheroffset+1, len, "%s: 0x%08x", hfinfo->name, val);
		subtree = proto_item_add_subtree(item, ett_ldap_DirSyncFlagsSubEntry);

		if (val & 0x1) {
			proto_tree_add_text(subtree, tvb, otheroffset+1, len, "Flag Object_Security");
		}
		if (val & 0x800) {
			proto_tree_add_text(subtree, tvb, otheroffset+1, len, "Flag Ancestor_First");
		}
		if (val & 0x2000) {
			proto_tree_add_text(subtree, tvb, otheroffset+1, len, "Flag Public_Data_Only");
		}
		if (val & 0x80000000) {
			proto_tree_add_text(subtree, tvb, otheroffset+1, len, "Flag Incremental_Value");
		}
	} else {
		proto_tree_add_text(tree, tvb, otheroffset+len, len, "%s: 0", hfinfo->name);
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
dissect_ldap_DirSyncControlValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_PasswdModifyRequestValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PasswdModifyRequestValue_sequence, hf_index, ett_ldap_PasswdModifyRequestValue);

  return offset;
}


static const ber_sequence_t PasswdModifyResponseValue_sequence[] = {
  { &hf_ldap_genPasswd      , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ldap_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_PasswdModifyResponseValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PasswdModifyResponseValue_sequence, hf_index, ett_ldap_PasswdModifyResponseValue);

  return offset;
}


static const ber_sequence_t CancelRequestValue_sequence[] = {
  { &hf_ldap_cancelID       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_ldap_MessageID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ldap_CancelRequestValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_T_mode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_SyncRequestValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_T_state(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ldap_SyncUUID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_SyncStateValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_SyncDoneValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_T_refreshDelete(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_T_refreshPresent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_refreshPresent_sequence, hf_index, ett_ldap_T_refreshPresent);

  return offset;
}


static const ber_sequence_t SET_OF_SyncUUID_set_of[1] = {
  { &hf_ldap_syncUUIDs_item , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ldap_SyncUUID },
};

static int
dissect_ldap_SET_OF_SyncUUID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_T_syncIdSet(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_SyncInfoValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_T_warning(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_T_error(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ldap_PasswordPolicyResponseValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PasswordPolicyResponseValue_sequence, hf_index, ett_ldap_PasswordPolicyResponseValue);

  return offset;
}

/*--- PDUs ---*/

static void dissect_LDAPMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ldap_LDAPMessage(FALSE, tvb, 0, &asn1_ctx, tree, hf_ldap_LDAPMessage_PDU);
}
static void dissect_SearchControlValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ldap_SearchControlValue(FALSE, tvb, 0, &asn1_ctx, tree, hf_ldap_SearchControlValue_PDU);
}
static void dissect_SortKeyList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ldap_SortKeyList(FALSE, tvb, 0, &asn1_ctx, tree, hf_ldap_SortKeyList_PDU);
}
static void dissect_SortResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ldap_SortResult(FALSE, tvb, 0, &asn1_ctx, tree, hf_ldap_SortResult_PDU);
}
static void dissect_DirSyncControlValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ldap_DirSyncControlValue(FALSE, tvb, 0, &asn1_ctx, tree, hf_ldap_DirSyncControlValue_PDU);
}
static void dissect_PasswdModifyRequestValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ldap_PasswdModifyRequestValue(FALSE, tvb, 0, &asn1_ctx, tree, hf_ldap_PasswdModifyRequestValue_PDU);
}
static void dissect_CancelRequestValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ldap_CancelRequestValue(FALSE, tvb, 0, &asn1_ctx, tree, hf_ldap_CancelRequestValue_PDU);
}
static void dissect_SyncRequestValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ldap_SyncRequestValue(FALSE, tvb, 0, &asn1_ctx, tree, hf_ldap_SyncRequestValue_PDU);
}
static void dissect_SyncStateValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ldap_SyncStateValue(FALSE, tvb, 0, &asn1_ctx, tree, hf_ldap_SyncStateValue_PDU);
}
static void dissect_SyncDoneValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ldap_SyncDoneValue(FALSE, tvb, 0, &asn1_ctx, tree, hf_ldap_SyncDoneValue_PDU);
}
static void dissect_SyncInfoValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ldap_SyncInfoValue(FALSE, tvb, 0, &asn1_ctx, tree, hf_ldap_SyncInfoValue_PDU);
}
static void dissect_PasswordPolicyResponseValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ldap_PasswordPolicyResponseValue(FALSE, tvb, 0, &asn1_ctx, tree, hf_ldap_PasswordPolicyResponseValue_PDU);
}


/*--- End of included file: packet-ldap-fn.c ---*/
#line 745 "../../asn1/ldap/packet-ldap-template.c"

static void
dissect_ldap_payload(tvbuff_t *tvb, packet_info *pinfo,
		     proto_tree *tree, ldap_conv_info_t *ldap_info,
		     gboolean is_mscldap)
{
  int offset = 0;
  guint length_remaining;
  guint msg_len = 0;
  int messageOffset = 0;
  guint headerLength = 0;
  guint length = 0;
  tvbuff_t *msg_tvb = NULL;
  gint8 ber_class;
  gboolean pc, ind = 0;
  gint32 ber_tag;

  attributedesc_string=NULL;


one_more_pdu:

    length_remaining = tvb_ensure_length_remaining(tvb, offset);

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
    msg_tvb = tvb_new_subset(tvb, offset, length, msg_len);

    /*
     * Now dissect the LDAP message.
     */
    ldap_info->is_mscldap = is_mscldap;
    pinfo->private_data = ldap_info;
    dissect_LDAPMessage_PDU(msg_tvb, pinfo, tree);

    offset += msg_len;

    /* If this was a sasl blob there might be another PDU following in the
     * same blob
     */
    if(tvb_length_remaining(tvb, offset)>=6){
        tvb = tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), -1);
	offset = 0;

        goto one_more_pdu;
    }

}

static void
ldap_frame_end(void)
{
   ldap_found_in_frame = FALSE;
}

static void
dissect_ldap_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean is_mscldap)
{
  int offset = 0;
  conversation_t *conversation;
  gboolean doing_sasl_security = FALSE;
  guint length_remaining;
  ldap_conv_info_t *ldap_info = NULL;
  proto_item *ldap_item = NULL;
  proto_tree *ldap_tree = NULL;

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
    ldap_info = g_malloc0(sizeof(ldap_conv_info_t));
    ldap_info->matched=g_hash_table_new(ldap_info_hash_matched, ldap_info_equal_matched);
    ldap_info->unmatched=g_hash_table_new(ldap_info_hash_unmatched, ldap_info_equal_unmatched);

    conversation_add_proto_data(conversation, proto_ldap, ldap_info);

    ldap_info->next = ldap_info_items;
    ldap_info_items = ldap_info;

  }

  switch (ldap_info->auth_type) {
    case LDAP_AUTH_SASL:
    /*
     * It's SASL; are we using a security layer?
     */
    if (ldap_info->first_auth_frame != 0 &&
       pinfo->fd->num >= ldap_info->first_auth_frame) {
	doing_sasl_security = TRUE;	/* yes */
    }
  }

    length_remaining = tvb_ensure_length_remaining(tvb, offset);

    /* It might still be a packet containing a SASL security layer
     * but its just that we never saw the BIND packet.
     * check if it looks like it could be a SASL blob here
     * and in that case just assume it is GSS-SPNEGO
     */
    if(!doing_sasl_security && (tvb_bytes_exist(tvb, offset, 5))
      &&(tvb_get_ntohl(tvb, offset)<=(guint)(tvb_reported_length_remaining(tvb, offset)-4))
      &&(tvb_get_guint8(tvb, offset+4)==0x60) ){
        ldap_info->auth_type=LDAP_AUTH_SASL;
        ldap_info->first_auth_frame=pinfo->fd->num;
        ldap_info->auth_mech=g_strdup("GSS-SPNEGO");
        doing_sasl_security=TRUE;
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
      register_frame_end_routine (ldap_frame_end);
      ldap_found_in_frame = TRUE;
    }

    ldap_item = proto_tree_add_item(tree, is_mscldap?proto_cldap:proto_ldap, tvb, 0, -1, FALSE);
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

    if (doing_sasl_security && tvb_get_guint8(tvb, offset) == 0) {
      proto_item *sasl_item = NULL;
      proto_tree *sasl_tree = NULL;
      tvbuff_t *sasl_tvb;
      guint sasl_len, sasl_msg_len, length;
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
      sasl_tvb = tvb_new_subset(tvb, offset, length, sasl_msg_len);

      if (ldap_tree) {
        proto_tree_add_uint(ldap_tree, hf_ldap_sasl_buffer_length, sasl_tvb, 0, 4,
                            sasl_len);

        sasl_item = proto_tree_add_text(ldap_tree, sasl_tvb, 0,  sasl_msg_len, "SASL Buffer");
        sasl_tree = proto_item_add_subtree(sasl_item, ett_ldap_sasl_blob);
      }

      if (ldap_info->auth_mech != NULL &&
          ((strcmp(ldap_info->auth_mech, "GSS-SPNEGO") == 0) ||
	   /* auth_mech may have been set from the bind */
	   (strcmp(ldap_info->auth_mech, "GSSAPI") == 0))) {
	  tvbuff_t *gssapi_tvb, *plain_tvb = NULL, *decr_tvb= NULL;
	  int ver_len;
	  int length;

          /*
           * This is GSS-API (using SPNEGO, but we should be done with
           * the negotiation by now).
           *
           * Dissect the GSS_Wrap() token; it'll return the length of
           * the token, from which we compute the offset in the tvbuff at
           * which the plaintext data, i.e. the LDAP message, begins.
           */
          length = tvb_length_remaining(sasl_tvb, 4);
          if ((guint)length > sasl_len)
              length = sasl_len;
	  gssapi_tvb = tvb_new_subset(sasl_tvb, 4, length, sasl_len);

	  /* Attempt decryption of the GSSAPI wrapped data if possible */
	  pinfo->decrypt_gssapi_tvb=DECRYPT_GSSAPI_NORMAL;
	  pinfo->gssapi_wrap_tvb=NULL;
	  pinfo->gssapi_encrypted_tvb=NULL;
	  pinfo->gssapi_decrypted_tvb=NULL;
          ver_len = call_dissector(gssapi_wrap_handle, gssapi_tvb, pinfo, sasl_tree);
	  /* if we could unwrap, do a tvb shuffle */
	  if(pinfo->gssapi_decrypted_tvb){
		decr_tvb=pinfo->gssapi_decrypted_tvb;
	  }
	  /* tidy up */
	  pinfo->decrypt_gssapi_tvb=0;
	  pinfo->gssapi_wrap_tvb=NULL;
	  pinfo->gssapi_encrypted_tvb=NULL;
	  pinfo->gssapi_decrypted_tvb=NULL;

          /*
           * if len is 0 it probably mean that we got a PDU that is not
           * aligned to the start of the segment.
           */
          if(ver_len==0){
             return;
          }

	  /*
	   * if we don't have unwrapped data,
	   * see if the wrapping involved encryption of the
	   * data; if not, just use the plaintext data.
	   */
	  if (!decr_tvb) {
	    if(!pinfo->gssapi_data_encrypted){
	      plain_tvb = tvb_new_subset_remaining(gssapi_tvb,  ver_len);
	    }
	  }

          if (decr_tvb) {
	    proto_item *enc_item = NULL;
	    proto_tree *enc_tree = NULL;

            /*
             * The LDAP message was encrypted in the packet, and has
             * been decrypted; dissect the decrypted LDAP message.
             */
	    col_set_str(pinfo->cinfo, COL_INFO, "SASL GSS-API Privacy (decrypted): ");

            if (sasl_tree) {
	      enc_item = proto_tree_add_text(sasl_tree, gssapi_tvb, ver_len, -1,
                                "GSS-API Encrypted payload (%d byte%s)",
                                sasl_len - ver_len,
                                plurality(sasl_len - ver_len, "", "s"));
	      enc_tree = proto_item_add_subtree(enc_item, ett_ldap_payload);
            }
	    dissect_ldap_payload(decr_tvb, pinfo, enc_tree, ldap_info, is_mscldap);
          } else if (plain_tvb) {
	    proto_item *plain_item = NULL;
	    proto_tree *plain_tree = NULL;

	    /*
	     * The LDAP message wasn't encrypted in the packet;
	     * dissect the plain LDAP message.
             */
	    col_set_str(pinfo->cinfo, COL_INFO, "SASL GSS-API Integrity: ");

	    if (sasl_tree) {
              plain_item = proto_tree_add_text(sasl_tree, gssapi_tvb, ver_len, -1,
                                "GSS-API payload (%d byte%s)",
                                sasl_len - ver_len,
                                plurality(sasl_len - ver_len, "", "s"));
	      plain_tree = proto_item_add_subtree(plain_item, ett_ldap_payload);
            }

           dissect_ldap_payload(plain_tvb, pinfo, plain_tree, ldap_info, is_mscldap);
	  } else {
            /*
             * The LDAP message was encrypted in the packet, and was
             * not decrypted; just show it as encrypted data.
             */
	    col_add_fstr(pinfo->cinfo, COL_INFO, "SASL GSS-API Privacy: payload (%d byte%s)",
			 sasl_len - ver_len,
			 plurality(sasl_len - ver_len, "", "s"));

	    if (sasl_tree) {
              proto_tree_add_text(sasl_tree, gssapi_tvb, ver_len, -1,
                                "GSS-API Encrypted payload (%d byte%s)",
                                sasl_len - ver_len,
                                plurality(sasl_len - ver_len, "", "s"));
	    }
          }
      }
    } else {
	/* plain LDAP, so dissect the payload */
	dissect_ldap_payload(tvb, pinfo, ldap_tree, ldap_info, is_mscldap);
    }
}

/*
 * prepend_dot is no longer used, but is being left in place in order to
 * maintain ABI compatibility.
 */
int dissect_mscldap_string(tvbuff_t *tvb, int offset, char *str, int max_len, gboolean prepend_dot _U_)
{
  int compr_len;
  const guchar *name;

  /* The name data MUST start at offset 0 of the tvb */
  compr_len = expand_dns_name(tvb, offset, max_len, 0, &name);
  g_strlcpy(str, name, max_len);
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
  guint32 flags;
  proto_item *item;
  proto_tree *tree=NULL;
  guint fields[] = {
             hf_mscldap_netlogon_flags_fnc,
             hf_mscldap_netlogon_flags_dnc,
             hf_mscldap_netlogon_flags_dns,
             hf_mscldap_netlogon_flags_wdc,
             hf_mscldap_netlogon_flags_rodc,
             hf_mscldap_netlogon_flags_ndnc,
             hf_mscldap_netlogon_flags_good_timeserv,
             hf_mscldap_netlogon_flags_writable,
             hf_mscldap_netlogon_flags_closest,
             hf_mscldap_netlogon_flags_timeserv,
             hf_mscldap_netlogon_flags_kdc,
             hf_mscldap_netlogon_flags_ds,
             hf_mscldap_netlogon_flags_ldap,
             hf_mscldap_netlogon_flags_gc,
             hf_mscldap_netlogon_flags_pdc,
             0 };
  guint  *field;
  header_field_info *hfi;
  gboolean one_bit_set = FALSE;

  flags=tvb_get_letohl(tvb, offset);
  item=proto_tree_add_item(parent_tree, hf_mscldap_netlogon_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  if(parent_tree){
    tree = proto_item_add_subtree(item, ett_mscldap_netlogon_flags);
  }

  proto_item_append_text(item, " (");

  for(field = fields; *field; field++) {
    proto_tree_add_boolean(tree, *field, tvb, offset, 4, flags);
    hfi = proto_registrar_get_nth(*field);

    if(flags & hfi->bitmask) {

      if(one_bit_set)
	proto_item_append_text(item, ", ");
      else
	one_bit_set = TRUE;

      proto_item_append_text(item, "%s", hfi->name);

    }
  }

  proto_item_append_text(item, ")");

  offset += 4;

  return offset;
}

static void dissect_NetLogon_PDU(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  int old_offset, offset=0;
  char str[256];
  guint16 itype;
  guint16 len;
  guint32 version;
  const char *fn;
  int fn_len;
  guint16 bc;
  proto_item *item;

  ldm_tree = NULL;


  /* Get the length of the buffer */
  len=tvb_length_remaining(tvb,offset);

  /* check the len if it is to small return */
  if (len < 10) return;

  /* Type */
  proto_tree_add_item(tree, hf_mscldap_netlogon_opcode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  itype = tvb_get_letohs(tvb, offset);
  offset += 2;

  /* get the version number from the end of the buffer, as the
     length is variable and the version determines what fields
	 need to be decoded */

  version = tvb_get_letohl(tvb,len-8);

  switch(itype){

		case LOGON_SAM_LOGON_RESPONSE:
			/* logon server name */
			fn = get_unicode_or_ascii_string(tvb,&offset,TRUE,&fn_len,FALSE,FALSE,&bc);
			proto_tree_add_string(tree, hf_mscldap_nb_hostname, tvb,offset, fn_len, fn);
			offset +=fn_len;

			/* username */
			fn = get_unicode_or_ascii_string(tvb,&offset,TRUE,&fn_len,FALSE,FALSE,&bc);
			proto_tree_add_string(tree, hf_mscldap_username, tvb,offset, fn_len, fn);
			offset +=fn_len;

			/* domain name */
			fn = get_unicode_or_ascii_string(tvb,&offset,TRUE,&fn_len,FALSE,FALSE,&bc);
			proto_tree_add_string(tree, hf_mscldap_nb_domain, tvb,offset, fn_len, fn);
			offset +=fn_len;

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
				offset=dissect_mscldap_string(tvb, offset, str, 255, FALSE);
				proto_tree_add_string(tree, hf_mscldap_forest, tvb, old_offset, offset-old_offset, str);

				/* Domain */
				old_offset=offset;
				offset=dissect_mscldap_string(tvb, offset, str, 255, FALSE);
				proto_tree_add_string(tree, hf_mscldap_domain, tvb, old_offset, offset-old_offset, str);

				/* Hostname */
				old_offset=offset;
				offset=dissect_mscldap_string(tvb, offset, str, 255, FALSE);
				proto_tree_add_string(tree, hf_mscldap_hostname, tvb, old_offset, offset-old_offset, str);

				/* DC IP Address */
				proto_tree_add_ipv4(tree, hf_mscldap_netlogon_ipaddress, tvb, offset, 4, tvb_get_ntohl(tvb,offset));
				offset += 4;

				/* Flags */
				offset = dissect_mscldap_netlogon_flags(tree, tvb, offset);

			}

			break;

		case LOGON_SAM_LOGON_RESPONSE_EX:
			/* MS-ADTS 7.3.1.9 */
			offset += 2; /* Skip over "Sbz" field (MUST be set to 0) */

			/* Flags */
			offset = dissect_mscldap_netlogon_flags(tree, tvb, offset);

			/* Domain GUID */
			proto_tree_add_item(tree, hf_mscldap_domain_guid, tvb, offset, 16, ENC_LITTLE_ENDIAN);
			offset += 16;

			/* Forest */
			old_offset=offset;
			offset=dissect_mscldap_string(tvb, offset, str, 255, FALSE);
			proto_tree_add_string(tree, hf_mscldap_forest, tvb, old_offset, offset-old_offset, str);

			/* Domain */
			old_offset=offset;
			offset=dissect_mscldap_string(tvb, offset, str, 255, FALSE);
			proto_tree_add_string(tree, hf_mscldap_domain, tvb, old_offset, offset-old_offset, str);

			/* Hostname */
			old_offset=offset;
			offset=dissect_mscldap_string(tvb, offset, str, 255, FALSE);
			proto_tree_add_string(tree, hf_mscldap_hostname, tvb, old_offset, offset-old_offset, str);

			/* NetBIOS Domain */
			old_offset=offset;
			offset=dissect_mscldap_string(tvb, offset, str, 255, FALSE);
			proto_tree_add_string(tree, hf_mscldap_nb_domain, tvb, old_offset, offset-old_offset, str);

			/* NetBIOS Hostname */
			old_offset=offset;
			offset=dissect_mscldap_string(tvb, offset, str, 255, FALSE);
			proto_tree_add_string(tree, hf_mscldap_nb_hostname, tvb, old_offset, offset-old_offset, str);

			/* User */
			old_offset=offset;
			offset=dissect_mscldap_string(tvb, offset, str, 255, FALSE);
			proto_tree_add_string(tree, hf_mscldap_username, tvb, old_offset, offset-old_offset, str);

			/* Server Site */
			old_offset=offset;
			offset=dissect_mscldap_string(tvb, offset, str, 255, FALSE);
			proto_tree_add_string(tree, hf_mscldap_sitename, tvb, old_offset, offset-old_offset, str);

			/* Client Site */
			old_offset=offset;
			offset=dissect_mscldap_string(tvb, offset, str, 255, FALSE);
			proto_tree_add_string(tree, hf_mscldap_clientsitename, tvb, old_offset, offset-old_offset, str);

			/* include the extra fields for version 5 with IP s */
			if ((version & NETLOGON_NT_VERSION_5EX_WITH_IP) == NETLOGON_NT_VERSION_5EX_WITH_IP){
				/* The ip address is returned as a sockaddr_in structure
				 *
				 *  This section may need to be updated if the base Windows APIs
				 *  are changed to support ipv6, which currently is not the case.
				 *
				 *  The desector assumes the length is based on ipv4 and
				 *  ignores the length
				 */

				/* skip the length of the sockaddr_in */

				offset +=1;

				/* add IP address and desect the sockaddr_in structure */

				old_offset = offset + 4;
				item = proto_tree_add_ipv4(tree, hf_mscldap_netlogon_ipaddress, tvb, old_offset, 4, tvb_get_ipv4(tvb,old_offset));

				if (tree){
					proto_tree *subtree;

					subtree = proto_item_add_subtree(item, ett_mscldap_ipdetails);

					/* get sockaddr family */
					proto_tree_add_item(subtree, hf_mscldap_netlogon_ipaddress_family, tvb, offset, 2, ENC_LITTLE_ENDIAN);
					offset +=2;

					/* get sockaddr port */
					proto_tree_add_item(subtree, hf_mscldap_netlogon_ipaddress_port, tvb, offset, 2, ENC_LITTLE_ENDIAN);
					offset +=2;

					/* get IP address */
					proto_tree_add_ipv4(subtree, hf_mscldap_netlogon_ipaddress_ipv4, tvb, offset, 4, tvb_get_ipv4(tvb,offset));
					offset +=4;

					/* skip the 8 bytes of zeros in the sockaddr structure */
					offset += 8;
				}

			}

			break;
  }


 /* complete the decode with the version and token details */

  offset = len-8;

  /* NETLOGON_NT_VERISON Options (MS-ADTS 7.3.1.1) */
  offset = dissect_mscldap_ntver_flags(tree, tvb, offset);

  /* LM Token */
  proto_tree_add_item(tree, hf_mscldap_netlogon_lm_token, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  /* NT Token */
  proto_tree_add_item(tree, hf_mscldap_netlogon_nt_token, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

}


static guint
get_sasl_ldap_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	/* sasl encapsulated ldap is 4 bytes plus the length in size */
	return tvb_get_ntohl(tvb, offset)+4;
}

static void
dissect_sasl_ldap_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_ldap_pdu(tvb, pinfo, tree, FALSE);
	return;
}

static guint
get_normal_ldap_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	guint32 len;
	gboolean ind;
	int data_offset;

	/* normal ldap is tag+len bytes plus the length
	 * offset is where the tag is
	 * offset+1 is where length starts
	 */
	data_offset=get_ber_length(tvb, offset+1, &len, &ind);
	return len+data_offset-offset;
}

static void
dissect_normal_ldap_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_ldap_pdu(tvb, pinfo, tree, FALSE);
	return;
}

static void
dissect_ldap_oid(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	char *oid;
	const char *oidname;

	/* tvb here contains an ascii string that is really an oid */
/* XXX   we should convert the string oid into a real oid so we can use
 *       proto_tree_add_oid() instead.
 */

	oid=tvb_get_ephemeral_string(tvb, 0, tvb_length(tvb));
	if(!oid){
		return;
	}

	oidname=oid_resolved_from_string(oid);

	if(oidname){
		proto_tree_add_text(tree, tvb, 0, tvb_length(tvb), "OID: %s (%s)",oid,oidname);
	} else {
		proto_tree_add_text(tree, tvb, 0, tvb_length(tvb), "OID: %s",oid);
	}
}

#define LDAP_ACCESSMASK_ADS_CREATE_CHILD	0x00000001
static const true_false_string ldap_AccessMask_ADS_CREATE_CHILD_tfs = {
   "ADS CREATE CHILD is SET",
   "Ads create child is NOT set",
};

#define LDAP_ACCESSMASK_ADS_DELETE_CHILD	0x00000002
static const true_false_string ldap_AccessMask_ADS_DELETE_CHILD_tfs = {
   "ADS DELETE CHILD is SET",
   "Ads delete child is NOT set",
};
#define LDAP_ACCESSMASK_ADS_LIST		0x00000004
static const true_false_string ldap_AccessMask_ADS_LIST_tfs = {
   "ADS LIST is SET",
   "Ads list is NOT set",
};
#define LDAP_ACCESSMASK_ADS_SELF_WRITE		0x00000008
static const true_false_string ldap_AccessMask_ADS_SELF_WRITE_tfs = {
   "ADS SELF WRITE is SET",
   "Ads self write is NOT set",
};
#define LDAP_ACCESSMASK_ADS_READ_PROP		0x00000010
static const true_false_string ldap_AccessMask_ADS_READ_PROP_tfs = {
   "ADS READ PROP is SET",
   "Ads read prop is NOT set",
};
#define LDAP_ACCESSMASK_ADS_WRITE_PROP		0x00000020
static const true_false_string ldap_AccessMask_ADS_WRITE_PROP_tfs = {
   "ADS WRITE PROP is SET",
   "Ads write prop is NOT set",
};
#define LDAP_ACCESSMASK_ADS_DELETE_TREE		0x00000040
static const true_false_string ldap_AccessMask_ADS_DELETE_TREE_tfs = {
   "ADS DELETE TREE is SET",
   "Ads delete tree is NOT set",
};
#define LDAP_ACCESSMASK_ADS_LIST_OBJECT		0x00000080
static const true_false_string ldap_AccessMask_ADS_LIST_OBJECT_tfs = {
   "ADS LIST OBJECT is SET",
   "Ads list object is NOT set",
};
#define LDAP_ACCESSMASK_ADS_CONTROL_ACCESS	0x00000100
static const true_false_string ldap_AccessMask_ADS_CONTROL_ACCESS_tfs = {
   "ADS CONTROL ACCESS is SET",
   "Ads control access is NOT set",
};

static void
ldap_specific_rights(tvbuff_t *tvb, gint offset, proto_tree *tree, guint32 access)
{
	proto_tree_add_boolean(tree, hf_ldap_AccessMask_ADS_CONTROL_ACCESS, tvb, offset, 4, access);

	proto_tree_add_boolean(tree, hf_ldap_AccessMask_ADS_LIST_OBJECT, tvb, offset, 4, access);

	proto_tree_add_boolean(tree, hf_ldap_AccessMask_ADS_DELETE_TREE, tvb, offset, 4, access);

	proto_tree_add_boolean(tree, hf_ldap_AccessMask_ADS_WRITE_PROP, tvb, offset, 4, access);

	proto_tree_add_boolean(tree, hf_ldap_AccessMask_ADS_READ_PROP, tvb, offset, 4, access);

	proto_tree_add_boolean(tree, hf_ldap_AccessMask_ADS_SELF_WRITE, tvb, offset, 4, access);

	proto_tree_add_boolean(tree, hf_ldap_AccessMask_ADS_LIST, tvb, offset, 4, access);

	proto_tree_add_boolean(tree, hf_ldap_AccessMask_ADS_DELETE_CHILD, tvb, offset, 4, access);

	proto_tree_add_boolean(tree, hf_ldap_AccessMask_ADS_CREATE_CHILD, tvb, offset, 4, access);
}
struct access_mask_info ldap_access_mask_info = {
	"LDAP",			/* Name of specific rights */
	ldap_specific_rights,	/* Dissection function */
	NULL,			/* Generic mapping table */
	NULL			/* Standard mapping table */
};

static void
dissect_ldap_nt_sec_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_nt_sec_desc(tvb, 0, pinfo, tree, NULL, TRUE, tvb_length(tvb), &ldap_access_mask_info);
}

static void
dissect_ldap_sid(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	char *tmpstr;

	/* this octet string contains an NT SID */
	dissect_nt_sid(tvb, 0, tree, "SID", &tmpstr, hf_ldap_sid);
	ldapvalue_string=tmpstr;
}

static void
dissect_ldap_guid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 drep[4] = { 0x10, 0x00, 0x00, 0x00}; /* fake DREP struct */
	e_uuid_t uuid;

	/* This octet string contained a GUID */
	dissect_dcerpc_uuid_t(tvb, 0, pinfo, tree, drep, hf_ldap_guid, &uuid);

	ldapvalue_string=ep_alloc(1024);
	g_snprintf(ldapvalue_string, 1023, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                   uuid.Data1, uuid.Data2, uuid.Data3,
                   uuid.Data4[0], uuid.Data4[1],
                   uuid.Data4[2], uuid.Data4[3],
                   uuid.Data4[4], uuid.Data4[5],
                   uuid.Data4[6], uuid.Data4[7]);
}

static void
dissect_ldap_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 sasl_len;
	guint32 ldap_len;
	gboolean ind;
	conversation_t *conversation;
	ldap_conv_info_t *ldap_info = NULL;

	/*
	 * Do we have a conversation for this connection?
	 */
	conversation = find_conversation(pinfo->fd->num,
					 &pinfo->src, &pinfo->dst,
					 pinfo->ptype, pinfo->srcport,
					 pinfo->destport, 0);
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

	tcp_dissect_pdus(tvb, pinfo, tree, ldap_desegment, 4, get_sasl_ldap_pdu_len, dissect_sasl_ldap_pdu);
	return;

this_was_not_sasl:
	/* check if it is a normal BER encoded LDAP packet
	 * i.e. first byte is 0x30 followed by a length that is
	 * <64k
	 * (no ldap PDUs are ever >64kb? )
	 */
	if(tvb_get_guint8(tvb, 0)!=0x30){
		goto this_was_not_normal_ldap;
	}

	/* check that length makes sense */
	get_ber_length(tvb, 1, &ldap_len, &ind);

	/* dont check ind since indefinite length is never used for ldap (famous last words)*/
	if(ldap_len<2){
		goto this_was_not_normal_ldap;
	}

	/*
	 * The minimun size of a LDAP pdu is 7 bytes
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
	tcp_dissect_pdus(tvb, pinfo, tree, ldap_desegment, 7, get_normal_ldap_pdu_len, dissect_normal_ldap_pdu);

	goto end;

this_was_not_normal_ldap:

	/* perhaps it was SSL? */
	if(ldap_info &&
	   ldap_info->start_tls_frame &&
	   ( pinfo->fd->num >= ldap_info->start_tls_frame)) {

	  /* we have started TLS and so this may be an SSL layer */
	  guint32 old_start_tls_frame;

	  /* temporarily dissect this port as SSL */
	  dissector_delete_uint("tcp.port", tcp_port, ldap_handle);
	  ssl_dissector_add(tcp_port, "ldap", TRUE);

	  old_start_tls_frame = ldap_info->start_tls_frame;
	  ldap_info->start_tls_frame = 0; /* make sure we don't call SSL again */
	  pinfo->can_desegment++; /* ignore this LDAP layer so SSL can use the TCP resegment */

	  call_dissector(ssl_handle, tvb, pinfo, tree);

	  ldap_info->start_tls_frame = old_start_tls_frame;
	  ssl_dissector_delete(tcp_port, "ldap", TRUE);

	  /* restore ldap as the dissector for this port */
	  dissector_add_uint("tcp.port", tcp_port, ldap_handle);

	  /* we are done */
	  return;
	}
 end:
	return;
}

static void
dissect_mscldap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_ldap_pdu(tvb, pinfo, tree, TRUE);
	return;
}


static void
ldap_reinit(void)
{
  ldap_conv_info_t *ldap_info;

  /* Free up state attached to the ldap_info structures */
  for (ldap_info = ldap_info_items; ldap_info != NULL; ) {
    ldap_conv_info_t *next;

    g_free(ldap_info->auth_mech);
    g_hash_table_destroy(ldap_info->matched);
    g_hash_table_destroy(ldap_info->unmatched);

    next = ldap_info->next;
    g_free(ldap_info);
    ldap_info = next;
  }

  ldap_info_items = NULL;
}

void
register_ldap_name_dissector_handle(const char *attr_type_p, dissector_handle_t dissector)
{
	dissector_add_string("ldap.name", attr_type_p, dissector);
}

void
register_ldap_name_dissector(const char *attr_type_p, dissector_t dissector, int proto)
{
	dissector_handle_t dissector_handle;

	dissector_handle=create_dissector_handle(dissector, proto);
	register_ldap_name_dissector_handle(attr_type_p, dissector_handle);
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

    { &hf_mscldap_nb_domain,
      { "NetBIOS Domain", "mscldap.nb_domain",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "NetBIOS name of the NC", HFILL }},

    { &hf_mscldap_nb_hostname,
      { "NetBIOS Hostname", "mscldap.nb_hostname",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "NetBIOS name of the server", HFILL }},

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
        TFS(&tfs_ntver_v1), 0x00000001, "See section 7.3.1.1 of MS-ADTS specification", HFILL }},

    { &hf_mscldap_ntver_flags_v5,
      { "V5", "mscldap.ntver.searchflags.v5", FT_BOOLEAN, 32,
        TFS(&tfs_ntver_v5), 0x00000002, "See section 7.3.1.1 of MS-ADTS specification", HFILL }},

    { &hf_mscldap_ntver_flags_v5ex,
      { "V5EX", "mscldap.ntver.searchflags.v5ex", FT_BOOLEAN, 32,
        TFS(&tfs_ntver_v5ex), 0x00000004, "See section 7.3.1.1 of MS-ADTS specification", HFILL }},

    { &hf_mscldap_ntver_flags_v5ep,
      { "V5EP", "mscldap.ntver.searchflags.v5ep", FT_BOOLEAN, 32,
        TFS(&tfs_ntver_v5ep), 0x00000008, "See section 7.3.1.1 of MS-ADTS specification", HFILL }},

    { &hf_mscldap_ntver_flags_vcs,
      { "VCS", "mscldap.ntver.searchflags.vcs", FT_BOOLEAN, 32,
        TFS(&tfs_ntver_vcs), 0x00000010, "See section 7.3.1.1 of MS-ADTS specification", HFILL }},

    { &hf_mscldap_ntver_flags_vnt4,
      { "VNT4", "mscldap.ntver.searchflags.vnt4", FT_BOOLEAN, 32,
        TFS(&tfs_ntver_vnt4), 0x01000000, "See section 7.3.1.1 of MS-ADTS specification", HFILL }},

    { &hf_mscldap_ntver_flags_vpdc,
      { "VPDC", "mscldap.ntver.searchflags.vpdc", FT_BOOLEAN, 32,
        TFS(&tfs_ntver_vpdc), 0x10000000, "See section 7.3.1.1 of MS-ADTS specification", HFILL }},

    { &hf_mscldap_ntver_flags_vip,
      { "VIP", "mscldap.ntver.searchflags.vip", FT_BOOLEAN, 32,
        TFS(&tfs_ntver_vip), 0x20000000, "See section 7.3.1.1 of MS-ADTS specification", HFILL }},

    { &hf_mscldap_ntver_flags_vl,
      { "VL", "mscldap.ntver.searchflags.vl", FT_BOOLEAN, 32,
        TFS(&tfs_ntver_vl), 0x40000000, "See section 7.3.1.1 of MS-ADTS specification", HFILL }},

    { &hf_mscldap_ntver_flags_vgc,
      { "VGC", "mscldap.ntver.searchflags.vgc", FT_BOOLEAN, 32,
        TFS(&tfs_ntver_vgc), 0x80000000, "See section 7.3.1.1 of MS-ADTS specification", HFILL }},


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
      { "WDC", "mscldap.netlogon.flags.writabledc.", FT_BOOLEAN, 32,
        TFS(&tfs_ads_wdc), 0x00001000, "Is this an writable dc (Windows 2008)?", HFILL }},

    { &hf_mscldap_netlogon_flags_dns,
      { "DNS", "mscldap.netlogon.flags.dnsname", FT_BOOLEAN, 32,
        TFS(&tfs_ads_dns), 0x20000000, "Does the server have a dns name (Windows 2008)?", HFILL }},

    { &hf_mscldap_netlogon_flags_dnc,
      { "DNC", "mscldap.netlogon.flags.defaultnc", FT_BOOLEAN, 32,
        TFS(&tfs_ads_dnc), 0x40000000, "Is this the default NC (Windows 2008)?", HFILL }},

    { &hf_mscldap_netlogon_flags_fnc,
      { "FDC", "mscldap.netlogon.flags.forestnc", FT_BOOLEAN, 32,
        TFS(&tfs_ads_fnc), 0x80000000, "Is the the NC the default forest root(Windows 2008)?", HFILL }},

    { &hf_ldap_guid,
      { "GUID", "ldap.guid", FT_GUID, BASE_NONE,
        NULL, 0, NULL, HFILL }},

    { &hf_ldap_AccessMask_ADS_CREATE_CHILD,
      { "Create Child", "ldap.AccessMask.ADS_CREATE_CHILD", FT_BOOLEAN, 32, TFS(&ldap_AccessMask_ADS_CREATE_CHILD_tfs), LDAP_ACCESSMASK_ADS_CREATE_CHILD, NULL, HFILL }},

    { &hf_ldap_AccessMask_ADS_DELETE_CHILD,
      { "Delete Child", "ldap.AccessMask.ADS_DELETE_CHILD", FT_BOOLEAN, 32, TFS(&ldap_AccessMask_ADS_DELETE_CHILD_tfs), LDAP_ACCESSMASK_ADS_DELETE_CHILD, NULL, HFILL }},

    { &hf_ldap_AccessMask_ADS_LIST,
      { "List", "ldap.AccessMask.ADS_LIST", FT_BOOLEAN, 32, TFS(&ldap_AccessMask_ADS_LIST_tfs), LDAP_ACCESSMASK_ADS_LIST, NULL, HFILL }},

    { &hf_ldap_AccessMask_ADS_SELF_WRITE,
      { "Self Write", "ldap.AccessMask.ADS_SELF_WRITE", FT_BOOLEAN, 32, TFS(&ldap_AccessMask_ADS_SELF_WRITE_tfs), LDAP_ACCESSMASK_ADS_SELF_WRITE, NULL, HFILL }},

    { &hf_ldap_AccessMask_ADS_READ_PROP,
      { "Read Prop", "ldap.AccessMask.ADS_READ_PROP", FT_BOOLEAN, 32, TFS(&ldap_AccessMask_ADS_READ_PROP_tfs), LDAP_ACCESSMASK_ADS_READ_PROP, NULL, HFILL }},

    { &hf_ldap_AccessMask_ADS_WRITE_PROP,
      { "Write Prop", "ldap.AccessMask.ADS_WRITE_PROP", FT_BOOLEAN, 32, TFS(&ldap_AccessMask_ADS_WRITE_PROP_tfs), LDAP_ACCESSMASK_ADS_WRITE_PROP, NULL, HFILL }},

    { &hf_ldap_AccessMask_ADS_DELETE_TREE,
      { "Delete Tree", "ldap.AccessMask.ADS_DELETE_TREE", FT_BOOLEAN, 32, TFS(&ldap_AccessMask_ADS_DELETE_TREE_tfs), LDAP_ACCESSMASK_ADS_DELETE_TREE, NULL, HFILL }},

    { &hf_ldap_AccessMask_ADS_LIST_OBJECT,
      { "List Object", "ldap.AccessMask.ADS_LIST_OBJECT", FT_BOOLEAN, 32, TFS(&ldap_AccessMask_ADS_LIST_OBJECT_tfs), LDAP_ACCESSMASK_ADS_LIST_OBJECT, NULL, HFILL }},

    { &hf_ldap_AccessMask_ADS_CONTROL_ACCESS,
      { "Control Access", "ldap.AccessMask.ADS_CONTROL_ACCESS", FT_BOOLEAN, 32, TFS(&ldap_AccessMask_ADS_CONTROL_ACCESS_tfs), LDAP_ACCESSMASK_ADS_CONTROL_ACCESS, NULL, HFILL }},


/*--- Included file: packet-ldap-hfarr.c ---*/
#line 1 "../../asn1/ldap/packet-ldap-hfarr.c"
    { &hf_ldap_LDAPMessage_PDU,
      { "LDAPMessage", "ldap.LDAPMessage",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_SearchControlValue_PDU,
      { "SearchControlValue", "ldap.SearchControlValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_SortKeyList_PDU,
      { "SortKeyList", "ldap.SortKeyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_SortResult_PDU,
      { "SortResult", "ldap.SortResult",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_DirSyncControlValue_PDU,
      { "DirSyncControlValue", "ldap.DirSyncControlValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_PasswdModifyRequestValue_PDU,
      { "PasswdModifyRequestValue", "ldap.PasswdModifyRequestValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_CancelRequestValue_PDU,
      { "CancelRequestValue", "ldap.CancelRequestValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_SyncRequestValue_PDU,
      { "SyncRequestValue", "ldap.SyncRequestValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_SyncStateValue_PDU,
      { "SyncStateValue", "ldap.SyncStateValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_SyncDoneValue_PDU,
      { "SyncDoneValue", "ldap.SyncDoneValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_SyncInfoValue_PDU,
      { "SyncInfoValue", "ldap.SyncInfoValue",
        FT_UINT32, BASE_DEC, VALS(ldap_SyncInfoValue_vals), 0,
        NULL, HFILL }},
    { &hf_ldap_PasswordPolicyResponseValue_PDU,
      { "PasswordPolicyResponseValue", "ldap.PasswordPolicyResponseValue",
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
      { "bindRequest", "ldap.bindRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_bindResponse,
      { "bindResponse", "ldap.bindResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_unbindRequest,
      { "unbindRequest", "ldap.unbindRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_searchRequest,
      { "searchRequest", "ldap.searchRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_searchResEntry,
      { "searchResEntry", "ldap.searchResEntry",
        FT_NONE, BASE_NONE, NULL, 0,
        "SearchResultEntry", HFILL }},
    { &hf_ldap_searchResDone,
      { "searchResDone", "ldap.searchResDone",
        FT_NONE, BASE_NONE, NULL, 0,
        "SearchResultDone", HFILL }},
    { &hf_ldap_searchResRef,
      { "searchResRef", "ldap.searchResRef",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SearchResultReference", HFILL }},
    { &hf_ldap_modifyRequest,
      { "modifyRequest", "ldap.modifyRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_modifyResponse,
      { "modifyResponse", "ldap.modifyResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_addRequest,
      { "addRequest", "ldap.addRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_addResponse,
      { "addResponse", "ldap.addResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_delRequest,
      { "delRequest", "ldap.delRequest",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_delResponse,
      { "delResponse", "ldap.delResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_modDNRequest,
      { "modDNRequest", "ldap.modDNRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyDNRequest", HFILL }},
    { &hf_ldap_modDNResponse,
      { "modDNResponse", "ldap.modDNResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyDNResponse", HFILL }},
    { &hf_ldap_compareRequest,
      { "compareRequest", "ldap.compareRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_compareResponse,
      { "compareResponse", "ldap.compareResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_abandonRequest,
      { "abandonRequest", "ldap.abandonRequest",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_extendedReq,
      { "extendedReq", "ldap.extendedReq",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExtendedRequest", HFILL }},
    { &hf_ldap_extendedResp,
      { "extendedResp", "ldap.extendedResp",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExtendedResponse", HFILL }},
    { &hf_ldap_intermediateResponse,
      { "intermediateResponse", "ldap.intermediateResponse",
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
      { "Control", "ldap.Control",
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
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_sasl,
      { "sasl", "ldap.sasl",
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
      { "equalityMatch", "ldap.equalityMatch",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_substrings,
      { "substrings", "ldap.substrings",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubstringFilter", HFILL }},
    { &hf_ldap_greaterOrEqual,
      { "greaterOrEqual", "ldap.greaterOrEqual",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_lessOrEqual,
      { "lessOrEqual", "ldap.lessOrEqual",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_present,
      { "present", "ldap.present",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_approxMatch,
      { "approxMatch", "ldap.approxMatch",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_extensibleMatch,
      { "extensibleMatch", "ldap.extensibleMatch",
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
      { "PartialAttributeList item", "ldap.PartialAttributeList_item",
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
      { "modification item", "ldap.modification_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_modifyRequest_modification_item", HFILL }},
    { &hf_ldap_operation,
      { "operation", "ldap.operation",
        FT_UINT32, BASE_DEC, VALS(ldap_T_operation_vals), 0,
        NULL, HFILL }},
    { &hf_ldap_modification,
      { "modification", "ldap.modification",
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
      { "AttributeList item", "ldap.AttributeList_item",
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
      { "ava", "ldap.ava",
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
      { "SortKeyList item", "ldap.SortKeyList_item",
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
    { &hf_ldap_value,
      { "value", "ldap.value",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ldap_flags,
      { "flags", "ldap.flags",
        FT_INT32, BASE_DEC, NULL, 0,
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
    { &hf_ldap_genPasswd,
      { "genPasswd", "ldap.genPasswd",
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
      { "refreshDelete", "ldap.refreshDelete",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_refreshDone,
      { "refreshDone", "ldap.refreshDone",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ldap_refreshPresent,
      { "refreshPresent", "ldap.refreshPresent",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ldap_syncIdSet,
      { "syncIdSet", "ldap.syncIdSet",
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

/*--- End of included file: packet-ldap-hfarr.c ---*/
#line 2069 "../../asn1/ldap/packet-ldap-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_ldap,
    &ett_ldap_payload,
    &ett_ldap_sasl_blob,
    &ett_ldap_msg,
    &ett_mscldap_netlogon_flags,
    &ett_mscldap_ntver_flags,
    &ett_mscldap_ipdetails,


/*--- Included file: packet-ldap-ettarr.c ---*/
#line 1 "../../asn1/ldap/packet-ldap-ettarr.c"
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
    &ett_ldap_DirSyncFlagsSubEntry,
    &ett_ldap_DirSyncControlValue,
    &ett_ldap_PasswdModifyRequestValue,
    &ett_ldap_PasswdModifyResponseValue,
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

/*--- End of included file: packet-ldap-ettarr.c ---*/
#line 2082 "../../asn1/ldap/packet-ldap-template.c"
  };

    module_t *ldap_module;

  /* Register protocol */
  proto_ldap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_ldap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));


  register_dissector("ldap", dissect_ldap_tcp, proto_ldap);

  ldap_module = prefs_register_protocol(proto_ldap, prefs_register_ldap);
  prefs_register_bool_preference(ldap_module, "desegment_ldap_messages",
    "Reassemble LDAP messages spanning multiple TCP segments",
    "Whether the LDAP dissector should reassemble messages spanning multiple TCP segments."
    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &ldap_desegment);

  prefs_register_uint_preference(ldap_module, "tcp.port", "LDAP TCP Port",
				 "Set the port for LDAP operations",
				 10, &global_ldap_tcp_port);

  prefs_register_uint_preference(ldap_module, "ssl.port", "LDAPS TCP Port",
				 "Set the port for LDAP operations over SSL",
				 10, &global_ldaps_tcp_port);

  prefs_register_obsolete_preference(ldap_module, "max_pdu");

  proto_cldap = proto_register_protocol(
	  "Connectionless Lightweight Directory Access Protocol",
	  "CLDAP", "cldap");

  register_init_routine(ldap_reinit);
  ldap_tap=register_tap("ldap");

  ldap_name_dissector_table = register_dissector_table("ldap.name", "LDAP Attribute Type Dissectors", FT_STRING, BASE_NONE);

}


/*--- proto_reg_handoff_ldap ---------------------------------------*/
void
proto_reg_handoff_ldap(void)
{
	dissector_handle_t cldap_handle;
	ldap_handle = find_dissector("ldap");

	dissector_add_uint("tcp.port", TCP_PORT_GLOBALCAT_LDAP, ldap_handle);

	cldap_handle = create_dissector_handle(dissect_mscldap, proto_cldap);
	dissector_add_uint("udp.port", UDP_PORT_CLDAP, cldap_handle);

	gssapi_handle = find_dissector("gssapi");
	gssapi_wrap_handle = find_dissector("gssapi_verf");
	spnego_handle = find_dissector("spnego");

	ntlmssp_handle = find_dissector("ntlmssp");

	ssl_handle = find_dissector("ssl");

	prefs_register_ldap();

/*  http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dsml/dsml/ldap_controls_and_session_support.asp */
	oid_add_from_string("LDAP_PAGED_RESULT_OID_STRING","1.2.840.113556.1.4.319");
	oid_add_from_string("LDAP_SERVER_SHOW_DELETED_OID","1.2.840.113556.1.4.417");
	oid_add_from_string("LDAP_SERVER_SORT_OID","1.2.840.113556.1.4.473");
	oid_add_from_string("LDAP_CONTROL_SORT_RESP_OID","1.2.840.113556.1.4.474");
	oid_add_from_string("LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID","1.2.840.113556.1.4.521");
	oid_add_from_string("LDAP_SERVER_NOTIFICATION_OID","1.2.840.113556.1.4.528");
	oid_add_from_string("LDAP_SERVER_EXTENDED_DN_OID","1.2.840.113556.1.4.529");
	oid_add_from_string("meetingAdvertiseScope","1.2.840.113556.1.4.582");
	oid_add_from_string("LDAP_SERVER_LAZY_COMMIT_OID","1.2.840.113556.1.4.619");
	oid_add_from_string("mhsORAddress","1.2.840.113556.1.4.650");
	oid_add_from_string("managedObjects","1.2.840.113556.1.4.654");
	oid_add_from_string("LDAP_CAP_ACTIVE_DIRECTORY_OID","1.2.840.113556.1.4.800");
	oid_add_from_string("LDAP_SERVER_SD_FLAGS_OID","1.2.840.113556.1.4.801");
	oid_add_from_string("LDAP_OID_COMPARATOR_OR","1.2.840.113556.1.4.804");
	oid_add_from_string("LDAP_SERVER_TREE_DELETE_OID","1.2.840.113556.1.4.805");
	oid_add_from_string("LDAP_SERVER_DIRSYNC_OID","1.2.840.113556.1.4.841");
	oid_add_from_string("None","1.2.840.113556.1.4.970");
	oid_add_from_string("LDAP_SERVER_VERIFY_NAME_OID","1.2.840.113556.1.4.1338");
	oid_add_from_string("LDAP_SERVER_DOMAIN_SCOPE_OID","1.2.840.113556.1.4.1339");
	oid_add_from_string("LDAP_SERVER_SEARCH_OPTIONS_OID","1.2.840.113556.1.4.1340");
	oid_add_from_string("LDAP_SERVER_PERMISSIVE_MODIFY_OID","1.2.840.113556.1.4.1413");
	oid_add_from_string("LDAP_SERVER_ASQ_OID","1.2.840.113556.1.4.1504");
	oid_add_from_string("LDAP_CAP_ACTIVE_DIRECTORY_V51_OID","1.2.840.113556.1.4.1670");
	oid_add_from_string("LDAP_SERVER_FAST_BIND_OID","1.2.840.113556.1.4.1781");
	oid_add_from_string("LDAP_CAP_ACTIVE_DIRECTORY_LDAP_INTEG_OID","1.2.840.113556.1.4.1791");
	oid_add_from_string("msDS-ObjectReference","1.2.840.113556.1.4.1840");
	oid_add_from_string("msDS-QuotaEffective","1.2.840.113556.1.4.1848");
	oid_add_from_string("LDAP_CAP_ACTIVE_DIRECTORY_ADAM_OID","1.2.840.113556.1.4.1851");
	oid_add_from_string("msDS-PortSSL","1.2.840.113556.1.4.1860");
	oid_add_from_string("msDS-isRODC","1.2.840.113556.1.4.1960");
	oid_add_from_string("msDS-SDReferenceDomain","1.2.840.113556.1.4.1711");
	oid_add_from_string("msDS-AdditionalDnsHostName","1.2.840.113556.1.4.1717");
	oid_add_from_string("None","1.3.6.1.4.1.1466.101.119.1");
	oid_add_from_string("LDAP_START_TLS_OID","1.3.6.1.4.1.1466.20037");
	oid_add_from_string("LDAP_CONTROL_VLVREQUEST VLV","2.16.840.1.113730.3.4.9");
	oid_add_from_string("LDAP_CONTROL_VLVRESPONSE VLV","2.16.840.1.113730.3.4.10");
	oid_add_from_string("LDAP_SERVER_QUOTA_CONTROL_OID","1.2.840.113556.1.4.1852");
	oid_add_from_string("LDAP_SERVER_RANGE_OPTION_OID","1.2.840.113556.1.4.802");
	oid_add_from_string("LDAP_SERVER_SHUTDOWN_NOTIFY_OID","1.2.840.113556.1.4.1907");
	oid_add_from_string("LDAP_SERVER_RANGE_RETRIEVAL_NOERR_OID","1.2.840.113556.1.4.1948");

	register_ldap_name_dissector("netlogon", dissect_NetLogon_PDU, proto_cldap);
	register_ldap_name_dissector("objectGUID", dissect_ldap_guid, proto_ldap);
	register_ldap_name_dissector("supportedControl", dissect_ldap_oid, proto_ldap);
	register_ldap_name_dissector("supportedCapabilities", dissect_ldap_oid, proto_ldap);
	register_ldap_name_dissector("objectSid", dissect_ldap_sid, proto_ldap);
	register_ldap_name_dissector("nTSecurityDescriptor", dissect_ldap_nt_sec_desc, proto_ldap);


/*--- Included file: packet-ldap-dis-tab.c ---*/
#line 1 "../../asn1/ldap/packet-ldap-dis-tab.c"
  register_ber_oid_dissector("1.2.840.113556.1.4.319", dissect_SearchControlValue_PDU, proto_ldap, "pagedResultsControl");
  register_ber_oid_dissector("1.2.840.113556.1.4.473", dissect_SortKeyList_PDU, proto_ldap, "sortKeyList");
  register_ber_oid_dissector("1.2.840.113556.1.4.474", dissect_SortResult_PDU, proto_ldap, "sortResult");
  register_ber_oid_dissector("1.2.840.113556.1.4.841", dissect_DirSyncControlValue_PDU, proto_ldap, "dirsync");
  register_ber_oid_dissector("1.3.6.1.4.1.4203.1.11.1", dissect_PasswdModifyRequestValue_PDU, proto_ldap, "passwdModifyOID");
  register_ber_oid_dissector("1.3.6.1.1.8", dissect_CancelRequestValue_PDU, proto_ldap, "cancelRequestOID");
  register_ber_oid_dissector("1.3.6.1.4.1.4203.1.9.1.1", dissect_SyncRequestValue_PDU, proto_ldap, "syncRequestOID");
  register_ber_oid_dissector("1.3.6.1.4.1.4203.1.9.1.2", dissect_SyncStateValue_PDU, proto_ldap, "syncStateOID");
  register_ber_oid_dissector("1.3.6.1.4.1.4203.1.9.1.3", dissect_SyncDoneValue_PDU, proto_ldap, "syncDoneOID");
  register_ber_oid_dissector("1.3.6.1.4.1.4203.1.9.1.4", dissect_SyncInfoValue_PDU, proto_ldap, "syncInfoOID");
  register_ber_oid_dissector("1.3.6.1.4.1.42.2.27.8.5.1", dissect_PasswordPolicyResponseValue_PDU, proto_ldap, "passwordPolicy");


/*--- End of included file: packet-ldap-dis-tab.c ---*/
#line 2196 "../../asn1/ldap/packet-ldap-template.c"


}

static void
prefs_register_ldap(void)
{

  if(tcp_port != global_ldap_tcp_port) {
    if(tcp_port)
      dissector_delete_uint("tcp.port", tcp_port, ldap_handle);

    /* Set our port number for future use */
    tcp_port = global_ldap_tcp_port;

    if(tcp_port)
      dissector_add_uint("tcp.port", tcp_port, ldap_handle);

  }

  if(ssl_port != global_ldaps_tcp_port) {
    if(ssl_port)
      ssl_dissector_delete(ssl_port, "ldap", TRUE);

    /* Set our port number for future use */
    ssl_port = global_ldaps_tcp_port;

    if(ssl_port)
      ssl_dissector_add(ssl_port, "ldap", TRUE);
  }

}
