/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* ./packet-ldap.c                                                            */
/* ../../tools/asn2eth.py -X -b -e -p ldap -c ldap.cnf -s packet-ldap-template Lightweight-Directory-Access-Protocol-V3.asn */

/* Input file: packet-ldap-template.c */

#line 1 "packet-ldap-template.c"
/* packet-ldap.c
 * Routines for ldap packet dissection
 *
 * See RFC 1777 (LDAP v2), RFC 2251 (LDAP v3), and RFC 2222 (SASL).
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
 * 15-NOV-2005 - Changed to use the asn2eth compiler
 * Anders Broman <anders.broman@ericsson.com>
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/emem.h>
#include <epan/oid_resolv.h>
#include <epan/strutil.h>

#include "packet-frame.h"
#include "packet-ldap.h"

#include "packet-ber.h"
#include "packet-per.h"

#define PNAME  "Lightweight-Directory-Access-Protocol"
#define PSNAME "LDAP"
#define PFNAME "ldap"

static dissector_handle_t ldap_handle=NULL;

/* Initialize the protocol and registered fields */
static int ldap_tap = -1;
static int proto_ldap = -1;
static int proto_cldap = -1;

static int hf_mscldap_netlogon_type = -1;
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
static int hf_mscldap_domain_guid = -1;
static int hf_mscldap_forest = -1;
static int hf_mscldap_domain = -1;
static int hf_mscldap_hostname = -1;
static int hf_mscldap_nb_domain = -1;
static int hf_mscldap_nb_hostname = -1;
static int hf_mscldap_username = -1;
static int hf_mscldap_sitename = -1;
static int hf_mscldap_clientsitename = -1;
static int hf_mscldap_netlogon_version = -1;
static int hf_mscldap_netlogon_lm_token = -1;
static int hf_mscldap_netlogon_nt_token = -1;

static int hf_ldap_sasl_buffer_length = -1;
static int hf_ldap_response_in = -1;
static int hf_ldap_response_to = -1;
static int hf_ldap_time = -1;


/*--- Included file: packet-ldap-hf.c ---*/
#line 1 "packet-ldap-hf.c"
static int hf_ldap_LDAPMessage_PDU = -1;          /* LDAPMessage */
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
static int hf_ldap_controlValue = -1;             /* OCTET_STRING */
static int hf_ldap_version = -1;                  /* INTEGER_1_127 */
static int hf_ldap_name = -1;                     /* LDAPDN */
static int hf_ldap_authentication = -1;           /* AuthenticationChoice */
static int hf_ldap_simple = -1;                   /* Simple */
static int hf_ldap_sasl = -1;                     /* SaslCredentials */
static int hf_ldap_mechanism = -1;                /* Mechanism */
static int hf_ldap_credentials = -1;              /* Credentials */
static int hf_ldap_bindResponse_resultCode = -1;  /* BindResponse_resultCode */
static int hf_ldap_serverSaslCreds = -1;          /* ServerSaslCreds */
static int hf_ldap_baseObject = -1;               /* LDAPDN */
static int hf_ldap_scope = -1;                    /* T_scope */
static int hf_ldap_derefAliases = -1;             /* T_derefAliases */
static int hf_ldap_sizeLimit = -1;                /* INTEGER_0_maxInt */
static int hf_ldap_timeLimit = -1;                /* INTEGER_0_maxInt */
static int hf_ldap_typesOnly = -1;                /* BOOLEAN */
static int hf_ldap_filter = -1;                   /* Filter */
static int hf_ldap_searchRequest_attributes = -1;  /* AttributeDescriptionList */
static int hf_ldap_and = -1;                      /* SET_OF_Filter */
static int hf_ldap_and_item = -1;                 /* Filter */
static int hf_ldap_or = -1;                       /* SET_OF_Filter */
static int hf_ldap_or_item = -1;                  /* Filter */
static int hf_ldap_not = -1;                      /* Filter */
static int hf_ldap_equalityMatch = -1;            /* AttributeValueAssertion */
static int hf_ldap_substrings = -1;               /* SubstringFilter */
static int hf_ldap_greaterOrEqual = -1;           /* AttributeValueAssertion */
static int hf_ldap_lessOrEqual = -1;              /* AttributeValueAssertion */
static int hf_ldap_present = -1;                  /* AttributeDescription */
static int hf_ldap_approxMatch = -1;              /* AttributeValueAssertion */
static int hf_ldap_extensibleMatch = -1;          /* MatchingRuleAssertion */
static int hf_ldap_substringFilter_substrings = -1;  /* T_substrings */
static int hf_ldap_substrings_item = -1;          /* T_substrings_item */
static int hf_ldap_initial = -1;                  /* LDAPString */
static int hf_ldap_any = -1;                      /* LDAPString */
static int hf_ldap_final = -1;                    /* LDAPString */
static int hf_ldap_matchingRule = -1;             /* MatchingRuleId */
static int hf_ldap_matchValue = -1;               /* AssertionValue */
static int hf_ldap_dnAttributes = -1;             /* BOOLEAN */
static int hf_ldap_objectName = -1;               /* LDAPDN */
static int hf_ldap_searchResultEntry_attributes = -1;  /* PartialAttributeList */
static int hf_ldap_PartialAttributeList_item = -1;  /* PartialAttributeList_item */
static int hf_ldap_SearchResultReference_item = -1;  /* LDAPURL */
static int hf_ldap_object = -1;                   /* LDAPDN */
static int hf_ldap_modifyRequest_modification = -1;  /* ModifyRequest_modification */
static int hf_ldap_modification_item = -1;        /* T_modification_item */
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
static int hf_ldap_requestValue = -1;             /* OCTET_STRING */
static int hf_ldap_extendedResponse_resultCode = -1;  /* ExtendedResponse_resultCode */
static int hf_ldap_responseName = -1;             /* ResponseName */
static int hf_ldap_response = -1;                 /* OCTET_STRING */

/*--- End of included file: packet-ldap-hf.c ---*/
#line 135 "packet-ldap-template.c"

/* Initialize the subtree pointers */
static gint ett_ldap = -1;
static gint ett_ldap_msg = -1;
static gint ett_ldap_sasl_blob = -1;
static gint ett_ldap_payload = -1;

static gint ett_mscldap_netlogon_flags = -1;



/*--- Included file: packet-ldap-ett.c ---*/
#line 1 "packet-ldap-ett.c"
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
static gint ett_ldap_BindRequest = -1;
static gint ett_ldap_AuthenticationChoice = -1;
static gint ett_ldap_SaslCredentials = -1;
static gint ett_ldap_BindResponse = -1;
static gint ett_ldap_SearchRequest = -1;
static gint ett_ldap_Filter = -1;
static gint ett_ldap_SET_OF_Filter = -1;
static gint ett_ldap_SubstringFilter = -1;
static gint ett_ldap_T_substrings = -1;
static gint ett_ldap_T_substrings_item = -1;
static gint ett_ldap_MatchingRuleAssertion = -1;
static gint ett_ldap_SearchResultEntry = -1;
static gint ett_ldap_PartialAttributeList = -1;
static gint ett_ldap_PartialAttributeList_item = -1;
static gint ett_ldap_SearchResultReference = -1;
static gint ett_ldap_ModifyRequest = -1;
static gint ett_ldap_ModifyRequest_modification = -1;
static gint ett_ldap_T_modification_item = -1;
static gint ett_ldap_AttributeTypeAndValues = -1;
static gint ett_ldap_AddRequest = -1;
static gint ett_ldap_AttributeList = -1;
static gint ett_ldap_AttributeList_item = -1;
static gint ett_ldap_ModifyDNRequest = -1;
static gint ett_ldap_CompareRequest = -1;
static gint ett_ldap_ExtendedRequest = -1;
static gint ett_ldap_ExtendedResponse = -1;

/*--- End of included file: packet-ldap-ett.c ---*/
#line 146 "packet-ldap-template.c"

/* desegmentation of LDAP */
static gboolean ldap_desegment = TRUE;
static guint    ldap_tcp_port = 389;
static gboolean do_protocolop = FALSE;

#define TCP_PORT_LDAP			389
#define UDP_PORT_CLDAP			389
#define TCP_PORT_GLOBALCAT_LDAP         3268 /* Windows 2000 Global Catalog */

static dissector_handle_t gssapi_handle;
static dissector_handle_t gssapi_wrap_handle;


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
  gboolean first_time;
  guint32  num_results;
} ldap_conv_info_t;
static ldap_conv_info_t *ldap_info_items;

static guint
ldap_info_hash_matched(gconstpointer k)
{
  const ldap_call_response_t *key = k;

  return key->messageId;
}

static gint
ldap_info_equal_matched(gconstpointer k1, gconstpointer k2)
{
  const ldap_call_response_t *key1 = k1;
  const ldap_call_response_t *key2 = k2;

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
  const ldap_call_response_t *key = k;

  return key->messageId;
}

static gint
ldap_info_equal_unmatched(gconstpointer k1, gconstpointer k2)
{
  const ldap_call_response_t *key1 = k1;
  const ldap_call_response_t *key2 = k2;

  return key1->messageId==key2->messageId;
}

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

    if(check_col(pinfo->cinfo, COL_INFO))
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
          lcr.is_request=FALSE;
          lcr.req_frame=0;
          lcr.rep_frame=pinfo->fd->num;
          break;
      }
      lcrp=g_hash_table_lookup(ldap_info->matched, &lcr);

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

		/* this a a request - add it to the unmatched list */

        /* check that we dont already have one of those in the
           unmatched list and if so remove it */

        lcr.messageId=messageId;
        lcrp=g_hash_table_lookup(ldap_info->unmatched, &lcr);
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

		/* this is a result - it should be in our unmatched list */

        lcr.messageId=messageId;
        lcrp=g_hash_table_lookup(ldap_info->unmatched, &lcr);

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
      if(lcrp->is_request){
        proto_tree_add_uint(tree, hf_ldap_response_in, tvb, 0, 0, lcrp->rep_frame);
      } else {
        nstime_t ns;
        proto_tree_add_uint(tree, hf_ldap_response_to, tvb, 0, 0, lcrp->req_frame);
        nstime_delta(&ns, &pinfo->fd->abs_ts, &lcrp->req_time);
        proto_tree_add_time(tree, hf_ldap_time, tvb, 0, 0, &ns);
      }
    }

    return lcrp;
}

static int dissect_mscldap_string(tvbuff_t *tvb, int offset, char *str, int maxlen, gboolean prepend_dot)
{
  guint8 len;

  len=tvb_get_guint8(tvb, offset);
  offset+=1;
  *str=0;

  while(len){
    /* add potential field separation dot */
    if(prepend_dot){
      if(!maxlen){
        *str=0;
        return offset;
      }
      maxlen--;
      *str++='.';
      *str=0;
    }

    if(len==0xc0){
      int new_offset;
      /* ops its a mscldap compressed string */

      new_offset=tvb_get_guint8(tvb, offset);
      if (new_offset == offset - 1)
        THROW(ReportedBoundsError);
      offset+=1;

      dissect_mscldap_string(tvb, new_offset, str, maxlen, FALSE);

      return offset;
    }

    prepend_dot=TRUE;

    if(maxlen<=len){
      if(maxlen>3){
        *str++='.';
        *str++='.';
        *str++='.';
      }
      *str=0;
      return offset; /* will mess up offset in caller, is unlikely */
    }
    tvb_memcpy(tvb, str, offset, len);
    str+=len;
    *str=0;
    maxlen-=len;
    offset+=len;


    len=tvb_get_guint8(tvb, offset);
    offset+=1;
  }
  *str=0;
  return offset;
}


/* These flag bits were found to be defined in the samba sources.
 * I hope they are correct (but have serious doubts about the CLOSEST
 * bit being used or being meaningful).
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
	"This is the CLOSEST dc (unreliable?)",
	"This is NOT the closest dc"
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
static int dissect_mscldap_netlogon_flags(proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
  guint32 flags;
  proto_item *item;
  proto_tree *tree=NULL;

  flags=tvb_get_letohl(tvb, offset);
  item=proto_tree_add_item(parent_tree, hf_mscldap_netlogon_flags, tvb, offset, 4, TRUE);
  if(parent_tree){
    tree = proto_item_add_subtree(item, ett_mscldap_netlogon_flags);
  }

  proto_tree_add_boolean(tree, hf_mscldap_netlogon_flags_ndnc,
    tvb, offset, 4, flags);
  proto_tree_add_boolean(tree, hf_mscldap_netlogon_flags_good_timeserv,
    tvb, offset, 4, flags);
  proto_tree_add_boolean(tree, hf_mscldap_netlogon_flags_writable,
    tvb, offset, 4, flags);
  proto_tree_add_boolean(tree, hf_mscldap_netlogon_flags_closest,
    tvb, offset, 4, flags);
  proto_tree_add_boolean(tree, hf_mscldap_netlogon_flags_timeserv,
    tvb, offset, 4, flags);
  proto_tree_add_boolean(tree, hf_mscldap_netlogon_flags_kdc,
    tvb, offset, 4, flags);
  proto_tree_add_boolean(tree, hf_mscldap_netlogon_flags_ds,
    tvb, offset, 4, flags);
  proto_tree_add_boolean(tree, hf_mscldap_netlogon_flags_ldap,
    tvb, offset, 4, flags);
  proto_tree_add_boolean(tree, hf_mscldap_netlogon_flags_gc,
    tvb, offset, 4, flags);
  proto_tree_add_boolean(tree, hf_mscldap_netlogon_flags_pdc,
    tvb, offset, 4, flags);

  offset += 4;

  return offset;
}

static void dissect_mscldap_response_netlogon(proto_tree *tree, tvbuff_t *tvb)
{
  int old_offset, offset=0;
  char str[256];

/*qqq*/

  /* Type */
  /*XXX someone that knows what the type means should add that knowledge here*/
  proto_tree_add_item(tree, hf_mscldap_netlogon_type, tvb, offset, 4, TRUE);
  offset += 4;

  /* Flags */
  offset = dissect_mscldap_netlogon_flags(tree, tvb, offset);

  /* Domain GUID */
  proto_tree_add_item(tree, hf_mscldap_domain_guid, tvb, offset, 16, TRUE);
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
  
  /* NetBios Domain */
  old_offset=offset;
  offset=dissect_mscldap_string(tvb, offset, str, 255, FALSE);
  proto_tree_add_string(tree, hf_mscldap_nb_domain, tvb, old_offset, offset-old_offset, str);
  
  /* NetBios Hostname */
  old_offset=offset;
  offset=dissect_mscldap_string(tvb, offset, str, 255, FALSE);
  proto_tree_add_string(tree, hf_mscldap_nb_hostname, tvb, old_offset, offset-old_offset, str);
  
  /* User */
  old_offset=offset;
  offset=dissect_mscldap_string(tvb, offset, str, 255, FALSE);
  proto_tree_add_string(tree, hf_mscldap_username, tvb, old_offset, offset-old_offset, str);
  
  /* Site */
  old_offset=offset;
  offset=dissect_mscldap_string(tvb, offset, str, 255, FALSE);
  proto_tree_add_string(tree, hf_mscldap_sitename, tvb, old_offset, offset-old_offset, str);
  
  /* Client Site */
  old_offset=offset;
  offset=dissect_mscldap_string(tvb, offset, str, 255, FALSE);
  proto_tree_add_string(tree, hf_mscldap_clientsitename, tvb, old_offset, offset-old_offset, str);
  
  /* Version */
  proto_tree_add_item(tree, hf_mscldap_netlogon_version, tvb, offset, 4, TRUE);
  offset += 4;

  /* LM Token */
  proto_tree_add_item(tree, hf_mscldap_netlogon_lm_token, tvb, offset, 2, TRUE);
  offset += 2;

  /* NT Token */
  proto_tree_add_item(tree, hf_mscldap_netlogon_nt_token, tvb, offset, 2, TRUE);
  offset += 2;

}

static void dissect_mscldap_response(proto_tree *tree, tvbuff_t *tvb, guint32 rpc)
{
  switch(rpc){
  case MSCLDAP_RPC_NETLOGON:
    dissect_mscldap_response_netlogon(tree, tvb);
    break;
  default:
    proto_tree_add_text(tree, tvb, 0, tvb_length(tvb),
      "ERROR: Unknown type of MS-CLDAP RPC call");
  }
}

static int dissect_ldap_AttributeDescription(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_);
static int dissect_ldap_AttributeValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_);

static int mscldap_rpc_call=0;


/*--- Included file: packet-ldap-fn.c ---*/
#line 1 "packet-ldap-fn.c"
/*--- Cyclic dependencies ---*/

/* Filter -> Filter/and -> Filter */
/* Filter -> Filter */
static int dissect_ldap_Filter(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);

static int dissect_filter(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_Filter(FALSE, tvb, offset, pinfo, tree, hf_ldap_filter);
}
static int dissect_and_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_Filter(FALSE, tvb, offset, pinfo, tree, hf_ldap_and_item);
}
static int dissect_or_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_Filter(FALSE, tvb, offset, pinfo, tree, hf_ldap_or_item);
}
static int dissect_not_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_Filter(TRUE, tvb, offset, pinfo, tree, hf_ldap_not);
}


/*--- Fields for imported types ---*/




static int
dissect_ldap_MessageID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 52 "ldap.cnf"

    offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &MessageID);

  
  ldm_tree = tree;



  return offset;
}
static int dissect_messageID(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_MessageID(FALSE, tvb, offset, pinfo, tree, hf_ldap_messageID);
}



static int
dissect_ldap_INTEGER_1_127(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_version(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_INTEGER_1_127(FALSE, tvb, offset, pinfo, tree, hf_ldap_version);
}



static int
dissect_ldap_LDAPString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 239 "ldap.cnf"
  tvbuff_t	*parameter_tvb = NULL;
  char          *ldapstring;
 
    offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


  if (parameter_tvb || (hf_index == hf_ldap_baseObject)) {
  
     ldap_do_protocolop(pinfo);

     if(parameter_tvb)
        ldapstring = tvb_get_string(parameter_tvb, 0, tvb_length_remaining(parameter_tvb, 0));
     else
        ldapstring = "<ROOT>";

     if(hf_index == hf_ldap_baseObject) {
  	/* this is search - but it on the scanline */
	if(check_col(pinfo->cinfo, COL_INFO)) 
	  col_append_fstr(pinfo->cinfo, COL_INFO, "\"%s\" ", ldapstring);
  
  	if(ldm_tree)
  	  proto_item_append_text(ldm_tree, " \"%s\"", ldapstring); 
     } else if ((hf_index == hf_ldap_errorMessage) && result) { /* only show message if not success */
	if(check_col(pinfo->cinfo, COL_INFO)) 
          col_append_fstr(pinfo->cinfo, COL_INFO, "(%s) ", ldapstring);     

        if(ldm_tree)
  	  proto_item_append_text(ldm_tree, " (%s)", ldapstring); 
     } else if (hf_index == hf_ldap_objectName) {
	if(check_col(pinfo->cinfo, COL_INFO)) 
          col_append_fstr(pinfo->cinfo, COL_INFO, "\"%s\" ", ldapstring);     

        if(ldm_tree)
  	  proto_item_append_text(ldm_tree, " \"%s\"", ldapstring); 
     }
     
     if(parameter_tvb && ldapstring)
        g_free(ldapstring);
  }



  return offset;
}
static int dissect_initial_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_LDAPString(TRUE, tvb, offset, pinfo, tree, hf_ldap_initial);
}
static int dissect_any_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_LDAPString(TRUE, tvb, offset, pinfo, tree, hf_ldap_any);
}
static int dissect_final_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_LDAPString(TRUE, tvb, offset, pinfo, tree, hf_ldap_final);
}



static int
dissect_ldap_LDAPDN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ldap_LDAPString(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_matchedDN(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_LDAPDN(FALSE, tvb, offset, pinfo, tree, hf_ldap_matchedDN);
}
static int dissect_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_LDAPDN(FALSE, tvb, offset, pinfo, tree, hf_ldap_name);
}
static int dissect_baseObject(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_LDAPDN(FALSE, tvb, offset, pinfo, tree, hf_ldap_baseObject);
}
static int dissect_objectName(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_LDAPDN(FALSE, tvb, offset, pinfo, tree, hf_ldap_objectName);
}
static int dissect_object(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_LDAPDN(FALSE, tvb, offset, pinfo, tree, hf_ldap_object);
}
static int dissect_entry(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_LDAPDN(FALSE, tvb, offset, pinfo, tree, hf_ldap_entry);
}
static int dissect_newSuperior_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_LDAPDN(TRUE, tvb, offset, pinfo, tree, hf_ldap_newSuperior);
}



static int
dissect_ldap_Simple(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 102 "ldap.cnf"
ldap_conv_info_t *ldap_info;

  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

	
	ldap_info = pinfo->private_data;
	ldap_info->auth_type = LDAP_AUTH_SIMPLE;

	pinfo->private_data = ldap_info;



  return offset;
}
static int dissect_simple_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_Simple(TRUE, tvb, offset, pinfo, tree, hf_ldap_simple);
}



static int
dissect_ldap_Mechanism(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 113 "ldap.cnf"

ldap_conv_info_t *ldap_info;
tvbuff_t	*parameter_tvb;
char *mechanism = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	ldap_info = pinfo->private_data;
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
    mechanism = tvb_get_string(parameter_tvb, 0, tvb_length_remaining(parameter_tvb,0));
    ldap_info->first_auth_frame = 0;	/* not known until we see the bind reply */
    /*
     * If the mechanism in this request is an empty string (which is
     * returned as a null pointer), use the saved mechanism instead.
     * Otherwise, if the saved mechanism is an empty string (null),
     * save this mechanism.
     */
    if (mechanism == NULL)
        mechanism = ldap_info->auth_mech;
    else {
      if (ldap_info->auth_mech == NULL) {
        g_free(ldap_info->auth_mech);
      }
      ldap_info->auth_mech = mechanism;
    }
	pinfo->private_data = ldap_info;



  return offset;
}
static int dissect_mechanism(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_Mechanism(FALSE, tvb, offset, pinfo, tree, hf_ldap_mechanism);
}



static int
dissect_ldap_Credentials(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 152 "ldap.cnf"

tvbuff_t	*parameter_tvb;
ldap_conv_info_t *ldap_info;

  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (!parameter_tvb)
		return offset;

	ldap_info = pinfo->private_data;
	if (ldap_info->auth_mech != NULL && strcmp(ldap_info->auth_mech, "GSS-SPNEGO") == 0) {
		/*
         * This is a GSS-API token ancapsulated within GSS-SPNEGO.
		 */
		 if (parameter_tvb)
			call_dissector(gssapi_handle, parameter_tvb, pinfo, tree);
	} else if (ldap_info->auth_mech != NULL && strcmp(ldap_info->auth_mech, "GSSAPI") == 0) {
        /*
         * This is a raw GSS-API token.
         */
		 if (parameter_tvb)
			call_dissector(gssapi_handle, parameter_tvb, pinfo, tree);
	}
	pinfo->private_data = ldap_info;



  return offset;
}
static int dissect_credentials(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_Credentials(FALSE, tvb, offset, pinfo, tree, hf_ldap_credentials);
}


static const ber_sequence_t SaslCredentials_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_mechanism },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_credentials },
  { 0, 0, 0, NULL }
};

static int
dissect_ldap_SaslCredentials(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SaslCredentials_sequence, hf_index, ett_ldap_SaslCredentials);

  return offset;
}
static int dissect_sasl_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_SaslCredentials(TRUE, tvb, offset, pinfo, tree, hf_ldap_sasl);
}


static const value_string ldap_AuthenticationChoice_vals[] = {
  {   0, "simple" },
  {   3, "sasl" },
  { 0, NULL }
};

static const ber_choice_t AuthenticationChoice_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_simple_impl },
  {   3, BER_CLASS_CON, 3, 0, dissect_sasl_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ldap_AuthenticationChoice(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 344 "ldap.cnf"
  gint branch = -1;
  gint auth = -1;
  const gchar *valstr;
  
    offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 AuthenticationChoice_choice, hf_index, ett_ldap_AuthenticationChoice,
                                 &branch);

  
  ldap_do_protocolop(pinfo);
  
  if((branch > -1) && (branch < (sizeof AuthenticationChoice_choice/sizeof AuthenticationChoice_choice[0])))
    auth = AuthenticationChoice_choice[branch].value;

  valstr = val_to_str(auth, ldap_AuthenticationChoice_vals, "Unknown auth(%u)");
  
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", valstr);
  
  if(ldm_tree)
    proto_item_append_text(ldm_tree, " %s", valstr);




  return offset;
}
static int dissect_authentication(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_AuthenticationChoice(FALSE, tvb, offset, pinfo, tree, hf_ldap_authentication);
}


static const ber_sequence_t BindRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_version },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_name },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_authentication },
  { 0, 0, 0, NULL }
};

static int
dissect_ldap_BindRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   BindRequest_sequence, hf_index, ett_ldap_BindRequest);

  return offset;
}
static int dissect_bindRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_BindRequest(FALSE, tvb, offset, pinfo, tree, hf_ldap_bindRequest);
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
  { 0, NULL }
};


static int
dissect_ldap_BindResponse_resultCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 322 "ldap.cnf"

  const gchar *valstr;

    offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &result);


  ldap_do_protocolop(pinfo);

  if(result) {
  
    valstr = val_to_str(result, ldap_BindResponse_resultCode_vals, "Unknown result(%u)");

    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", valstr);

    if(ldm_tree)
      proto_item_append_text(ldm_tree, " %s", valstr); 

  }
  


  return offset;
}
static int dissect_bindResponse_resultCode(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_BindResponse_resultCode(FALSE, tvb, offset, pinfo, tree, hf_ldap_bindResponse_resultCode);
}



static int
dissect_ldap_ErrorMessage(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ldap_LDAPString(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_errorMessage(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_ErrorMessage(FALSE, tvb, offset, pinfo, tree, hf_ldap_errorMessage);
}



static int
dissect_ldap_LDAPURL(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ldap_LDAPString(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_Referral_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_LDAPURL(FALSE, tvb, offset, pinfo, tree, hf_ldap_Referral_item);
}
static int dissect_SearchResultReference_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_LDAPURL(FALSE, tvb, offset, pinfo, tree, hf_ldap_SearchResultReference_item);
}


static const ber_sequence_t Referral_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_Referral_item },
};

static int
dissect_ldap_Referral(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      Referral_sequence_of, hf_index, ett_ldap_Referral);

  return offset;
}
static int dissect_referral_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_Referral(TRUE, tvb, offset, pinfo, tree, hf_ldap_referral);
}



static int
dissect_ldap_ServerSaslCreds(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 178 "ldap.cnf"

tvbuff_t	*parameter_tvb;
ldap_conv_info_t *ldap_info;

  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (!parameter_tvb)
		return offset;
	ldap_info = pinfo->private_data;
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
      ldap_info->first_auth_frame = pinfo->fd->num + 1;
      if (ldap_info->auth_mech != NULL &&
          strcmp(ldap_info->auth_mech, "GSS-SPNEGO") == 0) {
        /*
         * This is a GSS-API token.
         */
        call_dissector(gssapi_handle, parameter_tvb, pinfo, tree);
      } else if (ldap_info->auth_mech != NULL &&
          strcmp(ldap_info->auth_mech, "GSSAPI") == 0) {
        /*
         * This is a GSS-API token.
         */
        call_dissector(gssapi_handle, parameter_tvb, pinfo, tree);
		}
	break;
	}
	pinfo->private_data = ldap_info;



  return offset;
}
static int dissect_serverSaslCreds_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_ServerSaslCreds(TRUE, tvb, offset, pinfo, tree, hf_ldap_serverSaslCreds);
}


static const ber_sequence_t BindResponse_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_bindResponse_resultCode },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_matchedDN },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_errorMessage },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_referral_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serverSaslCreds_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ldap_BindResponse(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   BindResponse_sequence, hf_index, ett_ldap_BindResponse);

  return offset;
}
static int dissect_bindResponse(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_BindResponse(FALSE, tvb, offset, pinfo, tree, hf_ldap_bindResponse);
}



static int
dissect_ldap_UnbindRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 365 "ldap.cnf"

 implicit_tag = TRUE; /* correct problem with asn2eth */

   offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);


 ldap_do_protocolop(pinfo);  



  return offset;
}
static int dissect_unbindRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_UnbindRequest(FALSE, tvb, offset, pinfo, tree, hf_ldap_unbindRequest);
}


static const value_string ldap_T_scope_vals[] = {
  {   0, "baseObject" },
  {   1, "singleLevel" },
  {   2, "wholeSubtree" },
  { 0, NULL }
};


static int
dissect_ldap_T_scope(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 281 "ldap.cnf"

  gint 	scope;
  const gchar *valstr;

    offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &scope);


  ldap_do_protocolop(pinfo);

  valstr = val_to_str(scope, ldap_T_scope_vals, "Unknown scope(%u)");

  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", valstr);    
    
  if(ldm_tree)
    proto_item_append_text(ldm_tree, " %s", valstr); 



  return offset;
}
static int dissect_scope(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_T_scope(FALSE, tvb, offset, pinfo, tree, hf_ldap_scope);
}


static const value_string ldap_T_derefAliases_vals[] = {
  {   0, "neverDerefAliases" },
  {   1, "derefInSearching" },
  {   2, "derefFindingBaseObj" },
  {   3, "derefAlways" },
  { 0, NULL }
};


static int
dissect_ldap_T_derefAliases(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_derefAliases(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_T_derefAliases(FALSE, tvb, offset, pinfo, tree, hf_ldap_derefAliases);
}



static int
dissect_ldap_INTEGER_0_maxInt(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_sizeLimit(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_INTEGER_0_maxInt(FALSE, tvb, offset, pinfo, tree, hf_ldap_sizeLimit);
}
static int dissect_timeLimit(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_INTEGER_0_maxInt(FALSE, tvb, offset, pinfo, tree, hf_ldap_timeLimit);
}



static int
dissect_ldap_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_criticality(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_ldap_criticality);
}
static int dissect_typesOnly(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_ldap_typesOnly);
}
static int dissect_dnAttributes_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_ldap_dnAttributes);
}
static int dissect_deleteoldrdn(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_ldap_deleteoldrdn);
}


static const ber_sequence_t SET_OF_Filter_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_and_item },
};

static int
dissect_ldap_SET_OF_Filter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_Filter_set_of, hf_index, ett_ldap_SET_OF_Filter);

  return offset;
}
static int dissect_and_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_SET_OF_Filter(TRUE, tvb, offset, pinfo, tree, hf_ldap_and);
}
static int dissect_or_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_SET_OF_Filter(TRUE, tvb, offset, pinfo, tree, hf_ldap_or);
}

static int dissect_AttributeDescriptionList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_AttributeDescription(FALSE, tvb, offset, pinfo, tree, hf_ldap_AttributeDescriptionList_item);
}
static int dissect_attributeDesc(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_AttributeDescription(FALSE, tvb, offset, pinfo, tree, hf_ldap_attributeDesc);
}
static int dissect_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_AttributeDescription(FALSE, tvb, offset, pinfo, tree, hf_ldap_type);
}
static int dissect_type_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_AttributeDescription(TRUE, tvb, offset, pinfo, tree, hf_ldap_type);
}
static int dissect_present_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_AttributeDescription(TRUE, tvb, offset, pinfo, tree, hf_ldap_present);
}



static int
dissect_ldap_AssertionValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_assertionValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_AssertionValue(FALSE, tvb, offset, pinfo, tree, hf_ldap_assertionValue);
}
static int dissect_matchValue_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_AssertionValue(TRUE, tvb, offset, pinfo, tree, hf_ldap_matchValue);
}


static const ber_sequence_t AttributeValueAssertion_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_attributeDesc },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_assertionValue },
  { 0, 0, 0, NULL }
};

static int
dissect_ldap_AttributeValueAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AttributeValueAssertion_sequence, hf_index, ett_ldap_AttributeValueAssertion);

  return offset;
}
static int dissect_equalityMatch_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_AttributeValueAssertion(TRUE, tvb, offset, pinfo, tree, hf_ldap_equalityMatch);
}
static int dissect_greaterOrEqual_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_AttributeValueAssertion(TRUE, tvb, offset, pinfo, tree, hf_ldap_greaterOrEqual);
}
static int dissect_lessOrEqual_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_AttributeValueAssertion(TRUE, tvb, offset, pinfo, tree, hf_ldap_lessOrEqual);
}
static int dissect_approxMatch_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_AttributeValueAssertion(TRUE, tvb, offset, pinfo, tree, hf_ldap_approxMatch);
}
static int dissect_ava(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_AttributeValueAssertion(FALSE, tvb, offset, pinfo, tree, hf_ldap_ava);
}


static const value_string ldap_T_substrings_item_vals[] = {
  {   0, "initial" },
  {   1, "any" },
  {   2, "final" },
  { 0, NULL }
};

static const ber_choice_t T_substrings_item_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_initial_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_any_impl },
  {   2, BER_CLASS_CON, 2, 0, dissect_final_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ldap_T_substrings_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_substrings_item_choice, hf_index, ett_ldap_T_substrings_item,
                                 NULL);

  return offset;
}
static int dissect_substrings_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_T_substrings_item(FALSE, tvb, offset, pinfo, tree, hf_ldap_substrings_item);
}


static const ber_sequence_t T_substrings_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_substrings_item },
};

static int
dissect_ldap_T_substrings(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_substrings_sequence_of, hf_index, ett_ldap_T_substrings);

  return offset;
}
static int dissect_substringFilter_substrings(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_T_substrings(FALSE, tvb, offset, pinfo, tree, hf_ldap_substringFilter_substrings);
}


static const ber_sequence_t SubstringFilter_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_type },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_substringFilter_substrings },
  { 0, 0, 0, NULL }
};

static int
dissect_ldap_SubstringFilter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SubstringFilter_sequence, hf_index, ett_ldap_SubstringFilter);

  return offset;
}
static int dissect_substrings_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_SubstringFilter(TRUE, tvb, offset, pinfo, tree, hf_ldap_substrings);
}



static int
dissect_ldap_MatchingRuleId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ldap_LDAPString(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_matchingRule_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_MatchingRuleId(TRUE, tvb, offset, pinfo, tree, hf_ldap_matchingRule);
}


static const ber_sequence_t MatchingRuleAssertion_sequence[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_matchingRule_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_type_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_matchValue_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dnAttributes_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ldap_MatchingRuleAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MatchingRuleAssertion_sequence, hf_index, ett_ldap_MatchingRuleAssertion);

  return offset;
}
static int dissect_extensibleMatch_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_MatchingRuleAssertion(TRUE, tvb, offset, pinfo, tree, hf_ldap_extensibleMatch);
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
  {   0, BER_CLASS_CON, 0, 0, dissect_and_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_or_impl },
  {   2, BER_CLASS_CON, 2, 0, dissect_not_impl },
  {   3, BER_CLASS_CON, 3, 0, dissect_equalityMatch_impl },
  {   4, BER_CLASS_CON, 4, 0, dissect_substrings_impl },
  {   5, BER_CLASS_CON, 5, 0, dissect_greaterOrEqual_impl },
  {   6, BER_CLASS_CON, 6, 0, dissect_lessOrEqual_impl },
  {   7, BER_CLASS_CON, 7, 0, dissect_present_impl },
  {   8, BER_CLASS_CON, 8, 0, dissect_approxMatch_impl },
  {   9, BER_CLASS_CON, 9, 0, dissect_extensibleMatch_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ldap_Filter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Filter_choice, hf_index, ett_ldap_Filter,
                                 NULL);

  return offset;
}


static const ber_sequence_t AttributeDescriptionList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_AttributeDescriptionList_item },
};

static int
dissect_ldap_AttributeDescriptionList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      AttributeDescriptionList_sequence_of, hf_index, ett_ldap_AttributeDescriptionList);

  return offset;
}
static int dissect_searchRequest_attributes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_AttributeDescriptionList(FALSE, tvb, offset, pinfo, tree, hf_ldap_searchRequest_attributes);
}


static const ber_sequence_t SearchRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_baseObject },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_scope },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_derefAliases },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_sizeLimit },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_timeLimit },
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_typesOnly },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_filter },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_searchRequest_attributes },
  { 0, 0, 0, NULL }
};

static int
dissect_ldap_SearchRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SearchRequest_sequence, hf_index, ett_ldap_SearchRequest);

  return offset;
}
static int dissect_searchRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_SearchRequest(FALSE, tvb, offset, pinfo, tree, hf_ldap_searchRequest);
}

static int dissect_vals_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_AttributeValue(FALSE, tvb, offset, pinfo, tree, hf_ldap_vals_item);
}


static const ber_sequence_t SET_OF_AttributeValue_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_vals_item },
};

static int
dissect_ldap_SET_OF_AttributeValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_AttributeValue_set_of, hf_index, ett_ldap_SET_OF_AttributeValue);

  return offset;
}
static int dissect_vals(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_SET_OF_AttributeValue(FALSE, tvb, offset, pinfo, tree, hf_ldap_vals);
}


static const ber_sequence_t PartialAttributeList_item_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_type },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_vals },
  { 0, 0, 0, NULL }
};

static int
dissect_ldap_PartialAttributeList_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PartialAttributeList_item_sequence, hf_index, ett_ldap_PartialAttributeList_item);

  return offset;
}
static int dissect_PartialAttributeList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_PartialAttributeList_item(FALSE, tvb, offset, pinfo, tree, hf_ldap_PartialAttributeList_item);
}


static const ber_sequence_t PartialAttributeList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_PartialAttributeList_item },
};

static int
dissect_ldap_PartialAttributeList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      PartialAttributeList_sequence_of, hf_index, ett_ldap_PartialAttributeList);

  return offset;
}
static int dissect_searchResultEntry_attributes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_PartialAttributeList(FALSE, tvb, offset, pinfo, tree, hf_ldap_searchResultEntry_attributes);
}


static const ber_sequence_t SearchResultEntry_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_objectName },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_searchResultEntry_attributes },
  { 0, 0, 0, NULL }
};

static int
dissect_ldap_SearchResultEntry(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SearchResultEntry_sequence, hf_index, ett_ldap_SearchResultEntry);

  return offset;
}
static int dissect_searchResEntry(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_SearchResultEntry(FALSE, tvb, offset, pinfo, tree, hf_ldap_searchResEntry);
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
  { 0, NULL }
};


static int
dissect_ldap_T_resultCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 300 "ldap.cnf"

  const gchar *valstr;

    offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &result);


  ldap_do_protocolop(pinfo);

  if(result) {
  
    valstr = val_to_str(result, ldap_T_resultCode_vals, "Unknown result(%u)");

    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", valstr);

    if(ldm_tree)
      proto_item_append_text(ldm_tree, " %s", valstr); 

  }



  return offset;
}
static int dissect_resultCode(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_T_resultCode(FALSE, tvb, offset, pinfo, tree, hf_ldap_resultCode);
}


static const ber_sequence_t LDAPResult_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_resultCode },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_matchedDN },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_errorMessage },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_referral_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ldap_LDAPResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LDAPResult_sequence, hf_index, ett_ldap_LDAPResult);

  return offset;
}



static int
dissect_ldap_SearchResultDone(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ldap_LDAPResult(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_searchResDone(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_SearchResultDone(FALSE, tvb, offset, pinfo, tree, hf_ldap_searchResDone);
}


static const ber_sequence_t SearchResultReference_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_SearchResultReference_item },
};

static int
dissect_ldap_SearchResultReference(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SearchResultReference_sequence_of, hf_index, ett_ldap_SearchResultReference);

  return offset;
}
static int dissect_searchResRef(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_SearchResultReference(FALSE, tvb, offset, pinfo, tree, hf_ldap_searchResRef);
}


static const value_string ldap_T_operation_vals[] = {
  {   0, "add" },
  {   1, "delete" },
  {   2, "replace" },
  { 0, NULL }
};


static int
dissect_ldap_T_operation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_operation(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_T_operation(FALSE, tvb, offset, pinfo, tree, hf_ldap_operation);
}


static const ber_sequence_t AttributeTypeAndValues_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_type },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_vals },
  { 0, 0, 0, NULL }
};

static int
dissect_ldap_AttributeTypeAndValues(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AttributeTypeAndValues_sequence, hf_index, ett_ldap_AttributeTypeAndValues);

  return offset;
}
static int dissect_modification(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_AttributeTypeAndValues(FALSE, tvb, offset, pinfo, tree, hf_ldap_modification);
}


static const ber_sequence_t T_modification_item_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_operation },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_modification },
  { 0, 0, 0, NULL }
};

static int
dissect_ldap_T_modification_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_modification_item_sequence, hf_index, ett_ldap_T_modification_item);

  return offset;
}
static int dissect_modification_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_T_modification_item(FALSE, tvb, offset, pinfo, tree, hf_ldap_modification_item);
}


static const ber_sequence_t ModifyRequest_modification_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_modification_item },
};

static int
dissect_ldap_ModifyRequest_modification(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      ModifyRequest_modification_sequence_of, hf_index, ett_ldap_ModifyRequest_modification);

  return offset;
}
static int dissect_modifyRequest_modification(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_ModifyRequest_modification(FALSE, tvb, offset, pinfo, tree, hf_ldap_modifyRequest_modification);
}


static const ber_sequence_t ModifyRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_object },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_modifyRequest_modification },
  { 0, 0, 0, NULL }
};

static int
dissect_ldap_ModifyRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ModifyRequest_sequence, hf_index, ett_ldap_ModifyRequest);

  return offset;
}
static int dissect_modifyRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_ModifyRequest(FALSE, tvb, offset, pinfo, tree, hf_ldap_modifyRequest);
}



static int
dissect_ldap_ModifyResponse(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ldap_LDAPResult(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_modifyResponse(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_ModifyResponse(FALSE, tvb, offset, pinfo, tree, hf_ldap_modifyResponse);
}


static const ber_sequence_t AttributeList_item_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_type },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_vals },
  { 0, 0, 0, NULL }
};

static int
dissect_ldap_AttributeList_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AttributeList_item_sequence, hf_index, ett_ldap_AttributeList_item);

  return offset;
}
static int dissect_AttributeList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_AttributeList_item(FALSE, tvb, offset, pinfo, tree, hf_ldap_AttributeList_item);
}


static const ber_sequence_t AttributeList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_AttributeList_item },
};

static int
dissect_ldap_AttributeList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      AttributeList_sequence_of, hf_index, ett_ldap_AttributeList);

  return offset;
}
static int dissect_attributes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_AttributeList(FALSE, tvb, offset, pinfo, tree, hf_ldap_attributes);
}


static const ber_sequence_t AddRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_entry },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_attributes },
  { 0, 0, 0, NULL }
};

static int
dissect_ldap_AddRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AddRequest_sequence, hf_index, ett_ldap_AddRequest);

  return offset;
}
static int dissect_addRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_AddRequest(FALSE, tvb, offset, pinfo, tree, hf_ldap_addRequest);
}



static int
dissect_ldap_AddResponse(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ldap_LDAPResult(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_addResponse(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_AddResponse(FALSE, tvb, offset, pinfo, tree, hf_ldap_addResponse);
}



static int
dissect_ldap_DelRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ldap_LDAPDN(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_delRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_DelRequest(FALSE, tvb, offset, pinfo, tree, hf_ldap_delRequest);
}



static int
dissect_ldap_DelResponse(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ldap_LDAPResult(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_delResponse(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_DelResponse(FALSE, tvb, offset, pinfo, tree, hf_ldap_delResponse);
}



static int
dissect_ldap_RelativeLDAPDN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ldap_LDAPString(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_newrdn(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_RelativeLDAPDN(FALSE, tvb, offset, pinfo, tree, hf_ldap_newrdn);
}


static const ber_sequence_t ModifyDNRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_entry },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_newrdn },
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_deleteoldrdn },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_newSuperior_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ldap_ModifyDNRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ModifyDNRequest_sequence, hf_index, ett_ldap_ModifyDNRequest);

  return offset;
}
static int dissect_modDNRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_ModifyDNRequest(FALSE, tvb, offset, pinfo, tree, hf_ldap_modDNRequest);
}



static int
dissect_ldap_ModifyDNResponse(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ldap_LDAPResult(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_modDNResponse(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_ModifyDNResponse(FALSE, tvb, offset, pinfo, tree, hf_ldap_modDNResponse);
}


static const ber_sequence_t CompareRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_entry },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ava },
  { 0, 0, 0, NULL }
};

static int
dissect_ldap_CompareRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CompareRequest_sequence, hf_index, ett_ldap_CompareRequest);

  return offset;
}
static int dissect_compareRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_CompareRequest(FALSE, tvb, offset, pinfo, tree, hf_ldap_compareRequest);
}



static int
dissect_ldap_CompareResponse(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ldap_LDAPResult(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_compareResponse(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_CompareResponse(FALSE, tvb, offset, pinfo, tree, hf_ldap_compareResponse);
}



static int
dissect_ldap_AbandonRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ldap_MessageID(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_abandonRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_AbandonRequest(FALSE, tvb, offset, pinfo, tree, hf_ldap_abandonRequest);
}



static int
dissect_ldap_LDAPOID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 32 "ldap.cnf"

	tvbuff_t	*parameter_tvb;
	const gchar *name;
	proto_item	*item = NULL;



  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

#line 39 "ldap.cnf"
	if (!parameter_tvb)
		return offset;
	item = get_ber_last_created_item();
	name = get_oid_str_name(tvb_get_string(parameter_tvb, 0, tvb_length_remaining(parameter_tvb,0)));
	if(name){
		proto_item_append_text(item, " (%s)", name);
		proto_item_append_text(tree, " %s", name);	
	}



  return offset;
}
static int dissect_requestName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_LDAPOID(TRUE, tvb, offset, pinfo, tree, hf_ldap_requestName);
}



static int
dissect_ldap_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_controlValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_ldap_controlValue);
}
static int dissect_requestValue_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_ldap_requestValue);
}
static int dissect_response_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_ldap_response);
}


static const ber_sequence_t ExtendedRequest_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_requestName_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_requestValue_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ldap_ExtendedRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ExtendedRequest_sequence, hf_index, ett_ldap_ExtendedRequest);

  return offset;
}
static int dissect_extendedReq(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_ExtendedRequest(FALSE, tvb, offset, pinfo, tree, hf_ldap_extendedReq);
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
  { 0, NULL }
};


static int
dissect_ldap_ExtendedResponse_resultCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_extendedResponse_resultCode(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_ExtendedResponse_resultCode(FALSE, tvb, offset, pinfo, tree, hf_ldap_extendedResponse_resultCode);
}



static int
dissect_ldap_ResponseName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ldap_LDAPOID(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_responseName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_ResponseName(TRUE, tvb, offset, pinfo, tree, hf_ldap_responseName);
}


static const ber_sequence_t ExtendedResponse_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_extendedResponse_resultCode },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_matchedDN },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_errorMessage },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_referral_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_responseName_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_response_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ldap_ExtendedResponse(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ExtendedResponse_sequence, hf_index, ett_ldap_ExtendedResponse);

  return offset;
}
static int dissect_extendedResp(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_ExtendedResponse(FALSE, tvb, offset, pinfo, tree, hf_ldap_extendedResp);
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
  { 0, NULL }
};

static const ber_choice_t ProtocolOp_choice[] = {
  {   0, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_bindRequest },
  {   1, BER_CLASS_APP, 1, BER_FLAGS_NOOWNTAG, dissect_bindResponse },
  {   2, BER_CLASS_APP, 2, BER_FLAGS_NOOWNTAG, dissect_unbindRequest },
  {   3, BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_searchRequest },
  {   4, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_searchResEntry },
  {   5, BER_CLASS_APP, 5, BER_FLAGS_NOOWNTAG, dissect_searchResDone },
  {  19, BER_CLASS_APP, 19, BER_FLAGS_NOOWNTAG, dissect_searchResRef },
  {   6, BER_CLASS_APP, 6, BER_FLAGS_NOOWNTAG, dissect_modifyRequest },
  {   7, BER_CLASS_APP, 7, BER_FLAGS_NOOWNTAG, dissect_modifyResponse },
  {   8, BER_CLASS_APP, 8, BER_FLAGS_NOOWNTAG, dissect_addRequest },
  {   9, BER_CLASS_APP, 9, BER_FLAGS_NOOWNTAG, dissect_addResponse },
  {  10, BER_CLASS_APP, 10, BER_FLAGS_NOOWNTAG, dissect_delRequest },
  {  11, BER_CLASS_APP, 11, BER_FLAGS_NOOWNTAG, dissect_delResponse },
  {  12, BER_CLASS_APP, 12, BER_FLAGS_NOOWNTAG, dissect_modDNRequest },
  {  13, BER_CLASS_APP, 13, BER_FLAGS_NOOWNTAG, dissect_modDNResponse },
  {  14, BER_CLASS_APP, 14, BER_FLAGS_NOOWNTAG, dissect_compareRequest },
  {  15, BER_CLASS_APP, 15, BER_FLAGS_NOOWNTAG, dissect_compareResponse },
  {  16, BER_CLASS_APP, 16, BER_FLAGS_NOOWNTAG, dissect_abandonRequest },
  {  23, BER_CLASS_APP, 23, BER_FLAGS_NOOWNTAG, dissect_extendedReq },
  {  24, BER_CLASS_APP, 24, BER_FLAGS_NOOWNTAG, dissect_extendedResp },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ldap_ProtocolOp(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 60 "ldap.cnf"

  ldap_call_response_t *lcrp;
  ldap_conv_info_t *ldap_info = (ldap_conv_info_t *)pinfo->private_data;
  do_protocolop = TRUE;


  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ProtocolOp_choice, hf_index, ett_ldap_ProtocolOp,
                                 &ProtocolOp);

#line 66 "ldap.cnf"

  lcrp=ldap_match_call_response(tvb, pinfo, tree, MessageID, ProtocolOp);
  if(lcrp){
    tap_queue_packet(ldap_tap, pinfo, lcrp);
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
  
    	if (check_col(pinfo->cinfo, COL_INFO))
          col_append_fstr(pinfo->cinfo, COL_INFO, " [%d result%s]", 
  	    	        ldap_info->num_results, ldap_info->num_results == 1 ? "" : "s");
  		        
  	proto_item_append_text(tree, " [%d result%s]", 
  		        ldap_info->num_results, ldap_info->num_results == 1 ? "" : "s");
  		        
  	ldap_info->num_results = 0;
    	break;
     default:
   	break;
    } 
  }
  

  return offset;
}
static int dissect_protocolOp(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_ProtocolOp(FALSE, tvb, offset, pinfo, tree, hf_ldap_protocolOp);
}



static int
dissect_ldap_ControlType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ldap_LDAPOID(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_controlType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_ControlType(FALSE, tvb, offset, pinfo, tree, hf_ldap_controlType);
}


static const ber_sequence_t Control_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_controlType },
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_criticality },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_controlValue },
  { 0, 0, 0, NULL }
};

static int
dissect_ldap_Control(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Control_sequence, hf_index, ett_ldap_Control);

  return offset;
}
static int dissect_Controls_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_Control(FALSE, tvb, offset, pinfo, tree, hf_ldap_Controls_item);
}


static const ber_sequence_t Controls_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_Controls_item },
};

static int
dissect_ldap_Controls(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      Controls_sequence_of, hf_index, ett_ldap_Controls);

  return offset;
}
static int dissect_controls_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ldap_Controls(TRUE, tvb, offset, pinfo, tree, hf_ldap_controls);
}


static const ber_sequence_t LDAPMessage_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_messageID },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_protocolOp },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_controls_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ldap_LDAPMessage(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LDAPMessage_sequence, hf_index, ett_ldap_LDAPMessage);

  return offset;
}



static int
dissect_ldap_AttributeType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ldap_LDAPString(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const ber_sequence_t Attribute_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_type },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_vals },
  { 0, 0, 0, NULL }
};

static int
dissect_ldap_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Attribute_sequence, hf_index, ett_ldap_Attribute);

  return offset;
}

/*--- PDUs ---*/

static void dissect_LDAPMessage_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ldap_LDAPMessage(FALSE, tvb, 0, pinfo, tree, hf_ldap_LDAPMessage_PDU);
}


/*--- End of included file: packet-ldap-fn.c ---*/
#line 630 "packet-ldap-template.c"

static int
dissect_ldap_AttributeValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  tvbuff_t	*parameter_tvb;
  gchar		*string;
  guint32	i, len;
  proto_item 	*pi;
  ldap_conv_info_t *ldap_info;

  ldap_info=(ldap_conv_info_t *)pinfo->private_data;
  /* if this is cldap then this might hold the RPC reply
   */
  if(ldap_info && ldap_info->is_mscldap && mscldap_rpc_call){

    offset = dissect_ber_octet_string(implicit_tag, pinfo, NULL, tvb, offset, hf_index, &parameter_tvb);
    dissect_mscldap_response(tree, parameter_tvb, mscldap_rpc_call);
    mscldap_rpc_call=0;

    return offset;
  }

  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

  
  len = tvb_length_remaining(parameter_tvb, 0);
  
  for(i = 0; i < len; i++) 
    if(!g_ascii_isprint(tvb_get_guint8(parameter_tvb, i)))
      break;
  
  if(i == len) {
    string = tvb_get_string(parameter_tvb, 0, tvb_length_remaining(parameter_tvb, 0));
 
    pi = get_ber_last_created_item();
     
    proto_item_set_text(pi, string);

  }

  return offset;
}

static int
dissect_ldap_AttributeDescription(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  tvbuff_t	*parameter_tvb = NULL;
  char          *ldapstring=NULL;
  ldap_conv_info_t *ldap_info;

  ldap_info=(ldap_conv_info_t *)pinfo->private_data;

  /* if this is cldap then this holds the name of the RPC function called
   * and we have to remember it until the value is dissected.
   */
  if(ldap_info && ldap_info->is_mscldap){
    mscldap_rpc_call=0;
    dissect_ber_octet_string(implicit_tag, pinfo, NULL, tvb, offset, hf_index,
                                       &parameter_tvb);
    if(parameter_tvb){
       ldapstring = tvb_get_string(parameter_tvb, 0, tvb_length_remaining(parameter_tvb, 0));
    }
     
    if(ldapstring){
       if(!strcmp(ldapstring, "netlogon")){
           mscldap_rpc_call=MSCLDAP_RPC_NETLOGON;
       }
       g_free(ldapstring);
    }
  }

  offset = dissect_ldap_LDAPString(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}

static void
dissect_ldap_payload(tvbuff_t *tvb, packet_info *pinfo,
		     proto_tree *tree, ldap_conv_info_t *ldap_info,
		     gboolean rest_is_pad, gboolean is_mscldap)
{
  int offset = 0;
  gboolean first_time = TRUE;
  guint length_remaining;
  guint msg_len = 0;
  int messageOffset = 0;
  guint headerLength = 0;
  guint length = 0;
  tvbuff_t *msg_tvb = NULL;
  gint8 class;
  gboolean pc, ind = 0;
  gint32 ber_tag;

  while (tvb_reported_length_remaining(tvb, offset) > 0) {
    /*
     * This will throw an exception if we don't have any data left.
     * That's what we want.  (See "tcp_dissect_pdus()", which is
     * similar)
     */
    length_remaining = tvb_ensure_length_remaining(tvb, offset);

    if (rest_is_pad && length_remaining < 6) return;

    /*
     * The frame begins
     * with a "Sequence Of" header.
     * Can we do reassembly?
     */
    if (ldap_desegment && pinfo->can_desegment) {
        /*
         * Yes - is the "Sequence Of" header split across segment
         * boundaries?  We require at least 6 bytes for the header
         * which allows for a 4 byte length (ASN.1 BER).
         */
        if (length_remaining < 6) {
	  /* stop if the caller says that we are given all data and the rest is padding
	   * this is for the SASL GSSAPI case when the data is only signed and not sealed
	   */
          pinfo->desegment_offset = offset;
          pinfo->desegment_len = 6 - length_remaining;
          return;
        }
    }

    /*
     * OK, try to read the "Sequence Of" header; this gets the total
     * length of the LDAP message.
     */
	messageOffset = get_ber_identifier(tvb, offset, &class, &pc, &ber_tag);
	messageOffset = get_ber_length(tree, tvb, messageOffset, &msg_len, &ind);

    if (ber_tag == BER_UNI_TAG_SEQUENCE) {
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
     * Is the message split across segment boundaries?
     */
    if (length_remaining < msg_len) {
        /* provide a hint to TCP where the next PDU starts */
        pinfo->want_pdu_tracking=2;
        pinfo->bytes_until_next_pdu= msg_len - length_remaining;
        /*
         * Can we do reassembly?
         */
        if (ldap_desegment && pinfo->can_desegment) {
	    /*
	     * Yes.  Tell the TCP dissector where the data for this message
	     * starts in the data it handed us, and how many more bytes
	     * we need, and return.
	     */
	    pinfo->desegment_offset = offset;
	    pinfo->desegment_len = msg_len - length_remaining;

	    return;
        }
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

    /*dissect_ldap_message(msg_tvb, 0, pinfo, msg_tree, msg_item, first_time, ldap_info, is_mscldap);*/
	ldap_info->first_time= first_time;
	ldap_info->is_mscldap = is_mscldap;
	pinfo->private_data = ldap_info;
	dissect_LDAPMessage_PDU(msg_tvb, pinfo, tree);


    offset += msg_len;

    first_time = FALSE;
  }
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

  /*
   * Do we have a conversation for this connection?
   */
  conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                   pinfo->ptype, pinfo->srcport,
                                   pinfo->destport, 0);
  if (conversation == NULL) {
    /* We don't yet have a conversation, so create one. */
    conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst,
    	                    	    pinfo->ptype, pinfo->srcport,
                                    pinfo->destport, 0);

  }

  /*
   * Do we already have a type and mechanism?
   */
  ldap_info = conversation_get_proto_data(conversation, proto_ldap);
  if (ldap_info == NULL) {
    /* No.  Attach that information to the conversation, and add
     * it to the list of information structures.
     */
    ldap_info = se_alloc(sizeof(ldap_conv_info_t));
    ldap_info->auth_type = 0;
    ldap_info->auth_mech = 0;
    ldap_info->first_auth_frame = 0;
    ldap_info->matched=g_hash_table_new(ldap_info_hash_matched, ldap_info_equal_matched);
    ldap_info->unmatched=g_hash_table_new(ldap_info_hash_unmatched, ldap_info_equal_unmatched);
    ldap_info->num_results = 0;

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

  while (tvb_reported_length_remaining(tvb, offset) > 0) {

    /*
     * This will throw an exception if we don't have any data left.
     * That's what we want.  (See "tcp_dissect_pdus()", which is
     * similar, but doesn't have to deal with the SASL issues.
     * XXX - can we make "tcp_dissect_pdus()" provide enough information
     * to the "get_pdu_len" routine so that we could have one dealing
     * with the SASL issues, have that routine deal with SASL and
     * ASN.1, and just use "tcp_dissect_pdus()"?)
     */
    length_remaining = tvb_ensure_length_remaining(tvb, offset);

    /*
     * Try to find out if we have a plain LDAP buffer
     * with a "Sequence Of" header or a SASL buffer with
     * Can we do reassembly?
     */
    if (ldap_desegment && pinfo->can_desegment) {
        /*
         * Yes - is the "Sequence Of" header split across segment
         * boundaries?  We require at least 6 bytes for the header
         * which allows for a 4 byte length (ASN.1 BER).
	 * For the SASL case we need at least 4 bytes, so this is
	 * no problem here because we check for 6 bytes ans sasl buffers
	 * with less than 2 bytes should not exist...
         */
        if (length_remaining < 6) {
    	    pinfo->desegment_offset = offset;
    	    pinfo->desegment_len = 6 - length_remaining;
    	    return;
        }
    }

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
    if (check_col(pinfo->cinfo, COL_PROTOCOL)) col_set_str(pinfo->cinfo, COL_PROTOCOL, pinfo->current_proto);
    if (check_col(pinfo->cinfo, COL_INFO)) col_clear(pinfo->cinfo, COL_INFO);

    ldap_item = proto_tree_add_item(tree, proto_ldap, tvb, 0, -1, FALSE);
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
       * Is the buffer split across segment boundaries?
       */
      if (length_remaining < sasl_msg_len) {
        /* provide a hint to TCP where the next PDU starts */
        pinfo->want_pdu_tracking = 2;
        pinfo->bytes_until_next_pdu= sasl_msg_len - length_remaining;
        /*
         * Can we do reassembly?
         */
        if (ldap_desegment && pinfo->can_desegment) {
          /*
           * Yes.  Tell the TCP dissector where the data for this message
           * starts in the data it handed us, and how many more bytes we
           * need, and return.
           */
          pinfo->desegment_offset = offset;
          pinfo->desegment_len = sasl_msg_len - length_remaining;
          return;
        }
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

        sasl_item = proto_tree_add_text(ldap_tree, sasl_tvb, 0,  sasl_msg_len, "SASL buffer");
        sasl_tree = proto_item_add_subtree(sasl_item, ett_ldap_sasl_blob);
      }

      if (ldap_info->auth_mech != NULL &&
          strcmp(ldap_info->auth_mech, "GSS-SPNEGO") == 0) {
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
	      plain_tvb = tvb_new_subset(gssapi_tvb,  ver_len, -1, -1);
	    }
	  }

          if (decr_tvb) {
	    proto_item *enc_item = NULL;
	    proto_tree *enc_tree = NULL;

            /*
             * The LDAP message was encrypted in the packet, and has
             * been decrypted; dissect the decrypted LDAP message.
             */
            if (sasl_tree) {
	      enc_item = proto_tree_add_text(sasl_tree, gssapi_tvb, ver_len, -1,
                                "GSS-API Encrypted payload (%d byte%s)",
                                sasl_len - ver_len,
                                plurality(sasl_len - ver_len, "", "s"));
	      enc_tree = proto_item_add_subtree(enc_item, ett_ldap_payload);
            }
	    dissect_ldap_payload(decr_tvb, pinfo, enc_tree, ldap_info, TRUE, is_mscldap);
          } else if (plain_tvb) {
	    proto_item *plain_item = NULL;
	    proto_tree *plain_tree = NULL;

	    /*
	     * The LDAP message wasn't encrypted in the packet;
	     * dissect the plain LDAP message.
             */
	    if (sasl_tree) {
              plain_item = proto_tree_add_text(sasl_tree, gssapi_tvb, ver_len, -1,
                                "GSS-API payload (%d byte%s)",
                                sasl_len - ver_len,
                                plurality(sasl_len - ver_len, "", "s"));
	      plain_tree = proto_item_add_subtree(plain_item, ett_ldap_payload);
            }

           dissect_ldap_payload(plain_tvb, pinfo, plain_tree, ldap_info, TRUE, is_mscldap);
	  } else {
            /*
             * The LDAP message was encrypted in the packet, and was
             * not decrypted; just show it as encrypted data.
             */
            if (check_col(pinfo->cinfo, COL_INFO)) {
        	    col_add_fstr(pinfo->cinfo, COL_INFO, "LDAP GSS-API Encrypted payload (%d byte%s)",
                                 sasl_len - ver_len,
                                 plurality(sasl_len - ver_len, "", "s"));
            }
	    if (sasl_tree) {
              proto_tree_add_text(sasl_tree, gssapi_tvb, ver_len, -1,
                                "GSS-API Encrypted payload (%d byte%s)",
                                sasl_len - ver_len,
                                plurality(sasl_len - ver_len, "", "s"));
	    }
          }
      }
      offset += sasl_msg_len;
    } else {
	/* plain LDAP, so dissect the payload */
	dissect_ldap_payload(tvb, pinfo, ldap_tree, ldap_info, FALSE, is_mscldap);
	/* dissect_ldap_payload() has it's own loop so go out here */
	break;
    }
  }
}
static void
dissect_ldap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_ldap_pdu(tvb, pinfo, tree, FALSE);
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
  for (ldap_info = ldap_info_items; ldap_info != NULL; ldap_info = ldap_info->next) {
    if (ldap_info->auth_mech != NULL) {
      g_free(ldap_info->auth_mech);
      ldap_info->auth_mech=NULL;
    }
    g_hash_table_destroy(ldap_info->matched);
    ldap_info->matched=NULL;
    g_hash_table_destroy(ldap_info->unmatched);
    ldap_info->unmatched=NULL;
  }

  ldap_info_items = NULL;

}
/*--- proto_register_ldap -------------------------------------------*/
void proto_register_ldap(void) {

  /* List of fields */

  static hf_register_info hf[] = {

    { &hf_mscldap_netlogon_type,
      { "Type", "mscldap.netlogon.type",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Type of <please tell ethereal developers what this type is>", HFILL }},

    { &hf_mscldap_netlogon_version,
      { "Version", "mscldap.netlogon.version",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Version of <please tell ethereal developers what this type is>", HFILL }},

    { &hf_mscldap_netlogon_lm_token,
      { "LM Token", "mscldap.netlogon.lm_token",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "LM Token", HFILL }},

    { &hf_mscldap_netlogon_nt_token,
      { "NT Token", "mscldap.netlogon.nt_token",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "NT Token", HFILL }},

    { &hf_mscldap_netlogon_flags,
      { "Flags", "mscldap.netlogon.flags",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "Netlogon flags describing the DC properties", HFILL }},

    { &hf_mscldap_domain_guid,
      { "Domain GUID", "mscldap.domain.guid",
        FT_BYTES, BASE_HEX, NULL, 0x0,
        "Domain GUID", HFILL }},

    { &hf_mscldap_forest,
      { "Forest", "mscldap.forest",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Forest", HFILL }},

    { &hf_mscldap_domain,
      { "Domain", "mscldap.domain",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Domainname", HFILL }},

    { &hf_mscldap_hostname,
      { "Hostname", "mscldap.hostname",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Hostname", HFILL }},

    { &hf_mscldap_nb_domain,
      { "NetBios Domain", "mscldap.nb_domain",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "NetBios Domainname", HFILL }},

    { &hf_mscldap_nb_hostname,
      { "NetBios Hostname", "mscldap.nb_hostname",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "NetBios Hostname", HFILL }},

    { &hf_mscldap_username,
      { "User", "mscldap.username",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "User name", HFILL }},

    { &hf_mscldap_sitename,
      { "Site", "mscldap.sitename",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Site name", HFILL }},

    { &hf_mscldap_clientsitename,
      { "Client Site", "mscldap.clientsitename",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Client Site name", HFILL }},

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
        TFS(&tfs_ads_closest), 0x00000080, "Is this the closest dc? (is this used at all?)", HFILL }},

    { &hf_mscldap_netlogon_flags_writable,
      { "Writable", "mscldap.netlogon.flags.writable", FT_BOOLEAN, 32,
        TFS(&tfs_ads_writable), 0x00000100, "Is this dc writable? (i.e. can it update the AD?)", HFILL }},

    { &hf_mscldap_netlogon_flags_good_timeserv,
      { "Good Time Serv", "mscldap.netlogon.flags.good_timeserv", FT_BOOLEAN, 32,
        TFS(&tfs_ads_good_timeserv), 0x00000200, "Is this a Good Time Server? (i.e. does it have a hardware clock)", HFILL }},

    { &hf_mscldap_netlogon_flags_ndnc,
      { "NDNC", "mscldap.netlogon.flags.ndnc", FT_BOOLEAN, 32,
        TFS(&tfs_ads_ndnc), 0x00000400, "Is this an NDNC dc?", HFILL }},


	  	{ &hf_ldap_sasl_buffer_length,
		  { "SASL Buffer Length",	"ldap.sasl_buffer_length",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"SASL Buffer Length", HFILL }},
	    { &hf_ldap_response_in,
	      { "Response In", "ldap.response_in",
	        FT_FRAMENUM, BASE_DEC, NULL, 0x0,
	        "The response to this LDAP request is in this frame", HFILL }},
	    { &hf_ldap_response_to,
	      { "Response To", "ldap.response_to",
	        FT_FRAMENUM, BASE_DEC, NULL, 0x0,
	        "This is a response to the LDAP request in this frame", HFILL }},
	    { &hf_ldap_time,
	      { "Time", "ldap.time",
	        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
	        "The time between the Call and the Reply", HFILL }},


/*--- Included file: packet-ldap-hfarr.c ---*/
#line 1 "packet-ldap-hfarr.c"
    { &hf_ldap_LDAPMessage_PDU,
      { "LDAPMessage", "ldap.LDAPMessage",
        FT_NONE, BASE_NONE, NULL, 0,
        "LDAPMessage", HFILL }},
    { &hf_ldap_messageID,
      { "messageID", "ldap.messageID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LDAPMessage/messageID", HFILL }},
    { &hf_ldap_protocolOp,
      { "protocolOp", "ldap.protocolOp",
        FT_UINT32, BASE_DEC, VALS(ldap_ProtocolOp_vals), 0,
        "LDAPMessage/protocolOp", HFILL }},
    { &hf_ldap_controls,
      { "controls", "ldap.controls",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LDAPMessage/controls", HFILL }},
    { &hf_ldap_bindRequest,
      { "bindRequest", "ldap.bindRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolOp/bindRequest", HFILL }},
    { &hf_ldap_bindResponse,
      { "bindResponse", "ldap.bindResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolOp/bindResponse", HFILL }},
    { &hf_ldap_unbindRequest,
      { "unbindRequest", "ldap.unbindRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolOp/unbindRequest", HFILL }},
    { &hf_ldap_searchRequest,
      { "searchRequest", "ldap.searchRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolOp/searchRequest", HFILL }},
    { &hf_ldap_searchResEntry,
      { "searchResEntry", "ldap.searchResEntry",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolOp/searchResEntry", HFILL }},
    { &hf_ldap_searchResDone,
      { "searchResDone", "ldap.searchResDone",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolOp/searchResDone", HFILL }},
    { &hf_ldap_searchResRef,
      { "searchResRef", "ldap.searchResRef",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolOp/searchResRef", HFILL }},
    { &hf_ldap_modifyRequest,
      { "modifyRequest", "ldap.modifyRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolOp/modifyRequest", HFILL }},
    { &hf_ldap_modifyResponse,
      { "modifyResponse", "ldap.modifyResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolOp/modifyResponse", HFILL }},
    { &hf_ldap_addRequest,
      { "addRequest", "ldap.addRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolOp/addRequest", HFILL }},
    { &hf_ldap_addResponse,
      { "addResponse", "ldap.addResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolOp/addResponse", HFILL }},
    { &hf_ldap_delRequest,
      { "delRequest", "ldap.delRequest",
        FT_STRING, BASE_NONE, NULL, 0,
        "ProtocolOp/delRequest", HFILL }},
    { &hf_ldap_delResponse,
      { "delResponse", "ldap.delResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolOp/delResponse", HFILL }},
    { &hf_ldap_modDNRequest,
      { "modDNRequest", "ldap.modDNRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolOp/modDNRequest", HFILL }},
    { &hf_ldap_modDNResponse,
      { "modDNResponse", "ldap.modDNResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolOp/modDNResponse", HFILL }},
    { &hf_ldap_compareRequest,
      { "compareRequest", "ldap.compareRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolOp/compareRequest", HFILL }},
    { &hf_ldap_compareResponse,
      { "compareResponse", "ldap.compareResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolOp/compareResponse", HFILL }},
    { &hf_ldap_abandonRequest,
      { "abandonRequest", "ldap.abandonRequest",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolOp/abandonRequest", HFILL }},
    { &hf_ldap_extendedReq,
      { "extendedReq", "ldap.extendedReq",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolOp/extendedReq", HFILL }},
    { &hf_ldap_extendedResp,
      { "extendedResp", "ldap.extendedResp",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolOp/extendedResp", HFILL }},
    { &hf_ldap_AttributeDescriptionList_item,
      { "Item", "ldap.AttributeDescriptionList_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "AttributeDescriptionList/_item", HFILL }},
    { &hf_ldap_attributeDesc,
      { "attributeDesc", "ldap.attributeDesc",
        FT_STRING, BASE_NONE, NULL, 0,
        "AttributeValueAssertion/attributeDesc", HFILL }},
    { &hf_ldap_assertionValue,
      { "assertionValue", "ldap.assertionValue",
        FT_BYTES, BASE_HEX, NULL, 0,
        "AttributeValueAssertion/assertionValue", HFILL }},
    { &hf_ldap_type,
      { "type", "ldap.type",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ldap_vals,
      { "vals", "ldap.vals",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_ldap_vals_item,
      { "Item", "ldap.vals_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_ldap_resultCode,
      { "resultCode", "ldap.resultCode",
        FT_UINT32, BASE_DEC, VALS(ldap_T_resultCode_vals), 0,
        "LDAPResult/resultCode", HFILL }},
    { &hf_ldap_matchedDN,
      { "matchedDN", "ldap.matchedDN",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ldap_errorMessage,
      { "errorMessage", "ldap.errorMessage",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ldap_referral,
      { "referral", "ldap.referral",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_ldap_Referral_item,
      { "Item", "ldap.Referral_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "Referral/_item", HFILL }},
    { &hf_ldap_Controls_item,
      { "Item", "ldap.Controls_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "Controls/_item", HFILL }},
    { &hf_ldap_controlType,
      { "controlType", "ldap.controlType",
        FT_STRING, BASE_NONE, NULL, 0,
        "Control/controlType", HFILL }},
    { &hf_ldap_criticality,
      { "criticality", "ldap.criticality",
        FT_BOOLEAN, 8, NULL, 0,
        "Control/criticality", HFILL }},
    { &hf_ldap_controlValue,
      { "controlValue", "ldap.controlValue",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Control/controlValue", HFILL }},
    { &hf_ldap_version,
      { "version", "ldap.version",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BindRequest/version", HFILL }},
    { &hf_ldap_name,
      { "name", "ldap.name",
        FT_STRING, BASE_NONE, NULL, 0,
        "BindRequest/name", HFILL }},
    { &hf_ldap_authentication,
      { "authentication", "ldap.authentication",
        FT_UINT32, BASE_DEC, VALS(ldap_AuthenticationChoice_vals), 0,
        "BindRequest/authentication", HFILL }},
    { &hf_ldap_simple,
      { "simple", "ldap.simple",
        FT_BYTES, BASE_HEX, NULL, 0,
        "AuthenticationChoice/simple", HFILL }},
    { &hf_ldap_sasl,
      { "sasl", "ldap.sasl",
        FT_NONE, BASE_NONE, NULL, 0,
        "AuthenticationChoice/sasl", HFILL }},
    { &hf_ldap_mechanism,
      { "mechanism", "ldap.mechanism",
        FT_STRING, BASE_NONE, NULL, 0,
        "SaslCredentials/mechanism", HFILL }},
    { &hf_ldap_credentials,
      { "credentials", "ldap.credentials",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SaslCredentials/credentials", HFILL }},
    { &hf_ldap_bindResponse_resultCode,
      { "resultCode", "ldap.resultCode",
        FT_UINT32, BASE_DEC, VALS(ldap_BindResponse_resultCode_vals), 0,
        "BindResponse/resultCode", HFILL }},
    { &hf_ldap_serverSaslCreds,
      { "serverSaslCreds", "ldap.serverSaslCreds",
        FT_BYTES, BASE_HEX, NULL, 0,
        "BindResponse/serverSaslCreds", HFILL }},
    { &hf_ldap_baseObject,
      { "baseObject", "ldap.baseObject",
        FT_STRING, BASE_NONE, NULL, 0,
        "SearchRequest/baseObject", HFILL }},
    { &hf_ldap_scope,
      { "scope", "ldap.scope",
        FT_UINT32, BASE_DEC, VALS(ldap_T_scope_vals), 0,
        "SearchRequest/scope", HFILL }},
    { &hf_ldap_derefAliases,
      { "derefAliases", "ldap.derefAliases",
        FT_UINT32, BASE_DEC, VALS(ldap_T_derefAliases_vals), 0,
        "SearchRequest/derefAliases", HFILL }},
    { &hf_ldap_sizeLimit,
      { "sizeLimit", "ldap.sizeLimit",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SearchRequest/sizeLimit", HFILL }},
    { &hf_ldap_timeLimit,
      { "timeLimit", "ldap.timeLimit",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SearchRequest/timeLimit", HFILL }},
    { &hf_ldap_typesOnly,
      { "typesOnly", "ldap.typesOnly",
        FT_BOOLEAN, 8, NULL, 0,
        "SearchRequest/typesOnly", HFILL }},
    { &hf_ldap_filter,
      { "filter", "ldap.filter",
        FT_UINT32, BASE_DEC, VALS(ldap_Filter_vals), 0,
        "SearchRequest/filter", HFILL }},
    { &hf_ldap_searchRequest_attributes,
      { "attributes", "ldap.attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SearchRequest/attributes", HFILL }},
    { &hf_ldap_and,
      { "and", "ldap.and",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Filter/and", HFILL }},
    { &hf_ldap_and_item,
      { "Item", "ldap.and_item",
        FT_UINT32, BASE_DEC, VALS(ldap_Filter_vals), 0,
        "Filter/and/_item", HFILL }},
    { &hf_ldap_or,
      { "or", "ldap.or",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Filter/or", HFILL }},
    { &hf_ldap_or_item,
      { "Item", "ldap.or_item",
        FT_UINT32, BASE_DEC, VALS(ldap_Filter_vals), 0,
        "Filter/or/_item", HFILL }},
    { &hf_ldap_not,
      { "not", "ldap.not",
        FT_UINT32, BASE_DEC, VALS(ldap_Filter_vals), 0,
        "Filter/not", HFILL }},
    { &hf_ldap_equalityMatch,
      { "equalityMatch", "ldap.equalityMatch",
        FT_NONE, BASE_NONE, NULL, 0,
        "Filter/equalityMatch", HFILL }},
    { &hf_ldap_substrings,
      { "substrings", "ldap.substrings",
        FT_NONE, BASE_NONE, NULL, 0,
        "Filter/substrings", HFILL }},
    { &hf_ldap_greaterOrEqual,
      { "greaterOrEqual", "ldap.greaterOrEqual",
        FT_NONE, BASE_NONE, NULL, 0,
        "Filter/greaterOrEqual", HFILL }},
    { &hf_ldap_lessOrEqual,
      { "lessOrEqual", "ldap.lessOrEqual",
        FT_NONE, BASE_NONE, NULL, 0,
        "Filter/lessOrEqual", HFILL }},
    { &hf_ldap_present,
      { "present", "ldap.present",
        FT_STRING, BASE_NONE, NULL, 0,
        "Filter/present", HFILL }},
    { &hf_ldap_approxMatch,
      { "approxMatch", "ldap.approxMatch",
        FT_NONE, BASE_NONE, NULL, 0,
        "Filter/approxMatch", HFILL }},
    { &hf_ldap_extensibleMatch,
      { "extensibleMatch", "ldap.extensibleMatch",
        FT_NONE, BASE_NONE, NULL, 0,
        "Filter/extensibleMatch", HFILL }},
    { &hf_ldap_substringFilter_substrings,
      { "substrings", "ldap.substrings",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SubstringFilter/substrings", HFILL }},
    { &hf_ldap_substrings_item,
      { "Item", "ldap.substrings_item",
        FT_UINT32, BASE_DEC, VALS(ldap_T_substrings_item_vals), 0,
        "SubstringFilter/substrings/_item", HFILL }},
    { &hf_ldap_initial,
      { "initial", "ldap.initial",
        FT_STRING, BASE_NONE, NULL, 0,
        "SubstringFilter/substrings/_item/initial", HFILL }},
    { &hf_ldap_any,
      { "any", "ldap.any",
        FT_STRING, BASE_NONE, NULL, 0,
        "SubstringFilter/substrings/_item/any", HFILL }},
    { &hf_ldap_final,
      { "final", "ldap.final",
        FT_STRING, BASE_NONE, NULL, 0,
        "SubstringFilter/substrings/_item/final", HFILL }},
    { &hf_ldap_matchingRule,
      { "matchingRule", "ldap.matchingRule",
        FT_STRING, BASE_NONE, NULL, 0,
        "MatchingRuleAssertion/matchingRule", HFILL }},
    { &hf_ldap_matchValue,
      { "matchValue", "ldap.matchValue",
        FT_BYTES, BASE_HEX, NULL, 0,
        "MatchingRuleAssertion/matchValue", HFILL }},
    { &hf_ldap_dnAttributes,
      { "dnAttributes", "ldap.dnAttributes",
        FT_BOOLEAN, 8, NULL, 0,
        "MatchingRuleAssertion/dnAttributes", HFILL }},
    { &hf_ldap_objectName,
      { "objectName", "ldap.objectName",
        FT_STRING, BASE_NONE, NULL, 0,
        "SearchResultEntry/objectName", HFILL }},
    { &hf_ldap_searchResultEntry_attributes,
      { "attributes", "ldap.attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SearchResultEntry/attributes", HFILL }},
    { &hf_ldap_PartialAttributeList_item,
      { "Item", "ldap.PartialAttributeList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartialAttributeList/_item", HFILL }},
    { &hf_ldap_SearchResultReference_item,
      { "Item", "ldap.SearchResultReference_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "SearchResultReference/_item", HFILL }},
    { &hf_ldap_object,
      { "object", "ldap.object",
        FT_STRING, BASE_NONE, NULL, 0,
        "ModifyRequest/object", HFILL }},
    { &hf_ldap_modifyRequest_modification,
      { "modification", "ldap.modification",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ModifyRequest/modification", HFILL }},
    { &hf_ldap_modification_item,
      { "Item", "ldap.modification_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyRequest/modification/_item", HFILL }},
    { &hf_ldap_operation,
      { "operation", "ldap.operation",
        FT_UINT32, BASE_DEC, VALS(ldap_T_operation_vals), 0,
        "ModifyRequest/modification/_item/operation", HFILL }},
    { &hf_ldap_modification,
      { "modification", "ldap.modification",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyRequest/modification/_item/modification", HFILL }},
    { &hf_ldap_entry,
      { "entry", "ldap.entry",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ldap_attributes,
      { "attributes", "ldap.attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AddRequest/attributes", HFILL }},
    { &hf_ldap_AttributeList_item,
      { "Item", "ldap.AttributeList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeList/_item", HFILL }},
    { &hf_ldap_newrdn,
      { "newrdn", "ldap.newrdn",
        FT_STRING, BASE_NONE, NULL, 0,
        "ModifyDNRequest/newrdn", HFILL }},
    { &hf_ldap_deleteoldrdn,
      { "deleteoldrdn", "ldap.deleteoldrdn",
        FT_BOOLEAN, 8, NULL, 0,
        "ModifyDNRequest/deleteoldrdn", HFILL }},
    { &hf_ldap_newSuperior,
      { "newSuperior", "ldap.newSuperior",
        FT_STRING, BASE_NONE, NULL, 0,
        "ModifyDNRequest/newSuperior", HFILL }},
    { &hf_ldap_ava,
      { "ava", "ldap.ava",
        FT_NONE, BASE_NONE, NULL, 0,
        "CompareRequest/ava", HFILL }},
    { &hf_ldap_requestName,
      { "requestName", "ldap.requestName",
        FT_STRING, BASE_NONE, NULL, 0,
        "ExtendedRequest/requestName", HFILL }},
    { &hf_ldap_requestValue,
      { "requestValue", "ldap.requestValue",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ExtendedRequest/requestValue", HFILL }},
    { &hf_ldap_extendedResponse_resultCode,
      { "resultCode", "ldap.resultCode",
        FT_UINT32, BASE_DEC, VALS(ldap_ExtendedResponse_resultCode_vals), 0,
        "ExtendedResponse/resultCode", HFILL }},
    { &hf_ldap_responseName,
      { "responseName", "ldap.responseName",
        FT_STRING, BASE_NONE, NULL, 0,
        "ExtendedResponse/responseName", HFILL }},
    { &hf_ldap_response,
      { "response", "ldap.response",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ExtendedResponse/response", HFILL }},

/*--- End of included file: packet-ldap-hfarr.c ---*/
#line 1342 "packet-ldap-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_ldap,
	&ett_ldap_payload,
    &ett_ldap_sasl_blob,
	&ett_ldap_msg,
    &ett_mscldap_netlogon_flags,


/*--- Included file: packet-ldap-ettarr.c ---*/
#line 1 "packet-ldap-ettarr.c"
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
    &ett_ldap_BindRequest,
    &ett_ldap_AuthenticationChoice,
    &ett_ldap_SaslCredentials,
    &ett_ldap_BindResponse,
    &ett_ldap_SearchRequest,
    &ett_ldap_Filter,
    &ett_ldap_SET_OF_Filter,
    &ett_ldap_SubstringFilter,
    &ett_ldap_T_substrings,
    &ett_ldap_T_substrings_item,
    &ett_ldap_MatchingRuleAssertion,
    &ett_ldap_SearchResultEntry,
    &ett_ldap_PartialAttributeList,
    &ett_ldap_PartialAttributeList_item,
    &ett_ldap_SearchResultReference,
    &ett_ldap_ModifyRequest,
    &ett_ldap_ModifyRequest_modification,
    &ett_ldap_T_modification_item,
    &ett_ldap_AttributeTypeAndValues,
    &ett_ldap_AddRequest,
    &ett_ldap_AttributeList,
    &ett_ldap_AttributeList_item,
    &ett_ldap_ModifyDNRequest,
    &ett_ldap_CompareRequest,
    &ett_ldap_ExtendedRequest,
    &ett_ldap_ExtendedResponse,

/*--- End of included file: packet-ldap-ettarr.c ---*/
#line 1353 "packet-ldap-template.c"
  };

    module_t *ldap_module;

  /* Register protocol */
  proto_ldap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_ldap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));


  register_dissector("ldap", dissect_ldap, proto_ldap);

  ldap_module = prefs_register_protocol(proto_ldap, NULL);
  prefs_register_bool_preference(ldap_module, "desegment_ldap_messages",
    "Reassemble LDAP messages spanning multiple TCP segments",
    "Whether the LDAP dissector should reassemble messages spanning multiple TCP segments."
    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings, and disable \"Verify length\" in the BER protocol settings",
    &ldap_desegment);

  prefs_register_uint_preference(ldap_module, "tcp.port", "LDAP TCP Port",
				 "Set the port for LDAP operations",
				 10, &ldap_tcp_port);

  proto_cldap = proto_register_protocol(
	  "Connectionless Lightweight Directory Access Protocol",
	  "CLDAP", "cldap");

  register_init_routine(ldap_reinit);
  ldap_tap=register_tap("ldap");

}


/*--- proto_reg_handoff_ldap ---------------------------------------*/
void
proto_reg_handoff_ldap(void)
{
	dissector_handle_t ldap_handle, cldap_handle;
	ldap_handle = create_dissector_handle(dissect_ldap, proto_ldap);

	dissector_add("tcp.port", ldap_tcp_port, ldap_handle);
	dissector_add("tcp.port", TCP_PORT_GLOBALCAT_LDAP, ldap_handle);

	cldap_handle = create_dissector_handle(dissect_mscldap, proto_cldap);
	dissector_add("udp.port", UDP_PORT_CLDAP, cldap_handle);

	gssapi_handle = find_dissector("gssapi");
	gssapi_wrap_handle = find_dissector("gssapi_verf");

/*  http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dsml/dsml/ldap_controls_and_session_support.asp */
	register_ber_oid_name("1.2.840.113556.1.4.319","LDAP_PAGED_RESULT_OID_STRING");
	register_ber_oid_name("1.2.840.113556.1.4.417","LDAP_SERVER_SHOW_DELETED_OID");
	register_ber_oid_name("1.2.840.113556.1.4.473","LDAP_SERVER_SORT_OID");
	register_ber_oid_name("1.2.840.113556.1.4.521","LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID");
	register_ber_oid_name("1.2.840.113556.1.4.528","LDAP_SERVER_NOTIFICATION_OID");
	register_ber_oid_name("1.2.840.113556.1.4.529","LDAP_SERVER_EXTENDED_DN_OID");
	register_ber_oid_name("1.2.840.113556.1.4.619","LDAP_SERVER_LAZY_COMMIT_OID");
	register_ber_oid_name("1.2.840.113556.1.4.801","LDAP_SERVER_SD_FLAGS_OID");
	register_ber_oid_name("1.2.840.113556.1.4.805","LDAP_SERVER_TREE_DELETE_OID");
	register_ber_oid_name("1.2.840.113556.1.4.841","LDAP_SERVER_DIRSYNC_OID");
	register_ber_oid_name("1.2.840.113556.1.4.970 ","None");
	register_ber_oid_name("1.2.840.113556.1.4.1338","LDAP_SERVER_VERIFY_NAME_OID");
	register_ber_oid_name("1.2.840.113556.1.4.1339","LDAP_SERVER_DOMAIN_SCOPE_OID");
	register_ber_oid_name("1.2.840.113556.1.4.1340","LDAP_SERVER_SEARCH_OPTIONS_OID");
	register_ber_oid_name("1.2.840.113556.1.4.1413","LDAP_SERVER_PERMISSIVE_MODIFY_OID");
	register_ber_oid_name("1.2.840.113556.1.4.1504","LDAP_SERVER_ASQ_OID");
	register_ber_oid_name("1.2.840.113556.1.4.1781","LDAP_SERVER_FAST_BIND_OID");
	register_ber_oid_name("1.3.6.1.4.1.1466.101.119.1","None");
	register_ber_oid_name("1.3.6.1.4.1.1466.20037","LDAP_START_TLS_OID");
	register_ber_oid_name("2.16.840.1.113730.3.4.9","LDAP_CONTROL_VLVREQUEST VLV");


}


