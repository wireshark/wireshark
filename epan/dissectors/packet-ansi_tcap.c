/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-ansi_tcap.c                                                         */
/* ../../tools/asn2wrs.py -b -p ansi_tcap -c ./ansi_tcap.cnf -s ./packet-ansi_tcap-template -D . -O ../../epan/dissectors TCAP-Remote-Operations-Information-Objects.asn TCAPPackage.asn */

/* Input file: packet-ansi_tcap-template.c */

#line 1 "../../asn1/ansi_tcap/packet-ansi_tcap-template.c"
/* packet-ansi_tcap-template.c
 * Routines for ANSI TCAP
 * Copyright 2007 Anders Broman <anders.broman@ericsson.com>
 * Built from the gsm-map dissector Copyright 2004 - 2005, Anders Broman <anders.broman@ericsson.com>
 *
 * $Id$
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
 * References: T1.114
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/oids.h>
#include <epan/emem.h>
#include <epan/asn1.h>
#include <epan/strutil.h>

#include <string.h>
#include "packet-ber.h"
#include "packet-tcap.h"
#include "packet-ansi_tcap.h"
#include <epan/tcap-persistentdata.h>

#define PNAME  "ANSI Transaction Capabilities Application Part"
#define PSNAME "ANSI_TCAP"
#define PFNAME "ansi_tcap"


/* Preferences defaults */
gint ansi_tcap_response_matching_type = 0;

/* Initialize the protocol and registered fields */
static int proto_ansi_tcap = -1;

static int hf_ansi_tcapsrt_SessionId = -1;
static int hf_ansi_tcapsrt_Duplicate = -1;
static int hf_ansi_tcapsrt_BeginSession = -1;
static int hf_ansi_tcapsrt_EndSession = -1;
static int hf_ansi_tcapsrt_SessionTime = -1;
static int hf_ansi_tcap_bit_h = -1;
static int hf_ansi_tcap_op_family = -1;
static int hf_ansi_tcap_op_specifier = -1;


/*--- Included file: packet-ansi_tcap-hf.c ---*/
#line 1 "../../asn1/ansi_tcap/packet-ansi_tcap-hf.c"
static int hf_ansi_tcap_national = -1;            /* T_national */
static int hf_ansi_tcap_private = -1;             /* T_private */
static int hf_ansi_tcap_national_01 = -1;         /* INTEGER_M128_127 */
static int hf_ansi_tcap_private_01 = -1;          /* INTEGER */
static int hf_ansi_tcap_unidirectional = -1;      /* T_unidirectional */
static int hf_ansi_tcap_queryWithPerm = -1;       /* T_queryWithPerm */
static int hf_ansi_tcap_queryWithoutPerm = -1;    /* T_queryWithoutPerm */
static int hf_ansi_tcap_response = -1;            /* T_response */
static int hf_ansi_tcap_conversationWithPerm = -1;  /* T_conversationWithPerm */
static int hf_ansi_tcap_conversationWithoutPerm = -1;  /* T_conversationWithoutPerm */
static int hf_ansi_tcap_abort = -1;               /* T_abort */
static int hf_ansi_tcap_identifier = -1;          /* TransactionID */
static int hf_ansi_tcap_dialoguePortion = -1;     /* DialoguePortion */
static int hf_ansi_tcap_componentPortion = -1;    /* ComponentSequence */
static int hf_ansi_tcap_dialogPortion = -1;       /* DialoguePortion */
static int hf_ansi_tcap_causeInformation = -1;    /* T_causeInformation */
static int hf_ansi_tcap_abortCause = -1;          /* P_Abort_cause */
static int hf_ansi_tcap_userInformation = -1;     /* UserAbortInformation */
static int hf_ansi_tcap_version = -1;             /* ProtocolVersion */
static int hf_ansi_tcap_applicationContext = -1;  /* T_applicationContext */
static int hf_ansi_tcap_integerApplicationId = -1;  /* IntegerApplicationContext */
static int hf_ansi_tcap_objectApplicationId = -1;  /* ObjectIDApplicationContext */
static int hf_ansi_tcap_userInformation_01 = -1;  /* UserInformation */
static int hf_ansi_tcap_securityContext = -1;     /* T_securityContext */
static int hf_ansi_tcap_integerSecurityId = -1;   /* INTEGER */
static int hf_ansi_tcap_objectSecurityId = -1;    /* OBJECT_IDENTIFIER */
static int hf_ansi_tcap_confidentiality = -1;     /* Confidentiality */
static int hf_ansi_tcap__untag_item = -1;         /* EXTERNAL */
static int hf_ansi_tcap_confidentialityId = -1;   /* T_confidentialityId */
static int hf_ansi_tcap_integerConfidentialityId = -1;  /* INTEGER */
static int hf_ansi_tcap_objectConfidentialityId = -1;  /* OBJECT_IDENTIFIER */
static int hf_ansi_tcap__untag_item_01 = -1;      /* ComponentPDU */
static int hf_ansi_tcap_invokeLast = -1;          /* Invoke */
static int hf_ansi_tcap_returnResultLast = -1;    /* ReturnResult */
static int hf_ansi_tcap_returnError = -1;         /* ReturnError */
static int hf_ansi_tcap_reject = -1;              /* Reject */
static int hf_ansi_tcap_invokeNotLast = -1;       /* Invoke */
static int hf_ansi_tcap_returnResultNotLast = -1;  /* ReturnResult */
static int hf_ansi_tcap_componentIDs = -1;        /* T_componentIDs */
static int hf_ansi_tcap_operationCode = -1;       /* OperationCode */
static int hf_ansi_tcap_parameter = -1;           /* T_parameter */
static int hf_ansi_tcap_componentID = -1;         /* T_componentID */
static int hf_ansi_tcap_parameter_01 = -1;        /* T_parameter_01 */
static int hf_ansi_tcap_componentID_01 = -1;      /* T_componentID_01 */
static int hf_ansi_tcap_errorCode = -1;           /* ErrorCode */
static int hf_ansi_tcap_parameter_02 = -1;        /* T_parameter_02 */
static int hf_ansi_tcap_componentID_02 = -1;      /* OCTET_STRING_SIZE_0_1 */
static int hf_ansi_tcap_rejectProblem = -1;       /* Problem */
static int hf_ansi_tcap_parameter_03 = -1;        /* T_parameter_03 */
static int hf_ansi_tcap_paramSequence = -1;       /* T_paramSequence */
static int hf_ansi_tcap_paramSet = -1;            /* T_paramSet */

/*--- End of included file: packet-ansi_tcap-hf.c ---*/
#line 64 "../../asn1/ansi_tcap/packet-ansi_tcap-template.c"

/* Initialize the subtree pointers */
static gint ett_tcap = -1;
static gint ett_param = -1;
static gint ett_ansi_tcap_op_code_nat = -1;

static gint ett_otid = -1;
static gint ett_dtid = -1;
static gint ett_ansi_tcap_stat = -1;

static struct tcapsrt_info_t * gp_tcapsrt_info;
static gboolean tcap_subdissector_used=FALSE;

static struct tcaphash_context_t * gp_tcap_context=NULL;

/* Note the high bit should be masked off when registering in this table (0x7fff)*/
static dissector_table_t	ansi_tcap_national_opcode_table; /* National Operation Codes */


/*--- Included file: packet-ansi_tcap-ett.c ---*/
#line 1 "../../asn1/ansi_tcap/packet-ansi_tcap-ett.c"
static gint ett_ansi_tcap_OperationCode = -1;
static gint ett_ansi_tcap_ErrorCode = -1;
static gint ett_ansi_tcap_PackageType = -1;
static gint ett_ansi_tcap_UniTransactionPDU = -1;
static gint ett_ansi_tcap_TransactionPDU = -1;
static gint ett_ansi_tcap_Abort = -1;
static gint ett_ansi_tcap_T_causeInformation = -1;
static gint ett_ansi_tcap_DialoguePortion_U = -1;
static gint ett_ansi_tcap_T_applicationContext = -1;
static gint ett_ansi_tcap_T_securityContext = -1;
static gint ett_ansi_tcap_UserInformation_U = -1;
static gint ett_ansi_tcap_Confidentiality = -1;
static gint ett_ansi_tcap_T_confidentialityId = -1;
static gint ett_ansi_tcap_SEQUENCE_OF_ComponentPDU = -1;
static gint ett_ansi_tcap_ComponentPDU = -1;
static gint ett_ansi_tcap_Invoke = -1;
static gint ett_ansi_tcap_ReturnResult = -1;
static gint ett_ansi_tcap_ReturnError = -1;
static gint ett_ansi_tcap_Reject = -1;
static gint ett_ansi_tcap_T_parameter_03 = -1;
static gint ett_ansi_tcap_T_paramSequence = -1;
static gint ett_ansi_tcap_T_paramSet = -1;

/*--- End of included file: packet-ansi_tcap-ett.c ---*/
#line 83 "../../asn1/ansi_tcap/packet-ansi_tcap-template.c"

#define MAX_SSN 254

extern gboolean gtcap_PersistentSRT;
extern guint gtcap_RepetitionTimeout;
extern guint gtcap_LostTimeout;

static dissector_table_t ber_oid_dissector_table=NULL;
static const char * cur_oid;
static const char * tcapext_oid;
static proto_tree * tcap_top_tree=NULL;
static proto_tree * tcap_stat_tree=NULL;
static proto_item * tcap_stat_item=NULL;

static dissector_handle_t ansi_map_handle;

struct ansi_tcap_private_t ansi_tcap_private;
#define MAX_TID_STR_LEN 1024

static void ansi_tcap_ctx_init(struct ansi_tcap_private_t *a_tcap_ctx) {
  memset(a_tcap_ctx, '\0', sizeof(*a_tcap_ctx));
  a_tcap_ctx->signature = ANSI_TCAP_CTX_SIGNATURE;
  a_tcap_ctx->oid_is_present = FALSE;
  a_tcap_ctx->TransactionID_str = NULL;
}

static const value_string ansi_tcap_national_op_code_family_vals[] = {
  {  0x0, "All Families" },
  {  0x1, "Parameter" },
  {  0x2, "Charging" },
  {  0x3, "Provide Instructions" },
  {  0x4, "Connection Control" },
  {  0x5, "Caller Interaction" },
  {  0x6, "Send Notification" },
  {  0x7, "Network Management" },
  {  0x8, "Procedural" },
  {  0x9, "Operation Control" },
  {  0xa, "Report Event" },
  /* Spare */
  {  0x7e, "Miscellaneous" },
  {  0x7f, "Reserved" },
  { 0, NULL }
};

static void dissect_ansi_tcap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree);

/*
static dissector_handle_t tcap_handle = NULL;
static dissector_table_t sccp_ssn_table;

static GHashTable* ansi_sub_dissectors = NULL;
static GHashTable* itu_sub_dissectors = NULL;

  extern void add_ansi_tcap_subdissector(guint32 ssn, dissector_handle_t dissector) {
    g_hash_table_insert(ansi_sub_dissectors,GUINT_TO_POINTER(ssn),dissector);
    dissector_add_uint("sccp.ssn",ssn,tcap_handle);
}

extern void delete_ansi_tcap_subdissector(guint32 ssn, dissector_handle_t dissector _U_) {
    g_hash_table_remove(ansi_sub_dissectors,GUINT_TO_POINTER(ssn));
    dissector_delete_uint("sccp.ssn",ssn,tcap_handle);
}

dissector_handle_t get_ansi_tcap_subdissector(guint32 ssn) {
    return g_hash_table_lookup(ansi_sub_dissectors,GUINT_TO_POINTER(ssn));
}
*/

/* Transaction tracking */
/* Transaction table */
struct ansi_tcap_invokedata_t {
    gint OperationCode;
      /*
         0 : national,
         1 : private
      */
    gint32 OperationCode_private;
    gint32 OperationCode_national;
};

static GHashTable *TransactionId_table=NULL;

static void
ansi_tcap_init_transaction_table(void){

        /* Destroy any existing memory chunks / hashes. */
        if (TransactionId_table){
                g_hash_table_destroy(TransactionId_table);
                TransactionId_table = NULL;
        }

        TransactionId_table = g_hash_table_new(g_str_hash, g_str_equal);

}

static void
ansi_tcap_init_protocol(void)
{
        ansi_tcap_init_transaction_table();
}

/* Store Invoke information needed for the corresponding reply */
static void
save_invoke_data(packet_info *pinfo, proto_tree *tree _U_, tvbuff_t *tvb _U_){
  struct ansi_tcap_invokedata_t *ansi_tcap_saved_invokedata;
  address* src = &(pinfo->src);
  address* dst = &(pinfo->dst);
  char *buf;

  if ((!pinfo->fd->flags.visited)&&(ansi_tcap_private.TransactionID_str)){

          /* Only do this once XXX I hope its the right thing to do */
          /* The hash string needs to contain src and dest to distiguish differnt flows */
		  switch(ansi_tcap_response_matching_type){
				case 0:
					buf = ep_strdup(ansi_tcap_private.TransactionID_str);
					break;
				case 1:
					buf = ep_strdup_printf("%s%s",ansi_tcap_private.TransactionID_str,ep_address_to_str(src));
					break;
				default:
					buf = ep_strdup_printf("%s%s%s",ansi_tcap_private.TransactionID_str,ep_address_to_str(src),ep_address_to_str(dst));
					break;
			}

          /* If the entry allready exists don't owervrite it */
          ansi_tcap_saved_invokedata = (struct ansi_tcap_invokedata_t *)g_hash_table_lookup(TransactionId_table,buf);
          if(ansi_tcap_saved_invokedata)
                  return;

          ansi_tcap_saved_invokedata = se_new(struct ansi_tcap_invokedata_t);
          ansi_tcap_saved_invokedata->OperationCode = ansi_tcap_private.d.OperationCode;
          ansi_tcap_saved_invokedata->OperationCode_national = ansi_tcap_private.d.OperationCode_national;
          ansi_tcap_saved_invokedata->OperationCode_private = ansi_tcap_private.d.OperationCode_private;

          g_hash_table_insert(TransactionId_table,
                        se_strdup(buf),
                        ansi_tcap_saved_invokedata);
          /*
          g_warning("Tcap Invoke Hash string %s",buf);
          */
  }
}

static gboolean
find_saved_invokedata(packet_info *pinfo, proto_tree *tree _U_, tvbuff_t *tvb _U_){
  struct ansi_tcap_invokedata_t *ansi_tcap_saved_invokedata;
  address* src = &(pinfo->src);
  address* dst = &(pinfo->dst);
  char *buf;

  if (!ansi_tcap_private.TransactionID_str) {
    return FALSE;
  }

  /* The hash string needs to contain src and dest to distiguish differnt flows */
  buf = ep_alloc(MAX_TID_STR_LEN);
  buf[0] = '\0';
  /* Reverse order to invoke */
  g_snprintf(buf, MAX_TID_STR_LEN, "%s%s%s",
        ansi_tcap_private.TransactionID_str, ep_address_to_str(dst),
        ep_address_to_str(src));
  switch(ansi_tcap_response_matching_type){
		case 0:
			g_snprintf(buf,MAX_TID_STR_LEN,"%s",ansi_tcap_private.TransactionID_str);
			break;
		case 1:
			g_snprintf(buf,MAX_TID_STR_LEN,"%s%s",ansi_tcap_private.TransactionID_str,ep_address_to_str(dst));
			break;
		default:
			g_snprintf(buf,MAX_TID_STR_LEN,"%s%s%s",ansi_tcap_private.TransactionID_str,ep_address_to_str(dst),ep_address_to_str(src));
			break;
	}

  ansi_tcap_saved_invokedata = (struct ansi_tcap_invokedata_t *)g_hash_table_lookup(TransactionId_table, buf);
  if(ansi_tcap_saved_invokedata){
          ansi_tcap_private.d.OperationCode                      = ansi_tcap_saved_invokedata->OperationCode;
          ansi_tcap_private.d.OperationCode_national = ansi_tcap_saved_invokedata->OperationCode_national;
          ansi_tcap_private.d.OperationCode_private  = ansi_tcap_saved_invokedata->OperationCode_private;
          return TRUE;
  }
  return FALSE;
}

/* As currently ANSI MAP is the only possible sub dissector this function
 *  must be improved to handle general cases.
 *
 *
 *
 * TODO:
 * 1)Handle national codes
 *     Design option
 *     - Create a ansi.tcap.national dissector table and have dissectors for
 *       national codes register there and let ansi tcap call them.
 * 2)Handle Private codes properly
 *     Design question
 *     Unclear how to differentiate between different private "code sets".
 *     Use SCCP SSN table as before? or a ansi.tcap.private dissector table?
 *
 */
static gboolean
find_tcap_subdissector(tvbuff_t *tvb, asn1_ctx_t *actx, proto_tree *tree){
        proto_item *item;

        /* If "DialoguePortion objectApplicationId ObjectIDApplicationContext
         * points to the subdissector this code can be used.
         *
        if(ansi_tcap_private.d.oid_is_present){
                call_ber_oid_callback(ansi_tcap_private.objectApplicationId_oid, tvb, 0, actx-pinfo, tree);
                return TRUE;
        }
        */
        if(ansi_tcap_private.d.pdu == 1){
                /* Save Invoke data for this transaction */
                save_invoke_data(actx->pinfo, tree, tvb);
        }else{
                /* Get saved data for this transaction */
                if(find_saved_invokedata(actx->pinfo, tree, tvb)){
                        if(ansi_tcap_private.d.OperationCode == 0){
                                /* national */
                                item = proto_tree_add_int(tree, hf_ansi_tcap_national, tvb, 0, 0, ansi_tcap_private.d.OperationCode_national);
                        }else{
                                item = proto_tree_add_int(tree, hf_ansi_tcap_private, tvb, 0, 0, ansi_tcap_private.d.OperationCode_private);
                        }
                        PROTO_ITEM_SET_GENERATED(item);
                        ansi_tcap_private.d.OperationCode_item = item;
                }
        }
        if(ansi_tcap_private.d.OperationCode == 0){
                /* national */
				guint8 family = (ansi_tcap_private.d.OperationCode_national & 0x7f00)>>8;
				guint8 specifier = (guint8)(ansi_tcap_private.d.OperationCode_national & 0xff);
				if(!dissector_try_uint(ansi_tcap_national_opcode_table, ansi_tcap_private.d.OperationCode_national, tvb, actx->pinfo, tcap_top_tree)){
					item = proto_tree_add_text(tree, tvb, 0, -1,
							"Dissector for ANSI TCAP NATIONAL code:0x%x(Family %u, Specifier %u) \n"
							"not implemented. Contact Wireshark developers if you want this supported(Spec required)",
							ansi_tcap_private.d.OperationCode_national, family, specifier);
					PROTO_ITEM_SET_GENERATED(item);
					return FALSE;
				}
				return TRUE;
        }else if(ansi_tcap_private.d.OperationCode == 1){
                /* private */
                if((ansi_tcap_private.d.OperationCode_private & 0x0900) != 0x0900){
                        item = proto_tree_add_text(tree, tvb, 0, -1,
                                "Dissector for ANSI TCAP PRIVATE code:%u not implemented.\n"
								"Contact Wireshark developers if you want this supported(Spec required)",
                                ansi_tcap_private.d.OperationCode_private);
                        PROTO_ITEM_SET_GENERATED(item);
                        return FALSE;
                }
        }
        /* This is abit of a hack as it assumes the private codes with a "family" of 0x09 is ANSI MAP
         * See TODO above.
         * N.S0005-0 v 1.0 TCAP Formats and Procedures 5-16 Application Services
         * 6.3.2 Component Portion
         * The Operation Code is partitioned into an Operation Family followed by a
         * Specifier associated with each Operation Family member. For TIA/EIA-41 the
         * Operation Family is coded as decimal 9. Bit H of the Operation Family is always
         * coded as 0.
         */
        call_dissector(ansi_map_handle, tvb, actx->pinfo, tcap_top_tree);

        return TRUE;
}


/*--- Included file: packet-ansi_tcap-fn.c ---*/
#line 1 "../../asn1/ansi_tcap/packet-ansi_tcap-fn.c"


static int
dissect_ansi_tcap_T_national(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 20 "../../asn1/ansi_tcap/ansi_tcap.cnf"
 proto_tree *subtree;
 proto_item *spcifier_item;
 int start_offset = offset;
 guint8 family;
 guint8 specifier;
 
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &ansi_tcap_private.d.OperationCode_national);

  /* mask off the H bit */
  ansi_tcap_private.d.OperationCode_national = (ansi_tcap_private.d.OperationCode_national&0x7fff);
 
  subtree = proto_item_add_subtree(actx->created_item, ett_ansi_tcap_op_code_nat);
  /* Bit H is used to distinguish between Operations that require a reply and those that do not. A value of 1
   * indicates that a reply is required; a value of 0 indicates that a reply is not required.
   */
  family = (ansi_tcap_private.d.OperationCode_national & 0x7f00)>>8;
  specifier = (guint8)(ansi_tcap_private.d.OperationCode_national & 0xff);
  proto_tree_add_item(subtree, hf_ansi_tcap_bit_h, tvb, start_offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(subtree, hf_ansi_tcap_op_family, tvb, start_offset, 2, ENC_BIG_ENDIAN);
  spcifier_item = proto_tree_add_item(subtree, hf_ansi_tcap_op_specifier, tvb, start_offset, 2, ENC_BIG_ENDIAN);

  switch(family){
	case 0:
		/* All Families ( Not used ) */
		break;
	case 1:
		/* Parameter */
		if(specifier== 1){
			proto_item_append_text(spcifier_item, " Provide Value");
		}else if (specifier== 2){
			proto_item_append_text(spcifier_item, " Set Value");
		}
		break;
	case 2:
		/* Charging */
		if (specifier== 1){
			proto_item_append_text(spcifier_item, " Bill Call");
		}
		break;
	case 3:
		/* Provide Instructions */
		if (specifier== 1){
			proto_item_append_text(spcifier_item, " Start");
		}else if (specifier== 2){
			proto_item_append_text(spcifier_item, " Assist");
		}
		break;
	case 4:
		/* Connection Control */
		if (specifier== 1){
			proto_item_append_text(spcifier_item, " Connect");
		}else if (specifier== 2){
			proto_item_append_text(spcifier_item, " Temporary Connect");
		}else if (specifier== 3){
			proto_item_append_text(spcifier_item, " Disconnect");
		}else if (specifier== 4){
			proto_item_append_text(spcifier_item, " Forward Disconnect");
		}
		break;
	default:
		break;
  }
  



  return offset;
}



static int
dissect_ansi_tcap_T_private(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &ansi_tcap_private.d.OperationCode_private);

  return offset;
}


static const value_string ansi_tcap_OperationCode_vals[] = {
  {  16, "national" },
  {  17, "private" },
  { 0, NULL }
};

static const ber_choice_t OperationCode_choice[] = {
  {  16, &hf_ansi_tcap_national  , BER_CLASS_PRI, 16, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_national },
  {  17, &hf_ansi_tcap_private   , BER_CLASS_PRI, 17, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_private },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_OperationCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 OperationCode_choice, hf_index, ett_ansi_tcap_OperationCode,
                                 &ansi_tcap_private.d.OperationCode);

#line 16 "../../asn1/ansi_tcap/ansi_tcap.cnf"
  ansi_tcap_private.d.OperationCode_item = actx->created_item;

  return offset;
}



static int
dissect_ansi_tcap_INTEGER_M128_127(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ansi_tcap_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string ansi_tcap_ErrorCode_vals[] = {
  {  19, "national" },
  {  20, "private" },
  { 0, NULL }
};

static const ber_choice_t ErrorCode_choice[] = {
  {  19, &hf_ansi_tcap_national_01, BER_CLASS_PRI, 19, 0, dissect_ansi_tcap_INTEGER_M128_127 },
  {  20, &hf_ansi_tcap_private_01, BER_CLASS_PRI, 20, 0, dissect_ansi_tcap_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_ErrorCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ErrorCode_choice, hf_index, ett_ansi_tcap_ErrorCode,
                                 NULL);

  return offset;
}



static int
dissect_ansi_tcap_TransactionID_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 152 "../../asn1/ansi_tcap/ansi_tcap.cnf"

tvbuff_t *next_tvb;
guint8 len;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &next_tvb);


if(next_tvb) {
	len = tvb_length_remaining(next_tvb, 0);
	if(len !=0){
		/* 0 octets for the Unidirectional, 
		 * 4 octets for Query, Response & Abort
		 * 8 octets for Conversation in the order Originating then Responding TID
		 * 
		 * In order to match this it seems like we should only use the last 4 octets
		 * in the 8 octets case.
		 */
		if (len > 4){
			ansi_tcap_private.TransactionID_str = tvb_bytes_to_str(next_tvb, 4,len-4);
		}else{
			ansi_tcap_private.TransactionID_str = tvb_bytes_to_str(next_tvb, 0,len);
		}
	}
	switch(len) {
	case 1:
		gp_tcapsrt_info->src_tid=tvb_get_guint8(next_tvb, 0);
		break;
	case 2:
		gp_tcapsrt_info->src_tid=tvb_get_ntohs(next_tvb, 0);
		break;
	case 4:
		gp_tcapsrt_info->src_tid=tvb_get_ntohl(next_tvb, 0);
		break;
	default:
		gp_tcapsrt_info->src_tid=0;
		break;
	}
}



  return offset;
}



static int
dissect_ansi_tcap_TransactionID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 7, TRUE, dissect_ansi_tcap_TransactionID_U);

  return offset;
}



static int
dissect_ansi_tcap_OCTET_STRING_SIZE_1(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ansi_tcap_ProtocolVersion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 26, TRUE, dissect_ansi_tcap_OCTET_STRING_SIZE_1);

  return offset;
}



static int
dissect_ansi_tcap_IntegerApplicationContext(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 27, TRUE, dissect_ansi_tcap_INTEGER);

  return offset;
}



static int
dissect_ansi_tcap_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_ansi_tcap_ObjectIDApplicationContext(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 116 "../../asn1/ansi_tcap/ansi_tcap.cnf"

 static const char * oid_str;

   offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 28, TRUE, dissect_ansi_tcap_OBJECT_IDENTIFIER);

 	ansi_tcap_private.objectApplicationId_oid= (void*) oid_str;
	ansi_tcap_private.oid_is_present=TRUE;



  return offset;
}


static const value_string ansi_tcap_T_applicationContext_vals[] = {
  {  27, "integerApplicationId" },
  {  28, "objectApplicationId" },
  { 0, NULL }
};

static const ber_choice_t T_applicationContext_choice[] = {
  {  27, &hf_ansi_tcap_integerApplicationId, BER_CLASS_PRI, 27, BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_IntegerApplicationContext },
  {  28, &hf_ansi_tcap_objectApplicationId, BER_CLASS_PRI, 28, BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_ObjectIDApplicationContext },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_T_applicationContext(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_applicationContext_choice, hf_index, ett_ansi_tcap_T_applicationContext,
                                 NULL);

  return offset;
}



static int
dissect_ansi_tcap_EXTERNAL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_external_type(implicit_tag, tree, tvb, offset, actx, hf_index, NULL);

  return offset;
}


static const ber_sequence_t UserInformation_U_sequence_of[1] = {
  { &hf_ansi_tcap__untag_item, BER_CLASS_UNI, BER_UNI_TAG_EXTERNAL, BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_EXTERNAL },
};

static int
dissect_ansi_tcap_UserInformation_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      UserInformation_U_sequence_of, hf_index, ett_ansi_tcap_UserInformation_U);

  return offset;
}



static int
dissect_ansi_tcap_UserInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 29, TRUE, dissect_ansi_tcap_UserInformation_U);

  return offset;
}


static const value_string ansi_tcap_T_securityContext_vals[] = {
  {   0, "integerSecurityId" },
  {   1, "objectSecurityId" },
  { 0, NULL }
};

static const ber_choice_t T_securityContext_choice[] = {
  {   0, &hf_ansi_tcap_integerSecurityId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_INTEGER },
  {   1, &hf_ansi_tcap_objectSecurityId, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_OBJECT_IDENTIFIER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_T_securityContext(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_securityContext_choice, hf_index, ett_ansi_tcap_T_securityContext,
                                 NULL);

  return offset;
}


static const value_string ansi_tcap_T_confidentialityId_vals[] = {
  {   0, "integerConfidentialityId" },
  {   1, "objectConfidentialityId" },
  { 0, NULL }
};

static const ber_choice_t T_confidentialityId_choice[] = {
  {   0, &hf_ansi_tcap_integerConfidentialityId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_INTEGER },
  {   1, &hf_ansi_tcap_objectConfidentialityId, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_OBJECT_IDENTIFIER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_T_confidentialityId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_confidentialityId_choice, hf_index, ett_ansi_tcap_T_confidentialityId,
                                 NULL);

  return offset;
}


static const ber_sequence_t Confidentiality_sequence[] = {
  { &hf_ansi_tcap_confidentialityId, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ansi_tcap_T_confidentialityId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_Confidentiality(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Confidentiality_sequence, hf_index, ett_ansi_tcap_Confidentiality);

  return offset;
}


static const ber_sequence_t DialoguePortion_U_sequence[] = {
  { &hf_ansi_tcap_version   , BER_CLASS_PRI, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_ProtocolVersion },
  { &hf_ansi_tcap_applicationContext, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ansi_tcap_T_applicationContext },
  { &hf_ansi_tcap_userInformation_01, BER_CLASS_PRI, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_UserInformation },
  { &hf_ansi_tcap_securityContext, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ansi_tcap_T_securityContext },
  { &hf_ansi_tcap_confidentiality, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ansi_tcap_Confidentiality },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_DialoguePortion_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DialoguePortion_U_sequence, hf_index, ett_ansi_tcap_DialoguePortion_U);

  return offset;
}



static int
dissect_ansi_tcap_DialoguePortion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 25, TRUE, dissect_ansi_tcap_DialoguePortion_U);

  return offset;
}



static int
dissect_ansi_tcap_T_componentIDs(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ansi_tcap_T_parameter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 85 "../../asn1/ansi_tcap/ansi_tcap.cnf"

  if(find_tcap_subdissector(tvb, actx, tree))
    offset = tvb_length(tvb);
  



  return offset;
}


static const ber_sequence_t Invoke_sequence[] = {
  { &hf_ansi_tcap_componentIDs, BER_CLASS_PRI, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_componentIDs },
  { &hf_ansi_tcap_operationCode, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ansi_tcap_OperationCode },
  { &hf_ansi_tcap_parameter , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_T_parameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_Invoke(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 91 "../../asn1/ansi_tcap/ansi_tcap.cnf"
  ansi_tcap_private.d.pdu = 1;



  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Invoke_sequence, hf_index, ett_ansi_tcap_Invoke);

  return offset;
}



static int
dissect_ansi_tcap_T_componentID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ansi_tcap_T_parameter_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 98 "../../asn1/ansi_tcap/ansi_tcap.cnf"
  if(find_tcap_subdissector(tvb, actx, tree))
    offset = tvb_length(tvb);



  return offset;
}


static const ber_sequence_t ReturnResult_sequence[] = {
  { &hf_ansi_tcap_componentID, BER_CLASS_PRI, 15, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_componentID },
  { &hf_ansi_tcap_parameter_01, BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_T_parameter_01 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_ReturnResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 102 "../../asn1/ansi_tcap/ansi_tcap.cnf"
  ansi_tcap_private.d.pdu = 2;




  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReturnResult_sequence, hf_index, ett_ansi_tcap_ReturnResult);

  return offset;
}



static int
dissect_ansi_tcap_T_componentID_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ansi_tcap_T_parameter_02(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 108 "../../asn1/ansi_tcap/ansi_tcap.cnf"
  if(find_tcap_subdissector(tvb, actx, tree))
    offset = tvb_length(tvb);



  return offset;
}


static const ber_sequence_t ReturnError_sequence[] = {
  { &hf_ansi_tcap_componentID_01, BER_CLASS_PRI, 15, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_componentID_01 },
  { &hf_ansi_tcap_errorCode , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ansi_tcap_ErrorCode },
  { &hf_ansi_tcap_parameter_02, BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_T_parameter_02 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_ReturnError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 112 "../../asn1/ansi_tcap/ansi_tcap.cnf"
  ansi_tcap_private.d.pdu = 3;


  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReturnError_sequence, hf_index, ett_ansi_tcap_ReturnError);

  return offset;
}



static int
dissect_ansi_tcap_OCTET_STRING_SIZE_0_1(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string ansi_tcap_Problem_vals[] = {
  { 257, "general-unrecognisedComponentType" },
  { 258, "general-incorrectComponentPortion" },
  { 259, "general-badlyStructuredCompPortion" },
  { 260, "general-incorrectComponentCoding" },
  { 513, "invoke-duplicateInvocation" },
  { 514, "invoke-unrecognisedOperation" },
  { 515, "invoke-incorrectParameter" },
  { 516, "invoke-unrecognisedCorrelationID" },
  { 769, "returnResult-unrecognisedCorrelationID" },
  { 770, "returnResult-unexpectedReturnResult" },
  { 771, "returnResult-incorrectParameter" },
  { 1025, "returnError-unrecognisedCorrelationID" },
  { 1026, "returnError-unexpectedReturnError" },
  { 1027, "returnError-unrecognisedError" },
  { 1028, "returnError-unexpectedError" },
  { 1029, "returnError-incorrectParameter" },
  { 1281, "transaction-unrecognizedPackageType" },
  { 1282, "transaction-incorrectTransPortion" },
  { 1283, "transaction-badlyStructuredTransPortion" },
  { 1284, "transaction-unassignedRespondingTransID" },
  { 1285, "transaction-permissionToReleaseProblem" },
  { 1286, "transaction-resourceUnavailable" },
  { 0, NULL }
};


static int
dissect_ansi_tcap_Problem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t T_paramSequence_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_T_paramSequence(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_paramSequence_sequence, hf_index, ett_ansi_tcap_T_paramSequence);

  return offset;
}


static const ber_sequence_t T_paramSet_set[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_T_paramSet(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              T_paramSet_set, hf_index, ett_ansi_tcap_T_paramSet);

  return offset;
}


static const value_string ansi_tcap_T_parameter_03_vals[] = {
  {  16, "paramSequence" },
  {  18, "paramSet" },
  { 0, NULL }
};

static const ber_choice_t T_parameter_03_choice[] = {
  {  16, &hf_ansi_tcap_paramSequence, BER_CLASS_PRI, 16, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_paramSequence },
  {  18, &hf_ansi_tcap_paramSet  , BER_CLASS_PRI, 18, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_paramSet },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_T_parameter_03(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_parameter_03_choice, hf_index, ett_ansi_tcap_T_parameter_03,
                                 NULL);

  return offset;
}


static const ber_sequence_t Reject_sequence[] = {
  { &hf_ansi_tcap_componentID_02, BER_CLASS_PRI, 15, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_OCTET_STRING_SIZE_0_1 },
  { &hf_ansi_tcap_rejectProblem, BER_CLASS_PRI, 21, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_Problem },
  { &hf_ansi_tcap_parameter_03, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ansi_tcap_T_parameter_03 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_Reject(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Reject_sequence, hf_index, ett_ansi_tcap_Reject);

  return offset;
}


static const value_string ansi_tcap_ComponentPDU_vals[] = {
  {   9, "invokeLast" },
  {  10, "returnResultLast" },
  {  11, "returnError" },
  {  12, "reject" },
  {  13, "invokeNotLast" },
  {  14, "returnResultNotLast" },
  { 0, NULL }
};

static const ber_choice_t ComponentPDU_choice[] = {
  {   9, &hf_ansi_tcap_invokeLast, BER_CLASS_PRI, 9, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_Invoke },
  {  10, &hf_ansi_tcap_returnResultLast, BER_CLASS_PRI, 10, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_ReturnResult },
  {  11, &hf_ansi_tcap_returnError, BER_CLASS_PRI, 11, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_ReturnError },
  {  12, &hf_ansi_tcap_reject    , BER_CLASS_PRI, 12, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_Reject },
  {  13, &hf_ansi_tcap_invokeNotLast, BER_CLASS_PRI, 13, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_Invoke },
  {  14, &hf_ansi_tcap_returnResultNotLast, BER_CLASS_PRI, 14, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_ReturnResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_ComponentPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ComponentPDU_choice, hf_index, ett_ansi_tcap_ComponentPDU,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ComponentPDU_sequence_of[1] = {
  { &hf_ansi_tcap__untag_item_01, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ansi_tcap_ComponentPDU },
};

static int
dissect_ansi_tcap_SEQUENCE_OF_ComponentPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ComponentPDU_sequence_of, hf_index, ett_ansi_tcap_SEQUENCE_OF_ComponentPDU);

  return offset;
}



static int
dissect_ansi_tcap_ComponentSequence(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 8, TRUE, dissect_ansi_tcap_SEQUENCE_OF_ComponentPDU);

  return offset;
}


static const ber_sequence_t UniTransactionPDU_sequence[] = {
  { &hf_ansi_tcap_identifier, BER_CLASS_PRI, 7, BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_TransactionID },
  { &hf_ansi_tcap_dialoguePortion, BER_CLASS_PRI, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_DialoguePortion },
  { &hf_ansi_tcap_componentPortion, BER_CLASS_PRI, 8, BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_ComponentSequence },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_UniTransactionPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UniTransactionPDU_sequence, hf_index, ett_ansi_tcap_UniTransactionPDU);

  return offset;
}



static int
dissect_ansi_tcap_T_unidirectional(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 124 "../../asn1/ansi_tcap/ansi_tcap.cnf"
gp_tcapsrt_info->ope=TC_ANSI_ALL;
col_set_str(actx->pinfo->cinfo, COL_INFO, "unidirectional ");


  offset = dissect_ansi_tcap_UniTransactionPDU(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t TransactionPDU_sequence[] = {
  { &hf_ansi_tcap_identifier, BER_CLASS_PRI, 7, BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_TransactionID },
  { &hf_ansi_tcap_dialoguePortion, BER_CLASS_PRI, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_DialoguePortion },
  { &hf_ansi_tcap_componentPortion, BER_CLASS_PRI, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_ComponentSequence },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_TransactionPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TransactionPDU_sequence, hf_index, ett_ansi_tcap_TransactionPDU);

  return offset;
}



static int
dissect_ansi_tcap_T_queryWithPerm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 128 "../../asn1/ansi_tcap/ansi_tcap.cnf"
gp_tcapsrt_info->ope=TC_ANSI_ALL;
col_set_str(actx->pinfo->cinfo, COL_INFO, "queryWithPerm ");


  offset = dissect_ansi_tcap_TransactionPDU(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ansi_tcap_T_queryWithoutPerm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 132 "../../asn1/ansi_tcap/ansi_tcap.cnf"
gp_tcapsrt_info->ope=TC_ANSI_ALL;
col_set_str(actx->pinfo->cinfo, COL_INFO, "queryWithoutPerm ");


  offset = dissect_ansi_tcap_TransactionPDU(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ansi_tcap_T_response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 136 "../../asn1/ansi_tcap/ansi_tcap.cnf"
gp_tcapsrt_info->ope=TC_ANSI_ALL;
col_set_str(actx->pinfo->cinfo, COL_INFO, "response ");


  offset = dissect_ansi_tcap_TransactionPDU(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ansi_tcap_T_conversationWithPerm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 140 "../../asn1/ansi_tcap/ansi_tcap.cnf"
gp_tcapsrt_info->ope=TC_ANSI_ALL;
col_set_str(actx->pinfo->cinfo, COL_INFO, "conversationWithPerm ");


  offset = dissect_ansi_tcap_TransactionPDU(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ansi_tcap_T_conversationWithoutPerm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 144 "../../asn1/ansi_tcap/ansi_tcap.cnf"
gp_tcapsrt_info->ope=TC_ANSI_ALL;
col_set_str(actx->pinfo->cinfo, COL_INFO, "conversationWithoutPerm ");


  offset = dissect_ansi_tcap_TransactionPDU(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string ansi_tcap_P_Abort_cause_U_vals[] = {
  {   1, "unrecognizedPackageType" },
  {   2, "incorrectTransactionPortion" },
  {   3, "badlyStructuredTransactionPortion" },
  {   4, "unassignedRespondingTransactionID" },
  {   5, "permissionToReleaseProblem" },
  {   6, "resourceUnavailable" },
  {   7, "unrecognizedDialoguePortionID" },
  {   8, "badlyStructuredDialoguePortion" },
  {   9, "missingDialoguePortion" },
  {  10, "inconsistentDialoguePortion" },
  { 0, NULL }
};


static int
dissect_ansi_tcap_P_Abort_cause_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ansi_tcap_P_Abort_cause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 23, TRUE, dissect_ansi_tcap_P_Abort_cause_U);

  return offset;
}



static int
dissect_ansi_tcap_UserAbortInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 24, FALSE, dissect_ansi_tcap_EXTERNAL);

  return offset;
}


static const value_string ansi_tcap_T_causeInformation_vals[] = {
  {  23, "abortCause" },
  {  24, "userInformation" },
  { 0, NULL }
};

static const ber_choice_t T_causeInformation_choice[] = {
  {  23, &hf_ansi_tcap_abortCause, BER_CLASS_PRI, 23, BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_P_Abort_cause },
  {  24, &hf_ansi_tcap_userInformation, BER_CLASS_PRI, 24, BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_UserAbortInformation },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_T_causeInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_causeInformation_choice, hf_index, ett_ansi_tcap_T_causeInformation,
                                 NULL);

  return offset;
}


static const ber_sequence_t Abort_sequence[] = {
  { &hf_ansi_tcap_identifier, BER_CLASS_PRI, 7, BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_TransactionID },
  { &hf_ansi_tcap_dialogPortion, BER_CLASS_PRI, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_DialoguePortion },
  { &hf_ansi_tcap_causeInformation, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ansi_tcap_T_causeInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_Abort(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Abort_sequence, hf_index, ett_ansi_tcap_Abort);

  return offset;
}



static int
dissect_ansi_tcap_T_abort(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 148 "../../asn1/ansi_tcap/ansi_tcap.cnf"
gp_tcapsrt_info->ope=TC_ANSI_ABORT;
col_set_str(actx->pinfo->cinfo, COL_INFO, "Abort ");


  offset = dissect_ansi_tcap_Abort(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string ansi_tcap_PackageType_vals[] = {
  {   1, "unidirectional" },
  {   2, "queryWithPerm" },
  {   3, "queryWithoutPerm" },
  {   4, "response" },
  {   5, "conversationWithPerm" },
  {   6, "conversationWithoutPerm" },
  {  22, "abort" },
  { 0, NULL }
};

static const ber_choice_t PackageType_choice[] = {
  {   1, &hf_ansi_tcap_unidirectional, BER_CLASS_PRI, 1, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_unidirectional },
  {   2, &hf_ansi_tcap_queryWithPerm, BER_CLASS_PRI, 2, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_queryWithPerm },
  {   3, &hf_ansi_tcap_queryWithoutPerm, BER_CLASS_PRI, 3, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_queryWithoutPerm },
  {   4, &hf_ansi_tcap_response  , BER_CLASS_PRI, 4, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_response },
  {   5, &hf_ansi_tcap_conversationWithPerm, BER_CLASS_PRI, 5, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_conversationWithPerm },
  {   6, &hf_ansi_tcap_conversationWithoutPerm, BER_CLASS_PRI, 6, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_conversationWithoutPerm },
  {  22, &hf_ansi_tcap_abort     , BER_CLASS_PRI, 22, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_abort },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_PackageType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PackageType_choice, hf_index, ett_ansi_tcap_PackageType,
                                 NULL);

  return offset;
}


/*--- End of included file: packet-ansi_tcap-fn.c ---*/
#line 350 "../../asn1/ansi_tcap/packet-ansi_tcap-template.c"




static void
dissect_ansi_tcap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
    proto_item          *item=NULL;
    proto_tree          *tree=NULL;
#if 0
    proto_item          *stat_item=NULL;
    proto_tree          *stat_tree=NULL;
        gint                    offset = 0;
    struct tcaphash_context_t * p_tcap_context;
    dissector_handle_t subdissector_handle;
#endif
        asn1_ctx_t asn1_ctx;

        asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
        ansi_tcap_ctx_init(&ansi_tcap_private);

    tcap_top_tree = parent_tree;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ANSI TCAP");

    /* create display subtree for the protocol */
    if(parent_tree){
      item = proto_tree_add_item(parent_tree, proto_ansi_tcap, tvb, 0, -1, ENC_NA);
      tree = proto_item_add_subtree(item, ett_tcap);
      tcap_stat_item=item;
      tcap_stat_tree=tree;
    }
    cur_oid = NULL;
    tcapext_oid = NULL;

    pinfo->private_data = &ansi_tcap_private;
    gp_tcapsrt_info=tcapsrt_razinfo();
    tcap_subdissector_used=FALSE;
    gp_tcap_context=NULL;
    dissect_ansi_tcap_PackageType(FALSE, tvb, 0, &asn1_ctx, tree, -1);

#if 0 /* Skip this part for now it will be rewritten */
    if (g_ansi_tcap_HandleSRT && !tcap_subdissector_used ) {
                if (gtcap_DisplaySRT && tree) {
                        stat_item = proto_tree_add_text(tree, tvb, 0, 0, "Stat");
                        PROTO_ITEM_SET_GENERATED(stat_item);
                        stat_tree = proto_item_add_subtree(stat_item, ett_ansi_tcap_stat);
                }
                p_tcap_context=tcapsrt_call_matching(tvb, pinfo, stat_tree, gp_tcapsrt_info);
                ansi_tcap_private.context=p_tcap_context;

                /* If the current message is TCAP only,
                 * save the Application contexte name for the next messages
                 */
                if ( p_tcap_context && cur_oid && !p_tcap_context->oid_present ) {
                        /* Save the application context and the sub dissector */
                        g_strlcpy(p_tcap_context->oid, cur_oid, sizeof(p_tcap_context->oid));
                        if ( (subdissector_handle = dissector_get_string_handle(ber_oid_dissector_table, cur_oid)) ) {
                                p_tcap_context->subdissector_handle=subdissector_handle;
                                p_tcap_context->oid_present=TRUE;
                        }
                }
                if (g_ansi_tcap_HandleSRT && p_tcap_context && p_tcap_context->callback) {
                        /* Callback fonction for the upper layer */
                        (p_tcap_context->callback)(tvb, pinfo, stat_tree, p_tcap_context);
                }
        }
#endif
}


void
proto_reg_handoff_ansi_tcap(void)
{

        ansi_map_handle = find_dissector("ansi_map");
        ber_oid_dissector_table = find_dissector_table("ber.oid");
}



void
proto_register_ansi_tcap(void)
{
    module_t    *ansi_tcap_module;


/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        /* Tcap Service Response Time */
        { &hf_ansi_tcapsrt_SessionId,
          { "Session Id",
            "ansi_tcap.srt.session_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcapsrt_BeginSession,
          { "Begin Session",
            "ansi_tcap.srt.begin",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "SRT Begin of Session", HFILL }
        },
        { &hf_ansi_tcapsrt_EndSession,
          { "End Session",
            "ansi_tcap.srt.end",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "SRT End of Session", HFILL }
        },
        { &hf_ansi_tcapsrt_SessionTime,
          { "Session duration",
            "ansi_tcap.srt.sessiontime",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            "Duration of the TCAP session", HFILL }
        },
        { &hf_ansi_tcapsrt_Duplicate,
          { "Request Duplicate",
            "ansi_tcap.srt.duplicate",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
		{ &hf_ansi_tcap_bit_h,
          { "Require Reply", "ansi_tcap.req_rep",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
		{ &hf_ansi_tcap_op_family,
          { "Family",
            "ansi_tcap.op_family",
            FT_UINT16, BASE_DEC, VALS(ansi_tcap_national_op_code_family_vals), 0x7f00,
            NULL, HFILL }
        },
		{ &hf_ansi_tcap_op_specifier,
          { "Specifier",
            "ansi_tcap.op_specifier",
            FT_UINT16, BASE_DEC, NULL, 0x00ff,
            NULL, HFILL }
        },

/*--- Included file: packet-ansi_tcap-hfarr.c ---*/
#line 1 "../../asn1/ansi_tcap/packet-ansi_tcap-hfarr.c"
    { &hf_ansi_tcap_national,
      { "national", "ansi_tcap.national",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_private,
      { "private", "ansi_tcap.private",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_national_01,
      { "national", "ansi_tcap.national",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M128_127", HFILL }},
    { &hf_ansi_tcap_private_01,
      { "private", "ansi_tcap.private",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ansi_tcap_unidirectional,
      { "unidirectional", "ansi_tcap.unidirectional",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_queryWithPerm,
      { "queryWithPerm", "ansi_tcap.queryWithPerm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_queryWithoutPerm,
      { "queryWithoutPerm", "ansi_tcap.queryWithoutPerm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_response,
      { "response", "ansi_tcap.response",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_conversationWithPerm,
      { "conversationWithPerm", "ansi_tcap.conversationWithPerm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_conversationWithoutPerm,
      { "conversationWithoutPerm", "ansi_tcap.conversationWithoutPerm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_abort,
      { "abort", "ansi_tcap.abort",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_identifier,
      { "identifier", "ansi_tcap.identifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransactionID", HFILL }},
    { &hf_ansi_tcap_dialoguePortion,
      { "dialoguePortion", "ansi_tcap.dialoguePortion",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_componentPortion,
      { "componentPortion", "ansi_tcap.componentPortion",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ComponentSequence", HFILL }},
    { &hf_ansi_tcap_dialogPortion,
      { "dialogPortion", "ansi_tcap.dialogPortion",
        FT_NONE, BASE_NONE, NULL, 0,
        "DialoguePortion", HFILL }},
    { &hf_ansi_tcap_causeInformation,
      { "causeInformation", "ansi_tcap.causeInformation",
        FT_UINT32, BASE_DEC, VALS(ansi_tcap_T_causeInformation_vals), 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_abortCause,
      { "abortCause", "ansi_tcap.abortCause",
        FT_INT32, BASE_DEC, VALS(ansi_tcap_P_Abort_cause_U_vals), 0,
        "P_Abort_cause", HFILL }},
    { &hf_ansi_tcap_userInformation,
      { "userInformation", "ansi_tcap.userInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "UserAbortInformation", HFILL }},
    { &hf_ansi_tcap_version,
      { "version", "ansi_tcap.version",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ProtocolVersion", HFILL }},
    { &hf_ansi_tcap_applicationContext,
      { "applicationContext", "ansi_tcap.applicationContext",
        FT_UINT32, BASE_DEC, VALS(ansi_tcap_T_applicationContext_vals), 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_integerApplicationId,
      { "integerApplicationId", "ansi_tcap.integerApplicationId",
        FT_INT32, BASE_DEC, NULL, 0,
        "IntegerApplicationContext", HFILL }},
    { &hf_ansi_tcap_objectApplicationId,
      { "objectApplicationId", "ansi_tcap.objectApplicationId",
        FT_OID, BASE_NONE, NULL, 0,
        "ObjectIDApplicationContext", HFILL }},
    { &hf_ansi_tcap_userInformation_01,
      { "userInformation", "ansi_tcap.userInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_securityContext,
      { "securityContext", "ansi_tcap.securityContext",
        FT_UINT32, BASE_DEC, VALS(ansi_tcap_T_securityContext_vals), 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_integerSecurityId,
      { "integerSecurityId", "ansi_tcap.integerSecurityId",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ansi_tcap_objectSecurityId,
      { "objectSecurityId", "ansi_tcap.objectSecurityId",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_ansi_tcap_confidentiality,
      { "confidentiality", "ansi_tcap.confidentiality",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap__untag_item,
      { "_untag item", "ansi_tcap._untag_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_ansi_tcap_confidentialityId,
      { "confidentialityId", "ansi_tcap.confidentialityId",
        FT_UINT32, BASE_DEC, VALS(ansi_tcap_T_confidentialityId_vals), 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_integerConfidentialityId,
      { "integerConfidentialityId", "ansi_tcap.integerConfidentialityId",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ansi_tcap_objectConfidentialityId,
      { "objectConfidentialityId", "ansi_tcap.objectConfidentialityId",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_ansi_tcap__untag_item_01,
      { "ComponentPDU", "ansi_tcap.ComponentPDU",
        FT_UINT32, BASE_DEC, VALS(ansi_tcap_ComponentPDU_vals), 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_invokeLast,
      { "invokeLast", "ansi_tcap.invokeLast",
        FT_NONE, BASE_NONE, NULL, 0,
        "Invoke", HFILL }},
    { &hf_ansi_tcap_returnResultLast,
      { "returnResultLast", "ansi_tcap.returnResultLast",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReturnResult", HFILL }},
    { &hf_ansi_tcap_returnError,
      { "returnError", "ansi_tcap.returnError",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_reject,
      { "reject", "ansi_tcap.reject",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_invokeNotLast,
      { "invokeNotLast", "ansi_tcap.invokeNotLast",
        FT_NONE, BASE_NONE, NULL, 0,
        "Invoke", HFILL }},
    { &hf_ansi_tcap_returnResultNotLast,
      { "returnResultNotLast", "ansi_tcap.returnResultNotLast",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReturnResult", HFILL }},
    { &hf_ansi_tcap_componentIDs,
      { "componentIDs", "ansi_tcap.componentIDs",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_operationCode,
      { "operationCode", "ansi_tcap.operationCode",
        FT_UINT32, BASE_DEC, VALS(ansi_tcap_OperationCode_vals), 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_parameter,
      { "parameter", "ansi_tcap.parameter",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_componentID,
      { "componentID", "ansi_tcap.componentID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_parameter_01,
      { "parameter", "ansi_tcap.parameter",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_parameter_01", HFILL }},
    { &hf_ansi_tcap_componentID_01,
      { "componentID", "ansi_tcap.componentID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_componentID_01", HFILL }},
    { &hf_ansi_tcap_errorCode,
      { "errorCode", "ansi_tcap.errorCode",
        FT_UINT32, BASE_DEC, VALS(ansi_tcap_ErrorCode_vals), 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_parameter_02,
      { "parameter", "ansi_tcap.parameter",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_parameter_02", HFILL }},
    { &hf_ansi_tcap_componentID_02,
      { "componentID", "ansi_tcap.componentID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_0_1", HFILL }},
    { &hf_ansi_tcap_rejectProblem,
      { "rejectProblem", "ansi_tcap.rejectProblem",
        FT_INT32, BASE_DEC, VALS(ansi_tcap_Problem_vals), 0,
        "Problem", HFILL }},
    { &hf_ansi_tcap_parameter_03,
      { "parameter", "ansi_tcap.parameter",
        FT_UINT32, BASE_DEC, VALS(ansi_tcap_T_parameter_03_vals), 0,
        "T_parameter_03", HFILL }},
    { &hf_ansi_tcap_paramSequence,
      { "paramSequence", "ansi_tcap.paramSequence",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_paramSet,
      { "paramSet", "ansi_tcap.paramSet",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/*--- End of included file: packet-ansi_tcap-hfarr.c ---*/
#line 487 "../../asn1/ansi_tcap/packet-ansi_tcap-template.c"
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_tcap,
        &ett_param,
        &ett_otid,
        &ett_dtid,
        &ett_ansi_tcap_stat,
		&ett_ansi_tcap_op_code_nat,

/*--- Included file: packet-ansi_tcap-ettarr.c ---*/
#line 1 "../../asn1/ansi_tcap/packet-ansi_tcap-ettarr.c"
    &ett_ansi_tcap_OperationCode,
    &ett_ansi_tcap_ErrorCode,
    &ett_ansi_tcap_PackageType,
    &ett_ansi_tcap_UniTransactionPDU,
    &ett_ansi_tcap_TransactionPDU,
    &ett_ansi_tcap_Abort,
    &ett_ansi_tcap_T_causeInformation,
    &ett_ansi_tcap_DialoguePortion_U,
    &ett_ansi_tcap_T_applicationContext,
    &ett_ansi_tcap_T_securityContext,
    &ett_ansi_tcap_UserInformation_U,
    &ett_ansi_tcap_Confidentiality,
    &ett_ansi_tcap_T_confidentialityId,
    &ett_ansi_tcap_SEQUENCE_OF_ComponentPDU,
    &ett_ansi_tcap_ComponentPDU,
    &ett_ansi_tcap_Invoke,
    &ett_ansi_tcap_ReturnResult,
    &ett_ansi_tcap_ReturnError,
    &ett_ansi_tcap_Reject,
    &ett_ansi_tcap_T_parameter_03,
    &ett_ansi_tcap_T_paramSequence,
    &ett_ansi_tcap_T_paramSet,

/*--- End of included file: packet-ansi_tcap-ettarr.c ---*/
#line 498 "../../asn1/ansi_tcap/packet-ansi_tcap-template.c"
    };

	static enum_val_t ansi_tcap_response_matching_type_values[] = {
		{"Only Transaction ID will be used in Invoke/response matching",					"Transaction ID only", 0},
		{"Transaction ID and Source will be used in Invoke/response matching",				"Transaction ID and Source", 1},
		{"Transaction ID Source and Destination will be used in Invoke/response matching",	"Transaction ID Source and Destination", 2},
		{NULL, NULL, -1}
	};


/* Register the protocol name and description */
    proto_ansi_tcap = proto_register_protocol(PNAME, PSNAME, PFNAME);
        register_dissector("ansi_tcap", dissect_ansi_tcap, proto_ansi_tcap);

   /* Note the high bit should be masked off when registering in this table (0x7fff)*/
   ansi_tcap_national_opcode_table = register_dissector_table("ansi_tcap.nat.opcode", "ANSI TCAP National Opcodes", FT_UINT16, BASE_DEC);
/* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_ansi_tcap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    ansi_tcap_module = prefs_register_protocol(proto_ansi_tcap, proto_reg_handoff_ansi_tcap);

    prefs_register_enum_preference(ansi_tcap_module, "transaction.matchtype",
                                   "Type of matching invoke/response",
                                   "Type of matching invoke/response, risk of missmatch if loose matching choosen",
                                   &ansi_tcap_response_matching_type, ansi_tcap_response_matching_type_values, FALSE);

    register_init_routine(&ansi_tcap_init_protocol);
}
