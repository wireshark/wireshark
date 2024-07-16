/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-ansi_tcap.c                                                         */
/* asn2wrs.py -b -q -L -p ansi_tcap -c ./ansi_tcap.cnf -s ./packet-ansi_tcap-template -D . -O ../.. TCAP-Remote-Operations-Information-Objects.asn TCAPPackage.asn */

/* packet-ansi_tcap-template.c
 * Routines for ANSI TCAP
 * Copyright 2007 Anders Broman <anders.broman@ericsson.com>
 * Built from the gsm-map dissector Copyright 2004 - 2005, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 * References: T1.114
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/strutil.h>

#include "packet-ber.h"
#include "packet-tcap.h"
#include "packet-ansi_tcap.h"

#define PNAME  "ANSI Transaction Capabilities Application Part"
#define PSNAME "ANSI_TCAP"
#define PFNAME "ansi_tcap"

void proto_register_ansi_tcap(void);
void proto_reg_handoff_ansi_tcap(void);

/* Preference settings */
#define ANSI_TCAP_TID_ONLY            0
#define ANSI_TCAP_TID_AND_SOURCE      1
#define ANSI_TCAP_TID_SOURCE_AND_DEST 2
static int ansi_tcap_response_matching_type = ANSI_TCAP_TID_ONLY;

/* Initialize the protocol and registered fields */
static int proto_ansi_tcap;

#if 0
static int hf_ansi_tcapsrt_SessionId;
static int hf_ansi_tcapsrt_Duplicate;
static int hf_ansi_tcapsrt_BeginSession;
static int hf_ansi_tcapsrt_EndSession;
static int hf_ansi_tcapsrt_SessionTime;
#endif
static int hf_ansi_tcap_bit_h;
static int hf_ansi_tcap_op_family;
static int hf_ansi_tcap_op_specifier;

static int hf_ansi_tcap_national;                 /* T_national */
static int hf_ansi_tcap_private;                  /* T_private */
static int hf_ansi_tcap_national_01;              /* INTEGER_M128_127 */
static int hf_ansi_tcap_ec_private;               /* ANSIMAPPrivateErrorcode */
static int hf_ansi_tcap_unidirectional;           /* T_unidirectional */
static int hf_ansi_tcap_queryWithPerm;            /* T_queryWithPerm */
static int hf_ansi_tcap_queryWithoutPerm;         /* T_queryWithoutPerm */
static int hf_ansi_tcap_response;                 /* T_response */
static int hf_ansi_tcap_conversationWithPerm;     /* T_conversationWithPerm */
static int hf_ansi_tcap_conversationWithoutPerm;  /* T_conversationWithoutPerm */
static int hf_ansi_tcap_abort;                    /* T_abort */
static int hf_ansi_tcap_identifier;               /* TransactionID */
static int hf_ansi_tcap_dialoguePortion;          /* DialoguePortion */
static int hf_ansi_tcap_componentPortion;         /* ComponentSequence */
static int hf_ansi_tcap_dialogPortion;            /* DialoguePortion */
static int hf_ansi_tcap_causeInformation;         /* T_causeInformation */
static int hf_ansi_tcap_abortCause;               /* P_Abort_cause */
static int hf_ansi_tcap_abort_userInformation;    /* UserAbortInformation */
static int hf_ansi_tcap_version;                  /* ProtocolVersion */
static int hf_ansi_tcap_applicationContext;       /* T_applicationContext */
static int hf_ansi_tcap_integerApplicationId;     /* IntegerApplicationContext */
static int hf_ansi_tcap_objectApplicationId;      /* ObjectIDApplicationContext */
static int hf_ansi_tcap_userInformation;          /* UserInformation */
static int hf_ansi_tcap_securityContext;          /* T_securityContext */
static int hf_ansi_tcap_integerSecurityId;        /* INTEGER */
static int hf_ansi_tcap_objectSecurityId;         /* OBJECT_IDENTIFIER */
static int hf_ansi_tcap_confidentiality;          /* Confidentiality */
static int hf_ansi_tcap__untag_item;              /* EXTERNAL */
static int hf_ansi_tcap_confidentialityId;        /* T_confidentialityId */
static int hf_ansi_tcap_integerConfidentialityId;  /* INTEGER */
static int hf_ansi_tcap_objectConfidentialityId;  /* OBJECT_IDENTIFIER */
static int hf_ansi_tcap__untag_item_01;           /* ComponentPDU */
static int hf_ansi_tcap_invokeLast;               /* Invoke */
static int hf_ansi_tcap_returnResultLast;         /* ReturnResult */
static int hf_ansi_tcap_returnError;              /* ReturnError */
static int hf_ansi_tcap_reject;                   /* Reject */
static int hf_ansi_tcap_invokeNotLast;            /* Invoke */
static int hf_ansi_tcap_returnResultNotLast;      /* ReturnResult */
static int hf_ansi_tcap_componentIDs;             /* T_componentIDs */
static int hf_ansi_tcap_operationCode;            /* OperationCode */
static int hf_ansi_tcap_invoke_parameter;         /* T_invoke_parameter */
static int hf_ansi_tcap_componentID;              /* T_componentID */
static int hf_ansi_tcap_returnResult_parameter;   /* T_returnResult_parameter */
static int hf_ansi_tcap_componentID_01;           /* T_componentID_01 */
static int hf_ansi_tcap_errorCode;                /* ErrorCode */
static int hf_ansi_tcap_returnError_parameter;    /* T_returnError_parameter */
static int hf_ansi_tcap_componentID_02;           /* OCTET_STRING_SIZE_0_1 */
static int hf_ansi_tcap_rejectProblem;            /* Problem */
static int hf_ansi_tcap_reject_parameter;         /* T_reject_parameter */
static int hf_ansi_tcap_paramSequence;            /* T_paramSequence */
static int hf_ansi_tcap_paramSet;                 /* T_paramSet */

/* Initialize the subtree pointers */
static int ett_tcap;
static int ett_param;
static int ett_ansi_tcap_op_code_nat;

static int ett_otid;
static int ett_dtid;
static int ett_ansi_tcap_stat;

static expert_field ei_ansi_tcap_dissector_not_implemented;

static struct tcapsrt_info_t * gp_tcapsrt_info;
static bool tcap_subdissector_used=false;

static struct tcaphash_context_t * gp_tcap_context;

/* Note the high bit should be masked off when registering in this table (0x7fff)*/
static dissector_table_t  ansi_tcap_national_opcode_table; /* National Operation Codes */

static int ett_ansi_tcap_OperationCode;
static int ett_ansi_tcap_ErrorCode;
static int ett_ansi_tcap_PackageType;
static int ett_ansi_tcap_UniTransactionPDU;
static int ett_ansi_tcap_TransactionPDU;
static int ett_ansi_tcap_Abort;
static int ett_ansi_tcap_T_causeInformation;
static int ett_ansi_tcap_DialoguePortion_U;
static int ett_ansi_tcap_T_applicationContext;
static int ett_ansi_tcap_T_securityContext;
static int ett_ansi_tcap_UserInformation_U;
static int ett_ansi_tcap_Confidentiality;
static int ett_ansi_tcap_T_confidentialityId;
static int ett_ansi_tcap_SEQUENCE_OF_ComponentPDU;
static int ett_ansi_tcap_ComponentPDU;
static int ett_ansi_tcap_Invoke;
static int ett_ansi_tcap_ReturnResult;
static int ett_ansi_tcap_ReturnError;
static int ett_ansi_tcap_Reject;
static int ett_ansi_tcap_T_reject_parameter;
static int ett_ansi_tcap_T_paramSequence;
static int ett_ansi_tcap_T_paramSet;

#define MAX_SSN 254

/* When several Tcap components are received in a single TCAP message,
   we have to use several buffers for the stored parameters
   because else this data are erased during TAP dissector call */
#define MAX_TCAP_INSTANCE 10
int tcapsrt_global_current=0;
struct tcapsrt_info_t tcapsrt_global_info[MAX_TCAP_INSTANCE];

static dissector_table_t ber_oid_dissector_table;
static const char * cur_oid;
static const char * tcapext_oid;

static dissector_handle_t ansi_map_handle;
static dissector_handle_t ain_handle;

struct ansi_tcap_private_t ansi_tcap_private;
#define MAX_TID_STR_LEN 1024

static void ansi_tcap_ctx_init(struct ansi_tcap_private_t *a_tcap_ctx) {
  memset(a_tcap_ctx, '\0', sizeof(*a_tcap_ctx));
  a_tcap_ctx->signature = ANSI_TCAP_CTX_SIGNATURE;
  a_tcap_ctx->oid_is_present = false;
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

/* Transaction tracking */
/* Transaction table */
struct ansi_tcap_invokedata_t {
    int OperationCode;
      /*
         0 : national,
         1 : private
      */
    int32_t OperationCode_private;
    int32_t OperationCode_national;
};

static wmem_multimap_t *TransactionId_table;

/* Store Invoke information needed for the corresponding reply */
static void
save_invoke_data(packet_info *pinfo, proto_tree *tree _U_, tvbuff_t *tvb _U_){
  struct ansi_tcap_invokedata_t *ansi_tcap_saved_invokedata;
  char *src, *dst;
  char *buf;

  src = address_to_str(pinfo->pool, &(pinfo->src));
  dst = address_to_str(pinfo->pool, &(pinfo->dst));

  if ((!pinfo->fd->visited)&&(ansi_tcap_private.TransactionID_str)){

          /* Only do this once XXX I hope it's the right thing to do */
          /* The hash string needs to contain src and dest to distinguish different flows */
          switch(ansi_tcap_response_matching_type){
                        case ANSI_TCAP_TID_ONLY:
                                buf = wmem_strdup(pinfo->pool, ansi_tcap_private.TransactionID_str);
                                break;
                        case ANSI_TCAP_TID_AND_SOURCE:
                                buf = wmem_strdup_printf(pinfo->pool, "%s%s",ansi_tcap_private.TransactionID_str,src);
                                break;
                        case ANSI_TCAP_TID_SOURCE_AND_DEST:
                        default:
                                buf = wmem_strdup_printf(pinfo->pool, "%s%s%s",ansi_tcap_private.TransactionID_str,src,dst);
                                break;
                }

          ansi_tcap_saved_invokedata = wmem_new(wmem_file_scope(), struct ansi_tcap_invokedata_t);
          ansi_tcap_saved_invokedata->OperationCode = ansi_tcap_private.d.OperationCode;
          ansi_tcap_saved_invokedata->OperationCode_national = ansi_tcap_private.d.OperationCode_national;
          ansi_tcap_saved_invokedata->OperationCode_private = ansi_tcap_private.d.OperationCode_private;

          wmem_multimap_insert32(TransactionId_table,
                        wmem_strdup(wmem_file_scope(), buf),
                        pinfo->num,
                        ansi_tcap_saved_invokedata);
          /*
          ws_warning("Tcap Invoke Hash string %s",buf);
          */
  }
}

static bool
find_saved_invokedata(packet_info *pinfo, proto_tree *tree _U_, tvbuff_t *tvb _U_){
  struct ansi_tcap_invokedata_t *ansi_tcap_saved_invokedata;
  char *src, *dst;
  char *buf;

  if (!ansi_tcap_private.TransactionID_str) {
    return false;
  }

  src = address_to_str(pinfo->pool, &(pinfo->src));
  dst = address_to_str(pinfo->pool, &(pinfo->dst));

  /* The hash string needs to contain src and dest to distinguish different flows */
  buf = (char *)wmem_alloc(pinfo->pool, MAX_TID_STR_LEN);
  buf[0] = '\0';
  /* Reverse order to invoke */
  switch(ansi_tcap_response_matching_type){
        case ANSI_TCAP_TID_ONLY:
                snprintf(buf,MAX_TID_STR_LEN,"%s",ansi_tcap_private.TransactionID_str);
                break;
        case ANSI_TCAP_TID_AND_SOURCE:
                snprintf(buf,MAX_TID_STR_LEN,"%s%s",ansi_tcap_private.TransactionID_str,dst);
                break;
        case ANSI_TCAP_TID_SOURCE_AND_DEST:
        default:
                snprintf(buf,MAX_TID_STR_LEN,"%s%s%s",ansi_tcap_private.TransactionID_str,dst,src);
                break;
  }

  ansi_tcap_saved_invokedata = (struct ansi_tcap_invokedata_t *)wmem_multimap_lookup32_le(TransactionId_table, buf, pinfo->num);
  if(ansi_tcap_saved_invokedata){
          ansi_tcap_private.d.OperationCode                      = ansi_tcap_saved_invokedata->OperationCode;
          ansi_tcap_private.d.OperationCode_national = ansi_tcap_saved_invokedata->OperationCode_national;
          ansi_tcap_private.d.OperationCode_private  = ansi_tcap_saved_invokedata->OperationCode_private;
          return true;
  }
  return false;
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
static bool
find_tcap_subdissector(tvbuff_t *tvb, asn1_ctx_t *actx, proto_tree *tree){
        proto_item *item;

        /* If "DialoguePortion objectApplicationId ObjectIDApplicationContext
         * points to the subdissector this code can be used.
         *
        if(ansi_tcap_private.d.oid_is_present){
                call_ber_oid_callback(ansi_tcap_private.objectApplicationId_oid, tvb, 0, actx-pinfo, tree, NULL);
                return true;
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
                        proto_item_set_generated(item);
                        ansi_tcap_private.d.OperationCode_item = item;
                }
        }
        if(ansi_tcap_private.d.OperationCode == 0){
                /* national */
                uint8_t family = (ansi_tcap_private.d.OperationCode_national & 0x7f00)>>8;
                uint8_t specifier = (uint8_t)(ansi_tcap_private.d.OperationCode_national & 0xff);
                if(!dissector_try_uint(ansi_tcap_national_opcode_table, ansi_tcap_private.d.OperationCode_national, tvb, actx->pinfo, actx->subtree.top_tree)){
                        proto_tree_add_expert_format(tree, actx->pinfo, &ei_ansi_tcap_dissector_not_implemented, tvb, 0, -1,
                                        "Dissector for ANSI TCAP NATIONAL code:0x%x(Family %u, Specifier %u) \n"
                                        "not implemented. Contact Wireshark developers if you want this supported(Spec required)",
                                        ansi_tcap_private.d.OperationCode_national, family, specifier);
                        return false;
                }
                return true;
        }else if(ansi_tcap_private.d.OperationCode == 1){
                /* private */
                if((ansi_tcap_private.d.OperationCode_private & 0xff00) == 0x0900){
                    /* This is abit of a hack as it assumes the private codes with a "family" of 0x09 is ANSI MAP
                    * See TODO above.
                    * N.S0005-0 v 1.0 TCAP Formats and Procedures 5-16 Application Services
                    * 6.3.2 Component Portion
                    * The Operation Code is partitioned into an Operation Family followed by a
                    * Specifier associated with each Operation Family member. For TIA/EIA-41 the
                    * Operation Family is coded as decimal 9. Bit H of the Operation Family is always
                    * coded as 0.
                    */
                    call_dissector_with_data(ansi_map_handle, tvb, actx->pinfo, actx->subtree.top_tree, &ansi_tcap_private);

                    return true;
                } else if ((ansi_tcap_private.d.OperationCode_private & 0xf000) == 0x6000) {
                    call_dissector_with_data(ain_handle, tvb, actx->pinfo, actx->subtree.top_tree, &ansi_tcap_private);
                    return true;
                }
        }
        proto_tree_add_expert_format(tree, actx->pinfo, &ei_ansi_tcap_dissector_not_implemented, tvb, 0, -1,
            "Dissector for ANSI TCAP PRIVATE code:%u not implemented.\n"
            "Contact Wireshark developers if you want this supported(Spec required)",
            ansi_tcap_private.d.OperationCode_private);
        return false;
}



static int
dissect_ansi_tcap_T_national(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
 proto_tree *subtree;
 proto_item *spcifier_item;
 int start_offset = offset;
 uint8_t family;
 uint8_t specifier;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &ansi_tcap_private.d.OperationCode_national);

  /* mask off the H bit */
  ansi_tcap_private.d.OperationCode_national = (ansi_tcap_private.d.OperationCode_national&0x7fff);

  subtree = proto_item_add_subtree(actx->created_item, ett_ansi_tcap_op_code_nat);
  /* Bit H is used to distinguish between Operations that require a reply and those that do not. A value of 1
   * indicates that a reply is required; a value of 0 indicates that a reply is not required.
   */
  family = (ansi_tcap_private.d.OperationCode_national & 0x7f00)>>8;
  specifier = (uint8_t)(ansi_tcap_private.d.OperationCode_national & 0xff);
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
dissect_ansi_tcap_T_private(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ansi_tcap_OperationCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 OperationCode_choice, hf_index, ett_ansi_tcap_OperationCode,
                                 &ansi_tcap_private.d.OperationCode);

  ansi_tcap_private.d.OperationCode_item = actx->created_item;
  return offset;
}



static int
dissect_ansi_tcap_INTEGER_M128_127(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string ansi_tcap_ANSIMAPPrivateErrorcode_vals[] = {
  { 129, "unrecognized-MIN" },
  { 130, "unrecognized-ESN" },
  { 131, "mINorHLR-Mismatch" },
  { 132, "operation-Sequence-Problem" },
  { 133, "resource-Shortage" },
  { 134, "operation-Not-Supported" },
  { 135, "trunk-Unavailable" },
  { 136, "parameter-Error" },
  { 137, "system-Failure" },
  { 138, "unrecognized-Parameter-Value" },
  { 139, "feature-Inactive" },
  { 140, "missing-Parameter" },
  { 0, NULL }
};


static int
dissect_ansi_tcap_ANSIMAPPrivateErrorcode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
  {  20, &hf_ansi_tcap_ec_private, BER_CLASS_PRI, 20, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_ANSIMAPPrivateErrorcode },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_ErrorCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ErrorCode_choice, hf_index, ett_ansi_tcap_ErrorCode,
                                 NULL);

  return offset;
}



static int
dissect_ansi_tcap_TransactionID_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

tvbuff_t *next_tvb;
uint8_t len;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &next_tvb);


if(next_tvb) {
	len = tvb_reported_length_remaining(next_tvb, 0);
	if(len !=0){
		/* 0 octets for the Unidirectional,
		 * 4 octets for Query, Response & Abort
		 * 8 octets for Conversation in the order Originating then Responding TID
		 *
		 * In order to match this it seems like we should only use the last 4 octets
		 * in the 8 octets case.
		 */
		if (len > 4){
			ansi_tcap_private.TransactionID_str = tvb_bytes_to_str(actx->pinfo->pool, next_tvb, 4,len-4);
		}else{
			ansi_tcap_private.TransactionID_str = tvb_bytes_to_str(actx->pinfo->pool, next_tvb, 0,len);
		}
	}
	switch(len) {
	case 1:
		gp_tcapsrt_info->src_tid=tvb_get_uint8(next_tvb, 0);
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
dissect_ansi_tcap_TransactionID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 7, true, dissect_ansi_tcap_TransactionID_U);

  return offset;
}



static int
dissect_ansi_tcap_OCTET_STRING_SIZE_1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ansi_tcap_ProtocolVersion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 26, true, dissect_ansi_tcap_OCTET_STRING_SIZE_1);

  return offset;
}



static int
dissect_ansi_tcap_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ansi_tcap_IntegerApplicationContext(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 27, true, dissect_ansi_tcap_INTEGER);

  return offset;
}



static int
dissect_ansi_tcap_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_ansi_tcap_ObjectIDApplicationContext(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

 static const char * oid_str;

   offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 28, true, dissect_ansi_tcap_OBJECT_IDENTIFIER);

 	ansi_tcap_private.objectApplicationId_oid= (const void*) oid_str;
	ansi_tcap_private.oid_is_present=true;


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
dissect_ansi_tcap_T_applicationContext(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_applicationContext_choice, hf_index, ett_ansi_tcap_T_applicationContext,
                                 NULL);

  return offset;
}



static int
dissect_ansi_tcap_EXTERNAL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_external_type(implicit_tag, tree, tvb, offset, actx, hf_index, NULL);

  return offset;
}


static const ber_sequence_t UserInformation_U_sequence_of[1] = {
  { &hf_ansi_tcap__untag_item, BER_CLASS_UNI, BER_UNI_TAG_EXTERNAL, BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_EXTERNAL },
};

static int
dissect_ansi_tcap_UserInformation_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      UserInformation_U_sequence_of, hf_index, ett_ansi_tcap_UserInformation_U);

  return offset;
}



static int
dissect_ansi_tcap_UserInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 29, true, dissect_ansi_tcap_UserInformation_U);

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
dissect_ansi_tcap_T_securityContext(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ansi_tcap_T_confidentialityId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ansi_tcap_Confidentiality(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Confidentiality_sequence, hf_index, ett_ansi_tcap_Confidentiality);

  return offset;
}


static const ber_sequence_t DialoguePortion_U_sequence[] = {
  { &hf_ansi_tcap_version   , BER_CLASS_PRI, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_ProtocolVersion },
  { &hf_ansi_tcap_applicationContext, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ansi_tcap_T_applicationContext },
  { &hf_ansi_tcap_userInformation, BER_CLASS_PRI, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_UserInformation },
  { &hf_ansi_tcap_securityContext, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ansi_tcap_T_securityContext },
  { &hf_ansi_tcap_confidentiality, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ansi_tcap_Confidentiality },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_DialoguePortion_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DialoguePortion_U_sequence, hf_index, ett_ansi_tcap_DialoguePortion_U);

  return offset;
}



static int
dissect_ansi_tcap_DialoguePortion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 25, true, dissect_ansi_tcap_DialoguePortion_U);

  return offset;
}



static int
dissect_ansi_tcap_T_componentIDs(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ansi_tcap_T_invoke_parameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  if(find_tcap_subdissector(tvb, actx, tree))
    offset = tvb_reported_length(tvb);



  return offset;
}


static const ber_sequence_t Invoke_sequence[] = {
  { &hf_ansi_tcap_componentIDs, BER_CLASS_PRI, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_componentIDs },
  { &hf_ansi_tcap_operationCode, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ansi_tcap_OperationCode },
  { &hf_ansi_tcap_invoke_parameter, BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_T_invoke_parameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_Invoke(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  ansi_tcap_private.d.pdu = 1;


  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Invoke_sequence, hf_index, ett_ansi_tcap_Invoke);

  return offset;
}



static int
dissect_ansi_tcap_T_componentID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ansi_tcap_T_returnResult_parameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  if(find_tcap_subdissector(tvb, actx, tree))
    offset = tvb_reported_length(tvb);


  return offset;
}


static const ber_sequence_t ReturnResult_sequence[] = {
  { &hf_ansi_tcap_componentID, BER_CLASS_PRI, 15, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_componentID },
  { &hf_ansi_tcap_returnResult_parameter, BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_T_returnResult_parameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_ReturnResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  ansi_tcap_private.d.pdu = 2;



  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReturnResult_sequence, hf_index, ett_ansi_tcap_ReturnResult);

  return offset;
}



static int
dissect_ansi_tcap_T_componentID_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ansi_tcap_T_returnError_parameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  if(find_tcap_subdissector(tvb, actx, tree))
    offset = tvb_reported_length(tvb);


  return offset;
}


static const ber_sequence_t ReturnError_sequence[] = {
  { &hf_ansi_tcap_componentID_01, BER_CLASS_PRI, 15, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_componentID_01 },
  { &hf_ansi_tcap_errorCode , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ansi_tcap_ErrorCode },
  { &hf_ansi_tcap_returnError_parameter, BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_T_returnError_parameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_ReturnError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  ansi_tcap_private.d.pdu = 3;

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReturnError_sequence, hf_index, ett_ansi_tcap_ReturnError);

  return offset;
}



static int
dissect_ansi_tcap_OCTET_STRING_SIZE_0_1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ansi_tcap_Problem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t T_paramSequence_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_T_paramSequence(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_paramSequence_sequence, hf_index, ett_ansi_tcap_T_paramSequence);

  return offset;
}


static const ber_sequence_t T_paramSet_set[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_T_paramSet(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              T_paramSet_set, hf_index, ett_ansi_tcap_T_paramSet);

  return offset;
}


static const value_string ansi_tcap_T_reject_parameter_vals[] = {
  {  16, "paramSequence" },
  {  18, "paramSet" },
  { 0, NULL }
};

static const ber_choice_t T_reject_parameter_choice[] = {
  {  16, &hf_ansi_tcap_paramSequence, BER_CLASS_PRI, 16, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_paramSequence },
  {  18, &hf_ansi_tcap_paramSet  , BER_CLASS_PRI, 18, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_paramSet },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_T_reject_parameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_reject_parameter_choice, hf_index, ett_ansi_tcap_T_reject_parameter,
                                 NULL);

  return offset;
}


static const ber_sequence_t Reject_sequence[] = {
  { &hf_ansi_tcap_componentID_02, BER_CLASS_PRI, 15, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_OCTET_STRING_SIZE_0_1 },
  { &hf_ansi_tcap_rejectProblem, BER_CLASS_PRI, 21, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_Problem },
  { &hf_ansi_tcap_reject_parameter, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ansi_tcap_T_reject_parameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_Reject(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ansi_tcap_ComponentPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ComponentPDU_choice, hf_index, ett_ansi_tcap_ComponentPDU,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ComponentPDU_sequence_of[1] = {
  { &hf_ansi_tcap__untag_item_01, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ansi_tcap_ComponentPDU },
};

static int
dissect_ansi_tcap_SEQUENCE_OF_ComponentPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ComponentPDU_sequence_of, hf_index, ett_ansi_tcap_SEQUENCE_OF_ComponentPDU);

  return offset;
}



static int
dissect_ansi_tcap_ComponentSequence(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 8, true, dissect_ansi_tcap_SEQUENCE_OF_ComponentPDU);

  return offset;
}


static const ber_sequence_t UniTransactionPDU_sequence[] = {
  { &hf_ansi_tcap_identifier, BER_CLASS_PRI, 7, BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_TransactionID },
  { &hf_ansi_tcap_dialoguePortion, BER_CLASS_PRI, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_DialoguePortion },
  { &hf_ansi_tcap_componentPortion, BER_CLASS_PRI, 8, BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_ComponentSequence },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_UniTransactionPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UniTransactionPDU_sequence, hf_index, ett_ansi_tcap_UniTransactionPDU);

  return offset;
}



static int
dissect_ansi_tcap_T_unidirectional(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ansi_tcap_TransactionPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TransactionPDU_sequence, hf_index, ett_ansi_tcap_TransactionPDU);

  return offset;
}



static int
dissect_ansi_tcap_T_queryWithPerm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
gp_tcapsrt_info->ope=TC_ANSI_ALL;
col_set_str(actx->pinfo->cinfo, COL_INFO, "queryWithPerm ");

  offset = dissect_ansi_tcap_TransactionPDU(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ansi_tcap_T_queryWithoutPerm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
gp_tcapsrt_info->ope=TC_ANSI_ALL;
col_set_str(actx->pinfo->cinfo, COL_INFO, "queryWithoutPerm ");

  offset = dissect_ansi_tcap_TransactionPDU(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ansi_tcap_T_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
gp_tcapsrt_info->ope=TC_ANSI_ALL;
col_set_str(actx->pinfo->cinfo, COL_INFO, "response ");

  offset = dissect_ansi_tcap_TransactionPDU(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ansi_tcap_T_conversationWithPerm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
gp_tcapsrt_info->ope=TC_ANSI_ALL;
col_set_str(actx->pinfo->cinfo, COL_INFO, "conversationWithPerm ");

  offset = dissect_ansi_tcap_TransactionPDU(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ansi_tcap_T_conversationWithoutPerm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ansi_tcap_P_Abort_cause_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ansi_tcap_P_Abort_cause(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 23, true, dissect_ansi_tcap_P_Abort_cause_U);

  return offset;
}



static int
dissect_ansi_tcap_UserAbortInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 24, false, dissect_ansi_tcap_EXTERNAL);

  return offset;
}


static const value_string ansi_tcap_T_causeInformation_vals[] = {
  {  23, "abortCause" },
  {  24, "userInformation" },
  { 0, NULL }
};

static const ber_choice_t T_causeInformation_choice[] = {
  {  23, &hf_ansi_tcap_abortCause, BER_CLASS_PRI, 23, BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_P_Abort_cause },
  {  24, &hf_ansi_tcap_abort_userInformation, BER_CLASS_PRI, 24, BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_UserAbortInformation },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_T_causeInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_ansi_tcap_Abort(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Abort_sequence, hf_index, ett_ansi_tcap_Abort);

  return offset;
}



static int
dissect_ansi_tcap_T_abort(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
gp_tcapsrt_info->ope=TC_ANSI_ABORT;
col_set_str(actx->pinfo->cinfo, COL_INFO, "Abort ");

  offset = dissect_ansi_tcap_Abort(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


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
dissect_ansi_tcap_PackageType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PackageType_choice, hf_index, ett_ansi_tcap_PackageType,
                                 NULL);

  return offset;
}





static int
dissect_ansi_tcap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
    proto_item          *item=NULL;
    proto_tree          *tree=NULL;
#if 0
    proto_item          *stat_item=NULL;
    proto_tree          *stat_tree=NULL;
        int                     offset = 0;
    struct tcaphash_context_t * p_tcap_context;
    dissector_handle_t subdissector_handle;
#endif
        asn1_ctx_t asn1_ctx;

        asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
        ansi_tcap_ctx_init(&ansi_tcap_private);

    asn1_ctx.subtree.top_tree = parent_tree;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ANSI TCAP");

    /* create display subtree for the protocol */
    if(parent_tree){
      item = proto_tree_add_item(parent_tree, proto_ansi_tcap, tvb, 0, -1, ENC_NA);
      tree = proto_item_add_subtree(item, ett_tcap);
    }
    cur_oid = NULL;
    tcapext_oid = NULL;

    gp_tcapsrt_info=tcapsrt_razinfo();
    tcap_subdissector_used=false;
    gp_tcap_context=NULL;
    dissect_ansi_tcap_PackageType(false, tvb, 0, &asn1_ctx, tree, -1);

#if 0 /* Skip this part for now it will be rewritten */
    if (g_ansi_tcap_HandleSRT && !tcap_subdissector_used ) {
                if (gtcap_DisplaySRT && tree) {
                        stat_tree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_ansi_tcap_stat, &stat_item, "Stat");
                        proto_item_set_generated(stat_item);
                }
                p_tcap_context=tcapsrt_call_matching(tvb, pinfo, stat_tree, gp_tcapsrt_info);
                ansi_tcap_private.context=p_tcap_context;

                /* If the current message is TCAP only,
                 * save the Application contexte name for the next messages
                 */
                if ( p_tcap_context && cur_oid && !p_tcap_context->oid_present ) {
                        /* Save the application context and the sub dissector */
                        (void) g_strlcpy(p_tcap_context->oid, cur_oid, sizeof(p_tcap_context->oid));
                        if ( (subdissector_handle = dissector_get_string_handle(ber_oid_dissector_table, cur_oid)) ) {
                                p_tcap_context->subdissector_handle=subdissector_handle;
                                p_tcap_context->oid_present=true;
                        }
                }
                if (g_ansi_tcap_HandleSRT && p_tcap_context && p_tcap_context->callback) {
                        /* Callback function for the upper layer */
                        (p_tcap_context->callback)(tvb, pinfo, stat_tree, p_tcap_context);
                }
        }
#endif
    return tvb_captured_length(tvb);
}


void
proto_reg_handoff_ansi_tcap(void)
{
    ansi_map_handle = find_dissector_add_dependency("ansi_map", proto_ansi_tcap);
    ain_handle = find_dissector_add_dependency("ain", proto_ansi_tcap);
    ber_oid_dissector_table = find_dissector_table("ber.oid");
}



void
proto_register_ansi_tcap(void)
{
    module_t    *ansi_tcap_module;


/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
#if 0
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
#endif
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
    { &hf_ansi_tcap_ec_private,
      { "private", "ansi_tcap.ec_private",
        FT_UINT32, BASE_DEC, VALS(ansi_tcap_ANSIMAPPrivateErrorcode_vals), 0,
        "ANSIMAPPrivateErrorcode", HFILL }},
    { &hf_ansi_tcap_unidirectional,
      { "unidirectional", "ansi_tcap.unidirectional_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_queryWithPerm,
      { "queryWithPerm", "ansi_tcap.queryWithPerm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_queryWithoutPerm,
      { "queryWithoutPerm", "ansi_tcap.queryWithoutPerm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_response,
      { "response", "ansi_tcap.response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_conversationWithPerm,
      { "conversationWithPerm", "ansi_tcap.conversationWithPerm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_conversationWithoutPerm,
      { "conversationWithoutPerm", "ansi_tcap.conversationWithoutPerm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_abort,
      { "abort", "ansi_tcap.abort_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_identifier,
      { "identifier", "ansi_tcap.identifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransactionID", HFILL }},
    { &hf_ansi_tcap_dialoguePortion,
      { "dialoguePortion", "ansi_tcap.dialoguePortion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_componentPortion,
      { "componentPortion", "ansi_tcap.componentPortion",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ComponentSequence", HFILL }},
    { &hf_ansi_tcap_dialogPortion,
      { "dialogPortion", "ansi_tcap.dialogPortion_element",
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
    { &hf_ansi_tcap_abort_userInformation,
      { "userInformation", "ansi_tcap.userInformation_element",
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
    { &hf_ansi_tcap_userInformation,
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
      { "confidentiality", "ansi_tcap.confidentiality_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap__untag_item,
      { "_untag item", "ansi_tcap._untag_item_element",
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
      { "invokeLast", "ansi_tcap.invokeLast_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Invoke", HFILL }},
    { &hf_ansi_tcap_returnResultLast,
      { "returnResultLast", "ansi_tcap.returnResultLast_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReturnResult", HFILL }},
    { &hf_ansi_tcap_returnError,
      { "returnError", "ansi_tcap.returnError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_reject,
      { "reject", "ansi_tcap.reject_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_invokeNotLast,
      { "invokeNotLast", "ansi_tcap.invokeNotLast_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Invoke", HFILL }},
    { &hf_ansi_tcap_returnResultNotLast,
      { "returnResultNotLast", "ansi_tcap.returnResultNotLast_element",
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
    { &hf_ansi_tcap_invoke_parameter,
      { "parameter", "ansi_tcap.parameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_invoke_parameter", HFILL }},
    { &hf_ansi_tcap_componentID,
      { "componentID", "ansi_tcap.componentID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_returnResult_parameter,
      { "parameter", "ansi_tcap.parameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_returnResult_parameter", HFILL }},
    { &hf_ansi_tcap_componentID_01,
      { "componentID", "ansi_tcap.componentID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_componentID_01", HFILL }},
    { &hf_ansi_tcap_errorCode,
      { "errorCode", "ansi_tcap.errorCode",
        FT_UINT32, BASE_DEC, VALS(ansi_tcap_ErrorCode_vals), 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_returnError_parameter,
      { "parameter", "ansi_tcap.parameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_returnError_parameter", HFILL }},
    { &hf_ansi_tcap_componentID_02,
      { "componentID", "ansi_tcap.componentID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_0_1", HFILL }},
    { &hf_ansi_tcap_rejectProblem,
      { "rejectProblem", "ansi_tcap.rejectProblem",
        FT_INT32, BASE_DEC, VALS(ansi_tcap_Problem_vals), 0,
        "Problem", HFILL }},
    { &hf_ansi_tcap_reject_parameter,
      { "parameter", "ansi_tcap.parameter",
        FT_UINT32, BASE_DEC, VALS(ansi_tcap_T_reject_parameter_vals), 0,
        "T_reject_parameter", HFILL }},
    { &hf_ansi_tcap_paramSequence,
      { "paramSequence", "ansi_tcap.paramSequence_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_paramSet,
      { "paramSet", "ansi_tcap.paramSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    };

/* Setup protocol subtree array */
    static int *ett[] = {
        &ett_tcap,
        &ett_param,
        &ett_otid,
        &ett_dtid,
        &ett_ansi_tcap_stat,
        &ett_ansi_tcap_op_code_nat,
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
    &ett_ansi_tcap_T_reject_parameter,
    &ett_ansi_tcap_T_paramSequence,
    &ett_ansi_tcap_T_paramSet,
    };

    static ei_register_info ei[] = {
        { &ei_ansi_tcap_dissector_not_implemented, { "ansi_tcap.dissector_not_implemented", PI_UNDECODED, PI_WARN, "Dissector not implemented", EXPFILL }},
    };

    expert_module_t* expert_ansi_tcap;

    static const enum_val_t ansi_tcap_response_matching_type_values[] = {
        {"Only Transaction ID will be used in Invoke/response matching",                        "Transaction ID only", ANSI_TCAP_TID_ONLY},
        {"Transaction ID and Source will be used in Invoke/response matching",                  "Transaction ID and Source", ANSI_TCAP_TID_AND_SOURCE},
        {"Transaction ID Source and Destination will be used in Invoke/response matching",      "Transaction ID Source and Destination", ANSI_TCAP_TID_SOURCE_AND_DEST},
        {NULL, NULL, -1}
    };

/* Register the protocol name and description */
    proto_ansi_tcap = proto_register_protocol(PNAME, PSNAME, PFNAME);
    register_dissector("ansi_tcap", dissect_ansi_tcap, proto_ansi_tcap);

   /* Note the high bit should be masked off when registering in this table (0x7fff)*/
   ansi_tcap_national_opcode_table = register_dissector_table("ansi_tcap.nat.opcode", "ANSI TCAP National Opcodes", proto_ansi_tcap, FT_UINT16, BASE_DEC);
/* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_ansi_tcap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ansi_tcap = expert_register_protocol(proto_ansi_tcap);
    expert_register_field_array(expert_ansi_tcap, ei, array_length(ei));

    ansi_tcap_module = prefs_register_protocol(proto_ansi_tcap, proto_reg_handoff_ansi_tcap);

    prefs_register_enum_preference(ansi_tcap_module, "transaction.matchtype",
                                   "Type of matching invoke/response",
                                   "Type of matching invoke/response, risk of mismatch if loose matching chosen",
                                   &ansi_tcap_response_matching_type, ansi_tcap_response_matching_type_values, false);

    TransactionId_table = wmem_multimap_new_autoreset(wmem_epan_scope(), wmem_file_scope(), wmem_str_hash, g_str_equal);
}
