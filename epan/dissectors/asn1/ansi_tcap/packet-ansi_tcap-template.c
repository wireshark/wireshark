/* packet-ansi_tcap-template.c
 * Routines for ANSI TCAP
 * Copyright 2007 Anders Broman <anders.broman@ericsson.com>
 * Built from the gsm-map dissector Copyright 2004 - 2005, Anders Broman <anders.broman@ericsson.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
static gint ansi_tcap_response_matching_type = ANSI_TCAP_TID_ONLY;

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

#include "packet-ansi_tcap-hf.c"

/* Initialize the subtree pointers */
static gint ett_tcap = -1;
static gint ett_param = -1;
static gint ett_ansi_tcap_op_code_nat = -1;

static gint ett_otid = -1;
static gint ett_dtid = -1;
static gint ett_ansi_tcap_stat = -1;

static expert_field ei_ansi_tcap_dissector_not_implemented = EI_INIT;

static struct tcapsrt_info_t * gp_tcapsrt_info;
static gboolean tcap_subdissector_used=FALSE;

static struct tcaphash_context_t * gp_tcap_context=NULL;

/* Note the high bit should be masked off when registering in this table (0x7fff)*/
static dissector_table_t  ansi_tcap_national_opcode_table; /* National Operation Codes */

#include "packet-ansi_tcap-ett.c"

#define MAX_SSN 254

extern gboolean gtcap_PersistentSRT;
extern guint gtcap_RepetitionTimeout;
extern guint gtcap_LostTimeout;

/* When several Tcap components are received in a single TCAP message,
   we have to use several buffers for the stored parameters
   because else this data are erased during TAP dissector call */
#define MAX_TCAP_INSTANCE 10
int tcapsrt_global_current=0;
struct tcapsrt_info_t tcapsrt_global_info[MAX_TCAP_INSTANCE];

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
ansi_tcap_init(void)
{
        TransactionId_table = g_hash_table_new(g_str_hash, g_str_equal);
}

static void
ansi_tcap_cleanup(void)
{
        /* Destroy any existing memory chunks / hashes. */
        g_hash_table_destroy(TransactionId_table);
}

/* Store Invoke information needed for the corresponding reply */
static void
save_invoke_data(packet_info *pinfo, proto_tree *tree _U_, tvbuff_t *tvb _U_){
  struct ansi_tcap_invokedata_t *ansi_tcap_saved_invokedata;
  gchar *src, *dst;
  char *buf;

  src = address_to_str(wmem_packet_scope(), &(pinfo->src));
  dst = address_to_str(wmem_packet_scope(), &(pinfo->dst));

  if ((!pinfo->fd->flags.visited)&&(ansi_tcap_private.TransactionID_str)){

          /* Only do this once XXX I hope it's the right thing to do */
          /* The hash string needs to contain src and dest to distiguish differnt flows */
          switch(ansi_tcap_response_matching_type){
                        case ANSI_TCAP_TID_ONLY:
                                buf = wmem_strdup(wmem_packet_scope(), ansi_tcap_private.TransactionID_str);
                                break;
                        case ANSI_TCAP_TID_AND_SOURCE:
                                buf = wmem_strdup_printf(wmem_packet_scope(), "%s%s",ansi_tcap_private.TransactionID_str,src);
                                break;
                        case ANSI_TCAP_TID_SOURCE_AND_DEST:
                        default:
                                buf = wmem_strdup_printf(wmem_packet_scope(), "%s%s%s",ansi_tcap_private.TransactionID_str,src,dst);
                                break;
                }

          /* If the entry allready exists don't owervrite it */
          ansi_tcap_saved_invokedata = (struct ansi_tcap_invokedata_t *)g_hash_table_lookup(TransactionId_table,buf);
          if(ansi_tcap_saved_invokedata)
                  return;

          ansi_tcap_saved_invokedata = wmem_new(wmem_file_scope(), struct ansi_tcap_invokedata_t);
          ansi_tcap_saved_invokedata->OperationCode = ansi_tcap_private.d.OperationCode;
          ansi_tcap_saved_invokedata->OperationCode_national = ansi_tcap_private.d.OperationCode_national;
          ansi_tcap_saved_invokedata->OperationCode_private = ansi_tcap_private.d.OperationCode_private;

          g_hash_table_insert(TransactionId_table,
                        wmem_strdup(wmem_file_scope(), buf),
                        ansi_tcap_saved_invokedata);
          /*
          g_warning("Tcap Invoke Hash string %s",buf);
          */
  }
}

static gboolean
find_saved_invokedata(packet_info *pinfo, proto_tree *tree _U_, tvbuff_t *tvb _U_){
  struct ansi_tcap_invokedata_t *ansi_tcap_saved_invokedata;
  gchar *src, *dst;
  char *buf;

  if (!ansi_tcap_private.TransactionID_str) {
    return FALSE;
  }

  src = address_to_str(wmem_packet_scope(), &(pinfo->src));
  dst = address_to_str(wmem_packet_scope(), &(pinfo->dst));

  /* The hash string needs to contain src and dest to distiguish differnt flows */
  buf = (char *)wmem_alloc(wmem_packet_scope(), MAX_TID_STR_LEN);
  buf[0] = '\0';
  /* Reverse order to invoke */
  switch(ansi_tcap_response_matching_type){
        case ANSI_TCAP_TID_ONLY:
                g_snprintf(buf,MAX_TID_STR_LEN,"%s",ansi_tcap_private.TransactionID_str);
                break;
        case ANSI_TCAP_TID_AND_SOURCE:
                g_snprintf(buf,MAX_TID_STR_LEN,"%s%s",ansi_tcap_private.TransactionID_str,dst);
                break;
        case ANSI_TCAP_TID_SOURCE_AND_DEST:
        default:
                g_snprintf(buf,MAX_TID_STR_LEN,"%s%s%s",ansi_tcap_private.TransactionID_str,dst,src);
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
                call_ber_oid_callback(ansi_tcap_private.objectApplicationId_oid, tvb, 0, actx-pinfo, tree, NULL);
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
                        proto_tree_add_expert_format(tree, actx->pinfo, &ei_ansi_tcap_dissector_not_implemented, tvb, 0, -1,
                                        "Dissector for ANSI TCAP NATIONAL code:0x%x(Family %u, Specifier %u) \n"
                                        "not implemented. Contact Wireshark developers if you want this supported(Spec required)",
                                        ansi_tcap_private.d.OperationCode_national, family, specifier);
                        return FALSE;
                }
                return TRUE;
        }else if(ansi_tcap_private.d.OperationCode == 1){
                /* private */
                if((ansi_tcap_private.d.OperationCode_private & 0x0900) != 0x0900){
                        proto_tree_add_expert_format(tree, actx->pinfo, &ei_ansi_tcap_dissector_not_implemented, tvb, 0, -1,
                                "Dissector for ANSI TCAP PRIVATE code:%u not implemented.\n"
                                "Contact Wireshark developers if you want this supported(Spec required)",
                                ansi_tcap_private.d.OperationCode_private);
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
        call_dissector_with_data(ansi_map_handle, tvb, actx->pinfo, tcap_top_tree, &ansi_tcap_private);

        return TRUE;
}

#include "packet-ansi_tcap-fn.c"




static int
dissect_ansi_tcap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
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

    gp_tcapsrt_info=tcapsrt_razinfo();
    tcap_subdissector_used=FALSE;
    gp_tcap_context=NULL;
    dissect_ansi_tcap_PackageType(FALSE, tvb, 0, &asn1_ctx, tree, -1);

#if 0 /* Skip this part for now it will be rewritten */
    if (g_ansi_tcap_HandleSRT && !tcap_subdissector_used ) {
                if (gtcap_DisplaySRT && tree) {
                        stat_tree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_ansi_tcap_stat, &stat_item, "Stat");
                        PROTO_ITEM_SET_GENERATED(stat_item);
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
    return tvb_captured_length(tvb);
}


void
proto_reg_handoff_ansi_tcap(void)
{
    ansi_map_handle = find_dissector_add_dependency("ansi_map", proto_ansi_tcap);
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
#include "packet-ansi_tcap-hfarr.c"
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_tcap,
        &ett_param,
        &ett_otid,
        &ett_dtid,
        &ett_ansi_tcap_stat,
        &ett_ansi_tcap_op_code_nat,
        #include "packet-ansi_tcap-ettarr.c"
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
                                   &ansi_tcap_response_matching_type, ansi_tcap_response_matching_type_values, FALSE);

    register_init_routine(&ansi_tcap_init);
    register_cleanup_routine(&ansi_tcap_cleanup);
}
