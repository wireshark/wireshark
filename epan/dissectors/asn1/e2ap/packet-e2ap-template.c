/* packet-e2ap.c
 * Routines for E2APApplication Protocol (e2ap) packet dissection
 * Copyright 2021, Martin Mathieson
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References: ORAN-WG3.E2AP-v02.01, ORAN-WG3.E2SM-KPM-v02.02, ORAN-WG3.E2SM-RC.01.02
 */

#include "config.h"
#include <stdio.h>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/sctpppids.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include <epan/to_str.h>

#include "packet-e2ap.h"
#include "packet-per.h"
#define PNAME  "E2 Application Protocol"
#define PSNAME "E2AP"
#define PFNAME "e2ap"

/* Dissector will use SCTP PPID 18 or SCTP port. IANA assigned port = 37464 */
#define SCTP_PORT_E2AP 37464

void proto_register_e2ap(void);
void proto_reg_handoff_e2ap(void);

static dissector_handle_t e2ap_handle;

#include "packet-e2ap-val.h"

/* Initialize the protocol and registered fields */
static int proto_e2ap = -1;
#include "packet-e2ap-hf.c"

static int hf_e2ap_unmapped_ran_function_id = -1;
static int hf_e2ap_ran_function_name_not_recognised = -1;
static int hf_e2ap_ran_function_setup_frame = -1;



/* Initialize the subtree pointers */
static gint ett_e2ap = -1;

static expert_field ei_e2ap_ran_function_names_no_match = EI_INIT;
static expert_field ei_e2ap_ran_function_id_not_mapped = EI_INIT;

#include "packet-e2ap-ett.c"


/* Forward declarations */
static int dissect_E2SM_KPM_EventTriggerDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_KPM_ActionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_KPM_IndicationHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_KPM_IndicationMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_KPM_RANfunction_Description_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

static int dissect_E2SM_RC_EventTrigger_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_ActionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_RANFunctionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_IndicationMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_IndicationHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_CallProcessID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

static int dissect_E2SM_RC_ControlHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_ControlMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_ControlOutcome_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);



enum {
  INITIATING_MESSAGE,
  SUCCESSFUL_OUTCOME,
  UNSUCCESSFUL_OUTCOME
};

typedef struct _e2ap_ctx_t {
  guint32 message_type;
  guint32 ProcedureCode;
  guint32 ProtocolIE_ID;
  guint32 ProtocolExtensionID;
} e2ap_ctx_t;



struct e2ap_private_data {
  guint32 procedure_code;
  guint32 protocol_ie_id;
  guint32 protocol_extension_id;
  guint32 message_type;
  guint32 ran_ue_e2ap_id;

  guint32 ran_function_id;
  guint32 gnb_id_len;
#define MAX_GNB_ID_BYTES 6
  guint8  gnb_id_bytes[MAX_GNB_ID_BYTES];
};

static struct e2ap_private_data*
e2ap_get_private_data(packet_info *pinfo)
{
  struct e2ap_private_data *e2ap_data = (struct e2ap_private_data*)p_get_proto_data(pinfo->pool, pinfo, proto_e2ap, 0);
  if (!e2ap_data) {
    e2ap_data = wmem_new0(pinfo->pool, struct e2ap_private_data);
    p_add_proto_data(pinfo->pool, pinfo, proto_e2ap, 0, e2ap_data);
  }
  return e2ap_data;
}

/****************************************************************************************************************/
/* We learn which set of RAN functions pointers corresponds to a given ranFunctionID when we see E2SetupRequest */
typedef int (*pdu_dissector_t)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

/* Function pointers for a RANFunction */
typedef struct {
    pdu_dissector_t ran_function_definition_dissector;

    pdu_dissector_t ric_control_header_dissector;
    pdu_dissector_t ric_control_message_dissector;
    pdu_dissector_t ric_control_outcome_dissector;

    pdu_dissector_t ran_action_definition_dissector;
    pdu_dissector_t ran_indication_message_dissector;
    pdu_dissector_t ran_indication_header_dissector;
    pdu_dissector_t ran_callprocessid_dissector;
    pdu_dissector_t ran_event_trigger_dissector;
} ran_function_pointers_t;

typedef enum {
    MIN_RANFUNCTIONS,
    KPM_RANFUNCTIONS=0,
    RIC_RANFUNCTIONS,
    MAX_RANFUNCTIONS
} ran_function_t;

typedef struct {
    const char* name;
    ran_function_pointers_t functions;
} ran_function_name_mapping_t;

/* Static table mapping from string -> ran_function */
static const ran_function_name_mapping_t g_ran_functioname_table[MAX_RANFUNCTIONS] =
{
  { "ORAN-E2SM-KPM", {  dissect_E2SM_KPM_RANfunction_Description_PDU,

                        NULL,
                        NULL,
                        NULL,

                        dissect_E2SM_KPM_ActionDefinition_PDU,
                        dissect_E2SM_KPM_IndicationMessage_PDU,
                        dissect_E2SM_KPM_IndicationHeader_PDU,
                        NULL, /* no dissect_E2SM_KPM_CallProcessID_PDU */
                        dissect_E2SM_KPM_EventTriggerDefinition_PDU
                     }
  },
  { "ORAN-E2SM-RC",  {  dissect_E2SM_RC_RANFunctionDefinition_PDU,

                        dissect_E2SM_RC_ControlHeader_PDU,
                        dissect_E2SM_RC_ControlMessage_PDU,
                        dissect_E2SM_RC_ControlOutcome_PDU,

                        dissect_E2SM_RC_ActionDefinition_PDU,
                        dissect_E2SM_RC_IndicationMessage_PDU,
                        dissect_E2SM_RC_IndicationHeader_PDU,
                        dissect_E2SM_RC_CallProcessID_PDU,
                        dissect_E2SM_RC_EventTrigger_PDU
                     }
  }
};



/* Per-conversation mapping: ranFunctionId -> ran_function */
typedef struct {
    guint32                  setup_frame;
    guint32                  ran_function_id;
    ran_function_t           ran_function;
    ran_function_pointers_t *ran_function_pointers;
} ran_function_id_mapping_t;

typedef struct  {
#define MAX_RANFUNCTION_ENTRIES 8
    guint32                   num_entries;
    ran_function_id_mapping_t entries[MAX_RANFUNCTION_ENTRIES];
} ran_functionid_table_t;

const char *ran_function_to_str(ran_function_t ran_function)
{
    switch (ran_function) {
        case KPM_RANFUNCTIONS:
            return "KPM";
        case RIC_RANFUNCTIONS:
            return "RIC";

        default:
            return "Unknown";
    }
}

typedef struct {
#define MAX_GNBS 6
    guint32 num_gnbs;
    struct {
        guint32 len;
        guint8  value[MAX_GNB_ID_BYTES];
        ran_functionid_table_t *ran_function_table;
    } gnb[MAX_GNBS];
} gnb_ran_functions_t;

static gnb_ran_functions_t s_gnb_ran_functions;


/* Get RANfunctionID table from conversation data - create new if necessary */
ran_functionid_table_t* get_ran_functionid_table(packet_info *pinfo)
{
    conversation_t *p_conv;
    ran_functionid_table_t *p_conv_data = NULL;

    /* Lookup conversation */
    p_conv = find_conversation(pinfo->num, &pinfo->net_dst, &pinfo->net_src,
                               conversation_pt_to_endpoint_type(pinfo->ptype),
                               pinfo->destport, pinfo->srcport, 0);
    if (!p_conv) {
        /* None, so create new data and set */
        p_conv = conversation_new(pinfo->num, &pinfo->net_dst, &pinfo->net_src,
                                  conversation_pt_to_endpoint_type(pinfo->ptype),
                                  pinfo->destport, pinfo->srcport, 0);
        p_conv_data = (ran_functionid_table_t*)wmem_new0(wmem_file_scope(), ran_functionid_table_t);
        conversation_add_proto_data(p_conv, proto_e2ap, p_conv_data);
    }
    else {
        /* Will return existing conversation data */
        p_conv_data = (ran_functionid_table_t*)conversation_get_proto_data(p_conv, proto_e2ap);
    }

    return p_conv_data;
}


/* Store new RANfunctionID -> Service Model mapping in table */
static void store_ran_function_mapping(packet_info *pinfo, ran_functionid_table_t *table, struct e2ap_private_data *e2ap_data, const char *name)
{
    /* Stop if already reached table limit */
    if (table->num_entries == MAX_RANFUNCTION_ENTRIES) {
        /* TODO: expert info warning? */
        return;
    }

    guint32 ran_function_id = e2ap_data->ran_function_id;

    ran_function_t           ran_function = MAX_RANFUNCTIONS;  /* i.e. invalid */
    ran_function_pointers_t *ran_function_pointers = NULL;

    /* Check known RAN functions */
    for (int n=MIN_RANFUNCTIONS; n < MAX_RANFUNCTIONS; n++) {
        /* TODO: shouldn't need to check both positions! */
        if ((strcmp(name,   g_ran_functioname_table[n].name) == 0) ||
            (strcmp(name+1, g_ran_functioname_table[n].name) == 0)) {

            ran_function = n;
            ran_function_pointers = (ran_function_pointers_t*)&(g_ran_functioname_table[n].functions);
            break;
        }
    }

    /* Nothing to do if no matches */
    if (ran_function == MAX_RANFUNCTIONS) {
        return;
    }

    /* If ID already mapped, ignore */
    for (guint n=0; n < table->num_entries; n++) {
        if (table->entries[n].ran_function_id == ran_function_id) {
            return;
        }
    }

    /* OK, store this new entry */
    guint idx = table->num_entries++;
    table->entries[idx].setup_frame = pinfo->num;
    table->entries[idx].ran_function_id = ran_function_id;
    table->entries[idx].ran_function = ran_function;
    table->entries[idx].ran_function_pointers = ran_function_pointers;

    /* When add first entry, also want to set up table from gnbId -> table */
    if (idx == 0) {
        guint id_len = e2ap_data->gnb_id_len;
        guint8 *id_value = &e2ap_data->gnb_id_bytes[0];

        gboolean found = FALSE;
        for (guint n=0; n<s_gnb_ran_functions.num_gnbs; n++) {
            if ((s_gnb_ran_functions.gnb[n].len = id_len) &&
                (memcmp(s_gnb_ran_functions.gnb[n].value, id_value, id_len) == 0)) {
                // Already have an entry for this gnb.
                found = TRUE;
                break;
            }
        }

        if (!found) {
            /* Add entry (if room for 1 more) */
            guint32 new_idx = s_gnb_ran_functions.num_gnbs;
            if (new_idx < MAX_GNBS-1) {
                s_gnb_ran_functions.gnb[new_idx].len = id_len;
                memcpy(s_gnb_ran_functions.gnb[new_idx].value, id_value, id_len);
                s_gnb_ran_functions.gnb[new_idx].ran_function_table = table;

                s_gnb_ran_functions.num_gnbs++;
            }
        }
    }
}

/* Look for Service Model function pointers, based on current RANFunctionID in pinfo */
ran_function_pointers_t* lookup_ranfunction_pointers(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb)
{
    /* Get ranFunctionID from this frame */
    struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);
    guint ran_function_id = e2ap_data->ran_function_id;

    /* Look in table function pointers for this ranFunctionID */
    ran_functionid_table_t *table = get_ran_functionid_table(pinfo);
    for (guint n=0; n < table->num_entries; n++) {
        if (ran_function_id == table->entries[n].ran_function_id) {
            /* Point back at the setup frame where this ranfunction was mapped */
            proto_item *ti = proto_tree_add_uint(tree, hf_e2ap_ran_function_setup_frame,
                                                 tvb, 0, 0, table->entries[n].setup_frame);
            /* Also show that mapping */
            proto_item_append_text(ti, " (%u -> %s)", table->entries[n].ran_function_id, ran_function_to_str(table->entries[n].ran_function));
            proto_item_set_generated(ti);

            return table->entries[n].ran_function_pointers;
        }
    }

    /* No match found.. */
    proto_item *ti = proto_tree_add_item(tree, hf_e2ap_unmapped_ran_function_id, tvb, 0, 0, ENC_NA);
    expert_add_info_format(pinfo, ti, &ei_e2ap_ran_function_id_not_mapped,
                           "Service Model not mapped for FunctionID %u", ran_function_id);
    return NULL;
}

/* This will get used for E2nodeConfigurationUpdate, where we have a gnb-id but haven't seen E2setupRequest */
void update_conversation_from_gnb_id(asn1_ctx_t *actx _U_)
{
    packet_info *pinfo = actx->pinfo;
    struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);

    /* Look for conversation data */
    conversation_t *p_conv;
    ran_functionid_table_t *p_conv_data = NULL;

    /* Lookup conversation */
    p_conv = find_conversation(pinfo->num, &pinfo->net_dst, &pinfo->net_src,
                               conversation_pt_to_endpoint_type(pinfo->ptype),
                               pinfo->destport, pinfo->srcport, 0);

    if (!p_conv) {
        /* None, so create new data and set */
        p_conv = conversation_new(pinfo->num, &pinfo->net_dst, &pinfo->net_src,
                                  conversation_pt_to_endpoint_type(pinfo->ptype),
                                  pinfo->destport, pinfo->srcport, 0);
        p_conv_data = (ran_functionid_table_t*)wmem_new0(wmem_file_scope(), ran_functionid_table_t);
        conversation_add_proto_data(p_conv, proto_e2ap, p_conv_data);

        /* Look to see if we already know about the mappings in effect on this gNB */
        guint id_len = e2ap_data->gnb_id_len;
        guint8 *id_value = &e2ap_data->gnb_id_bytes[0];

        for (guint n=0; n<s_gnb_ran_functions.num_gnbs; n++) {
            if ((s_gnb_ran_functions.gnb[n].len = id_len) &&
                (memcmp(s_gnb_ran_functions.gnb[n].value, id_value, id_len) == 0)) {

                /* Have an entry for this gnb.  Set direct pointer to existing data (used by original conversation). */
                /* N.B. This means that no further updates for the gNB are expected on different conversations.. */
                p_conv_data = s_gnb_ran_functions.gnb[n].ran_function_table;
                conversation_add_proto_data(p_conv, proto_e2ap, p_conv_data);

                /* TODO: may want to try to add a generated field to pass back to E2setupRequest where RAN function mappings were first seen? */
                break;
            }
        }
    }
}


/* Dissector tables */
static dissector_table_t e2ap_ies_dissector_table;

//static dissector_table_t e2ap_ies_p1_dissector_table;
//static dissector_table_t e2ap_ies_p2_dissector_table;
static dissector_table_t e2ap_extension_dissector_table;
static dissector_table_t e2ap_proc_imsg_dissector_table;
static dissector_table_t e2ap_proc_sout_dissector_table;
static dissector_table_t e2ap_proc_uout_dissector_table;
static dissector_table_t e2ap_n2_ie_type_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

/* Currently not used
static int dissect_ProtocolIEFieldPairFirstValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_ProtocolIEFieldPairSecondValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
*/


static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);


#include "packet-e2ap-fn.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  e2ap_ctx_t e2ap_ctx;
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);

  e2ap_ctx.message_type        = e2ap_data->message_type;
  e2ap_ctx.ProcedureCode       = e2ap_data->procedure_code;
  e2ap_ctx.ProtocolIE_ID       = e2ap_data->protocol_ie_id;
  e2ap_ctx.ProtocolExtensionID = e2ap_data->protocol_extension_id;

  return (dissector_try_uint_new(e2ap_ies_dissector_table, e2ap_data->protocol_ie_id, tvb, pinfo, tree, FALSE, &e2ap_ctx)) ? tvb_captured_length(tvb) : 0;
}



/* Currently not used
static int dissect_ProtocolIEFieldPairFirstValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);

  return (dissector_try_uint(e2ap_ies_p1_dissector_table, e2ap_data->protocol_ie_id, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolIEFieldPairSecondValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);

  return (dissector_try_uint(e2ap_ies_p2_dissector_table, e2ap_data->protocol_ie_id, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}
*/


static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);

  return (dissector_try_uint_new(e2ap_proc_imsg_dissector_table, e2ap_data->procedure_code, tvb, pinfo, tree, TRUE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);

  return (dissector_try_uint_new(e2ap_proc_sout_dissector_table, e2ap_data->procedure_code, tvb, pinfo, tree, TRUE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);

  return (dissector_try_uint_new(e2ap_proc_uout_dissector_table, e2ap_data->procedure_code, tvb, pinfo, tree, TRUE, data)) ? tvb_captured_length(tvb) : 0;
}


static int
dissect_e2ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *e2ap_item = NULL;
  proto_tree *e2ap_tree = NULL;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "E2AP");
  col_clear(pinfo->cinfo, COL_INFO);

  /* create the e2ap protocol tree */
  e2ap_item = proto_tree_add_item(tree, proto_e2ap, tvb, 0, -1, ENC_NA);
  e2ap_tree = proto_item_add_subtree(e2ap_item, ett_e2ap);

  return dissect_E2AP_PDU_PDU(tvb, pinfo, e2ap_tree, NULL);
}


static void e2ap_init_protocol(void)
{
  s_gnb_ran_functions.num_gnbs = 0;
}


/*--- proto_reg_handoff_e2ap ---------------------------------------*/
void
proto_reg_handoff_e2ap(void)
{
  dissector_add_uint_with_preference("sctp.port", SCTP_PORT_E2AP, e2ap_handle);

#include "packet-e2ap-dis-tab.c"
}



/*--- proto_register_e2ap -------------------------------------------*/
void proto_register_e2ap(void) {

  /* List of fields */

  static hf_register_info hf[] = {
#include "packet-e2ap-hfarr.c"
      { &hf_e2ap_unmapped_ran_function_id,
          { "Unmapped RANfunctionID", "e2ap.unmapped-ran-function-id",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
      { &hf_e2ap_ran_function_name_not_recognised,
          { "RANfunction name not recognised", "e2ap.ran-function-name-not-recognised",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
      { &hf_e2ap_ran_function_setup_frame,
          { "RANfunction setup frame", "e2ap.setup-frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }}
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_e2ap,
#include "packet-e2ap-ettarr.c"
  };

  static ei_register_info ei[] = {
     { &ei_e2ap_ran_function_names_no_match, { "e2ap.ran-function-names-no-match", PI_PROTOCOL, PI_WARN, "RAN Function name doesn't match known service models", EXPFILL }},
     { &ei_e2ap_ran_function_id_not_mapped,   { "e2ap.ran-function-id-not-known", PI_PROTOCOL, PI_WARN, "Service Model not known for RANFunctionID", EXPFILL }},
  };

  expert_module_t* expert_e2ap;

  /* Register protocol */
  proto_e2ap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_e2ap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));


  /* Register dissector */
  e2ap_handle = register_dissector("e2ap", dissect_e2ap, proto_e2ap);

  expert_e2ap = expert_register_protocol(proto_e2ap);
  expert_register_field_array(expert_e2ap, ei, array_length(ei));

  /* Register dissector tables */
  e2ap_ies_dissector_table = register_dissector_table("e2ap.ies", "E2AP-PROTOCOL-IES", proto_e2ap, FT_UINT32, BASE_DEC);

  //  e2ap_ies_p1_dissector_table = register_dissector_table("e2ap.ies.pair.first", "E2AP-PROTOCOL-IES-PAIR FirstValue", proto_e2ap, FT_UINT32, BASE_DEC);
  //  e2ap_ies_p2_dissector_table = register_dissector_table("e2ap.ies.pair.second", "E2AP-PROTOCOL-IES-PAIR SecondValue", proto_e2ap, FT_UINT32, BASE_DEC);
  e2ap_extension_dissector_table = register_dissector_table("e2ap.extension", "E2AP-PROTOCOL-EXTENSION", proto_e2ap, FT_UINT32, BASE_DEC);
  e2ap_proc_imsg_dissector_table = register_dissector_table("e2ap.proc.imsg", "E2AP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_e2ap, FT_UINT32, BASE_DEC);
  e2ap_proc_sout_dissector_table = register_dissector_table("e2ap.proc.sout", "E2AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_e2ap, FT_UINT32, BASE_DEC);
  e2ap_proc_uout_dissector_table = register_dissector_table("e2ap.proc.uout", "E2AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_e2ap, FT_UINT32, BASE_DEC);
  e2ap_n2_ie_type_dissector_table = register_dissector_table("e2ap.n2_ie_type", "E2AP N2 IE Type", proto_e2ap, FT_STRING, FALSE);

  register_init_routine(&e2ap_init_protocol);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
