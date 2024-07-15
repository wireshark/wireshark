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
 * References: ORAN-WG3.E2AP-v03.00, ORAN-WG3.E2SM-KPM-v03.00, ORAN-WG3.E2SM-RC.03.00
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/sctpppids.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>
#include <epan/to_str.h>
#include <epan/oids.h>
#include <epan/tap.h>
#include <epan/stats_tree.h>

#include "packet-e2ap.h"
#include "packet-per.h"
#include "packet-ntp.h"

#define PNAME  "E2 Application Protocol"
#define PSNAME "E2AP"
#define PFNAME "e2ap"

/* Dissector will use SCTP PPID 70, 71 or 72 or SCTP port 37464. */
#define SCTP_PORT_E2AP 37464

void proto_register_e2ap(void);
void proto_reg_handoff_e2ap(void);

static dissector_handle_t e2ap_handle;

#include "packet-e2ap-val.h"

/* Initialize the protocol and registered fields */
static int proto_e2ap;
#include "packet-e2ap-hf.c"

static int hf_e2ap_unmapped_ran_function_id;
static int hf_e2ap_ran_function_name_not_recognised;
static int hf_e2ap_ran_function_setup_frame;
/* TODO: for each RAN Function, also link forward to where setup is referenced (if at all?).  Maybe just first usage? */

static int hf_e2ap_dissector_version;
static int hf_e2ap_frame_version;

static int hf_e2ap_timestamp_string;


/* Initialize the subtree pointers */
static int ett_e2ap;

static expert_field ei_e2ap_ran_function_names_no_match;
static expert_field ei_e2ap_ran_function_id_not_mapped;
static expert_field ei_e2ap_ran_function_dissector_mismatch;
static expert_field ei_e2ap_ran_function_max_dissectors_registered;

#include "packet-e2ap-ett.c"


/* Forward declarations */
static int dissect_e2ap_RANfunction_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);


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

static int dissect_E2SM_NI_EventTriggerDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_NI_ActionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_NI_RANfunction_Description_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_NI_IndicationMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_NI_IndicationHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_NI_CallProcessID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_NI_ControlHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_NI_ControlMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_NI_ControlOutcome_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

enum {
  INITIATING_MESSAGE,
  SUCCESSFUL_OUTCOME,
  UNSUCCESSFUL_OUTCOME
};


/* E2AP stats - Tap interface */

static void set_stats_message_type(packet_info *pinfo, int type);

static const uint8_t *st_str_packets        = "Total Packets";
static const uint8_t *st_str_packet_types   = "E2AP Packet Types";

static int st_node_packets = -1;
static int st_node_packet_types = -1;
static int e2ap_tap;

struct e2ap_tap_t {
    int e2ap_mtype;
};

#define MTYPE_E2_CONNECTION_UPDATE             1
#define MTYPE_E2_CONNECTION_UPDATE_ACK         2
#define MTYPE_E2_CONNECTION_UPDATE_FAIL        3
#define MTYPE_E2_CONFIGURATION_UPDATE          4
#define MTYPE_E2_CONFIGURATION_UPDATE_ACK      5
#define MTYPE_E2_CONFIGURATION_UPDATE_FAIL     6
#define MTYPE_E2_SETUP_FAIL                    7
#define MTYPE_E2_SETUP_REQUEST                 8
#define MTYPE_E2_SETUP_RESPONSE                9
#define MTYPE_ERROR_INDICATION                 10
#define MTYPE_RESET_REQUEST                    11
#define MTYPE_RESET_RESPONSE                   12
#define MTYPE_RIC_CONTROL_ACK                  13
#define MTYPE_RIC_CONTROL_FAIL                 14
#define MTYPE_RIC_CONTROL_REQUEST              15
#define MTYPE_RIC_IND                          16
#define MTYPE_RIC_SERVICE_QUERY                17
#define MTYPE_RIC_SERVICE_UPDATE               18
#define MTYPE_RIC_SERVICE_UPDATE_ACK           19
#define MTYPE_RIC_SERVICE_UPDATE_FAIL          20
#define MTYPE_RIC_SUBSCRIPTION_FAIL            21
#define MTYPE_RIC_SUBSCRIPTION_REQUEST         22
#define MTYPE_RIC_SUBSCRIPTION_RESPONSE        23
#define MTYPE_RIC_SUBSCRIPTION_DELETE_FAIL     24
#define MTYPE_RIC_SUBSCRIPTION_DELETE_REQUEST  25
#define MTYPE_RIC_SUBSCRIPTION_DELETE_RESPONSE 26
#define MTYPE_RIC_SUBSCRIPTION_DELETE_REQUIRED 27

/* Value Strings. TODO: ext? */
static const value_string mtype_names[] = {
    { MTYPE_E2_CONNECTION_UPDATE,                "E2connectionUpdate"},
    { MTYPE_E2_CONNECTION_UPDATE_ACK,            "E2connectionUpdateAcknowledge"},
    { MTYPE_E2_CONNECTION_UPDATE_FAIL,           "E2connectionUpdateFailure"},
    { MTYPE_E2_CONFIGURATION_UPDATE,             "E2nodeConfigurationUpdate"},
    { MTYPE_E2_CONFIGURATION_UPDATE_ACK,         "E2nodeConfigurationUpdateAcknowledge"},
    { MTYPE_E2_CONFIGURATION_UPDATE_FAIL,        "E2nodeConfigurationUpdateFailure"},
    { MTYPE_E2_SETUP_FAIL,                       "E2setupFailure"},
    { MTYPE_E2_SETUP_REQUEST,                    "E2setupRequest"},
    { MTYPE_E2_SETUP_RESPONSE,                   "E2setupResponse"},
    { MTYPE_ERROR_INDICATION,                    "ErrorIndication"},
    { MTYPE_RESET_REQUEST,                       "ResetRequest"},
    { MTYPE_RESET_RESPONSE,                      "ResetResponse"},
    { MTYPE_RIC_CONTROL_ACK,                     "RICcontrolAcknowledge"},
    { MTYPE_RIC_CONTROL_FAIL,                    "RICcontrolFailure"},
    { MTYPE_RIC_CONTROL_REQUEST,                 "RICcontrolRequest"},
    { MTYPE_RIC_IND,                             "RICindication"},
    { MTYPE_RIC_SERVICE_QUERY,                   "RICserviceQuery"},
    { MTYPE_RIC_SERVICE_UPDATE,                  "RICserviceUpdate"},
    { MTYPE_RIC_SERVICE_UPDATE_ACK,              "RICserviceUpdateAcknowledge"},
    { MTYPE_RIC_SERVICE_UPDATE_FAIL,             "RICserviceUpdateFailure"},
    { MTYPE_RIC_SUBSCRIPTION_FAIL,               "RICsubscriptionFailure"},
    { MTYPE_RIC_SUBSCRIPTION_REQUEST,            "RICsubscriptionRequest"},
    { MTYPE_RIC_SUBSCRIPTION_RESPONSE,           "RICsubscriptionResponse"},
    { MTYPE_RIC_SUBSCRIPTION_DELETE_FAIL,        "RICsubscriptionDeleteFailure"},
    { MTYPE_RIC_SUBSCRIPTION_DELETE_REQUEST,     "RICsubscriptionDeleteRequest"},
    { MTYPE_RIC_SUBSCRIPTION_DELETE_RESPONSE,    "RICsubscriptionDeleteResponse"},
    { MTYPE_RIC_SUBSCRIPTION_DELETE_REQUIRED,    "RICsubscriptionDeleteRequired"},
    { 0,  NULL }
};

static proto_tree *top_tree;

static void set_message_label(asn1_ctx_t *actx, int type)
{
  const char *label = val_to_str_const(type, mtype_names, "Unknown");
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, label);
  proto_item_append_text(top_tree, " (%s)", label);
}




/* Temporary private info to remember while dissecting frame */
struct e2ap_private_data {
  uint32_t procedure_code;
  uint32_t protocol_ie_id;
  uint32_t message_type;

  uint32_t ran_function_id;
  uint32_t gnb_id_len;
#define MAX_GNB_ID_BYTES 6
  uint8_t gnb_id_bytes[MAX_GNB_ID_BYTES];
  dissector_handle_t component_configuration_dissector;
  struct e2ap_tap_t *stats_tap;
};

/* Lookup temporary private info */
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
/* These are the strings that we look for at the beginning of RAN Function Description to identify RAN Function */
/* Static table mapping from string -> ran_function */
static const char* g_ran_function_name_table[MAX_RANFUNCTIONS] =
{
    "ORAN-E2SM-KPM",
    "ORAN-E2SM-RC",
    "ORAN-E2SM-NI",
    "{"               /* For now, CCC is the only JSON-based RAN Function, so just match opening */
};



/* Per-conversation mapping: ranFunctionId -> ran_function+dissector */
typedef struct {
    uint32_t                 setup_frame;
    uint32_t                 ran_function_id;
    ran_function_t           ran_function;
    char                     oid[MAX_OID_LEN];       // i.e., OID from setupRequest
    ran_function_dissector_t *dissector;
} ran_function_id_mapping_t;

typedef struct  {
#define MAX_RANFUNCTION_ENTRIES 8
    uint32_t                  num_entries;
    ran_function_id_mapping_t entries[MAX_RANFUNCTION_ENTRIES];
} ran_functionid_table_t;

static const char *ran_function_to_str(ran_function_t ran_function)
{
    switch (ran_function) {
        case KPM_RANFUNCTIONS:
            return "KPM";
        case RC_RANFUNCTIONS:
            return "RC";
        case NI_RANFUNCTIONS:
            return "NI";
        case CCC_RANFUNCTIONS:
            return "CCC";

        default:
            return "Unknown";
    }
}

/* Table of RAN Function tables, indexed by gnbId (bytes) */
typedef struct {
#define MAX_GNBS 6
    uint32_t num_gnbs;
    struct {
        uint8_t id_value[MAX_GNB_ID_BYTES];
        uint32_t id_len;
        ran_functionid_table_t *ran_function_table;
    } gnb[MAX_GNBS];
} gnb_ran_functions_t;

static gnb_ran_functions_t s_gnb_ran_functions_table;


/* Table of available dissectors for each RAN function */
typedef struct {
    uint32_t                 num_available_dissectors;
#define MAX_DISSECTORS_PER_RAN_FUNCTION 8
    ran_function_dissector_t* ran_function_dissectors[MAX_DISSECTORS_PER_RAN_FUNCTION];
} ran_function_available_dissectors_t;

/* Available dissectors should be set here */
static ran_function_available_dissectors_t g_ran_functions_available_dissectors[MAX_RANFUNCTIONS];

/* Will be called from outside this file by separate dissectors */
void register_e2ap_ran_function_dissector(ran_function_t ran_function, ran_function_dissector_t *dissector)
{
    if ((ran_function >= MIN_RANFUNCTIONS) && (ran_function < MAX_RANFUNCTIONS)) {
        ran_function_available_dissectors_t *available_dissectors = &g_ran_functions_available_dissectors[ran_function];
        if (available_dissectors->num_available_dissectors < MAX_DISSECTORS_PER_RAN_FUNCTION) {
            available_dissectors->ran_function_dissectors[available_dissectors->num_available_dissectors++] = dissector;
        }
    }
}


/* Get RANfunctionID table from conversation data - create new if necessary */
static ran_functionid_table_t* get_ran_functionid_table(packet_info *pinfo)
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
void e2ap_store_ran_function_mapping(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, const char *name)
{
    struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);
    ran_functionid_table_t *table = get_ran_functionid_table(pinfo);

    /* Need these pointers not to be NULL */
    if (!name || !table) {
      return;
    }

    /* Stop if already reached table limit */
    if (table->num_entries == MAX_RANFUNCTION_ENTRIES) {
        proto_tree_add_expert_format(tree, pinfo, &ei_e2ap_ran_function_max_dissectors_registered,
                                     tvb, 0, 0,
                                     "Dissector wants to register for %s, but max (%u) already reached",
                                     name, MAX_RANFUNCTION_ENTRIES);
        return;
    }

    uint32_t ran_function_id = e2ap_data->ran_function_id;

    ran_function_t           ran_function = MAX_RANFUNCTIONS;  /* i.e. invalid */
    ran_function_dissector_t *ran_function_dissector = NULL;

    /* Check known RAN function names */
    for (int n=MIN_RANFUNCTIONS; n < MAX_RANFUNCTIONS; n++) {
        if (strcmp(name, g_ran_function_name_table[n]) == 0) {
            ran_function = n;

            /* Don't know OID yet, so for now, just choose first/only one */
            /* TODO: is latest one likely to be more compatible? First fields (at least) come from E2SM.. */
            if (g_ran_functions_available_dissectors[table->entries[n].ran_function].num_available_dissectors) {
                ran_function_dissector = g_ran_functions_available_dissectors[table->entries[n].ran_function].ran_function_dissectors[0];
            }
            break;
        }
    }

    /* Nothing to do if no matches */
    if (ran_function == MAX_RANFUNCTIONS) {
        return;
    }

    /* If ID already mapped, can stop here */
    for (unsigned n=0; n < table->num_entries; n++) {
        if (table->entries[n].ran_function_id == ran_function_id) {
            return;
        }
    }

    /* OK, store this new entry */
    unsigned idx = table->num_entries++;
    table->entries[idx].setup_frame = pinfo->num;
    table->entries[idx].ran_function_id = ran_function_id;
    table->entries[idx].ran_function = ran_function;
    table->entries[idx].dissector = ran_function_dissector;

    /* When add first entry, also want to set up table from gnbId -> table */
    if (idx == 0) {
        unsigned id_len = e2ap_data->gnb_id_len;
        uint8_t *id_value = &e2ap_data->gnb_id_bytes[0];

        bool found = false;
        for (unsigned n=0; n<s_gnb_ran_functions_table.num_gnbs; n++) {
            if ((s_gnb_ran_functions_table.gnb[n].id_len = id_len) &&
                (memcmp(s_gnb_ran_functions_table.gnb[n].id_value, id_value, id_len) == 0)) {
                /* Already have an entry for this gnb. */
                found = true;
                break;
            }
        }

        if (!found) {
            /* Add entry (if room for 1 more) */
            uint32_t new_idx = s_gnb_ran_functions_table.num_gnbs;
            if (new_idx < MAX_GNBS-1) {
                s_gnb_ran_functions_table.gnb[new_idx].id_len = id_len;
                memcpy(s_gnb_ran_functions_table.gnb[new_idx].id_value, id_value, id_len);
                s_gnb_ran_functions_table.gnb[new_idx].ran_function_table = table;

                s_gnb_ran_functions_table.num_gnbs++;
            }
        }
    }
}

/* Look for Service Model function pointers, based on current RANFunctionID from frame */
static ran_function_dissector_t* lookup_ranfunction_dissector(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb)
{
    /* Get ranFunctionID from this frame */
    struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);
    unsigned ran_function_id = e2ap_data->ran_function_id;

    /* Get ranFunction table corresponding to this frame's conversation */
    ran_functionid_table_t *table = get_ran_functionid_table(pinfo);
    if (!table) {
        /* There is no ran function table associated with this frame's conversation info */
        return NULL;
    }

    /* Find the entry in this table corresponding to ran_function_id */
    for (unsigned n=0; n < table->num_entries; n++) {
        if (ran_function_id == table->entries[n].ran_function_id) {
            if (tree) {
                /* Point back at the setup frame where this ranfunction was mapped */
                proto_item *ti = proto_tree_add_uint(tree, hf_e2ap_ran_function_setup_frame,
                                                     tvb, 0, 0, table->entries[n].setup_frame);
                /* Show that mapping */
                proto_item_append_text(ti, " (%u -> %s)", table->entries[n].ran_function_id, ran_function_to_str(table->entries[n].ran_function));
                proto_item_set_generated(ti);

                /* Also take the chance to compare signalled and available dissector */
                char *frame_version = oid_resolved_from_string(pinfo->pool, table->entries[n].oid);
                ti = proto_tree_add_string(tree, hf_e2ap_frame_version, tvb, 0, 0, frame_version);
                proto_item_set_generated(ti);

                char *dissector_version = oid_resolved_from_string(pinfo->pool, table->entries[n].dissector->oid);
                ti = proto_tree_add_string(tree, hf_e2ap_dissector_version, tvb, 0, 0, dissector_version);
                proto_item_set_generated(ti);

                if (strcmp(frame_version, dissector_version) != 0) {
                    /* Expert info for version mismatch! */
                    expert_add_info_format(pinfo, ti, &ei_e2ap_ran_function_dissector_mismatch,
                                           "Dissector version mismatch - frame is %s but dissector is %s",
                                           frame_version, dissector_version);
                }
            }

            /* Return the dissector */
            return table->entries[n].dissector;
        }
    }

    if (tree) {
        /* No match found.. */
        proto_item *ti = proto_tree_add_item(tree, hf_e2ap_unmapped_ran_function_id, tvb, 0, 0, ENC_NA);
        expert_add_info_format(pinfo, ti, &ei_e2ap_ran_function_id_not_mapped,
                               "Service Model not mapped for FunctionID %u", ran_function_id);
    }

    return NULL;
}

/* Return the oid associated with this frame's conversation */
static char* lookup_ranfunction_oid(packet_info *pinfo)
{
    /* Get ranFunctionID from this frame */
    struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);
    unsigned ran_function_id = e2ap_data->ran_function_id;

    /* Get ranFunction table corresponding to this frame's conversation */
    ran_functionid_table_t *table = get_ran_functionid_table(pinfo);
    if (!table) {
        /* There is no ran function table associated with this frame's conversation info */
        return NULL;
    }

    /* Find the entry in this table corresponding to ran_function_id */
    for (unsigned n=0; n < table->num_entries; n++) {
        if (ran_function_id == table->entries[n].ran_function_id) {
            return (char*)(table->entries[n].oid);
        }
    }

    /* Not found */
    return NULL;
}


/* We now know the OID - can we set a dissector that is an exact match from what has been signalled? */
static void update_dissector_using_oid(packet_info *pinfo, ran_function_t ran_function)
{
    char *frame_oid = lookup_ranfunction_oid(pinfo);
    if (frame_oid == NULL) {
        /* TODO: error? */
        return;
    }

    bool found = false;

    /* Look at available dissectors for this RAN function */
    ran_function_available_dissectors_t *available = &g_ran_functions_available_dissectors[ran_function];
    if (!available->num_available_dissectors) {
        /* Oops - none available at all! */
        return;
    }

    // Get mapping in use
    struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);
    unsigned ran_function_id = e2ap_data->ran_function_id;
    ran_function_id_mapping_t *mapping = NULL;
    ran_functionid_table_t *table = get_ran_functionid_table(pinfo);
    if (!table) {
        return;
    }

    /* Find the entry in this table corresponding to ran_function_id */
    for (unsigned n=0; n < table->num_entries; n++) {
        if (ran_function_id == table->entries[n].ran_function_id) {
            mapping = &(table->entries[n]);
        }
    }

    if (!mapping) {
        return;
    }

    /* Set dissector pointer in ran_function_id_mapping_t */
    for (uint32_t n=0; n < available->num_available_dissectors; n++) {
        /* If exact match, set it */
        if (strcmp(frame_oid, available->ran_function_dissectors[n]->oid) == 0) {
            mapping->dissector = available->ran_function_dissectors[n];
            found = true;
            break;
        }
    }

    /* If not exact match, just set to first one available (TODO: closest above better?) */
    if (!found) {
        mapping->dissector = available->ran_function_dissectors[0];
    }
}


/* Update RANfunctionID -> Service Model mapping in table (now that we know OID) */
void e2ap_update_ran_function_mapping(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, const char *oid)
{
    /* Copy OID into table entry (so may be used to choose and be compared with chosen available dissector */
    struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);
    ran_functionid_table_t *table = get_ran_functionid_table(pinfo);
    /* Make sure we have private and table data to compare */
    if (!e2ap_data || !table) {
        return;
    }
    ran_function_t ran_function = MAX_RANFUNCTIONS;
    for (unsigned n=0; n < table->num_entries; n++) {
        if (e2ap_data->ran_function_id == table->entries[n].ran_function_id) {
            ran_function = table->entries[n].ran_function;
            g_strlcpy(table->entries[n].oid, oid, MAX_OID_LEN);
        }
    }

    /* Look up version from oid and show as generated field */
    char *version = oid_resolved_from_string(pinfo->pool, oid);
    proto_item *ti = proto_tree_add_string(tree, hf_e2ap_frame_version, tvb, 0, 0, version);
    proto_item_set_generated(ti);

    /* Can now pick most appropriate dissector for this RAN Function name, based upon this OID and the available dissectors */
    if (ran_function < MAX_RANFUNCTIONS) {
        if (pinfo->fd->visited) {
            update_dissector_using_oid(pinfo, ran_function);
        }
    }
}

/* This will get used for E2nodeConfigurationUpdate, where we have a gnb-id but haven't seen E2setupRequest */
static void update_conversation_from_gnb_id(asn1_ctx_t *actx)
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
        unsigned id_len = e2ap_data->gnb_id_len;
        uint8_t *id_value = &e2ap_data->gnb_id_bytes[0];

        for (unsigned n=0; n<s_gnb_ran_functions_table.num_gnbs; n++) {
            if ((s_gnb_ran_functions_table.gnb[n].id_len = id_len) &&
                (memcmp(s_gnb_ran_functions_table.gnb[n].id_value, id_value, id_len) == 0)) {

                /* Have an entry for this gnb.  Set direct pointer to existing data (used by original conversation). */
                /* N.B. This means that no further updates for the gNB are expected on different conversations.. */
                p_conv_data = s_gnb_ran_functions_table.gnb[n].ran_function_table;
                conversation_add_proto_data(p_conv, proto_e2ap, p_conv_data);

                /* TODO: may want to try to add a generated field to pass back to E2setupRequest where RAN function mappings were first seen? */
                break;
            }
        }
    }
}

static dissector_handle_t json_handle;

static int dissect_E2SM_NI_JSON_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Send to JSON dissector */
    return call_dissector_only(json_handle, tvb, pinfo, tree, NULL);
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
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);
  return (dissector_try_uint_new(e2ap_ies_dissector_table, e2ap_data->protocol_ie_id, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
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

  return (dissector_try_uint_new(e2ap_proc_imsg_dissector_table, e2ap_data->procedure_code, tvb, pinfo, tree, true, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);

  return (dissector_try_uint_new(e2ap_proc_sout_dissector_table, e2ap_data->procedure_code, tvb, pinfo, tree, true, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);

  return (dissector_try_uint_new(e2ap_proc_uout_dissector_table, e2ap_data->procedure_code, tvb, pinfo, tree, true, data)) ? tvb_captured_length(tvb) : 0;
}


static void set_stats_message_type(packet_info *pinfo, int type)
{
    struct e2ap_private_data* priv_data = e2ap_get_private_data(pinfo);
    priv_data->stats_tap->e2ap_mtype = type;
}

static void
e2ap_stats_tree_init(stats_tree *st)
{
    st_node_packets =      stats_tree_create_node(st, st_str_packets, 0, STAT_DT_INT, true);
    st_node_packet_types = stats_tree_create_pivot(st, st_str_packet_types, st_node_packets);
}

static tap_packet_status
e2ap_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_,
                       epan_dissect_t* edt _U_ , const void* p, tap_flags_t flags _U_)
{
    const struct e2ap_tap_t *pi = (const struct e2ap_tap_t *)p;

    tick_stat_node(st, st_str_packets, 0, false);
    stats_tree_tick_pivot(st, st_node_packet_types,
                          val_to_str(pi->e2ap_mtype, mtype_names,
                                     "Unknown packet type (%d)"));
    return TAP_PACKET_REDRAW;
}


/* Main dissection function */
static int
dissect_e2ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *e2ap_item = NULL;
  proto_tree *e2ap_tree = NULL;

  struct e2ap_tap_t *tap_info;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "E2AP");
  col_clear(pinfo->cinfo, COL_INFO);

  tap_info = wmem_new(pinfo->pool, struct e2ap_tap_t);
  tap_info->e2ap_mtype = 0; /* unknown/invalid */

  /* Add stats tap to private struct */
  struct e2ap_private_data *priv_data = e2ap_get_private_data(pinfo);
  priv_data->stats_tap = tap_info;

  /* Store top-level tree */
  top_tree = e2ap_tree;

  /* create the e2ap protocol tree */
  e2ap_item = proto_tree_add_item(tree, proto_e2ap, tvb, 0, -1, ENC_NA);
  e2ap_tree = proto_item_add_subtree(e2ap_item, ett_e2ap);

  dissect_E2AP_PDU_PDU(tvb, pinfo, e2ap_tree, NULL);

  tap_queue_packet(e2ap_tap, pinfo, tap_info);
  return tvb_captured_length(tvb);
}


static void e2ap_init_protocol(void)
{
  s_gnb_ran_functions_table.num_gnbs = 0;
}


/*--- proto_reg_handoff_e2ap ---------------------------------------*/
void
proto_reg_handoff_e2ap(void)
{
  dissector_add_uint_with_preference("sctp.port", SCTP_PORT_E2AP, e2ap_handle);
  dissector_add_uint("sctp.ppi", E2_CP_PROTOCOL_ID, e2ap_handle);
  dissector_add_uint("sctp.ppi", E2_UP_PROTOCOL_ID, e2ap_handle);
  dissector_add_uint("sctp.ppi", E2_DU_PROTOCOL_ID, e2ap_handle);

#include "packet-e2ap-dis-tab.c"

  /********************************/
  /* Known OIDs for RAN providers */
  /* N.B. These appear in the RAN Function ASN.1 definitions (except for CCC, which is based on JSON).
   * There is a registry of known OIDs though in the E2SM specification
   */

  /* KPM */
  oid_add_from_string("KPM v1",         "1.3.6.1.4.1.53148.1.1.2.2");
  oid_add_from_string("KPM v2",         "1.3.6.1.4.1.53148.1.2.2.2");
  oid_add_from_string("KPM v3",         "1.2.6.1.4.1.53148.1.3.2.2");

  /* RC */
  // TODO: appears to be the same???  Asking for clarification from ORAN..
  oid_add_from_string("RC  v1",         "1.3.6.1.4.1.53148.1.1.2.3");
  //oid_add_from_string("RC  v3",         "1.3.6.1.4.1.53148.1.1.2.3");
  //oid_add_from_string("RC  v4",         "1.3.6.1.4.1.53148.1.1.2.3");

  /* NI */
  oid_add_from_string("NI  v1",         "1.3.6.1.4.1.53148.1.1.2.1");

  /* CCC */
  oid_add_from_string("CCC v1",         "1.3.6.1.4.1.53148.1.1.2.4");
  oid_add_from_string("CCC v2",         "1.3.6.1.4.1.53148.1.2.2.4");
  oid_add_from_string("CCC v3",         "1.3.6.1.4.1.53148.1.3.2.4");
  oid_add_from_string("CCC v4",         "1.3.6.1.4.1.53148.1.4.2.4");
  oid_add_from_string("CCC v5",         "1.3.6.1.4.1.53148.1.5.2.4");


  /********************************/
  /* Register 'built-in' dissectors */

  static ran_function_dissector_t kpm_v3 =
  { "ORAN-E2SM-KPM", "1.2.6.1.4.1.53148.1.3.2.2", 3, 0,
    {  dissect_E2SM_KPM_RANfunction_Description_PDU,

       NULL,
       NULL,
       NULL,
       NULL,
       NULL,
       NULL,

       dissect_E2SM_KPM_ActionDefinition_PDU,
       dissect_E2SM_KPM_IndicationMessage_PDU,
       dissect_E2SM_KPM_IndicationHeader_PDU,
       NULL, /* no dissect_E2SM_KPM_CallProcessID_PDU */
       dissect_E2SM_KPM_EventTriggerDefinition_PDU
     }
  };

  static ran_function_dissector_t rc_v1 =
  { "ORAN-E2SM-RC",  "1.3.6.1.4.1.53148.1.1.2.3", 1, 3,
    {  dissect_E2SM_RC_RANFunctionDefinition_PDU,

       dissect_E2SM_RC_ControlHeader_PDU,
       dissect_E2SM_RC_ControlMessage_PDU,
       dissect_E2SM_RC_ControlOutcome_PDU,
       /* new for v3 */
       NULL,
       NULL,
       NULL,

       dissect_E2SM_RC_ActionDefinition_PDU,
       dissect_E2SM_RC_IndicationMessage_PDU,
       dissect_E2SM_RC_IndicationHeader_PDU,
       dissect_E2SM_RC_CallProcessID_PDU,
       dissect_E2SM_RC_EventTrigger_PDU
    }
  };

  static ran_function_dissector_t ni_v1 =
  { "ORAN-E2SM-NI",  "1.3.6.1.4.1.53148.1.1.2.1", 1, 0,
    {  dissect_E2SM_NI_RANfunction_Description_PDU,

       dissect_E2SM_NI_ControlHeader_PDU,
       dissect_E2SM_NI_ControlMessage_PDU,
       dissect_E2SM_NI_ControlOutcome_PDU,
       NULL,
       NULL,
       NULL,

       dissect_E2SM_NI_ActionDefinition_PDU,
       dissect_E2SM_NI_IndicationMessage_PDU,
       dissect_E2SM_NI_IndicationHeader_PDU,
       dissect_E2SM_NI_CallProcessID_PDU,
       dissect_E2SM_NI_EventTriggerDefinition_PDU
    }
  };

  static ran_function_dissector_t ccc_v1 =
  { "{", /*"ORAN-E2SM-CCC",*/  "1.3.6.1.4.1.53148.1.1.2.4", 1, 0,
    /* See table 5.1 */
    {  dissect_E2SM_NI_JSON_PDU,

       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       NULL,
       NULL,
       NULL,

       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU
    }
  };

  static ran_function_dissector_t ccc_v2 =
  { "{", /*"ORAN-E2SM-CCC",*/  "1.3.6.1.4.1.53148.1.2.2.4", 2, 0,
    /* See table 5.1 */
    {  dissect_E2SM_NI_JSON_PDU,

       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       NULL,
       NULL,
       NULL,

       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU
    }
  };

  static ran_function_dissector_t ccc_v3 =
  { "{", /*"ORAN-E2SM-CCC",*/  "1.3.6.1.4.1.53148.1.3.2.4", 3, 0,
    /* See table 5.1 */
    {  dissect_E2SM_NI_JSON_PDU,

       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       NULL,
       NULL,
       NULL,

       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU
    }
  };

  static ran_function_dissector_t ccc_v4 =
  { "{", /*"ORAN-E2SM-CCC",*/  "1.3.6.1.4.1.53148.1.4.2.4", 4, 0,
    /* See table 5.1 */
    {  dissect_E2SM_NI_JSON_PDU,

       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       NULL,
       NULL,
       NULL,

       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU
    }
  };

  static ran_function_dissector_t ccc_v5 =
  { "{", /*"ORAN-E2SM-CCC",*/  "1.3.6.1.4.1.53148.1.5.2.4", 5, 0,
    /* See table 5.1 */
    {  dissect_E2SM_NI_JSON_PDU,

       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       NULL,
       NULL,
       NULL,

       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU
    }
  };


  /* Register available dissectors.
   * Registering one version of each RAN Function here - others will need to be
   * registered in sepparate dissectors (e.g. kpm_v2) */
  register_e2ap_ran_function_dissector(KPM_RANFUNCTIONS, &kpm_v3);
  register_e2ap_ran_function_dissector(RC_RANFUNCTIONS,  &rc_v1);
  register_e2ap_ran_function_dissector(NI_RANFUNCTIONS,  &ni_v1);

  register_e2ap_ran_function_dissector(CCC_RANFUNCTIONS,  &ccc_v1);
  register_e2ap_ran_function_dissector(CCC_RANFUNCTIONS,  &ccc_v2);
  register_e2ap_ran_function_dissector(CCC_RANFUNCTIONS,  &ccc_v3);
  register_e2ap_ran_function_dissector(CCC_RANFUNCTIONS,  &ccc_v4);
  register_e2ap_ran_function_dissector(CCC_RANFUNCTIONS,  &ccc_v5);


  /* Cache JSON dissector */
  json_handle = find_dissector("json");

  stats_tree_register("e2ap", "e2ap", "E2AP", 0,
                      e2ap_stats_tree_packet, e2ap_stats_tree_init, NULL);

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
            NULL, HFILL }},

      { &hf_e2ap_dissector_version,
          { "Version (dissector)", "e2ap.version.dissector",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
      { &hf_e2ap_frame_version,
          { "Version (frame)", "e2ap.version.frame",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

      { &hf_e2ap_timestamp_string,
          { "Timestamp string", "e2ap.timestamp-string",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_e2ap,
#include "packet-e2ap-ettarr.c"
  };

  static ei_register_info ei[] = {
     { &ei_e2ap_ran_function_names_no_match, { "e2ap.ran-function-names-no-match", PI_PROTOCOL, PI_WARN, "RAN Function name doesn't match known service models", EXPFILL }},
     { &ei_e2ap_ran_function_id_not_mapped,   { "e2ap.ran-function-id-not-known", PI_PROTOCOL, PI_WARN, "Service Model not known for RANFunctionID", EXPFILL }},
     { &ei_e2ap_ran_function_dissector_mismatch,   { "e2ap.ran-function-dissector-version-mismatch", PI_PROTOCOL, PI_WARN, "Available dissector does not match signalled", EXPFILL }},
     { &ei_e2ap_ran_function_max_dissectors_registered,   { "e2ap.ran-function-max-dissectors-registered", PI_PROTOCOL, PI_WARN, "Available dissector does not match signalled", EXPFILL }},

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
  e2ap_n2_ie_type_dissector_table = register_dissector_table("e2ap.n2_ie_type", "E2AP N2 IE Type", proto_e2ap, FT_STRING, STRING_CASE_SENSITIVE);

  register_init_routine(&e2ap_init_protocol);

  e2ap_tap = register_tap("e2ap");
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
