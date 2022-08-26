/* packet-nbap-template.c
 * Routines for UMTS Node B Application Part(NBAP) packet dissection
 * Copyright 2005, 2009 Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref: 3GPP TS 25.433 version 6.6.0 Release 6
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/sctpppids.h>
#include <epan/asn1.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/uat.h>

#include "packet-per.h"
#include "packet-isup.h"
#include "packet-umts_fp.h"
#include "packet-umts_mac.h"
#include "packet-rrc.h"
#include "packet-umts_rlc.h"
#include "packet-nbap.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "UTRAN Iub interface NBAP signalling"
#define PSNAME "NBAP"
#define PFNAME "nbap"


#define NBAP_IGNORE_PORT 255

/* Debug */
#define DEBUG_NBAP 0
#if DEBUG_NBAP
#include <epan/to_str.h>
#define nbap_debug(...) ws_warning(__VA_ARGS__)
#else
#define nbap_debug(...)
#endif

void proto_register_nbap(void);
void proto_reg_handoff_nbap(void);

/* Protocol Handles */
static dissector_handle_t fp_handle;

#include "packet-nbap-val.h"

/* Initialize the protocol and registered fields */
static int proto_nbap = -1;
static int hf_nbap_transportLayerAddress_ipv4 = -1;
static int hf_nbap_transportLayerAddress_ipv6 = -1;
static int hf_nbap_transportLayerAddress_nsap = -1;
static int hf_nbap_reassembled_information_block = -1;

#include "packet-nbap-hf.c"

/* Initialize the subtree pointers */
static int ett_nbap = -1;
static int ett_nbap_TransportLayerAddress = -1;
static int ett_nbap_TransportLayerAddress_nsap = -1;
static int ett_nbap_ib_sg_data = -1;

#include "packet-nbap-ett.c"

static expert_field ei_nbap_no_find_port_info = EI_INIT;
static expert_field ei_nbap_no_set_comm_context_id = EI_INIT;
static expert_field ei_nbap_hsdsch_entity_not_specified = EI_INIT;

extern int proto_fp;

static dissector_handle_t nbap_handle;

/*
 * Structure to hold Setup Request/Response message conversation
 * we add all src add/port declared in SetupRequest msg
 * to match it with dst add/port declared in SetupResponse msg
 * so we gonna have conversation with exact match (src and dst addr and port)
 */
typedef struct nbap_setup_conv
{
  guint32 transaction_id;
  guint32 dd_mode;
  guint32 channel_id;
  guint32 request_frame_number;
  address addr;
  guint32 port;
  umts_fp_conversation_info_t *umts_fp_conversation_info;
  conversation_t *conv;
}nbap_setup_conv_t;

/*
 * Hash table to manage Setup Request/Response message conversation
 * we can look in table for proper conversation
 */
static wmem_map_t *nbap_setup_conv_table;

typedef struct
{
  gint num_dch_in_flow;
  gint next_dch;
  gint num_ul_chans;
  gint ul_chan_tf_size[MAX_FP_CHANS];
  gint ul_chan_num_tbs[MAX_FP_CHANS];
  gint num_dl_chans;
  gint dl_chan_tf_size[MAX_FP_CHANS];
  gint dl_chan_num_tbs[MAX_FP_CHANS];
}nbap_dch_channel_info_t;

/* Struct to collect E-DCH data in a packet
 * As the address data comes before the ddi entries
 * we save the address to be able to find the conversation and update the
 * conversation data.
 */
typedef struct
{
  address crnc_address;
  guint16 crnc_port;
  gint no_ddi_entries;
  guint8 edch_ddi[MAX_EDCH_DDIS];
  guint edch_macd_pdu_size[MAX_EDCH_DDIS];
  guint8 edch_type;  /* 1 means T2 */
  guint8 lchId[MAX_EDCH_DDIS]; /*Logical channel ids.*/
} nbap_edch_channel_info_t;


typedef struct
{
  guint32 crnc_address;
  guint16 crnc_port[maxNrOfEDCHMACdFlows];
} nbap_edch_port_info_t;

typedef struct
{
  address crnc_address;
  guint16 crnc_port;
  enum fp_rlc_mode rlc_mode;
  guint32 hsdsch_physical_layer_category;
  guint8 entity;  /* "ns" means type 1 and "ehs" means type 2, type 3 == ?*/
} nbap_hsdsch_channel_info_t;

typedef struct
{
 address crnc_address;
 guint16 crnc_port;
 enum fp_rlc_mode rlc_mode;
} nbap_common_channel_info_t;

/*Stuff for mapping NodeB-Comuncation Context ID to CRNC Communication Context ID*/
typedef struct com_ctxt_{
  /*guint   nodeb_context;*/
  guint crnc_context;
  guint frame_num;
}nbap_com_context_id_t;

enum TransportFormatSet_type_enum
{
  NBAP_DCH_UL,
  NBAP_DCH_DL,
  NBAP_CPCH,
  NBAP_FACH,
  NBAP_PCH
};

#define NBAP_MAX_IB_SEGMENT_LENGTH 222

typedef struct nbap_ib_segment_t {
  guint32 bit_length;
  guint8* data;
} nbap_ib_segment_t;

static nbap_ib_segment_t* nbap_parse_ib_sg_data_var1(packet_info *pinfo, tvbuff_t *tvb,gboolean is_short)
{
  guint8 bit_length;
  guint8* data;
  nbap_ib_segment_t* output;
  if ( tvb_captured_length(tvb) < 2 ) {
    return NULL;
  }
  if (is_short) {
    bit_length = tvb_get_guint8(tvb,0) + 1;
    data = (guint8*)tvb_memdup(pinfo->pool,tvb,1,(bit_length+7)/8);
  }
  else {
    bit_length = NBAP_MAX_IB_SEGMENT_LENGTH;
    data = (guint8*)tvb_memdup(pinfo->pool,tvb,0,(bit_length+7)/8);
  }
  output = wmem_new(pinfo->pool, nbap_ib_segment_t);
  output->bit_length = bit_length;
  output->data = data;
  return output;
}

/*****************************************************************************/
/* Packet private data                                                       */
/* For this dissector, all information passed between different ASN.1 nodes  */
/* should be done only through this API!                                     */
/*****************************************************************************/


typedef struct nbap_private_data_t
{
  guint32 transportLayerAddress_ipv4;
  guint16 binding_id_port;
  enum TransportFormatSet_type_enum transport_format_set_type;
  guint32 procedure_code;
  guint num_items;
  guint32 ul_scrambling_code;
  guint32 com_context_id;
  gint num_dch_in_flow;
  gint hrnti;
  guint32 protocol_ie_id;
  guint32 dd_mode;
  guint32 transaction_id;
  guint32 t_dch_id;
  guint32 dch_id;
  guint32 prev_dch_id;
  guint32 common_physical_channel_id;
  guint32 e_dch_macdflow_id;
  guint32 hsdsch_macdflow_id;
  gboolean max_mac_d_pdu_size_ext_ie_present;
  guint32 e_dch_ddi_value;
  guint32 logical_channel_id;
  guint32 common_macdflow_id;
  guint32 mac_d_pdu_size;
  guint32 common_transport_channel_id;
  gint paging_indications;
  guint32 ib_type;
  guint32 segment_type;
  gboolean crnc_context_present; /* Whether 'com_context_id' is set */
  guint8 dch_crc_present;
  /* Arrays */
  nbap_dch_channel_info_t nbap_dch_chnl_info[256];
  nbap_edch_channel_info_t nbap_edch_channel_info[maxNrOfEDCHMACdFlows];
  gint hsdsch_macdflow_ids[maxNrOfMACdFlows];
  nbap_hsdsch_channel_info_t nbap_hsdsch_channel_info[maxNrOfMACdFlows];
  nbap_common_channel_info_t nbap_common_channel_info[maxNrOfMACdFlows];	/*TODO: Fix this!*/
  wmem_list_t* ib_segments; /* Information block segments */
} nbap_private_data_t;


/* Helper function to get or create a private_data struct */
static nbap_private_data_t* nbap_get_private_data(packet_info *pinfo)
{
  guint8 i;
  /* NOTE: Unlike other ASN.1 dissectors which store information in
  * actx->private_data the NBAP dissector can't do so because some fields
  * are defined as their own 'PDU' (Like BindingID and TransportLayerAddress)
  * in those cases, the generic ASN.1 dissector creates a NEW 'ASN.1 context'
  * (asn1_ctx_t) and hence a new 'private data' field for them so information
  * can't be passes to/from them.
  */
  nbap_private_data_t *private_data = (nbap_private_data_t *)p_get_proto_data(pinfo->pool, pinfo, proto_nbap, 0);
  if(private_data == NULL ) {
    private_data = wmem_new0(pinfo->pool, nbap_private_data_t);
    p_add_proto_data(pinfo->pool, pinfo, proto_nbap, 0, private_data);
    /* Setting  default values */
    private_data->hsdsch_macdflow_id = 3;
    private_data->crnc_context_present = FALSE;
    private_data->procedure_code = 0xFFFF;
    private_data->dd_mode = 0xFFFF;
    private_data->dch_crc_present = 2; /* Unknown */
    for (i = 0; i < maxNrOfMACdFlows; i++) {
        private_data->nbap_hsdsch_channel_info[i].entity = hs;
    }
  }
  return private_data;
}

/* Helper function to reset the private data struct*/
static void nbap_reset_private_data(packet_info *pinfo)
{
  p_remove_proto_data(pinfo->pool, pinfo, proto_nbap, 0);
}

/*****************************************************************************/


/* Global Variables */

/* Variables for sub elements dissection */
static  const gchar *ProcedureID;
/* Trees */
static wmem_tree_t* edch_flow_port_map = NULL;
wmem_tree_t *nbap_scrambling_code_crncc_map = NULL;
wmem_tree_t *nbap_crncc_urnti_map = NULL;
static wmem_tree_t* com_context_map;

/* This table is used externally from FP, MAC and such, TODO: merge this with
 * lch_contents[] */
guint8 lchId_type_table[]= {
  MAC_CONTENT_UNKNOWN,  /* Shouldn't happen*/
  MAC_CONTENT_DCCH,  /* 1 to 4 SRB => DCCH*/
  MAC_CONTENT_DCCH,
  MAC_CONTENT_DCCH,
  MAC_CONTENT_DCCH,
  MAC_CONTENT_CS_DTCH,  /* 5 to 7 Conv CS speech => ?*/
  MAC_CONTENT_CS_DTCH,
  MAC_CONTENT_CS_DTCH,
  MAC_CONTENT_DCCH, /* 8 SRB => DCCH*/
  MAC_CONTENT_PS_DTCH,  /* 9 maps to DTCH*/
  MAC_CONTENT_UNKNOWN,  /* 10 Conv CS unknown*/
  MAC_CONTENT_PS_DTCH,  /* 11 Interactive PS => DTCH*/
  MAC_CONTENT_PS_DTCH,  /* 12 Streaming PS => DTCH*/
  MAC_CONTENT_CS_DTCH,  /* 13 Streaming CS*/
  MAC_CONTENT_PS_DTCH,  /* 14 Interactive PS => DTCH*/
  MAC_CONTENT_CCCH  /* This is CCCH? */
};

/* Mapping logicalchannel id to RLC_MODE */
guint8 lchId_rlc_map[] = {
  0,
  RLC_UM, /* Logical channel id = 1 is SRB1 which uses RLC_UM*/
  RLC_AM,
  RLC_AM,
  RLC_AM,
  RLC_TM, /*5 to 7 Conv CS Speech*/
  RLC_TM,
  RLC_TM, /*...*/
  RLC_AM,
  RLC_AM,
  RLC_AM,
  RLC_AM,
  RLC_AM,
  RLC_AM,
  RLC_AM,
  RLC_AM, /* This is CCCH which is UM?, probably not */
};

/* Preference variables */
/* Array with preference variables for easy looping, TODO: merge this with
 * lchId_type_table[] */
static int lch_contents[16] = {
  MAC_CONTENT_DCCH,
  MAC_CONTENT_DCCH,
  MAC_CONTENT_DCCH,
  MAC_CONTENT_DCCH,
  MAC_CONTENT_CS_DTCH,
  MAC_CONTENT_CS_DTCH,
  MAC_CONTENT_CS_DTCH,
  MAC_CONTENT_DCCH,
  MAC_CONTENT_PS_DTCH,
  MAC_CONTENT_UNKNOWN,
  MAC_CONTENT_PS_DTCH,
  MAC_CONTENT_PS_DTCH,
  MAC_CONTENT_CS_DTCH,
  MAC_CONTENT_PS_DTCH,
  MAC_CONTENT_CCCH,
  MAC_CONTENT_DCCH
};

static const enum_val_t content_types[] = {
  {"MAC_CONTENT_UNKNOWN", "MAC_CONTENT_UNKNOWN", MAC_CONTENT_UNKNOWN},
  {"MAC_CONTENT_DCCH", "MAC_CONTENT_DCCH", MAC_CONTENT_DCCH},
  {"MAC_CONTENT_PS_DTCH", "MAC_CONTENT_PS_DTCH", MAC_CONTENT_PS_DTCH},
  {"MAC_CONTENT_CS_DTCH", "MAC_CONTENT_CS_DTCH", MAC_CONTENT_CS_DTCH},
  {"MAC_CONTENT_CCCH", "MAC_CONTENT_CCCH", MAC_CONTENT_CCCH},
  {NULL, NULL, -1}};

typedef struct {
  const char *name;
  const char *title;
  const char *description;
} preference_strings;

/* This is used when registering preferences, name, title, description */
static const preference_strings ch_strings[] = {
  {"lch1_content", "Logical Channel 1 Content", "foo"},
  {"lch2_content", "Logical Channel 2 Content", "foo"},
  {"lch3_content", "Logical Channel 3 Content", "foo"},
  {"lch4_content", "Logical Channel 4 Content", "foo"},
  {"lch5_content", "Logical Channel 5 Content", "foo"},
  {"lch6_content", "Logical Channel 6 Content", "foo"},
  {"lch7_content", "Logical Channel 7 Content", "foo"},
  {"lch8_content", "Logical Channel 8 Content", "foo"},
  {"lch9_content", "Logical Channel 9 Content", "foo"},
  {"lch10_content", "Logical Channel 10 Content", "foo"},
  {"lch11_content", "Logical Channel 11 Content", "foo"},
  {"lch12_content", "Logical Channel 12 Content", "foo"},
  {"lch13_content", "Logical Channel 13 Content", "foo"},
  {"lch14_content", "Logical Channel 14 Content", "foo"},
  {"lch15_content", "Logical Channel 15 Content", "foo"},
  {"lch16_content", "Logical Channel 16 Content", "foo"}};

enum ib_sg_enc_type {
  IB_SG_DATA_ENC_VAR_1,
  IB_SG_DATA_ENC_VAR_2
};

static const enum_val_t ib_sg_enc_vals[] = {
  {"Encoding Variant 1 (TS 25.433 Annex D.2)",
   "Encoding Variant 1 (TS 25.433 Annex D.2)", IB_SG_DATA_ENC_VAR_1},
  {"Encoding Variant 2 (TS 25.433 Annex D.3)",
   "Encoding Variant 2 (TS 25.433 Annex D.3)", IB_SG_DATA_ENC_VAR_2},
  {NULL, NULL, -1}
};

static gint preferences_ib_sg_data_encoding = IB_SG_DATA_ENC_VAR_1;

/* Dissector tables */
static dissector_table_t nbap_ies_dissector_table;
static dissector_table_t nbap_extension_dissector_table;
static dissector_table_t nbap_proc_imsg_dissector_table;
static dissector_table_t nbap_proc_sout_dissector_table;
static dissector_table_t nbap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

static guint32 calculate_setup_conv_key(const guint32 transaction_id, const guint32 dd_mode, const guint32 channel_id);
static void add_setup_conv(const packet_info *pinfo _U_, const guint32 transaction_id, const guint32 dd_mode, const guint32 channel_id, const guint32 req_frame_number,
           const address *addr, const guint32 port, umts_fp_conversation_info_t * umts_fp_conversation_info, conversation_t *conv);
static nbap_setup_conv_t* find_setup_conv(const packet_info *pinfo _U_, const guint32 transaction_id, const guint32 dd_mode, const guint32 channel_id);
static void delete_setup_conv(nbap_setup_conv_t *conv);

/*Easy way to add hsdhsch binds for corner cases*/
static void add_hsdsch_bind(packet_info * pinfo);

#include "packet-nbap-fn.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  guint32 protocol_ie_id;
  protocol_ie_id = nbap_get_private_data(pinfo)->protocol_ie_id;
  return (dissector_try_uint_new(nbap_ies_dissector_table, protocol_ie_id, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  guint32 protocol_ie_id;
  protocol_ie_id = nbap_get_private_data(pinfo)->protocol_ie_id;
  return (dissector_try_uint_new(nbap_extension_dissector_table, protocol_ie_id, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  if (!ProcedureID) return 0;
  return (dissector_try_string(nbap_proc_imsg_dissector_table, ProcedureID, tvb, pinfo, tree, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  if (!ProcedureID) return 0;
  return (dissector_try_string(nbap_proc_sout_dissector_table, ProcedureID, tvb, pinfo, tree, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  if (!ProcedureID) return 0;
  return (dissector_try_string(nbap_proc_uout_dissector_table, ProcedureID, tvb, pinfo, tree, NULL)) ? tvb_captured_length(tvb) : 0;
}
static void add_hsdsch_bind(packet_info *pinfo){
  address null_addr;
  conversation_t *conversation = NULL;
  umts_fp_conversation_info_t *umts_fp_conversation_info;
  fp_hsdsch_channel_info_t* fp_hsdsch_channel_info = NULL;
  guint32 i;
  nbap_hsdsch_channel_info_t* nbap_hsdsch_channel_info;

  if (PINFO_FD_VISITED(pinfo)){
    return;
  }

  nbap_hsdsch_channel_info = nbap_get_private_data(pinfo)->nbap_hsdsch_channel_info;
  /* Set port to zero use that as an indication of whether we have data or not */
  clear_address(&null_addr);
  for (i = 0; i < maxNrOfMACdFlows; i++) {
    if (nbap_hsdsch_channel_info[i].crnc_port != 0){
      conversation = find_conversation(pinfo->num, &(nbap_hsdsch_channel_info[i].crnc_address), &null_addr, CONVERSATION_UDP,
                                      nbap_hsdsch_channel_info[i].crnc_port, 0, NO_ADDR_B);

      if (conversation == NULL) {
        /* It's not part of any conversation - create a new one. */
        conversation = conversation_new(pinfo->num, &(nbap_hsdsch_channel_info[i].crnc_address), &null_addr, CONVERSATION_UDP,
                                       nbap_hsdsch_channel_info[i].crnc_port, 0, NO_ADDR2|NO_PORT2);

        /* Set dissector */
        conversation_set_dissector(conversation, fp_handle);

        if(pinfo->link_dir==P2P_DIR_DL){
          umts_fp_conversation_info = wmem_new0(wmem_file_scope(), umts_fp_conversation_info_t);
          /* Fill in the HSDSCH relevant data */
          umts_fp_conversation_info->iface_type        = IuB_Interface;
          umts_fp_conversation_info->division          = Division_FDD;
          umts_fp_conversation_info->channel           = CHANNEL_HSDSCH;
          umts_fp_conversation_info->dl_frame_number   = 0;
          umts_fp_conversation_info->ul_frame_number   = pinfo->num;
          copy_address_wmem(wmem_file_scope(), &(umts_fp_conversation_info->crnc_address), &nbap_hsdsch_channel_info[i].crnc_address);
          umts_fp_conversation_info->crnc_port         = nbap_hsdsch_channel_info[i].crnc_port;

          fp_hsdsch_channel_info = wmem_new0(wmem_file_scope(), fp_hsdsch_channel_info_t);
          umts_fp_conversation_info->channel_specific_info = (void*)fp_hsdsch_channel_info;
          /*Added june 3, normally just the iterator variable*/
          fp_hsdsch_channel_info->hsdsch_macdflow_id = i ; /*hsdsch_macdflow_ids[i];*/ /* hsdsch_macdflow_id;*/

          /* Cheat and use the DCH entries */
          umts_fp_conversation_info->num_dch_in_flow++;
          umts_fp_conversation_info->dch_ids_in_flow_list[umts_fp_conversation_info->num_dch_in_flow -1] = i;

          if(nbap_hsdsch_channel_info[i].entity == entity_not_specified ){
            /*Error*/
            expert_add_info(pinfo, NULL, &ei_nbap_hsdsch_entity_not_specified);
          }else{
            fp_hsdsch_channel_info->hsdsch_entity = (enum fp_hsdsch_entity)nbap_hsdsch_channel_info[i].entity;
          }
          umts_fp_conversation_info->rlc_mode = nbap_hsdsch_channel_info[i].rlc_mode;
          set_umts_fp_conv_data(conversation, umts_fp_conversation_info);
        }
      }
    }
  }
}

/*
 * Function used to manage conversation declared in Setup Request/Response message
 */
static guint32 calculate_setup_conv_key(const guint32 transaction_id, const guint32 dd_mode, const guint32 channel_id)
{
  /* We need to pack 3 values on 32 bits:
   * 31-16 transaction_id
   * 15-14 dd_mode
   * 13-0  channel_id
   */
  guint32 key;
  key = transaction_id << 16;
  key |= (dd_mode & 0x03) << 14;
  key |= (channel_id & 0x3fff);
  nbap_debug("\tCalculating key 0x%04x", key);
  return key;
}

static void add_setup_conv(const packet_info *pinfo _U_, const guint32 transaction_id, const guint32 dd_mode, const guint32 channel_id, const guint32 req_frame_number,
              const address *addr, const guint32 port, umts_fp_conversation_info_t * umts_fp_conversation_info, conversation_t *conv)
{
  nbap_setup_conv_t *new_conv = NULL;
  guint32 key;

  nbap_debug("Creating new setup conv\t TransactionID: %u\tddMode: %u\tChannelID: %u\t %s:%u",
  transaction_id, dd_mode, channel_id, address_to_str(pinfo->pool, addr), port);

  new_conv = wmem_new0(wmem_file_scope(), nbap_setup_conv_t);

  /* fill with data */
  new_conv->transaction_id = transaction_id;
  new_conv->dd_mode = dd_mode;
  new_conv->channel_id = channel_id;
  new_conv->request_frame_number = req_frame_number;
  copy_address_wmem(wmem_file_scope(), &new_conv->addr, addr);
  new_conv->port = port;
  new_conv->umts_fp_conversation_info = umts_fp_conversation_info;
  new_conv->conv = conv;

  key = calculate_setup_conv_key(new_conv->transaction_id, new_conv->dd_mode, new_conv->channel_id);

  wmem_map_insert(nbap_setup_conv_table, GUINT_TO_POINTER(key), new_conv);
}

static nbap_setup_conv_t* find_setup_conv(const packet_info *pinfo _U_, const guint32 transaction_id, const guint32 dd_mode, const guint32 channel_id)
{
  nbap_setup_conv_t *conv;
  guint32 key;
  nbap_debug("Looking for Setup Conversation match\t TransactionID: %u\t ddMode: %u\t ChannelID: %u", transaction_id, dd_mode, channel_id);

  key = calculate_setup_conv_key(transaction_id, dd_mode, channel_id);

  conv = (nbap_setup_conv_t*) wmem_map_lookup(nbap_setup_conv_table, GUINT_TO_POINTER(key));

  if(conv == NULL){
    nbap_debug("\tDidn't find Setup Conversation match");
  }else{
    nbap_debug("\tFOUND Setup Conversation match\t TransactionID: %u\t ddMode: %u\t ChannelID: %u\t %s:%u",
         conv->transaction_id, conv->dd_mode, conv->channel_id, address_to_str(pinfo->pool, &(conv->addr)), conv->port);
  }

  return conv;
}

static void delete_setup_conv(nbap_setup_conv_t *conv)
{
  guint32 key;

  /* check if conversation exist */
  if(conv == NULL){
    nbap_debug("Trying delete Setup Conversation that does not exist (ptr == NULL)\t");
    return;
  }
  key = calculate_setup_conv_key(conv->transaction_id, conv->dd_mode, conv->channel_id);
  wmem_map_remove(nbap_setup_conv_table, GUINT_TO_POINTER(key));
}

static void nbap_init(void){
  guint8 i;
  /*Initialize*/
  com_context_map = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

  /*Initialize structure for muxed flow indication*/
  edch_flow_port_map = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

  /*Initialize Setup Conversation hash table*/
  nbap_setup_conv_table = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
  /*Initializing Scrambling Code to C-RNC Context & C-RNC Context to U-RNTI maps*/
  nbap_scrambling_code_crncc_map = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
  nbap_crncc_urnti_map = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

  for (i = 0; i < 15; i++) {
    lchId_type_table[i+1] = lch_contents[i];
  }
}

static int
dissect_nbap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  proto_item *nbap_item = NULL;
  proto_tree *nbap_tree = NULL;
  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "NBAP");

  /* create the nbap protocol tree */
  nbap_item = proto_tree_add_item(tree, proto_nbap, tvb, 0, -1, ENC_NA);
  nbap_tree = proto_item_add_subtree(nbap_item, ett_nbap);

  /* Clearing any old 'private data' stored */
  nbap_reset_private_data(pinfo);

  return dissect_NBAP_PDU_PDU(tvb, pinfo, nbap_tree, data);
}

/* Highest ProcedureCode value, used in heuristics */
#define NBAP_MAX_PC 56 /* id-secondaryULFrequencyUpdate = 56*/
#define NBAP_MSG_MIN_LENGTH 7
static gboolean
dissect_nbap_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  guint8 pdu_type;
  guint8 procedure_id;
  guint8 dd_mode;
  guint8 criticality;
  guint8 transaction_id_type;
  guint length;
  int length_field_offset;

  #define PDU_TYPE_OFFSET 0
  #define PROC_CODE_OFFSET 1
  #define DD_CRIT_OFFSET 2
  if (tvb_captured_length(tvb) < NBAP_MSG_MIN_LENGTH) {
    return FALSE;
  }

  pdu_type = tvb_get_guint8(tvb, PDU_TYPE_OFFSET);
  if (pdu_type & 0x1f) {
    /* pdu_type is not 0x00 (initiatingMessage), 0x20 (succesfulOutcome),
       0x40 (unsuccesfulOutcome) or 0x60 (outcome), ignore extension bit (0x80) */
    return FALSE;
  }

  procedure_id = tvb_get_guint8(tvb, PROC_CODE_OFFSET);
  if (procedure_id > NBAP_MAX_PC) {
      return FALSE;
  }

  dd_mode = tvb_get_guint8(tvb, DD_CRIT_OFFSET) >> 5;
  if (dd_mode >= 0x03) {
    /* dd_mode is not 0x00 (tdd), 0x01 (fdd) or 0x02 (common) */
    return FALSE;
  }

  criticality = (tvb_get_guint8(tvb, DD_CRIT_OFFSET) & 0x18) >> 3;
  if (criticality == 0x03) {
    /* criticality is not 0x00 (reject), 0x01 (ignore) or 0x02 (notify) */
    return FALSE;
  }

  /* Finding the offset for the length field - depends on wether the transaction id is long or short */
  transaction_id_type = (tvb_get_guint8(tvb, DD_CRIT_OFFSET) & 0x02) >> 1;
  if(transaction_id_type == 0x00) { /* Short transaction id - 1 byte*/
    length_field_offset = 4;
  }
  else { /* Long transaction id - 2 bytes*/
    length_field_offset = 5;
  }

  /* compute aligned PER length determinant without calling dissect_per_length_determinant()
     to avoid exceptions and info added to tree, info column and expert info */
  length = tvb_get_guint8(tvb, length_field_offset);
  length_field_offset += 1;
  if (length & 0x80) {
    if ((length & 0xc0) == 0x80) {
      length &= 0x3f;
      length <<= 8;
      length += tvb_get_guint8(tvb, length_field_offset);
      length_field_offset += 1;
    } else {
      length = 0;
    }
  }
  if (length!= (tvb_reported_length(tvb) - length_field_offset)){
    return FALSE;
  }

  dissect_nbap(tvb, pinfo, tree, data);

  return TRUE;
}

/*--- proto_register_nbap -------------------------------------------*/
void proto_register_nbap(void)
{
  module_t *nbap_module;
  guint8 i;

  /* List of fields */
  static hf_register_info hf[] = {
  { &hf_nbap_transportLayerAddress_ipv4,
    { "transportLayerAddress IPv4", "nbap.transportLayerAddress_ipv4",
    FT_IPv4, BASE_NONE, NULL, 0,
  NULL, HFILL }},
  { &hf_nbap_transportLayerAddress_ipv6,
    { "transportLayerAddress IPv6", "nbap.transportLayerAddress_ipv6",
    FT_IPv6, BASE_NONE, NULL, 0,
    NULL, HFILL }},
  { &hf_nbap_transportLayerAddress_nsap,
    { "transportLayerAddress NSAP", "nbap.transportLayerAddress_NSAP",
    FT_BYTES, BASE_NONE, NULL, 0,
    NULL, HFILL }},
  { &hf_nbap_reassembled_information_block,
    { "Reassembled Information Block", "nbap.reassembled_information_block",
    FT_BYTES, BASE_NONE, NULL, 0,
    NULL, HFILL }},
  #include "packet-nbap-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_nbap,
    &ett_nbap_TransportLayerAddress,
    &ett_nbap_TransportLayerAddress_nsap,
    &ett_nbap_ib_sg_data,
    #include "packet-nbap-ettarr.c"
  };

  static ei_register_info ei[] = {
    { &ei_nbap_no_set_comm_context_id, { "nbap.no_set_comm_context_id", PI_MALFORMED, PI_WARN, "Couldn't not set Communication Context-ID, fragments over reconfigured channels might fail", EXPFILL }},
    { &ei_nbap_no_find_port_info, { "nbap.no_find_port_info", PI_MALFORMED, PI_WARN, "Couldn't not find port information for reconfigured E-DCH flow, unable to reconfigure", EXPFILL }},
    { &ei_nbap_hsdsch_entity_not_specified, { "nbap.hsdsch_entity_not_specified", PI_MALFORMED,PI_ERROR, "HSDSCH Entity not specified!", EXPFILL }},
  };

  expert_module_t* expert_nbap;

  /* Register protocol */
  proto_nbap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_nbap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_nbap = expert_register_protocol(proto_nbap);
  expert_register_field_array(expert_nbap, ei, array_length(ei));

  /* Register dissector */
  nbap_handle = register_dissector("nbap", dissect_nbap, proto_nbap);

  nbap_module = prefs_register_protocol(proto_nbap, NULL);

  /* Register preferences for mapping logical channel IDs to MAC content types. */
  for (i = 0; i < 16; i++) {
    prefs_register_enum_preference(nbap_module, ch_strings[i].name, ch_strings[i].title, ch_strings[i].description, &lch_contents[i], content_types, FALSE);
  }
  prefs_register_enum_preference(nbap_module, "ib_sg_data_encoding",
    "IB_SG_DATA encoding",
    "Encoding used for the IB-SG-DATA element carrying segments of information blocks",
    &preferences_ib_sg_data_encoding, ib_sg_enc_vals, FALSE);

  /* Register dissector tables */
  nbap_ies_dissector_table = register_dissector_table("nbap.ies", "NBAP-PROTOCOL-IES", proto_nbap, FT_UINT32, BASE_DEC);
  nbap_extension_dissector_table = register_dissector_table("nbap.extension", "NBAP-PROTOCOL-EXTENSION", proto_nbap, FT_UINT32, BASE_DEC);
  nbap_proc_imsg_dissector_table = register_dissector_table("nbap.proc.imsg", "NBAP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_nbap, FT_STRING, BASE_NONE);
  nbap_proc_sout_dissector_table = register_dissector_table("nbap.proc.sout", "NBAP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_nbap, FT_STRING, BASE_NONE);
  nbap_proc_uout_dissector_table = register_dissector_table("nbap.proc.uout", "NBAP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_nbap, FT_STRING, BASE_NONE);

  register_init_routine(nbap_init);
}

/*
 * #define	EXTRA_PPI 1
 */
/*--- proto_reg_handoff_nbap ---------------------------------------*/
void
proto_reg_handoff_nbap(void)
{
  fp_handle = find_dissector("fp");
  dissector_add_uint("sctp.ppi", NBAP_PAYLOAD_PROTOCOL_ID, nbap_handle);
#ifdef EXTRA_PPI
  dissector_add_uint("sctp.ppi", 17, nbap_handle);
#endif
  dissector_add_for_decode_as("sctp.port", nbap_handle);
  heur_dissector_add("sctp", dissect_nbap_heur, "NBAP over SCTP", "nbap_sctp", proto_nbap, HEURISTIC_ENABLE);

#include "packet-nbap-dis-tab.c"
}

