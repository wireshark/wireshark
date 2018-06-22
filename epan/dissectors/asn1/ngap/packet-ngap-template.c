/* packet-ngap.c
 * Routines for E-UTRAN NG Application Protocol (NGAP) packet dissection
 * Copyright 2018, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References: 3GPP TS 38.413
 */

#include "config.h"

#include <epan/packet.h>

#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/sctpppids.h>
#include <epan/expert.h>
#include <epan/conversation.h>
#include <epan/proto_data.h>

#include "packet-ngap.h"
#include "packet-ber.h"
#include "packet-per.h"
#include "packet-e212.h"
#include "packet-sccp.h"
#include "packet-lte-rrc.h"
#include "packet-ranap.h"
#include "packet-bssgp.h"
#include "packet-a21.h"
#include "packet-gsm_map.h"
#include "packet-cell_broadcast.h"
#include "packet-gsm_a_common.h"

#define PNAME  "NG Application Protocol"
#define PSNAME "NGAP"
#define PFNAME "ngap"

/* Dissector will use SCTP PPID 18 or SCTP port. IANA assigned port = 36412 */
#define SCTP_PORT_NGAP 38412

void proto_register_ngap(void);
void proto_reg_handoff_ngap(void);

static dissector_handle_t nas_5gs_handle;

#include "packet-ngap-val.h"

/* Initialize the protocol and registered fields */
static int proto_ngap = -1;

static int hf_ngap_WarningMessageContents_nb_pages = -1;
static int hf_ngap_WarningMessageContents_decoded_page = -1;
#include "packet-ngap-hf.c"

/* Initialize the subtree pointers */
static gint ett_ngap = -1;
static gint ett_ngap_DataCodingScheme = -1;
static gint ett_ngap_WarningMessageContents = -1;
#include "packet-ngap-ett.c"

static expert_field ei_ngap_number_pages_le15 = EI_INIT;

enum{
  INITIATING_MESSAGE,
  SUCCESSFUL_OUTCOME,
  UNSUCCESSFUL_OUTCOME
};

struct ngap_conv_info {
  wmem_map_t *nbiot_ta;
  wmem_tree_t *nbiot_gnb_ue_ngap_id;
};

typedef struct _ngap_ctx_t {
    guint32 message_type;
    guint32 ProcedureCode;
    guint32 ProtocolIE_ID;
    guint32 ProtocolExtensionID;
} ngap_ctx_t;

struct ngap_private_data {
  struct ngap_conv_info *ngap_conv;
  guint32 procedure_code;
  guint32 protocol_ie_id;
  guint32 protocol_extension_id;
  guint32 message_type;
  guint32 handover_type_value;
  guint8 data_coding_scheme;
};

/* Global variables */
static guint gbl_ngapSctpPort=SCTP_PORT_NGAP;

static dissector_handle_t gcsna_handle = NULL;
static dissector_handle_t ngap_handle;

/* Dissector tables */
static dissector_table_t ngap_ies_dissector_table;
static dissector_table_t ngap_ies_p1_dissector_table;
static dissector_table_t ngap_ies_p2_dissector_table;
static dissector_table_t ngap_extension_dissector_table;
static dissector_table_t ngap_proc_imsg_dissector_table;
static dissector_table_t ngap_proc_sout_dissector_table;
static dissector_table_t ngap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
/* Currently not used
static int dissect_ProtocolIEFieldPairFirstValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_ProtocolIEFieldPairSecondValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
*/
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

static int dissect_InitialUEMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data);
#if 0
static int dissect_SourceRNC_ToTargetRNC_TransparentContainer_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_TargetRNC_ToSourceRNC_TransparentContainer_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_SourceBSS_ToTargetBSS_TransparentContainer_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_TargetBSS_ToSourceBSS_TransparentContainer_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
#endif


const value_string ngap_serialNumber_gs_vals[] = {
  { 0, "Display mode iamfdiate, cell wide"},
  { 1, "Display mode normal, PLMN wide"},
  { 2, "Display mode normal, tracking area wide"},
  { 3, "Display mode normal, cell wide"},
  { 0, NULL},
};

const value_string ngap_warningType_vals[] = {
  { 0, "Earthquake"},
  { 1, "Tsunami"},
  { 2, "Earthquake and Tsunami"},
  { 3, "Test"},
  { 4, "Other"},
  { 0, NULL},
};

static void
dissect_ngap_warningMessageContents(tvbuff_t *warning_msg_tvb, proto_tree *tree, packet_info *pinfo, guint8 dcs, int hf_nb_pages, int hf_decoded_page)
{
  guint32 offset;
  guint8 nb_of_pages, length, *str;
  proto_item *ti;
  tvbuff_t *cb_data_page_tvb, *cb_data_tvb;
  int i;

  nb_of_pages = tvb_get_guint8(warning_msg_tvb, 0);
  ti = proto_tree_add_uint(tree, hf_nb_pages, warning_msg_tvb, 0, 1, nb_of_pages);
  if (nb_of_pages > 15) {
    expert_add_info_format(pinfo, ti, &ei_ngap_number_pages_le15,
                           "Number of pages should be <=15 (found %u)", nb_of_pages);
    nb_of_pages = 15;
  }
  for (i = 0, offset = 1; i < nb_of_pages; i++) {
    length = tvb_get_guint8(warning_msg_tvb, offset+82);
    cb_data_page_tvb = tvb_new_subset_length(warning_msg_tvb, offset, length);
    cb_data_tvb = dissect_cbs_data(dcs, cb_data_page_tvb, tree, pinfo, 0);
    if (cb_data_tvb) {
      str = tvb_get_string_enc(wmem_packet_scope(), cb_data_tvb, 0, tvb_reported_length(cb_data_tvb), ENC_UTF_8|ENC_NA);
      proto_tree_add_string_format(tree, hf_decoded_page, warning_msg_tvb, offset, 83,
                                   str, "Decoded Page %u: %s", i+1, str);
    }
    offset += 83;
  }
}


static struct ngap_private_data*
ngap_get_private_data(packet_info *pinfo)
{
  struct ngap_private_data *ngap_data = (struct ngap_private_data*)p_get_proto_data(pinfo->pool, pinfo, proto_ngap, 0);
  if (!ngap_data) {
    ngap_data = wmem_new0(pinfo->pool, struct ngap_private_data);
    p_add_proto_data(pinfo->pool, pinfo, proto_ngap, 0, ngap_data);
  }
  return ngap_data;
}


#include "packet-ngap-fn.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  ngap_ctx_t ngap_ctx;
  struct ngap_private_data *ngap_data = ngap_get_private_data(pinfo);

  ngap_ctx.message_type        = ngap_data->message_type;
  ngap_ctx.ProcedureCode       = ngap_data->procedure_code;
  ngap_ctx.ProtocolIE_ID       = ngap_data->protocol_ie_id;
  ngap_ctx.ProtocolExtensionID = ngap_data->protocol_extension_id;

  return (dissector_try_uint_new(ngap_ies_dissector_table, ngap_data->protocol_ie_id, tvb, pinfo, tree, FALSE, &ngap_ctx)) ? tvb_captured_length(tvb) : 0;
}
/* Currently not used
static int dissect_ProtocolIEFieldPairFirstValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  struct ngap_private_data *ngap_data = ngap_get_private_data(pinfo);

  return (dissector_try_uint(ngap_ies_p1_dissector_table, ngap_data->protocol_ie_id, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolIEFieldPairSecondValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  struct ngap_private_data *ngap_data = ngap_get_private_data(pinfo);

  return (dissector_try_uint(ngap_ies_p2_dissector_table, ngap_data->protocol_ie_id, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}
*/

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  ngap_ctx_t ngap_ctx;
  struct ngap_private_data *ngap_data = ngap_get_private_data(pinfo);

  ngap_ctx.message_type        = ngap_data->message_type;
  ngap_ctx.ProcedureCode       = ngap_data->procedure_code;
  ngap_ctx.ProtocolIE_ID       = ngap_data->protocol_ie_id;
  ngap_ctx.ProtocolExtensionID = ngap_data->protocol_extension_id;

  return (dissector_try_uint_new(ngap_extension_dissector_table, ngap_data->protocol_extension_id, tvb, pinfo, tree, TRUE, &ngap_ctx)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct ngap_private_data *ngap_data = ngap_get_private_data(pinfo);

  return (dissector_try_uint_new(ngap_proc_imsg_dissector_table, ngap_data->procedure_code, tvb, pinfo, tree, TRUE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct ngap_private_data *ngap_data = ngap_get_private_data(pinfo);

  return (dissector_try_uint_new(ngap_proc_sout_dissector_table, ngap_data->procedure_code, tvb, pinfo, tree, TRUE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct ngap_private_data *ngap_data = ngap_get_private_data(pinfo);

  return (dissector_try_uint_new(ngap_proc_uout_dissector_table, ngap_data->procedure_code, tvb, pinfo, tree, TRUE, data)) ? tvb_captured_length(tvb) : 0;
}


static int
dissect_ngap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ngap_item = NULL;
  proto_tree *ngap_tree = NULL;
  conversation_t *conversation;
  struct ngap_private_data* ngap_data;
  wmem_list_frame_t *prev_layer;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "NGAP");
  /* ensure that parent dissector is not NGAP before clearing fence */
  prev_layer = wmem_list_frame_prev(wmem_list_tail(pinfo->layers));
  if (prev_layer && GPOINTER_TO_INT(wmem_list_frame_data(prev_layer)) != proto_ngap)
    col_clear_fence(pinfo->cinfo, COL_INFO);
  col_clear(pinfo->cinfo, COL_INFO);

  /* create the ngap protocol tree */
  ngap_item = proto_tree_add_item(tree, proto_ngap, tvb, 0, -1, ENC_NA);
  ngap_tree = proto_item_add_subtree(ngap_item, ett_ngap);

  ngap_data = ngap_get_private_data(pinfo);
  conversation = find_or_create_conversation(pinfo);
  ngap_data->ngap_conv = (struct ngap_conv_info *)conversation_get_proto_data(conversation, proto_ngap);
  if (!ngap_data->ngap_conv) {
    ngap_data->ngap_conv = wmem_new(wmem_file_scope(), struct ngap_conv_info);
    ngap_data->ngap_conv->nbiot_ta = wmem_map_new(wmem_file_scope(), wmem_int64_hash, g_int64_equal);
    ngap_data->ngap_conv->nbiot_gnb_ue_ngap_id = wmem_tree_new(wmem_file_scope());
    conversation_add_proto_data(conversation, proto_ngap, ngap_data->ngap_conv);
  }

  dissect_NGAP_PDU_PDU(tvb, pinfo, ngap_tree, NULL);
  return tvb_captured_length(tvb);
}

/*--- proto_reg_handoff_ngap ---------------------------------------*/
void
proto_reg_handoff_ngap(void)
{
  static gboolean Initialized=FALSE;
  static guint SctpPort;

  gcsna_handle = find_dissector_add_dependency("gcsna", proto_ngap);

  if (!Initialized) {
    nas_5gs_handle = find_dissector_add_dependency("nas-5gs", proto_ngap);
    dissector_add_for_decode_as("sctp.port", ngap_handle);
    dissector_add_uint("sctp.ppi", NGAP_PROTOCOL_ID,   ngap_handle);
    Initialized=TRUE;
#include "packet-ngap-dis-tab.c"
  } else {
    if (SctpPort != 0) {
      dissector_delete_uint("sctp.port", SctpPort, ngap_handle);
    }
  }

  SctpPort=gbl_ngapSctpPort;
  if (SctpPort != 0) {
    dissector_add_uint("sctp.port", SctpPort, ngap_handle);
  }
}

/*--- proto_register_ngap -------------------------------------------*/
void proto_register_ngap(void) {

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_ngap_WarningMessageContents_nb_pages,
      { "Number of Pages", "ngap.WarningMessageContents.nb_pages",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_WarningMessageContents_decoded_page,
      { "Decoded Page", "ngap.WarningMessageContents.decoded_page",
        FT_STRING, STR_UNICODE, NULL, 0,
        NULL, HFILL }},
#include "packet-ngap-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_ngap,
    &ett_ngap_DataCodingScheme,
    &ett_ngap_WarningMessageContents,
#include "packet-ngap-ettarr.c"
  };

  static ei_register_info ei[] = {
    { &ei_ngap_number_pages_le15, { "ngap.number_pages_le15", PI_MALFORMED, PI_ERROR, "Number of pages should be <=15", EXPFILL }}
  };

  module_t *ngap_module;
  expert_module_t* expert_ngap;

  /* Register protocol */
  proto_ngap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_ngap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_ngap = expert_register_protocol(proto_ngap);
  expert_register_field_array(expert_ngap, ei, array_length(ei));

  /* Register dissector */
  ngap_handle = register_dissector("ngap", dissect_ngap, proto_ngap);

  /* Register dissector tables */
  ngap_ies_dissector_table = register_dissector_table("ngap.ies", "NGAP-PROTOCOL-IES", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_ies_p1_dissector_table = register_dissector_table("ngap.ies.pair.first", "NGAP-PROTOCOL-IES-PAIR FirstValue", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_ies_p2_dissector_table = register_dissector_table("ngap.ies.pair.second", "NGAP-PROTOCOL-IES-PAIR SecondValue", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_extension_dissector_table = register_dissector_table("ngap.extension", "NGAP-PROTOCOL-EXTENSION", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_proc_imsg_dissector_table = register_dissector_table("ngap.proc.imsg", "NGAP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_proc_sout_dissector_table = register_dissector_table("ngap.proc.sout", "NGAP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_proc_uout_dissector_table = register_dissector_table("ngap.proc.uout", "NGAP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_ngap, FT_UINT32, BASE_DEC);

  /* Register configuration options for ports */
  ngap_module = prefs_register_protocol(proto_ngap, proto_reg_handoff_ngap);

  prefs_register_uint_preference(ngap_module, "sctp.port",
                                 "NGAP SCTP Port",
                                 "Set the SCTP port for NGAP messages",
                                 10,
                                 &gbl_ngapSctpPort);
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
