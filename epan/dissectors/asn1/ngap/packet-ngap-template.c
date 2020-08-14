/* packet-ngap.c
 * Routines for NG-RAN NG Application Protocol (NGAP) packet dissection
 * Copyright 2018, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References: 3GPP TS 38.413 v15.6.0 (2019-12)
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
#include <wsutil/wsjson.h>

#include "packet-ngap.h"
#include "packet-per.h"
#include "packet-e212.h"
#include "packet-s1ap.h"
#include "packet-ranap.h"
#include "packet-lte-rrc.h"
#include "packet-nr-rrc.h"
#include "packet-gsm_map.h"
#include "packet-cell_broadcast.h"
#include "packet-ntp.h"
#include "packet-gsm_a_common.h"
#include "packet-http.h"
#include "packet-ngap.h"

#define PNAME  "NG Application Protocol"
#define PSNAME "NGAP"
#define PFNAME "ngap"

/* Dissector will use SCTP PPID 18 or SCTP port. IANA assigned port = 36412 */
#define SCTP_PORT_NGAP 38412

void proto_register_ngap(void);
void proto_reg_handoff_ngap(void);

static dissector_handle_t ngap_handle;
static dissector_handle_t ngap_media_type_handle;
static dissector_handle_t nas_5gs_handle;
static dissector_handle_t nr_rrc_ue_radio_paging_info_handle;
static dissector_handle_t nr_rrc_ue_radio_access_cap_info_handle;
static dissector_handle_t lte_rrc_ue_radio_paging_info_handle;
static dissector_handle_t nrppa_handle;

static int proto_json = -1;

#include "packet-ngap-val.h"

/* Initialize the protocol and registered fields */
static int proto_ngap = -1;
static int hf_ngap_transportLayerAddressIPv4 = -1;
static int hf_ngap_transportLayerAddressIPv6 = -1;
static int hf_ngap_WarningMessageContents_nb_pages = -1;
static int hf_ngap_WarningMessageContents_decoded_page = -1;
static int hf_ngap_NGRANTraceID_TraceID = -1;
static int hf_ngap_NGRANTraceID_TraceRecordingSessionReference = -1;
static int hf_ngap_InterfacesToTrace_NG_C = -1;
static int hf_ngap_InterfacesToTrace_Xn_C = -1;
static int hf_ngap_InterfacesToTrace_Uu = -1;
static int hf_ngap_InterfacesToTrace_F1_C = -1;
static int hf_ngap_InterfacesToTrace_E1 = -1;
static int hf_ngap_InterfacesToTrace_reserved = -1;
static int hf_ngap_RATRestrictionInformation_e_UTRA = -1;
static int hf_ngap_RATRestrictionInformation_nR = -1;
static int hf_ngap_RATRestrictionInformation_reserved = -1;
static int hf_ngap_NrencyptionAlgorithms_nea1 = -1;
static int hf_ngap_NrencyptionAlgorithms_nea2 = -1;
static int hf_ngap_NrencyptionAlgorithms_nea3 = -1;
static int hf_ngap_NrencyptionAlgorithms_reserved = -1;
static int hf_ngap_NrintegrityProtectionAlgorithms_nia1 = -1;
static int hf_ngap_NrintegrityProtectionAlgorithms_nia2 = -1;
static int hf_ngap_NrintegrityProtectionAlgorithms_nia3 = -1;
static int hf_ngap_NrintegrityProtectionAlgorithms_reserved = -1;
static int hf_ngap_EUTRAencryptionAlgorithms_eea1 = -1;
static int hf_ngap_EUTRAencryptionAlgorithms_eea2 = -1;
static int hf_ngap_EUTRAencryptionAlgorithms_eea3 = -1;
static int hf_ngap_EUTRAencryptionAlgorithms_reserved = -1;
static int hf_ngap_EUTRAintegrityProtectionAlgorithms_eia1 = -1;
static int hf_ngap_EUTRAintegrityProtectionAlgorithms_eia2 = -1;
static int hf_ngap_EUTRAintegrityProtectionAlgorithms_eia3 = -1;
static int hf_ngap_EUTRAintegrityProtectionAlgorithms_reserved = -1;
#include "packet-ngap-hf.c"

/* Initialize the subtree pointers */
static gint ett_ngap = -1;
static gint ett_ngap_TransportLayerAddress = -1;
static gint ett_ngap_DataCodingScheme = -1;
static gint ett_ngap_WarningMessageContents = -1;
static gint ett_ngap_PLMNIdentity = -1;
static gint ett_ngap_NGAP_Message = -1;
static gint ett_ngap_NGRANTraceID = -1;
static gint ett_ngap_InterfacesToTrace = -1;
static gint ett_ngap_SourceToTarget_TransparentContainer = -1;
static gint ett_ngap_TargetToSource_TransparentContainer = -1;
static gint ett_ngap_RRCContainer = -1;
static gint ett_ngap_RATRestrictionInformation = -1;
static gint ett_ngap_NrencryptionAlgorithms = -1;
static gint ett_ngap_NrintegrityProtectionAlgorithms = -1;
static gint ett_ngap_EUTRAencryptionAlgorithms = -1;
static gint ett_ngap_EUTRAintegrityProtectionAlgorithms = -1;
static gint ett_ngap_UERadioCapabilityForPagingOfNR = -1;
static gint ett_ngap_UERadioCapabilityForPagingOfEUTRA = -1;
static gint ett_ngap_UERadioCapability = -1;
static gint ett_ngap_LastVisitedEUTRANCellInformation = -1;
static gint ett_ngap_LastVisitedUTRANCellInformation = -1;
static gint ett_ngap_LastVisitedGERANCellInformation = -1;
static gint ett_ngap_NASSecurityParametersFromNGRAN = -1;
static gint ett_ngap_NASC = -1;
static gint ett_ngap_NAS_PDU = -1;
static gint ett_ngap_EN_DCSONConfigurationTransfer = -1;
#include "packet-ngap-ett.c"

static expert_field ei_ngap_number_pages_le15 = EI_INIT;

enum{
  INITIATING_MESSAGE,
  SUCCESSFUL_OUTCOME,
  UNSUCCESSFUL_OUTCOME
};

typedef struct _ngap_ctx_t {
    guint32 message_type;
    guint32 ProcedureCode;
    guint32 ProtocolIE_ID;
    guint32 ProtocolExtensionID;
} ngap_ctx_t;

struct ngap_conv_info {
  address addr_a;
  guint32 port_a;
  GlobalRANNodeID_enum ranmode_id_a;
  address addr_b;
  guint32 port_b;
  GlobalRANNodeID_enum ranmode_id_b;
};

enum {
  SOURCE_TO_TARGET_TRANSPARENT_CONTAINER = 1,
  TARGET_TO_SOURCE_TRANSPARENT_CONTAINER
};

struct ngap_private_data {
  struct ngap_conv_info *ngap_conv;
  guint32 procedure_code;
  guint32 protocol_ie_id;
  guint32 protocol_extension_id;
  guint32 message_type;
  guint32 handover_type_value;
  guint8 data_coding_scheme;
  guint8 transparent_container_type;
};

enum {
  NGAP_NG_RAN_CONTAINER_AUTOMATIC,
  NGAP_NG_RAN_CONTAINER_GNB,
  NGAP_NG_RAN_CONTAINER_NG_ENB
};

static const enum_val_t ngap_target_ng_ran_container_vals[] = {
  {"automatic", "automatic", NGAP_NG_RAN_CONTAINER_AUTOMATIC},
  {"gnb", "gNB", NGAP_NG_RAN_CONTAINER_GNB},
  {"ng-enb","ng-eNB", NGAP_NG_RAN_CONTAINER_NG_ENB},
  {NULL, NULL, -1}
};

/* Global variables */
static guint gbl_ngapSctpPort = SCTP_PORT_NGAP;
static gboolean ngap_dissect_container = TRUE;
static gint ngap_dissect_target_ng_ran_container_as = NGAP_NG_RAN_CONTAINER_AUTOMATIC;

/* Dissector tables */
static dissector_table_t ngap_ies_dissector_table;
static dissector_table_t ngap_ies_p1_dissector_table;
static dissector_table_t ngap_ies_p2_dissector_table;
static dissector_table_t ngap_extension_dissector_table;
static dissector_table_t ngap_proc_imsg_dissector_table;
static dissector_table_t ngap_proc_sout_dissector_table;
static dissector_table_t ngap_proc_uout_dissector_table;
static dissector_table_t ngap_n2_ie_type_dissector_table;

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
static int dissect_PDUSessionResourceReleaseResponseTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_HandoverRequestAcknowledgeTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceModifyUnsuccessfulTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceSetupUnsuccessfulTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_HandoverResourceAllocationUnsuccessfulTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PathSwitchRequestSetupFailedTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_HandoverCommandTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_HandoverRequiredTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceModifyConfirmTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceModifyIndicationTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceModifyRequestTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceModifyResponseTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceNotifyTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceNotifyReleasedTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PathSwitchRequestUnsuccessfulTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceSetupRequestTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceSetupResponseTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PathSwitchRequestAcknowledgeTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PathSwitchRequestTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_HandoverPreparationUnsuccessfulTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceReleaseCommandTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

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

static void
ngap_PacketLossRate_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.1f%% (%u)", (float)v/10, v);
}

static void
ngap_PacketDelayBudget_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.1fms (%u)", (float)v/2, v);
}

static void
ngap_TimeUEStayedInCellEnhancedGranularity_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.1fs", ((float)v)/10);
}

static void
ngap_PeriodicRegistrationUpdateTimer_fmt(gchar *s, guint32 v)
{
  guint32 val = v & 0x1f;

  switch (v>>5) {
    case 0:
      g_snprintf(s, ITEM_LABEL_LENGTH, "%u min (%u)", val * 10, v);
      break;
    case 1:
    default:
      g_snprintf(s, ITEM_LABEL_LENGTH, "%u hr (%u)", val, v);
      break;
    case 2:
      g_snprintf(s, ITEM_LABEL_LENGTH, "%u hr (%u)", val * 10, v);
      break;
    case 3:
      g_snprintf(s, ITEM_LABEL_LENGTH, "%u sec (%u)", val * 2, v);
      break;
    case 4:
      g_snprintf(s, ITEM_LABEL_LENGTH, "%u sec (%u)", val * 30, v);
      break;
    case 5:
      g_snprintf(s, ITEM_LABEL_LENGTH, "%u min (%u)", val, v);
      break;
    case 7:
      g_snprintf(s, ITEM_LABEL_LENGTH, "deactivated (%u)", v);
      break;
  }
}

static struct ngap_private_data*
ngap_get_private_data(packet_info *pinfo)
{
  struct ngap_private_data *ngap_data = (struct ngap_private_data*)p_get_proto_data(pinfo->pool, pinfo, proto_ngap, 0);
  if (!ngap_data) {
    ngap_data = wmem_new0(pinfo->pool, struct ngap_private_data);
    ngap_data->handover_type_value = -1;
    p_add_proto_data(pinfo->pool, pinfo, proto_ngap, 0, ngap_data);
  }
  return ngap_data;
}

static GlobalRANNodeID_enum
ngap_get_ranmode_id(address *addr, guint32 port, packet_info *pinfo)
{
  struct ngap_private_data *ngap_data = ngap_get_private_data(pinfo);
  GlobalRANNodeID_enum ranmode_id = (GlobalRANNodeID_enum)-1;

  if (ngap_data->ngap_conv) {
    if (addresses_equal(addr, &ngap_data->ngap_conv->addr_a) && port == ngap_data->ngap_conv->port_a) {
      ranmode_id = ngap_data->ngap_conv->ranmode_id_a;
    } else if (addresses_equal(addr, &ngap_data->ngap_conv->addr_b) && port == ngap_data->ngap_conv->port_b) {
      ranmode_id = ngap_data->ngap_conv->ranmode_id_b;
    }
  }
  return ranmode_id;
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
  struct ngap_private_data *ngap_data;
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
    ngap_data->ngap_conv = wmem_new0(wmem_file_scope(), struct ngap_conv_info);
    copy_address_wmem(wmem_file_scope(), &ngap_data->ngap_conv->addr_a, &pinfo->src);
    ngap_data->ngap_conv->port_a = pinfo->srcport;
    ngap_data->ngap_conv->ranmode_id_a = (GlobalRANNodeID_enum)-1;
    copy_address_wmem(wmem_file_scope(), &ngap_data->ngap_conv->addr_b, &pinfo->dst);
    ngap_data->ngap_conv->port_b = pinfo->destport;
    ngap_data->ngap_conv->ranmode_id_b = (GlobalRANNodeID_enum)-1;
    conversation_add_proto_data(conversation, proto_ngap, ngap_data->ngap_conv);
  }

  return dissect_NGAP_PDU_PDU(tvb, pinfo, ngap_tree, NULL);
}

/* 3GPP TS 29.502 chapter 6.1.6.4.3 and 29.518 chapter 6.1.6.4.3 */
static int
dissect_ngap_media_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  int ret;
  char *json_data;
  const char *n2_info_class, *str, *content_id_str;
  jsmntok_t *tokens, *cur_tok, *n2_info_content_tok;
  dissector_handle_t subdissector;
  tvbuff_t* json_tvb = (tvbuff_t*)p_get_proto_data(pinfo->pool, pinfo, proto_json, 0);
  http_message_info_t *message_info = (http_message_info_t *)data;

  if (!json_tvb || !message_info || !message_info->content_id)
    return 0;

  json_data = tvb_get_string_enc(wmem_packet_scope(), json_tvb, 0, tvb_reported_length(json_tvb), ENC_UTF_8|ENC_NA);
  ret = json_parse(json_data, NULL, 0);
  if (ret <= 0)
    return 0;
  tokens = wmem_alloc_array(wmem_packet_scope(), jsmntok_t, ret);
  if (json_parse(json_data, tokens, ret) <= 0)
    return 0;
  cur_tok = json_get_object(json_data, tokens, "n2InfoContainer");
  if (!cur_tok) {
      /* look for n2Information too*/
      cur_tok = json_get_object(json_data, tokens, "n2Information");
  }
  if (cur_tok) {
    n2_info_class = json_get_string(json_data, cur_tok, "n2InformationClass");
    if (!n2_info_class)
      return 0;
    if (!strcmp(n2_info_class, "SM")) {
      cur_tok = json_get_object(json_data, cur_tok, "smInfo");
      if (!cur_tok)
        return 0;
      n2_info_content_tok = json_get_object(json_data, cur_tok, "n2InfoContent");
      if (!n2_info_content_tok)
        return 0;
      str = json_get_string(json_data, n2_info_content_tok, "ngapIeType");
      if (!str)
        return 0;
      subdissector = dissector_get_string_handle(ngap_n2_ie_type_dissector_table, str);
    } else if (!strcmp(n2_info_class, "RAN")) {
      cur_tok = json_get_object(json_data, cur_tok, "ranInfo");
      if (!cur_tok)
        return 0;
      n2_info_content_tok = json_get_object(json_data, cur_tok, "n2InfoContent");
      if (!n2_info_content_tok)
        return 0;
      str = json_get_string(json_data, n2_info_content_tok, "ngapIeType");
      if (!str)
        return 0;
      subdissector = dissector_get_string_handle(ngap_n2_ie_type_dissector_table, str);
    } else if (!strcmp(n2_info_class, "NRPPa")) {
      cur_tok = json_get_object(json_data, cur_tok, "nrppaInfo");
      if (!cur_tok)
        return 0;
      n2_info_content_tok = json_get_object(json_data, cur_tok, "nrppaPdu");
      if (!n2_info_content_tok)
        return 0;
      str = json_get_string(json_data, n2_info_content_tok, "ngapIeType");
      if (!str)
        return 0;
      subdissector = dissector_get_string_handle(ngap_n2_ie_type_dissector_table, str);
    } else if (!strcmp(n2_info_class, "PWS") ||
               !strcmp(n2_info_class, "PWS-BCAL") ||
               !strcmp(n2_info_class, "PWS-RF")) {
      cur_tok = json_get_object(json_data, cur_tok, "pwsInfo");
      if (!cur_tok)
        return 0;
      n2_info_content_tok = json_get_object(json_data, cur_tok, "pwsContainer");
      if (!n2_info_content_tok)
        return 0;
      subdissector = ngap_handle;
    } else {
      return 0;
    }
    cur_tok = json_get_object(json_data, n2_info_content_tok, "ngapData");
    if (!cur_tok)
      return 0;
    content_id_str = json_get_string(json_data, cur_tok, "contentId");
  } else {
    cur_tok = json_get_object(json_data, tokens, "n2SmInfo");
    if (cur_tok) {
      content_id_str = json_get_string(json_data, cur_tok, "contentId");
      str = json_get_string(json_data, tokens, "n2SmInfoType");
      if (!str)
        return 0;
      subdissector = dissector_get_string_handle(ngap_n2_ie_type_dissector_table, str);
    } else {
      return 0;
    }
  }

  if (subdissector) {
    proto_item *ngap_item;
    proto_tree *ngap_tree;

    if (!content_id_str || strcmp(content_id_str, message_info->content_id))
      return 0;
    col_append_sep_str(pinfo->cinfo, COL_PROTOCOL, "/", "NGAP");
    ngap_item = proto_tree_add_item(tree, proto_ngap, tvb, 0, -1, ENC_NA);
    ngap_tree = proto_item_add_subtree(ngap_item, ett_ngap);
    gboolean save_writable = col_get_writable(pinfo->cinfo, COL_PROTOCOL);
    col_set_writable(pinfo->cinfo, COL_PROTOCOL, FALSE);
    call_dissector_with_data(subdissector, tvb, pinfo, ngap_tree, NULL);
    col_set_writable(pinfo->cinfo, COL_PROTOCOL, save_writable);
    return tvb_captured_length(tvb);
  } else {
    return 0;
  }
}

/*--- proto_reg_handoff_ngap ---------------------------------------*/
void
proto_reg_handoff_ngap(void)
{
  static gboolean Initialized=FALSE;
  static guint SctpPort;

  if (!Initialized) {
    nas_5gs_handle = find_dissector_add_dependency("nas-5gs", proto_ngap);
    nr_rrc_ue_radio_paging_info_handle = find_dissector_add_dependency("nr-rrc.ue_radio_paging_info", proto_ngap);
    nr_rrc_ue_radio_access_cap_info_handle = find_dissector_add_dependency("nr-rrc.ue_radio_access_cap_info", proto_ngap);
    lte_rrc_ue_radio_paging_info_handle = find_dissector_add_dependency("lte-rrc.ue_radio_paging_info", proto_ngap);
    dissector_add_for_decode_as("sctp.port", ngap_handle);
    dissector_add_uint("sctp.ppi", NGAP_PROTOCOL_ID,   ngap_handle);
    Initialized=TRUE;
#include "packet-ngap-dis-tab.c"

    dissector_add_string("media_type", "application/vnd.3gpp.ngap", ngap_media_type_handle);
  } else {
    if (SctpPort != 0) {
      dissector_delete_uint("sctp.port", SctpPort, ngap_handle);
    }
  }

  nrppa_handle = find_dissector_add_dependency("nrppa", proto_ngap);
  proto_json = proto_get_id_by_filter_name("json");

  SctpPort=gbl_ngapSctpPort;
  if (SctpPort != 0) {
    dissector_add_uint("sctp.port", SctpPort, ngap_handle);
  }
}

/*--- proto_register_ngap -------------------------------------------*/
void proto_register_ngap(void) {

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_ngap_transportLayerAddressIPv4,
      { "TransportLayerAddress (IPv4)", "ngap.TransportLayerAddressIPv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_transportLayerAddressIPv6,
      { "TransportLayerAddress (IPv6)", "ngap.TransportLayerAddressIPv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_WarningMessageContents_nb_pages,
      { "Number of Pages", "ngap.WarningMessageContents.nb_pages",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_WarningMessageContents_decoded_page,
      { "Decoded Page", "ngap.WarningMessageContents.decoded_page",
        FT_STRING, STR_UNICODE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_NGRANTraceID_TraceID,
      { "TraceID", "ngap.NGRANTraceID.TraceID",
        FT_UINT24, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_NGRANTraceID_TraceRecordingSessionReference,
      { "TraceRecordingSessionReference", "ngap.NGRANTraceID.TraceRecordingSessionReference",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_InterfacesToTrace_NG_C,
      { "NG-C", "ngap.InterfacesToTrace.NG_C",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ngap_InterfacesToTrace_Xn_C,
      { "Xn-C", "ngap.InterfacesToTrace.Xn_C",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ngap_InterfacesToTrace_Uu,
      { "Uu", "ngap.InterfacesToTrace.Uu",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ngap_InterfacesToTrace_F1_C,
      { "F1-C", "ngap.InterfacesToTrace.F1_C",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ngap_InterfacesToTrace_E1,
      { "E1", "ngap.InterfacesToTrace.E1",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_ngap_InterfacesToTrace_reserved,
      { "Reserved", "ngap.InterfacesToTrace.reserved",
        FT_UINT8, BASE_HEX, NULL, 0x07,
        NULL, HFILL }},
    { &hf_ngap_RATRestrictionInformation_e_UTRA,
      { "e-UTRA", "ngap.RATRestrictionInformation.e_UTRA",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x80,
        NULL, HFILL }},
    { &hf_ngap_RATRestrictionInformation_nR,
      { "nR", "ngap.RATRestrictionInformation.nR",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x40,
        NULL, HFILL }},
    { &hf_ngap_RATRestrictionInformation_reserved,
      { "reserved", "ngap.RATRestrictionInformation.reserved",
        FT_UINT8, BASE_HEX, NULL, 0x3f,
        NULL, HFILL }},
    { &hf_ngap_NrencyptionAlgorithms_nea1,
      { "128-NEA1", "ngap.NrencyptionAlgorithms.nea1",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000,
        NULL, HFILL }},
    { &hf_ngap_NrencyptionAlgorithms_nea2,
      { "128-NEA2", "ngap.NrencyptionAlgorithms.nea2",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x4000,
        NULL, HFILL }},
    { &hf_ngap_NrencyptionAlgorithms_nea3,
      { "128-NEA3", "ngap.NrencyptionAlgorithms.nea3",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x2000,
        NULL, HFILL }},
    { &hf_ngap_NrencyptionAlgorithms_reserved,
      { "Reserved", "ngap.NrencyptionAlgorithms.reserved",
        FT_UINT16, BASE_HEX, NULL, 0x1fff,
        NULL, HFILL }},
    { &hf_ngap_NrintegrityProtectionAlgorithms_nia1,
      { "128-NIA1", "ngap.NrintegrityProtectionAlgorithms.nia1",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000,
        NULL, HFILL }},
    { &hf_ngap_NrintegrityProtectionAlgorithms_nia2,
      { "128-NIA2", "ngap.NrintegrityProtectionAlgorithms.nia2",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x4000,
        NULL, HFILL }},
    { &hf_ngap_NrintegrityProtectionAlgorithms_nia3,
      { "128-NIA3", "ngap.NrintegrityProtectionAlgorithms.nia3",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x2000,
        NULL, HFILL }},
    { &hf_ngap_NrintegrityProtectionAlgorithms_reserved,
      { "Reserved", "ngap.NrintegrityProtectionAlgorithms.reserved",
        FT_UINT16, BASE_HEX, NULL, 0x1fff,
        NULL, HFILL }},
    { &hf_ngap_EUTRAencryptionAlgorithms_eea1,
      { "128-EEA1", "ngap.EUTRAencryptionAlgorithms.eea1",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000,
        NULL, HFILL }},
    { &hf_ngap_EUTRAencryptionAlgorithms_eea2,
      { "128-EEA2", "ngap.EUTRAencryptionAlgorithms.eea2",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x4000,
        NULL, HFILL }},
    { &hf_ngap_EUTRAencryptionAlgorithms_eea3,
      { "128-EEA3", "ngap.EUTRAencryptionAlgorithms.eea3",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x2000,
        NULL, HFILL }},
    { &hf_ngap_EUTRAencryptionAlgorithms_reserved,
      { "Reserved", "ngap.EUTRAencryptionAlgorithms.reserved",
        FT_UINT16, BASE_HEX, NULL, 0x1fff,
        NULL, HFILL }},
    { &hf_ngap_EUTRAintegrityProtectionAlgorithms_eia1,
      { "128-EIA1", "ngap.EUTRAintegrityProtectionAlgorithms.eia1",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000,
        NULL, HFILL }},
    { &hf_ngap_EUTRAintegrityProtectionAlgorithms_eia2,
      { "128-EIA2", "ngap.EUTRAintegrityProtectionAlgorithms.eia2",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x4000,
        NULL, HFILL }},
    { &hf_ngap_EUTRAintegrityProtectionAlgorithms_eia3,
      { "128-EIA3", "ngap.EUTRAintegrityProtectionAlgorithms.eia3",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x2000,
        NULL, HFILL }},
    { &hf_ngap_EUTRAintegrityProtectionAlgorithms_reserved,
      { "Reserved", "ngap.EUTRAintegrityProtectionAlgorithms.reserved",
        FT_UINT16, BASE_HEX, NULL, 0x1fff,
        NULL, HFILL }},
#include "packet-ngap-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_ngap,
    &ett_ngap_TransportLayerAddress,
    &ett_ngap_DataCodingScheme,
    &ett_ngap_WarningMessageContents,
    &ett_ngap_PLMNIdentity,
    &ett_ngap_NGAP_Message,
    &ett_ngap_NGRANTraceID,
    &ett_ngap_InterfacesToTrace,
    &ett_ngap_SourceToTarget_TransparentContainer,
    &ett_ngap_TargetToSource_TransparentContainer,
    &ett_ngap_RRCContainer,
    &ett_ngap_RATRestrictionInformation,
    &ett_ngap_NrencryptionAlgorithms,
    &ett_ngap_NrintegrityProtectionAlgorithms,
    &ett_ngap_EUTRAencryptionAlgorithms,
    &ett_ngap_EUTRAintegrityProtectionAlgorithms,
    &ett_ngap_UERadioCapabilityForPagingOfNR,
    &ett_ngap_UERadioCapabilityForPagingOfEUTRA,
    &ett_ngap_UERadioCapability,
    &ett_ngap_LastVisitedEUTRANCellInformation,
    &ett_ngap_LastVisitedUTRANCellInformation,
    &ett_ngap_LastVisitedGERANCellInformation,
    &ett_ngap_NASSecurityParametersFromNGRAN,
    &ett_ngap_NASC,
    &ett_ngap_NAS_PDU,
    &ett_ngap_EN_DCSONConfigurationTransfer,
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
  ngap_media_type_handle = register_dissector("ngap_media_type", dissect_ngap_media_type, proto_ngap);

  /* Register dissector tables */
  ngap_ies_dissector_table = register_dissector_table("ngap.ies", "NGAP-PROTOCOL-IES", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_ies_p1_dissector_table = register_dissector_table("ngap.ies.pair.first", "NGAP-PROTOCOL-IES-PAIR FirstValue", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_ies_p2_dissector_table = register_dissector_table("ngap.ies.pair.second", "NGAP-PROTOCOL-IES-PAIR SecondValue", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_extension_dissector_table = register_dissector_table("ngap.extension", "NGAP-PROTOCOL-EXTENSION", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_proc_imsg_dissector_table = register_dissector_table("ngap.proc.imsg", "NGAP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_proc_sout_dissector_table = register_dissector_table("ngap.proc.sout", "NGAP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_proc_uout_dissector_table = register_dissector_table("ngap.proc.uout", "NGAP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_n2_ie_type_dissector_table = register_dissector_table("ngap.n2_ie_type", "NGAP N2 IE Type", proto_ngap, FT_STRING, FALSE);

  /* Register configuration options for ports */
  ngap_module = prefs_register_protocol(proto_ngap, proto_reg_handoff_ngap);

  prefs_register_uint_preference(ngap_module, "sctp.port",
                                 "NGAP SCTP Port",
                                 "Set the SCTP port for NGAP messages",
                                 10,
                                 &gbl_ngapSctpPort);
  prefs_register_bool_preference(ngap_module, "dissect_container",
                                 "Dissect TransparentContainer",
                                 "Dissect TransparentContainers that are opaque to NGAP",
                                 &ngap_dissect_container);
  prefs_register_enum_preference(ngap_module, "dissect_target_ng_ran_container_as",
                                 "Dissect target NG-RAN container as",
                                 "Select whether target NG-RAN container should be decoded automatically"
                                 " (based on NG Setup procedure) or manually",
                                 &ngap_dissect_target_ng_ran_container_as, ngap_target_ng_ran_container_vals, FALSE);
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
