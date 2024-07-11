/* packet-e1ap.c
 * Routines for E-UTRAN E1 Application Protocol (E1AP) packet dissection
 * Copyright 2018-2024, Pascal Quantin <pascal@wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References: 3GPP TS 37.483 V18.2.0 (2024-06)
 */

#include "config.h"

#include <epan/packet.h>

#include <epan/asn1.h>
#include <epan/sctpppids.h>
#include <epan/proto_data.h>

#include "packet-e1ap.h"
#include "packet-per.h"
#include "packet-e212.h"
#include "packet-ntp.h"
#include "packet-nr-rrc.h"
#include "packet-tcp.h"

#define PNAME  "E1 Application Protocol"
#define PSNAME "E1AP"
#define PFNAME "e1ap"

#define SCTP_PORT_E1AP 38462

void proto_register_e1ap(void);
void proto_reg_handoff_e1ap(void);

#include "packet-e1ap-val.h"

/* Initialize the protocol and registered fields */
static int proto_e1ap;

static int hf_e1ap_transportLayerAddressIPv4;
static int hf_e1ap_transportLayerAddressIPv6;
static int hf_e1ap_InterfacesToTrace_NG_C;
static int hf_e1ap_InterfacesToTrace_Xn_C;
static int hf_e1ap_InterfacesToTrace_Uu;
static int hf_e1ap_InterfacesToTrace_F1_C;
static int hf_e1ap_InterfacesToTrace_E1;
static int hf_e1ap_InterfacesToTrace_Reserved;
static int hf_e1ap_MeasurementsToActivate_Reserved1;
static int hf_e1ap_MeasurementsToActivate_M4;
static int hf_e1ap_MeasurementsToActivate_Reserved2;
static int hf_e1ap_MeasurementsToActivate_M6;
static int hf_e1ap_MeasurementsToActivate_M7;
static int hf_e1ap_ReportCharacteristics_TNLAvailableCapacityIndPeriodic;
static int hf_e1ap_ReportCharacteristics_HWCapacityIndPeriodic;
static int hf_e1ap_ReportCharacteristics_Reserved;
static int hf_e1ap_tcp_pdu_len;
#include "packet-e1ap-hf.c"

/* Initialize the subtree pointers */
static int ett_e1ap;
static int ett_e1ap_PLMN_Identity;
static int ett_e1ap_TransportLayerAddress;
static int ett_e1ap_InterfacesToTrace;
static int ett_e1ap_MeasurementsToActivate;
static int ett_e1ap_ReportCharacteristics;
static int ett_e1ap_BurstArrivalTime;
#include "packet-e1ap-ett.c"

enum{
  INITIATING_MESSAGE,
  SUCCESSFUL_OUTCOME,
  UNSUCCESSFUL_OUTCOME
};

typedef struct {
  uint32_t message_type;
  uint32_t procedure_code;
  uint32_t protocol_ie_id;
  const char *obj_id;
  e212_number_type_t number_type;
} e1ap_private_data_t;

/* Global variables */
static dissector_handle_t e1ap_handle;
static dissector_handle_t e1ap_tcp_handle;

/* Dissector tables */
static dissector_table_t e1ap_ies_dissector_table;
static dissector_table_t e1ap_extension_dissector_table;
static dissector_table_t e1ap_proc_imsg_dissector_table;
static dissector_table_t e1ap_proc_sout_dissector_table;
static dissector_table_t e1ap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

static void
e1ap_MaxPacketLossRate_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1f%% (%u)", (float)v/10, v);
}

static void
e1ap_PacketDelayBudget_uL_D1_Result_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fms (%u)", (float)v/2, v);
}

static void
e1ap_ExtendedPacketDelayBudget_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.2fms (%u)", (float)v/100, v);
}

static void
e1ap_N6Jitter_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fms (%d)", (float)v/2, (int32_t)v);
}

static e1ap_private_data_t*
e1ap_get_private_data(packet_info *pinfo)
{
  e1ap_private_data_t *e1ap_data = (e1ap_private_data_t*)p_get_proto_data(pinfo->pool, pinfo, proto_e1ap, 0);
  if (!e1ap_data) {
    e1ap_data = wmem_new0(pinfo->pool, e1ap_private_data_t);
    p_add_proto_data(pinfo->pool, pinfo, proto_e1ap, 0, e1ap_data);
  }
  return e1ap_data;
}

#include "packet-e1ap-fn.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  e1ap_ctx_t e1ap_ctx;
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(pinfo);

  e1ap_ctx.message_type        = e1ap_data->message_type;
  e1ap_ctx.ProcedureCode       = e1ap_data->procedure_code;
  e1ap_ctx.ProtocolIE_ID       = e1ap_data->protocol_ie_id;

  return (dissector_try_uint_new(e1ap_ies_dissector_table, e1ap_data->protocol_ie_id, tvb, pinfo, tree, false, &e1ap_ctx)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  e1ap_ctx_t e1ap_ctx;
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(pinfo);

  e1ap_ctx.message_type        = e1ap_data->message_type;
  e1ap_ctx.ProcedureCode       = e1ap_data->procedure_code;
  e1ap_ctx.ProtocolIE_ID       = e1ap_data->protocol_ie_id;

  return (dissector_try_uint_new(e1ap_extension_dissector_table, e1ap_data->protocol_ie_id, tvb, pinfo, tree, false, &e1ap_ctx)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(e1ap_proc_imsg_dissector_table, e1ap_data->procedure_code, tvb, pinfo, tree, false, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(e1ap_proc_sout_dissector_table, e1ap_data->procedure_code, tvb, pinfo, tree, false, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(e1ap_proc_uout_dissector_table, e1ap_data->procedure_code, tvb, pinfo, tree, false, data)) ? tvb_captured_length(tvb) : 0;
}


static int
dissect_e1ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *e1ap_item = NULL;
  proto_tree *e1ap_tree = NULL;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "E1AP");
  col_clear(pinfo->cinfo, COL_INFO);

  /* create the e1ap protocol tree */
  e1ap_item = proto_tree_add_item(tree, proto_e1ap, tvb, 0, -1, ENC_NA);
  e1ap_tree = proto_item_add_subtree(e1ap_item, ett_e1ap);

  dissect_E1AP_PDU_PDU(tvb, pinfo, e1ap_tree, NULL);
  return tvb_captured_length(tvb);
}

static unsigned
get_e1ap_tcp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                     int offset, void *data _U_)
{
  return tvb_get_ntohl(tvb, offset)+4;
}

static int
dissect_e1ap_tcp_pdu(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
  tvbuff_t *new_tvb;

  proto_tree_add_item(tree, hf_e1ap_tcp_pdu_len, tvb, 0, 4, ENC_NA);
  new_tvb = tvb_new_subset_remaining(tvb, 4);

  return dissect_e1ap(new_tvb, pinfo, tree, data);
}

static int
dissect_e1ap_tcp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
  tcp_dissect_pdus(tvb, pinfo, tree, true, 4,
                   get_e1ap_tcp_pdu_len, dissect_e1ap_tcp_pdu, data);
  return tvb_captured_length(tvb);
}

void proto_register_e1ap(void) {

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_e1ap_transportLayerAddressIPv4,
      { "IPv4 transportLayerAddress", "e1ap.transportLayerAddressIPv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_transportLayerAddressIPv6,
      { "IPv6 transportLayerAddress", "e1ap.transportLayerAddressIPv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_InterfacesToTrace_NG_C,
      { "NG-C", "e1ap.InterfacesToTrace.NG_C",
        FT_BOOLEAN, 8, TFS(&tfs_should_be_traced_should_not_be_traced), 0x80,
        NULL, HFILL }},
    { &hf_e1ap_InterfacesToTrace_Xn_C,
      { "Xn-C", "e1ap.InterfacesToTrace.Xn_C",
        FT_BOOLEAN, 8, TFS(&tfs_should_be_traced_should_not_be_traced), 0x40,
        NULL, HFILL }},
    { &hf_e1ap_InterfacesToTrace_Uu,
      { "Uu", "e1ap.InterfacesToTrace.Uu",
        FT_BOOLEAN, 8, TFS(&tfs_should_be_traced_should_not_be_traced), 0x20,
        NULL, HFILL }},
    { &hf_e1ap_InterfacesToTrace_F1_C,
      { "F1-C", "e1ap.InterfacesToTrace.F1_C",
        FT_BOOLEAN, 8, TFS(&tfs_should_be_traced_should_not_be_traced), 0x10,
        NULL, HFILL }},
    { &hf_e1ap_InterfacesToTrace_E1,
      { "E1", "e1ap.InterfacesToTrace.E1",
        FT_BOOLEAN, 8, TFS(&tfs_should_be_traced_should_not_be_traced), 0x08,
        NULL, HFILL }},
    { &hf_e1ap_InterfacesToTrace_Reserved,
      { "Reserved", "e1ap.InterfacesToTrace.Reserved",
        FT_UINT8, BASE_HEX, NULL, 0x07,
        NULL, HFILL }},
    { &hf_e1ap_MeasurementsToActivate_Reserved1,
      { "Reserved", "e1ap.MeasurementsToActivate.Reserved",
        FT_UINT8, BASE_HEX, NULL, 0xe0,
        NULL, HFILL }},
    { &hf_e1ap_MeasurementsToActivate_M4,
      { "M4", "e1ap.MeasurementsToActivate.M4",
        FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x10,
        NULL, HFILL }},
    { &hf_e1ap_MeasurementsToActivate_Reserved2,
      { "Reserved", "e1ap.MeasurementsToActivate.Reserved",
        FT_UINT8, BASE_HEX, NULL, 0x0c,
        NULL, HFILL }},
    { &hf_e1ap_MeasurementsToActivate_M6,
      { "M6", "e1ap.MeasurementsToActivate.M6",
        FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x02,
        NULL, HFILL }},
    { &hf_e1ap_MeasurementsToActivate_M7,
      { "M7", "e1ap.MeasurementsToActivate.M7",
        FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x01,
        NULL, HFILL }},
    { &hf_e1ap_ReportCharacteristics_TNLAvailableCapacityIndPeriodic,
      { "TNLAvailableCapacityIndPeriodic", "e1ap.ReportCharacteristics.TNLAvailableCapacityIndPeriodic",
        FT_BOOLEAN, 40, TFS(&tfs_requested_not_requested), 0x8000000000,
        NULL, HFILL }},
    { &hf_e1ap_ReportCharacteristics_HWCapacityIndPeriodic,
      { "HWCapacityIndPeriodic", "e1ap.ReportCharacteristics.HWCapacityIndPeriodic",
        FT_BOOLEAN, 40, TFS(&tfs_requested_not_requested), 0x4000000000,
        NULL, HFILL }},
    { &hf_e1ap_ReportCharacteristics_Reserved,
      { "Reserved", "e1ap.ReportCharacteristics.Reserved",
        FT_UINT40, BASE_HEX, NULL, 0x3ffffffff0,
        NULL, HFILL }},
    { &hf_e1ap_tcp_pdu_len,
      { "TCP PDU length", "e1ap.tcp_pdu_len",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
#include "packet-e1ap-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_e1ap,
    &ett_e1ap_PLMN_Identity,
    &ett_e1ap_TransportLayerAddress,
    &ett_e1ap_InterfacesToTrace,
    &ett_e1ap_MeasurementsToActivate,
    &ett_e1ap_ReportCharacteristics,
    &ett_e1ap_BurstArrivalTime,
#include "packet-e1ap-ettarr.c"
  };

  /* Register protocol */
  proto_e1ap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_e1ap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  e1ap_handle = register_dissector("e1ap", dissect_e1ap, proto_e1ap);
  e1ap_tcp_handle = register_dissector("e1ap_tcp", dissect_e1ap_tcp, proto_e1ap);

  /* Register dissector tables */
  e1ap_ies_dissector_table = register_dissector_table("e1ap.ies", "E1AP-PROTOCOL-IES", proto_e1ap, FT_UINT32, BASE_DEC);
  e1ap_extension_dissector_table = register_dissector_table("e1ap.extension", "E1AP-PROTOCOL-EXTENSION", proto_e1ap, FT_UINT32, BASE_DEC);
  e1ap_proc_imsg_dissector_table = register_dissector_table("e1ap.proc.imsg", "E1AP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_e1ap, FT_UINT32, BASE_DEC);
  e1ap_proc_sout_dissector_table = register_dissector_table("e1ap.proc.sout", "E1AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_e1ap, FT_UINT32, BASE_DEC);
  e1ap_proc_uout_dissector_table = register_dissector_table("e1ap.proc.uout", "E1AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_e1ap, FT_UINT32, BASE_DEC);
}

void
proto_reg_handoff_e1ap(void)
{
  dissector_add_uint_with_preference("sctp.port", SCTP_PORT_E1AP, e1ap_handle);
  dissector_add_uint_with_preference("tcp.port", 0, e1ap_tcp_handle);
  dissector_add_uint("sctp.ppi", E1AP_PROTOCOL_ID, e1ap_handle);
#include "packet-e1ap-dis-tab.c"
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
