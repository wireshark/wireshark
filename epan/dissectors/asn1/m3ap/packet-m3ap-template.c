/* packet-m3ap.c
 * Routines for M3 Application Protocol packet dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Reference: 3GPP TS 36.444 v16.0.0
 */

#include "config.h"

#include <epan/packet.h>

#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/sctpppids.h>
#include <epan/expert.h>
#include <epan/proto_data.h>

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-e212.h"
#include "packet-gtpv2.h"

#define PNAME  "M3 Application Protocol"
#define PSNAME "M3AP"
#define PFNAME "m3ap"

void proto_register_m3ap(void);
void proto_reg_handoff_m3ap(void);

/* M3AP uses port 36444 as recommended by IANA. */
#define M3AP_PORT 36444
static dissector_handle_t m3ap_handle;

#include "packet-m3ap-val.h"

/* Initialize the protocol and registered fields */
static int proto_m3ap;

static int hf_m3ap_Absolute_Time_ofMBMS_Data_value;
static int hf_m3ap_IPAddress_v4;
static int hf_m3ap_IPAddress_v6;

#include "packet-m3ap-hf.c"

/* Initialize the subtree pointers */
static int ett_m3ap;
static int ett_m3ap_IPAddress;
#include "packet-m3ap-ett.c"

static expert_field ei_m3ap_invalid_ip_address_len;

struct m3ap_private_data {
  e212_number_type_t number_type;
};

enum{
  INITIATING_MESSAGE,
  SUCCESSFUL_OUTCOME,
  UNSUCCESSFUL_OUTCOME
};

/* Global variables */
static uint32_t ProcedureCode;
static uint32_t ProtocolIE_ID;
/*static uint32_t ProtocolExtensionID; */
static int global_m3ap_port = M3AP_PORT;
static uint32_t message_type;

/* Dissector tables */
static dissector_table_t m3ap_ies_dissector_table;
static dissector_table_t m3ap_extension_dissector_table;
static dissector_table_t m3ap_proc_imsg_dissector_table;
static dissector_table_t m3ap_proc_sout_dissector_table;
static dissector_table_t m3ap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

static struct m3ap_private_data*
m3ap_get_private_data(packet_info *pinfo)
{
  struct m3ap_private_data *m3ap_data = (struct m3ap_private_data*)p_get_proto_data(pinfo->pool, pinfo, proto_m3ap, 0);
  if (!m3ap_data) {
    m3ap_data = wmem_new0(pinfo->pool, struct m3ap_private_data);
    p_add_proto_data(pinfo->pool, pinfo, proto_m3ap, 0, m3ap_data);
  }
  return m3ap_data;
}

#include "packet-m3ap-fn.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(m3ap_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(m3ap_extension_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(m3ap_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(m3ap_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(m3ap_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}


static int
dissect_m3ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item      *m3ap_item = NULL;
  proto_tree      *m3ap_tree = NULL;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);
  col_clear_fence(pinfo->cinfo, COL_INFO);
  col_clear(pinfo->cinfo, COL_INFO);

  /* create the m3ap protocol tree */
  m3ap_item = proto_tree_add_item(tree, proto_m3ap, tvb, 0, -1, ENC_NA);
  m3ap_tree = proto_item_add_subtree(m3ap_item, ett_m3ap);

  dissect_M3AP_PDU_PDU(tvb, pinfo, m3ap_tree, NULL);
  return tvb_captured_length(tvb);
}
/*--- proto_register_m3ap -------------------------------------------*/
void proto_register_m3ap(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_m3ap_Absolute_Time_ofMBMS_Data_value,
      { "Absolute-Time-ofMBMS-Data-value", "m3ap.Absolute_Time_ofMBMS_Data_value",
         FT_ABSOLUTE_TIME, ABSOLUTE_TIME_NTP_UTC, NULL, 0,
         NULL, HFILL }
    },
    { &hf_m3ap_IPAddress_v4,
      { "IPAddress", "m3ap.IPAddress_v4",
         FT_IPv4, BASE_NONE, NULL, 0,
         NULL, HFILL }
    },
    { &hf_m3ap_IPAddress_v6,
      { "IPAddress", "m3ap.IPAddress_v6",
         FT_IPv6, BASE_NONE, NULL, 0,
         NULL, HFILL }
    },

#include "packet-m3ap-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_m3ap,
    &ett_m3ap_IPAddress,
#include "packet-m3ap-ettarr.c"
  };

  expert_module_t* expert_m3ap;

  static ei_register_info ei[] = {
     { &ei_m3ap_invalid_ip_address_len, { "m3ap.invalid_ip_address_len", PI_MALFORMED, PI_ERROR, "Invalid IP address length", EXPFILL }}
  };

  /* Register protocol */
  proto_m3ap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_m3ap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_m3ap = expert_register_protocol(proto_m3ap);
  expert_register_field_array(expert_m3ap, ei, array_length(ei));
  /* Register dissector */
  m3ap_handle = register_dissector(PFNAME, dissect_m3ap, proto_m3ap);

  /* Register dissector tables */
  m3ap_ies_dissector_table = register_dissector_table("m3ap.ies", "M3AP-PROTOCOL-IES", proto_m3ap, FT_UINT32, BASE_DEC);
  m3ap_extension_dissector_table = register_dissector_table("m3ap.extension", "M3AP-PROTOCOL-EXTENSION", proto_m3ap, FT_UINT32, BASE_DEC);
  m3ap_proc_imsg_dissector_table = register_dissector_table("m3ap.proc.imsg", "M3AP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_m3ap, FT_UINT32, BASE_DEC);
  m3ap_proc_sout_dissector_table = register_dissector_table("m3ap.proc.sout", "M3AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_m3ap, FT_UINT32, BASE_DEC);
  m3ap_proc_uout_dissector_table = register_dissector_table("m3ap.proc.uout", "M3AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_m3ap, FT_UINT32, BASE_DEC);
}


/*--- proto_reg_handoff_m3ap ---------------------------------------*/
void
proto_reg_handoff_m3ap(void)
{
  static bool inited = false;
  static unsigned SctpPort;

  if( !inited ) {
    dissector_add_uint("sctp.ppi", PROTO_3GPP_M3AP_PROTOCOL_ID, m3ap_handle);
    inited = true;
#include "packet-m3ap-dis-tab.c"
    dissector_add_uint("m3ap.extension", 17, create_dissector_handle(dissect_AllocationAndRetentionPriority_PDU, proto_m3ap));
  }
  else {
    if (SctpPort != 0) {
      dissector_delete_uint("sctp.port", SctpPort, m3ap_handle);
    }
  }

  SctpPort = global_m3ap_port;
  if (SctpPort != 0) {
    dissector_add_uint("sctp.port", SctpPort, m3ap_handle);
  }
}
