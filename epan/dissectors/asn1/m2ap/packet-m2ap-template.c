/* packet-m2ap.c
 * Routines for M2 Application Protocol packet dissection
 * Copyright 2016-2023, Pascal Quantin <pascal@wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Reference: 3GPP TS 36.443 v17.0.1
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/sctpppids.h>
#include <epan/asn1.h>
#include <epan/expert.h>
#include <epan/proto_data.h>

#include "packet-per.h"
#include "packet-e212.h"

#define PNAME  "M2 Application Protocol"
#define PSNAME "M2AP"
#define PFNAME "m2ap"

void proto_register_m2ap(void);
void proto_reg_handoff_m2ap(void);

/* M2AP uses port 36443 as recommended by IANA. */
#define M2AP_PORT 36443

#include "packet-m2ap-val.h"

/* Initialize the protocol and registered fields */
static int proto_m2ap;

static int hf_m2ap_IPAddress_v4;
static int hf_m2ap_IPAddress_v6;
#include "packet-m2ap-hf.c"

/* Initialize the subtree pointers */
static int ett_m2ap;
static int ett_m2ap_PLMN_Identity;
static int ett_m2ap_IPAddress;
#include "packet-m2ap-ett.c"

static expert_field ei_m2ap_invalid_ip_address_len;

struct m2ap_private_data {
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
static uint32_t message_type;
static dissector_handle_t m2ap_handle;

/* Dissector tables */
static dissector_table_t m2ap_ies_dissector_table;
static dissector_table_t m2ap_extension_dissector_table;
static dissector_table_t m2ap_proc_imsg_dissector_table;
static dissector_table_t m2ap_proc_sout_dissector_table;
static dissector_table_t m2ap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

static struct m2ap_private_data*
m2ap_get_private_data(packet_info *pinfo)
{
  struct m2ap_private_data *m2ap_data = (struct m2ap_private_data*)p_get_proto_data(pinfo->pool, pinfo, proto_m2ap, 0);
  if (!m2ap_data) {
    m2ap_data = wmem_new0(pinfo->pool, struct m2ap_private_data);
    p_add_proto_data(pinfo->pool, pinfo, proto_m2ap, 0, m2ap_data);
  }
  return m2ap_data;
}

#include "packet-m2ap-fn.c"

static int
dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(m2ap_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int
dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(m2ap_extension_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int
dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(m2ap_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int
dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(m2ap_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int
dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(m2ap_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}


static int
dissect_m2ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *m2ap_item = NULL;
  proto_tree *m2ap_tree = NULL;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);
  col_clear_fence(pinfo->cinfo, COL_INFO);
  col_clear(pinfo->cinfo, COL_INFO);

  m2ap_item = proto_tree_add_item(tree, proto_m2ap, tvb, 0, -1, ENC_NA);
  m2ap_tree = proto_item_add_subtree(m2ap_item, ett_m2ap);

  dissect_M2AP_PDU_PDU(tvb, pinfo, m2ap_tree, NULL);

  return tvb_captured_length(tvb);
}

void
proto_register_m2ap(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_m2ap_IPAddress_v4,
      { "IPAddress", "m2ap.IPAddress_v4",
         FT_IPv4, BASE_NONE, NULL, 0,
         NULL, HFILL }
    },
    { &hf_m2ap_IPAddress_v6,
      { "IPAddress", "m2ap.IPAddress_v6",
         FT_IPv6, BASE_NONE, NULL, 0,
         NULL, HFILL }
    },
#include "packet-m2ap-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_m2ap,
    &ett_m2ap_PLMN_Identity,
    &ett_m2ap_IPAddress,
#include "packet-m2ap-ettarr.c"
  };

  expert_module_t* expert_m2ap;

  static ei_register_info ei[] = {
    { &ei_m2ap_invalid_ip_address_len, { "m2ap.invalid_ip_address_len", PI_MALFORMED, PI_ERROR, "Invalid IP address length", EXPFILL }}
  };

  /* Register protocol */
  proto_m2ap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_m2ap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_m2ap = expert_register_protocol(proto_m2ap);
  expert_register_field_array(expert_m2ap, ei, array_length(ei));
  /* Register dissector */
  m2ap_handle = register_dissector(PFNAME, dissect_m2ap, proto_m2ap);

  /* Register dissector tables */
  m2ap_ies_dissector_table = register_dissector_table("m2ap.ies", "M2AP-PROTOCOL-IES", proto_m2ap, FT_UINT32, BASE_DEC);
  m2ap_extension_dissector_table = register_dissector_table("m2ap.extension", "M2AP-PROTOCOL-EXTENSION", proto_m2ap, FT_UINT32, BASE_DEC);
  m2ap_proc_imsg_dissector_table = register_dissector_table("m2ap.proc.imsg", "M2AP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_m2ap, FT_UINT32, BASE_DEC);
  m2ap_proc_sout_dissector_table = register_dissector_table("m2ap.proc.sout", "M2AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_m2ap, FT_UINT32, BASE_DEC);
  m2ap_proc_uout_dissector_table = register_dissector_table("m2ap.proc.uout", "M2AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_m2ap, FT_UINT32, BASE_DEC);
}

void
proto_reg_handoff_m2ap(void)
{
  dissector_add_uint("sctp.ppi", PROTO_3GPP_M2AP_PROTOCOL_ID, m2ap_handle);
  dissector_add_uint("sctp.port", M2AP_PORT, m2ap_handle);
#include "packet-m2ap-dis-tab.c"
}
