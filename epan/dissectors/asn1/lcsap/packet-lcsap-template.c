/* packet-lcsap.c
 * Routines for LCS-AP packet dissembly.
 *
 * Copyright (c) 2011 by Spenser Sheng <spenser.sheng@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 * References:
 * ETSI TS 129 171 V9.2.0 (2010-10)
 */

#include "config.h"

#include <math.h>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/sctpppids.h>
#include <epan/expert.h>

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-e212.h"
#include "packet-sccp.h"
#include "packet-lcsap.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "LCS Application Protocol"
#define PSNAME "LCSAP"
#define PFNAME "lcsap"

void proto_register_lcsap(void);
void proto_reg_handoff_lcsap(void);

#define SCTP_PORT_LCSAP 9082
#include "packet-lcsap-val.h"

/* Initialize the protocol and registered fields */
static int proto_lcsap  =   -1;

static int hf_lcsap_pos_method = -1;
static int hf_lcsap_pos_usage = -1;
static int hf_lcsap_gnss_pos_method = -1;
static int hf_lcsap_gnss_id = -1;
static int hf_lcsap_gnss_pos_usage = -1;
#include "packet-lcsap-hf.c"

/* Initialize the subtree pointers */
static int ett_lcsap = -1;
static int ett_lcsap_plmnd_id = -1;
static int ett_lcsap_imsi = -1;
static int ett_lcsap_civic_address = -1;

#include "packet-lcsap-ett.c"

static expert_field ei_lcsap_civic_data_not_xml = EI_INIT;

/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;
static guint32 ProtocolExtensionID;
static guint32 PayloadType = -1;

/* Dissector handles */
static dissector_handle_t lcsap_handle;
static dissector_handle_t lpp_handle;
static dissector_handle_t lppa_handle;
static dissector_handle_t xml_handle;

/* Dissector tables */
static dissector_table_t lcsap_ies_dissector_table;

static dissector_table_t lcsap_extension_dissector_table;
static dissector_table_t lcsap_proc_imsg_dissector_table;
static dissector_table_t lcsap_proc_sout_dissector_table;
static dissector_table_t lcsap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);


/* 7.4.13 Positioning Data
 * Coding of positioning method (bits 8-4)
 */
static const value_string lcsap_pos_method_vals[] = {
  { 0x00, "Cell ID" },
  { 0x01, "Reserved" },
  { 0x02, "E-CID" },
  { 0x03, "Reserved" },
  { 0x04, "OTDOA" },
  { 0x05, "Reserved" },
  { 0x06, "Reserved" },
  { 0x07, "Reserved" },
  { 0x08, "U-TDOA" },
  { 0x09, "Reserved" },
  { 0x0a, "Reserved" },
  { 0x0b, "Reserved" },
  { 0x0c, "Reserved for other location technologies" },
  { 0x0d, "Reserved for other location technologies" },
  { 0x0e, "Reserved for other location technologies" },
  { 0x0f, "Reserved for other location technologies" },
  { 0x10, "Reserved for network specific positioning methods" },
  { 0x11, "Reserved for network specific positioning methods" },
  { 0x12, "Reserved for network specific positioning methods" },
  { 0x13, "Reserved for network specific positioning methods" },
  { 0x14, "Reserved for network specific positioning methods" },
  { 0x15, "Reserved for network specific positioning methods" },
  { 0x16, "Reserved for network specific positioning methods" },
  { 0x17, "Reserved for network specific positioning methods" },
  { 0x18, "Reserved for network specific positioning methods" },
  { 0x19, "Reserved for network specific positioning methods" },
  { 0x1a, "Reserved for network specific positioning methods" },
  { 0x1b, "Reserved for network specific positioning methods" },
  { 0x1c, "Reserved for network specific positioning methods" },
  { 0x1d, "Reserved for network specific positioning methods" },
  { 0x1e, "Reserved for network specific positioning methods" },
  { 0x1f, "Reserved for network specific positioning methods" },
  { 0, NULL }
};

/* Coding of usage (bits 3-1)*/
static const value_string lcsap_pos_usage_vals[] = {
  { 0x00, "Attempted unsuccessfully due to failure or interruption - not used" },
  { 0x01, "Attempted successfully: results not used to generate location - not used." },
  { 0x02, "Attempted successfully: results used to verify but not generate location - not used." },
  { 0x03, "Attempted successfully: results used to generate location" },
  { 0x04, "Attempted successfully: case where UE supports multiple mobile based positioning methods and the actual method or methods used by the UE cannot be determined." },
  { 0x05, "Reserved" },
  { 0x06, "Reserved" },
  { 0x07, "Reserved" },
  { 0, NULL }
};

/* Coding of Method (Bits 8-7) */
static const value_string lcsap_gnss_pos_method_vals[] = {
  { 0x00, "UE-Based" },
  { 0x01, "UE-Assisted" },
  { 0x02, "Conventional" },
  { 0x03, "Reserved" },
  { 0, NULL }
};

/* Coding of GNSS ID (Bits 6-4) */
static const value_string lcsap_gnss_id_vals[] = {
  { 0x00, "GPS" },
  { 0x01, "Galileo" },
  { 0x02, "SBAS" },
  { 0x03, "Modernized GPS" },
  { 0x04, "QZSS" },
  { 0x05, "GLONASS" },
  { 0x06, "Reserved" },
  { 0x07, "Reserved" },
  { 0, NULL }
};

/* Coding of usage (bits 3- 1) */
static const value_string lcsap_gnss_pos_usage_vals[] = {
  { 0x00, "Attempted unsuccessfully due to failure or interruption" },
  { 0x01, "Attempted successfully: results not used to generate location" },
  { 0x02, "Attempted successfully: results used to verify but not generate location" },
  { 0x03, "Attempted successfully: results used to generate location" },
  { 0x04, "Attempted successfully: case where UE supports multiple mobile based positioning methods and the actual method or methods used by the UE cannot be determined." },
  { 0x05, "Reserved" },
  { 0x06, "Reserved" },
  { 0x07, "Reserved" },
  { 0, NULL }
};


#include "packet-lcsap-fn.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(lcsap_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}


static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(lcsap_extension_dissector_table, ProtocolExtensionID, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(lcsap_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(lcsap_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(lcsap_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}


static int
dissect_lcsap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item  *lcsap_item = NULL;
  proto_tree  *lcsap_tree = NULL;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LCSAP");

  /* create the lcsap protocol tree */
  lcsap_item = proto_tree_add_item(tree, proto_lcsap, tvb, 0, -1, ENC_NA);
  lcsap_tree = proto_item_add_subtree(lcsap_item, ett_lcsap);

  dissect_LCS_AP_PDU_PDU(tvb, pinfo, lcsap_tree, NULL);
  return tvb_captured_length(tvb);
}

/*--- proto_reg_handoff_lcsap ---------------------------------------*/
void
proto_reg_handoff_lcsap(void)
{
  lpp_handle = find_dissector_add_dependency("lpp", proto_lcsap);
  lppa_handle = find_dissector_add_dependency("lppa", proto_lcsap);
  xml_handle = find_dissector_add_dependency("xml", proto_lcsap);
  dissector_add_uint_with_preference("sctp.port", SCTP_PORT_LCSAP, lcsap_handle);
  dissector_add_uint("sctp.ppi", LCS_AP_PAYLOAD_PROTOCOL_ID,   lcsap_handle);
#include "packet-lcsap-dis-tab.c"

}

/*--- proto_register_lcsap -------------------------------------------*/
void proto_register_lcsap(void) {

  /* List of fields */
  static hf_register_info hf[] = {
      /* 7.4.13 Positioning Data */
      { &hf_lcsap_pos_method,
        { "Positioning Method", "lcsap.pos_method",
          FT_UINT8, BASE_DEC, VALS(lcsap_pos_method_vals), 0xf8,
          NULL, HFILL }
      },
      { &hf_lcsap_pos_usage,
        { "Positioning usage", "lcsap.pos_usage",
          FT_UINT8, BASE_DEC, VALS(lcsap_pos_usage_vals), 0x07,
          NULL, HFILL }
      },
      { &hf_lcsap_gnss_pos_method,
        { "GNSS Positioning Method", "lcsap.gnss_pos_method",
          FT_UINT8, BASE_DEC, VALS(lcsap_gnss_pos_method_vals), 0xc0,
          NULL, HFILL }
      },
      { &hf_lcsap_gnss_id,
        { "GNSS ID", "lcsap.gnss_id",
          FT_UINT8, BASE_DEC, VALS(lcsap_gnss_id_vals), 0x38,
          NULL, HFILL }
      },
      { &hf_lcsap_gnss_pos_usage,
        { "GNSS Positioning usage", "lcsap.gnss_pos_usage",
          FT_UINT8, BASE_DEC, VALS(lcsap_gnss_pos_usage_vals), 0x07,
          NULL, HFILL }
      },

#include "packet-lcsap-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_lcsap,
    &ett_lcsap_plmnd_id,
    &ett_lcsap_imsi,
    &ett_lcsap_civic_address,
#include "packet-lcsap-ettarr.c"
 };

  /* module_t *lcsap_module; */
  expert_module_t *expert_lcsap;

  static ei_register_info ei[] = {
      { &ei_lcsap_civic_data_not_xml,
      { "lcsap.civic_data_not_xml", PI_PROTOCOL, PI_ERROR, "Should contain a UTF-8 encoded PIDF - LO XML document as defined in IETF RFC 4119", EXPFILL } },
  };


  /* Register protocol */
  proto_lcsap = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_lcsap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  lcsap_handle = register_dissector("lcsap", dissect_lcsap, proto_lcsap);

  /* Register dissector tables */
  lcsap_ies_dissector_table = register_dissector_table("lcsap.ies", "LCS-AP-PROTOCOL-IES", proto_lcsap, FT_UINT32, BASE_DEC);

  expert_lcsap = expert_register_protocol(proto_lcsap);
  expert_register_field_array(expert_lcsap, ei, array_length(ei));

  lcsap_extension_dissector_table = register_dissector_table("lcsap.extension", "LCS-AP-PROTOCOL-EXTENSION", proto_lcsap, FT_UINT32, BASE_DEC);
  lcsap_proc_imsg_dissector_table = register_dissector_table("lcsap.proc.imsg", "LCS-AP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_lcsap, FT_UINT32, BASE_DEC);
  lcsap_proc_sout_dissector_table = register_dissector_table("lcsap.proc.sout", "LCS-AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_lcsap, FT_UINT32, BASE_DEC);
  lcsap_proc_uout_dissector_table = register_dissector_table("lcsap.proc.uout", "LCS-AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_lcsap, FT_UINT32, BASE_DEC);

  /* lcsap_module = prefs_register_protocol(proto_lcsap, NULL); */

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
