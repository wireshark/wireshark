/* packet-nrppa.c
 * Routines for 3GPP NR Positioning Protocol A (NRPPa) packet dissection
 * Copyright 2019, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref 3GPP TS 38.455 V18.2.0 (2024-06)
 * https://www.3gpp.org
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/asn1.h>

#include "packet-per.h"
#include "packet-nrppa.h"

#define PNAME  "NR Positioning Protocol A (NRPPa)"
#define PSNAME "NRPPa"
#define PFNAME "nrppa"

void proto_register_nrppa(void);
void proto_reg_handoff_nrppa(void);

/* Initialize the protocol and registered fields */
static int proto_nrppa;

#include "packet-nrppa-hf.c"

/* Initialize the subtree pointers */
static int ett_nrppa;
#include "packet-nrppa-ett.c"

/* Global variables */
static uint32_t ProcedureCode;
static uint32_t ProtocolIE_ID;

/* Dissector tables */
static dissector_table_t nrppa_ies_dissector_table;
static dissector_table_t nrppa_extension_dissector_table;
static dissector_table_t nrppa_proc_imsg_dissector_table;
static dissector_table_t nrppa_proc_sout_dissector_table;
static dissector_table_t nrppa_proc_uout_dissector_table;

/* Include constants */
#include "packet-nrppa-val.h"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

#include "packet-nrppa-fn.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(nrppa_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(nrppa_extension_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(nrppa_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(nrppa_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(nrppa_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

/*--- proto_register_nrppa -------------------------------------------*/
void proto_register_nrppa(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-nrppa-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_nrppa,
#include "packet-nrppa-ettarr.c"
  };

  /* Register protocol */
  proto_nrppa = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("nrppa", dissect_NRPPA_PDU_PDU, proto_nrppa);

  /* Register fields and subtrees */
  proto_register_field_array(proto_nrppa, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

   /* Register dissector tables */
  nrppa_ies_dissector_table = register_dissector_table("nrppa.ies", "NRPPA-PROTOCOL-IES", proto_nrppa, FT_UINT32, BASE_DEC);
  nrppa_extension_dissector_table = register_dissector_table("nrppa.extension", "NRPPA-PROTOCOL-EXTENSION", proto_nrppa, FT_UINT32, BASE_DEC);
  nrppa_proc_imsg_dissector_table = register_dissector_table("nrppa.proc.imsg", "NRPPA-ELEMENTARY-PROCEDURE InitiatingMessage", proto_nrppa, FT_UINT32, BASE_DEC);
  nrppa_proc_sout_dissector_table = register_dissector_table("nrppa.proc.sout", "NRPPA-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_nrppa, FT_UINT32, BASE_DEC);
  nrppa_proc_uout_dissector_table = register_dissector_table("nrppa.proc.uout", "NRPPA-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_nrppa, FT_UINT32, BASE_DEC);
}

/*--- proto_reg_handoff_nrppa ---------------------------------------*/
void
proto_reg_handoff_nrppa(void)
{
#include "packet-nrppa-dis-tab.c"
}
