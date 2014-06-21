/* packet-lppa.c
 * Routines for 3GPP LTE Positioning Protocol A (LLPa) packet dissection
 * Copyright 2011, Pascal Quantin <pascal.quantin@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Ref 3GPP TS 36.455 version 11.3.0 Release 11
 * http://www.3gpp.org
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/asn1.h>

#include "packet-per.h"

#define PNAME  "LTE Positioning Protocol A (LPPa)"
#define PSNAME "LPPa"
#define PFNAME "lppa"

void proto_register_lppa(void);
void proto_reg_handoff_lppa(void);

/* Initialize the protocol and registered fields */
static int proto_lppa = -1;

#include "packet-lppa-hf.c"

/* Initialize the subtree pointers */
static gint ett_lppa = -1;
#include "packet-lppa-ett.c"

/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;

/* Dissector tables */
static dissector_table_t lppa_ies_dissector_table;
static dissector_table_t lppa_proc_imsg_dissector_table;
static dissector_table_t lppa_proc_sout_dissector_table;
static dissector_table_t lppa_proc_uout_dissector_table;

/* Include constants */
#include "packet-lppa-val.h"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

#include "packet-lppa-fn.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(lppa_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(lppa_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(lppa_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(lppa_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

/*--- proto_register_lppa -------------------------------------------*/
void proto_register_lppa(void) {

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-lppa-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_lppa,
#include "packet-lppa-ettarr.c"
  };

  /* Register protocol */
  proto_lppa = proto_register_protocol(PNAME, PSNAME, PFNAME);
  new_register_dissector("lppa", dissect_LPPA_PDU_PDU, proto_lppa);

  /* Register fields and subtrees */
  proto_register_field_array(proto_lppa, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

   /* Register dissector tables */
  lppa_ies_dissector_table = register_dissector_table("lppa.ies", "LPPA-PROTOCOL-IES", FT_UINT32, BASE_DEC);
  lppa_proc_imsg_dissector_table = register_dissector_table("lppa.proc.imsg", "LPPA-ELEMENTARY-PROCEDURE InitiatingMessage", FT_UINT32, BASE_DEC);
  lppa_proc_sout_dissector_table = register_dissector_table("lppa.proc.sout", "LPPA-ELEMENTARY-PROCEDURE SuccessfulOutcome", FT_UINT32, BASE_DEC);
  lppa_proc_uout_dissector_table = register_dissector_table("lppa.proc.uout", "LPPA-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", FT_UINT32, BASE_DEC);
}

/*--- proto_reg_handoff_lppa ---------------------------------------*/
void
proto_reg_handoff_lppa(void)
{
#include "packet-lppa-dis-tab.c"
}
