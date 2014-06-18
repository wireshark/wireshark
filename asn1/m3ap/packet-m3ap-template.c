/* packet-m3ap.c
 * Routines for M3 Application Protocol packet dissection
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
 * Reference: 3GPP TS 36.444 v11.0.0
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>

#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/sctpppids.h>

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-e212.h"
#include "packet-gtpv2.h"
#include "packet-ntp.h"

#define PNAME  "M3 Application Protocol"
#define PSNAME "M3AP"
#define PFNAME "m3ap"

void proto_register_m3ap(void);
void proto_reg_handoff_m3ap(void);

/* M3AP uses port 36444 as recommended by IANA. */
#define M3AP_PORT 36444
static dissector_handle_t m3ap_handle=NULL;

#include "packet-m3ap-val.h"

/* Initialize the protocol and registered fields */
static int proto_m3ap = -1;

static int hf_m3ap_Absolute_Time_ofMBMS_Data_value = -1;
static int hf_m3ap_IPAddress = -1;

#include "packet-m3ap-hf.c"

/* Initialize the subtree pointers */
static int ett_m3ap = -1;

#include "packet-m3ap-ett.c"

enum{
  INITIATING_MESSAGE,
  SUCCESSFUL_OUTCOME,
  UNSUCCESSFUL_OUTCOME
};

/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;
/*static guint32 ProtocolExtensionID; */
static int global_m3ap_port = M3AP_PORT;
static guint32 message_type;

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

#include "packet-m3ap-fn.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(m3ap_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(m3ap_extension_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(m3ap_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(m3ap_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(m3ap_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}


static void
dissect_m3ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item      *m3ap_item = NULL;
  proto_tree      *m3ap_tree = NULL;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, PNAME);

  /* create the m3ap protocol tree */
  if (tree) {
    m3ap_item = proto_tree_add_item(tree, proto_m3ap, tvb, 0, -1, ENC_NA);
    m3ap_tree = proto_item_add_subtree(m3ap_item, ett_m3ap);

    dissect_M3AP_PDU_PDU(tvb, pinfo, m3ap_tree, NULL);
  }
}
/*--- proto_register_m3ap -------------------------------------------*/
void proto_register_m3ap(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_m3ap_Absolute_Time_ofMBMS_Data_value,
      { "Absolute-Time-ofMBMS-Data-value", "m3ap.Absolute_Time_ofMBMS_Data_value",
         FT_STRING, BASE_NONE, NULL, 0,
         NULL, HFILL }
    },
    { &hf_m3ap_IPAddress,
      { "IPAddress", "m3ap.IPAddress",
         FT_IPv6, BASE_NONE, NULL, 0,
         NULL, HFILL }
    },

#include "packet-m3ap-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
                  &ett_m3ap,
#include "packet-m3ap-ettarr.c"
  };


  /* Register protocol */
  proto_m3ap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_m3ap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector tables */
  m3ap_ies_dissector_table = register_dissector_table("m3ap.ies", "M3AP-PROTOCOL-IES", FT_UINT32, BASE_DEC);
  m3ap_extension_dissector_table = register_dissector_table("m3ap.extension", "M3AP-PROTOCOL-EXTENSION", FT_UINT32, BASE_DEC);
  m3ap_proc_imsg_dissector_table = register_dissector_table("m3ap.proc.imsg", "M3AP-ELEMENTARY-PROCEDURE InitiatingMessage", FT_UINT32, BASE_DEC);
  m3ap_proc_sout_dissector_table = register_dissector_table("m3ap.proc.sout", "M3AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", FT_UINT32, BASE_DEC);
  m3ap_proc_uout_dissector_table = register_dissector_table("m3ap.proc.uout", "M3AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", FT_UINT32, BASE_DEC);
}


/*--- proto_reg_handoff_m3ap ---------------------------------------*/
void
proto_reg_handoff_m3ap(void)
{
  static gboolean inited = FALSE;
  static guint SctpPort;

  if( !inited ) {
    m3ap_handle = create_dissector_handle(dissect_m3ap, proto_m3ap);
    dissector_add_uint("sctp.ppi", PROTO_3GPP_M3AP_PROTOCOL_ID, m3ap_handle);
    inited = TRUE;
#include "packet-m3ap-dis-tab.c"
    dissector_add_uint("m3ap.extension", 17, new_create_dissector_handle(dissect_AllocationAndRetentionPriority_PDU, proto_m3ap));
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
