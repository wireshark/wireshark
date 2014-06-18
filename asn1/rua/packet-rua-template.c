/* packet-rua-template.c
 * Routines for UMTS Home Node B RANAP User Adaptation (RUA) packet dissection
 * Copyright 2010 Neil Piercy, ip.access Limited <Neil.Piercy@ipaccess.com>
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
 * Ref: 3GPP TS 25.468 version 8.1.0 Release 8
 */

#include "config.h"

#include <glib.h>
#include <string.h>

#include <epan/packet.h>
#include <epan/sctpppids.h>
#include <epan/asn1.h>
#include <epan/prefs.h>

#include "packet-per.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "UTRAN Iuh interface RUA signalling"
#define PSNAME "RUA"
#define PFNAME "rua"
/* Dissector to use SCTP PPID 19 or a configured SCTP port. IANA assigned port = 29169*/
#define SCTP_PORT_RUA              29169;

void proto_register_rua(void);

#include "packet-rua-val.h"

/* Initialize the protocol and registered fields */
static int proto_rua = -1;

#include "packet-rua-hf.c"

/* Initialize the subtree pointers */
static int ett_rua = -1;

 /* initialise sub-dissector handles */
 static dissector_handle_t ranap_handle = NULL;

#include "packet-rua-ett.c"

/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;
static guint global_sctp_port = SCTP_PORT_RUA

/* Dissector tables */
static dissector_table_t rua_ies_dissector_table;
static dissector_table_t rua_extension_dissector_table;
static dissector_table_t rua_proc_imsg_dissector_table;
static dissector_table_t rua_proc_sout_dissector_table;
static dissector_table_t rua_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

void proto_reg_handoff_rua(void);

#include "packet-rua-fn.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(rua_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(rua_extension_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(rua_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(rua_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(rua_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static void
dissect_rua(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *rua_item = NULL;
    proto_tree  *rua_tree = NULL;

    /* make entry in the Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RUA");

    /* create the rua protocol tree */
    rua_item = proto_tree_add_item(tree, proto_rua, tvb, 0, -1, ENC_NA);
    rua_tree = proto_item_add_subtree(rua_item, ett_rua);

    dissect_RUA_PDU_PDU(tvb, pinfo, rua_tree);
}

/*--- proto_register_rua -------------------------------------------*/
void proto_register_rua(void) {
module_t *rua_module;

  /* List of fields */

  static hf_register_info hf[] = {

#include "packet-rua-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
          &ett_rua,
#include "packet-rua-ettarr.c"
  };


  /* Register protocol */
  proto_rua = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_rua, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  register_dissector("rua", dissect_rua, proto_rua);

  /* Register dissector tables */
  rua_ies_dissector_table = register_dissector_table("rua.ies", "RUA-PROTOCOL-IES", FT_UINT32, BASE_DEC);
  rua_extension_dissector_table = register_dissector_table("rua.extension", "RUA-PROTOCOL-EXTENSION", FT_UINT32, BASE_DEC);
  rua_proc_imsg_dissector_table = register_dissector_table("rua.proc.imsg", "RUA-ELEMENTARY-PROCEDURE InitiatingMessage", FT_UINT32, BASE_DEC);
  rua_proc_sout_dissector_table = register_dissector_table("rua.proc.sout", "RUA-ELEMENTARY-PROCEDURE SuccessfulOutcome", FT_UINT32, BASE_DEC);
  rua_proc_uout_dissector_table = register_dissector_table("rua.proc.uout", "RUA-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", FT_UINT32, BASE_DEC);

  rua_module = prefs_register_protocol(proto_rua, proto_reg_handoff_rua);
  prefs_register_uint_preference(rua_module, "port", "RUA SCTP Port", "Set the port for RUA messages (Default of 29169)", 10, &global_sctp_port);

}


/*--- proto_reg_handoff_rua ---------------------------------------*/
void
proto_reg_handoff_rua(void)
{
        static gboolean initialized = FALSE;
        static dissector_handle_t rua_handle;
        static guint sctp_port;

        if (!initialized) {
                rua_handle = find_dissector("rua");
                ranap_handle = find_dissector("ranap");
                dissector_add_uint("sctp.ppi", RUA_PAYLOAD_PROTOCOL_ID, rua_handle);
                initialized = TRUE;
#include "packet-rua-dis-tab.c"

        } else {
                dissector_delete_uint("sctp.port", sctp_port, rua_handle);
        }
        /* Set our port number for future use */
        sctp_port = global_sctp_port;
        dissector_add_uint("sctp.port", sctp_port, rua_handle);
}
