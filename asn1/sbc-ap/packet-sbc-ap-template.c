/* packet-sbc-ap.c
 * Routines for SBc Application Part (SBc-AP) packet dissection
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
 * Ref 3GPP TS 29.168
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>

#include <stdio.h>
#include <string.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/sctpppids.h>

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-e212.h"

#define PNAME  "SBc Application Part"
#define PSNAME "SBCAP"
#define PFNAME "sbcap"

void proto_register_sbc_ap(void);
void proto_reg_handoff_sbc_ap(void);

/* The registered port number for SBc-AP is 29168.
 * The registered payload protocol identifier for SBc-AP is 24.
 */
#define SBC_AP_PORT 29168
static dissector_handle_t sbc_ap_handle=NULL;


#include "packet-sbc-ap-val.h"

/* Initialize the protocol and registered fields */
static int proto_sbc_ap = -1;

#include "packet-sbc-ap-hf.c"

/* Initialize the subtree pointers */
static int ett_sbc_ap = -1;

#include "packet-sbc-ap-ett.c"

enum{
	INITIATING_MESSAGE,
	SUCCESSFUL_OUTCOME,
	UNSUCCESSFUL_OUTCOME
};

/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;
static guint32 ProtocolExtensionID;
static int global_sbc_ap_port = SBC_AP_PORT;

/* Dissector tables */
static dissector_table_t sbc_ap_ies_dissector_table;
static dissector_table_t sbc_ap_extension_dissector_table;
static dissector_table_t sbc_ap_proc_imsg_dissector_table;
static dissector_table_t sbc_ap_proc_sout_dissector_table;
static dissector_table_t sbc_ap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

#include "packet-sbc-ap-fn.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(sbc_ap_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}
/* Currently not used
static int dissect_ProtocolIEFieldPairFirstValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(sbc_ap_ies_p1_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolIEFieldPairSecondValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(sbc_ap_ies_p2_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}
*/

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(sbc_ap_extension_dissector_table, ProtocolExtensionID, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(sbc_ap_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(sbc_ap_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(sbc_ap_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}


static void
dissect_sbc_ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item      *sbc_ap_item = NULL;
    proto_tree      *sbc_ap_tree = NULL;

    /* make entry in the Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PNAME);

    /* create the sbc_ap protocol tree */
    if (tree) {
        sbc_ap_item = proto_tree_add_item(tree, proto_sbc_ap, tvb, 0, -1, ENC_NA);
        sbc_ap_tree = proto_item_add_subtree(sbc_ap_item, ett_sbc_ap);

        dissect_SBC_AP_PDU_PDU(tvb, pinfo, sbc_ap_tree, NULL);
    }
}
/*--- proto_register_sbc_ap -------------------------------------------*/
void proto_register_sbc_ap(void) {

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-sbc-ap-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
                  &ett_sbc_ap,
#include "packet-sbc-ap-ettarr.c"
  };


  /* Register protocol */
  proto_sbc_ap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_sbc_ap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));


  /* Register dissector tables */
  sbc_ap_ies_dissector_table = register_dissector_table("sbc_ap.ies", "SBC-AP-PROTOCOL-IES", FT_UINT32, BASE_DEC);
  sbc_ap_extension_dissector_table = register_dissector_table("sbc_ap.extension", "SBC-AP-PROTOCOL-EXTENSION", FT_UINT32, BASE_DEC);
  sbc_ap_proc_imsg_dissector_table = register_dissector_table("sbc_ap.proc.imsg", "SBC-AP-ELEMENTARY-PROCEDURE InitiatingMessage", FT_UINT32, BASE_DEC);
  sbc_ap_proc_sout_dissector_table = register_dissector_table("sbc_ap.proc.sout", "SBC-AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", FT_UINT32, BASE_DEC);
  sbc_ap_proc_uout_dissector_table = register_dissector_table("sbc_ap.proc.uout", "SBC-AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", FT_UINT32, BASE_DEC);


}


/*--- proto_reg_handoff_sbc_ap ---------------------------------------*/
void
proto_reg_handoff_sbc_ap(void)
{
    static gboolean inited = FALSE;
	static guint SctpPort;

    if( !inited ) {
        sbc_ap_handle = create_dissector_handle(dissect_sbc_ap, proto_sbc_ap);
        dissector_add_uint("sctp.ppi", SBC_AP_PAYLOAD_PROTOCOL_ID,   sbc_ap_handle);
        inited = TRUE;
#include "packet-sbc-ap-dis-tab.c"
	} else {
		if (SctpPort != 0) {
			dissector_delete_uint("sctp.port", SctpPort, sbc_ap_handle);
		}
	}

	SctpPort = global_sbc_ap_port;
	if (SctpPort != 0) {
		dissector_add_uint("sctp.port", SctpPort, sbc_ap_handle);
	}

}





