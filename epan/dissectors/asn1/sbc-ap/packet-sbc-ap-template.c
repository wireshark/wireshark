/* packet-sbc-ap.c
 * Routines for SBc Application Part (SBc-AP) packet dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref 3GPP TS 29.168
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/sctpppids.h>
#include <epan/proto_data.h>

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-e212.h"
#include "packet-gsm_map.h"
#include "packet-s1ap.h"
#include "packet-lte-rrc.h"

#define PNAME  "SBc Application Part"
#define PSNAME "SBcAP"
#define PFNAME "sbcap"

void proto_register_sbc_ap(void);
void proto_reg_handoff_sbc_ap(void);

/* The registered port number for SBc-AP is 29168.
 * The registered payload protocol identifier for SBc-AP is 24.
 */
#define SBC_AP_PORT 29168
static dissector_handle_t sbc_ap_handle;


#include "packet-sbc-ap-val.h"

/* Initialize the protocol and registered fields */
static int proto_sbc_ap;

static int hf_sbc_ap_Serial_Number_gs;
static int hf_sbc_ap_Serial_Number_msg_code;
static int hf_sbc_ap_Serial_Number_upd_nb;
static int hf_sbc_ap_Warning_Type_value;
static int hf_sbc_ap_Warning_Type_emergency_user_alert;
static int hf_sbc_ap_Warning_Type_popup;
static int hf_sbc_ap_Warning_Message_Contents_nb_pages;
static int hf_sbc_ap_Warning_Message_Contents_decoded_page;
#include "packet-sbc-ap-hf.c"

/* Initialize the subtree pointers */
static int ett_sbc_ap;
static int ett_sbc_ap_Serial_Number;
static int ett_sbc_ap_Warning_Type;
static int ett_sbc_ap_Data_Coding_Scheme;
static int ett_sbc_ap_Warning_Message_Contents;

#include "packet-sbc-ap-ett.c"

enum{
	INITIATING_MESSAGE,
	SUCCESSFUL_OUTCOME,
	UNSUCCESSFUL_OUTCOME
};

struct sbc_ap_private_data {
  uint8_t data_coding_scheme;
  e212_number_type_t number_type;
};

/* Global variables */
static uint32_t ProcedureCode;
static uint32_t ProtocolIE_ID;
static uint32_t ProtocolExtensionID;
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


static struct sbc_ap_private_data*
sbc_ap_get_private_data(packet_info *pinfo)
{
  struct sbc_ap_private_data *sbc_ap_data = (struct sbc_ap_private_data*)p_get_proto_data(pinfo->pool, pinfo, proto_sbc_ap, 0);
  if (!sbc_ap_data) {
    sbc_ap_data = wmem_new0(pinfo->pool, struct sbc_ap_private_data);
    p_add_proto_data(pinfo->pool, pinfo, proto_sbc_ap, 0, sbc_ap_data);
  }
  return sbc_ap_data;
}

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


static int
dissect_sbc_ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item      *sbc_ap_item = NULL;
    proto_tree      *sbc_ap_tree = NULL;

    /* make entry in the Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);
    col_clear(pinfo->cinfo, COL_INFO);

    /* create the sbc_ap protocol tree */
    sbc_ap_item = proto_tree_add_item(tree, proto_sbc_ap, tvb, 0, -1, ENC_NA);
    sbc_ap_tree = proto_item_add_subtree(sbc_ap_item, ett_sbc_ap);

    dissect_SBC_AP_PDU_PDU(tvb, pinfo, sbc_ap_tree, NULL);

    return tvb_captured_length(tvb);
}
/*--- proto_register_sbc_ap -------------------------------------------*/
void proto_register_sbc_ap(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_sbc_ap_Serial_Number_gs,
      { "Geographical Scope", "sbc_ap.SerialNumber.gs",
        FT_UINT16, BASE_DEC, VALS(s1ap_serialNumber_gs_vals), 0xc000,
        NULL, HFILL }},
    { &hf_sbc_ap_Serial_Number_msg_code,
      { "Message Code", "sbc_ap.SerialNumber.msg_code",
        FT_UINT16, BASE_DEC, NULL, 0x3ff0,
        NULL, HFILL }},
    { &hf_sbc_ap_Serial_Number_upd_nb,
      { "Update Number", "sbc_ap.SerialNumber.upd_nb",
        FT_UINT16, BASE_DEC, NULL, 0x000f,
        NULL, HFILL }},
    { &hf_sbc_ap_Warning_Type_value,
      { "Warning Type Value", "sbc-ap.WarningType.value",
        FT_UINT16, BASE_DEC, VALS(s1ap_warningType_vals), 0xfe00,
        NULL, HFILL }},
    { &hf_sbc_ap_Warning_Type_emergency_user_alert,
      { "Emergency User Alert", "sbc-ap.WarningType.emergency_user_alert",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0100,
        NULL, HFILL }},
    { &hf_sbc_ap_Warning_Type_popup,
      { "Popup", "sbc-ap.WarningType.popup",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0080,
        NULL, HFILL }},
    { &hf_sbc_ap_Warning_Message_Contents_nb_pages,
      { "Number of Pages", "sbc-ap.WarningMessageContents.nb_pages",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Warning_Message_Contents_decoded_page,
      { "Decoded Page", "sbc-ap.WarningMessageContents.decoded_page",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
#include "packet-sbc-ap-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
                  &ett_sbc_ap,
                  &ett_sbc_ap_Serial_Number,
                  &ett_sbc_ap_Warning_Type,
                  &ett_sbc_ap_Data_Coding_Scheme,
                  &ett_sbc_ap_Warning_Message_Contents,
#include "packet-sbc-ap-ettarr.c"
  };


  /* Register protocol */
  proto_sbc_ap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_sbc_ap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  sbc_ap_handle = register_dissector(PFNAME, dissect_sbc_ap, proto_sbc_ap);

  /* Register dissector tables */
  sbc_ap_ies_dissector_table = register_dissector_table("sbc_ap.ies", "SBC-AP-PROTOCOL-IES", proto_sbc_ap, FT_UINT32, BASE_DEC);
  sbc_ap_extension_dissector_table = register_dissector_table("sbc_ap.extension", "SBC-AP-PROTOCOL-EXTENSION", proto_sbc_ap, FT_UINT32, BASE_DEC);
  sbc_ap_proc_imsg_dissector_table = register_dissector_table("sbc_ap.proc.imsg", "SBC-AP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_sbc_ap, FT_UINT32, BASE_DEC);
  sbc_ap_proc_sout_dissector_table = register_dissector_table("sbc_ap.proc.sout", "SBC-AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_sbc_ap, FT_UINT32, BASE_DEC);
  sbc_ap_proc_uout_dissector_table = register_dissector_table("sbc_ap.proc.uout", "SBC-AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_sbc_ap, FT_UINT32, BASE_DEC);


}


/*--- proto_reg_handoff_sbc_ap ---------------------------------------*/
void
proto_reg_handoff_sbc_ap(void)
{
    static bool inited = false;
	static unsigned SctpPort;

    if( !inited ) {
        dissector_add_uint("sctp.ppi", SBC_AP_PAYLOAD_PROTOCOL_ID,   sbc_ap_handle);
        inited = true;
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
