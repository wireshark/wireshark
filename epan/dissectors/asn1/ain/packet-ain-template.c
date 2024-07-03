/* packet-ain-template.c
* Routines for AIN
* Copyright 2018, Anders Broman <anders.broman@ericsson.com>
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
*
* SPDX-License-Identifier: GPL-2.0-or-later
*
* Ref
* GR-1299-CORE
*/

#include "config.h"

#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/expert.h>

#include "packet-ber.h"
#include "packet-ansi_tcap.h"

#if defined(__GNUC__)
/*
 * This is meant to handle dissect_ain_ROS' defined but not used.
 *
 * DIAG_OFF doesn't work with llvm-gcc, for some unknown reason, so
 * we just use the pragma directly.
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif

#define PNAME  "Advanced Intelligent Network"
#define PSNAME "AIN"
#define PFNAME "ain"

void proto_register_ain(void);
void proto_reg_handoff_ain(void);


/* Initialize the protocol and registered fields */
static int proto_ain;

static dissector_handle_t   ain_handle;

/* include constants */
#include "packet-ain-val.h"

static int hf_ain_ext_type_oid;
static int hf_ain_odd_even_indicator;
static int hf_ain_nature_of_address;
static int hf_ain_numbering_plan;
static int hf_ain_bcd_digits;
static int hf_ain_carrier_selection;
static int hf_ain_nature_of_carrier;
static int hf_ain_nr_digits;
static int hf_ain_carrier_bcd_digits;
static int hf_ain_amaslpid;

#include "packet-ain-hf.c"

/* Initialize the subtree pointers */
static int ett_ain;
static int ett_ain_digits;
static int ett_ain_carrierformat;
static int ett_ain_amaslpid;

#include "packet-ain-ett.c"

static expert_field ei_ain_unknown_invokeData;
static expert_field ei_ain_unknown_returnResultData;
static expert_field ei_ain_unknown_returnErrorData;

/* Global variables */
static uint32_t opcode;
static uint32_t errorCode;
//static const char *obj_id = NULL;

static int ain_opcode_type;
#define AIN_OPCODE_INVOKE        1
#define AIN_OPCODE_RETURN_RESULT 2
#define AIN_OPCODE_RETURN_ERROR  3
#define AIN_OPCODE_REJECT        4

/* Forward declarations */
static int dissect_invokeData(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_);
static int dissect_returnResultData(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_);
static int dissect_returnErrorData(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx);

static const value_string ain_np_vals[] = {
    {   0, "Unknown or not applicable"},
    {   1, "ISDN Numbering Plan (ITU Rec. E.164)"},
    {   2, "Telephony Numbering (ITU-T Rec. E.164,E.163)"},
    {   3, "Data Numbering (ITU-T Rec. X.121)"},
    {   4, "Telex Numbering (ITU-T Rec. F.69)"},
    {   5, "Maritime Mobile Numbering"},
    {   6, "Land Mobile Numbering (ITU-T Rec. E.212)"},
    {   7, "Private Numbering Plan"},
    {   0, NULL }
};

static const value_string ain_carrier_selection_vals[] = {
    {   0, "No indication"},
    {   1, "Selected carrier identification code presubscribed and not input by calling party"},
    {   2, "Selected carrier identification code presubscribed and input by calling party"},
    {   3, "Selected carrier identification code presubscribed, no indication of whether input by calling party"},
    {   4, "Selected carrier identification code not presubscribed and input by calling party"},
    {   0, NULL }
};

static const value_string ain_nature_of_carrier_vals[] = {
    {   0, "No NOC Provided"},
    {   1, "local"},
    {   2, "intraLATA toll"},
    {   3, "interLATA"},
    {   4, "local, intraLATA toll and interLATA"},
    {   5, "local and intraLATA toll"},
    {   6, "intraLATA toll and interLATA"},
    {   0, NULL }
};

#include "packet-ain-table.c"

#include "packet-ain-fn.c"

#include "packet-ain-table2.c"


static int
dissect_ain(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
    proto_item *ain_item;
    proto_tree *ain_tree = NULL;
    struct ansi_tcap_private_t *p_private_tcap = (struct ansi_tcap_private_t *)data;
    asn1_ctx_t asn1_ctx;
    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

    /* The TCAP dissector should have provided data but didn't so reject it. */
    if (data == NULL)
        return 0;
    /*
    * Make entry in the Protocol column on summary display
    */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AIN");

    /*
    * create the AIN protocol tree
    */
    ain_item = proto_tree_add_item(parent_tree, proto_ain, tvb, 0, -1, ENC_NA);
    ain_tree = proto_item_add_subtree(ain_item, ett_ain);

    switch (p_private_tcap->d.pdu) {
        /*
        1 : invoke,
        2 : returnResult,
        3 : returnError,
        4 : reject
        */
    case 1:
        opcode = p_private_tcap->d.OperationCode_private;
        /*ansi_map_is_invoke = true;*/
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s Invoke ", val_to_str(opcode, ain_opr_code_strings, "Unknown AIN PDU (%u)"));
        proto_item_append_text(p_private_tcap->d.OperationCode_item, " %s", val_to_str(opcode, ain_opr_code_strings, "Unknown AIN PDU (%u)"));
        dissect_invokeData(ain_tree, tvb, 0, &asn1_ctx);
        /*update_saved_invokedata(pinfo, p_private_tcap);*/
        break;
    //case 2:
    //    opcode = find_saved_invokedata(&asn1_ctx, p_private_tcap);
    //    col_add_fstr(pinfo->cinfo, COL_INFO, "%s ReturnResult ", val_to_str_ext(opcode, &ansi_map_opr_code_strings_ext, "Unknown ANSI-MAP PDU (%u)"));
    //    proto_item_append_text(p_private_tcap->d.OperationCode_item, " %s", val_to_str_ext(opcode, &ansi_map_opr_code_strings_ext, "Unknown ANSI-MAP PDU (%u)"));
    //    dissect_returnData(ain_tree, tvb, 0, &asn1_ctx);
    //    break;
    case 3:
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s ReturnError ", val_to_str(opcode, ain_opr_code_strings, "Unknown AIN PDU (%u)"));
        break;
    case 4:
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s Reject ", val_to_str(opcode, ain_opr_code_strings, "Unknown AIN PDU (%u)"));
        break;
    default:
        /* Must be Invoke ReturnResult ReturnError or Reject */
        DISSECTOR_ASSERT_NOT_REACHED();
        break;
    }

    return tvb_captured_length(tvb);
}

void proto_reg_handoff_ain(void) {

    /*static bool ain_prefs_initialized = false;*/
    /*static range_t *ssn_range;*/

}


void proto_register_ain(void) {
    /* List of fields */

    static hf_register_info hf[] = {


    { &hf_ain_ext_type_oid,
    { "AssignmentAuthority", "ain.ext_type_oid",
    FT_STRING, BASE_NONE, NULL, 0,
    "Type of ExtensionParameter", HFILL } },
    { &hf_ain_odd_even_indicator,
    { "Odd/even indicator",  "ain.odd_even_indicator",
    FT_BOOLEAN, 8, TFS(&tfs_odd_even), 0x80,
    NULL, HFILL } },
    { &hf_ain_nature_of_address,
    { "Nature of address",  "ain.nature_of_address",
    FT_UINT8, BASE_DEC, NULL, 0x7f,
    NULL, HFILL } },
    { &hf_ain_numbering_plan,
    { "Numbering plan",  "ain.numbering_plan",
    FT_UINT8, BASE_DEC, VALS(ain_np_vals), 0x70,
    NULL, HFILL } },
    { &hf_ain_bcd_digits,
    { "BCD digits", "ain.bcd_digits",
    FT_STRING, BASE_NONE, NULL, 0,
    NULL, HFILL } },
    { &hf_ain_carrier_selection,
    { "Carrier Selection",  "ain.carrier_selection",
    FT_UINT8, BASE_DEC, VALS(ain_carrier_selection_vals), 0x0,
    NULL, HFILL } },
    { &hf_ain_nature_of_carrier,
    { "Nature of Carrier",  "ain.nature_of_carrier",
    FT_UINT8, BASE_DEC, VALS(ain_nature_of_carrier_vals), 0xf0,
    NULL, HFILL } },
    { &hf_ain_nr_digits,
    { "Number of Digits",  "ain.nature_of_carrier",
    FT_UINT8, BASE_DEC, NULL, 0x0f,
    NULL, HFILL } },
    { &hf_ain_carrier_bcd_digits,
    { "Carrier digits", "ain.carrier_bcd_digits",
    FT_STRING, BASE_NONE, NULL, 0,
    NULL, HFILL } },
    { &hf_ain_amaslpid,
    { "AMAslpID", "ain.amaslpid",
    FT_STRING, BASE_NONE, NULL, 0,
    NULL, HFILL } },

#include "packet-ain-hfarr.c"
    };

    /* List of subtrees */
    static int *ett[] = {
        &ett_ain,
        &ett_ain_digits,
        &ett_ain_carrierformat,
        &ett_ain_amaslpid,
#include "packet-ain-ettarr.c"
    };

    static ei_register_info ei[] = {
        { &ei_ain_unknown_invokeData,{ "ain.unknown.invokeData", PI_MALFORMED, PI_WARN, "Unknown invokeData", EXPFILL } },
        { &ei_ain_unknown_returnResultData,{ "ain.unknown.returnResultData", PI_MALFORMED, PI_WARN, "Unknown returnResultData", EXPFILL } },
        { &ei_ain_unknown_returnErrorData,{ "ain.unknown.returnErrorData", PI_MALFORMED, PI_WARN, "Unknown returnResultData", EXPFILL } },
    };

    expert_module_t* expert_ain;

    /* Register protocol */
    proto_ain = proto_register_protocol(PNAME, PSNAME, PFNAME);
    ain_handle = register_dissector("ain", dissect_ain, proto_ain);
    /* Register fields and subtrees */
    proto_register_field_array(proto_ain, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ain = expert_register_protocol(proto_ain);
    expert_register_field_array(expert_ain, ei, array_length(ei));

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




