/* packet-lppa.c
 * Routines for 3GPP LTE Positioning Protocol A (LLPa) packet dissection
 * Copyright 2011-2019, Pascal Quantin <pascal@wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref 3GPP TS 36.455 version 15.2.1 Release 15
 * http://www.3gpp.org
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/proto_data.h>
#include <epan/asn1.h>

#include "packet-per.h"
#include "packet-lppa.h"

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

enum {
    INITIATING_MESSAGE,
    SUCCESSFUL_OUTCOME,
    UNSUCCESSFUL_OUTCOME
};

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

struct lppa_private_data {
    guint32 procedure_code;
    guint32 protocol_ie_id;
    guint32 protocol_extension_id;
    guint32 message_type;
};

static struct lppa_private_data*
lppa_get_private_data(packet_info* pinfo)
{
    struct lppa_private_data* lppa_data = (struct lppa_private_data*)p_get_proto_data(pinfo->pool, pinfo, proto_lppa, 0);
    if (!lppa_data) {
        lppa_data = wmem_new0(pinfo->pool, struct lppa_private_data);
        p_add_proto_data(pinfo->pool, pinfo, proto_lppa, 0, lppa_data);
    }
    return lppa_data;
}

#include "packet-lppa-fn.c"


static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

    lppa_ctx_t lppa_ctx;
    struct lppa_private_data* lppa_data = lppa_get_private_data(pinfo);

    lppa_ctx.message_type = lppa_data->message_type;
    lppa_ctx.ProcedureCode = lppa_data->procedure_code;
    lppa_ctx.ProtocolIE_ID = lppa_data->protocol_ie_id;
    lppa_ctx.ProtocolExtensionID = lppa_data->protocol_extension_id;

  return (dissector_try_uint_new(lppa_ies_dissector_table, lppa_ctx.ProtocolIE_ID, tvb, pinfo, tree, FALSE, &lppa_ctx)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    struct lppa_private_data* lppa_data = lppa_get_private_data(pinfo);
    return (dissector_try_uint_new(lppa_proc_imsg_dissector_table, lppa_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    struct lppa_private_data* lppa_data = lppa_get_private_data(pinfo);
    return (dissector_try_uint_new(lppa_proc_sout_dissector_table, lppa_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    struct lppa_private_data* lppa_data = lppa_get_private_data(pinfo);

    return (dissector_try_uint_new(lppa_proc_uout_dissector_table, lppa_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
}

/*--- proto_register_lppa -------------------------------------------*/
void proto_register_lppa(void) {

    /* List of fields */
    static hf_register_info hf[] = {

  #include "packet-lppa-hfarr.c"
    };

    /* List of subtrees */
    static gint* ett[] = {
        &ett_lppa,
  #include "packet-lppa-ettarr.c"
    };

    /* Register protocol */
    proto_lppa = proto_register_protocol(PNAME, PSNAME, PFNAME);
    register_dissector("lppa", dissect_LPPA_PDU_PDU, proto_lppa);

    /* Register fields and subtrees */
    proto_register_field_array(proto_lppa, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register dissector tables */
    lppa_ies_dissector_table = register_dissector_table("lppa.ies", "LPPA-PROTOCOL-IES", proto_lppa, FT_UINT32, BASE_DEC);
    lppa_proc_imsg_dissector_table = register_dissector_table("lppa.proc.imsg", "LPPA-ELEMENTARY-PROCEDURE InitiatingMessage", proto_lppa, FT_UINT32, BASE_DEC);
    lppa_proc_sout_dissector_table = register_dissector_table("lppa.proc.sout", "LPPA-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_lppa, FT_UINT32, BASE_DEC);
    lppa_proc_uout_dissector_table = register_dissector_table("lppa.proc.uout", "LPPA-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_lppa, FT_UINT32, BASE_DEC);
}

/*--- proto_reg_handoff_lppa ---------------------------------------*/
void
proto_reg_handoff_lppa(void)
{
#include "packet-lppa-dis-tab.c"
}
