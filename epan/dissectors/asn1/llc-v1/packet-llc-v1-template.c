/* packet-llc-v1-template.c
 * Copyright 2025, Martin Mathieson
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References: ORAN-WG3.E2SM-LLC-v01.00
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <wsutil/array.h>

#include "packet-e2ap.h"
#include "packet-per.h"

#define PNAME  "LLC V1"
#define PSNAME "LLCv1"
#define PFNAME "llc-v1"


void proto_register_llc_v1(void);
void proto_reg_handoff_llc_v1(void);


#include "packet-llc-v1-val.h"

/* Initialize the protocol and registered fields */
static int proto_llc_v1;
#include "packet-llc-v1-hf.c"


#include "packet-llc-v1-ett.c"


/* Forward declarations */
static int dissect_E2SM_LLC_RANFunctionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

static int dissect_E2SM_LLC_ControlHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_LLC_ControlMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_LLC_ControlOutcome_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

static int dissect_E2SM_LLC_ActionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_LLC_IndicationMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_LLC_IndicationHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_LLC_EventTrigger_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);


#include "packet-llc-v1-fn.c"


/*--- proto_reg_handoff_llc_v1 ---------------------------------------*/
void
proto_reg_handoff_llc_v1(void)
{
//#include "packet-llc-v1-dis-tab.c"

    static const ran_function_dissector_t llc =
    { "ORAN-E2SM-LLC", "1.3.6.1.4.1.53148.1.1.2.5", 1, 0,
      {  dissect_E2SM_LLC_RANFunctionDefinition_PDU,

         dissect_E2SM_LLC_ControlHeader_PDU,
         dissect_E2SM_LLC_ControlMessage_PDU,
         dissect_E2SM_LLC_ControlOutcome_PDU,

         NULL,
         NULL,
         NULL,

         dissect_E2SM_LLC_ActionDefinition_PDU,
         dissect_E2SM_LLC_IndicationMessage_PDU,
         dissect_E2SM_LLC_IndicationHeader_PDU,
         NULL,
         dissect_E2SM_LLC_EventTrigger_PDU
       }
    };

    /* Register dissector with e2ap */
    register_e2ap_ran_function_dissector(LLC_RANFUNCTIONS, &llc);
}



/*--- proto_register_llc_v1 -------------------------------------------*/
void proto_register_llc_v1(void) {

  /* List of fields */

  static hf_register_info hf[] = {
#include "packet-llc-v1-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
#include "packet-llc-v1-ettarr.c"
  };


  /* Register protocol */
  proto_llc_v1 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_llc_v1, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
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
