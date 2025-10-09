/* packet-rc-v3-template.c
 * Copyright 2021, Martin Mathieson
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References: ORAN-WG3.E2SM-rc-v03.05
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <wsutil/array.h>

#include "packet-e2ap.h"
#include "packet-per.h"
#include "packet-ntp.h"

#define PNAME  "RC V3"
#define PSNAME "RCv3"
#define PFNAME "rc-v3"


void proto_register_rc_v3(void);
void proto_reg_handoff_rc_v3(void);


#include "packet-rc-v3-val.h"

/* Initialize the protocol and registered fields */
static int proto_rc_v3;
#include "packet-rc-v3-hf.c"

static int hf_rc_v3_timestamp_string;


#include "packet-rc-v3-ett.c"


/* Forward declarations */
static int dissect_E2SM_RC_EventTrigger_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_ActionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_RANFunctionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_IndicationMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_IndicationHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_CallProcessID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_ControlHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_ControlMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_ControlOutcome_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

static int dissect_E2SM_RC_QueryOutcome_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_QueryDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_QueryHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);



#include "packet-rc-v3-fn.c"


/*--- proto_reg_handoff_rc_v3 ---------------------------------------*/
void
proto_reg_handoff_rc_v3(void)
{
//#include "packet-rc-v3-dis-tab.c"

    static const ran_function_dissector_t rc_v3 =
    { "ORAN-E2SM-RC",  "1.3.6.1.4.1.53148.1.1.2.3", 3, 5,
      {  dissect_E2SM_RC_RANFunctionDefinition_PDU,

         dissect_E2SM_RC_ControlHeader_PDU,
         dissect_E2SM_RC_ControlMessage_PDU,
         dissect_E2SM_RC_ControlOutcome_PDU,
         /* new for v3 */
         dissect_E2SM_RC_QueryOutcome_PDU,
         dissect_E2SM_RC_QueryDefinition_PDU,
         dissect_E2SM_RC_QueryHeader_PDU,

         dissect_E2SM_RC_ActionDefinition_PDU,
         dissect_E2SM_RC_IndicationMessage_PDU,
         dissect_E2SM_RC_IndicationHeader_PDU,
         dissect_E2SM_RC_CallProcessID_PDU,
         dissect_E2SM_RC_EventTrigger_PDU
      }
    };

    /* Register dissector with e2ap */
    register_e2ap_ran_function_dissector(RC_RANFUNCTIONS, &rc_v3);
}



/*--- proto_register_rc_v3 -------------------------------------------*/
void proto_register_rc_v3(void) {

  /* List of fields */

  static hf_register_info hf[] = {
#include "packet-rc-v3-hfarr.c"
      { &hf_rc_v3_timestamp_string,
          { "Timestamp string", "rc-v3.timestamp-string",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
#include "packet-rc-v3-ettarr.c"
  };


  /* Register protocol */
  proto_rc_v3 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_rc_v3, hf, array_length(hf));
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
