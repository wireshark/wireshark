/* packet-kpm-v2-template.c
 * Copyright 2021, Martin Mathieson
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References: ORAN-WG3.E2SM-KPM-v02.02
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/asn1.h>

#include "packet-e2ap.h"
#include "packet-per.h"
#include "packet-ntp.h"

#define PNAME  "KPM V2"
#define PSNAME "KPMv2"
#define PFNAME "kpm-v2"


void proto_register_kpm_v2(void);
void proto_reg_handoff_kpm_v2(void);


#include "packet-kpm-v2-val.h"

/* Initialize the protocol and registered fields */
static int proto_kpm_v2;
#include "packet-kpm-v2-hf.c"

static int hf_kpm_v2_timestamp_string;


#include "packet-kpm-v2-ett.c"


/* Forward declarations */
static int dissect_E2SM_KPM_EventTriggerDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_KPM_ActionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_KPM_IndicationHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_KPM_IndicationMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_KPM_RANfunction_Description_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

#include "packet-kpm-v2-fn.c"


/*--- proto_reg_handoff_kpm_v2 ---------------------------------------*/
void
proto_reg_handoff_kpm_v2(void)
{
//#include "packet-kpm-v2-dis-tab.c"

    static ran_function_dissector_t kpm_v2 =
    { "ORAN-E2SM-KPM", "1.3.6.1.4.1.53148.1.2.2.2", 2, 2,
      {  dissect_E2SM_KPM_RANfunction_Description_PDU,

         NULL,
         NULL,
         NULL,
         NULL,
         NULL,
         NULL,

         dissect_E2SM_KPM_ActionDefinition_PDU,
         dissect_E2SM_KPM_IndicationMessage_PDU,
         dissect_E2SM_KPM_IndicationHeader_PDU,
         NULL, /* no dissect_E2SM_KPM_CallProcessID_PDU */
         dissect_E2SM_KPM_EventTriggerDefinition_PDU
       }
    };

    /* Register dissector with e2ap */
    register_e2ap_ran_function_dissector(KPM_RANFUNCTIONS, &kpm_v2);
}



/*--- proto_register_kpm_v2 -------------------------------------------*/
void proto_register_kpm_v2(void) {

  /* List of fields */

  static hf_register_info hf[] = {
#include "packet-kpm-v2-hfarr.c"
      { &hf_kpm_v2_timestamp_string,
          { "Timestamp string", "kpm-v2.timestamp-string",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
#include "packet-kpm-v2-ettarr.c"
  };


  /* Register protocol */
  proto_kpm_v2 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_kpm_v2, hf, array_length(hf));
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
