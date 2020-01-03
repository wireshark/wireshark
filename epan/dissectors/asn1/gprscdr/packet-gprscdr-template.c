/* packet-gprscdr-template.c
 * Copyright 2011 , Anders Broman <anders.broman [AT] ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 * References: 3GPP TS 32.298 V14.0.0
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-gsm_map.h"
#include "packet-gsm_a_common.h"
#include "packet-e212.h"
#include "packet-gprscdr.h"
#include "packet-gtp.h"
#include "packet-gtpv2.h"

#define PNAME  "GPRS CDR"
#define PSNAME "GPRSCDR"
#define PFNAME "gprscdr"

void proto_register_gprscdr(void);

/* Define the GPRS CDR proto */
static int proto_gprscdr = -1;

#include "packet-gprscdr-hf.c"

static int ett_gprscdr = -1;
static int ett_gprscdr_timestamp = -1;
static int ett_gprscdr_plmn_id = -1;
static int ett_gprscdr_pdp_pdn_type = -1;
static int ett_gprscdr_eps_qos_arp = -1;
static int ett_gprscdr_managementextension_information = -1;
static int ett_gprscdr_userlocationinformation = -1;
#include "packet-gprscdr-ett.c"

static expert_field ei_gprscdr_not_dissected = EI_INIT;
static expert_field ei_gprscdr_choice_not_found = EI_INIT;

/* Global variables */
static const char *obj_id = NULL;

static const value_string gprscdr_daylight_saving_time_vals[] = {
    {0, "No adjustment"},
    {1, "+1 hour adjustment for Daylight Saving Time"},
    {2, "+2 hours adjustment for Daylight Saving Time"},
    {3, "Reserved"},
    {0, NULL}
};

/* 3GPP-RAT-Type
*  3GPP TS 29.061
*/
static const value_string gprscdr_rat_type_vals[] = {
    {0, "Reserved"},
    {1, "UTRAN"},
    {2, "GERAN"},
    {3, "WLAN"},
    {4, "GAN"},
    {5, "HSPA Evolution"},
    {6, "EUTRAN"},
    {7, "Virtual"},
    {8, "EUTRAN-NB-IoT"},
    {9, "LTE-M"},
    {10, "NR"},
    /* 11-100 Spare for future use TS 29.061 */
    {101, "IEEE 802.16e"},
    {102, "3GPP2 eHRPD"},
    {103, "3GPP2 HRPD"},
    /* 104-255 Spare for future use TS 29.061 */
    {0, NULL}
};

static int
dissect_gprscdr_uli(tvbuff_t *tvb _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int type) {
  proto_tree *ext_tree_uli;
  guint       length;

  length = tvb_reported_length(tvb);
  ext_tree_uli = proto_tree_add_subtree(tree, tvb, 0, length, ett_gprscdr_userlocationinformation, NULL, "UserLocationInformation");

  switch (type) {
  case 1:
      /* For GGSN/EGGSN-CDR,
       * this octet string is a 1:1 copy of the contents (i.e. starting with octet 4) of the
       * User Location Information (ULI) information element specified in 29.060, ch7.7.51.
       */
      dissect_gtp_uli(tvb, 0, actx->pinfo, ext_tree_uli, NULL);
      break;
  case 2:
      /* For SGW/PGW-CDR,
       * this octet string is a 1:1 copy of the contents (i.e. starting with octet 5) of the
       * User Location Information (ULI) information element specified in 29.274, ch8.21.
       */
      dissect_gtpv2_uli(tvb, actx->pinfo, ext_tree_uli, NULL, length, 0, 0, NULL);
      break;
  default:
      proto_tree_add_expert(ext_tree_uli, actx->pinfo, &ei_gprscdr_not_dissected, tvb, 0, length);
      break;
  }

  return length;
}

#include "packet-gprscdr-fn.c"



/* Register all the bits needed with the filtering engine */
void
proto_register_gprscdr(void)
{
  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-gprscdr-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_gprscdr,
    &ett_gprscdr_timestamp,
    &ett_gprscdr_plmn_id,
    &ett_gprscdr_pdp_pdn_type,
    &ett_gprscdr_eps_qos_arp,
    &ett_gprscdr_managementextension_information,
    &ett_gprscdr_userlocationinformation,
#include "packet-gprscdr-ettarr.c"
        };

  static ei_register_info ei[] = {
    { &ei_gprscdr_not_dissected, { "gprscdr.not_dissected", PI_UNDECODED, PI_WARN, "Not dissected", EXPFILL }},
    { &ei_gprscdr_choice_not_found, { "gprscdr.error.choice_not_found", PI_MALFORMED, PI_WARN, "GPRS CDR Error: This choice field(Record type) was not found", EXPFILL }},
  };

  expert_module_t* expert_gprscdr;

  proto_gprscdr = proto_register_protocol(PNAME, PSNAME, PFNAME);

  proto_register_field_array(proto_gprscdr, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_gprscdr = expert_register_protocol(proto_gprscdr);
  expert_register_field_array(expert_gprscdr, ei, array_length(ei));
}

/* The registration hand-off routine */

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
