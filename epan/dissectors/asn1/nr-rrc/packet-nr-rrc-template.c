/* packet-nr-rrc-template.c
 * NR;
 * Radio Resource Control (RRC) protocol specification
 * (3GPP TS 38.331 V15.0.0 Release 15) packet dissection
 * Copyright 2018, Pascal Quantin
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include "config.h"

#include <stdlib.h>

#include <epan/packet.h>
#include <epan/asn1.h>

#include <wsutil/str_util.h>

#include "packet-per.h"
#include "packet-lte-rrc.h"
#include "packet-nr-rrc.h"

#define PNAME  "NR Radio Resource Control (RRC) protocol"
#define PSNAME "NR RRC"
#define PFNAME "nr-rrc"

void proto_register_nr_rrc(void);
void proto_reg_handoff_nr_rrc(void);

/* Include constants */
#include "packet-nr-rrc-val.h"

/* Initialize the protocol and registered fields */
static int proto_nr_rrc = -1;
#include "packet-nr-rrc-hf.c"

/* Initialize the subtree pointers */
static gint ett_nr_rrc = -1;
#include "packet-nr-rrc-ett.c"
static gint ett_nr_rrc_UECapabilityInformation = -1;

/* Forward declarations */
int dissect_nr_rrc_RRCReconfiguration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
#if 0
static int dissect_UE_NR_Capability_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_UE_MRDC_Capability_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

typedef struct {
  guint8 rat_type;
} nr_rrc_private_data_t;

/* Helper function to get or create a struct that will be actx->private_data */
static nr_rrc_private_data_t* nr_rrc_get_private_data(asn1_ctx_t *actx)
{
  if (actx->private_data == NULL) {
    actx->private_data = wmem_new0(wmem_packet_scope(), nr_rrc_private_data_t);
  }
  return (nr_rrc_private_data_t*)actx->private_data;
}

static guint8 private_data_get_rat_type(asn1_ctx_t *actx)
{
  nr_rrc_private_data_t *private_data = (nr_rrc_private_data_t*)nr_rrc_get_private_data(actx);
  return private_data->rat_type;
}

static void private_data_set_rat_type(asn1_ctx_t *actx, guint8 rat_type)
{
  nr_rrc_private_data_t *private_data = (nr_rrc_private_data_t*)nr_rrc_get_private_data(actx);
  private_data->rat_type = rat_type;
}
#endif

#include "packet-nr-rrc-fn.c"

void proto_register_nr_rrc(void) {

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-nr-rrc-hfarr.c"

  };

  static gint *ett[] = {
    &ett_nr_rrc,
#include "packet-nr-rrc-ettarr.c"
    &ett_nr_rrc_UECapabilityInformation
  };

  /* Register protocol */
  proto_nr_rrc = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_nr_rrc, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register the dissectors defined in nr-rrc.cnf */
#include "packet-nr-rrc-dis-reg.c"
}

void
proto_reg_handoff_nr_rrc(void)
{
}
