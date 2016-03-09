/* packet-charging_ase-template.c
 * Copyright 2009 , Anders Broman <anders.broman [AT] ericsson.com>
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
 * References: ETSI ES 201 296 V1.3.1 (2003-04)
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-charging_ase.h"

#define PNAME  "Charging ASE"
#define PSNAME "ChargingASE"
#define PFNAME "chargingase"

void proto_register_charging_ase(void);
void proto_reg_handoff_charging_ase(void);

/* Define the Charging ASE proto */
static int proto_charging_ase = -1;

#include "packet-charging_ase-hf.c"

static int ett_charging_ase = -1;
#include "packet-charging_ase-ett.c"

static expert_field ei_charging_ase_extensions_not_dissected = EI_INIT;

static dissector_handle_t charging_ase_handle;

#include "packet-charging_ase-fn.c"

static int
dissect_charging_ase(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *it;
    proto_tree *tr;

    it=proto_tree_add_protocol_format(tree, proto_charging_ase, tvb, 0, -1, "Charging ASE");
    tr=proto_item_add_subtree(it, ett_charging_ase);

    if(tvb_reported_length(tvb)>0)
    {
        dissect_charging_ase_ChargingMessageType_PDU(tvb , pinfo, tr, NULL);
    }
    return tvb_captured_length(tvb);
}

/* Register all the bits needed with the filtering engine */
void
proto_register_charging_ase(void)
{
  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-charging_ase-hfarr.c"
  };

  /* List of subtrees */
    static gint *ett[] = {
    &ett_charging_ase,
#include "packet-charging_ase-ettarr.c"
        };

  static ei_register_info ei[] = {
      { &ei_charging_ase_extensions_not_dissected, { "charging_ase.extensions_not_dissected", PI_UNDECODED, PI_WARN, "Extensions not dissected", EXPFILL }},
  };

  expert_module_t* expert_charging_ase;

  proto_charging_ase = proto_register_protocol(PNAME, PSNAME, PFNAME);

  proto_register_field_array(proto_charging_ase, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_charging_ase = expert_register_protocol(proto_charging_ase);
  expert_register_field_array(expert_charging_ase, ei, array_length(ei));
}

/* The registration hand-off routine */
void
proto_reg_handoff_charging_ase(void)
{
  charging_ase_handle = create_dissector_handle(dissect_charging_ase, proto_charging_ase);
}

