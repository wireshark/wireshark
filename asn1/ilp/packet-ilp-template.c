/* packet-ilp.c
 * Routines for OMA Internal Location Protocol packet dissection
 * Copyright 2006, e.yimjia <jy.m12.0@gmail.com>
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
 * ref OMA-TS-ILP-V2_0_1-20121205-A
 * http://www.openmobilealliance.org
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/asn1.h>

#include "packet-per.h"
#include "packet-tcp.h"
#include "packet-gsm_map.h"

#define PNAME  "OMA Internal Location Protocol"
#define PSNAME "ILP"
#define PFNAME "ilp"

void proto_register_ilp(void);

static dissector_handle_t rrlp_handle;
static dissector_handle_t lpp_handle;

/* IANA Registered Ports
 * oma-ilp         7276/tcp    OMA Internal Location
 */
static guint gbl_ilp_port = 7276;

/* Initialize the protocol and registered fields */
static int proto_ilp = -1;


#define ILP_HEADER_SIZE 2

static gboolean ilp_desegment = TRUE;

#include "packet-ilp-hf.c"

/* Initialize the subtree pointers */
static gint ett_ilp = -1;
#include "packet-ilp-ett.c"

/* Include constants */
#include "packet-ilp-val.h"


#include "packet-ilp-fn.c"


static guint
get_ilp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  /* PDU length = Message length */
  return tvb_get_ntohs(tvb,offset);
}

static int
dissect_ilp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  tcp_dissect_pdus(tvb, pinfo, tree, ilp_desegment, ILP_HEADER_SIZE,
                   get_ilp_pdu_len, dissect_ILP_PDU_PDU, data);
  return tvb_captured_length(tvb);
}

void proto_reg_handoff_ilp(void);

/*--- proto_register_ilp -------------------------------------------*/
void proto_register_ilp(void) {

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-ilp-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_ilp,
#include "packet-ilp-ettarr.c"
  };

  module_t *ilp_module;


  /* Register protocol */
  proto_ilp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  new_register_dissector("ilp", dissect_ilp_tcp, proto_ilp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_ilp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  ilp_module = prefs_register_protocol(proto_ilp,proto_reg_handoff_ilp);

  prefs_register_bool_preference(ilp_module, "desegment_ilp_messages",
        "Reassemble ILP messages spanning multiple TCP segments",
        "Whether the ILP dissector should reassemble messages spanning multiple TCP segments."
        " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
        &ilp_desegment);

  /* Register a configuration option for port */
  prefs_register_uint_preference(ilp_module, "tcp.port",
                                 "ILP TCP Port",
                                 "Set the TCP port for ILP messages(IANA registered port is 7276)",
                                 10,
                                 &gbl_ilp_port);

}


/*--- proto_reg_handoff_ilp ---------------------------------------*/
void
proto_reg_handoff_ilp(void)
{
  static gboolean initialized = FALSE;
  static dissector_handle_t ilp_handle;
  static guint local_ilp_port;

  if (!initialized) {
    ilp_handle = find_dissector("ilp");
    dissector_add_string("media_type","application/oma-supl-ilp", ilp_handle);
    rrlp_handle = find_dissector("rrlp");
    lpp_handle = find_dissector("lpp");
    initialized = TRUE;
  } else {
    dissector_delete_uint("tcp.port", local_ilp_port, ilp_handle);
  }

  local_ilp_port = gbl_ilp_port;
  dissector_add_uint("tcp.port", gbl_ilp_port, ilp_handle);
}
