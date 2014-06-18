/* packet-ulp.c
 * Routines for OMA UserPlane Location Protocol packet dissection
 * Copyright 2006, Anders Broman <anders.broman@ericsson.com>
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
 * ref OMA-TS-ULP-V2_0_1-20121205-A
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

#define PNAME  "OMA UserPlane Location Protocol"
#define PSNAME "ULP"
#define PFNAME "ulp"

void proto_register_ulp(void);

static dissector_handle_t rrlp_handle;
static dissector_handle_t lpp_handle;

/* IANA Registered Ports
 * oma-ulp         7275/tcp    OMA UserPlane Location
 * oma-ulp         7275/udp    OMA UserPlane Location
 */
static guint gbl_ulp_tcp_port = 7275;
static guint gbl_ulp_udp_port = 7275;

/* Initialize the protocol and registered fields */
static int proto_ulp = -1;


#define ULP_HEADER_SIZE 2

static gboolean ulp_desegment = TRUE;

#include "packet-ulp-hf.c"

/* Initialize the subtree pointers */
static gint ett_ulp = -1;
#include "packet-ulp-ett.c"

/* Include constants */
#include "packet-ulp-val.h"


#include "packet-ulp-fn.c"


static guint
get_ulp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  /* PDU length = Message length */
  return tvb_get_ntohs(tvb,offset);
}

static int
dissect_ulp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  tcp_dissect_pdus(tvb, pinfo, tree, ulp_desegment, ULP_HEADER_SIZE,
                   get_ulp_pdu_len, dissect_ULP_PDU_PDU, data);
  return tvb_captured_length(tvb);
}

void proto_reg_handoff_ulp(void);

/*--- proto_register_ulp -------------------------------------------*/
void proto_register_ulp(void) {

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-ulp-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_ulp,
#include "packet-ulp-ettarr.c"
  };

  module_t *ulp_module;


  /* Register protocol */
  proto_ulp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  new_register_dissector("ulp", dissect_ulp_tcp, proto_ulp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_ulp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  ulp_module = prefs_register_protocol(proto_ulp,proto_reg_handoff_ulp);

  prefs_register_bool_preference(ulp_module, "desegment_ulp_messages",
    "Reassemble ULP messages spanning multiple TCP segments",
    "Whether the ULP dissector should reassemble messages spanning multiple TCP segments."
    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &ulp_desegment);

  /* Register a configuration option for port */
  prefs_register_uint_preference(ulp_module, "tcp.port",
                                 "ULP TCP Port",
                                 "Set the TCP port for ULP messages (IANA registered port is 7275)",
                                 10,
                                 &gbl_ulp_tcp_port);
  prefs_register_uint_preference(ulp_module, "udp.port",
                                 "ULP UDP Port",
                                 "Set the UDP port for ULP messages (IANA registered port is 7275)",
                                 10,
                                 &gbl_ulp_udp_port);

}


/*--- proto_reg_handoff_ulp ---------------------------------------*/
void
proto_reg_handoff_ulp(void)
{
  static gboolean initialized = FALSE;
  static dissector_handle_t ulp_tcp_handle, ulp_udp_handle;
  static guint local_ulp_tcp_port, local_ulp_udp_port;

  if (!initialized) {
    ulp_tcp_handle = find_dissector("ulp");
    dissector_add_string("media_type","application/oma-supl-ulp", ulp_tcp_handle);
    ulp_udp_handle = new_create_dissector_handle(dissect_ULP_PDU_PDU, proto_ulp);
    rrlp_handle = find_dissector("rrlp");
    lpp_handle = find_dissector("lpp");
    initialized = TRUE;
  } else {
    dissector_delete_uint("tcp.port", local_ulp_tcp_port, ulp_tcp_handle);
    dissector_delete_uint("udp.port", local_ulp_udp_port, ulp_udp_handle);
  }

  local_ulp_tcp_port = gbl_ulp_tcp_port;
  dissector_add_uint("tcp.port", gbl_ulp_tcp_port, ulp_tcp_handle);
  local_ulp_udp_port = gbl_ulp_udp_port;
  dissector_add_uint("udp.port", gbl_ulp_udp_port, ulp_udp_handle);
}

