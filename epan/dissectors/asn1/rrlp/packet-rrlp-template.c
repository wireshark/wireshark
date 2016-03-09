/* packet-rrlp.c
 * Routines for 3GPP Radio Resource LCS Protocol (RRLP) packet dissection
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
 * Ref 3GPP TS 44.031 version 11.0.0 Release 11
 * http://www.3gpp.org
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-gsm_a_common.h"

#define PNAME  "Radio Resource LCS Protocol (RRLP)"
#define PSNAME "RRLP"
#define PFNAME "rrlp"



#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

void proto_register_rrlp(void);
void proto_reg_handoff_rrlp(void);

/* Initialize the protocol and registered fields */
static int proto_rrlp = -1;


#include "packet-rrlp-hf.c"

/* Initialize the subtree pointers */
static gint ett_rrlp = -1;
#include "packet-rrlp-ett.c"

/* Include constants */
#include "packet-rrlp-val.h"


#include "packet-rrlp-fn.c"


/*--- proto_register_rrlp -------------------------------------------*/
void proto_register_rrlp(void) {

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-rrlp-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_rrlp,
#include "packet-rrlp-ettarr.c"
  };


  /* Register protocol */
  proto_rrlp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("rrlp", dissect_PDU_PDU, proto_rrlp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_rrlp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));


}


/*--- proto_reg_handoff_rrlp ---------------------------------------*/
void
proto_reg_handoff_rrlp(void)
{

}


