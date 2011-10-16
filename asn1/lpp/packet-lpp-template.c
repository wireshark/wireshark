/* packet-lpp.c
 * Routines for 3GPP LTE Positioning Protocol (LLP) packet dissection
 * Copyright 2011, Pascal Quantin <pascal.quantin@gmail.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Ref 3GPP TS 36.355 version 9.7.0 Release 9
 * http://www.3gpp.org
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/asn1.h>

#include "packet-per.h"

#define PNAME  "LTE Positioning Protocol (LLP)"
#define PSNAME "LPP"
#define PFNAME "lpp"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

/* Initialize the protocol and registered fields */
static int proto_lpp = -1;

#include "packet-lpp-hf.c"

/* Initialize the subtree pointers */
static gint ett_lpp = -1;
#include "packet-lpp-ett.c"

/* Include constants */
#include "packet-lpp-val.h"


#include "packet-lpp-fn.c"


/*--- proto_register_lpp -------------------------------------------*/
void proto_register_lpp(void) {

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-lpp-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_lpp,
#include "packet-lpp-ettarr.c"
  };


  /* Register protocol */
  proto_lpp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  new_register_dissector("lpp", dissect_LPP_Message_PDU, proto_lpp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_lpp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

 
}


/*--- proto_reg_handoff_lpp ---------------------------------------*/
void
proto_reg_handoff_lpp(void)
{

}


