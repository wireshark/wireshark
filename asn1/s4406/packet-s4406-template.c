/* packet-s4406.c
 * Routines for STANAG 4406 (X.400 Military Message Extensions)  packet dissection
 * Graeme Lunt 2005
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"

#include "packet-x509if.h"

#include "packet-s4406.h"
#include "packet-x411.h" 
#include "packet-x420.h" 

#define PNAME  "STANAG 4406 Military Message Extensions"
#define PSNAME "STANAG 4406"
#define PFNAME "s4406"

/* Initialize the protocol and registered fields */
int proto_s4406 = -1;

#include "packet-s4406-hf.c"

/* Initialize the subtree pointers */
static gint ett_s4406 = -1;
#include "packet-s4406-ett.c"

#include "packet-s4406-fn.c"




/*--- proto_register_s4406 -------------------------------------------*/
void proto_register_s4406(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
#include "packet-s4406-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_s4406,
#include "packet-s4406-ettarr.c"
  };

  /* Register protocol */
  proto_s4406 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_s4406, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_s4406 --- */
void proto_reg_handoff_s4406(void) {
#include "packet-s4406-dis-tab.c"

}
