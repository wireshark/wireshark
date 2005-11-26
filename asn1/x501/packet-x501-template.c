/* packet-x501.c
 * Routines for X.501 (DSA Operational Attributes)  packet dissection
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

#include "packet-x509sat.h"
#include "packet-x509if.h"
#include "packet-dap.h"
#include "packet-dsp.h"


#include "packet-x501.h"

#define PNAME  "X.501 Operational Attributes"
#define PSNAME "X501"
#define PFNAME "x501"

/* Initialize the protocol and registered fields */
int proto_x501 = -1;

#include "packet-x501-hf.c"

/* Initialize the subtree pointers */
static gint ett_x501 = -1;
#include "packet-x501-ett.c"

#include "packet-x501-fn.c"

/*--- proto_register_x501 -------------------------------------------*/
void proto_register_x501(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
#include "packet-x501-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_x501,
#include "packet-x501-ettarr.c"
  };

  /* Register protocol */
  proto_x501 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_x501, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_x501 --- */
void proto_reg_handoff_x501(void) {

#include "packet-x501-dis-tab.c" 

}
