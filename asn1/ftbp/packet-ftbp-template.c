/* packet-ftbp.c
 * Routines for File Transfer Body Part (FTBP) dissection (used in X.420 content)
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

#include "packet-acse.h"
#include "packet-ftam.h"
#include "packet-x411.h" 
#include "packet-x420.h" 

#include "packet-ftbp.h"

#define PNAME  "X.420 File Transfer Body Part"
#define PSNAME "FTBP"
#define PFNAME "ftbp"

/* Initialize the protocol and registered fields */
int proto_ftbp = -1;

#include "packet-ftbp-hf.c"

/* Initialize the subtree pointers */
static gint ett_ftbp = -1;
#include "packet-ftbp-ett.c"

#include "packet-ftbp-fn.c"


/*--- proto_register_ftbp -------------------------------------------*/
void proto_register_ftbp(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
#include "packet-ftbp-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_ftbp,
#include "packet-ftbp-ettarr.c"
  };

  /* Register protocol */
  proto_ftbp = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_ftbp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_ftbp --- */
void proto_reg_handoff_ftbp(void) {
#include "packet-ftbp-dis-tab.c"

}
