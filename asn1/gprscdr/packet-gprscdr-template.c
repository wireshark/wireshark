/* packet-gprscdr-template.c
 * Copyright 2011 , Anders Broman <anders.broman [AT] ericsson.com>
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
 * References: 3GPP TS 32.298
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-gsm_map.h"
#include "packet-gprscdr.h"

#define PNAME  "GPRS CDR"
#define PSNAME "GPRSCDR"
#define PFNAME "gprscdr"

/* Define the GPRS CDR proto */
static int proto_gprscdr = -1;

#include "packet-gprscdr-hf.c"

static int ett_gprscdr = -1;
static int ett_gprscdr_timestamp = -1;
#include "packet-gprscdr-ett.c"

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
#include "packet-gprscdr-ettarr.c"
        };

  proto_gprscdr = proto_register_protocol(PNAME, PSNAME, PFNAME);

  proto_register_field_array(proto_gprscdr, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

/* The registration hand-off routine */

