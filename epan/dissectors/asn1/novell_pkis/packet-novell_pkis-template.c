/* packet-novell_pkis.c
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
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/oids.h>
#include <epan/conversation.h>
#include <epan/asn1.h>

#include "packet-per.h"
#include "packet-ber.h"

#include "packet-novell_pkis-hf.c"
#include "packet-novell_pkis-ett.c"
#include "packet-novell_pkis-fn.c"

void proto_register_novell_pkis (void);
void proto_reg_handoff_novell_pkis(void);

static int proto_novell_pkis = -1;

void proto_reg_handoff_novell_pkis(void)
{
#include "packet-novell_pkis-dis-tab.c"
}

void proto_register_novell_pkis (void)
{
  static hf_register_info hf[] = {
#include "packet-novell_pkis-hfarr.c"
  };
  static gint *ett[] = {
#include "packet-novell_pkis-ettarr.c"
  };

  /* execute protocol initialization only once */
  if (proto_novell_pkis != -1) return;

  proto_novell_pkis = proto_register_protocol("Novell PKIS ASN.1 type", "novell_pkis", "novell_pkis");
  proto_register_field_array (proto_novell_pkis, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
}
