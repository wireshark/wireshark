/* packet-ip.c
 * Routines for dissassembly of the Hyper SCSI protocol.
 *
 * $Id: packet-hyperscsi.c,v 1.1 2002/11/14 07:55:42 sharpe Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 * Copyright 2002 Richard Sharpe <rsharpe@richardsharpe.com> 
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

#include <stdio.h>
#include <string.h>
#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>

static int proto_hyperscsi;

static int hf_hs_cmd = -1;

static gint ett_hyperscsi = -1; 

static void
dissect_hyperscsi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint     hs_hdr1, hs_hdr2, hs_hdr3;
  guint8    hs_res;
  guint16   hs_tagl;
  guint16   hs_frag;
  guint8    hs_lf; 
  int       offset = 0;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HYPERSCSI");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  hs_hdr1 = tvb_get_guint8(tvb, offset);
  offset++;
  hs_hdr2 = tvb_get_guint8(tvb, offset);
  offset++;
  hs_hdr3 = tvb_get_guint8(tvb, offset);
  offset++;

}

void
proto_register_hyperscsi(void)
{

  static hf_register_info hf[] = {

  };

  static gint *ett[] = {
    &ett_hyperscsi,
  };
  
  proto_hyperscsi = proto_register_protocol("HyperSCSI", "HyperSCSI", "hyperscsi");
  proto_register_field_array(proto_hyperscsi, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("hyperscsi", dissect_hyperscsi, proto_hyperscsi);
}

#define ETHERTYPE_HYPERSCSI 0x889A

void
proto_reg_handoff_hyperscsi(void)
{
  dissector_handle_t hs_handle;

  hs_handle = find_dissector("hyperscsi");
  dissector_add("ethertype", ETHERTYPE_HYPERSCSI, hs_handle);

}
