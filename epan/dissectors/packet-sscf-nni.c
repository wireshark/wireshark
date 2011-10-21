/* packet-sscf-nni.c
 * Routines for SSCF-NNI (Q.2140) frame disassembly
 * Jeff Morriss <jeff.morriss.ws [AT] gmail.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
 *
 * Copied from packet-sscop.c
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

static int proto_sscf = -1;

static gint ett_sscf = -1;

static dissector_handle_t mtp3_handle;

#define SSCF_PDU_LENGTH 4
#define SSCF_STATUS_OFFSET 3
#define SSCF_STATUS_LENGTH 1
#define SSCF_SPARE_OFFSET 0
#define SSCF_SPARE_LENGTH 3

static int hf_status = -1;
static int hf_spare = -1;

#define SSCF_STATUS_OOS	0x01
#define SSCF_STATUS_PO  0x02
#define SSCF_STATUS_IS  0x03
#define SSCF_STATUS_NORMAL 0x04
#define SSCF_STATUS_EMERGENCY 0x05
#define SSCF_STATUS_ALIGNMENT_NOT_SUCCESSFUL 0x7
#define SSCF_STATUS_MANAGEMENT_INITIATED 0x08
#define SSCF_STATUS_PROTOCOL_ERROR 0x09
#define SSCF_STATUS_PROVING_NOT_SUCCESSFUL 0x0a

static const value_string sscf_status_vals[] = {
	{ SSCF_STATUS_OOS,			"Out of Service" },
	{ SSCF_STATUS_PO,			"Processor Outage" },
	{ SSCF_STATUS_IS,			"In Service" },
	{ SSCF_STATUS_NORMAL,			"Normal" },
	{ SSCF_STATUS_EMERGENCY,		"Emergency" },
	{ SSCF_STATUS_ALIGNMENT_NOT_SUCCESSFUL, "Alignment Not Successful" },
	{ SSCF_STATUS_MANAGEMENT_INITIATED,	"Management Initiated" },
	{ SSCF_STATUS_PROTOCOL_ERROR,		"Protocol Error" },
	{ SSCF_STATUS_PROVING_NOT_SUCCESSFUL,	"Proving Not Successful" },
	{ 0,					NULL }
};

static void
dissect_sscf_nni(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint reported_length;
  proto_item *sscf_item = NULL;
  proto_tree *sscf_tree = NULL;
  guint8 sscf_status;

  reported_length = tvb_reported_length(tvb);	/* frame length */

  if (tree) {
    sscf_item = proto_tree_add_item(tree, proto_sscf, tvb, 0, -1, ENC_NA);
    sscf_tree = proto_item_add_subtree(sscf_item, ett_sscf);
  }

  if (reported_length > SSCF_PDU_LENGTH)
  {
    call_dissector(mtp3_handle, tvb, pinfo, tree);

  } else {

    sscf_status = tvb_get_guint8(tvb, SSCF_STATUS_OFFSET);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSCF-NNI");
    if (check_col(pinfo->cinfo, COL_INFO))
      col_add_fstr(pinfo->cinfo, COL_INFO, "STATUS (%s) ",
		   val_to_str(sscf_status, sscf_status_vals, "Unknown"));


    proto_tree_add_item(sscf_tree, hf_status, tvb, SSCF_STATUS_OFFSET,
			SSCF_STATUS_LENGTH, ENC_BIG_ENDIAN);
    proto_tree_add_item(sscf_tree, hf_spare, tvb, SSCF_SPARE_OFFSET,
			SSCF_SPARE_LENGTH, ENC_BIG_ENDIAN);
  }

}

void
proto_register_sscf(void)
{
  static hf_register_info hf[] =
  { { &hf_status, { "Status", "sscf-nni.status", FT_UINT8, BASE_HEX,
		    VALS(sscf_status_vals), 0x0, NULL, HFILL} },
    { &hf_spare, { "Spare", "sscf-nni.spare", FT_UINT24, BASE_HEX,
		    NULL, 0x0, NULL, HFILL} }
  };

  static gint *ett[] = {
    &ett_sscf,
  };

  proto_sscf = proto_register_protocol("SSCF-NNI", "SSCF-NNI", "sscf-nni");

  proto_register_field_array(proto_sscf, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("sscf-nni", dissect_sscf_nni, proto_sscf);

}

void
proto_reg_handoff_sscf(void)
{
  mtp3_handle = find_dissector("mtp3");
}
