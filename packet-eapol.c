/* packet-eapol.c
 * Routines for EAPOL 802.1X authentication header disassembly
 *
 * $Id: packet-eapol.c,v 1.6 2002/02/17 00:51:19 guy Exp $
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>
#include <epan/packet.h>
#include "packet-ieee8023.h"
#include "packet-ipx.h"
#include "packet-llc.h"
#include "etypes.h"

static int proto_eapol = -1;
static int hf_eapol_version = -1;
static int hf_eapol_type = -1;
static int hf_eapol_len = -1;

static gint ett_eapol = -1;

static dissector_handle_t data_handle;

typedef struct _e_eapol
{
    guint8 eapol_ver;
    guint8 eapol_type;
    guint16 eapol_len;
} e_eapol;

static const char *eapol_type_name[] = { 
    "EAP",
    "Start",
    "Logoff",
    "Key",
    "Encapsulated ASF Alert"
};
#define EAPOL_TYPE_COUNT (sizeof(eapol_type_name)/sizeof(eapol_type_name[0]))

extern void dissect_eap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void
dissect_eapol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  e_eapol     eapolh;
  guint       len;
  proto_tree *ti;
  proto_tree *volatile eapol_tree;
  tvbuff_t   *next_tvb;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "EAPOL");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  tvb_memcpy(tvb, (guint8 *)&eapolh, 0, sizeof(eapolh));
  eapolh.eapol_len = ntohs(eapolh.eapol_len);

  len = sizeof(eapolh) + eapolh.eapol_len;

  set_actual_length(tvb, len);

  eapol_tree = NULL;

  if (tree) {
    ti = proto_tree_add_item(tree, proto_eapol, tvb, 0, len, FALSE);
    eapol_tree = proto_item_add_subtree(ti, ett_eapol);

    proto_tree_add_uint(eapol_tree, hf_eapol_version, tvb, 0, 1, eapolh.eapol_ver);
    proto_tree_add_text(eapol_tree, tvb, 1, 1, "Type: %s (%u)", 
			eapolh.eapol_type > EAPOL_TYPE_COUNT?
			"Unknown" : eapol_type_name[eapolh.eapol_type],
			eapolh.eapol_type);
    proto_tree_add_uint(eapol_tree, hf_eapol_len,    tvb, 2, 2, eapolh.eapol_len);
  }

  next_tvb = tvb_new_subset(tvb, 4, -1, -1);

  if (eapolh.eapol_type == 0 && next_tvb != NULL) 
      dissect_eap(next_tvb, pinfo, eapol_tree);
  else
      call_dissector(data_handle,tvb_new_subset(tvb, 4,-1,tvb_reported_length_remaining(tvb,4)), pinfo, tree);
}

void
proto_register_eapol(void)
{
  static hf_register_info hf[] = {
	{ &hf_eapol_version, { 
		"Version", "eapol.version", FT_UINT8, BASE_DEC, 
		NULL, 0x0, "", HFILL }},
	{ &hf_eapol_type, { 
		"Type", "eapol.type", FT_UINT8, BASE_DEC, 
		0, 0x0, "", HFILL }},
	{ &hf_eapol_len, {
		"Length", "eapol.len", FT_UINT16, BASE_DEC,
		NULL, 0x0, "Length", HFILL }},
  };
  static gint *ett[] = {
	&ett_eapol,
  };

  proto_eapol = proto_register_protocol("802.1x Authentication", "EAPOL", "eapol");
  proto_register_field_array(proto_eapol, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_eapol(void)
{
  dissector_handle_t eapol_handle;

  data_handle = find_dissector("data");
  eapol_handle = create_dissector_handle(dissect_eapol, proto_eapol);
  dissector_add("ethertype", ETHERTYPE_EAPOL, eapol_handle);
}
