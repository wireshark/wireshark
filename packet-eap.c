/* packet-eap.c
 * Routines for EAP Extensible Authentication Protocol header disassembly
 *
 * $Id: packet-eap.c,v 1.2 2001/11/26 04:52:49 hagbard Exp $
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
#include "packet.h"
#include "packet-ieee8023.h"
#include "packet-ipx.h"
#include "packet-llc.h"
#include "etypes.h"
#include "ppptypes.h"

static int proto_eap = -1;
static int hf_eap_code = -1;
static int hf_eap_identifier = -1;
static int hf_eap_len = -1;
static int hf_eap_type = -1;

static gint ett_eap = -1;

static dissector_handle_t data_handle;

typedef struct _e_eap {
    guint8 eap_code;
    guint8 eap_id;
    guint16 eap_len;
} e_eap;

static const char *eap_code_name[] = { 
    "Undefined",
    "Request",
    "Response",
    "Success",
    "Failure",
};
#define EAP_CODE_COUNT (sizeof(eap_code_name)/sizeof(eap_code_name[0]))

static const char *eap_type_name[] = { 
    "Undefined",
    "Identity",
    "Nak (Response only)",
    "MD5-Challenge",
    "One-Time Password",
    "Generic Token Card",
};
#define EAP_TYPE_COUNT (sizeof(eap_type_name)/sizeof(eap_type_name[0]))


void
dissect_eap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  e_eap       eaph;
  guint       len;
  proto_tree *ti;
  proto_tree *volatile eap_tree;

  if (check_col(pinfo->fd, COL_PROTOCOL))
    col_set_str(pinfo->fd, COL_PROTOCOL, "EAP");
  if (check_col(pinfo->fd, COL_INFO))
    col_clear(pinfo->fd, COL_INFO);

  tvb_memcpy(tvb, (guint8 *)&eaph, 0, sizeof(eaph));
  eaph.eap_len = ntohs(eaph.eap_len);

  len = eaph.eap_len;

  set_actual_length(tvb, pinfo, len);

  eap_tree = NULL;

  if (tree) {
    ti = proto_tree_add_item(tree, proto_eap, tvb, 0, len, FALSE);
    eap_tree = proto_item_add_subtree(ti, ett_eap);

    proto_tree_add_text(eap_tree, tvb, 0, 0, "Code: %s (%u) ", 
			eaph.eap_code > EAP_CODE_COUNT?
			"Unknown": eap_code_name[eaph.eap_code],
			eaph.eap_code);

    proto_tree_add_uint(eap_tree, hf_eap_identifier, tvb, 1, 1, eaph.eap_id);
    proto_tree_add_uint(eap_tree, hf_eap_len,    tvb, 2, 2, eaph.eap_len);

    if (len > 4) {
	guint8 eap_type = tvb_get_guint8(tvb, 4);
	proto_tree_add_text(eap_tree, tvb, 4, 1, "Type: %s (%u)", 
			    eap_type > EAP_TYPE_COUNT?
			    "Unknown" : eap_type_name[eap_type],
			    eap_type);
    }
    if (len > 5)
      call_dissector(data_handle,tvb_new_subset(tvb, 5,-1,tvb_reported_length_remaining(tvb,5)), pinfo, tree);
  }
}

void
proto_register_eap(void)
{
  static hf_register_info hf[] = {
	{ &hf_eap_code, { 
		"Code", "eap.code", FT_UINT8, BASE_DEC, 
		NULL, 0x0, "", HFILL }},
	{ &hf_eap_identifier, {
		"Id", "eap.id", FT_UINT8, BASE_DEC,
		NULL, 0x0, "", HFILL }},
	{ &hf_eap_len, {
		"Length", "eap.len", FT_UINT16, BASE_DEC,
		NULL, 0x0, "", HFILL }},
	{ &hf_eap_type, { 
		"Type", "eap.type", FT_UINT8, BASE_DEC, 
		NULL, 0x0, "", HFILL }},
  };
  static gint *ett[] = {
	&ett_eap,
  };

  proto_eap = proto_register_protocol("Extensible Authentication Protocol", 
				      "EAP", "eap");
  proto_register_field_array(proto_eap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_eap(void)
{
  data_handle = find_dissector("data");
  dissector_add("ppp.protocol", PPP_EAP, dissect_eap, proto_eap);
}
