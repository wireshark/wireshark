/* packet-t125.c
 * Routines for t125 packet dissection
 * Copyright 2007, Ronnie Sahlberg
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <epan/asn1.h>
#include "packet-ber.h"
#include "packet-per.h"

#include "packet-t124.h"

#define PNAME  "MULTIPOINT-COMMUNICATION-SERVICE T.125"
#define PSNAME "T.125"
#define PFNAME "t125"


/* Initialize the protocol and registered fields */
static int proto_t125 = -1;
static proto_tree *top_tree = NULL;
#include "packet-t125-hf.c"

/* Initialize the subtree pointers */
static int ett_t125 = -1;

static int hf_t125_connectData = -1;
static int hf_t125_heur = -1;

#include "packet-t125-ett.c"

static heur_dissector_list_t t125_heur_subdissector_list;

#include "packet-t125-fn.c"

static int
dissect_t125(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree)
{
  proto_item *item = NULL;
  proto_tree *tree = NULL;
  gint8 ber_class;
  gboolean pc;
  gint32 tag;

  top_tree = parent_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "T.125");
  col_clear(pinfo->cinfo, COL_INFO);

  item = proto_tree_add_item(parent_tree, proto_t125, tvb, 0, tvb_length(tvb), ENC_NA);
  tree = proto_item_add_subtree(item, ett_t125);

  get_ber_identifier(tvb, 0, &ber_class, &pc, &tag);

  if ( (ber_class==BER_CLASS_APP) && (tag>=101) && (tag<=104) ){
    dissect_ConnectMCSPDU_PDU(tvb, pinfo, tree);
  } else  {
    t124_set_top_tree(top_tree);
    dissect_DomainMCSPDU_PDU(tvb, pinfo, tree);
  }

  return tvb_length(tvb);
}

static gboolean
dissect_t125_heur(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree)
{
  gint8 ber_class;
  gboolean pc;
  gint32 tag;
  guint32 choice_index = 100;
  asn1_ctx_t asn1_ctx;

  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);

  /* could be BER */
  get_ber_identifier(tvb, 0, &ber_class, &pc, &tag);
  /* or PER */
  dissect_per_constrained_integer(tvb, 0, &asn1_ctx,
				  NULL, hf_t125_heur, 0, 42,
				  &choice_index, FALSE);

  /* is this strong enough ? */
  if ( ((ber_class==BER_CLASS_APP) && ((tag>=101) && (tag<=104))) ||
       (choice_index <=42)) {

    dissect_t125(tvb, pinfo, parent_tree);

    return TRUE;
  }

  return FALSE;
}


/*--- proto_register_t125 -------------------------------------------*/
void proto_register_t125(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_t125_connectData,
      { "connectData", "t125.connectData",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t125_heur,
      { "heuristic", "t125.heuristic",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
#include "packet-t125-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_t125,
#include "packet-t125-ettarr.c"
  };

  /* Register protocol */
  proto_t125 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_t125, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_heur_dissector_list("t125", &t125_heur_subdissector_list);

  new_register_dissector("t125", dissect_t125, proto_t125);
}


/*--- proto_reg_handoff_t125 ---------------------------------------*/
void proto_reg_handoff_t125(void) {

  heur_dissector_add("cotp", dissect_t125_heur, proto_t125);
  heur_dissector_add("cotp_is", dissect_t125_heur, proto_t125);
}
