/* packet-credssp.c
 * Routines for CredSSP (Credential Security Support Provider) packet dissection
 * Graeme Lunt 2011
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-credssp.h"


#define PNAME  "Credential Security Support Provider"
#define PSNAME "CredSSP"
#define PFNAME "credssp"

#define TS_PASSWORD_CREDS   1
#define TS_SMARTCARD_CREDS  2
static gint creds_type;

/* Initialize the protocol and registered fields */
static int proto_credssp = -1;

/* List of dissectors to call for negoToken data */
static heur_dissector_list_t credssp_heur_subdissector_list;

static int hf_credssp_TSPasswordCreds = -1;   /* TSPasswordCreds */
static int hf_credssp_TSSmartCardCreds = -1;  /* TSSmartCardCreds */
static int hf_credssp_TSCredentials = -1;     /* TSCredentials */
#include "packet-credssp-hf.c"

/* Initialize the subtree pointers */
static gint ett_credssp = -1;
#include "packet-credssp-ett.c"

#include "packet-credssp-fn.c"

/*
* Dissect CredSSP PDUs
*/
static void
dissect_credssp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_credssp, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_credssp);
	}
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CredSSP");
  	col_clear(pinfo->cinfo, COL_INFO);

	creds_type = -1;
	dissect_TSRequest_PDU(tvb, pinfo, tree);
}

static gboolean
dissect_credssp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
  asn1_ctx_t asn1_ctx;
  int offset = 0;
  gint8 class;
  gboolean pc;
  gint32 tag;
  guint32 length;

  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

  /* Look for SEQUENCE, CONTEXT 0, and INTEGER 2 */  
  if(tvb_length(tvb) > 7) {
    offset = get_ber_identifier(tvb, offset, &class, &pc, &tag); 
    if((class == BER_CLASS_UNI) && (tag == BER_UNI_TAG_SEQUENCE) && (pc == TRUE)) {
      offset = get_ber_length(tvb, offset, NULL, NULL);
      offset = get_ber_identifier(tvb, offset, &class, &pc, &tag); 
      if((class == BER_CLASS_CON) && (tag == 0)) {
	offset = get_ber_length(tvb, offset, NULL, NULL);
	offset = get_ber_identifier(tvb, offset, &class, &pc, &tag); 
	if((class == BER_CLASS_UNI) && (tag == BER_UNI_TAG_INTEGER)) {
	  offset = get_ber_length(tvb, offset, &length, NULL);
	  if((length == 1) && (tvb_get_guint8(tvb, offset) == 2)) {
	    dissect_credssp(tvb, pinfo, parent_tree);
	    return TRUE;
	  }
	}
      }
    }
  }
  return FALSE;
}


/*--- proto_register_credssp -------------------------------------------*/
void proto_register_credssp(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
    { &hf_credssp_TSPasswordCreds,
      { "TSPasswordCreds", "credssp.TSPasswordCreds",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_credssp_TSSmartCardCreds,
      { "TSSmartCardCreds", "credssp.TSSmartCardCreds",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_credssp_TSCredentials,
      { "TSCredentials", "credssp.TSCredentials",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
#include "packet-credssp-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_credssp,
#include "packet-credssp-ettarr.c"
  };


  /* Register protocol */
  proto_credssp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("credssp", dissect_credssp, proto_credssp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_credssp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* heuristic dissectors for any premable e.g. CredSSP before RDP */
  register_heur_dissector_list("credssp", &credssp_heur_subdissector_list);

}


/*--- proto_reg_handoff_credssp --- */
void proto_reg_handoff_credssp(void) {

  heur_dissector_add("ssl", dissect_credssp_heur, proto_credssp);

}

