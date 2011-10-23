/* packet-t124.c
 * Routines for t124 packet dissection
 * Copyright 2010, Graeme Lunt
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
#include <epan/conversation.h>

#include <epan/asn1.h>
#include "packet-per.h"
#include "packet-ber.h"
#include "packet-t124.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "GENERIC-CONFERENCE-CONTROL T.124"
#define PSNAME "T.124"
#define PFNAME "t124"

/* Initialize the protocol and registered fields */
static int proto_t124 = -1;
static proto_tree *top_tree = NULL;

#include "packet-t124-hf.c"

/* Initialize the subtree pointers */
static int ett_t124 = -1;
static int ett_t124_connectGCCPDU = -1;

static int hf_t124_ConnectData = -1;
static int hf_t124_connectGCCPDU = -1;
static int hf_t124_DomainMCSPDU_PDU = -1;

static guint32 channelId = -1;

static const char *t124Identifier = NULL; /* extensions identifier */
static tvbuff_t *t124NSIdentifier = NULL; /* extensions non-standard identifier */
static dissector_table_t t124_ns_dissector_table=NULL;
static dissector_table_t t124_sd_dissector_table=NULL;

#include "packet-t124-ett.c"

#include "packet-t124-fn.c"

static const per_sequence_t t124Heur_sequence[] = {
  { &hf_t124_t124Identifier , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Key },
  { NULL, 0, 0, NULL }
};

void
register_t124_ns_dissector(const char *nsKey, dissector_t dissector, int proto)
{
  dissector_handle_t dissector_handle;

  dissector_handle=create_dissector_handle(dissector, proto);
  dissector_add_string("t124.ns", nsKey, dissector_handle);
}

void register_t124_sd_dissector(packet_info *pinfo _U_, guint32 channelId, dissector_t dissector, int proto)
{
  /* XXX: we should keep the sub-dissectors list per conversation
     as the same channels may be used.
     While we are just using RDP over T.124, then we can get away with it.
  */

  dissector_handle_t dissector_handle;

  dissector_handle=create_dissector_handle(dissector, proto);
  dissector_add_uint("t124.sd", channelId, dissector_handle);

}

guint32 t124_get_last_channelId(void)
{
  return channelId;
}

void t124_set_top_tree(proto_tree *tree)
{
  top_tree = tree;
}

int dissect_DomainMCSPDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);

  offset = dissect_t124_DomainMCSPDU(tvb, offset, &asn1_ctx, tree, hf_t124_DomainMCSPDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}

static int
dissect_t124_new(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree)
{
  proto_item *item = NULL;
  proto_tree *tree = NULL;
  asn1_ctx_t asn1_ctx;

  top_tree = parent_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "T.125");
  col_clear(pinfo->cinfo, COL_INFO);

  item = proto_tree_add_item(parent_tree, proto_t124, tvb, 0, tvb_length(tvb), ENC_NA);
  tree = proto_item_add_subtree(item, ett_t124);

  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  dissect_t124_ConnectData(tvb, 0, &asn1_ctx, tree, hf_t124_ConnectData);

  return tvb_length(tvb);
}

static void
dissect_t124(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree)
{
  dissect_t124_new(tvb, pinfo, parent_tree);
}

static gboolean
dissect_t124_heur(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree)
{
  asn1_ctx_t asn1_ctx;

  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);

  t124Identifier = NULL;

  (void) dissect_per_sequence(tvb, 0, &asn1_ctx, NULL, -1, -1, t124Heur_sequence);

  if((t124Identifier != NULL) &&
     (strcmp(t124Identifier, "0.0.20.124.0.1") == 0)) {

    dissect_t124(tvb, pinfo, parent_tree);

  }

  return FALSE;
}

/*--- proto_register_t124 -------------------------------------------*/
void proto_register_t124(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_t124_ConnectData,
      { "ConnectData", "t124.ConnectData",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_connectGCCPDU,
      { "connectGCCPDU", "t124.connectGCCPDU",
        FT_UINT32, BASE_DEC, VALS(t124_ConnectGCCPDU_vals), 0,
        NULL, HFILL }},
    { &hf_t124_DomainMCSPDU_PDU,
      { "DomainMCSPDU", "t124.DomainMCSPDU",
        FT_UINT32, BASE_DEC, VALS(t124_DomainMCSPDU_vals), 0,
        NULL, HFILL }},
#include "packet-t124-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_t124,
	  &ett_t124_connectGCCPDU,
#include "packet-t124-ettarr.c"
  };
  
  /* Register protocol */
  proto_t124 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_t124, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  t124_ns_dissector_table = register_dissector_table("t124.ns", "T.124 H.221 Non Standard Dissectors", FT_STRING, BASE_NONE);
  t124_sd_dissector_table = register_dissector_table("t124.sd", "T.124 H.221 Send Data Dissectors", FT_UINT32, BASE_NONE);

  new_register_dissector("t124", dissect_t124_new, proto_t124);

}

void
proto_reg_handoff_t124(void) {

  register_ber_oid_dissector("0.0.20.124.0.1", dissect_t124, proto_t124, "Generic Conference Control");

  heur_dissector_add("t125", dissect_t124_heur, proto_t124);

}
