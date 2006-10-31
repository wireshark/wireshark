/* packet-tali.c
 *
 * Routines for Transport Adapter Layer Interface (TALI) version 1.0 dissection (RFC 3094)
 *
 * Copyright : 2004 Viorel Suman, <vsuman[AT]avmob.ro>
 *             In association with Avalanche Mobile BV, http://www.avmob.com
 *
 * Dissector of a TALI (Transport Adapter Layer Interface) version 1.0, as defined by the
 * Tekelec (www.tekelec.com) in RFC 3094, http://www.ietf.org/rfc/rfc3094.txt
 *
 * $Id$
 *
 * Refer to the AUTHORS file or the AUTHORS section in the man page
 * for contacting the author(s) of this file.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include "packet-tcp.h"

#define TALI_SYNC_LENGTH    4
#define TALI_OPCODE_LENGTH  4
#define TALI_MSU_LENGTH     2
#define TALI_HEADER_LENGTH  TALI_SYNC_LENGTH + TALI_OPCODE_LENGTH + TALI_MSU_LENGTH

#define TALI_SYNC "TALI"
#define TALI_TEST "test"
#define TALI_ALLO "allo"
#define TALI_PROH "proh"
#define TALI_PROA "proa"
#define TALI_MONI "moni"
#define TALI_MONA "mona"
#define TALI_SCCP "sccp"
#define TALI_ISOT "isot"
#define TALI_MTP3 "mtp3"
#define TALI_SAAL "saal"

/* Initialize the subtree pointers */
static gint ett_tali = -1;
static gint ett_tali_sync = -1;
static gint ett_tali_opcode = -1;
static gint ett_tali_msu_length = -1;

static int proto_tali  = -1;
static dissector_handle_t tali_handle;
static dissector_table_t tali_dissector_table;

/* Initialize the protocol and registered fields */
static int hf_tali_sync_indicator = -1;
static int hf_tali_opcode_indicator = -1;
static int hf_tali_length_indicator = -1;

static dissector_handle_t data_handle;

/* Desegment TALI messages */
static gboolean tali_desegment = TRUE;

/* Code to actually dissect the packets */
static guint
get_tali_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  guint16 length;

  length = tvb_get_letohs(tvb, offset + TALI_SYNC_LENGTH + TALI_OPCODE_LENGTH);
  return length+TALI_HEADER_LENGTH;
}

static void
dissect_tali_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  char opcode[TALI_OPCODE_LENGTH+1]; /* TALI opcode */
  guint16 length; /* TALI length */
  tvbuff_t *payload_tvb = NULL;
  
  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item *tali_item = NULL;
  proto_tree *tali_tree = NULL;
  
  tvb_memcpy(tvb, opcode, TALI_SYNC_LENGTH, TALI_OPCODE_LENGTH);
  opcode[TALI_OPCODE_LENGTH] = '\0';
  length = tvb_get_letohs(tvb, TALI_SYNC_LENGTH + TALI_OPCODE_LENGTH);

  /* Make entries in Protocol column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TALI");
  
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_set_str(pinfo->cinfo, COL_INFO, "");
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s] packet, [%u] bytes in payload", opcode, length);
  }

  if (tree) {
    /* create display subtree for the protocol */
    tali_item = proto_tree_add_item(tree, proto_tali, tvb, 0, TALI_HEADER_LENGTH, TRUE);
    tali_tree = proto_item_add_subtree(tali_item, ett_tali);
    proto_tree_add_string(tali_tree, hf_tali_sync_indicator,   tvb, 0, TALI_SYNC_LENGTH, TALI_SYNC);
    proto_tree_add_string(tali_tree, hf_tali_opcode_indicator, tvb, TALI_SYNC_LENGTH, TALI_OPCODE_LENGTH, opcode);
    proto_tree_add_uint(tali_tree, hf_tali_length_indicator, tvb, TALI_SYNC_LENGTH + TALI_OPCODE_LENGTH, TALI_MSU_LENGTH, length);
  }

  if (length > 0) {
    payload_tvb = tvb_new_subset(tvb, TALI_HEADER_LENGTH, -1, -1);
    if (payload_tvb != NULL && !dissector_try_string(tali_dissector_table, opcode, payload_tvb, pinfo, tree)) {
      call_dissector(data_handle, payload_tvb, pinfo, tree);
    }
  }
}

static void
dissect_tali(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tcp_dissect_pdus(tvb, pinfo, tree, tali_desegment, TALI_HEADER_LENGTH,
                   get_tali_pdu_len, dissect_tali_pdu);
}

/*
 * A 'heuristic dissector' that attemtps to establish whether we have
 * a TALI MSU here.
 * Only works when:
 *	the fixed header is there
 *	it is a 'well-known' operation
 */
static gboolean
dissect_tali_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  char sync[TALI_SYNC_LENGTH];     /* TALI sync */
  char opcode[TALI_OPCODE_LENGTH]; /* TALI opcode */

  if (tvb_reported_length(tvb) < TALI_HEADER_LENGTH)	/* Mandatory header	*/
    return FALSE;

  tvb_memcpy(tvb, sync, 0, TALI_SYNC_LENGTH);
  if (strncmp(sync, TALI_SYNC, TALI_SYNC_LENGTH) != 0)
    return FALSE;

  tvb_memcpy(tvb, opcode, TALI_SYNC_LENGTH, TALI_OPCODE_LENGTH);
  if (strncmp(opcode, TALI_TEST, TALI_OPCODE_LENGTH) != 0 &&
      strncmp(opcode, TALI_ALLO, TALI_OPCODE_LENGTH) != 0 &&
      strncmp(opcode, TALI_PROH, TALI_OPCODE_LENGTH) != 0 &&
      strncmp(opcode, TALI_PROA, TALI_OPCODE_LENGTH) != 0 &&
      strncmp(opcode, TALI_MONI, TALI_OPCODE_LENGTH) != 0 &&
      strncmp(opcode, TALI_MONA, TALI_OPCODE_LENGTH) != 0 &&
      strncmp(opcode, TALI_SCCP, TALI_OPCODE_LENGTH) != 0 &&
      strncmp(opcode, TALI_ISOT, TALI_OPCODE_LENGTH) != 0 &&
      strncmp(opcode, TALI_MTP3, TALI_OPCODE_LENGTH) != 0 &&
      strncmp(opcode, TALI_SAAL, TALI_OPCODE_LENGTH) != 0)
    return FALSE;

  dissect_tali(tvb, pinfo, tree);
  return TRUE;
}

void
proto_register_tali(void)
{
  static hf_register_info hf[] = {
    { &hf_tali_sync_indicator,
      { "Sync", "tali.sync", FT_STRING, BASE_NONE, NULL, 0x00, "TALI SYNC", HFILL }},
    { &hf_tali_opcode_indicator,
      { "Opcode", "tali.opcode", FT_STRING, BASE_NONE, NULL, 0x00, "TALI Operation Code", HFILL }},
    { &hf_tali_length_indicator,
      { "Length", "tali.msu_length", FT_UINT16, BASE_DEC, NULL, 0x00, "TALI MSU Length", HFILL }}
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_tali,
    &ett_tali_sync,
    &ett_tali_opcode,
    &ett_tali_msu_length
  };
  module_t *tali_module;

  /* Register the protocol name and description */
  proto_tali = proto_register_protocol("Transport Adapter Layer Interface v1.0, RFC 3094", "TALI", "tali");
  register_dissector("tali", dissect_tali, proto_tali);
  tali_handle = create_dissector_handle(dissect_tali, proto_tali);
  
  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_tali, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  tali_dissector_table = register_dissector_table("tali.opcode", "Tali OPCODE", FT_STRING, BASE_NONE);

  tali_module = prefs_register_protocol(proto_tali, NULL);
  prefs_register_bool_preference(tali_module, "reassemble",
	"Reassemble TALI messages spanning multiple TCP segments",
	"Whether the TALI dissector should reassemble messages spanning multiple TCP segments."
	" To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &tali_desegment);
}

void
proto_reg_handoff_tali(void)
{
  heur_dissector_add("tcp", dissect_tali_heur, proto_tali);

  data_handle = find_dissector("data");
}

