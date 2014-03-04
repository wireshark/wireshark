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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define NEW_PROTO_TREE_API

#include "config.h"

#include <string.h>
#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
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

void proto_reg_handoff_tali(void);
void proto_register_tali(void);

/* Initialize the subtree pointers */
static gint ett_tali = -1;
static gint ett_tali_sync = -1;
static gint ett_tali_opcode = -1;
static gint ett_tali_msu_length = -1;

static header_field_info *hfi_tali = NULL;

#define TALI_HFI_INIT HFI_INIT(proto_tali)

/* Initialize the protocol and registered fields */
static header_field_info hfi_tali_sync_indicator TALI_HFI_INIT =
      { "Sync", "tali.sync", FT_STRING, BASE_NONE, NULL, 0x00, "TALI SYNC", HFILL };

static header_field_info hfi_tali_opcode_indicator TALI_HFI_INIT =
      { "Opcode", "tali.opcode", FT_STRING, BASE_NONE, NULL, 0x00, "TALI Operation Code", HFILL };

static header_field_info hfi_tali_length_indicator TALI_HFI_INIT =
      { "Length", "tali.msu_length", FT_UINT16, BASE_DEC, NULL, 0x00, "TALI MSU Length", HFILL };

static dissector_table_t tali_dissector_table;

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

static int
dissect_tali_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  char opcode[TALI_OPCODE_LENGTH+1]; /* TALI opcode */
  guint16 length; /* TALI length */
  tvbuff_t *payload_tvb = NULL;

  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item *tali_item = NULL;
  proto_tree *tali_tree = NULL;

  tvb_memcpy(tvb, (guint8*)opcode, TALI_SYNC_LENGTH, TALI_OPCODE_LENGTH);
  opcode[TALI_OPCODE_LENGTH] = '\0';
  length = tvb_get_letohs(tvb, TALI_SYNC_LENGTH + TALI_OPCODE_LENGTH);

  /* Make entries in Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "TALI");

  col_set_str(pinfo->cinfo, COL_INFO, "");
  col_append_fstr(pinfo->cinfo, COL_INFO, "[%s] packet, [%u] bytes in payload", opcode, length);

  if (tree) {
    /* create display subtree for the protocol */
    tali_item = proto_tree_add_item(tree, hfi_tali, tvb, 0, TALI_HEADER_LENGTH, ENC_NA);
    tali_tree = proto_item_add_subtree(tali_item, ett_tali);
    proto_tree_add_string(tali_tree, &hfi_tali_sync_indicator,   tvb, 0, TALI_SYNC_LENGTH, TALI_SYNC);
    proto_tree_add_string(tali_tree, &hfi_tali_opcode_indicator, tvb, TALI_SYNC_LENGTH, TALI_OPCODE_LENGTH, opcode);
    proto_tree_add_uint(tali_tree, &hfi_tali_length_indicator, tvb, TALI_SYNC_LENGTH + TALI_OPCODE_LENGTH, TALI_MSU_LENGTH, length);
  }

  if (length > 0) {
    payload_tvb = tvb_new_subset_remaining(tvb, TALI_HEADER_LENGTH);
    if (payload_tvb != NULL && !dissector_try_string(tali_dissector_table, opcode, payload_tvb, pinfo, tree, NULL)) {
      call_dissector(data_handle, payload_tvb, pinfo, tree);
    }
  }

  return tvb_length(tvb);
}

static int
dissect_tali(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  tcp_dissect_pdus(tvb, pinfo, tree, tali_desegment, TALI_HEADER_LENGTH,
                   get_tali_pdu_len, dissect_tali_pdu, data);
  return tvb_length(tvb);
}

/*
 * A 'heuristic dissector' that attemtps to establish whether we have
 * a TALI MSU here.
 * Only works when:
 *	the fixed header is there
 *	it is a 'well-known' operation
 */
static gboolean
dissect_tali_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  char opcode[TALI_OPCODE_LENGTH]; /* TALI opcode */

  if (tvb_reported_length(tvb) < TALI_HEADER_LENGTH)	/* Mandatory header	*/
    return FALSE;

  if (tvb_strneql(tvb, 0, TALI_SYNC, TALI_SYNC_LENGTH) != 0)
    return FALSE;

  tvb_memcpy(tvb, (guint8*)opcode, TALI_SYNC_LENGTH, TALI_OPCODE_LENGTH);
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

  dissect_tali(tvb, pinfo, tree, data);
  return TRUE;
}

void
proto_register_tali(void)
{
#ifndef HAVE_HFI_SECTION_INIT
  static header_field_info *hfi[] = {
    &hfi_tali_sync_indicator,
    &hfi_tali_opcode_indicator,
    &hfi_tali_length_indicator
  };
#endif

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_tali,
    &ett_tali_sync,
    &ett_tali_opcode,
    &ett_tali_msu_length
  };
  module_t *tali_module;

  int proto_tali;

  /* Register the protocol name and description */
  proto_tali = proto_register_protocol("Transport Adapter Layer Interface v1.0, RFC 3094", "TALI", "tali");
  hfi_tali   = proto_registrar_get_nth(proto_tali);

  new_register_dissector("tali", dissect_tali, proto_tali);

  /* Required function calls to register the header fields and subtrees used */
  proto_register_fields(proto_tali, hfi, array_length(hfi));
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
  heur_dissector_add("tcp", dissect_tali_heur, hfi_tali->id);

  data_handle = find_dissector("data");
}

