/* packet-tali.c
 *
 * Routines for Transport Adapter Layer Interface (TALI) version 1.0 dissection (RFC 3094)
 *
 * Copyright : 2004 Viorel Suman, <vsuman[AT]avmob.ro>
 *             In association with Avalanche Mobile BV, http://www.avmob.com
 *
 * Dissector of a TALI (Transport Adapter Layer Interface) version 1.0, as defined by the
 * Tekelec (www.tekelec.com) in RFC 3094, https://www.ietf.org/rfc/rfc3094
 *
 * Refer to the AUTHORS file or the AUTHORS section in the man page
 * for contacting the author(s) of this file.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

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

static int proto_tali;

static int hf_tali_length_indicator;
static int hf_tali_opcode_indicator;
static int hf_tali_sync_indicator;

/* Initialize the subtree pointers */
static int ett_tali;
static int ett_tali_sync;
static int ett_tali_opcode;
static int ett_tali_msu_length;

static dissector_table_t tali_dissector_table;

/* Desegment TALI messages */
static bool tali_desegment = true;

/* Code to actually dissect the packets */
static unsigned
get_tali_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
  uint16_t length;

  length = tvb_get_letohs(tvb, offset + TALI_SYNC_LENGTH + TALI_OPCODE_LENGTH);
  return length+TALI_HEADER_LENGTH;
}

static int
dissect_tali_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  char *opcode; /* TALI opcode */
  uint16_t length; /* TALI length */
  tvbuff_t *payload_tvb = NULL;

  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item *tali_item = NULL;
  proto_tree *tali_tree = NULL;

  opcode = (char *) tvb_get_string_enc(pinfo->pool, tvb, TALI_SYNC_LENGTH, TALI_OPCODE_LENGTH, ENC_ASCII|ENC_NA);
  length = tvb_get_letohs(tvb, TALI_SYNC_LENGTH + TALI_OPCODE_LENGTH);

  /* Make entries in Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "TALI");

  col_clear(pinfo->cinfo, COL_INFO);
  col_append_fstr(pinfo->cinfo, COL_INFO, "[%s] packet, [%u] bytes in payload", opcode, length);

  if (tree) {
    /* create display subtree for the protocol */
    tali_item = proto_tree_add_item(tree, proto_tali, tvb, 0, TALI_HEADER_LENGTH, ENC_NA);
    tali_tree = proto_item_add_subtree(tali_item, ett_tali);
    proto_tree_add_string(tali_tree, hf_tali_sync_indicator,   tvb, 0, TALI_SYNC_LENGTH, TALI_SYNC);
    proto_tree_add_string(tali_tree, hf_tali_opcode_indicator, tvb, TALI_SYNC_LENGTH, TALI_OPCODE_LENGTH, opcode);
    proto_tree_add_uint(tali_tree, hf_tali_length_indicator, tvb, TALI_SYNC_LENGTH + TALI_OPCODE_LENGTH, TALI_MSU_LENGTH, length);
  }

  if (length > 0) {
    payload_tvb = tvb_new_subset_remaining(tvb, TALI_HEADER_LENGTH);
    if (payload_tvb != NULL && !dissector_try_string(tali_dissector_table, opcode, payload_tvb, pinfo, tree, NULL)) {
      call_data_dissector(payload_tvb, pinfo, tree);
    }
  }

  return tvb_captured_length(tvb);
}

static int
dissect_tali(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  tcp_dissect_pdus(tvb, pinfo, tree, tali_desegment, TALI_HEADER_LENGTH,
                   get_tali_pdu_len, dissect_tali_pdu, data);
  return tvb_captured_length(tvb);
}

/*
 * A 'heuristic dissector' that attemtps to establish whether we have
 * a TALI MSU here.
 * Only works when:
 *   the fixed header is there
 *   it is a 'well-known' operation
 */
static bool
dissect_tali_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  char opcode[TALI_OPCODE_LENGTH]; /* TALI opcode */

  /*
   * If we don't have at least TALI_HEADER_LENGTH bytes worth of captured
   * data (i.e., available to look at), we can't determine whether this
   * looks like a TALI packet or not.  We must use tvb_captured_length()
   * because the data must be present in the capture, not sliced off due
   * to the snapshot length specified for the capture.
   */
  if (tvb_captured_length(tvb) < TALI_HEADER_LENGTH)   /* Mandatory header */
    return false;

  if (tvb_strneql(tvb, 0, TALI_SYNC, TALI_SYNC_LENGTH) != 0)
    return false;

  tvb_memcpy(tvb, (uint8_t*)opcode, TALI_SYNC_LENGTH, TALI_OPCODE_LENGTH);
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
    return false;

  dissect_tali(tvb, pinfo, tree, data);
  return true;
}

void
proto_register_tali(void)
{
  static hf_register_info hf[] = {
    { &hf_tali_sync_indicator,
      { "Sync", "tali.sync",
        FT_STRING, BASE_NONE, NULL, 0x00,
        "TALI SYNC", HFILL }
    },
    { &hf_tali_opcode_indicator,
      { "Opcode", "tali.opcode",
        FT_STRING, BASE_NONE, NULL, 0x00,
        "TALI Operation Code", HFILL }
    },
    { &hf_tali_length_indicator,
      { "Length", "tali.msu_length",
        FT_UINT16, BASE_DEC, NULL, 0x00,
        "TALI MSU Length", HFILL }
    },
  };

  /* Setup protocol subtree array */
  static int *ett[] = {
    &ett_tali,
    &ett_tali_sync,
    &ett_tali_opcode,
    &ett_tali_msu_length
  };
  module_t *tali_module;

  /* Register the protocol name and description */
  proto_tali = proto_register_protocol("Transport Adapter Layer Interface v1.0, RFC 3094", "TALI", "tali");
  proto_register_field_array(proto_tali, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("tali", dissect_tali, proto_tali);

  tali_dissector_table = register_dissector_table("tali.opcode", "Tali OPCODE", proto_tali, FT_STRING, STRING_CASE_SENSITIVE);

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
  heur_dissector_add("tcp", dissect_tali_heur, "Tali over TCP", "tali_tcp", proto_tali, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
