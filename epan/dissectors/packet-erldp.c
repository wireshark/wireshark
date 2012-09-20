/* packet-erldp.c
 * Erlang Distribution Protocol
 * http://www.erlang.org/doc/apps/erts/erl_dist_protocol.html
 *
 * 2010  Tomas Kukosa
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <string.h>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/emem.h>

#include <epan/dissectors/packet-tcp.h>
#include <epan/dissectors/packet-epmd.h>

#define ERL_PASS_THROUGH      'p'

#define VERSION_MAGIC 131   /* 130 in erlang 4.2 */

#define SMALL_INTEGER_EXT 'a'
#define INTEGER_EXT       'b'
#define FLOAT_EXT         'c'
#define ATOM_EXT          'd'
#define SMALL_ATOM_EXT    's'
#define REFERENCE_EXT     'e'
#define NEW_REFERENCE_EXT 'r'
#define PORT_EXT          'f'
#define NEW_FLOAT_EXT     'F'
#define PID_EXT           'g'
#define SMALL_TUPLE_EXT   'h'
#define LARGE_TUPLE_EXT   'i'
#define NIL_EXT           'j'
#define STRING_EXT        'k'
#define LIST_EXT          'l'
#define BINARY_EXT        'm'
#define BIT_BINARY_EXT    'M'
#define SMALL_BIG_EXT     'n'
#define LARGE_BIG_EXT     'o'
#define NEW_FUN_EXT       'p'
#define EXPORT_EXT        'q'
#define FUN_EXT           'u'

#define DIST_HEADER       'D'
#define ATOM_CACHE_REF    'R'
#define COMPRESSED        'P'

#define PNAME  "Erlang Distribution Protocol"
#define PSNAME "ErlDP"
#define PFNAME "erldp"

static const value_string etf_tag_vals[] = {
  { SMALL_INTEGER_EXT , "SMALL_INTEGER_EXT" },
  { INTEGER_EXT       , "INTEGER_EXT" },
  { FLOAT_EXT         , "FLOAT_EXT" },
  { ATOM_EXT          , "ATOM_EXT" },
  { SMALL_ATOM_EXT    , "SMALL_ATOM_EXT" },
  { REFERENCE_EXT     , "REFERENCE_EXT" },
  { NEW_REFERENCE_EXT , "NEW_REFERENCE_EXT" },
  { PORT_EXT          , "PORT_EXT" },
  { NEW_FLOAT_EXT     , "NEW_FLOAT_EXT" },
  { PID_EXT           , "PID_EXT" },
  { SMALL_TUPLE_EXT   , "SMALL_TUPLE_EXT" },
  { LARGE_TUPLE_EXT   , "LARGE_TUPLE_EXT" },
  { NIL_EXT           , "NIL_EXT" },
  { STRING_EXT        , "STRING_EXT" },
  { LIST_EXT          , "LIST_EXT" },
  { BINARY_EXT        , "BINARY_EXT" },
  { BIT_BINARY_EXT    , "BIT_BINARY_EXT" },
  { SMALL_BIG_EXT     , "SMALL_BIG_EXT" },
  { LARGE_BIG_EXT     , "LARGE_BIG_EXT" },
  { NEW_FUN_EXT       , "NEW_FUN_EXT" },
  { EXPORT_EXT        , "EXPORT_EXT" },
  { FUN_EXT           , "FUN_EXT" },
  { DIST_HEADER       , "DIST_HEADER" },
  { ATOM_CACHE_REF    , "ATOM_CACHE_REF" },
  { COMPRESSED        , "COMPRESSED" },
  {  0, NULL }
};

static const value_string erldp_ctlmsg_vals[] = {
  {  1, "LINK" },
  {  2, "SEND" },
  {  3, "EXIT" },
  {  4, "UNLINK" },
  {  5, "NODE_LINK" },
  {  6, "REG_SEND" },
  {  7, "GROUP_LEADER" },
  {  8, "EXIT2" },
  { 12, "SEND_TT" },
  { 13, "EXIT_TT" },
  { 16, "REG_SEND_TT" },
  { 18, "EXIT2_TT" },
  { 19, "MONITOR_P" },
  { 20, "DEMONITOR_P" },
  { 21, "MONITOR_P_EXIT" },
  {  0, NULL }
};

/* Initialize the protocol and registered fields */
int proto_erldp = -1;
static int hf_erldp_length_2 = -1;
static int hf_erldp_length_4 = -1;
static int hf_erldp_tag = -1;
static int hf_erldp_type = -1;
static int hf_erldp_version = -1;
static int hf_erldp_flags = -1;
static int hf_erldp_challenge = -1;
static int hf_erldp_digest = -1;
static int hf_erldp_name = -1;
static int hf_erldp_status = -1;

static int hf_etf_tag = -1;

/* Initialize the subtree pointers */
static gint ett_erldp = -1;

static gint ett_etf = -1;
static gint ett_etf_flags = -1;
static gint ett_etf_acrs = -1;
static gint ett_etf_acr = -1;
static gint ett_etf_tmp = -1;

/* Preferences */
static gboolean erldp_desegment = TRUE;

/* Dissectors */
static dissector_handle_t erldp_handle = NULL;

/* Subdissectors */
dissector_handle_t data_handle;

/*--- External Term Format ---*/

static gint dissect_etf_type(const gchar *label, packet_info *pinfo, tvbuff_t *tvb, gint offset, proto_tree *tree);

static gint dissect_etf_dist_header(packet_info *pinfo _U_, tvbuff_t *tvb, gint offset, proto_tree *tree) {
  guint8 num, flen, i, flg, isi;
  gint flg_offset, acrs_offset, acr_offset;
  guint32 atom_txt_len;
  gboolean new_entry, long_atom;
  proto_item *ti_acrs, *ti_acr, *ti_tmp;
  proto_tree *flags_tree, *acrs_tree, *acr_tree;
  const gchar *str;

  num = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1, "NumberOfAtomCacheRefs: %d", num);
  offset++;

  if (num == 0)
    return offset;

  flg_offset = offset;
  flen = num / 2 + 1;
  ti_tmp = proto_tree_add_text(tree, tvb, offset, flen, "Flags: %s", tvb_bytes_to_str(tvb, offset, flen));
  flags_tree = proto_item_add_subtree(ti_tmp, ett_etf_flags);
  for (i=0; i<num; i++) {
    flg = tvb_get_guint8(tvb, offset + i / 2);
    proto_tree_add_text(flags_tree, tvb, offset + i / 2, 1, "%s",
            decode_boolean_bitfield(flg, 0x08 << 4*(i%2), 8,
                        ep_strdup_printf("NewCacheEntryFlag[%2d]: SET", i),
                        ep_strdup_printf("NewCacheEntryFlag[%2d]: ---", i)));
    proto_tree_add_text(flags_tree, tvb, offset + i / 2, 1, "%s",
            decode_numeric_bitfield(flg, 0x07 << 4*(i%2), 8, ep_strdup_printf("SegmentIndex     [%2d]: %%u", i)));
  }
  flg = tvb_get_guint8(tvb, offset + num / 2);
  proto_tree_add_text(flags_tree, tvb, offset + num / 2, 1, "%s",
          decode_boolean_bitfield(flg, 0x01 << 4*(num%2), 8,
                      "LongAtoms: YES",
                      "LongAtoms: NO"));
  long_atom = flg & (0x01 << 4*(num%2));
  offset += flen;

  acrs_offset = offset;
  ti_acrs = proto_tree_add_text(tree, tvb, offset, 0, "AtomCacheRefs");
  acrs_tree = proto_item_add_subtree(ti_acrs, ett_etf_acrs);
  for (i=0; i<num; i++) {
    flg = tvb_get_guint8(tvb, flg_offset + i / 2);
    new_entry = flg & (0x08 << 4*(i%2));
    acr_offset = offset;
    ti_acr = proto_tree_add_text(acrs_tree, tvb, offset, 0, "AtomCacheRef[%2d]:", i);
    acr_tree = proto_item_add_subtree(ti_acr, ett_etf_acr);
    isi = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(acr_tree, tvb, offset, 1, "InternalSegmentIndex: %d", isi);
    proto_item_append_text(ti_acr, " %3d", isi);
    offset++;
    if (!new_entry)
      continue;
    atom_txt_len = (long_atom) ? tvb_get_ntohs(tvb, offset) : tvb_get_guint8(tvb, offset);
    proto_tree_add_text(acr_tree, tvb, offset, (long_atom) ? 2 : 1, "Length: %d", atom_txt_len);
    offset += (long_atom) ? 2 : 1;
    str = tvb_get_ephemeral_string(tvb, offset, atom_txt_len);
    proto_tree_add_text(acr_tree, tvb, offset, atom_txt_len, "AtomText: %s", str);
    proto_item_append_text(ti_acr, " - '%s'", str);
    offset += atom_txt_len;
    proto_item_set_len(ti_acr, offset - acr_offset);
  }
  proto_item_set_len(ti_acrs, offset - acrs_offset);

  return offset;
}

static gint dissect_etf_tuple_content(gboolean large, packet_info *pinfo, tvbuff_t *tvb, gint offset, proto_tree *tree, gchar **value_str _U_) {
  guint32 arity, i;

  arity = (large) ? tvb_get_ntohl(tvb, offset) : tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, (large) ? 4 : 1, "Arity: %u", arity);
  offset += (large) ? 4 : 1;
  for (i=0; i<arity; i++) {
    offset = dissect_etf_type(NULL, pinfo, tvb, offset, tree);
  }

  return offset;
}

static gint dissect_etf_type_content(guint8 tag, packet_info *pinfo, tvbuff_t *tvb, gint offset, proto_tree *tree, gchar **value_str) {
  gint32 len, int_val, i;

  switch (tag) {
    case DIST_HEADER:
      offset = dissect_etf_dist_header(pinfo, tvb, offset, tree);
      break;

    case ATOM_CACHE_REF:
      int_val = tvb_get_guint8(tvb, offset);
      proto_tree_add_text(tree, tvb, offset, 1, "AtomCacheReferenceIndex: %d", int_val);
      offset += 1;
      if (value_str)
        *value_str = ep_strdup_printf("%d", int_val);
      break;

    case SMALL_INTEGER_EXT:
      int_val = tvb_get_guint8(tvb, offset);
      proto_tree_add_text(tree, tvb, offset, 1, "Int: %d", int_val);
      offset += 1;
      if (value_str)
        *value_str = ep_strdup_printf("%d", int_val);
      break;

    case INTEGER_EXT:
      int_val = tvb_get_ntohl(tvb, offset);
      proto_tree_add_text(tree, tvb, offset, 4, "Int: %d", int_val);
      offset += 4;
      if (value_str)
        *value_str = ep_strdup_printf("%d", int_val);
      break;

    case PID_EXT:
      offset = dissect_etf_type("Node", pinfo, tvb, offset, tree);
      proto_tree_add_text(tree, tvb, offset, 4, "ID: 0x%08X", tvb_get_ntohl(tvb, offset));
      offset += 4;
      proto_tree_add_text(tree, tvb, offset, 4, "Serial: %u", tvb_get_ntohl(tvb, offset));
      offset += 4;
      proto_tree_add_text(tree, tvb, offset, 1, "Creation: %u", tvb_get_guint8(tvb, offset));
      offset++;
      break;

    case SMALL_TUPLE_EXT:
      offset = dissect_etf_tuple_content(FALSE, pinfo, tvb, offset, tree, value_str);
      break;

    case LARGE_TUPLE_EXT:
      offset = dissect_etf_tuple_content(TRUE, pinfo, tvb, offset, tree, value_str);
      break;

    case NIL_EXT:
      break;

    case LIST_EXT:
      len = tvb_get_ntohl(tvb, offset);
      proto_tree_add_text(tree, tvb, offset, 4, "Len: %d", len);
      offset += 4;
      for (i=0; i<len; i++) {
        offset = dissect_etf_type(NULL, pinfo, tvb, offset, tree);
      }
      offset = dissect_etf_type("Tail", pinfo, tvb, offset, tree);
      break;

    case NEW_REFERENCE_EXT:
      len = tvb_get_ntohs(tvb, offset);
      proto_tree_add_text(tree, tvb, offset, 2, "Len: %d", len);
      offset += 2;
      offset = dissect_etf_type("Node", pinfo, tvb, offset, tree);
      proto_tree_add_text(tree, tvb, offset, 1, "Creation: %u", tvb_get_guint8(tvb, offset));
      offset++;
      for (i=0; i<len; i++) {
        proto_tree_add_text(tree, tvb, offset, 4, "ID[%d]: 0x%08X", i, tvb_get_ntohl(tvb, offset));
        offset += 4;
      }
      break;
  }

  return offset;
}

static gint dissect_etf_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const gchar *label) {
  gint offset = 0;
  guint8 mag, tag;
  proto_item *ti;
  proto_tree *etf_tree;

  mag = tvb_get_guint8(tvb, offset);
  if (mag != VERSION_MAGIC) {
    return 0;
  }

  ti = proto_tree_add_text(tree, tvb, offset, -1, "%s", (label) ? label : "External Term Format");
  etf_tree = proto_item_add_subtree(ti, ett_etf);

  proto_tree_add_text(etf_tree, tvb, offset, 1, "VERSION_MAGIC: %d", mag);
  offset++;

  tag = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(etf_tree, hf_etf_tag, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  if (!label)
    proto_item_set_text(ti, "%s", val_to_str(tag, VALS(etf_tag_vals), "unknown tag (%d)"));

  offset = dissect_etf_type_content(tag, pinfo, tvb, offset, etf_tree, NULL);

  proto_item_set_len(ti, offset);

  return offset;
}

static gint dissect_etf_type(const gchar *label, packet_info *pinfo, tvbuff_t *tvb, gint offset, proto_tree *tree) {
  gint begin = offset;
  guint8 tag;
  proto_item *ti;
  proto_tree *etf_tree;
  gchar *value_str = NULL;

  ti = proto_tree_add_text(tree, tvb, offset, -1, "%s", (label) ? label : "External Term Format");
  etf_tree = proto_item_add_subtree(ti, ett_etf);

  tag = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(etf_tree, hf_etf_tag, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  if (!label)
    proto_item_set_text(ti, "%s", val_to_str(tag, VALS(etf_tag_vals), "unknown tag (%d)"));

  offset = dissect_etf_type_content(tag, pinfo, tvb, offset, etf_tree, &value_str);
  if (value_str)
    proto_item_append_text(ti, ": %s", value_str);

  proto_item_set_len(ti, offset - begin);

  return offset;
}

static gboolean is_handshake(tvbuff_t *tvb, int offset) {
  guint32 len = tvb_get_ntohs(tvb, offset);
  guint8 tag = tvb_get_guint8(tvb, offset + 2);
  return ((len > 0) && strchr("nras", tag) && (len == (guint32)tvb_length_remaining(tvb, offset + 2)));
}

/*--- dissect_erldp_handshake -------------------------------------------------*/
static void dissect_erldp_handshake(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  gint offset = 0;
  guint8 tag;
  gint i;
  gboolean is_challenge = FALSE;
  guint32 str_len;
  const gchar *str;

  proto_tree_add_item(tree, hf_erldp_length_2, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  tag = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_erldp_tag, tvb, offset, 1, ENC_ASCII|ENC_NA);
  offset++;

  switch (tag) {
    case 'n' :
      proto_tree_add_item(tree, hf_erldp_version, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(tree, hf_erldp_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      if (tvb_bytes_exist(tvb, offset, 4)) {
        for (i=0; i<4; i++)
          if(!g_ascii_isprint(tvb_get_guint8(tvb, offset + i))) {
            is_challenge = TRUE;
            break;
          }
      }
      if (is_challenge) {
        proto_tree_add_item(tree, hf_erldp_challenge, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
      }
      str_len = tvb_length_remaining(tvb, offset);
      str = tvb_get_ephemeral_string(tvb, offset, str_len);
      proto_tree_add_item(tree, hf_erldp_name, tvb, offset, str_len, ENC_ASCII|ENC_NA);
      col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s", (is_challenge) ? "SEND_CHALLENGE" : "SEND_NAME", str);
      break;

    case 'r' :
      proto_tree_add_item(tree, hf_erldp_challenge, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(tree, hf_erldp_digest, tvb, offset, 16, ENC_NA);
      /*offset += 16;*/
      col_add_str(pinfo->cinfo, COL_INFO, "SEND_CHALLENGE_REPLY");
      break;

    case 'a' :
      proto_tree_add_item(tree, hf_erldp_digest, tvb, offset, 16, ENC_NA);
      /*offset += 16;*/
      col_add_str(pinfo->cinfo, COL_INFO, "SEND_CHALLENGE_ACK");
      break;

    case 's' :
      str_len = tvb_length_remaining(tvb, offset);
      str = tvb_get_ephemeral_string(tvb, offset, str_len);
      proto_tree_add_item(tree, hf_erldp_status, tvb, offset, str_len, ENC_ASCII|ENC_NA);
      col_add_fstr(pinfo->cinfo, COL_INFO, "SEND_STATUS %s", str);
      break;
  }
}

/*--- dissect_erldp_pdu -------------------------------------------------*/
static void dissect_erldp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  gint offset;
  guint32 msg_len;
  guint8 type, ctl_op;
  proto_tree *erldp_tree;
  proto_item *ti;
  tvbuff_t *next_tvb = NULL;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);

  ti = proto_tree_add_item(tree, proto_erldp, tvb, 0, -1, ENC_NA);
  erldp_tree = proto_item_add_subtree(ti, ett_erldp);

  if (is_handshake(tvb, 0)) {
    dissect_erldp_handshake(tvb, pinfo, erldp_tree);
    return;
  }

  offset = 0;

  msg_len = tvb_get_ntohl(tvb, offset);
  proto_tree_add_item(erldp_tree, hf_erldp_length_4, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  if (msg_len == 0) {
    col_add_str(pinfo->cinfo, COL_INFO, "KEEP_ALIVE");
    return;
  }

  type = tvb_get_guint8(tvb, offset);
  switch (type) {
    case ERL_PASS_THROUGH:
      proto_tree_add_item(erldp_tree, hf_erldp_type, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;
      break;

    case VERSION_MAGIC:
      next_tvb = tvb_new_subset(tvb, offset, -1, 4 + msg_len - offset);
      offset += dissect_etf_pdu(next_tvb, pinfo, erldp_tree, "DistributionHeader");
      if ((tvb_get_guint8(tvb, offset) == SMALL_TUPLE_EXT) && (tvb_get_guint8(tvb, offset + 2) == SMALL_INTEGER_EXT)) {
        ctl_op = tvb_get_guint8(tvb, offset + 3);
        col_add_str(pinfo->cinfo, COL_INFO, val_to_str(ctl_op, VALS(erldp_ctlmsg_vals), "unknown ControlMessage operation (%d)"));
      }
      offset = dissect_etf_type("ControlMessage", pinfo, tvb, offset, erldp_tree);
      if (tvb_length_remaining(tvb, offset) > 0)
        dissect_etf_type("Message", pinfo, tvb, offset, erldp_tree);
      break;

    default:
      proto_tree_add_item(erldp_tree, hf_erldp_type, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;
      col_add_str(pinfo->cinfo, COL_INFO, "unknown header format");
      return;
  }
}

/*--- get_erldp_pdu_len -------------------------------------------------*/
static guint get_erldp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset) {
  if (is_handshake(tvb, offset))
    return(2 + tvb_get_ntohs(tvb, offset));
  else
    return(4 + tvb_get_ntohl(tvb, offset));
}

/*--- dissect_erldp -------------------------------------------------*/
static void
dissect_erldp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  tcp_dissect_pdus(tvb, pinfo, tree,
                   erldp_desegment,    /* desegment or not   */
                    4,               /* fixed-length part of the PDU */
                   get_erldp_pdu_len,  /* routine to get the length of the PDU */
                   dissect_erldp_pdu); /* routine to dissect a PDU */
}

/*--- proto_register_erldp ----------------------------------------------*/
void proto_register_erldp(void) {
  /* module_t *erldp_module; */

  /* List of fields */
  static hf_register_info hf[] = {
    /*--- Handshake fields ---*/
    { &hf_erldp_length_2, { "Length", "erldp.len",
                        FT_UINT16, BASE_DEC, NULL, 0x0,
                        "Message Length", HFILL}},
    { &hf_erldp_tag,  { "Tag", "erldp.tag",
                        FT_STRING, BASE_NONE, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_type, { "Type", "erldp.type",
                        FT_UINT8, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_version, { "Version", "erldp.version",
                        FT_UINT16, BASE_DEC, VALS(epmd_version_vals), 0x0,
                        NULL, HFILL}},
    { &hf_erldp_flags,  { "Flags", "erldp.flags",
                        FT_UINT32, BASE_HEX, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_challenge, { "Challenge", "erldp.challenge",
                        FT_UINT32, BASE_HEX, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_digest, { "Digest", "erldp.digest",
                        FT_BYTES, BASE_NONE, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_name, { "Name", "erldp.name",
                        FT_STRING, BASE_NONE, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_status, { "Status", "erldp.status",
                        FT_STRING, BASE_NONE, NULL, 0x0,
                        NULL, HFILL}},
    /*---  ---*/
    { &hf_erldp_length_4, { "Length", "erldp.len",
                        FT_UINT32, BASE_DEC, NULL, 0x0,
                        "Message Length", HFILL}},

    /*--- ETF  ---*/
    { &hf_etf_tag,    { "Tag", "erldp.etf_tag",
                        FT_UINT8, BASE_DEC, VALS(etf_tag_vals), 0x0,
                        NULL, HFILL}},
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_erldp,
    &ett_etf,
    &ett_etf_flags,
    &ett_etf_acrs,
    &ett_etf_acr,
    &ett_etf_tmp,
  };

  /* Register protocol and dissector */
  proto_erldp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector(PFNAME, dissect_erldp, proto_erldp);
  erldp_handle = find_dissector(PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_erldp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}

/*--- proto_reg_handoff_erldp -------------------------------------------*/
void proto_reg_handoff_erldp(void) {

  dissector_add_handle("tcp.port", erldp_handle);

  data_handle = find_dissector("data");
}
