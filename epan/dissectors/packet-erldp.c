/* packet-erldp.c
 * Erlang Distribution Protocol
 * http://www.erlang.org/doc/apps/erts/erl_dist_protocol.html
 *
 * 2010  Tomas Kukosa
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"


#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/reassemble.h>
#include "packet-tcp.h"
#include "packet-epmd.h"

#define ERL_PASS_THROUGH      'p'

#define VERSION_MAGIC 131   /* 130 in erlang 4.2 */

#define SMALL_INTEGER_EXT   'a'
#define INTEGER_EXT         'b'
#define FLOAT_EXT           'c'
#define ATOM_EXT            'd'
#define ATOM_UTF8_EXT       'v'
#define SMALL_ATOM_EXT      's'
#define SMALL_ATOM_UTF8_EXT 'w'
#define REFERENCE_EXT       'e'
#define NEW_REFERENCE_EXT   'r'
#define NEWER_REFERENCE_EXT 'Z'
#define PORT_EXT            'f'
#define NEW_PORT_EXT        'Y'
#define NEW_FLOAT_EXT       'F'
#define PID_EXT             'g'
#define NEW_PID_EXT         'X'
#define SMALL_TUPLE_EXT     'h'
#define LARGE_TUPLE_EXT     'i'
#define NIL_EXT             'j'
#define STRING_EXT          'k'
#define LIST_EXT            'l'
#define BINARY_EXT          'm'
#define BIT_BINARY_EXT      'M'
#define SMALL_BIG_EXT       'n'
#define LARGE_BIG_EXT       'o'
#define NEW_FUN_EXT         'p'
#define EXPORT_EXT          'q'
#define FUN_EXT             'u'

#define DIST_HEADER         'D'
#define DIST_FRAG_HEADER    'E'
#define DIST_FRAG_CONT      'F'
#define ATOM_CACHE_REF      'R'
#define COMPRESSED          'P'

#define PNAME  "Erlang Distribution Protocol"
#define PSNAME "ErlDP"
#define PFNAME "erldp"

void proto_register_erldp(void);
void proto_reg_handoff_erldp(void);

static const value_string etf_tag_vals[] = {
  { SMALL_INTEGER_EXT   , "SMALL_INTEGER_EXT" },
  { INTEGER_EXT         , "INTEGER_EXT" },
  { FLOAT_EXT           , "FLOAT_EXT" },
  { ATOM_EXT            , "ATOM_EXT" },
  { ATOM_UTF8_EXT       , "ATOM_UTF8_EXT" },
  { SMALL_ATOM_EXT      , "SMALL_ATOM_EXT" },
  { SMALL_ATOM_UTF8_EXT , "SMALL_ATOM_UTF8_EXT" },
  { REFERENCE_EXT       , "REFERENCE_EXT" },
  { NEW_REFERENCE_EXT   , "NEW_REFERENCE_EXT" },
  { NEWER_REFERENCE_EXT , "NEWER_REFERENCE_EXT" },
  { PORT_EXT            , "PORT_EXT" },
  { NEW_PORT_EXT        , "NEW_PORT_EXT" },
  { NEW_FLOAT_EXT       , "NEW_FLOAT_EXT" },
  { PID_EXT             , "PID_EXT" },
  { NEW_PID_EXT         , "NEW_PID_EXT" },
  { SMALL_TUPLE_EXT     , "SMALL_TUPLE_EXT" },
  { LARGE_TUPLE_EXT     , "LARGE_TUPLE_EXT" },
  { NIL_EXT             , "NIL_EXT" },
  { STRING_EXT          , "STRING_EXT" },
  { LIST_EXT            , "LIST_EXT" },
  { BINARY_EXT          , "BINARY_EXT" },
  { BIT_BINARY_EXT      , "BIT_BINARY_EXT" },
  { SMALL_BIG_EXT       , "SMALL_BIG_EXT" },
  { LARGE_BIG_EXT       , "LARGE_BIG_EXT" },
  { NEW_FUN_EXT         , "NEW_FUN_EXT" },
  { EXPORT_EXT          , "EXPORT_EXT" },
  { FUN_EXT             , "FUN_EXT" },
  { DIST_HEADER         , "DIST_HEADER" },
  { DIST_FRAG_HEADER    , "DIST_FRAG_HEADER" },
  { ATOM_CACHE_REF      , "ATOM_CACHE_REF" },
  { COMPRESSED          , "COMPRESSED" },
  {  0, NULL }
};

static const value_string etf_header_tag_vals[] = {
  { DIST_HEADER         , "DIST_HEADER" },
  { DIST_FRAG_HEADER    , "DIST_FRAG_HEADER" },
  { DIST_FRAG_CONT      , "DIST_FRAG_CONT" },
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
  { 22, "SEND_SENDER" },
  { 23, "SEND_SENDER_TT" },
  { 24, "PAYLOAD_EXIT" },
  { 25, "PAYLOAD_EXIT_TT" },
  { 26, "PAYLOAD_EXIT2" },
  { 27, "PAYLOAD_EXIT2_TT" },
  { 28, "PAYLOAD_MONITOR_P_EXIT" },
  { 29, "SPAWN_REQUEST" },
  { 30, "SPAWN_REQUEST_TT" },
  { 31, "SPAWN_REPLY" },
  { 32, "SPAWN_REPLY_TT" },
  {  0, NULL }
};

/* Initialize the protocol and registered fields */
static int proto_erldp = -1;
static int hf_erldp_length_2 = -1;
static int hf_erldp_length_4 = -1;
static int hf_etf_version_magic = -1;
static int hf_erldp_tag = -1;
static int hf_erldp_type = -1;
static int hf_erldp_version = -1;
static int hf_erldp_flags_v5 = -1;
static int hf_erldp_flags_v6 = -1;
static int hf_erldp_flags_published = -1;
static int hf_erldp_flags_atom_cache = -1;
static int hf_erldp_flags_extended_references = -1;
static int hf_erldp_flags_dist_monitor = -1;
static int hf_erldp_flags_fun_tags = -1;
static int hf_erldp_flags_dist_monitor_name = -1;
static int hf_erldp_flags_hidden_atom_cache = -1;
static int hf_erldp_flags_new_fun_tags = -1;
static int hf_erldp_flags_extended_pids_ports = -1;
static int hf_erldp_flags_export_ptr_tag = -1;
static int hf_erldp_flags_bit_binaries = -1;
static int hf_erldp_flags_new_floats = -1;
static int hf_erldp_flags_unicode_io = -1;
static int hf_erldp_flags_dist_hdr_atom_cache = -1;
static int hf_erldp_flags_small_atom_tags = -1;
static int hf_erldp_flags_ets_compressed = -1;
static int hf_erldp_flags_utf8_atoms = -1;
static int hf_erldp_flags_map_tag = -1;
static int hf_erldp_flags_big_creation = -1;
static int hf_erldp_flags_send_sender = -1;
static int hf_erldp_flags_big_seqtrace_labels = -1;
static int hf_erldp_flags_pending_connect = -1;
static int hf_erldp_flags_exit_payload = -1;
static int hf_erldp_flags_fragments = -1;
static int hf_erldp_flags_handshake_23 = -1;
static int hf_erldp_flags_unlink_id = -1;
static int hf_erldp_flags_reserved = -1;
static int hf_erldp_flags_spawn = -1;
static int hf_erldp_flags_name_me = -1;
static int hf_erldp_flags_v4_nc = -1;
static int hf_erldp_flags_alias = -1;
static int hf_erldp_flags_spare = -1;
static int hf_erldp_creation = -1;
static int hf_erldp_challenge = -1;
static int hf_erldp_digest = -1;
static int hf_erldp_nlen = -1;
static int hf_erldp_name = -1;
static int hf_erldp_status = -1;
static int hf_erldp_sequence_id = -1;
static int hf_erldp_fragment_id = -1;
static int hf_erldp_num_atom_cache_refs = -1;
static int hf_erldp_etf_flags = -1;
static int hf_erldp_internal_segment_index = -1;
static int hf_erldp_atom_length = -1;
static int hf_erldp_atom_length2 = -1;
static int hf_erldp_atom_text = -1;
static int hf_erldp_atom_cache_ref = -1;
static int hf_erldp_small_int_ext = -1;
static int hf_erldp_int_ext = -1;
static int hf_erldp_small_big_ext_len = -1;
static int hf_erldp_large_big_ext_len = -1;
static int hf_erldp_big_ext_int = -1;
static int hf_erldp_big_ext_str = -1;
static int hf_erldp_big_ext_bytes = -1;
static int hf_erldp_float_ext = -1;
static int hf_erldp_new_float_ext = -1;
static int hf_erldp_port_ext_id = -1;
static int hf_erldp_port_ext_creation = -1;
static int hf_erldp_pid_ext_id = -1;
static int hf_erldp_pid_ext_serial = -1;
static int hf_erldp_pid_ext_creation = -1;
static int hf_erldp_list_ext_len = -1;
static int hf_erldp_binary_ext_len = -1;
static int hf_erldp_binary_ext = -1;
static int hf_erldp_new_ref_ext_len = -1;
static int hf_erldp_new_ref_ext_creation = -1;
static int hf_erldp_new_ref_ext_id = -1;
static int hf_erldp_fun_ext_num_free = -1;
static int hf_erldp_new_fun_ext_size = -1;
static int hf_erldp_new_fun_ext_arity = -1;
static int hf_erldp_new_fun_ext_uniq = -1;
static int hf_erldp_new_fun_ext_index = -1;
static int hf_erldp_new_fun_ext_num_free = -1;

static int hf_etf_tag = -1;
static int hf_etf_dist_header_tag = -1;
static int hf_etf_dist_header_new_cache = -1;
static int hf_etf_dist_header_segment_index = -1;
static int hf_etf_dist_header_long_atoms = -1;
static int hf_etf_arity4 = -1;
static int hf_etf_arity = -1;

static int hf_etf_fragments = -1;
static int hf_etf_fragment = -1;
static int hf_etf_fragment_overlap = -1;
static int hf_etf_fragment_overlap_conflicts = -1;
static int hf_etf_fragment_multiple_tails = -1;
static int hf_etf_fragment_too_long_fragment = -1;
static int hf_etf_fragment_error = -1;
static int hf_etf_fragment_count = -1;
static int hf_etf_reassembled_in = -1;
static int hf_etf_reassembled_length = -1;
static int hf_etf_reassembled_data = -1;

static reassembly_table erldp_reassembly_table;

/* Initialize the subtree pointers */
static gint ett_erldp = -1;
static gint ett_erldp_flags = -1;

static gint ett_etf = -1;
static gint ett_etf_flags = -1;
static gint ett_etf_acrs = -1;
static gint ett_etf_acr = -1;
static gint ett_etf_tmp = -1;

static gint ett_etf_fragment = -1;
static gint ett_etf_fragments = -1;

/* Preferences */
static gboolean erldp_desegment = TRUE;

/* Dissectors */
static dissector_handle_t erldp_handle = NULL;

/* Defragmentation */
static const fragment_items etf_frag_items = {
    /* Fragment subtrees */
    &ett_etf_fragment,
    &ett_etf_fragments,
    /* Fragment fields */
    &hf_etf_fragments,
    &hf_etf_fragment,
    &hf_etf_fragment_overlap,
    &hf_etf_fragment_overlap_conflicts,
    &hf_etf_fragment_multiple_tails,
    &hf_etf_fragment_too_long_fragment,
    &hf_etf_fragment_error,
    &hf_etf_fragment_count,
    /* Reassembled in field */
    &hf_etf_reassembled_in,
    /* Reassembled length field */
    &hf_etf_reassembled_length,
    &hf_etf_reassembled_data,
    /* Tag */
    "Message fragments"
};

/*--- External Term Format ---*/

static gint dissect_etf_type(const gchar *label, packet_info *pinfo, tvbuff_t *tvb, gint offset, proto_tree *tree);
static gint dissect_etf_pdu_data(packet_info *pinfo, tvbuff_t *tvb, gint offset, proto_tree *tree);

static gint dissect_etf_dist_header(packet_info *pinfo _U_, tvbuff_t *tvb, gint offset, proto_tree *tree) {
  guint32 num, isi;
  guint8 flen, i, flg;
  gint flg_offset, acrs_offset, acr_offset;
  guint32 atom_txt_len;
  gboolean new_entry, long_atom;
  proto_item *ti_acrs, *ti_acr, *ti_tmp;
  proto_tree *flags_tree, *acrs_tree, *acr_tree;
  const guint8 *str;

  proto_tree_add_item_ret_uint(tree, hf_erldp_num_atom_cache_refs, tvb, offset, 1, ENC_BIG_ENDIAN, &num);
  offset++;

  if (num == 0)
    return offset;

  flg_offset = offset;
  flen = num / 2 + 1;
  ti_tmp = proto_tree_add_item(tree, hf_erldp_etf_flags, tvb, offset, flen, ENC_NA );
  flags_tree = proto_item_add_subtree(ti_tmp, ett_etf_flags);
  for (i=0; i<num; i++) {
    flg = tvb_get_guint8(tvb, offset + i / 2);
    proto_tree_add_boolean_format_value(flags_tree, hf_etf_dist_header_new_cache, tvb, offset + i / 2, 1,
                            (flg & (0x08 << 4*(i%2))), "NewCacheEntryFlag[%2d]: %s",
                            i, (flg & (0x08 << 4*(i%2))) ? "SET" : "---");
    proto_tree_add_uint_format(flags_tree, hf_etf_dist_header_segment_index, tvb, offset + i / 2, 1,
                            (flg & (0x07 << 4*(i%2))), "SegmentIndex     [%2d]: %u",
                            i, (flg & (0x07 << 4*(i%2))));
  }
  flg = tvb_get_guint8(tvb, offset + num / 2);
  proto_tree_add_boolean(flags_tree, hf_etf_dist_header_long_atoms, tvb, offset + num / 2, 1, (flg & (0x01 << 4*(num%2))));
  long_atom = flg & (0x01 << 4*(num%2));
  offset += flen;

  acrs_offset = offset;
  acrs_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_etf_acrs, &ti_acrs, "AtomCacheRefs");
  for (i=0; i<num; i++) {
    flg = tvb_get_guint8(tvb, flg_offset + i / 2);
    new_entry = flg & (0x08 << 4*(i%2));
    acr_offset = offset;
    acr_tree = proto_tree_add_subtree_format(acrs_tree, tvb, offset, 0, ett_etf_acr, &ti_acr, "AtomCacheRef[%2d]:", i);
    proto_tree_add_item_ret_uint(acr_tree, hf_erldp_internal_segment_index, tvb, offset, 1, ENC_BIG_ENDIAN, &isi);
    proto_item_append_text(ti_acr, " %3d", isi);
    offset++;
    if (!new_entry)
      continue;
    if (long_atom) {
      proto_tree_add_item_ret_uint(acr_tree, hf_erldp_atom_length2, tvb, offset, 2, ENC_BIG_ENDIAN, &atom_txt_len);
      offset += 2;
    }
    else {
      proto_tree_add_item_ret_uint(acr_tree, hf_erldp_atom_length, tvb, offset, 1, ENC_BIG_ENDIAN, &atom_txt_len);
      offset++;
    }
    proto_tree_add_item_ret_string(acr_tree, hf_erldp_atom_text, tvb, offset, atom_txt_len, ENC_NA|ENC_ASCII, wmem_packet_scope(), &str);
    proto_item_append_text(ti_acr, " - '%s'", str);
    offset += atom_txt_len;
    proto_item_set_len(ti_acr, offset - acr_offset);
  }
  proto_item_set_len(ti_acrs, offset - acrs_offset);

  return offset;
}

static gint dissect_etf_tuple_content(gboolean large, packet_info *pinfo, tvbuff_t *tvb, gint offset, proto_tree *tree, const gchar **value_str _U_) {
  guint32 arity, i;

  if (large) {
    proto_tree_add_item_ret_uint(tree, hf_etf_arity4, tvb, offset, 4, ENC_BIG_ENDIAN, &arity);
    offset += 4;
  } else {
    proto_tree_add_item_ret_uint(tree, hf_etf_arity, tvb, offset, 1, ENC_BIG_ENDIAN, &arity);
    offset++;
  }
  for (i=0; i<arity; i++) {
    offset = dissect_etf_type(NULL, pinfo, tvb, offset, tree);
  }

  return offset;
}

static gint dissect_etf_big_ext(tvbuff_t *tvb, gint offset, guint32 len, proto_tree *tree, const gchar **value_str) {
      guint8 sign;
      gint32 i;

      sign = tvb_get_guint8(tvb, offset);
      offset += 1;

      if (len <= 8) {
        guint64 big_val = 0;

        switch (len) {
        case 1: big_val = tvb_get_guint8(tvb, offset); break;
        case 2: big_val = tvb_get_letohs(tvb, offset); break;
        case 3: big_val = tvb_get_letoh24(tvb, offset); break;
        case 4: big_val = tvb_get_letohl(tvb, offset); break;
        case 5: big_val = tvb_get_letoh40(tvb, offset); break;
        case 6: big_val = tvb_get_letoh48(tvb, offset); break;
        case 7: big_val = tvb_get_letoh56(tvb, offset); break;
        case 8: big_val = tvb_get_letoh64(tvb, offset); break;
        }
        proto_tree_add_uint64_format_value(tree, hf_erldp_big_ext_int, tvb, offset, len,
                                           big_val, "%s%" PRIu64, sign ? "-"  : "", big_val);
        if (value_str)
          *value_str = wmem_strdup_printf(wmem_packet_scope(), "%s%" PRIu64,
                                          sign ? "-"  : "", big_val);
      } if (len < 64) {
        wmem_strbuf_t *strbuf = wmem_strbuf_sized_new(wmem_packet_scope(), len*1+3+1, len*1+3+1);

        wmem_strbuf_append(strbuf, "0x");
        for (i = len - 1; i >= 0; i--) {
          wmem_strbuf_append_printf(strbuf, "%02x", tvb_get_guint8(tvb, offset + i));
        }
        char *buf = wmem_strbuf_finalize(strbuf);

        proto_tree_add_string_format_value(tree, hf_erldp_big_ext_str, tvb, offset, len, buf, "%s", buf);

        if (value_str)
          *value_str = buf;
      } else
        proto_tree_add_item(tree, hf_erldp_big_ext_bytes, tvb, offset, len, ENC_NA);

      return offset + len;
}

static gint dissect_etf_type_content(guint8 tag, packet_info *pinfo, tvbuff_t *tvb, gint offset, proto_tree *tree, const gchar **value_str) {
  gint32 int_val;
  guint32 len, i, uint_val;
  guint32 id;
  const guint8 *str_val;

  switch (tag) {
    case ATOM_CACHE_REF:
      proto_tree_add_item_ret_uint(tree, hf_erldp_atom_cache_ref, tvb, offset, 1, ENC_BIG_ENDIAN, &uint_val);
      offset += 1;
      if (value_str)
        *value_str = wmem_strdup_printf(wmem_packet_scope(), "%d", uint_val);
      break;

    case SMALL_INTEGER_EXT:
      proto_tree_add_item_ret_uint(tree, hf_erldp_small_int_ext, tvb, offset, 1, ENC_BIG_ENDIAN, &uint_val);
      offset += 1;
      if (value_str)
        *value_str = wmem_strdup_printf(wmem_packet_scope(), "%u", uint_val);
      break;

    case INTEGER_EXT:
      proto_tree_add_item_ret_int(tree, hf_erldp_int_ext, tvb, offset, 4, ENC_BIG_ENDIAN, &int_val);
      offset += 4;
      if (value_str)
        *value_str = wmem_strdup_printf(wmem_packet_scope(), "%d", int_val);
      break;

    case SMALL_BIG_EXT: {
      proto_tree_add_item_ret_uint(tree, hf_erldp_small_big_ext_len, tvb, offset, 1, ENC_BIG_ENDIAN, &len);
      offset += 1;

      offset = dissect_etf_big_ext(tvb, offset, len, tree, value_str);
      break;
    }

    case LARGE_BIG_EXT: {
      proto_tree_add_item_ret_uint(tree, hf_erldp_large_big_ext_len, tvb, offset, 4, ENC_BIG_ENDIAN, &len);
      offset += 4;

      offset = dissect_etf_big_ext(tvb, offset, len, tree, value_str);
      break;
    }

    case FLOAT_EXT:
      proto_tree_add_item_ret_string(tree, hf_erldp_float_ext, tvb, offset, 31, ENC_NA|ENC_UTF_8, wmem_packet_scope(), &str_val);
      offset += 31;
      if (value_str)
        *value_str = (const gchar *)str_val;
      break;

    case NEW_FLOAT_EXT:
      proto_tree_add_item(tree, hf_erldp_new_float_ext, tvb, offset, 8, ENC_BIG_ENDIAN);
      if (value_str) {
        gdouble  new_float_val = tvb_get_ntohieee_double(tvb, offset);
        *value_str = wmem_strdup_printf(wmem_packet_scope(), "%f", new_float_val);
      }
      offset += 8;
      break;

    case ATOM_UTF8_EXT:
      proto_tree_add_item_ret_uint(tree, hf_erldp_atom_length2, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
      offset += 2;
      proto_tree_add_item_ret_string(tree, hf_erldp_atom_text, tvb, offset, len, ENC_NA|ENC_UTF_8, wmem_packet_scope(), &str_val);
      offset += len;
      if (value_str)
        *value_str = (const gchar *)str_val;
      break;

    case SMALL_ATOM_UTF8_EXT:
      proto_tree_add_item_ret_uint(tree, hf_erldp_atom_length, tvb, offset, 1, ENC_BIG_ENDIAN, &len);
      offset++;
      proto_tree_add_item_ret_string(tree, hf_erldp_atom_text, tvb, offset, len, ENC_NA|ENC_UTF_8, wmem_packet_scope(), &str_val);
      offset += len;
      if (value_str)
        *value_str = (const gchar *)str_val;
      break;

    case PORT_EXT:
      offset = dissect_etf_type("Node", pinfo, tvb, offset, tree);
      proto_tree_add_item(tree, hf_erldp_port_ext_id, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(tree, hf_erldp_port_ext_creation, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;
      break;

    case NEW_PORT_EXT:
      offset = dissect_etf_type("Node", pinfo, tvb, offset, tree);
      proto_tree_add_item(tree, hf_erldp_port_ext_id, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(tree, hf_erldp_port_ext_creation, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      break;

    case PID_EXT:
      offset = dissect_etf_type("Node", pinfo, tvb, offset, tree);
      proto_tree_add_item(tree, hf_erldp_pid_ext_id, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(tree, hf_erldp_pid_ext_serial, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(tree, hf_erldp_pid_ext_creation, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;
      break;

    case NEW_PID_EXT:
      offset = dissect_etf_type("Node", pinfo, tvb, offset, tree);
      proto_tree_add_item(tree, hf_erldp_pid_ext_id, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(tree, hf_erldp_pid_ext_serial, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(tree, hf_erldp_pid_ext_creation, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
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
      proto_tree_add_item_ret_uint(tree, hf_erldp_list_ext_len, tvb, offset, 4, ENC_BIG_ENDIAN, &len);
      offset += 4;
      for (i=0; i<len; i++) {
        offset = dissect_etf_type(NULL, pinfo, tvb, offset, tree);
      }
      offset = dissect_etf_type("Tail", pinfo, tvb, offset, tree);
      break;

    case BINARY_EXT:
      proto_tree_add_item_ret_uint(tree, hf_erldp_binary_ext_len, tvb, offset, 4, ENC_BIG_ENDIAN, &len);
      offset += 4;
      proto_tree_add_item(tree, hf_erldp_binary_ext, tvb, offset, len, ENC_NA);
      offset += len;
      break;

    case NEW_REFERENCE_EXT:
      proto_tree_add_item_ret_uint(tree, hf_erldp_new_ref_ext_len, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
      offset += 2;
      offset = dissect_etf_type("Node", pinfo, tvb, offset, tree);
      proto_tree_add_item(tree, hf_erldp_new_ref_ext_creation, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;
      for (i=0; i<len; i++) {
        id = tvb_get_ntohl(tvb, offset);
        proto_tree_add_uint_format(tree, hf_erldp_new_ref_ext_id, tvb, offset, 4,
                            id, "ID[%d]: 0x%08X", i, id);
        offset += 4;
      }
      break;

    case NEWER_REFERENCE_EXT:
      proto_tree_add_item_ret_uint(tree, hf_erldp_new_ref_ext_len, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
      offset += 2;
      offset = dissect_etf_type("Node", pinfo, tvb, offset, tree);
      proto_tree_add_item(tree, hf_erldp_new_ref_ext_creation, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      for (i=0; i<len; i++) {
        id = tvb_get_ntohl(tvb, offset);
        proto_tree_add_uint_format(tree, hf_erldp_new_ref_ext_id, tvb, offset, 4,
                            id, "ID[%d]: 0x%08X", i, id);
        offset += 4;
      }
      break;

    case FUN_EXT:
      proto_tree_add_item_ret_uint(tree, hf_erldp_fun_ext_num_free, tvb, offset, 4, ENC_BIG_ENDIAN, &len);
      offset += 4;
      offset = dissect_etf_type("Pid", pinfo, tvb, offset, tree);
      offset = dissect_etf_type("Module", pinfo, tvb, offset, tree);
      offset = dissect_etf_type("Index", pinfo, tvb, offset, tree);
      offset = dissect_etf_type("Unique", pinfo, tvb, offset, tree);

      for (i = 0; i < len; i++) {
          gchar buf[ITEM_LABEL_LENGTH];
          snprintf(buf, sizeof(buf), "Free Var[%u]", i + 1);
          offset = dissect_etf_type(buf, pinfo, tvb, offset, tree);
      }
      break;

    case NEW_FUN_EXT:
      proto_tree_add_item(tree, hf_erldp_new_fun_ext_size, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(tree, hf_erldp_new_fun_ext_arity, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      proto_tree_add_item(tree, hf_erldp_new_fun_ext_uniq, tvb, offset, 16, ENC_NA);
      offset += 16;
      proto_tree_add_item(tree, hf_erldp_new_fun_ext_index, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item_ret_uint(tree, hf_erldp_new_fun_ext_num_free, tvb, offset, 4, ENC_BIG_ENDIAN, &len);
      offset += 4;
      offset = dissect_etf_type("Module", pinfo, tvb, offset, tree);
      offset = dissect_etf_type("OldIndex", pinfo, tvb, offset, tree);
      offset = dissect_etf_type("OldUnique", pinfo, tvb, offset, tree);
      offset = dissect_etf_type("Pid", pinfo, tvb, offset, tree);

      for (i = 0; i < len; i++) {
          gchar buf[ITEM_LABEL_LENGTH];
          snprintf(buf, sizeof(buf), "Free Var[%u]", i + 1);
          offset = dissect_etf_type(buf, pinfo, tvb, offset, tree);
      }
      break;
  }

  return offset;
}

static gint dissect_etf_pdu_data(packet_info *pinfo, tvbuff_t *tvb, gint offset, proto_tree *tree) {
  guint8 ctl_op;

  if ((tvb_get_guint8(tvb, offset) == SMALL_TUPLE_EXT) && (tvb_get_guint8(tvb, offset + 2) == SMALL_INTEGER_EXT)) {
    ctl_op = tvb_get_guint8(tvb, offset + 3);
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str(ctl_op, VALS(erldp_ctlmsg_vals), "unknown ControlMessage operation (%d)"));
  }
  offset = dissect_etf_type("ControlMessage", pinfo, tvb, offset, tree);
  if (tvb_reported_length_remaining(tvb, offset) > 0)
    offset = dissect_etf_type("Message", pinfo, tvb, offset, tree);

  return offset;
}

static gint dissect_etf_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const gchar *label) {
  gint offset = 0;
  guint8 mag;
  guint32 tag;
  proto_item *ti;
  proto_tree *etf_tree;

  mag = tvb_get_guint8(tvb, offset);
  if (mag != VERSION_MAGIC) {
    return 0;
  }

  etf_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_etf, &ti, (label) ? label : "External Term Format");

  proto_tree_add_item(etf_tree, hf_etf_version_magic, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  proto_tree_add_item_ret_uint(etf_tree, hf_etf_dist_header_tag, tvb, offset, 1, ENC_BIG_ENDIAN, &tag);
  offset++;

  if (!label)
    proto_item_set_text(ti, "%s", val_to_str(tag, VALS(etf_header_tag_vals), "unknown tag (%d)"));

  switch (tag) {
    case DIST_HEADER:
      offset = dissect_etf_dist_header(pinfo, tvb, offset, etf_tree);
      proto_item_set_len(ti, offset);

      dissect_etf_pdu_data(pinfo, tvb, offset, tree);
      break;

    case DIST_FRAG_HEADER:
    case DIST_FRAG_CONT:
    {
      guint64 sequence_id, fragment_id;
      gboolean save_fragmented;
      fragment_head *frag_msg = NULL;
      tvbuff_t *next_tvb = NULL;
      gint len_rem;

      proto_tree_add_item_ret_uint64(etf_tree, hf_erldp_sequence_id, tvb, offset, 8, ENC_BIG_ENDIAN, &sequence_id);
      offset += 8;

      proto_tree_add_item_ret_uint64(etf_tree, hf_erldp_fragment_id, tvb, offset, 8, ENC_BIG_ENDIAN, &fragment_id);
      offset += 8;

      save_fragmented = pinfo->fragmented;

      len_rem = tvb_reported_length_remaining(tvb, offset);
      if (len_rem <= 0)
        return offset;

      pinfo->fragmented = TRUE;

      frag_msg = fragment_add_seq_next(&erldp_reassembly_table,
                                       tvb, offset, pinfo, (guint32)sequence_id, NULL,
                                       len_rem, fragment_id != 1);

      next_tvb = process_reassembled_data(tvb, offset, pinfo,
                                          "Reassembled ErlDP", frag_msg,
                                          &etf_frag_items, NULL, tree);

      if (next_tvb == NULL)
      { /* make a new subset */
        next_tvb = tvb_new_subset_remaining(tvb, offset);
        call_data_dissector(next_tvb, pinfo, tree);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (Fragment ID: %" PRIu64 ")", fragment_id);
      }
      else
      {
        offset = dissect_etf_dist_header(pinfo, next_tvb, 0, etf_tree);
        proto_item_set_len(ti, offset);

        dissect_etf_pdu_data(pinfo, next_tvb, offset, tree);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (Reassembled, Fragment ID: %" PRIu64 ")", fragment_id);
      }

      pinfo->fragmented = save_fragmented;
      offset = tvb_reported_length_remaining(tvb, offset);
      break;
    }
  }

  return offset;
}

static gint dissect_etf_versioned_type(const gchar *label, packet_info *pinfo, tvbuff_t *tvb, gint offset, proto_tree *tree) {
  if (tvb_get_guint8(tvb, offset) != VERSION_MAGIC) {
    proto_tree_add_item(tree, hf_erldp_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    col_set_str(pinfo->cinfo, COL_INFO, "unknown header format");
    return offset + 1;
  }
  offset += 1;

  return dissect_etf_type(label, pinfo, tvb, offset, tree);
}

static gint dissect_etf_type(const gchar *label, packet_info *pinfo, tvbuff_t *tvb, gint offset, proto_tree *tree) {
  gint begin = offset;
  guint32 tag;
  proto_item *ti;
  proto_tree *etf_tree;
  const gchar *value_str = NULL;

  etf_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_etf, &ti, (label) ? label : "External Term Format");

  proto_tree_add_item_ret_uint(etf_tree, hf_etf_tag, tvb, offset, 1, ENC_BIG_ENDIAN, &tag);
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
  return ((len > 0) && strchr("nNras", tag) && (len == (guint32)tvb_captured_length_remaining(tvb, offset + 2)));
}

/*--- dissect_erldp_handshake -------------------------------------------------*/
static void dissect_erldp_handshake(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  gint offset = 0;
  guint32 tag;
  gboolean is_challenge = FALSE;
  guint32 str_len;
  const guint8 *str;

  static int * const erldp_flags_flags[] = {
    &hf_erldp_flags_spare,
    &hf_erldp_flags_alias,
    &hf_erldp_flags_v4_nc,
    &hf_erldp_flags_name_me,
    &hf_erldp_flags_spawn,
    &hf_erldp_flags_reserved,
    &hf_erldp_flags_unlink_id,
    &hf_erldp_flags_handshake_23,
    &hf_erldp_flags_fragments,
    &hf_erldp_flags_exit_payload,
    &hf_erldp_flags_pending_connect,
    &hf_erldp_flags_big_seqtrace_labels,
    &hf_erldp_flags_send_sender,
    &hf_erldp_flags_big_creation,
    &hf_erldp_flags_map_tag,
    &hf_erldp_flags_utf8_atoms,
    &hf_erldp_flags_ets_compressed,
    &hf_erldp_flags_small_atom_tags,
    &hf_erldp_flags_dist_hdr_atom_cache,
    &hf_erldp_flags_unicode_io,
    &hf_erldp_flags_new_floats,
    &hf_erldp_flags_bit_binaries,
    &hf_erldp_flags_export_ptr_tag,
    &hf_erldp_flags_extended_pids_ports,
    &hf_erldp_flags_new_fun_tags,
    &hf_erldp_flags_hidden_atom_cache,
    &hf_erldp_flags_dist_monitor_name,
    &hf_erldp_flags_fun_tags,
    &hf_erldp_flags_dist_monitor,
    &hf_erldp_flags_extended_references,
    &hf_erldp_flags_atom_cache,
    &hf_erldp_flags_published,
    NULL
  };

  proto_tree_add_item(tree, hf_erldp_length_2, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item_ret_uint(tree, hf_erldp_tag, tvb, offset, 1, ENC_ASCII|ENC_NA, &tag);
  offset++;

  switch (tag) {
    case 'n' :
      proto_tree_add_item(tree, hf_erldp_version, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;

      proto_tree_add_bitmask(tree, tvb, offset, hf_erldp_flags_v5,
         ett_erldp_flags, erldp_flags_flags, ENC_BIG_ENDIAN);
      offset += 4;
      if (tvb_bytes_exist(tvb, offset, 4)) {
        if (!tvb_ascii_isprint(tvb, offset, 4)) {
          is_challenge = TRUE;
        }
      }
      if (is_challenge) {
        proto_tree_add_item(tree, hf_erldp_challenge, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
      }
      str_len = tvb_captured_length_remaining(tvb, offset);
      proto_tree_add_item_ret_string(tree, hf_erldp_name, tvb, offset, str_len, ENC_ASCII|ENC_NA, wmem_packet_scope(), &str);
      col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s", (is_challenge) ? "SEND_CHALLENGE" : "SEND_NAME", str);
      break;

    case 'N':
      proto_tree_add_bitmask(tree, tvb, offset, hf_erldp_flags_v6,
         ett_erldp_flags, erldp_flags_flags, ENC_BIG_ENDIAN);
      offset += 8;
      if (tvb_bytes_exist(tvb, offset + 6, 4)) {
        if (!tvb_ascii_isprint(tvb, offset + 6, 4)) {
          is_challenge = TRUE;
        }
      }
      if (is_challenge) {
        proto_tree_add_item(tree, hf_erldp_challenge, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
      }
      proto_tree_add_item(tree, hf_erldp_creation, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item_ret_uint(tree, hf_erldp_nlen, tvb, offset, 2, ENC_BIG_ENDIAN, &str_len);
      offset += 2;
      proto_tree_add_item_ret_string(tree, hf_erldp_name, tvb, offset, str_len, ENC_ASCII|ENC_NA, wmem_packet_scope(), &str);
      col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s", (is_challenge) ? "SEND_CHALLENGE" : "SEND_NAME", str);
      break;

    case 'r' :
      proto_tree_add_item(tree, hf_erldp_challenge, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(tree, hf_erldp_digest, tvb, offset, 16, ENC_NA);
      /*offset += 16;*/
      col_set_str(pinfo->cinfo, COL_INFO, "SEND_CHALLENGE_REPLY");
      break;

    case 'a' :
      proto_tree_add_item(tree, hf_erldp_digest, tvb, offset, 16, ENC_NA);
      /*offset += 16;*/
      col_set_str(pinfo->cinfo, COL_INFO, "SEND_CHALLENGE_ACK");
      break;

    case 's' :
      str_len = tvb_captured_length_remaining(tvb, offset);
      proto_tree_add_item_ret_string(tree, hf_erldp_status, tvb, offset, str_len, ENC_ASCII|ENC_NA, wmem_packet_scope(), &str);
      col_add_fstr(pinfo->cinfo, COL_INFO, "SEND_STATUS %s", str);
      break;
  }
}

/*--- dissect_erldp_pdu -------------------------------------------------*/
static int dissect_erldp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_) {
  gint offset;
  guint32 msg_len;
  guint8 type;
  proto_tree *erldp_tree;
  proto_item *ti;
  tvbuff_t *next_tvb = NULL;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);

  ti = proto_tree_add_item(tree, proto_erldp, tvb, 0, -1, ENC_NA);
  erldp_tree = proto_item_add_subtree(ti, ett_erldp);

  if (is_handshake(tvb, 0)) {
    dissect_erldp_handshake(tvb, pinfo, erldp_tree);
    return tvb_captured_length(tvb);
  }

  offset = 0;

  proto_tree_add_item_ret_uint(erldp_tree, hf_erldp_length_4, tvb, offset, 4, ENC_BIG_ENDIAN, &msg_len);
  offset += 4;

  if (msg_len == 0) {
    col_set_str(pinfo->cinfo, COL_INFO, "KEEP_ALIVE");
    return offset;
  }

  type = tvb_get_guint8(tvb, offset);
  switch (type) {
    case ERL_PASS_THROUGH:
      proto_tree_add_item(erldp_tree, hf_erldp_type, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;

      offset = dissect_etf_versioned_type("ControlMessage", pinfo, tvb, offset, erldp_tree);
      if (tvb_reported_length_remaining(tvb, offset) > 0) {
        dissect_etf_versioned_type("Message", pinfo, tvb, offset, erldp_tree);
      }
      break;

    case VERSION_MAGIC:
      next_tvb = tvb_new_subset_length_caplen(tvb, offset, -1, 4 + msg_len - offset);
      dissect_etf_pdu(next_tvb, pinfo, erldp_tree, "DistributionHeader");
     break;

    default:
      proto_tree_add_item(erldp_tree, hf_erldp_type, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;
      col_set_str(pinfo->cinfo, COL_INFO, "unknown header format");
  }

  return tvb_captured_length(tvb);
}

/*--- get_erldp_pdu_len -------------------------------------------------*/
static guint get_erldp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                               int offset, void *data _U_)
{
  if (is_handshake(tvb, offset))
    return(2 + tvb_get_ntohs(tvb, offset));

  return(4 + tvb_get_ntohl(tvb, offset));
}

/*--- dissect_erldp -------------------------------------------------*/
static int
dissect_erldp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data) {
  tcp_dissect_pdus(tvb, pinfo, tree,
                   erldp_desegment,    /* desegment or not   */
                    4,               /* fixed-length part of the PDU */
                   get_erldp_pdu_len,  /* routine to get the length of the PDU */
                   dissect_erldp_pdu, data); /* routine to dissect a PDU */
  return tvb_captured_length(tvb);
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
    { &hf_etf_version_magic, { "VERSION_MAGIC", "erldp.version_magic",
                        FT_UINT8, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_tag,  { "Tag", "erldp.tag",
                        FT_CHAR, BASE_HEX, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_type, { "Type", "erldp.type",
                        FT_UINT8, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_version, { "Version", "erldp.version",
                        FT_UINT16, BASE_DEC, VALS(epmd_version_vals), 0x0,
                        NULL, HFILL}},
    { &hf_erldp_flags_v5, { "Flags", "erldp.flags_v5",
                        FT_UINT32, BASE_HEX, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_flags_v6, { "Flags", "erldp.flags_v6",
                        FT_UINT64, BASE_HEX, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_flags_published, { "Published", "erldp.flags.published",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 0x1,
                        NULL, HFILL }},
    { &hf_erldp_flags_atom_cache, { "Atom Cache", "erldp.flags.atom_cache",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 0x2,
                        NULL, HFILL }},
    { &hf_erldp_flags_extended_references, { "Extended References", "erldp.flags.extended_references",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 0x4,
                        NULL, HFILL }},
    { &hf_erldp_flags_dist_monitor, { "Dist Monitor", "erldp.flags.dist_monitor",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 0x8,
                        NULL, HFILL }},
    { &hf_erldp_flags_fun_tags, { "Fun Tags", "erldp.flags.fun_tags",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 0x10,
                        NULL, HFILL }},
    { &hf_erldp_flags_dist_monitor_name, { "Dist Monitor Name", "erldp.flags.dist_monitor_name",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 0x20,
                        NULL, HFILL }},
    { &hf_erldp_flags_hidden_atom_cache, { "Hidden Atom Cache", "erldp.flags.hidden_atom_cache",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 0x40,
                        NULL, HFILL }},
    { &hf_erldp_flags_new_fun_tags, { "New Fun Tags", "erldp.flags.new_fun_tags",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 0x80,
                        NULL, HFILL }},
    { &hf_erldp_flags_extended_pids_ports, { "Extended Pids Ports", "erldp.flags.extended_pids_ports",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 0x100,
                        NULL, HFILL }},
    { &hf_erldp_flags_export_ptr_tag, { "Export PTR Tag", "erldp.flags.export_ptr_tag",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 0x200,
                        NULL, HFILL }},
    { &hf_erldp_flags_bit_binaries, { "Bit Binaries", "erldp.flags.bit_binaries",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 0x400,
                        NULL, HFILL }},
    { &hf_erldp_flags_new_floats, { "New Floats", "erldp.flags.new_floats",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 0x800,
                        NULL, HFILL }},
    { &hf_erldp_flags_unicode_io, { "Unicode IO", "erldp.flags.unicode_io",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 0x1000,
                        NULL, HFILL }},
    { &hf_erldp_flags_dist_hdr_atom_cache, { "Dist HDR Atom Cache", "erldp.flags.dist_hdr_atom_cache",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 0x2000,
                        NULL, HFILL }},
    { &hf_erldp_flags_small_atom_tags, { "Small Atom Tags", "erldp.flags.small_atom_tags",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 0x4000,
                        NULL, HFILL }},
    { &hf_erldp_flags_ets_compressed, { "ETS Compressed", "erldp.flags.ets_compressed",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 0x8000,
                        NULL, HFILL }},
    { &hf_erldp_flags_utf8_atoms, { "UTF8 Atoms", "erldp.flags.utf8_atoms",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 0x10000,
                        NULL, HFILL }},
    { &hf_erldp_flags_map_tag, { "Map Tag", "erldp.flags.map_tag",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 0x20000,
                        NULL, HFILL }},
    { &hf_erldp_flags_big_creation, { "Big Creation", "erldp.flags.big_creation",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 0x40000,
                        NULL, HFILL }},
    { &hf_erldp_flags_send_sender, { "Send Sender", "erldp.flags.send_sender",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 0x80000,
                        NULL, HFILL }},
    { &hf_erldp_flags_big_seqtrace_labels, { "Big Seqtrace Labels", "erldp.flags.big_seqtrace_labels",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 0x100000,
                        NULL, HFILL }},
    { &hf_erldp_flags_pending_connect, { "Pending Connect", "erldp.flags.pending_connect",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 0x200000,
                        NULL, HFILL }},
    { &hf_erldp_flags_exit_payload, { "Exit Payload", "erldp.flags.exit_payload",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 0x400000,
                        NULL, HFILL }},
    { &hf_erldp_flags_fragments, { "Fragments", "erldp.flags.fragments",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 0x800000,
                        NULL, HFILL }},
    { &hf_erldp_flags_handshake_23, { "Handshake 23", "erldp.flags.handshake_23",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 0x1000000,
                        NULL, HFILL }},
    { &hf_erldp_flags_unlink_id, { "Unlink Id", "erldp.flags.unlink_id",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 0x2000000,
                        NULL, HFILL }},
    { &hf_erldp_flags_reserved, { "Reserved", "erldp.flags.reserved",
                        FT_UINT64, BASE_DEC, NULL, 0xfc000000,
                        NULL, HFILL }},
    { &hf_erldp_flags_spawn, { "Spawn", "erldp.flags.spawn",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 1ULL << 32,
                        NULL, HFILL }},
    { &hf_erldp_flags_name_me, { "Name ME", "erldp.flags.name_me",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 1ULL << 33,
                        NULL, HFILL }},
    { &hf_erldp_flags_v4_nc, { "V4 NC", "erldp.flags.v4_nc",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 1ULL << 34,
                        NULL, HFILL }},
    { &hf_erldp_flags_alias, { "Alias", "erldp.flags.alias",
                        FT_BOOLEAN, 64, TFS(&tfs_true_false), 1ULL << 35,
                        NULL, HFILL }},
    { &hf_erldp_flags_spare, { "Spare", "erldp.flags.spare",
                        FT_UINT64, BASE_DEC, NULL,  ~(0ULL) << 36,
                        NULL, HFILL }},
    { &hf_erldp_creation, { "Creation", "erldp.creation",
                        FT_UINT32, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_challenge, { "Challenge", "erldp.challenge",
                        FT_UINT32, BASE_HEX, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_digest, { "Digest", "erldp.digest",
                        FT_BYTES, BASE_NONE, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_nlen, { "Name Length", "erldp.nlen",
                        FT_UINT16, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_name, { "Name", "erldp.name",
                        FT_STRING, BASE_NONE, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_status, { "Status", "erldp.status",
                        FT_STRING, BASE_NONE, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_sequence_id, { "Sequence Id", "erldp.sequence_id",
                        FT_UINT64, BASE_HEX, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_fragment_id, { "Fragment Id", "erldp.fragment_id",
                        FT_UINT64, BASE_HEX, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_num_atom_cache_refs, { "NumberOfAtomCacheRefs", "erldp.num_atom_cache_refs",
                        FT_UINT8, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_etf_flags, { "Flags", "erldp.etf_flags",
                        FT_BYTES, BASE_NONE, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_internal_segment_index, { "InternalSegmentIndex", "erldp.internal_segment_index",
                        FT_UINT8, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_atom_length, { "Length", "erldp.atom_length",
                        FT_UINT8, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_atom_length2, { "Length", "erldp.atom_length",
                        FT_UINT16, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_atom_text, { "AtomText", "erldp.atom_text",
                        FT_STRING, BASE_NONE, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_atom_cache_ref, { "AtomCacheReferenceIndex", "erldp.atom_cache_ref",
                        FT_UINT8, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_small_int_ext, { "Int", "erldp.small_int_ext",
                        FT_UINT8, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_int_ext, { "Int", "erldp.int_ext",
                        FT_INT32, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_small_big_ext_len, { "Len", "erldp.small_big_ext_len",
                        FT_UINT8, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_large_big_ext_len, { "Len", "erldp.large_big_ext_len",
                        FT_UINT32, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_big_ext_int, { "Int", "erldp.big_ext_int",
                        FT_UINT64, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_big_ext_str, { "Int", "erldp.big_ext_str",
                        FT_STRING, BASE_NONE, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_big_ext_bytes, { "Int", "erldp.big_ext_bytes",
                        FT_BYTES, BASE_NONE, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_float_ext, { "Float", "erldp.float_ext",
                        FT_STRINGZ, BASE_NONE, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_new_float_ext, { "Float", "erldp.new_float_ext",
                        FT_DOUBLE, BASE_NONE, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_port_ext_id, { "ID", "erldp.port_ext.id",
                        FT_UINT32, BASE_HEX, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_port_ext_creation, { "Creation", "erldp.port_ext.creation",
                        FT_UINT32, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_pid_ext_id, { "ID", "erldp.pid_ext.id",
                        FT_UINT32, BASE_HEX, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_pid_ext_serial, { "Serial", "erldp.pid_ext.serial",
                        FT_UINT32, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_pid_ext_creation, { "Creation", "erldp.pid_ext.creation",
                        FT_UINT32, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_list_ext_len, { "Len", "erldp.list_ext.len",
                        FT_UINT32, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_binary_ext_len, { "Len", "erldp.binary_ext.len",
                        FT_UINT32, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_binary_ext, { "Binary", "erldp.binary_ext",
                        FT_BYTES, BASE_SHOW_ASCII_PRINTABLE, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_new_ref_ext_len, { "Len", "erldp.new_ref_ext.len",
                        FT_UINT16, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_new_ref_ext_creation, { "Creation", "erldp.new_ref_ext.creation",
                        FT_UINT32, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_new_ref_ext_id, { "ID", "erldp.new_ref_ext.id",
                        FT_UINT32, BASE_HEX, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_fun_ext_num_free, { "Num Free", "erldp.fun_ext.num_free",
                        FT_UINT32, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_new_fun_ext_size, { "Size", "erldp.new_fun_ext.size",
                        FT_UINT32, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_new_fun_ext_arity, { "Arity", "erldp.new_fun_ext.arity",
                        FT_UINT8, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_new_fun_ext_uniq, { "Uniq", "erldp.new_fun_ext.uniq",
                        FT_BYTES, BASE_NONE, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_new_fun_ext_index, { "Index", "erldp.new_fun_ext.index",
                        FT_UINT32, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},
    { &hf_erldp_new_fun_ext_num_free, { "Num Free", "erldp.new_fun_ext.num_free",
                        FT_UINT32, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},

    /*---  ---*/
    { &hf_erldp_length_4, { "Length", "erldp.len",
                        FT_UINT32, BASE_DEC, NULL, 0x0,
                        "Message Length", HFILL}},

    /*--- ETF  ---*/
    { &hf_etf_tag,    { "Tag", "erldp.etf_tag",
                        FT_UINT8, BASE_DEC, VALS(etf_tag_vals), 0x0,
                        NULL, HFILL}},
    { &hf_etf_dist_header_tag, { "Tag", "erldp.etf_header_tag",
                        FT_UINT8, BASE_DEC, VALS(etf_header_tag_vals), 0x0,
                        NULL, HFILL}},

    { &hf_etf_dist_header_new_cache,    { "NewCacheEntryFlag", "erldp.dist_header.new_cache",
                        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08,
                        NULL, HFILL}},

    { &hf_etf_dist_header_segment_index,    { "SegmentIndex", "erldp.dist_header.segment_index",
                        FT_UINT8, BASE_DEC, NULL, 0x7,
                        NULL, HFILL}},

    { &hf_etf_dist_header_long_atoms,    { "LongAtoms", "erldp.dist_header.new_cache",
                        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x12,
                        NULL, HFILL}},

    { &hf_etf_arity4, { "Arity", "erldp.arity",
                        FT_UINT32, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},

    { &hf_etf_arity, { "Arity", "erldp.arity",
                        FT_UINT8, BASE_DEC, NULL, 0x0,
                        NULL, HFILL}},

    { &hf_etf_fragments, { "Message fragments", "erldp.dist.fragments",
                        FT_NONE, BASE_NONE, NULL, 0x0, NULL,
                        HFILL }},

    { &hf_etf_fragment, { "Message fragment", "erldp.dist.fragment",
                        FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                        NULL, HFILL }},

    { &hf_etf_fragment_overlap, { "Message fragment overlap", "erldp.dist.fragment.overlap",
                        FT_BOOLEAN, 0, NULL, 0x0,
                        NULL, HFILL }},

    { &hf_etf_fragment_overlap_conflicts, { "Message fragment overlapping with conflicting data",
                                                            "erldp.dist.fragment.overlap.conflicts",
                        FT_BOOLEAN, 0, NULL, 0x0,
                        NULL, HFILL }},

    { &hf_etf_fragment_multiple_tails, { "Message has multiple tail fragments",
                                                         "erldp.dist.fragment.multiple_tails",
                        FT_BOOLEAN, 0, NULL, 0x0,
                        NULL, HFILL }},

    { &hf_etf_fragment_too_long_fragment, { "Message fragment too long", "erldp.dist.fragment.too_long_fragment",
                        FT_BOOLEAN, 0, NULL, 0x0,
                        NULL, HFILL }},

    { &hf_etf_fragment_error, { "Message defragmentation error", "erldp.dist.fragment.error",
                        FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                        NULL, HFILL }},

    { &hf_etf_fragment_count, { "Message fragment count", "erldp.dist.fragment.count",
                        FT_UINT32, BASE_DEC, NULL, 0x0,
                        NULL, HFILL }},

    { &hf_etf_reassembled_in, { "Reassembled in", "erldp.dist.reassembled.in",
                        FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                        NULL, HFILL }},

    { &hf_etf_reassembled_length, { "Reassembled length", "erldp.dist.reassembled.length",
                        FT_UINT32, BASE_DEC, NULL, 0x0,
                        NULL, HFILL }},

    { &hf_etf_reassembled_data, { "Reassembled data", "erldp.dist.reassembled.data",
                        FT_BYTES, BASE_NONE, NULL, 0x0,
                        NULL, HFILL }},
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_erldp,
    &ett_erldp_flags,
    &ett_etf,
    &ett_etf_flags,
    &ett_etf_acrs,
    &ett_etf_acr,
    &ett_etf_tmp,
    &ett_etf_fragment,
    &ett_etf_fragments,
  };

  /* Register protocol and dissector */
  proto_erldp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  reassembly_table_register(&erldp_reassembly_table,
                          &addresses_reassembly_table_functions);

  erldp_handle = register_dissector(PFNAME, dissect_erldp, proto_erldp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_erldp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}

/*--- proto_reg_handoff_erldp -------------------------------------------*/
void proto_reg_handoff_erldp(void) {

  dissector_add_for_decode_as_with_preference("tcp.port", erldp_handle);
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
