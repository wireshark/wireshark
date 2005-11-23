/* packet-p_mul.c
 *
 * Routines for P_Mul (ACP142) packet disassembly.
 * A protocol for reliable multicast messaging in bandwidth constrained
 * and delayed acknowledgement (EMCON) environments.
 *
 * Copyright 2005, Stig Bjørlykke <stig@bjorlykke.org>, Thales Norway AS
 *
 * $Id$
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
 *
 * Ref:  http://www.jcs.mil/j6/cceb/acps/Acp142.pdf
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>

#include "packet-cdt.h"

#define PNAME  "P_Mul (ACP142)"
#define PSNAME "P_MUL"
#define PFNAME "p_mul"

/* Recommended UDP Port Numbers */
#define P_MUL_TPORT 2751
#define P_MUL_RPORT 2752
#define P_MUL_DPORT 2753
#define P_MUL_APORT 2754

/* PDU Types */
#define Data_PDU             0x00
#define Ack_PDU              0x01
#define Address_PDU          0x02
#define Discard_Message_PDU  0x03
#define Announce_PDU         0x04
#define Request_PDU          0x05
#define Reject_PDU           0x06
#define Release_PDU          0x07

/* Type of content to decode from Data_PDU */
#define DECODE_NONE      0
#define DECODE_CDT       1

void proto_reg_handoff_p_mul (void);

static int proto_p_mul = -1;

static int hf_length = -1;
static int hf_priority = -1;
static int hf_map_first = -1;
static int hf_map_last = -1;
static int hf_map_unused = -1;
static int hf_pdu_type = -1;
static int hf_no_pdus = -1;
static int hf_seq_no = -1;
static int hf_unused8 = -1;
static int hf_unused16 = -1;
static int hf_checksum = -1;
static int hf_source_id_ack = -1;
static int hf_source_id = -1;
static int hf_message_id = -1;
static int hf_expiry_time = -1;
static int hf_mc_group = -1;
static int hf_ann_mc_group = -1;
static int hf_count_of_dest = -1;
static int hf_length_of_res = -1;
static int hf_ack_count = -1;
static int hf_ack_entry = -1;
static int hf_ack_length = -1;
static int hf_miss_seq_no = -1;
static int hf_dest_entry = -1;
static int hf_dest_id = -1;
static int hf_msg_seq_no = -1;
static int hf_sym_key = -1;
static int hf_data_fragment = -1;

static int hf_msg_fragments = -1;
static int hf_msg_fragment = -1;
static int hf_msg_fragment_overlap = -1;
static int hf_msg_fragment_overlap_conflicts = -1;
static int hf_msg_fragment_multiple_tails = -1;
static int hf_msg_fragment_too_long_fragment = -1;
static int hf_msg_fragment_error = -1;
static int hf_msg_reassembled_in = -1;

static gint ett_p_mul = -1;
static gint ett_pdu_type = -1;
static gint ett_entry = -1;
static gint ett_msg_fragment = -1;
static gint ett_msg_fragments = -1;


/* User definable values to use for dissection */
static gboolean p_mul_reassemble = TRUE;
static gint decode_option = DECODE_NONE;

static guint global_p_mul_tport = P_MUL_TPORT;
static guint global_p_mul_rport = P_MUL_RPORT;
static guint global_p_mul_dport = P_MUL_DPORT;
static guint global_p_mul_aport = P_MUL_APORT;

static guint p_mul_tport = 0;
static guint p_mul_rport = 0;
static guint p_mul_dport = 0;
static guint p_mul_aport = 0;

static GHashTable *p_mul_fragment_table = NULL;
static GHashTable *p_mul_reassembled_table = NULL;

static const fragment_items p_mul_frag_items = {
  /* Fragment subtrees */
  &ett_msg_fragment,
  &ett_msg_fragments,
  /* Fragment fields */
  &hf_msg_fragments,
  &hf_msg_fragment,
  &hf_msg_fragment_overlap,
  &hf_msg_fragment_overlap_conflicts,
  &hf_msg_fragment_multiple_tails,
  &hf_msg_fragment_too_long_fragment,
  &hf_msg_fragment_error,
  /* Reassembled in field */
  &hf_msg_reassembled_in,
  /* Tag */
  "Message fragments"
};

static const value_string pdu_vals[] = {
  { Data_PDU,             "Data PDU"            },
  { Ack_PDU,              "Ack PDU"             },
  { Address_PDU,          "Address PDU"         },
  { Discard_Message_PDU,  "Discard Message PDU" },
  { Announce_PDU,         "Announce PDU"        },
  { Request_PDU,          "Request PDU"         },
  { Reject_PDU,           "Reject PDU"          },
  { Release_PDU,          "Release PDU"         },
  { 0,                    NULL                  } 
};

static enum_val_t decode_options[] = {
  { "none", "No decoding",          DECODE_NONE },
  { "cdt",  "Compressed Data Type", DECODE_CDT  },
  { NULL,   NULL,                   0           }
};

static const true_false_string yes_no = {
  "No", "Yes"
};

static const gchar *get_type (guint8 value)
{
  return val_to_str (value, pdu_vals, "Unknown");
}


/*Function checksum, found in ACP142 annex B-3 */
static guint16 checksum (guint8 *buffer, gint len, gint offset)
{
  guint16 c0 = 0, c1 = 0, ret, ctmp;
  gint16 cs;
  guint8 *hpp, *pls;

  buffer[offset] = 0;
  buffer[offset+1] = 0;
  ctmp = len - offset - 1;

  pls = buffer + len;
  hpp = buffer;

  while (hpp < pls) {
    if ((c0 += *hpp++) > 254) { c0 -= 255; }
    if ((c1 += c0) > 254) { c1 -= 255; }
  }

  if ((cs = ((ctmp * c0) - c1) % 255L) < 0) { cs += 255; }
  ret = cs << 8;
  if ((cs = (c1 - ((ctmp + 1L) * c0)) % 255L) < 0) { cs += 255; }
  ret |= cs;

  return ret;
}

static void dissect_reassembled_data (tvbuff_t *tvb, packet_info *pinfo _U_,
                                      proto_tree *tree)
{
  if (tvb == NULL || tree == NULL) {
    return;
  }

  if (decode_option == DECODE_CDT) {
    dissect_cdt (tvb, pinfo, tree);
  }
}

static void dissect_p_mul (tvbuff_t *tvb, packet_info *pinfo _U_,
                           proto_tree *tree)
{
  proto_tree *p_mul_tree = NULL, *field_tree = NULL;
  proto_item *ti = NULL, *en = NULL, *len_en = NULL;
  gboolean    save_fragmented;
  fragment_data *frag_msg = NULL;
  guint32     message_id = 0, no_pdus = 0, seq_no = 0;
  guint16     no_dest = 0, count = 0, len = 0, data_len = 0;
  guint16     checksum1, checksum2, pdu_length = 0;
  guint8      pdu_type = 0, *value = NULL, map = 0;
  gint        i, no_missing = 0, offset = 0;
  nstime_t    ts;

  if (check_col (pinfo->cinfo, COL_PROTOCOL))
    col_set_str (pinfo->cinfo, COL_PROTOCOL, "P_MUL");

  if (check_col (pinfo->cinfo, COL_INFO))
    col_clear (pinfo->cinfo, COL_INFO);

  /* First fetch PDU Type */
  pdu_type = tvb_get_guint8 (tvb, offset + 3) & 0x3F;

  ti = proto_tree_add_item (tree, proto_p_mul, tvb, offset, -1, FALSE);
  proto_item_append_text (ti, ", %s", get_type (pdu_type));
  p_mul_tree = proto_item_add_subtree (ti, ett_p_mul);

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, "%s", get_type (pdu_type));

  /* Length of PDU */
  pdu_length = tvb_get_ntohs (tvb, offset);
  len_en = proto_tree_add_item (p_mul_tree, hf_length, tvb, offset, 2, FALSE);
  offset += 2;

  switch (pdu_type) {

  case Data_PDU:
  case Ack_PDU:
  case Address_PDU:
  case Discard_Message_PDU:
    /* Priority */
    proto_tree_add_item (p_mul_tree, hf_priority, tvb, offset, 1, FALSE);
    break;

  default:
    /* Unused */
    proto_tree_add_item (p_mul_tree, hf_unused8, tvb, offset, 1, FALSE);
  }
  offset += 1;

  /* MAP / PDU_Type */
  en = proto_tree_add_uint_format (p_mul_tree, hf_pdu_type, tvb, offset, 1,
                                   pdu_type, "PDU Type: %s (0x%02x)",
                                   get_type (pdu_type), pdu_type);
  field_tree = proto_item_add_subtree (en, ett_pdu_type);

  switch (pdu_type) {

  case Address_PDU:
  case Announce_PDU:
    map = tvb_get_guint8 (tvb, offset);
    proto_tree_add_item (field_tree, hf_map_first, tvb, offset, 1, FALSE);
    proto_tree_add_item (field_tree, hf_map_last, tvb, offset, 1, FALSE);
    if ((map & 0x80) || (map & 0x40)) {
      proto_item_append_text (en, ", %s / %s",
                              (map & 0x80) ? "Not first" : "First",
                              (map & 0x40) ? "Not last" : "Last");
    } else {
      proto_item_append_text (en, ", Only one PDU");
    }
    break;

  default:
    proto_tree_add_item (field_tree, hf_map_unused, tvb, offset, 1, FALSE);
    break;
  }
  proto_tree_add_item (field_tree, hf_pdu_type, tvb, offset, 1, FALSE);
  offset += 1;

  switch (pdu_type) {

  case Address_PDU:
    /* Total Number of PDUs */
    no_pdus = tvb_get_ntohs (tvb, offset);
    proto_tree_add_item (p_mul_tree, hf_no_pdus, tvb, offset, 2, FALSE);
    proto_item_append_text (ti, ", No PDUs: %u", no_pdus);
    if (check_col (pinfo->cinfo, COL_INFO))
      col_append_fstr (pinfo->cinfo, COL_INFO, ", No PDUs: %u", no_pdus);
    break;

  case Data_PDU:
    /* Sequence Number of PDUs */
    seq_no = tvb_get_ntohs (tvb, offset);
    proto_tree_add_item (p_mul_tree, hf_seq_no, tvb, offset, 2, FALSE);
    proto_item_append_text (ti, ", Seq no: %u", seq_no);
    if (check_col (pinfo->cinfo, COL_INFO))
        col_append_fstr (pinfo->cinfo, COL_INFO, ", Seq no: %u", seq_no);
    break;

  case Announce_PDU:
    /* Count of Destination Entries */
    count = tvb_get_ntohs (tvb, offset);
    proto_tree_add_item (p_mul_tree, hf_count_of_dest, tvb, offset, 2,FALSE);
    break;

  default:
    /* Unused */
    proto_tree_add_item (p_mul_tree, hf_unused16, tvb, offset, 2, FALSE);
    break;
  }
  offset += 2;

  /* Checksum */
  len = tvb_length (tvb);
  value = tvb_get_string (tvb, 0, len);
  checksum1 = checksum (value, len, offset);
  checksum2 = tvb_get_ntohs (tvb, offset);
  g_free (value);
  en = proto_tree_add_item (p_mul_tree, hf_checksum, tvb, offset, 2, FALSE);
  if (checksum1 == checksum2) {
    proto_item_append_text (en, " (correct)");
  } else {
    proto_item_append_text (en, " (incorrect, should be 0x%04x)", checksum1);
  }
  offset += 2;

  if (pdu_type == Ack_PDU) {
    /* Source ID of Ack Sender */
    proto_tree_add_item (p_mul_tree, hf_source_id_ack, tvb, offset, 4, FALSE);
    offset += 4;

    /* Count of Ack Info Entries */
    count = tvb_get_ntohs (tvb, offset);
    proto_tree_add_item (p_mul_tree, hf_ack_count, tvb, offset, 2, FALSE);
    offset += 2;
  } else {
    /* Source Id */
    proto_tree_add_item (p_mul_tree, hf_source_id, tvb, offset, 4, FALSE);
    offset += 4;

    /* Message Id */
    message_id = tvb_get_ntohl (tvb, offset);
    proto_tree_add_item (p_mul_tree, hf_message_id, tvb, offset, 4, FALSE);
    offset += 4;
    
    proto_item_append_text (ti, ", MSID: %u", message_id);
    if (check_col (pinfo->cinfo, COL_INFO))
      col_append_fstr (pinfo->cinfo, COL_INFO, ", MSID: %u", message_id);
  }

  if (pdu_type == Address_PDU || pdu_type == Announce_PDU) {
    /* Expiry Time */
    ts.secs = tvb_get_ntohl (tvb, offset);
    ts.nsecs = 0;
    proto_tree_add_time (p_mul_tree, hf_expiry_time, tvb, offset, 4, &ts);
    offset += 4;
  }

  save_fragmented = pinfo->fragmented;

  switch (pdu_type) {

  case Address_PDU:
    /* Count of Destination Entries */
    no_dest = tvb_get_ntohs (tvb, offset);
    proto_tree_add_item (p_mul_tree, hf_count_of_dest, tvb, offset, 2, FALSE);
    offset += 2;

    /* Length of Reserved Field */
    len = tvb_get_ntohs (tvb, offset);
    proto_tree_add_item (p_mul_tree, hf_length_of_res, tvb, offset, 2, FALSE);
    offset += 2;

    for (i = 0; i < no_dest; i++) {
      /* Destination Entry */
      en = proto_tree_add_none_format (p_mul_tree, hf_dest_entry, tvb,
                                       offset, no_dest * (8 + len),
                                       "Destination Entry #%d", i + 1);
      field_tree = proto_item_add_subtree (en, ett_entry);

      /* Destination Id */
      proto_tree_add_item (field_tree, hf_dest_id, tvb, offset, 4, FALSE);
      offset += 4;

      /* Message Sequence Number */
      proto_tree_add_item (field_tree, hf_msg_seq_no, tvb, offset, 4, FALSE);
      offset += 4;

      if (len > 0) {
        /* Reserved Field (variable length) */
        proto_tree_add_none_format (field_tree, hf_sym_key, tvb, offset,
                                    len, "Symmetric Key (%d byte%s)",
                                    len, plurality (len, "", "s"));
        offset += len;
      }
    }

    proto_item_append_text (ti, ", Count of Dest: %u", no_dest);
    if (check_col (pinfo->cinfo, COL_INFO))
      col_append_fstr (pinfo->cinfo, COL_INFO, ", Count of Dest: %u", no_dest);

    if (p_mul_reassemble) {
      /* Add fragment to fragment table */
      frag_msg = fragment_add_seq_check (tvb, offset, pinfo, message_id,
                                         p_mul_fragment_table,
                                         p_mul_reassembled_table, 0, 0, TRUE);
      fragment_set_tot_len (pinfo, message_id, p_mul_fragment_table, no_pdus);
    }
    break;

  case Data_PDU:
    /* Fragment of Data (variable length) */
    data_len = tvb_length_remaining (tvb, offset);
    proto_tree_add_none_format (tree, hf_data_fragment, tvb, offset,
                                data_len, "Fragment %d of Data (%d byte%s)",
                                seq_no, data_len,
                                plurality (data_len, "", "s"));

    if (p_mul_reassemble) {
      tvbuff_t *new_tvb = NULL;

      pinfo->fragmented = TRUE;

      /* Add fragment to fragment table */
      frag_msg = fragment_add_seq_check (tvb, offset, pinfo, message_id,
                                         p_mul_fragment_table,
                                         p_mul_reassembled_table, seq_no,
                                         data_len, TRUE);
      new_tvb = process_reassembled_data (tvb, offset, pinfo,
                                          "Reassembled Data", frag_msg,
                                          &p_mul_frag_items, NULL, tree);

      if (check_col (pinfo->cinfo, COL_INFO) && frag_msg)
        col_append_fstr (pinfo->cinfo, COL_INFO, " (Message Reassembled)");

      if (new_tvb) {
        dissect_reassembled_data (new_tvb, pinfo, tree);
      }
    }
    break;

  case Ack_PDU:
    for (i = 0; i < count; i++) {
      /* Ack Info Entry */
      len = tvb_get_ntohs (tvb, offset);

      en = proto_tree_add_none_format (p_mul_tree, hf_ack_entry, tvb,
                                       offset, count * len,
                                       "Ack Info Entry #%d", i + 1);
      field_tree = proto_item_add_subtree (en, ett_entry);

      /* Length of Ack Info Entry */
      proto_tree_add_item (field_tree, hf_ack_length, tvb, offset, 2, FALSE);
      offset += 2;

      /* Source Id */
      proto_tree_add_item (field_tree, hf_source_id, tvb, offset, 4, FALSE);
      offset += 4;

      /* Message Id */
      proto_tree_add_item (field_tree, hf_message_id, tvb, offset, 4, FALSE);
      offset += 4;

      for (no_missing = 0; no_missing < (len - 10) / 2; no_missing++) {
        /* Missing Data PDU Seq Number */
        proto_tree_add_item (field_tree, hf_miss_seq_no, tvb,offset, 2, FALSE);
        offset += 2;
      }

      if (no_missing) {
        proto_item_append_text (ti, ", Missing seq numbers: %u", no_missing);
        if (check_col (pinfo->cinfo, COL_INFO))
          col_append_fstr (pinfo->cinfo, COL_INFO, ", Missing seq numbers: %u",
                           no_missing);
      }
    }
    break;

  case Announce_PDU:
    /* Announced Multicast Group */
    proto_tree_add_item (p_mul_tree, hf_ann_mc_group, tvb, offset, 4, FALSE);
    offset += 4;

    for (i = 0; i < count; i++) {
      /* Destination Id */
      proto_tree_add_item (p_mul_tree, hf_dest_id, tvb, offset, 4, FALSE);
      offset += 4;
    }
    break;

  case Request_PDU:
  case Reject_PDU:
  case Release_PDU:
    /* Multicast Group */
    proto_tree_add_item (p_mul_tree, hf_mc_group, tvb, offset, 4, FALSE);
    offset += 4;
    break;

  default:
    /* Nothing */
    break;
  }

  pinfo->fragmented = save_fragmented;

  /* Update length of P_Mul packet and check length values */
  proto_item_set_len (ti, offset);
  if (pdu_length != (offset + data_len)) {
    proto_item_append_text (len_en, " (incorrect, should be: %d)",
                            offset + data_len);
  } else if ((len = tvb_length_remaining (tvb, pdu_length)) > 0) {
    proto_item_append_text (len_en, " (more data in packet: %d)", len);
  }
}

static void p_mul_reassemble_init (void)
{
    fragment_table_init (&p_mul_fragment_table);
    reassembled_table_init (&p_mul_reassembled_table);
}

void proto_register_p_mul (void)
{
  static hf_register_info hf[] = {
    { &hf_length,
      { "Length of PDU", "p_mul.length", FT_UINT16, BASE_DEC,
        NULL, 0x0, "Length of PDU", HFILL } },
    { &hf_priority,
      { "Priority", "p_mul.priority", FT_UINT8, BASE_DEC,
        NULL, 0x0, "Priority", HFILL } },
    { &hf_map_first,
      { "First", "p_mul.first", FT_BOOLEAN, 8,
        TFS (&yes_no), 0x80, "First", HFILL } },
    { &hf_map_last,
      { "Last", "p_mul.last", FT_BOOLEAN, 8,
        TFS (&yes_no), 0x40, "Last", HFILL } },
    { &hf_map_unused,
      { "MAP unused", "p_mul.unused", FT_UINT8, BASE_DEC,
        NULL, 0xC0, "MAP unused", HFILL } },
    { &hf_pdu_type,
      { "PDU Type", "p_mul.pdu_type", FT_UINT8, BASE_DEC,
        VALS (pdu_vals), 0x3F, "PDU Type", HFILL } },
    { &hf_no_pdus,
      { "Total Number of PDUs", "p_mul.no_pdus", FT_UINT16, BASE_DEC,
        NULL, 0x0, "Total Number of PDUs", HFILL } },
    { &hf_seq_no,
      { "Sequence Number of PDUs", "p_mul.seq_no", FT_UINT16, BASE_DEC,
        NULL, 0x0, "Sequence Number of PDUs", HFILL } },
    { &hf_unused8,
      { "Unused", "p_mul.unused", FT_UINT8, BASE_DEC,
        NULL, 0x0, "Unused", HFILL } },
    { &hf_unused16,
      { "Unused", "p_mul.unused", FT_UINT16, BASE_DEC,
        NULL, 0x0, "Unused", HFILL } },
    { &hf_checksum,
      { "Checksum", "p_mul.checksum", FT_UINT16, BASE_HEX,
        NULL, 0x0, "Checksum", HFILL } },
    { &hf_source_id_ack,
      { "Source ID of Ack Sender", "p_mul.source_id_ack", FT_IPv4, BASE_DEC,
        NULL, 0x0, "Source ID of Ack Sender", HFILL } },
    { &hf_source_id,
      { "Source ID", "p_mul.source_id", FT_IPv4, BASE_DEC,
        NULL, 0x0, "Source ID", HFILL } },
    { &hf_message_id,
      { "Message ID (MSID)", "p_mul.message_id", FT_UINT32, BASE_DEC,
        NULL, 0x0, "Message ID", HFILL } },
    { &hf_expiry_time,
      { "Expiry Time", "p_mul.expiry_time", FT_ABSOLUTE_TIME, BASE_DEC,
        NULL, 0x0, "Expiry Time", HFILL } },
    { &hf_mc_group,
      { "Multicast Group", "p_mul.mc_group", FT_UINT32, BASE_DEC,
        NULL, 0x0, "Multicast Group", HFILL } },
    { &hf_ann_mc_group,
      { "Announced Multicast Group", "p_mul.ann_mc_group", FT_UINT32, BASE_DEC,
        NULL, 0x0, "Announced Multicast Group", HFILL } },
    { &hf_count_of_dest,
      { "Count of Destination Entries", "p_mul.dest_count", FT_UINT16,BASE_DEC,
        NULL, 0x0, "Count of Destination Entries", HFILL } },
    { &hf_length_of_res,
      { "Length of Reserved Field", "p_mul.reserved_length",FT_UINT16,BASE_DEC,
        NULL, 0x0, "Length of Reserved Field", HFILL } },
    { &hf_ack_count,
      { "Count of Ack Info Entries", "p_mul.ack_count", FT_UINT16, BASE_DEC,
        NULL, 0x0, "Count of Ack Info Entries", HFILL } },
    { &hf_ack_entry,
      { "Ack Info Entry", "p_mul.ack_info_entry", FT_NONE, BASE_NONE,
        NULL, 0x0, "Ack Info Entry", HFILL } },
    { &hf_ack_length,
      { "Length of Ack Info Entry", "p_mul.ack_length", FT_UINT16, BASE_DEC,
        NULL, 0x0, "Length of Ack Info Entry", HFILL } },
    { &hf_miss_seq_no,
      { "Missing Data PDU Seq Number", "p_mul.missing_seq_no", FT_UINT16,
        BASE_DEC, NULL, 0x0, "Missing Data PDU Seq Number", HFILL } },
    { &hf_dest_entry,
      { "Destination Entry", "p_mul.dest_entry", FT_NONE, BASE_NONE,
        NULL, 0x0, "Destination Entry", HFILL } },
    { &hf_dest_id,
      { "Destination ID", "p_mul.dest_id", FT_IPv4, BASE_DEC,
        NULL, 0x0, "Destination ID", HFILL } },
    { &hf_msg_seq_no,
      { "Message Sequence Number", "p_mul.msg_seq_no", FT_UINT16, BASE_DEC,
        NULL, 0x0, "Message Sequence Number", HFILL } },
    { &hf_sym_key,
      { "Symmetric Key", "p_mul.sym_key", FT_NONE, BASE_NONE,
        NULL, 0x0, "Symmetric Key", HFILL } },
    { &hf_data_fragment,
      { "Fragment of Data", "p_mul.data_fragment", FT_NONE, BASE_NONE,
        NULL, 0x0, "Fragment of Data", HFILL } },

    /* Fragment entries */
    { &hf_msg_fragments,
      { "Message fragments", "p_mul.fragments", FT_NONE, BASE_NONE,
        NULL, 0x00, "Message fragments", HFILL } },
    { &hf_msg_fragment,
      { "Message fragment", "p_mul.fragment", FT_FRAMENUM, BASE_NONE,
        NULL, 0x00, "Message fragment", HFILL } },
    { &hf_msg_fragment_overlap,
      { "Message fragment overlap", "p_mul.fragment.overlap", FT_BOOLEAN,
        BASE_NONE, NULL, 0x00, "Message fragment overlap", HFILL } },
    { &hf_msg_fragment_overlap_conflicts,
      { "Message fragment overlapping with conflicting data",
        "p_mul.fragment.overlap.conflicts", FT_BOOLEAN, BASE_NONE, NULL,
        0x00, "Message fragment overlapping with conflicting data", HFILL } },
    { &hf_msg_fragment_multiple_tails,
      { "Message has multiple tail fragments",
        "p_mul.fragment.multiple_tails", FT_BOOLEAN, BASE_NONE,
        NULL, 0x00, "Message has multiple tail fragments", HFILL } },
    { &hf_msg_fragment_too_long_fragment,
      { "Message fragment too long", "p_mul.fragment.too_long_fragment",
        FT_BOOLEAN, BASE_NONE, NULL, 0x00, "Message fragment too long",
        HFILL } },
    { &hf_msg_fragment_error,
      { "Message defragmentation error", "p_mul.fragment.error", FT_FRAMENUM,
        BASE_NONE, NULL, 0x00, "Message defragmentation error", HFILL } },
    { &hf_msg_reassembled_in,
      { "Reassembled in", "p_mul.reassembled.in", FT_FRAMENUM, BASE_NONE,
        NULL, 0x00, "Reassembled in", HFILL } },
  };

  static gint *ett[] = {
    &ett_p_mul,
    &ett_pdu_type,
    &ett_entry,
    &ett_msg_fragment,
    &ett_msg_fragments
  };

  module_t *p_mul_module;

  proto_p_mul = proto_register_protocol (PNAME, PSNAME, PFNAME);

  proto_register_field_array (proto_p_mul, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
  register_init_routine (&p_mul_reassemble_init);

  /* Register our configuration options */
  p_mul_module = prefs_register_protocol (proto_p_mul,
                                          proto_reg_handoff_p_mul);

  prefs_register_bool_preference (p_mul_module, "reassemble",
                                  "Reassemble fragmented P_Mul packets",
                                  "Reassemble fragmented P_Mul packets",
                                  &p_mul_reassemble);
  prefs_register_enum_preference (p_mul_module, "decode",
                                  "Decode Data PDU as",
                                  "Type of content in Data_PDU",
                                  &decode_option, decode_options, FALSE);
  prefs_register_uint_preference (p_mul_module, "tport", "TPORT",
                                  "Used for transmission of Request_PDUs, "
                                  "Reject_PDUs and Release_PDUs between"
                                  "the transmitters",
                                  10, &global_p_mul_tport);
  prefs_register_uint_preference (p_mul_module, "rport", "RPORT",
                                  "Used for transmission of Announce_PDUs "
                                  "to inform the receiver(s)",
                                  10, &global_p_mul_rport);
  prefs_register_uint_preference (p_mul_module, "dport", "DPORT",
                                  "Used for the data traffic from the "
                                  "transmitters to the receiver(s)",
                                  10, &global_p_mul_dport);
  prefs_register_uint_preference (p_mul_module, "aport", "APORT",
                                  "Used for the data traffic from the "
                                  "receiver(s) to the transmitter",
                                  10, &global_p_mul_aport);
}

void proto_reg_handoff_p_mul (void)
{
  static int p_mul_prefs_initialized = FALSE;
  static dissector_handle_t p_mul_handle;

  if (!p_mul_prefs_initialized) {
    p_mul_handle = create_dissector_handle (dissect_p_mul, proto_p_mul);
    p_mul_prefs_initialized = TRUE;
  } else {
    dissector_delete ("udp.port", p_mul_tport, p_mul_handle);
    dissector_delete ("udp.port", p_mul_rport, p_mul_handle);
    dissector_delete ("udp.port", p_mul_dport, p_mul_handle);
    dissector_delete ("udp.port", p_mul_aport, p_mul_handle);
  }

  /* Save port numbers for later deletion */
  p_mul_tport = global_p_mul_tport;
  p_mul_rport = global_p_mul_rport;
  p_mul_dport = global_p_mul_dport;
  p_mul_aport = global_p_mul_aport;

  /* We convert all P_Mul ports */
  dissector_add ("udp.port", global_p_mul_tport, p_mul_handle);
  dissector_add ("udp.port", global_p_mul_rport, p_mul_handle);
  dissector_add ("udp.port", global_p_mul_dport, p_mul_handle);
  dissector_add ("udp.port", global_p_mul_aport, p_mul_handle);
}
