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
 * Ref:  http://www.jcs.mil/j6/cceb/acps/Acp142.pdf
 */

/*
 * TODO:
 * - Obtain dedicated UDP port numbers
 * - SEQ/ACK analysis for Announce/Request/Reject/Release PDU
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/expert.h>
#include <epan/asn1.h>
#include <string.h>

#include "packet-cdt.h"

#define PNAME  "P_Mul (ACP142)"
#define PSNAME "P_MUL"
#define PFNAME "p_mul"

/* Recommended UDP Port Numbers */
#define DEFAULT_P_MUL_PORT_RANGE ""

/* PDU Types */
#define Data_PDU               0x00
#define Ack_PDU                0x01
#define Address_PDU            0x02
#define Discard_Message_PDU    0x03
#define Announce_PDU           0x04
#define Request_PDU            0x05
#define Reject_PDU             0x06
#define Release_PDU            0x07
#define FEC_Address_PDU        0x08
#define Extra_Address_PDU      0x12
#define Extra_FEC_Address_PDU  0x18

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
static int hf_checksum_good = -1;
static int hf_checksum_bad = -1;
static int hf_source_id_ack = -1;
static int hf_source_id = -1;
static int hf_message_id = -1;
static int hf_expiry_time = -1;
static int hf_mc_group = -1;
static int hf_ann_mc_group = -1;
static int hf_fec_len = -1;
static int hf_fec_id = -1;
static int hf_fec_parameters = -1;
static int hf_count_of_dest = -1;
static int hf_length_of_res = -1;
static int hf_ack_count = -1;
static int hf_ack_entry = -1;
static int hf_ack_length = -1;
static int hf_miss_seq_no = -1;
static int hf_miss_seq_range = -1;
static int hf_tot_miss_seq_no = -1;
static int hf_timestamp_option = -1;
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

static int hf_analysis_ack_time = -1;
static int hf_analysis_total_time = -1;
static int hf_analysis_retrans_time = -1;
static int hf_analysis_total_retrans_time = -1;
static int hf_analysis_last_pdu_num = -1;
static int hf_analysis_addr_pdu_num = -1;
static int hf_analysis_addr_pdu_time = -1;
static int hf_analysis_addr_pdu_missing = -1;
static int hf_analysis_prev_pdu_num = -1;
static int hf_analysis_prev_pdu_time = -1;
static int hf_analysis_prev_pdu_missing = -1;
static int hf_analysis_retrans_no = -1;
static int hf_analysis_ack_num = -1;
static int hf_analysis_ack_missing = -1;
static int hf_analysis_ack_dup_no = -1;
static int hf_analysis_msg_resend_from = -1;
static int hf_analysis_ack_resend_from = -1;

static gint ett_p_mul = -1;
static gint ett_pdu_type = -1;
static gint ett_dest_entry = -1;
static gint ett_ack_entry = -1;
static gint ett_range_entry = -1;
static gint ett_checksum = -1;
static gint ett_analysis = -1;
static gint ett_msg_fragment = -1;
static gint ett_msg_fragments = -1;

static dissector_handle_t p_mul_handle = NULL;

typedef struct _p_mul_id_key {
  guint32 id;
  guint16 seq;
  address addr;
} p_mul_id_key;

typedef struct _p_mul_id_val {
  gint     msg_type;                   /* Message type                   */
  guint32  prev_msg_id;                /* Previous message package num   */
  nstime_t prev_msg_time;              /* Previous message receive time  */
  guint32  addr_id;                    /* PDU package num for Address_PDU */
  nstime_t addr_time;                  /* PDU received time for Address_PDU */
  guint32  pdu_id;                     /* PDU package num                */
  nstime_t pdu_time;                   /* PDU receive time               */
  guint32  prev_pdu_id;                /* Previous PDU package num       */
  nstime_t prev_pdu_time;              /* Previous PDU receive time      */
  guint32  ack_id;                     /* Ack PDU package num            */
  guint16  last_found_pdu;             /* Last PDU num                   */
  nstime_t first_msg_time;             /* First message receive time     */
  guint32  msg_resend_count;           /* Message resend counter         */
  guint32  ack_resend_count;           /* Ack resend counter             */
} p_mul_id_val;

static GHashTable *p_mul_id_hash_table = NULL;

/* User definable values to use for dissection */
static range_t *global_p_mul_port_range;
static gboolean p_mul_reassemble = TRUE;
static gint decode_option = DECODE_NONE;
static gboolean use_relative_msgid = TRUE;
static gboolean use_seq_ack_analysis = TRUE;

static GHashTable *p_mul_fragment_table = NULL;
static GHashTable *p_mul_reassembled_table = NULL;

static guint32 message_id_offset = 0;

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
  { Data_PDU,              "Data PDU"              },
  { Ack_PDU,               "Ack PDU"               },
  { Address_PDU,           "Address PDU"           },
  { Discard_Message_PDU,   "Discard Message PDU"   },
  { Announce_PDU,          "Announce PDU"          },
  { Request_PDU,           "Request PDU"           },
  { Reject_PDU,            "Reject PDU"            },
  { Release_PDU,           "Release PDU"           },
  { FEC_Address_PDU,       "FEC Address PDU"       },
  { Extra_Address_PDU,     "Extra Address PDU"     },
  { Extra_FEC_Address_PDU, "Extra FEC Address PDU" },
  { 0,                     NULL                    }
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

  if (len < offset+2) {
    /* Buffer to small */
    return 0;
  }

  buffer[offset] = 0;
  buffer[offset+1] = 0;
  ctmp = len - offset - 1;

  pls = buffer + len;
  hpp = buffer;

  while (hpp < pls) {
    if ((c0 += *hpp++) > 254) { c0 -= 255; }
    if ((c1 += c0) > 254) { c1 -= 255; }
  }

  if ((cs = ((ctmp * c0) - c1) % 255) < 0) { cs += 255; }
  ret = cs << 8;
  if ((cs = (c1 - ((ctmp + 1L) * c0)) % 255) < 0) { cs += 255; }
  ret |= cs;

  return ret;
}

static guint p_mul_id_hash (gconstpointer k)
{
  p_mul_id_key *p_mul=(p_mul_id_key *)k;
  return p_mul->id;
}

static gint p_mul_id_hash_equal (gconstpointer k1, gconstpointer k2)
{
  p_mul_id_key *p_mul1=(p_mul_id_key *)k1;
  p_mul_id_key *p_mul2=(p_mul_id_key *)k2;
  if (p_mul1->id != p_mul2->id)
    return 0;

  if (p_mul1->seq != p_mul2->seq)
    return 0;
  
  return (ADDRESSES_EQUAL (&p_mul1->addr, &p_mul2->addr));
}

static p_mul_id_val *register_p_mul_id (packet_info *pinfo, guint8 pdu_type,
                                        guint32 message_id, guint16 seq_no,
                                        gint no_missing)
{
  p_mul_id_val *p_mul_data = NULL, *pkg_data = NULL;
  p_mul_id_key *p_mul_key = NULL;
  nstime_t      addr_time = { 0, 0 }, prev_time = { 0, 0 };
  guint         addr_id = 0, prev_id = 0;
  guint16       last_found_pdu = 0;
  gboolean      missing_pdu = FALSE, set_address = FALSE;

  if (pinfo->in_error_pkt) {
    /* No analysis of error packets */
    return NULL;
  }

  p_mul_key = se_alloc (sizeof (p_mul_id_key));

  if (!pinfo->fd->flags.visited && 
      (pdu_type == Address_PDU || pdu_type == Data_PDU || pdu_type == Discard_Message_PDU)) 
  {
    /* Try to match corresponding address PDU */
    p_mul_key->id = message_id;
    p_mul_key->seq = 0;
    SE_COPY_ADDRESS(&p_mul_key->addr, &(pinfo->src));
    set_address = TRUE;

    p_mul_data = (p_mul_id_val *) g_hash_table_lookup (p_mul_id_hash_table, p_mul_key);

    if (p_mul_data) {
      /* Found address PDU */
      last_found_pdu = p_mul_data->last_found_pdu;
      p_mul_data->last_found_pdu = seq_no;
      addr_id = p_mul_data->pdu_id;
      addr_time = p_mul_data->pdu_time;
      
      /* Save data for last found PDU */
      p_mul_data->prev_pdu_id = pinfo->fd->num;
      p_mul_data->prev_pdu_time = pinfo->fd->abs_ts;

      if (pdu_type == Data_PDU && p_mul_data->msg_resend_count == 0 && last_found_pdu != seq_no - 1) {
        /* Data_PDU and missing previous PDU */
        missing_pdu = TRUE;
      }
      
      if (last_found_pdu) {
        /* Try to match previous data PDU */
        p_mul_key->seq = last_found_pdu;
        p_mul_data = (p_mul_id_val *) g_hash_table_lookup (p_mul_id_hash_table, p_mul_key);
      }
      
      if (p_mul_data) {
        /* Found a previous PDU (Address or Data) */
        if (p_mul_data->prev_msg_id > 0) {
          prev_id = p_mul_data->prev_msg_id;
        } else {
          prev_id = p_mul_data->pdu_id;
        }
        prev_time = p_mul_data->pdu_time;
      }
    }
  }
  
  p_mul_key->id = message_id;
  p_mul_key->seq = seq_no;
  if (pdu_type == Ack_PDU) {
    SE_COPY_ADDRESS(&p_mul_key->addr, &(pinfo->dst));
  } else if (!set_address) {
    SE_COPY_ADDRESS(&p_mul_key->addr, &(pinfo->src));
  }

  p_mul_data = (p_mul_id_val *) g_hash_table_lookup (p_mul_id_hash_table, p_mul_key);

  if (!pinfo->fd->flags.visited) {
    if (p_mul_data) {
      if (pdu_type == Ack_PDU) {
        /* Only save this data if positive ack */
        if (no_missing == 0) {
          if (p_mul_data->ack_id == 0) {
            /* Only save reference to first ACK */
            p_mul_data->ack_id = pinfo->fd->num;
          } else {
            /* Only count when resending */
            p_mul_data->ack_resend_count++;
          }
        }
      } else {
        /* Message resent */
        p_mul_data->msg_resend_count++;
        p_mul_data->prev_msg_id = pinfo->fd->num;
        p_mul_data->prev_msg_time = p_mul_data->pdu_time;
        p_mul_data->pdu_time = pinfo->fd->abs_ts;

        if (pdu_type == Data_PDU) {
          p_mul_data->prev_pdu_id = prev_id;
          p_mul_data->prev_pdu_time = prev_time;
        }
      }
    } else {
      /* New message */
      p_mul_data = se_alloc (sizeof (p_mul_id_val));
      memset (p_mul_data, 0, sizeof (p_mul_id_val));
      p_mul_data->msg_type = pdu_type;

      if (pdu_type == Ack_PDU) {
        /* No matching message for this ack */
        p_mul_data->ack_id = pinfo->fd->num;
      } else {
        p_mul_data->pdu_id = pinfo->fd->num;
        p_mul_data->pdu_time = pinfo->fd->abs_ts;
        p_mul_data->addr_id = addr_id;
        p_mul_data->addr_time = addr_time;
        p_mul_data->first_msg_time = pinfo->fd->abs_ts;
        
        if (pdu_type == Data_PDU && !missing_pdu) {
          p_mul_data->prev_pdu_id = prev_id;
          p_mul_data->prev_pdu_time = prev_time;
        }

        g_hash_table_insert (p_mul_id_hash_table, p_mul_key, p_mul_data);
      }
    }

    pkg_data = se_alloc (sizeof (p_mul_id_val));
    *pkg_data = *p_mul_data;
    p_add_proto_data (pinfo->fd, proto_p_mul, pkg_data);
  } else {
    /* Fetch last values from data saved in packet */
    pkg_data = p_get_proto_data (pinfo->fd, proto_p_mul);

    if (p_mul_data && pdu_type != Ack_PDU && pkg_data->ack_id == 0) {
      pkg_data->ack_id = p_mul_data->ack_id;
    }
  }

  DISSECTOR_ASSERT (pkg_data);
  return pkg_data;
}

static p_mul_id_val *p_mul_add_seq_ack (tvbuff_t *tvb, packet_info *pinfo,
                                        proto_tree *p_mul_tree, gint offset,
                                        guint8 pdu_type, guint32 message_id,
                                        guint16 seq_no, gint no_missing)
{
  p_mul_id_val *pkg_data = NULL;
  proto_tree *analysis_tree = NULL;
  proto_item *en = NULL, *eh = NULL;
  nstime_t    ns;

  pkg_data = register_p_mul_id (pinfo, pdu_type, message_id, seq_no, 
                                no_missing);

  if (!pkg_data) {
    /* No need for seq/ack analysis */
    return NULL;
  }

  en = proto_tree_add_text (p_mul_tree, tvb, 0, 0, "SEQ/ACK analysis");
  PROTO_ITEM_SET_GENERATED (en);
  analysis_tree = proto_item_add_subtree (en, ett_analysis);

  if ((pdu_type == Address_PDU) || (pdu_type == Data_PDU) || 
      (pdu_type == Discard_Message_PDU)) 
  {
    if (pdu_type == Address_PDU) {
      if (pkg_data->ack_id) {
        en = proto_tree_add_uint (analysis_tree, hf_analysis_ack_num, tvb,
                                  0, 0, pkg_data->ack_id);
        PROTO_ITEM_SET_GENERATED (en);
      } else if (!pkg_data->msg_resend_count) {
        en = proto_tree_add_item (analysis_tree,
                                  hf_analysis_ack_missing,
                                  tvb, offset, 0, FALSE);
        if (pinfo->fd->flags.visited) {
          /* We do not know this on first visit and we do not want to
             add a entry in the "Expert Severity Info" for this note */
          expert_add_info_format (pinfo, en, PI_SEQUENCE, PI_NOTE,
                                  "Ack PDU missing");
          PROTO_ITEM_SET_GENERATED (en);
        }
      }
    } else {
      if (pkg_data->addr_id) {
        en = proto_tree_add_uint (analysis_tree, hf_analysis_addr_pdu_num, tvb,
                                  0, 0, pkg_data->addr_id);
        PROTO_ITEM_SET_GENERATED (en);
        
        nstime_delta (&ns, &pinfo->fd->abs_ts, &pkg_data->addr_time);
        en = proto_tree_add_time (analysis_tree, hf_analysis_addr_pdu_time,
                                  tvb, 0, 0, &ns);
        PROTO_ITEM_SET_GENERATED (en);
      } else if (!pkg_data->msg_resend_count) {
        en = proto_tree_add_item (analysis_tree,
                                  hf_analysis_addr_pdu_missing,
                                  tvb, offset, 0, FALSE);
        expert_add_info_format (pinfo, en, PI_SEQUENCE, PI_NOTE,
                                "Address PDU missing");
        PROTO_ITEM_SET_GENERATED (en);
      }

      if ((pdu_type == Data_PDU) && (pkg_data->prev_pdu_id != pkg_data->addr_id)) {
        if (pkg_data->prev_pdu_id) {
          en = proto_tree_add_uint (analysis_tree, hf_analysis_prev_pdu_num, tvb,
                                    0, 0, pkg_data->prev_pdu_id);
          PROTO_ITEM_SET_GENERATED (en);
          
          nstime_delta (&ns, &pinfo->fd->abs_ts, &pkg_data->prev_pdu_time);
          en = proto_tree_add_time (analysis_tree, hf_analysis_prev_pdu_time,
                                    tvb, 0, 0, &ns);
          PROTO_ITEM_SET_GENERATED (en);
        } else if (!pkg_data->msg_resend_count) {
          en = proto_tree_add_item (analysis_tree,
                                    hf_analysis_prev_pdu_missing,
                                    tvb, offset, 0, FALSE);
          expert_add_info_format (pinfo, en, PI_SEQUENCE, PI_NOTE,
                                  "Previous PDU missing");
          PROTO_ITEM_SET_GENERATED (en);
        }
      }
    }
    
    if (pkg_data->msg_resend_count) {
      en = proto_tree_add_uint (analysis_tree, hf_analysis_retrans_no,
                                tvb, 0, 0, pkg_data->msg_resend_count);
      PROTO_ITEM_SET_GENERATED (en);
      
      en = proto_tree_add_uint (analysis_tree, hf_analysis_msg_resend_from,
                                tvb, 0, 0, pkg_data->pdu_id);
      PROTO_ITEM_SET_GENERATED (en);

      expert_add_info_format (pinfo, en, PI_SEQUENCE, PI_NOTE,
                              "Retransmission #%d",
                              pkg_data->msg_resend_count);
      
      nstime_delta (&ns, &pinfo->fd->abs_ts, &pkg_data->prev_msg_time);
      en = proto_tree_add_time (analysis_tree, hf_analysis_retrans_time,
                                tvb, 0, 0, &ns);
      PROTO_ITEM_SET_GENERATED (en);
      
      nstime_delta (&ns, &pinfo->fd->abs_ts, &pkg_data->first_msg_time);
      eh = proto_tree_add_time (analysis_tree, hf_analysis_total_retrans_time,
                                tvb, 0, 0, &ns);
      PROTO_ITEM_SET_GENERATED (eh);

      if (pkg_data->first_msg_time.secs == pkg_data->prev_msg_time.secs &&
          pkg_data->first_msg_time.nsecs == pkg_data->prev_msg_time.nsecs) {
        /* Time values does not differ, hide the total time */
        PROTO_ITEM_SET_HIDDEN (eh);
      }
    }
  } else if (pdu_type == Ack_PDU) {
    if (pkg_data->msg_type != Ack_PDU) {
      en = proto_tree_add_uint (analysis_tree, hf_analysis_addr_pdu_num,
                                tvb, 0, 0, pkg_data->pdu_id);
      PROTO_ITEM_SET_GENERATED (en);
      
      if (no_missing == 0) {
        nstime_delta (&ns, &pinfo->fd->abs_ts, &pkg_data->first_msg_time);
        eh = proto_tree_add_time (analysis_tree, hf_analysis_total_time,
                                  tvb, 0, 0, &ns);
        PROTO_ITEM_SET_GENERATED (eh);
      }

      if (pkg_data->prev_pdu_id) {
        en = proto_tree_add_uint (analysis_tree, hf_analysis_last_pdu_num,
                                  tvb, 0, 0, pkg_data->prev_pdu_id);
        PROTO_ITEM_SET_GENERATED (en);
      
        nstime_delta (&ns, &pinfo->fd->abs_ts, &pkg_data->prev_pdu_time);
        en = proto_tree_add_time (analysis_tree, hf_analysis_ack_time,
                                  tvb, 0, 0, &ns);
        PROTO_ITEM_SET_GENERATED (en);
      }
    } else {
      en = proto_tree_add_item (analysis_tree, hf_analysis_addr_pdu_missing,
                                tvb, 0, 0, FALSE);
      PROTO_ITEM_SET_GENERATED (en);
      
      expert_add_info_format (pinfo, en, PI_SEQUENCE, PI_NOTE,
                              "Address PDU missing");
    }
    
    if (pkg_data->ack_resend_count) {
      en = proto_tree_add_uint (analysis_tree, hf_analysis_ack_dup_no,
                                tvb, 0, 0, pkg_data->ack_resend_count);
      PROTO_ITEM_SET_GENERATED (en);
      
      expert_add_info_format (pinfo, en, PI_SEQUENCE, PI_NOTE,
                              "Dup ACK #%d", pkg_data->ack_resend_count);

      en = proto_tree_add_uint (analysis_tree, hf_analysis_ack_resend_from,
                                tvb, 0, 0, pkg_data->ack_id);
      PROTO_ITEM_SET_GENERATED (en);
    }
  }

  return pkg_data;
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
  proto_tree *p_mul_tree = NULL, *field_tree = NULL, *checksum_tree = NULL;
  proto_item *ti = NULL, *en = NULL, *len_en = NULL;
  p_mul_id_val *pkg_data = NULL;
  gboolean    save_fragmented;
  fragment_data *frag_msg = NULL;
  guint32     message_id = 0;
  guint16     no_dest = 0, count = 0, len = 0, data_len = 0;
  guint16     checksum1, checksum2, pdu_length = 0, no_pdus = 0, seq_no = 0;
  guint8      pdu_type = 0, *value = NULL, map = 0, fec_len;
  gint        i, tot_no_missing = 0, no_missing = 0, offset = 0;
  GString     *message_id_list = NULL;
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

  /* Length of PDU */
  pdu_length = tvb_get_ntohs (tvb, offset);
  len_en = proto_tree_add_item (p_mul_tree, hf_length, tvb, offset, 2, FALSE);
  offset += 2;

  switch (pdu_type) {

  case Data_PDU:
  case Ack_PDU:
  case Address_PDU:
  case Discard_Message_PDU:
  case Extra_Address_PDU:
  case FEC_Address_PDU:
  case Extra_FEC_Address_PDU:
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

  if (pdu_type == Discard_Message_PDU) {
    expert_add_info_format (pinfo, en, PI_RESPONSE_CODE, PI_NOTE,
                            "Message discarded");
  }

  switch (pdu_type) {

  case Address_PDU:
  case Announce_PDU:
  case Extra_Address_PDU:
  case FEC_Address_PDU:
  case Extra_FEC_Address_PDU:
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
  case Extra_Address_PDU:
  case FEC_Address_PDU:
  case Extra_FEC_Address_PDU:
    /* Total Number of PDUs */
    no_pdus = tvb_get_ntohs (tvb, offset);
    seq_no = 0;
    proto_tree_add_item (p_mul_tree, hf_no_pdus, tvb, offset, 2, FALSE);
    proto_item_append_text (ti, ", No PDUs: %u", no_pdus);
    break;

  case Data_PDU:
    /* Sequence Number of PDUs */
    seq_no = tvb_get_ntohs (tvb, offset);
    proto_tree_add_item (p_mul_tree, hf_seq_no, tvb, offset, 2, FALSE);
    proto_item_append_text (ti, ", Seq no: %u", seq_no);
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
  en = proto_tree_add_item (p_mul_tree, hf_checksum, tvb, offset, 2, FALSE);
  checksum_tree = proto_item_add_subtree (en, ett_checksum);
  len = tvb_length (tvb);
  value = tvb_get_ephemeral_string (tvb, 0, len);
  checksum1 = checksum (value, len, offset);
  checksum2 = tvb_get_ntohs (tvb, offset);
  if (checksum1 == checksum2) {
    proto_item_append_text (en, " (correct)");
    en = proto_tree_add_boolean (checksum_tree, hf_checksum_good, tvb,
                                 offset, 2, TRUE);
    PROTO_ITEM_SET_GENERATED (en);
    en = proto_tree_add_boolean (checksum_tree, hf_checksum_bad, tvb,
                                 offset, 2, FALSE);
    PROTO_ITEM_SET_GENERATED (en);
  } else {
    proto_item_append_text (en, " (incorrect, should be 0x%04x)", checksum1);
    expert_add_info_format (pinfo, en, PI_CHECKSUM, PI_WARN, "Bad checksum");
    en = proto_tree_add_boolean (checksum_tree, hf_checksum_good, tvb,
                                 offset, 2, FALSE);
    PROTO_ITEM_SET_GENERATED (en);
    en = proto_tree_add_boolean (checksum_tree, hf_checksum_bad, tvb,
                                 offset, 2, TRUE);
    PROTO_ITEM_SET_GENERATED (en);
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
    if (use_relative_msgid) {
      if (message_id_offset == 0) {
        /* First P_Mul package - initialize message_id_offset */
        message_id_offset = message_id;
      }
      message_id -= message_id_offset;
      proto_tree_add_uint_format (p_mul_tree, hf_message_id, tvb, offset, 4,
                                  message_id, "Message ID (MSID): %u"
                                  "    (relative message id)", message_id);
    } else {
      proto_tree_add_item (p_mul_tree, hf_message_id, tvb, offset, 4, FALSE);
    }
    offset += 4;

    proto_item_append_text (ti, ", MSID: %u", message_id);
  }

  if (pdu_type == Address_PDU || pdu_type == Announce_PDU ||
      pdu_type == Extra_Address_PDU || pdu_type == FEC_Address_PDU ||
      pdu_type == Extra_FEC_Address_PDU) {
    /* Expiry Time */
    ts.secs = tvb_get_ntohl (tvb, offset);
    ts.nsecs = 0;
    proto_tree_add_time (p_mul_tree, hf_expiry_time, tvb, offset, 4, &ts);
    offset += 4;
  }

  if (pdu_type == FEC_Address_PDU || pdu_type == Extra_FEC_Address_PDU) {
    /* FEC Parameters Length */
    fec_len = tvb_get_guint8 (tvb, offset);
    proto_tree_add_item (p_mul_tree, hf_fec_len, tvb, offset, 1, FALSE);
    offset += 1;
    
    /* FEC ID */
    proto_tree_add_item (p_mul_tree, hf_fec_id, tvb, offset, 1, FALSE);
    offset += 1;
    
    if (fec_len > 0) {
      /* FEC Parameters */
      proto_tree_add_none_format (p_mul_tree, hf_fec_parameters, tvb, offset,
                                  fec_len, "FEC Parameters (%d byte%s)",
                                  fec_len, plurality (fec_len, "", "s"));
      offset += fec_len;
    }
  }

  switch (pdu_type) {

  case Address_PDU:
  case Extra_Address_PDU:
  case FEC_Address_PDU:
  case Extra_FEC_Address_PDU:
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
                                       offset, 8 + len,
                                       "Destination Entry #%d", i + 1);
      field_tree = proto_item_add_subtree (en, ett_dest_entry);

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
    break;

  case Data_PDU:
    /* Fragment of Data (variable length) */
    data_len = tvb_length_remaining (tvb, offset);
    proto_tree_add_none_format (p_mul_tree, hf_data_fragment, tvb, offset,
                                data_len, "Fragment %d of Data (%d byte%s)",
                                seq_no, data_len,
                                plurality (data_len, "", "s"));
    break;

  case Ack_PDU:
    if (check_col (pinfo->cinfo, COL_INFO)) {
      message_id_list = g_string_new ("");
    }
    for (i = 0; i < count; i++) {
      /* Ack Info Entry */
      len = tvb_get_ntohs (tvb, offset);

      en = proto_tree_add_none_format (p_mul_tree, hf_ack_entry, tvb,
                                       offset, len,
                                       "Ack Info Entry #%d", i + 1);
      field_tree = proto_item_add_subtree (en, ett_ack_entry);

      /* Length of Ack Info Entry */
      en = proto_tree_add_item (field_tree, hf_ack_length, tvb, offset, 
                                2, FALSE);
      offset += 2;

      if (len < 10) {
        proto_item_append_text (en, "    (invalid length)");
        expert_add_info_format (pinfo, en, PI_MALFORMED, PI_WARN,
                                "Invalid ack info length");
      }

      /* Source Id */
      proto_tree_add_item (field_tree, hf_source_id, tvb, offset, 4, FALSE);
      offset += 4;

      /* Message Id */
      message_id = tvb_get_ntohl (tvb, offset);
      if (use_relative_msgid) {
        if (message_id_offset == 0) {
          /* First P_Mul package - initialize message_id_offset */
          message_id_offset = message_id;
        }
        message_id -= message_id_offset;
        proto_tree_add_uint_format (field_tree, hf_message_id, tvb, offset, 4,
                                    message_id, "Message ID (MSID): %u"
                                    "    (relative message id)", message_id);
      } else {
        proto_tree_add_item (field_tree, hf_message_id, tvb, offset, 4, FALSE);
      }
      offset += 4;

      if (check_col (pinfo->cinfo, COL_INFO)) {
        if (i == 0) {
          g_string_printf (message_id_list, "%d", message_id);
        } else {
          g_string_append_printf (message_id_list, ",%d", message_id);
        }
      }

      if (len > 10) {
        gint num_seq_no = (len - 10) / 2;
        for (no_missing = 0; no_missing < num_seq_no; no_missing++) {
          /* Missing Data PDU Seq Number */
          seq_no = tvb_get_ntohs (tvb, offset);
          if ((seq_no != 0) && (no_missing < num_seq_no - 2) && tvb_get_ntohs (tvb, offset + 2) == 0) {
            /* We are handling a range */
            guint16 end_seq_no = tvb_get_ntohs (tvb, offset + 4);
            
            en = proto_tree_add_bytes_format (field_tree, hf_miss_seq_range,
                                              tvb, offset, 6,
                                              tvb_get_ptr (tvb, offset, 6),
                                             "Missing Data PDU Seq Range: %d - %d",
                                             seq_no, end_seq_no);
            if (seq_no >= end_seq_no) {
              proto_item_append_text (en, "    (invalid)");
              expert_add_info_format (pinfo, en, PI_UNDECODED, PI_WARN,
                                      "Invalid missing sequence range");
            } else {
              proto_tree *missing_tree;
              guint16 sno;
              
              missing_tree = proto_item_add_subtree (en, ett_range_entry);
              
              for (sno = seq_no; sno <= end_seq_no; sno++) {
                en = proto_tree_add_uint_format (missing_tree, hf_miss_seq_no,
                                                 tvb, offset, 6, sno,
                                                 "Missing Data PDU Seq Number: %d", sno);
                PROTO_ITEM_SET_GENERATED (en);
              }
              tot_no_missing += (end_seq_no - seq_no + 1);
            }

            offset += 6;
            no_missing += 2; /* Skip the next two */
          } else {
            /* No range, handle one seq no */
            en = proto_tree_add_item (field_tree, hf_miss_seq_no, tvb,offset, 
                                      2, FALSE);
            offset += 2;
            
            if (seq_no == 0) {
              proto_item_append_text (en, "    (invalid)");
              expert_add_info_format (pinfo, en, PI_UNDECODED, PI_WARN,
                                      "Invalid missing seq number");
            }
            tot_no_missing++;
          }
        }
      }
    }

    if (tvb_length_remaining (tvb, offset) >= 8) {
      /* Timestamp Option */
      proto_tree_add_item (p_mul_tree, hf_timestamp_option, tvb, offset, 8, FALSE);
      offset += 8;
    }
    
    if (tot_no_missing) {
      proto_item_append_text (ti, ", Missing seq numbers: %u", tot_no_missing);
      en = proto_tree_add_uint (p_mul_tree, hf_tot_miss_seq_no, tvb, 0, 0,
                                tot_no_missing);
      PROTO_ITEM_SET_GENERATED (en);
      expert_add_info_format (pinfo, en, PI_RESPONSE_CODE, PI_NOTE,
                              "Missing seq numbers: %d", tot_no_missing);
    }
    break;

  case Discard_Message_PDU:
    seq_no = G_MAXUINT16;       /* To make the seq_no uniq */
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

  /* Add SEQ/ACK analysis entry */
  if (use_seq_ack_analysis && (pdu_type <= Discard_Message_PDU) &&
      (pdu_type != Address_PDU || no_dest != 0)) 
  {
    pkg_data = p_mul_add_seq_ack (tvb, pinfo, p_mul_tree, offset, pdu_type, 
                                  message_id, seq_no, tot_no_missing);
  }
  
  if (check_col (pinfo->cinfo, COL_INFO)) {
    if (pkg_data) {
      if (pdu_type != Ack_PDU && pkg_data->msg_resend_count) {
        col_append_fstr (pinfo->cinfo, COL_INFO, "[Retrans %d#%d] ",
                         pkg_data->pdu_id, pkg_data->msg_resend_count);
      } else if (pdu_type == Ack_PDU && pkg_data->ack_resend_count) {
        col_append_fstr (pinfo->cinfo, COL_INFO, "[Dup ACK %d#%d] ",
                         pkg_data->ack_id, pkg_data->ack_resend_count);
      }
    }
    col_append_str (pinfo->cinfo, COL_INFO, get_type (pdu_type));
    if (pdu_type == Address_PDU || pdu_type == Extra_Address_PDU ||
        pdu_type == FEC_Address_PDU || pdu_type == Extra_FEC_Address_PDU) {
      col_append_fstr (pinfo->cinfo, COL_INFO, ", No PDUs: %u", no_pdus);
    } else if (pdu_type == Data_PDU) {
      col_append_fstr (pinfo->cinfo, COL_INFO, ", Seq no: %u", seq_no);
    }
    if (pdu_type == Address_PDU || pdu_type == Extra_Address_PDU ||
        pdu_type == FEC_Address_PDU || pdu_type == Extra_FEC_Address_PDU) {
      col_append_fstr (pinfo->cinfo, COL_INFO, ", Count of Dest: %u", no_dest);
    } else if (pdu_type == Ack_PDU) {
      if (tot_no_missing) {
        col_append_fstr (pinfo->cinfo, COL_INFO, ", Missing seq numbers: %u",
                         tot_no_missing);
      }
      col_append_fstr (pinfo->cinfo, COL_INFO, ", Count of Ack: %u", count);
    }
    if (pdu_type != Ack_PDU) {
      col_append_fstr (pinfo->cinfo, COL_INFO, ", MSID: %d", message_id);
    } else {
      if (count > 0) {
        col_append_fstr (pinfo->cinfo, COL_INFO, ", MSID: %s", message_id_list->str);
      }
      g_string_free (message_id_list, TRUE);
    }
  }

  if (p_mul_reassemble) {
    save_fragmented = pinfo->fragmented;

    if (pdu_type == Address_PDU && no_pdus > 0) {
      /* Start fragment table */
      fragment_start_seq_check (pinfo, message_id, p_mul_fragment_table, 
                                no_pdus - 1);
    } else if (pdu_type == Data_PDU) {
      tvbuff_t *new_tvb = NULL;
      
      pinfo->fragmented = TRUE;
      
      /* Add fragment to fragment table */
      frag_msg = fragment_add_seq_check (tvb, offset, pinfo, message_id,
                                         p_mul_fragment_table,
                                         p_mul_reassembled_table, seq_no - 1,
                                         data_len, TRUE);
      new_tvb = process_reassembled_data (tvb, offset, pinfo,
                                          "Reassembled Data", frag_msg,
                                          &p_mul_frag_items, NULL, tree);
      
      if (check_col (pinfo->cinfo, COL_INFO) && frag_msg)
        col_append_str (pinfo->cinfo, COL_INFO, " (Message Reassembled)");
 
      if (new_tvb) {
        dissect_reassembled_data (new_tvb, pinfo, tree);
      }
    }

    pinfo->fragmented = save_fragmented;
  }
  
  /* Update length of P_Mul packet and check length values */
  proto_item_set_len (ti, offset);
  if (pdu_length != (offset + data_len)) {
    proto_item_append_text (len_en, " (incorrect, should be: %d)",
                            offset + data_len);
    expert_add_info_format (pinfo, len_en, PI_MALFORMED, PI_WARN, 
                            "Incorrect length field");
  } else if ((len = tvb_length_remaining (tvb, pdu_length)) > 0) {
    proto_item_append_text (len_en, " (more data in packet: %d)", len);
    expert_add_info_format (pinfo, len_en, PI_MALFORMED, PI_WARN, 
                            "More data in packet");
  }
}

static void p_mul_init_routine (void)
{
  fragment_table_init (&p_mul_fragment_table);
  reassembled_table_init (&p_mul_reassembled_table);
  message_id_offset = 0;
  
  if (p_mul_id_hash_table) {
    g_hash_table_destroy (p_mul_id_hash_table);
  }

  p_mul_id_hash_table = g_hash_table_new (p_mul_id_hash, p_mul_id_hash_equal);
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
    { &hf_checksum_good,
      { "Good", "p_mul.checksum_good", FT_BOOLEAN, BASE_NONE,
        NULL, 0x0, "True: checksum matches packet content; "
        "False: doesn't match content or not checked", HFILL } },
    { &hf_checksum_bad,
      { "Bad", "p_mul.checksum_bad", FT_BOOLEAN, BASE_NONE,
        NULL, 0x0, "True: checksum doesn't match packet content; "
        "False: matches content or not checked", HFILL } },
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
    { &hf_fec_len,
      { "FEC Parameter Length", "p_mul.fec.length", FT_UINT8, BASE_DEC,
        NULL, 0x0, "Forward Error Correction Parameter Length", HFILL } },
    { &hf_fec_id,
      { "FEC ID", "p_mul.fec.id", FT_UINT8, BASE_HEX,
        NULL, 0x0, "Forward Error Correction ID", HFILL } },
    { &hf_fec_parameters,
      { "FEC Parameters", "p_mul.fec.parameters", FT_NONE, BASE_NONE,
        NULL, 0x0, "Forward Error Correction Parameters", HFILL } },
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
    { &hf_miss_seq_range,
      { "Missing Data PDU Seq Range", "p_mul.missing_seq_range", FT_BYTES,
        BASE_DEC, NULL, 0x0, "Missing Data PDU Seq Range", HFILL } },
    { &hf_tot_miss_seq_no,
      { "Total Number of Missing Data PDU Sequence Numbers", 
        "p_mul.no_missing_seq_no", FT_UINT16, BASE_DEC, NULL, 0x0, 
        "Total Number of Missing Data PDU Sequence Numbers", HFILL } },
    { &hf_timestamp_option,
      { "Timestamp Option", "p_mul.timestamp", FT_UINT64, BASE_DEC,
        NULL, 0x0, "Timestamp Option (in units of 100ms)", HFILL } },
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

    /*
    ** Ack matching / Resend
    */
    { &hf_analysis_ack_time,
      { "Ack Time", "p_mul.analysis.ack_time", FT_RELATIVE_TIME, BASE_NONE,
        NULL, 0x0, "The time between the Last PDU and the Ack", HFILL } },
    { &hf_analysis_total_time,
      { "Total Time", "p_mul.analysis.total_time", FT_RELATIVE_TIME, BASE_NONE,
        NULL, 0x0, "The time between the first Address PDU and the Ack", HFILL } },
    { &hf_analysis_retrans_time,
      { "Retransmission Time", "p_mul.analysis.retrans_time", FT_RELATIVE_TIME, BASE_NONE,
        NULL, 0x0, "The time between the last PDU and this PDU", HFILL } },
    { &hf_analysis_total_retrans_time,
      { "Total Retransmission Time", "p_mul.analysis.total_retrans_time", FT_RELATIVE_TIME, BASE_NONE,
        NULL, 0x0, "The time between the first PDU and this PDU", HFILL } },
    { &hf_analysis_addr_pdu_time,
      { "Time since Address PDU", "p_mul.analysis.elapsed_time", FT_RELATIVE_TIME, BASE_NONE,
        NULL, 0x0, "The time between the Address PDU and this PDU", HFILL } },
    { &hf_analysis_prev_pdu_time,
      { "PDU Delay", "p_mul.analysis.pdu_delay", FT_RELATIVE_TIME, BASE_NONE,
        NULL, 0x0, "The time between the last PDU and this PDU", HFILL } },
    { &hf_analysis_last_pdu_num,
      { "Last Data PDU in", "p_mul.analysis.last_pdu_in", FT_FRAMENUM, BASE_NONE,
        NULL, 0x0, "The last Data PDU found in this frame", HFILL } },
    { &hf_analysis_addr_pdu_num,
      { "Address PDU in", "p_mul.analysis.addr_pdu_in", FT_FRAMENUM, BASE_NONE,
        NULL, 0x0, "The Address PDU is found in this frame", HFILL } },
    { &hf_analysis_prev_pdu_num,
      { "Previous PDU in", "p_mul.analysis.prev_pdu_in", FT_FRAMENUM, BASE_NONE,
        NULL, 0x0, "The previous PDU is found in this frame", HFILL } },
    { &hf_analysis_ack_num,
      { "Ack PDU in", "p_mul.analysis.ack_in", FT_FRAMENUM, BASE_NONE,
        NULL, 0x0, "This packet has an Ack in this frame", HFILL } },
    { &hf_analysis_addr_pdu_missing,
      { "Address PDU missing", "p_mul.analysis.addr_pdu_missing", FT_NONE, BASE_NONE,
        NULL, 0x0, "The Address PDU for this packet is missing", HFILL } },
    { &hf_analysis_prev_pdu_missing,
      { "Previous PDU missing", "p_mul.analysis.prev_pdu_missing", FT_NONE, BASE_NONE,
        NULL, 0x0, "The previous PDU for this packet is missing", HFILL } },
    { &hf_analysis_ack_missing,
      { "Ack PDU missing", "p_mul.analysis.ack_missing", FT_NONE, BASE_NONE,
        NULL, 0x0, "The acknowledgement for this packet is missing", HFILL } },
    { &hf_analysis_retrans_no,
      { "Retransmission #", "p_mul.analysis.retrans_no", FT_UINT32, BASE_DEC,
        NULL, 0x0, "Retransmission count", HFILL } },
    { &hf_analysis_ack_dup_no,
      { "Duplicate ACK #", "p_mul.analysis.dup_ack_no", FT_UINT32, BASE_DEC,
        NULL, 0x0, "Duplicate Ack count", HFILL } },
    { &hf_analysis_msg_resend_from,
      { "Retransmission of Message in", "p_mul.analysis.msg_first_in", 
        FT_FRAMENUM, BASE_NONE,
        NULL, 0x0, "This Message was first sent in this frame", HFILL } },
    { &hf_analysis_ack_resend_from,
      { "Retransmission of Ack in", "p_mul.analysis.ack_first_in", 
        FT_FRAMENUM, BASE_NONE,
        NULL, 0x0, "This Ack was first sent in this frame", HFILL } },

  };

  static gint *ett[] = {
    &ett_p_mul,
    &ett_pdu_type,
    &ett_dest_entry,
    &ett_ack_entry,
    &ett_range_entry,
    &ett_checksum,
    &ett_analysis,
    &ett_msg_fragment,
    &ett_msg_fragments
  };

  module_t *p_mul_module;

  proto_p_mul = proto_register_protocol (PNAME, PSNAME, PFNAME);
  register_dissector(PFNAME, dissect_p_mul, proto_p_mul);
  
  proto_register_field_array (proto_p_mul, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
  register_init_routine (&p_mul_init_routine);

  /* Set default UDP ports */
  range_convert_str (&global_p_mul_port_range, DEFAULT_P_MUL_PORT_RANGE, 
                     MAX_UDP_PORT);

  /* Register our configuration options */
  p_mul_module = prefs_register_protocol (proto_p_mul,
                                          proto_reg_handoff_p_mul);

  prefs_register_obsolete_preference (p_mul_module, "tport");
  prefs_register_obsolete_preference (p_mul_module, "rport");
  prefs_register_obsolete_preference (p_mul_module, "dport");
  prefs_register_obsolete_preference (p_mul_module, "aport");

  prefs_register_range_preference (p_mul_module, "udp_ports", 
                                   "P_Mul port numbers",
                                   "Port numbers used for P_Mul traffic",
                                   &global_p_mul_port_range, MAX_UDP_PORT);
  prefs_register_bool_preference (p_mul_module, "reassemble",
                                  "Reassemble fragmented P_Mul packets",
                                  "Reassemble fragmented P_Mul packets",
                                  &p_mul_reassemble);
  prefs_register_bool_preference (p_mul_module, "relative_msgid",
                                  "Use relative Message ID",
                                  "Make the P_Mul dissector use relative"
                                  " message id number instead of absolute"
                                  " ones", &use_relative_msgid);
  prefs_register_bool_preference (p_mul_module, "seq_ack_analysis",
                                  "SEQ/ACK Analysis",
                                  "Calculate sequence/acknowledgement analysis",
                                  &use_seq_ack_analysis);
  prefs_register_enum_preference (p_mul_module, "decode",
                                  "Decode Data PDU as",
                                  "Type of content in Data_PDU",
                                  &decode_option, decode_options, FALSE);
}

static void range_delete_callback (guint32 port)
{
    dissector_delete ("udp.port", port, p_mul_handle);
}

static void range_add_callback (guint32 port)
{
    dissector_add ("udp.port", port, p_mul_handle);
}

void proto_reg_handoff_p_mul (void)
{
  static gboolean p_mul_prefs_initialized = FALSE;
  static range_t *p_mul_port_range;

  if (!p_mul_prefs_initialized) {
    p_mul_handle = find_dissector(PFNAME);
    p_mul_prefs_initialized = TRUE;
  } else {
    range_foreach (p_mul_port_range, range_delete_callback);
    g_free (p_mul_port_range);
  }

  /* Save port number for later deletion */
  p_mul_port_range = range_copy (global_p_mul_port_range);
    
  range_foreach (p_mul_port_range, range_add_callback);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 noexpandtab
 * :indentSize=2:tabSize=8:noTabs=false:
 */
