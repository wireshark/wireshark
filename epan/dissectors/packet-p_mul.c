/* packet-p_mul.c
 *
 * Routines for P_Mul (ACP142) packet disassembly.
 * A protocol for reliable multicast messaging in bandwidth constrained
 * and delayed acknowledgement (EMCON) environments.
 *
 * Copyright 2005, Stig Bjorlykke <stig@bjorlykke.org>, Thales Norway AS
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Ref:  http://jcs.dtic.mil/j6/cceb/acps/acp142/
 */

/*
 * TODO:
 * - Obtain dedicated UDP port numbers
 * - SEQ/ACK analysis for Announce/Request/Reject/Release PDU
 */

#include "config.h"


#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/expert.h>
#include <epan/asn1.h>
#include <epan/in_cksum.h>
#include <epan/proto_data.h>

#include <wsutil/str_util.h>

#include "packet-cdt.h"
#include "packet-ber.h"
#include "packet-s5066sis.h"

void proto_register_p_mul(void);
void proto_reg_handoff_p_mul(void);

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
#define Ack_Ack_PDU            0xFF    /* Fake type to indicate Ack-Ack */

/* Type of content to decode from Data_PDU */
#define DECODE_NONE      0
#define DECODE_BER       1
#define DECODE_CDT       2

static int proto_p_mul = -1;

static int hf_length = -1;
static int hf_priority = -1;
static int hf_map_first = -1;
static int hf_map_last = -1;
static int hf_map_unused = -1;
static int hf_pdu_type = -1;
static int hf_pdu_type_value = -1;
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
static int hf_msg_fragment_count = -1;
static int hf_msg_reassembled_in = -1;
static int hf_msg_reassembled_length = -1;

static int hf_analysis_ack_time = -1;
static int hf_analysis_trans_time = -1;
static int hf_analysis_retrans_time = -1;
static int hf_analysis_total_retrans_time = -1;
static int hf_analysis_last_pdu_num = -1;
static int hf_analysis_addr_pdu_num = -1;
static int hf_analysis_acks_addr_pdu_num = -1;
static int hf_analysis_acks_acked_addr_pdu_num = -1;
static int hf_analysis_addr_pdu_time = -1;
static int hf_analysis_prev_pdu_num = -1;
static int hf_analysis_prev_pdu_time = -1;
static int hf_analysis_retrans_no = -1;
static int hf_analysis_ack_num = -1;
static int hf_analysis_ack_missing = -1;
static int hf_analysis_ack_dup_no = -1;
static int hf_analysis_msg_resend_from = -1;
static int hf_analysis_ack_resend_from = -1;
static int hf_analysis_total_time = -1;

static gint ett_p_mul = -1;
static gint ett_pdu_type = -1;
static gint ett_dest_entry = -1;
static gint ett_ack_entry = -1;
static gint ett_range_entry = -1;
static gint ett_checksum = -1;
static gint ett_seq_analysis = -1;
static gint ett_ack_analysis = -1;
static gint ett_seq_ack_analysis = -1;
static gint ett_msg_fragment = -1;
static gint ett_msg_fragments = -1;

static expert_field ei_more_data = EI_INIT;
static expert_field ei_checksum_bad = EI_INIT;
static expert_field ei_tot_miss_seq_no = EI_INIT;
static expert_field ei_miss_seq_no = EI_INIT;
static expert_field ei_analysis_ack_missing = EI_INIT;
static expert_field ei_miss_seq_range = EI_INIT;
static expert_field ei_address_pdu_missing = EI_INIT;
static expert_field ei_analysis_ack_dup_no = EI_INIT;
static expert_field ei_length = EI_INIT;
static expert_field ei_analysis_prev_pdu_missing = EI_INIT;
static expert_field ei_message_discarded = EI_INIT;
static expert_field ei_ack_length = EI_INIT;
static expert_field ei_analysis_retrans_no = EI_INIT;

static dissector_handle_t p_mul_handle = NULL;

typedef struct _p_mul_id_key {
  guint32 id;
  guint16 seq;
  address addr;
} p_mul_id_key;

typedef struct _p_mul_seq_val {
  gint        msg_type;         /* Message type                      */
  guint32     prev_msg_id;      /* Previous message package num      */
  nstime_t    prev_msg_time;    /* Previous message receive time     */
  guint32     addr_id;          /* PDU package num for Address_PDU   */
  nstime_t    addr_time;        /* PDU received time for Address_PDU */
  guint32     pdu_id;           /* PDU package num                   */
  nstime_t    pdu_time;         /* PDU receive time                  */
  guint32     prev_pdu_id;      /* Previous PDU package num          */
  nstime_t    prev_pdu_time;    /* Previous PDU receive time         */
  guint16     last_found_pdu;   /* Last PDU num                      */
  nstime_t    first_msg_time;   /* First message receive time        */
  guint32     msg_resend_count; /* Message resend counter            */
  GHashTable *ack_data;
} p_mul_seq_val;

typedef struct _p_mul_ack_data {
  guint32  ack_id;                     /* Ack PDU package num               */
  guint32  ack_resend_count;           /* Ack resend counter                */
} p_mul_ack_data;

/* Hash table with current data for seq/ack analysis */
static GHashTable *p_mul_id_hash_table = NULL;

/* List of hash tables stored in each frame */
static GList *p_mul_package_data_list = NULL;

/* User definable values to use for dissection */
static range_t *global_p_mul_port_range;
static gboolean p_mul_reassemble = TRUE;
static gint decode_option = DECODE_NONE;
static gboolean use_relative_msgid = TRUE;
static gboolean use_seq_ack_analysis = TRUE;

static reassembly_table p_mul_reassembly_table;

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
  &hf_msg_fragment_count,
  /* Reassembled in field */
  &hf_msg_reassembled_in,
  /* Reassembled length field */
  &hf_msg_reassembled_length,
  /* Reassembled data field */
  NULL,
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
  { Ack_Ack_PDU,           "Ack-Ack PDU"           },
  { 0,                     NULL                    }
};

static const enum_val_t decode_options[] = {
  { "none", "No decoding",          DECODE_NONE },
  { "ber",  "BER encoded ASN.1",    DECODE_BER  },
  { "cdt",  "Compressed Data Type", DECODE_CDT  },
  { NULL,   NULL,                   0           }
};

static const true_false_string no_yes = {
  "No", "Yes"
};

static const gchar *get_type (guint8 value)
{
  return val_to_str_const (value, pdu_vals, "Unknown");
}


/* Function checksum, found in ACP 142 annex B04 (Fletcher algorithm) */
static guint16 checksum_acp142 (guint8 *buffer, gint len, gint offset)
{
  guint16  c0 = 0, c1 = 0, ret, ctmp;
  gint16   cs;
  guint8  *hpp, *pls;

  if (len < offset+2) {
    /* Buffer too small */
    return 0;
  }

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
  const p_mul_id_key *p_mul = (const p_mul_id_key *)k;
  return p_mul->id;
}

static gint p_mul_id_hash_equal (gconstpointer k1, gconstpointer k2)
{
  const p_mul_id_key *p_mul1 = (const p_mul_id_key *)k1;
  const p_mul_id_key *p_mul2 = (const p_mul_id_key *)k2;

  if (p_mul1->id != p_mul2->id)
    return 0;

  if (p_mul1->seq != p_mul2->seq)
    return 0;

  return (addresses_equal (&p_mul1->addr, &p_mul2->addr));
}

static p_mul_seq_val *lookup_seq_val (guint32 message_id, guint16 seq_no,
                                      address *addr)
{
  p_mul_seq_val *pkg_data;
  p_mul_id_key  *p_mul_key = wmem_new(wmem_file_scope(), p_mul_id_key);

  p_mul_key->id = message_id;
  p_mul_key->seq = seq_no;
  copy_address_wmem(wmem_file_scope(), &p_mul_key->addr, addr);

  pkg_data = (p_mul_seq_val *) g_hash_table_lookup (p_mul_id_hash_table, p_mul_key);

  return pkg_data;
}

static void p_mul_id_value_destroy (p_mul_seq_val *pkg_data)
{
  if (pkg_data->ack_data) {
    g_hash_table_destroy (pkg_data->ack_data);
  }
  g_free (pkg_data);
}

static void p_mul_package_data_destroy (GHashTable *pkg_list, gpointer user_data _U_)
{
  g_hash_table_destroy (pkg_list);
}

static void copy_hashtable_data (gpointer key, p_mul_ack_data *ack_data1, GHashTable *table)
{
  p_mul_ack_data *ack_data2;

  ack_data2 = wmem_new(wmem_file_scope(), p_mul_ack_data);
  ack_data2->ack_id = ack_data1->ack_id;
  ack_data2->ack_resend_count = ack_data1->ack_resend_count;

  g_hash_table_insert (table, key, ack_data2);
}

static p_mul_seq_val *register_p_mul_id (packet_info *pinfo, address *addr, guint32 dstIP,
                                         guint8 pdu_type, guint32 message_id,
                                         guint16 seq_no, gint no_missing)
{
  p_mul_seq_val  *p_mul_data = NULL, *pkg_data = NULL;
  p_mul_id_key   *p_mul_key;
  p_mul_ack_data *ack_data = NULL;
  nstime_t        addr_time, prev_time;
  guint           addr_id = 0, prev_id = 0;
  guint16         last_found_pdu = 0;
  gboolean        missing_pdu = FALSE, need_set_address = FALSE;
  GHashTable     *pkg_list;

  if (pinfo->flags.in_error_pkt) {
    /* No analysis of error packets */
    return NULL;
  }

  nstime_set_zero(&addr_time);
  nstime_set_zero(&prev_time);

  p_mul_key = wmem_new(wmem_file_scope(), p_mul_id_key);

  if (!pinfo->fd->flags.visited &&
      (pdu_type == Address_PDU || pdu_type == Data_PDU || pdu_type == Discard_Message_PDU))
  {
    /* Try to match corresponding address PDU */
    p_mul_key->id = message_id;
    p_mul_key->seq = 0;
    copy_address_wmem(wmem_file_scope(), &p_mul_key->addr, addr);
    need_set_address = TRUE;

    p_mul_data = (p_mul_seq_val *) g_hash_table_lookup (p_mul_id_hash_table, p_mul_key);

    if (p_mul_data) {
      /* Found address PDU */
      last_found_pdu = p_mul_data->last_found_pdu;
      p_mul_data->last_found_pdu = seq_no;
      addr_id = p_mul_data->pdu_id;
      addr_time = p_mul_data->pdu_time;

      /* Save data for last found PDU */
      p_mul_data->prev_pdu_id = pinfo->num;
      p_mul_data->prev_pdu_time = pinfo->abs_ts;

      if (pdu_type == Data_PDU && p_mul_data->msg_resend_count == 0 && last_found_pdu != seq_no - 1) {
        /* Data_PDU and missing previous PDU */
        missing_pdu = TRUE;
      }

      if (last_found_pdu) {
        /* Try to match previous data PDU */
        p_mul_key->seq = last_found_pdu;
        p_mul_data = (p_mul_seq_val *) g_hash_table_lookup (p_mul_id_hash_table, p_mul_key);
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
    } else if (pdu_type == Address_PDU) {
      addr_id = pinfo->num;
      addr_time = pinfo->abs_ts;
    }
  }

  pkg_list = (GHashTable *)p_get_proto_data(wmem_file_scope(), pinfo, proto_p_mul, 0);
  if (!pkg_list) {
    /* Never saved list for this packet, create a new */
    pkg_list = g_hash_table_new (NULL, NULL);
    p_mul_package_data_list = g_list_append (p_mul_package_data_list, pkg_list);
    p_add_proto_data(wmem_file_scope(), pinfo, proto_p_mul, 0, pkg_list);
  }

  if (!pinfo->fd->flags.visited) {
    p_mul_key->id = message_id;
    p_mul_key->seq = seq_no;
    if (!need_set_address) {
      copy_address_wmem(wmem_file_scope(), &p_mul_key->addr, addr);
    }
    p_mul_data = (p_mul_seq_val *) g_hash_table_lookup (p_mul_id_hash_table, p_mul_key);

    if (p_mul_data) {
      if (pdu_type == Ack_PDU) {
        /* Only save this data if positive ack */
        if (no_missing == 0) {
          ack_data = (p_mul_ack_data *)g_hash_table_lookup (p_mul_data->ack_data, GUINT_TO_POINTER(dstIP));
          if (!ack_data) {
            /* Only save reference to first ACK */
            ack_data = wmem_new0(wmem_file_scope(), p_mul_ack_data);
            ack_data->ack_id = pinfo->num;
            g_hash_table_insert (p_mul_data->ack_data, GUINT_TO_POINTER(dstIP), ack_data);
          } else {
            /* Only count when resending */
            ack_data->ack_resend_count++;
          }
        }
      } else {
        /* Message resent */
        p_mul_data->msg_resend_count++;
        p_mul_data->prev_msg_id = pinfo->num;
        p_mul_data->prev_msg_time = p_mul_data->pdu_time;
        p_mul_data->pdu_time = pinfo->abs_ts;

        if (pdu_type == Data_PDU) {
          p_mul_data->prev_pdu_id = prev_id;
          p_mul_data->prev_pdu_time = prev_time;
        }
      }
    } else {
      /* New message */
      if (pdu_type == Ack_PDU) {
        p_mul_data = wmem_new0(wmem_file_scope(), p_mul_seq_val);
      } else {
        p_mul_data = (p_mul_seq_val *)g_malloc0(sizeof (p_mul_seq_val));
      }
      p_mul_data->msg_type = pdu_type;
      if (pdu_type == Address_PDU || pdu_type == Ack_PDU) {
        p_mul_data->ack_data = g_hash_table_new (NULL, NULL);
      }

      if (pdu_type == Ack_PDU) {
        /* No matching message for this ack */
        ack_data = wmem_new0(wmem_file_scope(), p_mul_ack_data);
        ack_data->ack_id = pinfo->num;
        g_hash_table_insert (p_mul_data->ack_data, GUINT_TO_POINTER(dstIP), ack_data);
      } else {
        p_mul_data->pdu_id = pinfo->num;
        p_mul_data->pdu_time = pinfo->abs_ts;
        p_mul_data->addr_id = addr_id;
        p_mul_data->addr_time = addr_time;
        p_mul_data->first_msg_time = pinfo->abs_ts;

        if (pdu_type == Data_PDU && !missing_pdu) {
          p_mul_data->prev_pdu_id = prev_id;
          p_mul_data->prev_pdu_time = prev_time;
        }

        g_hash_table_insert (p_mul_id_hash_table, p_mul_key, p_mul_data);
      }
    }

    /* Copy the current package data to the frame */
    pkg_data = wmem_new(wmem_file_scope(), p_mul_seq_val);
    *pkg_data = *p_mul_data;
    if (p_mul_data->ack_data) {
      /* Copy the hash table for ack data */
      pkg_data->ack_data = g_hash_table_new (NULL, NULL);
      g_hash_table_foreach (p_mul_data->ack_data, (GHFunc) copy_hashtable_data, pkg_data->ack_data);
    }
    g_hash_table_insert (pkg_list, GUINT_TO_POINTER(message_id), pkg_data);
  } else {
    /* Fetch last values from data saved in packet */
    pkg_data = (p_mul_seq_val *)g_hash_table_lookup (pkg_list, GUINT_TO_POINTER(message_id));
  }

  DISSECTOR_ASSERT (pkg_data);
  return pkg_data;
}

static void add_ack_analysis (tvbuff_t *tvb, packet_info *pinfo, proto_tree *p_mul_tree,
                              gint offset, guint8 pdu_type, address *src, address *dst,
                              guint32 message_id, gint no_missing)
{
  proto_tree     *analysis_tree = NULL;
  proto_item     *sa            = NULL;
  proto_item     *en            = NULL;
  p_mul_seq_val  *pkg_data      = NULL;
  p_mul_ack_data *ack_data      = NULL;
  gboolean        item_added    = FALSE;
  guint32         dstIp;
  nstime_t        ns;

  if (pinfo->flags.in_error_pkt) {
    /* No analysis of error packets */
    return;
  }

  if (pdu_type == Address_PDU) {
    analysis_tree = proto_tree_add_subtree(p_mul_tree, tvb, 0, 0, ett_ack_analysis, &sa, "ACK analysis");
    PROTO_ITEM_SET_GENERATED (sa);

    /* Fetch package data */
    if ((pkg_data = lookup_seq_val (message_id, 0, src)) == NULL) {
      /* No need for seq/ack analysis yet */
      return;
    }

    if (dst == NULL) {
      /* Ack-Ack */
      if (pkg_data->addr_id) {
        en = proto_tree_add_uint (analysis_tree, hf_analysis_acks_acked_addr_pdu_num, tvb,
                                  0, 0, pkg_data->addr_id);
        PROTO_ITEM_SET_GENERATED (en);

        nstime_delta (&ns, &pinfo->abs_ts, &pkg_data->addr_time);
        en = proto_tree_add_time (analysis_tree, hf_analysis_total_time,
                                  tvb, 0, 0, &ns);
        PROTO_ITEM_SET_GENERATED (en);
      } else {
        proto_tree_add_expert(analysis_tree, pinfo, &ei_address_pdu_missing, tvb, offset, 0);
      }
      item_added = TRUE;
    } else {
      memcpy((guint8 *)&dstIp, dst->data, 4);
      if (pkg_data->ack_data) {
        ack_data = (p_mul_ack_data *)g_hash_table_lookup (pkg_data->ack_data, GUINT_TO_POINTER(dstIp));
      }

      /* Add reference to Ack_PDU */
      if (ack_data && ack_data->ack_id) {
        en = proto_tree_add_uint (analysis_tree, hf_analysis_ack_num, tvb,
                                  0, 0, ack_data->ack_id);
        PROTO_ITEM_SET_GENERATED (en);
        item_added = TRUE;
      } else if (!pkg_data->msg_resend_count) {
        en = proto_tree_add_item (analysis_tree,
                                  hf_analysis_ack_missing,
                                  tvb, offset, 0, ENC_NA);
        if (pinfo->fd->flags.visited) {
          /* We do not know this on first visit and we do not want to
             add a entry in the "Expert Severity Info" for this note */
          expert_add_info(pinfo, en, &ei_analysis_ack_missing);
          PROTO_ITEM_SET_GENERATED (en);
        }
        item_added = TRUE;
      }
    }

    if (!item_added) {
      PROTO_ITEM_SET_HIDDEN (sa);
    }
  } else if (pdu_type == Ack_PDU) {
    analysis_tree = proto_tree_add_subtree(p_mul_tree, tvb, 0, 0, ett_seq_ack_analysis, &sa, "SEQ/ACK analysis");
    PROTO_ITEM_SET_GENERATED (sa);

    /* Fetch package data */
    memcpy((guint8 *)&dstIp, dst->data, 4);
    if ((pkg_data = register_p_mul_id (pinfo, src, dstIp, pdu_type, message_id, 0, no_missing)) == NULL) {
      /* No need for seq/ack analysis yet */
      return;
    }
    if (pkg_data->ack_data) {
      ack_data = (p_mul_ack_data *)g_hash_table_lookup (pkg_data->ack_data, GUINT_TO_POINTER(dstIp));
    }

    /* Add reference to Address_PDU */
    if (pkg_data->msg_type != Ack_PDU) {
      en = proto_tree_add_uint (analysis_tree, hf_analysis_acks_addr_pdu_num, tvb,
                                0, 0, pkg_data->pdu_id);
      PROTO_ITEM_SET_GENERATED (en);

      if (no_missing == 0) {
        nstime_delta (&ns, &pinfo->abs_ts, &pkg_data->first_msg_time);
        en = proto_tree_add_time (analysis_tree, hf_analysis_trans_time,
                                  tvb, 0, 0, &ns);
        PROTO_ITEM_SET_GENERATED (en);
      }
    } else {
      proto_tree_add_expert(analysis_tree, pinfo, &ei_address_pdu_missing, tvb, offset, 0);
    }

    if (pkg_data->msg_type != Ack_PDU && pkg_data->prev_pdu_id) {
      /* Add reference to previous PDU */
      en = proto_tree_add_uint (analysis_tree, hf_analysis_last_pdu_num,
                                tvb, 0, 0, pkg_data->prev_pdu_id);
      PROTO_ITEM_SET_GENERATED (en);

      nstime_delta (&ns, &pinfo->abs_ts, &pkg_data->prev_pdu_time);
      en = proto_tree_add_time (analysis_tree, hf_analysis_ack_time,
                                tvb, 0, 0, &ns);
      PROTO_ITEM_SET_GENERATED (en);
    }

    if (ack_data && ack_data->ack_resend_count) {
      /* Add resend statistics */
      en = proto_tree_add_uint (analysis_tree, hf_analysis_ack_dup_no,
                                tvb, 0, 0, ack_data->ack_resend_count);
      PROTO_ITEM_SET_GENERATED (en);

      expert_add_info_format(pinfo, en, &ei_analysis_ack_dup_no, "Dup ACK #%d", ack_data->ack_resend_count);

      en = proto_tree_add_uint (analysis_tree, hf_analysis_ack_resend_from,
                                tvb, 0, 0, ack_data->ack_id);
      PROTO_ITEM_SET_GENERATED (en);

      col_append_fstr (pinfo->cinfo, COL_INFO, "[Dup ACK %d#%d] ",
                       ack_data->ack_id, ack_data->ack_resend_count);
    }
  }
}

static p_mul_seq_val *add_seq_analysis (tvbuff_t *tvb, packet_info *pinfo,
                                        proto_tree *p_mul_tree, address *src,
                                        gint offset,
                                        guint8 pdu_type, guint32 message_id,
                                        guint16 seq_no, gint no_missing)
{
  p_mul_seq_val *pkg_data;
  proto_tree    *analysis_tree;
  proto_item    *sa, *en = NULL, *eh = NULL;
  gboolean       item_added = FALSE;
  nstime_t       ns;

  pkg_data = register_p_mul_id (pinfo, src, 0, pdu_type, message_id, seq_no,
                                no_missing);

  if (!pkg_data) {
    /* No need for seq/ack analysis */
    return NULL;
  }

  analysis_tree = proto_tree_add_subtree(p_mul_tree, tvb, 0, 0, ett_seq_analysis, &sa, "SEQ analysis");
  PROTO_ITEM_SET_GENERATED (sa);

  if (pdu_type == Data_PDU || pdu_type == Discard_Message_PDU) {
    /* Add reference to Address_PDU */
    if (pkg_data->addr_id) {
      en = proto_tree_add_uint (analysis_tree, hf_analysis_addr_pdu_num, tvb,
                                0, 0, pkg_data->addr_id);
      PROTO_ITEM_SET_GENERATED (en);

      nstime_delta (&ns, &pinfo->abs_ts, &pkg_data->addr_time);
      en = proto_tree_add_time (analysis_tree, hf_analysis_addr_pdu_time,
                                tvb, 0, 0, &ns);
      PROTO_ITEM_SET_GENERATED (en);

      if (pkg_data->prev_pdu_id == pkg_data->addr_id) {
        /* Previous pdu time is the same as time since address pdu */
        en = proto_tree_add_time (analysis_tree, hf_analysis_prev_pdu_time,
                                  tvb, 0, 0, &ns);
        PROTO_ITEM_SET_GENERATED (en);
      }
      item_added = TRUE;
    } else if (!pkg_data->msg_resend_count) {
      proto_tree_add_expert(analysis_tree, pinfo, &ei_address_pdu_missing, tvb, offset, 0);
      item_added = TRUE;
    }
  }

  if ((pdu_type == Data_PDU) && (pkg_data->prev_pdu_id != pkg_data->addr_id)) {
    /* Add reference to previous Data_PDU */
    if (pkg_data->prev_pdu_id) {
      en = proto_tree_add_uint (analysis_tree, hf_analysis_prev_pdu_num, tvb,
                                0, 0, pkg_data->prev_pdu_id);
      PROTO_ITEM_SET_GENERATED (en);

      nstime_delta (&ns, &pinfo->abs_ts, &pkg_data->prev_pdu_time);
      en = proto_tree_add_time (analysis_tree, hf_analysis_prev_pdu_time,
                                tvb, 0, 0, &ns);
      PROTO_ITEM_SET_GENERATED (en);
      item_added = TRUE;
    } else if (!pkg_data->msg_resend_count) {
      proto_tree_add_expert(analysis_tree, pinfo, &ei_analysis_prev_pdu_missing, tvb, offset, 0);
      item_added = TRUE;
    }
  }

  if ((pdu_type == Address_PDU) || (pdu_type == Data_PDU) ||
      (pdu_type == Discard_Message_PDU)) {
    /* Add resend statistics */
    if (pkg_data->msg_resend_count) {
      en = proto_tree_add_uint (analysis_tree, hf_analysis_retrans_no,
                                tvb, 0, 0, pkg_data->msg_resend_count);
      PROTO_ITEM_SET_GENERATED (en);

      en = proto_tree_add_uint (analysis_tree, hf_analysis_msg_resend_from,
                                tvb, 0, 0, pkg_data->pdu_id);
      PROTO_ITEM_SET_GENERATED (en);

      expert_add_info_format(pinfo, en, &ei_analysis_retrans_no, "Retransmission #%d", pkg_data->msg_resend_count);

      nstime_delta (&ns, &pinfo->abs_ts, &pkg_data->prev_msg_time);
      en = proto_tree_add_time (analysis_tree, hf_analysis_retrans_time,
                                tvb, 0, 0, &ns);
      PROTO_ITEM_SET_GENERATED (en);

      nstime_delta (&ns, &pinfo->abs_ts, &pkg_data->first_msg_time);
      eh = proto_tree_add_time (analysis_tree, hf_analysis_total_retrans_time,
                                tvb, 0, 0, &ns);
      PROTO_ITEM_SET_GENERATED (eh);

      if (pkg_data->first_msg_time.secs == pkg_data->prev_msg_time.secs &&
          pkg_data->first_msg_time.nsecs == pkg_data->prev_msg_time.nsecs) {
        /* Time values does not differ, hide the total time */
        PROTO_ITEM_SET_HIDDEN (eh);
      }
      item_added = TRUE;

      col_append_fstr (pinfo->cinfo, COL_INFO, "[Retrans %d#%d] ",
                       pkg_data->pdu_id, pkg_data->msg_resend_count);
    }
  }

  if (!item_added) {
    PROTO_ITEM_SET_HIDDEN (sa);
  }

  return pkg_data;
}


static void dissect_reassembled_data (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  DISSECTOR_ASSERT(tvb != NULL);

  switch (decode_option) {
  case DECODE_BER:
    dissect_unknown_ber (pinfo, tvb, 0, tree);
    break;
  case DECODE_CDT:
    dissect_cdt (tvb, pinfo, tree);
    break;
  default:
    call_data_dissector(tvb, pinfo, tree);
    break;
  }
}

static int dissect_p_mul (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_tree    *p_mul_tree, *field_tree, *checksum_tree;
  proto_item    *ti, *en, *len_en;
  gboolean       save_fragmented;
  guint32        message_id = 0;
  guint16        no_dest = 0, count = 0, len, data_len = 0;
  guint16        checksum_calc, checksum_found;
  guint16        pdu_length, no_pdus = 0, seq_no = 0;
  guint8         pdu_type, *value, map = 0, fec_len;
  gint           i, tot_no_missing = 0, no_missing = 0, offset = 0;
  address        src, dst;
  wmem_strbuf_t *message_id_list = NULL;
  nstime_t       ts;
  gboolean       fletcher = FALSE;

  col_set_str (pinfo->cinfo, COL_PROTOCOL, "P_MUL");
  col_clear (pinfo->cinfo, COL_INFO);

  /* First fetch PDU Type */
  pdu_type = tvb_get_guint8 (tvb, offset + 3) & 0x3F;

  ti = proto_tree_add_item (tree, proto_p_mul, tvb, offset, -1, ENC_NA);
  proto_item_append_text (ti, ", %s", get_type (pdu_type));
  p_mul_tree = proto_item_add_subtree (ti, ett_p_mul);

  /* Length of PDU */
  pdu_length = tvb_get_ntohs (tvb, offset);
  len_en = proto_tree_add_item (p_mul_tree, hf_length, tvb, offset, 2, ENC_BIG_ENDIAN);
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
    proto_tree_add_item (p_mul_tree, hf_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
    break;

  default:
    /* Unused */
    proto_tree_add_item (p_mul_tree, hf_unused8, tvb, offset, 1, ENC_BIG_ENDIAN);
  }
  offset += 1;

  /* MAP / PDU_Type */
  en = proto_tree_add_uint_format (p_mul_tree, hf_pdu_type, tvb, offset, 1,
                                   pdu_type, "PDU Type: %s (0x%02x)",
                                   get_type (pdu_type), pdu_type);
  field_tree = proto_item_add_subtree (en, ett_pdu_type);

  if (pdu_type == Discard_Message_PDU) {
    expert_add_info(pinfo, en, &ei_message_discarded);
  }

  switch (pdu_type) {

  case Address_PDU:
  case Announce_PDU:
  case Extra_Address_PDU:
  case FEC_Address_PDU:
  case Extra_FEC_Address_PDU:
    map = tvb_get_guint8 (tvb, offset);
    proto_tree_add_item (field_tree, hf_map_first, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item (field_tree, hf_map_last, tvb, offset, 1, ENC_BIG_ENDIAN);
    if ((map & 0x80) || (map & 0x40)) {
      proto_item_append_text (en, ", %s / %s",
                              (map & 0x80) ? "Not first" : "First",
                              (map & 0x40) ? "Not last" : "Last");
    } else {
      proto_item_append_text (en, ", Only one PDU");
    }
    break;

  default:
    proto_tree_add_item (field_tree, hf_map_unused, tvb, offset, 1, ENC_BIG_ENDIAN);
    break;
  }
  proto_tree_add_item (field_tree, hf_pdu_type_value, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  switch (pdu_type) {

  case Address_PDU:
  case Extra_Address_PDU:
  case FEC_Address_PDU:
  case Extra_FEC_Address_PDU:
    /* Total Number of PDUs */
    no_pdus = tvb_get_ntohs (tvb, offset);
    seq_no = 0;
    proto_tree_add_item (p_mul_tree, hf_no_pdus, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_item_append_text (ti, ", No PDUs: %u", no_pdus);
    break;

  case Data_PDU:
    /* Sequence Number of PDUs */
    seq_no = tvb_get_ntohs (tvb, offset);
    proto_tree_add_item (p_mul_tree, hf_seq_no, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_item_append_text (ti, ", Seq no: %u", seq_no);
    break;

  case Announce_PDU:
    /* Count of Destination Entries */
    count = tvb_get_ntohs (tvb, offset);
    proto_tree_add_item (p_mul_tree, hf_count_of_dest, tvb, offset, 2, ENC_BIG_ENDIAN);
    break;

  default:
    /* Unused */
    proto_tree_add_item (p_mul_tree, hf_unused16, tvb, offset, 2, ENC_BIG_ENDIAN);
    break;
  }
  offset += 2;

  /* Checksum */
  en = proto_tree_add_item (p_mul_tree, hf_checksum, tvb, offset, 2, ENC_BIG_ENDIAN);
  checksum_tree = proto_item_add_subtree (en, ett_checksum);
  len = tvb_captured_length (tvb);
  value = (guint8 *)tvb_memdup (wmem_packet_scope(), tvb, 0, len);
  if (len >= offset+2) {
    value[offset] = 0;
    value[offset+1] = 0;
  }
  checksum_found = tvb_get_ntohs (tvb, offset);
  /* This computed IP checksum is network-byte-order, so convert to host-byte-order */
  checksum_calc = g_ntohs (ip_checksum (value, len));
  if (checksum_calc != checksum_found) {
    guint16 checksum1 = checksum_acp142 (value, len, offset);
    if (checksum1 == checksum_found) {
      checksum_calc = checksum1;
      fletcher = TRUE;
    }
  }
  if (checksum_calc == checksum_found) {
    if (fletcher) {
      proto_item_append_text (en, " [Fletcher algorithm]");
    }
    proto_item_append_text (en, " (correct)");
    en = proto_tree_add_boolean (checksum_tree, hf_checksum_good, tvb,
                                 offset, 2, TRUE);
    PROTO_ITEM_SET_GENERATED (en);
    en = proto_tree_add_boolean (checksum_tree, hf_checksum_bad, tvb,
                                 offset, 2, FALSE);
    PROTO_ITEM_SET_GENERATED (en);
  } else {
    proto_item_append_text (en, " (incorrect, should be 0x%04x)", checksum_calc);
    expert_add_info(pinfo, en, &ei_checksum_bad);
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
    set_address_tvb (&dst, AT_IPv4, 4, tvb, offset);
    proto_tree_add_item (p_mul_tree, hf_source_id_ack, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* Count of Ack Info Entries */
    count = tvb_get_ntohs (tvb, offset);
    proto_tree_add_item (p_mul_tree, hf_ack_count, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
  } else {
    /* Source Id */
    set_address_tvb (&src, AT_IPv4, 4, tvb, offset);
    proto_tree_add_item (p_mul_tree, hf_source_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* Message Id */
    message_id = tvb_get_ntohl (tvb, offset);
    if (use_relative_msgid) {
      if (message_id_offset == 0) {
        /* First P_Mul package - initialize message_id_offset */
        message_id_offset = message_id;
      }
      message_id -= message_id_offset;
      proto_tree_add_uint_format_value(p_mul_tree, hf_message_id, tvb, offset, 4,
                                  message_id, "%u    (relative message id)", message_id);
    } else {
      proto_tree_add_item (p_mul_tree, hf_message_id, tvb, offset, 4, ENC_BIG_ENDIAN);
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
    proto_tree_add_item (p_mul_tree, hf_fec_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* FEC ID */
    proto_tree_add_item (p_mul_tree, hf_fec_id, tvb, offset, 1, ENC_BIG_ENDIAN);
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
    proto_tree_add_item (p_mul_tree, hf_count_of_dest, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Length of Reserved Field */
    len = tvb_get_ntohs (tvb, offset);
    proto_tree_add_item (p_mul_tree, hf_length_of_res, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    for (i = 0; i < no_dest; i++) {
      /* Destination Entry */
      en = proto_tree_add_none_format (p_mul_tree, hf_dest_entry, tvb,
                                       offset, 8 + len,
                                       "Destination Entry #%d", i + 1);
      field_tree = proto_item_add_subtree (en, ett_dest_entry);

      /* Destination Id */
      set_address_tvb (&dst, AT_IPv4, 4, tvb, offset);
      proto_tree_add_item (field_tree, hf_dest_id, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;

      /* Message Sequence Number */
      proto_tree_add_item (field_tree, hf_msg_seq_no, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;

      if (len > 0) {
        /* Reserved Field (variable length) */
        proto_tree_add_none_format (field_tree, hf_sym_key, tvb, offset,
                                    len, "Symmetric Key (%d byte%s)",
                                    len, plurality (len, "", "s"));
        offset += len;
      }

      if (use_seq_ack_analysis) {
        add_ack_analysis (tvb, pinfo, field_tree, offset, pdu_type, &src, &dst,
                          message_id, 0);
      }
    }
    if (no_dest == 0 && use_seq_ack_analysis) {
      /* Add Ack-Ack analysis */
      add_ack_analysis (tvb, pinfo, p_mul_tree, offset, pdu_type, &src, NULL,
                        message_id, 0);
    }

    proto_item_append_text (ti, ", Count of Dest: %u", no_dest);
    break;

  case Data_PDU:
    /* Fragment of Data (variable length) */
    data_len = tvb_captured_length_remaining (tvb, offset);
    proto_tree_add_none_format (p_mul_tree, hf_data_fragment, tvb, offset,
                                data_len, "Fragment %d of Data (%d byte%s)",
                                seq_no, data_len,
                                plurality (data_len, "", "s"));
    break;

  case Ack_PDU:
    message_id_list = wmem_strbuf_new_label(wmem_packet_scope());

    for (i = 0; i < count; i++) {
      /* Ack Info Entry */
      len = tvb_get_ntohs (tvb, offset);

      en = proto_tree_add_none_format (p_mul_tree, hf_ack_entry, tvb,
                                       offset, len,
                                       "Ack Info Entry #%d", i + 1);
      field_tree = proto_item_add_subtree (en, ett_ack_entry);

      /* Length of Ack Info Entry */
      en = proto_tree_add_item (field_tree, hf_ack_length, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;

      if (len < 10) {
        proto_item_append_text (en, "    (invalid length)");
        expert_add_info(pinfo, en, &ei_ack_length);
      }

      /* Source Id */
      set_address_tvb (&src, AT_IPv4, 4, tvb, offset);
      proto_tree_add_item (field_tree, hf_source_id, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;

      /* Message Id */
      message_id = tvb_get_ntohl (tvb, offset);
      if (use_relative_msgid) {
        if (message_id_offset == 0) {
          /* First P_Mul package - initialize message_id_offset */
          message_id_offset = message_id;
        }
        message_id -= message_id_offset;
        proto_tree_add_uint_format_value(field_tree, hf_message_id, tvb, offset, 4,
                                    message_id, "%u    (relative message id)", message_id);
      } else {
        proto_tree_add_item (field_tree, hf_message_id, tvb, offset, 4, ENC_BIG_ENDIAN);
      }
      offset += 4;

      if (i == 0) {
        wmem_strbuf_append_printf (message_id_list, "%u", message_id);
      } else {
        wmem_strbuf_append_printf (message_id_list, ",%u", message_id);
      }

      if (len > 10) {
        gint num_seq_no = (len - 10) / 2;
        guint16 ack_seq_no, prev_ack_seq_no = 0;
        for (no_missing = 0; no_missing < num_seq_no; no_missing++) {
          /* Missing Data PDU Seq Number */
          ack_seq_no = tvb_get_ntohs (tvb, offset);
          if ((ack_seq_no != 0) && (no_missing < num_seq_no - 2) && tvb_get_ntohs (tvb, offset + 2) == 0) {
            /* We are handling a range */
            guint16 end_seq_no = tvb_get_ntohs (tvb, offset + 4);

            en = proto_tree_add_bytes_format_value(field_tree, hf_miss_seq_range,
                                              tvb, offset, 6, NULL,
                                             "%d - %d",
                                             ack_seq_no, end_seq_no);
            if (ack_seq_no >= end_seq_no) {
              proto_item_append_text (en, "    (invalid)");
              expert_add_info(pinfo, en, &ei_miss_seq_range);
            } else {
              proto_tree *missing_tree;
              guint16 sno;

              missing_tree = proto_item_add_subtree (en, ett_range_entry);

              for (sno = ack_seq_no; sno <= end_seq_no; sno++) {
                en = proto_tree_add_uint_format_value(missing_tree, hf_miss_seq_no,
                                                 tvb, offset, 6, sno,
                                                 "%d", sno);
                PROTO_ITEM_SET_GENERATED (en);
              }
              tot_no_missing += (end_seq_no - ack_seq_no + 1);
            }

            offset += 6;
            no_missing += 2; /* Skip the next two */
            prev_ack_seq_no = end_seq_no;
          } else {
            /* No range, handle one seq no */
            en = proto_tree_add_item (field_tree, hf_miss_seq_no, tvb,offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            if (ack_seq_no == 0) {
              proto_item_append_text (en, "    (invalid)");
              expert_add_info(pinfo, en, &ei_miss_seq_no);
            } else if (ack_seq_no <= prev_ack_seq_no) {
              proto_item_append_text (en, "    (end of list indicator)");
            } else {
              tot_no_missing++;
            }
            prev_ack_seq_no = ack_seq_no;
          }
        }
      }

      if (use_seq_ack_analysis) {
        add_ack_analysis (tvb, pinfo, field_tree, offset, pdu_type, &src, &dst,
                          message_id, no_missing);
      }
    }
    proto_item_append_text (ti, ", Count of Ack: %u", count);

    if (tvb_reported_length_remaining (tvb, offset) >= 8) {
      /* Timestamp Option (in units of 100ms) */
      guint64 timestamp;

      timestamp = tvb_get_ntoh64 (tvb, offset);
      proto_tree_add_uint64_format_value(p_mul_tree, hf_timestamp_option, tvb,
                                    offset, 8, timestamp,
                                    "%" G_GINT64_MODIFIER "d.%d second%s (%" G_GINT64_MODIFIER "u)",
                                    timestamp / 10, (int) timestamp % 10,
                                    (timestamp == 10) ? "" : "s", timestamp);
      offset += 8;
    }

    if (tot_no_missing) {
      proto_item_append_text (ti, ", Missing seq numbers: %u", tot_no_missing);
      en = proto_tree_add_uint (p_mul_tree, hf_tot_miss_seq_no, tvb, 0, 0,
                                tot_no_missing);
      PROTO_ITEM_SET_GENERATED (en);
      expert_add_info_format(pinfo, en, &ei_tot_miss_seq_no, "Missing seq numbers: %d", tot_no_missing);
    }
    break;

  case Discard_Message_PDU:
    seq_no = G_MAXUINT16;       /* To make the seq_no uniq */
    break;

  case Announce_PDU:
    /* Announced Multicast Group */
    proto_tree_add_item (p_mul_tree, hf_ann_mc_group, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    for (i = 0; i < count; i++) {
      /* Destination Id */
      proto_tree_add_item (p_mul_tree, hf_dest_id, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
    }
    break;

  case Request_PDU:
  case Reject_PDU:
  case Release_PDU:
    /* Multicast Group */
    proto_tree_add_item (p_mul_tree, hf_mc_group, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;

  default:
    /* Nothing */
    break;
  }

  /* Add SEQ/ACK analysis entry */
  if (use_seq_ack_analysis && (pdu_type <= Discard_Message_PDU) &&
      (pdu_type != Ack_PDU) && (pdu_type != Address_PDU || no_dest != 0))
  {
    add_seq_analysis (tvb, pinfo, p_mul_tree, &src, offset, pdu_type,
                                 message_id, seq_no, tot_no_missing);
  }

  /* Check if printing Ack-Ack */
  if (pdu_type == Address_PDU && no_dest == 0) {
    col_append_str (pinfo->cinfo, COL_INFO, get_type (Ack_Ack_PDU));
  } else {
    col_append_str (pinfo->cinfo, COL_INFO, get_type (pdu_type));
  }
  if (pdu_type == Address_PDU || pdu_type == Extra_Address_PDU ||
      pdu_type == FEC_Address_PDU || pdu_type == Extra_FEC_Address_PDU) {
    col_append_fstr (pinfo->cinfo, COL_INFO, ", No PDUs: %u", no_pdus);
  } else if (pdu_type == Data_PDU) {
    col_append_fstr (pinfo->cinfo, COL_INFO, ", Seq no: %u", seq_no);
  }
  if (pdu_type == Address_PDU || pdu_type == Extra_Address_PDU ||
      pdu_type == FEC_Address_PDU || pdu_type == Extra_FEC_Address_PDU) {
    if (no_dest > 0) {
      col_append_fstr (pinfo->cinfo, COL_INFO, ", Count of Dest: %u", no_dest);
    }
  } else if (pdu_type == Ack_PDU) {
    if (tot_no_missing) {
      col_append_fstr (pinfo->cinfo, COL_INFO, ", Missing seq numbers: %u",
                       tot_no_missing);
    }
    col_append_fstr (pinfo->cinfo, COL_INFO, ", Count of Ack: %u", count);
  }
  if (pdu_type != Ack_PDU) {
    col_append_fstr (pinfo->cinfo, COL_INFO, ", MSID: %u", message_id);
  } else {
    if (message_id_list && wmem_strbuf_get_len(message_id_list) > 0) {
      col_append_fstr (pinfo->cinfo, COL_INFO, ", MSID: %s", wmem_strbuf_get_str(message_id_list));
    }
  }

  if (p_mul_reassemble) {
    save_fragmented = pinfo->fragmented;

    if (pdu_type == Address_PDU && no_pdus > 0) {
      /* Start fragment table */
      fragment_start_seq_check (&p_mul_reassembly_table,
                                pinfo, message_id, NULL, no_pdus - 1);
    } else if (pdu_type == Data_PDU) {
      fragment_head *frag_msg;
      tvbuff_t      *new_tvb;

      pinfo->fragmented = TRUE;

      /* Add fragment to fragment table */
      frag_msg = fragment_add_seq_check (&p_mul_reassembly_table,
                                         tvb, offset, pinfo, message_id, NULL,
                                         seq_no - 1, data_len, TRUE);
      new_tvb = process_reassembled_data (tvb, offset, pinfo,
                                          "Reassembled P_MUL", frag_msg,
                                          &p_mul_frag_items, NULL, tree);

      if (frag_msg)
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
    expert_add_info(pinfo, len_en, &ei_length);
  } else if ((len = tvb_reported_length_remaining (tvb, pdu_length)) > 0) {
    proto_item_append_text (len_en, " (more data in packet: %d)", len);
    expert_add_info(pinfo, len_en, &ei_more_data);
  }

  return offset;
}

static void p_mul_init_routine (void)
{
  reassembly_table_init (&p_mul_reassembly_table,
                         &addresses_reassembly_table_functions);
  message_id_offset = 0;
  p_mul_id_hash_table = g_hash_table_new_full (p_mul_id_hash, p_mul_id_hash_equal, NULL, (GDestroyNotify)p_mul_id_value_destroy);
  p_mul_package_data_list = NULL;
}

static void p_mul_cleanup_routine (void)
{
  reassembly_table_destroy(&p_mul_reassembly_table);
  g_hash_table_destroy(p_mul_id_hash_table);
  g_list_foreach(p_mul_package_data_list, (GFunc)p_mul_package_data_destroy, NULL);
  g_list_free(p_mul_package_data_list);
}

void proto_register_p_mul (void)
{
  static hf_register_info hf[] = {
    { &hf_length,
      { "Length of PDU", "p_mul.length", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_priority,
      { "Priority", "p_mul.priority", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_map_first,
      { "First", "p_mul.first", FT_BOOLEAN, 8,
        TFS (&no_yes), 0x80, NULL, HFILL } },
    { &hf_map_last,
      { "Last", "p_mul.last", FT_BOOLEAN, 8,
        TFS (&no_yes), 0x40, NULL, HFILL } },
    { &hf_map_unused,
      { "MAP unused", "p_mul.unused", FT_UINT8, BASE_DEC,
        NULL, 0xC0, NULL, HFILL } },
    { &hf_pdu_type,
      { "PDU Type", "p_mul.pdu_type", FT_UINT8, BASE_DEC,
        VALS (pdu_vals), 0x3F, NULL, HFILL } },
    { &hf_pdu_type_value,
      { "PDU Type", "p_mul.pdu_type_value", FT_UINT8, BASE_DEC,
        VALS (pdu_vals), 0x3F, NULL, HFILL } },
    { &hf_no_pdus,
      { "Total Number of PDUs", "p_mul.no_pdus", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_seq_no,
      { "Sequence Number of PDUs", "p_mul.seq_no", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_unused8,
      { "Unused", "p_mul.unused", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_unused16,
      { "Unused", "p_mul.unused", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_checksum,
      { "Checksum", "p_mul.checksum", FT_UINT16, BASE_HEX,
        NULL, 0x0, NULL, HFILL } },
    { &hf_checksum_good,
      { "Good", "p_mul.checksum_good", FT_BOOLEAN, BASE_NONE,
        NULL, 0x0, "True: checksum matches packet content; False: doesn't match content or not checked", HFILL } },
    { &hf_checksum_bad,
      { "Bad", "p_mul.checksum_bad", FT_BOOLEAN, BASE_NONE,
        NULL, 0x0, "True: checksum doesn't match packet content; False: matches content or not checked", HFILL } },
    { &hf_source_id_ack,
      { "Source ID of Ack Sender", "p_mul.source_id_ack", FT_IPv4, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_source_id,
      { "Source ID", "p_mul.source_id", FT_IPv4, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_message_id,
      { "Message ID (MSID)", "p_mul.message_id", FT_UINT32, BASE_DEC,
        NULL, 0x0, "Message ID", HFILL } },
    { &hf_expiry_time,
      { "Expiry Time", "p_mul.expiry_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
        NULL, 0x0, NULL, HFILL } },
    { &hf_mc_group,
      { "Multicast Group", "p_mul.mc_group", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_ann_mc_group,
      { "Announced Multicast Group", "p_mul.ann_mc_group", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
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
        NULL, 0x0, NULL, HFILL } },
    { &hf_length_of_res,
      { "Length of Reserved Field", "p_mul.reserved_length",FT_UINT16,BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_ack_count,
      { "Count of Ack Info Entries", "p_mul.ack_count", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_ack_entry,
      { "Ack Info Entry", "p_mul.ack_info_entry", FT_NONE, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_ack_length,
      { "Length of Ack Info Entry", "p_mul.ack_length", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_miss_seq_no,
      { "Missing Data PDU Seq Number", "p_mul.missing_seq_no", FT_UINT16,
        BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_miss_seq_range,
      { "Missing Data PDU Seq Range", "p_mul.missing_seq_range", FT_BYTES,
        BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_tot_miss_seq_no,
      { "Total Number of Missing Data PDU Sequence Numbers",
        "p_mul.no_missing_seq_no", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },
    { &hf_timestamp_option,
      { "Timestamp", "p_mul.timestamp", FT_UINT64, BASE_DEC,
        NULL, 0x0, "Timestamp Option (in units of 100ms)", HFILL } },
    { &hf_dest_entry,
      { "Destination Entry", "p_mul.dest_entry", FT_NONE, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_dest_id,
      { "Destination ID", "p_mul.dest_id", FT_IPv4, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_msg_seq_no,
      { "Message Sequence Number", "p_mul.msg_seq_no", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_sym_key,
      { "Symmetric Key", "p_mul.sym_key", FT_NONE, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_data_fragment,
      { "Fragment of Data", "p_mul.data_fragment", FT_NONE, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },

    /* Fragment entries */
    { &hf_msg_fragments,
      { "Message fragments", "p_mul.fragments", FT_NONE, BASE_NONE,
        NULL, 0x00, NULL, HFILL } },
    { &hf_msg_fragment,
      { "Message fragment", "p_mul.fragment", FT_FRAMENUM, BASE_NONE,
        NULL, 0x00, NULL, HFILL } },
    { &hf_msg_fragment_overlap,
      { "Message fragment overlap", "p_mul.fragment.overlap", FT_BOOLEAN,
        BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_msg_fragment_overlap_conflicts,
      { "Message fragment overlapping with conflicting data",
        "p_mul.fragment.overlap.conflicts", FT_BOOLEAN, BASE_NONE, NULL,
        0x0, NULL, HFILL } },
    { &hf_msg_fragment_multiple_tails,
      { "Message has multiple tail fragments",
        "p_mul.fragment.multiple_tails", FT_BOOLEAN, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_msg_fragment_too_long_fragment,
      { "Message fragment too long", "p_mul.fragment.too_long_fragment",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL,
        HFILL } },
    { &hf_msg_fragment_error,
      { "Message defragmentation error", "p_mul.fragment.error", FT_FRAMENUM,
        BASE_NONE, NULL, 0x00, NULL, HFILL } },
    { &hf_msg_fragment_count,
      { "Message fragment count", "p_mul.fragment.count", FT_UINT32, BASE_DEC,
        NULL, 0x00, NULL, HFILL } },
    { &hf_msg_reassembled_in,
      { "Reassembled in", "p_mul.reassembled.in", FT_FRAMENUM, BASE_NONE,
        NULL, 0x00, NULL, HFILL } },
    { &hf_msg_reassembled_length,
      { "Reassembled P_MUL length", "p_mul.reassembled.length", FT_UINT32, BASE_DEC,
        NULL, 0x00, NULL, HFILL } },

    /*
    ** Ack matching / Resend
    */
    { &hf_analysis_ack_time,
      { "Ack Time", "p_mul.analysis.ack_time", FT_RELATIVE_TIME, BASE_NONE,
        NULL, 0x0, "The time between the Last PDU and the Ack", HFILL } },
    { &hf_analysis_trans_time,
      { "Transfer Time", "p_mul.analysis.trans_time", FT_RELATIVE_TIME, BASE_NONE,
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
    { &hf_analysis_acks_addr_pdu_num,
      { "This is an Ack to the Address PDU in", "p_mul.analysis.acks_addr_pdu_in", FT_FRAMENUM, BASE_NONE,
        FRAMENUM_TYPE(FT_FRAMENUM_ACK), 0x0, "The Address PDU is found in this frame", HFILL } },
    { &hf_analysis_acks_acked_addr_pdu_num,
      { "This is an Ack-Ack to the Address PDU in", "p_mul.analysis.acks_acked_addr_pdu_in", FT_FRAMENUM, BASE_NONE,
        FRAMENUM_TYPE(FT_FRAMENUM_DUP_ACK), 0x0, "The Address PDU is found in this frame", HFILL } },
    { &hf_analysis_prev_pdu_num,
      { "Previous PDU in", "p_mul.analysis.prev_pdu_in", FT_FRAMENUM, BASE_NONE,
        NULL, 0x0, "The previous PDU is found in this frame", HFILL } },
    { &hf_analysis_ack_num,
      { "Ack PDU in", "p_mul.analysis.ack_in", FT_FRAMENUM, BASE_NONE,
        NULL, 0x0, "This packet has an Ack in this frame", HFILL } },
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
    { &hf_analysis_total_time,
      { "Total Time", "p_mul.analysis.total_time", FT_RELATIVE_TIME, BASE_NONE,
        NULL, 0x0, "The time between the first and the last Address PDU", HFILL } },
  };

  static gint *ett[] = {
    &ett_p_mul,
    &ett_pdu_type,
    &ett_dest_entry,
    &ett_ack_entry,
    &ett_range_entry,
    &ett_checksum,
    &ett_seq_analysis,
    &ett_ack_analysis,
    &ett_seq_ack_analysis,
    &ett_msg_fragment,
    &ett_msg_fragments
  };
  static ei_register_info ei[] = {
      { &ei_address_pdu_missing, { "p_mul.analysis.addr_pdu_missing", PI_SEQUENCE, PI_NOTE, "Address PDU missing", EXPFILL }},
      { &ei_analysis_ack_missing, { "p_mul.analysis.ack_missing.expert", PI_SEQUENCE, PI_NOTE, "Ack PDU missing", EXPFILL }},
      { &ei_analysis_ack_dup_no, { "p_mul.analysis.dup_ack_no.expert", PI_SEQUENCE, PI_NOTE, "Dup ACK #", EXPFILL }},
      { &ei_analysis_prev_pdu_missing, { "p_mul.analysis.prev_pdu_missing", PI_SEQUENCE, PI_NOTE, "Previous PDU missing", EXPFILL }},
      { &ei_analysis_retrans_no, { "p_mul.analysis.retrans_no.expert", PI_SEQUENCE, PI_NOTE, "Retransmission #", EXPFILL }},
      { &ei_message_discarded, { "p_mul.message_discarded", PI_RESPONSE_CODE, PI_NOTE, "Message discarded", EXPFILL }},
      { &ei_checksum_bad, { "p_mul.checksum_bad.expert", PI_CHECKSUM, PI_WARN, "Bad checksum", EXPFILL }},
      { &ei_ack_length, { "p_mul.ack_length.invalid", PI_MALFORMED, PI_WARN, "Invalid ack info length", EXPFILL }},
      { &ei_miss_seq_range, { "p_mul.missing_seq_range.invalid", PI_UNDECODED, PI_WARN, "Invalid missing sequence range", EXPFILL }},
      { &ei_miss_seq_no, { "p_mul.missing_seq_no.invalid", PI_UNDECODED, PI_WARN, "Invalid missing seq number", EXPFILL }},
      { &ei_tot_miss_seq_no, { "p_mul.no_missing_seq_no.expert", PI_RESPONSE_CODE, PI_NOTE, "Missing seq numbers", EXPFILL }},
      { &ei_length, { "p_mul.length.invalid", PI_MALFORMED, PI_WARN, "Incorrect length field", EXPFILL }},
      { &ei_more_data, { "p_mul.more_data", PI_MALFORMED, PI_WARN, "More data in packet", EXPFILL }},
  };

  module_t *p_mul_module;
  expert_module_t* expert_p_mul;

  proto_p_mul = proto_register_protocol (PNAME, PSNAME, PFNAME);

  p_mul_handle = register_dissector(PFNAME, dissect_p_mul, proto_p_mul);

  proto_register_field_array (proto_p_mul, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
  expert_p_mul = expert_register_protocol(proto_p_mul);
  expert_register_field_array(expert_p_mul, ei, array_length(ei));
  register_init_routine (&p_mul_init_routine);
  register_cleanup_routine (&p_mul_cleanup_routine);

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

void proto_reg_handoff_p_mul (void)
{
  static gboolean  p_mul_prefs_initialized = FALSE;
  static range_t  *p_mul_port_range;

  if (!p_mul_prefs_initialized) {
    p_mul_prefs_initialized = TRUE;
    dissector_add_uint ("s5066sis.ctl.appid", S5066_CLIENT_S4406_ANNEX_E_TMI_1_P_MUL, p_mul_handle);
  } else {
    dissector_delete_uint_range ("udp.port", p_mul_port_range, p_mul_handle);
    g_free (p_mul_port_range);
  }

  /* Save port number for later deletion */
  p_mul_port_range = range_copy (global_p_mul_port_range);

  dissector_add_uint_range ("udp.port", p_mul_port_range, p_mul_handle);
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
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
