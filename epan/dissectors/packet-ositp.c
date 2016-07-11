/* packet-ositp.c
 * Routines for ISO/OSI transport protocol (connection-oriented
 * and connectionless) packet disassembly
 *
 * Laurent Deniel <laurent.deniel@free.fr>
 * Ralf Schneider <Ralf.Schneider@t-online.de>
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

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/conversation.h>
#include <epan/ipproto.h>
#include <epan/expert.h>
#include <epan/proto_data.h>

#include <wsutil/str_util.h>
#include "packet-frame.h"
#include "packet-osi.h"

void proto_register_cotp(void);
void proto_register_cltp(void);
void proto_reg_handoff_cotp(void);

/* protocols and fields */

static int  proto_clnp;

static int  proto_cotp         = -1;
static gint ett_cotp           = -1;
static gint ett_cotp_segments  = -1;
static gint ett_cotp_segment   = -1;

static int hf_cotp_li          = -1;
static int hf_cotp_type        = -1;
static int hf_cotp_srcref      = -1;
static int hf_cotp_destref     = -1;
static int hf_cotp_class       = -1;
static int hf_cotp_opts_extended_formats = -1;
static int hf_cotp_opts_no_explicit_flow_control = -1;
static int hf_cotp_tpdu_number = -1;
static int hf_cotp_tpdu_number_extended = -1;
static int hf_cotp_next_tpdu_number = -1;
static int hf_cotp_next_tpdu_number_extended = -1;
static int hf_cotp_eot          = -1;
static int hf_cotp_eot_extended = -1;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_cotp_parameter_code = -1;
static int hf_cotp_parameter_length = -1;
static int hf_cotp_parameter_value = -1;
static int hf_cotp_atn_extended_checksum16 = -1;
static int hf_cotp_atn_extended_checksum32 = -1;
static int hf_cotp_ack_time = -1;
static int hf_cotp_res_error_rate_target_value = -1;
static int hf_cotp_res_error_rate_min_accept = -1;
static int hf_cotp_res_error_rate_tdsu = -1;
static int hf_cotp_vp_priority = -1;
static int hf_cotp_transit_delay_targ_calling_called = -1;
static int hf_cotp_transit_delay_max_accept_calling_called = -1;
static int hf_cotp_transit_delay_targ_called_calling = -1;
static int hf_cotp_transit_delay_max_accept_called_calling = -1;
static int hf_cotp_max_throughput_targ_calling_called = -1;
static int hf_cotp_max_throughput_min_accept_calling_called = -1;
static int hf_cotp_max_throughput_targ_called_calling = -1;
static int hf_cotp_max_throughput_min_accept_called_calling = -1;
static int hf_cotp_avg_throughput_targ_calling_called = -1;
static int hf_cotp_avg_throughput_min_accept_calling_called = -1;
static int hf_cotp_avg_throughput_targ_called_calling = -1;
static int hf_cotp_avg_throughput_min_accept_called_calling = -1;
static int hf_cotp_sequence_number = -1;
static int hf_cotp_reassignment_time = -1;
static int hf_cotp_lower_window_edge = -1;
static int hf_cotp_credit = -1;
static int hf_cotp_tpdu_size = -1;
static int hf_cotp_checksum = -1;
static int hf_cotp_vp_version_nr = -1;
static int hf_cotp_network_expedited_data = -1;
static int hf_cotp_vp_opt_sel_class1_use = -1;
static int hf_cotp_use_16_bit_checksum = -1;
static int hf_cotp_transport_expedited_data_transfer = -1;
static int hf_cotp_preferred_maximum_tpdu_size = -1;
static int hf_cotp_inactivity_timer = -1;
static int hf_cotp_cause = -1;
static int hf_cotp_segment_data = -1;
static int hf_cotp_credit_cdt = -1;
static int hf_cotp_reject_cause = -1;

static int hf_cotp_segments    = -1;
static int hf_cotp_segment     = -1;
static int hf_cotp_segment_overlap = -1;
static int hf_cotp_segment_overlap_conflict = -1;
static int hf_cotp_segment_multiple_tails = -1;
static int hf_cotp_segment_too_long_segment = -1;
static int hf_cotp_segment_error = -1;
static int hf_cotp_segment_count = -1;
static int hf_cotp_reassembled_in = -1;
static int hf_cotp_reassembled_length = -1;

static expert_field ei_cotp_disconnect_confirm = EI_INIT;
static expert_field ei_cotp_multiple_tpdus = EI_INIT;
static expert_field ei_cotp_reject = EI_INIT;
static expert_field ei_cotp_connection = EI_INIT;
static expert_field ei_cotp_disconnect_request = EI_INIT;
static expert_field ei_cotp_preferred_maximum_tpdu_size = EI_INIT;

static int  proto_cltp         = -1;
static gint ett_cltp           = -1;

static int hf_cltp_li = -1;
static int hf_cltp_type = -1;

static const fragment_items cotp_frag_items = {
  &ett_cotp_segment,
  &ett_cotp_segments,
  &hf_cotp_segments,
  &hf_cotp_segment,
  &hf_cotp_segment_overlap,
  &hf_cotp_segment_overlap_conflict,
  &hf_cotp_segment_multiple_tails,
  &hf_cotp_segment_too_long_segment,
  &hf_cotp_segment_error,
  &hf_cotp_segment_count,
  &hf_cotp_reassembled_in,
  &hf_cotp_reassembled_length,
  /* Reassembled data field */
  NULL,
  "segments"
};

static dissector_handle_t rdp_cr_handle;
static dissector_handle_t rdp_cc_handle;

/*
 * ISO8073 OSI COTP definition
 * See http://standards.iso.org/ittf/PubliclyAvailableStandards/index.html
 * (or RFC905 for historic, and now-outdated information)
 */

/* don't use specific TPDU types to avoid alignment problems & copy overhead */

/* TPDU definition */

#define ED_TPDU             0x1 /* COTP */
#define EA_TPDU             0x2 /* COTP */
#define UD_TPDU             0x4 /* CLTP */
#define RJ_TPDU             0x5 /* COTP */
#define AK_TPDU             0x6 /* COTP */
#define ER_TPDU             0x7 /* COTP */
#define DR_TPDU             0x8 /* COTP */
#define DC_TPDU             0xC /* COTP */
#define CC_TPDU             0xD /* COTP */
#define CR_TPDU             0xE /* COTP */
#define DT_TPDU             0xF /* COTP */

static const value_string cotp_tpdu_type_abbrev_vals[] = {
  { ED_TPDU, "ED Expedited Data" },
  { EA_TPDU, "EA Expedited Data Acknowledgement" },
  { RJ_TPDU, "RJ Reject" },
  { AK_TPDU, "AK Data Acknowledgement" },
  { ER_TPDU, "ER TPDU Error" },
  { DR_TPDU, "DR Disconnect Request" },
  { DC_TPDU, "DC Disconnect Confirm" },
  { CC_TPDU, "CC Connect Confirm" },
  { CR_TPDU, "CR Connect Request" },
  { DT_TPDU, "DT Data" },
  { 0,       NULL }
};

static const value_string cltp_tpdu_type_abbrev_vals[] = {
  { UD_TPDU, "UD" },
  { 0,       NULL }
};

#if 0
static const value_string class_option_vals[] = {
  {0, "Class 0"},
  {1, "Class 1"},
  {2, "Class 2"},
  {3, "Class 3"},
  {4, "Class 4"},
  {0, NULL}
};
#endif

/* field position */

#define P_LI                0
#define P_TPDU              1
#define P_CDT               1
#define P_DST_REF           2
#define P_SRC_REF           4
#define P_TPDU_NR_0_1       2
#define P_TPDU_NR_234       4
#define P_VAR_PART_NDT      5
#define P_VAR_PART_EDT      8
#define P_VAR_PART_DC       6
#define P_CDT_IN_AK         8
#define P_CDT_IN_RJ         8
#define P_REJECT_ER         4
#define P_REASON_IN_DR      6
#define P_CLASS_OPTION      6

/*
 * TPDU length indicator values.
 * Checksum parameter is 4 octets - 1 octet of parameter code, 1 octet
 * of parameter length, 2 octets of checksum.
 */

#define LI_NORMAL_DT_CLASS_01           2
#define LI_NORMAL_DT_WITHOUT_CHECKSUM   4
#define LI_NORMAL_DT_WITH_CHECKSUM      (LI_NORMAL_DT_WITHOUT_CHECKSUM+4)
#define LI_EXTENDED_DT_WITHOUT_CHECKSUM 7
#define LI_EXTENDED_DT_WITH_CHECKSUM    (LI_EXTENDED_DT_WITHOUT_CHECKSUM+4)
#define LI_NORMAL_EA_WITHOUT_CHECKSUM   4
#define LI_NORMAL_EA_WITH_CHECKSUM      (LI_NORMAL_EA_WITHOUT_CHECKSUM+4)
#define LI_EXTENDED_EA_WITHOUT_CHECKSUM 7
#define LI_EXTENDED_EA_WITH_CHECKSUM    (LI_EXTENDED_EA_WITHOUT_CHECKSUM+4)
#define LI_NORMAL_RJ                    4
#define LI_EXTENDED_RJ                  9
#define LI_MIN_DR                       6
#define LI_MAX_DC                       9
#define LI_MAX_AK                       27
#define LI_MAX_EA                       11
#define LI_MAX_ER                       8
/* XXX - can we always decide this based on whether the length
   indicator is odd or not?  What if the variable part has an odd
   number of octets? */
#define is_LI_NORMAL_AK(p)               ((p & 0x01) == 0)

/*
 * Modified TPDU length indicator values due to ATN 4-octet extended
 * checksum.
 * Checksum parameter is 6 octets - 1 octet of parameter code, 1 octet
 * of parameter length, 4 octets of checksum.  That adds 2 octets to
 * the lengths with a 2-octet checksum.
 */
#define LI_ATN_NORMAL_DT_WITH_CHECKSUM       (LI_NORMAL_DT_WITH_CHECKSUM+2)
#define LI_ATN_EXTENDED_DT_WITH_CHECKSUM     (LI_EXTENDED_DT_WITH_CHECKSUM+2)
#define LI_ATN_NORMAL_EA_WITH_CHECKSUM       (LI_NORMAL_EA_WITH_CHECKSUM+2)
#define LI_ATN_EXTENDED_EA_WITH_CHECKSUM     (LI_EXTENDED_EA_WITH_CHECKSUM+2)
#define LI_ATN_NORMAL_RJ                     (LI_NORMAL_RJ+2)
#define LI_ATN_EXTENDED_RJ                   (LI_EXTENDED_RJ+2)
#define LI_ATN_MAX_DC                        (LI_MAX_DC+2)
#define LI_ATN_MAX_AK                        (LI_MAX_AK+2+1) /* +1 for padding? */
#define LI_ATN_MAX_EA                        (LI_MAX_EA+2)
#define LI_ATN_MAX_ER                        (LI_MAX_ER+2)

/* variant part */

#define VP_ACK_TIME             0x85
#define VP_RES_ERROR            0x86
#define VP_PRIORITY             0x87
#define VP_TRANSIT_DEL          0x88
#define VP_THROUGHPUT           0x89
#define VP_SEQ_NR               0x8A        /* in AK */
#define VP_REASSIGNMENT         0x8B
#define VP_FLOW_CNTL            0x8C        /* in AK */
#define VP_TPDU_SIZE            0xC0
#define VP_SRC_TSAP             0xC1        /* in CR/CC */
#define VP_DST_TSAP             0xC2
#define VP_CHECKSUM             0xC3
#define VP_VERSION_NR           0xC4
#define VP_PROTECTION           0xC5
#define VP_OPT_SEL              0xC6
#define VP_PROTO_CLASS          0xC7
#define VP_CLEARING_INFO        0xE0        /* in DR */
#define VP_PREF_MAX_TPDU_SIZE   0xF0
#define VP_INACTIVITY_TIMER     0xF2

/* ATN */
/* Parameter codes with bits 7 and 8 are explicitly not */
/* assigned by ISO/IEC 8073, nor is their use precluded. */
/* Parameter codes for ATN defined in ICAO doc 9507 Ed3 SV 5 section 5.5.2.4.3.1 */
#define VP_ATN_EC_32            0x08        /* 4 octet ATN Extended Transport Checksum parameter */
#define VP_ATN_EC_16            0x09        /* 2 octet ATN Extended Transport Checksum parameter */
/* ATN end */

static const value_string tp_vpart_type_vals[] = {
  { VP_ATN_EC_16,           "ATN extended checksum - 16 bit" },
  { VP_ATN_EC_32,           "ATN extended checksum - 32 bit" },
  { VP_ACK_TIME,            "ack time" },
  { VP_RES_ERROR,           "res error" },
  { VP_PRIORITY,            "priority" },
  { VP_TRANSIT_DEL,         "transit delay" },
  { VP_THROUGHPUT,          "throughput" },
  { VP_SEQ_NR,              "seq number" },
  { VP_REASSIGNMENT,        "reassignment" },
  { VP_FLOW_CNTL,           "flow control" },
  { VP_TPDU_SIZE,           "tpdu-size" },
  { VP_SRC_TSAP,            "src-tsap" },
  { VP_DST_TSAP,            "dst-tsap" },
  { VP_CHECKSUM,            "checksum" },
  { VP_VERSION_NR,          "version" },
  { VP_PROTECTION,          "protection" },
  { VP_OPT_SEL,             "options" },
  { VP_PROTO_CLASS,         "proto class" },
  { VP_CLEARING_INFO,       "additional connection clearing info" },
  { VP_PREF_MAX_TPDU_SIZE,  "preferred max TPDU size" },
  { VP_INACTIVITY_TIMER,    "inactivity timer" },
  { 0,                      NULL }
};

static int hf_cotp_vp_src_tsap = -1;
static int hf_cotp_vp_dst_tsap = -1;
static int hf_cotp_vp_src_tsap_bytes = -1;
static int hf_cotp_vp_dst_tsap_bytes = -1;

/* global variables */

/* List of dissectors to call for the variable part of CR PDUs. */
static heur_dissector_list_t cotp_cr_heur_subdissector_list;
/* List of dissectors to call for the variable part of CC PDUs. */
static heur_dissector_list_t cotp_cc_heur_subdissector_list;
/* List of dissectors to call for COTP packets put atop the Inactive
   Subset of CLNP. */
static heur_dissector_list_t cotp_is_heur_subdissector_list;
/* List of dissectors to call for COTP packets put atop CLNP */
static heur_dissector_list_t cotp_heur_subdissector_list;
/* List of dissectors to call for CLTP packets put atop CLNP */
static heur_dissector_list_t cltp_heur_subdissector_list;

/*
 * Reassembly of COTP.
 */
static reassembly_table cotp_reassembly_table;
static guint16    cotp_dst_ref = 0;
static gboolean   cotp_frame_reset = FALSE;
static gboolean   cotp_last_fragment = FALSE;

#define TSAP_DISPLAY_AUTO   0
#define TSAP_DISPLAY_STRING 1
#define TSAP_DISPLAY_BYTES  2

/* options */
static gboolean cotp_reassemble = TRUE;
static gint32   tsap_display = TSAP_DISPLAY_AUTO;
static gboolean cotp_decode_atn = FALSE;

static const enum_val_t tsap_display_options[] = {
  {"auto", "As strings if printable", TSAP_DISPLAY_AUTO},
  {"string", "As strings", TSAP_DISPLAY_STRING},
  {"bytes", "As bytes", TSAP_DISPLAY_BYTES},
  {NULL, NULL, -1}
};

/* function definitions */

#define MAX_TSAP_LEN    32

static void cotp_frame_end(void)
{
  if (!cotp_last_fragment) {
    /* Last COTP in frame is not fragmented.
     * No need for incrementing the dst_ref, so we decrement it here.
     */
    cotp_dst_ref--;
  }
  cotp_frame_reset = TRUE;
}

static gboolean is_all_printable(const guchar *stringtocheck, int length)
{
  gboolean allprintable;
  int      i;

  allprintable=TRUE;
  for (i=0;i<length;i++) {
    if (!g_ascii_isprint(stringtocheck[i])) {
      allprintable=FALSE;
      break;
    }
  }
  return allprintable;
} /* is_all_printable */


static gchar *print_tsap(tvbuff_t *tvb, int offset, int length)
{
  const guchar *tsap = tvb_get_ptr(tvb, offset, length);
  gchar    *cur;
  gboolean  allprintable;
  gint      idx = 0, returned_length;

  cur=(gchar *)wmem_alloc(wmem_packet_scope(), MAX_TSAP_LEN * 2 + 3);
  cur[0] = '\0';
  if (length <= 0 || length > MAX_TSAP_LEN)
    g_snprintf(cur, MAX_TSAP_LEN * 2 + 3, "<unsupported TSAP length>");
  else {
    allprintable = is_all_printable(tsap,length);
    if (!allprintable) {
      returned_length = g_snprintf(cur, MAX_TSAP_LEN * 2 + 3, "0x");
      idx += MIN(returned_length, MAX_TSAP_LEN * 2 + 3 - 1);
    }
    while (length != 0) {
      if (allprintable) {
        returned_length = g_snprintf(&cur[idx], MAX_TSAP_LEN * 2 + 3 - idx,
                                     "%c", *tsap ++);
        idx += MIN(returned_length, MAX_TSAP_LEN * 2 + 3 - idx - 1);
      } else {
        returned_length = g_snprintf(&cur[idx], MAX_TSAP_LEN * 2 + 3 - idx,
                                     "%02x", *tsap ++);
        idx += MIN(returned_length, MAX_TSAP_LEN * 2 + 3 - idx - 1);
      }
      length --;
    }
  }
  return cur;

} /* print_tsap */

static const true_false_string tfs_vp_opt_sel_class1_use = { "Receipt confirmation", "explicit AK variant" };

static gboolean ositp_decode_var_part(tvbuff_t *tvb, int offset, int vp_length,
                                      int class_option, int tpdu_len,
                                      packet_info *pinfo, proto_tree *tree)
{
  guint8          code, length;
  guint8          c1;
  guint16         s;
  guint32         offset_iso8073_checksum = 0;
  gint32          i                       = 0;
  guint8          tmp_code                = 0;
  guint           tmp_len                 = 0;
  guint32         pref_max_tpdu_size;
  proto_item     *hidden_item;

  while (vp_length != 0) {
    code = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_cotp_parameter_code, tvb, offset, 1, ENC_NA);
    offset += 1;
    vp_length -= 1;

    if (vp_length == 0)
      break;
    length = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_cotp_parameter_length, tvb, offset, 1, ENC_NA);
    offset += 1;
    vp_length -= 1;

    switch (code) {

    case VP_ATN_EC_16 : /* ATN */
      if (cotp_decode_atn) {
        guint16 sum;
        /* if an alternate OSI checksum is present in the currently unprocessed
         * VP section to the checksum algorithm has to know.
         * this may be the case for backward compatible CR TPDU */
        if (!offset_iso8073_checksum) {
          /* search following parameters in VP part for ISO checksum */
          for (i = offset + length; i < vp_length;) {
            tmp_code = tvb_get_guint8(tvb, i++);
            tmp_len = tvb_get_guint8(tvb, i++);
            if (tmp_code == VP_CHECKSUM) {
              offset_iso8073_checksum = i; /* save ISO 8073 checksum offset for ATN extended checksum calculation */
              break;
            }
            i += tmp_len;
          }
        }
        sum = check_atn_ec_16(tvb, tpdu_len , offset,
                                      offset_iso8073_checksum,
                                      pinfo->dst.len, (const guint8 *)pinfo->dst.data,
                                      pinfo->src.len, (const guint8 *)pinfo->src.data);
        proto_tree_add_checksum(tree, tvb, offset, hf_cotp_atn_extended_checksum16, -1, NULL, pinfo, sum, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY|PROTO_CHECKSUM_ZERO);
      } else {
        proto_tree_add_bytes_format_value(tree, hf_cotp_parameter_value, tvb, offset, length, NULL, "<not shown>");
      }
      offset += length;
      vp_length -= length;
      break;

    case VP_ATN_EC_32 : /* ATN */
      if (cotp_decode_atn) {
        guint32 sum;
        /* if an alternate OSI checksum is present in the currently unprocessed
         * VP section the checksum algorithm has to know.
         * this may be the case for backward compatible CR TPDU */
        if (!offset_iso8073_checksum) {
          /* search following parameters in VP part for ISO checksum */
          for (i = offset + length; i < vp_length;) {
            tmp_code = tvb_get_guint8(tvb, i++);
            tmp_len = tvb_get_guint8(tvb, i++);
            if (tmp_code == VP_CHECKSUM) {
              offset_iso8073_checksum = i; /* save ISO 8073 checksum offset for ATN extended checksum calculation */
              break;
            }
            i += tmp_len;
          }
        }
        sum = check_atn_ec_32(tvb, tpdu_len , offset,
                                      offset_iso8073_checksum,
                                      pinfo->dst.len, (const guint8 *)pinfo->dst.data,
                                      pinfo->src.len, (const guint8 *)pinfo->src.data);
        proto_tree_add_checksum(tree, tvb, offset, hf_cotp_atn_extended_checksum32, -1, NULL, pinfo, sum, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY|PROTO_CHECKSUM_ZERO);
      } else {
        proto_tree_add_bytes_format_value(tree, hf_cotp_parameter_value, tvb, offset, length, NULL, "<not shown>");
      }
      offset += length;
      vp_length -= length;
      break;

    case VP_ACK_TIME:
      proto_tree_add_item(tree, hf_cotp_ack_time, tvb, offset, length, ENC_BIG_ENDIAN);
      offset += length;
      vp_length -= length;
      break;

    case VP_RES_ERROR:
      s = tvb_get_guint8(tvb, offset);
      proto_tree_add_uint_format(tree, hf_cotp_res_error_rate_target_value, tvb, offset, 1,
                          s, "Residual error rate, target value: 10^%u", s);
      offset += 1;
      vp_length -= 1;

      s = tvb_get_guint8(tvb, offset);
      proto_tree_add_uint_format(tree, hf_cotp_res_error_rate_min_accept, tvb, offset, 1,
                          s, "Residual error rate, minimum acceptable: 10^%u", s);
      offset += 1;
      vp_length -= 1;

      s = tvb_get_guint8(tvb, offset);
      proto_tree_add_uint(tree,hf_cotp_res_error_rate_tdsu, tvb, offset, 1, 1 << s);
      offset += 1;
      vp_length -= 1;
      break;

    case VP_PRIORITY:
      proto_tree_add_item(tree, hf_cotp_vp_priority, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += length;
      vp_length -= length;
      break;

    case VP_TRANSIT_DEL:
      proto_tree_add_item(tree, hf_cotp_transit_delay_targ_calling_called, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      vp_length -= 2;

      proto_tree_add_item(tree, hf_cotp_transit_delay_max_accept_calling_called, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      vp_length -= 2;

      proto_tree_add_item(tree, hf_cotp_transit_delay_targ_called_calling, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      vp_length -= 2;

      proto_tree_add_item(tree, hf_cotp_transit_delay_max_accept_called_calling, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      vp_length -= 2;
      break;

    case VP_THROUGHPUT:
      proto_tree_add_item(tree, hf_cotp_max_throughput_targ_calling_called, tvb, offset, 3, ENC_BIG_ENDIAN);
      offset += 3;
      length -= 3;
      vp_length -= 3;

      proto_tree_add_item(tree, hf_cotp_max_throughput_min_accept_calling_called, tvb, offset, 3, ENC_BIG_ENDIAN);
      offset += 3;
      length -= 3;
      vp_length -= 3;

      proto_tree_add_item(tree, hf_cotp_max_throughput_targ_called_calling, tvb, offset, 3, ENC_BIG_ENDIAN);
      offset += 3;
      length -= 3;
      vp_length -= 3;

      proto_tree_add_item(tree, hf_cotp_max_throughput_min_accept_called_calling, tvb, offset, 3, ENC_BIG_ENDIAN);
      offset += 3;
      length -= 3;
      vp_length -= 3;

      if (length != 0) {    /* XXX - should be 0 or 12 */
        proto_tree_add_item(tree, hf_cotp_avg_throughput_targ_calling_called, tvb, offset, 3, ENC_BIG_ENDIAN);
        offset += 3;
        vp_length -= 3;

        proto_tree_add_item(tree, hf_cotp_avg_throughput_min_accept_calling_called, tvb, offset, 3, ENC_BIG_ENDIAN);
        offset += 3;
        vp_length -= 3;

        proto_tree_add_item(tree, hf_cotp_avg_throughput_targ_called_calling, tvb, offset, 3, ENC_BIG_ENDIAN);
        offset += 3;
        vp_length -= 3;

        proto_tree_add_item(tree, hf_cotp_avg_throughput_min_accept_called_calling, tvb, offset, 3, ENC_BIG_ENDIAN);
        offset += 3;
        vp_length -= 3;
      }
      break;

    case VP_SEQ_NR:
      proto_tree_add_item(tree, hf_cotp_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += length;
      vp_length -= length;
      break;

    case VP_REASSIGNMENT:
      proto_tree_add_item(tree, hf_cotp_reassignment_time, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += length;
      vp_length -= length;
      break;

    case VP_FLOW_CNTL:
      proto_tree_add_item(tree, hf_cotp_lower_window_edge, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      vp_length -= 4;

      proto_tree_add_item(tree, hf_cotp_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      vp_length -= 2;

      proto_tree_add_item(tree, hf_cotp_credit, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      vp_length -= 2;

      break;

    case VP_TPDU_SIZE:
      c1 = tvb_get_guint8(tvb, offset) & 0x0F;
      proto_tree_add_uint(tree, hf_cotp_tpdu_size, tvb, offset, 1, 1 << c1);
      offset += length;
      vp_length -= length;
      break;

    case VP_SRC_TSAP:
      /* if our preference is set to STRING or the TSAP is not printable,
       * add as bytes and hidden as string; otherwise vice-versa */
      if (tsap_display==TSAP_DISPLAY_STRING ||
          (tsap_display==TSAP_DISPLAY_AUTO &&
           is_all_printable(tvb_get_ptr(tvb, offset,length),length))) {
        proto_tree_add_string(tree, hf_cotp_vp_src_tsap, tvb, offset, length,
                              print_tsap(tvb, offset, length));
        hidden_item = proto_tree_add_item(tree, hf_cotp_vp_src_tsap_bytes, tvb,
                                          offset, length, ENC_NA);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
      } else {
        hidden_item = proto_tree_add_string(tree, hf_cotp_vp_src_tsap, tvb,
                                            offset, length,
                                            print_tsap(tvb, offset, length));
        PROTO_ITEM_SET_HIDDEN(hidden_item);
        proto_tree_add_item(tree, hf_cotp_vp_src_tsap_bytes, tvb, offset,
                            length, ENC_NA);
      }
      offset += length;
      vp_length -= length;
      break;

    case VP_DST_TSAP:
      /* if our preference is set to STRING or the TSAP is not printable,
       * add as bytes and hidden as string; otherwise vice-versa */
      if (tsap_display==TSAP_DISPLAY_STRING ||
          (tsap_display==TSAP_DISPLAY_AUTO &&
           is_all_printable(tvb_get_ptr(tvb,offset,length),length))) {
        proto_tree_add_string(tree, hf_cotp_vp_dst_tsap, tvb, offset, length,
                              print_tsap(tvb, offset, length));
        hidden_item = proto_tree_add_item(tree, hf_cotp_vp_dst_tsap_bytes, tvb,
                                          offset, length, ENC_NA);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
      } else {
        hidden_item = proto_tree_add_string(tree, hf_cotp_vp_dst_tsap, tvb,
                                            offset, length,
                                            print_tsap(tvb, offset, length));
        PROTO_ITEM_SET_HIDDEN(hidden_item);
        proto_tree_add_item(tree, hf_cotp_vp_dst_tsap_bytes, tvb, offset,
                            length, ENC_NA);
      }
      offset += length;
      vp_length -= length;
      break;

    case VP_CHECKSUM:
      offset_iso8073_checksum = offset; /* save ISO 8073 checksum offset for ATN extended checksum calculation */

      if (tvb_get_ntohs(tvb, offset) == 0) {
        /* No checksum present */
        proto_tree_add_checksum(tree, tvb, offset, hf_cotp_checksum, -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NOT_PRESENT);
      } else {
        guint32 calc_c0 = 0, calc_c1 = 0;

        if (osi_calc_checksum(tvb, 0, length, &calc_c0, &calc_c1)) {
            /* Successfully processed checksum, verify it */
            proto_tree_add_checksum(tree, tvb, offset, hf_cotp_checksum, -1, NULL, pinfo, calc_c0 | calc_c1, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY|PROTO_CHECKSUM_ZERO);
        } else {
            proto_tree_add_checksum(tree, tvb, offset, hf_cotp_checksum, -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
        }
      }

      offset += length;
      vp_length -= length;
      break;

    case VP_VERSION_NR:
      proto_tree_add_item(tree, hf_cotp_vp_version_nr, tvb, offset, 1, ENC_NA);
      offset += length;
      vp_length -= length;
      break;

    case VP_OPT_SEL:
      switch (class_option) {

      case 1:
        proto_tree_add_item(tree, hf_cotp_network_expedited_data, tvb, offset, 1, ENC_NA);

        proto_tree_add_item(tree, hf_cotp_vp_opt_sel_class1_use, tvb, offset, 1, ENC_NA);
        break;

      case 4:
        proto_tree_add_item(tree, hf_cotp_use_16_bit_checksum, tvb, offset, 1, ENC_NA);
        break;
      }

      proto_tree_add_item(tree, hf_cotp_transport_expedited_data_transfer, tvb, offset, 1, ENC_NA);
      offset += length;
      vp_length -= length;
      break;

    case VP_PREF_MAX_TPDU_SIZE:
      switch (length) {

      case 1:
        pref_max_tpdu_size = tvb_get_guint8(tvb, offset);
        break;

      case 2:
        pref_max_tpdu_size = tvb_get_ntohs(tvb, offset);
        break;

      case 3:
        pref_max_tpdu_size = tvb_get_ntoh24(tvb, offset);
        break;

      case 4:
        pref_max_tpdu_size = tvb_get_ntohl(tvb, offset);
        break;

      default:
        proto_tree_add_expert_format(tree, pinfo, &ei_cotp_preferred_maximum_tpdu_size, tvb, offset, length,
                            "Preferred maximum TPDU size: bogus length %u (not 1, 2, 3, or 4)", length);
        return FALSE;
      }
      proto_tree_add_uint(tree, hf_cotp_preferred_maximum_tpdu_size, tvb, offset, length, pref_max_tpdu_size*128);
      offset += length;
      vp_length -= length;
      break;

    case VP_INACTIVITY_TIMER:
      proto_tree_add_item(tree, hf_cotp_inactivity_timer, tvb, offset, length, ENC_BIG_ENDIAN);
      offset += length;
      vp_length -= length;
      break;

    case VP_PROTECTION:             /* user-defined */
    case VP_PROTO_CLASS:            /* todo */
    case VP_CLEARING_INFO:          /* user-defined */
    default:                        /* unknown, no decoding */
      proto_tree_add_bytes_format_value(tree, hf_cotp_parameter_value, tvb, offset, length, NULL, "<not shown>");
      offset += length;
      vp_length -= length;
      break;
    }
  } /* while */

  return TRUE;
}

static const value_string cotp_cause_vals[] = {
  { 0, "Reason not specified" },
  { 1, "Congestion at TSAP" },
  { 2, "Session entity not attached to TSAP" },
  { 3, "Address unknown" },
  { 128+0, "Normal Disconnect" },
  { 128+1, "Remote transport entity congestion" },
  { 128+2, "Connection negotiation failed" },
  { 128+3, "Duplicate source reference" },
  { 128+4, "Mismatched references" },
  { 128+5, "Protocol error" },
  { 128+7, "Reference overflow" },
  { 128+8, "Connection request refused" },
  { 128+10, "Header or parameter length invalid" },
  { 0,       NULL }
};

static int ositp_decode_DR(tvbuff_t *tvb, int offset, guint8 li, guint8 tpdu,
                           packet_info *pinfo, proto_tree *tree)
{
  proto_tree *cotp_tree = NULL;
  proto_item *ti        = NULL;
  guint16     dst_ref, src_ref;
  guchar      reason;
  guint       tpdu_len;

  /* ATN TPDU's tend to be larger than normal OSI,
   * so nothing to do with respect to LI checks */
  if (li < LI_MIN_DR)
    return -1;

  /* DR TPDUs can have user data, so they run to the end of the containing PDU */
  tpdu_len = tvb_reported_length_remaining(tvb, offset);

  dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);

  src_ref = tvb_get_ntohs(tvb, offset + P_SRC_REF);

  reason  = tvb_get_guint8(tvb, offset + P_REASON_IN_DR);

  pinfo->clnp_dstref = dst_ref;
  pinfo->clnp_srcref = src_ref;

  /* the settings of the TCP srcport and destport are currently disabled,
   * for the following reasons:
   * a) only used for ISO conversation handling (which currently doesn't work)
   * b) will prevent "ISO on TCP" (RFC1006) packets from using
   *    "follow TCP stream" correctly
   *
   * A future conversation handling might be able to handle different kinds of
   * conversations (TCP, ISO, TCP on TCP, ...), but in that case this has to be
   * fixed in any case.
   */
  /*pinfo->srcport = src_ref;*/
  /*pinfo->destport = dst_ref;*/
  if (try_val_to_str(reason, cotp_cause_vals) == NULL)
      return -1;

  col_append_fstr(pinfo->cinfo, COL_INFO,
                  "DR TPDU src-ref: 0x%04x dst-ref: 0x%04x", src_ref, dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, ENC_NA);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_uint(cotp_tree, hf_cotp_li, tvb, offset, 1,li);
    proto_tree_add_uint(cotp_tree, hf_cotp_type, tvb, offset +  1, 1, tpdu);
    proto_tree_add_uint(cotp_tree, hf_cotp_destref, tvb, offset +  2, 2,
                        dst_ref);
    proto_tree_add_uint(cotp_tree, hf_cotp_srcref, tvb, offset +  4, 2,
                        src_ref);
    proto_tree_add_item(cotp_tree, hf_cotp_cause, tvb, offset + 6, 1, ENC_NA);
  }
  offset += 7;
  li -= 6;

  if (tree)
    ositp_decode_var_part(tvb, offset, li, 4, tpdu_len, pinfo, cotp_tree);
  offset += li;

  expert_add_info_format(pinfo, ti, &ei_cotp_disconnect_request, "Disconnect Request(DR): 0x%x -> 0x%x", src_ref, dst_ref);

  /* User data */
  call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, tree);
  offset += tvb_captured_length_remaining(tvb, offset);
     /* we dissected all of the containing PDU */

  return offset;

} /* ositp_decode_DR */

static int ositp_decode_DT(tvbuff_t *tvb, int offset, guint8 li, guint8 tpdu,
                           packet_info *pinfo, proto_tree *tree,
                           gboolean uses_inactive_subset,
                           gboolean *subdissector_found)
{
  proto_tree        *cotp_tree       = NULL;
  proto_item        *ti;
  gboolean           is_extended;
  gboolean           is_class_234;
  guint32            dst_ref;
  guint32           *prev_dst_ref;
  guint              tpdu_nr;
  gboolean           fragment        = FALSE;
  guint32            fragment_length = 0;
  tvbuff_t          *next_tvb;
  fragment_head     *fd_head;
  conversation_t    *conv;
  guint              tpdu_len;
  heur_dtbl_entry_t *hdtbl_entry;

  /* DT TPDUs have user data, so they run to the end of the containing PDU */
  tpdu_len = tvb_reported_length_remaining(tvb, offset);

  /* The fixed part is 2 octets long, not including the length indicator,
     for classes 0 and 1; it is at least 4 octets long, not including
     the length indicator, for classes 2, 3, and 4. */
  is_class_234 = (li > LI_NORMAL_DT_CLASS_01);

  /* note: in the ATN the user is up to chose between 3 different checksums:
   *       standard OSI, 2 or 4 octet extended checksum.
   * The differences for DT are that the TPDU headers may be enlarged by 2
   * octets and that checksum related option codes and option lengths are
   * different.  To not mess up the original OSI dissector LI checking was
   * implemented separately. */
  if (!cotp_decode_atn) { /* non ATN, plain OSI*/
    /* VP_CHECKSUM is the only parameter allowed in the variable part.
     * (This means we may misdissect this if the packet is bad and
     * contains other parameters.).

     * XXX - not true; ISO/IEC 8073:1997 (E) says that "if the use of
     * non-blocking expedited data transfer service is negotiated (class
     * 4 only), the variable part shall contain the ED-TPDU-NR for the
     * first DT-TPDU created from a T-DATA request subsequent to the
     * T-EXPEDITED DATA request". */
    switch (li) {

      case LI_NORMAL_DT_WITH_CHECKSUM      :
        if (tvb_get_guint8(tvb, offset + P_VAR_PART_NDT) != VP_CHECKSUM)
          return -1;
        /* FALLTHROUGH */

      case LI_NORMAL_DT_WITHOUT_CHECKSUM   :
        tpdu_nr = tvb_get_guint8(tvb, offset + P_TPDU_NR_234);
        if (tpdu_nr & 0x80)
          tpdu_nr = tpdu_nr & 0x7F;
        else
          fragment = TRUE;
        is_extended = FALSE;
        dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);
        break;

      case LI_EXTENDED_DT_WITH_CHECKSUM    :
        if (tvb_get_guint8(tvb, offset + P_VAR_PART_EDT) != VP_CHECKSUM)
          return -1;
        /* FALLTHROUGH */

      case LI_EXTENDED_DT_WITHOUT_CHECKSUM :
        tpdu_nr = tvb_get_ntohl(tvb, offset + P_TPDU_NR_234);
        if (tpdu_nr & 0x80000000)
          tpdu_nr = tpdu_nr & 0x7FFFFFFF;
        else
          fragment = TRUE;
        is_extended = TRUE;
        dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);
        break;

      case LI_NORMAL_DT_CLASS_01           :
        tpdu_nr = tvb_get_guint8(tvb, offset + P_TPDU_NR_0_1);
        if (tpdu_nr & 0x80)
          tpdu_nr = tpdu_nr & 0x7F;
        else
          fragment = TRUE;
        is_extended = FALSE;
        prev_dst_ref = (guint32 *)p_get_proto_data(wmem_file_scope(), pinfo, proto_clnp, 0);
        if (!prev_dst_ref) {
          /* First COTP in frame - save previous dst_ref as offset */
          prev_dst_ref = wmem_new(wmem_file_scope(), guint32);
          *prev_dst_ref = cotp_dst_ref;
          p_add_proto_data(wmem_file_scope(), pinfo, proto_clnp, 0, prev_dst_ref);
        } else if (cotp_frame_reset) {
          cotp_dst_ref = *prev_dst_ref;
        }
        cotp_frame_reset = FALSE;
        cotp_last_fragment = fragment;
        dst_ref = cotp_dst_ref;
        conv = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
                                 pinfo->ptype, pinfo->srcport, pinfo->destport,
                                 0);
        if (conv) {
          /* Found a conversation, also use index for the generated dst_ref */
          dst_ref += (conv->conv_index << 16);
        }
        if (!fragment) {
          cotp_dst_ref++;
          register_frame_end_routine(pinfo, cotp_frame_end);
        }
        break;

      default : /* bad TPDU */
        return -1;
    } /* li */
  } else {
    /* check ATN class4 TPDU's here */

    /* check packet length indicators of DaTa(DT) TPDU
     * note: use of checksum depends on the selected RER
     *       (high:non-use medium:16-bit OSI/16-bit ext.ATN low:32-bit ext. ATN)
     *
     * note: sole use of TP4 class in the ATN
     * note: normal/extended TPDU numbering is negociable */
    switch (li) {

      /* normal DT with 2 octets of OSI or of ATN Extended Checksum */
      case LI_NORMAL_DT_WITH_CHECKSUM      :
        if (tvb_get_guint8(tvb, offset + P_VAR_PART_NDT) != VP_CHECKSUM &&
            tvb_get_guint8(tvb, offset + P_VAR_PART_NDT) != VP_ATN_EC_16)
          return -1;
        /* FALLTHROUGH */

      case LI_NORMAL_DT_WITHOUT_CHECKSUM   :
        tpdu_nr = tvb_get_guint8(tvb, offset + P_TPDU_NR_234);
        if (tpdu_nr & 0x80)
          tpdu_nr = tpdu_nr & 0x7F;
        else
          fragment = TRUE;
        is_extended = FALSE;
        dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);
        break;

      /* extended DT with 2 octets of OSI or of ATN Extended Checksum */
      case LI_EXTENDED_DT_WITH_CHECKSUM    :
        if (tvb_get_guint8(tvb, offset + P_VAR_PART_EDT) != VP_CHECKSUM &&
            tvb_get_guint8(tvb, offset + P_VAR_PART_EDT) != VP_ATN_EC_16)
          return -1;
        /* FALLTHROUGH */

      case LI_EXTENDED_DT_WITHOUT_CHECKSUM :
        tpdu_nr = tvb_get_ntohl(tvb, offset + P_TPDU_NR_234);
        if (tpdu_nr & 0x80000000)
          tpdu_nr = tpdu_nr & 0x7FFFFFFF;
        else
          fragment = TRUE;
        is_extended = TRUE;
        dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);
        break;

      /* normal DT with ATN Extended Checksum (4 octets)*/
      case LI_ATN_NORMAL_DT_WITH_CHECKSUM      :
        if (tvb_get_guint8(tvb, offset + P_VAR_PART_NDT) != VP_ATN_EC_32)
          return -1;

        tpdu_nr = tvb_get_guint8(tvb, offset + P_TPDU_NR_234);

        if (tpdu_nr & 0x80)
          tpdu_nr = tpdu_nr & 0x7F;
        else
          fragment = TRUE;
        is_extended = FALSE;
        dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);
        break;

      /* extended DT with 4 octets ATN Extended Checksum  */
      case LI_ATN_EXTENDED_DT_WITH_CHECKSUM:
        if (tvb_get_guint8(tvb, offset + P_VAR_PART_EDT) != VP_ATN_EC_32)
          return -1;

        tpdu_nr = tvb_get_ntohl(tvb, offset + P_TPDU_NR_234);
        if (tpdu_nr & 0x80000000)
          tpdu_nr = tpdu_nr & 0x7FFFFFFF;
        else
          fragment = TRUE;
        is_extended = TRUE;
        dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);
        break;

      default : /* bad TPDU */
        return -1;
    } /* li */
  } /* cotp_decode_atn */

  pinfo->clnp_dstref = dst_ref;

  pinfo->fragmented = fragment;
  if (is_class_234) {
      col_append_fstr(pinfo->cinfo, COL_INFO, "DT TPDU (%u) dst-ref: 0x%04x",
                      tpdu_nr, dst_ref);
    } else {
      col_append_fstr(pinfo->cinfo, COL_INFO, "DT TPDU (%u)", tpdu_nr);
    }

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, ENC_NA);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_uint(cotp_tree, hf_cotp_li, tvb, offset, 1,li);
  }
  offset += 1;

  if (tree) {
    proto_tree_add_uint(cotp_tree, hf_cotp_type, tvb, offset, 1, tpdu);
  }
  offset += 1;
  li -= 1;

  if (is_class_234) {
    if (tree)
      proto_tree_add_uint(cotp_tree, hf_cotp_destref, tvb, offset, 2, dst_ref);
    offset += 2;
    li -= 2;
  } else if (tree) {
    ti = proto_tree_add_uint (cotp_tree, hf_cotp_destref, tvb, offset, 0,
                              dst_ref);
    PROTO_ITEM_SET_GENERATED (ti);
  }

  if (is_extended) {
    if (tree) {
      proto_tree_add_uint(cotp_tree, hf_cotp_tpdu_number_extended, tvb, offset,
                          4, tpdu_nr);
      proto_tree_add_item(cotp_tree, hf_cotp_eot_extended, tvb, offset, 4,
                          ENC_BIG_ENDIAN);
    }
    offset += 4;
    li -= 4;
  } else {
    if (tree) {
      proto_tree_add_uint(cotp_tree, hf_cotp_tpdu_number, tvb, offset, 1,
                          tpdu_nr);
      proto_tree_add_item(cotp_tree, hf_cotp_eot, tvb, offset, 1,
                          ENC_BIG_ENDIAN);
    }
    offset += 1;
    li -= 1;
  }

  if (tree)
    ositp_decode_var_part(tvb, offset, li, 4, tpdu_len, pinfo, cotp_tree);
  offset += li;

  next_tvb = tvb_new_subset_remaining(tvb, offset);
  fragment_length = tvb_captured_length(next_tvb);
  if (fragment) {
    col_append_fstr(pinfo->cinfo, COL_INFO, " [COTP fragment, %u byte%s]",
        fragment_length, plurality(fragment_length, "", "s"));
  } else {
    col_append_fstr(pinfo->cinfo, COL_INFO, " EOT");
  }

  if (cotp_reassemble) {
    /*
     * XXX - these sequence numbers are connection sequence number,
     * not segment sequence numbers - the first segment of a
     * segmented packet doesn't have a specific sequence number (e.g., 0
     * or 1), it has whatever the appropriate sequence number is for
     * it in the connection.
     *
     * For now, we assume segments arrive in order, and just supply
     * the negation of the EOT flag as the "more flags" argument.
     * We should probably handle out-of-order packets separately,
     * so that we can deliver them in order even when *not*
     * reassembling.
     *
     * Note also that TP0 has no sequence number, and relies on
     *      the protocol atop which it runs to guarantee in-order delivery.
     */
    fd_head = fragment_add_seq_next(&cotp_reassembly_table, next_tvb, 0, pinfo,
                                    dst_ref, NULL, fragment_length, fragment);
    if (fd_head && fd_head->next) {
      /* don't use -1 if fragment length is zero (throws Exception) */
      proto_tree_add_bytes_format(cotp_tree, hf_cotp_segment_data, tvb, offset, (fragment_length) ? -1 : 0,
                          NULL, "COTP segment data (%u byte%s)", fragment_length,
                          plurality(fragment_length, "", "s"));

      if (!fragment) {
        /* This is the last packet */
        next_tvb = process_reassembled_data (next_tvb, offset, pinfo,
                                             "Reassembled COTP", fd_head,
                                             &cotp_frag_items, NULL, tree);
      } else if (pinfo->num != fd_head->reassembled_in) {
        /* Add a "Reassembled in" link if not reassembled in this frame */
        proto_tree_add_uint(cotp_tree, *(cotp_frag_items.hf_reassembled_in),
                            next_tvb, 0, 0, fd_head->reassembled_in);
      }
      pinfo->fragmented = fragment;
    }
  }

  if (uses_inactive_subset) {
    if (dissector_try_heuristic(cotp_is_heur_subdissector_list, next_tvb,
                                pinfo, tree, &hdtbl_entry, NULL)) {
      *subdissector_found = TRUE;
    } else {
      /* Fill in other Dissectors using inactive subset here */
      call_data_dissector(next_tvb, pinfo, tree);
    }
  } else {
    /*
     * We dissect payload if one of the following is TRUE:
     *
     * - Reassembly option for COTP in preferences is unchecked
     * - Reassembly option is checked and this packet is the last fragment
     */
    if ((!cotp_reassemble) || ((cotp_reassemble) && (!fragment))) {
      if (dissector_try_heuristic(cotp_heur_subdissector_list, next_tvb, pinfo,
                                  tree, &hdtbl_entry, NULL)) {
        *subdissector_found = TRUE;
      } else {
        call_data_dissector(next_tvb, pinfo, tree);
      }
    }
  }

  offset += tvb_captured_length_remaining(tvb, offset);
  /* we dissected all of the containing PDU */

  return offset;

} /* ositp_decode_DT */

static int ositp_decode_ED(tvbuff_t *tvb, int offset, guint8 li, guint8 tpdu,
                           packet_info *pinfo, proto_tree *tree)
{
  proto_tree *cotp_tree = NULL;
  proto_item *ti;
  gboolean    is_extended;
  guint16     dst_ref;
  guint       tpdu_nr;
  tvbuff_t   *next_tvb;
  guint       tpdu_len;

  /* ED TPDUs have user data, so they run to the end of the containing PDU */
  tpdu_len = tvb_reported_length_remaining(tvb, offset);

  /* note: in the ATN the user is up to chose between 3 different checksums:
   *       standard OSI, 2 or 4 octet extended checksum.
   * The differences for ED (as for DT) are that the TPDU headers may be
   * enlarged by 2 octets and that checksum related option codes and option
   * lengths are different.  To not mess up the original OSI dissector LI
   * checking was implemented separately.
   *
   * note: this could not be tested, because no sample was avail for expedited
   *       data */
  if (!cotp_decode_atn) {  /* non ATN, plain OSI*/
    /* ED TPDUs are never fragmented */

    /* VP_CHECKSUM is the only parameter allowed in the variable part.
      (This means we may misdissect this if the packet is bad and
      contains other parameters.) */
    switch (li) {

      case LI_NORMAL_DT_WITH_CHECKSUM      :
        if (tvb_get_guint8(tvb, offset + P_VAR_PART_NDT) != VP_CHECKSUM)
          return -1;
        /* FALLTHROUGH */

      case LI_NORMAL_DT_WITHOUT_CHECKSUM   :
        tpdu_nr = tvb_get_guint8(tvb, offset + P_TPDU_NR_234);
        if (tpdu_nr & 0x80)
          tpdu_nr = tpdu_nr & 0x7F;
        else
          return -1;
        is_extended = FALSE;
        break;

      case LI_EXTENDED_DT_WITH_CHECKSUM    :
        if (tvb_get_guint8(tvb, offset + P_VAR_PART_EDT) != VP_CHECKSUM)
          return -1;
        /* FALLTHROUGH */

      case LI_EXTENDED_DT_WITHOUT_CHECKSUM :
        tpdu_nr = tvb_get_ntohl(tvb, offset + P_TPDU_NR_234);
        if (tpdu_nr & 0x80000000)
          tpdu_nr = tpdu_nr & 0x7FFFFFFF;
        else
          return -1;
        is_extended = TRUE;
        break;

      default : /* bad TPDU */
        return -1;
    } /* li */
  } else {
    /* check packet length indicators of ATN Expedited Data (ED) TPDU
     * note: use of checksum depends on the selected RER
     *       (high:non-use medium:16-bit OSI/16-bit ext.ATN low:32-bit ext. ATN)
     *
     * note: sole use of TP4 class in the ATN
     * note: normal/extended TPDU numbering is negociable */
    switch (li) {

      case LI_NORMAL_DT_WITHOUT_CHECKSUM   :
        tpdu_nr = tvb_get_guint8(tvb, offset + P_TPDU_NR_234);
        if (tpdu_nr & 0x80)
          tpdu_nr = tpdu_nr & 0x7F;
        else
          return -1;
        is_extended = FALSE;
        break;

      case LI_NORMAL_DT_WITH_CHECKSUM      :
        if ((tvb_get_guint8(tvb, offset + P_VAR_PART_NDT) != VP_CHECKSUM) &&
             (tvb_get_guint8(tvb, offset + P_VAR_PART_NDT) != VP_ATN_EC_16))
          return -1;

        tpdu_nr = tvb_get_guint8(tvb, offset + P_TPDU_NR_234);
        if (tpdu_nr & 0x80)
          tpdu_nr = tpdu_nr & 0x7F;
        else
          return -1;
        is_extended = FALSE;
        break;

      case LI_ATN_NORMAL_DT_WITH_CHECKSUM      :
        if (tvb_get_guint8(tvb, offset + P_VAR_PART_NDT) != VP_ATN_EC_32)
          return -1;

        tpdu_nr = tvb_get_guint8(tvb, offset + P_TPDU_NR_234);
        if (tpdu_nr & 0x80)
          tpdu_nr = tpdu_nr & 0x7F;
        else
          return -1;
        is_extended = FALSE;
        break;

      case LI_EXTENDED_DT_WITHOUT_CHECKSUM :
        tpdu_nr = tvb_get_ntohl(tvb, offset + P_TPDU_NR_234);
        if (tpdu_nr & 0x80000000)
          tpdu_nr = tpdu_nr & 0x7FFFFFFF;
        else
          return -1;
        is_extended = TRUE;
        break;

      case LI_EXTENDED_DT_WITH_CHECKSUM    :
        if ((tvb_get_guint8(tvb, offset + P_VAR_PART_EDT) != VP_CHECKSUM) &&
              (tvb_get_guint8(tvb, offset + P_VAR_PART_EDT) != VP_ATN_EC_16))
          return -1;

        tpdu_nr = tvb_get_ntohl(tvb, offset + P_TPDU_NR_234);
        if (tpdu_nr & 0x80000000)
          tpdu_nr = tpdu_nr & 0x7FFFFFFF;
        else
          return -1;
        is_extended = TRUE;
        break;

      case LI_ATN_EXTENDED_DT_WITH_CHECKSUM    :
        if (tvb_get_guint8(tvb, offset + P_VAR_PART_EDT) != VP_ATN_EC_32)
          return -1;

        tpdu_nr = tvb_get_ntohl(tvb, offset + P_TPDU_NR_234);
        if (tpdu_nr & 0x80000000)
          tpdu_nr = tpdu_nr & 0x7FFFFFFF;
        else
          return -1;
        is_extended = TRUE;
        break;

      default : /* bad TPDU */
        return -1;
    } /* li */
  } /* cotp_decode_atn */

  dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);
  pinfo->clnp_dstref = dst_ref;

  col_append_fstr(pinfo->cinfo, COL_INFO, "ED TPDU (%u) dst-ref: 0x%04x",
                  tpdu_nr, dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, ENC_NA);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_uint(cotp_tree, hf_cotp_li, tvb, offset, 1,li);
  }
  offset += 1;

  if (tree) {
    proto_tree_add_uint(cotp_tree, hf_cotp_type, tvb, offset, 1, tpdu);
  }
  offset += 1;
  li -= 1;

  if (tree)
    proto_tree_add_uint(cotp_tree, hf_cotp_destref, tvb, offset, 2, dst_ref);
  offset += 2;
  li -= 2;

  if (is_extended) {
    if (tree) {
      proto_tree_add_uint(cotp_tree, hf_cotp_tpdu_number_extended, tvb, offset,
                          4, tpdu_nr);
    }
    offset += 4;
    li -= 4;
  } else {
    if (tree) {
      proto_tree_add_uint(cotp_tree, hf_cotp_tpdu_number, tvb, offset, 1,
                          tpdu_nr);
    }
    offset += 1;
    li -= 1;
  }

  if (tree)
    ositp_decode_var_part(tvb, offset, li, 4, tpdu_len, pinfo, cotp_tree);
  offset += li;

  /*
   * XXX - hand this to subdissectors but tell them that this is
   * in an ED packet?
   */
  next_tvb = tvb_new_subset_remaining(tvb, offset);
  call_data_dissector(next_tvb, pinfo, tree);

  offset += tvb_captured_length_remaining(tvb, offset);
     /* we dissected all of the containing PDU */

  return offset;

} /* ositp_decode_ED */

static int ositp_decode_RJ(tvbuff_t *tvb, int offset, guint8 li, guint8 tpdu,
                           guint8 cdt, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *cotp_tree;
  proto_item *ti;
  proto_item *item = NULL;
  guint16  dst_ref;
  guint    tpdu_nr;
  gushort  credit = 0;

  /* note: in the ATN the user is up to chose between 3 different checksums:
   *       standard OSI, 2 or 4 octet extended checksum.
   * The difference for RJ is that the TPDU header may be enlarged by 2 octets
   * for checksum parameters are not going to be checked here */
  if (!cotp_decode_atn) {  /* non ATN, plain OSI */
    switch(li) {
      case LI_NORMAL_RJ   :
        tpdu_nr = tvb_get_guint8(tvb, offset + P_TPDU_NR_234);
        break;
      case LI_EXTENDED_RJ :
        tpdu_nr = tvb_get_ntohl(tvb, offset + P_TPDU_NR_234);
        credit = tvb_get_ntohs(tvb, offset + P_CDT_IN_RJ);
        break;
      default :
        return -1;
    }
  } else {
    switch(li) {
      /* normal with 2 octets of OSI or ATN checksum */
      case LI_NORMAL_RJ   :
      /* with 4 octets of ATN checksum */
      case LI_ATN_NORMAL_RJ   :
        tpdu_nr = tvb_get_guint8(tvb, offset + P_TPDU_NR_234);
        break;
      /* extended with 2 octets of OSI or ATN checksum */
      case LI_EXTENDED_RJ :
      /* with 4 octets of ATN checksum */
      case LI_ATN_EXTENDED_RJ :
        tpdu_nr = tvb_get_ntohl(tvb, offset + P_TPDU_NR_234);
        credit = tvb_get_ntohs(tvb, offset + P_CDT_IN_RJ);
        break;
      default :
        return -1;
    }
  }

  dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);
  pinfo->clnp_dstref = dst_ref;

  col_append_fstr(pinfo->cinfo, COL_INFO, "RJ TPDU (%u) dst-ref: 0x%04x",
                  tpdu_nr, dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, ENC_NA);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_uint(cotp_tree, hf_cotp_li, tvb, offset, 1,li);
    item = proto_tree_add_uint(cotp_tree, hf_cotp_type, tvb, offset +  1, 1,
                               tpdu);
    if (li == LI_NORMAL_RJ) {
      proto_tree_add_uint(cotp_tree, hf_cotp_credit_cdt, tvb, offset +  1, 1, cdt);
    }
    proto_tree_add_uint(cotp_tree, hf_cotp_destref, tvb, offset +  2, 2,
                        dst_ref);
    if (li == LI_NORMAL_RJ)
      proto_tree_add_uint(cotp_tree, hf_cotp_next_tpdu_number, tvb, offset + 4,
                          1, tpdu_nr);
    else {
      proto_tree_add_uint(cotp_tree, hf_cotp_next_tpdu_number_extended, tvb,
                          offset + 4, 4, tpdu_nr);
      proto_tree_add_uint(cotp_tree, hf_cotp_credit, tvb, offset +  8, 2, credit);
    }
  }

  offset += li + 1;

  expert_add_info_format(pinfo, item, &ei_cotp_reject, "Reject(RJ): -> 0x%x", dst_ref);

  return offset;

} /* ositp_decode_RJ */

static int ositp_decode_CR_CC(tvbuff_t *tvb, int offset, guint8 li, guint8 tpdu,
                              packet_info *pinfo, proto_tree *tree,
                              gboolean uses_inactive_subset,
                              gboolean *subdissector_found)
{
  /* note: in the ATN the user is up to chose between 3 different checksums:
   *       standard OSI, 2 or 4 octet extended checksum.
   * Nothing has to be done here, for all ATN specifics are handled in VP. */

  /* CC & CR decoding in the same function */

  proto_tree *cotp_tree = NULL;
  proto_item *ti;
  proto_item *item = NULL;
  guint16 dst_ref, src_ref;
  guint8  class_option;
  tvbuff_t *next_tvb;
  guint   tpdu_len;
  heur_dtbl_entry_t *hdtbl_entry;
  static const int * class_options[] = {
     &hf_cotp_class,
     &hf_cotp_opts_extended_formats,
     &hf_cotp_opts_no_explicit_flow_control,
     NULL,
  };

  src_ref = tvb_get_ntohs(tvb, offset + P_SRC_REF);

  class_option = tvb_get_guint8(tvb, offset + P_CLASS_OPTION);
  if (((class_option & 0xF0) >> 4) > 4) /* class 0..4 allowed */
    return -1;

  /* CR and CC TPDUs can have user data, so they run to the end of the
   * containing PDU */
  tpdu_len = tvb_reported_length_remaining(tvb, offset);

  dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);
  pinfo->clnp_srcref = src_ref;
  pinfo->clnp_dstref = dst_ref;

  col_append_fstr(pinfo->cinfo, COL_INFO,
                  "%s TPDU src-ref: 0x%04x dst-ref: 0x%04x",
                  (tpdu == CR_TPDU) ? "CR" : "CC", src_ref, dst_ref);

  ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, ENC_NA);
  cotp_tree = proto_item_add_subtree(ti, ett_cotp);
  proto_tree_add_uint(cotp_tree, hf_cotp_li, tvb, offset, 1,li);
  offset += 1;

  item = proto_tree_add_uint(cotp_tree, hf_cotp_type, tvb, offset, 1, tpdu);
  offset += 1;
  li -= 1;

  proto_tree_add_uint(cotp_tree, hf_cotp_destref, tvb, offset, 2, dst_ref);
  offset += 2;
  li -= 2;

  proto_tree_add_uint(cotp_tree, hf_cotp_srcref, tvb, offset, 2, src_ref);
  offset += 2;
  li -= 2;

  /* expert info, but only if not encapsulated in TCP/SMB */
  /* XXX - the best way to detect seems to be if we have a port set */
  if (pinfo->destport == 0) {
    expert_add_info_format(pinfo, item, &ei_cotp_connection, "Connection %s: 0x%x -> 0x%x", tpdu == CR_TPDU ? "Request(CR)" : "Confirm(CC)", src_ref, dst_ref);
  }

  proto_tree_add_bitmask_list(cotp_tree, tvb, offset, 1, class_options, ENC_NA);
  offset += 1;
  li -= 1;

  if (li > 0) {
    /* There's more data left, so we have the variable part.

       Microsoft's RDP hijacks the variable part of CR and CC PDUs
       for their own user data (RDP runs atop Class 0, which doesn't
       support user data).

       Try what heuristic dissectors we have. */
    next_tvb = tvb_new_subset_length(tvb, offset, li);
    if (dissector_try_heuristic((tpdu == CR_TPDU) ?
                                 cotp_cr_heur_subdissector_list :
                                 cotp_cc_heur_subdissector_list,
                                next_tvb, pinfo, tree, &hdtbl_entry, NULL)) {
      /* A subdissector claimed this, so it really belongs to them. */
      *subdissector_found = TRUE;
    } else {
      /* No heuristic dissector claimed it, so dissect it as a regular
         variable part. */
      ositp_decode_var_part(tvb, offset, li, class_option, tpdu_len, pinfo,
                            cotp_tree);
    }
    offset += li;
  }

  /*
   * XXX - tell the subdissector that this is user data in a CR or
   * CC packet rather than a DT packet?
   */
  next_tvb = tvb_new_subset_remaining(tvb, offset);
  if (!uses_inactive_subset){
    if (dissector_try_heuristic(cotp_heur_subdissector_list, next_tvb, pinfo,
                                tree, &hdtbl_entry, NULL)) {
      *subdissector_found = TRUE;
    } else {
      call_data_dissector(next_tvb, pinfo, tree);
    }
  }
  else
    call_data_dissector( next_tvb, pinfo, tree);
  offset += tvb_captured_length_remaining(tvb, offset);
  /* we dissected all of the containing PDU */

  return offset;

} /* ositp_decode_CR_CC */

static int ositp_decode_DC(tvbuff_t *tvb, int offset, guint8 li, guint8 tpdu,
                           packet_info *pinfo, proto_tree *tree)
{
  proto_tree *cotp_tree = NULL;
  proto_item *ti;
  proto_item *item = NULL;
  guint16 dst_ref, src_ref;
  guint   tpdu_len;

  /* ATN may use checksums different from OSI */
  /* which may result in different TPDU header length. */
  if (!cotp_decode_atn) {
    if (li > LI_MAX_DC)
      return -1;
  } else {
    if (li > LI_ATN_MAX_DC)
      return -1;
  }

  /* DC TPDUs have no user data, so the length indicator determines the
   * length */
  tpdu_len = li + 1;

  dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);
  src_ref = tvb_get_ntohs(tvb, offset + P_SRC_REF);
  pinfo->clnp_dstref = dst_ref;
  pinfo->clnp_srcref = src_ref;

  col_append_fstr(pinfo->cinfo, COL_INFO,
                  "DC TPDU src-ref: 0x%04x dst-ref: 0x%04x", src_ref, dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, ENC_NA);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_uint(cotp_tree, hf_cotp_li, tvb, offset, 1,li);
  }
  offset += 1;

  if (tree) {
    item = proto_tree_add_uint(cotp_tree, hf_cotp_type, tvb, offset, 1, tpdu);
  }
  offset += 1;
  li -= 1;

  if (tree)
    proto_tree_add_uint(cotp_tree, hf_cotp_destref, tvb, offset, 2, dst_ref);
  offset += 2;
  li -= 2;

  if (tree)
    proto_tree_add_uint(cotp_tree, hf_cotp_srcref, tvb, offset, 2, src_ref);
  offset += 2;
  li -= 2;

  if (tree)
    ositp_decode_var_part(tvb, offset, li, 4, tpdu_len, pinfo, cotp_tree);
  offset += li;

  expert_add_info_format(pinfo, item, &ei_cotp_disconnect_confirm, "Disconnect Confirm(DC): 0x%x -> 0x%x", src_ref, dst_ref);

  return offset;

} /* ositp_decode_DC */

static int ositp_decode_AK(tvbuff_t *tvb, int offset, guint8 li, guint8 tpdu,
                           guint8 cdt, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *cotp_tree = NULL;
  proto_item *ti;
  guint16    dst_ref;
  guint      tpdu_nr;
  gushort    cdt_in_ak;
  guint      tpdu_len;

  if (!cotp_decode_atn) {
    if (li > LI_MAX_AK)
      return -1;
  } else {
    if (li > LI_ATN_MAX_AK)
      return -1;
  }

  /* AK TPDUs have no user data, so the length indicator determines the
   * length */
  tpdu_len = li + 1;

  /* is_LI_NORMAL_AK() works for normal ATN AK's, */
  /* for the TPDU header size may be enlarged by 2 octets */
  if (is_LI_NORMAL_AK(li)) {

    dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);
    tpdu_nr = tvb_get_guint8(tvb, offset + P_TPDU_NR_234);
    pinfo->clnp_dstref = dst_ref;

    col_append_fstr(pinfo->cinfo, COL_INFO, "AK TPDU (%u) dst-ref: 0x%04x",
                    tpdu_nr, dst_ref);

    if (tree) {
      ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, ENC_NA);
      cotp_tree = proto_item_add_subtree(ti, ett_cotp);
      proto_tree_add_uint(cotp_tree, hf_cotp_li, tvb, offset, 1,li);
    }
    offset += 1;

    if (tree) {
      proto_tree_add_uint(cotp_tree, hf_cotp_type, tvb, offset, 1, tpdu);
      proto_tree_add_uint(cotp_tree, hf_cotp_credit_cdt, tvb, offset, 1, cdt);
    }
    offset += 1;
    li -= 1;

    if (tree)
      proto_tree_add_uint(cotp_tree, hf_cotp_destref, tvb, offset, 2, dst_ref);
    offset += 2;
    li -= 2;

    if (tree) {
      proto_tree_add_uint(cotp_tree, hf_cotp_next_tpdu_number, tvb, offset, 1,
                          tpdu_nr);
    }
    offset += 1;
    li -= 1;

    if (tree)
      ositp_decode_var_part(tvb, offset, li, 4, tpdu_len, pinfo, cotp_tree);
    offset += li;

  } else { /* extended format */

    dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);
    tpdu_nr   = tvb_get_ntohl(tvb, offset + P_TPDU_NR_234);
    cdt_in_ak = tvb_get_ntohs(tvb, offset + P_CDT_IN_AK);
    pinfo->clnp_dstref = dst_ref;

    col_append_fstr(pinfo->cinfo, COL_INFO,
                    "AK TPDU (%u) dst-ref: 0x%04x Credit: %u",
                    tpdu_nr, dst_ref, cdt_in_ak);

    if (tree) {
      ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, ENC_NA);
      cotp_tree = proto_item_add_subtree(ti, ett_cotp);
      proto_tree_add_uint(cotp_tree, hf_cotp_li, tvb, offset, 1,li);
    }
    offset += 1;

    if (tree) {
      proto_tree_add_uint(cotp_tree, hf_cotp_type, tvb, offset, 1, tpdu);
    }
    offset += 1;
    li -= 1;

    if (tree)
      proto_tree_add_uint(cotp_tree, hf_cotp_destref, tvb, offset, 2, dst_ref);
    offset += 2;
    li -= 2;

    if (tree) {
      proto_tree_add_uint(cotp_tree, hf_cotp_next_tpdu_number_extended, tvb,
                          offset, 4, tpdu_nr);
    }
    offset += 4;
    li -= 4;

    if (tree) {
      proto_tree_add_uint(cotp_tree, hf_cotp_credit, tvb, offset, 2, cdt_in_ak);
    }
    offset += 2;
    li -= 2;

    if (tree)
      ositp_decode_var_part(tvb, offset, li, 4, tpdu_len, pinfo, cotp_tree);
    offset += li;

  } /* is_LI_NORMAL_AK */

  return offset;

} /* ositp_decode_AK */

static int ositp_decode_EA(tvbuff_t *tvb, int offset, guint8 li, guint8 tpdu,
                           packet_info *pinfo, proto_tree *tree)
{
  proto_tree *cotp_tree = NULL;
  proto_item *ti;
  gboolean is_extended;
  guint16  dst_ref;
  guint    tpdu_nr;
  guint    tpdu_len;

  /* Due to different checksums in the ATN the TPDU header sizes
   * as well as the checksum parameters may be different than plain OSI EA
   * because these are heavily checked for EA these checks had to be
   * re-implemented.
   * note: this could not be tested, because no sample was avail for expedited
   *       data */
  if (!cotp_decode_atn) {
    if (li > LI_MAX_EA)
      return -1;

    /* VP_CHECKSUM is the only parameter allowed in the variable part.
     (This means we may misdissect this if the packet is bad and
     contains other parameters.) */
    switch (li) {

      case LI_NORMAL_EA_WITH_CHECKSUM      :
        if (tvb_get_guint8(tvb, offset + P_VAR_PART_NDT) != VP_CHECKSUM ||
          tvb_get_guint8(tvb, offset + P_VAR_PART_NDT + 1) != 2)
            return -1;
        /* FALLTHROUGH */

      case LI_NORMAL_EA_WITHOUT_CHECKSUM   :
        tpdu_nr = tvb_get_guint8(tvb, offset + P_TPDU_NR_234);
        is_extended = FALSE;
        break;

      case LI_EXTENDED_EA_WITH_CHECKSUM    :
        if (tvb_get_guint8(tvb, offset + P_VAR_PART_EDT) != VP_CHECKSUM ||
            tvb_get_guint8(tvb, offset + P_VAR_PART_EDT + 1) != 2)
          return -1;
        /* FALLTHROUGH */

      case LI_EXTENDED_EA_WITHOUT_CHECKSUM :
        tpdu_nr = tvb_get_ntohl(tvb, offset + P_TPDU_NR_234);
        is_extended = TRUE;
        break;

      default : /* bad TPDU */
        return -1;
    } /* li */
  } else { /* cotp_decode_atn */
    /* check for ATN length: TPDU may be 2 octets longer due to checksum */
    if (li > LI_ATN_MAX_EA)
      return -1;

    switch (li) {

      /* extended TPDU numbering EA with  no checksum  */
      case LI_NORMAL_EA_WITHOUT_CHECKSUM   :
        tpdu_nr = tvb_get_guint8(tvb, offset + P_TPDU_NR_234);
        is_extended = FALSE;
        break;

      /* normal TPDU numbering EA with 2 octets of OSI or ATN extended
       * checksum */
      case LI_NORMAL_EA_WITH_CHECKSUM      :
        /* check checksum parameter (in VP) parameter code octet */
        if ((tvb_get_guint8(tvb, offset + P_VAR_PART_NDT) != VP_CHECKSUM) &&
            (tvb_get_guint8(tvb, offset + P_VAR_PART_NDT) != VP_ATN_EC_16))
          return -1;

        /* check checksum parameter (in VP) length octet */
        if (tvb_get_guint8(tvb, offset + P_VAR_PART_NDT + 1) != 2)
          return -1;

        tpdu_nr = tvb_get_guint8(tvb, offset + P_TPDU_NR_234);
        is_extended = FALSE;
        break;

      /* normal TPDU numbering EA with 4 octets of ATN extended checksum  */
      case LI_ATN_NORMAL_EA_WITH_CHECKSUM      :
        /* check checksum parameter (in VP) parameter code octet */
        if (tvb_get_guint8(tvb, offset + P_VAR_PART_NDT) != VP_ATN_EC_32)
          return -1;

        /* check checksum parameter (in VP) length octet */
        if (tvb_get_guint8(tvb, offset + P_VAR_PART_NDT + 1) != 4)
          return -1;

        tpdu_nr = tvb_get_guint8(tvb, offset + P_TPDU_NR_234);
        is_extended = FALSE;
        break;

      /* extended TPDU numbering EA with no checksum  */
      case LI_EXTENDED_EA_WITHOUT_CHECKSUM :
        tpdu_nr = tvb_get_ntohl(tvb, offset + P_TPDU_NR_234);
        is_extended = TRUE;
        break;

      /* extended TPDU numbering EA with 2 octets of OSI or ATN extended
       * checksum */
      case LI_EXTENDED_EA_WITH_CHECKSUM    :
        /* check checksum parameter (in VP) parameter code octet */
        if ((tvb_get_guint8(tvb, offset + P_VAR_PART_EDT) != VP_CHECKSUM) &&
             (tvb_get_guint8(tvb, offset + P_VAR_PART_EDT) != VP_ATN_EC_16))
          return -1;

        /* check checksum parameter (in VP) length octet */
        if (tvb_get_guint8(tvb, offset + P_VAR_PART_EDT + 1) != 2)
          return -1;

        tpdu_nr = tvb_get_ntohl(tvb, offset + P_TPDU_NR_234);
        is_extended = TRUE;
        break;

        /* extended EA with 4 octets ATN extended checksum  */
      case LI_ATN_EXTENDED_EA_WITH_CHECKSUM    :
        /* check checksum parameter (in VP) parameter code octet */
        if (tvb_get_guint8(tvb, offset + P_VAR_PART_EDT) != VP_ATN_EC_32)
          return -1;

        /* check checksum parameter (in VP) length octet */
        if (tvb_get_guint8(tvb, offset + P_VAR_PART_EDT + 1) != 2)
          return -1;

        tpdu_nr = tvb_get_ntohl(tvb, offset + P_TPDU_NR_234);
        is_extended = TRUE;
        break;

      default : /* bad TPDU */
        return -1;
    }
  }

  /* ER TPDUs have no user data, so the length indicator determines the
   * length */
  tpdu_len = li + 1;

  dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);
  pinfo->clnp_dstref = dst_ref;

  col_append_fstr(pinfo->cinfo, COL_INFO, "EA TPDU (%u) dst-ref: 0x%04x",
                  tpdu_nr, dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, ENC_NA);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_uint(cotp_tree, hf_cotp_li, tvb, offset, 1,li);
  }
  offset += 1;

  if (tree) {
    proto_tree_add_uint(cotp_tree, hf_cotp_type, tvb, offset, 1, tpdu);
  }
  offset += 1;
  li -= 1;

  if (tree)
    proto_tree_add_uint(cotp_tree, hf_cotp_destref, tvb, offset, 2, dst_ref);
  offset += 2;
  li -= 2;

  if (is_extended) {
    if (tree) {
      proto_tree_add_uint(cotp_tree, hf_cotp_next_tpdu_number_extended, tvb,
                          offset, 4, tpdu_nr);
    }
    offset += 4;
    li -= 4;
  } else {
    if (tree) {
      proto_tree_add_uint(cotp_tree, hf_cotp_next_tpdu_number, tvb, offset, 1,
                          tpdu_nr);
    }
    offset += 1;
    li -= 1;
  }

  if (tree)
    ositp_decode_var_part(tvb, offset, li, 4, tpdu_len,  pinfo, cotp_tree);
  offset += li;

  return offset;

} /* ositp_decode_EA */

static const value_string cotp_reject_vals[] = {
  { 0, "Reason not specified" },
  { 1, "Invalid parameter code" },
  { 2, "Invalid TPDU type" },
  { 3, "Invalid parameter value" },
  { 0,       NULL }
};

static int ositp_decode_ER(tvbuff_t *tvb, int offset, guint8 li, guint8 tpdu,
                           packet_info *pinfo, proto_tree *tree)
{
  proto_tree *cotp_tree = NULL;
  proto_item *ti;
  guint16 dst_ref;
  guint8 tpdu_len;

  /* ATN: except for modified LI checking nothing to be done here */
  if (!cotp_decode_atn) {
    if (li > LI_MAX_ER)
      return -1;
  } else {
    if (li > LI_ATN_MAX_ER)
      return -1;
  }

  /* ER TPDUs have no user data, so the length indicator determines the
   * length */
  tpdu_len = li + 1;

  if(try_val_to_str(tvb_get_guint8(tvb, offset + P_REJECT_ER), cotp_reject_vals) == NULL)
      return -1;

  dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);
  pinfo->clnp_dstref = dst_ref;

  col_append_fstr(pinfo->cinfo, COL_INFO, "ER TPDU dst-ref: 0x%04x", dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, ENC_NA);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_uint(cotp_tree, hf_cotp_li, tvb, offset, 1,li);
    proto_tree_add_uint(cotp_tree, hf_cotp_type, tvb, offset +  1, 1, tpdu);
    proto_tree_add_uint(cotp_tree, hf_cotp_destref, tvb, offset +  2, 2,
                        dst_ref);
    proto_tree_add_item(cotp_tree, hf_cotp_reject_cause, tvb, offset + 4, 1, ENC_NA);
  }
  offset += 5;
  li -= 4;

  if (tree)
    ositp_decode_var_part(tvb, offset, li, 4, tpdu_len, pinfo, cotp_tree);
  offset += li;

  return offset;

} /* ositp_decode_ER */

static int ositp_decode_UD(tvbuff_t *tvb, int offset, guint8 li, guint8 tpdu,
                           packet_info *pinfo, proto_tree *tree,
                           gboolean *subdissector_found)
{
  proto_item *ti;
  proto_tree *cltp_tree = NULL;
  tvbuff_t   *next_tvb;
  guint      tpdu_len;
  heur_dtbl_entry_t *hdtbl_entry;

  /* UD TPDUs have user data, so they run to the end of the containing PDU */
  tpdu_len = tvb_reported_length_remaining(tvb, offset);

  col_append_str(pinfo->cinfo, COL_INFO, "UD TPDU");

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cltp, tvb, offset, li + 1, ENC_NA);
    cltp_tree = proto_item_add_subtree(ti, ett_cltp);
    proto_tree_add_uint(cltp_tree, hf_cltp_li, tvb, offset, 1,li);
  }
  offset += 1;

  if (tree) {
    proto_tree_add_uint(cltp_tree, hf_cltp_type, tvb, offset, 1, tpdu);
  }
  offset += 1;
  li -= 1;

  if (tree)
    ositp_decode_var_part(tvb, offset, li, 0, tpdu_len, pinfo, cltp_tree);
  offset += li;

  next_tvb = tvb_new_subset_remaining(tvb, offset);

  if (dissector_try_heuristic(cltp_heur_subdissector_list, next_tvb,
                              pinfo, tree, &hdtbl_entry, NULL)) {
    *subdissector_found = TRUE;
  } else {
    call_data_dissector(next_tvb, pinfo, tree);
  }


  /*call_data_dissector(next_tvb, pinfo, tree); */

  offset += tvb_captured_length_remaining(tvb, offset);
  /* we dissected all of the containing PDU */

  return offset;

} /* ositp_decode_UD */

/* Returns the offset past the last valid COTP or CLTP PDU if we found
   at least one valid COTP or CLTP PDU, 0 otherwise.

   There doesn't seem to be any way in which the OSI network layer protocol
   distinguishes between COTP and CLTP, but the first two octets of both
   protocols' headers mean the same thing - length and PDU type - and the
   only valid CLTP PDU type is not a valid COTP PDU type, so we'll handle
   both of them here. */
static gint dissect_ositp_internal(tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree,
                                   gboolean uses_inactive_subset)
{
  int offset = 0;
  guint8 li, tpdu, cdt;
  gboolean first_tpdu = TRUE;
  int new_offset;
  gboolean found_ositp = FALSE;
  gboolean is_cltp = FALSE;
  gboolean subdissector_found = FALSE;

  /* Initialize the COL_INFO field; each of the TPDUs will have its
     information appended. */
  col_set_str(pinfo->cinfo, COL_INFO, "");

  while (tvb_offset_exists(tvb, offset)) {
    if (!first_tpdu) {
      col_append_str(pinfo->cinfo, COL_INFO, ", ");
      expert_add_info(pinfo, NULL, &ei_cotp_multiple_tpdus);
      /* adjust tvb and offset to the start of the current PDU */
      tvb = tvb_new_subset_remaining(tvb, offset);
      offset = 0 ;
    }
    if ((li = tvb_get_guint8(tvb, offset + P_LI)) == 0) {
      col_append_str(pinfo->cinfo, COL_INFO, "Length indicator is zero");
      if (!first_tpdu)
        call_data_dissector( tvb_new_subset_remaining(tvb, offset),
                       pinfo, tree);
      return found_ositp;
    }

    tpdu = (tvb_get_guint8(tvb, offset + P_TPDU) >> 4) & 0x0F;
    if (tpdu == UD_TPDU)
      pinfo->current_proto = "CLTP";    /* connectionless transport */
    cdt = tvb_get_guint8(tvb, offset + P_CDT) & 0x0F;

    switch (tpdu) {
      case CC_TPDU :
      case CR_TPDU :
        new_offset = ositp_decode_CR_CC(tvb, offset, li, tpdu, pinfo, tree,
                                        uses_inactive_subset, &subdissector_found);
        break;
      case DR_TPDU :
        new_offset = ositp_decode_DR(tvb, offset, li, tpdu, pinfo, tree);
        break;
      case DT_TPDU :
        new_offset = ositp_decode_DT(tvb, offset, li, tpdu, pinfo, tree,
                                     uses_inactive_subset, &subdissector_found);
        break;
      case ED_TPDU :
        new_offset = ositp_decode_ED(tvb, offset, li, tpdu, pinfo, tree);
        break;
      case RJ_TPDU :
        new_offset = ositp_decode_RJ(tvb, offset, li, tpdu, cdt, pinfo, tree);
        break;
      case DC_TPDU :
        new_offset = ositp_decode_DC(tvb, offset, li, tpdu, pinfo, tree);
        break;
      case AK_TPDU :
        new_offset = ositp_decode_AK(tvb, offset, li, tpdu, cdt, pinfo, tree);
        break;
      case EA_TPDU :
        new_offset = ositp_decode_EA(tvb, offset, li, tpdu, pinfo, tree);
        break;
      case ER_TPDU :
        new_offset = ositp_decode_ER(tvb, offset, li, tpdu, pinfo, tree);
        break;
      case UD_TPDU :
        new_offset = ositp_decode_UD(tvb, offset, li, tpdu, pinfo, tree,
                                     &subdissector_found);
        is_cltp = TRUE;
        break;
      default      :
        if (first_tpdu)
          col_append_fstr(pinfo->cinfo, COL_INFO, "Unknown TPDU type (0x%x)",
                          tpdu);
        new_offset = -1;    /* bad PDU type */
        break;
    }

    if (new_offset == -1) { /* incorrect TPDU */
      if (!first_tpdu)
        call_data_dissector( tvb_new_subset_remaining(tvb, offset),
                       pinfo, tree);
      break;
    }

    if (first_tpdu) {
      /* Well, we found at least one valid COTP or CLTP PDU, so I guess this
         is either COTP or CLTP. */
      if (!subdissector_found)
        col_set_str(pinfo->cinfo, COL_PROTOCOL, is_cltp ? "CLTP" : "COTP");
      found_ositp = TRUE;
    }

    offset = new_offset;
    first_tpdu = FALSE;
  }
  return found_ositp ? offset : 0;
} /* dissect_ositp_internal */

static gint dissect_ositp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                          void *data _U_)
{
  return dissect_ositp_internal(tvb, pinfo, tree, FALSE);
}

static gint dissect_ositp_inactive(tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree, void *data _U_)
{
  return dissect_ositp_internal(tvb, pinfo, tree, TRUE);
}

static void
cotp_reassemble_init(void)
{
  /*
   * XXX - this is a connection-oriented transport-layer protocol,
   * so we should probably use more than just network-layer
   * endpoint addresses to match segments together, but the functions
   * in addresses_ports_reassembly_table_functions do matching based
   * on port numbers, so they won't let us ensure that segments from
   * different connections don't get assembled together.
   */
  reassembly_table_init(&cotp_reassembly_table,
                        &addresses_reassembly_table_functions);
  cotp_dst_ref = 0;
}

static void
cotp_reassemble_cleanup(void)
{
  reassembly_table_destroy(&cotp_reassembly_table);
}

void proto_register_cotp(void)
{
  static hf_register_info hf[] = {
    { &hf_cotp_li,
      { "Length", "cotp.li", FT_UINT8, BASE_DEC,
        NULL, 0x0, "Length Indicator, length of this header", HFILL}},
    { &hf_cotp_type,
      { "PDU Type", "cotp.type", FT_UINT8, BASE_HEX,
        VALS(cotp_tpdu_type_abbrev_vals), 0x0,
        "PDU Type - upper nibble of byte", HFILL}},
    { &hf_cotp_srcref,
      { "Source reference", "cotp.srcref", FT_UINT16, BASE_HEX,
        NULL, 0x0, "Source address reference", HFILL}},
    { &hf_cotp_destref,
      { "Destination reference", "cotp.destref", FT_UINT16, BASE_HEX,
        NULL, 0x0, "Destination address reference", HFILL}},
    { &hf_cotp_class,
      { "Class", "cotp.class", FT_UINT8, BASE_DEC, NULL,
        0xF0, "Transport protocol class", HFILL}},
    { &hf_cotp_opts_extended_formats,
      { "Extended formats", "cotp.opts.extended_formats", FT_BOOLEAN, 8,
        NULL, 0x02, "Use of extended formats in classes 2, 3, and 4", HFILL}},
    { &hf_cotp_opts_no_explicit_flow_control,
      { "No explicit flow control", "cotp.opts.no_explicit_flow_control",
        FT_BOOLEAN, 8, NULL, 0x01, "No explicit flow control in class 2",
        HFILL}},
    { &hf_cotp_tpdu_number,
      { "TPDU number", "cotp.tpdu-number", FT_UINT8, BASE_HEX,
        NULL, 0x7f, NULL, HFILL}},
    { &hf_cotp_tpdu_number_extended,
      { "TPDU number", "cotp.tpdu-number", FT_UINT32, BASE_HEX,
        NULL, 0x0 /* XXX - 0x7fff? */, NULL, HFILL}},
    { &hf_cotp_next_tpdu_number,
      { "Your TPDU number", "cotp.next-tpdu-number", FT_UINT8, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
    { &hf_cotp_next_tpdu_number_extended,
      { "Your TPDU number", "cotp.next-tpdu-number", FT_UINT32, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
    { &hf_cotp_eot,
      { "Last data unit", "cotp.eot", FT_BOOLEAN, 8,
        TFS(&tfs_yes_no),  0x80,
        "Is current TPDU the last data unit of a complete DT TPDU sequence "
        "(End of TSDU)?", HFILL}},
    { &hf_cotp_eot_extended,
      { "Last data unit", "cotp.eot", FT_BOOLEAN, 32,
        TFS(&tfs_yes_no),  0x80000000,
        "Is current TPDU the last data unit of a complete DT TPDU sequence "
        "(End of TSDU)?", HFILL}},
    { &hf_cotp_segment_overlap,
      { "Segment overlap", "cotp.segment.overlap", FT_BOOLEAN, BASE_NONE,
        NULL, 0x0, "Segment overlaps with other segments", HFILL }},
    { &hf_cotp_segment_overlap_conflict,
      { "Conflicting data in segment overlap", "cotp.segment.overlap.conflict",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "Overlapping segments contained conflicting data", HFILL }},
    { &hf_cotp_segment_multiple_tails,
      { "Multiple tail segments found", "cotp.segment.multipletails",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "Several tails were found when reassembling the packet", HFILL }},
    { &hf_cotp_segment_too_long_segment,
      { "Segment too long", "cotp.segment.toolongsegment",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "Segment contained data past end of packet", HFILL }},
    { &hf_cotp_segment_error,
      { "Reassembly error", "cotp.segment.error", FT_FRAMENUM, BASE_NONE,
        NULL, 0x0, "Reassembly error due to illegal segments", HFILL }},
    { &hf_cotp_segment_count,
      { "Segment count", "cotp.segment.count", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},
    { &hf_cotp_segment,
      { "COTP Segment", "cotp.segment", FT_FRAMENUM, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},
    { &hf_cotp_segments,
      { "COTP Segments", "cotp.segments", FT_NONE, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},
    { &hf_cotp_reassembled_in,
      { "Reassembled COTP in frame", "cotp.reassembled_in",
        FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "This COTP packet is reassembled in this frame", HFILL }},
    { &hf_cotp_reassembled_length,
      { "Reassembled COTP length", "cotp.reassembled.length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "The total length of the reassembled payload", HFILL }},
/* ISO DP 8073 i13.3.4(a) Source and destination TSAPs are defined as
   identifiers of unspecified type and length.
   Some implementations of COTP use printable strings, others use raw bytes.
   We always add both representations to the tree; one will always be hidden
   depending on the tsap display preference */
    { &hf_cotp_vp_src_tsap,
      { "Source TSAP", "cotp.src-tsap", FT_STRING, BASE_NONE,
        NULL, 0x0, "Calling TSAP", HFILL }},
    { &hf_cotp_vp_src_tsap_bytes,
      { "Source TSAP", "cotp.src-tsap-bytes", FT_BYTES, BASE_NONE,
        NULL, 0x0, "Calling TSAP (bytes representation)", HFILL }},
    { &hf_cotp_vp_dst_tsap,
      { "Destination TSAP", "cotp.dst-tsap", FT_STRING, BASE_NONE,
        NULL, 0x0, "Called TSAP", HFILL }},
    { &hf_cotp_vp_dst_tsap_bytes,
      { "Destination TSAP", "cotp.dst-tsap-bytes", FT_BYTES, BASE_NONE,
        NULL, 0x0, "Called TSAP (bytes representation)", HFILL }},
      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_cotp_parameter_code, { "Parameter code", "cotp.parameter_code", FT_UINT8, BASE_HEX, VALS(tp_vpart_type_vals), 0x0, NULL, HFILL }},
      { &hf_cotp_parameter_length, { "Parameter length", "cotp.parameter_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_parameter_value, { "Parameter value", "cotp.parameter_value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_atn_extended_checksum16, { "ATN extended checksum", "cotp.atn_extended_checksum", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_atn_extended_checksum32, { "ATN extended checksum", "cotp.atn_extended_checksum", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_ack_time, { "Ack time (ms)", "cotp.ack_time", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_res_error_rate_target_value, { "Residual error rate, target value", "cotp.res_error_rate.target_value", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_res_error_rate_min_accept, { "Residual error rate, minimum acceptable", "cotp.res_error_rate.min_accept", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_res_error_rate_tdsu, { "Residual error rate, TSDU size of interest", "cotp.res_error_rate.tdsu", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_vp_priority, { "Priority", "cotp.vp_priority", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_transit_delay_targ_calling_called, { "Transit delay, target value, calling-called (ms)", "cotp.transit_delay.targ_calling_called", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_transit_delay_max_accept_calling_called, { "Transit delay, maximum acceptable, calling-called (ms)", "cotp.transit_delay.max_accept_calling_called", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_transit_delay_targ_called_calling, { "Transit delay, target value, called-calling (ms)", "cotp.transit_delay.targ_called_calling", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_transit_delay_max_accept_called_calling, { "Transit delay, maximum acceptable, called-calling (ms)", "cotp.transit_delay.max_accept_called_calling", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_max_throughput_targ_calling_called, { "Maximum throughput, target value, calling-called (o/s)", "cotp.max_throughput.targ_calling_called", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_max_throughput_min_accept_calling_called, { "Maximum throughput, minimum acceptable, calling-called (o/s)", "cotp.max_throughput.min_accept_calling_called", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_max_throughput_targ_called_calling, { "Maximum throughput, target value, called-calling (o/s)", "cotp.max_throughput.targ_called_calling", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_max_throughput_min_accept_called_calling, { "Maximum throughput, minimum acceptable, called-calling (o/s)", "cotp.max_throughput.min_accept_called_calling", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_avg_throughput_targ_calling_called, { "Average throughput, target value, calling-called (o/s)", "cotp.avg_throughput.targ_calling_called", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_avg_throughput_min_accept_calling_called, { "Average throughput, minimum acceptable, calling-called (o/s)", "cotp.avg_throughput.min_accept_calling_called", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_avg_throughput_targ_called_calling, { "Average throughput, target value, called-calling (o/s)", "cotp.avg_throughput.targ_called_calling", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_avg_throughput_min_accept_called_calling, { "Average throughput, minimum acceptable, called-calling (o/s)", "cotp.avg_throughput.min_accept_called_calling", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_sequence_number, { "Sequence number", "cotp.sequence_number", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_reassignment_time, { "Reassignment time (secs)", "cotp.reassignment_time", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_lower_window_edge, { "Lower window edge", "cotp.lower_window_edge", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_credit, { "Credit", "cotp.credit", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_tpdu_size, { "TPDU size", "cotp.tpdu_size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_checksum, { "Checksum", "cotp.checksum", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_vp_version_nr, { "Version", "cotp.vp_version_nr", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_network_expedited_data, { "Use of network expedited data", "cotp.network_expedited_data", FT_BOOLEAN, 8, TFS(&tfs_used_notused), 0x08, NULL, HFILL }},
      { &hf_cotp_vp_opt_sel_class1_use, { "Use", "cotp.vp_opt_sel_class1_use", FT_BOOLEAN, 8, TFS(&tfs_vp_opt_sel_class1_use), 0x04, NULL, HFILL }},
      { &hf_cotp_use_16_bit_checksum, { "16 bit checksum", "cotp.use_16_bit_checksum", FT_BOOLEAN, 8, TFS(&tfs_used_notused), 0x02, NULL, HFILL }},
      { &hf_cotp_transport_expedited_data_transfer, { "Transport expedited data transfer", "cotp.transport_expedited_data_transfer", FT_BOOLEAN, 8, TFS(&tfs_used_notused), 0x01, NULL, HFILL }},
      { &hf_cotp_preferred_maximum_tpdu_size, { "Preferred maximum TPDU size", "cotp.preferred_maximum_tpdu_size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_inactivity_timer, { "Inactivity timer (ms)", "cotp.inactivity_timer", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_cause, { "Cause", "cotp.cause", FT_UINT8, BASE_DEC, VALS(cotp_cause_vals), 0x0, NULL, HFILL }},
      { &hf_cotp_segment_data, { "COTP segment data", "cotp.segment_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_credit_cdt, { "Credit", "cotp.credit", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cotp_reject_cause, { "Reject cause", "cotp.reject_cause", FT_UINT8, BASE_DEC, VALS(cotp_reject_vals), 0x0, NULL, HFILL }},
  };
  static gint *ett[] = {
    &ett_cotp,
    &ett_cotp_segment,
    &ett_cotp_segments
  };
  static ei_register_info ei[] = {
      { &ei_cotp_disconnect_request, { "cotp.disconnect_request", PI_SEQUENCE, PI_CHAT, "Disconnect Request(DR): 0x%x -> 0x%x", EXPFILL }},
      { &ei_cotp_reject, { "cotp.reject", PI_SEQUENCE, PI_NOTE, "Reject(RJ): -> 0x%x", EXPFILL }},
      { &ei_cotp_connection, { "cotp.connection", PI_SEQUENCE, PI_CHAT, "Connection %s: 0x%x -> 0x%x", EXPFILL }},
      { &ei_cotp_disconnect_confirm, { "cotp.disconnect_confirm", PI_SEQUENCE, PI_CHAT, "Disconnect Confirm(DC): 0x%x -> 0x%x", EXPFILL }},
      { &ei_cotp_multiple_tpdus, { "cotp.multiple_tpdus", PI_SEQUENCE, PI_NOTE, "Multiple TPDUs in one packet", EXPFILL }},
      { &ei_cotp_preferred_maximum_tpdu_size, { "cotp.preferred_maximum_tpdu_size.invalid", PI_PROTOCOL, PI_WARN, "Preferred maximum TPDU size: bogus length", EXPFILL }},
  };

  module_t *cotp_module;
  expert_module_t* expert_cotp;

  proto_cotp = proto_register_protocol(PROTO_STRING_COTP, "COTP", "cotp");
  proto_register_field_array(proto_cotp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_cotp = expert_register_protocol(proto_cotp);
  expert_register_field_array(expert_cotp, ei, array_length(ei));
  cotp_module = prefs_register_protocol(proto_cotp, NULL);

  prefs_register_bool_preference(cotp_module, "reassemble",
                                 "Reassemble segmented COTP datagrams",
                                 "Whether segmented COTP datagrams should be "
                                 "reassembled. To use this option, you must "
                                 "also enable \"Allow subdissectors to "
                                 "reassemble TCP streams\" in the TCP "
                                 "protocol settings.",
                                 &cotp_reassemble);

  prefs_register_enum_preference(cotp_module, "tsap_display",
                                 "Display TSAPs as strings or bytes",
                                 "How TSAPs should be displayed",
                                 &tsap_display, tsap_display_options, FALSE);

  prefs_register_bool_preference(cotp_module, "decode_atn", "Decode ATN TPDUs",
                                 "Whether to decode OSI TPDUs with ATN "
                                 "(Aereonautical Telecommunications Network) "
                                 "extensions. To use this option, you must "
                                 "also enable \"Always try to decode NSDU as "
                                 "transport PDUs\" in the CLNP protocol "
                                 "settings.", &cotp_decode_atn);

  /* For handling protocols hijacking the variable part of CR or CC PDUs */
  cotp_cr_heur_subdissector_list = register_heur_dissector_list("cotp_cr", proto_cotp);
  cotp_cc_heur_subdissector_list = register_heur_dissector_list("cotp_cc", proto_cotp);

  /* subdissector code in inactive subset */
  cotp_is_heur_subdissector_list = register_heur_dissector_list("cotp_is", proto_cotp);

  /* other COTP/ISO 8473 subdissectors */
  cotp_heur_subdissector_list = register_heur_dissector_list("cotp", proto_cotp);

  /* XXX - what about CLTP and proto_cltp? */
  register_dissector("ositp", dissect_ositp, proto_cotp);
  register_dissector("ositp_inactive", dissect_ositp_inactive, proto_cotp);

  register_init_routine(cotp_reassemble_init);
  register_cleanup_routine(cotp_reassemble_cleanup);
}

void proto_register_cltp(void)
{
  static hf_register_info hf[] = {
    { &hf_cltp_li,
      { "Length", "cltp.li", FT_UINT8, BASE_DEC, NULL, 0x0,
        "Length Indicator, length of this header", HFILL}},
    { &hf_cltp_type,
      { "PDU Type", "cltp.type", FT_UINT8, BASE_HEX,
        VALS(cltp_tpdu_type_abbrev_vals), 0x0, NULL, HFILL}}
  };
  static gint *ett[] = {
    &ett_cltp
  };

  proto_cltp = proto_register_protocol(PROTO_STRING_CLTP, "CLTP", "cltp");
  proto_register_field_array(proto_cltp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  cltp_heur_subdissector_list = register_heur_dissector_list("cltp", proto_cltp);
}

void
proto_reg_handoff_cotp(void)
{
  dissector_handle_t ositp_handle;

  ositp_handle = find_dissector("ositp");
  dissector_add_uint("ip.proto", IP_PROTO_TP, ositp_handle);

  rdp_cr_handle = find_dissector("rdp_cr");
  rdp_cc_handle = find_dissector("rdp_cc");

  proto_clnp = proto_get_id_by_filter_name("clnp");
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
