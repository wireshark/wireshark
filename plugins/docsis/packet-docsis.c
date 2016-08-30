/* packet-docsis.c
 * Routines for docsis dissection
 * Copyright 2002, Anand V. Narwani <anand[AT]narwani.org>
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


/* This code is based on the DOCSIS 1.1 specification available at:
 * http://www.cablelabs.com/wp-content/uploads/specdocs/CM-SP-RFIv1.1-C01-050907.pdf
 *
 * DOCSIS Captures can be facilitated using the Cable Monitor Feature
 * available on Cisco Cable Modem Termination Systems :
 * http://www.cisco.com/univercd/cc/td/doc/product/cable/cab_rout/cmtsfg/ufg_cmon.htm
 *
 * This dissector depends on the presence of a DOCSIS enapsulation type.
 * There is no simple way to distinguish DOCSIS Frames from Ethernet frames,
 * since the frames are copied from the RF interface on the CMTS to
 * a Fast Ethernet interface; thus a preference was needed to enable
 * the DOCSIS encapsulation type.
 *
 * Libpcap 0.7 and later allow a link-layer header type to be specified for
 * some interfaces on some platforms; for Ethernet interfaces, they allow
 * DOCSIS to be specified.  If an Ethernet capture is done with a link-layer
 * type of DOCSIS, the file will have a link-layer header type of DLT_DOCSIS;
 * Wireshark will treat the frames in that capture as DOCSIS frames.
 */

#include "config.h"

#include <epan/packet.h>
#include <wiretap/wtap.h>
#include <epan/exceptions.h>

void proto_register_docsis(void);
void proto_reg_handoff_docsis(void);

#define FCTYPE_PACKET 0x00
#define FCTYPE_ATMPDU 0x01
#define FCTYPE_RESRVD 0x02
#define FCTYPE_MACSPC 0x03

#define EH_NULL_CONFIG 0
#define EH_REQUEST 1
#define EH_ACK_REQ 2
#define EH_BP_UP 3
#define EH_BP_DOWN 4
#define EH_SFLOW_HDR_DOWN 5
#define EH_SFLOW_HDR_UP 6
#define EH_BP_UP2 7
#define EH_DS_SERVICE 8
#define EH_RESERVED_9 9
#define EH_RESERVED_10 10
#define EH_RESERVED_11 11
#define EH_RESERVED_12 12
#define EH_RESERVED_13 13
#define EH_RESERVED_14 14
#define EH_EXTENDED 15

/* Initialize the protocol and registered fields */
static int proto_docsis = -1;
static int hf_docsis_fctype = -1;
static int hf_docsis_machdr_fcparm = -1;
static int hf_docsis_fcparm = -1;
static int hf_docsis_ehdron = -1;
static int hf_docsis_concat_cnt = -1;
static int hf_docsis_macparm = -1;
static int hf_docsis_ehdrlen = -1;
static int hf_docsis_len = -1;
static int hf_docsis_eh_type = -1;
static int hf_docsis_eh_len = -1;
static int hf_docsis_eh_val = -1;
static int hf_docsis_frag_rsvd = -1;
static int hf_docsis_frag_first = -1;
static int hf_docsis_frag_last = -1;
static int hf_docsis_frag_seq = -1;
static int hf_docsis_sid = -1;
static int hf_docsis_mini_slots = -1;
static int hf_docsis_requested_size = -1;
static int hf_docsis_hcs = -1;
static int hf_docsis_bpi_en = -1;
static int hf_docsis_toggle_bit = -1;
static int hf_docsis_key_seq = -1;
static int hf_docsis_ehdr_ver = -1;
static int hf_docsis_said = -1;
static int hf_docsis_ehdr_phsi = -1;
static int hf_docsis_ehdr_qind = -1;
static int hf_docsis_ehdr_grants = -1;
static int hf_docsis_reserved = -1;
static int hf_docsis_ehdr_ds_traffic_pri = -1;
static int hf_docsis_ehdr_ds_seq_chg_cnt = -1;
static int hf_docsis_ehdr_ds_dsid = -1;
static int hf_docsis_ehdr_ds_pkt_seq_num = -1;
static int hf_docsis_ehdr_bpup2_bpi_en = -1;
static int hf_docsis_ehdr_bpup2_toggle_bit = -1;
static int hf_docsis_ehdr_bpup2_key_seq = -1;
static int hf_docsis_ehdr_bpup2_ver = -1;
static int hf_docsis_ehdr_bpup2_sid = -1;
static dissector_handle_t docsis_handle;
static dissector_handle_t eth_withoutfcs_handle;
static dissector_handle_t docsis_mgmt_handle;
#if 0
static dissector_table_t docsis_dissector_table;
#endif

/* Initialize the subtree pointers */
static gint ett_docsis = -1;
static gint ett_ehdr = -1;

static const value_string fctype_vals[] = {
  {FCTYPE_PACKET, "Packet PDU"},
  {FCTYPE_ATMPDU, "ATM PDU"},
  {FCTYPE_RESRVD, "Reserved"},
  {FCTYPE_MACSPC, "MAC Specific"},
  {0, NULL}
};

static const value_string eh_type_vals[] = {
  {0,                 "NULL Configuration Parameter"},
  {EH_REQUEST,        "Request"},
  {EH_ACK_REQ,        "Acknowledgement Requested"},
  {EH_BP_UP,          "Upstream Privacy Element"},
  {EH_BP_DOWN,        "Downstream  Privacy Element"},
  {EH_SFLOW_HDR_UP,   "Service Flow EH; PHS Header Upstream"},
  {EH_SFLOW_HDR_DOWN, "Service Flow EH; PHS Header Downstream"},
  {EH_BP_UP2,         "Upstream Privacy with Multi Channel"},
  {EH_DS_SERVICE,     "Downstream Service"},
  {EH_RESERVED_9,     "Reserved"},
  {EH_RESERVED_10,    "Reserved"},
  {EH_RESERVED_10,    "Reserved"},
  {EH_RESERVED_11,    "Reserved"},
  {EH_RESERVED_12,    "Reserved"},
  {EH_RESERVED_13,    "Reserved"},
  {EH_RESERVED_14,    "Reserved"},
  {EH_EXTENDED,       "Extended"},
  {0, NULL}
};

static const value_string fcparm_vals[] = {
  {0x0, "Timing Header"},
  {0x1, "Mac Management Message"},
  {0x2, "Request Frame"},
  {0x3, "Fragmentation Header"},
  {0x4, "Queue Depth-based Request Frame"},
  {0x1C, "Concatenation Header"},
  {0, NULL}
};

static const true_false_string ehdron_tfs = {
  "Extended Header Present",
  "Extended Header Absent"
};

static const true_false_string ena_dis_tfs = {
  "Enabled",
  "Disabled"
};

static const true_false_string qind_tfs = {
  "Rate overrun",
  "Rate non-overrun"
};

static const true_false_string odd_even_tfs = {
  "Odd Key",
  "Even Key",
};

/* Dissection */
/* Code to Dissect the extended header */
static void
dissect_ehdr (tvbuff_t * tvb, proto_tree * tree, gboolean isfrag)
{
  proto_tree *ehdr_tree;
  proto_item *item;
  gint ehdrlen;
  int pos;
  guint8 type;
  guint8 len;
  guint8 val;
  guint8 mini_slots;
  guint16 sid;

  ehdrlen = tvb_get_guint8 (tvb, 1);
  pos = 4;

  ehdr_tree = proto_tree_add_subtree(tree, tvb, pos, ehdrlen, ett_ehdr, NULL, "Extended Header");
  while (pos < ehdrlen + 4)
    {
      type = (tvb_get_guint8 (tvb, pos) & 0xF0);
      len = (tvb_get_guint8 (tvb, pos) & 0x0F);
      if ((((type >> 4) & 0x0F)== 6) && (len == 2))
        {
          proto_tree_add_uint_format_value(ehdr_tree, hf_docsis_eh_type, tvb, pos, 1, 0x60, "Unsolicited Grant Sync EHDR Sub-Element");
        }
      else
        proto_tree_add_item (ehdr_tree, hf_docsis_eh_type, tvb, pos, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item (ehdr_tree, hf_docsis_eh_len, tvb, pos, 1, ENC_BIG_ENDIAN);
      switch ((type >> 4) & 0x0F)
        {
        case EH_REQUEST:
          if (len == 3)
            {
              mini_slots = tvb_get_guint8 (tvb, pos + 1);
              sid = tvb_get_ntohs (tvb, pos + 2);
              proto_tree_add_uint (ehdr_tree, hf_docsis_mini_slots, tvb,
                                   pos + 1, 1, mini_slots);
              proto_tree_add_uint (ehdr_tree, hf_docsis_sid, tvb, pos + 2, 2,
                                   sid);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case EH_ACK_REQ:
          if (len == 2)
            {
              sid = tvb_get_ntohs (tvb, pos + 1);
              proto_tree_add_uint (ehdr_tree, hf_docsis_sid, tvb, pos + 2, 2,
                                   sid);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case EH_BP_UP:
          proto_tree_add_item (ehdr_tree, hf_docsis_key_seq, tvb, pos + 1, 1,
                               ENC_BIG_ENDIAN);
          proto_tree_add_item (ehdr_tree, hf_docsis_ehdr_ver, tvb, pos + 1, 1,
                               ENC_BIG_ENDIAN);
          proto_tree_add_item (ehdr_tree, hf_docsis_bpi_en, tvb, pos + 2, 1,
                               ENC_BIG_ENDIAN);
          proto_tree_add_item (ehdr_tree, hf_docsis_toggle_bit, tvb, pos + 2,
                               1, ENC_BIG_ENDIAN);
          proto_tree_add_item (ehdr_tree, hf_docsis_sid, tvb, pos + 2, 2,
                               ENC_BIG_ENDIAN);
          proto_tree_add_item (ehdr_tree, hf_docsis_mini_slots, tvb, pos + 4,
                               1, ENC_BIG_ENDIAN);
          if (isfrag)
            {
              proto_tree_add_item (ehdr_tree, hf_docsis_frag_rsvd, tvb, pos+5,
                                  1, ENC_BIG_ENDIAN);
              proto_tree_add_item (ehdr_tree, hf_docsis_frag_first, tvb, pos+5,
                                  1, ENC_BIG_ENDIAN);
              proto_tree_add_item (ehdr_tree, hf_docsis_frag_last, tvb, pos+5,
                                  1, ENC_BIG_ENDIAN);
              proto_tree_add_item (ehdr_tree, hf_docsis_frag_seq, tvb, pos+5,
                                  1, ENC_BIG_ENDIAN);
            }
          break;
        case EH_BP_DOWN:
          proto_tree_add_item (ehdr_tree, hf_docsis_key_seq, tvb, pos + 1, 1,
                               ENC_BIG_ENDIAN);
          proto_tree_add_item (ehdr_tree, hf_docsis_ehdr_ver, tvb, pos + 1, 1,
                               ENC_BIG_ENDIAN);
          proto_tree_add_item (ehdr_tree, hf_docsis_bpi_en, tvb, pos + 2, 1,
                               ENC_BIG_ENDIAN);
          proto_tree_add_item (ehdr_tree, hf_docsis_toggle_bit, tvb, pos + 2,
                               1, ENC_BIG_ENDIAN);
          proto_tree_add_item (ehdr_tree, hf_docsis_said, tvb, pos + 2, 2,
                               ENC_BIG_ENDIAN);
          proto_tree_add_item (ehdr_tree, hf_docsis_reserved, tvb, pos + 4, 1,
                               ENC_BIG_ENDIAN);
          break;
        case EH_SFLOW_HDR_DOWN:
        case EH_SFLOW_HDR_UP:
          val = tvb_get_guint8 (tvb, pos+1);
          item = proto_tree_add_item(ehdr_tree, hf_docsis_ehdr_phsi, tvb, pos+1, 1, ENC_BIG_ENDIAN);
          if (val == 0)
          {
            proto_item_append_text(item, " (No PHS on current packet)" );
          }

          if (len == 2)
          {
            proto_tree_add_item (ehdr_tree, hf_docsis_ehdr_qind, tvb, pos+2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (ehdr_tree, hf_docsis_ehdr_grants, tvb, pos+2, 1, ENC_BIG_ENDIAN);
          }
          break;
        case EH_BP_UP2:
          proto_tree_add_item (ehdr_tree, hf_docsis_ehdr_bpup2_key_seq, tvb, pos + 1, 1,
                               ENC_BIG_ENDIAN);
          proto_tree_add_item (ehdr_tree, hf_docsis_ehdr_bpup2_ver, tvb, pos + 1, 1,
                               ENC_BIG_ENDIAN);
          proto_tree_add_item (ehdr_tree, hf_docsis_ehdr_bpup2_bpi_en, tvb, pos + 2, 1,
                               ENC_BIG_ENDIAN);
          proto_tree_add_item (ehdr_tree, hf_docsis_ehdr_bpup2_toggle_bit, tvb, pos + 2,
                               1, ENC_BIG_ENDIAN);
          proto_tree_add_item (ehdr_tree, hf_docsis_ehdr_bpup2_sid, tvb, pos + 2, 2,
                               ENC_BIG_ENDIAN);
          break;
        case EH_DS_SERVICE:
          proto_tree_add_item(ehdr_tree, hf_docsis_ehdr_ds_traffic_pri, tvb, pos+1, 1, ENC_BIG_ENDIAN);

          if (len == 3)
          {
            proto_tree_add_item (ehdr_tree, hf_docsis_ehdr_ds_dsid, tvb, pos+1, 3, ENC_BIG_ENDIAN);
          }

          if (len == 5)
          {
            proto_tree_add_item (ehdr_tree, hf_docsis_ehdr_ds_seq_chg_cnt, tvb, pos+1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (ehdr_tree, hf_docsis_ehdr_ds_dsid, tvb, pos+1, 3, ENC_BIG_ENDIAN);
            proto_tree_add_item (ehdr_tree, hf_docsis_ehdr_ds_pkt_seq_num, tvb, pos+4, 2, ENC_BIG_ENDIAN);
          }

          break;
        default:
          if (len > 0)
            proto_tree_add_item (ehdr_tree, hf_docsis_eh_val, tvb, pos + 1,
                                  len, ENC_NA);
        }
      pos += len + 1;
    }

  return;
}


static int
dissect_docsis (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  guint8 fc;
  guint8 fctype;
  guint8 fcparm;
  guint8 ehdron;
  gint mac_parm;
  gint hdrlen;
  guint16 len_sid;
  tvbuff_t *next_tvb, *mgt_tvb;
  gint pdulen, captured_length;
  gint framelen;
  gboolean isfrag = FALSE;
  gint oldconcatlen;

  proto_item *ti;
  proto_tree *docsis_tree;
  /* concatlen and concatpos are declared static to allow for recursive calls to
   * the dissect_docsis routine when dissecting Concatenated frames
   */
  static gint concatlen;
  static gint concatpos;

  /* Extract important fields */
  fc = tvb_get_guint8 (tvb, 0); /* Frame Control Byte */
  fctype = (fc >> 6) & 0x03;    /* Frame Control Type:  2 MSB Bits */
  fcparm = (fc >> 1) & 0x1F;    /* Frame Control Parameter: Next 5 Bits */
  ehdron = (fc & 0x01);         /* Extended Header Bit: LSB */

  if (fcparm == 0x04) {
    mac_parm = tvb_get_ntohs (tvb, 1);
    len_sid = tvb_get_ntohs (tvb, 3);
  } else {
    mac_parm = tvb_get_guint8 (tvb, 1);
    len_sid = tvb_get_ntohs (tvb, 2);
  }

  /* set Header length based on presence of Extended header */
  if (ehdron == 0x00) {
    if (fcparm == 0x04)
      hdrlen = 7;
    else
      hdrlen = 6;
  } else {
    hdrlen = 6 + mac_parm;
  }

  /* Captured PDU Length is based on the length of the header */
  captured_length = tvb_captured_length_remaining (tvb, hdrlen);

  /* If this is a Request Frame, then pdulen is 0 and framelen is 6 */
  if ((fctype == FCTYPE_MACSPC) && (fcparm == 0x02 || fcparm == 0x04))
    {
      pdulen = 0;
      framelen = 6;
    }
  else
    {
      framelen = 6 + len_sid;
      pdulen = len_sid - (mac_parm + 2);
    }

  /* if this is a concatenated frame setup the length of the concatenated
   * frame and set the position to the first byte of the first frame */
  if ((fctype == FCTYPE_MACSPC) && (fcparm == 0x1c))
    {
      concatlen = len_sid;
      concatpos = 6;
    }

  /* Make entries in Protocol column and Info column on summary display */
  col_set_str (pinfo->cinfo, COL_PROTOCOL, "DOCSIS");

  switch (fctype)
    {
      case FCTYPE_PACKET:
        col_set_str (pinfo->cinfo, COL_INFO, "Packet PDU");
        break;
      case FCTYPE_ATMPDU:
        col_set_str (pinfo->cinfo, COL_INFO, "ATM PDU");
        break;
      case FCTYPE_RESRVD:
        col_set_str (pinfo->cinfo, COL_INFO, "Reserved PDU");
        break;
      case FCTYPE_MACSPC:
        if (fcparm == 0x02)
          col_add_fstr (pinfo->cinfo, COL_INFO,
                        "Request Frame SID = %u Mini Slots = %u", len_sid,
                        mac_parm);
        else if (fcparm == 0x04)
          col_add_fstr (pinfo->cinfo, COL_INFO,
                        "Request Frame SID = %u Bytes Requested = %u", len_sid,
                        mac_parm);
        else if (fcparm == 0x03)
          col_set_str (pinfo->cinfo, COL_INFO, "Fragmented Frame");
        else
          col_set_str (pinfo->cinfo, COL_INFO, "Mac Specific");
        break;
    }  /* switch */

  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree)
    {
      ti = proto_tree_add_protocol_format (tree, proto_docsis, tvb, 0,
                                           hdrlen, "DOCSIS");
      docsis_tree = proto_item_add_subtree (ti, ett_docsis);

      /* add an item to the subtree, see section 1.6 for more information */
      proto_tree_add_item (docsis_tree, hf_docsis_fctype, tvb, 0, 1, ENC_BIG_ENDIAN);
      switch (fctype)
        {
          case FCTYPE_PACKET:
          case FCTYPE_ATMPDU:
          case FCTYPE_RESRVD:
            proto_tree_add_item (docsis_tree, hf_docsis_fcparm, tvb, 0, 1,
                                 ENC_BIG_ENDIAN);
            proto_tree_add_item (docsis_tree, hf_docsis_ehdron, tvb, 0, 1,
                                 ENC_BIG_ENDIAN);
            if (ehdron == 0x01)
              {
                proto_tree_add_item (docsis_tree, hf_docsis_ehdrlen, tvb, 1, 1,
                                     ENC_BIG_ENDIAN);
                proto_tree_add_item (docsis_tree, hf_docsis_len, tvb, 2, 2,
                                     ENC_BIG_ENDIAN);
                dissect_ehdr (tvb, docsis_tree, isfrag);
                proto_tree_add_item (docsis_tree, hf_docsis_hcs, tvb,
                                     4 + mac_parm, 2, ENC_BIG_ENDIAN);
              }
            else
              {
                proto_tree_add_item (docsis_tree, hf_docsis_macparm, tvb, 1, 1,
                                     ENC_BIG_ENDIAN);
                proto_tree_add_item (docsis_tree, hf_docsis_len, tvb, 2, 2,
                                     ENC_BIG_ENDIAN);
                proto_tree_add_item (docsis_tree, hf_docsis_hcs, tvb, 4, 2,
                                     ENC_BIG_ENDIAN);
              }
            break;
          case FCTYPE_MACSPC:
            proto_tree_add_item (docsis_tree, hf_docsis_machdr_fcparm, tvb, 0,
                                 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (docsis_tree, hf_docsis_ehdron, tvb, 0, 1,
                                 ENC_BIG_ENDIAN);
            /* Decode for a Request Frame.  No extended header */
            if (fcparm == 0x02)
              {
                proto_tree_add_uint (docsis_tree, hf_docsis_mini_slots, tvb, 1,
                                     1, mac_parm);
                proto_tree_add_uint (docsis_tree, hf_docsis_sid, tvb, 2, 2,
                                     len_sid);
                proto_tree_add_item (docsis_tree, hf_docsis_hcs, tvb, 4, 2,
                                     ENC_BIG_ENDIAN);
                break;
              }
            /* Decode for a Queue-depth Based Request */
            if (fcparm == 0x04)
              {
                proto_tree_add_uint (docsis_tree, hf_docsis_requested_size, tvb, 1,
                                     2, mac_parm);
                proto_tree_add_uint (docsis_tree, hf_docsis_sid, tvb, 3, 2,
                                     len_sid);
                proto_tree_add_item (docsis_tree, hf_docsis_hcs, tvb, 5, 2,
                                     ENC_BIG_ENDIAN);
                break;
              }
            /* Check if this is a fragmentation header */
            if (fcparm == 0x03)
              {
                isfrag = TRUE;
              }
            /* Decode for a Concatenated Header.  No Extended Header */
            if (fcparm == 0x1c)
              {
                proto_item_append_text (ti, " (Concatenated Header)");
                proto_tree_add_item (docsis_tree, hf_docsis_concat_cnt, tvb, 1,
                                     1, ENC_BIG_ENDIAN);
                proto_tree_add_item (docsis_tree, hf_docsis_len, tvb, 2, 2,
                                     ENC_BIG_ENDIAN);
                proto_tree_add_item (docsis_tree, hf_docsis_hcs, tvb, 4, 2,
                                     ENC_BIG_ENDIAN);
                break;
              }
            /* If Extended header is present then decode it */
            if (ehdron == 0x01)
              {
                proto_tree_add_item (docsis_tree, hf_docsis_ehdrlen, tvb, 1, 1,
                                     ENC_BIG_ENDIAN);
                proto_tree_add_item (docsis_tree, hf_docsis_len, tvb, 2, 2,
                                     ENC_BIG_ENDIAN);
                dissect_ehdr (tvb, docsis_tree, isfrag);
                proto_tree_add_item (docsis_tree, hf_docsis_hcs, tvb,
                                     4 + mac_parm, 2, ENC_BIG_ENDIAN);
                break;
              }
            /* default case for all other Mac Frame Types */
            proto_tree_add_item (docsis_tree, hf_docsis_macparm, tvb, 1, 1,
                                 ENC_BIG_ENDIAN);
            proto_tree_add_item (docsis_tree, hf_docsis_len, tvb, 2, 2,
                                 ENC_BIG_ENDIAN);
            proto_tree_add_item (docsis_tree, hf_docsis_hcs, tvb, 4, 2, ENC_BIG_ENDIAN);
            break;
        }
    }

  switch (fctype)
    {
      case FCTYPE_PACKET:
      case FCTYPE_RESRVD:
        if (pdulen >= 0)
          {
            if (pdulen > 0)
              {
                next_tvb = tvb_new_subset (tvb, hdrlen, captured_length, pdulen);
                call_dissector (eth_withoutfcs_handle, next_tvb, pinfo, tree);
              }
            if (concatlen > 0)
              {
                concatlen = concatlen - framelen;
                concatpos += framelen;
              }
          }
        break;
      case FCTYPE_MACSPC:
        switch (fcparm)
          {
            case 0x00:
            case 0x01:
              if (pdulen > 0)
                {
                  mgt_tvb = tvb_new_subset (tvb, hdrlen, captured_length, pdulen);
                  call_dissector (docsis_mgmt_handle, mgt_tvb, pinfo, tree);
                }
              if (concatlen > 0)
                {
                  concatlen = concatlen - framelen;
                  concatpos += framelen;
                }
              break;
            case 0x02:
              /* Don't do anything for a Request Frame */
              break;
            case 0x03:
              /* For Fragmentation Frames simply dissect using the data
               * dissector as we don't handle them yet
               */
              if (pdulen > 0)
                {
                  mgt_tvb = tvb_new_subset (tvb, hdrlen, captured_length, pdulen);
                  call_data_dissector(mgt_tvb, pinfo, tree);
                }
              if (concatlen > 0)
                {
                  concatlen = concatlen - framelen;
                  concatpos += framelen;
                }
              break;
            case 0x1c:
              /* call the docsis dissector on the same frame
               * to dissect DOCSIS frames within the concatenated
               * frame.  concatpos and concatlen are declared
               * static and are decremented and incremented
               * respectively when the inner
               * docsis frames are dissected. */
              while (concatlen > 0)
                {
                  oldconcatlen = concatlen;
                  next_tvb = tvb_new_subset (tvb, concatpos, -1, concatlen);
                  call_dissector (docsis_handle, next_tvb, pinfo, tree);
                  if (oldconcatlen <= concatlen)
                    THROW(ReportedBoundsError);
                }
              concatlen = 0;
              concatpos = 0;
              col_set_str(pinfo->cinfo, COL_INFO, "Concatenated Frame");
              break;
          }
        break;
    }
    return tvb_captured_length(tvb);
}


/* Register the protocol with Wireshark */
void
proto_register_docsis (void)
{
  static hf_register_info hf[] = {
    {&hf_docsis_fctype,
     {"FCType", "docsis.fctype",
      FT_UINT8, BASE_HEX, VALS (fctype_vals), 0xC0,
      "Frame Control Type", HFILL}
    },
    {&hf_docsis_fcparm,
     {"FCParm", "docsis.fcparm",
      FT_UINT8, BASE_DEC, NULL, 0x3E,
      "Parameter Field", HFILL}
    },
    {&hf_docsis_machdr_fcparm,
     {"FCParm", "docsis.fcparm",
      FT_UINT8, BASE_HEX, VALS (fcparm_vals), 0x3E,
      "Parameter Field", HFILL}
    },
    {&hf_docsis_ehdron,
     {"EHDRON", "docsis.ehdron",
      FT_BOOLEAN, 8, TFS (&ehdron_tfs), 0x01,
      "Extended Header Presence", HFILL}
    },
    {&hf_docsis_macparm,
     {"MacParm", "docsis.macparm",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "Mac Parameter Field", HFILL}
    },
    {&hf_docsis_concat_cnt,
     {"Number of Concatenated Frames", "docsis.concat_cnt",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ehdrlen,
     {"Extended Header Length (bytes)", "docsis.ehdrlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_len,
     {"Length of the MAC frame (bytes)", "docsis.len",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Length of the MAC frame, not counting the fixed-length MAC header", HFILL}
    },
    {&hf_docsis_eh_type,
     {"Type", "docsis.ehdr.type",
      FT_UINT8, BASE_DEC, VALS (eh_type_vals), 0xF0,
      "TLV Type", HFILL}
    },
    {&hf_docsis_eh_len,
     {"Length", "docsis.ehdr.len",
      FT_UINT8, BASE_DEC, NULL, 0x0F,
      "TLV Len", HFILL}
    },
    {&hf_docsis_eh_val,
     {"Value", "docsis.ehdr.value",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "TLV Value", HFILL}
    },
    {&hf_docsis_frag_rsvd,
     {"Reserved", "docsis.frag_rsvd",
      FT_UINT8, BASE_DEC, NULL, 0xC0,
      NULL, HFILL}
    },
    {&hf_docsis_frag_first,
     {"First Frame", "docsis.frag_first",
      FT_BOOLEAN, 8, NULL, 0x20,
      NULL, HFILL}
    },
    {&hf_docsis_frag_last,
     {"Last Frame", "docsis.frag_last",
      FT_BOOLEAN, 8, NULL, 0x10,
      NULL, HFILL}
    },
    {&hf_docsis_frag_seq,
     {"Fragmentation Sequence #", "docsis.frag_seq",
      FT_UINT8, BASE_DEC, NULL, 0x0F,
      "Fragmentation Sequence Number", HFILL}
    },
    {&hf_docsis_sid,
     {"SID", "docsis.ehdr.sid",
      FT_UINT16, BASE_DEC, NULL, 0x3FFF,
      "Service Identifier", HFILL}
    },
    {&hf_docsis_said,
     {"SAID", "docsis.ehdr.said",
      FT_UINT16, BASE_DEC, NULL, 0x3FFF,
      "Security Association Identifier", HFILL}
    },
    {&hf_docsis_reserved,
     {"Reserved", "docsis.ehdr.rsvd",
      FT_UINT8, BASE_HEX, NULL, 0x3FFF,
      "Reserved Byte", HFILL}
    },
    {&hf_docsis_mini_slots,
     {"MiniSlots", "docsis.ehdr.minislots",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Mini Slots Requested", HFILL}
    },
    {&hf_docsis_requested_size,
     {"Bytes Requested", "docsis.ehdr.reqsize",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_key_seq,
     {"Key Sequence", "docsis.ehdr.keyseq",
      FT_UINT8, BASE_DEC, NULL, 0xF0,
      NULL, HFILL}
    },
    {&hf_docsis_ehdr_ver,
     {"Version", "docsis.ehdr.ver",
      FT_UINT8, BASE_DEC, NULL, 0x0F,
      NULL, HFILL}
    },
    {&hf_docsis_ehdr_phsi,
     {"Payload Header Suppression Index", "docsis.ehdr.phsi",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ehdr_qind,
     {"Queue Indicator", "docsis.ehdr.qind",
      FT_BOOLEAN, 8, TFS(&qind_tfs), 0x80,
      NULL, HFILL}
    },
    {&hf_docsis_ehdr_grants,
     {"Active Grants", "docsis.ehdr.act_grants",
      FT_UINT8, BASE_DEC, NULL, 0x7F,
      NULL, HFILL}
    },
    {&hf_docsis_ehdr_bpup2_key_seq,
     {"Key Sequence", "docsis.ehdr.bpup2_keyseq",
      FT_UINT8, BASE_DEC, NULL, 0xF0,
      "NULL", HFILL}
    },
    {&hf_docsis_ehdr_bpup2_ver,
     {"Version", "docsis.ehdr.bpup2_ver",
      FT_UINT8, BASE_DEC, NULL, 0x0F,
      "NULL", HFILL}
    },
    {&hf_docsis_ehdr_bpup2_bpi_en,
     {"Encryption", "docsis.ehdr.bpup2_bpi_en",
      FT_BOOLEAN, 8, TFS (&ena_dis_tfs), 0x80,
      "BPI Enable", HFILL},
    },
    {&hf_docsis_ehdr_bpup2_toggle_bit,
     {"Toggle", "docsis.ehdr.bpup2_toggle_bit",
      FT_BOOLEAN, 8, TFS (&odd_even_tfs), 0x40,
      "NULL", HFILL},
    },
    {&hf_docsis_ehdr_bpup2_sid,
     {"SID", "docsis.ehdr.bpup2_sid",
      FT_UINT16, BASE_DEC, NULL, 0x3FFF,
      "Service Identifier", HFILL}
    },
    {&hf_docsis_ehdr_ds_traffic_pri,
     {"DS Traffic Priority", "docsis.ehdr.ds_traffic_pri",
      FT_UINT8, BASE_DEC, NULL, 0xE0,
      "NULL", HFILL}
    },
    {&hf_docsis_ehdr_ds_seq_chg_cnt,
     {"DS Sequence Change Count", "docsis.ehdr.ds_seq_chg_cnt",
      FT_UINT8, BASE_DEC, NULL, 0x10,
      "NULL", HFILL}
    },
    {&hf_docsis_ehdr_ds_dsid,
     {"DS DSID", "docsis.ehdr.ds_dsid",
      FT_UINT32, BASE_DEC, NULL, 0x0FFFFF,
      "NULL", HFILL}
    },
    {&hf_docsis_ehdr_ds_pkt_seq_num,
     {"DS Packet Sequence Number", "docsis.ehdr.ds_pkt_seq_num",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "NULL", HFILL}
    },
    {&hf_docsis_hcs,
     {"Header check sequence", "docsis.hcs",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL},
    },
    {&hf_docsis_bpi_en,
     {"Encryption", "docsis.bpi_en",
      FT_BOOLEAN, 8, TFS (&ena_dis_tfs), 0x80,
      "BPI Enable", HFILL},
    },
    {&hf_docsis_toggle_bit,
     {"Toggle", "docsis.toggle_bit",
      FT_BOOLEAN, 8, TFS (&odd_even_tfs), 0x40,
      NULL, HFILL},
    },

  };

  static gint *ett[] = {
    &ett_docsis,
    &ett_ehdr,
  };

  proto_docsis = proto_register_protocol ("DOCSIS 1.1", "DOCSIS", "docsis");

  proto_register_field_array (proto_docsis, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

#if 0
  docsis_dissector_table = register_dissector_table ("docsis",
                                                     "DOCSIS Encapsulation Type", proto_docsis,
                                                     FT_UINT8, BASE_DEC);
#endif

  register_dissector ("docsis", dissect_docsis, proto_docsis);
}

void
proto_reg_handoff_docsis (void)
{

  docsis_handle = find_dissector ("docsis");
  dissector_add_uint ("wtap_encap", WTAP_ENCAP_DOCSIS, docsis_handle);

  docsis_mgmt_handle = find_dissector ("docsis_mgmt");
  eth_withoutfcs_handle = find_dissector_add_dependency("eth_withoutfcs", proto_docsis);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
