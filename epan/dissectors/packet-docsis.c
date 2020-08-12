/* packet-docsis.c
 * Routines for docsis dissection
 * Copyright 2002, Anand V. Narwani <anand[AT]narwani.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


/* This code is based on the DOCSIS 1.1 specification available at:
 * http://www.cablelabs.com/wp-content/uploads/specdocs/CM-SP-RFIv1.1-C01-050907.pdf
 *
 * This code was updated to include DOCSIS 3.1 specification details available at:
 * http://www.cablelabs.com/wp-content/uploads/specdocs/CM-SP-MULPIv3.1-I09-160602.pdf
 *
 * Updates are backward compatible with previous DOCSIS spcifications.
 *
 * DOCSIS Captures can be facilitated using the Cable Monitor Feature
 * available on Cisco Cable Modem Termination Systems:
 * https://www.cisco.com/c/en/us/td/docs/cable/cmts/config_guide/b_cmts_security_and_cable_monitoring_features/b_cmts_security_and_cable_monitoring_features_chapter_010.html
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
 * Wireshark will treat the frames in that capture as DOCSIS frames, even
 * if the preference mentioned above isn't enabled.
 */

#include "config.h"

#include <epan/etypes.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/addr_resolv.h>
#include <wiretap/wtap.h>
#include <epan/exceptions.h>
#include <epan/crc16-tvb.h>
#include <epan/crc32-tvb.h>

void proto_register_docsis(void);
void proto_reg_handoff_docsis(void);

/* Assume all packets have an FCS */
static gboolean docsis_check_fcs = TRUE;
static gboolean docsis_dissect_encrypted_frames = FALSE;

#define DOCSIS_MIN_HEADER_LEN   6

#define FCTYPE_PACKET   0x00
#define FCTYPE_RESERVED 0x01
#define FCTYPE_ISOLAT   0x02
#define FCTYPE_MACSPC   0x03

#define FCPARM_TIMING_HDR           0x00
#define FCPARM_MAC_MGMT_HDR         0x01
#define FCPARM_RQST_FRM             0x02
#define FCPARM_FRAG_HDR             0x03
#define FCPARM_QUEUE_DEPTH_REQ_FRM  0x04
#define FCPARM_CONCAT_HDR           0x1C

#define EXT_HDR_OFF     0x00
#define EXT_HDR_ON      0x01

#define FRAG_FCS_LEN    4
#define FRAG_FIRST      0x20
#define FRAG_MIDDLE     0x00
#define FRAG_LAST       0x10

#define EH_NULL_CONFIG      0
#define EH_REQUEST          1
#define EH_ACK_REQ          2
#define EH_BP_UP            3
#define EH_BP_DOWN          4
#define EH_SFLOW_HDR_DOWN   5
#define EH_SFLOW_HDR_UP     6
#define EH_BP_UP2           7
#define EH_DS_SERVICE       8
#define EH_PATH_VERIFY      9
#define EH_RESERVED_10      10
#define EH_RESERVED_11      11
#define EH_RESERVED_12      12
#define EH_RESERVED_13      13
#define EH_RESERVED_14      14
#define EH_EXTENDED         15

/* Initialize the protocol and registered fields */
static int proto_docsis = -1;
static int hf_docsis_fctype = -1;
static int hf_docsis_machdr_fcparm = -1;
static int hf_docsis_fcparm = -1;
static int hf_docsis_exthdr = -1;
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
static int hf_docsis_hcs_status = -1;
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
static int hf_docsis_ehdr_pv_st_refpt = -1;
static int hf_docsis_ehdr_pv_timestamp = -1;

static int hf_docsis_fragments = -1;
static int hf_docsis_fragment = -1;
static int hf_docsis_fragment_overlap = -1;
static int hf_docsis_fragment_overlap_conflict = -1;
static int hf_docsis_fragment_multiple_tails = -1;
static int hf_docsis_fragment_too_long_fragment = -1;
static int hf_docsis_fragment_error = -1;
static int hf_docsis_fragment_count = -1;
static int hf_docsis_reassembled_in = -1;
static int hf_docsis_reassembled_length = -1;
static int hf_docsis_reassembled_data = -1;
static int hf_docsis_frag_fcs = -1;
static int hf_docsis_frag_fcs_status = -1;

static int hf_docsis_dst = -1;
static int hf_docsis_dst_resolved = -1;
static int hf_docsis_src = -1;
static int hf_docsis_src_resolved = -1;
static int hf_docsis_lg = -1;
static int hf_docsis_ig = -1;
static int hf_docsis_encrypted_payload = -1;

static dissector_handle_t docsis_handle;
static dissector_handle_t eth_withoutfcs_handle;
static dissector_handle_t docsis_mgmt_handle;
#if 0
static dissector_table_t docsis_dissector_table;
#endif

static expert_field ei_docsis_hcs_bad = EI_INIT;
static expert_field ei_docsis_len = EI_INIT;
static expert_field ei_docsis_frag_fcs_bad = EI_INIT;
static expert_field ei_docsis_eh_len = EI_INIT;

/* Initialize the subtree pointers */
static gint ett_docsis = -1;
static gint ett_ehdr = -1;
static gint ett_docsis_fragments = -1;
static gint ett_docsis_fragment = -1;
static gint ett_addr = -1;

static const value_string fctype_vals[] = {
  {FCTYPE_PACKET,   "Packet PDU"},
  {FCTYPE_RESERVED, "Reserved"},
  {FCTYPE_ISOLAT,   "Isolation PDU"},
  {FCTYPE_MACSPC,   "MAC Specific"},
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
  {EH_PATH_VERIFY,    "Path Verify"},
  {EH_RESERVED_10,    "Reserved"},
  {EH_RESERVED_11,    "Reserved"},
  {EH_RESERVED_12,    "Reserved"},
  {EH_RESERVED_13,    "Reserved"},
  {EH_RESERVED_14,    "Reserved"},
  {EH_EXTENDED,       "Extended"},
  {0, NULL}
};

static const value_string ms_fcparm_vals[] = {
  {FCPARM_TIMING_HDR,           "Timing Header"},
  {FCPARM_MAC_MGMT_HDR,         "MAC Management Message"},
  {FCPARM_RQST_FRM,             "Request Frame"},
  {FCPARM_FRAG_HDR,             "Fragmentation Header"},
  {FCPARM_QUEUE_DEPTH_REQ_FRM,  "Queue Depth-based Request Frame"},
  {FCPARM_CONCAT_HDR,           "Concatenation Header"},
  {0, NULL}
};

static const value_string pkt_fcparm_vals[] = {
  {0x00,           "PDU MAC"},
  {0x01,           "DELAY/DUPLICATE/MULTICAST/BROADCAST"},
  {0, NULL}
};

static const true_false_string exthdr_tfs = {
  "Extended Header Present",
  "Extended Header Absent"
};


static const value_string local_proto_checksum_vals[] = {
  { PROTO_CHECKSUM_E_BAD,        "Bad"  },
  { PROTO_CHECKSUM_E_GOOD,       "Good" },
  { PROTO_CHECKSUM_E_UNVERIFIED, "Unverified" },
  { PROTO_CHECKSUM_E_NOT_PRESENT, "Not present" },

  { 0,        NULL }
};

static const true_false_string qind_tfs = {
  "Rate overrun",
  "Rate non-overrun"
};

static const true_false_string odd_even_tfs = {
  "Odd Key",
  "Even Key",
};

static const value_string unique_no_phs[] = {
  { 0, "No PHS on current packet" },
  { 0, NULL }
};

/* Fragmentation Flags / Sequence */
static guint8 frag_flags;
static guint8 frag_seq;
static guint16 frag_sid;

/*
 * Defragmentation of DOCSIS
 */
static reassembly_table docsis_reassembly_table;


static const fragment_items docsis_frag_items = {
  &ett_docsis_fragment,
  &ett_docsis_fragments,
  &hf_docsis_fragments,
  &hf_docsis_fragment,
  &hf_docsis_fragment_overlap,
  &hf_docsis_fragment_overlap_conflict,
  &hf_docsis_fragment_multiple_tails,
  &hf_docsis_fragment_too_long_fragment,
  &hf_docsis_fragment_error,
  &hf_docsis_fragment_count,
  &hf_docsis_reassembled_in,
  &hf_docsis_reassembled_length,
  &hf_docsis_reassembled_data,
  "DOCSIS fragments"
};

/* Dissection */
/* Code to Dissect the extended header; TLV Formatted headers */
static void
dissect_ehdr (tvbuff_t * tvb, proto_tree * tree, packet_info * pinfo, gboolean *is_encrypted)
{
  proto_tree *ehdr_tree;
  proto_item *eh_length_item;
  gint ehdrlen;
  int pos;
  guint8 type;
  guint8 len;

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
    {
      proto_tree_add_item (ehdr_tree, hf_docsis_eh_type, tvb, pos, 1, ENC_BIG_ENDIAN);
    }

    eh_length_item = proto_tree_add_item (ehdr_tree, hf_docsis_eh_len, tvb, pos, 1, ENC_BIG_ENDIAN);


    switch ((type >> 4) & 0x0F)
    {
      case EH_REQUEST:
        /* Request: Minislots Requested */
        if (len == 3)
        {
          proto_tree_add_item(ehdr_tree, hf_docsis_mini_slots, tvb, pos + 1, 1, ENC_NA);
          proto_tree_add_item(ehdr_tree, hf_docsis_sid, tvb, pos + 2, 2, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info(pinfo, eh_length_item, &ei_docsis_eh_len);
          return;
        }
        break;
      case EH_ACK_REQ:
        /* Deprecated in DOCSIS 3.1 */
        if (len == 2)
        {
          proto_tree_add_item(ehdr_tree, hf_docsis_sid, tvb, pos + 1, 2, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info(pinfo, eh_length_item, &ei_docsis_eh_len);
          return;
        }
        break;
      case EH_BP_UP:
        /* Upstream Privacy EH Element or Upstream Privacy with fragmentation */
        proto_tree_add_item (ehdr_tree, hf_docsis_key_seq, tvb, pos + 1, 1,
                             ENC_BIG_ENDIAN);
        proto_tree_add_item (ehdr_tree, hf_docsis_ehdr_ver, tvb, pos + 1, 1,
                             ENC_BIG_ENDIAN);
        proto_tree_add_item_ret_boolean (ehdr_tree, hf_docsis_bpi_en, tvb, pos + 2, 1,
                             ENC_BIG_ENDIAN, is_encrypted);
        proto_tree_add_item (ehdr_tree, hf_docsis_toggle_bit, tvb, pos + 2,
                             1, ENC_BIG_ENDIAN);
        proto_tree_add_item (ehdr_tree, hf_docsis_sid, tvb, pos + 2, 2,
                             ENC_BIG_ENDIAN);
        frag_sid = tvb_get_guint8 (tvb, pos+2) & 0xCFFF;
        proto_tree_add_item (ehdr_tree, hf_docsis_mini_slots, tvb, pos + 4,
                             1, ENC_BIG_ENDIAN);
        if (pinfo->fragmented)
        {
          proto_tree_add_item (ehdr_tree, hf_docsis_frag_rsvd, tvb, pos+5,
                               1, ENC_BIG_ENDIAN);
          frag_flags = tvb_get_guint8 (tvb, pos+5) & 0x30;
          proto_tree_add_item (ehdr_tree, hf_docsis_frag_first, tvb, pos+5,
                               1, ENC_BIG_ENDIAN);
          proto_tree_add_item (ehdr_tree, hf_docsis_frag_last, tvb, pos+5,
                               1, ENC_BIG_ENDIAN);
          frag_seq = tvb_get_guint8 (tvb, pos+5) & 0x0F;
          proto_tree_add_item (ehdr_tree, hf_docsis_frag_seq, tvb, pos+5,
                               1, ENC_BIG_ENDIAN);
        }
        break;
      case EH_BP_DOWN:
        /* Downstream Privacy EH Element */
        proto_tree_add_item (ehdr_tree, hf_docsis_key_seq, tvb, pos + 1, 1,
                             ENC_BIG_ENDIAN);
        proto_tree_add_item (ehdr_tree, hf_docsis_ehdr_ver, tvb, pos + 1, 1,
                             ENC_BIG_ENDIAN);
        proto_tree_add_item_ret_boolean (ehdr_tree, hf_docsis_bpi_en, tvb, pos + 2, 1,
                             ENC_BIG_ENDIAN, is_encrypted);
        proto_tree_add_item (ehdr_tree, hf_docsis_toggle_bit, tvb, pos + 2,
                             1, ENC_BIG_ENDIAN);
        proto_tree_add_item (ehdr_tree, hf_docsis_said, tvb, pos + 2, 2,
                             ENC_BIG_ENDIAN);
        proto_tree_add_item (ehdr_tree, hf_docsis_reserved, tvb, pos + 4, 1,
                             ENC_BIG_ENDIAN);
        break;
      case EH_SFLOW_HDR_DOWN:
        /* Deprecated in DOCSIS 3.1, was Downstream Service Flow EH Element in earlier revisions */
      case EH_SFLOW_HDR_UP:
        /* Deprecated in DOCSIS 3.1, was Upstream Service Flow EH Element in earlier revisions */
        proto_tree_add_item(ehdr_tree, hf_docsis_ehdr_phsi, tvb, pos+1, 1, ENC_BIG_ENDIAN);

        if (len == 2)
        {
          proto_tree_add_item (ehdr_tree, hf_docsis_ehdr_qind, tvb, pos+2, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item (ehdr_tree, hf_docsis_ehdr_grants, tvb, pos+2, 1, ENC_BIG_ENDIAN);
        }
        break;
      case EH_BP_UP2:
        /* Upstream Privacy EH Element, version 2, with no piggyback request */
        proto_tree_add_item (ehdr_tree, hf_docsis_ehdr_bpup2_key_seq, tvb, pos + 1, 1,
                             ENC_BIG_ENDIAN);
        proto_tree_add_item (ehdr_tree, hf_docsis_ehdr_bpup2_ver, tvb, pos + 1, 1,
                             ENC_BIG_ENDIAN);
        proto_tree_add_item_ret_boolean (ehdr_tree, hf_docsis_ehdr_bpup2_bpi_en, tvb, pos + 2, 1,
                             ENC_BIG_ENDIAN, is_encrypted);
        proto_tree_add_item (ehdr_tree, hf_docsis_ehdr_bpup2_toggle_bit, tvb, pos + 2,
                             1, ENC_BIG_ENDIAN);
        proto_tree_add_item (ehdr_tree, hf_docsis_ehdr_bpup2_sid, tvb, pos + 2, 2,
                             ENC_BIG_ENDIAN);
        break;
      case EH_DS_SERVICE:
        /* Downstream Service EH Element */
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
      case EH_PATH_VERIFY:
        /* Path Verify EH Element */
        if (len == 5)
        {
          proto_tree_add_item (ehdr_tree, hf_docsis_ehdr_pv_st_refpt, tvb, pos+1, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item (ehdr_tree, hf_docsis_ehdr_pv_timestamp, tvb, pos+2, 4, ENC_BIG_ENDIAN);
        }
        break;
      case EH_EXTENDED:
        /* Extended EH Element, one or more Sub EH fields may follow; simply recurse */
        {
            tvbuff_t *subset = tvb_new_subset_remaining(tvb, pos);
            dissect_ehdr (subset, ehdr_tree, pinfo, is_encrypted);
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

/* Code to Dissect the Header Check Sequence field */
/* Return FALSE in case FCS validation is enabled, but FCS is incorrect */
/* Return TRUE in all other cases */
static gboolean
dissect_hcs_field (tvbuff_t * tvb, packet_info * pinfo, proto_tree * docsis_tree, gint hdrlen)
{
  /* dissect the header check sequence */
  if(docsis_check_fcs){
    /* CRC-CCITT(16+12+5+1) */
    guint16 fcs = g_ntohs(crc16_ccitt_tvb(tvb, (hdrlen - 2)));
    proto_tree_add_checksum(docsis_tree, tvb, (hdrlen - 2), hf_docsis_hcs, hf_docsis_hcs_status, &ei_docsis_hcs_bad, pinfo, fcs, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);

    return (tvb_get_ntohs(tvb, (hdrlen - 2)) == fcs) ? TRUE : FALSE;
  }
  else
  {
    proto_tree_add_checksum(docsis_tree, tvb, (hdrlen - 2), hf_docsis_hcs, hf_docsis_hcs_status, &ei_docsis_hcs_bad, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
  }
  return TRUE;
}

/* Code to Dissect the extended header length / MAC Param field and Length field */
/* The length field may condain a SID, but this logic is not handled here */
static void
dissect_exthdr_length_field (tvbuff_t * tvb, packet_info * pinfo, proto_tree * docsis_tree,
                             guint8 exthdr, guint16 mac_parm, guint16 len_sid, guint16 *payload_length, gboolean *is_encrypted)
{
  proto_item *length_item;
  if (exthdr == EXT_HDR_ON)
  {
    /* Add in Extended Header Length */
    proto_tree_add_item (docsis_tree, hf_docsis_ehdrlen, tvb, 1, 1,  ENC_BIG_ENDIAN);
    length_item = proto_tree_add_item (docsis_tree, hf_docsis_len, tvb, 2, 2, ENC_BIG_ENDIAN);
    /* Validate PDU length */
    if ((len_sid - mac_parm) > *payload_length)
    {
      *payload_length = len_sid;
      expert_add_info(pinfo, length_item, &ei_docsis_len);
    }
    /* Pass off to the Extended Header dissection */
    dissect_ehdr (tvb, docsis_tree, pinfo, is_encrypted);
  }
  else
  {
    /* Add in MAC Parm field only */
    proto_tree_add_item (docsis_tree, hf_docsis_macparm, tvb, 1, 1, ENC_BIG_ENDIAN);
    length_item = proto_tree_add_item (docsis_tree, hf_docsis_len, tvb, 2, 2, ENC_BIG_ENDIAN);
    /* Validate PDU length */
    if (len_sid > *payload_length)
    {
      *payload_length = len_sid;
      expert_add_info(pinfo, length_item, &ei_docsis_len);
    }
  }
  return;
}

/* Code to Dissect Encrypted DOCSIS Frames */
/* Print DST and SRC MACs and do not dissect the payload */
/* Implementation inferred from packet-eth.c */
static void
dissect_encrypted_frame (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, const guint8 fctype, const guint8 fcparm)
{
  guint32           offset, frame_len;
  const guint8      *src_addr, *dst_addr;
  const char        *src_addr_name, *dst_addr_name;
  proto_item        *addr_item;
  proto_tree        *addr_tree=NULL;
//  tvbuff_t          *next_tvb;

  /* According to CM-SP-SEC-v3.1, PDU regions of the following
   * frames must be encryped when security is enabled:
   * - Variable-length PDU MAC Frames;
   * - Fragmentation MAC Frames;
   * - Registration Request (REG-REQ-MP) MAC Management Message Frames;
   * - Isolation PDU MAC Frames.
   * There are also other corner cases when MAC Management frames might be encrypted
   * (e.g. EH_TYPE=7 as described in CM-SP-MULPIv3.1-I15-180509 Table 17 and Table 20)
   */
  if (fctype == FCTYPE_MACSPC) {
    if (fcparm == FCPARM_MAC_MGMT_HDR) {
      col_append_str (pinfo->cinfo, COL_INFO, " (Encrypted MMM)");
    } else if (fcparm == FCPARM_FRAG_HDR) {
      col_append_str (pinfo->cinfo, COL_INFO, " (Encrypted Fragmentation MAC Frame)");
    } else {
      col_append_str (pinfo->cinfo, COL_INFO, " (Encrypted)");
    }
  } else {
    col_append_str (pinfo->cinfo, COL_INFO, " (Encrypted)");
  }

  offset = 0;
  frame_len = tvb_captured_length_remaining (tvb, offset);
  switch (fctype)
  {
    case FCTYPE_PACKET:
    case FCTYPE_ISOLAT:
    case FCTYPE_MACSPC:
      dst_addr = tvb_get_ptr(tvb, 0, 6);
      dst_addr_name = get_ether_name(dst_addr);
      src_addr = tvb_get_ptr(tvb, 6, 6);
      src_addr_name = get_ether_name(src_addr);

      addr_item = proto_tree_add_ether(tree, hf_docsis_dst, tvb, 0, 6, dst_addr);
      addr_tree = proto_item_add_subtree(addr_item, ett_addr);
      addr_item=proto_tree_add_string(addr_tree, hf_docsis_dst_resolved, tvb, 0, 6,
          dst_addr_name);
      proto_item_set_generated(addr_item);
      proto_tree_add_item(addr_tree, hf_docsis_lg, tvb, 0, 3, ENC_BIG_ENDIAN);
      proto_tree_add_item(addr_tree, hf_docsis_ig, tvb, 0, 3, ENC_BIG_ENDIAN);

      addr_item = proto_tree_add_ether(tree, hf_docsis_src, tvb, 6, 6, src_addr);
      addr_tree = proto_item_add_subtree(addr_item, ett_addr);
      addr_item=proto_tree_add_string(addr_tree, hf_docsis_src_resolved, tvb, 6, 6,
          src_addr_name);
      proto_item_set_generated(addr_item);
      proto_tree_add_item(addr_tree, hf_docsis_lg, tvb, 6, 3, ENC_BIG_ENDIAN);
      proto_tree_add_item(addr_tree, hf_docsis_ig, tvb, 6, 3, ENC_BIG_ENDIAN);

      offset += 12;
      break;
  }
  proto_tree_add_item(tree, hf_docsis_encrypted_payload, tvb, offset, frame_len - offset, ENC_NA);

  return;
}

/* Main DOCSIS Dissection Entry Point */
/* Code to Dissect the DOCSIS Frames */
static int
dissect_docsis (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  guint8 fc = 0;
  guint8 fctype = 0;
  guint8 fcparm = 0;
  guint8 exthdr = 0;
  guint16 mac_parm = 0;
  guint8 hdrlen = DOCSIS_MIN_HEADER_LEN;
  guint16 len_sid = 0;
  tvbuff_t *next_tvb = NULL;
  tvbuff_t *mgt_tvb = NULL;
  gint pdulen = 0;
  guint16 payload_length = 0;
  /* guint16 framelen = 0; */
  gboolean save_fragmented;
  gboolean is_encrypted = FALSE;
  gboolean fcs_correct;
  proto_item *ti;
  proto_tree *docsis_tree;

  /* Extract Frame Control parts */
  fc = tvb_get_guint8 (tvb, 0); /* Frame Control Byte */
  fctype = (fc >> 6) & 0x03;    /* Frame Control Type:  2 MSB Bits */
  fcparm = (fc >> 1) & 0x1F;    /* Frame Control Parameter: Next 5 Bits */
  exthdr = (fc & 0x01);         /* Extended Header Bit: LSB */

  /* Extract the MAC Parm; MAC Parm and SID offsets; change for a Queue Depth Request */
  if (fcparm == FCPARM_QUEUE_DEPTH_REQ_FRM) {
    mac_parm = tvb_get_ntohs (tvb, 1);
    len_sid = tvb_get_ntohs (tvb, 3);
    hdrlen = DOCSIS_MIN_HEADER_LEN + 1; // 7-byte header for this message type
  } else {
    mac_parm = tvb_get_guint8 (tvb, 1);
    len_sid = tvb_get_ntohs (tvb, 2);
  }

  /* Set Header Length based on presence of Extended header */
  if (exthdr == EXT_HDR_ON) {
    hdrlen += mac_parm;
  }

  /* Captured Payload Length is based on the length of the header */
  payload_length = tvb_reported_length_remaining (tvb, hdrlen);

  /* If this is a Request Frame, then pdulen is 0 and framelen is 6 */
  if ((fctype == FCTYPE_MACSPC) && (fcparm == FCPARM_RQST_FRM || fcparm == FCPARM_QUEUE_DEPTH_REQ_FRM))
  {
    pdulen = 0;
    /*
    if (fcparm == FCPARM_QUEUE_DEPTH_REQ_FRM)
      framelen = DOCSIS_MIN_HEADER_LEN + 1;
    else
      framelen = DOCSIS_MIN_HEADER_LEN;
    */
  } else {
    /* framelen = DOCSIS_MIN_HEADER_LEN + len_sid; */
    pdulen = len_sid - (mac_parm + 2);
  }

  /* Make entries in Protocol column and Info column on summary display */
  col_set_str (pinfo->cinfo, COL_PROTOCOL, "DOCSIS");

  switch (fctype)
  {
    case FCTYPE_PACKET:
      col_set_str (pinfo->cinfo, COL_INFO, "Packet PDU");
      break;
    case FCTYPE_RESERVED:
      col_set_str (pinfo->cinfo, COL_INFO, "Reserved PDU");
      break;
    case FCTYPE_ISOLAT:
      col_set_str (pinfo->cinfo, COL_INFO, "Isolation PDU");
      break;
    case FCTYPE_MACSPC:
      if (fcparm == FCPARM_RQST_FRM)
        col_add_fstr (pinfo->cinfo, COL_INFO,
                      "Request Frame SID=%u Mini Slots=%u", len_sid,
                      mac_parm);
      else if (fcparm == FCPARM_QUEUE_DEPTH_REQ_FRM)
        col_add_fstr (pinfo->cinfo, COL_INFO,
                      "Request Frame SID=%u, Requested Size=%uxN bytes", len_sid,
                      mac_parm);
      else if (fcparm == FCPARM_FRAG_HDR)
        col_set_str (pinfo->cinfo, COL_INFO, "Fragmented Frame");
      else
        col_set_str (pinfo->cinfo, COL_INFO, "Mac Specific");
      break;
  }  /* switch fctype */

  ti = proto_tree_add_item(tree, proto_docsis, tvb, 0, hdrlen, ENC_NA);
  docsis_tree = proto_item_add_subtree (ti, ett_docsis);

  /* add an item to the subtree, see section 1.6 for more information */

  /* Add in FC Byte fields */
  proto_tree_add_item (docsis_tree, hf_docsis_fctype, tvb, 0, 1, ENC_BIG_ENDIAN);

  switch (fctype)
  {
    case FCTYPE_PACKET:
    {
      proto_item_append_text (ti, " Packet PDU");
      proto_tree_add_item (docsis_tree, hf_docsis_fcparm, tvb, 0, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item (docsis_tree, hf_docsis_exthdr, tvb, 0, 1, ENC_BIG_ENDIAN);
      /* Dissect Length field for a PDU */
      dissect_exthdr_length_field (tvb, pinfo, docsis_tree, exthdr, mac_parm, len_sid, &payload_length, &is_encrypted);
      /* Dissect Header Check Sequence field for a PDU */
      fcs_correct = dissect_hcs_field (tvb, pinfo, docsis_tree, hdrlen);
      if (fcs_correct && pdulen > 0)
      {
        next_tvb =  tvb_new_subset_remaining(tvb, hdrlen);
        if(is_encrypted && !docsis_dissect_encrypted_frames)
          dissect_encrypted_frame (next_tvb, pinfo, docsis_tree, fctype, fcparm);
        else
          call_dissector (eth_withoutfcs_handle, next_tvb, pinfo, docsis_tree);
      }
      break;
    }
    case FCTYPE_RESERVED:
    {
      proto_item_append_text (ti, " Reserved PDU");
      proto_tree_add_item (docsis_tree, hf_docsis_fcparm, tvb, 0, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item (docsis_tree, hf_docsis_exthdr, tvb, 0, 1, ENC_BIG_ENDIAN);
      /* Dissect Length field for a PDU */
      dissect_exthdr_length_field (tvb, pinfo, docsis_tree, exthdr, mac_parm, len_sid, &payload_length, &is_encrypted);
      /* Dissect Header Check Sequence field for a PDU */
      fcs_correct = dissect_hcs_field (tvb, pinfo, docsis_tree, hdrlen);
      if (fcs_correct)
      {
        /* Don't do anything for a Reserved Frame */
        next_tvb =  tvb_new_subset_remaining(tvb, hdrlen);
        call_data_dissector(next_tvb, pinfo, tree);
      }
      break;
    }
    case FCTYPE_ISOLAT:
    {
      proto_item_append_text (ti, " Isolation PDU");
      proto_tree_add_item (docsis_tree, hf_docsis_fcparm, tvb, 0, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item (docsis_tree, hf_docsis_exthdr, tvb, 0, 1, ENC_BIG_ENDIAN);
      /* Dissect Length field for a PDU */
      dissect_exthdr_length_field (tvb, pinfo, docsis_tree, exthdr, mac_parm, len_sid, &payload_length, &is_encrypted);
      /* Dissect Header Check Sequence field for a PDU */
      fcs_correct = dissect_hcs_field (tvb, pinfo, docsis_tree, hdrlen);
      if (fcs_correct && pdulen > 0)
      {
        next_tvb =  tvb_new_subset_remaining(tvb, hdrlen);
        if(is_encrypted && !docsis_dissect_encrypted_frames)
          dissect_encrypted_frame (next_tvb, pinfo, docsis_tree, fctype, fcparm);
        else
          call_dissector (eth_withoutfcs_handle, next_tvb, pinfo, docsis_tree);
      }
      break;
    }
    case FCTYPE_MACSPC:
    {
      proto_item_append_text (ti, " MAC-Specific PDU");
      proto_tree_add_item (docsis_tree, hf_docsis_machdr_fcparm, tvb, 0, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item (docsis_tree, hf_docsis_exthdr, tvb, 0, 1, ENC_BIG_ENDIAN);
      switch(fcparm)
      {
        case FCPARM_TIMING_HDR:
          // no break
        case FCPARM_MAC_MGMT_HDR:
        {
          /* Dissect Length field for a PDU */
          dissect_exthdr_length_field (tvb, pinfo, docsis_tree, exthdr, mac_parm, len_sid, &payload_length, &is_encrypted);
          /* Dissect Header Check Sequence field for a PDU */
          fcs_correct = dissect_hcs_field (tvb, pinfo, docsis_tree, hdrlen);
          if (fcs_correct)
          {
            /* Pass off to the DOCSIS Management dissector/s */
            mgt_tvb = tvb_new_subset_remaining(tvb, hdrlen);
            if(is_encrypted && !docsis_dissect_encrypted_frames)
              dissect_encrypted_frame (mgt_tvb, pinfo, docsis_tree, fctype, fcparm);
            else
              call_dissector (docsis_mgmt_handle, mgt_tvb, pinfo, docsis_tree);
          }
          break;
        }
        case FCPARM_RQST_FRM:
        {
          /* Decode for a Request Frame.  No extended header */
          proto_tree_add_uint (docsis_tree, hf_docsis_mini_slots, tvb, 1, 1, mac_parm);
          proto_tree_add_uint (docsis_tree, hf_docsis_sid, tvb, 2, 2, len_sid);
          /* Dissect Header Check Sequence field for a PDU */
          fcs_correct = dissect_hcs_field (tvb, pinfo, docsis_tree, hdrlen);
          if (fcs_correct)
          {
            /* Don't do anything for a Request Frame, there is no data following it*/
          }
          break;
        }
        case FCPARM_FRAG_HDR:
        {
          /* Check if this is a fragmentation header */
          save_fragmented = pinfo->fragmented;
          pinfo->fragmented = TRUE;

          /* Dissect Length field for a PDU */
          dissect_exthdr_length_field (tvb, pinfo, docsis_tree, exthdr, mac_parm, len_sid, &payload_length, &is_encrypted);
          /* Dissect Header Check Sequence field for a PDU */
          fcs_correct = dissect_hcs_field (tvb, pinfo, docsis_tree, hdrlen);
          if (fcs_correct)
          {
            /* Grab the Fragment FCS */
            guint32 sent_fcs = tvb_get_ntohl(tvb, (hdrlen + len_sid - 4));
            guint32 fcs = crc32_802_tvb(tvb, tvb_captured_length(tvb) - 4);

            /* Only defragment valid frames with a good FCS */
            if (sent_fcs == fcs)
            {
              fragment_item *frag_msg = NULL;
              frag_msg = fragment_add_seq_check(&docsis_reassembly_table,
                                                tvb, hdrlen, pinfo,
                                                frag_sid, NULL, /* ID for fragments belonging together */
                                                frag_seq, /* Fragment Sequence Number */
                                                (len_sid - 4), /* fragment length - to the end */
                                                !(frag_flags & FRAG_LAST)); /* More fragments? */

              next_tvb = process_reassembled_data(tvb, hdrlen, pinfo,
                                                  "Reassembled Message", frag_msg, &docsis_frag_items,
                                                  NULL, docsis_tree);

              if (frag_flags == FRAG_LAST)
                pinfo->fragmented = FALSE;
              else
                pinfo->fragmented = TRUE;

              if (frag_msg) { /* Reassembled */
                proto_item_append_text (ti, " (Message Reassembled)");
              } else { /* Not last packet of reassembled Short Message */
                proto_item_append_text (ti, " (Message fragment %u)", frag_seq);

              }

              if(next_tvb)
              {
                /* By default assume an Ethernet payload */
              if(is_encrypted && !docsis_dissect_encrypted_frames)
                dissect_encrypted_frame (next_tvb, pinfo, docsis_tree, fctype, fcparm);
              else
                call_dissector (eth_withoutfcs_handle, next_tvb, pinfo, docsis_tree);
              } else {
                /* Otherwise treat as Data */
                tvbuff_t *payload_tvb = tvb_new_subset_length_caplen(tvb, hdrlen, (len_sid - 4), -1);
                call_data_dissector(payload_tvb, pinfo, docsis_tree);
              }
            } else {
              /* Report frames with a bad FCS */
              expert_add_info(pinfo, ti, &ei_docsis_frag_fcs_bad);
            }
            /* Add the Fragment FCS to the end of the parent tree */
            proto_tree_add_checksum(docsis_tree, tvb, (hdrlen + len_sid - 4), hf_docsis_frag_fcs, hf_docsis_frag_fcs_status, &ei_docsis_frag_fcs_bad, pinfo, fcs, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);

            pinfo->fragmented = save_fragmented;
          }
          break;
        }
        case FCPARM_QUEUE_DEPTH_REQ_FRM:
        {
          /* Decode for a Queue-depth Based Request */
          proto_tree_add_uint (docsis_tree, hf_docsis_requested_size, tvb, 1, 2, mac_parm);
          proto_tree_add_uint (docsis_tree, hf_docsis_sid, tvb, 3, 2, len_sid);
          /* Dissect Header Check Sequence field for a PDU */
          fcs_correct = dissect_hcs_field (tvb, pinfo, docsis_tree, hdrlen);
          if (fcs_correct)
          {
          /* No PDU Payload for this frame */
          }
          break;
        }
        case FCPARM_CONCAT_HDR:
        {
          /* Decode for a Concatenated Header; ONLY for DOCSIS versions < 3.1.  No Extended Header */
          proto_item_append_text (ti, " (Concatenated Header)");
          proto_tree_add_item (docsis_tree, hf_docsis_concat_cnt, tvb, 1, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item (docsis_tree, hf_docsis_len, tvb, 2, 2, ENC_BIG_ENDIAN);
          /* Dissect Header Check Sequence field for a PDU */
          fcs_correct = dissect_hcs_field (tvb, pinfo, docsis_tree, hdrlen);
          if (fcs_correct)
          {
            // There used to be a section of code here that recursively
            // called dissect_docsis. It has been removed. If you plan on
            // adding concatenated PDU support back you should consider
            // doing something like the following:
            // dissect_docsis(...) {
            //   while(we_have_pdus_remaining) {
            //     int pdu_len = dissect_docsis_pdu(...)
            //     if (pdu_len < 1) {
            //       add_expert...
            //       break;
            //     }
            //   }
            // }
            // Adding back this functionality using recursion might result
            // in this dissector being disabled by default or removed entirely.
          }
          break;
        }
        default:
            /* Unknown parameter, stop dissection */
          break;
      } /* switch fcparm */
      break;
    }
  } /* switch fctype*/

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
      FT_UINT8, BASE_DEC, VALS (pkt_fcparm_vals), 0x3E,
      "Parameter Field", HFILL}
    },
    {&hf_docsis_machdr_fcparm,
     {"FCParm", "docsis.fcparm",
      FT_UINT8, BASE_DEC, VALS (ms_fcparm_vals), 0x3E,
      "Parameter Field", HFILL}
    },
    {&hf_docsis_exthdr,
     {"EXTHDR", "docsis.exthdr",
      FT_BOOLEAN, 8, TFS (&exthdr_tfs), 0x01,
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
      FT_UINT16, BASE_DEC_HEX, NULL, 0x3FFF,
      "Service Identifier", HFILL}
    },
    {&hf_docsis_said,
     {"SAID", "docsis.ehdr.said",
      FT_UINT16, BASE_DEC, NULL, 0x3FFF,
      "Security Association Identifier", HFILL}
    },
    {&hf_docsis_reserved,
     {"Reserved", "docsis.ehdr.rsvd",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "Reserved Byte", HFILL}
    },
    {&hf_docsis_mini_slots,
     {"MiniSlots", "docsis.ehdr.minislots",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Mini Slots Requested", HFILL}
    },
    {&hf_docsis_requested_size,
     {"Requested bytes in units of N bytes, N a parameter of the service flow for which this request is being made", "docsis.ehdr.reqsize",
      FT_UINT16, BASE_DEC, NULL, 0xFFFF,
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
      FT_UINT8, BASE_DEC|BASE_SPECIAL_VALS, VALS(unique_no_phs), 0x0,
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
      NULL, HFILL}
    },
    {&hf_docsis_ehdr_bpup2_ver,
     {"Version", "docsis.ehdr.bpup2_ver",
      FT_UINT8, BASE_DEC, NULL, 0x0F,
      NULL, HFILL}
    },
    {&hf_docsis_ehdr_bpup2_bpi_en,
     {"Encryption", "docsis.ehdr.bpup2_bpi_en",
      FT_BOOLEAN, 8, TFS (&tfs_enabled_disabled), 0x80,
      "BPI Enable", HFILL}
    },
    {&hf_docsis_ehdr_bpup2_toggle_bit,
     {"Toggle", "docsis.ehdr.bpup2_toggle_bit",
      FT_BOOLEAN, 8, TFS (&odd_even_tfs), 0x40,
      NULL, HFILL}
    },
    {&hf_docsis_ehdr_bpup2_sid,
     {"SID", "docsis.ehdr.bpup2_sid",
      FT_UINT16, BASE_DEC, NULL, 0x3FFF,
      "Service Identifier", HFILL}
    },
    { &hf_docsis_ehdr_pv_st_refpt,
     { "Start Reference Point", "docsis.ehdr.pv_start_ref",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL, HFILL}
    },
    { &hf_docsis_ehdr_pv_timestamp,
     { "Timestamp", "docsis.ehdr.pv_timestamp",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL, HFILL}
    },
    {&hf_docsis_ehdr_ds_traffic_pri,
     {"DS Traffic Priority", "docsis.ehdr.ds_traffic_pri",
      FT_UINT8, BASE_DEC, NULL, 0xE0,
      NULL, HFILL}
    },
    {&hf_docsis_ehdr_ds_seq_chg_cnt,
     {"DS Sequence Change Count", "docsis.ehdr.ds_seq_chg_cnt",
      FT_UINT8, BASE_DEC, NULL, 0x10,
      NULL, HFILL}
    },
    {&hf_docsis_ehdr_ds_dsid,
     {"DS DSID", "docsis.ehdr.ds_dsid",
      FT_UINT32, BASE_DEC, NULL, 0x0FFFFF,
      NULL, HFILL}
    },
    {&hf_docsis_ehdr_ds_pkt_seq_num,
     {"DS Packet Sequence Number", "docsis.ehdr.ds_pkt_seq_num",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_hcs,
     {"Header check sequence", "docsis.hcs",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    { &hf_docsis_hcs_status,
     { "HCS Status", "docsis.hcs.status",
       FT_UINT8, BASE_NONE, VALS(local_proto_checksum_vals), 0x0,
       NULL, HFILL}
    },
    { &hf_docsis_bpi_en,
     { "Encryption", "docsis.bpi_en",
       FT_BOOLEAN, 8, TFS (&tfs_enabled_disabled), 0x80,
       "BPI Enable", HFILL}
    },
    { &hf_docsis_toggle_bit,
     { "Toggle", "docsis.toggle_bit",
       FT_BOOLEAN, 8, TFS (&odd_even_tfs), 0x40,
       NULL, HFILL}
    },
    { &hf_docsis_fragment_overlap,
     { "Fragment overlap", "docsis.fragment.overlap",
       FT_BOOLEAN, BASE_NONE, NULL, 0x0,
       "Fragment overlaps with other fragments", HFILL}
    },
    { &hf_docsis_fragment_overlap_conflict,
     { "Conflicting data in fragment overlap", "docsis.fragment.overlap.conflict",
       FT_BOOLEAN, BASE_NONE, NULL, 0x0,
       "Overlapping fragments contained conflicting data", HFILL}
    },
    { &hf_docsis_fragment_multiple_tails,
     { "Multiple tail fragments found", "docsis.fragment.multipletails",
       FT_BOOLEAN, BASE_NONE, NULL, 0x0,
       "Several tails were found when defragmenting the packet", HFILL}
    },
    { &hf_docsis_fragment_too_long_fragment,
     { "Fragment too long", "docsis.fragment.toolongfragment",
       FT_BOOLEAN, BASE_NONE, NULL, 0x0,
       "Fragment contained data past end of packet", HFILL}
    },
    { &hf_docsis_fragment_error,
     { "Defragmentation error", "docsis.fragment.error",
       FT_FRAMENUM, BASE_NONE, NULL, 0x0,
       "Defragmentation error due to illegal fragments", HFILL}
    },
    { &hf_docsis_fragment_count,
     { "Fragment count", "docsis.fragment.count",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL, HFILL}
    },
    { &hf_docsis_fragment,
     { "DOCSIS Fragment", "docsis.fragment",
       FT_FRAMENUM, BASE_NONE, NULL, 0x0,
       NULL, HFILL}
    },
    { &hf_docsis_fragments,
     { "DOCSIS Fragments", "docsis.fragments",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       NULL, HFILL}
    },
    { &hf_docsis_reassembled_in,
     { "Reassembled DOCSIS in frame", "docsis.reassembled_in",
       FT_FRAMENUM, BASE_NONE, NULL, 0x0,
       "This DOCSIS packet is reassembled in this frame", HFILL}
    },
    { &hf_docsis_reassembled_length,
     { "Reassembled DOCSIS length", "docsis.reassembled.length",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       "The total length of the reassembled payload", HFILL}
    },
    { &hf_docsis_reassembled_data,
     { "Reassembled DOCSIS data", "docsis.reassembled.data",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       "The reassembled payload", HFILL}
    },
    { &hf_docsis_frag_fcs,
     { "Fragment FCS", "docsis.frag.fcs",
       FT_UINT32, BASE_HEX, NULL, 0x0,
       NULL, HFILL}
    },
    { &hf_docsis_frag_fcs_status,
     { "Fragment FCS Status", "docsis.frag.fcs.status",
       FT_UINT8, BASE_NONE, VALS(local_proto_checksum_vals), 0x0,
       NULL, HFILL}
    },
    { &hf_docsis_encrypted_payload,
      { "Encrypted Payload", "docsis.encrypted_payload",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Encryped data", HFILL }
    }
  };

  static ei_register_info ei[] = {
      { &ei_docsis_hcs_bad, { "docsis.hcs_bad", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
      { &ei_docsis_len, { "docsis.len.past_end", PI_MALFORMED, PI_ERROR, "Length field value goes past the end of the payload", EXPFILL }},
      { &ei_docsis_frag_fcs_bad, { "docsis.frag.fcs_bad", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
      { &ei_docsis_eh_len, { "docsis.ehdr.len.past_end", PI_MALFORMED, PI_ERROR, "Extended Header Length Invalid!", EXPFILL }}
  };

  static gint *ett[] = {
      &ett_docsis,
      &ett_ehdr,
      &ett_docsis_fragment,
      &ett_docsis_fragments,
      &ett_addr
  };

  module_t *docsis_module;
  expert_module_t* expert_docsis;

  proto_docsis = proto_register_protocol ("DOCSIS", "DOCSIS", "docsis");
  proto_register_field_array (proto_docsis, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  /* register expert notifications */
  expert_docsis = expert_register_protocol(proto_docsis);
  expert_register_field_array(expert_docsis, ei, array_length(ei));

  /* Register configuration preferences */
  docsis_module = prefs_register_protocol(proto_docsis, NULL);
  prefs_register_bool_preference(docsis_module, "check_fcs",
                                 "Validate the DOCSIS checksum if possible",
                                 "Whether or not to validate the Header Check Sequence",
                                 &docsis_check_fcs);
   prefs_register_bool_preference(docsis_module, "dissect_encrypted_frames",
                                 "Ignore EH 'encrypted' bit",
                                 "Whether or not to attempt to dissect encrypted DOCSIS payload",
                                 &docsis_dissect_encrypted_frames);

#if 0
  docsis_dissector_table = register_dissector_table ("docsis",
                                                     "DOCSIS Encapsulation Type", proto_docsis,
                                                     FT_UINT8, BASE_DEC);
#endif

  docsis_handle = register_dissector ("docsis", dissect_docsis, proto_docsis);
  reassembly_table_register(&docsis_reassembly_table,
                        &addresses_reassembly_table_functions);
}

void
proto_reg_handoff_docsis (void)
{
  dissector_add_uint ("wtap_encap", WTAP_ENCAP_DOCSIS, docsis_handle);

  hf_docsis_dst = proto_registrar_get_id_byname ("eth.dst");
  hf_docsis_dst_resolved = proto_registrar_get_id_byname ("eth.dst_resolved");
  hf_docsis_src = proto_registrar_get_id_byname ("eth.src");
  hf_docsis_src_resolved = proto_registrar_get_id_byname ("eth.src_resolved");
  hf_docsis_lg = proto_registrar_get_id_byname ("eth.lg");
  hf_docsis_ig = proto_registrar_get_id_byname ("eth.ig");

  docsis_mgmt_handle = find_dissector ("docsis_mgmt");
  eth_withoutfcs_handle = find_dissector_add_dependency("eth_withoutfcs", proto_docsis);
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
