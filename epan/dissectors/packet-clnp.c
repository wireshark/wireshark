/* packet-clnp.c
 * Routines for ISO/OSI network protocol packet disassembly
 *
 * $Id$
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include "packet-frame.h"
#include "packet-osi.h"
#include "packet-osi-options.h"
#include "packet-isis.h"
#include "packet-esis.h"
#include <epan/nlpid.h>
#include <epan/ipproto.h>

/* protocols and fields */

static int  proto_clnp         = -1;
static gint ett_clnp           = -1;
static gint ett_clnp_type      = -1;
static gint ett_clnp_segments  = -1;
static gint ett_clnp_segment   = -1;
static gint ett_clnp_disc_pdu  = -1;

static int hf_clnp_id          = -1;
static int hf_clnp_length      = -1;
static int hf_clnp_version     = -1;
static int hf_clnp_ttl         = -1;
static int hf_clnp_type        = -1;
static int hf_clnp_cnf_segmentation         = -1;
static int hf_clnp_cnf_more_segments        = -1;
static int hf_clnp_cnf_report_error         = -1;
static int hf_clnp_cnf_type    = -1;
static int hf_clnp_pdu_length  = -1;
static int hf_clnp_checksum    = -1;
static int hf_clnp_dest_length = -1;
static int hf_clnp_dest        = -1;
static int hf_clnp_src_length  = -1;
static int hf_clnp_src         = -1;
static int hf_clnp_segments    = -1;
static int hf_clnp_segment     = -1;
static int hf_clnp_segment_overlap          = -1;
static int hf_clnp_segment_overlap_conflict = -1;
static int hf_clnp_segment_multiple_tails   = -1;
static int hf_clnp_segment_too_long_segment = -1;
static int hf_clnp_segment_error            = -1;
static int hf_clnp_segment_count            = -1;
static int hf_clnp_reassembled_in           = -1;
static int hf_clnp_reassembled_length       = -1;

static const fragment_items clnp_frag_items = {
  &ett_clnp_segment,
  &ett_clnp_segments,
  &hf_clnp_segments,
  &hf_clnp_segment,
  &hf_clnp_segment_overlap,
  &hf_clnp_segment_overlap_conflict,
  &hf_clnp_segment_multiple_tails,
  &hf_clnp_segment_too_long_segment,
  &hf_clnp_segment_error,
  &hf_clnp_segment_count,
  &hf_clnp_reassembled_in,
  &hf_clnp_reassembled_length,
  /* Reassembled data field */
  NULL,
  "segments"
};

static dissector_handle_t clnp_handle;
static dissector_handle_t ositp_handle;
static dissector_handle_t ositp_inactive_handle;
static dissector_handle_t data_handle;

/*
 * ISO 8473 OSI CLNP definition (see RFC994)
 *
 *            _________________________________
 *           |           Fixed Part            |
 *           |_________________________________|
 *           |          Address Part           |
 *           |_________________________________|
 *           |   Segmentation Part (optional)  |
 *           |_________________________________|
 *           |     Options Part (optional)     |
 *           |_________________________________|
 *           |         Data (optional)         |
 *           |_________________________________|
 */

#define ISO8473_V1  0x01    /* CLNP version 1 */

/* Fixed part */

#define CNF_TYPE                0x1f
#define CNF_ERR_OK              0x20
#define CNF_MORE_SEGS           0x40
#define CNF_SEG_OK              0x80

#define DT_NPDU                 0x1C
#define MD_NPDU                 0x1D
#define ER_NPDU                 0x01
#define ERQ_NPDU                0x1E
#define ERP_NPDU                0x1F

static const value_string npdu_type_abbrev_vals[] = {
  { DT_NPDU,    "DT" },
  { MD_NPDU,    "MD" },
  { ER_NPDU,    "ER" },
  { ERQ_NPDU,   "ERQ" },
  { ERP_NPDU,   "ERP" },
  { 0,          NULL }
};

static const value_string npdu_type_vals[] = {
  { DT_NPDU,    "Data" },
  { MD_NPDU,    "Multicast Data" },
  { ER_NPDU,    "Error Report" },
  { ERQ_NPDU,   "Echo Request" },
  { ERP_NPDU,   "Echo Response" },
  { 0,          NULL }
};

/* field position */

#define P_CLNP_PROTO_ID         0
#define P_CLNP_HDR_LEN          1
#define P_CLNP_VERS             2
#define P_CLNP_TTL              3
#define P_CLNP_TYPE             4
#define P_CLNP_SEGLEN           5
#define P_CLNP_CKSUM            7
#define P_CLNP_ADDRESS_PART     9

/* Segmentation part */

struct clnp_segment {
  gushort       cng_id;         /* data unit identifier */
  gushort       cng_off;        /* segment offset */
  gushort       cng_tot_len;    /* total length */
};

/* NSAP selector */

#define NSEL_NET                0x00
#define NSEL_NP                 0x20
#define NSEL_TP                 0x21

/* global variables */

/* List of dissectors to call for CLNP packets */
static heur_dissector_list_t clnp_heur_subdissector_list;

/*
 * Reassembly of CLNP.
 */
static GHashTable *clnp_segment_table = NULL;
static GHashTable *clnp_reassembled_table = NULL;

/* options */
static guint tp_nsap_selector = NSEL_TP;
static gboolean always_decode_transport = FALSE;
static gboolean clnp_reassemble = TRUE;

/* function definitions */

/*
 *  CLNP part / main entry point
*/

static void
dissect_clnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree     *clnp_tree = NULL;
  proto_item     *ti;
  guint8          cnf_proto_id;
  guint8          cnf_hdr_len;
  guint8          cnf_vers;
  guint8          cnf_ttl;
  guint8          cnf_type;
  char            flag_string[6+1];
  const char     *pdu_type_string;
  proto_tree     *type_tree;
  guint16         segment_length;
  guint16         du_id = 0;
  guint16         segment_offset = 0;
  guint16         cnf_cksum;
  cksum_status_t  cksum_status;
  int             offset;
  guchar          src_len, dst_len, nsel, opt_len = 0;
  const guint8   *dst_addr, *src_addr;
  guint           next_length;
  proto_tree     *discpdu_tree;
  gboolean        save_in_error_pkt;
  fragment_data  *fd_head;
  tvbuff_t       *next_tvb;
  gboolean        update_col_info = TRUE;
  gboolean        save_fragmented;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "CLNP");
  col_clear(pinfo->cinfo, COL_INFO);

  cnf_proto_id = tvb_get_guint8(tvb, P_CLNP_PROTO_ID);
  if (cnf_proto_id == NLPID_NULL) {
    col_set_str(pinfo->cinfo, COL_INFO, "Inactive subset");
    if (tree) {
      ti = proto_tree_add_item(tree, proto_clnp, tvb, P_CLNP_PROTO_ID, 1, ENC_NA);
      clnp_tree = proto_item_add_subtree(ti, ett_clnp);
      proto_tree_add_uint_format(clnp_tree, hf_clnp_id, tvb, P_CLNP_PROTO_ID, 1,
                                 cnf_proto_id,
                                 "Inactive subset");
    }
    next_tvb = tvb_new_subset_remaining(tvb, 1);
    if (call_dissector(ositp_inactive_handle, next_tvb, pinfo, tree) == 0)
      call_dissector(data_handle,tvb, pinfo, tree);
    return;
  }

  /* return if version not known */
  cnf_vers = tvb_get_guint8(tvb, P_CLNP_VERS);
  if (cnf_vers != ISO8473_V1) {
    call_dissector(data_handle,tvb, pinfo, tree);
    return;
  }

  /* fixed part decoding */
  cnf_hdr_len = tvb_get_guint8(tvb, P_CLNP_HDR_LEN);
  opt_len = cnf_hdr_len;

  if (tree) {
    ti = proto_tree_add_item(tree, proto_clnp, tvb, 0, cnf_hdr_len, ENC_NA);
    clnp_tree = proto_item_add_subtree(ti, ett_clnp);
    proto_tree_add_uint(clnp_tree, hf_clnp_id, tvb, P_CLNP_PROTO_ID, 1,
                        cnf_proto_id);
    proto_tree_add_uint(clnp_tree, hf_clnp_length, tvb, P_CLNP_HDR_LEN, 1,
                        cnf_hdr_len);
    proto_tree_add_uint(clnp_tree, hf_clnp_version, tvb, P_CLNP_VERS, 1,
                        cnf_vers);
    cnf_ttl = tvb_get_guint8(tvb, P_CLNP_TTL);
    proto_tree_add_uint_format(clnp_tree, hf_clnp_ttl, tvb, P_CLNP_TTL, 1,
                               cnf_ttl,
                               "Holding Time : %u (%u.%u secs)",
                               cnf_ttl, cnf_ttl / 2, (cnf_ttl % 2) * 5);
  }

  cnf_type = tvb_get_guint8(tvb, P_CLNP_TYPE);
  pdu_type_string = val_to_str(cnf_type & CNF_TYPE, npdu_type_abbrev_vals,
                               "Unknown (0x%02x)");
  flag_string[0] = '\0';
  if (cnf_type & CNF_SEG_OK)
    g_strlcat(flag_string, "S ", 7);
  if (cnf_type & CNF_MORE_SEGS)
    g_strlcat(flag_string, "M ", 7);
  if (cnf_type & CNF_ERR_OK)
    g_strlcat(flag_string, "E ", 7);
  if (tree) {
    ti = proto_tree_add_uint_format(clnp_tree, hf_clnp_type, tvb, P_CLNP_TYPE, 1,
                                    cnf_type,
                                    "PDU Type     : 0x%02x (%s%s)",
                                    cnf_type,
                                    flag_string,
                                    pdu_type_string);
    type_tree = proto_item_add_subtree(ti, ett_clnp_type);
    proto_tree_add_item(type_tree, hf_clnp_cnf_segmentation, tvb, P_CLNP_TYPE, 1, ENC_NA);
    proto_tree_add_item(type_tree, hf_clnp_cnf_more_segments, tvb, P_CLNP_TYPE, 1, ENC_NA);
    proto_tree_add_item(type_tree, hf_clnp_cnf_report_error, tvb, P_CLNP_TYPE, 1, ENC_NA);
    proto_tree_add_item(type_tree, hf_clnp_cnf_type, tvb, P_CLNP_TYPE, 1, ENC_NA);
  }

  /* If we don't have the full header - i.e., not enough to see the
     segmentation part and determine whether this datagram is segmented
     or not - set the Info column now; we'll get an exception before
     we set it otherwise. */

  if (tvb_length(tvb) < cnf_hdr_len) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s NPDU %s", pdu_type_string, flag_string);
  }

  segment_length = tvb_get_ntohs(tvb, P_CLNP_SEGLEN);
  cnf_cksum = tvb_get_ntohs(tvb, P_CLNP_CKSUM);
  cksum_status = calc_checksum(tvb, 0, cnf_hdr_len, cnf_cksum);
  if (tree) {
    proto_tree_add_uint(clnp_tree, hf_clnp_pdu_length, tvb, P_CLNP_SEGLEN, 2,
                        segment_length);
    switch (cksum_status) {

    default:
      /*
       * No checksum present, or not enough of the header present to
       * checksum it.
       */
      proto_tree_add_uint_format(clnp_tree, hf_clnp_checksum, tvb,
                                 P_CLNP_CKSUM, 2,
                                 cnf_cksum,
                                 "Checksum     : 0x%04x",
                                 cnf_cksum);
      break;

    case CKSUM_OK:
      /*
       * Checksum is correct.
       */
      proto_tree_add_uint_format(clnp_tree, hf_clnp_checksum, tvb,
                                 P_CLNP_CKSUM, 2,
                                 cnf_cksum,
                                 "Checksum     : 0x%04x (correct)",
                                 cnf_cksum);
      break;

    case CKSUM_NOT_OK:
      /*
       * Checksum is not correct.
       */
      proto_tree_add_uint_format(clnp_tree, hf_clnp_checksum, tvb,
                                 P_CLNP_CKSUM, 2,
                                 cnf_cksum,
                                 "Checksum     : 0x%04x (incorrect)",
                                 cnf_cksum);
      break;
    }
    opt_len -= 9; /* Fixed part of Hesder */
  } /* tree */

  /* address part */

  offset = P_CLNP_ADDRESS_PART;
  dst_len  = tvb_get_guint8(tvb, offset);
  dst_addr = tvb_get_ptr(tvb, offset + 1, dst_len);
  nsel     = tvb_get_guint8(tvb, offset + dst_len);
  src_len  = tvb_get_guint8(tvb, offset + dst_len + 1);
  src_addr = tvb_get_ptr(tvb, offset + dst_len + 2, src_len);

  if (tree) {
    proto_tree_add_uint(clnp_tree, hf_clnp_dest_length, tvb, offset, 1,
                        dst_len);
    proto_tree_add_bytes_format(clnp_tree, hf_clnp_dest, tvb, offset + 1 , dst_len,
                                dst_addr,
                                " DA : %s",
                                print_nsap_net(dst_addr, dst_len));
    proto_tree_add_uint(clnp_tree, hf_clnp_src_length, tvb,
                        offset + 1 + dst_len, 1, src_len);
    proto_tree_add_bytes_format(clnp_tree, hf_clnp_src, tvb,
                                offset + dst_len + 2, src_len,
                                src_addr,
                                " SA : %s",
                                print_nsap_net(src_addr, src_len));

    opt_len -= dst_len + src_len +2;
  }

  SET_ADDRESS(&pinfo->net_src, AT_OSI, src_len, src_addr);
  SET_ADDRESS(&pinfo->src, AT_OSI, src_len, src_addr);
  SET_ADDRESS(&pinfo->net_dst, AT_OSI, dst_len, dst_addr);
  SET_ADDRESS(&pinfo->dst, AT_OSI, dst_len, dst_addr);

  /* Segmentation Part */

  offset += dst_len + src_len + 2;

  if (cnf_type & CNF_SEG_OK) {
#if 0
    struct clnp_segment seg;                                /* XXX - not used */
    tvb_memcpy(tvb, (guint8 *)&seg, offset, sizeof(seg));   /* XXX - not used */
#endif

    segment_offset = tvb_get_ntohs(tvb, offset + 2);
    du_id = tvb_get_ntohs(tvb, offset);
    if (tree) {
      proto_tree_add_text(clnp_tree, tvb, offset, 2,
                          "Data unit identifier: %06u",
                          du_id);
      proto_tree_add_text(clnp_tree, tvb, offset + 2 , 2,
                          "Segment offset      : %6u",
                          segment_offset);
      proto_tree_add_text(clnp_tree, tvb, offset + 4 , 2,
                          "Total length        : %6u",
                          tvb_get_ntohs(tvb, offset + 4));
    }

    offset  += 6;
    opt_len -= 6;
  }

  if (tree) {
    /* To do : decode options  */
#if 0
    proto_tree_add_text(clnp_tree, tvb, offset,
                        cnf_hdr_len - offset,
                        "Options/Data: <not shown>");
#endif
/* QUICK HACK Option Len:= PDU_Hd_length-( FixedPart+AddresPart+SegmentPart )*/

    dissect_osi_options( opt_len,
                         tvb, offset, clnp_tree );
  }

  offset = cnf_hdr_len;

  /* If clnp_reassemble is on, this is a segment, we have all the
   * data in the segment, and the checksum is valid, then just add the
   * segment to the hashtable.
   */
  save_fragmented = pinfo->fragmented;
  if (clnp_reassemble && (cnf_type & CNF_SEG_OK) &&
      ((cnf_type & CNF_MORE_SEGS) || segment_offset != 0) &&
      tvb_bytes_exist(tvb, offset, segment_length - cnf_hdr_len) &&
      segment_length > cnf_hdr_len &&
      cksum_status != CKSUM_NOT_OK) {
    fd_head = fragment_add_check(tvb, offset, pinfo, du_id, clnp_segment_table,
                                 clnp_reassembled_table, segment_offset,
                                 segment_length - cnf_hdr_len,
                                 cnf_type & CNF_MORE_SEGS);

    next_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled CLNP",
                                        fd_head, &clnp_frag_items, &update_col_info, clnp_tree);
  } else {
    /* If this is the first segment, dissect its contents, otherwise
       just show it as a segment.

       XXX - if we eventually don't save the reassembled contents of all
       segmented datagrams, we may want to always reassemble. */
    if ((cnf_type & CNF_SEG_OK) && segment_offset != 0) {
      /* Not the first segment - don't dissect it. */
      next_tvb = NULL;
    } else {
      /* First segment, or not segmented.  Dissect what we have here. */

      /* Get a tvbuff for the payload. */
      next_tvb = tvb_new_subset_remaining(tvb, offset);

      /*
       * If this is the first segment, but not the only segment,
       * tell the next protocol that.
       */
      if ((cnf_type & (CNF_SEG_OK|CNF_MORE_SEGS)) == (CNF_SEG_OK|CNF_MORE_SEGS))
        pinfo->fragmented = TRUE;
      else
        pinfo->fragmented = FALSE;
    }
  }

  if (next_tvb == NULL) {
    /* Just show this as a segment. */
    col_add_fstr(pinfo->cinfo, COL_INFO, "Fragmented %s NPDU %s(off=%u)",
                 pdu_type_string, flag_string, segment_offset);

    /* As we haven't reassembled anything, we haven't changed "pi", so
       we don't have to restore it. */
    call_dissector(data_handle, tvb_new_subset_remaining(tvb, offset), pinfo,
                   tree);
    pinfo->fragmented = save_fragmented;
    return;
  }

  if (tvb_offset_exists(tvb, offset)) {
    switch (cnf_type & CNF_TYPE) {

    case DT_NPDU:
    case MD_NPDU:
      /* Continue with COTP if any data.
         XXX - if this isn't the first Derived PDU of a segmented Initial
         PDU, skip that? */

      if (nsel == (guchar)tp_nsap_selector || always_decode_transport) {
        if (call_dissector(ositp_handle, next_tvb, pinfo, tree) != 0) {
          pinfo->fragmented = save_fragmented;
          return;       /* yes, it appears to be COTP or CLTP */
        }
      }
      if (dissector_try_heuristic(clnp_heur_subdissector_list, next_tvb,
                                  pinfo, tree, NULL)) {
          pinfo->fragmented = save_fragmented;
          return;       /* yes, it appears to be one of the protocols in the heuristic list */
      }

      break;

    case ER_NPDU:
      /* The payload is the header and "none, some, or all of the data
         part of the discarded PDU", i.e. it's like an ICMP error;
         dissect it as a CLNP PDU. */

      col_add_fstr(pinfo->cinfo, COL_INFO, "%s NPDU %s", pdu_type_string, flag_string);
      next_length = tvb_length_remaining(tvb, offset);
      if (next_length != 0) {
          /* We have payload; dissect it. */
          ti = proto_tree_add_text(clnp_tree, tvb, offset, next_length,
            "Discarded PDU");
          discpdu_tree = proto_item_add_subtree(ti, ett_clnp_disc_pdu);

          /* Save the current value of the "we're inside an error packet"
             flag, and set that flag; subdissectors may treat packets
             that are the payload of error packets differently from
             "real" packets. */
          save_in_error_pkt = pinfo->flags.in_error_pkt;
          pinfo->flags.in_error_pkt = TRUE;

          call_dissector(clnp_handle, next_tvb, pinfo, discpdu_tree);

          /* Restore the "we're inside an error packet" flag. */
          pinfo->flags.in_error_pkt = save_in_error_pkt;
      }
      pinfo->fragmented = save_fragmented;
      return;   /* we're done with this PDU */

    case ERQ_NPDU:
    case ERP_NPDU:
      /* XXX - dissect this */
      break;
    }
  }
  col_add_fstr(pinfo->cinfo, COL_INFO, "%s NPDU %s", pdu_type_string, flag_string);
  call_dissector(data_handle,next_tvb, pinfo, tree);
  pinfo->fragmented = save_fragmented;
} /* dissect_clnp */

static void
clnp_reassemble_init(void)
{
  fragment_table_init(&clnp_segment_table);
  reassembled_table_init(&clnp_reassembled_table);
}

void
proto_register_clnp(void)
{
  static hf_register_info hf[] = {
    { &hf_clnp_id,
      { "Network Layer Protocol Identifier", "clnp.nlpi", FT_UINT8, BASE_HEX,
        VALS(nlpid_vals), 0x0, NULL, HFILL }},

    { &hf_clnp_length,
      { "HDR Length", "clnp.len",          FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_clnp_version,
      { "Version", "clnp.version",  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_clnp_ttl,
      { "Holding Time", "clnp.ttl",        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_clnp_type,
      { "PDU Type", "clnp.type",     FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_clnp_cnf_segmentation,
      { "Segmentation permitted", "clnp.cnf.segmentation", FT_BOOLEAN, 8, TFS(&tfs_yes_no), CNF_SEG_OK, NULL, HFILL }},

    { &hf_clnp_cnf_more_segments,
      { "More segments", "clnp.cnf.more_segments", FT_BOOLEAN, 8, TFS(&tfs_yes_no), CNF_MORE_SEGS, NULL, HFILL }},

    { &hf_clnp_cnf_report_error,
      { "Report error if PDU discarded", "clnp.cnf.report_error", FT_BOOLEAN, 8, TFS(&tfs_yes_no), CNF_ERR_OK, NULL, HFILL }},

    { &hf_clnp_cnf_type,
      { "Type", "clnp.cnf.type", FT_UINT8, BASE_DEC, VALS(npdu_type_vals), CNF_TYPE, NULL, HFILL }},

    { &hf_clnp_pdu_length,
      { "PDU length", "clnp.pdu.len",  FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_clnp_checksum,
      { "Checksum", "clnp.checksum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_clnp_dest_length,
      { "DAL", "clnp.dsap.len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_clnp_dest,
      { "DA", "clnp.dsap",     FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_clnp_src_length,
      { "SAL", "clnp.ssap.len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_clnp_src,
      { "SA", "clnp.ssap",     FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_clnp_segment_overlap,
      { "Segment overlap", "clnp.segment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "Segment overlaps with other segments", HFILL }},

    { &hf_clnp_segment_overlap_conflict,
      { "Conflicting data in segment overlap", "clnp.segment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "Overlapping segments contained conflicting data", HFILL }},

    { &hf_clnp_segment_multiple_tails,
      { "Multiple tail segments found", "clnp.segment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "Several tails were found when reassembling the packet", HFILL }},

    { &hf_clnp_segment_too_long_segment,
      { "Segment too long", "clnp.segment.toolongsegment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "Segment contained data past end of packet", HFILL }},

    { &hf_clnp_segment_error,
      { "Reassembly error", "clnp.segment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "Reassembly error due to illegal segments", HFILL }},

    { &hf_clnp_segment_count,
      { "Segment count", "clnp.segment.count", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_clnp_segment,
      { "CLNP Segment", "clnp.segment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_clnp_segments,
      { "CLNP Segments", "clnp.segments", FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_clnp_reassembled_in,
      { "Reassembled CLNP in frame", "clnp.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "This CLNP packet is reassembled in this frame", HFILL }},

    { &hf_clnp_reassembled_length,
      { "Reassembled CLNP length", "clnp.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0,
        "The total length of the reassembled payload", HFILL }}
  };
  static gint *ett[] = {
    &ett_clnp,
    &ett_clnp_type,
    &ett_clnp_segments,
    &ett_clnp_segment,
    &ett_clnp_disc_pdu,
  };

  module_t *clnp_module;

  proto_clnp = proto_register_protocol(PROTO_STRING_CLNP, "CLNP", "clnp");
  proto_register_field_array(proto_clnp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_dissector("clnp", dissect_clnp, proto_clnp);
  register_heur_dissector_list("clnp", &clnp_heur_subdissector_list);
  register_init_routine(clnp_reassemble_init);

  clnp_module = prefs_register_protocol(proto_clnp, NULL);
  prefs_register_uint_preference(clnp_module, "tp_nsap_selector",
        "NSAP selector for Transport Protocol (last byte in hex)",
        "NSAP selector for Transport Protocol (last byte in hex)",
        16, &tp_nsap_selector);
  prefs_register_bool_preference(clnp_module, "always_decode_transport",
        "Always try to decode NSDU as transport PDUs",
        "Always try to decode NSDU as transport PDUs",
        &always_decode_transport);
  prefs_register_bool_preference(clnp_module, "reassemble",
        "Reassemble segmented CLNP datagrams",
        "Whether segmented CLNP datagrams should be reassembled",
        &clnp_reassemble);
}

void
proto_reg_handoff_clnp(void)
{
  ositp_handle = find_dissector("ositp");
  ositp_inactive_handle = find_dissector("ositp_inactive");
  data_handle = find_dissector("data");

  clnp_handle = create_dissector_handle(dissect_clnp, proto_clnp);
  dissector_add_uint("osinl", NLPID_ISO8473_CLNP, clnp_handle);
  dissector_add_uint("osinl", NLPID_NULL, clnp_handle); /* Inactive subset */
  dissector_add_uint("x.25.spi", NLPID_ISO8473_CLNP, clnp_handle);
}
