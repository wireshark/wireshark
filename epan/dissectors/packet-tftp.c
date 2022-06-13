/* packet-tftp.c
 * Routines for tftp packet dissection
 *
 * Richard Sharpe <rsharpe@ns.aus.com>
 * Craig Newell <CraigN@cheque.uq.edu.au>
 *      RFC2347 TFTP Option Extension
 * Joerg Mayer (see AUTHORS file)
 *      RFC2348 TFTP Blocksize Option
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-bootp.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Documentation:
 * RFC 1350: THE TFTP PROTOCOL (REVISION 2)
 * RFC 2090: TFTP Multicast Option
 *           (not yet implemented)
 * RFC 2347: TFTP Option Extension
 * RFC 2348: TFTP Blocksize Option
 * RFC 2349: TFTP Timeout Interval and Transfer Size Options
 *           (not yet implemented)
 * RFC 7440: TFTP Windowsize Option
 *
 * "msftwindow" reverse-engineered from Windows Deployment Services traffic:
 *  - Requested by RRQ (or WRQ?) including "msftwindow" option, with value
 *    "31416" (round(M_PI * 10000)).
 *  - Granted by OACK including "msftwindow" option, with value "27182"
 *    (floor(e * 10000)).
 *  - Each subsequent ACK will include an extra byte carrying the next
 *    windowsize -- the number of DATA blocks expected before another ACK will
 *    be sent.
 */

#include "config.h"

#include <stdlib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/export_object.h>
#include <epan/proto_data.h>
#include <epan/reassemble.h>

#include "packet-tftp.h"

void proto_register_tftp(void);

/* Things we may want to remember for a whole conversation */
typedef struct _tftp_conv_info_t {
  guint16      blocksize;
  const guint8 *source_file, *destination_file;
  guint32      request_frame;
  gboolean     tsize_requested;
  gboolean     dynamic_windowing_active;
  guint16      windowsize;
  guint16      prev_opcode;

  /* Sequence analysis */
  guint32      next_block_num;
  gboolean     blocks_missing;
  guint        file_length;
  gboolean     last_package_available;

  /* When exporting file object, build data here */
  guint32      next_tap_block_num;
  guint8       *payload_data;

  /* Assembly of fragments */
  guint32      reassembly_id;
  guint32      last_reassembly_package;

  /* Is the TFTP payload a regular file, or a frame of a higher protocol */
  gboolean     is_simple_file;
} tftp_conv_info_t;


static int proto_tftp = -1;
static int hf_tftp_opcode = -1;
static int hf_tftp_source_file = -1;
static int hf_tftp_destination_file = -1;
static int hf_tftp_request_frame = -1;
static int hf_tftp_transfer_type = -1;
static int hf_tftp_blocknum = -1;
static int hf_tftp_full_blocknum = -1;
static int hf_tftp_nextwindowsize = -1;
static int hf_tftp_error_code = -1;
static int hf_tftp_error_string = -1;
static int hf_tftp_option_name = -1;
static int hf_tftp_option_value = -1;
static int hf_tftp_data = -1;

static int hf_tftp_fragments = -1;
static int hf_tftp_fragment = -1;
static int hf_tftp_fragment_overlap = -1;
static int hf_tftp_fragment_overlap_conflicts = -1;
static int hf_tftp_fragment_multiple_tails = -1;
static int hf_tftp_fragment_too_long_fragment = -1;
static int hf_tftp_fragment_error = -1;
static int hf_tftp_fragment_count = -1;
static int hf_tftp_reassembled_in = -1;
static int hf_tftp_reassembled_length = -1;
static int hf_tftp_reassembled_data = -1;

static gint ett_tftp = -1;
static gint ett_tftp_option = -1;

static gint ett_tftp_fragment = -1;
static gint ett_tftp_fragments = -1;

static expert_field ei_tftp_error = EI_INIT;
static expert_field ei_tftp_likely_tsize_probe = EI_INIT;
static expert_field ei_tftp_blocksize_range = EI_INIT;
static expert_field ei_tftp_blocknum_will_wrap = EI_INIT;
static expert_field ei_tftp_windowsize_range = EI_INIT;
static expert_field ei_tftp_msftwindow_unrecognized = EI_INIT;
static expert_field ei_tftp_windowsize_change = EI_INIT;

#define LIKELY_TSIZE_PROBE_KEY 0
#define FULL_BLOCKNUM_KEY 1
#define CONVERSATION_KEY 2
#define WINDOWSIZE_CHANGE_KEY 3

static dissector_handle_t tftp_handle;

static heur_dissector_list_t heur_subdissector_list;
static reassembly_table tftp_reassembly_table;

static const fragment_items tftp_frag_items = {
  &ett_tftp_fragment,
  &ett_tftp_fragments,
  &hf_tftp_fragments,
  &hf_tftp_fragment,
  &hf_tftp_fragment_overlap,
  &hf_tftp_fragment_overlap_conflicts,
  &hf_tftp_fragment_multiple_tails,
  &hf_tftp_fragment_too_long_fragment,
  &hf_tftp_fragment_error,
  &hf_tftp_fragment_count,
  &hf_tftp_reassembled_in,
  &hf_tftp_reassembled_length,
  &hf_tftp_reassembled_data,
  "TFTP fragments"
};

#define UDP_PORT_TFTP_RANGE    "69"

void proto_reg_handoff_tftp (void);

/* User definable values */
static range_t *global_tftp_port_range = NULL;

/* minimum length is an ACK message of 4 bytes */
#define MIN_HDR_LEN  4

#define TFTP_RRQ            1
#define TFTP_WRQ            2
#define TFTP_DATA           3
#define TFTP_ACK            4
#define TFTP_ERROR          5
#define TFTP_OACK           6
#define TFTP_INFO         255
#define TFTP_NO_OPCODE 0xFFFF

static const value_string tftp_opcode_vals[] = {
  { TFTP_RRQ,   "Read Request" },
  { TFTP_WRQ,   "Write Request" },
  { TFTP_DATA,  "Data Packet" },
  { TFTP_ACK,   "Acknowledgement" },
  { TFTP_ERROR, "Error Code" },
  { TFTP_OACK,  "Option Acknowledgement" },
  { TFTP_INFO,  "Information (MSDP)" },
  { 0,          NULL }
};

/* Error codes 0 through 7 are defined in RFC 1350. */
#define TFTP_ERR_NOT_DEF      0
#define TFTP_ERR_NOT_FOUND    1
#define TFTP_ERR_NOT_ALLOWED  2
#define TFTP_ERR_DISK_FULL    3
#define TFTP_ERR_BAD_OP       4
#define TFTP_ERR_BAD_ID       5
#define TFTP_ERR_EXISTS       6
#define TFTP_ERR_NO_USER      7

/* Error code 8 is defined in RFC 1782. */
#define TFTP_ERR_OPT_FAIL     8

static const value_string tftp_error_code_vals[] = {
  { TFTP_ERR_NOT_DEF,     "Not defined" },
  { TFTP_ERR_NOT_FOUND,   "File not found" },
  { TFTP_ERR_NOT_ALLOWED, "Access violation" },
  { TFTP_ERR_DISK_FULL,   "Disk full or allocation exceeded" },
  { TFTP_ERR_BAD_OP,      "Illegal TFTP Operation" },
  { TFTP_ERR_BAD_ID,      "Unknown transfer ID" }, /* Does not cause termination */
  { TFTP_ERR_EXISTS,      "File already exists" },
  { TFTP_ERR_NO_USER,     "No such user" },
  { TFTP_ERR_OPT_FAIL,    "Option negotiation failed" },
  { 0, NULL }
};

static int tftp_eo_tap = -1;

/* Preference setting - defragment fragmented TFTP files */
static gboolean tftp_defragment = FALSE;

/* Used for TFTP Export Object feature */
typedef struct _tftp_eo_t {
  gchar    *filename;
  guint32  payload_len;
  guint8   *payload_data;
} tftp_eo_t;

/* Tap function */
static tap_packet_status
tftp_eo_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *data, tap_flags_t flags _U_)
{
  export_object_list_t *object_list = (export_object_list_t *)tapdata;
  const tftp_eo_t *eo_info = (const tftp_eo_t *)data;
  export_object_entry_t *entry;

  /* These values will be freed when the Export Object window is closed. */
  entry = g_new(export_object_entry_t, 1);

  /* Remember which frame had the last block of the file */
  entry->pkt_num = pinfo->num;

  /* Copy filename */
  entry->filename = g_path_get_basename(eo_info->filename);

  /* Free up unnecessary memory */
  g_free(eo_info->filename);

  /* Pass out the contiguous data and length already accumulated. */
  entry->payload_len = eo_info->payload_len;
  entry->payload_data = eo_info->payload_data;

  /* These 2 fields not used */
  entry->hostname = NULL;
  entry->content_type = NULL;

  /* Pass out entry to the GUI */
  object_list->add_entry(object_list->gui_data, entry);

  return TAP_PACKET_REDRAW; /* State changed - window should be redrawn */
}

static void
tftp_dissect_options(tvbuff_t *tvb, packet_info *pinfo, int offset,
                     proto_tree *tree, guint16 opcode, tftp_conv_info_t *tftp_info)
{
  int         option_len, value_len;
  int         value_offset;
  const char *optionname;
  const char *optionvalue;
  proto_tree *opt_tree;

  while (tvb_offset_exists(tvb, offset)) {
    /* option_len and value_len include the trailing 0 byte */
    option_len = tvb_strsize(tvb, offset);
    value_offset = offset + option_len;
    value_len = tvb_strsize(tvb, value_offset);
    /* use xxx_len-1 to exclude the trailing 0 byte, it would be
       displayed as nonprinting character
       tvb_format_text(pinfo->pool, ) creates a temporary 0-terminated buffer */
    optionname = tvb_format_text(pinfo->pool, tvb, offset, option_len-1);
    optionvalue = tvb_format_text(pinfo->pool, tvb, value_offset, value_len-1);
    opt_tree = proto_tree_add_subtree_format(tree, tvb, offset, option_len+value_len,
                                   ett_tftp_option, NULL, "Option: %s = %s", optionname, optionvalue);

    proto_tree_add_item(opt_tree, hf_tftp_option_name, tvb, offset,
                        option_len, ENC_ASCII);
    proto_tree_add_item(opt_tree, hf_tftp_option_value, tvb, value_offset,
                        value_len, ENC_ASCII);

    offset += option_len + value_len;

    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s=%s",
                    optionname, optionvalue);

    /* Special code to handle individual options */
    if ((opcode == TFTP_RRQ || opcode == TFTP_WRQ)) {
      if (!g_ascii_strcasecmp((const char *)optionname, "msftwindow")) {
        if (g_strcmp0((const char *)optionvalue, "31416")) {
          expert_add_info(pinfo, opt_tree, &ei_tftp_msftwindow_unrecognized);
        }
      } else if (!g_ascii_strcasecmp((const char *)optionname, "windowsize")) {
        gint windowsize = (gint)strtol((const char *)optionvalue, NULL, 10);
        if (windowsize < 1 || windowsize > 65535) {
          expert_add_info(pinfo, opt_tree, &ei_tftp_windowsize_range);
        }
      }
    } else if (opcode == TFTP_OACK) {
      if (!g_ascii_strcasecmp((const char *)optionname, "blksize")) {
        gint blocksize = (gint)strtol((const char *)optionvalue, NULL, 10);
        if (blocksize < 8 || blocksize > 65464) {
          expert_add_info(pinfo, opt_tree, &ei_tftp_blocksize_range);
        } else {
          tftp_info->blocksize = blocksize;
        }
      } else if (!g_ascii_strcasecmp((const char *)optionname, "windowsize")) {
        gint windowsize = (gint)strtol((const char *)optionvalue, NULL, 10);
        if (windowsize < 1 || windowsize > 65535) {
          expert_add_info(pinfo, opt_tree, &ei_tftp_windowsize_range);
        } else {
          tftp_info->windowsize = windowsize;
        }
      } else if (!g_ascii_strcasecmp((const char *)optionname, "msftwindow")) {
        if (!g_strcmp0((const char *)optionvalue, "27182")) {
          tftp_info->dynamic_windowing_active = TRUE;
        } else {
          expert_add_info(pinfo, opt_tree, &ei_tftp_msftwindow_unrecognized);
        }
      }
    } else if (!g_ascii_strcasecmp((const char *)optionname, "tsize") &&
               opcode == TFTP_RRQ) {
      tftp_info->tsize_requested = TRUE;
    }
  }
}

static gboolean
error_is_likely_tsize_probe(guint16 error, const tftp_conv_info_t *tftp_info)
{
  /*
   * The TFTP protocol does not define an explicit "close" for non-error
   * conditions, but it is traditionally implemented as an ERROR packet with
   * code zero (not defined) or 8 (option negotiation failed).  It is usually
   * produced when a client did not intend to proceed with a transfer, but was
   * just querying the transfer size ("tsize") through Option Negotiation.  The
   * ERROR packet would be observed directly after an OACK (when the server
   * supports Option Negotiation) or directly after DATA block #1 (when the
   * server does not support Option Negotiation).
   *
   * Inspect the state of the connection to see whether the ERROR packet would
   * most likely just be a request to close the connection after a transfer
   * size query.
   */
  if (error != TFTP_ERR_OPT_FAIL && error != TFTP_ERR_NOT_DEF) {
    return FALSE;
  }

  if (tftp_info->source_file != NULL && tftp_info->tsize_requested) {
    /* There was an earlier RRQ requesting the transfer size. */
    if (tftp_info->prev_opcode == TFTP_OACK) {
      /* Response to RRQ when server supports Option Negotiation. */
      return TRUE;
    }
    if (tftp_info->prev_opcode == TFTP_DATA && tftp_info->next_block_num == 2) {
      /* Response to RRQ when server doesn't support Option Negotiation. */
      return TRUE;
    }
  }
  return FALSE;
}

static guint32
determine_full_blocknum(guint16 blocknum, const tftp_conv_info_t *tftp_info)
{
  /*
   * 'blocknum' might have wrapped around after extending beyond 16 bits.  Use
   * the rest of the conversation state to recover any missing bits.
   */
  gint16 delta = (gint16)(tftp_info->next_block_num - blocknum);
  if (delta > (gint32)tftp_info->next_block_num) {
    /* Avoid wrapping back across 0. */
    return blocknum;
  }
  return tftp_info->next_block_num - delta;
}

static void dissect_tftp_message(tftp_conv_info_t *tftp_info,
                                 tvbuff_t *tvb, packet_info *pinfo,
                                 proto_tree *tree)
{
  proto_tree *tftp_tree;
  proto_item *root_ti;
  proto_item *ti;
  proto_item *blocknum_item;
  gint        offset    = 0;
  guint16     opcode;
  const char  *filename = NULL;
  guint16     bytes;
  guint32     blocknum;
  guint       i1;
  guint16     error;
  gboolean    likely_tsize_probe;
  gboolean    is_last_package;
  gboolean    is_fragmented;
  tvbuff_t    *next_tvb;
  fragment_head *tftpfd_head = NULL;
  heur_dtbl_entry_t *hdtbl_entry;
  struct tftpinfo tftpinfo;
  guint32     payload_data_offset;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "TFTP");

  /* Protocol root */
  root_ti = proto_tree_add_item(tree, proto_tftp, tvb, offset, -1, ENC_NA);
  tftp_tree = proto_item_add_subtree(root_ti, ett_tftp);

  /* Opcode */
  opcode = tvb_get_ntohs(tvb, offset);
  proto_tree_add_uint(tftp_tree, hf_tftp_opcode, tvb, offset, 2, opcode);
  col_add_str(pinfo->cinfo, COL_INFO,
              val_to_str(opcode, tftp_opcode_vals, "Unknown (0x%04x)"));
  offset += 2;

  /* read and write requests contain file names
     for other messages, we add the filenames from the conversation */
  if (tftp_info->request_frame != 0 && opcode != TFTP_RRQ && opcode != TFTP_WRQ) {
    if (tftp_info->source_file) {
      filename = tftp_info->source_file;
    } else if (tftp_info->destination_file) {
      filename = tftp_info->destination_file;
    }

    ti = proto_tree_add_string(tftp_tree, hf_tftp_destination_file, tvb, 0, 0, filename);
    proto_item_set_generated(ti);

    ti = proto_tree_add_uint_format(tftp_tree, hf_tftp_request_frame,
                                    tvb, 0, 0, tftp_info->request_frame,
                                    "%s in frame %u",
                                    tftp_info->source_file ? "Read Request" : "Write Request",
                                    tftp_info->request_frame);
    proto_item_set_generated(ti);
  }

  switch (opcode) {

  case TFTP_RRQ:
    i1 = tvb_strsize(tvb, offset);
    proto_tree_add_item_ret_string(tftp_tree, hf_tftp_source_file,
                        tvb, offset, i1, ENC_ASCII|ENC_NA, wmem_file_scope(), &tftp_info->source_file);

    /* we either have a source file name (for read requests) or a
       destination file name (for write requests)
       when we set one of the names, we clear the other */
    tftp_info->destination_file = NULL;
    tftp_info->request_frame = pinfo->num;

    col_append_fstr(pinfo->cinfo, COL_INFO, ", File: %s",
                    tvb_format_stringzpad(pinfo->pool, tvb, offset, i1));

    offset += i1;

    i1 = tvb_strsize(tvb, offset);
    proto_tree_add_item(tftp_tree, hf_tftp_transfer_type,
                        tvb, offset, i1, ENC_ASCII);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Transfer type: %s",
                    tvb_format_stringzpad(pinfo->pool, tvb, offset, i1));

    offset += i1;

    tftp_dissect_options(tvb, pinfo,  offset, tftp_tree,
                         opcode, tftp_info);
    break;

  case TFTP_WRQ:
    i1 = tvb_strsize(tvb, offset);
    proto_tree_add_item_ret_string(tftp_tree, hf_tftp_destination_file,
                        tvb, offset, i1, ENC_ASCII|ENC_NA, wmem_file_scope(), &tftp_info->destination_file);

    tftp_info->source_file = NULL; /* see above */
    tftp_info->request_frame = pinfo->num;

    col_append_fstr(pinfo->cinfo, COL_INFO, ", File: %s",
                    tvb_format_stringzpad(pinfo->pool, tvb, offset, i1));

    offset += i1;

    i1 = tvb_strsize(tvb, offset);
    proto_tree_add_item(tftp_tree, hf_tftp_transfer_type,
                        tvb, offset, i1, ENC_ASCII);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Transfer type: %s",
                    tvb_format_stringzpad(pinfo->pool, tvb, offset, i1));

    offset += i1;

    tftp_dissect_options(tvb, pinfo, offset, tftp_tree,
                         opcode,  tftp_info);
    break;

  case TFTP_INFO:
    tftp_dissect_options(tvb, pinfo, offset, tftp_tree,
                         opcode,  tftp_info);
    break;

  case TFTP_DATA:
    proto_item_set_len(root_ti, 4);
    blocknum_item = proto_tree_add_item_ret_uint(tftp_tree, hf_tftp_blocknum, tvb, offset, 2,
                                                 ENC_BIG_ENDIAN, &blocknum);
    offset += 2;

    if (!PINFO_FD_VISITED(pinfo)) {
      blocknum = determine_full_blocknum(blocknum, tftp_info);
      p_add_proto_data(wmem_file_scope(), pinfo, proto_tftp, FULL_BLOCKNUM_KEY,
                       GUINT_TO_POINTER(blocknum));
    } else {
      blocknum = GPOINTER_TO_UINT(p_get_proto_data(wmem_file_scope(), pinfo,
                                                   proto_tftp, FULL_BLOCKNUM_KEY));
    }
    ti = proto_tree_add_uint(tftp_tree, hf_tftp_full_blocknum, tvb, 0, 0,
                             blocknum);
    proto_item_set_generated(ti);

    bytes = tvb_reported_length_remaining(tvb, offset);
    is_last_package = (bytes < tftp_info->blocksize);

    /* Sequence analysis on blocknums (first pass only) */
    if (!PINFO_FD_VISITED(pinfo)) {
      tftp_info->last_package_available |= is_last_package;
      if (blocknum > tftp_info->next_block_num) {
        /* There is a gap.  Don't try to recover from this. */
        tftp_info->next_block_num = blocknum + 1;
        tftp_info->blocks_missing = TRUE;
        /* TODO: add info to a result table for showing expert info in later passes */
      }
      else if (blocknum == tftp_info->next_block_num) {
        /* OK, inc what we expect next */
        tftp_info->next_block_num++;
        tftp_info->file_length += bytes;
      }
    }

    /* Show number of bytes in this block, and whether it is the end of the file */
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Block: %u%s",
                    blocknum,
                    is_last_package ?" (last)":"" );

    is_fragmented = !(is_last_package && blocknum == 1);
    if (is_fragmented) {
      /* If tftp_defragment is on, this is a fragment,
       * then just add the fragment to the hashtable.
       */
      if (tftp_defragment && (pinfo->num <= tftp_info->last_reassembly_package)) {
        tftpfd_head = fragment_add_seq_check(&tftp_reassembly_table, tvb, offset, pinfo,
                                             tftp_info->reassembly_id, /* id */
                                             NULL,                     /* data */
                                             blocknum - 1,
                                             bytes, !is_last_package);

        next_tvb = process_reassembled_data(tvb, offset, pinfo,
                                            "Reassembled TFTP", tftpfd_head,
                                            &tftp_frag_items, NULL, tftp_tree);
      } else {
        next_tvb = NULL;
      }
    } else {
      next_tvb = tvb_new_subset_remaining(tvb, offset);
    }

    if (next_tvb == NULL) {
      /* Reassembly continues */
      call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, tree);
    } else {
      /* Reassembly completed successfully */
      tftp_info->last_reassembly_package = pinfo->num;
      if (tvb_reported_length(next_tvb) > 0) {
        tftpinfo.filename = filename;
        /* Is the payload recognised by another dissector? */
        if (!dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo,
                                     tree, &hdtbl_entry, &tftpinfo)) {
          call_data_dissector(next_tvb, pinfo, tree);
        } else {
          tftp_info->is_simple_file = FALSE;
        }
      }
    }

    if (blocknum == 0xFFFF && bytes == tftp_info->blocksize) {
       /* There will be a block 0x10000. */
       expert_add_info(pinfo, blocknum_item, &ei_tftp_blocknum_will_wrap);
    }

    /* If Export Object tap is listening, need to accumulate blocks info list
       to send to tap. But we have a number of conditions for this.
       */
    if (have_tap_listener(tftp_eo_tap) &&
        tftp_info->is_simple_file            /* This is a simple file */
        && filename != NULL                  /* There is a file name */
        && !tftp_info->blocks_missing        /* No missing blocks */
        && tftp_info->last_package_available /* Last package known */
    ) {

      if (blocknum == 1 && !tftp_info->payload_data) {
          tftp_info->payload_data = (guint8 *)g_try_malloc((gsize)tftp_info->file_length);
      }

      if (tftp_info->payload_data == NULL ||
          (blocknum != tftp_info->next_tap_block_num)) {
        /* Ignore. Not enough memory or just clicking previous frame */
        break;
      }
      payload_data_offset =
          (tftp_info->next_tap_block_num - 1) * tftp_info->blocksize;

      /* Copy data to its place in the payload_data */
      tvb_memcpy(tvb, tftp_info->payload_data + payload_data_offset, offset,
                 bytes);
      tftp_info->next_tap_block_num++;

      /* Tap export object only when reach end of file */
      if (is_last_package) {
        tftp_eo_t        *eo_info;

        /* Create the eo_info to pass to the listener */
        eo_info = wmem_new(pinfo->pool, tftp_eo_t);

        /* Set filename */
        eo_info->filename = g_strdup(filename);

        /* Set payload */
        eo_info->payload_len = tftp_info->file_length;
        eo_info->payload_data = tftp_info->payload_data;

        /* Send to tap */
        tap_queue_packet(tftp_eo_tap, pinfo, eo_info);

        /* Have sent, so forget payload_data, and only pay attention if we
           get back to the first block again. */
        tftp_info->next_tap_block_num = 1;
        tftp_info->payload_data = NULL;
      }
    }
    break;

  case TFTP_ACK:
    proto_tree_add_item_ret_uint(tftp_tree, hf_tftp_blocknum, tvb, offset, 2,
                                 ENC_BIG_ENDIAN, &blocknum);

    if (!PINFO_FD_VISITED(pinfo)) {
      blocknum = determine_full_blocknum(blocknum, tftp_info);
      p_add_proto_data(wmem_file_scope(), pinfo, proto_tftp, FULL_BLOCKNUM_KEY,
                       GUINT_TO_POINTER(blocknum));
    } else {
      blocknum = GPOINTER_TO_UINT(p_get_proto_data(wmem_file_scope(), pinfo,
                                                   proto_tftp, FULL_BLOCKNUM_KEY));
    }
    ti = proto_tree_add_uint(tftp_tree, hf_tftp_full_blocknum, tvb, 0, 0,
                             blocknum);
    proto_item_set_generated(ti);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Block: %u",
                    blocknum);
    offset += 2;

    if (tftp_info->dynamic_windowing_active && tvb_bytes_exist(tvb, offset, 1)) {
      gboolean windowsize_changed;
      guint8 windowsize = tvb_get_guint8(tvb, offset);
      ti = proto_tree_add_uint(tftp_tree, hf_tftp_nextwindowsize, tvb,
                               offset, 1, windowsize);
      if (!PINFO_FD_VISITED(pinfo)) {
        /*
         * Note changes in window size, but ignore the final ACK which includes
         * an unnecessary (and seemingly bogus) window size.
         */
        windowsize_changed = windowsize != tftp_info->windowsize &&
                             !tftp_info->last_package_available;
        if (windowsize_changed) {
          p_add_proto_data(wmem_file_scope(), pinfo, proto_tftp,
                           WINDOWSIZE_CHANGE_KEY, GUINT_TO_POINTER(1));
          tftp_info->windowsize = windowsize;
        }
      } else {
        windowsize_changed = p_get_proto_data(wmem_file_scope(), pinfo, proto_tftp, WINDOWSIZE_CHANGE_KEY) != NULL;
      }

      if (windowsize_changed) {
        expert_add_info(pinfo, ti, &ei_tftp_windowsize_change);
      }
    }
    break;

  case TFTP_ERROR:
    error = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tftp_tree, hf_tftp_error_code, tvb, offset, 2,
                        error);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Code: %s",
                    val_to_str(error, tftp_error_code_vals, "Unknown (%u)"));

    offset += 2;

    i1 = tvb_strsize(tvb, offset);
    proto_tree_add_item(tftp_tree, hf_tftp_error_string, tvb, offset,
                        i1, ENC_ASCII);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Message: %s",
                    tvb_format_stringzpad(pinfo->pool, tvb, offset, i1));

    /*
     * If the packet looks like an intentional "close" after a transfer-size
     * probe, don't report it as an error.
     */

    if (!PINFO_FD_VISITED(pinfo)) {
      likely_tsize_probe = error_is_likely_tsize_probe(error, tftp_info);
      if (likely_tsize_probe) {
        p_add_proto_data(wmem_file_scope(), pinfo, proto_tftp, LIKELY_TSIZE_PROBE_KEY, GUINT_TO_POINTER(1));
      }
    } else {
      likely_tsize_probe = GPOINTER_TO_UINT(p_get_proto_data(wmem_file_scope(), pinfo, proto_tftp,
                                                             LIKELY_TSIZE_PROBE_KEY)) != 0;
    }

    expert_add_info(pinfo, tftp_tree, likely_tsize_probe ? &ei_tftp_likely_tsize_probe : &ei_tftp_error);
    break;

  case TFTP_OACK:
    tftp_dissect_options(tvb, pinfo, offset, tftp_tree,
                         opcode, tftp_info);
    break;

  default:
    proto_tree_add_item(tftp_tree, hf_tftp_data, tvb, offset, -1, ENC_NA);
    break;

  }
  tftp_info->prev_opcode = opcode;
}

static tftp_conv_info_t *
tftp_info_for_conversation(conversation_t *conversation)
{
  tftp_conv_info_t *tftp_info;

  tftp_info = (tftp_conv_info_t *)conversation_get_proto_data(conversation, proto_tftp);
  if (!tftp_info) {
    tftp_info = wmem_new(wmem_file_scope(), tftp_conv_info_t);
    tftp_info->blocksize = 512; /* TFTP default block size */
    tftp_info->source_file = NULL;
    tftp_info->destination_file = NULL;
    tftp_info->request_frame = 0;
    tftp_info->tsize_requested = FALSE;
    tftp_info->dynamic_windowing_active = FALSE;
    tftp_info->windowsize = 0;
    tftp_info->prev_opcode = TFTP_NO_OPCODE;
    tftp_info->next_block_num = 1;
    tftp_info->blocks_missing = FALSE;
    tftp_info->file_length = 0;
    tftp_info->last_package_available = FALSE;
    tftp_info->next_tap_block_num = 1;
    tftp_info->payload_data = NULL;
    tftp_info->reassembly_id = conversation->conv_index;
    tftp_info->last_reassembly_package = G_MAXUINT32;
    tftp_info->is_simple_file = TRUE;
    conversation_add_proto_data(conversation, proto_tftp, tftp_info);
  }
  return tftp_info;
}

static gboolean
is_valid_request_body(tvbuff_t *tvb)
{
  gint offset = 2;
  guint zeros_counter = 0;
  for (gint i = offset; i < (gint)tvb_captured_length(tvb); ++i) {
    gchar c = (gchar)tvb_get_guint8(tvb, i);
    if (c == '\0') {
      zeros_counter++;
    } else if (!g_ascii_isprint(c)) {
      return FALSE;
    }
  }

  if (zeros_counter % 2 != 0 || zeros_counter == 0)
    return FALSE;

  offset += tvb_strsize(tvb, offset);
  guint len = tvb_strsize(tvb, offset);
  const gchar* mode = tvb_format_stringzpad(wmem_packet_scope(), tvb, offset, len);

  const gchar* modes[] = {"netscii", "octet", "mail"};
  for(guint i = 0; i < array_length(modes); ++i) {
    if (g_ascii_strcasecmp(mode, modes[i]) == 0) return TRUE;
  }

  return FALSE;
}

static gboolean
is_valid_request(tvbuff_t *tvb)
{
  if (tvb_captured_length(tvb) < MIN_HDR_LEN)
    return FALSE;
  guint16 opcode = tvb_get_ntohs(tvb, 0);
  if ((opcode != TFTP_RRQ) && (opcode != TFTP_WRQ))
    return FALSE;
  return is_valid_request_body(tvb);
}

static conversation_t* create_tftp_conversation(packet_info *pinfo)
{
  conversation_t* conversation = NULL;
  if (!PINFO_FD_VISITED(pinfo)) {
    /* New read or write request on first pass, so create conversation with client port only */
    conversation = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst, ENDPOINT_UDP,
                                    pinfo->srcport, 0, NO_PORT2);
    conversation_set_dissector(conversation, tftp_handle);
    /* Store conversation in this frame */
    p_add_proto_data(wmem_file_scope(), pinfo, proto_tftp, CONVERSATION_KEY,
                     (void *)conversation);
  } else {
    /* Read or write request, but not first pass, so look up existing conversation */
    conversation = (conversation_t *)p_get_proto_data(wmem_file_scope(), pinfo,
                                                      proto_tftp, CONVERSATION_KEY);
  }
  return conversation;
}

static gboolean
dissect_tftp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  if (is_valid_request_body(tvb)) {
    conversation_t* conversation = create_tftp_conversation(pinfo);
    dissect_tftp_message(tftp_info_for_conversation(conversation), tvb, pinfo, tree);
    return TRUE;
  }
  return FALSE;
}

static gboolean
dissect_embeddedtftp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  /* Used to dissect TFTP packets where one can not assume
     that the TFTP is the only protocol used by that port, and
     that TFTP may not be carried by UDP */
  conversation_t   *conversation;
  guint16           opcode;

  /*
   * We need to verify it could be a TFTP message before creating a conversation
   */

  if (tvb_captured_length(tvb) < MIN_HDR_LEN)
    return FALSE;

  opcode = tvb_get_ntohs(tvb, 0);

  switch (opcode) {
    case TFTP_RRQ:
    case TFTP_WRQ:
      /* These 2 opcodes have a NULL-terminated source file name after opcode. Verify */
      if (!is_valid_request_body(tvb))
        return FALSE;
     /* Intentionally dropping through here... */
    case TFTP_DATA:
    case TFTP_ACK:
    case TFTP_OACK:
    case TFTP_INFO:
      break;
    case TFTP_ERROR:
      /* for an error, we can verify the error code is legit */
      switch (tvb_get_ntohs(tvb, 2)) {
        case TFTP_ERR_NOT_DEF:
        case TFTP_ERR_NOT_FOUND:
        case TFTP_ERR_NOT_ALLOWED:
        case TFTP_ERR_DISK_FULL:
        case TFTP_ERR_BAD_OP:
        case TFTP_ERR_BAD_ID:
        case TFTP_ERR_EXISTS:
        case TFTP_ERR_NO_USER:
        case TFTP_ERR_OPT_FAIL:
          break;
        default:
          return FALSE;
      }
      break;
    default:
      return FALSE;
  }

  conversation = find_or_create_conversation(pinfo);
  dissect_tftp_message(tftp_info_for_conversation(conversation), tvb, pinfo, tree);
  return TRUE;
}

static int
dissect_tftp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  conversation_t   *conversation = NULL;

  /*
   * The first TFTP packet goes to the TFTP port; the second one
   * comes from some *other* port, but goes back to the same
   * IP address and port as the ones from which the first packet
   * came; all subsequent packets go between those two IP addresses
   * and ports.
   *
   * If this packet went to the TFTP port (either to one of the ports
   * set in the preferences or to a port set via Decode As), we check
   * to see if there's already a conversation with one address/port pair
   * matching the source IP address and port of this packet,
   * the other address matching the destination IP address of this
   * packet, and any destination port.
   *
   * If not, we create one, with its address 1/port 1 pair being
   * the source address/port of this packet, its address 2 being
   * the destination address of this packet, and its port 2 being
   * wildcarded, and give it the TFTP dissector as a dissector.
   */
  if ((value_is_in_range(global_tftp_port_range, pinfo->destport) ||
       (pinfo->match_uint == pinfo->destport)) &&
      is_valid_request(tvb))
  {
    conversation = create_tftp_conversation(pinfo);
  }

  if (conversation == NULL)
  {
    /* Not the initial read or write request */
    /* Look for wildcarded conversation based upon client port */
    if ((conversation = find_conversation(pinfo->num, &pinfo->dst, &pinfo->src, ENDPOINT_UDP,
                                     pinfo->destport, 0, NO_PORT_B)) && conversation_get_dissector(conversation, pinfo->num) == tftp_handle) {
#if 0
      /* XXX: While setting the wildcarded port makes sense, if we do that,
       * it's more complicated to find the correct conversation if ports are
       * reused. (find_conversation with full information prefers any exact
       * match, even with an earlier setup frame, to any wildcarded match.)
       * We would want to find the most recent conversations with one wildcard
       * and with both ports, and take the latest of those.
       */
      /* Set other side of conversation (server port) */
      if (pinfo->destport == conversation_key_port1(conversation->key_ptr))
        conversation_set_port2(conversation, pinfo->srcport);
#endif
    } else if ((conversation = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst, ENDPOINT_UDP,
                                     pinfo->srcport, 0, NO_PORT_B)) && conversation_get_dissector(conversation, pinfo->num) == tftp_handle) {

    } else {
      /* How did we get here? We must have matched one of the TFTP ports
       * and missed the WRQ/RRQ. While it is contrary to the spirit of
       * RFC 1350 for the server not to change ports, there appear to be
       * such servers out there (issue #18122), and since the default port
       * is IANA assigned it doesn't do harm to process it. Note that in
       * that case the conversation won't have the tftp dissector set. */
      conversation = find_conversation_pinfo(pinfo, 0);
      if (conversation == NULL) {
        return 0;
      }
    }
  }

  if (pinfo->num > conversation->last_frame) {
    conversation->last_frame = pinfo->num;
  }
  dissect_tftp_message(tftp_info_for_conversation(conversation), tvb, pinfo, tree);
  return tvb_captured_length(tvb);
}


static void
apply_tftp_prefs(void) {
  global_tftp_port_range = prefs_get_range_value("tftp", "udp.port");
}

void
proto_register_tftp(void)
{
  static hf_register_info hf[] = {
    { &hf_tftp_opcode,
      { "Opcode",             "tftp.opcode",
        FT_UINT16, BASE_DEC, VALS(tftp_opcode_vals), 0x0,
        "TFTP message type", HFILL }},

    { &hf_tftp_source_file,
      { "Source File",        "tftp.source_file",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "TFTP source file name", HFILL }},

    { &hf_tftp_destination_file,
      { "Destination File",   "tftp.destination_file",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "TFTP destination file name", HFILL }},

    { &hf_tftp_request_frame,
      { "Request frame",        "tftp.request_frame",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00,
        "TFTP request is in frame", HFILL }},

    { &hf_tftp_transfer_type,
      { "Type",               "tftp.type",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "TFTP transfer type", HFILL }},

    { &hf_tftp_blocknum,
      { "Block",              "tftp.block",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Block number", HFILL }},

    { &hf_tftp_full_blocknum,
      { "Full Block Number",  "tftp.block.full",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Block number, adjusted for wrapping", HFILL }},

    { &hf_tftp_nextwindowsize,
      { "Next Window Size", "tftp.nextwindowsize",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Number of blocks in next transfer window", HFILL }},

    { &hf_tftp_error_code,
      { "Error code",         "tftp.error.code",
        FT_UINT16, BASE_DEC, VALS(tftp_error_code_vals), 0x0,
        "Error code in case of TFTP error message", HFILL }},

    { &hf_tftp_error_string,
      { "Error message",      "tftp.error.message",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "Error string in case of TFTP error message", HFILL }},

    { &hf_tftp_option_name,
      { "Option name",        "tftp.option.name",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_tftp_option_value,
      { "Option value",       "tftp.option.value",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_tftp_data,
      { "Data",       "tftp.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_tftp_fragments,
      { "TFTP Fragments",        "tftp.fragments",
        FT_NONE, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},

    { &hf_tftp_fragment,
      { "TFTP Fragment",        "tftp.fragment",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},

    { &hf_tftp_fragment_overlap,
      { "Fragment overlap",        "tftp.fragment.overlap",
        FT_BOOLEAN, 0, NULL, 0x00,
        "Fragment overlaps with other fragments", HFILL }},

    { &hf_tftp_fragment_overlap_conflicts,
      { "Conflicting data in fragment overlap",
        "tftp.fragment.overlap.conflicts",
        FT_BOOLEAN, 0, NULL, 0x00,
        "Overlapping fragments contained conflicting data", HFILL }},

    { &hf_tftp_fragment_multiple_tails,
      { "Multiple tail fragments found",        "tftp.fragment.multipletails",
        FT_BOOLEAN, 0, NULL, 0x00,
        "Several tails were found when defragmenting the packet", HFILL }},

    { &hf_tftp_fragment_too_long_fragment,
      { "Fragment too long",        "tftp.fragment.toolongfragment",
        FT_BOOLEAN, 0, NULL, 0x00,
        "Fragment contained data past end of packet", HFILL }},

    { &hf_tftp_fragment_error,
      { "Defragmentation error",        "tftp.fragment.error",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00,
        "Defragmentation error due to illegal fragments", HFILL }},

    { &hf_tftp_fragment_count,
      { "Fragment count",        "tftp.fragment.count",
        FT_UINT32, BASE_DEC, NULL, 0x00,
        NULL, HFILL }},

    { &hf_tftp_reassembled_in,
      { "Reassembled TFTP in frame",        "tftp.reassembled_in",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00,
        "This TFTP packet is reassembled in this frame", HFILL }},

    { &hf_tftp_reassembled_length,
      { "Reassembled TFTP length",        "tftp.reassembled.length",
        FT_UINT32, BASE_DEC, NULL, 0x00,
        "The total length of the reassembled payload", HFILL }},

    { &hf_tftp_reassembled_data,
      { "Reassembled TFTP data",        "tftp.reassembled.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "The reassembled payload", HFILL }},
  };
  static gint *ett[] = {
    &ett_tftp,
    &ett_tftp_option,
    &ett_tftp_fragment,
    &ett_tftp_fragments,
  };

  static ei_register_info ei[] = {
     { &ei_tftp_error, { "tftp.error", PI_RESPONSE_CODE, PI_WARN, "TFTP ERROR packet", EXPFILL }},
     { &ei_tftp_likely_tsize_probe, { "tftp.likely_tsize_probe", PI_REQUEST_CODE, PI_CHAT, "Likely transfer size (tsize) probe", EXPFILL }},
     { &ei_tftp_blocksize_range, { "tftp.blocksize_range", PI_RESPONSE_CODE, PI_WARN, "TFTP blocksize out of range", EXPFILL }},
     { &ei_tftp_blocknum_will_wrap, { "tftp.block.wrap", PI_SEQUENCE, PI_NOTE, "TFTP block number is about to wrap", EXPFILL }},
     { &ei_tftp_windowsize_range, { "tftp.windowsize_range", PI_RESPONSE_CODE, PI_WARN, "TFTP windowsize out of range", EXPFILL }},
     { &ei_tftp_msftwindow_unrecognized, { "tftp.msftwindow.unrecognized", PI_RESPONSE_CODE, PI_WARN, "Unrecognized msftwindow option", EXPFILL }},
     { &ei_tftp_windowsize_change, { "tftp.windowsize.change", PI_SEQUENCE, PI_CHAT, "TFTP window size is changing", EXPFILL }},
  };

  module_t *tftp_module;
  expert_module_t* expert_tftp;

  proto_tftp = proto_register_protocol("Trivial File Transfer Protocol", "TFTP", "tftp");
  proto_register_field_array(proto_tftp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_tftp = expert_register_protocol(proto_tftp);
  expert_register_field_array(expert_tftp, ei, array_length(ei));

  heur_subdissector_list = register_heur_dissector_list("tftp", proto_tftp);
  reassembly_table_register(&tftp_reassembly_table, &addresses_ports_reassembly_table_functions);

  tftp_handle = register_dissector("tftp", dissect_tftp, proto_tftp);

  tftp_module = prefs_register_protocol(proto_tftp, apply_tftp_prefs);
  prefs_register_bool_preference(tftp_module, "defragment",
    "Reassemble fragmented TFTP files",
    "Whether fragmented TFTP files should be reassembled", &tftp_defragment);

  /* Register the tap for the "Export Object" function */
  tftp_eo_tap = register_export_object(proto_tftp, tftp_eo_packet, NULL);
}

void
proto_reg_handoff_tftp(void)
{
  heur_dissector_add("stun", dissect_embeddedtftp_heur, "TFTP over TURN", "tftp_stun", proto_tftp, HEURISTIC_ENABLE);
  heur_dissector_add("udp", dissect_tftp_heur, "TFTP", "tftp", proto_tftp, HEURISTIC_ENABLE);

  dissector_add_uint_range_with_preference("udp.port", UDP_PORT_TFTP_RANGE, tftp_handle);
  apply_tftp_prefs();
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
