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

void proto_register_tftp(void);

/* Things we may want to remember for a whole conversation */
typedef struct _tftp_conv_info_t {
  guint16      blocksize;
  const guint8 *source_file, *destination_file;
  gboolean     tsize_requested;
  guint16      prev_opcode;

  /* Sequence analysis */
  guint32      next_block_num;
  gboolean     blocks_missing;

  /* When exporting file object, build up list of data blocks here */
  guint32      next_tap_block_num;
  GSList       *block_list;
  guint        file_length;
} tftp_conv_info_t;


static int proto_tftp = -1;
static int hf_tftp_opcode = -1;
static int hf_tftp_source_file = -1;
static int hf_tftp_destination_file = -1;
static int hf_tftp_transfer_type = -1;
static int hf_tftp_blocknum = -1;
static int hf_tftp_full_blocknum = -1;
static int hf_tftp_error_code = -1;
static int hf_tftp_error_string = -1;
static int hf_tftp_option_name = -1;
static int hf_tftp_option_value = -1;
static int hf_tftp_data = -1;

static gint ett_tftp = -1;
static gint ett_tftp_option = -1;

static expert_field ei_tftp_error = EI_INIT;
static expert_field ei_tftp_likely_tsize_probe = EI_INIT;
static expert_field ei_tftp_blocksize_range = EI_INIT;
static expert_field ei_tftp_blocknum_will_wrap = EI_INIT;

#define LIKELY_TSIZE_PROBE_KEY 0
#define FULL_BLOCKNUM_KEY 1

static dissector_handle_t tftp_handle;

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

/* A list of block list entries to delete from cleanup callback when window is closed. */
typedef struct eo_info_dynamic_t {
    gchar  *filename;
    GSList *block_list;
} eo_info_dynamic_t;
static GSList *s_dynamic_info_list = NULL;

/* Used for TFTP Export Object feature */
typedef struct _tftp_eo_t {
	guint32  pkt_num;
	gchar    *filename;
	guint32  payload_len;
	GSList   *block_list;
} tftp_eo_t;

/* Tap function */
static tap_packet_status
tftp_eo_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *data)
{
  export_object_list_t *object_list = (export_object_list_t *)tapdata;
  const tftp_eo_t *eo_info = (const tftp_eo_t *)data;
  export_object_entry_t *entry;

  GSList *block_iterator;
  guint  payload_data_offset = 0;
  eo_info_dynamic_t *dynamic_info;

  /* These values will be freed when the Export Object window is closed. */
  entry = g_new(export_object_entry_t, 1);

  /* Remember which frame had the last block of the file */
  entry->pkt_num = pinfo->num;

  /* Copy filename */
  entry->filename = g_path_get_basename(eo_info->filename);

  /* Iterate over list of blocks and concatenate into contiguous memory */
  entry->payload_len = eo_info->payload_len;
  entry->payload_data = (guint8 *)g_try_malloc((gsize)entry->payload_len);
  for (block_iterator = eo_info->block_list; block_iterator; block_iterator = block_iterator->next) {
    GByteArray *block = (GByteArray*)block_iterator->data;
    memcpy(entry->payload_data + payload_data_offset,
               block->data,
               block->len);
    payload_data_offset += block->len;
  }

  /* These 2 fields not used */
  entry->hostname = NULL;
  entry->content_type = NULL;

  /* Add to list of entries to be cleaned up.  eo_info is only packet scope, so
     need to make list only of block list now */
  dynamic_info = g_new(eo_info_dynamic_t, 1);
  dynamic_info->filename = eo_info->filename;
  dynamic_info->block_list = eo_info->block_list;
  s_dynamic_info_list = g_slist_append(s_dynamic_info_list, (eo_info_dynamic_t*)dynamic_info);

  /* Pass out entry to the GUI */
  object_list->add_entry(object_list->gui_data, entry);

  return TAP_PACKET_REDRAW; /* State changed - window should be redrawn */
}

/* Clean up the stored parts of a single tapped entry */
static void cleanup_tftp_eo(eo_info_dynamic_t *dynamic_info)
{
  GSList *block_iterator;
  /* Free the filename */
  g_free(dynamic_info->filename);

  /* Walk list of block items */
  for (block_iterator = dynamic_info->block_list; block_iterator; block_iterator = block_iterator->next) {
    GByteArray *block = (GByteArray*)(block_iterator->data);
    /* Free block data and the block itself */
    g_byte_array_free(block, TRUE);
  }
}

/* Callback for freeing up data supplied with taps.  The taps themselves only have
   packet scope, so only store/free dynamic memory pointers */
static void tftp_eo_cleanup(void)
{
  /* Cleanup each entry in the global list */
  GSList *dynamic_iterator;
  for (dynamic_iterator = s_dynamic_info_list; dynamic_iterator; dynamic_iterator = dynamic_iterator->next) {
    eo_info_dynamic_t *dynamic_info = (eo_info_dynamic_t*)dynamic_iterator->data;
    cleanup_tftp_eo(dynamic_info);
  }
  /* List is empty again */
  s_dynamic_info_list = NULL;
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
       tvb_format_text() creates a temporary 0-terminated buffer */
    optionname = tvb_format_text(tvb, offset, option_len-1);
    optionvalue = tvb_format_text(tvb, value_offset, value_len-1);
    opt_tree = proto_tree_add_subtree_format(tree, tvb, offset, option_len+value_len,
                                   ett_tftp_option, NULL, "Option: %s = %s", optionname, optionvalue);

    proto_tree_add_item(opt_tree, hf_tftp_option_name, tvb, offset,
                        option_len, ENC_ASCII|ENC_NA);
    proto_tree_add_item(opt_tree, hf_tftp_option_value, tvb, value_offset,
                        value_len, ENC_ASCII|ENC_NA);

    offset += option_len + value_len;

    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s=%s",
                    optionname, optionvalue);

    /* Special code to handle individual options */
    if (!g_ascii_strcasecmp((const char *)optionname, "blksize") &&
        opcode == TFTP_OACK) {
      gint blocksize = (gint)strtol((const char *)optionvalue, NULL, 10);
      if (blocksize < 8 || blocksize > 65464) {
        expert_add_info(pinfo, NULL, &ei_tftp_blocksize_range);
      } else {
        tftp_info->blocksize = blocksize;
      }
    } else if (!g_ascii_strcasecmp((const char *)optionname, "tsize") &&
               opcode == TFTP_RRQ) {
      tftp_info->tsize_requested = TRUE;
    }
  }
}

static void cleanup_tftp_blocks(tftp_conv_info_t *conv)
{
    GSList *block_iterator;

    /* Walk list of block items */
    for (block_iterator = conv->block_list; block_iterator; block_iterator = block_iterator->next) {
        GByteArray *block = (GByteArray*)block_iterator->data;
        /* Free block data and the block itself */
        g_byte_array_free(block, TRUE);
    }
    conv->block_list = NULL;
    conv->file_length = 0;
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
  proto_item *ti;
  proto_item *blocknum_item;
  gint        offset    = 0;
  guint16     opcode;
  guint16     bytes;
  guint32     blocknum;
  guint       i1;
  guint16     error;
  tvbuff_t    *data_tvb = NULL;
  gboolean    likely_tsize_probe;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "TFTP");

  /* Protocol root */
  ti = proto_tree_add_item(tree, proto_tftp, tvb, offset, -1, ENC_NA);
  tftp_tree = proto_item_add_subtree(ti, ett_tftp);

  /* Opcode */
  opcode = tvb_get_ntohs(tvb, offset);
  proto_tree_add_uint(tftp_tree, hf_tftp_opcode, tvb, offset, 2, opcode);
  col_add_str(pinfo->cinfo, COL_INFO,
              val_to_str(opcode, tftp_opcode_vals, "Unknown (0x%04x)"));
  offset += 2;

  /* read and write requests contain file names
     for other messages, we add the filenames from the conversation */
  if (opcode!=TFTP_RRQ && opcode!=TFTP_WRQ) {
    if (tftp_info->source_file) {
      ti = proto_tree_add_string(tftp_tree, hf_tftp_source_file, tvb,
          0, 0, tftp_info->source_file);
      PROTO_ITEM_SET_GENERATED(ti);
    }

    if (tftp_info->destination_file) {
      ti = proto_tree_add_string(tftp_tree, hf_tftp_destination_file, tvb,
          0, 0, tftp_info->destination_file);
      PROTO_ITEM_SET_GENERATED(ti);
    }
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

    col_append_fstr(pinfo->cinfo, COL_INFO, ", File: %s",
                    tvb_format_stringzpad(tvb, offset, i1));

    offset += i1;

    i1 = tvb_strsize(tvb, offset);
    proto_tree_add_item(tftp_tree, hf_tftp_transfer_type,
                        tvb, offset, i1, ENC_ASCII|ENC_NA);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Transfer type: %s",
                    tvb_format_stringzpad(tvb, offset, i1));

    offset += i1;

    tftp_dissect_options(tvb, pinfo,  offset, tftp_tree,
                         opcode, tftp_info);
    break;

  case TFTP_WRQ:
    i1 = tvb_strsize(tvb, offset);
    proto_tree_add_item_ret_string(tftp_tree, hf_tftp_destination_file,
                        tvb, offset, i1, ENC_ASCII|ENC_NA, wmem_file_scope(), &tftp_info->destination_file);

    tftp_info->source_file = NULL; /* see above */

    col_append_fstr(pinfo->cinfo, COL_INFO, ", File: %s",
                    tvb_format_stringzpad(tvb, offset, i1));

    offset += i1;

    i1 = tvb_strsize(tvb, offset);
    proto_tree_add_item(tftp_tree, hf_tftp_transfer_type,
                        tvb, offset, i1, ENC_ASCII|ENC_NA);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Transfer type: %s",
                    tvb_format_stringzpad(tvb, offset, i1));

    offset += i1;

    tftp_dissect_options(tvb, pinfo, offset, tftp_tree,
                         opcode,  tftp_info);
    break;

  case TFTP_INFO:
    tftp_dissect_options(tvb, pinfo, offset, tftp_tree,
                         opcode,  tftp_info);
    break;

  case TFTP_DATA:
    blocknum_item = proto_tree_add_item_ret_uint(tftp_tree, hf_tftp_blocknum, tvb, offset, 2,
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
    PROTO_ITEM_SET_GENERATED(ti);

    /* Sequence analysis on blocknums (first pass only) */
    if (!PINFO_FD_VISITED(pinfo)) {
      if (blocknum > tftp_info->next_block_num) {
        /* There is a gap.  Don't try to recover from this. */
        tftp_info->next_block_num = blocknum + 1;
        tftp_info->blocks_missing = TRUE;
        /* TODO: add info to a result table for showing expert info in later passes */
      }
      else if (blocknum == tftp_info->next_block_num) {
        /* OK, inc what we expect next */
        tftp_info->next_block_num++;
      }
    }
    offset += 2;

    /* Show number of bytes in this block, and whether it is the end of the file */
    bytes = tvb_reported_length_remaining(tvb, offset);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Block: %u%s",
                    blocknum,
                    (bytes < tftp_info->blocksize)?" (last)":"" );

    /* Show data in tree */
    if (bytes > 0) {
      data_tvb = tvb_new_subset_length_caplen(tvb, offset, -1, bytes);
      call_data_dissector(data_tvb, pinfo, tree);
    }
    if (blocknum == 0xFFFF && bytes == tftp_info->blocksize) {
       /* There will be a block 0x10000. */
       expert_add_info(pinfo, blocknum_item, &ei_tftp_blocknum_will_wrap);
    }

    /* If Export Object tap is listening, need to accumulate blocks info list
       to send to tap. But if already know there are blocks missing, there is no
       point in trying. */
    if (have_tap_listener(tftp_eo_tap) && !tftp_info->blocks_missing) {
      if (blocknum == 1) {
        /* Reset data for this conversation, freeing any accumulated blocks! */
        cleanup_tftp_blocks(tftp_info);
        tftp_info->next_tap_block_num = 1;
      }

      if (blocknum != tftp_info->next_tap_block_num) {
        /* Ignore.  Could be missing frames, or just clicking previous frame */
        break;
      }

      if (bytes > 0) {
        /* Create a block for this block */
        GByteArray *block = g_byte_array_sized_new(bytes);
        block->len = bytes;
        tvb_memcpy(data_tvb, block->data, 0, bytes);

        /* Add to the end of the list (does involve traversing whole list..) */
        tftp_info->block_list = g_slist_append(tftp_info->block_list, block);
        tftp_info->file_length += bytes;

        /* Look for next blocknum next time */
        tftp_info->next_tap_block_num++;
      }

      /* Tap export object only when reach end of file */
      if (bytes < tftp_info->blocksize) {
        tftp_eo_t        *eo_info;

        /* If don't have a filename, won't tap file info */
        if ((tftp_info->source_file == NULL) && (tftp_info->destination_file == NULL)) {
            cleanup_tftp_blocks(tftp_info);
            break;
        }

        /* Create the eo_info to pass to the listener */
        eo_info = wmem_new(wmem_packet_scope(), tftp_eo_t);

        /* Set filename */
        if (tftp_info->source_file) {
          eo_info->filename = g_strdup(tftp_info->source_file);
        }
        else if (tftp_info->destination_file) {
          eo_info->filename = g_strdup(tftp_info->destination_file);
        }

        /* Send block list, which will be combined and freed at tap. */
        eo_info->payload_len = tftp_info->file_length;
        eo_info->pkt_num = blocknum;
        eo_info->block_list = tftp_info->block_list;

        /* Send to tap */
        tap_queue_packet(tftp_eo_tap, pinfo, eo_info);

        /* Have sent, so forget list of blocks, and only pay attention if we
           get back to the first block again. */
        tftp_info->block_list = NULL;
        tftp_info->next_tap_block_num = 1;
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
    PROTO_ITEM_SET_GENERATED(ti);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Block: %u",
                    blocknum);
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
                        i1, ENC_ASCII|ENC_NA);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Message: %s",
                    tvb_format_stringzpad(tvb, offset, i1));

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
    tftp_info->tsize_requested = FALSE;
    tftp_info->prev_opcode = TFTP_NO_OPCODE;
    tftp_info->next_block_num = 1;
    tftp_info->blocks_missing = FALSE;
    tftp_info->next_tap_block_num = 1;
    tftp_info->block_list = NULL;
    tftp_info->file_length = 0;

    conversation_add_proto_data(conversation, proto_tftp, tftp_info);
  }
  return tftp_info;
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
      {
        gint char_offset = 1;
        while (tvb_captured_length_remaining(tvb, char_offset)) {
          gchar c = (gchar)tvb_get_guint8(tvb, char_offset++);
          if (c == '\0') {
            /* NULL termination found - continue with dissection */
            break;
          }
          else if (!g_ascii_isprint(c)) {
            /* Not part of a file name - give up now */
            return FALSE;
          }
        }
        /* Would have to have a short capture length to not include the whole filename,
           but fall through here anyway rather than returning FALSE */
     }
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
  conversation_t   *conversation;

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
  if (value_is_in_range(global_tftp_port_range, pinfo->destport) ||
      (pinfo->match_uint == pinfo->destport)) {
    conversation = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst, ENDPOINT_UDP,
                                     pinfo->srcport, 0, NO_PORT_B);
    if( (conversation == NULL) || (conversation_get_dissector(conversation, pinfo->num) != tftp_handle) ){
      conversation = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst, ENDPOINT_UDP,
                                      pinfo->srcport, 0, NO_PORT2);
      conversation_set_dissector(conversation, tftp_handle);
    }
  } else {
    conversation = find_conversation_pinfo(pinfo, 0);
    if( (conversation == NULL) || (conversation_get_dissector(conversation, pinfo->num) != tftp_handle) ){
      conversation = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst, ENDPOINT_UDP,
                                      pinfo->destport, pinfo->srcport, 0);
      conversation_set_dissector(conversation, tftp_handle);
    } else if (conversation->options & NO_PORT_B) {
      if (pinfo->destport == conversation_key_port1(conversation->key_ptr))
        conversation_set_port2(conversation, pinfo->srcport);
      else
        return 0;
    }
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
  };
  static gint *ett[] = {
    &ett_tftp,
    &ett_tftp_option,
  };

  static ei_register_info ei[] = {
     { &ei_tftp_error, { "tftp.error", PI_RESPONSE_CODE, PI_WARN, "TFTP ERROR packet", EXPFILL }},
     { &ei_tftp_likely_tsize_probe, { "tftp.likely_tsize_probe", PI_REQUEST_CODE, PI_CHAT, "Likely transfer size (tsize) probe", EXPFILL }},
     { &ei_tftp_blocksize_range, { "tftp.blocksize_range", PI_RESPONSE_CODE, PI_WARN, "TFTP blocksize out of range", EXPFILL }},
     { &ei_tftp_blocknum_will_wrap, { "tftp.block.wrap", PI_SEQUENCE, PI_NOTE, "TFTP block number is about to wrap", EXPFILL }},
  };

  expert_module_t* expert_tftp;

  proto_tftp = proto_register_protocol("Trivial File Transfer Protocol", "TFTP", "tftp");
  proto_register_field_array(proto_tftp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_tftp = expert_register_protocol(proto_tftp);
  expert_register_field_array(expert_tftp, ei, array_length(ei));

  tftp_handle = register_dissector("tftp", dissect_tftp, proto_tftp);

  prefs_register_protocol(proto_tftp, apply_tftp_prefs);

  /* Register the tap for the "Export Object" function */
  tftp_eo_tap = register_export_object(proto_tftp, tftp_eo_packet, tftp_eo_cleanup);
}

void
proto_reg_handoff_tftp(void)
{
  heur_dissector_add("stun", dissect_embeddedtftp_heur, "TFTP over TURN", "tftp_stun", proto_tftp, HEURISTIC_ENABLE);

  dissector_add_uint_range_with_preference("udp.port", UDP_PORT_TFTP_RANGE, tftp_handle);
  apply_tftp_prefs();
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
