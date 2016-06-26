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

#include "packet-tftp.h"

void proto_register_tftp(void);

/* Things we may want to remember for a whole conversation */
typedef struct _tftp_conv_info_t {
  guint16      blocksize;
  const guint8 *source_file, *destination_file;

  /* Sequence analysis */
  guint        next_block_num;
  gboolean     blocks_missing;

  /* When exporting file object, build up list of data blocks here */
  guint        next_tap_block_num;
  GSList       *block_list;
  guint        file_length;
} tftp_conv_info_t;


static int proto_tftp = -1;
static int hf_tftp_opcode = -1;
static int hf_tftp_source_file = -1;
static int hf_tftp_destination_file = -1;
static int hf_tftp_transfer_type = -1;
static int hf_tftp_blocknum = -1;
static int hf_tftp_error_code = -1;
static int hf_tftp_error_string = -1;
static int hf_tftp_option_name = -1;
static int hf_tftp_option_value = -1;
static int hf_tftp_data = -1;

static gint ett_tftp = -1;
static gint ett_tftp_option = -1;

static expert_field ei_tftp_blocksize_range = EI_INIT;

static dissector_handle_t tftp_handle;

#define UDP_PORT_TFTP_RANGE    "69"

void proto_reg_handoff_tftp (void);

/* User definable values */
static range_t *global_tftp_port_range;

/* minimum length is an ACK message of 4 bytes */
#define MIN_HDR_LEN  4

#define TFTP_RRQ        1
#define TFTP_WRQ        2
#define TFTP_DATA       3
#define TFTP_ACK        4
#define TFTP_ERROR      5
#define TFTP_OACK       6
#define TFTP_INFO     255

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

#define TFTP_ERR_NOT_DEF      0
#define TFTP_ERR_NOT_FOUND    1
#define TFTP_ERR_NOT_ALLOWED  2
#define TFTP_ERR_DISK_FULL    3
#define TFTP_ERR_BAD_OP       4
#define TFTP_ERR_BAD_ID       5
#define TFTP_ERR_EXISTS       6
#define TFTP_ERR_NO_USER      7
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
    }
  }
}

static void cleanup_tftp_blocks(tftp_conv_info_t *conv)
{
    GSList *block_iterator;

    /* Walk list of block items */
    for (block_iterator = conv->block_list; block_iterator; block_iterator = block_iterator->next) {
        file_block_t *block = (file_block_t*)block_iterator->data;
        /* Free block data */
        wmem_free(NULL, block->data);

        /* Free block itself */
        g_free(block);
    }
    conv->block_list = NULL;
    conv->file_length = 0;
}


static void dissect_tftp_message(tftp_conv_info_t *tftp_info,
                                 tvbuff_t *tvb, packet_info *pinfo,
                                 proto_tree *tree)
{
  proto_tree *tftp_tree;
  proto_item *ti;
  gint        offset    = 0;
  guint16     opcode;
  guint16     bytes;
  guint16     blocknum;
  guint       i1;
  guint16     error;
  tvbuff_t    *data_tvb = NULL;

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
    blocknum = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tftp_tree, hf_tftp_blocknum, tvb, offset, 2,
                        blocknum);

    /* Sequence analysis on blocknums (first pass only) */
    if (!pinfo->fd->flags.visited) {
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
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Block: %i%s",
                    blocknum,
                    (bytes < tftp_info->blocksize)?" (last)":"" );

    /* Show data in tree */
    if (bytes > 0) {
      data_tvb = tvb_new_subset(tvb, offset, -1, bytes);
      call_data_dissector(data_tvb, pinfo, tree);
    }

    /* If Export Object tap is listening, need to accumulate blocks info list
       to send to tap. But if already know there are blocks missing, there is no
       point in trying. */
    if (have_tap_listener(tftp_eo_tap) && !tftp_info->blocks_missing) {
      file_block_t *block;

      if (blocknum == 1) {
        /* Reset data for this conversation, freeing any accumulated blocks! */
        cleanup_tftp_blocks(tftp_info);
        tftp_info->next_tap_block_num = 1;
      }

      if (blocknum != tftp_info->next_tap_block_num) {
        /* Ignore.  Could be missing frames, or just clicking previous frame */
        return;
      }

      if (bytes > 0) {
        /* Create a block for this block */
        block = (file_block_t*)g_malloc(sizeof(file_block_t));
        block->length = bytes;
        block->data = tvb_memdup(NULL, data_tvb, 0, bytes);

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
            return;
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
    blocknum = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tftp_tree, hf_tftp_blocknum, tvb, offset, 2,
                        blocknum);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Block: %i",
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

    expert_add_info(pinfo, NULL, &ei_tftp_blocksize_range);
    break;

  case TFTP_OACK:
    tftp_dissect_options(tvb, pinfo, offset, tftp_tree,
                         opcode, tftp_info);
    break;

  default:
    proto_tree_add_item(tftp_tree, hf_tftp_data, tvb, offset, -1, ENC_NA);
    break;

  }
}

static gboolean
dissect_embeddedtftp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  /* Used to dissect TFTP packets where one can not assume
     that the TFTP is the only protocol used by that port, and
     that TFTP may not be carried by UDP */
  conversation_t   *conversation = NULL;
  guint16           opcode;
  tftp_conv_info_t *tftp_info;

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

  tftp_info = (tftp_conv_info_t *)conversation_get_proto_data(conversation, proto_tftp);
  if (!tftp_info) {
    tftp_info = wmem_new(wmem_file_scope(), tftp_conv_info_t);
    tftp_info->blocksize = 512; /* TFTP default block size */
    tftp_info->source_file = NULL;
    tftp_info->destination_file = NULL;
    tftp_info->next_block_num = 1;
    tftp_info->blocks_missing = FALSE;
    tftp_info->next_tap_block_num = 1;
    tftp_info->block_list = NULL;
    tftp_info->file_length = 0;

    conversation_add_proto_data(conversation, proto_tftp, tftp_info);
  }

  dissect_tftp_message(tftp_info, tvb, pinfo, tree);
  return TRUE;
}

static int
dissect_tftp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  conversation_t   *conversation = NULL;
  tftp_conv_info_t *tftp_info;

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
    conversation = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst, PT_UDP,
                                     pinfo->srcport, 0, NO_PORT_B);
    if( (conversation == NULL) || (conversation_get_dissector(conversation, pinfo->num) != tftp_handle) ){
      conversation = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst, PT_UDP,
                                      pinfo->srcport, 0, NO_PORT2);
      conversation_set_dissector(conversation, tftp_handle);
    }
  } else {
    conversation = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
                                     pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
    if( (conversation == NULL) || (conversation_get_dissector(conversation, pinfo->num) != tftp_handle) ){
      conversation = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst, PT_UDP,
                                      pinfo->destport, pinfo->srcport, 0);
      conversation_set_dissector(conversation, tftp_handle);
    } else if (conversation->options & NO_PORT_B) {
      if (pinfo->destport == conversation->key_ptr->port1)
        conversation_set_port2(conversation, pinfo->srcport);
      else
        return 0;
    }
  }
  tftp_info = (tftp_conv_info_t *)conversation_get_proto_data(conversation, proto_tftp);
  if (!tftp_info) {
    tftp_info = wmem_new(wmem_file_scope(), tftp_conv_info_t);
    tftp_info->blocksize = 512; /* TFTP default block size */
    tftp_info->source_file = NULL;
    tftp_info->destination_file = NULL;
    tftp_info->next_block_num = 1;
    tftp_info->blocks_missing = FALSE;
    tftp_info->next_tap_block_num = 1;
    tftp_info->block_list = NULL;
    tftp_info->file_length = 0;
    conversation_add_proto_data(conversation, proto_tftp, tftp_info);
  }

  dissect_tftp_message(tftp_info, tvb, pinfo, tree);
  return tvb_captured_length(tvb);
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
      { "DESTINATION File",   "tftp.destination_file",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "TFTP source file name", HFILL }},

    { &hf_tftp_transfer_type,
      { "Type",               "tftp.type",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "TFTP transfer type", HFILL }},

    { &hf_tftp_blocknum,
      { "Block",              "tftp.block",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Block number", HFILL }},

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
     { &ei_tftp_blocksize_range, { "tftp.blocksize_range", PI_RESPONSE_CODE, PI_WARN, "TFTP blocksize out of range", EXPFILL }},
  };

  module_t *tftp_module;
  expert_module_t* expert_tftp;

  proto_tftp = proto_register_protocol("Trivial File Transfer Protocol",
                                       "TFTP", "tftp");
  proto_register_field_array(proto_tftp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_tftp = expert_register_protocol(proto_tftp);
  expert_register_field_array(expert_tftp, ei, array_length(ei));

  register_dissector("tftp", dissect_tftp, proto_tftp);

  /* Set default UDP ports */
  range_convert_str(&global_tftp_port_range, UDP_PORT_TFTP_RANGE, MAX_UDP_PORT);

  tftp_module = prefs_register_protocol(proto_tftp, proto_reg_handoff_tftp);
  prefs_register_range_preference(tftp_module, "udp_ports",
                                  "TFTP port numbers",
                                  "Port numbers used for TFTP traffic "
                                  "(default " UDP_PORT_TFTP_RANGE ")",
                                  &global_tftp_port_range, MAX_UDP_PORT);

  /* Register the tap for the "Export Object" function */
  tftp_eo_tap = register_tap("tftp_eo"); /* TFTP Export Object tap */
}

void
proto_reg_handoff_tftp(void)
{
  static range_t *tftp_port_range;
  static gboolean tftp_initialized = FALSE;

  if (!tftp_initialized) {
    tftp_handle = find_dissector("tftp");
    heur_dissector_add("stun", dissect_embeddedtftp_heur, "TFTP over TURN", "tftp_stun", proto_tftp, HEURISTIC_ENABLE);
    tftp_initialized = TRUE;
  } else {
    dissector_delete_uint_range("udp.port", tftp_port_range, tftp_handle);
    g_free(tftp_port_range);
  }

  tftp_port_range = range_copy(global_tftp_port_range);
  dissector_add_uint_range("udp.port", tftp_port_range, tftp_handle);
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
