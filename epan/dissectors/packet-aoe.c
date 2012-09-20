/* packet-aoe.c
 * Routines for dissecting the ATA over Ethernet protocol.
 *   Ronnie Sahlberg 2004
 *
 * $Id$
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
#include <epan/emem.h>
#include <epan/conversation.h>
#include <etypes.h>

static int proto_aoe;
static int hf_aoe_version=-1;
static int hf_aoe_flags_response=-1;
static int hf_aoe_flags_error=-1;
static int hf_aoe_error=-1;
static int hf_aoe_major=-1;
static int hf_aoe_minor=-1;
static int hf_aoe_cmd=-1;
static int hf_aoe_tag=-1;
static int hf_aoe_aflags_e=-1;
static int hf_aoe_aflags_d=-1;
static int hf_aoe_aflags_a=-1;
static int hf_aoe_aflags_w=-1;
static int hf_aoe_err_feature=-1;
static int hf_aoe_sector_count=-1;
static int hf_aoe_acmd=-1;
static int hf_aoe_astatus=-1;
static int hf_aoe_lba=-1;
static int hf_aoe_response_in=-1;
static int hf_aoe_response_to=-1;
static int hf_aoe_time=-1;

static gint ett_aoe = -1;
static gint ett_aoe_flags = -1;

#define AOE_FLAGS_RESPONSE 0x08
#define AOE_FLAGS_ERROR    0x04

#define AOE_AFLAGS_E    0x40
#define AOE_AFLAGS_D    0x10
#define AOE_AFLAGS_A    0x02
#define AOE_AFLAGS_W    0x01

static const true_false_string tfs_aflags_e = {
  "LBA48 extended command",
  "Normal command"
};
static const true_false_string tfs_aflags_d = {
  "?",
  "?"
};
static const true_false_string tfs_aflags_a = {
  "ASYNCHRONOUS Write",
  "synchronous write"
};
static const true_false_string tfs_aflags_w = {
  "WRITE to the device",
  "No write to device"
};

static const true_false_string tfs_response = {
  "Response",
  "Request"
};

static const true_false_string tfs_error = {
  "Error",
  "No error"
};

static const value_string error_vals[] = {
  { 1, "Unrecognized command code" },
  { 2, "Bad argument parameter" },
  { 3, "Device unavailable" },
  { 4, "Config string present" },
  { 5, "Unsupported version" },
  { 0, NULL}
};

#define AOE_CMD_ISSUE_ATA_COMMAND  0
#define AOE_CMD_QUERY_CONFIG_INFO  1
static const value_string cmd_vals[] = {
  { AOE_CMD_ISSUE_ATA_COMMAND, "Issue ATA Command" },
  { AOE_CMD_QUERY_CONFIG_INFO, "Query Config Information" },
  { 0, NULL}
};

static const value_string ata_cmd_vals[] = {
  { 0x00, "NOP" },
  { 0x08, "Atapi soft reset" },
  { 0x10, "Recalibrate" },
  { 0x20, "Read sectors (with retry)" },
  { 0x21, "Read sectors (no retry)" },
  { 0x22, "Read long (with retry)" },
  { 0x23, "Read long (no retry)" },
  { 0x24, "Read ext" },
  { 0x30, "Write sectors (with retry)" },
  { 0x31, "Write sectors (no retry)" },
  { 0x32, "Write long (with retry)" },
  { 0x33, "Write long (no retry)" },
  { 0x34, "Write ext" },
  { 0x3c, "Write verify" },
  { 0x40, "Read verify sectors (with retry)" },
  { 0x41, "Read verify sectors (no retry)" },
  { 0x50, "Format track" },
  { 0x70, "Seek" },
  { 0x90, "Execute device diagnostics" },
  { 0x91, "Initialize device parameters" },
  { 0x92, "Download microcode" },
  { 0x94, "Standy immediate" },
  { 0x95, "Idle immediate" },
  { 0x96, "Standby" },
  { 0x97, "Idle" },
  { 0x98, "Check power mode" },
  { 0x99, "Sleep" },
  { 0xa0, "Atapi packet" },
  { 0xa1, "Atapi identify device" },
  { 0xa2, "Atapi service" },
  { 0xb0, "Smart" },
  { 0xc4, "Read multiple" },
  { 0xc5, "Write multiple" },
  { 0xc6, "Set multiple mode" },
  { 0xc8, "Read dma (with retry)" },
  { 0xc9, "Read dma (no retry)" },
  { 0xca, "Write dma (with retry)" },
  { 0xcb, "Write dma (no retry)" },
  { 0xde, "Door lock" },
  { 0xdf, "Door unlock" },
  { 0xe0, "Standy immediate" },
  { 0xe1, "Idle immediate" },
  { 0xe2, "Standby" },
  { 0xe3, "Idle" },
  { 0xe4, "Read buffer" },
  { 0xe5, "Check power mode" },
  { 0xe6, "Sleep" },
  { 0xe8, "Write buffer" },
  { 0xec, "Identify Device" },
  { 0xed, "Media eject" },
  { 0xee, "Identify device dma" },
  { 0xef, "Set features" },
  { 0xf1, "Security set password" },
  { 0xf2, "Security unlock" },
  { 0xf3, "Security erase prepare" },
  { 0xf4, "Security erase unit" },
  { 0xf5, "Security freeze" },
  { 0xf6, "Security disable password" },
  { 0, NULL}
};

typedef struct ata_info_t {
  guint32 tag;
  void *conversation; /* just used to multiplex different conversations */
  guint32 request_frame;
  guint32 response_frame;
  nstime_t req_time;
  guint8 cmd;
} ata_info_t;
static GHashTable *ata_cmd_unmatched = NULL;
static GHashTable *ata_cmd_matched = NULL;

static guint
ata_cmd_hash_matched(gconstpointer k)
{
  return GPOINTER_TO_UINT(k);
}

static gint
ata_cmd_equal_matched(gconstpointer k1, gconstpointer k2)
{
  return k1==k2;
}

static guint
ata_cmd_hash_unmatched(gconstpointer k)
{
  const ata_info_t *key = k;

  return key->tag;
}

static gint
ata_cmd_equal_unmatched(gconstpointer k1, gconstpointer k2)
{
  const ata_info_t *key1 = k1;
  const ata_info_t *key2 = k2;

  return (key1->tag==key2->tag)&&(key1->conversation==key2->conversation);
}

static void
dissect_ata_pdu(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gboolean response, guint32 tag)
{
  proto_item *tmp_item;
  guint8 aflags;
  guint64 lba;
  ata_info_t *ata_info=NULL;
  conversation_t *conversation;

  /* only create a conversation for ATA commands */
  conversation = find_or_create_conversation(pinfo);

  if( !(pinfo->fd->flags.visited) ){
    if(!response){
      ata_info_t *tmp_ata_info;
      /* first time we see this request so add a struct for request/response
         matching */
      ata_info=se_alloc(sizeof(ata_info_t));
      ata_info->tag=tag;
      ata_info->conversation=conversation;
      ata_info->request_frame=pinfo->fd->num;
      ata_info->response_frame=0;
      ata_info->cmd=tvb_get_guint8(tvb, offset+3);
      ata_info->req_time=pinfo->fd->abs_ts;

      tmp_ata_info=g_hash_table_lookup(ata_cmd_unmatched, ata_info);
      if(tmp_ata_info){
        g_hash_table_remove(ata_cmd_unmatched, tmp_ata_info);
      }
      g_hash_table_insert(ata_cmd_unmatched, ata_info, ata_info);
    } else {
      ata_info_t tmp_ata_info;
      /* first time we see this response so see if we can match it with
         a request */
      tmp_ata_info.tag=tag;
      tmp_ata_info.conversation=conversation;
      ata_info=g_hash_table_lookup(ata_cmd_unmatched, &tmp_ata_info);
      /* woo hoo we could, so no need to store this in unmatched any more,
         move both request and response to the matched table */
      if(ata_info){
        ata_info->response_frame=pinfo->fd->num;
        g_hash_table_remove(ata_cmd_unmatched, ata_info);
        g_hash_table_insert(ata_cmd_matched, GUINT_TO_POINTER(ata_info->request_frame), ata_info);
        g_hash_table_insert(ata_cmd_matched, GUINT_TO_POINTER(ata_info->response_frame), ata_info);
      }
    }
  } else {
    ata_info=g_hash_table_lookup(ata_cmd_matched, GUINT_TO_POINTER(pinfo->fd->num));
  }

  if(ata_info){
    if(response){
      if(ata_info->request_frame){
	nstime_t delta_ts;
        tmp_item=proto_tree_add_uint(tree, hf_aoe_response_to, tvb, 0, 0, ata_info->request_frame);
        PROTO_ITEM_SET_GENERATED(tmp_item);
		nstime_delta(&delta_ts, &pinfo->fd->abs_ts, &ata_info->req_time);
        tmp_item=proto_tree_add_time(tree, hf_aoe_time, tvb, offset, 0,	&delta_ts);
        PROTO_ITEM_SET_GENERATED(tmp_item);
      }
    } else {
      if(ata_info->response_frame){
        tmp_item=proto_tree_add_uint(tree, hf_aoe_response_in, tvb, 0, 0, ata_info->response_frame);
        PROTO_ITEM_SET_GENERATED(tmp_item);
      }
    }
  }

  /* aflags */
  aflags=tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_aoe_aflags_e, tvb, offset, 1, ENC_BIG_ENDIAN);
  if(aflags&AOE_AFLAGS_E){
    proto_tree_add_item(tree, hf_aoe_aflags_d, tvb, offset, 1, ENC_BIG_ENDIAN);
  }
  if(aflags&AOE_AFLAGS_W){
    proto_tree_add_item(tree, hf_aoe_aflags_a, tvb, offset, 1, ENC_BIG_ENDIAN);
  }
  proto_tree_add_item(tree, hf_aoe_aflags_w, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  /* err/feature */
  proto_tree_add_item(tree, hf_aoe_err_feature, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  /* sector count */
  proto_tree_add_item(tree, hf_aoe_sector_count, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  /* ata command/status */
  if(!response){
    proto_tree_add_item(tree, hf_aoe_acmd, tvb, offset, 1, ENC_BIG_ENDIAN);
    col_append_fstr(pinfo->cinfo, COL_INFO, " ATA:%s", val_to_str(tvb_get_guint8(tvb, offset), ata_cmd_vals, " Unknown ATA<0x%02x>"));
  } else {
    proto_tree_add_item(tree, hf_aoe_astatus, tvb, offset, 1, ENC_BIG_ENDIAN);
    if(ata_info != NULL && ata_info->request_frame){
      /* we dont know what command it was unless we saw the request_frame */
      tmp_item=proto_tree_add_uint(tree, hf_aoe_acmd, tvb, 0, 0, ata_info->cmd);
      PROTO_ITEM_SET_GENERATED(tmp_item);
      col_append_fstr(pinfo->cinfo, COL_INFO, " ATA:%s", val_to_str(ata_info->cmd, ata_cmd_vals, " Unknown ATA<0x%02x>"));
    }
  }
  offset++;

  /*lba   probably complete wrong */
  lba=tvb_get_letohs(tvb, offset+4);
  lba=(lba<<32)|tvb_get_letohl(tvb, offset);
  offset+=8;
  proto_tree_add_uint64(tree, hf_aoe_lba, tvb, offset-8, 6, lba);

}

static void
dissect_aoe_v1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint8 flags, cmd;
  guint32 tag;
  proto_item *flags_item=NULL;
  proto_tree *flags_tree=NULL;

  /* read and dissect the flags */
  flags=tvb_get_guint8(tvb, 0)&0x0f;
  if(tree){
    flags_item=proto_tree_add_text(tree, tvb, 0, 1, "Flags:");
    flags_tree=proto_item_add_subtree(flags_item, ett_aoe_flags);
  }
  proto_tree_add_item(flags_tree, hf_aoe_flags_response, tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flags_tree, hf_aoe_flags_error, tvb, 0, 1, ENC_BIG_ENDIAN);
  if(flags_item){
    proto_item_append_text(flags_item,(flags&AOE_FLAGS_RESPONSE)?" Response":" Request");
    if(flags&AOE_FLAGS_ERROR){
      proto_item_append_text(flags_item, " Error");
    }
  }


  /* error */
  if(flags&AOE_FLAGS_ERROR){
    proto_tree_add_item(tree, hf_aoe_error, tvb, 1, 1, ENC_BIG_ENDIAN);
	col_append_fstr(pinfo->cinfo, COL_INFO, "Error:%s ", val_to_str(tvb_get_guint8(tvb, 1), error_vals, "Unknown error<%d>"));
  }

  /* major/minor address */
  proto_tree_add_item(tree, hf_aoe_major, tvb, 2, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_aoe_minor, tvb, 4, 1, ENC_BIG_ENDIAN);

  /* command */
  cmd=tvb_get_guint8(tvb, 5);
  proto_tree_add_item(tree, hf_aoe_cmd, tvb, 5, 1, ENC_BIG_ENDIAN);
  col_append_fstr(pinfo->cinfo, COL_INFO, "%s %s", val_to_str(cmd, cmd_vals, "Unknown command<%d>"), (flags&AOE_FLAGS_RESPONSE)?"Response":"Request");


  /* tag */
  tag=tvb_get_letohl(tvb, 6);
  proto_tree_add_item(tree, hf_aoe_tag, tvb, 6, 4, ENC_BIG_ENDIAN);


  switch(cmd){
  case AOE_CMD_ISSUE_ATA_COMMAND:
    dissect_ata_pdu(pinfo, tree, tvb, 10, flags&AOE_FLAGS_RESPONSE, tag);
    break;
  case AOE_CMD_QUERY_CONFIG_INFO:
    break;
  }

}

static void
dissect_aoe(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
  proto_item *item=NULL;
  proto_tree *tree=NULL;
  guint8 version;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "AoE");
  col_clear(pinfo->cinfo, COL_INFO);

  if (parent_tree) {
    item = proto_tree_add_item(parent_tree, proto_aoe, tvb, 0, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_aoe);
  }

  version=tvb_get_guint8(tvb, 0)>>4;
  proto_tree_add_uint(tree, hf_aoe_version, tvb, 0, 1, version);
  switch(version){
  case 1:
    dissect_aoe_v1(tvb, pinfo, tree);
    break;
  }
}

static void
ata_init(void)
{
  if(ata_cmd_unmatched){
    g_hash_table_destroy(ata_cmd_unmatched);
    ata_cmd_unmatched=NULL;
  }
  ata_cmd_unmatched=g_hash_table_new(ata_cmd_hash_unmatched, ata_cmd_equal_unmatched);

  if(ata_cmd_matched){
    g_hash_table_destroy(ata_cmd_matched);
    ata_cmd_matched=NULL;
  }
  ata_cmd_matched=g_hash_table_new(ata_cmd_hash_matched, ata_cmd_equal_matched);

}

void
proto_register_aoe(void)
{

  static hf_register_info hf[] = {
    { &hf_aoe_cmd,
      { "Command", "aoe.cmd", FT_UINT8, BASE_DEC, VALS(cmd_vals), 0x0,
	"AOE Command", HFILL}},
    { &hf_aoe_version,
      { "Version", "aoe.version", FT_UINT8, BASE_DEC, NULL, 0x0,
	"Version of the AOE protocol", HFILL}},
    { &hf_aoe_error,
      { "Error", "aoe.error", FT_UINT8, BASE_DEC, VALS(error_vals), 0x0,
	"Error code", HFILL}},
    { &hf_aoe_err_feature,
      { "Err/Feature", "aoe.err_feature", FT_UINT8, BASE_HEX, NULL, 0x0,
	NULL, HFILL}},
    { &hf_aoe_sector_count,
      { "Sector Count", "aoe.sector_count", FT_UINT8, BASE_DEC, NULL, 0x0,
	NULL, HFILL}},
    { &hf_aoe_flags_response,
      { "Response flag", "aoe.response", FT_BOOLEAN, 8, TFS(&tfs_response), AOE_FLAGS_RESPONSE, "Whether this is a response PDU or not", HFILL}},
    { &hf_aoe_flags_error,
      { "Error flag", "aoe.flags_error", FT_BOOLEAN, 8, TFS(&tfs_error), AOE_FLAGS_ERROR, "Whether this is an error PDU or not", HFILL}},
    { &hf_aoe_major,
      { "Major", "aoe.major", FT_UINT16, BASE_HEX, NULL, 0x0,
	"Major address", HFILL}},
    { &hf_aoe_minor,
      { "Minor", "aoe.minor", FT_UINT8, BASE_HEX, NULL, 0x0,
	"Minor address", HFILL}},
    { &hf_aoe_acmd,
      { "ATA Cmd", "aoe.ata.cmd", FT_UINT8, BASE_HEX, VALS(ata_cmd_vals), 0x0,
	"ATA command opcode", HFILL}},
    { &hf_aoe_astatus,
      { "ATA Status", "aoe.ata.status", FT_UINT8, BASE_HEX, NULL, 0x0,
	"ATA status bits", HFILL}},
    { &hf_aoe_tag,
      { "Tag", "aoe.tag", FT_UINT32, BASE_HEX, NULL, 0x0,
	"Command Tag", HFILL}},
    { &hf_aoe_aflags_e,
      { "E", "aoe.aflags.e", FT_BOOLEAN, 8, TFS(&tfs_aflags_e), AOE_AFLAGS_E, "Whether this is a normal or LBA48 command", HFILL}},
    { &hf_aoe_aflags_d,
      { "D", "aoe.aflags.d", FT_BOOLEAN, 8, TFS(&tfs_aflags_d), AOE_AFLAGS_D, NULL, HFILL}},
    { &hf_aoe_aflags_a,
      { "A", "aoe.aflags.a", FT_BOOLEAN, 8, TFS(&tfs_aflags_a), AOE_AFLAGS_A, "Whether this is an asynchronous write or not", HFILL}},
    { &hf_aoe_aflags_w,
      { "W", "aoe.aflags.w", FT_BOOLEAN, 8, TFS(&tfs_aflags_w), AOE_AFLAGS_W, "Is this a command writing data to the device or not", HFILL}},
    { &hf_aoe_lba,
      { "Lba", "aoe.lba", FT_UINT64, BASE_HEX, NULL, 0x00, "Lba address", HFILL}},
    { &hf_aoe_response_in,
      { "Response In", "aoe.response_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0, "The response to this packet is in this frame", HFILL }},
    { &hf_aoe_response_to,
      { "Response To", "aoe.response_to", FT_FRAMENUM, BASE_NONE, NULL, 0x0, "This is a response to the ATA command in this frame", HFILL }},
    { &hf_aoe_time,
      { "Time from request", "aoe.time", FT_RELATIVE_TIME, BASE_NONE, NULL, 0, "Time between Request and Reply for ATA calls", HFILL }},
  };

  static gint *ett[] = {
    &ett_aoe,
    &ett_aoe_flags,
  };

  proto_aoe = proto_register_protocol("ATAoverEthernet", "AOE", "aoe");
  proto_register_field_array(proto_aoe, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("aoe", dissect_aoe, proto_aoe);
  register_init_routine(ata_init);
}

void
proto_reg_handoff_aoe(void)
{
  dissector_handle_t aoe_handle;

  aoe_handle = find_dissector("aoe");
  dissector_add_uint("ethertype", ETHERTYPE_AOE, aoe_handle);

}
