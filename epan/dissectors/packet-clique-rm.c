/* packet-clique_rm.c
 * Routines for clique reliable multicast dissector
 * Copyright 2007, Collabora Ltd.
 *   @author: Sjoerd Simons <sjoerd.simons@collabora.co.uk>
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

void proto_register_clique_rm(void);
void proto_reg_handoff_clique_rm(void);

/* Initialize the protocol and registered fields */
static int proto_clique_rm = -1;

static int hf_clique_rm_version = -1;
static int hf_clique_rm_type = -1;
static int hf_clique_rm_sender = -1;
static int hf_clique_rm_packet_id = -1;
static int hf_clique_rm_depends = -1;
static int hf_clique_rm_depend_sender = -1;
static int hf_clique_rm_depend_packet_id = -1;
static int hf_clique_rm_failures = -1;
static int hf_clique_rm_failures_senders = -1;
static int hf_clique_rm_attempt_join = -1;
static int hf_clique_rm_attempt_join_senders = -1;
static int hf_clique_rm_join_failures = -1;
static int hf_clique_rm_join_failures_senders = -1;
static int hf_clique_rm_data_flags = -1;
static int hf_clique_rm_data_size = -1;
static int hf_clique_rm_data_stream_id = -1;
static int hf_clique_rm_data_data = -1;
static int hf_clique_rm_whois_request_id = -1;
static int hf_clique_rm_whois_reply_name = -1;
static int hf_clique_rm_whois_reply_name_length = -1;
static int hf_clique_rm_repair_request_sender_id = -1;
static int hf_clique_rm_repair_request_packet_id = -1;

/* Initialize the subtree pointers */
static gint ett_clique_rm = -1;
static gint ett_clique_rm_data = -1;
static gint ett_clique_rm_depends = -1;
static gint ett_clique_rm_depends_item = -1;
static gint ett_clique_rm_failures = -1;
static gint ett_clique_rm_join_failures = -1;
static gint ett_clique_rm_attempt_join = -1;
static gint ett_clique_rm_join = -1;

/* Packet types */
typedef enum {
  /* Unreliable packets */
  PACKET_TYPE_WHOIS_REQUEST = 0,
  PACKET_TYPE_WHOIS_REPLY,
  PACKET_TYPE_REPAIR_REQUEST,
  PACKET_TYPE_SESSION,
  /* Reliable packets */
  FIRST_RELIABLE_PACKET = 0xf,
  PACKET_TYPE_DATA = FIRST_RELIABLE_PACKET,
  /* No data just acknowledgement */
  PACKET_TYPE_NO_DATA,
  /* Some nodes failed */
  PACKET_TYPE_FAILURE,
  /* Start a joining attempt */
  PACKET_TYPE_ATTEMPT_JOIN,
  /* The real join */
  PACKET_TYPE_JOIN,
  /* Leaving now, bye */
  PACKET_TYPE_BYE,
  PACKET_TYPE_INVALID
} GibberRMulticastPacketType;

#define IS_RELIABLE(type) (type >= FIRST_RELIABLE_PACKET)

static const value_string packet_type_vals[] = {
  { PACKET_TYPE_WHOIS_REQUEST,   "Whois request" },
  { PACKET_TYPE_WHOIS_REPLY,     "Whois reply"   },
  { PACKET_TYPE_REPAIR_REQUEST,  "Repair request"},
  { PACKET_TYPE_SESSION,         "Session"       },
  { PACKET_TYPE_DATA,            "Data"          },
  /* No data just acknowledgement */
  { PACKET_TYPE_NO_DATA,         "No data"       },
  /* Some nodes failed */
  { PACKET_TYPE_FAILURE,         "Failure"       },
  /* Start a joining attempt */
  { PACKET_TYPE_ATTEMPT_JOIN,    "Attempt join"  },
  /* The real join */
  { PACKET_TYPE_JOIN,            "Join"          },
  /* Leaving now, bye */
  { PACKET_TYPE_BYE,             "Bye"           },

  { 0,                 NULL                 }
};

static void
dissect_sender_array(proto_tree *clique_rm_tree, int hf_header, gint ett_header,
    int hf_header_sender, tvbuff_t *tvb, int offset)
{
  guint       i, count;
  int         len;
  proto_item *ti;
  proto_tree *tree;


  count = tvb_get_guint8(tvb, offset);
  len   = 1 + 4 * count;
  ti    = proto_tree_add_item(clique_rm_tree, hf_header, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_item_set_len(ti, len);
  tree  = proto_item_add_subtree(ti, ett_header);
  offset++;

  for (i = 0; i < count; i++, offset += 4)
    proto_tree_add_item(tree, hf_header_sender, tvb, offset, 4, ENC_BIG_ENDIAN);
}

static void
dissect_data_packet(proto_tree *clique_rm_tree, tvbuff_t *tvb, int offset)
{
  proto_tree *tree;

  tree = proto_tree_add_subtree(clique_rm_tree, tvb, offset, -1, ett_clique_rm_data, NULL, "Data");

  proto_tree_add_item(tree, hf_clique_rm_data_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_clique_rm_data_stream_id, tvb, offset, 2,
      ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_clique_rm_data_size, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;


  proto_tree_add_item(tree, hf_clique_rm_data_data, tvb, offset, -1, ENC_NA);
}

static int
dissect_depends(proto_tree *clique_rm_tree, tvbuff_t *tvb, int offset)
{
  proto_item *ti;
  proto_tree *tree, *depend_tree;
  guint       ii, count;
  int         len;

  count = tvb_get_guint8(tvb, offset);
  len   = 1 + count * 8;

  ti = proto_tree_add_item(clique_rm_tree,
          hf_clique_rm_depends, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_item_set_len(ti, len);
  offset += 1;

  tree = proto_item_add_subtree(ti, ett_clique_rm_depends);
  for (ii = 0; ii < count; ii++)
  {
     depend_tree = proto_tree_add_subtree_format(tree, tvb, offset, 8,
                    ett_clique_rm_depends_item, NULL, "Depend item %d", ii+1);

     proto_tree_add_item(depend_tree, hf_clique_rm_depend_sender,
           tvb, offset, 4, ENC_BIG_ENDIAN);
     proto_tree_add_item(depend_tree, hf_clique_rm_depend_packet_id,
           tvb, offset+4, 4, ENC_BIG_ENDIAN);
     offset += 8;
  }

  return len;
}

/* Code to actually dissect the packets */
static void
dissect_reliable_packet(proto_tree *clique_rm_tree, guint8 type, tvbuff_t *tvb, int offset)
{
  if (!clique_rm_tree)
    return; /* no col_..() or expert...() calls in following */

  proto_tree_add_item(clique_rm_tree, hf_clique_rm_packet_id, tvb, offset, 4,
     ENC_BIG_ENDIAN);
  offset += 4;

  offset += dissect_depends(clique_rm_tree, tvb, offset);

  switch (type)
    {
      case PACKET_TYPE_DATA:
        dissect_data_packet(clique_rm_tree, tvb, offset);
        break;
      case PACKET_TYPE_NO_DATA:
        break;
      case PACKET_TYPE_FAILURE:
        dissect_sender_array(clique_rm_tree, hf_clique_rm_failures,
            ett_clique_rm_failures, hf_clique_rm_failures_senders, tvb, offset);
        break;
      case PACKET_TYPE_ATTEMPT_JOIN:
        dissect_sender_array(clique_rm_tree, hf_clique_rm_attempt_join,
            ett_clique_rm_attempt_join, hf_clique_rm_attempt_join_senders, tvb, offset);
        break;
      case PACKET_TYPE_JOIN:
        dissect_sender_array(clique_rm_tree, hf_clique_rm_join_failures,
            ett_clique_rm_join_failures, hf_clique_rm_join_failures_senders, tvb, offset);
        break;
      case PACKET_TYPE_BYE:
        break;
      default:
        break;
    }
}

static void
dissect_unreliable_packet(proto_tree *clique_rm_tree, guint8 type, tvbuff_t *tvb, int offset)
{
  guint len;

  if (!clique_rm_tree)
    return; /* no col_..() or expert...() calls in following */

  switch (type)
    {
      case PACKET_TYPE_WHOIS_REQUEST:
        proto_tree_add_item(clique_rm_tree,
          hf_clique_rm_whois_request_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        break;
      case PACKET_TYPE_WHOIS_REPLY:
        len = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(clique_rm_tree,
          hf_clique_rm_whois_reply_name_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(clique_rm_tree,
          hf_clique_rm_whois_reply_name, tvb, offset, len, ENC_ASCII|ENC_NA);
        break;
      case PACKET_TYPE_REPAIR_REQUEST:
        proto_tree_add_item(clique_rm_tree,
          hf_clique_rm_repair_request_sender_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(clique_rm_tree,
          hf_clique_rm_repair_request_packet_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        break;
      case PACKET_TYPE_SESSION:
        dissect_depends(clique_rm_tree, tvb, offset);
        break;
      default:
        break;
    }
}


static gboolean
dissect_clique_rm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  proto_tree *clique_rm_tree;
  guint8      version;
  guint8      type;
  int         offset = 0;
  guint64     qword;

  if (tvb_captured_length(tvb) < 12)
    return FALSE;

  qword = tvb_get_ntoh48(tvb,0);
  /* ASCII str for 'Clique' = 0x436c69717565 */
  if(qword != G_GUINT64_CONSTANT (0x436c69717565))
    return FALSE;
  offset += 6;

  version = tvb_get_guint8(tvb, offset);
  if (version != 1)
    return FALSE;
  offset++;

  type = tvb_get_guint8(tvb, offset);
  offset++;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Clique-rm");
  col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
               val_to_str(type, packet_type_vals, "Unknown (0x%02x)"));

  /* rewind back to just behind the prefix */
  offset = 6;

  ti = proto_tree_add_item(tree, proto_clique_rm, tvb, 0, -1, ENC_NA);
  clique_rm_tree = proto_item_add_subtree(ti, ett_clique_rm);

  proto_tree_add_item(clique_rm_tree, hf_clique_rm_version, tvb, offset, 1,
                      ENC_BIG_ENDIAN);
  offset++;

  proto_tree_add_item(clique_rm_tree, hf_clique_rm_type, tvb, offset, 1,
                      ENC_BIG_ENDIAN);
  offset++;

  col_append_fstr(pinfo->cinfo, COL_INFO, ", sender: 0x%x",
                    tvb_get_ntohl(tvb, offset));

  proto_tree_add_item(clique_rm_tree, hf_clique_rm_sender, tvb, offset,
                      4, ENC_BIG_ENDIAN);
  offset += 4;

  if (IS_RELIABLE(type)) {
    col_append_fstr(pinfo->cinfo, COL_INFO, ", id: 0x%x",
                      tvb_get_ntohl(tvb, offset));

    dissect_reliable_packet(clique_rm_tree,   type, tvb, offset);
  } else {
    dissect_unreliable_packet(clique_rm_tree, type, tvb, offset);
  }

  return TRUE;
}


/* Register the protocol with Wireshark */

void
proto_register_clique_rm(void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    { &hf_clique_rm_version,
      { "Version",           "clique_rm.version",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_clique_rm_type,
      { "Type",           "clique_rm.type",
        FT_UINT8, BASE_HEX, VALS(packet_type_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_clique_rm_sender,
      { "Sender",           "clique_rm.sender",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_clique_rm_packet_id,
      { "Packet id",           "clique_rm.packet_id",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_clique_rm_depends,
      { "Depends",           "clique_rm.depends",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_clique_rm_depend_sender,
      { "Sender",           "clique_rm.depends.sender",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_clique_rm_depend_packet_id,
      { "Packet id",           "clique_rm.depends.packet_id",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_clique_rm_failures,
      { "Failures",           "clique_rm.failures",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_clique_rm_failures_senders,
      { "Sender",           "clique_rm.failures.sender",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_clique_rm_attempt_join,
      { "New attempt join senders", "clique_rm.attempt_join",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_clique_rm_attempt_join_senders,
      { "Sender",           "clique_rm.attempt_join.sender",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_clique_rm_join_failures,
      { "Join failures",           "clique_rm.join_failures",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_clique_rm_join_failures_senders,
      { "Sender",           "clique_rm.join_failures.sender",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_clique_rm_data_flags,
      { "Data flags",           "clique_rm.data.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_clique_rm_data_size,
      { "Data total size",           "clique_rm.data.size",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_clique_rm_data_stream_id,
      { "Data stream id",           "clique_rm.data.stream_id",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_clique_rm_data_data,
      { "Raw data",           "clique_rm.data.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_clique_rm_whois_request_id,
      { "Whois request id",           "clique_rm.whois_request.id",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_clique_rm_whois_reply_name_length,
      { "Whois reply name length",    "clique_rm.whois_reply.length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_clique_rm_whois_reply_name,
      { "Whois reply name",           "clique_rm.whois_reply.name",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_clique_rm_repair_request_sender_id,
      { "Repair request for sender",
        "clique_rm.repair_request.sender_id",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_clique_rm_repair_request_packet_id,
      { "Repair request for packet",
        "clique_rm.repair_request.packet_id",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_clique_rm,
    &ett_clique_rm_depends,
    &ett_clique_rm_depends_item,
    &ett_clique_rm_data,
    &ett_clique_rm_failures,
    &ett_clique_rm_join_failures,
    &ett_clique_rm_attempt_join,
    &ett_clique_rm_join,
  };

/* Register the protocol name and description */
  proto_clique_rm = proto_register_protocol(
    "Clique Reliable Multicast Protocol", "Clique-rm", "clique-rm");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_clique_rm, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_clique_rm(void)
{
  heur_dissector_add("udp", dissect_clique_rm, "Clique RM over UDP", "clique_rm_udp", proto_clique_rm, HEURISTIC_ENABLE);
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
