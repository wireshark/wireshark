/* packet-memcache.c
 * Routines for Memcache Binary Protocol
 * http://code.google.com/p/memcached/wiki/MemcacheBinaryProtocol
 *
 * Copyright 2009, Stig Bjørlykke <stig@bjorlykke.org>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#include "packet-tcp.h"

#define PNAME  "Memcache Binary Protocol"
#define PSNAME "MEMCACHE"
#define PFNAME "memcache"

#define MEMCACHE_PORT         11211
#define MEMCACHE_HEADER_LEN   24

/* Magic Byte */
#define MAGIC_REQUEST         0x80
#define MAGIC_RESPONSE        0x81

/* Response Status */
#define RS_NO_ERROR           0x0000
#define RS_KEY_NOT_FOUND      0x0001
#define RS_KEY_EXISTS         0x0002
#define RS_VALUE_TOO_BIG      0x0003
#define RS_INVALID_ARGUMENTS  0x0004
#define RS_ITEM_NOT_STORED    0x0005
#define RS_UNKNOWN_COMMAND    0x0081
#define RS_OUT_OF_MEMORY      0x0082

/* Command Opcodes */
#define OP_GET                0x00
#define OP_SET                0x01
#define OP_ADD                0x02
#define OP_REPLACE            0x03
#define OP_DELETE             0x04
#define OP_INCREMENT          0x05
#define OP_DECREMENT          0x06
#define OP_QUIT               0x07
#define OP_FLUSH              0x08
#define OP_GET_Q              0x09
#define OP_NO_OP              0x0A
#define OP_VERSION            0x0B
#define OP_GET_K              0x0C
#define OP_GET_K_Q            0x0D
#define OP_APPEND             0x0E
#define OP_PREPEND            0x0F
#define OP_STAT               0x10
#define OP_SET_Q              0x11
#define OP_ADD_Q              0x12
#define OP_REPLACE_Q          0x13
#define OP_DELETE_Q           0x14
#define OP_INCREMENT_Q        0x15
#define OP_DECREMENT_Q        0x16
#define OP_QUIT_Q             0x17
#define OP_FLUSH_Q            0x18
#define OP_APPEND_Q           0x19
#define OP_PREPEND_Q          0x1A

/* Data Types */
#define DT_RAW_BYTES          0x00

static int proto_memcache = -1;

static int hf_magic = -1;
static int hf_opcode = -1;
static int hf_extras_length = -1;
static int hf_key_length = -1;
static int hf_value_length = -1;
static int hf_data_type = -1;
static int hf_reserved = -1;
static int hf_status = -1;
static int hf_total_body_length = -1;
static int hf_opaque = -1;
static int hf_cas = -1;
static int hf_extras = -1;
static int hf_extras_flags = -1;
static int hf_extras_expiration = -1;
static int hf_extras_delta = -1;
static int hf_extras_initial = -1;
static int hf_extras_unknown = -1;
static int hf_extras_missing = -1;
static int hf_key = -1;
static int hf_key_missing = -1;
static int hf_value = -1;
static int hf_value_missing = -1;
static int hf_uint64_response = -1;

static gint ett_memcache = -1;
static gint ett_extras = -1;

/* User definable values */
static gboolean memcache_desegment = TRUE;

static const value_string magic_vals[] = {
  { MAGIC_REQUEST,         "Request"            },
  { MAGIC_RESPONSE,        "Response"           },
  { 0, NULL }
};

static const value_string status_vals[] = {
  { RS_NO_ERROR,           "No error"           },
  { RS_KEY_NOT_FOUND,      "Key not found"      },
  { RS_KEY_EXISTS,         "Key exists"         },
  { RS_VALUE_TOO_BIG,      "Value too big"      },
  { RS_INVALID_ARGUMENTS,  "Invalid arguments"  },
  { RS_ITEM_NOT_STORED,    "Item not stored"    },
  { RS_UNKNOWN_COMMAND,    "Unknown command"    },
  { RS_OUT_OF_MEMORY,      "Out of memory"      },
  { 0, NULL }
};

static const value_string opcode_vals[] = {
  { OP_GET,                "Get"                },
  { OP_SET,                "Set"                },
  { OP_ADD,                "Add"                },
  { OP_REPLACE,            "Replace"            },
  { OP_DELETE,             "Delete"             },
  { OP_INCREMENT,          "Increment"          },
  { OP_DECREMENT,          "Decrement"          },
  { OP_QUIT,               "Quit"               },
  { OP_FLUSH,              "Flush"              },
  { OP_GET_Q,              "Get Quietly"        },
  { OP_NO_OP,              "No-op"              },
  { OP_VERSION,            "Version"            },
  { OP_GET_K,              "Get Key"            },
  { OP_GET_K_Q,            "Get Key Quietly"    },
  { OP_APPEND,             "Append"             },
  { OP_PREPEND,            "Prepend"            },
  { OP_STAT,               "Statistics"         },
  { OP_SET_Q,              "Set Quietly"        },
  { OP_ADD_Q,              "Add Quietly"        },
  { OP_REPLACE_Q,          "Replace Quietly"    },
  { OP_DELETE_Q,           "Delete Quietly"     },
  { OP_INCREMENT_Q,        "Increment Quietly"  },
  { OP_DECREMENT_Q,        "Decrement Quietly"  },
  { OP_QUIT_Q,             "Quit Quietly"       },
  { OP_FLUSH_Q,            "Flush Quietly"      },
  { OP_APPEND_Q,           "Append Quietly"     },
  { OP_PREPEND_Q,          "Prepend Quietly"    },
  { 0, NULL }
};

static const value_string data_type_vals[] = {
  { DT_RAW_BYTES,          "Raw bytes"          },
  { 0, NULL }
};

static guint 
get_memcache_pdu_len (packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  guint32 body_len;

  /* Get the length of the memcache body */
  body_len = tvb_get_ntohl(tvb, offset+8);

  /* That length doesn't include the header; add that in */
  return body_len + MEMCACHE_HEADER_LEN;
}

static void 
dissect_extras (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, 
                gint offset, guint8 extras_len, guint8 opcode, gboolean request)
{
  proto_tree *extras_tree = NULL;
  proto_item *extras_item = NULL, *ti;
  gint        save_offset = offset;
  gboolean    illegal = FALSE;  /* Set when extras shall not be present */
  gboolean    missing = FALSE;  /* Set when extras is missing */

  if (extras_len) {
    extras_item = proto_tree_add_item (tree, hf_extras, tvb, offset, extras_len, FALSE);
    extras_tree = proto_item_add_subtree (extras_item, ett_extras);
  }

  switch (opcode) {

  case OP_GET:
  case OP_GET_Q:
  case OP_GET_K:
  case OP_GET_K_Q:
    if (extras_len) {
      if (request) {
        /* Request shall not have extras */
        illegal = TRUE;
      } else {
        proto_tree_add_item (extras_tree, hf_extras_flags, tvb, offset, 4, FALSE);
        offset += 4;
      }
    } else if (!request) {
      /* Response must have extras */
      missing = TRUE;
    }
    break;

  case OP_SET:
  case OP_SET_Q:
  case OP_ADD:
  case OP_ADD_Q:
  case OP_REPLACE:
  case OP_REPLACE_Q:
    if (extras_len) {
      if (request) {
        proto_tree_add_item (extras_tree, hf_extras_flags, tvb, offset, 4, FALSE);
        offset += 4;
      
        proto_tree_add_item (extras_tree, hf_extras_expiration, tvb, offset, 4, FALSE);
        offset += 4;
      } else {
        /* Response shall not have extras */
        illegal = TRUE;
      }
    } else if (request) {
      /* Request must have extras */
      missing = TRUE;
    }
    break;

  case OP_INCREMENT:
  case OP_INCREMENT_Q:
  case OP_DECREMENT:
  case OP_DECREMENT_Q:
    if (extras_len) {
      if (request) {
        proto_tree_add_item (extras_tree, hf_extras_delta, tvb, offset, 8, FALSE);
        offset += 8;

        proto_tree_add_item (extras_tree, hf_extras_initial, tvb, offset, 8, FALSE);
        offset += 8;

        proto_tree_add_item (extras_tree, hf_extras_expiration, tvb, offset, 4, FALSE);
        offset += 4;
      } else {
        /* Response must not have extras (response is in Value) */
        illegal = TRUE;
      }
    } else if (request) {
      /* Request must have extras */
      missing = TRUE;
    }
    break;

  case OP_FLUSH:
  case OP_FLUSH_Q:
    if (extras_len) {
      proto_tree_add_item (extras_tree, hf_extras_expiration, tvb, offset, 4, FALSE);
      offset += 4;
    }
    break;

  case OP_DELETE:
  case OP_DELETE_Q:
  case OP_QUIT:
  case OP_QUIT_Q:
  case OP_VERSION:
  case OP_APPEND:
  case OP_APPEND_Q:
  case OP_PREPEND:
  case OP_PREPEND_Q:
  case OP_STAT:
    /* Must not have extras */
    if (extras_len) {
      illegal = TRUE;
    }
    break;

  default:
    if (extras_len) {
      /* Decode as unknown extras */
      proto_tree_add_item (extras_tree, hf_extras_unknown, tvb, offset, extras_len, FALSE);
      offset += extras_len;
    }
    break;
  }

  if (illegal) {
    ti = proto_tree_add_item (extras_tree, hf_extras_unknown, tvb, offset, extras_len, FALSE);
    expert_add_info_format (pinfo, ti, PI_UNDECODED, PI_WARN, "%s %s shall not have Extras", 
                            val_to_str (opcode, opcode_vals, "Opcode %d"),
                            request ? "Request" : "Response");
    offset += extras_len;
  } else if (missing) {
    ti = proto_tree_add_item (tree, hf_extras_missing, tvb, offset, 0, FALSE);
    expert_add_info_format (pinfo, ti, PI_UNDECODED, PI_WARN, "%s %s must have Extras",
                            val_to_str (opcode, opcode_vals, "Opcode %d"),
                            request ? "Request" : "Response");
  }

  if ((offset - save_offset) != extras_len) {
    expert_add_info_format (pinfo, extras_item, PI_UNDECODED, PI_WARN, "Illegal Extras length, should be %d", offset - save_offset);
  }
}

static void 
dissect_key (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, 
             gint offset, guint16 key_len, guint8 opcode, gboolean request)
{
  proto_item *ti = NULL;
  gboolean    illegal = FALSE;  /* Set when key shall not be present */
  gboolean    missing = FALSE;  /* Set when key is missing */

  if (key_len) {
    ti = proto_tree_add_item (tree, hf_key, tvb, offset, key_len, FALSE);
    offset += key_len;
  }

  /* Sanity check */
  if (key_len) {
    if ((opcode == OP_QUIT) || (opcode == OP_QUIT_Q) || (opcode == OP_NO_OP) || (opcode == OP_VERSION)) {
      /* Request and Response must not have key */
      illegal = TRUE;
    }
    if ((opcode == OP_SET) || (opcode == OP_ADD) || (opcode == OP_REPLACE) || (opcode == OP_DELETE) ||
        (opcode == OP_SET_Q) || (opcode == OP_ADD_Q) || (opcode == OP_REPLACE_Q) || (opcode == OP_DELETE_Q) ||
        (opcode == OP_FLUSH) || (opcode == OP_APPEND) || (opcode == OP_PREPEND) ||
        (opcode == OP_FLUSH_Q) || (opcode == OP_APPEND_Q) || (opcode == OP_PREPEND_Q))
    {
      /* Response must not have a key */
      if (!request) {
        illegal = TRUE;
      }
    }
  } else {
    if ((opcode == OP_GET) || (opcode == OP_GET_Q) || (opcode == OP_GET_K) || (opcode == OP_GET_K_Q) ||
        (opcode == OP_SET) || (opcode == OP_ADD) || (opcode == OP_REPLACE) || (opcode == OP_DELETE) ||
        (opcode == OP_SET_Q) || (opcode == OP_ADD_Q) || (opcode == OP_REPLACE_Q) || (opcode == OP_DELETE_Q) ||
        (opcode == OP_INCREMENT) || (opcode == OP_DECREMENT) || (opcode == OP_INCREMENT_Q) || (opcode == OP_DECREMENT_Q))
    {
      /* Request must have key */
      if (request) {
        missing = TRUE;
      }
    }
  }

  if (illegal) {
    expert_add_info_format (pinfo, ti, PI_UNDECODED, PI_WARN, "%s %s shall not have Key", 
                            val_to_str (opcode, opcode_vals, "Opcode %d"),
                            request ? "Request" : "Response");
  } else if (missing) {
    ti = proto_tree_add_item (tree, hf_key_missing, tvb, offset, 0, FALSE);
    expert_add_info_format (pinfo, ti, PI_UNDECODED, PI_WARN, "%s %s must have Key",
                            val_to_str (opcode, opcode_vals, "Opcode %d"),
                            request ? "Request" : "Response");
  }
}

static void 
dissect_value (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, 
               gint offset, guint8 value_len, guint8 opcode, gboolean request)
{
  proto_item *ti = NULL;
  gboolean    illegal = FALSE;  /* Set when value shall not be present */
  gboolean    missing = FALSE;  /* Set when value is missing */

  if (value_len > 0) {
    if (!request && ((opcode == OP_INCREMENT) || (opcode == OP_DECREMENT))) {
      ti = proto_tree_add_item (tree, hf_uint64_response, tvb, offset, 8, FALSE);
      if (value_len != 8) {
        expert_add_info_format (pinfo, ti, PI_UNDECODED, PI_WARN, "Illegal Value length, should be 8");
      }
    } else {
      ti = proto_tree_add_item (tree, hf_value, tvb, offset, value_len, FALSE);
    }
    offset += value_len;
  }

  /* Sanity check */
  if (value_len) {
    if ((opcode == OP_GET) || (opcode == OP_GET_Q) || (opcode == OP_GET_K) || (opcode == OP_GET_K_Q) || 
        (opcode == OP_INCREMENT) || (opcode == OP_DECREMENT) || (opcode == OP_VERSION) ||
        (opcode == OP_INCREMENT_Q) || (opcode == OP_DECREMENT_Q))
    {
      /* Request must not have value */
      if (request) {
        illegal = TRUE;
      }
    }
    if ((opcode == OP_DELETE) ||  (opcode == OP_QUIT) || (opcode == OP_FLUSH) || (opcode == OP_NO_OP) ||
        (opcode == OP_DELETE_Q) ||  (opcode == OP_QUIT_Q) || (opcode == OP_FLUSH_Q))
    {
      /* Request and Response must not have value */
      illegal = TRUE;
    }
    if ((opcode == OP_SET) || (opcode == OP_ADD) || (opcode == OP_REPLACE) ||
        (opcode == OP_SET_Q) || (opcode == OP_ADD_Q) || (opcode == OP_REPLACE_Q) ||
        (opcode == OP_APPEND) || (opcode == OP_PREPEND) || (opcode == OP_APPEND_Q) || (opcode == OP_PREPEND_Q))
    {
      /* Response must not have value */
      if (!request) {
        illegal = TRUE;
      }
    }
  } else {
    if ((opcode == OP_SET) || (opcode == OP_ADD) || (opcode == OP_REPLACE) ||
        (opcode == OP_SET_Q) || (opcode == OP_ADD_Q) || (opcode == OP_REPLACE_Q) ||
        (opcode == OP_APPEND) || (opcode == OP_PREPEND) || (opcode == OP_APPEND_Q) || (opcode == OP_PREPEND_Q))
    {
      /* Request must have a value */
      if (request) {
        missing = TRUE;
      }
    }
  }

  if (illegal) {
    expert_add_info_format (pinfo, ti, PI_UNDECODED, PI_WARN, "%s %s shall not have Value", 
                            val_to_str (opcode, opcode_vals, "Opcode %d"),
                            request ? "Request" : "Response");
  } else if (missing) {
    ti = proto_tree_add_item (tree, hf_value_missing, tvb, offset, 0, FALSE);
    expert_add_info_format (pinfo, ti, PI_UNDECODED, PI_WARN, "%s %s must have Value",
                            val_to_str (opcode, opcode_vals, "Opcode %d"),
                            request ? "Request" : "Response");
  }
}

static void 
dissect_memcache (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *memcache_tree;
  proto_item *memcache_item, *ti;
  gint        offset = 0;
  guint8      magic, opcode, extras_len;
  guint16     key_len, status = 0;
  guint32     body_len, value_len;
  gboolean    request;

  if (check_col (pinfo->cinfo, COL_PROTOCOL))
    col_set_str (pinfo->cinfo, COL_PROTOCOL, PSNAME);

  if (check_col (pinfo->cinfo, COL_INFO))
    col_clear (pinfo->cinfo, COL_INFO);

  memcache_item = proto_tree_add_item (tree, proto_memcache, tvb, offset, -1, FALSE);
  memcache_tree = proto_item_add_subtree (memcache_item, ett_memcache);

  magic = tvb_get_guint8 (tvb, offset);
  ti = proto_tree_add_item (memcache_tree, hf_magic, tvb, offset, 1, FALSE);
  offset += 1;

  if (match_strval (magic, magic_vals) == NULL) {
    expert_add_info_format (pinfo, ti, PI_UNDECODED, PI_WARN, "Unknown magic byte: %d", magic);
  }

  opcode = tvb_get_guint8 (tvb, offset);
  ti = proto_tree_add_item (memcache_tree, hf_opcode, tvb, offset, 1, FALSE);
  offset += 1;

  if (match_strval (opcode, opcode_vals) == NULL) {
    expert_add_info_format (pinfo, ti, PI_UNDECODED, PI_WARN, "Unknown opcode: %d", opcode);
  }

  proto_item_append_text (memcache_item, ", %s %s", val_to_str (opcode, opcode_vals, "Unknown opcode (%d)"),
                          val_to_str (magic, magic_vals, "Unknown magic (%d)"));

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, "%s %s", 
                     val_to_str (opcode, opcode_vals, "Unknown opcode (%d)"),
                     val_to_str (magic, magic_vals, "Unknown magic (%d)"));

  key_len = tvb_get_ntohs (tvb, offset);
  proto_tree_add_item (memcache_tree, hf_key_length, tvb, offset, 2, FALSE);
  offset += 2;

  extras_len = tvb_get_guint8 (tvb, offset);
  proto_tree_add_item (memcache_tree, hf_extras_length, tvb, offset, 1, FALSE);
  offset += 1;

  proto_tree_add_item (memcache_tree, hf_data_type, tvb, offset, 1, FALSE);
  offset += 1;

  status = tvb_get_ntohs (tvb, offset);
  if (magic & 0x01) {    /* We suppose this is a response, even when unknown magic byte */
    request = FALSE;
    ti = proto_tree_add_item (memcache_tree, hf_status, tvb, offset, 2, FALSE);
    if (status != 0) {
      expert_add_info_format (pinfo, ti, PI_RESPONSE_CODE, PI_NOTE, "%s: %s", 
                              val_to_str (opcode, opcode_vals, "Unknown opcode (%d)"),
                              val_to_str (status, status_vals, "Status: %d"));
    }
  } else {
    request = TRUE;
    ti = proto_tree_add_item (memcache_tree, hf_reserved, tvb, offset, 2, FALSE);
    if (status != 0) {
      expert_add_info_format (pinfo, ti, PI_UNDECODED, PI_WARN, "Reserved value: %d", status);
    }
  }
  offset += 2;

  body_len = tvb_get_ntohl (tvb, offset);
  value_len = body_len - extras_len - key_len;
  ti = proto_tree_add_uint (memcache_tree, hf_value_length, tvb, offset, 0, value_len);
  PROTO_ITEM_SET_GENERATED (ti);

  proto_tree_add_item (memcache_tree, hf_total_body_length, tvb, offset, 4, FALSE);
  offset += 4;

  proto_tree_add_item (memcache_tree, hf_opaque, tvb, offset, 4, FALSE);
  offset += 4;

  proto_tree_add_item (memcache_tree, hf_cas, tvb, offset, 8, FALSE);
  offset += 8;

  if (status == 0) {
    dissect_extras (tvb, pinfo, memcache_tree, offset, extras_len, opcode, request);
    offset += extras_len;

    dissect_key (tvb, pinfo, memcache_tree, offset, key_len, opcode, request);
    offset += key_len;

    dissect_value (tvb, pinfo, memcache_tree, offset, value_len, opcode, request);
    offset += value_len;
  } else if (body_len) {
    proto_tree_add_item (memcache_tree, hf_value, tvb, offset, body_len, FALSE);
    offset += body_len;

    if (check_col (pinfo->cinfo, COL_INFO))
      col_append_fstr (pinfo->cinfo, COL_INFO, " (%s)", 
                       val_to_str (status, status_vals, "Unknown status: %d"));
  } else {
    ti = proto_tree_add_item (memcache_tree, hf_value_missing, tvb, offset, 0, FALSE);
    expert_add_info_format (pinfo, ti, PI_UNDECODED, PI_WARN, "%s with status %s (%d) must have Value",
                            val_to_str (opcode, opcode_vals, "Opcode %d"),
                            val_to_str (status, status_vals, "Unknown"), status);
  }
}

static void 
dissect_memcache_tcp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tcp_dissect_pdus (tvb, pinfo, tree, memcache_desegment, 12,
                    get_memcache_pdu_len, dissect_memcache);
}

static void 
dissect_memcache_udp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_memcache (tvb, pinfo, tree);
}

void 
proto_register_memcache (void)
{
  static hf_register_info hf[] = {
    { &hf_magic,
      { "Magic", "memcache.magic", FT_UINT8, BASE_DEC, VALS(magic_vals), 0x0, "Magic number", HFILL } },
    { &hf_opcode,
      { "Opcode", "memcache.opcode", FT_UINT8, BASE_DEC, VALS(opcode_vals), 0x0, "Command code", HFILL } },
    { &hf_extras_length,
      { "Extras length", "memcache.extras.length", FT_UINT8, BASE_DEC, NULL, 0x0, "Length in bytes of the command extras", HFILL } },
    { &hf_key_length,
      { "Key Length", "memcache.key.length", FT_UINT16, BASE_DEC, NULL, 0x0, "Length in bytes of the text key that follows the command extras", HFILL } },
    { &hf_value_length,
      { "Value length", "memcache.value.length", FT_UINT32, BASE_DEC, NULL, 0x0, "Length in bytes of the value that follows the key", HFILL } },
    { &hf_data_type,
      { "Data type", "memcache.data_type", FT_UINT8, BASE_DEC, VALS(data_type_vals), 0x0, NULL, HFILL } },
    { &hf_reserved,
      { "Reserved", "memcache.reserved", FT_UINT16, BASE_DEC, NULL, 0x0, "Reserved for future use", HFILL } },
    { &hf_status,
      { "Status", "memcache.status", FT_UINT16, BASE_DEC, VALS(status_vals), 0x0, "Status of the response", HFILL } },
    { &hf_total_body_length,
      { "Total body length", "memcache.total_body_length", FT_UINT32, BASE_DEC, NULL, 0x0, "Length in bytes of extra + key + value", HFILL } },
    { &hf_opaque,
      { "Opaque", "memcache.opaque", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_cas,
      { "CAS", "memcache.cas", FT_UINT64, BASE_DEC, NULL, 0x0, "Data version check", HFILL } },
    { &hf_extras,
      { "Extras", "memcache.extras", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_flags,
      { "Flags", "memcache.extras.flags", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_expiration,
      { "Expiration", "memcache.extras.expiration", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_delta,
      { "Amount to add", "memcache.extras.delta", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_initial,
      { "Initial value", "memcache.extras.initial", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_unknown,
      { "Unknown", "memcache.extras.unknown", FT_BYTES, BASE_DEC, NULL, 0x0, "Unknown Extras", HFILL } },
    { &hf_extras_missing,
      { "Extras missing", "memcache.extras.missing", FT_NONE, BASE_NONE, NULL, 0x0, "Extras is mandatory for this command", HFILL } },
    { &hf_key,
      { "Key", "memcache.key", FT_STRING, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_key_missing,
      { "Key missing", "memcache.key.missing", FT_NONE, BASE_NONE, NULL, 0x0, "Key is mandatory for this command", HFILL } },
    { &hf_value,
      { "Value", "memcache.value", FT_STRING, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_value_missing,
      { "Value missing", "memcache.value.missing", FT_NONE, BASE_NONE, NULL, 0x0, "Value is mandatory for this command", HFILL } },
    { &hf_uint64_response,
      { "Response", "memcache.extras.response", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
  };

  static gint *ett[] = {
    &ett_memcache,
    &ett_extras
  };

  module_t *memcache_module;

  proto_memcache = proto_register_protocol (PNAME, PSNAME, PFNAME);
  register_dissector ("memcache.tcp", dissect_memcache_tcp, proto_memcache);
  register_dissector ("memcache.udp", dissect_memcache_udp, proto_memcache);
  
  proto_register_field_array (proto_memcache, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  /* Register our configuration options */
  memcache_module = prefs_register_protocol (proto_memcache, NULL);

  prefs_register_bool_preference (memcache_module, "desegment_pdus",
                                  "Reassemble PDUs spanning multiple TCP segments",
                                  "Whether the memcache dissector should reassemble PDUs"
                                  " spanning multiple TCP segments."
                                  " To use this option, you must also enable \"Allow subdissectors"
                                  " to reassemble TCP streams\" in the TCP protocol settings.",
                                  &memcache_desegment);
}

void 
proto_reg_handoff_memcache (void)
{
  dissector_handle_t memcache_tcp_handle;
  dissector_handle_t memcache_udp_handle;

  memcache_tcp_handle = find_dissector ("memcache.tcp");
  memcache_udp_handle = find_dissector ("memcache.udp");

  dissector_add ("tcp.port", MEMCACHE_PORT, memcache_tcp_handle);
  dissector_add ("udp.port", MEMCACHE_PORT, memcache_udp_handle);
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
 * ex: set shiftwidth=2 tabstop=8 noexpandtab
 * :indentSize=2:tabSize=8:noTabs=false:
 */
