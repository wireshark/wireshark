/* packet-couchbase.c
 *
 * Routines for Couchbase Protocol
 * Copyright 2011, Sergey Avseyev <sergey.avseyev@gmail.com>
 *
 * With contributions from Mark Woosey <mark@markwoosey.com>
 *
 *
 * Based on packet-memcache.c: mecmcache binary protocol.
 *
 * Routines for Memcache Binary Protocol
 * http://code.google.com/p/memcached/wiki/MemcacheBinaryProtocol
 *
 * Copyright 2009, Stig Bjorlykke <stig@bjorlykke.org>
 *
 * Routines for Memcache Textual Protocol
 * http://code.sixapart.com/svn/memcached/trunk/server/doc/protocol.txt
 *
 * Copyright 2009, Rama Chitta <rama@gear6.com>
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
#include <epan/expert.h>


#include "packet-tcp.h"

#define PNAME  "Couchbase Protocol"
#define PSNAME "Couchbase"
#define PFNAME "couchbase"

#define COUCHBASE_DEFAULT_PORT        "11210"
#define COUCHBASE_HEADER_LEN   24

 /* Magic Byte */
#define MAGIC_REQUEST         0x80
#define MAGIC_RESPONSE        0x81

 /* Response Status */
#define PROTOCOL_BINARY_RESPONSE_SUCCESS            0x00
#define PROTOCOL_BINARY_RESPONSE_KEY_ENOENT         0x01
#define PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS        0x02
#define PROTOCOL_BINARY_RESPONSE_E2BIG              0x03
#define PROTOCOL_BINARY_RESPONSE_EINVAL             0x04
#define PROTOCOL_BINARY_RESPONSE_NOT_STORED         0x05
#define PROTOCOL_BINARY_RESPONSE_DELTA_BADVAL       0x06
#define PROTOCOL_BINARY_RESPONSE_NOT_MY_VBUCKET     0x07
#define PROTOCOL_BINARY_RESPONSE_AUTH_ERROR         0x20
#define PROTOCOL_BINARY_RESPONSE_AUTH_CONTINUE      0x21
#define PROTOCOL_BINARY_RESPONSE_ERANGE             0x22
#define PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND    0x81
#define PROTOCOL_BINARY_RESPONSE_ENOMEM             0x82
#define PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED      0x83
#define PROTOCOL_BINARY_RESPONSE_EINTERNAL          0x84
#define PROTOCOL_BINARY_RESPONSE_EBUSY              0x85
#define PROTOCOL_BINARY_RESPONSE_ETMPFAIL           0x86

 /* Command Opcodes */
#define PROTOCOL_BINARY_CMD_GET                     0x00
#define PROTOCOL_BINARY_CMD_SET                     0x01
#define PROTOCOL_BINARY_CMD_ADD                     0x02
#define PROTOCOL_BINARY_CMD_REPLACE                 0x03
#define PROTOCOL_BINARY_CMD_DELETE                  0x04
#define PROTOCOL_BINARY_CMD_INCREMENT               0x05
#define PROTOCOL_BINARY_CMD_DECREMENT               0x06
#define PROTOCOL_BINARY_CMD_QUIT                    0x07
#define PROTOCOL_BINARY_CMD_FLUSH                   0x08
#define PROTOCOL_BINARY_CMD_GETQ                    0x09
#define PROTOCOL_BINARY_CMD_NOOP                    0x0a
#define PROTOCOL_BINARY_CMD_VERSION                 0x0b
#define PROTOCOL_BINARY_CMD_GETK                    0x0c
#define PROTOCOL_BINARY_CMD_GETKQ                   0x0d
#define PROTOCOL_BINARY_CMD_APPEND                  0x0e
#define PROTOCOL_BINARY_CMD_PREPEND                 0x0f
#define PROTOCOL_BINARY_CMD_STAT                    0x10
#define PROTOCOL_BINARY_CMD_SETQ                    0x11
#define PROTOCOL_BINARY_CMD_ADDQ                    0x12
#define PROTOCOL_BINARY_CMD_REPLACEQ                0x13
#define PROTOCOL_BINARY_CMD_DELETEQ                 0x14
#define PROTOCOL_BINARY_CMD_INCREMENTQ              0x15
#define PROTOCOL_BINARY_CMD_DECREMENTQ              0x16
#define PROTOCOL_BINARY_CMD_QUITQ                   0x17
#define PROTOCOL_BINARY_CMD_FLUSHQ                  0x18
#define PROTOCOL_BINARY_CMD_APPENDQ                 0x19
#define PROTOCOL_BINARY_CMD_PREPENDQ                0x1a
#define PROTOCOL_BINARY_CMD_VERBOSITY               0x1b
#define PROTOCOL_BINARY_CMD_TOUCH                   0x1c
#define PROTOCOL_BINARY_CMD_GAT                     0x1d
#define PROTOCOL_BINARY_CMD_GATQ                    0x1e

 /* SASL operations */
#define PROTOCOL_BINARY_CMD_SASL_LIST_MECHS         0x20
#define PROTOCOL_BINARY_CMD_SASL_AUTH               0x21
#define PROTOCOL_BINARY_CMD_SASL_STEP               0x22

 /* Range operations.
  * These commands are used for range operations and exist within
  * protocol_binary.h for use in other projects. Range operations are
  * not expected to be implemented in the memcached server itself.
  */
#define PROTOCOL_BINARY_CMD_RGET                    0x30
#define PROTOCOL_BINARY_CMD_RSET                    0x31
#define PROTOCOL_BINARY_CMD_RSETQ                   0x32
#define PROTOCOL_BINARY_CMD_RAPPEND                 0x33
#define PROTOCOL_BINARY_CMD_RAPPENDQ                0x34
#define PROTOCOL_BINARY_CMD_RPREPEND                0x35
#define PROTOCOL_BINARY_CMD_RPREPENDQ               0x36
#define PROTOCOL_BINARY_CMD_RDELETE                 0x37
#define PROTOCOL_BINARY_CMD_RDELETEQ                0x38
#define PROTOCOL_BINARY_CMD_RINCR                   0x39
#define PROTOCOL_BINARY_CMD_RINCRQ                  0x3a
#define PROTOCOL_BINARY_CMD_RDECR                   0x3b
#define PROTOCOL_BINARY_CMD_RDECRQ                  0x3c


 /* VBucket commands */
#define PROTOCOL_BINARY_CMD_SET_VBUCKET             0x3d
#define PROTOCOL_BINARY_CMD_GET_VBUCKET             0x3e
#define PROTOCOL_BINARY_CMD_DEL_VBUCKET             0x3f

 /* TAP commands */
#define PROTOCOL_BINARY_CMD_TAP_CONNECT             0x40
#define PROTOCOL_BINARY_CMD_TAP_MUTATION            0x41
#define PROTOCOL_BINARY_CMD_TAP_DELETE              0x42
#define PROTOCOL_BINARY_CMD_TAP_FLUSH               0x43
#define PROTOCOL_BINARY_CMD_TAP_OPAQUE              0x44
#define PROTOCOL_BINARY_CMD_TAP_VBUCKET_SET         0x45
#define PROTOCOL_BINARY_CMD_TAP_CHECKPOINT_START    0x46
#define PROTOCOL_BINARY_CMD_TAP_CHECKPOINT_END      0x47

 /* Commands from EP (eventually persistent) and bucket engines */
#define PROTOCOL_BINARY_CMD_STOP_PERSISTENCE        0x80
#define PROTOCOL_BINARY_CMD_START_PERSISTENCE       0x81
#define PROTOCOL_BINARY_CMD_SET_PARAM               0x82
#define PROTOCOL_BINARY_CMD_GET_REPLICA             0x83
#define PROTOCOL_BINARY_CMD_CREATE_BUCKET           0x85
#define PROTOCOL_BINARY_CMD_DELETE_BUCKET           0x86
#define PROTOCOL_BINARY_CMD_LIST_BUCKETS            0x87
#define PROTOCOL_BINARY_CMD_EXPAND_BUCKET           0x88
#define PROTOCOL_BINARY_CMD_SELECT_BUCKET           0x89
#define PROTOCOL_BINARY_CMD_START_REPLICATION       0x90
#define PROTOCOL_BINARY_CMD_STOP_REPLICATION        0x91
#define PROTOCOL_BINARY_CMD_OBSERVE                 0x92
#define PROTOCOL_BINARY_CMD_EVICT_KEY               0x93
#define PROTOCOL_BINARY_CMD_GET_LOCKED              0x94
#define PROTOCOL_BINARY_CMD_UNLOCK_KEY              0x95
#define PROTOCOL_BINARY_CMD_SYNC                    0x96
#define PROTOCOL_BINARY_CMD_LAST_CLOSED_CHECKPOINT  0x97
#define PROTOCOL_BINARY_CMD_RESTORE_FILE            0x98
#define PROTOCOL_BINARY_CMD_RESTORE_ABORT           0x99
#define PROTOCOL_BINARY_CMD_RESTORE_COMPLETE        0x9a
#define PROTOCOL_BINARY_CMD_ONLINE_UPDATE_START     0x9b
#define PROTOCOL_BINARY_CMD_ONLINE_UPDATE_COMPLETE  0x9c
#define PROTOCOL_BINARY_CMD_ONLINE_UPDATE_REVERT    0x9d
#define PROTOCOL_BINARY_CMD_DEREGISTER_TAP_CLIENT   0x9e
#define PROTOCOL_BINARY_CMD_RESET_REPLICATION_CHAIN 0x9f
#define PROTOCOL_BINARY_CMD_GET_META                0xa0
#define PROTOCOL_BINARY_CMD_GETQ_META               0xa1
#define PROTOCOL_BINARY_CMD_SET_WITH_META           0xa2
#define PROTOCOL_BINARY_CMD_SETQ_WITH_META          0xa3
#define PROTOCOL_BINARY_CMD_ADD_WITH_META           0xa4
#define PROTOCOL_BINARY_CMD_ADDQ_WITH_META          0xa5
#define PROTOCOL_BINARY_CMD_SNAPSHOT_VB_STATES      0xa6
#define PROTOCOL_BINARY_CMD_VBUCKET_BATCH_COUNT     0xa7


#define PROTOCOL_BINARY_CMD_SET_CLUSTER_CONFIG      0xb4
#define PROTOCOL_BINARY_CMD_GET_CLUSTER_CONFIG      0xb5


/* DCP commands */
#define PROTOCOL_BINARY_DCP_OPEN_CONNECTION         0x50
#define PROTOCOL_BINARY_DCP_ADD_STREAM              0x51
#define PROTOCOL_BINARY_DCP_CLOSE_STREAM            0x52
#define PROTOCOL_BINARY_DCP_STREAM_REQUEST          0x53
#define PROTOCOL_BINARY_DCP_FAILOVER_LOG_REQUEST    0x54
#define PROTOCOL_BINARY_DCP_STREAM_END              0x55
#define PROTOCOL_BINARY_DCP_SNAPSHOT_MARKER         0x56
#define PROTOCOL_BINARY_DCP_MUTATION                0x57
#define PROTOCOL_BINARY_DCP_DELETION                0x58
#define PROTOCOL_BINARY_DCP_EXPIRATION              0x59
#define PROTOCOL_BINARY_DCP_FLUSH                   0x5a
#define PROTOCOL_BINARY_DCP_SET_VBUCKET_STATE       0x5b

 /* vBucket states */
#define VBUCKET_ACTIVE                              0x01
#define VBUCKET_PENDING                             0x02
#define VBUCKET_REPLICA                             0x03
#define VBUCKET_DEAD                                0x04

 /* Data Types */
#define DT_RAW_BYTES          0x00

void proto_register_couchbase(void);
void proto_reg_handoff_couchbase(void);

static int proto_couchbase = -1;

static int hf_magic = -1;
static int hf_opcode = -1;
static int hf_extlength = -1;
static int hf_keylength = -1;
static int hf_value_length = -1;
static int hf_datatype = -1;
static int hf_vbucket = -1;
static int hf_status = -1;
static int hf_total_bodylength = -1;
static int hf_opaque = -1;
static int hf_cas = -1;
static int hf_ttp = -1;
static int hf_ttr = -1;
static int hf_extras = -1;
static int hf_extras_flags = -1;
static int hf_extras_flags_backfill = -1;
static int hf_extras_flags_dump = -1;
static int hf_extras_flags_list_vbuckets = -1;
static int hf_extras_flags_takeover_vbuckets = -1;
static int hf_extras_flags_support_ack = -1;
static int hf_extras_flags_request_keys_only = -1;
static int hf_extras_flags_checkpoint = -1;
static int hf_extras_expiration = -1;
static int hf_extras_delta = -1;
static int hf_extras_initial = -1;
static int hf_extras_unknown = -1;
static int hf_key = -1;
static int hf_value = -1;
static int hf_uint64_response = -1;
static int hf_observe = -1;
static int hf_observe_vbucket = -1;
static int hf_observe_keylength = -1;
static int hf_observe_key = -1;
static int hf_observe_status = -1;
static int hf_observe_cas = -1;

static expert_field ef_warn_shall_not_have_value = EI_INIT;
static expert_field ef_warn_shall_not_have_extras = EI_INIT;
static expert_field ef_warn_shall_not_have_key = EI_INIT;

static expert_field ei_value_missing = EI_INIT;
static expert_field ef_warn_must_have_extras = EI_INIT;
static expert_field ef_warn_must_have_key = EI_INIT;
static expert_field ef_warn_illegal_extras_length = EI_INIT;
static expert_field ef_warn_illegal_value_length = EI_INIT;
static expert_field ef_warn_unknown_magic_byte = EI_INIT;
static expert_field ef_warn_unknown_opcode = EI_INIT;
static expert_field ef_note_status_code = EI_INIT;

static gint ett_couchbase = -1;
static gint ett_extras = -1;
static gint ett_extras_flags = -1;
static gint ett_observe = -1;

static const value_string magic_vals[] = {

   { MAGIC_REQUEST,     "Request"  },
   { MAGIC_RESPONSE,    "Response" },
   { 0, NULL }
 };

static const value_string status_vals[] = {
  { PROTOCOL_BINARY_RESPONSE_SUCCESS,           "Success"                 },
  { PROTOCOL_BINARY_RESPONSE_KEY_ENOENT,        "Key not found"           },
  { PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS,       "Key exists"              },
  { PROTOCOL_BINARY_RESPONSE_E2BIG,             "Value too big"           },
  { PROTOCOL_BINARY_RESPONSE_EINVAL,            "Invalid arguments"       },
  { PROTOCOL_BINARY_RESPONSE_NOT_STORED,        "Key not stored"          },
  { PROTOCOL_BINARY_RESPONSE_DELTA_BADVAL,      "Bad value to incr/decr"  },
  { PROTOCOL_BINARY_RESPONSE_NOT_MY_VBUCKET,    "Not my vBucket"          },
  { PROTOCOL_BINARY_RESPONSE_AUTH_ERROR,        "Authentication error"    },
  { PROTOCOL_BINARY_RESPONSE_AUTH_CONTINUE,     "Authentication continue" },
  { PROTOCOL_BINARY_RESPONSE_ERANGE,            "Range error"             },
  { PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND,   "Unknown command"         },
  { PROTOCOL_BINARY_RESPONSE_ENOMEM,            "Out of memory"           },
  { PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED,     "Command isn't supported" },
  { PROTOCOL_BINARY_RESPONSE_EINTERNAL,         "Internal error"          },
  { PROTOCOL_BINARY_RESPONSE_EBUSY,             "Server is busy"          },
  { PROTOCOL_BINARY_RESPONSE_ETMPFAIL,          "Temporary failure"       },
  { 0, NULL }
};

static value_string_ext status_vals_ext = VALUE_STRING_EXT_INIT(status_vals);

static const value_string opcode_vals[] = {
  { PROTOCOL_BINARY_CMD_GET,                        "Get"                      },
  { PROTOCOL_BINARY_CMD_SET,                        "Set"                      },
  { PROTOCOL_BINARY_CMD_ADD,                        "Add"                      },
  { PROTOCOL_BINARY_CMD_REPLACE,                    "Replace"                  },
  { PROTOCOL_BINARY_CMD_DELETE,                     "Delete"                   },
  { PROTOCOL_BINARY_CMD_INCREMENT,                  "Increment"                },
  { PROTOCOL_BINARY_CMD_DECREMENT,                  "Decrement"                },
  { PROTOCOL_BINARY_CMD_QUIT,                       "Quit"                     },
  { PROTOCOL_BINARY_CMD_FLUSH,                      "Flush"                    },
  { PROTOCOL_BINARY_CMD_GETQ,                       "Get Quietly"              },
  { PROTOCOL_BINARY_CMD_NOOP,                       "NOOP"                     },
  { PROTOCOL_BINARY_CMD_VERSION,                    "Version"                  },
  { PROTOCOL_BINARY_CMD_GETK,                       "Get Key"                  },
  { PROTOCOL_BINARY_CMD_GETKQ,                      "Get Key Quietly"          },
  { PROTOCOL_BINARY_CMD_APPEND,                     "Append"                   },
  { PROTOCOL_BINARY_CMD_PREPEND,                    "Prepend"                  },
  { PROTOCOL_BINARY_CMD_STAT,                       "Statistics"               },
  { PROTOCOL_BINARY_CMD_SETQ,                       "Set Quietly"              },
  { PROTOCOL_BINARY_CMD_ADDQ,                       "Add Quietly"              },
  { PROTOCOL_BINARY_CMD_REPLACEQ,                   "Replace Quietly"          },
  { PROTOCOL_BINARY_CMD_DELETEQ,                    "Delete Quietly"           },
  { PROTOCOL_BINARY_CMD_INCREMENTQ,                 "Increment Quietly"        },
  { PROTOCOL_BINARY_CMD_DECREMENTQ,                 "Decrement Quietly"        },
  { PROTOCOL_BINARY_CMD_QUITQ,                      "Quit Quietly"             },
  { PROTOCOL_BINARY_CMD_FLUSHQ,                     "Flush Quietly"            },
  { PROTOCOL_BINARY_CMD_APPENDQ,                    "Append Quietly"           },
  { PROTOCOL_BINARY_CMD_PREPENDQ,                   "Prepend Quietly"          },
  { PROTOCOL_BINARY_CMD_VERBOSITY,                  "Verbosity"                },
  { PROTOCOL_BINARY_CMD_TOUCH,                      "Touch"                    },
  { PROTOCOL_BINARY_CMD_GAT,                        "Get and Touch"            },
  { PROTOCOL_BINARY_CMD_GATQ,                       "Gat and Touch Quietly"    },
  { PROTOCOL_BINARY_CMD_SASL_LIST_MECHS,            "List SASL Mechanisms"     },
  { PROTOCOL_BINARY_CMD_SASL_AUTH,                  "SASL Authenticate"        },
  { PROTOCOL_BINARY_CMD_SASL_STEP,                  "SASL Step"                },
  { PROTOCOL_BINARY_CMD_RGET,                       "Range Get"                },
  { PROTOCOL_BINARY_CMD_RSET,                       "Range Set"                },
  { PROTOCOL_BINARY_CMD_RSETQ,                      "Range Set Quietly"        },
  { PROTOCOL_BINARY_CMD_RAPPEND,                    "Range Append"             },
  { PROTOCOL_BINARY_CMD_RAPPENDQ,                   "Range Append Quietly"     },
  { PROTOCOL_BINARY_CMD_RPREPEND,                   "Range Prepend"            },
  { PROTOCOL_BINARY_CMD_RPREPENDQ,                  "Range Prepend Quietly"    },
  { PROTOCOL_BINARY_CMD_RDELETE,                    "Range Delete"             },
  { PROTOCOL_BINARY_CMD_RDELETEQ,                   "Range Delete Quietly"     },
  { PROTOCOL_BINARY_CMD_RINCR,                      "Range Increment"          },
  { PROTOCOL_BINARY_CMD_RINCRQ,                     "Range Increment Quietly"  },
  { PROTOCOL_BINARY_CMD_RDECR,                      "Range Decrement"          },
  { PROTOCOL_BINARY_CMD_RDECRQ,                     "Range Decrement Quietly"  },
  { PROTOCOL_BINARY_CMD_SET_VBUCKET,                "Set VBucket"              },
  { PROTOCOL_BINARY_CMD_GET_VBUCKET,                "Get VBucket"              },
  { PROTOCOL_BINARY_CMD_DEL_VBUCKET,                "Delete VBucket"           },
  { PROTOCOL_BINARY_CMD_TAP_CONNECT,                "TAP Connect"              },
  { PROTOCOL_BINARY_CMD_TAP_MUTATION,               "TAP Mutation"             },
  { PROTOCOL_BINARY_CMD_TAP_DELETE,                 "TAP Delete"               },
  { PROTOCOL_BINARY_CMD_TAP_FLUSH,                  "TAP Flush"                },
  { PROTOCOL_BINARY_CMD_TAP_OPAQUE,                 "TAP Opaque"               },
  { PROTOCOL_BINARY_CMD_TAP_VBUCKET_SET,            "TAP VBucket Set"          },
  { PROTOCOL_BINARY_CMD_TAP_CHECKPOINT_START,       "TAP Checkpoint Start"     },
  { PROTOCOL_BINARY_CMD_TAP_CHECKPOINT_END,         "TAP Checkpoint End"       },
  { PROTOCOL_BINARY_DCP_OPEN_CONNECTION,            "Open DCP Connection"      },
  { PROTOCOL_BINARY_DCP_ADD_STREAM,                 "Add DCP Stream"           },
  { PROTOCOL_BINARY_DCP_CLOSE_STREAM,               "Close DCP Stream"         },
  { PROTOCOL_BINARY_DCP_STREAM_REQUEST,             "DCP Stream Request"       },
  { PROTOCOL_BINARY_DCP_FAILOVER_LOG_REQUEST,       "Get DCP Failover Log"     },
  { PROTOCOL_BINARY_DCP_STREAM_END,                 "DCP Stream End"           },
  { PROTOCOL_BINARY_DCP_SNAPSHOT_MARKER,            "DCP Snapshot Marker"      },
  { PROTOCOL_BINARY_DCP_MUTATION,                   "DCP (Key) Mutation"       },
  { PROTOCOL_BINARY_DCP_DELETION,                   "DCP (Key) Deletion"       },
  { PROTOCOL_BINARY_DCP_EXPIRATION,                 "DCP (Key) Expiration"     },
  { PROTOCOL_BINARY_DCP_FLUSH,                      "DCP Flush"                },
  { PROTOCOL_BINARY_DCP_SET_VBUCKET_STATE,          "Set DCP VBucket State"    },
  { PROTOCOL_BINARY_CMD_STOP_PERSISTENCE,           "Stop Persistence"         },
  { PROTOCOL_BINARY_CMD_START_PERSISTENCE,          "Start Persistence"        },
  { PROTOCOL_BINARY_CMD_SET_PARAM,                  "Set Parameter"            },
  { PROTOCOL_BINARY_CMD_GET_REPLICA,                "Get Replica"              },
  { PROTOCOL_BINARY_CMD_CREATE_BUCKET,              "Create Bucket"            },
  { PROTOCOL_BINARY_CMD_DELETE_BUCKET,              "Delete Bucket"            },
  { PROTOCOL_BINARY_CMD_LIST_BUCKETS,               "List Buckets"             },
  { PROTOCOL_BINARY_CMD_EXPAND_BUCKET,              "Expand Bucket"            },
  { PROTOCOL_BINARY_CMD_SELECT_BUCKET,              "Select Bucket"            },
  { PROTOCOL_BINARY_CMD_START_REPLICATION,          "Start Replication"        },
  { PROTOCOL_BINARY_CMD_STOP_REPLICATION,           "Stop Replication"         },
  { PROTOCOL_BINARY_CMD_OBSERVE,                    "Observe"                  },
  { PROTOCOL_BINARY_CMD_EVICT_KEY,                  "Evict Key"                },
  { PROTOCOL_BINARY_CMD_GET_LOCKED,                 "Get Locked"               },
  { PROTOCOL_BINARY_CMD_UNLOCK_KEY,                 "Unlock Key"               },
  { PROTOCOL_BINARY_CMD_SYNC,                       "Sync"                     },
  { PROTOCOL_BINARY_CMD_LAST_CLOSED_CHECKPOINT,     "Last Closed Checkpoint"   },
  { PROTOCOL_BINARY_CMD_RESTORE_FILE,               "Restore File"             },
  { PROTOCOL_BINARY_CMD_RESTORE_ABORT,              "Restore Abort"            },
  { PROTOCOL_BINARY_CMD_RESTORE_COMPLETE,           "Restore Complete"         },
  { PROTOCOL_BINARY_CMD_ONLINE_UPDATE_START,        "Online Update Start"      },
  { PROTOCOL_BINARY_CMD_ONLINE_UPDATE_COMPLETE,     "Online Update Complete"   },
  { PROTOCOL_BINARY_CMD_ONLINE_UPDATE_REVERT,       "Online Update Revert"     },
  { PROTOCOL_BINARY_CMD_DEREGISTER_TAP_CLIENT,      "Deregister TAP Client"    },
  { PROTOCOL_BINARY_CMD_RESET_REPLICATION_CHAIN,    "Reset Replication Chain"  },
  { PROTOCOL_BINARY_CMD_GET_META,                   "Get Meta"                 },
  { PROTOCOL_BINARY_CMD_GETQ_META,                  "Get Meta Quietly"         },
  { PROTOCOL_BINARY_CMD_SET_WITH_META,              "Set with Meta"            },
  { PROTOCOL_BINARY_CMD_SETQ_WITH_META,             "Set with Meta Quietly"    },
  { PROTOCOL_BINARY_CMD_ADD_WITH_META,              "Add with Meta"            },
  { PROTOCOL_BINARY_CMD_ADDQ_WITH_META,             "Add with Meta Quietly"    },
  { PROTOCOL_BINARY_CMD_SNAPSHOT_VB_STATES,         "Snapshot VBuckets States" },
  { PROTOCOL_BINARY_CMD_VBUCKET_BATCH_COUNT,        "VBucket Batch Count"      },
  { PROTOCOL_BINARY_CMD_SET_CLUSTER_CONFIG,         "Set Cluster Config"       },
  { PROTOCOL_BINARY_CMD_GET_CLUSTER_CONFIG,         "Get Cluster Config"       },
  /* Internally defined values not valid here */
  { 0, NULL }
};

static value_string_ext opcode_vals_ext = VALUE_STRING_EXT_INIT(opcode_vals);

static const value_string datatype_vals[] = {
  { DT_RAW_BYTES,          "Raw bytes"          },
  { 0, NULL }
};

static dissector_handle_t couchbase_tcp_handle;
static dissector_handle_t json_handle;

/* couchbase ports */
static range_t *couchbase_tcp_port_range;


/* desegmentation of COUCHBASE payload */
static gboolean couchbase_desegment_body = TRUE;


static guint
get_couchbase_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  guint32 bodylen;

  /* Get the length of the memcache body */
  bodylen = tvb_get_ntohl(tvb, offset + 8);

  /* That length doesn't include the header; add that in */
  if ((bodylen + COUCHBASE_HEADER_LEN) > G_MAXUINT32) {
    return G_MAXUINT32;
  } else {
    return bodylen + COUCHBASE_HEADER_LEN;
  }
}

static void
dissect_extras(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
               gint offset, guint8 extlen, guint8 opcode, gboolean request)
{
  proto_tree *extras_tree = NULL;
  proto_item *extras_item = NULL;
  gint        save_offset = offset, ii;
  guint       bpos;
  gboolean    illegal = FALSE;  /* Set when extras shall not be present */
  gboolean    missing = FALSE;  /* Set when extras is missing */
  gboolean    first_flag;
  guint32     flags;
  proto_item *tf;
  const gchar   *tap_connect_flags[] = {
    "BACKFILL", "DUMP", "LIST_VBUCKETS", "TAKEOVER_VBUCKETS",
    "SUPPORT_ACK", "REQUEST_KEYS_ONLY", "CHECKPOINT", "REGISTERED_CLIENT"
  };

  if (extlen) {
    extras_item = proto_tree_add_item(tree, hf_extras, tvb, offset, extlen, ENC_NA);
    extras_tree = proto_item_add_subtree(extras_item, ett_extras);
  }

  switch (opcode) {

  case PROTOCOL_BINARY_CMD_GET:
  case PROTOCOL_BINARY_CMD_GETQ:
  case PROTOCOL_BINARY_CMD_GETK:
  case PROTOCOL_BINARY_CMD_GETKQ:
    if (extlen) {
      if (request) {
        /* Request shall not have extras */
        illegal = TRUE;
      } else {
        proto_tree_add_item(extras_tree, hf_extras_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
      }
    } else if (!request) {
      /* Response must have extras */
      missing = TRUE;
    }
    break;

  case PROTOCOL_BINARY_CMD_SET:
  case PROTOCOL_BINARY_CMD_SETQ:
  case PROTOCOL_BINARY_CMD_ADD:
  case PROTOCOL_BINARY_CMD_ADDQ:
  case PROTOCOL_BINARY_CMD_REPLACE:
  case PROTOCOL_BINARY_CMD_REPLACEQ:
    if (extlen) {
      if (request) {
        proto_tree_add_item(extras_tree, hf_extras_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(extras_tree, hf_extras_expiration, tvb, offset, 4, ENC_BIG_ENDIAN);
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

  case PROTOCOL_BINARY_CMD_INCREMENT:
  case PROTOCOL_BINARY_CMD_INCREMENTQ:
  case PROTOCOL_BINARY_CMD_DECREMENT:
  case PROTOCOL_BINARY_CMD_DECREMENTQ:
    if (extlen) {
      if (request) {
        proto_tree_add_item(extras_tree, hf_extras_delta, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;

        proto_tree_add_item(extras_tree, hf_extras_initial, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;

        proto_tree_add_item(extras_tree, hf_extras_expiration, tvb, offset, 4, ENC_BIG_ENDIAN);
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

  case PROTOCOL_BINARY_CMD_FLUSH:
  case PROTOCOL_BINARY_CMD_FLUSHQ:
    if (extlen) {
      proto_tree_add_item(extras_tree, hf_extras_expiration, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
    }
    break;

  case PROTOCOL_BINARY_CMD_DELETE:
  case PROTOCOL_BINARY_CMD_DELETEQ:
  case PROTOCOL_BINARY_CMD_QUIT:
  case PROTOCOL_BINARY_CMD_QUITQ:
  case PROTOCOL_BINARY_CMD_VERSION:
  case PROTOCOL_BINARY_CMD_APPEND:
  case PROTOCOL_BINARY_CMD_APPENDQ:
  case PROTOCOL_BINARY_CMD_PREPEND:
  case PROTOCOL_BINARY_CMD_PREPENDQ:
  case PROTOCOL_BINARY_CMD_STAT:
  case PROTOCOL_BINARY_CMD_OBSERVE:
    /* Must not have extras */
    if (extlen) {
      illegal = TRUE;
    }
    break;

  case PROTOCOL_BINARY_CMD_TAP_CONNECT:
    {
    static const int * extra_flags[] = {
        &hf_extras_flags_backfill,
        &hf_extras_flags_dump,
        &hf_extras_flags_list_vbuckets,
        &hf_extras_flags_takeover_vbuckets,
        &hf_extras_flags_support_ack,
        &hf_extras_flags_request_keys_only,
        &hf_extras_flags_checkpoint,
        NULL
    };

    tf = proto_tree_add_bitmask(extras_tree, tvb, offset, hf_extras_flags, ett_extras_flags, extra_flags, ENC_BIG_ENDIAN);

    flags = tvb_get_ntohl(tvb, offset);
    first_flag = TRUE;
    for (ii = 0; ii < 8; ii++) {
      bpos = 1 << ii;
      if (flags & bpos) {
        if (first_flag) {
          proto_item_append_text(tf, " (");
        }
        proto_item_append_text(tf, "%s%s",
                                  first_flag ? "" : ", ",
                                  tap_connect_flags[ii]);
        first_flag = FALSE;
      }
    }
    if (first_flag == TRUE) {
      proto_item_append_text(tf, " <None>");
    } else {
      proto_item_append_text(tf, ")");
    }

    offset += 4;
    }
    break;

  case PROTOCOL_BINARY_CMD_TAP_MUTATION:
    break;

  case PROTOCOL_BINARY_CMD_TAP_DELETE:
    break;

  case PROTOCOL_BINARY_CMD_TAP_FLUSH:
    break;

  case PROTOCOL_BINARY_CMD_TAP_OPAQUE:
    break;

  case PROTOCOL_BINARY_CMD_TAP_VBUCKET_SET:
    break;

  case PROTOCOL_BINARY_CMD_TAP_CHECKPOINT_START:
    break;

  case PROTOCOL_BINARY_CMD_TAP_CHECKPOINT_END:
    break;

  default:
    if (extlen) {
      /* Decode as unknown extras */
      proto_tree_add_item(extras_tree, hf_extras_unknown, tvb, offset, extlen, ENC_NA);
      offset += extlen;
    }
    break;
  }
  if (illegal) {
    proto_tree_add_expert_format(extras_tree, pinfo, &ef_warn_shall_not_have_extras, tvb, offset, 0,
                           "%s %s should not have extras",
                           val_to_str_ext(opcode, &opcode_vals_ext, "Opcode 0x%x"),
                           request ? "Request" : "Response");
    offset += extlen;
  } else if (missing) {

    proto_tree_add_expert_format(tree, pinfo, &ef_warn_must_have_extras, tvb, offset, 0,
                           "%s %s must have Extras",
                           val_to_str_ext(opcode, &opcode_vals_ext, "Opcode Ox%x"),
                           request ? "Request" : "Response");
}

  if ((offset - save_offset) != extlen) {
    expert_add_info_format(pinfo, extras_item, &ef_warn_illegal_extras_length,
                           "Illegal Extras length, should be %d", offset - save_offset);
  }
}

static void
dissect_key(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
            gint offset, int keylen, guint8 opcode, gboolean request)
{
  proto_item *ti = NULL;
  gboolean    illegal = FALSE;  /* Set when key shall not be present */
  gboolean    missing = FALSE;  /* Set when key is missing */

  if (keylen) {
    ti = proto_tree_add_item(tree, hf_key, tvb, offset, keylen, ENC_ASCII | ENC_NA);
    offset += keylen;
  }

  /* inSanity check */
  if (keylen) {
    if ((opcode == PROTOCOL_BINARY_CMD_QUIT) ||
        (opcode == PROTOCOL_BINARY_CMD_QUITQ) ||
        (opcode == PROTOCOL_BINARY_CMD_NOOP) ||
        (opcode == PROTOCOL_BINARY_CMD_VERSION) ||
        (opcode == PROTOCOL_BINARY_DCP_FAILOVER_LOG_REQUEST)
        ) {
      /* Request and Response must not have key */
      illegal = TRUE;
    }
    if ((opcode == PROTOCOL_BINARY_CMD_SET) ||
        (opcode == PROTOCOL_BINARY_CMD_ADD) ||
        (opcode == PROTOCOL_BINARY_CMD_REPLACE) ||
        (opcode == PROTOCOL_BINARY_CMD_DELETE) ||
        (opcode == PROTOCOL_BINARY_CMD_SETQ) ||
        (opcode == PROTOCOL_BINARY_CMD_ADDQ) ||
        (opcode == PROTOCOL_BINARY_CMD_REPLACEQ) ||
        (opcode == PROTOCOL_BINARY_CMD_DELETEQ) ||
        (opcode == PROTOCOL_BINARY_CMD_FLUSH) ||
        (opcode == PROTOCOL_BINARY_CMD_APPEND) ||
        (opcode == PROTOCOL_BINARY_CMD_PREPEND) ||
        (opcode == PROTOCOL_BINARY_CMD_FLUSHQ) ||
        (opcode == PROTOCOL_BINARY_CMD_APPENDQ) ||
        (opcode == PROTOCOL_BINARY_CMD_PREPENDQ)) {
      /* Response must not have a key */
      if (!request) {
        illegal = TRUE;
      }
    }
    if ((opcode == PROTOCOL_BINARY_DCP_ADD_STREAM) ||
        (opcode == PROTOCOL_BINARY_DCP_CLOSE_STREAM) ||
        (opcode == PROTOCOL_BINARY_DCP_STREAM_REQUEST) ||
        (opcode == PROTOCOL_BINARY_DCP_STREAM_END) ||
        (opcode == PROTOCOL_BINARY_DCP_SNAPSHOT_MARKER) ||
        (opcode == PROTOCOL_BINARY_DCP_FLUSH) ||
        (opcode == PROTOCOL_BINARY_DCP_SET_VBUCKET_STATE)) {
      /* Request must not have a key */
      if (request) {
        illegal = TRUE;
      }
    }
  } else {
    if ((opcode == PROTOCOL_BINARY_CMD_GET) ||
        (opcode == PROTOCOL_BINARY_CMD_GETQ) ||
        (opcode == PROTOCOL_BINARY_CMD_GETK) ||
        (opcode == PROTOCOL_BINARY_CMD_GETKQ) ||
        (opcode == PROTOCOL_BINARY_CMD_SET) ||
        (opcode == PROTOCOL_BINARY_CMD_ADD) ||
        (opcode == PROTOCOL_BINARY_CMD_REPLACE) ||
        (opcode == PROTOCOL_BINARY_CMD_DELETE) ||
        (opcode == PROTOCOL_BINARY_CMD_SETQ) ||
        (opcode == PROTOCOL_BINARY_CMD_ADDQ) ||
        (opcode == PROTOCOL_BINARY_CMD_REPLACEQ) ||
        (opcode == PROTOCOL_BINARY_CMD_DELETEQ) ||
        (opcode == PROTOCOL_BINARY_CMD_INCREMENT) ||
        (opcode == PROTOCOL_BINARY_CMD_DECREMENT) ||
        (opcode == PROTOCOL_BINARY_CMD_INCREMENTQ) ||
        (opcode == PROTOCOL_BINARY_CMD_DECREMENTQ) ||
        (opcode == PROTOCOL_BINARY_DCP_OPEN_CONNECTION)||
        (opcode == PROTOCOL_BINARY_DCP_MUTATION) ||
        (opcode == PROTOCOL_BINARY_DCP_DELETION) ||
        (opcode == PROTOCOL_BINARY_DCP_EXPIRATION)) {
      /* Request must have key */
      if (request) {
        missing = TRUE;
      }
    }
  }

  if (illegal) {
    expert_add_info_format(pinfo, ti, &ef_warn_shall_not_have_key, "%s %s shall not have Key",
                           val_to_str_ext(opcode, &opcode_vals_ext, "Opcode 0x%x"),
                           request ? "Request" : "Response");
  } else if (missing) {
    proto_tree_add_expert_format(tree, pinfo, &ef_warn_must_have_key, tvb, offset, 0,
                           "%s %s must have Key",
                           val_to_str_ext(opcode, &opcode_vals_ext, "Opcode Ox%x"),
                           request ? "Request" : "Response");
  }
}

static void
dissect_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
              gint offset, guint32 value_len, guint8 opcode, gboolean request)
{
  proto_item *ti = NULL;
  proto_tree *observe_tree;
  gboolean    illegal = FALSE;  /* Set when value shall not be present */
  gboolean    missing = FALSE;  /* Set when value is missing */

  if (value_len > 0) {
    if (opcode == PROTOCOL_BINARY_CMD_OBSERVE) {
      gint oo = offset, end = offset + value_len;
      ti = proto_tree_add_item(tree, hf_observe, tvb, offset, value_len, ENC_ASCII|ENC_NA);
      observe_tree = proto_item_add_subtree(ti, ett_observe);
      while (oo < end) {
        guint16 kl; /* keylength */
        proto_tree_add_item(observe_tree, hf_observe_vbucket, tvb, oo, 2, ENC_BIG_ENDIAN);
        oo += 2;
        kl = tvb_get_ntohs(tvb, oo);
        proto_tree_add_item(observe_tree, hf_observe_keylength, tvb, oo, 2, ENC_BIG_ENDIAN);
        oo += 2;
        proto_tree_add_item(observe_tree, hf_observe_key, tvb, oo, kl, ENC_ASCII|ENC_NA);
        oo += kl;
        if (!request) {
          proto_tree_add_item(observe_tree, hf_observe_status, tvb, oo, 1, ENC_BIG_ENDIAN);
          oo++;
          proto_tree_add_item(observe_tree, hf_observe_cas, tvb, oo, 8, ENC_BIG_ENDIAN);
          oo += 8;
        }
      }
    } else if (!request && ((opcode == PROTOCOL_BINARY_CMD_INCREMENT) || (opcode == PROTOCOL_BINARY_CMD_DECREMENT))) {
      ti = proto_tree_add_item(tree, hf_uint64_response, tvb, offset, 8, ENC_BIG_ENDIAN);
      if (value_len != 8) {
        expert_add_info_format(pinfo, ti, &ef_warn_illegal_value_length, "Illegal Value length, should be 8");
      }
    } else if (!request && opcode == PROTOCOL_BINARY_CMD_GET_CLUSTER_CONFIG) {
      tvbuff_t *json_tvb;
      ti = proto_tree_add_item(tree, hf_value, tvb, offset, value_len, ENC_ASCII | ENC_NA);
      json_tvb = tvb_new_subset(tvb, offset, value_len, value_len);
      call_dissector(json_handle, json_tvb, pinfo, tree);
    } else {
      ti = proto_tree_add_item(tree, hf_value, tvb, offset, value_len, ENC_ASCII | ENC_NA);
    }
}

  /* Sanity check */
  if (value_len) {
    if ((opcode == PROTOCOL_BINARY_CMD_GET) ||
        (opcode == PROTOCOL_BINARY_CMD_GETQ) ||
        (opcode == PROTOCOL_BINARY_CMD_GETK) ||
        (opcode == PROTOCOL_BINARY_CMD_GETKQ) ||
        (opcode == PROTOCOL_BINARY_CMD_INCREMENT) ||
        (opcode == PROTOCOL_BINARY_CMD_DECREMENT) ||
        (opcode == PROTOCOL_BINARY_CMD_VERSION) ||
        (opcode == PROTOCOL_BINARY_CMD_INCREMENTQ) ||
        (opcode == PROTOCOL_BINARY_CMD_DECREMENTQ) ||
        (opcode == PROTOCOL_BINARY_DCP_OPEN_CONNECTION) ||
        (opcode == PROTOCOL_BINARY_DCP_ADD_STREAM) ||
        (opcode == PROTOCOL_BINARY_DCP_CLOSE_STREAM) ||
        (opcode == PROTOCOL_BINARY_DCP_FAILOVER_LOG_REQUEST) ||
        (opcode == PROTOCOL_BINARY_DCP_STREAM_END) ||
        (opcode == PROTOCOL_BINARY_DCP_SNAPSHOT_MARKER) ||
        (opcode == PROTOCOL_BINARY_DCP_DELETION) ||
        (opcode == PROTOCOL_BINARY_DCP_EXPIRATION) ||
        (opcode == PROTOCOL_BINARY_DCP_FLUSH) ||
        (opcode == PROTOCOL_BINARY_DCP_SET_VBUCKET_STATE)) {
      /* Request must not have value */
      if (request) {
        illegal = TRUE;
      }
    }
    if ((opcode == PROTOCOL_BINARY_CMD_DELETE) ||
        (opcode == PROTOCOL_BINARY_CMD_QUIT) ||
        (opcode == PROTOCOL_BINARY_CMD_FLUSH) ||
        (opcode == PROTOCOL_BINARY_CMD_NOOP) ||
        (opcode == PROTOCOL_BINARY_CMD_DELETEQ) ||
        (opcode == PROTOCOL_BINARY_CMD_QUITQ) ||
        (opcode == PROTOCOL_BINARY_CMD_FLUSHQ)) {
      /* Request and Response must not have value */
      illegal = TRUE;
    }
    if ((opcode == PROTOCOL_BINARY_CMD_SET) ||
        (opcode == PROTOCOL_BINARY_CMD_ADD) ||
        (opcode == PROTOCOL_BINARY_CMD_REPLACE) ||
        (opcode == PROTOCOL_BINARY_CMD_SETQ) ||
        (opcode == PROTOCOL_BINARY_CMD_ADDQ) ||
        (opcode == PROTOCOL_BINARY_CMD_REPLACEQ) ||
        (opcode == PROTOCOL_BINARY_CMD_APPEND) ||
        (opcode == PROTOCOL_BINARY_CMD_PREPEND) ||
        (opcode == PROTOCOL_BINARY_CMD_APPENDQ) ||
        (opcode == PROTOCOL_BINARY_CMD_PREPENDQ)) {
      /* Response must not have value */
      if (!request) {
        illegal = TRUE;
      }
    }
  } else {
    if (opcode == PROTOCOL_BINARY_DCP_FAILOVER_LOG_REQUEST) {
      /* Successful response must have value */
      if (!request) {
        missing = TRUE;
      }
    }
  }

  if (illegal) {
    expert_add_info_format(pinfo, ti, &ef_warn_shall_not_have_value, "%s %s shall not have Value",
                           val_to_str_ext(opcode, &opcode_vals_ext, "Opcode 0x%x"),
                           request ? "Request" : "Response");
  } else if (missing) {
    expert_add_info_format(pinfo, ti, &ei_value_missing, "%s %s must have Value",
                           val_to_str_ext(opcode, &opcode_vals_ext, "Opcode 0x%x"),
                           request ? "Request" : "Response");
  }
}

static int
dissect_couchbase(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree *couchbase_tree;
  proto_item *couchbase_item, *ti;
  gint        offset = 0;
  guint8      magic, opcode, extlen;
  guint16     keylen, status = 0, vbucket;
  guint32     bodylen, value_len;
  gboolean    request;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);
  col_clear(pinfo->cinfo, COL_INFO);

  couchbase_item = proto_tree_add_item(tree, proto_couchbase, tvb, offset, -1, ENC_NA);
  couchbase_tree = proto_item_add_subtree(couchbase_item, ett_couchbase);

  magic = tvb_get_guint8(tvb, offset);
  ti = proto_tree_add_item(couchbase_tree, hf_magic, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  if (try_val_to_str(magic, magic_vals) == NULL) {
    expert_add_info_format(pinfo, ti, &ef_warn_unknown_magic_byte, "Unknown magic byte: 0x%x", magic);
  }

  opcode = tvb_get_guint8(tvb, offset);
  ti = proto_tree_add_item(couchbase_tree, hf_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  if (try_val_to_str_ext(opcode, &opcode_vals_ext) == NULL) {
    expert_add_info_format(pinfo, ti, &ef_warn_unknown_opcode, "Unknown opcode: 0x%x", opcode);
  }

  proto_item_append_text(couchbase_item, ", %s %s, Opcode: 0x%x",
                         val_to_str_ext(opcode, &opcode_vals_ext, "Unknown opcode"),
                         val_to_str(magic, magic_vals, "Unknown magic (0x%x)"),
                         opcode);

  col_append_fstr(pinfo->cinfo, COL_INFO, "%s %s, Opcode: 0x%x",
                  val_to_str_ext(opcode, &opcode_vals_ext, "Unknown opcode (0x%x)"),
                  val_to_str(magic, magic_vals, "Unknown magic (0x%x)"),
                  opcode);

  keylen = tvb_get_ntohs(tvb, offset);
  proto_tree_add_item(couchbase_tree, hf_keylength, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  extlen = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(couchbase_tree, hf_extlength, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(couchbase_tree, hf_datatype, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  if (magic & 0x01) {    /* We suppose this is a response, even when unknown magic byte */
    request = FALSE;
    status = tvb_get_ntohs(tvb, offset);
    ti = proto_tree_add_item(couchbase_tree, hf_status, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (status != 0) {
      expert_add_info_format(pinfo, ti, &ef_warn_unknown_opcode, "%s: %s",
                             val_to_str_ext(opcode, &opcode_vals_ext, "Unknown opcode (0x%x)"),
                             val_to_str_ext(status, &status_vals_ext, "Status: 0x%x"));
    }
  } else {
    request = TRUE;
    vbucket = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(couchbase_tree, hf_vbucket, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (opcode != PROTOCOL_BINARY_CMD_OBSERVE) {
      proto_item_append_text(couchbase_item, ", VBucket: 0x%x", vbucket);
      col_append_fstr(pinfo->cinfo, COL_INFO, ", VBucket: 0x%x", vbucket);
    }
  }
  offset += 2;

  bodylen = tvb_get_ntohl(tvb, offset);
  value_len = bodylen - extlen - keylen;
  ti = proto_tree_add_uint(couchbase_tree, hf_value_length, tvb, offset, 0, value_len);
  PROTO_ITEM_SET_GENERATED(ti);

  proto_tree_add_item(couchbase_tree, hf_total_bodylength, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  /* little endian (network) encoding because the client shouldn't apply any
   * conversions */
  proto_tree_add_item(couchbase_tree, hf_opaque, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  if (opcode == PROTOCOL_BINARY_CMD_OBSERVE) {
    proto_tree_add_item(couchbase_tree, hf_ttp, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(couchbase_tree, hf_ttr, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
  } else {
    proto_tree_add_item(couchbase_tree, hf_cas, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
  }

  if (status == 0) {
    dissect_extras(tvb, pinfo, couchbase_tree, offset, extlen, opcode, request);
    offset += extlen;

    dissect_key(tvb, pinfo, couchbase_tree, offset, keylen, opcode, request);
    offset += keylen;

    dissect_value(tvb, pinfo, couchbase_tree, offset, value_len, opcode, request);
} else if (bodylen) {
    proto_tree_add_item(couchbase_tree, hf_value, tvb, offset, bodylen, ENC_ASCII | ENC_NA);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
                    val_to_str_ext(status, &status_vals_ext, "Unknown status: 0x%x"));
  } else {
    proto_tree_add_expert_format(couchbase_tree, pinfo, &ei_value_missing, tvb, offset, 0,
                           "%s with status %s (0x%x) must have Value",
                           val_to_str_ext(opcode, &opcode_vals_ext, "Opcode 0x%x"),
                           val_to_str_ext(status, &status_vals_ext, "Unknown"), status);
  }
  return tvb_reported_length(tvb);
}

/* Dissect tcp packets based on the type of protocol (text/binary) */
static int
dissect_couchbase_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  gint        offset = 0;
  guint8      magic;

  magic = tvb_get_guint8(tvb, offset);

  if (try_val_to_str(magic, magic_vals) == NULL)
      return 0;

  tcp_dissect_pdus(tvb, pinfo, tree, couchbase_desegment_body, 12,
                     get_couchbase_pdu_len, dissect_couchbase, data);

  return tvb_captured_length(tvb);
}


/* Registration functions; register couchbase protocol,
 * its configuration options and also register the tcp dissectors.
 */
void
proto_register_couchbase(void)
{
  static hf_register_info hf[] = {
    { &hf_magic, { "Magic", "couchbase.magic", FT_UINT8, BASE_HEX, VALS(magic_vals), 0x0, "Magic number", HFILL } },
    { &hf_opcode, { "Opcode", "couchbase.opcode", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &opcode_vals_ext, 0x0, "Command code", HFILL } },
    { &hf_extlength, { "Extras Length", "couchbase.extras.length", FT_UINT8, BASE_DEC, NULL, 0x0, "Length in bytes of the command extras", HFILL } },
    { &hf_keylength, { "Key Length", "couchbase.key.length", FT_UINT16, BASE_DEC, NULL, 0x0, "Length in bytes of the text key that follows the command extras", HFILL } },
    { &hf_value_length, { "Value Length", "couchbase.value.length", FT_UINT32, BASE_DEC, NULL, 0x0, "Length in bytes of the value that follows the key", HFILL } },
    { &hf_datatype, { "Data Type", "couchbase.datatype", FT_UINT8, BASE_HEX, VALS(datatype_vals), 0x0, NULL, HFILL } },
    { &hf_vbucket, { "VBucket", "couchbase.vbucket", FT_UINT16, BASE_HEX, NULL, 0x0, "VBucket ID", HFILL } },
    { &hf_status, { "Status", "couchbase.status", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &status_vals_ext, 0x0, "Status of the response", HFILL } },
    { &hf_total_bodylength, { "Total Body Length", "couchbase.total_bodylength", FT_UINT32, BASE_DEC, NULL, 0x0, "Length in bytes of extra + key + value", HFILL } },
    { &hf_opaque, { "Opaque", "couchbase.opaque", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_cas, { "CAS", "couchbase.cas", FT_UINT64, BASE_HEX, NULL, 0x0, "Data version check", HFILL } },
    { &hf_ttp, { "Time to Persist", "couchbase.ttp", FT_UINT32, BASE_DEC, NULL, 0x0, "Approximate time needed to persist the key (milliseconds)", HFILL } },
    { &hf_ttr, { "Time to Replicate", "couchbase.ttr", FT_UINT32, BASE_DEC, NULL, 0x0, "Approximate time needed to replicate the key (milliseconds)", HFILL } },
    { &hf_extras, { "Extras", "couchbase.extras", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_flags, { "Flags", "couchbase.extras.flags", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_flags_backfill, { "Backfill Age", "couchbase.extras.flags.backfill", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x01, NULL, HFILL } },
    { &hf_extras_flags_dump, { "Dump", "couchbase.extras.flags.dump", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x02, NULL, HFILL } },
    { &hf_extras_flags_list_vbuckets, { "List VBuckets", "couchbase.extras.flags.list_vbuckets", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x04, NULL, HFILL } },
    { &hf_extras_flags_takeover_vbuckets, { "Takeover VBuckets", "couchbase.extras.flags.takeover_vbuckets", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x08, NULL, HFILL } },
    { &hf_extras_flags_support_ack, { "Support ACK", "couchbase.extras.flags.support_ack", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x10, NULL, HFILL } },
    { &hf_extras_flags_request_keys_only, { "Request Keys Only", "couchbase.extras.flags.request_keys_only", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x20, NULL, HFILL } },
    { &hf_extras_flags_checkpoint, { "Checkpoint", "couchbase.extras.flags.checkpoint", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x40, NULL, HFILL } },
    { &hf_extras_expiration, { "Expiration", "couchbase.extras.expiration", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_delta, { "Amount to Add", "couchbase.extras.delta", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_initial, { "Initial Value", "couchbase.extras.initial", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_unknown, { "Unknown", "couchbase.extras.unknown", FT_BYTES, BASE_NONE, NULL, 0x0, "Unknown Extras", HFILL } },
    { &hf_key, { "Key", "couchbase.key", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_value, { "Value", "couchbase.value", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_uint64_response, { "Response", "couchbase.extras.response", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_observe, { "Observe", "couchbase.observe", FT_STRING, BASE_NONE, NULL, 0x0, "The observe properties", HFILL } },
    { &hf_observe_key, { "Key", "couchbase.observe.key", FT_STRING, BASE_NONE, NULL, 0x0, "The observable key", HFILL } },
    { &hf_observe_keylength, { "Key Length", "couchbase.observe.keylength", FT_UINT16, BASE_DEC, NULL, 0x0, "The length of the observable key", HFILL } },
    { &hf_observe_vbucket, { "VBucket", "couchbase.observe.vbucket", FT_UINT16, BASE_HEX, NULL, 0x0, "VBucket of the observable key", HFILL } },
    { &hf_observe_status, { "Status", "couchbase.observe.status", FT_UINT8, BASE_HEX, NULL, 0x0, "Status of the observable key", HFILL } },
    { &hf_observe_cas, { "CAS", "couchbase.observe.cas", FT_UINT64, BASE_HEX, NULL, 0x0, "CAS value of the observable key", HFILL } },
  };

  static ei_register_info ei[] = {
    { &ei_value_missing, { "couchbase.value_missing", PI_PROTOCOL, PI_WARN, "Value is mandatory for this command", EXPFILL }},
    { &ef_warn_shall_not_have_value, { "couchbase.warn.shall_not_have_value", PI_UNDECODED, PI_WARN, "Packet shall not have value", EXPFILL }},
    { &ef_warn_shall_not_have_extras, { "couchbase.warn.shall_not_have_extras", PI_UNDECODED, PI_WARN, "Packet shall not have extras", EXPFILL }},
    { &ef_warn_shall_not_have_key, { "couchbase.warn.shall_not_have_key", PI_UNDECODED, PI_WARN, "Packet shall not have key", EXPFILL }},
    { &ef_warn_must_have_extras, { "couchbase.warn.must_have_extras", PI_UNDECODED, PI_WARN, "Packet must have extras", EXPFILL }},
    { &ef_warn_must_have_key, { "couchbase.warn.must_have_key", PI_UNDECODED, PI_WARN, "%s %s must have Key", EXPFILL }},
    { &ef_warn_illegal_extras_length, { "couchbase.warn.illegal_extras_length", PI_UNDECODED, PI_WARN, "Illegal Extras length", EXPFILL }},
    { &ef_warn_illegal_value_length, { "couchbase.warn.illegal_value_length", PI_UNDECODED, PI_WARN, "Illegal Value length", EXPFILL }},
    { &ef_warn_unknown_magic_byte, { "couchbase.warn.unknown_magic_byte", PI_UNDECODED, PI_WARN, "Unknown magic byte", EXPFILL }},
    { &ef_warn_unknown_opcode, { "couchbase.warn.unknown_opcode", PI_UNDECODED, PI_WARN, "Unknown opcode", EXPFILL }},
    { &ef_note_status_code, { "couchbase.note.status_code", PI_RESPONSE_CODE, PI_NOTE, "Status", EXPFILL }}
  };

  static gint *ett[] = {
    &ett_couchbase,
    &ett_extras,
    &ett_extras_flags,
    &ett_observe
  };

  module_t *couchbase_module;
  expert_module_t* expert_couchbase;

  proto_couchbase = proto_register_protocol(PNAME, PSNAME, PFNAME);

  proto_register_field_array(proto_couchbase, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  expert_couchbase = expert_register_protocol(proto_couchbase);
  expert_register_field_array(expert_couchbase, ei, array_length(ei));

  /* Set default port range */
  range_convert_str(&couchbase_tcp_port_range, COUCHBASE_DEFAULT_PORT, MAX_TCP_PORT);

  /* Register our configuration options */
  couchbase_module = prefs_register_protocol(proto_couchbase, NULL);

  prefs_register_bool_preference(couchbase_module, "desegment_pdus",
                                 "Reassemble PDUs spanning multiple TCP segments",
                                 "Whether the memcache dissector should reassemble PDUs"
                                 " spanning multiple TCP segments."
                                 " To use this option, you must also enable \"Allow subdissectors"
                                 " to reassemble TCP streams\" in the TCP protocol settings.",
                                 &couchbase_desegment_body);

  prefs_register_range_preference(couchbase_module, "tcp.ports", "Couchbase TCP ports",
                                  "TCP ports to be decoded as Couchbase (default is "
                                  COUCHBASE_DEFAULT_PORT ")",
                                  &couchbase_tcp_port_range, MAX_TCP_PORT);
}

/* Register the tcp couchbase dissector. */
void
proto_reg_handoff_couchbase(void)
{
  static range_t *tcp_port_range;
  static gboolean initialized = FALSE;

  if (initialized == FALSE) {
    couchbase_tcp_handle = new_create_dissector_handle(dissect_couchbase_tcp, proto_couchbase);
    initialized = TRUE;
  }
  else {
    dissector_delete_uint_range("tcp.port", tcp_port_range, couchbase_tcp_handle);
    g_free(tcp_port_range);
  }

  tcp_port_range = range_copy(couchbase_tcp_port_range);
  dissector_add_uint_range("tcp.port", tcp_port_range, couchbase_tcp_handle);

  json_handle = find_dissector("json");
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
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
