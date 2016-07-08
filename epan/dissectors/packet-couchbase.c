/* packet-couchbase.c
 *
 * Routines for Couchbase Protocol
 * Copyright 2015-2016, Dave Rigby <daver@couchbase.com>
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
#define PROTOCOL_BINARY_RESPONSE_ROLLBACK           0x23
#define PROTOCOL_BINARY_RESPONSE_EACCESS            0x24
#define PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND    0x81
#define PROTOCOL_BINARY_RESPONSE_ENOMEM             0x82
#define PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED      0x83
#define PROTOCOL_BINARY_RESPONSE_EINTERNAL          0x84
#define PROTOCOL_BINARY_RESPONSE_EBUSY              0x85
#define PROTOCOL_BINARY_RESPONSE_ETMPFAIL           0x86
#define PROTOCOL_BINARY_RESPONSE_SUBDOC_PATH_ENOENT         0xc0
#define PROTOCOL_BINARY_RESPONSE_SUBDOC_PATH_MISMATCH       0xc1
#define PROTOCOL_BINARY_RESPONSE_SUBDOC_PATH_EINVAL         0xc2
#define PROTOCOL_BINARY_RESPONSE_SUBDOC_PATH_E2BIG          0xc3
#define PROTOCOL_BINARY_RESPONSE_SUBDOC_DOC_E2DEEP          0xc4
#define PROTOCOL_BINARY_RESPONSE_SUBDOC_VALUE_CANTINSERT    0xc5
#define PROTOCOL_BINARY_RESPONSE_SUBDOC_DOC_NOTJSON         0xc6
#define PROTOCOL_BINARY_RESPONSE_SUBDOC_NUM_ERANGE          0xc7
#define PROTOCOL_BINARY_RESPONSE_SUBDOC_DELTA_ERANGE        0xc8
#define PROTOCOL_BINARY_RESPONSE_SUBDOC_PATH_EEXISTS        0xc9
#define PROTOCOL_BINARY_RESPONSE_SUBDOC_VALUE_ETOODEEP      0xca
#define PROTOCOL_BINARY_RESPONSE_SUBDOC_INVALID_COMBO       0xcb
#define PROTOCOL_BINARY_RESPONSE_SUBDOC_MULTI_PATH_FAILURE  0xcc

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
#define PROTOCOL_BINARY_CMD_HELLO                   0x1f

 /* SASL operations */
#define PROTOCOL_BINARY_CMD_SASL_LIST_MECHS         0x20
#define PROTOCOL_BINARY_CMD_SASL_AUTH               0x21
#define PROTOCOL_BINARY_CMD_SASL_STEP               0x22

/* Control */
#define PROTOCOL_BINARY_CMD_IOCTL_GET               0x23
#define PROTOCOL_BINARY_CMD_IOCTL_SET               0x24

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

#define PROTOCOL_BINARY_CMD_GET_ALL_VB_SEQNOS       0x48

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
#define PROTOCOL_BINARY_CMD_OBSERVE_SEQNO           0x91
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
#define PROTOCOL_BINARY_CMD_DEL_WITH_META           0xa8
#define PROTOCOL_BINARY_CMD_DELQ_WITH_META          0xa9
#define PROTOCOL_BINARY_CMD_CREATE_CHECKPOINT       0xaa
#define PROTOCOL_BINARY_CMD_NOTIFY_VBUCKET_UPDATE   0xac
#define PROTOCOL_BINARY_CMD_ENABLE_TRAFFIC          0xad
#define PROTOCOL_BINARY_CMD_DISABLE_TRAFFIC         0xae
#define PROTOCOL_BINARY_CMD_CHANGE_VB_FILTER        0xb0
#define PROTOCOL_BINARY_CMD_CHECKPOINT_PERSISTENCE  0xb1
#define PROTOCOL_BINARY_CMD_RETURN_META             0xb2
#define PROTOCOL_BINARY_CMD_COMPACT_DB              0xb3


#define PROTOCOL_BINARY_CMD_SET_CLUSTER_CONFIG      0xb4
#define PROTOCOL_BINARY_CMD_GET_CLUSTER_CONFIG      0xb5

/* Sub-document API commands */
#define PROTOCOL_BINARY_CMD_SUBDOC_GET              0xc5
#define PROTOCOL_BINARY_CMD_SUBDOC_EXISTS           0xc6
#define PROTOCOL_BINARY_CMD_SUBDOC_DICT_ADD         0xc7
#define PROTOCOL_BINARY_CMD_SUBDOC_DICT_UPSERT      0xc8
#define PROTOCOL_BINARY_CMD_SUBDOC_DELETE           0xc9
#define PROTOCOL_BINARY_CMD_SUBDOC_REPLACE          0xca
#define PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_PUSH_LAST  0xcb
#define PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_PUSH_FIRST 0xcc
#define PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_INSERT     0xcd
#define PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_ADD_UNIQUE 0xce
#define PROTOCOL_BINARY_CMD_SUBDOC_COUNTER          0xcf
#define PROTOCOL_BINARY_CMD_SUBDOC_MULTI_LOOKUP     0xd0
#define PROTOCOL_BINARY_CMD_SUBDOC_MULTI_MUTATION   0xd1

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
#define PROTOCOL_BINARY_DCP_NOOP                    0x5c
#define PROTOCOL_BINARY_DCP_BUFFER_ACKNOWLEDGEMENT  0x5d
#define PROTOCOL_BINARY_DCP_CONTROL                 0x5e
#define PROTOCOL_BINARY_DCP_RESERVED4               0x5f

#define PROTOCOL_BINARY_CMD_GET_RANDOM_KEY          0xb6
#define PROTOCOL_BINARY_CMD_SEQNO_PERSISTENCE       0xb7
#define PROTOCOL_BINARY_CMD_SCRUB                   0xf0
#define PROTOCOL_BINARY_CMD_ISASL_REFRESH           0xf1
#define PROTOCOL_BINARY_CMD_SSL_CERTS_REFRESH       0xf2
#define PROTOCOL_BINARY_CMD_GET_CMD_TIMER           0xf3
#define PROTOCOL_BINARY_CMD_SET_CTRL_TOKEN          0xf4
#define PROTOCOL_BINARY_CMD_GET_CTRL_TOKEN          0xf5

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
static int hf_extras_flags_dcp_connection_type = -1;
static int hf_extras_flags_dcp_add_stream_takeover = -1;
static int hf_extras_flags_dcp_add_stream_diskonly = -1;
static int hf_extras_flags_dcp_add_stream_latest = -1;
static int hf_extras_flags_dcp_snapshot_marker_memory = -1;
static int hf_extras_flags_dcp_snapshot_marker_disk = -1;
static int hf_extras_flags_dcp_snapshot_marker_chk = -1;
static int hf_extras_flags_dcp_snapshot_marker_ack = -1;
static int hf_subdoc_flags = -1;
static int hf_subdoc_flags_mkdirp = -1;
static int hf_extras_seqno = -1;
static int hf_extras_opaque = -1;
static int hf_extras_reserved = -1;
static int hf_extras_start_seqno = -1;
static int hf_extras_end_seqno = -1;
static int hf_extras_vbucket_uuid = -1;
static int hf_extras_snap_start_seqno = -1;
static int hf_extras_snap_end_seqno = -1;
static int hf_extras_expiration = -1;
static int hf_extras_delta = -1;
static int hf_extras_initial = -1;
static int hf_extras_unknown = -1;
static int hf_extras_by_seqno = -1;
static int hf_extras_rev_seqno = -1;
static int hf_extras_lock_time = -1;
static int hf_extras_nmeta = -1;
static int hf_extras_nru = -1;
static int hf_extras_bytes_to_ack = -1;
static int hf_extras_pathlen = -1;
static int hf_key = -1;
static int hf_path = -1;
static int hf_value = -1;
static int hf_uint64_response = -1;
static int hf_observe = -1;
static int hf_observe_vbucket = -1;
static int hf_observe_keylength = -1;
static int hf_observe_key = -1;
static int hf_observe_status = -1;
static int hf_observe_cas = -1;
static int hf_observe_vbucket_uuid = -1;
static int hf_observe_failed_over = -1;
static int hf_observe_last_persisted_seqno = -1;
static int hf_observe_current_seqno = -1;
static int hf_observe_old_vbucket_uuid = -1;
static int hf_observe_last_received_seqno = -1;

static int hf_failover_log = -1;
static int hf_failover_log_size = -1;
static int hf_failover_log_vbucket_uuid = -1;
static int hf_failover_log_vbucket_seqno = -1;

static int hf_vbucket_states = -1;
static int hf_vbucket_states_state = -1;
static int hf_vbucket_states_size = -1;
static int hf_vbucket_states_id = -1;
static int hf_vbucket_states_seqno = -1;

static int hf_multipath_opcode = -1;
static int hf_multipath_index = -1;
static int hf_multipath_pathlen = -1;
static int hf_multipath_path = -1;
static int hf_multipath_valuelen = -1;
static int hf_multipath_value = -1;

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
static gint ett_failover_log = -1;
static gint ett_vbucket_states = -1;
static gint ett_multipath = -1;

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
  { PROTOCOL_BINARY_RESPONSE_ROLLBACK,          "Rollback"                },
  { PROTOCOL_BINARY_RESPONSE_EACCESS,           "Access error"            },
  { PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND,   "Unknown command"         },
  { PROTOCOL_BINARY_RESPONSE_ENOMEM,            "Out of memory"           },
  { PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED,     "Command isn't supported" },
  { PROTOCOL_BINARY_RESPONSE_EINTERNAL,         "Internal error"          },
  { PROTOCOL_BINARY_RESPONSE_EBUSY,             "Server is busy"          },
  { PROTOCOL_BINARY_RESPONSE_ETMPFAIL,          "Temporary failure"       },
  { PROTOCOL_BINARY_RESPONSE_SUBDOC_PATH_ENOENT,
    "Subdoc: Path not does not exist"},
  { PROTOCOL_BINARY_RESPONSE_SUBDOC_PATH_MISMATCH,
    "Subdoc: Path mismatch"},
  { PROTOCOL_BINARY_RESPONSE_SUBDOC_PATH_EINVAL,
    "Subdoc: Invalid path"},
  { PROTOCOL_BINARY_RESPONSE_SUBDOC_PATH_E2BIG,
    "Subdoc: Path too large"},
  { PROTOCOL_BINARY_RESPONSE_SUBDOC_DOC_E2DEEP,
    "Subdoc: Document too deep"},
  { PROTOCOL_BINARY_RESPONSE_SUBDOC_VALUE_CANTINSERT,
    "Subdoc: Cannot insert specified value"},
  { PROTOCOL_BINARY_RESPONSE_SUBDOC_DOC_NOTJSON,
    "Subdoc: Existing document not JSON"},
  { PROTOCOL_BINARY_RESPONSE_SUBDOC_NUM_ERANGE,
    "Subdoc: Existing number outside valid arithmetic range"},
  { PROTOCOL_BINARY_RESPONSE_SUBDOC_DELTA_ERANGE,
    "Subdoc: Delta outside valid arithmetic range"},
  { PROTOCOL_BINARY_RESPONSE_SUBDOC_PATH_EEXISTS,
    "Subdoc: Document path already exists"},
  { PROTOCOL_BINARY_RESPONSE_SUBDOC_VALUE_ETOODEEP,
    "Subdoc: Inserting value would make document too deep"},
  { PROTOCOL_BINARY_RESPONSE_SUBDOC_INVALID_COMBO,
    "Subdoc: Invalid combination for multi-path command"},
  { PROTOCOL_BINARY_RESPONSE_SUBDOC_MULTI_PATH_FAILURE,
    "Subdoc: One or more paths in a multi-path command failed"},

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
  { PROTOCOL_BINARY_CMD_HELLO,                      "Hello"                    },
  { PROTOCOL_BINARY_CMD_SASL_LIST_MECHS,            "List SASL Mechanisms"     },
  { PROTOCOL_BINARY_CMD_SASL_AUTH,                  "SASL Authenticate"        },
  { PROTOCOL_BINARY_CMD_SASL_STEP,                  "SASL Step"                },
  { PROTOCOL_BINARY_CMD_IOCTL_GET,                  "IOCTL Get"                },
  { PROTOCOL_BINARY_CMD_IOCTL_SET,                  "IOCTL Set"                },
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
  { PROTOCOL_BINARY_CMD_GET_ALL_VB_SEQNOS,          "Get All VBucket Seqnos"   },
  { PROTOCOL_BINARY_DCP_OPEN_CONNECTION,            "DCP Open Connection"      },
  { PROTOCOL_BINARY_DCP_ADD_STREAM,                 "DCP Add Stream"           },
  { PROTOCOL_BINARY_DCP_CLOSE_STREAM,               "DCP Close Stream"         },
  { PROTOCOL_BINARY_DCP_STREAM_REQUEST,             "DCP Stream Request"       },
  { PROTOCOL_BINARY_DCP_FAILOVER_LOG_REQUEST,       "DCP Get Failover Log"     },
  { PROTOCOL_BINARY_DCP_STREAM_END,                 "DCP Stream End"           },
  { PROTOCOL_BINARY_DCP_SNAPSHOT_MARKER,            "DCP Snapshot Marker"      },
  { PROTOCOL_BINARY_DCP_MUTATION,                   "DCP (Key) Mutation"       },
  { PROTOCOL_BINARY_DCP_DELETION,                   "DCP (Key) Deletion"       },
  { PROTOCOL_BINARY_DCP_EXPIRATION,                 "DCP (Key) Expiration"     },
  { PROTOCOL_BINARY_DCP_FLUSH,                      "DCP Flush"                },
  { PROTOCOL_BINARY_DCP_SET_VBUCKET_STATE,          "DCP Set VBucket State"    },
  { PROTOCOL_BINARY_DCP_NOOP,                       "DCP NOOP"                 },
  { PROTOCOL_BINARY_DCP_BUFFER_ACKNOWLEDGEMENT,     "DCP Buffer Acknowledgement"},
  { PROTOCOL_BINARY_DCP_CONTROL,                    "DCP Control"              },
  { PROTOCOL_BINARY_DCP_RESERVED4,                  "DCP Set Reserved"         },
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
  { PROTOCOL_BINARY_CMD_OBSERVE_SEQNO,              "Observe Sequence Number"  },
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
  { PROTOCOL_BINARY_CMD_DEL_WITH_META,              "Delete with Meta"         },
  { PROTOCOL_BINARY_CMD_DELQ_WITH_META,             "Delete with Meta Quietly" },
  { PROTOCOL_BINARY_CMD_CREATE_CHECKPOINT,          "Create Checkpoint"        },
  { PROTOCOL_BINARY_CMD_NOTIFY_VBUCKET_UPDATE,      "Notify VBucket Update"    },
  { PROTOCOL_BINARY_CMD_ENABLE_TRAFFIC,             "Enable Traffic"           },
  { PROTOCOL_BINARY_CMD_DISABLE_TRAFFIC,            "Disable Traffic"          },
  { PROTOCOL_BINARY_CMD_CHANGE_VB_FILTER,           "Change VBucket Filter"    },
  { PROTOCOL_BINARY_CMD_CHECKPOINT_PERSISTENCE,     "Checkpoint Persistence"   },
  { PROTOCOL_BINARY_CMD_RETURN_META,                "Return Meta"              },
  { PROTOCOL_BINARY_CMD_COMPACT_DB,                 "Compact Database"         },
  { PROTOCOL_BINARY_CMD_SET_CLUSTER_CONFIG,         "Set Cluster Config"       },
  { PROTOCOL_BINARY_CMD_GET_CLUSTER_CONFIG,         "Get Cluster Config"       },
  { PROTOCOL_BINARY_CMD_GET_RANDOM_KEY,             "Get Random Key"           },
  { PROTOCOL_BINARY_CMD_SEQNO_PERSISTENCE,          "Seqno Persistence"        },
  { PROTOCOL_BINARY_CMD_SUBDOC_GET,                 "Subdoc Get"               },
  { PROTOCOL_BINARY_CMD_SUBDOC_EXISTS,              "Subdoc Exists"            },
  { PROTOCOL_BINARY_CMD_SUBDOC_DICT_ADD,            "Subdoc Dictionary Add"    },
  { PROTOCOL_BINARY_CMD_SUBDOC_DICT_UPSERT,         "Subdoc Dictionary Upsert" },
  { PROTOCOL_BINARY_CMD_SUBDOC_DELETE,              "Subdoc Delete"            },
  { PROTOCOL_BINARY_CMD_SUBDOC_REPLACE,             "Subdoc Replace"           },
  { PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_PUSH_LAST,     "Subdoc Array Push Last"   },
  { PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_PUSH_FIRST,    "Subdoc Array Push First"  },
  { PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_INSERT,        "Subdoc Array Insert"      },
  { PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_ADD_UNIQUE,    "Subdoc Array Add Unique"  },
  { PROTOCOL_BINARY_CMD_SUBDOC_COUNTER,             "Subdoc Counter"           },
  { PROTOCOL_BINARY_CMD_SUBDOC_MULTI_LOOKUP,        "Subdoc Multipath Lookup"  },
  { PROTOCOL_BINARY_CMD_SUBDOC_MULTI_MUTATION,      "Subdoc Multipath Mutation"},
  { PROTOCOL_BINARY_CMD_SCRUB,                      "Scrub"                    },
  { PROTOCOL_BINARY_CMD_ISASL_REFRESH,              "isasl Refresh"            },
  { PROTOCOL_BINARY_CMD_SSL_CERTS_REFRESH,          "SSL Certificates Refresh" },
  { PROTOCOL_BINARY_CMD_GET_CMD_TIMER,              "Internal Timer Control"   },
  { PROTOCOL_BINARY_CMD_SET_CTRL_TOKEN,             "Set Control Token"        },
  { PROTOCOL_BINARY_CMD_GET_CTRL_TOKEN,             "Get Control Token"        },

  /* Internally defined values not valid here */
  { 0, NULL }
};

static value_string_ext opcode_vals_ext = VALUE_STRING_EXT_INIT(opcode_vals);

const value_string dcp_connection_type_vals[] = {
  {0, "Consumer"},
  {1, "Producer"},
  {2, "Notifier"},
  {0, NULL}
};

const value_string vbucket_states_vals[] = {
  {1, "Active"},
  {2, "Replica"},
  {3, "Pending"},
  {4, "Dead"},
  {0, NULL}
};

static const value_string datatype_vals[] = {
  { DT_RAW_BYTES, "Raw bytes"},
  { 0, NULL }
};

static const int * subdoc_flags[] = {
  &hf_subdoc_flags_mkdirp,
  NULL
};

static dissector_handle_t couchbase_tcp_handle;
static dissector_handle_t json_handle;

/* couchbase ports */
static range_t *couchbase_tcp_port_range;


/* desegmentation of COUCHBASE payload */
static gboolean couchbase_desegment_body = TRUE;


static guint
get_couchbase_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                      int offset, void *data _U_)
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


/* Returns true if the specified opcode's response value is JSON. */
static gboolean
has_json_value(guint8 opcode)
{
  switch (opcode) {
  case PROTOCOL_BINARY_CMD_GET_CLUSTER_CONFIG:
  case PROTOCOL_BINARY_CMD_SUBDOC_GET:
    return TRUE;

  default:
    return FALSE;
  }
}

/* Dissects the required extras for subdoc single-path packets */
static void
dissect_subdoc_spath_required_extras(tvbuff_t *tvb, proto_tree *extras_tree,
                                     guint8 extlen, gboolean request, gint* offset,
                                     guint16 *path_len, gboolean *illegal)
{
  if (request) {
    if (extlen >= 3) {
      *path_len = tvb_get_ntohs(tvb, *offset);
      proto_tree_add_item(extras_tree, hf_extras_pathlen, tvb, *offset, 2,
                          ENC_BIG_ENDIAN);
      *offset += 2;

      proto_tree_add_bitmask(extras_tree, tvb, *offset, hf_subdoc_flags,
                             ett_extras_flags, subdoc_flags, ENC_BIG_ENDIAN);
      *offset += 1;
    } else {
      /* Must always have at least 3 bytes of extras */
      *illegal = TRUE;
    }
  }
}

static void
dissect_extras(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
               gint offset, guint8 extlen, guint8 opcode, gboolean request,
               guint16 *path_len)
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

  *path_len = 0;

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
  case PROTOCOL_BINARY_CMD_OBSERVE_SEQNO:
    /* Must not have extras */
    if (extlen) {
      illegal = TRUE;
    }
    break;

  case PROTOCOL_BINARY_CMD_GET_ALL_VB_SEQNOS:
    if (extlen) {
      if (request) {
        /* May have extras */
        proto_tree_add_item(extras_tree, hf_vbucket_states_state, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
      } else {
        /* Must not have extras */
        illegal = TRUE;
      }
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
  case PROTOCOL_BINARY_CMD_TAP_DELETE:
  case PROTOCOL_BINARY_CMD_TAP_FLUSH:
  case PROTOCOL_BINARY_CMD_TAP_OPAQUE:
  case PROTOCOL_BINARY_CMD_TAP_VBUCKET_SET:
  case PROTOCOL_BINARY_CMD_TAP_CHECKPOINT_START:
  case PROTOCOL_BINARY_CMD_TAP_CHECKPOINT_END:
    break;

  case PROTOCOL_BINARY_DCP_OPEN_CONNECTION:
    if (extlen) {
      if (request) {
        static const int * extra_flags[] = {
          &hf_extras_flags_dcp_connection_type,
          NULL
        };

        proto_tree_add_item(extras_tree, hf_extras_seqno, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_bitmask(extras_tree, tvb, offset, hf_extras_flags, ett_extras_flags, extra_flags, ENC_BIG_ENDIAN);
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

  case PROTOCOL_BINARY_DCP_ADD_STREAM:
    if (extlen) {
      if (request) {
        static const int * extra_flags[] = {
          &hf_extras_flags_dcp_add_stream_takeover,
          &hf_extras_flags_dcp_add_stream_diskonly,
          &hf_extras_flags_dcp_add_stream_latest,
          NULL
        };

        proto_tree_add_bitmask(extras_tree, tvb, offset, hf_extras_flags, ett_extras_flags, extra_flags, ENC_BIG_ENDIAN);
        offset += 4;
      } else {
        proto_tree_add_item(extras_tree, hf_extras_opaque, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
      }
    } else {
      missing = TRUE;
    }
    break;

  case PROTOCOL_BINARY_DCP_STREAM_REQUEST:
    if (extlen) {
      if (request) {
        static const int * extra_flags[] = {
          NULL
        };

        proto_tree_add_bitmask(extras_tree, tvb, offset, hf_extras_flags, ett_extras_flags, extra_flags, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(extras_tree, hf_extras_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(extras_tree, hf_extras_start_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item(extras_tree, hf_extras_end_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item(extras_tree, hf_extras_vbucket_uuid, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item(extras_tree, hf_extras_snap_start_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item(extras_tree, hf_extras_snap_end_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
      }
    } else if (request) {
      /* Request must have extras */
      missing = TRUE;
    }
    break;

  case PROTOCOL_BINARY_DCP_SNAPSHOT_MARKER:
    if (extlen) {
      if (request) {
        static const int * extra_flags[] = {
          &hf_extras_flags_dcp_snapshot_marker_memory,
          &hf_extras_flags_dcp_snapshot_marker_disk,
          &hf_extras_flags_dcp_snapshot_marker_chk,
          &hf_extras_flags_dcp_snapshot_marker_ack,
          NULL
        };

        proto_tree_add_item(extras_tree, hf_extras_start_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item(extras_tree, hf_extras_end_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_bitmask(extras_tree, tvb, offset, hf_extras_flags, ett_extras_flags, extra_flags, ENC_BIG_ENDIAN);
        offset += 4;
      } else {
        illegal = TRUE;
      }
    } else if (request) {
      /* Request must have extras */
      missing = TRUE;
    }
    break;

  case PROTOCOL_BINARY_DCP_MUTATION:
    if (extlen) {
      if (request) {
        static const int * extra_flags[] = {
          NULL
        };

        proto_tree_add_item(extras_tree, hf_extras_by_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item(extras_tree, hf_extras_rev_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_bitmask(extras_tree, tvb, offset, hf_extras_flags, ett_extras_flags, extra_flags, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(extras_tree, hf_extras_expiration, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(extras_tree, hf_extras_lock_time, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(extras_tree, hf_extras_nmeta, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(extras_tree, hf_extras_nru, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
      } else {
        illegal = TRUE;
      }
    } else if (request) {
      /* Request must have extras */
      missing = TRUE;
    }
    break;

  case PROTOCOL_BINARY_DCP_DELETION:
  case PROTOCOL_BINARY_DCP_EXPIRATION:
  case PROTOCOL_BINARY_DCP_FLUSH:
    if (extlen) {
      if (request) {
        proto_tree_add_item(extras_tree, hf_extras_by_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item(extras_tree, hf_extras_rev_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item(extras_tree, hf_extras_nmeta, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
      } else {
        illegal = TRUE;
      }
    } else if (request) {
      /* Request must have extras */
      missing = TRUE;
    }
    break;

  case PROTOCOL_BINARY_DCP_BUFFER_ACKNOWLEDGEMENT:
    if (extlen) {
      if (request) {
        proto_tree_add_item(extras_tree, hf_extras_bytes_to_ack, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
      } else {
        illegal = TRUE;
      }
    } else if (request) {
      /* Request must have extras */
      missing = TRUE;
    }
    break;

  case PROTOCOL_BINARY_CMD_SUBDOC_GET:
  case PROTOCOL_BINARY_CMD_SUBDOC_EXISTS:
    dissect_subdoc_spath_required_extras(tvb, extras_tree, extlen, request,
                                         &offset, path_len, &illegal);
    break;

  case PROTOCOL_BINARY_CMD_SUBDOC_DICT_ADD:
  case PROTOCOL_BINARY_CMD_SUBDOC_DICT_UPSERT:
  case PROTOCOL_BINARY_CMD_SUBDOC_DELETE:
  case PROTOCOL_BINARY_CMD_SUBDOC_REPLACE:
  case PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_PUSH_LAST:
  case PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_PUSH_FIRST:
  case PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_INSERT:
  case PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_ADD_UNIQUE:
  case PROTOCOL_BINARY_CMD_SUBDOC_COUNTER:
    dissect_subdoc_spath_required_extras(tvb, extras_tree, extlen, request,
                                         &offset, path_len, &illegal);
    if (request) {
      /* optional expiry only permitted for mutation requests,
         iff extlen == 7 */
      if (extlen == 7) {
        proto_tree_add_item(extras_tree, hf_extras_expiration, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
      } else if (extlen != 3) {
        illegal = TRUE;
      }
    }
    break;

  case PROTOCOL_BINARY_CMD_SUBDOC_MULTI_LOOKUP:
    if (request) {
      if (extlen) {
        illegal = TRUE;
      }
    }
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
    switch (opcode) {
    case PROTOCOL_BINARY_CMD_QUIT:
    case PROTOCOL_BINARY_CMD_QUITQ:
    case PROTOCOL_BINARY_CMD_NOOP:
    case PROTOCOL_BINARY_CMD_VERSION:
    case PROTOCOL_BINARY_DCP_FAILOVER_LOG_REQUEST:
    case PROTOCOL_BINARY_DCP_BUFFER_ACKNOWLEDGEMENT:
    case PROTOCOL_BINARY_CMD_GET_ALL_VB_SEQNOS:
      /* Request and Response must not have key */
      illegal = TRUE;
      break;

    case PROTOCOL_BINARY_CMD_SET:
    case PROTOCOL_BINARY_CMD_ADD:
    case PROTOCOL_BINARY_CMD_REPLACE:
    case PROTOCOL_BINARY_CMD_DELETE:
    case PROTOCOL_BINARY_CMD_SETQ:
    case PROTOCOL_BINARY_CMD_ADDQ:
    case PROTOCOL_BINARY_CMD_REPLACEQ:
    case PROTOCOL_BINARY_CMD_DELETEQ:
    case PROTOCOL_BINARY_CMD_FLUSH:
    case PROTOCOL_BINARY_CMD_APPEND:
    case PROTOCOL_BINARY_CMD_PREPEND:
    case PROTOCOL_BINARY_CMD_FLUSHQ:
    case PROTOCOL_BINARY_CMD_APPENDQ:
    case PROTOCOL_BINARY_CMD_PREPENDQ:
      /* Response must not have a key */
      if (!request) {
        illegal = TRUE;
      }
      break;

    case PROTOCOL_BINARY_DCP_ADD_STREAM:
    case PROTOCOL_BINARY_DCP_CLOSE_STREAM:
    case PROTOCOL_BINARY_DCP_STREAM_END:
    case PROTOCOL_BINARY_DCP_SNAPSHOT_MARKER:
    case PROTOCOL_BINARY_DCP_FLUSH:
    case PROTOCOL_BINARY_DCP_SET_VBUCKET_STATE:
      /* Request must not have a key */
      if (request) {
        illegal = TRUE;
      }
      break;
    }
  } else {
    switch (opcode) {
    case PROTOCOL_BINARY_CMD_GET:
    case PROTOCOL_BINARY_CMD_GETQ:
    case PROTOCOL_BINARY_CMD_GETK:
    case PROTOCOL_BINARY_CMD_GETKQ:
    case PROTOCOL_BINARY_CMD_SET:
    case PROTOCOL_BINARY_CMD_ADD:
    case PROTOCOL_BINARY_CMD_REPLACE:
    case PROTOCOL_BINARY_CMD_DELETE:
    case PROTOCOL_BINARY_CMD_SETQ:
    case PROTOCOL_BINARY_CMD_ADDQ:
    case PROTOCOL_BINARY_CMD_REPLACEQ:
    case PROTOCOL_BINARY_CMD_DELETEQ:
    case PROTOCOL_BINARY_CMD_INCREMENT:
    case PROTOCOL_BINARY_CMD_DECREMENT:
    case PROTOCOL_BINARY_CMD_INCREMENTQ:
    case PROTOCOL_BINARY_CMD_DECREMENTQ:
    case PROTOCOL_BINARY_DCP_OPEN_CONNECTION:
    case PROTOCOL_BINARY_DCP_MUTATION:
    case PROTOCOL_BINARY_DCP_DELETION:
    case PROTOCOL_BINARY_DCP_EXPIRATION:
      /* Request must have key */
      if (request) {
        missing = TRUE;
      }
      break;
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
dissect_multipath_lookup_response(tvbuff_t *tvb, packet_info *pinfo,
                                  proto_tree *tree, gint offset, guint32 value_len)
{
  gint end = offset + value_len;
  int spec_idx = 0;

  while (offset < end) {
    proto_item *ti;
    proto_tree *multipath_tree;
    tvbuff_t *json_tvb;
    guint32 result_len;
    gint start_offset = offset;

    ti = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_multipath,
                                       &multipath_tree, "Lookup Result [ %u ]",
                                       spec_idx);

    proto_tree_add_item(multipath_tree, hf_status, tvb, offset, 2,
                        ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item_ret_uint(multipath_tree, hf_value_length, tvb, offset,
                                 4, ENC_BIG_ENDIAN, &result_len);
    offset += 4;

    proto_tree_add_item(multipath_tree, hf_value, tvb, offset, result_len,
                        ENC_ASCII | ENC_NA);
    if (result_len > 0) {
        json_tvb = tvb_new_subset(tvb, offset, result_len, result_len);
        call_dissector(json_handle, json_tvb, pinfo, multipath_tree);
    }
    offset += result_len;

    proto_item_set_len(ti, offset - start_offset);

    spec_idx++;
  }
}

static void
dissect_multipath_mutation_response(tvbuff_t *tvb, packet_info *pinfo,
                                    proto_tree *tree, gint offset, guint32 value_len)
{
  gint end = offset + value_len;
  int spec_idx = 0;

  /* Expect a variable number of mutation responses:
   * - If response.status == SUCCESS, zero to N responses, one for each mutation
   *   spec which returns a value.
   * - If response.status != SUCCESS, exactly 1 response, for first failing
   *   spec.
   */
  while (offset < end) {
    proto_item *ti;
    proto_tree *multipath_tree;
    tvbuff_t *json_tvb;
    guint32 status;
    gint start_offset = offset;

    ti = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_multipath,
                                       &multipath_tree, "Mutation Result [ %u ]",
                                       spec_idx);

    proto_tree_add_item(multipath_tree, hf_multipath_index, tvb, offset, 1,
                        ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item_ret_uint(multipath_tree, hf_status, tvb, offset, 2,
                                 ENC_BIG_ENDIAN, &status);
    offset += 2;
    if (status == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
      guint32 result_len;
      proto_tree_add_item_ret_uint(multipath_tree, hf_value_length, tvb,
                                   offset, 4, ENC_BIG_ENDIAN, &result_len);
      offset += 4;

      proto_tree_add_item(multipath_tree, hf_value, tvb, offset, result_len,
                          ENC_ASCII | ENC_NA);
      if (result_len > 0) {
        json_tvb = tvb_new_subset(tvb, offset, result_len, result_len);
        call_dissector(json_handle, json_tvb, pinfo, multipath_tree);
      }
      offset += result_len;
    }
    proto_item_set_len(ti, offset - start_offset);

    spec_idx++;
  }
}

static void
dissect_multipath_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        gint offset, guint32 value_len, gboolean is_mutation,
                        gboolean request)
{
  gint end = offset + value_len;
  int spec_idx = 0;
  proto_item *ti;
  proto_tree *multipath_tree;

  if (request) {
    gint min_spec_size;

    /* Minimum size is the fixed header plus at least 1 byte for path. */
    min_spec_size = (is_mutation ? 8 : 4) + 1;

    while (offset + min_spec_size < end) {
      guint32 path_len;
      guint32 spec_value_len = 0;
      gint start_offset = offset;

      ti = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_multipath,
                                         &multipath_tree,
                                         (is_mutation ? "Mutation spec [ %u ]"
                                                      : "Lookup spec [ %u ]"),
                                         spec_idx);

      proto_tree_add_item(multipath_tree, hf_multipath_opcode, tvb, offset, 1,
                          ENC_BIG_ENDIAN);
      offset += 1;
      proto_tree_add_bitmask(multipath_tree, tvb, offset, hf_subdoc_flags,
                             ett_extras_flags, subdoc_flags, ENC_BIG_ENDIAN);
      offset += 1;

      proto_tree_add_item_ret_uint(multipath_tree, hf_multipath_pathlen, tvb,
                                   offset, 2, ENC_BIG_ENDIAN, &path_len);
      offset += 2;

      if (is_mutation) {
        proto_tree_add_item_ret_uint(multipath_tree, hf_multipath_valuelen,
                                     tvb, offset, 4, ENC_BIG_ENDIAN,
                                     &spec_value_len);
        offset += 4;
      }

      proto_tree_add_item(multipath_tree, hf_multipath_path, tvb, offset, path_len,
                          ENC_ASCII | ENC_NA);
      offset += path_len;

      if (spec_value_len > 0) {
        proto_tree_add_item(multipath_tree, hf_multipath_value, tvb, offset,
                            spec_value_len, ENC_ASCII | ENC_NA);
        offset += spec_value_len;
      }

      proto_item_set_len(ti, offset - start_offset);

      spec_idx++;
    }
  } else {
    if (is_mutation) {
      dissect_multipath_mutation_response(tvb, pinfo, tree, offset, value_len);
    } else {
      dissect_multipath_lookup_response(tvb, pinfo, tree, offset, value_len);
    }
  }
}

static void
dissect_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
              gint offset, guint32 value_len, guint16 path_len, guint8 opcode,
              gboolean request)
{
  proto_item *ti = NULL;
  gboolean    illegal = FALSE;  /* Set when value shall not be present */
  gboolean    missing = FALSE;  /* Set when value is missing */

  if (value_len > 0) {
    if (opcode == PROTOCOL_BINARY_CMD_OBSERVE) {
      proto_tree *observe_tree;
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
    } else if (opcode == PROTOCOL_BINARY_CMD_OBSERVE_SEQNO) {
      if (request) {
        ti = proto_tree_add_item(tree, hf_observe_vbucket_uuid, tvb, offset, 8, ENC_BIG_ENDIAN);
        if (value_len != 8) {
          expert_add_info_format(pinfo, ti, &ef_warn_illegal_value_length, "Illegal Value length, should be 8");
        }
      } else {
        /*
         * <format_type, vbucket id, vbucket uuid, last_persisted_seqno, current_seqno>
         *
         * - format_type is of type uint8_t and it describes whether
         *   the vbucket has failed over or not. 1 indicates a hard
         *   failover, 0 indicates otherwise.
         * - vbucket id is of type uint16_t and it is the identifier for
         *   the vbucket.
         * - vbucket uuid is of type uint64_t and it represents a UUID for
         *    the vbucket.
         * - last_persisted_seqno is of type uint64_t and it is the
         *   last sequence number that was persisted for this
         *   vbucket.
         * - current_seqno is of the type uint64_t and it is the
         *   sequence number of the latest mutation in the vbucket.
         *
         * In the case of a hard failover, the tuple is of the form
         * <format_type, vbucket id, vbucket uuid, last_persisted_seqno, current_seqno,
         * old vbucket uuid, last_received_seqno>
         *
         * - old vbucket uuid is of type uint64_t and it is the
         *   vbucket UUID of the vbucket prior to the hard failover.
         *
         * - last_received_seqno is of type uint64_t and it is the
         *   last received sequence number in the old vbucket uuid.
         *
         * The other fields are the same as that mentioned in the normal case.
         */
        guint8 failed_over;

        proto_tree_add_item(tree, hf_observe_failed_over, tvb, offset, 1, ENC_BIG_ENDIAN);
        failed_over = tvb_get_guint8(tvb, offset);
        offset++;
        proto_tree_add_item(tree, hf_observe_vbucket, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(tree, hf_observe_vbucket_uuid, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item(tree, hf_observe_last_persisted_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item(tree, hf_observe_current_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        if (failed_over) {
          proto_tree_add_item(tree, hf_observe_old_vbucket_uuid, tvb, offset, 8, ENC_BIG_ENDIAN);
          offset += 8;
          proto_tree_add_item(tree, hf_observe_last_received_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        }
      }
    } else if (!request && opcode == PROTOCOL_BINARY_DCP_STREAM_REQUEST) {
      if (value_len % 16 != 0) {
        expert_add_info_format(pinfo, ti, &ef_warn_illegal_value_length, "Response with bad failover log length");
      } else {
        proto_tree *failover_log_tree;
        gint cur = offset, end = offset + value_len;
        ti = proto_tree_add_item(tree, hf_failover_log, tvb, offset, value_len, ENC_ASCII|ENC_NA);
        failover_log_tree = proto_item_add_subtree(ti, ett_failover_log);
        ti = proto_tree_add_uint(failover_log_tree, hf_failover_log_size, tvb, offset, 0, (end - cur) / 16);
        PROTO_ITEM_SET_GENERATED(ti);
        while (cur < end) {
          proto_tree_add_item(failover_log_tree, hf_failover_log_vbucket_uuid, tvb, cur, 8, ENC_BIG_ENDIAN);
          cur += 8;
          proto_tree_add_item(failover_log_tree, hf_failover_log_vbucket_seqno, tvb, cur, 8, ENC_BIG_ENDIAN);
          cur += 8;
        }
      }
    } else if (!request && opcode == PROTOCOL_BINARY_CMD_GET_ALL_VB_SEQNOS) {
      if (value_len % 10 != 0) {
        expert_add_info_format(pinfo, ti, &ef_warn_illegal_value_length, "Response with bad body length");
      } else {
        proto_tree *vbucket_states_tree;
        gint cur = offset, end = offset + value_len;
        ti = proto_tree_add_item(tree, hf_vbucket_states, tvb, offset, value_len, ENC_ASCII|ENC_NA);
        vbucket_states_tree = proto_item_add_subtree(ti, ett_vbucket_states);
        ti = proto_tree_add_uint(vbucket_states_tree, hf_vbucket_states_size, tvb, offset, 0, (end - cur) / 10);
        PROTO_ITEM_SET_GENERATED(ti);
        while (cur < end) {
          proto_tree_add_item(vbucket_states_tree, hf_vbucket_states_id, tvb, cur, 2, ENC_BIG_ENDIAN);
          cur += 2;
          proto_tree_add_item(vbucket_states_tree, hf_vbucket_states_seqno, tvb, cur, 8, ENC_BIG_ENDIAN);
          cur += 8;
        }
      }
    } else if (!request && (opcode == PROTOCOL_BINARY_CMD_INCREMENT || opcode == PROTOCOL_BINARY_CMD_DECREMENT)) {
      ti = proto_tree_add_item(tree, hf_uint64_response, tvb, offset, 8, ENC_BIG_ENDIAN);
      if (value_len != 8) {
        expert_add_info_format(pinfo, ti, &ef_warn_illegal_value_length, "Illegal Value length, should be 8");
      }
    } else if (!request && has_json_value(opcode)) {
      tvbuff_t *json_tvb;
      ti = proto_tree_add_item(tree, hf_value, tvb, offset, value_len, ENC_ASCII | ENC_NA);
      json_tvb = tvb_new_subset(tvb, offset, value_len, value_len);
      call_dissector(json_handle, json_tvb, pinfo, tree);

    } else if (opcode == PROTOCOL_BINARY_CMD_SUBDOC_MULTI_LOOKUP ||
               opcode == PROTOCOL_BINARY_CMD_SUBDOC_MULTI_MUTATION) {
      dissect_multipath_value(tvb, pinfo, tree, offset, value_len,
                              (opcode == PROTOCOL_BINARY_CMD_SUBDOC_MULTI_MUTATION),
                              request);

    } else if (path_len != 0) {
        ti = proto_tree_add_item(tree, hf_path, tvb, offset, path_len, ENC_ASCII | ENC_NA);
        value_len -= path_len;
        if (value_len > 0) {
            ti = proto_tree_add_item(tree, hf_value, tvb, offset + path_len,
                                     value_len, ENC_ASCII | ENC_NA);
        }
    } else {
      ti = proto_tree_add_item(tree, hf_value, tvb, offset, value_len, ENC_ASCII | ENC_NA);
    }
  }

  /* Sanity check */
  if (value_len) {
    switch (opcode) {
    case PROTOCOL_BINARY_CMD_GET:
    case PROTOCOL_BINARY_CMD_GETQ:
    case PROTOCOL_BINARY_CMD_GETK:
    case PROTOCOL_BINARY_CMD_GETKQ:
    case PROTOCOL_BINARY_CMD_INCREMENT:
    case PROTOCOL_BINARY_CMD_DECREMENT:
    case PROTOCOL_BINARY_CMD_VERSION:
    case PROTOCOL_BINARY_CMD_INCREMENTQ:
    case PROTOCOL_BINARY_CMD_DECREMENTQ:
    case PROTOCOL_BINARY_DCP_OPEN_CONNECTION:
    case PROTOCOL_BINARY_DCP_ADD_STREAM:
    case PROTOCOL_BINARY_DCP_CLOSE_STREAM:
    case PROTOCOL_BINARY_DCP_FAILOVER_LOG_REQUEST:
    case PROTOCOL_BINARY_DCP_STREAM_END:
    case PROTOCOL_BINARY_DCP_SNAPSHOT_MARKER:
    case PROTOCOL_BINARY_DCP_DELETION:
    case PROTOCOL_BINARY_DCP_EXPIRATION:
    case PROTOCOL_BINARY_DCP_FLUSH:
    case PROTOCOL_BINARY_DCP_SET_VBUCKET_STATE:
      /* Request must not have value */
      if (request) {
        illegal = TRUE;
      }
      break;
    case PROTOCOL_BINARY_CMD_DELETE:
    case PROTOCOL_BINARY_CMD_QUIT:
    case PROTOCOL_BINARY_CMD_FLUSH:
    case PROTOCOL_BINARY_CMD_NOOP:
    case PROTOCOL_BINARY_CMD_DELETEQ:
    case PROTOCOL_BINARY_CMD_QUITQ:
    case PROTOCOL_BINARY_CMD_FLUSHQ:
      /* Request and Response must not have value */
      illegal = TRUE;
      break;
    case PROTOCOL_BINARY_CMD_SET:
    case PROTOCOL_BINARY_CMD_ADD:
    case PROTOCOL_BINARY_CMD_REPLACE:
    case PROTOCOL_BINARY_CMD_SETQ:
    case PROTOCOL_BINARY_CMD_ADDQ:
    case PROTOCOL_BINARY_CMD_REPLACEQ:
    case PROTOCOL_BINARY_CMD_APPEND:
    case PROTOCOL_BINARY_CMD_PREPEND:
    case PROTOCOL_BINARY_CMD_APPENDQ:
    case PROTOCOL_BINARY_CMD_PREPENDQ:
      /* Response must not have value */
      if (!request) {
        illegal = TRUE;
      }
      break;
    }
  } else {
    switch (opcode) {
    case PROTOCOL_BINARY_DCP_FAILOVER_LOG_REQUEST:
      /* Successful response must have value */
      if (!request) {
        missing = TRUE;
      }
      break;
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
    guint16 path_len = 0;

    dissect_extras(tvb, pinfo, couchbase_tree, offset, extlen, opcode, request,
                   &path_len);
    offset += extlen;

    dissect_key(tvb, pinfo, couchbase_tree, offset, keylen, opcode, request);
    offset += keylen;

    dissect_value(tvb, pinfo, couchbase_tree, offset, value_len, path_len,
                  opcode, request);
  } else if (bodylen) {
    proto_tree_add_item(couchbase_tree, hf_value, tvb, offset, bodylen,
                        ENC_ASCII | ENC_NA);
    if (status == PROTOCOL_BINARY_RESPONSE_NOT_MY_VBUCKET) {
      tvbuff_t *json_tvb;
      json_tvb = tvb_new_subset(tvb, offset, bodylen, bodylen);
      call_dissector(json_handle, json_tvb, pinfo, couchbase_tree);

    } else if (opcode == PROTOCOL_BINARY_CMD_SUBDOC_MULTI_LOOKUP) {
        dissect_multipath_lookup_response(tvb, pinfo, tree, offset, value_len);

    } else if (opcode == PROTOCOL_BINARY_CMD_SUBDOC_MULTI_MUTATION) {
        dissect_multipath_mutation_response(tvb, pinfo, tree, offset, value_len);
    }
    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
                    val_to_str_ext(status, &status_vals_ext, "Unknown status: 0x%x"));
  } else {
    /* Newer opcodes do not include a value in non-SUCCESS responses. */
    switch (opcode) {
    case PROTOCOL_BINARY_CMD_SUBDOC_GET:
    case PROTOCOL_BINARY_CMD_SUBDOC_EXISTS:
    case PROTOCOL_BINARY_CMD_SUBDOC_DICT_ADD:
    case PROTOCOL_BINARY_CMD_SUBDOC_DICT_UPSERT:
    case PROTOCOL_BINARY_CMD_SUBDOC_DELETE:
    case PROTOCOL_BINARY_CMD_SUBDOC_REPLACE:
    case PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_PUSH_LAST:
    case PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_PUSH_FIRST:
    case PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_INSERT:
    case PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_ADD_UNIQUE:
    case PROTOCOL_BINARY_CMD_SUBDOC_COUNTER:
    case PROTOCOL_BINARY_CMD_SUBDOC_MULTI_LOOKUP:
    case PROTOCOL_BINARY_CMD_SUBDOC_MULTI_MUTATION:
      break;

    default:
      ti = proto_tree_add_item(tree, hf_value, tvb, offset, 0,
                               ENC_ASCII | ENC_NA);
      expert_add_info_format(pinfo, ti, &ei_value_missing,
                             "%s with status %s (0x%x) must have Value",
                             val_to_str_ext(opcode, &opcode_vals_ext, "Opcode 0x%x"),
                             val_to_str_ext(status, &status_vals_ext, "Unknown"),
                             status);
      break;
    }
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
    { &hf_vbucket, { "VBucket", "couchbase.vbucket", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, "VBucket ID", HFILL } },
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

    /* Sub-document */
    { &hf_subdoc_flags, {"Subdoc flags", "couchbase.extras.subdoc.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL} },
    { &hf_subdoc_flags_mkdirp, {"MKDIR_P", "couchbase.extras.subdoc.flags.mkdir_p", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01, "Create non-existent intermediate paths", HFILL} },
    { &hf_extras_pathlen, { "Path Length", "couchbase.extras.pathlen", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    /* DCP flags */
    { &hf_extras_flags_dcp_connection_type, {"Connection Type", "couchbase.extras.flags.dcp_connection_type", FT_UINT32, BASE_HEX, VALS(dcp_connection_type_vals), 0x03, NULL, HFILL } },
    { &hf_extras_flags_dcp_add_stream_takeover, {"Take Over", "couchbase.extras.flags.dcp_add_stream_takeover", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x01, NULL, HFILL } },
    { &hf_extras_flags_dcp_add_stream_diskonly, {"Disk Only", "couchbase.extras.flags.dcp_add_stream_diskonly", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x02, NULL, HFILL } },
    { &hf_extras_flags_dcp_add_stream_latest, {"Latest", "couchbase.extras.flags.dcp_add_stream_latest", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x04, NULL, HFILL } },
    { &hf_extras_flags_dcp_snapshot_marker_memory, {"Memory", "couchbase.extras.flags.dcp_snapshot_marker_memory", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x01, NULL, HFILL } },
    { &hf_extras_flags_dcp_snapshot_marker_disk, {"Disk", "couchbase.extras.flags.dcp_snapshot_marker_disk", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x02, NULL, HFILL } },
    { &hf_extras_flags_dcp_snapshot_marker_chk, {"Chk", "couchbase.extras.flags.dcp_snapshot_marker_chk", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x04, NULL, HFILL } },
    { &hf_extras_flags_dcp_snapshot_marker_ack, {"Ack", "couchbase.extras.flags.dcp_snapshot_marker_ack", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x08, NULL, HFILL } },
    { &hf_extras_seqno, { "Sequence number", "couchbase.extras.seqno", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_opaque, { "Opaque (vBucket identifier)", "couchbase.extras.opaque", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_reserved, { "Reserved", "couchbase.extras.reserved", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_start_seqno, { "Start Sequence Number", "couchbase.extras.start_seqno", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_end_seqno, { "End Sequence Number", "couchbase.extras.start_seqno", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_vbucket_uuid, { "VBucket UUID", "couchbase.extras.vbucket_uuid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_snap_start_seqno, { "Snapshot Start Sequence Number", "couchbase.extras.snap_start_seqno", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_snap_end_seqno, { "Snapshot End Sequence Number", "couchbase.extras.snap_start_seqno", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_by_seqno, { "by_seqno", "couchbase.extras.by_seqno", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_rev_seqno, { "rev_seqno", "couchbase.extras.rev_seqno", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_lock_time, { "lock_time", "couchbase.extras.lock_time", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_nmeta, { "nmeta", "couchbase.extras.nmeta", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_nru, { "nru", "couchbase.extras.nru", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_bytes_to_ack, { "bytes_to_ack", "couchbase.extras.bytes_to_ack", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_failover_log, { "Failover Log", "couchbase.dcp.failover_log", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_failover_log_size, { "Size", "couchbase.dcp.failover_log.size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_failover_log_vbucket_uuid, { "VBucket UUID", "couchbase.dcp.failover_log.vbucket_uuid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_failover_log_vbucket_seqno, { "Sequence Number", "couchbase.dcp.failover_log.seqno", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    { &hf_vbucket_states, { "VBucket States", "couchbase.vbucket_states", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_vbucket_states_state, { "State", "couchbase.vbucket_states.state", FT_UINT32, BASE_HEX, VALS(vbucket_states_vals), 0x0, NULL, HFILL } },
    { &hf_vbucket_states_size, { "Size", "couchbase.vbucket_states.size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_vbucket_states_id, { "VBucket", "couchbase.vbucket_states.id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_vbucket_states_seqno, { "Sequence Number", "couchbase.vbucket_states.seqno", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_extras_expiration, { "Expiration", "couchbase.extras.expiration", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_delta, { "Amount to Add", "couchbase.extras.delta", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_initial, { "Initial Value", "couchbase.extras.initial", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_unknown, { "Unknown", "couchbase.extras.unknown", FT_BYTES, BASE_NONE, NULL, 0x0, "Unknown Extras", HFILL } },
    { &hf_key, { "Key", "couchbase.key", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_path, { "Path", "couchbase.path", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_value, { "Value", "couchbase.value", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_uint64_response, { "Response", "couchbase.extras.response", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_observe, { "Observe", "couchbase.observe", FT_STRING, BASE_NONE, NULL, 0x0, "The observe properties", HFILL } },
    { &hf_observe_key, { "Key", "couchbase.observe.key", FT_STRING, BASE_NONE, NULL, 0x0, "The observable key", HFILL } },
    { &hf_observe_keylength, { "Key Length", "couchbase.observe.keylength", FT_UINT16, BASE_DEC, NULL, 0x0, "The length of the observable key", HFILL } },
    { &hf_observe_vbucket, { "VBucket", "couchbase.observe.vbucket", FT_UINT16, BASE_HEX, NULL, 0x0, "VBucket of the observable key", HFILL } },
    { &hf_observe_status, { "Status", "couchbase.observe.status", FT_UINT8, BASE_HEX, NULL, 0x0, "Status of the observable key", HFILL } },
    { &hf_observe_cas, { "CAS", "couchbase.observe.cas", FT_UINT64, BASE_HEX, NULL, 0x0, "CAS value of the observable key", HFILL } },
    { &hf_observe_vbucket_uuid, { "VBucket UUID", "couchbase.observe.vbucket_uuid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_observe_last_persisted_seqno, { "Last persisted sequence number", "couchbase.observe.last_persisted_seqno", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_observe_current_seqno, { "Current sequence number", "couchbase.observe.current_seqno", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_observe_old_vbucket_uuid, { "Old VBucket UUID", "couchbase.observe.old_vbucket_uuid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_observe_last_received_seqno, { "Last received sequence number", "couchbase.observe.last_received_seqno", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_observe_failed_over, { "Failed over", "couchbase.observe.failed_over", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_multipath_opcode, { "Opcode", "couchbase.multipath.opcode", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &opcode_vals_ext, 0x0, "Command code", HFILL } },
    { &hf_multipath_index, { "Index", "couchbase.multipath.index", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_multipath_pathlen, { "Path Length", "couchbase.multipath.path.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_multipath_path, { "Path", "couchbase.multipath.path", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_multipath_valuelen, { "Value Length", "couchbase.multipath.value.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_multipath_value, { "Value", "couchbase.multipath.value", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
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
    &ett_observe,
    &ett_failover_log,
    &ett_vbucket_states,
    &ett_multipath
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
    couchbase_tcp_handle = create_dissector_handle(dissect_couchbase_tcp, proto_couchbase);
    initialized = TRUE;
  }
  else {
    dissector_delete_uint_range("tcp.port", tcp_port_range, couchbase_tcp_handle);
    g_free(tcp_port_range);
  }

  tcp_port_range = range_copy(couchbase_tcp_port_range);
  dissector_add_uint_range("tcp.port", tcp_port_range, couchbase_tcp_handle);

  json_handle = find_dissector_add_dependency("json", proto_couchbase);
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
