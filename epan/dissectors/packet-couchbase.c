/* packet-couchbase.c
 *
 * Routines for Couchbase Protocol
 *
 * Copyright 2019, Trond Norbye <trond@couchbase.com>
 * Copyright 2018, Jim Walker <jim@couchbase.com>
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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"


#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#ifdef HAVE_SNAPPY
#include <snappy-c.h>
#endif

#include "packet-tcp.h"
#include "packet-tls.h"

#include <math.h>

#define PNAME  "Couchbase Protocol"
#define PSNAME "Couchbase"
#define PFNAME "couchbase"

#define COUCHBASE_DEFAULT_PORT        "11210"
#define COUCHBASE_HEADER_LEN   24

 /* Magic Byte */
#define MAGIC_REQUEST         0x80
#define MAGIC_RESPONSE        0x81
#define MAGIC_RESPONSE_FLEX   0x18
#define MAGIC_REQUEST_FLEX    0x08

 /* Response Status */
#define PROTOCOL_BINARY_RESPONSE_SUCCESS            0x00
#define PROTOCOL_BINARY_RESPONSE_KEY_ENOENT         0x01
#define PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS        0x02
#define PROTOCOL_BINARY_RESPONSE_E2BIG              0x03
#define PROTOCOL_BINARY_RESPONSE_EINVAL             0x04
#define PROTOCOL_BINARY_RESPONSE_NOT_STORED         0x05
#define PROTOCOL_BINARY_RESPONSE_DELTA_BADVAL       0x06
#define PROTOCOL_BINARY_RESPONSE_NOT_MY_VBUCKET     0x07
#define PROTOCOL_BINARY_RESPONSE_NO_VBUCKET         0x08
#define PROTOCOL_BINARY_RESPONSE_LOCKED             0x09
#define PROTOCOL_BINARY_RESPONSE_AUTH_STALE         0x1f
#define PROTOCOL_BINARY_RESPONSE_AUTH_ERROR         0x20
#define PROTOCOL_BINARY_RESPONSE_AUTH_CONTINUE      0x21
#define PROTOCOL_BINARY_RESPONSE_ERANGE             0x22
#define PROTOCOL_BINARY_RESPONSE_ROLLBACK           0x23
#define PROTOCOL_BINARY_RESPONSE_EACCESS            0x24
#define PROTOCOL_BINARY_RESPONSE_NOT_INITIALIZED    0x25
#define PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND    0x81
#define PROTOCOL_BINARY_RESPONSE_ENOMEM             0x82
#define PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED      0x83
#define PROTOCOL_BINARY_RESPONSE_EINTERNAL          0x84
#define PROTOCOL_BINARY_RESPONSE_EBUSY              0x85
#define PROTOCOL_BINARY_RESPONSE_ETMPFAIL           0x86
#define PROTOCOL_BINARY_RESPONSE_XATTR_EINVAL       0x87
#define PROTOCOL_BINARY_RESPONSE_UNKNOWN_COLLECTION         0x88
#define PROTOCOL_BINARY_RESPONSE_NO_COLLECTIONS_MANIFEST    0x89
#define PROTOCOL_BINARY_RESPONSE_CANNOT_APPLY_MANIFEST      0x8a
#define PROTOCOL_BINARY_RESPONSE_MANIFEST_IS_AHEAD          0x8b
#define PROTOCOL_BINARY_RESPONSE_UNKNOWN_SCOPE              0x8c
#define PROTOCOL_BINARY_RESPONSE_DCP_STREAMID_INVALID       0x8d
#define PROTOCOL_BINARY_RESPONSE_DURABILITY_INVALID_LEVEL         0xa0
#define PROTOCOL_BINARY_RESPONSE_DURABILITY_IMPOSSIBLE            0xa1
#define PROTOCOL_BINARY_RESPONSE_SYNC_WRITE_IN_PROGRESS           0xa2
#define PROTOCOL_BINARY_RESPONSE_SYNC_WRITE_AMBIGUOUS             0xa3
#define PROTOCOL_BINARY_RESPONSE_SYNC_WRITE_RECOMMIT_IN_PROGRESS  0xa4
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
#define PROTOCOL_BINARY_RESPONSE_SUBDOC_SUCCESS_DELETED            0xcd
#define PROTOCOL_BINARY_RESPONSE_SUBDOC_XATTR_INVALID_FLAG_COMBO   0xce
#define PROTOCOL_BINARY_RESPONSE_SUBDOC_XATTR_INVALID_KEY_COMBO    0xcf
#define PROTOCOL_BINARY_RESPONSE_SUBDOC_XATTR_UNKNOWN_MACRO        0xd0
#define PROTOCOL_BINARY_RESPONSE_SUBDOC_XATTR_UNKNOWN_VATTR        0xd1
#define PROTOCOL_BINARY_RESPONSE_SUBDOC_XATTR_CANT_MODIFY_VATTR    0xd2
#define PROTOCOL_BINARY_RESPONSE_SUBDOC_MULTI_PATH_FAILURE_DELETED 0xd3
#define PROTOCOL_BINARY_RESPONSE_SUBDOC_INVALID_XATTR_ORDER        0xd4

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
#define PROTOCOL_BINARY_CMD_CONFIG_VALIDATE         0x25
#define PROTOCOL_BINARY_CMD_CONFIG_RELOAD           0x26
#define PROTOCOL_BINARY_CMD_AUDIT_PUT               0x27
#define PROTOCOL_BINARY_CMD_AUDIT_CONFIG_RELOAD     0x28
#define PROTOCOL_BINARY_CMD_SHUTDOWN                0x29

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

#define PROTOCOL_BINARY_CMD_COLLECTIONS_SET_MANIFEST 0xb9
#define PROTOCOL_BINARY_CMD_COLLECTIONS_GET_MANIFEST 0xba
#define PROTOCOL_BINARY_CMD_COLLECTIONS_GET_ID       0xbb
#define PROTOCOL_BINARY_CMD_COLLECTIONS_GET_SCOPE_ID 0xbc

#define PROTOCOL_BINARY_CMD_SET_DRIFT_COUNTER_STATE 0xc1
#define PROTOCOL_BINARY_CMD_GET_ADJUSTED_TIME       0xc2

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
#define PROTOCOL_BINARY_CMD_SUBDOC_GET_COUNT        0xd2

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
#define PROTOCOL_BINARY_DCP_SYSTEM_EVENT            0x5f
#define PROTOCOL_BINARY_DCP_PREPARE                 0x60
#define PROTOCOL_BINARY_DCP_SEQNO_ACK               0x61
#define PROTOCOL_BINARY_DCP_COMMIT                  0x62
#define PROTOCOL_BINARY_DCP_ABORT                   0x63
#define PROTOCOL_BINARY_DCP_SEQNO_ADVANCED          0x64
#define PROTOCOL_BINARY_DCP_OSO_SNAPSHOT            0x65

#define PROTOCOL_BINARY_CMD_GET_RANDOM_KEY          0xb6
#define PROTOCOL_BINARY_CMD_SEQNO_PERSISTENCE       0xb7
#define PROTOCOL_BINARY_CMD_GET_KEYS                0xb8
#define PROTOCOL_BINARY_CMD_SCRUB                   0xf0
#define PROTOCOL_BINARY_CMD_ISASL_REFRESH           0xf1
#define PROTOCOL_BINARY_CMD_SSL_CERTS_REFRESH       0xf2
#define PROTOCOL_BINARY_CMD_GET_CMD_TIMER           0xf3
#define PROTOCOL_BINARY_CMD_SET_CTRL_TOKEN          0xf4
#define PROTOCOL_BINARY_CMD_GET_CTRL_TOKEN          0xf5
#define PROTOCOL_BINARY_CMD_UPDATE_EXTERNAL_USER_PERMISSIONS 0xf6
#define PROTOCOL_BINARY_CMD_RBAC_REFRESH            0xf7
#define PROTOCOL_BINARY_CMD_AUTH_PROVIDER           0xf8
#define PROTOCOL_BINARY_CMD_DROP_PRIVILEGE          0xfb
#define PROTOCOL_BINARY_CMD_ADJUST_TIMEOFDAY        0xfc
#define PROTOCOL_BINARY_CMD_EWOULDBLOCK_CTL         0xfd
#define PROTOCOL_BINARY_CMD_GET_ERROR_MAP           0xfe

 /* vBucket states */
#define VBUCKET_ACTIVE                              0x01
#define VBUCKET_PENDING                             0x02
#define VBUCKET_REPLICA                             0x03
#define VBUCKET_DEAD                                0x04

 /* Data Types */
#define DT_RAW_BYTES          0x00
#define DT_JSON               0x01
#define DT_SNAPPY             0x02
#define DT_XATTR              0x04

void proto_register_couchbase(void);
void proto_reg_handoff_couchbase(void);

static int proto_couchbase = -1;

static int hf_magic = -1;
static int hf_opcode = -1;
static int hf_extlength = -1;
static int hf_keylength = -1;
static int hf_value_length = -1;
static int hf_datatype = -1;
static int hf_datatype_json = -1;
static int hf_datatype_snappy = -1;
static int hf_datatype_xattr = -1;
static int hf_vbucket = -1;
static int hf_status = -1;
static int hf_total_bodylength = -1;
static int hf_opaque = -1;
static int hf_cas = -1;
static int hf_ttp = -1;
static int hf_ttr = -1;
static int hf_collection_key_id = -1;
static int hf_collection_key_logical = -1;
static int hf_collection_manifest_id = -1;

static int hf_flex_extras_length = -1;
static int hf_flex_keylength = -1;
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
static int hf_extras_flags_dcp_include_xattrs = -1;
static int hf_extras_flags_dcp_no_value = -1;
static int hf_extras_flags_dcp_include_delete_times = -1;
static int hf_extras_flags_dcp_collections = -1;
static int hf_extras_flags_dcp_oso_snapshot_begin = -1;
static int hf_extras_flags_dcp_oso_snapshot_end = -1;
static int hf_subdoc_doc_flags = -1;
static int hf_subdoc_doc_flags_mkdoc = -1;
static int hf_subdoc_doc_flags_add = -1;
static int hf_subdoc_doc_flags_accessdeleted = -1;
static int hf_subdoc_doc_flags_createasdeleted = -1;
static int hf_subdoc_doc_flags_reserved = -1;
static int hf_subdoc_flags = -1;
static int hf_subdoc_flags_mkdirp = -1;
static int hf_subdoc_flags_xattrpath = -1;
static int hf_subdoc_flags_expandmacros = -1;
static int hf_subdoc_flags_reserved = -1;
static int hf_extras_seqno = -1;
static int hf_extras_mutation_seqno = -1;
static int hf_extras_opaque = -1;
static int hf_extras_reserved = -1;
static int hf_extras_start_seqno = -1;
static int hf_extras_end_seqno = -1;
static int hf_extras_high_completed_seqno = -1;
static int hf_extras_max_visible_seqno = -1;
static int hf_extras_marker_version = -1;
static int hf_extras_vbucket_uuid = -1;
static int hf_extras_snap_start_seqno = -1;
static int hf_extras_snap_end_seqno = -1;
static int hf_extras_expiration = -1;
static int hf_extras_delta = -1;
static int hf_extras_initial = -1;
static int hf_extras_unknown = -1;
static int hf_extras_by_seqno = -1;
static int hf_extras_rev_seqno = -1;
static int hf_extras_prepared_seqno = -1;
static int hf_extras_commit_seqno = -1;
static int hf_extras_abort_seqno = -1;
static int hf_extras_deleted = -1;
static int hf_extras_lock_time = -1;
static int hf_extras_nmeta = -1;
static int hf_extras_nru = -1;
static int hf_extras_bytes_to_ack = -1;
static int hf_extras_delete_time = -1;
static int hf_extras_delete_unused = -1;
static int hf_extras_system_event_id = -1;
static int hf_extras_system_event_version = -1;
static int hf_extras_pathlen = -1;
static int hf_extras_dcp_oso_snapshot_flags = -1;
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

static int hf_get_errmap_version = -1;

static int hf_failover_log = -1;
static int hf_failover_log_size = -1;
static int hf_failover_log_vbucket_uuid = -1;
static int hf_failover_log_vbucket_seqno = -1;

static int hf_vbucket_states = -1;
static int hf_vbucket_states_state = -1;
static int hf_vbucket_states_size = -1;
static int hf_vbucket_states_id = -1;
static int hf_vbucket_states_seqno = -1;

static int hf_bucket_type = -1;
static int hf_bucket_config = -1;
static int hf_config_key = -1;
static int hf_config_value = -1;

static int hf_multipath_opcode = -1;
static int hf_multipath_index = -1;
static int hf_multipath_pathlen = -1;
static int hf_multipath_path = -1;
static int hf_multipath_valuelen = -1;
static int hf_multipath_value = -1;

static int hf_meta_flags = -1;
static int hf_meta_expiration = -1;
static int hf_meta_revseqno = -1;
static int hf_meta_cas = -1;
static int hf_skip_conflict = -1;
static int hf_force_accept = -1;
static int hf_regenerate_cas = -1;
static int hf_force_meta = -1;
static int hf_is_expiration = -1;
static int hf_meta_options = -1;
static int hf_metalen = -1;
static int hf_meta_reqextmeta = -1;
static int hf_meta_deleted = -1;
static int hf_exptime = -1;
static int hf_extras_meta_seqno = -1;
static int hf_confres = -1;
static int hf_hello_features = -1;
static int hf_hello_features_feature = -1;

static int hf_xattr_length = -1;
static int hf_xattr_pair_length = -1;
static int hf_xattr_key = -1;
static int hf_xattr_value = -1;
static int hf_xattrs = -1;

static int hf_flex_extras = -1;
static int hf_flex_extras_n = -1;
static int hf_flex_frame_id_byte0 = -1;
static int hf_flex_frame_id_req = -1;
static int hf_flex_frame_id_res = -1;
static int hf_flex_frame_id_req_esc = -1;
static int hf_flex_frame_id_res_esc = -1;
static int hf_flex_frame_len = -1;
static int hf_flex_frame_len_esc = -1;
static int hf_flex_frame_tracing_duration = -1;
static int hf_flex_frame_durability_req = -1;
static int hf_flex_frame_dcp_stream_id = -1;
static int hf_flex_frame_impersonated_user = -1;

static expert_field ef_warn_shall_not_have_value = EI_INIT;
static expert_field ef_warn_shall_not_have_extras = EI_INIT;
static expert_field ef_warn_shall_not_have_key = EI_INIT;
static expert_field ef_compression_error = EI_INIT;
static expert_field ef_warn_unknown_flex_unsupported = EI_INIT;
static expert_field ef_warn_unknown_flex_id = EI_INIT;
static expert_field ef_warn_unknown_flex_len = EI_INIT;

static expert_field ei_value_missing = EI_INIT;
static expert_field ef_warn_must_have_extras = EI_INIT;
static expert_field ef_warn_must_have_key = EI_INIT;
static expert_field ef_warn_illegal_extras_length = EI_INIT;
static expert_field ef_warn_illegal_value_length = EI_INIT;
static expert_field ef_warn_unknown_magic_byte = EI_INIT;
static expert_field ef_warn_unknown_opcode = EI_INIT;
static expert_field ef_note_status_code = EI_INIT;
static expert_field ef_separator_not_found = EI_INIT;
static expert_field ef_illegal_value = EI_INIT;

static gint ett_couchbase = -1;
static gint ett_extras = -1;
static gint ett_extras_flags = -1;
static gint ett_observe = -1;
static gint ett_failover_log = -1;
static gint ett_vbucket_states = -1;
static gint ett_multipath = -1;
static gint ett_config = -1;
static gint ett_config_key = -1;
static gint ett_hello_features = -1;
static gint ett_datatype = -1;
static gint ett_xattrs = -1;
static gint ett_xattr_pair = -1;
static gint ett_flex_frame_extras = -1;
static gint ett_collection_key = -1;

static const value_string magic_vals[] = {
  { MAGIC_REQUEST,       "Request"  },
  { MAGIC_RESPONSE,      "Response" },
  { MAGIC_RESPONSE_FLEX, "Response with flexible framing extras" },
  { MAGIC_REQUEST_FLEX, "Request with flexible framing extras" },
  { 0, NULL }
};

#define FLEX_ESCAPE 0x0F

/*
  The flex extension identifiers are different for request/response
  i.e. 0 in a response is not 0 in a request
  Response IDs
 */
#define FLEX_RESPONSE_ID_RX_TX_DURATION 0

/* Request IDs */
#define FLEX_REQUEST_ID_REORDER 0
#define FLEX_REQUEST_ID_DURABILITY 1
#define FLEX_REQUEST_ID_DCP_STREAM_ID 2
#define FLEX_REQUEST_ID_OPEN_TRACING 3
#define FLEX_REQUEST_ID_IMPERSONATE 4
#define FLEX_REQUEST_ID_PRESERVE_TTL 5

static const value_string flex_frame_response_ids[] = {
  { FLEX_RESPONSE_ID_RX_TX_DURATION, "Server Recv->Send duration"},
  { 0, NULL }
};

static const value_string flex_frame_request_ids[] = {
  { FLEX_REQUEST_ID_REORDER, "Out of order Execution"},
  { FLEX_REQUEST_ID_DURABILITY, "Durability Requirements"},
  { FLEX_REQUEST_ID_DCP_STREAM_ID, "DCP Stream Identifier"},
  { FLEX_REQUEST_ID_OPEN_TRACING, "Open Tracing"},
  { FLEX_REQUEST_ID_IMPERSONATE, "Impersonate User"},
  { FLEX_REQUEST_ID_PRESERVE_TTL, "Preserve TTL"},
  { 0, NULL }
};

static const value_string flex_frame_durability_req[] = {
  { 1, "Majority"},
  { 2, "Majority and persist on active"},
  { 3, "Persist to majority"},
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
  { PROTOCOL_BINARY_RESPONSE_NO_VBUCKET,        "Not connected to a bucket" },
  { PROTOCOL_BINARY_RESPONSE_LOCKED,            "The requested resource is locked" },
  { PROTOCOL_BINARY_RESPONSE_AUTH_STALE,        "Authentication context is stale. Should reauthenticate." },
  { PROTOCOL_BINARY_RESPONSE_AUTH_ERROR,        "Authentication error"    },
  { PROTOCOL_BINARY_RESPONSE_AUTH_CONTINUE,     "Authentication continue" },
  { PROTOCOL_BINARY_RESPONSE_ERANGE,            "Range error"             },
  { PROTOCOL_BINARY_RESPONSE_ROLLBACK,          "Rollback"                },
  { PROTOCOL_BINARY_RESPONSE_EACCESS,           "Access error"            },
  { PROTOCOL_BINARY_RESPONSE_NOT_INITIALIZED,
    "The Couchbase cluster is currently initializing this node, and "
    "the Cluster manager has not yet granted all users access to the cluster."},
  { PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND,   "Unknown command"         },
  { PROTOCOL_BINARY_RESPONSE_ENOMEM,            "Out of memory"           },
  { PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED,     "Command isn't supported" },
  { PROTOCOL_BINARY_RESPONSE_EINTERNAL,         "Internal error"          },
  { PROTOCOL_BINARY_RESPONSE_EBUSY,             "Server is busy"          },
  { PROTOCOL_BINARY_RESPONSE_ETMPFAIL,          "Temporary failure"       },
  { PROTOCOL_BINARY_RESPONSE_XATTR_EINVAL,
    "There is something wrong with the syntax of the provided XATTR."},
  { PROTOCOL_BINARY_RESPONSE_UNKNOWN_COLLECTION,
    "Operation attempted with an unknown collection."},
  { PROTOCOL_BINARY_RESPONSE_NO_COLLECTIONS_MANIFEST,
    "No collections manifest has been set"},
  { PROTOCOL_BINARY_RESPONSE_CANNOT_APPLY_MANIFEST,
    "Cannot apply the given manifest"},
  { PROTOCOL_BINARY_RESPONSE_MANIFEST_IS_AHEAD,
    "Operation attempted with a manifest ahead of the server"},
  { PROTOCOL_BINARY_RESPONSE_UNKNOWN_SCOPE,
    "Operation attempted with an unknown scope."},
  { PROTOCOL_BINARY_RESPONSE_DCP_STREAMID_INVALID,
    "DCP Stream ID is invalid"},
  { PROTOCOL_BINARY_RESPONSE_DURABILITY_INVALID_LEVEL,
    "The specified durability level is invalid" },
  { PROTOCOL_BINARY_RESPONSE_DURABILITY_IMPOSSIBLE,
    "The specified durability requirements are not currently possible" },
  { PROTOCOL_BINARY_RESPONSE_SYNC_WRITE_IN_PROGRESS,
    "A SyncWrite is already in progress on the specified key"},
  { PROTOCOL_BINARY_RESPONSE_SYNC_WRITE_AMBIGUOUS,
    "The SyncWrite request has not completed in the specified time and has ambiguous result"},
  { PROTOCOL_BINARY_RESPONSE_SYNC_WRITE_RECOMMIT_IN_PROGRESS,
    "The SyncWrite is being re-committed after a change in active node"},
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
  { PROTOCOL_BINARY_RESPONSE_SUBDOC_SUCCESS_DELETED,
    "Subdoc: The operation completed successfully, but operated on a deleted document."},
  { PROTOCOL_BINARY_RESPONSE_SUBDOC_XATTR_INVALID_FLAG_COMBO,
    "Subdoc: The combination of the subdoc flags for the xattrs doesn't make any sense."},
  { PROTOCOL_BINARY_RESPONSE_SUBDOC_XATTR_INVALID_KEY_COMBO,
    "Subdoc: Only a single xattr key may be accessed at the same time."},
  { PROTOCOL_BINARY_RESPONSE_SUBDOC_XATTR_UNKNOWN_MACRO,
    "Subdoc: The server has no knowledge of the requested macro."},
  { PROTOCOL_BINARY_RESPONSE_SUBDOC_XATTR_UNKNOWN_VATTR,
    "Subdoc: The server has no knowledge of the requested virtual xattr."},
  { PROTOCOL_BINARY_RESPONSE_SUBDOC_XATTR_CANT_MODIFY_VATTR,
    "Subdoc: Virtual xattrs can't be modified."},
  { PROTOCOL_BINARY_RESPONSE_SUBDOC_MULTI_PATH_FAILURE_DELETED,
    "Subdoc: Specified key was found as a deleted document, but one or more path operations failed."},
  { PROTOCOL_BINARY_RESPONSE_SUBDOC_INVALID_XATTR_ORDER,
    "Subdoc: According to the spec all xattr commands should come first, followed by the commands for the document body."},
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
  { PROTOCOL_BINARY_CMD_CONFIG_VALIDATE,            "Config Validate"          },
  { PROTOCOL_BINARY_CMD_CONFIG_RELOAD,              "Config Reload"            },
  { PROTOCOL_BINARY_CMD_AUDIT_PUT,                  "Audit Put"                },
  { PROTOCOL_BINARY_CMD_AUDIT_CONFIG_RELOAD,        "Audit Config Reload"      },
  { PROTOCOL_BINARY_CMD_SHUTDOWN,                   "Shutdown"                 },
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
  { PROTOCOL_BINARY_DCP_SYSTEM_EVENT,               "DCP System Event"         },
  { PROTOCOL_BINARY_DCP_PREPARE,                    "DCP Prepare"              },
  { PROTOCOL_BINARY_DCP_SEQNO_ACK,                  "DCP Seqno Acknowledgement"},
  { PROTOCOL_BINARY_DCP_COMMIT,                     "DCP Commit"               },
  { PROTOCOL_BINARY_DCP_ABORT,                      "DCP Abort"                },
  { PROTOCOL_BINARY_DCP_SEQNO_ADVANCED,             "DCP Seqno Advanced"       },
  { PROTOCOL_BINARY_DCP_OSO_SNAPSHOT,               "DCP Out of Sequence Order Snapshot"},
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
  { PROTOCOL_BINARY_CMD_GET_KEYS,                   "Get Keys"                 },
  { PROTOCOL_BINARY_CMD_COLLECTIONS_SET_MANIFEST,   "Set Collection's Manifest" },
  { PROTOCOL_BINARY_CMD_COLLECTIONS_GET_MANIFEST,   "Get Collection's Manifest" },
  { PROTOCOL_BINARY_CMD_COLLECTIONS_GET_ID,         "Get Collection ID"        },
  { PROTOCOL_BINARY_CMD_COLLECTIONS_GET_SCOPE_ID,   "Get Scope ID"             },
  { PROTOCOL_BINARY_CMD_SET_DRIFT_COUNTER_STATE,    "Set Drift Counter State"  },
  { PROTOCOL_BINARY_CMD_GET_ADJUSTED_TIME,          "Get Adjusted Time"        },
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
  { PROTOCOL_BINARY_CMD_SUBDOC_GET_COUNT,           "Subdoc Get Count"         },
  { PROTOCOL_BINARY_CMD_SCRUB,                      "Scrub"                    },
  { PROTOCOL_BINARY_CMD_ISASL_REFRESH,              "isasl Refresh"            },
  { PROTOCOL_BINARY_CMD_SSL_CERTS_REFRESH,          "SSL Certificates Refresh" },
  { PROTOCOL_BINARY_CMD_GET_CMD_TIMER,              "Internal Timer Control"   },
  { PROTOCOL_BINARY_CMD_SET_CTRL_TOKEN,             "Set Control Token"        },
  { PROTOCOL_BINARY_CMD_GET_CTRL_TOKEN,             "Get Control Token"        },
  { PROTOCOL_BINARY_CMD_UPDATE_EXTERNAL_USER_PERMISSIONS, "Update External User Permissions"},
  { PROTOCOL_BINARY_CMD_RBAC_REFRESH,               "RBAC Refresh"             },
  { PROTOCOL_BINARY_CMD_AUTH_PROVIDER,              "Auth Provider"            },
  { PROTOCOL_BINARY_CMD_DROP_PRIVILEGE,             "Drop Privilege"           },
  { PROTOCOL_BINARY_CMD_ADJUST_TIMEOFDAY,           "Adjust Timeofday"         },
  { PROTOCOL_BINARY_CMD_EWOULDBLOCK_CTL,            "EWOULDBLOCK Control"      },
  { PROTOCOL_BINARY_CMD_GET_ERROR_MAP,              "Get Error Map"            },

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

static int * const datatype_vals[] = {
  &hf_datatype_json,
  &hf_datatype_snappy,
  &hf_datatype_xattr,
  NULL
};

static int * const subdoc_flags[] = {
  &hf_subdoc_flags_mkdirp,
  &hf_subdoc_flags_xattrpath,
  &hf_subdoc_flags_expandmacros,
  &hf_subdoc_flags_reserved,
  NULL
};

static int * const subdoc_doc_flags[] = {
  &hf_subdoc_doc_flags_mkdoc,
  &hf_subdoc_doc_flags_add,
  &hf_subdoc_doc_flags_accessdeleted,
  &hf_subdoc_doc_flags_createasdeleted,
  &hf_subdoc_doc_flags_reserved,
  NULL
};

static int * const set_with_meta_extra_flags[] = {
        &hf_force_meta,
        &hf_force_accept,
        &hf_regenerate_cas,
        &hf_skip_conflict,
        NULL
};

static int * const del_with_meta_extra_flags[] = {
        &hf_force_meta,
        &hf_force_accept,
        &hf_regenerate_cas,
        &hf_skip_conflict,
        &hf_is_expiration,
        NULL
};

static const value_string feature_vals[] = {
  {0x01, "Datatype (deprecated)"},
  {0x02, "TLS"},
  {0x03, "TCP Nodelay"},
  {0x04, "Mutation Seqno"},
  {0x05, "TCP Delay"},
  {0x06, "XATTR"},
  {0x07, "Error Map"},
  {0x08, "Select Bucket"},
  {0x09, "Collections (deprecated)"},
  {0x0a, "Snappy"},
  {0x0b, "JSON"},
  {0x0c, "Duplex"},
  {0x0d, "Clustermap Change Notification"},
  {0x0e, "Unordered Execution"},
  {0x0f, "Tracing"},
  {0x10, "AltRequestSupport"},
  {0x11, "SyncReplication"},
  {0x12, "Collections"},
  {0x13, "OpenTracing"},
  {0x14, "PreserveTtl"},
  {0x15, "VAttr"},
  {0x16, "Point in Time Recovery"},
  {0x17, "SubdocCreateAsDeleted"},
  {0, NULL}
};

static const value_string dcp_system_event_id_vals [] = {
    {0, "CreateCollection"},
    {1, "DropCollection"},
    {2, "FlushCollection"},
    {3, "CreateScope"},
    {4, "DropScope"},
    {0, NULL}
};

static int * const snapshot_marker_flags [] = {
    &hf_extras_flags_dcp_snapshot_marker_memory,
    &hf_extras_flags_dcp_snapshot_marker_disk,
    &hf_extras_flags_dcp_snapshot_marker_chk,
    &hf_extras_flags_dcp_snapshot_marker_ack,
    NULL
};

static dissector_handle_t couchbase_handle;
static dissector_handle_t json_handle;

/* desegmentation of COUCHBASE payload */
static gboolean couchbase_desegment_body = TRUE;
static guint couchbase_ssl_port = 11207;
static guint couchbase_ssl_port_pref = 11207;


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
has_json_value(gboolean is_request, guint8 opcode)
{
  if (is_request) {
    switch (opcode) {
    case PROTOCOL_BINARY_CMD_AUDIT_PUT:
      return TRUE;

    default:
      return FALSE;
    }
  } else {
    switch (opcode) {
    case PROTOCOL_BINARY_CMD_GET_CLUSTER_CONFIG:
    case PROTOCOL_BINARY_CMD_SUBDOC_GET:
    case PROTOCOL_BINARY_CMD_COLLECTIONS_GET_MANIFEST:
    case PROTOCOL_BINARY_CMD_COLLECTIONS_SET_MANIFEST:
      return TRUE;

    default:
      return FALSE;
    }
  }
}

static void dissect_dcp_xattrs(tvbuff_t *tvb, proto_tree *tree,
                               guint32 value_len, gint offset,
                               packet_info *pinfo) {
  guint32 xattr_size, pair_len;
  gint mark;
  proto_tree *xattr_tree, *pair_tree;
  proto_item *ti;

  proto_tree_add_item_ret_uint(tree, hf_xattr_length, tvb, offset, 4, ENC_BIG_ENDIAN, &xattr_size);
  value_len = value_len - (xattr_size + 4);
  offset += 4;

  ti = proto_tree_add_item(tree, hf_xattrs, tvb, offset, xattr_size, ENC_NA);
  xattr_tree = proto_item_add_subtree(ti, ett_xattrs);

  while (xattr_size > 0) {

    ti = proto_tree_add_item_ret_uint(xattr_tree, hf_xattr_pair_length, tvb, offset, 4, ENC_BIG_ENDIAN, &pair_len);
    pair_tree = proto_item_add_subtree(ti, ett_xattr_pair);
    offset += 4;
    xattr_size -= 4;

    mark = tvb_find_guint8(tvb, offset, pair_len, 0x00);
    if (mark == -1) {
      expert_add_info_format(pinfo, ti, &ef_separator_not_found, "Null byte not found");
      return;
    }

    ti = proto_tree_add_item(pair_tree, hf_xattr_key, tvb, offset, mark - offset, ENC_ASCII | ENC_NA);
    xattr_size -= (mark - offset) + 1;
    pair_len -= (mark - offset) + 1;
    offset = mark + 1;

    mark = tvb_find_guint8(tvb, offset, pair_len, 0x00);
    if (mark == -1) {
      expert_add_info_format(pinfo, ti, &ef_separator_not_found, "Null byte not found");
      return;
    }

    proto_tree_add_item(pair_tree, hf_xattr_value, tvb, offset, mark - offset, ENC_ASCII | ENC_NA);
    xattr_size -= (mark - offset) + 1;
    offset = mark + 1;
  }

  //The regular value
  proto_tree_add_item(tree, hf_value, tvb, offset, value_len, ENC_ASCII | ENC_NA);
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
        proto_tree_add_item(extras_tree, hf_extras_vbucket_uuid, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;

        proto_tree_add_item(extras_tree, hf_extras_mutation_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
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
        proto_tree_add_item(extras_tree, hf_extras_vbucket_uuid, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;

        proto_tree_add_item(extras_tree, hf_extras_mutation_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
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
  case PROTOCOL_BINARY_CMD_APPEND:
  case PROTOCOL_BINARY_CMD_APPENDQ:
  case PROTOCOL_BINARY_CMD_PREPEND:
  case PROTOCOL_BINARY_CMD_PREPENDQ:
    if (extlen) {
      if (request) {
        /* Must not have extras */
        illegal = TRUE;
      } else {
        proto_tree_add_item(extras_tree, hf_extras_vbucket_uuid, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;

        proto_tree_add_item(extras_tree, hf_extras_mutation_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
      }
    }
    break;

  case PROTOCOL_BINARY_CMD_QUIT:
  case PROTOCOL_BINARY_CMD_QUITQ:
  case PROTOCOL_BINARY_CMD_VERSION:
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
    static int * const extra_flags[] = {
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
        static int * const extra_flags[] = {
          &hf_extras_flags_dcp_connection_type,
          &hf_extras_flags_dcp_include_xattrs,
          &hf_extras_flags_dcp_no_value,
          &hf_extras_flags_dcp_collections,
          &hf_extras_flags_dcp_include_delete_times,
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
        static int * const extra_flags[] = {
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
        static int * const extra_flags[] = {
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
        // Two formats exist and the extlen allows us to know which is which
        if (extlen == 1) {
          proto_tree_add_item(extras_tree, hf_extras_marker_version, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
        } else if (extlen == 20){
          proto_tree_add_item(extras_tree, hf_extras_start_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
          offset += 8;
          proto_tree_add_item(extras_tree, hf_extras_end_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
          offset += 8;
          proto_tree_add_bitmask(extras_tree, tvb, offset, hf_extras_flags, ett_extras_flags, snapshot_marker_flags, ENC_BIG_ENDIAN);
          offset += 4;
        } else {
          illegal = TRUE;
        }
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
        static int * const extra_flags[] = {
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
    if (request) {
      if (extlen == 18 || extlen == 21) {
        proto_tree_add_item(extras_tree, hf_extras_by_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item(extras_tree, hf_extras_rev_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;

        // Is this a delete with delete_time (21 bytes) or not (18 bytes)?
        if (extlen == 18) {
          proto_tree_add_item(extras_tree, hf_extras_nmeta, tvb, offset, 2, ENC_BIG_ENDIAN);
          offset += 2;
        } else if (extlen == 21) {
          proto_tree_add_item(extras_tree, hf_extras_delete_time, tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
          proto_tree_add_item(extras_tree, hf_extras_delete_unused, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
        }
      } else if (extlen == 0) {
        missing = TRUE; // request with no extras
      }
    } else if (extlen) {
        illegal = TRUE; // response with extras
    }
    break;
  case PROTOCOL_BINARY_DCP_EXPIRATION:
    if (extlen) {
        if (request) {
            proto_tree_add_item(extras_tree, hf_extras_by_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
            offset += 8;
            proto_tree_add_item(extras_tree, hf_extras_rev_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
            offset += 8;
            if (extlen == 20) {
                proto_tree_add_item(extras_tree, hf_extras_delete_time, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            } else {
                // Handle legacy expiration packet (despite its lack of use)
                proto_tree_add_item(extras_tree, hf_extras_nmeta, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }
        } else {
            illegal = TRUE;
        }
    } else if (request) {
        /* Request must have extras */
        missing = TRUE;
    }
    break;
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
  case PROTOCOL_BINARY_DCP_SYSTEM_EVENT: {
    if (request && extlen == 13) {
      proto_tree_add_item(extras_tree, hf_extras_by_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
      offset += 8;
      proto_tree_add_item(extras_tree, hf_extras_system_event_id, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(extras_tree, hf_extras_system_event_version, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
    }
    break;
  }
  case PROTOCOL_BINARY_DCP_PREPARE: {
    if (extlen) {
      if (request) {
        static int * const extra_flags[] = {
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
        proto_tree_add_item(extras_tree, hf_extras_nru, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(extras_tree, hf_extras_deleted, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(extras_tree, hf_flex_frame_durability_req, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
      } else {
        illegal = TRUE;
      }
    } else if (request) {
      /* Request must have extras */
      missing = TRUE;
    }
    break;
  }
  case PROTOCOL_BINARY_DCP_SEQNO_ACK: {
    if (extlen) {
      if (request) {
        proto_tree_add_item(extras_tree, hf_extras_by_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
      } else {
        illegal = TRUE;
      }
    } else if (request) {
      /* Request must have extras */
      missing = TRUE;
    }
    break;
  }
  case PROTOCOL_BINARY_DCP_COMMIT: {
    if (extlen) {
      if (request) {
        proto_tree_add_item(extras_tree, hf_extras_prepared_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item(extras_tree, hf_extras_by_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
      } else {
        illegal = TRUE;
      }
    } else if (request) {
      /* Request must have extras */
      missing = TRUE;
    }
    break;
  }
  case PROTOCOL_BINARY_DCP_ABORT: {
    if (extlen) {
      if (request) {
        proto_tree_add_item(extras_tree, hf_extras_prepared_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item(extras_tree, hf_extras_abort_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
      } else {
        illegal = TRUE;
      }
    } else if (request) {
      /* Request must have extras */
      missing = TRUE;
    }
    break;
  }
  case PROTOCOL_BINARY_DCP_SEQNO_ADVANCED: {
    if (extlen) {
      if (request) {
        proto_tree_add_item(extras_tree, hf_extras_by_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
      } else {
        illegal = TRUE;
      }
    } else if (request) {
      /* Request must have extras */
      missing = TRUE;
    }
    break;
  }
  case PROTOCOL_BINARY_DCP_OSO_SNAPSHOT: {
    if (extlen) {
      if (request) {
        static int * const extra_flags[] = {
          &hf_extras_flags_dcp_oso_snapshot_begin,
          &hf_extras_flags_dcp_oso_snapshot_end,
          NULL
        };
        proto_tree_add_bitmask(extras_tree,
                               tvb,
                               offset,
                               hf_extras_dcp_oso_snapshot_flags,
                               ett_extras_flags,
                               extra_flags,
                               ENC_BIG_ENDIAN);
        offset += 4;
      } else {
        illegal = TRUE;
      }
    } else if (request) {
      /* Request must have extras */
      missing = TRUE;
    }
    break;
  }
  case PROTOCOL_BINARY_CMD_SUBDOC_GET:
  case PROTOCOL_BINARY_CMD_SUBDOC_EXISTS:
    dissect_subdoc_spath_required_extras(tvb, extras_tree, extlen, request,
                                         &offset, path_len, &illegal);
    if (extlen == 4) {
      proto_tree_add_bitmask(extras_tree, tvb, offset, hf_subdoc_doc_flags,
                             ett_extras_flags, subdoc_doc_flags, ENC_BIG_ENDIAN);
      offset += 1;
    }
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
         if and only if (extlen == 7 || extlen == 8) */
      if (extlen == 7 || extlen == 8) {
        proto_tree_add_item(extras_tree, hf_extras_expiration, tvb, offset,
                            4, ENC_BIG_ENDIAN);
        offset += 4;
      }
      /* optional doc flags only permitted if and only if
         (extlen == 4 || extlen == 8) */
      if (extlen == 4 || extlen == 8) {
        proto_tree_add_bitmask(extras_tree, tvb, offset, hf_subdoc_doc_flags,
                               ett_extras_flags, subdoc_doc_flags,
                               ENC_BIG_ENDIAN);
        offset += 1;
      }
      if (extlen != 3 && extlen != 7 && extlen != 4 && extlen != 8) {
        illegal = TRUE;
      }
    }
    break;

  case PROTOCOL_BINARY_CMD_SUBDOC_MULTI_LOOKUP:
    if (request) {
      if (extlen == 1) {
        proto_tree_add_bitmask(extras_tree, tvb, offset, hf_subdoc_doc_flags,
                               ett_extras_flags, subdoc_doc_flags,
                               ENC_BIG_ENDIAN);
        offset += 1;
      } else {
        illegal = TRUE;
      }
    }
    break;

  case PROTOCOL_BINARY_CMD_SUBDOC_MULTI_MUTATION:
    if (request) {
      if (extlen == 4 || extlen == 5) {
        proto_tree_add_item(extras_tree, hf_extras_expiration, tvb, offset, 4,
                            ENC_BIG_ENDIAN);
        offset += 4;
      }
      if (extlen == 1 || extlen == 5) {
        proto_tree_add_bitmask(extras_tree, tvb, offset, hf_subdoc_doc_flags,
                               ett_extras_flags, subdoc_doc_flags, ENC_BIG_ENDIAN);
        offset += 1;
      }
      if (extlen != 1 && extlen != 4 && extlen != 5) {
        illegal = TRUE;
      }
    }
    break;

  case PROTOCOL_BINARY_CMD_DEL_WITH_META:
  case PROTOCOL_BINARY_CMD_SET_WITH_META:
    if (request) {
      proto_tree_add_item(extras_tree, hf_meta_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(extras_tree, hf_meta_expiration, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(extras_tree, hf_meta_revseqno, tvb, offset, 8, ENC_BIG_ENDIAN);
      offset += 8;
      proto_tree_add_item(extras_tree, hf_meta_cas, tvb, offset, 8, ENC_BIG_ENDIAN);
      offset += 8;

      /*The previous 24 bytes are required. The next two fields are optional,
       * hence we are checking the extlen to see what fields we have. As they
       * are different lengths we can do this by just checking the length.*/

      // Options field (4 bytes)
      if (extlen == 28 || extlen == 30) {
          proto_tree_add_bitmask(
                  extras_tree,
                  tvb,
                  offset,
                  hf_meta_options,
                  ett_extras_flags,
                  (opcode == PROTOCOL_BINARY_CMD_DEL_WITH_META) ?
                      del_with_meta_extra_flags : set_with_meta_extra_flags,
                  ENC_BIG_ENDIAN);
          offset += 4;
      }
      // Meta Length field (2 bytes)
      if (extlen == 26 || extlen == 30) {
        proto_tree_add_item(extras_tree, hf_metalen, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
      }
    }
    break;

  case PROTOCOL_BINARY_CMD_GET_META:
    if (request) {
      if(extlen) {
        proto_tree_add_item(extras_tree, hf_meta_reqextmeta, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
      }
    } else {
      proto_tree_add_item(extras_tree, hf_meta_deleted, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(extras_tree, hf_meta_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(extras_tree, hf_exptime, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(extras_tree, hf_extras_meta_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
      offset += 8;
      if (extlen == 21) {
        proto_tree_add_item(extras_tree, hf_confres, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
      }
    }
    break;
  case PROTOCOL_BINARY_CMD_COLLECTIONS_GET_ID:
    if (!request) {
      proto_tree_add_item(extras_tree, hf_collection_manifest_id, tvb, offset, 8, ENC_BIG_ENDIAN);
      offset += 8;
      proto_tree_add_item(extras_tree, hf_collection_key_id, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
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

/*
  Decode an unsigned leb128 int from a slice within a tvbuff_t
  @param tvb buffer to read from
  @param start index of the first byte of 'slice'
  @param end index of the last byte of the buffer 'slice'
  @param [out] value the decoded value
  @returns next byte after the leb128 bytes or -1 if we failed to decode
*/
static gint
dissect_unsigned_leb128(tvbuff_t *tvb, gint start, gint end, guint32* value) {
    guint8 byte = tvb_get_guint8(tvb, start);
    *value = byte & 0x7f;


    if ((byte & 0x80) == 0x80) {
        guint32 shift = 7;
        gint byte_idx;
        for (byte_idx = start+1; byte_idx < end; byte_idx++) {
            byte = tvb_get_guint8(tvb, byte_idx);
            /* Ensure we are using a valid shift */
            if (shift > 32)
                return -1;
            *value |= (byte & 0x7f) << shift;
            if ((byte & 0x80) == 0) {
                break;
            }
            shift += 7;
        }
        return (byte_idx == end) ? -1 : byte_idx + 1;
    }
    return start + 1;
}

static void
dissect_key(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
            gint offset, int keylen, guint8 opcode, gboolean request)
{
  proto_item *ti = NULL;
  gboolean    illegal = FALSE;  /* Set when key shall not be present */
  gboolean    missing = FALSE;  /* Set when key is missing */

  if (keylen) {
    ti = proto_tree_add_item(tree, hf_key, tvb, offset, keylen, ENC_UTF_8|ENC_STR_HEX);

    /* assume collections are enabled and add a field for the CID */
    guint32 cid = 0;
    gint ok = dissect_unsigned_leb128(tvb, offset, offset + keylen, &cid);

    /* Add collection info to a subtree */
    proto_tree* cid_tree = proto_item_add_subtree(ti,
                                                  ett_collection_key);

    if (ok != -1) {
      proto_tree_add_uint(cid_tree,
                          hf_collection_key_id,
                          tvb,
                          offset,
                          (ok - offset),
                          cid);
      proto_tree_add_item(cid_tree,
                          hf_collection_key_logical,
                          tvb,
                          ok,
                          keylen - (ok - offset),
                          ENC_UTF_8|ENC_STR_HEX);
    } else {
      /* cid decode issue, could just be a non-collection stream, don't warn
         just add some info */
      proto_tree_add_string_format(cid_tree,
                                   hf_collection_key_logical,
                                   tvb,
                                   offset,
                                   keylen,
                                   NULL,
                                   "Collection ID didn't decode, maybe no CID.");
    }

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
    case PROTOCOL_BINARY_DCP_SYSTEM_EVENT:
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
        json_tvb = tvb_new_subset_length_caplen(tvb, offset, result_len, result_len);
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
        json_tvb = tvb_new_subset_length_caplen(tvb, offset, result_len, result_len);
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

    /* Minimum size is the fixed header. */
    min_spec_size = (is_mutation ? 8 : 4);

    while (offset + min_spec_size <= end) {
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

      if (path_len) {
        proto_tree_add_item(multipath_tree, hf_multipath_path, tvb, offset, path_len,
                            ENC_ASCII | ENC_NA);
        offset += path_len;
      }

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
              gboolean request, guint8 datatype)
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
    } else if (!request && (opcode == PROTOCOL_BINARY_DCP_STREAM_REQUEST || opcode == PROTOCOL_BINARY_DCP_FAILOVER_LOG_REQUEST)) {
      if (value_len % 16 != 0) {
        expert_add_info_format(pinfo, ti, &ef_warn_illegal_value_length, "Response with bad failover log length");
      } else {
        proto_tree *failover_log_tree;
        gint cur = offset, end = offset + value_len;
        ti = proto_tree_add_item(tree, hf_failover_log, tvb, offset, value_len, ENC_ASCII|ENC_NA);
        failover_log_tree = proto_item_add_subtree(ti, ett_failover_log);
        ti = proto_tree_add_uint(failover_log_tree, hf_failover_log_size, tvb, offset, 0, (end - cur) / 16);
        proto_item_set_generated(ti);
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
        proto_item_set_generated(ti);
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
    } else if (has_json_value(request, opcode)) {
      tvbuff_t *json_tvb;
      ti = proto_tree_add_item(tree, hf_value, tvb, offset, value_len, ENC_ASCII | ENC_NA);
      json_tvb = tvb_new_subset_length_caplen(tvb, offset, value_len, value_len);
      call_dissector(json_handle, json_tvb, pinfo, tree);

    } else if (opcode == PROTOCOL_BINARY_CMD_SUBDOC_MULTI_LOOKUP ||
               opcode == PROTOCOL_BINARY_CMD_SUBDOC_MULTI_MUTATION) {
      dissect_multipath_value(tvb, pinfo, tree, offset, value_len,
                              (opcode == PROTOCOL_BINARY_CMD_SUBDOC_MULTI_MUTATION),
                              request);

    } else if (opcode == PROTOCOL_BINARY_CMD_HELLO) {
      gint curr = offset, end = offset + value_len;
      proto_tree *hello_features_tree;
      ti = proto_tree_add_item(tree, hf_hello_features, tvb, offset, value_len, ENC_ASCII|ENC_NA);
      hello_features_tree = proto_item_add_subtree(ti, ett_hello_features);
      while (curr < end) {
        proto_tree_add_item(hello_features_tree, hf_hello_features_feature, tvb, curr, 2, ENC_BIG_ENDIAN);
        curr += 2;
      }
    } else if (path_len != 0) {
        ti = proto_tree_add_item(tree, hf_path, tvb, offset, path_len, ENC_ASCII | ENC_NA);
        value_len -= path_len;
        if (value_len > 0) {
            ti = proto_tree_add_item(tree, hf_value, tvb, offset + path_len,
                                     value_len, ENC_ASCII | ENC_NA);
        }
    } else if (request && opcode == PROTOCOL_BINARY_CMD_CREATE_BUCKET) {
      gint sep, equals_pos, sep_pos, config_len;
      proto_tree *key_tree, *config_tree = NULL;

      /* There are 2 main items stored in the value. The bucket type (represented by a path to the engine) and the
       * bucket config. These are separated by a NULL byte with the bucket type coming first.*/

      sep = tvb_find_guint8(tvb, offset, value_len, 0x00);
      if (sep == -1) {
        ti = proto_tree_add_item(tree, hf_value, tvb, offset, value_len, ENC_ASCII|ENC_NA);
        expert_add_info_format(pinfo, ti, &ef_separator_not_found, "Null byte not found");
      } else {
        proto_tree_add_item(tree, hf_bucket_type, tvb, offset, sep - offset, ENC_ASCII | ENC_NA);
        config_len = value_len - (sep - offset) - 1; //Don't include NULL byte in length
        if(config_len <= 0) {
          expert_add_info_format(pinfo, ti, &ef_separator_not_found, "Separator not found in expected location");
        } else {
          offset = sep + 1;// Ignore NULL byte

          ti = proto_tree_add_item(tree, hf_bucket_config, tvb, offset, config_len, ENC_ASCII | ENC_NA);
          config_tree = proto_item_add_subtree(ti, ett_config);
        }

        /* The config is arranged as "key=value;key=value..."*/
        while (config_len > 0) {
          // Get the key
          equals_pos = tvb_find_guint8(tvb, offset, config_len, 0x3d);
          if (equals_pos == -1) {
            expert_add_info_format(pinfo, ti, &ef_illegal_value, "Each key needs a value");
            break; // Break out the while loop
          }
          ti = proto_tree_add_item(config_tree, hf_config_key, tvb, offset, equals_pos - offset, ENC_ASCII | ENC_NA);
          key_tree = proto_item_add_subtree(ti, ett_config_key);
          config_len -= (equals_pos - offset + 1);
          offset = equals_pos + 1;
          if (config_len <= 0) {
            expert_add_info_format(pinfo, ti, &ef_illegal_value, "Corresponding value missing");
            break;//Break out of while loop
          }

          // Get the value
          sep_pos = tvb_find_guint8(tvb, offset, config_len, 0x3b);
          if (sep_pos == -1) {
            expert_add_info_format(pinfo, ti, &ef_separator_not_found, "Each key-value pair must be terminated by semi-colon");
            break; // Break out the while loop
          }
          proto_tree_add_item(key_tree, hf_config_value, tvb, offset, sep_pos - offset, ENC_ASCII | ENC_NA);
          config_len -= (sep_pos - offset + 1);
          offset = sep_pos + 1;
        }
      }
    } else if ((datatype & DT_XATTR) && (opcode == PROTOCOL_BINARY_CMD_SET_WITH_META ||
      opcode == PROTOCOL_BINARY_DCP_MUTATION || opcode == PROTOCOL_BINARY_DCP_DELETION ||
      opcode == PROTOCOL_BINARY_DCP_EXPIRATION || opcode == PROTOCOL_BINARY_DCP_PREPARE ||
      opcode == PROTOCOL_BINARY_CMD_DEL_WITH_META || opcode == PROTOCOL_BINARY_CMD_ADD_WITH_META ||
      opcode == PROTOCOL_BINARY_CMD_SETQ_WITH_META || opcode == PROTOCOL_BINARY_CMD_DELQ_WITH_META ||
      opcode == PROTOCOL_BINARY_CMD_ADDQ_WITH_META )) {

      dissect_dcp_xattrs(tvb, tree, value_len, offset, pinfo);
    } else if (request && opcode == PROTOCOL_BINARY_CMD_GET_ERROR_MAP) {
      if (value_len != 2) {
        expert_add_info_format(pinfo, ti, &ef_warn_illegal_value_length, "Illegal Value length, should be 2");
        ti = proto_tree_add_item(tree, hf_value, tvb, offset, value_len, ENC_ASCII | ENC_NA);
      } else {
        ti = proto_tree_add_item(tree, hf_get_errmap_version, tvb, offset, value_len, ENC_BIG_ENDIAN);
      }
    } else if (request && opcode == PROTOCOL_BINARY_DCP_SNAPSHOT_MARKER) {
      if (value_len != 36) {
        expert_add_info_format(pinfo, ti, &ef_warn_illegal_value_length, "Illegal Value length, should be 36");
        ti = proto_tree_add_item(tree, hf_value, tvb, offset, value_len, ENC_ASCII | ENC_NA);
      } else {
        proto_tree_add_item(tree, hf_extras_start_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item(tree, hf_extras_end_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_bitmask(tree, tvb, offset, hf_extras_flags, ett_extras_flags, snapshot_marker_flags, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_extras_max_visible_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item(tree, hf_extras_high_completed_seqno, tvb, offset, 8, ENC_BIG_ENDIAN);
      }
    } else {
      ti = proto_tree_add_item(tree, hf_value, tvb, offset, value_len, ENC_ASCII | ENC_NA);
#ifdef HAVE_SNAPPY
      if (datatype & DT_SNAPPY) {
        size_t orig_size = 0;
        snappy_status ret;
        guchar *decompressed_buffer = NULL;
        tvbuff_t* compressed_tvb = NULL;

        ret = snappy_uncompressed_length(tvb_get_ptr(tvb, offset, -1),
                                         tvb_captured_length_remaining(tvb, offset),
                                         &orig_size);
        if (ret == SNAPPY_OK) {
          decompressed_buffer = (guchar*)wmem_alloc(pinfo->pool, orig_size);
          ret = snappy_uncompress(tvb_get_ptr(tvb, offset, -1),
                                  tvb_captured_length_remaining(tvb, offset),
                                  decompressed_buffer,
                                  &orig_size);
          if (ret == SNAPPY_OK) {
            compressed_tvb = tvb_new_child_real_data(tvb, decompressed_buffer, (guint32)orig_size, (guint32)orig_size);
            add_new_data_source(pinfo, compressed_tvb, "Decompressed Data");
            if (datatype & DT_JSON) {
              call_dissector(json_handle, compressed_tvb, pinfo, tree);
            }
          } else {
            expert_add_info_format(pinfo, ti, &ef_compression_error, "Error uncompressing snappy data");
          }
        } else {
            expert_add_info_format(pinfo, ti, &ef_compression_error, "Error uncompressing snappy data");
        }
      }
#endif
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

static void flex_frame_duration_dissect(tvbuff_t* tvb,
                                        proto_tree* frame_tree,
                                        gint offset,
                                        gint length) {

  if (length != 2) {
    proto_tree_add_expert_format(frame_tree,
                                 NULL,
                                 &ef_warn_unknown_flex_len,
                                 tvb,
                                 offset,
                                 length,
                                 "FlexFrame: RX/TX Duration with illegal length %d", length);
  } else {
    guint16 encoded_micros = tvb_get_ntohs(tvb, offset);
    proto_tree_add_double(frame_tree,
                          hf_flex_frame_tracing_duration,
                          tvb,
                          offset,
                          2,
                          pow(encoded_micros, 1.74) / 2);
  }
}

static void flex_frame_reorder_dissect(tvbuff_t* tvb,
                                       proto_tree* frame_tree,
                                       gint offset,
                                       gint length) {
  /* Expects no data, so just check len */
  if (length != 0) {
    proto_tree_add_expert_format(frame_tree,
                                 NULL,
                                 &ef_warn_unknown_flex_len,
                                 tvb,
                                 offset,
                                 length,
                                 "FlexFrame: Out Of Order with illegal length %d", length);
  }
}

static void flex_frame_durability_dissect(tvbuff_t* tvb,
                                          proto_tree* frame_tree,
                                          gint offset,
                                          gint length) {
  if (!(length == 1 || length == 3)) {
    proto_tree_add_expert_format(frame_tree,
                                 NULL,
                                 &ef_warn_unknown_flex_len,
                                 tvb,
                                 offset,
                                 length,
                                 "FlexFrame: Durability with illegal length %d", length);
    return;
  }
  proto_tree_add_item(frame_tree, hf_flex_frame_durability_req, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void flex_frame_dcp_stream_id_dissect(tvbuff_t* tvb,
                                             proto_tree* frame_tree,
                                             gint offset,
                                             gint length) {
  if (length != 2) {
    proto_tree_add_expert_format(frame_tree,
                                 NULL,
                                 &ef_warn_unknown_flex_len,
                                 tvb,
                                 offset,
                                 length,
                                 "FlexFrame: DCP Stream ID with illegal length %d", length);
  } else {
    guint16 sid = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(frame_tree, hf_flex_frame_dcp_stream_id, tvb, offset, 2, sid);
  }
}

static void flex_frame_impersonate_dissect(tvbuff_t* tvb,
                                           proto_tree* frame_tree,
                                           gint offset,
                                           gint length) {
  proto_tree_add_item(frame_tree,
                      hf_flex_frame_impersonated_user,
                      tvb,
                      offset,
                      length,
                      ENC_UTF_8|ENC_STR_HEX);
}

static void flex_frame_preserve_ttl(tvbuff_t* tvb,
                                    proto_tree* frame_tree,
                                    gint offset,
                                    gint length) {
  /* Expects no data, so just check len */
  if (length != 0) {
    proto_tree_add_expert_format(frame_tree,
                                 NULL,
                                 &ef_warn_unknown_flex_len,
                                 tvb,
                                 offset,
                                 length,
                                 "FlexFrame: Preserve TTL with illegal length %d", length);
  }
}

typedef void (*flex_frame_by_id_dissect_fn)(tvbuff_t*,
                                            proto_tree*,
                                            gint,
                                            gint);

struct flex_frame_by_id_dissect {
  guint32 id;
  flex_frame_by_id_dissect_fn handler;
};

static const struct flex_frame_by_id_dissect flex_frame_response_dissect[] = {
  {FLEX_RESPONSE_ID_RX_TX_DURATION, &flex_frame_duration_dissect},
  {0, NULL }
};

static const struct flex_frame_by_id_dissect flex_frame_request_dissect[] = {
  { FLEX_REQUEST_ID_REORDER, &flex_frame_reorder_dissect},
  { FLEX_REQUEST_ID_DURABILITY, &flex_frame_durability_dissect},
  { FLEX_REQUEST_ID_DCP_STREAM_ID, &flex_frame_dcp_stream_id_dissect},
  { FLEX_REQUEST_ID_IMPERSONATE, &flex_frame_impersonate_dissect},
  { FLEX_REQUEST_ID_PRESERVE_TTL, &flex_frame_preserve_ttl},
  { 0, NULL }
};

/*
  Flexible Framing Extras:
  https://github.com/couchbase/kv_engine/blob/master/docs/BinaryProtocol.md
*/
static void dissect_flexible_framing_extras(tvbuff_t* tvb,
                                            packet_info* pinfo,
                                            proto_tree* tree,
                                            gint offset,
                                            guint8 flex_frame_extra_len,
                                            gboolean request) {

    /* select some request/response ID decoders */
  const struct flex_frame_by_id_dissect* id_dissectors = flex_frame_response_dissect;
  int info_id = hf_flex_frame_id_res;
  int info_id_esc = hf_flex_frame_id_res_esc;
  int info_len_id = hf_flex_frame_len;
  if (request) {
    id_dissectors = flex_frame_request_dissect;
    info_id = hf_flex_frame_id_req;
    info_id_esc = hf_flex_frame_id_req_esc;
  }

  /* This first item shows the entire extent of all frame extras.
     If we have multiple frames, we will add them in the iteration */
  proto_tree_add_uint(tree,
                      hf_flex_extras,
                      tvb,
                      offset,
                      flex_frame_extra_len,
                      flex_frame_extra_len);

  /* iterate until we've consumed the flex_frame_extra_len */
  gint bytes_remaining = flex_frame_extra_len;
  int frame_index = 0;

  while (bytes_remaining > 0) {

    /* FrameInfo starts with a 'tag' byte which is formed from 2 nibbles */
    guint8 tag_byte = tvb_get_guint8(tvb, offset);

    /* 0xff isn't defined yet in the spec as to what it should do */
    if (tag_byte == 0xFF) {
      proto_tree_add_expert_format(tree,
                                   pinfo,
                                   &ef_warn_unknown_flex_unsupported,
                                   tvb,
                                   offset,
                                   1,
                                   "Cannot decode 0xFF id/len byte");
      return;
    }

    /* extract the nibbles into u16, if the id/len nibbles are escapes, their
       true values come from following bytes and can be larger than u8 */
    guint16 id = tag_byte >> 4;
    guint16 len = tag_byte & 0x0F;

    int id_size = 1;
    /* Calculate the id/len and add to the tree */
    if (id == FLEX_ESCAPE) {
      id = id + tvb_get_guint8(tvb, offset + 1);
      id_size++;
      info_id = info_id_esc;
    }

    int len_size = 1;
    if (len == FLEX_ESCAPE) {
      len = len + tvb_get_guint8(tvb, offset + 1);
      len_size++;
      info_len_id = hf_flex_frame_len_esc;
    }

    /* add a new sub-tree for this FrameInfo */
    proto_item* flex_item = proto_tree_add_string_format(tree,
                                                         hf_flex_extras_n,
                                                         tvb,
                                                         offset,
                                                         1 + len,
                                                         NULL,
                                                         "Flexible Frame %d",
                                                         frame_index);

    proto_tree* frame_tree = proto_item_add_subtree(flex_item,
                                                    ett_flex_frame_extras);

    /* Now add the info under the sub-tree */
    proto_tree_add_uint(frame_tree, info_id, tvb, offset, id_size, id);
    proto_tree_add_uint(frame_tree, info_len_id, tvb, offset, len_size, len);

    /* this is broken if both len and id are escaped, but we've returned earlier
       for that case (with a warning) */
    offset = offset + 1 + (len_size - 1) + (id_size - 1);
    bytes_remaining = bytes_remaining - 1 - (len_size - 1) - (id_size - 1);;

    /* lookup a dissector function by id */
    int id_index = 0, found = 0;
    while (id_dissectors[id_index].handler) {
      if (id_dissectors[id_index].id == id) {
        id_dissectors[id_index].handler(tvb, frame_tree, offset, len);
        found = 1;
        break;
      }
      id_index++;
    }

    if (!found)  {
      proto_tree_add_expert_format(frame_tree,
                                   pinfo,
                                   &ef_warn_unknown_flex_id,
                                   tvb,
                                   offset,
                                   len,
                                   "FlexFrame: no dissector function for %d", id);
    }

    offset += len;
    bytes_remaining -= len;
    frame_index++;
  }
}

static gboolean
is_xerror(guint8 datatype, guint16 status)
{
  if ((datatype & DT_JSON) && status != PROTOCOL_BINARY_RESPONSE_SUBDOC_MULTI_PATH_FAILURE) {
    return TRUE;
  }
  return FALSE;
}

static int
dissect_couchbase(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree *couchbase_tree;
  proto_item *couchbase_item, *ti;
  gint        offset = 0;
  guint8      magic, opcode, extlen, datatype, flex_frame_extras = 0;
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

  /* Check for flex magic, which changes the header format */
  if (magic == MAGIC_RESPONSE_FLEX || magic == MAGIC_REQUEST_FLEX) {
    /* 2 separate bytes for the flex_extras and keylen */
    flex_frame_extras = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(couchbase_tree, hf_flex_extras_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    keylen = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(couchbase_tree, hf_flex_keylength, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
  } else {
    /* 2 bytes for the key */
    keylen = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(couchbase_tree, hf_keylength, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
  }

  extlen = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(couchbase_tree, hf_extlength, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  datatype = tvb_get_guint8(tvb, offset);
  proto_tree_add_bitmask(couchbase_tree, tvb, offset, hf_datatype, ett_datatype, datatype_vals, ENC_BIG_ENDIAN);
  offset += 1;

  /* We suppose this is a response, even when unknown magic byte */
  if (magic & 0x01 || magic == MAGIC_RESPONSE_FLEX) {
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
    switch (opcode) {
      case PROTOCOL_BINARY_CMD_OBSERVE:
      case PROTOCOL_BINARY_CMD_COLLECTIONS_GET_ID:
          break;
      default:
          proto_item_append_text(couchbase_item, ", VBucket: 0x%x", vbucket);
          col_append_fstr(pinfo->cinfo, COL_INFO, ", VBucket: 0x%x", vbucket);
    }
  }
  offset += 2;

  bodylen = tvb_get_ntohl(tvb, offset);
  value_len = bodylen - extlen - keylen - flex_frame_extras;
  ti = proto_tree_add_uint(couchbase_tree, hf_value_length, tvb, offset, 0, value_len);
  proto_item_set_generated(ti);

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

  // Flex frame extras should be dissected for success and errors
  if (flex_frame_extras) {
    dissect_flexible_framing_extras(tvb,
                                    pinfo,
                                    couchbase_tree,
                                    offset,
                                    flex_frame_extras,
                                    magic == MAGIC_REQUEST_FLEX);
    offset += flex_frame_extras;
  }

  if (status == 0) {
    guint16 path_len = 0;

    dissect_extras(tvb, pinfo, couchbase_tree, offset, extlen, opcode, request,
                   &path_len);
    offset += extlen;

    dissect_key(tvb, pinfo, couchbase_tree, offset, keylen, opcode, request);
    offset += keylen;

    dissect_value(tvb, pinfo, couchbase_tree, offset, value_len, path_len,
                  opcode, request, datatype);
  } else if (value_len) {
    proto_tree_add_item(couchbase_tree, hf_value, tvb, offset, value_len,
                        ENC_ASCII | ENC_NA);
    if (status == PROTOCOL_BINARY_RESPONSE_NOT_MY_VBUCKET || is_xerror(datatype, status)) {
      tvbuff_t *json_tvb;
      json_tvb = tvb_new_subset_length_caplen(tvb, offset, value_len, value_len);
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
    { &hf_datatype, { "Data Type", "couchbase.datatype", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL} },
    { &hf_datatype_json, { "JSON", "couchbase.datatype.json", FT_BOOLEAN, 8, TFS(&tfs_set_notset), DT_JSON, "JSON datatype", HFILL} },
    { &hf_datatype_snappy, { "Snappy", "couchbase.datatype.snappy", FT_BOOLEAN, 8, TFS(&tfs_set_notset), DT_SNAPPY, "Snappy Compressed", HFILL} },
    { &hf_datatype_xattr, { "XATTR", "couchbase.datatype.xattr", FT_BOOLEAN, 8, TFS(&tfs_set_notset), DT_XATTR, "Xattrs included", HFILL} },
    { &hf_vbucket, { "VBucket", "couchbase.vbucket", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, "VBucket ID", HFILL } },
    { &hf_status, { "Status", "couchbase.status", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &status_vals_ext, 0x0, "Status of the response", HFILL } },
    { &hf_total_bodylength, { "Total Body Length", "couchbase.total_bodylength", FT_UINT32, BASE_DEC, NULL, 0x0, "Length in bytes of extra + key + value", HFILL } },
    { &hf_opaque, { "Opaque", "couchbase.opaque", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_cas, { "CAS", "couchbase.cas", FT_UINT64, BASE_HEX, NULL, 0x0, "Data version check", HFILL } },
    { &hf_ttp, { "Time to Persist", "couchbase.ttp", FT_UINT32, BASE_DEC, NULL, 0x0, "Approximate time needed to persist the key (milliseconds)", HFILL } },
    { &hf_ttr, { "Time to Replicate", "couchbase.ttr", FT_UINT32, BASE_DEC, NULL, 0x0, "Approximate time needed to replicate the key (milliseconds)", HFILL } },

    { &hf_collection_key_id, { "Collection ID", "couchbase.key.collection_id", FT_UINT32, BASE_HEX, NULL, 0x0, "If this a collection stream, this is the collection-ID", HFILL } },
    { &hf_collection_key_logical, { "Collection Logical Key", "couchbase.key.logical_key", FT_STRING, BASE_NONE, NULL, 0x0, "If this a collection stream, this is the key in the collection", HFILL } },
    { &hf_collection_manifest_id, { "Collections Manifest ID", "couchbase.key.collection_manifest_id", FT_UINT64, BASE_HEX, NULL, 0x0, "The collections manifest id", HFILL } },

    { &hf_flex_keylength, { "Key Length", "couchbase.key.length", FT_UINT8, BASE_DEC, NULL, 0x0, "Length in bytes of the text key that follows the command extras", HFILL } },
    { &hf_flex_extras_length, { "Flexible Framing Extras Length", "couchbase.flex_extras", FT_UINT8, BASE_DEC, NULL, 0x0, "Length in bytes of the flexible framing extras that follows the response header", HFILL } },
    { &hf_flex_extras, {"Flexible Framing Extras", "couchbase.flex_frame_extras", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_flex_extras_n, {"Flexible Framing Extras", "couchbase.flex_frame_extras.string", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },

    { &hf_flex_frame_id_byte0, {"Flexible Frame Byte0", "couchbase.flex_frame.byte0", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_flex_frame_id_req, {"Flexible Frame ID (request)", "couchbase.flex_frame.frame.id", FT_UINT8, BASE_DEC, VALS(flex_frame_request_ids), 0x0, NULL, HFILL } },
    { &hf_flex_frame_id_res, {"Flexible Frame ID (response)", "couchbase.flex_frame.frame.id", FT_UINT8, BASE_DEC, VALS(flex_frame_response_ids), 0x0, NULL, HFILL } },
    { &hf_flex_frame_id_req_esc, {"Flexible Frame ID esc (request)", "couchbase.flex_frame.frame.id", FT_UINT16, BASE_DEC, VALS(flex_frame_request_ids), 0x0, NULL, HFILL } },
    { &hf_flex_frame_id_res_esc, {"Flexible Frame ID esc (response)", "couchbase.flex_frame.frame.id", FT_UINT16, BASE_DEC, VALS(flex_frame_response_ids), 0x0, NULL, HFILL } },


    { &hf_flex_frame_len, {"Flexible Frame Len", "couchbase.flex_frame.frame.len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_flex_frame_len_esc, {"Flexible Frame Len (esc)", "couchbase.flex_frame.frame.len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_flex_frame_tracing_duration, {"Server Recv->Send duration", "couchbase.flex_frame.frame.duration", FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, &units_microseconds, 0, NULL, HFILL } },
    { &hf_flex_frame_durability_req, {"Durability Requirement", "couchbase.flex_frame.frame.durability_req", FT_UINT8, BASE_DEC, VALS(flex_frame_durability_req), 0, NULL, HFILL } },
    { &hf_flex_frame_dcp_stream_id, {"DCP Stream Identifier", "couchbase.flex_frame.frame.dcp_stream_id", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_flex_frame_impersonated_user, {"Impersonated User", "couchbase.flex_frame.frame.impersonated_user", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

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
    { &hf_subdoc_flags, { "Subdoc flags", "couchbase.extras.subdoc.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL} },
    { &hf_subdoc_flags_mkdirp, { "MKDIR_P", "couchbase.extras.subdoc.flags.mkdir_p", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01, "Create non-existent intermediate paths", HFILL} },
    { &hf_subdoc_flags_xattrpath, { "XATTR_PATH", "couchbase.extras.subdoc.flags.xattr_path", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04, "If set path refers to extended attribute (XATTR)", HFILL} },
    { &hf_subdoc_flags_expandmacros, { "EXPAND_MACROS", "couchbase.extras.subdoc.flags.expand_macros", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10, "Expand macro values inside XATTRs", HFILL} },
    { &hf_subdoc_flags_reserved, {"Reserved fields", "couchbase.extras.subdoc.flags.reserved", FT_UINT8, BASE_HEX, NULL, 0xEA, "A reserved field", HFILL} },
    { &hf_subdoc_doc_flags, { "Subdoc Doc flags", "couchbase.extras.subdoc.doc_flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL} },
    { &hf_subdoc_doc_flags_mkdoc, { "MKDOC", "couchbase.extras.subdoc.doc_flags.mkdoc", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01, "Create document if it does not exist, implies mkdir_p", HFILL} },
    { &hf_subdoc_doc_flags_add, { "ADD", "couchbase.extras.subdoc.doc_flags.add", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02, "Fail if doc already exists", HFILL} },
    { &hf_subdoc_doc_flags_accessdeleted, { "ACCESS_DELETED", "couchbase.extras.subdoc.doc_flags.access_deleted", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04, "Allow access to XATTRs for deleted documents", HFILL} },
    { &hf_subdoc_doc_flags_createasdeleted, { "CREATE_AS_DELETED", "couchbase.extras.subdoc.doc_flags.create_as_deleted", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08, "If the document does not exist then create it in the Deleted state, instead of the normal Alive state", HFILL} },
    { &hf_subdoc_doc_flags_reserved, {"Reserved fields", "couchbase.extras.subdoc.doc_flags.reserved", FT_UINT8, BASE_HEX, NULL, 0xF0, "A reserved field", HFILL} },
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
    { &hf_extras_flags_dcp_include_xattrs, {"Include XATTRs", "couchbase.extras.flags.dcp_include_xattrs", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x04, "Indicates the server should include documents XATTRs", HFILL} },
    { &hf_extras_flags_dcp_no_value, {"No Value", "couchbase.extras.flags.dcp_no_value", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x08, "Indicates the server should strip off values", HFILL} },
    { &hf_extras_flags_dcp_collections, {"Enable Collections", "couchbase.extras.flags.dcp_collections", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x10, "Indicates the server should stream collections", HFILL} },
    { &hf_extras_flags_dcp_include_delete_times, {"Include Delete Times", "couchbase.extras.flags.dcp_include_delete_times", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x20, "Indicates the server should include delete timestamps", HFILL} },
    { &hf_extras_flags_dcp_oso_snapshot_begin, {"OSO Begin", "couchbase.extras.flags.dcp_oso_snapshot_begin", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x1, "The start of an OSO snapshot", HFILL} },
    { &hf_extras_flags_dcp_oso_snapshot_end, {"OSO End", "couchbase.extras.flags.dcp_oso_snapshot_end", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x2, "The end of an OSO snapshot", HFILL} },

    { &hf_extras_seqno, { "Sequence number", "couchbase.extras.seqno", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_mutation_seqno, { "Mutation Sequence Number", "couchbase.extras.mutation_seqno", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_opaque, { "Opaque (vBucket identifier)", "couchbase.extras.opaque", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_reserved, { "Reserved", "couchbase.extras.reserved", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_start_seqno, { "Start Sequence Number", "couchbase.extras.start_seqno", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_end_seqno, { "End Sequence Number", "couchbase.extras.end_seqno", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_high_completed_seqno, { "High Completed Sequence Number", "couchbase.extras.high_completed_seqno", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_max_visible_seqno, { "Max Visible Seqno", "couchbase.extras.max_visible_seqno", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_marker_version, { "Snapshot Marker Version", "couchbase.extras.marker_version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_vbucket_uuid, { "VBucket UUID", "couchbase.extras.vbucket_uuid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_snap_start_seqno, { "Snapshot Start Sequence Number", "couchbase.extras.snap_start_seqno", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_snap_end_seqno, { "Snapshot End Sequence Number", "couchbase.extras.snap_start_seqno", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_by_seqno, { "by_seqno", "couchbase.extras.by_seqno", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_prepared_seqno, { "by_seqno (prepared)", "couchbase.extras.by_seqno_prepared", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_commit_seqno, { "by_seqno (commit)", "couchbase.extras.by_seqno_commit", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_abort_seqno, { "by_seqno (abort)", "couchbase.extras.by_seqno_abort", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_rev_seqno, { "rev_seqno", "couchbase.extras.rev_seqno", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_lock_time, { "lock_time", "couchbase.extras.lock_time", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_nmeta, { "nmeta", "couchbase.extras.nmeta", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_nru, { "nru", "couchbase.extras.nru", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_deleted, { "deleted", "couchbase.extras.deleted", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_bytes_to_ack, { "bytes_to_ack", "couchbase.extras.bytes_to_ack", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_delete_time, { "delete_time", "couchbase.extras.delete_time", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_delete_unused, { "unused", "couchbase.extras.delete_unused", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_system_event_id, { "system_event_id", "couchbase.extras.system_event_id", FT_UINT32, BASE_DEC, VALS(dcp_system_event_id_vals), 0x0, NULL, HFILL } },
    { &hf_extras_system_event_version, { "system_event_version", "couchbase.extras.system_event_version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_dcp_oso_snapshot_flags, { "OSO snapshot flags", "couchbase.extras.dcp_oso_snapshot_flags", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_failover_log, { "Failover Log", "couchbase.dcp.failover_log", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_failover_log_size, { "Size", "couchbase.dcp.failover_log.size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_failover_log_vbucket_uuid, { "VBucket UUID", "couchbase.dcp.failover_log.vbucket_uuid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_failover_log_vbucket_seqno, { "Sequence Number", "couchbase.dcp.failover_log.seqno", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_vbucket_states, { "VBucket States", "couchbase.vbucket_states", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_vbucket_states_state, { "State", "couchbase.vbucket_states.state", FT_UINT32, BASE_HEX, VALS(vbucket_states_vals), 0x0, NULL, HFILL } },
    { &hf_vbucket_states_size, { "Size", "couchbase.vbucket_states.size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_vbucket_states_id, { "VBucket", "couchbase.vbucket_states.id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_vbucket_states_seqno, { "Sequence Number", "couchbase.vbucket_states.seqno", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_extras_expiration, { "Expiration", "couchbase.extras.expiration", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_delta, { "Amount to Add", "couchbase.extras.delta", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_initial, { "Initial Value", "couchbase.extras.initial", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_extras_unknown, { "Unknown", "couchbase.extras.unknown", FT_BYTES, BASE_NONE, NULL, 0x0, "Unknown Extras", HFILL } },
    { &hf_key, { "Key", "couchbase.key", FT_STRING, BASE_NONE, NULL, 0x0, "If this is a collection stream, the key is formed of a leb128 prefix and then the key", HFILL } },
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
    { &hf_observe_last_persisted_seqno, { "Last persisted sequence number", "couchbase.observe.last_persisted_seqno", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_observe_current_seqno, { "Current sequence number", "couchbase.observe.current_seqno", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_observe_old_vbucket_uuid, { "Old VBucket UUID", "couchbase.observe.old_vbucket_uuid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_observe_last_received_seqno, { "Last received sequence number", "couchbase.observe.last_received_seqno", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_observe_failed_over, { "Failed over", "couchbase.observe.failed_over", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_get_errmap_version, {"Version", "couchbase.geterrmap.version", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL} },

    { &hf_multipath_opcode, { "Opcode", "couchbase.multipath.opcode", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &opcode_vals_ext, 0x0, "Command code", HFILL } },
    { &hf_multipath_index, { "Index", "couchbase.multipath.index", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_multipath_pathlen, { "Path Length", "couchbase.multipath.path.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_multipath_path, { "Path", "couchbase.multipath.path", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_multipath_valuelen, { "Value Length", "couchbase.multipath.value.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_multipath_value, { "Value", "couchbase.multipath.value", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },

    { &hf_meta_flags, {"Flags", "couchbase.extras.flags", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL} },
    { &hf_meta_expiration, {"Expiration", "couchbase.extras.expiration", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL} },
    { &hf_meta_revseqno, {"RevSeqno", "couchbase.extras.revseqno", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL} },
    { &hf_meta_cas, {"CAS", "couchbase.extras.cas", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL} },
    { &hf_meta_options, {"Options", "couchbase.extras.options", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL} },
    { &hf_force_meta, {"FORCE_WITH_META_OP", "couchbase.extras.options.force_with_meta_op", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x01, NULL, HFILL} },
    { &hf_force_accept, {"FORCE_ACCEPT_WITH_META_OPS", "couchbase.extras.options.force_accept_with_meta_ops", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x02, NULL, HFILL} },
    { &hf_regenerate_cas, {"REGENERATE_CAS", "couchbase.extras.option.regenerate_cas", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x04, NULL, HFILL} },
    { &hf_skip_conflict, {"SKIP_CONFLICT_RESOLUTION", "couchbase.extras.options.skip_conflict_resolution", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x08, NULL, HFILL} },
    { &hf_is_expiration, {"IS_EXPIRATION", "couchbase.extras.options.is_expiration", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x10, NULL, HFILL} },
    { &hf_metalen, {"Meta Length", "couchbase.extras.meta_length", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL} },
    { &hf_meta_reqextmeta, {"ReqExtMeta", "couchbase.extras.reqextmeta", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL} },
    { &hf_meta_deleted, {"Deleted", "couchbase.extras.deleted", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL} },
    { &hf_exptime, {"Expiry", "couchbase.extras.expiry", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL} },
    { &hf_extras_meta_seqno, {"Seqno", "couchbase.extras.meta.seqno", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL} },
    { &hf_confres, {"ConfRes", "couchbase.extras.confres", FT_UINT8, BASE_HEX, NULL, 0x0, "Conflict Resolution Mode", HFILL} },

    { &hf_bucket_type, {"Bucket Type", "couchbase.bucket.type", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_bucket_config, {"Bucket Config", "couchbase.bucket.config", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_config_key, {"Key", "couchbase.bucket.config.key", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_config_value, {"Value", "couchbase.bucket.config.value", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_hello_features, {"Hello Features", "couchbase.hello.features", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_hello_features_feature, {"Feature", "couchbase.hello.features.feature", FT_UINT16, BASE_HEX, VALS(feature_vals), 0x0, NULL, HFILL} },

    { &hf_xattrs, { "XATTRs", "couchbase.xattrs", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_xattr_length, {  "XATTR Length", "couchbase.xattrs.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL} },
    { &hf_xattr_pair_length, { "XATTR Pair Length", "couchbase.xattrs.pair.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL} },
    { &hf_xattr_key, { "Key", "couchbase.xattrs.pair.key", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_xattr_value, { "Value", "couchbase.xattrs.pair.value", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },
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
    { &ef_note_status_code, { "couchbase.note.status_code", PI_RESPONSE_CODE, PI_NOTE, "Status", EXPFILL }},
    { &ef_separator_not_found, { "couchbase.warn.separator_not_found", PI_UNDECODED, PI_WARN, "Separator not found", EXPFILL }},
    { &ef_illegal_value, { "couchbase.warn.illegal_value", PI_UNDECODED, PI_WARN, "Illegal value for command", EXPFILL }},
    { &ef_compression_error, { "couchbase.error.compression", PI_UNDECODED, PI_WARN, "Compression error", EXPFILL }},
    { &ef_warn_unknown_flex_unsupported, { "couchbase.warn.unsupported_flexible_frame", PI_UNDECODED, PI_WARN, "Flexible Response ID warning", EXPFILL }},
    { &ef_warn_unknown_flex_id, { "couchbase.warn.unknown_flexible_frame_id", PI_UNDECODED, PI_WARN, "Flexible Response ID warning", EXPFILL }},
    { &ef_warn_unknown_flex_len, { "couchbase.warn.unknown_flexible_frame_len", PI_UNDECODED, PI_WARN, "Flexible Response ID warning", EXPFILL }}
  };

  static gint *ett[] = {
    &ett_couchbase,
    &ett_extras,
    &ett_flex_frame_extras,
    &ett_extras_flags,
    &ett_observe,
    &ett_failover_log,
    &ett_vbucket_states,
    &ett_multipath,
    &ett_config,
    &ett_config_key,
    &ett_hello_features,
    &ett_datatype,
    &ett_xattrs,
    &ett_xattr_pair,
    &ett_collection_key
  };

  module_t *couchbase_module;
  expert_module_t* expert_couchbase;

  proto_couchbase = proto_register_protocol(PNAME, PSNAME, PFNAME);

  proto_register_field_array(proto_couchbase, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  expert_couchbase = expert_register_protocol(proto_couchbase);
  expert_register_field_array(expert_couchbase, ei, array_length(ei));

  /* Register our configuration options */
  couchbase_module = prefs_register_protocol(proto_couchbase, &proto_reg_handoff_couchbase);

  couchbase_handle = register_dissector("couchbase", dissect_couchbase_tcp, proto_couchbase);

  prefs_register_bool_preference(couchbase_module, "desegment_pdus",
                                 "Reassemble PDUs spanning multiple TCP segments",
                                 "Whether the memcache dissector should reassemble PDUs"
                                 " spanning multiple TCP segments."
                                 " To use this option, you must also enable \"Allow subdissectors"
                                 " to reassemble TCP streams\" in the TCP protocol settings.",
                                 &couchbase_desegment_body);

  prefs_register_uint_preference(couchbase_module, "tls.port", "SSL/TLS Data Port",
                                 "The port used for communicating with the data service via SSL/TLS",
                                 10, &couchbase_ssl_port_pref);
  prefs_register_obsolete_preference(couchbase_module, "ssl_port");


}

/* Register the tcp couchbase dissector. */
void
proto_reg_handoff_couchbase(void)
{
  static gboolean initialized = FALSE;

  if (!initialized){
    json_handle = find_dissector_add_dependency("json", proto_couchbase);
    dissector_add_uint_range_with_preference("tcp.port", COUCHBASE_DEFAULT_PORT, couchbase_handle);
    initialized = TRUE;
  } else {
    ssl_dissector_delete(couchbase_ssl_port, couchbase_handle);
  }
  couchbase_ssl_port = couchbase_ssl_port_pref;
  ssl_dissector_add(couchbase_ssl_port, couchbase_handle);
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
