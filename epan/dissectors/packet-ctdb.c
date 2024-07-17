/* packet-ctdb.c
 * Routines for CTDB (Cluster TDB) dissection
 * Copyright 2007, Ronnie Sahlberg
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
void proto_register_ctdb(void);
void proto_reg_handoff_ctdb(void);

static dissector_handle_t ctdb_handle;

/* Initialize the protocol and registered fields */
static int proto_ctdb;
static int hf_ctdb_length;
static int hf_ctdb_opcode;
static int hf_ctdb_magic;
static int hf_ctdb_version;
static int hf_ctdb_dst;
static int hf_ctdb_src;
static int hf_ctdb_id;
static int hf_ctdb_flags_immediate;
static int hf_ctdb_dbid;
static int hf_ctdb_callid;
static int hf_ctdb_status;
static int hf_ctdb_keylen;
static int hf_ctdb_datalen;
static int hf_ctdb_errorlen;
static int hf_ctdb_key;
static int hf_ctdb_keyhash;
static int hf_ctdb_data;
static int hf_ctdb_error;
static int hf_ctdb_dmaster;
static int hf_ctdb_request_in;
static int hf_ctdb_response_in;
static int hf_ctdb_time;
static int hf_ctdb_generation;
static int hf_ctdb_hopcount;
static int hf_ctdb_rsn;
static int hf_ctdb_ctrl_opcode;
static int hf_ctdb_srvid;
static int hf_ctdb_clientid;
static int hf_ctdb_ctrl_flags;
static int hf_ctdb_recmaster;
static int hf_ctdb_recmode;
static int hf_ctdb_num_nodes;
static int hf_ctdb_vnn;
static int hf_ctdb_node_flags;
static int hf_ctdb_node_ip;
static int hf_ctdb_pid;
static int hf_ctdb_process_exists;

/* Initialize the subtree pointers */
static int ett_ctdb;
static int ett_ctdb_key;

static expert_field ei_ctdb_too_many_nodes;

/* this tree keeps track of caller/reqid for ctdb transactions */
static wmem_tree_t *ctdb_transactions;
typedef struct _ctdb_trans_t {
	uint32_t key_hash;
	uint32_t request_in;
	uint32_t response_in;
	nstime_t req_time;
} ctdb_trans_t;

/* this tree keeps track of CONTROL request/responses */
static wmem_tree_t *ctdb_controls;
typedef struct _ctdb_control_t {
	uint32_t opcode;
	uint32_t request_in;
	uint32_t response_in;
	nstime_t req_time;
} ctdb_control_t;

#define CTDB_REQ_CALL			0
#define CTDB_REPLY_CALL			1
#define CTDB_REQ_DMASTER		2
#define CTDB_REPLY_DMASTER		3
#define CTDB_REPLY_ERROR		4
#define CTDB_REQ_MESSAGE		5
#define CTDB_REQ_CONTROL		7
#define CTDB_REPLY_CONTROL		8
#define CTDB_REQ_KEEPALIVE		9
static const value_string ctdb_opcodes[] = {
	{CTDB_REQ_CALL,			"REQ_CALL"},
	{CTDB_REPLY_CALL,		"REPLY_CALL"},
	{CTDB_REQ_DMASTER,		"REQ_DMASTER"},
	{CTDB_REPLY_DMASTER,		"REPLY_DMASTER"},
	{CTDB_REPLY_ERROR,		"REPLY_ERROR"},
	{CTDB_REQ_MESSAGE,		"REQ_MESSAGE"},
	{CTDB_REQ_CONTROL,		"REQ_CONTROL"},
	{CTDB_REPLY_CONTROL,		"REPLY_CONTROL"},
	{CTDB_REQ_KEEPALIVE,		"REQ_KEEPALIVE"},
	{0,NULL}
};


#define CTDB_CONTROL_PROCESS_EXISTS		0
#define CTDB_CONTROL_STATISTICS			1
/* note: #2 removed upstream */
#define CTDB_CONTROL_CONFIG			2
#define CTDB_CONTROL_PING			3
#define CTDB_CONTROL_GETDBPATH			4
#define CTDB_CONTROL_GETVNNMAP			5
#define CTDB_CONTROL_SETVNNMAP			6
#define CTDB_CONTROL_GET_DEBUG			7
#define CTDB_CONTROL_SET_DEBUG			8
#define CTDB_CONTROL_GET_DBMAP			9
#define CTDB_CONTROL_GET_NODEMAPv4		10 /* obsolete */
#define CTDB_CONTROL_SET_DMASTER		11 /* obsolete */
/* note: #12 removed upstream */
#define CTDB_CONTROL_CLEAR_DB			12
#define CTDB_CONTROL_PULL_DB			13
#define CTDB_CONTROL_PUSH_DB			14
#define CTDB_CONTROL_GET_RECMODE		15
#define CTDB_CONTROL_SET_RECMODE		16
#define CTDB_CONTROL_STATISTICS_RESET		17
#define CTDB_CONTROL_DB_ATTACH			18
#define CTDB_CONTROL_SET_CALL			19 /* obsolete */
#define CTDB_CONTROL_TRAVERSE_START		20
#define CTDB_CONTROL_TRAVERSE_ALL		21
#define CTDB_CONTROL_TRAVERSE_DATA		22
#define CTDB_CONTROL_REGISTER_SRVID		23
#define CTDB_CONTROL_DEREGISTER_SRVID		24
#define CTDB_CONTROL_GET_DBNAME			25
#define CTDB_CONTROL_ENABLE_SEQNUM		26
#define CTDB_CONTROL_UPDATE_SEQNUM		27
/* note: #28 removed upstream */
#define CTDB_CONTROL_SET_SEQNUM_FREQUENCY	28
#define CTDB_CONTROL_DUMP_MEMORY		29
#define CTDB_CONTROL_GET_PID			30
#define CTDB_CONTROL_GET_RECMASTER		31
#define CTDB_CONTROL_SET_RECMASTER		32
#define CTDB_CONTROL_FREEZE			33
#define CTDB_CONTROL_THAW			34 /* obsolete */
#define CTDB_CONTROL_GET_PNN			35
#define CTDB_CONTROL_SHUTDOWN			36
#define CTDB_CONTROL_GET_MONMODE		37
/* note: #38, #39, #40 and #41 removed upstream */
#define CTDB_CONTROL_SET_MONMODE		38
#define CTDB_CONTROL_MAX_RSN			39
#define CTDB_CONTROL_SET_RSN_NONEMPTY		40
#define CTDB_CONTROL_DELETE_LOW_RSN		41
#define CTDB_CONTROL_TAKEOVER_IPv4		42 /* obsolete */
#define CTDB_CONTROL_RELEASE_IPv4		43 /* obsolete */
#define CTDB_CONTROL_TCP_CLIENT			44
#define CTDB_CONTROL_TCP_ADD			45
#define CTDB_CONTROL_TCP_REMOVE			46
#define CTDB_CONTROL_STARTUP			47
#define CTDB_CONTROL_SET_TUNABLE		48
#define CTDB_CONTROL_GET_TUNABLE		49
#define CTDB_CONTROL_LIST_TUNABLES		50
#define CTDB_CONTROL_GET_PUBLIC_IPSv4		51 /* obsolete */
#define CTDB_CONTROL_MODIFY_FLAGS		52
#define CTDB_CONTROL_GET_ALL_TUNABLES		53
#define CTDB_CONTROL_KILL_TCP			54 /* obsolete */
#define CTDB_CONTROL_GET_TCP_TICKLE_LIST	55
#define CTDB_CONTROL_SET_TCP_TICKLE_LIST	56
#define CTDB_CONTROL_REGISTER_SERVER_ID		57 /* obsolete */
#define CTDB_CONTROL_UNREGISTER_SERVER_ID	58 /* obsolete */
#define CTDB_CONTROL_CHECK_SERVER_ID		59 /* obsolete */
#define CTDB_CONTROL_GET_SERVER_ID_LIST		60 /* obsolete */
#define CTDB_CONTROL_DB_ATTACH_PERSISTENT	61
#define CTDB_CONTROL_PERSISTENT_STORE		62 /* obsolete */
#define CTDB_CONTROL_UPDATE_RECORD         	63
#define CTDB_CONTROL_SEND_GRATUITOUS_ARP	64
#define CTDB_CONTROL_TRANSACTION_START		65 /* obsolete */
#define CTDB_CONTROL_TRANSACTION_COMMIT		66 /* obsolete */
#define CTDB_CONTROL_WIPE_DATABASE		67
/* #68 removed */
#define CTDB_CONTROL_UPTIME			69
#define CTDB_CONTROL_START_RECOVERY		70
#define CTDB_CONTROL_END_RECOVERY		71
#define CTDB_CONTROL_RELOAD_NODES_FILE		72
/* #73 removed */
#define CTDB_CONTROL_TRY_DELETE_RECORDS		74
#define CTDB_CONTROL_ENABLE_MONITOR		75
#define CTDB_CONTROL_DISABLE_MONITOR		76
#define CTDB_CONTROL_ADD_PUBLIC_IP		77
#define CTDB_CONTROL_DEL_PUBLIC_IP		78
#define CTDB_CONTROL_RUN_EVENTSCRIPTS		79 /* obsolete */
#define CTDB_CONTROL_GET_CAPABILITIES		80
#define CTDB_CONTROL_START_PERSISTENT_UPDATE	81 /* obsolete */
#define CTDB_CONTROL_CANCEL_PERSISTENT_UPDATE	82 /* obsolete */
#define CTDB_CONTROL_TRANS2_COMMIT		83 /* obsolete */
#define CTDB_CONTROL_TRANS2_FINISHED		84 /* obsolete */
#define CTDB_CONTROL_TRANS2_ERROR		85 /* obsolete */
#define CTDB_CONTROL_TRANS2_COMMIT_RETRY	86 /* obsolete */
#define CTDB_CONTROL_RECD_PING			87
#define CTDB_CONTROL_RELEASE_IP			88
#define CTDB_CONTROL_TAKEOVER_IP		89
#define CTDB_CONTROL_GET_PUBLIC_IPS		90
#define CTDB_CONTROL_GET_NODEMAP		91
/* missing */
#define CTDB_CONTROL_GET_EVENT_SCRIPT_STATUS	96 /* obsolete */
#define CTDB_CONTROL_TRAVERSE_KILL		97
#define CTDB_CONTROL_RECD_RECLOCK_LATENCY	98
#define CTDB_CONTROL_GET_RECLOCK_FILE		99
#define CTDB_CONTROL_SET_RECLOCK_FILE		100 /* obsolete */
#define CTDB_CONTROL_STOP_NODE			101
#define CTDB_CONTROL_CONTINUE_NODE		102
#define CTDB_CONTROL_SET_NATGWSTATE		103 /* obsolete */
#define CTDB_CONTROL_SET_LMASTERROLE		104
#define CTDB_CONTROL_SET_RECMASTERROLE		105
#define CTDB_CONTROL_ENABLE_SCRIPT		107 /* obsolete */
#define CTDB_CONTROL_DISABLE_SCRIPT		108 /* obsolete */
#define CTDB_CONTROL_SET_BAN_STATE		109
#define CTDB_CONTROL_GET_BAN_STATE		110
#define CTDB_CONTROL_SET_DB_PRIORITY		111 /* obsolete */
#define CTDB_CONTROL_GET_DB_PRIORITY		112 /* obsolete */
#define CTDB_CONTROL_TRANSACTION_CANCEL		113 /* obsolete */
#define CTDB_CONTROL_REGISTER_NOTIFY		114
#define CTDB_CONTROL_DEREGISTER_NOTIFY		115
#define CTDB_CONTROL_TRANS2_ACTIVE		116 /* obsolete */
#define CTDB_CONTROL_GET_LOG			117 /* obsolete */
#define CTDB_CONTROL_CLEAR_LOG			118 /* obsolete */
#define CTDB_CONTROL_TRANS3_COMMIT		119
#define CTDB_CONTROL_GET_DB_SEQNUM		120
#define CTDB_CONTROL_DB_SET_HEALTHY		121
#define CTDB_CONTROL_DB_GET_HEALTH		122
#define CTDB_CONTROL_GET_PUBLIC_IP_INFO		123
#define CTDB_CONTROL_GET_IFACES			124
#define CTDB_CONTROL_SET_IFACE_LINK_STATE	125
#define CTDB_CONTROL_TCP_ADD_DELAYED_UPDATE	126
#define CTDB_CONTROL_GET_STAT_HISTORY		127
#define CTDB_CONTROL_SCHEDULE_FOR_DELETION	128
#define CTDB_CONTROL_SET_DB_READONLY		129
#define CTDB_CONTROL_CHECK_SRVIDS		130
#define CTDB_CONTROL_TRAVERSE_START_EXT		131
#define CTDB_CONTROL_GET_DB_STATISTICS		132
#define CTDB_CONTROL_SET_DB_STICKY		133
#define CTDB_CONTROL_RELOAD_PUBLIC_IPS		134
#define CTDB_CONTROL_TRAVERSE_ALL_EXT		135
#define CTDB_CONTROL_RECEIVE_RECORDS		136
#define CTDB_CONTROL_IPREALLOCATED		137
#define CTDB_CONTROL_GET_RUNSTATE		138
#define CTDB_CONTROL_DB_DETACH			139
#define CTDB_CONTROL_GET_NODES_FILE		140
#define CTDB_CONTROL_DB_FREEZE			141
#define CTDB_CONTROL_DB_THAW			142
#define CTDB_CONTROL_DB_TRANSACTION_START	143
#define CTDB_CONTROL_DB_TRANSACTION_COMMIT	144
#define CTDB_CONTROL_DB_TRANSACTION_CANCEL	145
#define CTDB_CONTROL_DB_PULL			146
#define CTDB_CONTROL_DB_PUSH_START		147
#define CTDB_CONTROL_DB_PUSH_CONFIRM		148


static const value_string ctrl_opcode_vals[] = {
	{CTDB_CONTROL_PROCESS_EXISTS,	"PROCESS_EXISTS"},
	{CTDB_CONTROL_STATISTICS,	"STATISTICS"},
	{CTDB_CONTROL_CONFIG,		"CONFIG"},
	{CTDB_CONTROL_PING,		"PING"},
	{CTDB_CONTROL_GETDBPATH,	"GETDBPATH"},
	{CTDB_CONTROL_GETVNNMAP,	"GETVNNMAP"},
	{CTDB_CONTROL_SETVNNMAP,	"SETVNNMAP"},
	{CTDB_CONTROL_GET_DEBUG,	"GET_DEBUG"},
	{CTDB_CONTROL_SET_DEBUG,	"SET_DEBUG"},
	{CTDB_CONTROL_GET_DBMAP,	"GET_DBMAP"},
	{CTDB_CONTROL_GET_NODEMAPv4,	"GET_NODEMAPv4"},
	{CTDB_CONTROL_SET_DMASTER,	"SET_DMASTER"},
	{CTDB_CONTROL_CLEAR_DB,		"CLEAR_DB"},
	{CTDB_CONTROL_PULL_DB,		"PULL_DB"},
	{CTDB_CONTROL_PUSH_DB,		"PUSH_DB"},
	{CTDB_CONTROL_GET_RECMODE,	"GET_RECMODE"},
	{CTDB_CONTROL_SET_RECMODE,	"SET_RECMODE"},
	{CTDB_CONTROL_STATISTICS_RESET,	"STATISTICS_RESET"},
	{CTDB_CONTROL_DB_ATTACH,	"DB_ATTACH"},
	{CTDB_CONTROL_SET_CALL,		"SET_CALL"},
	{CTDB_CONTROL_TRAVERSE_START,	"TRAVERSE_START"},
	{CTDB_CONTROL_TRAVERSE_ALL,	"TRAVERSE_ALL"},
	{CTDB_CONTROL_TRAVERSE_DATA,	"TRAVERSE_DATA"},
	{CTDB_CONTROL_REGISTER_SRVID,	"REGISTER_SRVID"},
	{CTDB_CONTROL_DEREGISTER_SRVID,	"DEREGISTER_SRVID"},
	{CTDB_CONTROL_GET_DBNAME,	"GET_DBNAME"},
	{CTDB_CONTROL_ENABLE_SEQNUM,	"ENABLE_SEQNUM"},
	{CTDB_CONTROL_UPDATE_SEQNUM,	"UPDATE_SEQNUM"},
	{CTDB_CONTROL_SET_SEQNUM_FREQUENCY,	"SET_SEQNUM_FREQUENCY"},
	{CTDB_CONTROL_DUMP_MEMORY,	"DUMP_MEMORY"},
	{CTDB_CONTROL_GET_PID,		"GET_PID"},
	{CTDB_CONTROL_GET_RECMASTER,	"GET_RECMASTER"},
	{CTDB_CONTROL_SET_RECMASTER,	"SET_RECMASTER"},
	{CTDB_CONTROL_FREEZE,		"FREEZE"},
	{CTDB_CONTROL_THAW,		"THAW"},
	{CTDB_CONTROL_GET_PNN,		"GET_PNN"},
	{CTDB_CONTROL_SHUTDOWN,		"SHUTDOWN"},
	{CTDB_CONTROL_GET_MONMODE,	"GET_MONMODE"},
	{CTDB_CONTROL_SET_MONMODE,	"SET_MONMODE"},
	{CTDB_CONTROL_MAX_RSN,		"MAX_RSN"},
	{CTDB_CONTROL_SET_RSN_NONEMPTY,	"SET_RSN_NONEMPTY"},
	{CTDB_CONTROL_DELETE_LOW_RSN,	"DELETE_LOW_RSN"},
	{CTDB_CONTROL_TAKEOVER_IPv4,	"TAKEOVER_IPv4"},
	{CTDB_CONTROL_RELEASE_IPv4,	"RELEASE_IPv4"},
	{CTDB_CONTROL_TCP_CLIENT,	"TCP_CLIENT"},
	{CTDB_CONTROL_TCP_ADD,		"TCP_ADD"},
	{CTDB_CONTROL_TCP_REMOVE,	"TCP_REMOVE"},
	{CTDB_CONTROL_STARTUP,		"STARTUP"},
	{CTDB_CONTROL_SET_TUNABLE,	"SET_TUNABLE"},
	{CTDB_CONTROL_GET_TUNABLE,	"GET_TUNABLE"},
	{CTDB_CONTROL_LIST_TUNABLES,	"LIST_TUNABLES"},
	{CTDB_CONTROL_GET_PUBLIC_IPSv4,	"GET_PUBLIC_IPSv4"},
	{CTDB_CONTROL_MODIFY_FLAGS,	"MODIFY_FLAGS"},
	{CTDB_CONTROL_GET_ALL_TUNABLES,	"GET_ALL_TUNABLES"},
	{CTDB_CONTROL_KILL_TCP,		"KILL_TCP"},
	{CTDB_CONTROL_GET_TCP_TICKLE_LIST,	"GET_TCP_TICKLE_LIST"},
	{CTDB_CONTROL_SET_TCP_TICKLE_LIST,	"SET_TCP_TICKLE_LIST"},
	{CTDB_CONTROL_REGISTER_SERVER_ID,	"REGISTER_SERVER_ID"},
	{CTDB_CONTROL_UNREGISTER_SERVER_ID,	"UNREGISTER_SERVER_ID"},
	{CTDB_CONTROL_CHECK_SERVER_ID,		"CHECK_SERVER_ID"},
	{CTDB_CONTROL_GET_SERVER_ID_LIST,	"GET_SERVER_ID_LIST"},
	{CTDB_CONTROL_DB_ATTACH_PERSISTENT,	"DB_ATTACH_PERSISTENT"},
	{CTDB_CONTROL_PERSISTENT_STORE,		"PERSISTENT_STORE"},
	{CTDB_CONTROL_UPDATE_RECORD,		"UPDATE_RECORD"},
	{CTDB_CONTROL_SEND_GRATUITOUS_ARP,	"SEND_GRATUITOUS_ARP"},
	{CTDB_CONTROL_TRANSACTION_START,	"TRANSACTION_START"},
	{CTDB_CONTROL_TRANSACTION_COMMIT,	"TRANSACTION_COMMIT"},
	{CTDB_CONTROL_WIPE_DATABASE,		"WIPE_DATABASE"},
	{CTDB_CONTROL_UPTIME,			"UPTIME"},
	{CTDB_CONTROL_START_RECOVERY,		"START_RECOVERY"},
	{CTDB_CONTROL_END_RECOVERY,		"END_RECOVERY"},
	{CTDB_CONTROL_RELOAD_NODES_FILE,	"RELOAD_NODES_FILE"},
	{CTDB_CONTROL_TRY_DELETE_RECORDS,	"TRY_DELETE_RECORDS"},
	{CTDB_CONTROL_ENABLE_MONITOR,		"ENABLE_MONITOR"},
	{CTDB_CONTROL_DISABLE_MONITOR,		"DISABLE_MONITOR"},
	{CTDB_CONTROL_ADD_PUBLIC_IP,		"ADD_PUBLIC_IP"},
	{CTDB_CONTROL_DEL_PUBLIC_IP,		"DEL_PUBLIC_IP"},
	{CTDB_CONTROL_RUN_EVENTSCRIPTS,		"RUN_EVENTSCRIPTS"},
	{CTDB_CONTROL_GET_CAPABILITIES,		"GET_CAPABILITIES"},
	{CTDB_CONTROL_START_PERSISTENT_UPDATE,	"START_PERSISTENT_UPDATE"},
	{CTDB_CONTROL_CANCEL_PERSISTENT_UPDATE,	"CANCEL_PERSISTENT_UPDATE"},
	{CTDB_CONTROL_TRANS2_COMMIT,		"TRANS2_COMMIT"},
	{CTDB_CONTROL_TRANS2_FINISHED,		"TRANS2_FINISHED"},
	{CTDB_CONTROL_TRANS2_ERROR,		"TRANS2_ERROR"},
	{CTDB_CONTROL_TRANS2_COMMIT_RETRY,	"TRANS2_COMMIT_RETRY"},
	{CTDB_CONTROL_RECD_PING,		"RECD_PING"},
	{CTDB_CONTROL_RELEASE_IP,		"RELEASE_IP"},
	{CTDB_CONTROL_TAKEOVER_IP,		"TAKEOVER_IP"},
	{CTDB_CONTROL_GET_PUBLIC_IPS,		"GET_PUBLIC_IPS"},
	{CTDB_CONTROL_GET_NODEMAP,		"GET_NODEMAP"},
	{CTDB_CONTROL_GET_EVENT_SCRIPT_STATUS,	"GET_EVENT_SCRIPT_STATUS"},
	{CTDB_CONTROL_TRAVERSE_KILL,		"TRAVERSE_KILL"},
	{CTDB_CONTROL_RECD_RECLOCK_LATENCY,	"RECD_RECLOCK_LATENCY"},
	{CTDB_CONTROL_GET_RECLOCK_FILE,		"GET_RECLOCK_FILE"},
	{CTDB_CONTROL_SET_RECLOCK_FILE,		"SET_RECLOCK_FILE"},
	{CTDB_CONTROL_STOP_NODE,		"STOP_NODE"},
	{CTDB_CONTROL_CONTINUE_NODE,		"CONTINUE_NODE"},
	{CTDB_CONTROL_SET_NATGWSTATE,		"SET_NATGWSTATE"},
	{CTDB_CONTROL_SET_LMASTERROLE,		"SET_LMASTERROLE"},
	{CTDB_CONTROL_SET_RECMASTERROLE,	"SET_RECMASTERROLE"},
	{CTDB_CONTROL_ENABLE_SCRIPT,		"ENABLE_SCRIPT"},
	{CTDB_CONTROL_DISABLE_SCRIPT,		"DISABLE_SCRIPT"},
	{CTDB_CONTROL_SET_BAN_STATE,		"SET_BAN_STATE"},
	{CTDB_CONTROL_GET_BAN_STATE,		"GET_BAN_STATE"},
	{CTDB_CONTROL_SET_DB_PRIORITY,		"SET_DB_PRIORITY"},
	{CTDB_CONTROL_GET_DB_PRIORITY,		"GET_DB_PRIORITY"},
	{CTDB_CONTROL_TRANSACTION_CANCEL,	"TRANSACTION_CANCEL"},
	{CTDB_CONTROL_REGISTER_NOTIFY,		"REGISTER_NOTIFY"},
	{CTDB_CONTROL_DEREGISTER_NOTIFY,	"DEREGISTER_NOTIFY"},
	{CTDB_CONTROL_TRANS2_ACTIVE,		"TRANS2_ACTIVE"},
	{CTDB_CONTROL_GET_LOG,			"GET_LOG"},
	{CTDB_CONTROL_CLEAR_LOG,		"CLEAR_LOG"},
	{CTDB_CONTROL_TRANS3_COMMIT,		"TRANS3_COMMIT"},
	{CTDB_CONTROL_GET_DB_SEQNUM,		"GET_DB_SEQNUM"},
	{CTDB_CONTROL_DB_SET_HEALTHY,		"DB_SET_HEALTHY"},
	{CTDB_CONTROL_DB_GET_HEALTH,		"DB_GET_HEALTH"},
	{CTDB_CONTROL_GET_PUBLIC_IP_INFO,	"GET_PUBLIC_IP_INFO"},
	{CTDB_CONTROL_GET_IFACES,		"GET_IFACES"},
	{CTDB_CONTROL_SET_IFACE_LINK_STATE,	"SET_IFACE_LINK_STATE"},
	{CTDB_CONTROL_TCP_ADD_DELAYED_UPDATE,	"TCP_ADD_DELAYED_UPDATE"},
	{CTDB_CONTROL_GET_STAT_HISTORY,		"GET_STAT_HISTORY"},
	{CTDB_CONTROL_SCHEDULE_FOR_DELETION,	"SCHEDULE_FOR_DELETION"},
	{CTDB_CONTROL_SET_DB_READONLY,		"SET_DB_READONLY"},
	{CTDB_CONTROL_CHECK_SRVIDS,		"CHECK_SRVIDS"},
	{CTDB_CONTROL_TRAVERSE_START_EXT,	"TRAVERSE_START_EXT"},
	{CTDB_CONTROL_GET_DB_STATISTICS,	"GET_DB_STATISTICS"},
	{CTDB_CONTROL_SET_DB_STICKY,		"SET_DB_STICKY"},
	{CTDB_CONTROL_RELOAD_PUBLIC_IPS,	"RELOAD_PUBLIC_IPS"},
	{CTDB_CONTROL_TRAVERSE_ALL_EXT,		"TRAVERSE_ALL_EXT"},
	{CTDB_CONTROL_RECEIVE_RECORDS,		"RECEIVE_RECORDS"},
	{CTDB_CONTROL_IPREALLOCATED,		"IPREALLOCATED"},
	{CTDB_CONTROL_GET_RUNSTATE,		"GET_RUNSTATE"},
	{CTDB_CONTROL_DB_DETACH,		"DB_DETACH"},
	{CTDB_CONTROL_GET_NODES_FILE,		"GET_NODES_FILE"},
	{CTDB_CONTROL_DB_FREEZE,		"DB_FREEZE"},
	{CTDB_CONTROL_DB_THAW,			"DB_THAW"},
	{CTDB_CONTROL_DB_TRANSACTION_START,	"DB_TRANSACTION_START"},
	{CTDB_CONTROL_DB_TRANSACTION_COMMIT,	"DB_TRANSACTION_COMMIT"},
	{CTDB_CONTROL_DB_TRANSACTION_CANCEL,	"DB_TRANSACTION_CANCEL"},
	{CTDB_CONTROL_DB_PULL,			"DB_PULL"},
	{CTDB_CONTROL_DB_PUSH_START,		"DB_PUSH_START"},
	{CTDB_CONTROL_DB_PUSH_CONFIRM,		"DB_PUSH_CONFIRM"},
	{0, NULL}
};



static int dissect_control_get_recmaster_reply(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, uint32_t status, int endianess _U_)
{
	proto_tree_add_uint(tree, hf_ctdb_recmaster, tvb, 0, 0, status);

	col_append_fstr(pinfo->cinfo, COL_INFO, " RecMaster:%d", status);

	return offset;
}

static const value_string recmode_vals[] = {
	{0, "NORMAL"},
	{1, "RECOVERY ACTIVE"},
	{0, NULL}
};

static int dissect_control_get_recmode_reply(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, uint32_t status, int endianess _U_)
{
	proto_tree_add_uint(tree, hf_ctdb_recmode, tvb, 0, 0, status);

	col_append_fstr(pinfo->cinfo, COL_INFO, " RecMode:%s",
		val_to_str(status, recmode_vals, "Unknown:%d"));

	return offset;
}

#define CTDB_MAX_NODES 500 /* Arbitrary. */
static int dissect_control_get_nodemap_reply(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, uint32_t status _U_, int endianess)
{
	uint32_t num_nodes;
	proto_item *item;

	/* num nodes */
	item = proto_tree_add_item(tree, hf_ctdb_num_nodes, tvb, offset, 4, endianess);
	if(endianess){
		num_nodes=tvb_get_letohl(tvb, offset);
	} else {
		num_nodes=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	if (num_nodes > CTDB_MAX_NODES) {
		expert_add_info_format(pinfo, item, &ei_ctdb_too_many_nodes, "Too many nodes (%u). Stopping dissection.", num_nodes);
		return offset;
	}

	while(num_nodes--){
		/* vnn */
		proto_tree_add_item(tree, hf_ctdb_vnn, tvb, offset, 4, endianess);
		offset+=4;

		/* node flags */
		proto_tree_add_item(tree, hf_ctdb_node_flags, tvb, offset, 4, endianess);
		offset+=4;

		/* here comes a sockaddr_in but we only store ipv4 addresses in it */
		proto_tree_add_item(tree, hf_ctdb_node_ip, tvb, offset+4, 4, ENC_BIG_ENDIAN);
		offset+=16;
	}

	return offset;
}

static int dissect_control_process_exist_request(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, uint32_t status _U_, int endianess)
{
	uint32_t pid;

	/* pid */
	proto_tree_add_item(tree, hf_ctdb_pid, tvb, offset, 4, endianess);
	if(endianess){
		pid=tvb_get_letohl(tvb, offset);
	} else {
		pid=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	col_append_fstr(pinfo->cinfo, COL_INFO, " pid:%d", pid);

	return offset;
}

static const true_false_string process_exists_tfs = {
	"Process does NOT exist",
	"Process Exists"
};

static int dissect_control_process_exist_reply(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, uint32_t status, int endianess _U_)
{
	proto_tree_add_boolean(tree, hf_ctdb_process_exists, tvb, offset, 4, status);
	return offset;
}

/* This defines the array of dissectors for request/reply controls */
typedef int (*control_dissector)(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, uint32_t status, int endianess);

typedef struct _control_dissector_array_t {
	uint32_t opcode;
	control_dissector request_dissector;
	control_dissector reply_dissector;
} control_dissector_array_t;

static control_dissector_array_t control_dissectors[] = {
	{CTDB_CONTROL_GET_RECMASTER,
		NULL,
		dissect_control_get_recmaster_reply},
	{CTDB_CONTROL_GET_RECMODE,
		NULL,
		dissect_control_get_recmode_reply},
	{CTDB_CONTROL_GET_NODEMAP,
		NULL,
		dissect_control_get_nodemap_reply},
	{CTDB_CONTROL_FREEZE,
		NULL,
		NULL},
	{CTDB_CONTROL_THAW,
		NULL,
		NULL},
	{CTDB_CONTROL_PROCESS_EXISTS,
		dissect_control_process_exist_request,
		dissect_control_process_exist_reply},

/*CTDB_CONTROL_STATISTICS*/
/*CTDB_CONTROL_CONFIG*/
/*CTDB_CONTROL_PING*/
/*CTDB_CONTROL_GETDBPATH*/
/*CTDB_CONTROL_GETVNNMAP*/
/*CTDB_CONTROL_SETVNNMAP*/
/*CTDB_CONTROL_GET_DEBUG*/
/*CTDB_CONTROL_SET_DEBUG*/
/*CTDB_CONTROL_GET_DBMAP*/
/*CTDB_CONTROL_SET_DMASTER*/
/*CTDB_CONTROL_CLEAR_DB*/
/*CTDB_CONTROL_PULL_DB*/
/*CTDB_CONTROL_PUSH_DB*/
/*CTDB_CONTROL_SET_RECMODE*/
/*CTDB_CONTROL_STATISTICS_RESET*/
/*CTDB_CONTROL_DB_ATTACH*/
/*CTDB_CONTROL_SET_CALL*/
/*CTDB_CONTROL_TRAVERSE_START*/
/*CTDB_CONTROL_TRAVERSE_ALL*/
/*CTDB_CONTROL_TRAVERSE_DATA*/
/*CTDB_CONTROL_REGISTER_SRVID*/
/*CTDB_CONTROL_DEREGISTER_SRVID*/
/*CTDB_CONTROL_GET_DBNAME*/
/*CTDB_CONTROL_ENABLE_SEQNUM*/
/*CTDB_CONTROL_UPDATE_SEQNUM*/
/*CTDB_CONTROL_SET_SEQNUM_FREQUENCY*/
/*CTDB_CONTROL_DUMP_MEMORY*/
/*CTDB_CONTROL_GET_PID*/
/*CTDB_CONTROL_SET_RECMASTER*/
/*CTDB_CONTROL_GET_VNN*/
/*CTDB_CONTROL_SHUTDOWN*/
/*CTDB_CONTROL_GET_MONMODE*/
/*CTDB_CONTROL_SET_MONMODE*/
/*CTDB_CONTROL_MAX_RSN*/
/*CTDB_CONTROL_SET_RSN_NONEMPTY*/
/*CTDB_CONTROL_DELETE_LOW_RSN*/
/*CTDB_CONTROL_TAKEOVER_IP*/
/*CTDB_CONTROL_RELEASE_IP*/
/*CTDB_CONTROL_TCP_CLIENT*/
/*CTDB_CONTROL_TCP_ADD*/
/*CTDB_CONTROL_TCP_REMOVE*/
/*CTDB_CONTROL_STARTUP*/
/*CTDB_CONTROL_SET_TUNABLE*/
/*CTDB_CONTROL_GET_TUNABLE*/
/*CTDB_CONTROL_LIST_TUNABLES*/
/*CTDB_CONTROL_GET_PUBLIC_IPS*/
/*CTDB_CONTROL_MODIFY_FLAGS*/
/*CTDB_CONTROL_GET_ALL_TUNABLES*/
/*CTDB_CONTROL_KILL_TCP*/
/*CTDB_CONTROL_GET_TCP_TICKLE_LIST*/
/*CTDB_CONTROL_SET_TCP_TICKLE_LIST*/
	{0, NULL, NULL}
};

static control_dissector find_control_dissector(uint32_t opcode, bool is_request)
{
	control_dissector_array_t *cd=control_dissectors;

	while(cd){
		if((!cd->opcode)&&(!cd->request_dissector)&&(!cd->reply_dissector)){
			break;
		}
		if(opcode==cd->opcode){
			if(is_request){
				return cd->request_dissector;
			} else {
				return cd->reply_dissector;
			}
		}
		cd++;
	}
	return NULL;
}

static const value_string ctdb_dbid_vals[] = {
	{0x435d3410, 		"notify.tdb"},
	{0x42fe72c5,		"locking.tdb"},
	{0x1421fb78,		"brlock.tdb"},
	{0x17055d90,		"connections.tdb"},
	{0xc0bdde6a,		"sessionid.tdb"},
	{0, NULL}
};

static void
ctdb_display_trans(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, ctdb_trans_t *ctdb_trans)
{
	proto_item *item;

	if(ctdb_trans->request_in!=pinfo->num){
		item=proto_tree_add_uint(tree, hf_ctdb_request_in, tvb, 0, 0, ctdb_trans->request_in);
		proto_item_set_generated(item);
	}

	if( (ctdb_trans->response_in!=0)
	  &&(ctdb_trans->response_in!=pinfo->num) ){
		item=proto_tree_add_uint(tree, hf_ctdb_response_in, tvb, 0, 0, ctdb_trans->response_in);
		proto_item_set_generated(item);
	}

	if(pinfo->num==ctdb_trans->response_in){
		nstime_t ns;

		nstime_delta(&ns, &pinfo->abs_ts, &ctdb_trans->req_time);
		item=proto_tree_add_time(tree, hf_ctdb_time, tvb, 0, 0, &ns);
		proto_item_set_generated(item);
	}
}

static void
ctdb_display_control(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, ctdb_control_t *ctdb_control)
{
	proto_item *item;

	if(ctdb_control->request_in!=pinfo->num){
		item=proto_tree_add_uint(tree, hf_ctdb_request_in, tvb, 0, 0, ctdb_control->request_in);
		proto_item_set_generated(item);
	}

	if( (ctdb_control->response_in!=0)
	  &&(ctdb_control->response_in!=pinfo->num) ){
		item=proto_tree_add_uint(tree, hf_ctdb_response_in, tvb, 0, 0, ctdb_control->response_in);
		proto_item_set_generated(item);
	}

	if(pinfo->num==ctdb_control->response_in){
		nstime_t ns;

		nstime_delta(&ns, &pinfo->abs_ts, &ctdb_control->req_time);
		item=proto_tree_add_time(tree, hf_ctdb_time, tvb, 0, 0, &ns);
		proto_item_set_generated(item);
	}
}

static uint32_t
ctdb_hash(tvbuff_t *tvb, int offset, uint32_t len)
{
	uint32_t value;
	uint32_t i;

	for(value=0x238F13AF*len, i=0; i < len; i++)
		value=(value+(tvb_get_uint8(tvb, offset+i) << (i*5 % 24)));

	return (1103515243 * value + 12345);
}

static int
dissect_ctdb_key(proto_tree *tree, tvbuff_t *tvb, int offset, uint32_t keylen, uint32_t *key_hash, int endianess)
{
	uint32_t keyhash;
	proto_item *key_item=NULL;
	proto_item *key_tree=NULL;

	if(tree){
		key_item=proto_tree_add_item(tree, hf_ctdb_key, tvb, offset, keylen, endianess);
		key_tree=proto_item_add_subtree(key_item, ett_ctdb_key);

	}

	keyhash=ctdb_hash(tvb, offset, keylen);
	proto_item_append_text(key_item, " (Hash:0x%08x)", keyhash);
	key_item=proto_tree_add_uint(key_tree, hf_ctdb_keyhash, tvb, 0, 0, keyhash);
	proto_item_set_generated(key_item);

	offset+=keylen;

	if(key_hash){
		*key_hash=keyhash;
	}

	return offset;
}

static int
dissect_ctdb_reply_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int endianess)
{
	uint32_t datalen;

	/* status */
	proto_tree_add_item(tree, hf_ctdb_status, tvb, offset, 4, endianess);
	offset+=4;

	/* datalen */
	proto_tree_add_item(tree, hf_ctdb_datalen, tvb, offset, 4, endianess);
	if(endianess){
		datalen=tvb_get_letohl(tvb, offset);
	} else {
		datalen=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	/* data */
	proto_tree_add_item(tree, hf_ctdb_data, tvb, offset, datalen, endianess);
	offset+=datalen;


	return offset;
}

static int
dissect_ctdb_reply_dmaster(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, uint32_t reqid, uint32_t dst, int endianess)
{
	uint32_t datalen, keylen;
	wmem_tree_key_t tkey[3];
	ctdb_trans_t *ctdb_trans;

	/* dbid */
	proto_tree_add_item(tree, hf_ctdb_dbid, tvb, offset, 4, endianess);
	offset+=4;


	/* rsn */
	offset=(offset+7)&0xfffff8; /* fixup alignment*/
	proto_tree_add_item(tree, hf_ctdb_rsn, tvb, offset, 8, endianess);
	offset+=8;

	/* keylen */
	proto_tree_add_item(tree, hf_ctdb_keylen, tvb, offset, 4, endianess);
	if(endianess){
		keylen=tvb_get_letohl(tvb, offset);
	} else {
		keylen=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	/* datalen */
	proto_tree_add_item(tree, hf_ctdb_datalen, tvb, offset, 4, endianess);
	if(endianess){
		datalen=tvb_get_letohl(tvb, offset);
	} else {
		datalen=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	/* key */
	offset=dissect_ctdb_key(tree, tvb, offset, keylen, NULL, endianess);

	/* data */
	proto_tree_add_item(tree, hf_ctdb_data, tvb, offset, datalen, endianess);
	offset+=datalen;

	tkey[0].length=1;
	tkey[0].key=&reqid;
	tkey[1].length=1;
	tkey[1].key=&dst;
	tkey[2].length=0;
	ctdb_trans=(ctdb_trans_t *)wmem_tree_lookup32_array(ctdb_transactions, &tkey[0]);

	if(ctdb_trans){
		ctdb_trans->response_in=pinfo->num;
		ctdb_display_trans(pinfo, tree, tvb, ctdb_trans);
	}

	return offset;
}

static int
dissect_ctdb_req_dmaster(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, uint32_t reqid, int endianess)
{
	uint32_t keylen, datalen, dmaster;
	wmem_tree_key_t tkey[3];
	ctdb_trans_t *ctdb_trans;

	/* dbid */
	proto_tree_add_item(tree, hf_ctdb_dbid, tvb, offset, 4, endianess);
	offset+=4;

	/* rsn */
	offset=(offset+7)&0xfffff8; /* fixup alignment*/
	proto_tree_add_item(tree, hf_ctdb_rsn, tvb, offset, 8, endianess);
	offset+=8;

	/* dmaster */
	proto_tree_add_item(tree, hf_ctdb_dmaster, tvb, offset, 4, endianess);
	if(endianess){
		dmaster=tvb_get_letohl(tvb, offset);
	} else {
		dmaster=tvb_get_ntohl(tvb, offset);
	}
	offset += 4;

	/* keylen */
	proto_tree_add_item(tree, hf_ctdb_keylen, tvb, offset, 4, endianess);
	if(endianess){
		keylen=tvb_get_letohl(tvb, offset);
	} else {
		keylen=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	/* datalen */
	proto_tree_add_item(tree, hf_ctdb_datalen, tvb, offset, 4, endianess);
	if(endianess){
		datalen=tvb_get_letohl(tvb, offset);
	} else {
		datalen=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	/* key */
	offset=dissect_ctdb_key(tree, tvb, offset, keylen, NULL, endianess);

	/* data */
	proto_tree_add_item(tree, hf_ctdb_data, tvb, offset, datalen, endianess);
	offset+=datalen;


	tkey[0].length=1;
	tkey[0].key=&reqid;
	tkey[1].length=1;
	tkey[1].key=&dmaster;
	tkey[2].length=0;
	ctdb_trans=(ctdb_trans_t *)wmem_tree_lookup32_array(ctdb_transactions, &tkey[0]);

	if(ctdb_trans){
		ctdb_display_trans(pinfo, tree, tvb, ctdb_trans);
	}

	return offset;
}



static int
dissect_ctdb_req_control(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, uint32_t reqid, uint32_t src, uint32_t dst, int endianess)
{
	uint32_t datalen;
	uint32_t opcode;
	ctdb_control_t *ctdb_control;
	control_dissector cd;
	int data_offset;

	/* ctrl opcode */
	proto_tree_add_item(tree, hf_ctdb_ctrl_opcode, tvb, offset, 4, endianess);
	if(endianess){
		opcode=tvb_get_letohl(tvb, offset);
	} else {
		opcode=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	col_add_fstr(pinfo->cinfo, COL_INFO, "%s Request %d->%d",
		val_to_str(opcode, ctrl_opcode_vals, "Unknown:%d"),
		src, dst);

	/* srvid */
	offset=(offset+7)&0xfffff8; /* fixup alignment*/
	proto_tree_add_item(tree, hf_ctdb_srvid, tvb, offset, 8, endianess);
	offset+=8;

	/* client id */
	proto_tree_add_item(tree, hf_ctdb_clientid, tvb, offset, 4, endianess);
	offset+=4;

	/* ctrl flags */
	proto_tree_add_item(tree, hf_ctdb_ctrl_flags, tvb, offset, 4, endianess);
	offset+=4;

	/* datalen */
	proto_tree_add_item(tree, hf_ctdb_datalen, tvb, offset, 4, endianess);
	if(endianess){
		datalen=tvb_get_letohl(tvb, offset);
	} else {
		datalen=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	/* data */
	data_offset=offset;
	if (datalen) {
		proto_tree_add_item(tree, hf_ctdb_data, tvb, offset, datalen, endianess);
		offset+=datalen;
	}

	/* setup request/response matching */
	if(!pinfo->fd->visited){
		wmem_tree_key_t tkey[4];

		ctdb_control=wmem_new(wmem_file_scope(), ctdb_control_t);
		ctdb_control->opcode=opcode;
		ctdb_control->request_in=pinfo->num;
		ctdb_control->response_in=0;
		ctdb_control->req_time=pinfo->abs_ts;
		tkey[0].length=1;
		tkey[0].key=&reqid;
		tkey[1].length=1;
		tkey[1].key=&src;
		tkey[2].length=1;
		tkey[2].key=&dst;
		tkey[3].length=0;

		wmem_tree_insert32_array(ctdb_controls, &tkey[0], ctdb_control);
	} else {
		wmem_tree_key_t tkey[4];

		tkey[0].length=1;
		tkey[0].key=&reqid;
		tkey[1].length=1;
		tkey[1].key=&src;
		tkey[2].length=1;
		tkey[2].key=&dst;
		tkey[3].length=0;
		ctdb_control=(ctdb_control_t *)wmem_tree_lookup32_array(ctdb_controls, &tkey[0]);
	}

	if (ctdb_control) {
		cd=find_control_dissector(ctdb_control->opcode, true);
		if (cd) {
			cd(pinfo, tree, tvb, data_offset, 0, endianess);
		}
		ctdb_display_control(pinfo, tree, tvb, ctdb_control);
	}

	return offset;
}

static int
dissect_ctdb_reply_control(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, uint32_t reqid, uint32_t src, uint32_t dst, int endianess)
{
	ctdb_control_t *ctdb_control;
	wmem_tree_key_t tkey[4];
	proto_item *item;
	uint32_t datalen, errorlen, status;
	int data_offset;
	control_dissector cd;

	tkey[0].length=1;
	tkey[0].key=&reqid;
	tkey[1].length=1;
	tkey[1].key=&dst;
	tkey[2].length=1;
	tkey[2].key=&src;
	tkey[3].length=0;
	ctdb_control=(ctdb_control_t *)wmem_tree_lookup32_array(ctdb_controls, &tkey[0]);

	if(!ctdb_control){
		return offset;
	}

	if(!pinfo->fd->visited){
		ctdb_control->response_in = pinfo->num;
	}

	/* ctrl opcode */
	item=proto_tree_add_uint(tree, hf_ctdb_ctrl_opcode, tvb, 0, 0, ctdb_control->opcode);
	proto_item_set_generated(item);

	col_add_fstr(pinfo->cinfo, COL_INFO, "%s Reply %d->%d",
		val_to_str(ctdb_control->opcode, ctrl_opcode_vals, "Unknown:%d"),
		src, dst);


	/* status */
	proto_tree_add_item(tree, hf_ctdb_status, tvb, offset, 4, endianess);
	if(endianess){
		status=tvb_get_letohl(tvb, offset);
	} else {
		status=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	/* datalen */
	proto_tree_add_item(tree, hf_ctdb_datalen, tvb, offset, 4, endianess);
	if(endianess){
		datalen=tvb_get_letohl(tvb, offset);
	} else {
		datalen=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	/* errorlen */
	proto_tree_add_item(tree, hf_ctdb_errorlen, tvb, offset, 4, endianess);
	if(endianess){
		errorlen=tvb_get_letohl(tvb, offset);
	} else {
		errorlen=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	/* data */
	data_offset=offset;
	if (datalen) {
		proto_tree_add_item(tree, hf_ctdb_data, tvb, offset, datalen, endianess);
		offset+=datalen;
	}


	/* error */
	if (errorlen) {
		proto_tree_add_item(tree, hf_ctdb_error, tvb, offset, errorlen, endianess);
		offset+=errorlen;
	}


	cd=find_control_dissector(ctdb_control->opcode, false);
	if (cd) {
		cd(pinfo, tree, tvb, data_offset, status, endianess);
	}

	ctdb_display_control(pinfo, tree, tvb, ctdb_control);
	return offset;
}

static const true_false_string flags_immediate_tfs={
	"DMASTER for the record must IMMEDIATELY be migrated to the caller",
	"Dmaster migration is not required"
};

static int
dissect_ctdb_req_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, uint32_t reqid, uint32_t caller, int endianess)
{
	uint32_t flags, keyhash;
	uint32_t keylen, datalen;
	ctdb_trans_t *ctdb_trans=NULL;

	/* flags */
	proto_tree_add_item(tree, hf_ctdb_flags_immediate, tvb, offset, 4, endianess);
	if(endianess){
		flags=tvb_get_letohl(tvb, offset);
	} else {
		flags=tvb_get_ntohl(tvb, offset);
	}
	if(flags&0x00000001){
		col_append_str(pinfo->cinfo, COL_INFO, " IMMEDIATE");
	}
	offset+=4;

	/* dbid */
	proto_tree_add_item(tree, hf_ctdb_dbid, tvb, offset, 4, endianess);
	offset+=4;

	/* callid */
	proto_tree_add_item(tree, hf_ctdb_callid, tvb, offset, 4, endianess);
	offset+=4;

	/* hopcount */
	proto_tree_add_item(tree, hf_ctdb_hopcount, tvb, offset, 4, endianess);
	offset+=4;

	/* keylen */
	proto_tree_add_item(tree, hf_ctdb_keylen, tvb, offset, 4, endianess);
	if(endianess){
		keylen=tvb_get_letohl(tvb, offset);
	} else {
		keylen=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	/* datalen */
	proto_tree_add_item(tree, hf_ctdb_datalen, tvb, offset, 4, endianess);
	if(endianess){
		datalen=tvb_get_letohl(tvb, offset);
	} else {
		datalen=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	/* key */
	offset=dissect_ctdb_key(tree, tvb, offset, keylen, &keyhash, endianess);

	/* data */
	proto_tree_add_item(tree, hf_ctdb_data, tvb, offset, datalen, endianess);
	offset+=datalen;

	/* setup request/response matching */
	if(!pinfo->fd->visited){
		wmem_tree_key_t tkey[3];

		ctdb_trans=wmem_new(wmem_file_scope(), ctdb_trans_t);
		ctdb_trans->key_hash=keyhash;
		ctdb_trans->request_in=pinfo->num;
		ctdb_trans->response_in=0;
		ctdb_trans->req_time=pinfo->abs_ts;
		tkey[0].length=1;
		tkey[0].key=&reqid;
		tkey[1].length=1;
		tkey[1].key=&caller;
		tkey[2].length=0;

		wmem_tree_insert32_array(ctdb_transactions, &tkey[0], ctdb_trans);
	} else {
		wmem_tree_key_t tkey[3];

		tkey[0].length=1;
		tkey[0].key=&reqid;
		tkey[1].length=1;
		tkey[1].key=&caller;
		tkey[2].length=0;
		ctdb_trans=(ctdb_trans_t *)wmem_tree_lookup32_array(ctdb_transactions, &tkey[0]);
	}

	if(ctdb_trans){
		ctdb_display_trans(pinfo, tree, tvb, ctdb_trans);
	}

	return offset;
}

static gboolean
dissect_ctdb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	proto_tree *tree=NULL;
	proto_item *item=NULL;
	int offset=0;
	uint32_t opcode, src, dst, reqid;
	int endianess;

	/* does this look like CTDB? */
	if(tvb_captured_length(tvb)<8){
		return FALSE;
	}
	switch(tvb_get_letohl(tvb, offset+4)){
	case 0x42445443:
		endianess=false;
		break;
	case 0x43544442:
		endianess=true;
		break;
	default:
		return FALSE;
	}


	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CTDB");
	col_clear(pinfo->cinfo, COL_INFO);

	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_ctdb, tvb, offset,
			-1, endianess);
		tree=proto_item_add_subtree(item, ett_ctdb);
	}

	/* header*/
	/* length */
	proto_tree_add_item(tree, hf_ctdb_length, tvb, offset, 4, endianess);
	offset+=4;

	/* magic */
	proto_tree_add_item(tree, hf_ctdb_magic, tvb, offset, 4, endianess);
	offset+=4;

	/* version */
	proto_tree_add_item(tree, hf_ctdb_version, tvb, offset, 4, endianess);
	offset+=4;

	/* generation */
	proto_tree_add_item(tree, hf_ctdb_generation, tvb, offset, 4, endianess);
	offset+=4;

	/* opcode */
	proto_tree_add_item(tree, hf_ctdb_opcode, tvb, offset, 4, endianess);
	if(endianess){
		opcode=tvb_get_letohl(tvb, offset);
	} else {
		opcode=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	/* dst */
	proto_tree_add_item(tree, hf_ctdb_dst, tvb, offset, 4, endianess);
	if(endianess){
		dst=tvb_get_letohl(tvb, offset);
	} else {
		dst=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	/* src */
	proto_tree_add_item(tree, hf_ctdb_src, tvb, offset, 4, endianess);
	if(endianess){
		src=tvb_get_letohl(tvb, offset);
	} else {
		src=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	/* id */
	proto_tree_add_item(tree, hf_ctdb_id, tvb, offset, 4, endianess);
	if(endianess){
		reqid=tvb_get_letohl(tvb, offset);
	} else {
		reqid=tvb_get_ntohl(tvb, offset);
	}
	offset+=4;

	col_append_fstr(pinfo->cinfo, COL_INFO, "%s %d->%d",
		val_to_str(opcode, ctdb_opcodes, "Unknown:%d"),
		src, dst);

	switch(opcode){
	case CTDB_REQ_CALL:
		dissect_ctdb_req_call(tvb, offset, pinfo, tree, reqid, src, endianess);
		break;
	case CTDB_REPLY_CALL:
		dissect_ctdb_reply_call(tvb, offset, pinfo, tree, endianess);
		break;
	case CTDB_REPLY_DMASTER:
		dissect_ctdb_reply_dmaster(tvb, offset, pinfo, tree, reqid, dst, endianess);
		break;
	case CTDB_REQ_DMASTER:
		dissect_ctdb_req_dmaster(tvb, offset, pinfo, tree, reqid, endianess);
		break;
	case CTDB_REPLY_ERROR:
		break;
	case CTDB_REQ_MESSAGE:
		break;
	case CTDB_REQ_CONTROL:
		dissect_ctdb_req_control(tvb, offset, pinfo, tree, reqid, src, dst, endianess);
		break;
	case CTDB_REPLY_CONTROL:
		dissect_ctdb_reply_control(tvb, offset, pinfo, tree, reqid, src, dst, endianess);
		break;
	};

	return TRUE;
}

static bool
dissect_ctdb_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    return (bool)dissect_ctdb(tvb, pinfo, tree, data);
}

/*
 * Register the protocol with Wireshark
 */
void
proto_register_ctdb(void)
{
	static hf_register_info hf[] = {
	{ &hf_ctdb_length, {
	  "Length", "ctdb.len", FT_UINT32, BASE_DEC,
	  NULL, 0x0, "Size of CTDB PDU", HFILL }},
	{ &hf_ctdb_dst, {
	  "Destination", "ctdb.dst", FT_UINT32, BASE_DEC,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_src, {
	  "Source", "ctdb.src", FT_UINT32, BASE_DEC,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_id, {
	  "Id", "ctdb.id", FT_UINT32, BASE_DEC,
	  NULL, 0x0, "Transaction ID", HFILL }},
	{ &hf_ctdb_opcode, {
	  "Opcode", "ctdb.opcode", FT_UINT32, BASE_DEC,
	  VALS(ctdb_opcodes), 0x0, "CTDB command opcode", HFILL }},
	{ &hf_ctdb_flags_immediate, {
	  "Immediate", "ctdb.immediate", FT_BOOLEAN, 32,
	  TFS(&flags_immediate_tfs), 0x00000001, "Force migration of DMASTER?", HFILL }},
	{ &hf_ctdb_dbid, {
	  "DB Id", "ctdb.dbid", FT_UINT32, BASE_HEX,
	  VALS(ctdb_dbid_vals), 0x0, "Database ID", HFILL }},
	{ &hf_ctdb_callid, {
	  "Call Id", "ctdb.callid", FT_UINT32, BASE_DEC,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_status, {
	  "Status", "ctdb.status", FT_UINT32, BASE_DEC,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_datalen, {
	  "Data Length", "ctdb.datalen", FT_UINT32, BASE_DEC,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_errorlen, {
	  "Error Length", "ctdb.errorlen", FT_UINT32, BASE_DEC,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_keylen, {
	  "Key Length", "ctdb.keylen", FT_UINT32, BASE_DEC,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_magic, {
	  "Magic", "ctdb.magic", FT_UINT32, BASE_HEX,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_version, {
	  "Version", "ctdb.version", FT_UINT32, BASE_DEC,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_dmaster, {
	  "Dmaster", "ctdb.dmaster", FT_UINT32, BASE_DEC,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_generation, {
	  "Generation", "ctdb.generation", FT_UINT32, BASE_DEC,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_key, {
	  "Key", "ctdb.key", FT_BYTES, BASE_NONE,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_keyhash, {
	  "KeyHash", "ctdb.keyhash", FT_UINT32, BASE_HEX,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_data, {
	  "Data", "ctdb.data", FT_BYTES, BASE_NONE,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_error, {
	  "Error", "ctdb.error", FT_BYTES, BASE_NONE,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_request_in, {
	  "Request In", "ctdb.request_in", FT_FRAMENUM, BASE_NONE,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_response_in, {
	  "Response In", "ctdb.response_in", FT_FRAMENUM, BASE_NONE,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_time, {
	  "Time since request", "ctdb.time", FT_RELATIVE_TIME, BASE_NONE,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_hopcount, {
	  "Hopcount", "ctdb.hopcount", FT_UINT32, BASE_DEC,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_rsn, {
	  "RSN", "ctdb.rsn", FT_UINT64, BASE_HEX,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_ctrl_opcode, {
	  "CTRL Opcode", "ctdb.ctrl_opcode", FT_UINT32, BASE_DEC,
	  VALS(ctrl_opcode_vals), 0x0, NULL, HFILL }},
	{ &hf_ctdb_srvid, {
	  "SrvId", "ctdb.srvid", FT_UINT64, BASE_HEX,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_clientid, {
	  "ClientId", "ctdb.clientid", FT_UINT32, BASE_HEX,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_ctrl_flags, {
	  "CTRL Flags", "ctdb.ctrl_flags", FT_UINT32, BASE_HEX,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_recmaster, {
	  "Recovery Master", "ctdb.recmaster", FT_UINT32, BASE_DEC,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_recmode, {
	  "Recovery Mode", "ctdb.recmode", FT_UINT32, BASE_DEC,
	  VALS(recmode_vals), 0x0, NULL, HFILL }},
	{ &hf_ctdb_num_nodes, {
	  "Num Nodes", "ctdb.num_nodes", FT_UINT32, BASE_DEC,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_vnn, {
	  "VNN", "ctdb.vnn", FT_UINT32, BASE_DEC,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_node_flags, {
	  "Node Flags", "ctdb.node_flags", FT_UINT32, BASE_HEX,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_node_ip, {
	  "Node IP", "ctdb.node_ip", FT_IPv4, BASE_NONE,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_pid, {
	  "PID", "ctdb.pid", FT_UINT32, BASE_DEC,
	  NULL, 0x0, NULL, HFILL }},
	{ &hf_ctdb_process_exists, {
	  "Process Exists", "ctdb.process_exists", FT_BOOLEAN, 32,
	  TFS(&process_exists_tfs), 0x00000001, NULL, HFILL }},
	};

	/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_ctdb,
		&ett_ctdb_key,
	};

	static ei_register_info ei[] = {
		{ &ei_ctdb_too_many_nodes, { "ctdb.too_many_nodes", PI_UNDECODED, PI_WARN, "Too many nodes", EXPFILL }},
	};

	expert_module_t* expert_ctdb;


	/* Register the protocol name and description */
	proto_ctdb = proto_register_protocol("Cluster TDB", "CTDB", "ctdb");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_ctdb, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_ctdb = expert_register_protocol(proto_ctdb);
	expert_register_field_array(expert_ctdb, ei, array_length(ei));

	/* Register the dissector */
	ctdb_handle = register_dissector("ctdb", dissect_ctdb, proto_ctdb);

	ctdb_transactions = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
	ctdb_controls     = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
}


void
proto_reg_handoff_ctdb(void)
{
	dissector_add_for_decode_as_with_preference("tcp.port", ctdb_handle);

	heur_dissector_add("tcp", dissect_ctdb_heur, "Cluster TDB over TCP", "ctdb_tcp", proto_ctdb, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
