/* packet-netlink-netfilter.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/aftypes.h>
#include <epan/etypes.h>
#include <epan/packet.h>
#include "packet-netlink.h"

void proto_register_netlink_netfilter(void);
void proto_reg_handoff_netlink_netfilter(void);

typedef struct {
	packet_info *pinfo;
	uint16_t hw_protocol; /* protocol for NFQUEUE packet payloads. */
} netlink_netfilter_info_t;

static dissector_handle_t netlink_netfilter;
static dissector_handle_t nflog_handle;
static dissector_table_t ethertype_table;

/* nfnetlink subsystems from <include/uapi/linux/netfilter/nfnetlink.h> */
enum {
	WS_NFNL_SUBSYS_NONE              =  0,
	WS_NFNL_SUBSYS_CTNETLINK         =  1,
	WS_NFNL_SUBSYS_CTNETLINK_EXP     =  2,
	WS_NFNL_SUBSYS_QUEUE             =  3,
	WS_NFNL_SUBSYS_ULOG              =  4,
	WS_NFNL_SUBSYS_OSF               =  5,
	WS_NFNL_SUBSYS_IPSET             =  6,
	WS_NFNL_SUBSYS_ACCT              =  7,
	WS_NFNL_SUBSYS_CTNETLINK_TIMEOUT =  8,
	WS_NFNL_SUBSYS_CTHELPER          =  9,
	WS_NFNL_SUBSYS_NFTABLES          = 10,
	WS_NFNL_SUBSYS_NFT_COMPAT        = 11,
	WS_NFNL_SUBSYS_HOOK              = 12,
	WS_NFNL_SUBSYS_COUNT             = 13,
};

/* nfnetlink ULOG subsystem types from <include/uapi/linux/netfilter/nfnetlink_log.h> */
enum ws_nfulnl_msg_types {
	WS_NFULNL_MSG_PACKET = 0,
	WS_NFULNL_MSG_CONFIG = 1
};

/* Macros for "hook function responses" from <include/uapi/linux/netfilter.h> */
enum ws_verdict_types {
	WS_NF_DROP      = 0,
	WS_NF_ACCEPT    = 1,
	WS_NF_STOLEN    = 2,
	WS_NF_QUEUE     = 3,
	WS_NF_REPEAT    = 4,
	WS_NF_STOP      = 5,
};

enum ws_nf_inet_hooks {
	WS_NF_INET_PRE_ROUTING  = 0,
	WS_NF_INET_LOCAL_IN     = 1,
	WS_NF_INET_FORWARD      = 2,
	WS_NF_INET_LOCAL_OUT    = 3,
	WS_NF_INET_POST_ROUTING = 4,
	WS_NF_INET_NUMHOOKS     = 5,
};

/* from <include/uapi/linux/netfilter/nf_conntrack_common.h> */
enum ws_ip_conntrack_info {
	WS_IP_CT_ESTABLISHED,
	WS_IP_CT_RELATED,
	WS_IP_CT_NEW,
	WS_IP_CT_IS_REPLY,
	WS_IP_CT_ESTABLISHED_REPLY = WS_IP_CT_ESTABLISHED + WS_IP_CT_IS_REPLY,
	WS_IP_CT_RELATED_REPLY = WS_IP_CT_RELATED + WS_IP_CT_IS_REPLY,
	WS_IP_CT_NUMBER,
};

enum ws_ip_conntrack_status {
	WS_IPS_EXPECTED_BIT = 0,
	WS_IPS_EXPECTED = (1 << WS_IPS_EXPECTED_BIT),
	WS_IPS_SEEN_REPLY_BIT = 1,
	WS_IPS_SEEN_REPLY = (1 << WS_IPS_SEEN_REPLY_BIT),
	WS_IPS_ASSURED_BIT = 2,
	WS_IPS_ASSURED = (1 << WS_IPS_ASSURED_BIT),
	WS_IPS_CONFIRMED_BIT = 3,
	WS_IPS_CONFIRMED = (1 << WS_IPS_CONFIRMED_BIT),
	WS_IPS_SRC_NAT_BIT = 4,
	WS_IPS_SRC_NAT = (1 << WS_IPS_SRC_NAT_BIT),
	WS_IPS_DST_NAT_BIT = 5,
	WS_IPS_DST_NAT = (1 << WS_IPS_DST_NAT_BIT),
	WS_IPS_SEQ_ADJUST_BIT = 6,
	WS_IPS_SEQ_ADJUST = (1 << WS_IPS_SEQ_ADJUST_BIT),
	WS_IPS_SRC_NAT_DONE_BIT = 7,
	WS_IPS_SRC_NAT_DONE = (1 << WS_IPS_SRC_NAT_DONE_BIT),
	WS_IPS_DST_NAT_DONE_BIT = 8,
	WS_IPS_DST_NAT_DONE = (1 << WS_IPS_DST_NAT_DONE_BIT),
	WS_IPS_DYING_BIT = 9,
	WS_IPS_DYING = (1 << WS_IPS_DYING_BIT),
	WS_IPS_FIXED_TIMEOUT_BIT = 10,
	WS_IPS_FIXED_TIMEOUT = (1 << WS_IPS_FIXED_TIMEOUT_BIT),
	WS_IPS_TEMPLATE_BIT = 11,
	WS_IPS_TEMPLATE = (1 << WS_IPS_TEMPLATE_BIT),
	WS_IPS_UNTRACKED_BIT = 12,
	WS_IPS_UNTRACKED = (1 << WS_IPS_UNTRACKED_BIT),
	WS_IPS_HELPER_BIT = 13,
	WS_IPS_HELPER = (1 << WS_IPS_HELPER_BIT),
	WS_IPS_OFFLOAD_BIT = 14,
	WS_IPS_OFFLOAD = (1 << WS_IPS_OFFLOAD_BIT),
	WS_IPS_HW_OFFLOAD_BIT = 15,
	WS_IPS_HW_OFFLOAD = (1 << WS_IPS_HW_OFFLOAD_BIT),
};

enum nfexp_flags {
	WS_NF_CT_EXPECT_PERMANENT   = (1 << 0),
	WS_NF_CT_EXPECT_INACTIVE    = (1 << 1),
	WS_NF_CT_EXPECT_USERSPACE   = (1 << 2),
};

/* from <include/uapi/linux/netfilter/nf_conntrack_tuple_common.h> */
enum ws_ip_conntrack_dir {
	WS_IP_CT_DIR_ORIGINAL       = 0,
	WS_IP_CT_DIR_REPLY          = 1,
};

/* nfnetlink QUEUE subsystem types from <include/uapi/linux/netfilter/nfnetlink_queue.h> */
enum ws_nfqnl_msg_types {
	WS_NFQNL_MSG_PACKET         = 0,
	WS_NFQNL_MSG_VERDICT        = 1,
	WS_NFQNL_MSG_CONFIG         = 2,
	WS_NFQNL_MSG_VERDICT_BATCH  = 3
};

enum ws_nfqnl_attr_type {
	WS_NFQA_UNSPEC              = 0,
	WS_NFQA_PACKET_HDR          = 1,
	WS_NFQA_VERDICT_HDR         = 2,
	WS_NFQA_MARK                = 3,
	WS_NFQA_TIMESTAMP           = 4,
	WS_NFQA_IFINDEX_INDEV       = 5,
	WS_NFQA_IFINDEX_OUTDEV      = 6,
	WS_NFQA_IFINDEX_PHYSINDEV   = 7,
	WS_NFQA_IFINDEX_PHYSOUTDEV  = 8,
	WS_NFQA_HWADDR              = 9,
	WS_NFQA_PAYLOAD             = 10,
	WS_NFQA_CT                  = 11,
	WS_NFQA_CT_INFO             = 12,
	WS_NFQA_CAP_LEN             = 13,
	WS_NFQA_SKB_INFO            = 14,
	WS_NFQA_EXP                 = 15,
	WS_NFQA_UID                 = 16,
	WS_NFQA_GID                 = 17,
	WS_NFQA_SECCTX              = 18,
	WS_NFQA_VLAN                = 19,
	WS_NFQA_L2HDR               = 20,
	WS_NFQA_PRIORITY            = 21,
};

enum ws_nfqnl_msg_config_cmds {
	WS_NFQNL_CFG_CMD_NONE       = 0,
	WS_NFQNL_CFG_CMD_BIND       = 1,
	WS_NFQNL_CFG_CMD_UNBIND     = 2,
	WS_NFQNL_CFG_CMD_PF_BIND    = 3,
	WS_NFQNL_CFG_CMD_PF_UNBIND  = 4,
};

enum ws_nfqnl_config_mode {
	WS_NFQNL_COPY_NONE          = 0,
	WS_NFQNL_COPY_META          = 1,
	WS_NFQNL_COPY_PACKET        = 2,
};

enum ws_nfqnl_attr_config {
	WS_NFQA_CFG_UNSPEC          = 0,
	WS_NFQA_CFG_CMD             = 1,
	WS_NFQA_CFG_PARAMS          = 2,
	WS_NFQA_CFG_QUEUE_MAXLEN    = 3,
	WS_NFQA_CFG_MASK            = 4,
	WS_NFQA_CFG_FLAGS           = 5,
};

/* from <include/uapi/linux/netfilter/nfnetlink_conntrack.h> */
enum ws_ctattr_tuple {
	WS_CTA_TUPLE_UNSPEC         = 0,
	WS_CTA_TUPLE_IP             = 1,
	WS_CTA_TUPLE_PROTO          = 2,
	WS_CTA_TUPLE_ZONE           = 3,
};

enum ws_ctattr_ip {
	WS_CTA_IP_UNSPEC            = 0,
	WS_CTA_IP_V4_SRC            = 1,
	WS_CTA_IP_V4_DST            = 2,
	WS_CTA_IP_V6_SRC            = 3,
	WS_CTA_IP_V6_DST            = 4,
};

enum ws_ctattr_l4proto {
	WS_CTA_PROTO_UNSPEC         = 0,
	WS_CTA_PROTO_NUM            = 1,
	WS_CTA_PROTO_SRC_PORT       = 2,
	WS_CTA_PROTO_DST_PORT       = 3,
	WS_CTA_PROTO_ICMP_ID        = 4,
	WS_CTA_PROTO_ICMP_TYPE      = 5,
	WS_CTA_PROTO_ICMP_CODE      = 6,
	WS_CTA_PROTO_ICMPV6_ID      = 7,
	WS_CTA_PROTO_ICMPV6_TYPE    = 8,
	WS_CTA_PROTO_ICMPV6_CODE    = 9,
};

enum ws_ctnl_exp_msg_types {
	WS_IPCTNL_MSG_EXP_NEW             = 0,
	WS_IPCTNL_MSG_EXP_GET             = 1,
	WS_IPCTNL_MSG_EXP_DELETE          = 2,
	WS_IPCTNL_MSG_EXP_GET_STATS_CPU   = 3,
};

enum ws_ctattr_expect {
	WS_CTA_EXPECT_UNSPEC        = 0,
	WS_CTA_EXPECT_MASTER        = 1,
	WS_CTA_EXPECT_TUPLE         = 2,
	WS_CTA_EXPECT_MASK          = 3,
	WS_CTA_EXPECT_TIMEOUT       = 4,
	WS_CTA_EXPECT_ID            = 5,
	WS_CTA_EXPECT_HELP_NAME     = 6,
	WS_CTA_EXPECT_ZONE          = 7,
	WS_CTA_EXPECT_FLAGS         = 8,
	WS_CTA_EXPECT_CLASS         = 9,
	WS_CTA_EXPECT_NAT           = 10,
	WS_CTA_EXPECT_FN            = 11,
};

enum ws_ctattr_expect_nat {
	WS_CTA_EXPECT_NAT_UNSPEC    = 0,
	WS_CTA_EXPECT_NAT_DIR       = 1,
	WS_CTA_EXPECT_NAT_TUPLE     = 2,
};

enum ws_ctattr_type {
	WS_CTA_UNSPEC               = 0,
	WS_CTA_TUPLE_ORIG           = 1,
	WS_CTA_TUPLE_REPLY          = 2,
	WS_CTA_STATUS               = 3,
	WS_CTA_PROTOINFO            = 4,
	WS_CTA_HELP                 = 5,
	WS_CTA_NAT_SRC              = 6,
	WS_CTA_TIMEOUT              = 7,
	WS_CTA_MARK                 = 8,
	WS_CTA_COUNTERS_ORIG        = 9,
	WS_CTA_COUNTERS_REPLY       = 10,
	WS_CTA_USE                  = 11,
	WS_CTA_ID                   = 12,
	WS_CTA_NAT_DST              = 13,
	WS_CTA_TUPLE_MASTER         = 14,
	WS_CTA_SEQ_ADJ_ORIG         = 15,
	WS_CTA_SEQ_ADJ_REPLY        = 16,
	WS_CTA_SECMARK              = 17,
	WS_CTA_ZONE                 = 18,
	WS_CTA_SECCTX               = 19,
	WS_CTA_TIMESTAMP            = 20,
	WS_CTA_MARK_MASK            = 21,
	WS_CTA_LABELS               = 22,
	WS_CTA_LABELS_MASK          = 23,
	WS_CTA_SYNPROXY             = 24,
	WS_CTA_FILTER               = 25,
	WS_CTA_STATUS_MASK          = 26,
};

enum ws_ctattr_help {
	WS_CTA_HELP_UNSPEC          = 0,
	WS_CTA_HELP_NAME            = 1,
	WS_CTA_HELP_INFO            = 2,
};

enum ws_ctattr_seqadj {
	WS_CTA_SEQADJ_UNSPEC           = 0,
	WS_CTA_SEQADJ_CORRECTION_POS   = 1,
	WS_CTA_SEQADJ_OFFSET_BEFORE    = 2,
	WS_CTA_SEQADJ_OFFSET_AFTER     = 3,
};

/* from <include/uapi/linux/netfilter/ipset/ip_set.h> */
enum ws_ipset_cmd {
	WS_IPSET_CMD_NONE           = 0,
	WS_IPSET_CMD_PROTOCOL       = 1,
	WS_IPSET_CMD_CREATE         = 2,
	WS_IPSET_CMD_DESTROY        = 3,
	WS_IPSET_CMD_FLUSH          = 4,
	WS_IPSET_CMD_RENAME         = 5,
	WS_IPSET_CMD_SWAP           = 6,
	WS_IPSET_CMD_LIST           = 7,
	WS_IPSET_CMD_SAVE           = 8,
	WS_IPSET_CMD_ADD            = 9,
	WS_IPSET_CMD_DEL            = 10,
	WS_IPSET_CMD_TEST           = 11,
	WS_IPSET_CMD_HEADER         = 12,
	WS_IPSET_CMD_TYPE           = 13,
	WS_IPSET_CMD_GET_BYNAME     = 14,
	WS_IPSET_CMD_GET_BYINDEX    = 15,
};

/* Attributes at command level */
enum ws_ipset_attr {
	WS_IPSET_ATTR_PROTOCOL      = 1,
	WS_IPSET_ATTR_SETNAME       = 2,
	WS_IPSET_ATTR_TYPENAME      = 3,
	WS_IPSET_ATTR_REVISION      = 4,
	WS_IPSET_ATTR_FAMILY        = 5,
	WS_IPSET_ATTR_FLAGS         = 6,
	WS_IPSET_ATTR_DATA          = 7,
	WS_IPSET_ATTR_ADT           = 8,
	WS_IPSET_ATTR_LINENO        = 9,
	WS_IPSET_ATTR_PROTOCOL_MIN  = 10,
	WS_IPSET_ATTR_INDEX         = 11,
};

/* CADT-specific attributes (Create/Abstract Data Type) */
enum ws_ipset_cadt_attr {
	WS_IPSET_ATTR_IP_FROM           = 1,
	WS_IPSET_ATTR_IP_TO             = 2,
	WS_IPSET_ATTR_CIDR              = 3,
	WS_IPSET_ATTR_PORT_FROM         = 4,
	WS_IPSET_ATTR_PORT_TO           = 5,
	WS_IPSET_ATTR_TIMEOUT           = 6,
	WS_IPSET_ATTR_PROTO             = 7,
	WS_IPSET_ATTR_CADT_FLAGS        = 8,
	WS_IPSET_ATTR_CADT_LINENO       = 9,
	WS_IPSET_ATTR_MARK              = 10,
	WS_IPSET_ATTR_MARKMASK          = 11,
	WS_IPSET_ATTR_BITMASK           = 12,
	/* (reserved up to 16) */
#define WS_IPSET_ATTR_CADT_MAX            16
	WS_IPSET_ATTR_INITVAL           = 17,
	WS_IPSET_ATTR_HASHSIZE          = 18,
	WS_IPSET_ATTR_MAXELEM           = 19,
	WS_IPSET_ATTR_NETMASK           = 20,
	WS_IPSET_ATTR_BUCKETSIZE        = 21,
	WS_IPSET_ATTR_RESIZE            = 22,
	WS_IPSET_ATTR_SIZE              = 23,
	WS_IPSET_ATTR_ELEMENTS          = 24,
	WS_IPSET_ATTR_REFERENCES        = 25,
	WS_IPSET_ATTR_MEMSIZE           = 26,
};

/* ADT-specific attributes */
enum ws_ipset_adt_attr {
	WS_IPSET_ATTR_ETHER             = 17,
	WS_IPSET_ATTR_NAME              = 18,
	WS_IPSET_ATTR_NAMEREF           = 19,
	WS_IPSET_ATTR_IP2               = 20,
	WS_IPSET_ATTR_CIDR2             = 21,
	WS_IPSET_ATTR_IP2_TO            = 22,
	WS_IPSET_ATTR_IFACE             = 23,
	WS_IPSET_ATTR_BYTES             = 24,
	WS_IPSET_ATTR_PACKETS           = 25,
	WS_IPSET_ATTR_COMMENT           = 26,
	WS_IPSET_ATTR_SKBMARK           = 27,
	WS_IPSET_ATTR_SKBPRIO           = 28,
	WS_IPSET_ATTR_SKBQUEUE          = 29,
	WS_IPSET_ATTR_PAD               = 30,
};

/* IP specific attributes */
enum ws_ipset_ip_attr {
	WS_IPSET_ATTR_IPADDR_IPV4       = 1,
	WS_IPSET_ATTR_IPADDR_IPV6       = 2,
};

static int proto_netlink_netfilter;

static int hf_ipset_adt_attr;
static int hf_ipset_adt_attr_comment;
static int hf_ipset_attr;
static int hf_ipset_attr_family;
static int hf_ipset_attr_flags;
static int hf_ipset_attr_setname;
static int hf_ipset_attr_typename;
static int hf_ipset_cadt_attr;
static int hf_ipset_cadt_attr_cadt_flags;
static int hf_ipset_cadt_attr_cidr;
static int hf_ipset_cadt_attr_timeout;
static int hf_ipset_command;
static int hf_ipset_ip_attr;
static int hf_ipset_ip_attr_ipv4;
static int hf_ipset_ip_attr_ipv6;
static int hf_netlink_netfilter_family;
static int hf_netlink_netfilter_resid;
static int hf_netlink_netfilter_subsys;
static int hf_netlink_netfilter_ulog_type;
static int hf_netlink_netfilter_version;
static int hf_nfct_attr;
static int hf_nfct_attr_id;
static int hf_nfct_attr_status;
static int hf_nfct_attr_status_flag_assured;
static int hf_nfct_attr_status_flag_confirmed;
static int hf_nfct_attr_status_flag_dst_nat;
static int hf_nfct_attr_status_flag_dst_nat_done;
static int hf_nfct_attr_status_flag_dying;
static int hf_nfct_attr_status_flag_expected;
static int hf_nfct_attr_status_flag_fixed_timeout;
static int hf_nfct_attr_status_flag_helper;
static int hf_nfct_attr_status_flag_hw_offload;
static int hf_nfct_attr_status_flag_offload;
static int hf_nfct_attr_status_flag_seen_reply;
static int hf_nfct_attr_status_flag_seq_adjust;
static int hf_nfct_attr_status_flag_src_nat;
static int hf_nfct_attr_status_flag_src_nat_done;
static int hf_nfct_attr_status_flag_template;
static int hf_nfct_attr_status_flag_untracked;
static int hf_nfct_attr_timeout;
static int hf_nfct_help_attr;
static int hf_nfct_help_attr_help_name;
static int hf_nfct_seqadj_attr;
static int hf_nfct_seqadj_attr_correction_pos;
static int hf_nfct_seqadj_attr_offset_after;
static int hf_nfct_seqadj_attr_offset_before;
static int hf_nfct_tuple_attr;
static int hf_nfct_tuple_ip_attr;
static int hf_nfct_tuple_ip_attr_ipv4;
static int hf_nfct_tuple_ip_attr_ipv6;
static int hf_nfct_tuple_proto_attr;
static int hf_nfct_tuple_proto_dst_port_attr;
static int hf_nfct_tuple_proto_num_attr;
static int hf_nfct_tuple_proto_src_port_attr;
static int hf_nfct_tuple_zone_attr;
static int hf_nfexp_attr;
static int hf_nfexp_attr_class;
static int hf_nfexp_attr_flag_inactive;
static int hf_nfexp_attr_flag_permanent;
static int hf_nfexp_attr_flag_userspace;
static int hf_nfexp_attr_flags;
static int hf_nfexp_attr_fn;
static int hf_nfexp_attr_id;
static int hf_nfexp_attr_timeout;
static int hf_nfexp_attr_zone;
static int hf_nfexp_nat_attr;
static int hf_nfexp_nat_attr_dir;
static int hf_nfexp_type;
static int hf_nfq_attr;
static int hf_nfq_caplen;
static int hf_nfq_config_attr;
static int hf_nfq_config_command_command;
static int hf_nfq_config_command_pf;
static int hf_nfq_config_flags;
static int hf_nfq_config_mask;
static int hf_nfq_config_params_copymode;
static int hf_nfq_config_params_copyrange;
static int hf_nfq_config_queue_maxlen;
static int hf_nfq_ctinfo;
static int hf_nfq_gid;
static int hf_nfq_hwaddr_addr;
static int hf_nfq_hwaddr_len;
static int hf_nfq_ifindex_indev;
static int hf_nfq_ifindex_outdev;
static int hf_nfq_ifindex_physindev;
static int hf_nfq_ifindex_physoutdev;
static int hf_nfq_nfmark;
static int hf_nfq_packet_hook;
static int hf_nfq_packet_hwprotocol;
static int hf_nfq_packet_id;
static int hf_nfq_timestamp;
static int hf_nfq_type;
static int hf_nfq_uid;
static int hf_nfq_verdict_id;
static int hf_nfq_verdict_verdict;
static int hf_nftables_command;
static int hf_nft_rule_attr;
static int hf_nft_rule_attr_table;
static int hf_nft_rule_attr_chain;
static int hf_nft_rule_attr_handle;
static int hf_nft_rule_attr_position;
static int hf_nft_rule_attr_userdata;
static int hf_nft_rule_attr_id;
static int hf_nft_rule_attr_position_id;
static int hf_nft_rule_attr_chain_id;
static int hf_nft_rule_compat_attr;
static int hf_nft_rule_compat_attr_proto;
static int hf_nft_rule_compat_attr_flags;
static int hf_nft_expr_attr;
static int hf_nft_expr_attr_name;
static int hf_nft_list_attr;
static int hf_nft_meta_attr;
static int hf_nft_meta_dreg;
static int hf_nft_meta_key;
static int hf_nft_meta_sreg;
static int hf_nft_cmp_attr;
static int hf_nft_cmp_sreg;
static int hf_nft_cmp_op;
static int hf_nft_payload_attr;
static int hf_nft_payload_dreg;
static int hf_nft_payload_base;
static int hf_nft_payload_offset;
static int hf_nft_payload_len;
static int hf_nft_payload_sreg;
static int hf_nft_payload_csum_type;
static int hf_nft_payload_csum_offset;
static int hf_nft_payload_csum_flags;
static int hf_nft_immediate_attr;
static int hf_nft_immediate_dreg;
static int hf_nft_nat_attr;
static int hf_nft_nat_type;
static int hf_nft_nat_family;
static int hf_nft_nat_reg_addr_min;
static int hf_nft_nat_reg_addr_max;
static int hf_nft_nat_reg_proto_min;
static int hf_nft_nat_reg_proto_max;
static int hf_nft_nat_flags;
static int hf_nft_data_attr;
static int hf_nft_data_value;
static int hf_padding;

static int ett_netlink_netfilter;
static int ett_nfct_attr;
static int ett_nfct_help_attr;
static int ett_nfct_seqadj_attr;
static int ett_nfct_status_attr;
static int ett_nfct_tuple_attr;
static int ett_nfct_tuple_ip_attr;
static int ett_nfct_tuple_proto_attr;
static int ett_nfq_config_attr;
static int ett_nfq_attr;
static int ett_nfexp_attr;
static int ett_nfexp_flags_attr;
static int ett_nfexp_nat_attr;
static int ett_ipset_attr;
static int ett_ipset_cadt_attr;
static int ett_ipset_adt_attr;
static int ett_ipset_ip_attr;
static int ett_nft_rule_attr;
static int ett_nft_rule_compat_attr;
static int ett_nft_expr_attr;
static int ett_nft_list_attr;
static int ett_nft_meta_attr;
static int ett_nft_cmp_attr;
static int ett_nft_payload_attr;
static int ett_nft_immediate_attr;
static int ett_nft_nat_attr;
static int ett_nft_data_attr;

static int dissect_netlink_netfilter_header(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	proto_tree_add_item(tree, hf_netlink_netfilter_family, tvb, offset, 1, ENC_NA);
	offset++;

	proto_tree_add_item(tree, hf_netlink_netfilter_version, tvb, offset, 1, ENC_NA);
	offset++;

	proto_tree_add_item(tree, hf_netlink_netfilter_resid, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	return offset;
}

/* tuple attribute, used by EXP and QUEUE */

static const value_string nfct_tuple_attr_vals[] = {
	{ WS_CTA_TUPLE_IP,              "IP address" },
	{ WS_CTA_TUPLE_PROTO,           "L4 protocol info" },
	{ WS_CTA_TUPLE_ZONE,            "Zone" },
	{ 0, NULL }
};

static const value_string nfct_tuple_ip_attr_vals[] = {
	{ WS_CTA_IP_V4_SRC,             "IPv4 source address" },
	{ WS_CTA_IP_V4_DST,             "IPv4 destination address" },
	{ WS_CTA_IP_V6_SRC,             "IPv6 source address" },
	{ WS_CTA_IP_V6_DST,             "IPv6 destination address" },
	{ 0, NULL }
};

static const value_string nfct_tuple_l4proto_attr_vals[] = {
	{ WS_CTA_PROTO_NUM,             "IP protocol number" },
	{ WS_CTA_PROTO_SRC_PORT,        "Source port" },
	{ WS_CTA_PROTO_DST_PORT,        "Destination port" },
	{ WS_CTA_PROTO_ICMP_ID,         "ICMPv4 ID" },
	{ WS_CTA_PROTO_ICMP_TYPE,       "ICMPv4 type" },
	{ WS_CTA_PROTO_ICMP_CODE,       "ICMPv4 code" },
	{ WS_CTA_PROTO_ICMPV6_ID,       "ICMPv6 ID" },
	{ WS_CTA_PROTO_ICMPV6_TYPE,     "ICMPv6 type" },
	{ WS_CTA_PROTO_ICMPV6_CODE,     "ICMPv6 code" },
	{ 0, NULL }
};

static int
dissect_nfct_tuple_proto_attrs(tvbuff_t *tvb, void *data _U_, struct packet_netlink_data *nl_data _U_, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_ctattr_l4proto type = (enum ws_ctattr_ip) nla_type & NLA_TYPE_MASK;

	switch (type) {
		case WS_CTA_PROTO_NUM:
			proto_tree_add_item(tree, hf_nfct_tuple_proto_num_attr, tvb, offset, len, ENC_BIG_ENDIAN);
			return 1;

		case WS_CTA_PROTO_SRC_PORT:
			proto_tree_add_item(tree, hf_nfct_tuple_proto_src_port_attr, tvb, offset, len, ENC_BIG_ENDIAN);
			return 1;

		case WS_CTA_PROTO_DST_PORT:
			proto_tree_add_item(tree, hf_nfct_tuple_proto_dst_port_attr, tvb, offset, len, ENC_BIG_ENDIAN);
			return 1;

		default:
			return 0;
	}
}

static int
dissect_nfct_tuple_ip_attrs(tvbuff_t *tvb, void *data _U_, struct packet_netlink_data *nl_data _U_, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_ctattr_ip type = (enum ws_ctattr_ip) nla_type & NLA_TYPE_MASK;

	switch (type) {
		case WS_CTA_IP_V4_SRC:
		case WS_CTA_IP_V4_DST:
			proto_tree_add_item(tree, hf_nfct_tuple_ip_attr_ipv4, tvb, offset, len, ENC_BIG_ENDIAN);
			return 1;

		case WS_CTA_IP_V6_SRC:
		case WS_CTA_IP_V6_DST:
			proto_tree_add_item(tree, hf_nfct_tuple_ip_attr_ipv6, tvb, offset, len, ENC_NA);
			return 1;

		default:
			return 0;
	}
}

static int
dissect_nfct_tuple_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_ctattr_tuple type = (enum ws_ctattr_tuple) nla_type & NLA_TYPE_MASK;
	netlink_netfilter_info_t *info = (netlink_netfilter_info_t *) data;

	switch (type) {
		case WS_CTA_TUPLE_IP:
			if (nla_type & NLA_F_NESTED)
				return dissect_netlink_attributes(tvb, hf_nfct_tuple_ip_attr, ett_nfct_tuple_ip_attr, info, nl_data,
								  tree, offset, len, dissect_nfct_tuple_ip_attrs);
			return 0;

		case WS_CTA_TUPLE_PROTO:
			if (nla_type & NLA_F_NESTED)
				return dissect_netlink_attributes(tvb, hf_nfct_tuple_proto_attr, ett_nfct_tuple_proto_attr, info, nl_data,
								  tree, offset, len, dissect_nfct_tuple_proto_attrs);
			return 0;

		case WS_CTA_TUPLE_ZONE:
			proto_tree_add_item(tree, hf_nfct_tuple_zone_attr, tvb, offset, len, ENC_BIG_ENDIAN);
			return 1;

		default:
			return 0;
	}
}

/* conntrack attributes, used by QUEUE and CT */

static const value_string nfct_attr_vals[] = {
	{ WS_CTA_TUPLE_ORIG,            "Original IP tuple" },
	{ WS_CTA_TUPLE_REPLY,           "Reply IP tuple" },
	{ WS_CTA_STATUS,                "Connection status" },
	{ WS_CTA_PROTOINFO,             "Protocol-specific info" },
	{ WS_CTA_HELP,                  "Helper" },
	{ WS_CTA_NAT_SRC,               "SNAT setup" },
	{ WS_CTA_TIMEOUT,               "Timeout" },
	{ WS_CTA_MARK,                  "Mark" },
	{ WS_CTA_COUNTERS_ORIG,         "COUNTERS_ORIG" },
	{ WS_CTA_COUNTERS_REPLY,        "COUNTERS_REPLY" },
	{ WS_CTA_USE,                   "Use count" },
	{ WS_CTA_ID,                    "ID" },
	{ WS_CTA_NAT_DST,               "DNAT setup" },
	{ WS_CTA_TUPLE_MASTER,          "Master IP tuple" },
	{ WS_CTA_SEQ_ADJ_ORIG,          "Sequence number adjustment (original direction)" },
	{ WS_CTA_SEQ_ADJ_REPLY,         "Sequence number adjustment (reply direction)" },
	{ WS_CTA_SECMARK,               "Security mark" },
	{ WS_CTA_ZONE,                  "Zone" },
	{ WS_CTA_SECCTX,                "Security context" },
	{ WS_CTA_TIMESTAMP,             "Timestamp" },
	{ WS_CTA_MARK_MASK,             "Mark mask" },
	{ WS_CTA_LABELS,                "LABELS" },
	{ WS_CTA_LABELS_MASK,           "LABELS_MASK" },
	{ WS_CTA_SYNPROXY,              "SYNPROXY" },
	{ WS_CTA_FILTER,                "FILTER" },
	{ WS_CTA_STATUS_MASK,           "STATUS_MASK" },
	{ 0, NULL }
};

static const value_string nfct_help_attr_vals[] = {
	{ WS_CTA_HELP_NAME,             "Helper name" },
	{ WS_CTA_HELP_INFO,             "Helper info" },
	{ 0, NULL }
};

static const value_string nfct_seqadj_attr_vals[] = {
	{ WS_CTA_SEQADJ_UNSPEC,         "Unspecified" },
	{ WS_CTA_SEQADJ_CORRECTION_POS, "Correction position" },
	{ WS_CTA_SEQADJ_OFFSET_BEFORE,  "Offset before" },
	{ WS_CTA_SEQADJ_OFFSET_AFTER,   "Offset after" },
	{ 0, NULL }
};

static int * const hf_nfct_attr_status_flags[] = {
	&hf_nfct_attr_status_flag_hw_offload,
	&hf_nfct_attr_status_flag_offload,
	&hf_nfct_attr_status_flag_helper,
	&hf_nfct_attr_status_flag_untracked,
	&hf_nfct_attr_status_flag_template,
	&hf_nfct_attr_status_flag_fixed_timeout,
	&hf_nfct_attr_status_flag_dying,
	&hf_nfct_attr_status_flag_dst_nat_done,
	&hf_nfct_attr_status_flag_src_nat_done,
	&hf_nfct_attr_status_flag_seq_adjust,
	&hf_nfct_attr_status_flag_dst_nat,
	&hf_nfct_attr_status_flag_src_nat,
	&hf_nfct_attr_status_flag_confirmed,
	&hf_nfct_attr_status_flag_assured,
	&hf_nfct_attr_status_flag_seen_reply,
	&hf_nfct_attr_status_flag_expected,
	NULL
};

static int
dissect_nfct_help_attrs(tvbuff_t *tvb, void *data _U_, struct packet_netlink_data *nl_data _U_, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_ctattr_help type = (enum ws_ctattr_help) nla_type & NLA_TYPE_MASK;

	switch (type) {
		case WS_CTA_HELP_NAME:
			proto_tree_add_item(tree, hf_nfct_help_attr_help_name, tvb, offset, len, ENC_UTF_8);
			return 1;

		default:
			break;
	}

	return 0;
}

static int
dissect_nfct_seqadj_attrs(tvbuff_t *tvb, void *data _U_, struct packet_netlink_data *nl_data _U_, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_ctattr_seqadj type = (enum ws_ctattr_seqadj) nla_type & NLA_TYPE_MASK;

	switch (type) {
		case WS_CTA_SEQADJ_CORRECTION_POS:
			proto_tree_add_item(tree, hf_nfct_seqadj_attr_correction_pos, tvb, offset, len, ENC_BIG_ENDIAN);
			return 1;

		case WS_CTA_SEQADJ_OFFSET_BEFORE:
			proto_tree_add_item(tree, hf_nfct_seqadj_attr_offset_before, tvb, offset, len, ENC_BIG_ENDIAN);
			return 1;

		case WS_CTA_SEQADJ_OFFSET_AFTER:
			proto_tree_add_item(tree, hf_nfct_seqadj_attr_offset_after, tvb, offset, len, ENC_BIG_ENDIAN);
			return 1;

		default:
			break;
	}

	return 0;
}

static int
dissect_nfct_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_ctattr_type type = (enum ws_ctattr_type) nla_type & NLA_TYPE_MASK;
	netlink_netfilter_info_t *info = (netlink_netfilter_info_t *) data;

	switch (type) {
		case WS_CTA_STATUS:
			proto_tree_add_bitmask(tree, tvb, offset, hf_nfct_attr_status,
					       ett_nfct_status_attr, hf_nfct_attr_status_flags, ENC_BIG_ENDIAN);
			return 1;

		case WS_CTA_TIMEOUT:
			proto_tree_add_item(tree, hf_nfct_attr_timeout, tvb, offset, len, ENC_BIG_ENDIAN);
			return 1;

		case WS_CTA_ID:
			proto_tree_add_item(tree, hf_nfct_attr_id, tvb, offset, len, ENC_BIG_ENDIAN);
			return 1;

		case WS_CTA_HELP:
			if (nla_type & NLA_F_NESTED)
				return dissect_netlink_attributes(tvb, hf_nfct_help_attr, ett_nfct_help_attr, info, nl_data,
								  tree, offset, len, dissect_nfct_help_attrs);
			return 0;

		case WS_CTA_SEQ_ADJ_ORIG:
		case WS_CTA_SEQ_ADJ_REPLY:
			if (nla_type & NLA_F_NESTED)
				return dissect_netlink_attributes(tvb, hf_nfct_seqadj_attr, ett_nfct_seqadj_attr, info, nl_data,
								  tree, offset, len, dissect_nfct_seqadj_attrs);
			return 0;

		case WS_CTA_TUPLE_ORIG:
		case WS_CTA_TUPLE_REPLY:
		case WS_CTA_TUPLE_MASTER:
			if (nla_type & NLA_F_NESTED)
				return dissect_netlink_attributes(tvb, hf_nfct_tuple_attr, ett_nfct_tuple_attr, info, nl_data,
								  tree, offset, len, dissect_nfct_tuple_attrs);
			return 0;

		default:
			return 0;
	}
}

/* CT - main */

static int
dissect_netfilter_ct(tvbuff_t *tvb, netlink_netfilter_info_t *info, struct packet_netlink_data *nl_data, proto_tree *tree, int offset)
{
	offset = dissect_netlink_netfilter_header(tvb, tree, offset);
	return dissect_netlink_attributes_to_end(tvb, hf_nfct_attr, ett_nfct_attr, info, nl_data,
						 tree, offset, dissect_nfct_attrs);
}

/* EXP */

static const value_string nfexp_type_vals[] = {
	{ WS_IPCTNL_MSG_EXP_NEW,             "New" },
	{ WS_IPCTNL_MSG_EXP_GET,             "Get" },
	{ WS_IPCTNL_MSG_EXP_DELETE,          "Delete" },
	{ WS_IPCTNL_MSG_EXP_GET_STATS_CPU,   "Get CPU stats" },
	{ 0, NULL }
};

static const value_string nfexp_attr_vals[] = {
	{ WS_CTA_EXPECT_MASTER,         "Master IP tuple" },
	{ WS_CTA_EXPECT_TUPLE,          "IP tuple" },
	{ WS_CTA_EXPECT_MASK,           "IP mask tuple" },
	{ WS_CTA_EXPECT_TIMEOUT,        "Timeout" },
	{ WS_CTA_EXPECT_ID,             "ID" },
	{ WS_CTA_EXPECT_HELP_NAME,      "Helper name" },
	{ WS_CTA_EXPECT_ZONE,           "Zone" },
	{ WS_CTA_EXPECT_FLAGS,          "Flags" },
	{ WS_CTA_EXPECT_CLASS,          "Class" },
	{ WS_CTA_EXPECT_NAT,            "NAT" },
	{ WS_CTA_EXPECT_FN,             "Expect function" },
	{ 0, NULL }
};

static const value_string nfexp_nat_attr_vals[] = {
	{ WS_CTA_EXPECT_NAT_DIR,        "Direction" },
	{ WS_CTA_EXPECT_NAT_TUPLE,      "IP tuple" },
	{ 0, NULL }
};

static const value_string nfexp_conntrack_dir_vals[] = {
	{ WS_IP_CT_DIR_ORIGINAL,        "Original direction" },
	{ WS_IP_CT_DIR_REPLY,           "Reply direction" },
	{ 0, NULL }
};

static int
dissect_nfexp_nat_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_ctattr_expect_nat type = (enum ws_ctattr_expect) nla_type & NLA_TYPE_MASK;
	netlink_netfilter_info_t *info = (netlink_netfilter_info_t *) data;

	switch (type) {
		case WS_CTA_EXPECT_NAT_DIR:
			proto_tree_add_item(tree, hf_nfexp_nat_attr_dir, tvb, offset, len, ENC_BIG_ENDIAN);
			return 1;

		case WS_CTA_EXPECT_NAT_TUPLE:
			if (nla_type & NLA_F_NESTED)
				return dissect_netlink_attributes(tvb, hf_nfct_tuple_attr, ett_nfct_tuple_attr, info, nl_data,
								  tree, offset, len, dissect_nfct_tuple_attrs);
			return 0;

		default:
			return 0;
	}
}

/* CTA_EXPECT_FLAGS bitfield */
static int * const hf_nfexp_attr_flags_bitfield[] = {
	&hf_nfexp_attr_flag_userspace,
	&hf_nfexp_attr_flag_inactive,
	&hf_nfexp_attr_flag_permanent,
	NULL
};

static int
dissect_nfexp_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_ctattr_expect type = (enum ws_ctattr_expect) nla_type & NLA_TYPE_MASK;
	netlink_netfilter_info_t *info = (netlink_netfilter_info_t *) data;

	switch (type) {
		case WS_CTA_EXPECT_TUPLE:
		case WS_CTA_EXPECT_MASK:
		case WS_CTA_EXPECT_MASTER:
			if (nla_type & NLA_F_NESTED)
				return dissect_netlink_attributes(tvb, hf_nfct_tuple_attr, ett_nfct_tuple_attr, info, nl_data,
								  tree, offset, len, dissect_nfct_tuple_attrs);
			return 0;

		case WS_CTA_EXPECT_NAT:
			if (nla_type & NLA_F_NESTED)
				return dissect_netlink_attributes(tvb, hf_nfexp_nat_attr, ett_nfexp_nat_attr, info, nl_data,
								  tree, offset, len, dissect_nfexp_nat_attrs);
			return 0;

		case WS_CTA_EXPECT_TIMEOUT:
			proto_tree_add_item(tree, hf_nfexp_attr_timeout, tvb, offset, len, ENC_BIG_ENDIAN);
			return 1;

		case WS_CTA_EXPECT_ID:
			proto_tree_add_item(tree, hf_nfexp_attr_id, tvb, offset, len, ENC_BIG_ENDIAN);
			return 1;

		case WS_CTA_EXPECT_CLASS:
			proto_tree_add_item(tree, hf_nfexp_attr_class, tvb, offset, len, ENC_BIG_ENDIAN);
			return 1;

		case WS_CTA_EXPECT_ZONE:
			proto_tree_add_item(tree, hf_nfexp_attr_zone, tvb, offset, len, ENC_BIG_ENDIAN);
			return 1;

		case WS_CTA_EXPECT_FN:
			proto_tree_add_item(tree, hf_nfexp_attr_fn, tvb, offset, len, ENC_UTF_8);
			return 1;

		case WS_CTA_EXPECT_FLAGS:
			proto_tree_add_bitmask(tree, tvb, offset, hf_nfexp_attr_flags,
					       ett_nfexp_flags_attr, hf_nfexp_attr_flags_bitfield, ENC_BIG_ENDIAN);
			return 1;

		default:
			return 0;
	}
}

/* EXP - main */

static int
dissect_netfilter_exp(tvbuff_t *tvb, netlink_netfilter_info_t *info, struct packet_netlink_data *nl_data, proto_tree *tree, int offset)
{
	//enum ws_ctnl_exp_msg_types type = (enum ws_ctnl_exp_msg_types) (info->data->type & 0xff);

	offset = dissect_netlink_netfilter_header(tvb, tree, offset);
	return dissect_netlink_attributes_to_end(tvb, hf_nfexp_attr, ett_nfexp_attr, info, nl_data,
						 tree, offset, dissect_nfexp_attrs);
}

/* QUEUE */

/* QUEUE - Config */

static const value_string nfq_type_vals[] = {
	{ WS_NFQNL_MSG_PACKET,          "Packet" },
	{ WS_NFQNL_MSG_VERDICT,         "Verdict" },
	{ WS_NFQNL_MSG_CONFIG,          "Config" },
	{ WS_NFQNL_MSG_VERDICT_BATCH,   "Verdict (batch)" },
	{ 0, NULL }
};

static const value_string nfq_config_command_vals[] = {
	{ WS_NFQNL_CFG_CMD_NONE,        "None" },
	{ WS_NFQNL_CFG_CMD_BIND,        "Bind" },
	{ WS_NFQNL_CFG_CMD_UNBIND,      "Unbind" },
	{ WS_NFQNL_CFG_CMD_PF_BIND,     "PF bind" },
	{ WS_NFQNL_CFG_CMD_PF_UNBIND,   "PF unbind" },
	{ 0, NULL }
};

static const value_string nfq_config_attr_vals[] = {
	{ WS_NFQA_CFG_UNSPEC,           "Unspecified" },
	{ WS_NFQA_CFG_CMD,              "Command" },
	{ WS_NFQA_CFG_PARAMS,           "Parameters" },
	{ WS_NFQA_CFG_QUEUE_MAXLEN,     "Maximum queue length" },
	{ WS_NFQA_CFG_MASK,             "Mask" },
	{ WS_NFQA_CFG_FLAGS,            "Flags" },
	{ 0, NULL }
};

static const value_string nfq_config_mode_vals[] = {
	{ WS_NFQNL_COPY_NONE,           "None" },
	{ WS_NFQNL_COPY_META,           "Meta" },
	{ WS_NFQNL_COPY_PACKET,         "Packet" },
	{ 0, NULL }
};

static int
dissect_nfq_config_attrs(tvbuff_t *tvb, void *data _U_, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_nfqnl_attr_config type = (enum ws_nfqnl_attr_config) nla_type;

	switch (type) {
		case WS_NFQA_CFG_UNSPEC:
			break;

		case WS_NFQA_CFG_CMD:
			if (len == 4) {
				proto_tree_add_item(tree, hf_nfq_config_command_command, tvb, offset, 1, ENC_NA);
				offset += 1;
				proto_tree_add_item(tree, hf_padding, tvb, offset, 1, ENC_NA);
				offset += 1;

				proto_tree_add_item(tree, hf_nfq_config_command_pf, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
			}
			break;

		case WS_NFQA_CFG_PARAMS:
			if (len == 5) {
				proto_tree_add_item(tree, hf_nfq_config_params_copyrange, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;

				proto_tree_add_item(tree, hf_nfq_config_params_copymode, tvb, offset, 1, ENC_NA);
				offset++;
			}
			break;

		case WS_NFQA_CFG_QUEUE_MAXLEN:
			if (len == 4) {
				proto_tree_add_item(tree, hf_nfq_config_queue_maxlen, tvb, offset, 4, nl_data->encoding);
				offset += 4;
			}
			break;

		case WS_NFQA_CFG_MASK:
			if (len == 4) {
				proto_tree_add_item(tree, hf_nfq_config_mask, tvb, offset, 4, nl_data->encoding);
				offset += 4;
			}
			break;

		case WS_NFQA_CFG_FLAGS:
			if (len == 4) {
				proto_tree_add_item(tree, hf_nfq_config_flags, tvb, offset, 4, nl_data->encoding);
				offset += 4;
			}
			break;
	}

	return offset;
}

/* QUEUE - Packet and verdict */

static const value_string nfq_attr_vals[] = {
	{ WS_NFQA_UNSPEC,               "Unspecified" },
	{ WS_NFQA_PACKET_HDR,           "Packet header" },
	{ WS_NFQA_VERDICT_HDR,          "Verdict header" },
	{ WS_NFQA_MARK,                 "Mark" },
	{ WS_NFQA_TIMESTAMP,            "Timestamp" },
	{ WS_NFQA_IFINDEX_INDEV,        "NFQA_IFINDEX_INDEV" },
	{ WS_NFQA_IFINDEX_OUTDEV,       "NFQA_IFINDEX_OUTDEV" },
	{ WS_NFQA_IFINDEX_PHYSINDEV,    "NFQA_IFINDEX_PHYSINDEV" },
	{ WS_NFQA_IFINDEX_PHYSOUTDEV,   "NFQA_IFINDEX_PHYSOUTDEV" },
	{ WS_NFQA_HWADDR,               "Hardware address" },
	{ WS_NFQA_PAYLOAD,              "Payload" },
	{ WS_NFQA_CT,                   "NFQA_CT" },
	{ WS_NFQA_CT_INFO,              "Conntrack info" },
	{ WS_NFQA_CAP_LEN,              "Length of captured packet" },
	{ WS_NFQA_SKB_INFO,             "SKB meta information" },
	{ WS_NFQA_EXP,                  "Conntrack expectation" },
	{ WS_NFQA_UID,                  "SK UID" },
	{ WS_NFQA_GID,                  "SK GID" },
	{ WS_NFQA_SECCTX,               "Security context string" },
	{ WS_NFQA_VLAN,                 "Packet VLAN info" },
	{ WS_NFQA_L2HDR,                "Full L2 header" },
	{ WS_NFQA_PRIORITY,             "Priority" },
	{ 0, NULL }
};

static const value_string nfq_verdict_vals[] = {
	{ WS_NF_DROP,   "DROP" },
	{ WS_NF_ACCEPT, "ACCEPT" },
	{ WS_NF_STOLEN, "STOLEN" },
	{ WS_NF_QUEUE,  "QUEUE" },
	{ WS_NF_REPEAT, "REPEAT" },
	{ WS_NF_STOP,   "STOP" },
	{ 0, NULL }
};

const value_string netfilter_hooks_vals[] = {
	{ WS_NF_INET_PRE_ROUTING,   "Pre-routing" },
	{ WS_NF_INET_LOCAL_IN,      "Local in" },
	{ WS_NF_INET_FORWARD,       "Forward" },
	{ WS_NF_INET_LOCAL_OUT,     "Local out" },
	{ WS_NF_INET_POST_ROUTING,  "Post-routing" },
	{ WS_NF_INET_NUMHOOKS,      "Number of hooks" },
	{ 0, NULL }
};

const value_string nfproto_family_vals[] = {
	{ WS_NFPROTO_UNSPEC,    "Unspecified" },
	{ WS_NFPROTO_INET,      "IPv4/IPv6" },
	{ WS_NFPROTO_IPV4,      "IPv4" },
	{ WS_NFPROTO_ARP,       "ARP" },
	{ WS_NFPROTO_NETDEV,    "Netdev" },
	{ WS_NFPROTO_BRIDGE,    "Bridge" },
	{ WS_NFPROTO_IPV6,      "IPv6" },
	{ WS_NFPROTO_DECNET,    "DECNET" },
	{ 0, NULL }
};

static const value_string nfq_ctinfo_vals[] = {
	{ WS_IP_CT_ESTABLISHED,         "ESTABLISHED" },
	{ WS_IP_CT_RELATED,             "RELATED" },
	{ WS_IP_CT_NEW,                 "NEW" },
	{ WS_IP_CT_IS_REPLY,            "IS_REPLY" },
/*	{ WS_IP_CT_ESTABLISHED_REPLY,   "ESTABLISHED_REPLY" }, XXX - duplicate of WS_IP_CT_ESTABLISHED */
	{ WS_IP_CT_RELATED_REPLY,       "RELATED_REPLY" },
	{ WS_IP_CT_NUMBER,              "NUMBER" },
	{ 0, NULL }
};

static int
dissect_nfq_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_nfqnl_attr_type type = (enum ws_nfqnl_attr_type) nla_type & NLA_TYPE_MASK;
	netlink_netfilter_info_t *info = (netlink_netfilter_info_t *) data;

	switch (type) {
		case WS_NFQA_UNSPEC:
			break;

		case WS_NFQA_PACKET_HDR:
			if (len == 7) {
				proto_tree_add_item(tree, hf_nfq_packet_id, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;

				proto_tree_add_item(tree, hf_nfq_packet_hwprotocol, tvb, offset, 2, ENC_BIG_ENDIAN);
				info->hw_protocol = tvb_get_ntohs(tvb, offset);
				offset += 2;

				proto_tree_add_item(tree, hf_nfq_packet_hook, tvb, offset, 1, ENC_NA);
				offset++;
			}
			break;

		case WS_NFQA_VERDICT_HDR:
			if (len == 8) {
				proto_tree_add_item(tree, hf_nfq_verdict_verdict, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;

				proto_tree_add_item(tree, hf_nfq_verdict_id, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			break;

		case WS_NFQA_MARK:
			if (len == 4) {
				proto_tree_add_item(tree, hf_nfq_nfmark, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			break;

		case WS_NFQA_TIMESTAMP:
			if (len == 16) {
				proto_tree_add_item(tree, hf_nfq_timestamp, tvb, offset, 16, ENC_TIME_SECS_NSECS|ENC_BIG_ENDIAN);
				offset += 16;
			}
			break;

		case WS_NFQA_IFINDEX_INDEV:
			if (len == 4) {
				proto_tree_add_item(tree, hf_nfq_ifindex_indev, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			break;

		case WS_NFQA_IFINDEX_OUTDEV:
			if (len == 4) {
				proto_tree_add_item(tree, hf_nfq_ifindex_outdev, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			break;

		case WS_NFQA_IFINDEX_PHYSINDEV:
			if (len == 4) {
				proto_tree_add_item(tree, hf_nfq_ifindex_physindev, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			break;

		case WS_NFQA_IFINDEX_PHYSOUTDEV:
			if (len == 4) {
				proto_tree_add_item(tree, hf_nfq_ifindex_physoutdev, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			break;

		case WS_NFQA_HWADDR:
			if (len >= 4) {
				uint16_t addrlen;

				proto_tree_add_item(tree, hf_nfq_hwaddr_len, tvb, offset, 2, ENC_BIG_ENDIAN);
				addrlen = tvb_get_ntohs(tvb, offset);
				offset += 2;
				proto_tree_add_item(tree, hf_padding, tvb, offset, 2, ENC_NA);
				offset += 2;


				/* XXX expert info if 4 + addrlen > len. */
				addrlen = MIN(addrlen, len - 4);
				proto_tree_add_item(tree, hf_nfq_hwaddr_addr, tvb, offset, addrlen, ENC_NA);
				offset += addrlen;
			}
			break;

		case WS_NFQA_PAYLOAD:
			if (len > 0) {
				tvbuff_t *next_tvb = tvb_new_subset_length(tvb, offset, len);
				proto_tree *parent_tree = proto_item_get_parent(tree);

				if (!dissector_try_uint(ethertype_table, info->hw_protocol, next_tvb, info->pinfo, parent_tree))
					call_data_dissector(next_tvb, info->pinfo, parent_tree);
				offset += len;
			}
			break;

		case WS_NFQA_CT:
			if (nla_type & NLA_F_NESTED)
				return dissect_netlink_attributes(tvb, hf_nfct_attr, ett_nfct_attr, info, nl_data,
								  tree, offset, len, dissect_nfct_attrs);
			break;

		case WS_NFQA_CT_INFO:
			if (len == 4) {
				proto_tree_add_item(tree, hf_nfq_ctinfo, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			break;

		case WS_NFQA_CAP_LEN:
			if (len == 4) {
				proto_tree_add_item(tree, hf_nfq_caplen, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			break;

		case WS_NFQA_SKB_INFO:
		case WS_NFQA_EXP:
			/* TODO */
			break;

		case WS_NFQA_UID:
			if (len == 4) {
				proto_tree_add_item(tree, hf_nfq_uid, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			break;

		case WS_NFQA_GID:
			if (len == 4) {
				proto_tree_add_item(tree, hf_nfq_gid, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			break;

		case WS_NFQA_SECCTX:
		case WS_NFQA_VLAN:
		case WS_NFQA_L2HDR:
		case WS_NFQA_PRIORITY:
			/* TODO */
			break;
	}

	return offset;
}

/* QUEUE - main */

static int
dissect_netfilter_queue(tvbuff_t *tvb, netlink_netfilter_info_t *info, struct packet_netlink_data *nl_data, proto_tree *tree, int offset)
{
	enum ws_nfqnl_msg_types type = (enum ws_nfqnl_msg_types) (nl_data->type & 0xff);

	offset = dissect_netlink_netfilter_header(tvb, tree, offset);

	switch (type) {
		case WS_NFQNL_MSG_CONFIG:
			return dissect_netlink_attributes_to_end(tvb, hf_nfq_config_attr, ett_nfq_config_attr, info, nl_data, tree, offset, dissect_nfq_config_attrs);

		case WS_NFQNL_MSG_PACKET:
		case WS_NFQNL_MSG_VERDICT:
			return dissect_netlink_attributes_to_end(tvb, hf_nfq_attr, ett_nfq_attr, info, nl_data, tree, offset, dissect_nfq_attrs);

		case WS_NFQNL_MSG_VERDICT_BATCH:
			/* TODO */
			break;
	}

	return offset;
}

/* ULOG */

static const value_string netlink_netfilter_ulog_type_vals[] = {
	{ WS_NFULNL_MSG_PACKET, "Packet" },
	{ WS_NFULNL_MSG_CONFIG, "Config" },
	{ 0, NULL }
};

static int
dissect_netfilter_ulog(tvbuff_t *tvb, netlink_netfilter_info_t *info, struct packet_netlink_data *nl_data, proto_tree *tree, int offset)
{
	enum ws_nfulnl_msg_types type = (enum ws_nfulnl_msg_types) (nl_data->type & 0xff);
	tvbuff_t *next_tvb;

	switch (type) {
		case WS_NFULNL_MSG_PACKET:
			/* Note that NFLOG dissects the nfgenmsg header */
			next_tvb = tvb_new_subset_remaining(tvb, offset);
			call_dissector(nflog_handle, next_tvb, info->pinfo, tree);
			offset = tvb_reported_length(tvb);
			break;

		default:
			break;
	}

	return offset;
}

/* IPSET */

static const value_string ipset_command_vals[] = {
	{ WS_IPSET_CMD_NONE,        "None" },
	{ WS_IPSET_CMD_PROTOCOL,    "Return protocol version" },
	{ WS_IPSET_CMD_CREATE,      "Create a new (empty) set" },
	{ WS_IPSET_CMD_DESTROY,     "Destroy a (empty) set" },
	{ WS_IPSET_CMD_FLUSH,       "Remove all elements from a set" },
	{ WS_IPSET_CMD_RENAME,      "Rename a set" },
	{ WS_IPSET_CMD_SWAP,        "Swap two sets" },
	{ WS_IPSET_CMD_LIST,        "List sets" },
	{ WS_IPSET_CMD_SAVE,        "Save sets" },
	{ WS_IPSET_CMD_ADD,         "Add an element to a set" },
	{ WS_IPSET_CMD_DEL,         "Delete an element from a set" },
	{ WS_IPSET_CMD_TEST,        "Test an element in a set" },
	{ WS_IPSET_CMD_HEADER,      "Get set header data only" },
	{ WS_IPSET_CMD_TYPE,        "Get set type" },
	{ WS_IPSET_CMD_GET_BYNAME,  "Get set by name" },
	{ WS_IPSET_CMD_GET_BYINDEX, "Get set by index" },
	{ 0, NULL }
};

static const value_string ipset_attr_vals[] = {
	{ WS_IPSET_ATTR_PROTOCOL,       "Protocol version" },
	{ WS_IPSET_ATTR_SETNAME,        "Name of the set" },
	{ WS_IPSET_ATTR_TYPENAME,       "Typename" },
	{ WS_IPSET_ATTR_REVISION,       "Settype revision" },
	{ WS_IPSET_ATTR_FAMILY,         "Settype family" },
	{ WS_IPSET_ATTR_FLAGS,          "Flags at command level" },
	{ WS_IPSET_ATTR_DATA,           "Nested attributes" },
	{ WS_IPSET_ATTR_ADT,            "Multiple data containers" },
	{ WS_IPSET_ATTR_LINENO,         "Restore lineno" },
	{ WS_IPSET_ATTR_PROTOCOL_MIN,   "Minimal supported version number" },
	{ WS_IPSET_ATTR_INDEX,          "Index" },
	{ 0, NULL }
};

static const value_string ipset_cadt_attr_vals[] = {
	{ WS_IPSET_ATTR_IP_FROM,        "IP_FROM" },
	{ WS_IPSET_ATTR_IP_TO,          "IP_TO" },
	{ WS_IPSET_ATTR_CIDR,           "CIDR" },
	{ WS_IPSET_ATTR_PORT_FROM,      "PORT_FROM" },
	{ WS_IPSET_ATTR_PORT_TO,        "PORT_TO" },
	{ WS_IPSET_ATTR_TIMEOUT,        "TIMEOUT" },
	{ WS_IPSET_ATTR_PROTO,          "PROTO" },
	{ WS_IPSET_ATTR_CADT_FLAGS,     "CADT_FLAGS" },
	{ WS_IPSET_ATTR_CADT_LINENO,    "CADT_LINENO" },
	{ WS_IPSET_ATTR_MARK,           "MARK" },
	{ WS_IPSET_ATTR_MARKMASK,       "MARKMASK" },
	{ WS_IPSET_ATTR_BITMASK,        "BITMASK" },
	/* up to 16 is reserved. */
	{ WS_IPSET_ATTR_INITVAL,        "INITVAL" },
	{ WS_IPSET_ATTR_HASHSIZE,       "HASHSIZE" },
	{ WS_IPSET_ATTR_MAXELEM,        "MAXELEM" },
	{ WS_IPSET_ATTR_NETMASK,        "NETMASK" },
	{ WS_IPSET_ATTR_BUCKETSIZE,     "BUCKETSIZE" },
	{ WS_IPSET_ATTR_RESIZE,         "RESIZE" },
	{ WS_IPSET_ATTR_SIZE,           "SIZE" },
	{ WS_IPSET_ATTR_ELEMENTS,       "ELEMENTS" },
	{ WS_IPSET_ATTR_REFERENCES,     "REFERENCES" },
	{ WS_IPSET_ATTR_MEMSIZE,        "MEMSIZE" },
	{ 0, NULL }
};

static const value_string ipset_adt_attr_vals[] = {
	/* Nasty! Duplication from CADT above... */
	{ WS_IPSET_ATTR_IP_FROM,        "IP_FROM" },
	{ WS_IPSET_ATTR_IP_TO,          "IP_TO" },
	{ WS_IPSET_ATTR_CIDR,           "CIDR" },
	{ WS_IPSET_ATTR_PORT_FROM,      "PORT_FROM" },
	{ WS_IPSET_ATTR_PORT_TO,        "PORT_TO" },
	{ WS_IPSET_ATTR_TIMEOUT,        "TIMEOUT" },
	{ WS_IPSET_ATTR_PROTO,          "PROTO" },
	{ WS_IPSET_ATTR_CADT_FLAGS,     "CADT_FLAGS" },
	{ WS_IPSET_ATTR_CADT_LINENO,    "CADT_LINENO" },
	{ WS_IPSET_ATTR_MARK,           "MARK" },
	{ WS_IPSET_ATTR_MARKMASK,       "MARKMASK" },
	/* End of duplication, other attributes follow. */
	{ WS_IPSET_ATTR_ETHER,          "ETHER" },
	{ WS_IPSET_ATTR_NAME,           "NAME" },
	{ WS_IPSET_ATTR_NAMEREF,        "NAMEREF" },
	{ WS_IPSET_ATTR_IP2,            "IP2" },
	{ WS_IPSET_ATTR_CIDR2,          "CIDR2" },
	{ WS_IPSET_ATTR_IP2_TO,         "IP2_TO" },
	{ WS_IPSET_ATTR_IFACE,          "IFACE" },
	{ WS_IPSET_ATTR_BYTES,          "BYTES" },
	{ WS_IPSET_ATTR_PACKETS,        "PACKETS" },
	{ WS_IPSET_ATTR_COMMENT,        "COMMENT" },
	{ WS_IPSET_ATTR_SKBMARK,        "SKBMARK" },
	{ WS_IPSET_ATTR_SKBPRIO,        "SKBPRIO" },
	{ WS_IPSET_ATTR_SKBQUEUE,       "SKBQUEUE" },
	{ WS_IPSET_ATTR_PAD,            "PAD" },
	{ 0, NULL }
};

static const value_string ipset_ip_attr_vals[] = {
	{ WS_IPSET_ATTR_IPADDR_IPV4,    "IPv4 address" },
	{ WS_IPSET_ATTR_IPADDR_IPV6,    "IPv6 address" },
	{ 0, NULL }
};

static int
dissect_ipset_ip_attrs(tvbuff_t *tvb, void *data _U_, struct packet_netlink_data *nl_data _U_, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_ipset_ip_attr type = (enum ws_ipset_ip_attr) nla_type & NLA_TYPE_MASK;

	switch (type) {
		case WS_IPSET_ATTR_IPADDR_IPV4:
			proto_tree_add_item(tree, hf_ipset_ip_attr_ipv4, tvb, offset, len, ENC_BIG_ENDIAN);
			return 1;

		case WS_IPSET_ATTR_IPADDR_IPV6:
			proto_tree_add_item(tree, hf_ipset_ip_attr_ipv6, tvb, offset, len, ENC_NA);
			return 1;
	}

	return 0;
}

static int
dissect_ipset_cadt_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_ipset_cadt_attr type = (enum ws_ipset_cadt_attr) nla_type & NLA_TYPE_MASK;
	netlink_netfilter_info_t *info = (netlink_netfilter_info_t *) data;

	switch (type) {
		case WS_IPSET_ATTR_IP_FROM:
		case WS_IPSET_ATTR_IP_TO:
			if (nla_type & NLA_F_NESTED)
				return dissect_netlink_attributes(tvb, hf_ipset_ip_attr, ett_ipset_ip_attr, info, nl_data, tree, offset, len, dissect_ipset_ip_attrs);
			return 0;

		case WS_IPSET_ATTR_CIDR:
			if (len == 1) {
				proto_tree_add_item(tree, hf_ipset_cadt_attr_cidr, tvb, offset, len, ENC_NA);
				return 1;
			}
			return 0;

		case WS_IPSET_ATTR_PORT_FROM:
		case WS_IPSET_ATTR_PORT_TO:
			/* TODO */
			return 0;

		case WS_IPSET_ATTR_TIMEOUT:
			if (len == 4) {
				proto_tree_add_item(tree, hf_ipset_cadt_attr_timeout, tvb, offset, len, ENC_BIG_ENDIAN);
				return 1;
			}
			return 0;

		case WS_IPSET_ATTR_PROTO:
			/* TODO */
			return 0;

		case WS_IPSET_ATTR_CADT_FLAGS:
			if (len == 4) {
				proto_tree_add_item(tree, hf_ipset_cadt_attr_cadt_flags, tvb, offset, len, ENC_BIG_ENDIAN);
				/* TODO show bits from enum ipset_cadt_flags */
				return 1;
			}
			return 0;

		case WS_IPSET_ATTR_CADT_LINENO:
		case WS_IPSET_ATTR_MARK:
		case WS_IPSET_ATTR_MARKMASK:
		case WS_IPSET_ATTR_BITMASK:
		case WS_IPSET_ATTR_INITVAL:
		case WS_IPSET_ATTR_HASHSIZE:
		case WS_IPSET_ATTR_MAXELEM:
		case WS_IPSET_ATTR_NETMASK:
		case WS_IPSET_ATTR_BUCKETSIZE:
		case WS_IPSET_ATTR_RESIZE:
		case WS_IPSET_ATTR_SIZE:
		case WS_IPSET_ATTR_ELEMENTS:
		case WS_IPSET_ATTR_REFERENCES:
		case WS_IPSET_ATTR_MEMSIZE:
			/* TODO */
			return 0;
	}

	return 0;
}

static int
dissect_ipset_adt_data_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_ipset_adt_attr type = (enum ws_ipset_adt_attr) nla_type & NLA_TYPE_MASK;

	if ((nla_type & NLA_TYPE_MASK) <= WS_IPSET_ATTR_CADT_MAX)
		return dissect_ipset_cadt_attrs(tvb, data, nl_data, tree, nla_type, offset, len);

	switch (type) {
		case WS_IPSET_ATTR_COMMENT:
			proto_tree_add_item(tree, hf_ipset_adt_attr_comment, tvb, offset, len, ENC_UTF_8);
			return 1;

		default:
			return 0;
	}

	return 0;
}

static int
dissect_ipset_adt_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	netlink_netfilter_info_t *info = (netlink_netfilter_info_t *) data;

	if (nla_type & NLA_F_NESTED)
		return dissect_netlink_attributes(tvb, hf_ipset_adt_attr, ett_ipset_adt_attr, info, nl_data, tree, offset, len, dissect_ipset_adt_data_attrs);
	return 0;
}

static int
dissect_ipset_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_ipset_attr type = (enum ws_ipset_attr) nla_type & NLA_TYPE_MASK;
	netlink_netfilter_info_t *info = (netlink_netfilter_info_t *) data;

	switch (type) {
		case WS_IPSET_ATTR_PROTOCOL:
			/* TODO */
			return 0;

		case WS_IPSET_ATTR_SETNAME:
			proto_tree_add_item(tree, hf_ipset_attr_setname, tvb, offset, len, ENC_UTF_8);
			return 1;

		case WS_IPSET_ATTR_TYPENAME:
			proto_tree_add_item(tree, hf_ipset_attr_typename, tvb, offset, len, ENC_UTF_8);
			return 1;

		case WS_IPSET_ATTR_REVISION:
			/* TODO */
			return 0;

		case WS_IPSET_ATTR_FAMILY:
			proto_tree_add_item(tree, hf_ipset_attr_family, tvb, offset, len, ENC_BIG_ENDIAN);
			return 1;

		case WS_IPSET_ATTR_FLAGS:
			if (len == 4) {
				proto_tree_add_item(tree, hf_ipset_attr_flags, tvb, offset, len, ENC_BIG_ENDIAN);
				/* TODO show bits from enum ipset_cmd_flags */
				return 1;
			}
			return 0;

		case WS_IPSET_ATTR_DATA:
			/* See ipset lib/PROTOCOL, CADT attributes only follow for some commands */
			if (nla_type & NLA_F_NESTED) {
				uint16_t command = nl_data->type & 0xffff;

				if (command == WS_IPSET_CMD_CREATE ||
				    command == WS_IPSET_CMD_LIST ||
				    command == WS_IPSET_CMD_SAVE)
					return dissect_netlink_attributes(tvb, hf_ipset_cadt_attr, ett_ipset_cadt_attr, info, nl_data, tree, offset, len, dissect_ipset_cadt_attrs);
				else
					return dissect_netlink_attributes(tvb, hf_ipset_adt_attr, ett_ipset_adt_attr, info, nl_data, tree, offset, len, dissect_ipset_adt_data_attrs);
			}
			return 0;

		case WS_IPSET_ATTR_ADT:
			/* Following this, there will be an IPSET_ATTR_DATA with regular ADT attributes, not CADT */
			if (nla_type & NLA_F_NESTED)
				return dissect_netlink_attributes(tvb, hf_ipset_attr, ett_ipset_attr, info, nl_data, tree, offset, len, dissect_ipset_adt_attrs);
			return 0;

		case WS_IPSET_ATTR_LINENO:
		case WS_IPSET_ATTR_PROTOCOL_MIN:
		case WS_IPSET_ATTR_INDEX:
			/* TODO */
			return 0;
	}

	return 0;
}

static int
dissect_netfilter_ipset(tvbuff_t *tvb, netlink_netfilter_info_t *info, struct packet_netlink_data *nl_data, proto_tree *tree, int offset)
{
	offset = dissect_netlink_netfilter_header(tvb, tree, offset);
	return dissect_netlink_attributes_to_end(tvb, hf_ipset_attr, ett_ipset_attr, info, nl_data, tree, offset, dissect_ipset_attrs);
}

/* NFTABLES */

/* Netfilter commands from <include/uapi/linux/netfilter/netfilter.h> */
enum nf_tables_msg_types {
	WS_NFT_MSG_NEWTABLE             = 0,
	WS_NFT_MSG_GETTABLE             = 1,
	WS_NFT_MSG_DELTABLE             = 2,
	WS_NFT_MSG_NEWCHAIN             = 3,
	WS_NFT_MSG_GETCHAIN             = 4,
	WS_NFT_MSG_DELCHAIN             = 5,
	WS_NFT_MSG_NEWRULE              = 6,
	WS_NFT_MSG_GETRULE              = 7,
	WS_NFT_MSG_DELRULE              = 8,
	WS_NFT_MSG_NEWSET               = 9,
	WS_NFT_MSG_GETSET               = 10,
	WS_NFT_MSG_DELSET               = 11,
	WS_NFT_MSG_NEWSETELEM           = 12,
	WS_NFT_MSG_GETSETELEM           = 13,
	WS_NFT_MSG_DELSETELEM           = 14,
	WS_NFT_MSG_NEWGEN               = 15,
	WS_NFT_MSG_GETGEN               = 16,
	WS_NFT_MSG_TRACE                = 17,
	WS_NFT_MSG_NEWOBJ               = 18,
	WS_NFT_MSG_GETOBJ               = 19,
	WS_NFT_MSG_DELOBJ               = 20,
	WS_NFT_MSG_GETOBJ_RESET         = 21,
	WS_NFT_MSG_NEWFLOWTABLE         = 22,
	WS_NFT_MSG_GETFLOWTABLE         = 23,
	WS_NFT_MSG_DELFLOWTABLE         = 24,
	WS_NFT_MSG_GETRULE_RESET        = 25,
	WS_NFT_MSG_DESTROYTABLE         = 26,
	WS_NFT_MSG_DESTROYCHAIN         = 27,
	WS_NFT_MSG_DESTROYRULE          = 28,
	WS_NFT_MSG_DESTROYSET           = 29,
	WS_NFT_MSG_DESTROYSETELEM       = 30,
	WS_NFT_MSG_DESTROYOBJ           = 31,
	WS_NFT_MSG_DESTROYFLOWTABLE     = 32,
	WS_NFT_MSG_GETSETELEM_RESET     = 33,
};

/* nftables rule attributes from <include/uapi/linux/netfilter/nf_tables.h> */
enum ws_nft_rule_attributes {
	WS_NFTA_RULE_UNSPEC      = 0,
	WS_NFTA_RULE_TABLE       = 1,
	WS_NFTA_RULE_CHAIN       = 2,
	WS_NFTA_RULE_HANDLE      = 3,
	WS_NFTA_RULE_EXPRESSIONS = 4,
	WS_NFTA_RULE_COMPAT      = 5,
	WS_NFTA_RULE_POSITION    = 6,
	WS_NFTA_RULE_USERDATA    = 7,
	WS_NFTA_RULE_PAD         = 8,
	WS_NFTA_RULE_ID          = 9,
	WS_NFTA_RULE_POSITION_ID = 10,
	WS_NFTA_RULE_CHAIN_ID    = 11,
};

/* nftables rule compat attributes from <include/uapi/linux/netfilter/nf_tables.h> */
enum ws_nft_rule_compat_attributes {
	WS_NFTA_RULE_COMPAT_UNSPEC = 0,
	WS_NFTA_RULE_COMPAT_PROTO  = 1,
	WS_NFTA_RULE_COMPAT_FLAGS  = 2,
};

/* nftables expression attributes from <include/uapi/linux/netfilter/nf_tables.h> */
enum ws_nft_expr_attributes {
	WS_NFTA_EXPR_UNSPEC = 0,
	WS_NFTA_EXPR_NAME   = 1,
	WS_NFTA_EXPR_DATA   = 2,
};

/* nftables list attributes from <include/uapi/linux/netfilter/nf_tables.h> */
enum ws_nft_list_attributes {
	WS_NFTA_LIST_UNSPEC = 0,
	WS_NFTA_LIST_ELEM   = 1,
};

/* nftables meta expression attributes from <include/uapi/linux/netfilter/nf_tables.h> */
enum ws_nft_meta_attributes {
	WS_NFTA_META_UNSPEC = 0,
	WS_NFTA_META_DREG   = 1,
	WS_NFTA_META_KEY    = 2,
	WS_NFTA_META_SREG   = 3,
};

/* nftables meta expression keys from <include/uapi/linux/netfilter/nf_tables.h> */
enum ws_nft_meta_keys {
	WS_NFT_META_LEN          = 0,
	WS_NFT_META_PROTOCOL     = 1,
	WS_NFT_META_PRIORITY     = 2,
	WS_NFT_META_MARK         = 3,
	WS_NFT_META_IIF          = 4,
	WS_NFT_META_OIF          = 5,
	WS_NFT_META_IIFNAME      = 6,
	WS_NFT_META_OIFNAME      = 7,
	WS_NFT_META_IFTYPE       = 8,
	WS_NFT_META_OIFTYPE      = 9,
	WS_NFT_META_SKUID        = 10,
	WS_NFT_META_SKGID        = 11,
	WS_NFT_META_NFTRACE      = 12,
	WS_NFT_META_RTCLASSID    = 13,
	WS_NFT_META_SECMARK      = 14,
	WS_NFT_META_NFPROTO      = 15,
	WS_NFT_META_L4PROTO      = 16,
	WS_NFT_META_BRI_IIFNAME  = 17,
	WS_NFT_META_BRI_OIFNAME  = 18,
	WS_NFT_META_PKTTYPE      = 19,
	WS_NFT_META_CPU          = 20,
	WS_NFT_META_IIFGROUP     = 21,
	WS_NFT_META_OIFGROUP     = 22,
	WS_NFT_META_CGROUP       = 23,
	WS_NFT_META_PRANDOM      = 24,
	WS_NFT_META_SECPATH      = 25,
	WS_NFT_META_IIFKIND      = 26,
	WS_NFT_META_OIFKIND      = 27,
	WS_NFT_META_BRI_IIFPVID  = 28,
	WS_NFT_META_BRI_IIFVPROTO = 29,
	WS_NFT_META_TIME_NS      = 30,
	WS_NFT_META_TIME_DAY     = 31,
	WS_NFT_META_TIME_HOUR    = 32,
	WS_NFT_META_SDIF         = 33,
	WS_NFT_META_SDIFNAME     = 34,
	WS_NFT_META_BRI_BROUTE   = 35,
	WS_NFT_META_BRI_IIFHWADDR = 37,
};

/* nftables cmp expression attributes from <include/uapi/linux/netfilter/nf_tables.h> */
enum ws_nft_cmp_attributes {
	WS_NFTA_CMP_UNSPEC = 0,
	WS_NFTA_CMP_SREG   = 1,
	WS_NFTA_CMP_OP     = 2,
	WS_NFTA_CMP_DATA   = 3,
};

/* nftables cmp expression operations from <include/uapi/linux/netfilter/nf_tables.h> */
enum ws_nft_cmp_ops {
	WS_NFT_CMP_EQ  = 0,
	WS_NFT_CMP_NEQ = 1,
	WS_NFT_CMP_LT  = 2,
	WS_NFT_CMP_LTE = 3,
	WS_NFT_CMP_GT  = 4,
	WS_NFT_CMP_GTE = 5,
};

/* nftables payload expression attributes from <include/uapi/linux/netfilter/nf_tables.h> */
enum ws_nft_payload_attributes {
	WS_NFTA_PAYLOAD_UNSPEC      = 0,
	WS_NFTA_PAYLOAD_DREG        = 1,
	WS_NFTA_PAYLOAD_BASE        = 2,
	WS_NFTA_PAYLOAD_OFFSET      = 3,
	WS_NFTA_PAYLOAD_LEN         = 4,
	WS_NFTA_PAYLOAD_SREG        = 5,
	WS_NFTA_PAYLOAD_CSUM_TYPE   = 6,
	WS_NFTA_PAYLOAD_CSUM_OFFSET = 7,
	WS_NFTA_PAYLOAD_CSUM_FLAGS  = 8,
};

/* nftables immediate expression attributes from <include/uapi/linux/netfilter/nf_tables.h> */
enum ws_nft_immediate_attributes {
	WS_NFTA_IMMEDIATE_UNSPEC = 0,
	WS_NFTA_IMMEDIATE_DREG   = 1,
	WS_NFTA_IMMEDIATE_DATA   = 2,
};

/* nftables NAT expression attributes from <include/uapi/linux/netfilter/nf_tables.h> */
enum ws_nft_nat_attributes {
	WS_NFTA_NAT_UNSPEC         = 0,
	WS_NFTA_NAT_TYPE           = 1,
	WS_NFTA_NAT_FAMILY         = 2,
	WS_NFTA_NAT_REG_ADDR_MIN   = 3,
	WS_NFTA_NAT_REG_ADDR_MAX   = 4,
	WS_NFTA_NAT_REG_PROTO_MIN  = 5,
	WS_NFTA_NAT_REG_PROTO_MAX  = 6,
	WS_NFTA_NAT_FLAGS          = 7,
};

/* nftables NAT expression types from <include/uapi/linux/netfilter/nf_tables.h> */
enum ws_nft_nat_types {
	WS_NFT_NAT_SNAT = 0,
	WS_NFT_NAT_DNAT = 1,
};

/* nftables data attributes from <include/uapi/linux/netfilter/nf_tables.h> */
enum ws_nft_data_attributes {
	WS_NFTA_DATA_UNSPEC  = 0,
	WS_NFTA_DATA_VALUE   = 1,
	WS_NFTA_DATA_VERDICT = 2,
};

typedef struct {
	netlink_netfilter_info_t *base;
	uint32_t key;
	uint32_t dreg;
	uint32_t sreg;
	bool has_key;
	bool has_dreg;
	bool has_sreg;
} nft_meta_ctx_t;

typedef struct {
	const uint8_t *data;
	uint32_t data_len;
	bool has_data;
} nft_data_ctx_t;

typedef struct {
	netlink_netfilter_info_t *base;
	uint32_t op;
	uint32_t sreg;
	nft_data_ctx_t data_ctx;
	bool has_op;
	bool has_sreg;
} nft_cmp_ctx_t;

typedef struct {
	netlink_netfilter_info_t *base;
	uint32_t dreg;
	uint32_t sreg;
	uint32_t base_field;
	uint32_t offset;
	uint32_t len;
	uint32_t csum_type;
	uint32_t csum_offset;
	uint32_t csum_flags;
	bool has_dreg;
	bool has_sreg;
	bool has_base;
	bool has_offset;
	bool has_len;
	bool has_csum_type;
	bool has_csum_offset;
	bool has_csum_flags;
} nft_payload_ctx_t;

typedef struct {
	netlink_netfilter_info_t *base;
	uint32_t dreg;
	nft_data_ctx_t data_ctx;
	bool has_dreg;
} nft_immediate_ctx_t;

typedef struct {
	netlink_netfilter_info_t *base;
	uint32_t type;
	uint32_t family;
	uint32_t reg_addr_min;
	uint32_t reg_addr_max;
	uint32_t reg_proto_min;
	uint32_t reg_proto_max;
	uint32_t flags;
	bool has_type;
	bool has_family;
	bool has_reg_addr_min;
	bool has_reg_addr_max;
	bool has_reg_proto_min;
	bool has_reg_proto_max;
	bool has_flags;
} nft_nat_ctx_t;

typedef struct {
	netlink_netfilter_info_t *base;
	const char *expr_name;
} nft_expr_ctx_t;


static const value_string nft_rule_attr_vals[] = {
	{ WS_NFTA_RULE_UNSPEC,      "Unspecified" },
	{ WS_NFTA_RULE_TABLE,       "Table" },
	{ WS_NFTA_RULE_CHAIN,       "Chain" },
	{ WS_NFTA_RULE_HANDLE,      "Handle" },
	{ WS_NFTA_RULE_EXPRESSIONS, "Expressions" },
	{ WS_NFTA_RULE_COMPAT,      "Compatibility" },
	{ WS_NFTA_RULE_POSITION,    "Position" },
	{ WS_NFTA_RULE_USERDATA,    "User data" },
	{ WS_NFTA_RULE_PAD,         "Padding" },
	{ WS_NFTA_RULE_ID,          "ID" },
	{ WS_NFTA_RULE_POSITION_ID, "Position ID" },
	{ WS_NFTA_RULE_CHAIN_ID,    "Chain ID" },
	{ 0, NULL }
};

static const value_string nft_rule_compat_attr_vals[] = {
	{ WS_NFTA_RULE_COMPAT_UNSPEC, "Unspecified" },
	{ WS_NFTA_RULE_COMPAT_PROTO,  "Protocol" },
	{ WS_NFTA_RULE_COMPAT_FLAGS,  "Flags" },
	{ 0, NULL }
};

static const value_string nft_expr_attr_vals[] = {
	{ WS_NFTA_EXPR_UNSPEC, "Unspecified" },
	{ WS_NFTA_EXPR_NAME,   "Name" },
	{ WS_NFTA_EXPR_DATA,   "Data" },
	{ 0, NULL }
};

static const value_string nft_list_attr_vals[] = {
	{ WS_NFTA_LIST_UNSPEC, "Unspecified" },
	{ WS_NFTA_LIST_ELEM,   "Element" },
	{ 0, NULL }
};

static const value_string nft_meta_attr_vals[] = {
	{ WS_NFTA_META_UNSPEC, "Unspecified" },
	{ WS_NFTA_META_DREG,   "Destination register" },
	{ WS_NFTA_META_KEY,    "Key" },
	{ WS_NFTA_META_SREG,   "Source register" },
	{ 0, NULL }
};

static const value_string nft_meta_key_vals[] = {
	{ WS_NFT_META_LEN,          "Packet length" },
	{ WS_NFT_META_PROTOCOL,     "Ethertype protocol" },
	{ WS_NFT_META_PRIORITY,     "TC packet priority" },
	{ WS_NFT_META_MARK,         "Netfilter packet mark" },
	{ WS_NFT_META_IIF,          "Input interface index" },
	{ WS_NFT_META_OIF,          "Output interface index" },
	{ WS_NFT_META_IIFNAME,      "Input interface name" },
	{ WS_NFT_META_OIFNAME,      "Output interface name" },
	{ WS_NFT_META_IFTYPE,       "Input interface type" },
	{ WS_NFT_META_OIFTYPE,      "Output interface type" },
	{ WS_NFT_META_SKUID,        "Originating socket UID" },
	{ WS_NFT_META_SKGID,        "Originating socket GID" },
	{ WS_NFT_META_NFTRACE,      "Packet nftrace bit" },
	{ WS_NFT_META_RTCLASSID,    "Routing realm" },
	{ WS_NFT_META_SECMARK,      "Packet secmark" },
	{ WS_NFT_META_NFPROTO,      "Netfilter protocol" },
	{ WS_NFT_META_L4PROTO,      "Layer 4 protocol" },
	{ WS_NFT_META_BRI_IIFNAME,  "Bridge input interface name" },
	{ WS_NFT_META_BRI_OIFNAME,  "Bridge output interface name" },
	{ WS_NFT_META_PKTTYPE,      "Packet type" },
	{ WS_NFT_META_CPU,          "CPU ID" },
	{ WS_NFT_META_IIFGROUP,     "Input interface group" },
	{ WS_NFT_META_OIFGROUP,     "Output interface group" },
	{ WS_NFT_META_CGROUP,       "Control group ID" },
	{ WS_NFT_META_PRANDOM,      "Pseudo-random number" },
	{ WS_NFT_META_SECPATH,      "Has security path" },
	{ WS_NFT_META_IIFKIND,      "Input interface kind" },
	{ WS_NFT_META_OIFKIND,      "Output interface kind" },
	{ WS_NFT_META_BRI_IIFPVID,  "Bridge input port PVID" },
	{ WS_NFT_META_BRI_IIFVPROTO, "Bridge input VLAN proto" },
	{ WS_NFT_META_TIME_NS,      "Time since epoch (ns)" },
	{ WS_NFT_META_TIME_DAY,     "Day of week" },
	{ WS_NFT_META_TIME_HOUR,    "Hour of day" },
	{ WS_NFT_META_SDIF,         "Slave device interface index" },
	{ WS_NFT_META_SDIFNAME,     "Slave device interface name" },
	{ WS_NFT_META_BRI_BROUTE,   "Bridge broute bit" },
	{ WS_NFT_META_BRI_IIFHWADDR, "Bridge input interface hardware address" },
	{ 0, NULL }
};

static const value_string nft_cmp_attr_vals[] = {
	{ WS_NFTA_CMP_UNSPEC, "Unspecified" },
	{ WS_NFTA_CMP_SREG,   "Source register" },
	{ WS_NFTA_CMP_OP,     "Operation" },
	{ WS_NFTA_CMP_DATA,   "Data" },
	{ 0, NULL }
};

static const value_string nft_cmp_op_vals[] = {
	{ WS_NFT_CMP_EQ,  "Equal" },
	{ WS_NFT_CMP_NEQ, "Not equal" },
	{ WS_NFT_CMP_LT,  "Less than" },
	{ WS_NFT_CMP_LTE, "Less than or equal" },
	{ WS_NFT_CMP_GT,  "Greater than" },
	{ WS_NFT_CMP_GTE, "Greater than or equal" },
	{ 0, NULL }
};

static const value_string nft_payload_attr_vals[] = {
	{ WS_NFTA_PAYLOAD_UNSPEC,      "Unspecified" },
	{ WS_NFTA_PAYLOAD_DREG,        "Destination register" },
	{ WS_NFTA_PAYLOAD_BASE,        "Base" },
	{ WS_NFTA_PAYLOAD_OFFSET,      "Offset" },
	{ WS_NFTA_PAYLOAD_LEN,         "Length" },
	{ WS_NFTA_PAYLOAD_SREG,        "Source register" },
	{ WS_NFTA_PAYLOAD_CSUM_TYPE,   "Checksum type" },
	{ WS_NFTA_PAYLOAD_CSUM_OFFSET, "Checksum offset" },
	{ WS_NFTA_PAYLOAD_CSUM_FLAGS,  "Checksum flags" },
	{ 0, NULL }
};

/* NFT_PAYLOAD_LL_HEADER=0, NFT_PAYLOAD_NETWORK_HEADER=1, NFT_PAYLOAD_TRANSPORT_HEADER=2 */
static const value_string nft_payload_base_vals[] = {
	{ 0, "link layer" },
	{ 1, "network" },
	{ 2, "transport" },
	{ 0, NULL }
};

static const value_string nft_immediate_attr_vals[] = {
	{ WS_NFTA_IMMEDIATE_UNSPEC, "Unspecified" },
	{ WS_NFTA_IMMEDIATE_DREG,   "Destination register" },
	{ WS_NFTA_IMMEDIATE_DATA,   "Data" },
	{ 0, NULL }
};

static const value_string nft_nat_attr_vals[] = {
	{ WS_NFTA_NAT_UNSPEC,        "Unspecified" },
	{ WS_NFTA_NAT_TYPE,          "Type" },
	{ WS_NFTA_NAT_FAMILY,        "Family" },
	{ WS_NFTA_NAT_REG_ADDR_MIN,  "Address min register" },
	{ WS_NFTA_NAT_REG_ADDR_MAX,  "Address max register" },
	{ WS_NFTA_NAT_REG_PROTO_MIN, "Protocol min register" },
	{ WS_NFTA_NAT_REG_PROTO_MAX, "Protocol max register" },
	{ WS_NFTA_NAT_FLAGS,         "Flags" },
	{ 0, NULL }
};

static const value_string nft_nat_type_vals[] = {
	{ WS_NFT_NAT_SNAT, "Source NAT" },
	{ WS_NFT_NAT_DNAT, "Destination NAT" },
	{ 0, NULL }
};

static const value_string nft_data_attr_vals[] = {
	{ WS_NFTA_DATA_UNSPEC,  "Unspecified" },
	{ WS_NFTA_DATA_VALUE,   "Value" },
	{ WS_NFTA_DATA_VERDICT, "Verdict" },
	{ 0, NULL }
};

/* Forward declaration for dissect_nft_data_attrs (needed by cmp and immediate dissectors) */
static int dissect_nft_data_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len);

static int
dissect_nft_meta_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data _U_, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_nft_meta_attributes type = (enum ws_nft_meta_attributes) nla_type & NLA_TYPE_MASK;
	nft_meta_ctx_t *ctx = (nft_meta_ctx_t *) data;

	switch (type) {
		case WS_NFTA_META_DREG:
			proto_tree_add_item_ret_uint(tree, hf_nft_meta_dreg, tvb, offset, len, ENC_BIG_ENDIAN, &ctx->dreg);
			ctx->has_dreg = true;
			return 1;

		case WS_NFTA_META_KEY:
			proto_tree_add_item_ret_uint(tree, hf_nft_meta_key, tvb, offset, len, ENC_BIG_ENDIAN, &ctx->key);
			ctx->has_key = true;
			return 1;

		case WS_NFTA_META_SREG:
			proto_tree_add_item_ret_uint(tree, hf_nft_meta_sreg, tvb, offset, len, ENC_BIG_ENDIAN, &ctx->sreg);
			ctx->has_sreg = true;
			return 1;

		case WS_NFTA_META_UNSPEC:
		default:
			return 0;
	}

	return 0;
}

static int
dissect_nft_cmp_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_nft_cmp_attributes type = (enum ws_nft_cmp_attributes) nla_type & NLA_TYPE_MASK;
	nft_cmp_ctx_t *ctx = (nft_cmp_ctx_t *) data;

	switch (type) {
		case WS_NFTA_CMP_SREG:
			proto_tree_add_item_ret_uint(tree, hf_nft_cmp_sreg, tvb, offset, len, ENC_BIG_ENDIAN, &ctx->sreg);
			ctx->has_sreg = true;
			return 1;

		case WS_NFTA_CMP_OP:
			proto_tree_add_item_ret_uint(tree, hf_nft_cmp_op, tvb, offset, len, ENC_BIG_ENDIAN, &ctx->op);
			ctx->has_op = true;
			return 1;

		case WS_NFTA_CMP_DATA:
			if (nla_type & NLA_F_NESTED)
				return dissect_netlink_attributes(tvb, hf_nft_data_attr, ett_nft_data_attr, &ctx->data_ctx, nl_data,
				                                  tree, offset, len, dissect_nft_data_attrs);
			return 0;

		case WS_NFTA_CMP_UNSPEC:
		default:
			return 0;
	}

	return 0;
}

static int
dissect_nft_payload_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data _U_, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_nft_payload_attributes type = (enum ws_nft_payload_attributes) nla_type & NLA_TYPE_MASK;
	nft_payload_ctx_t *ctx = (nft_payload_ctx_t *) data;

	switch (type) {
		case WS_NFTA_PAYLOAD_DREG:
			proto_tree_add_item_ret_uint(tree, hf_nft_payload_dreg, tvb, offset, len, ENC_BIG_ENDIAN, &ctx->dreg);
			ctx->has_dreg = true;
			return 1;

		case WS_NFTA_PAYLOAD_BASE:
			proto_tree_add_item_ret_uint(tree, hf_nft_payload_base, tvb, offset, len, ENC_BIG_ENDIAN, &ctx->base_field);
			ctx->has_base = true;
			return 1;

		case WS_NFTA_PAYLOAD_OFFSET:
			proto_tree_add_item_ret_uint(tree, hf_nft_payload_offset, tvb, offset, len, ENC_BIG_ENDIAN, &ctx->offset);
			ctx->has_offset = true;
			return 1;

		case WS_NFTA_PAYLOAD_LEN:
			proto_tree_add_item_ret_uint(tree, hf_nft_payload_len, tvb, offset, len, ENC_BIG_ENDIAN, &ctx->len);
			ctx->has_len = true;
			return 1;

		case WS_NFTA_PAYLOAD_SREG:
			proto_tree_add_item_ret_uint(tree, hf_nft_payload_sreg, tvb, offset, len, ENC_BIG_ENDIAN, &ctx->sreg);
			ctx->has_sreg = true;
			return 1;

		case WS_NFTA_PAYLOAD_CSUM_TYPE:
			proto_tree_add_item_ret_uint(tree, hf_nft_payload_csum_type, tvb, offset, len, ENC_BIG_ENDIAN, &ctx->csum_type);
			ctx->has_csum_type = true;
			return 1;

		case WS_NFTA_PAYLOAD_CSUM_OFFSET:
			proto_tree_add_item_ret_uint(tree, hf_nft_payload_csum_offset, tvb, offset, len, ENC_BIG_ENDIAN, &ctx->csum_offset);
			ctx->has_csum_offset = true;
			return 1;

		case WS_NFTA_PAYLOAD_CSUM_FLAGS:
			proto_tree_add_item_ret_uint(tree, hf_nft_payload_csum_flags, tvb, offset, len, ENC_BIG_ENDIAN, &ctx->csum_flags);
			ctx->has_csum_flags = true;
			return 1;

		case WS_NFTA_PAYLOAD_UNSPEC:
		default:
			return 0;
	}

	return 0;
}

static int
dissect_nft_immediate_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_nft_immediate_attributes type = (enum ws_nft_immediate_attributes) nla_type & NLA_TYPE_MASK;
	nft_immediate_ctx_t *ctx = (nft_immediate_ctx_t *) data;

	switch (type) {
		case WS_NFTA_IMMEDIATE_DREG:
			proto_tree_add_item_ret_uint(tree, hf_nft_immediate_dreg, tvb, offset, len, ENC_BIG_ENDIAN, &ctx->dreg);
			ctx->has_dreg = true;
			return 1;

		case WS_NFTA_IMMEDIATE_DATA:
			if (nla_type & NLA_F_NESTED)
				return dissect_netlink_attributes(tvb, hf_nft_data_attr, ett_nft_data_attr, &ctx->data_ctx, nl_data,
				                                  tree, offset, len, dissect_nft_data_attrs);
			return 0;

		case WS_NFTA_IMMEDIATE_UNSPEC:
		default:
			return 0;
	}

	return 0;
}

static int
dissect_nft_nat_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data _U_, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_nft_nat_attributes type = (enum ws_nft_nat_attributes) nla_type & NLA_TYPE_MASK;
	nft_nat_ctx_t *ctx = (nft_nat_ctx_t *) data;

	switch (type) {
		case WS_NFTA_NAT_TYPE:
			proto_tree_add_item_ret_uint(tree, hf_nft_nat_type, tvb, offset, len, ENC_BIG_ENDIAN, &ctx->type);
			ctx->has_type = true;
			return 1;

		case WS_NFTA_NAT_FAMILY:
			proto_tree_add_item_ret_uint(tree, hf_nft_nat_family, tvb, offset, len, ENC_BIG_ENDIAN, &ctx->family);
			ctx->has_family = true;
			return 1;

		case WS_NFTA_NAT_REG_ADDR_MIN:
			proto_tree_add_item_ret_uint(tree, hf_nft_nat_reg_addr_min, tvb, offset, len, ENC_BIG_ENDIAN, &ctx->reg_addr_min);
			ctx->has_reg_addr_min = true;
			return 1;

		case WS_NFTA_NAT_REG_ADDR_MAX:
			proto_tree_add_item_ret_uint(tree, hf_nft_nat_reg_addr_max, tvb, offset, len, ENC_BIG_ENDIAN, &ctx->reg_addr_max);
			ctx->has_reg_addr_max = true;
			return 1;

		case WS_NFTA_NAT_REG_PROTO_MIN:
			proto_tree_add_item_ret_uint(tree, hf_nft_nat_reg_proto_min, tvb, offset, len, ENC_BIG_ENDIAN, &ctx->reg_proto_min);
			ctx->has_reg_proto_min = true;
			return 1;

		case WS_NFTA_NAT_REG_PROTO_MAX:
			proto_tree_add_item_ret_uint(tree, hf_nft_nat_reg_proto_max, tvb, offset, len, ENC_BIG_ENDIAN, &ctx->reg_proto_max);
			ctx->has_reg_proto_max = true;
			return 1;

		case WS_NFTA_NAT_FLAGS:
			proto_tree_add_item_ret_uint(tree, hf_nft_nat_flags, tvb, offset, len, ENC_BIG_ENDIAN, &ctx->flags);
			ctx->has_flags = true;
			return 1;

		case WS_NFTA_NAT_UNSPEC:
		default:
			return 0;
	}

	return 0;
}

static int
dissect_nft_data_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data _U_, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_nft_data_attributes type = (enum ws_nft_data_attributes) nla_type & NLA_TYPE_MASK;

	switch (type) {
		case WS_NFTA_DATA_VALUE:
			{
				nft_data_ctx_t *ctx = (nft_data_ctx_t *) data;
				proto_tree_add_item(tree, hf_nft_data_value, tvb, offset, len, ENC_NA);
				ctx->data = tvb_get_ptr(tvb, offset, len);
				ctx->data_len = len;
				ctx->has_data = true;
			}
			return 1;

		case WS_NFTA_DATA_VERDICT:
			/* TODO: Verdict dissector */
			return 0;

		case WS_NFTA_DATA_UNSPEC:
		default:
			return 0;
	}

	return 0;
}

static int
dissect_nft_expr_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_nft_expr_attributes type = (enum ws_nft_expr_attributes) nla_type & NLA_TYPE_MASK;

	switch (type) {
		case WS_NFTA_EXPR_NAME:
			{
				nft_expr_ctx_t *expr_ctx = (nft_expr_ctx_t *) data;
				proto_tree_add_item(tree, hf_nft_expr_attr_name, tvb, offset, len, ENC_UTF_8);
				/* Store expression name for NFTA_EXPR_DATA dispatch */
				expr_ctx->expr_name = (const char *)tvb_get_string_enc(expr_ctx->base->pinfo->pool, tvb, offset, len, ENC_UTF_8);
			}
			return 1;

		case WS_NFTA_EXPR_DATA:
			if (nla_type & NLA_F_NESTED) {
				nft_expr_ctx_t *expr_ctx = (nft_expr_ctx_t *) data;
				int ret = 0;
				proto_item *expr_item = proto_tree_get_parent(proto_tree_get_parent_tree(tree));

				/* Dispatch to appropriate expression-specific dissector based on name */
				if (expr_ctx->expr_name) {
					if (strcmp(expr_ctx->expr_name, "meta") == 0) {
						nft_meta_ctx_t meta_ctx;
						memset(&meta_ctx, 0, sizeof(meta_ctx));
						meta_ctx.base = expr_ctx->base;

						ret = dissect_netlink_attributes(tvb, hf_nft_meta_attr, ett_nft_meta_attr, &meta_ctx, nl_data,
						                                  tree, offset, len, dissect_nft_meta_attrs);
						/* Format: "meta load <key> => reg <dreg>" or "meta set <key> with reg <sreg>" */
						if (meta_ctx.has_dreg && meta_ctx.has_key) {
							proto_item_append_text(expr_item, "  [ meta load %s => reg %u ]",
							                       val_to_str_const(meta_ctx.key, nft_meta_key_vals, "unknown"),
							                       meta_ctx.dreg);
						} else if (meta_ctx.has_sreg && meta_ctx.has_key) {
							proto_item_append_text(expr_item, "  [ meta set %s with reg %u ]",
							                       val_to_str_const(meta_ctx.key, nft_meta_key_vals, "unknown"),
							                       meta_ctx.sreg);
						}
					}
					else if (strcmp(expr_ctx->expr_name, "cmp") == 0) {
						nft_cmp_ctx_t cmp_ctx;
						memset(&cmp_ctx, 0, sizeof(cmp_ctx));
						cmp_ctx.base = expr_ctx->base;

						ret = dissect_netlink_attributes(tvb, hf_nft_cmp_attr, ett_nft_cmp_attr, &cmp_ctx, nl_data,
						                                  tree, offset, len, dissect_nft_cmp_attrs);
						/* Format: "cmp <op> reg <sreg> <data>" */
						if (cmp_ctx.has_op && cmp_ctx.has_sreg && cmp_ctx.data_ctx.has_data) {
							uint32_t i;
							proto_item_append_text(expr_item, "  [ cmp %s reg %u 0x",
							                       val_to_str_const(cmp_ctx.op, nft_cmp_op_vals, "unknown"),
							                       cmp_ctx.sreg);
							for (i = 0; i < cmp_ctx.data_ctx.data_len && i < 8; i++) {
								proto_item_append_text(expr_item, "%02x", cmp_ctx.data_ctx.data[i]);
							}
							proto_item_append_text(expr_item, " ]");
						}
					}
					else if (strcmp(expr_ctx->expr_name, "payload") == 0) {
						nft_payload_ctx_t payload_ctx;
						memset(&payload_ctx, 0, sizeof(payload_ctx));
						payload_ctx.base = expr_ctx->base;

						ret = dissect_netlink_attributes(tvb, hf_nft_payload_attr, ett_nft_payload_attr, &payload_ctx, nl_data,
						                                  tree, offset, len, dissect_nft_payload_attrs);
						/* Format: "payload load ..." or "payload write ..." depending on sreg */
						if (payload_ctx.has_sreg && payload_ctx.has_base &&
							payload_ctx.has_offset && payload_ctx.has_len) {
							/* Write mode: "payload write reg <sreg> => <len>b @ <base> header + <offset> csum_type <type> csum_off <off> csum_flags <flags>" */
							proto_item_append_text(expr_item, "  [ payload write reg %u => %ub @ %s header + %u",
												payload_ctx.sreg,
												payload_ctx.len,
												val_to_str_const(payload_ctx.base_field, nft_payload_base_vals, "unknown"),
												payload_ctx.offset);
							if (payload_ctx.has_csum_type)
								proto_item_append_text(expr_item, " csum_type %u", payload_ctx.csum_type);
							if (payload_ctx.has_csum_offset)
								proto_item_append_text(expr_item, " csum_off %u", payload_ctx.csum_offset);
							if (payload_ctx.has_csum_flags)
								proto_item_append_text(expr_item, " csum_flags 0x%x", payload_ctx.csum_flags);
							proto_item_append_text(expr_item, " ]");
						} else if (payload_ctx.has_dreg && payload_ctx.has_base &&
								payload_ctx.has_offset && payload_ctx.has_len) {
							/* Load mode: "payload load <len>b @ <base> header + <offset> => reg <dreg>" */
							proto_item_append_text(expr_item, "  [ payload load %ub @ %s header + %u => reg %u ]",
												payload_ctx.len,
												val_to_str_const(payload_ctx.base_field, nft_payload_base_vals, "unknown"),
												payload_ctx.offset,
												payload_ctx.dreg);
						}
					}
					else if (strcmp(expr_ctx->expr_name, "immediate") == 0) {
						nft_immediate_ctx_t imm_ctx;
						memset(&imm_ctx, 0, sizeof(imm_ctx));
						imm_ctx.base = expr_ctx->base;

						ret = dissect_netlink_attributes(tvb, hf_nft_immediate_attr, ett_nft_immediate_attr, &imm_ctx, nl_data,
						                                  tree, offset, len, dissect_nft_immediate_attrs);
						/* Format: "immediate reg <dreg> <data>" */
						if (imm_ctx.has_dreg && imm_ctx.data_ctx.has_data) {
							uint32_t i;
							proto_item_append_text(expr_item, "  [ immediate reg %u 0x",
							                       imm_ctx.dreg);
							for (i = 0; i < imm_ctx.data_ctx.data_len && i < 8; i++) {
								proto_item_append_text(expr_item, "%02x", imm_ctx.data_ctx.data[i]);
							}
							proto_item_append_text(expr_item, " ]");
						}
					}
					else if (strcmp(expr_ctx->expr_name, "nat") == 0) {
						nft_nat_ctx_t nat_ctx;
						memset(&nat_ctx, 0, sizeof(nat_ctx));
						nat_ctx.base = expr_ctx->base;

						ret = dissect_netlink_attributes(tvb, hf_nft_nat_attr, ett_nft_nat_attr, &nat_ctx, nl_data,
						                                  tree, offset, len, dissect_nft_nat_attrs);
						/* Format: "nat <type> <family> addr_min reg <reg> proto_min reg <reg>" */
						if (nat_ctx.has_type && nat_ctx.has_family) {
							proto_item_append_text(expr_item, "  [ nat %s %s",
							                       val_to_str_const(nat_ctx.type, nft_nat_type_vals, "unknown"),
							                       val_to_str_const(nat_ctx.family, nfproto_family_vals, "unknown"));
							if (nat_ctx.has_reg_addr_min)
								proto_item_append_text(expr_item, " addr_min reg %u", nat_ctx.reg_addr_min);
							if (nat_ctx.has_reg_proto_min)
								proto_item_append_text(expr_item, " proto_min reg %u", nat_ctx.reg_proto_min);
							if (nat_ctx.has_reg_addr_max)
								proto_item_append_text(expr_item, " addr_max reg %u", nat_ctx.reg_addr_max);
							if (nat_ctx.has_reg_proto_max)
								proto_item_append_text(expr_item, " proto_max reg %u", nat_ctx.reg_proto_max);
							if (nat_ctx.has_flags)
								proto_item_append_text(expr_item, " flags 0x%x", nat_ctx.flags);
							proto_item_append_text(expr_item, " ]");
						}
					}
				}
				return ret;
			}
			return 0;

		case WS_NFTA_EXPR_UNSPEC:
		default:
			return 0;
	}

	return 0;
}

static int
dissect_nft_list_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_nft_list_attributes type = (enum ws_nft_list_attributes) nla_type & NLA_TYPE_MASK;
	netlink_netfilter_info_t *info = (netlink_netfilter_info_t *) data;

	switch (type) {
		case WS_NFTA_LIST_ELEM:
			if (nla_type & NLA_F_NESTED) {
				nft_expr_ctx_t expr_ctx;
				memset(&expr_ctx, 0, sizeof(expr_ctx));
				expr_ctx.base = info;
				return dissect_netlink_attributes(tvb, hf_nft_expr_attr, ett_nft_expr_attr, &expr_ctx, nl_data,
								  tree, offset, len, dissect_nft_expr_attrs);
			}
			return 0;

		case WS_NFTA_LIST_UNSPEC:
		default:
			return 0;
	}

	return 0;
}

static int
dissect_nft_rule_compat_attrs(tvbuff_t *tvb, void *data _U_, struct packet_netlink_data *nl_data _U_, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_nft_rule_compat_attributes type = (enum ws_nft_rule_compat_attributes) nla_type & NLA_TYPE_MASK;

	switch (type) {
		case WS_NFTA_RULE_COMPAT_PROTO:
			proto_tree_add_item(tree, hf_nft_rule_compat_attr_proto, tvb, offset, len, ENC_BIG_ENDIAN);
			return 1;

		case WS_NFTA_RULE_COMPAT_FLAGS:
			proto_tree_add_item(tree, hf_nft_rule_compat_attr_flags, tvb, offset, len, ENC_BIG_ENDIAN);
			return 1;

		case WS_NFTA_RULE_COMPAT_UNSPEC:
		default:
			return 0;
	}

	return 0;
}

static int
dissect_nft_rule_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_nft_rule_attributes type = (enum ws_nft_rule_attributes) nla_type & NLA_TYPE_MASK;
	netlink_netfilter_info_t *info = (netlink_netfilter_info_t *) data;

	switch (type) {
		case WS_NFTA_RULE_TABLE:
		{
			const uint8_t *table_name;
			proto_tree_add_item_ret_string(tree, hf_nft_rule_attr_table, tvb, offset, len, ENC_UTF_8, info->pinfo->pool, &table_name);
			proto_item_append_text(tree, ": %s", table_name);
			return 1;
		}

		case WS_NFTA_RULE_CHAIN:
		{
			const uint8_t *chain_name;
			proto_tree_add_item_ret_string(tree, hf_nft_rule_attr_chain, tvb, offset, len, ENC_UTF_8, info->pinfo->pool, &chain_name);
			proto_item_append_text(tree, ": %s", chain_name);
			return 1;
		}

		case WS_NFTA_RULE_HANDLE:
			proto_tree_add_item(tree, hf_nft_rule_attr_handle, tvb, offset, len, ENC_BIG_ENDIAN);
			return 1;

		case WS_NFTA_RULE_EXPRESSIONS:
			if (nla_type & NLA_F_NESTED)
				return dissect_netlink_attributes(tvb, hf_nft_list_attr, ett_nft_list_attr, info, nl_data,
								  tree, offset, len, dissect_nft_list_attrs);
			return 0;

		case WS_NFTA_RULE_COMPAT:
			if (nla_type & NLA_F_NESTED)
				return dissect_netlink_attributes(tvb, hf_nft_rule_compat_attr, ett_nft_rule_compat_attr, info, nl_data,
								  tree, offset, len, dissect_nft_rule_compat_attrs);
			return 0;

		case WS_NFTA_RULE_POSITION:
			proto_tree_add_item(tree, hf_nft_rule_attr_position, tvb, offset, len, ENC_BIG_ENDIAN);
			return 1;

		case WS_NFTA_RULE_USERDATA:
		{
			const uint8_t *userdata;
			proto_tree_add_item_ret_string(tree, hf_nft_rule_attr_userdata, tvb, offset, len, ENC_UTF_8, info->pinfo->pool, &userdata);
			proto_item_append_text(tree, ": %s", userdata);
			return 1;
		}

		case WS_NFTA_RULE_ID:
			proto_tree_add_item(tree, hf_nft_rule_attr_id, tvb, offset, len, ENC_BIG_ENDIAN);
			return 1;

		case WS_NFTA_RULE_POSITION_ID:
			proto_tree_add_item(tree, hf_nft_rule_attr_position_id, tvb, offset, len, ENC_BIG_ENDIAN);
			return 1;

		case WS_NFTA_RULE_CHAIN_ID:
			proto_tree_add_item(tree, hf_nft_rule_attr_chain_id, tvb, offset, len, ENC_BIG_ENDIAN);
			return 1;

		case WS_NFTA_RULE_UNSPEC:
		case WS_NFTA_RULE_PAD:
		default:
			return 0;
	}

	return 0;
}

static int
dissect_netfilter_nftables(tvbuff_t *tvb, netlink_netfilter_info_t *info, struct packet_netlink_data *nl_data, proto_tree *tree, int offset)
{
	enum nf_tables_msg_types type = (enum nf_tables_msg_types) (nl_data->type & 0xff);

	offset = dissect_netlink_netfilter_header(tvb, tree, offset);

	switch (type) {
		case WS_NFT_MSG_NEWRULE:
		case WS_NFT_MSG_GETRULE:
		case WS_NFT_MSG_DELRULE:
		case WS_NFT_MSG_GETRULE_RESET:
		case WS_NFT_MSG_DESTROYRULE:
			return dissect_netlink_attributes_to_end(tvb, hf_nft_rule_attr, ett_nft_rule_attr, info, nl_data, tree, offset, dissect_nft_rule_attrs);

		default:
			/* Other nftables message types not yet implemented */
			return offset;
	}
}

static const value_string nftables_command_vals[] = {
	{ WS_NFT_MSG_NEWTABLE,         "New table" },
	{ WS_NFT_MSG_GETTABLE,         "Get table" },
	{ WS_NFT_MSG_DELTABLE,         "Delete table" },
	{ WS_NFT_MSG_NEWCHAIN,         "New chain" },
	{ WS_NFT_MSG_GETCHAIN,         "Get chain" },
	{ WS_NFT_MSG_DELCHAIN,         "Delete chain" },
	{ WS_NFT_MSG_NEWRULE,          "New rule" },
	{ WS_NFT_MSG_GETRULE,          "Get rule" },
	{ WS_NFT_MSG_DELRULE,          "Delete rule" },
	{ WS_NFT_MSG_NEWSET,           "New set" },
	{ WS_NFT_MSG_GETSET,           "Get set" },
	{ WS_NFT_MSG_DELSET,           "Delete set" },
	{ WS_NFT_MSG_NEWSETELEM,       "New set element" },
	{ WS_NFT_MSG_GETSETELEM,       "Get set element" },
	{ WS_NFT_MSG_DELSETELEM,       "Delete set element" },
	{ WS_NFT_MSG_NEWGEN,           "New rule-set generation" },
	{ WS_NFT_MSG_GETGEN,           "Get rule-set generation" },
	{ WS_NFT_MSG_TRACE,            "Trace" },
	{ WS_NFT_MSG_NEWOBJ,           "New stateful object" },
	{ WS_NFT_MSG_GETOBJ,           "Get stateful object" },
	{ WS_NFT_MSG_DELOBJ,           "Delete stateful object" },
	{ WS_NFT_MSG_GETOBJ_RESET,     "Get and reset stateful object" },
	{ WS_NFT_MSG_NEWFLOWTABLE,     "New flow table" },
	{ WS_NFT_MSG_GETFLOWTABLE,     "Get flow table" },
	{ WS_NFT_MSG_DELFLOWTABLE,     "Delete flow table" },
	{ WS_NFT_MSG_GETRULE_RESET,    "Get rules and reset stateful expressions" },
	{ WS_NFT_MSG_DESTROYTABLE,     "Destroy table" },
	{ WS_NFT_MSG_DESTROYCHAIN,     "Destroy chain" },
	{ WS_NFT_MSG_DESTROYRULE,      "Destroy rule" },
	{ WS_NFT_MSG_DESTROYSET,       "Destroy set" },
	{ WS_NFT_MSG_DESTROYSETELEM,   "Destroy set element" },
	{ WS_NFT_MSG_DESTROYOBJ,       "Destroy stateful object" },
	{ WS_NFT_MSG_DESTROYFLOWTABLE, "Destroy flow table" },
	{ WS_NFT_MSG_GETSETELEM_RESET, "Get set elements and reset stateful expressions" },
	{ 0, NULL }
};


static const value_string netlink_netfilter_subsystem_vals[] = {
	{ WS_NFNL_SUBSYS_NONE,              "None" },
	{ WS_NFNL_SUBSYS_CTNETLINK,         "Conntrack" },
	{ WS_NFNL_SUBSYS_CTNETLINK_EXP,     "Conntrack expect" },
	{ WS_NFNL_SUBSYS_QUEUE,             "Netfilter packet queue" },
	{ WS_NFNL_SUBSYS_ULOG,              "Netfilter userspace logging" },
	{ WS_NFNL_SUBSYS_OSF,               "OS fingerprint" },
	{ WS_NFNL_SUBSYS_IPSET,             "IP set" },
	{ WS_NFNL_SUBSYS_ACCT,              "Extended Netfilter accounting infrastructure" },
	{ WS_NFNL_SUBSYS_CTNETLINK_TIMEOUT, "Extended Netfilter Connection Tracking timeout tuning" },
	{ WS_NFNL_SUBSYS_CTHELPER,          "Connection Tracking Helpers" },
	{ WS_NFNL_SUBSYS_NFTABLES,          "Netfilter tables" },
	{ WS_NFNL_SUBSYS_NFT_COMPAT,        "x_tables compatibility layer for nf_tables" },
	{ WS_NFNL_SUBSYS_HOOK,              "Hook" },
	{ WS_NFNL_SUBSYS_COUNT,             "Count" },
	{ 0, NULL }
};

static int
dissect_netlink_netfilter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	struct packet_netlink_data *nl_data = (struct packet_netlink_data *)data;
	netlink_netfilter_info_t info;
	proto_tree *nlmsg_tree;
	proto_item *pi;
	int offset = 0;

	DISSECTOR_ASSERT(nl_data && nl_data->magic == PACKET_NETLINK_MAGIC);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Netlink netfilter");
	col_clear(pinfo->cinfo, COL_INFO);

	pi = proto_tree_add_item(tree, proto_netlink_netfilter, tvb, 0, -1, ENC_NA);
	nlmsg_tree = proto_item_add_subtree(pi, ett_netlink_netfilter);

	/* Netlink message header (nlmsghdr) */
	offset = dissect_netlink_header(tvb, pinfo, nlmsg_tree, offset, nl_data->encoding, -1, NULL);
	proto_tree_add_item(nlmsg_tree, hf_netlink_netfilter_subsys, tvb, 4, 2, nl_data->encoding);
	switch (nl_data->type >> 8) {
		case WS_NFNL_SUBSYS_CTNETLINK_EXP:
			proto_tree_add_item(nlmsg_tree, hf_nfexp_type, tvb, 4, 2, nl_data->encoding);
			break;

		case WS_NFNL_SUBSYS_QUEUE:
			proto_tree_add_item(nlmsg_tree, hf_nfq_type, tvb, 4, 2, nl_data->encoding);
			break;

		case WS_NFNL_SUBSYS_ULOG:
			proto_tree_add_item(nlmsg_tree, hf_netlink_netfilter_ulog_type, tvb, 4, 2, nl_data->encoding);
			break;

		case WS_NFNL_SUBSYS_IPSET:
			proto_tree_add_item(nlmsg_tree, hf_ipset_command, tvb, 4, 2, nl_data->encoding);
			break;

		case WS_NFNL_SUBSYS_NFTABLES:
			proto_tree_add_item(nlmsg_tree, hf_nftables_command, tvb, 4, 2, nl_data->encoding);
			break;
	}

	info.pinfo = pinfo;
	info.hw_protocol = 0;

	switch (nl_data->type >> 8) {
		case WS_NFNL_SUBSYS_CTNETLINK:
			offset = dissect_netfilter_ct(tvb, &info, nl_data, nlmsg_tree, offset);
			break;

		case WS_NFNL_SUBSYS_CTNETLINK_EXP:
			offset = dissect_netfilter_exp(tvb, &info, nl_data, nlmsg_tree, offset);
			break;

		case WS_NFNL_SUBSYS_QUEUE:
			offset = dissect_netfilter_queue(tvb, &info, nl_data, nlmsg_tree, offset);
			break;

		case WS_NFNL_SUBSYS_ULOG:
			offset = dissect_netfilter_ulog(tvb, &info, nl_data, nlmsg_tree, offset);
			break;

		case WS_NFNL_SUBSYS_IPSET:
			offset = dissect_netfilter_ipset(tvb, &info, nl_data, nlmsg_tree, offset);
			break;

		case WS_NFNL_SUBSYS_NFTABLES:
			offset = dissect_netfilter_nftables(tvb, &info, nl_data, nlmsg_tree, offset);
			break;

		default:
			call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, nlmsg_tree);
			offset = tvb_reported_length(tvb);
			break;
	}

	return offset;
}

void
proto_register_netlink_netfilter(void)
{
	static hf_register_info hf[] = {
		{ &hf_netlink_netfilter_family,
			{ "Protocol family", "netlink-netfilter.family",
			  FT_UINT8, BASE_DEC, VALS(nfproto_family_vals), 0x00,
			  "nfnetlink protocol family", HFILL }
		},
		{ &hf_netlink_netfilter_version,
			{ "Version", "netlink-netfilter.version",
			  FT_UINT8, BASE_DEC, NULL, 0x00,
			  "nfnetlink version", HFILL }
		},
		{ &hf_netlink_netfilter_resid,
			{ "Resource id", "netlink-netfilter.res_id",
			  FT_UINT16, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfct_tuple_proto_num_attr,
			{ "Protocol", "netlink-netfilter.nfct_tuple.proto.num",
			  FT_UINT8, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfct_tuple_proto_src_port_attr,
			{ "Port", "netlink-netfilter.nfct_tuple.proto.src_port",
			  FT_UINT16, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfct_tuple_proto_dst_port_attr,
			{ "Port", "netlink-netfilter.nfct_tuple.proto.dst_port",
			  FT_UINT16, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfct_tuple_proto_attr,
			{ "Type", "netlink-netfilter.nfct_tuple.proto",
			  FT_UINT16, BASE_DEC, VALS(nfct_tuple_l4proto_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_nfct_tuple_ip_attr_ipv4,
			{ "IPv4 address", "netlink-netfilter.nfct_tuple.ip.ip_addr",
			  FT_IPv4, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfct_tuple_ip_attr_ipv6,
			{ "IPv6 address", "netlink-netfilter.nfct_tuple.ip.ip6_addr",
			  FT_IPv6, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfct_tuple_ip_attr,
			{ "Type", "netlink-netfilter.nfct_tuple.ip",
			  FT_UINT16, BASE_DEC, VALS(nfct_tuple_ip_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_nfct_tuple_zone_attr,
			{ "Zone", "netlink-netfilter.nfct_tuple.zone",
			  FT_UINT16, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfct_tuple_attr,
			{ "Type", "netlink-netfilter.nfct_tuple",
			  FT_UINT16, BASE_DEC, VALS(nfct_tuple_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_nfct_attr_timeout,
			{ "Timeout", "netlink-netfilter.ct_attr.timeout",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfct_attr_id,
			{ "ID", "netlink-netfilter.ct_attr.id",
			  FT_UINT32, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfct_attr_status_flag_expected,
			{ "Expected", "netlink-netfilter.ct_attr.status.expected",
			  FT_UINT32, BASE_DEC, NULL, WS_IPS_EXPECTED,
			  "It is an expected connection", HFILL }
		},
		{ &hf_nfct_attr_status_flag_seen_reply,
			{ "Seen reply", "netlink-netfilter.ct_attr.status.seen_reply",
			  FT_UINT32, BASE_DEC, NULL, WS_IPS_SEEN_REPLY,
			  "Packets going in both directions have been seen", HFILL }
		},
		{ &hf_nfct_attr_status_flag_assured,
			{ "Assured", "netlink-netfilter.ct_attr.status.assured",
			  FT_UINT32, BASE_DEC, NULL, WS_IPS_ASSURED,
			  "Conntrack should never be early-expired", HFILL }
		},
		{ &hf_nfct_attr_status_flag_confirmed,
			{ "Confirmed", "netlink-netfilter.ct_attr.status.confirmed",
			  FT_UINT32, BASE_DEC, NULL, WS_IPS_CONFIRMED,
			  "Connection is confirmed: originating packet has left box", HFILL }
		},
		{ &hf_nfct_attr_status_flag_src_nat,
			{ "Source NAT", "netlink-netfilter.ct_attr.status.src_nat",
			  FT_UINT32, BASE_DEC, NULL, WS_IPS_SRC_NAT,
			  "Connection needs source NAT in orig dir.", HFILL }
		},
		{ &hf_nfct_attr_status_flag_dst_nat,
			{ "Destination NAT", "netlink-netfilter.ct_attr.status.dst_nat",
			  FT_UINT32, BASE_DEC, NULL, WS_IPS_DST_NAT,
			  "Connection needs destination NAT in orig dir.", HFILL }
		},
		{ &hf_nfct_attr_status_flag_seq_adjust,
			{ "Sequence adjust", "netlink-netfilter.ct_attr.status.seq_adjust",
			  FT_UINT32, BASE_DEC, NULL, WS_IPS_SEQ_ADJUST,
			  "Connection needs TCP sequence adjusted", HFILL }
		},
		{ &hf_nfct_attr_status_flag_src_nat_done,
			{ "Source NAT done", "netlink-netfilter.ct_attr.status.src_nat_done",
			  FT_UINT32, BASE_DEC, NULL, WS_IPS_SRC_NAT_DONE,
			  "Source NAT has been initialized", HFILL }
		},
		{ &hf_nfct_attr_status_flag_dst_nat_done,
			{ "Destination NAT done", "netlink-netfilter.ct_attr.status.dst_nat_done",
			  FT_UINT32, BASE_DEC, NULL, WS_IPS_DST_NAT_DONE,
			  "Destination NAT has been initialized", HFILL }
		},
		{ &hf_nfct_attr_status_flag_dying,
			{ "Dying", "netlink-netfilter.ct_attr.status.dying",
			  FT_UINT32, BASE_DEC, NULL, WS_IPS_DYING,
			  "Connection is dying (removed from lists)", HFILL }
		},
		{ &hf_nfct_attr_status_flag_fixed_timeout,
			{ "Fixed timeout", "netlink-netfilter.ct_attr.status.fixed_timeout",
			  FT_UINT32, BASE_DEC, NULL, WS_IPS_FIXED_TIMEOUT,
			  "Connection has fixed timeout", HFILL }
		},
		{ &hf_nfct_attr_status_flag_template,
			{ "Template", "netlink-netfilter.ct_attr.status.template",
			  FT_UINT32, BASE_DEC, NULL, WS_IPS_TEMPLATE,
			  "Conntrack is a template", HFILL }
		},
		{ &hf_nfct_attr_status_flag_untracked,
			{ "Untracked", "netlink-netfilter.ct_attr.status.untracked",
			  FT_UINT32, BASE_DEC, NULL, WS_IPS_UNTRACKED,
			  "Conntrack is a fake untracked entry.  Obsolete and not used anymore", HFILL }
		},
		{ &hf_nfct_attr_status_flag_helper,
			{ "Helper", "netlink-netfilter.ct_attr.status.helper",
			  FT_UINT32, BASE_DEC, NULL, WS_IPS_HELPER,
			  "Conntrack got a helper explicitly attached via CT target", HFILL }
		},
		{ &hf_nfct_attr_status_flag_offload,
			{ "Offload", "netlink-netfilter.ct_attr.status.offload",
			  FT_UINT32, BASE_DEC, NULL, WS_IPS_OFFLOAD,
			  NULL, HFILL }
		},
		{ &hf_nfct_attr_status_flag_hw_offload,
			{ "HW offload", "netlink-netfilter.ct_attr.status.hw_offload",
			  FT_UINT32, BASE_DEC, NULL, WS_IPS_HW_OFFLOAD,
			  NULL, HFILL }
		},
		{ &hf_nfct_attr_status,
			{ "Status", "netlink-netfilter.ct_attr.status",
			  FT_UINT32, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfct_help_attr_help_name,
			{ "Helper name", "netlink-netfilter.ct_help_attr.help_name",
			  FT_STRINGZ, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_nfct_help_attr,
			{ "Helper", "netlink-netfilter.ct_help_attr",
			  FT_UINT16, BASE_DEC, VALS(nfct_help_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_nfct_seqadj_attr_correction_pos,
			{ "Position", "netlink-netfilter.ct_seqadj_correction_pos",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfct_seqadj_attr_offset_before,
			{ "Offset", "netlink-netfilter.ct_seqadj_offset_before",
			  FT_INT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfct_seqadj_attr_offset_after,
			{ "Offset", "netlink-netfilter.ct_seqadj_offset_after",
			  FT_INT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfct_seqadj_attr,
			{ "Adjustment", "netlink-netfilter.ct_seqadj_attr",
			  FT_UINT16, BASE_DEC, VALS(nfct_seqadj_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_nfct_attr,
			{ "Type", "netlink-netfilter.ct.attr",
			  FT_UINT16, BASE_DEC, VALS(nfct_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_nfexp_nat_attr_dir,
			{ "Direction", "netlink-netfilter.nfexp.nat.dir",
			  FT_UINT32, BASE_DEC, VALS(nfexp_conntrack_dir_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfexp_nat_attr,
			{ "Type", "netlink-netfilter.nfexp.nat",
			  FT_UINT16, BASE_DEC, VALS(nfexp_nat_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_nfexp_attr_timeout,
			{ "Timeout", "netlink-netfilter.nfexp.timeout",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfexp_attr_id,
			{ "ID", "netlink-netfilter.nfexp.id",
			  FT_UINT32, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfexp_attr_class,
			{ "Class", "netlink-netfilter.nfexp.class",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfexp_attr_zone,
			{ "Zone", "netlink-netfilter.nfexp.zone",
			  FT_UINT16, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfexp_attr_fn,
			{ "Name", "netlink-netfilter.nfexp.fn",
			  FT_STRINGZ, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_nfexp_attr_flag_permanent,
			{ "Permanent", "netlink-netfilter.nfexp.flags.permanent",
			  FT_UINT32, BASE_DEC, NULL, WS_NF_CT_EXPECT_PERMANENT,
			  NULL, HFILL }
		},
		{ &hf_nfexp_attr_flag_inactive,
			{ "Inactive", "netlink-netfilter.nfexp.flags.inactive",
			  FT_UINT32, BASE_DEC, NULL, WS_NF_CT_EXPECT_INACTIVE,
			  NULL, HFILL }
		},
		{ &hf_nfexp_attr_flag_userspace,
			{ "Userspace", "netlink-netfilter.nfexp.flags.userspace",
			  FT_UINT32, BASE_DEC, NULL, WS_NF_CT_EXPECT_USERSPACE,
			  NULL, HFILL }
		},
		{ &hf_nfexp_attr_flags,
			{ "Flags", "netlink-netfilter.nfexp.flags",
			  FT_UINT32, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfexp_attr,
			{ "Type", "netlink-netfilter.exp.attr",
			  FT_UINT16, BASE_DEC, VALS(nfexp_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_nfq_config_command_command,
			{ "Command", "netlink-netfilter.queue.config.command.command",
			  FT_UINT8, BASE_DEC, VALS(nfq_config_command_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfq_config_command_pf,
			{ "Protocol family", "netlink-netfilter.queue.config.command.pf",
			  FT_UINT16, BASE_DEC, VALS(nfproto_family_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfq_config_params_copyrange,
			{ "Copy range", "netlink-netfilter.queue.config.params.copy_range",
			  FT_UINT32, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfq_config_params_copymode,
			{ "Copy mode", "netlink-netfilter.queue.config.params.copy_mode",
			  FT_UINT8, BASE_DEC, VALS(nfq_config_mode_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfq_config_queue_maxlen,
			{ "Maximum queue length", "netlink-netfilter.queue.config.queue_maxlen",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfq_config_mask,
			{ "Flags mask", "netlink-netfilter.queue.config.mask",
			  FT_UINT32, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfq_config_flags,
			{ "Flags", "netlink-netfilter.queue.config.flags",
			  FT_UINT32, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfq_config_attr,
			{ "Type", "netlink-netfilter.queue.config_attr",
			  FT_UINT16, BASE_DEC, VALS(nfq_config_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_nfq_verdict_verdict,
			{ "Verdict", "netlink-netfilter.queue.verdict.verdict",
			  FT_UINT32, BASE_DEC, VALS(nfq_verdict_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfq_verdict_id,
			{ "Verdict ID", "netlink-netfilter.queue.verdict.id",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfq_packet_id,
			{ "Packet ID", "netlink-netfilter.queue.packet.id",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfq_packet_hwprotocol,
			{ "HW protocol", "netlink-netfilter.queue.packet.protocol",
			  FT_UINT16, BASE_HEX, VALS(etype_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfq_packet_hook,
			{ "Netfilter hook", "netlink-netfilter.queue.packet.hook",
			  FT_UINT8, BASE_DEC, VALS(netfilter_hooks_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfq_nfmark,
			{ "Mark", "netlink-netfilter.queue.nfmark",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfq_timestamp,
			{ "Timestamp", "netlink-netfilter.queue.timestamp",
			  FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfq_ifindex_indev,
			{ "IFINDEX_INDEV", "netlink-netfilter.queue.ifindex_indev",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfq_ifindex_outdev,
			{ "IFINDEX_OUTDEV", "netlink-netfilter.queue.ifindex_outdev",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfq_ifindex_physindev,
			{ "IFINDEX_PHYSINDEV", "netlink-netfilter.queue.ifindex_physindev",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfq_ifindex_physoutdev,
			{ "IFINDEX_PHYSOUTDEV", "netlink-netfilter.queue.ifindex_physoutdev",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfq_hwaddr_len,
			{ "Address length", "netlink-netfilter.queue.hwaddr.len",
			  FT_UINT16, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfq_hwaddr_addr,
			{ "Address", "netlink-netfilter.queue.hwaddr.addr",
			  FT_ETHER, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfq_ctinfo,
			{ "Conntrack info", "netlink-netfilter.queue.ct_info",
			  FT_UINT32, BASE_DEC, VALS(nfq_ctinfo_vals), 0x00,
			  "Connection state tracking info", HFILL }
		},
		{ &hf_nfq_caplen,
			{ "Length of captured packet", "netlink-netfilter.queue.caplen",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  "Length of captured, untruncated packet", HFILL }
		},
		{ &hf_nfq_uid,
			{ "UID", "netlink-netfilter.queue.uid",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfq_gid,
			{ "GID", "netlink-netfilter.queue.gid",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfq_attr,
			{ "Type", "netlink-netfilter.queue.attr",
			  FT_UINT16, BASE_DEC, VALS(nfq_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_netlink_netfilter_ulog_type,
			{ "Type", "netlink-netfilter.ulog_type",
			  FT_UINT16, BASE_DEC, VALS(netlink_netfilter_ulog_type_vals), 0x00FF,
			  NULL, HFILL }
		},
		{ &hf_ipset_attr,
			{ "Type", "netlink-netfilter.ipset_attr",
			  FT_UINT16, BASE_DEC, VALS(ipset_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_ipset_cadt_attr,
			{ "Type", "netlink-netfilter.ipset_cadt_attr",
			  FT_UINT16, BASE_DEC, VALS(ipset_cadt_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_ipset_cadt_attr_cidr,
			{ "CIDR", "netlink-netfilter.ipset.cidr",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_ipset_cadt_attr_timeout,
			{ "Timeout", "netlink-netfilter.ipset.timeout",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_ipset_cadt_attr_cadt_flags,
			{ "Flags", "netlink-netfilter.ipset.cadt_flags",
			  FT_UINT32, BASE_HEX, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_ipset_attr_setname,
			{ "Setname", "netlink-netfilter.ipset.setname",
			  FT_STRINGZ, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_ipset_attr_typename,
			{ "Typename", "netlink-netfilter.ipset.typename",
			  FT_STRINGZ, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_ipset_attr_family,
			{ "Settype family", "netlink-netfilter.ipset.family",
			  FT_UINT8, BASE_DEC, VALS(nfproto_family_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_ipset_attr_flags,
			{ "Flags", "netlink-netfilter.ipset.flags",
			  FT_UINT32, BASE_HEX, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_ipset_adt_attr,
			{ "Type", "netlink-netfilter.ipset_adt_attr",
			  FT_UINT16, BASE_DEC, VALS(ipset_adt_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_ipset_adt_attr_comment,
			{ "Comment", "netlink-netfilter.ipset.comment",
			  FT_STRINGZ, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_ipset_ip_attr,
			{ "Type", "netlink-netfilter.ipset_ip_attr",
			  FT_UINT16, BASE_DEC, VALS(ipset_ip_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_ipset_ip_attr_ipv4,
			{ "IPv4 address", "netlink-netfilter.ipset.ip_addr",
			  FT_IPv4, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_ipset_ip_attr_ipv6,
			{ "IPv6 address", "netlink-netfilter.ipset.ip6_addr",
			  FT_IPv6, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nfexp_type,
			{ "Type", "netlink-netfilter.exp_type",
			  FT_UINT16, BASE_DEC, VALS(nfexp_type_vals), 0x00FF,
			  NULL, HFILL }
		},
		{ &hf_nfq_type,
			{ "Type", "netlink-netfilter.queue_type",
			  FT_UINT16, BASE_DEC, VALS(nfq_type_vals), 0x00FF,
			  NULL, HFILL }
		},
		{ &hf_ipset_command,
			{ "Command", "netlink-netfilter.ipset_command",
			  FT_UINT16, BASE_DEC, VALS(ipset_command_vals), 0x00FF,
			  NULL, HFILL }
		},
		{ &hf_nftables_command,
			{ "Command", "netlink-netfilter.nftables_command",
			  FT_UINT16, BASE_DEC, VALS(nftables_command_vals), 0x00FF,
			  NULL, HFILL }
		},
		{ &hf_nft_rule_attr,
			{ "Type", "netlink-netfilter.nft_rule",
			  FT_UINT16, BASE_DEC, VALS(nft_rule_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_nft_rule_attr_table,
			{ "Table", "netlink-netfilter.nft_rule.table",
			  FT_STRINGZ, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_rule_attr_chain,
			{ "Chain", "netlink-netfilter.nft_rule.chain",
			  FT_STRINGZ, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_rule_attr_handle,
			{ "Handle", "netlink-netfilter.nft_rule.handle",
			  FT_UINT64, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_rule_attr_position,
			{ "Position", "netlink-netfilter.nft_rule.position",
			  FT_UINT64, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_rule_attr_userdata,
			{ "Userdata", "netlink-netfilter.nft_rule.userdata",
			  FT_STRING, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_rule_attr_id,
			{ "ID", "netlink-netfilter.nft_rule.id",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_rule_attr_position_id,
			{ "Position ID", "netlink-netfilter.nft_rule.position_id",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_rule_attr_chain_id,
			{ "Chain ID", "netlink-netfilter.nft_rule.chain_id",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_rule_compat_attr,
			{ "Type", "netlink-netfilter.nft_rule.compat",
			  FT_UINT16, BASE_DEC, VALS(nft_rule_compat_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_nft_rule_compat_attr_proto,
			{ "Protocol", "netlink-netfilter.nft_rule.compat.proto",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_rule_compat_attr_flags,
			{ "Flags", "netlink-netfilter.nft_rule.compat.flags",
			  FT_UINT32, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_expr_attr,
			{ "Type", "netlink-netfilter.nft_expr",
			  FT_UINT16, BASE_DEC, VALS(nft_expr_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_nft_expr_attr_name,
			{ "Name", "netlink-netfilter.nft_expr.name",
			  FT_STRINGZ, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_list_attr,
			{ "Type", "netlink-netfilter.nft_list",
			  FT_UINT16, BASE_DEC, VALS(nft_list_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_nft_meta_attr,
			{ "Type", "netlink-netfilter.nft_expr.meta",
			  FT_UINT16, BASE_DEC, VALS(nft_meta_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_nft_meta_dreg,
			{ "Destination register", "netlink-netfilter.nft_expr.meta.dreg",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_meta_key,
			{ "Key", "netlink-netfilter.nft_expr.meta.key",
			  FT_UINT32, BASE_DEC, VALS(nft_meta_key_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_meta_sreg,
			{ "Source register", "netlink-netfilter.nft_expr.meta.sreg",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_cmp_attr,
			{ "Type", "netlink-netfilter.nft_expr.cmp",
			  FT_UINT16, BASE_DEC, VALS(nft_cmp_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_nft_cmp_sreg,
			{ "Source register", "netlink-netfilter.nft_expr.cmp.sreg",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_cmp_op,
			{ "Operation", "netlink-netfilter.nft_expr.cmp.op",
			  FT_UINT32, BASE_DEC, VALS(nft_cmp_op_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_payload_attr,
			{ "Type", "netlink-netfilter.nft_expr.payload",
			  FT_UINT16, BASE_DEC, VALS(nft_payload_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_nft_payload_dreg,
			{ "Destination register", "netlink-netfilter.nft_expr.payload.dreg",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_payload_base,
			{ "Base", "netlink-netfilter.nft_expr.payload.base",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_payload_offset,
			{ "Offset", "netlink-netfilter.nft_expr.payload.offset",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_payload_len,
			{ "Length", "netlink-netfilter.nft_expr.payload.len",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_payload_sreg,
			{ "Source register", "netlink-netfilter.nft_expr.payload.sreg",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_payload_csum_type,
			{ "Checksum type", "netlink-netfilter.nft_expr.payload.csum_type",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_payload_csum_offset,
			{ "Checksum offset", "netlink-netfilter.nft_expr.payload.csum_offset",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_payload_csum_flags,
			{ "Checksum flags", "netlink-netfilter.nft_expr.payload.csum_flags",
			  FT_UINT32, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_immediate_attr,
			{ "Type", "netlink-netfilter.nft_expr.immediate",
			  FT_UINT16, BASE_DEC, VALS(nft_immediate_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_nft_immediate_dreg,
			{ "Destination register", "netlink-netfilter.nft_expr.immediate.dreg",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_nat_attr,
			{ "Type", "netlink-netfilter.nft_expr.nat",
			  FT_UINT16, BASE_DEC, VALS(nft_nat_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_nft_nat_type,
			{ "NAT type", "netlink-netfilter.nft_expr.nat.type",
			  FT_UINT32, BASE_DEC, VALS(nft_nat_type_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_nat_family,
			{ "Family", "netlink-netfilter.nft_expr.nat.family",
			  FT_UINT32, BASE_DEC, VALS(nfproto_family_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_nat_reg_addr_min,
			{ "Address min register", "netlink-netfilter.nft_expr.nat.reg_addr_min",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_nat_reg_addr_max,
			{ "Address max register", "netlink-netfilter.nft_expr.nat.reg_addr_max",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_nat_reg_proto_min,
			{ "Protocol min register", "netlink-netfilter.nft_expr.nat.reg_proto_min",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_nat_reg_proto_max,
			{ "Protocol max register", "netlink-netfilter.nft_expr.nat.reg_proto_max",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_nat_flags,
			{ "Flags", "netlink-netfilter.nft_expr.nat.flags",
			  FT_UINT32, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_nft_data_attr,
			{ "Type", "netlink-netfilter.nft_data",
			  FT_UINT16, BASE_DEC, VALS(nft_data_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_nft_data_value,
			{ "Value", "netlink-netfilter.nft_data.value",
			  FT_BYTES, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_netfilter_subsys,
			{ "Subsystem", "netlink-netfilter.subsys",
			  FT_UINT16, BASE_DEC, VALS(netlink_netfilter_subsystem_vals), 0xFF00,
			  NULL, HFILL }
		},
		{ &hf_padding,
			{ "Padding", "netlink-netfilter.padding",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		}
	};

	static int *ett[] = {
		&ett_netlink_netfilter,
		&ett_nfct_attr,
		&ett_nfct_help_attr,
		&ett_nfct_seqadj_attr,
		&ett_nfct_status_attr,
		&ett_nfct_tuple_attr,
		&ett_nfct_tuple_ip_attr,
		&ett_nfct_tuple_proto_attr,
		&ett_nfq_config_attr,
		&ett_nfq_attr,
		&ett_nfexp_attr,
		&ett_nfexp_flags_attr,
		&ett_nfexp_nat_attr,
		&ett_ipset_attr,
		&ett_ipset_cadt_attr,
		&ett_ipset_adt_attr,
		&ett_ipset_ip_attr,
		&ett_nft_rule_attr,
		&ett_nft_rule_compat_attr,
		&ett_nft_expr_attr,
		&ett_nft_list_attr,
		&ett_nft_meta_attr,
		&ett_nft_cmp_attr,
		&ett_nft_payload_attr,
		&ett_nft_immediate_attr,
		&ett_nft_nat_attr,
		&ett_nft_data_attr,
	};

	proto_netlink_netfilter = proto_register_protocol("Linux netlink netfilter protocol", "netfilter", "netlink-netfilter" );
	proto_register_field_array(proto_netlink_netfilter, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	netlink_netfilter = register_dissector("netfilter", dissect_netlink_netfilter, proto_netlink_netfilter);
}

void
proto_reg_handoff_netlink_netfilter(void)
{
	dissector_add_uint("netlink.protocol", WS_NETLINK_NETFILTER, netlink_netfilter);

	nflog_handle = find_dissector_add_dependency("nflog", proto_netlink_netfilter);
	ethertype_table = find_dissector_table("ethertype");
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
