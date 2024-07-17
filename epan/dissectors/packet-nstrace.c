/* packet-nstrace.c
 * Routines for nstrace dissection
 * Copyright 2006, Ravi Kondamuru <Ravi.Kondamuru@citrix.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <epan/packet.h>
#include <wiretap/netscaler.h>

#define NSPR_V35_HEADER_LEN_OFFSET  26
#define NSPR_V35_ERROR_CODE_OFFSET  28
#define NSPR_V35_APP_OFFSET  29
#define NSPR_V35_NEXT_RECORD_OFFSET  34
#define NSPR_V35_TOTAL_SIZE  35

#define MAX_UNKNOWNREC_LOOP 5

#define NS_TCPCC_DEFAULT  0x00
#define NS_TCPCC_WESTWOOD 0x01
#define NS_TCPCC_BIC    0x02
#define NS_TCPCC_CUBIC  0x03
#define NS_TCPCC_NILE   0x04
#define NS_TCPCC_CUBIC_HYSTART 0x05
#define NS_TCPCC_INVALID  0x06
#define NS_TCPCC_LAST 0x07

#define TRCDBG_PRR 0x1
#define TRCDBG_BRST 0X2
#define TRCDBG_DRB 0X4
#define TRCDBG_NILE 0x8
#define TRCDBG_RTT 0x10


/* Netscaler Record types */
#define NSREC_NULL     0x00

/* 1.Standard protocols */
#define NSREC_ETHERNET 0x01
#define NSREC_HTTP     0x02

/* 2. netscaler specific records */
#define NSREC_TCPDEBUG  0x80
#define NSREC_CGP       0x81
#define NSREC_ICA       0x82
#define NSREC_INFO      0x83
#define NSREC_VMNAMES   0x84
#define NSREC_CLUSTER   0x85
#define NSREC_HTTP2     0x86
#define NSREC_SSL       0x87
#define NSREC_APPFW     0x88
#define NSREC_POL       0x89
#define NSREC_MPTCP     0x8A
#define NSREC_TCPDEBUG2 0x8B
#define NSREC_HTTPINFO  0x8D
#define NSREC_TCPCC     0x8C
#define NSREC_TRCDBG    0x8E
#define UNKNOWN_LAST    0xFF

/* Packet error codes */
#define ERR_NONE              0
#define ERR_DROP_PERX_LONGPKT 1
#define ERR_DROP_PERX_FIXHDR  2
#define ERR_DROP_PERX_DUPFREE 3
#define ERR_PKT_FWD           4
#define ERR_PKT_FWD6          5
#define ERR_LAST              6

#define APP_NULL    0x00
#define APP_IP      0x01
#define APP_TCP     0x02
#define APP_SPDY    0x03
#define APP_UDP     0x04
#define APP_HSM     0x05
#define APP_DNS     0x06
#define APP_SSLDEC  0x07
#define APP_AAA     0x08
#define APP_SNMP    0x09
#define APP_RTSP    0x0A
#define APP_NAT     0x0B
#define APP_MYSQL   0x0C
#define APP_IPFIX   0x0D
#define APP_ORACLE  0x0E
#define APP_ICA     0x0F
#define APP_SMPP    0x10
#define APP_RDP     0x11
#define APP_TFTP    0x12
#define APP_PPTP    0x13
#define APP_MPTCPIN 0x14
#define APP_HTTP2   0x15
#define APP_IPSEC   0x16
#define APP_TEST    0x17
#define APP_L2      0x18
#define APP_LLDP    0x19
#define APP_VPATH   0x1A
#define APP_NAT64   0x1B
#define APP_APPFW   0x1C
#define APP_IP6     0x1D
#define APP_ARP     0x1E
#define APP_SSLENC  0x1F
#define APP_MPTCPOUT 0x20
#define APP_DRB     0x21
#define APP_PRR     0x22

void proto_register_ns(void);
void proto_reg_handoff_ns(void);

static int proto_nstrace;

static int hf_ns_nicno;
static int hf_ns_src_vm;
static int hf_ns_dst_vm;
static int hf_ns_dir;
static int hf_ns_pcbdevno;
static int hf_ns_l_pcbdevno;
static int hf_ns_devno;
static int hf_ns_vlantag;
static int hf_ns_coreid;

static int hf_ns_errorcode;
static int hf_ns_app;

static int hf_ns_snode;
static int hf_ns_dnode;
static int hf_ns_clflags;
static int hf_ns_clflags_res;
static int hf_ns_clflags_rssh;
static int hf_ns_clflags_rss;
static int hf_ns_clflags_dfd;
static int hf_ns_clflags_fr;
static int hf_ns_clflags_fp;

static int hf_ns_activity;
static int hf_ns_activity_perf_collection;
static int hf_ns_activity_pcb_zombie;
static int hf_ns_activity_natpcb_zombie;
static int hf_ns_activity_lbstats_sync;
static int hf_ns_activity_stats_req;

static int hf_ns_capflags;
static int hf_ns_capflags_dbg;
static int hf_ns_capflags_int;
static int hf_ns_capflags_skipnwhdr;

static int hf_ns_tcpdbg;
static int hf_ns_tcpdbg_cwnd;
static int hf_ns_tcpdbg_rtrtt;
static int hf_ns_tcpdbg_tsrecent;
static int hf_ns_tcpdbg_httpabort;

static int hf_ns_tcpdbg2;
static int hf_ns_tcpdbg2_sndCwnd;
static int hf_ns_tcpdbg2_ssthresh;
static int hf_ns_tcpdbg2_sndbuf;
static int hf_ns_tcpdbg2_max_rcvbuf;
static int hf_ns_tcpdbg2_bw_estimate;
static int hf_ns_tcpdbg2_rtt;
static int hf_ns_tcpdbg2_tcpos_pktcnt;
static int hf_ns_tcpdbg2_ts_recent;
static int hf_ns_tcpdbg2_tcp_cfgsndbuf;
static int hf_ns_tcpdbg2_tcp_flvr;
static int hf_ns_trcdbg;
static int hf_ns_trcdbg_val1;
static int hf_ns_trcdbg_val1_PRR;
static int hf_ns_trcdbg_val1_NILE;
static int hf_ns_trcdbg_val1_RTT;
static int hf_ns_trcdbg_val1_BURST;
static int hf_ns_trcdbg_val2;
static int hf_ns_trcdbg_val2_PRR;
static int hf_ns_trcdbg_val2_NILE;
static int hf_ns_trcdbg_val2_RTT;
static int hf_ns_trcdbg_val3;
static int hf_ns_trcdbg_val3_PRR;
static int hf_ns_trcdbg_val3_NILE;
static int hf_ns_trcdbg_val3_RTT;
static int hf_ns_trcdbg_val4;
static int hf_ns_trcdbg_val4_PRR;
static int hf_ns_trcdbg_val4_NILE;
static int hf_ns_trcdbg_val4_RTT;
static int hf_ns_trcdbg_val5;
static int hf_ns_trcdbg_val5_DRB_APP;
static int hf_ns_trcdbg_val5_NILE;
static int hf_ns_trcdbg_val5_RTT;
static int hf_ns_trcdbg_val6;
static int hf_ns_trcdbg_val6_DRB_APP;
static int hf_ns_trcdbg_val6_NILE;
static int hf_ns_trcdbg_val6_RTT;
static int hf_ns_trcdbg_val7;
static int hf_ns_trcdbg_val7_DRB;
static int hf_ns_trcdbg_val7_NILE;
static int hf_ns_trcdbg_val7_DRB_APP;
static int hf_ns_trcdbg_val8;
static int hf_ns_trcdbg_val8_DRB;
static int hf_ns_trcdbg_val8_NILE;
static int hf_ns_trcdbg_val8_DRB_APP;
static int hf_ns_trcdbg_val9;
static int hf_ns_trcdbg_val9_DRB;
static int hf_ns_trcdbg_val9_NILE;
static int hf_ns_trcdbg_val10;
static int hf_ns_trcdbg_val10_DRB;
static int hf_ns_trcdbg_val10_NILE;
static int hf_ns_trcdbg_val11;
static int hf_ns_trcdbg_val11_RTT;
static int hf_ns_trcdbg_val11_DRB;
static int hf_ns_trcdbg_val11_DRB_APP;
static int hf_ns_trcdbg_val11_NILE;
static int hf_ns_trcdbg_val11_BURST;
static int hf_ns_trcdbg_val12;
static int hf_ns_trcdbg_val12_NILE;
static int hf_ns_trcdbg_val12_RTT;
static int hf_ns_trcdbg_val13;
static int hf_ns_trcdbg_val13_DRB;
static int hf_ns_trcdbg_val13_NILE;
static int hf_ns_trcdbg_val14;
static int hf_ns_trcdbg_val14_NILE;
static int hf_ns_trcdbg_val15;
static int hf_ns_httpInfo;
static int hf_ns_httpInfo_httpabort;

static int hf_ns_tcpcc;
static int hf_ns_tcpcc_last_max_cwnd;
static int hf_ns_tcpcc_loss_cwnd;
static int hf_ns_tcpcc_last_time;
static int hf_ns_tcpcc_last_cwnd;
static int hf_ns_tcpcc_delay_min;
static int hf_ns_tcpcc_ack_cnt;
static int hf_ns_tcpcc_last_ack;
static int hf_ns_tcpcc_round_start;
static int hf_ns_tcpcc_end_seq;
static int hf_ns_tcpcc_curr_rtt;
static int hf_ns_tcpcc_rtt_min;
static int hf_ns_tcpcc_alpha;
static int hf_ns_tcpcc_beta_val;
static int hf_ns_tcpcc_rtt_low;
static int hf_ns_tcpcc_rtt_above;
static int hf_ns_tcpcc_max_rtt;
static int hf_ns_tcpcc_base_rtt;
static int hf_ns_unknownrec;
static int hf_ns_unknowndata;

static int hf_ns_inforec;
static int hf_ns_inforec_info;

static int hf_ns_sslrec;
static int hf_ns_sslrec_seq;

static int hf_ns_mptcprec;
static int hf_ns_mptcprec_subflowid;

static int hf_ns_vmnamerec;
static int hf_ns_vmnamerec_srcvmname;
static int hf_ns_vmnamerec_dstvmname;

static int hf_ns_clusterrec;
static int hf_ns_clu_snode;
static int hf_ns_clu_dnode;
static int hf_ns_clu_clflags;
static int hf_ns_clu_clflags_res;
static int hf_ns_clu_clflags_rssh;
static int hf_ns_clu_clflags_rss;
static int hf_ns_clu_clflags_dfd;
static int hf_ns_clu_clflags_fr;
static int hf_ns_clu_clflags_fp;

static int ett_ns;
static int ett_ns_flags;
static int ett_ns_activity_flags;
static int ett_ns_tcpdebug;
static int ett_ns_tcpdebug2;
static int ett_ns_trcdbg;
static int ett_ns_httpInfo;
static int ett_ns_tcpcc;
static int ett_ns_inforec;
static int ett_ns_sslrec;
static int ett_ns_mptcprec;
static int ett_ns_vmnamerec;
static int ett_ns_clusterrec;
static int ett_ns_clu_clflags;
static int ett_ns_unknownrec;
static int ett_ns_capflags;

static int hf_ns_snd_cwnd;
static int hf_ns_realtime_rtt;
static int hf_ns_ts_recent;
static int hf_ns_http_abort_tracking_reason;

static const value_string ns_errorcode_vals[] = {
  { ERR_NONE,  "No Error" },
  { ERR_DROP_PERX_LONGPKT,  "Long packet" },
  { ERR_DROP_PERX_FIXHDR,   "Fix header" },
  { ERR_DROP_PERX_DUPFREE,  "Dup free" },
  { ERR_PKT_FWD,            "Forwarded packet" },
  { ERR_PKT_FWD6,           "Forwarded ipv6 packet" },
  { 0, NULL },
};

static const value_string tcp_dbg2_flavour[] = {

	{ NS_TCPCC_DEFAULT,  "DEFAULT"},
	{ NS_TCPCC_WESTWOOD, "WESTWOOD" },
	{ NS_TCPCC_BIC,"BIC"},
	{ NS_TCPCC_CUBIC,"CUBIC"},
	{ NS_TCPCC_NILE,"NILE"},
	{ NS_TCPCC_CUBIC_HYSTART, "HYSTART"},
	{ NS_TCPCC_INVALID ,"INVALID"},
	{ 0, NULL },
};
static const value_string ns_app_vals[] = {
  { APP_NULL,  "NULL"   },
  { APP_IP,    "IP"     },
  { APP_DNS,   "DNS"    },
  { APP_SSLDEC,"SSL-DEC"},
  { APP_AAA,   "AAA"    },
  { APP_SNMP,  "SNMP"   },
  { APP_RTSP,  "RTSP"   },
  { APP_NAT,   "NAT"    },
  { APP_MYSQL, "MYSQL"  },
  { APP_ORACLE,"ORACLE" },
  { APP_SMPP,  "SMPP"   },
  { APP_TFTP,  "TFTP"   },
  { APP_PPTP,  "PPTP"   },
  { APP_MPTCPIN,"MPTCP-IN"  },
  { APP_HTTP2, "HTTP2"  },
  { APP_IPSEC, "IPSEC"  },
  { APP_TEST,  "TEST"   },
  { APP_L2,    "L2"     },
  { APP_LLDP,  "LLDP"   },
  { APP_VPATH, "VPATH"  },
  { APP_NAT64, "NAT64"  },
  { APP_APPFW, "APPFW"  },
  { APP_IP6,   "IP6"    },
  { APP_ARP,   "ARP"    },
  { APP_SSLENC,"SSL-ENC"},
  { APP_MPTCPOUT,"MPTCP-OUT"  },
  { APP_DRB,    "DRB"    },
  { APP_PRR,    "PRR"    },
  { 0,   NULL    },
};
static value_string_ext ns_app_vals_ext = VALUE_STRING_EXT_INIT(ns_app_vals);


static const value_string ns_dir_vals[] = {
	{ NSPR_PDPKTRACEFULLTX_V26,    "TX" },
	{ NSPR_PDPKTRACEFULLTXB_V26,   "TXB" },
	{ NSPR_PDPKTRACEFULLRX_V26,    "RX" },
	{ NSPR_PDPKTRACEFULLNEWRX_V26, "NEW_RX" },
	{ NSPR_PDPKTRACEPARTTX_V26,    "TX" },
	{ NSPR_PDPKTRACEPARTTXB_V26,   "TXB" },
	{ NSPR_PDPKTRACEPARTRX_V26,    "RX" },
	{ NSPR_PDPKTRACEPARTNEWRX_V26, "NEW_RX" },
	{ NSPR_PDPKTRACEFULLTX_V30,    "TX" },
	{ NSPR_PDPKTRACEFULLTXB_V30,   "TXB" },
	{ NSPR_PDPKTRACEFULLRX_V30,    "RX" },
	{ NSPR_PDPKTRACEFULLNEWRX_V30, "NEW_RX" },
	{ NSPR_PDPKTRACEFULLTX_V35,    "TX" },
	{ NSPR_PDPKTRACEFULLTXB_V35,   "TXB" },
	{ NSPR_PDPKTRACEFULLRX_V35,    "RX" },
	{ NSPR_PDPKTRACEFULLNEWRX_V35, "NEW_RX" },
	{ NSPR_PDPKTRACEFULLTX_V25,    "TX" },
	{ NSPR_PDPKTRACEFULLTXB_V25,   "TXB" },
	{ NSPR_PDPKTRACEFULLRX_V25,    "RX" },
	{ NSPR_PDPKTRACEFULLNEWRX_V25, "NEW_RX" },
	{ NSPR_PDPKTRACEPARTTX_V25,    "TX" },
	{ NSPR_PDPKTRACEPARTTXB_V25,   "TXB" },
	{ NSPR_PDPKTRACEPARTRX_V25,    "RX" },
	{ NSPR_PDPKTRACEPARTNEWRX_V25, "NEW_RX" },
	{ NSPR_PDPKTRACEFULLTX_V20,    "TX" },
	{ NSPR_PDPKTRACEFULLTXB_V20,   "TXB" },
	{ NSPR_PDPKTRACEFULLRX_V20,    "RX" },
	{ NSPR_PDPKTRACEPARTTX_V20,    "TX" },
	{ NSPR_PDPKTRACEPARTTXB_V20,   "TXB" },
	{ NSPR_PDPKTRACEPARTRX_V20,    "RX" },
	{ NSPR_PDPKTRACEFULLTX_V21,    "TX" },
	{ NSPR_PDPKTRACEFULLTXB_V21,   "TXB" },
	{ NSPR_PDPKTRACEFULLRX_V21,    "RX" },
	{ NSPR_PDPKTRACEPARTTX_V21,    "TX" },
	{ NSPR_PDPKTRACEPARTTXB_V21,   "TXB" },
	{ NSPR_PDPKTRACEPARTRX_V21,    "RX" },
	{ NSPR_PDPKTRACEFULLTX_V22,    "TX" },
	{ NSPR_PDPKTRACEFULLTXB_V22,   "TXB" },
	{ NSPR_PDPKTRACEFULLRX_V22,    "RX" },
	{ NSPR_PDPKTRACEPARTTX_V22,    "TX" },
	{ NSPR_PDPKTRACEPARTTXB_V22,   "TXB" },
	{ NSPR_PDPKTRACEPARTRX_V22,    "RX" },
	{ NSPR_PDPKTRACEFULLTX_V23,    "TX" },
	{ NSPR_PDPKTRACEFULLTXB_V23,   "TXB" },
	{ NSPR_PDPKTRACEFULLRX_V23,    "RX" },
	{ NSPR_PDPKTRACEPARTTX_V23,    "TX" },
	{ NSPR_PDPKTRACEPARTTXB_V23,   "TXB" },
	{ NSPR_PDPKTRACEPARTRX_V23,    "RX" },
	{ NSPR_PDPKTRACEFULLTX_V24,    "TX" },
	{ NSPR_PDPKTRACEFULLTXB_V24,   "TXB" },
	{ NSPR_PDPKTRACEFULLRX_V24,    "RX" },
	{ NSPR_PDPKTRACEFULLNEWRX_V24, "NEW_RX" },
	{ NSPR_PDPKTRACEPARTTX_V24,    "TX" },
	{ NSPR_PDPKTRACEPARTTXB_V24,   "TXB" },
	{ NSPR_PDPKTRACEPARTRX_V24,    "RX" },
	{ NSPR_PDPKTRACEPARTNEWRX_V24, "NEW_RX" },
	{ NSPR_PDPKTRACEFULLTX_V10,    "TX" },
	{ NSPR_PDPKTRACEFULLTXB_V10,   "TXB" },
	{ NSPR_PDPKTRACEFULLRX_V10,    "RX" },
	{ NSPR_PDPKTRACEPARTTX_V10,    "TX"  },
	{ NSPR_PDPKTRACEPARTTXB_V10,   "TXB" },
	{ NSPR_PDPKTRACEPARTRX_V10,    "RX" },
	{ 0,              NULL }
};
static value_string_ext ns_dir_vals_ext = VALUE_STRING_EXT_INIT(ns_dir_vals);


static const value_string ns_httpabortcode_vals[] = {
	{0, "connection is trackable"},
	{1, "connection is marked for NOREUSE on receiving CONNECT request"},
	{2, "no reuse due to HTTP/0.9 Request processing"},
	{3, "received FIN from server in the middle of transaction"},
	{4, "VPN GSLB CONNECTION PROXY connections"},
	{5, "if http FA moves to unknown on clt req; svr_pcb's http state is also made unknown"},
	{6, "Incomplete HTTP chunk"},
	{7, "forward proxy connect url received and flagged for noreuse"},
	{8, "connection is not reused because we received more than content-length amount of data from server"},
	{9, "the Incomplete header reassembly failed"},
	{10, "invalid header"},
	{11, "RTSP : the Incomplete header reassembly failed"},
	{12, "RTSP : incomplete header processing is terminated in case of interleaved RTSP data frame"},
	{13, "websocket connection upgrade failed on server side"},
	{14, "RTSP : connection is marked untrackable due to memory failures"},
	{15, "RTSP : transaction marked untrackable"},
	{0, NULL },
};
static value_string_ext ns_httpabortcode_vals_ext = VALUE_STRING_EXT_INIT(ns_httpabortcode_vals);

static dissector_handle_t nstrace_handle;

static dissector_handle_t eth_withoutfcs_handle;
static dissector_handle_t http_handle;


static void add35records(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *ns_tree);

#define CL_FP 	0x01
#define CL_FR 	0x02
#define CL_DFD	0x04
#define CL_RSS	0x08
#define CL_RSSH	0x10
#define CL_RES	0xE0

#define NS_PE_STATE_PERF_COLLECTION_IN_PROG     0x00000001
#define NS_PE_STATE_PCB_ZOMBIE_IN_PROG          0x00000002
#define NS_PE_STATE_NATPCB_ZOMBIE_IN_PROG       0x00000004
#define NS_PE_STATE_LBSTATS_SYNC_IN_PROG        0x00000008
#define NS_PE_STATE_STATS_REQ_IN_PROG           0x00000010

#define NS_CAPFLAG_DBG          0x00020000
#define NS_CAPFLAG_INT          0x00040000
#define NS_CAPFLAG_SKIPNWHDR    0x00080000

static int
dissect_nstrace(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int error_code = 0;
	proto_tree	*ns_tree;
	proto_item	*ti;
	struct nstr_phdr *pnstr = &(pinfo->pseudo_header->nstr);
	tvbuff_t	*next_tvb_eth_client;
	uint8_t		src_vmname_len = 0, dst_vmname_len = 0;
	uint8_t		variable_ns_len = 0;
	uint32_t		vlan;
	static int * const activity_flags[] = {
		&hf_ns_activity_perf_collection,
		&hf_ns_activity_pcb_zombie,
		&hf_ns_activity_natpcb_zombie,
		&hf_ns_activity_lbstats_sync,
		&hf_ns_activity_stats_req,
		NULL
	};

	switch(pnstr->rec_type)
	{
	case NSPR_HEADER_VERSION205:
	case NSPR_HEADER_VERSION300:
	case NSPR_HEADER_VERSION206:
		src_vmname_len = tvb_get_uint8(tvb,pnstr->src_vmname_len_offset);
		dst_vmname_len = tvb_get_uint8(tvb,pnstr->dst_vmname_len_offset);
		variable_ns_len = src_vmname_len + dst_vmname_len;
		pnstr->eth_offset += variable_ns_len;
		break;
	}

	ti = proto_tree_add_protocol_format(tree, proto_nstrace, tvb, 0, pnstr->eth_offset, "NetScaler Packet Trace");
	ns_tree = proto_item_add_subtree(ti, ett_ns);

	proto_tree_add_item(ns_tree, hf_ns_dir, tvb, pnstr->dir_offset, pnstr->dir_len, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ns_tree, hf_ns_nicno, tvb, pnstr->nicno_offset, pnstr->nicno_len, ENC_LITTLE_ENDIAN);

	switch (pnstr->rec_type)
	{
	case NSPR_HEADER_VERSION300:
	case NSPR_HEADER_VERSION206:
		proto_tree_add_bitmask(ns_tree, tvb, pnstr->ns_activity_offset, hf_ns_activity, ett_ns_activity_flags, activity_flags, ENC_LITTLE_ENDIAN);

		proto_tree_add_item(ns_tree, hf_ns_snd_cwnd, tvb, (pnstr->ns_activity_offset + 4), 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(ns_tree, hf_ns_realtime_rtt, tvb, (pnstr->ns_activity_offset + 8), 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(ns_tree, hf_ns_ts_recent, tvb, (pnstr->ns_activity_offset + 12), 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(ns_tree, hf_ns_http_abort_tracking_reason, tvb, (pnstr->dst_vmname_len_offset + 1), 1, ENC_LITTLE_ENDIAN);

		/* fall through */

	case NSPR_HEADER_VERSION205:

		if(src_vmname_len){
			proto_tree_add_item(ns_tree,hf_ns_src_vm,tvb,pnstr->data_offset,src_vmname_len,ENC_ASCII);
			}

		if(dst_vmname_len){
			proto_tree_add_item(ns_tree,hf_ns_dst_vm,tvb,pnstr->data_offset+src_vmname_len,dst_vmname_len,ENC_ASCII);
			}
		/* fall through */


	case NSPR_HEADER_VERSION204:
		{
		static int * const clflags[] = {
			&hf_ns_clflags_res,
			&hf_ns_clflags_rssh,
			&hf_ns_clflags_rss,
			&hf_ns_clflags_dfd,
			&hf_ns_clflags_fr,
			&hf_ns_clflags_fp,
			NULL
		};

		proto_tree_add_item(ns_tree, hf_ns_snode, tvb, pnstr->srcnodeid_offset, 2, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(ns_tree, hf_ns_dnode, tvb, pnstr->destnodeid_offset, 2, ENC_LITTLE_ENDIAN);

		proto_tree_add_bitmask(ns_tree, tvb, pnstr->clflags_offset, hf_ns_clflags, ett_ns_flags, clflags, ENC_NA);
		}
		/* fall through */

	case NSPR_HEADER_VERSION203:
		proto_tree_add_item(ns_tree, hf_ns_coreid, tvb, pnstr->coreid_offset, 2, ENC_LITTLE_ENDIAN);
		/* fall through */

	case NSPR_HEADER_VERSION202:
		proto_tree_add_item_ret_uint(ns_tree, hf_ns_vlantag, tvb, pnstr->vlantag_offset, 2, ENC_LITTLE_ENDIAN, &vlan);
		/* fall through */

	case NSPR_HEADER_VERSION201:
		proto_tree_add_item(ns_tree, hf_ns_pcbdevno, tvb, pnstr->pcb_offset, 4, ENC_LITTLE_ENDIAN);
		ti = proto_tree_add_item(ns_tree, hf_ns_devno, tvb, pnstr->pcb_offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_set_hidden(ti);

		proto_tree_add_item(ns_tree, hf_ns_l_pcbdevno, tvb, pnstr->l_pcb_offset, 4, ENC_LITTLE_ENDIAN);
		ti = proto_tree_add_item(ns_tree, hf_ns_devno, tvb, pnstr->l_pcb_offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_set_hidden(ti);

		break;

	case NSPR_HEADER_VERSION350:
		{
			static int * const cap_flags[] = {
				&hf_ns_capflags_dbg,
				&hf_ns_capflags_int,
				&hf_ns_capflags_skipnwhdr,
				NULL
			};
			proto_tree_add_bitmask(ns_tree, tvb, pnstr->ns_activity_offset, hf_ns_activity, ett_ns_activity_flags, activity_flags, ENC_LITTLE_ENDIAN);
			proto_tree_add_bitmask(ns_tree, tvb, pnstr->ns_activity_offset, hf_ns_capflags, ett_ns_capflags, cap_flags, ENC_LITTLE_ENDIAN);

			proto_tree_add_item(ns_tree, hf_ns_errorcode, tvb, NSPR_V35_ERROR_CODE_OFFSET, 1, ENC_LITTLE_ENDIAN);
			error_code = tvb_get_uint8(tvb, NSPR_V35_ERROR_CODE_OFFSET);
			proto_tree_add_item(ns_tree, hf_ns_app, tvb, NSPR_V35_APP_OFFSET, 1, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(ns_tree, hf_ns_coreid, tvb, pnstr->coreid_offset, 2, ENC_LITTLE_ENDIAN);

			/* NSPR_HEADER_VERSION202 stuff */
			proto_tree_add_item_ret_uint(ns_tree, hf_ns_vlantag, tvb, pnstr->vlantag_offset, 2, ENC_LITTLE_ENDIAN, &vlan);

			/* NSPR_HEADER_VERSION201 stuff */
			proto_tree_add_item(ns_tree, hf_ns_pcbdevno, tvb, pnstr->pcb_offset, 4, ENC_LITTLE_ENDIAN);
			ti = proto_tree_add_item(ns_tree, hf_ns_devno, tvb, pnstr->pcb_offset, 4, ENC_LITTLE_ENDIAN);
			proto_item_set_hidden(ti);

			proto_tree_add_item(ns_tree, hf_ns_l_pcbdevno, tvb, pnstr->l_pcb_offset, 4, ENC_LITTLE_ENDIAN);
			ti = proto_tree_add_item(ns_tree, hf_ns_devno, tvb, pnstr->l_pcb_offset, 4, ENC_LITTLE_ENDIAN);
			proto_item_set_hidden(ti);

			add35records(tvb, pinfo, tree, ns_tree);
			if (error_code)
			{
				col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "NS DROPPED | ");
			}
		}
		break; /* we can return here. break;ing in case some compilers are unhappy */

	default:
		break;
	}

	if(pnstr->rec_type != NSPR_HEADER_VERSION350){
		/* Dissect as Ethernet */
		next_tvb_eth_client = tvb_new_subset_remaining(tvb, pnstr->eth_offset);
		call_dissector(eth_withoutfcs_handle, next_tvb_eth_client, pinfo, tree);
	}

	return tvb_captured_length(tvb);
}

static bool no_record_header(int rec_type)
{
	switch(rec_type)
	{
	case NSREC_ETHERNET:
	case NSREC_HTTP:
	case NSREC_NULL:
		return true;
	}

	return false;
}

static void add35records(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *ns_tree)
{
	tvbuff_t  *next_tvb;
	unsigned  nsheaderlen=0;
	uint8_t   ssl_internal=0;
	unsigned		offset;
	int flavour_value = 0;
	int app_value = 0;
	int morerecs=1;
	int loopcount=0;
	int reclen = 0, nextrec = 0;
	int cur_record=tvb_get_uint8(tvb, NSPR_V35_NEXT_RECORD_OFFSET);
	bool record_header;
	proto_tree* subtree;
	proto_item* subitem;
	unsigned int tcp_mode = 0;
	static int * const cluster_flags[] = {
		&hf_ns_clu_clflags_fp,
		&hf_ns_clu_clflags_fr,
		&hf_ns_clu_clflags_dfd,
		&hf_ns_clu_clflags_rss,
		&hf_ns_clu_clflags_rssh,
		&hf_ns_clu_clflags_res,
		NULL,
	};
	int hf_ns_trcdbg_val1_final = hf_ns_trcdbg_val1;
	int hf_ns_trcdbg_val2_final = hf_ns_trcdbg_val2;
	int hf_ns_trcdbg_val3_final = hf_ns_trcdbg_val3;
	int hf_ns_trcdbg_val4_final = hf_ns_trcdbg_val4;
	int hf_ns_trcdbg_val5_final = hf_ns_trcdbg_val5;
	int hf_ns_trcdbg_val6_final = hf_ns_trcdbg_val6;
	int hf_ns_trcdbg_val7_final = hf_ns_trcdbg_val7;
	int hf_ns_trcdbg_val8_final = hf_ns_trcdbg_val8;
	int hf_ns_trcdbg_val9_final = hf_ns_trcdbg_val9;
	int hf_ns_trcdbg_val10_final = hf_ns_trcdbg_val10;
	int hf_ns_trcdbg_val11_final = hf_ns_trcdbg_val11;
	int hf_ns_trcdbg_val12_final = hf_ns_trcdbg_val12;
	int hf_ns_trcdbg_val13_final = hf_ns_trcdbg_val13;
	int hf_ns_trcdbg_val14_final = hf_ns_trcdbg_val14;

	nsheaderlen = tvb_get_letohs(tvb, NSPR_V35_HEADER_LEN_OFFSET);
	offset = NSPR_V35_TOTAL_SIZE;

	do {
		record_header = !no_record_header(cur_record);
		if (record_header)
		{
			reclen = tvb_get_letohs(tvb,offset);
			nextrec = tvb_get_uint8(tvb,offset+2);
		}

		switch (cur_record){
			/* Add a case statement here for each record */
		case NSREC_ETHERNET:
			/* Call Ethernet dissector */
			next_tvb = tvb_new_subset_remaining(tvb, offset);
			call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);
			if (ssl_internal){
				col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[NS_INTERNAL_SSL]");
			}
			morerecs = 0;
			break;
		case NSREC_HTTP:
			/* Call HTTP dissector */
			morerecs = 0;
			next_tvb = tvb_new_subset_remaining(tvb, offset);
			call_dissector(http_handle, next_tvb, pinfo, tree);
			break;
		case NSREC_NULL:
			morerecs = 0;
			break;
		case NSREC_TCPDEBUG:
			/* Add tcpdebug subtree */
			subitem = proto_tree_add_item(ns_tree, hf_ns_tcpdbg, tvb, offset, reclen, ENC_NA);
			subtree = proto_item_add_subtree(subitem, ett_ns_tcpdebug);
			proto_tree_add_item(subtree, hf_ns_tcpdbg_cwnd, tvb, offset + 3, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_ns_tcpdbg_rtrtt, tvb, offset + 7, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_ns_tcpdbg_tsrecent, tvb, offset + 11, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_ns_tcpdbg_httpabort, tvb, offset + 15, 1, ENC_LITTLE_ENDIAN);

			offset += reclen;
			cur_record = nextrec;
			break;
		case NSREC_TCPDEBUG2:
			/* Add tcpdebug2 subtree */
			subitem = proto_tree_add_item(ns_tree, hf_ns_tcpdbg2, tvb, offset, reclen, ENC_NA);
			subtree = proto_item_add_subtree(subitem, ett_ns_tcpdebug2);
			proto_tree_add_item(subtree, hf_ns_tcpdbg2_sndCwnd, tvb, offset + 3, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_ns_tcpdbg2_ssthresh, tvb, offset + 7, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_ns_tcpdbg2_sndbuf, tvb, offset + 11, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_ns_tcpdbg2_max_rcvbuf, tvb, offset + 15, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_ns_tcpdbg2_bw_estimate, tvb, offset + 19, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_ns_tcpdbg2_rtt, tvb, offset + 23, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_ns_tcpdbg2_tcpos_pktcnt, tvb, offset + 27, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_ns_tcpdbg2_ts_recent, tvb, offset + 31, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_ns_tcpdbg2_tcp_cfgsndbuf, tvb, offset + 35, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_ns_tcpdbg2_tcp_flvr, tvb, offset + 39, 1, ENC_LITTLE_ENDIAN);
			flavour_value = tvb_get_uint8(tvb, offset + 39);

			offset += reclen;
			cur_record = nextrec;
			break;
		case NSREC_TRCDBG:
			/* Add tcpdebug2 subtree */
			subitem = proto_tree_add_item(ns_tree, hf_ns_trcdbg, tvb, offset, reclen, ENC_NA);
			subtree = proto_item_add_subtree(subitem, ett_ns_trcdbg);
			app_value = tvb_get_uint8(tvb, NSPR_V35_APP_OFFSET);
			tcp_mode = tvb_get_uint32(tvb, offset + 59, ENC_LITTLE_ENDIAN);
			switch(tcp_mode)
			{
				case TRCDBG_PRR:
				case TRCDBG_DRB:
				case (TRCDBG_DRB | TRCDBG_PRR):
					switch(app_value)
					{
						case APP_PRR:
							hf_ns_trcdbg_val1_final = hf_ns_trcdbg_val1_PRR;
							hf_ns_trcdbg_val2_final = hf_ns_trcdbg_val2_PRR;
							hf_ns_trcdbg_val3_final = hf_ns_trcdbg_val3_PRR;
							hf_ns_trcdbg_val4_final = hf_ns_trcdbg_val4_PRR;
							hf_ns_trcdbg_val7_final = hf_ns_trcdbg_val7_DRB;
							hf_ns_trcdbg_val8_final = hf_ns_trcdbg_val8_DRB;
							hf_ns_trcdbg_val9_final = hf_ns_trcdbg_val9_DRB;
							hf_ns_trcdbg_val10_final = hf_ns_trcdbg_val10_DRB;
							hf_ns_trcdbg_val11_final = hf_ns_trcdbg_val11_DRB;
							hf_ns_trcdbg_val13_final = hf_ns_trcdbg_val13_DRB;
							break;
						case APP_DRB:
							hf_ns_trcdbg_val5_final = hf_ns_trcdbg_val5_DRB_APP;
							hf_ns_trcdbg_val6_final = hf_ns_trcdbg_val6_DRB_APP;
							hf_ns_trcdbg_val7_final = hf_ns_trcdbg_val7_DRB_APP;
							hf_ns_trcdbg_val8_final = hf_ns_trcdbg_val8_DRB_APP;
							hf_ns_trcdbg_val9_final = hf_ns_trcdbg_val9_DRB;
							hf_ns_trcdbg_val10_final = hf_ns_trcdbg_val10_DRB;
							hf_ns_trcdbg_val11_final = hf_ns_trcdbg_val11_DRB_APP;
							hf_ns_trcdbg_val13_final = hf_ns_trcdbg_val13_DRB;
							break;
						default:
							hf_ns_trcdbg_val7_final = hf_ns_trcdbg_val7_DRB;
							hf_ns_trcdbg_val8_final = hf_ns_trcdbg_val8_DRB;
							hf_ns_trcdbg_val9_final = hf_ns_trcdbg_val9_DRB;
							hf_ns_trcdbg_val10_final = hf_ns_trcdbg_val10_DRB;
							hf_ns_trcdbg_val11_final = hf_ns_trcdbg_val11_DRB;
							hf_ns_trcdbg_val13_final = hf_ns_trcdbg_val13_DRB;
					}
					break;
				case TRCDBG_RTT:
					hf_ns_trcdbg_val1_final = hf_ns_trcdbg_val1_RTT;
					hf_ns_trcdbg_val2_final = hf_ns_trcdbg_val2_RTT;
					hf_ns_trcdbg_val3_final = hf_ns_trcdbg_val3_RTT;
					hf_ns_trcdbg_val4_final = hf_ns_trcdbg_val4_RTT;
					hf_ns_trcdbg_val5_final = hf_ns_trcdbg_val5_RTT;
					hf_ns_trcdbg_val6_final = hf_ns_trcdbg_val6_RTT;
					hf_ns_trcdbg_val11_final = hf_ns_trcdbg_val11_RTT;
					hf_ns_trcdbg_val12_final = hf_ns_trcdbg_val12_RTT;
					break;
				case TRCDBG_BRST:
					hf_ns_trcdbg_val1_final = hf_ns_trcdbg_val1_BURST;
					hf_ns_trcdbg_val11_final = hf_ns_trcdbg_val11_BURST;
					break;
				case TRCDBG_NILE:
					hf_ns_trcdbg_val1_final = hf_ns_trcdbg_val1_NILE;
					hf_ns_trcdbg_val2_final = hf_ns_trcdbg_val2_NILE;
					hf_ns_trcdbg_val3_final = hf_ns_trcdbg_val3_NILE;
					hf_ns_trcdbg_val4_final = hf_ns_trcdbg_val4_NILE;
					hf_ns_trcdbg_val5_final = hf_ns_trcdbg_val5_NILE;
					hf_ns_trcdbg_val6_final = hf_ns_trcdbg_val6_NILE;
					hf_ns_trcdbg_val7_final = hf_ns_trcdbg_val7_NILE;
					hf_ns_trcdbg_val8_final = hf_ns_trcdbg_val8_NILE;
					hf_ns_trcdbg_val9_final = hf_ns_trcdbg_val9_NILE;
					hf_ns_trcdbg_val10_final = hf_ns_trcdbg_val10_NILE;
					hf_ns_trcdbg_val11_final = hf_ns_trcdbg_val11_NILE;
					hf_ns_trcdbg_val12_final = hf_ns_trcdbg_val12_NILE;
					hf_ns_trcdbg_val13_final = hf_ns_trcdbg_val13_NILE;
					hf_ns_trcdbg_val14_final = hf_ns_trcdbg_val14_NILE;
				default:
					break;
			}

			proto_tree_add_item(subtree, hf_ns_trcdbg_val1_final, tvb, offset + 3, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_ns_trcdbg_val2_final, tvb, offset + 7, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_ns_trcdbg_val3_final, tvb, offset + 11, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_ns_trcdbg_val4_final, tvb, offset + 15, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_ns_trcdbg_val5_final, tvb, offset + 19, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_ns_trcdbg_val6_final, tvb, offset + 23, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_ns_trcdbg_val7_final, tvb, offset + 27, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_ns_trcdbg_val8_final, tvb, offset + 31, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_ns_trcdbg_val9_final, tvb, offset + 35, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_ns_trcdbg_val10_final, tvb, offset + 39, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_ns_trcdbg_val11_final, tvb, offset + 43, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_ns_trcdbg_val12_final, tvb, offset + 47, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_ns_trcdbg_val13_final, tvb, offset + 51, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_ns_trcdbg_val14_final, tvb, offset + 55, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_ns_trcdbg_val15, tvb, offset + 59, 4, ENC_LITTLE_ENDIAN);

			offset += reclen;
			cur_record = nextrec;
			break;
		case NSREC_HTTPINFO:
			/* Add httpinfo subtree */
			subitem = proto_tree_add_item(ns_tree, hf_ns_httpInfo, tvb, offset, reclen, ENC_NA);
			subtree = proto_item_add_subtree(subitem, ett_ns_httpInfo);
			proto_tree_add_item(subtree, hf_ns_httpInfo_httpabort, tvb, offset + 3, 1, ENC_LITTLE_ENDIAN);

			offset += reclen;
			cur_record = nextrec;
			break;
		case NSREC_TCPCC:
			/* Add tcpcc subtree */
			subitem = proto_tree_add_item(ns_tree, hf_ns_tcpcc, tvb, offset, reclen, ENC_NA);
			subtree = proto_item_add_subtree(subitem, ett_ns_tcpcc);
			switch (flavour_value)
			{
				case NS_TCPCC_BIC:
					proto_tree_add_item(subtree, hf_ns_tcpcc_last_max_cwnd, tvb, offset + 3, 4, ENC_LITTLE_ENDIAN);
					proto_tree_add_item(subtree, hf_ns_tcpcc_loss_cwnd, tvb, offset + 7, 4, ENC_LITTLE_ENDIAN);
					proto_tree_add_item(subtree, hf_ns_tcpcc_last_time, tvb, offset + 11, 4, ENC_LITTLE_ENDIAN);
					proto_tree_add_item(subtree, hf_ns_tcpcc_last_cwnd, tvb, offset + 15, 4, ENC_LITTLE_ENDIAN);
					break;
				case NS_TCPCC_CUBIC:
					proto_tree_add_item(subtree, hf_ns_tcpcc_last_cwnd, tvb, offset + 3, 4, ENC_LITTLE_ENDIAN);
					proto_tree_add_item(subtree, hf_ns_tcpcc_last_time, tvb, offset + 7, 4, ENC_LITTLE_ENDIAN);
					proto_tree_add_item(subtree, hf_ns_tcpcc_last_max_cwnd, tvb, offset + 11, 4, ENC_LITTLE_ENDIAN);
					proto_tree_add_item(subtree, hf_ns_tcpcc_delay_min, tvb, offset + 15, 4, ENC_LITTLE_ENDIAN);
					proto_tree_add_item(subtree, hf_ns_tcpcc_ack_cnt, tvb, offset + 19, 4, ENC_LITTLE_ENDIAN);
					break;
				case NS_TCPCC_NILE:
					proto_tree_add_item(subtree, hf_ns_tcpcc_alpha, tvb, offset + 3, 4, ENC_LITTLE_ENDIAN);
					proto_tree_add_item(subtree, hf_ns_tcpcc_beta_val, tvb, offset + 7, 4, ENC_LITTLE_ENDIAN);
					proto_tree_add_item(subtree, hf_ns_tcpcc_rtt_low, tvb, offset + 11, 4, ENC_LITTLE_ENDIAN);
					proto_tree_add_item(subtree, hf_ns_tcpcc_rtt_above, tvb, offset + 15, 4, ENC_LITTLE_ENDIAN);
					proto_tree_add_item(subtree, hf_ns_tcpcc_max_rtt, tvb, offset + 19, 4, ENC_LITTLE_ENDIAN);
					proto_tree_add_item(subtree, hf_ns_tcpcc_base_rtt, tvb, offset + 23, 4, ENC_LITTLE_ENDIAN);
					break;
				case NS_TCPCC_WESTWOOD:
					proto_tree_add_item(subtree, hf_ns_tcpcc_rtt_min, tvb, offset + 3, 4, ENC_LITTLE_ENDIAN);
					break;
				case NS_TCPCC_CUBIC_HYSTART:
					proto_tree_add_item(subtree, hf_ns_tcpcc_last_ack, tvb, offset + 3, 4, ENC_LITTLE_ENDIAN);
					proto_tree_add_item(subtree, hf_ns_tcpcc_delay_min, tvb, offset + 7, 4, ENC_LITTLE_ENDIAN);
					proto_tree_add_item(subtree, hf_ns_tcpcc_round_start, tvb, offset + 11, 4, ENC_LITTLE_ENDIAN);
					proto_tree_add_item(subtree, hf_ns_tcpcc_end_seq, tvb, offset + 15, 4, ENC_LITTLE_ENDIAN);
					proto_tree_add_item(subtree, hf_ns_tcpcc_curr_rtt, tvb, offset + 19, 4, ENC_LITTLE_ENDIAN);
					break;
				case NS_TCPCC_INVALID:
					break;
				case NS_TCPCC_DEFAULT:
					break;
			}
			offset += reclen;
			cur_record = nextrec;
			break;

			case NSREC_INFO:
				subitem = proto_tree_add_item(ns_tree, hf_ns_inforec, tvb, offset, reclen, ENC_NA);
				subtree = proto_item_add_subtree(subitem, ett_ns_inforec);
				proto_tree_add_item(subtree, hf_ns_inforec_info, tvb, offset+3, reclen-3, ENC_ASCII);

				offset += reclen;
				cur_record = nextrec;
				break;
			case NSREC_SSL:
				subitem = proto_tree_add_item(ns_tree, hf_ns_sslrec, tvb, offset, reclen, ENC_NA);
				subtree = proto_item_add_subtree(subitem, ett_ns_sslrec);
				proto_tree_add_item(subtree, hf_ns_sslrec_seq, tvb, offset+3, 4, ENC_LITTLE_ENDIAN);

				ssl_internal=1;

				offset += reclen;
				cur_record = nextrec;
				break;
			case NSREC_MPTCP:
				subitem = proto_tree_add_item(ns_tree, hf_ns_mptcprec, tvb, offset, reclen, ENC_NA);
				subtree = proto_item_add_subtree(subitem, ett_ns_mptcprec);
				proto_tree_add_item(subtree, hf_ns_mptcprec_subflowid, tvb, offset+3, 1, ENC_LITTLE_ENDIAN);

				offset += reclen;
				cur_record = nextrec;
				break;
			case NSREC_VMNAMES:
			{
				int srcvmnamelen = tvb_get_uint8(tvb,offset+3);
				int dstvmnamelen = tvb_get_uint8(tvb,offset+4);
				subitem = proto_tree_add_item(ns_tree, hf_ns_vmnamerec, tvb, offset, reclen, ENC_NA);
				subtree = proto_item_add_subtree(subitem, ett_ns_vmnamerec);
				proto_tree_add_item(subtree, hf_ns_vmnamerec_srcvmname, tvb, offset+5,
														srcvmnamelen, ENC_ASCII);
				proto_tree_add_item(subtree, hf_ns_vmnamerec_dstvmname, tvb, offset+5+srcvmnamelen,
														dstvmnamelen, ENC_ASCII);

				offset += reclen;
				cur_record = nextrec;
			}
			break;

			case NSREC_CLUSTER:
				subitem = proto_tree_add_item(ns_tree, hf_ns_clusterrec, tvb, offset, reclen, ENC_NA);
				subtree = proto_item_add_subtree(subitem, ett_ns_clusterrec);

				proto_tree_add_item(subtree, hf_ns_clu_snode, tvb, offset+3, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(subtree, hf_ns_clu_dnode, tvb, offset+5, 2, ENC_LITTLE_ENDIAN);

				proto_tree_add_bitmask(subtree,tvb, offset+7,hf_ns_clu_clflags,ett_ns_flags,cluster_flags,ENC_NA);
				offset += reclen;
				cur_record = nextrec;
				break;

			default:
			/* This will end up in an infinite loop if the file is corrupt */
				loopcount++;
				subitem = proto_tree_add_item(ns_tree, hf_ns_unknownrec, tvb, offset, reclen, ENC_NA);
				subtree = proto_item_add_subtree(subitem, ett_ns_unknownrec);
				proto_tree_add_item(subtree, hf_ns_unknowndata, tvb, offset+3, reclen-3, ENC_NA);

				if(cur_record == UNKNOWN_LAST){
					morerecs=0;
				}else{
					offset += reclen;
					cur_record = nextrec;
				}
				break;
		}
	}while( morerecs &&
					loopcount < (MAX_UNKNOWNREC_LOOP) && /* additional checks to prevent infinite loops */
					offset<=nsheaderlen);
}

void
proto_register_ns(void)
{
	static hf_register_info hf[] = {

		{ &hf_ns_nicno,
		  { "Nic No", "nstrace.nicno",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},

		{ &hf_ns_src_vm,
		  { "Src Vm Name", "nstrace.src_vm",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},

		{ &hf_ns_dst_vm,
		  { "Dst Vm Name", "nstrace.dst_vm",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},

		{ &hf_ns_coreid,
		  { "Core Id", "nstrace.coreid",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},

		{ &hf_ns_dir,
		  { "Operation", "nstrace.dir",
		    FT_UINT16, BASE_HEX|BASE_EXT_STRING, &ns_dir_vals_ext, 0x0,
		    NULL, HFILL }
		},

		{ &hf_ns_pcbdevno,
		  { "PcbDevNo", "nstrace.pdevno",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},

		{ &hf_ns_l_pcbdevno,
		  { "Linked PcbDevNo", "nstrace.l_pdevno",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},

		{ &hf_ns_devno,
		  { "DevNo", "nstrace.devno",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},

		{ &hf_ns_vlantag,
		  { "Vlan", "nstrace.vlan",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},

		{ &hf_ns_snode,
		  { "Source Node", "nstrace.snode",
		    FT_INT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},

		{ &hf_ns_dnode,
		  { "Destination Node", "nstrace.dnode",
		    FT_INT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},

		{ &hf_ns_clflags,
		  { "Cluster Flags", "nstrace.flags",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},

		{ &hf_ns_clflags_res,
		  { "Reserved", "nstrace.flags.res",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), CL_RES,
		    NULL, HFILL}
		},

		{ &hf_ns_clflags_rssh,
		  { "RSSHASH", "nstrace.flags.rssh",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), CL_RSSH,
		    NULL, HFILL}
		},

		{ &hf_ns_clflags_rss,
		  { "SRSS", "nstrace.flags.srss",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), CL_RSS,
		    NULL, HFILL}
		},

		{ &hf_ns_clflags_dfd,
		  { "DFD", "nstrace.flags.dfd",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), CL_DFD,
		    NULL, HFILL}
		},

		{ &hf_ns_clflags_fr,
		  { "Flow receiver (FR)", "nstrace.flags.fr",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), CL_FR,
		    NULL, HFILL}
		},

		{ &hf_ns_clflags_fp,
		  { "Flow processor (FP)", "nstrace.flags.fp",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), CL_FP,
		    NULL, HFILL}
		},

		{ &hf_ns_activity,
		  { "Activity Flags", "nstrace.activity",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL}
		},

		{ &hf_ns_activity_perf_collection,
		  { "Perf Collection", "nstrace.activity.perfcollection",
		    FT_BOOLEAN, 32, NULL, NS_PE_STATE_PERF_COLLECTION_IN_PROG,
		    NULL, HFILL}
		},

		{ &hf_ns_activity_pcb_zombie,
		  { "PCB Zombie", "nstrace.activity.pcbzombie",
		    FT_BOOLEAN, 32, NULL, NS_PE_STATE_PCB_ZOMBIE_IN_PROG,
		    NULL, HFILL}
		},

		{ &hf_ns_activity_natpcb_zombie,
		  { "NATPCB Zombie", "nstrace.activity.natpcbzombie",
		    FT_BOOLEAN, 32, NULL, NS_PE_STATE_NATPCB_ZOMBIE_IN_PROG,
		    NULL, HFILL}
		},

		{ &hf_ns_activity_lbstats_sync,
		  { "LB Stats Sync", "nstrace.activity.lbstatssync",
		    FT_BOOLEAN, 32, NULL, NS_PE_STATE_LBSTATS_SYNC_IN_PROG,
		    NULL, HFILL}
		},

		{ &hf_ns_activity_stats_req,
		  { "Stats Req", "nstrace.activity.statsreq",
		    FT_BOOLEAN, 32, NULL, NS_PE_STATE_STATS_REQ_IN_PROG,
		    NULL, HFILL}
		},

		{ &hf_ns_snd_cwnd,
			{ "SendCwnd", "nstrace.sndcwnd",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				NULL, HFILL }
		},

		{ &hf_ns_realtime_rtt,
			{ "RTT", "nstrace.rtt",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				NULL, HFILL }
		},

		{ &hf_ns_ts_recent,
			{ "tsRecent", "nstrace.tsrecent",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				NULL, HFILL }
		},

		{ &hf_ns_http_abort_tracking_reason,
			{ "httpAbortTrackCode", "nstrace.httpabort",
				FT_UINT8, BASE_DEC|BASE_EXT_STRING, &ns_httpabortcode_vals_ext, 0x0,
				NULL, HFILL }
		},


		{ &hf_ns_capflags,
		  { "Capture Flags", "nstrace.capflags",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL}
		},

		{ &hf_ns_capflags_dbg,
		  { "debug packet", "nstrace.capflags.dbg",
		    FT_BOOLEAN, 32, NULL, NS_CAPFLAG_DBG,
		    NULL, HFILL}
		},

		{ &hf_ns_capflags_int,
		  { "internal packet", "nstrace.capflags.int",
		    FT_BOOLEAN, 32, NULL, NS_CAPFLAG_INT,
		    NULL, HFILL}
		},

		{ &hf_ns_capflags_skipnwhdr,
		  { "skip headers", "nstrace.capflags.skipnwhdr",
		    FT_BOOLEAN, 32, NULL, NS_CAPFLAG_SKIPNWHDR,
		    NULL, HFILL}
		},

		{ &hf_ns_tcpdbg,
		  { "TCP Debug Info", "nstrace.tcpdbg",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL}
		},

		{ &hf_ns_tcpdbg_cwnd,
		  { "TcpCwnd", "nstrace.tcpdbg.tcpcwnd",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},

		{ &hf_ns_tcpdbg_rtrtt,
		  { "TcpRTT", "nstrace.tcpdbg.rtrtt",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},

		{ &hf_ns_tcpdbg_tsrecent,
		  { "TcpTsrecent", "nstrace.tcpdbg.tcptsrecent",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},

		{ &hf_ns_tcpdbg_httpabort,
		  { "HTTPabrtReason", "nstrace.tcpdbg.httpabort",
		    FT_UINT8, BASE_DEC, VALS(ns_httpabortcode_vals), 0x0,
		    NULL, HFILL }
		},

				/** Fields of Tcp Debug 2 records**/
		{ &hf_ns_tcpdbg2,
		{ "TCP Debug Info", "nstrace.tcpdbg2",
		FT_NONE, BASE_NONE, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_tcpdbg2_sndCwnd,
		{ "SndCwnd", "nstrace.tcpdbg2.sndCwnd",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_tcpdbg2_ssthresh,
		{ "Ssthresh", "nstrace.tcpdbg2.ssthresh",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_tcpdbg2_sndbuf,
		{ "MaxSndBuf", "nstrace.tcpdbg2.maxsndbuf",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_tcpdbg2_max_rcvbuf,
		{ "MaxRcvbuff", "nstrace.tcpdbg2.maxrcvbuff",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_tcpdbg2_bw_estimate,
		{ "BwEstimate", "nstrace.tcpdbg2.bwEstimate",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_tcpdbg2_rtt,
		{ "Rtt", "nstrace.tcpdbg2.rtt",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_tcpdbg2_tcpos_pktcnt,
		{ "Ospckcnt", "nstrace.tcpdbg2.Ospckcnt",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_tcpdbg2_ts_recent,
		{ "tsRecent", "nstrace.tcpdbg2.tsRecent",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_tcpdbg2_tcp_cfgsndbuf,
		{ "cfgSndBuf", "nstrace.tcpdbg2.cfgSndBuf",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_tcpdbg2_tcp_flvr,
		{ "Flavour", "nstrace.tcpdbg2.flavour",
		FT_UINT8, BASE_DEC, VALS(tcp_dbg2_flavour), 0x0,
		NULL, HFILL }
		},

		/**  Fields for generic trace debug record **/
		{ &hf_ns_trcdbg,
		{ "Additional debug", "nstrace.trcdbg",
		FT_NONE, BASE_NONE, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val1,
		{ "val1", "nstrace.trcdbg.val1",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val1_PRR,
		{ "bytes_in_flight", "nstrace.trcdbg.val1",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val1_NILE,
		{ "Alpha_min", "nstrace.trcdbg.val1",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val1_RTT,
		{ "RTT_timems", "nstrace.trcdbg.val1",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val1_BURST,
		{ "Rate_bytes_msec", "nstrace.trcdbg.val1",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val2,
		{ "val2", "nstrace.trcdbg.val2",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val2_PRR,
		{ "Cong_state", "nstrace.trcdbg.val2",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val2_RTT,
		{ "real_time_RTT", "nstrace.trcdbg.val2",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val2_NILE,
		{ "Alpha_max", "nstrace.trcdbg.val2",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val3,
		{ "val3", "nstrace.trcdbg.val3",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val3_PRR,
		{ "prr_delivered", "nstrace.trcdbg.val3",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val3_RTT,
		{ "rtt_min", "nstrace.trcdbg.val3",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val3_NILE,
		{ "nile_da", "nstrace.trcdbg.val3",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val4,
		{ "val4", "nstrace.trcdbg.val4",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val4_PRR,
		{ "prr_out", "nstrace.trcdbg.val4",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val4_RTT,
		{ "ts_ecr", "nstrace.trcdbg.val4",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val4_NILE,
		{ "nile_dm", "nstrace.trcdbg.val4",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val5,
		{ "val5", "nstrace.trcdbg.val5",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val5_DRB_APP,
		{ "RetxQ_bytes", "nstrace.trcdbg.val5",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val5_RTT,
		{ "rtt_seq", "nstrace.trcdbg.val5",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val5_NILE,
		{ "d1_percent", "nstrace.trcdbg.val5",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},


		{ &hf_ns_trcdbg_val6,
		{ "val6", "nstrace.trcdbg.val6",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val6_DRB_APP,
		{ "waitQ_bytes", "nstrace.trcdbg.val6",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val6_RTT,
		{ "cong_state", "nstrace.trcdbg.val6",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val6_NILE,
		{ "d2_percent", "nstrace.trcdbg.val6",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val7,
		{ "val7", "nstrace.trcdbg.val7",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val7_DRB,
		{ "adv_wnd", "nstrace.trcdbg.val7",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val7_DRB_APP,
		{ "link_adv_wnd", "nstrace.trcdbg.val7",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val7_NILE,
		{ "d3_percent", "nstrace.trcdbg.val7",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val8,
		{ "val8", "nstrace.trcdbg.val8",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val8_DRB,
		{ "link_snd_cwnd", "nstrace.trcdbg.val8",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val8_DRB_APP,
		{ "snd_cwnd", "nstrace.trcdbg.val8",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val8_NILE,
		{ "nile_d1", "nstrace.trcdbg.val8",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val9,
		{ "val9", "nstrace.trcdbg.val9",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val9_DRB,
		{ "cong_state", "nstrace.trcdbg.val9",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val9_NILE,
		{ "nile_d2", "nstrace.trcdbg.val9",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val10,
		{ "val10", "nstrace.trcdbg.val10",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val10_DRB,
		{ "target_wnd", "nstrace.trcdbg.val10",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val10_NILE,
		{ "nile_d3", "nstrace.trcdbg.val10",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val11,
		{ "val11", "nstrace.trcdbg.val11",
		FT_INT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val11_DRB,
		{ "delta_rcvbuf", "nstrace.trcdbg.val11",
		FT_INT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val11_DRB_APP,
		{ "link_delta_rcvbuf", "nstrace.trcdbg.val11",
		FT_INT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val11_NILE,
		{ "beta_min", "nstrace.trcdbg.val11",
		FT_INT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val11_RTT,
		{ "rtt_smoothed", "nstrace.trcdbg.val11",
		FT_INT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val11_BURST,
		{ "rate_data_credit", "nstrace.trcdbg.val11",
		FT_INT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val12,
		{ "val12", "nstrace.trcdbg.val12",
		FT_INT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val12_RTT,
		{ "rtt_variance", "nstrace.trcdbg.val12",
		FT_INT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val12_NILE,
		{ "beta_min", "nstrace.trcdbg.val12",
		FT_INT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val13,
		{ "val13", "nstrace.trcdbg.val13",
		FT_INT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val13_DRB,
		{ "cmpr_advWnd_trgt", "nstrace.trcdbg.val13",
		FT_INT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val13_NILE,
		{ "rtt_factor", "nstrace.trcdbg.val13",
		FT_INT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val14,
		{ "val14", "nstrace.trcdbg.val14",
		FT_INT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val14_NILE,
		{ "rtt_filter", "nstrace.trcdbg.val14",
		FT_INT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_trcdbg_val15,
		{ "val15", "nstrace.trcdbg.val15",
		FT_INT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		/** Fields of httpInfo	**/
		{ &hf_ns_httpInfo,
		{ "HTTPInfo", "nstrace.httpInfo",
		FT_NONE, BASE_NONE, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_httpInfo_httpabort,
		{ "HTTPabortReason", "nstrace.httpInfo.httpabort",
		FT_UINT8, BASE_DEC, VALS(ns_httpabortcode_vals), 0x0,
		NULL, HFILL }
		},

		/** Fields of Tcp CC Records  **/
		{ &hf_ns_tcpcc,
		{ "TcpCC", "nstrace.tcpcc",
		FT_NONE, BASE_NONE, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_tcpcc_last_max_cwnd,
		{ "Last_max_cwnd", "nstrace.tcpcc.lastmaxcwnd",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},
		{ &hf_ns_tcpcc_loss_cwnd,
		{ "Loss_cwnd", "nstrace.tcpcc.losscwnd",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_tcpcc_last_time,
		{ "Last_time", "nstrace.tcpcc.lasttime",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_tcpcc_last_cwnd,
		{ "Last_cwnd", "nstrace.tcpcc.lastcwnd",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_tcpcc_delay_min,
		{ "Delay_min", "nstrace.tcpcc.delaymin",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_tcpcc_ack_cnt,
		{ "Ack_cnt", "nstrace.tcpcc.ackcnt",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_tcpcc_last_ack,
		{ "Last_ack", "nstrace.tcpcc.lastack",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_tcpcc_round_start,
		{ "Round_start", "nstrace.tcpcc.roundstart",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_tcpcc_end_seq,
		{ "End_seq", "nstrace.tcpcc.endseq",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_tcpcc_curr_rtt,
		{ "Curr_rtt", "nstrace.tcpcc.currrtt",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_tcpcc_rtt_min,
		{ "Rtt_min", "nstrace.tcpcc.rttmin",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_tcpcc_alpha,
		{ "Alpha", "nstrace.tcpcc.alpha",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_tcpcc_beta_val,
		{ "Beta_val", "nstrace.tcpcc.betaval",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_tcpcc_rtt_low,
		{ "Rtt_low", "nstrace.tcpcc.rttlow",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_tcpcc_rtt_above,
		{ "Rtt_above", "nstrace.tcpcc.rttabove",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_tcpcc_max_rtt,
		{ "Max_rtt", "nstrace.tcpcc.maxrtt",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_tcpcc_base_rtt,
		{ "Base_rtt", "nstrace.tcpcc.basertt",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
		},

		{ &hf_ns_unknownrec,
		  { "unknown ns record", "nstrace.unknown",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL}
		},

		{ &hf_ns_unknowndata,
		  { "data", "nstrace.unknown.data",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL}
		},

		{ &hf_ns_inforec,
		  { "info record", "nstrace.inforec",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL}
		},

		{ &hf_ns_inforec_info,
		  { "info", "nstrace.inforec.info",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL}
		},

		{ &hf_ns_sslrec,
		  { "ssl record", "nstrace.sslrec",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL}
		},

		{ &hf_ns_sslrec_seq,
		  { "SSL record seq no", "nstrace.sslrec.seq",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL}
		},

		{ &hf_ns_mptcprec,
		  { "mptcp record", "nstrace.mptcp",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL}
		},

		{ &hf_ns_mptcprec_subflowid,
		  { "MPTCP subflow id", "nstrace.sslrec.subflow",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL}
		},

		{ &hf_ns_vmnamerec,
		  { "vmname record", "nstrace.vmnames",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL}
		},

		{ &hf_ns_vmnamerec_srcvmname,
		  { "SrcVmName", "nstrace.vmnames.srcvmname",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL}
		},

		{ &hf_ns_vmnamerec_dstvmname,
		  { "DstVmName", "nstrace.vmnames.dstvmnames",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL}
		},

		{ &hf_ns_clusterrec,
		  { "cluster record", "nstrace.cluster",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL}
		},

		{ &hf_ns_clu_snode,
		  { "Source Node", "nstrace.cluster.snode",
		    FT_INT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},

		{ &hf_ns_clu_dnode,
		  { "Destination Node", "nstrace.cluster.dnode",
		    FT_INT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_ns_clu_clflags,
		  { "Cluster Flags", "nstrace.cluster.flags",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},

		{ &hf_ns_clu_clflags_res,
		  { "Reserved", "nstrace.cluster.flags.res",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), CL_RES,
		    NULL, HFILL}
		},

		{ &hf_ns_clu_clflags_rssh,
		  { "RSSHASH", "nstrace.cluster.flags.rssh",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), CL_RSSH,
		    NULL, HFILL}
		},

		{ &hf_ns_clu_clflags_rss,
		  { "SRSS", "nstrace.cluster.flags.srss",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), CL_RSS,
		    NULL, HFILL}
		},

		{ &hf_ns_clu_clflags_dfd,
		  { "DFD", "nstrace.cluster.flags.dfd",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), CL_DFD,
		    NULL, HFILL}
		},

		{ &hf_ns_clu_clflags_fr,
		  { "Flow receiver (FR)", "nstrace.cluster.flags.fr",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), CL_FR,
		    NULL, HFILL}
		},

		{ &hf_ns_clu_clflags_fp,
		  { "Flow processor (FP)", "nstrace.cluster.flags.fp",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), CL_FP,
		    NULL, HFILL}
		},

		{ &hf_ns_errorcode,
		  { "Errorcode", "nstrace.err",
		    FT_UINT8, BASE_HEX, VALS(ns_errorcode_vals), 0x0,
		    NULL, HFILL }
		},

		{ &hf_ns_app,
		  { "App", "nstrace.app",
		    FT_UINT8, BASE_HEX|BASE_EXT_STRING, &ns_app_vals_ext, 0x0,
		    NULL, HFILL }
		},

	};

	static int *ett[] = {
		&ett_ns,
		&ett_ns_flags,
		&ett_ns_activity_flags,
		&ett_ns_tcpdebug,
		&ett_ns_tcpdebug2,
		&ett_ns_trcdbg,
		&ett_ns_httpInfo,
		&ett_ns_tcpcc,
		&ett_ns_unknownrec,
		&ett_ns_inforec,
		&ett_ns_vmnamerec,
		&ett_ns_clusterrec,
		&ett_ns_clu_clflags,
		&ett_ns_sslrec,
		&ett_ns_mptcprec,
		&ett_ns_capflags,
	};

	proto_nstrace = proto_register_protocol("NetScaler Trace", "NS Trace", "ns");
	proto_register_field_array(proto_nstrace, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	nstrace_handle = register_dissector("ns", dissect_nstrace, proto_nstrace);
}


void proto_reg_handoff_ns(void)
{
	eth_withoutfcs_handle = find_dissector_add_dependency("eth_withoutfcs", proto_nstrace);
	http_handle = find_dissector_add_dependency("http", proto_nstrace);

	dissector_add_uint("wtap_encap", WTAP_ENCAP_NSTRACE_1_0, nstrace_handle);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_NSTRACE_2_0, nstrace_handle);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_NSTRACE_3_0, nstrace_handle);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_NSTRACE_3_5, nstrace_handle);
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
