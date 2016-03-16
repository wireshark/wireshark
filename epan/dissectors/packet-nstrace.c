/* packet-nstrace.c
 * Routines for nstrace dissection
 * Copyright 2006, Ravi Kondamuru <Ravi.Kondamuru@citrix.com>
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
#include <wiretap/netscaler.h>


/* This is new long header (3 bytes long) to be included where needed */
#define NSPR_HEADER3B_V20(prefix) \
    guint8 prefix##_RecordType;    /* Record Type */ \
    guint8 prefix##_RecordSizeLow; /* Record Size including header */ \
    guint8 prefix##_RecordSizeHigh /* Record Size including header */ \
                                   /* end of declaration */
#define NSPR_HEADER3B_V21 NSPR_HEADER3B_V20
#define NSPR_HEADER3B_V22 NSPR_HEADER3B_V20
#define NSPR_HEADER3B_V30 NSPR_HEADER3B_V20

typedef struct  nspr_pktracefull_v35
{
    NSPR_HEADER3B_V30(fp);  /* long performance header */
    guint8 fp_DevNo;   /* Network Device (NIC) number */
    guint8 fp_AbsTimeHr[8];  /*High resolution absolute time in nanosec*/
    guint8 fp_PcbDevNo[4];    /* PCB devno */
    guint8 fp_lPcbDevNo[4];   /* link PCB devno */
    guint8 fp_PktSizeOrg[2];  /* Original packet size */
    guint8 fp_VlanTag[2]; /* vlan tag */
    guint8 fp_Coreid[2]; /* coreid of the packet */
    guint8 fp_headerlen[2];
    guint8 fp_errorcode;
    guint8 fp_app;
    guint8 fp_ns_activity[4];
    guint8 fp_nextrecord;
} nspr_pktracefull_v35_t;
#define nspr_pktracefull_v35_s  ((guint32)(sizeof(nspr_pktracefull_v35_t)))
#define MAX_UNKNOWNREC_LOOP 5
/* Generic trace record header */
typedef struct nspr_tracerechdr_s
{
  guint8 rec_len[2];
  guint8 nextrec_type;
} nspr_tracerechdr_t;

/*Trace record for tcp debug*/
typedef struct nspr_rec_tcpdebug_s
{
  nspr_tracerechdr_t rechdr;
  guint8 snd_cwnd[4];
  guint8 real_time_rtt[4];
  guint8 ts_recent[4];
  guint8 http_abort_reason;
} nspr_rec_tcpdebug_t;

/*info trace record*/
typedef struct nspr_rec_info_s
{
  nspr_tracerechdr_t rechdr;
} nspr_rec_info_t;

/*cluster trace record*/
typedef struct nspr_rec_cluster_s
{
  nspr_tracerechdr_t rechdr;
  guint8 fp_srcNodeId[2]; /* cluster nodeid of the packet */
  guint8 fp_destNodeId[2];
  guint8 fp_clFlags;
} nspr_rec_cluster_t;

/*vmnames trace record*/
typedef struct nspr_rec_vmname_s
{
  nspr_tracerechdr_t rechdr;
  guint8 src_vmname_len;
  guint8 dst_vmname_len;
} nspr_rec_vmname_t;

typedef struct nspr_rec_ssl_s
{
  nspr_tracerechdr_t rechdr;
  guint8 seq[4];
  guint8 appseq[4];
} nspr_rec_ssl_t;

typedef struct nspr_rec_mptcp_s
{
  nspr_tracerechdr_t rechdr;
  guint8 subflowid;
}nspr_rec_mptcp_t;

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

void proto_register_ns(void);
void proto_reg_handoff_ns(void);

static int proto_nstrace = -1;

static int hf_ns_nicno = -1;
static int hf_ns_src_vm = -1;
static int hf_ns_dst_vm = -1;
static int hf_ns_dir = -1;
static int hf_ns_pcbdevno = -1;
static int hf_ns_l_pcbdevno = -1;
static int hf_ns_devno = -1;
static int hf_ns_vlantag = -1;
static int hf_ns_coreid = -1;

static int hf_ns_errorcode = -1;
static int hf_ns_app = -1;

static int hf_ns_snode = -1;
static int hf_ns_dnode = -1;
static int hf_ns_clflags = -1;
static int hf_ns_clflags_res = -1;
static int hf_ns_clflags_rssh = -1;
static int hf_ns_clflags_rss = -1;
static int hf_ns_clflags_dfd = -1;
static int hf_ns_clflags_fr = -1;
static int hf_ns_clflags_fp = -1;

static int hf_ns_activity = -1;
static int hf_ns_activity_perf_collection = -1;
static int hf_ns_activity_pcb_zombie  = -1;
static int hf_ns_activity_natpcb_zombie  = -1;
static int hf_ns_activity_lbstats_sync  = -1;
static int hf_ns_activity_stats_req  = -1;

static int hf_ns_capflags           = -1;
static int hf_ns_capflags_dbg       = -1;
static int hf_ns_capflags_int       = -1;
static int hf_ns_capflags_skipnwhdr = -1;

static int hf_ns_tcpdbg          = -1;
static int hf_ns_tcpdbg_cwnd     = -1;
static int hf_ns_tcpdbg_rtrtt    = -1;
static int hf_ns_tcpdbg_tsrecent = -1;
static int hf_ns_tcpdbg_httpabort = -1;

static int hf_ns_unknownrec      = -1;
static int hf_ns_unknowndata     = -1;

static int hf_ns_inforec         = -1;
static int hf_ns_inforec_info    = -1;

static int hf_ns_sslrec         = -1;
static int hf_ns_sslrec_seq     = -1;

static int hf_ns_mptcprec         = -1;
static int hf_ns_mptcprec_subflowid  = -1;

static int hf_ns_vmnamerec           = -1;
static int hf_ns_vmnamerec_srcvmname = -1;
static int hf_ns_vmnamerec_dstvmname = -1;

static int hf_ns_clusterrec    = -1;
static int hf_ns_clu_snode = -1;
static int hf_ns_clu_dnode = -1;
static int hf_ns_clu_clflags = -1;
static int hf_ns_clu_clflags_res = -1;
static int hf_ns_clu_clflags_rssh = -1;
static int hf_ns_clu_clflags_rss = -1;
static int hf_ns_clu_clflags_dfd = -1;
static int hf_ns_clu_clflags_fr = -1;
static int hf_ns_clu_clflags_fp = -1;

static gint ett_ns = -1;
static gint ett_ns_flags = -1;
static gint ett_ns_activity_flags = -1;
static gint ett_ns_tcpdebug = -1;
static gint ett_ns_inforec  = -1;
static gint ett_ns_sslrec  = -1;
static gint ett_ns_mptcprec  = -1;
static gint ett_ns_vmnamerec  = -1;
static gint ett_ns_clusterrec  = -1;
static gint ett_ns_clu_clflags  = -1;
static gint ett_ns_unknownrec = -1;
static gint ett_ns_capflags = -1;

static int hf_ns_snd_cwnd = -1;
static int hf_ns_realtime_rtt = -1;
static int hf_ns_ts_recent = -1;
static int hf_ns_http_abort_tracking_reason = -1;

static const value_string ns_errorcode_vals[] = {
  { ERR_NONE,  "No Error" },
  { ERR_DROP_PERX_LONGPKT,  "Long packet" },
  { ERR_DROP_PERX_FIXHDR,   "Fix header" },
  { ERR_DROP_PERX_DUPFREE,  "Dup free" },
  { ERR_PKT_FWD,            "Forwarded packet" },
  { ERR_PKT_FWD6,           "Forwarded ipv6 packet" },
  { ERR_LAST,               NULL },
};

static const value_string ns_app_vals[] = {
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
  { APP_NULL,   NULL    },
};

static const value_string ns_dir_vals[] = {
	{ NSPR_PDPKTRACEFULLTX_V10,    "TX" },
	{ NSPR_PDPKTRACEFULLTX_V20,    "TX" },
	{ NSPR_PDPKTRACEFULLTX_V30,    "TX" },
	{ NSPR_PDPKTRACEFULLTX_V35,    "TX" },
	{ NSPR_PDPKTRACEFULLTXB_V10,   "TXB" },
	{ NSPR_PDPKTRACEFULLTXB_V20,   "TXB" },
	{ NSPR_PDPKTRACEFULLTXB_V30,   "TXB" },
	{ NSPR_PDPKTRACEFULLTXB_V35,   "TXB" },
	{ NSPR_PDPKTRACEFULLRX_V10,    "RX" },
	{ NSPR_PDPKTRACEFULLRX_V20,    "RX" },
	{ NSPR_PDPKTRACEFULLRX_V30,    "RX" },
	{ NSPR_PDPKTRACEFULLRX_V35,    "RX" },
	{ NSPR_PDPKTRACEPARTTX_V10,    "TX"  },
	{ NSPR_PDPKTRACEPARTTX_V20,    "TX" },
	{ NSPR_PDPKTRACEPARTTXB_V10,   "TXB" },
	{ NSPR_PDPKTRACEPARTTXB_V20,   "TXB" },
	{ NSPR_PDPKTRACEPARTRX_V10,    "RX" },
	{ NSPR_PDPKTRACEPARTRX_V20,    "RX" },
	{ NSPR_PDPKTRACEFULLTX_V21,    "TX" },
	{ NSPR_PDPKTRACEFULLTXB_V21,   "TXB" },
	{ NSPR_PDPKTRACEFULLRX_V21,    "RX" },
	{ NSPR_PDPKTRACEPARTTX_V21,    "TX" },
	{ NSPR_PDPKTRACEPARTTXB_V21,   "TXB" },
	{ NSPR_PDPKTRACEPARTRX_V21,    "RX" },
	{ NSPR_PDPKTRACEFULLTX_V22,    "TX" },
	{ NSPR_PDPKTRACEFULLTX_V23,    "TX" },
	{ NSPR_PDPKTRACEFULLTX_V24,    "TX" },
	{ NSPR_PDPKTRACEFULLTX_V25,    "TX" },
	{ NSPR_PDPKTRACEFULLTX_V26,    "TX" },
	{ NSPR_PDPKTRACEFULLTXB_V22,   "TXB" },
	{ NSPR_PDPKTRACEFULLTXB_V23,   "TXB" },
	{ NSPR_PDPKTRACEFULLTXB_V24,   "TXB" },
	{ NSPR_PDPKTRACEFULLTXB_V25,   "TXB" },
	{ NSPR_PDPKTRACEFULLTXB_V26,   "TXB" },
	{ NSPR_PDPKTRACEFULLRX_V22,    "RX" },
	{ NSPR_PDPKTRACEFULLRX_V23,    "RX" },
	{ NSPR_PDPKTRACEFULLRX_V24,    "RX" },
	{ NSPR_PDPKTRACEFULLRX_V25,    "RX" },
	{ NSPR_PDPKTRACEFULLRX_V26,    "RX" },
	{ NSPR_PDPKTRACEFULLNEWRX_V24, "NEW_RX" },
	{ NSPR_PDPKTRACEFULLNEWRX_V25, "NEW_RX" },
	{ NSPR_PDPKTRACEFULLNEWRX_V26, "NEW_RX" },
	{ NSPR_PDPKTRACEFULLNEWRX_V30, "NEW_RX" },
	{ NSPR_PDPKTRACEFULLNEWRX_V35, "NEW_RX" },
	{ NSPR_PDPKTRACEPARTTX_V22,    "TX" },
	{ NSPR_PDPKTRACEPARTTX_V23,    "TX" },
	{ NSPR_PDPKTRACEPARTTX_V24,    "TX" },
	{ NSPR_PDPKTRACEPARTTX_V25,    "TX" },
	{ NSPR_PDPKTRACEPARTTX_V26,    "TX" },
	{ NSPR_PDPKTRACEPARTTXB_V22,   "TXB" },
	{ NSPR_PDPKTRACEPARTTXB_V23,   "TXB" },
	{ NSPR_PDPKTRACEPARTTXB_V24,   "TXB" },
	{ NSPR_PDPKTRACEPARTTXB_V25,   "TXB" },
	{ NSPR_PDPKTRACEPARTTXB_V26,   "TXB" },
	{ NSPR_PDPKTRACEPARTRX_V22,    "RX" },
	{ NSPR_PDPKTRACEPARTRX_V23,    "RX" },
	{ NSPR_PDPKTRACEPARTRX_V24,    "RX" },
	{ NSPR_PDPKTRACEPARTRX_V25,    "RX" },
	{ NSPR_PDPKTRACEPARTRX_V26,    "RX" },
	{ NSPR_PDPKTRACEPARTNEWRX_V24, "NEW_RX" },
	{ NSPR_PDPKTRACEPARTNEWRX_V25, "NEW_RX" },
	{ NSPR_PDPKTRACEPARTNEWRX_V26, "NEW_RX" },
	{ 0,              NULL }
};

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
	{ 16, NULL },
};

static dissector_handle_t eth_withoutfcs_handle;
static dissector_handle_t http_handle;


void add35records(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *ns_tree);

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

#define NSHDR_OFFSET_35(field)    offsetof(struct  nspr_pktracefull_v35, field)
#define NSHDR_RECOFFSET_35(field) (guint)(offsetof(nspr_tracerechdr_t, field))
#define TCPRECOFFSET(field)       (guint)(offsetof(nspr_rec_tcpdebug_t, field))
#define INFORECOFFSET(field)      (guint)(offsetof(nspr_rec_info_t, field))
#define CLUSTERRECOFFSET(field)   (guint)(offsetof(nspr_rec_cluster_t, field))
#define VMNAMERECOFFSET(field)    (guint)(offsetof(nspr_rec_vmname_t, field))
#define SSLRECOFFSET(field)       (guint)(offsetof(nspr_rec_ssl_t, field))
#define MPTCPRECOFFSET(field)     (guint)(offsetof(nspr_rec_mptcp_t, field))
static int
dissect_nstrace(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree     *ns_tree = NULL, *flagtree = NULL;
	proto_item     *ti = NULL, *flagitem = NULL;
	struct nstr_phdr *pnstr = &(pinfo->pseudo_header->nstr);
	tvbuff_t       *next_tvb_eth_client;
	guint8		offset;
	wmem_strbuf_t  *flags_strbuf = wmem_strbuf_new_label(wmem_packet_scope());
	guint8		flagoffset;
	guint8		src_vmname_len = 0, dst_vmname_len = 0;
	guint8		variable_ns_len = 0;

	wmem_strbuf_append(flags_strbuf, "None");

	if (pnstr->rec_type == NSPR_HEADER_VERSION205 || pnstr->rec_type == NSPR_HEADER_VERSION300 || pnstr->rec_type == NSPR_HEADER_VERSION206)	{
		src_vmname_len = tvb_get_guint8(tvb,pnstr->src_vmname_len_offset);
		dst_vmname_len = tvb_get_guint8(tvb,pnstr->dst_vmname_len_offset);
		variable_ns_len = src_vmname_len + dst_vmname_len;
		pnstr->eth_offset += variable_ns_len;
	}

	ti = proto_tree_add_protocol_format(tree, proto_nstrace, tvb, 0, pnstr->eth_offset, "NetScaler Packet Trace");
	ns_tree = proto_item_add_subtree(ti, ett_ns);

	proto_tree_add_item(ns_tree, hf_ns_dir, tvb, pnstr->dir_offset, pnstr->dir_len, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ns_tree, hf_ns_nicno, tvb, pnstr->nicno_offset, pnstr->nicno_len, ENC_LITTLE_ENDIAN);

	switch (pnstr->rec_type)
	{
	case NSPR_HEADER_VERSION300:
	case NSPR_HEADER_VERSION206:
		flagoffset = pnstr->ns_activity_offset;
		flagitem = proto_tree_add_item(ns_tree, hf_ns_activity, tvb, flagoffset, 4, ENC_LITTLE_ENDIAN);
		flagtree = proto_item_add_subtree(flagitem, ett_ns_activity_flags);
		proto_tree_add_item(flagtree, hf_ns_activity_perf_collection, tvb, flagoffset, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(flagtree, hf_ns_activity_pcb_zombie, tvb, flagoffset, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(flagtree, hf_ns_activity_natpcb_zombie, tvb, flagoffset, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(flagtree, hf_ns_activity_lbstats_sync, tvb, flagoffset, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(flagtree, hf_ns_activity_stats_req, tvb, flagoffset, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(ns_tree, hf_ns_snd_cwnd, tvb, (flagoffset + 4), 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(ns_tree, hf_ns_realtime_rtt, tvb, (flagoffset + 8), 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(ns_tree, hf_ns_ts_recent, tvb, (flagoffset + 12), 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(ns_tree, hf_ns_http_abort_tracking_reason, tvb, (pnstr->dst_vmname_len_offset + 1), 1, ENC_LITTLE_ENDIAN);

		/* fall through to next case */

	case NSPR_HEADER_VERSION205:

		if(src_vmname_len){
			proto_tree_add_item(ns_tree,hf_ns_src_vm,tvb,pnstr->data_offset,src_vmname_len,ENC_ASCII|ENC_NA);
			}

		if(dst_vmname_len){
			proto_tree_add_item(ns_tree,hf_ns_dst_vm,tvb,pnstr->data_offset+src_vmname_len,dst_vmname_len,ENC_ASCII|ENC_NA);
			}
		/* fall through to next case */


	case NSPR_HEADER_VERSION204:
		{
		static const int * clflags[] = {
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
		/* fall through to next case */

	case NSPR_HEADER_VERSION203:
		proto_tree_add_item(ns_tree, hf_ns_coreid, tvb, pnstr->coreid_offset, 2, ENC_LITTLE_ENDIAN);
		/* fall through to next case */

	case NSPR_HEADER_VERSION202:
		col_add_fstr(pinfo->cinfo, COL_8021Q_VLAN_ID, "%d", tvb_get_letohs(tvb, pnstr->vlantag_offset));
		proto_tree_add_item(ns_tree, hf_ns_vlantag, tvb, pnstr->vlantag_offset, 2, ENC_LITTLE_ENDIAN);
		/* fall through to next case */

	case NSPR_HEADER_VERSION201:
		proto_tree_add_item(ns_tree, hf_ns_pcbdevno, tvb, pnstr->pcb_offset, 4, ENC_LITTLE_ENDIAN);
		ti = proto_tree_add_item(ns_tree, hf_ns_devno, tvb, pnstr->pcb_offset, 4, ENC_LITTLE_ENDIAN);
		PROTO_ITEM_SET_HIDDEN(ti);

		proto_tree_add_item(ns_tree, hf_ns_l_pcbdevno, tvb, pnstr->l_pcb_offset, 4, ENC_LITTLE_ENDIAN);
		ti = proto_tree_add_item(ns_tree, hf_ns_devno, tvb, pnstr->l_pcb_offset, 4, ENC_LITTLE_ENDIAN);
		PROTO_ITEM_SET_HIDDEN(ti);

		break;

	case NSPR_HEADER_VERSION350:
		{
			proto_tree *capflagtree = NULL;
			proto_item *capflagitem = NULL;
			flagoffset = pnstr->ns_activity_offset;
			flagitem = proto_tree_add_item(ns_tree, hf_ns_activity, tvb, flagoffset, 4, ENC_LITTLE_ENDIAN);
			flagtree = proto_item_add_subtree(flagitem, ett_ns_activity_flags);
			proto_tree_add_item(flagtree, hf_ns_activity_perf_collection, tvb, flagoffset, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(flagtree, hf_ns_activity_pcb_zombie, tvb, flagoffset, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(flagtree, hf_ns_activity_natpcb_zombie, tvb, flagoffset, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(flagtree, hf_ns_activity_lbstats_sync, tvb, flagoffset, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(flagtree, hf_ns_activity_stats_req, tvb, flagoffset, 4, ENC_LITTLE_ENDIAN);

			capflagitem = proto_tree_add_item(ns_tree, hf_ns_capflags, tvb, flagoffset, 4, ENC_LITTLE_ENDIAN);
			capflagtree = proto_item_add_subtree(capflagitem, ett_ns_capflags);
			proto_tree_add_item(capflagtree, hf_ns_capflags_dbg, tvb, flagoffset, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(capflagtree, hf_ns_capflags_int, tvb, flagoffset, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(capflagtree, hf_ns_capflags_skipnwhdr, tvb, flagoffset, 4, ENC_LITTLE_ENDIAN);

			proto_tree_add_item(ns_tree, hf_ns_errorcode, tvb, NSHDR_OFFSET_35(fp_errorcode), sizeof(guint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(ns_tree, hf_ns_app, tvb, NSHDR_OFFSET_35(fp_app), sizeof(guint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(ns_tree, hf_ns_coreid, tvb, pnstr->coreid_offset, 2, ENC_LITTLE_ENDIAN);

			/* NSPR_HEADER_VERSION202 stuff */
			col_add_fstr(pinfo->cinfo, COL_8021Q_VLAN_ID, "%d", tvb_get_letohs(tvb, pnstr->vlantag_offset));
			proto_tree_add_item(ns_tree, hf_ns_vlantag, tvb, pnstr->vlantag_offset, 2, ENC_LITTLE_ENDIAN);

			/* NSPR_HEADER_VERSION201 stuff */
			proto_tree_add_item(ns_tree, hf_ns_pcbdevno, tvb, pnstr->pcb_offset, 4, ENC_LITTLE_ENDIAN);
			ti = proto_tree_add_item(ns_tree, hf_ns_devno, tvb, pnstr->pcb_offset, 4, ENC_LITTLE_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(ti);

			proto_tree_add_item(ns_tree, hf_ns_l_pcbdevno, tvb, pnstr->l_pcb_offset, 4, ENC_LITTLE_ENDIAN);
			ti = proto_tree_add_item(ns_tree, hf_ns_devno, tvb, pnstr->l_pcb_offset, 4, ENC_LITTLE_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(ti);

			add35records(tvb, pinfo, tree, ns_tree);
		}
		break; /* we can return here. break;ing in case some compilers are unhappy */

	default:
		break;
	}

	if(pnstr->rec_type != NSPR_HEADER_VERSION350){
		/* Dissect as Ethernet */
		offset = pnstr->eth_offset;
		next_tvb_eth_client = tvb_new_subset_remaining(tvb, offset);
		call_dissector(eth_withoutfcs_handle, next_tvb_eth_client, pinfo, tree);
	}

	return tvb_captured_length(tvb);
}

void add35records(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *ns_tree)
{
	tvbuff_t       *next_tvb_eth_client;
	guint     nsheaderlen=0;
	guint8    ssl_internal=0;
	guint		offset;
	int morerecs=1;
	int loopcount=0;
	static const int * cluster_flags[] = {
		&hf_ns_clu_clflags_fp,
		&hf_ns_clu_clflags_fr,
		&hf_ns_clu_clflags_dfd,
		&hf_ns_clu_clflags_rss,
		&hf_ns_clu_clflags_rssh,
		&hf_ns_clu_clflags_res,
		NULL,
	};
	int cur_record=tvb_get_guint8(tvb,NSHDR_OFFSET_35(fp_nextrecord));

	nsheaderlen = tvb_get_letohs(tvb, NSHDR_OFFSET_35(fp_headerlen));
	offset = sizeof(nspr_pktracefull_v35_t);

	do{
		switch(cur_record){
			/* Add a case statement here for each record */
			case NSREC_ETHERNET:
				/* Call Ethernet dissector */
				next_tvb_eth_client = tvb_new_subset_remaining(tvb, offset);
				call_dissector(eth_withoutfcs_handle, next_tvb_eth_client, pinfo, tree);
				if(ssl_internal){
					col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[NS_INTERNAL_SSL]");
				}
				morerecs=0;
				break;
			case NSREC_HTTP:
				/* Call HTTP dissector */
				{
					tvbuff_t *next_tvb_http_client;
					morerecs=0;
					next_tvb_http_client = tvb_new_subset_remaining(tvb, offset);
					call_dissector(http_handle, next_tvb_http_client, pinfo, tree);
				}
				break;
			case NSREC_TCPDEBUG:
			{
				proto_item *tcpdbgItem=NULL;
				proto_tree *tcpdbgTree=NULL;
				int reclen = tvb_get_letohs(tvb,offset+NSHDR_RECOFFSET_35(rec_len));
				int nextrec = tvb_get_guint8(tvb,offset+NSHDR_RECOFFSET_35(nextrec_type));
				/* Add tcpdebug subtree */
				tcpdbgItem = proto_tree_add_item(ns_tree, hf_ns_tcpdbg, tvb, offset, reclen, ENC_NA);
				tcpdbgTree = proto_item_add_subtree(tcpdbgItem, ett_ns_tcpdebug);
				proto_tree_add_item(tcpdbgTree, hf_ns_tcpdbg_cwnd, tvb, offset+TCPRECOFFSET(snd_cwnd), 4, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(tcpdbgTree, hf_ns_tcpdbg_rtrtt, tvb, offset+TCPRECOFFSET(real_time_rtt), 4, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(tcpdbgTree, hf_ns_tcpdbg_tsrecent, tvb, offset+TCPRECOFFSET(ts_recent), 4, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(tcpdbgTree, hf_ns_tcpdbg_httpabort, tvb, offset+TCPRECOFFSET(http_abort_reason), 1, ENC_LITTLE_ENDIAN);

				offset += reclen;
				cur_record = nextrec;
			}
			break;
			case NSREC_INFO:
			{
				proto_item *infoItem=NULL;
				proto_tree *infoTree=NULL;
				int reclen = tvb_get_letohs(tvb,offset+NSHDR_RECOFFSET_35(rec_len));
				int nextrec = tvb_get_guint8(tvb,offset+NSHDR_RECOFFSET_35(nextrec_type));
				infoItem = proto_tree_add_item(ns_tree, hf_ns_inforec, tvb, offset, reclen, ENC_NA);
				infoTree = proto_item_add_subtree(infoItem, ett_ns_inforec);
				proto_tree_add_item(infoTree, hf_ns_inforec_info, tvb, offset+(guint)sizeof(nspr_rec_info_t), reclen-3, ENC_ASCII|ENC_NA);

				offset += reclen;
				cur_record = nextrec;
			}
			break;
			case NSREC_SSL:
			{
				proto_item *sslItem=NULL;
				proto_tree *sslTree=NULL;
				int reclen = tvb_get_letohs(tvb,offset+NSHDR_RECOFFSET_35(rec_len));
				int nextrec = tvb_get_guint8(tvb,offset+NSHDR_RECOFFSET_35(nextrec_type));

				sslItem = proto_tree_add_item(ns_tree, hf_ns_sslrec, tvb, offset, reclen, ENC_NA);
				sslTree = proto_item_add_subtree(sslItem, ett_ns_sslrec);
				proto_tree_add_item(sslTree, hf_ns_sslrec_seq, tvb, offset+SSLRECOFFSET(seq), 4, ENC_LITTLE_ENDIAN);

				ssl_internal=1;

				offset += reclen;
				cur_record = nextrec;
			}
			break;
			case NSREC_MPTCP:
			{
				proto_item *mptcpItem=NULL;
				proto_tree *mptcpTree=NULL;
				int reclen = tvb_get_letohs(tvb,offset+NSHDR_RECOFFSET_35(rec_len));
				int nextrec = tvb_get_guint8(tvb,offset+NSHDR_RECOFFSET_35(nextrec_type));

				mptcpItem = proto_tree_add_item(ns_tree, hf_ns_mptcprec, tvb, offset, reclen, ENC_NA);
				mptcpTree = proto_item_add_subtree(mptcpItem, ett_ns_mptcprec);
				proto_tree_add_item(mptcpTree, hf_ns_mptcprec_subflowid, tvb, offset+MPTCPRECOFFSET(subflowid), 1, ENC_LITTLE_ENDIAN);

				offset += reclen;
				cur_record = nextrec;
			}
			break;
			case NSREC_VMNAMES:
			{
				proto_item *vmnameItem=NULL;
				proto_tree *vmnameTree=NULL;
				gint reclen = tvb_get_letohs(tvb,offset+NSHDR_RECOFFSET_35(rec_len));
				gint nextrec = tvb_get_guint8(tvb,offset+NSHDR_RECOFFSET_35(nextrec_type));

				gint srcvmnamelen = tvb_get_guint8(tvb,offset+VMNAMERECOFFSET(src_vmname_len));
				gint dstvmnamelen = tvb_get_guint8(tvb,offset+VMNAMERECOFFSET(dst_vmname_len));
				vmnameItem = proto_tree_add_item(ns_tree, hf_ns_vmnamerec, tvb, offset, reclen, ENC_NA);
				vmnameTree = proto_item_add_subtree(vmnameItem, ett_ns_vmnamerec);
				proto_tree_add_item(vmnameTree, hf_ns_vmnamerec_srcvmname, tvb, offset+(guint)sizeof(nspr_rec_vmname_t),
														srcvmnamelen, ENC_ASCII|ENC_NA);
				proto_tree_add_item(vmnameTree, hf_ns_vmnamerec_dstvmname, tvb, offset+(guint)sizeof(nspr_rec_vmname_t)+srcvmnamelen,
														dstvmnamelen, ENC_ASCII|ENC_NA);

				offset += reclen;
				cur_record = nextrec;
			}
			break;

			case NSREC_CLUSTER:
			{
				proto_item *clusterItem=NULL;
				proto_tree *clusterTree=NULL;
				gint reclen = tvb_get_letohs(tvb,offset+NSHDR_RECOFFSET_35(rec_len));
				gint nextrec = tvb_get_guint8(tvb,offset+NSHDR_RECOFFSET_35(nextrec_type));

				clusterItem = proto_tree_add_item(ns_tree, hf_ns_clusterrec, tvb, offset, reclen, ENC_NA);
				clusterTree = proto_item_add_subtree(clusterItem, ett_ns_clusterrec);

				proto_tree_add_item(clusterTree, hf_ns_clu_snode, tvb, offset+CLUSTERRECOFFSET(fp_srcNodeId), 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(clusterTree, hf_ns_clu_dnode, tvb, offset+CLUSTERRECOFFSET(fp_destNodeId), 2, ENC_LITTLE_ENDIAN);

					proto_tree_add_bitmask(clusterTree,tvb, offset+CLUSTERRECOFFSET(fp_clFlags),hf_ns_clu_clflags,ett_ns_flags,cluster_flags,ENC_NA);
				offset += reclen;
				cur_record = nextrec;
			}
			break;

			case NSREC_NULL:
				morerecs = 0;
				break;

			default:
			/* This will end up in an infinite loop if the file is corrupt */
			{
				proto_item *unknownItem=NULL;
				proto_tree *unknownTree=NULL;
				int reclen = tvb_get_letohs(tvb,offset+NSHDR_RECOFFSET_35(rec_len));
				int nextrec = tvb_get_guint8(tvb,offset+NSHDR_RECOFFSET_35(nextrec_type));
				loopcount++;
				unknownItem = proto_tree_add_item(ns_tree, hf_ns_unknownrec, tvb, offset, reclen, ENC_NA);
				unknownTree = proto_item_add_subtree(unknownItem, ett_ns_unknownrec);
				proto_tree_add_item(unknownTree, hf_ns_unknowndata, tvb, offset+3, reclen-3, ENC_NA);

				if(cur_record == UNKNOWN_LAST){
					morerecs=0;
				}else{
					offset += reclen;
					cur_record = nextrec;
				}
			}
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
		    FT_UINT8, BASE_HEX, VALS(ns_dir_vals), 0x0,
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
				FT_UINT8, BASE_DEC, VALS(ns_httpabortcode_vals), 0x0,
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
		    FT_STRING, STR_ASCII, NULL, 0x0,
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
		    FT_STRING, STR_ASCII, NULL, 0x0,
		    NULL, HFILL}
		},

		{ &hf_ns_vmnamerec_dstvmname,
		  { "DstVmName", "nstrace.vmnames.dstvmnames",
		    FT_STRING, STR_ASCII, NULL, 0x0,
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
		    FT_UINT8, BASE_HEX, VALS(ns_app_vals), 0x0,
		    NULL, HFILL }
		},

	};

	static gint *ett[] = {
		&ett_ns,
		&ett_ns_flags,
		&ett_ns_activity_flags,
		&ett_ns_tcpdebug,
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

}


void proto_reg_handoff_ns(void)
{
	dissector_handle_t nstrace_handle;

	eth_withoutfcs_handle = find_dissector_add_dependency("eth_withoutfcs", proto_nstrace);
	http_handle = find_dissector_add_dependency("http", proto_nstrace);

	nstrace_handle = create_dissector_handle(dissect_nstrace, proto_nstrace);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_NSTRACE_1_0, nstrace_handle);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_NSTRACE_2_0, nstrace_handle);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_NSTRACE_3_0, nstrace_handle);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_NSTRACE_3_5, nstrace_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
