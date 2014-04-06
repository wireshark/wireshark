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

#include <glib.h>
#include <epan/packet.h>
#include <epan/wmem/wmem.h>
#include <wiretap/netscaler.h>

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


static gint ett_ns = -1;
static gint ett_ns_flags = -1;
static gint ett_ns_activity_flags = -1;

static const value_string ns_dir_vals[] = {
	{ NSPR_PDPKTRACEFULLTX_V10,    "TX" },
	{ NSPR_PDPKTRACEFULLTX_V20,    "TX" },
	{ NSPR_PDPKTRACEFULLTX_V30,    "TX" },
	{ NSPR_PDPKTRACEFULLTXB_V10,   "TXB" },
	{ NSPR_PDPKTRACEFULLTXB_V20,   "TXB" },
	{ NSPR_PDPKTRACEFULLTXB_V30,   "TXB" },
	{ NSPR_PDPKTRACEFULLRX_V10,    "RX" },
	{ NSPR_PDPKTRACEFULLRX_V20,    "RX" },
	{ NSPR_PDPKTRACEFULLRX_V30,    "RX" },
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

static dissector_handle_t eth_withoutfcs_handle;

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

static void
dissect_nstrace(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree     *ns_tree = NULL, *flagtree = NULL;
	proto_item     *ti = NULL, *flagitem = NULL;
	struct nstr_phdr *pnstr = &(pinfo->pseudo_header->nstr);
	tvbuff_t       *next_tvb_eth_client;
	guint8		offset;
	guint		i, bpos;
	wmem_strbuf_t  *flags_strbuf = wmem_strbuf_new_label(wmem_packet_scope());
	static const gchar *flags[] = {"FP", "FR", "DFD", "SRSS", "RSSH"};
	gboolean 	first_flag = TRUE;
	guint8		flagoffset, flagval;
	guint8		src_vmname_len = 0, dst_vmname_len = 0;
	guint8		variable_ns_len = 0;
	guint 		flagval32;

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
		flagval32 = tvb_get_letohl(tvb, flagoffset);
		flagitem = proto_tree_add_uint_format(ns_tree, hf_ns_activity, tvb, flagoffset, 4, flagval32,
						"Activity Flags: 0x%04x", flagval32);
		flagtree = proto_item_add_subtree(flagitem, ett_ns_activity_flags);
		proto_tree_add_item(flagtree, hf_ns_activity_perf_collection, tvb, flagoffset, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(flagtree, hf_ns_activity_pcb_zombie, tvb, flagoffset, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(flagtree, hf_ns_activity_natpcb_zombie, tvb, flagoffset, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(flagtree, hf_ns_activity_lbstats_sync, tvb, flagoffset, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(flagtree, hf_ns_activity_stats_req, tvb, flagoffset, 4, ENC_LITTLE_ENDIAN);

	case NSPR_HEADER_VERSION205:

		if(src_vmname_len){
			proto_tree_add_item(ns_tree,hf_ns_src_vm,tvb,pnstr->data_offset,src_vmname_len,ENC_ASCII|ENC_NA);
			}

		if(dst_vmname_len){
			proto_tree_add_item(ns_tree,hf_ns_dst_vm,tvb,pnstr->data_offset+src_vmname_len,dst_vmname_len,ENC_ASCII|ENC_NA);
			}


	case NSPR_HEADER_VERSION204:

		flagoffset = pnstr->clflags_offset;
		flagval = tvb_get_guint8(tvb, flagoffset);

		for (i = 0; i < 5; i++) {
			bpos = 1 << i;
			if (flagval & bpos) {
				if (first_flag) {
					wmem_strbuf_truncate(flags_strbuf, 0);
				}
				wmem_strbuf_append_printf(flags_strbuf, "%s%s", first_flag ? "" : ", ", flags[i]);
				first_flag = FALSE;
			}
		}

		proto_tree_add_item(ns_tree, hf_ns_snode, tvb, pnstr->srcnodeid_offset, 2, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(ns_tree, hf_ns_dnode, tvb, pnstr->destnodeid_offset, 2, ENC_LITTLE_ENDIAN);

		flagitem = proto_tree_add_uint_format_value(ns_tree, hf_ns_clflags, tvb, flagoffset, 1, flagval,
						"0x%02x (%s)", flagval, wmem_strbuf_get_str(flags_strbuf));
		flagtree = proto_item_add_subtree(flagitem, ett_ns_flags);

		proto_tree_add_boolean(flagtree, hf_ns_clflags_res, tvb, flagoffset, 1, flagval);
		proto_tree_add_boolean(flagtree, hf_ns_clflags_rssh, tvb, flagoffset, 1, flagval);
		proto_tree_add_boolean(flagtree, hf_ns_clflags_rss, tvb, flagoffset, 1, flagval);
		proto_tree_add_boolean(flagtree, hf_ns_clflags_dfd, tvb, flagoffset, 1, flagval);
		proto_tree_add_boolean(flagtree, hf_ns_clflags_fr, tvb, flagoffset, 1, flagval);
		proto_tree_add_boolean(flagtree, hf_ns_clflags_fp, tvb, flagoffset, 1, flagval);

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

	default:
		break;
	}

	/* Dissect as Ethernet */
	offset = pnstr->eth_offset;
	next_tvb_eth_client = tvb_new_subset_remaining(tvb, offset);
	call_dissector(eth_withoutfcs_handle, next_tvb_eth_client, pinfo, tree);
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
		  { "NetScaler Activity", "nstrace.activity",
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

	};

	static gint *ett[] = {
		&ett_ns,
		&ett_ns_flags,
		&ett_ns_activity_flags,
	};

	proto_nstrace = proto_register_protocol("NetScaler Trace", "NS Trace", "ns");
	proto_register_field_array(proto_nstrace, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}


void proto_reg_handoff_ns(void)
{
	dissector_handle_t nstrace_handle;

	eth_withoutfcs_handle = find_dissector("eth_withoutfcs");

	nstrace_handle = create_dissector_handle(dissect_nstrace, proto_nstrace);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_NSTRACE_1_0, nstrace_handle);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_NSTRACE_2_0, nstrace_handle);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_NSTRACE_3_0, nstrace_handle);
}
