/* packet-isis-lsp.c
 * Routines for decoding isis lsp packets and their CLVs
 *
 * $Id: packet-isis-lsp.c,v 1.3 2000/01/24 03:33:32 guy Exp $
 * Stuart Stanley <stuarts@mxmail.net>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
 *
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>

#ifdef HAVE_NET_INET_H
#include <net/inet.h>
#endif

#include "packet.h"
#include "packet-isis.h"
#include "packet-isis-clv.h"
#include "packet-isis-lsp.h"
#include "resolv.h"

/* lsp packets */
static int proto_isis_lsp = -1;
static int hf_isis_lsp_pdu_length = -1;
static int hf_isis_lsp_remaining_life = -1;
static int hf_isis_lsp_sequence_number = -1;
static int hf_isis_lsp_checksum = -1;
static int hf_isis_lsp_clv_ipv4_int_addr = -1;

static gint ett_isis_lsp = -1;
static gint ett_isis_lsp_clv_area_addr = -1;
static gint ett_isis_lsp_clv_is_neighbors = -1;
static gint ett_isis_lsp_clv_unknown = -1;
static gint ett_isis_lsp_clv_partition_dis = -1;
static gint ett_isis_lsp_clv_prefix_neighbors = -1;
static gint ett_isis_lsp_clv_nlpid = -1;
static gint ett_isis_lsp_clv_auth = -1;
static gint ett_isis_lsp_clv_ipv4_int_addr = -1;
static gint ett_isis_lsp_clv_ip_reachability = -1;

static const char *isis_lsp_attached_bits[] = {
	"error", "expense", "delay", "default" };

static const value_string isis_lsp_istype_vals[] = {
	{ ISIS_LSP_TYPE_UNUSED0,	"Unused 0x0 (invalid)"},
	{ ISIS_LSP_TYPE_LEVEL_1,	"Level 1 IS"},
	{ ISIS_LSP_TYPE_UNUSED2,	"Unused 0x2 (invalid)"},
	{ ISIS_LSP_TYPE_LEVEL_2,	"Level 2 IS"},
	{ 0, NULL } };

/* 
 * Predclare dissectors for use in clv dissection.
 */
static void dissect_lsp_area_address_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree);
static void dissect_lsp_l1_is_neighbors_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree);
static void dissect_lsp_l1_es_neighbors_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree);
static void dissect_lsp_l2_is_neighbors_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree);
static void dissect_lsp_partition_dis_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree);
static void dissect_lsp_prefix_neighbors_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree);
static void dissect_lsp_ip_reachability_clv(const u_char *pd, int offset,
		guint length, frame_data *fd, proto_tree *tree);
static void dissect_lsp_nlpid_clv(const u_char *pd, int offset,
		guint length, frame_data *fd, proto_tree *tree);
static void dissect_lsp_ip_int_addr_clv(const u_char *pd, int offset,
		guint length, frame_data *fd, proto_tree *tree);
static void dissect_lsp_l1_auth_clv(const u_char *pd, int offset,
		guint length, frame_data *fd, proto_tree *tree);
static void dissect_lsp_l2_auth_clv(const u_char *pd, int offset,
		guint length, frame_data *fd, proto_tree *tree);

static const isis_clv_handle_t clv_l1_lsp_opts[] = {
	{
		ISIS_CLV_L1_LSP_AREA_ADDRESS,
		"Area address(es)",
		&ett_isis_lsp_clv_area_addr,
		dissect_lsp_area_address_clv
	},
	{
		ISIS_CLV_L1_LSP_IS_NEIGHBORS,
		"IS Neighbor(s)",
		&ett_isis_lsp_clv_is_neighbors,
		dissect_lsp_l1_is_neighbors_clv
	},
	{
		ISIS_CLV_L1_LSP_ES_NEIGHBORS,
		"ES Neighbor(s)",
		&ett_isis_lsp_clv_is_neighbors,
		dissect_lsp_l1_es_neighbors_clv
	},
	{
		ISIS_CLV_L1_LSP_IP_INT_REACHABLE,
		"IP Internal reachability",
		&ett_isis_lsp_clv_ip_reachability,
		dissect_lsp_ip_reachability_clv
	},
	{
		ISIS_CLV_L1_LSP_NLPID,
		"NLPID",
		&ett_isis_lsp_clv_nlpid,
		dissect_lsp_nlpid_clv
	},
	{
		ISIS_CLV_L1_LSP_IP_INTERFACE_ADDR,
		"IP Interface address(es)",
		&ett_isis_lsp_clv_ipv4_int_addr,
		dissect_lsp_ip_int_addr_clv
	},
	{
		ISIS_CLV_L1_LSP_AUTHENTICATION_NS,
		"Authentication(non-spec)",
		&ett_isis_lsp_clv_auth,
		dissect_lsp_l1_auth_clv
	},
	{
		ISIS_CLV_L1_LSP_AUTHENTICATION,
		"Authentication",
		&ett_isis_lsp_clv_auth,
		dissect_lsp_l1_auth_clv
	},
	{
		0,
		"",
		NULL,
		NULL
	}
};

static const isis_clv_handle_t clv_l2_lsp_opts[] = {
	{
		ISIS_CLV_L1_LSP_AREA_ADDRESS,
		"Area address(es)",
		&ett_isis_lsp_clv_area_addr,
		dissect_lsp_area_address_clv
	},
	{
		ISIS_CLV_L2_LSP_IS_NEIGHBORS,
		"IS Neighbor(s)",
		&ett_isis_lsp_clv_is_neighbors,
		dissect_lsp_l2_is_neighbors_clv
	},
	{
		ISIS_CLV_L2_LSP_PARTITION_DIS,
		"Parition Designated Level 2 IS",
		&ett_isis_lsp_clv_partition_dis,
		dissect_lsp_partition_dis_clv
	},
	{
		ISIS_CLV_L2_LSP_PREFIX_NEIGHBORS,
		"Prefix neighbors",
		&ett_isis_lsp_clv_prefix_neighbors,
		dissect_lsp_prefix_neighbors_clv
	},
	{
		ISIS_CLV_L2_LSP_IP_INT_REACHABLE,
		"IP Internal reachability",
		&ett_isis_lsp_clv_ip_reachability,
		dissect_lsp_ip_reachability_clv
	},
	{
		ISIS_CLV_L2_LSP_NLPID,
		"NLPID",
		&ett_isis_lsp_clv_nlpid,
		dissect_lsp_nlpid_clv
	},
	{
		ISIS_CLV_L2_LSP_IP_EXT_REACHABLE,
		"IP external reachability",
		&ett_isis_lsp_clv_ip_reachability,
		dissect_lsp_ip_reachability_clv
	},
	{
		ISIS_CLV_L2_LSP_IP_INTERFACE_ADDR,
		"IP Interface address(es)",
		&ett_isis_lsp_clv_ipv4_int_addr,
		dissect_lsp_ip_int_addr_clv
	},
	{
		ISIS_CLV_L2_LSP_AUTHENTICATION_NS,
		"Authentication(non spec)",
		&ett_isis_lsp_clv_auth,
		dissect_lsp_l2_auth_clv
	},
	{
		ISIS_CLV_L2_LSP_AUTHENTICATION,
		"Authentication",
		&ett_isis_lsp_clv_auth,
		dissect_lsp_l2_auth_clv
	},
	{
		0,
		"",
		NULL,
		NULL
	}
};


/*
 * Name: dissect_metric()
 * 
 * Description:
 *	Display a metric prefix portion.  ISIS has the concept of multple
 *	metric per prefix (default, delay, expense, and error).  This
 *	routine assists other dissectors by adding a single one of
 *	these to the display tree..  
 *
 *	The 8th(msbit) bit in the metric octet is the "supported" bit.  The
 *		"default" support is required, so we support a "force_supported"
 *		flag that tells us that it MUST be zero (zero==supported,
 *		so it really should be a "not supported" in the boolean sense)
 *		and to display a protocol failure accordingly.  Notably,
 *		Cisco IOS 12(6) blows this!
 *	The 7th bit must be zero (reserved).
 *
 * Input:
 *	u_char * : packet data
 *	int : offset into packet data where we are.
 *	guint : length of clv we are decoding
 *	frame_data * : frame data (complete frame)
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : force supported.  True is the supported bit MUST be zero.
 * 
 * Output:
 *	void, but we will add to proto tree if !NULL.
 */
static void 
dissect_metric(proto_tree *tree, int offset, guint8 value, 
		char *pstr, int force_supported ) {
	int s;

	if ( !tree ) return;

	s = ISIS_LSP_CLV_METRIC_SUPPORTED(value);
	proto_tree_add_text ( tree, offset, 1, 
		"%s Metric: %s%s %s%d:%d", pstr,
		s ? "Not supported" : "Supported",
		(s && force_supported) ? "(but is required to be)":"",
		ISIS_LSP_CLV_METRIC_RESERVED(value) ? "(reserved bit != 0)":"",
		ISIS_LSP_CLV_METRIC_VALUE(value), value );
}
	

/*
 * Name: dissect_lsp_ip_reachabillityclv()
 *
 * Description:
 *	Decode an IP reachability CLV.  This can be either internal or
 *	external (the clv format does not change and which type we are
 *	displaying is put there by the dispatcher).  All of these
 *	are a metric block followed by an IP addr and mask.
 *
 * Input:
 *	u_char * : packet data
 *	int : current offset into packet data
 *	guint : length of this clv
 *	frame_data * : frame data
 *	proto_tree * : proto tree to build on (may be null)
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void 
dissect_lsp_ip_reachability_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree) {
	proto_item 	*ti;
	proto_tree	*ntree = NULL;
	guint32		src, mask;

	while ( length > 0 ) {
		if (length<12) {
			isis_dissect_unknown(offset, length, tree, fd,
				"short IP reachability (%d vs 12)", length );
			return;
		}
		/* 
		 * Gotta build a sub-tree for all our pieces
		 */
		if ( tree ) {
			memcpy(&src, &pd[offset+4], 4);
			memcpy(&mask, &pd[offset+8], 4);
			ti = proto_tree_add_text ( tree, offset, 12, 
				"IP prefix: %s (%s) : %s",
				get_hostname(src), ip_to_str((guint8*)&src),
				ip_to_str((guint8*)&mask) );
			ntree = proto_item_add_subtree(ti, 
				ett_isis_lsp_clv_ip_reachability);
			dissect_metric ( ntree, offset, pd[offset], "Default", 
				TRUE );
			dissect_metric ( ntree, offset + 1, pd[offset+1], 
				"Delay", FALSE );
			dissect_metric ( ntree, offset + 2, pd[offset+2], 
				"Expense",FALSE );
			dissect_metric ( ntree, offset + 3, pd[offset+3], 
				"Error", FALSE );
		}
		offset += 12;
		length -= 12;
	}
}
/*
 * Name: dissect_lsp_nlpid_clv()
 *
 * Description:
 *	Decode for a lsp packets NLPID clv.  Calls into the
 *	clv common one.
 *
 * Input:
 *	u_char * : packet data
 *	int : current offset into packet data
 *	guint : length of this clv
 *	frame_data * : frame data
 *	proto_tree * : proto tree to build on (may be null)
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void 
dissect_lsp_nlpid_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree) {
	isis_dissect_nlpid_clv(pd, offset, length, fd, tree );
}

/*
 * Name: dissect_lsp_ip_int_addr_clv()
 *
 * Description:
 *	Decode for a lsp packets ip interface addr clv.  Calls into the
 *	clv common one.
 *
 * Input:
 *	u_char * : packet data
 *	int : current offset into packet data
 *	guint : length of this clv
 *	frame_data * : frame data
 *	proto_tree * : proto tree to build on (may be null)
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void 
dissect_lsp_ip_int_addr_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree) {
	isis_dissect_ip_int_clv(pd, offset, length, fd, tree, 
		hf_isis_lsp_clv_ipv4_int_addr );
}

/*
 * Name: dissect_lsp_L1_auth_clv()
 *
 * Description:
 *	Decode for a lsp packets authenticaion clv.  Calls into the
 *	clv common one.  An auth inside a L1 LSP is a per area password
 *
 * Input:
 *	u_char * : packet data
 *	int : current offset into packet data
 *	guint : length of this clv
 *	frame_data * : frame data
 *	proto_tree * : proto tree to build on (may be null)
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void 
dissect_lsp_l1_auth_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree) {
	isis_dissect_authentication_clv(pd, offset, length, fd, tree, 
		"Per area authentication" );
}

/*
 * Name: dissect_lsp_L2_auth_clv()
 *
 * Description:
 *	Decode for a lsp packets authenticaion clv.  Calls into the
 *	clv common one.  An auth inside a L2 LSP is a per domain password
 *
 * Input:
 *	u_char * : packet data
 *	int : current offset into packet data
 *	guint : length of this clv
 *	frame_data * : frame data
 *	proto_tree * : proto tree to build on (may be null)
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void 
dissect_lsp_l2_auth_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree) {
	isis_dissect_authentication_clv(pd, offset, length, fd, tree, 
		"Per domain authentication" );
}

/*
 * Name: dissect_lsp_area_address_clv()
 *
 * Description:
 *	Decode for a lsp packet's area address clv.  Call into clv common
 *	one.
 *
 * Input:
 *	u_char * : packet data
 *	int : offset into packet data where we are.
 *	guint : length of clv we are decoding
 *	frame_data * : frame data (complete frame)
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void 
dissect_lsp_area_address_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree) {
	isis_dissect_area_address_clv(pd, offset, length, fd, tree );
}

/*
 * Name: dissect_lsp_eis_neighbors_clv_inner()
 *
 * Description:
 *	Real work horse for showing neighbors.  This means we decode the
 *	first octet as either virtual/!virtual (if show_virtual param is
 *	set), or as a must == 0 reserved value.
 *
 *	Once past that, we decode n neighbor elements.  Each neighbor
 *	is comprised of a metric block (is dissect_metric) and the
 *	addresses.
 *
 * Input:
 *	u_char * : packet data
 *	int : offset into packet data where we are.
 *	guint : length of clv we are decoding
 *	frame_data * : frame data (complete frame)
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : set to decode first octet as virtual vs reserved == 0
 *	int : set to indicate EIS instead of IS (6 octet per addr instead of 7)
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void 
dissect_lsp_eis_neighbors_clv_inner(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree,
		int show_virtual, int is_eis) {
	proto_item 	*ti;
	proto_tree	*ntree = NULL;
	int		tlen;

	if (is_eis) {
		tlen = 10;
	} else {
		tlen = 11;
		if ( tree ) {
			if ( show_virtual ) {
				/* virtual path flag */
				proto_tree_add_text ( tree, offset, 1, 
				   &pd[offset] ? "IsNotVirtual" : "IsVirtual" );
			} else {
				proto_tree_add_text ( tree, offset, 1, 
					"Reserved value 0x%02x, must == 0",
					pd[offset]  );
			}
		}
		offset++;
		length--;
			
	}

	while ( length > 0 ) {
		if (length<tlen) {
			isis_dissect_unknown(offset, length, tree, fd,
				"short E/IS reachability (%d vs %d)", length,
				tlen );
			return;
		}
		/* 
		 * Gotta build a sub-tree for all our pieces
		 */
		if ( tree ) {
			if ( is_eis ) {
				ti = proto_tree_add_text ( tree, offset, 11, 
					"ES Neighbor: %02x%02x.%02x%02x.%02x%02x",
					pd[offset+4], pd[offset+5], 
					pd[offset+6], pd[offset+7], 
					pd[offset+8], pd[offset+9] );
			} else {
				ti = proto_tree_add_text ( tree, offset, 11, 
					"IS Neighbor: %02x%02x.%02x%02x.%02x%02x-%02x",
					pd[offset+4], pd[offset+5], 
					pd[offset+6], pd[offset+7], 
					pd[offset+8], pd[offset+9],
					pd[offset+10] );
			}
			ntree = proto_item_add_subtree(ti, 
				ett_isis_lsp_clv_is_neighbors);
			dissect_metric ( ntree, offset, pd[offset], "Default", 
				TRUE );
			dissect_metric ( ntree, offset + 1, pd[offset+1], 
				"Delay", FALSE );
			dissect_metric ( ntree, offset + 2, pd[offset+2], 
				"Expense",FALSE );
			dissect_metric ( ntree, offset + 3, pd[offset+3], 
				"Error", FALSE );
		}
		offset += tlen;
		length -= tlen;
	}
}

/*
 * Name: dissect_lsp_l1_is_neighbors_clv()
 *
 * Description:
 *	Dispatch a l1 intermediate system neighbor by calling
 *	the inner function with show virtual set to TRUE and is es set to FALSE.
 *
 * Input:
 *	u_char * : packet data
 *	int : offset into packet data where we are.
 *	guint : length of clv we are decoding
 *	frame_data * : frame data (complete frame)
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void 
dissect_lsp_l1_is_neighbors_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree) {
	dissect_lsp_eis_neighbors_clv_inner( pd, offset, length, fd, tree,TRUE,
		FALSE );
}

/*
 * Name: dissect_lsp_l1_es_neighbors_clv()
 *
 * Description:
 *	Dispatch a l1 end or intermediate system neighbor by calling
 *	the inner function with show virtual set to TRUE and es set to TRUE.
 *
 * Input:
 *	u_char * : packet data
 *	int : offset into packet data where we are.
 *	guint : length of clv we are decoding
 *	frame_data * : frame data (complete frame)
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void 
dissect_lsp_l1_es_neighbors_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree) {
	dissect_lsp_eis_neighbors_clv_inner( pd, offset, length, fd, tree,
		TRUE, TRUE);
}

/*
 * Name: dissect_lsp_l2_is_neighbors_clv()
 *
 * Description:
 *	Dispatch a l2 intermediate system neighbor by calling
 *	the inner function with show virtual set to FALSE, and is es set
 *	to FALSE
 *
 * Input:
 *	u_char * : packet data
 *	int : offset into packet data where we are.
 *	guint : length of clv we are decoding
 *	frame_data * : frame data (complete frame)
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void 
dissect_lsp_l2_is_neighbors_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree) {
	dissect_lsp_eis_neighbors_clv_inner(pd,offset, length, fd, tree, FALSE,
		FALSE);
}

/*
 * Name: dissect_lsp_partition_dis_clv()
 *
 * Description:
 *	This CLV is used to indicate which system is the designated
 *	IS for partition repair.  This means just putting out the 6 octet
 *	IS.
 *
 * Input:
 *	u_char * : packet data
 *	int : offset into packet data where we are.
 *	guint : length of clv we are decoding
 *	frame_data * : frame data (complete frame)
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void 
dissect_lsp_partition_dis_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree) {

	if ( length < 6 ) {
		isis_dissect_unknown(offset, length, tree, fd,
				"short lsp parition DIS(%d vs 6)", length );
		return;
	}
	/* 
	 * Gotta build a sub-tree for all our pieces
	 */
	if ( tree ) {
		proto_tree_add_text ( tree, offset+4, 6, 
			"Partition designated L2 IS: %02x%02x.%02x%02x.%02x%02x",
			pd[offset], pd[offset+1], pd[offset+2],
			pd[offset+3], pd[offset+4], pd[offset+5]);
	}
	length -= 6;
	offset +=  6;
	if ( length > 0 ){
		isis_dissect_unknown(offset, length, tree, fd,
				"Long lsp parition DIS, %d left over", length );
		return;
	}
}

/*
 * Name: dissect_lsp_prefix_neighbors_clv()
 *
 * Description:
 *	The prefix CLV describes what other (OSI) networks we can reach
 *	and what their cost is.  It is built from a metric block
 *	(see dissect_metric) followed by n addresses.
 *
 * Input:
 *	u_char * : packet data
 *	int : offset into packet data where we are.
 *	guint : length of clv we are decoding
 *	frame_data * : frame data (complete frame)
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void 
dissect_lsp_prefix_neighbors_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree) {
	char *sbuf;
	int mylen;

	if ( length < 4 ) {
		isis_dissect_unknown(offset, length, tree, fd,
			"Short lsp prefix neighbors (%d vs 4)", length );
		return;
	}
	if ( tree ) {
		dissect_metric ( tree, offset, pd[offset], "Default", TRUE );
		dissect_metric ( tree, offset + 1, pd[offset+1], 
			"Delay", FALSE );
		dissect_metric ( tree, offset + 2, pd[offset+2], 
			"Expense", FALSE );
		dissect_metric ( tree, offset + 3, pd[offset+3], 
			"Error", FALSE );
	}
	offset += 4;
	length -= 4;
	while ( length > 0 ) {
		mylen = pd[offset];
		length--;
		if (length<=0) {
			isis_dissect_unknown(offset, length, tree, fd,
				"Zero payload space after length in prefix neighbor" );
			return;
		}
		if ( mylen > length) {
			isis_dissect_unknown(offset, length, tree, fd,
				"Interal length of prefix neighbor too long (%d vs %d)", 
				mylen, length );
			return;
		}

		/* 
		 * Lets turn the area address into "standard" 0000.0000.etc
		 * format string.  
		 */
		sbuf = isis_address_to_string ( pd, offset + 1, mylen );
		/* and spit it out */
		if ( tree ) {
			proto_tree_add_text ( tree, offset, mylen + 1, 
				"Area address (%d): %s", mylen, sbuf );
		}
		offset += mylen + 1;
		length -= mylen;	/* length already adjusted for len fld*/
	}
}

/*
 * Name: isis_lsp_decode_lsp_id()
 *
 * Description: 
 *	Display a LSP id into the display tree.
 *
 * Input:
 *	char * : title string
 *	proto_tree * : tree to display into. REQUIRED
 *	int : offset into packet data where we are.
 *	isis_lsp_id_t * : id to display.
 *
 * Output:
 *      void, but we will add to proto tree
 */
void
isis_lsp_decode_lsp_id(char *tstr, proto_tree *tree, int offset, 
		isis_lsp_id_t *id ) {
	proto_tree_add_text(tree, offset, 8, 
		"%s: %02x%02x.%02x%02x.%02x%02x.%02x-%02x", tstr,
			id->source_id[0],
			id->source_id[1],
			id->source_id[2],
			id->source_id[3],
			id->source_id[4],
			id->source_id[5],
			id->psuodonode_id,
			id->lsp_number );
}

/*
 * Name: isis_dissect_isis_lsp()
 *
 * Description:
 *	Print out the LSP part of the main header and then call the CLV
 *	de-mangler with the right list of valid CLVs.
 *
 * Input:
 *	u_char * : packet data
 *	int : offset into packet data where we are.
 *	guint : length of clv we are decoding
 *	frame_data * : frame data (complete frame)
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
void 
isis_dissect_isis_lsp(int lsp_type, int header_length, 
		const u_char *pd, int offset, frame_data *fd, proto_tree *tree){
	isis_lsp_t	*ilp;
	proto_item	*ti;
	proto_tree	*lsp_tree = NULL;
	int		hlen;
	char		sbuf[128];
	int		inx, q, some, value, len;

	hlen = sizeof(*ilp);

	if (!BYTES_ARE_IN_FRAME(offset, hlen)) {
		isis_dissect_unknown(offset, hlen, tree, fd,
			"not enough capture data for header (%d vs %d)",
			hlen, END_OF_FRAME);
		return;
	}
	
	ilp = (isis_lsp_t *) &pd[offset];

	if (tree) {
		ti = proto_tree_add_item(tree, proto_isis_lsp,
			offset, END_OF_FRAME, NULL);
		lsp_tree = proto_item_add_subtree(ti, ett_isis_lsp);
		proto_tree_add_item(lsp_tree, hf_isis_lsp_pdu_length,
			offset, 2, pntohs(&ilp->isis_lsp_pdu_length));
		proto_tree_add_item(lsp_tree, hf_isis_lsp_remaining_life,
			offset + 2, 2, pntohs(&ilp->isis_lsp_remaining_life));
		isis_lsp_decode_lsp_id("LSP ID", lsp_tree, offset + 4, 
			&ilp->isis_lsp_id );
		proto_tree_add_item(lsp_tree, hf_isis_lsp_sequence_number,
			offset + 12, 4, 
			pntohl(&ilp->isis_lsp_sequence_number));

		/* XXX -> we could validate the cksum here! */
		proto_tree_add_item(lsp_tree, hf_isis_lsp_checksum,
			offset + 16, 2, pntohs(&ilp->isis_lsp_checksum));

		/*
		 * We need to build our type block values. 
		 */
		sbuf[0] = 0;
		some = 0;
		value = ISIS_LSP_ATT(ilp->isis_lsp_type_block);
		inx = 0;
		for ( q = (1<<ISIS_LSP_ATT_SHIFT); q > 0; q = q >> 1 ){
			if (q & value) { 
				if (some++) {
					strcat(sbuf, ", ");
				}
				strcat ( sbuf, isis_lsp_attached_bits[inx] );
			}
			inx++;
		}
		if (!some) { 
			strcat ( sbuf, "<none set!>" );
		}
		proto_tree_add_text(lsp_tree, offset + 18, 1, 
			"Type block(0x%02x): P:%d, Supported metric(s): %s, OL:%d, istype:%s",
			ilp->isis_lsp_type_block, 
			ISIS_LSP_PARTITION(ilp->isis_lsp_type_block) ? 1 : 0,
			sbuf,
			ISIS_LSP_HIPPITY(ilp->isis_lsp_type_block) ? 1 : 0,
			val_to_str(ISIS_LSP_IS_TYPE(ilp->isis_lsp_type_block),
				isis_lsp_istype_vals, "Unknown (0x%x)")
			);

	}

	offset += hlen;
	len = pntohs(&ilp->isis_lsp_pdu_length);
	len -= header_length;
	if (len < 0) {
		isis_dissect_unknown(offset, header_length, tree, fd,
			"packet header length %d went beyond packet",
			 header_length );
		return;
	}
	/*
	 * Now, we need to decode our CLVs.  We need to pass in
	 * our list of valid ones!
	 */
	if (lsp_type == ISIS_TYPE_L1_LSP){
		isis_dissect_clvs ( clv_l1_lsp_opts, len, pd, offset, fd, 
			lsp_tree, ett_isis_lsp_clv_unknown );
	} else {
		isis_dissect_clvs ( clv_l2_lsp_opts, len, pd, offset, fd, 
			lsp_tree, ett_isis_lsp_clv_unknown );
	}
}
/*
 * Name: proto_register_isis_lsp()
 *
 * Description: 
 *	Register our protocol sub-sets with protocol manager.
 *	NOTE: this procedure is autolinked by the makefile process that
 *		builds register.c
 *
 * Input:
 *	u_char * : packet data
 *	int : offset into packet data where we are.
 *	guint : length of clv we are decoding
 *	frame_data * : frame data (complete frame)
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
void 
proto_register_isis_lsp(void) {
	static hf_register_info hf[] = {
		{ &hf_isis_lsp_pdu_length,
		{ "PDU length",		"isis_lsp.pdu_length", FT_UINT16, 
		  BASE_DEC, NULL, 0x0, "" }},

		{ &hf_isis_lsp_remaining_life,
		{ "Remaining life",	"isis_lsp.remaining_life", FT_UINT16, 
		  BASE_DEC, NULL, 0x0, "" }},

		{ &hf_isis_lsp_sequence_number,
		{ "Sequence number",           "isis_lsp.sequence_number", 
		  FT_UINT32, BASE_HEX, NULL, 0x0, "" }},

		{ &hf_isis_lsp_checksum,
		{ "Checksum",		"isis_lsp.checksum",FT_UINT16, 
		  BASE_HEX, NULL, 0x0, "" }},

		{ &hf_isis_lsp_clv_ipv4_int_addr,
		{ "IPv4 interface address: ", "", FT_IPv4,
		   BASE_NONE, NULL, 0x0, "" }},
	};
	static gint *ett[] = {
		&ett_isis_lsp,
		&ett_isis_lsp_clv_area_addr,
		&ett_isis_lsp_clv_is_neighbors,
		&ett_isis_lsp_clv_unknown,
		&ett_isis_lsp_clv_partition_dis,
		&ett_isis_lsp_clv_prefix_neighbors,
		&ett_isis_lsp_clv_auth,
		&ett_isis_lsp_clv_nlpid,
		&ett_isis_lsp_clv_ipv4_int_addr,
		&ett_isis_lsp_clv_ip_reachability,
	};

	proto_isis_lsp = proto_register_protocol("ISIS lsp", "ISIS-lsp");
	proto_register_field_array(proto_isis_lsp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
