/* packet-atalk.c
 * Routines for Appletalk packet disassembly (DDP, currently).
 *
 * $Id: packet-atalk.c,v 1.61 2002/01/20 22:12:25 guy Exp $
 *
 * Simon Wilkinson <sxw@dcs.ed.ac.uk>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998
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
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>
#include "packet.h"
#include "etypes.h"
#include "ppptypes.h"
#include "aftypes.h"
#include "atalk-utils.h"

static int proto_llap = -1;
static int hf_llap_dst = -1;
static int hf_llap_src = -1;
static int hf_llap_type = -1;

static int proto_ddp = -1;
static int hf_ddp_hopcount = -1;
static int hf_ddp_len = -1;
static int hf_ddp_checksum = -1;
static int hf_ddp_dst_net = -1;
static int hf_ddp_src_net = -1;
static int hf_ddp_dst_node = -1;
static int hf_ddp_src_node = -1;
static int hf_ddp_dst_socket = -1;
static int hf_ddp_src_socket = -1;
static int hf_ddp_type = -1;

static int proto_nbp = -1;
static int hf_nbp_op = -1;
static int hf_nbp_info = -1;
static int hf_nbp_count = -1;
static int hf_nbp_tid = -1;

static int hf_nbp_node_net = -1;
static int hf_nbp_node_port = -1;
static int hf_nbp_node_node = -1;
static int hf_nbp_node_enum = -1;
static int hf_nbp_node_object = -1;
static int hf_nbp_node_type = -1;
static int hf_nbp_node_zone = -1;

static int proto_rtmp = -1;
static int hf_rtmp_net = -1;
static int hf_rtmp_node_len = -1;
static int hf_rtmp_node = -1;
static int hf_rtmp_tuple_net = -1;
static int hf_rtmp_tuple_range_start = -1;
static int hf_rtmp_tuple_range_end = -1;
static int hf_rtmp_tuple_dist = -1;
static int hf_rtmp_function = -1;

static gint ett_nbp = -1;
static gint ett_nbp_info = -1;
static gint ett_nbp_node = -1;
static gint ett_rtmp = -1;
static gint ett_rtmp_tuple = -1;
static gint ett_ddp = -1;
static gint ett_llap = -1;
static gint ett_pstring = -1;

static dissector_table_t ddp_dissector_table;

static dissector_handle_t data_handle;

#define DDP_SHORT_HEADER_SIZE 5

/*
 * P = Padding, H = Hops, L = Len
 *
 * PPHHHHLL LLLLLLLL
 *
 * Assumes the argument is in host byte order.
 */
#define ddp_hops(x)	( ( x >> 10) & 0x3C )
#define ddp_len(x)		( x & 0x03ff )
typedef struct _e_ddp {
  guint16	hops_len; /* combines pad, hops, and len */
  guint16	sum,dnet,snet;
  guint8	dnode,snode;
  guint8	dport,sport;
  guint8	type;
} e_ddp;

#define DDP_HEADER_SIZE 13


static const value_string op_vals[] = {
  {DDP_RTMPDATA, "AppleTalk Routing Table response or data" },
  {DDP_NBP, "AppleTalk Name Binding Protocol packet"},
  {DDP_ATP, "AppleTalk Transaction Protocol packet"},
  {DDP_AEP, "AppleTalk Echo Protocol packet"},
  {DDP_RTMPREQ, "AppleTalk Routing Table request"},
  {DDP_ZIP, "AppleTalk Zone Information Protocol packet"},
  {DDP_ADSP, "AppleTalk Data Stream Protocol"},
  {DDP_EIGRP, "Cisco EIGRP for AppleTalk"},
  {0, NULL}
};

static const value_string rtmp_function_vals[] = {
  {1, "Request"},
  {2, "Route Data Request (split horizon processed)"},
  {3, "Route Data Request (no split horizon processing)"},
  {0, NULL}
};

#define NBP_LOOKUP 2
#define NBP_FORWARD 4
#define NBP_REPLY 3

static const value_string nbp_op_vals[] = {
  {NBP_LOOKUP, "lookup"},
  {NBP_FORWARD, "forward request"},
  {NBP_REPLY, "reply"},
  {0, NULL}
};

/*
 * XXX - do this with an FT_UINT_STRING?
 * Unfortunately, you can't extract from an FT_UINT_STRING the string,
 * which we'd want to do in order to put it into the "Data:" portion.
 */
int dissect_pascal_string(tvbuff_t *tvb, int offset, proto_tree *tree,
	int hf_index)
{
	int len;
	
	len = tvb_get_guint8(tvb, offset);
	offset++;

	if ( tree )
	{
		char *tmp;
		proto_tree *item;
		proto_tree *subtree;
		
		/*
		 * XXX - if we could do this inside the protocol tree
		 * code, we could perhaps avoid allocating and freeing
		 * this string buffer.
		 */
		tmp = g_malloc( len+1 );
		tvb_memcpy(tvb, tmp, offset, len);
		tmp[len] = 0;
		item = proto_tree_add_string(tree, hf_index, tvb, offset-1, len+1, tmp);

		subtree = proto_item_add_subtree(item, ett_pstring);
		proto_tree_add_text(subtree, tvb, offset-1, 1, "Length: %d", len);
		proto_tree_add_text(subtree, tvb, offset, len, "Data: %s", tmp);
		
		g_free(tmp);
	}
	offset += len;
	
	return offset;	
}

static void
dissect_rtmp_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  proto_tree *rtmp_tree;
  proto_item *ti;
  guint8 function;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTMP");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  function = tvb_get_guint8(tvb, 0);

  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
	val_to_str(function, rtmp_function_vals, "Unknown function (%02)"));
  
  if (tree) {
    ti = proto_tree_add_item(tree, proto_rtmp, tvb, 0, 1, FALSE);
    rtmp_tree = proto_item_add_subtree(ti, ett_rtmp);

    proto_tree_add_uint(rtmp_tree, hf_rtmp_function, tvb, 0, 1, function);
  }
}

static void
dissect_rtmp_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  proto_tree *rtmp_tree;
  proto_item *ti;
  int offset = 0;
  guint16 net;
  guint8 nodelen,nodelen_bits;
  guint16 node; /* might be more than 8 bits */
  int i;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTMP");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  net = tvb_get_ntohs(tvb, offset);
  nodelen_bits = tvb_get_guint8(tvb, offset+2);
  if ( nodelen_bits <= 8 ) {
    node = tvb_get_guint8(tvb, offset)+1;
    nodelen = 1;
  } else {
    node = tvb_get_ntohs(tvb, offset);
    nodelen = 2;
  }
  
  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_fstr(pinfo->cinfo, COL_INFO, "Net: %u  Node Len: %u  Node: %u",
		net, nodelen_bits, node);
  
  if (tree) {
    ti = proto_tree_add_item(tree, proto_rtmp, tvb, offset, -1, FALSE);
    rtmp_tree = proto_item_add_subtree(ti, ett_rtmp);

    proto_tree_add_uint(rtmp_tree, hf_rtmp_net, tvb, offset, 2, net);
    proto_tree_add_uint(rtmp_tree, hf_rtmp_node_len, tvb, offset+2, 1,
			nodelen_bits);
    proto_tree_add_uint(rtmp_tree, hf_rtmp_node, tvb, offset+3, nodelen,
			node);
    offset += 3 + nodelen;

    i = 1;
    while (tvb_offset_exists(tvb, offset)) {
      proto_tree *tuple_item, *tuple_tree;
      guint16 tuple_net;
      guint8 tuple_dist;
      guint16 tuple_range_end;

      tuple_net = tvb_get_ntohs(tvb, offset);
      tuple_dist = tvb_get_guint8(tvb, offset+2);

      if (tuple_dist & 0x80) {
        tuple_range_end = tvb_get_ntohs(tvb, offset+3);
        tuple_item = proto_tree_add_text(rtmp_tree, tvb, offset, 6,
			"Tuple %d:  Range Start: %u  Dist: %u  Range End: %u",
			i, tuple_net, tuple_dist&0x7F, tuple_range_end);
      } else {
        tuple_item = proto_tree_add_text(rtmp_tree, tvb, offset, 3,
			"Tuple %d:  Net: %u  Dist: %u",
			i, tuple_net, tuple_dist);
      }
      tuple_tree = proto_item_add_subtree(tuple_item, ett_rtmp_tuple);

      if (tuple_dist & 0x80) {
        proto_tree_add_uint(tuple_tree, hf_rtmp_tuple_range_start, tvb, offset, 2, 
			tuple_net);
      } else {
        proto_tree_add_uint(tuple_tree, hf_rtmp_tuple_net, tvb, offset, 2, 
			tuple_net);
      }
      proto_tree_add_uint(tuple_tree, hf_rtmp_tuple_dist, tvb, offset+2, 1,
			tuple_dist & 0x7F);

      if (tuple_dist & 0x80) {
        /*
         * Extended network tuple.
         */
        proto_tree_add_item(tuple_tree, hf_rtmp_tuple_range_end, tvb, offset+3, 2, 
				FALSE);
	offset += 6;
      } else
        offset += 3;

      i++;
    }
  }
}

static void
dissect_nbp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  proto_tree *nbp_tree;
  proto_tree *nbp_info_tree;
  proto_item *ti, *info_item;
  int offset = 0;
  guint8 info;
  guint op, count;
  unsigned int i;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NBP");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  info = tvb_get_guint8(tvb, offset);
  op = info >> 4;
  count = info & 0x0F;

  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_fstr(pinfo->cinfo, COL_INFO, "Op: %s  Count: %u",
      val_to_str(op, nbp_op_vals, "Unknown (0x%01x)"), count);
  
  if (tree) {
    ti = proto_tree_add_item(tree, proto_nbp, tvb, offset, -1, FALSE);
    nbp_tree = proto_item_add_subtree(ti, ett_nbp);

    info_item = proto_tree_add_uint_format(nbp_tree, hf_nbp_info, tvb, offset, 1,
		info,
		"Info: 0x%01X  Operation: %s  Count: %u", info,
		val_to_str(op, nbp_op_vals, "Unknown (0x%01X)"),
		count);
    nbp_info_tree = proto_item_add_subtree(info_item, ett_nbp_info);
    proto_tree_add_uint(nbp_info_tree, hf_nbp_op, tvb, offset, 1, info);
    proto_tree_add_uint(nbp_info_tree, hf_nbp_count, tvb, offset, 1, info);
    proto_tree_add_item(nbp_tree, hf_nbp_tid, tvb, offset+1, 1, FALSE);
    offset += 2;

    for (i=0; i<count; i++) {
      proto_tree *node_item,*node_tree;
      int soffset = offset;

      node_item = proto_tree_add_text(nbp_tree, tvb, offset, -1, 
			"Node %d", i+1);
      node_tree = proto_item_add_subtree(node_item, ett_nbp_node);

      proto_tree_add_item(node_tree, hf_nbp_node_net, tvb, offset, 2, FALSE);
      offset += 2;
      proto_tree_add_item(node_tree, hf_nbp_node_node, tvb, offset, 1, FALSE);
      offset++;
      proto_tree_add_item(node_tree, hf_nbp_node_port, tvb, offset, 1, FALSE);
      offset++;
      proto_tree_add_item(node_tree, hf_nbp_node_enum, tvb, offset, 1, FALSE);
      offset++;

      offset = dissect_pascal_string(tvb, offset, node_tree, hf_nbp_node_object);
      offset = dissect_pascal_string(tvb, offset, node_tree, hf_nbp_node_type);
      offset = dissect_pascal_string(tvb, offset, node_tree, hf_nbp_node_zone);

      proto_item_set_len(node_item, offset-soffset);
    }
  }

  return;
}

static void
dissect_ddp_short(tvbuff_t *tvb, packet_info *pinfo, guint8 dnode,
		  guint8 snode, proto_tree *tree)
{
  guint16 len;
  guint8  dport;
  guint8  sport;
  guint8  type;
  proto_tree *ddp_tree = NULL;
  proto_item *ti;
  static struct atalk_ddp_addr src, dst;
  tvbuff_t   *new_tvb;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DDP");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_ddp, tvb, 0, DDP_SHORT_HEADER_SIZE,
			     FALSE);
    ddp_tree = proto_item_add_subtree(ti, ett_ddp);
  }
  len = tvb_get_ntohs(tvb, 0);
  if (tree)
      proto_tree_add_uint(ddp_tree, hf_ddp_len, tvb, 0, 2, len);
  dport = tvb_get_guint8(tvb, 2);
  if (tree)
    proto_tree_add_uint(ddp_tree, hf_ddp_dst_socket, tvb, 2, 1, dport);
  sport = tvb_get_guint8(tvb, 3);
  if (tree)
    proto_tree_add_uint(ddp_tree, hf_ddp_src_socket, tvb, 3, 1, sport);
  type = tvb_get_guint8(tvb, 4);
  
  src.net = 0;
  src.node = snode;
  src.port = sport;
  dst.net = 0;
  dst.node = dnode;
  dst.port = dport;
  SET_ADDRESS(&pinfo->net_src, AT_ATALK, sizeof src, (guint8 *)&src);
  SET_ADDRESS(&pinfo->src, AT_ATALK, sizeof src, (guint8 *)&src);
  SET_ADDRESS(&pinfo->net_dst, AT_ATALK, sizeof dst, (guint8 *)&dst);
  SET_ADDRESS(&pinfo->dst, AT_ATALK, sizeof dst, (guint8 *)&dst);

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_str(pinfo->cinfo, COL_INFO,
      val_to_str(type, op_vals, "Unknown DDP protocol (%02x)"));
  }
  if (tree)
    proto_tree_add_uint(ddp_tree, hf_ddp_type, tvb, 4, 1, type);
  
  new_tvb = tvb_new_subset(tvb, DDP_SHORT_HEADER_SIZE, -1, -1);

  if (!dissector_try_port(ddp_dissector_table, type, new_tvb, pinfo, tree))
    call_dissector(data_handle,new_tvb, pinfo, tree);
}

static void
dissect_ddp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  e_ddp       ddp;
  proto_tree *ddp_tree;
  proto_item *ti;
  static struct atalk_ddp_addr src, dst;
  tvbuff_t   *new_tvb;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DDP");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  tvb_memcpy(tvb, (guint8 *)&ddp, 0, sizeof(e_ddp));
  ddp.dnet=ntohs(ddp.dnet);
  ddp.snet=ntohs(ddp.snet);
  ddp.sum=ntohs(ddp.sum);
  ddp.hops_len=ntohs(ddp.hops_len);
  
  src.net = ddp.snet;
  src.node = ddp.snode;
  src.port = ddp.sport;
  dst.net = ddp.dnet;
  dst.node = ddp.dnode;
  dst.port = ddp.dport;
  SET_ADDRESS(&pinfo->net_src, AT_ATALK, sizeof src, (guint8 *)&src);
  SET_ADDRESS(&pinfo->src, AT_ATALK, sizeof src, (guint8 *)&src);
  SET_ADDRESS(&pinfo->net_dst, AT_ATALK, sizeof dst, (guint8 *)&dst);
  SET_ADDRESS(&pinfo->dst, AT_ATALK, sizeof dst, (guint8 *)&dst);

  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_str(pinfo->cinfo, COL_INFO,
      val_to_str(ddp.type, op_vals, "Unknown DDP protocol (%02x)"));
  
  if (tree) {
    ti = proto_tree_add_item(tree, proto_ddp, tvb, 0, DDP_HEADER_SIZE,
			     FALSE);
    ddp_tree = proto_item_add_subtree(ti, ett_ddp);
    proto_tree_add_uint(ddp_tree, hf_ddp_hopcount,   tvb, 0, 1,
			ddp_hops(ddp.hops_len));
    proto_tree_add_uint(ddp_tree, hf_ddp_len,        tvb, 0, 2, 
			ddp_len(ddp.hops_len));
    proto_tree_add_uint(ddp_tree, hf_ddp_checksum,   tvb, 2,  2,
			ddp.sum);
    proto_tree_add_uint(ddp_tree, hf_ddp_dst_net,    tvb, 4,  2,
			ddp.dnet);
    proto_tree_add_uint(ddp_tree, hf_ddp_src_net,    tvb, 6,  2,
			ddp.snet);
    proto_tree_add_uint(ddp_tree, hf_ddp_dst_node,   tvb, 8,  1,
			ddp.dnode);
    proto_tree_add_uint(ddp_tree, hf_ddp_src_node,   tvb, 9,  1,
			ddp.snode);
    proto_tree_add_uint(ddp_tree, hf_ddp_dst_socket, tvb, 10, 1,
			ddp.dport);
    proto_tree_add_uint(ddp_tree, hf_ddp_src_socket, tvb, 11, 1,
			ddp.sport);
    proto_tree_add_uint(ddp_tree, hf_ddp_type,       tvb, 12, 1,
			ddp.type);  
  }

  new_tvb = tvb_new_subset(tvb, DDP_HEADER_SIZE, -1, -1);

  if (!dissector_try_port(ddp_dissector_table, ddp.type, new_tvb, pinfo, tree))
    call_dissector(data_handle,new_tvb, pinfo, tree);
}

static const value_string llap_type_vals[] = {
  {0x01, "Short DDP"},
  {0x02, "DDP" },
  {0x81, "Enquiry"},
  {0x82, "Acknowledgement"},
  {0x84, "RTS"},
  {0x85, "CTS"},
  {0, NULL}
};

void
capture_llap(const u_char *pd, int len, packet_counts *ld)
{
  ld->other++;
}

static void
dissect_llap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint8 dnode;
  guint8 snode;
  guint8 type;
  proto_tree *llap_tree = NULL;
  proto_item *ti;
  tvbuff_t   *new_tvb;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LLAP");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_llap, tvb, 0, 3, FALSE);
    llap_tree = proto_item_add_subtree(ti, ett_llap);
  }

  dnode = tvb_get_guint8(tvb, 0);
  if (tree)  
    proto_tree_add_uint(llap_tree, hf_llap_dst, tvb, 0, 1, dnode);
  snode = tvb_get_guint8(tvb, 1);
  if (tree)
    proto_tree_add_uint(llap_tree, hf_llap_src, tvb, 1, 1, snode);
  type = tvb_get_guint8(tvb, 2);
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_str(pinfo->cinfo, COL_INFO,
      val_to_str(type, llap_type_vals, "Unknown LLAP type (%02x)"));
  }
  if (tree)
    proto_tree_add_uint(llap_tree, hf_llap_type, tvb, 2, 1, type);
  
  new_tvb = tvb_new_subset(tvb, 3, -1, -1);

  if (proto_is_protocol_enabled(proto_ddp)) {
    pinfo->current_proto = "DDP";
    switch (type) {

    case 0x01:
      dissect_ddp_short(new_tvb, pinfo, dnode, snode, tree);
      return;

    case 0x02:
      dissect_ddp(new_tvb, pinfo, tree);
      return;
    }
  }
  call_dissector(data_handle,new_tvb, pinfo, tree);
}

void
proto_register_atalk(void)
{
  static hf_register_info hf_llap[] = {
    { &hf_llap_dst,
      { "Destination Node",	"llap.dst",	FT_UINT8,  BASE_DEC, NULL, 0x0,
      	"", HFILL }},

    { &hf_llap_src,
      { "Source Node",		"llap.src",	FT_UINT8,  BASE_DEC, NULL, 0x0,
      	"", HFILL }},

    { &hf_llap_type,
      { "Type",			"llap.type",	FT_UINT8,  BASE_HEX, VALS(llap_type_vals), 0x0,
      	"", HFILL }},
  };

  static hf_register_info hf_ddp[] = {
    { &hf_ddp_hopcount,
      { "Hop count",		"ddp.hopcount",	FT_UINT8,  BASE_DEC, NULL, 0x0,
      	"", HFILL }},

    { &hf_ddp_len,
      { "Datagram length",	"ddp.len",	FT_UINT16, BASE_DEC, NULL, 0x0,
      	"", HFILL }},

    { &hf_ddp_checksum,
      { "Checksum",		"ddp.checksum",	FT_UINT16, BASE_DEC, NULL, 0x0,
      	"", HFILL }},

    { &hf_ddp_dst_net,
      { "Destination Net",	"ddp.dst.net",	FT_UINT16, BASE_DEC, NULL, 0x0,
      	"", HFILL }},

    { &hf_ddp_src_net,
      { "Source Net",		"ddp.src.net",	FT_UINT16, BASE_DEC, NULL, 0x0,
      	"", HFILL }},

    { &hf_ddp_dst_node,
      { "Destination Node",	"ddp.dst.node",	FT_UINT8,  BASE_DEC, NULL, 0x0,
      	"", HFILL }},

    { &hf_ddp_src_node,
      { "Source Node",		"ddp.src.node",	FT_UINT8,  BASE_DEC, NULL, 0x0,
      	"", HFILL }},

    { &hf_ddp_dst_socket,
      { "Destination Socket",	"ddp.dst.socket", FT_UINT8,  BASE_DEC, NULL, 0x0,
      	"", HFILL }},

    { &hf_ddp_src_socket,
      { "Source Socket",       	"ddp.src.socket", FT_UINT8,  BASE_DEC, NULL, 0x0,
      	"", HFILL }},

    { &hf_ddp_type,
      { "Protocol type",       	"ddp.type",	FT_UINT8,  BASE_DEC, VALS(op_vals), 0x0,
      	"", HFILL }},
  };

  static hf_register_info hf_nbp[] = {
    { &hf_nbp_op,
      { "Operation",		"nbp.op",	FT_UINT8,  BASE_DEC, 
		VALS(nbp_op_vals), 0xF0, "Operation", HFILL }},
    { &hf_nbp_info,
      { "Info",		"nbp.info",	FT_UINT8,  BASE_HEX, 
		NULL, 0x0, "Info", HFILL }},
    { &hf_nbp_count,
      { "Count",		"nbp.count",	FT_UINT8,  BASE_DEC, 
		NULL, 0x0F, "Count", HFILL }},
    { &hf_nbp_node_net,
      { "Network",		"nbp.net",	FT_UINT16,  BASE_DEC, 
		NULL, 0x0, "Network", HFILL }},
    { &hf_nbp_node_node,
      { "Node",		"nbp.node",	FT_UINT8,  BASE_DEC, 
		NULL, 0x0, "Node", HFILL }},
    { &hf_nbp_node_port,
      { "Port",		"nbp.port",	FT_UINT8,  BASE_DEC, 
		NULL, 0x0, "Port", HFILL }},
    { &hf_nbp_node_enum,
      { "Enumerator",		"nbp.enum",	FT_UINT8,  BASE_DEC, 
		NULL, 0x0, "Enumerator", HFILL }},
    { &hf_nbp_node_object,
      { "Object",		"nbp.object",	FT_STRING,  BASE_DEC, 
		NULL, 0x0, "Object", HFILL }},
    { &hf_nbp_node_type,
      { "Type",		"nbp.type",	FT_STRING,  BASE_DEC, 
		NULL, 0x0, "Type", HFILL }},
    { &hf_nbp_node_zone,
      { "Zone",		"nbp.zone",	FT_STRING,  BASE_DEC, 
		NULL, 0x0, "Zone", HFILL }},
    { &hf_nbp_tid,
      { "Transaction ID",		"nbp.tid",	FT_UINT8,  BASE_DEC, 
		NULL, 0x0, "Transaction ID", HFILL }}
  };

  static hf_register_info hf_rtmp[] = {
    { &hf_rtmp_net,
      { "Net",		"rtmp.net",	FT_UINT16,  BASE_DEC, 
		NULL, 0x0, "Net", HFILL }},
    { &hf_rtmp_node,
      { "Node",		"nbp.nodeid",	FT_UINT8,  BASE_DEC, 
		NULL, 0x0, "Node", HFILL }},
    { &hf_rtmp_node_len,
      { "Node Length",		"nbp.nodeid.length",	FT_UINT8,  BASE_DEC, 
		NULL, 0x0, "Node Length", HFILL }},
    { &hf_rtmp_tuple_net,
      { "Net",		"rtmp.tuple.net",	FT_UINT16,  BASE_DEC, 
		NULL, 0x0, "Net", HFILL }},
    { &hf_rtmp_tuple_range_start,
      { "Range Start",		"rtmp.tuple.range_start",	FT_UINT16,  BASE_DEC, 
		NULL, 0x0, "Range Start", HFILL }},
    { &hf_rtmp_tuple_range_end,
      { "Range End",		"rtmp.tuple.range_end",	FT_UINT16,  BASE_DEC, 
		NULL, 0x0, "Range End", HFILL }},
    { &hf_rtmp_tuple_dist,
      { "Distance",		"rtmp.tuple.dist",	FT_UINT16,  BASE_DEC, 
		NULL, 0x0, "Distance", HFILL }},
    { &hf_rtmp_function,
      { "Function",		"rtmp.function",	FT_UINT8,  BASE_DEC, 
		VALS(rtmp_function_vals), 0x0, "Request Function", HFILL }}
  };


  static gint *ett[] = {
  	&ett_llap,
	&ett_ddp,
	&ett_nbp,
	&ett_nbp_info,
	&ett_nbp_node,
	&ett_pstring,
	&ett_rtmp,
	&ett_rtmp_tuple
  };

  proto_llap = proto_register_protocol("LocalTalk Link Access Protocol", "LLAP", "llap");
  proto_register_field_array(proto_llap, hf_llap, array_length(hf_llap));

  proto_ddp = proto_register_protocol("Datagram Delivery Protocol", "DDP", "ddp");
  proto_register_field_array(proto_ddp, hf_ddp, array_length(hf_ddp));

  proto_nbp = proto_register_protocol("Name Binding Protocol", "NBP", "nbp");
  proto_register_field_array(proto_nbp, hf_nbp, array_length(hf_nbp));

  proto_rtmp = proto_register_protocol("Routing Table Maintenance Protocol",
				       "RTMP", "rtmp");
  proto_register_field_array(proto_rtmp, hf_rtmp, array_length(hf_rtmp));

  proto_register_subtree_array(ett, array_length(ett));

  /* subdissector code */
  ddp_dissector_table = register_dissector_table("ddp.type", "DDP packet type",
						 FT_UINT8, BASE_HEX);
}

void
proto_reg_handoff_atalk(void)
{
  dissector_handle_t ddp_handle, nbp_handle, rtmp_request_handle;
  dissector_handle_t rtmp_data_handle, llap_handle;

  ddp_handle = create_dissector_handle(dissect_ddp, proto_ddp);
  dissector_add("ethertype", ETHERTYPE_ATALK, ddp_handle);
  dissector_add("chdlctype", ETHERTYPE_ATALK, ddp_handle);
  dissector_add("ppp.protocol", PPP_AT, ddp_handle);
  dissector_add("null.type", BSD_AF_APPLETALK, ddp_handle);

  nbp_handle = create_dissector_handle(dissect_nbp, proto_nbp);
  dissector_add("ddp.type", DDP_NBP, nbp_handle);

  rtmp_request_handle = create_dissector_handle(dissect_rtmp_request, proto_rtmp);
  rtmp_data_handle = create_dissector_handle(dissect_rtmp_data, proto_rtmp);
  dissector_add("ddp.type", DDP_RTMPREQ, rtmp_request_handle);
  dissector_add("ddp.type", DDP_RTMPDATA, rtmp_data_handle);

  llap_handle = create_dissector_handle(dissect_llap, proto_llap);
  dissector_add("wtap_encap", WTAP_ENCAP_LOCALTALK, llap_handle);

  data_handle = find_dissector("data");
}
