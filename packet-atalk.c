/* packet-atalk.c
 * Routines for Appletalk packet disassembly (DDP, currently).
 *
 * $Id: packet-atalk.c,v 1.37 2000/05/30 03:35:51 guy Exp $
 *
 * Simon Wilkinson <sxw@dcs.ed.ac.uk>
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
#include "packet-atalk.h"
#include "etypes.h"
#include "ppptypes.h"

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
static int hf_rtmp_tuple_net = -1;
static int hf_rtmp_tuple_dist = -1;
static int hf_rtmp_net = -1;
static int hf_rtmp_node_len = -1;
static int hf_rtmp_node = -1;

static gint ett_nbp = -1;
static gint ett_nbp_info = -1;
static gint ett_nbp_node = -1;
static gint ett_rtmp = -1;
static gint ett_rtmp_tuple = -1;
static gint ett_ddp = -1;
static gint ett_pstring = -1;

static dissector_table_t ddp_dissector_table;

/* P = Padding, H = Hops, L = Len */
#if BYTE_ORDER == BIG_ENDIAN
 /* PPHHHHLL LLLLLLLL */
# define ddp_hops(x)	( ( x >> 10) & 0x3C )
# define ddp_len(x)		( x & 0x03ff )
#else
 /* LLLLLLLL PPHHHHLL*/
# define ddp_hops(x)	( x & 0x3C )
# define ddp_len(x)		( ntohs(x) & 0x03ff )
#endif
typedef struct _e_ddp {
  guint16	hops_len; /* combines pad, hops, and len */
  guint16	sum,dnet,snet;
  guint8	dnode,snode;
  guint8	dport,sport;
  guint8	type;
} e_ddp;

#define DDP_HEADER_SIZE 13

gchar *
atalk_addr_to_str(const struct atalk_ddp_addr *addrp)
{
  static gchar	str[3][14];
  static gchar	*cur;

  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {
    cur = &str[2][0];
  } else {
    cur = &str[0][0];
  }

  sprintf(cur, "%u.%u:%u", addrp->net, addrp->node, addrp->port);
  return cur;
}

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

#define NBP_LOOKUP 2
#define NBP_FORWARD 4
#define NBP_REPLY 3

static const value_string nbp_op_vals[] = {
  {NBP_LOOKUP, "lookup"},
  {NBP_FORWARD, "forward request"},
  {NBP_REPLY, "reply"},
  {0, NULL}
};

int dissect_pascal_string(const u_char *pd, int offset, frame_data *fd, 
	proto_tree *tree, int hf_index)
{
	int len;
	
	if ( ! BYTES_ARE_IN_FRAME(offset,1) ) {
		dissect_data(pd,offset,fd,tree);
		return END_OF_FRAME;
	}
		
	len = pd[offset];
	if ( ! BYTES_ARE_IN_FRAME(offset,len) ) {
		dissect_data(pd,offset,fd,tree);
		return END_OF_FRAME;
	}
	offset++;

	if ( tree )
	{
		char *tmp;
		proto_tree *item;
		proto_tree *subtree;
		
		tmp = g_malloc( len+1 );
		memcpy(tmp, &pd[offset], len);
		tmp[len] = 0;
		item = proto_tree_add_item(tree, hf_index, NullTVB, offset-1, len+1, tmp);

		subtree = proto_item_add_subtree(item, ett_pstring);
		proto_tree_add_text(subtree, NullTVB, offset-1, 1, "Length: %d", len);
		proto_tree_add_text(subtree, NullTVB, offset, len, "Data: %s", tmp);
		
		g_free(tmp);
	}
	offset += len;
	
	return offset;	
}

static void
dissect_rtmp_request(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  dissect_data(pd, offset, fd, tree);
  return;
}

static void
dissect_rtmp_data(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  proto_tree *rtmp_tree;
  proto_item *ti;
  guint16 net;
  guint8 nodelen,nodelen_bits;
  guint16 node; /* might be more than 8 bits */
  int i;

  if (!BYTES_ARE_IN_FRAME(offset, 3)) {
    dissect_data(pd, offset, fd, tree);
    return;
  }

  net = pntohs(&pd[offset]);
  nodelen_bits = pd[offset+2];
  if ( nodelen_bits <= 8 ) {
  	node = pd[offset]+1;
	nodelen = 1;
  } else {
    node = pntohs(&pd[offset]);
	nodelen = 2;
  }
  
  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "RTMP");

  if (check_col(fd, COL_INFO))
    col_add_fstr(fd, COL_INFO, "Net: %d  Node Len: %d  Node: %d",
		net, nodelen_bits, node);
  
  if (tree) {
    ti = proto_tree_add_item(tree, proto_rtmp, NullTVB, offset, END_OF_FRAME, NULL);
    rtmp_tree = proto_item_add_subtree(ti, ett_rtmp);

	proto_tree_add_item(rtmp_tree, hf_rtmp_net, NullTVB, offset, 2, net);
	proto_tree_add_item(rtmp_tree, hf_rtmp_node_len, NullTVB, offset+2, 1, nodelen_bits);
	proto_tree_add_item(rtmp_tree, hf_rtmp_node, NullTVB, offset+3, nodelen, nodelen);
    offset += 3 + nodelen;

    i = 1;
	while ( BYTES_ARE_IN_FRAME(offset, 1) )
	{
		proto_tree *tuple_item, *tuple_tree;
		guint16 tuple_net, tuple_net2;
		guint8 tuple_dist, tuple_dist2;

		if ( ! BYTES_ARE_IN_FRAME(offset, 3) )
		{
			dissect_data(pd,offset,fd,rtmp_tree);
			return;
		}

		tuple_net = pntohs(&pd[offset]);
		tuple_dist = pd[offset+2];

		tuple_item = proto_tree_add_text(rtmp_tree, NullTVB, offset, 3, 
			"Tuple %d:  Net: %d  Dist: %d",
			i, tuple_net, tuple_dist);
		tuple_tree = proto_item_add_subtree(tuple_item, ett_rtmp_tuple);

		proto_tree_add_item(tuple_tree, hf_rtmp_tuple_net, NullTVB, offset, 2, 
			tuple_net);
		proto_tree_add_item(tuple_tree, hf_rtmp_tuple_dist, NullTVB, offset+2, 1,
			tuple_dist);

		if ( tuple_dist == 0 || tuple_dist & 0x80 ) /* phase 1/2 */
		{
			if ( ! BYTES_ARE_IN_FRAME(offset+3, 3) )
			{
				dissect_data(pd,offset,fd,rtmp_tree);
				return;
			}

			tuple_net2 = pntohs(&pd[offset+3]);
			tuple_dist2 = pd[offset+5];

			proto_tree_add_item(tuple_tree, hf_rtmp_tuple_net, NullTVB, offset, 2, 
				tuple_net2);
			proto_tree_add_item(tuple_tree, hf_rtmp_tuple_dist, NullTVB, offset+2, 1,
				tuple_dist2);
				
			proto_item_set_len(tuple_item, 6);
			offset += 6;
		}
		else /* screwy gatorbox/etc. */
		{
			offset += 3;
		}

		i++;
	}
  }

  return;
}

static void
dissect_nbp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  proto_tree *nbp_tree;
  proto_tree *nbp_info_tree;
  proto_item *ti, *info_item;
  guint op, count;
  int i;

  if (!BYTES_ARE_IN_FRAME(offset, 2)) {
    dissect_data(pd, offset, fd, tree);
    return;
  }

  op = pd[offset] >> 4;
  count = pd[offset] & 0x0F;

  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "NBP");

  if (check_col(fd, COL_INFO))
    col_add_fstr(fd, COL_INFO, "Op: %s  Count: %d",
      val_to_str(op, nbp_op_vals, "unknown (%1x)"), count);
  
  if (tree) {
    ti = proto_tree_add_item(tree, proto_nbp, NullTVB, offset, END_OF_FRAME, NULL);
    nbp_tree = proto_item_add_subtree(ti, ett_nbp);

    info_item = proto_tree_add_uint_format(nbp_tree, hf_nbp_info, NullTVB, offset, 1,
		pd[offset], 
		"Info: 0x%01X  Operation: %s  Count: %d", pd[offset],
		val_to_str(op, nbp_op_vals, "unknown"),
		count);
	nbp_info_tree = proto_item_add_subtree(info_item, ett_nbp_info);
    proto_tree_add_item(nbp_info_tree, hf_nbp_op, NullTVB, offset, 1, pd[offset]);
    proto_tree_add_item(nbp_info_tree, hf_nbp_count, NullTVB, offset, 1, pd[offset]);
    proto_tree_add_item(nbp_tree, hf_nbp_tid, NullTVB, offset+1, 1, pd[offset+1]);
	offset += 2;

    for (i=0; i<count; i++) {
		struct atalk_ddp_addr addr;
		proto_tree *node_item,*node_tree;
		int soffset = offset;

		if ( !BYTES_ARE_IN_FRAME(offset, 6) ) {
			dissect_data(pd,offset,fd,nbp_tree);
			return;
		}

		node_item = proto_tree_add_text(nbp_tree, NullTVB, offset, 4, 
			"Node %d", i+1);
		node_tree = proto_item_add_subtree(node_item, ett_nbp_node);

		addr.net = pntohs(&pd[offset]);
		addr.node = pd[offset+2];
		addr.port = pd[offset+3];

		/* note, this is probably wrong, I need to look at my info at work
			tomorrow to straighten it out */

		proto_tree_add_item(node_tree, hf_nbp_node_net, NullTVB, offset, 2, addr.net);
		offset += 2;
		proto_tree_add_item(node_tree, hf_nbp_node_node, NullTVB, offset, 1, addr.node);
		offset++;
		proto_tree_add_item(node_tree, hf_nbp_node_port, NullTVB, offset, 1, addr.port);
		offset++;
		proto_tree_add_item(node_tree, hf_nbp_node_enum, NullTVB, offset, 1, pd[offset]);
		offset++;

		offset = dissect_pascal_string(pd,offset,fd,node_tree,hf_nbp_node_object);
		offset = dissect_pascal_string(pd,offset,fd,node_tree,hf_nbp_node_type);
		offset = dissect_pascal_string(pd,offset,fd,node_tree,hf_nbp_node_zone);

		proto_item_set_len(node_item, offset-soffset);
	}
  }

  return;
}

void
dissect_ddp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  e_ddp       ddp;
  proto_tree *ddp_tree;
  proto_item *ti;
  static struct atalk_ddp_addr src, dst;

  if (!BYTES_ARE_IN_FRAME(offset, DDP_HEADER_SIZE)) {
    dissect_data(pd, offset, fd, tree);
    return;
  }

  memcpy(&ddp, &pd[offset], sizeof(e_ddp));
  ddp.dnet=ntohs(ddp.dnet);
  ddp.snet=ntohs(ddp.snet);
  ddp.sum=ntohs(ddp.sum);
  
  src.net = ddp.snet;
  src.node = ddp.snode;
  src.port = ddp.sport;
  dst.net = ddp.dnet;
  dst.node = ddp.dnode;
  dst.port = ddp.dport;
  SET_ADDRESS(&pi.net_src, AT_ATALK, sizeof src, (guint8 *)&src);
  SET_ADDRESS(&pi.src, AT_ATALK, sizeof src, (guint8 *)&src);
  SET_ADDRESS(&pi.net_dst, AT_ATALK, sizeof dst, (guint8 *)&dst);
  SET_ADDRESS(&pi.dst, AT_ATALK, sizeof dst, (guint8 *)&dst);

  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "DDP");
  if (check_col(fd, COL_INFO))
    col_add_str(fd, COL_INFO,
      val_to_str(ddp.type, op_vals, "Unknown DDP protocol (%02x)"));
  
  if (tree) {
    ti = proto_tree_add_item(tree, proto_ddp, NullTVB, offset, DDP_HEADER_SIZE, NULL);
    ddp_tree = proto_item_add_subtree(ti, ett_ddp);
    proto_tree_add_item(ddp_tree, hf_ddp_hopcount, NullTVB, offset,      1, 
			ddp_hops(ddp.hops_len));
    proto_tree_add_item(ddp_tree, hf_ddp_len, NullTVB, offset,	    2, 
			ddp_len(ddp.hops_len));
    proto_tree_add_item(ddp_tree, hf_ddp_checksum, NullTVB, offset + 2,  2, ddp.sum);
    proto_tree_add_item(ddp_tree, hf_ddp_dst_net, NullTVB, offset + 4,  2, ddp.dnet);
    proto_tree_add_item(ddp_tree, hf_ddp_src_net, NullTVB,  offset + 6,  2, ddp.snet);
    proto_tree_add_item(ddp_tree, hf_ddp_dst_node, NullTVB, offset + 8,  1, ddp.dnode);
    proto_tree_add_item(ddp_tree, hf_ddp_src_node, NullTVB, offset + 9,  1, ddp.snode);
    proto_tree_add_item(ddp_tree, hf_ddp_dst_socket, NullTVB, offset + 10, 1, ddp.dport);
    proto_tree_add_item(ddp_tree, hf_ddp_src_socket, NullTVB, offset + 11, 1, ddp.sport);
    proto_tree_add_item(ddp_tree, hf_ddp_type, NullTVB, offset + 12, 1, ddp.type);  
  }

  offset += DDP_HEADER_SIZE;

  if (!dissector_try_port(ddp_dissector_table, ddp.type, pd, offset, fd, tree))
    dissect_data(pd, offset, fd, tree);
}

void
proto_register_atalk(void)
{
  static hf_register_info hf_ddp[] = {
    { &hf_ddp_hopcount,
      { "Hop count",		"ddp.hopcount",	FT_UINT8,  BASE_DEC, NULL, 0x0,
      	"" }},

    { &hf_ddp_len,
      { "Datagram length",	"ddp.len",	FT_UINT16, BASE_DEC, NULL, 0x0,
      	"" }},

    { &hf_ddp_checksum,
      { "Checksum",		"ddp.checksum",	FT_UINT16, BASE_DEC, NULL, 0x0,
      	"" }},

    { &hf_ddp_dst_net,
      { "Destination Net",	"ddp.dst.net",	FT_UINT16, BASE_DEC, NULL, 0x0,
      	"" }},

    { &hf_ddp_src_net,
      { "Source Net",		"ddp.src.net",	FT_UINT16, BASE_DEC, NULL, 0x0,
      	"" }},

    { &hf_ddp_dst_node,
      { "Destination Node",	"ddp.dst.node",	FT_UINT8,  BASE_DEC, NULL, 0x0,
      	"" }},

    { &hf_ddp_src_node,
      { "Source Node",		"ddp.src.node",	FT_UINT8,  BASE_DEC, NULL, 0x0,
      	"" }},

    { &hf_ddp_dst_socket,
      { "Destination Socket",	"ddp.dst.socket", FT_UINT8,  BASE_DEC, NULL, 0x0,
      	"" }},

    { &hf_ddp_src_socket,
      { "Source Socket",       	"ddp.src.socket", FT_UINT8,  BASE_DEC, NULL, 0x0,
      	"" }},

    { &hf_ddp_type,
      { "Protocol type",       	"ddp.type",	FT_UINT8,  BASE_DEC, VALS(op_vals), 0x0,
      	"" }},
  };

  static hf_register_info hf_nbp[] = {
    { &hf_nbp_op,
      { "Operation",		"nbp.op",	FT_UINT8,  BASE_DEC, 
		VALS(nbp_op_vals), 0xF0, "Operation" }},
    { &hf_nbp_info,
      { "Info",		"nbp.info",	FT_UINT8,  BASE_HEX, 
		NULL, 0x0, "Info" }},
    { &hf_nbp_count,
      { "Count",		"nbp.count",	FT_UINT8,  BASE_DEC, 
		NULL, 0x0F, "Count" }},
    { &hf_nbp_node_net,
      { "Network",		"nbp.net",	FT_UINT16,  BASE_DEC, 
		NULL, 0x0, "Network" }},
    { &hf_nbp_node_node,
      { "Node",		"nbp.node",	FT_UINT8,  BASE_DEC, 
		NULL, 0x0, "Node" }},
    { &hf_nbp_node_port,
      { "Port",		"nbp.port",	FT_UINT8,  BASE_DEC, 
		NULL, 0x0, "Port" }},
    { &hf_nbp_node_enum,
      { "Enumerator",		"nbp.enum",	FT_UINT8,  BASE_DEC, 
		NULL, 0x0, "Enumerator" }},
    { &hf_nbp_node_object,
      { "Object",		"nbp.object",	FT_STRING,  BASE_DEC, 
		NULL, 0x0, "Object" }},
    { &hf_nbp_node_type,
      { "Type",		"nbp.type",	FT_STRING,  BASE_DEC, 
		NULL, 0x0, "Type" }},
    { &hf_nbp_node_zone,
      { "Zone",		"nbp.zone",	FT_STRING,  BASE_DEC, 
		NULL, 0x0, "Zone" }},
    { &hf_nbp_tid,
      { "Transaction ID",		"nbp.tid",	FT_UINT8,  BASE_DEC, 
		NULL, 0x0, "Transaction ID" }}
  };

  static hf_register_info hf_rtmp[] = {
    { &hf_rtmp_net,
      { "Net",		"rtmp.net",	FT_UINT16,  BASE_DEC, 
		NULL, 0x0, "Net" }},
    { &hf_rtmp_node,
      { "Node",		"nbp.nodeid",	FT_UINT8,  BASE_DEC, 
		NULL, 0x0, "Node" }},
    { &hf_rtmp_node_len,
      { "Node Length",		"nbp.nodeid.length",	FT_UINT8,  BASE_DEC, 
		NULL, 0x0, "Node Length" }},
    { &hf_rtmp_tuple_net,
      { "Net",		"rtmp.tuple.net",	FT_UINT16,  BASE_DEC, 
		NULL, 0x0, "Net" }},
    { &hf_rtmp_tuple_dist,
      { "Distance",		"rtmp.tuple.dist",	FT_UINT16,  BASE_DEC, 
		NULL, 0x0, "Distance" }}
  };


  static gint *ett[] = {
    &ett_ddp,
	&ett_nbp,
	&ett_nbp_info,
	&ett_nbp_node,
	&ett_pstring,
	&ett_rtmp,
	&ett_rtmp_tuple
  };

  proto_ddp = proto_register_protocol("Datagram Delivery Protocol", "ddp");
  proto_register_field_array(proto_ddp, hf_ddp, array_length(hf_ddp));

  proto_nbp = proto_register_protocol("Name Binding Protocol", "nbp");
  proto_register_field_array(proto_nbp, hf_nbp, array_length(hf_nbp));

  proto_rtmp = proto_register_protocol("Routing Table", "rtmp");
  proto_register_field_array(proto_rtmp, hf_rtmp, array_length(hf_rtmp));

  proto_register_subtree_array(ett, array_length(ett));

  /* subdissector code */
  ddp_dissector_table = register_dissector_table("ddp.type");
}

void
proto_reg_handoff_atalk(void)
{
  dissector_add("ethertype", ETHERTYPE_ATALK, dissect_ddp);
  dissector_add("ppp.protocol", PPP_AT, dissect_ddp);
  dissector_add("ddp.type", DDP_NBP, dissect_nbp);
  dissector_add("ddp.type", DDP_RTMPREQ, dissect_rtmp_request);
  dissector_add("ddp.type", DDP_RTMPDATA, dissect_rtmp_data);
}
