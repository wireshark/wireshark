/* packet-ddp.c
 * Routines for DDP packet disassembly.
 *
 * $Id: packet-atalk.c,v 1.15 1999/10/12 06:20:02 gram Exp $
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

#include <glib.h>
#include "globals.h"
#include "packet.h"

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

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

#define DDP_RTMPDATA	0x01
#define DDP_NBP		0x02
#define DDP_ATP		0x03
#define DDP_AEP		0x04
#define DDP_RTMPREQ	0x05
#define DDP_ZIP		0x06
#define DDP_ADSP	0x07
#define DDP_HEADER_SIZE 13

void
dissect_ddp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  e_ddp       ddp;
  proto_tree *ddp_tree;
  proto_item *ti;
  value_string op_vals[] = { {DDP_RTMPDATA, "AppleTalk Routing Table response or data" },
  			     {DDP_NBP, "AppleTalk Name Binding Protocol packet"},
  			     {DDP_ATP, "AppleTalk Transaction Protocol packet"},
  			     {DDP_AEP, "AppleTalk Echo Protocol packet"},
  			     {DDP_RTMPREQ, "AppleTalk Routing Table request"},
  			     {DDP_ZIP, "AppleTalk Zone Information Protocol packet"},
  			     {DDP_ADSP, "AppleTalk Data Stream Protocol"},
                             {0, NULL} };

  if (!BYTES_ARE_IN_FRAME(offset, DDP_HEADER_SIZE)) {
    dissect_data(pd, offset, fd, tree);
    return;
  }

  memcpy(&ddp, &pd[offset], sizeof(e_ddp));
  ddp.dnet=ntohs(ddp.dnet);
  ddp.snet=ntohs(ddp.snet);
  ddp.sum=ntohs(ddp.sum);
  
  if (check_col(fd, COL_RES_NET_SRC))
    col_add_fstr(fd, COL_RES_NET_SRC, "%d.%d:%d", ddp.snet, ddp.snode, ddp.sport);
  if (check_col(fd, COL_RES_NET_DST))
    col_add_fstr(fd, COL_RES_NET_DST, "%d.%d:%d", ddp.dnet, ddp.dnode, ddp.dport);
  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "DDP");
  if (check_col(fd, COL_INFO))
    col_add_str(fd, COL_INFO,
      val_to_str(ddp.type, op_vals, "Unknown DDP protocol (%02x)"));
  
  if (tree) {
    ti = proto_tree_add_item(tree, proto_ddp, offset, DDP_HEADER_SIZE, NULL);
    ddp_tree = proto_item_add_subtree(ti, ETT_IP);
    proto_tree_add_item(ddp_tree, hf_ddp_hopcount, offset,      1, 
			ddp_hops(ddp.hops_len));
    proto_tree_add_item(ddp_tree, hf_ddp_len, offset,	    2, 
			ddp_len(ddp.hops_len));
    proto_tree_add_item(ddp_tree, hf_ddp_checksum, offset + 2,  2, ddp.sum);
    proto_tree_add_item(ddp_tree, hf_ddp_dst_net, offset + 4,  2, ddp.dnet);
    proto_tree_add_item(ddp_tree, hf_ddp_src_net,  offset + 6,  2, ddp.snet);
    proto_tree_add_item(ddp_tree, hf_ddp_dst_node, offset + 8,  1, ddp.dnode);
    proto_tree_add_item(ddp_tree, hf_ddp_src_node, offset + 9,  1, ddp.snode);
    proto_tree_add_item(ddp_tree, hf_ddp_dst_socket, offset + 10, 1, ddp.dport);
    proto_tree_add_item(ddp_tree, hf_ddp_src_socket, offset + 11, 1, ddp.sport);
    proto_tree_add_item(ddp_tree, hf_ddp_type, offset + 12, 1, ddp.type);  
  }

  offset += DDP_HEADER_SIZE;

}

void
proto_register_atalk(void)
{
  static hf_register_info hf[] = {
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
      { "Protocol type",       	"ddp.type",	FT_UINT8,  BASE_DEC, NULL, 0x0,
      	"" }},
  };

  proto_ddp = proto_register_protocol("Datagram Delivery Protocol", "ddp");
  proto_register_field_array(proto_ddp, hf, array_length(hf));
}
