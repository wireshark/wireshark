/* packet-eigrp.c
 *
 * $Id: packet-eigrp.c,v 1.6 2000/08/13 14:08:09 deniel Exp $
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
#include "resolv.h"

#include "packet-atalk.h"
#include "packet-ip.h"
#include "packet-ipx.h"

/* EIGRP Structs and Definitions. */    

/* EIGRP Opcodes */

#define EIGRP_UPDATE    0x01
#define EIGRP_REQUEST   0x02
#define EIGRP_QUERY     0x03
#define EIGRP_REPLY     0x04
#define EIGRP_HELLO     0x05

typedef struct _e_eigrp 
   {
   guint8 eigrp_version;
   guint8 eigrp_opcode;
   guint16 eigrp_checksum;
   guint16 eigrp_subnets;
   guint16 eigrp_networks;
   guint32 eigrp_sequence;
   guint32 eigrp_asnumber;
   guint8 eigrp_type1;
   guint8 eigrp_subtype1;
   guint16 eigrp_length1;
   guint16 eigrp_holdtime;
   guint8 eigrp_type2;
   guint8 eigrp_subtype2;
   guint16 eigrp_length2;
   guint8 eigrp_level;
   guint16 eigrp_dummy;
   } e_eigrp;

static int proto_eigrp = -1;

static gint ett_eigrp = -1;

static const value_string eigrp_opcode_vals[] = {
	{ EIGRP_HELLO,		"Hello/Ack" },
	{ EIGRP_UPDATE,		"Update" },
   	{ EIGRP_REPLY, 		"Reply" },
   	{ EIGRP_QUERY, 		"Query" },
	{ EIGRP_REQUEST,	"Request" },
	{ 0,				NULL }    
};

static void
dissect_eigrp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  e_eigrp     ih;
  proto_tree *eigrp_tree;
  proto_item *ti;
  guint16    cksum;

  OLD_CHECK_DISPLAY_AS_DATA(proto_eigrp, pd, offset, fd, tree);

  /* Avoids alignment problems on many architectures. */
  memcpy(&ih, &pd[offset], sizeof(e_eigrp));
  /* To do: check for runts, errs, etc. */
  cksum = ntohs(ih.eigrp_checksum);
  
  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "EIGRP");
  if (check_col(fd, COL_INFO))
    col_add_str(fd, COL_INFO,
	val_to_str( ih.eigrp_opcode, eigrp_opcode_vals, "Unknown (0x%04x)"));
  if (tree) {

     ti = proto_tree_add_item(tree, proto_eigrp, NullTVB, offset, END_OF_FRAME, FALSE);
     eigrp_tree = proto_item_add_subtree(ti, ett_eigrp);
  
     proto_tree_add_text(eigrp_tree, NullTVB, offset, 1, "Version: %u", ih.eigrp_version); 
     proto_tree_add_text(eigrp_tree, NullTVB, offset + 1, 1, "Opcode: %u (%s)", ih.eigrp_opcode,
         val_to_str( ih.eigrp_opcode, eigrp_opcode_vals, "Unknown") );
     proto_tree_add_text(eigrp_tree, NullTVB, offset + 2, 2, "Checksum: 0x%x", cksum); 
     proto_tree_add_text(eigrp_tree, NullTVB, offset + 4, 2, "Subnets in local net: %u", ih.eigrp_subnets); 
     proto_tree_add_text(eigrp_tree, NullTVB, offset + 6, 2, "Networks in Autonomous System: %d", ih.eigrp_networks); 
     proto_tree_add_text(eigrp_tree, NullTVB, offset + 8, 4, "Sequence Number: 0x%x", ih.eigrp_sequence); 
     proto_tree_add_text(eigrp_tree, NullTVB, offset + 12, 4, "Autonomous System number: %u", ih.eigrp_asnumber); 
   }
}

void
proto_register_eigrp(void)
   {
      static gint *ett[] = {
        &ett_eigrp,
      };
   proto_eigrp = proto_register_protocol("Enhanced Interior Gateway Routing Protocol", "eigrp");
   proto_register_subtree_array(ett, array_length(ett));
   }

void
proto_reg_handoff_eigrp(void)
{
    old_dissector_add("ip.proto", IP_PROTO_EIGRP, dissect_eigrp);
    old_dissector_add("ddp.type", DDP_EIGRP, dissect_eigrp);
    old_dissector_add("ipx.socket", IPX_SOCKET_EIGRP, dissect_eigrp);
}
