/* packet-isis-clv.c
 * Common CLV decode routines.
 *
 * $Id: packet-isis-clv.c,v 1.13 2001/06/23 19:45:12 guy Exp $
 * Stuart Stanley <stuarts@mxmail.net>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include "packet.h"
#include "packet-osi.h"
#include "packet-isis.h"
#include "packet-isis-clv.h"
#include "nlpid.h"


/*
 * Name: isis_dissect_area_address_clv()
 * 
 * Description:
 *	Take an area address CLV and display it pieces.  An area address
 *	CLV is n, x byte hex strings.
 *
 * Input:
 *	u_char * : packet data
 *	int : offset into packet data where we are.
 *	guint : length of clv we are decoding
 *	frame_data * : frame data (complete frame)
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 * 
 * Output:
 *	void, but we will add to proto tree if !NULL.
 */
void 
isis_dissect_area_address_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree ) {
	char 		*sbuf;
	int		mylen;

	while ( length > 0 ) {
		mylen = pd[offset];
		length--;
		if (length<=0) {
			isis_dissect_unknown( offset, length, tree, fd,
				"short address (no length for payload)");
			return;
		}
		if ( mylen > length) {
			isis_dissect_unknown(offset, length, tree, fd, 
				"short address, packet say %d, we have %d left",
				mylen, length );
			return;
		}

		/* 
		 * Lets turn the area address into "standard" 0000.0000.etc
		 * format string.  
		 */
/*		sbuf = isis_address_to_string ( pd, offset + 1, mylen );*/
      sbuf = print_nsap_net( pd + offset + 1, mylen );
		/* and spit it out */
		if ( tree ) {
			proto_tree_add_text ( tree, NullTVB, offset, mylen + 1,  
				"Area address (%d): %s", mylen, sbuf );
		}
		offset += mylen + 1;
		length -= mylen;	/* length already adjusted for len fld*/
	}
}


/*
 * Name: isis_dissect_authentication_clv()
 * 
 * Description:
 *	Take apart the CLV that hold authentication information.  This
 *	is currently 1 octet auth type (which must be 1) and then
 *	the clear text password.
 *	
 *	An ISIS password has different meaning depending where it
 *	is found.  Thus we support a passed in prefix string to 
 *	use to name this.
 *
 * Input:
 *	u_char * : packet data
 *	int : offset into packet data where we are.
 *	guint : length of clv we are decoding
 *	frame_data * : frame data (complete frame)
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	char * : Password meaning
 * 
 * Output:
 *	void, but we will add to proto tree if !NULL.
 */
void 
isis_dissect_authentication_clv(const u_char *pd, int offset, guint length, 
		frame_data *fd, proto_tree *tree, char *meaning) {
	u_char pw_type;
	char sbuf[300];		/* 255 + header info area */
	char *s = sbuf;
	int auth_unsupported;

	if ( length <= 0 ) {
		return;
	}

	pw_type = pd[offset++];
	length--;
	auth_unsupported = FALSE;

	switch (pw_type) {
	case 1:
		s += sprintf ( s, "clear text (1), password (length %d) = ", length );

		if ( length > 0 ) {
		  strncpy(s, &pd[offset], length);
		  s[length] = 0;
                } else {
		  strcat(s, "no clear-text password found!!!" );
		}
		break;
	case 54:
	        s += sprintf ( s, "hmac-md5 (54), password (length %d) = ", length );

                if ( length == 16 ) {
		  s += sprintf ( s, "0x%02x", pd[offset++] );
		  length--;
		  while (length > 0) {
		    s += sprintf ( s, "%02x", pd[offset++] );
		    length--;
		    }
                    s = 0;
                } else {
                  strcat(s, "illegal hmac-md5 digest format (must be 16 bytes)" );
		}
		break;
	default:
		s += sprintf ( s, "type 0x%02x (0x%02x): ", pw_type, length );
		auth_unsupported=TRUE;
		break;
	}

	proto_tree_add_text ( tree, NullTVB, offset - 1, length + 1,
			"%s %s", meaning, sbuf );

       	if ( auth_unsupported ) {
       		isis_dissect_unknown(offset, length, tree, fd,
       			"Unknown authentication type" );
	}	
}	    

/*
 * Name: isis_dissect_hostname_clv()
 *
 * Description:
 *      dump the hostname information found in TLV 137
 *      pls note that the hostname is not null terminated
 *
 * Input:
 *      u_char * : packet data
 *      int : offset into packet data where we are.
 *      guint : length of clv we are decoding
 *      frame_data * : frame data (complete frame)
 *      proto_tree * : protocol display tree to fill out.  May be NULL
 *      char * : Password meaning
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */


void
isis_dissect_hostname_clv(const u_char *pd, int offset,
                guint length, frame_data *fd, proto_tree *tree ) {
        char sbuf[256*6];
        char *s = sbuf;
        int hlen = length;
        int old_offset = offset;


        if ( !tree ) return;            /* nothing to do! */

        memcpy ( s, &pd[offset], hlen);
        sbuf[hlen] = 0;                 /* don't forget null termination */

        if ( hlen == 0 ) {
                sprintf ( sbuf, "--none--" );
        }

        proto_tree_add_text ( tree, NullTVB, old_offset, hlen,
                        "Hostname: %s", sbuf );
}




void 
isis_dissect_mt_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree, gint tree_id ) {
	
  int  mt_block;
  char mt_desc[60];

	while (length>1) {
	  /* length can only be a multiple of 2, otherwise there is 
	     something broken -> so decode down until length is 1 */
	  if (length!=1)
	    {
	      /* fetch two bytes */
	      mt_block=(*(pd+offset)<<8)+(*(pd+offset+1));

	      /* mask out the lower 12 bits */
	      switch(mt_block&0x0fff) {
	        case 0:
		  strcpy(mt_desc,"IPv4 unicast");
		  break;
	        case 1:
		  strcpy(mt_desc,"In-Band Management");
		  break;
	        case 2:
		  strcpy(mt_desc,"IPv6 unicast");
		  break;
	        case 3:
		  strcpy(mt_desc,"Multicast");
		  break;
	        case 4095:
		  strcpy(mt_desc,"Development, Experimental or Proprietary");
		  break;
	        default:
		  strcpy(mt_desc,"Reserved for IETF Consensus");
	      }
	        proto_tree_add_text ( tree, NullTVB, offset, 2 ,
                        "%s Topology (0x%x)%s%s",
				      mt_desc,
				      mt_block&0xfff,
				      (mt_block&0x8000) ? "" : ", no sub-TLVs present",
				      (mt_block&0x4000) ? ", ATT bit set" : "" );
	    }
	  else {
	    proto_tree_add_text ( tree, NullTVB, offset, 1 ,
                        "malformed MT-ID");
	    break;
	  }
	  length=length-2;
	  offset=offset+2;
	}
}


/*
 * Name: isis_dissect_ip_int_clv()
 * 
 * Description:
 *	Take apart the CLV that lists all the IP interfaces.  The
 *	meaning of which is slightly different for the different base packet
 *	types, but the display is not different.  What we have is n ip
 *	addresses, plain and simple.
 *
 * Input:
 *	u_char * : packet data
 *	int : offset into packet data where we are.
 *	guint : length of clv we are decoding
 *	frame_data * : frame data (complete frame)
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	gint : tree id to use for proto tree.
 * 
 * Output:
 *	void, but we will add to proto tree if !NULL.
 */
void 
isis_dissect_ip_int_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree, gint tree_id ) {
	guint32 addr;
	if ( length <= 0 ) {
		return;
	}

	while ( length > 0 ) {
		if ( length < 4 ) {
			isis_dissect_unknown(offset, length, tree, fd,
				"Short ip interface address (%d vs 4)",length );
			return;
		}
		memcpy(&addr, &pd[offset], sizeof(addr));
		if ( tree ) {
			proto_tree_add_ipv4(tree, tree_id, NullTVB, offset, 4, addr);
		}
		offset += 4;
		length -= 4;
	}
}

/*
 * Name: isis_dissect_ipv6_int_clv()
 * 
 * Description:
 *	Take apart the CLV that lists all the IPv6 interfaces.  The
 *	meaning of which is slightly different for the different base packet
 *	types, but the display is not different.  What we have is n ip
 *	addresses, plain and simple.
 *
 * Input:
 *	u_char * : packet data
 *	int : offset into packet data where we are.
 *	guint : length of clv we are decoding
 *	frame_data * : frame data (complete frame)
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	gint : tree id to use for proto tree.
 * 
 * Output:
 *	void, but we will add to proto tree if !NULL.
 */
void 
isis_dissect_ipv6_int_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree, gint tree_id ) {
	guint8 addr [16];

	if ( length <= 0 ) {
		return;
	}

	while ( length > 0 ) {
		if ( length < 16 ) {
			isis_dissect_unknown(offset, length, tree, fd,
				"Short IPv6 interface address (%d vs 16)",length );
			return;
		}
		memcpy(addr, &pd[offset], sizeof(addr));
		if ( tree ) {
			proto_tree_add_ipv6(tree, tree_id, NullTVB, offset, 16, addr);
		}
		offset += 16;
		length -= 16;
	}
}

/*
 * Name: isis_dissect_te_router_id_clv()
 *
 * Description:
 *      Display the Traffic Engineering Router ID TLV #134.
 *      This TLV is like the IP Interface TLV, except that
 *      only _one_ IP address is present
 *
 * Input:
 *      u_char * : packet data
 *      int : offset into packet data where we are.
 *      guint : length of clv we are decoding
 *      frame_data * : frame data (complete frame)
 *      proto_tree * : protocol display tree to fill out.  May be NULL
 *      gint : tree id to use for proto tree.
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
void
isis_dissect_te_router_id_clv(const u_char *pd, int offset,
                guint length, frame_data *fd, proto_tree *tree, gint tree_id ) {
        guint32 addr;
        if ( length <= 0 ) {
                return;
        }

        if ( length != 4 ) {
                isis_dissect_unknown(offset, length, tree, fd,
                        "malformed Traffic Engineering Router ID (%d vs 4)",length );
                return;
        }
        memcpy(&addr, &pd[offset], sizeof(addr));
        if ( tree ) {
                proto_tree_add_ipv4(tree, tree_id, NullTVB, offset, 4, addr);
        }
}

/*
 * Name: isis_dissect_nlpid_clv()
 * 
 * Description:
 *	Take apart a NLPID packet and display it.  The NLPID (for intergrated
 *	ISIS, contains n network layer protocol IDs that the box supports.
 *	Our display buffer we use is upto 255 entries, 6 bytes per (0x00, )
 *	plus 1 for zero termination.  We just just 256*6 for simplicity.
 *
 * Input:
 *	u_char * : packet data
 *	int : offset into packet data where we are.
 *	guint : length of clv we are decoding
 *	frame_data * : frame data (complete frame)
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 * 
 * Output:
 *	void, but we will add to proto tree if !NULL.
 */
void 
isis_dissect_nlpid_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree ) {
	char sbuf[256*6];
	char *s = sbuf;
	int hlen = length;
	int old_offset = offset;

	if ( !tree ) return;		/* nothing to do! */

	while ( length-- > 0 ) {
		if (s != sbuf ) {
			s += sprintf ( s, ", " ); 
		}
		s += sprintf ( s, "%s (0x%02x)",
		    val_to_str(pd[offset], nlpid_vals, "Unknown"), pd[offset]);
		offset++;	
	}

	if ( hlen == 0 ) {
		sprintf ( sbuf, "--none--" );
	}

	proto_tree_add_text ( tree, NullTVB, old_offset, hlen,
			"NLPID(s): %s", sbuf );
}

/*
 * Name: isis_dissect_clvs()
 * 
 * Description:
 *	Dispatch routine to shred all the CLVs in a packet.  We just
 *	walk through the clv entries in the packet.  For each one, we
 *	search the passed in valid clv's for this protocol (opts) for
 *	a matching code.  If found, we add to the display tree and
 *	then call the dissector.  If it is not, we just post an
 *	"unknown" clv entrie using the passed in unknown clv tree id.
 *
 * Input:
 *	isis_clv_handle_t * : NULL dissector terminated array of codes
 *		and handlers (along with tree text and tree id's).
 *	int : length of CLV area.
 *	u_char * : packet data
 *	int : offset into packet data where we are.
 *	guint : length of clv we are decoding
 *	frame_data * : frame data (complete frame)
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	gint : unknown clv tree id
 * 
 * Output:
 *	void, but we will add to proto tree if !NULL.
 */
void 
isis_dissect_clvs(const isis_clv_handle_t *opts, int len, int id_length,
		const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
		gint unknown_tree_id ) { 
	guint8 code;
	guint8 length;
	int q;
	proto_item	*ti;
	proto_tree	*clv_tree;
	char		sbuf[255];
	int 		adj;

	while ( len > 0 ) {
		code = pd[offset++];
		length = pd[offset++];
		adj = (sizeof(code) + sizeof(length) + length);
		len -= adj;
		if ( len < 0 || !BYTES_ARE_IN_FRAME(offset, length) ) {
			isis_dissect_unknown(offset, adj, tree, fd,
				"Short CLV header (%d vs %d)",
				adj, len + adj );
			return;
		}
		q = 0;
		while ((opts[q].dissect != NULL )&&( opts[q].optcode != code )){
			q++;
		}
		if ( opts[q].dissect ) {
			if (tree) {
				/* adjust by 2 for code/len octets */
				snprintf ( sbuf, sizeof(sbuf), "%s (%d)", 
					opts[q].tree_text, length ); 
				ti = proto_tree_add_text(tree, NullTVB, offset - 2, 
					length + 2, sbuf);
				clv_tree = proto_item_add_subtree(ti, 
					*opts[q].tree_id );
			} else {
				clv_tree = NULL;
			}
			opts[q].dissect(pd, offset, length, id_length, fd,
				clv_tree );
		} else {
			if (tree) { 
				snprintf ( sbuf, sizeof(sbuf), 
					"Unknown code (%d:%d)", code, length ); 
				ti = proto_tree_add_text(tree, NullTVB, offset - 2, 
					length + 2, sbuf);
				clv_tree = proto_item_add_subtree(ti, 
					unknown_tree_id );
			} else { 
				clv_tree = NULL;
			}
		}
		offset += length;
	}
}
