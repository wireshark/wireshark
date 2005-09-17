/* packet-isis-clv.c
 * Common CLV decode routines.
 *
 * $Id$
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include "packet-osi.h"
#include "packet-isis.h"
#include "packet-isis-clv.h"
#include <epan/nlpid.h>

/*
 * Name: isis_dissect_area_address_clv()
 *
 * Description:
 *	Take an area address CLV and display it pieces.  An area address
 *	CLV is n, x byte hex strings.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	int : length of clv we are decoding
 *
 * Output:
 *	void, but we will add to proto tree if !NULL.
 */
void
isis_dissect_area_address_clv(tvbuff_t *tvb, proto_tree *tree, int offset,
	int length)
{
	int		arealen,area_idx;

	while ( length > 0 ) {
		arealen = tvb_get_guint8(tvb, offset);
		length--;
		if (length<=0) {
			isis_dissect_unknown(tvb, tree, offset,
				"short address (no length for payload)");
			return;
		}
		if ( arealen > length) {
			isis_dissect_unknown(tvb, tree, offset,
				"short address, packet says %d, we have %d left",
				arealen, length );
			return;
		}

		if ( tree ) {
			proto_item *ti;
	
			/*
			 * Throw an exception rather than putting in a
			 * partial address.
			 */
			tvb_ensure_bytes_exist ( tvb, offset, arealen + 1 );

			ti = proto_tree_add_text ( tree, tvb, offset, arealen + 1,
				"Area address (%d): ", arealen );

			/*
			 * Lets turn the area address into "standard"
			 * xx.xxxx.xxxx.xxxx.xxxx.xxxx.xxxx format string.
	                 * this is a private routine as the print_nsap_net in
			 * epan/osi_utils.c is incomplete and we need only
			 * a subset - actually some nice placing of dots ....
			 */
			for (area_idx = 0; area_idx < arealen; area_idx++) {
				proto_item_append_text(ti, "%02x",
				    tvb_get_guint8(tvb, offset+area_idx+1));
				if (((area_idx & 1) == 0) &&
				    (area_idx + 1 < arealen)) {
					proto_item_append_text(ti, ".");
				}
			}
		}
		offset += arealen + 1;
		length -= arealen;	/* length already adjusted for len fld*/
	}
}


/*
 * Name: isis_dissect_authentication_clv()
 *
 * Description:
 *	Take apart the CLV that hold authentication information.  This
 *	is currently 1 octet auth type.
 *      the two defined authentication types
 *	  are 1 for a clear text password and
 *           54 for a HMAC-MD5 digest
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	int : length of clv we are decoding
 *
 * Output:
 *	void, but we will add to proto tree if !NULL.
 */
void
isis_dissect_authentication_clv(tvbuff_t *tvb, proto_tree *tree, int offset,
	int length)
{
	guchar pw_type;
	int auth_unsupported;
	proto_item *ti;

	if ( length <= 0 ) {
		return;
	}

	pw_type = tvb_get_guint8(tvb, offset);
	offset += 1;
	length--;
	auth_unsupported = FALSE;

	switch (pw_type) {
	case 1:
		ti = proto_tree_add_text ( tree, tvb, offset - 1, length + 1,
		    "clear text (1), password (length %d) = ", length);
		if ( length > 0 ) {
		  proto_item_append_text(ti, "%s",
		    tvb_format_text(tvb, offset, length));
                } else {
		  proto_item_append_text(ti, "no clear-text password found!!!");
		}
		break;
	case 54:
		ti = proto_tree_add_text ( tree, tvb, offset - 1, length + 1,
		    "hmac-md5 (54), password (length %d) = ", length);

		if ( length == 16 ) {
		  proto_item_append_text(ti, "0x%02x", tvb_get_guint8(tvb, offset));
		  offset += 1;
		  length--;
		  while (length > 0) {
		    proto_item_append_text(ti, "%02x", tvb_get_guint8(tvb, offset));
		    offset += 1;
		    length--;
		  }
		} else {
		  proto_item_append_text(ti,
		      "illegal hmac-md5 digest format (must be 16 bytes)");
		}
		break;
	default:
		ti = proto_tree_add_text ( tree, tvb, offset - 1, length + 1,
		    "type 0x%02x (0x%02x): ", pw_type, length );
		auth_unsupported=TRUE;
		break;
	}

       	if ( auth_unsupported ) {
		isis_dissect_unknown(tvb, tree, offset,
       			"Unknown authentication type" );
	}
}

/*
 * Name: isis_ip_authentication_clv()
 *
 * Description:
 *      dump the IP authentication information found in TLV 133
 *      the CLV is standardized in rf1195, however all major
 *      implementations use TLV #10
 * Input:
 *      tvbuff_t * : tvbuffer for packet data
 *      proto_tree * : protocol display tree to fill out.  May be NULL
 *      int : offset into packet data where we are.
 *      int : length of clv we are decoding
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */


void
isis_dissect_ip_authentication_clv(tvbuff_t *tvb, proto_tree *tree, int offset,
	int length)
{
        if ( !tree ) return;            /* nothing to do! */

        if ( length != 0 ) {
                proto_tree_add_text ( tree, tvb, offset, length,
                        "IP Authentication: %.*s", length,
                        tvb_get_ptr(tvb, offset, length) );
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
 *      tvbuff_t * : tvbuffer for packet data
 *      proto_tree * : protocol display tree to fill out.  May be NULL
 *      int : offset into packet data where we are.
 *      int : length of clv we are decoding
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */


void
isis_dissect_hostname_clv(tvbuff_t *tvb, proto_tree *tree, int offset,
	int length)
{
        if ( !tree ) return;            /* nothing to do! */

        if ( length == 0 ) {
                proto_tree_add_text ( tree, tvb, offset, length,
                        "Hostname: --none--" );
        } else {
                proto_tree_add_text ( tree, tvb, offset, length,
                        "Hostname: %.*s", length,
                        tvb_get_ptr(tvb, offset, length) );
        }
}




void
isis_dissect_mt_clv(tvbuff_t *tvb, proto_tree *tree, int offset, int length,
	int tree_id)
{
	guint16 mt_block;
	char *mt_desc;

	while (length>0) {
	    /* length can only be a multiple of 2, otherwise there is
	       something broken -> so decode down until length is 1 */
	    if (length!=1) {
		/* fetch two bytes */
		mt_block=tvb_get_ntohs(tvb, offset);

		/* mask out the lower 12 bits */
		switch(mt_block&0x0fff) {
		case 0:
		    mt_desc="IPv4 unicast";
		    break;
		case 1:
		    mt_desc="In-Band Management";
		    break;
		case 2:
		    mt_desc="IPv6 unicast";
		    break;
		case 3:
		    mt_desc="Multicast";
		    break;
		case 4095:
		    mt_desc="Development, Experimental or Proprietary";
		    break;
		default:
		    mt_desc="Reserved for IETF Consensus";
		    break;
		}
		proto_tree_add_uint_format ( tree, tree_id, tvb, offset, 2,
			mt_block,
			"%s Topology (0x%03x)%s%s",
				      mt_desc,
				      mt_block&0xfff,
				      (mt_block&0x8000) ? "" : ", no sub-TLVs present",
				      (mt_block&0x4000) ? ", ATT bit set" : "" );
	    } else {
		proto_tree_add_text ( tree, tvb, offset, 1,
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
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	int : length of clv we are decoding
 *	int : tree id to use for proto tree.
 *
 * Output:
 *	void, but we will add to proto tree if !NULL.
 */
void
isis_dissect_ip_int_clv(tvbuff_t *tvb, proto_tree *tree, int offset,
	int length, int tree_id)
{
	if ( length <= 0 ) {
		return;
	}

	while ( length > 0 ) {
		if ( length < 4 ) {
			isis_dissect_unknown(tvb, tree, offset,
				"Short IP interface address (%d vs 4)",length );
			return;
		}

		if ( tree ) {
			proto_tree_add_item(tree, tree_id, tvb, offset, 4, FALSE);
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
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	int : length of clv we are decoding
 *	int : tree id to use for proto tree.
 *
 * Output:
 *	void, but we will add to proto tree if !NULL.
 */
void
isis_dissect_ipv6_int_clv(tvbuff_t *tvb, proto_tree *tree, int offset,
	int length, int tree_id)
{
	guint8 addr [16];

	if ( length <= 0 ) {
		return;
	}

	while ( length > 0 ) {
		if ( length < 16 ) {
			isis_dissect_unknown(tvb, tree, offset,
				"Short IPv6 interface address (%d vs 16)",length );
			return;
		}
		tvb_memcpy(tvb, addr, offset, sizeof(addr));
		if ( tree ) {
			proto_tree_add_ipv6(tree, tree_id, tvb, offset, 16, addr);
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
 *      tvbuff_t * : tvbuffer for packet data
 *      proto_tree * : protocol display tree to fill out.  May be NULL
 *      int : offset into packet data where we are.
 *      int : length of clv we are decoding
 *      int : tree id to use for proto tree.
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
void
isis_dissect_te_router_id_clv(tvbuff_t *tvb, proto_tree *tree, int offset,
	int length, int tree_id)
{
        if ( length <= 0 ) {
                return;
        }

        if ( length != 4 ) {
		isis_dissect_unknown(tvb, tree, offset,
                        "malformed Traffic Engineering Router ID (%d vs 4)",length );
                return;
        }
        if ( tree ) {
                proto_tree_add_item(tree, tree_id, tvb, offset, 4, FALSE);
        }
}

/*
 * Name: isis_dissect_nlpid_clv()
 *
 * Description:
 *	Take apart a NLPID packet and display it.  The NLPID (for intergrated
 *	ISIS, contains n network layer protocol IDs that the box supports.
 *	We max out at 256 entries.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	int : length of clv we are decoding
 *
 * Output:
 *	void, but we will add to proto tree if !NULL.
 */

#define TRUNCATED_TEXT " [truncated]"
void
isis_dissect_nlpid_clv(tvbuff_t *tvb, proto_tree *tree, int offset, int length)
{
	gboolean first;
	proto_item *ti;

	if ( !tree ) return;		/* nothing to do! */

	/*
	 * Throw an exception rather than putting in a
	 * partial address.
	 */
	tvb_ensure_bytes_exist ( tvb, offset, length );

	if (length <= 0) {
		proto_tree_add_text (tree, tvb, offset, length,
			"NLPID(s): --none--");
	} else {
		first = TRUE;
		ti = proto_tree_add_text (tree, tvb, offset, length,
			"NLPID(s): ");
		while (length-- > 0 ) {
			if (!first) {
				proto_item_append_text(ti, ", ");
			}
			proto_item_append_text(ti, "%s (0x%02x)",
				val_to_str(tvb_get_guint8(tvb, offset), nlpid_vals,
				"Unknown"), tvb_get_guint8(tvb, offset));
			offset++;
			first = FALSE;
		}
	}
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
 *	"unknown" clv entry using the passed in unknown clv tree id.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	isis_clv_handle_t * : NULL dissector terminated array of codes
 *		and handlers (along with tree text and tree id's).
 *	int : length of CLV area.
 *	int : length of IDs in packet.
 *	int : unknown clv tree id
 *
 * Output:
 *	void, but we will add to proto tree if !NULL.
 */
void
isis_dissect_clvs(tvbuff_t *tvb, proto_tree *tree, int offset,
	const isis_clv_handle_t *opts, int len, int id_length,
	int unknown_tree_id)
{
	guint8 code;
	guint8 length;
	int q;
	proto_item	*ti;
	proto_tree	*clv_tree;
	int 		adj;

	while ( len > 0 ) {
		code = tvb_get_guint8(tvb, offset);
		offset += 1;

		length = tvb_get_guint8(tvb, offset);
		offset += 1;

		adj = (sizeof(code) + sizeof(length) + length);
		len -= adj;
		if ( len < 0 ) {
			isis_dissect_unknown(tvb, tree, offset,
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
				ti = proto_tree_add_text(tree, tvb, offset - 2,
					length + 2, "%s (%u)",
					opts[q].tree_text, length );
				clv_tree = proto_item_add_subtree(ti,
					*opts[q].tree_id );
			} else {
				clv_tree = NULL;
			}
			opts[q].dissect(tvb, clv_tree, offset,
				id_length, length);
		} else {
			if (tree) {
				ti = proto_tree_add_text(tree, tvb, offset - 2,
					length + 2, "Unknown code %u (%u)",
					code, length);
				clv_tree = proto_item_add_subtree(ti,
					unknown_tree_id );
			} else {
				clv_tree = NULL;
			}
		}
		offset += length;
	}
}
