/* packet-sdp.c
 * Routines for SDP packet disassembly (RFC 2327)
 *
 * Jason Lango <jal@netapp.com>
 * Liberally copied from packet-http.c, by Guy Harris <guy@alum.mit.edu>
 *
 * $Id: packet-sdp.c,v 1.27 2002/02/02 02:52:41 guy Exp $
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

#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>
#include <ctype.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>

static int proto_sdp = -1;

/* Top level fields */
static int hf_protocol_version = -1;
static int hf_owner = -1;
static int hf_session_name = -1;
static int hf_session_info = -1;
static int hf_uri = -1;
static int hf_email = -1;
static int hf_phone = -1;
static int hf_connection_info = -1;
static int hf_bandwidth = -1;
static int hf_timezone = -1;
static int hf_encryption_key = -1;
static int hf_session_attribute = -1;
static int hf_media_attribute = -1;
static int hf_time = -1;
static int hf_repeat_time = -1;
static int hf_media = -1;
static int hf_media_title = -1;
static int hf_unknown = -1;
static int hf_misplaced = -1;
static int hf_invalid = -1;

/* hf_owner subfields*/
static int hf_owner_username = -1;
static int hf_owner_sessionid = -1;
static int hf_owner_version = -1;
static int hf_owner_network_type = -1;
static int hf_owner_address_type = -1;
static int hf_owner_address = -1;

/* hf_connection_info subfields */
static int hf_connection_info_network_type = -1;
static int hf_connection_info_address_type = -1;
static int hf_connection_info_connection_address = -1;
static int hf_connection_info_ttl = -1;
static int hf_connection_info_num_addr = -1;

/* hf_bandwidth subfields */
static int hf_bandwidth_modifier = -1;
static int hf_bandwidth_value = -1;

/* hf_time subfields */
static int hf_time_start = -1;
static int hf_time_stop = -1;

/* hf_repeat_time subfield */
static int hf_repeat_time_interval = -1;
static int hf_repeat_time_duration = -1;
static int hf_repeat_time_offset = -1;

/* hf_timezone subfields */
static int hf_timezone_time = -1;
static int hf_timezone_offset = -1;

/* hf_encryption_key subfields */
static int hf_encryption_key_type = -1;
static int hf_encryption_key_data = -1;

/* hf_session_attribute subfields */
static int hf_session_attribute_field = -1;
static int hf_session_attribute_value = -1;

/* hf_media subfields */
static int hf_media_media = -1;
static int hf_media_port = -1;
static int hf_media_portcount = -1;
static int hf_media_proto = -1;
static int hf_media_format = -1;

/* hf_session_attribute subfields */
static int hf_media_attribute_field = -1;
static int hf_media_attribute_value = -1;

/* trees */
static int ett_sdp = -1;
static int ett_sdp_owner = -1;
static int ett_sdp_connection_info = -1;
static int ett_sdp_bandwidth = -1;
static int ett_sdp_time = -1;
static int ett_sdp_repeat_time = -1;
static int ett_sdp_timezone = -1;
static int ett_sdp_encryption_key = -1;
static int ett_sdp_session_attribute = -1;
static int ett_sdp_media = -1;
static int ett_sdp_media_attribute = -1;

/* static functions */

static void call_sdp_subdissector(tvbuff_t *tvb, packet_info *pinfo, 
				  proto_tree *tree, int hf, proto_tree* ti);

/* Subdissector functions */
static void dissect_sdp_owner(tvbuff_t *tvb, packet_info *pinfo, 
			      proto_tree *tree, proto_item* ti);
static void dissect_sdp_connection_info(tvbuff_t *tvb, packet_info *pinfo,
					proto_tree *tree, proto_item* ti);
static void dissect_sdp_bandwidth(tvbuff_t *tvb, packet_info *pinfo,
				  proto_tree *tree, proto_item *ti);
static void dissect_sdp_time(tvbuff_t *tvb, packet_info *pinfo,
			     proto_tree *tree, proto_item* ti);
static void dissect_sdp_repeat_time(tvbuff_t *tvb, packet_info *pinfo,
				    proto_tree *tree, proto_item* ti);
static void dissect_sdp_timezone(tvbuff_t *tvb, packet_info *pinfo,
				 proto_tree *tree, proto_item* ti);
static void dissect_sdp_encryption_key(tvbuff_t *tvb, packet_info *pinfo,
				       proto_tree *tree, proto_item * ti);
static void dissect_sdp_session_attribute(tvbuff_t *tvb, packet_info *pinfo,
				  proto_tree *tree,proto_item *ti);
static void dissect_sdp_media(tvbuff_t *tvb, packet_info *pinfo,
			      proto_tree *tree, proto_item *ti);
static void dissect_sdp_media_attribute(tvbuff_t *tvb, packet_info *pinfo,
				  proto_tree *tree,proto_item *ti);

static void
dissect_sdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*sdp_tree;
	proto_item	*ti, *sub_ti;
	gint		offset = 0;
	gint		next_offset;
	int		linelen;
	u_char		section;
	u_char		type;
	u_char          delim;
	int		datalen;
	int             tokenoffset;
	int             hf = -1;

	/*
	 * As RFC 2327 says, "SDP is purely a format for session
	 * description - it does not incorporate a transport protocol,
	 * and is intended to use different transport protocols as
	 * appropriate including the Session Announcement Protocol,
	 * Session Initiation Protocol, Real-Time Streaming Protocol,
	 * electronic mail using the MIME extensions, and the
	 * Hypertext Transport Protocol."
	 *
	 * We therefore don't set the protocol or info columns;
	 * instead, we append to them, so that we don't erase
	 * what the protocol inside which the SDP stuff resides
	 * put there.
	 */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_append_str(pinfo->cinfo, COL_PROTOCOL, "/SDP");

	if (check_col(pinfo->cinfo, COL_INFO)) {
		/* XXX: Needs description. */
		col_append_str(pinfo->cinfo, COL_INFO, ", with session description");
	}

	if (!tree)
		return;

	ti = proto_tree_add_item(tree, proto_sdp, tvb, offset, -1, FALSE);
	sdp_tree = proto_item_add_subtree(ti, ett_sdp);

	/*
	 * Show the SDP message a line at a time.
	 */
	section = 0;
	while (tvb_offset_exists(tvb, offset)) {
		/*
		 * Find the end of the line.
		 */
		linelen = tvb_find_line_end_unquoted(tvb, offset, -1,
		    &next_offset);

		/*
		 * Line must contain at least e.g. "v=".
		 */
		if (linelen < 2)
			break;

		type = tvb_get_guint8(tvb,offset);
		delim = tvb_get_guint8(tvb,offset + 1);
		if (delim != '=') {
		        proto_tree_add_item(sdp_tree,hf_invalid,tvb, offset,
					      linelen, FALSE);
                        offset = next_offset;
			continue;
		}

		/*
		 * Attributes.
		 */
		switch (type) {
		case 'v':
		        hf = hf_protocol_version;
			section = 'v';
			break;
		case 'o':
		        hf = hf_owner;
			break;
		case 's':
		        hf = hf_session_name;
			break;
		case 'i':
		        if (section == 'v'){
			        hf = hf_session_info;
			}
			else if (section == 'm'){
			        hf = hf_media_title;
			}
			else{
			        hf = hf_misplaced;
			}
			break;
		case 'u':
		        hf = hf_uri;
			break;
		case 'e':
		        hf = hf_email;
			break;
		case 'p':
		        hf = hf_phone;
			break;
		case 'c':
		        hf = hf_connection_info;
			break;
		case 'b':
		        hf = hf_bandwidth;
			break;
		case 't':
		        hf = hf_time;
			section = 't';
			break;
		case 'r':
		        hf = hf_repeat_time;
			break;
		case 'm':
		        hf = hf_media;
			section = 'm';
			break;
		case 'k':
		        hf = hf_encryption_key;
			break;
		case 'a':
		        if (section == 'v'){
			        hf = hf_session_attribute; 
			}
			else if (section == 'm'){
			        hf = hf_media_attribute;
			}
			else{
			        hf = hf_misplaced;
			}
			break;
		case 'z':
		        hf = hf_timezone;
			break;
		default:
		        hf = hf_unknown;
			break;
		}
		tokenoffset = 2;
		if( hf == hf_unknown || hf == hf_misplaced )
		  tokenoffset = 0;
		sub_ti = proto_tree_add_string(sdp_tree,hf,tvb, offset, 
					       linelen,
					       tvb_get_ptr(tvb,
						      offset+tokenoffset,
						      linelen - tokenoffset));
		call_sdp_subdissector(tvb_new_subset(tvb,offset+tokenoffset,
						     linelen-tokenoffset,-1),
				      pinfo,tree,hf,sub_ti);
		offset = next_offset;
	}

	datalen = tvb_length_remaining(tvb, offset);
	if (datalen > 0) {
		proto_tree_add_text(sdp_tree, tvb, offset, datalen,
		    "Data (%d bytes)", datalen);
	}
}

static void 
call_sdp_subdissector(tvbuff_t *tvb, packet_info *pinfo, 
		      proto_tree *tree, int hf, proto_tree* ti){
  if(hf == hf_owner){
    dissect_sdp_owner(tvb,pinfo,tree,ti);
  } else if ( hf == hf_connection_info) {
    dissect_sdp_connection_info(tvb,pinfo,tree,ti);
  } else if ( hf == hf_bandwidth) {
    dissect_sdp_bandwidth(tvb,pinfo,tree,ti);
  } else if ( hf == hf_time) {
    dissect_sdp_time(tvb,pinfo,tree,ti);
  } else if ( hf == hf_repeat_time ){
    dissect_sdp_repeat_time(tvb,pinfo,tree,ti);
  } else if ( hf == hf_timezone ) {
    dissect_sdp_timezone(tvb,pinfo,tree,ti);
  } else if ( hf == hf_encryption_key ) {
    dissect_sdp_encryption_key(tvb,pinfo,tree,ti);
  } else if ( hf == hf_session_attribute ){
    dissect_sdp_session_attribute(tvb,pinfo,tree,ti);
  } else if ( hf == hf_media ) {
    dissect_sdp_media(tvb,pinfo,tree,ti);
  } else if ( hf == hf_media_attribute ){
    dissect_sdp_media_attribute(tvb,pinfo,tree,ti);
  }
}

static void 
dissect_sdp_owner(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		  proto_item *ti){
  proto_tree *sdp_owner_tree;
  gint offset,next_offset,tokenlen;

  if(!tree)
    return;
  
  offset = 0;
  next_offset = 0;
  tokenlen = 0;

  sdp_owner_tree = proto_item_add_subtree(ti,ett_sdp_owner);
  
  /* Find the username */
  next_offset = tvb_find_guint8(tvb,offset,-1,' ');
  if( next_offset == -1 )
    return;
  tokenlen = next_offset - offset;

  proto_tree_add_item(sdp_owner_tree,hf_owner_username,tvb, offset,tokenlen,
		      FALSE);
  offset = next_offset  + 1;

  /* Find the session id */
  next_offset = tvb_find_guint8(tvb,offset,-1,' ');
  if( next_offset == -1 )
    return;
  tokenlen = next_offset - offset;

  proto_tree_add_item(sdp_owner_tree,hf_owner_sessionid, tvb, 
		      offset,tokenlen,FALSE);
  offset = next_offset + 1;

  /* Find the version */
  next_offset = tvb_find_guint8(tvb,offset,-1,' ');
  if( next_offset == -1 )
    return;
  tokenlen = next_offset - offset;

  proto_tree_add_item(sdp_owner_tree,hf_owner_version, tvb,
		      offset,tokenlen,FALSE);
  offset = next_offset + 1;

  /* Find the network type */
  next_offset = tvb_find_guint8(tvb,offset,-1,' ');
  if( next_offset == -1 )
    return;
  tokenlen = next_offset - offset;

  proto_tree_add_item(sdp_owner_tree,hf_owner_network_type, tvb, 
		      offset,tokenlen,FALSE);
  offset = next_offset + 1;
  
  /* Find the address type */
  next_offset = tvb_find_guint8(tvb,offset,-1,' ');
  if( next_offset == -1 )
    return;
  tokenlen = next_offset - offset;

  proto_tree_add_item(sdp_owner_tree,hf_owner_address_type, tvb, 
		      offset,tokenlen,FALSE);
  offset = next_offset + 1;

  /* Find the address */
  proto_tree_add_item(sdp_owner_tree,hf_owner_address, tvb, offset, -1, FALSE);
}

static void 
dissect_sdp_connection_info(tvbuff_t *tvb, packet_info *pinfo,
			    proto_tree *tree, proto_item* ti){
  proto_tree *sdp_connection_info_tree;
  gint offset,next_offset,tokenlen;

  if(!tree)
    return;
  
  offset = 0;
  next_offset = 0;
  tokenlen = 0;
  
  sdp_connection_info_tree = proto_item_add_subtree(ti,
						    ett_sdp_connection_info);
  
  /* Find the network type */
  next_offset = tvb_find_guint8(tvb,offset,-1,' ');
  if( next_offset == -1 )
    return;
  tokenlen = next_offset - offset;

  proto_tree_add_item(sdp_connection_info_tree,
		      hf_connection_info_network_type,tvb, 
		      offset,tokenlen,FALSE);
  offset = next_offset + 1;

  /* Find the address type */
  next_offset = tvb_find_guint8(tvb,offset,-1,' ');
  if( next_offset == -1 )
    return;
  tokenlen = next_offset - offset;

  proto_tree_add_item(sdp_connection_info_tree,
		      hf_connection_info_address_type,tvb, 
		      offset,tokenlen,FALSE);
  offset = next_offset + 1;

  /* Find the connection address */
  next_offset = tvb_find_guint8(tvb,offset,-1,'/');
  if( next_offset == -1){
    tokenlen = -1;	/* end of tvbuff */
  } else {
    tokenlen = next_offset - offset;
  }
  proto_tree_add_item(sdp_connection_info_tree,
		      hf_connection_info_connection_address, tvb, 
		      offset,tokenlen,FALSE);
  if(next_offset != -1){
    offset = next_offset + 1;
    next_offset = tvb_find_guint8(tvb,offset,-1,'/');
    if( next_offset == -1){
      tokenlen = -1;	/* end of tvbuff */
    } else {
      tokenlen = next_offset - offset;
    }
    proto_tree_add_item(sdp_connection_info_tree,
			hf_connection_info_ttl,tvb,offset,tokenlen,FALSE);
    if(next_offset != -1){
      offset = next_offset + 1;
      proto_tree_add_item(sdp_connection_info_tree,
			  hf_connection_info_num_addr, tvb,
			  offset, -1, FALSE);
    }
  }
}

static void 
dissect_sdp_bandwidth(tvbuff_t *tvb, packet_info *pinfo,
		      proto_tree *tree,proto_item *ti){
  proto_tree * sdp_bandwidth_tree;
  gint offset, next_offset, tokenlen;
  
  if(!tree)
    return;

  offset = 0;
  next_offset = 0;
  tokenlen = 0;

  sdp_bandwidth_tree = proto_item_add_subtree(ti,ett_sdp_bandwidth);

  /* find the modifier */
  next_offset = tvb_find_guint8(tvb,offset,-1,':');

  if( next_offset == -1)
    return;
  
  tokenlen = next_offset - offset;
  
  proto_tree_add_item(sdp_bandwidth_tree, hf_bandwidth_modifier,
		      tvb, offset, tokenlen, FALSE);

  offset = next_offset + 1;
  
  proto_tree_add_item(sdp_bandwidth_tree, hf_bandwidth_value,
		      tvb, offset, -1, FALSE);

}

static void dissect_sdp_time(tvbuff_t *tvb, packet_info *pinfo,
			     proto_tree *tree, proto_item* ti){
  proto_tree *sdp_time_tree;
  gint offset,next_offset, tokenlen;

  if(!tree)
    return;
  
  offset = 0;
  next_offset = 0;
  tokenlen = 0;
  
  sdp_time_tree = proto_item_add_subtree(ti,ett_sdp_time);

  /* get start time */
  next_offset = tvb_find_guint8(tvb,offset,-1,' ');
  if( next_offset == -1 )
    return;

  tokenlen = next_offset - offset;
  proto_tree_add_item(sdp_time_tree, hf_time_start, tvb,
		      offset, tokenlen, FALSE);

  /* get stop time */
  offset = next_offset + 1;
  proto_tree_add_item(sdp_time_tree,hf_time_start, tvb,
		      offset, -1, FALSE);
}

static void dissect_sdp_repeat_time(tvbuff_t *tvb, packet_info *pinfo,
				    proto_tree *tree, proto_item* ti){
  proto_tree *sdp_repeat_time_tree;
  gint offset,next_offset, tokenlen;

  if(!tree)
    return;
  
  offset = 0;
  next_offset = 0;
  tokenlen = 0;
  
  sdp_repeat_time_tree = proto_item_add_subtree(ti,ett_sdp_time);

  /* get interval */
  next_offset = tvb_find_guint8(tvb,offset,-1,' ');
  if( next_offset == -1 )
    return;

  tokenlen = next_offset - offset;
  proto_tree_add_item(sdp_repeat_time_tree, hf_repeat_time_interval, tvb,
		      offset, tokenlen, FALSE);

  /* get duration */
  offset = next_offset + 1;
  next_offset = tvb_find_guint8(tvb,offset,-1,' ');
  if( next_offset == -1 )
    return;

  tokenlen = next_offset - offset;
  proto_tree_add_item(sdp_repeat_time_tree,hf_repeat_time_duration, tvb,
		      offset, tokenlen, FALSE);

  /* get offsets */
  do{
    offset = next_offset +1;
    next_offset = tvb_find_guint8(tvb,offset,-1,' ');
    if(next_offset != -1){
      tokenlen = next_offset - offset;
    } else {
      tokenlen = -1;	/* end of tvbuff */
    }
    proto_tree_add_item(sdp_repeat_time_tree, hf_repeat_time_offset,
			tvb, offset, tokenlen, FALSE);
  } while( next_offset != -1 );
  
}
static void 
dissect_sdp_timezone(tvbuff_t *tvb, packet_info *pinfo,
		     proto_tree *tree, proto_item* ti){
  proto_tree* sdp_timezone_tree;
  gint offset, next_offset, tokenlen;
  if(!tree)
    return;
  offset = 0;
  next_offset = 0;
  tokenlen = 0;
  
  sdp_timezone_tree = proto_item_add_subtree(ti,ett_sdp_timezone);
  
  do{
    next_offset = tvb_find_guint8(tvb,offset,-1,' ');
    if(next_offset == -1)
      break;
    tokenlen = next_offset - offset;
    
    proto_tree_add_item(sdp_timezone_tree,hf_timezone_time,tvb,
			offset, tokenlen, FALSE);
    offset = next_offset + 1;
    next_offset = tvb_find_guint8(tvb,offset,-1,' ');
    if(next_offset != -1){
      tokenlen = next_offset - offset;
    } else {
      tokenlen = -1;	/* end of tvbuff */
    }
    proto_tree_add_item(sdp_timezone_tree,hf_timezone_offset,tvb,
			offset, tokenlen, FALSE);
    offset = next_offset + 1;
  } while (next_offset != -1);
    
}


static void dissect_sdp_encryption_key(tvbuff_t *tvb, packet_info *pinfo,
				       proto_tree *tree, proto_item * ti){
  proto_tree *sdp_encryption_key_tree;
  gint offset, next_offset, tokenlen;

  offset = 0;
  next_offset = 0;
  tokenlen = 0;

  sdp_encryption_key_tree = proto_item_add_subtree(ti,ett_sdp_encryption_key);

  next_offset = tvb_find_guint8(tvb,offset,-1,':');

  if(next_offset == -1)
    return;

  tokenlen = next_offset - offset;
  
  proto_tree_add_item(sdp_encryption_key_tree,hf_encryption_key_type,
		      tvb, offset, tokenlen, FALSE);
  
  offset = next_offset + 1;
  proto_tree_add_item(sdp_encryption_key_tree,hf_encryption_key_data,
		      tvb, offset, -1, FALSE);

}



static void dissect_sdp_session_attribute(tvbuff_t *tvb, packet_info *pinfo,
					  proto_tree *tree, proto_item * ti){
  proto_tree *sdp_session_attribute_tree;
  gint offset, next_offset, tokenlen;

  offset = 0;
  next_offset = 0;
  tokenlen = 0;

  sdp_session_attribute_tree = proto_item_add_subtree(ti,
						      ett_sdp_session_attribute);

  next_offset = tvb_find_guint8(tvb,offset,-1,':');

  if(next_offset == -1)
    return;

  tokenlen = next_offset - offset;
  
  proto_tree_add_item(sdp_session_attribute_tree,
		      hf_session_attribute_field,
		      tvb, offset, tokenlen, FALSE);
  
  offset = next_offset + 1;
  proto_tree_add_item(sdp_session_attribute_tree,
		      hf_session_attribute_value,
		      tvb, offset, -1, FALSE);

}

static void 
dissect_sdp_media(tvbuff_t *tvb, packet_info *pinfo,
		  proto_tree *tree, proto_item *ti){
  proto_tree *sdp_media_tree;
  gint offset, next_offset, tokenlen;

  if(!tree)
    return;
  
  offset = 0;
  next_offset = 0;
  tokenlen = 0;

  sdp_media_tree = proto_item_add_subtree(ti,ett_sdp_media);

  next_offset = tvb_find_guint8(tvb,offset, -1, ' ');
  
  if(next_offset == -1)
    return;

  tokenlen = next_offset - offset;
  
  proto_tree_add_item(sdp_media_tree, hf_media_media, tvb, 
		      offset, tokenlen, FALSE);

  offset = next_offset + 1;

  next_offset = tvb_find_guint8(tvb,offset, -1, ' ');
  if(next_offset == -1)
    return;
  tokenlen = next_offset - offset;
  next_offset = tvb_find_guint8(tvb,offset, tokenlen, '/');
  
  if(next_offset != -1){
    tokenlen = next_offset - offset;
  
    proto_tree_add_item(sdp_media_tree, hf_media_port, tvb, 
			offset, tokenlen, FALSE);
    offset = next_offset + 1;
    next_offset = tvb_find_guint8(tvb,offset, -1, ' ');
    if(next_offset == -1)
      return;
    tokenlen = next_offset - offset;
    proto_tree_add_item(sdp_media_tree, hf_media_portcount, tvb,
			offset, tokenlen, FALSE);
    offset = next_offset + 1;
  } else {
    next_offset = tvb_find_guint8(tvb,offset, -1, ' ');
    
    if(next_offset == -1)
      return;
    tokenlen = next_offset - offset;
    
    proto_tree_add_item(sdp_media_tree, hf_media_port, tvb,
			offset, tokenlen, FALSE);
    offset = next_offset + 1;
  }

  next_offset = tvb_find_guint8(tvb,offset,-1,' ');
  
  if( next_offset == -1)
    return;
  
  tokenlen = next_offset - offset;

  proto_tree_add_item(sdp_media_tree, hf_media_proto, tvb,
		      offset, tokenlen, FALSE);

  do{
    offset = next_offset + 1;
    next_offset = tvb_find_guint8(tvb,offset,-1,' ');
    
    if(next_offset == -1){
      tokenlen = -1;	/* End of tvbuff */
    } else {
      tokenlen = next_offset - offset;
    }

    proto_tree_add_item(sdp_media_tree, hf_media_format, tvb,
			offset, tokenlen, FALSE);
  } while (next_offset != -1);

}

static void dissect_sdp_media_attribute(tvbuff_t *tvb, packet_info *pinfo,
					  proto_tree *tree, proto_item * ti){
  proto_tree *sdp_media_attribute_tree;
  gint offset, next_offset, tokenlen;

  offset = 0;
  next_offset = 0;
  tokenlen = 0;

  sdp_media_attribute_tree = proto_item_add_subtree(ti,
						      ett_sdp_media_attribute);

  next_offset = tvb_find_guint8(tvb,offset,-1,':');

  if(next_offset == -1)
    return;

  tokenlen = next_offset - offset;
  
  proto_tree_add_item(sdp_media_attribute_tree,
		      hf_media_attribute_field,
		      tvb, offset, tokenlen, FALSE);
  
  offset = next_offset + 1;
  proto_tree_add_item(sdp_media_attribute_tree,
		      hf_media_attribute_value,
		      tvb, offset, -1, FALSE);

}

void
proto_register_sdp(void)
{
  static hf_register_info hf[] = {
    { &hf_protocol_version,
      { "Session Description Protocol Version (v)",
	"sdp.version", FT_STRING, BASE_NONE,NULL,0x0,
	"Session Description Protocol Version", HFILL }},
    { &hf_owner, 
      { "Owner/Creator, Session Id (o)",
	"sdp.owner", FT_STRING, BASE_NONE, NULL, 0x0,
	"Owner/Creator, Session Id", HFILL}},
    { &hf_session_name,
      { "Session Name (s)",
	"sdp.session_name", FT_STRING, BASE_NONE,NULL, 0x0,
	"Session Name", HFILL }},
    { &hf_session_info,
      { "Session Information (i)", 
	"sdp.session_info", FT_STRING, BASE_NONE, NULL, 0x0,
	"Session Information", HFILL }},
    { &hf_uri,
      { "URI of Description (u)",
	"sdp.uri", FT_STRING, BASE_NONE,NULL, 0x0,
	"URI of Description", HFILL }},
    { &hf_email,
      { "E-mail Address (e)", 
	"sdp.email", FT_STRING, BASE_NONE, NULL, 0x0,
	"E-mail Address", HFILL }},
    { &hf_phone,
      { "Phone Number (p)",
	"sdp.phone", FT_STRING, BASE_NONE, NULL, 0x0,
	"Phone Number", HFILL }},
    { &hf_connection_info,
      { "Connection Information (c)",
	"sdp.connection_info", FT_STRING, BASE_NONE, NULL, 0x0,
	"Connection Information", HFILL }},
    { &hf_bandwidth,
      { "Bandwidth Information (b)",
	"sdp.bandwidth", FT_STRING, BASE_NONE, NULL, 0x0,
	"Bandwidth Information", HFILL }},
    { &hf_timezone,
      { "Time Zone Adjustments (z)",
	"sdp.timezone", FT_STRING, BASE_NONE, NULL, 0x0,
	"Time Zone Adjustments", HFILL }},
    { &hf_encryption_key,
      { "Encryption Key (k)",
	"sdp.encryption_key", FT_STRING, BASE_NONE, NULL, 0x0,
	"Encryption Key", HFILL }},
    { &hf_session_attribute, 
      { "Session Attribute (a)", 
	"sdp.session_attr", FT_STRING, BASE_NONE, NULL, 0x0,
	"Session Attribute", HFILL }},
    { &hf_media_attribute, 
      { "Media Attribute (a)", 
	"sdp.media_attr", FT_STRING, BASE_NONE, NULL, 0x0,
	"Media Attribute", HFILL }},
    { &hf_time,
      { "Time Description, active time (t)",
	"sdp.time", FT_STRING, BASE_NONE, NULL, 0x0,
	"Time Description, active time", HFILL }},
    { &hf_repeat_time,
      { "Repeat Time (r)",
	"sdp.repeat_time", FT_STRING, BASE_NONE, NULL, 0x0,
	"Repeat Time", HFILL }},
    { &hf_media,
      { "Media Description, name and address (m)",
	"sdp.media", FT_STRING, BASE_NONE, NULL, 0x0,
	"Media Description, name and address", HFILL }},
    { &hf_media_title,
      { "Media Title (i)",
	"sdp.media_title",FT_STRING, BASE_NONE, NULL, 0x0,
	"Media Title", HFILL }},
    { &hf_unknown,
      { "Unknown",
	"sdp.unknown",FT_STRING, BASE_NONE, NULL, 0x0,
	"Unknown", HFILL }},
    { &hf_misplaced,
      { "Misplaced",
	"sdp.misplaced",FT_STRING, BASE_NONE, NULL, 0x0,
	"Misplaced", HFILL }},
    { &hf_invalid,
      { "Invalid line",
	"sdp.invalid",FT_STRING, BASE_NONE, NULL, 0x0,
	"Invalid line", HFILL }},
    { &hf_owner_username,
      { "Owner Username",
	"sdp.owner.username",FT_STRING, BASE_NONE, NULL, 0x0,
	"Owner Username", HFILL }},
    { &hf_owner_sessionid,
      { "Session ID",
	"sdp.owner.sessionid",FT_STRING, BASE_NONE, NULL, 0x0,
	"Session ID", HFILL }},
    { &hf_owner_version,
      { "Session Version",
	"sdp.owner.version",FT_STRING, BASE_NONE, NULL, 0x0,
	"Session Version", HFILL }},
    { &hf_owner_network_type,
      { "Owner Network Type",
	"sdp.owner.network_type",FT_STRING, BASE_NONE, NULL, 0x0,
	"Owner Network Type", HFILL }},
    { &hf_owner_address_type,
      { "Owner Address Type",
	"sdp.owner.address_type",FT_STRING, BASE_NONE, NULL, 0x0,
	"Owner Address Type", HFILL }},
    { &hf_owner_address,
      { "Owner Address",
	"sdp.owner.address",FT_STRING, BASE_NONE, NULL, 0x0,
	"Owner Address", HFILL }},
    { &hf_connection_info_network_type,
      { "Connection Network Type",
	"sdp.connection_info.network_type",FT_STRING, BASE_NONE, NULL, 0x0,
	"Connection Network Type", HFILL }},
    { &hf_connection_info_address_type,
      { "Connection Address Type",
	"sdp.connection_info.address_type",FT_STRING, BASE_NONE, NULL, 0x0,
	"Connection Address Type", HFILL }},
    { &hf_connection_info_connection_address,
      { "Connection Address",
	"sdp.connection_info.address",FT_STRING, BASE_NONE, NULL, 0x0,
	"Connection Address", HFILL }},
    { &hf_connection_info_ttl,
      { "Connection TTL",
	"sdp.connection_info.ttl",FT_STRING, BASE_NONE, NULL, 0x0,
	"Connection TTL", HFILL }},
    { &hf_connection_info_num_addr,
      { "Connection Number of Addresses",
	"sdp.connection_info.num_addr",FT_STRING, BASE_NONE, NULL, 0x0,
	"Connection Number of Addresses", HFILL }},
    { &hf_bandwidth_modifier,
      { "Bandwidth Modifier",
	"sdp.bandwidth.modifier",FT_STRING, BASE_NONE, NULL, 0x0,
	"Bandwidth Modifier", HFILL }},    
    { &hf_bandwidth_value,
      { "Bandwidth Value",
	"sdp.bandwidth.value",FT_STRING, BASE_NONE, NULL, 0x0,
	"Bandwidth Value", HFILL }},    
    { &hf_time_start,
      { "Session Start Time",
	"sdp.time.start",FT_STRING, BASE_NONE, NULL, 0x0,
	"Session Start Time", HFILL }},
    { &hf_time_stop,
      { "Session Stop Time",
	"sdp.time.stop",FT_STRING, BASE_NONE, NULL, 0x0,
	"Session Stop Time", HFILL }},
    { &hf_repeat_time_interval,
      { "Repeat Interval",
	"sdp.repeat_time.interval",FT_STRING, BASE_NONE, NULL, 0x0,
	"Repeat Interval", HFILL }},
    { &hf_repeat_time_duration,
      { "Repeat Duration",
	"sdp.repeat_time.duration",FT_STRING, BASE_NONE, NULL, 0x0,
	"Repeat Duration", HFILL }},
    { &hf_repeat_time_offset,
      { "Repeat Offset",
	"sdp.repeat_time.offset",FT_STRING, BASE_NONE, NULL, 0x0,
	"Repeat Offset", HFILL }},
    { &hf_timezone_time,
      { "Timezone Time",
	"sdp.timezone.time",FT_STRING, BASE_NONE, NULL, 0x0,
	"Timezone Time", HFILL }},
    { &hf_timezone_offset,
      { "Timezone Offset",
	"sdp.timezone.offset",FT_STRING, BASE_NONE, NULL, 0x0,
	"Timezone Offset", HFILL }},
    { &hf_encryption_key_type,
      { "Key Type",
	"sdp.encryption_key.type",FT_STRING, BASE_NONE, NULL, 0x0,
	"Type", HFILL }},
    { &hf_encryption_key_data,
      { "Key Data",
	"sdp.encryption_key.data",FT_STRING, BASE_NONE, NULL, 0x0,
	"Data", HFILL }},
    { &hf_session_attribute_field,
      { "Session Attribute Fieldname",
	"sdp.session_attr.field",FT_STRING, BASE_NONE, NULL, 0x0,
	"Session Attribute Fieldname", HFILL }},
    { &hf_session_attribute_value,
      { "Session Attribute Value",
	"sdp.session_attr.value",FT_STRING, BASE_NONE, NULL, 0x0,
	"Session Attribute Value", HFILL }},
    { &hf_media_media,
      { "Media Type",
	"sdp.media.media",FT_STRING, BASE_NONE, NULL, 0x0,
	"Media Type", HFILL }},
    { &hf_media_port,
      { "Media Port",
	"sdp.media.port",FT_STRING, BASE_NONE, NULL, 0x0,
	"Media Port", HFILL }},
    { &hf_media_portcount,
      { "Media Port Count",
	"sdp.media.portcount",FT_STRING, BASE_NONE, NULL, 0x0,
	"Media Port Count", HFILL }},
    { &hf_media_proto,
      { "Media Proto",
	"sdp.media.proto",FT_STRING, BASE_NONE, NULL, 0x0,
	"Media Proto", HFILL }},
    { &hf_media_format,
      { "Media Format",
	"sdp.media.format",FT_STRING, BASE_NONE, NULL, 0x0,
	"Media Format", HFILL }},
    { &hf_media_attribute_field,
      { "Media Attribute Fieldname",
	"sdp.media_attribute.field",FT_STRING, BASE_NONE, NULL, 0x0,
	"Media Attribute Fieldname", HFILL }},
    { &hf_media_attribute_value,
      { "Media Attribute Value",
	"sdp.media_attribute.value",FT_STRING, BASE_NONE, NULL, 0x0,
	"Media Attribute Value", HFILL }},

  };
  static gint *ett[] = {
    &ett_sdp,
    &ett_sdp_owner,
    &ett_sdp_connection_info,
    &ett_sdp_bandwidth,
    &ett_sdp_time,
    &ett_sdp_repeat_time,
    &ett_sdp_timezone,
    &ett_sdp_encryption_key,
    &ett_sdp_session_attribute,
    &ett_sdp_media,
    &ett_sdp_media_attribute,
  };
  
  proto_sdp = proto_register_protocol("Session Description Protocol",
				      "SDP", "sdp");
  proto_register_field_array(proto_sdp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
	
  /*
   * Register the dissector by name, so other dissectors can
   * grab it by name rather than just referring to it directly
   * (you can't refer to it directly from a plugin dissector
   * on Windows without stuffing it into the Big Transfer Vector).
   */
  register_dissector("sdp", dissect_sdp, proto_sdp);
}
