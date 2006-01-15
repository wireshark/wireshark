/* packet-sdp.c
 * Routines for SDP packet disassembly (RFC 2327)
 *
 * Jason Lango <jal@netapp.com>
 * Liberally copied from packet-http.c, by Guy Harris <guy@alum.mit.edu>
 *
 * $Id$
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

#include <string.h>
#include <ctype.h>

#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef NEED_INET_ATON_H
# include <epan/inet_aton.h>
#endif

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>		/* needed to define AF_ values on Windows */
#endif

#ifdef NEED_INET_V6DEFS_H
# include "inet_v6defs.h"
#endif

#include <glib.h> 
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/strutil.h>
#include <epan/emem.h>

#include "tap.h"
#include "packet-sdp.h"

#include "packet-rtp.h"
#include <epan/rtp_pt.h>
#include "packet-rtcp.h"

#include "packet-t38.h"

static dissector_handle_t rtp_handle=NULL;
static dissector_handle_t rtcp_handle=NULL;

static dissector_handle_t t38_handle=NULL;

static int sdp_tap = -1;

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
static int hf_invalid = -1;
static int hf_ipbcp_version = -1;
static int hf_ipbcp_type = -1;

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


#define SDP_MAX_RTP_CHANNELS 4
#define SDP_MAX_RTP_PAYLOAD_TYPES 20

typedef struct {
	gint32 pt[SDP_MAX_RTP_PAYLOAD_TYPES];
	gint8 pt_count;
	GHashTable *rtp_dyn_payload;
} transport_media_pt_t;

typedef struct {
	char *connection_address;
	char *connection_type;
	char *media_port[SDP_MAX_RTP_CHANNELS];
	char *media_proto[SDP_MAX_RTP_CHANNELS];
	transport_media_pt_t media[SDP_MAX_RTP_CHANNELS];
	gint8 media_count;
} transport_info_t;

/* static functions */

static void call_sdp_subdissector(tvbuff_t *tvb, int hf, proto_tree* ti,
				  transport_info_t *transport_info);

/* Subdissector functions */
static void dissect_sdp_owner(tvbuff_t *tvb, proto_item* ti);
static void dissect_sdp_connection_info(tvbuff_t *tvb, proto_item* ti,
					transport_info_t *transport_info);
static void dissect_sdp_bandwidth(tvbuff_t *tvb, proto_item *ti);
static void dissect_sdp_time(tvbuff_t *tvb, proto_item* ti);
static void dissect_sdp_repeat_time(tvbuff_t *tvb, proto_item* ti);
static void dissect_sdp_timezone(tvbuff_t *tvb, proto_item* ti);
static void dissect_sdp_encryption_key(tvbuff_t *tvb, proto_item * ti);
static void dissect_sdp_session_attribute(tvbuff_t *tvb, proto_item *ti);
static void dissect_sdp_media(tvbuff_t *tvb, proto_item *ti,
			      transport_info_t *transport_info);
static void dissect_sdp_media_attribute(tvbuff_t *tvb, proto_item *ti, transport_info_t *transport_info);

static void
dissect_sdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*sdp_tree;
	proto_item	*ti, *sub_ti;
	gint		offset = 0;
	gint		next_offset;
	int		linelen;
	gboolean        in_media_description;
	guchar		type;
	guchar          delim;
	int		datalen;
	int             tokenoffset;
	int             hf = -1;
	char            *string;

	address 	src_addr;

	transport_info_t transport_info;

	guint32 	port=0;
	gboolean 	is_rtp=FALSE;
	gboolean 	is_t38=FALSE;
	gboolean 	set_rtp=FALSE;
	gboolean 	is_ipv4_addr=FALSE;
	gboolean	is_ipv6_addr=FALSE;
    guint32 	ipaddr[4];
	gint		n,i;
	sdp_packet_info *sdp_pi;

    /* Initialise packet info for passing to tap */
    sdp_pi = ep_alloc(sizeof(sdp_packet_info));
    sdp_pi->summary_str[0] = '\0';

	/* Initialise RTP channel info */
	transport_info.connection_address=NULL;
	transport_info.connection_type=NULL;
	for (n=0; n < SDP_MAX_RTP_CHANNELS; n++)
	{
	    transport_info.media_port[n]=NULL;
	    transport_info.media_proto[n]=NULL;
		transport_info.media[n].pt_count = 0;
		transport_info.media[n].rtp_dyn_payload = g_hash_table_new( g_int_hash, g_int_equal);
	}
	transport_info.media_count = 0;

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

	ti = proto_tree_add_item(tree, proto_sdp, tvb, offset, -1, FALSE);
	sdp_tree = proto_item_add_subtree(ti, ett_sdp);

	/*
	 * Show the SDP message a line at a time.
	 */
	in_media_description = FALSE;
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
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
			break;
		case 'o':
		        hf = hf_owner;
			break;
		case 's':
		        hf = hf_session_name;
			break;
		case 'i':
		        if (in_media_description) {
			        hf = hf_media_title;
			}
			else{
			        hf = hf_session_info;
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
			break;
		case 'r':
		        hf = hf_repeat_time;
			break;
		case 'm':
		        hf = hf_media;
			in_media_description = TRUE;
			break;
		case 'k':
		        hf = hf_encryption_key;
			break;
		case 'a':
		        if (in_media_description) {
			        hf = hf_media_attribute;
			}
			else{
			        hf = hf_session_attribute;
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
		if (hf == hf_unknown)
			tokenoffset = 0;
		string = tvb_get_ephemeral_string(tvb, offset + tokenoffset,
		    linelen - tokenoffset);
		sub_ti = proto_tree_add_string_format(sdp_tree,hf,tvb, offset,
					       linelen, string,
					       "%s: %s",
					       proto_registrar_get_name(hf),
					       format_text(string,
					         linelen - tokenoffset));
		call_sdp_subdissector(tvb_new_subset(tvb,offset+tokenoffset,
						     linelen-tokenoffset,
						     linelen-tokenoffset),
				      hf,sub_ti,&transport_info),
		offset = next_offset;
	}


	/* Now look, if we have strings collected.
	 * Try to convert ipv4 addresses and ports into binary format,
	 * so we can use them to detect rtp and rtcp streams.
	 * Don't forget to free the strings!
	 */

	for (n = 0; n < transport_info.media_count; n++)
	{
	    if(transport_info.media_port[n]!=NULL) {
		    port = atol(transport_info.media_port[n]);
	    }
	    if(transport_info.media_proto[n]!=NULL) {
		    /* Check if media protocol is RTP */
		    is_rtp = (strcmp(transport_info.media_proto[n],"RTP/AVP")==0);
		    /* Check if media protocol is T38 */
		    is_t38 = ( (strcmp(transport_info.media_proto[n],"UDPTL")==0) || (strcmp(transport_info.media_proto[n],"udptl")==0) );

	    }
	    if(transport_info.connection_address!=NULL) {
		    if(transport_info.connection_type!=NULL) {
		    	if (strcmp(transport_info.connection_type,"IP4")==0) {
				    if(inet_pton(AF_INET,transport_info.connection_address, &ipaddr)==1 ) {
					    /* connection_address could be converted to a valid ipv4 address*/
					    is_ipv4_addr=TRUE;
				    	src_addr.type=AT_IPv4;
				    	src_addr.len=4;
				    }
				}
				else if (strcmp(transport_info.connection_type,"IP6")==0){
					if (inet_pton(AF_INET6, transport_info.connection_address, &ipaddr)==1){
					    /* connection_address could be converted to a valid ipv6 address*/
						is_ipv6_addr=TRUE;
					    src_addr.type=AT_IPv6;
					    src_addr.len=16;
					}
				}
		    }
	    }
		set_rtp = FALSE;
	    /* Add rtp and rtcp conversation, if available (overrides t38 if conversation already set) */
	    if((!pinfo->fd->flags.visited) && port!=0 && is_rtp && (is_ipv4_addr || is_ipv6_addr)){
		    src_addr.data=(char *)&ipaddr;
		    if(rtp_handle){
				rtp_add_address(pinfo, &src_addr, port, 0,
	                "SDP", pinfo->fd->num, transport_info.media[n].rtp_dyn_payload);
				set_rtp = TRUE;
		    }
		    if(rtcp_handle){
				port++;
				rtcp_add_address(pinfo, &src_addr, port, 0,
	                 "SDP", pinfo->fd->num);
		    }
		} 
			
	    /* Add t38 conversation, if available and only if no rtp */
	    if((!pinfo->fd->flags.visited) && port!=0 && !set_rtp && is_t38 && is_ipv4_addr){
			src_addr.data=(char *)&ipaddr;
            if(t38_handle){
				t38_add_address(pinfo, &src_addr, port, 0, "SDP", pinfo->fd->num);
            }	
	    }

		/* Create the RTP summary str for the Voip Call analysis */
		for (i = 0; i < transport_info.media[n].pt_count; i++)
		{
			/* if the payload type is dynamic (96 to 127), check the hash table to add the desc in the SDP summary */
			if ( (transport_info.media[n].pt[i] >=96) && (transport_info.media[n].pt[i] <=127) ) {
				gchar *str_dyn_pt = g_hash_table_lookup(transport_info.media[n].rtp_dyn_payload, &transport_info.media[n].pt[i]);
				if (str_dyn_pt)
					g_snprintf(sdp_pi->summary_str, 50, "%s %s", sdp_pi->summary_str, str_dyn_pt);
				else
					g_snprintf(sdp_pi->summary_str, 50, "%s %d", sdp_pi->summary_str, transport_info.media[n].pt[i]);
			} else 
				g_snprintf(sdp_pi->summary_str, 50, "%s %s", sdp_pi->summary_str, val_to_str(transport_info.media[n].pt[i], rtp_payload_type_short_vals, "%u"));
		}

		/* Free the hash table if we did't assigned it to a conv use it */
		if (set_rtp == FALSE) 
			rtp_free_hash_dyn_payload(transport_info.media[n].rtp_dyn_payload);

		/* Create the T38 summary str for the Voip Call analysis */
		if (is_t38) g_snprintf(sdp_pi->summary_str, 50, "%s t38", sdp_pi->summary_str);	
	}

	/* Free the remainded hash tables not used */
	for (n = transport_info.media_count; n < SDP_MAX_RTP_CHANNELS; n++)
	{
		rtp_free_hash_dyn_payload(transport_info.media[n].rtp_dyn_payload);
	}


	datalen = tvb_length_remaining(tvb, offset);
	if (datalen > 0) {
		proto_tree_add_text(sdp_tree, tvb, offset, datalen,
		    "Data (%d bytes)", datalen);
	}

    /* Report this packet to the tap */
    tap_queue_packet(sdp_tap, pinfo, sdp_pi);
}

static void
call_sdp_subdissector(tvbuff_t *tvb, int hf, proto_tree* ti, transport_info_t *transport_info){
  if(hf == hf_owner){
    dissect_sdp_owner(tvb,ti);
  } else if ( hf == hf_connection_info) {
    dissect_sdp_connection_info(tvb,ti,transport_info);
  } else if ( hf == hf_bandwidth) {
    dissect_sdp_bandwidth(tvb,ti);
  } else if ( hf == hf_time) {
    dissect_sdp_time(tvb,ti);
  } else if ( hf == hf_repeat_time ){
    dissect_sdp_repeat_time(tvb,ti);
  } else if ( hf == hf_timezone ) {
    dissect_sdp_timezone(tvb,ti);
  } else if ( hf == hf_encryption_key ) {
    dissect_sdp_encryption_key(tvb,ti);
  } else if ( hf == hf_session_attribute ){
    dissect_sdp_session_attribute(tvb,ti);
  } else if ( hf == hf_media ) {
    dissect_sdp_media(tvb,ti,transport_info);
  } else if ( hf == hf_media_attribute ){
    dissect_sdp_media_attribute(tvb,ti,transport_info);
  }
}

static void
dissect_sdp_owner(tvbuff_t *tvb, proto_item *ti){
  proto_tree *sdp_owner_tree;
  gint offset,next_offset,tokenlen;

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

/*
 * XXX - this can leak memory if an exception is thrown after we've fetched
 * a string.
 */
static void
dissect_sdp_connection_info(tvbuff_t *tvb, proto_item* ti,
			    transport_info_t *transport_info){
  proto_tree *sdp_connection_info_tree;
  gint offset,next_offset,tokenlen;

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
  /* Save connection address type */
  transport_info->connection_type = tvb_get_ephemeral_string(tvb, offset, tokenlen);


  proto_tree_add_item(sdp_connection_info_tree,
		      hf_connection_info_address_type,tvb,
		      offset,tokenlen,FALSE);
  offset = next_offset + 1;

  /* Find the connection address */
  /* XXX - what if there's a <number of addresses> value? */
  next_offset = tvb_find_guint8(tvb,offset,-1,'/');
  if( next_offset == -1){
    tokenlen = -1;	/* end of tvbuff */
    /* Save connection address */
    transport_info->connection_address =
        tvb_get_ephemeral_string(tvb, offset, tvb_length_remaining(tvb, offset));
  } else {
    tokenlen = next_offset - offset;
    /* Save connection address */
    transport_info->connection_address = tvb_get_ephemeral_string(tvb, offset, tokenlen);
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
dissect_sdp_bandwidth(tvbuff_t *tvb, proto_item *ti){
  proto_tree * sdp_bandwidth_tree;
  gint offset, next_offset, tokenlen;

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

static void dissect_sdp_time(tvbuff_t *tvb, proto_item* ti){
  proto_tree *sdp_time_tree;
  gint offset,next_offset, tokenlen;

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
  proto_tree_add_item(sdp_time_tree, hf_time_stop, tvb,
		      offset, -1, FALSE);
}

static void dissect_sdp_repeat_time(tvbuff_t *tvb, proto_item* ti){
  proto_tree *sdp_repeat_time_tree;
  gint offset,next_offset, tokenlen;

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
dissect_sdp_timezone(tvbuff_t *tvb, proto_item* ti){
  proto_tree* sdp_timezone_tree;
  gint offset, next_offset, tokenlen;
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


static void dissect_sdp_encryption_key(tvbuff_t *tvb, proto_item * ti){
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



static void dissect_sdp_session_attribute(tvbuff_t *tvb, proto_item * ti){
  proto_tree *sdp_session_attribute_tree;
  gint offset, next_offset, tokenlen;
  guint8 *field_name;
  
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

  field_name = tvb_get_ephemeral_string(tvb, offset, tokenlen);
  
  offset = next_offset + 1;

  if (strcmp(field_name, "ipbcp") == 0) {
	  
	  offset = tvb_pbrk_guint8(tvb,offset,-1,"0123456789");
	  
	  if (offset == -1)
		  return;
	  
	  next_offset = tvb_find_guint8(tvb,offset,-1,' ');
	  
	  if (next_offset == -1)
		  return;
	  
	  tokenlen = next_offset - offset;
	  
	  proto_tree_add_item(sdp_session_attribute_tree,hf_ipbcp_version,tvb,offset,tokenlen,FALSE);

	  offset = tvb_pbrk_guint8(tvb,offset,-1,"ABCDEFGHIJKLMNOPQRSTUVWXYZ");

	  if (offset == -1)
		  return;

	  tokenlen = tvb_find_line_end(tvb,offset,-1, &next_offset, FALSE);
	  
	  if (tokenlen == -1) 
		  return;
	  
	  proto_tree_add_item(sdp_session_attribute_tree,hf_ipbcp_type,tvb,offset,tokenlen,FALSE);
	  
  } else {
	  proto_tree_add_item(sdp_session_attribute_tree,
						  hf_session_attribute_value,
						  tvb, offset, -1, FALSE);

  }
}

static void
dissect_sdp_media(tvbuff_t *tvb, proto_item *ti,
		  transport_info_t *transport_info){
  proto_tree *sdp_media_tree;
  gint offset, next_offset, tokenlen, index;
  guint8 *media_format;

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
    /* Save port info */
    transport_info->media_port[transport_info->media_count] = tvb_get_ephemeral_string(tvb, offset, tokenlen);

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
    /* Save port info */
    transport_info->media_port[transport_info->media_count] = tvb_get_ephemeral_string(tvb, offset, tokenlen);

    /* XXX Remember Port */
    proto_tree_add_item(sdp_media_tree, hf_media_port, tvb,
			offset, tokenlen, FALSE);
    offset = next_offset + 1;
  }

  next_offset = tvb_find_guint8(tvb,offset,-1,' ');

  if( next_offset == -1)
    return;

  tokenlen = next_offset - offset;
  /* Save port protocol */
  transport_info->media_proto[transport_info->media_count] = tvb_get_ephemeral_string(tvb, offset, tokenlen);

  /* XXX Remember Protocol */
  proto_tree_add_item(sdp_media_tree, hf_media_proto, tvb,
		      offset, tokenlen, FALSE);

  do{
    offset = next_offset + 1;
    next_offset = tvb_find_guint8(tvb,offset,-1,' ');

    if(next_offset == -1){
      tokenlen = tvb_length_remaining(tvb, offset);	/* End of tvbuff */
      if (tokenlen == 0)
        break;	/* Nothing more left */
    } else {
      tokenlen = next_offset - offset;
    }
    
    if (strcmp(transport_info->media_proto[transport_info->media_count],
               "RTP/AVP") == 0) {
      media_format = tvb_get_ephemeral_string(tvb, offset, tokenlen);
      proto_tree_add_string(sdp_media_tree, hf_media_format, tvb, offset,
                             tokenlen, val_to_str(atol(media_format), rtp_payload_type_vals, "%u"));
	  index = transport_info->media[transport_info->media_count].pt_count;
	  transport_info->media[transport_info->media_count].pt[index] = atol(media_format);
	  if (index < (SDP_MAX_RTP_PAYLOAD_TYPES-1))
		  transport_info->media[transport_info->media_count].pt_count++;
    } else {
      proto_tree_add_item(sdp_media_tree, hf_media_format, tvb,
			  offset, tokenlen, FALSE);
    }
  } while (next_offset != -1);

  /* Increase the count of media channels, but don't walk off the end
     of the arrays. */
  if (transport_info->media_count < (SDP_MAX_RTP_CHANNELS-1)){
    transport_info->media_count++;
  }

  /* XXX Dissect traffic to "Port" as "Protocol"
   *     Remember this Port/Protocol pair so we can tear it down again later
   *     Actually, it's harder than that:
   *         We need to find out the address of the other side first and it
   *         looks like that info can be found in SIP headers only.
   */

}

static void dissect_sdp_media_attribute(tvbuff_t *tvb, proto_item * ti, transport_info_t *transport_info){
  proto_tree *sdp_media_attribute_tree;
  gint offset, next_offset, tokenlen, n;
  guint8 *field_name;
  guint8 *payload_type;
  guint8 *encoding_name;

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

  field_name = tvb_get_ephemeral_string(tvb, offset, tokenlen);

  offset = next_offset + 1;
  proto_tree_add_item(sdp_media_attribute_tree,
		      hf_media_attribute_value,
		      tvb, offset, -1, FALSE);

  /* decode the rtpmap to see if it is DynamicPayload to dissect them automatic */
  if (strcmp(field_name, "rtpmap") == 0) {
	gint *key;

	next_offset = tvb_find_guint8(tvb,offset,-1,' ');

    if(next_offset == -1)
		return;

    tokenlen = next_offset - offset;

    payload_type = tvb_get_ephemeral_string(tvb, offset, tokenlen);

    offset = next_offset + 1;

    next_offset = tvb_find_guint8(tvb,offset,-1,'/');

    if(next_offset == -1){
        return;
    }

    tokenlen = next_offset - offset;

    encoding_name = tvb_get_string(tvb, offset, tokenlen);

	key=g_malloc( sizeof(gint) );
	*key=atol(payload_type);

	/* As per RFC2327 it is possible to have multiple Media Descriptions ("m=") For example:

			a=rtpmap:101 G726-32/8000
			m=audio 49170 RTP/AVP 0 97
			a=rtpmap:97 telephone-event/8000
			m=audio 49172 RTP/AVP 97 101
			a=rtpmap:97 G726-24/8000

	The Media attributes ("a="s) after the "m=" only apply for that "m=". 
	If there is an "a=" before the first "m=", that attribute apply for all the session	(all the "m="s).
	*/

	/* so, if this "a=" appear before any "m=", we add it to all the dynamic hash tables */ 
	if (transport_info->media_count == 0) {
		for (n=0; n < SDP_MAX_RTP_CHANNELS; n++) {
			if (n==0)
				g_hash_table_insert(transport_info->media[n].rtp_dyn_payload, key, encoding_name);
			else {	/* we create a new key and encoding_name to assign to the other hash tables */
				gint *key2;
				key2=g_malloc( sizeof(gint) );
				*key2=atol(payload_type);
				g_hash_table_insert(transport_info->media[n].rtp_dyn_payload, key2, encoding_name);
			}
		}

	/* if the "a=" is after an "m=", only apply to this "m=" */
	} else 
		/* in case there is an overflow in SDP_MAX_RTP_CHANNELS, we keep always the last "m=" */
		if (transport_info->media_count == SDP_MAX_RTP_CHANNELS-1)
			g_hash_table_insert(transport_info->media[ transport_info->media_count ].rtp_dyn_payload, key, encoding_name);		
		else
			g_hash_table_insert(transport_info->media[ transport_info->media_count-1 ].rtp_dyn_payload, key, encoding_name);

  }
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
	"Bandwidth Value (in kbits/s)", HFILL }},
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
	"Media Protocol", HFILL }},
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
    { &hf_ipbcp_version,
      { "IPBCP Protocol Version",
	"ipbcp.version",FT_STRING, BASE_NONE, NULL, 0x0,
	"IPBCP Protocol Version", HFILL }},
    { &hf_ipbcp_type,
      { "IPBCP Command Type",
	"ipbcp.command",FT_STRING, BASE_NONE, NULL, 0x0,
	"IPBCP Command Type", HFILL }},
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

  /* Register for tapping */
  sdp_tap = register_tap("sdp");
}

void
proto_reg_handoff_sdp(void)
{
  dissector_handle_t sdp_handle;

  rtp_handle = find_dissector("rtp");
  rtcp_handle = find_dissector("rtcp");

  t38_handle = find_dissector("t38");

  sdp_handle = find_dissector("sdp");
  dissector_add_string("media_type", "application/sdp", sdp_handle);
}
