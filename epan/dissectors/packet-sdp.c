/* packet-sdp.c
 * Routines for SDP packet disassembly (RFC 2327)
 *
 * Jason Lango <jal@netapp.com>
 * Liberally copied from packet-http.c, by Guy Harris <guy@alum.mit.edu>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 * Ref http://www.ietf.org/rfc/rfc4566.txt?number=4566
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <ctype.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>           /* needed to define AF_ values on Windows */
#endif

#ifdef NEED_INET_V6DEFS_H
# include "wsutil/inet_v6defs.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/emem.h>
#include <epan/base64.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/tap.h>

#include "packet-sdp.h"
#include "packet-frame.h"
#include "packet-rtp.h"
#include <epan/rtp_pt.h>

#include "packet-rtcp.h"
#include "packet-t38.h"
#include "packet-msrp.h"
#include "packet-per.h"
#include "packet-h245.h"
#include "packet-h264.h"
#include "packet-mp4ves.h"

static dissector_handle_t rtp_handle    = NULL;
static dissector_handle_t rtcp_handle   = NULL;
static dissector_handle_t t38_handle    = NULL;
static dissector_handle_t msrp_handle   = NULL;
static dissector_handle_t h264_handle   = NULL;
static dissector_handle_t mp4ves_handle = NULL;

static int sdp_tap = -1;

static int proto_sdp = -1;

/* preference globals */
static gboolean global_sdp_establish_conversation = TRUE;

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
static int hf_media_encoding_name = -1;
static int hf_media_sample_rate = -1;
static int hf_media_format_specific_parameter = -1;
static int hf_sdp_fmtp_mpeg4_profile_level_id = -1;
static int hf_sdp_fmtp_h263_profile = -1;
static int hf_sdp_fmtp_h263_level = -1;
static int hf_sdp_h264_packetization_mode = -1;
static int hf_SDPh223LogicalChannelParameters = -1;

/* hf_session_attribute hf_media_attribute subfields */
static int hf_key_mgmt_att_value = -1;
static int hf_key_mgmt_prtcl_id = -1;
static int hf_key_mgmt_data = -1;

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
static int ett_sdp_fmtp = -1;
static int ett_sdp_key_mgmt = -1;


#define SDP_MAX_RTP_CHANNELS 4
#define SDP_MAX_RTP_PAYLOAD_TYPES 20
#define SDP_NO_OF_PT 128
typedef struct {
  gint32 pt[SDP_MAX_RTP_PAYLOAD_TYPES];
  gint8 pt_count;
  GHashTable *rtp_dyn_payload;
} transport_media_pt_t;

typedef struct {
  char *connection_address;
  char *connection_type;
  char *media_type;
  char *encoding_name[SDP_NO_OF_PT];
  int   sample_rate[SDP_NO_OF_PT];
  char *media_port[SDP_MAX_RTP_CHANNELS];
  char *media_proto[SDP_MAX_RTP_CHANNELS];
  transport_media_pt_t media[SDP_MAX_RTP_CHANNELS];
  gint8 media_count;
} transport_info_t;


/* MSRP transport info (as set while parsing path attribute) */
static gboolean msrp_transport_address_set = FALSE;
static guint32  msrp_ipaddr[4];
static guint16  msrp_port_number;

/* key-mgmt dissector
 * IANA registry:
 * http://www.iana.org/assignments/sdp-parameters
 */
static dissector_table_t key_mgmt_dissector_table;


/* Protocol registration */
void proto_register_sdp(void);
void proto_reg_handoff_sdp(void);


/* static functions */

static void call_sdp_subdissector(tvbuff_t *tvb, packet_info *pinfo, int hf, proto_tree* ti, int length,
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
static void dissect_sdp_session_attribute(tvbuff_t *tvb, packet_info *pinfo, proto_item *ti);
static void dissect_sdp_media(tvbuff_t *tvb, proto_item *ti,
                              transport_info_t *transport_info);
static void dissect_sdp_media_attribute(tvbuff_t *tvb, packet_info *pinfo, proto_item *ti, int length,transport_info_t *transport_info);

static void free_encoding_name_str (void *ptr)
{
  encoding_name_and_rate_t *encoding_name_and_rate = (encoding_name_and_rate_t *)ptr;

  if (encoding_name_and_rate->encoding_name) {
    g_free(encoding_name_and_rate->encoding_name);
  }
}

static void
dissect_sdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree  *sdp_tree;
  proto_item  *ti, *sub_ti;
  gint        offset = 0;
  gint        next_offset;
  int         linelen;
  gboolean    in_media_description;
  guchar      type;
  guchar      delim;
  int         datalen;
  int         tokenoffset;
  int         hf = -1;
  char        *string;

  address     src_addr;

  transport_info_t transport_info;

  guint32     port=0;
  gboolean    is_rtp=FALSE;
  gboolean    is_srtp=FALSE;
  gboolean    is_t38=FALSE;
  gboolean    is_msrp=FALSE;
  gboolean    set_rtp=FALSE;
  gboolean    is_ipv4_addr=FALSE;
  gboolean    is_ipv6_addr=FALSE;
  gboolean    is_video=FALSE;
  guint32     ipaddr[4];
  gint        n,i;
  sdp_packet_info *sdp_pi;
  gchar       *unknown_encoding = ep_strdup("Unknown");

  /* Initialise packet info for passing to tap */
  sdp_pi = ep_alloc(sizeof(sdp_packet_info));
  sdp_pi->summary_str[0] = '\0';

  /* Initialise RTP channel info */
  transport_info.connection_address=NULL;
  transport_info.connection_type=NULL;
  transport_info.media_type=NULL;
  for (n=0; n < SDP_NO_OF_PT; n++){
    transport_info.encoding_name[n]=unknown_encoding;
    transport_info.sample_rate[n] = 0;
  }
  for (n=0; n < SDP_MAX_RTP_CHANNELS; n++)
  {
    transport_info.media_port[n]=NULL;
    transport_info.media_proto[n]=NULL;
    transport_info.media[n].pt_count = 0;
    transport_info.media[n].rtp_dyn_payload =
        g_hash_table_new_full( g_int_hash, g_int_equal, g_free, free_encoding_name_str);
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
  col_append_str(pinfo->cinfo, COL_PROTOCOL, "/SDP");

  /* XXX: Needs description. */
  col_append_str(pinfo->cinfo, COL_INFO, ", with session description");

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
    linelen = tvb_find_line_end_unquoted(tvb, offset, -1, &next_offset);



    /*
     * Line must contain at least e.g. "v=".
     */
    if (linelen < 2)
      break;

    type = tvb_get_guint8(tvb,offset);
    delim = tvb_get_guint8(tvb,offset + 1);
    if (delim != '=') {
      proto_item *ti2 = proto_tree_add_item(sdp_tree, hf_invalid, tvb, offset, linelen, FALSE);
      expert_add_info_format(pinfo, ti2, PI_MALFORMED, PI_NOTE,
                             "Invalid SDP line (no '=' delimiter)");
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
    string = (char*)tvb_get_ephemeral_string(tvb, offset + tokenoffset,
                                             linelen - tokenoffset);
    sub_ti = proto_tree_add_string(sdp_tree, hf, tvb, offset, linelen,
                                   string);
    call_sdp_subdissector(tvb_new_subset(tvb,offset+tokenoffset,
                                         linelen-tokenoffset,
                                         linelen-tokenoffset),
                                         pinfo,
                                         hf,sub_ti,linelen-tokenoffset,&transport_info),
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
      /* Check if media protocol is RTP
       * and stream decoding is enabled in preferences
       */
       if(global_sdp_establish_conversation){
         /* Check if media protocol is RTP */
         is_rtp = (strcmp(transport_info.media_proto[n],"RTP/AVP")==0);
         /* Check if media protocol is SRTP */
         is_srtp = (strcmp(transport_info.media_proto[n],"RTP/SAVP")==0);
         /* Check if media protocol is T38 */
         is_t38 = ( (strcmp(transport_info.media_proto[n],"UDPTL")==0) ||
                    (strcmp(transport_info.media_proto[n],"udptl")==0) );
         /* Check if media protocol is MSRP/TCP */
         is_msrp = (strcmp(transport_info.media_proto[n],"msrp/tcp")==0);
       }
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
    if (strcmp(transport_info.media_type,"video")==0){
      is_video = TRUE;
    }
    set_rtp = FALSE;
    /* Add (s)rtp and (s)rtcp conversation, if available (overrides t38 if conversation already set) */
    if((!pinfo->fd->flags.visited) && port!=0 && (is_rtp||is_srtp) && (is_ipv4_addr || is_ipv6_addr)){
      src_addr.data=(guint8*)&ipaddr;
      if(rtp_handle){
        if (is_srtp) {
          struct srtp_info *dummy_srtp_info = se_alloc0(sizeof(struct srtp_info));
          srtp_add_address(pinfo, &src_addr, port, 0, "SDP", pinfo->fd->num, is_video,
                           transport_info.media[n].rtp_dyn_payload, dummy_srtp_info);
        } else {
          rtp_add_address(pinfo, &src_addr, port, 0, "SDP", pinfo->fd->num, is_video,
                          transport_info.media[n].rtp_dyn_payload);
        }
        set_rtp = TRUE;
      }
      if(rtcp_handle){
        port++;
        rtcp_add_address(pinfo, &src_addr, port, 0, "SDP", pinfo->fd->num);
      }
    }

    /* Add t38 conversation, if available and only if no rtp */
    if((!pinfo->fd->flags.visited) && port!=0 && !set_rtp && is_t38 && is_ipv4_addr){
      src_addr.data=(guint8*)&ipaddr;
      if(t38_handle){
        t38_add_address(pinfo, &src_addr, port, 0, "SDP", pinfo->fd->num);
      }
    }

    /* Add MSRP conversation.  Uses addresses discovered in attribute
       rather than connection information of media session line */
    if (is_msrp ){
      if ((!pinfo->fd->flags.visited) && msrp_transport_address_set){
        if(msrp_handle){
          src_addr.type=AT_IPv4;
          src_addr.len=4;
          src_addr.data=(guint8*)&msrp_ipaddr;
          msrp_add_address(pinfo, &src_addr, msrp_port_number, "SDP", pinfo->fd->num);
        }
      }
    }

    if (port!=0) {
      /* Create the RTP summary str for the Voip Call analysis */
      for (i = 0; i < transport_info.media[n].pt_count; i++)
      {
        /* if the payload type is dynamic (96 to 127), check the hash table to add the desc in the SDP summary */
        if ( (transport_info.media[n].pt[i] >=96) && (transport_info.media[n].pt[i] <=127) ) {
          encoding_name_and_rate_t *encoding_name_and_rate_pt = g_hash_table_lookup(transport_info.media[n].rtp_dyn_payload, &transport_info.media[n].pt[i]);
          if (encoding_name_and_rate_pt) {
            if (strlen(sdp_pi->summary_str)) g_strlcat(sdp_pi->summary_str, " ", 50);
            g_strlcat(sdp_pi->summary_str, encoding_name_and_rate_pt->encoding_name, 50);
          } else {
            char num_pt[10];
            g_snprintf(num_pt, 10, "%u", transport_info.media[n].pt[i]);
            if (strlen(sdp_pi->summary_str)) g_strlcat(sdp_pi->summary_str, " ", 50);
            g_strlcat(sdp_pi->summary_str, num_pt, 50);
          }
        } else
          if (strlen(sdp_pi->summary_str)) g_strlcat(sdp_pi->summary_str, " ", 50);
          g_strlcat(sdp_pi->summary_str, val_to_str_ext(transport_info.media[n].pt[i], &rtp_payload_type_short_vals_ext, "%u"), 50);
      }
    }

    /* Free the hash table if we did't assigned it to a conv use it */
    if (set_rtp == FALSE)
      rtp_free_hash_dyn_payload(transport_info.media[n].rtp_dyn_payload);

    /* Create the T38 summary str for the Voip Call analysis */
    if (port!=0 && is_t38) {
      if (strlen(sdp_pi->summary_str)) g_strlcat(sdp_pi->summary_str, " ", 50);
      g_strlcat(sdp_pi->summary_str, "t38", 50);
    }
  }

  /* Free the remainded hash tables not used */
  for (n = transport_info.media_count; n < SDP_MAX_RTP_CHANNELS; n++)
  {
    rtp_free_hash_dyn_payload(transport_info.media[n].rtp_dyn_payload);
  }


  datalen = tvb_length_remaining(tvb, offset);
  if (datalen > 0) {
    proto_tree_add_text(sdp_tree, tvb, offset, datalen, "Data (%d bytes)",
                        datalen);
  }

  /* Report this packet to the tap */
  tap_queue_packet(sdp_tap, pinfo, sdp_pi);
}

static void
call_sdp_subdissector(tvbuff_t *tvb, packet_info *pinfo, int hf, proto_tree* ti, int length,transport_info_t *transport_info){
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
    dissect_sdp_session_attribute(tvb,pinfo,ti);
  } else if ( hf == hf_media ) {
    dissect_sdp_media(tvb,ti,transport_info);
  } else if ( hf == hf_media_attribute ){
    dissect_sdp_media_attribute(tvb,pinfo,ti, length, transport_info);
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

  proto_tree_add_item(sdp_owner_tree, hf_owner_username, tvb, offset, tokenlen,
                      FALSE);
  offset = next_offset  + 1;

  /* Find the session id */
  next_offset = tvb_find_guint8(tvb,offset,-1,' ');
  if( next_offset == -1 )
    return;
  tokenlen = next_offset - offset;

  proto_tree_add_item(sdp_owner_tree, hf_owner_sessionid, tvb, offset,
                      tokenlen, FALSE);
  offset = next_offset + 1;

  /* Find the version */
  next_offset = tvb_find_guint8(tvb,offset,-1,' ');
  if( next_offset == -1 )
    return;
  tokenlen = next_offset - offset;

  proto_tree_add_item(sdp_owner_tree, hf_owner_version, tvb, offset, tokenlen,
                      FALSE);
  offset = next_offset + 1;

  /* Find the network type */
  next_offset = tvb_find_guint8(tvb,offset,-1,' ');
  if( next_offset == -1 )
    return;
  tokenlen = next_offset - offset;

  proto_tree_add_item(sdp_owner_tree, hf_owner_network_type, tvb, offset,
                      tokenlen, FALSE);
  offset = next_offset + 1;

  /* Find the address type */
  next_offset = tvb_find_guint8(tvb,offset,-1,' ');
  if( next_offset == -1 )
    return;
  tokenlen = next_offset - offset;

  proto_tree_add_item(sdp_owner_tree, hf_owner_address_type, tvb, offset,
                      tokenlen, FALSE);
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
                      hf_connection_info_network_type, tvb, offset, tokenlen,
                      FALSE);
  offset = next_offset + 1;

  /* Find the address type */
  next_offset = tvb_find_guint8(tvb,offset,-1,' ');
  if( next_offset == -1 )
    return;
  tokenlen = next_offset - offset;
  /* Save connection address type */
  transport_info->connection_type = (char*)tvb_get_ephemeral_string(tvb, offset, tokenlen);


  proto_tree_add_item(sdp_connection_info_tree,
                      hf_connection_info_address_type, tvb, offset, tokenlen,
                      FALSE);
  offset = next_offset + 1;

  /* Find the connection address */
  /* XXX - what if there's a <number of addresses> value? */
  next_offset = tvb_find_guint8(tvb,offset,-1,'/');
  if( next_offset == -1){
    tokenlen = -1; /* end of tvbuff */
    /* Save connection address */
    transport_info->connection_address =
        (char*)tvb_get_ephemeral_string(tvb, offset, tvb_length_remaining(tvb, offset));
  } else {
    tokenlen = next_offset - offset;
    /* Save connection address */
    transport_info->connection_address = (char*)tvb_get_ephemeral_string(tvb, offset, tokenlen);
  }

  proto_tree_add_item(sdp_connection_info_tree,
                      hf_connection_info_connection_address, tvb, offset,
                      tokenlen, FALSE);
  if(next_offset != -1){
    offset = next_offset + 1;
    next_offset = tvb_find_guint8(tvb,offset,-1,'/');
    if( next_offset == -1){
      tokenlen = -1; /* end of tvbuff */
    } else {
      tokenlen = next_offset - offset;
    }
    proto_tree_add_item(sdp_connection_info_tree,
                        hf_connection_info_ttl, tvb, offset, tokenlen, FALSE);
    if(next_offset != -1){
      offset = next_offset + 1;
      proto_tree_add_item(sdp_connection_info_tree,
                          hf_connection_info_num_addr, tvb, offset, -1, FALSE);
    }
  }
}

static void
dissect_sdp_bandwidth(tvbuff_t *tvb, proto_item *ti){
  proto_tree * sdp_bandwidth_tree;
  gint offset, next_offset, tokenlen;
  proto_item *item;
  gboolean unit_is_kbs = FALSE;
  gboolean unit_is_bps = FALSE;

  offset = 0;
  next_offset = 0;
  tokenlen = 0;

  sdp_bandwidth_tree = proto_item_add_subtree(ti,ett_sdp_bandwidth);

  /* find the modifier */
  next_offset = tvb_find_guint8(tvb,offset,-1,':');

  if( next_offset == -1)
    return;

  tokenlen = next_offset - offset;

  item = proto_tree_add_item(sdp_bandwidth_tree, hf_bandwidth_modifier, tvb, offset,
                      tokenlen, FALSE);
  if (tvb_strneql(tvb, offset, "CT", 2) == 0){
    proto_item_append_text(item, " [Conference Total(total bandwidth of all RTP sessions)]");
    unit_is_kbs = TRUE;
  }else if (tvb_strneql(tvb, offset, "AS", 2) == 0){
    proto_item_append_text(item, " [Application Specific (RTP session bandwidth)]");
    unit_is_kbs = TRUE;
  }else if (tvb_strneql(tvb, offset, "TIAS", 4) == 0){
    proto_item_append_text(item, " [Transport Independent Application Specific maximum]");
    unit_is_bps = TRUE;
  }


  offset = next_offset + 1;

  item = proto_tree_add_item(sdp_bandwidth_tree, hf_bandwidth_value, tvb, offset, -1,
                      FALSE);
  if (unit_is_kbs == TRUE)
    proto_item_append_text(item, " kb/s");
  if (unit_is_bps == TRUE)
    proto_item_append_text(item, " b/s");
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
  proto_tree_add_item(sdp_time_tree, hf_time_start, tvb, offset, tokenlen,
                      FALSE);

  /* get stop time */
  offset = next_offset + 1;
  proto_tree_add_item(sdp_time_tree, hf_time_stop, tvb, offset, -1, FALSE);
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
      tokenlen = -1; /* end of tvbuff */
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

    proto_tree_add_item(sdp_timezone_tree, hf_timezone_time, tvb, offset,
                        tokenlen, FALSE);
    offset = next_offset + 1;
    next_offset = tvb_find_guint8(tvb,offset,-1,' ');
    if(next_offset != -1){
      tokenlen = next_offset - offset;
    } else {
      tokenlen = -1; /* end of tvbuff */
    }
    proto_tree_add_item(sdp_timezone_tree, hf_timezone_offset, tvb, offset,
                        tokenlen, FALSE);
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

static void dissect_key_mgmt(tvbuff_t *tvb, packet_info * pinfo, proto_item * ti){
  gchar *data_p = NULL;
  gchar *prtcl_id = NULL;
  gint len;
  tvbuff_t *keymgmt_tvb;
  gboolean found_match = FALSE;
  proto_tree *key_tree;
  gint next_offset;
  gint offset = 0;
  gint tokenlen;

  key_tree = proto_item_add_subtree(ti, ett_sdp_key_mgmt);

  next_offset = tvb_find_guint8(tvb,offset,-1,' ');

  if (next_offset == -1)
    return;

  tokenlen = next_offset - offset;
  prtcl_id = tvb_get_ephemeral_string(tvb, offset, tokenlen);

  proto_tree_add_item(key_tree, hf_key_mgmt_prtcl_id, tvb, offset, tokenlen, FALSE);

  offset = next_offset + 1;

  len = tvb_length_remaining(tvb, offset);
  if (len < 0)
    return;

  data_p = tvb_get_ephemeral_string(tvb, offset, len);
  keymgmt_tvb = base64_to_tvb(tvb, data_p);
  add_new_data_source(pinfo, keymgmt_tvb, "Key Management Data");

  if ( prtcl_id != NULL && key_mgmt_dissector_table != NULL ) {
    found_match = dissector_try_string(key_mgmt_dissector_table,
                                       prtcl_id,
                                       keymgmt_tvb, pinfo,
                                       key_tree);
  }

  if (found_match) {
    proto_item *ti2 = proto_tree_add_item(key_tree, hf_key_mgmt_data,
                                         keymgmt_tvb, 0, -1, ENC_NA);
    PROTO_ITEM_SET_HIDDEN(ti2);
  }
  else {
    proto_tree_add_item(key_tree, hf_key_mgmt_data,
                        keymgmt_tvb, 0, -1, ENC_NA);
  }

}


static void dissect_sdp_session_attribute(tvbuff_t *tvb, packet_info * pinfo, proto_item * ti){
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

  proto_tree_add_item(sdp_session_attribute_tree, hf_session_attribute_field,
                      tvb, offset, tokenlen, FALSE);

  field_name = tvb_get_ephemeral_string(tvb, offset, tokenlen);

  offset = next_offset + 1;

  if (strcmp((char*)field_name, "ipbcp") == 0) {
    offset = tvb_pbrk_guint8(tvb,offset,-1,(guint8 *)"0123456789", NULL);

    if (offset == -1)
      return;

    next_offset = tvb_find_guint8(tvb,offset,-1,' ');

    if (next_offset == -1)
      return;

    tokenlen = next_offset - offset;

    proto_tree_add_item(sdp_session_attribute_tree,hf_ipbcp_version,tvb,offset,tokenlen,FALSE);

    offset = tvb_pbrk_guint8(tvb,offset,-1,(guint8 *)"ABCDEFGHIJKLMNOPQRSTUVWXYZ", NULL);

    if (offset == -1)
      return;

    tokenlen = tvb_find_line_end(tvb,offset,-1, &next_offset, FALSE);

    if (tokenlen == -1)
      return;

    proto_tree_add_item(sdp_session_attribute_tree,hf_ipbcp_type,tvb,offset,tokenlen,FALSE);
  } else if (strcmp((char*)field_name, "key-mgmt") == 0) {
    tvbuff_t *key_tvb;
    proto_item *key_ti;

    key_tvb = tvb_new_subset_remaining(tvb, offset);
    key_ti = proto_tree_add_item(sdp_session_attribute_tree, hf_key_mgmt_att_value, key_tvb, 0, -1, FALSE);

    dissect_key_mgmt(key_tvb, pinfo, key_ti);
  } else {
    proto_tree_add_item(sdp_session_attribute_tree, hf_session_attribute_value,
                        tvb, offset, -1, FALSE);
  }
}


/* Dissect media description */
static void
dissect_sdp_media(tvbuff_t *tvb, proto_item *ti,
                  transport_info_t *transport_info){
  proto_tree *sdp_media_tree;
  gint offset, next_offset, tokenlen, idx;
  guint8 *media_format;

  offset = 0;
  next_offset = 0;
  tokenlen = 0;

  /* Re-initialise for a new media description */
  msrp_transport_address_set = FALSE;

  /* Create tree for media session */
  sdp_media_tree = proto_item_add_subtree(ti,ett_sdp_media);

  next_offset = tvb_find_guint8(tvb,offset, -1, ' ');

  if(next_offset == -1)
    return;

  tokenlen = next_offset - offset;

  /* Type of media session */
  proto_tree_add_item(sdp_media_tree, hf_media_media, tvb, offset, tokenlen,
                      FALSE);

  transport_info->media_type = (char*)tvb_get_ephemeral_string(tvb, offset, tokenlen);

  offset = next_offset + 1;

  next_offset = tvb_find_guint8(tvb,offset, -1, ' ');
  if(next_offset == -1)
    return;
  tokenlen = next_offset - offset;
  next_offset = tvb_find_guint8(tvb,offset, tokenlen, '/');

  if(next_offset != -1){
    tokenlen = next_offset - offset;
    /* Save port info */
    transport_info->media_port[transport_info->media_count] = (char*)tvb_get_ephemeral_string(tvb, offset, tokenlen);

    proto_tree_add_uint(sdp_media_tree, hf_media_port, tvb, offset, tokenlen,
                        atoi((char*)tvb_get_ephemeral_string(tvb, offset, tokenlen)));
    offset = next_offset + 1;
    next_offset = tvb_find_guint8(tvb,offset, -1, ' ');
    if(next_offset == -1)
      return;
    tokenlen = next_offset - offset;
    proto_tree_add_item(sdp_media_tree, hf_media_portcount, tvb, offset,
                        tokenlen, FALSE);
    offset = next_offset + 1;
  } else {
    next_offset = tvb_find_guint8(tvb,offset, -1, ' ');

    if(next_offset == -1)
      return;
    tokenlen = next_offset - offset;
    /* Save port info */
    transport_info->media_port[transport_info->media_count] = (char*)tvb_get_ephemeral_string(tvb, offset, tokenlen);

    /* XXX Remember Port */
    proto_tree_add_uint(sdp_media_tree, hf_media_port, tvb, offset, tokenlen,
                        atoi((char*)tvb_get_ephemeral_string(tvb, offset, tokenlen)));
    offset = next_offset + 1;
  }

  next_offset = tvb_find_guint8(tvb,offset,-1,' ');

  if( next_offset == -1)
    return;

  tokenlen = next_offset - offset;
  /* Save port protocol */
  transport_info->media_proto[transport_info->media_count] = (char*)tvb_get_ephemeral_string(tvb, offset, tokenlen);

  /* XXX Remember Protocol */
  proto_tree_add_item(sdp_media_tree, hf_media_proto, tvb, offset, tokenlen,
                      FALSE);

  do {
    offset = next_offset + 1;
    next_offset = tvb_find_guint8(tvb,offset,-1,' ');

    if(next_offset == -1){
      tokenlen = tvb_length_remaining(tvb, offset); /* End of tvbuff */
      if (tokenlen == 0)
        break; /* Nothing more left */
    } else {
      tokenlen = next_offset - offset;
    }

    if (strcmp(transport_info->media_proto[transport_info->media_count],
               "RTP/AVP") == 0) {
      media_format = tvb_get_ephemeral_string(tvb, offset, tokenlen);
      proto_tree_add_string(sdp_media_tree, hf_media_format, tvb, offset,
                            tokenlen, val_to_str_ext(atol((char*)media_format), &rtp_payload_type_vals_ext, "%u"));
      idx = transport_info->media[transport_info->media_count].pt_count;
      transport_info->media[transport_info->media_count].pt[idx] = atol((char*)media_format);
      if (idx < (SDP_MAX_RTP_PAYLOAD_TYPES-1))
        transport_info->media[transport_info->media_count].pt_count++;
    } else {
      proto_tree_add_item(sdp_media_tree, hf_media_format, tvb, offset,
                          tokenlen, FALSE);
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

static tvbuff_t *
ascii_bytes_to_tvb(tvbuff_t *tvb, packet_info *pinfo, gint len, gchar *msg)
{
  guint8 *buf = g_malloc(10240);

  /* arbitrary maximum length */
  if(len<20480){
    int i;
    tvbuff_t *bytes_tvb;

    /* first, skip to where the encoded pdu starts, this is
       the first hex digit after the '=' char.
    */
    while(1){
      if((*msg==0)||(*msg=='\n')){
        return NULL;
      }
      if(*msg=='='){
        msg++;
        break;
      }
      msg++;
    }
    while(1){
      if((*msg==0)||(*msg=='\n')){
        return NULL;
      }
      if( ((*msg>='0')&&(*msg<='9'))
          ||  ((*msg>='a')&&(*msg<='f'))
          ||  ((*msg>='A')&&(*msg<='F'))){
        break;
      }
      msg++;
    }
    i=0;
    while( ((*msg>='0')&&(*msg<='9'))
           ||((*msg>='a')&&(*msg<='f'))
           ||((*msg>='A')&&(*msg<='F'))  ){
      int val;
      if((*msg>='0')&&(*msg<='9')){
        val=(*msg)-'0';
      } else if((*msg>='a')&&(*msg<='f')){
        val=(*msg)-'a'+10;
      } else if((*msg>='A')&&(*msg<='F')){
        val=(*msg)-'A'+10;
      } else {
        return NULL;
      }
      val<<=4;
      msg++;
      if((*msg>='0')&&(*msg<='9')){
        val|=(*msg)-'0';
      } else if((*msg>='a')&&(*msg<='f')){
        val|=(*msg)-'a'+10;
      } else if((*msg>='A')&&(*msg<='F')){
        val|=(*msg)-'A'+10;
      } else {
        return NULL;
      }
      msg++;

      buf[i]=(guint8)val;
      i++;
    }
    if(i==0){
      return NULL;
    }
    bytes_tvb = tvb_new_child_real_data(tvb, buf,i,i);
    tvb_set_free_cb(bytes_tvb, g_free);
    add_new_data_source(pinfo, bytes_tvb, "ASCII bytes to tvb");
    return bytes_tvb;
  }
  return NULL;
}

/* Annex X Profiles and levels definition */
static const value_string h263_profile_vals[] =
{
  { 0,    "Baseline Profile" },
  { 1,    "H.320 Coding Efficiency Version 2 Backward-Compatibility Profile" },
  { 2,    "Version 1 Backward-Compatibility Profile" },
  { 3,    "Version 2 Interactive and Streaming Wireless Profile" },
  { 4,    "Version 3 Interactive and Streaming Wireless Profile" },
  { 5,    "Conversational High Compression Profile" },
  { 6,    "Conversational Internet Profile" },
  { 7,    "Conversational Interlace Profile" },
  { 8,    "High Latency Profile" },
  { 0, NULL },
};


/* RFC 4629 The level are described in table X.2 of H.263 annex X */
static const value_string h263_level_vals[] =
{
  { 10,    "QCIF (176 x 144), 1 x 64Kb/s" },
  { 20,    "CIF (352 x 288), 2 x 64Kb/s" },
  { 30,    "CIF (352 x 288), 6 x 64Kb/s" },
  { 40,    "CIF (352 x 288), 32 x 64Kb/s" },
  { 45,    "QCIF (176 x144) support of CPFMT, 2 x 64Kb/s" },
  { 50,    "CIF (352 x 288) support of CPFMT, 64 x 64Kb/s" },
  { 60,    "CPFMT: 720 x 288 support of CPFMT, 128 x 64Kb/s" },
  { 70,    "CPFMT: 720 x 576 support of CPFMT, 256 x 64Kb/s" },
  { 0, NULL },
};


static const value_string h264_packetization_mode_vals[] =
{
  { 0,    "Single NAL mode" },
  { 1,    "Non-interleaved mode" },
  { 2,    "Interleaved mode" },
  { 0, NULL },
};

/*
 * TODO: Make this a more generic routine to dissect fmtp parameters depending on media types
 */
static void
decode_sdp_fmtp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint offset, gint tokenlen, char *mime_type){
  gint next_offset;
  gint end_offset;
  guint8 *field_name;
  gchar *format_specific_parameter;
  proto_item *item;
  tvbuff_t *data_tvb;

  end_offset = offset + tokenlen;

  /*
  proto_tree_add_text(tree, tvb, offset, tokenlen, "Debug; Analysed string: '%s'",
  tvb_get_ephemeral_string(tvb, offset, tokenlen));
  */

  /* Look for an '=' within this value - this may indicate that there is a
     profile-level-id parameter to find if the MPEG4 media type is in use */
  next_offset = tvb_find_guint8(tvb,offset,-1,'=');
  if (next_offset == -1)
  {
    /* Give up (and avoid exception) if '=' not found */
    return;
  }

  /* Find the name of the parameter */
  tokenlen = next_offset - offset;
  field_name = tvb_get_ephemeral_string(tvb, offset, tokenlen);
  /*proto_tree_add_text(tree, tvb, offset, tokenlen, "Debug; MIMEtype '%s'Parameter name: '%s'", mime_type, field_name); */

  offset = next_offset;

  /* Dissect the MPEG4 profile-level-id parameter if present */
  if (mime_type != NULL && g_ascii_strcasecmp(mime_type, "MP4V-ES") == 0) {
    if (strcmp((char*)field_name, "profile-level-id") == 0) {
      offset++;
      tokenlen = end_offset - offset;
      format_specific_parameter = tvb_get_ephemeral_string(tvb, offset, tokenlen);
      item = proto_tree_add_uint(tree, hf_sdp_fmtp_mpeg4_profile_level_id, tvb, offset, tokenlen,
                                 atol((char*)format_specific_parameter));
      PROTO_ITEM_SET_GENERATED(item);
    } else if (strcmp((char*)field_name, "config") == 0) {
      /* String including "=" */
      tokenlen = end_offset - offset;
      format_specific_parameter = tvb_get_ephemeral_string(tvb, offset, tokenlen);
      /* ascii_bytes_to_tvb requires the "=" to be in the buffer */
      data_tvb = ascii_bytes_to_tvb(tvb, pinfo, tokenlen, format_specific_parameter);
      if(mp4ves_handle && data_tvb){
        dissect_mp4ves_config(data_tvb, pinfo, tree);
      }
    }
  }

  /* Dissect the H263-2000 profile parameter if present */
  if ((mime_type != NULL && g_ascii_strcasecmp(mime_type, "H263-2000") == 0)||(mime_type != NULL && g_ascii_strcasecmp(mime_type, "H263-1998") == 0)) {
    if (strcmp((char*)field_name, "profile") == 0) {
      offset++;
      tokenlen = end_offset - offset;
      format_specific_parameter = tvb_get_ephemeral_string(tvb, offset, tokenlen);
      item = proto_tree_add_uint(tree, hf_sdp_fmtp_h263_profile, tvb, offset, tokenlen,
                                 atol((char*)format_specific_parameter));
      PROTO_ITEM_SET_GENERATED(item);
    } else if(strcmp((char*)field_name, "level") == 0) {
      offset++;
      tokenlen = end_offset - offset;
      format_specific_parameter = tvb_get_ephemeral_string(tvb, offset, tokenlen);
      item = proto_tree_add_uint(tree, hf_sdp_fmtp_h263_level, tvb, offset, tokenlen,
                                 atol((char*)format_specific_parameter));
      PROTO_ITEM_SET_GENERATED(item);
    }
  }


  /* Dissect the H264 profile-level-id parameter
   * RFC 3984:
   * A base16 [6] (hexadecimal) representation of
   * the following three bytes in the sequence
   * parameter set NAL unit specified in [1]: 1)
   * profile_idc, 2) a byte herein referred to as
   * profile-iop, composed of the values of
   * constraint_set0_flag, constraint_set1_flag,
   * constraint_set2_flag, and reserved_zero_5bits
   * in bit-significance order, starting from the
   * most significant bit, and 3) level_idc.
   */
  if (mime_type != NULL && g_ascii_strcasecmp(mime_type, "H264") == 0) {
    if (strcmp(field_name, "profile-level-id") == 0) {
      int length = 0;

      /* Length includes "=" as it's required by ascii_bytes_to_tvb()*/
      tokenlen = end_offset - offset;
      format_specific_parameter = tvb_get_ephemeral_string(tvb, offset, tokenlen);
      data_tvb = ascii_bytes_to_tvb(tvb, pinfo, tokenlen, format_specific_parameter);
      if(!data_tvb){
        proto_tree_add_text(tree, tvb, offset, tokenlen, "Could not convert '%s' to 3 bytes",format_specific_parameter);
        return;
      }
      length = tvb_length(data_tvb);
      if (length == 3){
        if(h264_handle && data_tvb){
          dissect_h264_profile(data_tvb, pinfo, tree);
        }
      }else{
        item = proto_tree_add_text(tree, tvb, offset, tokenlen, "Incorrectly coded, must be three bytes");
        PROTO_ITEM_SET_GENERATED(item);
      }
    }else if (strcmp(field_name, "packetization-mode") == 0) {
      offset++;
      tokenlen = end_offset - offset;
      format_specific_parameter = tvb_get_ephemeral_string(tvb, offset, tokenlen);
      item = proto_tree_add_uint(tree, hf_sdp_h264_packetization_mode, tvb, offset, tokenlen,
                                 atol((char*)format_specific_parameter));
      PROTO_ITEM_SET_GENERATED(item);

    }else if (strcmp(field_name, "sprop-parameter-sets") == 0) {
      /* The value of the parameter is the
         base64 [6] representation of the initial
         parameter set NAL units as specified in
         sections 7.3.2.1 and 7.3.2.2 of [1].  The
         parameter sets are conveyed in decoding order,
         and no framing of the parameter set NAL units
         takes place.  A comma is used to separate any
         pair of parameter sets in the list.
      */
      gchar *data_p = NULL;
      gint comma_offset;


      /* Move past '=' */
      offset++;
      comma_offset = tvb_find_guint8(tvb,offset,-1,',');
      if (comma_offset != -1){
        tokenlen = comma_offset - offset;
      }else{
        tokenlen = end_offset - offset;
      }

      data_p = tvb_get_ephemeral_string(tvb, offset, tokenlen);
      proto_tree_add_text(tree, tvb, offset, tokenlen, "NAL unit 1 string: %s", data_p);

      /* proto_tree_add_text(tree, tvb, offset, tokenlen, "String %s",data_p); */
      data_tvb = base64_to_tvb(tvb, data_p);
      add_new_data_source(pinfo, data_tvb, "h264 prop-parameter-sets");

      if(h264_handle && data_tvb){
        TRY {
          dissect_h264_nal_unit(data_tvb, pinfo, tree);
		}
        CATCH(BoundsError) {
          RETHROW;
		}
        CATCH(ReportedBoundsError) {
          show_reported_bounds_error(tvb, pinfo, tree);
		}
        ENDTRY;
        if (comma_offset != -1){
          /* Second NAL unit */
          offset = comma_offset +1;
          tokenlen = end_offset - offset;
          data_p = tvb_get_ephemeral_string(tvb, offset, tokenlen);
          proto_tree_add_text(tree, tvb, offset, tokenlen, "NAL unit 2 string: %s", data_p);
          data_tvb = base64_to_tvb(tvb, data_p);
          add_new_data_source(pinfo, data_tvb, "h264 prop-parameter-sets 2");
          dissect_h264_nal_unit(data_tvb, pinfo, tree);
        }
      }
    }
  }

}

typedef struct {
        const char *name;
} sdp_names_t;

#define SDP_RTPMAP              1
#define SDP_FMTP                2
#define SDP_PATH                3
#define SDP_H248_ITEM   4

static const sdp_names_t sdp_media_attribute_names[] = {
  { "Unknown-name"},    /* 0 Pad so that the real headers start at index 1 */
  { "rtpmap"},          /* 1 */
  { "fmtp"},            /* 2 */
  { "path"},            /* 3 */
  { "h248item"},        /* 4 */
};

static gint find_sdp_media_attribute_names(tvbuff_t *tvb, int offset, guint len)
{
  guint i;

  for (i = 1; i < array_length(sdp_media_attribute_names); i++) {
    if (len == strlen(sdp_media_attribute_names[i].name) &&
        tvb_strncaseeql(tvb, offset, sdp_media_attribute_names[i].name, len) == 0)
      return i;
  }

  return -1;
}

static void dissect_sdp_media_attribute(tvbuff_t *tvb, packet_info *pinfo, proto_item * ti, int length, transport_info_t *transport_info){
  proto_tree *sdp_media_attribute_tree;
  proto_item *fmtp_item, *media_format_item;
  proto_tree *fmtp_tree;
  gint offset, next_offset, tokenlen, n, colon_offset;
  /*??guint8 *field_name;*/
  guint8 *payload_type;
  guint8 *attribute_value;
  gint   *key;
  guint8 pt;
  gint  sdp_media_attrbute_code;
  const char *msrp_res = "msrp://";
  const char *h324ext_h223lcparm = "h324ext/h223lcparm";
  gboolean has_more_pars = TRUE;
  tvbuff_t *h245_tvb;
  encoding_name_and_rate_t *encoding_name_and_rate;

  offset = 0;
  next_offset = 0;
  tokenlen = 0;

  /* Create attribute tree */
  sdp_media_attribute_tree = proto_item_add_subtree(ti,
                                                    ett_sdp_media_attribute);
  /* Find end of field */
  colon_offset = tvb_find_guint8(tvb,offset,-1,':');

  if(colon_offset == -1)
    return;

  /* Attribute field name is token before ':' */
  tokenlen = colon_offset - offset;
  proto_tree_add_item(sdp_media_attribute_tree,
                      hf_media_attribute_field,
                      tvb, offset, tokenlen, FALSE);
  /*??field_name = tvb_get_ephemeral_string(tvb, offset, tokenlen);*/
  sdp_media_attrbute_code = find_sdp_media_attribute_names(tvb, offset, tokenlen);

  /* Skip colon */
  offset = colon_offset + 1;
  /* skip leading wsp */
  offset = tvb_skip_wsp(tvb,offset,tvb_length_remaining(tvb,offset));

  /* Value is the remainder of the line */
  attribute_value = tvb_get_ephemeral_string(tvb, offset, tvb_length_remaining(tvb, offset));



  /*********************************************/
  /* Special parsing for some field name types */

  switch (sdp_media_attrbute_code){
  case SDP_RTPMAP:
    /* decode the rtpmap to see if it is DynamicPayload to dissect them automatic */
    next_offset = tvb_find_guint8(tvb,offset,-1,' ');

    if(next_offset == -1)
      return;

    tokenlen = next_offset - offset;

    proto_tree_add_item(sdp_media_attribute_tree, hf_media_format, tvb,
                        offset, tokenlen, FALSE);

    payload_type = tvb_get_ephemeral_string(tvb, offset, tokenlen);

    offset = next_offset + 1;

    next_offset = tvb_find_guint8(tvb,offset,-1,'/');

    if(next_offset == -1){
      return;
    }

    tokenlen = next_offset - offset;

    proto_tree_add_item(sdp_media_attribute_tree, hf_media_encoding_name, tvb,
                        offset, tokenlen, FALSE);

    key=g_malloc( sizeof(gint) );
    *key=atol((char*)payload_type);
    pt = atoi((char*)payload_type);
    if (pt >= SDP_NO_OF_PT) {
      return;   /* Invalid */
    }
    transport_info->encoding_name[pt] = (char*)tvb_get_ephemeral_string(tvb, offset, tokenlen);

    next_offset =  next_offset + 1;
    offset = next_offset;
    while (length-1 >= next_offset){
      if(!isdigit(tvb_get_guint8(tvb, next_offset)))
        break;
      next_offset++;
    }
    tokenlen = next_offset - offset;
    proto_tree_add_item(sdp_media_attribute_tree, hf_media_sample_rate, tvb,
                        offset, tokenlen, FALSE);
    transport_info->sample_rate[pt] = atoi(tvb_get_ephemeral_string(tvb, offset, tokenlen));
    /* As per RFC2327 it is possible to have multiple Media Descriptions ("m=").
       For example:

       a=rtpmap:101 G726-32/8000
       m=audio 49170 RTP/AVP 0 97
       a=rtpmap:97 telephone-event/8000
       m=audio 49172 RTP/AVP 97 101
       a=rtpmap:97 G726-24/8000

       The Media attributes ("a="s) after the "m=" only apply for that "m=".
       If there is an "a=" before the first "m=", that attribute applies for
       all the session (all the "m="s).
    */

    /* so, if this "a=" appear before any "m=", we add it to all the dynamic
     * hash tables
     */
    if (transport_info->media_count == 0) {
      for (n=0; n < SDP_MAX_RTP_CHANNELS; n++) {
        encoding_name_and_rate = g_malloc( sizeof(encoding_name_and_rate_t));
        encoding_name_and_rate->encoding_name = g_strdup(transport_info->encoding_name[pt]);
        encoding_name_and_rate->sample_rate = transport_info->sample_rate[pt];
        if (n==0){
          g_hash_table_insert(transport_info->media[n].rtp_dyn_payload,
                              key, encoding_name_and_rate);
        }
        else {    /* we create a new key and encoding_name to assign to the other hash tables */
          gint *key2;
          key2=g_malloc( sizeof(gint) );
          *key2=atol((char*)payload_type);
          g_hash_table_insert(transport_info->media[n].rtp_dyn_payload,
                              key2, encoding_name_and_rate);
        }
      }
      return;
      /* if the "a=" is after an "m=", only apply to this "m=" */
    }else
      /* in case there is an overflow in SDP_MAX_RTP_CHANNELS, we keep always the last "m=" */
      encoding_name_and_rate = g_malloc( sizeof(encoding_name_and_rate_t));

    encoding_name_and_rate->encoding_name = g_strdup(transport_info->encoding_name[pt]);
    encoding_name_and_rate->sample_rate = transport_info->sample_rate[pt];
    if (transport_info->media_count == SDP_MAX_RTP_CHANNELS-1)
      g_hash_table_insert(transport_info->media[ transport_info->media_count ].rtp_dyn_payload,
                          key, encoding_name_and_rate);
    else
      g_hash_table_insert(transport_info->media[ transport_info->media_count-1 ].rtp_dyn_payload,
                            key, encoding_name_and_rate);
    break;
  case SDP_FMTP:
    if(sdp_media_attribute_tree){
      guint8 media_format;
      /* Reading the Format parameter(fmtp) */
      /* Skip leading space, if any */
      offset = tvb_skip_wsp(tvb,offset,tvb_length_remaining(tvb,offset));
      /* Media format extends to the next space */
      next_offset = tvb_find_guint8(tvb,offset,-1,' ');

      if(next_offset == -1)
        return;

      tokenlen = next_offset - offset;


      media_format_item = proto_tree_add_item(sdp_media_attribute_tree,
                                              hf_media_format, tvb, offset,
                                              tokenlen, FALSE);
      media_format = atoi((char*)tvb_get_ephemeral_string(tvb, offset, tokenlen));
      if (media_format >= SDP_NO_OF_PT) {
        return;   /* Invalid */
      }

      /* Append encoding name to format if known */
      proto_item_append_text(media_format_item, " [%s]",
                             transport_info->encoding_name[media_format]);

      /*??payload_type = tvb_get_ephemeral_string(tvb, offset, tokenlen);*/
      /* Move offset past the payload type */
      offset = next_offset + 1;

      while(has_more_pars==TRUE){
        next_offset = tvb_find_guint8(tvb,offset,-1,';');
        offset = tvb_skip_wsp(tvb,offset,tvb_length_remaining(tvb,offset));

        if(next_offset == -1){
          has_more_pars = FALSE;
          next_offset= tvb_length(tvb);
        }else{

        }

        /* There are at least 2 - add the first parameter */
        tokenlen = next_offset - offset;
        fmtp_item = proto_tree_add_item(sdp_media_attribute_tree,
                                        hf_media_format_specific_parameter, tvb,
                                        offset, tokenlen, FALSE);

        fmtp_tree = proto_item_add_subtree(fmtp_item, ett_sdp_fmtp);

        decode_sdp_fmtp(fmtp_tree, tvb, pinfo, offset, tokenlen,
                        transport_info->encoding_name[media_format]);

        /* Move offset past "; " and onto firts char */
        offset = next_offset + 1;
      }
    }
    break;
  case SDP_PATH:
    /* msrp attributes that contain address needed for conversation */
    /*    RFC 4975
     *    path = path-label ":" path-list
     *    path-label = "path"
     *    path-list= MSRP-URI *(SP MSRP-URI)
     *    MSRP-URI = msrp-scheme "://" authority
     *       ["/" session-id] ";" transport *( ";" URI-parameter)
     *                        ; authority as defined in RFC3986
     *
     *    msrp-scheme = "msrp" / "msrps"
     * RFC 3986
     * The authority component is preceded by a double slash ("//") and is terminated by
     * the next slash ("/"), question mark ("?"), or number sign ("#") character, or by
     * the end of the URI.
     */

    /* Check for "msrp://" */
    if (strncmp((char*)attribute_value, msrp_res, strlen(msrp_res)) == 0){
      int address_offset, port_offset, port_end_offset;

      /* Address starts here */
      address_offset = offset + (int)strlen(msrp_res);

      /* Port is after next ':' */
      port_offset = tvb_find_guint8(tvb, address_offset, -1, ':');
      /* Check if port is present if not skipp */
      if(port_offset!= -1){
        /* Port ends with '/' */
        port_end_offset = tvb_find_guint8(tvb, port_offset, -1, '/');

        /* Attempt to convert address */
        if (inet_pton(AF_INET, (char*)tvb_get_ephemeral_string(tvb, address_offset, port_offset-address_offset), &msrp_ipaddr) > 0) {
          /* Get port number */
          msrp_port_number = atoi((char*)tvb_get_ephemeral_string(tvb, port_offset+1, port_end_offset-port_offset-1));
          /* Set flag so this info can be used */
          msrp_transport_address_set = TRUE;
        }
      }
    }
    break;
  case SDP_H248_ITEM:
    /* Decode h248 item ITU-T Rec. H.248.12 (2001)/Amd.1 (11/2002)*/
    if (strncmp((char*)attribute_value, h324ext_h223lcparm, strlen(msrp_res)) == 0){
      /* A.5.1.3 H.223 Logical channel parameters
       * This property indicates the H.245
       * H223LogicalChannelsParameters structure encoded by applying the PER specified in
       * ITU-T Rec. X.691. Value encoded as per A.5.1.2. For text encoding the mechanism defined
       * in ITU-T Rec. H.248.15 is used.
       */
      gint len;
      asn1_ctx_t actx;

      len = (gint)strlen(attribute_value);
      h245_tvb = ascii_bytes_to_tvb(tvb, pinfo, len, attribute_value);
      /* arbitrary maximum length */
      /* should go through a handle, however,  the two h245 entry
         points are different, one is over tpkt and the other is raw
      */
      if (h245_tvb){
        asn1_ctx_init(&actx, ASN1_ENC_PER, TRUE, pinfo);
        dissect_h245_H223LogicalChannelParameters(h245_tvb, 0, &actx, sdp_media_attribute_tree, hf_SDPh223LogicalChannelParameters);
      }
    }
    break;
  default:
    /* No special treatment for values of this attribute type, just add as one item. */
    proto_tree_add_item(sdp_media_attribute_tree, hf_media_attribute_value,
                        tvb, offset, -1, FALSE);
    break;
  }
}

void
proto_register_sdp(void)
{
  static hf_register_info hf[] = {
    { &hf_protocol_version,
      { "Session Description Protocol Version (v)",
        "sdp.version", FT_STRING, BASE_NONE,NULL,0x0,
        NULL, HFILL }},
    { &hf_owner,
      { "Owner/Creator, Session Id (o)",
        "sdp.owner", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL}},
    { &hf_session_name,
      { "Session Name (s)",
        "sdp.session_name", FT_STRING, BASE_NONE,NULL, 0x0,
        NULL, HFILL }},
    { &hf_session_info,
      { "Session Information (i)",
        "sdp.session_info", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_uri,
      { "URI of Description (u)",
        "sdp.uri", FT_STRING, BASE_NONE,NULL, 0x0,
        NULL, HFILL }},
    { &hf_email,
      { "E-mail Address (e)",
        "sdp.email", FT_STRING, BASE_NONE, NULL, 0x0,
        "E-mail Address", HFILL }},
    { &hf_phone,
      { "Phone Number (p)",
        "sdp.phone", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_connection_info,
      { "Connection Information (c)",
        "sdp.connection_info", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_bandwidth,
      { "Bandwidth Information (b)",
        "sdp.bandwidth", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_timezone,
      { "Time Zone Adjustments (z)",
        "sdp.timezone", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_encryption_key,
      { "Encryption Key (k)",
        "sdp.encryption_key", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_session_attribute,
      { "Session Attribute (a)",
        "sdp.session_attr", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_media_attribute,
      { "Media Attribute (a)",
        "sdp.media_attr", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_time,
      { "Time Description, active time (t)",
        "sdp.time", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_repeat_time,
      { "Repeat Time (r)",
        "sdp.repeat_time", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_media,
      { "Media Description, name and address (m)",
        "sdp.media", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_media_title,
      { "Media Title (i)",
        "sdp.media_title",FT_STRING, BASE_NONE, NULL, 0x0,
        "Media Title", HFILL }},
    { &hf_unknown,
      { "Unknown",
        "sdp.unknown",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_invalid,
      { "Invalid line",
        "sdp.invalid",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_owner_username,
      { "Owner Username",
        "sdp.owner.username",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_owner_sessionid,
      { "Session ID",
        "sdp.owner.sessionid",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_owner_version,
      { "Session Version",
        "sdp.owner.version",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_owner_network_type,
      { "Owner Network Type",
        "sdp.owner.network_type",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_owner_address_type,
      { "Owner Address Type",
        "sdp.owner.address_type",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_owner_address,
      { "Owner Address",
        "sdp.owner.address",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_connection_info_network_type,
      { "Connection Network Type",
        "sdp.connection_info.network_type",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_connection_info_address_type,
      { "Connection Address Type",
        "sdp.connection_info.address_type",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_connection_info_connection_address,
      { "Connection Address",
        "sdp.connection_info.address",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_connection_info_ttl,
      { "Connection TTL",
        "sdp.connection_info.ttl",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_connection_info_num_addr,
      { "Connection Number of Addresses",
        "sdp.connection_info.num_addr",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_bandwidth_modifier,
      { "Bandwidth Modifier",
        "sdp.bandwidth.modifier",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_bandwidth_value,
      { "Bandwidth Value",
        "sdp.bandwidth.value",FT_STRING, BASE_NONE, NULL, 0x0,
        "Bandwidth Value (in kbits/s)", HFILL }},
    { &hf_time_start,
      { "Session Start Time",
        "sdp.time.start",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_time_stop,
      { "Session Stop Time",
        "sdp.time.stop",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_repeat_time_interval,
      { "Repeat Interval",
        "sdp.repeat_time.interval",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_repeat_time_duration,
      { "Repeat Duration",
        "sdp.repeat_time.duration",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_repeat_time_offset,
      { "Repeat Offset",
        "sdp.repeat_time.offset",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_timezone_time,
      { "Timezone Time",
        "sdp.timezone.time",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_timezone_offset,
      { "Timezone Offset",
        "sdp.timezone.offset",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_encryption_key_type,
      { "Key Type",
        "sdp.encryption_key.type",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_encryption_key_data,
      { "Key Data",
        "sdp.encryption_key.data",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_session_attribute_field,
      { "Session Attribute Fieldname",
        "sdp.session_attr.field",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_session_attribute_value,
      { "Session Attribute Value",
        "sdp.session_attr.value",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_media_media,
      { "Media Type",
        "sdp.media.media",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_media_port,
      { "Media Port",
        "sdp.media.port",FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_media_portcount,
      { "Media Port Count",
        "sdp.media.portcount",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_media_proto,
      { "Media Protocol",
        "sdp.media.proto",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_media_format,
      { "Media Format",
        "sdp.media.format",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_media_attribute_field,
      { "Media Attribute Fieldname",
        "sdp.media_attribute.field",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_media_attribute_value,
      { "Media Attribute Value",
        "sdp.media_attribute.value",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_media_encoding_name,
      { "MIME Type",
        "sdp.mime.type",FT_STRING, BASE_NONE, NULL, 0x0,
        "SDP MIME Type", HFILL }},
    { &hf_media_sample_rate,
      { "Sample Rate",
        "sdp.sample_rate",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_media_format_specific_parameter,
      { "Media format specific parameters",
        "sdp.fmtp.parameter",FT_STRING, BASE_NONE, NULL, 0x0,
        "Format specific parameter(fmtp)", HFILL }},
    { &hf_ipbcp_version,
      { "IPBCP Protocol Version",
        "ipbcp.version",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_ipbcp_type,
      { "IPBCP Command Type",
        "ipbcp.command",FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_sdp_fmtp_mpeg4_profile_level_id,
      { "Level Code",
        "sdp.fmtp.profile_level_id",FT_UINT32, BASE_DEC,VALS(mp4ves_level_indication_vals), 0x0,
        NULL, HFILL }},
    { &hf_sdp_fmtp_h263_profile,
      { "Profile",
        "sdp.fmtp.h263profile",FT_UINT32, BASE_DEC,VALS(h263_profile_vals), 0x0,
        NULL, HFILL }},
    { &hf_sdp_fmtp_h263_level,
      { "Level",
        "sdp.fmtp.h263level",FT_UINT32, BASE_DEC,VALS(h263_level_vals), 0x0,
        NULL, HFILL }},
    { &hf_sdp_h264_packetization_mode,
      { "Packetization mode",
        "sdp.fmtp.h264_packetization_mode",FT_UINT32, BASE_DEC,VALS(h264_packetization_mode_vals), 0x0,
        NULL, HFILL }},
    { &hf_SDPh223LogicalChannelParameters,
      { "h223LogicalChannelParameters", "sdp.h223LogicalChannelParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_key_mgmt_att_value,
      { "Key Management",
        "sdp.key_mgmt", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_key_mgmt_prtcl_id,
      { "Key Management Protocol (kmpid)",
        "sdp.key_mgmt.kmpid", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_key_mgmt_data,
      { "Key Management Data",
        "sdp.key_mgmt.data", FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
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
    &ett_sdp_fmtp,
    &ett_sdp_key_mgmt,
  };

  module_t *sdp_module;

  proto_sdp = proto_register_protocol("Session Description Protocol",
                                      "SDP", "sdp");
  proto_register_field_array(proto_sdp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  key_mgmt_dissector_table = register_dissector_table("key_mgmt",
                                                      "Key Management", FT_STRING, BASE_NONE);

  /*
   * Preferences registration
   */
   sdp_module = prefs_register_protocol(proto_sdp, NULL);
   prefs_register_bool_preference(sdp_module, "establish_conversation",
       "Establish Media Conversation",
       "Specifies that RTP/RTCP/T.38/MSRP/etc streams are decoded based "
       "upon port numbers found in SDP payload",
       &global_sdp_establish_conversation);

  /*
   * Register the dissector by name, so other dissectors can
   * grab it by name rather than just referring to it directly.
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
  msrp_handle = find_dissector("msrp");
  t38_handle = find_dissector("t38");
  h264_handle = find_dissector("h264");
  mp4ves_handle = find_dissector("mp4ves");

  sdp_handle = find_dissector("sdp");
  dissector_add_string("media_type", "application/sdp", sdp_handle);
  dissector_add_uint("bctp.tpi", 0x20, sdp_handle);
}
