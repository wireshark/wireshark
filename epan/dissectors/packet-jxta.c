/* packet-jxta.c
 * Routines for JXTA packet dissection
 * Copyright 2004, Mike Duigou <bondolo@jxta.org>
 * Heavily based on packet-jabber.c, which in turn is heavily based on 
 * on packet-acap.c, which in turn is heavily based on 
 * packet-imap.c, Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c, packet-jabber.c, packet-udp.c
 *
 * JXTA specification from http://spec.jxta.org
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
#include <epan/strutil.h>
#include <epan/prefs.h>
#include "packet-tcp.h"

static int proto_jxta = -1;

static int hf_jxta_udp = -1;
static int hf_jxta_udpsig = -1;
static int hf_jxta_welcome = -1;
static int hf_jxta_framing = -1;
static int hf_jxta_framing_header_name_length = -1;
static int hf_jxta_framing_header_name = -1;
static int hf_jxta_framing_header_value_length = -1;
static int hf_jxta_framing_header_value = -1;
static int hf_jxta_message = -1;
static int hf_jxta_message_sig = -1;
static int hf_jxta_message_version = -1;
static int hf_jxta_message_namespaces_count = -1;
static int hf_jxta_message_namespace_len = -1;
static int hf_jxta_message_namespace_name = -1;
static int hf_jxta_message_element_count = -1;
static int hf_jxta_element = -1;
static int hf_jxta_element_sig = -1;
static int hf_jxta_element_namespaceid = -1;
static int hf_jxta_element_flags = -1;
static int hf_jxta_element_name_len = -1;
static int hf_jxta_element_name = -1;
static int hf_jxta_element_type_len = -1;
static int hf_jxta_element_type = -1;
static int hf_jxta_element_encoding_len = -1;
static int hf_jxta_element_encoding = -1;
static int hf_jxta_element_data_length = -1;
static int hf_jxta_element_content_len = -1;
static int hf_jxta_element_content = -1;

static gint ett_jxta_welcome = -1;
static gint ett_jxta_udp = -1;
static gint ett_jxta_framing = -1;
static gint ett_jxta_msg = -1;
static gint ett_jxta_elem = -1;

static dissector_handle_t udpm_jxta_handle;
static dissector_handle_t tcp_jxta_handle;
static dissector_handle_t http_jxta_handle;

/** our header fields */
static hf_register_info hf[] = {
  { &hf_jxta_udp,
    { "JXTA UDP Message", "jxta.udp", FT_NONE, BASE_NONE, NULL, 0x0,
      "JXTA UDP Message", HFILL }
  },
  { &hf_jxta_udpsig,
    { "Signature", "jxta.udpsig", FT_STRING, BASE_NONE, NULL, 0x0,
      "JXTA UDP Signature", HFILL }
  },
  { &hf_jxta_welcome,
    { "Welcome Message", "jxta.welcome", FT_NONE, BASE_NONE, NULL, 0x0,
      "JXTA Connection Welcome Message", HFILL }
  },
  { &hf_jxta_framing,
    { "JXTA Message Framing", "jxta.framing", FT_NONE, BASE_NONE, NULL, 0x0,
      "JXTA Message Framing Header", HFILL }
  },
  { &hf_jxta_framing_header_name_length,
    { "Name Length", "jxta.framing.header.namelen", FT_UINT8, BASE_DEC, NULL, 0x0,
      "JXTA Message Framing Header Name Length", HFILL }
  },
  { &hf_jxta_framing_header_name,
    { "Name", "jxta.framing.header.name", FT_STRING, FT_NONE, NULL, 0x0,
      "JXTA Message Framing Header Name", HFILL }
  },
  { &hf_jxta_framing_header_value_length,
    { "Value Length", "jxta.framing.header.valuelen", FT_UINT16, BASE_DEC, NULL, 0x0,
      "JXTA Message Framing Header Value Length", HFILL }
  },
  { &hf_jxta_framing_header_value,
    { "Value", "jxta.framing.header.value", FT_BYTES, BASE_HEX, NULL, 0x0,
      "JXTA Message Framing Header Value", HFILL }
  },
  { &hf_jxta_message,
    { "JXTA Message", "jxta.message", FT_NONE, BASE_NONE, NULL, 0x0,
      "JXTA Message", HFILL }
  },
  { &hf_jxta_message_sig,
    { "Signature", "jxta.message.signature", FT_STRING, BASE_NONE, NULL, 0x0,
      "JXTA Message Signature", HFILL }
  },
  { &hf_jxta_message_version,
    { "Version", "jxta.message.version", FT_UINT8, BASE_DEC, NULL, 0x0,
      "JXTA Message Version", HFILL }
  },
  { &hf_jxta_message_namespaces_count,
    { "Namespace Count", "jxta.message.namespaces", FT_UINT16, BASE_DEC, NULL, 0x0,
      "JXTA Message Namespaces", HFILL }
  },
  { &hf_jxta_message_namespace_len,
    { "Namespace Name Length", "jxta.message.namespace.len", FT_UINT16, BASE_DEC, NULL, 0x0,
      "JXTA Message Namespace Name Length", HFILL }
  },
  { &hf_jxta_message_namespace_name,
    { "Namespace Name", "jxta.message.namespace.name", FT_STRING, BASE_NONE, NULL, 0x0,
      "JXTA Message Namespace Name", HFILL }
  },
  { &hf_jxta_message_element_count,
    { "Element Count", "jxta.message.elements", FT_UINT16, BASE_DEC, NULL, 0x0,
      "JXTA Message Element Count", HFILL }
  },
  { &hf_jxta_element,
    { "JXTA Message Element", "jxta.message.element", FT_NONE, BASE_NONE, NULL, 0x0,
      "JXTA Message Element", HFILL }
  },
  { &hf_jxta_element_sig,
    { "Signature", "jxta.message.element.signature", FT_STRING, BASE_NONE, NULL, 0x0,
      "JXTA Message Element Signature", HFILL }
  },
  { &hf_jxta_element_namespaceid,
    { "Namespace ID", "jxta.message.element.namespaceid", FT_UINT8, BASE_DEC, NULL, 0x0,
      "JXTA Message Element Namespace ID", HFILL }
  },
  
  /* TODO 20050104 bondolo This should be a bitfield */
  
  { &hf_jxta_element_flags,
    { "Flags", "jxta.message.element.flags", FT_UINT8, BASE_HEX, NULL, 0x0,
      "JXTA Message Element Flags", HFILL }
  },
  { &hf_jxta_element_name_len,
    { "Element Name Length", "jxta.message.element.name.length", FT_UINT16, BASE_DEC, NULL, 0x0,
      "JXTA Message Element Name Length", HFILL }
  },
  { &hf_jxta_element_name,
    { "Element Name", "jxta.message.element.name", FT_STRING, BASE_NONE, NULL, 0x0,
      "JXTA Message Element Name", HFILL }
  },
  { &hf_jxta_element_type_len,
    { "Element Type Length", "jxta.message.element.type.length", FT_UINT16, BASE_DEC, NULL, 0x0,
      "JXTA Message Element Name Length", HFILL }
  },
  { &hf_jxta_element_type,
    { "Element Type", "jxta.message.element.type", FT_STRING, BASE_NONE, NULL, 0x0,
      "JXTA Message Element Name", HFILL }
  },
  { &hf_jxta_element_encoding_len,
    { "Element Type Length", "jxta.message.element.encoding.length", FT_UINT16, BASE_DEC, NULL, 0x0,
      "JXTA Message Element Encoding Length", HFILL }
  },
  { &hf_jxta_element_encoding,
    { "Element Type", "jxta.message.element.encoding", FT_STRING, BASE_NONE, NULL, 0x0,
      "JXTA Message Element Encoding", HFILL }
  },
  { &hf_jxta_element_content_len,
    { "Element Content Length", "jxta.message.element.content.length", FT_UINT32, BASE_DEC, NULL, 0x0,
      "JXTA Message Element Content Length", HFILL }
  },
  { &hf_jxta_element_content,
    { "Element Content", "jxta.message.element.content", FT_BYTES, BASE_HEX, NULL, 0x0,
      "JXTA Message Element Content", HFILL }
  },
};

/** setup protocol subtree array */
static gint * const ett[] = {
  &ett_jxta_welcome,
  &ett_jxta_udp,
  &ett_jxta_framing,
  &ett_jxta_msg,
  &ett_jxta_elem
};

static int gUDP_MULTICAST_PORT_JXTA = 1234;
static int gHTTP_PORT_JXTA = 9700;
static int gTCP_PORT_JXTA = 9701;

static int regUDP_MULTICAST_PORT_JXTA = -1;
static int regHTTP_PORT_JXTA = -1;
static int regTCP_PORT_JXTA = -1;


static void dissect_jxta_framing(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_jxta_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

void proto_reg_handoff_jxta(void);

/**
    Dissect a tvbuff containing a JXTA UDP header, JXTA Message framing and a JXTA Message
**/
static void dissect_jxta_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  proto_tree      *jxta_tree = NULL;
  proto_item      *ti;

  if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "JXTA");
  }

  if (check_col(pinfo->cinfo, COL_INFO)) {
    /*
     * bondolo For now just say its a message. eventually put in dest addr.
     * XXX - if "dest addr" means the IP destination address, that's
     * already going to be in the "destination address" column if you're
     * displaying that.
     */
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", "UDP Message");
  }

  if (tree) {
    ti = proto_tree_add_item(tree, hf_jxta_udp, tvb, 0, -1, FALSE);
    jxta_tree = proto_item_add_subtree(ti, ett_jxta_udp);
    
    ti = proto_tree_add_item( jxta_tree, hf_jxta_udpsig, tvb, 0, 4, FALSE );
  }
  
  if( tvb_memeql(tvb, 0, "JXTA", 4) == 0 ) {
    tvbuff_t* jxta_framed_message_tvb = tvb_new_subset( tvb, 4, -1, -1 );

    dissect_jxta_framing( jxta_framed_message_tvb, pinfo, tree );
  }
}

static void dissect_jxta_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_jxta_message( tvb, pinfo, tree );
}

static void dissect_jxta_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 0, NULL, dissect_jxta_tcp_pdu);
}

/**
    Dissect a tvbuff containing a JXTA Message framing and a JXTA Message
**/
static void dissect_jxta_framing(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  proto_tree      *jxta_tree = NULL;
  proto_item      *ti;
  guint offset = 0;
  tvbuff_t* jxta_message_tvb;
  
  if (tree) {
    ti = proto_tree_add_item(tree, hf_jxta_framing, tvb, 0, -1, FALSE);
    jxta_tree = proto_item_add_subtree(ti, ett_jxta_framing);
    }
    
  /* parse framing headers */
  do {
    guint8 headernamelen = tvb_get_guint8( tvb, offset );

    if(tree) {
      proto_tree_add_item( jxta_tree, hf_jxta_framing_header_name_length, tvb, offset, 1, headernamelen );
    }
    
    if( tree && (headernamelen != 0) ) {
      /*
       * Put header name into protocol tree.
       */
      proto_tree_add_item(jxta_tree, hf_jxta_framing_header_name, tvb, offset+1, headernamelen, FALSE);
    }
    
    offset += 1 + headernamelen;
      
    if( headernamelen > 0 ) {
      guint16 headervaluelen = tvb_get_ntohs( tvb, offset );

      if( tree ) {
        proto_tree_add_uint(jxta_tree, hf_jxta_framing_header_value_length, tvb, offset, 2, headervaluelen );

        /** TODO bondolo Add specific handling for known header types */

        /*
         * Put header value into protocol tree.
         */
        proto_tree_add_item(jxta_tree, hf_jxta_framing_header_value, tvb, offset+2, headervaluelen, FALSE );
      }
      
      offset += 2 + headervaluelen;
    }
    
    if( 0 == headernamelen ) {
      break;
    }
  } while( TRUE );
  
  jxta_message_tvb = tvb_new_subset( tvb, offset, -1, -1 );

  /* Call it a new layer and pass the tree as we got it */
  dissect_jxta_message( jxta_message_tvb, pinfo, tree );
}

/**
    Dissect a tvbuff containing a JXTA Message
**/
static void dissect_jxta_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  proto_tree      *jxta_tree = NULL;
  proto_item      *ti;

  if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "JXTA");
  }

  if (check_col(pinfo->cinfo, COL_INFO)) {
    /*
     * TODO bondolo For now just say its a message. eventually put in dest addr.
     * XXX - if "dest addr" means the IP destination address, that's
     * already going to be in the "destination address" column if you're
     * displaying that.
     */
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", "Message");
  }

  if (tree) {
    ti = proto_tree_add_item(tree, hf_jxta_message, tvb, 0, -1, FALSE);
    jxta_tree = proto_item_add_subtree(ti, ett_jxta_udp);
  }

  if( tree ) {
    proto_tree_add_item( jxta_tree, hf_jxta_message_sig, tvb, 0, 4, FALSE);
    
    if( tvb_memeql(tvb, 0, "jxmg", 4) == 0) {
        guint8 messageVersion;
        
        messageVersion = tvb_get_guint8( tvb, sizeof(guint32) );
        proto_tree_add_uint( jxta_tree, hf_jxta_message_version, tvb, sizeof(guint32), 1, messageVersion );
        
        if( 0 == messageVersion ) {
            int eachNamespace;
            guint16 numberOfElements;
            unsigned int offset = 7;
            guint16 messageNamespaceCount = tvb_get_ntohs( tvb, 5 );
            
            /* parse namespaces */
            /* TODO 20050103 bondolo Should record the namespaces and number them. */
            for( eachNamespace = 0; eachNamespace < messageNamespaceCount; eachNamespace++ ) {
                guint8 namespaceLen = tvb_get_guint8( tvb, offset );
                
                proto_tree_add_uint(jxta_tree, hf_jxta_message_namespace_len, tvb, offset++, namespaceLen, namespaceLen );
                
                proto_tree_add_item(jxta_tree, hf_jxta_message_namespace_name, tvb, offset, namespaceLen, FALSE);
                    
                offset += namespaceLen;
            }
            
            /* parse elements */
            numberOfElements = tvb_get_ntohs( tvb, offset );
            proto_tree_add_item(jxta_tree, hf_jxta_message_element_count, tvb, offset, sizeof(guint16), FALSE );
            offset += sizeof(guint16);
            
            while( offset < tvb_reported_length(tvb) ) {
                    proto_tree   *jxta_elem_tree = NULL;
                    proto_item      *elem_ti;
                    
                    elem_ti = proto_tree_add_item(jxta_tree, hf_jxta_element, tvb, 0, -1, FALSE);
                    jxta_elem_tree = proto_item_add_subtree(elem_ti, ett_jxta_elem);

                /* gross hack for parsing of signature element */
                element_parse :
                {
                proto_tree_add_item( jxta_tree, hf_jxta_element_sig, tvb, offset, 4, FALSE );
                offset += 4;
                if( tvb_memeql(tvb, offset - 4, "jxel", 4) == 0 ) {
                    guint8 namespaceID;
                    guint8 flags;
                    guint16 nameLen;
                    guint32 elemContentLength;

                    namespaceID = tvb_get_guint8( tvb, offset );
                    proto_tree_add_uint( jxta_elem_tree, hf_jxta_element_namespaceid, tvb, offset, sizeof(guint8), namespaceID );
                    offset += sizeof(guint8);
                
                    flags = tvb_get_guint8( tvb, offset );
                    proto_tree_add_uint( jxta_elem_tree, hf_jxta_element_flags, tvb, offset, sizeof(guint8), flags );
                    offset += sizeof(guint8);
                    
                    nameLen  = tvb_get_ntohs( tvb, offset );
                    proto_tree_add_uint( jxta_elem_tree, hf_jxta_element_name_len, tvb, offset, sizeof(guint16), nameLen );
                    offset += sizeof(guint16);
                    
                    proto_tree_add_item(jxta_elem_tree, hf_jxta_element_name, tvb, offset, nameLen, FALSE);
                        
                    offset += nameLen;
                    
                    /* process type */
                    if( (flags & 0x01) != 0 ) {
                        guint16 typeLen  = tvb_get_ntohs( tvb, offset );
                        proto_tree_add_uint( jxta_elem_tree, hf_jxta_element_type_len, tvb, offset, sizeof(guint16), typeLen );
                        offset += sizeof(guint16);

                        proto_tree_add_item(jxta_elem_tree, hf_jxta_element_type, tvb, offset, typeLen, FALSE);

                        offset += typeLen;
                    }
                    
                    /* process encoding */
                    if( (flags & 0x02) != 0 ) {
                        guint16 encodingLen  = tvb_get_ntohs( tvb, offset );
                        ti = proto_tree_add_item( jxta_elem_tree, hf_jxta_element_encoding_len, tvb, offset, sizeof(guint16), FALSE );
                        offset += sizeof(guint16);

                        proto_tree_add_item(jxta_elem_tree, hf_jxta_element_encoding, tvb, offset, encodingLen, FALSE);

                        offset += encodingLen;
                    }
                    
                    /* content */
                    elemContentLength = tvb_get_ntohl( tvb, offset );
                    ti = proto_tree_add_item( jxta_elem_tree, hf_jxta_element_content_len, tvb, offset, sizeof(guint32), FALSE );
                    offset += sizeof(guint32);
                    
                    ti = proto_tree_add_item( jxta_elem_tree, hf_jxta_element_content, tvb, offset, elemContentLength, FALSE );
                    offset += elemContentLength;
                    
                    /* XXX Evil Hack Warning : handle parsing of signature element. Would be better with recursion.*/
                    if( (flags & 0x04) != 0 ) {
                        goto element_parse;
                    }
                }
                    
                proto_item_set_end( elem_ti, tvb, offset - 1 );
                }
            }
        }
    }    
  }
}

void proto_register_jxta(void)
{
  module_t *jxta_module;

  proto_jxta = proto_register_protocol("JXTA P2P", "JXTA", "jxta");
  
   /* Register header fields */
  proto_register_field_array(proto_jxta, hf, array_length(hf));
  
  /* Register JXTA Sub-tree */
  proto_register_subtree_array(ett, array_length(ett));

  /* Register preferences */
  jxta_module = prefs_register_protocol(proto_jxta, proto_reg_handoff_jxta);
  
  prefs_register_uint_preference(jxta_module, "tcp.port", "JXTA TCP Port",
				 "Set the port for JXTA TCP messages",
				 10, &gTCP_PORT_JXTA);

  prefs_register_uint_preference(jxta_module, "http.port", "JXTA HTTP Port",
				 "Set the port for JXTA HTTP messages",
				 10, &gHTTP_PORT_JXTA);

  prefs_register_uint_preference(jxta_module, "udp.port", "JXTA UDP Multicast Port",
				 "Set the port for JXTA UDP Multicast messages",
				 10, &gUDP_MULTICAST_PORT_JXTA);
}

void proto_reg_handoff_jxta(void) {
  static gboolean jxta_prefs_initialized = FALSE;

  if (!jxta_prefs_initialized) {
    udpm_jxta_handle = create_dissector_handle(dissect_jxta_udp, proto_jxta);
    tcp_jxta_handle = create_dissector_handle(dissect_jxta_tcp, proto_jxta);
    http_jxta_handle = create_dissector_handle(dissect_jxta_message, proto_jxta);

    jxta_prefs_initialized = TRUE;
  } else {
    dissector_delete("udp.port", regUDP_MULTICAST_PORT_JXTA, udpm_jxta_handle);

    dissector_delete("tcp.port", regTCP_PORT_JXTA, tcp_jxta_handle);

    dissector_delete("http.port", regHTTP_PORT_JXTA, http_jxta_handle);
  }

  /* remember what ports we registered on for later removal */
  regUDP_MULTICAST_PORT_JXTA = gUDP_MULTICAST_PORT_JXTA;
  regTCP_PORT_JXTA = gTCP_PORT_JXTA;
  regHTTP_PORT_JXTA = gHTTP_PORT_JXTA;
   
  /* register as a sub-dissector of UDP  tagged on port field */
  dissector_add("udp.port", regUDP_MULTICAST_PORT_JXTA, udpm_jxta_handle);

  /* register as a sub-dissector of TCP tagged on port field*/
  dissector_add("tcp.port", regTCP_PORT_JXTA, tcp_jxta_handle);

  /* register as a sub-dissector of HTTP tagged on port field */
  dissector_add("http.port", regHTTP_PORT_JXTA, http_jxta_handle);
}
