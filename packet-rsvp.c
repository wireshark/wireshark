/* packet-rsvp.c
 * Routines for RSVP packet disassembly
 *
 * (c) Copyright Ashok Narayanan <ashokn@cisco.com>
 *
 * $Id: packet-rsvp.c,v 1.6 1999/08/27 19:21:36 gram Exp $
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

/*
 * NOTES
 *
 * This module defines routines to disassemble RSVP packets, as defined in
 * RFC 2205. All objects from RC2205 are supported, in IPv4 and IPv6 mode.
 * In addition, the Integrated Services traffic specification objects
 * defined in RFC2210 are also supported. 
 *
 * IPv6 support is not completely tested
 */

 
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#include <glib.h>
#include "packet.h"
#include "packet-ip.h"
#include "packet-ipv6.h"
#include "packet-rsvp.h"

static int proto_rsvp = -1;

/* Stuff for IEEE float handling */

#define IEEE_NUMBER_WIDTH	32	/* bits in number */
#define IEEE_EXP_WIDTH		8	/* bits in exponent */
#define IEEE_MANTISSA_WIDTH	23	/* IEEE_NUMBER_WIDTH - 1 - IEEE_EXP_WIDTH */

#define IEEE_SIGN_MASK		0x80000000
#define IEEE_EXPONENT_MASK	0x7F800000
#define IEEE_MANTISSA_MASK	0x007FFFFF
#define IEEE_INFINITY		IEEE_EXPONENT_MASK

#define IEEE_IMPLIED_BIT (1 << IEEE_MANTISSA_WIDTH)
#define IEEE_INFINITE ((1 << IEEE_EXP_WIDTH) - 1)
#define IEEE_BIAS ((1 << (IEEE_EXP_WIDTH - 1)) - 1)

#define MINUS_INFINITY (signed)0x80000000L
#define PLUS_INFINITY  0x7FFFFFFF

static const value_string proto_vals[] = { {IP_PROTO_ICMP, "ICMP"},
                                           {IP_PROTO_IGMP, "IGMP"},
                                           {IP_PROTO_TCP,  "TCP" },
                                           {IP_PROTO_UDP,  "UDP" },
                                           {IP_PROTO_OSPF, "OSPF"},
                                           {0,             NULL  } };

/* Filter keys */
enum rsvp_filter_keys {

    /* Message types */
    RSVPF_MSG,          /* Message type */
    /* Shorthand for message types */
    RSVPF_PATH,
    RSVPF_RESV,
    RSVPF_PATHERR,
    RSVPF_RESVERR,
    RSVPF_PATHTEAR,
    RSVPF_RESVTEAR,
    RSVPF_RCONFIRM,

    /* Does the message contain an object of this type? */
    RSVPF_OBJECT,
    /* Object present shorthands */
    RSVPF_SESSION,
    RSVPF_DUMMY_1,
    RSVPF_HOP,
    RSVPF_INTEGRITY,
    RSVPF_TIME_VALUES,
    RSVPF_ERROR,
    RSVPF_SCOPE,
    RSVPF_STYLE,
    RSVPF_FLOWSPEC,
    RSVPF_FILTER_SPEC,
    RSVPF_SENDER,
    RSVPF_TSPEC,
    RSVPF_ADSPEC,
    RSVPF_POLICY,
    RSVPF_CONFIRM,
    RSVPF_UNKNOWN_OBJ, 

    /* Session object */
    RSVPF_SESSION_IP,
    RSVPF_SESSION_PROTO,
    RSVPF_SESSION_PORT,

    /* Sender template */
    RSVPF_SENDER_IP,
    RSVPF_SENDER_PORT,

    /* Sentinel */
    RSVPF_MAX
};

static int rsvp_filter[RSVPF_MAX];

static hf_register_info rsvpf_info[] = {

    /* Message type number */
    {&rsvp_filter[RSVPF_MSG], 
     { "Message Type", "rsvp.msg", FT_VALS_UINT8, VALS(message_type_vals) }},

    /* Message type shorthands */
    {&rsvp_filter[RSVPF_PATH], 
     { "Path Message", "rsvp.path", FT_UINT8, NULL }},
    {&rsvp_filter[RSVPF_RESV], 
     { "Resv Message", "rsvp.resv", FT_UINT8, NULL }},
    {&rsvp_filter[RSVPF_PATHERR], 
     { "Path Error Message", "rsvp.perr", FT_UINT8, NULL }},
    {&rsvp_filter[RSVPF_RESVERR], 
     { "Resv Error Message", "rsvp.rerr", FT_UINT8, NULL }},
    {&rsvp_filter[RSVPF_PATHTEAR], 
     { "Path Tear Message", "rsvp.ptear", FT_UINT8, NULL }},
    {&rsvp_filter[RSVPF_RESVTEAR], 
     { "Resv Tear Message", "rsvp.rtear", FT_UINT8, NULL }},
    {&rsvp_filter[RSVPF_RCONFIRM], 
     { "Resv Confirm Message", "rsvp.resvconf", FT_UINT8, NULL }},

    /* Object present */
    {&rsvp_filter[RSVPF_OBJECT], 
     { "", "rsvp.object", FT_VALS_UINT8, VALS(rsvp_class_vals) }},

    /* Object present shorthands */
    {&rsvp_filter[RSVPF_SESSION], 
     { "SESSION", "rsvp.session", FT_UINT8, NULL }},
    {&rsvp_filter[RSVPF_HOP], 
     { "HOP", "rsvp.hop", FT_UINT8, NULL }},
    {&rsvp_filter[RSVPF_INTEGRITY], 
     { "INTEGRITY", "rsvp.integrity", FT_UINT8, NULL }},
    {&rsvp_filter[RSVPF_TIME_VALUES], 
     { "TIME VALUES", "rsvp.time", FT_UINT8, NULL }},
    {&rsvp_filter[RSVPF_ERROR], 
     { "ERROR", "rsvp.error", FT_UINT8, NULL }},
    {&rsvp_filter[RSVPF_SCOPE], 
     { "SCOPE", "rsvp.scope", FT_UINT8, NULL }},
    {&rsvp_filter[RSVPF_STYLE], 
     { "STYLE", "rsvp.style", FT_UINT8, NULL }},
    {&rsvp_filter[RSVPF_FLOWSPEC], 
     { "FLOWSPEC", "rsvp.flowspec", FT_UINT8, NULL }},
    {&rsvp_filter[RSVPF_FILTER_SPEC], 
     { "FILTERSPEC", "rsvp.filter", FT_UINT8, NULL }},
    {&rsvp_filter[RSVPF_SENDER], 
     { "SENDER TEMPLATE", "rsvp.sender", FT_UINT8, NULL }},
    {&rsvp_filter[RSVPF_TSPEC], 
     { "SENDER TSPEC", "rsvp.tspec", FT_UINT8, NULL }},
    {&rsvp_filter[RSVPF_ADSPEC], 
     { "ADSPEC", "rsvp.adspec", FT_UINT8, NULL }},
    {&rsvp_filter[RSVPF_POLICY], 
     { "POLICY", "rsvp.policy", FT_UINT8, NULL }},
    {&rsvp_filter[RSVPF_CONFIRM], 
     { "CONFIRM", "rsvp.confirm", FT_UINT8, NULL }},
    {&rsvp_filter[RSVPF_UNKNOWN_OBJ], 
     { "Unknown object", "rsvp.obj_unknown", FT_UINT8, NULL }},

    /* Session fields */
    {&rsvp_filter[RSVPF_SESSION_IP], 
     { "Destination address", "rsvp.session.ip", FT_IPv4, NULL }},
    {&rsvp_filter[RSVPF_SESSION_PORT], 
     { "Port number", "rsvp.session.port", FT_UINT16, NULL }},
    {&rsvp_filter[RSVPF_SESSION_PROTO], 
     { "Protocol", "rsvp.session.proto", FT_VALS_UINT8, VALS(proto_vals) }},

    /* Sender template fields */
    {&rsvp_filter[RSVPF_SENDER_IP], 
     { "Sender Template IPv4 address", "rsvp.template.ip", FT_IPv4, NULL }},
    {&rsvp_filter[RSVPF_SENDER_PORT], 
     { "Sender Template port number", "rsvp.template.port", FT_UINT16, NULL }}
};

static inline int rsvp_class_to_filter_num(int classnum)
{
    switch(classnum) {
    case RSVP_CLASS_SESSION :
    case RSVP_CLASS_HOP :
    case RSVP_CLASS_INTEGRITY :
    case RSVP_CLASS_TIME_VALUES :
    case RSVP_CLASS_ERROR :
    case RSVP_CLASS_SCOPE :
    case RSVP_CLASS_STYLE :
    case RSVP_CLASS_FLOWSPEC :
    case RSVP_CLASS_FILTER_SPEC :
    case RSVP_CLASS_SENDER_TEMPLATE :
    case RSVP_CLASS_SENDER_TSPEC :
    case RSVP_CLASS_ADSPEC :
    case RSVP_CLASS_POLICY :
    case RSVP_CLASS_CONFIRM :
	return classnum + RSVPF_OBJECT;
	
    default:
	return RSVPF_UNKNOWN_OBJ;
    }
}

static inline int ieee_float_is_zero (long number)
{
    return(!(number & ~IEEE_SIGN_MASK));
}

/*
 * simple conversion: ieee floating point to long
 */
static long ieee_to_long (const void *p)
{
    long number;
    long sign;
    long exponent;
    long mantissa;

    number = pntohl(p);
    sign = number & IEEE_SIGN_MASK;
    exponent = number & IEEE_EXPONENT_MASK;
    mantissa = number & IEEE_MANTISSA_MASK;

    if (ieee_float_is_zero(number)) {
	/* number is zero, unnormalized, or not-a-number */
	return 0;
    }
    if (IEEE_INFINITY == exponent) {
	/* number is positive or negative infinity, or a special value */
	return (sign? MINUS_INFINITY: PLUS_INFINITY);
    }

    exponent = (exponent >> IEEE_MANTISSA_WIDTH) - IEEE_BIAS;
    if (exponent < 0) {
	/* number is between zero and one */
	return 0;
    }

    mantissa |= IEEE_IMPLIED_BIT;
    if (exponent <= IEEE_MANTISSA_WIDTH)
	mantissa >>= IEEE_MANTISSA_WIDTH - exponent;
    else
	mantissa <<= exponent - IEEE_MANTISSA_WIDTH;

    if (sign)
	return -mantissa;
    else
	return mantissa;
}

void 
dissect_rsvp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) 
{
    proto_tree *rsvp_tree = NULL, *ti; 
    proto_tree *rsvp_header_tree;
    proto_tree *rsvp_object_tree;
    char *packet_type, *object_type;
    rsvp_header *hdr;
    rsvp_object *obj;
    int i, len, mylen;
    int msg_length;
    int obj_length;
    int offset2;

    hdr = (rsvp_header *)&pd[offset];
    packet_type = match_strval(hdr->message_type, message_type_vals);
    if (check_col(fd, COL_PROTOCOL))
        col_add_str(fd, COL_PROTOCOL, "RSVP");
    if (check_col(fd, COL_INFO)) {
        if (packet_type != NULL)
            col_add_str(fd, COL_INFO, packet_type); 
        else
            col_add_fstr(fd, COL_INFO, "Unknown (%d)", hdr->message_type); 
    }

    if (tree) {
	msg_length = pntohs(pd+offset+6);
	ti = proto_tree_add_item(tree, proto_rsvp, offset, msg_length, NULL);
	rsvp_tree = proto_item_add_subtree(ti, ETT_RSVP);

	ti = proto_tree_add_text(rsvp_tree, offset, 
			      sizeof(rsvp_header), "RSVP Header"); 
	rsvp_header_tree = proto_item_add_subtree(ti, ETT_RSVP_HDR);

        proto_tree_add_text(rsvp_header_tree, offset, 1, "RSVP Version: %d", 
			 (hdr->ver_flags & 0xf0)>>4);  
	proto_tree_add_text(rsvp_header_tree, offset, 1, "Flags: %02X",
			 hdr->ver_flags & 0xf);  
	proto_tree_add_item(rsvp_header_tree, rsvp_filter[RSVPF_MSG], 
			    offset+1, 1, hdr->message_type);
	proto_tree_add_item_hidden(rsvp_header_tree, rsvp_filter[RSVPF_MSG + hdr->message_type], 
			    offset+1, 1, 1);
/*
	proto_tree_add_text(rsvp_header_tree, offset+1, 1, "Message Type: %d - %s",
			 hdr->message_type, 
			 packet_type?packet_type:"Unknown");
*/
	proto_tree_add_text(rsvp_header_tree, offset + 2 , 2, "Message Checksum");
	proto_tree_add_text(rsvp_header_tree, offset + 4 , 1, "Sending TTL: %d",
			 hdr->sending_ttl);
	proto_tree_add_text(rsvp_header_tree, offset + 6 , 2, "Message length: %d",
			 msg_length);

	offset += sizeof(rsvp_header);
	len = 0;
	while (len + sizeof(rsvp_header) < msg_length) {
	    obj = (rsvp_object *)&pd[offset];
	    obj_length = pntohs(pd+offset);
	    if (offset + obj_length > fd->cap_len) {
		proto_tree_add_text(rsvp_tree, offset, 1, 
				 "Further data not captured");
		break;
	    }
	    
	    object_type = match_strval(obj->class, rsvp_class_vals);
	    if (!object_type) object_type = "Unknown";
	    /*
	    ti = proto_tree_add_text(rsvp_tree, offset, 
				  obj_length, 
				  "%s (%d)", object_type, obj->class);
	    */
	    ti = proto_tree_add_item_hidden(rsvp_tree, rsvp_filter[RSVPF_OBJECT], 
				     offset, obj_length, obj->class);
	    ti = proto_tree_add_item(rsvp_tree, rsvp_filter[rsvp_class_to_filter_num(obj->class)], 
				     offset, obj_length, obj->class);

	    offset2 = offset + sizeof(rsvp_object);

	    switch(obj->class) {

	    case RSVP_CLASS_SESSION : 		
		rsvp_object_tree = proto_item_add_subtree(ti, ETT_RSVP_SESSION);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %d - %s", 
				    obj->class, object_type);
		switch(obj->type) {
		case 1: {
		    rsvp_session_ipv4 *sess = (rsvp_session_ipv4 *)obj;
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 1 - IPv4");
		    /*
		    proto_tree_add_text(rsvp_object_tree, offset2, 4, 
					"Destination address: %s", 
					ip_to_str((guint8 *) &(sess->destination)));
		    */
		    proto_tree_add_item(rsvp_object_tree, rsvp_filter[RSVPF_SESSION_IP], 
					offset2, 4, sess->destination);

		    /* proto_tree_add_text(rsvp_object_tree, offset2+4, 1,
		       "Protocol: %d", sess->protocol);*/
		    proto_tree_add_item(rsvp_object_tree, rsvp_filter[RSVPF_SESSION_PROTO], 
					offset2+4, 1, sess->protocol);
		    proto_tree_add_text(rsvp_object_tree, offset2+5, 1,
					"Flags: %d", sess->flags);
		    /* proto_tree_add_text(rsvp_object_tree, offset2+6, 2,
					"Destination port: %d", 
					pntohs(pd+offset2+6)); */
		    proto_tree_add_item(rsvp_object_tree, rsvp_filter[RSVPF_SESSION_PORT], 
					offset2+6, 2, pntohs(pd+offset2+6));
		    break;
		}

		case 2: {
		    rsvp_session_ipv6 *sess = (rsvp_session_ipv6 *)obj;
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 2 - IPv6");
		    proto_tree_add_text(rsvp_object_tree, offset2, 4, 
					"Destination address: %s", 
					ip6_to_str(&(sess->destination)));
		    proto_tree_add_text(rsvp_object_tree, offset2+16, 1,
					"Protocol: %d", sess->protocol);
		    proto_tree_add_text(rsvp_object_tree, offset2+17, 1,
					"Flags: %d", sess->flags);
		    proto_tree_add_text(rsvp_object_tree, offset2+18, 2,
					"Destination port: %d", 
					pntohs(pd+offset2+18));
		    break;
		}
		
		default: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: Unknown (%d)",
					obj->type);
		    i = obj_length - sizeof(rsvp_object);
		    proto_tree_add_text(rsvp_object_tree, offset2, i,
					"Data (%d bytes)", i);
		}
		}
		break;
		
	    case RSVP_CLASS_HOP :		
		rsvp_object_tree = proto_item_add_subtree(ti, ETT_RSVP_HOP);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %d - %s", 
				    obj->class, object_type);
		switch(obj->type) {
		case 1: {
		    rsvp_hop_ipv4 *hop = (rsvp_hop_ipv4 *)obj;
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 1 - IPv4");
		    proto_tree_add_text(rsvp_object_tree, offset2, 4, 
					"Neighbor address: %s", 
					ip_to_str((guint8 *) &(hop->neighbor)));
		    proto_tree_add_text(rsvp_object_tree, offset2+4, 4,
					"Logical interface: %0x", 
					pntohl(pd+offset2+4));
		    break;
		}

		case 2: {
		    rsvp_hop_ipv6 *hop = (rsvp_hop_ipv6 *)obj;
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 2 - IPv6");
		    proto_tree_add_text(rsvp_object_tree, offset2, 4, 
					"Neighbor address: %s", 
					ip6_to_str(&(hop->neighbor)));
		    proto_tree_add_text(rsvp_object_tree, offset2+16, 4,
					"Logical interface: %0x", 
					pntohl(pd+offset2+16));
		    break;
		}
		
		default: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: Unknown (%d)",
					obj->type);
		    i = obj_length - sizeof(rsvp_object);
		    proto_tree_add_text(rsvp_object_tree, offset2, i,
					"Data (%d bytes)", i);
		}
		}
		break;
		
	    case RSVP_CLASS_TIME_VALUES : 
		rsvp_object_tree = proto_item_add_subtree(ti, ETT_RSVP_TIME_VALUES);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %d - %s", 
				    obj->class, object_type);
		switch(obj->type) {
		case 1: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 1");
		    proto_tree_add_text(rsvp_object_tree, offset2, 4, 
					"Refresh interval: %u ms (%u seconds)",
					pntohl(pd+offset2),
					pntohl(pd+offset2)/1000);
		    break;
		}

		default: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: Unknown (%d)",
					obj->type);
		    i = obj_length - sizeof(rsvp_object);
		    proto_tree_add_text(rsvp_object_tree, offset2, i,
					"Data (%d bytes)", i);
		    break;
		}
		}
		break;

	    case RSVP_CLASS_ERROR :
		rsvp_object_tree = proto_item_add_subtree(ti, ETT_RSVP_ERROR);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %d - %s", 
				    obj->class, object_type);
		switch(obj->type) {
		case 1: {
		    rsvp_error_ipv4 *err = (rsvp_error_ipv4 *)obj;
		    char *err_str = match_strval(err->error_code, rsvp_error_vals);
		    if (!err_str) err_str = "Unknown";

		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 1 - IPv4");
		    proto_tree_add_text(rsvp_object_tree, offset2, 4, 
					"Error node: %s",
					ip_to_str((guint8 *) &(err->error_node)));
		    proto_tree_add_text(rsvp_object_tree, offset2+4, 1,
					"Flags: %02x", err->flags);
		    proto_tree_add_text(rsvp_object_tree, offset2+5, 1,
					"Error code: %d - %s", err->error_code,
					err_str);
		    proto_tree_add_text(rsvp_object_tree, offset2+6, 2,
					"Error value: %d", pntohs(pd+offset2+6));
		    
		    break;
		}

		case 2: {
		    rsvp_error_ipv6 *err = (rsvp_error_ipv6 *)obj;
		    char *err_str = match_strval(err->error_code, rsvp_error_vals);
		    if (!err_str) err_str = "Unknown";
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 2 - IPv6");
		    proto_tree_add_text(rsvp_object_tree, offset2, 4, 
					"Error node: %s",
					ip6_to_str(&(err->error_node)));
		    proto_tree_add_text(rsvp_object_tree, offset2+16, 1,
					"Flags: %02x", err->flags);
		    proto_tree_add_text(rsvp_object_tree, offset2+17, 1,
					"Error code: %d - %s", err->error_code,
					err_str);
		    proto_tree_add_text(rsvp_object_tree, offset2+18, 2,
					"Error value: %d", pntohs(pd+offset2+18));
		    
		    break;
		}
		
		default: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: Unknown (%d)",
					obj->type);
		    i = obj_length - sizeof(rsvp_object);
		    proto_tree_add_text(rsvp_object_tree, offset2, i,
					"Data (%d bytes)", i);
		}
		}
		break;
		

	    case RSVP_CLASS_SCOPE : 
		mylen = obj_length;
		rsvp_object_tree = proto_item_add_subtree(ti, ETT_RSVP_SCOPE);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %d - %s", 
				    obj->class, object_type);
		switch(obj->type) {
		case 1: {
		    unsigned long ip;
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 1 - IPv4");
		    while (mylen > sizeof(rsvp_object)) {
			ip = pntohl(pd+offset2);
			proto_tree_add_text(rsvp_object_tree, offset2, 4, 
					    "IPv4 Address: %s",
					    ip_to_str((guint8 *) &ip));
			offset2 += 4;
			mylen -= 4;
		    }
		    break;
		}

		case 2: {
		    struct e_in6_addr *ip;
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 2 - IPv6");
		    while (mylen>sizeof(rsvp_object)) {
			ip = (struct e_in6_addr *)pd+offset2;
			proto_tree_add_text(rsvp_object_tree, offset2, 16, 
					    "IPv6 Address: %s",
					    ip6_to_str(ip));
			offset2 += 16;
			mylen -= 16;
		    }
		    break;
		}
		
		default: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: Unknown (%d)",
					obj->type);
		    i = obj_length - sizeof(rsvp_object);
		    proto_tree_add_text(rsvp_object_tree, offset2, i,
					"Data (%d bytes)", i);
		}
		}
		break;
		
	    case RSVP_CLASS_STYLE : 
		rsvp_object_tree = proto_item_add_subtree(ti, ETT_RSVP_STYLE);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %d - %s", 
				    obj->class, object_type);
		switch(obj->type) {
		case 1: {
		    unsigned long ip = pntohl(pd+offset2);
		    char *style_str = match_strval(ip, style_vals);
		    if (!style_str) style_str = "Unknown";
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 1");
		    proto_tree_add_text(rsvp_object_tree, offset2+5, 1,
					"Style: %ld - %s", ip, style_str);
		    break;
		}

		default: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: Unknown (%d)",
					obj->type);
		    i = obj_length - sizeof(rsvp_object);
		    proto_tree_add_text(rsvp_object_tree, offset2, i,
					"Data (%d bytes)", i);
		    break;
		}
		}
		break;
	    
	    case RSVP_CLASS_CONFIRM :		
		rsvp_object_tree = proto_item_add_subtree(ti, ETT_RSVP_CONFIRM);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %d - %s", 
				    obj->class, object_type);
		switch(obj->type) {
		case 1: {
		    rsvp_confirm_ipv4 *confirm = (rsvp_confirm_ipv4 *)obj;
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 1 - IPv4");
		    proto_tree_add_text(rsvp_object_tree, offset2, 4, 
					"Receiver address: %s", 
					ip_to_str((guint8 *) &(confirm->receiver)));
		    break;
		}

		case 2: {
		    rsvp_confirm_ipv6 *confirm = (rsvp_confirm_ipv6 *)obj;
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 2 - IPv6");
		    proto_tree_add_text(rsvp_object_tree, offset2, 16, 
					"Receiver address: %s", 
					ip6_to_str(&(confirm->receiver)));
		    break;
		}

		default: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: Unknown (%d)",
					obj->type);
		    i = obj_length - sizeof(rsvp_object);
		    proto_tree_add_text(rsvp_object_tree, offset2, i,
					"Data (%d bytes)", i);
		}
		}
		break;

	    case RSVP_CLASS_SENDER_TEMPLATE :
		rsvp_object_tree = proto_item_add_subtree(ti, ETT_RSVP_SENDER_TEMPLATE);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %d - %s", 
				    obj->class, object_type);
		goto common_template;
	    case RSVP_CLASS_FILTER_SPEC :
		rsvp_object_tree = proto_item_add_subtree(ti, ETT_RSVP_FILTER_SPEC);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %d - %s", 
				    obj->class, object_type);
	    common_template:
		switch(obj->type) {
		case 1: {
		    rsvp_template_ipv4 *tem = (rsvp_template_ipv4 *)obj;
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 1 - IPv4");
		    proto_tree_add_text(rsvp_object_tree, offset2, 4, 
					"Source address: %s", 
					ip_to_str((guint8 *) &(tem->source)));
		    proto_tree_add_text(rsvp_object_tree, offset2+6, 2,
					"Source port: %d", pntohs(pd+offset2+6));
		    break;
		}

		case 2: {
		    rsvp_template_ipv6 *tem = (rsvp_template_ipv6 *)obj;
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 2 - IPv6");
		    proto_tree_add_text(rsvp_object_tree, offset2, 16, 
					"Source address: %s", 
					ip6_to_str(&(tem->source)));
		    proto_tree_add_text(rsvp_object_tree, offset2+18, 2,
					"Source port: %d", pntohs(pd+offset2+18));
		    break;
		}
		
		default: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: Unknown (%d)",
					obj->type);
		    i = obj_length - sizeof(rsvp_object);
		    proto_tree_add_text(rsvp_object_tree, offset2, i,
					"Data (%d bytes)", i);
		}
		}
		break;

	    case RSVP_CLASS_SENDER_TSPEC : {
		rsvp_tspec *tspec = (rsvp_tspec *)obj;
		IS_tspec *ist;
		QUAL_tspec *qt;
		service_hdr  *sh;
		char *str;

		mylen = obj_length;
		rsvp_object_tree = proto_item_add_subtree(ti, ETT_RSVP_SENDER_TSPEC);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %d - %s", 
				    obj->class, object_type);

		proto_tree_add_text(rsvp_object_tree, offset2, 1, 
				 "Message format version: %d", 
				 tspec->version>>4);
		proto_tree_add_text(rsvp_object_tree, offset2+2, 2, 
				 "Data length: %d words, not including header", 
				 pntohs(pd+offset2+2));

		mylen -=4;
		offset2 +=4;
		while (mylen > 4) {
		    sh = (service_hdr *)(pd+offset2);
		    str = match_strval(sh->service_num, qos_vals);
		    if (!str) str = "Unknown";

		    proto_tree_add_text(rsvp_object_tree, offset2, 1, 
					"Service header: %d - %s", 
					sh->service_num, str);
		    proto_tree_add_text(rsvp_object_tree, offset2+2, 2, 
				 "Length of service %d data: %d words, " 
				 "not including header", 
				 sh->service_num,
				 ntohs(sh->length));

		    offset2+=4; mylen -=4; 

		    switch(sh->service_num) {
			
		    case QOS_TSPEC :
			ist = (IS_tspec *)sh;

			/* Token bucket TSPEC */
			str = match_strval(ist->param_id, svc_vals);
			if (!str) str = "Unknown";
			proto_tree_add_text(rsvp_object_tree, offset2, 1, 
					    "Parameter %d - %s", 
					    ist->param_id, str);
			proto_tree_add_text(rsvp_object_tree, offset2+1, 1, 
					    "Parameter %d flags: %d", 
					    ist->param_id, ist->flags_tspec);
			proto_tree_add_text(rsvp_object_tree, offset2+2, 2, 
					    "Parameter %d data length: %d words, " 
					    "not including header",
					    ist->param_id,
					    /* pntohs(pd+offset2+10)); */
					    ntohs(ist->parameter_length));
			proto_tree_add_text(rsvp_object_tree, offset2+4, 4, 
					    "Token bucket rate: %ld", 
					    ieee_to_long(pd+offset2+4));
			proto_tree_add_text(rsvp_object_tree, offset2+8, 4, 
					    "Token bucket size: %ld", 
					    ieee_to_long(pd+offset2+8));
			proto_tree_add_text(rsvp_object_tree, offset2+12, 4, 
					    "Peak data rate: %ld", 
					    ieee_to_long(pd+offset2+12));
			proto_tree_add_text(rsvp_object_tree, offset2+16, 4, 
					    "Minimum policed unit: %d", 
					    pntohl(pd+offset2+16));
			proto_tree_add_text(rsvp_object_tree, offset2+20, 4, 
					    "Maximum policed unit: %d", 
					    pntohl(pd+offset2+20));

			break;

		    case QOS_QUALITATIVE :
			qt = (QUAL_tspec *)sh;

			/* Token bucket TSPEC */
			str = match_strval(qt->param_id, svc_vals);
			if (!str) str = "Unknown";
			proto_tree_add_text(rsvp_object_tree, offset2, 1, 
					    "Parameter %d - %s", 
					    qt->param_id, str);
			proto_tree_add_text(rsvp_object_tree, offset2+1, 1, 
					    "Parameter %d flags: %d", 
					    qt->param_id, qt->flags_tspec);
			proto_tree_add_text(rsvp_object_tree, offset2+2, 2, 
					    "Parameter %d data length: %d words, " 
					    "not including header",
					    qt->param_id,
					    /* pntohs(pd+offset2+10)); */
					    ntohs(qt->parameter_length));
			proto_tree_add_text(rsvp_object_tree, offset2+4, 4, 
					    "Maximum policed unit: %d", 
					    pntohl(pd+offset2+4));

			break;

		    }
		    offset2 += ntohs(sh->length)*4; 
		    mylen -= ntohs(sh->length)*4;
		}
		    
		break;
	    }

	    case RSVP_CLASS_FLOWSPEC : {
		rsvp_flowspec *flowspec = (rsvp_flowspec *)obj;
		IS_flowspec *isf;
		QUAL_flowspec *qf;
		service_hdr *sh;
		int mylen;

		char *str;

		mylen = obj_length;
		rsvp_object_tree = proto_item_add_subtree(ti, ETT_RSVP_FLOWSPEC);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %d - %s", 
				    obj->class, object_type);

		proto_tree_add_text(rsvp_object_tree, offset2, 1, 
				 "Message format version: %d", 
				 flowspec->version>>4);
		proto_tree_add_text(rsvp_object_tree, offset2+2, 2, 
				 "Data length: %d words, not including header", 
				 pntohs(pd+offset2+2));

		mylen -=4;
		offset2+=4;
		while (mylen > 4) {
		    sh = (service_hdr *)(pd+offset2);
		    str = match_strval(sh->service_num, intsrv_services_str);
		    if (!str) str = "Unknown";

		    proto_tree_add_text(rsvp_object_tree, offset2, 1, 
					"Service header: %d - %s", 
					sh->service_num, str);
		    proto_tree_add_text(rsvp_object_tree, offset2+2, 2, 
				 "Length of service %d data: %d words, " 
				 "not including header", 
				 sh->service_num,
				 ntohs(sh->length));

		    offset2+=4; mylen -=4; 

		    switch(sh->service_num) {

		    case QOS_CONTROLLED_LOAD :
		    case QOS_GUARANTEED :
			/* Treat both these the same for now */
			isf = (IS_flowspec *)sh;

			str = match_strval(isf->tspec.param_id, svc_vals);
			if (!str) str = "Unknown";
			proto_tree_add_text(rsvp_object_tree, offset2, 1, 
					    "Parameter %d - %s", 
					    isf->tspec.param_id, str);
			proto_tree_add_text(rsvp_object_tree, offset2+1, 1, 
					    "Parameter %d flags: %d", 
					    isf->tspec.param_id, isf->tspec.flags_tspec);
			proto_tree_add_text(rsvp_object_tree, offset2+2, 2, 
					    "Parameter %d data length: %d words, " 
					    "not including header",
					    isf->tspec.param_id,
					    ntohs(isf->tspec.parameter_length));
			proto_tree_add_text(rsvp_object_tree, offset2+4, 4, 
					    "Token bucket rate: %ld", 
					    ieee_to_long(pd+offset2+4));
			proto_tree_add_text(rsvp_object_tree, offset2+8, 4, 
					    "Token bucket size: %ld", 
					    ieee_to_long(pd+offset2+8));
			proto_tree_add_text(rsvp_object_tree, offset2+12, 4, 
					    "Peak data rate: %ld", 
					    ieee_to_long(pd+offset2+12));
			proto_tree_add_text(rsvp_object_tree, offset2+16, 4, 
					    "Minimum policed unit: %d", 
					    pntohl(pd+offset2+16));
			proto_tree_add_text(rsvp_object_tree, offset2+20, 4, 
					    "Maximum policed unit: %d", 
					    pntohl(pd+offset2+20));
			if (sh->service_num!=QOS_GUARANTEED)
			    break;
			
			/* Guaranteed-rate RSpec */
			str = match_strval(isf->rspec.param_id, svc_vals);
			if (!str) str="Unknown";
			proto_tree_add_text(rsvp_object_tree, offset2+24, 1, 
					    "Parameter %d - %s", 
					    isf->rspec.param_id, str);
			proto_tree_add_text(rsvp_object_tree, offset2+25, 1, 
					    "Parameter %d flags: %d", 
					    isf->rspec.param_id, isf->rspec.flags_rspec);
			proto_tree_add_text(rsvp_object_tree, offset2+26, 2, 
					    "Parameter %d data length: %d words, " 
					    "not including header",
					    isf->rspec.param_id,
					    ntohs(isf->rspec.param2_length));

			proto_tree_add_text(rsvp_object_tree, offset2+28, 4, 
					    "Rate: %ld", 
					    ieee_to_long(pd+offset2+28));
			proto_tree_add_text(rsvp_object_tree, offset2+32, 4, 
					    "Slack term: %d", 
					    pntohl(pd+offset2+32));
			break;

		    case QOS_QUALITATIVE :
			qf = (QUAL_flowspec *)sh;

			str = match_strval(qf->param_id, svc_vals);
			if (!str) str = "Unknown";
			proto_tree_add_text(rsvp_object_tree, offset2, 1, 
					    "Parameter %d - %s", 
					    qf->param_id, str);
			proto_tree_add_text(rsvp_object_tree, offset2+1, 1, 
					    "Parameter %d flags: %d", 
					    qf->param_id, qf->flags_tspec);
			proto_tree_add_text(rsvp_object_tree, offset2+2, 2, 
					    "Parameter %d data length: %d words, " 
					    "not including header",
					    qf->param_id,
					    ntohs(qf->parameter_length));
			proto_tree_add_text(rsvp_object_tree, offset2+4, 4, 
					    "Maximum policed unit: %ld", 
					    pntohl(pd+offset2+4));
			
			break;
		    }
		    offset2 += ntohs(sh->length)*4;
		    mylen -= ntohs(sh->length)*4;
		}

		break;
	    }

	    case RSVP_CLASS_ADSPEC : {
		proto_tree *adspec_tree;
		service_hdr *shdr;
		param_hdr *phdr; 

		char *str;
		int tree_num;

		mylen = obj_length;
		rsvp_object_tree = proto_item_add_subtree(ti, ETT_RSVP_ADSPEC);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %d - %s", 
				    obj->class, object_type);
		
		proto_tree_add_text(rsvp_object_tree, offset2, 1, 
				    "Message format version: %d", 
				    (*((unsigned char *)pd+offset2))>>4);
		proto_tree_add_text(rsvp_object_tree, offset2+2, 2, 
				    "Data length: %d words, not including header", 
				    pntohs(pd+offset2+2));
		offset2+=4;
		tree_num=ETT_RSVP_ADSPEC_SUBTREE1;
		mylen -= 4;
		while (mylen > 4) {
		    shdr = (service_hdr *)(pd + offset2);
		    str = match_strval(shdr->service_num, intsrv_services_str);

		    ti = proto_tree_add_text(rsvp_object_tree, offset2, 
					     (pntohs(&shdr->length)+1)<<2,
					     str?str:"Unknown");
		    adspec_tree = proto_item_add_subtree(ti, tree_num++);
		    proto_tree_add_text(adspec_tree, offset2, 1,
					"Service header %d - %s",
					shdr->service_num, str);
		    proto_tree_add_text(adspec_tree, offset2+1, 1,
					(shdr->break_bit&0x80)?
					"Break bit set":"Break bit not set");
		    proto_tree_add_text(adspec_tree, offset2+2, 2, 
					"Data length: %d words, not including header", 
					pntohs(&shdr->length));
		    offset2+=4; i=(pntohs(&shdr->length)+1)<<2; mylen-=4;
		    while (i>4) {
			phdr = (param_hdr *)(pd + offset2);
			str = match_strval(phdr->id, adspec_params);
			if (str) {
			    switch(phdr->id) {
			    case 4:
			    case 8:
			    case 10:
			    case 133:
			    case 134:
			    case 135:
			    case 136:
				/* 32-bit unsigned integer */
				proto_tree_add_text(adspec_tree, offset2, 
						    (pntohs(&phdr->length)+1)<<2,
						    "%s - %lu (type %d, length %d)",
						    str, 
						    (unsigned long)pntohl(&phdr->dataval), 
						    phdr->id, pntohs(&phdr->length));
				break;
				
			    case 6:
				/* IEEE float */
				proto_tree_add_text(adspec_tree, offset2, 
						    (pntohs(&phdr->length)+1)<<2,
						    "%s - %lu (type %d, length %d)",
						    str, 
						    ieee_to_long(&phdr->dataval), 
						    phdr->id, pntohs(&phdr->length));
				break;
			    default: 
				proto_tree_add_text(adspec_tree, offset2, 
						    (pntohs(&phdr->length)+1)<<2,
						    "%s (type %d, length %d)",
						    str, 
						    phdr->id, pntohs(&phdr->length));
			    }
			} else {
			    proto_tree_add_text(adspec_tree, offset2, 
						(pntohs(&phdr->length)+1)<<2,
						"Unknown (type %d, length %d)",
						phdr->id, pntohs(&phdr->length));
			}
			offset2+=(pntohs(&phdr->length)+1)<<2;
			i-=(pntohs(&phdr->length)+1)<<2;
			mylen-=(pntohs(&phdr->length)+1)<<2;
		    }
		}
		break;
	    }

	    case RSVP_CLASS_INTEGRITY :
		rsvp_object_tree = proto_item_add_subtree(ti, ETT_RSVP_INTEGRITY);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %d - %s", 
				    obj->class, object_type);
		goto default_class;

	    case RSVP_CLASS_POLICY :
		rsvp_object_tree = proto_item_add_subtree(ti, ETT_RSVP_POLICY);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %d - %s", 
				    obj->class, object_type);
		goto default_class;

	    default :
		rsvp_object_tree = proto_item_add_subtree(ti, ETT_RSVP_UNKNOWN_CLASS);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %d - %s", 
				    obj->class, object_type);
	    default_class:
		i = obj_length - sizeof(rsvp_object);
		proto_tree_add_text(rsvp_object_tree, offset2, i,
				 "Data (%d bytes)", i);
		break;

	    case RSVP_CLASS_NULL :
		break;

	    }  
	    
	    offset += obj_length;
	    len += obj_length;
	}
    }
}

void
proto_register_rsvp(void)
{
        proto_rsvp = proto_register_protocol("Resource ReserVation Protocol (RSVP)", "rsvp");
        proto_register_field_array(proto_rsvp, rsvpf_info, array_length(rsvpf_info));
}
