/* packet-diameter.c
 * Routines for DIAMETER packet disassembly
 *
 * $Id: packet-diameter.c,v 1.23 2001/06/18 02:17:45 guy Exp $
 *
 * Copyright (c) 2001 by David Frascone <dave@frascone.com>
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
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <glib.h>
#include "packet.h"
#include "resolv.h"
#include "prefs.h"

/* This must be defined before we include packet-diameter-defs.h s*/
typedef struct _value_value_pair {
        guint32 val1;
        guint32 val2;
} value_value_pair;

/* Valid data types */
typedef enum {
	DIAMETER_DATA=1,
	DIAMETER_STRING,
	DIAMETER_ADDRESS,
	DIAMETER_INTEGER32,
	DIAMETER_INTEGER64,
	DIAMETER_UNSIGNED32,
	DIAMETER_UNSIGNED64,
	DIAMETER_FLOAT32,
	DIAMETER_FLOAT64,
	DIAMETER_FLOAT128,
	DIAMETER_TIME,
	DIAMETER_GROUPED
} diameterDataTypes;

#include "packet-diameter-defs.h"

#define  NTP_TIME_DIFF                   (2208988800UL)

#define TCP_PORT_DIAMETER	1812
#define SCTP_PORT_DIAMETER	1812

static int proto_diameter = -1;
static int hf_diameter_length = -1;
static int hf_diameter_code = -1;
static int hf_diameter_hopbyhopid =-1;
static int hf_diameter_endtoendid =-1;
static int hf_diameter_reserved = -1;
static int hf_diameter_flags = -1;
static int hf_diameter_version = -1;
static int hf_diameter_vendor_id = -1;

static int hf_diameter_avp_code = -1;
static int hf_diameter_avp_length = -1;
static int hf_diameter_avp_reserved = -1;
static int hf_diameter_avp_flags = -1;
static int hf_diameter_avp_vendor_id = -1;


static int hf_diameter_avp_data_uint32 = -1;
static int hf_diameter_avp_data_int32 = -1;
#if 0
static int hf_diameter_avp_data_uint64 = -1;
static int hf_diameter_avp_data_int64 = -1;
#endif
static int hf_diameter_avp_data_bytes = -1;
static int hf_diameter_avp_data_string = -1;
static int hf_diameter_avp_data_v4addr = -1;
static int hf_diameter_avp_data_v6addr = -1;
static int hf_diameter_avp_data_time = -1;

static gint ett_diameter = -1;
static gint ett_diameter_avp = -1;
static gint ett_diameter_avpinfo = -1;

static char gbl_diameterString[200];
static int gbl_diameterTcpPort=TCP_PORT_DIAMETER;
static int gbl_diameterSctpPort=SCTP_PORT_DIAMETER;

typedef struct _e_diameterhdr {
	guint8 reserved;
	guint8 flagsVer;
	guint16 pktLength;
	guint32 hopByHopId;
	guint32 endToEndId;
	guint32 commandCode;
	guint32 vendorId;
} e_diameterhdr;

typedef struct _e_avphdr {
	guint32 avp_code;
	guint16 avp_length;
	guint8  avp_reserved;
	guint8  avp_flags;
	guint32 avp_vendorId;           /* optional */
} e_avphdr;

#define AUTHENTICATOR_LENGTH 12

/* Diameter Header Flags */
#define DIAM_FLAGS_E 0x20
#define DIAM_FLAGS_I 0x10
#define DIAM_FLAGS_R 0x08
#define DIAM_FLAGS_RESERVED 0xc0         /* 11000000  -- X X E I R V V V */

/* Diameter AVP Flags */
#define AVP_FLAGS_P 0x0020
#define AVP_FLAGS_V 0x0004
#define AVP_FLAGS_M 0x0001
#define AVP_FLAGS_RESERVED 0xea          /* 11101010  -- X X X P X V X M */

#define MIN_AVP_SIZE (sizeof(e_avphdr) - sizeof(guint32))
#define MIN_DIAMETER_SIZE (sizeof(e_diameterhdr) + MIN_AVP_SIZE)

static gchar *rd_value_to_str(e_avphdr *avph,const u_char *input, int length);
static void dissect_avps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static guint32 match_numval(guint32 val, const value_value_pair *vs);
static gchar *DetermineMessageType(char flagsVer);

/* Code to actually dissect the packets */

/*
 * Main dissector
 */
static void dissect_diameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	tvbuff_t        *avp_tvb;
	proto_tree *diameter_tree;
	e_diameterhdr dh;
	char *codestrval;
	size_t offset=0;
	size_t avplength;
	proto_tree *avp_tree;
	proto_item *avptf;
	int BadPacket = FALSE;
	
/* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->fd, COL_PROTOCOL)) 
		col_add_str(pinfo->fd, COL_PROTOCOL, "Diameter");
	if (check_col(pinfo->fd, COL_INFO)) 
		col_clear(pinfo->fd, COL_INFO);
	
	/* Copy our header */
	tvb_memcpy(tvb, (guint8*) &dh, offset, sizeof(dh));
	
	/* Fix byte ordering in our static structure */
	dh.pktLength = ntohs(dh.pktLength);
	dh.hopByHopId = ntohl(dh.hopByHopId);
	dh.endToEndId = ntohl(dh.endToEndId);
	
	dh.commandCode = ntohl(dh.commandCode);
	dh.vendorId = ntohl(dh.vendorId);
	
	codestrval=  match_strval(dh.commandCode,diameter_command_code_vals);
	if (codestrval==NULL) {
		codestrval="Unknown Command Code";
	}

	/* Short packet.  Should have at LEAST one avp */
	if (dh.pktLength < MIN_DIAMETER_SIZE) {
		g_warning("DIAMETER: Packet too short: %d bytes less than min size (%d bytes))",
			dh.pktLength, MIN_DIAMETER_SIZE);
		BadPacket = TRUE;
	}

	/* And, check our reserved flags/version */
	if (dh.reserved || (dh.flagsVer & DIAM_FLAGS_RESERVED) ||
		((dh.flagsVer & 0x7) != 1)) {
		g_warning("DIAMETER: Bad packet: Bad Flags or Version");
		BadPacket = TRUE;
	}

	if (check_col(pinfo->fd, COL_INFO)) {
		col_add_fstr(pinfo->fd, COL_INFO,
		    "%s%s: %s(%d) vendor=%d (hop-id=%d) (end-id=%d) EIR=%d%d%d",
		    (BadPacket)?"***** Bad Packet!: ":"",
		    DetermineMessageType(dh.flagsVer),
		    codestrval, dh.commandCode, dh.vendorId,
		    dh.hopByHopId, dh.endToEndId,
		    (dh.flagsVer & DIAM_FLAGS_E)?1:0,
		    (dh.flagsVer & DIAM_FLAGS_I)?1:0,
		    (dh.flagsVer & DIAM_FLAGS_R)?1:0);
	}
	

/* In the interest of speed, if "tree" is NULL, don't do any work not
   necessary to generate protocol tree items. */
	if (tree) {

/* create display subtree for the protocol */
		ti = proto_tree_add_item(tree, proto_diameter, tvb, offset, tvb_length(tvb), FALSE);
		diameter_tree = proto_item_add_subtree(ti, ett_diameter);

		/* Reserved */
		proto_tree_add_uint(diameter_tree, hf_diameter_reserved, tvb, offset, 1, dh.reserved);
		offset +=1;

		/* Flags */
		proto_tree_add_uint_format(diameter_tree,
		    hf_diameter_flags,
		    tvb, offset, 1,
		    dh.flagsVer,
		    "Packet flags: 0x%02x  E:%d I:%d R:%d (%s)",
		    (dh.flagsVer&0xf8)>>3,
		    (dh.flagsVer & DIAM_FLAGS_E)?1:0,
		    (dh.flagsVer & DIAM_FLAGS_I)?1:0,
		    (dh.flagsVer & DIAM_FLAGS_R)?1:0,
		    DetermineMessageType(dh.flagsVer));

		/* Version */
		proto_tree_add_uint(diameter_tree,
		    hf_diameter_version,
		    tvb, offset, 1,
		    dh.flagsVer);

		offset+=1;

		
		/* Length */
		proto_tree_add_uint(diameter_tree,
		    hf_diameter_length, tvb,
		    offset, 2, dh.pktLength);
		offset +=2;

		/* Hop-by-hop Identifier */
		proto_tree_add_uint(diameter_tree, hf_diameter_hopbyhopid,
		    tvb, offset, 4, dh.hopByHopId);
		offset += 4;

		/* End-to-end Identifier */
		proto_tree_add_uint(diameter_tree, hf_diameter_endtoendid,
		    tvb, offset, 4, dh.endToEndId);
		offset += 4;

		/* Command Code */
		proto_tree_add_uint(diameter_tree, hf_diameter_code,
		    tvb, offset, 4, dh.commandCode);
		offset += 4;

		/* Vendor Id */
		proto_tree_add_uint(diameter_tree,hf_diameter_vendor_id,
		    tvb, offset, 4,
		    dh.vendorId);
		offset += 4;

		/* If we have a bad packet, don't bother trying to parse the AVPs */
		if (BadPacket) {
			return;
		}

		/* Start looking at the AVPS */
		/* Make the next tvbuff */

		/* Update the lengths */
		avplength= dh.pktLength - sizeof(e_diameterhdr);
    
		avp_tvb = tvb_new_subset(tvb, offset, -1, avplength);
		avptf = proto_tree_add_text(diameter_tree,
		    tvb, offset, tvb_length(tvb),
		    "Attribute Value Pairs");
		
		avp_tree = proto_item_add_subtree(avptf,
		    ett_diameter_avp);
		if (avp_tree != NULL) {
			dissect_avps( avp_tvb, pinfo, avp_tree);
		}
	}
} /* dissect_diameter */

/*
 * This function will dissect the AVPs in a diameter packet.  It handles
 * all normal types, and even recursively calls itself for grouped AVPs
 */
static void dissect_avps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *avp_tree)
{
/* adds the attribute value pairs to the tree */
	e_avphdr avph;
	gchar *avptpstrval;
	gchar *valstr;
	guint32 vendorId=0;
	int hdrLength;
	int fixAmt;
	proto_tree *avpi_tree;
	int vendorOffset;
	size_t offset = 0 ;
	char dataBuffer[4096];
	tvbuff_t        *group_tvb;
	proto_tree *group_tree;
	proto_item *grouptf;
	proto_item *avptf;
	char buffer[1024];
	int BadPacket = FALSE;
	
	size_t packetLength;
	size_t avpDataLength;
	int avpType;

	packetLength = tvb_length(tvb);

	/* Check for invalid packet lengths */
	if (packetLength <= 0) {
		proto_tree_add_text(avp_tree, tvb, offset, tvb_length(tvb),
		    "No Attribute Value Pairs Found");
		return;
	}
	

	/* Spin around until we run out of packet */
	while (packetLength > 0 ) {
		vendorOffset = 0;
		
		/* Check for short packet */
		if (packetLength < MIN_AVP_SIZE) {
			g_warning("DIAMETER: AVP Payload too short: %d bytes less than min size (%d bytes))",
				packetLength, MIN_AVP_SIZE);
			BadPacket = TRUE;
			/* Don't even bother trying to parse a short packet. */
			return;
		}

		/* Copy our header */
		tvb_memcpy(tvb, (guint8*) &avph, offset, sizeof(avph));

		/* Fix the byte ordering */
		avph.avp_code = ntohl(avph.avp_code);
		avph.avp_length = ntohs(avph.avp_length);

		/* Dissect our vendor id if it exists  and set hdr length*/
		if (avph.avp_flags & AVP_FLAGS_V) {
			vendorId = ntohl(avph.avp_vendorId);
			/* Vendor id */
			hdrLength = sizeof(e_avphdr);
		} else {
			/* No vendor */
			hdrLength = sizeof(e_avphdr) - 
			    sizeof(guint32);
		}

		/* Check for bad length */
		if (avph.avp_length < MIN_AVP_SIZE || 
		    (avph.avp_length > packetLength)) {
			g_warning("DIAMETER: AVP payload size invalid: avp_length: %d bytes,  min: %d bytes,    packetLen: %d",
				avph.avp_length, MIN_AVP_SIZE, packetLength);
			BadPacket = TRUE;
		}

		/* Check for bad flags */
		if (avph.avp_reserved || 
		    (avph.avp_flags & AVP_FLAGS_RESERVED)) {
		        g_warning("DIAMETER: Invalid AVP: avph.avp_reserved = 0x%x, avph.avp_flags = 0x%x, resFl=0x%x",
			avph.avp_reserved, avph.avp_flags, AVP_FLAGS_RESERVED);
			BadPacket = TRUE;
		}
		
	        /*
		 * Fix byte-alignment (Diameter AVPs are sent on 4 byte
		 * boundries)
		 */
		fixAmt = 4 - (avph.avp_length % 4);
		if (fixAmt == 4) fixAmt = 0;

		packetLength = packetLength - (avph.avp_length + fixAmt);

		/* Check for out of bounds */
		if (packetLength < 0) {
		        g_warning("DIAMETER: Bad AVP: Bad new length (%d bytes)",
				packetLength);
			BadPacket = TRUE;
		}

		avptpstrval = match_strval(avph.avp_code, diameter_attrib_type_vals);
		if (avptpstrval == NULL) avptpstrval="Unknown Type";

		avptf = proto_tree_add_text(avp_tree, tvb,
		    offset, avph.avp_length,
		    "%s(%d) l:0x%x (%d bytes)",
		    avptpstrval, avph.avp_code, avph.avp_length,
		    avph.avp_length);
		avpi_tree = proto_item_add_subtree(avptf,
		    ett_diameter_avpinfo);

		if (avpi_tree !=NULL) {
			/* Command Code */
			proto_tree_add_uint(avpi_tree, hf_diameter_avp_code,
			    tvb, offset, 4, avph.avp_code);
			offset += 4;
		
			proto_tree_add_uint(avpi_tree, hf_diameter_avp_length,
			    tvb, offset, 2, avph.avp_length);
			offset += 2;

			proto_tree_add_uint(avpi_tree, hf_diameter_avp_reserved,
			    tvb, offset, 1, avph.avp_reserved);
			offset += 1;

			proto_tree_add_uint_format(avpi_tree,
			    hf_diameter_avp_flags, tvb,
			    offset, 1, avph.avp_flags,
			    "Flags: P:%d V:%d M:%d",
			    (avph.avp_flags & AVP_FLAGS_P)?1:0,
			    (avph.avp_flags & AVP_FLAGS_V)?1:0,
			    (avph.avp_flags & AVP_FLAGS_M)?1:0);
			offset += 1;

			if (avph.avp_flags & AVP_FLAGS_V) {
				proto_tree_add_uint(avpi_tree, hf_diameter_avp_vendor_id,
				    tvb, offset, 4, avph.avp_vendorId);
				offset += 4;
			}

			avpDataLength = avph.avp_length - hdrLength;

			/*
			 * If we've got a bad packet, just highlight the data.  Don't try
			 * to parse it, and, don't move to next AVP.
			 */
			if (BadPacket) {
				offset -= hdrLength;
				proto_tree_add_bytes_format(avpi_tree, hf_diameter_avp_data_bytes,
				    tvb, offset, tvb_length(tvb) - offset, dataBuffer,
				    "Bad AVP (Suspect Data Not Dissected)");
				return;
			}

			avpType=match_numval(avph.avp_code, diameter_printinfo);
			tvb_memcpy(tvb, (guint8*) dataBuffer, offset, MIN(4095,
				       avph.avp_length - hdrLength));
			
			switch(avpType) {
			case DIAMETER_GROUPED:
				sprintf(buffer, "%s Grouped AVPs", avptpstrval);
				/* Recursively call ourselves */
				grouptf = proto_tree_add_text(avpi_tree,
				    tvb, offset, tvb_length(tvb),
				    buffer);
				
				group_tree = proto_item_add_subtree(grouptf,
				    ett_diameter_avp);

				group_tvb = tvb_new_subset(tvb, offset,
				    MIN(avpDataLength, tvb_length(tvb)-offset), avpDataLength);
				if (group_tree != NULL) {
					dissect_avps( group_tvb, pinfo, group_tree);
				}
				break;
				
			case DIAMETER_STRING:
				proto_tree_add_string_format(avpi_tree, hf_diameter_avp_data_string,
				    tvb, offset, avpDataLength, dataBuffer,
				    "String: %*.*s", (int)avpDataLength, (int)avpDataLength,
				    dataBuffer);
				break;
			case DIAMETER_ADDRESS:
				if (avpDataLength == 4) {
				        guint32 ipv4Address = ntohl((*(guint32*)dataBuffer));
					proto_tree_add_ipv4_format(avpi_tree, hf_diameter_avp_data_v4addr,
					    tvb, offset, avpDataLength, ipv4Address,
					    "IPv4 Address: %u.%u.%u.%u",
					    (ipv4Address&0xff000000)>>24,
					    (ipv4Address&0xff0000)>>16,
					    (ipv4Address&0xff00)>>8,
					    (ipv4Address&0xff));
				} else if (avpDataLength == 16) {
					proto_tree_add_ipv6_format(avpi_tree, hf_diameter_avp_data_v6addr,
					    tvb, offset, avpDataLength, dataBuffer, 
					    "IPv6 Address: %04x:%04x:%04x:%04x",
					    *((guint32*)dataBuffer),
					    *((guint32*)&dataBuffer[4]),
					    *((guint32*)&dataBuffer[8]),
					    *((guint32*)&dataBuffer[12]));
				} else {
					proto_tree_add_bytes_format(avpi_tree, hf_diameter_avp_data_bytes,
					    tvb, offset, avpDataLength, dataBuffer,
					    "Error!  Bad Address Length");
				}
				break;

			case DIAMETER_INTEGER32:
			case DIAMETER_UNSIGNED32:
			case DIAMETER_INTEGER64:
			case DIAMETER_UNSIGNED64:
				valstr=rd_value_to_str(&avph, dataBuffer, offset);
				
				proto_tree_add_int_format(avpi_tree, hf_diameter_avp_data_int32,
				    tvb, offset, avpDataLength, (*(guint32*)dataBuffer),
				    "Value: %s",  valstr);

				break;

			case DIAMETER_TIME:
				valstr=rd_value_to_str(&avph, dataBuffer, offset);

				proto_tree_add_bytes_format(avpi_tree, hf_diameter_avp_data_bytes,
				    tvb, offset, avpDataLength, dataBuffer, "Time: %s", valstr);
				break;
				
			default:
			case DIAMETER_DATA:
				proto_tree_add_bytes_format(avpi_tree, hf_diameter_avp_data_bytes,
				    tvb, offset, avpDataLength, dataBuffer,
				    "Data");
				break;
				
			}
			offset += avph.avp_length - hdrLength;
		}
		offset += fixAmt; /* fix byte alignment */
	}
} /* dissect_avps */

/* Generic routine to work with value value pairs */
static guint32 match_numval(guint32 val, const value_value_pair *vs)
{
  guint32 i = 0;

  while (vs[i].val1) {
    if (vs[i].val1 == val)
      return(vs[i].val2);
    i++;
  }

  return(0);
}

static gchar *rd_match_strval(guint32 val, const value_string *vs) {
	gchar		*result;
	result=match_strval(val,vs);
	if (result == NULL ) {
		result="Undefined";
	}
	return result;
}
static char *customValCheck(int code, int value)
{
	switch (code) {
	case DIAMETER_ATT_QOS_SERVICE_TYPE:
		return rd_match_strval(value, diameter_qos_service_type_vals);
		break;
	case DIAMETER_ATT_SERVICE_TYPE:
		return rd_match_strval(value, diameter_service_type_vals);
		break;
	case DIAMETER_ATT_PROHIBIT:
		return rd_match_strval(value, diameter_prohibit_vals);
		break;
	case DIAMETER_ATT_PROMPT:
		return rd_match_strval(value, diameter_prompt_vals);
		break;
	case DIAMETER_ATT_SOURCE_PORT:
		return rd_match_strval(value, diameter_source_port_vals);
		break;
	case DIAMETER_ATT_NAS_PORT_TYPE:
		return rd_match_strval(value, diameter_nas_port_type_vals);
		break;
	case DIAMETER_ATT_INTERFACE_ADDRESS:
		return rd_match_strval(value, diameter_interface_address_vals);
		break;
	case DIAMETER_ATT_FRAMED_ROUTING:
		return rd_match_strval(value, diameter_framed_routing_vals);
		break;
	case DIAMETER_ATT_ARAP_ZONE_ACCESS:
		return rd_match_strval(value, diameter_arap_zone_access_vals);
		break;
	case DIAMETER_ATT_ACCT_AUTHENTIC:
		return rd_match_strval(value, diameter_acct_authentic_vals);
		break;
	case DIAMETER_ATT_FRAMED_PROTOCOL:
		return rd_match_strval(value, diameter_framed_protocol_vals);
		break;
	case DIAMETER_ATT_FRAMED_COMPRESSION:
		return rd_match_strval(value, diameter_framed_compression_vals);
		break;
	case DIAMETER_ATT_AUTHENTICATION_TYPE:
		return rd_match_strval(value, diameter_authentication_type_vals);
		break;
	case DIAMETER_ATT_ACCT_TERMINATE_CAUSE:
		return rd_match_strval(value, diameter_acct_terminate_cause_vals);
		break;
	case DIAMETER_ATT_PROTOCOL:
		return rd_match_strval(value, diameter_protocol_vals);
		break;
	case DIAMETER_ATT_DESTINATION_PORT:
		return rd_match_strval(value, diameter_destination_port_vals);
		break;
	case DIAMETER_ATT_TERMINATION_ACTION:
		return rd_match_strval(value, diameter_termination_action_vals);
		break;
	case DIAMETER_ATT_EXTENSION_ID:
		return rd_match_strval(value, diameter_extension_id_vals);
		break;
	case DIAMETER_ATT_MERIT_LAS_CODE:
		return rd_match_strval(value, diameter_merit_las_code_vals);
		break;
	case DIAMETER_ATT_LOGIN_SERVICE:
		return rd_match_strval(value, diameter_login_service_vals);
		break;
	case DIAMETER_ATT_RSVP_SERVICE_TYPE:
		return rd_match_strval(value, diameter_rsvp_service_type_vals);
		break;
	case DIAMETER_ATT_ACCT_STATUS_TYPE:
		return rd_match_strval(value, diameter_acct_status_type_vals);
		break;
	}

	return NULL;
}

static gchar *rd_value_to_str(e_avphdr *avph, const u_char *input, int length)
{
	int print_type;
	guint32 intval;
	char *valstr;
	static char buffer[1024];

/* prints the values of the attribute value pairs into a text buffer */
	
	print_type=match_numval(avph->avp_code,diameter_printinfo);

	/* Set the Default */
	strcpy(buffer, "Unknown Value");

	/* Default begin */
	switch(print_type)
		{
		case DIAMETER_INTEGER32:
			/* Check for custom values */
			intval=pntohl(input);
			valstr=customValCheck(avph->avp_code, intval);
			if (valstr) {
				sprintf(buffer,"%s (%u)", valstr, intval);
			} else {
				sprintf(buffer,"%d", intval);
			}
			break;
		case DIAMETER_UNSIGNED32:
			/* Check for custom values */
			intval=pntohl(input);
			valstr=customValCheck(avph->avp_code, intval);
			if (valstr) {
				sprintf(buffer,"%s (%u)", valstr, intval);
			} else {
				sprintf(buffer,"%u", intval);
			}
			break;
#ifdef G_HAVE_GINT64
		/* XXX - have to handle platforms without 64-bit integral
		   types.
		   Have to handle platforms where "%lld" and "%llu"
		   aren't the right formats to use to print 64-bit integral
		   types. */
		case DIAMETER_INTEGER64:
		{
			gint64 llval;
			llval = pntohll(input);
			sprintf(buffer,"%lld", llval);
		}
			break;
		case DIAMETER_UNSIGNED64:
		{
			guint64 llval;
			llval = pntohll(input);
			sprintf(buffer,"%llu", llval);
		}
			break;
#endif
		case DIAMETER_TIME:
		{
			struct tm lt;
			intval=pntohl(input);
			intval -= NTP_TIME_DIFF;
			lt=*localtime((time_t *)&intval);
			strftime(buffer, 1024, 
			    "%a, %d %b %Y %H:%M:%S %z",&lt);
		}
		default:
			/* Do nothing */
			;
		}
	return buffer;
} /* rd value to str */

static gchar *
DetermineMessageType(char flagsVer)
{
	/* Get rid of version */
	flagsVer = flagsVer >> 3;

	/* Mask out reserved bits */
	flagsVer = flagsVer & 0x7;

	switch (flagsVer) {
	case 0x0: /* Indication */
		return "Indication";
	case 0x4: /* Request */
		return "Request";
	case 0x1: /* Answer */
		return "Answer";
	case 0x6: /* Query */
		return "Query";
	case 0x3: /* Reply */
		return "Reply";
	default:
		return "Illegal Command Type";
	}
} /* DetermineMessageType */


void
proto_reg_handoff_diameter(void)
{
	static int Initialized=FALSE;
	static int TcpPort=0;
	static int SctpPort=0;

	if (Initialized) {
		dissector_delete("tcp.port", TcpPort, dissect_diameter);
		dissector_delete("sctp.port", SctpPort, dissect_diameter);
	} else {
		Initialized=TRUE;
	}

	/* set port for future deletes */
	TcpPort=gbl_diameterTcpPort;
	SctpPort=gbl_diameterSctpPort;

	strcpy(gbl_diameterString, "Diameter Protocol");

        /* g_warning ("Diameter: Adding tcp dissector to port %d",
		gbl_diameterTcpPort); */
	dissector_add("tcp.port", gbl_diameterTcpPort, dissect_diameter,
	    proto_diameter);
	dissector_add("sctp.port", gbl_diameterSctpPort,
	    dissect_diameter, proto_diameter);
}

/* registration with the filtering engine */
void
proto_register_diameter(void)
{

	static hf_register_info hf[] = {
		{ &hf_diameter_reserved,
		  { "Reserved", "diameter.reserved", FT_UINT8, BASE_HEX, NULL, 0x0,
		    "Should be zero", HFILL }},
		{ &hf_diameter_flags,
		  { "Flags", "diameter.flags", FT_UINT8, BASE_HEX, NULL, 0xf8,
		    "", HFILL }},
		{ &hf_diameter_version,
		  { "Version", "diameter.version", FT_UINT8, BASE_HEX, NULL, 0x07,
		    "", HFILL }},
		{ &hf_diameter_length,
		  { "Length","diameter.length", FT_UINT16, BASE_DEC, NULL, 0x0,
		    "", HFILL }},
		{ &hf_diameter_hopbyhopid,
		  { "Hop-by-Hop Identifier", "diameter.hopbyhopid", FT_UINT32,
		    BASE_HEX, NULL, 0x0, "", HFILL }},
		{ &hf_diameter_endtoendid,
		  { "End-to-End Identifier", "diameter.endtoendid", FT_UINT32, 
		    BASE_HEX, NULL, 0x0, "", HFILL }},
		{ &hf_diameter_code,
		  { "Command Code","diameter.code", FT_UINT32, BASE_DEC,
		    VALS(diameter_command_code_vals), 0x0, "", HFILL }},
		{ &hf_diameter_vendor_id,
		  { "VendorId",	"diameter.vendorId", FT_UINT32, BASE_DEC, NULL, 0x0,
		    "", HFILL }},

		{ &hf_diameter_avp_code,
		  { "AVP Code","diameter.avp.code", FT_UINT32, BASE_DEC,
		    VALS(diameter_attrib_type_vals), 0x0, "", HFILL }},
		{ &hf_diameter_avp_length,
		  { "AVP length","diameter.avp.length", FT_UINT16, BASE_DEC,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_reserved,
		  { "AVP Reserved","diameter.avp.reserved", FT_UINT8, BASE_HEX,
		    NULL, 0x0, "Should be Zero", HFILL }},
		{ &hf_diameter_avp_flags,
		  { "AVP Flags","diameter.avp.flags", FT_UINT8, BASE_HEX,
		    NULL, 0x1f, "", HFILL }},
		{ &hf_diameter_avp_vendor_id,
		  { "AVP Vendor Id","diameter.avp.vendorId", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_data_uint32,
		  { "AVP Data","diameter.avp.data.uint32", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "", HFILL }},
#if 0
		{ &hf_diameter_avp_data_uint64,
		  { "AVP Data","diameter.avp.data.uint64", FT_UINT64, BASE_DEC,
		    NULL, 0x0, "", HFILL }},
#endif
		{ &hf_diameter_avp_data_int32,
		  { "AVP Data","diameter.avp.data.int32", FT_INT32, BASE_DEC,
		    NULL, 0x0, "", HFILL }},
#if 0
		{ &hf_diameter_avp_data_int64,
		  { "AVP Data","diameter.avp.data.int64", FT_INT_64, BASE_DEC,
		    NULL, 0x0, "", HFILL }},
#endif
		{ &hf_diameter_avp_data_bytes,
		  { "AVP Data","diameter.avp.data.bytes", FT_BYTES, BASE_NONE,
		    NULL, 0x0, "", HFILL }},

		{ &hf_diameter_avp_data_string,
		  { "AVP Data","diameter.avp.data.string", FT_STRING, BASE_NONE,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_data_v4addr,
		  { "AVP Data","diameter.avp.data.v4addr", FT_IPv4, BASE_NONE,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_data_v6addr,
		  { "AVP Data","diameter.avp.data.v6addr", FT_IPv6, BASE_NONE,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_data_time,
		  { "AVP Data","diameter.avp.data.time", FT_ABSOLUTE_TIME, BASE_NONE,
		    NULL, 0x0, "", HFILL }},

	};
	static gint *ett[] = {
		&ett_diameter,
		&ett_diameter_avp,
		&ett_diameter_avpinfo
	};
	module_t *diameter_module;

	proto_diameter = proto_register_protocol (gbl_diameterString,
	    "DIAMETER", "diameter");
	proto_register_field_array(proto_diameter, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register a configuration option for port */
	diameter_module = prefs_register_protocol(proto_diameter,
	    proto_reg_handoff_diameter);
	prefs_register_uint_preference(diameter_module, "tcp.port",
				       "DIAMETER TCP Port",
				       "Set the TCP port for DIAMETER messages",
				       10,
				       &gbl_diameterTcpPort);
	prefs_register_uint_preference(diameter_module, "sctp.port",
				       "DIAMETER SCTP Port",
				       "Set the SCTP port for DIAMETER messages",
				       10,
				       &gbl_diameterSctpPort);
}
