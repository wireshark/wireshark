/* packet-diameter.c
 * Routines for DIAMETER packet disassembly
 *
 * $Id: packet-diameter.c,v 1.7 2000/11/17 21:00:35 gram Exp $
 *
 * Copyright (c) 2000 by David Frascone <chaos@mindspring.com>
 *
 * Ethereal - Network traffic analyzer
 * By Johan Feyaerts
 * Copyright 1999 Johan Feyaerts
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

/* This must be defined before we include our dictionary defs */

typedef struct _value_value_pair {
        guint16 val1;
        guint16 val2;
} value_value_pair;

typedef enum {
	DIAMETER_DATA=1,
	DIAMETER_STRING,
	DIAMETER_ADDRESS,
	DIAMETER_INTEGER32,
	DIAMETER_INTEGER64,
	DIAMETER_TIME,
	DIAMETER_COMPLEX
} diameterDataTypes;

#include "packet-diameter.h"
#include "packet-diameter-defs.h"

#define COMMAND_CODE_OFFSET 20
#define  NTP_TIME_DIFF                   (2208988800UL)

#undef SCTP_DISSECTORS_ENABLED

#define UDP_PORT_DIAMETER	2645
#define TCP_PORT_DIAMETER	1812
#ifdef SCTP_DISSECTORS_ENABLED
#define SCTP_PORT_DIAMETER	1812
#endif
/* #define UDP_PORT_DIAMETER	1812  -- Compiling this in breaks RADIUS */

static int proto_diameter = -1;
static int hf_diameter_length = -1;
static int hf_diameter_code = -1;
static int hf_diameter_id =-1;
static int hf_diameter_flags = -1;
static int hf_diameter_ns = -1;
static int hf_diameter_nr = -1;

static gint ett_diameter = -1;
static gint ett_diameter_avp = -1;
static gint ett_diameter_avpinfo = -1;

static char gbl_diameterString[200];
static int gbl_diameterUdpPort=UDP_PORT_DIAMETER;
static int gbl_diameterTcpPort=TCP_PORT_DIAMETER;
#ifdef SCTP_DISSECTORS_ENABLED
static int gbl_diameterSctpPort=SCTP_PORT_DIAMETER;
#endif
gboolean gbl_commandCodeInHeader = FALSE;

typedef struct _e_diameterhdr {
  guint8 code;                   /* Must be 254 for diameter */
  guint8 flagsVer;
  guint16 pktLength;
  guint32 identifier;
  union {
    struct {
      guint16 nextSend;
      guint16 nextReceived;
    } old;
    struct {
      guint32 commandCode;
      guint32 vendorId;
      guint16 nextSend;
      guint16 nextReceived;
    } new;
  } u;
} e_diameterhdr;

typedef struct _e_avphdr {
  guint32 avp_type;
  guint16 avp_length;
  guint16 avp_flags;
  guint32 avp_vendorId;           /* optional */
  guint32 avp_tag;                /* optional */
  
} e_avphdr;

#define AUTHENTICATOR_LENGTH 12

#define DIAM_FLAGS_A 0x10
#define DIAM_FLAGS_W 0x08
#define AVP_FLAGS_P 0x0010
#define AVP_FLAGS_T 0x0008
#define AVP_FLAGS_V 0x0004
#define AVP_FLAGS_R 0x0002
#define AVP_FLAGS_M 0x0001

void proto_reg_handoff_diameter(void);

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

static gchar *rdconvertbufftostr(gchar *dest,guint8 length,const guint8 *pd)
{
/*converts the raw buffer into printable text */
guint32 i;
guint32 totlen=0;

        dest[0]='"';
        dest[1]=0;
        totlen=1;
        for (i=0; i < (guint32)length; i++)
        {
                if( isalnum((int)pd[i])||ispunct((int)pd[i])
                                ||((int)pd[i]==' '))            {
                        dest[totlen]=(gchar)pd[i];
                        totlen++;
                }
                else
                {
                        sprintf(&(dest[totlen]), "\\%03u", pd[i]);
                        totlen=totlen+strlen(&(dest[totlen]));
                }
        }
        dest[totlen]='"';
        dest[totlen+1]=0;
        return dest;
}

static gchar *rd_match_strval(guint32 val, const value_string *vs) {
	gchar		*result;
	result=match_strval(val,vs);
	if (result == NULL ) {
		result="Undefined";
	}
	return result;
}
static char *complexValCheck(e_avphdr *avp, const char *data, size_t dataLen)
{
	const char *rawData;
	static char returnStr[1024];

	switch (avp->avp_type) {
	case DIAMETER_ATT_INTEGRITY_CHECK_VALUE:
	{
		struct {
			guint32 transform;
			guint32 keyid;
		} icv;
		
		memcpy(&icv, data, 8);
		icv.transform=ntohl(icv.transform);
		icv.keyid=ntohl(icv.keyid);
		rawData = &data[8];

		sprintf(returnStr, 
		    "transform: 0x%08x (%d) keyid: 0x%08x (%d) Hash: ",
		    icv.transform, icv.transform, icv.keyid, icv.keyid);
		
		rdconvertbufftostr(&returnStr[strlen(returnStr)],
		    dataLen-8,
		    rawData);
		return returnStr;
	}
	}

	return NULL;;
} /* complexValCheck */
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
	case DIAMETER_ATT_COMMAND_CODE:
		return rd_match_strval(value, diameter_command_code_vals);
		break;
	case DIAMETER_ATT_FRAMED_IP_ADDRESS:
		return rd_match_strval(value, diameter_framed_ip_address_vals);
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
	case DIAMETER_ATT_REBOOT_TYPE:
		return rd_match_strval(value, diameter_reboot_type_vals);
		break;
	case DIAMETER_ATT_ACCT_STATUS_TYPE:
		return rd_match_strval(value, diameter_acct_status_type_vals);
		break;
	}

	return NULL;
}

static gchar *rd_value_to_str(e_avphdr *avph,const u_char *pd, int offset)
{
	int print_type;
	gchar *cont;
	guint32 intval;
	int dataLen;
	char *valstr;
	static char buffer[1024];

	dataLen = avph->avp_length - sizeof(e_avphdr);

	if (!(avph->avp_flags & AVP_FLAGS_V))
		dataLen += 4;
	if (!(avph->avp_flags & AVP_FLAGS_T))
		dataLen += 4;

/* prints the values of the attribute value pairs into a text buffer */
	
	print_type=match_numval(avph->avp_type,diameter_printinfo);
	/* Default begin */
	sprintf(buffer,"Value: ");
	cont=&buffer[strlen(buffer)];
	switch(print_type)
		{
		case DIAMETER_COMPLEX:
			valstr=complexValCheck(avph, &(pd[offset]), dataLen);
			if (valstr) {
				strcpy(cont, valstr);
				break;
			}
				
			/* Intentional fall through */
		case DIAMETER_DATA:
		case DIAMETER_STRING:
			rdconvertbufftostr(cont,dataLen,
			    &(pd[offset]));
			break;
		case DIAMETER_ADDRESS:
			sprintf(cont,"%u.%u.%u.%u",(guint8)pd[offset],
			    (guint8)pd[offset+1],(guint8)pd[offset+2],
			    (guint8)pd[offset+3]);
			break;
		case DIAMETER_INTEGER32:
			/* Check for custom values */
			intval=pntohl(&(pd[offset]));
			valstr=customValCheck(avph->avp_type, intval);
			if (valstr) {
				sprintf(cont,"%s (%u)", valstr, intval);
			} else {
				sprintf(cont,"%u", intval);
			}
			break;
		case DIAMETER_INTEGER64:
			sprintf(cont,"Unsupported Conversion");
			break;
		case DIAMETER_TIME:
		{
			struct tm lt;
			intval=pntohl(&(pd[offset]));
			intval -= NTP_TIME_DIFF;
			lt=*localtime((time_t *)&intval);
			strftime(cont, 1024, 
			    "%a, %d %b %Y %H:%M:%S %z",&lt);
		}
		break;
			
		default:
			rdconvertbufftostr(cont,dataLen,
			    &(pd[offset]));
			break;
		}
	if (cont == buffer) {
		strcpy(cont,"Unknown Value");
	}
	return buffer;
}


static void dissect_attribute_value_pairs(const u_char *pd, int offset,
    frame_data *fd, proto_tree *tree, int avplength) {
/* adds the attribute value pairs to the tree */
	e_avphdr avph;
	gchar *avptpstrval;
	gchar *valstr;
	guint32 tag=0;
	guint32 vendorId=0;
	int dataOffset;
	int fixAmt;
	proto_item *avptf;
	proto_tree *avptree;
	int vendorOffset, tagOffset;
	
	if (avplength==0) {
		proto_tree_add_text(tree, NullTVB,offset,0,
		    "No Attribute Value Pairs Found");
		return;
	}
	
	while (avplength > 0 ) {
		vendorOffset = tagOffset = 0;
		memcpy(&avph,&pd[offset],sizeof(e_avphdr));
		avph.avp_type = ntohl(avph.avp_type);
		avph.avp_length = ntohs(avph.avp_length);
		avph.avp_flags = ntohs(avph.avp_flags);
		
		if (avph.avp_flags & AVP_FLAGS_V) {
			vendorId = ntohl(avph.avp_vendorId);
			vendorOffset = 8;
			if (avph.avp_flags & AVP_FLAGS_T) {
				tag = ntohl(avph.avp_tag);
				tagOffset = 12;
				dataOffset = sizeof(e_avphdr);
			} else {
				/* only a vendor id */
				dataOffset = sizeof(e_avphdr) - sizeof(guint32);
			}
		} else {
			if (avph.avp_flags & AVP_FLAGS_T) {
				/* tag in vendor field */
				tag = ntohl(avph.avp_vendorId);
				tagOffset = 8;
				dataOffset = sizeof(e_avphdr) - sizeof(guint32);
			} else {
				/* No vendor or tag info */
				dataOffset = sizeof(e_avphdr) -
				    (2*sizeof(guint32));
			}
		}
		
	        /*
		 * Fix byte-alignment
		 */
		fixAmt = 4 - (avph.avp_length % 4);
		if (fixAmt == 4) fixAmt = 0;
		avplength=avplength - (avph.avp_length + fixAmt);
		avptpstrval=match_strval(avph.avp_type, diameter_attrib_type_vals);
		if (avptpstrval == NULL) avptpstrval="Unknown Type";
		if (!BYTES_ARE_IN_FRAME(offset, avph.avp_length)) {
			break;
		}
		avptf = proto_tree_add_text(tree,NullTVB,
		    offset, avph.avp_length,
		    "%s(%d) l:0x%x (%d bytes)",
		    avptpstrval,avph.avp_type,avph.avp_length,
		    avph.avp_length);
		avptree = proto_item_add_subtree(avptf,
		    ett_diameter_avpinfo);
		if (avptree !=NULL) {
			proto_tree_add_text(avptree,NullTVB,
			    offset, 4,
			    "AVP Code: %s(%d)",
			    avptpstrval,avph.avp_type);
			proto_tree_add_text(avptree,NullTVB,
			    offset+4 , 2,
			    "Length: 0x%x(%d bytes)",
			    avph.avp_length, avph.avp_length);
			proto_tree_add_text(avptree,NullTVB,
			    offset+6, 2,
			    "Flags: P:%d T:%d V:%d R:%d M:%d",
			    (avph.avp_flags & AVP_FLAGS_P)?1:0,
			    (avph.avp_flags & AVP_FLAGS_T)?1:0,
			    (avph.avp_flags & AVP_FLAGS_V)?1:0,
			    (avph.avp_flags & AVP_FLAGS_R)?1:0,
			    (avph.avp_flags & AVP_FLAGS_M)?1:0);
			if (vendorOffset) {
				proto_tree_add_text(avptree,NullTVB,
				    offset+vendorOffset, 4,
				    "VendorId: 0x%08x (%d)",
				    vendorId, vendorId);
			}
			if (tagOffset) {
				proto_tree_add_text(avptree,NullTVB,
				    offset+tagOffset, 4,
				    "Tag: 0x%08x (%d)",
				    tag, tag);
			}
			valstr=rd_value_to_str(&avph, pd, offset+dataOffset);
			proto_tree_add_text(avptree,NullTVB,
			    offset+dataOffset, avph.avp_length - dataOffset,
			    "Data: (%d bytes) %s",
			    avph.avp_length - dataOffset, valstr);
		}
		offset=offset+avph.avp_length + fixAmt;
	}
}

void dissect_diameter(const u_char *pd, int offset, frame_data *fd, 
    proto_tree *tree)
{
  proto_tree *diameter_tree,*avptree;
  proto_item *ti,*avptf;
  int avplength,hdrlength, offsetavp;
  e_diameterhdr dh;
  int commandCode;
  char buffer[2000];
  int nextSend=0, nextReceived=0;
  
  gchar *codestrval;
  
  OLD_CHECK_DISPLAY_AS_DATA(proto_diameter, pd, offset, fd, tree);
  
  if (gbl_commandCodeInHeader) 
    hdrlength=sizeof(e_diameterhdr);
  else
    hdrlength = sizeof(e_diameterhdr) - (2 * sizeof(guint32));

  memcpy(&dh,&pd[offset],hdrlength);
  /* Fix byte ordering in our static structure */
  dh.pktLength = ntohs(dh.pktLength);
  dh.identifier = ntohl(dh.identifier);
  
  /* Our code is in first avp */
  if (gbl_commandCodeInHeader) {
    dh.u.new.commandCode = ntohl(dh.u.new.commandCode);
    dh.u.new.vendorId = ntohl(dh.u.new.vendorId);

    if ((DIAM_FLAGS_W & dh.flagsVer)) {
      dh.u.new.nextSend = ntohs(dh.u.new.nextSend);
      dh.u.new.nextReceived = ntohs(dh.u.new.nextReceived);
      nextSend = dh.u.new.nextSend;
      nextReceived = dh.u.new.nextReceived;
    } else {
        hdrlength -= 4;
    }
    commandCode = dh.u.new.commandCode;
  } else {
    if ((DIAM_FLAGS_W & dh.flagsVer)) {
      dh.u.old.nextSend = ntohs(dh.u.old.nextSend);
      dh.u.old.nextReceived = ntohs(dh.u.old.nextReceived);
      nextSend = dh.u.old.nextSend;
      nextReceived = dh.u.old.nextReceived;
    } else {
        hdrlength -= 4;
    }
    memcpy(&commandCode, &pd[offset+COMMAND_CODE_OFFSET], 4);
    commandCode = ntohl(commandCode);
  }
  
  codestrval=  match_strval(commandCode,diameter_command_code_vals);
  if (codestrval==NULL) {
    codestrval="Unknown Packet";
  }
  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "DIAMETER");
  if (check_col(fd, COL_INFO)) {
    if (DIAM_FLAGS_W & dh.flagsVer) {
       if (DIAM_FLAGS_A & dh.flagsVer) {
         sprintf(buffer,"ACK (id=%d, l=%d, s=%d, r=%d)",
	         dh.identifier, dh.pktLength, nextSend,
	         nextReceived);
       } else {
         sprintf(buffer,"%s(%d) (id=%d, l=%d, s=%d, r=%d)",
	         codestrval,commandCode, dh.identifier, dh.pktLength,
	         nextSend, nextReceived);
       }
    } else {
       if (DIAM_FLAGS_A & dh.flagsVer) {
         sprintf(buffer,"ACK (id=%d, l=%d)",
	         dh.identifier, dh.pktLength);
       } else {
         sprintf(buffer,"%s(%d) (id=%d, l=%d)",
	         codestrval,commandCode,
		dh.identifier, dh.pktLength);
       }
   }
    col_add_fstr(fd,COL_INFO,buffer);
  }
  
  if (tree) {
    
    ti = proto_tree_add_protocol_format(tree, proto_diameter, NullTVB,
					offset, dh.pktLength, "%s",
					gbl_diameterString);
    diameter_tree = proto_item_add_subtree(ti, ett_diameter);
    
    if (!(DIAM_FLAGS_A & dh.flagsVer)) {
      proto_tree_add_uint_format(diameter_tree,
				 hf_diameter_code,
				 NullTVB,
				 offset+0,
				 1, dh.code, "Packet code:0x%02x",
				 dh.code);
    }
    
    proto_tree_add_uint_format(diameter_tree,
			       hf_diameter_flags,
			       NullTVB, offset+1, 1,
			       dh.flagsVer,
			       "Packet flags/Version: 0x%02x (Flags:0x%x,"
			       " A:%d W:%d Version=0x%1x (%d)",
			       dh.flagsVer, (dh.flagsVer&0xf8)>>3,
			       (DIAM_FLAGS_A & dh.flagsVer)?1:0,
			       (DIAM_FLAGS_W & dh.flagsVer)?1:0,
			       dh.flagsVer&0x07, dh.flagsVer&0x07);
    proto_tree_add_uint_format(diameter_tree,
			       hf_diameter_length, NullTVB,
			       offset+2, 2,
			       dh.pktLength, 
			       "Packet length: 0x%04x (%d)",dh.pktLength,
			       dh.pktLength); 
    proto_tree_add_uint_format(diameter_tree,hf_diameter_id,
			       NullTVB, offset+4, 4,
			       dh.identifier, "Packet identifier: 0x%08x (%d)",
			       dh.identifier, dh.identifier);         
    if (gbl_commandCodeInHeader) {
      proto_tree_add_uint_format(diameter_tree,hf_diameter_id,
				 NullTVB, offset+8, 4,
				 dh.identifier, "Command Code: 0x%08x (%d:%s)",
				 dh.u.new.commandCode, dh.u.new.commandCode,
				 codestrval);         
      proto_tree_add_uint_format(diameter_tree,hf_diameter_id,
				 NullTVB, offset+12, 4,
				 dh.identifier, "VendorId: 0x%08x (%d)",
				 dh.u.new.vendorId, dh.u.new.vendorId);         
      if (DIAM_FLAGS_W & dh.flagsVer) {
        proto_tree_add_uint_format(diameter_tree,
				   hf_diameter_ns, NullTVB,
				   offset+16, 2,
				   nextSend, 
				   "Ns: 0x%02x(%d)",nextSend, nextSend);
	
	proto_tree_add_uint_format(diameter_tree,
				   hf_diameter_nr, NullTVB,
				   offset+20, 2,
				   nextReceived, 
				   "Nr: 0x%02x(%d)", nextReceived,
				   nextReceived); 
      }
    } else {
      if (DIAM_FLAGS_W & dh.flagsVer) {
	proto_tree_add_uint_format(diameter_tree,
				   hf_diameter_ns, NullTVB,
				   offset+8, 2,
				   nextSend, 
				   "Ns: 0x%02x(%d)",nextSend, nextSend);
	
	proto_tree_add_uint_format(diameter_tree,
				   hf_diameter_nr, NullTVB,
				   offset+10, 2,
				   nextReceived, 
				   "Nr: 0x%02x(%d)", nextReceived,
				   nextReceived); 
      }
    }
    
    /* Update the lengths */
    avplength= dh.pktLength -hdrlength;
    offsetavp=offset+hdrlength;
    
    /* list the attribute value pairs */
    
    avptf = proto_tree_add_text(diameter_tree,
				NullTVB,offset+hdrlength,avplength,
				"Attribute value pairs");
    avptree = proto_item_add_subtree(avptf,
				     ett_diameter_avp);
    if (avptree !=NULL) {
      dissect_attribute_value_pairs( pd,
				     offsetavp,fd,avptree,avplength);
    }
  }
}

/* registration with the filtering engine */
void
proto_register_diameter(void)
{
	static hf_register_info hf[] = {
		{ &hf_diameter_code,
		  { "Code","diameter.code", FT_UINT8, BASE_DEC, NULL, 0x0,
		    "" }},
		
		{ &hf_diameter_flags,
		  { "Flags+Version", "diameter.flags", FT_UINT8, BASE_DEC, NULL, 0x0,
		    "" }},
		
		{ &hf_diameter_length,
		{ "Length","diameter.length", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "" }},
		
		{ &hf_diameter_id,
		{ "Identifier",	"diameter.id", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "" }},

		{ &hf_diameter_ns,
		  { "Next Send",	"diameter.ns", FT_UINT16, BASE_DEC, NULL, 0x0,
		    "" }},
		{ &hf_diameter_nr,
		  { "Next Received",	"diameter.nr", FT_UINT16, BASE_DEC, NULL, 0x0,
		    "" }},

	};
	static gint *ett[] = {
		&ett_diameter,
		&ett_diameter_avp,
		&ett_diameter_avpinfo
	};
	module_t *diameter_module;
	
	/* Register a configuration option for port */
	diameter_module = prefs_register_module("Diameter", "Diameter",
	    proto_reg_handoff_diameter);
	prefs_register_uint_preference(diameter_module, "udp.port",
				       "DIAMETER UDP Port",
				       "Set the port for DIAMETER messages (if"
				       " other than RADIUS port)",
				       10,
				       &gbl_diameterUdpPort);
	prefs_register_uint_preference(diameter_module, "tcp.port",
				       "DIAMETER TCP Port",
				       "Set the TCP port for DIAMETER messages",
				       10,
				       &gbl_diameterTcpPort);
#ifdef SCTP_DISSECTORS_ENABLED
	prefs_register_uint_preference(diameter_module, "sctp.port",
				       "DIAMETER SCTP Port",
				       "Set the SCTP port for DIAMETER messages",
				       10,
				       &gbl_diameterSctpPort);
#endif
	prefs_register_bool_preference(diameter_module, "command_in_header",
				       "Command code in header",
				       "Whether the command code is in the header, or in the first AVP",
				       &gbl_commandCodeInHeader);

	proto_diameter = proto_register_protocol (gbl_diameterString, "diameter");
	proto_register_field_array(proto_diameter, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_diameter(void)
{
	static int Initialized=FALSE;
	static int UdpPort=0;
	static int TcpPort=0;
#ifdef SCTP_DISSECTORS_ENABLED
	static int SctpPort=0;
#endif
	if (Initialized) {
		old_dissector_delete("udp.port", UdpPort, dissect_diameter);
		old_dissector_delete("tcp.port", TcpPort, dissect_diameter);
#ifdef SCTP_DISSECTORS_ENABLED
		old_dissector_delete("sctp.srcport", SctpPort, dissect_diameter);
		old_dissector_delete("sctp.destport", SctpPort, dissect_diameter);
#endif
	} else {
		Initialized=TRUE;
	}

	/* set port for future deletes */
	UdpPort=gbl_diameterUdpPort;
	TcpPort=gbl_diameterTcpPort;
#ifdef SCTP_DISSECTORS_ENABLED
	SctpPort=gbl_diameterSctpPort;
#endif

	strcpy(gbl_diameterString, "Diameter Protocol");

        /* g_warning ("Diameter: Adding tcp dissector to port %d",
		gbl_diameterTcpPort); */
	old_dissector_add("tcp.port", gbl_diameterTcpPort, dissect_diameter);
	old_dissector_add("udp.port", gbl_diameterUdpPort, dissect_diameter);
#ifdef SCTP_DISSECTORS_ENABLED
	old_dissector_add("sctp.srcport", gbl_diameterSctpPort, dissect_diameter);
	old_dissector_add("sctp.destport", gbl_diameterSctpPort, dissect_diameter);
#endif
}
