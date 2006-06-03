/* packet-btsdp.c
 * Routines for Bluetooth SDP dissection
 * Copyright 2002, Wolfgang Hansmann <hansmann@cs.uni-bonn.de>
 *
 * Refactored for wireshark checkin
 *   Ronnie Sahlberg 2006
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/value_string.h>
#include <epan/emem.h>
#include <etypes.h>
#include "packet-btl2cap.h"

/* Initialize the protocol and registered fields */
static int proto_btsdp = -1;
static int hf_pduid = -1;
static int hf_tid = -1;
static int hf_plen = -1;
static int hf_ssr_total_count = -1;
static int hf_ssr_current_count = -1;
static int hf_error_code = -1;
static int hf_ssares_al_bytecount = -1;


/* Initialize the subtree pointers */
static gint ett_btsdp = -1;
static gint ett_btsdp_ssr = -1;
static gint ett_btsdp_des = -1;
static gint ett_btsdp_attribute = -1;
static gint ett_btsdp_service_search_pattern = -1;
static gint ett_btsdp_attribute_idlist = -1;

static const value_string vs_pduid[] = {
	{0x1, "SDP_ErrorResponse"},
	{0x2, "SDP_ServiceSearchRequest"},
	{0x3, "SDP_ServiceSearchResponse"},
	{0x4, "SDP_ServiceAttributeRequest"},
	{0x5, "SDP_ServiceAttributeResponse"},
	{0x6, "SDP_ServiceSearchAttributeRequest"},
	{0x7, "SDP_ServiceSearchAttributeResponse"},
	{0, NULL}
};

static const value_string vs_error_code[] = {
	{0x0001, "Invalid/unsupported SDP version"},
	{0x0002, "Invalid Service Record Handle"},
	{0x0003, "Invalid request syntax"},
	{0x0004, "Invalid PDU size"},
	{0x0005, "Invalid Continuation State"},
	{0x0006, "Insufficient Resources to satisfy Request"},
	{0, NULL}
};

static const value_string vs_general_attribute_id[] = {
	{0x0000, "ServiceRecordHandle"},
	{0x0001, "ServiceClassIDList"},
	{0x0002, "ServiceRecordState"},
	{0x0003, "ServiceID"},
	{0x0004, "ProtocolDescriptorList"},
	{0x0005, "BrowseGroupList"},
	{0x0006, "LanguageBaseAttributeIDList"},
	{0x0007, "ServiceinfoTimeToLive"},
	{0x0008, "ServiceAvailability"},
	{0x0009, "BluetoothProfileDescriptorList"},
	{0x000a, "DocumentationURL"},
	{0x000b, "ClientExecutableURL"},
	{0x000c, "IconURL"},
	{0x0100, "Service Name"},
	{0x0101, "Service Description"},
	{0x0102, "Service Provider"},
	{0, NULL}
};


static const value_string vs_protocols[] = {
	{0x0001, "SDP"},
	{0x0002, "UDP"},
	{0x0003, "RFCOMM"},
	{0x0004, "TCP"},
	{0x0005, "TCS-BIN"},
	{0x0006, "TCS-AT"},
	{0x0008, "OBEX"},
	{0x0009, "IP"},
	{0x000A, "FTP"},
	{0x000C, "HTTP"},
	{0x000E, "WSP"},
	{0x000F, "BNEP"},
	{0x0010, "UPNP"},
	{0x0011, "HIDP"},
	{0x0012, "HardcopyControlChannel"},
	{0x0014, "HardcopyDataChannel"},
	{0x0016, "HardcopyNotification"},
	{0x0017, "AVCTP"},
	{0x0019, "AVDTP"},
	{0x001B, "CMPT"},
	{0x001D, "UDI_C-Plane"},
	{0x0100, "L2CAP"},
	{0, NULL}
};

static const value_string vs_service_classes[] = {

	{0x0001, "SDP"},
	{0x0002, "UDP"},
	{0x0003, "RFCOMM"},
	{0x0004, "TCP"},
	{0x0005, "TCS-BIN"},
	{0x0006, "TCS-AT"},
	{0x0008, "OBEX"},
	{0x0009, "IP"},
	{0x000A, "FTP"},
	{0x000C, "HTTP"},
	{0x000E, "WSP"},
	{0x000F, "BNEP"},
	{0x0010, "UPNP"},
	{0x0011, "HIDP"},
	{0x0012, "HardcopyControlChannel"},
	{0x0014, "HardcopyDataChannel"},
	{0x0016, "HardcopyNotification"},
	{0x0017, "AVCTP"},
	{0x0019, "AVDTP"},
	{0x001B, "CMPT"},
	{0x001D, "UDI_C-Plane"},
	{0x0100, "L2CAP"},
	{0x1000, "ServiceDiscoveryServerServiceClassID"},
	{0x1001, "BrowseGroupDescriptorServiceClassID"},
	{0x1002, "PublicBrowseGroup"},
	{0x1101, "SerialPort"},
	{0x1102, "LANAccessUsingPPP"},
	{0x1103, "DialupNetworking"},
	{0x1104, "IrMCSync"},
	{0x1105, "OBEXObjectPush"},
	{0x1106, "OBEXFileTransfer"},
	{0x1107, "IrMCSyncCommand"},
	{0x1108, "Headset"},
	{0x1109, "CordlessTelephony"},
	{0x110A, "AudioSource"},
	{0x110B, "AudioSink"},
	{0x110C, "A/V_RemoteControlTarget"},
	{0x110D, "AdvancedAudioDistribution"},
	{0x110E, "A/V_RemoteControl"},
	{0x110F, "VideoConferencing"},
	{0x1110, "Intercom"},
	{0x1111, "Fax"},
	{0x1112, "HeadsetAudioGateway"},
	{0x1113, "WAP"},
	{0x1114, "WAP_CLIENT"},
	{0x1115, "PANU"},
	{0x1116, "NAP"},
	{0x1117, "GN"},
	{0x1118, "DirectPrinting"},
	{0x1119, "ReferencePrinting"},
	{0x111A, "Imaging"},
	{0x111B, "ImagingResponder"},
	{0x111C, "ImagingAutomaticArchive"},
	{0x111D, "ImagingReferencedObjects"},
	{0x1115, "PANU"},
	{0x1116, "NAP"},
	{0x1117, "GN"},
	{0x1118, "DirectPrinting"},
	{0x1119, "ReferencePrinting"},
	{0x111A, "Imaging"},
	{0x111B, "ImagingResponder"},
	{0x111C, "ImagingAutomaticArchive"},
	{0x111D, "ImagingReferencedObjects"},
	{0x111E, "Handsfree"},
	{0x111F, "HandsfreeAudioGateway"},
	{0x1120, "DirectPrintingReferenceObjectsService"},
	{0x1121, "ReflectedUI"},
	{0x1122, "BasicPrinting"},
	{0x1123, "PrintingStatus"},
	{0x1124, "HumanInterfaceDeviceService"},
	{0x1125, "HardcopyCableReplacement"},
	{0x1126, "HCR_Print"},
	{0x1127, "HCR_Scan"},
	{0x1128, "Common_ISDN_Access"},
	{0x1129, "VideoConferencingGW"},
	{0x112A, "UDI_MT"},
	{0x112B, "UDI_TA"},
	{0x112C, "Audio/Video"},
	{0x112D, "SIM_Access"},
	{0x1200, "PnPInformation"},
	{0x1201, "GenericNetworking"},
	{0x1202, "GenericFileTransfer"},
	{0x1203, "GenericAudio"},
	{0x1204, "GenericTelephony"},
	{0x1205, "UPNP_Service"},
	{0x1206, "UPNP_IP_Service"},
	{0x1300, "ESDP_UPNP_IP_PAN"},
	{0x1301, "ESDP_UPNP_IP_LAP"},
	{0x1302, "ESDP_UPNP_L2CAP"},
	{0, NULL}
};



static int 
get_type_length(tvbuff_t *tvb, int offset, int *length)
{
	int size = 0;
	guint8 byte0 = tvb_get_guint8(tvb, offset);
	offset++;
	
	switch (byte0 & 0x07) {
	case 0:
		size = (byte0 >> 3) == 0 ? 0 : 1;
		break;
	case 1:
		size = 2;
		break;
	case 2:
		size = 4;
		break;
	case 3:		
		size = 8;
		break;
	case 4:
		size = 16;
		break;
	case 5:
		size = tvb_get_guint8(tvb, offset);
		offset++;
		break;
	case 6:
		size = tvb_get_ntohs(tvb, offset);
		offset += 2;
		break;
	case 7:
		size = tvb_get_ntohl(tvb, offset);
		offset += 4;
		break;		
	}

	*length = size;
	return offset;
}


static guint32 
get_uint_by_size(tvbuff_t *tvb, int off, int size) 
{
	switch(size) {
	case 0:
		return tvb_get_guint8(tvb, off);
	case 1:
		return tvb_get_ntohs(tvb, off);
	case 2:
		return tvb_get_ntohl(tvb, off);
	default:
		return 0xffffffff;
	}
}


static gint32 
get_int_by_size(tvbuff_t *tvb, int off, int size) 
{
	switch(size) {
	case 0:
		return tvb_get_guint8(tvb, off);
	case 1:
		return tvb_get_ntohs(tvb, off);
	case 2:
		return tvb_get_ntohl(tvb, off);
	default:
		return -1;
	}
}


static int 
dissect_attribute_id_list(proto_tree *t, tvbuff_t *tvb, int offset)
{
	proto_item *ti;
	proto_tree *st;
	int start_offset, bytes_to_go;

	start_offset=offset;
	ti = proto_tree_add_text(t, tvb, offset, 2, "AttributeIDList");
	st = proto_item_add_subtree(ti, ett_btsdp_attribute_idlist);

	offset = get_type_length(tvb, offset, &bytes_to_go);
	proto_item_set_len(ti, offset - start_offset + bytes_to_go);

	while(bytes_to_go>0){
		guint8 byte0 = tvb_get_guint8(tvb, offset);

		if (byte0 == 0x09) { /* 16 bit attribute id */

			proto_tree_add_text(st, tvb, offset, 3, "0x%04x", 
					    tvb_get_ntohs(tvb, offset + 1));
			offset+=3;
			bytes_to_go-=3;
		} else if (byte0 == 0x0a) { /* 32 bit attribute range */

			proto_tree_add_text(st, tvb, offset, 5, "0x%04x - 0x%04x", 
					    tvb_get_ntohs(tvb, offset + 1),
					    tvb_get_ntohs(tvb, offset + 3));
			offset+=5;
			bytes_to_go-=5;
		}
	}
	return offset - start_offset;
}


static int
dissect_sdp_error_response(proto_tree *t, tvbuff_t *tvb, int offset) {
	
        proto_tree_add_item(t, hf_error_code, tvb, offset, 2, FALSE);
	offset+=2;

	return offset;
}


static int
dissect_sdp_type(proto_tree *t, tvbuff_t *tvb, int offset, char **attr_val)
{
#define MAX_SDP_LEN 1024
	int strpos=0, size, start_offset, type_size;
	char *str;
	guint8 byte0;
	guint8 type;
	guint8 size_index;


	str=ep_alloc(MAX_SDP_LEN+1);
	*attr_val=str;
	str[0]=0;

	byte0=tvb_get_guint8(tvb, offset);
	type=(byte0>>3)&0x1f;
	size_index=byte0&0x07;

	start_offset=offset;
	offset = get_type_length(tvb, offset, &size);
	type_size = offset - start_offset + size;


	switch (type) {
	case 0:
		proto_tree_add_text(t, tvb, start_offset, type_size, "Nil ");
		if(strpos<MAX_SDP_LEN){
			strpos+=g_snprintf(str+strpos, MAX_SDP_LEN-strpos, "Nil ");
		}
		break;
	case 1: {
		guint32 val = get_uint_by_size(tvb, offset, size_index);
		proto_tree_add_text(t, tvb, start_offset, type_size, 
				    "unsigned int %d ", val);
		if(strpos<MAX_SDP_LEN){
			strpos+=g_snprintf(str+strpos, MAX_SDP_LEN-strpos, "%u ", val);
		}
		break;
	}
	case 2: {
		guint32 val = get_int_by_size(tvb, offset, size_index);
		proto_tree_add_text(t, tvb, start_offset, type_size, 
				    "signed int %d ", val);
		if(strpos<MAX_SDP_LEN){
			strpos+=g_snprintf(str+strpos, MAX_SDP_LEN-strpos, "%d ", val);
		}
		break;
	}
	case 3: {
		char *ptr = tvb_bytes_to_str(tvb, offset, size);

		if(size == 2){

			guint16 id = tvb_get_ntohs(tvb, offset);	
			const char *uuid_name = val_to_str(id, vs_service_classes, "Unknown");

			proto_tree_add_text(t, tvb, start_offset, type_size,
					    "%s(0x%s) ", uuid_name, ptr);
			if(strpos<MAX_SDP_LEN){
				strpos+=g_snprintf(str+strpos, MAX_SDP_LEN-strpos, "UUID:%s (0x%s) ", uuid_name, ptr);
			}
		} else {

			proto_tree_add_text(t, tvb, start_offset, type_size, 
					    "UUID 0x%s ", ptr);
			if(strpos<MAX_SDP_LEN){
				strpos+=g_snprintf(str+strpos, MAX_SDP_LEN-strpos, "0x%s ", ptr);
			}
		}
		break;
	}
	case 8:	/* fall through */
	case 4: {
		char *ptr = tvb_get_ephemeral_string(tvb, offset, size);
		
		proto_tree_add_text(t, tvb, start_offset, type_size, "%s \"%s\"", 
				    type == 8 ? "URL" : "String", ptr);
		if(strpos<MAX_SDP_LEN){
			strpos+=g_snprintf(str+strpos, MAX_SDP_LEN-strpos, "%s ", ptr);
		}
		break;
	}
	case 5: {
		guint8 var = tvb_get_guint8(tvb, offset);

		proto_tree_add_text(t, tvb, start_offset, type_size, "%s", 
				    var ? "true" : "false");
		if(strpos<MAX_SDP_LEN){
			strpos+=g_snprintf(str+strpos, MAX_SDP_LEN-strpos, "%s ", var?"true":"false");
		}
		break;
	}
	case 6: /* Data Element sequence */
	case 7: /* Data Element alternative */ {
		proto_tree *st;
		proto_item *ti;
		int bytes_to_go = size;
		int first = 1;
		char *substr;

		ti = proto_tree_add_text(t, tvb, start_offset, type_size, "%s", 
					 type == 6 ? "Data Element sequence" : 
					 "Data Element alternative");
		st = proto_item_add_subtree(ti, ett_btsdp_des);

		if(strpos<MAX_SDP_LEN){
			strpos+=g_snprintf(str+strpos, MAX_SDP_LEN-strpos, "{ ");
		}

		while(bytes_to_go > 0){
			if(!first){
				if(strpos<MAX_SDP_LEN){
					strpos+=g_snprintf(str+strpos, MAX_SDP_LEN-strpos, ", ");
				}
			} else {
				first = 0;
			}

			size = dissect_sdp_type(st, tvb, offset, &substr);
			if(strpos<MAX_SDP_LEN){
				strpos+=g_snprintf(str+strpos, MAX_SDP_LEN-strpos, "%s ", substr);
			}
			offset += size;
			bytes_to_go -= size;
		}

		if(strpos<MAX_SDP_LEN){
			strpos+=g_snprintf(str+strpos, MAX_SDP_LEN-strpos, "} ");
		}
		break;
	}
	}

	/* make sure the string is 0 terminated */
	str[MAX_SDP_LEN]=0;

	return type_size;
}




static int 
dissect_sdp_service_attribute(proto_tree *tree, tvbuff_t *tvb, int offset)
{

	proto_tree *st, *ti_sa, *ti_av;
	int size;
	const char *att_name;
	guint16 id;
	char *attr_val;

	id = tvb_get_ntohs(tvb, offset+1);
	att_name = val_to_str(id, vs_general_attribute_id, "Unknown");
	
	ti_sa = proto_tree_add_text(tree, tvb, offset, -1, 
				    "Service Attribute: id = %s (0x%x)", att_name, id);
	st = proto_item_add_subtree(ti_sa, ett_btsdp_attribute);
	

	proto_tree_add_text(st, tvb, offset, 3, "Attribute ID: %s (0x%x)", att_name, id);
	ti_av = proto_tree_add_text(st, tvb, offset + 3, -1, "Attribute Value");
	st = proto_item_add_subtree(ti_av, ett_btsdp_attribute);


	size = dissect_sdp_type(st, tvb, offset + 3, &attr_val);
	proto_item_append_text(ti_sa, ", value = %s", attr_val);


	proto_item_set_len(ti_sa, size + 3);
	proto_item_set_len(ti_av, size);

	return offset+size+3;
}


static int 
dissect_sdp_service_attribute_list(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	proto_item *ti;
	proto_tree *st;
	int start_offset = offset, len;

	offset = get_type_length(tvb, offset, &len);

	ti = proto_tree_add_text(tree, tvb, start_offset, -1, "AttributeList");
	st = proto_item_add_subtree(ti, ett_btsdp_attribute);

	if(!len){
		return offset;
	}

	while (offset - start_offset < len) {
		offset = dissect_sdp_service_attribute(st, tvb, offset);
	}

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}



static int 
dissect_sdp_service_attribute_list_array(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	proto_item *ti;
	proto_tree *st;
	int start_offset, len;
	
	start_offset=offset;
	offset = get_type_length(tvb, offset, &len);
	ti = proto_tree_add_text(tree, tvb, start_offset, offset-start_offset+len, "AttributeLists");
	st = proto_item_add_subtree(ti, ett_btsdp_attribute);

	start_offset=offset;
	while(offset-start_offset < len) {
		offset = dissect_sdp_service_attribute_list(st, tvb, offset);
	}

	return offset;
}



static int
dissect_sdp_service_search_attribute_response(proto_tree *tree, tvbuff_t *tvb, int offset) 
{

	proto_tree_add_item(tree, hf_ssares_al_bytecount, tvb, offset, 2, FALSE);
	offset += 2;

	offset += dissect_sdp_service_attribute_list_array(tree, tvb, offset);

	return offset;
}


static int
dissect_sdp_service_search_attribute_request(proto_tree *t, tvbuff_t *tvb, int offset)
{
	proto_tree *st;
	proto_item *ti;
	int start_offset;
	int size, bytes_to_go;
	char *str;

	start_offset = offset;
	ti = proto_tree_add_text(t, tvb, offset, 2, "ServiceSearchPattern");
	st = proto_item_add_subtree(ti, ett_btsdp_attribute);

	offset = get_type_length(tvb, offset, &bytes_to_go);
	proto_item_set_len(ti, offset - start_offset + bytes_to_go);


	while(bytes_to_go>0) {
		size = dissect_sdp_type(st, tvb, offset, &str);
		proto_item_append_text(st, " %s", str);
		offset+=size;
		bytes_to_go-=size;
	}

	/* dissect maximum attribute byte count */
	proto_tree_add_text(t, tvb, offset, 2, "MaximumAttributeByteCount: %d", tvb_get_ntohs(tvb, offset));
	offset+=2;


	offset += dissect_attribute_id_list(t, tvb, offset);

	proto_tree_add_text(t, tvb, offset, -1, "ContinuationState");

	return offset;
}

static int 
dissect_sdp_service_attribute_response(proto_tree *t, tvbuff_t *tvb, int offset)
{
	proto_tree_add_text(t, tvb, offset, 2, "AttributeListByteCount: %d",
			    tvb_get_ntohs(tvb, offset));
	offset+=2;
	
	offset = dissect_sdp_service_attribute_list(t, tvb, offset);

	proto_tree_add_text(t, tvb, offset, -1, "ContinuationState");
	offset+=tvb_length_remaining(tvb, offset);

	return offset;
}


static int 
dissect_sdp_service_attribute_request(proto_tree *t, tvbuff_t *tvb, int offset)
{
	proto_tree_add_text(t, tvb, offset, 4, "ServiceRecordHandle: 0x%x", 
			    tvb_get_ntohl(tvb, offset));
	offset+=4;

	proto_tree_add_text(t, tvb, offset, 2, "MaximumAttributeByteCount: %d", 
			    tvb_get_ntohs(tvb, offset));
	offset+=2;

	offset += dissect_attribute_id_list(t, tvb, offset);

	proto_tree_add_text(t, tvb, offset, -1, "ContinuationState");
	offset+=tvb_length_remaining(tvb, offset);
	return offset;
}


static int 
dissect_sdp_service_search_request(proto_tree *t, tvbuff_t *tvb, int offset)
{
        int start_offset, bytes_to_go, size;
	proto_item *ti;
	proto_tree *st;
  
	start_offset=offset;
        ti = proto_tree_add_text(t, tvb, offset, 2, "ServiceSearchPattern");
	st = proto_item_add_subtree(ti, ett_btsdp_service_search_pattern);

	offset = get_type_length(tvb, offset, &bytes_to_go);
	proto_item_set_len(ti, offset - start_offset + bytes_to_go);

	while(bytes_to_go>0){
		char *str;
		size = dissect_sdp_type(st, tvb, offset, &str);
		proto_item_append_text(st, " %s", str);
		offset+=size;
		bytes_to_go-=size;
	}

	/* dissect maximum service record count */

	proto_tree_add_text(t, tvb, offset, 2, "MaximumServiceRecordCount: %d", 
			    tvb_get_ntohs(tvb, offset));
	offset+=2;

	proto_tree_add_text(t, tvb, offset, -1, "ContinuationState");
	offset+=tvb_length_remaining(tvb, offset);
	return offset;
}


static int 
dissect_sdp_service_search_response(proto_tree *t, tvbuff_t *tvb, int offset)
{
	proto_tree *st;
	proto_item *ti;
	guint16 curr_count;
	
	proto_tree_add_item(t, hf_ssr_total_count, tvb, offset, 2, FALSE);
	offset+=2;

	curr_count = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(t, hf_ssr_current_count, tvb, offset, 2, FALSE);
	offset+=2;

	ti = proto_tree_add_text(t, tvb, offset, 
				 curr_count * 4, "ServiceRecordHandleList");
	st = proto_item_add_subtree(ti, ett_btsdp_ssr);
	offset+=4;

	while(curr_count>0){
		proto_tree_add_text(st, tvb, offset, 4, "0x%x", tvb_get_ntohl(tvb, offset));
		offset+=4;
		curr_count--;
	}

	proto_tree_add_text(t, tvb, offset, -1, "ContinuationState");
	offset+=tvb_length_remaining(tvb, offset);

	return offset;
}


static void 
dissect_btsdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *st;
	guint8 pdu;
	guint16 plen;
	const char *pdu_name;
	int offset=0;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "SDP");

	ti = proto_tree_add_item(tree, proto_btsdp, tvb, 0, -1, FALSE);
	st = proto_item_add_subtree(ti, ett_btsdp);

	/* pdu id */
	pdu = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(st, hf_pduid, tvb, offset, 1, FALSE);
	pdu_name = val_to_str(pdu, vs_pduid, "Unknown");
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s ",pinfo->p2p_dir==P2P_DIR_SENT?"Sent":"Rcvd", pdu_name);
	}
	proto_item_append_text(ti, ": %s (0x%x)", pdu_name, pdu);
	offset++;

	/* tid */
	proto_tree_add_item(st, hf_tid, tvb, offset, 2, FALSE);
	offset+=2;

	/* plen */
	plen = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(st, hf_plen, tvb, offset, 2, FALSE);
	offset+=2;

	switch(pdu) {
	case 0x1:
		offset=dissect_sdp_error_response(st, tvb, offset);
		break;
	case 0x2:
		offset=dissect_sdp_service_search_request(st, tvb, offset);
		break;
	case 0x3:
		offset=dissect_sdp_service_search_response(st, tvb, offset);
		break;
	case 0x4:
		offset=dissect_sdp_service_attribute_request(st, tvb, offset);
		break;
	case 0x5:
		offset=dissect_sdp_service_attribute_response(st, tvb, offset);
		break;
	case 0x6:
		offset=dissect_sdp_service_search_attribute_request(st, tvb, offset);
		break;
	case 07:
		offset=dissect_sdp_service_search_attribute_response(st, tvb, offset);
		break;
	}
}


void 
proto_register_btsdp(void)
{                   
	static hf_register_info hf[] = {
		{&hf_pduid,
			{"PDU", "btsdp.pdu",
			FT_UINT8, BASE_HEX, VALS(vs_pduid), 0,          
			"PDU type", HFILL}
		},
		{&hf_tid,
			{"TransactionID", "btsdp.tid",
			FT_UINT16, BASE_HEX, NULL, 0,          
			"Transaction ID", HFILL}
		},
		{&hf_plen,
			{"ParameterLength", "btsdp.len",
			FT_UINT16, BASE_DEC, NULL, 0,          
			"ParameterLength", HFILL}
		},
		{&hf_error_code, 
		        {"ErrorCode", "btsdp.error_code", 
			FT_UINT16, BASE_HEX, NULL, 0, 
			 "Error Code", HFILL}
		},
		{&hf_ssr_total_count,
		        {"TotalServiceRecordCount", "btsdp.ssr.total_count",
			FT_UINT16, BASE_DEC, NULL, 0,
			 "Total count of service records", HFILL}
		},
		{&hf_ssr_current_count,
		        {"CurrentServiceRecordCount", "btsdp.ssr.current_count",
			FT_UINT16, BASE_DEC, NULL, 0,
			 "count of service records in this message", HFILL}
		},
		{&hf_ssares_al_bytecount,
		        {"AttributeListsByteCount", "btsdp.ssares.byte_count",
			FT_UINT16, BASE_DEC, NULL, 0,
			 "count of bytes in attribute list response", HFILL}
		}
	};

	/* Setup protocol subtree array */

	static gint *ett[] = {
		&ett_btsdp,
		&ett_btsdp_ssr,
		&ett_btsdp_des,
		&ett_btsdp_attribute,
		&ett_btsdp_service_search_pattern,
		&ett_btsdp_attribute_idlist
	};

	proto_btsdp = proto_register_protocol("Bluetooth SDP", "BTSDP", "btsdp");

	register_dissector("btsdp", dissect_btsdp, proto_btsdp);
	
	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_btsdp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_btsdp(void)
{
	dissector_handle_t btsdp_handle;

	btsdp_handle = find_dissector("btsdp");
	dissector_add("btl2cap.psm", BTL2CAP_PSM_SDP, btsdp_handle);
}
