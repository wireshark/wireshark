/* packet-SML.c
 * Routines for SML dissection
 * Copyright 2013, Alexander Gaertner <gaertner.alex@gmx.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
SML dissector is based on v1.03 (12.11.2008) specifications of "smart message language" protocol

Link to specifications: http://www.vde.com/de/fnn/arbeitsgebiete/messwesen/Sym2/infomaterial/seiten/sml-spezifikation.aspx

Short description of the SML protocol on the SML Wireshark Wiki page:  http://wiki.wireshark.org/SML
*/

#include "config.h"
#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/crc16-tvb.h>
#include <epan/expert.h>

#define TCP_PORT_SML		0
#define UDP_PORT_SML		0

#define ESC_SEQ_END		G_GUINT64_CONSTANT(0x1b1b1b1b1a)
#define ESC_SEQ			0x1b1b1b1b

#define OPEN_REQ		0x0100
#define OPEN_RES		0x0101
#define CLOSE_REQ		0x0200
#define CLOSE_RES		0x0201
#define PROFILEPACK_REQ		0x0300
#define PROFILEPACK_RES		0x0301
#define PROFILELIST_REQ		0x0400
#define PROFILELIST_RES		0x0401
#define GETPROCPARAMETER_REQ	0x0500
#define GETPROCPARAMETER_RES	0x0501
#define SETPROCPARAMETER_REQ	0x0600
#define GETLIST_REQ		0x0700
#define GETLIST_RES		0x0701
#define ATTENTION		0xFF01

#define PROC_VALUE		0x01
#define	PROC_PERIOD		0x02
#define	PROC_TUPEL		0x03
#define PROC_TIME		0x04

#define SHORT_LIST		0x70
#define LONG_LIST		0xF0

#define OPTIONAL		0x01

#define UNSIGNED8		0x62
#define UNSIGNED16		0x63

#define LIST_6_ELEMENTS		0x76
#define MSB			0x80

static guint tcp_port_pref = TCP_PORT_SML;
static guint udp_port_pref = UDP_PORT_SML;

/* Forward declaration we need below (if using proto_reg_handoff as a prefs callback)*/
void proto_register_sml(void);
void proto_reg_handoff_sml(void);

/* Initialize the protocol and registered fields */
static int proto_sml = -1;

static int hf_sml_esc = -1;
static int hf_sml_version_1 = -1;
static int hf_sml_groupNo = -1;
static int hf_sml_transactionId = -1;
static int hf_sml_datatype = -1;
static int hf_sml_abortOnError = -1;
static int hf_sml_MessageBody = -1;
static int hf_sml_crc16 = -1;
static int hf_sml_endOfSmlMsg = -1;
static int hf_sml_end = -1;
static int hf_sml_codepage = -1;
static int hf_sml_clientId = -1;
static int hf_sml_reqFileId = -1;
static int hf_sml_serverId = -1;
static int hf_sml_username = -1;
static int hf_sml_password = -1;
static int hf_sml_smlVersion = -1;
static int hf_sml_listName = -1;
static int hf_sml_globalSignature = -1;
static int hf_sml_refTime = -1;
static int hf_sml_actSensorTime = -1;
static int hf_sml_timetype = -1;
static int hf_sml_objName = -1;
static int hf_sml_status = -1;
static int hf_sml_valTime = -1;
static int hf_sml_unit = -1;
static int hf_sml_scaler = -1;
static int hf_sml_value = -1;
static int hf_sml_valueSignature = -1;
static int hf_sml_listSignature = -1;
static int hf_sml_actGatewayTime = -1;
static int hf_sml_parameterTreePath = -1;
static int hf_sml_attribute = -1;
static int hf_sml_parameterName = -1;
static int hf_sml_procParValue = -1;
static int hf_sml_procParValueTime = -1;
static int hf_sml_padding = -1;
static int hf_sml_secIndex = -1;
static int hf_sml_attentionNo = -1;
static int hf_sml_attentionMsg = -1;
static int hf_sml_withRawdata = -1;
static int hf_sml_beginTime = -1;
static int hf_sml_endTime = -1;
static int hf_sml_object_list_Entry = -1;
static int hf_sml_actTime = -1;
static int hf_sml_regPeriod = -1;
static int hf_sml_rawdata = -1;
static int hf_sml_periodSignature = -1;
static int hf_sml_profileSignature = -1;
static int hf_sml_signature_mA_R2_R3 = -1;
static int hf_sml_signature_pA_R1_R4 = -1;
static int hf_sml_unit_mA = -1;
static int hf_sml_scaler_mA = -1;
static int hf_sml_value_mA = -1;
static int hf_sml_unit_pA = -1;
static int hf_sml_scaler_pA = -1;
static int hf_sml_value_pA = -1;
static int hf_sml_unit_R1 = -1;
static int hf_sml_scaler_R1 = -1;
static int hf_sml_value_R1 = -1;
static int hf_sml_unit_R2 = -1;
static int hf_sml_scaler_R2 = -1;
static int hf_sml_value_R2 = -1;
static int hf_sml_unit_R3 = -1;
static int hf_sml_scaler_R3 = -1;
static int hf_sml_value_R3 = -1;
static int hf_sml_unit_R4 = -1;
static int hf_sml_scaler_R4 = -1;
static int hf_sml_value_R4 = -1;

static const value_string datatype []={
	{0x52, "Integer 8"},
	{0x53, "Integer 16"},
	{0x54, "Integer cropped"},
	{0x55, "Integer 32"},
	{0x56, "Integer cropped"},
	{0x57, "Integer cropped"},
	{0x58, "Integer cropped"},
	{0x59, "Integer 64"},
	{0x62, "Unsigned 8"},
	{0x63, "Unsigned 16"},
	{0x64, "Unsigned cropped"},
	{0x65, "Unsigned 32"},
	{0x66, "Unsigned cropped"},
	{0x67, "Unsigned cropped"},
	{0x68, "Unsigned cropped"},
	{0x69, "Unsigned 64"},
	{0x42, "Boolean"},
	{0, NULL}
};

static const value_string sml_abort[]={
	{0x00, "Continue"},
	{0x01, "Continue at next group"},
	{0x02, "Continue than abort"},
	{0xFF, "Abort"},
	{0, NULL}
};

static const value_string sml_body[]={
	{OPEN_REQ, "PublicOpen.Req"},
	{OPEN_RES, "PublicOpen.Res"},
	{CLOSE_REQ, "PublicClose.Req"},
	{CLOSE_RES, "PublicClose.Res"},
	{PROFILEPACK_REQ, "GetProfilePack.Req"},
	{PROFILEPACK_RES, "GetProfilePack.Res"},
	{PROFILELIST_REQ, "GetProfileList.Req"},
	{PROFILELIST_RES, "GetProfileList.Res"},
	{GETPROCPARAMETER_REQ, "GetProcParameter.Req"},
	{GETPROCPARAMETER_RES, "GetProcParameter.Res"},
	{SETPROCPARAMETER_REQ, "SetProcParameter.Req"},
	{GETLIST_REQ, "GetList.Req"},
	{GETLIST_RES, "GetList.Res"},
	{ATTENTION, "Attention.Res"},
	{0, NULL}
};

static const value_string sml_timetypes[]={
	{0x01, "secIndex"},
	{0x02, "timestamp"},
	{0, NULL}
};

static const value_string procvalues[]={
	{PROC_VALUE, "Value"},
	{PROC_PERIOD, "PeriodEntry"},
	{PROC_TUPEL, "TupelEntry"},
	{PROC_TIME, "Time"},
	{0, NULL}
};

static const range_string attentionValues[]={
	{0xE000, 0xFCFF, "application specific"},
	{0xFD00, 0xFD00, "acknowledged"},
	{0xFD01, 0xFD01, "order will be executed later"},
	{0xFE00, 0xFE00, "error undefined"},
	{0xFE01, 0xFE01, "unknown SML designator"},
	{0xFE02, 0xFE02, "User/Password wrong"},
	{0xFE03, 0xFE03, "serverId not available"},
	{0xFE04, 0xFE04, "reqFileId not available"},
	{0xFE05, 0xFE05, "destination attributes cannot be written"},
	{0xFE06, 0xFE06, "destination attributes cannot be read"},
	{0xFE07, 0xFE07, "communication disturbed"},
	{0xFE08, 0xFE08, "rawdata cannot be interpreted"},
	{0xFE09, 0xFE09, "value out of range"},
	{0xFE0A, 0xFE0A, "order not executed"},
	{0xFE0B, 0xFE0B, "checksum failed"},
	{0xFE0C, 0xFE0C, "broadcast not supported"},
	{0xFE0D, 0xFE0D, "unexpected message"},
	{0xFE0E, 0xFE0E, "unknown object in the profile"},
	{0xFE0F, 0xFE0F, "datatype not supported"},
	{0xFE10, 0xFE10, "optional element not supported"},
	{0xFE11, 0xFE11, "no entry in requested profile"},
	{0xFE12, 0xFE12, "end limit before begin limit"},
	{0xFE13, 0xFE13, "no entry in requested area"},
	{0xFE14, 0xFE14, "SML file without close"},
	{0xFE15, 0xFE15, "busy, response cannot be sent"},
	{0,0, NULL}
};

static const range_string bools[]={
	{0x00, 0x00, "false"},
	{0x01, 0xFF, "true"},
	{0,0, NULL}
};

/* Initialize the subtree pointers */
static gint ett_sml = -1;
static gint ett_sml_mainlist = -1;
static gint ett_sml_version = -1;
static gint ett_sml_sublist = -1;
static gint ett_sml_trans = -1;
static gint ett_sml_group = -1;
static gint ett_sml_abort = -1;
static gint ett_sml_body = -1;
static gint ett_sml_mblist = -1;
static gint ett_sml_mttree = -1;
static gint ett_sml_crc16 = -1;
static gint ett_sml_clientId = -1;
static gint ett_sml_codepage = -1;
static gint ett_sml_reqFileId= -1;
static gint ett_sml_serverId = -1;
static gint ett_sml_username = -1;
static gint ett_sml_password = -1;
static gint ett_sml_smlVersion = -1;
static gint ett_sml_listName = -1;
static gint ett_sml_globalSignature = -1;
static gint ett_sml_refTime = -1;
static gint ett_sml_actSensorTime = -1;
static gint ett_sml_timetype = -1;
static gint ett_sml_time = -1;
static gint ett_sml_valList = -1;
static gint ett_sml_listEntry = -1;
static gint ett_sml_objName = -1;
static gint ett_sml_status = -1;
static gint ett_sml_valTime = -1;
static gint ett_sml_unit = -1;
static gint ett_sml_scaler = -1;
static gint ett_sml_value = -1;
static gint ett_sml_valueSignature = -1;
static gint ett_sml_listSignature = -1;
static gint ett_sml_valtree = -1;
static gint ett_sml_actGatewayTime = -1;
static gint ett_sml_treepath = -1;
static gint ett_sml_parameterTreePath = -1;
static gint ett_sml_attribute = -1;
static gint ett_sml_parameterTree = -1;
static gint ett_sml_parameterName = -1;
static gint ett_sml_child = -1;
static gint ett_sml_periodEntry = -1;
static gint ett_sml_procParValue = -1;
static gint ett_sml_procParValueTime = -1;
static gint ett_sml_procParValuetype = -1;
static gint ett_sml_msgend = -1;
static gint ett_sml_tupel = -1;
static gint ett_sml_secIndex = -1;
static gint ett_sml_signature = -1;
static gint ett_sml_attentionNo = -1;
static gint ett_sml_attentionMsg = -1;
static gint ett_sml_withRawdata = -1;
static gint ett_sml_beginTime = -1;
static gint ett_sml_endTime = -1;
static gint ett_sml_object_list = -1;
static gint ett_sml_object_list_Entry = -1;
static gint ett_sml_actTime = -1;
static gint ett_sml_regPeriod = -1;
static gint ett_sml_rawdata = -1;
static gint ett_sml_periodSignature = -1;
static gint ett_sml_period_List_Entry = -1;
static gint ett_sml_periodList = -1;
static gint ett_sml_headerList = -1;
static gint ett_sml_header_List_Entry = -1;
static gint ett_sml_profileSignature = -1;
static gint ett_sml_valuelist = -1;
static gint ett_sml_value_List_Entry = -1;
static gint ett_sml_signature_mA_R2_R3 = -1;
static gint ett_sml_signature_pA_R1_R4 = -1;
static gint ett_sml_unit_mA = -1;
static gint ett_sml_scaler_mA = -1;
static gint ett_sml_value_mA = -1;
static gint ett_sml_unit_pA = -1;
static gint ett_sml_scaler_pA = -1;
static gint ett_sml_value_pA = -1;
static gint ett_sml_unit_R1 = -1;
static gint ett_sml_scaler_R1 = -1;
static gint ett_sml_value_R1 = -1;
static gint ett_sml_unit_R2 = -1;
static gint ett_sml_scaler_R2 = -1;
static gint ett_sml_value_R2 = -1;
static gint ett_sml_unit_R3 = -1;
static gint ett_sml_scaler_R3 = -1;
static gint ett_sml_value_R3 = -1;
static gint ett_sml_unit_R4 = -1;
static gint ett_sml_scaler_R4 = -1;
static gint ett_sml_value_R4 = -1;
static gint ett_sml_tree_Entry = -1;
static gint ett_sml_dasDetails = -1;
static gint ett_sml_attentionDetails = -1;

static expert_field ei_sml_messagetype_unknown = EI_INIT;
static expert_field ei_sml_procParValue_errror = EI_INIT;
static expert_field ei_sml_procParValue_invalid = EI_INIT;
static expert_field ei_sml_segment_needed = EI_INIT;
static expert_field ei_sml_endOfSmlMsg = EI_INIT;
static expert_field ei_sml_crc_error = EI_INIT;
static expert_field ei_sml_tupel_error = EI_INIT;
static expert_field ei_sml_crc_error_length = EI_INIT;
static expert_field ei_sml_invalid_count = EI_INIT;
static expert_field ei_sml_MessageBody = EI_INIT;
static expert_field ei_sml_esc_error = EI_INIT;

/*options*/
static gboolean sml_reassemble = TRUE;
static gboolean sml_crc_enabled = FALSE;

/*get number of length octets and calculate how many data octets, it's like BER but not the same! */
static void get_length(tvbuff_t *tvb, guint *offset, guint *data, guint *length){
	guint check = 0;
	guint temp_offset = 0;

	temp_offset = *offset;
	*data = 0;
	*length = 0;

	check = tvb_get_guint8(tvb, temp_offset);
	if (check == OPTIONAL){
		*length = 1;
	}
	else if ((check & 0x80) == MSB){
		while ((check & 0x80) == MSB){
			check = check & 0x0F;

			*data = *data + check;
			*data <<= 4;
			*length+=1;

			temp_offset+=1;
			check = tvb_get_guint8(tvb, temp_offset);
		}
		check = check & 0x0F;

		*data = *data + check;
		*length+=1;
		*data = *data - *length;
	}
	else{
		check = check & 0x0F;
		*length+=1;
		*data = check - *length;
	}
}

/*often used fields*/
static void sml_value(tvbuff_t *tvb,proto_tree *insert_tree,guint *offset, guint *data, guint *length){
	proto_item *value = NULL;
	proto_tree *value_tree = NULL;

	get_length(tvb, offset, data, length);
	value = proto_tree_add_bytes_format (insert_tree, hf_sml_value, tvb, *offset, *length + *data, NULL,"value %s", (*data == 0)? ": NOT SET" : "");

	if (tvb_get_guint8(tvb, *offset) != OPTIONAL){
		value_tree = proto_item_add_subtree (value, ett_sml_value);
		if ((tvb_get_guint8(tvb, *offset) & 0x80) == MSB || (tvb_get_guint8(tvb, *offset) & 0xF0) == 0){
			proto_tree_add_text (value_tree, tvb, *offset, *length, "Length: %d %s", *data, plurality(*data, "octet", "octets"));
			*offset+= *length;
		}
		else {
			proto_tree_add_item (value_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
			*offset+=1;
		}
		proto_tree_add_item (value_tree, hf_sml_value, tvb, *offset, *data, ENC_NA);
		*offset+= *data;
	}
	else
		*offset+=1;
}

static void sml_time_type(tvbuff_t *tvb, proto_tree *SML_time_tree, guint *offset){
	proto_item *timetype = NULL;
	proto_tree *timetype_tree = NULL;

	timetype = proto_tree_add_text (SML_time_tree, tvb, *offset, 2, "SML-Time Type");
	timetype_tree = proto_item_add_subtree (timetype, ett_sml_timetype);

	proto_tree_add_item (timetype_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
	*offset+=1;
	proto_tree_add_item (timetype_tree, hf_sml_timetype, tvb, *offset, 1, ENC_NA);
	*offset+=1;
}

static void field_codepage(tvbuff_t *tvb, proto_tree *insert_tree, guint *offset, guint *data, guint *length){
	proto_item *codepage = NULL;
	proto_tree *codepage_tree = NULL;

	get_length(tvb, offset, data, length);
	codepage = proto_tree_add_bytes_format (insert_tree, hf_sml_codepage, tvb, *offset, *length + *data, NULL,"Codepage %s", (*data == 0)? ": NOT SET" : "");

	if (*data > 0) {
		codepage_tree = proto_item_add_subtree (codepage , ett_sml_codepage);
		proto_tree_add_text (codepage_tree, tvb, *offset, *length, "Length: %d %s", *data ,plurality(*data, "octet", "octets"));
		*offset+= *length;

		proto_tree_add_item (codepage_tree, hf_sml_codepage, tvb, *offset, *data, ENC_NA);
		*offset+= *data;
	}
	else
		*offset+=1;
}

static void field_clientId(tvbuff_t *tvb, proto_tree *insert_tree, guint *offset, guint *data, guint *length){
	proto_item *clientId = NULL;
	proto_tree *clientId_tree = NULL;

	get_length(tvb, offset, data, length);
	clientId = proto_tree_add_bytes_format (insert_tree, hf_sml_clientId, tvb, *offset, *length + *data, NULL, "clientID %s", (*data == 0)? ": NOT SET" : "");

	if (*data > 0) {
		clientId_tree = proto_item_add_subtree (clientId, ett_sml_clientId);
		proto_tree_add_text (clientId_tree, tvb, *offset, *length, "Length: %d %s", *data, plurality(*data, "octet", "octets"));
		*offset+=*length;
		proto_tree_add_item (clientId_tree, hf_sml_clientId, tvb, *offset, *data, ENC_NA);
		*offset+=*data;
	}
	else
		*offset+=1;
}

static void field_reqFileId(tvbuff_t *tvb, proto_tree *insert_tree, guint *offset, guint *data, guint *length){
	proto_item *reqFileId = NULL;
	proto_tree *reqFileId_tree = NULL;

	get_length(tvb, offset, data, length);
	reqFileId = proto_tree_add_text (insert_tree, tvb, *offset, *length + *data, "reqFileId");

	reqFileId_tree = proto_item_add_subtree (reqFileId, ett_sml_reqFileId);
	proto_tree_add_text (reqFileId_tree, tvb, *offset, *length, "Length: %d %s", *data, plurality(*data, "octet", "octets"));
	*offset+=*length;
	proto_tree_add_item (reqFileId_tree, hf_sml_reqFileId, tvb, *offset, *data, ENC_NA);
	*offset+=*data;
}

static void field_serverId(tvbuff_t *tvb, proto_tree *insert_tree, guint *offset, guint *data, guint *length){
	proto_item *serverId = NULL;
	proto_tree *serverId_tree = NULL;

	/*Server ID OPTIONAL*/
	get_length(tvb, offset, data, length);
	serverId = proto_tree_add_bytes_format (insert_tree,hf_sml_serverId, tvb, *offset, *length + *data, NULL, "Server ID %s", (*data == 0)? ": NOT SET" : "");

	if (*data > 0){
		serverId_tree = proto_item_add_subtree (serverId , ett_sml_serverId);
		proto_tree_add_text (serverId_tree, tvb, *offset, *length, "Length: %d %s", *data, plurality(*data, "octet", "octets"));
		*offset+=*length;
		proto_tree_add_item (serverId_tree, hf_sml_serverId, tvb, *offset, *data, ENC_NA);
		*offset+=*data;
	}
	else
		*offset+=1;
}

static void field_username(tvbuff_t *tvb, proto_tree *insert_tree, guint *offset, guint *data, guint *length){
	proto_item *username = NULL;
	proto_tree *username_tree = NULL;

	/*Username OPTIONAL*/
	get_length(tvb, offset, data, length);
	username = proto_tree_add_string_format (insert_tree,hf_sml_username, tvb, *offset, *length + *data, NULL, "Username %s", (*data == 0)? ": NOT SET" : "");

	if (*data > 0){
		username_tree = proto_item_add_subtree (username , ett_sml_username);
		proto_tree_add_text (username_tree, tvb, *offset, *length, "Length: %d %s", *data, plurality(*data, "octet", "octets"));
		*offset+=*length;
		proto_tree_add_item (username_tree, hf_sml_username, tvb, *offset, *data, ENC_ASCII | ENC_BIG_ENDIAN);
		*offset+=*data;
	}
	else
		*offset+=1;
}

static void field_password(tvbuff_t *tvb, proto_tree *insert_tree, guint *offset, guint *data, guint *length){
	proto_item *password = NULL;
	proto_tree *password_tree = NULL;

	/*Password OPTIONAL*/
	get_length(tvb, offset, data, length);
	password = proto_tree_add_string_format (insert_tree,hf_sml_password, tvb, *offset, *length + *data, NULL, "Password %s", (*data == 0)? ": NOT SET" : "");

	if (*data > 0) {
		password_tree = proto_item_add_subtree (password, ett_sml_password);
		proto_tree_add_text (password_tree, tvb, *offset, *length, "Length: %d %s", *data, plurality(*data, "octet", "octets"));
		*offset+=*length;
		proto_tree_add_item (password_tree, hf_sml_password, tvb, *offset, *data, ENC_ASCII | ENC_BIG_ENDIAN);
		*offset+=*data;
	}
	else
		*offset+=1;
}

static void field_smlVersion(tvbuff_t *tvb, proto_tree *insert_tree, guint *offset, guint *data, guint *length){
	proto_item *smlVersion = NULL;
	proto_tree *smlVersion_tree = NULL;

	/*sml-Version OPTIONAL*/
	get_length(tvb, offset, data, length);
	smlVersion = proto_tree_add_uint_format (insert_tree, hf_sml_smlVersion, tvb, *offset, *length + *data, *length + *data, "SML-Version %s", (*data == 0)? ": Version 1" : "");

	if (*data > 0) {
		smlVersion_tree = proto_item_add_subtree (smlVersion, ett_sml_smlVersion);
		proto_tree_add_item (smlVersion_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
		*offset+=1;

		proto_tree_add_item (smlVersion_tree, hf_sml_smlVersion, tvb, *offset, 1,ENC_NA);
		*offset+=1;
	}
	else
		*offset+=1;
}

static void field_globalSignature(tvbuff_t *tvb, proto_tree *insert_tree, guint *offset, guint *data, guint *length){
	proto_item *globalSignature = NULL;
	proto_tree *globalSignature_tree = NULL;

	/*Global Signature OPTIONAL*/
	get_length(tvb, offset, data, length);

	globalSignature = proto_tree_add_bytes_format (insert_tree, hf_sml_globalSignature, tvb, *offset, *length + *data, NULL, "global Signature %s", (*data == 0)? ": NOT SET" : "");

	if (*data > 0){
		globalSignature_tree = proto_item_add_subtree (globalSignature, ett_sml_globalSignature);
		proto_tree_add_text (globalSignature_tree, tvb, *offset, *length, "Length: %d %s", *data, plurality(*data, "octet", "octets"));
		*offset+=*length;
		proto_tree_add_item (globalSignature_tree, hf_sml_globalSignature, tvb, *offset, *data, ENC_NA);
		*offset+=*data;
	}
	else
		*offset+=1;
}

static void field_listName(tvbuff_t *tvb, proto_tree *insert_tree, guint *offset, guint *data, guint *length){
	proto_item *listName = NULL;
	proto_tree *listName_tree = NULL;

	/*List Name OPTIONAL*/
	get_length(tvb, offset, data, length);
	listName = proto_tree_add_bytes_format (insert_tree,hf_sml_listName, tvb, *offset, *length + *data, NULL, "List Name %s", (*data == 0)? ": NOT SET" : "");

	if (*data > 0) {
		listName_tree = proto_item_add_subtree (listName, ett_sml_listName);
		proto_tree_add_text (listName_tree, tvb, *offset, *length, "Length: %d %s", *length ,plurality(*data, "octet", "octets"));
		*offset+=*length;
		proto_tree_add_item (listName_tree, hf_sml_listName, tvb, *offset, *data, ENC_NA);
		*offset+=*data;
	}
	else
		*offset+=1;
}

static void field_objName(tvbuff_t *tvb, proto_tree *insert_tree, guint *offset, guint *data, guint *length){
	proto_item *objName = NULL;
	proto_tree *objName_tree = NULL;

	/*Objectname*/
	get_length(tvb, offset, data, length);
	objName = proto_tree_add_text (insert_tree, tvb, *offset, *length + *data ,"Objectname");

	objName_tree = proto_item_add_subtree (objName, ett_sml_objName);
	proto_tree_add_text (objName_tree, tvb, *offset, *length, "Length: %d %s", *data ,plurality(*data, "octet", "octets"));
	*offset+=*length;
	proto_tree_add_item (objName_tree, hf_sml_objName, tvb, *offset, *data, ENC_NA);
	*offset+=*data;
}

static void field_status(tvbuff_t *tvb, proto_tree *insert_tree, guint *offset, guint *data, guint *length){
	proto_item *status = NULL;
	proto_tree *status_tree = NULL;

	get_length(tvb, offset, data, length);
	status = proto_tree_add_text (insert_tree, tvb, *offset, *length + *data ,"status %s", (*data == 0)? ": NOT SET" : "");

	if (*data > 0){
		status_tree = proto_item_add_subtree (status, ett_sml_status);
		proto_tree_add_item (status_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
		*offset+=1;
		proto_tree_add_item (status_tree, hf_sml_status, tvb, *offset, *data, ENC_BIG_ENDIAN);
		*offset+= *data;
	}
	else
		*offset+=1;
}

static void field_unit(tvbuff_t *tvb, proto_tree *insert_tree, guint *offset, guint *data, guint *length){
	proto_item *unit = NULL;
	proto_tree *unit_tree = NULL;

	/*unit OPTIONAL*/
	get_length(tvb, offset, data, length);
	unit = proto_tree_add_uint_format (insert_tree, hf_sml_unit, tvb, *offset, *length + *data, *length + *data, "Unit %s", (*data == 0)? ": NOT SET" : "");
	if (*data > 0) {
		unit_tree = proto_item_add_subtree (unit, ett_sml_unit);
		proto_tree_add_item (unit_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
		*offset+=1;
		proto_tree_add_item(unit_tree, hf_sml_unit, tvb, *offset, 1, ENC_NA);
		*offset+=1;
	}
	else
		*offset+=1;
}

static void field_scaler(tvbuff_t *tvb, proto_tree *insert_tree, guint *offset, guint *data, guint *length){
	proto_item *scaler = NULL;
	proto_tree *scaler_tree = NULL;

	/*Scaler OPTIONAL*/
	get_length(tvb, offset, data, length);
	scaler = proto_tree_add_uint_format (insert_tree, hf_sml_scaler, tvb, *offset, *length + *data, *length + *data, "Scaler %s", (*data == 0)? ": NOT SET" : "");

	if (*data > 0){
		scaler_tree = proto_item_add_subtree (scaler, ett_sml_scaler);
		proto_tree_add_item (scaler_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
		*offset+=1;
		proto_tree_add_item(scaler_tree, hf_sml_scaler, tvb, *offset, 1, ENC_NA);
		*offset+=1;
	}
	else
		*offset+=1;
}

static void field_valueSignature(tvbuff_t *tvb, proto_tree *insert_tree, guint *offset, guint *data, guint *length){
	proto_item *valueSignature = NULL;
	proto_tree *valueSignature_tree = NULL;

	/*value Signature*/
	get_length(tvb, offset, data, length);
	valueSignature = proto_tree_add_bytes_format (insert_tree, hf_sml_valueSignature, tvb, *offset, *length + *data, NULL, "ValueSignature %s", (*data == 0)? ": NOT SET" : "");

	if (*data > 0){
		valueSignature_tree = proto_item_add_subtree (valueSignature, ett_sml_valueSignature);
		proto_tree_add_text (valueSignature_tree, tvb, *offset, *length, "Length: %d %s", *data, plurality(*data, "octet", "octets"));
		*offset+=*length;
		proto_tree_add_item (valueSignature_tree, hf_sml_valueSignature, tvb, *offset, *data, ENC_NA);
		*offset+=*data;
	}
	else
		*offset+=1;
}

static void field_parameterTreePath(tvbuff_t *tvb, proto_tree *insert_tree, guint *offset, guint *data, guint *length){
	proto_item *parameterTreePath = NULL;
	proto_tree *parameterTreePath_tree = NULL;

	/*parameterTreePath*/
	get_length(tvb, offset, data, length);
	parameterTreePath = proto_tree_add_bytes_format (insert_tree, hf_sml_parameterTreePath, tvb, *offset, *length + *data, NULL, "path_Entry %s", (*data == 0)? ": NOT SET" : "");

	parameterTreePath_tree = proto_item_add_subtree (parameterTreePath, ett_sml_parameterTreePath);
	proto_tree_add_text (parameterTreePath_tree, tvb, *offset, *length, "Length: %d %s", *data ,plurality(*data, "octet", "octets"));
	*offset+=*length;
	proto_tree_add_item (parameterTreePath_tree, hf_sml_parameterTreePath, tvb, *offset, *data, ENC_NA);
	*offset+=*data;
}

static void field_ObjReqEntry(tvbuff_t *tvb, proto_tree *insert_tree, guint *offset, guint *data, guint *length){
	proto_item *object_list_Entry = NULL;
	proto_tree *object_list_Entry_tree = NULL;

	/*parameterTreePath*/
	get_length(tvb, offset, data, length);
	object_list_Entry = proto_tree_add_text (insert_tree, tvb ,*offset, *length + *data, "object_list_Entry");
	object_list_Entry_tree = proto_item_add_subtree (object_list_Entry, ett_sml_object_list_Entry);
	proto_tree_add_text (object_list_Entry_tree, tvb, *offset, *length, "Length: %d %s", *data ,plurality(*data, "octet", "octets"));
	*offset+=*length;
	proto_tree_add_item (object_list_Entry_tree, hf_sml_object_list_Entry, tvb, *offset, *data, ENC_NA);
	*offset+=*data;
}

static void field_regPeriod(tvbuff_t *tvb, proto_tree *insert_tree, guint *offset, guint *data, guint *length){
	proto_item *regPeriod = NULL;
	proto_tree *regPeriod_tree = NULL;

	get_length(tvb, offset, data, length);
	regPeriod = proto_tree_add_text (insert_tree, tvb, *offset, *length + *data, "regPeriod");

	regPeriod_tree = proto_item_add_subtree (regPeriod, ett_sml_regPeriod);
	proto_tree_add_item (regPeriod_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
	*offset+=1;
	proto_tree_add_item (regPeriod_tree, hf_sml_regPeriod, tvb, *offset, *data, ENC_BIG_ENDIAN);
	*offset+=*data;
}

static void field_rawdata(tvbuff_t *tvb, proto_tree *insert_tree, guint *offset, guint *data, guint *length){
	proto_item *rawdata = NULL;
	proto_tree *rawdata_tree = NULL;

	/*rawdata*/
	get_length(tvb, offset, data, length);
	rawdata = proto_tree_add_bytes_format (insert_tree, hf_sml_rawdata, tvb, *offset, *length + *data, NULL, "rawdata %s", (*data == 0)? ": NOT SET" : "");

	if (*data > 0){
		rawdata_tree = proto_item_add_subtree (rawdata, ett_sml_rawdata);
		proto_tree_add_text (rawdata_tree, tvb, *offset, *length, "Length: %d %s", *data, plurality(*data, "octet", "octets"));
		*offset+=*length;
		proto_tree_add_item (rawdata_tree, hf_sml_rawdata, tvb, *offset, *data, ENC_NA);
		*offset+=*data;
	}
	else
		*offset+=1;
}

static void field_periodSignature(tvbuff_t *tvb, proto_tree *insert_tree, guint *offset, guint *data, guint *length){
	proto_item *periodSignature = NULL;
	proto_tree *periodSignature_tree = NULL;

	/*periodSignature*/
	get_length(tvb, offset, data, length);
	periodSignature = proto_tree_add_bytes_format (insert_tree, hf_sml_periodSignature, tvb, *offset, *length + *data, NULL,"periodSignature %s", (*data == 0)? ": NOT SET" : "");

	if (*data > 0){
		periodSignature_tree = proto_item_add_subtree (periodSignature, ett_sml_periodSignature);
		proto_tree_add_text (periodSignature_tree, tvb, *offset, *length, "Length: %d %s", *data, plurality(*data, "octet", "octets"));
		*offset+=*length;
		proto_tree_add_item (periodSignature_tree, hf_sml_periodSignature, tvb, *offset, *data, ENC_NA);
		*offset+=*data;
	}
	else
		*offset+=1;
}

static void field_actTime(tvbuff_t *tvb, proto_tree *insert_tree, guint *offset, guint *data, guint *length){
	proto_item *actTime = NULL;
	proto_tree *actTime_tree = NULL;

	get_length(tvb, offset, data, length);
	actTime = proto_tree_add_text (insert_tree, tvb, *offset, *length + *data, "actTime");
	actTime_tree = proto_item_add_subtree (actTime, ett_sml_actTime);
	proto_tree_add_item (actTime_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
	*offset+=1;
	proto_tree_add_item(actTime_tree, hf_sml_actTime, tvb, *offset, *data, ENC_BIG_ENDIAN);
	*offset+=*data;
}

static void field_valTime(tvbuff_t *tvb, proto_tree *insert_tree, guint *offset, guint *data, guint *length){
	proto_item *valTime = NULL;
	proto_tree *valTime_tree = NULL;

	get_length(tvb, offset, data, length);
	valTime = proto_tree_add_text (insert_tree, tvb, *offset, *length + *data, "valTime");
	valTime_tree = proto_item_add_subtree (valTime, ett_sml_valTime);
	proto_tree_add_item (valTime_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
	*offset+=1;
	proto_tree_add_item(valTime_tree, hf_sml_valTime, tvb, *offset, *data, ENC_BIG_ENDIAN);
	*offset+=*data;
}

static void TupelEntryTree(tvbuff_t *tvb, proto_tree *procParValue_tree, guint *offset){
	proto_item *TupelEntry = NULL;
	proto_item *SML_time = NULL;
	proto_item *secIndex = NULL;
	proto_item *unit_pA = NULL;
	proto_item *scaler_pA = NULL;
	proto_item *value_pA = NULL;
	proto_item *unit_mA = NULL;
	proto_item *scaler_mA = NULL;
	proto_item *value_mA = NULL;
	proto_item *unit_R1 = NULL;
	proto_item *scaler_R1 = NULL;
	proto_item *value_R1 = NULL;
	proto_item *unit_R2 = NULL;
	proto_item *scaler_R2 = NULL;
	proto_item *value_R2 = NULL;
	proto_item *unit_R3 = NULL;
	proto_item *scaler_R3 = NULL;
	proto_item *value_R3 = NULL;
	proto_item *unit_R4 = NULL;
	proto_item *scaler_R4 = NULL;
	proto_item *value_R4 = NULL;
	proto_item *signature_pA_R1_R4 = NULL;
	proto_item *signature_mA_R2_R3 = NULL;

	proto_tree *TupelEntry_list = NULL;
	proto_tree *SML_time_tree = NULL;
	proto_tree *secIndex_tree = NULL;
	proto_tree *unit_pA_tree = NULL;
	proto_tree *scaler_pA_tree = NULL;
	proto_tree *value_pA_tree = NULL;
	proto_tree *unit_mA_tree = NULL;
	proto_tree *scaler_mA_tree = NULL;
	proto_tree *value_mA_tree = NULL;
	proto_tree *unit_R1_tree = NULL;
	proto_tree *scaler_R1_tree = NULL;
	proto_tree *value_R1_tree = NULL;
	proto_tree *unit_R2_tree = NULL;
	proto_tree *scaler_R2_tree = NULL;
	proto_tree *value_R2_tree = NULL;
	proto_tree *unit_R3_tree = NULL;
	proto_tree *scaler_R3_tree = NULL;
	proto_tree *value_R3_tree = NULL;
	proto_tree *unit_R4_tree = NULL;
	proto_tree *scaler_R4_tree = NULL;
	proto_tree *value_R4_tree = NULL;
	proto_tree *signature_pA_R1_R4_tree = NULL;
	proto_tree *signature_mA_R2_R3_tree = NULL;

	guint data = 0;
	guint length = 0;

	/*Tupel_List*/
	TupelEntry = proto_tree_add_text (procParValue_tree, tvb, *offset, -1, "TupelEntry");
	TupelEntry_list = proto_item_add_subtree (TupelEntry, ett_sml_tupel);
	get_length(tvb, offset, &data, &length);
	*offset+=length;

	/*Server Id*/
	field_serverId(tvb, TupelEntry_list, offset, &data, &length);

	/*secindex*/
	SML_time = proto_tree_add_text (procParValue_tree, tvb, *offset, -1, "secIndex");
	SML_time_tree = proto_item_add_subtree (SML_time, ett_sml_time);
	*offset+=1;
	sml_time_type(tvb, SML_time_tree, offset);
	get_length(tvb, offset, &data, &length);
	secIndex = proto_tree_add_text (SML_time_tree, tvb, *offset, length + data, "secIndex");
	secIndex_tree = proto_item_add_subtree (secIndex, ett_sml_secIndex);
	proto_tree_add_item (secIndex_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
	*offset+=1;
	proto_tree_add_item(secIndex_tree, hf_sml_secIndex, tvb, *offset, data, ENC_BIG_ENDIAN);
	*offset+=data;
	proto_item_set_end(SML_time, tvb, *offset);

	/*Sml Status OPTIONAL*/
	field_status(tvb, TupelEntry_list, offset, &data, &length);

	/*unit_pA*/
	unit_pA= proto_tree_add_text (TupelEntry_list, tvb, *offset, 2, "unit_pA");
	unit_pA_tree = proto_item_add_subtree(unit_pA, ett_sml_unit_pA);
	proto_tree_add_item (unit_pA_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
	*offset+=1;
	proto_tree_add_item (unit_pA_tree, hf_sml_unit_pA, tvb, *offset, 1, ENC_NA);
	*offset+=1;

	/*scaler_pA*/
	scaler_pA= proto_tree_add_text (TupelEntry_list, tvb, *offset, 2, "scaler_pA");
	scaler_pA_tree = proto_item_add_subtree(scaler_pA, ett_sml_scaler_pA);
	proto_tree_add_item (scaler_pA_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
	*offset+=1;
	proto_tree_add_item (scaler_pA_tree, hf_sml_scaler_pA, tvb, *offset, 1, ENC_NA);
	*offset+=1;

	/*value_pA*/
	get_length(tvb, offset, &data, &length);
	value_pA= proto_tree_add_text (TupelEntry_list, tvb, *offset, length+data, "value_pA");
	value_pA_tree = proto_item_add_subtree(value_pA, ett_sml_value_pA);
	proto_tree_add_item (value_pA_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
	*offset+=1;
	proto_tree_add_item (value_pA_tree, hf_sml_value_pA, tvb, *offset, data, ENC_NA);
	*offset+=data;

	/*unit_R1*/
	unit_R1= proto_tree_add_text (TupelEntry_list, tvb, *offset, 2, "unit_R1");
	unit_R1_tree = proto_item_add_subtree(unit_R1, ett_sml_unit_R1);
	proto_tree_add_item (unit_R1_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
	*offset+=1;
	proto_tree_add_item (unit_R1_tree, hf_sml_unit_R1, tvb, *offset, 1, ENC_NA);
	*offset+=1;

	/*scaler_R1*/
	scaler_R1= proto_tree_add_text (TupelEntry_list, tvb, *offset, 1, "scaler_R1");
	scaler_R1_tree = proto_item_add_subtree(scaler_R1, ett_sml_scaler_R1);
	proto_tree_add_item (scaler_R1_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
	*offset+=1;
	proto_tree_add_item (scaler_R1_tree, hf_sml_scaler_R1, tvb, *offset, 1, ENC_NA);
	*offset+=1;

	/*value_R1*/
	get_length(tvb, offset, &data, &length);
	value_R1= proto_tree_add_text (TupelEntry_list, tvb, *offset, length+data, "value_R1");
	value_R1_tree = proto_item_add_subtree(value_R1, ett_sml_value_R1);
	proto_tree_add_item (value_R1_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
	*offset+=1;
	proto_tree_add_item (value_R1_tree, hf_sml_value_R1, tvb, *offset, data, ENC_NA);
	*offset+=data;

	/*unit_R4*/
	unit_R4= proto_tree_add_text (TupelEntry_list, tvb, *offset, 2, "unit_R4");
	unit_R4_tree = proto_item_add_subtree(unit_R4, ett_sml_unit_R4);
	proto_tree_add_item (unit_R4_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
	*offset+=1;
	proto_tree_add_item (unit_R4_tree, hf_sml_unit_R4, tvb, *offset, 1, ENC_NA);
	*offset+=1;

	/*scaler_R4*/
	scaler_R4= proto_tree_add_text (TupelEntry_list, tvb, *offset, 2, "scaler_R4");
	scaler_R4_tree = proto_item_add_subtree(scaler_R4, ett_sml_scaler_R4);
	proto_tree_add_item (scaler_R4_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
	*offset+=1;
	proto_tree_add_item (scaler_R4_tree, hf_sml_scaler_R4, tvb, *offset, 1, ENC_NA);
	*offset+=1;

	/*value_R4*/
	get_length(tvb, offset, &data, &length);
	value_R4= proto_tree_add_text (TupelEntry_list, tvb, *offset, length+data, "value_R4");
	value_R4_tree = proto_item_add_subtree(value_R4, ett_sml_value_R4);
	proto_tree_add_item (value_R4_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
	*offset+=1;
	proto_tree_add_item (value_R4_tree, hf_sml_value_R4, tvb, *offset, data, ENC_NA);
	*offset+=data;

	/*signature_pA_R1_R4*/
	get_length(tvb, offset, &data, &length);
	signature_pA_R1_R4= proto_tree_add_text (TupelEntry_list, tvb, *offset, length+data, "signature_pa_R1_R4");
	signature_pA_R1_R4_tree = proto_item_add_subtree(signature_pA_R1_R4, ett_sml_signature_pA_R1_R4);
	proto_tree_add_text (signature_pA_R1_R4_tree, tvb, *offset, length, "Length: %d %s", data ,plurality(data, "octet", "octets"));
	*offset+=length;
	proto_tree_add_item (signature_pA_R1_R4_tree, hf_sml_signature_pA_R1_R4, tvb, *offset, data, ENC_NA);
	*offset+=data;

	/*unit_mA*/
	unit_mA= proto_tree_add_text (TupelEntry_list, tvb, *offset, 2, "unit_mA");
	unit_mA_tree = proto_item_add_subtree(unit_mA, ett_sml_unit_mA);
	proto_tree_add_item (unit_mA_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
	*offset+=1;
	proto_tree_add_item (unit_mA_tree, hf_sml_unit_mA, tvb, *offset, 1, ENC_NA);
	*offset+=1;

	/*scaler_mA*/
	scaler_mA= proto_tree_add_text (TupelEntry_list, tvb, *offset, 2, "scaler_mA");
	scaler_mA_tree = proto_item_add_subtree(scaler_mA, ett_sml_scaler_mA);
	proto_tree_add_item (scaler_mA_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
	*offset+=1;
	proto_tree_add_item (scaler_mA_tree, hf_sml_scaler_mA, tvb, *offset, 1, ENC_NA);
	*offset+=1;

	/*value_mA*/
	get_length(tvb, offset, &data, &length);
	value_mA= proto_tree_add_text (TupelEntry_list, tvb, *offset, length+data, "value_mA");
	value_mA_tree = proto_item_add_subtree(value_mA, ett_sml_value_mA);
	proto_tree_add_item (value_mA_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
	*offset+=1;
	proto_tree_add_item (value_mA_tree, hf_sml_value_mA, tvb, *offset, data, ENC_NA);
	*offset+=data;

	/*unit_R2*/
	unit_R2= proto_tree_add_text (TupelEntry_list, tvb, *offset, 2, "unit_R2");
	unit_R2_tree = proto_item_add_subtree(unit_R2, ett_sml_unit_R2);
	proto_tree_add_item (unit_R2_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
	*offset+=1;
	proto_tree_add_item (unit_R2_tree, hf_sml_unit_R2, tvb, *offset, 1, ENC_NA);
	*offset+=1;

	/*scaler_R2*/
	scaler_R2= proto_tree_add_text (TupelEntry_list, tvb, *offset, 2, "scaler_R2");
	scaler_R2_tree = proto_item_add_subtree(scaler_R2, ett_sml_scaler_R2);
	proto_tree_add_item (scaler_R2_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
	*offset+=1;
	proto_tree_add_item (scaler_R2_tree, hf_sml_scaler_R2, tvb, *offset, 1, ENC_NA);
	*offset+=1;

	/*value_R2*/
	get_length(tvb, offset, &data, &length);
	value_R2= proto_tree_add_text (TupelEntry_list, tvb, *offset, length+data, "value_R2");
	value_R2_tree = proto_item_add_subtree(value_R2, ett_sml_value_R2);
	proto_tree_add_item (value_R2_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
	*offset+=1;
	proto_tree_add_item (value_R2_tree, hf_sml_value_R2, tvb, *offset, data, ENC_NA);
	*offset+=data;

	/*unit_R3*/
	unit_R3= proto_tree_add_text (TupelEntry_list, tvb, *offset, 2, "unit_R3");
	unit_R3_tree = proto_item_add_subtree(unit_R3, ett_sml_unit_R3);
	proto_tree_add_item (unit_R3_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
	*offset+=1;
	proto_tree_add_item (unit_R3_tree, hf_sml_unit_R3, tvb, *offset, 1, ENC_NA);
	*offset+=1;

	/*scaler_R3*/
	scaler_R3= proto_tree_add_text (TupelEntry_list, tvb, *offset, 2, "scaler_R3");
	scaler_R3_tree = proto_item_add_subtree(scaler_R3, ett_sml_scaler_R3);
	proto_tree_add_item (scaler_R3_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
	*offset+=1;
	proto_tree_add_item (scaler_R3_tree, hf_sml_scaler_R3, tvb, *offset, 1, ENC_NA);
	*offset+=1;

	/*value_R3*/
	get_length(tvb, offset, &data, &length);
	value_R3= proto_tree_add_text (TupelEntry_list, tvb, *offset, length+data, "value_R3");
	value_R3_tree = proto_item_add_subtree(value_R3, ett_sml_value_R3);
	proto_tree_add_item (value_R3_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
	*offset+=1;
	proto_tree_add_item (value_R3_tree, hf_sml_value_R3, tvb, *offset, data, ENC_NA);
	*offset+=data;

	/*signature_mA_R2_R3*/
	get_length(tvb, offset, &data, &length);
	signature_mA_R2_R3= proto_tree_add_text (TupelEntry_list, tvb, *offset, length+data, "signature_mA_R2_R3");
	signature_mA_R2_R3_tree = proto_item_add_subtree(signature_mA_R2_R3, ett_sml_signature_mA_R2_R3);
	proto_tree_add_text (signature_mA_R2_R3_tree, tvb, *offset, length, "Length: %d %s", data ,plurality(data, "octet", "octets"));
	*offset+=length;
	proto_tree_add_item (signature_mA_R2_R3_tree, hf_sml_signature_mA_R2_R3, tvb, *offset, data, ENC_NA);
	*offset+=data;

	proto_item_set_end(TupelEntry, tvb, *offset);
}

static void child_tree(tvbuff_t *tvb, packet_info *pinfo, proto_tree *insert_tree, guint *offset, guint *data, guint *length){
	proto_item *parameterName = NULL;
	proto_item *procParValue = NULL;
	proto_item *child = NULL;
	proto_item *procParValuetype = NULL;
	proto_item *periodEntry = NULL;
	proto_item *SML_time = NULL;
	proto_item *procParValueTime = NULL;
	proto_item *tree_Entry = NULL;

	proto_tree *parameterName_tree = NULL;
	proto_tree *procParValue_tree = NULL;
	proto_tree *procParValuetype_tree = NULL;
	proto_tree *periodEntry_tree = NULL;
	proto_tree *SML_time_tree = NULL;
	proto_tree *procParValueTime_tree = NULL;
	proto_tree *child_list = NULL;
	proto_tree *tree_Entry_list = NULL;

	guint i = 0;
	guint repeat = 0;
	guint check = 0;

	/*parameterName*/
	get_length(tvb, offset, data, length);
	parameterName = proto_tree_add_text (insert_tree, tvb, *offset, *length + *data ,"parameterName");
	parameterName_tree = proto_item_add_subtree (parameterName, ett_sml_parameterName);
	proto_tree_add_text (parameterName_tree, tvb, *offset, *length, "Length: %d %s", *data ,plurality(*data, "octet", "octets"));
	*offset+=*length;
	proto_tree_add_item (parameterName_tree, hf_sml_parameterName, tvb, *offset, *data, ENC_NA);
	*offset+=*data;

	/*procParValue OPTIONAL*/
	check = tvb_get_guint8(tvb, *offset);

	if (check == OPTIONAL){
		procParValue = proto_tree_add_item(insert_tree, hf_sml_procParValue, tvb, *offset, 1, ENC_NA);
		proto_item_append_text(procParValue, ": NOT SET");
		*offset+=1;
	}
	else if (check == 0x72){
		get_length(tvb, offset, data, length);
		procParValue = proto_tree_add_text(insert_tree, tvb, *offset, -1, "ProcParValue");
		procParValue_tree = proto_item_add_subtree (procParValue, ett_sml_procParValue);
		*offset+=1;

		/*procParValue CHOOSE*/
		procParValuetype = proto_tree_add_text (procParValue_tree, tvb, *offset, 2, "ProcParValueType");
		procParValuetype_tree = proto_item_add_subtree (procParValuetype, ett_sml_procParValuetype);
		proto_tree_add_item (procParValuetype_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
		*offset+=1;
		check = tvb_get_guint8(tvb, *offset);
		proto_tree_add_item (procParValuetype_tree, hf_sml_procParValue, tvb, *offset, 1 ,ENC_NA);
		*offset+=1;

		switch (check) {
			case PROC_VALUE:
				/*value*/
				sml_value(tvb, procParValue_tree, offset, data, length);
				break;

			case PROC_PERIOD:
				/*period*/
				get_length(tvb, offset, data, length);
				periodEntry = proto_tree_add_text(procParValue_tree, tvb, *offset, -1, "PeriodEntry List with %d %s", *length + *data, plurality(*length + *data, "element", "elements"));
				periodEntry_tree = proto_item_add_subtree(periodEntry, ett_sml_periodEntry);
				*offset+=*length;

				/*objName*/
				field_objName(tvb, periodEntry_tree, offset, data, length);

				/*unit OPTIONAL*/
				field_unit(tvb, periodEntry_tree, offset, data, length);

				/*scaler OPTIONAL*/
				field_scaler(tvb, periodEntry_tree, offset, data, length);

				/*value*/
				sml_value(tvb, periodEntry_tree, offset, data, length);

				/*value Signature*/
				field_valueSignature(tvb, periodEntry_tree, offset, data, length);

				proto_item_set_end(periodEntry, tvb, *offset);
				break;

			case PROC_TUPEL:
				/*TupelEntry*/
				if (tvb_get_guint8(tvb, *offset) == 0xF1 && tvb_get_guint8(tvb, *offset+1) == 0x07){
					TupelEntryTree(tvb, procParValue_tree, offset);
				}
				else {
					expert_add_info(pinfo, NULL, &ei_sml_tupel_error);
					return;
				}
				break;

			case PROC_TIME:
				SML_time = proto_tree_add_text (procParValue_tree, tvb, *offset, -1, "Time");
				SML_time_tree = proto_item_add_subtree (SML_time, ett_sml_time);
				*offset+=1;

				sml_time_type(tvb, SML_time_tree, offset);

				/*Time*/
				get_length(tvb, offset, data, length);
				procParValueTime = proto_tree_add_text (SML_time_tree, tvb, *offset, *length + *data, "procParValueTime");
				procParValueTime_tree = proto_item_add_subtree (procParValueTime, ett_sml_procParValueTime);
				proto_tree_add_item (procParValueTime_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
				*offset+=1;
				proto_tree_add_item(procParValueTime_tree, hf_sml_procParValueTime, tvb, *offset, *data, ENC_BIG_ENDIAN);
				*offset+=*data;

				proto_item_set_end(SML_time, tvb, *offset);
				break;

			default:
				expert_add_info(pinfo, procParValue, &ei_sml_procParValue_invalid);
				break;
		}
		proto_item_set_end(procParValue, tvb, *offset);
	}
	else {
		expert_add_info(pinfo, NULL, &ei_sml_procParValue_errror);
		return;
	}

	/*child list OPTIONAL*/
	check = tvb_get_guint8(tvb, *offset);

	if (check == OPTIONAL){
		proto_tree_add_text (insert_tree, tvb, *offset, 1, "Child List: NOT SET");
		*offset+=1;
	}
	else if ((check & 0x0F) != 0){
		if (check == 0x71){
			get_length(tvb, offset, data, length);
			child = proto_tree_add_text(insert_tree, tvb, *offset, -1, "Child List with %d %s", *length + *data, plurality(*length + *data, "element", "elements"));
			child_list = proto_item_add_subtree(child, ett_sml_child);
			*offset+=1;

			tree_Entry = proto_tree_add_text (child_list, tvb, *offset, -1, "tree_Entry");
			tree_Entry_list = proto_item_add_subtree(tree_Entry, ett_sml_tree_Entry);
			*offset+=1;

			child_tree(tvb, pinfo,tree_Entry_list, offset, data, length);

			proto_item_set_end(tree_Entry, tvb, *offset);
			proto_item_set_end(child, tvb, *offset);
		}
		else if ((check & 0xF0) == SHORT_LIST || (check & 0xF0) == LONG_LIST){
			get_length(tvb, offset, data, length);
			repeat = *length + *data;
			child = proto_tree_add_text(insert_tree, tvb, *offset, -1, "Child List with %d %s", *length + *data, plurality(*length + *data, "element", "elements"));
			child_list = proto_item_add_subtree(child, ett_sml_child);
			if (repeat <= 0){
				expert_add_info_format(pinfo, child, &ei_sml_invalid_count, "invalid loop count");
				return;
			}
			*offset+=*length;

			for(i =0 ; i < repeat; i++){
				tree_Entry = proto_tree_add_text (child_list, tvb, *offset, -1, "tree_Entry");
				tree_Entry_list = proto_item_add_subtree(tree_Entry, ett_sml_tree_Entry);

				if (tvb_get_guint8(tvb, *offset) != 0x73){
					expert_add_info_format(pinfo, tree_Entry, &ei_sml_invalid_count, "invalid count of elements in tree_Entry");
					return;
				}
				*offset+=1;

				child_tree(tvb, pinfo, tree_Entry_list, offset, data, length);
				proto_item_set_end(tree_Entry, tvb, *offset);
			}
			proto_item_set_end(child, tvb, *offset);
		}
	}
	else {
		expert_add_info_format(pinfo, NULL, &ei_sml_invalid_count, "invalid count of elements in child List");
	}
}

/*messagetypes*/
static void decode_PublicOpenReq (tvbuff_t *tvb, proto_tree *messagebodytree_list, guint *offset){
	guint data = 0;
	guint length = 0;

	/*Codepage OPTIONAL*/
	field_codepage (tvb, messagebodytree_list, offset, &data, &length);

	/*clientID*/
	field_clientId (tvb, messagebodytree_list, offset, &data, &length);

	/*reqFileId*/
	field_reqFileId (tvb, messagebodytree_list, offset, &data, &length);

	/*ServerID*/
	field_serverId(tvb,messagebodytree_list, offset, &data, &length);

	/*user*/
	field_username(tvb,messagebodytree_list, offset, &data, &length);

	/*password*/
	field_password(tvb,messagebodytree_list, offset, &data, &length);

	/*sml-Version OPTIONAL*/
	field_smlVersion(tvb,messagebodytree_list, offset, &data, &length);
}

static void decode_PublicOpenRes (tvbuff_t *tvb, proto_tree *messagebodytree_list, guint *offset){
	proto_item *refTime = NULL;
	proto_item *SML_time = NULL;

	proto_tree *refTime_tree = NULL;
	proto_tree *SML_time_tree = NULL;

	guint data = 0;
	guint length = 0;

	/*Codepage OPTIONAL*/
	field_codepage (tvb, messagebodytree_list, offset, &data, &length);

	/*clientID OPTIONAL*/
	field_clientId (tvb, messagebodytree_list, offset, &data, &length);

	/*reqFileId*/
	field_reqFileId (tvb, messagebodytree_list, offset, &data, &length);

	/*ServerID*/
	field_serverId(tvb,messagebodytree_list,offset, &data, &length);

	/*RefTime Optional*/
	get_length(tvb, offset, &data, &length);

	if (data == 0){
		proto_tree_add_text (messagebodytree_list, tvb, *offset, length + data, "refTime: NOT SET");
		*offset+=1;
	}
	else{
		/*SML TIME*/
		SML_time = proto_tree_add_text (messagebodytree_list, tvb, *offset, -1, "refTime");
		SML_time_tree = proto_item_add_subtree (SML_time, ett_sml_time);
		*offset+=1;

		sml_time_type(tvb, SML_time_tree, offset);

		/*refTime*/
		get_length(tvb, offset, &data, &length);
		refTime = proto_tree_add_text (SML_time_tree, tvb, *offset, length+data, "refTime");
		refTime_tree = proto_item_add_subtree (refTime, ett_sml_refTime);
		proto_tree_add_item (refTime_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
		*offset+=1;
		proto_tree_add_item(refTime_tree, hf_sml_refTime, tvb, *offset, data, ENC_BIG_ENDIAN);
		*offset+=data;
		proto_item_set_end(SML_time,tvb,*offset);
	}
	/*sml-Version OPTIONAL*/
	field_smlVersion(tvb, messagebodytree_list, offset, &data, &length);
}

static gboolean decode_GetProfile_List_Pack_Req (tvbuff_t *tvb, packet_info *pinfo, proto_tree *messagebodytree_list, guint *offset){
	proto_item *withRawdata = NULL;
	proto_item *SML_time = NULL;
	proto_item *beginTime = NULL;
	proto_item *treepath = NULL;
	proto_item *object_list = NULL;
	proto_item *endTime = NULL;
	proto_item *dasDetails = NULL;

	proto_tree *withRawdata_tree = NULL;
	proto_tree *SML_time_tree = NULL;
	proto_tree *beginTime_tree = NULL;
	proto_tree *treepath_list = NULL;
	proto_tree *object_list_list = NULL;
	proto_tree *endTime_tree = NULL;
	proto_tree *dasDetails_list = NULL;

	guint i = 0;
	guint repeat = 0;
	guint check = 0;
	guint data = 0;
	guint length = 0;

	/*ServerID*/
	field_serverId(tvb,messagebodytree_list, offset, &data, &length);

	/*user*/
	field_username(tvb,messagebodytree_list, offset, &data, &length);

	/*password*/
	field_password(tvb,messagebodytree_list, offset, &data, &length);

	/*withRawdata OPTIONAL*/
	get_length(tvb, offset, &data, &length);
	withRawdata = proto_tree_add_uint_format (messagebodytree_list, hf_sml_withRawdata, tvb, *offset, data+length, data+length, "withRawdata %s", (data == 0)? ": NOT SET" : "");

	if (data > 0) {
		withRawdata_tree = proto_item_add_subtree (withRawdata, ett_sml_withRawdata);
		proto_tree_add_item (withRawdata_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
		*offset+=1;
		proto_tree_add_item (withRawdata_tree, hf_sml_withRawdata, tvb, *offset, 1, ENC_NA);
		*offset+=1;
	}
	else
		*offset+=1;

	/*beginTime OPTIONAL*/
	get_length(tvb, offset, &data, &length);

	if (data == 0){
		proto_tree_add_text (messagebodytree_list, tvb, *offset, length + data, "beginTime: NOT SET");
		*offset+=1;
	}
	else {
		/*SML TIME*/
		SML_time = proto_tree_add_text (messagebodytree_list, tvb, *offset, -1, "beginTime");
		SML_time_tree = proto_item_add_subtree (SML_time, ett_sml_time);
		*offset+=1;

		sml_time_type(tvb, SML_time_tree, offset);

		/*beginTime*/
		get_length(tvb, offset, &data, &length);
		beginTime = proto_tree_add_text (SML_time_tree, tvb, *offset, length + data, "beginTime");
		beginTime_tree = proto_item_add_subtree (beginTime, ett_sml_beginTime);
		proto_tree_add_item (beginTime_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
		*offset+=1;
		proto_tree_add_item(beginTime_tree, hf_sml_beginTime, tvb, *offset, data, ENC_BIG_ENDIAN);
		*offset+=data;
		proto_item_set_end(SML_time,tvb,*offset);
	}

	/*endTime OPTIONAL*/
	get_length(tvb, offset, &data, &length);

	if (data == 0){
		proto_tree_add_text (messagebodytree_list, tvb, *offset, length + data, "endTime: NOT SET");
		*offset+=1;
	}
	else {
		/*SML TIME*/
		SML_time = proto_tree_add_text (messagebodytree_list, tvb, *offset, -1, "endTime");
		SML_time_tree = proto_item_add_subtree (SML_time, ett_sml_time);
		*offset+=1;

		sml_time_type(tvb, SML_time_tree, offset);

		/*endTime*/
		get_length(tvb, offset, &data, &length);
		endTime = proto_tree_add_text (SML_time_tree, tvb, *offset, length + data, "endTime");
		endTime_tree = proto_item_add_subtree (endTime, ett_sml_beginTime);
		proto_tree_add_item (endTime_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
		*offset+=1;
		proto_tree_add_item(endTime_tree, hf_sml_endTime, tvb, *offset, data, ENC_BIG_ENDIAN);
		*offset+=data;
		proto_item_set_end(SML_time,tvb,*offset);
	}

	/*Treepath List*/
	get_length(tvb, offset, &data, &length);
	repeat = (data+length);
	treepath = proto_tree_add_text (messagebodytree_list, tvb, *offset, -1, "parameterTreePath with %d %s", length+data, plurality(length+data, "element", "elements"));
	treepath_list = proto_item_add_subtree(treepath, ett_sml_treepath);

	if ((tvb_get_guint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_guint8(tvb,*offset) & 0xF0) != SHORT_LIST){
		expert_add_info_format(pinfo, treepath, &ei_sml_invalid_count, "invalid count of elements in Treepath");
		return TRUE;
	}
	else if (repeat <= 0){
		expert_add_info_format(pinfo, treepath, &ei_sml_invalid_count, "invalid loop count");
		return TRUE;
	}
	*offset+=length;

	for (i=0; i< repeat; i++) {
		field_parameterTreePath(tvb, treepath_list, offset, &data, &length);
	}
	proto_item_set_end(treepath, tvb, *offset);

	/*object_list*/
	if (tvb_get_guint8(tvb,*offset) == OPTIONAL){
		proto_tree_add_text (messagebodytree_list, tvb, *offset, 1, "object_List: NOT SET");
		*offset+=1;
	}
	else{
		get_length(tvb, offset, &data, &length);
		repeat = (data+length);
		object_list = proto_tree_add_text (messagebodytree_list, tvb, *offset, -1, "object_List with %d %s", length+data, plurality(length+data, "element", "elements"));
		object_list_list = proto_item_add_subtree(object_list, ett_sml_object_list);

		if ((tvb_get_guint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_guint8(tvb,*offset) & 0xF0) != SHORT_LIST){
			expert_add_info_format(pinfo, object_list, &ei_sml_invalid_count, "invalid count of elements in object_List");
			return TRUE;
		}
		else if (repeat <= 0){
			expert_add_info_format(pinfo, treepath, &ei_sml_invalid_count, "invalid loop count");
			return TRUE;
		}

		*offset+=length;

		for (i=0; i< repeat; i++) {
			field_ObjReqEntry(tvb, object_list_list, offset, &data, &length);
		}
		proto_item_set_end(object_list, tvb, *offset);
	}

	/*dasDetails*/
	check = tvb_get_guint8(tvb,*offset);

	if (check == OPTIONAL){
		proto_tree_add_text (messagebodytree_list, tvb, *offset, 1, "dasDetails: NOT SET");
		*offset+=1;
	}
	else if ((check & 0xF0) == LONG_LIST || (check & 0xF0) == SHORT_LIST){
		get_length(tvb, offset, &data, &length);
		dasDetails = proto_tree_add_text(messagebodytree_list, tvb, *offset, -1, "dasDetails with %d %s", length+data, plurality(length+data, "element", "elements"));
		dasDetails_list = proto_item_add_subtree(dasDetails, ett_sml_dasDetails);
		*offset+=length;

		child_tree(tvb, pinfo, dasDetails_list, offset, &data, &length);
		proto_item_set_end(dasDetails, tvb, *offset);
	}
	else {
		expert_add_info_format(pinfo, NULL, &ei_sml_invalid_count, "invalid count of elements in dasDetails");
		return TRUE;
	}
	return FALSE;
}

static gboolean decode_GetProfilePackRes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *messagebodytree_list, guint *offset){
	proto_item *SML_time = NULL;
	proto_item *treepath = NULL;
	proto_item *periodList = NULL;
	proto_item *period_List_Entry = NULL;
	proto_item *headerList = NULL;
	proto_item *header_List_Entry = NULL;
	proto_item *profileSignature = NULL;
	proto_item *valuelist = NULL;
	proto_item *value_List_Entry = NULL;

	proto_tree *SML_time_tree = NULL;
	proto_tree *treepath_list = NULL;
	proto_tree *periodList_list = NULL;
	proto_tree *period_List_Entry_list = NULL;
	proto_tree *headerList_subtree = NULL;
	proto_tree *header_List_Entry_list = NULL;
	proto_tree *profileSignature_tree = NULL;
	proto_tree *valuelist_list = NULL;
	proto_tree *value_List_Entry_list = NULL;

	guint i = 0;
	guint d = 0;
	guint repeat = 0;
	guint repeat2= 0;
	guint data = 0;
	guint length = 0;

	/*ServerID*/
	field_serverId(tvb, messagebodytree_list, offset, &data, &length);

	/*actTime*/
	get_length(tvb, offset, &data, &length);
	SML_time = proto_tree_add_text (messagebodytree_list, tvb, *offset, -1, "actTime List with %d %s", length+data, plurality(length+data, "element", "elements"));
	SML_time_tree = proto_item_add_subtree (SML_time, ett_sml_time);
	*offset+=1;
	sml_time_type(tvb, SML_time_tree, offset);
	field_actTime(tvb, SML_time_tree, offset, &data, &length);
	proto_item_set_end(SML_time,tvb,*offset);

	/*regPeriod*/
	field_regPeriod(tvb, messagebodytree_list, offset, &data, &length);

	/*Treepath List*/
	get_length(tvb, offset, &data, &length);
	repeat = (data+length);
	treepath = proto_tree_add_text (messagebodytree_list, tvb, *offset, -1, "parameterTreePath with %d %s", length+data, plurality(length+data, "element", "elements"));
	treepath_list = proto_item_add_subtree(treepath, ett_sml_treepath);

	if ((tvb_get_guint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_guint8(tvb,*offset) & 0xF0) != SHORT_LIST){
		expert_add_info_format(pinfo, treepath, &ei_sml_invalid_count, "invalid count of elements in Treepath");
		return TRUE;
	}
	else if (repeat <= 0){
		expert_add_info_format(pinfo, treepath, &ei_sml_invalid_count, "invalid loop count");
		return TRUE;
	}

	*offset+=length;

	for (i=0; i< repeat; i++) {
		field_parameterTreePath(tvb, treepath_list, offset, &data, &length);
	}
	proto_item_set_end(treepath, tvb, *offset);

	/*headerList*/
	get_length(tvb, offset, &data, &length);
	repeat = (data+length);
	headerList = proto_tree_add_text (messagebodytree_list, tvb, *offset, -1, "header_List with %d %s", length+data, plurality(length+data, "element", "elements"));
	headerList_subtree = proto_item_add_subtree(headerList, ett_sml_headerList);

	if ((tvb_get_guint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_guint8(tvb,*offset) & 0xF0) != SHORT_LIST){
		expert_add_info_format(pinfo, headerList, &ei_sml_invalid_count, "invalid count of elements in headerlist");
		return TRUE;
	}
	else if (repeat <= 0){
		expert_add_info_format(pinfo, headerList, &ei_sml_invalid_count, "invalid loop count");
		return TRUE;
	}

	*offset+=length;

	for (i=0; i< repeat; i++) {
		get_length(tvb, offset, &data, &length);
		header_List_Entry = proto_tree_add_text (headerList_subtree, tvb, *offset, -1, "header_List_Entry with %d %s", length+data, plurality(length+data, "element", "elements"));
		header_List_Entry_list = proto_item_add_subtree(header_List_Entry, ett_sml_header_List_Entry);
		*offset+=1;

		/*objname*/
		field_objName(tvb, header_List_Entry_list, offset, &data, &length);

		/*unit*/
		field_unit(tvb, header_List_Entry_list, offset, &data, &length);

		/*scaler*/
		field_scaler(tvb, header_List_Entry_list, offset, &data, &length);

		proto_item_set_end(header_List_Entry, tvb, *offset);
	}
	proto_item_set_end(headerList, tvb, *offset);

	/*period List*/
	get_length(tvb, offset, &data, &length);
	repeat = (data+length);
	periodList = proto_tree_add_text (messagebodytree_list, tvb, *offset, -1, "period_List with %d %s", length+data, plurality(length+data, "element", "elements"));
	periodList_list = proto_item_add_subtree(periodList, ett_sml_periodList);

	if ((tvb_get_guint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_guint8(tvb,*offset) & 0xF0) != SHORT_LIST){
		expert_add_info_format(pinfo, periodList, &ei_sml_invalid_count, "invalid count of elements in periodList");
		return TRUE;
	}
	else if (repeat <= 0){
		expert_add_info_format(pinfo, periodList, &ei_sml_invalid_count, "invalid loop count");
		return TRUE;
	}

	*offset+=length;

	for (i=0; i< repeat; i++) {
		get_length(tvb, offset, &data, &length);
		period_List_Entry = proto_tree_add_text (periodList_list, tvb, *offset, -1, "period_List_Entry with %d %s", length+data, plurality(length+data, "element", "elements"));
		period_List_Entry_list = proto_item_add_subtree(period_List_Entry, ett_sml_period_List_Entry);
		*offset+=1;

		/*valTime*/
		get_length(tvb, offset, &data, &length);
		SML_time = proto_tree_add_text (period_List_Entry, tvb, *offset, -1, "valTime");
		SML_time_tree = proto_item_add_subtree (SML_time, ett_sml_time);
		*offset+=1;
		sml_time_type(tvb, SML_time_tree, offset);
		field_valTime(tvb, SML_time_tree, offset, &data, &length);
		proto_item_set_end(SML_time,tvb, *offset);

		/*status*/
		field_status(tvb, period_List_Entry_list, offset, &data, &length);

		/*value List*/
		get_length(tvb, offset, &data, &length);
		repeat2 = data + length;
		valuelist = proto_tree_add_text (period_List_Entry_list, tvb, *offset, -1, "period_List with %d %s", length+data, plurality(length+data, "element", "elements"));
		valuelist_list = proto_item_add_subtree(valuelist, ett_sml_valuelist);

		if ((tvb_get_guint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_guint8(tvb,*offset) & 0xF0) != SHORT_LIST){
			expert_add_info_format(pinfo, valuelist, &ei_sml_invalid_count, "invalid count of elements in valueList");
			return TRUE;
		}
		else if (repeat2 <= 0){
			expert_add_info_format(pinfo, valuelist, &ei_sml_invalid_count, "invalid loop count");
			return TRUE;
		}

		*offset+=length;

		for (d=0; d< repeat2; d++) {
			get_length(tvb, offset, &data, &length);
			value_List_Entry = proto_tree_add_text (valuelist_list, tvb, *offset, -1, "value_List_Entry with %d %s", length+data, plurality(length+data, "element", "elements"));
			value_List_Entry_list = proto_item_add_subtree(value_List_Entry, ett_sml_value_List_Entry);
			*offset+=1;

			/*value*/
			sml_value(tvb, value_List_Entry_list, offset, &data, &length);

			/*value Signature*/
			field_valueSignature(tvb, value_List_Entry_list, offset, &data, &length);

			proto_item_set_end(value_List_Entry, tvb, *offset);
		}
		proto_item_set_end(valuelist, tvb, *offset);

		/*period Signature*/
		field_periodSignature(tvb, period_List_Entry_list, offset, &data, &length);

		proto_item_set_end(period_List_Entry, tvb, *offset);
	}
	proto_item_set_end(periodList,tvb, *offset);

	/*rawdata*/
	field_rawdata(tvb, messagebodytree_list, offset, &data, &length);

	/*profile Signature*/
	get_length(tvb, offset, &data, &length);
	profileSignature = proto_tree_add_bytes_format (messagebodytree_list, hf_sml_profileSignature, tvb, *offset, length+data, NULL, "profileSignature %s", (data == 0)? ": NOT SET" : "");

	if (data > 0){
		profileSignature_tree = proto_item_add_subtree (profileSignature, ett_sml_profileSignature);
		proto_tree_add_text (profileSignature_tree, tvb, *offset, length, "Length: %d %s", data, plurality(data, "octet", "octets"));
		*offset+=length;
		proto_tree_add_item (profileSignature_tree, hf_sml_profileSignature, tvb, *offset, data, ENC_NA);
		*offset+=data;
	}
	else
		*offset+=1;

	return FALSE;
}

static gboolean decode_GetProfileListRes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *messagebodytree_list, guint *offset){
	proto_item *SML_time = NULL;
	proto_item *treepath = NULL;
	proto_item *periodList = NULL;
	proto_item *periodList_Entry = NULL;

	proto_tree *SML_time_tree = NULL;
	proto_tree *treepath_list = NULL;
	proto_tree *periodList_list = NULL;
	proto_tree *periodList_Entry_list = NULL;

	guint i = 0;
	guint repeat = 0;
	guint data = 0;
	guint length = 0;

	/*ServerID*/
	field_serverId(tvb, messagebodytree_list, offset, &data, &length);

	/*actTime*/
	get_length(tvb, offset, &data, &length);
	SML_time = proto_tree_add_text (messagebodytree_list, tvb, *offset, -1, "actTime");
	SML_time_tree = proto_item_add_subtree (SML_time, ett_sml_time);
	*offset+=1;
	sml_time_type(tvb, SML_time_tree, offset);
	field_actTime(tvb, SML_time_tree, offset, &data, &length);
	proto_item_set_end(SML_time,tvb, *offset);

	/*regPeriod*/
	field_regPeriod(tvb, messagebodytree_list, offset, &data, &length);

	/*Treepath List*/
	get_length(tvb, offset, &data, &length);
	repeat = (data+length);
	treepath = proto_tree_add_text (messagebodytree_list, tvb, *offset, -1, "parameterTreePath with %d %s", length+data, plurality(length+data, "element", "elements"));
	treepath_list = proto_item_add_subtree(treepath, ett_sml_treepath);

	if ((tvb_get_guint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_guint8(tvb,*offset) & 0xF0) != SHORT_LIST){
		expert_add_info_format(pinfo, treepath, &ei_sml_invalid_count, "invalid count of elements in parameterTreePath");
		return TRUE;
	}
	else if (repeat <= 0){
		expert_add_info_format(pinfo, treepath, &ei_sml_invalid_count, "invalid loop count");
		return TRUE;
	}

	*offset+=length;

	for (i=0; i< repeat; i++) {
		field_parameterTreePath(tvb, treepath_list, offset, &data, &length);
	}
	proto_item_set_end(treepath, tvb,*offset);

	/*valTime Optional*/
	get_length(tvb, offset, &data, &length);

	if (data == 0){
		proto_tree_add_text (messagebodytree_list, tvb, *offset, length + data, "valTime: NOT SET");
		*offset+=1;
	}
	else {
		/*SML TIME*/
		SML_time = proto_tree_add_text (messagebodytree_list, tvb, *offset, -1, "valTime");
		SML_time_tree = proto_item_add_subtree (SML_time, ett_sml_time);
		*offset+=1;

		sml_time_type(tvb, SML_time_tree, offset);
		field_valTime(tvb, SML_time_tree, offset, &data, &length);
		proto_item_set_end(SML_time,tvb,*offset);
	}

	/*Status*/
	field_status(tvb, messagebodytree_list, offset, &data, &length);

	/*period-List*/
	get_length(tvb, offset, &data, &length);
	repeat = (data+length);
	periodList = proto_tree_add_text (messagebodytree_list, tvb, *offset, -1, "period-List with %d %s", length+data, plurality(length+data, "element", "elements"));
	periodList_list = proto_item_add_subtree(periodList, ett_sml_periodList);

	if ((tvb_get_guint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_guint8(tvb,*offset) & 0xF0) != SHORT_LIST){
		expert_add_info_format(pinfo, periodList, &ei_sml_invalid_count, "invalid count of elements in periodList");
		return TRUE;
	}
	else if (repeat <= 0){
		expert_add_info_format(pinfo, periodList, &ei_sml_invalid_count, "invalid loop count");
		return TRUE;
	}

	*offset+=length;

	for (i=0; i< repeat; i++) {
		get_length(tvb, offset, &data, &length);
		periodList_Entry = proto_tree_add_text (periodList_list, tvb, *offset, -1, "PeriodEntry");
		periodList_Entry_list = proto_item_add_subtree(periodList_Entry, ett_sml_period_List_Entry);
		*offset+=1;

		/*ObjName*/
		field_objName(tvb, periodList_Entry_list, offset, &data, &length);

		/*Unit*/
		field_unit(tvb, periodList_Entry_list, offset, &data, &length);

		/*scaler*/
		field_scaler(tvb, periodList_Entry_list, offset, &data, &length);

		/*value*/
		sml_value(tvb, periodList_Entry_list, offset, &data, &length);

		/*value*/
		field_valueSignature(tvb, periodList_Entry_list, offset, &data, &length);

		proto_item_set_end(periodList_Entry, tvb, *offset);
	}
	proto_item_set_end(periodList, tvb, *offset);

	/*rawdata*/
	field_rawdata(tvb, messagebodytree_list, offset, &data, &length);

	/*period Signature*/
	field_periodSignature(tvb, messagebodytree_list, offset, &data, &length);

	return FALSE;
}

static void decode_GetListReq (tvbuff_t *tvb, proto_tree *messagebodytree_list, guint *offset){
	guint data = 0;
	guint length = 0;

	/*clientID*/
	field_clientId (tvb, messagebodytree_list, offset, &data, &length);

	/*ServerID*/
	field_serverId(tvb,messagebodytree_list,offset, &data, &length);

	/*user*/
	field_username(tvb,messagebodytree_list,offset, &data, &length);

	/*password*/
	field_password(tvb,messagebodytree_list,offset, &data, &length);

	/*listName*/
	field_listName(tvb,messagebodytree_list,offset, &data, &length);
}

static gboolean decode_GetListRes (tvbuff_t *tvb, packet_info *pinfo, proto_tree *messagebodytree_list, guint *offset){
	proto_item *actSensorTime = NULL;
	proto_item *valList = NULL;
	proto_item *listSignature = NULL;
	proto_item *valtree = NULL;
	proto_item *actGatewayTime = NULL;
	proto_item *SML_time;

	proto_tree *actSensorTime_tree = NULL;
	proto_tree *valList_list = NULL;
	proto_tree *listSignature_tree = NULL;
	proto_tree *valtree_list = NULL;
	proto_tree *actGatewayTime_tree = NULL;
	proto_tree *SML_time_tree = NULL;

	guint repeat = 0;
	guint i = 0;
	guint data = 0;
	guint length = 0;

	/*clientID OPTIONAL*/
	field_clientId (tvb, messagebodytree_list, offset, &data, &length);

	/*ServerID*/
	field_serverId(tvb, messagebodytree_list, offset, &data, &length);

	/*listName*/
	field_listName(tvb, messagebodytree_list, offset, &data, &length);

	/*actSensorTime OPTIONAL*/
	get_length(tvb, offset, &data, &length);

	if (data == 0){
		proto_tree_add_text (messagebodytree_list, tvb, *offset, length + data, "actSensorTime: NOT SET");
		*offset+=1;
	}
	else {
		/*SML TIME*/
		SML_time = proto_tree_add_text (messagebodytree_list, tvb, *offset, -1, "actSensorTime");
		SML_time_tree = proto_item_add_subtree (SML_time, ett_sml_time);
		*offset+=1;

		sml_time_type(tvb, SML_time_tree, offset);

		/*actSensorTime*/
		get_length(tvb, offset, &data, &length);
		actSensorTime = proto_tree_add_text (SML_time_tree, tvb, *offset, length + data, "actSensorTime");
		actSensorTime_tree = proto_item_add_subtree (actSensorTime, ett_sml_actSensorTime);
		proto_tree_add_item (actSensorTime_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
		*offset+=1;
		proto_tree_add_item(actSensorTime_tree, hf_sml_actSensorTime, tvb, *offset, data, ENC_BIG_ENDIAN);
		*offset+=data;
		proto_item_set_end(SML_time,tvb,*offset);
	}

	/*valList*/
	get_length(tvb, offset, &data, &length);
	repeat = (length + data);
	valtree = proto_tree_add_text (messagebodytree_list, tvb, *offset, -1, "valList with %d %s", length+data, plurality(length+data, "element", "elements"));
	valtree_list = proto_item_add_subtree (valtree, ett_sml_valtree);

	if ((tvb_get_guint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_guint8(tvb,*offset) & 0xF0) != SHORT_LIST){
		expert_add_info_format(pinfo, valtree, &ei_sml_invalid_count, "invalid count of elements in valList");
		return TRUE;
	}
	else if (repeat <= 0){
		expert_add_info_format(pinfo, valtree, &ei_sml_invalid_count, "invalid loop count");
		return TRUE;
	}

	*offset+=length;

	for (i=0; i < repeat; i++){
		get_length(tvb, offset, &data, &length);
		valList = proto_tree_add_text (valtree_list, tvb, *offset, -1, "valListEntry");
		valList_list = proto_item_add_subtree (valList, ett_sml_valList);
		*offset+=length;

		/*objName*/
		field_objName(tvb, valList_list, offset, &data, &length);

		/*Sml Status OPTIONAL*/
		field_status(tvb, valList_list, offset, &data, &length);

		/*valTime OPTIONAL*/
		get_length(tvb, offset, &data, &length);

		if (data == 0){
			proto_tree_add_text (valList_list, tvb, *offset, length + data, "valTime: NOT SET");
			*offset+=1;
		}
		else {
			/*SML TIME*/
			SML_time = proto_tree_add_text (valList_list, tvb, *offset, -1, "valTime");
			SML_time_tree = proto_item_add_subtree (SML_time, ett_sml_time);
			*offset+=1;

			sml_time_type(tvb, SML_time_tree, offset);
			field_valTime(tvb, SML_time_tree, offset, &data, &length);
			proto_item_set_end(SML_time, tvb, *offset);
		}

		/*unit OPTIONAL*/
		field_unit(tvb, valList_list, offset, &data, &length);

		/*Scaler OPTIONAL*/
		field_scaler(tvb, valList_list, offset, &data, &length);

		/*value*/
		sml_value(tvb, valList_list, offset, &data, &length);

		/*value Signature*/
		field_valueSignature(tvb, valList_list, offset, &data, &length);

		proto_item_set_end(valList, tvb, *offset);
	}
	proto_item_set_end(valtree, tvb, *offset);

	/*List Signature OPTIONAL*/
	get_length(tvb, offset, &data, &length);
	listSignature = proto_tree_add_bytes_format (messagebodytree_list, hf_sml_listSignature, tvb, *offset, length+data, NULL, "ListSignature %s", (data == 0)? ": NOT SET" : "");

	if (data > 0){
		listSignature_tree = proto_item_add_subtree (listSignature, ett_sml_listSignature);
		proto_tree_add_text (listSignature_tree, tvb, *offset, length, "Length: %d %s", data, plurality(data, "byte", "bytes"));
		*offset+=length;
		proto_tree_add_item (listSignature_tree, hf_sml_listSignature, tvb, *offset, data, ENC_NA);
		*offset+=data;
	}
	else
		*offset+=1;

	/*actGatewayTime OPTIONAL*/
	get_length(tvb, offset, &data, &length);

	if (data == 0){
		proto_tree_add_text (messagebodytree_list, tvb, *offset, length + data, "actGatewayTime: NOT SET");
		*offset+=1;
	}
	else{
		/*SML TIME*/
		SML_time = proto_tree_add_text (messagebodytree_list, tvb, *offset, -1, "actGatewayTime");
		SML_time_tree = proto_item_add_subtree (SML_time, ett_sml_time);
		*offset+=1;

		sml_time_type(tvb, SML_time_tree, offset);

		get_length(tvb, offset, &data, &length);
		actGatewayTime = proto_tree_add_text (SML_time_tree, tvb, *offset, length + data, "actGatewayTime");
		actGatewayTime_tree = proto_item_add_subtree (actGatewayTime, ett_sml_actSensorTime);
		proto_tree_add_item (actGatewayTime_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
		*offset+=1;
		proto_tree_add_item(actGatewayTime_tree, hf_sml_actGatewayTime, tvb, *offset, data, ENC_BIG_ENDIAN);
		*offset+=data;
		proto_item_set_end(SML_time,tvb,*offset);
	}
	return FALSE;
}

static gboolean decode_GetProcParameterReq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *messagebodytree_list, guint *offset){
	proto_item *treepath = NULL;
	proto_item *attribute = NULL;

	proto_tree *treepath_list = NULL;
	proto_tree *attribute_tree = NULL;

	guint i = 0;
	guint repeat = 0;
	guint data = 0;
	guint length = 0;

	/*ServerID*/
	field_serverId(tvb, messagebodytree_list, offset, &data, &length);

	/*user*/
	field_username(tvb, messagebodytree_list, offset, &data, &length);

	/*password*/
	field_password(tvb, messagebodytree_list, offset, &data, &length);

	/*Treepath List*/
	get_length(tvb, offset, &data, &length);
	repeat = data+length;
	treepath = proto_tree_add_text (messagebodytree_list, tvb, *offset, -1, "ParameterTreePath with %d %s", length+data, plurality(length+data, "element", "elements"));
	treepath_list = proto_item_add_subtree(treepath, ett_sml_treepath);

	if ((tvb_get_guint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_guint8(tvb,*offset) & 0xF0) != SHORT_LIST){
		expert_add_info_format(pinfo, treepath, &ei_sml_invalid_count, "invalid count of elements in ParameterTreePath");
		return TRUE;
	}
	else if (repeat <= 0){
		expert_add_info_format(pinfo, treepath, &ei_sml_invalid_count, "invalid loop count");
		return TRUE;
	}

	*offset+=length;

	for (i=0; i< repeat; i++) {
		field_parameterTreePath(tvb, treepath_list, offset, &data, &length);
	}
	proto_item_set_end(treepath, tvb, *offset);

	/*attribute*/
	get_length(tvb, offset, &data, &length);
	attribute = proto_tree_add_bytes_format (messagebodytree_list,hf_sml_attribute, tvb, *offset, length+data, NULL, "attribute %s", (data == 0)? ": NOT SET" : "");

	if (data > 0) {
		attribute_tree = proto_item_add_subtree (attribute, ett_sml_attribute);
		proto_tree_add_text (attribute_tree, tvb, *offset, length, "Length: %d %s", data, plurality(data, "octet", "octets"));
		*offset+=length;
		proto_tree_add_item (attribute_tree, hf_sml_attribute, tvb, *offset, data, ENC_NA);
		*offset+=data;
	}
	else
		*offset+=1;

	return FALSE;
}

static gboolean decode_GetProcParameterRes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *messagebodytree_list, guint *offset){
	proto_item *treepath = NULL;
	proto_item *parameterTree =NULL;

	proto_tree *treepath_list = NULL;
	proto_tree *parameterTree_list = NULL;

	guint i = 0;
	guint repeat = 0;
	guint data = 0;
	guint length = 0;

	/*ServerID*/
	field_serverId(tvb, messagebodytree_list, offset, &data, &length);

	/*Treepath List*/
	get_length(tvb, offset, &data, &length);
	repeat = (data+length);
	treepath = proto_tree_add_text (messagebodytree_list, tvb, *offset, -1, "parameterTreePath with %d %s", length+data, plurality(length+data, "element", "elements"));
	treepath_list = proto_item_add_subtree(treepath, ett_sml_treepath);

	if ((tvb_get_guint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_guint8(tvb,*offset) & 0xF0) != SHORT_LIST){
		expert_add_info_format(pinfo, treepath, &ei_sml_invalid_count, "invalid count of elements in ParameterTreePath");
		return TRUE;
	}
	else if (repeat <= 0){
		expert_add_info_format(pinfo, treepath, &ei_sml_invalid_count, "invalid loop count");
		return TRUE;
	}

	*offset+=length;

	for (i=0; i< repeat; i++) {
		field_parameterTreePath(tvb, treepath_list, offset, &data, &length);
	}
	proto_item_set_end(treepath, tvb, *offset);

	/*parameterTree*/
	get_length(tvb, offset, &data, &length);
	parameterTree = proto_tree_add_text(messagebodytree_list, tvb, *offset, -1, "parameterTree with %d %s", length+data, plurality(length+data, "element", "elements"));
	parameterTree_list = proto_item_add_subtree(parameterTree, ett_sml_parameterTree);

	if ((tvb_get_guint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_guint8(tvb,*offset) & 0xF0) != SHORT_LIST){
		expert_add_info_format(pinfo, parameterTree, &ei_sml_invalid_count, "invalid count of elements in parameterTree");
		return TRUE;
	}

	*offset+=length;

	child_tree(tvb, pinfo,parameterTree_list, offset, &data, &length);
	proto_item_set_end(parameterTree, tvb, *offset);

	return FALSE;
}

static gboolean decode_SetProcParameterReq(tvbuff_t *tvb, packet_info *pinfo,proto_tree *messagebodytree_list, guint *offset){
	proto_item *treepath = NULL;
	proto_item *parameterTree = NULL;

	proto_tree *treepath_list = NULL;
	proto_tree *parameterTree_list = NULL;

	guint i = 0;
	guint repeat = 0;
	guint data = 0;
	guint length = 0;

	/*ServerID*/
	field_serverId(tvb, messagebodytree_list, offset, &data, &length);

	/*user*/
	field_username(tvb, messagebodytree_list, offset, &data, &length);

	/*password*/
	field_password(tvb, messagebodytree_list, offset, &data, &length);

	/*Treepath List*/
	get_length(tvb, offset, &data, &length);
	repeat = (data+length);
	treepath = proto_tree_add_text (messagebodytree_list, tvb, *offset, -1, "parameterTreePath with %d %s", length+data, plurality(length+data, "element", "elements"));
	treepath_list = proto_item_add_subtree(treepath, ett_sml_treepath);

	if ((tvb_get_guint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_guint8(tvb,*offset) & 0xF0) != SHORT_LIST){
		expert_add_info_format(pinfo, treepath, &ei_sml_invalid_count, "invalid count of elements in ParameterTreePath");
		return TRUE;
	}
	else if (repeat <= 0){
		expert_add_info_format(pinfo, treepath, &ei_sml_invalid_count, "invalid loop count");
		return TRUE;
	}

	*offset+=length;

	for (i=0; i< repeat; i++) {
		field_parameterTreePath(tvb, treepath_list, offset, &data, &length);
	}
	proto_item_set_end(treepath, tvb, *offset);

	/*parameterTree*/
	get_length(tvb, offset, &data, &length);
	parameterTree = proto_tree_add_text(messagebodytree_list, tvb, *offset, -1, "parameterTree with %d %s", length+data, plurality(length+data, "element", "elements"));
	parameterTree_list = proto_item_add_subtree(parameterTree, ett_sml_parameterTree);

	if ((tvb_get_guint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_guint8(tvb,*offset) & 0xF0) != SHORT_LIST){
		expert_add_info_format(pinfo, parameterTree, &ei_sml_invalid_count, "invalid count of elements in parameterTree");
		return TRUE;
	}

	*offset+=length;

	child_tree(tvb, pinfo,parameterTree_list, offset, &data, &length);
	proto_item_set_end(parameterTree, tvb, *offset);

	return FALSE;
}

static gboolean decode_AttentionRes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *messagebodytree_list, guint *offset){
	proto_item *attentionNo = NULL;
	proto_item *attentionMsg = NULL;
	proto_item *attentionDetails = NULL;

	proto_tree *attentionNo_tree = NULL;
	proto_tree *attentionMsg_tree = NULL;
	proto_tree *attentionDetails_list = NULL;

	guint data = 0;
	guint length = 0;

	/*ServerID*/
	field_serverId(tvb, messagebodytree_list, offset, &data, &length);

	/*attention NO*/
	get_length(tvb, offset, &data, &length);
	attentionNo = proto_tree_add_text (messagebodytree_list, tvb ,*offset, length+data, "attentionNo");
	attentionNo_tree = proto_item_add_subtree (attentionNo, ett_sml_attentionNo);
	proto_tree_add_text (attentionNo_tree, tvb, *offset, length, "Length: %d %s", data ,plurality(data, "octet", "octets"));
	*offset+=length;

	if (data == 6){
		*offset+=4;
		proto_tree_add_item (attentionNo_tree, hf_sml_attentionNo, tvb, *offset, 2, ENC_BIG_ENDIAN);
		*offset+=2;
	}
	else {
		proto_tree_add_text (attentionNo_tree, tvb ,*offset, data, "unknown attentionNo");
		*offset+=data;
	}

	/*attention Msg*/
	get_length(tvb, offset, &data, &length);
	attentionMsg = proto_tree_add_string_format (messagebodytree_list, hf_sml_attentionMsg, tvb, *offset, length+data, NULL, "attentionMsg %s", (data == 0)? ": NOT SET" : "");

	if (data > 0){
		attentionMsg_tree = proto_item_add_subtree (attentionMsg, ett_sml_attentionMsg);
		proto_tree_add_text (attentionMsg_tree, tvb, *offset, length, "Length: %d %s", data, plurality(data, "octet", "octets"));
		*offset+=length;
		proto_tree_add_item (attentionMsg_tree, hf_sml_attentionMsg, tvb, *offset, data, ENC_ASCII | ENC_BIG_ENDIAN);
		*offset+=data;
	}
	else
		*offset+=1;

	/*attentiondetails*/
	if (tvb_get_guint8(tvb,*offset) == OPTIONAL){
		proto_tree_add_text (messagebodytree_list, tvb, *offset, 1, "attentionDetails: NOT SET");
		*offset+=1;
	}
	else{
		get_length(tvb, offset, &data, &length);
		attentionDetails = proto_tree_add_text(messagebodytree_list, tvb, *offset, -1, "attentionDetails with %d %s", length+data, plurality(length+data, "element", "elements"));
		attentionDetails_list = proto_item_add_subtree(attentionDetails, ett_sml_attentionDetails);

		if ((tvb_get_guint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_guint8(tvb,*offset) & 0xF0) != SHORT_LIST){
			expert_add_info_format(pinfo, attentionDetails, &ei_sml_invalid_count, "invalid count of elements in attentionDetails");
			return TRUE;
		}

		*offset+=length;

		child_tree(tvb, pinfo,attentionDetails_list, offset, &data, &length);
		proto_item_set_end(attentionDetails, tvb, *offset);
	}

	return FALSE;
}

/*dissect SML-File*/
static void dissect_sml_file(tvbuff_t *tvb, packet_info *pinfo, gint *offset, proto_tree *sml_tree){
	proto_item *file = NULL;
	proto_item *mainlist = NULL;
	proto_item *trans = NULL;
	proto_item *groupNo = NULL;
	proto_item *abortOnError = NULL;
	proto_item *sublist = NULL;
	proto_item *messagebody = NULL;
	proto_item *crc16 = NULL;
	proto_item *messagebodytree = NULL;
	proto_item *msgend = NULL;

	proto_tree *mainlist_list = NULL;
	proto_tree *trans_tree = NULL;
	proto_tree *groupNo_tree = NULL;
	proto_tree *abortOnError_tree = NULL;
	proto_tree *sublist_list = NULL;
	proto_tree *messagebody_tree = NULL;
	proto_tree *crc16_tree = NULL;
	proto_tree *messagebodytree_list = NULL;
	proto_tree *msgend_tree = NULL;

	guint16 messagebody_switch = 0;
	guint16 crc_check = 0;
	guint16 crc_ref = 0;
	guint check = 0;

	guint available = 0;
	guint crc_msg_len = 0;
	guint crc_file_len = 0;
	guint data = 0;
	guint length = 0;

	gboolean msg_error = FALSE;
	gboolean close1 = FALSE;
	gboolean close2 = FALSE;
	gint end_offset = 0;

	guint start_offset;
	start_offset = *offset;

	end_offset = tvb_reported_length_remaining(tvb, *offset);
	if (end_offset <= 0){
		return;
	}

	if (tvb_get_ntoh40(tvb, end_offset-8) != ESC_SEQ_END && pinfo->can_desegment){
		if (tvb_get_guint8(tvb, end_offset-1) != 0){
			pinfo->desegment_offset = start_offset;
			pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
			return;
		}
		else if (tvb_get_guint8(tvb, end_offset-4) != UNSIGNED16 && tvb_get_guint8(tvb, end_offset-3) != UNSIGNED8){
			pinfo->desegment_offset = start_offset;
			pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
			return;
		}
	}
	else if (!pinfo->can_desegment){
		expert_add_info(pinfo, NULL, &ei_sml_segment_needed);
	}

	while(!close1 && !close2){
		if (sml_reassemble){
			file = proto_tree_add_text(sml_tree,tvb, *offset, -1 , "----SML-File----");
		}

		/*check if escape*/
		if (tvb_get_ntohl(tvb, *offset) == ESC_SEQ){
			crc_file_len = *offset;
			/*Escape Start*/
			proto_tree_add_item (sml_tree, hf_sml_esc, tvb, *offset, 4, ENC_BIG_ENDIAN);
			*offset+=4;

			/*Version*/
			if (tvb_get_guint8(tvb, *offset) == 0x01){
				proto_tree_add_item (sml_tree, hf_sml_version_1, tvb, *offset, 4, ENC_BIG_ENDIAN);
				*offset+=4;
			}
			else{
				proto_tree_add_text (sml_tree, tvb, *offset, -1, "SML Version 2 not supported");
				return;
			}
		}

		while (!close1){
			crc_msg_len = *offset;

			/*List*/
			get_length(tvb, offset, &data, &length);
			mainlist = proto_tree_add_text (sml_tree, tvb, *offset, -1, "List with %d %s", length+data, plurality(length+data, "element", "elements"));

			mainlist_list = proto_item_add_subtree (mainlist, ett_sml_mainlist);
			if (tvb_get_guint8(tvb, *offset) != LIST_6_ELEMENTS) {
				expert_add_info_format(pinfo, mainlist, &ei_sml_invalid_count, "invalid count of elements");
				return;
			}
			*offset+=1;

			/*Transaction ID*/
			get_length(tvb, offset, &data, &length);
			trans = proto_tree_add_text (mainlist_list, tvb, *offset, length + data ,"Transaction ID");
			trans_tree = proto_item_add_subtree (trans, ett_sml_trans);
			proto_tree_add_text (trans_tree, tvb, *offset, length, "Length: %d %s", data, plurality(data, "octet", "octets"));
			*offset+=length;
			proto_tree_add_item (trans_tree, hf_sml_transactionId, tvb, *offset, data, ENC_NA);
			*offset+=data;

			/*Group No*/
			groupNo = proto_tree_add_text (mainlist_list, tvb, *offset, 2, "Group No");
			groupNo_tree = proto_item_add_subtree (groupNo, ett_sml_group);
			proto_tree_add_item (groupNo_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
			*offset+=1;
			proto_tree_add_item (groupNo_tree, hf_sml_groupNo, tvb, *offset, 1, ENC_NA);
			*offset+=1;

			/*abort on Error*/
			abortOnError = proto_tree_add_text (mainlist_list, tvb, *offset, 2, "Abort on Error");
			abortOnError_tree = proto_item_add_subtree (abortOnError ,ett_sml_abort);
			proto_tree_add_item(abortOnError_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
			*offset+=1;
			proto_tree_add_item(abortOnError_tree, hf_sml_abortOnError, tvb, *offset, 1, ENC_NA);
			*offset+=1;

			/*Sub List*/
			sublist = proto_tree_add_text (mainlist_list, tvb, *offset, -1, "MessageBody");
			sublist_list = proto_item_add_subtree (sublist, ett_sml_sublist);
			*offset+=1;

			/*Zero Cutting Check*/
			get_length(tvb, offset, &data, &length);
			messagebody = proto_tree_add_text (sublist_list, tvb, *offset, length + data, "Messagetype");
			messagebody_tree = proto_item_add_subtree (messagebody , ett_sml_mttree);
			proto_tree_add_item (messagebody_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
			*offset+=1;

			if (data == 4){
				*offset+=2;
			}
			else if (data !=2){
				expert_add_info(pinfo, messagebody, &ei_sml_messagetype_unknown);
				return;
			}

			messagebody_switch = tvb_get_ntohs(tvb, *offset);
			proto_tree_add_item (messagebody_tree, hf_sml_MessageBody, tvb, *offset, 2, ENC_BIG_ENDIAN);
			*offset+=2;

			/*MessageBody List*/
			get_length(tvb, offset, &data, &length);
			messagebodytree = proto_tree_add_text (sublist_list, tvb, *offset, -1, "List with %d %s", length+data, plurality(length+data, "element", "elements"));
			messagebodytree_list = proto_item_add_subtree (messagebodytree, ett_sml_mblist);
			*offset+=length;

			switch (messagebody_switch){
				case OPEN_REQ:
					col_append_str (pinfo->cinfo, COL_INFO, "OpenReq; ");
					proto_item_append_text(mainlist, " [Open Request]");
					decode_PublicOpenReq(tvb, messagebodytree_list, offset);
					break;
				case OPEN_RES:
					col_append_str (pinfo->cinfo, COL_INFO, "OpenRes; ");
					proto_item_append_text(mainlist, " [Open Response]");
					decode_PublicOpenRes(tvb, messagebodytree_list, offset);
					break;
				case CLOSE_REQ:
					col_append_str (pinfo->cinfo, COL_INFO, "CloseReq; ");
					proto_item_append_text(mainlist, " [Close Request]");
					field_globalSignature(tvb, messagebodytree_list, offset, &data, &length);
					break;
				case CLOSE_RES:
					col_append_str (pinfo->cinfo, COL_INFO, "CloseRes; ");
					proto_item_append_text(mainlist, " [Close Response]");
					field_globalSignature(tvb, messagebodytree_list, offset, &data, &length);
					break;
				case PROFILEPACK_REQ:
					col_append_str (pinfo->cinfo, COL_INFO, "GetProfilePackReq; ");
					proto_item_append_text(mainlist, " [GetProfilePack Request]");
					msg_error = decode_GetProfile_List_Pack_Req(tvb, pinfo,messagebodytree_list, offset);
					break;
				case PROFILEPACK_RES:
					col_append_str (pinfo->cinfo, COL_INFO, "GetProfilePackRes; ");
					proto_item_append_text(mainlist, " [GetProfilePack Response]");
					msg_error = decode_GetProfilePackRes(tvb, pinfo,messagebodytree_list, offset);
					break;
				case PROFILELIST_REQ:
					col_append_str (pinfo->cinfo, COL_INFO, "GetProfileListReq; ");
					proto_item_append_text(mainlist, " [GetProfileList Request]");
					msg_error = decode_GetProfile_List_Pack_Req(tvb, pinfo,messagebodytree_list, offset);
					break;
				case PROFILELIST_RES:
					col_append_str (pinfo->cinfo, COL_INFO, "GetProfileListRes; ");
					proto_item_append_text(mainlist, " [GetProfileList Response]");
					msg_error = decode_GetProfileListRes(tvb, pinfo,messagebodytree_list, offset);
					break;
				case GETPROCPARAMETER_REQ:
					col_append_str (pinfo->cinfo, COL_INFO, "GetProcParameterReq; ");
					proto_item_append_text(mainlist, " [GetProcParameter Request]");
					msg_error =  decode_GetProcParameterReq(tvb, pinfo,messagebodytree_list, offset);
					break;
				case GETPROCPARAMETER_RES:
					col_append_str (pinfo->cinfo, COL_INFO, "GetProcParameterRes; ");
					proto_item_append_text(mainlist, " [GetProcParameter Response]");
					msg_error =  decode_GetProcParameterRes(tvb, pinfo,messagebodytree_list, offset);
					break;
				case SETPROCPARAMETER_REQ:
					col_append_str (pinfo->cinfo, COL_INFO, "SetProcParameterReq; ");
					proto_item_append_text(mainlist, " [SetProcParameter Request]");
					msg_error =  decode_SetProcParameterReq(tvb, pinfo,messagebodytree_list, offset);
					break;
				case GETLIST_REQ:
					col_append_str (pinfo->cinfo, COL_INFO, "GetListReq; ");
					proto_item_append_text(mainlist, " [GetList Request]");
					decode_GetListReq(tvb, messagebodytree_list, offset);
					break;
				case GETLIST_RES:
					col_append_str (pinfo->cinfo, COL_INFO, "GetListRes; ");
					proto_item_append_text(mainlist, " [GetList Response]");
					msg_error =  decode_GetListRes(tvb, pinfo,messagebodytree_list, offset);
					break;
				case ATTENTION:
					col_append_str (pinfo->cinfo, COL_INFO, "AttentionRes; ");
					proto_item_append_text(mainlist, " [Attention Response]");
					msg_error =  decode_AttentionRes(tvb, pinfo,messagebodytree_list, offset);
					break;
				default :
					expert_add_info(pinfo, messagebodytree, &ei_sml_messagetype_unknown);
					return;
			}

			if (msg_error){
				expert_add_info(pinfo, messagebodytree, &ei_sml_MessageBody);
				return;
			}

			proto_item_set_end(messagebodytree, tvb, *offset);
			proto_item_set_end(sublist, tvb, *offset);

			/* CRC 16*/
			get_length(tvb, offset, &data, &length);
			crc16 = proto_tree_add_text (mainlist_list, tvb, *offset, data + length, "CRC");
			crc16_tree = proto_item_add_subtree (crc16, ett_sml_crc16);

			if(tvb_get_guint8(tvb, *offset) != UNSIGNED8 && tvb_get_guint8(tvb, *offset) != UNSIGNED16){
				expert_add_info(pinfo, crc16, &ei_sml_crc_error_length);
				return;
			}

			proto_tree_add_item (crc16_tree, hf_sml_datatype, tvb, *offset, 1, ENC_NA);
			*offset+=1;

			proto_tree_add_item (crc16_tree, hf_sml_crc16, tvb, *offset, data, ENC_BIG_ENDIAN);
			*offset+=data;

			if (sml_crc_enabled) {
				crc_msg_len = (*offset - crc_msg_len - data - 1);
				crc_check = crc16_ccitt_tvb_offset(tvb, (*offset - crc_msg_len - data - 1), crc_msg_len);
				crc_ref = tvb_get_letohs(tvb, *offset-2);

				if (data == 1){
					crc_ref = crc_ref & 0xFF00;
				}

				if (crc_check == crc_ref) {
					proto_tree_add_text (crc16_tree, tvb, *offset, 0, "[CRC Okay]");
				}
				else {
					/*(little to big endian convert) to display in correct order*/
					crc_check = ((crc_check >> 8) & 0xFF) + ((crc_check << 8 & 0xFF00));
					proto_tree_add_text (crc16_tree, tvb, *offset, 0, "[CRC Bad 0x%X]", crc_check);
					expert_add_info(pinfo, crc16, &ei_sml_crc_error);
				}
			}
			else {
				proto_tree_add_text (crc16_tree, tvb, *offset, 0, "[CRC validation disabled]");
			}

			/*Message END*/
			if (tvb_get_guint8 (tvb, *offset) == 0){
				proto_tree_add_item (mainlist_list, hf_sml_endOfSmlMsg, tvb, *offset, 1, ENC_BIG_ENDIAN);
				*offset+=1;
			}
			else {
				expert_add_info(pinfo, NULL, &ei_sml_endOfSmlMsg);
				return;
			}

			proto_item_set_end(mainlist, tvb, *offset);

			if (tvb_reported_length_remaining(tvb, *offset) > 0){
				check = tvb_get_guint8(tvb, *offset);

				if (check == LIST_6_ELEMENTS){
					close1 = FALSE;
				}
				else if (check == 0x1b || check == 0){
					close1 = TRUE;
				}
			}
			else if (sml_reassemble && pinfo->can_desegment){
				pinfo->desegment_offset = start_offset;
				pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
				return;
			}
			else
				return;
		}

		/*Padding*/
		if (check == 0){
			length = 1;
			*offset+=1;

			while (tvb_get_guint8(tvb, *offset) == 0){
				length++;
				*offset+=1;
			}
			*offset-=length;

			proto_tree_add_item (sml_tree, hf_sml_padding, tvb, *offset, length, ENC_NA);
			*offset+=length;
		}

		/*Escape End*/
		if(tvb_get_ntoh40(tvb, *offset) != ESC_SEQ_END){
			expert_add_info(pinfo, NULL, &ei_sml_esc_error);
			return;
		}
		proto_tree_add_item (sml_tree, hf_sml_esc, tvb, *offset, 4, ENC_BIG_ENDIAN);
		*offset+=4;

		/*MSG END*/
		msgend = proto_tree_add_item (sml_tree, hf_sml_end, tvb, *offset, 4, ENC_BIG_ENDIAN);
		msgend_tree = proto_item_add_subtree (msgend, ett_sml_msgend);
		*offset+=1;
		proto_tree_add_item (msgend_tree, hf_sml_padding, tvb, *offset, 1, ENC_NA);
		*offset+=1;
		proto_tree_add_item (msgend_tree, hf_sml_crc16, tvb, *offset, 2, ENC_BIG_ENDIAN);
		*offset+=2;

		if (sml_crc_enabled && sml_reassemble){
			crc_file_len = *offset - crc_file_len - 2;
			crc_check = crc16_ccitt_tvb_offset(tvb,*offset-crc_file_len-2, crc_file_len);
			crc_ref = tvb_get_letohs(tvb, *offset-2);

			if (crc_check == crc_ref){
				proto_tree_add_text (msgend_tree, tvb, *offset, 0, "[CRC Okay]");
			}
			else{
				/*(little to big endian convert) to display in correct order*/
				crc_check = ((crc_check >> 8) & 0xFF) + ((crc_check << 8) & 0xFF00);
				proto_tree_add_text (msgend_tree, tvb, *offset, 0, "[CRC Bad 0x%X]", crc_check);
				expert_add_info_format(pinfo, msgend, &ei_sml_crc_error, "CRC error (messages not reassembled ?)");
			}
		}
		else {
			proto_tree_add_text (msgend_tree, tvb, *offset, 0, "[CRC validation disabled]");
		}

		available = tvb_reported_length_remaining(tvb, *offset);
		if (available <= 0){
			close2 = TRUE;
		}
		else {
			if (sml_reassemble){
				proto_item_set_end(file, tvb, *offset);
			}
			else {
				proto_tree_add_text(sml_tree,tvb, *offset, 0 , "---New SML File---");
			}
			close1 = FALSE;
		}
	}
}

/* main */
static void dissect_sml (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	proto_item *sml_item = NULL;
	proto_tree *sml_tree = NULL;

	guint offset = 0;

	/*Check if not SML*/
	if (tvb_get_ntohl(tvb, offset) != ESC_SEQ && tvb_get_guint8(tvb, offset) != LIST_6_ELEMENTS){
		return;
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SML");
	col_clear(pinfo->cinfo,COL_INFO);

	/* create display subtree for the protocol */
	sml_item = proto_tree_add_item(tree, proto_sml, tvb, 0, -1, ENC_NA);
	sml_tree = proto_item_add_subtree(sml_item, ett_sml);
	dissect_sml_file(tvb, pinfo, &offset, sml_tree);
}

void proto_register_sml (void) {
	module_t *sml_module;
	expert_module_t* expert_sml;

	static hf_register_info hf[] = {
		{ &hf_sml_esc,
			{ "Escape", "sml.esc", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_version_1,
			{ "Version 1", "sml.version_1", FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_smlVersion,
			{ "SML Version", "sml.version", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_crc16,
			{ "CRC16", "sml.crc", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_endOfSmlMsg,
			{ "End of SML Msg", "sml.end", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_transactionId,
			{ "Transaction ID", "sml.transactionid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_groupNo,
			{ "GroupNo", "sml.groupno", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_datatype,
			{ "Datatype", "sml.datatype", FT_UINT8, BASE_HEX, VALS (datatype), 0x0, NULL, HFILL }},
		{ &hf_sml_abortOnError,
			{ "Abort On Error", "sml.abort", FT_UINT8, BASE_HEX, VALS (sml_abort), 0x0, NULL, HFILL }},
		{ &hf_sml_MessageBody,
			{ "Messagebody", "sml.messagebody", FT_UINT16, BASE_HEX, VALS (sml_body), 0x0, NULL, HFILL }},
		{ &hf_sml_end,
			{ "End of Msg", "sml.end", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_codepage,
			{ "Codepage", "sml.codepage", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_clientId,
			{ "Client ID", "sml.clientid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_reqFileId,
			{ "reqFile ID", "sml.reqfileid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_serverId,
			{ "server ID", "sml.serverid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_username,
			{ "Username", "sml.username", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_password,
			{ "Password", "sml.password", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_listName,
			{ "List Name", "sml.listname", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_globalSignature,
			{ "Global Signature", "sml.globalsignature", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_refTime,
			{ "refTime", "sml.reftime", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_actSensorTime,
			{ "actSensorTime", "sml.actsensortime", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_timetype,
			{ "Time type", "sml.timetype", FT_UINT8, BASE_HEX, VALS (sml_timetypes), 0x0, NULL, HFILL }},
		{ &hf_sml_objName,
			{ "objName", "sml.objname", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_status,
			{ "Status", "sml.status", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_valTime,
			{ "valTime", "sml.valtime", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_unit,
			{ "unit", "sml.unit", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_scaler,
			{ "scaler", "sml.scaler", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_value,
			{ "value", "sml.value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_valueSignature,
			{ "ValueSignature", "sml.valuesignature", FT_BYTES, BASE_NONE, NULL, 0x0,NULL, HFILL }},
		{ &hf_sml_listSignature,
			{ "ListSignature", "sml.listsignature", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_actGatewayTime,
			{ "actGatewayTime", "sml.gatewaytime", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_parameterTreePath,
			{ "path_Entry", "sml.parametertreepath", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_attribute,
			{ "attribute", "sml.attribute", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_parameterName,
			{ "parameterName", "sml.parametername", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_procParValue,
			{ "procParValue", "sml.procparvalue", FT_UINT8, BASE_HEX, VALS(procvalues), 0x0, NULL, HFILL }},
		{ &hf_sml_procParValueTime,
			{ "procParValueTime", "sml.procparvaluetime", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_padding,
			{ "Padding", "sml.padding", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_secIndex,
			{ "secIndex", "sml.secindex", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_attentionNo,
			{ "attentionNo", "sml.attentionno", FT_UINT16, BASE_HEX|BASE_RANGE_STRING, RVALS(attentionValues), 0x0, NULL, HFILL }},
		{ &hf_sml_attentionMsg,
			{ "attentionMsg", "sml.attentionmsg", FT_STRING, BASE_NONE, NULL, 0x0 , NULL, HFILL }},
		{ &hf_sml_withRawdata,
			{ "withRawdata", "sml.withrawdata", FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(bools), 0x0 , NULL, HFILL }},
		{ &hf_sml_beginTime,
			{ "beginTime", "sml.begintime", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_endTime,
			{ "endTime", "sml.endtime", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_actTime,
			{ "endTime", "sml.acttime", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_object_list_Entry,
			{ "object_list_Entry", "sml.objectentry", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_regPeriod,
			{ "regPeriod", "sml.regperiod", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_rawdata,
			{ "rawdata", "sml.rawdata", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_periodSignature,
			{ "periodSignature", "sml.periodsignature", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_profileSignature,
			{ "profileSignature", "sml.profilesignature", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_signature_mA_R2_R3,
			{ "signature_mA_R2_R3", "sml.signaturema", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_signature_pA_R1_R4,
			{ "signature_pA_R1_R4", "sml.signaturepa", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_unit_mA,
			{ "unit_mA", "sml.unitmA", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_unit_pA,
			{ "unit_pA", "sml.unitpA", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_unit_R1,
			{ "unit_R1", "sml.unitR1", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_unit_R2,
			{ "unit_R2", "sml.unitR2", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_unit_R3,
			{ "unit_R3", "sml.unitR3", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_unit_R4,
			{ "unit_R4", "sml.unitR4", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_scaler_mA,
			{ "scaler_mA", "sml.scalermA", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_scaler_pA,
			{ "scaler_pA", "sml.scalerpA", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_scaler_R1,
			{ "scaler_R1", "sml.scalerR1", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_scaler_R2,
			{ "scaler_R2", "sml.scalerR2", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_scaler_R3,
			{ "scaler_R3", "sml.scalerR3", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_scaler_R4,
			{ "scaler_R4", "sml.scalerR4", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_value_mA,
			{ "value_mA", "sml.valuemA", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_value_pA,
			{ "value_pA", "sml.valuepA", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_value_R1,
			{ "value_R1", "sml.valueR1", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_value_R2,
			{ "value_R2", "sml.valueR2", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_value_R3,
			{ "value_R3", "sml.valueR3", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_value_R4,
			{ "value_R4", "sml.valueR4", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_sml,
		&ett_sml_mainlist,
		&ett_sml_version,
		&ett_sml_sublist,
		&ett_sml_trans,
		&ett_sml_group,
		&ett_sml_abort,
		&ett_sml_body,
		&ett_sml_mblist,
		&ett_sml_mttree,
		&ett_sml_clientId,
		&ett_sml_codepage,
		&ett_sml_reqFileId,
		&ett_sml_serverId,
		&ett_sml_username,
		&ett_sml_password,
		&ett_sml_smlVersion,
		&ett_sml_crc16,
		&ett_sml_listName,
		&ett_sml_globalSignature,
		&ett_sml_refTime,
		&ett_sml_actSensorTime,
		&ett_sml_timetype,
		&ett_sml_time,
		&ett_sml_valList,
		&ett_sml_objName,
		&ett_sml_listEntry,
		&ett_sml_status,
		&ett_sml_valTime,
		&ett_sml_unit,
		&ett_sml_scaler,
		&ett_sml_value,
		&ett_sml_valueSignature,
		&ett_sml_valtree,
		&ett_sml_listSignature,
		&ett_sml_actGatewayTime,
		&ett_sml_treepath,
		&ett_sml_parameterTreePath,
		&ett_sml_attribute,
		&ett_sml_parameterTree,
		&ett_sml_parameterName,
		&ett_sml_child,
		&ett_sml_periodEntry,
		&ett_sml_procParValueTime,
		&ett_sml_procParValuetype,
		&ett_sml_procParValue,
		&ett_sml_msgend,
		&ett_sml_tupel,
		&ett_sml_secIndex,
		&ett_sml_signature,
		&ett_sml_attentionNo,
		&ett_sml_attentionMsg,
		&ett_sml_withRawdata,
		&ett_sml_beginTime,
		&ett_sml_endTime,
		&ett_sml_object_list,
		&ett_sml_object_list_Entry,
		&ett_sml_actTime,
		&ett_sml_regPeriod,
		&ett_sml_rawdata,
		&ett_sml_periodSignature,
		&ett_sml_period_List_Entry,
		&ett_sml_periodList,
		&ett_sml_header_List_Entry,
		&ett_sml_profileSignature,
		&ett_sml_valuelist,
		&ett_sml_headerList,
		&ett_sml_value_List_Entry,
		&ett_sml_signature_mA_R2_R3,
		&ett_sml_signature_pA_R1_R4,
		&ett_sml_unit_mA,
		&ett_sml_scaler_mA,
		&ett_sml_value_mA,
		&ett_sml_unit_pA,
		&ett_sml_scaler_pA,
		&ett_sml_value_pA,
		&ett_sml_unit_R1,
		&ett_sml_scaler_R1,
		&ett_sml_value_R1,
		&ett_sml_unit_R2,
		&ett_sml_scaler_R2,
		&ett_sml_value_R2,
		&ett_sml_unit_R3,
		&ett_sml_scaler_R3,
		&ett_sml_value_R3,
		&ett_sml_unit_R4,
		&ett_sml_scaler_R4,
		&ett_sml_value_R4,
		&ett_sml_tree_Entry,
		&ett_sml_dasDetails,
		&ett_sml_attentionDetails
	};

	static ei_register_info ei[] = {
		{ &ei_sml_tupel_error, { "sml.tupel_error_", PI_PROTOCOL, PI_ERROR, "error in Tupel", EXPFILL }},
		{ &ei_sml_procParValue_invalid, { "sml.procparvalue.invalid", PI_PROTOCOL, PI_WARN, "invalid procParValue", EXPFILL }},
		{ &ei_sml_procParValue_errror, { "sml.procparvalue.error", PI_PROTOCOL, PI_ERROR, "error in procParValue", EXPFILL }},
		{ &ei_sml_invalid_count, { "sml.invalid_count", PI_PROTOCOL, PI_ERROR, "invalid loop count", EXPFILL }},
		{ &ei_sml_segment_needed, { "sml.segment_needed", PI_REASSEMBLE, PI_NOTE, "probably segment needed", EXPFILL }},
		{ &ei_sml_messagetype_unknown, { "sml.messagetype.unknown", PI_PROTOCOL, PI_ERROR, "unknown Messagetype", EXPFILL }},
		{ &ei_sml_MessageBody, { "sml.messagebody.error", PI_PROTOCOL, PI_ERROR, "Error in MessageBody", EXPFILL }},
		{ &ei_sml_crc_error_length, { "sml.crc.length_error", PI_PROTOCOL, PI_ERROR, "CRC length error", EXPFILL }},
		{ &ei_sml_crc_error, { "sml.crc.error", PI_CHECKSUM, PI_WARN, "CRC error", EXPFILL }},
		{ &ei_sml_endOfSmlMsg, { "sml.end.not_zero", PI_PROTOCOL, PI_ERROR, "MsgEnd not 0x00", EXPFILL }},
		{ &ei_sml_esc_error, { "sml.esc.error", PI_PROTOCOL, PI_ERROR, "escapesequence error", EXPFILL }},
	};

	proto_sml = proto_register_protocol("Smart Message Language","SML", "sml");
	sml_module = prefs_register_protocol(proto_sml, proto_reg_handoff_sml);

	prefs_register_bool_preference (sml_module, "reassemble", "Enable reassemble", "Enable reassembling (default is enabled)", &sml_reassemble);
	prefs_register_bool_preference (sml_module, "crc", "Enable crc calculation", "Enable crc (default is disabled)", &sml_crc_enabled);
	prefs_register_uint_preference(sml_module, "tcp.port", "SML TCP Port", "Set the TCP port for SML (Default is 0), recommended port is 7259", 10, &tcp_port_pref);
	prefs_register_uint_preference(sml_module, "udp.port", "SML UDP Port", "Set the UDP port for SML (Default is 0), recommended port is 7259", 10, &udp_port_pref);

	proto_register_field_array(proto_sml, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_sml = expert_register_protocol(proto_sml);
	expert_register_field_array(expert_sml, ei, array_length(ei));
}

void proto_reg_handoff_sml(void) {
	static gboolean initialized = FALSE;
	static int old_tcp_port;
	static int old_udp_port;
	static dissector_handle_t sml_handle;

	if (!initialized) {
		sml_handle = create_dissector_handle(dissect_sml, proto_sml);
		initialized = TRUE;
	} else {
		dissector_delete_uint("tcp.port", old_tcp_port, sml_handle);
		dissector_delete_uint("udp.port", old_udp_port, sml_handle);
	}
	old_tcp_port = tcp_port_pref;
	old_udp_port = udp_port_pref;

	dissector_add_uint("tcp.port", tcp_port_pref, sml_handle);
	dissector_add_uint("udp.port", udp_port_pref, sml_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
