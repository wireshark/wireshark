/* packet-sml.c
 * Routines for SML dissection
 * Copyright 2013, Alexander Gaertner <gaertner.alex@gmx.de>
 *
 * Enhancements for SML 1.05 dissection
 * Copyright 2022, Uwe Heuert <uwe.heuert@exceeding-solutions.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
SML dissector is based on v1.03 (12.11.2008) specifications of "smart message language" protocol

Link to specifications: http://www.vde.com/de/fnn/arbeitsgebiete/messwesen/Sym2/infomaterial/seiten/sml-spezifikation.aspx

Short description of the SML protocol on the SML Wireshark Wiki page:
    https://gitlab.com/wireshark/wireshark/-/wikis/SML
*/

#include "config.h"
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/crc16-tvb.h>
#include <epan/expert.h>

#include <wsutil/str_util.h>

#define ESC_SEQ_END		UINT64_C(0x1b1b1b1b1a)
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
#define	PROC_TUPLE		0x03
#define PROC_TIME		0x04
#define PROC_LISTENTRY	0x05

#define TIME_SECINDEX				0x01
#define	TIME_TIMESTAMP				0x02
#define	TIME_LOCALTIMESTAMP			0x03

#define LISTTYPE_TIME				0x01
#define	LISTTYPE_TIMESTAMPEDVALUE	0x02
#define	LISTTYPE_COSEMVALUE			0x03

#define COSEMVALUE_SCALER_UNIT		0x01

#define SHORT_LIST		0x70
#define LONG_LIST		0xF0

#define OPTIONAL		0x01

#define UNSIGNED8		0x62
#define UNSIGNED16		0x63

#define LIST_6_ELEMENTS		0x76
#define MSB			0x80

/* Forward declaration we need below (if using proto_reg_handoff as a prefs callback)*/
void proto_register_sml(void);
void proto_reg_handoff_sml(void);

static dissector_handle_t sml_handle;

/* Initialize the protocol and registered fields */
static int proto_sml;

static int hf_sml_esc;
static int hf_sml_version_1;
static int hf_sml_groupNo;
static int hf_sml_transactionId;
static int hf_sml_length;
static int hf_sml_datatype;
static int hf_sml_abortOnError;
static int hf_sml_MessageBody;
static int hf_sml_crc16;
static int hf_sml_crc16_status;
static int hf_sml_endOfSmlMsg;
static int hf_sml_end;
static int hf_sml_codepage;
static int hf_sml_clientId;
static int hf_sml_reqFileId;
static int hf_sml_serverId;
static int hf_sml_username;
static int hf_sml_password;
static int hf_sml_smlVersion;
static int hf_sml_listName;
static int hf_sml_globalSignature;
static int hf_sml_timetype;
static int hf_sml_objName;
static int hf_sml_status;
static int hf_sml_unit;
static int hf_sml_scaler;
static int hf_sml_value;
static int hf_sml_simplevalue;
static int hf_sml_valueSignature;
static int hf_sml_listSignature;
static int hf_sml_parameterTreePath;
static int hf_sml_attribute;
static int hf_sml_parameterName;
static int hf_sml_procParValue;
static int hf_sml_padding;
static int hf_sml_secIndex;
static int hf_sml_timestamp;
static int hf_sml_localOffset;
static int hf_sml_seasonTimeOffset;
static int hf_sml_attentionNo;
static int hf_sml_attentionMsg;
static int hf_sml_withRawdata;
static int hf_sml_object_list_Entry;
static int hf_sml_regPeriod;
static int hf_sml_rawdata;
static int hf_sml_periodSignature;
static int hf_sml_profileSignature;
static int hf_sml_signature_mA_R2_R3;
static int hf_sml_signature_pA_R1_R4;
static int hf_sml_unit_mA;
static int hf_sml_scaler_mA;
static int hf_sml_value_mA;
static int hf_sml_unit_pA;
static int hf_sml_scaler_pA;
static int hf_sml_value_pA;
static int hf_sml_unit_R1;
static int hf_sml_scaler_R1;
static int hf_sml_value_R1;
static int hf_sml_unit_R2;
static int hf_sml_scaler_R2;
static int hf_sml_value_R2;
static int hf_sml_unit_R3;
static int hf_sml_scaler_R3;
static int hf_sml_value_R3;
static int hf_sml_unit_R4;
static int hf_sml_scaler_R4;
static int hf_sml_value_R4;
static int hf_sml_file_marker;
static int hf_sml_new_file_marker;
static int hf_sml_listtype;
static int hf_sml_cosemvalue;

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
	{0x72, "ListType" },
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
	{OPEN_REQ,	       "PublicOpen.Req"},
	{OPEN_RES,	       "PublicOpen.Res"},
	{CLOSE_REQ,	       "PublicClose.Req"},
	{CLOSE_RES,	       "PublicClose.Res"},
	{PROFILEPACK_REQ,      "GetProfilePack.Req"},
	{PROFILEPACK_RES,      "GetProfilePack.Res"},
	{PROFILELIST_REQ,      "GetProfileList.Req"},
	{PROFILELIST_RES,      "GetProfileList.Res"},
	{GETPROCPARAMETER_REQ, "GetProcParameter.Req"},
	{GETPROCPARAMETER_RES, "GetProcParameter.Res"},
	{SETPROCPARAMETER_REQ, "SetProcParameter.Req"},
	{GETLIST_REQ,	       "GetList.Req"},
	{GETLIST_RES,	       "GetList.Res"},
	{ATTENTION,	       "Attention.Res"},
	{0, NULL}
};

static const value_string sml_timetypes[]={
	{0x01, "secIndex"},
	{0x02, "timestamp"},
	{0x03, "localTimestamp" },
	{0, NULL}
};

static const value_string procvalues[]={
	{PROC_VALUE,  "Value"},
	{PROC_PERIOD, "PeriodEntry"},
	{PROC_TUPLE,  "TupleEntry"},
	{PROC_TIME,   "Time"},
	{PROC_LISTENTRY, "ListEntry"},
	{0, NULL}
};

static const value_string listtypevalues[] = {
	{ LISTTYPE_TIME, "smlTime" },
	{ LISTTYPE_TIMESTAMPEDVALUE, "smlTimestampedValue" },
	{ LISTTYPE_COSEMVALUE, "smlCosemValue" },
	{ 0, NULL }
};

static const value_string cosemvaluevalues[] = {
	{ COSEMVALUE_SCALER_UNIT, "scaler_unit" },
	{ 0, NULL }
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
static int ett_sml;
static int ett_sml_mainlist;
static int ett_sml_version;
static int ett_sml_sublist;
static int ett_sml_trans;
static int ett_sml_group;
static int ett_sml_abort;
static int ett_sml_body;
static int ett_sml_mblist;
static int ett_sml_mttree;
static int ett_sml_crc16;
static int ett_sml_clientId;
static int ett_sml_codepage;
static int ett_sml_reqFileId;
static int ett_sml_serverId;
static int ett_sml_username;
static int ett_sml_password;
static int ett_sml_smlVersion;
static int ett_sml_listName;
static int ett_sml_globalSignature;
static int ett_sml_refTime;
static int ett_sml_actSensorTime;
static int ett_sml_timetype;
static int ett_sml_time;
static int ett_sml_valList;
static int ett_sml_listEntry;
static int ett_sml_objName;
static int ett_sml_status;
static int ett_sml_valTime;
static int ett_sml_unit;
static int ett_sml_scaler;
static int ett_sml_value;
static int ett_sml_simplevalue;
static int ett_sml_valueSignature;
static int ett_sml_listSignature;
static int ett_sml_valtree;
static int ett_sml_actGatewayTime;
static int ett_sml_treepath;
static int ett_sml_parameterTreePath;
static int ett_sml_attribute;
static int ett_sml_parameterTree;
static int ett_sml_parameterName;
static int ett_sml_child;
static int ett_sml_periodEntry;
static int ett_sml_procParValue;
static int ett_sml_procParValueTime;
static int ett_sml_procParValuetype;
static int ett_sml_msgend;
static int ett_sml_tuple;
static int ett_sml_secIndex;
static int ett_sml_timestamp;
static int ett_sml_localTimestamp;
static int ett_sml_localOffset;
static int ett_sml_seasonTimeOffset;
static int ett_sml_signature;
static int ett_sml_attentionNo;
static int ett_sml_attentionMsg;
static int ett_sml_withRawdata;
static int ett_sml_beginTime;
static int ett_sml_endTime;
static int ett_sml_object_list;
static int ett_sml_object_list_Entry;
static int ett_sml_actTime;
static int ett_sml_regPeriod;
static int ett_sml_rawdata;
static int ett_sml_periodSignature;
static int ett_sml_period_List_Entry;
static int ett_sml_periodList;
static int ett_sml_headerList;
static int ett_sml_header_List_Entry;
static int ett_sml_profileSignature;
static int ett_sml_valuelist;
static int ett_sml_value_List_Entry;
static int ett_sml_signature_mA_R2_R3;
static int ett_sml_signature_pA_R1_R4;
static int ett_sml_unit_mA;
static int ett_sml_scaler_mA;
static int ett_sml_value_mA;
static int ett_sml_unit_pA;
static int ett_sml_scaler_pA;
static int ett_sml_value_pA;
static int ett_sml_unit_R1;
static int ett_sml_scaler_R1;
static int ett_sml_value_R1;
static int ett_sml_unit_R2;
static int ett_sml_scaler_R2;
static int ett_sml_value_R2;
static int ett_sml_unit_R3;
static int ett_sml_scaler_R3;
static int ett_sml_value_R3;
static int ett_sml_unit_R4;
static int ett_sml_scaler_R4;
static int ett_sml_value_R4;
static int ett_sml_tree_Entry;
static int ett_sml_dasDetails;
static int ett_sml_attentionDetails;
static int ett_sml_listtypetype;
static int ett_sml_listtype;
static int ett_sml_timestampedvaluetype;
static int ett_sml_timestampedvalue;
static int ett_sml_cosemvaluetype;
static int ett_sml_cosemvalue;
static int ett_sml_scaler_unit;

static expert_field ei_sml_messagetype_unknown;
static expert_field ei_sml_procParValue_errror;
static expert_field ei_sml_procParValue_invalid;
static expert_field ei_sml_segment_needed;
static expert_field ei_sml_endOfSmlMsg;
static expert_field ei_sml_crc_error;
static expert_field ei_sml_tuple_error;
static expert_field ei_sml_crc_error_length;
static expert_field ei_sml_invalid_count;
static expert_field ei_sml_MessageBody;
static expert_field ei_sml_esc_error;
static expert_field ei_sml_version2_not_supported;
static expert_field ei_sml_attentionNo;
static expert_field ei_sml_listtype_invalid;
static expert_field ei_sml_cosemvalue_invalid;

/*options*/
static bool sml_reassemble = true;
static bool sml_crc_enabled;

/*get number of length octets and calculate how many data octets, it's like BER but not the same! */
static void get_length(tvbuff_t *tvb, unsigned *offset, unsigned *data, unsigned *length){
	unsigned check = 0;
	unsigned temp_offset = 0;

	temp_offset = *offset;
	*data = 0;
	*length = 0;

	check = tvb_get_uint8(tvb, temp_offset);
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
			check = tvb_get_uint8(tvb, temp_offset);
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
static void field_scaler(tvbuff_t *tvb, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length);
static void field_unit(tvbuff_t *tvb, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length);
static void field_status(tvbuff_t *tvb, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length);
static void sml_time_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *SML_time_tree, unsigned *offset);

static void sml_simplevalue(tvbuff_t *tvb, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length){
	proto_item *value = NULL;
	proto_tree *value_tree = NULL;

	get_length(tvb, offset, data, length);
	value = proto_tree_add_bytes_format(insert_tree, hf_sml_simplevalue, tvb, *offset, *length + *data, NULL, "value %s", (*data == 0) ? ": NOT SET" : "");

	if (tvb_get_uint8(tvb, *offset) != OPTIONAL){
		value_tree = proto_item_add_subtree(value, ett_sml_simplevalue);
		if ((tvb_get_uint8(tvb, *offset) & 0x80) == MSB || (tvb_get_uint8(tvb, *offset) & 0xF0) == 0){
			proto_tree_add_uint(value_tree, hf_sml_length, tvb, *offset, *length, *data);
			*offset += *length;
		}
		else {
			proto_tree_add_item(value_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
			*offset += 1;
		}
		proto_tree_add_item(value_tree, hf_sml_simplevalue, tvb, *offset, *data, ENC_NA);
		*offset += *data;
	}
	else
		*offset += 1;
}

static void sml_timestampedvalue_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *timestampedvalue_tree, unsigned *offset){
	proto_tree *SML_timestampedvalue_type_tree;
	proto_tree *SML_time_tree;
	proto_item *SML_time;
	unsigned data = 0;
	unsigned length = 0;

	SML_timestampedvalue_type_tree = proto_tree_add_subtree(timestampedvalue_tree, tvb, *offset, -1, ett_sml_timestampedvaluetype, NULL, "SML_TimestampedValue Type");

	/*smlTime*/
	SML_time_tree = proto_tree_add_subtree(SML_timestampedvalue_type_tree, tvb, *offset, -1, ett_sml_time, &SML_time, "smlTime");
	*offset += 1;
	sml_time_type(tvb, pinfo, SML_time_tree, offset);
	proto_item_set_end(SML_time, tvb, *offset);

	/*status*/
	field_status(tvb, SML_timestampedvalue_type_tree, offset, &data, &length);

	/*simpleValue*/
	sml_simplevalue(tvb, SML_timestampedvalue_type_tree, offset, &data, &length);
}

static void sml_cosem_scaler_unit_type(tvbuff_t *tvb, proto_tree *cosem_scaler_unit_tree, unsigned *offset){
	unsigned data, length;

	/*scaler*/
	get_length(tvb, offset, &data, &length);
	field_scaler(tvb, cosem_scaler_unit_tree, offset, &data, &length);

	/*unit*/
	get_length(tvb, offset, &data, &length);
	field_unit(tvb, cosem_scaler_unit_tree, offset, &data, &length);
}

static void sml_cosemvalue_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *cosemvalue_tree, unsigned *offset){
	unsigned check = 0;
	proto_item *SML_cosem_scaler_unit;
	proto_tree *SML_cosemvalue_type_tree;
	proto_tree *SML_cosem_scaler_unit_tree;

	SML_cosemvalue_type_tree = proto_tree_add_subtree(cosemvalue_tree, tvb, *offset, -1, ett_sml_cosemvaluetype, NULL, "SML_CosemValue Type");

	proto_tree_add_item(SML_cosemvalue_type_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset += 1;
	proto_tree_add_item(SML_cosemvalue_type_tree, hf_sml_cosemvalue, tvb, *offset, 1, ENC_BIG_ENDIAN);

	check = tvb_get_uint8(tvb, *offset);
	*offset += 1;

	switch (check) {
		case COSEMVALUE_SCALER_UNIT:
			/*scaler_unit*/
			SML_cosem_scaler_unit_tree = proto_tree_add_subtree(SML_cosemvalue_type_tree, tvb, *offset, -1, ett_sml_scaler_unit, &SML_cosem_scaler_unit, "CosemScalerUnit");
			*offset += 1;
			sml_cosem_scaler_unit_type(tvb, SML_cosem_scaler_unit_tree, offset);
			break;

		default:
			expert_add_info(pinfo, SML_cosemvalue_type_tree, &ei_sml_cosemvalue_invalid);
			break;
	}
}

static void sml_listtype_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *listtype_tree, unsigned *offset){
	unsigned check = 0;
	proto_tree *SML_listtype_type_tree;
	proto_item *SML_time;
	proto_tree *SML_time_tree = NULL;
	proto_item *SML_timestampedvalue;
	proto_tree *SML_timestampedvalue_tree = NULL;
	proto_item *SML_cosemvalue;
	proto_tree *SML_cosemvalue_tree = NULL;

	SML_listtype_type_tree = proto_tree_add_subtree(listtype_tree, tvb, *offset, -1, ett_sml_listtypetype, NULL, "SML_ListType Type");

	proto_tree_add_item(SML_listtype_type_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset += 1;
	proto_tree_add_item(SML_listtype_type_tree, hf_sml_listtype, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset += 1;

	check = tvb_get_uint8(tvb, *offset);
	*offset += 1;

	switch (check) {
		case LISTTYPE_TIME:
			/*smlTime*/
			SML_time_tree = proto_tree_add_subtree(SML_listtype_type_tree, tvb, *offset, -1, ett_sml_time, &SML_time, "Time");
			*offset += 1;
			sml_time_type(tvb, pinfo, SML_time_tree, offset);
			proto_item_set_end(SML_time, tvb, *offset);
			break;

		case LISTTYPE_TIMESTAMPEDVALUE:
			/*smlTimestampedValue*/
			SML_timestampedvalue_tree = proto_tree_add_subtree(SML_listtype_type_tree, tvb, *offset, -1, ett_sml_timestampedvalue, &SML_timestampedvalue, "TimestampedValue");
			*offset += 1;
			sml_timestampedvalue_type(tvb, pinfo, SML_timestampedvalue_tree, offset);
			proto_item_set_end(SML_timestampedvalue, tvb, *offset);
			break;

		case LISTTYPE_COSEMVALUE:
			/*smlCosemValue*/
			SML_cosemvalue_tree = proto_tree_add_subtree(SML_listtype_type_tree, tvb, *offset, -1, ett_sml_cosemvalue, &SML_cosemvalue, "CosemValue");
			*offset += 1;
			sml_cosemvalue_type(tvb, pinfo, SML_cosemvalue_tree, offset);
			break;

		default:
			expert_add_info(pinfo, SML_listtype_type_tree, &ei_sml_listtype_invalid);
			break;
	}
}

static void sml_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length){
	proto_item *value = NULL;
	proto_tree *value_tree = NULL;

	get_length(tvb, offset, data, length);
	value = proto_tree_add_bytes_format (insert_tree, hf_sml_value, tvb, *offset, *length + *data, NULL,"value %s", (*data == 0)? ": NOT SET" : "");

	if (tvb_get_uint8(tvb, *offset) != OPTIONAL){
		value_tree = proto_item_add_subtree (value, ett_sml_value);
		if (tvb_get_uint8(tvb, *offset) == 0x72) {
			sml_listtype_type(tvb, pinfo, value_tree, offset);
		}
		else
		{
			if ((tvb_get_uint8(tvb, *offset) & 0x80) == MSB || (tvb_get_uint8(tvb, *offset) & 0xF0) == 0){
				proto_tree_add_uint(value_tree, hf_sml_length, tvb, *offset, *length, *data);
				*offset+= *length;
			}
			else {
				proto_tree_add_item (value_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
				*offset+=1;
			}
			proto_tree_add_item (value_tree, hf_sml_value, tvb, *offset, *data, ENC_NA);
			*offset+= *data;
		}
	}
	else
		*offset+=1;
}

static void sml_time_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *SML_time_tree, unsigned *offset){
	unsigned check = 0;
	proto_tree *timetype_tree;
	proto_tree *timevalue_tree;
	proto_tree *localtimestamptype_tree;
	unsigned data = 0;
	unsigned length = 0;

	timetype_tree = proto_tree_add_subtree(SML_time_tree, tvb, *offset, 2, ett_sml_timetype, NULL, "SML-Time Type");

	proto_tree_add_item (timetype_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;
	proto_tree_add_item (timetype_tree, hf_sml_timetype, tvb, *offset, 1, ENC_BIG_ENDIAN);
	//*offset+=1;

	check = tvb_get_uint8(tvb, *offset);
	*offset += 1;

	switch (check) {
		case TIME_SECINDEX:
			/*secIndex*/
			get_length(tvb, offset, &data, &length);
			timevalue_tree = proto_tree_add_subtree(SML_time_tree, tvb, *offset, length + data, ett_sml_secIndex, NULL, "secIndex");
			proto_tree_add_item(timevalue_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
			*offset += 1;
			proto_tree_add_item(timevalue_tree, hf_sml_secIndex, tvb, *offset, data, ENC_BIG_ENDIAN);
			*offset += data;

			break;
		case TIME_TIMESTAMP:
			/*timestamp*/
			get_length(tvb, offset, &data, &length);
			timevalue_tree = proto_tree_add_subtree(SML_time_tree, tvb, *offset, length + data, ett_sml_timestamp, NULL, "timestamp");
			proto_tree_add_item(timevalue_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
			*offset += 1;
			proto_tree_add_item(timevalue_tree, hf_sml_timestamp, tvb, *offset, data, ENC_BIG_ENDIAN);
			*offset += data;

			break;

		case TIME_LOCALTIMESTAMP:
			/*localTimestamp*/
			localtimestamptype_tree = proto_tree_add_subtree(SML_time_tree, tvb, *offset, length + data, ett_sml_localTimestamp, NULL, "localTimestamp");
			*offset += 1;

			get_length(tvb, offset, &data, &length);
			timevalue_tree = proto_tree_add_subtree(localtimestamptype_tree, tvb, *offset, length + data, ett_sml_timestamp, NULL, "timestamp");
			proto_tree_add_item(timevalue_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
			*offset += 1;
			proto_tree_add_item(timevalue_tree, hf_sml_timestamp, tvb, *offset, data, ENC_BIG_ENDIAN);
			*offset += data;

			get_length(tvb, offset, &data, &length);
			timevalue_tree = proto_tree_add_subtree(localtimestamptype_tree, tvb, *offset, length + data, ett_sml_localOffset, NULL, "localOffset");
			proto_tree_add_item(timevalue_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
			*offset += 1;
			proto_tree_add_item(timevalue_tree, hf_sml_localOffset, tvb, *offset, data, ENC_BIG_ENDIAN);
			*offset += data;

			get_length(tvb, offset, &data, &length);
			timevalue_tree = proto_tree_add_subtree(localtimestamptype_tree, tvb, *offset, length + data, ett_sml_seasonTimeOffset, NULL, "seasonTimeOffset");
			proto_tree_add_item(timevalue_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
			*offset += 1;
			proto_tree_add_item(timevalue_tree, hf_sml_seasonTimeOffset, tvb, *offset, data, ENC_BIG_ENDIAN);
			*offset += data;

			break;

		default:
			expert_add_info(pinfo, timetype_tree, &ei_sml_listtype_invalid);
			break;
	}
}

static void field_codepage(tvbuff_t *tvb, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length){
	proto_item *codepage = NULL;
	proto_tree *codepage_tree = NULL;

	get_length(tvb, offset, data, length);
	codepage = proto_tree_add_bytes_format (insert_tree, hf_sml_codepage, tvb, *offset, *length + *data, NULL,"Codepage %s", (*data == 0)? ": NOT SET" : "");

	if (*data > 0) {
		codepage_tree = proto_item_add_subtree (codepage , ett_sml_codepage);
		proto_tree_add_uint(codepage_tree, hf_sml_length, tvb, *offset, *length, *data);
		*offset+= *length;

		proto_tree_add_item (codepage_tree, hf_sml_codepage, tvb, *offset, *data, ENC_NA);
		*offset+= *data;
	}
	else
		*offset+=1;
}

static void field_clientId(tvbuff_t *tvb, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length){
	proto_item *clientId = NULL;
	proto_tree *clientId_tree = NULL;

	get_length(tvb, offset, data, length);
	clientId = proto_tree_add_bytes_format (insert_tree, hf_sml_clientId, tvb, *offset, *length + *data, NULL, "clientID %s", (*data == 0)? ": NOT SET" : "");

	if (*data > 0) {
		clientId_tree = proto_item_add_subtree (clientId, ett_sml_clientId);
		proto_tree_add_uint(clientId_tree, hf_sml_length, tvb, *offset, *length, *data);
		*offset+=*length;
		proto_tree_add_item (clientId_tree, hf_sml_clientId, tvb, *offset, *data, ENC_NA);
		*offset+=*data;
	}
	else
		*offset+=1;
}

static void field_reqFileId(tvbuff_t *tvb, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length){
	proto_tree *reqFileId_tree;

	get_length(tvb, offset, data, length);
	reqFileId_tree = proto_tree_add_subtree(insert_tree, tvb, *offset, *length + *data, ett_sml_reqFileId, NULL, "reqFileId");

	proto_tree_add_uint (reqFileId_tree, hf_sml_length, tvb, *offset, *length, *data);
	*offset+=*length;
	proto_tree_add_item (reqFileId_tree, hf_sml_reqFileId, tvb, *offset, *data, ENC_NA);
	*offset+=*data;
}

static void field_serverId(tvbuff_t *tvb, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length){
	proto_item *serverId = NULL;
	proto_tree *serverId_tree = NULL;

	/*Server ID OPTIONAL*/
	get_length(tvb, offset, data, length);
	serverId = proto_tree_add_bytes_format (insert_tree,hf_sml_serverId, tvb, *offset, *length + *data, NULL, "Server ID %s", (*data == 0)? ": NOT SET" : "");

	if (*data > 0){
		serverId_tree = proto_item_add_subtree (serverId , ett_sml_serverId);
		proto_tree_add_uint (serverId_tree, hf_sml_length, tvb, *offset, *length, *data);
		*offset+=*length;
		proto_tree_add_item (serverId_tree, hf_sml_serverId, tvb, *offset, *data, ENC_NA);
		*offset+=*data;
	}
	else
		*offset+=1;
}

static void field_username(tvbuff_t *tvb, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length){
	proto_item *username = NULL;
	proto_tree *username_tree = NULL;

	/*Username OPTIONAL*/
	get_length(tvb, offset, data, length);
	username = proto_tree_add_string_format (insert_tree,hf_sml_username, tvb, *offset, *length + *data, NULL, "Username %s", (*data == 0)? ": NOT SET" : "");

	if (*data > 0){
		username_tree = proto_item_add_subtree (username , ett_sml_username);
		proto_tree_add_uint (username_tree, hf_sml_length, tvb, *offset, *length, *data);
		*offset+=*length;
		proto_tree_add_item (username_tree, hf_sml_username, tvb, *offset, *data, ENC_ASCII | ENC_BIG_ENDIAN);
		*offset+=*data;
	}
	else
		*offset+=1;
}

static void field_password(tvbuff_t *tvb, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length){
	proto_item *password = NULL;
	proto_tree *password_tree = NULL;

	/*Password OPTIONAL*/
	get_length(tvb, offset, data, length);
	password = proto_tree_add_string_format (insert_tree,hf_sml_password, tvb, *offset, *length + *data, NULL, "Password %s", (*data == 0)? ": NOT SET" : "");

	if (*data > 0) {
		password_tree = proto_item_add_subtree (password, ett_sml_password);
		proto_tree_add_uint (password_tree, hf_sml_length, tvb, *offset, *length, *data);
		*offset+=*length;
		proto_tree_add_item (password_tree, hf_sml_password, tvb, *offset, *data, ENC_ASCII | ENC_BIG_ENDIAN);
		*offset+=*data;
	}
	else
		*offset+=1;
}

static void field_smlVersion(tvbuff_t *tvb, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length){
	proto_item *smlVersion = NULL;
	proto_tree *smlVersion_tree = NULL;

	/*sml-Version OPTIONAL*/
	get_length(tvb, offset, data, length);
	smlVersion = proto_tree_add_uint_format (insert_tree, hf_sml_smlVersion, tvb, *offset, *length + *data, *length + *data, "SML-Version %s", (*data == 0)? ": Version 1" : "");

	if (*data > 0) {
		smlVersion_tree = proto_item_add_subtree (smlVersion, ett_sml_smlVersion);
		proto_tree_add_item (smlVersion_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
		*offset+=1;

		proto_tree_add_item (smlVersion_tree, hf_sml_smlVersion, tvb, *offset, 1,ENC_BIG_ENDIAN);
		*offset+=1;
	}
	else
		*offset+=1;
}

static void field_globalSignature(tvbuff_t *tvb, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length){
	proto_item *globalSignature = NULL;
	proto_tree *globalSignature_tree = NULL;

	/*Global Signature OPTIONAL*/
	get_length(tvb, offset, data, length);

	globalSignature = proto_tree_add_bytes_format (insert_tree, hf_sml_globalSignature, tvb, *offset, *length + *data, NULL, "global Signature %s", (*data == 0)? ": NOT SET" : "");

	if (*data > 0){
		globalSignature_tree = proto_item_add_subtree (globalSignature, ett_sml_globalSignature);
		proto_tree_add_uint (globalSignature_tree, hf_sml_length, tvb, *offset, *length, *data);
		*offset+=*length;
		proto_tree_add_item (globalSignature_tree, hf_sml_globalSignature, tvb, *offset, *data, ENC_NA);
		*offset+=*data;
	}
	else
		*offset+=1;
}

static void field_listName(tvbuff_t *tvb, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length){
	proto_item *listName = NULL;
	proto_tree *listName_tree = NULL;

	/*List Name OPTIONAL*/
	get_length(tvb, offset, data, length);
	listName = proto_tree_add_bytes_format (insert_tree,hf_sml_listName, tvb, *offset, *length + *data, NULL, "List Name %s", (*data == 0)? ": NOT SET" : "");

	if (*data > 0) {
		listName_tree = proto_item_add_subtree (listName, ett_sml_listName);
		proto_tree_add_uint (listName_tree, hf_sml_length, tvb, *offset, *length, *data);
		*offset+=*length;
		proto_tree_add_item (listName_tree, hf_sml_listName, tvb, *offset, *data, ENC_NA);
		*offset+=*data;
	}
	else
		*offset+=1;
}

static void field_objName(tvbuff_t *tvb, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length){
	proto_tree *objName_tree;

	/*Objectname*/
	get_length(tvb, offset, data, length);
	objName_tree = proto_tree_add_subtree(insert_tree, tvb, *offset, *length + *data, ett_sml_objName, NULL, "Objectname");

	proto_tree_add_uint (objName_tree, hf_sml_length, tvb, *offset, *length, *data);
	*offset+=*length;
	proto_tree_add_item (objName_tree, hf_sml_objName, tvb, *offset, *data, ENC_NA);
	*offset+=*data;
}

static void field_status(tvbuff_t *tvb, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length){
	proto_tree *status_tree = NULL;

	get_length(tvb, offset, data, length);
	status_tree = proto_tree_add_subtree_format(insert_tree, tvb, *offset, *length + *data,
						ett_sml_status, NULL, "status %s", (*data == 0)? ": NOT SET" : "");

	if (*data > 0){
		proto_tree_add_item (status_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
		*offset+=1;
		proto_tree_add_item (status_tree, hf_sml_status, tvb, *offset, *data, ENC_BIG_ENDIAN);
		*offset+= *data;
	}
	else
		*offset+=1;
}

static void field_unit(tvbuff_t *tvb, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length){
	proto_item *unit = NULL;
	proto_tree *unit_tree = NULL;

	/*unit OPTIONAL*/
	get_length(tvb, offset, data, length);
	unit = proto_tree_add_uint_format (insert_tree, hf_sml_unit, tvb, *offset, *length + *data, *length + *data, "Unit %s", (*data == 0)? ": NOT SET" : "");
	if (*data > 0) {
		unit_tree = proto_item_add_subtree (unit, ett_sml_unit);
		proto_tree_add_item (unit_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
		*offset+=1;
		proto_tree_add_item(unit_tree, hf_sml_unit, tvb, *offset, 1, ENC_BIG_ENDIAN);
		*offset+=1;
	}
	else
		*offset+=1;
}

static void field_scaler(tvbuff_t *tvb, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length){
	proto_item *scaler = NULL;
	proto_tree *scaler_tree = NULL;

	/*Scaler OPTIONAL*/
	get_length(tvb, offset, data, length);
	scaler = proto_tree_add_uint_format (insert_tree, hf_sml_scaler, tvb, *offset, *length + *data, *length + *data, "Scaler %s", (*data == 0)? ": NOT SET" : "");

	if (*data > 0){
		scaler_tree = proto_item_add_subtree (scaler, ett_sml_scaler);
		proto_tree_add_item (scaler_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
		*offset+=1;
		proto_tree_add_item(scaler_tree, hf_sml_scaler, tvb, *offset, 1, ENC_BIG_ENDIAN);
		*offset+=1;
	}
	else
		*offset+=1;
}

static void field_valueSignature(tvbuff_t *tvb, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length){
	proto_item *valueSignature = NULL;
	proto_tree *valueSignature_tree = NULL;

	/*value Signature*/
	get_length(tvb, offset, data, length);
	valueSignature = proto_tree_add_bytes_format (insert_tree, hf_sml_valueSignature, tvb, *offset, *length + *data, NULL, "ValueSignature %s", (*data == 0)? ": NOT SET" : "");

	if (*data > 0){
		valueSignature_tree = proto_item_add_subtree (valueSignature, ett_sml_valueSignature);
		proto_tree_add_uint (valueSignature_tree, hf_sml_length, tvb, *offset, *length, *data);
		*offset+=*length;
		proto_tree_add_item (valueSignature_tree, hf_sml_valueSignature, tvb, *offset, *data, ENC_NA);
		*offset+=*data;
	}
	else
		*offset+=1;
}

static void field_parameterTreePath(tvbuff_t *tvb, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length){
	proto_item *parameterTreePath = NULL;
	proto_tree *parameterTreePath_tree = NULL;

	/*parameterTreePath*/
	get_length(tvb, offset, data, length);
	parameterTreePath = proto_tree_add_bytes_format (insert_tree, hf_sml_parameterTreePath, tvb, *offset, *length + *data, NULL, "path_Entry %s", (*data == 0)? ": NOT SET" : "");

	parameterTreePath_tree = proto_item_add_subtree (parameterTreePath, ett_sml_parameterTreePath);
	proto_tree_add_uint (parameterTreePath_tree, hf_sml_length, tvb, *offset, *length, *data);
	*offset+=*length;
	proto_tree_add_item (parameterTreePath_tree, hf_sml_parameterTreePath, tvb, *offset, *data, ENC_NA);
	*offset+=*data;
}

static void field_ObjReqEntry(tvbuff_t *tvb, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length){
	proto_tree *object_list_Entry_tree;

	/*parameterTreePath*/
	get_length(tvb, offset, data, length);
	object_list_Entry_tree = proto_tree_add_subtree(insert_tree, tvb ,*offset, *length + *data, ett_sml_object_list_Entry, NULL, "object_list_Entry");
	proto_tree_add_uint (object_list_Entry_tree, hf_sml_length, tvb, *offset, *length, *data);
	*offset+=*length;
	proto_tree_add_item (object_list_Entry_tree, hf_sml_object_list_Entry, tvb, *offset, *data, ENC_NA);
	*offset+=*data;
}

static void field_regPeriod(tvbuff_t *tvb, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length){
	proto_tree *regPeriod_tree;

	get_length(tvb, offset, data, length);
	regPeriod_tree = proto_tree_add_subtree(insert_tree, tvb, *offset, *length + *data, ett_sml_regPeriod, NULL, "regPeriod");

	proto_tree_add_item (regPeriod_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;
	proto_tree_add_item (regPeriod_tree, hf_sml_regPeriod, tvb, *offset, *data, ENC_BIG_ENDIAN);
	*offset+=*data;
}

static void field_rawdata(tvbuff_t *tvb, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length){
	proto_item *rawdata = NULL;
	proto_tree *rawdata_tree = NULL;

	/*rawdata*/
	get_length(tvb, offset, data, length);
	rawdata = proto_tree_add_bytes_format (insert_tree, hf_sml_rawdata, tvb, *offset, *length + *data, NULL, "rawdata %s", (*data == 0)? ": NOT SET" : "");

	if (*data > 0){
		rawdata_tree = proto_item_add_subtree (rawdata, ett_sml_rawdata);
		proto_tree_add_uint (rawdata_tree, hf_sml_length, tvb, *offset, *length, *data);
		*offset+=*length;
		proto_tree_add_item (rawdata_tree, hf_sml_rawdata, tvb, *offset, *data, ENC_NA);
		*offset+=*data;
	}
	else
		*offset+=1;
}

static void field_periodSignature(tvbuff_t *tvb, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length){
	proto_item *periodSignature = NULL;
	proto_tree *periodSignature_tree = NULL;

	/*periodSignature*/
	get_length(tvb, offset, data, length);
	periodSignature = proto_tree_add_bytes_format (insert_tree, hf_sml_periodSignature, tvb, *offset, *length + *data, NULL,"periodSignature %s", (*data == 0)? ": NOT SET" : "");

	if (*data > 0){
		periodSignature_tree = proto_item_add_subtree (periodSignature, ett_sml_periodSignature);
		proto_tree_add_uint (periodSignature_tree, hf_sml_length, tvb, *offset, *length, *data);
		*offset+=*length;
		proto_tree_add_item (periodSignature_tree, hf_sml_periodSignature, tvb, *offset, *data, ENC_NA);
		*offset+=*data;
	}
	else
		*offset+=1;
}
/*
static void field_actTime(tvbuff_t *tvb, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length){
	proto_tree *actTime_tree;

	get_length(tvb, offset, data, length);
	actTime_tree = proto_tree_add_subtree(insert_tree, tvb, *offset, *length + *data, ett_sml_actTime, NULL, "actTime");
	proto_tree_add_item (actTime_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;
	proto_tree_add_item(actTime_tree, hf_sml_actTime, tvb, *offset, *data, ENC_BIG_ENDIAN);
	*offset+=*data;
}

static void field_valTime(tvbuff_t *tvb, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length){
	proto_tree *valTime_tree;

	get_length(tvb, offset, data, length);
	valTime_tree = proto_tree_add_subtree(insert_tree, tvb, *offset, *length + *data, ett_sml_valTime, NULL, "valTime");
	proto_tree_add_item (valTime_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;
	proto_tree_add_item(valTime_tree, hf_sml_valTime, tvb, *offset, *data, ENC_BIG_ENDIAN);
	*offset+=*data;
}
*/
static void TupleEntryTree(tvbuff_t *tvb, packet_info *pinfo, proto_tree *procParValue_tree, unsigned *offset){
	proto_item *SML_time;
	proto_item *TupleEntry;

	proto_tree *TupleEntry_list = NULL;
	proto_tree *SML_time_tree = NULL;
	//proto_tree *secIndex_tree = NULL;
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

	unsigned data = 0;
	unsigned length = 0;

	/*Tuple_List*/
	TupleEntry_list = proto_tree_add_subtree(procParValue_tree, tvb, *offset, -1, ett_sml_tuple, &TupleEntry, "TupleEntry");
	get_length(tvb, offset, &data, &length);
	*offset+=length;

	/*Server Id*/
	field_serverId(tvb, TupleEntry_list, offset, &data, &length);

	/*secindex*/
	SML_time_tree = proto_tree_add_subtree(procParValue_tree, tvb, *offset, -1, ett_sml_time, &SML_time, "secIndex");
	*offset+=1;
	sml_time_type(tvb, pinfo, SML_time_tree, offset);
	proto_item_set_end(SML_time, tvb, *offset);

	/*Sml Status OPTIONAL*/
	field_status(tvb, TupleEntry_list, offset, &data, &length);

	/*unit_pA*/
	unit_pA_tree = proto_tree_add_subtree(TupleEntry_list, tvb, *offset, 2, ett_sml_unit_pA, NULL, "unit_pA");
	proto_tree_add_item (unit_pA_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;
	proto_tree_add_item (unit_pA_tree, hf_sml_unit_pA, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;

	/*scaler_pA*/
	scaler_pA_tree = proto_tree_add_subtree(TupleEntry_list, tvb, *offset, 2, ett_sml_scaler_pA, NULL, "scaler_pA");
	proto_tree_add_item (scaler_pA_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;
	proto_tree_add_item (scaler_pA_tree, hf_sml_scaler_pA, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;

	/*value_pA*/
	get_length(tvb, offset, &data, &length);
	value_pA_tree = proto_tree_add_subtree(TupleEntry_list, tvb, *offset, length+data, ett_sml_value_pA, NULL, "value_pA");
	proto_tree_add_item (value_pA_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;
	proto_tree_add_item (value_pA_tree, hf_sml_value_pA, tvb, *offset, data, ENC_BIG_ENDIAN);
	*offset+=data;

	/*unit_R1*/
	unit_R1_tree = proto_tree_add_subtree(TupleEntry_list, tvb, *offset, 2, ett_sml_unit_R1, NULL, "unit_R1");
	proto_tree_add_item (unit_R1_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;
	proto_tree_add_item (unit_R1_tree, hf_sml_unit_R1, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;

	/*scaler_R1*/
	scaler_R1_tree = proto_tree_add_subtree(TupleEntry_list, tvb, *offset, 1, ett_sml_scaler_R1, NULL, "scaler_R1");
	proto_tree_add_item (scaler_R1_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;
	proto_tree_add_item (scaler_R1_tree, hf_sml_scaler_R1, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;

	/*value_R1*/
	get_length(tvb, offset, &data, &length);
	value_R1_tree = proto_tree_add_subtree(TupleEntry_list, tvb, *offset, length+data, ett_sml_value_R1, NULL, "value_R1");
	proto_tree_add_item (value_R1_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;
	proto_tree_add_item (value_R1_tree, hf_sml_value_R1, tvb, *offset, data, ENC_BIG_ENDIAN);
	*offset+=data;

	/*unit_R4*/
	unit_R4_tree = proto_tree_add_subtree(TupleEntry_list, tvb, *offset, 2, ett_sml_unit_R4, NULL, "unit_R4");
	proto_tree_add_item (unit_R4_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;
	proto_tree_add_item (unit_R4_tree, hf_sml_unit_R4, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;

	/*scaler_R4*/
	scaler_R4_tree = proto_tree_add_subtree(TupleEntry_list, tvb, *offset, 2, ett_sml_scaler_R4, NULL, "scaler_R4");
	proto_tree_add_item (scaler_R4_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;
	proto_tree_add_item (scaler_R4_tree, hf_sml_scaler_R4, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;

	/*value_R4*/
	get_length(tvb, offset, &data, &length);
	value_R4_tree = proto_tree_add_subtree(TupleEntry_list, tvb, *offset, length+data, ett_sml_value_R4, NULL, "value_R4");
	proto_tree_add_item (value_R4_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;
	proto_tree_add_item (value_R4_tree, hf_sml_value_R4, tvb, *offset, data, ENC_BIG_ENDIAN);
	*offset+=data;

	/*signature_pA_R1_R4*/
	get_length(tvb, offset, &data, &length);
	signature_pA_R1_R4_tree = proto_tree_add_subtree(TupleEntry_list, tvb, *offset, length+data, ett_sml_signature_pA_R1_R4, NULL, "signature_pa_R1_R4");
	proto_tree_add_uint (signature_pA_R1_R4_tree, hf_sml_length, tvb, *offset, length, data);
	*offset+=length;
	proto_tree_add_item (signature_pA_R1_R4_tree, hf_sml_signature_pA_R1_R4, tvb, *offset, data, ENC_NA);
	*offset+=data;

	/*unit_mA*/
	unit_mA_tree = proto_tree_add_subtree(TupleEntry_list, tvb, *offset, 2, ett_sml_unit_mA, NULL, "unit_mA");
	proto_tree_add_item (unit_mA_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;
	proto_tree_add_item (unit_mA_tree, hf_sml_unit_mA, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;

	/*scaler_mA*/
	scaler_mA_tree = proto_tree_add_subtree(TupleEntry_list, tvb, *offset, 2, ett_sml_scaler_mA, NULL, "scaler_mA");
	proto_tree_add_item (scaler_mA_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;
	proto_tree_add_item (scaler_mA_tree, hf_sml_scaler_mA, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;

	/*value_mA*/
	get_length(tvb, offset, &data, &length);
	value_mA_tree = proto_tree_add_subtree(TupleEntry_list, tvb, *offset, length+data, ett_sml_value_mA, NULL, "value_mA");
	proto_tree_add_item (value_mA_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;
	proto_tree_add_item (value_mA_tree, hf_sml_value_mA, tvb, *offset, data, ENC_BIG_ENDIAN);
	*offset+=data;

	/*unit_R2*/
	unit_R2_tree = proto_tree_add_subtree(TupleEntry_list, tvb, *offset, 2, ett_sml_unit_R2, NULL, "unit_R2");
	proto_tree_add_item (unit_R2_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;
	proto_tree_add_item (unit_R2_tree, hf_sml_unit_R2, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;

	/*scaler_R2*/
	scaler_R2_tree = proto_tree_add_subtree(TupleEntry_list, tvb, *offset, 2, ett_sml_scaler_R2, NULL, "scaler_R2");
	proto_tree_add_item (scaler_R2_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;
	proto_tree_add_item (scaler_R2_tree, hf_sml_scaler_R2, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;

	/*value_R2*/
	get_length(tvb, offset, &data, &length);
	value_R2_tree = proto_tree_add_subtree(TupleEntry_list, tvb, *offset, length+data, ett_sml_value_R2, NULL, "value_R2");
	proto_tree_add_item (value_R2_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;
	proto_tree_add_item (value_R2_tree, hf_sml_value_R2, tvb, *offset, data, ENC_BIG_ENDIAN);
	*offset+=data;

	/*unit_R3*/
	unit_R3_tree = proto_tree_add_subtree(TupleEntry_list, tvb, *offset, 2, ett_sml_unit_R3, NULL, "unit_R3");
	proto_tree_add_item (unit_R3_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;
	proto_tree_add_item (unit_R3_tree, hf_sml_unit_R3, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;

	/*scaler_R3*/
	scaler_R3_tree = proto_tree_add_subtree(TupleEntry_list, tvb, *offset, 2, ett_sml_scaler_R3, NULL, "scaler_R3");
	proto_tree_add_item (scaler_R3_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;
	proto_tree_add_item (scaler_R3_tree, hf_sml_scaler_R3, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;

	/*value_R3*/
	get_length(tvb, offset, &data, &length);
	value_R3_tree = proto_tree_add_subtree(TupleEntry_list, tvb, *offset, length+data, ett_sml_value_R3, NULL, "value_R3");
	proto_tree_add_item (value_R3_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset+=1;
	proto_tree_add_item (value_R3_tree, hf_sml_value_R3, tvb, *offset, data, ENC_BIG_ENDIAN);
	*offset+=data;

	/*signature_mA_R2_R3*/
	get_length(tvb, offset, &data, &length);
	signature_mA_R2_R3_tree = proto_tree_add_subtree(TupleEntry_list, tvb, *offset, length+data, ett_sml_signature_mA_R2_R3, NULL, "signature_mA_R2_R3");
	proto_tree_add_uint (signature_mA_R2_R3_tree, hf_sml_length, tvb, *offset, length, data);
	*offset+=length;
	proto_tree_add_item (signature_mA_R2_R3_tree, hf_sml_signature_mA_R2_R3, tvb, *offset, data, ENC_NA);
	*offset+=data;

	proto_item_set_end(TupleEntry, tvb, *offset);
}

// NOLINTNEXTLINE(misc-no-recursion)
static void child_tree(tvbuff_t *tvb, packet_info *pinfo, proto_tree *insert_tree, unsigned *offset, unsigned *data, unsigned *length){
	proto_item *parameterName;
	proto_item *procParValue;
	proto_item *child;
	proto_item *periodEntry;
	proto_item *SML_time;
	proto_item *listEntry;
	proto_item *tree_Entry;

	proto_tree *parameterName_tree = NULL;
	proto_tree *procParValue_tree = NULL;
	proto_tree *procParValuetype_tree = NULL;
	proto_tree *periodEntry_tree = NULL;
	proto_tree *SML_time_tree = NULL;
	proto_tree *listEntry_tree = NULL;
	//proto_tree *procParValueTime_tree = NULL;
	proto_tree *child_list = NULL;
	proto_tree *tree_Entry_list = NULL;

	unsigned i = 0;
	unsigned repeat = 0;
	unsigned check = 0;

	/*parameterName*/
	get_length(tvb, offset, data, length);
	parameterName_tree = proto_tree_add_subtree(insert_tree, tvb, *offset, *length + *data, ett_sml_parameterName, &parameterName, "parameterName");
	proto_tree_add_uint (parameterName_tree, hf_sml_length, tvb, *offset, *length, *data);
	*offset+=*length;
	proto_tree_add_item (parameterName_tree, hf_sml_parameterName, tvb, *offset, *data, ENC_NA);
	*offset+=*data;

	/*procParValue OPTIONAL*/
	check = tvb_get_uint8(tvb, *offset);

	if (check == OPTIONAL){
		procParValue = proto_tree_add_item(insert_tree, hf_sml_procParValue, tvb, *offset, 1, ENC_BIG_ENDIAN);
		proto_item_append_text(procParValue, ": NOT SET");
		*offset+=1;
	}
	else if (check == 0x72){
		get_length(tvb, offset, data, length);
		procParValue_tree = proto_tree_add_subtree(insert_tree, tvb, *offset, -1, ett_sml_procParValue, &procParValue, "ProcParValue");
		*offset+=1;

		/*procParValue CHOOSE*/
		procParValuetype_tree = proto_tree_add_subtree(procParValue_tree, tvb, *offset, 2, ett_sml_procParValuetype, NULL, "ProcParValueType");
		proto_tree_add_item (procParValuetype_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
		*offset+=1;
		check = tvb_get_uint8(tvb, *offset);
		proto_tree_add_item (procParValuetype_tree, hf_sml_procParValue, tvb, *offset, 1 ,ENC_BIG_ENDIAN);
		*offset+=1;

		switch (check) {
			case PROC_VALUE:
				/*value*/
				sml_value(tvb, pinfo, procParValue_tree, offset, data, length);
				break;

			case PROC_PERIOD:
				/*period*/
				get_length(tvb, offset, data, length);
				periodEntry_tree = proto_tree_add_subtree_format(procParValue_tree, tvb, *offset, -1, ett_sml_periodEntry, &periodEntry,
										"PeriodEntry List with %d %s", *length + *data, plurality(*length + *data, "element", "elements"));
				*offset+=*length;

				/*objName*/
				field_objName(tvb, periodEntry_tree, offset, data, length);

				/*unit OPTIONAL*/
				field_unit(tvb, periodEntry_tree, offset, data, length);

				/*scaler OPTIONAL*/
				field_scaler(tvb, periodEntry_tree, offset, data, length);

				/*value*/
				sml_value(tvb, pinfo, periodEntry_tree, offset, data, length);

				/*value Signature*/
				field_valueSignature(tvb, periodEntry_tree, offset, data, length);

				proto_item_set_end(periodEntry, tvb, *offset);
				break;

			case PROC_TUPLE:
				/*TupleEntry*/
				if (tvb_get_uint8(tvb, *offset) == 0xF1 && tvb_get_uint8(tvb, *offset+1) == 0x07){
					TupleEntryTree(tvb, pinfo, procParValue_tree, offset);
				}
				else {
					expert_add_info(pinfo, NULL, &ei_sml_tuple_error);
					return;
				}
				break;

			case PROC_TIME:
				SML_time_tree = proto_tree_add_subtree(procParValue_tree, tvb, *offset, -1, ett_sml_time, &SML_time, "Time");
				*offset+=1;
				sml_time_type(tvb, pinfo, SML_time_tree, offset);
				proto_item_set_end(SML_time, tvb, *offset);
				break;

			case PROC_LISTENTRY:
				/*listEntry*/
				get_length(tvb, offset, data, length);
				listEntry_tree = proto_tree_add_subtree_format(procParValue_tree, tvb, *offset, -1, ett_sml_listEntry, &listEntry,
					"ListEntry List with %d %s", *length + *data, plurality(*length + *data, "element", "elements"));
				*offset += *length;

				/*objName*/
				field_objName(tvb, listEntry_tree, offset, data, length);

				/*status OPTIONAL*/
				field_status(tvb, listEntry_tree, offset, data, length);

				/*valTime OPTIONAL*/
				SML_time_tree = proto_tree_add_subtree(listEntry_tree, tvb, *offset, -1, ett_sml_time, &SML_time, "Time");
				*offset += 1;
				sml_time_type(tvb, pinfo, SML_time_tree, offset);
				proto_item_set_end(SML_time, tvb, *offset);

				/*unit OPTIONAL*/
				field_unit(tvb, listEntry_tree, offset, data, length);

				/*scaler OPTIONAL*/
				field_scaler(tvb, listEntry_tree, offset, data, length);

				/*value*/
				sml_value(tvb, pinfo, listEntry_tree, offset, data, length);

				/*valueSignature OPTIONAL*/
				field_valueSignature(tvb, listEntry_tree, offset, data, length);

				proto_item_set_end(listEntry, tvb, *offset);
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
	check = tvb_get_uint8(tvb, *offset);

	child_list = proto_tree_add_subtree(insert_tree, tvb, *offset, -1, ett_sml_child, &child, "Child List");
	if (check == OPTIONAL){
		proto_item_append_text(child, ": NOT SET");
		proto_item_set_len(child, 1);
		*offset+=1;
	}
	else if ((check & 0x0F) != 0){
		if (check == 0x71){
			get_length(tvb, offset, data, length);
			proto_item_append_text(child, "with %d %s", *length + *data, plurality(*length + *data, "element", "elements"));
			*offset+=1;

			tree_Entry_list = proto_tree_add_subtree(child_list, tvb, *offset, -1, ett_sml_tree_Entry, &tree_Entry, "tree_Entry");
			*offset+=1;

			increment_dissection_depth(pinfo);
			child_tree(tvb, pinfo,tree_Entry_list, offset, data, length);
			decrement_dissection_depth(pinfo);

			proto_item_set_end(tree_Entry, tvb, *offset);
			proto_item_set_end(child, tvb, *offset);
		}
		else if ((check & 0xF0) == SHORT_LIST || (check & 0xF0) == LONG_LIST){
			get_length(tvb, offset, data, length);
			repeat = *length + *data;
			proto_item_append_text(child, "with %d %s", *length + *data, plurality(*length + *data, "element", "elements"));
			if (repeat <= 0){
				expert_add_info_format(pinfo, child, &ei_sml_invalid_count, "invalid loop count");
				return;
			}
			*offset+=*length;

			for(i =0 ; i < repeat; i++){
				tree_Entry_list = proto_tree_add_subtree(child_list, tvb, *offset, -1, ett_sml_tree_Entry, &tree_Entry, "tree_Entry");

				if (tvb_get_uint8(tvb, *offset) != 0x73){
					expert_add_info_format(pinfo, tree_Entry, &ei_sml_invalid_count, "invalid count of elements in tree_Entry");
					return;
				}
				*offset+=1;

				increment_dissection_depth(pinfo);
				child_tree(tvb, pinfo, tree_Entry_list, offset, data, length);
				decrement_dissection_depth(pinfo);
				proto_item_set_end(tree_Entry, tvb, *offset);
			}
			proto_item_set_end(child, tvb, *offset);
		}
	}
	else {
		expert_add_info_format(pinfo, child, &ei_sml_invalid_count, "invalid count of elements in child List");
	}
}

/*messagetypes*/
static void decode_PublicOpenReq (tvbuff_t *tvb, proto_tree *messagebodytree_list, unsigned *offset){
	unsigned data = 0;
	unsigned length = 0;

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

static void decode_PublicOpenRes (tvbuff_t *tvb, packet_info *pinfo, proto_tree *messagebodytree_list, unsigned *offset){
	proto_item *SML_time = NULL;

	//proto_tree *refTime_tree = NULL;
	proto_tree *SML_time_tree = NULL;

	unsigned data = 0;
	unsigned length = 0;

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

	SML_time_tree = proto_tree_add_subtree(messagebodytree_list, tvb, *offset, -1, ett_sml_time, &SML_time, "refTime");
	if (data == 0){
		proto_item_append_text(SML_time, ": NOT SET");
		proto_item_set_len(SML_time, length + data);
		*offset+=1;
	}
	else{
		/*SML TIME*/
		*offset+=1;
		sml_time_type(tvb, pinfo, SML_time_tree, offset);
		proto_item_set_end(SML_time,tvb,*offset);
	}
	/*sml-Version OPTIONAL*/
	field_smlVersion(tvb, messagebodytree_list, offset, &data, &length);
}

static bool decode_GetProfile_List_Pack_Req (tvbuff_t *tvb, packet_info *pinfo, proto_tree *messagebodytree_list, unsigned *offset){
	proto_item *withRawdata = NULL;
	proto_item *SML_time = NULL;
	proto_item *treepath = NULL;
	proto_item *object_list = NULL;
	proto_item *dasDetails = NULL;

	proto_tree *withRawdata_tree = NULL;
	proto_tree *SML_time_tree = NULL;
	//proto_tree *beginTime_tree = NULL;
	proto_tree *treepath_list = NULL;
	proto_tree *object_list_list = NULL;
	//proto_tree *endTime_tree = NULL;
	proto_tree *dasDetails_list = NULL;

	unsigned i = 0;
	unsigned repeat = 0;
	unsigned check = 0;
	unsigned data = 0;
	unsigned length = 0;

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
		proto_tree_add_item (withRawdata_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
		*offset+=1;
		proto_tree_add_item (withRawdata_tree, hf_sml_withRawdata, tvb, *offset, 1, ENC_BIG_ENDIAN);
		*offset+=1;
	}
	else
		*offset+=1;

	/*beginTime OPTIONAL*/
	get_length(tvb, offset, &data, &length);

	SML_time_tree = proto_tree_add_subtree(messagebodytree_list, tvb, *offset, -1, ett_sml_time, &SML_time, "beginTime");
	if (data == 0){
		proto_item_append_text(SML_time, ": NOT SET");
		proto_item_set_len(SML_time, length + data);
		*offset+=1;
	}
	else {
		/*SML TIME*/
		*offset+=1;
		sml_time_type(tvb, pinfo, SML_time_tree, offset);
		proto_item_set_end(SML_time,tvb,*offset);
	}

	/*endTime OPTIONAL*/
	get_length(tvb, offset, &data, &length);

	SML_time_tree = proto_tree_add_subtree(messagebodytree_list, tvb, *offset, -1, ett_sml_time, &SML_time, "endTime");
	if (data == 0){
		proto_item_append_text(SML_time, ": NOT SET");
		proto_item_set_len(SML_time, length + data);
		*offset+=1;
	}
	else {
		/*SML TIME*/
		*offset+=1;
		sml_time_type(tvb, pinfo, SML_time_tree, offset);
		proto_item_set_end(SML_time,tvb,*offset);
	}

	/*Treepath List*/
	get_length(tvb, offset, &data, &length);
	repeat = (data+length);
	treepath_list = proto_tree_add_subtree_format(messagebodytree_list, tvb, *offset, -1, ett_sml_treepath, &treepath,
					"parameterTreePath with %d %s", length+data, plurality(length+data, "element", "elements"));

	if ((tvb_get_uint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_uint8(tvb,*offset) & 0xF0) != SHORT_LIST){
		expert_add_info_format(pinfo, treepath, &ei_sml_invalid_count, "invalid count of elements in Treepath");
		return true;
	}
	else if (repeat <= 0){
		expert_add_info_format(pinfo, treepath, &ei_sml_invalid_count, "invalid loop count");
		return true;
	}
	*offset+=length;

	for (i=0; i< repeat; i++) {
		field_parameterTreePath(tvb, treepath_list, offset, &data, &length);
	}
	proto_item_set_end(treepath, tvb, *offset);

	/*object_list*/
	object_list_list = proto_tree_add_subtree(messagebodytree_list, tvb, *offset, -1, ett_sml_object_list, &object_list, "object_List");
	if (tvb_get_uint8(tvb,*offset) == OPTIONAL){
		proto_item_append_text(object_list, ": NOT SET");
		proto_item_set_len(object_list, 1);
		*offset+=1;
	}
	else{
		get_length(tvb, offset, &data, &length);
		repeat = (data+length);
		proto_item_append_text(object_list, " with %d %s", length+data, plurality(length+data, "element", "elements"));

		if ((tvb_get_uint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_uint8(tvb,*offset) & 0xF0) != SHORT_LIST){
			expert_add_info_format(pinfo, object_list, &ei_sml_invalid_count, "invalid count of elements in object_List");
			return true;
		}
		else if (repeat <= 0){
			expert_add_info_format(pinfo, treepath, &ei_sml_invalid_count, "invalid loop count");
			return true;
		}

		*offset+=length;

		for (i=0; i< repeat; i++) {
			field_ObjReqEntry(tvb, object_list_list, offset, &data, &length);
		}
		proto_item_set_end(object_list, tvb, *offset);
	}

	/*dasDetails*/
	check = tvb_get_uint8(tvb,*offset);

	dasDetails_list = proto_tree_add_subtree(messagebodytree_list, tvb, *offset, -1, ett_sml_dasDetails, &dasDetails, "dasDetails");
	if (check == OPTIONAL){
		proto_item_append_text(dasDetails, ": NOT SET");
		proto_item_set_len(dasDetails, 1);
		*offset+=1;
	}
	else if ((check & 0xF0) == LONG_LIST || (check & 0xF0) == SHORT_LIST){
		get_length(tvb, offset, &data, &length);
		proto_item_append_text(dasDetails, " with %d %s", length+data, plurality(length+data, "element", "elements"));
		*offset+=length;

		child_tree(tvb, pinfo, dasDetails_list, offset, &data, &length);
		proto_item_set_end(dasDetails, tvb, *offset);
	}
	else {
		expert_add_info_format(pinfo, dasDetails, &ei_sml_invalid_count, "invalid count of elements in dasDetails");
		return true;
	}
	return false;
}

static bool decode_GetProfilePackRes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *messagebodytree_list, unsigned *offset){
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

	unsigned i = 0;
	unsigned d = 0;
	unsigned repeat = 0;
	unsigned repeat2= 0;
	unsigned data = 0;
	unsigned length = 0;

	/*ServerID*/
	field_serverId(tvb, messagebodytree_list, offset, &data, &length);

	/*actTime*/
	get_length(tvb, offset, &data, &length);
	SML_time_tree = proto_tree_add_subtree_format(messagebodytree_list, tvb, *offset, -1, ett_sml_time, &SML_time,
				"actTime List with %d %s", length+data, plurality(length+data, "element", "elements"));
	*offset+=1;
	sml_time_type(tvb, pinfo, SML_time_tree, offset);
	proto_item_set_end(SML_time,tvb,*offset);

	/*regPeriod*/
	field_regPeriod(tvb, messagebodytree_list, offset, &data, &length);

	/*Treepath List*/
	get_length(tvb, offset, &data, &length);
	repeat = (data+length);
	treepath_list = proto_tree_add_subtree_format(messagebodytree_list, tvb, *offset, -1, ett_sml_treepath, &treepath,
					"parameterTreePath with %d %s", length+data, plurality(length+data, "element", "elements"));

	if ((tvb_get_uint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_uint8(tvb,*offset) & 0xF0) != SHORT_LIST){
		expert_add_info_format(pinfo, treepath, &ei_sml_invalid_count, "invalid count of elements in Treepath");
		return true;
	}
	else if (repeat <= 0){
		expert_add_info_format(pinfo, treepath, &ei_sml_invalid_count, "invalid loop count");
		return true;
	}

	*offset+=length;

	for (i=0; i< repeat; i++) {
		field_parameterTreePath(tvb, treepath_list, offset, &data, &length);
	}
	proto_item_set_end(treepath, tvb, *offset);

	/*headerList*/
	get_length(tvb, offset, &data, &length);
	repeat = (data+length);
	headerList_subtree = proto_tree_add_subtree_format(messagebodytree_list, tvb, *offset, -1, ett_sml_headerList, &headerList,
							"header_List with %d %s", length+data, plurality(length+data, "element", "elements"));

	if ((tvb_get_uint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_uint8(tvb,*offset) & 0xF0) != SHORT_LIST){
		expert_add_info_format(pinfo, headerList, &ei_sml_invalid_count, "invalid count of elements in headerlist");
		return true;
	}
	else if (repeat <= 0){
		expert_add_info_format(pinfo, headerList, &ei_sml_invalid_count, "invalid loop count");
		return true;
	}

	*offset+=length;

	for (i=0; i< repeat; i++) {
		get_length(tvb, offset, &data, &length);
		header_List_Entry_list = proto_tree_add_subtree_format(headerList_subtree, tvb, *offset, -1, ett_sml_header_List_Entry, &header_List_Entry,
								"header_List_Entry with %d %s", length+data, plurality(length+data, "element", "elements"));
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
	periodList_list = proto_tree_add_subtree_format(messagebodytree_list, tvb, *offset, -1, ett_sml_periodList, &periodList,
				"period_List with %d %s", length+data, plurality(length+data, "element", "elements"));

	if ((tvb_get_uint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_uint8(tvb,*offset) & 0xF0) != SHORT_LIST){
		expert_add_info_format(pinfo, periodList, &ei_sml_invalid_count, "invalid count of elements in periodList");
		return true;
	}
	else if (repeat <= 0){
		expert_add_info_format(pinfo, periodList, &ei_sml_invalid_count, "invalid loop count");
		return true;
	}

	*offset+=length;

	for (i=0; i< repeat; i++) {
		get_length(tvb, offset, &data, &length);
		period_List_Entry_list = proto_tree_add_subtree_format(periodList_list, tvb, *offset, -1, ett_sml_period_List_Entry, &period_List_Entry,
						"period_List_Entry with %d %s", length+data, plurality(length+data, "element", "elements"));
		*offset+=1;

		/*valTime*/
		get_length(tvb, offset, &data, &length);
		SML_time_tree = proto_tree_add_subtree(period_List_Entry, tvb, *offset, -1, ett_sml_time, &SML_time, "valTime");
		*offset+=1;
		sml_time_type(tvb, pinfo, SML_time_tree, offset);
		proto_item_set_end(SML_time,tvb, *offset);

		/*status*/
		field_status(tvb, period_List_Entry_list, offset, &data, &length);

		/*value List*/
		get_length(tvb, offset, &data, &length);
		repeat2 = data + length;
		valuelist_list = proto_tree_add_subtree_format(period_List_Entry_list, tvb, *offset, -1, ett_sml_valuelist, &valuelist,
							       "period_List with %d %s", length+data, plurality(length+data, "element", "elements"));

		if ((tvb_get_uint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_uint8(tvb,*offset) & 0xF0) != SHORT_LIST){
			expert_add_info_format(pinfo, valuelist, &ei_sml_invalid_count, "invalid count of elements in valueList");
			return true;
		}
		else if (repeat2 <= 0){
			expert_add_info_format(pinfo, valuelist, &ei_sml_invalid_count, "invalid loop count");
			return true;
		}

		*offset+=length;

		for (d=0; d< repeat2; d++) {
			get_length(tvb, offset, &data, &length);
			value_List_Entry_list = proto_tree_add_subtree_format(valuelist_list, tvb, *offset, -1, ett_sml_value_List_Entry, NULL,
									"value_List_Entry with %d %s", length+data, plurality(length+data, "element", "elements"));
			*offset+=1;

			/*value*/
			sml_value(tvb, pinfo, value_List_Entry_list, offset, &data, &length);

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
		proto_tree_add_uint (profileSignature_tree, hf_sml_length, tvb, *offset, length, data);
		*offset+=length;
		proto_tree_add_item (profileSignature_tree, hf_sml_profileSignature, tvb, *offset, data, ENC_NA);
		*offset+=data;
	}
	else
		*offset+=1;

	return false;
}

static bool decode_GetProfileListRes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *messagebodytree_list, unsigned *offset){
	proto_item *SML_time = NULL;
	proto_item *treepath = NULL;
	proto_item *periodList = NULL;
	proto_item *periodList_Entry = NULL;

	proto_tree *SML_time_tree = NULL;
	proto_tree *treepath_list = NULL;
	proto_tree *periodList_list = NULL;
	proto_tree *periodList_Entry_list = NULL;

	unsigned i = 0;
	unsigned repeat = 0;
	unsigned data = 0;
	unsigned length = 0;

	/*ServerID*/
	field_serverId(tvb, messagebodytree_list, offset, &data, &length);

	/*actTime*/
	get_length(tvb, offset, &data, &length);
	SML_time_tree = proto_tree_add_subtree(messagebodytree_list, tvb, *offset, -1, ett_sml_time, &SML_time, "actTime");
	*offset+=1;
	sml_time_type(tvb, pinfo, SML_time_tree, offset);
	proto_item_set_end(SML_time,tvb, *offset);

	/*regPeriod*/
	field_regPeriod(tvb, messagebodytree_list, offset, &data, &length);

	/*Treepath List*/
	get_length(tvb, offset, &data, &length);
	repeat = (data+length);
	treepath_list = proto_tree_add_subtree_format(messagebodytree_list, tvb, *offset, -1, ett_sml_treepath, &treepath,
				"parameterTreePath with %d %s", length+data, plurality(length+data, "element", "elements"));

	if ((tvb_get_uint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_uint8(tvb,*offset) & 0xF0) != SHORT_LIST){
		expert_add_info_format(pinfo, treepath, &ei_sml_invalid_count, "invalid count of elements in parameterTreePath");
		return true;
	}
	else if (repeat <= 0){
		expert_add_info_format(pinfo, treepath, &ei_sml_invalid_count, "invalid loop count");
		return true;
	}

	*offset+=length;

	for (i=0; i< repeat; i++) {
		field_parameterTreePath(tvb, treepath_list, offset, &data, &length);
	}
	proto_item_set_end(treepath, tvb,*offset);

	/*valTime Optional*/
	get_length(tvb, offset, &data, &length);

	SML_time_tree = proto_tree_add_subtree(messagebodytree_list, tvb, *offset, -1, ett_sml_time, &SML_time, "valTime");
	if (data == 0){
		proto_item_append_text(SML_time, ": NOT SET");
		proto_item_set_len(SML_time, length + data);
		*offset+=1;
	}
	else {
		/*SML TIME*/
		*offset+=1;
		sml_time_type(tvb, pinfo, SML_time_tree, offset);
		proto_item_set_end(SML_time,tvb,*offset);
	}

	/*Status*/
	field_status(tvb, messagebodytree_list, offset, &data, &length);

	/*period-List*/
	get_length(tvb, offset, &data, &length);
	repeat = (data+length);
	periodList_list = proto_tree_add_subtree_format(messagebodytree_list, tvb, *offset, -1, ett_sml_periodList, &periodList,
					"period-List with %d %s", length+data, plurality(length+data, "element", "elements"));

	if ((tvb_get_uint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_uint8(tvb,*offset) & 0xF0) != SHORT_LIST){
		expert_add_info_format(pinfo, periodList, &ei_sml_invalid_count, "invalid count of elements in periodList");
		return true;
	}
	else if (repeat <= 0){
		expert_add_info_format(pinfo, periodList, &ei_sml_invalid_count, "invalid loop count");
		return true;
	}

	*offset+=length;

	for (i=0; i< repeat; i++) {
		get_length(tvb, offset, &data, &length);
		periodList_Entry_list = proto_tree_add_subtree(periodList_list, tvb, *offset, -1, ett_sml_period_List_Entry, &periodList_Entry, "PeriodEntry");
		*offset+=1;

		/*ObjName*/
		field_objName(tvb, periodList_Entry_list, offset, &data, &length);

		/*Unit*/
		field_unit(tvb, periodList_Entry_list, offset, &data, &length);

		/*scaler*/
		field_scaler(tvb, periodList_Entry_list, offset, &data, &length);

		/*value*/
		sml_value(tvb, pinfo, periodList_Entry_list, offset, &data, &length);

		/*value*/
		field_valueSignature(tvb, periodList_Entry_list, offset, &data, &length);

		proto_item_set_end(periodList_Entry, tvb, *offset);
	}
	proto_item_set_end(periodList, tvb, *offset);

	/*rawdata*/
	field_rawdata(tvb, messagebodytree_list, offset, &data, &length);

	/*period Signature*/
	field_periodSignature(tvb, messagebodytree_list, offset, &data, &length);

	return false;
}

static void decode_GetListReq (tvbuff_t *tvb, proto_tree *messagebodytree_list, unsigned *offset){
	unsigned data = 0;
	unsigned length = 0;

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

static bool decode_GetListRes (tvbuff_t *tvb, packet_info *pinfo, proto_tree *messagebodytree_list, unsigned *offset){
	proto_item *valList = NULL;
	proto_item *listSignature = NULL;
	proto_item *valtree = NULL;
	proto_item *SML_time;

	//proto_tree *actSensorTime_tree = NULL;
	proto_tree *valList_list = NULL;
	proto_tree *listSignature_tree = NULL;
	proto_tree *valtree_list = NULL;
	//proto_tree *actGatewayTime_tree = NULL;
	proto_tree *SML_time_tree = NULL;

	unsigned repeat = 0;
	unsigned i = 0;
	unsigned data = 0;
	unsigned length = 0;

	/*clientID OPTIONAL*/
	field_clientId (tvb, messagebodytree_list, offset, &data, &length);

	/*ServerID*/
	field_serverId(tvb, messagebodytree_list, offset, &data, &length);

	/*listName*/
	field_listName(tvb, messagebodytree_list, offset, &data, &length);

	/*actSensorTime OPTIONAL*/
	get_length(tvb, offset, &data, &length);

	SML_time_tree = proto_tree_add_subtree(messagebodytree_list, tvb, *offset, -1, ett_sml_time, &SML_time, "actSensorTime");
	if (data == 0){
		proto_item_append_text(SML_time, ": NOT SET");
		proto_item_set_len(SML_time, length + data);
		*offset+=1;
	}
	else {
		/*SML TIME*/
		*offset+=1;
		sml_time_type(tvb, pinfo, SML_time_tree, offset);
		proto_item_set_end(SML_time,tvb,*offset);
	}

	/*valList*/
	get_length(tvb, offset, &data, &length);
	repeat = (length + data);
	valtree_list = proto_tree_add_subtree_format(messagebodytree_list, tvb, *offset, -1, ett_sml_valtree, &valtree,
						"valList with %d %s", length+data, plurality(length+data, "element", "elements"));

	if ((tvb_get_uint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_uint8(tvb,*offset) & 0xF0) != SHORT_LIST){
		expert_add_info_format(pinfo, valtree, &ei_sml_invalid_count, "invalid count of elements in valList");
		return true;
	}
	else if (repeat <= 0){
		expert_add_info_format(pinfo, valtree, &ei_sml_invalid_count, "invalid loop count");
		return true;
	}

	*offset+=length;

	for (i=0; i < repeat; i++){
		get_length(tvb, offset, &data, &length);
		valList_list = proto_tree_add_subtree(valtree_list, tvb, *offset, -1, ett_sml_valList, &valList, "valListEntry");
		*offset+=length;

		/*objName*/
		field_objName(tvb, valList_list, offset, &data, &length);

		/*Sml Status OPTIONAL*/
		field_status(tvb, valList_list, offset, &data, &length);

		/*valTime OPTIONAL*/
		get_length(tvb, offset, &data, &length);

		SML_time_tree = proto_tree_add_subtree(valList_list, tvb, *offset, -1, ett_sml_time, &SML_time, "valTime");
		if (data == 0){
			proto_item_append_text(SML_time, ": NOT SET");
			proto_item_set_len(SML_time, length + data);
			*offset+=1;
		}
		else {
			/*SML TIME*/
			*offset+=1;
			sml_time_type(tvb, pinfo, SML_time_tree, offset);
			proto_item_set_end(SML_time, tvb, *offset);
		}

		/*unit OPTIONAL*/
		field_unit(tvb, valList_list, offset, &data, &length);

		/*Scaler OPTIONAL*/
		field_scaler(tvb, valList_list, offset, &data, &length);

		/*value*/
		sml_value(tvb, pinfo, valList_list, offset, &data, &length);

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
		proto_tree_add_uint (listSignature_tree, hf_sml_length, tvb, *offset, length, data);
		*offset+=length;
		proto_tree_add_item (listSignature_tree, hf_sml_listSignature, tvb, *offset, data, ENC_NA);
		*offset+=data;
	}
	else
		*offset+=1;

	/*actGatewayTime OPTIONAL*/
	get_length(tvb, offset, &data, &length);

	SML_time_tree = proto_tree_add_subtree(messagebodytree_list, tvb, *offset, -1, ett_sml_time, &SML_time, "actGatewayTime");
	if (data == 0){
		proto_item_append_text(SML_time, ": NOT SET");
		proto_item_set_len(SML_time, length + data);
		*offset+=1;
	}
	else{
		/*SML TIME*/
		*offset+=1;
		sml_time_type(tvb, pinfo, SML_time_tree, offset);
		proto_item_set_end(SML_time,tvb,*offset);
	}
	return false;
}

static bool decode_GetProcParameterReq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *messagebodytree_list, unsigned *offset){
	proto_item *treepath = NULL;
	proto_item *attribute = NULL;

	proto_tree *treepath_list = NULL;
	proto_tree *attribute_tree = NULL;

	unsigned i = 0;
	unsigned repeat = 0;
	unsigned data = 0;
	unsigned length = 0;

	/*ServerID*/
	field_serverId(tvb, messagebodytree_list, offset, &data, &length);

	/*user*/
	field_username(tvb, messagebodytree_list, offset, &data, &length);

	/*password*/
	field_password(tvb, messagebodytree_list, offset, &data, &length);

	/*Treepath List*/
	get_length(tvb, offset, &data, &length);
	repeat = data+length;
	treepath_list = proto_tree_add_subtree_format(messagebodytree_list, tvb, *offset, -1, ett_sml_treepath, &treepath,
					"ParameterTreePath with %d %s", length+data, plurality(length+data, "element", "elements"));

	if ((tvb_get_uint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_uint8(tvb,*offset) & 0xF0) != SHORT_LIST){
		expert_add_info_format(pinfo, treepath, &ei_sml_invalid_count, "invalid count of elements in ParameterTreePath");
		return true;
	}
	else if (repeat <= 0){
		expert_add_info_format(pinfo, treepath, &ei_sml_invalid_count, "invalid loop count");
		return true;
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
		proto_tree_add_uint (attribute_tree, hf_sml_length, tvb, *offset, length, data);
		*offset+=length;
		proto_tree_add_item (attribute_tree, hf_sml_attribute, tvb, *offset, data, ENC_NA);
		*offset+=data;
	}
	else
		*offset+=1;

	return false;
}

static bool decode_GetProcParameterRes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *messagebodytree_list, unsigned *offset){
	proto_item *treepath = NULL;
	proto_item *parameterTree =NULL;

	proto_tree *treepath_list = NULL;
	proto_tree *parameterTree_list = NULL;

	unsigned i = 0;
	unsigned repeat = 0;
	unsigned data = 0;
	unsigned length = 0;

	/*ServerID*/
	field_serverId(tvb, messagebodytree_list, offset, &data, &length);

	/*Treepath List*/
	get_length(tvb, offset, &data, &length);
	repeat = (data+length);
	treepath_list = proto_tree_add_subtree_format(messagebodytree_list, tvb, *offset, -1, ett_sml_treepath, &treepath,
					"parameterTreePath with %d %s", length+data, plurality(length+data, "element", "elements"));

	if ((tvb_get_uint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_uint8(tvb,*offset) & 0xF0) != SHORT_LIST){
		expert_add_info_format(pinfo, treepath, &ei_sml_invalid_count, "invalid count of elements in ParameterTreePath");
		return true;
	}
	else if (repeat <= 0){
		expert_add_info_format(pinfo, treepath, &ei_sml_invalid_count, "invalid loop count");
		return true;
	}

	*offset+=length;

	for (i=0; i< repeat; i++) {
		field_parameterTreePath(tvb, treepath_list, offset, &data, &length);
	}
	proto_item_set_end(treepath, tvb, *offset);

	/*parameterTree*/
	get_length(tvb, offset, &data, &length);
	parameterTree_list = proto_tree_add_subtree_format(messagebodytree_list, tvb, *offset, -1, ett_sml_parameterTree, &parameterTree,
				"parameterTree with %d %s", length+data, plurality(length+data, "element", "elements"));

	if ((tvb_get_uint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_uint8(tvb,*offset) & 0xF0) != SHORT_LIST){
		expert_add_info_format(pinfo, parameterTree, &ei_sml_invalid_count, "invalid count of elements in parameterTree");
		return true;
	}

	*offset+=length;

	child_tree(tvb, pinfo,parameterTree_list, offset, &data, &length);
	proto_item_set_end(parameterTree, tvb, *offset);

	return false;
}

static bool decode_SetProcParameterReq(tvbuff_t *tvb, packet_info *pinfo,proto_tree *messagebodytree_list, unsigned *offset){
	proto_item *treepath = NULL;
	proto_item *parameterTree = NULL;

	proto_tree *treepath_list = NULL;
	proto_tree *parameterTree_list = NULL;

	unsigned i = 0;
	unsigned repeat = 0;
	unsigned data = 0;
	unsigned length = 0;

	/*ServerID*/
	field_serverId(tvb, messagebodytree_list, offset, &data, &length);

	/*user*/
	field_username(tvb, messagebodytree_list, offset, &data, &length);

	/*password*/
	field_password(tvb, messagebodytree_list, offset, &data, &length);

	/*Treepath List*/
	get_length(tvb, offset, &data, &length);
	repeat = (data+length);
	treepath_list = proto_tree_add_subtree_format(messagebodytree_list, tvb, *offset, -1, ett_sml_treepath, &treepath,
					"parameterTreePath with %d %s", length+data, plurality(length+data, "element", "elements"));

	if ((tvb_get_uint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_uint8(tvb,*offset) & 0xF0) != SHORT_LIST){
		expert_add_info_format(pinfo, treepath, &ei_sml_invalid_count, "invalid count of elements in ParameterTreePath");
		return true;
	}
	else if (repeat <= 0){
		expert_add_info_format(pinfo, treepath, &ei_sml_invalid_count, "invalid loop count");
		return true;
	}

	*offset+=length;

	for (i=0; i< repeat; i++) {
		field_parameterTreePath(tvb, treepath_list, offset, &data, &length);
	}
	proto_item_set_end(treepath, tvb, *offset);

	/*parameterTree*/
	get_length(tvb, offset, &data, &length);
	parameterTree_list = proto_tree_add_subtree_format(messagebodytree_list, tvb, *offset, -1, ett_sml_parameterTree, &parameterTree,
				"parameterTree with %d %s", length+data, plurality(length+data, "element", "elements"));

	if ((tvb_get_uint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_uint8(tvb,*offset) & 0xF0) != SHORT_LIST){
		expert_add_info_format(pinfo, parameterTree, &ei_sml_invalid_count, "invalid count of elements in parameterTree");
		return true;
	}

	*offset+=length;

	child_tree(tvb, pinfo,parameterTree_list, offset, &data, &length);
	proto_item_set_end(parameterTree, tvb, *offset);

	return false;
}

static bool decode_AttentionRes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *messagebodytree_list, unsigned *offset){
	proto_item *attentionMsg = NULL;
	proto_item *attentionDetails = NULL;

	proto_tree *attentionNo_tree = NULL;
	proto_tree *attentionMsg_tree = NULL;
	proto_tree *attentionDetails_list = NULL;
    proto_item *attentionNo_item;

	unsigned data = 0;
	unsigned length = 0;

	/*ServerID*/
	field_serverId(tvb, messagebodytree_list, offset, &data, &length);

	/*attention NO*/
	get_length(tvb, offset, &data, &length);
	attentionNo_tree = proto_tree_add_subtree(messagebodytree_list, tvb ,*offset, length+data, ett_sml_attentionNo, &attentionNo_item, "attentionNo");
	proto_tree_add_uint (attentionNo_tree, hf_sml_length, tvb, *offset, length, data);
	*offset+=length;

	if (data == 6){
		*offset+=4;
		proto_tree_add_item (attentionNo_tree, hf_sml_attentionNo, tvb, *offset, 2, ENC_BIG_ENDIAN);
		*offset+=2;
	}
	else {
		expert_add_info(pinfo, attentionNo_item, &ei_sml_attentionNo);
		*offset+=data;
	}

	/*attention Msg*/
	get_length(tvb, offset, &data, &length);
	attentionMsg = proto_tree_add_string_format (messagebodytree_list, hf_sml_attentionMsg, tvb, *offset, length+data, NULL, "attentionMsg %s", (data == 0)? ": NOT SET" : "");

	if (data > 0){
		attentionMsg_tree = proto_item_add_subtree (attentionMsg, ett_sml_attentionMsg);
		proto_tree_add_uint (attentionMsg_tree, hf_sml_length, tvb, *offset, length, data);
		*offset+=length;
		proto_tree_add_item (attentionMsg_tree, hf_sml_attentionMsg, tvb, *offset, data, ENC_ASCII | ENC_BIG_ENDIAN);
		*offset+=data;
	}
	else
		*offset+=1;

	/*attentiondetails*/
	attentionDetails_list = proto_tree_add_subtree(messagebodytree_list, tvb, *offset, -1, ett_sml_attentionDetails, &attentionDetails, "attentionDetails");
	if (tvb_get_uint8(tvb,*offset) == OPTIONAL){
		proto_item_append_text(attentionDetails, ": NOT SET");
		proto_item_set_len(attentionDetails, 1);
		*offset+=1;
	}
	else{
		get_length(tvb, offset, &data, &length);
		proto_item_append_text(attentionDetails, " with %d %s", length+data, plurality(length+data, "element", "elements"));

		if ((tvb_get_uint8(tvb,*offset) & 0xF0) != LONG_LIST && (tvb_get_uint8(tvb,*offset) & 0xF0) != SHORT_LIST){
			expert_add_info_format(pinfo, attentionDetails, &ei_sml_invalid_count, "invalid count of elements in attentionDetails");
			return true;
		}

		*offset+=length;

		child_tree(tvb, pinfo,attentionDetails_list, offset, &data, &length);
		proto_item_set_end(attentionDetails, tvb, *offset);
	}

	return false;
}

/*dissect SML-File*/
static void dissect_sml_file(tvbuff_t *tvb, packet_info *pinfo, int *offset, proto_tree *sml_tree){
	proto_item *file = NULL;
	proto_item *mainlist;
	proto_item *sublist;
	proto_item *messagebody;
	proto_item *crc16;
	proto_item *messagebodytree;
	proto_item *msgend;

	proto_tree *mainlist_list = NULL;
	proto_tree *trans_tree = NULL;
	proto_tree *groupNo_tree = NULL;
	proto_tree *abortOnError_tree = NULL;
	proto_tree *sublist_list = NULL;
	proto_tree *messagebody_tree = NULL;
	proto_tree *crc16_tree = NULL;
	proto_tree *messagebodytree_list = NULL;
	proto_tree *msgend_tree = NULL;

	uint16_t messagebody_switch = 0;
	uint16_t crc_check = 0;
	uint16_t crc_ref = 0;
	unsigned check = 0;

	unsigned available = 0;
	unsigned crc_msg_len = 0;
	unsigned crc_file_len = 0;
	unsigned data = 0;
	unsigned length = 0;

	bool msg_error = false;
	bool close1 = false;
	bool close2 = false;
	int end_offset = 0;

	unsigned start_offset;
	start_offset = *offset;

	end_offset = tvb_reported_length_remaining(tvb, *offset);
	if (end_offset <= 0){
		return;
	}

	if (tvb_get_ntoh40(tvb, end_offset-8) != ESC_SEQ_END && pinfo->can_desegment){
		if (tvb_get_uint8(tvb, end_offset-1) != 0){
			pinfo->desegment_offset = start_offset;
			pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
			return;
		}
		else if (tvb_get_uint8(tvb, end_offset-4) != UNSIGNED16 && tvb_get_uint8(tvb, end_offset-3) != UNSIGNED8){
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
			file = proto_tree_add_item(sml_tree, hf_sml_file_marker, tvb, *offset, -1, ENC_NA);
		}

		/*check if escape*/
		if (tvb_get_ntohl(tvb, *offset) == ESC_SEQ){
			crc_file_len = *offset;
			/*Escape Start*/
			proto_tree_add_item (sml_tree, hf_sml_esc, tvb, *offset, 4, ENC_BIG_ENDIAN);
			*offset+=4;

			/*Version*/
			if (tvb_get_uint8(tvb, *offset) == 0x01){
				proto_tree_add_item (sml_tree, hf_sml_version_1, tvb, *offset, 4, ENC_BIG_ENDIAN);
				*offset+=4;
			}
			else{
				proto_tree_add_expert(sml_tree, pinfo, &ei_sml_version2_not_supported, tvb, *offset, -1);
				return;
			}
		}

		while (!close1){
			crc_msg_len = *offset;

			/*List*/
			get_length(tvb, offset, &data, &length);
			mainlist_list = proto_tree_add_subtree_format(sml_tree, tvb, *offset, -1, ett_sml_mainlist, &mainlist, "List with %d %s",
								      length+data, plurality(length+data, "element", "elements"));

			if (tvb_get_uint8(tvb, *offset) != LIST_6_ELEMENTS) {
				expert_add_info_format(pinfo, mainlist, &ei_sml_invalid_count, "invalid count of elements");
				return;
			}
			*offset+=1;

			/*Transaction ID*/
			get_length(tvb, offset, &data, &length);
			trans_tree = proto_tree_add_subtree_format(mainlist_list, tvb, *offset, length + data, ett_sml_trans, NULL, "Transaction ID");
			proto_tree_add_uint (trans_tree, hf_sml_length, tvb, *offset, length, data);
			*offset+=length;
			proto_tree_add_item (trans_tree, hf_sml_transactionId, tvb, *offset, data, ENC_NA);
			*offset+=data;

			/*Group No*/
			groupNo_tree = proto_tree_add_subtree(mainlist_list, tvb, *offset, 2, ett_sml_group, NULL, "Group No");
			proto_tree_add_item (groupNo_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
			*offset+=1;
			proto_tree_add_item (groupNo_tree, hf_sml_groupNo, tvb, *offset, 1, ENC_BIG_ENDIAN);
			*offset+=1;

			/*abort on Error*/
			abortOnError_tree = proto_tree_add_subtree(mainlist_list, tvb, *offset, 2, ett_sml_abort, NULL, "Abort on Error");
			proto_tree_add_item(abortOnError_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
			*offset+=1;
			proto_tree_add_item(abortOnError_tree, hf_sml_abortOnError, tvb, *offset, 1, ENC_BIG_ENDIAN);
			*offset+=1;

			/*Sub List*/
			sublist_list = proto_tree_add_subtree(mainlist_list, tvb, *offset, -1, ett_sml_sublist, &sublist, "MessageBody");
			*offset+=1;

			/*Zero Cutting Check*/
			get_length(tvb, offset, &data, &length);
			messagebody_tree = proto_tree_add_subtree(sublist_list, tvb, *offset, length + data, ett_sml_mttree, &messagebody, "Messagetype");
			proto_tree_add_item (messagebody_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
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
			messagebodytree_list = proto_tree_add_subtree_format(sublist_list, tvb, *offset, -1, ett_sml_mblist, &messagebodytree,
												"List with %d %s", length+data, plurality(length+data, "element", "elements"));
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
					decode_PublicOpenRes(tvb, pinfo, messagebodytree_list, offset);
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
			crc16_tree = proto_tree_add_subtree(mainlist_list, tvb, *offset, data + length, ett_sml_crc16, &crc16, "CRC");

			if(tvb_get_uint8(tvb, *offset) != UNSIGNED8 && tvb_get_uint8(tvb, *offset) != UNSIGNED16){
				expert_add_info(pinfo, crc16, &ei_sml_crc_error_length);
				return;
			}

			proto_tree_add_item (crc16_tree, hf_sml_datatype, tvb, *offset, 1, ENC_BIG_ENDIAN);
			*offset+=1;

			if (sml_crc_enabled) {
				crc_msg_len = (*offset - crc_msg_len - 1);
				crc_check = crc16_ccitt_tvb_offset(tvb, (*offset - crc_msg_len - 1), crc_msg_len);

				if (data == 1){
					crc_ref = crc_ref & 0xFF00;
				}

				proto_tree_add_checksum(crc16_tree, tvb, *offset, hf_sml_crc16, hf_sml_crc16_status, &ei_sml_crc_error, pinfo, crc_check,
									ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
			}
			else {
				proto_tree_add_checksum(crc16_tree, tvb, *offset, hf_sml_crc16, hf_sml_crc16_status, &ei_sml_crc_error, pinfo, 0,
									ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
			}
			*offset+=data;

			/*Message END*/
			if (tvb_get_uint8 (tvb, *offset) == 0){
				proto_tree_add_item (mainlist_list, hf_sml_endOfSmlMsg, tvb, *offset, 1, ENC_BIG_ENDIAN);
				*offset+=1;
			}
			else {
				expert_add_info(pinfo, NULL, &ei_sml_endOfSmlMsg);
				return;
			}

			proto_item_set_end(mainlist, tvb, *offset);

			if (tvb_reported_length_remaining(tvb, *offset) > 0){
				check = tvb_get_uint8(tvb, *offset);

				if (check == LIST_6_ELEMENTS){
					close1 = false;
				}
				else if (check == 0x1b || check == 0){
					close1 = true;
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

			while (tvb_get_uint8(tvb, *offset) == 0){
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

		if (sml_crc_enabled && sml_reassemble){
			crc_file_len = *offset - crc_file_len;
			crc_check = crc16_ccitt_tvb_offset(tvb,*offset-crc_file_len, crc_file_len);

			proto_tree_add_checksum(msgend_tree, tvb, *offset, hf_sml_crc16, hf_sml_crc16_status, &ei_sml_crc_error, pinfo, crc_check,
									ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
		}
		else {
			proto_tree_add_checksum(msgend_tree, tvb, *offset, hf_sml_crc16, hf_sml_crc16_status, &ei_sml_crc_error, pinfo, crc_check,
									ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
		}
		*offset+=2;

		available = tvb_reported_length_remaining(tvb, *offset);
		if (available <= 0){
			close2 = true;
		}
		else {
			if (sml_reassemble){
				proto_item_set_end(file, tvb, *offset);
			}
			else {
				proto_tree_add_item(sml_tree, hf_sml_new_file_marker, tvb, *offset, 0, ENC_NA);
			}
			close1 = false;
		}
	}
}

/* main */
static int dissect_sml (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_) {
	proto_item *sml_item;
	proto_tree *sml_tree;

	unsigned offset = 0;

	/*Check if not SML*/
	if (tvb_get_ntohl(tvb, offset) != ESC_SEQ && tvb_get_uint8(tvb, offset) != LIST_6_ELEMENTS){
		return 0;
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SML");
	col_clear(pinfo->cinfo,COL_INFO);

	/* create display subtree for the protocol */
	sml_item = proto_tree_add_item(tree, proto_sml, tvb, 0, -1, ENC_NA);
	sml_tree = proto_item_add_subtree(sml_item, ett_sml);
	dissect_sml_file(tvb, pinfo, &offset, sml_tree);
	return tvb_captured_length(tvb);
}

static void
sml_fmt_length( char *result, uint32_t length )
{
   snprintf( result, ITEM_LABEL_LENGTH, "%d %s", length, plurality(length, "octet", "octets"));
}

void proto_register_sml (void) {
	module_t *sml_module;
	expert_module_t* expert_sml;

	static hf_register_info hf[] = {
		{ &hf_sml_esc,
			{ "Escape", "sml.esc", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_version_1,
			{ "Version 1", "sml.version_1", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_smlVersion,
			{ "SML Version", "sml.version", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_crc16,
			{ "CRC16", "sml.crc", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_crc16_status,
			{ "CRC16 Status", "sml.crc.status", FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0, NULL, HFILL }},
		{ &hf_sml_endOfSmlMsg,
			{ "End of SML Msg", "sml.end", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_transactionId,
			{ "Transaction ID", "sml.transactionid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_length,
			{ "Length", "sml.length", FT_UINT32, BASE_CUSTOM, CF_FUNC(sml_fmt_length), 0x0, NULL, HFILL }},
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
		{ &hf_sml_timetype,
			{ "Time type", "sml.timetype", FT_UINT8, BASE_HEX, VALS (sml_timetypes), 0x0, NULL, HFILL }},
		{ &hf_sml_objName,
			{ "objName", "sml.objname", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_status,
			{ "Status", "sml.status", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_unit,
			{ "unit", "sml.unit", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_scaler,
			{ "scaler", "sml.scaler", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_value,
			{ "value", "sml.value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_simplevalue,
			{ "simplevalue", "sml.simplevalue", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sml_valueSignature,
			{ "ValueSignature", "sml.valuesignature", FT_BYTES, BASE_NONE, NULL, 0x0,NULL, HFILL }},
		{ &hf_sml_listSignature,
			{ "ListSignature", "sml.listsignature", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_parameterTreePath,
			{ "path_Entry", "sml.parametertreepath", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_attribute,
			{ "attribute", "sml.attribute", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_parameterName,
			{ "parameterName", "sml.parametername", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_procParValue,
			{ "procParValue", "sml.procparvalue", FT_UINT8, BASE_HEX, VALS(procvalues), 0x0, NULL, HFILL }},
		{ &hf_sml_padding,
			{ "Padding", "sml.padding", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_secIndex,
			{ "secIndex", "sml.secindex", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_timestamp,
			{ "timestamp", "sml.timestamp", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sml_localOffset,
			{ "localOffset", "sml.localOffset", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sml_seasonTimeOffset,
			{ "seasonTimeOffset", "sml.seasonTimeOffset", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sml_attentionNo,
			{ "attentionNo", "sml.attentionno", FT_UINT16, BASE_HEX|BASE_RANGE_STRING, RVALS(attentionValues), 0x0, NULL, HFILL }},
		{ &hf_sml_attentionMsg,
			{ "attentionMsg", "sml.attentionmsg", FT_STRING, BASE_NONE, NULL, 0x0 , NULL, HFILL }},
		{ &hf_sml_withRawdata,
			{ "withRawdata", "sml.withrawdata", FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(bools), 0x0 , NULL, HFILL }},
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
			{ "value_R4", "sml.valueR4", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_file_marker,
			{ "---SML-File---", "sml.file_marker", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_new_file_marker,
			{ "---New SML File---", "sml.new_file_marker", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sml_listtype,
			{ "listType", "sml.listtype", FT_UINT8, BASE_HEX, VALS(listtypevalues), 0x0, NULL, HFILL }},
		{ &hf_sml_cosemvalue,
			{ "cosemvalue", "sml.cosemvalue", FT_UINT8, BASE_HEX, VALS(cosemvaluevalues), 0x0, NULL, HFILL } },
	};

	/* Setup protocol subtree array */
	static int *ett[] = {
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
		&ett_sml_simplevalue,
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
		&ett_sml_tuple,
		&ett_sml_secIndex,
		&ett_sml_timestamp,
		&ett_sml_localTimestamp,
		&ett_sml_localOffset,
		&ett_sml_seasonTimeOffset,
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
		&ett_sml_attentionDetails,
		&ett_sml_listtypetype,
		&ett_sml_listtype,
		&ett_sml_timestampedvaluetype,
		&ett_sml_timestampedvalue,
		&ett_sml_cosemvaluetype,
		&ett_sml_cosemvalue,
		&ett_sml_scaler_unit
	};

	static ei_register_info ei[] = {
		{ &ei_sml_tuple_error, { "sml.tuple_error_", PI_PROTOCOL, PI_ERROR, "error in Tuple", EXPFILL }},
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
		{ &ei_sml_version2_not_supported, { "sml.version2_not_supported", PI_UNDECODED, PI_WARN, "SML Version 2 not supported", EXPFILL }},
		{ &ei_sml_attentionNo, { "sml.attentionno.unknown", PI_PROTOCOL, PI_WARN, "unknown attentionNo", EXPFILL }},
		{ &ei_sml_listtype_invalid, { "sml.listtype.invalid", PI_PROTOCOL, PI_WARN, "invalid listtype", EXPFILL } },
		{ &ei_sml_cosemvalue_invalid, { "sml.cosemvalue.invalid", PI_PROTOCOL, PI_WARN, "invalid cosemvalue", EXPFILL } },
	};

	proto_sml = proto_register_protocol("Smart Message Language","SML", "sml");
	sml_handle = register_dissector("sml", dissect_sml, proto_sml);

	sml_module = prefs_register_protocol(proto_sml, NULL);

	prefs_register_bool_preference (sml_module, "reassemble", "Enable reassemble", "Enable reassembling (default is enabled)", &sml_reassemble);
	prefs_register_bool_preference (sml_module, "crc", "Enable crc calculation", "Enable crc (default is disabled)", &sml_crc_enabled);

	proto_register_field_array(proto_sml, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_sml = expert_register_protocol(proto_sml);
	expert_register_field_array(expert_sml, ei, array_length(ei));
}

void proto_reg_handoff_sml(void) {
	dissector_add_for_decode_as_with_preference("tcp.port", sml_handle);
	dissector_add_for_decode_as_with_preference("udp.port", sml_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
