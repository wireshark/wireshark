/* packet-dcerpc-pn-io.c
 * Routines for PROFINET IO dissection
 * (based on DCE-RPC and PN-RT protocols)
 *
 * $ID: $
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
#include <sys/types.h>
#endif

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"



static int proto_pn_io = -1;

static int hf_pn_io_opnum = -1;
static int hf_pn_io_reserved16 = -1;

static int hf_pn_io_array = -1;
static int hf_pn_io_status = -1;
static int hf_pn_io_args_max = -1;
static int hf_pn_io_args_len = -1;
static int hf_pn_io_array_max_count = -1;
static int hf_pn_io_array_offset = -1;
static int hf_pn_io_array_act_count = -1;

static int hf_pn_io_data = -1;

static int hf_pn_io_ar_uuid = -1;
static int hf_pn_io_api = -1;
static int hf_pn_io_slot_nr = -1;
static int hf_pn_io_subslot_nr = -1;
static int hf_pn_io_index = -1;
static int hf_pn_io_seq_number = -1;
static int hf_pn_io_record_data_length = -1;
static int hf_pn_io_padding = -1;
static int hf_pn_io_add_val1 = -1;
static int hf_pn_io_add_val2 = -1;

static int hf_pn_io_block = -1;
static int hf_pn_io_block_type = -1;
static int hf_pn_io_block_length = -1;
static int hf_pn_io_block_version_high = -1;
static int hf_pn_io_block_version_low = -1;

static int hf_pn_io_sessionkey = -1;
static int hf_pn_io_control_command = -1;
static int hf_pn_io_control_command_prmend = -1;
static int hf_pn_io_control_command_applready = -1;
static int hf_pn_io_control_command_release = -1;
static int hf_pn_io_control_command_done = -1;
static int hf_pn_io_control_block_properties = -1;

static int hf_pn_io_error_code = -1;
static int hf_pn_io_error_decode = -1;
static int hf_pn_io_error_code1 = -1;
static int hf_pn_io_error_code2 = -1;
static int hf_pn_io_error_code1_pniorw = -1;
static int hf_pn_io_error_code1_pnio = -1;

static int hf_pn_io_alarm_type = -1;
static int hf_pn_io_alarm_specifier = -1;
static int hf_pn_io_alarm_specifier_sequence = -1;
static int hf_pn_io_alarm_specifier_channel = -1;
static int hf_pn_io_alarm_specifier_manufacturer = -1;
static int hf_pn_io_alarm_specifier_submodule = -1;
static int hf_pn_io_alarm_specifier_ardiagnosis = -1;

static int hf_pn_io_alarm_dst_endpoint = -1;
static int hf_pn_io_alarm_src_endpoint = -1;
static int hf_pn_io_pdu_type = -1;
static int hf_pn_io_pdu_type_type = -1;
static int hf_pn_io_pdu_type_version = -1;
static int hf_pn_io_add_flags = -1;
static int hf_pn_io_window_size = -1;
static int hf_pn_io_tack = -1;
static int hf_pn_io_send_seq_num = -1;
static int hf_pn_io_ack_seq_num = -1;
static int hf_pn_io_var_part_len = -1;

static int hf_pn_io_module_ident_number = -1;
static int hf_pn_io_submodule_ident_number = -1;

static gint ett_pn_io = -1;
static gint ett_pn_io_block = -1;
static gint ett_pn_io_status = -1;
static gint ett_pn_io_rta = -1;
static gint ett_pn_io_pdu_type = -1;
static gint ett_pn_io_add_flags = -1;
static gint ett_pn_io_control_command = -1;

static e_uuid_t uuid_pn_io_device = { 0xDEA00001, 0x6C97, 0x11D1, { 0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D } };
static guint16  ver_pn_io_device = 1;

static e_uuid_t uuid_pn_io_controller = { 0xDEA00002, 0x6C97, 0x11D1, { 0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D } };
static guint16  ver_pn_io_controller = 1;

static e_uuid_t uuid_pn_io_supervisor = { 0xDEA00003, 0x6C97, 0x11D1, { 0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D } };
static guint16  ver_pn_io_supervisor = 1;

static e_uuid_t uuid_pn_io_parameterserver = { 0xDEA00004, 0x6C97, 0x11D1, { 0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D } };
static guint16  ver_pn_io_parameterserver = 1;


static const value_string pn_io_block_type[] = {
	{ 0x0000, "Reserved" },
	{ 0x0001, "Alarm Notification High"},
	{ 0x0002, "Alarm Notification Low"},
	{ 0x0008, "WriteRecordReq"},
	{ 0x8008, "WriteRecordRes"},
	{ 0x0009, "ReadRecordReq"},
	{ 0x8009, "ReadRecordRes"},
	{ 0x0010, "ManufacturerSpecificDiagnosisBlock"},
	{ 0x0011, "ChannelDiagnosisBlock"},
	{ 0x0012, "ExpectedIdentificationDataBlock"},
	{ 0x0014, "SubstituteValue RecordDataRead"},
	{ 0x0015, "RecordInputDataObjectElement"},
	{ 0x0016, "RecordOutputDataObjectElement"},
	{ 0x0017, "RecordOutputDataSubstituteObjectElement"},
	{ 0x0018, "ARData"},
	{ 0x0019, "LogData"},
	{ 0x001A, "APIData"},
	{ 0x0020, "I&M0"},
	{ 0x0021, "I&M1"},
	{ 0x0022, "I&M2"},
	{ 0x0023, "I&M3"},
	{ 0x0024, "I&M4"},
	{ 0x8001, "Alarm Ack High"},
	{ 0x8002, "Alarm Ack Low"},
	{ 0x0101, "ARBlockReq"},
	{ 0x8101, "ARBlockRes"},
	{ 0x0102, "IOCRBlockReq"},
	{ 0x8102, "IOCRBlockRes"},
	{ 0x0103, "AlarmCRBlockReq"},
	{ 0x8103, "AlarmCRBlockRes"},
	{ 0x0104, "ExpectedSubmoduleBlockReq"},
	{ 0x8104, "ModuleDiffBlock"},
	{ 0x0105, "PrmServerBlockReq"},
	{ 0x8105, "PrmServerBlockRes"},
	{ 0x0110, "IODBlockReq"},
	{ 0x8110, "IODBlockRes"},
	{ 0x0111, "IODBlockReq"},
	{ 0x8111, "IODBlockRes"},
	{ 0x0112, "IOXBlockReq"},
	{ 0x8112, "IOXBlockRes"},
	{ 0x0113, "IOXBlockReq"},
	{ 0x8113, "IOXBlockRes"},
	{ 0x0114, "ReleaseBlockReq"},
	{ 0x8114, "ReleaseBlockRes"},
	{ 0, NULL }
};

static const value_string pn_io_alarm_type[] = {
	{ 0x0000, "Reserved" },
	{ 0x0001, "Diagnosis" },
	{ 0x0002, "Process" },
	{ 0x0003, "Pull" },
	{ 0x0004, "Plug" },
	{ 0x0005, "Status" },
	{ 0x0006, "Update" },
	{ 0x0007, "Redundancy" },
	{ 0x0008, "Controlled by supervisor" },
	{ 0x0009, "Released by supervisor" },
	{ 0x000A, "Plug wrong submodule" },
	{ 0x000B, "Return of submodule" },
    /* 0x000C - 0x001F reserved */
    /* 0x0020 - 0x007F manufacturer specific */
    /* 0x0080 - 0x00FF reserved for profiles */
    /* 0x0100 - 0xFFFF reserved */
    { 0, NULL }
};

static const value_string pn_io_pdu_type[] = {
	{ 0x01, "Data-RTA-PDU" },
	{ 0x02, "NACK-RTA-PDU" },
	{ 0x03, "ACK-RTA-PDU" },
	{ 0x04, "ERR-RTA-PDU" },
    { 0, NULL }
};

static const value_string pn_io_error_code[] = {
	{ 0x00, "OK" },
	{ 0x81, "PNIO" },
	{ 0xCF, "RTA error" },
	{ 0xDA, "AlarmAck" },
	{ 0xDB, "IODConnectRes" },
	{ 0xDC, "IODReleaseRes" },
	{ 0xDD, "IODControlRes" },
	{ 0xDE, "IODReadRes" },
	{ 0xDF, "IODWriteRes" },
    { 0, NULL }
};

static const value_string pn_io_error_decode[] = {
	{ 0x00, "OK" },
	{ 0x80, "PNIORW" },
	{ 0x81, "PNIO" },
    { 0, NULL }
};

/*
XXX: the next 2 are dependant on error_code and error_decode

e.g.: CL-RPC error:
error_code .. see above
error_decode .. 0x81
error_code1 .. 0x69
error_code2 ..
1 RPC_ERR_REJECTED
2 RPC_ERR_FAULTED
3 RPC_ERR_TIMEOUT
4 RPC_ERR_IN_ARGS
5 RPC_ERR_OUT_ARGS
6 RPC_ERR_DECODE
7 RPC_ERR_PNIO_OUT_ARGS
8 Application Timeout
*/

/* XXX: add some more error codes here */
static const value_string pn_io_error_code1[] = {
	{ 0x00, "OK" },
    { 0, NULL }
};

/* XXX: add some more error codes here */
static const value_string pn_io_error_code2[] = {
	{ 0x00, "OK" },
    { 0, NULL }
};

static const value_string pn_io_error_code1_pniorw[] = {
	{ 0x0a /* 10*/, "application" },
	{ 0x0b /* 11*/, "access" },
	{ 0x0c /* 12*/, "resource" },
	{ 0x0d /* 13*/, "user specific(13)" },
	{ 0x0e /* 14*/, "user specific(14)" },
	{ 0x0f /* 15*/, "user specific(15)" },
    { 0, NULL }
};

static const value_string pn_io_error_code1_pnio[] = {
	{ 0x00 /*  0*/, "Reserved" },
	{ 0x01 /*  1*/, "Connect: Faulty ARBlockReq" },
	{ 0x02 /*  2*/, "Connect: Faulty IOCRBlockReq" },
	{ 0x03 /*  3*/, "Connect: Faulty ExpectedSubmoduleBlockReq" },
	{ 0x04 /*  4*/, "Connect: Faulty AlarmCRBlockReq" },
	{ 0x05 /*  5*/, "Connect: Faulty PrmServerBlockReq" },

	{ 0x14 /* 20*/, "IODControl: Faulty ControlBlockConnect" },
	{ 0x15 /* 21*/, "IODControl: Faulty ControlBlockPlug" },
	{ 0x16 /* 22*/, "IOXControl: Faulty ControlBlock after a connect est." },
	{ 0x17 /* 23*/, "IOXControl: Faulty ControlBlock a plug alarm" },

    { 0x28 /* 40*/, "Release: Faulty ReleaseBlock" },

    { 0x3c /* 60*/, "AlarmAck Error Codes" },
    { 0x3d /* 61*/, "CMDEV" },
    { 0x3e /* 62*/, "CMCTL" },
    { 0x3f /* 63*/, "NRPM" },
    { 0x40 /* 64*/, "RMPM" },
    { 0x41 /* 65*/, "ALPMI" },
    { 0x42 /* 66*/, "ALPMR" },
    { 0x43 /* 67*/, "LMPM" },
    { 0x44 /* 68*/, "MMAC" },
    { 0x45 /* 69*/, "RPC" },
    { 0x46 /* 70*/, "APMR" },
    { 0x47 /* 71*/, "APMS" },
    { 0x48 /* 72*/, "CPM" },
    { 0x49 /* 73*/, "PPM" },
    { 0x4a /* 74*/, "DCPUCS" },
    { 0x4b /* 75*/, "DCPUCR" },
    { 0x4c /* 76*/, "DCPMCS" },
    { 0x4d /* 77*/, "DCPMCR" },
    { 0x4e /* 78*/, "FSPM" },
	{ 0xfd /*253*/, "RTA_ERR_CLS_PROTOCOL" },
    { 0, NULL }
};



/* dissect the four status (error) fields */
static int
dissect_PNIO_status(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint8  u8ErrorCode;
    guint8  u8ErrorDecode;
    guint8  u8ErrorCode1;
    guint8  u8ErrorCode2;

    proto_item *sub_item;
	proto_tree *sub_tree;
	guint32 u32SubStart;
    int bytemask = (drep[0] & 0x10) ? 3 : 0;
    const value_string *error_code1_vals;



    /* status */
    sub_item = proto_tree_add_item(tree, hf_pn_io_status, tvb, offset, 0, FALSE);
	sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_status);
    u32SubStart = offset;

    /* the PNIOStatus field is existing in both the RPC and the application data,
     * depending on the current PDU.
     * As the byte representation of these layers are different, this has to be handled
     * in a somewhat different way than elsewhere. */

    dissect_dcerpc_uint8(tvb, offset+(0^bytemask), pinfo, sub_tree, drep, 
                        hf_pn_io_error_code, &u8ErrorCode);
	dissect_dcerpc_uint8(tvb, offset+(1^bytemask), pinfo, sub_tree, drep, 
                        hf_pn_io_error_decode, &u8ErrorDecode);

    switch(u8ErrorDecode) {
    case(0x80): /* PNIORW */
	    dissect_dcerpc_uint8(tvb, offset+(2^bytemask), pinfo, sub_tree, drep, 
                            hf_pn_io_error_code1_pniorw, &u8ErrorCode1);
        error_code1_vals = pn_io_error_code1_pniorw;
        break;
    case(0x81): /* PNIO */
	    dissect_dcerpc_uint8(tvb, offset+(2^bytemask), pinfo, sub_tree, drep, 
                            hf_pn_io_error_code1_pnio, &u8ErrorCode1);
        error_code1_vals = pn_io_error_code1_pnio;
        break;
    default:
	    dissect_dcerpc_uint8(tvb, offset+(2^bytemask), pinfo, sub_tree, drep, 
                            hf_pn_io_error_code1, &u8ErrorCode1);
        error_code1_vals = pn_io_error_code1;
    }

    /* XXX - this has to be decode specific too */
	dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep, 
                        hf_pn_io_error_code2, &u8ErrorCode2);

    offset +=4;

    if(u8ErrorCode == 0 && u8ErrorDecode == 0 && u8ErrorCode1 == 0 && u8ErrorCode2 == 0) {
        proto_item_append_text(sub_item, ": OK");
        if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_str(pinfo->cinfo, COL_INFO, ", OK");
    } else {
        proto_item_append_text(sub_item, ": Error Code: \"%s\", Decode: \"%s\", Code1: \"%s\" Code2: 0x%x", 
            val_to_str(u8ErrorCode, pn_io_error_code, "(0x%x)"),
            val_to_str(u8ErrorDecode, pn_io_error_decode, "(0x%x)"),
            val_to_str(u8ErrorCode1, error_code1_vals, "(0x%x)"),
            u8ErrorCode2);
        if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_fstr(pinfo->cinfo, COL_INFO, ", Error Code: %s, Decode: %s, Code1: 0x%x Code2: 0x%x",
            val_to_str(u8ErrorCode, pn_io_error_code, "(0x%x)"),
            val_to_str(u8ErrorDecode, pn_io_error_decode, "(0x%x)"),
            u8ErrorCode1,
            u8ErrorCode2);
    }
	proto_item_set_len(sub_item, offset - u32SubStart);

    return offset;
}


/* dissect the alarm specifier */
static int
dissect_Alarm_specifier(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16AlarmSpecifierSequence;
    guint16 u16AlarmSpecifierChannel;
    guint16 u16AlarmSpecifierManufacturer;
    guint16 u16AlarmSpecifierSubmodule;
    guint16 u16AlarmSpecifierAR;
    proto_item *sub_item;
	proto_tree *sub_tree;

    /* alarm specifier */
	sub_item = proto_tree_add_item(tree, hf_pn_io_alarm_specifier, tvb, offset, 2, FALSE);
	sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_pdu_type);

	dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_alarm_specifier_sequence, &u16AlarmSpecifierSequence);
    u16AlarmSpecifierSequence &= 0x07FF;
	dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_alarm_specifier_channel, &u16AlarmSpecifierChannel);
    u16AlarmSpecifierChannel = (u16AlarmSpecifierChannel &0x0800) >> 11;
	dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_alarm_specifier_manufacturer, &u16AlarmSpecifierManufacturer);
    u16AlarmSpecifierManufacturer = (u16AlarmSpecifierManufacturer &0x1000) >> 12;
	dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_alarm_specifier_submodule, &u16AlarmSpecifierSubmodule);
    u16AlarmSpecifierSubmodule = (u16AlarmSpecifierSubmodule & 0x2000) >> 13;
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_alarm_specifier_ardiagnosis, &u16AlarmSpecifierAR);
    u16AlarmSpecifierAR = (u16AlarmSpecifierAR & 0x8000) >> 15;


    proto_item_append_text(sub_item, ", Sequence: %u, Channel: %u, Manuf: %u, Submodule: %u AR: %u", 
        u16AlarmSpecifierSequence, u16AlarmSpecifierChannel, 
        u16AlarmSpecifierManufacturer, u16AlarmSpecifierSubmodule, u16AlarmSpecifierAR);

    return offset;
}


/* dissect the alarm header */
static int
dissect_Alarm_header(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16AlarmType;
    guint32 u32Api;
    guint16 u16SlotNr;
    guint16 u16SubslotNr;

	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_alarm_type, &u16AlarmType);
	offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_api, &u32Api);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_slot_nr, &u16SlotNr);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_subslot_nr, &u16SubslotNr);

    if (check_col(pinfo->cinfo, COL_INFO))
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s, Slot: %u/%u", 
        val_to_str(u16AlarmType, pn_io_alarm_type, "Unknown"),
        u16SlotNr, u16SubslotNr);

    return offset;
}


/* dissect the alarm note block */
static int
dissect_Alarm_note_block(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep, guint16 body_length)
{
    guint32 u32ModuleIdentNumber;
    guint32 u32SubmoduleIdentNumber;

    if (check_col(pinfo->cinfo, COL_INFO))
	    col_append_str(pinfo->cinfo, COL_INFO, ", Alarm Notification");

    offset = dissect_Alarm_header(tvb, offset, pinfo, tree, drep);
    
	offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_module_ident_number, &u32ModuleIdentNumber);
	offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_submodule_ident_number, &u32SubmoduleIdentNumber);

    offset = dissect_Alarm_specifier(tvb, offset, pinfo, tree, drep);

    /* XXX - dissect AlarmItem */
    body_length -= 20;
    proto_tree_add_string_format(tree, hf_pn_io_data, tvb, offset, body_length, "data", 
        "Alarm Item Data: %u bytes", body_length);
    offset += body_length;

    return offset;
}


/* dissect the alarm acknowledge block */
static int
dissect_Alarm_ack_block(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    if (check_col(pinfo->cinfo, COL_INFO))
	    col_append_str(pinfo->cinfo, COL_INFO, ", Alarm Ack");

    offset = dissect_Alarm_header(tvb, offset, pinfo, tree, drep);

    offset = dissect_Alarm_specifier(tvb, offset, pinfo, tree, drep);

    offset = dissect_PNIO_status(tvb, offset, pinfo, tree, drep);

    return offset;
}


/* dissect the read/write header */
static int
dissect_ReadWrite_header(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    e_uuid_t uuid;
    guint32 u32Api;
    guint16 u16SlotNr;
    guint16 u16SubslotNr;
    guint16 u16Index;
    guint16 u16SeqNr;

	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_seq_number, &u16SeqNr);

    offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_ar_uuid, &uuid);

	offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_api, &u32Api);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_slot_nr, &u16SlotNr);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_subslot_nr, &u16SubslotNr);
    proto_tree_add_string_format(tree, hf_pn_io_padding, tvb, offset, 2, "padding", "Padding: 2 bytes");
    offset += 2;
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_index, &u16Index);

    if (check_col(pinfo->cinfo, COL_INFO))
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", Api: %u, Slot: %u/%u",
            u32Api, u16SlotNr, u16SubslotNr);

    return offset;
}


/* dissect the read/write request block */
static int
dissect_ReadWrite_rqst_block(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32RecDataLen;


    offset = dissect_ReadWrite_header(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_record_data_length, &u32RecDataLen);
    /* XXX: don't know how to handle the optional TargetARUUID */

    if (check_col(pinfo->cinfo, COL_INFO))
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", %u bytes",
            u32RecDataLen);

    return offset;
}


/* dissect the read/write response block */
static int
dissect_ReadWrite_resp_block(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32RecDataLen;
    guint16 u16AddVal1;
    guint16 u16AddVal2;


    offset = dissect_ReadWrite_header(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_record_data_length, &u32RecDataLen);

	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_add_val1, &u16AddVal1);

	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_add_val2, &u16AddVal2);

    if (check_col(pinfo->cinfo, COL_INFO))
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", %u bytes",
            u32RecDataLen);

    return offset;
}


/* dissect the control/connect block */
static int
dissect_ControlConnect_block(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    e_uuid_t    ar_uuid;
	proto_item *sub_item;
	proto_tree *sub_tree;
    guint16     u16PrmEnd;
    guint16     u16ApplReady;
    guint16     u16Release;
    guint16     u16CmdDone;


    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_reserved16, NULL);

    offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_ar_uuid, &ar_uuid);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_sessionkey, NULL);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_reserved16, NULL);

    sub_item = proto_tree_add_item(tree, hf_pn_io_control_command, tvb, offset, 2, FALSE);
	sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_control_command);

    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_control_command_prmend, &u16PrmEnd);
    if(u16PrmEnd & 0x0001) {
        proto_item_append_text(sub_item, ", Parameter End");
        if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_fstr(pinfo->cinfo, COL_INFO, ", Command: \"Parameter End\"");
    }
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_control_command_applready, &u16ApplReady);
    if((u16ApplReady >> 1) & 0x0001) {
        proto_item_append_text(sub_item, ", Application Ready");
        if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_fstr(pinfo->cinfo, COL_INFO, ", Command: \"Application Ready\"");
    }
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_control_command_release, &u16Release);
    if((u16Release >> 2) & 0x0001) {
        proto_item_append_text(sub_item, ", Release");
        if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_fstr(pinfo->cinfo, COL_INFO, ", Command: \"Release\"");
    }
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_control_command_done, &u16CmdDone);
    if((u16CmdDone >> 3) & 0x0001) {
        proto_item_append_text(sub_item, ", Done");
        if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_fstr(pinfo->cinfo, COL_INFO, ", Command: \"Done\"");
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_control_block_properties, NULL);

    return offset;
}


/* dissect one PN-IO block (depending on the block type) */
static int
dissect_block(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep, guint32 u32Idx)
{
    guint16 u16BlockType;
    guint16 u16BlockLength;
    guint8 u8BlockVersionHigh;
    guint8 u8BlockVersionLow;
	proto_item *sub_item;
	proto_tree *sub_tree;
	guint32 u32SubStart;
    guint16 u16BodyLength;


    /* from here, we only have big endian (network byte ordering) */
    drep[0] &= ~0x10;

    sub_item = proto_tree_add_item(tree, hf_pn_io_block, tvb, offset, 0, FALSE);
	sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_block);
    u32SubStart = offset;

	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_block_type, &u16BlockType);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_block_length, &u16BlockLength);
	offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_block_version_high, &u8BlockVersionHigh);
	offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_block_version_low, &u8BlockVersionLow);

    /* block length is without type and length fields, but with version field */
    /* as it's already dissected, remove it */
    u16BodyLength = u16BlockLength - 2;

    switch(u16BlockType) {
    case(0x0001):
    case(0x0002):
        dissect_Alarm_note_block(tvb, offset, pinfo, sub_tree, drep, u16BodyLength);
        break;
    case(0x0110):
    case(0x0112):
    case(0x0114):
        if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
            val_to_str(u16BlockType, pn_io_block_type, "Unknown"));
        dissect_ControlConnect_block(tvb, offset, pinfo, sub_tree, drep);
        break;
    case(0x0008):
    case(0x0009):
        dissect_ReadWrite_rqst_block(tvb, offset, pinfo, sub_tree, drep);
        break;
    case(0x8001):
    case(0x8002):
        dissect_Alarm_ack_block(tvb, offset, pinfo, sub_tree, drep);
        break;
    case(0x8008):
    case(0x8009):
        dissect_ReadWrite_resp_block(tvb, offset, pinfo, sub_tree, drep);
        break;
    case(0x8110):
    case(0x8112):
    case(0x8114):
        if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
            val_to_str(u16BlockType, pn_io_block_type, "Unknown"));
        dissect_ControlConnect_block(tvb, offset, pinfo, sub_tree, drep);
        break;
    default:
        if (check_col(pinfo->cinfo, COL_INFO) && u32Idx < 3)
	        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
            val_to_str(u16BlockType, pn_io_block_type, "Unknown"));
    	proto_tree_add_string_format(sub_tree, hf_pn_io_data, tvb, offset, u16BodyLength, "undecoded", "Undecoded Data: %d bytes", u16BodyLength);
    }
    offset += u16BodyLength;

	proto_item_append_text(sub_item, "[%u]: Type=\"%s\" (0x%04x), Length=%u(+4), Version=%u.%u", 
		u32Idx, val_to_str(u16BlockType, pn_io_block_type, "Unknown"), u16BlockType,
        u16BlockLength, u8BlockVersionHigh, u8BlockVersionLow);
	proto_item_set_len(sub_item, offset - u32SubStart);

    return offset;
}


/* dissect any number of PN-IO blocks */
static int
dissect_blocks(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32Idx = 0;
    

    while(tvb_length(tvb) > (guint) offset) {
        offset = dissect_block(tvb, offset, pinfo, tree, drep, u32Idx);
        u32Idx++;
    }

    if(u32Idx > 3) {
        if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_fstr(pinfo->cinfo, COL_INFO, ", ... (%u blocks)",
            u32Idx);
    }
	return offset;
}


/* dissect a PN-IO (DCE-RPC) request header */
static int
dissect_IPNIO_rqst_header(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32ArgsMax;
    guint32 u32ArgsLen;
    guint32 u32MaxCount;
    guint32 u32Offset;
    guint32 u32ArraySize;

	proto_item *sub_item;
	proto_tree *sub_tree;
	guint32 u32SubStart;


    /* args_max */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_args_max, &u32ArgsMax);
    /* args_len */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_args_len, &u32ArgsLen);

    sub_item = proto_tree_add_item(tree, hf_pn_io_array, tvb, offset, 0, FALSE);
	sub_tree = proto_item_add_subtree(sub_item, ett_pn_io);
    u32SubStart = offset;

    /* RPC array header */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_array_max_count, &u32MaxCount);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_array_offset, &u32Offset);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_array_act_count, &u32ArraySize);

	proto_item_append_text(sub_item, ": Max: %u, Offset: %u, Size: %u", 
        u32MaxCount, u32Offset, u32ArraySize);
	proto_item_set_len(sub_item, offset - u32SubStart);

    return offset;
}


/* dissect a PN-IO (DCE-RPC) response header */
static int
dissect_IPNIO_resp_header(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32ArgsLen;
    guint32 u32MaxCount;
    guint32 u32Offset;
    guint32 u32ArraySize;

	proto_item *sub_item;
	proto_tree *sub_tree;
	guint32 u32SubStart;

    offset = dissect_PNIO_status(tvb, offset, pinfo, tree, drep);

    /* args_len */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_args_len, &u32ArgsLen);

    sub_item = proto_tree_add_item(tree, hf_pn_io_array, tvb, offset, 0, FALSE);
	sub_tree = proto_item_add_subtree(sub_item, ett_pn_io);
    u32SubStart = offset;

    /* RPC array header */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_array_max_count, &u32MaxCount);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_array_offset, &u32Offset);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_array_act_count, &u32ArraySize);

    proto_item_append_text(sub_item, ": Max: %u, Offset: %u, Size: %u", 
        u32MaxCount, u32Offset, u32ArraySize);
	proto_item_set_len(sub_item, offset - u32SubStart);

    return offset;
}


/* dissect a PN-IO connect request */
static int
dissect_IPNIO_Connect_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    
    offset = dissect_IPNIO_rqst_header(tvb, offset, pinfo, tree, drep);

    offset = dissect_blocks(tvb, offset, pinfo, tree, drep);

	return offset;
}


/* dissect a PN-IO connect response */
static int
dissect_IPNIO_Connect_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

    offset = dissect_IPNIO_resp_header(tvb, offset, pinfo, tree, drep);

    offset = dissect_blocks(tvb, offset, pinfo, tree, drep);

	return offset;
}


/* dissect a PN-IO release request */
static int
dissect_IPNIO_Release_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    
    offset = dissect_IPNIO_rqst_header(tvb, offset, pinfo, tree, drep);

    offset = dissect_blocks(tvb, offset, pinfo, tree, drep);

	return offset;
}


/* dissect a PN-IO release response */
static int
dissect_IPNIO_Release_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

    offset = dissect_IPNIO_resp_header(tvb, offset, pinfo, tree, drep);

    offset = dissect_blocks(tvb, offset, pinfo, tree, drep);

	return offset;
}


/* dissect a PN-IO control request */
static int
dissect_IPNIO_Control_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    
    offset = dissect_IPNIO_rqst_header(tvb, offset, pinfo, tree, drep);

    offset = dissect_blocks(tvb, offset, pinfo, tree, drep);

    return offset;
}


/* dissect a PN-IO control response */
static int
dissect_IPNIO_Control_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

    offset = dissect_IPNIO_resp_header(tvb, offset, pinfo, tree, drep);

    offset = dissect_blocks(tvb, offset, pinfo, tree, drep);

    return offset;
}


/* dissect a PN-IO read request */
static int
dissect_IPNIO_Read_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    
    offset = dissect_IPNIO_rqst_header(tvb, offset, pinfo, tree, drep);

    offset = dissect_block(tvb, offset, pinfo, tree, drep, 0);

	return offset;
}


/* dissect a PN-IO read response */
static int
dissect_IPNIO_Read_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    gint remain;

    offset = dissect_IPNIO_resp_header(tvb, offset, pinfo, tree, drep);

    offset = dissect_block(tvb, offset, pinfo, tree, drep, 0);

    /* XXX - remaining bytes: dissection not yet implemented */
    remain = tvb_length_remaining(tvb, offset);
    proto_tree_add_string_format(tree, hf_pn_io_data, tvb, offset, remain, "data", "User Data: %d bytes", remain);
    offset += remain;

	return offset;
}


/* dissect a PN-IO write request */
static int
dissect_IPNIO_Write_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    gint remain;

    offset = dissect_IPNIO_rqst_header(tvb, offset, pinfo, tree, drep);

    offset = dissect_block(tvb, offset, pinfo, tree, drep, 0);

    /* XXX - remaining bytes: dissection not yet implemented */
    remain = tvb_length_remaining(tvb, offset);
    proto_tree_add_string_format(tree, hf_pn_io_data, tvb, offset, remain, "data", "User Data: %d bytes", remain);
    offset += remain;

	return offset;
}


/* dissect a PN-IO write response */
static int
dissect_IPNIO_Write_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

    offset = dissect_IPNIO_resp_header(tvb, offset, pinfo, tree, drep);

    offset = dissect_block(tvb, offset, pinfo, tree, drep, 0);

	return offset;
}


/* dissect a PN-IO Data PDU (on top of PN-RT protocol) */
static int
dissect_PNIO_Data(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    proto_item *data_item;
/*	proto_tree *data_tree;*/


    /* satisfy gcc warning about "unused parameter" */
    /* (will be used, when dissection is continued here) */
    if(drep == drep);

	data_item = proto_tree_add_protocol_format(tree, proto_pn_io, tvb, 0, tvb_length(tvb),
				"PROFINET IO Data: %u bytes", tvb_length(tvb));

#if 0
    /* XXX - remaining bytes: dissection not yet implemented */
    data_tree = proto_item_add_subtree(data_item, ett_pn_io_rta);

    proto_tree_add_string_format(data_tree, hf_pn_io_data, tvb, 0, tvb_length(tvb), "data", 
        "PN-IO Data: %u bytes", tvb_length(tvb));
#endif

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
	    col_add_str(pinfo->cinfo, COL_PROTOCOL, "PNIO");

    return offset;
}


/* dissect a PN-IO RTA PDU (on top of PN-RT protocol) */
static int
dissect_PNIO_RTA(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16AlarmDstEndpoint;
    guint16 u16AlarmSrcEndpoint;
    guint8  u8PDUType;
    guint8  u8PDUVersion;
    guint8  u8WindowSize;
    guint8  u8Tack;
    guint16 u16SendSeqNum;
    guint16 u16AckSeqNum;
    guint16 u16VarPartLen;

    proto_item *rta_item;
	proto_tree *rta_tree;

    proto_item *sub_item;
	proto_tree *sub_tree;

	rta_item = proto_tree_add_protocol_format(tree, proto_pn_io, tvb, 0, 0,
				"PROFINET IO Alarm");
	rta_tree = proto_item_add_subtree(rta_item, ett_pn_io_rta);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, rta_tree, drep, 
                    hf_pn_io_alarm_dst_endpoint, &u16AlarmDstEndpoint);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, rta_tree, drep, 
                    hf_pn_io_alarm_src_endpoint, &u16AlarmSrcEndpoint);

    if (check_col(pinfo->cinfo, COL_INFO))
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", Src: 0x%x, Dst: 0x%x",
        u16AlarmSrcEndpoint, u16AlarmDstEndpoint);

    /* PDU type */
	sub_item = proto_tree_add_item(rta_tree, hf_pn_io_pdu_type, tvb, offset, 1, FALSE);
	sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_pdu_type);
    dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep, 
                    hf_pn_io_pdu_type_type, &u8PDUType);
    u8PDUType &= 0x0F;
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep, 
                    hf_pn_io_pdu_type_version, &u8PDUVersion);
    u8PDUVersion >>= 4;
    proto_item_append_text(sub_item, ", Type: %s, Version: %u", 
        val_to_str(u8PDUType, pn_io_pdu_type, "Unknown"),
        u8PDUVersion);

    /* additional flags */
	sub_item = proto_tree_add_item(rta_tree, hf_pn_io_add_flags, tvb, offset, 1, FALSE);
	sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_add_flags);
    dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep, 
                    hf_pn_io_window_size, &u8WindowSize);
    u8WindowSize &= 0x0F;
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep, 
                    hf_pn_io_tack, &u8Tack);
    u8Tack >>= 4;
    proto_item_append_text(sub_item, ", Window Size: %u, Tack: %u", 
        u8WindowSize, u8Tack);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, rta_tree, drep, 
                    hf_pn_io_send_seq_num, &u16SendSeqNum);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, rta_tree, drep, 
                    hf_pn_io_ack_seq_num, &u16AckSeqNum);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, rta_tree, drep, 
                    hf_pn_io_var_part_len, &u16VarPartLen);

    switch(u8PDUType & 0x0F) {
    case(1):    /* Data-RTA */
    	if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_str(pinfo->cinfo, COL_INFO, ", Data-RTA");
        offset = dissect_block(tvb, offset, pinfo, rta_tree, drep, 0);
        break;
    case(2):    /* NACK-RTA */
    	if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_str(pinfo->cinfo, COL_INFO, ", NACK-RTA");
        /* no additional data */
        break;
    case(3):    /* ACK-RTA */
    	if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_str(pinfo->cinfo, COL_INFO, ", ACK-RTA");
        /* no additional data */
        break;
    case(4):    /* ERR-RTA */
    	if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_str(pinfo->cinfo, COL_INFO, ", ERR-RTA");
        offset = dissect_PNIO_status(tvb, offset, pinfo, rta_tree, drep);
        break;
    default:
        proto_tree_add_string_format(tree, hf_pn_io_data, tvb, 0, tvb_length(tvb), "data", 
            "PN-IO Alarm: unknown PDU type 0x%x", u8PDUType);    
    }

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
	    col_add_str(pinfo->cinfo, COL_PROTOCOL, "PNIO-AL");

    return offset;
}


/* possibly dissect a PN-IO PN-RT packet */
static gboolean
dissect_PNIO_heur(tvbuff_t *tvb, 
	packet_info *pinfo, proto_tree *tree)
{
    guint8  drep_data = 0;
    guint8  *drep = &drep_data;
	guint8  u8CBAVersion;
    guint16 u16FrameID;


    /* the sub tvb will NOT contain the frame_id here! */
    u16FrameID = GPOINTER_TO_UINT(pinfo->private_data);

    u8CBAVersion = tvb_get_guint8 (tvb, 0);

    /* is this a PNIO class 2 data packet? */
	/* frame id must be in valid range (cyclic Real-Time, class=2) */
	if (u16FrameID >= 0x8000 && u16FrameID < 0xbf00) {
        dissect_PNIO_Data(tvb, 0, pinfo, tree, drep);
        return TRUE;
    }

    /* is this a PNIO class 1 data packet? */
	/* frame id must be in valid range (cyclic Real-Time, class=1) and
     * first byte (CBA version field) has to be != 0x11 */
	if (u16FrameID >= 0xc000 && u16FrameID < 0xfb00 && u8CBAVersion != 0x11) {
        dissect_PNIO_Data(tvb, 0, pinfo, tree, drep);
        return TRUE;
    }

    /* is this a PNIO high priority alarm packet? */
    if(u16FrameID == 0xfc01) {
    	if (check_col(pinfo->cinfo, COL_INFO))
	        col_add_str(pinfo->cinfo, COL_INFO, "Alarm High");

        dissect_PNIO_RTA(tvb, 0, pinfo, tree, drep);
        return TRUE;
    }

    /* is this a PNIO low priority alarm packet? */
    if(u16FrameID == 0xfe01) {
    	if (check_col(pinfo->cinfo, COL_INFO))
	        col_add_str(pinfo->cinfo, COL_INFO, "Alarm Low");

        dissect_PNIO_RTA(tvb, 0, pinfo, tree, drep);
        return TRUE;
    }

    /* this PN-RT packet doesn't seem to be PNIO specific */
    return FALSE;
}


/* the PNIO dcerpc interface table */
static dcerpc_sub_dissector pn_io_dissectors[] = {
{ 0, "Connect", dissect_IPNIO_Connect_rqst, dissect_IPNIO_Connect_resp },
{ 1, "Release", dissect_IPNIO_Release_rqst, dissect_IPNIO_Release_resp },
{ 2, "Read",    dissect_IPNIO_Read_rqst,    dissect_IPNIO_Read_resp },
{ 3, "Write",   dissect_IPNIO_Write_rqst,   dissect_IPNIO_Write_resp },
{ 4, "Control", dissect_IPNIO_Control_rqst, dissect_IPNIO_Control_resp },
	{ 0, NULL, NULL, NULL }
};


void
proto_register_pn_io (void)
{
	static hf_register_info hf[] = {
	{ &hf_pn_io_opnum,
		{ "Operation", "pn_io.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_io_reserved16,
		{ "Reserved", "pn_io.reserved16", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
	{ &hf_pn_io_array,
        { "Array", "pn_io.array", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
	{ &hf_pn_io_status,
		{ "Status", "pn_io.status", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
	{ &hf_pn_io_args_max,
		{ "ArgsMaximum", "pn_io.args_max", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_io_args_len,
		{ "ArgsLength", "pn_io.args_len", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_io_array_max_count,
		{ "MaximumCount", "pn_io.array_max_count", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_io_array_offset,
		{ "Offset", "pn_io.array_offset", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_io_array_act_count,
		{ "ActualCount", "pn_io.array_act_count", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_ar_uuid,
      { "ARUUID", "pn_io.ar_uuid", FT_STRING, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_api,
      { "API", "pn_io.api", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_slot_nr,
      { "SlotNumber", "pn_io.slot_nr", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_subslot_nr,
      { "SubslotNumber", "pn_io.subslot_nr", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_index,
      { "Index", "pn_io.index", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_seq_number,
      { "SeqNumber", "pn_io.seq_number", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_record_data_length,
      { "RecordDataLength", "pn_io.record_data_length", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_padding,
      { "Padding", "pn_io.padding", FT_STRING, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_add_val1,
      { "AdditionalValue1", "pn_io.add_val1", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_add_val2,
      { "AdditionalValue2", "pn_io.add_val2", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_block_type,
      { "BlockType", "pn_io.block_type", FT_UINT16, BASE_HEX, VALS(pn_io_block_type), 0x0, "", HFILL }},
    { &hf_pn_io_block_length,
      { "BlockLength", "pn_io.block_length", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_block_version_high,
      { "BlockVersionHigh", "pn_io.block_version_high", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_block_version_low,
      { "BlockVersionLow", "pn_io.block_version_low", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_sessionkey,
      { "SessionKey", "pn_io.session_key", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_control_command,
      { "ControlCommand", "pn_io.control_command", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_control_command_prmend,
      { "PrmEnd", "pn_io.control_command.prmend", FT_UINT16, BASE_DEC, NULL, 0x0001, "", HFILL }},
    { &hf_pn_io_control_command_applready,
      { "ApplicationReady", "pn_io.control_command.applready", FT_UINT16, BASE_DEC, NULL, 0x0002, "", HFILL }},
    { &hf_pn_io_control_command_release,
      { "Release", "pn_io.control_command.release", FT_UINT16, BASE_DEC, NULL, 0x0004, "", HFILL }},
    { &hf_pn_io_control_command_done,
      { "Done", "pn_io.control_command.done", FT_UINT16, BASE_DEC, NULL, 0x0008, "", HFILL }},
    { &hf_pn_io_control_block_properties,
      { "ControlBlockProperties", "pn_io.control_block_properties", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_pn_io_error_code,
      { "ErrorCode", "pn_io.error_code", FT_UINT8, BASE_HEX, VALS(pn_io_error_code), 0x0, "", HFILL }},
    { &hf_pn_io_error_decode,
      { "ErrorDecode", "pn_io.error_decode", FT_UINT8, BASE_HEX, VALS(pn_io_error_decode), 0x0, "", HFILL }},
    { &hf_pn_io_error_code1,
      { "ErrorCode1", "pn_io.error_code1", FT_UINT8, BASE_HEX, VALS(pn_io_error_code1), 0x0, "", HFILL }},
    { &hf_pn_io_error_code2,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_HEX, VALS(pn_io_error_code2), 0x0, "", HFILL }},
    { &hf_pn_io_error_code1_pniorw,
      { "ErrorCode1 (PNIORW)", "pn_io.error_code1", FT_UINT8, BASE_HEX, VALS(pn_io_error_code1_pniorw), 0x0, "", HFILL }},
    { &hf_pn_io_error_code1_pnio,
      { "ErrorCode1 (PNIO)", "pn_io.error_code1", FT_UINT8, BASE_HEX, VALS(pn_io_error_code1_pnio), 0x0, "", HFILL }},
	{ &hf_pn_io_block,
    { "Block", "pn_io.block", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_data,
      { "Undecoded Data", "pn_io.data", FT_STRING, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_pn_io_alarm_type,
      { "AlarmType", "pn_io.alarm_type", FT_UINT16, BASE_HEX, VALS(pn_io_alarm_type), 0x0, "", HFILL }},

    { &hf_pn_io_alarm_specifier,
      { "AlarmSpecifier", "pn_io.alarm_specifier", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_alarm_specifier_sequence,
      { "SequenceNumber", "pn_io.alarm_specifier.sequence", FT_UINT16, BASE_HEX, NULL, 0x07FF, "", HFILL }},
    { &hf_pn_io_alarm_specifier_channel,
      { "ChannelDiagnosis", "pn_io.alarm_specifier.channel", FT_UINT16, BASE_HEX, NULL, 0x0800, "", HFILL }},
    { &hf_pn_io_alarm_specifier_manufacturer,
      { "ManufacturerSpecificDiagnosis", "pn_io.alarm_specifier.manufacturer", FT_UINT16, BASE_HEX, NULL, 0x1000, "", HFILL }},
    { &hf_pn_io_alarm_specifier_submodule,
      { "SubmoduleDiagnosisState", "pn_io.alarm_specifier.submodule", FT_UINT16, BASE_HEX, NULL, 0x2000, "", HFILL }},
    { &hf_pn_io_alarm_specifier_ardiagnosis,
      { "ARDiagnosisState", "pn_io.alarm_specifier.ardiagnosis", FT_UINT16, BASE_HEX, NULL, 0x8000, "", HFILL }},

    { &hf_pn_io_alarm_dst_endpoint,
      { "AlarmDstEndpoint", "pn_io.alarm_dst_endpoint", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_alarm_src_endpoint,
      { "AlarmSrcEndpoint", "pn_io.alarm_src_endpoint", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_pdu_type,
      { "PDUType", "pn_io.pdu_type", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_pdu_type_type,
      { "Type", "pn_io.pdu_type.type", FT_UINT8, BASE_HEX, VALS(pn_io_pdu_type), 0x0F, "", HFILL }},
    { &hf_pn_io_pdu_type_version,
      { "Version", "pn_io.pdu_type.version", FT_UINT8, BASE_HEX, NULL, 0xF0, "", HFILL }},
    { &hf_pn_io_add_flags,
      { "AddFlags", "pn_io.add_flags", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_window_size,
      { "WindowSize", "pn_io.window_size", FT_UINT8, BASE_DEC, NULL, 0x0F, "", HFILL }},
    { &hf_pn_io_tack,
      { "TACK", "pn_io.tack", FT_UINT8, BASE_HEX, NULL, 0xF0, "", HFILL }},
    { &hf_pn_io_send_seq_num,
      { "SendSeqNum", "pn_io.send_seq_num", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_ack_seq_num,
      { "AckSeqNum", "pn_io.ack_seq_num", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_var_part_len,
      { "VarPartLen", "pn_io.var_part_len", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_module_ident_number,
      { "ModuleIdentNumber", "pn_io.module_ident_number", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_submodule_ident_number,
      { "SubmoduleIdentNumber", "pn_io.submodule_ident_number", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }}
    };

	static gint *ett[] = {
		&ett_pn_io,
        &ett_pn_io_block,
        &ett_pn_io_status,
        &ett_pn_io_rta,
		&ett_pn_io_pdu_type,
        &ett_pn_io_add_flags,
        &ett_pn_io_control_command
	};
	proto_pn_io = proto_register_protocol ("PROFINET IO", "PNIO-CM", "pn_io");
	proto_register_field_array (proto_pn_io, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_pn_io (void)
{
	/* Register the protocols as dcerpc */
	dcerpc_init_uuid (proto_pn_io, ett_pn_io, &uuid_pn_io_device, ver_pn_io_device, pn_io_dissectors, hf_pn_io_opnum);
	dcerpc_init_uuid (proto_pn_io, ett_pn_io, &uuid_pn_io_controller, ver_pn_io_controller, pn_io_dissectors, hf_pn_io_opnum);
	dcerpc_init_uuid (proto_pn_io, ett_pn_io, &uuid_pn_io_supervisor, ver_pn_io_supervisor, pn_io_dissectors, hf_pn_io_opnum);
	dcerpc_init_uuid (proto_pn_io, ett_pn_io, &uuid_pn_io_parameterserver, ver_pn_io_parameterserver, pn_io_dissectors, hf_pn_io_opnum);

	heur_dissector_add("pn_rt", dissect_PNIO_heur, proto_pn_io);
}
