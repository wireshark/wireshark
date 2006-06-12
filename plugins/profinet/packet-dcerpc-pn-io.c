/* packet-dcerpc-pn-io.c
 * Routines for PROFINET IO dissection.
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
 */

/*
 * The PN-IO protocol is a field bus protocol related to decentralized 
 * periphery and is developed by the PROFIBUS Nutzerorganisation e.V. (PNO), 
 * see: www.profibus.com
 *
 *
 * PN-IO is based on the common DCE-RPC and the "lightweight" PN-RT 
 * (ethernet type 0x8892) protocols.
 *
 * The context manager (CM) part is handling context information 
 * (like establishing, ...) and is using DCE-RPC as it's underlying 
 * protocol.
 *
 * The actual cyclic data transfer and acyclic notification uses the 
 * "lightweight" PN-RT protocol.
 *
 * There are some other related PROFINET protocols (e.g. PN-DCP, which is 
 * handling addressing topics).
 *
 * Please note: the PROFINET CBA protocol is independant of the PN-IO protocol!
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
#include <epan/emem.h>
#include <epan/dissectors/packet-dcerpc.h>



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

static int hf_pn_io_ar_type = -1;
static int hf_pn_io_cminitiator_macadd = -1;
static int hf_pn_io_cminitiator_objectuuid = -1;
static int hf_pn_io_ar_properties = -1;
static int hf_pn_io_cminitiator_activitytimeoutfactor = -1;
static int hf_pn_io_cminitiator_udprtport = -1;
static int hf_pn_io_station_name_length = -1;
static int hf_pn_io_cminitiator_station_name = -1;

static int hf_pn_io_cmresponder_macadd = -1;
static int hf_pn_io_cmresponder_udprtport = -1;

static int hf_pn_io_iocr_type = -1;
static int hf_pn_io_iocr_reference = -1;
static int hf_pn_io_lt = -1;
static int hf_pn_io_iocr_properties = -1;
static int hf_pn_io_data_length = -1;
static int hf_pn_io_frame_id = -1;
static int hf_pn_io_send_clock_factor = -1;
static int hf_pn_io_reduction_ratio = -1;
static int hf_pn_io_phase = -1;
static int hf_pn_io_sequence = -1;
static int hf_pn_io_frame_send_offset = -1;
static int hf_pn_io_watchdog_factor = -1;
static int hf_pn_io_data_hold_factor = -1;
static int hf_pn_io_iocr_tag_header = -1;
static int hf_pn_io_iocr_multicast_mac_add = -1;
static int hf_pn_io_number_of_apis = -1;
static int hf_pn_io_number_of_io_data_objects = -1;
static int hf_pn_io_io_data_object_frame_offset = -1;
static int hf_pn_io_number_of_iocs = -1;
static int hf_pn_io_iocs_frame_offset = -1;

static int hf_pn_io_alarmcr_type = -1;
static int hf_pn_io_alarmcr_properties = -1;
static int hf_pn_io_rta_timeoutfactor = -1;
static int hf_pn_io_rta_retries = -1;
static int hf_pn_io_localalarmref = -1;
static int hf_pn_io_maxalarmdatalength = -1;
static int hf_pn_io_alarmcr_tagheaderhigh = -1;
static int hf_pn_io_alarmcr_tagheaderlow = -1;

static int hf_pn_io_ar_uuid = -1;
static int hf_pn_io_target_ar_uuid = -1;
static int hf_pn_io_api_tree = -1;
static int hf_pn_io_module_tree = -1;
static int hf_pn_io_submodule_tree = -1;
static int hf_pn_io_io_data_object = -1;
static int hf_pn_io_io_cs = -1;
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
static int hf_pn_io_block_header = -1;
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

static int hf_pn_io_number_of_modules = -1;
static int hf_pn_io_module_ident_number = -1;
static int hf_pn_io_module_properties = -1;
static int hf_pn_io_module_state = -1;
static int hf_pn_io_number_of_submodules = -1;
static int hf_pn_io_submodule_ident_number = -1;
static int hf_pn_io_submodule_properties = -1;
static int hf_pn_io_submodule_state = -1;
static int hf_pn_io_data_description_tree = -1;
static int hf_pn_io_data_description = -1;
static int hf_pn_io_submodule_data_length = -1;
static int hf_pn_io_length_iocs = -1;
static int hf_pn_io_length_iops = -1;

static int hf_pn_io_ioxs = -1;
static int hf_pn_io_ioxs_extension = -1;
static int hf_pn_io_ioxs_res14 = -1;
static int hf_pn_io_ioxs_instance = -1;
static int hf_pn_io_ioxs_datastate = -1;

static int hf_pn_io_address_resolution_properties = -1;
static int hf_pn_io_mci_timeout_factor = -1;
static int hf_pn_io_provider_station_name = -1;


static gint ett_pn_io = -1;
static gint ett_pn_io_block = -1;
static gint ett_pn_io_block_header = -1;
static gint ett_pn_io_status = -1;
static gint ett_pn_io_rtc = -1;
static gint ett_pn_io_rta = -1;
static gint ett_pn_io_pdu_type = -1;
static gint ett_pn_io_add_flags = -1;
static gint ett_pn_io_control_command = -1;
static gint ett_pn_io_ioxs = -1;
static gint ett_pn_io_api = -1;
static gint ett_pn_io_data_description = -1;
static gint ett_pn_io_module = -1;
static gint ett_pn_io_submodule = -1;
static gint ett_pn_io_io_data_object = -1;
static gint ett_pn_io_io_cs = -1;

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
	{ 0x0106, "MCRBlockReq"},
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
	{ 0x0009, "Released" },
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

static const value_string pn_io_ioxs[] = {
	{ 0x00 /*  0*/, "detected by subslot" },
	{ 0x01 /*  1*/, "detected by slot" },
	{ 0x02 /*  2*/, "detected by IO device" },
	{ 0x03 /*  3*/, "detected by IO controller" },
    { 0, NULL }
};


static const value_string pn_io_ar_type[] = {
	{ 0x0000, "reserved" },
	{ 0x0001, "IOCARSingle" },
	{ 0x0002, "reserved" },
	{ 0x0003, "IOCARCIR" },
	{ 0x0004, "IOCAR_IOControllerRedundant" },
	{ 0x0005, "IOCAR_IODeviceRedundant" },
	{ 0x0006, "IOSAR" },
    /*0x0007 - 0xFFFF reserved */
    { 0, NULL }
};

static const value_string pn_io_iocr_type[] = {
	{ 0x0000, "reserved" },
	{ 0x0001, "Input CR" },
	{ 0x0002, "Output CR" },
	{ 0x0003, "Multicast Provider CR" },
	{ 0x0004, "Multicast Consumer CR" },
    /*0x0005 - 0xFFFF reserved */
    { 0, NULL }
};


static const value_string pn_io_data_description[] = {
	{ 0x0000, "reserved" },
	{ 0x0001, "Input" },
	{ 0x0002, "Output" },
	{ 0x0003, "reserved" },
    /*0x0004 - 0xFFFF reserved */
    { 0, NULL }
};



static const value_string pn_io_module_state[] = {
	{ 0x0000, "no module" },
	{ 0x0001, "wrong module" },
	{ 0x0002, "proper module" },
	{ 0x0003, "substitute" },
    /*0x0004 - 0xFFFF reserved */
    { 0, NULL }
};






/* dissect a 6 byte MAC address */
static int 
dissect_MAC(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                    proto_tree *tree, int hfindex, guint8 *pdata)
{
    guint8 data[6];

    tvb_memcpy(tvb, data, offset, 6);
    if(tree)
        proto_tree_add_ether(tree, hfindex, tvb, offset, 6, data);

    if (pdata)
        memcpy(pdata, data, 6);

    return offset + 6;
}





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
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s, Slot: 0x%x/0x%x", 
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
	packet_info *pinfo, proto_tree *tree, guint8 *drep, guint16 *u16Index, e_uuid_t *aruuid)
{
    guint32 u32Api;
    guint16 u16SlotNr;
    guint16 u16SubslotNr;
    guint16 u16SeqNr;

	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_seq_number, &u16SeqNr);

    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_ar_uuid, aruuid);

	offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_api, &u32Api);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_slot_nr, &u16SlotNr);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_subslot_nr, &u16SubslotNr);
    proto_tree_add_string_format(tree, hf_pn_io_padding, tvb, offset, 2, "padding", "Padding: 2 bytes");
    offset += 2;
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_index, u16Index);

    if (check_col(pinfo->cinfo, COL_INFO))
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", Api: 0x%x, Slot: 0x%x/0x%x",
            u32Api, u16SlotNr, u16SubslotNr);

    return offset;
}


/* dissect the read/write request block */
static int
dissect_ReadWrite_rqst_block(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep, guint16 *u16Index, guint32 *u32RecDataLen)
{
    e_uuid_t aruuid;
    e_uuid_t null_uuid;

    offset = dissect_ReadWrite_header(tvb, offset, pinfo, tree, drep, u16Index, &aruuid);

	offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_record_data_length, u32RecDataLen);

    memset(&null_uuid, 0, sizeof(e_uuid_t));
    if(memcmp(&aruuid, &null_uuid, sizeof (e_uuid_t)) == 0) {
        offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_target_ar_uuid, &aruuid);
    }

    if (check_col(pinfo->cinfo, COL_INFO))
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", %u bytes",
            *u32RecDataLen);

    return offset;
}


/* dissect the read/write response block */
static int
dissect_ReadWrite_resp_block(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep, guint16 *u16Index)
{
    e_uuid_t aruuid;
    guint32 u32RecDataLen;
    guint16 u16AddVal1;
    guint16 u16AddVal2;


    offset = dissect_ReadWrite_header(tvb, offset, pinfo, tree, drep, u16Index, &aruuid);

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

    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep, 
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


/* dissect the ARBlockReq */
static int
dissect_ARBlockReq(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16ARType;
    e_uuid_t uuid;
    guint16 u16SessionKey;
    guint8 mac[6];
    guint32 u32ARProperties;
    guint16 u16TimeoutFactor;
    guint16 u16UDPRTPort;
    guint16 u16NameLength;
    guint8 *pu8StationName;


	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_ar_type, &u16ARType);
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_ar_uuid, &uuid);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_sessionkey, &u16SessionKey);
    offset = dissect_MAC(tvb, offset, pinfo, tree, 
                        hf_pn_io_cminitiator_macadd, mac);
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_cminitiator_objectuuid, &uuid);
	offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_ar_properties, &u32ARProperties);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_cminitiator_activitytimeoutfactor, &u16TimeoutFactor);   /* XXX - special values */
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_cminitiator_udprtport, &u16UDPRTPort);   /* XXX - special values */
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_station_name_length, &u16NameLength);

    pu8StationName = ep_alloc(u16NameLength+1);
    tvb_memcpy(tvb, pu8StationName, offset, u16NameLength);
    pu8StationName[u16NameLength] = '\0';
    proto_tree_add_string (tree, hf_pn_io_cminitiator_station_name, tvb, offset, u16NameLength, pu8StationName);
    offset += u16NameLength;

    /*if (check_col(pinfo->cinfo, COL_INFO))
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", Api: %u, Slot: %u/%u",
            u32Api, u16SlotNr, u16SubslotNr);*/

    return offset;
}


/* dissect the ARBlockRes */
static int
dissect_ARBlockRes(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16ARType;
    e_uuid_t uuid;
    guint16 u16SessionKey;
    guint8 mac[6];
    guint16 u16UDPRTPort;


	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_ar_type, &u16ARType);
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_ar_uuid, &uuid);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_sessionkey, &u16SessionKey);
    offset = dissect_MAC(tvb, offset, pinfo, tree, 
                        hf_pn_io_cmresponder_macadd, mac);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_cmresponder_udprtport, &u16UDPRTPort);   /* XXX - special values */

    /*if (check_col(pinfo->cinfo, COL_INFO))
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", Api: %u, Slot: %u/%u",
            u32Api, u16SlotNr, u16SubslotNr);*/

    return offset;
}


/* dissect the IOCRBlockReq */
static int
dissect_IOCRBlockReq(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16IOCRType;
    guint16 u16IOCRReference;
    guint16 u16LT;
    guint32 u32IOCRProperties;
    guint16 u16DataLength;
    guint16 u16FrameID;
    guint16 u16SendClockFactor;
    guint16 u16ReductionRatio;
    guint16 u16Phase;
    guint16 u16Sequence;
    guint32 u32FrameSendOffset;
    guint16 u16WatchdogFactor;
    guint16 u16DataHoldFactor;
    guint16 u16IOCRTagHeader;
    guint8 mac[6];
    guint16 u16NumberOfAPIs;
    guint32 u32Api;
    guint16 u16NumberOfIODataObjects;
    guint16 u16SlotNr;
    guint16 u16SubslotNr;
    guint16 u16IODataObjectFrameOffset;
    guint16 u16NumberOfIOCS;
    guint16 u16IOCSFrameOffset;
    proto_item *api_item;
	proto_tree *api_tree;
	guint32 u32ApiStart;
    guint16 u16Tmp;
    proto_item *sub_item;
	proto_tree *sub_tree;
	guint32 u32SubStart;


	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_iocr_type, &u16IOCRType);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_iocr_reference, &u16IOCRReference);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_lt, &u16LT);
	offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_iocr_properties, &u32IOCRProperties);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_data_length, &u16DataLength);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_frame_id, &u16FrameID);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_send_clock_factor, &u16SendClockFactor);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_reduction_ratio, &u16ReductionRatio);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_phase, &u16Phase);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_sequence, &u16Sequence);
	offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_frame_send_offset, &u32FrameSendOffset);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_watchdog_factor, &u16WatchdogFactor);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_data_hold_factor, &u16DataHoldFactor);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_iocr_tag_header, &u16IOCRTagHeader);
    offset = dissect_MAC(tvb, offset, pinfo, tree, 
                        hf_pn_io_iocr_multicast_mac_add, mac);

	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_number_of_apis, &u16NumberOfAPIs);
    while(u16NumberOfAPIs--) {
        api_item = proto_tree_add_item(tree, hf_pn_io_api_tree, tvb, offset, 0, FALSE);
	    api_tree = proto_item_add_subtree(api_item, ett_pn_io_api);
        u32ApiStart = offset;

        /* API */
	    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, api_tree, drep, 
                            hf_pn_io_api, &u32Api);
        /* NumberOfIODataObjects */
	    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, api_tree, drep, 
                            hf_pn_io_number_of_io_data_objects, &u16NumberOfIODataObjects);

        u16Tmp = u16NumberOfIODataObjects;
        while(u16Tmp--) {
            sub_item = proto_tree_add_item(api_tree, hf_pn_io_io_data_object, tvb, offset, 0, FALSE);
	        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_io_data_object);
            u32SubStart = offset;

            /* SlotNumber */
	        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep, 
                                hf_pn_io_slot_nr, &u16SlotNr);
            /* Subslotnumber */
	        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep, 
                                hf_pn_io_subslot_nr, &u16SubslotNr);
            /* IODataObjectFrameOffset */
	        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep, 
                                hf_pn_io_io_data_object_frame_offset, &u16IODataObjectFrameOffset);

            proto_item_append_text(sub_item, ": Slot: 0x%x, Subslot: 0x%x FrameOffset: %u", 
                u16SlotNr, u16SubslotNr, u16IODataObjectFrameOffset);

	        proto_item_set_len(sub_item, offset - u32SubStart);
        }
        /* NumberOfIOCS */
	    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, api_tree, drep, 
                            hf_pn_io_number_of_iocs, &u16NumberOfIOCS);

        u16Tmp = u16NumberOfIOCS;
        while(u16Tmp--) {
            sub_item = proto_tree_add_item(api_tree, hf_pn_io_io_cs, tvb, offset, 0, FALSE);
	        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_io_cs);
            u32SubStart = offset;

            /* SlotNumber */
	        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep, 
                                hf_pn_io_slot_nr, &u16SlotNr);
            /* Subslotnumber */
	        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep, 
                                hf_pn_io_subslot_nr, &u16SubslotNr);
            /* IOCSFrameOffset */
	        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep, 
                                hf_pn_io_iocs_frame_offset, &u16IOCSFrameOffset);

            proto_item_append_text(sub_item, ": Slot: 0x%x, Subslot: 0x%x FrameOffset: %u", 
                u16SlotNr, u16SubslotNr, u16IOCSFrameOffset);

	        proto_item_set_len(sub_item, offset - u32SubStart);
        }

        proto_item_append_text(api_item, ": %u, NumberOfIODataObjects: %u NumberOfIOCS: %u", 
            u32Api, u16NumberOfIODataObjects, u16NumberOfIOCS);

	    proto_item_set_len(api_item, offset - u32ApiStart);
    }

    return offset;
}


/* dissect the AlarmCRBlockReq */
static int
dissect_AlarmCRBlockReq(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16AlarmCRType;
    guint16 u16LT;
    guint32 u32AlarmCRProperties;
    guint16 u16RTATimeoutFactor;
    guint16 u16RTARetries;
    guint16 u16LocalAlarmReference;
    guint16 u16MaxAlarmDataLength;
    guint16 u16AlarmCRTagHeaderHigh;
    guint16 u16AlarmCRTagHeaderLow;


	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_alarmcr_type, &u16AlarmCRType);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_lt, &u16LT);
	offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_alarmcr_properties, &u32AlarmCRProperties);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_rta_timeoutfactor, &u16RTATimeoutFactor);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_rta_retries, &u16RTARetries);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_localalarmref, &u16LocalAlarmReference);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_maxalarmdatalength, &u16MaxAlarmDataLength);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_alarmcr_tagheaderhigh, &u16AlarmCRTagHeaderHigh);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_alarmcr_tagheaderlow, &u16AlarmCRTagHeaderLow);

    return offset;
}


/* dissect the AlarmCRBlockRes */
static int
dissect_AlarmCRBlockRes(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16AlarmCRType;
    guint16 u16LocalAlarmReference;
    guint16 u16MaxAlarmDataLength;


	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_alarmcr_type, &u16AlarmCRType);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_localalarmref, &u16LocalAlarmReference);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_maxalarmdatalength, &u16MaxAlarmDataLength);

    return offset;
}



/* dissect the IOCRBlockRes */
static int
dissect_IOCRBlockRes(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16IOCRType;
    guint16 u16IOCRReference;
    guint16 u16FrameID;


	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_iocr_type, &u16IOCRType);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_iocr_reference, &u16IOCRReference);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_frame_id, &u16FrameID);

    return offset;
}



/* dissect the MCRBlockReq */
static int
dissect_MCRBlockReq(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16IOCRReference;
    guint32 u32AddressResolutionProperties;
    guint16 u16MCITimeoutFactor;
    guint16 u16NameLength;
    guint8 *pu8StationName;


	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_iocr_reference, &u16IOCRReference);
	offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_address_resolution_properties, &u32AddressResolutionProperties);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_mci_timeout_factor, &u16MCITimeoutFactor);

	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_station_name_length, &u16NameLength);

    pu8StationName = ep_alloc(u16NameLength+1);
    tvb_memcpy(tvb, pu8StationName, offset, u16NameLength);
    pu8StationName[u16NameLength] = '\0';
    proto_tree_add_string (tree, hf_pn_io_provider_station_name, tvb, offset, u16NameLength, pu8StationName);
    offset += u16NameLength;    

    return offset;
}



/* dissect the DataDescription */
static int
dissect_DataDescription(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16DataDescription;
    guint16 u16SubmoduleDataLength;
    guint8  u8LengthIOCS;
    guint8  u8LengthIOPS;
    proto_item *sub_item;
	proto_tree *sub_tree;
	guint32 u32SubStart;


    sub_item = proto_tree_add_item(tree, hf_pn_io_data_description_tree, tvb, offset, 0, FALSE);
	sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_data_description);
    u32SubStart = offset;

    /* DataDescription */
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep, 
                    hf_pn_io_data_description, &u16DataDescription);
    /* SubmoduleDataLength */
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep, 
                    hf_pn_io_submodule_data_length, &u16SubmoduleDataLength);
    /* LengthIOCS */
	offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep, 
                    hf_pn_io_length_iocs, &u8LengthIOCS);
    /* LengthIOPS */
	offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep, 
                    hf_pn_io_length_iops, &u8LengthIOPS);

    proto_item_append_text(sub_item, ": %s, SubmoduleDataLength: %u, LengthIOCS: %u, u8LengthIOPS: %u", 
        val_to_str(u16DataDescription, pn_io_data_description, "(0x%x)"), 
        u16SubmoduleDataLength, u8LengthIOCS, u8LengthIOPS);
	proto_item_set_len(sub_item, offset - u32SubStart);

    return offset;
}


/* dissect the ExpectedSubmoduleBlockReq */
static int
dissect_ExpectedSubmoduleBlockReq(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16NumberOfAPIs;
    guint32 u32Api;
    guint16 u16SlotNr;
    guint32 u32ModuleIdentNumber;
    guint16 u16ModuleProperties;
    guint16 u16NumberOfSubmodules;
    guint16 u16SubslotNr;
    guint32 u32SubmoduleIdentNumber;
    guint16 u16SubmoduleProperties;
    proto_item *api_item;
	proto_tree *api_tree;
	guint32 u32ApiStart;
    proto_item *sub_item;
	proto_tree *sub_tree;
	guint32 u32SubStart;


	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_number_of_apis, &u16NumberOfAPIs);
    while(u16NumberOfAPIs--) {
        api_item = proto_tree_add_item(tree, hf_pn_io_api_tree, tvb, offset, 0, FALSE);
	    api_tree = proto_item_add_subtree(api_item, ett_pn_io_api);
        u32ApiStart = offset;

        /* API */
	    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, api_tree, drep, 
                            hf_pn_io_api, &u32Api);
        /* SlotNumber */
	    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, api_tree, drep, 
                            hf_pn_io_slot_nr, &u16SlotNr);
        /* ModuleIdentNumber */
	    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, api_tree, drep, 
                            hf_pn_io_module_ident_number, &u32ModuleIdentNumber);
        /* ModuleProperties */
	    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, api_tree, drep, 
                            hf_pn_io_module_properties, &u16ModuleProperties);
        /* NumberOfSubmodules */
	    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, api_tree, drep, 
                            hf_pn_io_number_of_submodules, &u16NumberOfSubmodules);

        proto_item_append_text(api_item, ": %u, Slot: 0x%x, ModuleIdentNumber: 0x%x ModuleProperties: 0x%x NumberOfSubmodules: %u", 
            u32Api, u16SlotNr, u32ModuleIdentNumber, u16ModuleProperties, u16NumberOfSubmodules);

        while(u16NumberOfSubmodules--) {
            sub_item = proto_tree_add_item(api_tree, hf_pn_io_submodule_tree, tvb, offset, 0, FALSE);
	        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_submodule);
            u32SubStart = offset;

            /* Subslotnumber */
	        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep, 
                                hf_pn_io_subslot_nr, &u16SubslotNr);
            /* SubmoduleIdentNumber */
	        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, 
                            hf_pn_io_submodule_ident_number, &u32SubmoduleIdentNumber);
            /* SubmoduleProperties */
	        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep, 
                            hf_pn_io_submodule_properties, &u16SubmoduleProperties);

            switch(u16SubmoduleProperties & 0x03) {
            case(0x00): /* no input and no output data (one Input DataDescription Block follows) */
                offset = dissect_DataDescription(tvb, offset, pinfo, sub_tree, drep);
                break;
            case(0x01): /* input data (one Input DataDescription Block follows) */
                offset = dissect_DataDescription(tvb, offset, pinfo, sub_tree, drep);
                break;
            case(0x02): /* output data (one Output DataDescription Block follows) */
                offset = dissect_DataDescription(tvb, offset, pinfo, sub_tree, drep);
                break;
            case(0x03): /* input and output data (one Input and one Output DataDescription Block follows) */
                offset = dissect_DataDescription(tvb, offset, pinfo, sub_tree, drep);
                offset = dissect_DataDescription(tvb, offset, pinfo, sub_tree, drep);
                break;
            }

            proto_item_append_text(sub_item, ": Subslot: 0x%x, SubmoduleIdent: 0x%x SubmoduleProperties: 0x%x", 
                u16SubslotNr, u32SubmoduleIdentNumber, u16SubmoduleProperties);
	        proto_item_set_len(sub_item, offset - u32SubStart);
        }

	    proto_item_set_len(api_item, offset - u32ApiStart);
    }

    return offset;
}


/* dissect the ModuleDiffBlock */
static int
dissect_ModuleDiffBlock(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16NumberOfAPIs;
    guint32 u32Api;
    guint16 u16NumberOfModules;
    guint16 u16SlotNr;
    guint32 u32ModuleIdentNumber;
    guint16 u16ModuleState;
    guint16 u16NumberOfSubmodules;
    guint16 u16SubslotNr;
    guint32 u32SubmoduleIdentNumber;
    guint16 u16SubmoduleState;
    proto_item *api_item;
	proto_tree *api_tree;
	guint32 u32ApiStart;
    proto_item *module_item;
	proto_tree *module_tree;
	guint32 u32ModuleStart;
    proto_item *sub_item;
	proto_tree *sub_tree;
	guint32 u32SubStart;


    /* NumberOfAPIs */
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_number_of_apis, &u16NumberOfAPIs);
    while(u16NumberOfAPIs--) {
        api_item = proto_tree_add_item(tree, hf_pn_io_api_tree, tvb, offset, 0, FALSE);
	    api_tree = proto_item_add_subtree(api_item, ett_pn_io_api);
        u32ApiStart = offset;

        /* API */
	    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, api_tree, drep, 
                            hf_pn_io_api, &u32Api);
        /* NumberOfModules */
	    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, api_tree, drep, 
                            hf_pn_io_number_of_modules, &u16NumberOfModules);

        proto_item_append_text(api_item, ": %u, NumberOfModules: %u", 
            u32Api, u16NumberOfModules);

        while(u16NumberOfModules--) {
            module_item = proto_tree_add_item(api_tree, hf_pn_io_module_tree, tvb, offset, 0, FALSE);
	        module_tree = proto_item_add_subtree(module_item, ett_pn_io_module);
            u32ModuleStart = offset;

            /* SlotNumber */
	        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, module_tree, drep, 
                                hf_pn_io_slot_nr, &u16SlotNr);
            /* ModuleIdentNumber */
	        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, module_tree, drep, 
                                hf_pn_io_module_ident_number, &u32ModuleIdentNumber);
            /* ModuleState */
	        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, module_tree, drep, 
                                hf_pn_io_module_state, &u16ModuleState);
            /* NumberOfSubmodules */
	        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, module_tree, drep, 
                                hf_pn_io_number_of_submodules, &u16NumberOfSubmodules);

            proto_item_append_text(module_item, ": Slot 0x%x, ModuleIdent: 0x%x ModuleState: %s NumberOfSubmodules: %u", 
                u16SlotNr, u32ModuleIdentNumber, 
                val_to_str(u16ModuleState, pn_io_module_state, "(0x%x)"), 
                u16NumberOfSubmodules);

            while(u16NumberOfSubmodules--) {
                sub_item = proto_tree_add_item(module_tree, hf_pn_io_submodule_tree, tvb, offset, 0, FALSE);
	            sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_submodule);
                u32SubStart = offset;

                /* Subslotnumber */
	            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep, 
                                    hf_pn_io_subslot_nr, &u16SubslotNr);
                /* SubmoduleIdentNumber */
	            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, 
                                hf_pn_io_submodule_ident_number, &u32SubmoduleIdentNumber);
                /* SubmoduleState */
	            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep, 
                                hf_pn_io_submodule_state, &u16SubmoduleState);

                proto_item_append_text(sub_item, ": Subslot 0x%x, SubmoduleIdentNumber: 0x%x, SubmoduleState: 0x%x", 
                    u16SubslotNr, u32SubmoduleIdentNumber, u16SubmoduleState);

	            proto_item_set_len(sub_item, offset - u32SubStart);
            } /* NumberOfSubmodules */

	        proto_item_set_len(module_item, offset - u32ModuleStart);
        }

	    proto_item_set_len(api_item, offset - u32ApiStart);
    }

    return offset;
}


/* dissect one PN-IO block (depending on the block type) */
static int
dissect_block(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep, guint16 *u16Index, guint32 *u32RecDataLen)
{
    guint16 u16BlockType;
    guint16 u16BlockLength;
    guint8 u8BlockVersionHigh;
    guint8 u8BlockVersionLow;
	proto_item *sub_item;
	proto_tree *sub_tree;
	guint32 u32SubStart;
    guint16 u16BodyLength;
	proto_item *header_item;
	proto_tree *header_tree;


    /* from here, we only have big endian (network byte ordering)!!! */
    drep[0] &= ~0x10;

    sub_item = proto_tree_add_item(tree, hf_pn_io_block, tvb, offset, 0, FALSE);
	sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_block);
    u32SubStart = offset;

    header_item = proto_tree_add_item(sub_tree, hf_pn_io_block_header, tvb, offset, 6, FALSE);
	header_tree = proto_item_add_subtree(header_item, ett_pn_io_block_header);

	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, header_tree, drep, 
                        hf_pn_io_block_type, &u16BlockType);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, header_tree, drep, 
                        hf_pn_io_block_length, &u16BlockLength);
	offset = dissect_dcerpc_uint8(tvb, offset, pinfo, header_tree, drep, 
                        hf_pn_io_block_version_high, &u8BlockVersionHigh);
	offset = dissect_dcerpc_uint8(tvb, offset, pinfo, header_tree, drep, 
                        hf_pn_io_block_version_low, &u8BlockVersionLow);

    /* XXX - append block_header data to header_item */

    /* block length is without type and length fields, but with version field */
    /* as it's already dissected, remove it */
    u16BodyLength = u16BlockLength - 2;
    tvb_ensure_bytes_exist(tvb, offset, u16BodyLength);

    switch(u16BlockType) {
    case(0x0001):
    case(0x0002):
        dissect_Alarm_note_block(tvb, offset, pinfo, sub_tree, drep, u16BodyLength);
        break;
    case(0x0101):
        dissect_ARBlockReq(tvb, offset, pinfo, sub_tree, drep);
        break;
    case(0x0102):
        dissect_IOCRBlockReq(tvb, offset, pinfo, sub_tree, drep);
        break;
    case(0x0103):
        dissect_AlarmCRBlockReq(tvb, offset, pinfo, sub_tree, drep);
        break;
    case(0x0104):
        dissect_ExpectedSubmoduleBlockReq(tvb, offset, pinfo, sub_tree, drep);
        break;
    case(0x0106):
        dissect_MCRBlockReq(tvb, offset, pinfo, sub_tree, drep);
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
        dissect_ReadWrite_rqst_block(tvb, offset, pinfo, sub_tree, drep, u16Index, u32RecDataLen);
        break;
    case(0x8001):
    case(0x8002):
        dissect_Alarm_ack_block(tvb, offset, pinfo, sub_tree, drep);
        break;
    case(0x8008):
    case(0x8009):
        dissect_ReadWrite_resp_block(tvb, offset, pinfo, sub_tree, drep, u16Index);
        break;
    case(0x8101):
        dissect_ARBlockRes(tvb, offset, pinfo, sub_tree, drep);
        break;
    case(0x8102):
        dissect_IOCRBlockRes(tvb, offset, pinfo, sub_tree, drep);
        break;
    case(0x8103):
        dissect_AlarmCRBlockRes(tvb, offset, pinfo, sub_tree, drep);
        break;
    case(0x8104):
        dissect_ModuleDiffBlock(tvb, offset, pinfo, sub_tree, drep);
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
        if (check_col(pinfo->cinfo, COL_INFO) && *u16Index < 3)
	        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
            val_to_str(u16BlockType, pn_io_block_type, "Unknown"));
    	proto_tree_add_string_format(sub_tree, hf_pn_io_data, tvb, offset, u16BodyLength, "undecoded", "Undecoded Data: %d bytes", u16BodyLength);
    }
    offset += u16BodyLength;

	proto_item_append_text(sub_item, "[%u]: Type=\"%s\" (0x%04x), Length=%u(+4), Version=%u.%u", 
		*u16Index, val_to_str(u16BlockType, pn_io_block_type, "Unknown"), u16BlockType,
        u16BlockLength, u8BlockVersionHigh, u8BlockVersionLow);
	proto_item_set_len(sub_item, offset - u32SubStart);

    return offset;
}


/* dissect any number of PN-IO blocks */
static int
dissect_blocks(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16Index = 0;
    guint32 u32RecDataLen;
    

    while(tvb_length(tvb) > (guint) offset) {
        offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen);
        u16Index++;
    }

    /* we don't want to have too many blocks in the info column */
    if(u16Index > 3) {
        if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_fstr(pinfo->cinfo, COL_INFO, ", ... (%u blocks)",
            u16Index);
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


	if (check_col(pinfo->cinfo, COL_PROTOCOL))
	    col_add_str(pinfo->cinfo, COL_PROTOCOL, "PNIO-CM");

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


	if (check_col(pinfo->cinfo, COL_PROTOCOL))
	    col_add_str(pinfo->cinfo, COL_PROTOCOL, "PNIO-CM");

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

    /* IODConnectReq */
    offset = dissect_blocks(tvb, offset, pinfo, tree, drep);

	return offset;
}


/* dissect a PN-IO connect response */
static int
dissect_IPNIO_Connect_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

    offset = dissect_IPNIO_resp_header(tvb, offset, pinfo, tree, drep);

    /* IODConnectRes */
    offset = dissect_blocks(tvb, offset, pinfo, tree, drep);

	return offset;
}


/* dissect a PN-IO release request */
static int
dissect_IPNIO_Release_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    
    offset = dissect_IPNIO_rqst_header(tvb, offset, pinfo, tree, drep);

    /* IODReleaseReq */
    offset = dissect_blocks(tvb, offset, pinfo, tree, drep);

	return offset;
}


/* dissect a PN-IO release response */
static int
dissect_IPNIO_Release_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

    offset = dissect_IPNIO_resp_header(tvb, offset, pinfo, tree, drep);

    /* IODReleaseRes */
    offset = dissect_blocks(tvb, offset, pinfo, tree, drep);

	return offset;
}


/* dissect a PN-IO control request */
static int
dissect_IPNIO_Control_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    
    offset = dissect_IPNIO_rqst_header(tvb, offset, pinfo, tree, drep);

    /* IODControlReq */
    offset = dissect_blocks(tvb, offset, pinfo, tree, drep);

    return offset;
}


/* dissect a PN-IO control response */
static int
dissect_IPNIO_Control_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

    offset = dissect_IPNIO_resp_header(tvb, offset, pinfo, tree, drep);

    /* IODControlRes */
    offset = dissect_blocks(tvb, offset, pinfo, tree, drep);

    return offset;
}


/* dissect a PN-IO read request */
static int
dissect_IPNIO_Read_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16Index = 0;
    guint32 u32RecDataLen;

    offset = dissect_IPNIO_rqst_header(tvb, offset, pinfo, tree, drep);

    /* IODReadReq */
    offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen);

	return offset;
}


/* dissect a PN-IO read response */
static int
dissect_IPNIO_Read_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    gint remain;
    guint16 u16Index = 0;
    guint32 u32RecDataLen;

    offset = dissect_IPNIO_resp_header(tvb, offset, pinfo, tree, drep);

    /* IODReadHeader */
    offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen);

    /* XXX - RecordDataRead: dissection not yet implemented */
    remain = tvb_length_remaining(tvb, offset);
    proto_tree_add_string_format(tree, hf_pn_io_data, tvb, offset, remain, "data", "User Data: %d bytes", remain);
    offset += remain;

	return offset;
}


static int
dissect_IODWriteReq(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    gint remain;
    guint16 u16Index = 0;
    guint32 u32RecDataLen;


    /* IODWriteHeader */
    offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen);


    /* IODWriteMultipleReq? */
    if(u16Index == 0xe040) {
        while((remain = tvb_length_remaining(tvb, offset)) > 0) {
            offset = dissect_IODWriteReq(tvb, offset, pinfo, tree, drep);
        }
    } else {
        /* RecordDataWrite */
        /* XXX - dissection not yet implemented */
        proto_tree_add_string_format(tree, hf_pn_io_data, tvb, offset, u32RecDataLen, "data", "RecordDataWrite: %d bytes", u32RecDataLen);
        offset += u32RecDataLen;

        /* XXX - add padding (required with IODWriteMultipleReq) */
        switch(offset % 4) {
        case(3):
            offset += 1;
            break;
        case(2):
            offset += 2;
            break;
        case(1):
            offset += 3;
            break;
        }
    }

    return offset;
}

/* dissect a PN-IO write request */
static int
dissect_IPNIO_Write_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_IPNIO_rqst_header(tvb, offset, pinfo, tree, drep);

    offset = dissect_IODWriteReq(tvb, offset, pinfo, tree, drep);

	return offset;
}



static int
dissect_IODWriteRes(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    gint remain;
    guint16 u16Index = 0;
    guint32 u32RecDataLen;


    /* IODWriteResHeader */
    offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen);

    /* IODWriteMultipleRes? */
    if(u16Index == 0xe040) {
        while((remain = tvb_length_remaining(tvb, offset)) > 0) {
            offset = dissect_IODWriteRes(tvb, offset, pinfo, tree, drep);
        }
    }

    return offset;
}


/* dissect a PN-IO write response */
static int
dissect_IPNIO_Write_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16Index = 0;

    offset = dissect_IPNIO_resp_header(tvb, offset, pinfo, tree, drep);

    offset = dissect_IODWriteRes(tvb, offset, pinfo, tree, drep);

	return offset;
}


/* dissect the IOxS (IOCS, IOPS) field */
static int
dissect_PNIO_IOxS(tvbuff_t *tvb, int offset,
	packet_info *pinfo _U_, proto_tree *tree, guint8 *drep _U_)
{
    guint8 u8IOxS;
    proto_item *ioxs_item = NULL;
    proto_tree *ioxs_tree = NULL;


    u8IOxS = tvb_get_guint8(tvb, offset);

    /* add ioxs subtree */
	ioxs_item = proto_tree_add_uint_format(tree, hf_pn_io_ioxs, 
		tvb, offset, 1, u8IOxS,
		"IOxS: 0x%02x (%s%s)", 
		u8IOxS, 
		(u8IOxS & 0x01) ? "another IOxS follows " : "",
		(u8IOxS & 0x80) ? "good" : "bad");
	ioxs_tree = proto_item_add_subtree(ioxs_item, ett_pn_io_ioxs);

	proto_tree_add_uint(ioxs_tree, hf_pn_io_ioxs_extension, tvb, offset, 1, u8IOxS);
	proto_tree_add_uint(ioxs_tree, hf_pn_io_ioxs_res14, tvb, offset, 1, u8IOxS);
	proto_tree_add_uint(ioxs_tree, hf_pn_io_ioxs_instance, tvb, offset, 1, u8IOxS);
	proto_tree_add_uint(ioxs_tree, hf_pn_io_ioxs_datastate, tvb, offset, 1, u8IOxS);

    return offset + 1;
}


/* dissect a PN-IO Cyclic Service Data Unit (on top of PN-RT protocol) */
static int
dissect_PNIO_C_SDU(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    proto_item *data_item;
	proto_tree *data_tree;


    if (check_col(pinfo->cinfo, COL_PROTOCOL))
	    col_add_str(pinfo->cinfo, COL_PROTOCOL, "PNIO");

    if(tree) {
	    data_item = proto_tree_add_protocol_format(tree, proto_pn_io, tvb, offset, tvb_length(tvb),
				    "PROFINET IO Cyclic Service Data Unit: %u bytes", tvb_length(tvb));
        data_tree = proto_item_add_subtree(data_item, ett_pn_io_rtc);

        offset = dissect_PNIO_IOxS(tvb, offset, pinfo, data_tree, drep);

        /* XXX - dissect the remaining data */
        /* this will be one or more DataItems followed by an optional GAP and RTCPadding */
        /* as we don't have the required context information to dissect the specific DataItems, this will be tricky :-( */
	    data_item = proto_tree_add_protocol_format(data_tree, proto_pn_io, tvb, offset, tvb_length_remaining(tvb, offset),
				    "Data: %u bytes (including GAP and RTCPadding)", tvb_length_remaining(tvb, offset));
    }

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
    int     start_offset = offset;
    guint16 u16Index = 0;
    guint32 u32RecDataLen;


    proto_item *rta_item;
	proto_tree *rta_tree;

    proto_item *sub_item;
	proto_tree *sub_tree;


	if (check_col(pinfo->cinfo, COL_PROTOCOL))
	    col_add_str(pinfo->cinfo, COL_PROTOCOL, "PNIO-AL");

	rta_item = proto_tree_add_protocol_format(tree, proto_pn_io, tvb, offset, tvb_length(tvb), 
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
        offset = dissect_block(tvb, offset, pinfo, rta_tree, drep, &u16Index, &u32RecDataLen);
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

    proto_item_set_len(rta_item, offset - start_offset);

    return offset;
}


/* possibly dissect a PN-IO related PN-RT packet */
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
        dissect_PNIO_C_SDU(tvb, 0, pinfo, tree, drep);
        return TRUE;
    }

    /* is this a PNIO class 1 data packet? */
	/* frame id must be in valid range (cyclic Real-Time, class=1) and
     * first byte (CBA version field) has to be != 0x11 */
	if (u16FrameID >= 0xc000 && u16FrameID < 0xfb00 && u8CBAVersion != 0x11) {
        dissect_PNIO_C_SDU(tvb, 0, pinfo, tree, drep);
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
{ 5, "Read Implicit",    dissect_IPNIO_Read_rqst,    dissect_IPNIO_Read_resp },
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

    { &hf_pn_io_ar_type,
    { "ARType", "pn_io.ar_type", FT_UINT16, BASE_HEX, VALS(pn_io_ar_type), 0x0, "", HFILL }},
	{ &hf_pn_io_cminitiator_macadd,
      { "CMInitiatorMacAdd", "pn_io.cminitiator_mac_add", FT_ETHER, BASE_HEX, 0x0, 0x0, "", HFILL }},
	{ &hf_pn_io_cminitiator_objectuuid,
      { "CMInitiatorObjectUUID", "pn_io.cminitiator_uuid", FT_GUID, BASE_NONE, 0x0, 0x0, "", HFILL }},
	{ &hf_pn_io_ar_properties,
		{ "ARProperties", "pn_io.ar_properties", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},  /* XXX - 32 bitfield! */
	{ &hf_pn_io_cminitiator_activitytimeoutfactor,
		{ "CMInitiatorActivityTimeoutFactor", "pn_io.cminitiator_activitytimeoutfactor", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},  /* XXX - special values */
	{ &hf_pn_io_cminitiator_udprtport,
		{ "CMInitiatorUDPRTPort", "pn_io.cminitiator_udprtport", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},  /* XXX - special values */
	{ &hf_pn_io_station_name_length,
		{ "StationNameLength", "pn_io.station_name_length", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_io_cminitiator_station_name,
		{ "CMInitiatorStationName", "pn_io.cminitiator_station_name", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

	{ &hf_pn_io_cmresponder_macadd,
      { "CMResponderMacAdd", "pn_io.cmresponder_macadd", FT_ETHER, BASE_HEX, 0x0, 0x0, "", HFILL }},
	{ &hf_pn_io_cmresponder_udprtport,
		{ "CMResponderUDPRTPort", "pn_io.cmresponder_udprtport", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},  /* XXX - special values */

    { &hf_pn_io_iocr_type,
    { "IOCRType", "pn_io.iocr_type", FT_UINT16, BASE_HEX, VALS(pn_io_iocr_type), 0x0, "", HFILL }},
    { &hf_pn_io_iocr_reference,
    { "IOCRReference", "pn_io.iocr_reference", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_lt,
    { "LT", "pn_io.lt", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
	{ &hf_pn_io_iocr_properties,
    { "IOCRProperties", "pn_io.iocr_properties", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},  /* XXX - 32 bitfield! */
    { &hf_pn_io_data_length,
      { "DataLength", "pn_io.data_length", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_frame_id,
      { "FrameID", "pn_io.frame_id", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_send_clock_factor,
      { "SendClockFactor", "pn_io.send_clock_factor", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }}, /* XXX - special values */
    { &hf_pn_io_reduction_ratio,
      { "ReductionRatio", "pn_io.reduction_ratio", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }}, /* XXX - special values */
    { &hf_pn_io_phase,
      { "Phase", "pn_io.phase", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_sequence,
      { "Sequence", "pn_io.sequence", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_frame_send_offset,
      { "FrameSendOffset", "pn_io.frame_send_offset", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_watchdog_factor,
      { "WatchdogFactor", "pn_io.watchdog_factor", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_data_hold_factor,
      { "DataHoldFactor", "pn_io.data_hold_factor", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_iocr_tag_header,
      { "IOCRTagHeader", "pn_io.iocr_tag_header", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_iocr_multicast_mac_add,
      { "IOCRMulticastMACAdd", "pn_io.iocr_multicast_mac_add", FT_ETHER, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_number_of_apis,
      { "NumberOfAPIs", "pn_io.number_of_apis", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_number_of_io_data_objects,
      { "NumberOfIODataObjects", "pn_io.number_of_io_data_objects", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_io_data_object_frame_offset,
      { "IODataObjectFrameOffset", "pn_io.io_data_object_frame_offset", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_number_of_iocs,
      { "NumberOfIOCS", "pn_io.number_of_iocs", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_iocs_frame_offset,
      { "IOCSFrameOffset", "pn_io.iocs_frame_offset", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_pn_io_alarmcr_type,
    { "AlarmCRType", "pn_io.alarmcr_type", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
	{ &hf_pn_io_alarmcr_properties,
    { "AlarmCRProperties", "pn_io.alarmcr_properties", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},  /* XXX - 32 bitfield! */
	{ &hf_pn_io_rta_timeoutfactor,
		{ "RTATimeoutFactor", "pn_io.rta_timeoutfactor", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},  /* XXX - special values */
	{ &hf_pn_io_rta_retries,
		{ "RTARetries", "pn_io.rta_retries", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},  /* XXX - only values 3 - 15 allowed */
	{ &hf_pn_io_localalarmref,
		{ "LocalAlarmReference", "pn_io.localalarmref", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},  /* XXX - special values */
	{ &hf_pn_io_maxalarmdatalength,
		{ "MaxAlarmDataLength", "pn_io.maxalarmdatalength", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},  /* XXX - only values 200 - 1432 allowed */
	{ &hf_pn_io_alarmcr_tagheaderhigh,
		{ "AlarmCRTagHeaderHigh", "pn_io.alarmcr_tagheaderhigh", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},  /* XXX - 16 bitfield! */
	{ &hf_pn_io_alarmcr_tagheaderlow,
		{ "AlarmCRTagHeaderLow", "pn_io.alarmcr_tagheaderlow", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},  /* XXX - 16 bitfield!*/

    { &hf_pn_io_api_tree,
      { "API", "pn_io.api", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_module_tree,
      { "Module", "pn_io.module", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_submodule_tree,
      { "Submodule", "pn_io.submodule", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_io_data_object,
      { "IODataObject", "pn_io.io_data_object", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_io_cs,
      { "IOCS", "pn_io.io_cs", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_pn_io_ar_uuid,
      { "ARUUID", "pn_io.ar_uuid", FT_GUID, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_target_ar_uuid,
      { "TargetARUUID", "pn_io.target_ar_uuid", FT_GUID, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_api,
      { "API", "pn_io.api", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_slot_nr,
      { "SlotNumber", "pn_io.slot_nr", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_subslot_nr,
      { "SubslotNumber", "pn_io.subslot_nr", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_index,
      { "Index", "pn_io.index", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
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
    { &hf_pn_io_block_header,
      { "BlockHeader", "pn_io.block_header", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
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
      { "SubmoduleIdentNumber", "pn_io.submodule_ident_number", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_pn_io_number_of_modules,
      { "NumberOfModules", "pn_io.number_of_modules", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_module_properties,
      { "ModuleProperties", "pn_io.module_properties", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_module_state,
      { "ModuleState", "pn_io.module_state", FT_UINT16, BASE_HEX, VALS(pn_io_module_state), 0x0, "", HFILL }},
    { &hf_pn_io_number_of_submodules,
      { "NumberOfSubmodules", "pn_io.number_of_submodules", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_submodule_properties,
      { "SubmoduleProperties", "pn_io.submodule_properties", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_submodule_state,
      { "SubmoduleState", "pn_io.submodule_state", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_pn_io_data_description_tree,
      { "DataDescription", "pn_io.data_description", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_data_description,
      { "DataDescription", "pn_io.data_description", FT_UINT16, BASE_HEX, VALS(pn_io_data_description), 0x0, "", HFILL }},
    { &hf_pn_io_submodule_data_length,
      { "SubmoduleDataLength", "pn_io.submodule_data_length", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_length_iocs,
      { "LengthIOCS", "pn_io.length_iocs", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_length_iops,
      { "LengthIOPS", "pn_io.length_iops", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_pn_io_ioxs,
      { "IOxS", "pn_io.ioxs", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_ioxs_extension,
      { "Extension (1:another IOxS follows/0:no IOxS follows)", "pn_io.ioxs.extension", FT_UINT8, BASE_HEX, NULL, 0x01, "", HFILL }},
    { &hf_pn_io_ioxs_res14,
      { "Reserved (should be zero)", "pn_io.ioxs.res14", FT_UINT8, BASE_HEX, NULL, 0x1E, "", HFILL }},
    { &hf_pn_io_ioxs_instance,
      { "Instance (only valid, if DataState is bad)", "pn_io.ioxs.instance", FT_UINT8, BASE_HEX, VALS(pn_io_ioxs), 0x60, "", HFILL }},
    { &hf_pn_io_ioxs_datastate,
      { "DataState (1:good/0:bad)", "pn_io.ioxs.datastate", FT_UINT8, BASE_HEX, NULL, 0x80, "", HFILL }},

    { &hf_pn_io_address_resolution_properties,
      { "AddressResolutionProperties", "pn_io.address_resolution_properties", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_mci_timeout_factor,
      { "MCITimeoutFactor", "pn_io.mci_timeout_factor", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_io_provider_station_name,
		{ "ProviderStationName", "pn_io.provider_station_name", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }}

    };

	static gint *ett[] = {
		&ett_pn_io,
        &ett_pn_io_block,
        &ett_pn_io_block_header,
        &ett_pn_io_status,
        &ett_pn_io_rtc,
        &ett_pn_io_rta,
		&ett_pn_io_pdu_type,
        &ett_pn_io_add_flags,
        &ett_pn_io_control_command,
        &ett_pn_io_ioxs,
        &ett_pn_io_api,
        &ett_pn_io_data_description,
        &ett_pn_io_module,
        &ett_pn_io_submodule,
        &ett_pn_io_io_data_object,
        &ett_pn_io_io_cs
	};

	proto_pn_io = proto_register_protocol ("PROFINET IO", "PNIO", "pn_io");
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
