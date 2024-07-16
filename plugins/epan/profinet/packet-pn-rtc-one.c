/* packet-pn-rtc-one.c
 * Routines for PROFINET IO - RTC1 dissection.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
 * (like establishing, ...) and is using DCE-RPC as its underlying
 * protocol.
 *
 * The actual cyclic data transfer and acyclic notification uses the
 * "lightweight" PN-RT protocol.
 *
 * There are some other related PROFINET protocols (e.g. PN-DCP, which is
 * handling addressing topics).
 *
 * Please note: the PROFINET CBA protocol is independent of the PN-IO protocol!
 */

/*
 * Cyclic PNIO RTC1 Data Dissection:
 *
 * To dissect cyclic PNIO RTC1 frames, this plug-in has to collect important module
 * information out of "Ident OK", "Connect Request" and "Write Response"
 * frames first.
 *
 * The data of Stationname-, -type and -id will be gained out of
 * packet-pn-dcp.c. The header packet-pn.h will transfer those data between
 * those two files.
 *
 * This file is used as a "addon" for packet-dcerpc-pn-io.c. Within "packet-dcerpc-pn-io.c"
 * the defined structures in "packet-pn.h" will be filled with all necessary information.
 * Those informations will be used in thise file to dissect cyclic PNIO RTC1 and PROFIsafe
 * frames. Furthermore since RTC1 is a special frame type of PNIO, this dissection uses the
 * already defined protocol PNIO.
 *
 * Overview for cyclic PNIO RTC1 data dissection functions:
 *   -> dissect_PNIO_C_SDU_RTC1 (general dissection of RTC1)
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/dissectors/packet-dcerpc.h>
#include <epan/proto.h>
#include <epan/expert.h>

#include "packet-pn.h"


#define F_MESSAGE_TRAILER_4BYTE  4      /* PROFIsafe: Defines the Amount of Bytes for CRC and Status-/Controlbyte in PROFIsafe 2.4 */
#define F_MESSAGE_TRAILER_5BYTE  5      /* PROFIsafe: Defines the Amount of Bytes for CRC and Status-/Controlbyte in PROFIsafe 2.6 */
#define PN_INPUT_CR              1      /* PROFINET Input Connect Request value */
#define PN_INPUT_DATADESCRITPION 1      /* PROFINET Input Data Description value */

#define PA_PROFILE_API 0x9700u

static int proto_pn_io_rtc1;

/* General module information */
static int hf_pn_io_frame_info_type;
static int hf_pn_io_frame_info_vendor;
static int hf_pn_io_frame_info_nameofstation;
static int hf_pn_io_frame_info_gsd_found;
static int hf_pn_io_frame_info_gsd_error;
static int hf_pn_io_frame_info_gsd_path;
static int hf_pn_io_io_data_object;
static int hf_pn_io_io_data_object_info_module_diff;
static int hf_pn_io_io_data_object_info_moduleidentnumber;
static int hf_pn_io_io_data_object_info_submoduleidentnumber;

static int hf_pn_io_iocs;
static int hf_pn_io_iops;
static int hf_pn_io_ioxs_extension;
static int hf_pn_io_ioxs_res14;
static int hf_pn_io_ioxs_instance;
static int hf_pn_io_ioxs_datastate;

/* PROFIsafe statusbyte and controlbyte */
static int hf_pn_io_ps_sb;
static int hf_pn_io_ps_sb_iparOK;
static int hf_pn_io_ps_sb_DeviceFault;
static int hf_pn_io_ps_sb_CECRC;
static int hf_pn_io_ps_sb_WDtimeout;
static int hf_pn_io_ps_sb_FVactivated;
static int hf_pn_io_ps_sb_Toggle_d;
static int hf_pn_io_ps_sb_ConsNr_reset;
static int hf_pn_io_ps_sb_res;
static int hf_pn_io_ps_sb_toggelBitChanged;
static int hf_pn_io_ps_sb_toggelBitChange_slot_nr;
static int hf_pn_io_ps_sb_toggelBitChange_subslot_nr;

static int hf_pn_io_ps_cb;
static int hf_pn_io_ps_cb_iparEN;
static int hf_pn_io_ps_cb_OAReq;
static int hf_pn_io_ps_cb_resetConsNr;
static int hf_pn_io_ps_cb_useTO2;
static int hf_pn_io_ps_cb_activateFV;
static int hf_pn_io_ps_cb_Toggle_h;
static int hf_pn_io_ps_cb_Chf_ACK;
static int hf_pn_io_ps_cb_loopcheck;
static int hf_pn_io_ps_cb_toggelBitChanged;
static int hf_pn_io_ps_cb_toggelBitChange_slot_nr;
static int hf_pn_io_ps_cb_toggelBitChange_subslot_nr;

/* PROFIsafe */
static int hf_pn_io_ps_f_dest_adr;
static int hf_pn_io_ps_f_data;

/* PA Profile 4.02 */
static int hf_pn_pa_profile_status;
static int hf_pn_pa_profile_status_quality;
static int hf_pn_pa_profile_status_substatus_bad;
static int hf_pn_pa_profile_status_substatus_uncertain;
static int hf_pn_pa_profile_status_substatus_good;
static int hf_pn_pa_profile_status_update_event;
static int hf_pn_pa_profile_status_simulate;
static int hf_pn_pa_profile_value_8bit;
static int hf_pn_pa_profile_value_16bit;
static int hf_pn_pa_profile_value_float;

static int ett_pn_io_rtc;
static int ett_pn_io_ioxs;
static int ett_pn_io_io_data_object;
static int ett_pn_pa_profile_status;

static expert_field ei_pn_io_too_many_data_objects;

static const value_string pn_io_ioxs_extension[] = {
    { 0x00 /*  0*/, "No IOxS octet follows" },
    { 0x01 /*  1*/, "One more IOxS octet follows" },
    { 0, NULL }
};

static const value_string pn_io_ioxs_instance[] = {
    { 0x00 /*  0*/, "Detected by subslot" },
    { 0x01 /*  1*/, "Detected by slot" },
    { 0x02 /*  2*/, "Detected by IO device" },
    { 0x03 /*  3*/, "Detected by IO controller" },
    { 0, NULL }
};

static const value_string pn_io_ioxs_datastate[] = {
    { 0x00 /*  0*/, "Bad" },
    { 0x01 /*  1*/, "Good" },
    { 0, NULL }
};

static const value_string pn_pa_profile_status_quality[] = {
    { 0x00 /*  0*/, "BAD" },
    { 0x01 /*  1*/, "UNCERTAIN" },
    { 0x02 /*  2*/, "GOOD" },
    { 0, NULL }
};

static const value_string pn_pa_profile_status_substatus_bad[] = {
    { 0x0, "Non specific" },
    { 0x2, "Not connected" },
    { 0x8, "Passivated" },
    { 0x9, "Maintenance alarm, more diagnosis" },
    { 0xA, "Process related, no maintenance" },
    { 0xF, "Function check, value not usable" },
    { 0, NULL }
};

static const value_string pn_pa_profile_status_substatus_uncertain[] = {
    { 0x2, "Substitute set" },
    { 0x3, "Initial value" },
    { 0xA, "Maintenance demanded" },
    { 0xE, "Process related, no maintenance" },
    { 0, NULL }
};

static const value_string pn_pa_profile_status_substatus_good[] = {
    { 0x0, "Good" },
    { 0x7, "Local override" },
    { 0x8, "Initial fail safe" },
    { 0x9, "Maintenance required" },
    { 0xA, "Maintenance demanded" },
    { 0xF, "Function check" },
    { 0, NULL }
};

static const value_string pn_pa_profile_status_update_event[] = {
    { 0x0, "No event" },
    { 0x1, "Update event" },
    { 0, NULL }
};

static const value_string pn_pa_profile_status_simulate[] = {
    { 0x0, "Simulation off" },
    { 0x1, "Simulation active" },
    { 0, NULL }
};


static int * const ps_sb_fields[] = {
    &hf_pn_io_ps_sb_res,
    &hf_pn_io_ps_sb_ConsNr_reset,
    &hf_pn_io_ps_sb_Toggle_d,
    &hf_pn_io_ps_sb_FVactivated,
    &hf_pn_io_ps_sb_WDtimeout,
    &hf_pn_io_ps_sb_CECRC,
    &hf_pn_io_ps_sb_DeviceFault,
    &hf_pn_io_ps_sb_iparOK,
    NULL
};

static int * const ps_cb_fields[] = {
    &hf_pn_io_ps_cb_loopcheck,
    &hf_pn_io_ps_cb_Chf_ACK,
    &hf_pn_io_ps_cb_Toggle_h,
    &hf_pn_io_ps_cb_activateFV,
    &hf_pn_io_ps_cb_useTO2,
    &hf_pn_io_ps_cb_resetConsNr,
    &hf_pn_io_ps_cb_OAReq,
    &hf_pn_io_ps_cb_iparEN,
    NULL
};

static int * const ioxs_fields[] = {
    &hf_pn_io_ioxs_datastate,
    &hf_pn_io_ioxs_instance,
    &hf_pn_io_ioxs_res14,
    &hf_pn_io_ioxs_extension,
    NULL
};

/*
static int * const pa_profile_status_fields[] = {
    &hf_pn_pa_profile_status_quality,
    &hf_pn_pa_profile_status_substatus_bad,
    &hf_pn_pa_profile_status_substatus_uncertain,
    &hf_pn_pa_profile_status_substatus_good,
    &hf_pn_pa_profile_status_update_event,
    &hf_pn_pa_profile_status_simulate,
    NULL
};
*/

/* Dissector for PROFIsafe Status Byte */
static int
dissect_pn_io_ps_SB(tvbuff_t *tvb, int offset,
packet_info *pinfo _U_, proto_tree *tree, uint8_t *drep _U_, int hfindex, int * const *fields)
{

    if (tree) {
        uint8_t    u8StatusByte;
        proto_item *sb_item;

        u8StatusByte = tvb_get_uint8(tvb, offset);

        /* Add Status Byte subtree */
        sb_item = proto_tree_add_bitmask_with_flags(tree, tvb, offset, hfindex, ett_pn_io_ioxs, fields,
            ENC_LITTLE_ENDIAN, BMT_NO_APPEND);
        proto_item_append_text(sb_item, " (%s)", ((u8StatusByte == 0x20) || (u8StatusByte == 0x00)) ? "normal" : "unnormal");
    }

    return offset + 1;
}


/* Dissector for PROFIsafe Control Byte */
static int
dissect_pn_io_ps_CB(tvbuff_t *tvb, int offset,
packet_info *pinfo _U_, proto_tree *tree, uint8_t *drep _U_, int hfindex, int * const *fields)
{

    if (tree) {
        uint8_t    u8ControlByte;
        proto_item *cb_item;

        u8ControlByte = tvb_get_uint8(tvb, offset);

        /* Add Status Byte subtree */
        cb_item = proto_tree_add_bitmask_with_flags(tree, tvb, offset, hfindex, ett_pn_io_ioxs, fields,
            ENC_LITTLE_ENDIAN, BMT_NO_APPEND);
        proto_item_append_text(cb_item, " (%s)", ((u8ControlByte == 0x20) || (u8ControlByte == 0x00) ||
            (u8ControlByte == 0xa0) || (u8ControlByte == 0x80)) ? "normal" : "unnormal");
    }

    return offset + 1;
}


/* Dissector for IOCS (As each IOCS stands for a specific Slot & Subslot) */
static int
dissect_PNIO_IOCS(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree,
            uint8_t *drep _U_, int hfindex, uint16_t slotNr, uint16_t subSlotNr, int * const *fields)
{

    if (tree) {
        uint8_t     u8IOxS;
        proto_item *ioxs_item;

        u8IOxS = tvb_get_uint8(tvb, offset);

        /* Add ioxs subtree */
        ioxs_item = proto_tree_add_bitmask_with_flags(tree, tvb, offset, hfindex,
            ett_pn_io_ioxs, fields, ENC_LITTLE_ENDIAN, BMT_NO_APPEND);
        proto_item_append_text(ioxs_item,
            " (%s%s), Slot: 0x%x, Subslot: 0x%x",
            (u8IOxS & 0x01) ? "another IOxS follows " : "",
            (u8IOxS & 0x80) ? "good" : "bad",
            slotNr,
            subSlotNr);
    }

    return offset + 1;
}


/* dissect the IOxS (IOCS, IOPS) field */
static int
dissect_PNIO_IOxS(tvbuff_t *tvb, int offset,
packet_info *pinfo _U_, proto_tree *tree, uint8_t *drep _U_, int hfindex, int * const *fields)
{

    if (tree) {
        uint8_t    u8IOxS;
        proto_item *ioxs_item;

        u8IOxS = tvb_get_uint8(tvb, offset);

        /* Add ioxs subtree */
        ioxs_item = proto_tree_add_bitmask_with_flags(tree, tvb, offset, hfindex,
            ett_pn_io_ioxs, fields, ENC_LITTLE_ENDIAN, BMT_NO_APPEND);
        proto_item_append_text(ioxs_item,
            " (%s%s)",
            (u8IOxS & 0x01) ? "another IOxS follows " : "",
            (u8IOxS & 0x80) ? "good" : "bad");
    }

    return offset + 1;
}


/* Universal dissector for flexibel PROFIsafe Data 8 to 64 Bits */
static int
dissect_pn_io_ps_uint(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
    proto_tree *tree, uint8_t *drep,
int hfindex, uint8_t bytelength, uint64_t *pdata)
{
    uint64_t data;
    bool generalDissection;

    generalDissection = false;

    switch (bytelength) {
    case 1:     /* 8 Bit Safety IO Data */
        data = tvb_get_uint8(tvb, offset);
        if (pdata)
            *pdata = data;
        break;

    case 2:     /* 16 Bit Safety IO Data */
        data = tvb_get_letohs(tvb, offset);
        if (pdata)
            *pdata = data;
        break;

    case 3:     /* 24 Bit Safety IO Data */
        data = tvb_get_letoh24(tvb, offset);
        if (pdata)
            *pdata = data;
        break;

    case 4:     /* 32 Bit Safety IO Data */
        data = tvb_get_letohl(tvb, offset);
        if (pdata)
            *pdata = data;
        break;

    case 5:     /* 40 Bit Safety IO Data */
        data = tvb_get_letoh40(tvb, offset);
        if (pdata)
            *pdata = data;
        break;

    case 6:     /* 48 Bit Safety IO Data */
        data = tvb_get_letoh48(tvb, offset);
        if (pdata)
            *pdata = data;
        break;

    case 7:     /* 56 Bit Safety IO Data */
        data = tvb_get_letoh56(tvb, offset);
        if (pdata)
            *pdata = data;
        break;

    case 8:     /* 64 Bit Safety IO Data */
        data = tvb_get_letoh64(tvb, offset);
        if (pdata)
            *pdata = data;
        break;

    default:    /* Safety IO Data is too big to save it into one variable */
        dissect_pn_user_data(tvb, offset, pinfo, tree, bytelength, "Safety IO Data");
        generalDissection = true;
        break;
    }

    if (tree && generalDissection == false) {
        proto_tree_add_item(tree, hfindex, tvb, offset, bytelength, DREP_ENC_INTEGER(drep));
    }

    return offset + bytelength;
}


/* dissect a PN-IO RTC1 Cyclic Service Data Unit */
int
dissect_PNIO_C_SDU_RTC1(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, uint8_t *drep _U_, uint16_t frameid)
{
    proto_tree  *data_tree = NULL;

    /* Count & offset for comparison of the arrays */
    uint16_t    frameOffset;
    uint32_t    objectCounter;
    bool        inputFlag;
    bool        outputFlag;
    bool        psInfoText;     /* Used to display only once per frame the info text "PROFIsafe Device" */

    proto_item *data_item;
    proto_item *IODataObject_item;
    proto_item *IODataObject_item_info;
    proto_tree *IODataObject_tree;
    proto_item *ModuleID_item;
    proto_item *ModuleDiff_item;

    wmem_strbuf_t *moduleName;

    uint8_t toggleBitSb;
    uint8_t toggleBitCb;
    uint64_t f_data;

    uint8_t statusbyte;
    uint8_t controlbyte;
    uint8_t safety_io_data_length;

    uint16_t number_io_data_objects_input_cr;
    uint16_t number_iocs_input_cr;
    uint16_t number_io_data_objects_output_cr;
    uint16_t number_iocs_output_cr;

    conversation_t    *conversation;
    stationInfo       *station_info = NULL;
    iocsObject        *iocs_object;
    ioDataObject      *io_data_object;
    moduleDiffInfo    *module_diff_info;
    wmem_list_frame_t *frame;
    wmem_list_frame_t *frame_diff;

    /* Initial */
    frameOffset = 0;
    f_data = 0;
    inputFlag = false;
    outputFlag = false;
    psInfoText = false;
    number_io_data_objects_input_cr = 0;
    number_iocs_input_cr = 0;
    number_io_data_objects_output_cr = 0;
    number_iocs_output_cr = 0;

    wmem_list_frame_t  *aruuid_frame;
    ARUUIDFrame        *current_aruuid_frame = NULL;
    uint32_t            current_aruuid = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PNIO");            /* set protocol name */

    data_item = proto_tree_add_protocol_format(tree, proto_pn_io_rtc1, tvb, offset, tvb_captured_length(tvb),
            "PROFINET IO Cyclic Service Data Unit: %u bytes", tvb_captured_length(tvb));
    data_tree = proto_item_add_subtree(data_item, ett_pn_io_rtc);

    /* dissect_dcerpc_uint16(tvb, offset, pinfo, data_tree, drep, hf_pn_io_packedframe_SFCRC, &u16SFCRC); */
    if (dissect_CSF_SDU_heur(tvb, pinfo, data_tree, NULL))
        return(tvb_captured_length(tvb));

    /* Only dissect cyclic RTC1 frames, if PN Connect Request has been read */
    conversation = find_conversation(pinfo->num, &pinfo->dl_src, &pinfo->dl_dst, CONVERSATION_NONE, 0, 0, 0);

    /* Detect input data package and output data package */
    if (conversation != NULL) {
        if (aruuid_frame_setup_list != NULL) {
            for (aruuid_frame = wmem_list_tail(aruuid_frame_setup_list); aruuid_frame != NULL; aruuid_frame = wmem_list_frame_prev(aruuid_frame)) {
                current_aruuid_frame = (ARUUIDFrame*)wmem_list_frame_data(aruuid_frame);
                /* There are prerequisites to dissect RTC frame data */
                /* Current station info must be found before RTC frame dissection starts */
                /* if RTC frame has setup frame and setup frame number is less than RTC frame number AND if RTC frame has release frame and release frame number is greater than RTC frame number */
                /* if RTC frame has setup frame and setup frame number is less than RTC frame number AND RTC frame does not have release frame yet! */
                /* then, get AR UUID of current station info */
                if ((current_aruuid_frame->setupframe && current_aruuid_frame->setupframe < pinfo->num) &&
                   ((current_aruuid_frame->releaseframe && current_aruuid_frame->releaseframe > pinfo->num) ||
                    !current_aruuid_frame->releaseframe)) {
                    if (current_aruuid_frame->inputframe == frameid) {
                        current_aruuid = current_aruuid_frame->aruuid.data1;
                        break;
                    }
                    else if (current_aruuid_frame->outputframe == frameid) {
                        current_aruuid = current_aruuid_frame->aruuid.data1;
                        break;
                    }
                }
            }
        }

        station_info = (stationInfo*)conversation_get_proto_data(conversation, current_aruuid);

        if (station_info != NULL) {
            pn_find_dcp_station_info(station_info, conversation);

            if (pnio_ps_selection == true) {
                col_set_str(pinfo->cinfo, COL_PROTOCOL, "PNIO_PS");    /* set PROFISsafe protocol name */
            }

            if (addresses_equal(&(pinfo->src), conversation_key_addr1(conversation->key_ptr)) && addresses_equal(&(pinfo->dst), conversation_key_addr2(conversation->key_ptr))) {
                inputFlag = true;
                outputFlag = false;
                number_io_data_objects_input_cr = station_info->ioDataObjectNr_in;
                number_iocs_input_cr = station_info->iocsNr_in;
            }

            if (addresses_equal(&(pinfo->dst), conversation_key_addr1(conversation->key_ptr)) && addresses_equal(&(pinfo->src), conversation_key_addr2(conversation->key_ptr))) {
                outputFlag = true;
                inputFlag = false;
                number_io_data_objects_output_cr = station_info->ioDataObjectNr_out;
                number_iocs_output_cr = station_info->iocsNr_out;
            }
        }
    }

    /* ------- Input (PNIO) / Response (PNIO_PS) Frame Handling ------- */
    if (inputFlag) {
        if (pnio_ps_selection == true) {
            proto_tree_add_string_format_value(data_tree, hf_pn_io_frame_info_type, tvb,
                offset, 0, "Response", "Response Frame (IO_Device -> IO_Controller)");
        }
        else {
            proto_tree_add_string_format_value(data_tree, hf_pn_io_frame_info_type, tvb,
                offset, 0, "Input", "Input Frame (IO_Device -> IO_Controller)");
        }

        if (station_info != NULL) {
            if (station_info->typeofstation != NULL) {
                proto_tree_add_string_format_value(data_tree, hf_pn_io_frame_info_vendor, tvb, 0,
                    0, station_info->typeofstation, "\"%s\"", station_info->typeofstation);
            }
            if (station_info->nameofstation != NULL) {
                proto_tree_add_string_format_value(data_tree, hf_pn_io_frame_info_nameofstation, tvb, 0,
                    0, station_info->nameofstation, "\"%s\"", station_info->nameofstation);
            }

            if (station_info->gsdPathLength == true) {      /* given path isn't too long for the array */
                if (station_info->gsdFound == true) {       /* found a GSD-file */
                    if (station_info->gsdLocation != NULL) {
                        IODataObject_item_info = proto_tree_add_item(data_tree, hf_pn_io_frame_info_gsd_found, tvb, offset, 0, ENC_NA);
                        proto_item_append_text(IODataObject_item_info, ": \"%s\"", station_info->gsdLocation);
                    }
                }
                else {
                    if (station_info->gsdLocation != NULL) {
                        IODataObject_item_info = proto_tree_add_item(data_tree, hf_pn_io_frame_info_gsd_error, tvb, offset, 0, ENC_NA);
                        proto_item_append_text(IODataObject_item_info, " Please place relevant GSD-file under \"%s\"", station_info->gsdLocation);
                    }
                }
            }
            else {
                IODataObject_item_info = proto_tree_add_item(data_tree, hf_pn_io_frame_info_gsd_path, tvb, offset, 0, ENC_NA);
                proto_item_append_text(IODataObject_item_info, " Please check your GSD-file networkpath. (No Path configured)");
            }
        }

        /* ---- Input IOData-/IOCS-Object Handling ---- */
        objectCounter = number_io_data_objects_input_cr + number_iocs_input_cr;
        if (objectCounter > (unsigned)tvb_reported_length_remaining(tvb, offset)) {
            expert_add_info_format(pinfo, data_item, &ei_pn_io_too_many_data_objects, "Too many data objects: %d", objectCounter);
            return(tvb_captured_length(tvb));
        }

        while (objectCounter--) {
            /* ---- Input IO Data Object Handling ---- */
            if (station_info != NULL) {
                for (frame = wmem_list_head(station_info->ioobject_data_in); frame != NULL; frame = wmem_list_frame_next(frame)) {
                    io_data_object = (ioDataObject*)wmem_list_frame_data(frame);
                    if (io_data_object->frameOffset == frameOffset) {
                        /* Found following object */

                        IODataObject_item = proto_tree_add_item(data_tree, hf_pn_io_io_data_object, tvb, offset, 0, ENC_NA);
                        IODataObject_tree = proto_item_add_subtree(IODataObject_item, ett_pn_io_io_data_object);

                        /* Control: the Device still uses the correct ModuleIdentNumber? */
                        for (frame_diff = wmem_list_head(station_info->diff_module); frame_diff != NULL; frame_diff = wmem_list_frame_next(frame_diff)) {
                            module_diff_info = (moduleDiffInfo*)wmem_list_frame_data(frame_diff);
                            if (io_data_object->moduleIdentNr != module_diff_info->modulID) {
                                ModuleDiff_item = proto_tree_add_item(IODataObject_tree, hf_pn_io_io_data_object_info_module_diff, tvb, 0, 0, ENC_NA);
                                proto_item_append_text(ModuleDiff_item, ": Device using ModuleIdentNumber 0x%08x instead of 0x%08x", module_diff_info->modulID, io_data_object->moduleIdentNr);
                                break;
                            }
                        }

                        proto_tree_add_uint(IODataObject_tree, hf_pn_io_io_data_object_info_moduleidentnumber, tvb, 0, 0, io_data_object->moduleIdentNr);
                        proto_tree_add_uint(IODataObject_tree, hf_pn_io_io_data_object_info_submoduleidentnumber, tvb, 0, 0, io_data_object->subModuleIdentNr);

                        /* PROFIsafe Supported Inputmodule handling */
                        if (io_data_object->profisafeSupported == true && pnio_ps_selection == true) {
                            if (io_data_object->profisafeSupported == true && psInfoText == false) {
                                /* Only add one information string per device to the infotext */
                                col_append_str(pinfo->cinfo, COL_INFO, ", PROFIsafe Device");    /* Add string to wireshark infotext */
                                psInfoText = true;
                            }

                            proto_tree_add_uint(IODataObject_tree, hf_pn_io_ps_f_dest_adr, tvb, 0, 0, io_data_object->f_dest_adr);

                            /* Get Safety IO Data */
                            if (io_data_object->f_crc_seed == false) {
                                safety_io_data_length = io_data_object->length - F_MESSAGE_TRAILER_4BYTE;
                            } else {
                                safety_io_data_length = io_data_object->length - F_MESSAGE_TRAILER_5BYTE;
                            }

                            if (safety_io_data_length > 0) {
                                offset = dissect_pn_io_ps_uint(tvb, offset, pinfo, IODataObject_tree, drep, hf_pn_io_ps_f_data,
                                    safety_io_data_length, &f_data);
                            }

                            /* ---- Check for new PNIO data using togglebit ---- */
                            statusbyte = tvb_get_uint8(tvb, offset);
                            toggleBitSb = statusbyte & 0x20;     /* get ToggleBit of StatusByte */

                            if (io_data_object->lastToggleBit != toggleBitSb) {    /* ToggleBit has changed --> new Data incoming */
                                /* Special Filter for ToggleBit within Statusbyte */
                                ModuleID_item = proto_tree_add_uint(IODataObject_tree, hf_pn_io_ps_sb_toggelBitChanged, tvb, offset, 0, toggleBitSb);
                                proto_item_set_hidden(ModuleID_item);

                                ModuleID_item = proto_tree_add_uint(IODataObject_tree, hf_pn_io_ps_sb_toggelBitChange_slot_nr, tvb, offset, 0, io_data_object->slotNr);
                                proto_item_set_hidden(ModuleID_item);

                                ModuleID_item = proto_tree_add_uint(IODataObject_tree, hf_pn_io_ps_sb_toggelBitChange_subslot_nr, tvb, offset, 0, io_data_object->subSlotNr);
                                proto_item_set_hidden(ModuleID_item);
                            }

                            offset = dissect_pn_io_ps_SB(tvb, offset, pinfo, IODataObject_tree, drep, hf_pn_io_ps_sb, ps_sb_fields);
                            offset = dissect_pn_user_data(tvb, offset, pinfo, IODataObject_tree, io_data_object->f_crc_len, "CRC");

                            io_data_object->last_sb_cb = statusbyte;       /* save the value of current statusbyte */
                            io_data_object->lastToggleBit = toggleBitSb;   /* save the value of current togglebit within statusbyte */
                        }    /* END of PROFIsafe Module Handling */

                        else {
                            /* Module is not PROFIsafe supported */
                            if (io_data_object->api == PA_PROFILE_API)
                            {
                                offset = dissect_pn_pa_profile_data(tvb, offset, pinfo, IODataObject_tree, io_data_object->length, "IO Data");
                            }
                            else
                            {
                                offset = dissect_pn_user_data(tvb, offset, pinfo, IODataObject_tree, io_data_object->length, "IO Data");
                            }
                        }

                        if (io_data_object->discardIOXS == false) {
                            offset = dissect_PNIO_IOxS(tvb, offset, pinfo, IODataObject_tree, drep, hf_pn_io_iops, ioxs_fields);
                            proto_item_set_len(IODataObject_item, io_data_object->length + 1);     /* Length = Databytes + IOXS Byte */
                        }
                        else {
                            proto_item_set_len(IODataObject_item, io_data_object->length);         /* Length = Databytes */
                        }

                        proto_item_append_text(IODataObject_item, ": Slot: 0x%x Subslot: 0x%x",
                            io_data_object->slotNr, io_data_object->subSlotNr);


                        /* ModuleIdentNr appears not only once in GSD-file -> set module name more generally */
                        if (io_data_object->amountInGSDML > 1) {    /* if ModuleIdentNr only appears once in GSD-file, use the found GSD-file-ModuleName, else ... */
                            if (io_data_object->slotNr == 0) {
                                moduleName = wmem_strbuf_new(pinfo->pool, "Headstation");
                            }
                            else {
                                moduleName = wmem_strbuf_new(pinfo->pool, "Module");
                            }

                            if (io_data_object->profisafeSupported == true) {
                                /* PROFIsafe */
                                if (io_data_object->length >= 5) {        /* 5 due to 3 CRC bytes &  1 status byte & (at least) 1 data byte */
                                    wmem_strbuf_append(moduleName, ", DI");
                                }
                                else {
                                    wmem_strbuf_append(moduleName, ", DO");
                                }
                            }
                            else {
                                /* PROFINET */
                                if (io_data_object->length > 0) {
                                    wmem_strbuf_append(moduleName, ", DI");
                                }
                                else {
                                    wmem_strbuf_append(moduleName, ", DO");
                                }
                            }

                            io_data_object->moduleNameStr = wmem_strdup(wmem_file_scope(), wmem_strbuf_get_str(moduleName));
                        }

                        proto_item_append_text(IODataObject_item, " ModuleName: \"%s\"", io_data_object->moduleNameStr);

                        /* emphasize the PROFIsafe supported Modul */
                        if (io_data_object->profisafeSupported == true && pnio_ps_selection == true) {
                            (proto_item_append_text(IODataObject_item, " (PROFIsafe Module)"));
                        }


                        /* Set frameOffset to its new value, to find the next object */
                        frameOffset = frameOffset + io_data_object->length;  /* frameOffset = current value + data bytes */
                        if (io_data_object->discardIOXS == false) {
                            frameOffset = frameOffset + 1;      /* frameOffset = current value + iops byte */
                        }
                    }
                }
            }

            /* ---- Input IOCS Object Handling ---- */
            if (station_info != NULL) {
                for (frame = wmem_list_head(station_info->iocs_data_in); frame != NULL; frame = wmem_list_frame_next(frame)) {
                    iocs_object = (iocsObject*)wmem_list_frame_data(frame);
                    if (iocs_object->frameOffset == frameOffset) {
                        offset = dissect_PNIO_IOCS(tvb, offset, pinfo, data_tree, drep, hf_pn_io_iocs, iocs_object->slotNr,
                            iocs_object->subSlotNr, ioxs_fields);

                        /* Set frameOffset to its new value, to find the next object */
                        frameOffset = frameOffset + 1;      /* frameOffset = current value + iops byte */

                        break;
                    }
                }
            }
        }

        /* Dissect padding */
        offset = dissect_pn_user_data(tvb, offset, pinfo, tree, tvb_captured_length_remaining(tvb, offset), "GAP and RTCPadding");
    }   /* END of Input Frame Handling */

    /* ----- Output (PNIO) / Request (PNIO_PS) Frame Handling ------ */
    else if (outputFlag) {
        if (pnio_ps_selection == true) {
            proto_tree_add_string_format_value(data_tree, hf_pn_io_frame_info_type, tvb,
                offset, 0, "Request", "Request Frame (IO_Controller -> IO_Device)");
        }
        else {
            proto_tree_add_string_format_value(data_tree, hf_pn_io_frame_info_type, tvb,
                offset, 0, "Output", "Output Frame (IO_Controller -> IO_Device)");
        }

        if (station_info != NULL) {
            if (station_info->typeofstation != NULL) {
                proto_tree_add_string_format_value(data_tree, hf_pn_io_frame_info_vendor, tvb, 0,
                    0, station_info->typeofstation, "\"%s\"", station_info->typeofstation);
            }
            if (station_info->nameofstation != NULL) {
                proto_tree_add_string_format_value(data_tree, hf_pn_io_frame_info_nameofstation, tvb, 0,
                    0, station_info->nameofstation, "\"%s\"", station_info->nameofstation);
            }

            if (station_info->gsdPathLength == true) {      /* given path isn't too long for the array */
                if (station_info->gsdFound == true) {       /* found a GSD-file */
                    if (station_info->gsdLocation != NULL) {
                        IODataObject_item_info = proto_tree_add_item(data_tree, hf_pn_io_frame_info_gsd_found, tvb, offset, 0, ENC_NA);
                        proto_item_append_text(IODataObject_item_info, ": \"%s\"", station_info->gsdLocation);
                    }
                }
                else {
                    if (station_info->gsdLocation != NULL) {
                        IODataObject_item_info = proto_tree_add_item(data_tree, hf_pn_io_frame_info_gsd_error, tvb, offset, 0, ENC_NA);
                        proto_item_append_text(IODataObject_item_info, " Please place relevant GSD-file under \"%s\"", station_info->gsdLocation);
                    }
                }
            }
            else {
                IODataObject_item_info = proto_tree_add_item(data_tree, hf_pn_io_frame_info_gsd_path, tvb, offset, 0, ENC_NA);
                proto_item_append_text(IODataObject_item_info, " Please check your GSD-file networkpath. (No Path configured)");
            }
        }

        /* ---- Output IOData-/IOCS-Object Handling ---- */
        objectCounter = number_io_data_objects_output_cr + number_iocs_output_cr;
        if (objectCounter > (unsigned)tvb_reported_length_remaining(tvb, offset)) {
            expert_add_info_format(pinfo, data_item, &ei_pn_io_too_many_data_objects, "Too many data objects: %d", objectCounter);
            return(tvb_captured_length(tvb));
        }
        while (objectCounter--) {
            /* ---- Output IO Data Object Handling ---- */
            if (station_info != NULL) {
                for (frame = wmem_list_head(station_info->ioobject_data_out); frame != NULL; frame = wmem_list_frame_next(frame)) {
                    io_data_object = (ioDataObject*)wmem_list_frame_data(frame);
                    if (io_data_object != NULL && io_data_object->frameOffset == frameOffset) {
                        /* Found following object */

                        IODataObject_item = proto_tree_add_item(data_tree, hf_pn_io_io_data_object, tvb, offset, 0, ENC_NA);
                        IODataObject_tree = proto_item_add_subtree(IODataObject_item, ett_pn_io_io_data_object);

                        /* Control: the Device still uses the correct ModuleIdentNumber? */
                        for (frame_diff = wmem_list_head(station_info->diff_module); frame_diff != NULL; frame_diff = wmem_list_frame_next(frame_diff)) {
                            module_diff_info = (moduleDiffInfo*)wmem_list_frame_data(frame_diff);
                            if (io_data_object->moduleIdentNr != module_diff_info->modulID) {
                                ModuleDiff_item = proto_tree_add_item(IODataObject_tree, hf_pn_io_io_data_object_info_module_diff, tvb, 0, 0, ENC_NA);
                                proto_item_append_text(ModuleDiff_item, ": Device using ModuleIdentNumber 0x%08x instead of 0x%08x", module_diff_info->modulID, io_data_object->moduleIdentNr);
                                break;
                            }
                        }

                        proto_tree_add_uint(IODataObject_tree, hf_pn_io_io_data_object_info_moduleidentnumber, tvb, 0, 0, io_data_object->moduleIdentNr);
                        proto_tree_add_uint(IODataObject_tree, hf_pn_io_io_data_object_info_submoduleidentnumber, tvb, 0, 0, io_data_object->subModuleIdentNr);

                        if (io_data_object->profisafeSupported == true && pnio_ps_selection == true) {
                            if (io_data_object->profisafeSupported == true && psInfoText == false) {
                                /* Only add one information string per device to the infotext */
                                col_append_str(pinfo->cinfo, COL_INFO, ", PROFIsafe Device");    /* Add string to wireshark infotext */
                                psInfoText = true;
                            }

                            proto_tree_add_uint(IODataObject_tree, hf_pn_io_ps_f_dest_adr, tvb, 0, 0, io_data_object->f_dest_adr);

                            /* Get Safety IO Data */
                            if (io_data_object->f_crc_seed == false) {
                                safety_io_data_length = io_data_object->length - F_MESSAGE_TRAILER_4BYTE;
                            } else {
                                safety_io_data_length = io_data_object->length - F_MESSAGE_TRAILER_5BYTE;
                            }

                            if (safety_io_data_length > 0) {
                                offset = dissect_pn_io_ps_uint(tvb, offset, pinfo, IODataObject_tree, drep, hf_pn_io_ps_f_data,
                                    safety_io_data_length, &f_data);
                            }

                            /* ---- Check for new PNIO data using togglebit ---- */
                            controlbyte = tvb_get_uint8(tvb, offset);
                            toggleBitCb = controlbyte & 0x20;               /* get ToggleBit of Controlbyte */

                            if (io_data_object->lastToggleBit != toggleBitCb) {   /* ToggleBit has changed --> new Data incoming */
                                /* Special Filter for ToggleBit within Controlbyte */
                                ModuleID_item = proto_tree_add_uint(IODataObject_tree, hf_pn_io_ps_cb_toggelBitChanged, tvb, offset, 0, toggleBitCb);
                                proto_item_set_hidden(ModuleID_item);

                                ModuleID_item = proto_tree_add_uint(IODataObject_tree, hf_pn_io_ps_cb_toggelBitChange_slot_nr, tvb, offset, 0, io_data_object->slotNr);
                                proto_item_set_hidden(ModuleID_item);

                                ModuleID_item = proto_tree_add_uint(IODataObject_tree, hf_pn_io_ps_cb_toggelBitChange_subslot_nr, tvb, offset, 0, io_data_object->subSlotNr);
                                proto_item_set_hidden(ModuleID_item);
                            }

                            offset = dissect_pn_io_ps_CB(tvb, offset, pinfo, IODataObject_tree, drep, hf_pn_io_ps_cb, ps_cb_fields);
                            offset = dissect_pn_user_data(tvb, offset, pinfo, IODataObject_tree, io_data_object->f_crc_len, "CRC");

                            io_data_object->last_sb_cb = controlbyte;         /* save the value of current controlbyte */
                            io_data_object->lastToggleBit = toggleBitCb;      /* save the value of current togglebit within controlbyte */
                        }    /* End of PROFIsafe Module Handling */
                        else {
                            /* Module is not PROFIsafe supported */
                            if (io_data_object->api == PA_PROFILE_API)
                            {
                                offset = dissect_pn_pa_profile_data(tvb, offset, pinfo, IODataObject_tree, io_data_object->length, "IO Data");
                            }
                            else
                            {
                                offset = dissect_pn_user_data(tvb, offset, pinfo, IODataObject_tree, io_data_object->length, "IO Data");
                            }
                        }

                        if (io_data_object->discardIOXS == false) {
                            offset = dissect_PNIO_IOxS(tvb, offset, pinfo, IODataObject_tree, drep, hf_pn_io_iops, ioxs_fields);
                            proto_item_set_len(IODataObject_item, io_data_object->length + 1);        /* Length = Databytes + IOXS Byte */
                        }
                        else {
                            proto_item_set_len(IODataObject_item, io_data_object->length);            /* Length = Databytes */
                        }

                        proto_item_append_text(IODataObject_item, ": Slot: 0x%x Subslot: 0x%x",
                            io_data_object->slotNr, io_data_object->subSlotNr);


                        /* ModuleIdentNr appears not only once in GSD-file -> set module name more generally */
                        if (io_data_object->amountInGSDML > 1) {    /* if ModuleIdentNr only appears once in GSD-file, use the found GSD-file-ModuleName, else ... */
                            if (io_data_object->slotNr == 0) {
                                moduleName = wmem_strbuf_new(pinfo->pool, "Headstation");
                            }
                            else {
                                moduleName = wmem_strbuf_new(pinfo->pool, "Module");
                            }

                            if (io_data_object->profisafeSupported == true) {
                                /* PROFIsafe */
                                if (io_data_object->length >= 5) {        /* 5 due to 3 CRC bytes &  1 status byte & (at least) 1 data byte */
                                    wmem_strbuf_append(moduleName, ", DO");
                                }
                                else {
                                    wmem_strbuf_append(moduleName, ", DI");
                                }
                            }
                            else {
                                /* PROFINET */
                                if (io_data_object->length > 0) {
                                    wmem_strbuf_append(moduleName, ", DO");
                                }
                                else {
                                    wmem_strbuf_append(moduleName, ", DI");
                                }
                            }

                            io_data_object->moduleNameStr = wmem_strdup(wmem_file_scope(), wmem_strbuf_get_str(moduleName));
                        }

                        proto_item_append_text(IODataObject_item, " ModuleName: \"%s\"", io_data_object->moduleNameStr);

                        /* emphasize the PROFIsafe supported Modul */
                        if (io_data_object->profisafeSupported == true && pnio_ps_selection == true) {
                            proto_item_append_text(IODataObject_item, " (PROFIsafe Module)");
                        }

                        /* Set frameOffset to its new value, to find the next object */
                        frameOffset = frameOffset + io_data_object->length; /* frameOffset = current value + data bytes */
                        if (io_data_object->discardIOXS == false) {
                            frameOffset = frameOffset + 1;      /* frameOffset = current value + iops byte */
                        }
                    }
                }
            }

            /* ---- Output IOCS Object Handling ---- */
            if (station_info != NULL) {
                for (frame = wmem_list_head(station_info->iocs_data_out); frame != NULL; frame = wmem_list_frame_next(frame)) {
                    iocs_object = (iocsObject*)wmem_list_frame_data(frame);
                    if (iocs_object->frameOffset == frameOffset) {
                        offset = dissect_PNIO_IOCS(tvb, offset, pinfo, data_tree, drep, hf_pn_io_iocs, iocs_object->slotNr,
                            iocs_object->subSlotNr, ioxs_fields);

                        /* Set frameOffset to its new value, to find the next object */
                        frameOffset = frameOffset + 1;      /* frameOffset = current value + iops byte */

                        break;
                    }
                }
            }
        }

        /* Dissect padding */
        offset = dissect_pn_user_data(tvb, offset, pinfo, tree, tvb_captured_length_remaining(tvb, offset), "GAP and RTCPadding");
    }   /* END of Output Frame Handling */

    return offset;
}


/* dissect the PA Profile status field */
static int
dissect_pn_pa_profile_status(tvbuff_t *tvb, int offset,
                             packet_info *pinfo _U_, proto_tree *tree, int hfindex)
{

    if (tree) {
        uint8_t     u8status;
        uint8_t     quality;
        proto_item *status_item;
        proto_tree *status_tree;
        const char* quality_name = NULL;

        u8status = tvb_get_uint8(tvb, offset);
        quality = (u8status >> 6u) & 0x3u;

        /* add status subtree */
        status_item = proto_tree_add_uint(tree, hfindex, tvb, offset, 1, u8status);

        quality_name = try_val_to_str(quality, pn_pa_profile_status_quality);

        proto_item_append_text(status_item,
                               " (%s)",
                               (quality_name != NULL) ? quality_name : "invalid");

        status_tree = proto_item_add_subtree(status_item, ett_pn_pa_profile_status);

        proto_tree_add_item(status_tree, hf_pn_pa_profile_status_quality, tvb, offset, 1, ENC_NA);

        switch(quality)
        {
            case 0:
                proto_tree_add_item(status_tree, hf_pn_pa_profile_status_substatus_bad, tvb, offset, 1, ENC_NA);
                break;
            case 1:
                proto_tree_add_item(status_tree, hf_pn_pa_profile_status_substatus_uncertain, tvb, offset, 1, ENC_NA);
                break;
            case 2:
                proto_tree_add_item(status_tree, hf_pn_pa_profile_status_substatus_good, tvb, offset, 1, ENC_NA);
                break;
            default:
                break;
        }
        proto_tree_add_item(status_tree, hf_pn_pa_profile_status_update_event, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(status_tree, hf_pn_pa_profile_status_simulate,     tvb, offset, 1, ENC_NA);
    }

    return offset + 1;
}

int
dissect_pn_pa_profile_data(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                          proto_tree *tree, uint32_t length, const char *text)
{
    (void)text;
    /*
        All PA Profile submodules carry an 8-bit "status" plus the real data, which
        currently is a float, an 8-bit integer or a 16-bit integer.
        So we will have either 2, 3 or 5 bytes.
    */
    if (length == 2u)
    {
        proto_tree_add_item(tree, hf_pn_pa_profile_value_8bit, tvb, offset, 1, ENC_BIG_ENDIAN);
        dissect_pn_pa_profile_status(tvb, offset+1, pinfo, tree, hf_pn_pa_profile_status);
    }
    else if (length == 3u)
    {
        proto_tree_add_item(tree, hf_pn_pa_profile_value_16bit, tvb, offset, 2, ENC_BIG_ENDIAN);
        dissect_pn_pa_profile_status(tvb, offset+2, pinfo, tree, hf_pn_pa_profile_status);
    }
    else if (length == 5u)
    {
        proto_tree_add_item(tree, hf_pn_pa_profile_value_float, tvb, offset, 4, ENC_BIG_ENDIAN);
        dissect_pn_pa_profile_status(tvb, offset+4, pinfo, tree, hf_pn_pa_profile_status);
    }
    else
    {
        /* Delegate to standard user data if unknown */
        (void)dissect_pn_user_data(tvb, offset, pinfo, tree, length, "IO Data");
    }

    return offset + length;
}

void
init_pn_io_rtc1(int proto)
{
    static hf_register_info hf[] = {
        { &hf_pn_io_io_data_object,
            { "IODataObject", "pn_io.io_data_object",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_io_io_data_object_info_module_diff,
            { "Difference", "pn_io.io_data_object.diff_module",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_io_io_data_object_info_moduleidentnumber,
            { "ModuleIdentNumber", "pn_io.io_data_object.module_nr",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_io_io_data_object_info_submoduleidentnumber,
            { "SubmoduleIdentNumber", "pn_io.io_data_object.submodule_nr",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_io_frame_info_type,
            { "PN Frame Type", "pn_io.frame_info.type",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_io_frame_info_vendor,
            { "DeviceVendorValue", "pn_io.frame_info.vendor",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_io_frame_info_nameofstation,
            { "NameOfStation", "pn_io.frame_info.nameofstation",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_io_frame_info_gsd_found,
            { "GSD-file found", "pn_io.frame_info.gsd_found",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_io_frame_info_gsd_error,
            { "GSD-file not found.", "pn_io.frame_info.gsd_error",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_io_frame_info_gsd_path,
            { "GSD-file networkpath failure!", "pn_io.frame_info.gsd_path",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_io_iocs,
            { "IOCS", "pn_io.ioxs",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_io_iops,
            { "IOPS", "pn_io.ioxs",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_io_ioxs_extension,
            { "Extension", "pn_io.ioxs.extension",
            FT_UINT8, BASE_HEX, VALS(pn_io_ioxs_extension), 0x01,
            NULL, HFILL }
        },
        { &hf_pn_io_ioxs_res14,
            { "Reserved", "pn_io.ioxs.res14",
            FT_UINT8, BASE_HEX, NULL, 0x1E,
            NULL, HFILL }
        },
        { &hf_pn_io_ioxs_instance,
            { "Instance", "pn_io.ioxs.instance",
            FT_UINT8, BASE_HEX, VALS(pn_io_ioxs_instance), 0x60,
            NULL, HFILL }
        },
        { &hf_pn_io_ioxs_datastate,
            { "DataState", "pn_io.ioxs.datastate",
            FT_UINT8, BASE_HEX, VALS(pn_io_ioxs_datastate), 0x80,
            NULL, HFILL }
        },
        /* PROFIsafe parameter */
        /* Status Byte & Control Byte for PROFIsafe --- dissector handle */
        { &hf_pn_io_ps_sb,
            { "Status Byte", "pn_io.ps.sb",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_io_ps_sb_toggelBitChanged,
            { "Status Byte", "pn_io.ps.sb.toggle_d_changed",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_io_ps_sb_toggelBitChange_slot_nr,
            { "Slot_Number", "pn_io.ps.sb.toggle_d_changed.slot",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_io_ps_sb_toggelBitChange_subslot_nr,
            { "Sub_Slot_Number", "pn_io.ps.sb.toggle_d_changed.subslot",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_io_ps_cb,
            { "Control Byte", "pn_io.ps.cb",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_io_ps_cb_toggelBitChanged,
            { "Control Byte", "pn_io.ps.cb.toggle_h_changed",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_io_ps_cb_toggelBitChange_slot_nr,
            { "Slot_Number", "pn_io.ps.cb.toggle_h_changed.slot",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_io_ps_cb_toggelBitChange_subslot_nr,
            { "Sub_Slot_Number", "pn_io.ps.cb.toggle_h_changed.subslot",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        /* Structures for dissecting Status Byte & Control Byte PROFIsafe ---dissector details */
        { &hf_pn_io_ps_sb_iparOK,
            { "iPar_OK - F-Device has new iParameter values assigned", "pn_io.ps.sb.iPar_OK",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pn_io_ps_sb_DeviceFault,
            { "Device_Fault - Failure exists in F-Device or F-Module", "pn_io.ps.sb.DeviceFault",
            FT_UINT8, BASE_HEX, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pn_io_ps_sb_CECRC,
            { "CE_CRC - CRC Communication fault", "pn_io.ps.sb.CE_CRC",
            FT_UINT8, BASE_HEX, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pn_io_ps_sb_WDtimeout,
            { "WD_timeout - WatchDog timeout Communication fault", "pn_io.ps.sb.WD_timeout",
            FT_UINT8, BASE_HEX, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_pn_io_ps_sb_FVactivated,
            { "FV_activated - Fail-safe values (FV) activated", "pn_io.ps.sb.FV_activated",
            FT_UINT8, BASE_HEX, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_pn_io_ps_sb_Toggle_d,
            { "Toggle_d - Device-based Toggle Bit", "pn_io.ps.sb.Toggle_d",
            FT_UINT8, BASE_HEX, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_pn_io_ps_sb_ConsNr_reset,
            { "cons_nr_R - F-Device has reset its consecutive number counter", "pn_io.ps.sb.cons_nr_R",
            FT_UINT8, BASE_HEX, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_pn_io_ps_sb_res,
            { "Bit7 - reserved for future releases", "pn_io.ps.sb.bit7",
            FT_UINT8, BASE_HEX, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_pn_io_ps_cb_iparEN,
            { "iPar_EN - iParameter assignment deblocked", "pn_io.ps.cb.iparEN",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pn_io_ps_cb_OAReq,
            { "OA_Req - Operator acknowledge requested", "pn_io.ps.cb.OA_Req",
            FT_UINT8, BASE_HEX, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pn_io_ps_cb_resetConsNr,
            { "R_cons_nr - Set the Virtual Consecutive Number within the F-Device to be \"0\"", "pn_io.ps.cb.R_cons_nr",
            FT_UINT8, BASE_HEX, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pn_io_ps_cb_useTO2,
            { "Bit3 - Reserved or Use the secondary watchdog (Use_TO2)", "pn_io.ps.cb.bit3",
            FT_UINT8, BASE_HEX, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_pn_io_ps_cb_activateFV,
            { "activate_FV - Fail-safe values (FV) to be activated", "pn_io.ps.cb.activate_FV",
            FT_UINT8, BASE_HEX, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_pn_io_ps_cb_Toggle_h,
            { "Toggle_h - Host-based Toggle Bit", "pn_io.ps.cb.Toggle_h",
            FT_UINT8, BASE_HEX, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_pn_io_ps_cb_Chf_ACK,
            { "Bit6 - Reserved or Operator acknowledge after cleared channel fault (ChF_Ack)", "pn_io.ps.cb.bit6",
            FT_UINT8, BASE_HEX, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_pn_io_ps_cb_loopcheck,
            { "Bit7 - Reserved or Loop-back check (Loopcheck, shall be set to 1)", "pn_io.ps.cb.bit7",
            FT_UINT8, BASE_HEX, NULL, 0x80,
            NULL, HFILL }
        },
        /* PROFIsafe */
        { &hf_pn_io_ps_f_dest_adr,
            { "F_Dest_Add", "pn_io.ps.f_dest_add",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_io_ps_f_data,
            { "SafetyIO Data", "pn_io.ps.f_data",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_pa_profile_status,
            { "Status", "pn_io.pa.status",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_pa_profile_status_quality,
            { "Quality", "pn_io.pa.status.quality",
            FT_UINT8, BASE_HEX, VALS(pn_pa_profile_status_quality), 0xC0,
            NULL, HFILL }
        },
        { &hf_pn_pa_profile_status_substatus_bad,
            { "Substatus", "pn_io.pa.status.substatus",
            FT_UINT8, BASE_HEX, VALS(pn_pa_profile_status_substatus_bad), 0x3C,
            NULL, HFILL }
        },
        { &hf_pn_pa_profile_status_substatus_uncertain,
            { "Substatus", "pn_io.pa.status.substatus",
            FT_UINT8, BASE_HEX, VALS(pn_pa_profile_status_substatus_uncertain), 0x3C,
            NULL, HFILL }
        },
        { &hf_pn_pa_profile_status_substatus_good,
            { "Substatus", "pn_io.pa.status.substatus",
            FT_UINT8, BASE_HEX, VALS(pn_pa_profile_status_substatus_good), 0x3C,
            NULL, HFILL }
        },
        { &hf_pn_pa_profile_status_update_event,
            { "Update Event", "pn_io.pa.status.update",
            FT_UINT8, BASE_HEX, VALS(pn_pa_profile_status_update_event), 0x02,
            NULL, HFILL }
        },
        { &hf_pn_pa_profile_status_simulate,
            { "Simulate", "pn_io.pa.status.simulate",
            FT_UINT8, BASE_HEX, VALS(pn_pa_profile_status_simulate), 0x01,
            NULL, HFILL }
        },
        { &hf_pn_pa_profile_value_8bit,
            { "Value", "pn_io.pa.value",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_pa_profile_value_16bit,
            { "Value", "pn_io.pa.value",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_pa_profile_value_float,
            { "Value", "pn_io.pa.value.float",
            FT_FLOAT, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_pn_io_rtc,
        &ett_pn_io_ioxs,
        &ett_pn_io_io_data_object,
        &ett_pn_pa_profile_status
    };

    static ei_register_info ei[] = {
        { &ei_pn_io_too_many_data_objects, { "pn_io.too_many_data_objects", PI_MALFORMED, PI_ERROR, "Too many data objects", EXPFILL }},
    };

    expert_module_t* expert_pn_io;

    proto_pn_io_rtc1 = proto;
    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_pn_io = expert_register_protocol(proto_pn_io_rtc1);
    expert_register_field_array(expert_pn_io, ei, array_length(ei));
}


/*
* Editor modelines  -  https://www.wireshark.org/tools/modelines.html
*
* Local variables:
* c-basic-offset: 4
* tab-width: 8
* indent-tabs-mode: nil
* End:
*
* vi: set shiftwidth=4 tabstop=8 expandtab:
* :indentSize=4:tabSize=8:noTabs=true:
*/
