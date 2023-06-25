#include <stdint.h>
#include "packet-pldm-base.h"

static int proto_pldm_platform=-1;
static int hf_completion_code=-1;
static int hf_pldm_cmd=-1;

/* Event messages */
static int hf_format_version=-1;
static int hf_TID=-1;
static int hf_event_class=-1;
static int hf_result_status=-1;
static int hf_sensor_id=-1;
static int hf_sensor_event_class=-1;
static int hf_sensor_offset=-1;
static int hf_event_state=-1;
static int hf_event_prev_state=-1;
static int hf_sensor_data_size=-1;
static int hf_sensor_value_u8=-1;
static int hf_sensor_value_s8=-1;
static int hf_sensor_value_u16=-1;
static int hf_sensor_value_s16=-1;
static int hf_sensor_value_u32=-1;
static int hf_sensor_value_s32=-1;
static int hf_sensor_op_state=-1;
static int hf_sensor_prev_op_state=-1;
static int hf_sensor_rearm=-1;
static int hf_sensor_composite_count=-1;
//static int hf_sensor_event_msg_enable=-1;
//static int hf_sensor_=-1;
static int hf_heartbeat_format_ver=-1;
static int hf_heartbeat_sequence_num=-1;
static int hf_pdr_data_format=-1;
static int hf_pdr_num_change_recs=-1;

/* Set Event Receiver */
static int hf_event_message_global=-1;
static int hf_transport_protocol_type=-1;
static int hf_event_receiver_addr_info=-1;
static int hf_heartbeat_timer=-1;

/* Effecter */
static int hf_effecter_id=-1;
static int hf_effecter_count=-1;
static int hf_effecter_datasize=-1;
static int hf_effecter_value_u8=-1;
static int hf_effecter_value_s8=-1;
static int hf_effecter_value_u16=-1;
static int hf_effecter_value_s16=-1;
static int hf_effecter_value_u32=-1;
static int hf_effecter_value_s32=-1;

/* PDR */
static int hf_record_handle=-1;
static int hf_data_handle=-1;
static int hf_transfer_op_flag=-1;
static int hf_request_count=-1;
static int hf_record_change_num=-1;
static int hf_next_record_handle=-1;
static int hf_next_data_handle=-1;
static int hf_transfer_flag=-1;
static int hf_response_count=-1;
//static int hf_record_data=-1;
static int hf_transfer_crc=-1;


static const value_string pldm_cmds[] ={
//Terminus commands
    {0x01, "SetTID"},
    {0x02, "GetTID"},
    {0x03, "GetTerminusUID"},
    {0x04, "SetEventReceiver"},
    {0x05, "GetEventReceiver"},
    {0x0A, "PlatformEventMessage"},
    {0x0B, "PollForPlatformEventMessage"},
    {0x0C, "EventMessageSupported"},
    {0x0D, "EventMessageBufferSize "},
//Numeric Sensor commands
    {0x10, "SetNumericSensorEnable"},
    {0x11, "GetSensorReading"},
    {0x12, "GetSensorThresholds"},
    {0x13, "SetSensorThresholds"},
    {0x14, "RestoreSensorThresholds"},
    {0x15, "GetSensorHysteresis"},
    {0x16, "SetSensorHysteresis"},
    {0x17, "InitNumericSensor"},
//State Sensor commands
    {0x20, "SetStateSensorEnables"},
    {0x21, "GetStateSensorReadings"},
    {0x22, "InitStateSensor"},
//PLDM Effecter commands
    {0x30, "SetNumericEffecterEnable"},
    {0x31, "SetNumericEffecterValue"},
    {0x32, "GetNumericEffecterValue"},
    {0x38, "SetStateEffecterEnables"},
    {0x39, "SetStateEffecterStates"},
    {0x3A, "GetStateEffecterStates"},
//PLDM Event Log commands
    {0x40, "GetPLDMEventLogInfo"},
    {0x41, "EnablePLDMEventLogging"},
    {0x42, "ClearPLDMEventLog"},
    {0x43, "GetPLDMEventLogTimestamp"},
    {0x44, "SetPLDMEventLogTimestamp"},
    {0x45, "ReadPLDMEventLog"},
    {0x46, "GetPLDMEventLogPolicyInfo"},
    {0x47, "SetPLDMEventLogPolicy"},
    {0x48, "FindPLDMEventLogEntry"},
//PDR Repository commands
    {0x50, "GetPDRRepositoryInfo"},
    {0x51, "GetPDR"},
    {0x52, "FindPDR"},
    {0x53, "GetPDRRepositorySignature"},
    {0x58, "RunInitAgent"},
    {0, NULL}
};


static const value_string event_classes[] ={
    {0, "Sensor Event"},
    {1, "Effector Event"},
    {2, "Redfish Task Event"},
    {3, "Redfish Message Event"},
    {4, "Pldm PDR Repository Change Event"},
    {5, "Pldm Message Poll Event"},
    {6, "Heartbeat Timer Elapsed Event"},
    {0, NULL}
//other OEM ones
};

static const value_string sensor_event_classes[] ={
    {0, "Sensor Operational"},
    {1, "State Sensor State"},
    {2, "Numeric Sensor State"},
    {0, NULL}
};

static const value_string completion_codes[]={
    {0x0, "Success"},
    {0x1, "Error"},
    {0x2, "Invalid Data"},
    {0x3, "Invalid Length"},
    {0x4, "Not Ready"},
    {0x5, "Unsupported PLDM command"},
    {0x20, "Invalid PLDM type"},
    {0, NULL}
    // TODO check if types of messages have same error codes (eg effecter, pdr repo)
};

static const value_string result_status[] ={
    {0,  "No Logging"},
    {1,  "Logging disabled"},
    {2,  "Log Full"},
    {3,  "Accepted for logging"},
    {4,  "Logged"},
    {5,  "Logging Rejected"},
    {0, NULL}
};

static const value_string event_message_global_enable[]={
    {0, "Disable"},
    {1, "Enable Async"},
    {2, "Enable Polling"},
    {3, "Enable Async Keep Alive"},
    {0, NULL}
};

static const value_string transport_protocols[]={
    {0, "MCTP"},
    {1, "NC-SI/RBT"},
    {2, "Vendor Specific"},
    {0, NULL}
};

static const value_string transfer_op_flags[] ={
    {0x0,   "Get Next Part"},
    {0x1,   "Get First Part"},
    {0, NULL}
};

static const value_string transfer_flags[] ={
    {0x1,   "Start"},
    {0x2,   "Middle"},
    {0x4,   "End"},
    {0x5,   "Start and End"},
    {0, NULL}
};

int
dissect_platform(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *p_tree, void* data){

    struct packet_data *d = (struct packet_data*) data;
    guint8 offset = 0;
    guint8 request = d->direction;
    guint8 pldm_cmd = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(p_tree, hf_pldm_cmd, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    if (!request) {
        proto_tree_add_item(p_tree, hf_completion_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        guint8 completion_code = tvb_get_guint8(tvb, offset);
        if (completion_code)
            return tvb_captured_length(tvb);
        offset += 1;
    }
    switch(pldm_cmd){
    case 0x04: //Set Event Receiver command
        if (request) {
            proto_tree_add_item(p_tree, hf_event_message_global, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(p_tree, hf_transport_protocol_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            guint8 transport_protocol = tvb_get_guint8(tvb, offset);
            offset += 1;
            if (transport_protocol == 0) { //MCTP
                proto_tree_add_item(p_tree, hf_event_receiver_addr_info, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;
                proto_tree_add_item(p_tree, hf_heartbeat_timer, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            }
        }
        break;
    case 0x0a: //Platform Event Message command
        if (request) {
            proto_tree_add_item(p_tree, hf_format_version, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(p_tree, hf_TID, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(p_tree, hf_event_class, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            guint8 event_class = tvb_get_guint8(tvb, offset);
            offset += 1;
            guint8 sensor_event_class;
            /* Event Data */
            switch(event_class) {
            case 0x0: //Sensor
                proto_tree_add_item(p_tree, hf_sensor_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                proto_tree_add_item(p_tree, hf_sensor_event_class, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                sensor_event_class = tvb_get_guint8(tvb, offset);
                offset += 1;
                if (sensor_event_class == 0) { //Sensor Operational State
                    proto_tree_add_item(p_tree, hf_sensor_op_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset += 1;
                    proto_tree_add_item(p_tree, hf_sensor_prev_op_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset += 1;
                } else if (sensor_event_class == 1) { //State Sensor State
                    proto_tree_add_item(p_tree, hf_sensor_offset, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset += 1;
                    proto_tree_add_item(p_tree, hf_event_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset += 1;
                    proto_tree_add_item(p_tree, hf_event_prev_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset += 1;
                } else if (sensor_event_class == 2) { //Numeric Sensor State
		    // untested
                    proto_tree_add_item(p_tree, hf_event_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset += 1;
                    proto_tree_add_item(p_tree, hf_event_prev_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset += 1;
                    proto_tree_add_item(p_tree, hf_sensor_data_size, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset += 1;
                    guint8 size = tvb_get_guint8(tvb, offset);
	            switch (size) {
		    case 0: proto_tree_add_item(p_tree, hf_sensor_value_u8, tvb, offset, 1, ENC_LITTLE_ENDIAN); break;
		    case 1: proto_tree_add_item(p_tree, hf_sensor_value_s8, tvb, offset, 1, ENC_LITTLE_ENDIAN); break;
		    case 2: proto_tree_add_item(p_tree, hf_sensor_value_u16, tvb, offset, 2, ENC_LITTLE_ENDIAN); break;
		    case 3: proto_tree_add_item(p_tree, hf_sensor_value_s16, tvb, offset, 2, ENC_LITTLE_ENDIAN); break;
		    case 4: proto_tree_add_item(p_tree, hf_sensor_value_u32, tvb, offset, 4, ENC_LITTLE_ENDIAN); break;
		    case 5: proto_tree_add_item(p_tree, hf_sensor_value_s32, tvb, offset, 4, ENC_LITTLE_ENDIAN); break;
	            }
                } else { //Invalid
                    col_append_fstr(pinfo->cinfo, COL_INFO, "Invalid byte");
                }
                break;
            case 0x4: //PLDM PDR Repository Change Event
                if (request) {
                    proto_tree_add_item(p_tree, hf_pdr_data_format, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset += 1;
                    proto_tree_add_item(p_tree, hf_pdr_num_change_recs, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset += 1;
                    //todo
                }
                break;
            case 0x6: //Heartbeat elapsed
                if (request) {
                    proto_tree_add_item(p_tree, hf_heartbeat_format_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset += 1;
                    proto_tree_add_item(p_tree, hf_heartbeat_sequence_num, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset += 1;
                }
                break;
            default:
                g_print("To be implemented platform event message type %x\n", event_class);
            }
        } else {
            proto_tree_add_item(p_tree, hf_result_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        }
        break;
    /*case 0x20: //SetStateSensorReadings
            proto_tree_add_item(p_tree, hf_sensor_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset +=2;
            proto_tree_add_item(p_tree, hf_sensor_composite_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset +=1;
            proto_tree_add_item(p_tree, hf_sensor_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset +=1;
            proto_tree_add_item(p_tree, hf_sensor_op_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset +=1;
            proto_tree_add_item(p_tree, hf_sensor_event_msg_enable, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset +=1;
        break;*/
    case 0x21: //GetStateSensorReadings
        if (request) {
            proto_tree_add_item(p_tree, hf_sensor_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset +=2;
            proto_tree_add_item(p_tree, hf_sensor_rearm, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        } else {
            proto_tree_add_item(p_tree, hf_sensor_composite_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset +=1;
            //state fields
        }
        break;
    case 0x31: //SetNumericEffecterValue
	       //untested
        if (request) {
            proto_tree_add_item(p_tree, hf_effecter_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset +=2;
            proto_tree_add_item(p_tree, hf_effecter_datasize, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            guint8 size = tvb_get_guint8(tvb, offset);
	    switch (size) {
		    case 0: proto_tree_add_item(p_tree, hf_effecter_value_u8, tvb, offset, 1, ENC_LITTLE_ENDIAN); break;
		    case 1: proto_tree_add_item(p_tree, hf_effecter_value_s8, tvb, offset, 1, ENC_LITTLE_ENDIAN); break;
		    case 2: proto_tree_add_item(p_tree, hf_effecter_value_u16, tvb, offset, 2, ENC_LITTLE_ENDIAN); break;
		    case 3: proto_tree_add_item(p_tree, hf_effecter_value_s16, tvb, offset, 2, ENC_LITTLE_ENDIAN); break;
		    case 4: proto_tree_add_item(p_tree, hf_effecter_value_u32, tvb, offset, 4, ENC_LITTLE_ENDIAN); break;
		    case 5: proto_tree_add_item(p_tree, hf_effecter_value_s32, tvb, offset, 4, ENC_LITTLE_ENDIAN); break;
	    }
        }
        break;
    case 0x39: //SetStateEffecterStates
	if (request) {
            proto_tree_add_item(p_tree, hf_effecter_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset +=2;
            proto_tree_add_item(p_tree, hf_effecter_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	}
	break;
    case 0x51: //GetPDR
        if (request) {
            proto_tree_add_item(p_tree, hf_record_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset +=4;
            proto_tree_add_item(p_tree, hf_data_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset +=4;
            proto_tree_add_item(p_tree, hf_transfer_op_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset +=1;
            proto_tree_add_item(p_tree, hf_request_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset +=2;
            proto_tree_add_item(p_tree, hf_record_change_num, tvb, offset, 2, ENC_LITTLE_ENDIAN);

        } else {
            proto_tree_add_item(p_tree, hf_next_record_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset +=4;
            proto_tree_add_item(p_tree, hf_next_data_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset +=4;
            proto_tree_add_item(p_tree, hf_transfer_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            guint8 transfer_flag = tvb_get_guint8(tvb, offset);
            offset +=1;
            proto_tree_add_item(p_tree, hf_response_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            guint16 response_count = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
            offset +=2;
            if (response_count) {
                //TODO add record data to tree
                offset += response_count;
            }
            if (transfer_flag == 0x4) {
                //CRC only present if flag == end
                proto_tree_add_item(p_tree, hf_transfer_crc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            }
        }
        break;
    default:
        col_append_fstr(pinfo->cinfo, COL_INFO, "Unsupported or Invalid PLDM command %x ", pldm_cmd);
        g_print("Invalid PLDM platform cmd %x \n", pldm_cmd);
        break;
    }
    return tvb_captured_length(tvb);
}

void
proto_register_platform(void)
{
    static hf_register_info hf[] ={
        { &hf_pldm_cmd,{
            "PLDM Command Type", "pldm.cmd",
            FT_UINT8, BASE_HEX,
            VALS(pldm_cmds), 0x0,
            NULL, HFILL}
         },
         { &hf_completion_code,{
            "Completion Code", "pldm.cc",
            FT_UINT8, BASE_DEC,
            VALS(completion_codes), 0x0,
            NULL, HFILL}
         },
        /* PDR */
         { &hf_record_handle,{
            "PDR record handle", "pldm.platform.pdr.record_handle",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_data_handle,{
            "PDR data transfer handle", "pldm.platform.pdr.data_handle",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_transfer_op_flag,{
            "PDR transfer operation flag", "pldm.platform.pdr.transfer_op_flag",
            FT_UINT8, BASE_DEC,
            VALS(transfer_op_flags), 0x0,
            NULL, HFILL}
         },
         { &hf_request_count,{
            "PDR request count", "pldm.platform.pdr.request.count",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_record_change_num,{
            "PDR record change number", "pldm.platform.pdr.record_change_number",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_next_record_handle,{
            "PDR next record handle", "pldm.platform.pdr.next_record_handle",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_next_data_handle,{
            "PDR next data transfer handle", "pldm.platform.pdr.next_data_handle",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_transfer_flag,{
            "PDR transfer flag", "pldm.platform.pdr.transfer_flag",
            FT_UINT8, BASE_DEC,
            VALS(transfer_flags), 0x0,
            NULL, HFILL}
         },
         { &hf_response_count,{
            "PDR response count", "pldm.platform.pdr.response.count",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
        //TODO
         /*{ &hf_record_data,{
            "PDR record data", "pldm.platform.pdr.data",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },*/
         { &hf_transfer_crc,{
            "PDR transfer CRC", "pldm.platform.pdr.crc",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
	/* Effecter */
         { &hf_effecter_id,{
            "Effecter ID", "pldm.platform.effecter.id",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_effecter_count,{
            "Effecter count", "pldm.platform.effecter.count",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_effecter_datasize,{
            "Effecter Data Size", "pldm.platform.effecter.datasize",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_effecter_value_u8,{
            "Effecter Value", "pldm.platform.effecter.value",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_effecter_value_s8,{
            "Effecter Value", "pldm.platform.effecter.value",
            FT_INT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_effecter_value_u16,{
            "Effecter Value", "pldm.platform.effecter.value",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_effecter_value_s16,{
            "Effecter Value", "pldm.platform.effecter.value",
            FT_INT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_effecter_value_u32,{
            "Effecter Value", "pldm.platform.effecter.value",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_effecter_value_s32,{
            "Effecter Value", "pldm.platform.effecter.value",
            FT_INT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
        /* Event Receiver */
         { &hf_event_message_global,{
            "Event message global enable", "pldm.platform.receiver.enable",
            FT_UINT8, BASE_DEC,
            VALS(event_message_global_enable), 0x0,
            NULL, HFILL}
         },
         { &hf_transport_protocol_type,{
            "Transport protocol", "pldm.platform.receiver.transport",
            FT_UINT8, BASE_DEC,
            VALS(transport_protocols), 0x0,
            NULL, HFILL}
         },
        //todo this varies in size based on transport protocol type
        // 1 byte MCTP
        // X for NCSI
        // X for vendor specific
         { &hf_event_receiver_addr_info,{
            "Event receiver address info", "pldm.platform.receiver.addr_info",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_heartbeat_timer,{
            "Heartbeat timer", "pldm.platform.receiver.timer",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
        /* Event message */
         { &hf_format_version,{
            "Format Version", "pldm.platform.event.format_version",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_TID,{
            "TID", "pldm.platform.event.TID",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_event_class,{
            "Event Class", "pldm.platform.event.class",
            FT_UINT8, BASE_DEC,
            VALS(event_classes), 0x0,
            NULL, HFILL}
         },
         { &hf_result_status,{
            "Completion Code", "pldm.status",
            FT_UINT8, BASE_DEC,
            VALS(result_status), 0x0,
            NULL, HFILL}
         },
         { &hf_sensor_id,{
            "Sensor ID", "pldm.platform.event.sensor_id",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_sensor_event_class,{
            "Sensor event class", "pldm.platform.event.sensor_event_class",
            FT_UINT8, BASE_DEC,
            VALS(sensor_event_classes), 0x0,
            NULL, HFILL}
         },
         { &hf_sensor_offset,{
            "Sensor offset", "pldm.platform.event.sensor_offset",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_event_state,{
            "Event state", "pldm.platform.event.state",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_event_prev_state,{
            "Event previous state", "pldm.platform.event.prev_state",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_sensor_data_size,{
            "Sensor data size", "pldm.platform.sensor.data_size",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
/*         { &hf_sensor_event_msg_enable,{
            "Sensor event message enable", "pldm.platform.sensor.event_msg_en",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },*/
         { &hf_sensor_rearm,{
            "Sensor rearm", "pldm.platform.sensor_rearm",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_sensor_composite_count,{
            "Sensor composite count", "pldm.platform.sensor.comp_count",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_pdr_data_format,{
            "PDR Repository change data format", "pldm.platform.event.pdr.data_format",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_pdr_num_change_recs,{
            "PDR Repository number of records changed", "pldm.platform.event.pdr.num_records",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_sensor_value_u8,{
            "Sensor reading", "pldm.platform.event.sensor.data",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_sensor_value_s8,{
            "Sensor reading", "pldm.platform.event.sensor.data",
            FT_INT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_sensor_value_u16,{
            "Sensor reading", "pldm.platform.event.sensor.data",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_sensor_value_s16,{
            "Sensor reading", "pldm.platform.event.sensor.data",
            FT_INT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_sensor_value_u32,{
            "Sensor reading", "pldm.platform.event.sensor.data",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_sensor_value_s32,{
            "Sensor reading", "pldm.platform.event.sensor.data",
            FT_INT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_sensor_op_state,{
            "Sensor present operational state", "pldm.platform.event.sensor.op_state",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_sensor_prev_op_state,{
            "Sensor previous operational state", "pldm.platform.event.sensor.prev_op_state",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_heartbeat_format_ver,{
            "Format Version", "pldm.platform.event.heartbeat.format_version",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
         { &hf_heartbeat_sequence_num,{
            "Heartbeat sequence number", "pldm.platform.event.heartbeat.seq",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
         },
    };

    proto_pldm_platform = proto_register_protocol (
        "PLDM Plaform Monitoring Protocol", /* name */
        "PLDM_P",                           /* short_name  */
        "pldm.platform"                     /* filter_name */
        );
    proto_register_field_array(proto_pldm_platform, hf, array_length(hf));
}

void
proto_reg_handoff_platform(void)
{
    static dissector_handle_t platform_handle;

    platform_handle = create_dissector_handle(dissect_platform, proto_pldm_platform);
    dissector_add_uint("pldm.type", PLDM_PLATFORM, platform_handle);
}
