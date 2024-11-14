/* packet-ecpri.c
 * Routines for eCPRI dissection
 * Copyright 2019, Maximilian Kohler <maximilian.kohler@viavisolutions.com>
 * Copyright 2024, Tomasz Woszczynski <duchowe50k@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * ------------------------------------------------------------------------------------------------
 * eCPRI Transport Network V1.2 -- Specifications
 * http://www.cpri.info/downloads/Requirements_for_the_eCPRI_Transport_Network_V1_2_2018_06_25.pdf
 * eCPRI Transport Network V2.0 -- Specifications
 * https://www.cpri.info/downloads/eCPRI_v_2.0_2019_05_10c.pdf
 *
 * May carry ORAN FH-CUS (packet-oran.c) - Message Types, 0, 2, 5
 * See https://specifications.o-ran.org/specifications, WG4, Fronthaul Interfaces Workgroup
 * ------------------------------------------------------------------------------------------------
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/etypes.h>
#include <epan/tfs.h>
#include <epan/unit_strings.h>
#include <proto.h>

/**************************************************************************************************/
/* Definition for eCPRI lengths                                                                   */
/**************************************************************************************************/
/* eCPRI Common Header (4 Bytes) */
#define ECPRI_HEADER_LENGTH                         4
/* Message Type Length */
#define ECPRI_MSG_TYPE_0_PAYLOAD_MIN_LENGTH         4
#define ECPRI_MSG_TYPE_1_PAYLOAD_MIN_LENGTH         4
#define ECPRI_MSG_TYPE_2_PAYLOAD_MIN_LENGTH         4
#define ECPRI_MSG_TYPE_3_PAYLOAD_MIN_LENGTH         8
#define ECPRI_MSG_TYPE_4_PAYLOAD_MIN_LENGTH        12
#define ECPRI_MSG_TYPE_5_PAYLOAD_MIN_LENGTH        20
#define ECPRI_MSG_TYPE_6_PAYLOAD_MIN_LENGTH         3
#define ECPRI_MSG_TYPE_7_PAYLOAD_MIN_LENGTH         4
#define ECPRI_MSG_TYPE_8_PAYLOAD_MIN_LENGTH         9
#define ECPRI_MSG_TYPE_11_PAYLOAD_LENGTH           12
#define ECPRI_MSG_TYPE_7_ELEMENT_SIZE               8

/**************************************************************************************************/
/* Definition for Action Types in Message Type 5: One-way Delay Measurement                       */
/**************************************************************************************************/
#define ECPRI_MSG_TYPE_5_REQ                    0x00
#define ECPRI_MSG_TYPE_5_REQ_FOLLOWUP           0x01
#define ECPRI_MSG_TYPE_5_RESPONSE               0x02
#define ECPRI_MSG_TYPE_5_REMOTE_REQ             0x03
#define ECPRI_MSG_TYPE_5_REMOTE_REQ_FOLLOWUP    0x04
#define ECPRI_MSG_TYPE_5_FOLLOWUP               0x05
#define ECPRI_MSG_TYPE_5_RESERVED_MIN           0x06
#define ECPRI_MSG_TYPE_5_RESERVED_MAX           0xFF

/**************************************************************************************************/
/* Definition for Event Types in Message Type 7: Event Indication                                 */
/**************************************************************************************************/
#define ECPRI_MSG_TYPE_7_FAULT_INDICATION       0x00
#define ECPRI_MSG_TYPE_7_FAULT_INDICATION_ACK   0x01
#define ECPRI_MSG_TYPE_7_NOTIF_INDICATION       0x02
#define ECPRI_MSG_TYPE_7_SYNC_REQUEST           0x03
#define ECPRI_MSG_TYPE_7_SYNC_ACK               0x04
#define ECPRI_MSG_TYPE_7_SYNC_END_INDICATION    0x05
#define ECPRI_MSG_TYPE_7_RESERVED_MIN           0x06
#define ECPRI_MSG_TYPE_7_RESERVED_MAX           0xFF

/**************************************************************************************************/
/* Definition for Fault/Notification Ranges in Message Type 7: Event Indication                   */
/**************************************************************************************************/
#define ECPRI_MSG_TYPE_7_FAULTS_MIN             0x000
#define ECPRI_MSG_TYPE_7_FAULTS_MAX             0x3FF
#define ECPRI_MSG_TYPE_7_NOTIF_MIN              0x400
#define ECPRI_MSG_TYPE_7_NOTIF_MAX              0x7FF
#define ECPRI_MSG_TYPE_7_VENDOR_MIN             0x800
#define ECPRI_MSG_TYPE_7_VENDOR_MAX             0xFFF

/**************************************************************************************************/
/* Definition for Action Types in Message Type 11: IWF Delay Control                              */
/**************************************************************************************************/
#define ECPRI_MSG_TYPE_11_REQUEST_GET_DELAYS    0x00
#define ECPRI_MSG_TYPE_11_RESPONSE_GET_DELAYS   0x01
#define ECPRI_MSG_TYPE_11_RESERVED_MIN          0x02
#define ECPRI_MSG_TYPE_11_RESERVED_MAX          0xFF

/**************************************************************************************************/
/* Function Prototypes                                                                            */
/**************************************************************************************************/
void proto_register_ecpri(void);
void proto_reg_handoff_ecpri(void);

/**************************************************************************************************/
/* Initialize the subtree pointers                                                                */
/**************************************************************************************************/
static int ett_ecpri;
static int ett_ecpri_header;
static int ett_ecpri_payload;
static int ett_ecpri_timestamp;
static int ett_ecpri_element;

/**************************************************************************************************/
/* Initialize the protocol and registered fields                                                  */
/**************************************************************************************************/
static int proto_ecpri;

static int hf_payload;

/* Fields for eCPRI Common Header */
static int hf_common_header;
static int hf_common_header_ecpri_protocol_revision;
static int hf_common_header_reserved;
static int hf_common_header_c_bit;
static int hf_common_header_ecpri_message_type;
static int hf_common_header_ecpri_payload_size;

/* Fields for Message Type 0: IQ Data */
static int hf_iq_data_pc_id;
static int hf_iq_data_seq_id;
static int hf_iq_data_iq_samples_of_user_data;

/* Fields for Message Type 1: Bit Sequence */
static int hf_bit_sequence_pc_id;
static int hf_bit_sequence_seq_id;
static int hf_bit_sequence_bit_sequence_of_user_data;

/* Fields for Message Type 2: Real-Time Control Data */
static int hf_real_time_control_data_rtc_id;
static int hf_real_time_control_data_seq_id;
static int hf_real_time_control_data_rtc_data;

/* Fields for Message Type 3: Generic Data Transfer */
static int hf_generic_data_transfer_pc_id;
static int hf_generic_data_transfer_seq_id;
static int hf_generic_data_transfer_data_transferred;

/* Fields for Message Type 4: Remote Memory Access */
static int hf_remote_memory_access_id;
static int hf_remote_memory_access_read_write;
static int hf_remote_memory_access_request_response;
static int hf_remote_memory_access_element_id;
static int hf_remote_memory_access_address;
static int hf_remote_memory_access_data_length;
static int hf_remote_memory_access_data;

/* Fields for Message Type 5: One-Way Delay Measurement */
static int hf_one_way_delay_measurement_id;
static int hf_one_way_delay_measurement_action_type;
static int hf_one_way_delay_measurement_timestamp;
static int hf_one_way_delay_measurement_timestamp_seconds;
static int hf_one_way_delay_measurement_timestamp_nanoseconds;
static int hf_one_way_delay_measurement_compensation_value;
static int hf_one_way_delay_measurement_dummy_bytes;

/* Fields for Message Type 6: Remote Reset */
static int hf_remote_reset_reset_id;
static int hf_remote_reset_reset_code;
static int hf_remote_reset_vendor_specific_payload;

/* Fields for Message Type 7: Event Indication */
static int hf_event_indication_event_id;
static int hf_event_indication_event_type;
static int hf_event_indication_sequence_number;
static int hf_event_indication_number_of_faults_notifications;
static int hf_event_indication_element;
static int hf_event_indication_element_id;
static int hf_event_indication_raise_cease;
static int hf_event_indication_fault_notification;
static int hf_event_indication_additional_information;

/* Fields for Message Type 8: IWF Start-Up */
static int hf_iwf_start_up_pc_id;
static int hf_iwf_start_up_hyperframe_number; /* #Z field */
static int hf_iwf_start_up_subframe_number; /* #X field */
static int hf_iwf_start_up_timestamp;
static int hf_iwf_start_up_fec_bit_indicator;
static int hf_iwf_start_up_scrambling_bit_indicator;
static int hf_iwf_start_up_line_rate;
static int hf_iwf_start_up_data_transferred;

/* Fields for Message Type 11: IWF Delay Control */
static int hf_iwf_delay_control_pc_id;
static int hf_iwf_delay_control_delay_control_id;
static int hf_iwf_delay_control_action_type;
static int hf_iwf_delay_control_delay_a;
static int hf_iwf_delay_control_delay_b;

/* Overall length of eCPRI frame */
static int hf_ecpri_length;

/**************************************************************************************************/
/* Preference to use the eCPRI Specification 1.2 encoding                                         */
/**************************************************************************************************/
static bool pref_message_type_decoding    = true;

/**************************************************************************************************/
/* eCPRI Handle                                                                                   */
/**************************************************************************************************/
static dissector_handle_t ecpri_handle;

/**************************************************************************************************/
/* Initialize expert info fields                                                                  */
/**************************************************************************************************/
static expert_field ei_ecpri_frame_length;
static expert_field ei_payload_size;
static expert_field ei_comp_val;
static expert_field ei_time_stamp;
static expert_field ei_data_length;
static expert_field ei_c_bit;
static expert_field ei_fault_notif;
static expert_field ei_number_faults;
static expert_field ei_iwf_delay_control_action_type;
static expert_field ei_ecpri_not_dis_yet;

/**************************************************************************************************/
/* Field Encoding of Message Types                                                                */
/**************************************************************************************************/

#define ECPRI_MESSAGE_TYPE_IQ_DATA                      0
#define ECPRI_MESSAGE_TYPE_BIT_SEQUENCE                 1
#define ECPRI_MESSAGE_TYPE_REAL_TIME_CONTROL_DATA       2
#define ECPRI_MESSAGE_TYPE_GENERIC_DATA_TRANSFER        3
#define ECPRI_MESSAGE_TYPE_REMOTE_MEMORY_ACCESS         4
#define ECPRI_MESSAGE_TYPE_ONE_WAY_DELAY_MEASUREMENT    5
#define ECPRI_MESSAGE_TYPE_REMOTE_RESET                 6
#define ECPRI_MESSAGE_TYPE_EVENT_INDICATION             7
#define ECPRI_MESSAGE_TYPE_IWF_STARTUP                  8
#define ECPRI_MESSAGE_TYPE_IWF_OPERATION                9
#define ECPRI_MESSAGE_TYPE_IWF_MAPPING                  10
#define ECPRI_MESSAGE_TYPE_IWF_DELAY_CONTROL            11

static const range_string ecpri_msg_types[] = {
    /* Message Types (3.2.4) */
    { ECPRI_MESSAGE_TYPE_IQ_DATA,                   ECPRI_MESSAGE_TYPE_IQ_DATA,                   "IQ Data" },
    { ECPRI_MESSAGE_TYPE_BIT_SEQUENCE,              ECPRI_MESSAGE_TYPE_BIT_SEQUENCE,              "Bit Sequence" },
    { ECPRI_MESSAGE_TYPE_REAL_TIME_CONTROL_DATA,    ECPRI_MESSAGE_TYPE_REAL_TIME_CONTROL_DATA,    "Real-Time Control Data" },
    { ECPRI_MESSAGE_TYPE_GENERIC_DATA_TRANSFER,     ECPRI_MESSAGE_TYPE_GENERIC_DATA_TRANSFER,     "Generic Data Transfer" },
    { ECPRI_MESSAGE_TYPE_REMOTE_MEMORY_ACCESS,      ECPRI_MESSAGE_TYPE_REMOTE_MEMORY_ACCESS,      "Remote Memory Access" },
    { ECPRI_MESSAGE_TYPE_ONE_WAY_DELAY_MEASUREMENT, ECPRI_MESSAGE_TYPE_ONE_WAY_DELAY_MEASUREMENT, "One-Way Delay Measurement" },
    { ECPRI_MESSAGE_TYPE_REMOTE_RESET,              ECPRI_MESSAGE_TYPE_REMOTE_RESET,              "Remote Reset" },
    { ECPRI_MESSAGE_TYPE_EVENT_INDICATION,          ECPRI_MESSAGE_TYPE_EVENT_INDICATION,          "Event Indication" },
    { ECPRI_MESSAGE_TYPE_IWF_STARTUP,               ECPRI_MESSAGE_TYPE_IWF_STARTUP,               "IWF Start-Up" },
    { ECPRI_MESSAGE_TYPE_IWF_OPERATION,             ECPRI_MESSAGE_TYPE_IWF_OPERATION,             "IWF Operation" },
    { ECPRI_MESSAGE_TYPE_IWF_MAPPING,               ECPRI_MESSAGE_TYPE_IWF_MAPPING,               "IWF Mapping" },
    { ECPRI_MESSAGE_TYPE_IWF_DELAY_CONTROL,         ECPRI_MESSAGE_TYPE_IWF_DELAY_CONTROL,         "IWF Delay Control" },
    /* Message Types 12 -  63*/
    { 12,  63,   "Reserved" },
    /* Message Types 64 - 255 */
    { 64,  255,  "Vendor Specific" },
    { 0,   0,    NULL }
};

/**************************************************************************************************/
/* Field Encoding of Message Type 4: Remote Memory Access                                         */
/**************************************************************************************************/
static const value_string remote_memory_access_read_write_coding[] = {
    { 0x0,    "Read"          },
    { 0x1,    "Write"         },
    { 0x2,    "Write_No_resp" },
    { 0x3,    "Reserved"      },
    { 0x4,    "Reserved"      },
    { 0x5,    "Reserved"      },
    { 0x6,    "Reserved"      },
    { 0x7,    "Reserved"      },
    { 0x8,    "Reserved"      },
    { 0x9,    "Reserved"      },
    { 0xA,    "Reserved"      },
    { 0xB,    "Reserved"      },
    { 0xC,    "Reserved"      },
    { 0xD,    "Reserved"      },
    { 0xE,    "Reserved"      },
    { 0xF,    "Reserved"      },
    { 0,      NULL            }
};

static const value_string remote_memory_access_request_response_coding[] = {
    { 0x0,    "Request"  },
    { 0x1,    "Response" },
    { 0x2,    "Failure"  },
    { 0x3,    "Reserved" },
    { 0x4,    "Reserved" },
    { 0x5,    "Reserved" },
    { 0x6,    "Reserved" },
    { 0x7,    "Reserved" },
    { 0x8,    "Reserved" },
    { 0x9,    "Reserved" },
    { 0xA,    "Reserved" },
    { 0xB,    "Reserved" },
    { 0xC,    "Reserved" },
    { 0xD,    "Reserved" },
    { 0xE,    "Reserved" },
    { 0xF,    "Reserved" },
    { 0,      NULL       }
};

/**************************************************************************************************/
/* Field Encoding of Message Type 5: One-way Delay Measurement                                    */
/**************************************************************************************************/
static const range_string one_way_delay_measurement_action_type_coding[] = {
    { 0x00,    0x00,    "Request"                       },
    { 0x01,    0x01,    "Request with Follow_Up"        },
    { 0x02,    0x02,    "Response"                      },
    { 0x03,    0x03,    "Remote Request"                },
    { 0x04,    0x04,    "Remote request with Follow_Up" },
    { 0x05,    0x05,    "Follow_Up"                     },
    { 0x06,    0xFF,    "Reserved"                      },
    { 0,       0,       NULL                            }
};

/**************************************************************************************************/
/* Field Encoding of Message Type 6: Remote Reset                                                 */
/**************************************************************************************************/
static const range_string remote_reset_reset_coding[] = {
    { 0x00,    0x00,    "Reserved"              },
    { 0x01,    0x01,    "Remote reset request"  },
    { 0x02,    0x02,    "Remote reset response" },
    { 0x03,    0xFF,    "Reserved"              },
    { 0,       0,       NULL                    }
};

/**************************************************************************************************/
/* Field Encoding of Message Type 7: Event Indication                                             */
/**************************************************************************************************/
static const range_string event_indication_event_type_coding[] = {
    { 0x00,    0x00,    "Fault(s) Indication"             },
    { 0x01,    0x01,    "Fault(s) Indication Acknowledge" },
    { 0x02,    0x02,    "Notification(s) Indication"      },
    { 0x03,    0x03,    "Synchronization Request"         },
    { 0x04,    0x04,    "Synchronization Acknowledge"     },
    { 0x05,    0x05,    "Synchronization End Indication"  },
    { 0x06,    0xFF,    "Reserved"                        },
    { 0,       0,       NULL                              }
};

static const range_string event_indication_element_id_coding[] = {
    { 0x0000,    0xFFFE,    "Vendor specific usage"                          },
    { 0xFFFF,    0xFFFF,    "Fault/Notification applicable for all Elements" },
    { 0,         0,         NULL                                             }
};

static const value_string event_indication_raise_ceased_coding[] = {
    { 0x00,    "Raise a fault" },
    { 0x01,    "Cease a fault" },
    { 0x02,    "Reserved"     },
    { 0x03,    "Reserved"     },
    { 0x04,    "Reserved"     },
    { 0x05,    "Reserved"     },
    { 0x06,    "Reserved"     },
    { 0x07,    "Reserved"     },
    { 0x08,    "Reserved"     },
    { 0x09,    "Reserved"     },
    { 0x0A,    "Reserved"     },
    { 0x0B,    "Reserved"     },
    { 0x0C,    "Reserved"     },
    { 0x0D,    "Reserved"     },
    { 0x0E,    "Reserved"     },
    { 0x0F,    "Reserved"     },
    { 0,       NULL           }
};

static const range_string event_indication_fault_notif_coding[] = {
    /* eCPRI reserved Faults from 0x000 to 0x3FF */
    { 0x000,    0x000,    "General Userplane HW Fault"                    },
    { 0x001,    0x001,    "General Userplane SW Fault"                    },
    { 0x002,    0x3FF,    "eCPRI reserved Faults"                         },
    /* eCPRI reserved Notifications from 0x400 to 0x7FF */
    { 0x400,    0x400,    "Unknown message type received"                 },
    { 0x401,    0x401,    "Userplane data buffer underflow"               },
    { 0x402,    0x402,    "Userplane data buffer overflow"                },
    { 0x403,    0x403,    "Userplane data arrived too early"              },
    { 0x404,    0x404,    "Userplane data received too late"              },
    { 0x405,    0x7FF,    "eCPRI reserved Notifications"                  },
    /* Vendor Specific Fault Indication and Notification from 0x800 to 0xFFF */
    { 0x800,    0xFFF,    "Vendor Specific Fault Indication/Notification" },
    { 0,        0,        NULL                                            }
};

/**************************************************************************************************/
/* Field Encoding of Message Type 8: IWF Start-Up                                                 */
/**************************************************************************************************/
static const range_string iwf_start_up_line_rate_coding[] = {
    { 0x00,  0x00,    "Reserved"                     },
    { 0x01,  0x01,    "CPRI line bit rate option 1"  },
    { 0x02,  0x02,    "CPRI line bit rate option 2"  },
    { 0x03,  0x03,    "CPRI line bit rate option 3"  },
    { 0x04,  0x04,    "CPRI line bit rate option 4"  },
    { 0x05,  0x05,    "CPRI line bit rate option 5"  },
    { 0x06,  0x06,    "CPRI line bit rate option 6"  },
    { 0x07,  0x07,    "CPRI line bit rate option 7"  },
    { 0x08,  0x08,    "CPRI line bit rate option 7A" },
    { 0x09,  0x09,    "CPRI line bit rate option 8"  },
    { 0x0A,  0x0A,    "CPRI line bit rate option 9"  },
    { 0x0B,  0x0B,    "CPRI line bit rate option 10" },
    { 0x0C,  0x1F,    "Reserved"                     },
    { 0,        0,    NULL                           }
};

/**************************************************************************************************/
/* Field Encoding of Message Type 11: IWF Delay Control                                           */
/**************************************************************************************************/
static const range_string iwf_delay_control_action_type_coding[] = {
    { 0x00,  0x00,    "Request get delays"   },
    { 0x01,  0x01,    "Response get delays"  },
    { 0x02,  0xFF,    "Reserved"             },
    { 0,     0,       NULL                   }
};

static const true_false_string tfs_c_bit =
{
    "Another eCPRI message follows this one with eCPRI PDU",
    "This eCPRI message is last one inside eCPRI PDU"
};

static dissector_handle_t oran_fh_handle;

/**************************************************************************************************/
/* Implementation of the functions                                                                */
/**************************************************************************************************/
static int dissect_ecpri(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    tvbuff_t *next_tvb;

    /* Proto Items/Trees for eCPRI */
    proto_item *ecpri_item;
    proto_tree *ecpri_tree;

    /* Proto Items/Trees for eCPRI Common Header */
    proto_item *header_item;
    proto_tree *header_tree;
    proto_item *ti_payload_size;
    proto_item *ti_c_bit;

    /* Proto Items/Trees for eCPRI Payload */
    proto_item *payload_item;
    proto_tree *payload_tree;
    /* Proto Items/Trees for Message Type 4: Remote Memory Access */
    proto_item *ti_data_length;
    /* Proto Items/Trees for Message Type 5: One-way Delay Measurement */
    proto_item *timestamp_item;
    proto_tree *timestamp_tree;
    proto_item *ti_comp_val;
    /* Proto Items/Trees for Message Type 7: Event Indication */
    proto_item *element_item;
    proto_tree *element_tree;
    proto_item *ti_num_faults;
    proto_item *ti_fault_notif;

    int offset;
    uint32_t msg_type;
    uint32_t event_type;
    uint32_t concatenation;
    uint32_t num_faults_notif;
    uint32_t action_type;
    uint32_t fault_notif;
    uint16_t payload_size;
    uint32_t data_length;
    uint16_t reported_length;
    uint16_t remaining_length;
    uint32_t time_stamp_ns;
    uint64_t time_stamp_s;
    uint64_t comp_val;

    reported_length = tvb_reported_length(tvb);

    /* Check of eCPRI min. length (header-length) */
    if (reported_length < ECPRI_HEADER_LENGTH)
        return 0;

    /* Set column of protocol eCPRI */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "eCPRI");
    col_clear(pinfo->cinfo, COL_INFO);

    offset = 0;
    concatenation = tvb_get_uint8(tvb, offset) & 0x01;
    if (concatenation != 0x00)
    {
        col_append_str(pinfo->cinfo, COL_INFO, "Concatenation");
    }

    /* do-while loop for concatenation check */
    bool concatenation_bit;
    do
    {
        /* 4-byte boundary check for concatenation */
        if (offset % 4 != 0)
        {
            offset = offset + 4 - (offset % 4);
        }

        /* Read Payload Size */
        payload_size = tvb_get_ntohs(tvb, offset+2);

        /* eCPRI tree */
        if (payload_size + ECPRI_HEADER_LENGTH <= reported_length)
        {
            ecpri_item = proto_tree_add_item(tree, proto_ecpri, tvb, offset, payload_size + ECPRI_HEADER_LENGTH, ENC_NA);
        }
        else
        {
            ecpri_item = proto_tree_add_item(tree, proto_ecpri, tvb, offset, -1, ENC_NA);
            expert_add_info_format(
                pinfo, ecpri_item, &ei_ecpri_frame_length,
                "eCPRI frame length %u is too small, Should be min. %d",
                reported_length, payload_size + ECPRI_HEADER_LENGTH);
        }
        ecpri_tree = proto_item_add_subtree(ecpri_item, ett_ecpri);

        /* eCPRI header subtree */
        header_item = proto_tree_add_string_format(ecpri_tree, hf_common_header, tvb, offset, ECPRI_HEADER_LENGTH, "", "eCPRI Common Header");
        header_tree = proto_item_add_subtree(header_item, ett_ecpri_header);

        /* eCPRI Protocol Revision */
        proto_tree_add_item(header_tree, hf_common_header_ecpri_protocol_revision, tvb, offset, 1, ENC_NA);
        /* Reserved */
        proto_tree_add_item(header_tree, hf_common_header_reserved, tvb, offset, 1, ENC_NA);
        /* Concatenated */
        ti_c_bit = proto_tree_add_item_ret_boolean(header_tree, hf_common_header_c_bit, tvb, offset, 1, ENC_NA, &concatenation_bit);
        offset += 1;

        /* eCPRI Message Type */
        proto_tree_add_item_ret_uint(header_tree, hf_common_header_ecpri_message_type, tvb, offset, 1, ENC_NA, &msg_type);
        /* Append Message Type into info column & header item */
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ",", "Message Type: %s", try_rval_to_str(msg_type, ecpri_msg_types));
        proto_item_append_text(header_item, "   MessageType: %s", try_rval_to_str(msg_type, ecpri_msg_types));
        offset += 1;

        /* eCPRI Payload Size */
        ti_payload_size = proto_tree_add_item(header_tree, hf_common_header_ecpri_payload_size, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* eCPRI payload-subtree */
        /* Length Check */
        if (reported_length >= ECPRI_HEADER_LENGTH + payload_size)
        {
            /* OK, add undecoded payload */
            payload_item = proto_tree_add_item(ecpri_tree, hf_payload, tvb, offset, payload_size, ENC_NA);
        }
        else
        {
            expert_add_info_format(
                pinfo, ti_payload_size, &ei_payload_size,
                "Payload Size %u is too big, maximal %u is possible",
                payload_size, reported_length - ECPRI_HEADER_LENGTH);
            payload_item = proto_tree_add_item(ecpri_tree, hf_payload, tvb, offset, -1, ENC_NA);
        }

        payload_tree = proto_item_add_subtree(payload_item, ett_ecpri_payload);
        remaining_length = reported_length - offset;

        /* Call the FH CUS dissector if preference set */
        if (pref_message_type_decoding)
        {
            tvbuff_t *fh_tvb = tvb_new_subset_length(tvb, offset, payload_size);
            /***********************************************************************************************/
            /* See whether O-RAN fronthaul sub-dissector handles this, otherwise decode as vanilla eCPRI   */
            /* N.B. FH CUS dissector only handles:                                                         */
            /* - message type 0 (IQ DATA)                                                                  */
            /* - message type 2 (RT CTRL DATA)                                                             */
            /***********************************************************************************************/
            if (call_dissector_only(oran_fh_handle, fh_tvb, pinfo, tree, &msg_type))
            {
                /* Assume that it has claimed the entire tvb */
                offset = tvb_reported_length(tvb);
            }
            else
            {
                /* ORAN FH-CUS dissector didn't handle it */
                switch (msg_type)
                {
                case ECPRI_MESSAGE_TYPE_IQ_DATA: /* 3.2.4.1. IQ Data */
                    /* N.B. if ORAN dissector is enabled, it will handle this type instead! */
                    if (payload_size < ECPRI_MSG_TYPE_0_PAYLOAD_MIN_LENGTH)
                    {
                        expert_add_info_format(
                            pinfo, ti_payload_size, &ei_payload_size,
                            "Payload Size %u is too small for encoding Message Type %u. Should be min. %d",
                            payload_size, msg_type, ECPRI_MSG_TYPE_0_PAYLOAD_MIN_LENGTH);

                        offset += payload_size;
                        break;
                    }

                    if (remaining_length >= ECPRI_MSG_TYPE_0_PAYLOAD_MIN_LENGTH)
                    {
                        proto_tree_add_item(payload_tree, hf_iq_data_pc_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        proto_tree_add_item(payload_tree, hf_iq_data_seq_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        remaining_length -= ECPRI_MSG_TYPE_0_PAYLOAD_MIN_LENGTH;
                        if (remaining_length >= payload_size - ECPRI_MSG_TYPE_0_PAYLOAD_MIN_LENGTH)
                        {
                            proto_tree_add_item(payload_tree, hf_iq_data_iq_samples_of_user_data, tvb, offset, payload_size - ECPRI_MSG_TYPE_0_PAYLOAD_MIN_LENGTH, ENC_NA);
                            offset += payload_size - ECPRI_MSG_TYPE_0_PAYLOAD_MIN_LENGTH;
                        }
                    }
                    break;
                case ECPRI_MESSAGE_TYPE_BIT_SEQUENCE: /* 3.2.4.2. Bit Sequence */
                    if (payload_size < ECPRI_MSG_TYPE_1_PAYLOAD_MIN_LENGTH)
                    {
                        expert_add_info_format(
                            pinfo, ti_payload_size, &ei_payload_size,
                            "Payload Size %u is too small for encoding Message Type %u. Should be min. %d",
                            payload_size, msg_type, ECPRI_MSG_TYPE_1_PAYLOAD_MIN_LENGTH);

                        offset += payload_size;
                        break;
                    }

                    if (remaining_length >= ECPRI_MSG_TYPE_1_PAYLOAD_MIN_LENGTH)
                    {
                        proto_tree_add_item(payload_tree, hf_bit_sequence_pc_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        proto_tree_add_item(payload_tree, hf_bit_sequence_seq_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        remaining_length -= ECPRI_MSG_TYPE_1_PAYLOAD_MIN_LENGTH;
                        if (remaining_length >= payload_size - ECPRI_MSG_TYPE_1_PAYLOAD_MIN_LENGTH)
                        {
                            proto_tree_add_item(payload_tree, hf_bit_sequence_bit_sequence_of_user_data, tvb, offset, payload_size - ECPRI_MSG_TYPE_1_PAYLOAD_MIN_LENGTH, ENC_NA);
                            offset += payload_size - ECPRI_MSG_TYPE_1_PAYLOAD_MIN_LENGTH;
                        }
                    }
                    break;

                case ECPRI_MESSAGE_TYPE_REAL_TIME_CONTROL_DATA: /* 3.2.4.3. Real-Time Control Data */
                    /* N.B. if ORAN dissector is enabled, it will handle this type instead! */
                    if (payload_size < ECPRI_MSG_TYPE_2_PAYLOAD_MIN_LENGTH)
                    {
                        expert_add_info_format(
                            pinfo, ti_payload_size, &ei_payload_size,
                            "Payload Size %u is too small for encoding Message Type %u. Should be min. %d",
                            payload_size, msg_type, ECPRI_MSG_TYPE_2_PAYLOAD_MIN_LENGTH);

                        offset += payload_size;
                        break;
                    }

                    if (remaining_length >= ECPRI_MSG_TYPE_2_PAYLOAD_MIN_LENGTH)
                    {
                        proto_tree_add_item(payload_tree, hf_real_time_control_data_rtc_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        proto_tree_add_item(payload_tree, hf_real_time_control_data_seq_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        remaining_length -= ECPRI_MSG_TYPE_2_PAYLOAD_MIN_LENGTH;
                        if (remaining_length >= payload_size - ECPRI_MSG_TYPE_2_PAYLOAD_MIN_LENGTH)
                        {
                            proto_tree_add_item(payload_tree, hf_real_time_control_data_rtc_data, tvb, offset, payload_size - ECPRI_MSG_TYPE_2_PAYLOAD_MIN_LENGTH, ENC_NA);
                            offset += payload_size - ECPRI_MSG_TYPE_2_PAYLOAD_MIN_LENGTH;
                        }
                    }
                    break;

                case ECPRI_MESSAGE_TYPE_GENERIC_DATA_TRANSFER: /* 3.2.4.4. Generic Data Transfer */
                    if (payload_size < ECPRI_MSG_TYPE_3_PAYLOAD_MIN_LENGTH)
                    {
                        expert_add_info_format(
                            pinfo, ti_payload_size, &ei_payload_size,
                            "Payload Size %u is too small for encoding Message Type %u. Should be min. %d",
                            payload_size, msg_type, ECPRI_MSG_TYPE_3_PAYLOAD_MIN_LENGTH);

                        offset += payload_size;
                        break;
                    }

                    if (remaining_length >= ECPRI_MSG_TYPE_3_PAYLOAD_MIN_LENGTH)
                    {
                        proto_tree_add_item(payload_tree, hf_generic_data_transfer_pc_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;
                        proto_tree_add_item(payload_tree, hf_generic_data_transfer_seq_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;
                        remaining_length -= ECPRI_MSG_TYPE_3_PAYLOAD_MIN_LENGTH;
                        if (remaining_length >= payload_size - ECPRI_MSG_TYPE_3_PAYLOAD_MIN_LENGTH)
                        {
                            proto_tree_add_item(payload_tree, hf_generic_data_transfer_data_transferred, tvb, offset, payload_size - ECPRI_MSG_TYPE_3_PAYLOAD_MIN_LENGTH, ENC_NA);
                            offset += payload_size - ECPRI_MSG_TYPE_3_PAYLOAD_MIN_LENGTH;
                        }
                    }
                    break;

                case ECPRI_MESSAGE_TYPE_REMOTE_MEMORY_ACCESS: /* 3.2.4.5. Remote Memory Access */
                    if (payload_size < ECPRI_MSG_TYPE_4_PAYLOAD_MIN_LENGTH)
                    {
                        expert_add_info_format(
                            pinfo, ti_payload_size, &ei_payload_size,
                            "Payload Size %u is too small for encoding Message Type %u. Should be min. %d",
                            payload_size, msg_type, ECPRI_MSG_TYPE_4_PAYLOAD_MIN_LENGTH);

                        offset += payload_size;
                        break;
                    }

                    if (remaining_length >= ECPRI_MSG_TYPE_4_PAYLOAD_MIN_LENGTH)
                    {
                        proto_tree_add_item(payload_tree, hf_remote_memory_access_id, tvb, offset, 1, ENC_NA);
                        offset += 1;
                        proto_tree_add_item(payload_tree, hf_remote_memory_access_read_write, tvb, offset, 1, ENC_NA);
                        proto_tree_add_item(payload_tree, hf_remote_memory_access_request_response, tvb, offset, 1, ENC_NA);
                        offset += 1;
                        proto_tree_add_item(payload_tree, hf_remote_memory_access_element_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        proto_tree_add_item(payload_tree, hf_remote_memory_access_address, tvb, offset, 6, ENC_NA);
                        offset += 6;
                        ti_data_length = proto_tree_add_item_ret_uint(payload_tree, hf_remote_memory_access_data_length, tvb, offset, 2, ENC_BIG_ENDIAN, &data_length);
                        offset += 2;
                        remaining_length -= ECPRI_MSG_TYPE_4_PAYLOAD_MIN_LENGTH;
                        if (remaining_length >= (payload_size - ECPRI_MSG_TYPE_4_PAYLOAD_MIN_LENGTH))
                        {
                            if (data_length == ((uint32_t)(payload_size - ECPRI_MSG_TYPE_4_PAYLOAD_MIN_LENGTH)))
                            {
                                proto_tree_add_item(payload_tree, hf_remote_memory_access_data, tvb, offset, payload_size - ECPRI_MSG_TYPE_4_PAYLOAD_MIN_LENGTH, ENC_NA);
                                offset += payload_size - ECPRI_MSG_TYPE_4_PAYLOAD_MIN_LENGTH;
                            }
                            else if (data_length < ((uint32_t)(payload_size - ECPRI_MSG_TYPE_4_PAYLOAD_MIN_LENGTH)))
                            {
                                expert_add_info_format(
                                    pinfo, ti_data_length, &ei_data_length,
                                    "Data Length %u is too small, should be %u",
                                    data_length, payload_size - ECPRI_MSG_TYPE_4_PAYLOAD_MIN_LENGTH);
                            }
                            else
                            {
                                expert_add_info_format(
                                    pinfo, ti_data_length, &ei_data_length,
                                    "Data Length %u is too big, should be %u",
                                    data_length, payload_size - ECPRI_MSG_TYPE_4_PAYLOAD_MIN_LENGTH);
                            }
                        }
                    }
                    break;

                case ECPRI_MESSAGE_TYPE_ONE_WAY_DELAY_MEASUREMENT: /* 3.2.4.6. One-way Delay Measurement */
                    if (payload_size < ECPRI_MSG_TYPE_5_PAYLOAD_MIN_LENGTH)
                    {
                        expert_add_info_format(
                            pinfo, ti_payload_size, &ei_payload_size,
                            "Payload Size %u is too small for encoding Message Type %u. Should be min. %d",
                            payload_size, msg_type, ECPRI_MSG_TYPE_5_PAYLOAD_MIN_LENGTH);

                        offset += payload_size;
                        break;
                    }

                    if (remaining_length >= ECPRI_MSG_TYPE_5_PAYLOAD_MIN_LENGTH)
                    {
                        proto_tree_add_item(payload_tree, hf_one_way_delay_measurement_id, tvb, offset, 1, ENC_NA);
                        offset += 1;
                        proto_tree_add_item_ret_uint(payload_tree, hf_one_way_delay_measurement_action_type, tvb, offset, 1, ENC_NA, &action_type);
                        offset += 1;
                        /* Time Stamp for seconds and nano-seconds */
                        timestamp_item = proto_tree_add_item(payload_tree, hf_one_way_delay_measurement_timestamp, tvb, offset, 10, ENC_NA);
                        timestamp_tree = proto_item_add_subtree(timestamp_item, ett_ecpri_timestamp);
                        proto_tree_add_item_ret_uint64(timestamp_tree, hf_one_way_delay_measurement_timestamp_seconds, tvb, offset, 6, ENC_BIG_ENDIAN, &time_stamp_s);
                        offset += 6;
                        proto_tree_add_item_ret_uint(timestamp_tree, hf_one_way_delay_measurement_timestamp_nanoseconds, tvb, offset, 4, ENC_BIG_ENDIAN, &time_stamp_ns);
                        offset += 4;
                        if (action_type >= ECPRI_MSG_TYPE_5_RESERVED_MIN)
                        {
                            expert_add_info_format(
                                pinfo, timestamp_item, &ei_time_stamp,
                                "Time stamp is not defined for Action Type %u",
                                action_type);
                        }
                        else if (
                            action_type != ECPRI_MSG_TYPE_5_REQ &&
                            action_type != ECPRI_MSG_TYPE_5_RESPONSE &&
                            action_type != ECPRI_MSG_TYPE_5_FOLLOWUP &&
                            time_stamp_s != 0 && time_stamp_ns != 0)
                        {
                            expert_add_info_format(
                                pinfo, timestamp_item, &ei_time_stamp,
                                "Time stamp is not defined for Action Type %u, should be 0",
                                action_type);
                        }
                        ti_comp_val = proto_tree_add_item_ret_uint64(payload_tree, hf_one_way_delay_measurement_compensation_value, tvb, offset, 8, ENC_BIG_ENDIAN, &comp_val);
                        proto_item_append_text(ti_comp_val, " = %fns", comp_val / 65536.0);

                        if (action_type >= ECPRI_MSG_TYPE_5_RESERVED_MIN)
                        {
                            expert_add_info_format(
                                pinfo, timestamp_item, &ei_time_stamp,
                                "Compensation Value is not defined for Action Type %u",
                                action_type);
                        }
                        else if (
                            action_type != ECPRI_MSG_TYPE_5_REQ &&
                            action_type != ECPRI_MSG_TYPE_5_RESPONSE &&
                            action_type != ECPRI_MSG_TYPE_5_FOLLOWUP &&
                            comp_val != 0)
                        {
                            expert_add_info_format(
                                pinfo, ti_comp_val, &ei_comp_val,
                                "Compensation Value is not defined for Action Type %u, should be 0",
                                action_type);
                        }
                        offset += 8;
                        remaining_length -= ECPRI_MSG_TYPE_5_PAYLOAD_MIN_LENGTH;
                        if (remaining_length >= payload_size - ECPRI_MSG_TYPE_5_PAYLOAD_MIN_LENGTH)
                        {
                            proto_tree_add_item(payload_tree, hf_one_way_delay_measurement_dummy_bytes, tvb, offset, payload_size - ECPRI_MSG_TYPE_5_PAYLOAD_MIN_LENGTH, ENC_NA);
                            offset += payload_size - ECPRI_MSG_TYPE_5_PAYLOAD_MIN_LENGTH;
                        }
                    }
                    break;

                case ECPRI_MESSAGE_TYPE_REMOTE_RESET: /* 3.2.4.7. Remote Reset */
                    if (payload_size < ECPRI_MSG_TYPE_6_PAYLOAD_MIN_LENGTH)
                    {
                        expert_add_info_format(
                            pinfo, ti_payload_size, &ei_payload_size,
                            "Payload Size %u is too small for encoding Message Type %u. Should be min. %d",
                            payload_size, msg_type, ECPRI_MSG_TYPE_6_PAYLOAD_MIN_LENGTH);

                        offset += payload_size;
                        break;
                    }

                    if (remaining_length >= ECPRI_MSG_TYPE_6_PAYLOAD_MIN_LENGTH)
                    {
                        proto_tree_add_item(payload_tree, hf_remote_reset_reset_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        proto_tree_add_item(payload_tree, hf_remote_reset_reset_code, tvb, offset, 1, ENC_NA);
                        offset += 1;
                        remaining_length -= ECPRI_MSG_TYPE_6_PAYLOAD_MIN_LENGTH;
                        if (remaining_length >= payload_size - ECPRI_MSG_TYPE_6_PAYLOAD_MIN_LENGTH)
                        {
                            proto_tree_add_item(payload_tree, hf_remote_reset_vendor_specific_payload, tvb, offset, payload_size - ECPRI_MSG_TYPE_6_PAYLOAD_MIN_LENGTH, ENC_NA);
                            offset += payload_size - ECPRI_MSG_TYPE_6_PAYLOAD_MIN_LENGTH;
                        }
                    }
                    break;

                case ECPRI_MESSAGE_TYPE_EVENT_INDICATION: /* 3.2.4.8. Event Indication */
                    if (payload_size < ECPRI_MSG_TYPE_7_PAYLOAD_MIN_LENGTH)
                    {
                        expert_add_info_format(
                            pinfo, ti_payload_size, &ei_payload_size,
                            "Payload Size %u is too small for encoding Message Type %u. Should be min. %d",
                            payload_size, msg_type, ECPRI_MSG_TYPE_7_PAYLOAD_MIN_LENGTH);

                        offset += payload_size;
                        break;
                    }

                    if (remaining_length >= ECPRI_MSG_TYPE_7_PAYLOAD_MIN_LENGTH)
                    {
                        proto_tree_add_item(payload_tree, hf_event_indication_event_id, tvb, offset, 1, ENC_NA);
                        offset += 1;
                        proto_tree_add_item_ret_uint(payload_tree, hf_event_indication_event_type, tvb, offset, 1, ENC_NA, &event_type);
                        offset += 1;
                        proto_tree_add_item(payload_tree, hf_event_indication_sequence_number, tvb, offset, 1, ENC_NA);
                        offset += 1;
                        ti_num_faults = proto_tree_add_item_ret_uint(payload_tree, hf_event_indication_number_of_faults_notifications, tvb, offset, 1, ENC_NA, &num_faults_notif);
                        offset += 1;
                        /* Only for Event Type Fault Indication (0x00) and Notification Indication (0x02) */
                        if (event_type == ECPRI_MSG_TYPE_7_FAULT_INDICATION || event_type == ECPRI_MSG_TYPE_7_NOTIF_INDICATION)
                        {
                            /* These two Event Types should have notifications or faults */
                            if (num_faults_notif == 0)
                            {
                                expert_add_info_format(
                                    pinfo, ti_num_faults, &ei_number_faults,
                                    "Number of Faults/Notif %u should be > 0",
                                    num_faults_notif);
                                break;
                            }

                            /* Check Size of Elements */
                            const uint16_t expected_payload_size = ECPRI_MSG_TYPE_7_PAYLOAD_MIN_LENGTH + num_faults_notif * ECPRI_MSG_TYPE_7_ELEMENT_SIZE;
                            if (payload_size == expected_payload_size)
                            {
                                /* Dissect elements in loop */
                                for (uint32_t i = 0; i < num_faults_notif; i++)
                                {
                                    element_item = proto_tree_add_item(payload_tree, hf_event_indication_element, tvb, offset, ECPRI_MSG_TYPE_7_ELEMENT_SIZE, ENC_NA);
                                    proto_item_prepend_text(element_item, "#%u: ", i + 1);
                                    element_tree = proto_item_add_subtree(element_item, ett_ecpri_element);

                                    proto_tree_add_item(element_tree, hf_event_indication_element_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                                    offset += 2;
                                    proto_tree_add_item(element_tree, hf_event_indication_raise_cease, tvb, offset, 1, ENC_NA);
                                    ti_fault_notif = proto_tree_add_item_ret_uint(element_tree, hf_event_indication_fault_notification, tvb, offset, 2, ENC_BIG_ENDIAN, &fault_notif);

                                    /* Faults and Notifications cannot be mixed */
                                    const bool is_fault_event = event_type == ECPRI_MSG_TYPE_7_FAULT_INDICATION;
                                    const bool is_notif_event = event_type == ECPRI_MSG_TYPE_7_NOTIF_INDICATION;

                                    const bool is_fault_notif_in_fault_range = fault_notif <= ECPRI_MSG_TYPE_7_FAULTS_MAX;

                                    const bool is_fault_notif_in_notif_range =
                                        fault_notif >= ECPRI_MSG_TYPE_7_NOTIF_MIN &&
                                        fault_notif <= ECPRI_MSG_TYPE_7_NOTIF_MAX;

                                    const bool is_fault_notif_in_vendor_range =
                                        fault_notif >= ECPRI_MSG_TYPE_7_VENDOR_MIN &&
                                        fault_notif <= ECPRI_MSG_TYPE_7_VENDOR_MAX;

                                    if (is_fault_event && !(is_fault_notif_in_fault_range || is_fault_notif_in_vendor_range))
                                    {
                                        expert_add_info_format(
                                            pinfo, ti_fault_notif, &ei_fault_notif,
                                            "Only Faults are permitted with Event Type Faults Indication (0x%.2X)",
                                            event_type);
                                    }
                                    else if (is_notif_event && !(is_fault_notif_in_notif_range || is_fault_notif_in_vendor_range))
                                    {
                                        expert_add_info_format(
                                            pinfo, ti_fault_notif, &ei_fault_notif,
                                            "Only Notifications are permitted with Event Type Notifications Indication (0x%.2X)",
                                            event_type);
                                    }
                                    offset += 2;
                                    proto_tree_add_item(element_tree, hf_event_indication_additional_information, tvb, offset, 4, ENC_BIG_ENDIAN);
                                    offset += 4;
                                }
                            }
                            else if (payload_size < expected_payload_size)
                            {
                                expert_add_info_format(
                                    pinfo, ti_num_faults, &ei_number_faults,
                                    "Number of Faults/Notif %u is maybe too big",
                                    num_faults_notif);

                                expert_add_info_format(
                                    pinfo, ti_payload_size, &ei_payload_size,
                                    "Payload Size is maybe too small: %u",
                                    payload_size);
                            }
                            else
                            {
                                expert_add_info_format(
                                    pinfo, ti_num_faults, &ei_number_faults,
                                    "Number of Faults/Notif %u is maybe too small",
                                    num_faults_notif);

                                expert_add_info_format(
                                    pinfo, ti_payload_size, &ei_payload_size,
                                    "Payload Size is maybe too big: %u",
                                    payload_size);
                            }

                        }
                        else if (
                            event_type == ECPRI_MSG_TYPE_7_FAULT_INDICATION_ACK ||
                            event_type == ECPRI_MSG_TYPE_7_SYNC_REQUEST ||
                            event_type == ECPRI_MSG_TYPE_7_SYNC_ACK ||
                            event_type == ECPRI_MSG_TYPE_7_SYNC_END_INDICATION)
                        {
                            /* Number of Faults/Notifs should be 0, only 4 Byte possible*/
                            if (payload_size > 4)
                            {
                                expert_add_info_format(
                                    pinfo, ti_payload_size, &ei_payload_size,
                                    "Payload Size %u should be 4",
                                    payload_size);
                            }
                            /* These Event Types shouldn't have faults or notifications */
                            if (num_faults_notif != 0)
                            {
                                expert_add_info_format(
                                    pinfo, ti_num_faults, &ei_number_faults,
                                    "Number of Faults/Notif %u should be 0",
                                    num_faults_notif);
                            }
                        }
                        else
                        {
                            /* These Event Types are reserved, don't know how to decode */
                            if (num_faults_notif != 0)
                            {
                                expert_add_info_format(
                                    pinfo, ti_num_faults, &ei_number_faults,
                                    "Number of Faults/Notif %u, but no knowledge about encoding, because Event Type is reserved.",
                                    num_faults_notif);
                            }
                        }
                    }
                    break;

                case ECPRI_MESSAGE_TYPE_IWF_STARTUP: /* 3.2.4.9. IWF Start-Up */
                    if (payload_size < ECPRI_MSG_TYPE_8_PAYLOAD_MIN_LENGTH)
                    {
                        expert_add_info_format(
                            pinfo, ti_payload_size, &ei_payload_size,
                            "Payload Size %u is too small for encoding Message Type %u. Should be min. %d",
                            payload_size, msg_type, ECPRI_MSG_TYPE_8_PAYLOAD_MIN_LENGTH);

                        offset += payload_size;
                        break;
                    }

                    if (remaining_length >= ECPRI_MSG_TYPE_8_PAYLOAD_MIN_LENGTH)
                    {
                        proto_tree_add_item(payload_tree, hf_iwf_start_up_pc_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;

                        proto_tree_add_item(payload_tree, hf_iwf_start_up_hyperframe_number, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;

                        proto_tree_add_item(payload_tree, hf_iwf_start_up_subframe_number, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;

                        /* Time Stamp as nanoseconds */
                        proto_tree_add_item(payload_tree, hf_iwf_start_up_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;

                        /* F, S, r (skipped), Line Rate */
                        proto_tree_add_item(payload_tree, hf_iwf_start_up_fec_bit_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(payload_tree, hf_iwf_start_up_scrambling_bit_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(payload_tree, hf_iwf_start_up_line_rate, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;

                        remaining_length -= ECPRI_MSG_TYPE_8_PAYLOAD_MIN_LENGTH;
                        if (remaining_length >= payload_size - ECPRI_MSG_TYPE_8_PAYLOAD_MIN_LENGTH)
                        {
                            proto_tree_add_item(payload_tree, hf_iwf_start_up_data_transferred, tvb, offset, payload_size - ECPRI_MSG_TYPE_8_PAYLOAD_MIN_LENGTH, ENC_NA);
                            offset += payload_size - ECPRI_MSG_TYPE_8_PAYLOAD_MIN_LENGTH;
                        }
                    }
                    break;
                case ECPRI_MESSAGE_TYPE_IWF_OPERATION: /* 3.2.4.10. IWF Operation */
                    proto_tree_add_expert(payload_tree, pinfo, &ei_ecpri_not_dis_yet, tvb, offset, -1);
                    break;
                case ECPRI_MESSAGE_TYPE_IWF_MAPPING: /* 3.2.4.11. IWF Mapping */
                    proto_tree_add_expert(payload_tree, pinfo, &ei_ecpri_not_dis_yet, tvb, offset, -1);
                    break;
                case ECPRI_MESSAGE_TYPE_IWF_DELAY_CONTROL: /* 3.2.4.12. IWF Delay Control */
                    if (payload_size != ECPRI_MSG_TYPE_11_PAYLOAD_LENGTH)
                    {
                        expert_add_info_format(
                            pinfo, ti_payload_size, &ei_payload_size,
                            "Payload Size %u is too small or too big for encoding Message Type %u. Should be exactly %d",
                            payload_size, msg_type, ECPRI_MSG_TYPE_11_PAYLOAD_LENGTH);

                        offset += payload_size;
                        break;
                    }

                    if (remaining_length >= ECPRI_MSG_TYPE_11_PAYLOAD_LENGTH)
                    {
                        proto_tree_add_item(payload_tree, hf_iwf_delay_control_pc_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;

                        proto_tree_add_item(payload_tree, hf_iwf_delay_control_delay_control_id, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;

                        proto_item *ti_iwf_delay_control_action_type;
                        uint32_t iwf_delay_control_action_type;
                        ti_iwf_delay_control_action_type = proto_tree_add_item_ret_uint(
                            payload_tree, hf_iwf_delay_control_action_type, tvb, offset, 1, ENC_NA, &iwf_delay_control_action_type);
                        offset += 1;

                        proto_item *ti_iwf_delay_control_delay_a;
                        uint32_t iwf_delay_control_delay_a;
                        ti_iwf_delay_control_delay_a = proto_tree_add_item_ret_uint(
                            payload_tree, hf_iwf_delay_control_delay_a, tvb, offset, 4, ENC_BIG_ENDIAN, &iwf_delay_control_delay_a);
                        proto_item_append_text(ti_iwf_delay_control_delay_a, " = %fns", iwf_delay_control_delay_a / 16.0);
                        offset += 4;

                        proto_item *ti_iwf_delay_control_delay_b;
                        uint32_t iwf_delay_control_delay_b;
                        ti_iwf_delay_control_delay_b = proto_tree_add_item_ret_uint(
                            payload_tree, hf_iwf_delay_control_delay_b, tvb, offset, 4, ENC_BIG_ENDIAN, &iwf_delay_control_delay_b);
                        proto_item_append_text(ti_iwf_delay_control_delay_b, " = %fns", iwf_delay_control_delay_b / 16.0);
                        offset += 4;

                        const bool is_action_type_req = iwf_delay_control_action_type == ECPRI_MSG_TYPE_11_REQUEST_GET_DELAYS;
                        const bool are_delays_zero = iwf_delay_control_delay_a == 0 && iwf_delay_control_delay_b == 0;
                        if (is_action_type_req && !are_delays_zero)
                        {
                            expert_add_info_format(
                                pinfo, ti_iwf_delay_control_action_type, &ei_iwf_delay_control_action_type,
                                "Action Type %u is Request Get Delays, but Delays are not 0",
                                iwf_delay_control_action_type);
                        }
                        else if (!is_action_type_req && are_delays_zero)
                        {
                            expert_add_info_format(
                                pinfo, ti_iwf_delay_control_action_type, &ei_iwf_delay_control_action_type,
                                "Action Type %u is not Request Get Delays, but Delays are 0",
                                iwf_delay_control_action_type);
                        }
                    }
                    break;
                default:
                    /* Reserved or Vendor Specific */
                    offset += payload_size;
                    break;
                }
            }
        }
        /* If Preference not chosen,  Payload will be not decoded */
        else
        {
            if (reported_length >= offset + payload_size)
            {
                offset += payload_size;
            }
        }
    } while (concatenation_bit != 0 && ((reported_length - offset) >= ECPRI_HEADER_LENGTH));

    /* Expecting last concatenation bit to be false */
    if (concatenation_bit != false)
    {
        expert_add_info_format(pinfo, ti_c_bit, &ei_c_bit, "Concatenation Bit is 1, should be 0");
    }

    /* Not dissected buffer - any remainder passed to data dissector */
    if (offset != 0)
    {
        next_tvb = tvb_new_subset_remaining(tvb, offset);
        call_data_dissector(next_tvb, pinfo, tree);
    }

    /* Overall eCPRI length (based upon reported length of tvb passed in) */
    proto_item *length_ti = proto_tree_add_uint(ecpri_tree, hf_ecpri_length, tvb, 0, 0, reported_length);
    proto_item_set_generated(length_ti);

    return reported_length;
}

void proto_register_ecpri(void)
{
    static hf_register_info hf[] = {
    /* eCPRI Common Header */
        { &hf_common_header, { "eCPRI Common Header", "ecpri.header", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_common_header_ecpri_protocol_revision, { "Protocol Revision", "ecpri.revision", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL } },
        { &hf_common_header_reserved, { "Reserved", "ecpri.reserved", FT_UINT8, BASE_DEC, NULL, 0x0E, NULL, HFILL } },
        { &hf_common_header_c_bit, { "C-Bit", "ecpri.cbit", FT_BOOLEAN, 8, TFS(&tfs_c_bit), 0x01, "Concatenation indicator", HFILL } },
        { &hf_common_header_ecpri_message_type, { "Message Type", "ecpri.type", FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(ecpri_msg_types), 0x0, NULL, HFILL } },
        { &hf_common_header_ecpri_payload_size, { "Payload Size", "ecpri.size", FT_UINT16, BASE_DEC, NULL, 0x0, "Size of eCPRI message payload in bytes", HFILL } },
    /* eCPRI Payload */
        { &hf_payload,   { "eCPRI Payload", "ecpri.payload", FT_BYTES, SEP_COLON, NULL, 0x0, NULL, HFILL } },
        { &hf_ecpri_length, { "eCPRI Length", "ecpri.length", FT_UINT32, BASE_DEC, NULL, 0x0, "Length in bytes, including header", HFILL } },
    /* Message Type 0: IQ Data */
        { &hf_iq_data_pc_id, { "PC_ID", "ecpri.pcid", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_iq_data_seq_id, { "SEQ_ID", "ecpri.iqd.seqid", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_iq_data_iq_samples_of_user_data, { "IQ Samples of User Data", "ecpri.iqd.iqdata", FT_BYTES, SEP_COLON, NULL, 0x0, NULL, HFILL } },
    /* Message Type 1: Bit Sequence */
        { &hf_bit_sequence_pc_id, { "PC_ID", "ecpri.pcid", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_bit_sequence_seq_id, { "SEQ_ID", "ecpri.bs.seqid", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_bit_sequence_bit_sequence_of_user_data, { "Bit Sequence", "ecpri.bs.bitseq", FT_BYTES, SEP_COLON, NULL, 0x0, NULL, HFILL } },
    /* Message Type 2: Real-Time Control Data */
        { &hf_real_time_control_data_rtc_id, { "RTC_ID", "ecpri.rtcd.rtcid", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_real_time_control_data_seq_id, { "SEQ_ID", "ecpri.rtcd.seqid", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_real_time_control_data_rtc_data, { "Real-Time Control Data", "ecpri.rtcd.rtcdata", FT_BYTES, SEP_COLON, NULL, 0x0, NULL, HFILL } },
    /* Message Type 3: Generic Data Transfer */
        { &hf_generic_data_transfer_pc_id, { "PC_ID", "ecpri.pcid", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_generic_data_transfer_seq_id, { "SEQ_ID", "ecpri.gdt.seqid", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_generic_data_transfer_data_transferred, { "Data transferred", "ecpri.gdt.gendata", FT_BYTES, SEP_COLON, NULL, 0x0, NULL, HFILL } },
    /* Message Type 4: Remote Memory Access */
        { &hf_remote_memory_access_id, { "Remote Memory Access ID", "ecpri.rma.rmaid", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_remote_memory_access_read_write, { "Read/Write", "ecpri.rma.rw", FT_UINT8, BASE_HEX, VALS(remote_memory_access_read_write_coding), 0xF0, NULL, HFILL } },
        { &hf_remote_memory_access_request_response, { "Request/Response", "ecpri.rma.reqresp", FT_UINT8, BASE_HEX, VALS(remote_memory_access_request_response_coding), 0x0F, NULL, HFILL } },
        { &hf_remote_memory_access_element_id, { "Element ID", "ecpri.rma.elementid", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_remote_memory_access_address, { "Address", "ecpri.rma.address", FT_BYTES, SEP_COLON, NULL, 0x0, NULL, HFILL } },
        { &hf_remote_memory_access_data_length, { "Data Length", "ecpri.rma.datalength", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_remote_memory_access_data, { "Data", "ecpri.rma.rmadata", FT_BYTES, SEP_COLON, NULL, 0x0, NULL, HFILL } },
    /* Message Type 5: One-Way Delay Measurement */
        { &hf_one_way_delay_measurement_id, { "Measurement ID", "ecpri.owdm.measurementid", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_one_way_delay_measurement_action_type, { "Action Type", "ecpri.owdm.actiontype", FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(one_way_delay_measurement_action_type_coding), 0x0, NULL, HFILL } },
        { &hf_one_way_delay_measurement_timestamp, { "Timestamp", "ecpri.owdm.timestamp", FT_BYTES, SEP_COLON, NULL, 0x0, NULL, HFILL } },
        { &hf_one_way_delay_measurement_timestamp_seconds, { "Seconds", "ecpri.owdm.sec", FT_UINT48, BASE_DEC|BASE_UNIT_STRING, UNS(&units_seconds), 0x0, NULL, HFILL } },
        { &hf_one_way_delay_measurement_timestamp_nanoseconds, { "Nanoseconds", "ecpri.owdm.nanosec", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_nanoseconds), 0x0, NULL, HFILL } },
        { &hf_one_way_delay_measurement_compensation_value, { "Compensation Value", "ecpri.owdm.compval", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_one_way_delay_measurement_dummy_bytes, { "Dummy bytes", "ecpri.owdm.owdmdata", FT_BYTES, SEP_COLON, NULL, 0x0, NULL, HFILL } },
    /* Message Type 6: Remote Reset */
        { &hf_remote_reset_reset_id, { "Reset ID", "ecpri.rr.resetid", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_remote_reset_reset_code, { "Reset Code Op", "ecpri.rr.resetcode", FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(remote_reset_reset_coding), 0x0, NULL, HFILL } },
        { &hf_remote_reset_vendor_specific_payload, { "Vendor Specific Payload", "ecpri.rr.vendorpayload", FT_BYTES, SEP_COLON, NULL, 0x0, NULL, HFILL } },
    /* Message Type 7: Event Indication */
        { &hf_event_indication_event_id, { "Event ID", "ecpri.ei.eventid", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_event_indication_event_type, { "Event Type", "ecpri.ei.eventtype", FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(event_indication_event_type_coding), 0x0, NULL, HFILL } },
        { &hf_event_indication_sequence_number, { "Sequence Number", "ecpri.ei.seqnum", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_event_indication_number_of_faults_notifications, { "Number of Faults/Notifications", "ecpri.ei.numberfaultnotif", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_event_indication_element, { "Element", "ecpri.ei.element", FT_BYTES, SEP_COLON, NULL, 0x0, NULL, HFILL } },
        { &hf_event_indication_element_id, { "Element ID", "ecpri.ei.elementid", FT_UINT16, BASE_HEX|BASE_RANGE_STRING, RVALS(event_indication_element_id_coding),  0x0, NULL, HFILL } },
        { &hf_event_indication_raise_cease, { "Raise/Cease", "ecpri.ei.raisecease", FT_UINT8, BASE_HEX, VALS(event_indication_raise_ceased_coding), 0xF0, NULL, HFILL } },
        { &hf_event_indication_fault_notification, { "Fault/Notification", "ecpri.ei.faultnotif", FT_UINT16, BASE_HEX|BASE_RANGE_STRING, RVALS(event_indication_fault_notif_coding), 0x0FFF, NULL, HFILL } },
        { &hf_event_indication_additional_information, { "Additional Information", "ecpri.ei.addinfo", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    /* Message Type 8: IWF Start-Up */
        { &hf_iwf_start_up_pc_id, { "PC_ID", "ecpri.pcid", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_iwf_start_up_hyperframe_number, { "Hyperframe Number #Z", "ecpri.iwfsu.hfn", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_iwf_start_up_subframe_number, { "Subframe Number #Y", "ecpri.iwfsu.sfn", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_iwf_start_up_timestamp, { "Timestamp", "ecpri.iwfsu.timestamp", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_nanoseconds), 0x0, NULL, HFILL } },
        { &hf_iwf_start_up_fec_bit_indicator, { "FEC Bit Indicator", "ecpri.iwfsu.fecbit", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x80, NULL, HFILL } },
        { &hf_iwf_start_up_scrambling_bit_indicator, { "Scrambling Bit Indicator", "ecpri.iwfsu.scramblingbit", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x40, NULL, HFILL } },
        { &hf_iwf_start_up_line_rate, { "Line Rate", "ecpri.iwfsu.linerate", FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(iwf_start_up_line_rate_coding), 0x1F, NULL, HFILL } },
        { &hf_iwf_start_up_data_transferred, { "Data transferred", "ecpri.iwfsu.vendorpayload", FT_BYTES, SEP_COLON, NULL, 0x0, NULL, HFILL } },
    /* Message Type 11: IWF Delay Control */
        { &hf_iwf_delay_control_pc_id, { "PC_ID", "ecpri.pcid", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_iwf_delay_control_delay_control_id, { "Delay Control ID", "ecpri.iwfdc.id", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_iwf_delay_control_action_type, { "Action Type", "ecpri.iwfdc.actiontype", FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(iwf_delay_control_action_type_coding), 0x0, NULL, HFILL } },
        { &hf_iwf_delay_control_delay_a, { "Delay A", "ecpri.iwfdc.delaya", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_iwf_delay_control_delay_b, { "Delay B", "ecpri.iwfdc.delayb", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_ecpri,
        &ett_ecpri_header,
        &ett_ecpri_payload,
        &ett_ecpri_timestamp,
        &ett_ecpri_element
    };

    static ei_register_info ei[] = {
        { &ei_ecpri_frame_length,   { "ecpri.frame.length.invalid", PI_PROTOCOL, PI_ERROR, "Invalid eCPRI Frame Length", EXPFILL }},
        { &ei_payload_size,         { "ecpri.payload.size.invalid", PI_PROTOCOL, PI_ERROR, "Invalid Payload Size",       EXPFILL }},
        { &ei_data_length,          { "ecpri.data.length.invalid",  PI_PROTOCOL, PI_ERROR, "Invalid Data Length",        EXPFILL }},
        { &ei_comp_val,             { "ecpri.comp.val.invalid",     PI_PROTOCOL, PI_ERROR, "Invalid Compensation Value", EXPFILL }},
        { &ei_time_stamp,           { "ecpri.time.stamp.invalid",   PI_PROTOCOL, PI_ERROR, "Invalid Time Stamp",         EXPFILL }},
        { &ei_c_bit,                { "ecpri.concat.bit.invalid",   PI_PROTOCOL, PI_ERROR, "Invalid Concatenation Bit",  EXPFILL }},
        { &ei_fault_notif,          { "ecpri.fault.notif.invalid",  PI_PROTOCOL, PI_ERROR, "Invalid Fault/Notification", EXPFILL }},
        { &ei_number_faults,        { "ecpri.num.faults.invalid",   PI_PROTOCOL, PI_ERROR, "Invalid Number of Faults",   EXPFILL }},
        { &ei_iwf_delay_control_action_type, { "ecpri.action.type.invalid", PI_PROTOCOL, PI_ERROR, "Invalid Action Type", EXPFILL }},
        { &ei_ecpri_not_dis_yet,    { "ecpri.not_dissected_yet",    PI_PROTOCOL, PI_NOTE,  "Not dissected yet",   EXPFILL }}
    };

    expert_module_t* expert_ecpri;
    module_t* ecpri_module;

    /* Register the protocol name and description */
    proto_ecpri = proto_register_protocol("evolved Common Public Radio Interface",    /* Protoname */
                                          "eCPRI",                                    /* Proto Shortname */
                                          "ecpri");                                   /* Proto Abbrev */
    ecpri_handle = register_dissector("ecpri", dissect_ecpri, proto_ecpri);


    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_ecpri, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    /* Register Expert Info */
    expert_ecpri = expert_register_protocol(proto_ecpri);
    expert_register_field_array(expert_ecpri, ei, array_length(ei));
    /* Register Preference */
    ecpri_module = prefs_register_protocol(proto_ecpri, NULL);
    /* If not set, it shows which message type was used, but no decoding of payload */
    prefs_register_bool_preference(ecpri_module,
            "ecpripref.msg.decoding",
            "Decode Message Types",
            "Decode the Message Types according to eCPRI Specification V2.0",
            &pref_message_type_decoding);
}

void proto_reg_handoff_ecpri(void)
{
    dissector_add_uint("ethertype", ETHERTYPE_ECPRI, ecpri_handle);             /* Ethertypes 0xAEFE */
    dissector_add_uint_range_with_preference("udp.port", "", ecpri_handle);     /* UDP Port Preference */

    oran_fh_handle = find_dissector("oran_fh_cus");
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
