/* packet-ecpri.c
 * Routines for eCPRI dissection
 * Copyright 2019, Maximilian Kohler <maximilian.kohler@viavisolutions.com>
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
 * ------------------------------------------------------------------------------------------------
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/etypes.h>

/**************************************************************************************************/
/* Definition for eCPRI lengths                                                                   */
/**************************************************************************************************/
/* eCPRI Common Header (4 Bytes) */
#define ECPRI_HEADER_LENGTH                         4
/* Message Type Length */
#define ECPRI_MSG_TYPE_0_1_PAYLOAD_MIN_LENGTH       4
#define ECPRI_MSG_TYPE_2_PAYLOAD_MIN_LENGTH         4
#define ECPRI_MSG_TYPE_3_PAYLOAD_MIN_LENGTH         8
#define ECPRI_MSG_TYPE_4_PAYLOAD_MIN_LENGTH        12
#define ECPRI_MSG_TYPE_5_PAYLOAD_MIN_LENGTH        20
#define ECPRI_MSG_TYPE_6_PAYLOAD_MIN_LENGTH         3
#define ECPRI_MSG_TYPE_7_PAYLOAD_MIN_LENGTH         4
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
/* Function Prototypes                                                                            */
/**************************************************************************************************/
void proto_register_ecpri(void);
void proto_reg_handoff_ecpri(void);

/**************************************************************************************************/
/* Initialize the subtree pointers                                                                */
/**************************************************************************************************/
static gint ett_ecpri                = -1;
static gint ett_ecpri_header         = -1;
static gint ett_ecpri_payload        = -1;
static gint ett_ecpri_timestamp      = -1;
static gint ett_ecpri_element        = -1;

/**************************************************************************************************/
/* Initialize the protocol and registered fields                                                  */
/**************************************************************************************************/
static int proto_ecpri               = -1;
/* Fields for Common Header */
static int hf_header                 = -1;
static int hf_proto_rev              = -1;
static int hf_reserved               = -1;
static int hf_c_bit                  = -1;
static int hf_msg_type               = -1;
static int hf_payload_size           = -1;
/* Fields for Payload */
static int hf_payload                = -1;
/* Fields for Payload of Message Type 0 and 1 */
static int hf_pc_id                  = -1;
/* Fields for Payload of Message Type 0, 1 and 2 */
static int hf_seq_id                 = -1;
/* Fields for Payload of Message Type 2 */
static int hf_rtc_id                 = -1;
/* Fields for Payload of Message Type 3 */
static int hf_pc_id2                 = -1;
static int hf_seq_id2                = -1;
/* Fields for Payload of Message Type 4 */
static int hf_rma_id                 = -1;
static int hf_read_write             = -1;
static int hf_request_response       = -1;
static int hf_element_id             = -1;
static int hf_address                = -1;
static int hf_data_length            = -1;
/* Fields for Payload of Message Type 5 */
static int hf_measurement_id         = -1;
static int hf_action_type            = -1;
static int hf_timestamp              = -1;
static int hf_timestamp_sec          = -1;
static int hf_timestamp_nanosec      = -1;
static int hf_compensation_value     = -1;
/* Fields for Payload of Message Type 6 */
static int hf_reset_id               = -1;
static int hf_reset_code             = -1;
/* Fields for Payload of Message Type 7 */
static int hf_event_id               = -1;
static int hf_event_type             = -1;
static int hf_sequence_num           = -1;
static int hf_number_faults_notif    = -1;
static int hf_element                = -1;
static int hf_element_id2            = -1;
static int hf_raise_cease            = -1;
static int hf_fault_notif            = -1;
static int hf_add_info               = -1;
/* Fields for Payload - rest of data */
static int hf_data                   = -1;

/**************************************************************************************************/
/* Preference to use the eCPRI Specification 1.2 encoding                                         */
/**************************************************************************************************/
static gboolean message_type_decoding    = TRUE;

/**************************************************************************************************/
/* eCPRI Handle                                                                                   */
/**************************************************************************************************/
static dissector_handle_t ecpri_handle;

/**************************************************************************************************/
/* Initialize expert info fields                                                                  */
/**************************************************************************************************/
static expert_field ei_ecpri_frame_length   = EI_INIT;
static expert_field ei_payload_size         = EI_INIT;
static expert_field ei_comp_val             = EI_INIT;
static expert_field ei_time_stamp           = EI_INIT;
static expert_field ei_data_length          = EI_INIT;
static expert_field ei_c_bit                = EI_INIT;
static expert_field ei_fault_notif          = EI_INIT;
static expert_field ei_number_faults        = EI_INIT;
static expert_field ei_ecpri_not_dis_yet    = EI_INIT;

/**************************************************************************************************/
/* Field Encoding of Message Types                                                                */
/**************************************************************************************************/

#define ECPRI_MT_IQ_DATA            0
#define ECPRI_MT_BIT_SEQ            1
#define ECPRI_MT_RT_CTRL_DATA       2
#define ECPRI_MT_GEN_DATA_TFER      3
#define ECPRI_MT_REM_MEM_ACC        4
#define ECPRI_MT_1WAY_DELAY         5
#define ECPRI_MT_REM_RST            6
#define ECPRI_MT_EVT_IND            7
#define ECPRI_MT_IWF_STARTUP        8
#define ECRPI_MT_IWF_OP             9
#define ECRPI_MT_IWF_MAPPING        10
#define ECRPI_MT_IWF_DELAY_CONTROL  11

static const range_string ecpri_msg_types[] = {
        /* Message Types (3.2.4) */
        { ECPRI_MT_IQ_DATA,            ECPRI_MT_IQ_DATA,            "IQ Data"                   },
        { ECPRI_MT_BIT_SEQ,            ECPRI_MT_BIT_SEQ,            "Bit Sequence"              },
        { ECPRI_MT_RT_CTRL_DATA,       ECPRI_MT_RT_CTRL_DATA,       "Real-Time Control Data"    },
        { ECPRI_MT_GEN_DATA_TFER,      ECPRI_MT_GEN_DATA_TFER,      "Generic Data Transfer"     },
        { ECPRI_MT_REM_MEM_ACC,        ECPRI_MT_REM_MEM_ACC,        "Remote Memory Access"      },
        { ECPRI_MT_1WAY_DELAY,         ECPRI_MT_1WAY_DELAY,         "One-Way Delay Measurement" },
        { ECPRI_MT_REM_RST,            ECPRI_MT_REM_RST,            "Remote Reset"              },
        { ECPRI_MT_EVT_IND,            ECPRI_MT_EVT_IND,            "Event Indication"          },
        { ECPRI_MT_IWF_STARTUP,        ECPRI_MT_IWF_STARTUP,        "IWF Start-Up"              },
        { ECRPI_MT_IWF_OP,             ECRPI_MT_IWF_OP,             "IWF Operation"             },
        { ECRPI_MT_IWF_MAPPING,        ECRPI_MT_IWF_MAPPING,        "IWF Mapping"               },
        { ECRPI_MT_IWF_DELAY_CONTROL,  ECRPI_MT_IWF_DELAY_CONTROL,  "IWF Delay Control"         },
        /* Message Types 12 -  63*/
        { 12,                          63,                          "Reserved"                  },
        /* Message Types 64 - 255 */
        { 64,                          255,                         "Vendor Specific"           },
        { 0,      0,      NULL  }
};

/**************************************************************************************************/
/* Field Encoding of Message Type 4: Remote Memory Access                                         */
/**************************************************************************************************/
static const value_string read_write_coding[] = {
        { 0x0,    "Read"                },
        { 0x1,    "Write"               },
        { 0x2,    "Write no Response"   },
        { 0x3,    "Reserved"            },
        { 0x4,    "Reserved"            },
        { 0x5,    "Reserved"            },
        { 0x6,    "Reserved"            },
        { 0x7,    "Reserved"            },
        { 0x8,    "Reserved"            },
        { 0x9,    "Reserved"            },
        { 0xA,    "Reserved"            },
        { 0xB,    "Reserved"            },
        { 0xC,    "Reserved"            },
        { 0xD,    "Reserved"            },
        { 0xE,    "Reserved"            },
        { 0xF,    "Reserved"            },
        { 0,      NULL                  }
};

static const value_string request_response_coding[] = {
        { 0x0,    "Request"     },
        { 0x1,    "Response"    },
        { 0x2,    "Failure"     },
        { 0x3,    "Reserved"    },
        { 0x4,    "Reserved"    },
        { 0x5,    "Reserved"    },
        { 0x6,    "Reserved"    },
        { 0x7,    "Reserved"    },
        { 0x8,    "Reserved"    },
        { 0x9,    "Reserved"    },
        { 0xA,    "Reserved"    },
        { 0xB,    "Reserved"    },
        { 0xC,    "Reserved"    },
        { 0xD,    "Reserved"    },
        { 0xE,    "Reserved"    },
        { 0xF,    "Reserved"    },
        { 0,      NULL          }
};

/**************************************************************************************************/
/* Field Encoding of Message Type 5: One-way Delay Measurement                                    */
/**************************************************************************************************/
static const range_string action_type_coding[] = {
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
static const range_string reset_coding[] = {
        { 0x00,    0x00,    "Reserved"              },
        { 0x01,    0x01,    "Remote reset request"  },
        { 0x02,    0x02,    "Remote reset response" },
        { 0x03,    0xFF,    "Reserved"              },
        { 0,       0,       NULL                    }
};

/**************************************************************************************************/
/* Field Encoding of Message Type 7: Event Indication                                             */
/**************************************************************************************************/
static const range_string event_type_coding[] = {
        { 0x00,    0x00,    "Fault(s) Indication"             },
        { 0x01,    0x01,    "Fault(s) Indication Acknowledge" },
        { 0x02,    0x02,    "Notification(s) Indication"      },
        { 0x03,    0x03,    "Synchronization Request"         },
        { 0x04,    0x04,    "Synchronization Acknowledge"     },
        { 0x05,    0x05,    "Synchronization End Indication"  },
        { 0x06,    0xFF,    "Reserved"                        },
        { 0,       0,       NULL                              }
};

static const range_string element_id_coding[] = {
        { 0x0000,    0xFFFE,    "Vendor specific usage"                          },
        { 0xFFFF,    0xFFFF,    "Fault/Notification applicable for all Elements" },
        { 0,         0,         NULL                                             }
};

static const value_string raise_ceased_coding[] = {
        { 0x0,    "Raise a fault" },
        { 0x1,    "Cease a fault" },
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

static const range_string fault_notif_coding[] = {
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

static dissector_handle_t oran_handle;

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
    guint32 msg_type;
    guint32 event_type;
    guint8 concatenation;
    guint32 num_faults_notif;
    guint32 action_type;
    guint32 fault_notif;
    guint16 payload_size;
    guint32 data_length;
    guint16 reported_length;
    guint16 remaining_length;
    guint32 time_stamp_ns;
    guint64 time_stamp_s;
    guint64 comp_val;

    reported_length = tvb_reported_length(tvb);

    /* Check of eCPRI min. length (header-length) */
    if (reported_length < ECPRI_HEADER_LENGTH)
        return 0;

    /* Set column of protocol eCPRI */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "eCPRI");
    col_clear(pinfo->cinfo, COL_INFO);

    offset = 0;
    concatenation = tvb_get_guint8(tvb, offset) & 0x01;
    if (concatenation != 0x00)
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, "Concatenation");
    }

    /* do-while loop for concatenation check */
    do
    {
        /* 4-byte boundary check for concatenation */
        if (offset % 4 != 0)
            offset = offset + 4 - (offset % 4);

        /* Read Payload Size */
        payload_size = tvb_get_ntohs(tvb, offset + 2);
        /* Read C-Bit (Concatenation) */
        concatenation = tvb_get_guint8(tvb, offset) & 0x01;

        /* eCPRI tree */
        if (payload_size + ECPRI_HEADER_LENGTH <= reported_length)
        {
            ecpri_item = proto_tree_add_item(tree, proto_ecpri, tvb, offset, payload_size + ECPRI_HEADER_LENGTH, ENC_NA);
        }
        else
        {
            ecpri_item = proto_tree_add_item(tree, proto_ecpri, tvb, offset, -1, ENC_NA);
            expert_add_info_format(pinfo, ecpri_item, &ei_ecpri_frame_length, "eCPRI frame length %d is too small, should be min. %d", reported_length, payload_size + ECPRI_HEADER_LENGTH);
        }
        ecpri_tree = proto_item_add_subtree(ecpri_item, ett_ecpri);

        /* eCPRI header-subtree */
        header_item = proto_tree_add_item(ecpri_tree, hf_header, tvb, offset, ECPRI_HEADER_LENGTH, ENC_BIG_ENDIAN);
        header_tree = proto_item_add_subtree(header_item, ett_ecpri_header);

        proto_tree_add_item(header_tree, hf_proto_rev, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(header_tree, hf_reserved, tvb, offset, 1, ENC_NA);
        ti_c_bit = proto_tree_add_item(header_tree, hf_c_bit, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item_ret_uint(header_tree, hf_msg_type, tvb, offset, 1, ENC_NA, &msg_type);
        /* Append Message Type into info column & header item */
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ",", "Message Type: %s", try_rval_to_str(msg_type, ecpri_msg_types));
        proto_item_append_text(header_item, "   MessageType: %s", try_rval_to_str(msg_type, ecpri_msg_types));
        offset += 1;
        ti_payload_size = proto_tree_add_item(header_tree, hf_payload_size, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* eCPRI payload-subtree */
        /* Length Check */
        if (reported_length >= ECPRI_HEADER_LENGTH + payload_size)
        {
            payload_item = proto_tree_add_item(ecpri_tree, hf_payload, tvb, offset, payload_size, ENC_NA);
        }
        else
        {
            expert_add_info_format(pinfo, ti_payload_size, &ei_payload_size, "Payload Size %d is too big, maximal %d is possible", payload_size, reported_length - ECPRI_HEADER_LENGTH);
            payload_item = proto_tree_add_item(ecpri_tree, hf_payload, tvb, offset, -1, ENC_NA);
        }

        payload_tree = proto_item_add_subtree(payload_item, ett_ecpri_payload);
        remaining_length = reported_length - offset;
        if (message_type_decoding)
        {
            tvbuff_t *fh_tvb = tvb_new_subset_length_caplen(tvb, offset, payload_size, payload_size);
            /* See whether we have an O-RAN fronthaul sub-dissector that handles this, otherwise decode vanilla eCPRI */
            if (call_dissector_only(oran_handle, fh_tvb, pinfo, tree, &msg_type)) {
                /* Assume that it has claimed the entire tvb */
                offset = tvb_reported_length(tvb);
            }
            else {
                switch (msg_type)
                {
                case ECPRI_MT_IQ_DATA:
                    /* 3.2.4.1 IQ Data */
                case ECPRI_MT_BIT_SEQ:
                    /* 3.2.4.2 Bit Sequence */
                    if (payload_size >= ECPRI_MSG_TYPE_0_1_PAYLOAD_MIN_LENGTH)
                    {
                        if (remaining_length >= ECPRI_MSG_TYPE_0_1_PAYLOAD_MIN_LENGTH)
                        {
                            proto_tree_add_item(payload_tree, hf_pc_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                            offset += 2;
                            proto_tree_add_item(payload_tree, hf_seq_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                            offset += 2;
                            remaining_length -= ECPRI_MSG_TYPE_0_1_PAYLOAD_MIN_LENGTH;
                            if (remaining_length >= payload_size - ECPRI_MSG_TYPE_0_1_PAYLOAD_MIN_LENGTH)
                            {
                                proto_tree_add_item(payload_tree, hf_data, tvb, offset, payload_size - ECPRI_MSG_TYPE_0_1_PAYLOAD_MIN_LENGTH, ENC_NA);
                                offset += payload_size - ECPRI_MSG_TYPE_0_1_PAYLOAD_MIN_LENGTH;
                            }
                        }
                    }
                    else
                    {
                        expert_add_info_format(pinfo, ti_payload_size, &ei_payload_size, "Payload Size %d is too small for encoding Message Type %d. Should be min. %d", payload_size, msg_type, ECPRI_MSG_TYPE_0_1_PAYLOAD_MIN_LENGTH);
                    }
                    break;
                case ECPRI_MT_RT_CTRL_DATA:
                    /* 3.2.4.3 Real-Time Control Data */
                    /* N.B. if ORAN dissector is enabled, it will handle this type instead! */
                    if (payload_size >= ECPRI_MSG_TYPE_2_PAYLOAD_MIN_LENGTH)
                    {
                        if (remaining_length >= ECPRI_MSG_TYPE_2_PAYLOAD_MIN_LENGTH)
                        {
                            proto_tree_add_item(payload_tree, hf_rtc_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                            offset += 2;
                            proto_tree_add_item(payload_tree, hf_seq_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                            offset += 2;
                            remaining_length -= ECPRI_MSG_TYPE_2_PAYLOAD_MIN_LENGTH;
                            if (remaining_length >= payload_size - ECPRI_MSG_TYPE_2_PAYLOAD_MIN_LENGTH)
                            {
                                proto_tree_add_item(payload_tree, hf_data, tvb, offset, payload_size - ECPRI_MSG_TYPE_2_PAYLOAD_MIN_LENGTH, ENC_NA);
                                offset += payload_size - ECPRI_MSG_TYPE_2_PAYLOAD_MIN_LENGTH;
                            }
                        }
                    }
                    else
                    {
                        expert_add_info_format(pinfo, ti_payload_size, &ei_payload_size, "Payload Size %d is too small for encoding Message Type %d. Should be min. %d", payload_size, msg_type, ECPRI_MSG_TYPE_2_PAYLOAD_MIN_LENGTH);
                    }
                    break;
                case ECPRI_MT_GEN_DATA_TFER:
                    /* 3.2.4.4 Generic Data Transfer */
                    if (payload_size >= ECPRI_MSG_TYPE_3_PAYLOAD_MIN_LENGTH)
                    {
                        if (remaining_length >= ECPRI_MSG_TYPE_3_PAYLOAD_MIN_LENGTH)
                        {
                            proto_tree_add_item(payload_tree, hf_pc_id2, tvb, offset, 4, ENC_BIG_ENDIAN);
                            offset += 4;
                            proto_tree_add_item(payload_tree, hf_seq_id2, tvb, offset, 4, ENC_BIG_ENDIAN);
                            offset += 4;
                            remaining_length -= ECPRI_MSG_TYPE_3_PAYLOAD_MIN_LENGTH;
                            if (remaining_length >= payload_size - ECPRI_MSG_TYPE_3_PAYLOAD_MIN_LENGTH)
                            {
                                proto_tree_add_item(payload_tree, hf_data, tvb, offset, payload_size - ECPRI_MSG_TYPE_3_PAYLOAD_MIN_LENGTH, ENC_NA);
                                offset += payload_size - ECPRI_MSG_TYPE_3_PAYLOAD_MIN_LENGTH;
                            }
                        }
                    }
                    else
                    {
                        expert_add_info_format(pinfo, ti_payload_size, &ei_payload_size, "Payload Size %d is too small for encoding Message Type %d. Should be min. %d", payload_size, msg_type, ECPRI_MSG_TYPE_3_PAYLOAD_MIN_LENGTH);
                    }
                    break;
                case ECPRI_MT_REM_MEM_ACC:
                    /* 3.2.4.5 Remote Memory Access */
                    if (payload_size >= ECPRI_MSG_TYPE_4_PAYLOAD_MIN_LENGTH)
                    {
                        if (remaining_length >= ECPRI_MSG_TYPE_4_PAYLOAD_MIN_LENGTH)
                        {
                            proto_tree_add_item(payload_tree, hf_rma_id, tvb, offset, 1, ENC_NA);
                            offset += 1;
                            proto_tree_add_item(payload_tree, hf_read_write, tvb, offset, 1, ENC_NA);
                            proto_tree_add_item(payload_tree, hf_request_response, tvb, offset, 1, ENC_NA);
                            offset += 1;
                            proto_tree_add_item(payload_tree, hf_element_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                            offset += 2;
                            proto_tree_add_item(payload_tree, hf_address, tvb, offset, 6, ENC_NA);
                            offset += 6;
                            ti_data_length = proto_tree_add_item_ret_uint(payload_tree, hf_data_length, tvb, offset, 2, ENC_BIG_ENDIAN, &data_length);
                            offset += 2;
                            remaining_length -= ECPRI_MSG_TYPE_4_PAYLOAD_MIN_LENGTH;
                            if (remaining_length >= payload_size - ECPRI_MSG_TYPE_4_PAYLOAD_MIN_LENGTH)
                            {
                                if (data_length == (guint32)(payload_size - ECPRI_MSG_TYPE_4_PAYLOAD_MIN_LENGTH))
                                {
                                    proto_tree_add_item(payload_tree, hf_data, tvb, offset, payload_size - ECPRI_MSG_TYPE_4_PAYLOAD_MIN_LENGTH, ENC_NA);
                                    offset += payload_size - ECPRI_MSG_TYPE_4_PAYLOAD_MIN_LENGTH;
                                }
                                else if (data_length < (guint32)(payload_size - ECPRI_MSG_TYPE_4_PAYLOAD_MIN_LENGTH))
                                {
                                    expert_add_info_format(pinfo, ti_data_length, &ei_data_length, "Data Length %d is too small, should be %d", data_length, payload_size - ECPRI_MSG_TYPE_4_PAYLOAD_MIN_LENGTH);
                                }
                                else
                                {
                                    expert_add_info_format(pinfo, ti_data_length, &ei_data_length, "Data Length %d is too big, should be %d", data_length, payload_size - ECPRI_MSG_TYPE_4_PAYLOAD_MIN_LENGTH);
                                }
                            }
                        }
                    }
                    else
                    {
                        expert_add_info_format(pinfo, ti_payload_size, &ei_payload_size, "Payload Size %d is too small for encoding Message Type %d. Should be min. %d", payload_size, msg_type, ECPRI_MSG_TYPE_4_PAYLOAD_MIN_LENGTH);
                    }
                    break;
                case ECPRI_MT_1WAY_DELAY:
                    /* 3.2.4.6 One-way Delay Measurement */
                    if (payload_size >= ECPRI_MSG_TYPE_5_PAYLOAD_MIN_LENGTH)
                    {
                        if (remaining_length >= ECPRI_MSG_TYPE_5_PAYLOAD_MIN_LENGTH)
                        {
                            proto_tree_add_item(payload_tree, hf_measurement_id, tvb, offset, 1, ENC_NA);
                            offset += 1;
                            proto_tree_add_item_ret_uint(payload_tree, hf_action_type, tvb, offset, 1, ENC_NA, &action_type);
                            offset += 1;
                            /* Time Stamp for seconds and nano-seconds */
                            timestamp_item = proto_tree_add_item(payload_tree, hf_timestamp, tvb, offset, 10, ENC_NA);
                            timestamp_tree = proto_item_add_subtree(timestamp_item, ett_ecpri_timestamp);
                            proto_tree_add_item_ret_uint64(timestamp_tree, hf_timestamp_sec, tvb, offset, 6, ENC_BIG_ENDIAN, &time_stamp_s);
                            offset += 6;
                            proto_tree_add_item_ret_uint(timestamp_tree, hf_timestamp_nanosec, tvb, offset, 4, ENC_BIG_ENDIAN, &time_stamp_ns);
                            offset += 4;
                            if (action_type >= ECPRI_MSG_TYPE_5_RESERVED_MIN)
                            {
                                expert_add_info_format(pinfo, timestamp_item, &ei_time_stamp, "Time stamp is not defined for Action Type %d", action_type);
                            }
                            else if (action_type != ECPRI_MSG_TYPE_5_REQ && action_type != ECPRI_MSG_TYPE_5_RESPONSE && action_type != ECPRI_MSG_TYPE_5_FOLLOWUP && time_stamp_s != 0x0000000000000000 && time_stamp_ns != 0x00000000)
                            {
                                expert_add_info_format(pinfo, timestamp_item, &ei_time_stamp, "Time stamp is not defined for Action Type %d, should be 0", action_type);
                            }
                            ti_comp_val = proto_tree_add_item_ret_uint64(payload_tree, hf_compensation_value, tvb, offset, 8, ENC_BIG_ENDIAN, &comp_val);
                            proto_item_append_text(ti_comp_val, " = %fns", comp_val / 65536.0);

                            if (action_type >= ECPRI_MSG_TYPE_5_RESERVED_MIN)
                            {
                                expert_add_info_format(pinfo, timestamp_item, &ei_time_stamp, "Compensation Value is not defined for Action Type %d", action_type);
                            }
                            else if (action_type != ECPRI_MSG_TYPE_5_REQ && action_type != ECPRI_MSG_TYPE_5_RESPONSE && action_type != ECPRI_MSG_TYPE_5_FOLLOWUP && comp_val != 0x0000000000000000)
                            {
                                expert_add_info_format(pinfo, ti_comp_val, &ei_comp_val, "Compensation Value is not defined for Action Type %d, should be 0", action_type);
                            }
                            offset += 8;
                            remaining_length -= ECPRI_MSG_TYPE_5_PAYLOAD_MIN_LENGTH;
                            if (remaining_length >= payload_size - ECPRI_MSG_TYPE_5_PAYLOAD_MIN_LENGTH)
                            {
                                proto_tree_add_item(payload_tree, hf_data, tvb, offset, payload_size - ECPRI_MSG_TYPE_5_PAYLOAD_MIN_LENGTH, ENC_NA);
                                offset += payload_size - ECPRI_MSG_TYPE_5_PAYLOAD_MIN_LENGTH;
                            }
                        }
                    }
                    else
                    {
                        expert_add_info_format(pinfo, ti_payload_size, &ei_payload_size, "Payload Size %d is too small for encoding Message Type %d. Should be min. %d", payload_size, msg_type, ECPRI_MSG_TYPE_5_PAYLOAD_MIN_LENGTH);
                    }
                    break;
                case ECPRI_MT_REM_RST:
                    /* Remote Reset */
                    if (payload_size >= ECPRI_MSG_TYPE_6_PAYLOAD_MIN_LENGTH)
                    {
                        if (remaining_length >= ECPRI_MSG_TYPE_6_PAYLOAD_MIN_LENGTH)
                        {
                            proto_tree_add_item(payload_tree, hf_reset_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                            offset += 2;
                            proto_tree_add_item(payload_tree, hf_reset_code, tvb, offset, 1, ENC_NA);
                            offset += 1;
                            remaining_length -= ECPRI_MSG_TYPE_6_PAYLOAD_MIN_LENGTH;
                            if (remaining_length >= payload_size - ECPRI_MSG_TYPE_6_PAYLOAD_MIN_LENGTH)
                            {
                                proto_tree_add_item(payload_tree, hf_data, tvb, offset, payload_size - ECPRI_MSG_TYPE_6_PAYLOAD_MIN_LENGTH, ENC_NA);
                                offset += payload_size - ECPRI_MSG_TYPE_6_PAYLOAD_MIN_LENGTH;
                            }
                        }
                    }
                    else
                    {
                        expert_add_info_format(pinfo, ti_payload_size, &ei_payload_size, "Payload Size %d is too small for encoding Message Type %d. Should be min. %d", payload_size, msg_type, ECPRI_MSG_TYPE_6_PAYLOAD_MIN_LENGTH);
                    }
                    break;
                case ECPRI_MT_EVT_IND:
                    /* Event Indication */
                    if (payload_size >= ECPRI_MSG_TYPE_7_PAYLOAD_MIN_LENGTH)
                    {
                        if (remaining_length >= ECPRI_MSG_TYPE_7_PAYLOAD_MIN_LENGTH)
                        {
                            proto_tree_add_item(payload_tree, hf_event_id, tvb, offset, 1, ENC_NA);
                            offset += 1;
                            proto_tree_add_item_ret_uint(payload_tree, hf_event_type, tvb, offset, 1, ENC_NA, &event_type);
                            offset += 1;
                            proto_tree_add_item(payload_tree, hf_sequence_num, tvb, offset, 1, ENC_NA);
                            offset += 1;
                            ti_num_faults = proto_tree_add_item_ret_uint(payload_tree, hf_number_faults_notif, tvb, offset, 1, ENC_NA, &num_faults_notif);
                            offset += 1;
                            /* Only for Event Type Fault Indication (0x00) and Notification Indication (0x02) */
                            if (event_type == ECPRI_MSG_TYPE_7_FAULT_INDICATION || event_type == ECPRI_MSG_TYPE_7_NOTIF_INDICATION)
                            {
                                /* These two Event Types should have notifications or faults */
                                if (num_faults_notif > 0)
                                {
                                    /* Check Size of Elements */
                                    if (payload_size == ECPRI_MSG_TYPE_7_PAYLOAD_MIN_LENGTH + num_faults_notif * ECPRI_MSG_TYPE_7_ELEMENT_SIZE)
                                    {
                                        /* Dissect elements in loop */
                                        for (guint32 i = 0; i < num_faults_notif; i++)
                                        {
                                            element_item = proto_tree_add_item(payload_tree, hf_element, tvb, offset, ECPRI_MSG_TYPE_7_ELEMENT_SIZE, ENC_NA);
                                            proto_item_prepend_text(element_item, "#%d: ", i + 1);
                                            element_tree =proto_item_add_subtree(element_item, ett_ecpri_element);

                                            proto_tree_add_item(element_tree, hf_element_id2, tvb, offset, 2, ENC_BIG_ENDIAN);
                                            offset += 2;
                                            proto_tree_add_item(element_tree, hf_raise_cease, tvb, offset, 1, ENC_NA);
                                            ti_fault_notif = proto_tree_add_item_ret_uint(element_tree, hf_fault_notif, tvb, offset, 2, ENC_BIG_ENDIAN, &fault_notif);
                                            /* Faults and Notifications cannot be mixed */
                                            if (event_type == ECPRI_MSG_TYPE_7_FAULT_INDICATION && !((fault_notif <= ECPRI_MSG_TYPE_7_FAULTS_MAX) || (fault_notif >= ECPRI_MSG_TYPE_7_VENDOR_MIN && fault_notif <= ECPRI_MSG_TYPE_7_VENDOR_MAX)))
                                            {
                                                expert_add_info_format(pinfo, ti_fault_notif, &ei_fault_notif, "Only Faults are permitted with Event Type Faults Indication (0x%.2X)", event_type);
                                            }
                                            else if (event_type == ECPRI_MSG_TYPE_7_NOTIF_INDICATION && !((fault_notif >= ECPRI_MSG_TYPE_7_NOTIF_MIN && fault_notif <= ECPRI_MSG_TYPE_7_NOTIF_MAX) || (fault_notif >= ECPRI_MSG_TYPE_7_VENDOR_MIN && fault_notif <= ECPRI_MSG_TYPE_7_VENDOR_MAX)))
                                            {
                                                expert_add_info_format(pinfo, ti_fault_notif, &ei_fault_notif, "Only Notifications are permitted with Event Type Notifications Indication (0x%.2X)", event_type);
                                            }
                                            offset += 2;
                                            proto_tree_add_item(element_tree, hf_add_info, tvb, offset, 4, ENC_BIG_ENDIAN);
                                            offset += 4;
                                        }
                                    }
                                    else if (payload_size < ECPRI_MSG_TYPE_7_PAYLOAD_MIN_LENGTH + num_faults_notif * ECPRI_MSG_TYPE_7_ELEMENT_SIZE)
                                    {
                                        expert_add_info_format(pinfo, ti_num_faults, &ei_number_faults, "Number of Faults/Notif %d is maybe too big", num_faults_notif);
                                        expert_add_info_format(pinfo, ti_payload_size, &ei_payload_size, "Payload Size is maybe too small");
                                    }
                                    else
                                    {
                                        expert_add_info_format(pinfo, ti_num_faults, &ei_number_faults, "Number of Faults/Notif %d is maybe too small", num_faults_notif);
                                        expert_add_info_format(pinfo, ti_payload_size, &ei_payload_size, "Payload Size is maybe too big");
                                    }
                                }
                                else
                                {
                                    expert_add_info_format(pinfo, ti_num_faults, &ei_number_faults, "Number of Faults/Notif %d should be > 0", num_faults_notif);
                                }
                            }
                            else if (event_type == ECPRI_MSG_TYPE_7_FAULT_INDICATION_ACK || event_type == ECPRI_MSG_TYPE_7_SYNC_REQUEST || event_type == ECPRI_MSG_TYPE_7_SYNC_ACK || event_type == ECPRI_MSG_TYPE_7_SYNC_END_INDICATION)
                            {
                                /* Number of Faults/Notifs should be 0, only 4 Byte possible*/
                                if (payload_size > 4)
                                {
                                    expert_add_info_format(pinfo, ti_payload_size, &ei_payload_size, "Payload Size %d should be 4", payload_size);
                                }
                                /* These Event Types shouldn't have faults or notifications */
                                if (num_faults_notif != 0)
                                {
                                    expert_add_info_format(pinfo, ti_num_faults, &ei_number_faults, "Number of Faults/Notif %d should be 0", num_faults_notif);
                                }
                            }
                            else
                            {
                                /* These Event Types are reserved, don't know how to decode */
                                if (num_faults_notif != 0)
                                {
                                    expert_add_info_format(pinfo, ti_num_faults, &ei_number_faults, "Number of Faults/Notif %d, but no knowledge about encoding, because Event Type is reserved.", num_faults_notif);
                                }
                            }
                        }
                    }
                    else
                    {
                        /* Minimal Length is bigger then actual Payload Size */
                        expert_add_info_format(pinfo, ti_payload_size, &ei_payload_size, "Payload Size %d is too small for encoding Message Type %d. Should be min. %d", payload_size, msg_type, ECPRI_MSG_TYPE_7_PAYLOAD_MIN_LENGTH);
                    }
                    break;
                case ECPRI_MT_IWF_STARTUP:
                    /* 3.2.4.9 IWF Start-Up */
                case ECRPI_MT_IWF_OP:
                    /* 3.2.4.10 IWF Operation */
                case ECRPI_MT_IWF_MAPPING:
                    /* 3.2.4.11 IWF Mapping */
                case ECRPI_MT_IWF_DELAY_CONTROL:
                    /* 3.2.4.12 IWF Delay Control */
                    proto_tree_add_expert(payload_tree, pinfo, &ei_ecpri_not_dis_yet, tvb, offset, -1);
                    break;

                default:
                    /* Reserved or Vendor Specific */
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
    } while (concatenation != 0 && reported_length - offset >= ECPRI_HEADER_LENGTH);
    if (concatenation != 0)
        expert_add_info_format(pinfo, ti_c_bit, &ei_c_bit, "Concatenation Bit is 1, should be 0");

    /* Not dissected buffer */
    if (offset != 0)
    {
        next_tvb = tvb_new_subset_remaining(tvb, offset);
        call_data_dissector(next_tvb, pinfo, tree);
    }

    return reported_length;
}

void proto_register_ecpri(void)
{
    static hf_register_info hf[] = {
        /* eCPRI Common Header */
            { &hf_header,    { "eCPRI Common Header", "ecpri.header",   FT_UINT32, BASE_HEX,                   NULL,                   0x00, NULL, HFILL } },
            { &hf_proto_rev, { "Protocol Revision",   "ecpri.revision", FT_UINT8,  BASE_DEC,                   NULL,                   0xF0, NULL, HFILL } },
            { &hf_reserved,  { "Reserved",            "ecpri.reserved", FT_UINT8,  BASE_DEC,                   NULL,                   0x0E, NULL, HFILL } },
            { &hf_c_bit,     { "C-Bit",               "ecpri.cbit",     FT_UINT8,  BASE_DEC,                   NULL,                   0x01, NULL, HFILL } },
            { &hf_msg_type,  { "Message Type",        "ecpri.type",     FT_UINT8,  BASE_HEX|BASE_RANGE_STRING, RVALS(ecpri_msg_types), 0x00, NULL, HFILL } },
            { &hf_payload_size, { "Payload Size",     "ecpri.size",     FT_UINT16, BASE_DEC,                   NULL,                   0x00, NULL, HFILL } },
        /* eCPRI Payload */
            { &hf_payload,   { "eCPRI Payload",       "ecpri.payload",  FT_BYTES,  SEP_COLON, NULL, 0x00, NULL, HFILL } },
            /* Message Type 0 and 1: IQ Data and Bit Sequence */
            { &hf_pc_id,     { "PC_ID",               "ecpri.pcid",     FT_UINT16, BASE_HEX,  NULL, 0x00, NULL, HFILL } },
            /* Message Type 0, 1 and 2: IQ Data, Bit Sequence and Real-Time Control Data */
            { &hf_seq_id,    { "SEQ_ID",              "ecpri.seqid",    FT_UINT16, BASE_HEX,  NULL, 0x00, NULL, HFILL } },
            /* Message Type 2: Real-Time Control Data */
            { &hf_rtc_id,    { "RTC_ID",              "ecpri.rtcid",    FT_UINT16, BASE_HEX,  NULL, 0x00, NULL, HFILL } },
            /* Message Type 3: Generic Data Transfer */
            { &hf_pc_id2,    { "PC_ID",               "ecpri.pcid",     FT_UINT32, BASE_HEX,  NULL, 0x00, NULL, HFILL } },
            { &hf_seq_id2,   { "SEQ_ID",              "ecpri.seqid",    FT_UINT32, BASE_HEX,  NULL, 0x00, NULL, HFILL } },
            /* Message Type 4: Remote Memory Access */
            { &hf_rma_id,      { "Remote Memory Access ID", "ecpri.rmaid",     FT_UINT8,  BASE_HEX,  NULL,                          0x00, NULL, HFILL } },
            { &hf_read_write,  { "Read/Write",              "ecpri.rw",        FT_UINT8,  BASE_HEX,  VALS(read_write_coding),       0xF0, NULL, HFILL } },
            { &hf_request_response, { "Request/Response",   "ecpri.reqresp",   FT_UINT8,  BASE_HEX,  VALS(request_response_coding), 0x0F, NULL, HFILL } },
            { &hf_element_id,  { "Element ID",              "ecpri.elementid", FT_UINT16, BASE_HEX,  NULL,                          0x00, NULL, HFILL } },
            { &hf_address,     { "Address",                 "ecpri.address",   FT_BYTES,  SEP_COLON, NULL,                          0x00, NULL, HFILL } },
            { &hf_data_length, { "Data Length",             "ecpri.length",    FT_UINT16, BASE_DEC,  NULL,                          0x00, NULL, HFILL } },
            /* Message Type 5: One-way Delay Measurement */
            { &hf_measurement_id, { "Measurement ID",  "ecpri.measurementid",  FT_UINT8,  BASE_HEX,                  NULL,               0x00, NULL, HFILL } },
            { &hf_action_type,        { "Action Type", "ecpri.actiontype",     FT_UINT8,  BASE_HEX|BASE_RANGE_STRING, RVALS(action_type_coding), 0x00, NULL, HFILL } },
            { &hf_timestamp,          { "Time Stamp",  "ecpri.timestamp",      FT_BYTES,  SEP_COLON,                 NULL,               0x00, NULL, HFILL } },
            { &hf_timestamp_sec,      { "Seconds",     "ecpri.sec",            FT_UINT48, BASE_DEC|BASE_UNIT_STRING, &units_seconds,     0x00, NULL, HFILL } },
            { &hf_timestamp_nanosec,  { "Nanoseconds", "ecpri.nanosec",        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_nanoseconds, 0x00, NULL, HFILL } },
            { &hf_compensation_value, { "Compensation Value", "ecpri.compval", FT_UINT64, BASE_DEC,                  NULL,               0x00, NULL, HFILL } },
            /* Message Type 6: Remote Reset */
            { &hf_reset_id,     { "Reset ID",       "ecpri.resetid",   FT_UINT16,  BASE_HEX,                   NULL,                   0x00,     NULL, HFILL } },
            { &hf_reset_code,   { "Reset Code Op",  "ecpri.resetcode", FT_UINT8,   BASE_HEX|BASE_RANGE_STRING, RVALS(reset_coding),    0x00,     NULL, HFILL } },
            /* Message Type 7: Event Indication */
            { &hf_event_id,     { "Event ID",               "ecpri.eventid",    FT_UINT8,  BASE_HEX,                     NULL,                     0x00, NULL, HFILL } },
            { &hf_event_type,   { "Event Type",             "ecpri.eventtype",  FT_UINT8,  BASE_HEX|BASE_RANGE_STRING,   RVALS(event_type_coding), 0x00, NULL, HFILL } },
            { &hf_sequence_num, { "Sequence Number",        "ecpri.seqnum",     FT_UINT8,  BASE_DEC,                     NULL,                     0x00, NULL, HFILL } },
            { &hf_number_faults_notif, { "Number of Faults/Notifications", "ecpri.numberfaultnotif", FT_UINT8, BASE_DEC, NULL,                     0x00, NULL, HFILL } },
            { &hf_element,      { "Element",                "ecpri.element",    FT_BYTES,  SEP_COLON,                    NULL,                     0x00, NULL, HFILL } },
            { &hf_element_id2,  { "Element ID",             "ecpri.elementid",  FT_UINT16, BASE_HEX|BASE_RANGE_STRING,   RVALS(element_id_coding), 0x00, NULL, HFILL } },
            { &hf_raise_cease,  { "Raise/Cease",            "ecpri.raisecease", FT_UINT8,  BASE_HEX,                     VALS(raise_ceased_coding), 0xF0, NULL, HFILL } },
            { &hf_fault_notif,  { "Fault/Notification",     "ecpri.faultnotif", FT_UINT16, BASE_HEX|BASE_RANGE_STRING,   RVALS(fault_notif_coding), 0x0FFF, NULL, HFILL } },
            { &hf_add_info,     { "Additional Information", "ecpri.addinfo",    FT_UINT32, BASE_HEX,                     NULL,                     0x00, NULL, HFILL } },
            /* Rest of Payload */
            { &hf_data,         { "User Data",  "ecpri.data",   FT_BYTES,   SEP_COLON,  NULL,   0x00,   NULL,   HFILL } }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
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
            { &ei_ecpri_not_dis_yet,    { "ecpri.not_dissected_yet",    PI_PROTOCOL, PI_NOTE,  "Not dissected yet",   EXPFILL }}
    };

    expert_module_t* expert_ecpri;
    module_t* module_message_decoding;

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
    module_message_decoding = prefs_register_protocol( proto_ecpri, NULL);
    /* If not set, it shows which message type was used, but no decoding of payload */
    prefs_register_bool_preference(module_message_decoding,
            "ecpripref.msg.decoding",
            "Decode Message Type",
            "Decode the Message Types according to eCPRI Specification V1.2",
    &message_type_decoding);
}

void proto_reg_handoff_ecpri(void)
{
    dissector_add_uint("ethertype", ETHERTYPE_ECPRI, ecpri_handle);             /* Ethertypes 0xAEFE */
    dissector_add_uint_range_with_preference("udp.port", "", ecpri_handle);     /* UDP Port Preference */

    oran_handle = find_dissector("oran_fh_cus");
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
