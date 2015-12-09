/*
 * packet-rtcdc.c
 * Routines for the RTCWeb Data Channel Protocol dissection
 * as specified in
 * http://tools.ietf.org/html/draft-jesup-rtcweb-data-protocol-03
 * and specified in
 * http://tools.ietf.org/html/draft-ietf-rtcweb-data-protocol-08
 * We might want to remove the support of
 * http://tools.ietf.org/html/draft-jesup-rtcweb-data-protocol-03
 * in the future, but I'll leave it in for now.
 * Copyright 2012 - 2013, Michael Tuexen <tuexen@wireshark.org>
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

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/sctpppids.h>

void proto_register_rtcdc(void);
void proto_reg_handoff_rtcdc(void);

/* PPID used for this protocol */
static guint32 rtcdc_ppid = WEBRTC_DCEP_PROTOCOL_ID;

/* Initialize the protocol and registered fields */
static int proto_rtcdc = -1;
static int hf_message_type = -1;
static int hf_channel_type = -1;
static int hf_flags = -1;
static int hf_flags_reserved = -1;
static int hf_unordered_allowed = -1;
static int hf_reliability = -1;
static int hf_priority = -1;
static int hf_label = -1;
static int hf_error = -1;
static int hf_sid = -1;
static int hf_new_channel_type = -1;
static int hf_new_reliability = -1;
static int hf_new_priority = -1;
static int hf_new_label_length = -1;
static int hf_new_protocol_length = -1;
static int hf_new_label = -1;
static int hf_new_protocol = -1;

/* Initialize the subtree pointers */
static gint ett_rtcdc = -1;
static gint ett_flags = -1;

static expert_field ei_rtcdc_new_reliability_non_zero = EI_INIT;
static expert_field ei_rtcdc_message_type_unknown = EI_INIT;
static expert_field ei_rtcdc_inconsistent_label_and_parameter_length = EI_INIT;
static expert_field ei_rtcdc_message_too_long = EI_INIT;
static expert_field ei_rtcdc_new_channel_type = EI_INIT;

#define DATA_CHANNEL_OPEN_REQUEST     0x00
#define DATA_CHANNEL_OPEN_RESPONSE    0x01
#define DATA_CHANNEL_ACK              0x02
#define DATA_CHANNEL_NEW_OPEN_REQUEST 0x03

static const value_string message_type_values[] = {
    { DATA_CHANNEL_OPEN_REQUEST,     "DATA_CHANNEL_OPEN_REQUEST"  },
    { DATA_CHANNEL_OPEN_RESPONSE,    "DATA_CHANNEL_OPEN_RESPONSE" },
    { DATA_CHANNEL_ACK,              "DATA_CHANNEL_ACK"           },
    { DATA_CHANNEL_NEW_OPEN_REQUEST, "DATA_CHANNEL_OPEN_REQUEST"  },
    { 0,                             NULL                         }
};

#define DATA_CHANNEL_RELIABLE                0x00
#define DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT 0x01
#define DATA_CHANNEL_PARTIAL_RELIABLE_TIMED  0x02

static const value_string channel_type_values[] = {
    { DATA_CHANNEL_RELIABLE,                "DATA_CHANNEL_RELIABLE"                },
    { DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT, "DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT" },
    { DATA_CHANNEL_PARTIAL_RELIABLE_TIMED,  "DATA_CHANNEL_PARTIAL_RELIABLE_TIMED"  },
    { 0,                                    NULL                                   }
};

#define MESSAGE_TYPE_LENGTH 1
#define CHANNEL_TYPE_LENGTH 1
#define FLAGS_LENGTH        2
#define RELIABILITY_LENGTH  2
#define PRIORITY_LENGTH     2

#define MESSAGE_TYPE_OFFSET 0
#define CHANNEL_TYPE_OFFSET (MESSAGE_TYPE_OFFSET + MESSAGE_TYPE_LENGTH)
#define FLAGS_OFFSET        (CHANNEL_TYPE_OFFSET + CHANNEL_TYPE_LENGTH)
#define RELIABILITY_OFFSET  (FLAGS_OFFSET + FLAGS_LENGTH)
#define PRIORITY_OFFSET     (RELIABILITY_OFFSET + RELIABILITY_LENGTH)
#define LABEL_OFFSET        (PRIORITY_OFFSET + PRIORITY_LENGTH)

#define DATA_CHANNEL_FLAG_OUT_OF_ORDER_ALLOWED_MASK 0x0001
#define DATA_CHANNEL_FLAG_RESERVED_MASK             0xFFFE

static void
dissect_open_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *rtcdc_tree, proto_item *rtcdc_item _U_)
{
    if (rtcdc_tree) {
        proto_tree *flags_tree;
        proto_item *flags_item;

        proto_tree_add_item(rtcdc_tree, hf_channel_type, tvb, CHANNEL_TYPE_OFFSET, CHANNEL_TYPE_LENGTH, ENC_BIG_ENDIAN);
        flags_item = proto_tree_add_item(rtcdc_tree, hf_flags, tvb, FLAGS_OFFSET, FLAGS_LENGTH, ENC_BIG_ENDIAN);
        flags_tree = proto_item_add_subtree(flags_item, ett_flags);
        proto_tree_add_item(flags_tree, hf_flags_reserved, tvb, FLAGS_OFFSET, FLAGS_LENGTH, ENC_BIG_ENDIAN);
        proto_tree_add_item(flags_tree, hf_unordered_allowed, tvb, FLAGS_OFFSET, FLAGS_LENGTH, ENC_BIG_ENDIAN);
        proto_tree_add_item(rtcdc_tree, hf_reliability, tvb, RELIABILITY_OFFSET, RELIABILITY_LENGTH, ENC_BIG_ENDIAN);
        proto_tree_add_item(rtcdc_tree, hf_priority, tvb, PRIORITY_OFFSET, PRIORITY_LENGTH, ENC_BIG_ENDIAN);
        proto_tree_add_item(rtcdc_tree, hf_label, tvb, LABEL_OFFSET, -1, ENC_ASCII|ENC_NA);
    }
    return;
}

#define ERROR_LENGTH                 1
#define SID_LENGTH                   2
#define DATA_CHANNEL_RESPONSE_LENGTH (MESSAGE_TYPE_LENGTH + ERROR_LENGTH + FLAGS_LENGTH + SID_LENGTH)

#define ERROR_OFFSET                 (MESSAGE_TYPE_OFFSET + MESSAGE_TYPE_LENGTH)
#define SID_OFFSET                   (FLAGS_OFFSET + FLAGS_LENGTH)

static void
dissect_open_response_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *rtcdc_tree, proto_item *rtcdc_item)
{
    if (tvb_reported_length(tvb) > DATA_CHANNEL_RESPONSE_LENGTH) {
        expert_add_info(pinfo, rtcdc_item, &ei_rtcdc_message_too_long);
    }
    if (rtcdc_tree) {
        proto_tree_add_item(rtcdc_tree, hf_error, tvb, ERROR_OFFSET, ERROR_LENGTH, ENC_BIG_ENDIAN);
        proto_tree_add_item(rtcdc_tree, hf_flags, tvb, FLAGS_OFFSET, FLAGS_LENGTH, ENC_BIG_ENDIAN);
        proto_tree_add_item(rtcdc_tree, hf_sid, tvb, SID_OFFSET, SID_LENGTH, ENC_BIG_ENDIAN);
    }
    return;
}

#define DATA_CHANNEL_ACK_LENGTH MESSAGE_TYPE_LENGTH

static void
dissect_open_ack_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *rtcdc_tree _U_, proto_item *rtcdc_item)
{
    if (tvb_reported_length(tvb) > DATA_CHANNEL_ACK_LENGTH) {
        expert_add_info(pinfo, rtcdc_item, &ei_rtcdc_message_too_long);
    }
    return;
}

#define NEW_DATA_CHANNEL_RELIABLE                          0x00
#define NEW_DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT           0x01
#define NEW_DATA_CHANNEL_PARTIAL_RELIABLE_TIMED            0x02
#define NEW_DATA_CHANNEL_RELIABLE_UNORDERED                0x80
#define NEW_DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED 0x81
#define NEW_DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED  0x82

static const value_string new_channel_type_values[] = {
    { NEW_DATA_CHANNEL_RELIABLE,                          "DATA_CHANNEL_RELIABLE"                          },
    { NEW_DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT,           "DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT"           },
    { NEW_DATA_CHANNEL_PARTIAL_RELIABLE_TIMED,            "DATA_CHANNEL_PARTIAL_RELIABLE_TIMED"            },
    { NEW_DATA_CHANNEL_RELIABLE_UNORDERED,                "DATA_CHANNEL_RELIABLE_UNORDERED"                },
    { NEW_DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED, "DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED" },
    { NEW_DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED,  "DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED"  },
    { 0,                                                  NULL                                             }
};

#define NEW_MESSAGE_TYPE_LENGTH    1
#define NEW_CHANNEL_TYPE_LENGTH    1
#define NEW_PRIORITY_LENGTH        2
#define NEW_RELIABILITY_LENGTH     4
#define NEW_LABEL_LENGTH_LENGTH    2
#define NEW_PROTOCOL_LENGTH_LENGTH 2
#define NEW_OPEN_REQUEST_HEADER_LENGTH (guint)(NEW_MESSAGE_TYPE_LENGTH + \
                                               NEW_CHANNEL_TYPE_LENGTH + \
                                               NEW_PRIORITY_LENGTH +    \
                                               NEW_RELIABILITY_LENGTH + \
                                               NEW_LABEL_LENGTH_LENGTH + \
                                               NEW_PROTOCOL_LENGTH_LENGTH)

#define NEW_MESSAGE_TYPE_OFFSET    0
#define NEW_CHANNEL_TYPE_OFFSET    (NEW_MESSAGE_TYPE_OFFSET + NEW_MESSAGE_TYPE_LENGTH)
#define NEW_PRIORITY_OFFSET        (NEW_CHANNEL_TYPE_OFFSET + NEW_CHANNEL_TYPE_LENGTH)
#define NEW_RELIABILITY_OFFSET     (NEW_PRIORITY_OFFSET + NEW_PRIORITY_LENGTH)
#define NEW_LABEL_LENGTH_OFFSET    (NEW_RELIABILITY_OFFSET + NEW_RELIABILITY_LENGTH)
#define NEW_PROTOCOL_LENGTH_OFFSET (NEW_LABEL_LENGTH_OFFSET + NEW_LABEL_LENGTH_LENGTH)
#define NEW_LABEL_OFFSET           (NEW_PROTOCOL_LENGTH_OFFSET + NEW_PROTOCOL_LENGTH_LENGTH)

static void
dissect_new_open_request_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *rtcdc_tree, proto_item *rtcdc_item)
{
    guint8  channel_type;
    guint32 reliability;
    guint16 label_length;
    guint16 protocol_length;

    channel_type = tvb_get_guint8(tvb, NEW_CHANNEL_TYPE_OFFSET);
    if ((channel_type & 0x7f) > 0x02) {
        expert_add_info(pinfo, rtcdc_item, &ei_rtcdc_new_channel_type);
    }
    reliability = tvb_get_ntohl(tvb, NEW_RELIABILITY_OFFSET);
    if ((reliability > 0) && ((channel_type & 0x7f) == 0x00)) {
        expert_add_info(pinfo, rtcdc_item, &ei_rtcdc_new_reliability_non_zero);
    }
    label_length = tvb_get_ntohs(tvb, NEW_LABEL_LENGTH_OFFSET);
    protocol_length = tvb_get_ntohs(tvb, NEW_PROTOCOL_LENGTH_OFFSET);
    if (NEW_OPEN_REQUEST_HEADER_LENGTH + (guint)label_length + (guint)protocol_length != tvb_reported_length(tvb)) {
        expert_add_info(pinfo, rtcdc_item, &ei_rtcdc_inconsistent_label_and_parameter_length);
    }
    if (rtcdc_tree) {
        proto_tree_add_item(rtcdc_tree, hf_new_channel_type, tvb, NEW_CHANNEL_TYPE_OFFSET, NEW_CHANNEL_TYPE_LENGTH, ENC_BIG_ENDIAN);
        proto_tree_add_item(rtcdc_tree, hf_new_priority, tvb, NEW_PRIORITY_OFFSET, NEW_PRIORITY_LENGTH, ENC_BIG_ENDIAN);
        proto_tree_add_item(rtcdc_tree, hf_new_reliability, tvb, NEW_RELIABILITY_OFFSET, NEW_RELIABILITY_LENGTH, ENC_BIG_ENDIAN);
        proto_tree_add_item(rtcdc_tree, hf_new_label_length, tvb, NEW_LABEL_LENGTH_OFFSET, NEW_LABEL_LENGTH_LENGTH, ENC_BIG_ENDIAN);
        proto_tree_add_item(rtcdc_tree, hf_new_protocol_length, tvb, NEW_PROTOCOL_LENGTH_OFFSET, NEW_PROTOCOL_LENGTH_LENGTH, ENC_BIG_ENDIAN);
        proto_tree_add_item(rtcdc_tree, hf_new_label, tvb, NEW_LABEL_OFFSET, label_length, ENC_ASCII|ENC_NA);
        proto_tree_add_item(rtcdc_tree, hf_new_protocol, tvb, NEW_LABEL_OFFSET + label_length, protocol_length, ENC_ASCII|ENC_NA);
    }
    return;
}

static int
dissect_rtcdc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *rtcdc_item, *msg_item;
    proto_tree *rtcdc_tree;
    guint8      message_type;

    message_type  = tvb_get_guint8(tvb, MESSAGE_TYPE_OFFSET);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTCDC");
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str_const(message_type, message_type_values, "reserved"));
    rtcdc_item = proto_tree_add_item(tree, proto_rtcdc, tvb, 0, -1, ENC_NA);
    rtcdc_tree = proto_item_add_subtree(rtcdc_item, ett_rtcdc);
    msg_item   = proto_tree_add_item(rtcdc_tree, hf_message_type, tvb, MESSAGE_TYPE_OFFSET, MESSAGE_TYPE_LENGTH, ENC_BIG_ENDIAN);

    switch (message_type) {
        case DATA_CHANNEL_OPEN_REQUEST:
            dissect_open_request_message(tvb, pinfo, rtcdc_tree, rtcdc_item);
            break;
        case DATA_CHANNEL_OPEN_RESPONSE:
            dissect_open_response_message(tvb, pinfo, rtcdc_tree, rtcdc_item);
            break;
        case DATA_CHANNEL_ACK:
            dissect_open_ack_message(tvb, pinfo, rtcdc_tree, rtcdc_item);
            break;
        case DATA_CHANNEL_NEW_OPEN_REQUEST:
            dissect_new_open_request_message(tvb, pinfo, rtcdc_tree, rtcdc_item);
            break;
        default:
            expert_add_info(pinfo, msg_item, &ei_rtcdc_message_type_unknown);
            break;
    }
    return tvb_captured_length(tvb);
}

void
proto_register_rtcdc(void)
{
    module_t        *rtcdc_module;
    expert_module_t *expert_rtcdc;

    static hf_register_info hf[] = {
        { &hf_message_type,
          { "Message type", "rtcdc.message_type",
            FT_UINT8, BASE_DEC, VALS(message_type_values), 0x0,
            NULL, HFILL }
        },
        { &hf_channel_type,
          { "Channel type", "rtcdc.channel_type",
            FT_UINT8, BASE_DEC, VALS(channel_type_values), 0x0,
            NULL, HFILL }
        },
        { &hf_flags,
          { "Flags", "rtcdc.flags",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_flags_reserved,
          { "Reserved", "rtcdc.flags_reserved",
            FT_UINT16, BASE_HEX, NULL, DATA_CHANNEL_FLAG_RESERVED_MASK,
            NULL, HFILL }
        },
        { &hf_unordered_allowed,
          { "Unordered allowed", "rtcdc.flags_unordered_allowed",
            FT_BOOLEAN, 16, NULL, DATA_CHANNEL_FLAG_OUT_OF_ORDER_ALLOWED_MASK,
            NULL, HFILL }
        },
        { &hf_reliability,
          { "Reliability parameter", "rtcdc.reliability_parameter",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_priority,
          { "Priority", "rtcdc.priority",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_label,
          { "Label", "rtcdc.label",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_error,
          { "Error", "rtcdc.error",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_sid,
          { "Reverse stream identifier", "rtcdc.reverse_stream_id",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_new_channel_type,
          { "Channel type", "rtcdc.channel_type",
            FT_UINT8, BASE_DEC, VALS(new_channel_type_values), 0x0,
            NULL, HFILL }
        },
        { &hf_new_reliability,
          { "Reliability parameter", "rtcdc.reliability_parameter",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_new_priority,
          { "Priority", "rtcdc.priority",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_new_label_length,
          { "Label length", "rtcdc.label_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_new_protocol_length,
          { "Protocol length", "rtcdc.protocol_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_new_label,
          { "Label", "rtcdc.label",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_new_protocol,
          { "Protocol", "rtcdc.protocol",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        }
    };
    static gint *ett[] = {
        &ett_rtcdc,
        &ett_flags
    };

    static ei_register_info ei[] = {
        { &ei_rtcdc_message_too_long, { "rtcdc.message_too_long", PI_MALFORMED, PI_ERROR, "Message too long", EXPFILL }},
        { &ei_rtcdc_new_channel_type, { "rtcdc.channel_type.unknown", PI_PROTOCOL, PI_WARN, "Unknown channel type", EXPFILL }},
        { &ei_rtcdc_new_reliability_non_zero, { "rtcdc.reliability_parameter.non_zero", PI_PROTOCOL, PI_WARN, "Reliability parameter non zero for reliable channel", EXPFILL }},
        { &ei_rtcdc_inconsistent_label_and_parameter_length, { "rtcdc.inconsistent_label_and_parameter_length", PI_MALFORMED, PI_ERROR, "Inconsistent label and parameter length", EXPFILL }},
        { &ei_rtcdc_message_type_unknown, { "rtcdc.message_type.unknown", PI_PROTOCOL, PI_WARN, "Unknown message type", EXPFILL }},
    };

    proto_rtcdc = proto_register_protocol("WebRTC Datachannel Protocol", "RTCDC", "rtcdc");
    proto_register_field_array(proto_rtcdc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_rtcdc = expert_register_protocol(proto_rtcdc);
    expert_register_field_array(expert_rtcdc, ei, array_length(ei));
    rtcdc_module = prefs_register_protocol(proto_rtcdc, proto_reg_handoff_rtcdc);
    prefs_register_uint_preference(rtcdc_module, "sctp.ppi", "RTCDC SCTP PPID", "RTCDC SCTP PPID if other than the default", 10, &rtcdc_ppid);
}

void
proto_reg_handoff_rtcdc(void)
{
    static gboolean           initialized = FALSE;
    static dissector_handle_t rtcdc_handle;
    static guint32            current_ppid;

    if (!initialized) {
        rtcdc_handle = create_dissector_handle(dissect_rtcdc, proto_rtcdc);
        initialized = TRUE;
    } else {
        dissector_delete_uint("sctp.ppi", current_ppid, rtcdc_handle);
    }
    current_ppid = rtcdc_ppid;
    dissector_add_uint("sctp.ppi", current_ppid, rtcdc_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
