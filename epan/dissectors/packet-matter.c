/* packet-matter.c
 * Routines for Matter IoT protocol dissection
 * Copyright 2023, Nicolás Alvarez <nicolas.alvarez@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * The Matter protocol provides an interoperable application
 * layer solution for smart home devices over IPv6.
 *
 * The specification can be freely requested at:
 * https://csa-iot.org/developer-resource/specifications-download-request/
 */

#include <config.h>

#include <epan/packet.h>

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_matter(void);
void proto_register_matter(void);

/* Initialize the protocol and registered fields */
static dissector_handle_t matter_handle;

static int proto_matter = -1;
static int hf_message_flags = -1;
static int hf_message_version = -1;
static int hf_message_has_source = -1;
static int hf_message_dsiz = -1;
static int hf_message_session_id = -1;
static int hf_message_security_flags = -1;
static int hf_message_flag_privacy = -1;
static int hf_message_flag_control = -1;
static int hf_message_flag_extensions = -1;
static int hf_message_session_type = -1;
static int hf_message_counter = -1;
static int hf_message_src_id = -1;
static int hf_message_dest_id = -1;
static int hf_message_privacy_header = -1;

static int hf_payload = -1;
static int hf_payload_exchange_flags = -1;
static int hf_payload_flag_initiator = -1;
static int hf_payload_flag_ack = -1;
static int hf_payload_flag_reliability = -1;
static int hf_payload_flag_secured_extensions = -1;
static int hf_payload_flag_vendor = -1;
static int hf_payload_protocol_opcode = -1;
static int hf_payload_exchange_id = -1;
static int hf_payload_protocol_vendor_id = -1;
static int hf_payload_protocol_id = -1;
static int hf_payload_ack_counter = -1;
static int hf_payload_secured_ext_length = -1;
static int hf_payload_secured_ext = -1;
static int hf_payload_application = -1;

static gint ett_matter = -1;
static gint ett_message_flags = -1;
static gint ett_security_flags = -1;
static gint ett_payload = -1;
static gint ett_exchange_flags = -1;

/* message flags + session ID + security flags + counter */
#define MATTER_MIN_LENGTH 8

#define MESSAGE_FLAG_VERSION_MASK       0xF0
#define MESSAGE_FLAG_HAS_SOURCE         0x04
#define MESSAGE_FLAG_HAS_DEST_NODE      0x01
#define MESSAGE_FLAG_HAS_DEST_GROUP     0x02
#define MESSAGE_FLAG_DSIZ_MASK          0x03

#define SECURITY_FLAG_HAS_PRIVACY       0x80
#define SECURITY_FLAG_IS_CONTROL        0x40
#define SECURITY_FLAG_HAS_EXTENSIONS    0x20
#define SECURITY_FLAG_SESSION_TYPE_MASK 0x03

#define EXCHANGE_FLAG_IS_INITIATOR      0x01
#define EXCHANGE_FLAG_ACK_MSG           0x02
#define EXCHANGE_FLAG_RELIABILITY       0x04
#define EXCHANGE_FLAG_HAS_SECURED_EXT   0x08
#define EXCHANGE_FLAG_HAS_VENDOR_PROTO  0x10

static const value_string dsiz_vals[] = {
    { 0, "Not present" },
    { MESSAGE_FLAG_HAS_DEST_NODE,  "64-bit Node ID" },
    { MESSAGE_FLAG_HAS_DEST_GROUP, "16-bit Group ID" },
    { 0, NULL }
};

static const value_string session_type_vals[] = {
    { 0, "Unicast Session" },
    { 1, "Group Session" },
    { 0, NULL }
};

static int
dissect_matter_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pl_tree);

static int
dissect_matter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *matter_tree;
    guint       offset = 0;

    /* info extracted from the packet */
    guint8 message_flags = 0;
    guint8 security_flags = 0;
    guint8 message_dsiz = 0;
    guint8 message_session_type = 0;
    guint session_id = 0;

    /* Check that the packet is long enough for it to belong to us. */
    if (tvb_reported_length(tvb) < MATTER_MIN_LENGTH)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Matter");

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_matter, tvb, 0, -1, ENC_NA);

    matter_tree = proto_item_add_subtree(ti, ett_matter);

    static int* const message_flag_fields[] = {
        &hf_message_version,
        &hf_message_has_source,
        &hf_message_dsiz,
        NULL
    };
    static int* const message_secflag_fields[] = {
        &hf_message_flag_privacy,
        &hf_message_flag_control,
        &hf_message_flag_extensions,
        &hf_message_session_type,
        NULL
    };

    proto_tree_add_bitmask(matter_tree, tvb, offset, hf_message_flags, ett_message_flags, message_flag_fields, ENC_LITTLE_ENDIAN);
    message_flags = tvb_get_guint8(tvb, offset);
    message_dsiz = (message_flags & MESSAGE_FLAG_DSIZ_MASK);
    offset += 1;

    proto_tree_add_item_ret_uint(matter_tree, hf_message_session_id, tvb, offset, 2, ENC_LITTLE_ENDIAN, &session_id);
    offset += 2;

    proto_tree_add_bitmask(matter_tree, tvb, offset, hf_message_security_flags, ett_security_flags, message_secflag_fields, ENC_LITTLE_ENDIAN);
    security_flags = tvb_get_guint8(tvb, offset);
    message_session_type = (security_flags & SECURITY_FLAG_SESSION_TYPE_MASK);
    offset += 1;

    // decryption of message privacy is not yet supported,
    // but add an opaque field with the encrypted blob
    if (security_flags & SECURITY_FLAG_HAS_PRIVACY) {

        guint privacy_header_length = 4;
        if (message_flags & MESSAGE_FLAG_HAS_SOURCE) {
            privacy_header_length += 8;
        }
        if (message_dsiz == MESSAGE_FLAG_HAS_DEST_NODE) {
            privacy_header_length += 8;
        } else if (message_dsiz == MESSAGE_FLAG_HAS_DEST_GROUP) {
            privacy_header_length += 2;
        }
        proto_tree_add_bytes_format(matter_tree, hf_message_privacy_header, tvb, offset, privacy_header_length, NULL, "Encrypted Headers");
        offset += privacy_header_length;

    } else {

        proto_tree_add_item(matter_tree, hf_message_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        if (message_flags & MESSAGE_FLAG_HAS_SOURCE) {
            proto_tree_add_item(matter_tree, hf_message_src_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        }

        if (message_dsiz == MESSAGE_FLAG_HAS_DEST_NODE) {
            proto_tree_add_item(matter_tree, hf_message_dest_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        } else if (message_dsiz == MESSAGE_FLAG_HAS_DEST_GROUP) {
            proto_tree_add_item(matter_tree, hf_message_dest_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

    }

    // "The Unsecured Session SHALL be indicated when both Session Type and Session ID are set to 0."
    // Secured sessions not yet supported.
    if (message_session_type == 0 && session_id == 0) {
        proto_item *payload_item = proto_tree_add_none_format(matter_tree, hf_payload, tvb, offset, -1, "Protocol Payload");
        proto_tree *payload_tree = proto_item_add_subtree(payload_item, ett_payload);
        tvbuff_t *next_tvb = tvb_new_subset_remaining(tvb, offset);

        offset += dissect_matter_payload(next_tvb, pinfo, payload_tree);
    } else {
        guint payload_length = tvb_reported_length_remaining(tvb, offset);
        proto_tree_add_none_format(matter_tree, hf_payload, tvb, offset, payload_length, "Encrypted Payload (%u bytes)", payload_length);
    }

    return offset;
}

static int
dissect_matter_payload(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *pl_tree)
{
    guint offset = 0;

    guint8 exchange_flags = 0;

    static int* const exchange_flag_fields[] = {
        &hf_payload_flag_initiator,
        &hf_payload_flag_ack,
        &hf_payload_flag_reliability,
        &hf_payload_flag_secured_extensions,
        &hf_payload_flag_vendor,
        NULL
    };
    proto_tree_add_bitmask(pl_tree, tvb, offset, hf_payload_exchange_flags, ett_exchange_flags, exchange_flag_fields, ENC_LITTLE_ENDIAN);
    exchange_flags = tvb_get_guint8(tvb, offset);
    offset += 1;

    proto_tree_add_item(pl_tree, hf_payload_protocol_opcode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    proto_tree_add_item(pl_tree, hf_payload_exchange_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    if (exchange_flags & EXCHANGE_FLAG_HAS_VENDOR_PROTO) {
        // NOTE: The Matter specification R1.0 (22-27349) section 4.4 says
        // the Vendor ID comes after the Protocol ID. However, the SDK
        // implementation expects and produces the vendor ID first and the
        // protocol ID afterwards. This was reported, and the maintainers
        // declared it a bug in the *specification*, which will be resolved
        // in a future version:
        // https://github.com/project-chip/connectedhomeip/issues/25003
        // So we parse Vendor ID first, contrary to the current spec.
        proto_tree_add_item(pl_tree, hf_payload_protocol_vendor_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }

    proto_tree_add_item(pl_tree, hf_payload_protocol_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    if (exchange_flags & EXCHANGE_FLAG_ACK_MSG) {
        proto_tree_add_item(pl_tree, hf_payload_ack_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    if (exchange_flags & EXCHANGE_FLAG_HAS_SECURED_EXT) {
        guint secured_ext_len = 0;
        proto_tree_add_item_ret_uint(pl_tree, hf_payload_secured_ext_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &secured_ext_len);
        offset += 2;
        proto_tree_add_item(pl_tree, hf_payload_secured_ext, tvb, offset, secured_ext_len, ENC_NA);
        offset += secured_ext_len;
    }
    guint application_length = tvb_reported_length_remaining(tvb, offset);
    proto_tree_add_bytes_format(pl_tree, hf_payload_application, tvb, offset, application_length, NULL, "Application payload (%u bytes)", application_length);
    offset += application_length;
    return offset;
}

void
proto_register_matter(void)
{
    static hf_register_info hf[] = {
        { &hf_message_flags,
          { "Message Flags", "matter.message.flags",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_message_version,
          { "Version", "matter.message.version",
            FT_UINT8, BASE_DEC, NULL, MESSAGE_FLAG_VERSION_MASK,
            "Message format version", HFILL }
        },
        { &hf_message_has_source,
          { "Has Source ID", "matter.message.has_source_id",
            FT_BOOLEAN, 8, NULL, MESSAGE_FLAG_HAS_SOURCE,
            "Source ID field is present", HFILL }
        },
        { &hf_message_dsiz,
          { "Destination ID Type", "matter.message.dsiz",
            FT_UINT8, BASE_DEC, VALS(dsiz_vals), MESSAGE_FLAG_DSIZ_MASK,
            "Size and meaning of the Destination Node ID field", HFILL }
        },
        { &hf_message_session_id,
          { "Session ID", "matter.message.session_id",
            FT_UINT16, BASE_HEX, NULL, 0,
            "The session associated with this message", HFILL }
        },
        { &hf_message_security_flags,
          { "Security Flags", "matter.message.security_flags",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Message security flags", HFILL }
        },
        { &hf_message_flag_privacy,
          { "Privacy", "matter.message.has_privacy",
            FT_BOOLEAN, 8, NULL, SECURITY_FLAG_HAS_PRIVACY,
            "Whether the message is encoded with privacy enhancements", HFILL }
        },
        { &hf_message_flag_control,
          { "Control", "matter.message.is_control",
            FT_BOOLEAN, 8, NULL, SECURITY_FLAG_IS_CONTROL,
            "Whether this is a control message", HFILL }
        },
        { &hf_message_flag_extensions,
          { "Message Extensions", "matter.message.has_extensions",
            FT_BOOLEAN, 8, NULL, SECURITY_FLAG_HAS_EXTENSIONS,
            "Whether message extensions are present", HFILL }
        },
        { &hf_message_session_type,
          { "Session Type", "matter.message.session_type",
            FT_UINT8, BASE_HEX, VALS(session_type_vals), SECURITY_FLAG_SESSION_TYPE_MASK,
            "The type of session associated with the message", HFILL }
        },
        { &hf_message_counter,
          { "Message Counter", "matter.message.counter",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_message_src_id,
          { "Source Node ID", "matter.message.src_id",
            FT_UINT64, BASE_HEX, NULL, 0,
            "Unique identifier of the source node", HFILL }
        },
        { &hf_message_dest_id,
          { "Destination Node ID", "matter.message.dest_id",
            FT_UINT64, BASE_HEX, NULL, 0,
            "Unique identifier of the destination node or group", HFILL }
        },
        { &hf_message_privacy_header,
          { "Encrypted header fields", "matter.message.privacy_header",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Headers encrypted with message privacy", HFILL }
        },
        { &hf_payload,
          { "Payload", "matter.payload",
            FT_NONE, BASE_NONE, NULL, 0,
            "Message Payload", HFILL }
        },
        { &hf_payload_exchange_flags,
          { "Exchange Flags", "matter.payload.exchange_flags",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Flags related to the exchange", HFILL }
        },
        { &hf_payload_flag_initiator,
          { "Initiator", "matter.payload.initiator",
            FT_BOOLEAN, 8, NULL, EXCHANGE_FLAG_IS_INITIATOR,
            "Whether the message was sent by the initiator of the exchange", HFILL }
        },
        { &hf_payload_flag_ack,
          { "Acknowledgement", "matter.payload.ack_msg",
            FT_BOOLEAN, 8, NULL, EXCHANGE_FLAG_ACK_MSG,
            "Whether the message is an acknowledgement of a previously-received message", HFILL }
        },
        { &hf_payload_flag_reliability,
          { "Reliability", "matter.payload.reliability",
            FT_BOOLEAN, 8, NULL, EXCHANGE_FLAG_RELIABILITY,
            "Whether the sender wishes to receive an acknowledgement for this message", HFILL }
        },
        { &hf_payload_flag_secured_extensions,
          { "Secure extensions", "matter.payload.has_secured_ext",
            FT_BOOLEAN, 8, NULL, EXCHANGE_FLAG_HAS_SECURED_EXT,
            "Whether this message contains Secured Extensions", HFILL }
        },
        { &hf_payload_flag_vendor,
          { "Has Vendor ID", "matter.payload.has_vendor_protocol",
            FT_BOOLEAN, 8, NULL, EXCHANGE_FLAG_HAS_VENDOR_PROTO,
            "Whether this message contains a protocol vendor ID", HFILL }
        },
        { &hf_payload_protocol_opcode,
          { "Protocol Opcode", "matter.payload.protocol_opcode",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Opcode of the message (depends on Protocol ID)", HFILL }
        },
        { &hf_payload_exchange_id,
          { "Exchange ID", "matter.payload.exchange_id",
            FT_UINT16, BASE_HEX, NULL, 0,
            "The exchange to which the message belongs", HFILL }
        },
        { &hf_payload_protocol_vendor_id,
          { "Protocol Vendor ID", "matter.payload.protocol_vendor_id",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Vendor ID namespace for the protocol ID", HFILL }
        },
        { &hf_payload_protocol_id,
          { "Protocol ID", "matter.payload.protocol_id",
            FT_UINT16, BASE_HEX, NULL, 0,
            "The protocol in which the Protocol Opcode of the message is defined", HFILL }
        },
        { &hf_payload_ack_counter,
          { "Acknowledged message counter", "matter.payload.ack_counter",
            FT_UINT32, BASE_HEX, NULL, 0,
            "The message counter of a previous message that is being acknowledged by this message", HFILL }
        },
        { &hf_payload_secured_ext_length,
          { "Secured extensions length", "matter.payload.secured_ext.length",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Secured extensions payload length, in bytes", HFILL }
        },
        { &hf_payload_secured_ext,
          { "Secured extensions payload", "matter.payload.secured_ext",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_payload_application,
          { "Application payload", "matter.payload.application",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_matter,
        &ett_message_flags,
        &ett_security_flags,
        &ett_payload,
        &ett_exchange_flags,
    };

    /* Register the protocol name and description */
    proto_matter = proto_register_protocol("Matter", "Matter", "matter");
    matter_handle = register_dissector("matter", dissect_matter, proto_matter);

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_matter, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_matter(void)
{
    dissector_add_for_decode_as("udp.port", matter_handle);
}
