/* packet-matter.c
 * Routines for Matter IoT protocol dissection
 * Copyright 2023, Nicolás Alvarez <nicolas.alvarez@gmail.com>
 * Copyright 2024, Arkadiusz Bokowy <a.bokowy@samsung.com>
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
 *
 * Comments below reference section numbers of the Matter Core Specification R1.0 (22-27349-001).
 *
 * Matter-TLV dissector is based on Matter Specification Version 1.3.
 */

#include <config.h>

#include <epan/expert.h>
#include <epan/packet.h>

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_matter(void);
void proto_register_matter(void);

/* Initialize the protocol and registered fields */
static dissector_handle_t matter_handle;

static int proto_matter;
static int hf_message_flags;
static int hf_message_version;
static int hf_message_has_source;
static int hf_message_dsiz;
static int hf_message_session_id;
static int hf_message_security_flags;
static int hf_message_flag_privacy;
static int hf_message_flag_control;
static int hf_message_flag_extensions;
static int hf_message_session_type;
static int hf_message_counter;
static int hf_message_src_id;
static int hf_message_dest_id;
static int hf_message_privacy_header;

static int hf_payload;
static int hf_payload_exchange_flags;
static int hf_payload_flag_initiator;
static int hf_payload_flag_ack;
static int hf_payload_flag_reliability;
static int hf_payload_flag_secured_extensions;
static int hf_payload_flag_vendor;
static int hf_payload_protocol_opcode;
static int hf_payload_exchange_id;
static int hf_payload_protocol_vendor_id;
static int hf_payload_protocol_id;
static int hf_payload_ack_counter;
static int hf_payload_secured_ext_length;
static int hf_payload_secured_ext;
static int hf_payload_application;

static int hf_matter_tlv_elem;
static int hf_matter_tlv_elem_control;
static int hf_matter_tlv_elem_control_tag_format;
static int hf_matter_tlv_elem_control_element_type;
static int hf_matter_tlv_elem_tag;
static int hf_matter_tlv_elem_length;
static int hf_matter_tlv_elem_value_int;
static int hf_matter_tlv_elem_value_uint;
static int hf_matter_tlv_elem_value_bytes;

static int ett_matter;
static int ett_message_flags;
static int ett_security_flags;
static int ett_payload;
static int ett_exchange_flags;

static int ett_matter_tlv;
static int ett_matter_tlv_control;

static expert_field ei_matter_tlv_unsupported_control;

/* message flags + session ID + security flags + counter */
#define MATTER_MIN_LENGTH 8

// Section 4.4.1.2
#define MESSAGE_FLAG_VERSION_MASK       0xF0
#define MESSAGE_FLAG_HAS_SOURCE         0x04
#define MESSAGE_FLAG_HAS_DEST_NODE      0x01
#define MESSAGE_FLAG_HAS_DEST_GROUP     0x02
#define MESSAGE_FLAG_DSIZ_MASK          0x03

// Section 4.4.1.4
#define SECURITY_FLAG_HAS_PRIVACY       0x80
#define SECURITY_FLAG_IS_CONTROL        0x40
#define SECURITY_FLAG_HAS_EXTENSIONS    0x20
#define SECURITY_FLAG_SESSION_TYPE_MASK 0x03

// Section 4.4.3.1
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

// Appendix 7.2. Tag Control Field
static const value_string matter_tlv_tag_format_vals[] = {
    { 0, "Anonymous Tag Form, 0 octets" },
    { 1, "Context-specific Tag Form, 1 octet" },
    { 2, "Common Profile Tag Form, 2 octets" },
    { 3, "Common Profile Tag Form, 4 octets" },
    { 4, "Implicit Profile Tag Form, 2 octets" },
    { 5, "Implicit Profile Tag Form, 4 octets" },
    { 6, "Fully-qualified Tag Form, 6 octets" },
    { 7, "Fully-qualified Tag Form, 8 octets" },
    { 0, NULL }
};

// Appendix 7.1. Element Type Field
static const value_string matter_tlv_elem_type_vals[] = {
    { 0x00, "Signed Integer, 1-octet value" },
    { 0x01, "Signed Integer, 2-octet value" },
    { 0x02, "Signed Integer, 4-octet value" },
    { 0x03, "Signed Integer, 8-octet value" },
    { 0x04, "Unsigned Integer, 1-octet value" },
    { 0x05, "Unsigned Integer, 2-octet value" },
    { 0x06, "Unsigned Integer, 4-octet value" },
    { 0x07, "Unsigned Integer, 8-octet value" },
    { 0x08, "Boolean False" },
    { 0x09, "Boolean True" },
    { 0x0A, "Floating Point Number, 4-octet value" },
    { 0x0B, "Floating Point Number, 8-octet value" },
    { 0x0C, "UTF-8 String, 1-octet length" },
    { 0x0D, "UTF-8 String, 2-octet length" },
    { 0x0E, "UTF-8 String, 4-octet length" },
    { 0x0F, "UTF-8 String, 8-octet length" },
    { 0x10, "Octet String, 1-octet length" },
    { 0x11, "Octet String, 2-octet length" },
    { 0x12, "Octet String, 4-octet length" },
    { 0x13, "Octet String, 8-octet length" },
    { 0x14, "Null" },
    { 0x15, "Structure" },
    { 0x16, "Array" },
    { 0x17, "List" },
    // XXX: If the Tag Control Field is set to 0x00 (Anonymous Tag), the
    //      value of 0x18 means "End of Container". For other Tag Control
    //      Field values, the value of 0x18 is reserved.
    // TODO: This should be handled in the dissector.
    { 0x18, "End of Container" },
    { 0x19, "Reserved" },
    { 0x1A, "Reserved" },
    { 0x1B, "Reserved" },
    { 0x1C, "Reserved" },
    { 0x1D, "Reserved" },
    { 0x1E, "Reserved" },
    { 0x1F, "Reserved" },
    { 0, NULL }
};

static int
dissect_matter_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pl_tree);

static int
dissect_matter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *matter_tree;
    uint32_t    offset = 0;

    /* info extracted from the packet */
    uint8_t message_flags = 0;
    uint8_t security_flags = 0;
    uint8_t message_dsiz = 0;
    uint8_t message_session_type = 0;
    uint32_t session_id = 0;

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

    // Section 4.4.1.2
    proto_tree_add_bitmask(matter_tree, tvb, offset, hf_message_flags, ett_message_flags, message_flag_fields, ENC_LITTLE_ENDIAN);
    message_flags = tvb_get_uint8(tvb, offset);
    message_dsiz = (message_flags & MESSAGE_FLAG_DSIZ_MASK);
    offset += 1;

    // Section 4.4.1.3
    proto_tree_add_item_ret_uint(matter_tree, hf_message_session_id, tvb, offset, 2, ENC_LITTLE_ENDIAN, &session_id);
    offset += 2;

    // Section 4.4.1.4
    proto_tree_add_bitmask(matter_tree, tvb, offset, hf_message_security_flags, ett_security_flags, message_secflag_fields, ENC_LITTLE_ENDIAN);
    security_flags = tvb_get_uint8(tvb, offset);
    message_session_type = (security_flags & SECURITY_FLAG_SESSION_TYPE_MASK);
    offset += 1;

    // decryption of message privacy is not yet supported,
    // but add an opaque field with the encrypted blob
    // Section 4.8.3
    if (security_flags & SECURITY_FLAG_HAS_PRIVACY) {

        uint32_t privacy_header_length = 4;
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

        // Section 4.4.1.5
        proto_tree_add_item(matter_tree, hf_message_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        // Section 4.4.1.6
        if (message_flags & MESSAGE_FLAG_HAS_SOURCE) {
            proto_tree_add_item(matter_tree, hf_message_src_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        }
        // Section 4.4.1.7
        if (message_dsiz == MESSAGE_FLAG_HAS_DEST_NODE) {
            proto_tree_add_item(matter_tree, hf_message_dest_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        } else if (message_dsiz == MESSAGE_FLAG_HAS_DEST_GROUP) {
            proto_tree_add_item(matter_tree, hf_message_dest_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

    }

    // Section 4.4.1.4: "The Unsecured Session SHALL be indicated
    // when both Session Type and Session ID are set to 0."
    // Secured sessions not yet supported in the dissector.
    if (message_session_type == 0 && session_id == 0) {
        proto_item *payload_item = proto_tree_add_none_format(matter_tree, hf_payload, tvb, offset, -1, "Protocol Payload");
        proto_tree *payload_tree = proto_item_add_subtree(payload_item, ett_payload);
        tvbuff_t *next_tvb = tvb_new_subset_remaining(tvb, offset);

        offset += dissect_matter_payload(next_tvb, pinfo, payload_tree);
    } else {
        uint32_t payload_length = tvb_reported_length_remaining(tvb, offset);
        proto_tree_add_none_format(matter_tree, hf_payload, tvb, offset, payload_length, "Encrypted Payload (%u bytes)", payload_length);
    }

    return offset;
}

static int
dissect_matter_payload(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *pl_tree)
{
    uint32_t offset = 0;

    uint8_t exchange_flags = 0;

    static int* const exchange_flag_fields[] = {
        &hf_payload_flag_initiator,
        &hf_payload_flag_ack,
        &hf_payload_flag_reliability,
        &hf_payload_flag_secured_extensions,
        &hf_payload_flag_vendor,
        NULL
    };
    // Section 4.4.3.1
    proto_tree_add_bitmask(pl_tree, tvb, offset, hf_payload_exchange_flags, ett_exchange_flags, exchange_flag_fields, ENC_LITTLE_ENDIAN);
    exchange_flags = tvb_get_uint8(tvb, offset);
    offset += 1;

    // Section 4.4.3.2
    proto_tree_add_item(pl_tree, hf_payload_protocol_opcode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    // Section 4.4.3.3
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

    // Section 4.4.3.4
    proto_tree_add_item(pl_tree, hf_payload_protocol_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    // Section 4.4.3.6
    if (exchange_flags & EXCHANGE_FLAG_ACK_MSG) {
        proto_tree_add_item(pl_tree, hf_payload_ack_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    // Section 4.4.3.7
    if (exchange_flags & EXCHANGE_FLAG_HAS_SECURED_EXT) {
        uint32_t secured_ext_len = 0;
        proto_tree_add_item_ret_uint(pl_tree, hf_payload_secured_ext_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &secured_ext_len);
        offset += 2;
        proto_tree_add_item(pl_tree, hf_payload_secured_ext, tvb, offset, secured_ext_len, ENC_NA);
        offset += secured_ext_len;
    }
    uint32_t application_length = tvb_reported_length_remaining(tvb, offset);
    proto_tree_add_bytes_format(pl_tree, hf_payload_application, tvb, offset, application_length, NULL, "Application payload (%u bytes)", application_length);
    offset += application_length;
    return offset;
}

// Dissect the Matter-defined TLV encoding.
// Appendix A: Tag-length-value (TLV) Encoding Format
static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_matter_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    // For signed and unsigned integer types and for UTF-8 and octet strings,
    // the length is encoded in the lowest 2 bits of the control byte.
    static const int elem_sizes[] = { 1, 2, 4, 8 };

    int matter_tlv_elem_tag = hf_matter_tlv_elem_tag;
    int length = tvb_reported_length_remaining(tvb, 0);
    int offset = 0;

    if (data != NULL)
        // Use caller-provided tag field.
        matter_tlv_elem_tag = *((int *)data);

    while (offset < length) {

        // The new element is created with initial length set to 1 which accounts
        // for the control byte (tag format and element type). The length will be
        // updated once the element is fully dissected.
        proto_item *ti_element = proto_tree_add_item(tree, hf_matter_tlv_elem, tvb, offset, 1, ENC_NA);
        proto_tree *tree_element = proto_item_add_subtree(ti_element, ett_matter_tlv);
        int base_offset = offset;

        uint32_t control_tag_format = 0;
        uint32_t control_element = 0;

        proto_item *ti_control = proto_tree_add_item(tree_element, hf_matter_tlv_elem_control, tvb, offset, 1, ENC_NA);
        proto_tree *tree_control = proto_item_add_subtree(ti_control, ett_matter_tlv_control);
        // The tag format is determined by the upper 3 bits of the control byte.
        proto_tree_add_item_ret_uint(tree_control, hf_matter_tlv_elem_control_tag_format, tvb, offset, 1, ENC_NA, &control_tag_format);
        // The element type is determined by the lower 5 bits of the control byte.
        proto_tree_add_item_ret_uint(tree_control, hf_matter_tlv_elem_control_element_type, tvb, offset, 1, ENC_NA, &control_element);

        offset += 1;

        proto_item_append_text(ti_element, ": %s", val_to_str_const(control_element, matter_tlv_elem_type_vals, "Unknown"));

        // The control byte 0x18 means "End of Container".
        if (control_tag_format == 0 && control_element == 0x18)
            return offset;

        switch (control_tag_format)
        {
        case 0: // Anonymous Tag Form (0 octets)
            break;
        case 1: // Context-specific Tag Form (1 octet)
            proto_tree_add_item(tree_element, matter_tlv_elem_tag, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;
        default:
            goto unsupported_control;
        }

        // The string length might be encoded on 1, 2, 4 or 8 octets. In theory,
        // the length can be up to 2^64 - 1 bytes, but in practice, it should be
        // limited to a reasonable value (it should be safe to assume that the
        // length will not exceed 2^16 - 1 bytes).
        uint64_t str_length;

        switch (control_element)
        {
        case 0x00: // Signed Integer, 1-octet value
        case 0x01: // Signed Integer, 2-octet value
        case 0x02: // Signed Integer, 4-octet value
        case 0x03: // Signed Integer, 8-octet value
        case 0x04: // Unsigned Integer, 1-octet value
        case 0x05: // Unsigned Integer, 2-octet value
        case 0x06: // Unsigned Integer, 4-octet value
        case 0x07: // Unsigned Integer, 8-octet value
        {
            // Integer type (signed or unsigned) is encoded in the 3rd bit of the control element.
            int hf = (control_element & 0x04) ? hf_matter_tlv_elem_value_uint : hf_matter_tlv_elem_value_int;
            int size = elem_sizes[control_element & 0x03];
            proto_tree_add_item(tree_element, hf, tvb, offset, size, ENC_LITTLE_ENDIAN);
            offset += size;
            break;
        }
        case 0x08: // Boolean False
        case 0x09: // Boolean True
            break;
        case 0x10: // Octet String (1-octet length)
        case 0x11: // Octet String (2-octet length)
        case 0x12: // Octet String (4-octet length)
        case 0x13: // Octet String (8-octet length)
        {
            int size = elem_sizes[control_element & 0x03];
            proto_tree_add_item_ret_uint64(tree_element, hf_matter_tlv_elem_length, tvb, offset, size, ENC_LITTLE_ENDIAN, &str_length);
            offset += size;
            proto_tree_add_item(tree_element, hf_matter_tlv_elem_value_bytes, tvb, offset, (int)str_length, ENC_NA);
            offset += str_length;
            break;
        }
        case 0x14: // Null
            break;
        case 0x15: // Structure
        case 0x16: // Array
        case 0x17: // List
            offset += dissect_matter_tlv(tvb_new_subset_remaining(tvb, offset), pinfo, tree_element, data);
            break;
        default:
            goto unsupported_control;
        }

        proto_item_set_len(ti_element, offset - base_offset);
        continue;

unsupported_control:
        expert_add_info(pinfo, tree_control, &ei_matter_tlv_unsupported_control);
        proto_item_set_len(ti_element, offset - base_offset);
        return length;
    }

    return length;
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
        },
        { &hf_matter_tlv_elem,
          { "TLV Element", "matter.tlv",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Matter-TLV Element", HFILL }
        },
        { &hf_matter_tlv_elem_control,
          { "Control Byte", "matter.tlv.control",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Matter-TLV Control Byte", HFILL }
        },
        { &hf_matter_tlv_elem_control_tag_format,
          { "Tag Format", "matter.tlv.control.tag",
            FT_UINT8, BASE_HEX, VALS(matter_tlv_tag_format_vals), 0xE0,
            NULL, HFILL }
        },
        { &hf_matter_tlv_elem_control_element_type,
          { "Element Type", "matter.tlv.control.element",
            FT_UINT8, BASE_HEX, VALS(matter_tlv_elem_type_vals), 0x1F,
            NULL, HFILL }
        },
        { &hf_matter_tlv_elem_tag,
          { "Tag", "matter.tlv.tag",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_matter_tlv_elem_length,
          { "Length", "matter.tlv.length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_matter_tlv_elem_value_int,
          { "Value", "matter.tlv.value_int",
            FT_INT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_matter_tlv_elem_value_uint,
          { "Value", "matter.tlv.value_uint",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_matter_tlv_elem_value_bytes,
          { "Value", "matter.tlv.value_bytes",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_matter,
        &ett_message_flags,
        &ett_security_flags,
        &ett_payload,
        &ett_exchange_flags,
        &ett_matter_tlv,
        &ett_matter_tlv_control,
    };

    static ei_register_info ei[] = {
        { &ei_matter_tlv_unsupported_control,
          { "matter.tlv.control.unsupported", PI_UNDECODED, PI_WARN,
            "Unsupported Matter-TLV control byte", EXPFILL }
        },
    };

    /* Register the protocol name and description */
    proto_matter = proto_register_protocol("Matter", "Matter", "matter");
    matter_handle = register_dissector("matter", dissect_matter, proto_matter);
    register_dissector("matter.tlv", dissect_matter_tlv, proto_matter);

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_matter, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module_t *expert = expert_register_protocol(proto_matter);
    expert_register_field_array(expert, ei, array_length(ei));

}

void
proto_reg_handoff_matter(void)
{
    dissector_add_for_decode_as("udp.port", matter_handle);
}
