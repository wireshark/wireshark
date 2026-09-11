/* packet-packclient.c
 * Routines for PackClient Launcher/Core Transport dissection
 * Copyright 2026, Ivan Immanuel Shaji
 *
 * Protocol research and tooling:
 * https://ivanimmanuel-dev.github.io/PackClient/
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/packet.h>

#include "packet-tcp.h"

void proto_reg_handoff_packclient(void);
void proto_register_packclient(void);

#define PACKCLIENT_FRAME_HEADER_LEN        4
#define PACKCLIENT_TYPE_LEN                4
#define PACKCLIENT_FRAME_PREFIX            0x5A400000U
#define PACKCLIENT_FRAME_PREFIX_MASK       0xFFC00000U
#define PACKCLIENT_BODY_LENGTH_MASK        0x003FFFFFU

#define PACKCLIENT_TYPE_CORE_1             0x01U
#define PACKCLIENT_TYPE_CORE_2             0x02U
#define PACKCLIENT_TYPE_CORE_STRUCTURED    0x03U
#define PACKCLIENT_TYPE_CORE_10            0x0AU
#define PACKCLIENT_TYPE_CORE_INVENTORY     0x0BU
#define PACKCLIENT_TYPE_CORE_17            0x11U
#define PACKCLIENT_TYPE_CORE_PV10          0x12U
#define PACKCLIENT_TYPE_PLAINTEXT          0x15U
#define PACKCLIENT_TYPE_ENVELOPE           0x16U

#define PACKCLIENT_BODY_PLH1               36U
#define PACKCLIENT_BODY_PLC1               28U
#define PACKCLIENT_BODY_PLA1               44U
#define PACKCLIENT_BODY_PLK1               60U

#define PACKCLIENT_ENVELOPE_OVERHEAD_LEN   0x35U
#define PACKCLIENT_MAX_OBJECT_SIZE         0x08000000U

static int proto_packclient;

static int hf_packclient_frame_word;
static int hf_packclient_body_length;
static int hf_packclient_message_type;
static int hf_packclient_phase;
static int hf_packclient_object_magic;
static int hf_packclient_object_version;
static int hf_packclient_plh1_field_06;
static int hf_packclient_plh1_field_08;
static int hf_packclient_plh1_field_0c;
static int hf_packclient_plh1_tick_count;
static int hf_packclient_plh1_process_id;
static int hf_packclient_plh1_reserved;
static int hf_packclient_plc1_field_06;
static int hf_packclient_plc1_challenge;
static int hf_packclient_pla1_reserved;
static int hf_packclient_pla1_authenticator;
static int hf_packclient_envelope_version;
static int hf_packclient_envelope_iv;
static int hf_packclient_envelope_ciphertext_length;
static int hf_packclient_envelope_format;
static int hf_packclient_envelope_hmac;
static int hf_packclient_plk1_wire_version;
static int hf_packclient_plk1_lz4_flag;
static int hf_packclient_plk1_reserved;
static int hf_packclient_plk1_total_size;
static int hf_packclient_plk1_original_size;
static int hf_packclient_plk1_expected_sha256;
static int hf_packclient_core_payload;
static int hf_packclient_core_command;
static int hf_packclient_pv10_magic;
static int hf_packclient_pv10_jpeg_length;
static int hf_packclient_pv10_jpeg;

static int ett_packclient;

static expert_field ei_packclient_malformed_framing = EI_INIT;
static expert_field ei_packclient_malformed_object = EI_INIT;
static expert_field ei_packclient_malformed_envelope = EI_INIT;
static expert_field ei_packclient_malformed_pv10 = EI_INIT;

static dissector_handle_t packclient_handle;

static const uint8_t packclient_magic_plh1[] = { 'P', 'L', 'H', '1' };
static const uint8_t packclient_magic_plc1[] = { 'P', 'L', 'C', '1' };
static const uint8_t packclient_magic_pla1[] = { 'P', 'L', 'A', '1' };
static const uint8_t packclient_magic_plk1[] = { 'P', 'L', 'K', '1' };
static const uint8_t packclient_magic_pv10[] = { 'P', 'V', '1', '0' };

static const uint8_t packclient_core_prefix_inp[] = { 'I', 'N', 'P', '|' };
static const uint8_t packclient_core_prefix_sys[] = { 'S', 'Y', 'S', '|' };
static const uint8_t packclient_core_prefix_tlm[] = { 'T', 'L', 'M', '|' };
static const uint8_t packclient_core_prefix_scr[] = { 'S', 'C', 'R', '|' };
static const uint8_t packclient_core_prefix_q[] = { 'Q', '|' };
static const uint8_t packclient_core_prefix_pipe[] = { 'P', 'I', 'P', 'E', '|' };

typedef struct {
    const uint8_t *bytes;
    unsigned length;
} packclient_marker_t;

static const packclient_marker_t packclient_core_command_prefixes[] = {
    { packclient_core_prefix_inp, sizeof(packclient_core_prefix_inp) },
    { packclient_core_prefix_sys, sizeof(packclient_core_prefix_sys) },
    { packclient_core_prefix_tlm, sizeof(packclient_core_prefix_tlm) },
    { packclient_core_prefix_scr, sizeof(packclient_core_prefix_scr) },
    { packclient_core_prefix_q, sizeof(packclient_core_prefix_q) },
    { packclient_core_prefix_pipe, sizeof(packclient_core_prefix_pipe) },
};

static const value_string packclient_message_type_vals[] = {
    { PACKCLIENT_TYPE_CORE_1,          "Core type 1" },
    { PACKCLIENT_TYPE_CORE_2,          "Core type 2" },
    { PACKCLIENT_TYPE_CORE_STRUCTURED, "Core structured message" },
    { PACKCLIENT_TYPE_CORE_10,         "Core type 10" },
    { PACKCLIENT_TYPE_CORE_INVENTORY,  "Core host inventory" },
    { PACKCLIENT_TYPE_CORE_17,         "Core type 17" },
    { PACKCLIENT_TYPE_CORE_PV10,       "Core PV10 preview" },
    { PACKCLIENT_TYPE_PLAINTEXT,       "Plaintext delivery" },
    { PACKCLIENT_TYPE_ENVELOPE,        "Authenticated encrypted envelope" },
    { 0, NULL }
};

static bool
packclient_valid_frame_word(uint32_t frame_word)
{
    return (frame_word & PACKCLIENT_FRAME_PREFIX_MASK) == PACKCLIENT_FRAME_PREFIX;
}

static bool
packclient_is_core_type(uint32_t message_type)
{
    switch (message_type) {
    case PACKCLIENT_TYPE_CORE_1:
    case PACKCLIENT_TYPE_CORE_2:
    case PACKCLIENT_TYPE_CORE_STRUCTURED:
    case PACKCLIENT_TYPE_CORE_10:
    case PACKCLIENT_TYPE_CORE_INVENTORY:
    case PACKCLIENT_TYPE_CORE_17:
    case PACKCLIENT_TYPE_CORE_PV10:
        return true;
    default:
        return false;
    }
}

static bool
packclient_known_plaintext_body_length(uint32_t body_length)
{
    switch (body_length) {
    case PACKCLIENT_BODY_PLH1:
    case PACKCLIENT_BODY_PLC1:
    case PACKCLIENT_BODY_PLA1:
    case PACKCLIENT_BODY_PLK1:
        return true;
    default:
        return false;
    }
}

static uint32_t
packclient_expected_body_for_magic(tvbuff_t *tvb)
{
    if (tvb_memeql(tvb, 8, packclient_magic_plh1, 4) == 0)
        return PACKCLIENT_BODY_PLH1;
    if (tvb_memeql(tvb, 8, packclient_magic_plc1, 4) == 0)
        return PACKCLIENT_BODY_PLC1;
    if (tvb_memeql(tvb, 8, packclient_magic_pla1, 4) == 0)
        return PACKCLIENT_BODY_PLA1;
    if (tvb_memeql(tvb, 8, packclient_magic_plk1, 4) == 0)
        return PACKCLIENT_BODY_PLK1;

    return 0;
}

static bool
packclient_validate_plaintext_object(tvbuff_t *tvb, uint32_t body_length)
{
    uint32_t expected_body;
    uint16_t version;

    expected_body = packclient_expected_body_for_magic(tvb);
    if (expected_body == 0 || expected_body != body_length)
        return false;

    version = tvb_get_letohs(tvb, 12);

    if (expected_body == PACKCLIENT_BODY_PLH1) {
        return version == 1 &&
               tvb_get_letohs(tvb, 14) == 0x20 &&
               tvb_get_letohl(tvb, 16) == 0 &&
               tvb_get_letohl(tvb, 20) == 1 &&
               tvb_get_letohl(tvb, 36) == 0;
    }

    if (expected_body == PACKCLIENT_BODY_PLC1)
        return version == 1;

    if (expected_body == PACKCLIENT_BODY_PLA1)
        return version == 1 && tvb_get_letohs(tvb, 14) == 0;

    if (expected_body == PACKCLIENT_BODY_PLK1) {
        uint64_t total_size = tvb_get_letoh64(tvb, 16);
        uint64_t original_size = tvb_get_letoh64(tvb, 24);

        if (version != 1 && version != 2)
            return false;
        if (total_size == 0 || total_size > PACKCLIENT_MAX_OBJECT_SIZE)
            return false;
        if (version == 2 &&
            (original_size == 0 || original_size > PACKCLIENT_MAX_OBJECT_SIZE))
            return false;

        return true;
    }

    return false;
}

static bool
packclient_valid_heuristic_start(tvbuff_t *tvb)
{
    unsigned captured_length = tvb_captured_length(tvb);
    uint32_t frame_word;
    uint32_t body_length;
    uint32_t message_type;

    if (captured_length < PACKCLIENT_FRAME_HEADER_LEN + PACKCLIENT_TYPE_LEN)
        return false;

    frame_word = tvb_get_letohl(tvb, 0);
    if (!packclient_valid_frame_word(frame_word))
        return false;

    body_length = frame_word & PACKCLIENT_BODY_LENGTH_MASK;
    if (body_length < PACKCLIENT_TYPE_LEN)
        return false;

    /* Require a complete valid first PDU before heuristic binding. */
    if (captured_length < PACKCLIENT_FRAME_HEADER_LEN + body_length)
        return false;

    message_type = tvb_get_letohl(tvb, 4);

    if (message_type == PACKCLIENT_TYPE_PLAINTEXT) {
        if (!packclient_known_plaintext_body_length(body_length))
            return false;

        return packclient_validate_plaintext_object(tvb, body_length);
    }

    if (message_type == PACKCLIENT_TYPE_ENVELOPE) {
        uint32_t envelope_length = body_length - PACKCLIENT_TYPE_LEN;
        uint32_t ciphertext_length;

        if (envelope_length < PACKCLIENT_ENVELOPE_OVERHEAD_LEN + 16)
            return false;
        if (tvb_get_uint8(tvb, 8) != 1)
            return false;

        /* Heuristic binding intentionally remains Launcher-only. */
        ciphertext_length = tvb_get_ntohl(tvb, 25);
        return ciphertext_length != 0 && (ciphertext_length % 16) == 0 &&
               (uint64_t)ciphertext_length + PACKCLIENT_ENVELOPE_OVERHEAD_LEN ==
                   envelope_length;
    }

    return false;
}

static const char *
packclient_add_plaintext_object(tvbuff_t *tvb, packet_info *pinfo,
                                proto_tree *tree, proto_item *root,
                                uint32_t body_length)
{
    uint32_t expected_body;
    uint16_t version;

    if (body_length < 8)
        return NULL;

    expected_body = packclient_expected_body_for_magic(tvb);
    if (expected_body == 0)
        return NULL;

    if (expected_body != body_length) {
        expert_add_info_format(pinfo, root, &ei_packclient_malformed_object,
                               "%s has an invalid payload length",
                               expected_body == PACKCLIENT_BODY_PLH1 ? "PLH1" :
                               expected_body == PACKCLIENT_BODY_PLC1 ? "PLC1" :
                               expected_body == PACKCLIENT_BODY_PLA1 ? "PLA1" : "PLK1");
        return NULL;
    }

    version = tvb_get_letohs(tvb, 12);

    if (expected_body == PACKCLIENT_BODY_PLH1) {
        if (version != 1 || tvb_get_letohs(tvb, 14) != 0x20 ||
            tvb_get_letohl(tvb, 16) != 0 || tvb_get_letohl(tvb, 20) != 1 ||
            tvb_get_letohl(tvb, 36) != 0) {
            expert_add_info_format(pinfo, root, &ei_packclient_malformed_object,
                                   "PLH1 fixed field validation failed");
            return NULL;
        }

        proto_tree_add_item(tree, hf_packclient_object_magic, tvb, 8, 4, ENC_ASCII);
        proto_tree_add_item(tree, hf_packclient_object_version, tvb, 12, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_packclient_plh1_field_06, tvb, 14, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_packclient_plh1_field_08, tvb, 16, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_packclient_plh1_field_0c, tvb, 20, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_packclient_plh1_tick_count, tvb, 24, 8, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_packclient_plh1_process_id, tvb, 32, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_packclient_plh1_reserved, tvb, 36, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_string(tree, hf_packclient_phase, tvb, 4, 4, "Launcher");
        return "PLH1";
    }

    if (expected_body == PACKCLIENT_BODY_PLC1) {
        if (version != 1) {
            expert_add_info_format(pinfo, root, &ei_packclient_malformed_object,
                                   "PLC1 version must be 1");
            return NULL;
        }

        proto_tree_add_item(tree, hf_packclient_object_magic, tvb, 8, 4, ENC_ASCII);
        proto_tree_add_item(tree, hf_packclient_object_version, tvb, 12, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_packclient_plc1_field_06, tvb, 14, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_packclient_plc1_challenge, tvb, 16, 16, ENC_NA);
        proto_tree_add_string(tree, hf_packclient_phase, tvb, 4, 4, "Launcher");
        return "PLC1";
    }

    if (expected_body == PACKCLIENT_BODY_PLA1) {
        if (version != 1 || tvb_get_letohs(tvb, 14) != 0) {
            expert_add_info_format(pinfo, root, &ei_packclient_malformed_object,
                                   "PLA1 fixed field validation failed");
            return NULL;
        }

        proto_tree_add_item(tree, hf_packclient_object_magic, tvb, 8, 4, ENC_ASCII);
        proto_tree_add_item(tree, hf_packclient_object_version, tvb, 12, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_packclient_pla1_reserved, tvb, 14, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_packclient_pla1_authenticator, tvb, 16, 32, ENC_NA);
        proto_tree_add_string(tree, hf_packclient_phase, tvb, 4, 4, "Launcher");
        return "PLA1";
    }

    if (expected_body == PACKCLIENT_BODY_PLK1) {
        uint64_t total_size = tvb_get_letoh64(tvb, 16);
        uint64_t original_size = tvb_get_letoh64(tvb, 24);

        if (version != 1 && version != 2) {
            expert_add_info_format(pinfo, root, &ei_packclient_malformed_object,
                                   "PLK1 wire version must be 1 or 2");
            return NULL;
        }
        if (total_size == 0 || total_size > PACKCLIENT_MAX_OBJECT_SIZE) {
            expert_add_info_format(pinfo, root, &ei_packclient_malformed_object,
                                   "PLK1 total size is outside 1..0x08000000");
            return NULL;
        }
        if (version == 2 &&
            (original_size == 0 || original_size > PACKCLIENT_MAX_OBJECT_SIZE)) {
            expert_add_info_format(pinfo, root, &ei_packclient_malformed_object,
                                   "PLK1 original size is outside 1..0x08000000");
            return NULL;
        }

        proto_tree_add_item(tree, hf_packclient_object_magic, tvb, 8, 4, ENC_ASCII);
        proto_tree_add_item(tree, hf_packclient_plk1_wire_version, tvb, 12, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_packclient_plk1_lz4_flag, tvb, 14, 1, ENC_NA);
        proto_tree_add_item(tree, hf_packclient_plk1_reserved, tvb, 15, 1, ENC_NA);
        proto_tree_add_item(tree, hf_packclient_plk1_total_size, tvb, 16, 8, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_packclient_plk1_original_size, tvb, 24, 8, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_packclient_plk1_expected_sha256, tvb, 32, 32, ENC_NA);
        proto_tree_add_string(tree, hf_packclient_phase, tvb, 4, 4, "Launcher");
        return "PLK1";
    }

    return NULL;
}

static const char *
packclient_add_envelope_metadata(tvbuff_t *tvb, packet_info *pinfo,
                                 proto_tree *tree, proto_item *root,
                                 uint32_t body_length)
{
    uint32_t envelope_length = body_length - PACKCLIENT_TYPE_LEN;
    uint32_t expected_ciphertext_length;
    uint32_t ciphertext_length_be;
    uint32_t ciphertext_length_le;
    uint32_t ciphertext_length;
    uint8_t version;
    unsigned encoding;
    const char *format;
    const char *phase = NULL;
    bool launcher_format;
    bool core_format;

    if (envelope_length < PACKCLIENT_ENVELOPE_OVERHEAD_LEN) {
        expert_add_info_format(pinfo, root, &ei_packclient_malformed_envelope,
                               "type 0x16 envelope is shorter than 0x35 bytes");
        return NULL;
    }

    version = tvb_get_uint8(tvb, 8);
    ciphertext_length_be = tvb_get_ntohl(tvb, 25);
    ciphertext_length_le = tvb_get_letohl(tvb, 25);
    expected_ciphertext_length = envelope_length - PACKCLIENT_ENVELOPE_OVERHEAD_LEN;
    launcher_format = ciphertext_length_be == expected_ciphertext_length;
    core_format = ciphertext_length_le == expected_ciphertext_length;

    proto_tree_add_item(tree, hf_packclient_envelope_version, tvb, 8, 1, ENC_NA);
    proto_tree_add_item(tree, hf_packclient_envelope_iv, tvb, 9, 16, ENC_NA);

    if (version != 1) {
        expert_add_info_format(pinfo, root, &ei_packclient_malformed_envelope,
                               "type 0x16 envelope version must be 1");
        return NULL;
    }

    if (launcher_format && !core_format) {
        ciphertext_length = ciphertext_length_be;
        encoding = ENC_BIG_ENDIAN;
        format = "Launcher (big-endian length)";
        phase = "Launcher";
    } else if (core_format && !launcher_format) {
        ciphertext_length = ciphertext_length_le;
        encoding = ENC_LITTLE_ENDIAN;
        format = "Core (little-endian length)";
        phase = "Core";
    } else if (launcher_format && core_format) {
        ciphertext_length = ciphertext_length_be;
        encoding = ENC_BIG_ENDIAN;
        format = "Ambiguous byte order";
    } else {
        expert_add_info_format(pinfo, root, &ei_packclient_malformed_envelope,
                               "type 0x16 envelope length does not match its ciphertext length");
        return NULL;
    }

    proto_tree_add_item(tree, hf_packclient_envelope_ciphertext_length, tvb, 25, 4, encoding);
    proto_tree_add_string(tree, hf_packclient_envelope_format, tvb, 25, 4, format);
    if (phase != NULL)
        proto_tree_add_string(tree, hf_packclient_phase, tvb, 4, 4, phase);

    if (ciphertext_length == 0) {
        expert_add_info_format(pinfo, root, &ei_packclient_malformed_envelope,
                               "type 0x16 ciphertext is empty");
        return NULL;
    }
    if ((ciphertext_length % 16) != 0) {
        expert_add_info_format(pinfo, root, &ei_packclient_malformed_envelope,
                               "type 0x16 ciphertext length is not AES block-aligned");
        return NULL;
    }

    proto_tree_add_item(tree, hf_packclient_envelope_hmac, tvb,
                        29 + ciphertext_length, 32, ENC_NA);
    return "type 0x16 metadata";
}

static void
packclient_add_core_command(tvbuff_t *tvb, proto_tree *tree, uint32_t payload_length)
{
    unsigned payload_offset = 8;
    unsigned command_offset = 0;
    unsigned command_length = 0;
    bool found = false;

    for (unsigned offset = 0; offset < payload_length && !found; offset++) {
        unsigned remaining = payload_length - offset;

        for (unsigned marker_idx = 0; marker_idx < array_length(packclient_core_command_prefixes);
             marker_idx++) {
            const packclient_marker_t *marker = &packclient_core_command_prefixes[marker_idx];

            if (remaining >= marker->length &&
                tvb_memeql(tvb, payload_offset + offset,
                           marker->bytes, marker->length) == 0) {
                command_offset = offset;
                command_length = remaining;
                found = true;
                break;
            }
        }
    }

    if (!found)
        return;

    for (unsigned offset = 0; offset < command_length; offset++) {
        if (tvb_get_uint8(tvb, payload_offset + command_offset + offset) == 0) {
            command_length = offset;
            break;
        }
    }

    if (command_length > 0) {
        proto_tree_add_item(tree, hf_packclient_core_command, tvb,
                            payload_offset + command_offset, command_length, ENC_ASCII);
    }
}

static const char *
packclient_add_core_metadata(tvbuff_t *tvb, packet_info *pinfo,
                             proto_tree *tree, proto_item *root,
                             uint32_t message_type, uint32_t body_length)
{
    uint32_t payload_length = body_length - PACKCLIENT_TYPE_LEN;

    proto_tree_add_string(tree, hf_packclient_phase, tvb, 4, 4, "Core");
    if (payload_length > 0)
        proto_tree_add_item(tree, hf_packclient_core_payload, tvb, 8, payload_length, ENC_NA);

    if (message_type == PACKCLIENT_TYPE_CORE_PV10) {
        uint32_t jpeg_length;

        if (payload_length < 8) {
            expert_add_info_format(pinfo, root, &ei_packclient_malformed_pv10,
                                   "PV10 payload is shorter than 8 bytes");
            return NULL;
        }
        if (tvb_memeql(tvb, 8, packclient_magic_pv10, 4) != 0) {
            expert_add_info_format(pinfo, root, &ei_packclient_malformed_pv10,
                                   "Core type 18 payload does not begin with PV10");
            return NULL;
        }

        jpeg_length = tvb_get_letohl(tvb, 12);
        proto_tree_add_item(tree, hf_packclient_pv10_magic, tvb, 8, 4, ENC_ASCII);
        proto_tree_add_item(tree, hf_packclient_pv10_jpeg_length, tvb, 12, 4,
                            ENC_LITTLE_ENDIAN);

        if (jpeg_length != payload_length - 8) {
            expert_add_info_format(pinfo, root, &ei_packclient_malformed_pv10,
                                   "PV10 JPEG length does not match the payload");
            return NULL;
        }
        if (jpeg_length < 2 || tvb_get_ntohs(tvb, 16) != 0xFFD8) {
            expert_add_info_format(pinfo, root, &ei_packclient_malformed_pv10,
                                   "PV10 data does not begin with a JPEG SOI marker");
            return NULL;
        }
        if (jpeg_length < 4 || tvb_get_ntohs(tvb, 16 + jpeg_length - 2) != 0xFFD9) {
            expert_add_info_format(pinfo, root, &ei_packclient_malformed_pv10,
                                   "PV10 data does not end with a JPEG EOI marker");
            return NULL;
        }

        proto_tree_add_item(tree, hf_packclient_pv10_jpeg, tvb, 16, jpeg_length, ENC_NA);
        return "Core PV10 JPEG";
    }

    packclient_add_core_command(tvb, tree, payload_length);
    return val_to_str_const(message_type, packclient_message_type_vals, "Core message");
}

static unsigned
get_packclient_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset,
                       void *data _U_)
{
    uint32_t frame_word = tvb_get_letohl(tvb, offset);

    if (!packclient_valid_frame_word(frame_word))
        return PACKCLIENT_FRAME_HEADER_LEN;

    return PACKCLIENT_FRAME_HEADER_LEN +
           (frame_word & PACKCLIENT_BODY_LENGTH_MASK);
}

static int
dissect_packclient_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                       void *data _U_)
{
    proto_item *ti;
    proto_tree *packclient_tree;
    unsigned reported_length = tvb_reported_length(tvb);
    uint32_t frame_word = tvb_get_letohl(tvb, 0);
    uint32_t body_length = frame_word & PACKCLIENT_BODY_LENGTH_MASK;
    uint32_t message_type;
    const char *classification = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PACKCLIENT");

    ti = proto_tree_add_item(tree, proto_packclient, tvb, 0, -1, ENC_NA);
    packclient_tree = proto_item_add_subtree(ti, ett_packclient);

    proto_tree_add_item(packclient_tree, hf_packclient_frame_word, tvb, 0, 4,
                        ENC_LITTLE_ENDIAN);
    proto_tree_add_item(packclient_tree, hf_packclient_body_length, tvb, 0, 4,
                        ENC_LITTLE_ENDIAN);

    if (!packclient_valid_frame_word(frame_word) ||
        body_length < PACKCLIENT_TYPE_LEN ||
        reported_length != PACKCLIENT_FRAME_HEADER_LEN + body_length) {
        proto_item_append_text(ti, " (malformed framing)");
        expert_add_info(pinfo, ti, &ei_packclient_malformed_framing);
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Malformed framing");
        col_set_fence(pinfo->cinfo, COL_INFO);
        return tvb_captured_length(tvb);
    }

    proto_tree_add_item(packclient_tree, hf_packclient_message_type, tvb, 4, 4,
                        ENC_LITTLE_ENDIAN);
    message_type = tvb_get_letohl(tvb, 4);

    if (message_type == PACKCLIENT_TYPE_PLAINTEXT) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Plaintext");
        classification = packclient_add_plaintext_object(
            tvb, pinfo, packclient_tree, ti, body_length);
    } else if (message_type == PACKCLIENT_TYPE_ENVELOPE) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ",
                           "Encrypted envelope (authentication not verified)");
        classification = packclient_add_envelope_metadata(
            tvb, pinfo, packclient_tree, ti, body_length);
    } else if (packclient_is_core_type(message_type)) {
        classification = packclient_add_core_metadata(
            tvb, pinfo, packclient_tree, ti, message_type, body_length);
    } else {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ",
                            "Message type 0x%08x", message_type);
    }

    if (classification != NULL) {
        if (packclient_is_core_type(message_type))
            col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", classification);
        else
            col_append_fstr(pinfo->cinfo, COL_INFO, " %s", classification);
        proto_item_append_text(ti, " (%s)", classification);
    }

    /* TCP may call the stream dissector more than once in one frame. */
    col_set_fence(pinfo->cinfo, COL_INFO);
    return tvb_captured_length(tvb);
}

static int
dissect_packclient_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                       void *data)
{
    /* Clear TCP's summary once, preserving any already fenced PDU summary. */
    col_clear(pinfo->cinfo, COL_INFO);
    tcp_dissect_pdus(tvb, pinfo, tree, true, PACKCLIENT_FRAME_HEADER_LEN,
                     get_packclient_pdu_len, dissect_packclient_pdu, data);
    return tvb_captured_length(tvb);
}

static bool
dissect_packclient_heur_tcp(tvbuff_t *tvb, packet_info *pinfo,
                            proto_tree *tree, void *data)
{
    conversation_t *conversation;

    if (!packclient_valid_heuristic_start(tvb))
        return false;

    conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, packclient_handle);

    dissect_packclient_tcp(tvb, pinfo, tree, data);
    return true;
}

void
proto_register_packclient(void)
{
    static hf_register_info hf[] = {
        { &hf_packclient_frame_word,
          { "Frame word", "packclient.frame_word",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_body_length,
          { "Body length", "packclient.body_length",
            FT_UINT32, BASE_DEC, NULL, PACKCLIENT_BODY_LENGTH_MASK,
            NULL, HFILL }
        },
        { &hf_packclient_message_type,
          { "Message type", "packclient.message_type",
            FT_UINT32, BASE_HEX, VALS(packclient_message_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_phase,
          { "Protocol phase", "packclient.phase",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_object_magic,
          { "Object magic", "packclient.object.magic",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_object_version,
          { "Object version", "packclient.object.version",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_plh1_field_06,
          { "PLH1 field +0x06", "packclient.plh1.field_06",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_plh1_field_08,
          { "PLH1 field +0x08", "packclient.plh1.field_08",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_plh1_field_0c,
          { "PLH1 field +0x0C", "packclient.plh1.field_0c",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_plh1_tick_count,
          { "PLH1 tick count", "packclient.plh1.tick_count",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_plh1_process_id,
          { "PLH1 process ID", "packclient.plh1.process_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_plh1_reserved,
          { "PLH1 reserved", "packclient.plh1.reserved",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_plc1_field_06,
          { "PLC1 field +0x06", "packclient.plc1.field_06",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_plc1_challenge,
          { "PLC1 challenge", "packclient.plc1.challenge",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_pla1_reserved,
          { "PLA1 reserved", "packclient.pla1.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_pla1_authenticator,
          { "PLA1 authenticator", "packclient.pla1.authenticator",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Authenticator bytes; not cryptographically verified", HFILL }
        },
        { &hf_packclient_envelope_version,
          { "Envelope version", "packclient.envelope.version",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_envelope_iv,
          { "Envelope IV", "packclient.envelope.iv",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_envelope_ciphertext_length,
          { "Ciphertext length", "packclient.envelope.ciphertext_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_envelope_format,
          { "Envelope format", "packclient.envelope.format",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_envelope_hmac,
          { "Envelope HMAC-SHA-256", "packclient.envelope.hmac",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Authentication tag bytes; not cryptographically verified", HFILL }
        },
        { &hf_packclient_plk1_wire_version,
          { "PLK1 wire version", "packclient.plk1.wire_version",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_plk1_lz4_flag,
          { "PLK1 LZ4 flag", "packclient.plk1.lz4_flag",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_plk1_reserved,
          { "PLK1 reserved", "packclient.plk1.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_plk1_total_size,
          { "PLK1 total size", "packclient.plk1.total_size",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_plk1_original_size,
          { "PLK1 original size", "packclient.plk1.original_size",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_plk1_expected_sha256,
          { "PLK1 expected plaintext SHA-256", "packclient.plk1.expected_sha256",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Expected digest from the header; delivered plaintext is not verified", HFILL }
        },
        { &hf_packclient_core_payload,
          { "Core payload", "packclient.core.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_core_command,
          { "Core command text", "packclient.core.command",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_pv10_magic,
          { "PV10 magic", "packclient.pv10.magic",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_pv10_jpeg_length,
          { "PV10 JPEG length", "packclient.pv10.jpeg_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_packclient_pv10_jpeg,
          { "PV10 JPEG data", "packclient.pv10.jpeg",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_packclient,
    };

    static ei_register_info ei[] = {
        { &ei_packclient_malformed_framing,
          { "packclient.expert.malformed_framing", PI_MALFORMED, PI_ERROR,
            "Malformed PackClient framing", EXPFILL }
        },
        { &ei_packclient_malformed_object,
          { "packclient.expert.malformed_object", PI_MALFORMED, PI_ERROR,
            "Malformed PackClient object", EXPFILL }
        },
        { &ei_packclient_malformed_envelope,
          { "packclient.expert.malformed_envelope", PI_MALFORMED, PI_ERROR,
            "Malformed PackClient type 0x16 envelope", EXPFILL }
        },
        { &ei_packclient_malformed_pv10,
          { "packclient.expert.malformed_pv10", PI_MALFORMED, PI_ERROR,
            "Malformed PackClient Core PV10 preview", EXPFILL }
        },
    };

    expert_module_t *expert_packclient;

    proto_packclient = proto_register_protocol(
        "PackClient Transport", "PACKCLIENT", "packclient");

    proto_register_field_array(proto_packclient, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_packclient = expert_register_protocol(proto_packclient);
    expert_register_field_array(expert_packclient, ei, array_length(ei));

    packclient_handle = register_dissector(
        "packclient", dissect_packclient_tcp, proto_packclient);
}

void
proto_reg_handoff_packclient(void)
{
    heur_dissector_add("tcp", dissect_packclient_heur_tcp,
                       "PackClient Launcher Transport over TCP",
                       "packclient_tcp", proto_packclient, HEURISTIC_ENABLE);

    /* Avoid a static TCP port binding. */
    dissector_add_for_decode_as("tcp.port", packclient_handle);
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
