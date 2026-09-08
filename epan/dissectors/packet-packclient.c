/* packet-packclient.c
 * Routines for PackClient Launcher Transport dissection
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
static int hf_packclient_envelope_hmac;
static int hf_packclient_plk1_wire_version;
static int hf_packclient_plk1_lz4_flag;
static int hf_packclient_plk1_reserved;
static int hf_packclient_plk1_total_size;
static int hf_packclient_plk1_original_size;
static int hf_packclient_plk1_expected_sha256;

static int ett_packclient;

static expert_field ei_packclient_malformed_framing = EI_INIT;
static expert_field ei_packclient_malformed_object = EI_INIT;
static expert_field ei_packclient_malformed_envelope = EI_INIT;

static dissector_handle_t packclient_handle;

static const uint8_t packclient_magic_plh1[] = { 'P', 'L', 'H', '1' };
static const uint8_t packclient_magic_plc1[] = { 'P', 'L', 'C', '1' };
static const uint8_t packclient_magic_pla1[] = { 'P', 'L', 'A', '1' };
static const uint8_t packclient_magic_plk1[] = { 'P', 'L', 'K', '1' };

static const value_string packclient_message_type_vals[] = {
    { PACKCLIENT_TYPE_PLAINTEXT, "Plaintext" },
    { PACKCLIENT_TYPE_ENVELOPE,  "Encrypted envelope" },
    { 0, NULL }
};

static bool
packclient_valid_frame_word(uint32_t frame_word)
{
    return (frame_word & PACKCLIENT_FRAME_PREFIX_MASK) == PACKCLIENT_FRAME_PREFIX;
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
    uint8_t version;
    uint32_t ciphertext_length;

    if (envelope_length < PACKCLIENT_ENVELOPE_OVERHEAD_LEN) {
        expert_add_info_format(pinfo, root, &ei_packclient_malformed_envelope,
                               "type 0x16 envelope is shorter than 0x35 bytes");
        return NULL;
    }

    version = tvb_get_uint8(tvb, 8);
    ciphertext_length = tvb_get_ntohl(tvb, 25);

    proto_tree_add_item(tree, hf_packclient_envelope_version, tvb, 8, 1, ENC_NA);
    proto_tree_add_item(tree, hf_packclient_envelope_iv, tvb, 9, 16, ENC_NA);
    proto_tree_add_item(tree, hf_packclient_envelope_ciphertext_length, tvb, 25, 4,
                        ENC_BIG_ENDIAN);

    if (version != 1) {
        expert_add_info_format(pinfo, root, &ei_packclient_malformed_envelope,
                               "type 0x16 envelope version must be 1");
        return NULL;
    }
    if ((uint64_t)ciphertext_length + PACKCLIENT_ENVELOPE_OVERHEAD_LEN != envelope_length) {
        expert_add_info_format(pinfo, root, &ei_packclient_malformed_envelope,
                               "type 0x16 envelope length does not match its ciphertext length");
        return NULL;
    }
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
    } else {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ",
                            "Message type 0x%08x", message_type);
    }

    if (classification != NULL) {
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
    };

    expert_module_t *expert_packclient;

    proto_packclient = proto_register_protocol(
        "PackClient Launcher Transport", "PACKCLIENT", "packclient");

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
